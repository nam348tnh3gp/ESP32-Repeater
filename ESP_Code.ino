/*
   ESP32 NAT ROUTER - APEX ULTRA (bản Arduino)

   Logic dùng chung với bản ESP-IDF (main/main.c) nằm ở 3 header cạnh file này:
     apex_common.h  - kiểm tra dữ liệu, so sánh hằng thời gian, hysteresis RAM
     apex_dns.h     - DNS captive portal + forwarder không chặn
     apex_ui.h      - giao diện web có đăng nhập
   => Khi mở bằng Arduino IDE hãy giữ 3 file .h này CÙNG THƯ MỤC với ESP_Code.ino.

   Mô hình bảo mật:
     - Trang trạng thái chỉ đọc; cấu hình yêu cầu đăng nhập (POST /login bằng mật khẩu AP).
     - Token phiên (128 bit) chỉ được trả về sau khi đăng nhập đúng; khoá 60 s sau 5 lần sai.
     - Mọi request tới IP phía STA (mạng uplink) bị từ chối: chỉ phục vụ khách của AP.
   Giới hạn đã biết: dùng HTTP thuần (không TLS) và mật khẩu AP mặc định là 12345678 - hãy đổi ngay.
*/

#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_task_wdt.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_chip_info.h>
#include <esp_random.h>
#include <esp_idf_version.h>
#include <atomic>

#include "apex_common.h"
#include "apex_dns.h"
#include "apex_ui.h"

// ================= CẤU HÌNH =================
#define CHANNEL_2G_MIN 1
#define CHANNEL_2G_MAX 13
#define CHANNEL_5G_MIN 36
#define CHANNEL_5G_MAX 165
#define CHANNEL_5G_36 36

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

#define WATCHDOG_TIMEOUT 45
#define DEFAULT_MAX_CLIENTS 7
#define DEFAULT_AP_CHANNEL 1
#define DEFAULT_AP_HIDDEN 0
#define DEFAULT_BAND_5GHZ 0
#define MIN_CLIENTS 1
#define MAX_CLIENTS_LIMIT 10

#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3
#define LOGIN_MAX_FAILS       5
#define LOGIN_LOCKOUT_MS      60000

#define STA_MAX_RETRY 5
#define STA_RECONNECT_BACKOFF_MS 30000

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GATEWAY(192, 168, 4, 1);
IPAddress AP_SUBNET(255, 255, 255, 0);

AsyncWebServer server(80);
Preferences prefs;

String sta_ssid, sta_pass, ap_ssid, ap_pass;
std::atomic<bool> internetOK{false};
std::atomic<bool> natEnabled{false};
std::atomic<bool> memPressure{false};
std::atomic<int> lastRSSI{-100};

// Các handler HTTP đều chạy trên một task (async_tcp) nên các biến dưới đây không cần mutex.
String sessionToken;
static uint32_t lastConfigRequestWindow = 0;
static int configRequestCount = 0;
static int loginFailCount = 0;
static uint32_t loginLockUntilMs = 0;

// Yêu cầu khởi động lại được hoãn để không chặn task async_tcp (và để phản hồi kịp gửi đi).
static volatile uint32_t restartAtMs = 0;

SemaphoreHandle_t staStateMutex = nullptr;
SemaphoreHandle_t internetCheckTrigger = nullptr;

EventGroupHandle_t wifiEventGroup = nullptr;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static int s_retry_num = 0;              // bảo vệ bởi staStateMutex
static bool sta_configured = false;
static bool sta_disconnected = true;     // bảo vệ bởi staStateMutex

static esp_netif_t *s_ap_netif = nullptr;

int ap_channel = DEFAULT_AP_CHANNEL;
bool ap_hidden = DEFAULT_AP_HIDDEN;
int max_clients = DEFAULT_MAX_CLIENTS;
bool use_5ghz = DEFAULT_BAND_5GHZ;

bool board_supports_5ghz = false;
String board_model = "Unknown";

static void scheduleRestart(uint32_t delayMs) {
    uint32_t t = millis() + delayMs;
    if (t == 0) t = 1;
    restartAtMs = t;
}

// ================= NAT (esp_netif) =================
// Kích thước bảng NAPT do cấu hình SDK quyết định, không chỉnh được lúc chạy.
bool enableNAT() {
    if (natEnabled.load()) return true;
    if (s_ap_netif == nullptr) {
        Serial.println("❌ enableNAT: AP netif chưa sẵn sàng");
        return false;
    }
    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err == ESP_OK) {
        natEnabled.store(true);
        Serial.println("✅ NAT Enabled");
        return true;
    }
    Serial.printf("❌ Failed to enable NAT: %s\n", esp_err_to_name(err));
    return false;
}

void disableNAT() {
    if (!natEnabled.load()) return;
    if (s_ap_netif != nullptr) {
        esp_err_t err = esp_netif_napt_disable(s_ap_netif);
        if (err != ESP_OK) {
            Serial.printf("❌ Failed to disable NAT: %s\n", esp_err_to_name(err));
        }
    }
    natEnabled.store(false);
    Serial.println("⚠️ NAT Disabled");
}

// ================= KIỂM TRA INTERNET =================
bool isInternetAvailable() {
    return internetOK.load();
}

// Chỉ coi là online khi nhận đúng 204 và KHÔNG theo redirect: captive portal của mạng uplink
// thường trả 302 -> 200 và trước đây bị nhận nhầm là "có internet".
bool performInternetCheck() {
    HTTPClient http;
    http.setConnectTimeout(5000);
    http.setTimeout(5000);
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
    if (!http.begin("http://connectivitycheck.gstatic.com/generate_204")) return false;
    int code = http.GET();
    http.end();
    return (code == 204);
}

// ================= DNS CAPTIVE PORTAL (apex_dns.h) =================
static int dnsCbInternet(void *ctx) { (void)ctx; return internetOK.load() ? 1 : 0; }
static uint32_t dnsCbUpstream(void *ctx) { (void)ctx; return (uint32_t)WiFi.dnsIP(0); }
static uint32_t dnsCbRand(void) { return esp_random(); }
static void dnsCbWdt(void) { esp_task_wdt_reset(); }
static void dnsCbLog(const char *m) { Serial.printf("🌐 %s\n", m); }

void dnsCaptiveTask(void *pv) {
    esp_task_wdt_add(nullptr);
    for (;;) {
        apex_dns_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.port = 53;
        cfg.bind_addr = (uint32_t)AP_IP;      // chỉ lắng nghe trên IP của AP
        cfg.ap_ip[0] = AP_IP[0]; cfg.ap_ip[1] = AP_IP[1]; cfg.ap_ip[2] = AP_IP[2]; cfg.ap_ip[3] = AP_IP[3];
        cfg.internet_ok = dnsCbInternet;
        cfg.upstream_ip = dnsCbUpstream;
        cfg.rand32 = dnsCbRand;
        cfg.wdt_kick = dnsCbWdt;
        cfg.log = dnsCbLog;

        int r = apex_dns_run(&cfg);           // chỉ trả về khi lỗi socket
        Serial.printf("❌ DNS server dừng (%d), thử lại sau 2s\n", r);
        for (int i = 0; i < 4; i++) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}

// ================= HTTP HELPERS =================
static void sendText(AsyncWebServerRequest *r, int code, const char *msg) {
    r->send(code, "text/plain; charset=utf-8", msg);
}

static void redirectToPortal(AsyncWebServerRequest *r) {
    AsyncWebServerResponse *resp = r->beginResponse(302);
    resp->addHeader("Location", "http://192.168.4.1/");
    r->send(resp);
}

// Chỉ phục vụ kết nối tới địa chỉ IP của AP; chặn truy cập từ phía mạng uplink (STA).
static bool onApSide(AsyncWebServerRequest *r) {
    return IPAddress(r->client()->localIP()) == AP_IP;
}

#define REQUIRE_AP_SIDE(r)                                   \
    do {                                                     \
        if (!onApSide(r)) { sendText(r, 403, "Forbidden"); return; } \
    } while (0)

void handleCaptive204(AsyncWebServerRequest *r) {
    REQUIRE_AP_SIDE(r);
    if (isInternetAvailable()) r->send(204);
    else redirectToPortal(r);
}

void handleCaptiveSuccess(AsyncWebServerRequest *r) {
    REQUIRE_AP_SIDE(r);
    if (isInternetAvailable()) r->send(404);
    else redirectToPortal(r);
}

void handleCaptiveApple(AsyncWebServerRequest *r) {
    REQUIRE_AP_SIDE(r);
    if (isInternetAvailable()) {
        r->send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
    } else {
        redirectToPortal(r);
    }
}

void handleCaptiveNcsi(AsyncWebServerRequest *r) {
    REQUIRE_AP_SIDE(r);
    if (isInternetAvailable()) r->send(200, "text/plain", "Microsoft NCSI");
    else redirectToPortal(r);
}

// ================= BOARD / VALIDATION =================
void detectBoardCapabilities() {
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    switch (chip_info.model) {
        case CHIP_ESP32:    board_model = "ESP32"; board_supports_5ghz = false; break;
        case CHIP_ESP32S2:  board_model = "ESP32-S2"; board_supports_5ghz = false; break;
        case CHIP_ESP32S3:  board_model = "ESP32-S3"; board_supports_5ghz = false; break;
        case CHIP_ESP32C3:  board_model = "ESP32-C3"; board_supports_5ghz = false; break;
        case CHIP_ESP32C5:  board_model = "ESP32-C5"; board_supports_5ghz = true; break;
        case CHIP_ESP32C6:  board_model = "ESP32-C6"; board_supports_5ghz = false; break;
        case CHIP_ESP32H2:  board_model = "ESP32-H2"; board_supports_5ghz = false; break;
        case CHIP_ESP32P4:  board_model = "ESP32-P4"; board_supports_5ghz = false; break;
        default:            board_model = "ESP32 (Unknown)"; board_supports_5ghz = false; break;
    }
    Serial.printf("🔍 Board Detected: %s\n", board_model.c_str());
    if (!board_supports_5ghz && use_5ghz) {
        use_5ghz = false;
        Serial.println("⚠️ Board does not support 5GHz - Forcing 2.4GHz mode");
    }
}

bool isValidChannel(int ch, bool is5GHz) {
    if (!board_supports_5ghz && is5GHz) return false;
    if (is5GHz) return (ch >= CHANNEL_5G_MIN && ch <= CHANNEL_5G_MAX);
    return (ch >= CHANNEL_2G_MIN && ch <= CHANNEL_2G_MAX);
}

int validateChannel(int ch, bool is5GHz) {
    if (!board_supports_5ghz && is5GHz) return DEFAULT_AP_CHANNEL;
    if (isValidChannel(ch, is5GHz)) return ch;
    return is5GHz ? CHANNEL_5G_36 : DEFAULT_AP_CHANNEL;
}

int validateMaxClients(int clients) {
    if (clients >= MIN_CLIENTS && clients <= MAX_CLIENTS_LIMIT) return clients;
    return DEFAULT_MAX_CLIENTS;
}

// ================= WATCHDOG =================
static void configureWatchdog() {
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
    esp_task_wdt_config_t cfg = {};
    cfg.timeout_ms = WATCHDOG_TIMEOUT * 1000;
    cfg.idle_core_mask = 0;
    cfg.trigger_panic = true;
    // Core Arduino đã khởi tạo TWDT sẵn (timeout mặc định rất ngắn) => phải reconfigure,
    // gọi init sẽ bị từ chối và timeout 45 s không bao giờ có hiệu lực.
    esp_err_t e = esp_task_wdt_reconfigure(&cfg);
    if (e == ESP_ERR_INVALID_STATE) e = esp_task_wdt_init(&cfg);
    if (e != ESP_OK) Serial.printf("⚠️ Cấu hình watchdog thất bại: %s\n", esp_err_to_name(e));
#elif ESP_IDF_VERSION_MAJOR >= 5
    esp_task_wdt_config_t cfg = {};
    cfg.timeout_ms = WATCHDOG_TIMEOUT * 1000;
    cfg.idle_core_mask = 0;
    cfg.trigger_panic = true;
    esp_task_wdt_init(&cfg);
#else
    esp_task_wdt_init(WATCHDOG_TIMEOUT, true);
#endif
}

// ================= WIFI EVENT HANDLER =================
void wifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (sta_configured) esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        bool should_retry = false;
        xSemaphoreTake(staStateMutex, portMAX_DELAY);
        sta_disconnected = true;
        if (s_retry_num < STA_MAX_RETRY) { s_retry_num++; should_retry = true; }
        int retry = s_retry_num;
        xSemaphoreGive(staStateMutex);

        // Trước đây bit CONNECTED không bao giờ bị xoá => trạng thái "đã kết nối" bị kẹt và
        // staReconnectTask không bao giờ chạy lại sau khi mất kết nối.
        xEventGroupClearBits(wifiEventGroup, WIFI_CONNECTED_BIT);
        if (should_retry) {
            esp_wifi_connect();
            Serial.printf("Retry connecting... (%d/%d)\n", retry, STA_MAX_RETRY);
        } else {
            xEventGroupSetBits(wifiEventGroup, WIFI_FAIL_BIT);
            Serial.printf("STA retry exhausted, background retry every %d s\n", STA_RECONNECT_BACKOFF_MS / 1000);
        }
        disableNAT();
        internetOK.store(false);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        Serial.printf("Got IP: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        xSemaphoreTake(staStateMutex, portMAX_DELAY);
        s_retry_num = 0;
        sta_disconnected = false;
        xSemaphoreGive(staStateMutex);
        xEventGroupClearBits(wifiEventGroup, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifiEventGroup, WIFI_CONNECTED_BIT);
        // Đánh thức internetCheckTask ngay để điện thoại không cache kết luận "no internet".
        if (internetCheckTrigger != nullptr) xSemaphoreGive(internetCheckTrigger);
    }
}

void staReconnectTask(void *pv) {
    esp_task_wdt_add(nullptr);
    for (;;) {
        esp_task_wdt_reset();
        EventBits_t bits = xEventGroupGetBits(wifiEventGroup);
        bool should_connect = false;
        xSemaphoreTake(staStateMutex, portMAX_DELAY);
        if (sta_configured && !(bits & WIFI_CONNECTED_BIT) && sta_disconnected) {
            should_connect = true;
            sta_disconnected = false;
        }
        xSemaphoreGive(staStateMutex);

        if (should_connect) {
            Serial.println("Background STA reconnect attempt...");
            esp_err_t err = esp_wifi_connect();
            if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
                xSemaphoreTake(staStateMutex, portMAX_DELAY);
                sta_disconnected = true;
                xSemaphoreGive(staStateMutex);
                Serial.printf("esp_wifi_connect failed: %s\n", esp_err_to_name(err));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(STA_RECONNECT_BACKOFF_MS));
    }
}

// ================= AUTH =================
bool checkAuthAndRate(AsyncWebServerRequest *r) {
    auto tok = r->getParam("token", true);
    if (tok == nullptr || !apex_ct_equal(tok->value().c_str(), sessionToken.c_str())) {
        sendText(r, 401, "Chưa đăng nhập hoặc token không hợp lệ");
        return false;
    }
    uint32_t now = millis();
    if ((uint32_t)(now - lastConfigRequestWindow) > CONFIG_RATE_WINDOW_MS) {
        lastConfigRequestWindow = now;
        configRequestCount = 0;
    }
    configRequestCount++;
    if (configRequestCount > CONFIG_RATE_MAX_REQ) {
        sendText(r, 429, "Quá nhiều yêu cầu, vui lòng thử lại sau");
        return false;
    }
    return true;
}

// ================= TASKS =================
void networkTask(void * pv) {
    esp_task_wdt_add(nullptr);
    for (;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        // Hysteresis: tắt NAT khi RAM < ngưỡng nguy hiểm, chỉ cho bật lại khi RAM hồi phục.
        bool prev = memPressure.load();
        bool now_p = apex_mem_pressure(prev ? 1 : 0, currHeap) != 0;
        memPressure.store(now_p);
        if (now_p && !prev) {
            Serial.printf("⚠️ RAM thấp (%u B) - tắt NAT\n", (unsigned)currHeap);
            disableNAT();
            internetOK.store(false);
        } else if (!now_p && prev) {
            Serial.printf("✅ RAM đã hồi phục (%u B)\n", (unsigned)currHeap);
            if (internetCheckTrigger != nullptr) xSemaphoreGive(internetCheckTrigger);
        }

        lastRSSI.store((WiFi.status() == WL_CONNECTED) ? WiFi.RSSI() : -100);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void internetCheckTask(void *pv) {
    esp_task_wdt_add(nullptr);
    for (;;) {
        esp_task_wdt_reset();

        bool sta_connected = (xEventGroupGetBits(wifiEventGroup) & WIFI_CONNECTED_BIT) != 0;
        bool reachable = sta_connected ? performInternetCheck() : false;
        esp_task_wdt_reset();

        // Chỉ bật NAT khi thật sự có internet VÀ RAM không thấp.
        bool should_be_online = sta_connected && reachable && !memPressure.load();

        if (should_be_online) {
            if (!natEnabled.load()) {
                if (!enableNAT()) should_be_online = false;
            }
        } else {
            if (natEnabled.load()) disableNAT();
        }
        internetOK.store(should_be_online);

        if (should_be_online) {
            Serial.println("✅ Internet: ONLINE");
        } else {
            Serial.printf("❌ Internet: OFFLINE (STA=%d, Reachable=%d, MemLow=%d)\n",
                          sta_connected, reachable, (int)memPressure.load());
        }
        xSemaphoreTake(internetCheckTrigger, pdMS_TO_TICKS(10000));
    }
}

// ================= SETUP =================
static void makeSessionToken() {
    char buf[33];
    snprintf(buf, sizeof(buf), "%08x%08x%08x%08x",
             (unsigned)esp_random(), (unsigned)esp_random(), (unsigned)esp_random(), (unsigned)esp_random());
    sessionToken = buf;
}

void setup() {
    Serial.begin(115200);
    delay(100);

    configureWatchdog();   // phải xong TRƯỚC khi các task gọi esp_task_wdt_add

    detectBoardCapabilities();
    prefs.begin("apex-v22", false);
    staStateMutex = xSemaphoreCreateMutex();
    internetCheckTrigger = xSemaphoreCreateBinary();
    wifiEventGroup = xEventGroupCreate();

    sta_ssid = prefs.getString("sta_ssid", "");
    sta_pass = prefs.getString("sta_pass", "");
    if (sta_ssid.length() > 0 && !apex_valid_ssid(sta_ssid.c_str())) sta_ssid = "";
    ap_ssid = prefs.getString("ap_ssid", APEX_DEFAULT_AP_SSID);
    if (!apex_valid_ssid(ap_ssid.c_str())) ap_ssid = APEX_DEFAULT_AP_SSID;   // tránh AP không SSID => không vào được
    ap_pass = prefs.getString("ap_pass", APEX_DEFAULT_AP_PASS);
    if (!apex_valid_wpa_pass(ap_pass.c_str())) ap_pass = APEX_DEFAULT_AP_PASS;
    sta_configured = (sta_ssid.length() > 0);

    if (board_supports_5ghz) {
        use_5ghz = prefs.getBool("use_5ghz", DEFAULT_BAND_5GHZ);
    }
    ap_channel = validateChannel(prefs.getInt("ap_channel", DEFAULT_AP_CHANNEL), use_5ghz);
    ap_hidden = prefs.getBool("ap_hidden", DEFAULT_AP_HIDDEN);
    max_clients = validateMaxClients(prefs.getInt("max_clients", DEFAULT_MAX_CLIENTS));

    Serial.printf("\n=== APEX ULTRA V%s ===\n\n", APEX_VERSION);
    if (apex_ct_equal(ap_pass.c_str(), APEX_DEFAULT_AP_PASS)) {
        Serial.println("⚠️ CẢNH BÁO: đang dùng mật khẩu AP mặc định, hãy đổi ngay!");
    }

    WiFi.persistent(false);          // cấu hình do ứng dụng tự lưu trong NVS
    WiFi.setAutoReconnect(false);    // tự quản lý reconnect (wifiEventHandler + staReconnectTask)
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, ap_hidden ? 1 : 0, max_clients);

    s_ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (s_ap_netif == nullptr) {
        Serial.println("❌ Không lấy được AP netif handle - NAT sẽ không hoạt động!");
    }
    makeSessionToken();   // sau khi WiFi đã chạy: esp_random() là RNG phần cứng thật

    Serial.printf("📡 AP: %s | Ch:%d | IP: %s\n", ap_ssid.c_str(), ap_channel, AP_IP.toString().c_str());

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifiEventHandler, nullptr, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifiEventHandler, nullptr, nullptr));

    if (sta_ssid.length() > 0) {
        WiFi.begin(sta_ssid.c_str(), sta_pass.c_str());
        Serial.printf("📡 Connecting to STA: %s\n", sta_ssid.c_str());
    } else {
        Serial.printf("⚠️ Connect to AP: %s | http://%s\n", ap_ssid.c_str(), AP_IP.toString().c_str());
    }

    // ---------- Trang chính + API ----------
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        r->send(200, "text/html; charset=utf-8", APEX_INDEX_HTML);
    });

    // POST /login (pass=<mật khẩu AP>) -> {"token":"..."}
    server.on("/login", HTTP_POST, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        uint32_t now = millis();
        if (loginLockUntilMs != 0 && (int32_t)(loginLockUntilMs - now) > 0) {
            char msg[64];
            snprintf(msg, sizeof(msg), "Sai quá nhiều lần. Thử lại sau %u giây",
                     (unsigned)((loginLockUntilMs - now) / 1000 + 1));
            sendText(r, 429, msg);
            return;
        }
        auto p = r->getParam("pass", true);
        bool ok = (p != nullptr) && apex_ct_equal(p->value().c_str(), ap_pass.c_str());
        if (ok) {
            loginFailCount = 0;
            loginLockUntilMs = 0;
        } else if (++loginFailCount >= LOGIN_MAX_FAILS) {
            loginFailCount = 0;
            loginLockUntilMs = millis() + LOGIN_LOCKOUT_MS;
            if (loginLockUntilMs == 0) loginLockUntilMs = 1;
        }
        if (!ok) { sendText(r, 401, "Sai mật khẩu"); return; }

        String json = "{\"token\":\"" + sessionToken + "\"}";
        AsyncWebServerResponse *resp = r->beginResponse(200, "application/json", json);
        resp->addHeader("Cache-Control", "no-store");
        r->send(resp);
    });

    server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        JsonDocument doc;
        doc["ram"] = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        doc["internet"] = internetOK.load();
        doc["nat"] = natEnabled.load();
        doc["memLow"] = memPressure.load();
        doc["rssi"] = lastRSSI.load();
        doc["clients"] = (int)WiFi.softAPgetStationNum();
        doc["clientLimit"] = max_clients;
        doc["staConnected"] = (xEventGroupGetBits(wifiEventGroup) & WIFI_CONNECTED_BIT) != 0;
        doc["staSsid"] = sta_ssid;
        doc["weakPassword"] = apex_ct_equal(ap_pass.c_str(), APEX_DEFAULT_AP_PASS);
        String out;
        serializeJson(doc, out);
        r->send(200, "application/json", out);
    });

    server.on("/api/config", HTTP_GET, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        JsonDocument doc;
        doc["apSsid"] = ap_ssid;
        doc["staSsid"] = sta_ssid;
        String out;
        serializeJson(doc, out);
        r->send(200, "application/json", out);
    });

    server.on("/api/clients", HTTP_GET, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();
        wifi_sta_list_t wifi_sta_list;
        if (esp_wifi_ap_get_sta_list(&wifi_sta_list) == ESP_OK && s_ap_netif != nullptr) {
            int num = wifi_sta_list.num;
            if (num > 10) num = 10;
            if (num > 0) {
                esp_netif_pair_mac_ip_t pairs[10] = {};
                for (int i = 0; i < num; i++) memcpy(pairs[i].mac, wifi_sta_list.sta[i].mac, 6);
                esp_netif_dhcps_get_clients_by_mac(s_ap_netif, num, pairs);
                for (int i = 0; i < num; i++) {
                    JsonObject c = arr.add<JsonObject>();
                    char m[18];
                    snprintf(m, sizeof(m), "%02X:%02X:%02X:%02X:%02X:%02X",
                             pairs[i].mac[0], pairs[i].mac[1], pairs[i].mac[2],
                             pairs[i].mac[3], pairs[i].mac[4], pairs[i].mac[5]);
                    c["mac"] = m;
                    c["ip"] = IPAddress(pairs[i].ip.addr).toString();
                }
            }
        }
        String out;
        serializeJson(doc, out);
        r->send(200, "application/json", out);
    });

    // ---------- Lưu cấu hình (cần token) ----------
    server.on("/save-sta", HTTP_POST, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        if (!checkAuthAndRate(r)) return;
        auto ps = r->getParam("ssid", true);
        auto pp = r->getParam("pass", true);
        String ssid = ps ? ps->value() : String("");
        String pass = pp ? pp->value() : String("");
        if (!apex_valid_ssid(ssid.c_str())) {
            sendText(r, 400, "Tên WiFi phải dài 1-32 byte");
            return;
        }
        if (pass.length() > 0 && !apex_valid_wpa_pass(pass.c_str())) {
            sendText(r, 400, "Mật khẩu WiFi phải dài 8-63 ký tự (hoặc để trống nếu mạng mở)");
            return;
        }
        prefs.putString("sta_ssid", ssid);
        prefs.putString("sta_pass", pass);
        sendText(r, 200, "Đã lưu. Thiết bị đang khởi động lại, sẽ mất kết nối vài giây...");
        scheduleRestart(1500);
    });

    server.on("/save-ap", HTTP_POST, [](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        if (!checkAuthAndRate(r)) return;
        auto ps = r->getParam("ssid", true);
        auto pp = r->getParam("pass", true);
        auto pc = r->getParam("channel", true);
        String ssid = ps ? ps->value() : String("");
        String pass = pp ? pp->value() : String("");
        String chs = pc ? pc->value() : String("");

        bool changeSsid = (ssid.length() > 0);
        bool changePass = (pass.length() > 0);
        bool changeCh = (chs.length() > 0);
        if (changeSsid && !apex_valid_ssid(ssid.c_str())) {
            sendText(r, 400, "Tên WiFi phải dài 1-32 byte, không chứa ký tự điều khiển");
            return;
        }
        if (changePass && !apex_valid_wpa_pass(pass.c_str())) {
            sendText(r, 400, "Mật khẩu AP phải dài 8-63 ký tự");
            return;
        }
        int ch = chs.toInt();
        if (changeCh && !isValidChannel(ch, use_5ghz)) {
            sendText(r, 400, "Kênh WiFi không hợp lệ");
            return;
        }
        if (changeSsid && ssid == ap_ssid) changeSsid = false;
        if (changePass && pass == ap_pass) changePass = false;
        if (changeCh && ch == ap_channel) changeCh = false;
        if (!changeSsid && !changePass && !changeCh) {
            sendText(r, 200, "Không có thay đổi nào để lưu.");
            return;
        }
        if (changeSsid) prefs.putString("ap_ssid", ssid);
        if (changePass) prefs.putString("ap_pass", pass);
        if (changeCh) prefs.putInt("ap_channel", ch);
        sendText(r, 200, "Đã lưu. Thiết bị đang khởi động lại, hãy kết nối lại bằng thông tin mới...");
        scheduleRestart(1500);
    });

    // ---------- Captive portal HTTP ----------
    server.on("/generate_204", HTTP_GET, handleCaptive204);
    server.on("/connectivity-check", HTTP_GET, handleCaptive204);
    server.on("/captive", HTTP_GET, handleCaptive204);
    server.on("/canonical.html", HTTP_GET, handleCaptive204);
    server.on("/apple-sd", HTTP_GET, handleCaptive204);
    server.on("/success", HTTP_GET, handleCaptiveSuccess);
    server.on("/hotspot-detect.html", HTTP_GET, handleCaptiveApple);
    server.on("/library/test/success.html", HTTP_GET, handleCaptiveApple);
    server.on("/ncsi.txt", HTTP_GET, handleCaptiveNcsi);

    // URL lạ: khi chưa có internet thì đưa về trang chính (captive portal), ngược lại trả 404.
    server.onNotFound([](AsyncWebServerRequest *r){
        REQUIRE_AP_SIDE(r);
        if (!isInternetAvailable()) redirectToPortal(r);
        else r->send(404, "text/plain", "Not found");
    });
    server.begin();

    xTaskCreate(dnsCaptiveTask, "DNS_CAPTIVE", 4096, nullptr, 5, nullptr);
    xTaskCreate(internetCheckTask, "INET_CHECK", 6144, nullptr, 2, nullptr);
    xTaskCreate(staReconnectTask, "STA_RECONNECT", 3072, nullptr, 2, nullptr);
    esp_task_wdt_add(nullptr);
    xTaskCreatePinnedToCore(networkTask, "NET", 4096, nullptr, 4, nullptr, 0);

    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, LOW); delay(80);
        digitalWrite(LED_BUILTIN, HIGH); delay(80);
    }

    Serial.printf("✅ APEX ULTRA V%s Ready on %s!\n", APEX_VERSION, board_model.c_str());
    Serial.println("🔐 Cấu hình: mở http://192.168.4.1 và đăng nhập bằng mật khẩu AP");
}

void loop() {
    esp_task_wdt_reset();
    uint32_t t = restartAtMs;
    if (t != 0 && (int32_t)(millis() - t) >= 0) {
        ESP.restart();
    }
    vTaskDelay(10);
}
