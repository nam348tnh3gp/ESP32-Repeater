/*
   ESP32 NAT ROUTER - V22.3.0 (FIXED, đồng bộ đầy đủ với main.c mới nhất)
   Kế thừa toàn bộ fix từ V22.2.0, PORT THÊM từ main.c:
     - DNS captive-portal thông minh: forward thật lên 8.8.8.8 khi có internet,
       chỉ spoof domain kiểm tra captive-portal khi CHƯA có internet.
     - HTTP handler bắt các domain kiểm tra captive-portal
       (generate_204, hotspot-detect.html, ncsi.txt, success, ...).
     - perform_internet_check() qua HTTP GET thật (generate_204) thay vì chỉ
       connect TCP thô tới 1.1.1.1:53 (không phản ánh đúng internet thật).
     - FIX race "no internet": semaphore đánh thức kiểm tra internet NGAY khi
       STA vừa có IP, thay vì chờ hết chu kỳ định kỳ - đây là nguyên nhân
       khiến điện thoại cache nhầm "no internet" dù dashboard báo online.
     - STA retry/reconnect nền đầy đủ (s_retry_num, sta_disconnected,
       sta_reconnect_task) - trước đây .ino chỉ gọi WiFi.begin() 1 lần.
     - Form Save chuyển sang POST + AJAX (không reload trang), có prefill
       cấu hình hiện tại (/api/config), /api/clients tách riêng.
     - NAT giờ chỉ bật khi THẬT SỰ có internet (không chỉ WiFi.status()==
       WL_CONNECTED), khớp đúng logic main.c.
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
#include <atomic>

#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>

// ================= BOARD DETECTION =================
#define CHANNEL_2G_MIN 1
#define CHANNEL_2G_MAX 13
#define CHANNEL_5G_MIN 36
#define CHANNEL_5G_MAX 165
#define CHANNEL_5G_36 36

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// ================= KERNEL DEFINITIONS =================
#define DEFAULT_NAPT_SLOTS 512
#define DEFAULT_NAPT_TCP   256
#define MEM_CRITICAL_THRESHOLD 26000
#define WATCHDOG_TIMEOUT 45
#define DEFAULT_MAX_CLIENTS 7

#define DEFAULT_AP_CHANNEL 1
#define DEFAULT_AP_HIDDEN 0
#define DEFAULT_BAND_5GHZ 0
#define MIN_CLIENTS 1
#define MAX_CLIENTS_LIMIT 10

#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3

#define STA_MAX_RETRY 5
#define STA_RECONNECT_BACKOFF_MS 30000

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GATEWAY(192, 168, 4, 1);
IPAddress AP_SUBNET(255, 255, 255, 0);

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
Preferences prefs;

String sta_ssid, sta_pass, ap_ssid, ap_pass;
std::atomic<bool> internetOK{false};
std::atomic<bool> internetReachable{false};
std::atomic<bool> natEnabled{false};
std::atomic<int> lastRSSI{-100};
std::atomic<int> currentClients{0};
unsigned long uptimeStart = 0;

String sessionToken;
unsigned long lastConfigRequestWindow = 0;
int configRequestCount = 0;

SemaphoreHandle_t prefsMutex = nullptr;
SemaphoreHandle_t staStateMutex = nullptr;

// FIX (race no-internet, port từ main.c): đánh thức internetCheckTask ngay
// khi STA vừa có IP, thay vì để nó chờ hết chu kỳ. Nếu không có fix này,
// điện thoại join AP ngay sau khi ESP32 vừa lên mạng sẽ nhận captive-check
// trả lời "chưa có internet" và HĐH sẽ CACHE lại kết luận đó, không tự kiểm
// tra lại - dù vài giây sau dashboard đã báo online thật.
SemaphoreHandle_t internetCheckTrigger = nullptr;

EventGroupHandle_t wifiEventGroup = nullptr;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static int s_retry_num = 0;              // bảo vệ bởi staStateMutex
static bool sta_configured = false;
static bool sta_disconnected = true;     // bảo vệ bởi staStateMutex

static esp_netif_t *s_ap_netif = nullptr;

// ================= CAPTIVE PORTAL DOMAINS (port từ main.c) =================
static const char* captive_domains[] = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "detectportal.firefox.com",
    "www.msftncsi.com",
    "captive.apple.com",
    "www.apple.com",
    "clients3.google.com",
    "nmcheck.gnome.org",
    "www.google.com",
    NULL
};

int ap_channel = DEFAULT_AP_CHANNEL;
bool ap_hidden = DEFAULT_AP_HIDDEN;
int max_clients = DEFAULT_MAX_CLIENTS;
bool use_5ghz = DEFAULT_BAND_5GHZ;

// nat_max_slots/nat_max_tcp: chỉ để hiển thị/lưu lại - kích thước bảng NAT
// thật do Kconfig của SDK quyết định (xem ghi chú V22.2.0).
int nat_max_slots = DEFAULT_NAPT_SLOTS;
int nat_max_tcp = DEFAULT_NAPT_TCP;

bool board_supports_5ghz = false;
String board_model = "Unknown";

// ================= NAT FUNCTIONS (esp_netif) =================
bool enableNAT() {
    if (natEnabled.load()) return true;
    if (s_ap_netif == nullptr) {
        Serial.println("❌ enableNAT: AP netif chưa sẵn sàng");
        return false;
    }
    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err == ESP_OK) {
        natEnabled.store(true);
        Serial.printf("✅ NAT Enabled (slots=%d, tcp=%d)\n", nat_max_slots, nat_max_tcp);
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

// ================= HÀM KIỂM TRA INTERNET (port từ main.c) =================
bool isInternetAvailable() {
    return internetOK.load();
}

// FIX (port từ main.c): kiểm tra internet bằng HTTP GET thật (generate_204)
// thay vì chỉ connect TCP thô tới 1.1.1.1:53 - phản ánh đúng khả năng
// duyệt web thật, không chỉ "cổng 53 có mở hay không".
bool performInternetCheck() {
    HTTPClient http;
    http.setConnectTimeout(5000);
    http.setTimeout(5000);
    if (!http.begin("http://connectivitycheck.gstatic.com/generate_204")) return false;
    int code = http.GET();
    http.end();
    return (code == 204 || code == 200);
}

// ================= CAPTIVE PORTAL DNS SERVER (port từ main.c) =================
static bool endsWithDomain(const char *qname, const char *domain) {
    size_t qname_len = strlen(qname);
    size_t domain_len = strlen(domain);
    if (qname_len < domain_len) return false;
    if (qname_len > 0 && qname[qname_len - 1] == '.') qname_len--;
    if (qname_len < domain_len) return false;
    const char *qname_end = qname + (qname_len - domain_len);
    return strncasecmp(qname_end, domain, domain_len) == 0;
}

void dnsCaptiveTask(void *pv) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t buffer[512];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        Serial.println("❌ DNS: Failed to create socket");
        vTaskDelete(nullptr);
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(53);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        Serial.println("❌ DNS: Failed to bind to port 53");
        close(sock);
        vTaskDelete(nullptr);
        return;
    }

    Serial.println("✅ DNS Captive Portal started on port 53");

    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (len > 0 && len >= 12) {
            bool internet = isInternetAvailable();

            if (internet) {
                // Có internet -> forward thật lên 8.8.8.8
                int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (upstream_sock < 0) {
                    uint8_t resp[512];
                    memcpy(resp, buffer, len);
                    resp[2] = 0x81; resp[3] = 0x80;
                    memset(resp + 4, 0, 8);
                    sendto(sock, resp, len, 0, (struct sockaddr *)&client_addr, addr_len);
                } else {
                    struct sockaddr_in upstream_addr;
                    upstream_addr.sin_family = AF_INET;
                    upstream_addr.sin_port = htons(53);
                    upstream_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

                    int sent = sendto(upstream_sock, buffer, len, 0, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
                    if (sent >= 0) {
                        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
                        setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                        uint8_t upstream_resp[512];
                        int up_len = recv(upstream_sock, upstream_resp, sizeof(upstream_resp), 0);
                        if (up_len > 0) {
                            sendto(sock, upstream_resp, up_len, 0, (struct sockaddr *)&client_addr, addr_len);
                        } else {
                            uint8_t resp[512];
                            memcpy(resp, buffer, len);
                            resp[2] = 0x81; resp[3] = 0x80;
                            memset(resp + 4, 0, 8);
                            sendto(sock, resp, len, 0, (struct sockaddr *)&client_addr, addr_len);
                        }
                    }
                    close(upstream_sock);
                }
            } else {
                // Chưa có internet -> chỉ spoof domain kiểm tra captive-portal
                char qname[256] = {0};
                int qname_len = 0;
                int pos = 12;
                bool parse_ok = true;
                bool compressed = false;
                while (pos < len && buffer[pos] != 0) {
                    uint8_t label_len = buffer[pos];
                    if ((label_len & 0xC0) == 0xC0) { compressed = true; break; }
                    pos++;
                    if (pos + label_len > len) { parse_ok = false; break; }
                    for (int i = 0; i < label_len; i++) {
                        if (qname_len < (int)sizeof(qname) - 1) qname[qname_len++] = buffer[pos++];
                        else { parse_ok = false; break; }
                    }
                    if (!parse_ok) break;
                    if (qname_len < (int)sizeof(qname) - 1) qname[qname_len++] = '.';
                }
                if (!parse_ok || compressed || qname_len == 0) { vTaskDelay(pdMS_TO_TICKS(1)); continue; }
                qname[qname_len] = '\0';

                bool is_captive_domain = false;
                for (int i = 0; captive_domains[i] != NULL; i++) {
                    if (endsWithDomain(qname, captive_domains[i])) { is_captive_domain = true; break; }
                }

                if (is_captive_domain) {
                    uint8_t response[512];
                    memcpy(response, buffer, len);
                    response[2] = 0x85; response[3] = 0x80;
                    memset(response + 4, 0, 8);
                    response[6] = 0x00; response[7] = 0x01;

                    int qname_end = 12;
                    bool has_compression = false;
                    while (qname_end < len && buffer[qname_end] != 0) {
                        uint8_t label_len = buffer[qname_end];
                        if ((label_len & 0xC0) == 0xC0) { has_compression = true; break; }
                        if (qname_end + 1 + label_len > len) break;
                        qname_end += 1 + label_len;
                    }
                    if (has_compression || qname_end >= len || buffer[qname_end] != 0) { vTaskDelay(pdMS_TO_TICKS(1)); continue; }

                    int off = qname_end + 1 + 4;
                    if (off > len || off + 16 > (int)sizeof(response)) { vTaskDelay(pdMS_TO_TICKS(1)); continue; }

                    response[off++] = 0xC0; response[off++] = 0x0C;
                    response[off++] = 0x00; response[off++] = 0x01;
                    response[off++] = 0x00; response[off++] = 0x01;
                    response[off++] = 0x00; response[off++] = 0x00;
                    response[off++] = 0x00; response[off++] = 0x3C;
                    response[off++] = 0x00; response[off++] = 0x04;
                    response[off++] = 192; response[off++] = 168;
                    response[off++] = 4;   response[off++] = 1;

                    sendto(sock, response, off, 0, (struct sockaddr *)&client_addr, addr_len);
                } else {
                    uint8_t resp[512];
                    memcpy(resp, buffer, len);
                    resp[2] = 0x81; resp[3] = 0x83;
                    memset(resp + 4, 0, 8);
                    sendto(sock, resp, len, 0, (struct sockaddr *)&client_addr, addr_len);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

// ================= CAPTIVE PORTAL HTTP HANDLERS (port từ main.c) =================
void handleCaptive204(AsyncWebServerRequest *r) {
    if (isInternetAvailable()) {
        r->send(204);
    } else {
        AsyncWebServerResponse *resp = r->beginResponse(302);
        resp->addHeader("Location", "http://192.168.4.1/");
        r->send(resp);
    }
}

void handleCaptiveSuccess(AsyncWebServerRequest *r) {
    if (isInternetAvailable()) {
        r->send(404);
    } else {
        AsyncWebServerResponse *resp = r->beginResponse(302);
        resp->addHeader("Location", "http://192.168.4.1/");
        r->send(resp);
    }
}

// ================= UTILS =================
String urlDecode(String str) {
    String decoded = "";
    char ch; int i, j;
    for (i = 0; i < (int)str.length(); i++) {
        if (str[i] == '%' && i + 2 < (int)str.length()) {
            j = 0;
            if (sscanf(str.substring(i + 1, i + 3).c_str(), "%x", &j) == 1) {
                ch = (char)j; decoded += ch; i += 2;
            } else {
                decoded += str[i];
            }
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

// ================= BOARD DETECTION =================
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

// ================= VALIDATION =================
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

String validateAPPassword(String pwd) {
    if (pwd.length() == 0 || pwd.length() < 8) return "12345678";
    return pwd;
}

int validateNATSlots(int slots, int tcp_ports) {
    if (slots < 64) slots = 64;
    if (slots > 4096) slots = 4096;
    if (slots < tcp_ports) slots = tcp_ports;
    return slots;
}

int validateNATTCP(int tcp) {
    if (tcp < 32) tcp = 32;
    if (tcp > 2048) tcp = 2048;
    return tcp;
}

// ================= WIFI EVENT HANDLER (port từ main.c: retry + IP_EVENT) =================
void wifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (sta_configured) esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        bool should_retry = false;
        xSemaphoreTake(staStateMutex, portMAX_DELAY);
        sta_disconnected = true;
        if (s_retry_num < STA_MAX_RETRY) { s_retry_num++; should_retry = true; }
        xSemaphoreGive(staStateMutex);

        if (should_retry) {
            esp_wifi_connect();
            Serial.printf("Retry connecting... (%d/%d)\n", s_retry_num, STA_MAX_RETRY);
        } else {
            xEventGroupSetBits(wifiEventGroup, WIFI_FAIL_BIT);
            Serial.printf("STA retry exhausted, will retry again in background every %d s\n", STA_RECONNECT_BACKOFF_MS / 1000);
        }
        disableNAT();
        internetOK.store(false);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        currentClients.fetch_add(1);
        Serial.printf("✅ Client connected | Total: %d/%d\n", currentClients.load(), max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        int newCount = currentClients.fetch_sub(1) - 1;
        if (newCount < 0) currentClients.store(0);
        Serial.printf("❌ Client disconnected | Total: %d/%d\n", currentClients.load(), max_clients);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        Serial.printf("Got IP: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        xSemaphoreTake(staStateMutex, portMAX_DELAY);
        s_retry_num = 0;
        sta_disconnected = false;
        xSemaphoreGive(staStateMutex);
        xEventGroupClearBits(wifiEventGroup, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifiEventGroup, WIFI_CONNECTED_BIT);
        // FIX (race no-internet): vừa có IP thì đánh thức internetCheckTask
        // kiểm tra NGAY, không chờ chu kỳ định kỳ tiếp theo.
        if (internetCheckTrigger != nullptr) xSemaphoreGive(internetCheckTrigger);
    }
}

// ================= TASK NỀN KẾT NỐI LẠI STA (port từ main.c) =================
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
            if (err != ESP_OK) {
                xSemaphoreTake(staStateMutex, portMAX_DELAY);
                sta_disconnected = true;
                xSemaphoreGive(staStateMutex);
                Serial.printf("esp_wifi_connect failed: %s\n", esp_err_to_name(err));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(STA_RECONNECT_BACKOFF_MS));
    }
}

// ================= AUTH / RATE LIMIT =================
bool checkAuthAndRate(AsyncWebServerRequest *r) {
    if (!r->hasParam("token", true) || r->getParam("token", true)->value() != sessionToken) {
        r->send(401, "text/plain", "❌ Unauthorized: token thiếu hoặc sai");
        return false;
    }
    unsigned long now = millis();
    if (now - lastConfigRequestWindow > CONFIG_RATE_WINDOW_MS) {
        lastConfigRequestWindow = now;
        configRequestCount = 0;
    }
    configRequestCount++;
    if (configRequestCount > CONFIG_RATE_MAX_REQ) {
        r->send(429, "text/plain", "❌ Quá nhiều yêu cầu, vui lòng thử lại sau");
        return false;
    }
    return true;
}

// ================= HTML UI (port từ main.c: POST+AJAX, prefill, staStatus) =================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<link rel='icon' href='data:,'>
<title>APEX ULTRA</title>
<style>
*{box-sizing:border-box;}body{font-family:Arial;background:#020617;color:#f8fafc;padding:15px;max-width:480px;margin:0 auto;}
.card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;}
label{display:block;font-size:13px;color:#94a3b8;margin-top:8px;}
input,select{width:100%;padding:12px;margin:4px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}
input:invalid{border-color:#f87171;}
button{width:100%;padding:14px;margin-top:10px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}
button:disabled{background:#475569;color:#94a3b8;cursor:wait;}
.warning{color:#f59e0b;margin-top:8px;}
.hint{font-size:12px;color:#64748b;margin:2px 0 0;}
.msg{font-size:13px;margin-top:8px;min-height:16px;}
.msg.ok{color:#4ade80;}.msg.err{color:#f87171;}
</style></head><body>
<div class='card'><h3>APEX ULTRA V22.3.0 (Fixed)</h3>
<div>RAM: <b id='ram'>0</b> KB</div>
<div>Internet: <span id='net'>WAIT</span></div>
<div>NAT: <span id='nat'>WAIT</span></div>
<div>Uplink: <span id='staStatus'>WAIT</span></div>
<div>Signal: <b id='rssi'>-</b> dBm</div>
<div>Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>7</b></div>
<div id='ctable' style='font-size:12px;margin-top:6px;'>-</div>
<div id='weakWarn' class='warning' style='display:none;'>⚠️ Đang dùng mật khẩu AP mặc định — hãy đổi ngay!</div>
<div id='pollErr' class='msg err' style='display:none;'>⚠️ Mất kết nối tới thiết bị — đang thử lại...</div>
</div>
<div class='card'><h3>Uplink Configuration</h3>
<form id='staForm' action='/save-sta' method='post'>
<label for='staSsidInp'>Tên WiFi cần kết nối</label>
<input name='ssid' id='staSsidInp' placeholder='WiFi Name' required maxlength='32'>
<label for='staPassInp'>Mật khẩu</label>
<input name='pass' id='staPassInp' type='password' placeholder='Password' maxlength='63'>
<input type='hidden' name='token' class='tokenField' value=''>
<button type='submit'>Connect</button>
<div class='msg' id='staMsg'></div>
</form></div>
<div class='card'><h3>AP Configuration</h3>
<form id='apForm' action='/save-ap' method='post'>
<label for='apSsidInp'>Tên WiFi phát ra (AP SSID)</label>
<input name='ssid' id='apSsidInp' placeholder='AP SSID' maxlength='32'>
<label for='apPassInp'>Mật khẩu mới (tối thiểu 8 ký tự)</label>
<input name='pass' id='apPassInp' type='password' placeholder='Password (min 8)' minlength='8' maxlength='63'>
<p class='hint'>Để trống nếu không muốn đổi mật khẩu.</p>
<input name='channel' placeholder='Channel (1-13)' value=''>
<input type='hidden' name='token' class='tokenField' value=''>
<button type='submit'>Save & Reboot</button>
<div class='msg' id='apMsg'></div>
</form></div>
<div class='card'><h3>NAT Settings</h3>
<form id='natForm' action='/save-nat' method='post'>
<label for='natSlotsInp'>NAPT Slots (64-4096)</label>
<input name='slots' id='natSlotsInp' type='number' min='64' max='4096' placeholder='NAPT Slots' value='512'>
<label for='natTcpInp'>TCP ports (32-2048)</label>
<input name='tcp' id='natTcpInp' type='number' min='32' max='2048' placeholder='TCP ports' value='256'>
<input type='hidden' name='token' class='tokenField' value=''>
<button type='submit'>Save & Reboot</button>
<div class='msg' id='natMsg'></div>
</form></div>
<script>
let pollFailed=0;
function fetchData(){fetch('/api/status').then(r=>r.json()).then(d=>{
pollFailed=0;document.getElementById('pollErr').style.display='none';
document.getElementById('ram').innerText=Math.round(d.ram/1024);
document.getElementById('net').innerText=d.internet?'ONLINE':'OFFLINE';
document.getElementById('nat').innerText=d.nat?'ACTIVE':'OFF';
document.getElementById('staStatus').innerText=d.staConnected?('Connected: '+d.staSsid):(d.staSsid?'Connecting to '+d.staSsid+'...':'Not configured');
document.getElementById('rssi').innerText=d.staConnected?d.rssi:'-';
document.getElementById('clientCount').innerText=d.clientCount;
document.getElementById('clientLimit').innerText=d.clientLimit;
document.getElementById('weakWarn').style.display=d.weakPassword?'block':'none';
}).catch(()=>{pollFailed++;if(pollFailed>=2)document.getElementById('pollErr').style.display='block';});}
setInterval(fetchData,2000);fetchData();
function fetchClients(){fetch('/api/clients').then(r=>r.json()).then(list=>{
const el=document.getElementById('ctable');
if(!list.length){el.innerHTML='<i>No clients</i>';return;}
el.innerHTML=list.map(c=>`<div>• ${c.ip} <small>[${c.mac}]</small></div>`).join('');
}).catch(()=>{});}
setInterval(fetchClients,5000);fetchClients();
function loadConfig(){fetch('/api/config').then(r=>r.json()).then(c=>{
document.getElementById('apSsidInp').value=c.apSsid;
if(c.staSsid){document.getElementById('staSsidInp').value=c.staSsid;}
});}
loadConfig();
fetch('/get-token').then(r=>r.json()).then(t=>{
document.querySelectorAll('.tokenField').forEach(el=>el.value=t.token);
});
function bindForm(formId,msgId,rebootWarn){
const form=document.getElementById(formId);
const msg=document.getElementById(msgId);
const btn=form.querySelector('button');
form.addEventListener('submit',function(ev){
ev.preventDefault();
btn.disabled=true;btn.innerText='Đang lưu...';
msg.className='msg';msg.innerText='';
fetch(form.action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(form)).toString()})
.then(async r=>{const t=await r.text();if(r.ok){msg.className='msg ok';msg.innerText=t+(rebootWarn?' Thiết bị sẽ mất kết nối vài giây...':'');}
else{msg.className='msg err';msg.innerText=t;btn.disabled=false;btn.innerText='Retry';}})
.catch(()=>{msg.className='msg err';msg.innerText='Không thể kết nối tới thiết bị.';btn.disabled=false;btn.innerText='Retry';});
});}
bindForm('staForm','staMsg',true);
bindForm('apForm','apMsg',true);
bindForm('natForm','natMsg',true);
</script></body></html>
)rawliteral";

// ================= NETWORK TASK (chỉ còn broadcast + client list) =================
void networkTask(void * pv) {
    esp_task_wdt_add(nullptr);
    static uint32_t lastBroadcast = 0;

    for (;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        if (currHeap < MEM_CRITICAL_THRESHOLD && natEnabled.load()) {
            disableNAT();
            Serial.println("⚠️ Memory critical - NAT disabled");
        }

        lastRSSI.store((WiFi.status() == WL_CONNECTED) ? WiFi.RSSI() : -100);

        if (millis() - lastBroadcast > 2000) {
            JsonDocument doc;
            doc["ram"] = currHeap;
            doc["internet"] = internetOK.load();
            doc["nat"] = natEnabled.load();
            doc["rssi"] = lastRSSI.load();
            doc["clientCount"] = currentClients.load();
            doc["clientLimit"] = max_clients;
            doc["weakPassword"] = (ap_pass == "12345678");

            String out;
            serializeJson(doc, out);
            ws.textAll(out);
            lastBroadcast = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ================= INTERNET CHECK TASK (port từ main.c) =================
// FIX: NAT giờ chỉ bật khi THẬT SỰ có internet (kiểm tra HTTP thật), không
// chỉ dựa vào WiFi.status()==WL_CONNECTED như bản cũ.
void internetCheckTask(void *pv) {
    esp_task_wdt_add(nullptr);
    for (;;) {
        esp_task_wdt_reset();

        bool sta_connected = (xEventGroupGetBits(wifiEventGroup) & WIFI_CONNECTED_BIT) != 0;
        bool reachable = sta_connected ? performInternetCheck() : false;
        internetReachable.store(reachable);

        bool should_be_online = sta_connected && reachable;

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
            Serial.printf("❌ Internet: OFFLINE (STA=%d, Reachable=%d)\n", sta_connected, reachable);
        }

        // FIX (race no-internet): chờ tối đa 10s, đánh thức ngay nếu STA vừa
        // có IP (xem wifiEventHandler).
        xSemaphoreTake(internetCheckTrigger, pdMS_TO_TICKS(10000));
    }
}

// ================= SETUP =================
void setup() {
    Serial.begin(115200);
    delay(100);
    uptimeStart = millis();

    detectBoardCapabilities();
    prefs.begin("apex-v22", false);
    prefsMutex = xSemaphoreCreateMutex();
    staStateMutex = xSemaphoreCreateMutex();
    internetCheckTrigger = xSemaphoreCreateBinary();
    wifiEventGroup = xEventGroupCreate();

    sta_ssid = prefs.getString("sta_ssid", "");
    sta_pass = prefs.getString("sta_pass", "");
    ap_ssid = prefs.getString("ap_ssid", "APEX_ULTRA");
    ap_pass = validateAPPassword(prefs.getString("ap_pass", "12345678"));
    sta_configured = (sta_ssid.length() > 0);

    if (board_supports_5ghz) {
        use_5ghz = prefs.getBool("use_5ghz", DEFAULT_BAND_5GHZ);
    }

    ap_channel = validateChannel(prefs.getInt("ap_channel", DEFAULT_AP_CHANNEL), use_5ghz);
    ap_hidden = prefs.getBool("ap_hidden", DEFAULT_AP_HIDDEN);
    max_clients = validateMaxClients(prefs.getInt("max_clients", DEFAULT_MAX_CLIENTS));

    int saved_tcp = validateNATTCP(prefs.getInt("nat_tcp", DEFAULT_NAPT_TCP));
    int saved_slots = validateNATSlots(prefs.getInt("nat_slots", DEFAULT_NAPT_SLOTS), saved_tcp);
    nat_max_slots = saved_slots;
    nat_max_tcp = saved_tcp;

    sessionToken = String((uint32_t)esp_random(), HEX) + String((uint32_t)esp_random(), HEX);

    Serial.println("\n=== APEX ULTRA V22.3.0 - FIXED BUILD ===\n");
    if (ap_pass == "12345678") {
        Serial.println("⚠️ CẢNH BÁO: đang dùng mật khẩu AP mặc định, hãy đổi ngay!");
    }

    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, ap_hidden ? 1 : 0, max_clients);

    s_ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (s_ap_netif == nullptr) {
        Serial.println("❌ Không lấy được AP netif handle - NAT sẽ không hoạt động!");
    }

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

    server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){ r->send_P(200, "text/html", index_html); });

    server.on("/get-token", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"token\":\"" + sessionToken + "\"}";
        r->send(200, "application/json", json);
    });

    server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest *r){
        JsonDocument doc;
        doc["ram"] = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        doc["internet"] = internetOK.load();
        doc["nat"] = natEnabled.load();
        doc["rssi"] = lastRSSI.load();
        doc["clientCount"] = currentClients.load();
        doc["clientLimit"] = max_clients;
        bool staConnected = (xEventGroupGetBits(wifiEventGroup) & WIFI_CONNECTED_BIT) != 0;
        doc["staConnected"] = staConnected;
        doc["staSsid"] = sta_ssid;
        doc["weakPassword"] = (ap_pass == "12345678");
        String out;
        serializeJson(doc, out);
        r->send(200, "application/json", out);
    });

    server.on("/api/config", HTTP_GET, [](AsyncWebServerRequest *r){
        JsonDocument doc;
        doc["apSsid"] = ap_ssid;
        doc["staSsid"] = sta_ssid;
        String out;
        serializeJson(doc, out);
        r->send(200, "application/json", out);
    });

    server.on("/api/clients", HTTP_GET, [](AsyncWebServerRequest *r){
        JsonDocument doc;
        JsonArray arr = doc.to<JsonArray>();
        wifi_sta_list_t wifi_sta_list;
        if (esp_wifi_ap_get_sta_list(&wifi_sta_list) == ESP_OK && s_ap_netif != nullptr) {
            int num = wifi_sta_list.num;
            if (num > 10) num = 10;
            if (num > 0) {
                esp_netif_pair_mac_ip_t pairs[10] = {0};
                for (int i = 0; i < num; i++) memcpy(pairs[i].mac, wifi_sta_list.sta[i].mac, 6);
                esp_netif_dhcps_get_clients_by_mac(s_ap_netif, num, pairs);
                for (int i = 0; i < num; i++) {
                    JsonObject c = arr.add<JsonObject>();
                    char m[18];
                    sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X",
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

    server.on("/save-sta", HTTP_POST, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("ssid", true)) prefs.putString("sta_ssid", r->getParam("ssid", true)->value());
        if (r->hasParam("pass", true)) prefs.putString("sta_pass", r->getParam("pass", true)->value());
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "STA Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-ap", HTTP_POST, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("ssid", true)) prefs.putString("ap_ssid", r->getParam("ssid", true)->value());
        if (r->hasParam("pass", true)) {
            String p = r->getParam("pass", true)->value();
            if (p.length() >= 8) prefs.putString("ap_pass", p);
        }
        if (r->hasParam("channel", true)) {
            int ch = r->getParam("channel", true)->value().toInt();
            if (ch > 0) prefs.putInt("ap_channel", validateChannel(ch, use_5ghz));
        }
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "AP Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-nat", HTTP_POST, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        int new_tcp = DEFAULT_NAPT_TCP;
        int new_slots = DEFAULT_NAPT_SLOTS;
        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("tcp", true)) {
            new_tcp = validateNATTCP(r->getParam("tcp", true)->value().toInt());
            prefs.putInt("nat_tcp", new_tcp);
        }
        if (r->hasParam("slots", true)) {
            new_slots = validateNATSlots(r->getParam("slots", true)->value().toInt(), new_tcp);
            prefs.putInt("nat_slots", new_slots);
        }
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "NAT Config Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    // Captive portal HTTP handlers (port từ main.c)
    server.on("/generate_204", HTTP_GET, handleCaptive204);
    server.on("/connectivity-check", HTTP_GET, handleCaptive204);
    server.on("/success", HTTP_GET, handleCaptiveSuccess);
    server.on("/captive", HTTP_GET, handleCaptive204);
    server.on("/hotspot-detect.html", HTTP_GET, handleCaptive204);
    server.on("/library/test/success.html", HTTP_GET, handleCaptive204);
    server.on("/ncsi.txt", HTTP_GET, handleCaptive204);
    server.on("/canonical.html", HTTP_GET, handleCaptive204);
    server.on("/apple-sd", HTTP_GET, handleCaptive204);

    ws.onEvent([](AsyncWebSocket *s, AsyncWebSocketClient *c, AwsEventType t, void *arg, uint8_t *data, size_t len) {
        if (t == WS_EVT_DATA && len == 4 && memcmp(data, "ping", 4) == 0) c->text("pong");
    });
    server.addHandler(&ws);
    server.begin();

    xTaskCreate(dnsCaptiveTask, "DNS_CAPTIVE", 4096, nullptr, 5, nullptr);
    xTaskCreate(internetCheckTask, "INET_CHECK", 4096, nullptr, 2, nullptr);
    xTaskCreate(staReconnectTask, "STA_RECONNECT", 3072, nullptr, 2, nullptr);

#if ESP_IDF_VERSION_MAJOR >= 5
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT * 1000,
        .idle_core_mask = (1 << 0) | (1 << 1),
        .trigger_panic = true,
    };
    esp_task_wdt_init(&wdt_config);
#else
    esp_task_wdt_init(WATCHDOG_TIMEOUT, true);
#endif
    esp_task_wdt_add(nullptr);
    xTaskCreatePinnedToCore(networkTask, "NET", 8192, nullptr, 4, nullptr, 0);

    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, LOW); delay(80);
        digitalWrite(LED_BUILTIN, HIGH); delay(80);
    }

    Serial.printf("✅ APEX ULTRA V22.3.0 Ready on %s!\n", board_model.c_str());
    Serial.printf("🔑 Session token: %s\n", sessionToken.c_str());
    Serial.println("✅ Captive Portal: DNS + HTTP handlers enabled");
}

void loop() {
    esp_task_wdt_reset();
    vTaskDelay(10);
}