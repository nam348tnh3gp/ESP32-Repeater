/*
   ESP32 NAT ROUTER - V22.2.0 (FIXED, ported từ main.c đã build thành công)
   - Các lỗi đã vá (kế thừa từ V22.1.0):
     1) Watchdog không được reset trong loop() -> thiết bị tự reboot mỗi 45s
     2) Không có xác thực cho các route đổi cấu hình (save-sta/save-ap/save-nat)
     3) urlDecode() bị gọi 2 lần trên mật khẩu đã được decode sẵn -> sai mật khẩu
     4) urlDecode() dùng biến chưa khởi tạo khi sscanf thất bại
     5) handleScan() block AsyncTCP task tới 8 giây -> đứng cả dashboard
     8) Không cảnh báo khi còn dùng mật khẩu AP mặc định yếu
     9) Ghi NVS (Preferences) không có mutex bảo vệ giữa các request đồng thời
   - MỚI trong V22.2.0 (port từ main.c sau khi build thật thành công):
     6+7) Bỏ hẳn ip_napt_init()/ip_napt_enable()/ip_napt_disable() +
          sys_lock_tcpip_core()/sys_unlock_tcpip_core() - đây là API nội bộ
          của lwIP, chữ ký thay đổi giữa các phiên bản SDK và đã gây lỗi biên
          dịch thật (implicit declaration / incompatible pointer type) khi
          build main.c. Chuyển sang esp_netif_napt_enable()/
          esp_netif_napt_disable() - API công khai, ổn định của esp_netif.h.
     10) getIPFromMAC() cũ tự đọc bảng arp_table nội bộ của lwIP (không có
         trong header công khai của Arduino core, rủi ro không compile được
         hoặc không link được). Thay bằng esp_netif_dhcps_get_clients_by_mac()
         - API DHCP server chính thức, lấy đúng IP đã cấp cho từng MAC.
*/

#include <Arduino.h>
#include <DNSServer.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_task_wdt.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_chip_info.h>
#include <atomic>

#ifndef CONFIG_IDF_TARGET_ESP32C5
#include <esp_temp_sensor.h>
#endif

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
#define MAX_SCAN_NETWORKS 10
#define DEFAULT_MAX_CLIENTS 7
#define TEMP_UPDATE_INTERVAL 5000

#define DEFAULT_AP_CHANNEL 1
#define DEFAULT_AP_HIDDEN 0
#define DEFAULT_BAND_5GHZ 0
#define MIN_CLIENTS 1
#define MAX_CLIENTS_LIMIT 10

#define DNS_MODE_CAPTIVE 0
#define DNS_MODE_NORMAL 1
#define DEFAULT_DNS_MODE DNS_MODE_CAPTIVE

#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GATEWAY(192, 168, 4, 1);
IPAddress AP_SUBNET(255, 255, 255, 0);

DNSServer dns;
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
Preferences prefs;

String sta_ssid, sta_pass, ap_ssid, ap_pass;
std::atomic<bool> internetOK{false}, natEnabled{false};
std::atomic<int> lastRSSI{-100}, lastTemp{0};
std::atomic<bool> scanInProgress{false};
std::atomic<int> currentClients{0};
unsigned long uptimeStart = 0;

String sessionToken;
unsigned long lastConfigRequestWindow = 0;
int configRequestCount = 0;

SemaphoreHandle_t prefsMutex = nullptr;

volatile bool scanReady = false;
String scanResultJson = "[]";

// FIX (napt v2, port từ main.c): handle esp_netif của AP, dùng cho
// esp_netif_napt_enable()/disable() và esp_netif_dhcps_get_clients_by_mac().
static esp_netif_t *s_ap_netif = nullptr;

int ap_channel = DEFAULT_AP_CHANNEL;
bool ap_hidden = DEFAULT_AP_HIDDEN;
int max_clients = DEFAULT_MAX_CLIENTS;
int dns_mode = DEFAULT_DNS_MODE;
bool use_5ghz = DEFAULT_BAND_5GHZ;

// nat_max_slots/nat_max_tcp: từ V22.2.0 trở đi, kích thước bảng NAT thật sự
// được quyết định bởi Kconfig của SDK (CONFIG_LWIP_NAT_MAX /
// CONFIG_LWIP_NAT_PORTMAP_MAX), không còn set runtime qua ip_napt_init()
// được nữa. Hai biến này chỉ còn để hiển thị/lưu lại giá trị người dùng
// mong muốn trên dashboard, không ảnh hưởng hành vi NAT thật.
int nat_max_slots = DEFAULT_NAPT_SLOTS;
int nat_max_tcp = DEFAULT_NAPT_TCP;

bool board_supports_5ghz = false;
String board_model = "Unknown";

// ================= NAT FUNCTIONS (esp_netif, ổn định giữa các bản SDK) =================
void enableNAT() {
    if (WiFi.status() != WL_CONNECTED || natEnabled.load()) return;
    if (s_ap_netif == nullptr) {
        Serial.println("❌ enableNAT: AP netif chưa sẵn sàng");
        return;
    }
    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err == ESP_OK) {
        natEnabled.store(true);
        Serial.printf("✅ NAT Enabled (slots=%d, tcp=%d - theo Kconfig của SDK)\n", nat_max_slots, nat_max_tcp);
    } else {
        Serial.printf("❌ Failed to enable NAT: %s\n", esp_err_to_name(err));
    }
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
    Serial.printf("📡 5GHz Support: %s\n", board_supports_5ghz ? "YES" : "NO");

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
    if (pwd.length() == 0) return "12345678";
    if (pwd.length() < 8) return "12345678";
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

// ================= TEMPERATURE =================
float getTemperature() {
#ifdef CONFIG_IDF_TARGET_ESP32C5
    return 0.0f;
#else
    float temp;
    if (temp_sensor_read_celsius(&temp) == ESP_OK) return temp;
    return 0.0f;
#endif
}

// ================= DNS =================
void setupDNS() {
    if (dns_mode == DNS_MODE_CAPTIVE) {
        dns.start(53, "*", AP_IP);
        Serial.println("✅ DNS Captive Portal Mode");
    } else {
        dns.start(53, "*", IPAddress(0, 0, 0, 0));
        Serial.println("✅ DNS Normal Mode");
    }
}

// ================= WIFI EVENT HANDLER =================
void wifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        currentClients.fetch_add(1);
        Serial.printf("✅ Client connected | Total: %d/%d\n", currentClients.load(), max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        int newCount = currentClients.fetch_sub(1) - 1;
        if (newCount < 0) currentClients.store(0);
        Serial.printf("❌ Client disconnected | Total: %d/%d\n", currentClients.load(), max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        // FIX (port từ main.c): mất uplink STA thì tắt NAT luôn.
        disableNAT();
    }
}

// ================= AUTH / RATE LIMIT =================
bool checkAuthAndRate(AsyncWebServerRequest *r) {
    if (!r->hasParam("token") || r->getParam("token")->value() != sessionToken) {
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

// ================= HTML UI =================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>APEX ULTRA V22.2.0</title>
<style>
*{box-sizing:border-box;}
body{font-family:Arial,sans-serif;background:#020617;color:#f8fafc;padding:15px;margin:0;}
.card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;border:1px solid #334155;}
input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}
button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}
.badge{padding:4px 8px;border-radius:6px;display:inline-block;}
.warning{color:#f59e0b;}
</style></head><body>
<div class='card'>
  <h3>🛡️ APEX ULTRA V22.2.0 (Fixed Build)</h3>
  <div id='boardInfo'></div>
  <div>📊 RAM: <b id='ram'>0</b> KB</div>
  <div>🌡️ Temp: <b id='temp'>--</b> °C</div>
  <div>🌐 Net: <span id='net' class='badge'>WAIT</span></div>
  <div>🔁 NAT: <span id='nat' class='badge'>WAIT</span></div>
  <div>📱 Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>0</b></div>
  <div id='weakPassWarning' class='warning' style='display:none;margin-top:8px;'>⚠️ Đang dùng mật khẩu AP mặc định (12345678) — hãy đổi ngay trong mục cấu hình bên dưới!</div>
</div>

<div class='card'>
  <h3>📡 Uplink Configuration</h3>
  <button id='scanBtn'>🔍 Scan WiFi</button>
  <form action='/save-sta' method='get' class='authForm'>
    <input name='ssid' id='ssidInp' placeholder='WiFi Name' required>
    <input name='pass' type='password' placeholder='Password'>
    <input type='hidden' name='token' class='tokenField' value=''>
    <button type='submit'>🚀 Connect</button>
  </form>
</div>

<div class='card'>
  <h3>🎛️ Access Point Configuration</h3>
  <form action='/save-ap' method='get' class='authForm'>
    <input name='ssid' placeholder='AP SSID' value='APEX_ULTRA'>
    <input name='pass' type='password' placeholder='AP Password (min 8)'>
    <input name='channel' placeholder='Channel (1-13 hoặc 36-165)' value='1'>
    <input type='hidden' name='token' class='tokenField' value=''>
    <button type='submit'>💾 Save & Reboot</button>
  </form>
</div>

<div class='card'>
  <h3>⚙️ NAT Advanced Settings</h3>
  <form action='/save-nat' method='get' id='natForm' class='authForm'>
    <input name='slots' id='natSlots' placeholder='Max NAPT Slots (64-4096)' value='512'>
    <input name='tcp' id='natTcp' placeholder='Max TCP ports (32-2048)' value='256'>
    <input type='hidden' name='token' class='tokenField' value=''>
    <button type='submit'>💾 Save NAT Config & Reboot</button>
  </form>
  <small>⚠️ Giá trị này hiện chỉ mang tính lưu lại/hiển thị - kích thước bảng NAT thật do SDK (Kconfig) quyết định.</small>
</div>

<div class='card'><h3>👥 Connected Clients</h3><div id='ctable' style='font-size:12px;'>-</div></div>

<script>
let ws = new WebSocket('ws://' + location.hostname + '/ws');
ws.onmessage = e => {
    let d = JSON.parse(e.data);
    document.getElementById('ram').innerText = Math.round(d.ram/1024);
    document.getElementById('temp').innerText = d.temp;
    document.getElementById('net').innerText = d.internet ? 'ONLINE' : 'OFFLINE';
    document.getElementById('nat').innerText = d.nat ? 'ACTIVE' : 'OFF';
    document.getElementById('clientCount').innerText = d.clientCount;
    document.getElementById('clientLimit').innerText = d.clientLimit;
    document.getElementById('weakPassWarning').style.display = d.weakPassword ? 'block' : 'none';
    let h = '';
    d.clients.forEach(c => { h += `<div>• ${c.ip} <small>[${c.mac}]</small></div>`; });
    document.getElementById('ctable').innerHTML = h || '<i>No clients</i>';
};

fetch('/get-token').then(r=>r.json()).then(t=>{
    document.querySelectorAll('.tokenField').forEach(el => el.value = t.token);
});

document.getElementById('scanBtn').onclick = async () => {
    let btn = document.getElementById('scanBtn');
    btn.innerText = '⏳ Scanning...';
    await fetch('/scan');
    let tries = 0;
    let poll = setInterval(async () => {
        let r = await fetch('/scan-status');
        let d = await r.json();
        tries++;
        if (d.ready) {
            clearInterval(poll);
            let nets = d.networks;
            let list = nets.map((n,i)=> i+": "+n.ssid+" ("+n.rssi+"dBm)").join("\n");
            let s = prompt("Select WiFi (enter number):\n"+list);
            if (s !== null && nets[s]) document.getElementById('ssidInp').value = nets[s].ssid;
            btn.innerText = '🔍 Scan WiFi';
        } else if (tries > 100) {
            clearInterval(poll);
            btn.innerText = '🔍 Scan WiFi';
        }
    }, 300);
};

fetch('/get-board-info').then(r=>r.json()).then(info=>{
    document.getElementById('boardInfo').innerHTML = `🔧 Board: ${info.model} | 5GHz: ${info.supports_5ghz ? '✅' : '❌'}`;
});
fetch('/get-nat-config').then(r=>r.json()).then(nat=>{
    document.getElementById('natSlots').value = nat.slots;
    document.getElementById('natTcp').value = nat.tcp;
});
</script></body></html>
)rawliteral";

// ================= SCAN (bất đồng bộ, không block AsyncTCP task) =================
void scanTaskFn(void *pv) {
    WiFi.scanNetworks(true);
    int n = -1, timeout = 8000, elapsed = 0;

    while (n == -1 && elapsed < timeout) {
        vTaskDelay(pdMS_TO_TICKS(100));
        n = WiFi.scanComplete();
        elapsed += 100;
    }

    JsonDocument doc;
    JsonArray array = doc.to<JsonArray>();

    if (n > 0) {
        int limit = min(n, MAX_SCAN_NETWORKS);
        for (int i = 0; i < limit; i++) {
            JsonObject item = array.add<JsonObject>();
            item["ssid"] = WiFi.SSID(i);
            item["rssi"] = WiFi.RSSI(i);
        }
    }
    WiFi.scanDelete();

    String out;
    serializeJson(doc, out);
    scanResultJson = out;
    scanReady = true;
    scanInProgress.store(false);
    vTaskDelete(nullptr);
}

void handleScan(AsyncWebServerRequest *r) {
    if (scanInProgress.exchange(true)) {
        r->send(429, "application/json", "[]");
        return;
    }
    scanReady = false;
    scanResultJson = "[]";
    xTaskCreate(scanTaskFn, "SCAN", 4096, nullptr, 1, nullptr);
    r->send(202, "application/json", "{\"status\":\"scanning\"}");
}

void handleScanStatus(AsyncWebServerRequest *r) {
    String json = "{\"ready\":";
    json += scanReady ? "true" : "false";
    json += ",\"networks\":";
    json += scanReady ? scanResultJson : "[]";
    json += "}";
    r->send(200, "application/json", json);
}

// ================= NETWORK TASK =================
void networkTask(void * pv) {
    esp_task_wdt_add(nullptr);
    static uint32_t lastBroadcast = 0;
    static unsigned long lastTempUpdate = 0;
    static int lastClientCount = -1;

    for (;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        if (currHeap < MEM_CRITICAL_THRESHOLD && natEnabled.load()) {
            disableNAT();
            Serial.println("⚠️ Memory critical - NAT disabled");
        }

        if (WiFi.status() == WL_CONNECTED) {
            enableNAT();
            lastRSSI.store(WiFi.RSSI());
        } else {
            lastRSSI.store(-100);
        }

        if (millis() - lastTempUpdate > TEMP_UPDATE_INTERVAL) {
            lastTemp.store((int)(getTemperature() * 10));
            lastTempUpdate = millis();
        }

        if (millis() - lastBroadcast > 2000) {
            JsonDocument doc;
            doc["ram"] = currHeap;
            doc["internet"] = internetOK.load();
            doc["nat"] = natEnabled.load();
            doc["rssi"] = lastRSSI.load();
            doc["temp"] = lastTemp.load() / 10.0;
            doc["uptime"] = (millis() - uptimeStart) / 1000;
            doc["clientCount"] = currentClients.load();
            doc["clientLimit"] = max_clients;
            doc["weakPassword"] = (ap_pass == "12345678");

            JsonArray clis = doc["clients"].to<JsonArray>();
            wifi_sta_list_t wifi_sta_list;
            esp_wifi_ap_get_sta_list(&wifi_sta_list);

            if (lastClientCount != wifi_sta_list.num) {
                lastClientCount = wifi_sta_list.num;
                Serial.printf("📡 Clients: %d/%d\n", lastClientCount, max_clients);
            }

            // FIX (port từ main.c): lấy IP theo MAC qua DHCP server chính
            // thức thay vì tự đọc bảng arp nội bộ của lwIP.
            int num = wifi_sta_list.num;
            if (num > 10) num = 10;
            if (num > 0 && s_ap_netif != nullptr) {
                esp_netif_pair_mac_ip_t pairs[10] = {0};
                for (int i = 0; i < num; i++) {
                    memcpy(pairs[i].mac, wifi_sta_list.sta[i].mac, 6);
                }
                esp_netif_dhcps_get_clients_by_mac(s_ap_netif, num, pairs);

                for (int i = 0; i < num; i++) {
                    JsonObject c = clis.add<JsonObject>();
                    char m[18];
                    sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X",
                            pairs[i].mac[0], pairs[i].mac[1], pairs[i].mac[2],
                            pairs[i].mac[3], pairs[i].mac[4], pairs[i].mac[5]);
                    c["mac"] = m;
                    c["ip"] = IPAddress(pairs[i].ip.addr).toString();
                }
            }

            String out;
            serializeJson(doc, out);
            ws.textAll(out);
            lastBroadcast = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
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

    sta_ssid = prefs.getString("sta_ssid", "");
    sta_pass = prefs.getString("sta_pass", "");
    ap_ssid = prefs.getString("ap_ssid", "APEX_ULTRA");
    ap_pass = validateAPPassword(prefs.getString("ap_pass", "12345678"));

    if (board_supports_5ghz) {
        use_5ghz = prefs.getBool("use_5ghz", DEFAULT_BAND_5GHZ);
    }

    ap_channel = validateChannel(prefs.getInt("ap_channel", DEFAULT_AP_CHANNEL), use_5ghz);
    ap_hidden = prefs.getBool("ap_hidden", DEFAULT_AP_HIDDEN);
    max_clients = validateMaxClients(prefs.getInt("max_clients", DEFAULT_MAX_CLIENTS));
    dns_mode = prefs.getInt("dns_mode", DEFAULT_DNS_MODE);

    int saved_tcp = validateNATTCP(prefs.getInt("nat_tcp", DEFAULT_NAPT_TCP));
    int saved_slots = validateNATSlots(prefs.getInt("nat_slots", DEFAULT_NAPT_SLOTS), saved_tcp);
    nat_max_slots = saved_slots;
    nat_max_tcp = saved_tcp;

    sessionToken = String((uint32_t)esp_random(), HEX) + String((uint32_t)esp_random(), HEX);

    Serial.println("\n=== APEX ULTRA V22.2.0 - FIXED BUILD ===\n");
    if (ap_pass == "12345678") {
        Serial.println("⚠️ CẢNH BÁO: đang dùng mật khẩu AP mặc định, hãy đổi ngay!");
    }

#ifndef CONFIG_IDF_TARGET_ESP32C5
    temp_sensor_config_t temp_sensor = TSENS_CONFIG_DEFAULT();
    temp_sensor.dac_offset = TSENS_DAC_L2;
    temp_sensor_set_config(temp_sensor);
    temp_sensor_start();
#endif

    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, ap_hidden ? 1 : 0, max_clients);

    // FIX (napt v2, port từ main.c): lấy handle esp_netif của AP ngay sau
    // khi softAP() đã tạo xong interface, dùng cho esp_netif_napt_enable/
    // disable() và esp_netif_dhcps_get_clients_by_mac() về sau.
    s_ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (s_ap_netif == nullptr) {
        Serial.println("❌ Không lấy được AP netif handle - NAT sẽ không hoạt động!");
    }

    Serial.printf("📡 AP: %s | Ch:%d | IP: %s\n", ap_ssid.c_str(), ap_channel, AP_IP.toString().c_str());

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifiEventHandler, nullptr, nullptr));

    if (sta_ssid.length() > 0) {
        WiFi.begin(sta_ssid.c_str(), sta_pass.c_str());
        Serial.printf("📡 Connecting to STA: %s\n", sta_ssid.c_str());
    } else {
        Serial.printf("⚠️ Connect to AP: %s | http://%s\n", ap_ssid.c_str(), AP_IP.toString().c_str());
    }

    server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){ r->send_P(200, "text/html", index_html); });
    server.on("/scan", HTTP_GET, handleScan);
    server.on("/scan-status", HTTP_GET, handleScanStatus);

    server.on("/get-token", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"token\":\"" + sessionToken + "\"}";
        r->send(200, "application/json", json);
    });

    server.on("/get-board-info", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"model\":\"" + board_model + "\",\"supports_5ghz\":" +
                      String(board_supports_5ghz ? "true" : "false") + "}";
        r->send(200, "application/json", json);
    });

    server.on("/get-nat-config", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"slots\":" + String(nat_max_slots) + ",\"tcp\":" + String(nat_max_tcp) + "}";
        r->send(200, "application/json", json);
    });

    server.on("/save-sta", HTTP_GET, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("ssid")) prefs.putString("sta_ssid", r->getParam("ssid")->value());
        if (r->hasParam("pass")) prefs.putString("sta_pass", r->getParam("pass")->value());
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "✅ STA Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-ap", HTTP_GET, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("ssid")) prefs.putString("ap_ssid", r->getParam("ssid")->value());
        if (r->hasParam("pass")) {
            String p = r->getParam("pass")->value();
            if (p.length() >= 8) prefs.putString("ap_pass", p);
        }
        if (r->hasParam("channel")) {
            int ch = r->getParam("channel")->value().toInt();
            prefs.putInt("ap_channel", validateChannel(ch, use_5ghz));
        }
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "✅ AP Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-nat", HTTP_GET, [](AsyncWebServerRequest *r){
        if (!checkAuthAndRate(r)) return;
        int new_tcp = DEFAULT_NAPT_TCP;
        int new_slots = DEFAULT_NAPT_SLOTS;

        xSemaphoreTake(prefsMutex, portMAX_DELAY);
        if (r->hasParam("tcp")) {
            new_tcp = validateNATTCP(r->getParam("tcp")->value().toInt());
            prefs.putInt("nat_tcp", new_tcp);
        }
        if (r->hasParam("slots")) {
            new_slots = validateNATSlots(r->getParam("slots")->value().toInt(), new_tcp);
            prefs.putInt("nat_slots", new_slots);
        }
        xSemaphoreGive(prefsMutex);
        r->send(200, "text/plain", "✅ NAT Config Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    ws.onEvent([](AsyncWebSocket *s, AsyncWebSocketClient *c, AwsEventType t, void *arg, uint8_t *data, size_t len) {
        if (t == WS_EVT_DATA && len == 4 && memcmp(data, "ping", 4) == 0) {
            c->text("pong");
        }
    });
    server.addHandler(&ws);
    server.begin();
    setupDNS();

    xTaskCreatePinnedToCore([](void* p){
        esp_task_wdt_add(nullptr);
        for (;;) {
            esp_task_wdt_reset();
            if (WiFi.status() == WL_CONNECTED) {
                WiFiClient c;
                c.setTimeout(1500);
                internetOK.store(c.connect("1.1.1.1", 53));
                c.stop();
            } else {
                internetOK.store(false);
            }
            vTaskDelay(20000);
        }
    }, "CHK", 2048, nullptr, 1, nullptr, 1);

    esp_task_wdt_init(WATCHDOG_TIMEOUT, true);
    esp_task_wdt_add(nullptr);
    xTaskCreatePinnedToCore(networkTask, "NET", 8192, nullptr, 4, nullptr, 0);

    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, LOW); delay(80);
        digitalWrite(LED_BUILTIN, HIGH); delay(80);
    }

    Serial.printf("✅ APEX ULTRA V22.2.0 Ready on %s!\n", board_model.c_str());
    Serial.printf("🔑 Session token: %s\n", sessionToken.c_str());
}

void loop() {
    dns.processNextRequest();
    esp_task_wdt_reset();
    vTaskDelay(10);
}