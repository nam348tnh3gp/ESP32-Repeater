// ============================================================================
// APEX ULTRA V22.0.1 - FULL STANDALONE .INO
// Hoạt động độc lập, không cần file header hay thư viện ngoài
// ============================================================================

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
#include <nvs_flash.h>
#include <lwip/netif.h>
#include <lwip/priv/tcpip_priv.h>
#include <lwip/etharp.h>

// ================= NAT DECLARATIONS =================
#ifdef __cplusplus
extern "C" {
#endif
void ip_napt_init(uint16_t max_slots, uint16_t max_tcp_ports);
err_t ip_napt_enable(ip4_addr_t addr, int dir);
void ip_napt_disable(void);
#ifdef __cplusplus
}
#endif

// ================= TEMPERATURE =================
#ifndef CONFIG_IDF_TARGET_ESP32C5
#include <esp_temp_sensor.h>
#endif

// ================= GLOBALS =================
DNSServer dns;
AsyncWebServer webServer(80);
AsyncWebSocket ws("/ws");
Preferences prefs;

String sta_ssid, sta_pass, ap_ssid, ap_pass;
volatile bool internetOK = false;
volatile bool natEnabled = false;
volatile int lastRSSI = -100;
volatile int lastTemp = 0;
volatile bool scanInProgress = false;
volatile int currentClients = 0;
unsigned long uptimeStart = 0;

// AP Config
int ap_channel = 1;
bool ap_hidden = false;
int max_clients = 7;
int dns_mode = 0;
bool use_5ghz = false;

// NAT Config
int nat_max_slots = 512;
int nat_max_tcp = 256;

// Board info
bool board_supports_5ghz = false;
String board_model = "Unknown";

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GATEWAY(192, 168, 4, 1);
IPAddress AP_SUBNET(255, 255, 255, 0);

// ================= UTILS =================
String urlDecode(String str) {
    String decoded = "";
    char ch; int i, j;
    for (i = 0; i < str.length(); i++) {
        if (str[i] == '%') {
            sscanf(str.substring(i + 1, i + 3).c_str(), "%x", &j);
            ch = (char)j; decoded += ch; i += 2;
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
    
    switch(chip_info.model) {
        case CHIP_ESP32:    board_model = "ESP32"; board_supports_5ghz = false; break;
        case CHIP_ESP32S2:  board_model = "ESP32-S2"; board_supports_5ghz = false; break;
        case CHIP_ESP32S3:  board_model = "ESP32-S3"; board_supports_5ghz = false; break;
        case CHIP_ESP32C3:  board_model = "ESP32-C3"; board_supports_5ghz = false; break;
        case CHIP_ESP32C6:  board_model = "ESP32-C6"; board_supports_5ghz = false; break;
        default:            board_model = "ESP32"; board_supports_5ghz = false; break;
    }
    
    Serial.printf("Board: %s | 5GHz: %s\n", board_model.c_str(), board_supports_5ghz ? "YES" : "NO");
}

// ================= VALIDATION =================
int validateChannel(int ch, bool is5GHz) {
    if (!board_supports_5ghz && is5GHz) return 1;
    if (is5GHz) {
        if (ch >= 36 && ch <= 165) return ch;
        return 36;
    }
    if (ch >= 1 && ch <= 13) return ch;
    return 1;
}

int validateMaxClients(int clients) {
    if (clients >= 1 && clients <= 10) return clients;
    return 7;
}

String validateAPPassword(String pwd) {
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
    if (dns_mode == 0) {
        dns.start(53, "*", AP_IP);
        Serial.println("DNS Captive Portal Mode");
    } else {
        dns.start(53, "*", IPAddress(0, 0, 0, 0));
        Serial.println("DNS Normal Mode");
    }
}

// ================= NAT FUNCTIONS =================
void enableNAT() {
    if (WiFi.status() == WL_CONNECTED && !natEnabled) {
        sys_lock_tcpip_core();
        if (ip_napt_enable(WiFi.localIP(), 1)) {
            natEnabled = true;
            Serial.println("NAT Enabled");
        } else {
            Serial.println("NAT Failed");
        }
        sys_unlock_tcpip_core();
    }
}

void disableNAT() {
    if (natEnabled) {
        sys_lock_tcpip_core();
        ip_napt_disable();
        sys_unlock_tcpip_core();
        natEnabled = false;
        Serial.println("NAT Disabled");
    }
}

void initNAT() {
    sys_lock_tcpip_core();
    ip_napt_disable();
    ip_napt_init(nat_max_slots, nat_max_tcp);
    sys_unlock_tcpip_core();
    Serial.printf("NAT init: slots=%d, tcp=%d\n", nat_max_slots, nat_max_tcp);
}

// ================= GET IP FROM MAC =================
String getIPFromMAC(uint8_t* mac) {
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        struct etharp_entry *entry = &arp_table[i];
        if (entry->state == ETHARP_STATE_STABLE || entry->state == ETHARP_STATE_PENDING) {
            if (memcmp(entry->ethaddr.addr, mac, ETH_HWADDR_LEN) == 0) {
                char ip_str[16];
                ip4addr_ntoa_r(&entry->ipaddr, ip_str, sizeof(ip_str));
                return String(ip_str);
            }
        }
    }
    return "Pending";
}

// ================= HTML UI =================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>APEX ULTRA</title>
<style>
*{box-sizing:border-box;}
body{font-family:Arial;background:#020617;color:#f8fafc;padding:15px;}
.card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;}
input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}
button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}
.warning{color:#f59e0b;font-size:12px;}
</style></head><body>
<div class='card'>
  <h3>APEX ULTRA V22.0.1</h3>
  <div id='boardInfo'></div>
  <div>RAM: <b id='ram'>0</b> KB</div>
  <div>Temp: <b id='temp'>--</b> °C</div>
  <div>Internet: <span id='net'>WAIT</span></div>
  <div>NAT: <span id='nat'>WAIT</span></div>
  <div>Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>0</b></div>
</div>

<div class='card'>
  <h3>Uplink Configuration</h3>
  <button id='scanBtn'>Scan WiFi</button>
  <form action='/save-sta' method='get'>
    <input name='ssid' id='ssidInp' placeholder='WiFi Name' required>
    <input name='pass' type='password' placeholder='Password'>
    <button type='submit'>Connect</button>
  </form>
</div>

<div class='card'>
  <h3>AP Configuration</h3>
  <form action='/save-ap' method='get'>
    <input name='ssid' placeholder='AP SSID' value='APEX_ULTRA'>
    <input name='pass' type='password' placeholder='Password (min 8)'>
    <input name='channel' placeholder='Channel (1-13)' value='1'>
    <button type='submit'>Save & Reboot</button>
  </form>
</div>

<div class='card'>
  <h3>NAT Settings</h3>
  <form action='/save-nat' method='get'>
    <input name='slots' id='natSlots' placeholder='NAPT Slots (64-4096)' value='512'>
    <input name='tcp' id='natTcp' placeholder='TCP ports (32-2048)' value='256'>
    <button type='submit'>Save & Reboot</button>
  </form>
</div>

<div class='card'><h3>Connected Clients</h3><div id='ctable'>-</div></div>

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
    let h = '';
    d.clients.forEach(c => { h += `<div>${c.ip} [${c.mac}]</div>`; });
    document.getElementById('ctable').innerHTML = h || '-';
};

document.getElementById('scanBtn').onclick = async () => {
    let btn = document.getElementById('scanBtn');
    btn.innerText = 'Scanning...';
    let r = await fetch('/scan');
    let nets = await r.json();
    let list = nets.map((n,i)=> i+": "+n.ssid+" ("+n.rssi+"dBm)").join("\n");
    let s = prompt("Select WiFi (enter number):\n"+list);
    if(s !== null && nets[s]) document.getElementById('ssidInp').value = nets[s].ssid;
    btn.innerText = 'Scan WiFi';
};

fetch('/get-board-info').then(r=>r.json()).then(info=>{
    document.getElementById('boardInfo').innerHTML = `Board: ${info.model} | 5GHz: ${info.supports_5ghz ? 'Yes' : 'No'}`;
});
</script></body></html>
)rawliteral";

// ================= SCAN HANDLER =================
void handleScan(AsyncWebServerRequest *request) {
    if (scanInProgress) {
        request->send(429, "application/json", "[]");
        return;
    }

    scanInProgress = true;
    WiFi.scanNetworks(true);
    int n = -1, timeout = 8000, elapsed = 0;
    
    while (n == -1 && elapsed < timeout) {
        delay(100);
        n = WiFi.scanComplete();
        elapsed += 100;
        esp_task_wdt_reset();
    }

    if (n <= 0) {
        WiFi.scanDelete();
        scanInProgress = false;
        request->send(500, "application/json", "[]");
        return;
    }

    JsonDocument doc;
    JsonArray array = doc.to<JsonArray>();
    int limit = (n < 10) ? n : 10;
    
    for (int i = 0; i < limit; i++) {
        JsonObject item = array.add<JsonObject>();
        item["ssid"] = WiFi.SSID(i);
        item["rssi"] = WiFi.RSSI(i);
    }

    String out;
    serializeJson(doc, out);
    WiFi.scanDelete();
    scanInProgress = false;
    request->send(200, "application/json", out);
}

// ================= WIFI EVENT HANDLER =================
void wifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        currentClients++;
        Serial.printf("Client connected: %d/%d\n", currentClients, max_clients);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        if (currentClients > 0) currentClients--;
        Serial.printf("Client disconnected: %d/%d\n", currentClients, max_clients);
    }
}

// ================= NETWORK TASK =================
void networkTask(void * pv) {
    esp_task_wdt_add(NULL);
    static uint32_t lastBroadcast = 0;
    static bool natInitialized = false;
    static unsigned long lastTempUpdate = 0;

    for(;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        if (WiFi.status() == WL_CONNECTED) {
            if (!natInitialized) {
                initNAT();
                natInitialized = true;
            }
            enableNAT();
            lastRSSI = WiFi.RSSI();
        } else {
            lastRSSI = -100;
            natInitialized = false;
        }

        if (millis() - lastTempUpdate > 5000) {
            lastTemp = (int)(getTemperature() * 10);
            lastTempUpdate = millis();
        }

        if (millis() - lastBroadcast > 2000) {
            JsonDocument doc;
            doc["ram"] = currHeap;
            doc["internet"] = internetOK;
            doc["nat"] = natEnabled;
            doc["temp"] = lastTemp / 10.0;
            doc["clientCount"] = currentClients;
            doc["clientLimit"] = max_clients;

            JsonArray clis = doc["clients"].to<JsonArray>();
            wifi_sta_list_t wifi_sta_list;
            esp_wifi_ap_get_sta_list(&wifi_sta_list);
            
            for (int i = 0; i < wifi_sta_list.num; i++) {
                JsonObject c = clis.add<JsonObject>();
                char m[18]; 
                sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", 
                        wifi_sta_list.sta[i].mac[0], wifi_sta_list.sta[i].mac[1],
                        wifi_sta_list.sta[i].mac[2], wifi_sta_list.sta[i].mac[3],
                        wifi_sta_list.sta[i].mac[4], wifi_sta_list.sta[i].mac[5]);
                c["mac"] = m;
                c["ip"] = getIPFromMAC(wifi_sta_list.sta[i].mac);
            }

            String out;
            serializeJson(doc, out);
            ws.textAll(out);
            lastBroadcast = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ================= INTERNET CHECK =================
void internetCheckTask(void * pv) {
    esp_task_wdt_add(NULL);
    for(;;){ 
        esp_task_wdt_reset();
        if(WiFi.status() == WL_CONNECTED){
            WiFiClient c; 
            c.setTimeout(1500);
            internetOK = c.connect("1.1.1.1", 53); 
            c.stop();
        } else {
            internetOK = false;
        }
        vTaskDelay(20000); 
    }
}

// ================= SETUP =================
void setup() {
    Serial.begin(115200);
    delay(100);
    uptimeStart = millis();
    
    Serial.println("\n==========================================");
    Serial.println("APEX ULTRA V22.0.1 - STANDALONE");
    Serial.println("==========================================\n");
    
    // Init NVS
    nvs_flash_init();
    
    // Board detection
    detectBoardCapabilities();
    
    // Load config
    prefs.begin("apex-v22", false);
    sta_ssid = prefs.getString("sta_ssid", "");
    sta_pass = urlDecode(prefs.getString("sta_pass", ""));
    ap_ssid = prefs.getString("ap_ssid", "APEX_ULTRA");
    ap_pass = validateAPPassword(urlDecode(prefs.getString("ap_pass", "12345678")));
    ap_channel = validateChannel(prefs.getInt("ap_channel", 1), use_5ghz);
    max_clients = validateMaxClients(prefs.getInt("max_clients", 7));
    
    int saved_tcp = validateNATTCP(prefs.getInt("nat_tcp", 256));
    int saved_slots = validateNATSlots(prefs.getInt("nat_slots", 512), saved_tcp);
    nat_max_slots = saved_slots;
    nat_max_tcp = saved_tcp;
    
    Serial.printf("NAT: slots=%d, tcp=%d\n", nat_max_slots, nat_max_tcp);
    
    // Temperature sensor
#ifndef CONFIG_IDF_TARGET_ESP32C5
    temp_sensor_config_t temp_sensor = TSENS_CONFIG_DEFAULT();
    temp_sensor.dac_offset = TSENS_DAC_L2;
    temp_sensor_set_config(temp_sensor);
    temp_sensor_start();
#endif
    
    // Setup WiFi AP
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, 0, max_clients);
    Serial.printf("AP: %s | Ch:%d | IP: %s\n", ap_ssid.c_str(), ap_channel, AP_IP.toString().c_str());
    
    // Register event handler
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifiEventHandler, NULL, NULL);
    
    // Connect to STA
    if (sta_ssid.length() > 0) {
        WiFi.begin(sta_ssid.c_str(), sta_pass.c_str());
        Serial.printf("Connecting to STA: %s\n", sta_ssid.c_str());
    } else {
        Serial.printf("No STA configured. Connect to AP: http://%s\n", AP_IP.toString().c_str());
    }
    
    // Web server routes
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        request->send_P(200, "text/html", index_html);
    });
    
    webServer.on("/scan", HTTP_GET, handleScan);
    
    webServer.on("/get-board-info", HTTP_GET, [](AsyncWebServerRequest *request){
        String json = "{\"model\":\"" + board_model + "\",\"supports_5ghz\":" + 
                      String(board_supports_5ghz ? "true" : "false") + "}";
        request->send(200, "application/json", json);
    });
    
    webServer.on("/save-sta", HTTP_GET, [](AsyncWebServerRequest *request){
        if(request->hasParam("ssid")) prefs.putString("sta_ssid", request->getParam("ssid")->value());
        if(request->hasParam("pass")) prefs.putString("sta_pass", request->getParam("pass")->value());
        request->send(200, "text/plain", "STA Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });
    
    webServer.on("/save-ap", HTTP_GET, [](AsyncWebServerRequest *request){
        if(request->hasParam("ssid")) prefs.putString("ap_ssid", request->getParam("ssid")->value());
        if(request->hasParam("pass")) {
            String p = request->getParam("pass")->value();
            if (p.length() >= 8) prefs.putString("ap_pass", p);
        }
        if(request->hasParam("channel")) {
            int ch = request->getParam("channel")->value().toInt();
            prefs.putInt("ap_channel", validateChannel(ch, false));
        }
        request->send(200, "text/plain", "AP Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });
    
    webServer.on("/save-nat", HTTP_GET, [](AsyncWebServerRequest *request){
        if(request->hasParam("tcp")) {
            int new_tcp = validateNATTCP(request->getParam("tcp")->value().toInt());
            prefs.putInt("nat_tcp", new_tcp);
        }
        if(request->hasParam("slots")) {
            int new_slots = validateNATSlots(request->getParam("slots")->value().toInt(), nat_max_tcp);
            prefs.putInt("nat_slots", new_slots);
        }
        request->send(200, "text/plain", "NAT Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });
    
    ws.onEvent([](AsyncWebSocket *s, AsyncWebSocketClient *c, AwsEventType t, void *arg, uint8_t *data, size_t len) {
        if (t == WS_EVT_DATA && len == 4 && memcmp(data, "ping", 4) == 0) {
            c->text("pong");
        }
    });
    webServer.addHandler(&ws);
    webServer.begin();
    setupDNS();
    
    // Create tasks
    xTaskCreatePinnedToCore(networkTask, "NET_TASK", 8192, NULL, 4, NULL, 0);
    xTaskCreatePinnedToCore(internetCheckTask, "CHK_TASK", 2048, NULL, 1, NULL, 1);
    
    // Watchdog
    esp_task_wdt_init(45, true);
    esp_task_wdt_add(NULL);
    
    // Blink LED
    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, LOW); delay(80);
        digitalWrite(LED_BUILTIN, HIGH); delay(80);
    }
    
    Serial.printf("APEX ULTRA Ready on %s!\n", board_model.c_str());
}

void loop() {
    dns.processNextRequest();
    vTaskDelay(10);
}
