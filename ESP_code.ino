/*
   ESP32 NAT ROUTER - V16 (APEX KERNEL)
   - Category: Secure Embedded Network OS
   - Security: Hardware RNG Token, Token-Bound RPC
   - Logic: Active Rate-Limiting, Pressure-Based NAT Purge
   - Infrastructure: Multi-Task Watchdog, SMP-Safe Atomics
*/

#include <WiFi.h>
#include <DNSServer.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_task_wdt.h>
#include <esp_wifi.h>
#include <atomic>
#include <lwip/napt.h>
#include <lwip/netif.h>
#include <lwip/priv/tcpip_priv.h>

// ================= KERNEL CONFIG =================
#define DNS_PORT 53
#define WATCHDOG_TIMEOUT 45
#define MAX_AP_CLIENTS 8
#define MAX_WS_CLIENTS 2
#define MEM_CRITICAL_THRESHOLD 26000
#define SESSION_KEY_LEN 16

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GATEWAY(192, 168, 4, 1);
IPAddress AP_SUBNET(255, 255, 255, 0);

// ================= SYSTEM STATE =================
DNSServer dns;
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
Preferences prefs;

String sta_ssid, sta_pass, session_token;
std::atomic<bool> internetOK{false}, natEnabled{false};
std::atomic<uint32_t> lastNatPressure{0}, lastNatInitAttempt{0};
String lastRebootReason = "Normal Boot";

// ================= SECURITY & RESOURCE GUARD =================

struct RateLimitGuard {
    static std::atomic<int> activeReqs;
    bool allowed;
    RateLimitGuard() {
        if (activeReqs.fetch_add(1, std::memory_order_seq_cst) >= 3) { 
            activeReqs.fetch_sub(1, std::memory_order_seq_cst);
            allowed = false; 
        } else allowed = true;
    }
    ~RateLimitGuard() { if (allowed) activeReqs.fetch_sub(1, std::memory_order_seq_cst); }
};
std::atomic<int> RateLimitGuard::activeReqs{0};

void generateSecureToken() {
    char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    session_token = "";
    for (int i = 0; i < SESSION_KEY_LEN; i++) {
        session_token += charset[esp_random() % (sizeof(charset) - 1)];
    }
}

// ================= UI (APEX DASHBOARD) =================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>V16 APEX KERNEL</title>
<style>
body{font-family:system-ui,sans-serif;background:#020617;color:#f8fafc;padding:15px;margin:0;}
.card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;border:1px solid #334155;box-shadow:0 4px 20px rgba(0,0,0,0.4);}
.badge{padding:4px 10px;border-radius:6px;font-weight:bold;font-size:11px;background:#334155;}
.ok{color:#10b981;border:1px solid #10b981;} .bad{color:#ef4444;border:1px solid #ef4444;}
.st-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px;}
button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;transition:0.1s;}
button:active{opacity:0.8;}
input{width:100%;padding:12px;margin:10px 0;border-radius:8px;border:1px solid #334155;background:#0f172a;color:white;box-sizing:border-box;}
</style></head><body>
<div class='card'>
  <h2 style='color:#38bdf8;margin:0 0 5px 0;'>🛡️ APEX KERNEL V16</h2>
  <code style='font-size:10px;color:#94a3b8;'>SID: %TOKEN%</code>
  <hr style='border:0;border-top:1px solid #334155;margin:15px 0;'>
  <div class='st-grid'>
    <span>Internet: <span id='net' class='badge'>WAIT</span></span>
    <span>Heap: <b id='hcur'>0</b> KB</span>
    <span>Uptime: <b id='upt'>0</b>s</span>
    <span>NAT: <span id='natp' class='badge'>-</span></span>
  </div>
</div>
<div id='clist' class='card'><h3>👥 Connected Devices</h3><div id='ctable' style='font-size:12px;'>-</div></div>
<div class='card'>
  <form action='/save-sta'><input name='ssid' placeholder='SSID'><input name='pass' type='password' placeholder='Pass'><button type='submit'>Apply Config</button></form>
</div>
<script>
let token = '%TOKEN%';
let ws = new WebSocket('ws://'+window.location.hostname+'/ws');
function send(c){ if(ws.readyState===1) ws.send(JSON.stringify({cmd:c,token:token})); }
ws.onmessage = e => {
  let d = JSON.parse(e.data);
  document.getElementById('net').innerText = d.internet ? 'ONLINE' : 'OFFLINE';
  document.getElementById('net').className = 'badge ' + (d.internet ? 'ok' : 'bad');
  document.getElementById('hcur').innerText = Math.round(d.heap/1024);
  document.getElementById('upt').innerText = d.uptime;
  document.getElementById('natp').innerText = ['STABLE','STRESS','PURGE'][d.nat_p];
  let h = ''; d.clients.forEach(c => { h += `<div>• ${c.ip} <small style='color:#64748b'>[${c.mac}]</small></div>`; });
  document.getElementById('ctable').innerHTML = h || 'No devices connected';
};
</script></body></html>
)rawliteral";

// ================= CORE KERNEL TASK =================

void networkTask(void * pv) {
    esp_task_wdt_add(NULL);
    static bool natInit = false;
    static uint32_t lastBroadcast = 0;

    for(;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        // [V16 PRESSURE CONTROL]
        if (currHeap < MEM_CRITICAL_THRESHOLD) {
            lastNatPressure.store(2); // PURGE STATE
            LOCK_TCPIP_CORE();
            ip_napt_disable();
            ip_napt_init(MAX_NAPT_SLOTS, MAX_NAPT_TCP); // Force clear table
            UNLOCK_TCPIP_CORE();
            natEnabled.store(false);
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            lastNatPressure.store(currHeap < 50000 ? 1 : 0);
        }

        // NAT Lifecycle
        if (WiFi.status() == WL_CONNECTED) {
            if (!natInit && (millis() - lastNatInitAttempt > 10000)) {
                lastNatInitAttempt = millis();
                LOCK_TCPIP_CORE();
                ip_napt_init(MAX_NAPT_SLOTS, MAX_NAPT_TCP);
                ip_napt_set_idle_timeout(30);
                UNLOCK_TCPIP_CORE();
                natInit = true;
            }
            if (!natEnabled.load()) {
                LOCK_TCPIP_CORE();
                if (ip_napt_enable(WiFi.localIP(), 1)) natEnabled.store(true);
                UNLOCK_TCPIP_CORE();
            }
        }

        // WS Telemetry with Limit Enforcement
        if (millis() - lastBroadcast > 2000) {
            JsonDocument doc;
            doc["internet"] = internetOK.load();
            doc["heap"] = currHeap;
            doc["uptime"] = millis()/1000;
            doc["nat_p"] = lastNatPressure.load();
            
            JsonArray clis = doc["clients"].to<JsonArray>();
            wifi_sta_list_t sList; esp_wifi_ap_get_sta_list(&sList);
            tcpip_adapter_sta_list_t aList; tcpip_adapter_get_sta_list(&sList, &aList);
            for (int i = 0; i < aList.num; i++) {
                JsonObject c = clis.add<JsonObject>();
                char m[18]; sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", aList.sta[i].mac[0], aList.sta[i].mac[1], aList.sta[i].mac[2], aList.sta[i].mac[3], aList.sta[i].mac[4], aList.sta[i].mac[5]);
                c["mac"] = m; c["ip"] = ip4addr_ntoa(&(aList.sta[i].ip));
            }
            String out; serializeJson(doc, out); ws.textAll(out);
            lastBroadcast = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

// ================= HANDLERS =================

void onWsEvent(AsyncWebSocket *s, AsyncWebSocketClient *c, AwsEventType t, void *arg, uint8_t *data, size_t len) {
    if (t == WS_EVT_CONNECT) {
        // [V16] WS Client Hard-Limit
        if (s->count() > MAX_WS_CLIENTS) c->close(1008, "Too many clients");
    }
    if (t == WS_EVT_DATA) {
        RateLimitGuard guard; // [V16] Rate limiting applied to Control Plane
        if (!guard.allowed) return;

        JsonDocument doc;
        if (deserializeJson(doc, data, len) == DeserializationError::Ok) {
            if (doc["token"].is<const char*>() && doc["token"] == session_token) {
                if (doc["cmd"] == "reboot") {
                    prefs.putString("reboot_msg", "APEX RPC REBOOT");
                    xTaskCreate([](void*){ vTaskDelay(1000); ESP.restart(); }, "rb", 2048, NULL, 1, NULL);
                }
            }
        }
    }
}

void setup() {
    Serial.begin(115200);
    prefs.begin("apex-v16", false);
    lastRebootReason = prefs.getString("reboot_msg", "Normal");
    prefs.putString("reboot_msg", "Kernel Panic/WDT");
    
    generateSecureToken(); // Cryptographic session
    
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    WiFi.softAP("APEX_CORE", "12345678", 1, 0, MAX_AP_CLIENTS);

    dns.start(DNS_PORT, "*", AP_IP);
    ws.onEvent(onWsEvent); server.addHandler(&ws);

    server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){
        RateLimitGuard guard;
        if (!guard.allowed) return r->send(429, "text/plain", "Too many requests");
        String html = index_html;
        html.replace("%TOKEN%", session_token);
        r->send(200, "text/html", html);
    });

    server.on("/save-sta", HTTP_GET, [](AsyncWebServerRequest *r){
        if(r->hasParam("ssid")) prefs.putString("sta_ssid", r->getParam("ssid")->value());
        if(r->hasParam("pass")) prefs.putString("sta_pass", r->getParam("pass")->value());
        r->send(200, "text/plain", "OK. Rebooting...");
        xTaskCreate([](void*){ vTaskDelay(1000); ESP.restart(); }, "rb", 2048, NULL, 1, NULL);
    });

    server.begin();
    esp_task_wdt_init(WATCHDOG_TIMEOUT, true);
    
    // Core Registration
    xTaskCreatePinnedToCore(networkTask, "APEX_NET", 10240, NULL, 4, NULL, 0); 
    xTaskCreatePinnedToCore([](void* p){ 
        esp_task_wdt_add(NULL);
        for(;;){ esp_task_wdt_reset(); dns.processNextRequest(); vTaskDelay(pdMS_TO_TICKS(50)); } 
    }, "APEX_DNS", 2048, NULL, 1, NULL, 1);    
    xTaskCreatePinnedToCore([](void* p){ 
        esp_task_wdt_add(NULL);
        for(;;){ 
            esp_task_wdt_reset();
            if(WiFi.status()==WL_CONNECTED){
                WiFiClient c; c.setTimeout(1200);
                internetOK.store(c.connect("1.1.1.1", 53)); c.stop();
            } else internetOK.store(false);
            vTaskDelay(pdMS_TO_TICKS(20000)); 
        } 
    }, "APEX_CHK", 2048, NULL, 1, NULL, 1);
    esp_task_wdt_add(NULL);
}

void loop() { esp_task_wdt_reset(); vTaskDelay(pdMS_TO_TICKS(1000)); }
