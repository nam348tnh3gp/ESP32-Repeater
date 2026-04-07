/*
   ESP32 NAT ROUTER - V19.9.9 (Auto-detect 5GHz Support)
   - Auto-detect if board supports 5GHz AP mode
   - Disable 5GHz option on unsupported boards
   - Show board model info on web interface
*/

#include <WiFi.h>
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
#include <lwip/napt.h>
#include <lwip/netif.h>
#include <lwip/priv/tcpip_priv.h>
#include <lwip/etharp.h>

// ================= FIX: conditional include for temperature sensor =================
#ifndef CONFIG_IDF_TARGET_ESP32C5
#include <esp_temp_sensor.h>
#endif

// ================= BOARD DETECTION =================
// List of ESP32 chips that support 5GHz AP mode
// Currently only ESP32-C5 supports 5GHz
#define CHIP_SUPPORTS_5GHZ(chip_model) (chip_model == CHIP_ESP32C5)

// 5GHz channel ranges (only defined for supported chips)
#define CHANNEL_2G_MIN 1
#define CHANNEL_2G_MAX 13
#define CHANNEL_5G_MIN 36
#define CHANNEL_5G_MAX 165
#define CHANNEL_5G_36 36
#define CHANNEL_5G_40 40
#define CHANNEL_5G_44 44
#define CHANNEL_5G_48 48
#define CHANNEL_5G_149 149
#define CHANNEL_5G_153 153
#define CHANNEL_5G_157 157
#define CHANNEL_5G_161 161

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// ================= KERNEL DEFINITIONS =================
#define MAX_NAPT_SLOTS 2048
#define MAX_NAPT_TCP 1024
#define LOCK_TCPIP_CORE()   sys_lock_tcpip_core()
#define UNLOCK_TCPIP_CORE() sys_unlock_tcpip_core()
#define MEM_CRITICAL_THRESHOLD 26000 
#define WATCHDOG_TIMEOUT 45
#define MAX_SCAN_NETWORKS 10
#define DEFAULT_MAX_CLIENTS 7
#define TEMP_UPDATE_INTERVAL 5000

// AP Config Defaults
#define DEFAULT_AP_CHANNEL 1
#define DEFAULT_AP_HIDDEN 0
#define DEFAULT_BAND_5GHZ 0
#define MIN_CLIENTS 1
#define MAX_CLIENTS_LIMIT 10

// DNS Mode
#define DNS_MODE_CAPTIVE 0
#define DNS_MODE_NORMAL 1
#define DEFAULT_DNS_MODE DNS_MODE_CAPTIVE

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

// AP Config variables
int ap_channel = DEFAULT_AP_CHANNEL;
bool ap_hidden = DEFAULT_AP_HIDDEN;
int max_clients = DEFAULT_MAX_CLIENTS;
int dns_mode = DEFAULT_DNS_MODE;
bool use_5ghz = DEFAULT_BAND_5GHZ;

// Board info
bool board_supports_5ghz = false;
String board_model = "Unknown";

// ================= UTILS =================

String urlDecode(String str) {
    String decoded = "";
    char ch; int i, j;
    for (i = 0; i < str.length(); i++) {
        if (str[i] == '%') {
            sscanf(str.substring(i + 1, i + 3).c_str(), "%x", &j);
            ch = (char)j; decoded += ch; i += 2;
        } else if (str[i] == '+') decoded += ' ';
        else decoded += ch;
    }
    return decoded;
}

// ================= BOARD DETECTION FUNCTION =================
void detectBoardCapabilities() {
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    
    // Determine chip model
    switch(chip_info.model) {
        case CHIP_ESP32:
            board_model = "ESP32";
            board_supports_5ghz = false;
            break;
        case CHIP_ESP32S2:
            board_model = "ESP32-S2";
            board_supports_5ghz = false;
            break;
        case CHIP_ESP32S3:
            board_model = "ESP32-S3";
            board_supports_5ghz = false;
            break;
        case CHIP_ESP32C3:
            board_model = "ESP32-C3";
            board_supports_5ghz = false;
            break;
        case CHIP_ESP32C5:
            board_model = "ESP32-C5";
            board_supports_5ghz = true;
            break;
        case CHIP_ESP32C6:
            board_model = "ESP32-C6";
            board_supports_5ghz = false;  // C6 supports 2.4GHz only
            break;
        case CHIP_ESP32H2:
            board_model = "ESP32-H2";
            board_supports_5ghz = false;  // H2 is 2.4GHz only
            break;
        case CHIP_ESP32P4:
            board_model = "ESP32-P4";
            board_supports_5ghz = false;  // P4 doesn't have WiFi
            break;
        default:
            board_model = "ESP32 (Unknown)";
            board_supports_5ghz = false;
            break;
    }
    
    // Override if we detect 5GHz capability via WiFi band check
    wifi_band_t supported_bands;
    if (esp_wifi_get_band(&supported_bands) == ESP_OK) {
        if (supported_bands & WIFI_BAND_5GHZ) {
            board_supports_5ghz = true;
        }
    }
    
    Serial.printf("🔍 Board Detected: %s\n", board_model.c_str());
    Serial.printf("📡 5GHz Support: %s\n", board_supports_5ghz ? "YES" : "NO");
    
    // Force disable 5GHz if board doesn't support it
    if (!board_supports_5ghz && use_5ghz) {
        use_5ghz = false;
        Serial.println("⚠️ Board does not support 5GHz - Forcing 2.4GHz mode");
    }
}

// ================= VALIDATION FUNCTIONS =================
bool isValidChannel(int ch, bool is5GHz) {
    if (!board_supports_5ghz && is5GHz) {
        return false;
    }
    
    if (is5GHz) {
        return (ch >= CHANNEL_5G_MIN && ch <= CHANNEL_5G_MAX);
    } else {
        return (ch >= CHANNEL_2G_MIN && ch <= CHANNEL_2G_MAX);
    }
}

int validateChannel(int ch, bool is5GHz) {
    if (!board_supports_5ghz && is5GHz) {
        Serial.println("⚠️ 5GHz not supported on this board, using 2.4GHz channel");
        return DEFAULT_AP_CHANNEL;
    }
    
    if (isValidChannel(ch, is5GHz)) return ch;
    Serial.printf("⚠️ Invalid channel %d for %s, using default\n", 
                  ch, is5GHz ? "5GHz" : "2.4GHz");
    return is5GHz ? CHANNEL_5G_36 : DEFAULT_AP_CHANNEL;
}

int validateMaxClients(int clients) {
    if (clients >= MIN_CLIENTS && clients <= MAX_CLIENTS_LIMIT) return clients;
    Serial.printf("⚠️ Invalid max clients %d, using default %d\n", clients, DEFAULT_MAX_CLIENTS);
    return DEFAULT_MAX_CLIENTS;
}

String validateAPPassword(String pwd) {
    if (pwd.length() == 0) {
        Serial.println("⚠️ Empty AP password, using default '12345678'");
        return "12345678";
    }
    if (pwd.length() < 8) {
        Serial.printf("⚠️ Password too short (%d chars), using default '12345678'\n", pwd.length());
        return "12345678";
    }
    return pwd;
}

// ================= TEMPERATURE =================
float getTemperature() {
#ifdef CONFIG_IDF_TARGET_ESP32C5
    return 0.0f;
#else
    float temp;
    if (temp_sensor_read_celsius(&temp) == ESP_OK) {
        return temp;
    }
    return 0.0f;
#endif
}

// ================= RECONFIGURE AP WITH BAND SUPPORT =================
void reconfigureAP() {
    if (board_supports_5ghz) {
        wifi_config_t ap_config = {};
        strcpy((char*)ap_config.ap.ssid, ap_ssid.c_str());
        strcpy((char*)ap_config.ap.password, ap_pass.c_str());
        ap_config.ap.ssid_len = ap_ssid.length();
        ap_config.ap.channel = ap_channel;
        ap_config.ap.authmode = ap_pass.length() ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        ap_config.ap.ssid_hidden = ap_hidden ? 1 : 0;
        ap_config.ap.max_connection = max_clients;
        
        if (use_5ghz && board_supports_5ghz) {
            ap_config.ap.phy_11b = 0;
            ap_config.ap.phy_11g = 0;
            ap_config.ap.phy_11n = 1;
            ap_config.ap.phy_11ax = 1;
            esp_wifi_set_band(WIFI_BAND_5GHZ);
        } else {
            esp_wifi_set_band(WIFI_BAND_2GHZ);
        }
        
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        esp_wifi_start();
    } else {
        WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, ap_hidden ? 1 : 0, max_clients);
    }
    
    Serial.printf("📡 AP Reconfigured: %s | %s | Ch:%d | Hidden:%s | Max:%d\n",
                  ap_ssid.c_str(), (use_5ghz && board_supports_5ghz) ? "5GHz" : "2.4GHz", 
                  ap_channel, ap_hidden ? "Yes" : "No", max_clients);
}

// ================= DNS CONFIGURATION =================
void setupDNS() {
    if (dns_mode == DNS_MODE_CAPTIVE) {
        dns.start(53, "*", AP_IP);
        Serial.println("✅ DNS Captive Portal Mode: All domains -> 192.168.4.1");
    } else {
        dns.start(53, "*", IPAddress(0, 0, 0, 0));
        Serial.println("✅ DNS Normal Mode: Standard DNS resolution");
    }
}

// ================= WIFI EVENT HANDLER =================
void wifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*)event_data;
        currentClients.fetch_add(1);
        Serial.printf("✅ Client connected: %02X:%02X:%02X:%02X:%02X:%02X | Total: %d/%d\n",
                      event->mac[0], event->mac[1], event->mac[2],
                      event->mac[3], event->mac[4], event->mac[5],
                      currentClients.load(), max_clients);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*)event_data;
        int newCount = currentClients.fetch_sub(1) - 1;
        if (newCount < 0) currentClients.store(0);
        Serial.printf("❌ Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X | Total: %d/%d\n",
                      event->mac[0], event->mac[1], event->mac[2],
                      event->mac[3], event->mac[4], event->mac[5],
                      currentClients.load(), max_clients);
    }
}

// ================= REAL IP RESOLVER =================
struct netif* getAPNetif() {
    esp_netif_t *ap_esp_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_esp_netif != NULL) {
        return esp_netif_get_netif_impl(ap_esp_netif);
    }

    struct netif *netif_ap = netif_list;
    while (netif_ap != NULL) {
        if ((netif_ap->name[0] == 'a' && netif_ap->name[1] == 'p') ||
            (netif_ap->name[0] == 's' && netif_ap->name[1] == 't')) {
            return netif_ap;
        }
        netif_ap = netif_ap->next;
    }
    return NULL;
}

String getIPFromMAC(uint8_t* mac) {
    struct netif *netif_ap = getAPNetif();
    if (netif_ap == NULL) return "No AP Netif";

    struct eth_addr mac_addr;
    memcpy(mac_addr.addr, mac, ETH_HWADDR_LEN);
    ip4_addr_t *ip_found = NULL;

    LOCK_TCPIP_CORE();
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        struct etharp_entry *entry = &arp_table[i];
        if (entry->state == ETHARP_STATE_STABLE || entry->state == ETHARP_STATE_PENDING) {
            if (memcmp(entry->ethaddr.addr, mac, ETH_HWADDR_LEN) == 0) {
                ip_found = &entry->ipaddr;
                break;
            }
        }
    }
    UNLOCK_TCPIP_CORE();

    if (ip_found != NULL) {
        char ip_str[16];
        ip4addr_ntoa_r(ip_found, ip_str, sizeof(ip_str));
        return String(ip_str);
    }
    return "Pending...";
}

// ================= HTML UI (Dynamic 5GHz option) =================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1, user-scalable=yes'>
<title>APEX ULTRA V19.9.9</title>
<style>
*{box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#020617;color:#f8fafc;padding:15px;margin:0;}
.card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;border:1px solid #334155;}
.st-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px;}
.badge{padding:4px 8px;border-radius:6px;font-weight:bold;font-size:10px;border:1px solid #475569;display:inline-block;}
.ok{color:#10b981;border-color:#10b981;} .bad{color:#ef4444;border-color:#ef4444;}
.nat-on{color:#3b82f6;border-color:#3b82f6;}
.nat-off{color:#ef4444;border-color:#ef4444;}
.sig-bar{display:inline-block;width:3px;margin-left:1px;background:#475569;}
.sig-bar.act{background:#10b981;}
input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #334155;background:#0f172a;color:white;box-sizing:border-box;font-size:16px;}
select:disabled{opacity:0.5;cursor:not-allowed;}
button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;font-size:16px;transition:opacity 0.2s;}
button:active{opacity:0.8;}
.scanning{background:#a855f7 !important;color:white !important;}
.pending{color:#f59e0b;}
.config-row{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap;}
.config-row input{flex:1;min-width:100px;}
.config-row select{flex:1;min-width:100px;}
.error-message{color:#ef4444;font-size:12px;margin-top:5px;display:none;}
.success-message{color:#10b981;font-size:12px;margin-top:5px;display:none;}
.ios-note{background:#0f172a;padding:10px;border-radius:8px;margin-top:10px;font-size:12px;color:#94a3b8;text-align:center;}
.info-box{background:#0f172a;padding:10px;border-radius:8px;margin-bottom:15px;font-size:13px;border-left:3px solid #38bdf8;}
.warning-5ghz{background:#451a03;border:1px solid #f59e0b;color:#fde047;padding:10px;border-radius:8px;margin-top:10px;font-size:12px;display:none;}
.disabled-option{background:#1a1a2e;border:1px solid #ef4444;color:#fca5a5;padding:10px;border-radius:8px;margin-top:10px;font-size:12px;display:none;}
</style></head><body>
<div class='card'>
  <h3 style='margin:0;color:#38bdf8;'>🛡️ APEX ULTRA V19.9.9</h3>
  <div class='info-box' id='boardInfo'>🔍 Detecting board...</div>
  <div class='st-grid' style='margin-top:15px;'>
    <span>📊 RAM: <b id='ram'>0</b> KB</span>
    <span>🌡️ Temp: <b id='temp'>--</b> °C</span>
    <span>⏱️ Uptime: <b id='uptime'>0</b>s</span>
    <span>🌐 Net: <span id='net' class='badge'>WAIT</span></span>
    <span>🔁 NAT: <span id='nat' class='badge'>WAIT</span></span>
    <span>📱 Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>--</b></span>
    <span style='grid-column:span 2;'>📡 Signal: <b id='rs'>-</b> dBm <span id='bars'></span></span>
  </div>
  <div class='ios-note' id='iosNote' style='display:none;'>
    💡 iOS: If config page doesn't open, open Safari and go to <strong>http://192.168.4.1</strong>
  </div>
</div>

<div class='card'>
  <h3>📡 Uplink Configuration</h3>
  <button id='scanBtn' style='background:#475569;color:white;margin-bottom:10px;'>🔍 Scan WiFi Networks</button>
  <form id='staForm' action='/save-sta' method='get' onsubmit='return validateSTAForm()'>
    <input name='ssid' id='ssidInp' placeholder='WiFi Name' required>
    <input name='pass' type='password' id='staPass' placeholder='Password'>
    <div id='staError' class='error-message'></div>
    <button type='submit'>🚀 Connect Router</button>
  </form>
</div>

<div class='card'>
  <h3>🎛️ Access Point Configuration</h3>
  <form id='apForm' action='/save-ap' method='get' onsubmit='return validateAPForm()'>
    <input name='ssid' id='apSsid' placeholder='AP SSID' value='APEX_ULTRA' required>
    <input name='pass' type='password' id='apPass' placeholder='AP Password (min 8)'>
    <div class='config-row'>
      <select name='band' id='apBand' onchange='updateChannelSuggestions()'>
        <option value='0'>2.4 GHz (2G: ch 1-13)</option>
      </select>
    </div>
    <div class='config-row'>
      <input name='channel' id='apChannel' placeholder='Channel' value='1'>
      <select name='hidden' id='apHidden'>
        <option value='0'>Visible SSID</option>
        <option value='1'>Hidden SSID</option>
      </select>
      <input name='maxclients' id='apMaxClients' placeholder='Max Clients (1-10)' value='7'>
    </div>
    <div id='apError' class='error-message'></div>
    <div id='apSuccess' class='success-message'></div>
    <div id='warning5G' class='warning-5ghz'>
      ⚠️ Lưu ý: Chế độ 5GHz chỉ hoạt động trên ESP32-C5. Thiết bị cũ (2.4GHz only) sẽ không thấy WiFi này.
    </div>
    <div id='disabled5G' class='disabled-option'>
      ❌ Board hiện tại (<span id='currentBoard'></span>) KHÔNG hỗ trợ 5GHz AP mode.<br>
      Chỉ ESP32-C5 mới có khả năng phát WiFi 5GHz.
    </div>
    <button type='submit' style='background:#a855f7;'>💾 Save AP Config & Reboot</button>
  </form>
  <small>⚠️ 5GHz: Tốc độ cao hơn, phạm vi ngắn hơn | 2.4GHz: Phạm vi xa hơn, tương thích tốt hơn</small>
</div>

<div class='card'>
  <h3>⚙️ Advanced Settings</h3>
  <form id='dnsForm' action='/save-dns' method='get'>
    <select name='dnsmode' id='dnsModeSelect'>
      <option value='0'>Captive Portal (Redirect all to config page)</option>
      <option value='1'>Normal DNS (Standard internet browsing)</option>
    </select>
    <div id='dnsInfo' class='success-message' style='margin-top:10px;'></div>
    <button type='submit' style='background:#475569;'>💾 Save DNS Mode & Reboot</button>
  </form>
  <small>💡 Captive Portal: Good for initial setup | Normal: Better for regular use</small>
</div>

<div class='card'><h3>👥 Connected Clients</h3><div id='ctable' style='font-size:12px;'>-</div></div>

<script>
let isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
if (isIOS) document.getElementById('iosNote').style.display = 'block';

let ws = null;
let wsRetryCount = 0;
const MAX_RETRY = 10;
let wsHeartbeat = null;
let boardSupports5G = false;

function updateChannelSuggestions() {
    let band = document.getElementById('apBand').value;
    let chInput = document.getElementById('apChannel');
    let warningDiv = document.getElementById('warning5G');
    
    if (band === '1' && boardSupports5G) {
        warningDiv.style.display = 'block';
        if (chInput.value === '1' || chInput.value === '6' || chInput.value === '11') {
            chInput.value = '36';
        }
        chInput.placeholder = '5GHz: 36,40,44,48,149,153,157,161 (36-165)';
    } else {
        warningDiv.style.display = 'none';
        if (chInput.value === '36') chInput.value = '1';
        chInput.placeholder = '2.4GHz: 1-13';
    }
}

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    try {
        ws = new WebSocket('ws://' + window.location.hostname + '/ws');
        ws.onopen = function() {
            console.log('✅ WebSocket connected');
            wsRetryCount = 0;
            if (wsHeartbeat) clearInterval(wsHeartbeat);
            wsHeartbeat = setInterval(function() {
                if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping');
            }, 15000);
        };
        ws.onclose = function() {
            console.log('⚠️ WebSocket disconnected');
            if (wsHeartbeat) clearInterval(wsHeartbeat);
            if (wsRetryCount < MAX_RETRY) {
                wsRetryCount++;
                setTimeout(connectWebSocket, 2000 * wsRetryCount);
            }
        };
        ws.onerror = function(e) { console.log('❌ WebSocket error:', e); };
        ws.onmessage = function(e) {
            let d = JSON.parse(e.data);
            document.getElementById('ram').innerText = Math.round(d.ram/1024);
            document.getElementById('temp').innerText = d.temp.toFixed(1);
            document.getElementById('uptime').innerText = d.uptime;
            document.getElementById('net').innerText = d.internet ? 'ONLINE' : 'OFFLINE';
            document.getElementById('net').className = 'badge ' + (d.internet ? 'ok' : 'bad');
            document.getElementById('nat').innerText = d.nat ? 'ACTIVE' : 'DISABLED';
            document.getElementById('nat').className = 'badge ' + (d.nat ? 'nat-on' : 'nat-off');
            document.getElementById('rs').innerText = d.rssi;
            document.getElementById('clientCount').innerText = d.clientCount;
            document.getElementById('clientLimit').innerText = d.clientLimit;
            let b = ''; for(let i=1;i<=4;i++) b += `<div class='sig-bar ${i<=d.bars?"act":""}' style='height:${i*3}px'></div>`;
            document.getElementById('bars').innerHTML = b;
            let h = ''; d.clients.forEach(c => { 
                let pendingClass = c.ip === 'Pending...' ? 'pending' : '';
                h += `<div>• <b class='${pendingClass}'>${c.ip}</b> <small style='color:#64748b'>[${c.mac}]</small></div>`; 
            });
            document.getElementById('ctable').innerHTML = h || '<i style="color:#64748b;">No clients connected</i>';
        };
    } catch(e) {
        console.log('WebSocket init error:', e);
        setTimeout(connectWebSocket, 3000);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    connectWebSocket();
    
    // Get board info and config
    fetch('/get-board-info').then(r=>r.json()).then(info=>{
        boardSupports5G = info.supports_5ghz;
        let boardHtml = `🔧 Board: <strong>${info.model}</strong> | 5GHz: ${info.supports_5ghz ? '✅ Supported' : '❌ Not supported'}`;
        document.getElementById('boardInfo').innerHTML = boardHtml;
        
        let bandSelect = document.getElementById('apBand');
        let disabledDiv = document.getElementById('disabled5G');
        let currentBoardSpan = document.getElementById('currentBoard');
        
        if (!boardSupports5G) {
            // Remove 5GHz option and disable it
            while(bandSelect.options.length > 1) bandSelect.remove(1);
            disabledDiv.style.display = 'block';
            currentBoardSpan.innerText = info.model;
            bandSelect.disabled = true;
        } else {
            // Add 5GHz option
            let option = document.createElement('option');
            option.value = '1';
            option.text = '5 GHz (5G: ch 36-165) - WiFi 6';
            bandSelect.appendChild(option);
        }
        
        // Load saved config
        fetch('/get-ap-config').then(r=>r.json()).then(d=>{
            if (boardSupports5G && d.band_5ghz) {
                bandSelect.value = '1';
            } else {
                bandSelect.value = '0';
            }
            document.getElementById('apChannel').value = d.channel;
            document.getElementById('apHidden').value = d.hidden ? '1' : '0';
            document.getElementById('apMaxClients').value = d.max_clients;
            updateChannelSuggestions();
        }).catch(()=>{});
    }).catch(()=>{});
});

function validateSTAForm() {
    let ssid = document.getElementById('ssidInp').value.trim();
    let errorDiv = document.getElementById('staError');
    if(ssid === '') {
        errorDiv.innerText = '❌ SSID cannot be empty';
        errorDiv.style.display = 'block';
        return false;
    }
    errorDiv.style.display = 'none';
    return true;
}

function validateAPForm() {
    let errorDiv = document.getElementById('apError');
    let successDiv = document.getElementById('apSuccess');
    let password = document.getElementById('apPass').value;
    let channel = parseInt(document.getElementById('apChannel').value);
    let maxClients = parseInt(document.getElementById('apMaxClients').value);
    let band = document.getElementById('apBand').value;

    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';

    if(password.length > 0 && password.length < 8) {
        errorDiv.innerText = '❌ Password must be at least 8 characters (or leave empty to keep current)';
        errorDiv.style.display = 'block';
        return false;
    }

    // Validate channel based on band (only if 5GHz is actually supported)
    if (band === '1' && boardSupports5G) {
        if(isNaN(channel) || channel < 36 || channel > 165) {
            errorDiv.innerText = '❌ 5GHz channel must be between 36 and 165 (recommended: 36,40,44,48,149,153,157,161)';
            errorDiv.style.display = 'block';
            return false;
        }
    } else {
        if(isNaN(channel) || channel < 1 || channel > 13) {
            errorDiv.innerText = '❌ 2.4GHz channel must be between 1 and 13';
            errorDiv.style.display = 'block';
            return false;
        }
    }

    if(isNaN(maxClients) || maxClients < 1 || maxClients > 10) {
        errorDiv.innerText = '❌ Max clients must be between 1 and 10';
        errorDiv.style.display = 'block';
        return false;
    }

    successDiv.innerText = '✅ Settings validated! Rebooting...';
    successDiv.style.display = 'block';
    return true;
}

document.getElementById('scanBtn').onclick = async () => {
    let btn = document.getElementById('scanBtn');
    if(btn.innerText.includes('Scanning')) return;
    btn.innerText = '⏳ Scanning...';
    btn.classList.add('scanning');

    try {
        let r = await fetch('/scan');
        let nets = await r.json();
        let listStr = nets.map((n,i)=> i+": "+n.ssid+" ("+n.rssi+"dBm)").join("\n");
        let s = prompt("Select WiFi (enter number):\n" + listStr);
        if(s !== null && nets[s]) document.getElementById('ssidInp').value = nets[s].ssid;
    } catch(e) {
        let xhr = new XMLHttpRequest();
        xhr.open('GET', '/scan', true);
        xhr.onload = function() {
            let nets = JSON.parse(xhr.responseText);
            let listStr = nets.map((n,i)=> i+": "+n.ssid+" ("+n.rssi+"dBm)").join("\n");
            let s = prompt("Select WiFi (enter number):\n" + listStr);
            if(s !== null && nets[s]) document.getElementById('ssidInp').value = nets[s].ssid;
        };
        xhr.send();
    }

    btn.innerText = '🔍 Scan WiFi Networks';
    btn.classList.remove('scanning');
};

fetch('/get-dns').then(r=>r.json()).then(d=>{
    document.getElementById('dnsModeSelect').value = d.dnsmode;
}).catch(()=>{});
</script></body></html>
)rawliteral";

// ================= OPTIMIZED SCAN HANDLER =================
void handleScan(AsyncWebServerRequest *r) {
    if (scanInProgress.exchange(true)) {
        r->send(429, "application/json", "[]");
        return;
    }

    WiFi.scanNetworks(true);
    int n = -1;
    int timeout = 8000;
    int elapsed = 0;

    while (n == -1 && elapsed < timeout) {
        delay(100);
        n = WiFi.scanComplete();
        elapsed += 100;
        esp_task_wdt_reset();
    }

    if (n == -2 || n <= 0) {
        WiFi.scanDelete();
        scanInProgress.store(false);
        r->send(500, "application/json", "[]");
        return;
    }

    JsonDocument doc;
    JsonArray array = doc.to<JsonArray>();

    int limit = (n > MAX_SCAN_NETWORKS) ? MAX_SCAN_NETWORKS : n;
    for (int i = 0; i < limit; i++) {
        JsonObject item = array.add<JsonObject>();
        item["ssid"] = WiFi.SSID(i);
        item["rssi"] = WiFi.RSSI(i);
    }

    String out;
    serializeJson(doc, out);

    WiFi.scanDelete();
    scanInProgress.store(false);
    r->send(200, "application/json", out);
}

// ================= CORE NETWORK TASK =================
void networkTask(void * pv) {
    esp_task_wdt_add(NULL);
    static uint32_t lastBroadcast = 0;
    static bool natInit = false;
    static int lastClientCount = -1;
    static unsigned long lastTempUpdate = 0;

    for(;;) {
        esp_task_wdt_reset();
        uint32_t currHeap = heap_caps_get_free_size(MALLOC_CAP_8BIT);

        if (currHeap < MEM_CRITICAL_THRESHOLD) {
            LOCK_TCPIP_CORE();
            ip_napt_disable();
            ip_napt_init(MAX_NAPT_SLOTS, MAX_NAPT_TCP);
            UNLOCK_TCPIP_CORE();
            natEnabled.store(false);
            Serial.println("⚠️ Memory critical - NAT purged");
        }

        if (WiFi.status() == WL_CONNECTED) {
            if (!natInit) {
                LOCK_TCPIP_CORE();
                ip_napt_init(MAX_NAPT_SLOTS, MAX_NAPT_TCP);
                UNLOCK_TCPIP_CORE();
                natInit = true;
                Serial.println("✅ NAT initialized");
            }
            if (!natEnabled.load()) {
                LOCK_TCPIP_CORE();
                if (ip_napt_enable(WiFi.localIP(), 1)) {
                    natEnabled.store(true);
                    Serial.println("✅ NAT Enabled - Full router mode");
                }
                UNLOCK_TCPIP_CORE();
            }
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

            int r = lastRSSI.load();
            doc["bars"] = (r > -55) ? 4 : (r > -65) ? 3 : (r > -75) ? 2 : (r > -85) ? 1 : 0;

            JsonArray clis = doc["clients"].to<JsonArray>();

            wifi_sta_list_t wifi_sta_list;
            esp_wifi_ap_get_sta_list(&wifi_sta_list);

            if (lastClientCount != wifi_sta_list.num) {
                lastClientCount = wifi_sta_list.num;
                Serial.printf("📡 Clients: %d/%d connected\n", lastClientCount, max_clients);
            }

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

// ================= SETUP =================
void setup() {
    Serial.begin(115200);
    delay(100);
    uptimeStart = millis();
    
    // Detect board capabilities FIRST
    detectBoardCapabilities();
    
    prefs.begin("apex-v19", false);

    // Load configurations with validation
    sta_ssid = prefs.getString("sta_ssid", "");
    sta_pass = urlDecode(prefs.getString("sta_pass", ""));
    ap_ssid = prefs.getString("ap_ssid", "APEX_ULTRA");
    ap_pass = validateAPPassword(urlDecode(prefs.getString("ap_pass", "12345678")));
    
    // Only load 5GHz setting if board supports it
    if (board_supports_5ghz) {
        use_5ghz = prefs.getBool("use_5ghz", DEFAULT_BAND_5GHZ);
    } else {
        use_5ghz = false;
    }
    
    ap_channel = validateChannel(prefs.getInt("ap_channel", DEFAULT_AP_CHANNEL), use_5ghz);
    ap_hidden = prefs.getBool("ap_hidden", DEFAULT_AP_HIDDEN);
    max_clients = validateMaxClients(prefs.getInt("max_clients", DEFAULT_MAX_CLIENTS));
    dns_mode = prefs.getInt("dns_mode", DEFAULT_DNS_MODE);

    Serial.println("\n╔════════════════════════════════════════════╗");
    Serial.println("║   APEX ULTRA V19.9.9 - 5GHz Auto-Detect ║");
    Serial.println("║   iOS & Android Compatible              ║");
    Serial.println("╚════════════════════════════════════════════╝\n");

#ifndef CONFIG_IDF_TARGET_ESP32C5
    temp_sensor_config_t temp_sensor = TSENS_CONFIG_DEFAULT();
    temp_sensor.dac_offset = TSENS_DAC_L2;
    temp_sensor_set_config(temp_sensor);
    temp_sensor_start();
#endif

    // Setup WiFi mode
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
    
    if (board_supports_5ghz) {
        wifi_config_t ap_config = {};
        strcpy((char*)ap_config.ap.ssid, ap_ssid.c_str());
        strcpy((char*)ap_config.ap.password, ap_pass.c_str());
        ap_config.ap.ssid_len = ap_ssid.length();
        ap_config.ap.channel = ap_channel;
        ap_config.ap.authmode = ap_pass.length() ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        ap_config.ap.ssid_hidden = ap_hidden ? 1 : 0;
        ap_config.ap.max_connection = max_clients;
        
        if (use_5ghz) {
            ap_config.ap.phy_11b = 0;
            ap_config.ap.phy_11g = 0;
            ap_config.ap.phy_11n = 1;
            ap_config.ap.phy_11ax = 1;
            esp_wifi_set_band(WIFI_BAND_5GHZ);
            Serial.println("📡 5GHz Mode ENABLED - WiFi 6 on 5GHz band");
        } else {
            esp_wifi_set_band(WIFI_BAND_2GHZ);
            Serial.println("📡 2.4GHz Mode - Standard WiFi");
        }
        
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        esp_wifi_start();
    } else {
        WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str(), ap_channel, ap_hidden ? 1 : 0, max_clients);
    }

    Serial.printf("📡 AP: %s | %s | Ch:%d | IP: %s\n", 
                  ap_ssid.c_str(), (use_5ghz && board_supports_5ghz) ? "5GHz" : "2.4GHz",
                  ap_channel, AP_IP.toString().c_str());
    Serial.printf("📡 Hidden: %s | Max Clients: %d\n", 
                  ap_hidden ? "Yes" : "No", max_clients);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifiEventHandler,
                                                        NULL,
                                                        NULL));

    if (sta_ssid.length() > 0) {
        WiFi.begin(sta_ssid.c_str(), sta_pass.c_str());
        Serial.printf("📡 Connecting to STA: %s\n", sta_ssid.c_str());
    } else {
        Serial.printf("⚠️ Connect to AP: %s | http://%s\n", ap_ssid.c_str(), AP_IP.toString().c_str());
        Serial.println("   Then configure your WiFi network via web interface");
    }

    // Web Server Routes
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){ 
        r->send_P(200, "text/html", index_html); 
    });
    server.on("/scan", HTTP_GET, handleScan);
    
    server.on("/get-board-info", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"model\":\"" + board_model + "\",\"supports_5ghz\":" + 
                      String(board_supports_5ghz ? "true" : "false") + "}";
        r->send(200, "application/json", json);
    });
    
    server.on("/get-ap-config", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"band_5ghz\":" + String(use_5ghz ? "true" : "false") + 
                      ",\"channel\":" + String(ap_channel) +
                      ",\"hidden\":" + String(ap_hidden ? "true" : "false") +
                      ",\"max_clients\":" + String(max_clients) + "}";
        r->send(200, "application/json", json);
    });
    
    server.on("/get-dns", HTTP_GET, [](AsyncWebServerRequest *r){
        String json = "{\"dnsmode\":" + String(dns_mode) + "}";
        r->send(200, "application/json", json);
    });

    server.on("/save-sta", HTTP_GET, [](AsyncWebServerRequest *r){
        if(r->hasParam("ssid")) prefs.putString("sta_ssid", r->getParam("ssid")->value());
        if(r->hasParam("pass")) prefs.putString("sta_pass", r->getParam("pass")->value());
        r->send(200, "text/plain", "✅ STA Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-ap", HTTP_GET, [](AsyncWebServerRequest *r){
        if(r->hasParam("ssid")) prefs.putString("ap_ssid", r->getParam("ssid")->value());

        if(r->hasParam("pass")) {
            String p = r->getParam("pass")->value();
            if (p.length() == 0 || p.length() >= 8) {
                prefs.putString("ap_pass", p);
            }
        }

        // Only save band setting if board supports 5GHz
        if(r->hasParam("band") && board_supports_5ghz) {
            prefs.putBool("use_5ghz", r->getParam("band")->value() == "1");
        }

        if(r->hasParam("channel")) {
            bool is5GHz = false;
            if(r->hasParam("band") && board_supports_5ghz) {
                is5GHz = (r->getParam("band")->value() == "1");
            }
            int ch = r->getParam("channel")->value().toInt();
            prefs.putInt("ap_channel", validateChannel(ch, is5GHz));
        }

        if(r->hasParam("hidden")) {
            prefs.putBool("ap_hidden", r->getParam("hidden")->value() == "1");
        }

        if(r->hasParam("maxclients")) {
            int clients = r->getParam("maxclients")->value().toInt();
            prefs.putInt("max_clients", validateMaxClients(clients));
        }

        r->send(200, "text/plain", "✅ AP Config Saved. Rebooting...");
        delay(1000);
        ESP.restart();
    });

    server.on("/save-dns", HTTP_GET, [](AsyncWebServerRequest *r){
        if(r->hasParam("dnsmode")) {
            int mode = r->getParam("dnsmode")->value().toInt();
            if (mode == DNS_MODE_CAPTIVE || mode == DNS_MODE_NORMAL) {
                prefs.putInt("dns_mode", mode);
                r->send(200, "text/plain", "✅ DNS Mode Saved. Rebooting...");
                delay(1000);
                ESP.restart();
                return;
            }
        }
        r->send(400, "text/plain", "❌ Invalid DNS mode");
    });

    ws.onEvent([](AsyncWebSocket *s, AsyncWebSocketClient *c, AwsEventType t, void *arg, uint8_t *data, size_t len) {
        if (t == WS_EVT_CONNECT) {
            Serial.printf("🔌 WebSocket client connected: %u\n", c->id());
        } else if (t == WS_EVT_DISCONNECT) {
            Serial.printf("🔌 WebSocket client disconnected: %u\n", c->id());
        } else if (t == WS_EVT_DATA) {
            if (len == 4 && memcmp(data, "ping", 4) == 0) {
                c->text("pong");
            }
        }
    });
    server.addHandler(&ws);

    server.begin();
    setupDNS();
    Serial.printf("🌐 Web: http://%s\n", AP_IP.toString().c_str());
    Serial.printf("🌐 DNS Mode: %s\n", dns_mode == DNS_MODE_CAPTIVE ? "Captive Portal" : "Normal DNS");

    if (MDNS.begin("apex")) {
        Serial.println("✅ mDNS: http://apex.local");
    }

    esp_task_wdt_init(WATCHDOG_TIMEOUT, true);
    esp_task_wdt_add(NULL);

    xTaskCreatePinnedToCore(networkTask, "NET", 8192, NULL, 4, NULL, 0);
    xTaskCreatePinnedToCore([](void* p){ 
        esp_task_wdt_add(NULL);
        for(;;){ 
            esp_task_wdt_reset();
            if(WiFi.status() == WL_CONNECTED){
                WiFiClient c; 
                c.setTimeout(1500);
                internetOK.store(c.connect("1.1.1.1", 53)); 
                c.stop();
            } else {
                internetOK.store(false);
            }
            vTaskDelay(20000); 
        } 
    }, "CHK", 2048, NULL, 1, NULL, 1);

    pinMode(LED_BUILTIN, OUTPUT);
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, LOW);
        delay(80);
        digitalWrite(LED_BUILTIN, HIGH);
        delay(80);
    }
    Serial.printf("✅ APEX ULTRA V19.9.9 Ready on %s!\n", board_model.c_str());
    if (use_5ghz && board_supports_5ghz) {
        Serial.printf("   🌟 5GHz AP Mode Active - Channel %d\n", ap_channel);
        Serial.printf("   📱 Connect with WiFi 6 compatible devices\n");
    }
}

void loop() { 
    dns.processNextRequest(); 
    vTaskDelay(10); 
}
