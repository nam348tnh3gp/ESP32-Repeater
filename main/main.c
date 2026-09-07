#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_chip_info.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_task_wdt.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/etharp.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"   // <-- thêm để dùng inet_addr()

#include "esp_http_server.h"
#include "cJSON.h"

// ================= DEFINES =================
#define AP_SSID "APEX_ULTRA"
#define AP_PASS "12345678"
#define AP_CHANNEL 1
#define AP_MAX_CONN 7

#define STA_SSID_CONF "sta_ssid"
#define STA_PASS_CONF "sta_pass"

#define NAT_MAX_SLOTS 512
#define NAT_MAX_TCP 256

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

#define STA_MAX_RETRY 5
#define STA_RECONNECT_BACKOFF_MS 30000

#define WATCHDOG_TIMEOUT_S 45

#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3

#define SSID_BUF_LEN 33
#define PASS_BUF_LEN 65
#define QUERY_VALUE_LEN 96

// ================= GLOBALS =================
static const char *TAG = "APEX_ROUTER";

static EventGroupHandle_t wifi_event_group;
static int s_retry_num = 0;
static bool sta_configured = false;

static httpd_handle_t server = NULL;

static SemaphoreHandle_t state_mutex;
static bool nat_enabled = false;
static esp_netif_t *s_ap_netif = NULL;
static bool internet_ok = false;
static int current_clients = 0;
static int last_rssi = -100;

static char sta_ssid[SSID_BUF_LEN] = {0};
static char sta_pass[PASS_BUF_LEN] = {0};
static char ap_ssid[SSID_BUF_LEN] = "APEX_ULTRA";
static char ap_pass[PASS_BUF_LEN] = "12345678";
static int32_t ap_channel = AP_CHANNEL;
static int32_t max_clients = AP_MAX_CONN;

static int32_t nat_slots = NAT_MAX_SLOTS;
static int32_t nat_tcp = NAT_MAX_TCP;

static nvs_handle_t s_nvs_handle;

static SemaphoreHandle_t nvs_mutex;
static char session_token[24] = {0};
static unsigned long last_config_window_ms = 0;
static int config_request_count = 0;

// ================= CAPTIVE PORTAL FIX =================
static int dns_socket = -1;          // (không bắt buộc dùng)
static TaskHandle_t dns_task_handle = NULL;

// HTML trang chủ (giữ nguyên)
static const char *index_html_tmpl =
"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
"<link rel='icon' href='data:,'>"
"<title>APEX ULTRA</title>"
"<style>"
"*{box-sizing:border-box;}body{font-family:Arial;background:#020617;color:#f8fafc;padding:15px;max-width:480px;margin:0 auto;}"
".card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;}"
"label{display:block;font-size:13px;color:#94a3b8;margin-top:8px;}"
"input,select{width:100%;padding:12px;margin:4px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}"
"input:invalid{border-color:#f87171;}"
"button{width:100%;padding:14px;margin-top:10px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}"
"button:disabled{background:#475569;color:#94a3b8;cursor:wait;}"
".warning{color:#f59e0b;margin-top:8px;}"
".hint{font-size:12px;color:#64748b;margin:2px 0 0;}"
".msg{font-size:13px;margin-top:8px;min-height:16px;}"
".msg.ok{color:#4ade80;}.msg.err{color:#f87171;}"
".offline{color:#f87171;}"
"</style>"
"</head><body>"
"<div class='card'><h3>APEX ULTRA V22.0.2 - ESP-IDF (Fixed)</h3>"
"<div>RAM: <b id='ram'>0</b> KB</div>"
"<div>Internet: <span id='net'>WAIT</span></div>"
"<div>NAT: <span id='nat'>WAIT</span></div>"
"<div>Uplink: <span id='staStatus'>WAIT</span></div>"
"<div>Signal: <b id='rssi'>-</b> dBm</div>"
"<div>Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>7</b></div>"
"<div id='ctable' style='font-size:12px;margin-top:6px;'>-</div>"
"<div id='weakWarn' class='warning' style='display:none;'>⚠️ Đang dùng mật khẩu AP mặc định — hãy đổi ngay!</div>"
"<div id='pollErr' class='msg err' style='display:none;'>⚠️ Mất kết nối tới thiết bị — đang thử lại...</div>"
"</div>"
"<div class='card'><h3>Uplink Configuration</h3>"
"<form id='staForm' action='/save-sta' method='post' class='authForm'>"
"<label for='staSsidInp'>Tên WiFi cần kết nối</label>"
"<input name='ssid' id='staSsidInp' placeholder='WiFi Name' required maxlength='32'>"
"<label for='staPassInp'>Mật khẩu</label>"
"<input name='pass' id='staPassInp' type='password' placeholder='Password' maxlength='63'>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Connect</button>"
"<div class='msg' id='staMsg'></div>"
"</form></div>"
"<div class='card'><h3>AP Configuration</h3>"
"<form id='apForm' action='/save-ap' method='post' class='authForm'>"
"<label for='apSsidInp'>Tên WiFi phát ra (AP SSID)</label>"
"<input name='ssid' id='apSsidInp' placeholder='AP SSID' maxlength='32'>"
"<label for='apPassInp'>Mật khẩu mới (tối thiểu 8 ký tự)</label>"
"<input name='pass' id='apPassInp' type='password' placeholder='Password (min 8)' minlength='8' maxlength='63'>"
"<p class='hint'>Để trống nếu không muốn đổi mật khẩu.</p>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Save & Reboot</button>"
"<div class='msg' id='apMsg'></div>"
"</form></div>"
"<div class='card'><h3>NAT Settings</h3>"
"<form id='natForm' action='/save-nat' method='post' class='authForm'>"
"<label for='natSlotsInp'>NAPT Slots (64-4096)</label>"
"<input name='slots' id='natSlotsInp' type='number' min='64' max='4096' placeholder='NAPT Slots' value='512'>"
"<label for='natTcpInp'>TCP ports (32-2048)</label>"
"<input name='tcp' id='natTcpInp' type='number' min='32' max='2048' placeholder='TCP ports' value='256'>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Save & Reboot</button>"
"<div class='msg' id='natMsg'></div>"
"</form></div>"
"<script>"
"let pollFailed=0;"
"function fetchData(){fetch('/api/status').then(r=>r.json()).then(d=>{"
"pollFailed=0;document.getElementById('pollErr').style.display='none';"
"document.getElementById('ram').innerText=Math.round(d.ram/1024);"
"document.getElementById('net').innerText=d.internet?'ONLINE':'OFFLINE';"
"document.getElementById('nat').innerText=d.nat?'ACTIVE':'OFF';"
"document.getElementById('staStatus').innerText=d.staConnected?('Connected: '+d.staSsid):(d.staSsid?'Connecting to '+d.staSsid+'...':'Not configured');"
"document.getElementById('rssi').innerText=d.staConnected?d.rssi:'-';"
"document.getElementById('clientCount').innerText=d.clients;"
"document.getElementById('weakWarn').style.display=d.weakPassword?'block':'none';"
"}).catch(()=>{pollFailed++;if(pollFailed>=2)document.getElementById('pollErr').style.display='block';});}"
"setInterval(fetchData,2000);fetchData();"
"function fetchClients(){fetch('/api/clients').then(r=>r.json()).then(list=>{"
"const el=document.getElementById('ctable');"
"if(!list.length){el.innerHTML='<i>No clients</i>';return;}"
"el.innerHTML=list.map(c=>`<div>• ${c.ip} <small>[${c.mac}]</small></div>`).join('');"
"}).catch(()=>{});}"
"setInterval(fetchClients,5000);fetchClients();"
"function loadConfig(){fetch('/api/config').then(r=>r.json()).then(c=>{"
"document.getElementById('apSsidInp').value=c.apSsid;"
"if(c.staSsid){document.getElementById('staSsidInp').value=c.staSsid;}"
"});}"
"loadConfig();"
"fetch('/get-token').then(r=>r.json()).then(t=>{"
"document.querySelectorAll('.tokenField').forEach(el=>el.value=t.token);"
"});"
"function bindForm(formId,msgId,rebootWarn){"
"const form=document.getElementById(formId);"
"const msg=document.getElementById(msgId);"
"const btn=form.querySelector('button');"
"form.addEventListener('submit',function(ev){"
"ev.preventDefault();"
"btn.disabled=true;btn.innerText='Đang lưu...';"
"msg.className='msg';msg.innerText='';"
"fetch(form.action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(form)).toString()})"
".then(async r=>{const t=await r.text();if(r.ok){msg.className='msg ok';msg.innerText=t+(rebootWarn?' Thiết bị sẽ mất kết nối vài giây...':'');}"
"else{msg.className='msg err';msg.innerText=t;btn.disabled=false;btn.innerText='Retry';}})"
".catch(()=>{msg.className='msg err';msg.innerText='Không thể kết nối tới thiết bị.';btn.disabled=false;btn.innerText='Retry';});"
"});}"
"bindForm('staForm','staMsg',true);"
"bindForm('apForm','apMsg',true);"
"bindForm('natForm','natMsg',true);"
"</script></body></html>";

// ================= HÀM KIỂM TRA INTERNET =================
static bool is_internet_available(void) {
    bool ok;
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    ok = internet_ok;
    xSemaphoreGive(state_mutex);
    return ok;
}

// ================= CAPTIVE PORTAL DNS SERVER =================
static void dns_captive_task(void *pv) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t buffer[512];

    // Tạo socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS: Failed to create socket");
        return;
    }

    // Bind tới port 53 (DNS)
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(53);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "DNS: Failed to bind to port 53");
        close(sock);
        return;
    }

    ESP_LOGI(TAG, "✅ DNS Captive Portal started on port 53");

    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&client_addr, &addr_len);
        if (len > 0) {
            bool internet = is_internet_available();

            if (internet) {
                // Forward DNS query tới DNS upstream (8.8.8.8)
                int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (upstream_sock >= 0) {
                    struct sockaddr_in upstream_addr;
                    upstream_addr.sin_family = AF_INET;
                    upstream_addr.sin_port = htons(53);
                    upstream_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

                    sendto(upstream_sock, buffer, len, 0,
                           (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));

                    // Timeout 1 giây để nhận phản hồi
                    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
                    setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                    uint8_t upstream_resp[512];
                    int up_len = recv(upstream_sock, upstream_resp, sizeof(upstream_resp), 0);
                    if (up_len > 0) {
                        // Gửi lại phản hồi cho client
                        sendto(sock, upstream_resp, up_len, 0,
                               (struct sockaddr *)&client_addr, addr_len);
                    }
                    close(upstream_sock);
                }
            } else {
                // Xây dựng DNS response giả trả IP AP (192.168.4.1)
                uint8_t response[512];
                memset(response, 0, sizeof(response));

                int resp_len = len;
                memcpy(response, buffer, len);

                response[2] = 0x85;  // QR=1, AA=1
                response[3] = 0x80;  // RA=1
                response[6] = 0x00;
                response[7] = 0x01;  // Answer count = 1

                // Tìm vị trí bắt đầu của QNAME
                int qname_start = 12;
                int qname_len = 0;
                for (int i = qname_start; i < len; i++) {
                    if (buffer[i] == 0) {
                        qname_len = i - qname_start;
                        break;
                    }
                }

                int off = qname_start + qname_len + 1;
                response[off++] = 0xC0;
                response[off++] = 0x0C;

                // Type A (1)
                response[off++] = 0x00;
                response[off++] = 0x01;

                // Class IN (1)
                response[off++] = 0x00;
                response[off++] = 0x01;

                // TTL (60 seconds)
                response[off++] = 0x00;
                response[off++] = 0x00;
                response[off++] = 0x00;
                response[off++] = 0x3C;

                // Data length: 4 bytes
                response[off++] = 0x00;
                response[off++] = 0x04;

                // IP: 192.168.4.1
                response[off++] = 192;
                response[off++] = 168;
                response[off++] = 4;
                response[off++] = 1;

                resp_len = off;

                sendto(sock, response, resp_len, 0,
                       (struct sockaddr *)&client_addr, addr_len);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    close(sock);
}

// ================= CAPTIVE PORTAL HTTP HANDLERS =================
static esp_err_t captive_204_handler(httpd_req_t *req) {
    if (is_internet_available()) {
        // Khi có Internet thật, trả 404 để tránh bị coi là captive portal
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_send(req, NULL, 0);
    } else {
        // Khi chưa có Internet, giữ captive portal
        httpd_resp_set_status(req, "204 No Content");
        httpd_resp_send(req, NULL, 0);
    }
    return ESP_OK;
}

static esp_err_t captive_success_handler(httpd_req_t *req) {
    if (is_internet_available()) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_send(req, NULL, 0);
    } else {
        const char *html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Internet OK</title></head>"
                           "<body style='font-family:Arial;text-align:center;padding:50px;'>"
                           "<h1>✅ Internet Connection OK</h1>"
                           "<p>You can now browse the internet.</p>"
                           "<a href='http://192.168.4.1'>Go to Dashboard</a>"
                           "</body></html>";
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, html, strlen(html));
    }
    return ESP_OK;
}

// ================= UTILITY FUNCTIONS =================
static void url_decode(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) return;
    size_t out = 0;
    while (*src && out + 1 < dst_size) {
        char a, b;
        if ((*src == '%') && (a = src[1]) && (b = src[2]) &&
            isxdigit((unsigned char)a) && isxdigit((unsigned char)b)) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            dst[out++] = (char)((a << 4) | b);
            src += 3;
        } else if (*src == '+') {
            dst[out++] = ' ';
            src++;
        } else {
            dst[out++] = *src++;
        }
    }
    dst[out] = '\0';
}

static void save_config(void) {
    xSemaphoreTake(nvs_mutex, portMAX_DELAY);
    nvs_set_str(s_nvs_handle, "ap_ssid", ap_ssid);
    nvs_set_str(s_nvs_handle, "ap_pass", ap_pass);
    nvs_set_i32(s_nvs_handle, "ap_channel", ap_channel);
    nvs_set_i32(s_nvs_handle, "max_clients", max_clients);
    nvs_set_i32(s_nvs_handle, "nat_slots", nat_slots);
    nvs_set_i32(s_nvs_handle, "nat_tcp", nat_tcp);
    nvs_commit(s_nvs_handle);
    xSemaphoreGive(nvs_mutex);
}

static void load_config(void) {
    size_t len;

    len = sizeof(ap_ssid);
    if (nvs_get_str(s_nvs_handle, "ap_ssid", ap_ssid, &len) != ESP_OK) {
        strncpy(ap_ssid, AP_SSID, sizeof(ap_ssid) - 1);
    }

    len = sizeof(ap_pass);
    if (nvs_get_str(s_nvs_handle, "ap_pass", ap_pass, &len) != ESP_OK) {
        strncpy(ap_pass, AP_PASS, sizeof(ap_pass) - 1);
    }

    nvs_get_i32(s_nvs_handle, "ap_channel", &ap_channel);
    if (ap_channel < 1 || ap_channel > 13) ap_channel = AP_CHANNEL;

    nvs_get_i32(s_nvs_handle, "max_clients", &max_clients);
    if (max_clients < 1 || max_clients > 10) max_clients = AP_MAX_CONN;

    nvs_get_i32(s_nvs_handle, "nat_slots", &nat_slots);
    if (nat_slots < 64 || nat_slots > 4096) nat_slots = NAT_MAX_SLOTS;

    nvs_get_i32(s_nvs_handle, "nat_tcp", &nat_tcp);
    if (nat_tcp < 32 || nat_tcp > 2048) nat_tcp = NAT_MAX_TCP;
    if (nat_slots < nat_tcp) nat_slots = nat_tcp;

    len = sizeof(sta_ssid);
    nvs_get_str(s_nvs_handle, STA_SSID_CONF, sta_ssid, &len);

    len = sizeof(sta_pass);
    nvs_get_str(s_nvs_handle, STA_PASS_CONF, sta_pass, &len);

    sta_configured = (strlen(sta_ssid) > 0);
}

// ================= NAT FUNCTIONS =================
static void enable_nat(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool already = nat_enabled;
    xSemaphoreGive(state_mutex);
    if (already) return;

    if (s_ap_netif == NULL) {
        ESP_LOGE(TAG, "enable_nat: AP netif chưa được khởi tạo");
        return;
    }
    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_napt_enable failed: %s", esp_err_to_name(err));
        return;
    }

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    nat_enabled = true;
    xSemaphoreGive(state_mutex);
    ESP_LOGI(TAG, "NAT enabled (slots=%d, tcp=%d)", (int)nat_slots, (int)nat_tcp);
}

static void disable_nat(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool was_enabled = nat_enabled;
    xSemaphoreGive(state_mutex);
    if (!was_enabled) return;

    if (s_ap_netif != NULL) {
        esp_err_t err = esp_netif_napt_disable(s_ap_netif);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_netif_napt_disable failed: %s", esp_err_to_name(err));
        }
    }

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    nat_enabled = false;
    xSemaphoreGive(state_mutex);
    ESP_LOGI(TAG, "NAT disabled");
}

// ================= WIFI EVENT HANDLER =================
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (sta_configured) esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < STA_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry connecting... (%d/%d)", s_retry_num, STA_MAX_RETRY);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGW(TAG, "STA retry exhausted, will retry again in background every %d s",
                     STA_RECONNECT_BACKOFF_MS / 1000);
        }
        disable_nat();
        ESP_LOGI(TAG, "STA disconnected");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        current_clients++;
        int c = current_clients;
        xSemaphoreGive(state_mutex);
        ESP_LOGI(TAG, "Client connected: %d/%d", c, (int)max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        if (current_clients > 0) current_clients--;
        int c = current_clients;
        xSemaphoreGive(state_mutex);
        ESP_LOGI(TAG, "Client disconnected: %d/%d", c, (int)max_clients);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupClearBits(wifi_event_group, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        enable_nat();
    }
}

// FIX #4: task nền định kỳ thử kết nối lại STA
static void sta_reconnect_task(void *pv) {
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_task_wdt_reset();
        EventBits_t bits = xEventGroupGetBits(wifi_event_group);
        if (sta_configured && !(bits & WIFI_CONNECTED_BIT)) {
            ESP_LOGI(TAG, "Background STA reconnect attempt...");
            s_retry_num = 0;
            esp_wifi_connect();
        }
        vTaskDelay(pdMS_TO_TICKS(STA_RECONNECT_BACKOFF_MS));
    }
}

// ================= WIFI INIT =================
static void wifi_init(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .password = "",
            .ssid_len = 0,
            .channel = ap_channel,
            .max_connection = max_clients,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    strncpy((char *)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid) - 1);
    strncpy((char *)ap_config.ap.password, ap_pass, sizeof(ap_config.ap.password) - 1);
    if (strlen(ap_pass) == 0) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    if (strlen(sta_ssid) > 0) {
        wifi_config_t sta_config = {
            .sta = {
                .ssid = "",
                .password = "",
                .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            },
        };
        strncpy((char *)sta_config.sta.ssid, sta_ssid, sizeof(sta_config.sta.ssid) - 1);
        strncpy((char *)sta_config.sta.password, sta_pass, sizeof(sta_config.sta.password) - 1);
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    }

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi started. AP: %s on channel %d", ap_ssid, (int)ap_channel);
}

// ================= AUTH / RATE LIMIT =================
static bool read_post_body(httpd_req_t *req, char *buf, size_t buf_size) {
    int total_len = req->content_len;
    if (total_len <= 0 || (size_t)total_len >= buf_size) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_send(req, "Invalid or too large request body", HTTPD_RESP_USE_STRLEN);
        return false;
    }
    int received = 0;
    while (received < total_len) {
        int ret = httpd_req_recv(req, buf + received, total_len - received);
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (ret <= 0) {
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_send(req, "Failed to read request body", HTTPD_RESP_USE_STRLEN);
            return false;
        }
        received += ret;
    }
    buf[total_len] = '\0';
    return true;
}

static bool check_auth_and_rate(const char *body, httpd_req_t *req) {
    char token[24] = {0};
    bool has_token = httpd_query_key_value(body, "token", token, sizeof(token)) == ESP_OK;

    if (!has_token || strcmp(token, session_token) != 0) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_send(req, "Unauthorized: missing/invalid token", HTTPD_RESP_USE_STRLEN);
        return false;
    }

    unsigned long now = (unsigned long)(esp_timer_get_time() / 1000ULL);
    if (now - last_config_window_ms > CONFIG_RATE_WINDOW_MS) {
        last_config_window_ms = now;
        config_request_count = 0;
    }
    config_request_count++;
    if (config_request_count > CONFIG_RATE_MAX_REQ) {
        httpd_resp_set_status(req, "429 Too Many Requests");
        httpd_resp_send(req, "Too many requests, slow down", HTTPD_RESP_USE_STRLEN);
        return false;
    }
    return true;
}

// ================= HTTP HANDLERS =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, index_html_tmpl, strlen(index_html_tmpl));
}

static esp_err_t token_get_handler(httpd_req_t *req) {
    char buffer[48];
    snprintf(buffer, sizeof(buffer), "{\"token\":\"%s\"}", session_token);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, strlen(buffer));
}

static esp_err_t status_get_handler(httpd_req_t *req) {
    char buffer[400];
    uint32_t free_heap = esp_get_free_heap_size();

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool nat_e = nat_enabled;
    bool inet = internet_ok;
    int clients = current_clients;
    int rssi = last_rssi;
    xSemaphoreGive(state_mutex);

    bool sta_connected = (xEventGroupGetBits(wifi_event_group) & WIFI_CONNECTED_BIT) != 0;

    snprintf(buffer, sizeof(buffer),
        "{\"ram\":%lu,\"internet\":%s,\"nat\":%s,\"clients\":%d,\"rssi\":%d,"
        "\"staConnected\":%s,\"staSsid\":\"%s\",\"weakPassword\":%s}",
        (unsigned long)free_heap,
        inet ? "true" : "false",
        nat_e ? "true" : "false",
        clients,
        rssi,
        sta_connected ? "true" : "false",
        sta_ssid,
        (strcmp(ap_pass, "12345678") == 0) ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, strlen(buffer));
}

static esp_err_t config_get_handler(httpd_req_t *req) {
    char buffer[200];
    snprintf(buffer, sizeof(buffer),
        "{\"apSsid\":\"%s\",\"staSsid\":\"%s\"}",
        ap_ssid, sta_ssid);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, strlen(buffer));
}

static esp_err_t clients_get_handler(httpd_req_t *req) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK || s_ap_netif == NULL) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_send(req, "[]", HTTPD_RESP_USE_STRLEN);
    }

    int num = sta_list.num;
    if (num > 10) num = 10;

    esp_netif_pair_mac_ip_t pairs[10] = {0};
    for (int i = 0; i < num; i++) {
        memcpy(pairs[i].mac, sta_list.sta[i].mac, 6);
    }
    esp_netif_dhcps_get_clients_by_mac(s_ap_netif, num, pairs);

    char buffer[10 * 48 + 4];
    int off = 0;
    buffer[off++] = '[';
    for (int i = 0; i < num; i++) {
        off += snprintf(buffer + off, sizeof(buffer) - off,
            "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ip\":\"" IPSTR "\"}",
            (i > 0) ? "," : "",
            pairs[i].mac[0], pairs[i].mac[1], pairs[i].mac[2],
            pairs[i].mac[3], pairs[i].mac[4], pairs[i].mac[5],
            IP2STR(&pairs[i].ip));
    }
    buffer[off++] = ']';
    buffer[off] = '\0';

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, off);
}

static esp_err_t save_sta_get_handler(httpd_req_t *req) {
    char query[QUERY_VALUE_LEN * 3];
    if (!read_post_body(req, query, sizeof(query))) return ESP_OK;
    if (!check_auth_and_rate(query, req)) return ESP_OK;

    char ssid[SSID_BUF_LEN] = {0};
    char pass[PASS_BUF_LEN] = {0};
    char value[QUERY_VALUE_LEN];

    if (httpd_query_key_value(query, "ssid", value, sizeof(value)) == ESP_OK) {
        url_decode(ssid, sizeof(ssid), value);
    }
    if (httpd_query_key_value(query, "pass", value, sizeof(value)) == ESP_OK) {
        url_decode(pass, sizeof(pass), value);
    }

    if (strlen(ssid) > 0) {
        xSemaphoreTake(nvs_mutex, portMAX_DELAY);
        nvs_set_str(s_nvs_handle, STA_SSID_CONF, ssid);
        nvs_set_str(s_nvs_handle, STA_PASS_CONF, pass);
        nvs_commit(s_nvs_handle);
        xSemaphoreGive(nvs_mutex);
        ESP_LOGI(TAG, "Saved STA: %s", ssid);
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "STA Saved. Rebooting...", HTTPD_RESP_USE_STRLEN);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t save_ap_get_handler(httpd_req_t *req) {
    char query[QUERY_VALUE_LEN * 3];
    if (!read_post_body(req, query, sizeof(query))) return ESP_OK;
    if (!check_auth_and_rate(query, req)) return ESP_OK;

    char ssid[SSID_BUF_LEN] = {0};
    char pass[PASS_BUF_LEN] = {0};
    char value[QUERY_VALUE_LEN];

    if (httpd_query_key_value(query, "ssid", value, sizeof(value)) == ESP_OK) {
        url_decode(ssid, sizeof(ssid), value);
        if (strlen(ssid) > 0) strncpy(ap_ssid, ssid, sizeof(ap_ssid) - 1);
    }
    if (httpd_query_key_value(query, "pass", value, sizeof(value)) == ESP_OK) {
        url_decode(pass, sizeof(pass), value);
        if (strlen(pass) >= 8) strncpy(ap_pass, pass, sizeof(ap_pass) - 1);
    }

    save_config();

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "AP Saved. Rebooting...", HTTPD_RESP_USE_STRLEN);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t save_nat_get_handler(httpd_req_t *req) {
    char query[QUERY_VALUE_LEN * 2];
    if (!read_post_body(req, query, sizeof(query))) return ESP_OK;
    if (!check_auth_and_rate(query, req)) return ESP_OK;

    char value[16];

    if (httpd_query_key_value(query, "slots", value, sizeof(value)) == ESP_OK) {
        int slots = atoi(value);
        if (slots >= 64 && slots <= 4096) nat_slots = slots;
    }
    if (httpd_query_key_value(query, "tcp", value, sizeof(value)) == ESP_OK) {
        int tcp = atoi(value);
        if (tcp >= 32 && tcp <= 2048) nat_tcp = tcp;
    }
    if (nat_slots < nat_tcp) nat_slots = nat_tcp;

    save_config();

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "NAT Saved. Rebooting...", HTTPD_RESP_USE_STRLEN);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

// ================= URI DEFINITIONS =================
static const httpd_uri_t root_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
};

static const httpd_uri_t token_uri = {
    .uri = "/get-token",
    .method = HTTP_GET,
    .handler = token_get_handler,
};

static const httpd_uri_t status_uri = {
    .uri = "/api/status",
    .method = HTTP_GET,
    .handler = status_get_handler,
};

static const httpd_uri_t config_uri = {
    .uri = "/api/config",
    .method = HTTP_GET,
    .handler = config_get_handler,
};

static const httpd_uri_t clients_uri = {
    .uri = "/api/clients",
    .method = HTTP_GET,
    .handler = clients_get_handler,
};

static const httpd_uri_t save_sta_uri = {
    .uri = "/save-sta",
    .method = HTTP_POST,
    .handler = save_sta_get_handler,
};

static const httpd_uri_t save_ap_uri = {
    .uri = "/save-ap",
    .method = HTTP_POST,
    .handler = save_ap_get_handler,
};

static const httpd_uri_t save_nat_uri = {
    .uri = "/save-nat",
    .method = HTTP_POST,
    .handler = save_nat_get_handler,
};

// Captive portal URIs
static const httpd_uri_t captive_204_uri = {
    .uri = "/generate_204",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_connectivity_uri = {
    .uri = "/connectivity-check",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_success_uri = {
    .uri = "/success",
    .method = HTTP_GET,
    .handler = captive_success_handler,
};

static const httpd_uri_t captive_apple_uri = {
    .uri = "/captive",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_hotspot_uri = {
    .uri = "/hotspot-detect.html",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_library_uri = {
    .uri = "/library/test/success.html",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_ncsi_uri = {
    .uri = "/ncsi.txt",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_canonical_uri = {
    .uri = "/canonical.html",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static const httpd_uri_t captive_apple_site_uri = {
    .uri = "/apple-sd",
    .method = HTTP_GET,
    .handler = captive_204_handler,
};

static void start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 20;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
        httpd_register_uri_handler(server, &token_uri);
        httpd_register_uri_handler(server, &status_uri);
        httpd_register_uri_handler(server, &config_uri);
        httpd_register_uri_handler(server, &clients_uri);
        httpd_register_uri_handler(server, &save_sta_uri);
        httpd_register_uri_handler(server, &save_ap_uri);
        httpd_register_uri_handler(server, &save_nat_uri);

        httpd_register_uri_handler(server, &captive_204_uri);
        httpd_register_uri_handler(server, &captive_connectivity_uri);
        httpd_register_uri_handler(server, &captive_success_uri);
        httpd_register_uri_handler(server, &captive_apple_uri);
        httpd_register_uri_handler(server, &captive_hotspot_uri);
        httpd_register_uri_handler(server, &captive_library_uri);
        httpd_register_uri_handler(server, &captive_ncsi_uri);
        httpd_register_uri_handler(server, &captive_canonical_uri);
        httpd_register_uri_handler(server, &captive_apple_site_uri);

        ESP_LOGI(TAG, "Web server started with captive portal support");
    }
}

// ================= INTERNET CHECK TASK =================
static void internet_check_task(void *pv) {
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_task_wdt_reset();

        EventBits_t bits = xEventGroupGetBits(wifi_event_group);
        bool sta_connected = (bits & WIFI_CONNECTED_BIT) != 0;

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        bool nat_e = nat_enabled;
        xSemaphoreGive(state_mutex);

        bool ok = sta_connected && nat_e;

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        internet_ok = ok;
        xSemaphoreGive(state_mutex);

        if (ok) {
            ESP_LOGI(TAG, "✅ Internet: ONLINE (STA connected + NAT enabled)");
        } else {
            ESP_LOGI(TAG, "❌ Internet: OFFLINE (STA=%d, NAT=%d)", sta_connected, nat_e);
        }

        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

// ================= MAIN =================
void app_main(void) {
    ESP_LOGI(TAG, "==========================================");
    ESP_LOGI(TAG, "APEX ULTRA V22.0.2 - ESP-IDF NAT ROUTER (FIXED)");
    ESP_LOGI(TAG, "==========================================\n");

    state_mutex = xSemaphoreCreateMutex();
    nvs_mutex = xSemaphoreCreateMutex();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    nvs_open("apex_v22", NVS_READWRITE, &s_nvs_handle);
    load_config();

    ESP_LOGI(TAG, "NAT: slots=%d, tcp=%d", (int)nat_slots, (int)nat_tcp);

    uint32_t r1 = esp_random(), r2 = esp_random();
    snprintf(session_token, sizeof(session_token), "%08lx%08lx", (unsigned long)r1, (unsigned long)r2);
    ESP_LOGI(TAG, "Session token: %s", session_token);
    if (strcmp(ap_pass, "12345678") == 0) {
        ESP_LOGW(TAG, "CANH BAO: dang dung mat khau AP mac dinh, hay doi ngay!");
    }

    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&wdt_config);
    esp_task_wdt_add(NULL);

    wifi_init();

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to STA");
    } else {
        ESP_LOGI(TAG, "No STA configured or connection failed (will keep retrying in background)");
    }

    start_webserver();

    xTaskCreate(internet_check_task, "inet_check", 3072, NULL, 2, NULL);
    xTaskCreate(sta_reconnect_task, "sta_reconnect", 3072, NULL, 2, NULL);
    xTaskCreate(dns_captive_task, "dns_captive", 4096, NULL, 5, NULL);

    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << 2),
        .mode = GPIO_MODE_OUTPUT,
        .intr_type = GPIO_INTR_DISABLE,
        .pull_down_en = 0,
        .pull_up_en = 0,
    };
    gpio_config(&io_conf);

    for (int i = 0; i < 3; i++) {
        gpio_set_level(2, 0);
        vTaskDelay(pdMS_TO_TICKS(80));
        gpio_set_level(2, 1);
        vTaskDelay(pdMS_TO_TICKS(80));
    }

    ESP_LOGI(TAG, "APEX ULTRA Ready! AP: %s", ap_ssid);
    ESP_LOGI(TAG, "Connect to http://192.168.4.1");
    ESP_LOGI(TAG, "✅ Captive Portal: DNS + HTTP handlers enabled");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_task_wdt_reset();

        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            xSemaphoreTake(state_mutex, portMAX_DELAY);
            last_rssi = ap_info.rssi;
            xSemaphoreGive(state_mutex);
        }
    }
}
