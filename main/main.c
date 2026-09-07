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
#include "nvs_flash.h"
#include "esp_task_wdt.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/etharp.h"
#include "lwip/dns.h"

#include "esp_http_server.h"
#include "cJSON.h"

// ================= NAT DECLARATIONS =================
// FIX #(napt): ưu tiên header chính thức nếu SDK có sẵn, tránh sai chữ ký hàm
#if __has_include("lwip/napt.h")
  #include "lwip/napt.h"
#else
extern void ip_napt_init(uint16_t max_slots, uint16_t max_tcp_ports);
extern err_t ip_napt_enable(ip4_addr_t addr, int dir);
extern void ip_napt_disable(void);
#endif

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
// FIX #4: sau khi hết lượt retry ban đầu, vẫn thử kết nối lại định kỳ thay vì
// bỏ cuộc vĩnh viễn.
#define STA_RECONNECT_BACKOFF_MS 30000

#define WATCHDOG_TIMEOUT_S 45

// FIX #3: cấu hình rate-limit cho control plane
#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3

// Kích thước buffer thống nhất cho mọi chuỗi liên quan tới WiFi, khớp với
// giới hạn thật của wifi_config_t (ssid tối đa 32 byte gồm null, password
// tối đa 64 byte gồm null). Dùng chung 1 hằng số để không còn lệch size
// giữa các buffer như bản gốc.
#define SSID_BUF_LEN 33
#define PASS_BUF_LEN 65
#define QUERY_VALUE_LEN 96

// ================= GLOBALS =================
static const char *TAG = "APEX_ROUTER";

static EventGroupHandle_t wifi_event_group;
static int s_retry_num = 0;
static bool sta_configured = false;

static httpd_handle_t server = NULL;

// FIX #6: bảo vệ các biến trạng thái dùng chung giữa nhiều task bằng 1 mutex
// nhẹ thay vì đọc/ghi trực tiếp không đồng bộ.
static SemaphoreHandle_t state_mutex;
static bool nat_enabled = false;
static bool internet_ok = false;
static int current_clients = 0;
static int last_rssi = -100;

static char sta_ssid[SSID_BUF_LEN] = {0};
static char sta_pass[PASS_BUF_LEN] = {0};
static char ap_ssid[SSID_BUF_LEN] = "APEX_ULTRA";
static char ap_pass[PASS_BUF_LEN] = "12345678";
static int ap_channel = AP_CHANNEL;
static int max_clients = AP_MAX_CONN;

static int nat_slots = NAT_MAX_SLOTS;
static int nat_tcp = NAT_MAX_TCP;

static nvs_handle_t nvs_handle;

// FIX #3: mutex bảo vệ ghi NVS + token phiên chống truy cập trái phép
static SemaphoreHandle_t nvs_mutex;
static char session_token[24] = {0};
static unsigned long last_config_window_ms = 0;
static int config_request_count = 0;

// HTML trang chủ
static const char *index_html_tmpl =
"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>APEX ULTRA</title>"
"<style>"
"*{box-sizing:border-box;}body{font-family:Arial;background:#020617;color:#f8fafc;padding:15px;}"
".card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;}"
"input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}"
"button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}"
".warning{color:#f59e0b;}"
"</style>"
"</head><body>"
"<div class='card'><h3>APEX ULTRA V22.0.2 - ESP-IDF (Fixed)</h3>"
"<div>RAM: <b id='ram'>0</b> KB</div>"
"<div>Internet: <span id='net'>WAIT</span></div>"
"<div>NAT: <span id='nat'>WAIT</span></div>"
"<div>Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>7</b></div>"
"<div id='weakWarn' class='warning' style='display:none;'>⚠️ Đang dùng mật khẩu AP mặc định — hãy đổi ngay!</div>"
"</div>"
"<div class='card'><h3>Uplink Configuration</h3>"
"<form action='/save-sta' method='get' class='authForm'>"
"<input name='ssid' id='ssidInp' placeholder='WiFi Name' required maxlength='32'>"
"<input name='pass' type='password' placeholder='Password' maxlength='63'>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Connect</button>"
"</form></div>"
"<div class='card'><h3>AP Configuration</h3>"
"<form action='/save-ap' method='get' class='authForm'>"
"<input name='ssid' placeholder='AP SSID' value='APEX_ULTRA' maxlength='32'>"
"<input name='pass' type='password' placeholder='Password (min 8)' maxlength='63'>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Save & Reboot</button>"
"</form></div>"
"<div class='card'><h3>NAT Settings</h3>"
"<form action='/save-nat' method='get' class='authForm'>"
"<input name='slots' placeholder='NAPT Slots' value='512'>"
"<input name='tcp' placeholder='TCP ports' value='256'>"
"<input type='hidden' name='token' class='tokenField' value=''>"
"<button type='submit'>Save & Reboot</button>"
"</form></div>"
"<script>"
"function fetchData(){fetch('/api/status').then(r=>r.json()).then(d=>{"
"document.getElementById('ram').innerText=Math.round(d.ram/1024);"
"document.getElementById('net').innerText=d.internet?'ONLINE':'OFFLINE';"
"document.getElementById('nat').innerText=d.nat?'ACTIVE':'OFF';"
"document.getElementById('clientCount').innerText=d.clients;"
"document.getElementById('weakWarn').style.display=d.weakPassword?'block':'none';"
"});}"
"setInterval(fetchData,2000);fetchData();"
"fetch('/get-token').then(r=>r.json()).then(t=>{"
"document.querySelectorAll('.tokenField').forEach(el=>el.value=t.token);"
"});"
"</script></body></html>";

// ================= UTILITY FUNCTIONS =================
// FIX #1 (CRITICAL): url_decode giờ nhận thêm dst_size và KHÔNG BAO GIỜ ghi
// vượt quá biên của buffer đích, kể cả khi chuỗi nguồn dài hơn. Đây là fix
// cho lỗi stack buffer overflow qua /save-ap (và mọi endpoint khác dùng
// hàm này).
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
    nvs_set_str(nvs_handle, "ap_ssid", ap_ssid);
    nvs_set_str(nvs_handle, "ap_pass", ap_pass);
    nvs_set_i32(nvs_handle, "ap_channel", ap_channel);
    nvs_set_i32(nvs_handle, "max_clients", max_clients);
    nvs_set_i32(nvs_handle, "nat_slots", nat_slots);
    nvs_set_i32(nvs_handle, "nat_tcp", nat_tcp);
    nvs_commit(nvs_handle);
    xSemaphoreGive(nvs_mutex);
}

static void load_config(void) {
    size_t len;

    len = sizeof(ap_ssid);
    if (nvs_get_str(nvs_handle, "ap_ssid", ap_ssid, &len) != ESP_OK) {
        strncpy(ap_ssid, AP_SSID, sizeof(ap_ssid) - 1);
    }

    len = sizeof(ap_pass);
    if (nvs_get_str(nvs_handle, "ap_pass", ap_pass, &len) != ESP_OK) {
        strncpy(ap_pass, AP_PASS, sizeof(ap_pass) - 1);
    }

    nvs_get_i32(nvs_handle, "ap_channel", &ap_channel);
    if (ap_channel < 1 || ap_channel > 13) ap_channel = AP_CHANNEL;

    nvs_get_i32(nvs_handle, "max_clients", &max_clients);
    if (max_clients < 1 || max_clients > 10) max_clients = AP_MAX_CONN;

    nvs_get_i32(nvs_handle, "nat_slots", &nat_slots);
    if (nat_slots < 64 || nat_slots > 4096) nat_slots = NAT_MAX_SLOTS;

    nvs_get_i32(nvs_handle, "nat_tcp", &nat_tcp);
    if (nat_tcp < 32 || nat_tcp > 2048) nat_tcp = NAT_MAX_TCP;
    if (nat_slots < nat_tcp) nat_slots = nat_tcp;

    len = sizeof(sta_ssid);
    nvs_get_str(nvs_handle, STA_SSID_CONF, sta_ssid, &len);

    len = sizeof(sta_pass);
    nvs_get_str(nvs_handle, STA_PASS_CONF, sta_pass, &len);

    sta_configured = (strlen(sta_ssid) > 0);
}

// ================= NAT FUNCTIONS =================
static void enable_nat(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool already = nat_enabled;
    xSemaphoreGive(state_mutex);
    if (already) return;

    sys_lock_tcpip_core();
    ip_napt_init(nat_slots, nat_tcp);
    ip_napt_enable(ip_2_ip4(&netif_default->ip_addr), 1);
    sys_unlock_tcpip_core();

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    nat_enabled = true;
    xSemaphoreGive(state_mutex);
    ESP_LOGI(TAG, "NAT enabled (slots=%d, tcp=%d)", nat_slots, nat_tcp);
}

static void disable_nat(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool was_enabled = nat_enabled;
    xSemaphoreGive(state_mutex);
    if (!was_enabled) return;

    sys_lock_tcpip_core();
    ip_napt_disable();
    sys_unlock_tcpip_core();

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
            // FIX #4: không còn bỏ cuộc vĩnh viễn. Báo FAIL cho lần chờ đầu
            // tiên ở app_main(), nhưng vẫn để 1 task nền định kỳ thử kết nối
            // lại (xem sta_reconnect_task) thay vì im lặng mất uplink mãi mãi.
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGW(TAG, "STA retry exhausted, will retry again in background every %d s",
                     STA_RECONNECT_BACKOFF_MS / 1000);
        }
        ESP_LOGI(TAG, "STA disconnected");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        current_clients++;
        int c = current_clients;
        xSemaphoreGive(state_mutex);
        ESP_LOGI(TAG, "Client connected: %d/%d", c, max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        if (current_clients > 0) current_clients--;
        int c = current_clients;
        xSemaphoreGive(state_mutex);
        ESP_LOGI(TAG, "Client disconnected: %d/%d", c, max_clients);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupClearBits(wifi_event_group, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        enable_nat();
    }
}

// FIX #4: task nền định kỳ thử kết nối lại STA nếu đang cấu hình STA mà
// hiện không có IP (thay vì bỏ cuộc vĩnh viễn sau STA_MAX_RETRY lần).
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
    esp_netif_create_default_wifi_ap();
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

    // AP config
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
    // FIX #1: dùng strncpy + đảm bảo null-terminate, không strcpy "mù" nữa.
    strncpy((char *)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid) - 1);
    strncpy((char *)ap_config.ap.password, ap_pass, sizeof(ap_config.ap.password) - 1);
    if (strlen(ap_pass) == 0) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    // STA config if available
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
    ESP_LOGI(TAG, "WiFi started. AP: %s on channel %d", ap_ssid, ap_channel);
}

// ================= AUTH / RATE LIMIT (FIX #3) =================
static bool check_auth_and_rate(httpd_req_t *req, char *query, size_t query_len) {
    char token[24] = {0};
    bool has_token = (httpd_req_get_url_query_str(req, query, query_len) == ESP_OK) &&
                      (httpd_query_key_value(query, "token", token, sizeof(token)) == ESP_OK);

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
    char buffer[300];
    uint32_t free_heap = esp_get_free_heap_size();

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool nat_e = nat_enabled;
    bool inet = internet_ok;
    int clients = current_clients;
    int rssi = last_rssi;
    xSemaphoreGive(state_mutex);

    snprintf(buffer, sizeof(buffer),
        "{\"ram\":%lu,\"internet\":%s,\"nat\":%s,\"clients\":%d,\"rssi\":%d,\"weakPassword\":%s}",
        (unsigned long)free_heap,
        inet ? "true" : "false",
        nat_e ? "true" : "false",
        clients,
        rssi,
        (strcmp(ap_pass, "12345678") == 0) ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, strlen(buffer));
}

static esp_err_t save_sta_get_handler(httpd_req_t *req) {
    char query[QUERY_VALUE_LEN * 3];
    if (!check_auth_and_rate(req, query, sizeof(query))) return ESP_OK;

    char ssid[SSID_BUF_LEN] = {0};
    char pass[PASS_BUF_LEN] = {0};
    char value[QUERY_VALUE_LEN];

    // FIX #1: mọi url_decode() giờ đều truyền kích thước buffer đích thật
    if (httpd_query_key_value(query, "ssid", value, sizeof(value)) == ESP_OK) {
        url_decode(ssid, sizeof(ssid), value);
    }
    if (httpd_query_key_value(query, "pass", value, sizeof(value)) == ESP_OK) {
        url_decode(pass, sizeof(pass), value);
    }

    if (strlen(ssid) > 0) {
        xSemaphoreTake(nvs_mutex, portMAX_DELAY);
        nvs_set_str(nvs_handle, STA_SSID_CONF, ssid);
        nvs_set_str(nvs_handle, STA_PASS_CONF, pass);
        nvs_commit(nvs_handle);
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
    if (!check_auth_and_rate(req, query, sizeof(query))) return ESP_OK;

    char ssid[SSID_BUF_LEN] = {0};
    char pass[PASS_BUF_LEN] = {0};
    char value[QUERY_VALUE_LEN];

    // FIX #1 (CRITICAL): trước đây gọi url_decode(ssid, value) với
    // ssid[32] và value[64] không kiểm tra biên -> stack buffer overflow.
    // Giờ luôn truyền sizeof(ssid)/sizeof(pass) làm giới hạn ghi.
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
    if (!check_auth_and_rate(req, query, sizeof(query))) return ESP_OK;

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

static const httpd_uri_t save_sta_uri = {
    .uri = "/save-sta",
    .method = HTTP_GET,
    .handler = save_sta_get_handler,
};

static const httpd_uri_t save_ap_uri = {
    .uri = "/save-ap",
    .method = HTTP_GET,
    .handler = save_ap_get_handler,
};

static const httpd_uri_t save_nat_uri = {
    .uri = "/save-nat",
    .method = HTTP_GET,
    .handler = save_nat_get_handler,
};

static void start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 8;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
        httpd_register_uri_handler(server, &token_uri);
        httpd_register_uri_handler(server, &status_uri);
        httpd_register_uri_handler(server, &save_sta_uri);
        httpd_register_uri_handler(server, &save_ap_uri);
        httpd_register_uri_handler(server, &save_nat_uri);
        ESP_LOGI(TAG, "Web server started");
    }
}

// ================= INTERNET CHECK TASK =================
static void internet_check_task(void *pv) {
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_task_wdt_reset();

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        bool nat_e = nat_enabled;
        xSemaphoreGive(state_mutex);

        bool ok;
        if (nat_e) {
            struct netif *netif = netif_default;
            if (netif && netif_is_up(netif)) {
                ip_addr_t dns_ip;
                dns_getserver(0, &dns_ip);
                ok = !ip_addr_isany(&dns_ip);
            } else {
                ok = false;
            }
        } else {
            ok = false;
        }

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        internet_ok = ok;
        xSemaphoreGive(state_mutex);

        vTaskDelay(pdMS_TO_TICKS(20000));
    }
}

// ================= MAIN =================
void app_main(void) {
    ESP_LOGI(TAG, "==========================================");
    ESP_LOGI(TAG, "APEX ULTRA V22.0.2 - ESP-IDF NAT ROUTER (FIXED)");
    ESP_LOGI(TAG, "==========================================\n");

    state_mutex = xSemaphoreCreateMutex();
    nvs_mutex = xSemaphoreCreateMutex();

    // Init NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Open NVS
    nvs_open("apex_v22", NVS_READWRITE, &nvs_handle);
    load_config();

    ESP_LOGI(TAG, "NAT: slots=%d, tcp=%d", nat_slots, nat_tcp);

    // FIX #3: sinh token phiên bằng hardware RNG cho control-plane
    uint32_t r1 = esp_random(), r2 = esp_random();
    snprintf(session_token, sizeof(session_token), "%08lx%08lx", (unsigned long)r1, (unsigned long)r2);
    ESP_LOGI(TAG, "Session token: %s", session_token);
    if (strcmp(ap_pass, "12345678") == 0) {
        ESP_LOGW(TAG, "CANH BAO: dang dung mat khau AP mac dinh, hay doi ngay!");
    }

    // FIX #5: bật Task Watchdog cho toàn hệ thống
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&wdt_config);
    esp_task_wdt_add(NULL); // đăng ký task app_main (chính là task chạy while(1) bên dưới)

    // Init WiFi
    wifi_init();

    // Wait for connection or timeout
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

    // Start web server
    start_webserver();

    // Start internet check task
    xTaskCreate(internet_check_task, "inet_check", 3072, NULL, 2, NULL);

    // FIX #4: task nền tự thử kết nối lại STA định kỳ, không còn bỏ cuộc mãi mãi
    xTaskCreate(sta_reconnect_task, "sta_reconnect", 3072, NULL, 2, NULL);

    // Blink LED (GPIO2)
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

    // Main loop - just keep running
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_task_wdt_reset(); // FIX #5: feed watchdog của chính task này

        // Update RSSI
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            xSemaphoreTake(state_mutex, portMAX_DELAY);
            last_rssi = ap_info.rssi;
            xSemaphoreGive(state_mutex);
        }
    }
}