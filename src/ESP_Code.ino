// ============================================================================
// APEX ULTRA V22.0.1 - ESP-IDF NAT ROUTER
// Build 100% với ESP-IDF, không phụ thuộc Arduino
// ============================================================================

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_chip_info.h"
#include "nvs_flash.h"
#include "esp_task_wdt.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/etharp.h"
#include "lwip/dns.h"

#include "esp_http_server.h"
#include "cJSON.h"

// ================= NAT DECLARATIONS =================
extern void ip_napt_init(uint16_t max_slots, uint16_t max_tcp_ports);
extern err_t ip_napt_enable(ip4_addr_t addr, int dir);
extern void ip_napt_disable(void);

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

#define HTTP_GET 0
#define HTTP_POST 1

// ================= GLOBALS =================
static const char *TAG = "APEX_ROUTER";

static EventGroupHandle_t wifi_event_group;
static int s_retry_num = 0;

static httpd_handle_t server = NULL;
static bool nat_enabled = false;
static bool internet_ok = false;
static int current_clients = 0;
static int last_rssi = -100;

static char sta_ssid[64] = {0};
static char sta_pass[64] = {0};
static char ap_ssid[32] = "APEX_ULTRA";
static char ap_pass[64] = "12345678";
static int ap_channel = AP_CHANNEL;
static int max_clients = AP_MAX_CONN;

static int nat_slots = NAT_MAX_SLOTS;
static int nat_tcp = NAT_MAX_TCP;

static nvs_handle_t nvs_handle;

// HTML trang chủ
static const char *index_html = 
"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>APEX ULTRA</title>"
"<style>"
"*{box-sizing:border-box;}body{font-family:Arial;background:#020617;color:#f8fafc;padding:15px;}"
".card{background:#1e293b;padding:20px;margin-bottom:15px;border-radius:12px;}"
"input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#0f172a;color:white;border:1px solid #334155;}"
"button{width:100%;padding:14px;background:#38bdf8;color:#020617;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}"
"</style>"
"</head><body>"
"<div class='card'><h3>APEX ULTRA V22.0.1 - ESP-IDF</h3>"
"<div>RAM: <b id='ram'>0</b> KB</div>"
"<div>Internet: <span id='net'>WAIT</span></div>"
"<div>NAT: <span id='nat'>WAIT</span></div>"
"<div>Clients: <b id='clientCount'>0</b> / <b id='clientLimit'>7</b></div>"
"</div>"
"<div class='card'><h3>Uplink Configuration</h3>"
"<form action='/save-sta' method='get'>"
"<input name='ssid' id='ssidInp' placeholder='WiFi Name' required>"
"<input name='pass' type='password' placeholder='Password'>"
"<button type='submit'>Connect</button>"
"</form></div>"
"<div class='card'><h3>AP Configuration</h3>"
"<form action='/save-ap' method='get'>"
"<input name='ssid' placeholder='AP SSID' value='APEX_ULTRA'>"
"<input name='pass' type='password' placeholder='Password (min 8)'>"
"<button type='submit'>Save & Reboot</button>"
"</form></div>"
"<div class='card'><h3>NAT Settings</h3>"
"<form action='/save-nat' method='get'>"
"<input name='slots' placeholder='NAPT Slots' value='512'>"
"<input name='tcp' placeholder='TCP ports' value='256'>"
"<button type='submit'>Save & Reboot</button>"
"</form></div>"
"<script>"
"function fetchData(){fetch('/api/status').then(r=>r.json()).then(d=>{"
"document.getElementById('ram').innerText=Math.round(d.ram/1024);"
"document.getElementById('net').innerText=d.internet?'ONLINE':'OFFLINE';"
"document.getElementById('nat').innerText=d.nat?'ACTIVE':'OFF';"
"document.getElementById('clientCount').innerText=d.clients;"
"});}"
"setInterval(fetchData,2000);fetchData();"
"</script></body></html>";

// ================= UTILITY FUNCTIONS =================
static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = (char)((a << 4) | b);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

static void save_config() {
    nvs_set_str(nvs_handle, "ap_ssid", ap_ssid);
    nvs_set_str(nvs_handle, "ap_pass", ap_pass);
    nvs_set_i32(nvs_handle, "ap_channel", ap_channel);
    nvs_set_i32(nvs_handle, "max_clients", max_clients);
    nvs_set_i32(nvs_handle, "nat_slots", nat_slots);
    nvs_set_i32(nvs_handle, "nat_tcp", nat_tcp);
    nvs_commit(nvs_handle);
}

static void load_config() {
    size_t len;
    
    len = sizeof(ap_ssid);
    if (nvs_get_str(nvs_handle, "ap_ssid", ap_ssid, &len) != ESP_OK) {
        strcpy(ap_ssid, AP_SSID);
    }
    
    len = sizeof(ap_pass);
    if (nvs_get_str(nvs_handle, "ap_pass", ap_pass, &len) != ESP_OK) {
        strcpy(ap_pass, AP_PASS);
    }
    
    nvs_get_i32(nvs_handle, "ap_channel", &ap_channel);
    if (ap_channel < 1 || ap_channel > 13) ap_channel = AP_CHANNEL;
    
    nvs_get_i32(nvs_handle, "max_clients", &max_clients);
    if (max_clients < 1 || max_clients > 10) max_clients = AP_MAX_CONN;
    
    nvs_get_i32(nvs_handle, "nat_slots", &nat_slots);
    if (nat_slots < 64 || nat_slots > 4096) nat_slots = NAT_MAX_SLOTS;
    
    nvs_get_i32(nvs_handle, "nat_tcp", &nat_tcp);
    if (nat_tcp < 32 || nat_tcp > 2048) nat_tcp = NAT_MAX_TCP;
    
    len = sizeof(sta_ssid);
    nvs_get_str(nvs_handle, STA_SSID_CONF, sta_ssid, &len);
    
    len = sizeof(sta_pass);
    nvs_get_str(nvs_handle, STA_PASS_CONF, sta_pass, &len);
}

// ================= NAT FUNCTIONS =================
static void enable_nat() {
    if (!nat_enabled) {
        sys_lock_tcpip_core();
        ip_napt_init(nat_slots, nat_tcp);
        ip_napt_enable(ip_2_ip4(&netif_default->ip_addr), 1);
        sys_unlock_tcpip_core();
        nat_enabled = true;
        ESP_LOGI(TAG, "NAT enabled (slots=%d, tcp=%d)", nat_slots, nat_tcp);
    }
}

static void disable_nat() {
    if (nat_enabled) {
        sys_lock_tcpip_core();
        ip_napt_disable();
        sys_unlock_tcpip_core();
        nat_enabled = false;
        ESP_LOGI(TAG, "NAT disabled");
    }
}

// ================= WIFI EVENT HANDLER =================
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 5) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry connecting... (%d/5)", s_retry_num);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "STA disconnected");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        current_clients++;
        ESP_LOGI(TAG, "Client connected: %d/%d", current_clients, max_clients);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        if (current_clients > 0) current_clients--;
        ESP_LOGI(TAG, "Client disconnected: %d/%d", current_clients, max_clients);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        enable_nat();
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
    strcpy((char *)ap_config.ap.ssid, ap_ssid);
    strcpy((char *)ap_config.ap.password, ap_pass);
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
        strcpy((char *)sta_config.sta.ssid, sta_ssid);
        strcpy((char *)sta_config.sta.password, sta_pass);
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    }
    
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi started. AP: %s on channel %d", ap_ssid, ap_channel);
}

// ================= HTTP HANDLERS =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, index_html, strlen(index_html));
}

static esp_err_t status_get_handler(httpd_req_t *req) {
    char buffer[256];
    uint32_t free_heap = esp_get_free_heap_size();
    
    snprintf(buffer, sizeof(buffer),
        "{\"ram\":%lu,\"internet\":%s,\"nat\":%s,\"clients\":%d,\"rssi\":%d}",
        free_heap,
        internet_ok ? "true" : "false",
        nat_enabled ? "true" : "false",
        current_clients,
        last_rssi);
    
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, strlen(buffer));
}

static esp_err_t save_sta_get_handler(httpd_req_t *req) {
    char ssid[64] = {0};
    char pass[64] = {0};
    
    char query[256];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char param[32];
        char value[64];
        
        if (httpd_query_key_value(query, "ssid", value, sizeof(value)) == ESP_OK) {
            url_decode(ssid, value);
        }
        if (httpd_query_key_value(query, "pass", value, sizeof(value)) == ESP_OK) {
            url_decode(pass, value);
        }
    }
    
    if (strlen(ssid) > 0) {
        nvs_set_str(nvs_handle, STA_SSID_CONF, ssid);
        nvs_set_str(nvs_handle, STA_PASS_CONF, pass);
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Saved STA: %s", ssid);
    }
    
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "STA Saved. Rebooting...", 22);
    
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t save_ap_get_handler(httpd_req_t *req) {
    char ssid[32] = {0};
    char pass[64] = {0};
    
    char query[256];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char value[64];
        
        if (httpd_query_key_value(query, "ssid", value, sizeof(value)) == ESP_OK) {
            url_decode(ssid, value);
            if (strlen(ssid) > 0) strcpy(ap_ssid, ssid);
        }
        if (httpd_query_key_value(query, "pass", value, sizeof(value)) == ESP_OK) {
            url_decode(pass, value);
            if (strlen(pass) >= 8) strcpy(ap_pass, pass);
        }
    }
    
    save_config();
    
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "AP Saved. Rebooting...", 22);
    
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t save_nat_get_handler(httpd_req_t *req) {
    char query[256];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char value[16];
        
        if (httpd_query_key_value(query, "slots", value, sizeof(value)) == ESP_OK) {
            int slots = atoi(value);
            if (slots >= 64 && slots <= 4096) nat_slots = slots;
        }
        if (httpd_query_key_value(query, "tcp", value, sizeof(value)) == ESP_OK) {
            int tcp = atoi(value);
            if (tcp >= 32 && tcp <= 2048) nat_tcp = tcp;
        }
    }
    
    save_config();
    
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "NAT Saved. Rebooting...", 22);
    
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static const httpd_uri_t root_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
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
    
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
        httpd_register_uri_handler(server, &status_uri);
        httpd_register_uri_handler(server, &save_sta_uri);
        httpd_register_uri_handler(server, &save_ap_uri);
        httpd_register_uri_handler(server, &save_nat_uri);
        ESP_LOGI(TAG, "Web server started");
    }
}

// ================= INTERNET CHECK TASK =================
static void internet_check_task(void *pv) {
    while (1) {
        if (nat_enabled) {
            struct netif *netif = netif_default;
            if (netif && netif_is_up(netif)) {
                ip_addr_t dns_ip;
                dns_getserver(0, &dns_ip);
                internet_ok = !ip_addr_isany(&dns_ip);
            } else {
                internet_ok = false;
            }
        } else {
            internet_ok = false;
        }
        vTaskDelay(pdMS_TO_TICKS(20000));
    }
}

// ================= MAIN =================
void app_main(void) {
    ESP_LOGI(TAG, "==========================================");
    ESP_LOGI(TAG, "APEX ULTRA V22.0.1 - ESP-IDF NAT ROUTER");
    ESP_LOGI(TAG, "==========================================\n");
    
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
    
    // Init WiFi
    wifi_init();
    
    // Wait for connection or timeout
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           portMAX_DELAY);
    
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to STA (if configured)");
    } else {
        ESP_LOGI(TAG, "No STA configured or connection failed");
    }
    
    // Start web server
    start_webserver();
    
    // Start internet check task
    xTaskCreate(internet_check_task, "inet_check", 2048, NULL, 2, NULL);
    
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
        
        // Update RSSI
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            last_rssi = ap_info.rssi;
        }
    }
}
