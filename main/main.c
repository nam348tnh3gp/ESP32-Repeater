/*
 * APEX ULTRA - ESP-IDF NAT router (ESP32 / AP+STA + NAPT + captive portal)
 *
 * Logic dùng chung với bản Arduino nằm ở các header cạnh thư mục này:
 *   apex_common.h  (kiểm tra dữ liệu, so sánh hằng thời gian, JSON escape, parse form, hysteresis RAM)
 *   apex_dns.h     (DNS captive portal + forwarder không chặn)
 *   apex_ui.h      (giao diện web có đăng nhập)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_http_client.h"
#include "esp_http_server.h"
#include "esp_random.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "lwip/sockets.h"

#include "apex_common.h"
#include "apex_dns.h"
#include "apex_ui.h"

// ================= DEFINES =================
#define AP_CHANNEL_DEFAULT   1
#define AP_MAX_CONN_DEFAULT  7
#define AP_MAX_CONN_LIMIT    10

#define NVS_NAMESPACE   "apex_v22"
#define NVS_STA_SSID    "sta_ssid"
#define NVS_STA_PASS    "sta_pass"
#define NVS_AP_SSID     "ap_ssid"
#define NVS_AP_PASS     "ap_pass"
#define NVS_AP_CHANNEL  "ap_channel"
#define NVS_MAX_CLIENTS "max_clients"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

#define STA_MAX_RETRY            5
#define STA_RECONNECT_BACKOFF_MS 30000

#define WATCHDOG_TIMEOUT_S 45

/* Giới hạn tần suất lệnh ghi cấu hình (đã xác thực) và chống dò mật khẩu ở /login */
#define CONFIG_RATE_WINDOW_MS 5000
#define CONFIG_RATE_MAX_REQ   3
#define LOGIN_MAX_FAILS       5
#define LOGIN_LOCKOUT_MS      60000

#define SSID_BUF_LEN   (APEX_SSID_MAX + 1)
#define PASS_BUF_LEN   (APEX_PASS_MAX + 1)
/* Giá trị form đã mã hoá %XX có thể dài gấp 3 lần bản giải mã */
#define BODY_BUF_LEN   640
#define TOKEN_LEN      32

// ================= GLOBALS =================
static const char *TAG = "APEX";

static EventGroupHandle_t wifi_event_group;
static int  s_retry_num = 0;          // bảo vệ bởi sta_state_mutex
static bool sta_configured = false;
static bool sta_disconnected = true;  // bảo vệ bởi sta_state_mutex

static httpd_handle_t server = NULL;

static SemaphoreHandle_t state_mutex;      // nat_enabled, internet_ok, mem_pressure, last_rssi
static SemaphoreHandle_t nvs_mutex;
static SemaphoreHandle_t rate_limit_mutex; // bộ đếm rate-limit + khoá đăng nhập
static SemaphoreHandle_t sta_state_mutex;
static SemaphoreHandle_t internet_check_trigger;

static bool nat_enabled = false;
static bool internet_ok = false;
static bool mem_pressure = false;
static int  last_rssi = -100;

static esp_netif_t *s_ap_netif = NULL;
static esp_netif_t *s_sta_netif = NULL;

static char sta_ssid[SSID_BUF_LEN] = {0};
static char sta_pass[PASS_BUF_LEN] = {0};
static char ap_ssid[SSID_BUF_LEN]  = APEX_DEFAULT_AP_SSID;
static char ap_pass[PASS_BUF_LEN]  = APEX_DEFAULT_AP_PASS;
static int32_t ap_channel  = AP_CHANNEL_DEFAULT;
static int32_t max_clients = AP_MAX_CONN_DEFAULT;

static nvs_handle_t s_nvs_handle;

static char session_token[TOKEN_LEN + 1] = {0};
static uint32_t last_config_window_ms = 0;
static int config_request_count = 0;
static int login_fail_count = 0;
static uint32_t login_lock_until_ms = 0;

static esp_timer_handle_t s_restart_timer = NULL;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000ULL); }

// ================= STATE HELPERS =================
static bool is_internet_available(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool ok = internet_ok;
    xSemaphoreGive(state_mutex);
    return ok;
}

static bool get_mem_pressure(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool p = mem_pressure;
    xSemaphoreGive(state_mutex);
    return p;
}

// ================= RESTART (không chặn luồng httpd) =================
static void restart_cb(void *arg) {
    (void)arg;
    esp_restart();
}

static void schedule_restart(uint32_t delay_ms) {
    if (s_restart_timer == NULL) {
        const esp_timer_create_args_t args = { .callback = restart_cb, .name = "apex_restart" };
        if (esp_timer_create(&args, &s_restart_timer) != ESP_OK) {
            esp_restart();
            return;
        }
    }
    esp_timer_stop(s_restart_timer);  // an toàn nếu chưa chạy
    esp_timer_start_once(s_restart_timer, (uint64_t)delay_ms * 1000ULL);
}

// ================= CONFIG (NVS) =================
static void copy_str(char *dst, size_t dst_sz, const char *src) {
    strncpy(dst, src, dst_sz - 1);
    dst[dst_sz - 1] = '\0';
}

static void save_ap_config(void) {
    xSemaphoreTake(nvs_mutex, portMAX_DELAY);
    nvs_set_str(s_nvs_handle, NVS_AP_SSID, ap_ssid);
    nvs_set_str(s_nvs_handle, NVS_AP_PASS, ap_pass);
    nvs_set_i32(s_nvs_handle, NVS_AP_CHANNEL, ap_channel);
    nvs_set_i32(s_nvs_handle, NVS_MAX_CLIENTS, max_clients);
    nvs_commit(s_nvs_handle);
    xSemaphoreGive(nvs_mutex);
}

static void save_sta_config(const char *ssid, const char *pass) {
    xSemaphoreTake(nvs_mutex, portMAX_DELAY);
    nvs_set_str(s_nvs_handle, NVS_STA_SSID, ssid);
    nvs_set_str(s_nvs_handle, NVS_STA_PASS, pass);
    nvs_commit(s_nvs_handle);
    xSemaphoreGive(nvs_mutex);
}

static void load_config(void) {
    size_t len;

    len = sizeof(ap_ssid);
    if (nvs_get_str(s_nvs_handle, NVS_AP_SSID, ap_ssid, &len) != ESP_OK || !apex_valid_ssid(ap_ssid)) {
        copy_str(ap_ssid, sizeof(ap_ssid), APEX_DEFAULT_AP_SSID);
    }

    len = sizeof(ap_pass);
    if (nvs_get_str(s_nvs_handle, NVS_AP_PASS, ap_pass, &len) != ESP_OK || !apex_valid_wpa_pass(ap_pass)) {
        copy_str(ap_pass, sizeof(ap_pass), APEX_DEFAULT_AP_PASS);
    }

    nvs_get_i32(s_nvs_handle, NVS_AP_CHANNEL, &ap_channel);
    if (ap_channel < 1 || ap_channel > 13) ap_channel = AP_CHANNEL_DEFAULT;

    nvs_get_i32(s_nvs_handle, NVS_MAX_CLIENTS, &max_clients);
    if (max_clients < 1 || max_clients > AP_MAX_CONN_LIMIT) max_clients = AP_MAX_CONN_DEFAULT;

    len = sizeof(sta_ssid);
    if (nvs_get_str(s_nvs_handle, NVS_STA_SSID, sta_ssid, &len) != ESP_OK || !apex_valid_ssid(sta_ssid)) {
        sta_ssid[0] = '\0';
    }
    len = sizeof(sta_pass);
    if (nvs_get_str(s_nvs_handle, NVS_STA_PASS, sta_pass, &len) != ESP_OK) {
        sta_pass[0] = '\0';
    }
    sta_configured = (sta_ssid[0] != '\0');
}

// ================= NAT =================
// Kích thước bảng NAPT do cấu hình SDK (sdkconfig / lwIP) quyết định, không chỉnh được lúc chạy.
static bool enable_nat(void) {
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool already = nat_enabled;
    xSemaphoreGive(state_mutex);
    if (already) return true;

    if (s_ap_netif == NULL) {
        ESP_LOGE(TAG, "enable_nat: AP netif chưa khởi tạo");
        return false;
    }
    esp_err_t err = esp_netif_napt_enable(s_ap_netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_napt_enable failed: %s", esp_err_to_name(err));
        return false;
    }
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    nat_enabled = true;
    xSemaphoreGive(state_mutex);
    ESP_LOGI(TAG, "NAT enabled");
    return true;
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

// ================= KIỂM TRA INTERNET =================
// Chỉ coi là online khi nhận đúng 204. Không theo redirect: captive portal của mạng uplink
// thường trả 302 -> 200 và trước đây bị nhận nhầm là "có internet".
static bool perform_internet_check(void) {
    esp_http_client_config_t config = {
        .url = "http://connectivitycheck.gstatic.com/generate_204",
        .timeout_ms = 5000,
        .method = HTTP_METHOD_GET,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) return false;

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    return (err == ESP_OK) && (status_code == 204);
}

// ================= DNS CAPTIVE PORTAL (apex_dns.h) =================
static int dns_cb_internet(void *ctx) { (void)ctx; return is_internet_available() ? 1 : 0; }

static uint32_t dns_cb_upstream(void *ctx) {
    (void)ctx;
    esp_netif_dns_info_t d;
    if (s_sta_netif != NULL &&
        esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &d) == ESP_OK &&
        d.ip.type == ESP_IPADDR_TYPE_V4) {
        return d.ip.u_addr.ip4.addr;
    }
    return 0;
}

static uint32_t dns_cb_rand(void) { return esp_random(); }
static void dns_cb_wdt(void) { esp_task_wdt_reset(); }
static void dns_cb_log(const char *m) { ESP_LOGI(TAG, "%s", m); }

static void dns_captive_task(void *pv) {
    (void)pv;
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_netif_ip_info_t ip;
        if (s_ap_netif == NULL || esp_netif_get_ip_info(s_ap_netif, &ip) != ESP_OK || ip.ip.addr == 0) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        apex_dns_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.port = 53;
        cfg.bind_addr = ip.ip.addr;              // chỉ lắng nghe trên IP của AP
        memcpy(cfg.ap_ip, &ip.ip.addr, 4);
        cfg.internet_ok = dns_cb_internet;
        cfg.upstream_ip = dns_cb_upstream;
        cfg.rand32 = dns_cb_rand;
        cfg.wdt_kick = dns_cb_wdt;
        cfg.log = dns_cb_log;

        int r = apex_dns_run(&cfg);               // chỉ trả về khi lỗi socket
        ESP_LOGE(TAG, "DNS server dừng (%d), thử lại sau 2s", r);
        for (int i = 0; i < 4; i++) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}

// ================= WIFI EVENT HANDLER =================
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    (void)arg;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (sta_configured) esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        bool should_retry = false;
        xSemaphoreTake(sta_state_mutex, portMAX_DELAY);
        sta_disconnected = true;
        if (s_retry_num < STA_MAX_RETRY) {
            s_retry_num++;
            should_retry = true;
        }
        int retry = s_retry_num;
        xSemaphoreGive(sta_state_mutex);

        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        if (should_retry) {
            esp_wifi_connect();
            ESP_LOGI(TAG, "Retry connecting... (%d/%d)", retry, STA_MAX_RETRY);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGW(TAG, "STA retry exhausted, background retry every %d s", STA_RECONNECT_BACKOFF_MS / 1000);
        }
        disable_nat();
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        internet_ok = false;
        xSemaphoreGive(state_mutex);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xSemaphoreTake(sta_state_mutex, portMAX_DELAY);
        s_retry_num = 0;
        sta_disconnected = false;
        xSemaphoreGive(sta_state_mutex);
        xEventGroupClearBits(wifi_event_group, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        // Đánh thức internet_check_task ngay, tránh điện thoại cache kết luận "no internet".
        if (internet_check_trigger != NULL) xSemaphoreGive(internet_check_trigger);
    }
}

static void sta_reconnect_task(void *pv) {
    (void)pv;
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_task_wdt_reset();
        EventBits_t bits = xEventGroupGetBits(wifi_event_group);
        bool should_connect = false;
        xSemaphoreTake(sta_state_mutex, portMAX_DELAY);
        if (sta_configured && !(bits & WIFI_CONNECTED_BIT) && sta_disconnected) {
            should_connect = true;
            sta_disconnected = false;   // tránh gọi lặp
        }
        xSemaphoreGive(sta_state_mutex);

        if (should_connect) {
            ESP_LOGI(TAG, "Background STA reconnect attempt...");
            esp_err_t err = esp_wifi_connect();
            if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
                xSemaphoreTake(sta_state_mutex, portMAX_DELAY);
                sta_disconnected = true;
                xSemaphoreGive(sta_state_mutex);
                ESP_LOGW(TAG, "esp_wifi_connect failed: %s", esp_err_to_name(err));
            }
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
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    // Cấu hình WiFi do ứng dụng tự quản lý trong NVS => không để driver ghi thêm vào flash.
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .password = "",
            .ssid_len = 0,
            .channel = (uint8_t)ap_channel,
            .max_connection = (uint8_t)max_clients,
            .authmode = WIFI_AUTH_WPA2_PSK,   // bỏ WPA1 (WPA_WPA2_PSK) vốn yếu
            .pmf_cfg = { .capable = true, .required = false },
        },
    };
    copy_str((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid), ap_ssid);
    copy_str((char *)ap_config.ap.password, sizeof(ap_config.ap.password), ap_pass);

    // Chưa cấu hình uplink thì chỉ bật AP: tránh STA quét/kết nối vô ích (driver log cảnh báo mỗi giây)
    // và tránh tranh chấp sóng với AP. Lưu cấu hình STA luôn khởi động lại nên chế độ được chọn lại.
    ESP_ERROR_CHECK(esp_wifi_set_mode(sta_configured ? WIFI_MODE_APSTA : WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    if (sta_configured) {
        wifi_config_t sta_config = { 0 };
        copy_str((char *)sta_config.sta.ssid, sizeof(sta_config.sta.ssid), sta_ssid);
        copy_str((char *)sta_config.sta.password, sizeof(sta_config.sta.password), sta_pass);
        // Mạng uplink không mật khẩu: nếu để ngưỡng WPA2 thì không bao giờ kết nối được.
        sta_config.sta.threshold.authmode = (sta_pass[0] == '\0') ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    }

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi started. AP: %s on channel %d", ap_ssid, (int)ap_channel);
}

// ================= HTTP HELPERS =================
static esp_err_t send_text(httpd_req_t *req, const char *status, const char *msg) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
}

// Chỉ phục vụ kết nối đến địa chỉ IP của AP; chặn truy cập từ phía mạng uplink (STA).
static bool request_on_ap_side(httpd_req_t *req) {
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0 || s_ap_netif == NULL) return false;
    struct sockaddr_in local;
    socklen_t l = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &l) != 0 || local.sin_family != AF_INET) return false;
    esp_netif_ip_info_t ip;
    if (esp_netif_get_ip_info(s_ap_netif, &ip) != ESP_OK) return false;
    return local.sin_addr.s_addr == ip.ip.addr;
}

#define REQUIRE_AP_SIDE(req)                                         \
    do {                                                             \
        if (!request_on_ap_side(req)) {                              \
            send_text(req, "403 Forbidden", "Forbidden");            \
            return ESP_OK;                                           \
        }                                                            \
    } while (0)

// Đọc body POST với giới hạn kích thước và thời gian (trước đây vòng lặp timeout là vô hạn).
static bool read_post_body(httpd_req_t *req, char *buf, size_t buf_size) {
    int total_len = (int)req->content_len;
    if (total_len <= 0 || (size_t)total_len >= buf_size) {
        send_text(req, "400 Bad Request", "Yêu cầu không hợp lệ hoặc quá lớn");
        return false;
    }
    int received = 0;
    int timeouts = 0;
    while (received < total_len) {
        int ret = httpd_req_recv(req, buf + received, (size_t)(total_len - received));
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            if (++timeouts >= 3) {
                httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "Hết thời gian nhận dữ liệu");
                return false;
            }
            continue;
        }
        if (ret <= 0) {
            send_text(req, "400 Bad Request", "Không đọc được dữ liệu");
            return false;
        }
        received += ret;
    }
    buf[total_len] = '\0';
    return true;
}

// Token + giới hạn tần suất cho các lệnh ghi cấu hình.
static bool check_auth_and_rate(const char *body, httpd_req_t *req) {
    char token[TOKEN_LEN + 8];
    int r = apex_form_get(body, "token", token, sizeof(token));
    if (r != 1 || !apex_ct_equal(token, session_token)) {
        send_text(req, "401 Unauthorized", "Chưa đăng nhập hoặc token không hợp lệ");
        return false;
    }

    xSemaphoreTake(rate_limit_mutex, portMAX_DELAY);
    uint32_t now = now_ms();
    if ((uint32_t)(now - last_config_window_ms) > CONFIG_RATE_WINDOW_MS) {
        last_config_window_ms = now;
        config_request_count = 0;
    }
    config_request_count++;
    bool rate_ok = (config_request_count <= CONFIG_RATE_MAX_REQ);
    xSemaphoreGive(rate_limit_mutex);

    if (!rate_ok) {
        send_text(req, "429 Too Many Requests", "Quá nhiều yêu cầu, vui lòng thử lại sau");
        return false;
    }
    return true;
}

// ================= HTTP HANDLERS =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, APEX_INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

// POST /login  (pass=<mật khẩu AP>)  ->  {"token":"..."}
static esp_err_t login_post_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);

    xSemaphoreTake(rate_limit_mutex, portMAX_DELAY);
    uint32_t now = now_ms();
    bool locked = (login_lock_until_ms != 0) && ((int32_t)(login_lock_until_ms - now) > 0);
    uint32_t wait_s = locked ? (login_lock_until_ms - now) / 1000 + 1 : 0;
    xSemaphoreGive(rate_limit_mutex);
    if (locked) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Sai quá nhiều lần. Thử lại sau %u giây", (unsigned)wait_s);
        return send_text(req, "429 Too Many Requests", msg);
    }

    char body[BODY_BUF_LEN / 2];
    if (!read_post_body(req, body, sizeof(body))) return ESP_OK;

    char pass[PASS_BUF_LEN + 8];
    bool ok = (apex_form_get(body, "pass", pass, sizeof(pass)) == 1) && apex_ct_equal(pass, ap_pass);

    xSemaphoreTake(rate_limit_mutex, portMAX_DELAY);
    if (ok) {
        login_fail_count = 0;
        login_lock_until_ms = 0;
    } else if (++login_fail_count >= LOGIN_MAX_FAILS) {
        login_fail_count = 0;
        login_lock_until_ms = now_ms() + LOGIN_LOCKOUT_MS;
        if (login_lock_until_ms == 0) login_lock_until_ms = 1;
    }
    xSemaphoreGive(rate_limit_mutex);

    if (!ok) return send_text(req, "401 Unauthorized", "Sai mật khẩu");

    char out[64];
    snprintf(out, sizeof(out), "{\"token\":\"%s\"}", session_token);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_get_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);

    uint32_t free_heap = esp_get_free_heap_size();

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    bool nat_e = nat_enabled;
    bool inet = internet_ok;
    bool memlow = mem_pressure;
    int rssi = last_rssi;
    xSemaphoreGive(state_mutex);

    wifi_sta_list_t sta_list;
    int clients = (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) ? sta_list.num : 0;
    bool sta_connected = (xEventGroupGetBits(wifi_event_group) & WIFI_CONNECTED_BIT) != 0;

    char ssid_esc[SSID_BUF_LEN * 6 + 1];
    apex_json_escape(ssid_esc, sizeof(ssid_esc), sta_ssid);

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
        "{\"ram\":%lu,\"internet\":%s,\"nat\":%s,\"memLow\":%s,\"clients\":%d,\"clientLimit\":%d,"
        "\"rssi\":%d,\"staConnected\":%s,\"staSsid\":\"%s\",\"weakPassword\":%s}",
        (unsigned long)free_heap,
        inet ? "true" : "false",
        nat_e ? "true" : "false",
        memlow ? "true" : "false",
        clients, (int)max_clients,
        rssi,
        sta_connected ? "true" : "false",
        ssid_esc,
        apex_ct_equal(ap_pass, APEX_DEFAULT_AP_PASS) ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t config_get_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    char a[SSID_BUF_LEN * 6 + 1], s[SSID_BUF_LEN * 6 + 1];
    apex_json_escape(a, sizeof(a), ap_ssid);
    apex_json_escape(s, sizeof(s), sta_ssid);
    char buffer[2 * (SSID_BUF_LEN * 6 + 1) + 48];
    snprintf(buffer, sizeof(buffer), "{\"apSsid\":\"%s\",\"staSsid\":\"%s\"}", a, s);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buffer, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t clients_get_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    httpd_resp_set_type(req, "application/json");

    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK || s_ap_netif == NULL) {
        return httpd_resp_send(req, "[]", HTTPD_RESP_USE_STRLEN);
    }
    int num = sta_list.num;
    if (num > 10) num = 10;

    esp_netif_pair_mac_ip_t pairs[10];
    memset(pairs, 0, sizeof(pairs));
    for (int i = 0; i < num; i++) memcpy(pairs[i].mac, sta_list.sta[i].mac, 6);
    if (num > 0) esp_netif_dhcps_get_clients_by_mac(s_ap_netif, num, pairs);

    char buffer[1024];
    size_t off = 0;
    buffer[off++] = '[';
    for (int i = 0; i < num; i++) {
        if (off + 80 >= sizeof(buffer)) break;
        int w = snprintf(buffer + off, sizeof(buffer) - off,
            "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ip\":\"" IPSTR "\"}",
            (i > 0) ? "," : "",
            pairs[i].mac[0], pairs[i].mac[1], pairs[i].mac[2],
            pairs[i].mac[3], pairs[i].mac[4], pairs[i].mac[5],
            IP2STR(&pairs[i].ip));
        if (w < 0 || (size_t)w >= sizeof(buffer) - off) break;
        off += (size_t)w;
    }
    buffer[off++] = ']';
    return httpd_resp_send(req, buffer, (ssize_t)off);
}

static esp_err_t save_sta_post_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    char body[BODY_BUF_LEN];
    if (!read_post_body(req, body, sizeof(body))) return ESP_OK;
    if (!check_auth_and_rate(body, req)) return ESP_OK;

    char ssid[SSID_BUF_LEN + 8];
    char pass[PASS_BUF_LEN + 8];
    int rs = apex_form_get(body, "ssid", ssid, sizeof(ssid));
    int rp = apex_form_get(body, "pass", pass, sizeof(pass));

    if (rs != 1 || !apex_valid_ssid(ssid)) {
        return send_text(req, "400 Bad Request", "Tên WiFi phải dài 1-32 byte");
    }
    if (rp == -1 || (pass[0] != '\0' && !apex_valid_wpa_pass(pass))) {
        return send_text(req, "400 Bad Request", "Mật khẩu WiFi phải dài 8-63 ký tự (hoặc để trống nếu mạng mở)");
    }
    if (rp == 0) pass[0] = '\0';

    save_sta_config(ssid, pass);
    ESP_LOGI(TAG, "Saved STA: %s", ssid);
    schedule_restart(1500);
    return send_text(req, "200 OK", "Đã lưu. Thiết bị đang khởi động lại, sẽ mất kết nối vài giây...");
}

static esp_err_t save_ap_post_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    char body[BODY_BUF_LEN];
    if (!read_post_body(req, body, sizeof(body))) return ESP_OK;
    if (!check_auth_and_rate(body, req)) return ESP_OK;

    char ssid[SSID_BUF_LEN + 8];
    char pass[PASS_BUF_LEN + 8];
    int rs = apex_form_get(body, "ssid", ssid, sizeof(ssid));
    int rp = apex_form_get(body, "pass", pass, sizeof(pass));
    if (rs == -1) return send_text(req, "400 Bad Request", "Tên WiFi quá dài (tối đa 32 byte)");
    if (rp == -1) return send_text(req, "400 Bad Request", "Mật khẩu quá dài (tối đa 63 ký tự)");

    bool change_ssid = (rs == 1 && ssid[0] != '\0');
    bool change_pass = (rp == 1 && pass[0] != '\0');
    if (change_ssid && !apex_valid_ssid(ssid)) {
        return send_text(req, "400 Bad Request", "Tên WiFi phải dài 1-32 byte, không chứa ký tự điều khiển");
    }
    if (change_pass && !apex_valid_wpa_pass(pass)) {
        return send_text(req, "400 Bad Request", "Mật khẩu AP phải dài 8-63 ký tự");
    }
    if (change_ssid && strcmp(ssid, ap_ssid) == 0) change_ssid = false;
    if (change_pass && strcmp(pass, ap_pass) == 0) change_pass = false;
    if (!change_ssid && !change_pass) {
        return send_text(req, "200 OK", "Không có thay đổi nào để lưu.");
    }

    if (change_ssid) copy_str(ap_ssid, sizeof(ap_ssid), ssid);
    if (change_pass) copy_str(ap_pass, sizeof(ap_pass), pass);
    save_ap_config();
    ESP_LOGI(TAG, "Saved AP: %s", ap_ssid);
    schedule_restart(1500);
    return send_text(req, "200 OK", "Đã lưu. Thiết bị đang khởi động lại, hãy kết nối lại bằng thông tin mới...");
}

// ================= CAPTIVE PORTAL HTTP =================
static esp_err_t redirect_to_portal(httpd_req_t *req) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t captive_204_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    if (is_internet_available()) {
        httpd_resp_set_status(req, "204 No Content");
        return httpd_resp_send(req, NULL, 0);
    }
    return redirect_to_portal(req);
}

static esp_err_t captive_success_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    if (is_internet_available()) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_send(req, NULL, 0);
    }
    return redirect_to_portal(req);
}

static esp_err_t captive_apple_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    if (is_internet_available()) {
        httpd_resp_set_type(req, "text/html");
        return httpd_resp_send(req, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
                               HTTPD_RESP_USE_STRLEN);
    }
    return redirect_to_portal(req);
}

static esp_err_t captive_ncsi_handler(httpd_req_t *req) {
    REQUIRE_AP_SIDE(req);
    if (is_internet_available()) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_send(req, "Microsoft NCSI", HTTPD_RESP_USE_STRLEN);
    }
    return redirect_to_portal(req);
}

// Mọi URL lạ: khi chưa có internet thì đưa về trang chính (captive portal), ngược lại trả 404.
static esp_err_t not_found_handler(httpd_req_t *req, httpd_err_code_t err) {
    (void)err;
    if (!request_on_ap_side(req)) {
        httpd_resp_set_status(req, "403 Forbidden");
        return httpd_resp_send(req, "Forbidden", HTTPD_RESP_USE_STRLEN);
    }
    if (!is_internet_available()) return redirect_to_portal(req);
    httpd_resp_set_status(req, "404 Not Found");
    return httpd_resp_send(req, "Not found", HTTPD_RESP_USE_STRLEN);
}

// ================= WEB SERVER =================
static void register_uri(const char *uri, httpd_method_t method, esp_err_t (*handler)(httpd_req_t *)) {
    httpd_uri_t u = { .uri = uri, .method = method, .handler = handler, .user_ctx = NULL };
    esp_err_t err = httpd_register_uri_handler(server, &u);
    if (err != ESP_OK) ESP_LOGE(TAG, "register %s failed: %s", uri, esp_err_to_name(err));
}

static void start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 20;
    config.max_open_sockets = 7;      // cần CONFIG_LWIP_MAX_SOCKETS >= 7 + 3 (+ socket DNS/HTTP client) - xem sdkconfig.defaults
    config.stack_size = 6144;
    config.recv_wait_timeout = 5;
    config.send_wait_timeout = 5;

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Không khởi động được web server");
        return;
    }
    register_uri("/", HTTP_GET, root_get_handler);
    register_uri("/login", HTTP_POST, login_post_handler);
    register_uri("/api/status", HTTP_GET, status_get_handler);
    register_uri("/api/config", HTTP_GET, config_get_handler);
    register_uri("/api/clients", HTTP_GET, clients_get_handler);
    register_uri("/save-sta", HTTP_POST, save_sta_post_handler);
    register_uri("/save-ap", HTTP_POST, save_ap_post_handler);

    register_uri("/generate_204", HTTP_GET, captive_204_handler);
    register_uri("/connectivity-check", HTTP_GET, captive_204_handler);
    register_uri("/captive", HTTP_GET, captive_204_handler);
    register_uri("/canonical.html", HTTP_GET, captive_204_handler);
    register_uri("/apple-sd", HTTP_GET, captive_204_handler);
    register_uri("/success", HTTP_GET, captive_success_handler);
    register_uri("/hotspot-detect.html", HTTP_GET, captive_apple_handler);
    register_uri("/library/test/success.html", HTTP_GET, captive_apple_handler);
    register_uri("/ncsi.txt", HTTP_GET, captive_ncsi_handler);

    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, not_found_handler);
    ESP_LOGI(TAG, "Web server started with captive portal support");
}

// ================= INTERNET CHECK TASK =================
static void internet_check_task(void *pv) {
    (void)pv;
    esp_task_wdt_add(NULL);
    for (;;) {
        esp_task_wdt_reset();

        bool sta_connected = (xEventGroupGetBits(wifi_event_group) & WIFI_CONNECTED_BIT) != 0;
        bool reachable = sta_connected ? perform_internet_check() : false;
        esp_task_wdt_reset();

        // Chỉ bật NAT khi thật sự có internet VÀ RAM không thấp (hysteresis ở vòng lặp chính).
        bool should_be_online = sta_connected && reachable && !get_mem_pressure();

        if (should_be_online) {
            if (!enable_nat()) should_be_online = false;
        } else {
            disable_nat();
        }

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        internet_ok = should_be_online;
        xSemaphoreGive(state_mutex);

        // Chỉ log khi trạng thái đổi (trước đây log lặp lại mỗi 10 s).
        static int last_logged = -1;
        int cur = should_be_online ? 1 : 0;
        if (cur != last_logged) {
            last_logged = cur;
            if (cur) {
                ESP_LOGI(TAG, "Internet: ONLINE");
            } else {
                ESP_LOGI(TAG, "Internet: OFFLINE (STA=%d, Reachable=%d, MemLow=%d)",
                         sta_connected, reachable, (int)get_mem_pressure());
            }
        }

        // Chờ tối đa 10 s, nhưng được đánh thức ngay khi STA vừa có IP.
        xSemaphoreTake(internet_check_trigger, pdMS_TO_TICKS(10000));
    }
}

// ================= MAIN =================
static SemaphoreHandle_t must_mutex(void) {
    SemaphoreHandle_t m = xSemaphoreCreateMutex();
    if (m == NULL) { ESP_LOGE(TAG, "Không tạo được mutex"); abort(); }
    return m;
}

static void make_session_token(void) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < TOKEN_LEN; i += 8) {
        uint32_t r = esp_random();
        for (int j = 0; j < 8; j++) {
            session_token[i + j] = hex[(r >> (28 - 4 * j)) & 0xF];
        }
    }
    session_token[TOKEN_LEN] = '\0';
}

void app_main(void) {
    ESP_LOGI(TAG, "APEX ULTRA V%s - ESP-IDF NAT router", APEX_VERSION);

    state_mutex = must_mutex();
    nvs_mutex = must_mutex();
    rate_limit_mutex = must_mutex();
    sta_state_mutex = must_mutex();
    internet_check_trigger = xSemaphoreCreateBinary();
    if (internet_check_trigger == NULL) { ESP_LOGE(TAG, "Không tạo được semaphore"); abort(); }

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_nvs_handle));
    load_config();

    if (apex_ct_equal(ap_pass, APEX_DEFAULT_AP_PASS)) {
        ESP_LOGW(TAG, "CẢNH BÁO: đang dùng mật khẩu AP mặc định, hãy đổi ngay!");
    }

    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    esp_err_t wdt_err = esp_task_wdt_reconfigure(&wdt_config);
    if (wdt_err != ESP_OK) ESP_LOGW(TAG, "esp_task_wdt_reconfigure: %s", esp_err_to_name(wdt_err));
    esp_task_wdt_add(NULL);

    wifi_init();
    // Token 128 bit tạo SAU khi WiFi đã chạy: lúc này esp_random() mới là RNG phần cứng thật sự.
    make_session_token();

    start_webserver();

    xTaskCreate(internet_check_task, "inet_check", 6144, NULL, 2, NULL);
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

    ESP_LOGI(TAG, "Sẵn sàng. AP: %s -> http://192.168.4.1 (đăng nhập bằng mật khẩu AP)", ap_ssid);

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_task_wdt_reset();

        wifi_ap_record_t ap_info;
        int rssi = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) ? ap_info.rssi : -100;

        // Theo dõi RAM với hysteresis: thiếu RAM -> tắt NAT; chỉ bật lại khi RAM hồi phục.
        uint32_t free_heap = esp_get_free_heap_size();
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        last_rssi = rssi;
        bool prev = mem_pressure;
        mem_pressure = apex_mem_pressure(prev ? 1 : 0, free_heap) != 0;
        bool now_p = mem_pressure;
        xSemaphoreGive(state_mutex);

        if (now_p && !prev) {
            ESP_LOGW(TAG, "RAM thấp (%u B) - tắt NAT", (unsigned)free_heap);
            disable_nat();
            xSemaphoreTake(state_mutex, portMAX_DELAY);
            internet_ok = false;
            xSemaphoreGive(state_mutex);
        } else if (!now_p && prev) {
            ESP_LOGI(TAG, "RAM đã hồi phục (%u B)", (unsigned)free_heap);
            xSemaphoreGive(internet_check_trigger);   // kiểm tra lại ngay và bật NAT
        }
    }
}
