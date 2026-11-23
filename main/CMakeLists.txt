# Các header dùng chung (apex_common.h, apex_dns.h, apex_ui.h) nằm ở thư mục gốc dự án,
# cạnh ESP_Code.ino, nên thêm ".." vào INCLUDE_DIRS.
idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "." ".."
                    REQUIRES
                        nvs_flash
                        esp_wifi
                        esp_event
                        esp_netif
                        esp_timer
                        esp_http_client
                        esp_http_server
                        lwip
                        driver)
