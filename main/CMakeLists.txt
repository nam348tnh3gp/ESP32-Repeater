idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES 
                        nvs_flash
                        esp_wifi
                        esp_event
                        esp_netif
                        lwip
                        esp_http_server
                        json)
