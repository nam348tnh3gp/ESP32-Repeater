[![Platform: ESP32](https://img.shields.io/badge/Platform-ESP32-blue)](https://www.espressif.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-22.4.0-orange)](https://github.com/nam348tnh3gp/ESP32-Repeater)

# ESP32 NAT Router – APEX ULTRA (V22.4.0)

Firmware biến một board ESP32 thành **repeater WiFi có NAT**: ESP32 kết nối vào mạng WiFi hiện có (STA) và phát lại một mạng riêng (AP) cho các thiết bị khác, kèm trang quản trị web và captive portal.

> **Ghi chú trung thực:** đây là firmware cho thiết bị nhúng cỡ nhỏ. Thông lượng NAT của ESP32 chỉ ở mức vài chục Mbps trở xuống, giao diện quản trị chạy **HTTP thuần (không TLS)**, và danh sách board bên dưới chỉ là những chip mà code hướng tới, không phải bảng cam kết đã kiểm thử.

---

## Hai bản cài đặt, một lõi dùng chung

| Bản | File chính | Dùng khi |
|---|---|---|
| **ESP-IDF** (bản chính) | `main/main.c` + `platformio.ini` | Muốn kiểm soát cấu hình SDK (số socket, NAPT…) |
| Arduino | `ESP_Code.ino` | Muốn build nhanh bằng Arduino IDE / arduino-cli |

Cả hai dùng chung ba header ở thư mục gốc, nên mọi sửa lỗi logic chỉ làm một nơi:

* `apex_common.h` – kiểm tra SSID/mật khẩu, so sánh hằng thời gian, JSON escape, parse form, ngưỡng RAM có hysteresis
* `apex_dns.h` – DNS captive portal + forwarder không chặn
* `apex_ui.h` – giao diện web (có đăng nhập)

> Khi dùng Arduino IDE, đặt `ESP_Code.ino` và ba file `apex_*.h` **cùng một thư mục** (tên thư mục phải là `ESP_Code`).

---

## Tính năng

* WiFi **AP + STA đồng thời**, NAPT của lwIP.
* **NAT chỉ bật khi thật sự có internet**: kiểm tra bằng HTTP GET `generate_204`, chỉ chấp nhận mã **204** và không theo redirect (captive portal của mạng uplink không còn bị nhận nhầm là "có internet").
* **Captive portal**: DNS + HTTP handler cho Android / iOS / Windows / Firefox. Khi chưa có internet, các domain kiểm tra captive được trả về IP của thiết bị; khi đã có internet, mọi truy vấn được **forward** lên DNS của mạng uplink (fallback 8.8.8.8).
* **Tự kết nối lại STA**: thử lại tối đa 5 lần, sau đó thử nền mỗi 30 giây.
* **Bảo vệ RAM có hysteresis**: tắt NAT khi heap < 26 KB, chỉ bật lại khi heap > 40 KB (không còn bật/tắt liên tục quanh một ngưỡng).
* **Watchdog** 45 giây trên các task chính (kể cả DNS).
* Dashboard: RAM, trạng thái internet/NAT, RSSI, danh sách client, cảnh báo mật khẩu mặc định / RAM thấp.

## Mô hình bảo mật

* Trang trạng thái chỉ đọc. **Muốn đổi cấu hình phải đăng nhập** (`POST /login`) bằng **mật khẩu AP**.
* Token phiên 128 bit (RNG phần cứng) chỉ được trả về sau khi đăng nhập đúng; không còn endpoint trả token công khai.
* Đăng nhập sai 5 lần → khoá 60 giây. Các lệnh ghi cấu hình giới hạn 3 yêu cầu / 5 giây.
* **Chỉ phục vụ khách của AP**: mọi request tới địa chỉ IP phía STA (mạng uplink) bị từ chối, DNS chỉ lắng nghe trên IP của AP (không thành open resolver cho mạng uplink).
* Dữ liệu nhập được kiểm tra phía thiết bị: SSID 1–32 byte, mật khẩu WPA2 8–63 ký tự. SSID rỗng không còn có thể làm hỏng cấu hình AP.
* AP dùng WPA2-PSK (bản ESP-IDF bỏ chế độ hỗn hợp WPA1).

**Giới hạn còn lại:** HTTP không mã hoá nên người cùng AP có thể nghe lén mật khẩu khi bạn đăng nhập; mật khẩu AP mặc định là `12345678` — **hãy đổi ngay** lần đầu dùng (dashboard sẽ cảnh báo).

## Dùng nhanh

1. Nạp firmware, kết nối vào WiFi `APEX_ULTRA` (mật khẩu mặc định `12345678`).
2. Mở `http://192.168.4.1`, đăng nhập bằng mật khẩu AP.
3. Nhập WiFi uplink ở mục **Uplink Configuration** → thiết bị tự khởi động lại và kết nối.
4. Đổi tên/mật khẩu AP ở mục **AP Configuration** (để trống mật khẩu = giữ nguyên).

Kích thước bảng NAPT do cấu hình SDK quyết định lúc build, **không chỉnh được lúc chạy** (các ô "NAPT slots" cũ trên giao diện chưa từng có tác dụng nên đã bị gỡ).

## Build

### ESP-IDF (PlatformIO)

```bash
pip install -r requirements.txt
rm -rf .pio sdkconfig        # bắt buộc sau khi đổi sdkconfig.defaults
pio run                      # build
pio run -t upload            # nạp (PlatformIO tự dò cổng)
```

Phân vùng app trong `partitions.csv` rộng 1,875 MB (mặc định của PlatformIO chỉ 1 MB nên ESP32-C6 từng tràn flash); `sdkconfig.defaults` còn bật `-Os`, tắt HTTPS của HTTP client và IPv6 để firmware nhỏ hơn. Ngoài ra `sdkconfig.defaults` đã đặt `CONFIG_LWIP_IPV4_NAPT`, `CONFIG_LWIP_IP_FORWARD` và `CONFIG_LWIP_MAX_SOCKETS=16` (cần cho web server + DNS + HTTP client chạy đồng thời).

### Arduino

Cài thư viện theo `requirements.arduino` (AsyncTCP, ESPAsyncWebServer, ArduinoJson) và core `esp32:esp32` (CI dùng 3.2.0), chọn board ESP32 rồi biên dịch `ESP_Code.ino`. NAPT cần được bật trong thư viện lwIP của core bạn dùng; nếu `esp_netif_napt_enable` lỗi lúc chạy, hãy dùng bản ESP-IDF.

## Kiểm thử

```bash
./tests/run.sh
```

Chạy trên máy host (gcc + python3, có AddressSanitizer/UBSan): unit test của `apex_common.h`, và test chức năng của DNS server thật trên loopback (captive, forwarder không chặn, chống trả lời giả mạo, gói lỗi). Phần phụ thuộc ESP-IDF (WiFi, NAT, web server) chỉ được xác nhận qua CI build và thử trên board thật.

## Board mục tiêu

ESP32 (WROOM-32/32U/32D/32E, PICO-D4 đều là cùng một chip), ESP32-S2/S3/C3/C5/C6 ở mức "code hướng tới, chưa kiểm thử đầy đủ". ESP32-S2 và các chip C-series chỉ có **một lõi**; firmware không phụ thuộc vào việc có hai lõi (chỉ `networkTask` bản Arduino được ghim vào core 0).

## Giấy phép

MIT – xem `LICENSE`.
