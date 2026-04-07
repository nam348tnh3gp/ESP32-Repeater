FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Cài Arduino CLI
RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
ENV PATH="/root/bin:${PATH}"

# Cấu hình board manager URL cho ESP32 development (chứa core 3.3.0-alpha1)
RUN arduino-cli core update-index
RUN arduino-cli config add board_manager.additional_urls https://espressif.github.io/arduino-esp32/package_esp32_dev_index.json
RUN arduino-cli core update-index

# Cài core alpha hỗ trợ ESP32-C5
RUN arduino-cli core install esp32:esp32@3.3.0-alpha1

# Cài các thư viện cần thiết
RUN arduino-cli lib install "AsyncTCP"
RUN arduino-cli lib install "ESP Async WebServer"
RUN arduino-cli lib install "ArduinoJson"

WORKDIR /firmware
COPY . .

# Tạo cấu trúc sketch đúng chuẩn (tên thư mục trùng với file .ino)
# Giả sử file .ino của bạn là ESP_Code.ino
RUN mkdir -p ESP_Code && cp ESP_Code.ino ESP_Code/ESP_Code.ino
WORKDIR /firmware/ESP_Code

# Biên dịch với flag bật NAPT
RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 \
    --export-binaries \
    --verbose \
    --build-property compiler.cpp.extra_flags="-DLWIP_NAPT=1"
