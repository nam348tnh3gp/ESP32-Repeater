FROM ubuntu:22.04

# Cập nhật hệ thống và cài đặt các gói cần thiết
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Tải và cài đặt Arduino CLI
RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
ENV PATH="/root/bin:${PATH}"

# Cập nhật chỉ mục core và thêm URL kho lưu trữ phát triển của ESP32
RUN arduino-cli core update-index
RUN arduino-cli config add board_manager.additional_urls https://espressif.github.io/arduino-esp32/package_esp32_dev_index.json

# Cập nhật chỉ mục core một lần nữa sau khi thêm URL mới
RUN arduino-cli core update-index

# Cài đặt phiên bản core alpha 3.3.0-alpha1 có hỗ trợ ESP32-C5
RUN arduino-cli core install esp32:esp32@3.3.0-alpha1

# Cài đặt thủ công các thư viện mà code của bạn yêu cầu
RUN arduino-cli lib install "AsyncTCP"
RUN arduino-cli lib install "ESP Async WebServer"
RUN arduino-cli lib install "ArduinoJson"

# Thiết lập thư mục làm việc
WORKDIR /firmware

# Sao chép toàn bộ nội dung dự án vào container
COPY . .

# Tạo thư mục sketch với đúng cấu trúc mà Arduino CLI yêu cầu
# Giả sử file .ino của bạn là 'ESP_Code.ino', hãy thay đổi nếu tên khác
RUN mkdir -p ESP_Code && cp ESP_Code.ino ESP_Code/ESP_Code.ino
WORKDIR /firmware/ESP_Code

# Biên dịch firmware. Lúc này FQBN sẽ được nhận diện
RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 --export-binaries --verbose
