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

# Cập nhật chỉ mục và cài đặt lõi (core) cho ESP32 (bao gồm C5)
RUN arduino-cli core update-index
RUN arduino-cli core install esp32:esp32@3.0.7

# Thiết lập thư mục làm việc trong container
WORKDIR /firmware

# Sao chép toàn bộ nội dung dự án vào container
COPY . .

# Tạo thư mục sketch với đúng cấu trúc mà Arduino CLI yêu cầu
# Ví dụ: Tên file .ino của bạn là 'ESP_Code.ino'
RUN mkdir -p ESP_Code && cp ESP_Code.ino ESP_Code/ESP_Code.ino
WORKDIR /firmware/ESP_Code

# Biên dịch firmware
RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 --export-binaries
