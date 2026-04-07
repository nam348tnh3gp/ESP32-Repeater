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

# Cài đặt board ESP32
RUN arduino-cli core update-index
RUN arduino-cli core install esp32:esp32@3.0.7

WORKDIR /firmware

# Copy toàn bộ code vào thư mục có tên giống file .ino
# Tạo thư mục ESP_Code và copy file vào đó
RUN mkdir -p ESP_Code
COPY ESP_Code.ino ESP_Code/ESP_Code.ino

# Chuyển vào thư mục sketch
WORKDIR /firmware/ESP_Code

# Compile
RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 --export-binaries .
