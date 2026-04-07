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

# Cài đặt board ESP32 (bao gồm C5)
RUN arduino-cli core update-index
RUN arduino-cli core install esp32:esp32@3.0.7

# Tạo thư mục sketch
WORKDIR /firmware
COPY . .

# Liệt kê các board có sẵn để debug
RUN arduino-cli board listall | grep -i esp32c5 || echo "ESP32-C5 not found in list"

# Compile với FQBN đúng
RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 --export-binaries .
