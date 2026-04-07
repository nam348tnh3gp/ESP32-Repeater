FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Cài Arduino CLI
RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
ENV PATH="/root/bin:${PATH}"

# Cài ESP32 core (bao gồm C5)
RUN arduino-cli core update-index
RUN arduino-cli core install esp32:esp32@3.0.7

WORKDIR /firmware
COPY . .

RUN arduino-cli compile --fqbn esp32:esp32:esp32c5 \
    --build-property build.partitions=default \
    --export-binaries .
