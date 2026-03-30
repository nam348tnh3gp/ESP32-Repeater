[![Platform: ESP32](https://img.shields.io/badge/Platform-ESP32-blue)](https://www.espressif.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-19.9.7-orange)](https://github.com/nam348tnh3gp/ESP32-Repeater)
[![Arduino](https://img.shields.io/badge/Arduino-ESP32-cyan)](https://www.arduino.cc/)
# 🛡️ ESP32 NAT Router – V19.9.7 (APEX ULTRA)

**Category:** Secure Embedded Network OS
**Platform:** ESP32 (Dual-Core)
**Architecture:** SMP-aware RTOS + lwIP NAT (NAPT)

---

## 📝 Supported Boards

This firmware has been tested and verified on the following ESP32 boards:

* **ESP32-WROOM-32** (standard Dev Module)
* **ESP32-WROOM-32U** (external antenna version)
* **ESP32-WROOM-32D**
* **ESP32-WROOM-32E**
* **ESP32-S2 / S3** (limited testing, adjust NAT slots)
* **ESP32-PICO-D4**

> ⚠️ Notes:
>
> * Some boards with very limited RAM (< 320KB free heap) may experience NAT table purges more frequently.
> * For ESP32-S2/S3, dual-core task assignment may need minor tweaks for network task pinning.

---

## 🚀 Overview

**APEX KERNEL V19.9.7** is a high-performance, security-focused NAT router firmware for ESP32.
It transforms a single ESP32 board into a **WiFi repeater / access point with NAT**, complete with:

* 🔐 Token-based secure control plane
* ⚡ Real-time WebSocket telemetry dashboard
* 🧠 Memory-aware NAT lifecycle management
* 🛡️ Active rate limiting & watchdog protection

This firmware is designed for **24/7 stable operation** under constrained hardware conditions.

---

## ✨ Key Features

### 🌐 Networking

* WiFi **AP + STA concurrent mode**
* Full **NAPT (Network Address Port Translation)** using lwIP
* DHCP + DNS captive portal support
* Automatic internet connectivity detection

---

### 🔐 Security Layer

* **Hardware RNG session token** (`esp_random()`)
* Token-bound RPC (WebSocket command authentication)
* **Rate-limited control plane** (anti-spam / anti-flood)
* WebSocket client limit enforcement

---

### 🧠 Resource Management

* **Dynamic NAT pressure control**

  * `STABLE` → normal operation
  * `STRESS` → memory warning
  * `PURGE` → forced NAT table reset
* Heap monitoring with critical threshold protection
* Automatic NAT reinitialization

---

### ⚙️ Kernel Architecture

* Dual-core task separation:

  * Core 0 → Network + NAT engine
  * Core 1 → DNS + health check
* SMP-safe atomic variables (`std::atomic`)
* Multi-task **Watchdog Timer (WDT)** protection

---

### 📊 Web Dashboard (APEX UI)

* Real-time stats via WebSocket:

  * Internet status
  * Heap memory
  * Uptime
  * NAT pressure state
* Connected client list (IP + MAC)
* STA configuration panel

---

## 🧩 System Architecture

```
                ┌────────────────────┐
                │   Web Dashboard    │
                │  (WebSocket UI)    │
                └─────────┬──────────┘
                          │
                ┌─────────▼──────────┐
                │   Control Plane    │
                │ Token + RateLimit  │
                └─────────┬──────────┘
                          │
        ┌─────────────────▼─────────────────┐
        │        APEX NETWORK TASK          │
        │  - NAT lifecycle                 │
        │  - Memory pressure control       │
        │  - Telemetry broadcast           │
        └─────────────────┬─────────────────┘
                          │
        ┌─────────────────▼─────────────────┐
        │        lwIP NAPT Engine           │
        │   (ip_napt_enable / init)         │
        └───────────────────────────────────┘
```

---

## ⚙️ Configuration

### Default Access Point

* SSID: `APEX_ULTRA`
* Password: `12345678`
* IP: `192.168.4.1`

---

### Kernel Parameters

| Parameter                | Value       | Description           |
| ------------------------ | ----------- | --------------------- |
| `MAX_AP_CLIENTS`         | 8           | Max connected devices |
| `MAX_WS_CLIENTS`         | 2           | Max dashboard clients |
| `WATCHDOG_TIMEOUT`       | 45s         | WDT timeout           |
| `MEM_CRITICAL_THRESHOLD` | 26000 bytes | NAT purge trigger     |
| `SESSION_KEY_LEN`        | 16          | Token length          |

---

## 🛠️ Build & Flash

### Requirements

* Arduino IDE / PlatformIO
* ESP32 Board Package
* Libraries:

  * `ESPAsyncWebServer`
  * `AsyncTCP`
  * `ArduinoJson`
  * `Preferences` (built-in)

---

### Flashing

1. Select board: **ESP32 Dev Module**
2. Set partition scheme: **Default / Large APP**
3. Upload firmware
4. Open Serial Monitor (115200 baud)

---

## 🌍 Usage

1. Connect to WiFi: `APEX_ULTRA`
2. Open browser:

   ```
   http://192.168.4.1
   ```
3. View dashboard
4. Configure STA (uplink WiFi)
5. Router auto-reboots and connects

---

## 🔄 NAT Lifecycle Logic

The system continuously evaluates memory:

* **Heap > 50KB** → `STABLE`
* **Heap 26KB–50KB** → `STRESS`
* **Heap < 26KB** → `PURGE`

  * Disable NAT
  * Clear NAT table
  * Reinitialize

This ensures **zero memory leak accumulation** over long uptime.

---

## 🔐 Security Model

### Session Token

* Generated at boot using hardware RNG
* Injected into UI
* Required for all RPC commands

### Rate Limiting

* Max **3 concurrent control requests**
* Prevents:

  * Web flooding
  * WS abuse
  * Resource exhaustion

---

## 📡 Background Tasks

| Task       | Core   | Function           |
| ---------- | ------ | ------------------ |
| `APEX_NET` | Core 0 | NAT + telemetry    |
| `APEX_DNS` | Core 1 | DNS captive portal |
| `APEX_CHK` | Core 1 | Internet check     |
| `loop()`   | Any    | WDT keepalive      |

---

## 🔁 Reboot Handling

* Stores reboot reason in NVS (`Preferences`)
* Possible states:

  * `Normal`
  * `APEX RPC REBOOT`
  * `Kernel Panic/WDT`

---

## ⚠️ Limitations

* Max ~8 clients (hardware constraint)
* NAT table size limited by ESP32 RAM
* No HTTPS (HTTP only dashboard)
* Not suitable for high-bandwidth environments

---

## 🧪 Stability Notes

* Designed for **low-power edge networking**
* Safe for **24/7 operation**
* Self-healing under:

  * Memory pressure
  * NAT overflow
  * Connection instability

---

## 📌 Future Improvements

* HTTPS dashboard (TLS)
* OTA firmware updates
* Bandwidth shaping / QoS
* Advanced firewall rules
* Multi-SSID support

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Developed as part of a **high-performance embedded networking experiment** on ESP32.
