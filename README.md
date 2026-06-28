# SniffPal

**Your network. Instantly understood.**

SniffPal is a local-first network intelligence tool. Drop in a packet capture and instantly see every device, what it is doing, who it is talking to, and whether anything looks suspicious. Everything runs in your browser. No uploads, no cloud, no backend.

## Live Demo

[kannanokannan.github.io/sniffpal](https://kannanokannan.github.io/sniffpal)

## What It Does

- **Device discovery** - identifies devices by vendor, hostname, mDNS, SSDP, LLMNR, and NetBIOS data
- **Protocol detection** - mDNS, SSDP, LLMNR, NetBIOS, MQTT, CoAP, DNS, HTTP, TLS SNI, and more
- **Security findings** - structured findings with IDs such as `PRIV_MDNS_001` and `IOT_TEL_001`
- **AI insights** - plain-English explanations via Chrome on-device AI or local fallback templates
- **Health Score** - 0-100 network security score with grade
- **Topology Map** - compact dashboard preview plus expandable connected-box map, device groups, click-to-inspect cards, and inferred gateway detection when the real router is not directly seen in the capture
- **Guest WiFi Privacy Report** - contextual report for captive portals, visible domains, clear HTTP, WPAD, and shared-LAN discovery
- **Pi live monitor** - capture progress, packet count, device count, protocol mix, CPU, RAM, temperature, uptime, local time, and live network I/O while the Pi is running
- **Band detection** - 2.4 GHz / 5 GHz / 6 GHz per device from monitor mode captures
- **PDF export** - full installer-style report with devices, findings, traffic, and recommendations
- **Zero upload** - capture data never leaves your machine

## How To Use (Web)

1. Capture packets using Wireshark or the included Python tool.
2. Export as JSON in Wireshark: `File -> Export Packet Dissections -> As JSON`.
3. Drop the file into SniffPal.

## Raspberry Pi Mode

SniffPal can also run as a self-contained Raspberry Pi network monitor.

The web and Pi experiences share one React codebase. Public sites such as `context-stack.org/sniffpal` and GitHub Pages show the PC file-upload version. Pi mode only activates on local Pi/LAN hosts such as `sniffpal.local`, private LAN IPs, or port `8080` loopback.

### Quick Start

```bash
git clone https://github.com/kannanokannan/sniffpal.git
cd sniffpal
bash pi/install.sh
cd pi && sudo python3 server.py
```

Open `http://sniffpal.local:8080`. SniffPal captures automatically every 10 minutes by default.

Packet capture needs raw network access on Linux, so start the Pi server with `sudo` or install it as a root-owned service.

### Pi Features

- Auto-capture on a schedule: 5 / 10 / 30 / 60 minutes
- Digest storage for the last 48 captures
- One-click manual capture
- Live capture progress with packets, devices, and protocols while capture is running
- Live Pi system metrics: CPU, RAM, temperature, uptime, local time, and network upload/download speed
- Capture mode switch: Standard mode for built-in Wi-Fi, Monitor mode for USB adapters with band detection
- Browser-based analysis; the Pi captures and serves data locally
- Topology map uses capture data to show device groups and gateway relationships

## Capture Tools

- **Wireshark** - GUI capture on any platform
- **`capture.py`** - managed mode capture; works on standard Pi Wi-Fi hardware
- **`capture_monitor.py`** - monitor mode capture; requires a compatible USB Wi-Fi adapter and adds Wi-Fi band data. Use the Pi settings panel to switch from Standard mode to Monitor mode.

```bash
cd scapy-capture-tool

# Managed mode
sudo python3 capture.py -i wlan0 -t 60

# Monitor mode with band detection
sudo airmon-ng start wlan1
sudo python3 capture_monitor.py -i wlan1mon -c 500
```

## Tech Stack

- React 18 + Vite 5.4.1
- Tailwind CSS v3
- Web Workers for off-thread parsing
- Flask + APScheduler for Pi mode
- Scapy for packet capture
- Chrome built-in AI and local template fallback for explanations

## Project Structure

```text
src/
  core/                shared parser, health score, AI, and geoip logic
  components/          React UI components
  utils/               web-only utilities
pi/                    Raspberry Pi server
scapy-capture-tool/    Python packet capture tools
```

## Roadmap

- [x] Device fingerprinting with mDNS, SSDP, LLMNR, and NetBIOS
- [x] IoT threat detection for cleartext MQTT and CoAP
- [x] AI insights with graceful local fallback
- [x] PDF export
- [x] Raspberry Pi mode
- [x] Network Topology Map with expandable connected-box layout and inferred gateway
- [x] Guest WiFi Privacy Report with compact entry point and slide-over detail view
- [x] Monitor mode capture with 2.4 / 5 / 6 GHz band detection
- [x] Pi live capture progress and system metrics
- [x] UPnP IGD AddPortMapping detection
- [ ] C2 beacon detection
- [ ] Historical baseline and trend view

## License

MIT
