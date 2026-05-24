# SniffPal

**Your network. Instantly understood.**

SniffPal is a local-first network intelligence tool. Drop in a packet capture and instantly see every device, what it's doing, who it's talking to, and whether anything looks suspicious — all in your browser, zero data uploaded.

## Live Demo
→ [kannanokannan.github.io/sniffpal](https://kannanokannan.github.io/sniffpal)

## What it does
- **Device discovery** — identifies every device by vendor, hostname, and protocols
- **Protocol detection** — mDNS, SSDP, LLMNR, NetBIOS, MQTT, CoAP
- **Security findings** — structured findings with IDs (PRIV_MDNS_001, IOT_TEL_001 etc.)
- **AI insights** — plain English analysis via Gemini Nano (Chrome) or local fallback
- **Health Score** — 0–100 network security score with grade
- **Topology Map** — SVG network map, clustered star layout (IoT / Mobile / Network / Computer), router auto-detected, animated data flow lines, colour-coded by Wi-Fi band (2.4 / 5 / 6 GHz), click-to-inspect any node
- **Band detection** — 2.4 GHz / 5 GHz / 6 GHz per device from monitor mode captures
- **PDF export** — full report with all devices, findings, traffic breakdown
- **Zero upload** — 100% client-side, your data never leaves your browser

## How to use (Web)
1. Capture packets using Wireshark or the included Python tool
2. Export as JSON (Wireshark: File → Export Packet Dissections → As JSON)
3. Drop the file into SniffPal

## Raspberry Pi Mode
SniffPal runs as a self-contained network monitor on any Raspberry Pi.

### Quick start
```bash
git clone https://github.com/kannanokannan/sniffpal.git
cd sniffpal
bash pi/install.sh
cd pi && sudo python3 server.py
```

Open `http://sniffpal.local:8080` — SniffPal captures automatically every 10 minutes.

### Pi features
- Auto-capture on a schedule (configurable: 5 / 10 / 30 / 60 min)
- Digest storage — keeps last 48 captures (raw deleted after processing)
- One-click manual capture
- All analysis runs in the browser — Pi just captures and serves

## Capture tools
- **Wireshark** — GUI, any platform
- **`capture.py`** — managed mode, works on all hardware (default for Pi auto-capture)
- **`capture_monitor.py`** — monitor mode, requires compatible USB Wi-Fi adapter; captures band data (2.4 / 5 / 6 GHz) per device

```bash
cd scapy-capture-tool

# Managed mode (standard)
sudo python3 capture.py -i wlan0 -t 60

# Monitor mode (band detection)
sudo airmon-ng start wlan1
sudo python3 capture_monitor.py -i wlan1mon -c 500
```

## Tech stack
- React 18 + Vite 5.4.1
- Tailwind CSS v3
- Web Workers (off-thread parsing)
- Flask + APScheduler (Pi server)
- Scapy (packet capture)

## Project structure
```
src/
  core/          # shared logic (parser, healthScore, AI, geoip)
  components/    # React UI components
  utils/         # web-only utilities
pi/              # Raspberry Pi server
scapy-capture-tool/  # Python packet capture
```

## Roadmap
- [x] Device fingerprinting (mDNS/SSDP/LLMNR/NetBIOS)
- [x] IoT threat detection (MQTT cleartext)
- [x] AI insights (Gemini Nano + local fallback)
- [x] PDF export
- [x] Raspberry Pi mode
- [x] Network Topology Map (SVG, band-aware)
- [x] Monitor mode capture + 2.4/5/6 GHz band detection
- [ ] UPnP IGD detection
- [ ] C2 beacon detection
- [ ] Docker image
- [ ] Historical baseline + trend view

## License
MIT
