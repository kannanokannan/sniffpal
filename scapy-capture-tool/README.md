# SniffPal Capture Tool

Capture network traffic on a Raspberry Pi (or any Linux box) and output a JSON file ready to drop straight into [SniffPal](https://kannanokannan.github.io/sniffpal).

No Wireshark needed.

---

## Prerequisites

```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install scapy
```

Or install from requirements.txt:

```bash
pip3 install -r requirements.txt
```

---

## Usage

### Basic — capture on default interface for 60 seconds
```bash
sudo python3 capture.py
```

### Specify interface and duration
```bash
sudo python3 capture.py -i wlan0 -t 120
```

### Specify interface, duration, and output filename
```bash
sudo python3 capture.py -i wlan0 -t 60 -o my-capture.json
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `-i` / `--interface` | auto (prefers wlan0) | Network interface to capture on |
| `-t` / `--timeout` | 60 | Capture duration in seconds |
| `-o` / `--output` | `sniffpal-capture-YYYYMMDD-HHMMSS.json` | Output filename |

---

## How to find your interface name

```bash
ip link show
```

Look for names like `wlan0` (Wi-Fi), `eth0` (wired), `wlan1` (USB adapter).

Example output:
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

---

## How to upload to SniffPal

1. Run the capture tool — a `.json` file is created in the current directory
2. Copy it to your laptop/desktop (via `scp`, USB, or any file transfer)
3. Open [kannanokannan.github.io/sniffpal](https://kannanokannan.github.io/sniffpal)
4. Drag and drop the `.json` file onto the upload area
5. Analysis appears instantly — devices, websites, security alerts, AI insights

### Copy file from Pi to laptop (example)
```bash
scp pi@raspberrypi.local:~/sniffpal-capture-*.json .
```

---

## Note: must run with sudo

Scapy requires raw socket access to capture packets. Always run with `sudo`:

```bash
sudo python3 capture.py
```

Without sudo you'll get: `Error: Permission denied. Run with sudo.`

---

## Stop early

Press `Ctrl+C` at any time — the tool saves whatever packets were captured so far and exits cleanly.

---

## Output format

The JSON output matches Wireshark's export format exactly — same `_source.layers` structure with dot-notation keys (`eth.src`, `ip.src`, `dns.qry.name` etc.) — so SniffPal's parser reads it without any changes.

Protocols captured: Ethernet, IP, IPv6, TCP, UDP, DNS, mDNS, DHCP, ARP, SSDP/UPnP, LLMNR, NetBIOS, MQTT, CoAP, IGMP, ICMP, TLS (SNI via port detection).
