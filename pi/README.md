# SniffPal Pi Server

Run SniffPal as a whole-LAN monitor on a Raspberry Pi. Captures traffic every 30 minutes, keeps 24 hours of history (48 digests), and serves the full SniffPal dashboard locally.

---

## Prerequisites

- Raspberry Pi (any model with Wi-Fi) running Raspberry Pi OS / Debian
- Python 3.9+
- Node.js 18+ (for building the React app)

---

## Installation

```bash
cd pi
chmod +x install.sh
./install.sh
```

This will:
1. Install Flask + APScheduler via pip
2. Install scapy
3. Build the React app into `../dist/`
4. Create the `digests/` directory

---

## How to Run

```bash
cd pi
sudo python3 server.py
```

The server starts on port 8080 and is accessible at:
- `http://sniffpal.local:8080`
- `http://<your-pi-ip>:8080`

---

## How Scheduled Capture Works

Once started, the server automatically captures network traffic for **30 minutes** every 30 minutes using `scapy-capture-tool/capture.py`.

- Captures run on `wlan0` by default
- Each capture is saved as a digest in `pi/digests/`
- A maximum of **48 digests** (24 hours) are kept — oldest are deleted automatically
- Raw capture files are deleted after the digest is saved

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the SniffPal React dashboard |
| `/api/status` | GET | Server status + digest count |
| `/api/digests` | GET | List all stored digests (summary only) |
| `/api/digests/latest` | GET | Full latest digest (for SniffPal parser) |
| `/api/digests/<file>` | GET | Specific digest by filename |
| `/api/capture/start` | POST | Trigger a manual capture immediately |

---

## How to Change Capture Interval

Edit `server.py` and find this line:

```python
scheduler.add_job(run_capture, 'interval', minutes=30, id='scheduled_capture')
```

Change `minutes=30` to your preferred interval.

---

## How to Change the Network Interface

Edit `server.py` and find the `run_capture()` function:

```python
subprocess.run(
    ['sudo', 'python3', capture_script,
     '-i', 'wlan0', '-t', '1800', '-o', raw_path],
```

Change `'wlan0'` to your interface (e.g. `'eth0'`). Find your interface with:

```bash
ip link show
```

---

## Run as a Service (Auto-start on Boot)

Create `/etc/systemd/system/sniffpal.service`:

```ini
[Unit]
Description=SniffPal Pi Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/sniffpal/pi/server.py
WorkingDirectory=/home/pi/sniffpal/pi
User=root
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable it:

```bash
sudo systemctl enable sniffpal
sudo systemctl start sniffpal
```
