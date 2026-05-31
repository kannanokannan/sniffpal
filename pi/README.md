# SniffPal Pi Server

Run SniffPal as a local Raspberry Pi network monitor. The Pi captures traffic, stores recent digests, and serves the browser dashboard at `http://sniffpal.local:8080`.

## Quick Install

```bash
cd ~/sniffpal
bash pi/deploy.sh
```

The deploy script installs Python dependencies, builds the React app, creates a root-owned `sniffpal` systemd service, and starts it.

## Dashboard

Open:

```text
http://sniffpal.local:8080
```

The Pi Monitor screen shows:

- capture status
- stored digest count
- selected capture mode
- capture interface
- packet/device/protocol progress during capture
- CPU, RAM, temperature, uptime, Pi local time, and live network upload/download speed

## Capture Modes

### Standard Mode

Default mode. Uses `scapy-capture-tool/capture.py`.

- Works with the Pi built-in Wi-Fi interface, usually `wlan0`
- Captures devices, traffic, websites, alerts, and topology
- Does not include 2.4 / 5 / 6 GHz band metadata

### Monitor Mode

Uses `scapy-capture-tool/capture_monitor.py`.

- Requires a compatible USB Wi-Fi adapter
- Interface is usually something like `wlan1mon`
- Adds Wi-Fi band metadata for topology rings
- Does not replace Standard mode for full traffic analysis; it is best used for band/topology enrichment

Enable monitor mode first:

```bash
sudo airmon-ng start wlan1
```

Then choose `Monitor` in the Pi settings panel and set the interface to `wlan1mon`.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the SniffPal dashboard |
| `/api/status` | GET | Server status, settings, capture state, Pi identity, and system metrics |
| `/api/capture/start` | POST | Starts a manual capture |
| `/api/capture/events` | GET | Live capture event stream |
| `/api/digests` | GET | Lists stored digests |
| `/api/digests/latest` | GET | Returns the latest digest |
| `/api/settings` | GET/POST | Reads or saves capture settings |

## Service Commands

```bash
sudo systemctl status sniffpal
sudo systemctl restart sniffpal
sudo journalctl -u sniffpal -f
```

## Notes

- Packet capture requires root access.
- Raw captures are temporary; saved digest JSON files live in `pi/digests/`.
- Keep `pi/digests/` out of git.
