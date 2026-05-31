#!/bin/bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_FILE="/etc/systemd/system/sniffpal.service"

echo "== SniffPal Pi deploy =="
echo "App: $APP_DIR"

echo "[1/5] Installing Python dependencies"
sudo pip3 install -r "$APP_DIR/pi/requirements.txt" --break-system-packages
sudo pip3 install scapy --break-system-packages

echo "[2/5] Installing web dependencies"
cd "$APP_DIR"
npm install

echo "[3/5] Building web app"
npm run build

echo "[4/5] Installing systemd service"
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=SniffPal Pi Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/pi/server.py
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

echo "[5/5] Starting service"
sudo systemctl daemon-reload
sudo systemctl enable sniffpal
sudo systemctl restart sniffpal
sudo systemctl --no-pager --full status sniffpal

echo
echo "SniffPal is running at:"
echo "  http://sniffpal.local:8080"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
