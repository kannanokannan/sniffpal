#!/bin/bash
set -e

echo "================================================"
echo "  SniffPal Pi Server — Installation"
echo "================================================"
echo ""

# Install Python dependencies
echo "[1/4] Installing Python dependencies..."
sudo pip3 install flask apscheduler --break-system-packages

# Install scapy if not already present
echo "[2/4] Installing scapy..."
sudo pip3 install scapy --break-system-packages

# Build React app (requires Node.js + npm)
echo "[3/4] Building React app..."
cd "$(dirname "$0")/.."
if ! command -v npm &> /dev/null; then
    echo "  WARNING: npm not found. Skipping React build."
    echo "  Install Node.js first, then run: npm install && npm run build"
else
    npm install
    npm run build
    echo "  React app built successfully."
fi

# Create digests directory
echo "[4/4] Creating digests directory..."
mkdir -p "$(dirname "$0")/digests"

echo ""
echo "================================================"
echo "  ✅ SniffPal Pi server ready."
echo ""
echo "  To start:"
echo "    cd pi"
echo "    sudo python3 server.py"
echo ""
echo "  Then open:"
echo "    http://sniffpal.local:8080"
echo "    http://$(hostname -I | awk '{print $1}'):8080"
echo "================================================"
