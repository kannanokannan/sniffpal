#!/usr/bin/env python3
"""
SniffPal Monitor Mode Capture
Captures raw 802.11 frames including Radiotap header for band detection.

Prerequisites:
  - Wi-Fi adapter that supports monitor mode (NOT Pi's built-in wlan0 reliably)
  - Enable monitor mode first: sudo airmon-ng start wlan1
  - Run: sudo python3 capture_monitor.py -i wlan1mon -c 500
"""

import argparse
import json
import time
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, RadioTap
except ImportError:
    print("Error: scapy is not installed. Run: sudo pip3 install scapy --break-system-packages")
    exit(1)

sniffpal_buffer = []

def get_band(freq):
    if not freq:
        return "Unknown"
    if 2400 <= freq < 2500:
        return "2.4 GHz"
    elif 5000 <= freq < 5900:
        return "5 GHz"
    elif freq >= 5900:
        return "6 GHz"
    return "Unknown"

def process_packet(packet):
    if not (packet.haslayer(RadioTap) and packet.haslayer(Dot11)):
        return
    try:
        freq = packet[RadioTap].Channel
        band = get_band(freq)
        src_mac = packet[Dot11].addr2
        dst_mac = packet[Dot11].addr1

        if not src_mac or not dst_mac:
            return

        packet_data = {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.time_epoch": str(time.time()),
                        "frame.time": datetime.now().strftime("%b %d, %Y %H:%M:%S.%f IST"),
                        "frame.len": str(len(packet))
                    },
                    "wlan": {
                        "wlan.sa": src_mac,
                        "wlan.da": dst_mac,
                        "wlan.ta": src_mac,
                        "wlan.ra": dst_mac,
                        "wlan.fc.type_subtype": str(packet[Dot11].subtype)
                    },
                    "radiotap": {
                        "radiotap.channel.freq": str(freq) if freq else "",
                        "sniffpal.injected_band": band
                    }
                }
            }
        }
        sniffpal_buffer.append(packet_data)
        print(f"  {src_mac} → {dst_mac} | {band} ({freq} MHz)")

    except (AttributeError, TypeError):
        pass

def main():
    parser = argparse.ArgumentParser(description="SniffPal Monitor Mode Capture")
    parser.add_argument("-i", "--interface", default="wlan0mon", help="Monitor mode interface (default: wlan0mon)")
    parser.add_argument("-c", "--count", type=int, default=500, help="Packet count (default: 500)")
    parser.add_argument("-o", "--output", default=None, help="Output filename")
    args = parser.parse_args()

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = args.output or f"sniffpal-monitor-{ts}.json"

    print(f"SniffPal Monitor Mode Capture")
    print(f"Interface : {args.interface}")
    print(f"Packets   : {args.count}")
    print(f"Output    : {output_file}")
    print(f"{'─' * 50}")
    print("NOTE: Ensure interface is in monitor mode first:")
    print("  sudo airmon-ng start wlan1")
    print(f"{'─' * 50}\n")

    try:
        sniff(iface=args.interface, prn=process_packet, count=args.count)
    except KeyboardInterrupt:
        print("\nStopped early — saving captured packets...")
    except Exception as e:
        print(f"Error: {e}")
        print("Is the interface in monitor mode? Try: sudo airmon-ng start wlan1")

    with open(output_file, "w") as f:
        json.dump(sniffpal_buffer, f, indent=2)

    print(f"\nCaptured {len(sniffpal_buffer)} packets → {output_file}")
    print("Upload to SniffPal to view band-aware device analysis.")

if __name__ == "__main__":
    main()
