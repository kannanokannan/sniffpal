#!/usr/bin/env python3
"""
SniffPal Capture Tool
Captures network traffic and outputs Wireshark-compatible JSON
for upload to kannanokannan.github.io/sniffpal

Usage:
    sudo python3 capture.py
    sudo python3 capture.py -i wlan0 -t 120
    sudo python3 capture.py -i wlan0 -t 60 -o out.json
"""

import argparse
import json
import os
import sys
import signal
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.dhcp import DHCP, BOOTP
except ImportError:
    print("Error: scapy is not installed. Run: pip3 install scapy")
    sys.exit(1)


# ── Global packet store (allows KeyboardInterrupt save) ──────────────────────
captured_packets = []
capture_done = False
seen_devices = set()
protocol_counts = Counter()


def get_default_interface():
    """Auto-detect network interface, prefer wlan0."""
    preferred = ['wlan0', 'eth0', 'en0', 'ens33', 'enp0s3']
    available = get_if_list()
    for iface in preferred:
        if iface in available:
            return iface
    # Return first non-loopback interface
    for iface in available:
        if iface != 'lo':
            return iface
    return conf.iface


def safe_str(val):
    """Convert bytes or any value to a clean string."""
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8', errors='replace').rstrip('\x00').strip()
        except Exception:
            return val.hex()
    return str(val) if val is not None else ''


def extract_dns_layer(pkt):
    """Extract DNS fields into Wireshark-style dict."""
    dns_layer = {}
    try:
        dns = pkt[DNS]
        dns_layer['dns.flags.response'] = str(dns.qr)
        dns_layer['dns.flags.rcode']    = str(dns.rcode)

        # Question section
        if dns.qdcount > 0 and dns.qd:
            qname = safe_str(dns.qd.qname)
            if qname.endswith('.'):
                qname = qname[:-1]
            dns_layer['dns.qry.name'] = qname

        # Answer section
        if dns.ancount > 0 and dns.an:
            an = dns.an
            rrname = safe_str(an.rrname)
            if rrname.endswith('.'):
                rrname = rrname[:-1]
            dns_layer['dns.resp.name'] = rrname
            if hasattr(an, 'rdata'):
                dns_layer['dns.resp.addr'] = safe_str(an.rdata)

    except Exception:
        pass
    return dns_layer


def extract_dhcp_layer(pkt):
    """Extract DHCP/BOOTP options into Wireshark-style dict."""
    dhcp_layer = {}
    try:
        if BOOTP in pkt:
            bootp = pkt[BOOTP]
            # DHCP options
            if DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple):
                        name, val = opt[0], opt[1] if len(opt) > 1 else None
                        if name == 'message-type' and val is not None:
                            dhcp_layer['dhcp.option.dhcp'] = str(int(val))
                        elif name == 'hostname' and val is not None:
                            dhcp_layer['dhcp.option.hostname'] = safe_str(val)
                        elif name == 'vendor_class_id' and val is not None:
                            dhcp_layer['dhcp.option.vendor_class_id'] = safe_str(val)
    except Exception:
        pass
    return dhcp_layer


def packet_to_wireshark(pkt, pkt_num):
    """Convert a Scapy packet to Wireshark JSON layer format."""
    layers = {}

    try:
        # ── frame ──────────────────────────────────────────────────────────
        ts = float(pkt.time)
        dt = datetime.fromtimestamp(ts)
        layers['frame'] = {
            'frame.number':     str(pkt_num),
            'frame.time':       dt.strftime('%b %d, %Y %H:%M:%S.%f000 IST'),
            'frame.time_epoch': f'{ts:.6f}',
            'frame.len':        str(len(pkt)),
        }

        # ── Ethernet ───────────────────────────────────────────────────────
        if Ether in pkt:
            eth = pkt[Ether]
            layers['eth'] = {
                'eth.src': eth.src,
                'eth.dst': eth.dst,
            }

        # ── ARP ────────────────────────────────────────────────────────────
        if ARP in pkt:
            arp = pkt[ARP]
            layers['arp'] = {
                'arp.opcode':         str(arp.op),
                'arp.src.hw_mac':     arp.hwsrc,
                'arp.src.proto_ipv4': arp.psrc,
                'arp.dst.hw_mac':     arp.hwdst,
                'arp.dst.proto_ipv4': arp.pdst,
            }

        # ── IP ─────────────────────────────────────────────────────────────
        if IP in pkt:
            ip = pkt[IP]
            layers['ip'] = {
                'ip.src':   ip.src,
                'ip.dst':   ip.dst,
                'ip.proto': str(ip.proto),
                'ip.ttl':   str(ip.ttl),
            }

        # ── IPv6 ───────────────────────────────────────────────────────────
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            layers['ipv6'] = {
                'ipv6.src': ip6.src,
                'ipv6.dst': ip6.dst,
                'ipv6.nxt': str(ip6.nh),
            }

        # ── ICMP ───────────────────────────────────────────────────────────
        if ICMP in pkt:
            icmp = pkt[ICMP]
            layers['icmp'] = {
                'icmp.type': str(icmp.type),
                'icmp.code': str(icmp.code),
            }

        # ── TCP ────────────────────────────────────────────────────────────
        if TCP in pkt:
            tcp = pkt[TCP]
            layers['tcp'] = {
                'tcp.srcport': str(tcp.sport),
                'tcp.dstport': str(tcp.dport),
                'tcp.flags':   str(tcp.flags),
            }
            # TLS hint (port 443/8443)
            if tcp.dport in (443, 8443) or tcp.sport in (443, 8443):
                layers['tls'] = {}

            # HTTP hint (port 80)
            if tcp.dport == 80 or tcp.sport == 80:
                layers['http'] = {}

            # MQTT (port 1883) — flag presence
            if tcp.dport == 1883 or tcp.sport == 1883:
                try:
                    raw_payload = bytes(tcp.payload)
                    if raw_payload:
                        layers['mqtt'] = {'mqtt.raw': raw_payload[:256].hex()}
                except Exception:
                    layers['mqtt'] = {}

        # ── UDP ────────────────────────────────────────────────────────────
        if UDP in pkt:
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            layers['udp'] = {
                'udp.srcport': str(sport),
                'udp.dstport': str(dport),
                'udp.length':  str(udp.len),
            }

            # DNS / mDNS (53, 5353) / LLMNR (5355)
            if DNS in pkt:
                if sport in (53, 5353, 5355) or dport in (53, 5353, 5355):
                    dns_fields = extract_dns_layer(pkt)
                    if dns_fields:
                        layers['dns'] = dns_fields

            # DHCP (67/68)
            if sport in (67, 68) or dport in (67, 68):
                dhcp_fields = extract_dhcp_layer(pkt)
                if dhcp_fields:
                    layers['bootp'] = dhcp_fields

            # SSDP / UPnP (1900)
            if sport == 1900 or dport == 1900:
                try:
                    raw_payload = bytes(udp.payload)
                    text = raw_payload.decode('utf-8', errors='replace')
                    ssdp = {'ssdp.raw': text[:1024]}
                    # Parse common SSDP headers into dot-notation
                    for line in text.splitlines():
                        if ':' in line:
                            key, _, val = line.partition(':')
                            key_l = key.strip().lower()
                            val = val.strip()
                            if key_l == 'server':
                                ssdp['ssdp.server'] = val
                            elif key_l == 'location':
                                ssdp['ssdp.location'] = val
                            elif key_l == 'usn':
                                ssdp['ssdp.usn'] = val
                            elif key_l in ('nt', 'st'):
                                ssdp['ssdp.nt'] = val
                    layers['ssdp'] = ssdp
                except Exception:
                    pass

            # NetBIOS (137)
            if sport == 137 or dport == 137:
                try:
                    raw_payload = bytes(udp.payload)
                    layers['nbns'] = {'nbns.raw': raw_payload[:256].hex()}
                except Exception:
                    pass

            # LLMNR (5355) — raw if DNS layer didn't parse
            if (sport == 5355 or dport == 5355) and 'dns' not in layers:
                try:
                    raw_payload = bytes(udp.payload)
                    layers['llmnr'] = {'llmnr.raw': raw_payload[:256].hex()}
                except Exception:
                    pass

            # CoAP (5683) — flag presence
            if sport == 5683 or dport == 5683:
                try:
                    raw_payload = bytes(udp.payload)
                    if raw_payload:
                        layers['coap'] = {'coap.raw': raw_payload[:256].hex()}
                except Exception:
                    layers['coap'] = {}

            # IGMP (IP proto 2) — already handled via IP layer proto field
            # but add explicit marker if detected
            if IP in pkt and pkt[IP].proto == 2:
                try:
                    layers['igmp'] = {'igmp.type': str(pkt[IP].payload.type)
                                      if hasattr(pkt[IP].payload, 'type') else ''}
                except Exception:
                    layers['igmp'] = {}

    except Exception:
        pass  # Skip packets that fail to parse entirely

    return {'_source': {'layers': layers}}


def detect_protocol(pkt):
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if sport == 80 or dport == 80:
            return 'HTTP'
        if sport in (443, 8443) or dport in (443, 8443):
            return 'TLS'
        if sport == 1883 or dport == 1883:
            return 'MQTT'
        return 'TCP'
    if UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if sport in (53, 5353, 5355) or dport in (53, 5353, 5355):
            return 'DNS'
        if sport == 1900 or dport == 1900:
            return 'SSDP'
        if sport == 5683 or dport == 5683:
            return 'CoAP'
        return 'UDP'
    if ARP in pkt:
        return 'ARP'
    if ICMP in pkt:
        return 'ICMP'
    return 'Other'


def packet_handler(pkt):
    """Called by Scapy for each captured packet."""
    global captured_packets, seen_devices, protocol_counts
    pkt_num = len(captured_packets) + 1
    try:
        entry = packet_to_wireshark(pkt, pkt_num)
        captured_packets.append(entry)
        if Ether in pkt:
            if pkt[Ether].src:
                seen_devices.add(pkt[Ether].src)
            if pkt[Ether].dst:
                seen_devices.add(pkt[Ether].dst)
        protocol_counts[detect_protocol(pkt)] += 1
        if pkt_num % 50 == 0:
            print(
                'SNIFFPAL_PROGRESS ' + json.dumps({
                    'packets': pkt_num,
                    'devices': len(seen_devices),
                    'protocols': dict(protocol_counts.most_common(6)),
                }),
                flush=True,
            )
    except Exception:
        pass  # Never crash the capture loop


def save_output(output_file):
    """Write captured packets to JSON file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(captured_packets, f, separators=(',', ':'))
    print(f'\nCaptured {len(captured_packets)} packets → {output_file}')


def main():
    parser = argparse.ArgumentParser(
        description='SniffPal Capture Tool — capture network traffic for SniffPal analysis'
    )
    parser.add_argument('-i', '--interface', default=None,
                        help='Network interface (default: auto-detect, prefer wlan0)')
    parser.add_argument('-t', '--timeout', type=int, default=60,
                        help='Capture duration in seconds (default: 60)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output filename (default: sniffpal-capture-YYYYMMDD-HHMMSS.json)')
    args = parser.parse_args()

    # Resolve interface
    iface = args.interface or get_default_interface()

    # Resolve output filename
    if args.output:
        output_file = args.output
    else:
        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        output_file = f'sniffpal-capture-{ts}.json'

    print(f'Capturing on {iface}... ({args.timeout}s)')
    print(f'Output: {output_file}')
    print('Press Ctrl+C to stop early and save.\n')

    # Handle Ctrl+C — save what we have
    def handle_interrupt(sig, frame):
        print('\nInterrupted — saving partial capture...')
        save_output(output_file)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    try:
        sniff(
            iface=iface,
            prn=packet_handler,
            timeout=args.timeout,
            store=False,  # don't store in Scapy — we store in our list
        )
    except PermissionError:
        print('Error: Permission denied. Run with sudo.')
        sys.exit(1)
    except Exception as e:
        print(f'Error during capture: {e}')
        if captured_packets:
            print('Saving partial capture...')
            save_output(output_file)
        sys.exit(1)

    save_output(output_file)


if __name__ == '__main__':
    main()
