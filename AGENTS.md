# SniffPal - AI Context for Codex

## What This Is

SniffPal is a browser-based network packet analyser. It parses Wireshark JSON, pcap/pcapng, and scapy-capture-tool output locally. The core promise is simple: capture data stays on the user's machine.

Live: https://kannanokannan.github.io/sniffpal

## Key Files

| File | Role |
|---|---|
| `src/core/parser.worker.js` | Core engine. Packet parsing, device enrichment, threat detection, finding generation. Runs off-thread. |
| `src/core/geminiNano.js` | AI tier manager. Chrome on-device AI first, local fallback templates when unavailable. |
| `src/core/healthScore.js` | Computes the network Health Score from findings and alerts. |
| `src/core/geoip.js` | In-bundle IP geolocation. No API calls. |
| `src/utils/useSession.js` | Session state helper. Uses session storage patterns, not persistent sensitive storage. |
| `src/components/TopologyMap.jsx` | Clustered topology map with inferred gateway fallback and Wi-Fi band rings. |
| `pi/server.py` | Raspberry Pi monitor server. Captures on schedule and serves the built web app. |
| `scapy-capture-tool/` | Python capture tools for managed and monitor mode captures. |
| `pi/deploy.sh` | One-command Pi installer that builds the app and installs a root-owned systemd service. |

## Architecture

1. User drops a capture file, or Pi mode loads the latest digest.
2. The file is handed to `src/core/parser.worker.js` through a Web Worker.
3. The worker builds:
   - `devices` map
   - `enrichmentData` map
   - legacy `alerts`
   - structured `findings`
   - websites, trackers, protocols, traffic types, and capture metadata
4. The UI renders dashboards, device inventory, websites, security findings, topology, and reports.
5. AI explanations are optional and local-first. If AI is unavailable, template explanations are shown.

## Finding Structure

Every structured finding must follow this shape:

```js
{
  id: 'IOT_TEL_001',
  severity: 'critical',
  title: 'Short human-readable title',
  description: 'Self-contained explanation with device context, risk, and attacker impact.',
  device: mac,
  fix: 'Actionable fix for a non-technical user.',
  standard: 'RFC XXXX / Standard name',
}
```

## Finding ID Conventions

| Prefix | Domain |
|---|---|
| `PRIV_` | Privacy leaks such as device identity or service advertising |
| `INFO_` | Informational, low-risk observations |
| `SEC_` | Active security threats |
| `IOT_TEL_` | IoT cleartext telemetry |
| `IOT_UPNP_` | UPnP / IGD port punching |
| `IOT_C2_` | Direct-IP or command-and-control style behavior |
| `IOT_IGMP_` | IGMP and multicast manipulation |

## Implemented Findings

| ID | Trigger | Status |
|---|---|---|
| `PRIV_MDNS_001` | Device broadcasting hardware details over mDNS | Shipped |
| `INFO_MDNS_002` | Device advertising services over mDNS | Shipped |
| `PRIV_SSDP_001` | Device advertising details over UPnP/SSDP | Shipped |
| `INFO_NBNS_001` | Windows hostname exposed over NetBIOS | Shipped |
| `IOT_TEL_001` | Cleartext MQTT or CoAP telemetry | Shipped |
| `IOT_UPNP_002` | UPnP IGD AddPortMapping request | Shipped |

## Topology Notes

- The topology view uses `src/components/TopologyMap.jsx`.
- If a real `.1` gateway is present, it is used as the center node.
- If a router-like device is present, it is used as the gateway.
- If neither is present, SniffPal infers the subnet gateway as `.1` and marks it as inferred instead of incorrectly promoting the capture device or Pi.
- Monitor mode captures can add Wi-Fi band rings for 2.4 GHz, 5 GHz, and 6 GHz.
- ARP count-only floods are treated as noisy unless the same MAC claims more than one IP. This avoids flagging the Pi capture interface as MitM during normal local captures.

## Pi Mode

Pi mode is served by `pi/server.py`. The Pi captures locally and the browser still performs the analysis. Keep raw captures and digest files out of git.

Useful local endpoints:

- `GET /api/status`
- `POST /api/capture/start`
- `GET /api/capture/events`
- `GET /api/digests/latest`
- `GET /api/settings`
- `POST /api/settings`

`/api/status` includes live capture state, Pi identity, capture mode, temperature, uptime, local time, and optional `psutil` CPU/RAM/network counters.

Capture modes:

- `standard` runs `scapy-capture-tool/capture.py` against the normal interface, usually `wlan0`.
- `monitor` runs `scapy-capture-tool/capture_monitor.py` against the monitor interface, usually `wlan1mon`, and is only for compatible USB Wi-Fi adapters.

## Do Not

- Do not use persistent storage for sensitive capture data such as MACs, IPs, device names, credentials, or domains.
- Do not add external API calls for findings or enrichment.
- Do not upgrade Vite, Tailwind, React, or Recharts without an explicit migration task.
- Do not commit raw captures, digests, `.pcap`, `.pcapng`, or exported packet JSON.
- Do not add GPL or non-commercial tracker lists.
- Do not attempt CVE matching from guessed firmware strings.

## Deployment

GitHub Pages uses:

```bash
npm run build
npm run deploy
```

The Pi uses the built `dist/` folder served by Flask.
