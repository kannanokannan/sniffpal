# SniffPal — AI Context for Claude Code

## What this is
Browser-based network packet analyser. Parses Wireshark JSON or scapy-capture-tool output. 100% client-side — zero data leaves the machine. React + Vite, hosted on GitHub Pages.

Live: https://kannanokannan.github.io/sniffpal

---

## Key Files

| File | Role |
|------|------|
| `src/workers/parser.worker.js` | Core engine. All packet parsing, device enrichment, threat detection, finding generation. Runs off-thread. |
| `src/utils/geminiNano.js` | AI tier manager. Tier 1 = Gemini Nano v3 (Chrome on-device), Tier 2 = SmolLM2-360M via Transformers.js, Tier 3 = expert templates. |
| `src/utils/healthScore.js` | Computes the network Health Score from findings + alerts. |
| `src/utils/geoip.js` | In-bundle IP geolocation. No API calls. |
| `src/utils/useSession.js` | Session state hook. Uses sessionStorage (not localStorage — CodeQL requirement). |
| `src/components/` | UI components — DeviceCard, FindingCard, AlertBadge etc. |

---

## Architecture: How Parsing Works

1. User drops a Wireshark `.json` or scapy output file.
2. File is handed to `parser.worker.js` via Web Worker (off-thread, no UI freeze).
3. Worker parses every packet, builds:
   - `devices` map (MAC → device profile)
   - `enrichmentData` map (MAC → mDNS/SSDP/LLMNR/NetBIOS enrichment)
   - `securityAlerts` array (legacy alert format)
   - Protocol-specific Sets (`mqttUnencryptedDevices`, `coapUnencryptedDevices`, `upnpDevices`, etc.)
4. Worker calls `generateFindings()` → structured findings array with IDs.
5. Worker `postMessage`s everything to main thread.
6. AI tier in `geminiNano.js` generates plain-English insights per finding.

---

## Finding Structure

Every structured finding must follow this shape exactly:

```js
{
  id: 'IOT_TEL_001',          // Namespaced ID — see conventions below
  severity: 'critical',        // 'critical' | 'warning' | 'info'
  title: `"${label}" short description`,
  description: `Full explanation — what the risk is, who can exploit it, how.`,
  device: mac,                 // MAC address string
  fix: 'Actionable fix for a non-technical user.',
  standard: 'RFC XXXX / Standard name',
}
```

---

## Finding ID Conventions

| Prefix | Domain |
|--------|--------|
| `PRIV_` | Privacy leaks (device identity, service advertising) |
| `INFO_` | Informational, low risk |
| `SEC_` | Active security threats (ARP spoof, rogue DHCP, credentials) |
| `IOT_TEL_` | IoT cleartext telemetry |
| `IOT_UPNP_` | UPnP / IGD port punching |
| `IOT_C2_` | C2 beaconing / direct IP connections |
| `IOT_IGMP_` | IGMP flood / multicast manipulation |

---

## Implemented Findings (as of v2.1)

| ID | Trigger | Status |
|----|---------|--------|
| `PRIV_MDNS_001` | Device broadcasting hardware details via mDNS | ✅ Shipped |
| `INFO_MDNS_002` | Device advertising services via mDNS | ✅ Shipped |
| `PRIV_SSDP_001` | Device advertising via UPnP/SSDP | ✅ Shipped |
| `INFO_NBNS_001` | Windows hostname exposed via NetBIOS | ✅ Shipped |
| `IOT_TEL_001` | Cleartext MQTT (TCP 1883) or CoAP (UDP 5683) | ✅ Shipped |

### Security Alerts (legacy format, not structured findings)
`SEC_ARP_001` ARP spoofing, `SEC_DHCP_001` rogue DHCP, `SEC_CRED_001` cleartext credentials, ICMP redirect, DNS NXDOMAIN flood, TCP retransmissions, high latency, odd-hours traffic, foreign IP connections.

---

## Roadmap: Next Findings to Build

Priority order:

1. **`IOT_UPNP_002`** — IGD port punching. Detect HTTP POST to router IP containing SOAP `AddPortMapping`. SSDP (port 1900) already parsed.
2. **`IOT_C2_001` (Phase 1)** — No-DNS check. Build a Set of all IPs resolved via DNS in capture. Flag outbound connections to external IPs not in that Set. Whitelist NTP (UDP 123), mDNS (UDP 5353). Timing/periodicity analysis deferred to Pi v3.0.
3. **`IOT_IGMP_001`** — IGMP flood precursor. 50+ unique multicast group joins (use Set) in 5s from one MAC. Defer to Pi v3.0.
4. **`IOT_IGMP_002`** — Fail-open breach. Sustained high-bw multicast UDP arriving without IGMP Join from capture device. Only reliable on wired/router captures — fragile on Wi-Fi. Defer to Pi v3.0.

---

## How to Add a New Finding

1. Declare any needed tracking state (Set/Map) near line 160 in `parser.worker.js`.
2. Populate it in the packet loop (around line 430).
3. Pass it to `generateFindings()` — update both the call (line ~616) and the function signature.
4. Add the finding block inside `generateFindings()` following the structure above.
5. Update this file's findings table.

---

## AI Tiers (geminiNano.js)

| Tier | Condition | Engine |
|------|-----------|--------|
| 1 | Chrome 138+ with Gemini Nano v3 Ready | Chrome Summarizer + LanguageModel API (on-device) |
| 2 | Chrome without Nano | SmolLM2-360M-Instruct via Transformers.js (hf-mirror.com — HF blocked in India) |
| 3 | Any other browser | Expert template strings |

**Rule:** Never load Transformers.js before file upload.

---

## Do Not

- Use `localStorage` — CodeQL blocks it. Use `sessionStorage` via `useSession.js`.
- Add findings that require external API calls — breaks zero-upload privacy promise.
- Use DDG Tracker Radar (CC BY-NC-SA) or EasyPrivacy (GPLv3) — licensing risk.
- Attempt CVE matching — devices don't broadcast firmware versions reliably.
- Port nDPI to WASM — realistic timeline is 3-6+ months, not worth it.

---

## Deployment

GitHub Pages via `npm run build` → `dist/` → pushed to `gh-pages` branch.
scapy capture tool lives in `scapy-capture-tool/` — tested on Pi 500 / Linux.

---

## 🚀 Instructions for Claude Code: Push This Update to GitHub

These files are ready to be applied to the SniffPal repo and pushed.

### What to do

1. **Copy the files into the repo:**
   - `src/workers/parser.worker.js` → replace existing file at same path
   - `CLAUDE.md` → place at repo root (this file)

2. **Stage and commit:**
```bash
git add src/workers/parser.worker.js CLAUDE.md
git commit -m "feat: IOT_TEL_001 structured finding + CoAP detection + CLAUDE.md

- Add IOT_TEL_001 per-device structured finding for cleartext MQTT/CoAP telemetry
- Detect CoAP on UDP 5683 (alongside existing MQTT TCP 1883)
- generateFindings() now receives mqttUnencryptedDevices + coapUnencryptedDevices Sets
- Finding includes device label, protocol detail, actionable fix, NIST SP 800-213 ref
- Add CLAUDE.md: full AI context — architecture, finding conventions, roadmap, do-nots"
```

3. **Push to GitHub:**
```bash
git push origin main
```

If auth fails, use:
```bash
git remote set-url origin https://YOUR_GITHUB_TOKEN@github.com/kannanokannan/sniffpal.git
git push origin main
```

### What changed
| File | Change |
|------|--------|
| `src/workers/parser.worker.js` | Added `coapUnencryptedDevices` Set, CoAP port 5683 detection, `IOT_TEL_001` structured finding in `generateFindings()` |
| `CLAUDE.md` | New file — AI context for Claude Code |
