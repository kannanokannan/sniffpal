# SniffPal — Changelog

All notable changes to this project will be documented here. Format: [Semantic Versioning](https://semver.org)

---

## \[2.1.1\] — May 2026 (Current)

### Fixed

- SNI-extracted domains now correctly show HTTPS — were wrongly flagged as HTTP  
- HTTP warning badge only fires on explicit port 80 non-TLS traffic  
- Self-traffic no longer floods Sites Visited and Security Alerts  
- "Mark my device" button in Devices tab stores self IP to localStorage  
- Sites list hides own browsing by default when self IP is set  
- Security alerts move self-IP activity into a separate non-threat section  
- Info banner guides user to mark their device if not done yet

---

## \[2.1.0\] — May 2026

### Security Fixes

- MAC addresses now hashed with SHA-256 before storing in localStorage (CodeQL \#1)  
- Devices map changed to `Object.create(null)` \+ MAC regex validation (CodeQL \#4)

### New Features

- IoT detection — unencrypted MQTT (port 1883), UPnP/SSDP (port 1900\)  
- Odd-hours traffic detection — flags devices active between 2am–5am  
- mDNS device naming — extracts real device names from `_service._tcp.local` queries  
- Foreign IP detection — binary-search CIDR lookup for CN/RU/KP/IR with connection count  
- PDF installer report — Generate Report button using `window.print()`  
- Health score now correctly fires `mqtt_unencrypted` and `foreign_ip` hooks  
- Capture start/end timestamps added to result payload  
- Version bumped to v2.1 throughout UI

### Large File Fixes

- Removed `FileReader.readAsText()` on main thread — was blocking UI with no progress  
- File object now passed directly to worker — zero copy, no main-thread reading  
- Replaced full-file `JSON.parse()` with two-phase streaming parser  
  - Phase 1 — byte-level scan records packet offsets, reservoir-samples to 25,000  
  - Phase 2 — reads each sampled packet individually via `file.slice()`  
- Fixed `Invalid string length` V8 crash on large captures  
- "No file size limit" badge added to upload screen

---

## \[2.0.0\] — May 2026

### New Features

- Network health score — 0 to 100 with letter grade A through F  
- Session persistence via IndexedDB — resume last session on next open  
- Device trust/ignore system — mark devices as trusted, persisted per MAC  
- Search bar in device table  
- Data panel — click any chart element for detailed breakdown  
- PCAPdroid integration guide in upload screen  
- tshark CLI conversion commands with documentation links  
- Collapsible help section in file upload screen

---

## \[1.1.0\] — May 2026

### New Features

- Web Worker parser — UI never freezes regardless of file size  
- 500MB+ file support via smart packet sampling (max 25,000 packets)  
- Live progress bar during parsing  
- Privacy report sidebar with tracker breakdown (fuchsia theme)  
- Security alerts strip always visible at top of dashboard

---

## \[1.0.0\] — May 2026

### Initial Release

- Wireshark JSON file parser (drag and drop)  
- Device detection via MAC/OUI vendor lookup  
- Protocol breakdown pie chart  
- Top talkers bar chart  
- Website detection via TLS SNI extraction  
- Ad tracker detection — 25+ trackers including Google, Facebook, TikTok  
- ARP spoofing detection  
- Rogue DHCP server detection  
- ICMP redirect attack detection  
- Cleartext credential detection  
- DNS malware and DGA detection  
- TCP retransmission monitoring  
- Network latency RTT analysis  
- GitHub Pages deployment  
- Professional README and SECURITY.md

