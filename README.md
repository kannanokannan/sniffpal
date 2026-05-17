# 🔍 SniffPal — Network Intelligence Tool

> Like Chrome DevTools — but for your **entire network**.  
> Drop a Wireshark file. Instantly understand every device, 
> website visited, and security threat.  
> **100% local. Zero uploads. Zero servers. AI-powered.**

![Version](https://img.shields.io/badge/version-2.0.0-cyan)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Built With](https://img.shields.io/badge/built%20with-React%20%2B%20Vite-purple)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

---

## ✨ What Is SniffPal?

Most network tools are built for experts. SniffPal is different.

Drop a Wireshark capture file and get an **instant visual breakdown** of:
- Every device — not just a MAC address, but **"Sony Bravia TV 
  running tvOS"** via mDNS/SSDP enrichment
- Every website visited — even HTTPS (via TLS SNI)
- Who is tracking you (Google Analytics, Facebook Pixel, TikTok...)
- Security threats: ARP spoofing, rogue DHCP, ICMP redirects, 
  cleartext credentials
- Privacy risks: devices leaking model names, firmware versions, 
  service lists over the local network
- **AI-powered plain English explanations** of every finding — 
  no jargon

No installation of servers. No data leaves your machine. Ever.

---

## 🚀 Live Demo

👉 **[kannanokannan.github.io/sniffpal](https://kannanokannan.github.io/sniffpal)**

---

## 📸 What You See

### Overview Tab
- Protocol breakdown pie chart
- Top talkers bar chart
- Traffic type distribution (streaming, gaming, browsing, chat/API)

### Devices Tab
- Enriched device cards: **real device names** from mDNS, SSDP, 
  NetBIOS, LLMNR
- Manufacturer, model, OS hints where available
- Protocol source badges: mDNS · SSDP · LLMNR · NetBIOS
- IP addresses with full IPv6 support
- Per-device bandwidth and activity bars

### Websites Tab
- All domains visited on your network
- HTTPS vs HTTP badge
- Tracker detection (~25 known tracker domains)

### Security Tab
- ARP Spoofing detection
- Rogue DHCP server detection
- ICMP Redirect attack detection
- Cleartext credential exposure
- UPnP/SSDP active device warnings
- DNS health + NXDOMAIN rate
- TCP retransmission analysis
- **AI Insights** — plain English explanation of every finding

---

## 🛠️ How To Use

### Step 1 — Capture Traffic in Wireshark
Open Wireshark and capture on your network interface.

### Step 2 — Export as JSON
```
File → Export Packet Dissections → As JSON
```

### Step 3 — Drop into SniffPal
Drag and drop the JSON file. Results appear instantly.

### Step 4 — Read AI Insights
Chrome 138+ with Gemini Nano automatically explains every finding 
in plain English. Falls back to SmolLM2 or expert templates on 
other setups.

---

## 🔍 What SniffPal Detects

### Devices
| Feature | How |
|---|---|
| MAC Address | Ethernet layer |
| Vendor / Brand | OUI MAC prefix lookup |
| Device Name | mDNS PTR/TXT records, NetBIOS broadcasts |
| Device Type | SSDP SERVER header, mDNS service type |
| Manufacturer / Model | SSDP UPnP advertisement strings |
| OS / Firmware hint | mDNS TXT records, SSDP version strings |
| Active Services | mDNS SRV records (AirPlay, Google Cast...) |
| IP Address | IP/IPv6 layer |
| Hostname | DHCP options, LLMNR, NetBIOS |
| Bandwidth used | Frame length accumulation |

### Websites
| Feature | How |
|---|---|
| HTTPS sites | TLS SNI handshake extraction |
| HTTP sites | HTTP Host header |
| DNS queries | DNS query name field |
| Failed lookups | NXDOMAIN response code |
| Tracker detection | Domain blocklist matching |

### Security & Privacy Findings
| ID | Threat | Detection |
|---|---|---|
| SEC_ARP_001 | ARP Spoofing | MAC claiming multiple IPs |
| SEC_DHCP_001 | Rogue DHCP | Multiple DHCP offer sources |
| SEC_ICMP_001 | ICMP Redirect | ICMP type 5 packets |
| SEC_CRED_001 | Cleartext Passwords | HTTP Auth + FTP USER/PASS |
| PRIV_MDNS_001 | Device name leak via mDNS | mDNS PTR/TXT broadcast |
| PRIV_SSDP_001 | Model/firmware leak via SSDP | UPnP advertisement |
| INFO_NBNS_001 | Windows hostname broadcast | NetBIOS name service |
| INFO_MDNS_002 | Active service advertisement | mDNS SRV records |
| SEC_DNS_001 | DNS malware/DGA activity | High NXDOMAIN rate |
| SEC_TCP_001 | TCP connection problems | Retransmission + RTT |

---

## 🤖 AI Insights

Plain English explanations of every finding. No jargon.

| Tier | Condition | Model |
|---|---|---|
| 1st | Chrome 138+, 4GB+ VRAM or 16GB+ RAM | Gemini Nano v3 (on-device) |
| 2nd | Chrome without sufficient hardware | SmolLM2-360M via Transformers.js |
| Fallback | Any browser | Expert-written templates |

Zero data leaves your device in all three cases.

---

## 💻 Run Locally

```bash
git clone https://github.com/kannanokannan/sniffpal.git
cd sniffpal
npm install
npm run dev
# Open http://localhost:5173
```

### Requirements
- Node.js 18+
- Chrome 138+ recommended for AI Insights
- Any modern browser for core features

---

## 🏗️ Tech Stack

| Tool | Purpose |
|---|---|
| React + Vite | Frontend framework |
| Tailwind CSS | Styling |
| Recharts | Charts and visualizations |
| Lucide React | Icons |
| Web Worker | Off-thread packet parsing |
| IndexedDB | Client-side session storage |
| Browser FileReader API | Local file parsing |
| Chrome Summarizer API | Session summary via Gemini Nano |
| Chrome LanguageModel API | Per-finding explanations via Gemini Nano |
| @huggingface/transformers | SmolLM2-360M local fallback |

**Zero backend. Zero database. Zero API keys required.**

---

## 📁 Project Structure
```
sniffpal/
├── src/
│   ├── components/
│   │   ├── FileUpload.jsx        # Drag & drop file input
│   │   ├── SummaryCards.jsx      # Top stats cards
│   │   ├── ProtocolChart.jsx     # Pie + bar charts
│   │   ├── DeviceTable.jsx       # Device explorer + enriched cards
│   │   ├── WebsitesTab.jsx       # Sites + tracker detection
│   │   └── SecurityTab.jsx       # Security alerts + AI Insights
│   ├── workers/
│   │   └── parser.worker.js      # Wireshark JSON parser (Web Worker)
│   ├── utils/
│   │   └── geminiNano.js         # Chrome AI + Transformers.js layer
│   └── App.jsx                   # Main app + tab routing
├── public/
├── package.json
└── README.md
```

---

## 🗺️ Roadmap

### Version 1.0 ✅
- [x] Device detection with vendor lookup
- [x] Protocol breakdown charts
- [x] Top talkers visualization
- [x] Website detection via TLS SNI + DNS
- [x] Tracker / advertiser detection
- [x] ARP spoofing detection
- [x] Rogue DHCP detection
- [x] ICMP redirect detection
- [x] Cleartext credential detection
- [x] DNS health analysis
- [x] TCP retransmission analysis
- [x] Network health score (0–100)

### Version 2.0 ✅ (Current)
- [x] mDNS enrichment — real device names from broadcasts
- [x] SSDP/UPnP enrichment — manufacturer, model, firmware
- [x] LLMNR + NetBIOS hostname parsing
- [x] Structured privacy findings with IDs
- [x] Protocol source badges on device cards
- [x] AI Insights — Gemini Nano v3 integration
- [x] AI fallback — SmolLM2-360M via Transformers.js
- [x] Expert template fallback for all browsers
- [x] Security fix — localStorage to sessionStorage
- [x] IPv6 address truncation fix

### Version 3.0 (Planned)
- [ ] Raspberry Pi disk image — whole-LAN monitoring
- [ ] Python packet capture — drop Wireshark dependency
- [ ] Live capture integration
- [ ] Export report as PDF
- [ ] Device uptime and historical baseline tracking
- [ ] Android app via VpnService API

---

## 🤝 Contributing

```bash
git checkout -b feature/your-feature
git commit -m "Add: your feature"
git push origin feature/your-feature
# Open a Pull Request
```

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

Built by [@kannanokannan](https://github.com/kannanokannan)  
Photography: [@archer_ztudios](https://instagram.com/archerztudios)

---

[![GitHub stars](https://img.shields.io/github/stars/kannanokannan/sniffpal?style=social)](https://github.com/kannanokannan/sniffpal)
