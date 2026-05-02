# 🔍 SniffPal — Network Intelligence Tool

> Like Chrome DevTools — but for your **entire network**.  
> Drop a Wireshark file. Instantly understand every device, website visited, and security threat.  
> **100% local. Zero uploads. Zero servers.**

![Version](https://img.shields.io/badge/version-1.0.0-cyan)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Built With](https://img.shields.io/badge/built%20with-React%20%2B%20Vite-purple)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

---

## ✨ What Is SniffPal?

Most network tools are built for experts. SniffPal is different.

Drop a Wireshark capture file and get an **instant visual breakdown** of:
- Every device on your network with vendor detection
- Every website visited — even HTTPS (via SNI)
- Who is tracking you (Google Analytics, Facebook Pixel, etc.)
- Security threats: ARP spoofing, rogue DHCP, ICMP redirects
- Traffic types: streaming, gaming, video calls, browsing

No installation of servers. No data leaves your machine. Ever.

---

## 🚀 Live Demo

👉 **[sniffpal.netlify.app](https://sniffpal.netlify.app)** *(coming soon)*

---

## 📸 Screenshots

### Overview Tab
- Protocol breakdown pie chart
- Top talkers bar chart
- Traffic type distribution

### Devices Tab
- Device icons based on vendor (🍎 Apple, 📡 Netgear, 📦 Amazon...)
- IP addresses + hostnames
- Per-device bandwidth and activity bars

### Websites Tab
- All domains visited on your network
- HTTPS vs HTTP badge
- 👁️ Tracker detection (Google Analytics, Facebook Pixel, TikTok, Hotjar...)

### Security Tab
- 🔴 ARP Spoofing detection
- 🔴 Rogue DHCP server detection
- 🔴 ICMP Redirect attack detection
- 🔴 Cleartext credential exposure
- 🟡 DNS health + NXDOMAIN rate
- 🟡 TCP retransmission analysis
- 🟡 Network latency monitoring

---

## 🛠️ How To Use

### Step 1 — Capture Traffic in Wireshark
Open Wireshark and start a capture on your network interface.

### Step 2 — Export as JSON
```
File → Export Packet Dissections → As JSON
```
Save the `.json` file anywhere on your machine.

### Step 3 — Drop into SniffPal
Drag and drop (or browse) the JSON file into SniffPal.  
Results appear instantly — no waiting, no uploading.

---

## 🔍 What SniffPal Detects

### 📱 Devices
| Feature | How |
|---|---|
| MAC Address | Ethernet layer |
| Vendor / Brand | OUI MAC prefix lookup |
| IP Address | IP/IPv6 layer |
| Hostname | DHCP options |
| Traffic type | Port + protocol analysis |
| Bandwidth used | Frame length accumulation |

### 🌐 Websites
| Feature | How |
|---|---|
| HTTPS sites | TLS SNI handshake extraction |
| HTTP sites | HTTP Host header |
| DNS queries | DNS query name field |
| Failed lookups | NXDOMAIN response code |
| Tracker detection | Domain blocklist matching |

### ⚠️ Security Checks
| Threat | Detection Method |
|---|---|
| ARP Spoofing | MAC claiming multiple IPs + reply flood |
| Rogue DHCP | Multiple DHCP offer sources |
| ICMP Redirect | ICMP type 5 packets |
| Cleartext Passwords | HTTP Authorization + FTP USER/PASS |
| SQL/XSS Injection | URI pattern matching |
| DNS Malware (DGA) | High NXDOMAIN rate analysis |
| TCP Problems | Retransmission + RTT analysis |

---

## 💻 Run Locally

```bash
# Clone the repo
git clone https://github.com/kannanokannan/sniffpal.git
cd sniffpal

# Install dependencies
npm install

# Start dev server
npm run dev

# Open browser
http://localhost:5173
```

### Requirements
- Node.js 18+
- Any modern browser

---

## 🏗️ Tech Stack

| Tool | Purpose |
|---|---|
| React + Vite | Frontend framework |
| Tailwind CSS | Styling |
| Recharts | Charts and visualizations |
| Lucide React | Icons |
| Browser FileReader API | Local file parsing |

**Zero backend. Zero database. Zero API keys.**

---

## 📁 Project Structure

```
sniffpal/
├── src/
│   ├── components/
│   │   ├── FileUpload.jsx       # Drag & drop file input
│   │   ├── SummaryCards.jsx     # Top stats cards
│   │   ├── ProtocolChart.jsx    # Pie + bar charts
│   │   ├── DeviceTable.jsx      # Device explorer
│   │   ├── WebsitesTab.jsx      # Sites + tracker detection
│   │   └── SecurityTab.jsx      # Security alerts
│   ├── utils/
│   │   └── parser.js            # Wireshark JSON parser
│   └── App.jsx                  # Main app + routing
├── public/
├── package.json
└── README.md
```

---

## 🗺️ Roadmap

### Version 1.0 (Current)
- [x] Device detection with vendor lookup
- [x] Protocol breakdown charts
- [x] Top talkers visualization
- [x] Website detection via SNI + DNS
- [x] Tracker / advertiser detection
- [x] ARP spoofing detection
- [x] Rogue DHCP detection
- [x] ICMP redirect detection
- [x] Cleartext credential detection
- [x] DNS health analysis
- [x] TCP retransmission analysis

### Version 2.0 (Planned)
- [ ] WiFi channel analysis (monitor mode captures)
- [ ] Signal strength heatmap
- [ ] Export report as PDF
- [ ] Chrome Extension version
- [ ] Live capture via local tshark integration
- [ ] Device uptime tracking
- [ ] AI-powered plain English summary

---

## 🤝 Contributing

Pull requests are welcome!

```bash
# Fork the repo
# Create your branch
git checkout -b feature/your-feature

# Make changes and commit
git commit -m "Add: your feature description"

# Push
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

## ⭐ If This Helped You

Give it a star on GitHub — it helps others find the project!

[![GitHub stars](https://img.shields.io/github/stars/kannanokannan/sniffpal?style=social)](https://github.com/kannanokannan/sniffpal)
