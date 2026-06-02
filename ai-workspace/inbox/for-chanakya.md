## Task 002 | project: sniffpal | owner: chanakya
Context: Full repo read of kannanokannan/sniffpal completed by Hanuman.
Task: Review summary below. Draft projects/sniffpal/DECISION_LOG.md
and projects/sniffpal/TODO.md based on actual repo state.
Expected output: Two files committed to ai-workspace under projects/sniffpal/
Constraints: Decisions must reflect actual repo state. No assumptions.

### Repo summary

#### Identity
- Repo: https://github.com/kannanokannan/sniffpal
- Live: https://kannanokannan.github.io/sniffpal
- Version: 2.1.1 (package.json + UI header)
- License: implied open source (no LICENSE file in local tree — verify on GitHub)
- Description: 100% client-side browser-based network packet analyser. Zero upload. Parses Wireshark JSON, pcap, pcapng, and scapy output.

#### Stack
- React 18.3.1 + Vite 5.4.1 (PINNED — must not change) + Tailwind CSS v3 (PINNED — must not change)
- Recharts 2.12.7 (protocol/traffic charts)
- Lucide React 0.383.0 (icons)
- @huggingface/transformers 4.2.0 (Transformers.js AI fallback)
- gh-pages 6.1.1 (GitHub Pages deploy)
- Flask + APScheduler (Pi server, not in npm)
- Scapy (Python capture tool, not in npm)
- Deployment: `npm run build` → `npm run deploy` → gh-pages branch

#### File tree (non-trivial files)
```
sniffpal/
├── src/
│   ├── App.jsx                     # Root component, IS_PI_MODE detection, Pi dashboard
│   ├── main.jsx                    # React entry point
│   ├── index.css / App.css         # Global styles
│   ├── core/
│   │   ├── parser.worker.js        # CORE: all parsing, enrichment, findings. Web Worker.
│   │   ├── geminiNano.js           # AI tier manager (Chrome Built-in AI → Transformers.js)
│   │   ├── healthScore.js          # 0-100 network security score
│   │   └── geoip.js                # In-bundle IP→country lookup (no API)
│   ├── components/
│   │   ├── TopologyMap.jsx         # SVG clustered topology map (recently improved)
│   │   ├── SecurityTab.jsx         # Findings + AI explanations tab
│   │   ├── DeviceTable.jsx         # Device inventory with trust/search
│   │   ├── WebsitesTab.jsx         # Sites visited (.local domains filtered)
│   │   ├── ProtocolChart.jsx       # Recharts protocol/traffic charts
│   │   ├── SummaryCards.jsx        # Top stat cards
│   │   ├── PrivacyReport.jsx       # Tracker breakdown panel
│   │   ├── DataPanel.jsx           # Drill-down panel from chart clicks
│   │   ├── HealthScore.jsx         # Health score display
│   │   ├── FileUpload.jsx          # Drag-and-drop upload zone (web mode only)
│   │   └── PrintReport.jsx         # Print-only PDF report
│   └── utils/
│       ├── useSession.js           # IndexedDB session persistence (24hr expiry)
│       └── parser.js               # ORPHANED — old parser copy, nothing imports it
├── pi/
│   ├── server.py                   # Flask server: serves dist/, schedules captures, API
│   ├── install.sh                  # Basic pip + npm install + mkdir digests
│   ├── deploy.sh                   # Full systemd service install (newer, preferred)
│   ├── requirements.txt            # flask>=3.0.0, apscheduler>=3.10.0
│   └── README.md                   # Pi server docs (some content stale — references 30min interval, now 10min)
├── scapy-capture-tool/
│   ├── capture.py                  # Managed mode capture (standard, works on all hardware)
│   ├── capture_monitor.py          # Monitor mode (802.11 + Radiotap, band detection)
│   ├── requirements.txt            # scapy>=2.5.0
│   └── README.md                   # Covers capture.py only — capture_monitor.py not yet documented
├── ai-workspace/                   # Created by Hanuman — agent coordination workspace
├── sniffpal-update/                # Residual staging dir from earlier dev session
│   ├── CLAUDE.md
│   └── src/workers/parser.worker.js  # Stale copy — superseded by src/core/parser.worker.js
├── AGENTS.md                       # AI agent context (more up-to-date than CLAUDE.md)
├── CLAUDE.md                       # AI context for Claude Code
├── CHANGELOG.md                    # Full history v1.0→v2.1.1
├── SECURITY.md                     # Vulnerability reporting policy
├── README.md                       # User-facing readme (recently updated)
├── llms.txt                        # LLM context file (slightly stale — v2.1.1, some planned items now shipped)
├── TOPOLOGY_IMPROVEMENTS.md        # Completed task spec (can be archived)
├── eslint.config.js / vite.config.js / tailwind.config.js / postcss.config.js
└── public/favicon.svg / public/icons.svg
```

#### What exists and works
- Full packet parsing pipeline: Wireshark JSON, pcap (legacy + pcapng), scapy output
- Streaming parser handles 500MB+ files via reservoir sampling (max 25,000 packets)
- Device enrichment: mDNS, SSDP, LLMNR, NetBIOS — rich device naming + service detection
- Security findings: PRIV_MDNS_001, INFO_MDNS_002, PRIV_SSDP_001, INFO_NBNS_001, IOT_TEL_001 (MQTT+CoAP), IOT_UPNP_002 (from AGENTS.md — verify in parser.worker.js)
- Legacy alerts: ARP spoof, rogue DHCP, ICMP redirect, cleartext creds, FTP, DNS NXDOMAIN flood, TCP retransmissions, latency, MQTT unencrypted, UPnP active, odd-hours traffic, foreign IPs (CN/RU/KP/IR)
- Two-tier AI: Chrome Built-in AI (Summarizer + LanguageModel) → Transformers.js SmolLM2-360M-Instruct via hf-mirror.com
- Health Score 0-100 with grade A-F
- PDF report via window.print() (PrintReport.jsx)
- Session persistence: IndexedDB, 24hr expiry
- Device trust/ignore: SHA-256 hashed MACs in sessionStorage
- Self-device marking: IP stored in sessionStorage
- Topology Map: clustered star SVG (IoT/Mobile/Network/Computer/Other), router auto-detect (.1 IP → vendor hints → lowest IP fallback → inferred gateway node), animated data-flow lines, band colour rings, click popups
- Pi mode: IS_PI_MODE detection (not github.io and not localhost), Pi dashboard panel, Start Capture, Load Latest, Settings (interval/interface), localStorage for Pi settings
- Pi server: Flask, APScheduler, /api/status|digests|digests/latest|capture/start|settings GET+POST
- Monitor mode capture: capture_monitor.py, 802.11 Radiotap, band detection (2.4/5/6 GHz), SNIFFPAL_PROGRESS JSON progress events
- wlan.sa/wlan.da MAC fallback in parser for monitor mode packets
- band + freq fields on device objects
- .local mDNS domain filter in WebsitesTab

#### What is incomplete / missing
1. **`IOT_C2_001`** (no-DNS outbound beacon detection) — listed in roadmap, not implemented in parser.worker.js
2. **`IOT_IGMP_001`/`IOT_IGMP_002`** — multicast flood detection — listed as deferred to Pi v3.0, not implemented
3. **`/api/capture/events` SSE endpoint** — listed in AGENTS.md but not in pi/server.py
4. **Pi live temperature/uptime/CPU/RAM metrics** — mentioned in AGENTS.md under /api/status, not in current server.py
5. **Capture mode switch in Pi UI** — AGENTS.md mentions standard vs monitor mode in pi/server.py, not implemented
6. **`src/utils/parser.js`** — orphaned old parser, nothing imports it, should be deleted
7. **`sniffpal-update/` directory** — stale staging dir, should be deleted or gitignored
8. **`scapy-capture-tool/README.md`** — documents capture.py only; capture_monitor.py is undocumented there
9. **`pi/README.md`** — references 30-minute capture interval (default is now 10 minutes)
10. **`llms.txt`** — IOT_UPNP_002 and IOT_C2_001 listed as "planned" but IOT_UPNP_002 appears shipped per AGENTS.md
11. **Audit Profiles beyond GDPR** — not in scope for sniffpal but worth noting for contextboundary
12. **Version string** — still "v2.1.1.1" in App.jsx UI header; package.json says "2.1.1"

#### Open GitHub issues/PRs
- No open issues found (gh issue list returned empty)
- No open PRs found (gh pr list returned empty)
- One stale branch: `claude/contextboundary-readme-update-Zlk7w` (this is on contextboundary repo, not sniffpal)

#### Git history summary (most recent 10 commits)
```
03e7743  feat: add Pi health metrics and capture mode switch
00e0894  fix: serve prefixed Pi assets before Flask static fallback
331ad49  fix: serve GitHub Pages asset paths in Pi mode
b5fa9f7  feat: add pi live monitor progress and UPnP IGD detection
ff6a561  fix: allow pi capture when server runs as root
48a367c  fix: improve topology gateway layout and docs
c90273a  fix: topology map router detection + clustered star layout + animations
2f4a71e  feat: monitor mode capture + band detection + topology map + .local filter
0d80da3  feat: Pi mode UI + settings + fresh README + llms.txt
86cf811  feat: src/core restructure + PDF fix + Pi server v1
```
Active development. Multiple commits per session. No test suite. No CI/CD.

#### Constraints that must be respected
- Vite 5.4.1 — pinned (v6/v8 broke build)
- Tailwind v3 — pinned (v4 CSS syntax breaks build)
- No external API calls in findings/enrichment (zero-upload promise)
- No sessionStorage for sensitive data → use IndexedDB (useSession.js)
- No DDG Tracker Radar or EasyPrivacy lists (licensing risk)
- No CVE matching from firmware guesses
- No heavy npm deps without bundle size check
- scapy requires sudo on Linux
- pi/digests/ gitignored — never commit capture data

---

## Task 002 | project: contextboundary | owner: chanakya
Context: Full repo read of kannanokannan/contextboundary completed by Hanuman.
Task: Review summary below. Draft projects/contextboundary/DECISION_LOG.md
and projects/contextboundary/TODO.md based on actual repo state.
Expected output: Two files committed to ai-workspace under projects/contextboundary/
Constraints: Decisions must reflect actual repo state. No assumptions.

### Repo summary

#### Identity
- Repo: https://github.com/kannanokannan/contextboundary
- Version: v0.1 (draft)
- License: Apache 2.0
- Description: Vendor-neutral open-source specification for enterprise AI data egress governance. Defines where AI-processed data is allowed to flow. Deployment-agnostic. Not a product — a specification.
- Sibling projects: ContextOps (organisational governance), Sthala (on-prem sovereign implementation)
- Family root: https://github.com/kannanokannan/context-stack

#### File tree (root level — no subdirectory structure despite README claiming one)
```
contextboundary/
├── README.md                  # Full project description, canonical diagram, tier table, roadmap
├── FRAMEWORK.md               # Core specification (~12 min read)
├── ARCHITECTURE.md            # Three-layer model + five-zone model description
├── RATIONALE.md               # Why now, regulatory context, what the gap is
├── CONTRIBUTING.md            # Contribution guidelines
├── LICENSE                    # Apache 2.0
├── CLAUDE.md                  # AI agent context
├── boundary-diagram.md        # Canonical five-zone diagram with annotations
├── tier-classification.md     # Egress Tier I/II/III definitions and routing rules
├── vendor-tier-matrix.md      # Five-zone responsibility matrix
├── gdpr.md                    # GDPR Audit Profile (v0.1 reference, only profile shipped)
├── vendors.md                 # Starter vendor registry (Endpoint Atlas)
├── contextops-mapping.md      # Bridge to ContextOps methodology
├── llms.txt                   # Short LLM context
├── llms-full.txt              # Full LLM context
├── .gitignore
└── mnt/                       # Directory (contents unknown — possibly empty or system artifact)
```

#### What exists and is complete
- Core specification (FRAMEWORK.md): Three Axes (Egress Tier, Geography/Jurisdiction, Vendor Tier Responsibility), Canonical Boundary Diagram, Crossing Point definitions, Audit Profile pattern, Endpoint Atlas pattern
- Architecture model: five-zone boundary model + three-layer ownership model (Layer 1 Vendor LLM / Layer 2 Domain Knowledge / Layer 3 Client Solution Overlay) documented in ARCHITECTURE.md
- Tier classification (tier-classification.md): Tier I/II/III definitions, routing rules
- Vendor tier matrix (vendor-tier-matrix.md): five-zone responsibility matrix
- GDPR Audit Profile (gdpr.md): one complete regulation-specific overlay
- Vendor registry (vendors.md): starter Endpoint Atlas entries
- ContextOps mapping (contextops-mapping.md): bridge to organisational governance layer
- Rationale (RATIONALE.md): full regulatory context, sovereignty gap argument, competitive positioning vs existing tools (Pipelock, LlamaFirewall, Trylon Gateway)
- README: complete — canonical diagram, tier table, three axes, hero artifacts, roadmap, family description

#### What is incomplete / missing (from README roadmap v0.2)
1. **DPDP Audit Profile** — India Digital Personal Data Protection Act — not yet created
2. **RBI sectoral guidelines Audit Profile** — not yet created
3. **HIPAA Audit Profile** — not yet created
4. **SOC2 Audit Profile** — not yet created
5. **EU AI Act Audit Profile** — not yet created (critical — enforcement August 2, 2026)
6. **LGPD Audit Profile** — Brazil, not yet created
7. **Expanded Endpoint Atlas** — top 50 enterprise AI vendors — currently starter entries only
8. **Legacy hardware substrate guidance** — existing infrastructure as Tier II/III platform
9. **Worked examples** — SMB clinic, mid-market cooperative bank, Indian IT services firm
10. **Observability sink protection pattern** — regional log sinks, edge redaction

#### Structural discrepancy
- README and FRAMEWORK.md describe a subdirectory structure:
  `architecture/`, `audit-profiles/`, `endpoint-atlas/`, `connectors/`
  with files like `architecture/boundary-diagram.md`, `audit-profiles/gdpr.md`, etc.
- **Actual repo structure is flat** — all files sit at root level
- This is a documentation/reality mismatch that should be resolved (either restructure or update the documented paths)

#### Open GitHub issues/PRs
- No open issues found
- One stale branch: `claude/contextboundary-readme-update-Zlk7w` — purpose unknown, possibly a previous AI-generated PR branch; should be reviewed or deleted

#### Active development signals
- Flat structure vs described nested structure suggests the repo is in early/rapid iteration
- CLAUDE.md present — AI-assisted authoring workflow in use
- No versioning beyond "v0.1" tag in prose — no git tags observed
- No CI/CD, no tests (specification repo — expected)

#### Constraints / Do Not Touch
- Per CLAUDE.md: do not touch LICENSE, CONTRIBUTING.md, llms.txt, llms-full.txt, .gitignore, or .claude/
- Do not restructure the repo without explicit task
- Do not rename files
- Terminology: Red/Amber/Green → Tier I/II/III (already enforced in main files; verify no stragglers)
