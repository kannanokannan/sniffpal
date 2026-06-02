# Decision Log — SniffPal

---

## 2026-06-02 | Core positioning
Decision: SniffPal is a browser-based network analyzer for developers. Open-source (Apache 2.0) with Pro features monetized via one-time purchase on Polar.sh.
Rationale: Zero recurring cost friction for adoption. Pro tier funds development.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Stack locked
Decision: React + Vite + Tailwind + Recharts. All dependency versions pinned.
Rationale: Stable, known stack. No upgrades without explicit decision.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Two-tier AI architecture
Decision: Two-tier AI — local heuristic analysis (tier 1) + Anthropic API (tier 2) for deeper findings. Tier 2 is opt-in.
Rationale: Keeps core functionality offline-capable. API cost is user-controlled.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Pi mode and monitor mode
Decision: Raspberry Pi mode (Pi as full router, Nokia G-2425G-A as dumb AP) and monitor mode are supported features, not experimental.
Rationale: Network instrumentation on real hardware is a core use case relevant to SniffPal's development and positioning.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | DevTools extension roadmap
Decision: Three planned extensions — HAR-Purge (primary, zero Manifest V3 friction), Console-AI (top AI-first recommendation, intercepts console errors + network context, explains via Anthropic API), Schema-Sentry (follow-up). SniffPal is the foundation.
Rationale: HAR-Purge has lowest friction to ship. Console-AI has highest viral potential ("Ask your browser what's wrong with your app").
Locked by: Kannan
Status: Locked — sequencing not yet locked

---

## 2026-06-02 | parser.js deprecation
Decision: src/utils/parser.js is orphaned. To be removed once confirmed no runtime dependency exists.
Rationale: Dead code identified in Hanuman repo read (2026-06-02).
Locked by: Chanakya (pending Kannan confirmation)
Status: Under review

---

## 2026-06-02 | sniffpal-update/ directory
Decision: stale sniffpal-update/ directory to be removed.
Rationale: Identified as stale in Hanuman repo read (2026-06-02). No active purpose.
Locked by: Chanakya (pending Kannan confirmation)
Status: Under review
