# TODO — SniffPal

Last updated: 2026-06-02
Source: Hanuman full repo read (2026-06-02)

---

## P0 — Critical (gaps between claims and reality)

- [ ] **#1 IOT_C2_001 not built** — AGENTS.md references this finding type but implementation is missing. Either build it or remove the claim from AGENTS.md.
  - Files: `AGENTS.md`, relevant findings module

- [ ] **#2 /api/capture/events SSE endpoint missing** — Documented as a feature but not implemented in server.py. Gap between docs and reality.
  - Files: `server.py`, API docs

- [ ] **#3 Pi health metrics gap** — AGENTS.md claims Pi health metrics are reported but server.py does not implement them. Align implementation with claims or update AGENTS.md.
  - Files: `server.py`, `AGENTS.md`

---

## P1 — Important (code hygiene + docs)

- [ ] **#4 Remove orphaned src/utils/parser.js** — Confirmed unused. Remove once no runtime dependency verified.
  - Files: `src/utils/parser.js`

- [ ] **#5 Remove stale sniffpal-update/ directory** — No active purpose. Clutters repo.
  - Files: `sniffpal-update/`

- [ ] **#6 Document capture_monitor.py** — Undocumented in scapy README. Any user setting up Pi mode will hit this gap.
  - Files: `pi/README.md`, `capture_monitor.py`

- [ ] **#7 Fix stale 30-min interval reference in pi/README.md** — Outdated reference. Confirm actual interval and update.
  - Files: `pi/README.md`

---

## P2 — Roadmap (DevTools extensions)

- [ ] **#8 Build HAR-Purge DevTools extension** — Primary extension target. Zero Manifest V3 friction. Apache 2.0 + Pro via Polar.sh.

- [ ] **#9 Build Console-AI DevTools extension** — Top AI-first target. Intercepts console errors + reads minified stack traces alongside network requests. Explains failures via Anthropic API. Viral framing: "Ask your browser what's wrong with your app."

- [ ] **#10 Plan Schema-Sentry** — Follow-up extension after Console-AI. Scope not yet defined.

---

## Done

- [x] Full HAR parsing pipeline
- [x] All 5 structured findings implemented
- [x] Two-tier AI (local heuristic + Anthropic API)
- [x] Health score
- [x] Topology map
- [x] Pi mode
- [x] Monitor mode
- [x] Session persistence
