# TODO — ContextBoundary

Last updated: 2026-06-02
Source: Hanuman full repo read (2026-06-02)

---

## P0 — Critical (open decisions blocking progress)

- [ ] **#1 Resolve vendor tier layout — 4-zone vs 5-zone** — 5-zone adds Compute Vendor as separate column. Chanakya leans 5-zone for sovereignty audit clarity. Kannan to decide before hero diagram is drafted.
  - Owner: Kannan decision → Chanakya drafts diagram spec → Hanuman renders

- [ ] **#2 Resolve legacy hardware origin thesis** — Dell R520/R730 as Tier II/III substrate. E-waste angle not in existing literature. Decide whether this is in scope for v0.1 or a v0.2 addition.
  - Owner: Kannan decision

- [ ] **#3 Fix repo structure to match README** — README describes nested architecture/ and audit-profiles/ subdirs. Actual repo is flat. Create the folder structure README promises.
  - Files: repo root
  - Owner: Hanuman

- [ ] **#4 Delete stale branch** — claude/contextboundary-readme-update-Zlk7w. Review and delete.
  - Owner: Kannan or Hanuman

---

## P1 — v0.2 Roadmap (from repo)

- [ ] **#5 DPDP compliance profile** — India Digital Personal Data Protection Act. High priority given Chennai base.
- [ ] **#6 RBI compliance profile** — Reserve Bank of India AI governance requirements.
- [ ] **#7 HIPAA profile** — US healthcare. Needed for enterprise US market.
- [ ] **#8 SOC2 profile** — Enterprise trust baseline. Blocking for US SaaS buyers.
- [ ] **#9 EU AI Act profile** — High-risk system classification and egress implications.
- [ ] **#10 LGPD profile** — Brazil. Completes major geography coverage.
- [ ] **#11 Expanded Endpoint Atlas** — More endpoint types, vendor-specific entries.
- [ ] **#12 Legacy hardware guide** — If origin thesis confirmed — Dell R520/R730 as sovereign compute substrate.
- [ ] **#13 Worked examples** — End-to-end boundary governance walkthroughs per compliance profile.
- [ ] **#14 Observability sink pattern** — How egress events flow to SIEM/logging infrastructure.

---

## P2 — Polish

- [ ] **#15 Hero boundary diagram** — Primary visual artifact. Cannot be built until vendor tier layout decision (#1) is resolved.
- [ ] **#16 Audit Profiles structure** — Formal per-axis audit profile templates.
- [ ] **#17 Endpoint Atlas v1** — Initial catalog of AI endpoint types and boundary classification.

---

## Done

- [x] Three axes defined and locked
- [x] ITIL 4 anchor decision locked
- [x] Peer positioning to ContextOps locked
- [x] v0.2 roadmap items identified in repo
