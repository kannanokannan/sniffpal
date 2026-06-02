# Decision Log — ContextBoundary

---

## 2026-06-02 | Project positioning
Decision: ContextBoundary is a peer technical-layer reference connector to ContextOps. Not a subordinate project. Governs AI context egress. Anchors to ITIL 4 Four Dimensions model.
Rationale: ITIL 4 Four Dimensions (Organizations/People, Information/Technology, Partners/Suppliers, Value Streams) maps directly to ContextBoundary's three axes. Ops and ITSM teams already speak ITIL.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Three axes locked
Decision: Three axes — Privacy Tiers (I/II/III), Geography (GDPR/DPDP/RBI), Vendor Tier Responsibility (Customer/AMS/Product/LLM chain). Vendor Tier Responsibility is the key differentiator not present in existing literature.
Rationale: The chain of responsibility across vendor tiers is the unsolved governance problem in enterprise AI deployments.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Hero artifact
Decision: Hero artifact is the boundary diagram. Supporting artifacts: Audit Profiles, Endpoint Atlas.
Rationale: A single visual that shows the three axes and vendor tier chain is the clearest entry point for ITSM practitioners.
Locked by: Kannan
Status: Locked

---

## 2026-06-02 | Vendor tier layout — OPEN
Decision: 4-zone vs 5-zone vendor tier layout not yet resolved. 5-zone adds Compute Vendor as a separate column for sovereignty audit clarity.
Rationale: Chanakya leans 5-zone. Adds Compute Vendor separation which matters for air-gapped and sovereign cloud deployments. Pending Kannan decision.
Locked by: Pending
Status: Open

---

## 2026-06-02 | Legacy hardware origin thesis — OPEN
Decision: Origin thesis around legacy/refurb hardware (old Xeons — Dell R520/R730) as Tier II/III substrate not yet resolved. Positions ContextBoundary with an e-waste angle not in existing literature.
Rationale: Unique angle. Low-cost sovereign compute substrate is a real enterprise problem. Not yet validated against the roadmap.
Locked by: Pending
Status: Open

---

## 2026-06-02 | Repo structure mismatch
Decision: README describes nested architecture/ and audit-profiles/ subdirectories but actual repo is flat. Fix repo structure to match README, not the other way around.
Rationale: README represents the intended design. Flat structure is an incomplete implementation.
Locked by: Chanakya (pending Kannan confirmation)
Status: Under review

---

## 2026-06-02 | Stale branch cleanup
Decision: Branch claude/contextboundary-readme-update-Zlk7w is stale. Review and delete if no active work.
Rationale: Identified by Hanuman in repo read (2026-06-02).
Locked by: Chanakya (pending Kannan confirmation)
Status: Under review
