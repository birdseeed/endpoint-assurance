# ADR-0008: Dashboard as primary product surface; reports as toggleable outputs; public scan as free tier

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. The three-tier offering ladder this ADR describes (Report / Patch & Deploy / Full Endpoint Management) no longer exists as named. Full Endpoint Management maps to `managed` (confirmed in `go-service/docs/architecture.md`, PAT-1048). This ADR's own text does not say how Report and Patch & Deploy individually resolve into the new two-value split, so this note does not assert that mapping. The decision text is unchanged.

**Status:** Accepted
**Deciders:** Andy (sole maintainer)

---

## Context

Through the first build sprint, `dashboard.patched.im` was conceived as an internal ops tool. CVE reports were the primary customer-facing deliverable — PDF emailed on demand. The public CVE scan (`/public/scan`) was a one-shot lead-capture page backed by the Microsoft Graph API.

After the first build sprint it became clear that three things had shifted:

1. **The dashboard itself is the product.** A live, always-current fleet view (CIS L1 score, CVE posture, device inventory) is more compelling than a periodic PDF report. Customers in IoM SME and regulated sectors want a portal they can check at any time, not an email they receive monthly. The PDF report becomes evidence for an audit, not the product itself.

2. **The old CVE-scanning internals are the wrong architecture.** The public scan used a separate Graph API pipeline that ran inside the dashboard. The new pipeline — macOS/Windows agent → `POST /v1/inventory` → extractor → evaluator → compliance signals — produces richer, more accurate, continuously-updated data. CVE scoring should move off the one-shot Graph-only path and onto the continuous agent pipeline. The dashboard rebuilds around this.

3. **The public scan is the top-of-funnel, not the product.** A free one-shot CVE assessment (from a Jamf export or limited Graph read) lets a prospect experience value before committing to an agent deployment. This is the free tier: no account, no agent, one report. Everything above it requires the agent pipeline and a customer dashboard.

These three realisations together represent a product-level reshape that must be reflected in the architecture.

---

## Decision

**The dashboard (`dashboard.patched.im`) is the primary product surface.**

- The live fleet view — CIS L1 compliance score, CVE posture, device inventory, patch status — is what customers pay for.
- The internal rebuild drops the old CVE-scanning pipeline from the dashboard entirely. Scanning now lives in the agent pipeline (macOS `patched-collect.sh` + Windows collector → Go API → extractor → evaluator).
- The dashboard proxies the Go API (`example-api-host:8443`) for all data. No data lives only in the dashboard.

**Reports are toggleable outputs, not the primary product.**

- PDF reports (CIS compliance, executive summary, CVE summary) remain available and are a key deliverable for Tier 1 customers — they are evidence for auditors and insurers.
- They become outputs generated from the live pipeline data, not the primary experience. Frequency and format are configurable per tenant.
- The three-tier offering ladder (Report / Patch & Deploy / Full Endpoint Management — PAT-81) maps onto which dashboard surfaces and agent capabilities are unlocked, not onto whether you get a report.

**The public CVE scan is the free tier.**

- The public scan (`/public/scan`) is the top-of-funnel lead-capture mechanism: a prospect can request a one-shot assessment (from a Jamf export or a read-only Graph consent) with no account required.
- It is not the product. It is a conversion tool. The scan result links to a call-to-action to deploy the agent and get a live dashboard.
- Architecturally: the public scan runs off a separate path (Graph-only or Jamf export parsing); it does not use the continuous agent pipeline. The two paths must not be conflated in the DB schema or the evaluator.

---

## Consequences

### Immediate

- The Internal Dashboard rebuild project (PAT-327 and related issues) is the vehicle for this. Old CVE-scanning code is scrapped from the dashboard.
- Agent pipeline health becomes critical infrastructure. If the agent stops phoning home, the customer dashboard goes stale. Monitoring (PAT-229, PAT-149) is not optional past customer #1.
- The customer portal (PAT-331) is a read-only, customer-scoped view of the same data that the internal dashboard shows — not a separate product. It reuses the same Go API, same pipeline, same schema.

### Architecture implications

- `dashboard.patched.im` remains staff-facing for now. The customer-facing surface is `app.patched.im` (Customer Portal, PAT-410).
- Reports are generated from `compliance_evaluations` + `device_apps` + `raw_payloads` (already the case). No new report-specific collection pipeline is needed.
- The public scan keeps its own `scans` table and Scanner engine (`scanner.py`) — deliberately isolated from the continuous pipeline so a broken scan engine cannot affect live customer data.
- Per-tenant feature toggles (PAT-83) and the tier-switch endpoint (PAT-397) are the technical enforcement layer for the three-tier model.

### What this is NOT deciding

- This is not a decision about when to launch the customer portal or which tier ships first.
- It does not change the agent wire format or the Go API schema.
- It does not address mobile devices, Linux, or EDR signal ingestion (those remain separate roadmap stubs).
