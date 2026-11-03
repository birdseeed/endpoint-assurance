# Customer portal: reports & infocards inventory (PAT-763)

Audit pass only — no behaviour change. Catalogues what the customer portal
(`app.patched.im`, this repo) actually ships today against the admin
dashboard's report catalogue, and reviews the portal's infocards against a
candidate list. Follow-up work, if any, should be filed as separate tickets.

Sources reviewed: `main.py`, `templates/*.html` (this repo); `main.py`
`REPORT_CATALOG` / `_REPORT_PDF_PATHS` (`Patched-LTD/dashboard`); the
`/v1/portal/*` handlers and `RenderPortalReportPDF` (`Patched-LTD/patched.im`,
`go-service/internal/handlers/portal.go` and `go-service/internal/report/portal_pdf.go`).

## Portal surface today

Eight pages behind CF Access, all reading from `/v1/portal/*` (no portal DB):
Overview (`/`), Devices (`/devices`, `/devices/{id}`, `/devices.csv`),
Extensions (`/extensions`), Findings (`/findings`), Unapproved apps
(`/unapproved-apps`), Reports (`/reports`), Install (`/install`),
Support (`/support`).

The portal generates exactly **one** report type: a customer-layout PDF
(`POST /reports/generate` → platform `generatePortalReport` →
`RenderPortalReportPDF`) covering CIS Level 1 posture, open findings and
patch status for the whole estate, on demand or on a customer-configured
schedule (daily/weekly/monthly, PAT-703). This is a bespoke composite
document — it is rendered by its own function, distinct from the 13 admin
report generators, and does not correspond 1:1 to any single catalog entry.

## Report parity matrix

Admin catalogue = `REPORT_CATALOG` in `dashboard/main.py` (13 types, all
PDF, admin-triggered or per-tenant-subscription email via
`report_subscriptions` / `_run_report_tick`).

| # | Report | Admin dashboard | Customer portal | Format (portal) | Portal source | Customer visibility |
|---|---|---|---|---|---|---|
| 1 | Executive Estate Summary | Yes (`executive-summary`) | Partial | PDF (composite report) | `POST /v1/portal/reports` → `generatePortalReport` | Default — closest analogue is the portal's one on-demand/scheduled report, but it's a distinct generator, not the admin executive-summary PDF |
| 2 | CIS Compliance Report | Yes (`cis-compliance`) | Partial | Portal-native page + composite PDF | Overview dial (`cis_score_current`), device detail "Compliance signals" table (`compliance_signals`, per device only) | Default — score/trend and per-device pass/fail are visible; no estate-wide pass/fail-per-control report exists |
| 3 | CVE / Vulnerability Exposure | Yes (`cve-report`) | Yes/Partial | Portal-native page (`/findings`) + summarised in composite PDF | `GET /v1/portal/findings` | Default — full findings list is portal-native; no standalone downloadable CVE report or history |
| 4 | Patch & Update Status | Yes (`patch-status`) | Partial | Portal-native infocard + composite PDF | Overview `patch_status` (up_to_date/pending/failed), per-device pill | Default — aggregate counts shown; no dedicated patch-status report/download |
| 5 | Stale / Inactive Endpoints | Yes (`stale-endpoints`) | Yes | Portal-native page + CSV | `/devices?view=stale&stale_days=7\|14\|30`, `/devices.csv?stale_days=N` | Default — filterable UI + CSV export exist; no PDF/scheduled report equivalent |
| 6 | Certificate Expiry | Yes (`cert-expiry`) | No | — | — | Not exposed anywhere in the portal (routes, templates, or upstream calls) |
| 7 | Software Inventory & Metering | Yes (`software-inventory`) | No | — | — | Device detail shows only apps *with open CVE findings* (`apps_with_findings`), not a full installed-software inventory or usage/metering view |
| 8 | App Policy Drift / Governance | Yes (`app-policy-drift`) | Partial | Portal-native page | `GET /v1/portal/unapproved-apps` → `FetchPortalUnapprovedApps`, which filters the same `FetchAppPolicyDriftReport` the admin report uses down to `policy == "unapproved"` rows | Default — `/unapproved-apps` (PAT-729) shows unapproved-policy apps and devices affected; the admin report's other policy rows (mandatory, approved, unmanaged) and their drift are not exposed |
| 9 | Browser Extension Risk | Yes (`browser-extensions`) | Partial | Portal-native page | `GET /v1/portal/extensions` | Default — `/extensions` (PAT-933) lists every browser extension in the estate with approval state (approved/unapproved/unreviewed/ignored), browsers and devices, unapproved first; no scored "risk" report or downloadable equivalent to the admin report exists |
| 10 | EDR / Security-Tooling Coverage | Yes (`edr-coverage`) | No | — | — | Not exposed |
| 11 | Device Health / Hardware | Yes (`device-health`) | No | — | — | Not exposed (no battery/SMART/storage fields anywhere in portal templates or `/v1/portal/devices` consumption) |
| 12 | Encryption & Disk Posture | Yes (`encryption-posture`) | Partial | Portal-native (per-device only) | `device.encryption_ok` — devices list column + device-detail pill | Default — per-device encryption state is visible; no estate-wide encryption-posture report or removable-storage findings |
| 13 | Local Admin / Privileged Access | Yes (`local-admin`) | No | — | — | Not exposed |

**Reading:** of the 13 admin report types, 5 have no portal equivalent at
all (certs, software inventory, EDR coverage, device health/hardware, local
admin), 7 have partial coverage via infocards/native pages rather than a
matching downloadable report (executive summary, CIS compliance, patch
status, app policy drift, browser extension risk, encryption posture — plus
CVE findings, which is native-page-only), and 1 (stale endpoints) has full
native-page + CSV coverage. No admin report has a *literal* portal
counterpart by name — the only thing customers can generate or schedule is
the single composite PDF. Whether each of the 5 admin-only reports should
stay internal-only, go customer-facing by default, or sit behind a tier is a
product decision for follow-up tickets, not decided by this audit.

## Infocard / summary-card review

Only Overview (`/`) carries infocards; `templates/overview.html` renders
five `<section class="card">` blocks fed by `GET /v1/portal/overview`.

| Candidate card | Exists today | Data source | Current placement | Notes |
|---|---|---|---|---|
| Overall estate health / status | Partial | `cis_score_current` (dial) | Overview | The CIS dial functions as the de facto headline, but there's no single card that synthesises CVE + CIS + patch into one status |
| Device count and active/stale split | Partial | `devices_reporting_24h`, `devices_total` | Overview ("Devices reporting" card) | Overview shows reported-in-24h vs. total only; the active/stale/silent split (per `DEVICE_FRESHNESS` vocabulary) only appears on `/devices` as tabs, not as an overview infocard |
| High-risk items requiring attention | No | — | — | No card aggregates top action items across CVE/CIS/patch findings |
| Critical/high CVE count | Yes | `findings_open.critical`/`.high` | Overview ("Open findings by severity" card) | |
| CIS/compliance score | Yes | `cis_score_current`, `cis_trend` | Overview (dial + trend cards) | |
| Stale endpoints | Partial | `annotate_staleness()` | `/devices` page only | Count/filter exist on the Devices page; not surfaced as an overview infocard |
| Hardware health warnings (battery, disk SMART, low storage) | No | — | — | No hardware fields anywhere in portal payloads consumed |
| Encryption posture (FileVault/BitLocker off, unencrypted removable storage) | Partial | `device.encryption_ok` | Devices list column + device-detail pill | Per-device only; no estate-wide "N devices unencrypted" card, no removable-storage signal |
| Patch/update status (pending, failed) | Yes | `patch_status.up_to_date/.pending/.failed` | Overview ("Patch status" card) | |
| Browser extension risk | No | — | — | Feature (Browser Extension Control) not yet shipped per the admin catalogue description |
| App policy drift | No | — | — | |
| EDR/security tooling coverage gaps | No | — | — | |
| Local admin / privileged access exposure | No | — | — | |
| Certificate expiry (expired, ≤7d, ≤30d) | No | — | — | |
| Agent health (last check-in, offline/errored) | Partial | `devices_reporting_24h` | Overview ("Devices reporting" card) | Gives a reporting-rate proxy; no explicit "N agents offline/errored" framing |

This audit deliberately stops short of recommending placement, copy,
tier-gating, or privacy handling for the missing/partial cards — that design
work belongs in whichever follow-up ticket(s) get filed from this inventory,
per the ticket's own scope note ("not a build task").
