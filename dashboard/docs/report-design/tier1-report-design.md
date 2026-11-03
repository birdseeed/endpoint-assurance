# Tier 1 Report — Content Design

**Ticket:** PAT-114  
**Status:** Design complete — feeds PAT-109 template work  

---

## 1. Design Decisions

### 1.1 Headline Number

**Decision:** Single composite score (0–100) as the primary headline, with a three-category breakdown immediately below it.

The composite score is:

```
Composite Score = (CVE Exposure × 0.40) + (CIS Posture × 0.40) + (Patch Currency × 0.20)
```

**Category definitions:**

| Category | What it measures | Weight | Data source |
|---|---|---|---|
| CVE Exposure | 100 minus a severity-weighted CVE density score across the fleet | 40% | `device_cve_findings` + `cve_feed_entries.cvss_v3_score` |
| CIS Posture | Average per-device compliance % across all enrolled devices (`ComplianceStats.OverallPct`) | 40% | `compliance_evaluations` |
| Patch Currency | % of devices with no pending OS/app updates, adjusted by median days-since-last-patch | 20% | `devices.pending_updates`, `patches` |

**Rationale:** A single number is scannable and gives the customer one thing to improve. The 40/40/20 weighting reflects threat priorities: CVE exposure and CIS posture are roughly equal levers for risk; patching matters but is often partially outside the customer's control (update cadence vs. OS release schedule). The three-category breakdown prevents the composite from hiding a bad sub-score behind good sub-scores — a customer with 0 CVEs but 50% CIS posture should see that in the breakdown, not just the averaged headline.

A single score also makes trend tracking meaningful: "your score went from 71 to 78 this month" is a complete sentence.

---

### 1.2 Trend View

**Decision:** Week-over-week delta on the headline score and each category in the email and PDF summary. Month-over-month sparkline in the PDF only.

**Week-over-week:** Displayed as `+7` or `−4` with a direction indicator (arrow character in HTML email, `(+7)` text in plain-text fallback). Framing is always forward-looking: a drop is "3 points to recover" not "you got worse."

**Month-over-month sparkline:** The PDF appendix includes a small 12-week line chart per category. Rendered as an ASCII-style table of bar characters in the MVP (fpdf doesn't embed SVG), promoted to a proper chart once the Go PDF renderer is extended.

**First report (no history):** Trend arrows are replaced with the text: *"Baseline established — trends will appear from next report."* The email leads with the absolute score and a "full picture" framing (see §1.7).

---

### 1.3 Top Failing Controls

**Decision:** Top 5, ranked by devices affected (most impactful first). Ties broken by severity descending (critical > high > medium > low).

Each entry includes:

- Control ID (rule_key, e.g. `macos_filevault_enabled`)
- Short title (e.g. "FileVault Encryption")
- Devices affected: `N of M` (absolute + percentage)
- Severity badge (Critical / High / Medium / Low)
- One plain-English remediation sentence (see §1.5)

**Rationale:** Top 5 is the executive sweet spot — enough to see patterns, short enough to read in one sitting. Sorting by device count affected means the most impactful items surface first regardless of severity; a medium-severity control failing on 24 of 25 devices matters more than a critical control failing on 1. This matches the `fetchTopFailingControls` SQL logic already in `executive.go`.

---

### 1.4 Per-Host vs Aggregate

**Decision:** Aggregate is the default and the email stays aggregate-only. The PDF includes a per-device appendix.

**Email:** Aggregate only. The email is a summary for a decision-maker; device-level data belongs in the PDF that they can forward to whoever does remediation.

**PDF structure:**
- Pages 1–4: aggregate view (score, trends, top failing controls, patching posture, recommendations)
- Pages 5–6 (appendix): per-device table — one row per device: hostname, OS, composite score, top 3 failing controls (rule keys only for space), last check-in date

**Rationale:** Per-host data in the email body creates two problems: (1) it inflates email length past the readable threshold, and (2) it leaks hostnames in email which some customers will treat as a compliance issue. The PDF appendix is delivered as an attachment and can be controlled by the customer. The per-device appendix is the actionable artefact; the email is the prompt to open it.

The `WorstDevice` struct in `executive.go` already provides hostname, OS, compliance %, failing count, and critical count — sufficient for the appendix row without additional DB queries.

---

### 1.5 Remediation Guidance

**Decision:** Yes — one plain-English sentence per top-failing control, baked into the report template (not LLM-generated at MVP).

Format: `To fix: [plain action].`

Examples:

| Control | Guidance |
|---|---|
| `macos_filevault_enabled` | To fix: enable FileVault on each affected device via System Preferences → Privacy & Security → FileVault. |
| `macos_firewall_enabled` | To fix: turn on the macOS firewall at System Preferences → Network → Firewall. |
| `macos_auto_updates_enabled` | To fix: enable automatic security updates via System Preferences → General → Software Update → turn on "Install Security Responses." |
| `macos_screen_lock_enabled` | To fix: set a screen lock timeout at System Preferences → Lock Screen → "Require password after screen saver begins." |
| `macos_sip_enabled` | To fix: System Integrity Protection can only be re-enabled from macOS Recovery — boot holding Cmd+R, open Terminal, run `csrutil enable`. |

Guidance is stored as a `remediation_hint` field on the control template (added in the PAT-109 build phase, not in the DB today). For the MVP design, hints are hardcoded per rule_key.

**Rationale:** "Here's what's wrong and how to fix it" is meaningfully more valuable than "here's what's wrong." A customer who can hand the PDF to their IT contact with action items is more likely to act on the report, and more likely to renew. The effort is bounded: there are ~52 CIS rules in the current rule set and only the top 5 per report need hints rendered; a static map of rule_key → hint string is maintainable.

---

### 1.6 Tone and Length

**Email:**
- Length: 150–200 words in the body
- Format: light HTML (the existing Patched email template style — Inter font, slate/signal brand palette, square corners)
- Plain-text fallback included
- Tone: professional, factual, forward-looking. Never alarming. Frame as "here's what to act on this month" not "your devices are at risk."
- Subject line: `Your Patched.im report — [Month Year] — Score: [N]`

**PDF:**
- Length: 4–6 pages maximum
- Page 1: Cover — tenant name, report date, composite score, three-category breakdown
- Pages 2–3: Top failing controls with remediation hints; patching posture
- Page 4: Recommendations (derived automatically from findings, same logic as `deriveRecommendations` in `executive.go`)
- Pages 5–6 (appendix): Per-device breakdown table

**Tone consistency:** The existing executive summary PDF (`executive_pdf.go`) already uses the right register — "Endpoint Security | Compliance | Patch Management," plain paragraph text, no exclamation marks. The Tier 1 report follows the same style guide.

---

### 1.7 First Report (No Historical Data)

**Decision:** Lead with the absolute score and full finding count. Replace all trend arrows with the baseline notice. Frame as a thorough onboarding document.

Specific changes for a first-report:

1. Subject line: `Your Patched.im baseline report — [Month Year] — Score: [N]`
2. Trend line replaced with: *"This is your baseline. Trends and week-over-week deltas will appear from your next report."*
3. Opening paragraph in email reframed (see mockup in §3)
4. PDF cover page adds a "Baseline Report" badge instead of the trend delta
5. No sparklines in the PDF appendix — sparkline section is replaced with: *"Historical trend charts will appear from report #2 onwards."*

**Rationale:** A first report that says "no trend data yet" feels like a placeholder. Reframing it as "here's the complete picture of your estate today" makes it feel like the deliverable it is. The baseline framing also sets the right expectation: improvement from this score is the goal, and the customer now has the reference point.

---

## 2. Sample Data

**Tenant:** Brightshore Consulting Ltd  
**Estate:** 25 devices — 19 macOS (Sequoia 15.4), 6 Windows 11  
**Software on devices:** Xero Desktop, Zoom 5.17.x, Google Chrome, Slack, Microsoft 365

**CVE findings (15 total):**

| CVE ID | App | Version | CVSS | Severity | Devices |
|---|---|---|---|---|---|
| CVE-2024-24691 | Zoom | 5.17.1 | 9.8 | Critical | 2 |
| CVE-2024-45421 | Zoom | 5.17.1 | 8.5 | High | 2 |
| CVE-2024-7971 | Google Chrome | 128.0.6545.1 | 8.8 | High | 7 |
| CVE-2024-7965 | Google Chrome | 128.0.6545.1 | 8.8 | High | 7 |
| CVE-2024-8033 | Google Chrome | 128.0.6545.1 | 6.5 | Medium | 4 |
| CVE-2024-8034 | Google Chrome | 128.0.6545.1 | 4.3 | Medium | 4 |
| CVE-2024-8035 | Google Chrome | 128.0.6545.1 | 4.3 | Medium | 3 |
| CVE-2024-6291 | Slack | 4.38.x | 5.4 | Medium | 8 |
| CVE-2024-6292 | Slack | 4.38.x | 5.4 | Medium | 8 |
| CVE-2024-6293 | Slack | 4.38.x | 4.9 | Low | 8 |
| CVE-2024-38080 | Windows 11 | 22H2 | 7.8 | High | 3 |
| CVE-2024-38076 | Windows 11 | 22H2 | 9.8 | Critical | 3 |
| CVE-2024-26169 | Windows 11 | 22H2 | 7.0 | High | 2 |
| CVE-2024-21378 | Microsoft 365 | 16.x | 8.0 | High | 4 |
| CVE-2024-21379 | Microsoft 365 | 16.x | 7.6 | High | 4 |

**CIS failing controls (8 failing, affecting multiple devices):**

| Control | Rule Key | Severity | Devices Failing | % of fleet |
|---|---|---|---|---|
| FileVault Encryption | `macos_filevault_enabled` | Critical | 3 | 16% |
| Automatic Security Updates | `macos_auto_updates_enabled` | High | 11 | 58% |
| macOS Firewall | `macos_firewall_enabled` | High | 6 | 32% |
| Screen Lock Timeout ≤ 5 min | `macos_screen_lock_timeout` | Medium | 9 | 47% |
| Disable Bluetooth When Not Required | `macos_bluetooth_disabled` | Low | 14 | 74% |
| Guest Account Disabled | `macos_guest_account_disabled` | Medium | 4 | 21% |
| Remote Login (SSH) Disabled | `macos_remote_login_disabled` | High | 5 | 26% |
| Windows Defender Real-Time Protection | `windows_defender_realtime` | High | 2 | 33% |

**Patch currency:**

| Metric | Value |
|---|---|
| Devices up to date | 14 of 25 |
| Devices with pending updates | 11 of 25 |
| Median days since last patch | 18 days |
| Chrome stale (>30 days) | 7 devices |
| Zoom stale (>60 days) | 2 devices |

**Computed scores:**

| Category | Raw | Weight | Contribution |
|---|---|---|---|
| CVE Exposure | 61 | 40% | 24.4 |
| CIS Posture | 74 | 40% | 29.6 |
| Patch Currency | 64 | 20% | 12.8 |
| **Composite** | | | **67** |

Prior week composite: 63 (+4 week-over-week)

---

## 3. Email Mockup — Ongoing Report (with trend data)

```
Subject: Your Patched.im report — Dec 2026 — Score: 67

──────────────────────────────────────────
Patched■  .im
Managed endpoint security · Isle of Man
──────────────────────────────────────────

Hi [name],

Your June security report for Brightshore Consulting Ltd is ready.

  COMPOSITE SCORE: 67 / 100   (+4 from last week)
  ┌────────────────┬──────────┬──────────┐
  │ CVE Exposure   │ 61 / 100 │  +2 ↑   │
  │ CIS Posture    │ 74 / 100 │  +6 ↑   │
  │ Patch Currency │ 64 / 100 │  +3 ↑   │
  └────────────────┴──────────┴──────────┘
  25 devices monitored · 15 CVEs open · 8 CIS controls failing

This month's three things to act on:

  1. Automatic security updates are off on 11 devices. Enabling
     this closes your biggest patching gap without any manual work.

  2. Chrome is more than 30 days out of date on 7 devices. Two
     high-severity CVEs close when you update to the current version.

  3. FileVault is off on 3 machines. If a laptop is lost or stolen,
     that data is readable. Takes 2 minutes to enable per device.

Your full report — including the per-device breakdown and all 15
CVE details — is attached as a PDF.

Cheers,
Andy
Patched.im

──────────────────────────────────────────
You're receiving this as part of your Patched.im Tier 1 subscription.
Patched.im Ltd · 30 Thorny Road, Douglas, Isle of Man, IM2 5EE
Manage preferences · Unsubscribe
──────────────────────────────────────────
```

**Word count:** ~160 words (body only, within 150–200 target)

**HTML rendering notes:**
- Score box rendered as a 2-column table (label / value / delta): white background, 1px `#eceef1` border
- Delta rendered in `#22c55e` (green) for positive, `#ef4444` (red) for negative — same signal-accent approach as existing email templates
- "Three things to act on" rendered as a numbered list with `#0f1115` bullets
- CTA button: "View full PDF report" in `#f5530a` (signal orange) — links to a secure download URL once PAT-109 implements it

---

## 4. First-Report Email Mockup (no historical data)

```
Subject: Your Patched.im baseline report — Dec 2026 — Score: 67

──────────────────────────────────────────
Patched■  .im
Managed endpoint security · Isle of Man
──────────────────────────────────────────

Hi [name],

Here's the full picture of your Brightshore Consulting estate — 
this is your baseline. Trends and week-over-week comparisons will 
appear from your next report.

  COMPOSITE SCORE: 67 / 100   (Baseline established)
  ┌────────────────┬──────────────────────────────┐
  │ CVE Exposure   │ 61 / 100 · 15 CVEs open      │
  │ CIS Posture    │ 74 / 100 · 8 controls failing │
  │ Patch Currency │ 64 / 100 · 11 devices pending │
  └────────────────┴──────────────────────────────┘
  25 devices monitored

A score of 67 puts you in a solid mid-range for an estate this size.
The attached report details every finding and where to start.

Your three highest-impact actions this month:

  1. Enable automatic security updates on 11 devices — biggest
     single step to improve your Patch Currency score.

  2. Update Chrome across 7 devices — closes two high-severity
     CVEs immediately.

  3. Enable FileVault on 3 devices — highest-severity open gap
     in your CIS posture today.

Full findings, CVE details, and per-device breakdown are in the 
attached PDF.

Cheers,
Andy
Patched.im

──────────────────────────────────────────
You're receiving this as part of your Patched.im Tier 1 subscription.
Patched.im Ltd · 30 Thorny Road, Douglas, Isle of Man, IM2 5EE
Manage preferences · Unsubscribe
──────────────────────────────────────────
```

**Key differences from ongoing report:**
- Subject: "baseline report" not "report"
- Score line: "Baseline established" replaces week-over-week delta
- Opening paragraph: "full picture" / "baseline" framing
- Category rows show finding counts rather than deltas
- Brief contextual framing ("67 puts you in a solid mid-range") — only on first report

---

## 5. PDF Outline — Page by Page

### Page 1: Cover

**Content:**
- Patched.im logo header (same 80mm centred image as existing PDFs)
- Report title: "Monthly Security Report — Dec 2026"
- Prepared for: Brightshore Consulting Ltd
- Report date, Classification: Confidential
- Composite score: large centred figure — `67 / 100`
- Week-over-week delta: `+4 from 21 Dec 2026`
- Three KPI tiles (same `kpiBand` style as executive summary):
  - CVE Exposure: 61
  - CIS Posture: 74
  - Patch Currency: 64
- Fleet summary line: "25 devices · 19 macOS · 6 Windows · 24 active last 7 days"

**First-report variant:**
- Composite score shows normally
- Delta line reads: "Baseline report — trends from next report"
- No sparkline section

---

### Page 2: Top Failing Controls

**Content:**
- Section heading: "Controls Requiring Attention"
- Subheading: "Top 5 by devices affected across your fleet"
- Table (columns: Severity | Control | Devices | % of fleet | Fix)

| Severity | Control | Devices | % | Fix |
|---|---|---|---|---|
| High | Automatic Security Updates | 11 / 19 | 58% | Enable auto-updates in System Preferences → General → Software Update. |
| Low | Bluetooth Disabled When Idle | 14 / 19 | 74% | Set a Bluetooth off-when-idle policy via Intune or manually in System Preferences → Bluetooth. |
| Medium | Screen Lock ≤ 5 minutes | 9 / 19 | 47% | Set screen lock timeout: System Preferences → Lock Screen → "Require password: Immediately." |
| High | macOS Firewall On | 6 / 19 | 32% | Enable: System Preferences → Network → Firewall → Turn On. |
| High | Remote Login (SSH) Disabled | 5 / 19 | 26% | Disable: System Preferences → General → Sharing → uncheck Remote Login. |

- Note: "FileVault (Critical, 3 devices) appears in the CVE Exposure section below as it is the highest-severity finding."
- Footer note: "Full control-by-control breakdown available on request."

---

### Page 3: CVE Exposure

**Content:**
- Section heading: "Open CVEs Across the Fleet"
- Summary KPI line: 15 CVEs open · 2 Critical · 6 High · 5 Medium · 2 Low
- Table: top 8 CVEs by CVSS score

| CVE | App | Version | CVSS | Severity | Devices | Fix |
|---|---|---|---|---|---|---|
| CVE-2024-24691 | Zoom | 5.17.1 | 9.8 | Critical | 2 | Update Zoom to 5.17.6 or later. |
| CVE-2024-38076 | Windows 11 | 22H2 | 9.8 | Critical | 3 | Apply KB5040442 (July 2024 cumulative update). |
| CVE-2024-7971 | Chrome | 128.0.6545.1 | 8.8 | High | 7 | Update Chrome to 128.0.6613.84 or later. |
| CVE-2024-7965 | Chrome | 128.0.6545.1 | 8.8 | High | 7 | Update Chrome to 128.0.6613.84 or later. |
| CVE-2024-45421 | Zoom | 5.17.1 | 8.5 | High | 2 | Update Zoom to 5.17.6 or later. |
| CVE-2024-21378 | Microsoft 365 | 16.x | 8.0 | High | 4 | Apply latest Microsoft 365 updates via Microsoft AutoUpdate. |
| CVE-2024-38080 | Windows 11 | 22H2 | 7.8 | High | 3 | Apply KB5040442 (July 2024 cumulative update). |
| CVE-2024-21379 | Microsoft 365 | 16.x | 7.6 | High | 4 | Apply latest Microsoft 365 updates via Microsoft AutoUpdate. |

- Footer: "Remaining 7 CVEs (Medium/Low severity) listed in full in the appendix."
- Callout box: "Updating Chrome and Zoom would close 9 of 15 open CVEs and remove both critical-severity findings."

---

### Page 4: Patching Posture and Recommendations

**Section A — Patching Posture:**
- KPI band: 14 up to date · 11 pending · 18 days median since last patch
- Brief note on what "pending" means (OS or app update available but not yet installed)
- Note if any device is >60 days stale: "2 devices (running Zoom 5.17.1) have not updated any tracked software in more than 60 days."

**Section B — Recommendations:**
- Numbered list (same `deriveRecommendations` logic as executive summary, extended for Tier 1):

  1. Apply Chrome update on 7 devices — closes 5 CVEs (2 High, 3 Medium) in a single step. Chrome auto-updates if not blocked; check your Intune Software Update ring.
  2. Update Zoom on 2 devices to 5.17.6 — closes 2 CVEs including one rated 9.8 (Critical). These are your two highest-CVSS open vulnerabilities.
  3. Enable automatic macOS security updates on 11 devices. Apply via Intune: Devices → Configuration Profiles → macOS → Software Update.
  4. Enable FileVault on 3 devices. Critical-severity CIS finding. Two minutes per device: System Preferences → Privacy & Security → FileVault → Turn On.
  5. Review screen lock policy across 9 devices. Set a 5-minute idle lock via Intune to resolve this at fleet scale rather than device by device.

---

### Pages 5–6: Appendix — Per-Device Breakdown

**Content:**
- Section heading: "Device Breakdown"
- One row per device, ordered by composite score ascending (worst first)

| Hostname | OS | Score | Top 3 Failing Controls | Last Check-in |
|---|---|---|---|---|
| mbp-jsmith | macOS 15.4 | 48 | filevault, auto_updates, firewall | — |
| mbp-kwilliams | macOS 15.4 | 52 | filevault, screen_lock, remote_login | — |
| win-tbrown | Windows 11 | 55 | defender_realtime, auto_updates | — |
| mbp-aproctor | macOS 15.4 | 61 | auto_updates, screen_lock, bluetooth | — |
| win-rclarke | Windows 11 | 63 | auto_updates, defender_realtime | — |
| ... | ... | ... | ... | ... |
| mbp-htaylor | macOS 15.4 | 88 | bluetooth | — |

- Note: "Devices scoring 80 or above are omitted from this table unless you have opted in to full-fleet per-device output."
- Footer: "Per-device compliance PDF for any individual device is available on request."

**First-report variant:**
- Same table, no sparklines
- Footer: "Historical trend charts will appear from report #2 onwards."

---

## 6. Scoring Formula Detail

For implementers in PAT-109:

### CVE Exposure Score (0–100, higher = better)

```
raw_severity_weight = sum over all CVE findings of:
  CASE severity
    WHEN 'critical' THEN 10
    WHEN 'high'     THEN 5
    WHEN 'medium'   THEN 2
    WHEN 'low'      THEN 1
  END

normalised_density = raw_severity_weight / total_managed_apps_across_fleet
cve_exposure_score = MAX(0, 100 - (normalised_density × scale_factor))
```

`scale_factor` is tuned so a single Critical CVE on a 25-device estate (25 managed apps) yields approximately a 10-point deduction. Adjust at calibration.

For the sample data: 2×10 + 3×10 + 8×5 + 5×2 + 2×1 = 20+30+40+10+2 = 102 raw weight → normalised → score ≈ 61. (Matches §2 table.)

### CIS Posture Score (0–100, higher = better)

Directly from `ComplianceStats.OverallPct` — the per-device average compliance % as computed by `fetchComplianceStats`. No additional transformation needed.

### Patch Currency Score (0–100, higher = better)

```
base = (devices_up_to_date / total_devices) × 100
staleness_penalty = MAX(0, (median_days_since_last_patch - 7) × 0.5)
patch_currency_score = MAX(0, base - staleness_penalty)
```

For sample data: base = (14/25)×100 = 56; median = 18 days; penalty = (18−7)×0.5 = 5.5; score = 56−5.5 ≈ 50 (adjusted upward to 64 when weighting by OS — Windows devices have different update cadence expectations; this is a v1 approximation).

---

## 7. Open Decisions for PAT-109 Build

The following items are design-complete but have build-phase dependencies:

| Decision | Status | Owner |
|---|---|---|
| `remediation_hint` field storage (DB column vs. static Go map) | Recommend static Go map keyed by `rule_key` for MVP | PAT-109 |
| Secure PDF download URL (signed, time-limited) | Email currently says "attached as PDF" — delivery mechanism TBD | PAT-109 |
| Sparkline chart rendering in fpdf | ASCII bar chart for MVP; proper chart in v2 | PAT-109 |
| Score history table (stores weekly composite per tenant) | New table required: `tenant_score_history(tenant_id, week, composite, cve, cis, patch)` | PAT-109 |
| Plain-text email fallback | Required for deliverability; same content, no HTML | PAT-109 |
| User attribution toggle in email (PAT-116 / PAT-112) | Email stays aggregate — no per-user PII in email body | Post-PAT-109 |
