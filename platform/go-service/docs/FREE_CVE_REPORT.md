# Free CVE Report — format specification

**format_version: v2.2** (PAT-1871, 2026-09-20)

This document defines the canonical layout and content contract for the patched.im
Free CVE Vulnerability Assessment PDF. The platform is the authoritative renderer;
the dashboard and scan module consume the output but do not render it themselves.

---

## Version history

| Version | Date | Notes |
|---|---|---|
| `v1` | — | Initial frozen spec (PAT-326). Sections 1–7, confidence classification, NVD source, footer. |
| `v1.1` | — | PAT-439. Adds Section 8 "What happens next" closing page. Bumps footer to `format v1.1`. No struct changes; all prior fields are unchanged. |
| `v2.0` | 2026-08-06 | PAT-1205. Part 2 restructured: the old flat, severity-banded per-hit table is replaced by a ranked Remediation Plan (one action per affected app, sorted by severity impact) plus a Possibly Affected section for unconfirmed findings; the old table survives verbatim as Appendix A. `CVEHit` gains `FixedVersion` (the NVD fix-target version, when known). Real structural/contract change — bumps footer to `format v2.0`. |
| `v2.1` | 2026-09-20 | PAT-1853. Each rendered non-empty CVE description now carries explicit NVD, MSRC, or Apple provenance. The methodology no longer claims all description text is NVD-sourced. Apple vendor-only CVEs remain descriptionless when Apple supplies no per-CVE title and NVD has no description. |
| `v2.2` | 2026-09-20 | PAT-1871. Adds a tri-state exploitation-evidence section. An active-exploitation claim now requires fresh, exact-CVE CISA KEV or SOFA evidence with source, retrieval time and match basis. Severity and CVSS cannot set it; missing, failed or stale authority renders as Unknown. |

---

## Sections (in order)

### 1. Cover / branding
- patched.im branded header image (shared with compliance reports)
- Tagline: "Endpoint Security | Compliance | Patch Management"
- Title: **"Free CVE Vulnerability Assessment"**
- "Prepared for: `<tenant name>`" block
- Generated-at timestamp (UTC, format: `02 Jan 2006 15:04 UTC`)
- Horizontal rule

### 2. Methodology note
Short paragraph (3–4 lines) explaining:
- CVE data sourced from the NIST National Vulnerability Database (NVD) API 2.0
- App-to-CVE matching via curated CPE mappings against device inventory
- Two confidence levels (see Section 3)
- Findings refreshed nightly; snapshot date shown in footer

For vendor-confirmed operating-system findings, a rendered description is
explicitly labelled with its source. Apple vendor-only CVEs with no per-CVE
Apple title and no NVD description remain deliberately descriptionless; the
report does not infer or invent an Apple description.

### 3. Confidence classification
Visible callout box or table with two rows:

| Confidence | Meaning |
|---|---|
| **Version confirmed** | Installed version falls within a known NVD vulnerable version range. High confidence. |
| **Version not verified** | Product matches a CVE but NVD provides no usable version-range data. Potentially affected — manual verification recommended. |

### 4. Executive summary
Table: count of CVEs by severity band.

| Severity | CVEs | Confirmed | Unverified |
|---|---|---|---|
| CRITICAL | N | N | N |
| HIGH | N | N | N |
| MEDIUM | N | N | N |
| LOW | N | N | N |
| **Total** | **N** | **N** | **N** |

### 5. Remediation Plan (v2.0)

Confirmed findings (`match_confidence` of `version_confirmed` or
`version_vendor_confirmed`) are folded into one ranked action per affected
application via `report.BuildCVEActions`, instead of one row per (device, app,
CVE) hit. Grouping key is the app name exactly as it appears in the data — no
fuzzy/cross-version normalisation.

**Section heading:** `Remediation Plan — N actions clear X of Y findings (Z%)`,
where X is the confirmed-hit count, Y is confirmed + unverified hits, and Z is
`round(100 * X / Y)`. This same percentage is echoed as a headline sentence in
the Section 4 executive-summary narrative, so the two numbers can never drift
apart (`remediationCoveragePct`).

**Summary table columns:** Action (numbered, "N. AppName → TargetVersion") |
Devices | CVEs | Worst severity | Top CVSS.

**Ordering** (fully deterministic, no map iteration in the output): actions
sorted by CriticalCount desc, then HighCount desc, then total CVE count desc,
then device count desc, then AppName asc.

**Per-action block**, one per action, in the order above:
- Heading: `N. Update {AppName} → {TargetVersion or "latest vendor release"}`
- Stat line: device count, CVE count with severity breakdown, top CVSS
- Wrapped device list: hostname + installed version, deduped by hostname,
  sorted by hostname ascending
- Compact per-CVE table: CVE ID, CVSS, Severity, Description (truncated),
  Confidence — CVEs sorted by severity band then CVE ID ascending

`TargetVersion` is `max(FixedVersion)` (via `cvematch.CompareVersions`) across
every confirmed hit backing the action, skipping empty strings; `""` when no
hit in the group carries a known `FixedVersion`, rendered as "latest vendor
release". `FixedVersion` itself is `CPERange.VEndExcl` from the NVD range that
matched the finding (`cvematch.versionInRange`) — the first version NOT
vulnerable.

### 5a. Possibly Affected — Verify Manually (v2.0)

Findings with `match_confidence == "version_unverified"` — NVD has no usable
version-range data to confirm or exclude the installed version — are split out
per app into `report.CVEUnverifiedGroup` entries, sorted by app name
ascending. One summary row per group: App | Devices | CVEs | Worst severity.
No per-CVE table (kept terse; this section exists so unconfirmed findings
aren't lost, not to duplicate the Remediation Plan's depth).

The import-scan path has no device OS, so it matches with an unknown platform
and applies no platform filter (PAT-2107). The age cut does apply: a CVE with
no usable version data that was published more than three years before the
scan is not listed as possibly affected.

A CVE can be confirmed for one device and unverified for another (e.g. an
unparseable installed-version string on one device but not another); its hits
are split accordingly, so the same CVE can appear in both an app's
Remediation Plan action and its Possibly Affected group.

### 6. Footnote — confidence disclaimer
> _"Possibly affected" findings indicate that the installed product matches a CVE
> in the NVD database, but no authoritative version-range data is available to
> confirm or exclude the specific installed version. These findings should be
> reviewed manually. patched.im recommends updating to the latest vendor-released
> version._

### 6a. Exploitation evidence (v2.2)

One row per CVE records `Known exploited`, `Not listed`, or `Unknown`, followed
by its authoritative source, source retrieval time and CVE match basis. A fresh
exact-CVE match in CISA KEV or SOFA is required for `Known exploited`.
`Not listed` requires fresh, successfully parsed CISA KEV and SOFA sources and
is rendered with explicit absence evidence from both. A missing, failed or
older-than-48-hours state for either source renders `Unknown` with the
availability reason. Severity and CVSS are deliberately excluded from this
decision.

### 7. Closing / footer
- Page X / Y (right-aligned, in page footer)
- Final line at bottom of technical-findings page:
  `Generated by patched.im | format v2.2 | <generated-at UTC>`

### 8. Appendix A — Full Findings (v2.0; renamed from "Findings" at v1)

The pre-v2.0 flat findings table, unchanged, demoted to an appendix and forced
onto its own page — after the footer above, before "What happens next" — so
it reads as reference material behind the Remediation Plan and Possibly
Affected sections, not the main content.

One sub-section per severity band (CRITICAL → HIGH → MEDIUM → LOW), rendered only
when that band has at least one CVE. Each sub-section contains a table of CVEs in
that band, ordered by CVE ID ascending.

**Findings table columns:**

| CVE ID | CVSS | Description (truncated) | Affected app | Version | Confidence |
|---|---|---|---|---|---|
| CVE-2024-… | 9.8 | A heap buffer overflow… | Google Chrome | 120.0.6099.130 | **Confirmed** |
| CVE-2024-… | 7.5 | Memory corruption in… | Dropbox | 180.4 | *Possibly affected* |

**Rendering rules:**
- `version_confirmed` renders as bold "Confirmed" in the Confidence column
- `version_unverified` renders as italic "Possibly affected" in the Confidence column
- Description truncated to 80 chars
- If a CVE affects multiple devices, repeat the row for each (device, app) pair
- Each row shows the device hostname alongside the app

### 9. What happens next (v1.1)

New final page, appended after the methodology note. Findings pages are unchanged — the commercial content is quarantined here so the advisory artifact stays neutral.

**Structure:**

- Kicker: `05 · What happens next`
- Title: "From a one-off scan to an estate that stays clear"
- Short intro paragraph (point-in-time framing)
- Three tier rungs — each rendered with a left accent bar, number, name, status badge, flow caption, and description:

| No | Name | Flow | Status badge source |
|---|---|---|---|
| 01 | Report | Scan + Prove | `TierStatuses.Report` |
| 02 | Patch & Deploy | Scan + Patch + Prove | `TierStatuses.PatchAndDeploy` |
| 03 | Full Endpoint Management | Configuration + policy enforcement | `TierStatuses.FullEndpointManagement` |

- CTA block (dark slate panel): "Want a hand reading your results?" with booking link `CVEReportCTAURL`, reply-to `scans@patched.im`, CAN-SPAM address.

**Rung status config** (`go-service/internal/report/cve_report.go`):

```go
var TierStatuses = struct { ... }{
    Report:                 TierStatusAvailable,   // flip to TierStatusComingSoon if needed
    PatchAndDeploy:         TierStatusComingSoon,  // flip to TierStatusAvailable when tier ships
    FullEndpointManagement: TierStatusComingSoon,  // flip to TierStatusAvailable when tier ships
}
```

One-line change per tier. The PAT-440 go-live checklist is the gate for these flips.

---

## Determinism guarantee

Given identical input data, the renderer MUST produce byte-for-byte equivalent
output (stable ordering, no random IDs, no wall-clock timestamps beyond the
`GeneratedAt` field passed in). This ensures Stage 3 (test harness) can assert
section presence and counts against the format without flakiness. Enforced by
`TestRenderFreeCVEPDF_Determinism` (`internal/report/cve_report_test.go`),
added at PAT-1205.

`BuildCVEActions`' own ordering (see Section 5) carries the same guarantee: no
raw map iteration reaches its output, checked directly by
`TestBuildCVEActions_Determinism`.

PAT-1205 note: this guarantee did not actually hold at the byte level before
the determinism test was added — `go-pdf/fpdf` ranges over internal Go maps
(fonts, font files, images) when emitting PDF objects, which randomises
object numbering run to run independent of any input to this renderer.
`RenderFreeCVEPDF` now calls `pdf.SetCatalogSort(true)`, which makes fpdf sort
those keys before emitting them. `SetCreationDate`/`SetModificationDate` are
also pinned to `GeneratedAt` (fpdf defaults both to `time.Now()` otherwise).
Both calls are load-bearing for this guarantee — do not remove them.

---

## Out of scope for v2.0

- CIS cross-reference (planned)
- KEV / CISA exploit-known overlay (planned)
- Email delivery (PAT-187, dashboard-side)
