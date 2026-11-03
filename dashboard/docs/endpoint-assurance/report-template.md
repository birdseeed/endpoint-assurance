# Endpoint Assurance - Assessment Report

**Template - PAT-1299.** For the specialist delivering the engagement: fill
every `[CUSTOMER NAME]`-style bracket, replace every `[specialist input
required: ...]` block with your own written judgement, and delete this line
before sending. Do not leave a placeholder in a delivered report. If a
section has nothing to report (for example no shadow-IT findings), say so
explicitly - "no shadow-IT applications identified in the assessment period"
is a finding, not a gap to delete.

**What this report is not.** A free CVE scan reads a single file the
prospect sends us and lists what it finds, once. This report is built from
weeks of instrumented observation of the customer's real estate, plus your
own written judgement about what to fix first and why. If a paragraph in
this report could have come out of the free scan, cut it or add the
judgement that makes it worth paying for.

---

## Cover

| Field | Value |
|---|---|
| Prepared for | [CUSTOMER NAME] |
| Prepared by | [SPECIALIST NAME], Patched.im |
| Assessment period | [START DATE] to [END DATE] |
| Devices in scope | [N] devices ([N] macOS, [N] Windows) |
| Report date | [REPORT DATE] |
| Classification | Confidential - prepared for [CUSTOMER NAME] only |

This report is delivered to [CUSTOMER NAME] over a signed, time-limited
download link (`GET /reports/download/{token}`, PAT-370). The link expires
after first use or [specialist input required: confirm the configured
expiry window]. Do not email this document as an attachment or forward the
link outside the named recipient.

**Commercial terms** (confirm against the current signed order - the
authoritative copy of these terms lives in the engagement letter, PAT-1300,
not here): this assessment fee is credited in full against onboarding if a
Managed Patching or Full Endpoint Management retainer starts within 90 days
of this report date. [specialist input required: confirm the 90-day window
start date and credit amount against the signed order for this engagement.]

---

## 1. Executive summary

*Written for a finance director or MLRO, not an engineer. No tool names,
no CVE identifiers, no jargon a non-technical reader has to look up. Three
things only, in plain money and plain risk.*

**What would fail an audit.**
[specialist input required: one paragraph, plain language. Name the
specific control gap in terms an auditor would write it up as - e.g.
"[N] of [N] laptops can be used to install software or change security
settings without IT approval, which a Cyber Essentials or ISO 27001
auditor would record as a failed access control." Do not use CVE IDs,
CVSS scores, or product version numbers here - those belong in Section 2.]

**What would fail an insurer's renewal questions.**
[specialist input required: one paragraph. Cyber insurance renewal
questionnaires typically ask about patch cadence, admin rights, and
endpoint visibility in plain yes/no terms. State plainly which of those
questions [CUSTOMER NAME] could not currently answer "yes" to, and what
that exposure means in practice - e.g. "if asked whether all endpoints
are running supported, patched operating systems, the honest answer today
is no."]

**What it would cost to fix.**
[specialist input required: a single plain-money figure or range, broken
into (a) what a retainer removes as an ongoing service and (b) what stays
the customer's own cost regardless of retainer - e.g. software licence
renewals identified in Section 2.3 are the customer's spend either way;
Patched surfaces them, it does not pay them. Do not quote CVE-level detail
here - a total, and the shape of it.]

---

## 2. Findings by class, risk-ranked

List every finding within a class most severe first. Each finding states
what was observed, which framework control(s) it maps to, and what
"fixed" looks like. Do not invent a fourth finding class - CVE and
configuration posture, standing local-admin exposure, and licence/shadow-IT
visibility are the three this assessment produces from real collected
data. Anything else observed during the engagement that does not come
from one of these three data sources belongs in a **Specialist observation**
callout, clearly marked as professional judgement rather than a data
finding, not folded into one of the three classes as if it were.

### 2.1 CVE and configuration posture baseline

**What this is drawn from:** the endpoint agent's CVE match against the
NVD feed (`device_cve_findings`, scored against `cve_feed_entries.cvss_v3_score`)
and the CIS-derived configuration compliance check per device
(`compliance_evaluations`, aggregated as `ComplianceStats.OverallPct`) -
the same data sources behind the automated Tier 1 report (PAT-114). This
report adds the sequencing and judgement a generated score does not: which
finding to fix first, and why it matters more than the others on the list.

**Framework mapping**

| Framework | Control | Why it applies |
|---|---|---|
| Cyber Essentials | Security update management | CE requires security updates for all software applied within its patch cadence, and no software past vendor end-of-life. An open Critical/High CVE with a vendor fix available is a direct CE fail. |
| Cyber Essentials | Secure configuration | Failing CIS baseline controls (encryption, firewall, auto-update settings) are configuration weaknesses CE requires addressed as shipped, not left on manufacturer defaults. |
| ISO 27001 Annex A | A.8.8 - Management of technical vulnerabilities | Requires timely identification and remediation of technical vulnerabilities. An unpatched CVE with no tracked remediation plan is the control failing in practice. |
| ISO 27001 Annex A | A.8.9 - Configuration management | Requires configurations (including security configurations) to be established, documented, and monitored. A failing CIS control is a documented configuration-management gap. |
| UK GDPR | Article 32(1)(b) - security of processing | Requires the ability to ensure ongoing confidentiality, integrity, availability and resilience of processing systems. A device with an exploitable, unpatched vulnerability cannot be said to have that assurance. |

**Worked example** (fictional customer, illustrative values only):

> **Finding CVE-01 - Critical - Zoom 5.17.1 remote code execution (CVE-2024-24691, CVSS 9.8)**
> Present on 2 of 41 devices at Marlow & Vance Solicitors LLP
> (mvl-jsanderson, mvl-kwhitfield), both on the fee-earner VLAN with access
> to client case files. A vendor fix has shipped (5.17.6) and is not
> currently applied. This is the single highest-severity open finding in
> the estate and the fastest to close: no configuration change, one
> application update.
> *Maps to:* CE Security update management (fail); ISO 27001 A.8.8 (fail);
> GDPR Article 32(1)(b) (at risk - see Section 1).
>
> **Finding CFG-01 - High - FileVault disabled (`macos_filevault_enabled`)**
> 6 of 33 macOS devices at Marlow & Vance Solicitors LLP have full-disk
> encryption disabled, including two partner laptops that leave the office
> daily. A lost or stolen device in this state exposes every client file on
> it in plain text - this is the finding most likely to become a reportable
> data breach, not merely a compliance gap.
> *Maps to:* CE Secure configuration (fail); ISO 27001 A.8.9 (fail); GDPR
> Article 32(1)(b) (materially at risk for the affected devices).

[specialist input required: repeat this finding format for every CVE and
configuration finding in [CUSTOMER NAME]'s actual estate, most severe
first. Pull the underlying data from the CVE Findings and Compliance
Status tabs for this tenant.]

---

### 2.2 Standing local-admin exposure

**What this is drawn from:** the per-device admin-account count collected
by the endpoint agent, reported against the CIS macOS 5.8 control (and the
Windows equivalent) - the same data behind the Local Admin / Privileged
Access report proxy. This shows who *can* make unsupervised changes to a
device, independent of whether any CVE or CIS finding is currently open -
a clean CVE report on a device with standing admin rights is not evidence
of good posture, it is evidence the next mistake has nothing standing in
its way.

**Framework mapping**

| Framework | Control | Why it applies |
|---|---|---|
| Cyber Essentials | User access control | CE requires that administrative privileges are only given to staff who need them, used only for administrative tasks, and not used as the default day-to-day account. Standing local admin on a primary-user account fails this directly. |
| ISO 27001 Annex A | A.8.2 - Privileged access rights | Requires the allocation and use of privileged access rights to be restricted and managed. An account with unaudited, permanent local admin is privileged access that is neither restricted nor managed. |
| ISO 27001 Annex A | A.5.15 - Access control | The broader access control policy this specific technical control sits under - cite alongside A.8.2, not instead of it. |
| UK GDPR | Article 32(1)(b) and 32(4) - security of processing / staff access | Article 32(4) specifically requires steps to ensure anyone with access to personal data processes it only on instruction. Standing admin rights widen who can access, export, or alter data held on a device beyond what their role requires. |

**Worked example** (fictional customer, illustrative values only):

> **Finding ADM-01 - High - 23 of 41 devices (56%) run with a standing
> local-administrator account as the primary user profile**
> At Marlow & Vance Solicitors LLP, the majority of the estate has no
> separation between day-to-day use and administrative capability. This
> includes 4 of 6 devices used by support staff with no operational need
> for local admin at all. In practice this means a phishing payload or a
> malicious browser extension on any of these 23 devices runs with the
> same privilege as the person who set the machine up - no elevation
> prompt, no audit trail, no barrier. This is a single change that removes
> the largest share of "one mistake becomes a full compromise" risk in the
> estate, and it is independent of the patch and configuration work in
> Section 2.1.
> *Maps to:* CE User access control (fail); ISO 27001 A.8.2 and A.5.15
> (fail); GDPR Article 32(1)(b) and 32(4) (at risk).

[specialist input required: state the actual admin-account count and
percentage for [CUSTOMER NAME]'s estate, name any devices where standing
admin is a genuine operational requirement (and record that as an accepted
exception, not a finding), and rank remaining exposure by role sensitivity
- finance, legal, and anyone with access to regulated data first.]

---

### 2.3 Licence and shadow-IT visibility

**What this is drawn from:** two distinct data sources, both real and
both worth keeping separate rather than blurring into one paragraph -

- **Metering** - installed application inventory across the estate with
  last-used dates and launch counts per device, collected for licence
  reclaim purposes.
- **Shadow IT** - applications detected on the estate that do not match
  anything in the customer's approved app policy or the Patched software
  catalogue.

An app can appear in one of these without the other: a properly licensed
but unused seat is a metering finding, not a shadow-IT finding. An
unapproved app in active daily use is a shadow-IT finding regardless of
whether it costs anything. Do not conflate them in the write-up.

**Framework mapping**

| Framework | Control | Why it applies |
|---|---|---|
| Cyber Essentials | Secure configuration | CE requires unnecessary software to be removed or disabled, since anything installed is attack surface whether or not it is licensed. An unapproved application discovered outside the customer's policy is a direct instance of this. |
| ISO 27001 Annex A | A.5.9 - Inventory of information and other associated assets | Requires an inventory of assets, including software. An application the customer cannot account for is, by definition, missing from that inventory. |
| ISO 27001 Annex A | A.8.19 - Installation of software on operational systems | Requires rules governing the installation of software by users. Shadow IT found on the estate is direct evidence that rule is not currently enforced, whatever the customer's policy document says. |
| UK GDPR | Article 32(1)(b) and 32(2) - security of processing | Article 32(2) specifically calls out unauthorised access to, and processing of, personal data as a risk to weigh. An unmanaged application with no vetted data-handling terms and no visibility into what it does with local files is exactly that risk, independent of any CVE in it. |

**Worked example** (fictional customer, illustrative values only):

> **Finding LIC-01 - Medium - Adobe Acrobat Pro: 10 licensed seats, 14
> installs, 3 devices launched in the last 90 days**
> Marlow & Vance Solicitors LLP is both over-deployed against its licence
> count (14 installs against 10 seats - a compliance exposure if audited by
> the vendor) and carrying at least 7 reclaimable seats where the
> application has not been opened in 90 days. Net effect: right-sizing this
> one application closes the licence-compliance gap and removes ongoing
> spend on unused seats in the same action.
>
> **Finding SHD-01 - Medium - personal Dropbox accounts on 6 of 41 devices,
> active use on 4**
> Not part of the approved app policy, not provisioned or managed by IT,
> and in active daily use on 4 machines - meaning client files are most
> likely already being synced to storage outside the firm's control. This
> is the shadow-IT finding most likely to matter to an auditor or an
> insurer, because it is active data movement, not dormant software.
> *Maps to:* CE Secure configuration (fail); ISO 27001 A.5.9 and A.8.19
> (fail); GDPR Article 32(1)(b)/(2) (at risk - data exposure route, not
> merely a cost or governance issue).

[specialist input required: pull the actual metering and shadow-IT
findings for [CUSTOMER NAME] from the Software Metering and Shadow IT
tabs, list every application found, and separate licence-cost findings
from active-data-risk findings as in the worked example above - they read
very differently to a reader deciding what to act on first.]

---

## 3. Remediation plan, sequenced

State the order of work and why that order, not just a list. Each item
names exactly what Patched does under each retainer tier and what stays
with the customer regardless of tier. Do not blur that line - it is what
the customer is deciding whether to buy.

At the Endpoint Assurance tier alone (no retainer), Patched's work stops
at this report: the findings, the framework mapping, and this sequenced
plan. Applying any of the fixes below is not included at this tier - that
execution is what a retainer buys.

| Priority | Finding | Why this order | Endpoint Assurance only | Managed Patching | Full Endpoint Management |
|---|---|---|---|---|---|
| 1 | Critical/High CVEs with a vendor fix available (2.1) | Fastest to close, highest severity, no workflow change required - pure patching. | Reported and sequenced here. Customer's own IT/MSP applies the update. | Patched applies the fix: controlled patching from Patched-verified sources, staged to the agreed rollout plan. | Same as Managed Patching, plus the fix is folded into the standing CIS L1 baseline enforced through the customer's own Intune. |
| 2 | Failing CIS configuration controls (2.1) | Config fixes are usually free (a settings change, not a purchase) and close the specific gaps an auditor checks for by name. | Reported here, mapped to control. Customer's own IT/MSP applies the change. | Same reporting; fixing individual settings is not a Managed Patching deliverable - it is scoped as part of Full Endpoint Management's baseline. | Patched deploys and maintains the CIS L1 baseline directly in the customer's Intune; drift is reviewed and remediated on an agreed cadence. |
| 3 | Standing local-admin exposure (2.2) | The single change with the biggest effect on future incidents, but it requires a workflow (elevation process) rather than a one-off fix, so it follows the faster wins above. | Reported and ranked by role sensitivity here. Not actioned at this tier. | Not included - Managed Patching does not remove standing admin rights. | Patched removes standing local admin and manages audited just-in-time elevation in its place. |
| 4 | Licence right-sizing (2.3) | Cost recovery, not security risk - lowest urgency of the four, and the decision to cancel or reassign a licence is commercial, not technical. | Reported here with the reclaimable-seat figures. | Ongoing visibility via reports on demand and the Self Service App Catalogue, which reduces new shadow-IT by letting staff self-serve approved apps instead. Actioning licence cancellations is the customer's own procurement decision either way. | Same as Managed Patching. |
| 5 | Shadow-IT applications in active use (2.3) | Addressed after the above because it typically requires a staff conversation or a policy decision, not just a technical change. | Reported here. Not actioned at this tier. | Browser-extension inventory and policy review is included; removing a specific unapproved desktop application is scoped case by case, not a blanket inclusion. | Same as Managed Patching, with configuration drift (including newly-appeared unapproved software against policy) reviewed and remediated on an agreed cadence. |

[specialist input required: adjust the priority order if [CUSTOMER NAME]'s
actual findings warrant it - for example, an actively-exploited CVE on a
device handling regulated data should outrank everything else regardless
of this default sequencing. State explicitly if you have reordered
anything from the default above, and why.]

---

## 4. Evidence appendix

The raw posture behind the judgement above, so every claim in this report
is auditable against a named source rather than merely asserted. Where a
number appears in Sections 1 to 3, it should be possible to find the row
it came from here.

**4.1 CVE and configuration posture (Section 2.1)**

- Source: `device_cve_findings` (per-device CVE matches), scored against
  `cve_feed_entries.cvss_v3_score`; `compliance_evaluations` (per-device
  CIS control pass/fail), aggregated as `ComplianceStats.OverallPct`.
- Console access: CVE Findings and Compliance Status tabs, under the
  customer's Assurance workflow group.
- [specialist input required: attach or reference the full per-device CVE
  list and CIS control breakdown for the assessment period - not just the
  worked examples used in Section 2.1.]

**4.2 Standing local-admin exposure (Section 2.2)**

- Source: per-device admin-account count reported against CIS macOS 5.8 /
  the Windows equivalent, via the Local Admin / Privileged Access report.
- [specialist input required: attach or reference the full per-device
  admin-account table, including any accepted exceptions noted in 2.2.]

**4.3 Licence and shadow-IT visibility (Section 2.3)**

- Source: application metering (installed-app inventory with last-used
  dates and launch counts, under the customer's Evidence → Software
  Metering tab) and shadow-IT findings (unapproved-application detection
  against the customer's app policy and the Patched software catalogue,
  under Evidence → Shadow IT).
- [specialist input required: attach or reference the full metering table
  (app, seats licensed if known, installs, last-used date, launch count)
  and the full shadow-IT findings list.]

**4.4 What this appendix does not cover**

This assessment reports on what the endpoint agent can observe and what
the customer's own policy records say. It is not a penetration test, not
a review of network or cloud infrastructure outside managed endpoints, and
not a legal opinion on regulatory compliance - the framework mappings in
Section 2 identify which control area a finding relates to, they do not
constitute a certification against Cyber Essentials, ISO 27001, or UK
GDPR. [specialist input required: note here if anything else was out of
scope for this specific engagement, per the signed scoping questionnaire.]

---

*End of report template. Delete this line and every remaining
`[specialist input required: ...]` marker before sending to the customer.*
