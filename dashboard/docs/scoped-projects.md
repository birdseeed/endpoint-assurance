# Scoped project offerings

Delivery IP for the Projects page (`projects.html`), lifted from three
tickets cancelled in the August sweeps as product scope while their useful
half - the offering shape, the engagement structure, the baseline repo - was
kept as delivery IP: PAT-667 and PAT-171 ("Tier 3 Intune migration service
offering", filed twice five weeks apart) and PAT-666 (CIS L1 baseline-as-code
repo). This document is that IP, written once, in the same place as the
Endpoint Assurance pack.

Scoped projects sell at £4,000 to £18,000 (per the Projects page), which is
half the practice's revenue model alongside the retainer tier. Every band
below is a starting point for a quote, not a published price - confirm scope
against the estate in front of you before it goes in an email, the same
discipline the Endpoint Assurance scoping questionnaire uses for its own
fee-banding section.

## A prospect asking what a project involves and what it costs

Each offering below has the same shape: a phase breakdown, exit criteria,
and a fee band. Where a source ticket gave a real number, it's used as-is.
Where none did, the band is a reasoned position inside the £4k-£18k
envelope the page already commits to, marked for specialist confirmation
per engagement rather than quoted from memory.

---

### Endpoint security review

Review Windows and macOS controls, evidence gaps and practical exposure -
the assurance-and-governance group's entry point, usually the first scoped
project after an Endpoint Assurance assessment surfaces something too broad
for the retainer to absorb in one cycle.

**Phases:** estate and control inventory → gap analysis against the
customer's regulatory or insurance obligations → risk-ranked remediation
plan → handover.

**Exit criteria:** a written, risk-ranked remediation plan the customer can
hand to their own IT, MSP or auditor, with each finding scoped to owner and
priority.

**Fee band:** £4,000-£7,000. [Specialist input required: confirm against
estate size and whether EDR/MDM tooling already exists to instrument
against, or whether this project has to establish baseline visibility
first.]

### Software governance

Turn discovered applications into a customer-owned policy process -
classification, ownership, conditions, review dates - built on the same
approved-software catalogue model the product itself uses.

**Phases:** software identity and classification review → catalogue
foundation stood up in the customer's own tooling → owner and
review-date assignment → decision-and-risk-acceptance evidence trail.

**Exit criteria:** a working, customer-owned classification catalogue with
every discovered application assigned an owner and a review date, not a
one-time spreadsheet.

**Fee band:** £5,000-£9,000. [Specialist input required: scales with
discovered-application count and how much of the customer's software estate
is already inventoried versus starting cold.]

### Policy and configuration

A documented, supportable configuration baseline - the offering the CIS L1
baseline-as-code repo (PAT-666) exists to deliver.

**What ships:** versioned CIS L1 configuration profiles for macOS and
Windows 11, one repo, tagged by benchmark section so a specific control maps
to a specific commit. Releases tagged `cis-macos-2026-Q1` / `cis-windows-2026-Q1`
style, so "which baseline is live" is a git tag, not a claim. Git history is
the audit trail - every change to a control has a commit, an author and a
reason, which is the cheapest credibility artefact in the estate for a
regulated buyer's procurement to inspect.

**What does not ship:** a dashboard deploy pipeline or drift-detection
product surface. Those stay cancelled product scope; the repo is
deliberately just the baseline, deployed through the customer's own Intune
or Jamf.

**Phases:** CIS-aligned policy selection for the customer's platform mix →
compliance and configuration profile authoring → pilot deployment → estate
rollout → exceptions, ownership and review-evidence handover.

**Exit criteria:** the tagged baseline repo deployed and enforcing in the
customer's own management platform, with an exceptions log and a named
review owner.

**Fee band:** £5,000-£10,000 per platform (macOS or Windows 11); confirm a
combined band before quoting both. This is both a project deliverable and
the yardstick an Endpoint Assurance assessment measures against, so it is
worth pricing as a durable artefact rather than a one-off engagement.

### Audit and workflow

Make findings usable by decision-makers, auditors and the customer's own
endpoint team - evidence packs, ownership workflow, ticketing routing,
closure evidence.

**Phases:** management and technical evidence-pack design → finding
ownership and review workflow → ticketing/management-platform routing →
closure evidence and reporting cadence.

**Exit criteria:** findings routed into the customer's own ticketing or
management platform with an agreed reporting cadence, not a report that
lands and goes stale.

**Fee band:** £4,000-£7,000. [Specialist input required: the deciding factor
is how much existing ticketing/workflow tooling the customer already runs
versus needing one stood up as part of the project.]

### Patching strategy

Define how operating systems and applications will be kept current - the
offering that turns "we should probably patch faster" into an operating
model.

**Phases:** tooling, ownership and coverage review → application and OS
priority ranking → pilot groups, update rings and change model design →
reporting, escalation and handover.

**Exit criteria:** a documented, owned patching cadence with defined update
rings, a change model and an escalation path, handed over to the customer's
own team or MSP to run.

**Fee band:** £4,000-£8,000. [Specialist input required: scales with
platform count (Windows-only vs Windows+macOS) and estate size.]

### Automated end-user deployment

Build repeatable application delivery for Windows and macOS users - the
broader offering that PAT-667/PAT-171's Intune migration work sits inside
when the customer already has a target platform and just needs delivery
built out.

**Phases:** platform workflow design (Intune, Jamf or partner platform) →
application onboarding and detection rule authoring → phased rollout with a
pilot ring → rollback plan and operational handover.

**Exit criteria:** a working, tested deployment pipeline for the customer's
application set, with detection rules, phased rings and a documented
rollback path, run at least once end to end before handover.

**Fee band:** £5,000-£10,000. [Specialist input required: scales with
application count and how much existing packaging/detection logic the
customer already has.]

### SCCM to Intune migration

The most fully specified offering, sourced directly from PAT-667 and
PAT-171. Move Windows management deliberately without losing operational
control.

**Engagement shape (from PAT-171, the better-shaped of the two source
tickets):**

1. **Discovery.** Estate inventory, dependency mapping, current SCCM
   collection/deployment/policy structure.
2. **Tenant preparation.** Microsoft 365 and Entra clean-up, licence check,
   baseline assignment groups built ahead of the pilot.
3. **Pilot ring.** A small, representative device group migrated first,
   co-managed where the estate needs a transition period rather than a
   cutover.
4. **Wave migration.** Remaining devices migrated in scheduled waves sized
   to the estate and change window.
5. **Handover.** Documented operating model, plus the handover report
   below.

**What the deliverable includes (from PAT-667):**

* A migration checklist template covering device readiness, co-management
  workload transition, and cutover verification per wave.
* A Graph API tenant-provisioning script: device groups, compliance
  policies, policy assignment built idempotently against the target tenant,
  so re-running it against a corrected input doesn't duplicate assignments.
* A handover report template - the artefact the customer is left holding,
  not just a completed migration. This is what makes the engagement a
  deliverable rather than a fortnight of somebody's time.

**Exit criteria:** all in-scope devices migrated and verified against the
target tenant, Autopilot/co-management readiness confirmed, and the
handover report delivered.

**Fee band:** £2,000-£5,000 one-off, plus subscription (PAT-667's own
figure). This is the one offering with a sourced number rather than a
reasoned band - confirm it still holds against current estate sizes before
quoting; it was set against an earlier tier-economics baseline.

### Intune and Jamf tenant setup

Stand up or improve the management platform the customer has already
chosen - the foundational offering that SCCM-to-Intune migration and
automated deployment both assume already exists.

**Phases:** tenant foundations and enrolment → Autopilot, Apple Business
Manager and Automated Device Enrolment configuration → groups, compliance
and configuration profile structure → application delivery and patching
workflow handover.

**Exit criteria:** a working tenant with enrolment, compliance and at least
one deployed application workflow proven end to end, handed over with
operating documentation.

**Fee band:** £4,000-£8,000 per platform. [Specialist input required: a
combined Intune+Jamf setup for a mixed estate should band up from a single
platform, not be quoted as two independent projects run in parallel.]

---

## Handover report template (from PAT-667)

Every scoped project - not only the Intune migration it was written for -
ends with a handover report, because that's what the customer keeps once
the engagement closes. Shape:

1. **What changed.** Before and after state, in the customer's own
   terminology for their estate, not tooling jargon.
2. **What was verified.** The proof that the exit criteria were actually
   met - a migrated-device count, a passing pilot, a deployed and enforcing
   policy - not a claim that the work happened.
3. **What the customer now owns and operates.** The platform, the
   configuration, the policy - restated plainly, because the boundary
   published on the Projects page (the infrastructure a project stands up
   remains the customer's) has to be true in the handover document too, not
   just on the website.
4. **What's still open.** Anything the exit criteria didn't cover, named
   rather than implied as done.
5. **What Patched's role is from here.** Nothing, unless a retainer follows
   - and if one does, this report is the retainer's starting evidence base.

## Tenant-preparation checklist (from PAT-171)

The place an estimate goes wrong if it isn't written down, because tenant
prep is invisible scope until it's missing:

* Microsoft 365 and Entra ID clean-up - stale accounts, orphaned groups,
  conflicting naming conventions resolved before they're migrated forward.
* Licence check - confirm the licence SKUs in play actually cover the
  target management and compliance features being configured.
* Baseline assignment groups built and tested against the pilot ring before
  any wave migration references them.
* Co-management workload transition plan, if the estate needs a transition
  period rather than a cutover.
* Autopilot / Apple Business Manager / Automated Device Enrolment readiness
  confirmed for the target device population.

This checklist is the SCCM-to-Intune migration's own prerequisite list, but
every offering above that stands up or touches a management platform
(automated deployment, Intune and Jamf tenant setup) draws from the same
list - tenant prep is the same invisible-scope trap regardless of which
scoped project it's attached to.
