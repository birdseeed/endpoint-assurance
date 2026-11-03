# Endpoint Assurance - Delivery Runbook

> **STATUS: UNEXECUTED. Do not use with a paying customer until this changes.**
>
> **Ticket: PAT-1301.** No phase below has been run end to end against a real
> or staging estate. This document was written by reading the code that each
> step depends on and, where possible, the console UI that drives it - it has
> not been walked through live. The ticket that produced it is explicit that
> a runbook nobody has executed is not a runbook. Before this is used with a
> paying customer, a specialist must run the full cycle once against tenant
> zero or a staging estate: provision, install, observe, remove, verify
> removal, deliver. Record what broke and fix this document, not just the
> problem.
>
> Every step below that could not be verified against real code or a real
> system is marked **[UNVERIFIED]** inline, where it appears. A step with no
> such marker was checked against the code cited next to it, not assumed. The
> single most important unverified thing in this document is in Phase 7: the
> automated agent-removal path carries an explicit "do not ship to customer
> endpoints" warning in its own source code that this session found no
> evidence has been lifted. Read Phase 7 before promising a customer
> unattended removal.

## What this is

The agreed product shape: install the Patched agent on a prospect's estate
for 2 to 4 weeks, observe only, deliver a written report live on a call, and
if no retainer follows, take the agent off. The agent is the instrument; the
report is the deliverable. This document is the operational sequence a
specialist follows from signed order to agent removed and report delivered.

Read alongside the two sibling documents this runbook assumes:

- `docs/endpoint-assurance/scoping-questionnaire.md` (PAT-1300) - answered
  before the order is signed; its Section D (regulatory driver) sets the
  deadline this runbook's timing works backwards from, and Section G sets
  deployment access.
- `docs/endpoint-assurance/engagement-letter.md` (PAT-1300) - Section 4 sets
  the 2 to 4 week instrumentation window and the removal commitment this
  runbook executes; Section 5 sets the data-handling terms.
- `docs/endpoint-assurance/report-template.md` (PAT-1299) - what Phase 6
  produces; the handover call in Phase 8 follows this template's section
  order.
- `docs/endpoint-assurance/catalogue-onboarding.md` (PAT-1298) - the
  verification and commercial contract for applications identified in the
  questionnaire or during the observation window.

## How to read this document

Numbered phases, each with preconditions, the actual command or console
action where one exists, what to verify before moving on, and what to do if
the step fails. A quick-reference summary of the four load-bearing mechanics
this runbook depends on follows immediately below; each is expanded in full,
with file references, in the phase where it is used.

| Mechanic | Verdict | Where it matters |
|---|---|---|
| Assessment tenant tier | Verified. Use `report` tier, App Control stays Off. | Phase 2 |
| Observation window | Verified against agent polling and server ingestion code. Minimum 3 weeks, not 2. | Phase 4 |
| Automated removal (signed expiry) | Verified the mechanism works as designed, but its own source carries an unresolved "do not ship to customer endpoints" warning. Do not treat it as the only removal path yet. | Phase 7 |
| Handover call structure | No code to verify - this is a proposed structure, not a discovered one. Mark this call's structure as a first draft to be revised after the dry run. | Phase 8 |

---

## Pre-flight checklist

Before starting Phase 1, confirm:

- [ ] Signed order and signed scoping questionnaire both on file, dated.
- [ ] Scoping questionnaire Section D4/D5 deadline identified, and the
      instrumentation window length (2, 3, or 4 weeks) chosen to land the
      report before it, per engagement-letter.md Section 4.
- [ ] Scoping questionnaire Section G1 confirms who can approve agent
      installation, and that approval is in place, not pending.
- [ ] Named specialist assigned as the report author and handover-call host
      (report-template.md cover page "Prepared by").
- [ ] Named recipient for the signed download link confirmed (report-template.md
      Cover, "Prepared for") - the report is delivered to one named person,
      not a distribution list.

---

## Phase 1 - Confirm the order and set the deadline

**Precondition:** pre-flight checklist complete.

1. Read the signed scoping questionnaire in full, not just Sections B and D.
   Section F (line-of-business applications) determines whether any
   catalogue onboarding work is needed before instrumentation starts -
   an application not already in the Patched software catalogue needs
   vetting time that eats into the window. Record each one against the
   dispositions in `catalogue-onboarding.md`; do not describe an application
   as covered until its verification record is complete.
2. Fix the instrumentation window length now (2, 3, or 4 weeks) and the
   exact start date. Work backwards from the D4/D5 deadline in the scoping
   questionnaire, not forwards from today.
   **[UNVERIFIED]** whether 2 weeks should ever actually be offered - see
   Phase 4. If the customer's deadline forces a 2-week window, this must be
   a conscious exception recorded in writing (email or a note against the
   order), not a silent default.
3. Confirm the report delivery date and book the handover call (Phase 8)
   provisionally now, so the customer has it on their calendar before
   instrumentation even starts.

**Verify before moving on:** window start date, window length, and handover
call date are all written down somewhere the whole team can see (the Linear
ticket for this engagement, or wherever else Patched tracks live customer
work) - not only in this specialist's head.

**On failure:** if Section F reveals a business-critical application that is
not in the catalogue and cannot be vetted in time, say so to the customer
before the order is signed, not after. This is a scoping problem, not an
instrumentation problem.

---

## Phase 2 - Provision the assessment tenant

**Precondition:** Phase 1 complete, start date confirmed.

### What tier to run at - verified against code

The ticket's assumption was "a Report-style tier" - confirmed correct, but
the exact vocabulary is more specific than "Report-style," and getting the
adjacent setting wrong opens a real destructive-enforcement gate. Verified
in `patched.im/go-service/internal/handlers/admin.go`:

- The commercial tier a tenant is billed and gated on
  (`tenants.subscription_tier`) has exactly three values, defined at
  `admin.go:773-776`: `report`, `patch`, `full_endpoint`.
- Setting a tenant's subscription tier maps to the agent's own behavioural
  tier via `agentTierFor()` (`admin.go:791-799`): `report` maps the agent
  itself to `report_deploy` - collect-and-report only. `full_endpoint` maps
  it to `managed`, described in a comment at `admin.go:786-790` as a strict
  superset of `patch` plus additional enforcement actions gated specifically
  on `tier == "managed"`.
- **The setting to avoid: App Control.** `SetTenantTierHandler`
  (`admin.go:816-1007`) contains, at `admin.go:920-930`, SQL that forces
  `app_control_enabled = TRUE` whenever tier is set to `full_endpoint`.
  App Control routes themselves (`/app-control`, `/app-control/admins`,
  `/app-control/allowlist`) are gated behind `needsFullEndpoint`
  (`patched.im/go-service/cmd/patched-api/main.go:544-547`). What App
  Control unlocks, per `patched.im/go-service/internal/agentconfig/schema.go:20-26`:
  `AppControlPolicy.Enabled` gates whether the agent enforces at all, and
  `ExtensionRemovals` is - in the schema's own comment at `schema.go:26` -
  a "destructive-removal directive": the agent deletes browser extensions
  under its own authority. This is the destructive-enforcement gate the
  ticket's constraint refers to, and it is real, not hypothetical.
- The agent's safe default is confirmed independently at
  `agentconfig/schema.go:163-176`: `DefaultConfigBody()` sets
  `Tier: "report_deploy"`, commented in the code as "the conservative
  default: collect and report, no patching."

**Provisioning steps (dashboard console):**

1. Console → **Create tenant** modal (`templates/console.html:3388-3468`).
   Fill in the customer's name and details from the signed order. The
   one-time bearer token and HMAC secret are shown once in the modal - save
   them for the install step in Phase 3, they are not retrievable again
   through the UI.
2. Open the new tenant's **Account** tab. Set:
   - **Plan tier** dropdown (`acct-tier`, `console.html:420-424`) to
     **"Report & Deploy"** (value `report`). Do not select "Report, Deploy &
     Patch" or "Full Management" for an assessment tenant.
   - **App Control** dropdown (`acct-app-control`, `console.html:450-454`)
     stays **"Off"**. It defaults to Off for a new tenant; confirm it reads
     Off rather than assuming it.
   - **Lifecycle stage** (`acct-state`, `console.html:431-436`) to
     **"Prospect"**.
3. Save. The hint text at `console.html:426-428` states the change applies
   to entitlement and agent config immediately - there is no separate
   publish step.

**Verify before moving on:** reopen the Account tab after saving and confirm
Plan tier reads "Report & Deploy" and App Control reads "Off." Do not trust
the save confirmation alone - the tier hint warns this is a live change, so
confirm the state it actually landed in.

**On failure:** if the tier dropdown does not show "Report & Deploy" as an
option, or the save does not stick, stop and escalate to engineering rather
than working around it by editing agent-config directly - the tier and
App Control fields are linked server-side (`admin.go:920-930`), and editing
one without going through `SetTenantTierHandler` risks leaving them out of
sync.

---

## Phase 3 - Deploy the agent to the estate

**Precondition:** Phase 2 complete and verified; deployment access confirmed
per scoping questionnaire Section G2 (existing MDM, manual install guide, or
login script).

1. Retrieve the bearer token and HMAC secret saved from the Create Tenant
   modal in Phase 2.
2. Install per the method agreed in scoping G2. **[UNVERIFIED]** - this
   runbook does not attempt to restate the full install procedure for every
   platform and deployment method; that lives in the existing agent
   installation documentation (not part of this ticket's scope) and should
   be linked here once confirmed rather than duplicated.
3. Use the customer's approved MDM, endpoint-management or documented local
   deployment route. The Dashboard provides assurance evidence and does not
   initiate package deployment; Installomator-based scripts are not a current
   Patched delivery path. Confirm the chosen route during deployment planning,
   before endpoint work starts.

**Verify before moving on:** device count enrolling in the console over the
first 24 to 48 hours tracks the count agreed in scoping Section B1. A
material shortfall (devices that should be checking in but are not) is a
deployment problem to chase down now, before it silently shortens the
observation window in Phase 4.

**On failure:** a device that never enrols is a device with zero data for
the report - note it and its likely cause (offline, access denied,
install script failure) so Phase 6 can state explicitly why it is absent
rather than silently under-counting against the scoping questionnaire's
declared device count.

---

## Phase 4 - The observation window

### Why 2 weeks is not enough - verified against the metering mechanics

The ticket's assumption was that last-used metering needs weeks to
accumulate before "installed but never opened" is meaningful. Confirmed, and
the underlying mechanics point to a specific minimum, not an arbitrary one:

- **What the agent actually captures.** On macOS, the agent reads Spotlight
  metadata per app (`mdls -raw -name kMDItemLastUsedDate` and
  `kMDItemUseCount`) rather than hooking process launches directly
  (`updater/macos/lib/apps.sh:12-22,37-42`) - this only credits a launch via
  Finder, Dock, `open`, or Spotlight, and can under-report direct `exec`
  launches (noted in `updater/docs/windows-metering-adr.md:7` and the
  equivalent macOS design note). On Windows, the agent reads the UserAssist
  registry key, summed across loaded user hives
  (`updater/docs/windows-metering-adr.md:7,13,21,35`) - GUI launches only.
- **How often that gets collected.** Once per day. The macOS collector
  LaunchDaemon runs on a 24-hour `StartInterval`
  (`updater/macos/com.patched.collect.plist:26-27`); the Windows worker's
  default scan interval is `TimeSpan.FromHours(24)`
  (`updater/windows/src/Service/Worker.cs:21,1085`).
- **How the server stores it.** One row per `(tenant, device, app,
  platform, date)` per day, with same-day re-ingests merged rather than
  overwritten (`patched.im/go-service/internal/handlers/inventory.go:175-192,254-260,335-351`).
  `last_used_at` and `launch_count` are preserved via `COALESCE` across
  scans, not reset (`patched.im/go-service/internal/extractor/upsert.go:405-406`)
  - so the risk in a short window is under-collection at the *start*
  (an app used once early, correctly recorded, then nothing to compare
  against), not staleness.
- **No documented minimum window exists in the code.** The closest artefact
  is `patched.im/go-service/docs/adr/0005-software-metering-source.md:65,73`,
  which notes that "launches in the last N days" has to be derived
  server-side by diffing successive daily readings and flags this as an
  unbuilt open item - so there is no built-in floor protecting a specialist
  from reading a too-short window as meaningful. This is a judgement call
  this runbook is making, not a limit the system enforces.

**The concrete minimum: 3 weeks (21 days), not 2.** With daily-only
collection, a 7-day window gives roughly seven snapshots. Software used on
a weekly cadence (payroll runs every Monday, a monthly-close tool used once
a period) has a real chance of its one use falling entirely outside a 7-day
window - the report would then call it "unused" when it is not, which is
exactly the kind of false positive that undermines a paid report's
credibility. Three weekly cycles (21 days) gives near-certain coverage of
weekly-cadence software and partial coverage of monthly-cadence software;
four weeks improves the monthly-cadence coverage further, which is why the
engagement letter's 2 to 4 week range exists rather than a fixed number.

**If a customer asks for a shorter window:** do not silently agree to 2
weeks and treat the metering findings the same way. Either extend the
report delivery date to protect a 3-week minimum, or - if the deadline in
scoping D4/D5 genuinely cannot move - deliver the report on schedule but
mark Section 2.3 (Licence and shadow-IT visibility) of the report
explicitly as low-confidence for anything under 3 weeks of data, per the
report template's own instruction to say so explicitly rather than delete
a weak section. Do not silently present a 2-week metering read with the
same confidence as a 3-week one.

**Verify before moving on:** at the 3-week mark (or earlier if the window
is being compressed per the paragraph above), spot-check that devices
enrolled in Phase 3 are still reporting daily - a device that stopped
checking in partway through the window has a shorter effective observation
period than the calendar window suggests, and that should be noted against
that device specifically in Phase 6.

**On failure:** a gap in daily check-ins for a specific device mid-window is
a connectivity or agent-health problem worth chasing (per Phase 3's
verification step), not something to paper over in the report - state the
actual effective observation period per device if it differs materially
from the engagement's calendar window.

---

## Phase 5 - Mid-window health check

**Precondition:** at least one week into the observation window.

1. Confirm device check-in count still matches the count from Phase 3's
   verification step.
2. Spot-check that CVE findings, compliance evaluations, and admin-account
   counts are populating for a sample of devices (the three data sources
   named in report-template.md Section 2). An empty result set from any of
   these this far into the window is worth investigating now rather than
   discovering it while writing the report in Phase 6.

**Verify before moving on:** no unexplained gap in any of the four data
sources (CVE findings, compliance, admin accounts, metering) for the
sampled devices.

**On failure:** if a data source is empty for reasons that cannot be fixed
before the report is due (a scan that has not run, a check that requires
a config not present on these devices), flag this to the customer and the
report author now - the report template requires saying explicitly when a
finding class has nothing to report, and "nothing to report" needs to be
distinguished honestly from "the data never arrived."

---

## Phase 6 - Compile the report

**Precondition:** observation window complete (Phase 4's minimum met, or a
documented exception per that phase).

1. Work through `report-template.md` section by section, replacing every
   `[specialist input required: ...]` block with genuine written judgement
   pulled from this tenant's actual data, per that template's own
   instructions.
2. Pull data per the template's Evidence appendix (Section 4): CVE Findings
   and Compliance Status tabs (2.1), Local Admin / Privileged Access report
   (2.2), Software Metering and Shadow IT tabs (2.3).
3. Have a second person (not the report's author) read the finished report
   before it is finalised - the report template itself frames this as a
   paid deliverable built on professional judgement, not a generated score,
   and a second read is the cheapest check against a misread finding before
   it reaches the customer.
4. Generate the signed, time-limited download link
   (`GET /reports/download/{token}` per report-template.md Cover) and
   confirm it resolves before the handover call, not during it.

**Verify before moving on:** every `[specialist input required: ...]` marker
is gone from the finished document, and the download link has been tested
by someone other than its author.

**On failure:** a section with genuinely nothing to report is written as
"no [X] identified in the assessment period," per the template's own
instruction - it is never left as a deleted section or a lingering
placeholder.

---

## Phase 7 - Schedule agent removal

This is the phase where the ticket's assumption needed the most scrutiny,
and where this runbook found the sharpest gap between what the product is
supposed to do and what the code currently permits shipping.

### What the code actually does - verified

Decommission is implemented on both platforms as a real signed-expiry path,
under PAT-1107 through PAT-1111. Console side: the tenant's **"Remove
Patched agents"** panel has an expiry date/time field and a purge checkbox
(`_dcSaveExpiry()`, `console.html:14219-14250`), sending
`{mode: "expiry", expires_at, purge, reason}` via
`PUT /admin/tenants/{tenant_id}/decommission`
(`main.py:6308-6440`), proxied to the go-service's own
`PUT /admin/tenants/{tenantID}/decommission`
(route registration `patched.im/go-service/cmd/patched-api/main.go:449-451`;
handler `patched.im/go-service/internal/handlers/agent_decommission.go`,
PAT-1108). The directive is cryptographically signed.

On the device side: macOS polls its config every 15 minutes
(`updater/endpoint/com.patched.config-poll.plist:6,27`); once the signed
directive's `expires_at` is reached, `patched-fetch-config.sh`'s
decommission gate (`updater/endpoint/patched-fetch-config.sh:900-1298`)
independently re-verifies the signature, tenant binding, anti-rollback, and
expiry sanity at the point of action, then stages and runs a detached
LaunchDaemon (`updater/endpoint/patched-decommission.sh`) that performs the
actual removal. Windows follows the equivalent path via
`DecommissionRunner.cs`, `DecommissionHandoff.cs`, and
`DecommissionHandoffScript.cs` under `windows/src/Service/`, using a
scheduled task rather than a LaunchDaemon. **Both platforms are covered -
this is not a macOS-only mechanism.**

**Can this run with zero manual action once scheduled? Almost - one
deliberate manual step remains by design.** Setting the `expires_at` date in
the console (the step above) is itself the one manual action; once set,
removal fires unattended at the scheduled time with no further customer or
Patched action required. That single step is exactly what this runbook
already has a specialist do in the console, so in practice it is not extra
work - the point is that "fully automatic" is not accurate; "one scheduled
action, then automatic" is.

**What gets removed, and what does not - verified, and this matters for a
paying customer.** Core removal (binaries, LaunchDaemons/services,
bundle directories) happens regardless. Credentials and local queue/state
(`/etc/patched`, `/var/db/patched` on macOS; Windows Credential Manager
entries and `%ProgramData%\Patched` on Windows) are removed **only if
`purge=true`** was set on the expiry directive
(`updater/endpoint/patched-decommission.sh:388-392`;
`windows/src/Service/DecommissionHandoffScript.cs:317-385`). The default is
`purge=false`. **For an Endpoint Assurance engagement, always set
`purge=true`** when scheduling the expiry in the console - a paid assessment
that leaves credentials or cached inventory behind on a prospect's device is
both a trust problem and a data-protection one, exactly the failure mode
this ticket asked to be checked. Even with `purge=true`, the decommission
log file itself is not guaranteed to be removed: on macOS,
`/var/log/patched-decommission.log` is never deleted by the script
(`patched-decommission.sh:394-417` only removes the daemon directory and
plist); on Windows the log clears only if `purge=true` and only after
cleanup succeeds (`DecommissionHandoffScript.cs:517-527`). A stray log file
naming the tenant is a low-severity but real residue - worth a manual check
in the post-engagement inspection below rather than assuming purge means
nothing is left.

**Is there a verifiable signal removal happened? Yes, well-designed, with
one honest caveat.** Both platforms send an "acknowledged" report before
removal and a verified "removed" report after, and both fail closed - a
failed removal retries rather than falsely reporting success. The caveat:
if a device never boots or checks in again, or transport fails past the
bounded retry window (10 boots on Windows), the device simply never reports
either outcome - it sits unreported rather than confirmed-failed. **This
means "no failure reported" is not the same as "confirmed removed" for a
device that has gone dark** - the post-engagement checklist below treats
these as two different states on purpose.

### The gap this phase found, and how it was closed (PAT-1344, 2026-08-14)

When this runbook was written, every decommission source file carried an
explicit "do not ship to customer endpoints until the security review is
complete" warning, and no evidence could be found that the review had ever
happened. That made manual per-device removal verification mandatory rather
than a fallback, which does not scale.

**The review had genuinely never been run**, which PAT-1344 established
rather than assumed: the PRs that built this path (#406 macOS, #407 Windows)
narrate review rounds in their own bodies, but the only machine-recorded
review signal on either is a scan that failed to complete, and both merged
over it. Author-written prose about a review is not a review.

**It has now been run.** The complete decommission path - 2358 lines across
`patched-decommission.sh`, `com.patched.decommission.plist`, and the four
Windows `Decommission*.cs` files - was reviewed by three independent
non-author reviewers, and every finding was checked against the code with
citations rather than accepted at face value. One was real and is fixed: the
pre-purge credential snapshot could fail silently, letting an irreversible
purge complete while leaving the platform permanently unable to be told the
outcome. The rest did not survive verification. The warnings in all three
files have been replaced with a record of what cleared them.

One qualification a specialist should know rather than discover: this is the
compensating local review described in the workspace CLAUDE.md, not an
enforced upstream gate - the `patched/non-author-review` rulesets are
disabled estate-wide, which is tracked separately under PAT-941.

**What this means for this runbook now:**

1. Schedule the signed expiry per the steps above. It is the primary removal
   mechanism, and it is now cleared to be relied on for a paying customer's
   estate.
2. **Automatic expiry is the primary path; manual per-device verification is
   the exception, not the rule.** Verify by hand only where the platform
   cannot give you a verified "removed" report - specifically the
   gone-dark case described above, where a device never boots or checks in
   again and therefore sits unreported rather than confirmed-failed. That
   distinction, not a blanket per-device sweep, is what Phase 9's checklist
   is for.
3. Still verify the residue items called out above - the decommission log
   file on macOS, and the `purge=true` setting itself - since those are
   design residues rather than review gaps and are unaffected by the
   clearance.

**Verify before moving on:** the expiry directive is confirmed set in the
console (reopen the "Remove Patched agents" panel and confirm the date and
purge=true are saved, the same discipline as Phase 2's tier check).

**On failure:** if the console save does not stick or the directive does
not appear acknowledged by devices within the first polling cycle after
being set, do not assume it will resolve itself before the expiry date -
escalate and verify manually per Phase 9 regardless of outcome.

---

## Phase 8 - The handover call

**Precondition:** Phase 6 report finalised and download link tested; Phase 7
expiry scheduled (removal does not need to have completed yet - it can be
mid-flight during this call, provided Phase 9's verification happens after).

**[UNVERIFIED - proposed structure, not one confirmed by having run a real
call.]** The report is delivered live, not emailed, because the retainer
conversation happens inside this call, not after it. Structure the call
around the report template's own section order so the customer is never
asked to jump around a document they have not seen yet:

1. **Open by stating why this call, not an email.** One sentence: the
   findings are specific to their estate and worth walking through together
   rather than reading cold.
2. **Executive summary first, read close to verbatim** (report-template.md
   Section 1). This is written for a finance director or MLRO, not an
   engineer - deliver it that way. Pause after each of the three points
   (audit failure, insurer exposure, cost to fix) for reaction before
   moving on.
3. **Walk Section 2's findings in the template's own order** - CVE and
   configuration posture, then standing local-admin exposure, then licence
   and shadow-IT visibility. Lead each with the worked-example framing the
   template itself uses: what was observed, what it means in practice, not
   just a table of numbers.
4. **Present Section 3's remediation plan as a sequence, not a list** -
   the template's own point is "why this order," so make the ordering
   logic explicit on the call: fastest wins first, workflow-dependent
   changes later.
5. **State the commercial terms plainly before asking anything** - the
   90-day credit against onboarding (report-template.md Cover, "Commercial
   terms"), and what each retainer tier would actually do differently with
   these specific findings (the template's Section 3 table, tier by tier).
6. **Ask directly whether they want to proceed to a retainer**, naming a
   specific tier based on what the findings actually warrant, not a generic
   upsell. If the answer is no or not yet, confirm the agent-removal timing
   from Phase 7 with them explicitly, so it is not a surprise.
7. **Close with the evidence appendix as reference, not a walkthrough** -
   mention it exists and where the underlying data lives (Section 4), but
   do not narrate every row live on the call.

**Verify before moving on:** the customer has explicitly stated a decision
(retainer / not now / needs time), even if "needs time" is the actual
answer - do not leave the call without a stated next step and a date to
revisit it.

**On failure:** if the call has to be rescheduled after the report link has
already been generated, reconfirm the link has not expired before the
rescheduled call (report-template.md Cover states it expires after first
use or a configured window - **[UNVERIFIED]** the configured window itself,
same gap the report template flags in its own text).

---

## Phase 9 - Post-engagement

**Precondition:** handover call complete, expiry directive from Phase 7 has
reached its scheduled time.

1. **Verify removal, per device, not just per estate-wide status.** For
   every device that was in scope, confirm the "removed" terminal report
   was received (Phase 7's verifiable signal). Do not treat "no failure
   reported" as equivalent to "confirmed removed" for any device that has
   not sent that terminal report - per Phase 7, those are different states.
2. **For any device stuck in "unreported":** this is the exception case
   Phase 7 describes - a device that has gone dark, not a device the
   removal mechanism failed on. Since PAT-1344 cleared the automated path,
   this is the only case that still needs hands on it. **[UNVERIFIED]** -
   this runbook does not have a confirmed manual-removal procedure to hand
   a specialist for this case, because it has not been exercised. Until it
   has been, treat an unreported device as an open item that blocks closing
   the engagement, not something to let lapse.
3. **Spot-check for residue even on confirmed-removed devices**, per
   Phase 7's log-file caveat - this is a quick manual check, not a full
   audit, but it is the honest completion of "a paid assessment should not
   leave anything behind."
4. **Tenant disposition, by outcome:**
   - **Retainer signed:** leave the tenant as-is; it becomes the retainer's
     ongoing tenant. Update its lifecycle stage from "Prospect" to
     "Onboarding" or "Active" as appropriate (`acct-state`,
     `console.html:431-436`).
   - **No retainer:** use the console's **"Offboard"** action first
     (`modal-offboard`, `console.html:3474-3502`, soft and reversible) -
     not the **"Permanently delete"** hard-purge action
     (`modal-purge`, `console.html:3418-3444`) - so the assessment data
     remains available for the retention period stated in the engagement
     letter's data-handling section, rather than being destroyed
     immediately. Both actions require typed tenant-name confirmation.
5. Record the outcome (retainer / not, and why, if known) wherever Patched
   tracks live customer engagements.

**Verify before moving on / engagement close:** every in-scope device shows
a confirmed "removed" status, not merely "no failure reported"; tenant
disposition matches the retainer outcome; report link tested and
delivered; commercial terms (90-day credit) recorded against the customer's
record if they did not convert immediately, so it is not lost by the time
they come back.

---

## Post-engagement checklist

- [ ] Every in-scope device confirmed "removed" (Phase 9.1), not merely
      unreported-and-assumed-fine.
- [ ] Any device stuck in "unreported" resolved or explicitly escalated as
      an open item, not silently dropped.
- [ ] Spot-check for residue (credentials, cached data, log files) on a
      sample of removed devices.
- [ ] Tenant disposition set correctly (Offboard, not Delete, unless the
      customer specifically requests full deletion).
- [ ] Report delivered live on the handover call, decision recorded.
- [ ] 90-day onboarding credit window recorded against the customer if they
      did not convert on the call.
- [ ] This runbook updated with anything that did not match reality during
      this engagement - especially anything marked **[UNVERIFIED]** above
      that is now confirmed one way or the other.

---

## What this runbook found that the ticket did not assume

- **The tier vocabulary is more specific than "Report-style."** The correct
  value is `report` (console label "Report & Deploy"), and it is a genuinely
  separate axis from App Control - App Control is not gated by tier alone in
  a way that a report-tier tenant could stumble into, but it is a setting
  that must be actively left off rather than something that is safe by
  omission. See Phase 2.
- **The 2-week end of the stated 2-to-4-week window is probably too short
  to trust for the metering-derived findings**, based on the actual daily
  collection cadence. This was a judgement call this runbook made from the
  mechanics, not something the code enforces or warns about - there is no
  built-in floor. See Phase 4.
- **Automated agent removal is real and works as designed, but is not
  currently cleared in its own source code to ship to a paying customer's
  estate.** This is the most consequential finding in this document: the
  product's stated shape ("if no retainer follows, the agent comes off,"
  implicitly unattended) currently depends on a mechanism whose own authors
  have marked it not-yet-approved for exactly this use. This is a real
  blocker worth surfacing before Endpoint Assurance is sold at any volume,
  not just a documentation gap. See Phase 7.
