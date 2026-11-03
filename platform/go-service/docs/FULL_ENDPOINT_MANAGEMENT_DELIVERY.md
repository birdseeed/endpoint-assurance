# Full Endpoint Management delivery runbook

This runbook defines the attended delivery path for the first Full Endpoint Management engagements. It is the customer-one operating method, not a substitute for the versioned CIS L1 content pack in PAT-614 and not an authorisation to build the PAT-613 renderer.

The customer owns its Microsoft tenant and devices. Patched owns the delivery plan, change evidence, exception record, and verification that the intended endpoint state actually changed. Internal technical tier names and entitlements remain unchanged.

## Safety rules

- Never assign a new baseline directly to all users or all devices. Use a named pilot device group, then a separately approved broad group.
- Never create a setting from memory. Every setting must exist in the approved, versioned PAT-614 content pack and cite its benchmark source.
- Never treat an Intune success state as endpoint proof. Verify the corresponding Patched compliance signal on each pilot device after a fresh inventory upload.
- Never overwrite an existing customer policy in place. Record it, check for setting conflicts, and create a separately named Patched policy so rollback is assignment removal rather than reconstruction.
- Never place tenant IDs, user data, credentials, recovery keys, exported profiles, or customer screenshots in this repository. Customer evidence belongs in the approved engagement evidence store.
- Stop on an unexplained conflict, an unhealthy Patched collection path, an incomplete backup/recovery prerequisite, or a pilot result that differs from the approved plan.

## Required records

Create these records before making a change:

| Record | Minimum content |
|---|---|
| Engagement | Customer, service, accountable Patched specialist, authorised customer contact, change window, escalation route |
| Tenant readiness | Intune licence/authority, supported platforms, enrolment method, device ownership, Apple and Windows enrolment prerequisites, existing policy owners |
| Baseline decision | PAT-614 pack ID and version, benchmark revision, OS versions, approved deviations |
| Change plan | Pilot group, broad group, exclusions, deployment order, success measures, observation period, rollback owner |
| Exception register | Control ID, affected devices/users, reason, compensating control, owner, expiry/review date |
| Evidence index | Before and after Patched reports, Intune assignment/status export, device list, decisions, timestamps, operator |

The evidence index references customer-held artefacts. It does not copy sensitive material into Linear or git.

## Phase 1: qualify the tenant

1. Confirm the signed scope covers configuration enforcement and names the customer contact authorised to approve changes.
2. Confirm the customer has a supported Intune tenant, suitable licences, and a working management authority.
3. Inventory enrolment state by platform:
   - macOS: confirm the Apple MDM push certificate. For Automated Device Enrollment, confirm the Apple Business Manager token, device assignment, and enrolment profile.
   - Windows: confirm the agreed corporate enrolment path and that the selected pilot devices are managed by Intune. Autopilot is preferred for new corporate devices but is not required to remediate an already managed estate.
4. Record unsupported, personal, shared, kiosk, stale, or offline devices. Do not silently exclude them from the denominator.
5. Confirm an active break-glass administrator and a customer-approved recovery method exist. Do not collect the credential.
6. Confirm Patched has a recent successful inventory for every proposed pilot device and that compliance evaluation is healthy.

Exit only when the tenant, devices, contacts, and recovery path are known. Otherwise return to the get-fit project and do not schedule enforcement.

## Phase 2: capture the before state

1. Export or otherwise record existing configuration and compliance policy names, assignments, exclusions, scope tags, owners, and last-modified times.
2. Record conflicting settings and overlapping profiles. A matching setting in two policies is a conflict even when the current values happen to agree.
3. Generate a fresh Patched posture report for the pilot candidates and index the underlying observation time.
4. Map each failing or unknown Patched rule to the selected PAT-614 enforcement entry. Mark gaps explicitly:
   - `mapped`: the approved pack has a deployable setting or script;
   - `manual`: the control requires an attended customer action;
   - `advisory-only`: Patched measures it but the approved pack does not enforce it;
   - `not-applicable`: justified for this tenant with review date;
   - `unresolved`: blocks rollout for that control.
5. Review likely user and application impact with the customer. Convert every accepted deviation into an exception before deployment.

## Phase 3: prepare the pilot

1. Select at least one representative device per in-scope platform and important hardware/application class. Prefer devices whose users can participate in the change window.
2. Create a dedicated, customer-named pilot device group. Record its exact membership before assignment.
3. Build policies only from one immutable PAT-614 pack version. Name every object with the service, platform, pack version, and functional group so provenance survives export.
4. Keep core and tunable controls in separate policies. Apply customer exceptions only to the tunable policy or through an explicit exclusion group.
5. Validate the policy settings and assignments with a second person where available. For a solo delivery, use a timed self-review after the draft and record the review time.
6. Obtain the authorised customer contact's approval for the exact pilot membership, policy list, window, success measures, and rollback trigger.

## Phase 4: deploy and observe the pilot

1. Assign the prepared policies to the pilot group only. Microsoft recommends a pilot group for policy deployment; do not use `All users` or `All devices` here.
2. Record assignment time, operator, policy IDs, and the before membership snapshot.
3. Trigger or wait for normal Intune check-in. Do not use destructive remote actions to accelerate proof.
4. Monitor Intune per-setting and per-device status for conflicts, errors, pending states, and unexpected non-applicability.
5. On each pilot device, confirm user access and the agreed business-critical applications still work.
6. Run a fresh Patched collection and upload. Confirm the observation is newer than the assignment and that every mapped control reports the expected endpoint state.
7. Reconcile Intune and Patched evidence:
   - both agree: candidate success;
   - Intune succeeds but Patched disagrees: fail the pilot and investigate actual endpoint state;
   - Intune is pending but Patched already agrees: keep observing, do not infer assignment health;
   - either source is missing/stale: evidence incomplete, not success.

The pilot observation period is agreed per change risk. Do not broaden while a reboot, login cycle, policy refresh, or normal workday needed to exercise the control has not occurred.

## Phase 5: rollback or broaden

Rollback triggers include loss of access, application breakage, repeated policy conflict, unexpected scope, stale or missing verification evidence, or any material result outside the approved plan.

Rollback sequence:

1. Remove the affected Patched policy assignment from the pilot group. Do not delete the policy or edit the baseline version.
2. Restore the previously documented assignment only if Patched intentionally replaced one under the approved plan.
3. Confirm Intune received the assignment change and the affected endpoint returned to an operable state.
4. Run a fresh Patched collection where the rollback changes a measured control.
5. Record the incident, affected scope, decision, remaining exposure, and next action before another attempt.

If the pilot succeeds:

1. Present the reconciled before/after evidence and open exceptions to the authorised contact.
2. Obtain a separate approval for broad assignment. Pilot approval is not broad-rollout approval.
3. Add devices in controlled rings sized to the customer's support capacity. Preserve a holdback group until the final review.
4. Repeat Intune plus Patched reconciliation for every ring. Stop the expansion on the first unexplained disagreement.

## Phase 6: close and operate

Delivery is complete only when:

- every in-scope device is assigned, explicitly excepted, or recorded as unreachable/out of scope;
- every mapped control has a fresh Patched endpoint observation after deployment;
- Intune errors and conflicts are resolved or accepted with an owner and review date;
- the final pack version, assignments, exceptions, evidence index, and rollback record are attached to the engagement;
- the customer receives the agreed evidence and knows the named contacts and support route;
- the 90-day plan records residual get-fit work and the next posture review date.

After closure, treat a pack version change as a new controlled change. Do not edit the meaning of a version already deployed to a customer.

## Future automation boundary

This runbook deliberately uses the Intune admin centre and customer-approved manual consent/administration. PAT-612, PAT-613, PAT-615, PAT-616, and PAT-170 may automate parts of it only after real engagements show repeated, stable operations.

Automation must preserve the same invariants: immutable pack version, tenant and ring scoping, explicit approval, complete audit trail, rollback, and endpoint verification. A Graph success response can never replace Patched's on-device evidence.

## References

- [CIS golden baseline roadmap](cis-golden-baseline-roadmap.md)
- [CIS rule catalogue and evaluator contract](CIS_RULES.md)
- [Rule-pack authoring contract](RULE_PACKS.md)
- [Microsoft Intune: assign policies](https://learn.microsoft.com/en-us/intune/intune-service/configuration/device-profile-assign)
- [Microsoft Intune: macOS deployment guide](https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-macos)
- [Microsoft Intune: enrol devices](https://learn.microsoft.com/en-us/intune/device-enrollment/enroll-devices)
