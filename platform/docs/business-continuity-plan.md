# Business continuity plan

**Audience:** customer due diligence, supplier take-on questionnaires, insurers, Cyber Essentials and ISO assessors.
**Owner:** Patched.im Ltd (139269C), Isle of Man.
**Status:** first published draft, 3 September 2026 (PAT-1498). Written to be honest rather than reassuring, because a plan that overstates its own maturity fails at exactly the moment it is read.

## The question this document exists to answer

Patched is delivered by one person. Any serious buyer will ask what happens to their evidence, their agents and their data if that person is unavailable. Three horizons, answered plainly.

## What is actually at risk

Patched holds device inventory, software and compliance evidence for its customers, and runs a collector on their endpoints. It does not hold anything the customer cannot operate without: it is an evidence and governance layer, not a control plane. No endpoint depends on Patched to boot, to authenticate, to receive updates or to reach the internet. If Patched stops entirely, no customer estate stops working.

That is the single most important sentence in this plan, and it is a consequence of the product boundary rather than of a mitigation. Patched observes and evidences; the customer's own Intune, Jamf or patching platform remediates. Losing the supplier loses the evidence, not the estate.

## Unavailable for a week

Nothing is required. Collection, evaluation, scheduled reporting and backups all run unattended. The customer portal continues to serve live posture and on-demand reports. Retainer review work pauses and is picked up on return.

Practical limit: an incident on the platform during that week would not be responded to. Alerting exists and is proven by injected failure, but there is one pair of hands behind it.

## Unavailable for a month

The estate continues to operate. What lapses is judgement work: no assessment reports written, no findings reviewed, no retainer sessions. A customer needing evidence during that period can self-serve it from the portal, which is why the portal is a continuity control and not just a convenience.

At this horizon a customer should be told, and offered either a pause in fees or a clean exit under the terms below.

## Unavailable permanently

The plan is orderly wind-down, not indefinite drift.

**Agents remove themselves.** Every agent ships with a signed expiry. When the date passes it removes itself with no directive sent and no server contact required. This inverts the usual risk: if Patched disappears, the collector comes off the estate by design rather than persisting unmanaged on someone's laptops. The mechanism is built (PAT-1108, PAT-1109, PAT-1110); confirming it end to end on a real endpoint is part of the delivery dry run (PAT-1301) and must be done before the first customer install.

**Data goes back to the customer.** Full export of their inventory, findings and reports, in a documented format, followed by deletion. The export path exists in the portal today.

**Restoration by someone else is possible.** The estate is documented to an external-auditor standard: an architecture overview, per-host architecture notes, a secrets-management register, deploy and restore runbooks. A competent engineer with the credentials can stand the platform up from the backups. What makes that real rather than theoretical is credential escrow, which is the open item below.

## Backups and restore

| Leg | Mechanism | Schedule | Retention |
|---|---|---|---|
| Off-provider, primary | Restic, `pg_dump -Fc` to Cloudflare R2 `patched-backups` | Nightly 03:00 UTC | 7 daily, 4 weekly, 3 monthly |
| prod-01 | `dashboard.db` and generated reports to R2 `patched-backups/prod-01` | Nightly | As above |

Backups are encrypted client-side with AES-256 before they leave the server, so the backup store holds ciphertext only. Each leg ships a heartbeat on completion and the state is surfaced on the dashboard service-health strip. The first R2 snapshot was verified clean.

**Restore path:** `restic restore latest`, then `pg_restore` into a fresh PostgreSQL instance, then a DNS swap at Cloudflare. **Target RTO: one working day. Target RPO: 24 hours**, bounded by the nightly schedule.

**Relocation:** a documented playbook moves the estate from Hetzner to a UK provider within one working day, for a customer whose own obligations require UK data residency.

## The gaps, stated rather than hidden

A due-diligence reader will find these anyway, and finding them unlisted is worse than finding them listed.

- **The restic repository password is the single unrecoverable secret.** If both the environment file and the password-manager entry are lost, the R2 backup repository cannot be opened by anyone. Escrow of that password, held so that a third party can reach it if Andy cannot, is the highest-value continuity control not yet in place and is the practical meaning of everything under "unavailable permanently".
- **No alert has ever fired in production.** The alerting is built and has been proven by deliberately injected failure, but the production alert directory is empty, so there is no positive delivery evidence from a real incident.
- **Deploy provenance is broken or absent on two of three hosts** (PAT-992), so the running commit cannot currently be proven from the outside on those boxes.
- **The three production signing keys are software-generated and held in CI secrets**, against an internal runbook that specifies a cloud HSM. The gap is known, deliberate and estate-wide; migrating all three together is planned rather than built.
- **A disaster-recovery rehearsal has not been run end to end.** Restores have been verified at the snapshot level; a full restore-and-swap under timed conditions has not.
- **A backup leg has silently failed before.** PAT-949 was marked Done while `portal-01` in fact had no backups for three days. The heartbeat that would now catch that is the fix; the incident is recorded because it is the reason to trust the heartbeat rather than the ticket.

## Review

This plan is reviewed when any of the following changes: the hosting estate, the backup mechanism, the number of people delivering the service, or the product boundary. It is reviewed in any case before the first customer signature and annually thereafter.
