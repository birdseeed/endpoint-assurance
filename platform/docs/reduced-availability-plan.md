# Reduced-availability plan

Two pages, per PAT-1500's own scope. This document covers only the
mechanical half - what runs, what to switch off, the shutdown and restart
sequences - because that half is derivable from the estate as documented.
The business-state half (what the first eight weeks are spent on if
availability holds, and where customer/pipeline/runway facts live) is
Andy's own call and is left unwritten below, marked accordingly.

## What is actually running unattended right now

Everything in this section runs today with no daily human input. The
question this document exists to answer is what happens to each of them
if that stays true for months rather than days, not what happens over a
week - `business-continuity-plan.md` (PAT-1498) already covers the
week-to-month horizon for a customer audience. This one is internal and
longer-horizon.

| What | Mechanism | Fails unsafely if left alone? |
|---|---|---|
| Nightly vendor verification + catalogue signing | `daily-vendor-verify.yml`, a scheduled GitHub Actions workflow in `updater` | No - it fails *closed* (skips signing, does not publish a bad catalogue) if the GitHub Actions budget runs out. See below. |
| Signed software catalogue | Artifact of the workflow above, served from `example-api-host` | No - a stale-but-signed catalogue is safe; agents keep using the last good one. |
| Alerting | Prometheus rules on `example-api-host`, delivering to email/Slack | No - alerts are read by nobody while pre-production regardless (standing decision), so this doesn't change behaviour, only removes the one pair of eyes that would act on a page. |
| The three VPSes (`example-api-host`, `example-prod-host`, `example-portal-host`) | Hetzner, billed monthly | **Yes, financially** - they keep costing money indefinitely if nobody cancels them. [Andy to confirm current monthly cost per box and the Hetzner billing/cancellation mechanism - not documented anywhere I could find.] |
| Domains (`patched.im` and subdomains, Cloudflare-managed) | Cloudflare Registrar / DNS | **Yes** - a lapsed renewal breaks every public surface (website, api.patched.im, app.patched.im, scan.patched.im) at once. [Andy to confirm renewal dates and whether auto-renew is on.] |
| GitHub org and its Actions budget | GitHub Team plan, per-org Actions minutes budget | **Yes, but fails closed, not silently** - PAT-1443 already found this budget can run out mid-month and hard-blocks all CI when it does. That's the correct failure mode for an unattended period (nothing publishes something wrong; it just stops publishing), but it means the catalogue stops updating and looks abandoned to anyone checking. |

## Shutdown sequence, if availability drops

In the order that minimises cost and risk fastest, cheapest actions first:

1. **Cancel or pause anything metered that a mothballed business doesn't need**: any paid tier on GitHub (Team plan minutes/seats), Linear (already at its free-plan issue cap as of 2026-09-09), and any other per-seat SaaS. [Andy to enumerate - this document doesn't have a full subscription list.]
2. **Leave the three VPSes running rather than tear them down**, unless the cost is a genuine problem. Rationale: they fail safe if untouched (see table above), and standing them back up from a cold state (fresh Hetzner boxes, restored from the R2 backup per `business-continuity-plan.md`'s restore path) costs more specialist time than a few months of hosting cost. Tear down only as a last resort, and only after confirming the R2 restic backups are current and the repository password is retrievable (that plan's own flagged gap - resolve that *before* relying on it as the fallback).
3. **Do not disable the nightly verifier or catalogue signing.** It fails closed on its own if the GitHub budget runs out; there's nothing to gain by disabling it deliberately, and it's one less thing to remember to re-enable.
4. **Do not touch alerting.** It's already unread by decision; leaving it running costs nothing and means it's ready the moment someone is watching again.
5. **Confirm domain auto-renew is on and the payment method behind it won't lapse.** This is the one item on this list that turns into an outage rather than a cost if missed - do this first in practice, even though it's listed last for cost-minimisation order.

## Restart sequence, if availability returns

Reverse order, cheapest confidence-check first:

1. Confirm domains and DNS are intact (they will be, if step 5 above held).
2. Confirm the three VPSes are still reachable over Tailscale and the last nightly backup heartbeat is recent (dashboard service-health strip).
3. Re-enable/re-fund anything paused in shutdown step 1 (GitHub Actions budget, Linear plan, etc).
4. Confirm the last signed catalogue isn't stale beyond what agents will tolerate, and that a fresh `daily-vendor-verify.yml` run succeeds.
5. Only then resume any customer-facing or sales activity - the estate should be confirmed healthy before it's represented as such to anyone.

## Not covered here - Andy's own sections

* **If availability holds: what the first eight weeks are spent on.** Depends on PAT-1302's answer, which has been "not this week" for seven weeks running as of this writing. Not something this document can respond to on your behalf.
* **Where the commercial state of the business is recorded.** No customer, pipeline, lead, invoice or runway fact currently has a home in Linear (the Working state doc is explicitly an engineering document). This needs your own input on what exists and where it should live.
