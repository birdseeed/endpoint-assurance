# Finding verification lifecycle

PAT-1878 extends PAT-1829's disposition API with an evidence-backed,
append-only lifecycle shared by CIS, CVE and software-policy findings.

## Identity

Every lifecycle identity contains `tenant_id`, `finding_kind` and
`finding_key`. CIS and software findings also contain `device_id`; CVEs retain
PAT-1829's tenant-wide aggregate identity.

| Kind | Identity |
|---|---|
| `cis` | tenant + device + compliance `rule_key` |
| `cve` | tenant + CVE ID |
| `software` | tenant + device + `<drift_type>:<policy_id>` |

Software drift types are `mandatory_missing`, `unapproved_present` and
`version_below_minimum`. The staff drift endpoint returns this stable value as
`software_key`.

## Events and authority

`finding_lifecycle_events` is immutable. Update, delete and truncate are
blocked by database triggers. The complete sequence is available from:

```text
GET /admin/tenants/{tenantID}/finding-lifecycle/history
```

Optional filters are `finding_kind`, `finding_key` and `device_id`. Both read
endpoints also accept `limit` (default and maximum `500`) and `offset`
(default `0`). Every query is tenant-scoped even when an identity filter is
supplied. Responses include explicit `limit`, `offset` and `returned` page
metadata; the retained `total` field is the number returned on that page.

Human/customer actions are:

- `acknowledged`
- `risk_accepted` (retained PAT-1829 compatibility)
- `guidance_issued`
- `customer_applied`
- `pending_verification`

They are recorded through `POST /admin/tenants/{tenantID}/finding-dispositions`.
The legacy input `closed` is accepted only as an alias for
`pending_verification`. `verified_fixed`, `still_failing` and `recurred` are
never accepted from this route.

Actions and endpoint reductions take the same transaction-scoped lock for one
finding identity, so their append order cannot fork. Aggregate CVEs are
reconciled in bounded identity pages and one short transaction per tenant/CVE;
no lifecycle lock is retained across the estate.

Endpoint evidence produces:

- `first_observed` for the first authoritative failing observation;
- `currently_observed` for a later failing observation;
- `still_failing` when a fresh check fails after verification was requested;
- `verified_fixed` when a fresh authoritative check passes;
- `recurred` when a fresh failure follows a verified closure; and
- `verification_unknown` when collection is stale, partial, unavailable or
  otherwise lacks authority.

Patched itself produces one more event, `withdrawn` (PAT-2107), with
`source_type` `matcher`:

- `withdrawn` when a CVE finding stops being matched while a device that
  backed it still reports the same software at the same version. Nothing
  changed on the device, so the disappearance is a matcher correction (a
  matcher fix, a CVE feed revision or a mapping change), not a fix.

`withdrawn` is never authoritative and carries no `observed_at`, because it is
Patched's decision rather than endpoint evidence; the unchanged devices are in
its `evidence.unchanged_devices`. It is decided before the authority check and
needs no fresh inventory: the matcher reads only this same inventory, so if it
is unchanged nothing on the device can have caused the disappearance.
"Unchanged" compares the last failing evidence's app name and version with the
device's current inventory: `device_apps` (name case-insensitively, version
exactly), the device's `os_build`/`os_version` for OS findings, and the current
Homebrew list for Homebrew findings. The CVE identity is tenant-wide, so if any
backing device is unchanged the identity is withdrawn rather than claimed as
fixed, even when another device did upgrade. A finding whose software was
removed or whose version changed keeps the authority-gated `verified_fixed`
path above.

A withdrawn finding is closed but not fixed: a later pass adds nothing (it is
never turned into `verified_fixed`), a verification requested before it is
moot, and reconciling it again adds nothing. If the matcher matches it again
it re-opens as `first_observed`, a new finding rather than a recurrence of a
fix that never happened. `withdrawn` raises no notification.

Freshness uses the endpoint's `collected_at`, not server receive time. A
replayed or re-extracted payload at or before the latest observation or
verification request cannot close a finding. Missing collection times and
times more than five minutes ahead of trusted server receipt are not
authoritative. Evidence delayed by more than 24 hours relative to trusted
receipt is also non-authoritative, matching the product's daily inventory
cycle. When verification is pending, trusted receipt itself must be later than
the request; tolerated endpoint clock skew cannot make evidence received
before the action verify that action.

CIS authority requires a real observed value. A pass manufactured by a rule's
unknown-evidence fallback cannot close a finding. Software absence requires an
explicit authoritative inventory scope (`all_software` or the bounded
`windows_winget` scope). Software lifecycle evaluation uses the same full
identity, platform override and specificity precedence as the staff drift and
signed posture surfaces, so a specific approval suppresses a broader
unapproved match consistently. CVE closure requires every device that backed the
last failing aggregate to submit a newer inventory authoritative for the
matched application's scope. The newest inventory run by trusted receipt is
evaluated as a whole; an older complete run is never reused when the newest
run is incomplete. OS CVEs use the always-present OS inventory
fields rather than application absence authority. Native or non-Winget
Windows matches remain valid positive observations, but their unsupported
absence scope can never verify closure. A missing, `unknown` or unparseable
installed version leaves minimum-version verification unknown rather than
being treated as a passing version.

## Current projection

```text
GET /admin/tenants/{tenantID}/finding-lifecycle
```

This returns the latest state plus milestone timestamps, recurrence count and
event count. `verified_fixed_at` remains populated after a recurrence, so the
current projection never erases closure history. The event endpoint remains
the canonical audit record. The same bounded `limit`/`offset` contract applies
to current projections and immutable history.

## Migration and rollback

Migration `0191_finding_lifecycle_withdrawn` (PAT-2107) widens the event type,
source type and source-shape CHECKs for `withdrawn`/`matcher`. The authority
CHECK is unchanged: it already forces every non-`endpoint_observation` row to
`authoritative = false`. Its rollback refuses once any withdrawn row exists.

Migration `0156_finding_verification_lifecycle` is additive. It retains the
PAT-1829 table, extends it for software identities and backfills every existing
disposition. A legacy human `closed` row becomes a migrated
`pending_verification` event, never a verified closure.

Rollback is fail-closed when any lifecycle event exists because those events
are non-reconstructible commercial and audit history. Before the first event,
the rollback restores the exact PAT-1829 constraints and mutation guard.

## Notifications

PAT-1888 turns five of these transitions into customer notifications:
`first_observed`, `recurred`, `verification_unknown`, `verified_fixed` and
`still_failing`. `currently_observed`, `withdrawn` and the operator action
events raise nothing.

Events are raised only after the transaction that wrote the lifecycle row has
committed, and raising one performs database writes only. Delivery happens in a
separate sweeper, so a destination that is down, slow or hostile cannot fail,
delay or roll back the transaction that established the finding. Nothing in the
notification path re-judges evidence: a stale-evidence notification says
verification could not be confirmed, never that the finding cleared.

Channel configuration, the signature recipe, the event catalogue and the
dead-letter view are in `docs/NOTIFICATIONS.md`.
