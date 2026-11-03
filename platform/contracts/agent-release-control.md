# Agent release control (PAT-2004)

Platform implementation, migration `0204_agent_release_control`. Deployment,
real canary telemetry, CI stable-envelope creation (PAT-2003), and agent
consumption (PAT-2005) require separate operating evidence.

## Customer API

`GET /v1/portal/agent-releases` returns `channel`, `pinned_version`, `hold`,
`latest` keyed by platform then beta/stable, `devices` with override and effective
channel/version, observed daemon version and canary health, aggregate canary
readiness, and `p0_notice`. Global readiness contains no other tenant's device
identifiers. Any authenticated portal role can read.

`PUT /v1/portal/agent-releases` accepts one of:

```json
{"action":"device_channels","device_ids":["device-uuid"],"channel":"beta"}
{"action":"device_channels","device_ids":["device-uuid"],"channel":null}
{"action":"hold"}
{"action":"clear_hold"}
{"action":"approve"}
```

An override only opts a device into beta; `stable` is refused. Null or omitted
channel clears the override and restores the tenant policy. Bulk channel writes contain 1 to 500 unique owned device UUIDs, commit together,
and fail without partial changes for an unknown or foreign device. Only the
database-confirmed portal `admin` role can write, checked with `FOR SHARE` inside
the write transaction. Tenant and actor come from authenticated identity only.
Every accepted write records the actor, request and pin in the append-only audit.

Hold records a distinct hold flag and the current stable pin (or latest stable
if no pin exists). Approve clears hold and pins the latest stable. Clear hold
clears the hold and pin. A pin must exist for every OS in the tenant's estate.
Latest stable platform skew or missing stable state returns 409. An estate with
no devices requires matching macOS and Windows stable versions. Explicit beta
devices retain the tenant's stable pin ceiling and must never advance past it.
Existing tenant-wide beta configuration is
reported, but a beta device without an explicit pre-beta baseline cannot qualify
for promotion.

## Publication and evidence

Internal routes require the normal internal admin token. Request JSON is bounded,
rejects unknown/case-folded/duplicate keys and trailing input.

`POST /admin/agent-versions` publishes beta only. Existing exact identities can
be registered idempotently, including historical stable rows. Artifact changes
under an existing platform/channel/version return 409, preventing reuse of
observations from different bytes. New stable registration returns 409 with
`promotion_required`.

`POST /admin/agent-releases/promote` accepts the usual registration payload with
`channel=stable` and a CI-produced stable-channel `artifact_metadata_signature`.
The signed payload must bind the exact version, platform, channel, stable URL and
SHA256. SHA256 and HMAC must match the beta bytes. The API checks envelope shape
and binding; endpoint consumers still verify Ed25519 against their pinned key.
The platform does not hold the CI private artifact key. CI may use a stable URL
for the same bytes; it must publish those bytes before promotion. Stable insertion,
promotion record and audit are atomic. Beta is retained. Identical existing
stable metadata is idempotent; conflicts return 409. Re-registration never
refreshes publication time.

The gate requires an explicitly beta device belonging to a tenant with
`tenant_kind=internal`, plus every device effectively on beta for the platform.
No tenant name is treated as authority. Each device needs fresh, complete,
version-attributed inventory observations spanning at least 72 hours after both
beta entry and publication, with a final observation within 26 hours. This named
inventory-cadence tolerance accommodates daily uploads plus scheduling jitter.
Receiving
another version during the period blocks promotion. Soak uses server receipt
time, not the agent's clock; inventory more than five minutes from receipt time
cannot establish runtime evidence. Pre-beta health fault keys are snapshotted on
entry. Missing or stale pre-beta health (older than 26 hours), incomplete health,
or any newly introduced fault observed during the soak blocks promotion, even if
a later inventory clears it.

Daemon health is complete only when the health array is explicitly present,
no malformed or capped entries were dropped, and every sanitised entry was
successfully written under the accepted inventory watermark. Invalid, stale or
future runtime observations do not interrupt inventory ingestion: a bounded
`release observation skipped` warning names the device and reason, and no
release evidence is recorded.

`POST /admin/agent-releases/evidence` records complete monitor windows:

```json
{"platform":"macos","version":"1.2.3","metric":"upload","window_start":"2026-09-20T00:00:00Z","window_end":"2026-09-23T00:00:00Z","attempts":100,"failures":0,"provenance":"monitor:immutable-run-id"}
```

Allowed metrics: `artifact_verification`, `config_verification`, `service_crash`,
`restart_loop`, `enrolment`, `upload`. The first four require `device_id` and zero
failures. Enrolment/upload are aggregate platform/version rates and must omit
`device_id`, so failures before device creation remain countable. Counts are
bounded to 1 billion; failures cannot exceed attempts; attempt count must be
positive. Windows must have positive duration and cannot end more than five
minutes in the future. Provenance must identify an immutable monitor/CI run.
An identical window/provenance replay is idempotent; changed counts conflict.
Version evidence is channel-independent so monitors can report the previous
stable baseline. It cannot create beta publication authority: promotion still
requires the matching registered beta candidate.

For each participant the gate requires a complete candidate window covering its
whole soak through five minutes before promotion for every metric. Rate metrics
also require a >=72 hour aggregate window for the previous stable version,
ending within 26 hours before that device entered beta. Monitor coverage remains
continuous through five minutes before promotion; daily inventory tolerance does
not relax monitor coverage. Every candidate rate
sample intersecting the soak is compared to that stable baseline using exact
integer ratios. A failed blocker sample or an above-baseline rate sample remains
blocking even after a clean sample. Zero attempts and missing windows are
missing evidence, never success. Missing evidence returns precise refusal
reasons. Reports from currently absent monitors are not fabricated.

`POST /admin/agent-releases/observations` is the menu-bar version probe contract:

```json
{"device_id":"device-uuid","platform":"macos-menubar","version":"1.2.3","observed_at":"2026-09-23T00:00:00Z","health_complete":true,"fault_keys":[],"provenance":"probe:immutable-run-id"}
```

Only `macos-menubar` is accepted here; macOS/Windows daemon version comes from
successful inventory extraction. The probe must be within five minutes of the
server clock, name an owned macOS device and registered version, explicitly
report health completeness, and contain at most 128 unique bounded kind/subject
pairs. Provenance is immutable and idempotent; conflicting reuse returns 409.
The observation source is `internal_probe` and does not update device inventory.
The menu-bar pre-beta baseline comes from a fresh complete stable probe before
beta entry, not the daemon's health table. PAT-2003/monitoring must supply these
observations and windows; absence keeps promotion closed.

Inventory and portal changes participate in a shared promotion lock and are
serialised within their tenant before device or health writes, preserving the
pre-beta baseline. Promotion, publication and internal evidence use the exclusive
gate lock. Config projection takes only the tenant lock: unrelated tenants'
inventory and config reads are not globally serialised. Due notices are all
recorded as activated in one transaction, with one config generation bump.

## Critical security update

`POST /admin/tenants/{tenantID}/agent-releases/p0` accepts `version`, `banner`, and
`scheduled_at` at least 24 hours in the future. Version must be latest common
stable and the tenant must have a valid contact email. In one transaction it
records the immediate portal banner, due email schedule with recipient snapshot,
and audit. No customer API can cancel the notice.

The API's bounded Graph mail worker consumes due email schedules, retries every
five minutes up to 288 attempts, and stores pending/failed/delivered status and
an immutable attempt audit. Missing Graph configuration is an explicit failed
delivery. Graph acceptance is not proof of inbox receipt. Delivery is at least
once: a process crash after Graph acceptance but before commit may duplicate mail.
No real email is sent by tests. Operating acceptance requires an observed worker
attempt and actual authorised customer delivery, not merely a schedule row.

At the scheduled time signed agent configuration forces stable with a minimum
P0 version regardless of customer hold, ordinary pin or beta override. The
effective pin is the maximum of all due P0 floors and the customer's stable pin,
using the repository's strict version comparator. A newer approved stable pin
can advance beyond the floor; clearing a hold cannot remove the floor. Different
versions that cannot be safely ordered fail closed. Its first
config projection durably advances the config generation once. Customer control
writes remain audited but cannot suppress this projection.

Audit, observations, cohorts, rate evidence and promotions reject UPDATE,
DELETE and TRUNCATE. They survive tenant purge without tenant/device FKs. These
triggers protect against accidental mutation, not the owning deploy role. Live
settings and notice queues use tenant/device FKs and are purged with the tenant.
Rollback requires old binaries first and export of irrecoverable release ledgers
before dropping `0204` tables.
