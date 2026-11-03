# Notifications

PAT-1888. Tenant owners configure where finding, stale-evidence and
verification events go, and Patched delivers them without an operator running
each channel by hand.

This is separate from the PAT-134 outbound webhooks (`tenant_webhooks`), which
keep serving their own two event types. See "Relationship to PAT-134" below.

## What a notification is allowed to say

A notification is a product claim, so the wording is constrained by the
evidence behind it:

- Every event is derived from a finding lifecycle transition that has already
  been written. Nothing in the notification path judges evidence, re-derives a
  status, or decides a finding is closed.
- `evidence.stale` says verification could not be confirmed. It never says a
  finding cleared. Absence of evidence is not authority.
- `verification.passed` is raised only from the lifecycle's `verified_fixed`
  transition, which the reducer produces only from fresh, authoritative
  endpoint evidence.
- An event with no severity is delivered rather than filtered out. A severity
  threshold suppresses findings we know are below it, never findings we merely
  failed to grade.

## Event catalogue

| Event | Raised from lifecycle transition | Meaning |
|---|---|---|
| `finding.opened` | `first_observed` | A finding failed for the first time. |
| `finding.recurred` | `recurred` | A previously verified-fixed finding is failing again. |
| `evidence.stale` | `verification_unknown` | Verification was requested, and the evidence needed to judge it is missing or older than one collection cycle. The finding is not cleared. |
| `verification.passed` | `verified_fixed` | Fresh authoritative evidence shows the finding now passes. |
| `verification.failed` | `still_failing` | Fresh authoritative evidence shows the finding still fails after a customer action. |
| `test.ping` | none | A synthetic test event. Not subscribable; sent only by the test endpoint. |
| `software.first_seen` | none (PAT-2009) | The daily new software digest. Raised only for a tenant that has turned the new software notification on (off by default); see "New software notification" below. |

`currently_observed` raises nothing. It is the daily restatement of a failure
that has already been notified. `withdrawn` (PAT-2107) raises nothing either:
it records a matcher correction, a CVE finding Patched retracted while the
software on the device stayed the same, and it must never read as
`verification.passed`. The operator action events
(`acknowledged`, `risk_accepted`, `guidance_issued`, `customer_applied`,
`pending_verification`) also raise nothing: they are the customer's own actions
coming back at them.

Events are raised from three places, always after the transaction that wrote
the lifecycle row has committed:

- `internal/extractor` for CIS and software-policy findings, per payload.
- `cmd/patched-cve-sync` for CVE findings, per reconciliation.

## Channels

A channel is one destination owned by one tenant. Two types exist.

**Webhook.** A tenant-supplied `https://` URL plus a signing secret Patched
generates. Delivery is an HTTP POST through the SSRF-hardened outbound client.

**Email.** A list of recipient addresses, at most 25. Delivery goes through
Microsoft Graph `sendMail` from the Patched mailbox (`internal/graphmail`),
which is the only customer email transport this service uses. Email is not
signed.

Both types carry:

- `events`: which of the catalogued event types this channel wants.
- `min_severity`: one of `low`, `medium`, `high`, `critical`. The default is
  `low`, which takes everything.
- `enabled`: the per-tenant rollback switch.

### Routes

All on the internal Tailscale-bound listener, behind `ADMIN_API_TOKEN`.

```text
GET    /admin/tenants/{tenantID}/notification-channels
POST   /admin/tenants/{tenantID}/notification-channels
PUT    /admin/tenants/{tenantID}/notification-channels/{channelID}
DELETE /admin/tenants/{tenantID}/notification-channels/{channelID}
GET    /admin/tenants/{tenantID}/notification-channels/{channelID}/deliveries
POST   /admin/tenants/{tenantID}/notification-channels/{channelID}/test
GET    /admin/tenants/{tenantID}/notification-deliveries
```

Create a webhook channel:

```bash
curl -sS -X POST "$ADMIN/admin/tenants/$TENANT/notification-channels" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "channel_type": "webhook",
        "name": "Security team endpoint",
        "destination_url": "https://hooks.example.com/patched",
        "events": ["finding.opened", "evidence.stale", "verification.passed"],
        "min_severity": "high"
      }'
```

The response carries `secret` once. It is stored envelope-encrypted and is
never returned again by any route, including update and test. There is no
retrieval path and no rotation path through update: to change the secret,
create a new channel and delete the old one.

Create an email channel:

```bash
curl -sS -X POST "$ADMIN/admin/tenants/$TENANT/notification-channels" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "channel_type": "email",
        "name": "IT inbox",
        "recipients": ["it@customer.example"],
        "events": ["finding.opened", "finding.recurred"]
      }'
```

`channel_type` is immutable after creation. An update leaves absent fields
alone, so `{"enabled": false}` is a complete rollback request.

## Signature verification recipe

Every webhook delivery carries four headers:

| Header | Value |
|---|---|
| `X-Patched-Event` | the event type, for routing before parsing |
| `X-Patched-Timestamp` | Unix seconds when the delivery was signed |
| `X-Patched-Signature` | `sha256=<hex>` |
| `X-Patched-Idempotency-Key` | the deterministic key for this delivery |

The signature is `HMAC-SHA256` over `"<timestamp>.<raw body>"`, keyed by the
UTF-8 bytes of the 64-character hex secret shown at channel creation. The
timestamp is inside the signed material, so a captured delivery cannot be
re-dated and replayed.

```python
import hashlib, hmac, time

def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 300:
        return False                       # reject replays outside five minutes
    material = timestamp.encode() + b"." + body
    expected = "sha256=" + hmac.new(secret.encode(), material, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Sign over the raw request bytes, before any JSON parsing or re-encoding.

The PAT-134 `tenant_webhooks` path uses the older body-only recipe
(`HMAC-SHA256` over the body alone) and is unchanged, so existing receivers
keep working.

## Payload

```json
{
  "event_type": "finding.opened",
  "tenant_id": "<uuid>",
  "subject": "cis/<device-uuid>/audit_pam_su@2026-09-20T09:12:31Z",
  "severity": "high",
  "idempotency_key": "<64 hex chars>",
  "timestamp": "2026-09-20T09:12:31Z",
  "data": {
    "finding_kind": "cis",
    "finding_key": "audit_pam_su",
    "lifecycle_event": "first_observed",
    "device_id": "<uuid>",
    "rule_key": "audit_pam_su",
    "status": "fail",
    "benchmark_version": "2.1.0",
    "observed_at": "2026-09-20T09:12:31Z"
  }
}
```

The idempotency key is in the body as well as the header, so a receiver that
reads only the body can still deduplicate.

## Idempotency

The key is `SHA-256` over `channel_id`, event type and subject, joined with a
unit separator. A unique index on `(channel_id, idempotency_key)` makes a
duplicate trigger a no-op insert rather than a second delivery.

The subject is the deduplication unit:

```text
<finding kind>/<device id or ->/<finding key>@<observed_at RFC3339Nano>
```

The observation time is part of it deliberately, and it is the evidence's own
timestamp rather than a row id or the wall clock. Re-processing the same
payload produces the same subject and is suppressed, which is the replay we
want gone. A transition drawn from a later collection produces a new subject,
so a finding that recurs twice is notified twice.

## Delivery, retry and dead letters

Raising an event and delivering it never touch:

1. Raising writes `notification_deliveries` rows and nothing else. There is no
   network call on that path, so a destination that is down, slow or hostile
   cannot fail, delay or roll back the transaction that established the
   finding.
2. A sweeper inside `patched-api` polls due rows every 20 seconds, makes one
   attempt each through a bounded worker pool, and records the outcome.

Because the schedule lives in `next_attempt_at` rather than in a timer, a
restart mid-backoff loses nothing.

Each delivery row ends in one of three states:

| State | Meaning |
|---|---|
| `pending` | awaiting a first attempt or a scheduled retry |
| `delivered` | accepted by the destination |
| `dead_letter` | terminal failure |

A dead-lettered row carries `failure_reason`:

| Reason | Cause |
|---|---|
| `permanent_error` | the destination returned 4xx, or Graph rejected the message for a reason retrying cannot fix |
| `max_attempts` | the retry budget was spent on retriable failures |
| `undeliverable_configuration` | the channel cannot be delivered to at all: a blocked destination, a missing secret, a signing secret that cannot be decrypted, no recipients, or an unconfigured Graph mailer |

A signing secret that cannot be unwrapped, which is what a rotated or removed
`PATCHED_KEK` produces, dead-letters on the first sweep rather than being
skipped. Skipping it would leave the row pending and due forever, and because
the sweeper selects the oldest due rows up to a batch limit, a run of such rows
would crowd healthy deliveries out of every batch. The stored `last_error` says
only that the secret could not be decrypted: no ciphertext, no key material.

The budget is six attempts, with the shared backoff (30 seconds doubling,
capped at one hour), so a failing destination reaches its terminal state in
roughly two hours rather than retrying indefinitely. Every attempt updates
`attempt_count`, `response_status`, `last_attempt_at` and `last_error`.
`last_error` is truncated and redacted: query strings, bearer tokens and client
secrets are stripped before it is stored.

List the dead letters for a tenant:

```bash
curl -sS "$ADMIN/admin/tenants/$TENANT/notification-deliveries?state=dead_letter&limit=50" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN"
```

`limit` is clamped to 200. `state` accepts `pending`, `delivered`,
`dead_letter` or nothing for all three. The same filters work per channel on
`/notification-channels/{channelID}/deliveries`.

Retention is not automatic yet. `notifications.PruneDelivered` removes
delivered rows older than a given age in one bounded statement, and never
touches pending or dead-lettered rows, but nothing schedules it. See
"Follow-ups".

## Test events

```bash
curl -sS -X POST "$ADMIN/admin/tenants/$TENANT/notification-channels/$CHANNEL/test" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN"
```

It sends one synthetic `test.ping`, signed exactly like a real delivery, and
returns the delivery row id and its state. The only row it writes is that
delivery record: no finding, no `finding_lifecycle_events` row, no compliance
evaluation. The payload is explicitly marked `"test": true` and says in words
that it is not a finding, so a receiver cannot mistake it for evidence.

Each call uses a fresh subject, so a repeated test is delivered again rather
than deduplicated against the first.

A failed test still returns 200 with the failure in `state`. The delivery row
records what happened either way.

## Secrets

- Webhook signing secrets are generated server-side, returned once at creation,
  and stored through the envelope helpers (`PATCHED_KEK`, `penc1:` prefix) with
  the same decrypt-with-plaintext-fallback as `internal/webhook`.
- No read, list, update or test response carries a secret. The `Channel` type
  has no field one could travel in.
- Transport errors are redacted before they are stored or logged.
- `internal/graphmail` builds its own error values rather than wrapping the
  transport's, so the Graph client secret cannot reach a log line through an
  error string.

## SSRF protections

Webhook destinations are tenant-supplied, so they are treated as hostile. The
controls live in `internal/webhook/safedial.go` and are shared with PAT-134
rather than reimplemented:

1. `ValidateDestination` at configuration time rejects anything that is not
   `https://` and any literal internal address.
2. The dialer's `Control` hook runs after DNS resolution on the concrete
   address about to be dialled, so DNS rebinding does not help. It refuses
   loopback, RFC1918, unique-local, link-local (including `169.254.169.254`),
   unspecified, multicast and the `100.64.0.0/10` tailnet range.
3. Redirects are never followed, so a 3xx to an internal host cannot escape the
   first two.
4. `PostHardened` re-validates the stored URL at the point of use, so a row
   that predates a policy change is refused rather than delivered to.

A destination we will always refuse is treated as a configuration fault and
dead-letters immediately, rather than spending the whole retry budget first.

## Rollback

Per tenant, per channel:

```sql
UPDATE notification_channels SET enabled = false, updated_at = now()
WHERE tenant_id = '<uuid>';
```

or `PUT .../notification-channels/{channelID}` with `{"enabled": false}`.

A disabled channel accepts no new events and its queued deliveries are not
swept, because the sweeper joins on enabled channels only. Configuration,
delivery history and retry state all stay put. There is no destructive
migration in this feature.

Deliveries already queued when the channel was disabled stay `pending`. They
are retained rather than sent, they remain visible on the channel's deliveries
listing (`?state=pending`), and they resume from where they were if the channel
is re-enabled. Nothing is discarded and nothing is silently dropped, so the
retained retry state can be inspected while the rollback is in force.

`0157_notification_channels_rollback.sql` is the schema-level reversal and is
destructive: it discards every channel and the whole delivery audit trail. It
is for removing the feature from the platform, not for stopping one tenant's
notifications.

## Configuration

| Variable | Purpose | Missing |
|---|---|---|
| `GRAPH_MAIL_TENANT_ID` | Entra tenant id of the Patched.im tenant | email channels dead-letter |
| `GRAPH_MAIL_CLIENT_ID` | "Patched.im Mailer" app registration id | as above |
| `GRAPH_MAIL_CLIENT_SECRET` | client secret for that app | as above |
| `GRAPH_MAIL_FROM` | sending mailbox, for example `noreply@patched.im` | as above |
| `PATCHED_KEK` | envelope key for signing secrets at rest | secrets stored in plaintext |

An incomplete `GRAPH_MAIL_*` configuration is logged once at startup and leaves
webhook channels working. Email deliveries then dead-letter with
`undeliverable_configuration` and a `last_error` naming the missing
configuration, so the failure is visible to the tenant owner rather than
silently invisible.

## New software notification (PAT-2009)

`software.first_seen` is not a lifecycle transition, so it sits outside
`webhook.FindingEvents` in `webhook.SoftwareChannelEvents`; a channel may
subscribe to either list (`webhook.ChannelEvents`). It is raised only when
the tenant's `new_software_enabled` setting is on
(`/v1/portal/software-notifications`, default off), by the software
governance runner in `patched-api`, once a day for the window ending at the
07:00 UTC slot. The window starts where the previous one ended
(`tenant_software_notification_settings.new_software_notified_through`), so
nothing is skipped or repeated, and the subject is the window end, so a
replayed window is deduplicated by the idempotency key. A day with no new
product raises nothing. The data block carries `window_start`, `window_end`,
`product_count`, `truncated`, `coverage` and up to 200 `products` (name,
platform, identifier, product key, approval state, first seen, device count,
first device hostname).

A Slack incoming webhook cannot receive this directly: channels post the
Patched JSON body, and Slack expects its own `text` payload. Point the
channel at an email address, or at a relay that reformats.

## Unapproved software alert lifecycle (PAT-2097)

The customer's unapproved software alert (`software.unapproved_detected`,
`docs/API.md`) is now tracked per (episode, device) as `open`,
`acknowledged` or `resolved`. What that changes about delivery:

- **Acknowledging and resolving send nothing.** No email, no webhook.
- **A re-open sends no immediate email and no webhook.** An alert resolved
  as not observed whose product is reported on the device again, still
  Unapproved, re-opens
  and is listed once in the tenant's next 07:00 UTC unapproved software
  digest, in a "Found again" section after the newly found products. A
  digest can now be sent for re-opens alone. Re-opens are cleared once that
  digest is sent, or when the tenant has no contact email. A transient send
  failure retries with the same backoff and attempt limit as pending alerts,
  without spending the day's slot, even when the digest holds only
  re-opens; a permanent failure or exhausted retries leaves them for the
  next day's digest. A re-open newer than the digest's slot is never
  cleared by it. An alert acknowledged or resolved
  again before the digest is not listed.
- The choice is deliberate: the product was already reported once for this
  episode, and an immediate email each time an intermittently reporting
  device flips would be noise. A new Unapproved decision is a new episode and
  alerts as before.

## Relationship to PAT-134

`tenant_webhooks` and `webhook_deliveries` serve `score.changed`,
`vulnerability.discovered` and, since PAT-2009, `software.unapproved_detected`
(the customer's unapproved software alert, see `docs/API.md`). They still use
the body-only signature, and still have their own sweeper and their own
8-attempt budget. The unapproved alert is enqueued with `webhook.Enqueue`,
inside the same transaction as its dedupe ledger, and delivered only by the
sweeper.

PAT-2009 fixed the sweeper to decrypt the stored secret before signing. It
signed with the stored value, which is `penc1:` ciphertext whenever
`PATCHED_KEK` is set, so every retry of a PAT-134 delivery carried a
signature no receiver could verify.

The finding events are deliberately not added to the legacy subscription list.
Nothing fires them through `tenant_webhooks`, so accepting a subscription there
would create a configuration that looks healthy and silently never delivers.
`webhook.KnownEvents` is the legacy set and `webhook.FindingEvents` is this
catalogue, and a test guards the split.

What is shared rather than duplicated: the SSRF-hardened HTTP client, the
signing helpers, the retry decision (`webhook.ClassifyAttempt`, which the
PAT-134 sweeper now delegates to) and the backoff curve.

## Follow-ups

- Nothing schedules `PruneDelivered`, so delivered rows accumulate. A timer or
  a call from an existing nightly job would close it.
- CVE events are graded from `device_cve_findings.severity`, which is absent on
  the closure path (the findings have already been pruned). Those events are
  ungraded and therefore delivered to every subscribed channel regardless of
  threshold, which is the correct default but noisier than a graded one.
- Score and vulnerability events still ride the PAT-134 path. Folding them into
  channels would give them thresholds, idempotency and dead letters too.
