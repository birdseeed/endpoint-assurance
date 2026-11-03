# Service exceptions (PAT-1966 backend slice)

`GET /admin/service-exceptions` is a read-only internal admin route. It uses the
existing `ADMIN_API_TOKEN` guard on the internal listener. It is absent from the
public router and has no write method, tenant filter, source path or action URL.
Query parameters do not select evidence. Responses use `Cache-Control: no-store`.
This is local implementation evidence, not deployed operating proof. The dashboard
integration, independent review and installed verification remain separate gates.

## Wire contract

The JSON object contains `observed_at` (UTC request observation time), `coverage`
(always `partial` in this slice), `checks` and `exceptions` (always arrays).

Every check contains:

| Field | Meaning |
| --- | --- |
| `id`, `name`, `explanation` | Stable category and plain-language purpose |
| `source`, `scope` | Evidence source and host/component scope |
| `availability` | `available`, `degraded` or `unavailable`; partial evidence is degraded |
| `result` | `ok`, `failed`, `stale`, `unknown` or `unavailable` |
| `checked_at` | UTC request reading time, or null for an unconnected source |
| `last_success_at` | Actual source success timestamp or null; never a successful request disguised as history |
| `next_expected_at` | Actual source schedule time or null; always null in this slice |
| `reason`, `next_action` | Plain explanation and read-only investigation guidance |

Scheduled-job and backup checks also include bounded `observations` rows with
`id`, `scope`, `result`, nullable `evidence_at` and nullable `last_success_at`.
These retain actual per-job success history without claiming category-wide health.
Scheduled-job success history is limited to the 10 rows read for each job.

Every exception contains `id`, `check_id`, nullable `tenant_id`, `scope`, nullable
`since`, `evidence_at`, `reason` and `deep_link`. `since` is null because these
sources do not establish failure onset; the reason explicitly says so. Evidence
uses UTC source completion, receipt or heartbeat timestamps. Links are fixed
`/console#automations` or `/console#ops`, verified against the existing dashboard
section catalogue. Tenant identity comes only from the filtered database join.
Checks have fixed order; exceptions sort by ID. Private job output, errors,
heartbeat labels/details, recipients, report paths and credentials are not emitted.

## Evidence and limits

| Check | Source and interpretation |
| --- | --- |
| Scheduled jobs | Registry metadata from `internal/automations/tracker.go`; only `active` jobs. Read at most 10 rows per job, ordered by start time then row ID, without selecting output/error columns. Only the latest valid completed observation can produce an exception. `failed` and `warning` are failures; latest success clears the older failure. Consecutive failures/warnings are counted only within the returned 10 rows. Missing, running, invalid or future-dated observations remain unknown. Portal backup run history is not fabricated from a heartbeat. |
| Device reports | Latest global `raw_payloads.received_at`, plus the oldest 100 customer receipt observations. The join requires `tenant_kind = customer` and `revoked_at IS NULL`. A 101st row makes truncation explicit. Global `last_success_at` means successful receipt only. No observation, a failed query or a fresh global receipt can establish that all devices report. Expected population, reporting-drop detection and processing failure outcomes remain unknown. |
| Backups | Fixed `db-r2.json`, `prod-r2.json`, `portal-r2.json` heartbeat files from the configured local directory. Missing, malformed, oversized, unreadable, mismatched-job, unknown-status and future timestamp files remain unknown. File and directory symlinks are rejected; `openat` pins the directory and refuses FIFOs/nonregular files. Each file is capped at 4 KiB. Failed status uses the file modification timestamp as local heartbeat evidence, never as job completion or failure onset. Staleness uses actual last success. Success is not restore-test evidence. |
| Server health | A bounded database ping establishes only current API database connectivity. No stored success history, remote server availability, disk capacity or certificate status is claimed. |
| Outgoing email | Unavailable: dashboard email checks are not connected. Configured channels do not prove authentication, acceptance, rejection, bounces or recipient delivery. |
| Customer access | Unavailable: API mappings do not establish exact provider membership, invitations or provisioning outcomes. Dashboard federation and PAT-2382 integration are separate. |
| Assurance processing | Unavailable: no confirmed durable evaluator/matcher job outcome source and threshold is connected. Customer findings are not service failures. |
| Vulnerability data | Unavailable: feed outcome and source-owned overdue evidence are not connected. |
| Reports | Unavailable: migration 0126 freezes issued `report_records` with pending delivery; migration 0052's delivery enum is not a working mailer. Do not infer failed delivery, stuck generation or recipient proof from these rows. Dashboard `send_audit` and check status remain separate sources. |
| Version checks | Unavailable: deployment receipts and file verification records are not connected; stale verification is not an old-release verdict. |
| Billing | Unavailable until provider integration: no invented trial-end, payment-failure, cancellation or webhook evidence. |

Intune connector outcomes, catalogue sync failures and signup-to-first-finding
age also lack a supported source here. Quarantined/retired catalogue history is
excluded, not labelled current. These require bounded source work before becoming
operating exceptions; this endpoint does not call providers or start collectors.

The database work shares one 5-second request context, including pool acquisition,
queries and ping. Failed reads discard that source's partial query results and
remain degraded/unknown; another source's supported exception can still appear.
The API executes SELECTs only. Backup files are local regular-file reads with a
fixed job count and byte limit. There is no filesystem scan, arbitrary path read,
provider request, job launch, schedule change or database mutation.

## Threshold provenance and remaining decisions

| Observation | Limit | Existing source |
| --- | --- | --- |
| Global receipt | Older than 4 hours; critical copy after 24 hours | Dashboard `static/js/console-work.js`, `ingestHours` |
| Customer receipt | Older than 12 hours; critical copy after 48 hours | Dashboard `static/js/console-work.js`, `lagHours` |
| Backup last success | Older than 26 hours | Dashboard `static/js/console-work.js`, backup `ageHours` |
| Completed active daily/nightly job | Older than 36 hours | Dashboard `static/js/console-automations.js`, 24-hour interval times `STALE_MULTIPLIER = 1.5` |

Comparisons are strictly greater than the limit. They describe observation age,
not proven downtime, failure onset, a missed schedule or a population drop.

The current active Go registry jobs are `health_signals_recompute` (daily),
`api01_backup`, `prod01_backup` and `portal01_backup` (nightly). The automations UI
uses an explicit 24-hour health-signals interval and the 24-hour daily/default
interval for these other jobs, multiplied by 1.5. The feed applies that existing
coarse **36-hour UI heuristic** to these named jobs' completed observations,
retaining the actual completion and success timestamps. The separate backup
heartbeat source keeps its **26-hour** last-success limit. The earlier prepared
30-hour stale-job criterion reused the backup limit incorrectly; it has been
corrected to a safely overdue 40-hour fixture, with separate 30-hour and 36-hour
boundary HTTP tests.

This validates observation-age provenance, not exact timer schedules. Registry
schedule descriptions do not establish the next expected run, missed schedule,
stuck-running limit or failure onset: `next_expected_at` and exception `since`
remain null. A future job without validated cadence retains unknown observation
scope; the feed does not apply the UI's default interval to unknown jobs.

No source-owned thresholds are assumed for signup age, report generation, assurance
processing, feed freshness, restore tests, disk capacity or certificate expiry.
These gaps require a bounded follow-up source/threshold decision. No new timers,
migrations, credentials, provider access or operating claims are introduced.
