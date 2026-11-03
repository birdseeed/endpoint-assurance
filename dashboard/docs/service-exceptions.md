# Service exceptions (PAT-1966)

Home reads `GET /admin/service-exceptions/proxy` independently of the retained
Service health rail. It no longer invokes tenant attention, customer-posture
triage or the separate Home automation loader. Existing backend routes and
specialist permissions are unchanged. The browser assets use the server's
`CONSOLE_BUILD_ID` (`2026-10-04-pat1966`).

The proxy uses the existing admin session/Bearer and owner/consultant middleware.
It makes one fixed internal `GET /admin/service-exceptions`, sends no caller query
parameters, follows no redirects and returns `Cache-Control: no-store`. The
response is limited to 512 KiB, with a five-second transport timeout and an
additional six-second streaming deadline checked between chunks. An unavailable
or structurally invalid response is a generic 502, never successful empty data.
No provider request, job launch, schedule change, notification, credential read,
migration or recovery action is added.

`service_exceptions.py` projects the eleven fixed categories and their bounded
observations. UTC timestamps must describe real calendar dates, not lie in the
future, and retain their source value. Unknown nullable fields remain null.
Category/exception identifiers and tenant identifiers are checked. Only the fixed
`/console#ops` and `/console#automations` exception links are accepted. An invalid
known source is quarantined as unknown and its exceptions discarded; supported
exceptions from other categories remain. Unknown source IDs or broken top-level
arrays reject the response. Only contracted fields are copied at every level.

The browser validates the same evidence boundary independently, renders source
text through DOM text nodes, and never changes tenant context from an exception.
Loading, unavailable, partial coverage and a successful read with no recorded
exceptions have distinct states. Native disclosure controls and links retain
keyboard focus. A sequence guard prevents an older refresh replacing a newer
one. Every category exposes purpose, source/host, result, source timestamps,
reason and next action. Per-job evidence and prior success remain separate;
no category recovery, failure onset or next-run time is fabricated.

## Local evidence

The existing database path is opened in SQLite `mode=ro` under a scoped
`readonly_db_connections` context. The ordinary write connection path remains
unchanged. The projection also enables `query_only`, a one-second busy timeout
and a progress-handler deadline for each read, closes every connection and
never treats a failed query as a successful empty result.

- `check_statuses`: a fixed allowlist of email, revision, named-host maintenance
  and current scheduler tick checks. Only name, state and `evaluated_at` are
  selected, at most 64 rows. No raw reason is selected. Freshness uses the
  existing `_check_status_freshness` limits, not new monitoring thresholds.
  Invalid/future source times are unknown; expired readings are stale, not
  current failures or proof of an old release. A latest recorded successful
  check can retain its source success time even when that reading is stale.
- `report_send_audit_log`: the latest 100 attempts, with a 101st-row truncation
  signal. Only ID, source time, tenant ID and outcome are selected. Failed
  attempts are historical observations, not proof of an unresolved incident.
  A `sent` attempt remains unknown for recipient delivery. Actor, recipient,
  tenant label, detail, file paths and provider responses are not selected.

The upstream API still supplies active job history, tenant receipt age, backup
heartbeats and current API database-read scope. This dashboard does not redefine
its age thresholds. A global receipt does not establish reporting population; a
backup heartbeat does not establish restore success. Exact customer access and
provider membership, billing, provider bounce/delivery telemetry, processing and
feed outcome gaps remain visibly unavailable until those sources exist.

## Verification boundary

Frozen HTTP/middleware and real Chromium acceptance cover all eleven categories,
partial/empty/unavailable/loading states, source validation, role boundaries,
private-field removal, retry, hostile text and fixed keyboard links. Additional
Node and Python checks cover UTC/calendar rejection, independent-source
quarantine, scoped read-only database enforcement and per-job success history.
These are offline implementation checks. Independent review, publication and
installed verification belong to the parent run; this document makes no claim
that this dashboard slice is deployed or operationally accepted.
