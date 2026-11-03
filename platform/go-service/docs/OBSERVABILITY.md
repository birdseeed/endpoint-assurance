# Observability and logging

**Status:** Prometheus instrumented (4 metrics, live). No Grafana, no Alertmanager, no log aggregation yet.

> **Correction (PAT-1377, 2026-08-15):** this snapshot predates Alertmanager
> and the real alert rules (`api-vps-artefacts/alerting/prometheus-rules-patched.yml`,
> live since PAT-149) and is wrong on two of the four metrics below:
> `patched_extractor_rows_processed_total`'s label is `result`, not `status`,
> and `patched_extractor_batch_size` is a Histogram, not a Gauge (so its
> series are `patched_extractor_batch_size_{bucket,count,sum}`, not a bare
> name). Those two errors are exactly what let `ExtractorStalled` and
> `DeadLetterRows` ship matching zero series in production; see PAT-1377 and
> `go-service/docs/architecture.md` "Current state" for what's actually true
> today. Treat this whole file as historical background, not a live
> reference; it has not been kept in sync with what actually deployed.

---

## Current state

### Prometheus metrics (live)

The API and extractor binaries expose `/admin/metrics` (Prometheus text format). The endpoint is reachable only over Tailscale (`example-api-host.example-tailnet.ts.net:8443`).

| Metric | Type | Labels | What it measures |
|---|---|---|---|
| `patched_http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests handled by the API, counted by method/path/status code |
| `patched_http_request_duration_seconds` | Histogram | `method`, `path` | Latency per request (buckets at 5ms, 25ms, 100ms, 500ms, 2s, 10s) |
| `patched_extractor_rows_processed_total` | Counter | `result` (success/error/dead_letter) | Rows processed by the extractor worker |
| `patched_extractor_batch_size` | Histogram | - | Rows claimed per extractor poll cycle (series: `_bucket`, `_count`, `_sum`) |
| `patched_cve_match_queue_depth` | Gauge | - | Rows in `cve_match_queue`, including stuck rows (PAT-2024; served by patched-extractor on `127.0.0.1:8083`) |
| `patched_cve_match_queue_oldest_age_seconds` | Gauge | - | Age of the oldest queued CVE match; `CVEMatchQueueBacklog` fires above 1800 |
| `patched_cve_match_queue_stuck` | Gauge | - | Queue rows whose retries are exhausted (still counted in depth and age) |
| `patched_cve_match_queue_refreshed_timestamp_seconds` | Gauge | - | Unix time the queue gauges were last read; `CVEMatchQueueMetricsStale` fires when older than 30 minutes |
| `patched_cve_match_queue_dropped_total` | Counter | - | Match requests refused at a queue cap: the global 50,000 rows, or since PAT-2030 the requesting tenant's own 10,000; those products read as pending until the nightly match |
| `patched_cve_match_queue_tenant_dropped_total` | Counter | `tenant_id` | PAT-2169. Every cap refusal increments the global `patched_cve_match_queue_dropped_total` aggregate and this counter for the affected tenant, whether the tenant's 10,000-row share or the global 50,000-row cap refused it. This has no device, product, error, or other unbounded label. |
| `patched_cve_match_queue_tenant_depth` | Gauge | `tenant_id` | PAT-2030. Observation rows queued for one tenant, including stuck rows. A tenant near 10,000 is at its fair-share cap and its further changes are being dropped to the nightly match. Mapping jobs have no tenant until expanded and are not counted here. A tenant's series is removed once its backlog is empty |
| `patched_cve_match_queue_tenant_oldest_age_seconds` | Gauge | `tenant_id` | PAT-2030. Age of one tenant's oldest queued observation. `CVEMatchQueueTenantBacklog` fires above 1800 seconds for 2 minutes, identifying the tenant behind a global backlog. |
| `patched_cve_match_observations_total` | Counter | `result` (matched/error) | Observations re-matched from the queue |
| `patched_mcp_privacy_guard_rejections_total` | Counter | - | Inventory payloads refused by the PAT-2021 `mcp_servers` privacy guard (an MCP server entry with a field outside the PAT-2020 allowlist, or an unreduced value). Served by patched-api. Any increase fires `McpPrivacyGuardRejected`; the matching log line is `event=mcp_privacy_guard_rejected` (tenant and fixed classes, never a value). |

**Scrape config (if Prometheus is running locally or at a remote endpoint):**

```yaml
scrape_configs:
  - job_name: patched-api
    scheme: https
    tls_config:
      insecure_skip_verify: true  # CF Origin Cert — not CA-signed for *.ts.net
    static_configs:
      - targets: ['example-api-host.example-tailnet.ts.net:8443']
    metrics_path: /admin/metrics
```

### Health endpoint

```
GET /admin/health  (Tailscale-only)
→ {"status": "ok", "db": "ok", "version": "<git-sha>"}
```

Returns 200 on all components healthy; 503 if DB ping fails. Used by the monitoring heartbeat and ops scripts.

### Logging (journald)

All log output goes to `journald` via `systemd`. Neither binary uses a log library that writes structured JSON to a file; all output is plain text to stderr.

| Service | journald unit | Log level env var |
|---|---|---|
| patched-api | `patched-api.service` | `LOG_LEVEL` (`info` default) |
| patched-extractor | `patched-extractor.service` | `LOG_LEVEL` (`info` default) |
| patched-dashboard | `patched-dashboard.service` | n/a (dashboard.env) |

**Read logs:**

```bash
journalctl -u patched-api -n 100 --no-pager
journalctl -u patched-api -f                   # follow
journalctl -u patched-extractor --since "1h ago"
```

Journald retention is controlled by `/etc/systemd/journald.conf`:
- `SystemMaxUse=500M` — max disk space for logs
- `MaxRetentionSec=7776000` — 90 days

### What's logged today (per journald)

| Component | What's logged | What's NOT logged |
|---|---|---|
| API | Request start (method, path, tenant_id), auth failure reason, response status, panic recovery | Request body (PII), response body, per-field validation errors |
| Extractor | Batch start/end with count, individual row success/error, dead-letter promotion | Field-level extraction debug, per-rule evaluation detail |
| Dashboard | Startup, heartbeat write, uncaught errors | Request log |

---

## Named gaps

| Gap | Impact | Planned fix |
|---|---|---|
| No Grafana dashboard | No visual view of request rates, latency percentiles, or extractor throughput. Querying Prometheus requires CLI or ad-hoc `curl` | Add Grafana on `example-api-host` (Docker, Tailscale-only port) |
| ~~No Alertmanager~~ | **Stale: Alertmanager is live** (PAT-149/PAT-20,) and routes to Slack `#alerts`, not a Teams webhook. See `api-vps-artefacts/alerting/prometheus-rules-patched.yml` for the live rules and `api-vps-artefacts/alerting/MESSAGE-GRAMMAR.md` for the message contract. | Done |
| No extractor lag alert | Dead-lettered or stalling rows can accumulate for hours unnoticed | Alert: `patched_extractor_rows_processed_total{status="dead_letter"} > 0` |
| No structured log aggregation | Auth failures, nonce replays, and error events can't be queried across time without SSH + grep | Phase 2: JSON log output → Loki (push) or Cloudflare Logpush |
| No admin API audit log | Admin endpoint calls (tenant create, credential rotate, etc.) leave no queryable record | See `go-service/docs/AUDIT_STORE.md` — separate build item |
| No distributed tracing | Can't trace a single inventory POST from receipt → extraction → evaluation | Out of scope at current scale |
| Dashboard heartbeat not self-healing | `patched-dashboard` writes a heartbeat every 60s; if it falls behind, there's no alert | Add a heartbeat lag monitor (simple: check `updated_at < now() - interval '5 minutes'` in a cron on prod-01) |

---

## Alerting rules (live)

**Correction (PAT-1632):** this section previously described a planned "Tier 1 /
Tier 2" severity taxonomy notified over a Teams webhook. That was never built.
What actually shipped (PAT-149/PAT-20, live) is Alertmanager
routing to Slack `#alerts`, with a two-level `critical`/`warning` severity carried
directly on each Prometheus rule, not a page-worthy/investigate-later tier split
notified to different channels. The rule definitions live in
`api-vps-artefacts/alerting/prometheus-rules-patched.yml`; the message contract
(required fields, severity mapping, timestamp/truncation rules, firing vs resolved
shape) is `api-vps-artefacts/alerting/MESSAGE-GRAMMAR.md`. See that file rather than
this one for anything about how an alert message should read; this doc stays a
pointer, not a second copy of the rule list.

---

## Planned Grafana dashboards

| Dashboard | Panels |
|---|---|
| **API overview** | Request rate (rpm), p50/p95/p99 latency, error rate, status code breakdown, top paths by volume |
| **Extractor health** | Rows processed/min by status, batch size over time, dead-letter count, lag indicator |
| **System health** | CPU + memory (if node_exporter added), Go GC pause time, open file descriptors |

Grafana access: Tailscale-only, port 3000 on `example-api-host`.

---

## Planned structured logging

Phase 2 target: replace plain stderr output with structured JSON logs.

**Library:** `log/slog` (Go stdlib ≥ 1.21) — no new dependency.

**Per-request fields:**
```json
{
  "time": "2026-12-21T10:00:00Z",
  "level": "INFO",
  "msg": "request",
  "method": "POST",
  "path": "/v1/inventory",
  "tenant_id": "abc123",
  "status": 202,
  "duration_ms": 12,
  "trace_id": "..."
}
```

**Shipping options:**
1. Loki push (api-01 → Loki instance, Tailscale-only): low-cost; adds a service dependency.
2. Cloudflare Logpush (if using CF Workers at the edge): no VPS change needed; only covers requests that pass through CF.
3. Papertrail / Logtail SaaS: simplest ops; small monthly cost; appropriate at pre-revenue scale.

Decision deferred until Grafana/Alertmanager is operational.

---

## Operational queries

Useful one-liners for manual observability until dashboards exist:

```bash
# Auth failure rate in last 1h
journalctl -u patched-api --since "1h ago" | grep -c "auth failure"

# Dead-letter count (extractor)
journalctl -u patched-extractor --since "24h ago" | grep -c "dead.letter"

# Check Prometheus metrics directly
curl -s --insecure https://example-api-host.example-tailnet.ts.net:8443/admin/metrics | grep patched_

# Health check
curl -s --insecure https://example-api-host.example-tailnet.ts.net:8443/admin/health | jq .

# Extractor lag: rows pending extraction
psql "$DATABASE_URL" -c "SELECT count(*) FROM raw_payloads WHERE extracted_at IS NULL AND attempts < 10;"
```

---

## Build order

When investing in observability:

1. **Alertmanager + alert rules** — highest leverage; catches incidents automatically. Low build cost (config only).
2. **Grafana dashboards** — visual layer over existing Prometheus; day-to-day ops speedup.
3. **Extractor lag query → cron alert** — simple SQL + curl check on a cron, not a full Prometheus rule.
4. **Structured JSON logging (slog)** — enables log shipping; requires a pass over all log callsites.
5. **Log shipping** — Loki or SaaS; adds a new dependency; defer until structured logging is done.

---

## `notify.go`: customer-facing events (not ops alerting)

`NOTIFY_SLACK_WEBHOOK_URL` (`go-service/internal/notify/notify.go`) is a separate
notification path from everything above in this document. It dispatches
customer-facing platform events (rollout auto-paused, app-launch restricted, new-app
detected) to a tenant-facing channel, and its audience is a customer's own operator,
not Patched staff monitoring `#alerts`. It is deliberately **not** built to the
ops-alerting message grammar in `api-vps-artefacts/alerting/MESSAGE-GRAMMAR.md`
(§8 there explains why). Because its Slack and email channels silently no-op when
their env vars are unset (by design, see the package doc comment), a fully
unconfigured `Notifier` looks identical to a healthy one from the outside.
`Notifier.ConfiguredChannelCount()` is how to detect that, and `/admin/health`
exposes it as `ServiceHealth.NotifyChannelsConfigured`.

---

## Related docs

- `go-service/docs/AUDIT_STORE.md` — admin action and auth event audit log (separate from observability metrics)
- `api-vps-artefacts/OPERATIONS.md §Extractor lag` — runbook for investigating a stalled extractor
- `api-vps-artefacts/BACKUP_DR.md` — backup health check procedure (dashboard heartbeat monitor)
- `api-vps-artefacts/alerting/MESSAGE-GRAMMAR.md`: live ops-alerting message contract (severity vocabulary, required fields, firing/resolved shape)
