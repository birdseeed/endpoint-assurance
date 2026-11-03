# Observability

**Subsystem:** metrics, logging, alerting
**Status:** Prometheus metrics live; Grafana + Alertmanager open.

---

## What's instrumented

### Prometheus metrics

`patched-api` exposes `GET /metrics` on the internal `:8081` listener (Tailscale-only), and `patched-extractor` exposes its own `GET /metrics` on a separate loopback-only `:8083` listener (PAT-1377, see below). Prometheus v2.45.3 runs on `example-api-host` itself, scraping both every 30s (`patched-api` and `patched-extractor` jobs).

| Metric | Type | Labels | What it measures |
|---|---|---|---|
| `patched_http_requests_total` | Counter | `route`, `status` | Request count by route and HTTP status |
| `patched_http_request_duration_seconds` | Histogram | `route`, `status` | Latency per route |
| `patched_extractor_rows_processed_total` | Counter | `result` (`success`/`error`/`dead_letter`) | Extraction outcomes, served on `:8083` |
| `patched_extractor_batch_size` | Histogram | - | Rows claimed per poll cycle, served on `:8083` |

PAT-1377: the two extractor metrics used to be registered on patched-api's
`:8081` (they're defined in the shared `internal/metrics` package) but only
ever incremented inside `patched-extractor`'s own `Worker.Run`, a different
OS process. That meant a permanently-zero series on `:8081` and no series at
all anywhere the extractor process itself was concerned, which is why
`ExtractorStalled` and `DeadLetterRows` never matched a live series. Fixed by
registering and serving them from `patched-extractor` itself.

`route` uses chi route patterns (e.g. `/v1/inventory`, not `/v1/inventory/abc123`), so per-tenant UUIDs never become a cardinality problem.

### Health endpoint

`GET /admin/health` (Tailscale-only `:8081`) returns:
- Go service version and uptime.
- Postgres connection pool stats.
- `service_health.backup_jobs` — one entry per backup leg, with `status` and `last_success_at`.

```bash
curl -s http://127.0.0.1:8081/admin/health | jq .
```

### Structured logging

`patched-api` and `patched-extractor` log to journald (`journalctl -u patched-api`). Logs are JSON-structured with fields: `level`, `msg`, `route`, `status`, `duration_ms`, `tenant_id` (redacted for auth failures).

---

## What's NOT yet instrumented (open gaps)

| Gap | Notes |
|---|---|
| **Grafana dashboards** | Prometheus is running and scraping; no dashboards created yet. Roadmap item; needed before first revenue customer. |
| **Alertmanager** | No alert rules defined. No Teams/PagerDuty webhook. An api-01 outage or backup failure is not currently paged. |
| **Admin API audit log** | Admin actions (tenant create, rule change, credential rotation) are recorded in DB tables but are not shipped to a SIEM or external log store. |
| **SIEM / log shipping** | Logs stay in journald on each box. No aggregation, no cross-host search. |
| **Extractor lag alert** | The `raw_payloads WHERE extracted_at IS NULL` count is not monitored with an alert. Manual query only. |

---

## How to scrape Prometheus manually

From a Mac on the Tailscale tailnet:

```bash
curl -s http://100.64.10.1:8081/metrics | grep patched_        # patched-api
curl -s http://example-api-host.example-tailnet.ts.net:8081/metrics | grep patched_  # patched-api
# Extractor metrics (patched_extractor_batch_size, patched_extractor_rows_processed_total)
# are only on example-api-host itself (this port is loopback-only, PAT-1377):
ssh root@example-api-host 'curl -s http://127.0.0.1:8083/metrics | grep patched_'
```

Check Prometheus targets:

```bash
ssh root@example-api-host
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
```

---

## Planned observability (roadmap)

- **Grafana** — live dashboard for `patched_http_requests_total`, `patched_extractor_rows_processed_total`, backup health. Run on `example-api-host` or `example-prod-host`; Tailscale-only access.
- **Alertmanager** — alert rules for: service down (5-minute window), extractor lag > 100 rows, backup job not seen in 26h. Webhook to Microsoft Teams.
- **Admin audit store** — append-only log table for all admin API mutations, with a retention policy and optional export.

---

## Key files

| File | Role |
|---|---|
| `internal/handlers/metrics.go` | Prometheus metric registration and middleware |
| `api-vps-artefacts/prometheus.yml` | Prometheus scrape config |
| `api-vps-artefacts/patched-api.service` | systemd unit (includes `--metrics-listen` if set) |
