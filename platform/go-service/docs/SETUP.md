# Local development setup

Clone-to-running-locally for the Go ingestion service. Tested on macOS (Andy's Mac), should work the same on Linux.

## Prerequisites

- **Go 1.22+** — `go version` should show 1.22 or later. Install: `brew install go`.
- **Postgres 16** — local Docker one-liner (recommended) or native install.
- **`psql`** client — `brew install libpq && brew link --force libpq`.
- **`gitleaks`** — pre-commit hook requires it. `brew install gitleaks`.

## 1. Clone + go mod

```bash
git clone git@github.com:Patched-LTD/patched.im.git
cd patched.im/go-service
go mod download
go build ./...  # confirm everything compiles
```

## 2. Postgres setup

**Option A — Docker (recommended for local dev):**
```bash
docker run -d \
  --name patched-pg \
  -e POSTGRES_USER=patched \
  -e POSTGRES_PASSWORD=localdev \
  -e POSTGRES_DB=patched \
  -p 5432:5432 \
  postgres:16
```

**Option B — Native (Homebrew):**
```bash
brew install postgresql@16
brew services start postgresql@16
createuser -s patched
createdb -O patched patched
psql -U patched -d patched -c "ALTER USER patched WITH PASSWORD 'localdev';"
```

## 3. Run migrations

Apply in order:

```bash
DB="psql -h 127.0.0.1 -U patched -d patched"
$DB -f migrations/0001_initial.sql
$DB -f migrations/0002_extraction.sql
$DB -f migrations/0003_compliance_rules.sql
$DB -f migrations/0004_patching_data.sql
```

Verify:
```bash
psql -h 127.0.0.1 -U patched -d patched -c "\dt"
```
Should list: `compliance_evaluations`, `compliance_rules`, `compliance_signals`, `device_apps`, `devices`, `patches`, `raw_payloads*`, `schema_migrations`, `tenants`.

## 4. Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | **yes** | — | pgx connection string |
| `FEEDBACK_ENABLED` | no | `false` | Enables authenticated `/v1/portal/feedback` and the stale-state reconciler; false returns 404 for intake and stops reconciliation. |
| `SELF_SERVICE_SIGNUP_ENABLED` | no | `false` | PAT-1883. Enables self-service organisation sign-up (`/v1/portal/signup/*`) and access management (`/v1/portal/access*`). While false every one of those routes answers 404 to a verified caller using the route's method (a wrong method is still 405, and the authentication answers still come first; the contract has the detail). Setting it back to false is the rollback: existing tenants, memberships, invitations and audit rows are kept. Booleans accept `true/false/1/0/yes/no/on/off`; anything else is false. Needs migrations 0229 and 0230. **Do not enable it until the customer portal recognises the `owner` role.** Today the portal treats an owner as a viewer, so an owner would lose every write screen. For the same reason `POST /admin/portal-users` refuses `"role": "owner"` with `400` while this is false; an owner row that already exists keeps working either way. |
| `PORTAL_INVITATION_TTL_HOURS` | no | `168` | PAT-1883. Hours an invitation can be accepted for. Read when the invitation is created; changing it does not move existing invitations. |
| `PORTAL_INVITATIONS_PER_HOUR` | no | `20` | PAT-1883. Invitations one tenant may create per hour. `429` with `Retry-After` beyond it. |
| `SIGNUP_ORG_CREATIONS_PER_HOUR` | no | `20` | PAT-1883. Organisations created in any hour across every caller. It counts organisations that were created: a request takes a slot only when it is about to create a tenant and gives it back unless one is committed, so requests that create nothing cannot hold sign-up shut. `429` with `Retry-After` beyond it. There is no per-client-address limit beside it: the portal calls the platform from its own server, so every sign-up arrives from one address and a per-address limit would be a second, lower global cap. This limit and `PORTAL_INVITATIONS_PER_HOUR` are in memory and per process: they reset on restart. A zero, negative or unparsable value means the default, never "no limit". |
| `LINEAR_API_KEY` | no | — | Enables asynchronous feedback issue creation and daily state reconciliation. Unset leaves accepted feedback pending and reconciliation logs degraded. |
| `LINEAR_WEBHOOK_SECRET` | **yes when subscribed** | — | Linear Issue webhook signing secret for `POST /public/linear-webhook`. Unset fails closed with 503 before parsing or database work. Do not reuse `LINEAR_API_KEY`. |
| `LISTEN_PUBLIC` | no | `127.0.0.1:8080` | Public ingestion listener |
| `LISTEN_INTERNAL` | no | `127.0.0.1:8081` | Internal admin listener |
| `ADMIN_API_TOKEN` | **yes (prod)** | — | Shared secret required on internal `/admin/*` routes. Send as `Authorization: Bearer <token>`. If unset, the admin surface fails **closed** (503); `/health` and `/metrics` stay open. Any caller (the dashboard, ops scripts) must present it. |
| `HMAC_COMPATIBILITY_TELEMETRY_ENABLED` | no | `true` | PAT-1872 inventory-signing compatibility aggregate. Set to `false` (also `0`, `off`, or `no`) and restart to stop telemetry writes independently; this never changes the v3, targetless-v2, or body-only authentication acceptance flags. |
| `BACKUP_HEARTBEAT_TOKEN` | **yes (prod)** | — | Dedicated shared secret for `POST /v1/backup-health` (public listener; PAT-954) — **not** `ADMIN_API_TOKEN`, **not** a tenant bearer token. Send as `Authorization: Bearer <token>`. If unset, the endpoint fails **closed** (503). |
| `BACKUP_HEARTBEAT_RATE_LIMIT_RPM` | no | `6` | Requests/minute for `POST /v1/backup-health`'s single shared rate-limit bucket |
| `BACKUP_HEARTBEAT_RATE_LIMIT_BURST` | no | `3` | Burst size for the same bucket |
| `BACKUP_HEARTBEAT_ALLOWED_JOBS` | no | `portal-r2` | Comma-separated allowlist of `job` ids `POST /v1/backup-health` may write. `PATCHED_BACKUP_HEALTH_DIR` is shared with other hosts' heartbeat files (e.g. prod-01's `prod-r2.json`); anything outside this list gets `403`, so the portal-01 credential can never overwrite another host's row. |
| `JAMF_WEBHOOK_PUBLIC_BASE_URL` | no | `https://api.patched.im` | PAT-2145. Public origin the portal's Jamf setup page builds the webhook URL from (`<base>/v1/webhooks/jamf/<id>`). Set it on staging so the URL a customer pastes into Jamf Pro points at the right host. |
| `JAMF_WEBHOOK_RATE_LIMIT_RPM` | no | `300` | PAT-2145. Authenticated Jamf events per minute per tenant, charged only after authentication. Sized for check-ins from a few thousand Macs; inventory and enrolment events are far rarer. |
| `JAMF_WEBHOOK_RATE_LIMIT_BURST` | no | `100` | PAT-2145. Burst for the same bucket. |
| `JAMF_WEBHOOK_FAILED_AUTH_GLOBAL_RPM` / `_BURST` | no | `600` / `200` | PAT-2145. Failed Jamf webhook authentications per minute, all callers. While exhausted, webhook IDs that have not authenticated in 48 hours are refused 429 before any database read. |
| `JAMF_WEBHOOK_FAILED_AUTH_RPM` / `_BURST` | no | `30` / `20` | PAT-2145. The same, per `CF-Connecting-IP`, per real webhook ID, and for unknown IDs as one shared bucket. Never charged to a tenant's own bucket. |
| `TRIAL_PROVISION_PER_IP_PER_HOUR` | no | `5` | PAT-2529. Requests per hour one client address (`CF-Connecting-IP`, IPv6 keyed on its /64) may send to `POST /v1/trial/provision`, counted before the body is read, valid or not. A token bucket: the full count is available at once and one token returns every hour/count. A value that is not a positive integer falls back to the default. |
| `TRIAL_PROVISION_GLOBAL_PER_HOUR` | no | `30` | PAT-2529. The same limit for the whole route, all callers together. A request refused by its own client bucket does not spend it. Over either limit the route answers `429` with `Retry-After`. Both limits are in memory and reset on restart. |
| `PATCHED_BACKUP_HEALTH_DIR` | no | `/srv/backup/health` | Directory of per-job backup-heartbeat JSON files. `GET /admin/health` reads every `*.json` file here (`readBackupJobs`); `POST /v1/backup-health` writes into it. |

Sample `.env` (not auto-loaded — set in shell or use `direnv`):
```bash
export DATABASE_URL="postgres://patched:localdev@127.0.0.1:5432/patched?sslmode=disable"
export LISTEN_PUBLIC="127.0.0.1:8080"
export LISTEN_INTERNAL="127.0.0.1:8081"
export ADMIN_API_TOKEN="$(openssl rand -base64 32)"   # prod: keep in /etc/patched-api/env
```

## 5. Run the service

```bash
source .env   # or export vars manually
go run ./cmd/patched-api
```

Confirm it's alive:
```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","version":"0.1.0"}
```

## 6. Bootstrap a test tenant

With the service running, create a local-test tenant via the internal admin endpoint:

```bash
curl -X POST http://127.0.0.1:8081/admin/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"local-test"}'
```

Response (one-time — **save these**):
```json
{
  "tenant_id": "aaaaaaaa-...",
  "bearer_token": "base64url-token",
  "hmac_secret_b64": "base64-secret",
  "warning": "store bearer_token and hmac_secret_b64 immediately — neither is recoverable; ..."
}
```

Write the credentials to the macOS agent config directory (if testing the full pipeline):
```bash
sudo mkdir -p /etc/patched
sudo bash -c 'echo "YOUR-TENANT-UUID" > /etc/patched/tenant-id'
sudo bash -c 'echo "YOUR-BEARER-TOKEN" > /etc/patched/bearer-token'
sudo bash -c 'echo "YOUR-HMAC-SECRET-B64" > /etc/patched/hmac-secret'
sudo chmod 600 /etc/patched/*
```

## 7. Run tests

```bash
cd go-service
go test ./...
go vet ./...
```

The evaluator and extractor tests run without a database. Integration and other
DB-gated tests require the `TEST_DATABASE_URL` env var; `DATABASE_URL` remains
the application runtime configuration variable.

## 8. Test a fake payload

Generate and submit a minimal valid payload to verify the full ingestion path:

```bash
# Use the tenant credentials from step 6
BEARER="YOUR-BEARER-TOKEN"
HMAC_B64="YOUR-HMAC-SECRET-B64"

# Minimal payload (schema_version 2)
BODY='{"schema_version":2,"agent":"test","agent_version":"0.0.1","tenant_id":"YOUR-TENANT-UUID","collected_at":"2026-11-15T12:00:00Z","device":{"serial":"TEST001","hw_uuid":"01234567-89AB-CDEF-0123-456789ABCDEF","hostname":"test-mac","computer_name":"Test Mac","hw_model":"Mac14,2","arch":"arm64","last_boot":"2026-11-15T08:00:00Z"},"hardware":{"cpu_model":"Apple M2","cpu_cores":8,"ram_gb":16,"disk_total_gb":500.0,"disk_free_gb":300.0},"os":{"name":"macOS","version":"15.4.1","build":"24E263"},"compliance":{"filevault":"On","sip":"enabled","pending_updates_count":0},"security_tools":[],"system_extensions":[],"background_items":[],"icloud":{"signed_in":"No"},"apps":[]}'

# Compute HMAC-SHA256 of the body
SIG=$(python3 -c "
import hmac, hashlib, base64, sys
secret = base64.b64decode('$HMAC_B64')
body = sys.stdin.buffer.read()
print(hmac.new(secret, body, hashlib.sha256).hexdigest(), end='')
" <<< "$BODY")

# POST to the public ingestion endpoint
curl -v -X POST http://127.0.0.1:8080/v1/inventory \
  -H "Authorization: Bearer $BEARER" \
  -H "X-Patched-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d "$BODY"
```

Verify the row landed:
```bash
psql -h 127.0.0.1 -U patched -d patched -c \
  "SELECT id, received_at, length(body::text) AS bytes FROM raw_payloads ORDER BY received_at DESC LIMIT 3;"
```

## 9. Run the extractor

The extractor is a separate binary that drains `raw_payloads`:

```bash
go run ./cmd/patched-extractor
```

It polls every 5 seconds. It also runs the automatic CPE mapping proposer
(PAT-2138) in its own goroutine, never inside an ingest transaction. Its
environment, read from `/etc/patched-extractor/env` in production:

| Variable | Default | Notes |
|---|---|---|
| `CPE_PROPOSER_ENABLED` | `true` | `false` stops proposing: no NVD search, no model call (logged at startup; proposer status `disabled`). Unmapped products are still recorded at ingest, and the maintenance sweeps (automatic-mapping re-check, deleted-mapping reconciliation, expiry) keep running. |
| `CPE_AUTO_PUBLISH_ENABLED` | `true` | `false` sends every proposal to staff review, whatever the evidence. The kill switch for automatic mappings. |
| `CPE_PROPOSER_INTERVAL` | `2m` | Go duration between runs (minimum 10s). |
| `CPE_PROPOSER_BATCH` | `10` | Proposals per run (1-100). |
| `CPE_PROPOSER_MODEL` | `claude-haiku-4-5-20251001` | Anthropic model id. |
| `ANTHROPIC_API_KEY` | unset | Unset: proposals get NVD candidates only, go to staff review as `model_unavailable`, and the proposer reports `degraded` (log line, `patched_cpe_proposer_degraded{reason="model_unavailable"}`, admin API status). |
| `CPE_MODEL_ZDR_CONFIRMED` | `false` | Set to `true` only once zero data retention is confirmed on the Anthropic organisation that owns `ANTHROPIC_API_KEY`. Until then the model is never called, even with a key: proposals take the no-model path above and the proposer reports `degraded` / `model_zdr_unconfirmed`. |
| `NVD_API_KEY` | unset | The same NVD key `patched-cve-sync` uses. The proposer takes a tenth of NVD's limit, shared by every proposer process through the `cpe_nvd_budget` row: one request per 6s with a key, one per 60s without, retries included. |

Booleans accept `true/false/1/0/yes/no/on/off`; anything else keeps the
default and logs a warning. `patched-cve-sync` reads the same variables for
`--mode=cpe-propose`, plus `LINEAR_API_TOKEN` and `LINEAR_TEAM_KEY` (default
`PAT`) for the review digest (`--mode=cpe-review-digest`, and nightly in
`--mode=scheduled`).

After one cycle, verify the device row appeared:
```bash
psql -h 127.0.0.1 -U patched -d patched -c \
  "SELECT id, hostname, os_version, last_seen FROM devices;"
```

## What works locally vs what needs the tailnet

| Surface | Works locally? | Notes |
|---|---|---|
| `GET /health` | ✅ | Both listeners |
| `POST /v1/inventory` | ✅ | Full pipeline including extractor |
| `POST /admin/tenants` | ✅ | Hit `127.0.0.1:8081` directly |
| `GET /admin/reports/*.pdf` | ✅ | Requires a device with extracted compliance data |
| Caddy TLS termination | ✗ | Caddy runs on the VPS only |
| Tailscale-bound internal endpoints | ✗ | `api-internal.patched.im:8443` needs Tailscale; locally just use `127.0.0.1:8081` directly |
| Real macOS agent → local service | ✅ | Set `PATCHED_API_URL=http://127.0.0.1:8080` in the uploader |

## Common issues

- **`pq: relation "raw_payloads_2026_07" does not exist`** — the partition for the current month doesn't exist. Check `0001_initial.sql` and add the current month's partition manually, or extend the migration.
- **`401 Unauthorized` from POST /v1/inventory`** — wrong bearer or HMAC. Recheck step 6; the HMAC secret must be base64-decoded before use.
- **Extractor loops but nothing extracts** — check `raw_payloads.extraction_error`. Likely `"unsupported schema_version"` if the payload was malformed, or a DB error.
- **`go: module not found`** — run `go mod download` in `go-service/`.
