# Ingestion path — POST /v1/inventory

**Subsystem:** public ingestion endpoint
**Code:** `cmd/patched-api/`, `internal/handlers/`, `internal/auth/`, `internal/extractor/`

---

## What it does

Every managed endpoint (macOS or Windows) posts a JSON inventory payload to `POST /v1/inventory`. This is the only write path for endpoint data. The flow goes:

```
Endpoint → Cloudflare edge → Caddy :443 → Go :8080
  → auth verify (bearer + HMAC + timestamp + nonce)
  → body size check (5 MB cap in Caddyfile)
  → JSON decode into typed struct
  → raw_payloads INSERT (JSONB, immutable)
  → 200 OK

patched-extractor (async, separate process):
  → polls raw_payloads WHERE extracted_at IS NULL
  → buildSignalsMap()
  → devices/device_apps/compliance_signals upsert
  → Evaluate() → compliance_evaluations INSERT
  → marks extracted_at = now()
```

The two stages (ingest → extract) are decoupled deliberately. The ingestion handler is minimal and fast (auth + raw write); extraction is where the expensive work happens.

---

## Auth hot path

Auth runs before any JSON parse or DB write. A request without valid auth fails at ~100 µs.

1. **Bearer token**: `Authorization: Bearer <token>`. The service looks up the SHA-256 hash of the token in `tenant_credentials` joined to `tenants`. Unknown or revoked tenant → 401.
2. **HMAC-SHA256**: `X-Patched-Signature` header must equal `HMAC-SHA256(per-tenant-key, request-body)`. Computed over the raw body bytes before JSON decode. Mismatch → 401.
3. **Timestamp freshness**: `X-Patched-Timestamp` must be within ±300 seconds of server time. Stale → 401.
4. **Nonce replay**: `X-Patched-Nonce` is checked against `seen_nonces` table. Duplicate within the skew window → 401.

All four checks must pass. The order matters: bearer lookup first (cheapest), nonce check last (DB write on success).

---

## Payload schema

The payload schema is versioned (`schema_version` field). The extractor supports v2 and v3. v3 added the `compliance` object for the full CIS L1 signal surface. Canonical schema in `go-service/docs/PAYLOAD_SCHEMA.md`; JSON Schema at `go-service/docs/payload.schema.json`.

---

## raw_payloads table

```sql
raw_payloads(
  id            bigserial,
  device_id     uuid REFERENCES devices(id),
  tenant_id     uuid REFERENCES tenants(id),
  body          jsonb,           -- immutable raw payload
  received_at   timestamptz,
  extracted_at  timestamptz,     -- NULL until extractor processes this row
  extraction_attempts integer,
  extraction_error    text
)
```

The table is **partitioned monthly** (`PARTITION BY RANGE (received_at)`). Partitions must be created manually each month — there is no `pg_partman` automation at MVP. See `OPERATIONS.md §Monthly partition missing` for the add-partition command.

`raw_payloads` rows are never updated after extraction (only `extracted_at`, `extraction_attempts`, and `extraction_error` change). The JSONB body is the audit-grade immutable record.

---

## Extractor (async)

`patched-extractor` is a separate systemd binary that polls for unextracted rows in a tight loop (configurable `EXTRACTOR_POLL_EVERY`). For each row:

1. Decode the JSONB into a typed Go struct (same schema as the ingestion handler).
2. Upsert `devices` (on `hw_uuid` for macOS, `machine_id` for Windows).
3. Upsert `device_apps` (full app list replace; stale entries get `last_seen` bumped, new entries inserted).
4. Upsert `compliance_signals` (flat key/value from the `compliance` object).
5. Call `Evaluate()` with the full T1 + per-tenant T2 rule set.
6. INSERT into `compliance_evaluations` (append-only; one row per device × rule × run).
7. Commit; set `extracted_at = now()`.

If any step fails, `extraction_attempts` is incremented. At `extraction_attempts = 10` the row is dead-lettered — it stays in `raw_payloads` with `extraction_error` set but is never retried automatically. Clear the error manually to allow another attempt (see `OPERATIONS.md §Extractor lag`).

---

## Key files

| File | Role |
|---|---|
| `internal/handlers/inventory.go` | HTTP handler — auth, decode, raw_payloads insert |
| `internal/auth/auth.go` | Bearer lookup, HMAC verify, timestamp/nonce checks |
| `internal/extractor/upsert.go` | Main extraction: devices/apps/signals/evaluations |
| `internal/extractor/upsert.go:263` | `buildSignalsMap()` — flat map[string]string for Evaluate() |
| `internal/evaluator/evaluator.go` | `Evaluate()` — rules-as-data CIS engine |
| `go-service/docs/PAYLOAD_SCHEMA.md` | Canonical payload field reference |
