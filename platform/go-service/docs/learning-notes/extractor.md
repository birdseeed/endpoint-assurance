# Extractor — raw_payloads → structured tables

**Subsystem:** async payload extraction worker
**Binary:** `patched-extractor` (separate systemd unit from `patched-api`)
**Code:** `cmd/patched-extractor/`, `internal/extractor/`

---

## Why a separate binary?

The ingestion handler (`patched-api`) is on the hot path — it must return 200 quickly to the endpoint. All the expensive work (JSON decode of potentially large app lists, app upserts, compliance signal evaluation) is deferred to a separate worker that polls `raw_payloads` asynchronously.

This also means ingestion never fails due to transient extractor errors. A batch of devices can POST successfully even if the extractor is briefly down; they'll be picked up when it recovers.

---

## The poll loop

```go
for {
    rows = SELECT * FROM raw_payloads WHERE extracted_at IS NULL
               AND extraction_attempts < 10
               ORDER BY received_at
               LIMIT batchSize
    FOR EACH row:
        extract(row)    // see below
    SLEEP(pollEvery)
}
```

Configurable via env: `EXTRACTOR_BATCH_SIZE` (default 10), `EXTRACTOR_POLL_EVERY` (default 5s).

---

## Per-row extraction

For each `raw_payloads` row:

1. **Increment `extraction_attempts`** — immediately, so a crash mid-extraction is counted.
2. **Decode JSONB** into the typed payload struct (same schema as the ingestion handler expects).
3. **Upsert `devices`** — keyed on `(tenant_id, hw_uuid)` for macOS or `(tenant_id, machine_id)` for Windows. Updates `os_version`, `hostname`, `last_seen`, etc.
4. **Upsert `device_apps`** — full replace strategy: delete apps not in the new payload, insert/update apps that are. Each app row carries `name`, `version`, `identifier`, `sha256`, `signer`, `team_id`, `first_seen`, `last_seen`.
5. **Upsert `compliance_signals`** — flat key/value from `payload.compliance` map. Each signal is `(device_id, key, value, observed_at)`.
6. **`buildSignalsMap()`** — reads all current signals for this device from `compliance_signals` and returns a `map[string]string` for the evaluator.
7. **`LoadRules(T1)` + `LoadRulesForTenant(T2, tenantID)`** — loads the applicable rule set for this device's tenant.
8. **`Evaluate(rules, signals)`** — runs the CIS L1 rule engine; returns `[]EvaluationResult`.
9. **INSERT `compliance_evaluations`** — one row per rule per device per run. Append-only; never updates existing rows.
10. **Set `extracted_at = now()`** — marks the row as complete. All of steps 2–10 run in a single DB transaction.

---

## Dead-lettering

If `extraction_attempts` reaches 10, the row is dead-lettered:
- `extraction_error` is set to a descriptive message.
- The poll loop skips it (`WHERE extraction_attempts < 10`).
- Data for that device is stale until the error is cleared manually.

**To re-queue a dead-lettered row:**

```sql
UPDATE raw_payloads
SET extraction_error = NULL, extraction_attempts = 0
WHERE extracted_at IS NULL AND extraction_attempts >= 10;
```

The most common causes:
- `"unsupported schema_version"` — collector version mismatch.
- Parse error — malformed JSON (shouldn't happen post-auth, but possible on corrupt payloads).
- Constraint violation — usually a device row conflict on a race condition.

---

## buildSignalsMap

```go
func buildSignalsMap(ctx, pool, deviceID) (map[string]string, error)
```

Located in `internal/extractor/upsert.go:263`. Reads all `compliance_signals` rows for the device and builds a flat `map[string]string`. The key is `compliance_signals.key`, the value is `compliance_signals.value`.

The evaluator operates on this map — it does not read compliance_signals directly. This is intentional: the same signals map can be used for multiple evaluation passes without re-reading the DB.

---

## Observability

The extractor exposes Prometheus metrics:

| Metric | Type | What it measures |
|---|---|---|
| `patched_extractor_rows_processed_total{result}` | Counter | Rows processed, labelled `success`, `error`, or `dead_letter` |
| `patched_extractor_batch_size` | Histogram | Rows claimed per poll cycle |

Scrape target: `localhost:8083/metrics`, patched-extractor's own loopback-only
listener (PAT-1377). Not shared with `patched-api`'s `:8081`: these metrics
are only ever observed inside this binary's `Worker.Run`, so registering them
in patched-api's process (the original wiring) produced a permanently-zero
series there and nothing anywhere else. See `docs/architecture.md`.

Lag detection: `SELECT COUNT(*) FROM raw_payloads WHERE extracted_at IS NULL` — anything > a few rows after the poll interval is worth investigating.

---

## Key files

| File | Role |
|---|---|
| `cmd/patched-extractor/main.go` | Entry point; poll loop |
| `internal/extractor/upsert.go` | Per-row extraction: devices, apps, signals, evaluations |
| `internal/extractor/upsert.go:263` | `buildSignalsMap()` |
| `internal/evaluator/evaluator.go` | `Evaluate()` — called from upsert.go |
| `internal/evaluator/rules.go` | `LoadRules()`, `LoadRulesForTenant()` |
| `api-vps-artefacts/patched-extractor.service` | systemd unit |
