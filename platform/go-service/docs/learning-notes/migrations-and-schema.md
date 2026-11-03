# Migrations and schema

**Subsystem:** database schema management
**Code:** `migrations/`, `go-service/docs/SCHEMA.md`

---

## Migration pattern

Migrations are plain `.sql` files, applied manually with `psql`. There is no ORM migration framework — the apply step is:

```bash
psql -h 127.0.0.1 -U patched -d patched -f migrations/00NN_description.sql
```

A `schema_migrations` table tracks what's been applied:

```sql
CREATE TABLE schema_migrations (
  version     text PRIMARY KEY,
  applied_at  timestamptz DEFAULT now(),
  description text           -- nullable; added manually before 0030+
);
```

After applying a migration, insert a row:

```sql
INSERT INTO schema_migrations (version, description)
VALUES ('0035', 'drop dashboard tables');
```

**Convention:** migrations are numbered `0001`, `0002`, … and are strictly sequential. They are never edited after being applied to production. If a migration was wrong, add a corrective migration — never modify the original.

---

## Current migration state

: migrations `0001`–`0035` applied. Key milestones:

| Range | What landed |
|---|---|
| `0001`–`0005` | Core tables: tenants, devices, device_apps, raw_payloads, patches |
| `0006`–`0008` | macOS T2 compliance rules (batches 1–3) |
| `0009`–`0011` | Schema refinements, compliance signals |
| `0015` | `agent_config` table (Ed25519 signed config) |
| `0017` | Multi-credential `tenant_credentials` with `expires_at` |
| `0019` | Windows T1 CIS rules (13 controls) |
| `0020` | `device_apps.last_used_at` / `launch_count` (software metering) |
| `0023` | Software allowlist (`allowlist_baseline_apps`, `tenant_allowlists`) |
| `0024`–`0028` | Windows T2 CIS rules (batches 1–5) |
| `0029` | `device_credentials` (per-device auth for /v1/posture) |
| `0032` | `tenant_app_policies` |
| `0033` + `0035` | Dashboard tables created then dropped (PAT-489 — dashboard reverted to SQLite) |

---

## Key tables

| Table | Role | Notes |
|---|---|---|
| `tenants` | Tenant registry | FK anchor for all tenant data |
| `tenant_credentials` | Bearer tokens + HMAC keys | Hashed; multiple per tenant for rotation |
| `device_credentials` | Per-device auth tokens | For /v1/posture |
| `devices` | One row per managed endpoint | Keyed on `(tenant_id, hw_uuid/machine_id)` |
| `device_apps` | Installed software per device | Full-replace on each extraction |
| `compliance_signals` | Flat key/value from payload | Last-write-wins per `(device_id, key)` |
| `compliance_evaluations` | Rule engine output | Append-only; historical |
| `compliance_rules` | The CIS L1 rule set | 104 rows; SQL-only changes |
| `tenant_rules` | Per-tenant T2 activation + overrides | FK to both tenants + compliance_rules |
| `tenant_rule_changes` | Audit log for tenant_rules mutations | Append-only |
| `tenant_platform_changes` | Audit log for platform switch flips | Append-only |
| `raw_payloads` | Immutable raw JSON payloads | Partitioned monthly |
| `seen_nonces` | Replay-attack prevention | Pruned at > 10 min old |
| `agent_config` | Per-tenant config served by /v1/agent-config | Ed25519 signed at response time |
| `tenant_app_policies` | Per-app classification (mandatory/approved/etc.) | App policy model |
| `tenant_allowlists` | Custom software allow-list per tenant | Supplement to baseline |
| `allowlist_baseline_apps` | Seeded OS baseline (69 macOS + Windows entries) | Never tenant-specific |

---

## raw_payloads partitioning

`raw_payloads` is partitioned by `received_at` (range, monthly). Partitions must be created manually before the first POST of each month:

```sql
CREATE TABLE raw_payloads_2026_09 PARTITION OF raw_payloads
FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
```

See `OPERATIONS.md §Monthly partition missing` for the emergency fix if a partition is missing. There is no `pg_partman` automation at MVP — this is a backlog item.

Dropping a partition deletes the raw archive for that month. It does NOT affect `devices`, `compliance_signals`, `compliance_evaluations`, or `device_apps` — extraction is complete and the data is already in the structured tables.

---

## Adding a migration

1. Create `migrations/00NN_description.sql` (next sequential number).
2. Test against a local Postgres instance.
3. Apply on `example-api-host`: `psql -h 127.0.0.1 -U patched -d patched -f migrations/00NN_description.sql`.
4. Insert the tracking row: `INSERT INTO schema_migrations (version, description) VALUES ('00NN', 'what it does');`.
5. Update `go-service/docs/architecture.md §Current state` — the "Migrations applied" line.
6. Commit the `.sql` file to the repo.

**Never** edit a migration that's been applied to production. Always correct forward.

---

## Postgres tuning (api-01 sizing)

Box is CPX22 (4 GB RAM). Tuning from `postgresql.conf`:

| Setting | Value | Why |
|---|---|---|
| `shared_buffers` | 768 MB | ~19% of RAM (Postgres guidance for dedicated server) |
| `effective_cache_size` | 2 GB | Tells the planner how much memory is available for caching |
| `work_mem` | 8 MB | Per-sort/hash operation; multiple can run in parallel |

---

## Key files

| File | Role |
|---|---|
| `migrations/` | All SQL migrations, numbered sequentially |
| `go-service/docs/SCHEMA.md` | Full schema reference — all tables, columns, indexes |
| `api-vps-artefacts/pg_hba.conf` | Postgres client auth config |
| `go-service/docs/architecture.md §Current state` | Live migration count on production |
