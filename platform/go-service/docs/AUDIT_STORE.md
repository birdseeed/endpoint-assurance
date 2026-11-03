# Audit store — architecture

**Status:** Partial coverage exists (per-entity append-only tables). No cross-system audit log or SIEM shipping yet. Full audit store is a pre-customer deliverable.

---

## What audit coverage exists today

Several append-only tables already capture specific mutation events:

| Table | What it records | Created |
|---|---|---|
| `tenant_rule_changes` | Every `tenant_rules` mutation: who changed what rule, old/new values, timestamp | migration `0009` |
| `tenant_platform_changes` | Every `macos_enabled`/`windows_enabled` toggle: tenant, old/new state, timestamp | migration `0013` |
| `tenant_credentials` | Credential issuance (creation + rotation) is implicit in row history; `expires_at` marks rotation events | migration `0017` |
| `compliance_evaluations` | Every rule evaluation result, append-only — complete evaluation history per device | migration `0003` |
| `provenance_records` | Every `/v1/provenance` POST: source IP, user agent, raw body — immutable audit trail for agent provenance events | migration `0016` |
| `raw_payloads` | Every inventory POST body — immutable, partitioned monthly | migration `0001` |

These tables serve their immediate purpose but are not a unified audit store: they have different schemas, no common event model, no cross-table query surface, and are not shipped to any external log store.

---

## Actor attribution is not authenticated (PAT-1135)

All six admin-write audit tables (`tenant_decommission_audit`, `tenant_tier_changes`,
`tenant_platform_changes`, `tenant_rule_changes`, `tenant_app_policy_changes`,
`device_revocations`) carry an actor-type column (`actor`, `changed_by`, or
`admin_id`). Before PAT-1135 that column held whatever string the caller's JSON
body claimed — `"actor": "alice"` and the row said `alice`, unverified.

That is dishonest given the auth model above: `/admin/*` has no per-person
identity, only the one shared `ADMIN_API_TOKEN`. As of migration `0092`
(`0092_audit_attribution.sql`) every write to these six tables instead:

- Sets the existing actor column to the constant `"admin_shared_token"` — the
  only identity the server can actually vouch for.
- Sets the new `claimed_actor` column (nullable) to the caller-supplied string,
  unmodified and explicitly untrusted.
- Sets the new `source_addr` column (nullable) to the observed client IP,
  best-effort, same extraction as `provenance_records.source_ip`.

See `internal/handlers/audit_attribution.go` for the helper every affected
handler now calls. This does not add per-person identity to the admin
surface — it only stops the audit trail from *implying* it has that identity
when it does not. Real per-person attribution is expected to arrive with
PAT-700 (`DASHBOARD_OPERATORS`).

---

## What is NOT recorded today

| Event category | Current state | Gap |
|---|---|---|
| Admin API mutations | Not logged beyond the entity-specific tables above | No `admin_events` log; no who/when for tenant CRUD, device cert issuance, etc. |
| Auth failures | Logged to journald only; not in the DB; no retention after log rotation | |
| Auth successes | Not logged (implicit in raw_payloads.received_at) | |
| Nonce replay attempts | Logged to journald at WARN; no DB row | |
| Allowlist changes | Not logged (no `tenant_allowlist_changes` table) | |
| App policy changes | Not logged | |
| Credential access (reads of bearer-hashed tokens) | Not logged | |
| Service restart / deployment events | journald only | |
| Suppression actions (`suppressed_until`) | Written to `tenant_rules` but no separate `suppression_history` | |

---

## Event taxonomy for a full audit store

A complete audit store should cover four event categories:

### 1. Authentication events

| Event | Captured data |
|---|---|
| Auth success | `tenant_id`, `device_id` (if device-auth), `endpoint`, `timestamp`, `source_ip` |
| Auth failure (bearer) | `reason`, `endpoint`, `timestamp`, `source_ip` |
| Auth failure (HMAC) | `reason`, `endpoint`, `timestamp`, `source_ip` |
| Auth failure (timestamp) | `skew_seconds`, `endpoint`, `timestamp`, `source_ip` |
| Nonce replay | `nonce_hash`, `tenant_id`, `timestamp`, `source_ip` |

### 2. Admin actions

| Event | Captured data |
|---|---|
| Tenant created | `tenant_id`, `name`, `actor`, `timestamp` |
| Tenant revoked | `tenant_id`, `actor`, `timestamp`, `reason` |
| Credential issued | `tenant_id`, `credential_id`, `actor`, `timestamp` |
| Credential rotated | `tenant_id`, `old_credential_id`, `new_credential_id`, `actor`, `timestamp` |
| Platform toggle | `tenant_id`, `platform`, `old_state`, `new_state`, `actor`, `timestamp` |
| Rule toggle | `tenant_id`, `rule_id`, `enabled`, `actor`, `timestamp` |
| Rule suppression | `tenant_id`, `rule_id`, `suppressed_until`, `reason`, `actor`, `timestamp` |
| Allowlist change | `tenant_id`, `app_identifier`, `action` (add/remove), `actor`, `timestamp` |
| App policy change | `tenant_id`, `app_identifier`, `policy`, `actor`, `timestamp` |
| Device cert issued | `tenant_id`, `device_id`, `actor`, `timestamp` |

### 3. Compliance events

| Event | Captured data |
|---|---|
| Evaluation run | `device_id`, `tenant_id`, `rule_count`, `pass_count`, `fail_count`, `timestamp` (already in `compliance_evaluations`) |
| Rule status change | `device_id`, `rule_id`, `previous_status`, `new_status`, `timestamp` (derivable from `compliance_evaluations`) |

### 4. System events

| Event | Captured data |
|---|---|
| Service start/stop | `service`, `version`, `timestamp` |
| Migration applied | `migration_version`, `timestamp` |
| Binary deployed | `service`, `old_commit`, `new_commit`, `timestamp` |

---

## Proposed schema

A single `audit_events` table with a `data` JSONB column for event-specific fields:

```sql
CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  event_type  text NOT NULL,            -- e.g. 'auth.failure.hmac', 'admin.tenant.revoked'
  tenant_id   uuid REFERENCES tenants(id),  -- NULL for non-tenant events
  device_id   uuid REFERENCES devices(id),  -- NULL for non-device events
  actor       text,                     -- 'service', 'admin:<ip>', 'agent:<device_id>'
  source_ip   inet,                     -- NULL for internal events
  data        jsonb NOT NULL DEFAULT '{}',   -- event-specific fields (schema per event_type)
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_created_at ON audit_events (created_at DESC);
CREATE INDEX audit_events_tenant_id ON audit_events (tenant_id, created_at DESC);
CREATE INDEX audit_events_event_type ON audit_events (event_type, created_at DESC);
```

**Design decisions:**

- `bigserial` not UUID primary key — append-only table benefits from sequential access; no distributed uniqueness need.
- JSONB `data` for event-specific fields — avoids wide nullable-column table; each `event_type` has a documented JSON schema.
- `actor` text field (not FK) — actors can be `'service'`, `'admin:<ip>'`, or agent identifiers; FK to `tenants` is too narrow.
- Append-only — no `UPDATE`, no `DELETE` on `audit_events`. Corrections are compensating events.
- No partitioning at MVP — add monthly partitioning if table grows large (>10M rows/month).

---

## Retention policy

| Event category | Retention | Rationale |
|---|---|---|
| Auth failures | 90 days | Incident investigation window |
| Admin actions | 3 years | SOC 2, CE+, GDPR Art.30 records of processing |
| Compliance events | 2 years | Compliance trend analysis; audit readiness |
| System events | 1 year | Deployment audit trail |

Retention implemented as monthly partitions + `DROP TABLE audit_events_YYYY_MM` after expiry (same pattern as `raw_payloads`).

---

## Where audit events are emitted

Auth events are emitted in `internal/auth/auth.go` (where failures are detected). Admin events are emitted in each handler function after the mutation succeeds (not before — a failed mutation should not be logged as an audit success).

The emit function should be a fire-and-forget goroutine write to avoid adding latency to the hot path:

```go
// Non-blocking emit
go func() {
  _ = db.AuditLog(ctx, audit.Event{
    Type:     "auth.failure.hmac",
    TenantID: &tenantID,
    SourceIP: r.RemoteAddr,
    Data:     map[string]any{"endpoint": r.URL.Path},
  })
}()
```

Audit write failures are logged at WARN but must not fail the request — audit is observability, not the critical path.

---

## SIEM shipping (roadmap)

The audit store is an internal DB table. For compliance reporting (SOC 2, CE+), a log shipping leg is required:

1. **Phase 1 (MVP):** `audit_events` table in Postgres, queryable via psql. Sufficient for a manual audit.
2. **Phase 2:** Periodic export of `audit_events` rows to a structured log store (Loki, Elasticsearch, or Cloudflare Logpush). Required for SOC 2 Type I audit evidence.
3. **Phase 3:** Real-time alerting on high-risk events (multiple auth failures from same IP, admin credential rotation, etc.) via Alertmanager or a SIEM rule.

---

## Build trigger

Build the `audit_events` table and auth-event emitters before the first paying customer. The current state (no auth failure logging, no admin action log) is insufficient for SOC 2 or CE+ attestation.

Priority order:
1. `audit_events` table + migration.
2. Auth failure emitters (auth.go).
3. Admin action emitters (highest-value: tenant CRUD, credential rotation, rule changes).
4. Compliance event emitters (derivable from `compliance_evaluations` joins — lower priority).
5. Log shipping setup.

---

## Related docs

- `go-service/docs/SCHEMA.md` — current table list; audit_events will be added when built
- `go-service/docs/learning-notes/migrations-and-schema.md` — migration pattern
- `go-service/docs/learning-notes/auth-model.md` — auth flow where audit events are emitted
- `docs/threat-model.md` — STRIDE analysis identifies audit log gaps in the open items table
