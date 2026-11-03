# Tenant data model

**Subsystem:** multi-tenancy, credential management, per-tenant policy
**Code:** `internal/handlers/`, `migrations/`

---

## Overview

Patched is a multi-tenant SaaS. All device data is isolated by `tenant_id`. The tenant hierarchy:

```
tenants
  ├── tenant_credentials (bearer + HMAC key, multiple per tenant for rotation)
  ├── device_credentials (per-device bearer + HMAC, for /v1/posture)
  ├── devices → device_apps, compliance_signals, compliance_evaluations
  ├── tenant_rules (per-rule T2 activation, severity overrides, suppression)
  │     └── tenant_rule_changes (append-only audit log)
  ├── tenant_platform_changes (append-only: macos_enabled/windows_enabled flips)
  ├── tenant_app_policies (mandatory/approved/unapproved/unmanaged per app)
  ├── tenant_allowlists (per-tenant software allow-list)
  └── allowlist_default_deny flag
```

---

## tenants table

Key columns:

| Column | Purpose |
|---|---|
| `id` | UUID primary key (used as FK in all other tables) |
| `name` | Display name ("Acme Ltd") |
| `intune_tenant_id` | Microsoft tenant ID — optional, used for Tier 3 Graph access |
| `macos_enabled` | Master switch: if false, no macOS T1/T2 evaluation runs |
| `windows_enabled` | Master switch: if false, no Windows T1/T2 evaluation runs |
| `revoked_at` | Non-NULL = tenant is disabled; auth rejects all requests immediately |
| `allowlist_default_deny` | true = devices with unlisted software fail the allowlist scan |

---

## Credential model

### Tenant credentials

`tenant_credentials` stores hashed bearer tokens and HMAC secrets. Multiple rows per tenant are valid during rotation — all non-expired rows are checked.

```
bearer_token_hash = sha256(plaintext_token)   -- stored as bytea
hmac_secret                                    -- stored as bytea (raw bytes, not b64)
expires_at                                     -- NULL = no expiry; non-NULL = grace-period credential
```

The plaintext token is shown once on creation and cannot be recovered. Rotation:
```
POST /admin/tenants/{id}/rotate-credentials
  → mints new credential
  → sets expires_at on old credential (CREDENTIAL_GRACE_HOURS, default 24h)
  → returns new plaintext (ONCE ONLY)
```

### Device credentials

`device_credentials` (migration `0029`) follows the same bearer + HMAC pattern but is scoped to a specific device (`device_id NOT NULL`). Used exclusively by `GET /v1/posture` to authenticate the requesting device and return only its own posture.

---

## Per-tenant rule policy (tenant_rules)

```sql
tenant_rules(
  id                uuid PRIMARY KEY,
  tenant_id         uuid REFERENCES tenants(id),
  rule_id           uuid REFERENCES compliance_rules(id),
  enabled           boolean,           -- T2 gate: true = rule evaluates for this tenant
  override_severity text,              -- overrides compliance_rules.severity in reports
  suppression_reason text,             -- operator note for the exemption
  suppressed_until  timestamptz        -- NULL = active; non-NULL future = suppressed
)
```

Every mutation is recorded in `tenant_rule_changes` (append-only). The admin API (`PUT /admin/tenants/{id}/rules/{ruleId}`) writes both tables in one transaction.

**T1 rules:** the `enabled` column has no effect on evaluation gate — T1 rules always evaluate when the platform is enabled. `tenant_rules` rows for T1 rules can still carry `override_severity` and suppression.

**T2 rules:** require `enabled = true` in `tenant_rules` to be included in `LoadRulesForTenant()`.

**PII gate:** before a T2 rule can be activated for any tenant, `compliance_rules.pii_observed` must be non-NULL (documents what personal data the signal reveals). Enforced by code review, not a DB constraint.

---

## Platform master switches

`tenants.macos_enabled` and `tenants.windows_enabled` are on/off toggles. When a platform is disabled:
- `patched-extractor` skips all rule evaluation (including T1) for that platform's payloads.
- Devices on that platform still appear in the device list but have no compliance evaluations.

Every flip is recorded in `tenant_platform_changes` (append-only audit log). Admin API: `GET`/`PUT /admin/tenant-platforms/{tenantID}`.

---

## App policy model

`tenant_app_policies` stores per-tenant, per-app classifications:

| Policy | Meaning |
|---|---|
| `mandatory` | Must be installed on all devices |
| `approved` | Permitted; not required |
| `unapproved` | Should not be installed |
| `unmanaged` | No policy set |

Each row has an `enforcement_tier`: `report` (advisory only), `app_management`, or `managed`. Matched in priority order: by `team_id` > `bundle_id` > `name`.

Drift is computed at query time by `GET /v1/posture` (`mandatory_missing + unapproved_present`) and surfaced in the posture response.

---

## Tenant lifecycle

| Event | Action |
|---|---|
| Onboarding | `POST /admin/tenants` → creates `tenants` row + first `tenant_credentials` pair |
| Credential rotation | `POST /admin/tenants/{id}/rotate-credentials` → new credential, 24h grace on old |
| Platform toggle | `PUT /admin/tenant-platforms/{id}` → updates master switch, logs to `tenant_platform_changes` |
| Revocation | Direct SQL: `UPDATE tenants SET revoked_at = now()` → all auth checks fail immediately |
| Deletion | Not yet automated — manual SQL required (cascading FK deletes) |

---

## Key files

| File | Role |
|---|---|
| `migrations/0001_initial.sql` | `tenants` table |
| `migrations/0017_tenant_credentials.sql` | Multi-credential schema with `expires_at` |
| `migrations/0029_device_credentials.sql` | Per-device credential schema |
| `internal/handlers/tenant.go` | Admin API: tenant CRUD, platform switches |
| `internal/handlers/rules.go` | `PUT /admin/tenants/{id}/rules/{ruleId}` |
| `go-service/docs/SCHEMA.md` | Full schema reference with all tables |
