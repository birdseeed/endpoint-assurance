# T5 Settings-Behaviour Suite Results

Run: 2026-07-07T09:19:16.073659+00:00

| Scenario | Result | Observed Behaviour |
|---|---|---|
| S1: T2 default-off | **PASS** | T2 in evals=False (want False), T1 present=True (want True), dashboard T2=False (want False), dashboard T1=True (want True) |
| S2: T2 enable | **PASS** | PUT status=200, T2 eval={'rule_key': 'cis_macos_5_2_2_min_length', 'title': 'Require minimum password length of 15 characters', 'severity': 'medium', 'status': 'fail', 'observed_value': '8', 'evaluated_at': '2026-07-07T10:18:57.594047+01:00'} |
| S3: T2 disable (DELETE) | **PASS** | DELETE status=200, T2 in evals=False (want False) |
| S4: Suppression (enabled=true + suppressed_until=future) | **PASS** | PUT status=200, extractor_ran=True, T2 in evals=False (want False), total evals (T1 rules present)=19. Semantics: suppressed_until < now() must be TRUE to include; future suppressed_until excludes rule. |
| S5: Severity override | **PASS** | GET /tenant-rules shows override=True. device_detail.severity='medium' (reads compliance_rules.severity = GLOBAL). findings.severity='critical' (reads compliance_evaluations.severity = EFFECTIVE/overridden). DEVIATION: device detail returns global severity, not effective; two endpoints disagree when |
| S6: Per-OS master switch (macos off → no evals; on → evals) | **PASS** | disable status=200, no_evals_when_off=True, device_in_db=True, device_in_API_list=False (DEVIATION: spec says device appears in API list, but FetchTenantDevices filters macOS devices via enabledOSFilter when macos_enabled=false), re-enable status=200, evals_when_on=True (20 rules) |
| S7: Global rule kill-switch | **PASS** | sip in evals (want False)=False, restored=True, restore verify row='t' |
| S8: Audit trails | **PASS** | rule change_types observed=['disabled', 'enabled', 'severity_overridden', 'suppressed', 'unsuppressed'], expected_subset=['disabled', 'enabled', 'severity_overridden', 'suppressed', 'unsuppressed'], platform_disable=True, platform_enable=True |

## Key Observations

### Suppression semantics (S4)
The SQL in `LoadRulesForTenant` includes:
```sql
AND (tr.suppressed_until IS NULL OR tr.suppressed_until < now())
```
This means: a rule is included ONLY when `suppressed_until` is NULL OR already past.
A future `suppressed_until` excludes the rule from the JOIN → rule not evaluated.
So `enabled=true` + `suppressed_until=<future>` → **not evaluated** (suppressed).

### Severity override surfacing (S5)
The `LoadRulesForTenant` query uses `COALESCE(tr.override_severity, cr.severity)` as
the severity, which is what gets stored in `compliance_evaluations.severity` at ingest
time by the extractor. The findings endpoint (`GET /admin/tenants/{id}/findings`) reads
`compliance_evaluations.severity` — so it returns the **effective (overridden) severity**,
not the global rule severity.

### Platform-switch behaviour (S6)
When `macos_enabled=false`, `isPlatformEnabled` returns false → extractor skips evaluation
entirely (no `compliance_evaluations` rows written), but still runs `upsertDevice`,
`upsertApps`, `insertComplianceSignals` etc. Device IS in the `devices` DB table.
DEVIATION: `FetchTenantDevices` uses `enabledOSFilter` → SQL adds `d.os NOT IN ('macOS')`
→ macOS devices are EXCLUDED from `GET /admin/tenants/{id}/devices` when macos_enabled=false.
The spec says 'device appears in /admin/tenants/{id}/devices' — this is NOT the actual behaviour.

### Audit trail change_type values (S8)
Observed `tenant_rule_changes.change_type` values:
- rule change_types observed=['disabled', 'enabled', 'severity_overridden', 'suppressed', 'unsuppressed'], expected_subset=['disabled', 'enabled', 'severity_overridden', 'suppressed', 'unsuppressed'], platform_disable=True, platform_enable=True

## Deviations / Findings

1. **S6: Platform-switch hides macOS devices from API list when disabled**: The spec says
   'device appears in /admin/tenants/{id}/devices'. In reality, `FetchTenantDevices` uses
   `enabledOSFilter` which generates `d.os NOT IN ('macOS')` when `macos_enabled=false`.
   macOS devices are excluded from the API listing while the platform is off.
   The device IS in the `devices` table (extractor ran `upsertDevice`), just hidden from the API.

2. **S5: device detail returns global severity, not effective (overridden) severity**:
   `GET /admin/devices/{id}` uses `report.Fetch` which joins `compliance_rules.severity`
   (global), ignoring any `override_severity` in `tenant_rules`.
   `GET /admin/tenants/{id}/findings` reads `compliance_evaluations.severity` which IS
   the effective/overridden severity stored at evaluation time.
   Two endpoints disagree when an override is active.
