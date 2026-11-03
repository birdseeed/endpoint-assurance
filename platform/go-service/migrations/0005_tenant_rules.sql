-- patched.im — 0005_tenant_rules.sql
-- ADR-0001 action item 3: per-tenant rule activation model + PII annotation.
--
-- Three additions:
--
--   1. compliance_rules gains three columns:
--      - collection_tier: T1 (always-evaluate) / T2 (per-tenant) / T3 (out of scope)
--      - pii_observed: documents what personal data each signal can reveal
--      - requires_user_consent: blocks T2 activation without a consent story
--
--   2. tenant_rules: per-tenant rule on/off toggle, severity override, suppression.
--      T1 rules evaluate regardless; a tenant_rules row for a T1 rule only
--      adds an override_severity or a suppression window.
--      T2 rules are NOT evaluated for a tenant unless an enabled tenant_rules row
--      exists — absence = off.
--
--   3. tenant_rule_changes: append-only audit log of every tenant_rules mutation.
--
-- All 17 existing rules are T1. T2 rules will be inserted in later migrations
-- as the collector expands (ADR-0001 action item 5). The evaluator's LoadRules
-- query gains AND collection_tier = 'T1' as a defensive guard in this same
-- change — when T2 rules arrive, a separate LoadRulesForTenant(tenantID) will
-- join against tenant_rules for the T2 slice.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0005_tenant_rules.sql

BEGIN;

-- ============================================================================
-- COMPLIANCE_RULES additions
-- ============================================================================

ALTER TABLE compliance_rules
    ADD COLUMN collection_tier TEXT NOT NULL DEFAULT 'T1'
        CHECK (collection_tier IN ('T1', 'T2', 'T3')),
    ADD COLUMN pii_observed TEXT,
    ADD COLUMN requires_user_consent BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN compliance_rules.collection_tier IS
    'T1 = collect+evaluate always (core baseline). T2 = collect always, evaluate per tenant_rules. T3 = out of scope. See go-service/docs/adr/0001-cis-collection-scope.md.';
COMMENT ON COLUMN compliance_rules.pii_observed IS
    'Human-readable description of what personal data this signal could reveal. NULL = no PII concern. Required non-NULL before any T2 rule is published to tenants.';
COMMENT ON COLUMN compliance_rules.requires_user_consent IS
    'True if collecting this signal reads user-specific data (e.g. user plist under ~/Library). Blocks T2 activation without a documented consent story in the privacy notice.';

-- Set collection_tier explicitly on all 17 existing rules.
-- Default is already 'T1', but an explicit UPDATE makes pg_stat_activity and
-- audit logs unambiguous about the intent at migration time.
UPDATE compliance_rules SET collection_tier = 'T1';

-- PII annotations for the T1 signals that touch user-owned data.
-- T1 rules are always-collected (pii_observed is documentation-only for them);
-- T2 rules will gate activation on this column being non-NULL.
UPDATE compliance_rules
SET pii_observed     = 'Reads the primary local user''s screensaver plist. Reveals account username via FIRST_USER lookup (dscl, UID >= 500).',
    requires_user_consent = false      -- root-readable plist; no per-user consent required under Intune deployment
WHERE signal_key = 'screensaver_password';

UPDATE compliance_rules
SET pii_observed = 'Reports the macOS account name configured for automatic login, if set. Reveals a local username when auto-login is enabled.'
WHERE signal_key = 'auto_login_user';

UPDATE compliance_rules
SET pii_observed = 'Reports the count of local admin group members (excluding root). Does not report account names — count only.'
WHERE signal_key = 'local_admin_count';

-- ============================================================================
-- TENANT_RULES — per-tenant rule activation, severity overrides, suppression
-- ============================================================================

CREATE TABLE tenant_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id             UUID NOT NULL REFERENCES compliance_rules(id),
    enabled             BOOLEAN NOT NULL DEFAULT true,
    override_severity   TEXT CHECK (override_severity IN ('low', 'medium', 'high', 'critical')),
    suppression_reason  TEXT,
    suppressed_until    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, rule_id)
);

CREATE INDEX idx_tenant_rules_tenant  ON tenant_rules(tenant_id);
CREATE INDEX idx_tenant_rules_enabled ON tenant_rules(tenant_id)
    WHERE enabled = true;

COMMENT ON TABLE tenant_rules IS
    'Per-tenant rule controls. T2 rules not present here are not evaluated for that tenant. T1 rules evaluate regardless; rows here add severity overrides or suppression windows.';
COMMENT ON COLUMN tenant_rules.override_severity IS
    'Tenant-specific severity. Overrides compliance_rules.severity for this tenant''s evaluations and reports. NULL = use global severity.';
COMMENT ON COLUMN tenant_rules.suppression_reason IS
    'Free-text operator note explaining the suppression (e.g. "accepted risk — compensating control documented in risk register").';
COMMENT ON COLUMN tenant_rules.suppressed_until IS
    'Non-NULL and in the future = rule is suppressed until this timestamp. NULL or past timestamp = rule is active.';

-- ============================================================================
-- TENANT_RULE_CHANGES — append-only audit log
-- ============================================================================

CREATE TABLE tenant_rule_changes (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    rule_id             UUID NOT NULL,
    changed_by          TEXT NOT NULL DEFAULT 'system',
    change_type         TEXT NOT NULL CHECK (change_type IN (
                            'enabled', 'disabled',
                            'suppressed', 'unsuppressed',
                            'severity_overridden', 'severity_reset'
                        )),
    old_enabled         BOOLEAN,
    new_enabled         BOOLEAN,
    old_severity        TEXT,
    new_severity        TEXT,
    suppression_reason  TEXT,
    suppressed_until    TIMESTAMPTZ,
    changed_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trchanges_tenant_time ON tenant_rule_changes(tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_rule_changes IS
    'Append-only audit trail of every tenant_rules mutation. Never UPDATE or DELETE rows here — use INSERT to record each change.';
COMMENT ON COLUMN tenant_rule_changes.changed_by IS
    'Identity of the actor: email address, API key label, or "system" for automated changes.';
COMMENT ON COLUMN tenant_rule_changes.change_type IS
    'What changed: enabled/disabled = on-off toggle; suppressed/unsuppressed = time-boxed suppression; severity_overridden/severity_reset = per-tenant severity.';

-- ============================================================================
-- BOOKKEEPING
-- ============================================================================

INSERT INTO schema_migrations (version) VALUES ('0005_tenant_rules');

COMMIT;
