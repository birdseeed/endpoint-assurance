-- 0064: trial tenant provisioning columns (PAT-668).
--
--   is_trial          — marks this tenant as a self-serve trial (provisioned
--                       via POST /v1/trial/provision). Full-paid tenants have
--                       is_trial=false (default).
--   trial_expires_at  — when the trial window closes; NULL on full-paid tenants.
--                       Computed as now()+14 days at provisioning time.
--   trial_device_cap  — maximum number of enrolled devices allowed during trial.
--                       Default 3; NULL = no cap (used for full-paid tenants
--                       but left as 3 for trials by the provision handler).
--
-- Index on email avoids a full table scan in the "one active trial per email"
-- uniqueness check in the provision endpoint.

BEGIN;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS is_trial         BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS trial_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS trial_email      TEXT,
    ADD COLUMN IF NOT EXISTS trial_device_cap INT         NOT NULL DEFAULT 3;

-- Enforce uniqueness of trial_email across all trial rows (not just active ones)
-- at the DB layer. NULL email (full-paid tenants) is excluded. The application
-- handler also enforces the "one active trial per email" rule by only checking
-- rows where trial_expires_at > now() — the uniqueness constraint here prevents
-- two concurrent provisions for the same email from racing past the application
-- check. Note: index predicates cannot use non-IMMUTABLE functions (no now());
-- the expiry-based active check lives in application code only.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_trial_email
    ON tenants (trial_email)
    WHERE is_trial AND trial_email IS NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0064_tenant_trial')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
