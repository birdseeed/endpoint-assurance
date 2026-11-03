-- patched.im — 0116_catalogue_target_operations.sql
-- PAT-1538 (PAT-1481 ADR-0011 §4/§7): per-(target,operation) global
-- verification state machine.
--
-- Install, update and uninstall are independent capabilities (ADR-0011 §4):
-- suspending one operation must not silently suspend or approve another. This
-- table sits beneath the existing global catalogue_platform_targets row and
-- reuses that row's identity and signer_provenance rather than duplicating
-- them — one row here per (platform_target, operation).
--
-- state starts 'pending_verification' and moves to 'verified' or 'blocked' as
-- the (not-yet-built) verification pipeline runs; 'suspended' and 'retired'
-- are later lifecycle states per ADR-0011 §7 (publication and endpoint
-- authority fail closed).
--
-- Additive / non-actuating: nothing reads this table's state yet to gate
-- execution. No worker or runner is added by this migration.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0116_catalogue_target_operations.sql
BEGIN;

CREATE TABLE catalogue_target_operations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_target_id  UUID        NOT NULL REFERENCES catalogue_platform_targets(id) ON DELETE CASCADE,
    operation           TEXT        NOT NULL CHECK (operation IN ('install', 'update', 'uninstall')),
    state               TEXT        NOT NULL DEFAULT 'pending_verification' CHECK (state IN (
                          'pending_verification', 'verified', 'blocked', 'suspended', 'retired')),
    recipe_revision     TEXT,
    verified_release_id TEXT,
    verified_at         TIMESTAMPTZ,
    verification_detail JSONB       NOT NULL DEFAULT '{}'::jsonb,
    state_error         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform_target_id, operation)
);
CREATE INDEX catalogue_target_operations_state_idx ON catalogue_target_operations (state);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_target_operations TO patched;

INSERT INTO schema_migrations (version) VALUES ('0116_catalogue_target_operations')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
