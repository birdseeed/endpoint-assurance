-- patched.im — 0086_drop_mirror_eula_approvals_rollback.sql
-- Rollback for 0086_drop_mirror_eula_approvals.sql (PAT-847).
--
-- Recreates mirror_eula_approvals with the exact schema from
-- 0073_mirror_eula_approvals.sql (columns, unique index, partial index,
-- grant). DATA IS NOT RESTORABLE: the DROP TABLE in the forward migration is
-- destructive — no snapshot of the dropped rows is taken by this rollback.
-- The table comes back empty. If you need the pre-drop approval rows back,
-- restore from a database backup taken before 0086 was applied instead of
-- relying on this rollback.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0086_drop_mirror_eula_approvals_rollback.sql
BEGIN;

CREATE TABLE mirror_eula_approvals (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    label_identity  TEXT         NOT NULL,  -- team:<id> | bundle:<id> | name:<name>, lowercased
    platform        TEXT         NOT NULL CHECK (platform IN ('macos', 'windows')),
    name            TEXT,                   -- human display label at approval time
    approved        BOOLEAN      NOT NULL DEFAULT TRUE,
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source          TEXT         NOT NULL CHECK (source IN ('discovered', 'manual')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX mirror_eula_approvals_identity_platform_uniq
    ON mirror_eula_approvals (label_identity, platform);

CREATE INDEX mirror_eula_approvals_approved_idx
    ON mirror_eula_approvals (label_identity, platform)
    WHERE approved = TRUE;

GRANT SELECT, INSERT, UPDATE, DELETE ON mirror_eula_approvals TO patched;

-- ============================================================================
-- BOOKKEEPING

DELETE FROM schema_migrations WHERE version = '0086_drop_mirror_eula_approvals';

COMMIT;
