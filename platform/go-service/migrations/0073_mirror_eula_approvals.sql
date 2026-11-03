-- patched.im — 0073_mirror_eula_approvals.sql
-- PAT-794: mirror EULA approval state — single source of truth.
--
-- This table replaces the two disconnected approval stores the mirror pipeline
-- used to straddle (the dashboard's own SQLite table + the mirror_eula_approved
-- boolean sprinkled across engine/labels/*.json in the updater repo). Both the
-- Catalogue admin UI (via the :8081 admin API) and the CI mirror pipeline (via
-- GET /admin/mirror/approved) now read and write this one store.
--
-- label_identity is the same precedence key used by fetchAppPolicy /
-- detectNewTenantApps (internal/handlers/posture.go, internal/extractor/new_apps.go):
--   team:<team_id>  > bundle:<bundle_id> > name:<lower(name)>
-- stored lowercased. platform pins the row to macos/windows so the CI can match
-- it against a platform-specific label.
--
-- source:
--   discovered — approved from the cross-tenant candidate queue (app seen
--                installed on a real tenant).
--   manual     — added ahead of discovery (Andy wants it mirrored proactively).
--
-- approved is a soft flag: DELETE /admin/mirror/approvals/{id} clears it to
-- FALSE (a revocation) rather than dropping the row, so a revoked label falls
-- back into the candidate review queue and the approval history is preserved.
-- Re-approving the same (label_identity, platform) flips it back to TRUE.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0073_mirror_eula_approvals.sql
BEGIN;

-- DEPLOY ORDERING: safe to apply anytime; no existing table depends on this one.

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

-- One approval row per (label, platform). POST upserts on this key; the CI
-- pipeline and the admin UI therefore never see duplicate approvals for the
-- same label.
CREATE UNIQUE INDEX mirror_eula_approvals_identity_platform_uniq
    ON mirror_eula_approvals (label_identity, platform);

-- GET /admin/mirror/approved and the candidate anti-join both filter on
-- approved = TRUE; index the live set for those hot reads.
CREATE INDEX mirror_eula_approvals_approved_idx
    ON mirror_eula_approvals (label_identity, platform)
    WHERE approved = TRUE;

GRANT SELECT, INSERT, UPDATE, DELETE ON mirror_eula_approvals TO patched;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0073_mirror_eula_approvals');

COMMIT;
