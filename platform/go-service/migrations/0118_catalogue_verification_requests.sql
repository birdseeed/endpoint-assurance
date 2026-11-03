-- patched.im — 0118_catalogue_verification_requests.sql
-- PAT-1538 (PAT-1481 ADR-0011 §6): coalescing verification outbox.
--
-- "Verify a global release once regardless of tenant count." The partial
-- unique index on dedup_key (only for queued/running rows) means a second
-- tenant's request for the identical (target, operation, version, source
-- hash, artifact hash, recipe revision) while one is already in flight must
-- be coalesced by the caller catching the unique-violation and appending its
-- tenant_id to requested_by_tenant_ids on the existing row, rather than
-- inserting a duplicate row. There is no worker or runner in this migration —
-- table and dedup contract only.
--
-- artifact_hash is nullable (unknown until the artifact is fetched); the
-- generated dedup_key expression coalesces it to '' so a NULL artifact_hash
-- does not break the generated column. An empty-string artifact_hash is
-- rejected by CHECK rather than merely discouraged: coalesce(NULL, '') and
-- coalesce('', '') both produce '', so a real empty string would silently
-- collide with the NULL case in dedup_key and defeat the distinction the
-- column exists to preserve.
--
-- Additive / non-actuating: nothing reads or drains this table yet.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0118_catalogue_verification_requests.sql
BEGIN;

CREATE TABLE catalogue_verification_requests (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_target_id UUID        NOT NULL REFERENCES catalogue_platform_targets(id) ON DELETE CASCADE,
    operation          TEXT        NOT NULL CHECK (operation IN ('install', 'update', 'uninstall')),
    candidate_version  TEXT        NOT NULL,
    source_url_hash    TEXT        NOT NULL,
    artifact_hash      TEXT        CHECK (artifact_hash IS NULL OR artifact_hash <> ''),
    recipe_revision    TEXT        NOT NULL,
    dedup_key          TEXT        GENERATED ALWAYS AS (
                         platform_target_id::text || ':' || operation || ':' || candidate_version || ':' ||
                         source_url_hash || ':' || coalesce(artifact_hash, '') || ':' || recipe_revision
                       ) STORED,
    status             TEXT        NOT NULL DEFAULT 'queued' CHECK (status IN (
                         'queued', 'running', 'completed', 'failed')),
    requested_by_tenant_ids UUID[] NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX catalogue_verification_requests_dedup_key_uq ON catalogue_verification_requests (dedup_key) WHERE status IN ('queued', 'running');
CREATE INDEX catalogue_verification_requests_status_idx ON catalogue_verification_requests (status);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_verification_requests TO patched;

INSERT INTO schema_migrations (version) VALUES ('0118_catalogue_verification_requests')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
