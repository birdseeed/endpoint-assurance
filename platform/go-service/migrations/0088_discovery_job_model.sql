-- patched.im — 0088_discovery_job_model.sql
-- PAT-848 S1 (PAT-943): durable discovery/job model + idempotent job
-- endpoints. Extends (does not fork) the PAT-850 catalogue review model
-- (0078_catalogue_review_model.sql).
--
-- See ../../updater/docs/nightly-discovery-unification.md ("Durable job
-- handoff") for the full design. Summary:
--
--   discovery_runs         one row per nightly discovery adapter execution
--                          (macOS or Windows), recorded once at end-of-run.
--   discovery_jobs         the durable, IDEMPOTENT unit of work the
--                          discovery stage hands to the execution stage for
--                          one catalogue_platform_targets row. Keyed
--                          (product_id, platform, version_or_checksum,
--                          operation) — re-creating the same key returns the
--                          existing job, never a duplicate (a rerun of the
--                          nightly after a mid-run failure resumes
--                          idempotently). `state` reuses the EXACT pipeline-
--                          progression vocabulary already established by
--                          catalogue_platform_targets.state / the Go
--                          CatalogueState type (ready, queued, downloading,
--                          scanning, verifying, published, failed) — one
--                          shared contract, not a second one.
--   catalogue_platform_targets  gains four last_published_*/last_verified_*
--                          columns: the per-target baseline (version,
--                          SHA-256, signer) the discovery stage diffs
--                          against, replacing the verifier-state branch as
--                          orchestration truth.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0088_discovery_job_model.sql
BEGIN;

-- DEPLOY ORDERING: apply after 0078 (catalogue_platform_targets must exist).
-- Additive only: nothing existing depends on discovery_runs/discovery_jobs,
-- and the four new catalogue_platform_targets columns are nullable with no
-- default that could change existing read behaviour.

-- discovery_runs: one row per nightly discovery adapter execution.
CREATE TABLE discovery_runs (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    platform           TEXT        NOT NULL CHECK (platform IN ('macos','windows')),
    started_at         TIMESTAMPTZ NOT NULL,
    finished_at        TIMESTAMPTZ,
    status             TEXT        NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    targets_evaluated  INTEGER     NOT NULL DEFAULT 0,
    jobs_created       INTEGER     NOT NULL DEFAULT 0,
    detail             JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- free-form per-decision counts etc.
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX discovery_runs_platform_started_idx ON discovery_runs (platform, started_at DESC);

-- discovery_jobs: the idempotent job queue/state machine.
CREATE TABLE discovery_jobs (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id           UUID        NOT NULL REFERENCES catalogue_products(id) ON DELETE CASCADE,
    platform             TEXT        NOT NULL CHECK (platform IN ('macos','windows')),
    -- operation: 'mirror' = download -> scan -> verify -> publish the same
    -- bytes; 'vendor_direct' = verify + pin the vendor URL/checksum without
    -- re-hosting (these two reuse the delivery_mode vocabulary and must match
    -- the target's current delivery_mode; enforced in the Go handler, not
    -- here, since it requires a lookup). 'reverify' = periodic full
    -- re-attestation of an already-published version (PAT-848 S4): it needs
    -- its own key space because the same (product, platform, version) has
    -- already consumed the mirror/vendor_direct key when it was published —
    -- without it, a reverify_due job would idempotently collide with the
    -- completed publish job and no-op. 'reverify' is valid for either
    -- delivery mode; S4 defines its cadence/re-arm semantics.
    operation            TEXT        NOT NULL CHECK (operation IN ('mirror','vendor_direct','reverify')),
    version_or_checksum  TEXT        NOT NULL,  -- resolved version string OR checksum, whichever the discovery adapter resolved
    state                TEXT        NOT NULL DEFAULT 'ready' CHECK (state IN (
                            'ready','queued','downloading','scanning','verifying','published','failed')),
    state_error          TEXT,
    state_updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    discovery_run_id     UUID        REFERENCES discovery_runs(id) ON DELETE SET NULL,
    -- decision is why this job exists: change_detected (new/changed version)
    -- or reverify_due (periodic re-attestation cadence). These are the only
    -- two discovery decisions that ever create a job (see design doc) — a
    -- discovery adapter never posts unchanged/needs_metadata/failed here.
    decision             TEXT        NOT NULL CHECK (decision IN ('change_detected','reverify_due')),
    reason               TEXT,
    source_url           TEXT,
    expected_signer      JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- {team_id, authenticode_publisher, ...}
    expected_checksum    TEXT,       -- independent trusted checksum (winget hash, vendor sha256 URL), when known
    discovered_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor                TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, platform, version_or_checksum, operation)
);
CREATE INDEX discovery_jobs_state_idx ON discovery_jobs (platform, state);
CREATE INDEX discovery_jobs_product_idx ON discovery_jobs (product_id);
CREATE INDEX discovery_jobs_run_idx ON discovery_jobs (discovery_run_id) WHERE discovery_run_id IS NOT NULL;

-- catalogue_platform_targets: per-target baseline the discovery stage diffs
-- against (last successfully published + last verified: version, SHA-256,
-- signer). Populated by POST /admin/discovery/jobs/state as a job passes
-- verifying/published — see internal/handlers/discovery_jobs.go.
ALTER TABLE catalogue_platform_targets
    ADD COLUMN last_published_version TEXT,
    ADD COLUMN last_published_sha256  TEXT,
    ADD COLUMN last_published_at      TIMESTAMPTZ,
    ADD COLUMN last_verified_version  TEXT,
    ADD COLUMN last_verified_sha256   TEXT,
    ADD COLUMN last_verified_signer   JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN last_verified_at       TIMESTAMPTZ;

GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_runs TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_jobs TO patched;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0088_discovery_job_model')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
