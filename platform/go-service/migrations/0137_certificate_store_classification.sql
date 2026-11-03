-- patched.im — 0137_certificate_store_classification.sql
-- PAT-1738: classify platform-root certificates by thumbprint (server half).
--
-- Two changes:
--
-- 1. device_certificates.store — which OS certificate store a row came from.
--    Every row before this migration implicitly came from Windows
--    LocalMachine\My or macOS System.keychain (the only stores either agent
--    read), so the backfill default 'My' is exactly correct for existing
--    rows; no data migration beyond the column add is needed. See
--    docs/PAYLOAD_SCHEMA.md "Certificates array — store field" for the wire
--    contract (updater PAT-1738 is the coordinated agent-side change that
--    starts sending 'Root'/'CA'/'System').
--
-- 2. platform_root_certificates — an external, provenance-tracked list of
--    known Microsoft/Apple platform-root certificate thumbprints, keyed by
--    (thumbprint_sha1, platform). Populated by
--    `patched-cve-sync --mode=root-sync` (internal/platformroot), which
--    fetches the CCADB-published Microsoft Trusted Root Program list and
--    Apple TLS Server Authentication root list. This mirrors the
--    provenance-recording shape os_cve_advisories established in
--    migrations/0050_os_cve_store.sql: source + source_url + fetched_at on
--    every row, so staleness is detectable and every classification can be
--    traced back to the exact published list it came from.
--
-- thumbprint_sha1 uses the same hash algorithm as device_certificates.sha1
-- (SHA-1, lowercase hex) on purpose — see internal/platformroot's fetch code
-- for how it is computed identically from both source lists — so
-- classification is a plain equality join, never a re-hash at query time.
--
-- is_platform_root / is_suspicious are NOT stored columns: both are computed
-- live, per query, via a LEFT JOIN against this table (see
-- internal/report/cert_expiry.go and internal/handlers/health_admin.go).
-- This is deliberate — storing a classification as a mutable column on
-- device_certificates would need re-computation on every root-list refresh,
-- and a stale stored flag from before a rogue thumbprint was disclosed would
-- fail closed in the wrong direction (silently still "not a platform root").
--
-- Rollback: migrations/0137_certificate_store_classification_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0137_certificate_store_classification.sql
-- Note: 0135_seed_t2_baseline.sql must have been applied first.

BEGIN;

-- ============================================================================
-- 1. device_certificates.store
-- ============================================================================

ALTER TABLE device_certificates ADD COLUMN store TEXT NOT NULL DEFAULT 'My';

COMMENT ON COLUMN device_certificates.store IS
    'Which OS certificate store this row was read from (PAT-1738). Windows: '
    '"My" | "Root" | "CA". macOS: "System" (the only keychain read). Defaults '
    'to "My" for every row collected before this field existed, and for any '
    'payload from an un-upgraded agent that omits it — matching what was '
    'true before this migration (the only source was LocalMachine\My / '
    'System.keychain). Does not by itself mean a row is a platform root; see '
    'platform_root_certificates.';

-- ============================================================================
-- 2. platform_root_certificates
-- ============================================================================

CREATE TABLE platform_root_certificates (
    thumbprint_sha1 TEXT        NOT NULL,
    platform        TEXT        NOT NULL CHECK (platform IN ('windows', 'macos')),
    source          TEXT        NOT NULL,   -- e.g. 'microsoft-ccadb', 'apple-ccadb-tls-server-auth'
    source_url      TEXT,
    fetched_at      TIMESTAMPTZ NOT NULL,
    subject_cn      TEXT,                   -- human debugging/audit only; never used in classification logic
    PRIMARY KEY (thumbprint_sha1, platform)
);

COMMENT ON TABLE platform_root_certificates IS
    'Known Microsoft/Apple platform-root certificate thumbprints (PAT-1738), '
    'fetched from the published CCADB Trusted Root Program lists by '
    '`patched-cve-sync --mode=root-sync`. Used to classify device_certificates '
    'rows as platform_root (thumbprint matched) vs. suspicious (subject text '
    'looks like a platform root but the thumbprint does not match) at query '
    'time — never stored as a mutable flag on device_certificates itself, so '
    'a root-list refresh reclassifies every row on the next read with no '
    'backfill step.';
COMMENT ON COLUMN platform_root_certificates.thumbprint_sha1 IS
    'Lowercase hex SHA-1 fingerprint. Same hash algorithm and casing as '
    'device_certificates.sha1, so the join is a plain equality.';
COMMENT ON COLUMN platform_root_certificates.source IS
    'Which published list this thumbprint came from, e.g. '
    '"microsoft-ccadb" or "apple-ccadb-tls-server-auth". Recorded per row, '
    'not just per sync run, since a future source could be added without a '
    'schema change.';
COMMENT ON COLUMN platform_root_certificates.fetched_at IS
    'Updated on every successful root-sync run that observed this thumbprint '
    '(even when the row already existed), so staleness is detectable the '
    'same way os_cve_advisories.synced_at is used.';

CREATE INDEX idx_platform_root_certs_platform ON platform_root_certificates (platform);

-- The app connects as the unprivileged `patched` role; without these grants
-- root-sync's upserts and the report/admin-health read paths 500 with
-- "permission denied for table" (cf. PAT-579 / 0050_os_cve_store.sql).
GRANT SELECT, INSERT, UPDATE ON platform_root_certificates TO patched;

INSERT INTO schema_migrations (version) VALUES ('0137_certificate_store_classification')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
