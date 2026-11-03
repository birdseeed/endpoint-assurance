-- PAT-409: authoritative OS-build → CVE advisories.
--
-- Fast-follow to the NVD CPE matcher (PAT-335). The launch path feeds the device
-- OS to the generic match engine as a pseudo-app (apple:macos / microsoft:windows_*)
-- via NVD CPE with version-range gating. NVD's OS-build coverage is coarse and
-- noisy, so we add vendor-grade sources:
--
--   * macOS  — Apple security-releases feed (CVEs per macOS version / build)
--   * Windows — MSRC CVRF / Security Update Guide API (CVEs per build / KB)
--
-- These rows are reconciled against NVD by the OS matcher (internal/oscve): an OS
-- finding backed by a vendor advisory is emitted as match_confidence
-- 'version_vendor_confirmed' and the NVD CPE finding for the same (device, CVE) is
-- suppressed. NVD CPE remains the fallback where no vendor advisory exists.

BEGIN;

CREATE TABLE os_cve_advisories (
    id            BIGSERIAL PRIMARY KEY,
    os_platform   TEXT NOT NULL,                 -- 'macos' | 'windows'
    os_version    TEXT NOT NULL DEFAULT '',      -- marketing version, e.g. '14.5' / '10.0.19045'
    os_build      TEXT NOT NULL DEFAULT '',      -- build / KB, e.g. '23F79' (Apple) or '19045.4651' / 'KB5040442' (MS)
    cve_id        TEXT NOT NULL,                 -- e.g. CVE-2024-12345
    cvss_v3_score NUMERIC(4,1),                  -- NULL when the vendor advisory omits a score
    severity      TEXT,                          -- CRITICAL/HIGH/MEDIUM/LOW/NONE (best-effort from vendor data)
    fixed_in_build TEXT NOT NULL DEFAULT '',     -- build/KB that remediates this CVE, where the feed states it
    source        TEXT NOT NULL,                 -- 'apple' | 'msrc'
    advisory_url  TEXT NOT NULL DEFAULT '',      -- source advisory page (HT / MSRC URL)
    published_at  TIMESTAMPTZ,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One advisory row per (platform, version, build, CVE, source). A CVE can be
    -- listed against several builds; each gets its own row.
    UNIQUE (os_platform, os_version, os_build, cve_id, source)
);

CREATE INDEX idx_os_cve_platform_version ON os_cve_advisories (os_platform, os_version);
CREATE INDEX idx_os_cve_build            ON os_cve_advisories (os_platform, os_build);
CREATE INDEX idx_os_cve_cve             ON os_cve_advisories (cve_id);

-- The app connects as the unprivileged `patched` role; without these grants the
-- OS-CVE sync (INSERT) and report read path (SELECT) 500 with
-- "permission denied for table" (cf. PAT-579 for tenant_new_apps).
GRANT SELECT, INSERT, UPDATE ON os_cve_advisories TO patched;
GRANT USAGE, SELECT ON SEQUENCE os_cve_advisories_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0050_os_cve_store');

COMMIT;
