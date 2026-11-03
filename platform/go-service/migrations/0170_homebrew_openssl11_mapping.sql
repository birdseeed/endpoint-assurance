-- 0170: curated Homebrew mapping for openssl@1.1 (PAT-2044)
--
-- 0168 left openssl@1.1 out of the seed because its letter releases (1.1.1s,
-- 1.1.1t) were beyond the numeric-only version comparator, which read 1.1.1s
-- as equal to 1.1.1t and so as fixed. PAT-2044 teaches the comparator
-- OpenSSL's letter suffixes, and sends any shape it cannot order with
-- certainty (pre-releases such as 3.0.0-rc1) to version_unverified rather
-- than "not in range", so the formula can now be mapped.
--
-- The NVD key is the same one 0168 verified for openssl@3: openssl:openssl.
-- NVD files the 1.0.2 and 1.1.1 branches under it with letter bounds
-- (CVE-2023-0286: 1.1.1 <= v < 1.1.1t).
--
-- Additive only. WHERE NOT EXISTS keeps an existing row, including one a
-- person has already curated, untouched.
BEGIN;

INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
SELECT 'macos', 'openssl@1.1', 'openssl', 'openssl',
       'PAT-2044 curated; NVD key verified 2026-09-23 (as openssl@3 in 0168)',
       'homebrew_formula', 'curated'
WHERE NOT EXISTS (
    SELECT 1 FROM app_cpe_mappings
    WHERE source_type = 'homebrew_formula'
      AND lower(match_name) = 'openssl@1.1'
      AND cpe_vendor = 'openssl'
      AND cpe_product = 'openssl'
);

COMMENT ON COLUMN device_cve_findings.confidence_tier IS
    'PAT-2023: high (curated mapping, version in NVD range) or low (version not confirmable: no range data, HEAD build, or a version the comparator cannot order against the bound, such as a pre-release; PAT-2044). medium is reserved and never produced: only curated mappings match. NULL outside Homebrew.';

INSERT INTO schema_migrations (version) VALUES ('0170_homebrew_openssl11_mapping')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
