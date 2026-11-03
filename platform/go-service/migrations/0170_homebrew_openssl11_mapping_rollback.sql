-- Rollback for 0170_homebrew_openssl11_mapping (PAT-2044).
--
-- Roll the binary back first if the comparator change is also being undone:
-- a pre-PAT-2044 binary reads 1.1.1s as equal to 1.1.1t, so with this mapping
-- in place it would under-report openssl@1.1.
--
-- Removes only the row 0170 inserted (matched on its notes), so a mapping a
-- person curated separately survives. Findings on openssl@1.1 are derived:
-- they are removed here only when no mapping for the formula remains, and
-- are rebuilt by the next full match after a re-apply.

BEGIN;

DELETE FROM app_cpe_mappings
WHERE source_type = 'homebrew_formula'
  AND lower(match_name) = 'openssl@1.1'
  AND cpe_vendor = 'openssl'
  AND cpe_product = 'openssl'
  AND notes LIKE 'PAT-2044 curated;%';

DELETE FROM device_cve_findings f
WHERE f.package_source = 'homebrew_formula'
  AND lower(f.package_name) = 'openssl@1.1'
  AND NOT EXISTS (
      SELECT 1 FROM app_cpe_mappings m
      WHERE m.source_type = 'homebrew_formula' AND lower(m.match_name) = 'openssl@1.1'
  );

COMMENT ON COLUMN device_cve_findings.confidence_tier IS
    'PAT-2023: high (curated mapping, version in NVD range) or low (version not confirmable: no range data, HEAD build, letter-suffixed or unparseable version). medium is reserved and never produced: only curated mappings match. NULL outside Homebrew.';

DELETE FROM schema_migrations WHERE version = '0170_homebrew_openssl11_mapping';

COMMIT;
