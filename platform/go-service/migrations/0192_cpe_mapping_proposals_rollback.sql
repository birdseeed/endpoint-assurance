-- Rollback for 0192 (PAT-2138). Refuses while any automatic mapping or
-- automatic finding exists: narrowing the two CHECK constraints over such a
-- row would fail anyway, and silently deleting them would drop CVE findings
-- without a lifecycle event. Revoke every auto mapping through the admin API
-- (which withdraws its findings) and let the matcher run first.
BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM app_cpe_mappings WHERE review_state = 'auto' LIMIT 1)
       OR EXISTS (SELECT 1 FROM device_cve_findings WHERE mapping_basis = 'auto' LIMIT 1) THEN
        RAISE EXCEPTION '0192 rollback refused: automatic CPE mappings or findings exist';
    END IF;
END;
$$;

DROP INDEX software_installations_name_normalized_idx;
DROP INDEX device_apps_name_tokens_idx;
DROP INDEX device_apps_name_normalized_idx;
DROP TABLE cpe_proposal_origins;
DROP TABLE cpe_nvd_budget;
DROP TABLE cpe_proposer_status;
DROP TABLE cpe_vendor_aliases;
DROP TABLE cpe_dictionary_cache;
DROP TABLE cpe_mapping_proposal_audit;
DROP FUNCTION reject_cpe_mapping_proposal_audit_mutation();
DROP TABLE cpe_mapping_proposals;

ALTER TABLE device_cve_findings
    DROP CONSTRAINT device_cve_findings_mapping_basis_check,
    ADD CONSTRAINT device_cve_findings_mapping_basis_check
        CHECK (mapping_basis IN ('curated', 'auto_seeded'));

ALTER TABLE app_cpe_mappings
    DROP CONSTRAINT app_cpe_mappings_auto_is_app_name,
    DROP CONSTRAINT app_cpe_mappings_review_state_check,
    ADD CONSTRAINT app_cpe_mappings_review_state_check
        CHECK (review_state IN ('curated', 'auto_seeded'));

DROP FUNCTION cpe_name_tokens(text);
DROP FUNCTION cpe_normalize_name(text);

DELETE FROM schema_migrations WHERE version = '0192_cpe_mapping_proposals';

COMMIT;
