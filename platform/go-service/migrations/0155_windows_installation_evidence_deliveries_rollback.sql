-- API binary rollback is safe with this table retained. Never erase an
-- admitted delivery high-water mark, including an empty target publication.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM windows_installation_evidence_deliveries) THEN
        RAISE EXCEPTION 'Retain Windows installation evidence delivery history; roll back the binary or publish a higher version';
    END IF;
END;
$$;
DROP TABLE windows_installation_evidence_deliveries;
DROP FUNCTION guard_windows_installation_evidence_deliveries();
DELETE FROM schema_migrations WHERE version = '0155_windows_installation_evidence_deliveries';
COMMIT;
