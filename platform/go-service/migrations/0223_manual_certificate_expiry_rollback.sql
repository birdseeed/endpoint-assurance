-- Roll binaries back first. Customer records/audit cannot be reconstructed.
-- Fail closed once the feature has meaningful data; prefer leaving additive tables.
BEGIN;
LOCK TABLE tenant_uploaded_certificates, tenant_uploaded_certificate_audit IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM tenant_uploaded_certificates)
       OR EXISTS (SELECT 1 FROM tenant_uploaded_certificate_audit) THEN
        RAISE EXCEPTION 'cannot roll back 0223: customer certificate metadata or audit exists';
    END IF;
END $$;
DROP TABLE tenant_uploaded_certificate_audit;
DROP TABLE tenant_uploaded_certificates;
DELETE FROM schema_migrations WHERE version = '0223_manual_certificate_expiry';
COMMIT;
