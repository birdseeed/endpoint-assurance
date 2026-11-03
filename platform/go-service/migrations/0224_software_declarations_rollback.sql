-- Roll the binaries back first: every policy resolver reads
-- effective_tenant_app_policies. Declarations and their decision history
-- cannot be reconstructed, so this fails closed once either holds a row;
-- prefer leaving the additive objects in place.
BEGIN;
LOCK TABLE tenant_software_declarations, software_declaration_decisions IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM tenant_software_declarations)
       OR EXISTS (SELECT 1 FROM software_declaration_decisions) THEN
        RAISE EXCEPTION 'cannot roll back 0224: software declarations or their decision history exist';
    END IF;
END $$;
DROP FUNCTION effective_tenant_app_policies(UUID);
DROP TABLE software_declaration_decisions;
DROP FUNCTION reject_software_declaration_decision_mutation();
DROP TABLE tenant_software_declarations;
DELETE FROM schema_migrations WHERE version = '0224_software_declarations';
COMMIT;
