-- patched.im — rollback for 0146_finding_dispositions.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_finding_dispositions_append_only_truncate ON finding_dispositions;
DROP TRIGGER IF EXISTS trg_finding_dispositions_append_only ON finding_dispositions;
DROP FUNCTION IF EXISTS reject_finding_dispositions_truncate();
DROP FUNCTION IF EXISTS guard_finding_dispositions_mutation();
DROP TABLE IF EXISTS finding_dispositions;

DELETE FROM schema_migrations WHERE version = '0146_finding_dispositions';

COMMIT;
