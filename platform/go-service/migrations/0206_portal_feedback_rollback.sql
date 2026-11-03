BEGIN;
-- Block concurrent intake until the empty-table check and DROP have completed.
DO $$
DECLARE retained BOOLEAN;
BEGIN
 IF to_regclass('feedback') IS NOT NULL THEN
  EXECUTE 'LOCK TABLE feedback IN ACCESS EXCLUSIVE MODE';
  EXECUTE 'SELECT EXISTS (SELECT 1 FROM feedback)' INTO retained;
  IF retained THEN
   RAISE EXCEPTION 'Refusing feedback rollback: retained customer feedback must be preserved';
  END IF;
 END IF;
END $$;
DROP TABLE IF EXISTS feedback;
DELETE FROM schema_migrations WHERE version='0206_portal_feedback';
COMMIT;
