BEGIN;
-- Binary rollback needs no DDL: the PAT-2035 and PAT-2036 binaries never write
-- the new types or the category column, and they ignore both. Schema rollback
-- is refused once a support or design request exists, because narrowing the
-- type list would either fail or hide a customer's request. Freeze intake with
-- FEEDBACK_ENABLED=false and keep the schema instead.
DO $$
BEGIN
  LOCK TABLE feedback IN ACCESS EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM feedback WHERE type IN ('support','design') OR category IS NOT NULL) THEN
    RAISE EXCEPTION 'Refusing 0222 rollback: support or design feedback exists; freeze intake with FEEDBACK_ENABLED=false instead';
  END IF;
END $$;

ALTER TABLE feedback
  DROP CONSTRAINT feedback_type_category_check,
  DROP CONSTRAINT feedback_category_values_check,
  DROP CONSTRAINT feedback_type_severity_check,
  DROP CONSTRAINT feedback_type_values_check;
ALTER TABLE feedback DROP COLUMN category;
ALTER TABLE feedback
  ADD CONSTRAINT feedback_type_check CHECK (type IN ('bug','feature','question')),
  ADD CONSTRAINT feedback_check CHECK ((type = 'bug' AND severity IS NOT NULL) OR (type IN ('feature','question') AND severity IS NULL));
DELETE FROM schema_migrations WHERE version = '0222_feedback_support_design_types';
COMMIT;
