-- PAT-2347: split Feedback from Support. The feedback queue gains two types,
-- 'support' (something is wrong, or a question: the Support door) and
-- 'design' (design or usability: the Feedback door), plus a category that
-- only a support request carries.
--
-- Expand only. 'bug', 'feature' and 'question' stay valid so the PAT-2035
-- binary and a portal on either side of this rollout keep working; the
-- portal stops offering Bug and Question in its own change. No row is
-- rewritten: existing rows keep their type and get a NULL category.
--
-- The two type CHECKs are found by what they say, not by their generated
-- names (feedback_type_check, feedback_check). Production's schema has
-- drifted from the migration text before (PAT-2051), so a name that was
-- right on a scratch database is not proof it is right on the box.
BEGIN;

LOCK TABLE feedback IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE c RECORD; dropped INTEGER := 0;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
     WHERE conrelid = 'feedback'::regclass AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%''bug''%'
  LOOP
    EXECUTE format('ALTER TABLE feedback DROP CONSTRAINT %I', c.conname);
    dropped := dropped + 1;
  END LOOP;
  -- Exactly two exist today: the type list and the type/severity pairing.
  -- Any other count means the live table is not what 0206 says; stop rather
  -- than guess which rule to keep.
  IF dropped <> 2 THEN
    RAISE EXCEPTION '0222: expected 2 feedback type constraints, found %', dropped;
  END IF;
END $$;

ALTER TABLE feedback ADD COLUMN category TEXT;

ALTER TABLE feedback
  ADD CONSTRAINT feedback_type_values_check
    CHECK (type IN ('bug','feature','question','support','design')),
  ADD CONSTRAINT feedback_type_severity_check
    CHECK ((type = 'bug' AND severity IS NOT NULL)
        OR (type IN ('feature','question','support','design') AND severity IS NULL)),
  ADD CONSTRAINT feedback_category_values_check
    CHECK (category IS NULL OR category IN ('not_working','findings_or_reports','account_billing')),
  ADD CONSTRAINT feedback_type_category_check
    CHECK ((type = 'support' AND category IS NOT NULL)
        OR (type <> 'support' AND category IS NULL));

INSERT INTO schema_migrations (version) VALUES ('0222_feedback_support_design_types') ON CONFLICT (version) DO NOTHING;
COMMIT;
