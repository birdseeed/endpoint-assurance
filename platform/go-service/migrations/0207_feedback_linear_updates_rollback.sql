BEGIN;
-- Binary rollback needs no DDL: 0207 is expand-compatible and PAT-2035 ignores
-- these columns and tables. Schema rollback is intentionally refused once any
-- webhook, transition or email evidence exists because dropping it would hide
-- customer-visible history or an unresolved delivery obligation.
DO $$
DECLARE retained BOOLEAN;
BEGIN
  LOCK TABLE feedback IN ACCESS EXCLUSIVE MODE;
  SELECT EXISTS (SELECT 1 FROM feedback_linear_webhook_deliveries)
      OR EXISTS (SELECT 1 FROM feedback_status_audit)
      OR EXISTS (SELECT 1 FROM feedback_status_email_outbox)
      OR EXISTS (SELECT 1 FROM feedback_status_email_attempts)
    INTO retained;
  IF retained THEN
    RAISE EXCEPTION 'Refusing 0207 rollback: retain webhook, transition and email delivery evidence; freeze with FEEDBACK_ENABLED=false and unsubscribe the Linear webhook instead';
  END IF;
END $$;

DROP TABLE feedback_status_email_attempts;
DROP TABLE feedback_status_email_outbox;
DROP TRIGGER feedback_status_audit_no_change ON feedback_status_audit;
DROP FUNCTION feedback_status_audit_append_only();
DROP TABLE feedback_status_audit;
DROP TABLE feedback_linear_webhook_deliveries;
DROP INDEX feedback_reconcile_due;
DROP INDEX feedback_linear_issue_unique;
ALTER TABLE feedback
  DROP COLUMN reconcile_last_error,
  DROP COLUMN next_reconcile_at,
  DROP COLUMN reconcile_attempts,
  DROP COLUMN linear_checked_at,
  DROP COLUMN linear_updated_at;
DELETE FROM schema_migrations WHERE version='0207_feedback_linear_updates';
COMMIT;
