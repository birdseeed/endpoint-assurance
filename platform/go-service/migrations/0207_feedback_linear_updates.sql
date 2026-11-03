-- PAT-2036: authenticated Linear status updates, append-only transition
-- history and a retry-safe customer-email outbox. This migration is additive
-- so the PAT-2035 binary can run unchanged while the new binary is rolled out.
BEGIN;

ALTER TABLE feedback
  ADD COLUMN linear_updated_at TIMESTAMPTZ,
  ADD COLUMN linear_checked_at TIMESTAMPTZ,
  ADD COLUMN reconcile_attempts INTEGER NOT NULL DEFAULT 0 CHECK (reconcile_attempts >= 0),
  ADD COLUMN next_reconcile_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN reconcile_last_error TEXT;

CREATE UNIQUE INDEX feedback_linear_issue_unique
  ON feedback(linear_issue_id) WHERE linear_issue_id IS NOT NULL;
CREATE INDEX feedback_reconcile_due
  ON feedback(next_reconcile_at)
  WHERE linear_issue_id IS NOT NULL
    AND status NOT IN ('shipped','closed_not_planned','closed_merged');

CREATE TABLE feedback_linear_webhook_deliveries (
  delivery_id TEXT PRIMARY KEY CHECK (char_length(delivery_id) BETWEEN 1 AND 128),
  linear_issue_id TEXT NOT NULL CHECK (char_length(linear_issue_id) BETWEEN 1 AND 128),
  event_updated_at TIMESTAMPTZ NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('processing','transitioned','unchanged','stale','unknown_issue','unknown_state')),
  received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE feedback_status_audit (
  id BIGSERIAL PRIMARY KEY,
  -- Deliberately no FKs: like the existing append-only ledgers, this history
  -- must survive tenant/feedback deletion and must not block those deletions
  -- through its no-DELETE trigger.
  feedback_id BIGINT NOT NULL,
  tenant_id UUID NOT NULL,
  from_status TEXT NOT NULL CHECK (from_status IN ('received','planned','on_the_roadmap','in_progress','shipped','closed_not_planned','closed_merged')),
  to_status TEXT NOT NULL CHECK (to_status IN ('received','planned','on_the_roadmap','in_progress','shipped','closed_not_planned','closed_merged')),
  changed_at TIMESTAMPTZ NOT NULL,
  linear_state TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('webhook','reconcile')),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (from_status <> to_status)
);
CREATE INDEX feedback_status_audit_tenant_feedback
  ON feedback_status_audit(tenant_id,feedback_id,changed_at DESC);

CREATE TABLE feedback_status_email_outbox (
  id BIGSERIAL PRIMARY KEY,
  audit_id BIGINT NOT NULL UNIQUE REFERENCES feedback_status_audit(id) ON DELETE CASCADE,
  feedback_id BIGINT NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  recipient TEXT NOT NULL CHECK (char_length(recipient) BETWEEN 3 AND 320),
  feedback_reference TEXT NOT NULL,
  feedback_title TEXT NOT NULL,
  customer_status TEXT NOT NULL CHECK (customer_status IN ('shipped','closed_not_planned','closed_merged')),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sending','delivered','dead_letter','ambiguous')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 6),
  next_attempt_at TIMESTAMPTZ,
  lease_until TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  delivered_at TIMESTAMPTZ,
  CHECK ((state='pending' AND next_attempt_at IS NOT NULL AND lease_until IS NULL)
      OR (state='sending' AND next_attempt_at IS NULL AND lease_until IS NOT NULL)
      OR (state IN ('delivered','dead_letter','ambiguous') AND next_attempt_at IS NULL AND lease_until IS NULL))
);
CREATE INDEX feedback_status_email_due
  ON feedback_status_email_outbox(next_attempt_at)
  WHERE state='pending';
CREATE INDEX feedback_status_email_expired
  ON feedback_status_email_outbox(lease_until)
  WHERE state='sending';

CREATE TABLE feedback_status_email_attempts (
  id BIGSERIAL PRIMARY KEY,
  outbox_id BIGINT NOT NULL REFERENCES feedback_status_email_outbox(id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 6),
  started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ,
  outcome TEXT NOT NULL CHECK (outcome IN ('sending','delivered','retry','dead_letter','ambiguous')),
  error TEXT,
  UNIQUE(outbox_id,attempt_number)
);

CREATE FUNCTION feedback_status_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'feedback status audit is append-only';
END;
$$;
CREATE TRIGGER feedback_status_audit_no_change
  BEFORE UPDATE OR DELETE OR TRUNCATE ON feedback_status_audit
  FOR EACH STATEMENT EXECUTE FUNCTION feedback_status_audit_append_only();

GRANT SELECT, INSERT, UPDATE ON feedback_linear_webhook_deliveries TO patched;
GRANT SELECT, INSERT ON feedback_status_audit TO patched;
GRANT SELECT, INSERT, UPDATE ON feedback_status_email_outbox TO patched;
GRANT SELECT, INSERT, UPDATE ON feedback_status_email_attempts TO patched;
GRANT USAGE, SELECT ON SEQUENCE feedback_status_audit_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE feedback_status_email_outbox_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE feedback_status_email_attempts_id_seq TO patched;

INSERT INTO schema_migrations(version) VALUES ('0207_feedback_linear_updates') ON CONFLICT (version) DO NOTHING;
COMMIT;
