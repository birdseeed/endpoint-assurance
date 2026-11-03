-- 0176: audit ledger for the Homebrew CPE review queue admin API (PAT-2046)
--
-- PAT-2023 (0168) added homebrew_cpe_review_queue and the Homebrew
-- source_type/review_state columns on app_cpe_mappings, but nothing yet let
-- staff work the queue. This migration adds only the audit ledger the new
-- admin API writes to (GET/POST /admin/homebrew/review/*,
-- internal/homebrewreview): the queue and mapping tables it reads and writes
-- already exist and already carry the grants they need (0168).
--
-- Same append-only shape as software_category_audit (0163, PAT-2015): one
-- row per map/accept_suggestion/dismiss action, who, when, before and after.
-- Same known limitation, not restated in full here: the reject triggers stop
-- an accidental UPDATE/DELETE/TRUNCATE, not the owning role (`patched`,
-- which runs migrations and the app) -- see AGENTS.md and 0163's comment.
BEGIN;

CREATE TABLE homebrew_review_audit (
    id            BIGSERIAL PRIMARY KEY,
    review_id     BIGINT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('map', 'accept_suggestion', 'dismiss')),
    actor         TEXT NOT NULL,
    claimed_actor TEXT,
    source_addr   TEXT,
    before        JSONB,
    after         JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX homebrew_review_audit_review_idx
    ON homebrew_review_audit (review_id, at);

CREATE FUNCTION reject_homebrew_review_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'homebrew_review_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_homebrew_review_audit_reject_update
    BEFORE UPDATE OR DELETE ON homebrew_review_audit
    FOR EACH ROW EXECUTE FUNCTION reject_homebrew_review_audit_mutation();
CREATE TRIGGER trg_homebrew_review_audit_reject_truncate
    BEFORE TRUNCATE ON homebrew_review_audit
    FOR EACH STATEMENT EXECUTE FUNCTION reject_homebrew_review_audit_mutation();

COMMENT ON TABLE homebrew_review_audit IS
    'PAT-2046: append-only who/when/before/after audit of every Homebrew CPE review queue action (map, accept_suggestion, dismiss).';

GRANT SELECT, INSERT ON homebrew_review_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE homebrew_review_audit_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0176_homebrew_review_admin')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
