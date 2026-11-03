-- 0217: revoke an unused enrolment (bootstrap) token through the admin API (PAT-2287).
--
-- Until now a minted token's only exits were being consumed by POST /v1/enrol,
-- being superseded by a newer email-link mint (0084), or reaching its 24-hour
-- expiry. A token minted for a machine that then cannot be reached, or one
-- pasted somewhere it should not be, stayed live for up to a day, and the only
-- way to kill it sooner was a hand write to the production database.
--
-- bootstrap_tokens.revoked_at: set once by
-- POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke and never
-- cleared. /v1/enrol's consume UPDATE requires it to be NULL, and a revoked
-- token is refused with the same 410 response as an expired one so the reason
-- is not disclosed to whoever holds it.
--
-- enrollment_token_audit.action: the table has recorded mints only since 0040,
-- so every existing row is a mint and the default keeps both mint writers
-- (mintTenantEnrolmentToken, and anything else inserting without the column)
-- unchanged. A revoke writes its own row with action 'revoke'.
--
-- enrollment_token_audit.actor: the principal the server can vouch for on a
-- revoke. /admin/* authenticates with the one shared ADMIN_API_TOKEN, so this
-- is always 'admin_shared_token' (PAT-1135, internal/handlers/
-- audit_attribution.go), never a caller-supplied name. It is a constant, not
-- an identifier, so tenant-purge anonymisation (0101/0109) has nothing new to
-- redact. NULL on mint rows, which keep using actor_email (0077).
--
-- Additive and defensive: bootstrap_tokens (0036) and enrollment_token_audit
-- (0040) predate MIGRATION_FLOOR, so every ADD is IF NOT EXISTS and the
-- constraints are named and dropped before being (re)added. ADD COLUMN with a
-- constant default does not rewrite the table and fires no row trigger, so the
-- append-only guard on enrollment_token_audit (0101) is not engaged.
BEGIN;

ALTER TABLE bootstrap_tokens
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ; -- NULL = not revoked

ALTER TABLE enrollment_token_audit
    ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'mint';

ALTER TABLE enrollment_token_audit
    ADD COLUMN IF NOT EXISTS actor TEXT;

ALTER TABLE enrollment_token_audit
    DROP CONSTRAINT IF EXISTS enrollment_token_audit_action_check;
ALTER TABLE enrollment_token_audit
    ADD CONSTRAINT enrollment_token_audit_action_check
        CHECK (action IN ('mint', 'revoke'));

-- A revoke row must say who did it. Purge anonymisation never touches actor,
-- so this holds for surviving rows too.
ALTER TABLE enrollment_token_audit
    DROP CONSTRAINT IF EXISTS enrollment_token_audit_revoke_actor_check;
ALTER TABLE enrollment_token_audit
    ADD CONSTRAINT enrollment_token_audit_revoke_actor_check
        CHECK (action <> 'revoke' OR actor IS NOT NULL);

COMMENT ON COLUMN bootstrap_tokens.revoked_at IS
    'PAT-2287: when an operator revoked this unconsumed token via POST /admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke. Set once, never cleared. /v1/enrol refuses a revoked token with the same 410 as an expired one. Who revoked it is in enrollment_token_audit (action = revoke).';
COMMENT ON COLUMN enrollment_token_audit.action IS
    'PAT-2287: mint (every row before 0217, and every mint since) or revoke. A revoke row copies the token''s delivery_path and expires_at; generated_at is the revoke time.';
COMMENT ON COLUMN enrollment_token_audit.actor IS
    'PAT-2287: authenticated principal for a revoke row, always admin_shared_token (PAT-1135: /admin/* has no per-person identity). NULL on mint rows, which carry actor_email (0077) instead.';

INSERT INTO schema_migrations (version) VALUES ('0217_bootstrap_token_revoke')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
