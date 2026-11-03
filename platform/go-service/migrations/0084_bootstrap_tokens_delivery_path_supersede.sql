-- patched.im - 0084_bootstrap_tokens_delivery_path_supersede.sql
-- PAT-836: scope invalidate-on-regenerate to the email-link delivery path only.
--
-- The agent-enrollment contract says minting a new enrolment token
-- invalidates a tenant's prior unconsumed token. The implementation never
-- did this — every mint just inserted a new bootstrap_tokens row. The
-- correct, decided scope (see internal/handlers/enrolment.go,
-- mintTenantEnrolmentToken) is narrower than "every mint invalidates":
--   - email-link (single link, one per tenant): minting a new token DOES
--     supersede the tenant's prior unconsumed email-link token(s).
--   - mdm (fleet enrolment, N devices enrolling concurrently): minting a
--     new token must NEVER touch any other outstanding mdm token.
-- bootstrap_tokens had no delivery_path column at all, so there was no way
-- to scope a supersede-scan to "prior tokens of the SAME delivery path."
-- delivery_path already exists on enrollment_token_audit (0040), but that
-- insert is explicitly best-effort/non-fatal (an audit failure must never
-- block issuing a token — see the comment in mintTenantEnrolmentToken), so
-- an audit row can legitimately be missing even when the bootstrap_tokens
-- row exists. Joining through it to gate supersession would be unsafe.
--
-- Column defaults, deliberately kept (not dropped after backfill):
-- bootstrap_tokens has a SECOND, narrower mint path — trial.go's
-- mintEnrollmentToken (PAT-668 self-serve trial flow) — that INSERTs
-- directly into this table WITHOUT a delivery_path column, and is
-- deliberately untouched by this ticket (same as it was left untouched by
-- PAT-453 — see the doc comment on mintTenantEnrolmentToken). Dropping the
-- column default after backfill (the usual add-nullable/backfill/enforce
-- dance) would make every trial-provision INSERT start failing a NOT NULL
-- constraint. Keeping DEFAULT 'mdm' permanently means that insert keeps
-- working unmodified, and 'mdm' is also the semantically-correct label for
-- it: a trial-provision token is never subject to email-link supersede
-- semantics either way, since the supersede logic lives only in
-- mintTenantEnrolmentToken, which trial.go's helper never calls.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0084_bootstrap_tokens_delivery_path_supersede.sql
BEGIN;

-- DEPLOY ORDERING: additive columns + index, safe to apply anytime; nothing
-- existing depends on them. Ship the Go change (enrolment.go) in the same
-- release so supersede-on-remint is live as soon as the columns exist.

ALTER TABLE bootstrap_tokens
    ADD COLUMN IF NOT EXISTS delivery_path TEXT NOT NULL DEFAULT 'mdm'
        CHECK (delivery_path IN ('mdm', 'email-link'));

ALTER TABLE bootstrap_tokens
    ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ; -- NULL = not superseded

-- Best-effort backfill: recover the real delivery_path for historical rows
-- from enrollment_token_audit where a matching audit row happens to exist.
-- Every row this UPDATE doesn't touch keeps the 'mdm' default above, which
-- is also the correct value for every historical trial.go-minted row (that
-- path never had a delivery_path concept at all) and a safe, conservative
-- guess for any other unmatched row (unscoped/legacy admin mints defaulted
-- to "mdm" behaviourally, per MintBootstrapTokenHandler's `path` query
-- param default).
UPDATE bootstrap_tokens bt
SET delivery_path = eta.delivery_path
FROM enrollment_token_audit eta
WHERE eta.token_id = bt.id
  AND eta.delivery_path = 'email-link';

-- Supports the supersede-scan mintTenantEnrolmentToken runs on every
-- email-link mint (tenant_id + delivery_path = 'email-link' AND
-- consumed_at IS NULL AND superseded_at IS NULL) without a table scan.
-- Partial on the two NULL-state columns keeps the index tiny — consumed or
-- already-superseded rows (the overwhelming majority over time) are never
-- indexed at all.
CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_supersede_scan
    ON bootstrap_tokens (tenant_id, delivery_path)
    WHERE consumed_at IS NULL AND superseded_at IS NULL;

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0084_bootstrap_tokens_delivery_path_supersede')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
