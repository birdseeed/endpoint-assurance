-- Migration 0016: seen_nonces table for replay protection (PAT-338)
--
-- Stores nonces from inbound requests to detect replays. The unique constraint
-- on (tenant_id, nonce) makes the ON CONFLICT DO NOTHING insert in
-- auth.CheckAndStoreNonce the authoritative replay check. Rows are pruned to
-- the replay skew window (default ±300 s) on each insert, so the table stays
-- bounded.

BEGIN;

CREATE TABLE seen_nonces (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID        NOT NULL,
    nonce      TEXT        NOT NULL,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT seen_nonces_tenant_nonce_unique UNIQUE (tenant_id, nonce)
);

CREATE INDEX seen_nonces_seen_at_idx ON seen_nonces (seen_at);

INSERT INTO schema_migrations (version) VALUES ('0016');

COMMIT;
