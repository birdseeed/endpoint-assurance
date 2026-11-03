-- patched.im — 0157_notification_channels.sql
-- PAT-1888: tenant-owned notification channels for finding, stale-evidence and
-- verification events.
--
-- Additive only. The PAT-134 tables (tenant_webhooks, webhook_deliveries) are
-- untouched and keep serving their own v1 event types; nothing here migrates or
-- drops them. Rollback for a single tenant is `enabled = false` on the channel
-- row, which retains the audit trail and the retry state.
--
-- Apply with: psql -h patched-api-01 -U patched -d patched -f migrations/0157_notification_channels.sql

BEGIN;

-- One configured destination for one tenant. channel_type decides which of the
-- destination columns carry meaning, enforced by the CHECK below rather than by
-- application code alone.
--
--   webhook: destination_url + secret, recipients empty
--   email:   recipients, no destination_url and no secret
--
-- secret holds the envelope-encrypted (penc1:) HMAC secret. The plaintext is
-- returned exactly once, in the create response, and is never readable again
-- through any API surface.
CREATE TABLE notification_channels (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_type    TEXT        NOT NULL CHECK (channel_type IN ('webhook', 'email')),
    name            TEXT        NOT NULL CHECK (btrim(name) <> ''),
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    events          TEXT[]      NOT NULL DEFAULT '{}',
    min_severity    TEXT        NOT NULL DEFAULT 'low'
                                CHECK (min_severity IN ('low', 'medium', 'high', 'critical')),
    destination_url TEXT,
    secret          TEXT,
    recipients      TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT notification_channels_shape CHECK (
        (channel_type = 'webhook'
             AND destination_url IS NOT NULL
             AND secret IS NOT NULL
             AND cardinality(recipients) = 0)
        OR
        (channel_type = 'email'
             AND destination_url IS NULL
             AND secret IS NULL
             AND cardinality(recipients) > 0)
    )
);

CREATE INDEX notification_channels_tenant_idx ON notification_channels(tenant_id);

-- One delivery per (channel, event occurrence). state is the whole lifecycle:
--
--   pending     awaiting a first attempt or a scheduled retry (next_attempt_at set)
--   delivered   accepted by the destination (succeeded_at set)
--   dead_letter terminal failure; failure_reason says which kind
--
-- tenant_id is denormalised from the channel so a tenant-wide dead-letter
-- listing never has to trust a join for its isolation boundary.
--
-- last_error is a truncated, redacted transport error. Never a secret, never a
-- response body.
CREATE TABLE notification_deliveries (
    id              BIGSERIAL   PRIMARY KEY,
    channel_id      UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    subject         TEXT        NOT NULL,
    idempotency_key TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    state           TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (state IN ('pending', 'delivered', 'dead_letter')),
    failure_reason  TEXT,
    response_status INT,
    attempt_count   INT         NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    succeeded_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The idempotency boundary: one row per (channel, event occurrence), so a
-- replayed trigger conflicts instead of sending a second copy.
CREATE UNIQUE INDEX notification_deliveries_idempotency_idx
    ON notification_deliveries(channel_id, idempotency_key);

CREATE INDEX notification_deliveries_channel_idx
    ON notification_deliveries(channel_id, created_at DESC);

-- Partial index for the delivery sweeper: only rows actually due.
CREATE INDEX notification_deliveries_pending_idx
    ON notification_deliveries(next_attempt_at)
    WHERE state = 'pending' AND next_attempt_at IS NOT NULL;

-- Partial index for the tenant-wide dead-letter listing.
CREATE INDEX notification_deliveries_dead_letter_idx
    ON notification_deliveries(tenant_id, created_at DESC)
    WHERE state = 'dead_letter';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE notification_channels TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE notification_deliveries TO patched;
GRANT USAGE, SELECT ON SEQUENCE notification_deliveries_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0157_notification_channels')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
