-- patched.im — 0055_tenant_webhooks.sql
-- PAT-134: Outbound webhooks for tenant integrations.
-- v1 event types: score.changed, vulnerability.discovered
-- Apply with: psql -h patched-api-01 -U patched -d patched -f migrations/0055_tenant_webhooks.sql

BEGIN;

-- Per-tenant webhook endpoint configurations.
-- secret is a 64-char hex string (32 random bytes); shown only at creation time.
-- events is a text array of subscribed event types (e.g. '{score.changed}').
CREATE TABLE tenant_webhooks (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url        TEXT        NOT NULL,
    secret     TEXT        NOT NULL,
    events     TEXT[]      NOT NULL DEFAULT '{}',
    enabled    BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tenant_webhooks_tenant_idx ON tenant_webhooks(tenant_id);

-- Delivery log + retry queue.
-- Rows are created when an event fires; next_attempt_at drives retry scheduling.
-- succeeded_at NULL + next_attempt_at NULL = terminal failure (gave up).
-- succeeded_at NOT NULL = delivered successfully.
CREATE TABLE webhook_deliveries (
    id              BIGSERIAL   PRIMARY KEY,
    webhook_id      UUID        NOT NULL REFERENCES tenant_webhooks(id) ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    response_status INT,
    attempt_count   INT         NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    succeeded_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webhook_deliveries_webhook_idx ON webhook_deliveries(webhook_id);
-- Partial index for the retry poller: only pending rows.
CREATE INDEX webhook_deliveries_pending_idx ON webhook_deliveries(next_attempt_at)
    WHERE succeeded_at IS NULL AND next_attempt_at IS NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0055_tenant_webhooks');

COMMIT;
