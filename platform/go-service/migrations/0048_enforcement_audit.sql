-- PAT-603: enforcement audit log — stores events emitted by agents when they
-- remove an unauthorised local admin or block an unapproved app.

BEGIN;

CREATE TABLE enforcement_audit (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    device_id    TEXT        NOT NULL,
    event_type   TEXT        NOT NULL CHECK (event_type IN ('admin_removed','admin_removal_skipped','app_blocked','app_block_skipped')),
    subject      TEXT        NOT NULL,
    details      JSONB       NOT NULL DEFAULT '{}',
    occurred_at  TIMESTAMPTZ NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX enforcement_audit_tenant_time ON enforcement_audit (tenant_id, ingested_at DESC);
CREATE INDEX enforcement_audit_device ON enforcement_audit (tenant_id, device_id, ingested_at DESC);

-- The app connects as the unprivileged `patched` role; without this grant the
-- enforcement-audit endpoint 500s with "permission denied for table" (cf. PAT-579
-- for tenant_new_apps). Append-only audit log: SELECT (dashboard) + INSERT (agent
-- ingestion) only — no UPDATE/DELETE, to keep the trail tamper-evident.
GRANT SELECT, INSERT ON enforcement_audit TO patched;

INSERT INTO schema_migrations (version) VALUES ('0048_enforcement_audit');

COMMIT;
