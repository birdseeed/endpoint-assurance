BEGIN;

-- ─── PAT-370: Report delivery infrastructure ──────────────────────────────────
--
-- Four tables:
--   delivery_contacts   — per-tenant address book (named email contacts)
--   report_schedules    — named, repeating report delivery schedules per tenant
--   report_records      — log of every generated report (ad-hoc + scheduled)
--   report_download_tokens — per-send, single-use 30-day download tokens
--                            for external (non-dashboard) recipients
--
-- R2 cold-storage: files older than 24 months should move to R2.
-- TODO: implement R2 cold-pull; for now report_records.archived=TRUE flags them.

-- ─── delivery_contacts ────────────────────────────────────────────────────────
CREATE TABLE delivery_contacts (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label       TEXT        NOT NULL,          -- display name, e.g. "Jane Smith (CSO)"
    email       TEXT        NOT NULL,
    note        TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_delivery_contacts_tenant ON delivery_contacts (tenant_id);

-- ─── report_schedules ─────────────────────────────────────────────────────────
-- cadence:        daily | weekly | monthly | quarterly | ad_hoc
-- cadence_config: JSONB — e.g. {"day_of_week": 1} (Monday=1), {"day_of_month": 1}
-- content_type:   full | cve_only | cis_only
-- recipient_ids:  JSONB array of delivery_contact UUIDs + user refs
--                 e.g. [{"type":"contact","id":"<uuid>"}, {"type":"user","email":"..."}]
-- ad_hoc_emails:  JSONB array of plain email strings (one-off sends)
CREATE TABLE report_schedules (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           TEXT        NOT NULL,
    cadence        TEXT        NOT NULL DEFAULT 'monthly'
                               CHECK (cadence IN ('daily','weekly','monthly','quarterly','ad_hoc')),
    cadence_config JSONB       NOT NULL DEFAULT '{}',
    content_type   TEXT        NOT NULL DEFAULT 'full'
                               CHECK (content_type IN ('full','cve_only','cis_only')),
    recipient_ids  JSONB       NOT NULL DEFAULT '[]',
    ad_hoc_emails  JSONB       NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_report_schedules_tenant ON report_schedules (tenant_id);

-- ─── report_records ───────────────────────────────────────────────────────────
-- schedule_id is NULL for ad-hoc generate-now runs.
-- pdf_path / xlsx_path: relative paths under the report storage root
--   (or R2 key when archived).
-- recipient_summary: JSONB snapshot of who received this delivery.
-- delivery_status: pending | sent | failed
-- archived: TRUE when cold-moved to R2 (content_path = R2 key).
--           TODO: implement R2 cold-pull; flag only for now.
CREATE TABLE report_records (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    schedule_id        UUID        REFERENCES report_schedules(id) ON DELETE SET NULL,
    name               TEXT        NOT NULL,
    generated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start       DATE,
    period_end         DATE,
    pdf_path           TEXT,
    xlsx_path          TEXT,
    recipient_summary  JSONB       NOT NULL DEFAULT '[]',
    delivery_status    TEXT        NOT NULL DEFAULT 'pending'
                                   CHECK (delivery_status IN ('pending','sent','failed')),
    archived           BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_report_records_tenant          ON report_records (tenant_id, created_at DESC);
CREATE INDEX idx_report_records_schedule        ON report_records (schedule_id);
CREATE INDEX idx_report_records_delivery_status ON report_records (delivery_status);

-- ─── report_download_tokens ───────────────────────────────────────────────────
-- One token per (report_record, recipient send).  Single-use: used_at set on
-- first redemption, any subsequent attempt returns 410 Gone.  Expire after 30 days.
CREATE TABLE report_download_tokens (
    id               BIGSERIAL   PRIMARY KEY,
    report_record_id UUID        NOT NULL REFERENCES report_records(id) ON DELETE CASCADE,
    email            TEXT        NOT NULL,
    token            UUID        NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
    used_at          TIMESTAMPTZ,              -- NULL = not yet redeemed
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rdt_token           ON report_download_tokens (token);
CREATE INDEX idx_rdt_report_record   ON report_download_tokens (report_record_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON delivery_contacts        TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON report_schedules         TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON report_records           TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON report_download_tokens   TO patched;
GRANT USAGE, SELECT ON SEQUENCE report_download_tokens_id_seq   TO patched;

INSERT INTO schema_migrations (version) VALUES ('0052_report_delivery');

COMMIT;
