-- patched.im — 0031_device_report_digests.sql
-- PAT-473: per-device report digest store for audit-trail evidence.
--
-- When a per-device compliance PDF is generated the handler computes its
-- SHA-256 digest and inserts a row here. The posture endpoint's evidence block
-- reads the most recent digest for the device (type = 'compliance') and
-- exposes it as last_signed_report_digest — allowing an agent or auditor to
-- verify the report has not been tampered with post-generation.
--
-- report_type is an enum over currently-supported report formats:
--   compliance  — per-device CIS L1 compliance PDF
--   executive   — tenant-level executive summary PDF
--   cve         — free CVE vulnerability assessment PDF
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0031_device_report_digests.sql

BEGIN;

CREATE TABLE device_report_digests (
    id           BIGSERIAL    PRIMARY KEY,
    device_id    UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    report_type  TEXT         NOT NULL DEFAULT 'compliance'
                                  CHECK (report_type IN ('compliance', 'executive', 'cve')),
    sha256       TEXT         NOT NULL,
    generated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Latest-digest-per-device lookup used by posture evidence.
CREATE INDEX device_report_digests_device_time_idx
    ON device_report_digests (device_id, generated_at DESC);

-- ============================================================================
-- BOOKKEEPING

INSERT INTO schema_migrations (version) VALUES ('0031_device_report_digests');

COMMIT;
