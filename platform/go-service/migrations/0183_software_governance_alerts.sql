-- patched.im - 0183_software_governance_alerts.sql
-- PAT-2009: software governance reporting and customer notifications.
--
-- Additive apart from the report type constraints described below: no
-- existing column, index, row or trigger is changed. The existing tables this
-- feature reads or writes are:
--
--   tenants (0001, contact_email from 0049)      read
--   devices, device_apps (0001)                   read
--   device_browser_extensions (0018)              read
--   tenant_app_policies (0032)                    read
--   tenant_extension_policies (0071)              read
--   tenant_webhooks, webhook_deliveries (0055)    read / INSERT only
--   software_installations (0111)                 read
--   software_approval_decisions (0182)            read
--   notification_channels / _deliveries (0157)    through internal/notifications
--
-- New foreign keys reference tenants(id) and devices(id) only, the same way
-- 0157 and 0180 already do on patched-api-01.
--
-- One change to existing tables: the report type CHECK constraints from 0148
-- are widened with the three PAT-2009 report types, so the new reports can be
-- issued (report_records, created in 0052) and scheduled
-- (portal_report_schedules, 0061). Both constraints were created by 0148,
-- above the MIGRATION_FLOOR drift boundary, and are replaced whole here with
-- the 0148 list plus the new types.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0183_software_governance_alerts.sql

BEGIN;

-- Per-tenant settings. No row means the defaults: the unapproved software
-- alert is ON, the new software notification is OFF. The digest and window
-- cursors live here too, written only by the background runner.
CREATE TABLE tenant_software_notification_settings (
    tenant_id                      UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    unapproved_alerts_enabled      BOOLEAN     NOT NULL DEFAULT true,
    new_software_enabled           BOOLEAN     NOT NULL DEFAULT false,
    updated_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The verified portal email for a portal write, 'operator' for the admin
    -- API, NULL for a row the runner created to hold its cursors.
    updated_by                     TEXT        CHECK (updated_by IS NULL OR (btrim(updated_by) <> '' AND length(updated_by) <= 320)),
    -- End of the last daily digest slot for which the unapproved software
    -- digest email was sent.
    unapproved_digest_sent_at      TIMESTAMPTZ,
    -- End of the last window the new software notification covered. The next
    -- window starts here, so no product first seen is skipped or repeated.
    new_software_notified_through  TIMESTAMPTZ
);

-- One unapproved episode per transition of one policy row into 'unapproved'.
-- An episode is the dedupe scope for device alerts: a device is alerted at
-- most once per episode, however often it reports. A later transition into
-- 'unapproved' (after the product was approved, ignored or unreviewed in
-- between) opens a new episode, so its devices are alerted again.
--
--   source 'portal'    a customer admin marked it (marked_by is their email)
--   source 'operator'  the operator admin API set it (marked_by NULL)
--   source 'observed'  no recorded transition: the policy was already
--                      unapproved when first seen by this feature, or was set
--                      by a path that does not open episodes. marked_at is
--                      the policy row's updated_at, the best evidence held.
--   source 'baseline'  seeded by this migration for a policy already
--                      unapproved when it ran (see the baseline seed below).
CREATE TABLE software_unapproved_episodes (
    id           BIGSERIAL   PRIMARY KEY,
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_kind  TEXT        NOT NULL CHECK (policy_kind IN ('application', 'browser_extension')),
    policy_id    BIGINT      NOT NULL,
    source       TEXT        NOT NULL CHECK (source IN ('portal', 'operator', 'observed', 'baseline')),
    marked_by    TEXT        CHECK (marked_by IS NULL OR (marked_by = lower(marked_by) AND btrim(marked_by) <> '')),
    marked_at    TIMESTAMPTZ NOT NULL,
    -- One policy write request (a portal PUT or an operator call) shares one
    -- batch_id across the episodes it opens, so their alerts share one email.
    batch_id     UUID,
    -- NULL until the marked alert for a portal or operator episode has been
    -- raised (or deliberately not raised: not installed, alerts off). The
    -- episode row is written inside the policy-write transaction, the raise
    -- after the commit; the runner raises any episode still NULL, so a failed
    -- post-commit raise delays the alert rather than losing it.
    raised_at    TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (source = 'portal' OR marked_by IS NULL)
);

CREATE INDEX software_unapproved_episodes_policy_idx
    ON software_unapproved_episodes (tenant_id, policy_kind, policy_id, id DESC);
CREATE INDEX software_unapproved_episodes_unraised_idx
    ON software_unapproved_episodes (created_at)
    WHERE raised_at IS NULL AND source IN ('portal', 'operator');

-- One outbound alert. trigger 'marked' is the admin action (one per episode,
-- listing every device the product was on at the time); trigger 'observed'
-- is one newly observed device. payload is the event data exactly as it was
-- given to the webhook outbox, so the email and the webhook describe the
-- same thing.
--
-- email_state:
--   pending       awaiting its email (immediately for 'marked', in the daily
--                 digest for 'observed')
--   sent          included in an email Graph accepted
--   dead_letter   the email failed permanently or ran out of attempts
--   no_recipient  the tenant has no usable contact email; the webhook still
--                 went out
CREATE TABLE software_unapproved_alerts (
    id                     BIGSERIAL   PRIMARY KEY,
    tenant_id              UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    episode_id             BIGINT      NOT NULL REFERENCES software_unapproved_episodes(id) ON DELETE CASCADE,
    trigger                TEXT        NOT NULL CHECK (trigger IN ('marked', 'observed')),
    device_id              UUID        REFERENCES devices(id) ON DELETE CASCADE,
    payload                JSONB       NOT NULL,
    webhook_deliveries     INT         NOT NULL DEFAULT 0 CHECK (webhook_deliveries >= 0),
    email_state            TEXT        NOT NULL DEFAULT 'pending'
                                       CHECK (email_state IN ('pending', 'sent', 'dead_letter', 'no_recipient')),
    email_attempts         INT         NOT NULL DEFAULT 0 CHECK (email_attempts >= 0),
    email_next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    email_last_error       TEXT        CHECK (email_last_error IS NULL OR length(email_last_error) <= 400),
    email_sent_at          TIMESTAMPTZ,
    -- Marked alerts from one policy-write request share this id and one
    -- email. Webhooks stay one per product.
    email_batch_id         UUID,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((trigger = 'marked' AND device_id IS NULL) OR (trigger = 'observed' AND device_id IS NOT NULL))
);

CREATE UNIQUE INDEX software_unapproved_alerts_marked_uq
    ON software_unapproved_alerts (episode_id) WHERE trigger = 'marked';
CREATE UNIQUE INDEX software_unapproved_alerts_observed_uq
    ON software_unapproved_alerts (episode_id, device_id) WHERE trigger = 'observed';
CREATE INDEX software_unapproved_alerts_tenant_idx
    ON software_unapproved_alerts (tenant_id, created_at DESC);
CREATE INDEX software_unapproved_alerts_email_pending_idx
    ON software_unapproved_alerts (email_next_attempt_at)
    WHERE email_state = 'pending';

-- The dedupe ledger: every (episode, device) pair already covered by an
-- alert, whether by the admin action's alert or by its own observed alert.
-- Ingest alerts only for a pair with no row here. A suppressed_baseline row
-- has no alert: the pair was present when this migration ran and was
-- recorded as already known, so deploying sends nothing about it.
CREATE TABLE software_unapproved_alerted_devices (
    episode_id           BIGINT      NOT NULL REFERENCES software_unapproved_episodes(id) ON DELETE CASCADE,
    device_id            UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id            UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id             BIGINT      REFERENCES software_unapproved_alerts(id) ON DELETE CASCADE,
    suppressed_baseline  BOOLEAN     NOT NULL DEFAULT false,
    alerted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (episode_id, device_id),
    CHECK ((alert_id IS NOT NULL) <> suppressed_baseline)
);

CREATE INDEX software_unapproved_alerted_devices_alert_idx
    ON software_unapproved_alerted_devices (alert_id);

-- Weekly governance counts, recorded going forward by the runner (the last
-- capture in a week wins). The drift trend reads this rather than
-- re-classifying old installations under today's policy, which would rewrite
-- history every time a product is approved. Weeks before the first capture
-- are reported as not recorded, never as zero.
CREATE TABLE software_governance_weekly (
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    week_start            DATE        NOT NULL,
    installed_products    INT         NOT NULL CHECK (installed_products >= 0),
    unapproved_products   INT         NOT NULL CHECK (unapproved_products >= 0),
    unreviewed_products   INT         NOT NULL CHECK (unreviewed_products >= 0),
    unapproved_devices    INT         NOT NULL CHECK (unapproved_devices >= 0),
    devices_total         INT         NOT NULL CHECK (devices_total >= 0),
    devices_stale         INT         NOT NULL CHECK (devices_stale >= 0),
    captured_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, week_start),
    CHECK (extract(isodow FROM week_start) = 1)
);

ALTER TABLE report_records
    DROP CONSTRAINT IF EXISTS report_records_report_type_valid;
ALTER TABLE report_records
    ADD CONSTRAINT report_records_report_type_valid CHECK (report_type IN (
        'executive-summary', 'cis-compliance', 'cve-report', 'patch-status',
        'stale-endpoints', 'cert-expiry', 'software-inventory',
        'app-policy-drift', 'browser-extensions', 'edr-coverage',
        'device-health', 'encryption-posture', 'local-admin',
        'device-compliance',
        'new-software', 'software-drift', 'approved-software'
    ));

ALTER TABLE portal_report_schedules
    DROP CONSTRAINT IF EXISTS portal_report_schedules_report_type_valid;
ALTER TABLE portal_report_schedules
    ADD CONSTRAINT portal_report_schedules_report_type_valid CHECK (report_type IN (
        'executive-summary', 'cis-compliance', 'cve-report', 'patch-status',
        'stale-endpoints', 'cert-expiry', 'edr-coverage',
        'encryption-posture', 'local-admin',
        'new-software', 'software-drift', 'approved-software'
    ));

-- BEGIN baseline seed (PAT-2009)
-- No alert burst on deploy. Every policy that is Unapproved when this runs
-- gets a 'baseline' episode, and every device that currently has a matching
-- product is recorded in the ledger as suppressed_baseline, with no alert,
-- no webhook and no email. After deploy only a new (product, device) pair or
-- a new Unapproved marking alerts.
--
-- The match here is deliberately wider than the runtime resolver
-- (apppolicy.Resolve needs every identity field of a policy to match; this
-- takes any one, case-insensitively, on any platform). A pair the resolver
-- would not tie to the policy never alerts for it anyway, so over-matching
-- only suppresses pairs that could not alert, while under-matching would let
-- a pre-existing pair alert. Trimming matches Go's strings.TrimSpace
-- (unicode.IsSpace: ASCII whitespace, NEL, NBSP and the Unicode space
-- separators), which is what the runtime resolver applies; btrim alone strips
-- only spaces. Idempotent: a policy that already has an episode is skipped.
WITH pol AS (
    SELECT id, tenant_id, team_id, bundle_id, winget_id, name, updated_at
    FROM tenant_app_policies
    WHERE policy = 'unapproved'
), ep AS (
    INSERT INTO software_unapproved_episodes (tenant_id, policy_kind, policy_id, source, marked_at)
    SELECT p.tenant_id, 'application', p.id, 'baseline', p.updated_at
    FROM pol p
    WHERE NOT EXISTS (SELECT 1 FROM software_unapproved_episodes e
                      WHERE e.tenant_id = p.tenant_id AND e.policy_kind = 'application' AND e.policy_id = p.id)
    RETURNING id, tenant_id, policy_id
)
INSERT INTO software_unapproved_alerted_devices (episode_id, device_id, tenant_id, suppressed_baseline)
SELECT DISTINCT ep.id, d.id, d.tenant_id, true
FROM ep
JOIN pol p ON p.id = ep.policy_id
JOIN devices d ON d.tenant_id = p.tenant_id
JOIN device_apps da ON da.device_id = d.id AND (
       (p.bundle_id IS NOT NULL AND lower(regexp_replace(da.identifier, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g')) = lower(regexp_replace(p.bundle_id, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g')))
    OR (p.winget_id IS NOT NULL AND lower(regexp_replace(da.identifier, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g')) = lower(regexp_replace(p.winget_id, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g')))
    OR (p.team_id   IS NOT NULL AND lower(regexp_replace(da.team_id, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g'))    = lower(regexp_replace(p.team_id, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g')))
    OR (p.name      IS NOT NULL AND lower(regexp_replace(da.name, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g'))       = lower(regexp_replace(p.name, '^[\t\n\v\f\r \u0085   -     　]+|[\t\n\v\f\r \u0085   -     　]+$', '', 'g'))))
ON CONFLICT (episode_id, device_id) DO NOTHING;

WITH pol AS (
    SELECT id, tenant_id, browser, extension_id, updated_at
    FROM tenant_extension_policies
    WHERE policy = 'unapproved'
), ep AS (
    INSERT INTO software_unapproved_episodes (tenant_id, policy_kind, policy_id, source, marked_at)
    SELECT p.tenant_id, 'browser_extension', p.id, 'baseline', p.updated_at
    FROM pol p
    WHERE NOT EXISTS (SELECT 1 FROM software_unapproved_episodes e
                      WHERE e.tenant_id = p.tenant_id AND e.policy_kind = 'browser_extension' AND e.policy_id = p.id)
    RETURNING id, tenant_id, policy_id
)
INSERT INTO software_unapproved_alerted_devices (episode_id, device_id, tenant_id, suppressed_baseline)
SELECT DISTINCT ep.id, d.id, d.tenant_id, true
FROM ep
JOIN pol p ON p.id = ep.policy_id
JOIN devices d ON d.tenant_id = p.tenant_id
JOIN device_browser_extensions dbe ON dbe.device_id = d.id
     AND dbe.extension_id = p.extension_id
     AND (p.browser = 'any' OR dbe.browser = p.browser)
ON CONFLICT (episode_id, device_id) DO NOTHING;
-- END baseline seed (PAT-2009)

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_software_notification_settings TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_episodes TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_alerts TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_unapproved_alerted_devices TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE software_governance_weekly TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_unapproved_episodes_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_unapproved_alerts_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0183_software_governance_alerts')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
