-- patched.im - 0184_software_alert_lifecycle.sql
-- PAT-2097: a lifecycle for PAT-2009's unapproved software alerts, so they
-- are managed over time rather than lost in an inbox.
--
-- Granularity. 0183 stores an outbound alert (software_unapproved_alerts) as
-- either one 'marked' alert listing many devices or one 'observed' alert for
-- one device, and records every (episode, device) pair it covered in
-- software_unapproved_alerted_devices. The lifecycle lives on that ledger
-- row: one tracked alert per (unapproved episode, device), whichever
-- outbound alert first reported it. A marked alert on 40 devices is 40
-- tracked alerts, each acknowledged and resolved on its own evidence. The
-- 0183 'baseline' rows (a pair already present when 0183 ran, recorded with
-- no outbound alert) are tracked too: the software is still Unapproved and
-- present, it just was not announced.
--
-- Additive only. New columns on software_unapproved_alerted_devices, one new
-- append-only table, no existing column, constraint or row meaning changed.
--
--   status             open -> acknowledged -> resolved; resolved -> open
--                      again (re-open) when the product is observed on the
--                      device again while still Unapproved. Nothing closes
--                      on a timer.
--   resolved_reason    not_observed    an authoritative complete report
--                                      proved the product gone (PAT-2063,
--                                      PAT-2075, PAT-2055 authority rules)
--                      approved        the policy moved to approved (or
--                                      operator mandatory)
--                      ignored         the policy moved to ignored/unmanaged
--                      policy_removed  the policy row was deleted
--                      superseded      the alert no longer describes an
--                                      active case: the product is still
--                                      installed but another policy row (or
--                                      none) now governs it, or a newer
--                                      episode of the same policy replaced
--                                      this one (detail.evidence says which)
--   product            snapshot of the product the alert is about (the
--                      softwaregov.Product JSON); NULL for a baseline row
--                      until the device next reports it.
--
-- software_unapproved_alert_transitions is the append-only history: who
-- (actor_kind portal_user | operator | system, actor = the verified portal
-- email for portal_user), when, from, to, note, reason. Like 0182 it has no
-- foreign keys, so it survives a device or tenant purge, and UPDATE, DELETE
-- and TRUNCATE are rejected by trigger. That stops an accidental write; it
-- does not stop the owning role, which can disable the trigger. Do not
-- describe it as tamper-proof.
--
-- Backfill: every existing row starts 'open' with a system transition. Rows
-- of an episode that is not the latest for its policy are resolved as
-- superseded (detail.evidence 'superseded_episode'), leaving at most one
-- active alert per (policy, device). Rows whose policy is, at migration
-- time, no longer Unapproved are then resolved with the matching reason, exactly as the policy write paths now do in the
-- same transaction as the policy change. No row is resolved as not_observed
-- here: absence needs an authoritative report, which a migration does not
-- have.
--
-- Rollback: migrations/0184_software_alert_lifecycle_rollback.sql
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0184_software_alert_lifecycle.sql

BEGIN;

ALTER TABLE software_unapproved_alerted_devices
    ADD COLUMN id                    BIGSERIAL,
    ADD COLUMN status                TEXT        NOT NULL DEFAULT 'open',
    ADD COLUMN status_changed_at     TIMESTAMPTZ,
    ADD COLUMN acknowledged_at       TIMESTAMPTZ,
    ADD COLUMN acknowledged_by       TEXT,
    ADD COLUMN acknowledged_by_kind  TEXT,
    ADD COLUMN resolved_at           TIMESTAMPTZ,
    ADD COLUMN resolved_reason       TEXT,
    ADD COLUMN reopened_count        INT         NOT NULL DEFAULT 0,
    ADD COLUMN last_reopened_at      TIMESTAMPTZ,
    -- A re-open sends no immediate email or webhook; it is listed in the
    -- tenant's next daily unapproved software digest. True until then.
    ADD COLUMN reopen_digest_pending BOOLEAN     NOT NULL DEFAULT false,
    -- Retry state for a digest that carries only re-opens and failed to
    -- send transiently (the alert rows keep their own email_attempts).
    ADD COLUMN reopen_digest_attempts        INT         NOT NULL DEFAULT 0,
    ADD COLUMN reopen_digest_next_attempt_at TIMESTAMPTZ,
    ADD COLUMN product               JSONB;

UPDATE software_unapproved_alerted_devices SET status_changed_at = alerted_at;

ALTER TABLE software_unapproved_alerted_devices
    ALTER COLUMN status_changed_at SET DEFAULT now(),
    ALTER COLUMN status_changed_at SET NOT NULL,
    ADD CONSTRAINT software_unapproved_alerted_devices_id_key UNIQUE (id),
    ADD CONSTRAINT software_unapproved_alerted_devices_status_valid
        CHECK (status IN ('open', 'acknowledged', 'resolved')),
    ADD CONSTRAINT software_unapproved_alerted_devices_reason_valid
        CHECK (resolved_reason IS NULL OR resolved_reason IN ('not_observed', 'approved', 'ignored', 'policy_removed', 'superseded')),
    ADD CONSTRAINT software_unapproved_alerted_devices_resolved_shape
        CHECK ((status = 'resolved') = (resolved_at IS NOT NULL AND resolved_reason IS NOT NULL)
               AND (status = 'resolved' OR (resolved_at IS NULL AND resolved_reason IS NULL))),
    ADD CONSTRAINT software_unapproved_alerted_devices_ack_shape
        CHECK ((status <> 'acknowledged' OR acknowledged_at IS NOT NULL)
               AND ((acknowledged_at IS NULL) = (acknowledged_by_kind IS NULL))
               AND (acknowledged_by_kind IS NULL OR acknowledged_by_kind IN ('portal_user', 'operator'))
               AND ((acknowledged_by_kind = 'portal_user') = (acknowledged_by IS NOT NULL))
               AND (acknowledged_by IS NULL OR (acknowledged_by = lower(acknowledged_by)
                    AND btrim(acknowledged_by) <> '' AND length(acknowledged_by) <= 320))),
    ADD CONSTRAINT software_unapproved_alerted_devices_reopen_shape
        CHECK (reopened_count >= 0 AND (reopened_count = 0) = (last_reopened_at IS NULL) AND reopen_digest_attempts >= 0),
    ADD CONSTRAINT software_unapproved_alerted_devices_product_shape
        CHECK (product IS NULL OR jsonb_typeof(product) = 'object');

CREATE INDEX software_unapproved_alerted_devices_tenant_status_idx
    ON software_unapproved_alerted_devices (tenant_id, status, status_changed_at DESC);
CREATE INDEX software_unapproved_alerted_devices_device_idx
    ON software_unapproved_alerted_devices (device_id);
CREATE INDEX software_unapproved_alerted_devices_active_idx
    ON software_unapproved_alerted_devices (alerted_at)
    WHERE status IN ('open', 'acknowledged');
CREATE INDEX software_unapproved_alerted_devices_reopen_digest_idx
    ON software_unapproved_alerted_devices (tenant_id)
    WHERE reopen_digest_pending;

CREATE TABLE software_unapproved_alert_transitions (
    id               BIGSERIAL   PRIMARY KEY,
    tenant_id        UUID        NOT NULL,
    -- software_unapproved_alerted_devices.id, deliberately without a foreign
    -- key (a cascade would be a DELETE the append-only trigger rejects).
    alert_device_id  BIGINT      NOT NULL,
    episode_id       BIGINT      NOT NULL,
    device_id        UUID        NOT NULL,
    from_status      TEXT        CHECK (from_status IS NULL OR from_status IN ('open', 'acknowledged', 'resolved')),
    to_status        TEXT        NOT NULL CHECK (to_status IN ('open', 'acknowledged', 'resolved')),
    actor_kind       TEXT        NOT NULL CHECK (actor_kind IN ('portal_user', 'operator', 'system')),
    actor            TEXT,
    reason           TEXT        CHECK (reason IS NULL OR reason IN ('not_observed', 'approved', 'ignored', 'policy_removed', 'superseded')),
    note             TEXT        CHECK (note IS NULL OR (btrim(note) <> '' AND char_length(note) <= 1000)),
    -- Evidence behind a system transition, and for a re-open the product and
    -- device as observed, which the daily digest lists.
    detail           JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_status IS DISTINCT FROM to_status),
    CHECK ((to_status = 'resolved') = (reason IS NOT NULL)),
    CHECK ((actor_kind = 'portal_user') = (actor IS NOT NULL)),
    CHECK (actor IS NULL OR (actor = lower(actor) AND btrim(actor) <> '' AND length(actor) <= 320))
);

CREATE INDEX software_unapproved_alert_transitions_alert_idx
    ON software_unapproved_alert_transitions (alert_device_id, id);
CREATE INDEX software_unapproved_alert_transitions_tenant_idx
    ON software_unapproved_alert_transitions (tenant_id, created_at DESC);

CREATE FUNCTION reject_software_unapproved_alert_transitions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_unapproved_alert_transitions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_software_unapproved_alert_transitions_append_only
    BEFORE UPDATE OR DELETE ON software_unapproved_alert_transitions
    FOR EACH ROW
    EXECUTE FUNCTION reject_software_unapproved_alert_transitions_mutation();

CREATE FUNCTION reject_software_unapproved_alert_transitions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_unapproved_alert_transitions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_software_unapproved_alert_transitions_append_only_truncate
    BEFORE TRUNCATE ON software_unapproved_alert_transitions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_software_unapproved_alert_transitions_truncate();

COMMENT ON TABLE software_unapproved_alert_transitions IS
    'Append-only history of unapproved software alert status changes (PAT-2097). UPDATE, DELETE and TRUNCATE are rejected by trigger, including for the owning role; the owning role can still disable the trigger, so this is not tamper-proof. No foreign keys on purpose (survives device and tenant purge, 0182 pattern).';

-- BEGIN backfill (PAT-2097)
-- Product snapshot from the outbound alert that covered the pair: the
-- product whose listed devices include this device, else the first.
UPDATE software_unapproved_alerted_devices ad
SET product = (
    SELECT p.value - 'devices' - 'device_count'
    FROM software_unapproved_alerts a,
         jsonb_array_elements(COALESCE(a.payload->'products', '[]'::jsonb)) WITH ORDINALITY AS p(value, ord)
    WHERE a.id = ad.alert_id
    ORDER BY (EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(p.value->'devices', '[]'::jsonb)) d
                      WHERE d->>'device_id' = ad.device_id::text)) DESC, p.ord
    LIMIT 1)
WHERE ad.alert_id IS NOT NULL AND ad.product IS NULL;

-- Every existing row starts open.
INSERT INTO software_unapproved_alert_transitions
    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, detail, created_at)
SELECT ad.tenant_id, ad.id, ad.episode_id, ad.device_id, NULL, 'open', 'system',
       jsonb_build_object('source', 'migration_0184'), ad.alerted_at
FROM software_unapproved_alerted_devices ad;

-- Then one active alert per (policy, device): a row whose episode is not the
-- latest for its policy was replaced by a newer episode (the policy went
-- Unapproved, then something else, then Unapproved again before 0184). It
-- resolves as superseded, as OpenEpisodeTx now does going forward.
WITH stale AS (
    SELECT ad.id, ad.tenant_id, ad.episode_id, ad.device_id,
           (SELECT max(e2.id) FROM software_unapproved_episodes e2
            WHERE e2.tenant_id = e.tenant_id AND e2.policy_kind = e.policy_kind
              AND e2.policy_id = e.policy_id) AS latest
    FROM software_unapproved_alerted_devices ad
    JOIN software_unapproved_episodes e ON e.id = ad.episode_id
    WHERE ad.status = 'open'
), resolved AS (
    UPDATE software_unapproved_alerted_devices ad
    SET status = 'resolved', status_changed_at = now(), resolved_at = now(), resolved_reason = 'superseded'
    FROM stale s
    WHERE ad.id = s.id AND s.episode_id <> s.latest
    RETURNING ad.id, ad.tenant_id, ad.episode_id, ad.device_id, s.latest
)
INSERT INTO software_unapproved_alert_transitions
    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, reason, detail)
SELECT tenant_id, id, episode_id, device_id, 'open', 'resolved', 'system', 'superseded',
       jsonb_build_object('source', 'migration_0184', 'evidence', 'superseded_episode', 'episode_id', latest)
FROM resolved;

-- Then the policy rule: a row whose policy is no longer Unapproved resolves
-- with the reason the policy write paths use.
WITH current_policy AS (
    SELECT ad.id AS row_id, ad.tenant_id, ad.episode_id, ad.device_id,
           CASE e.policy_kind
               WHEN 'application' THEN (SELECT p.policy FROM tenant_app_policies p
                                        WHERE p.id = e.policy_id AND p.tenant_id = e.tenant_id)
               ELSE (SELECT p.policy FROM tenant_extension_policies p
                     WHERE p.id = e.policy_id AND p.tenant_id = e.tenant_id)
           END AS policy
    FROM software_unapproved_alerted_devices ad
    JOIN software_unapproved_episodes e ON e.id = ad.episode_id
    WHERE ad.status = 'open'
), decided AS (
    SELECT row_id, tenant_id, episode_id, device_id,
           CASE
               WHEN policy IS NULL THEN 'policy_removed'
               WHEN policy IN ('approved', 'mandatory') THEN 'approved'
               WHEN policy IN ('unmanaged', 'ignored') THEN 'ignored'
           END AS reason
    FROM current_policy
    WHERE policy IS DISTINCT FROM 'unapproved'
), resolved AS (
    UPDATE software_unapproved_alerted_devices ad
    SET status = 'resolved', status_changed_at = now(), resolved_at = now(), resolved_reason = d.reason
    FROM decided d
    WHERE ad.id = d.row_id AND d.reason IS NOT NULL
    RETURNING ad.id, ad.tenant_id, ad.episode_id, ad.device_id, ad.resolved_reason
)
INSERT INTO software_unapproved_alert_transitions
    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, reason, detail)
SELECT tenant_id, id, episode_id, device_id, 'open', 'resolved', 'system', resolved_reason,
       jsonb_build_object('source', 'migration_0184', 'evidence', 'policy_state')
FROM resolved;
-- END backfill (PAT-2097)

GRANT SELECT, INSERT ON TABLE software_unapproved_alert_transitions TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_unapproved_alert_transitions_id_seq TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_unapproved_alerted_devices_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0184_software_alert_lifecycle')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
