-- PAT-2404: staff review of an observed, signed software identity into a
-- reviewed catalogue alias, and its withdrawal.
--
-- Additive. One nullable column, one new table, and a narrowed replacement of
-- one function. No existing row is rewritten.
--
--   software_product_aliases.retired_at  NULL = live. Set when staff withdraw
--     a reviewed alias; cleared when the same identity is reviewed again. A
--     retired alias is kept: installations, observations and declarations
--     that already point at it keep their history. Catalogue-only change (no
--     default, no rewrite); ACCESS EXCLUSIVE on the alias table for
--     milliseconds. The 0111 UNIQUE on the identity tuple is untouched, so an
--     identity has one alias row for ever, live or retired.
--
--   software_catalogue_audit  one row per review and per retirement, written
--     in the transaction that makes the change, with the PAT-1135 actor split
--     (server-established actor, untrusted claimed_actor, source address).
--     No foreign key, as the other ledgers: nothing can cascade into it or be
--     blocked by it. UPDATE, DELETE and TRUNCATE are rejected by trigger. That
--     stops an accident. It does not stop the owning role, which runs both
--     the migrations and the application. Do not describe it as tamper-proof.
--
--   effective_tenant_app_policies  replaced. The 0224 body is kept byte for
--     byte and one more conjunct is appended: an approved policy row linked
--     to a declaration whose resolved alias is retired is not returned, on
--     either platform. The result is therefore always a subset of what the
--     0224 version returned for the same data: a conjunction can only remove
--     rows. The 0224 whitespace handling and identifier currency rules are
--     inside the unchanged part. The declaration, its policy row and every
--     decision ledger are left as they are; clearing retired_at restores the
--     row to the result.
--
-- Deploy before the binaries: the new binaries read retired_at. The old
-- binaries are unaffected by the column and by the narrower function.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0226_software_catalogue_review.sql
BEGIN;

ALTER TABLE software_product_aliases ADD COLUMN retired_at TIMESTAMPTZ;

CREATE TABLE software_catalogue_audit (
    id            BIGSERIAL PRIMARY KEY,
    action        TEXT NOT NULL CHECK (action IN ('review', 'retire')),
    alias_id      UUID NOT NULL,
    product_id    UUID NOT NULL,
    actor         TEXT NOT NULL CHECK (btrim(actor) <> ''),
    claimed_actor TEXT,
    source_addr   TEXT,
    reason        TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    before        JSONB,
    after         JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX software_catalogue_audit_alias_idx
    ON software_catalogue_audit (alias_id, id);

CREATE FUNCTION reject_software_catalogue_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_catalogue_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_software_catalogue_audit_reject_update
    BEFORE UPDATE OR DELETE ON software_catalogue_audit
    FOR EACH ROW EXECUTE FUNCTION reject_software_catalogue_audit_mutation();
CREATE TRIGGER trg_software_catalogue_audit_reject_truncate
    BEFORE TRUNCATE ON software_catalogue_audit
    FOR EACH STATEMENT EXECUTE FUNCTION reject_software_catalogue_audit_mutation();

CREATE OR REPLACE FUNCTION effective_tenant_app_policies(p_tenant UUID) RETURNS SETOF tenant_app_policies
LANGUAGE sql STABLE AS $fn$
SELECT p.* FROM tenant_app_policies p
WHERE p.tenant_id=p_tenant AND NOT EXISTS (
    SELECT 1 FROM tenant_software_declarations d
    WHERE d.policy_id=p.id AND d.tenant_id=p.tenant_id AND d.platform='windows'
      AND p.policy='approved'
      AND NOT COALESCE((
        p.platform=d.platform AND lower(btrim(p.bundle_id))=d.resolved_identifier
        AND d.resolved_publisher_key IS NOT NULL
        AND EXISTS (SELECT 1 FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id
            WHERE a.id=d.resolved_alias_id AND a.platform=d.platform
              AND a.identity_kind=d.resolved_kind AND a.identity_value_normalized=d.resolved_identifier
              AND a.companion_value_normalized=d.resolved_companion AND sp.lifecycle_state='active'
              AND a.match_confidence IN ('exact','high') AND a.provenance='reviewed')
        AND EXISTS (SELECT 1 FROM software_installations si
            LEFT JOIN software_observations o ON o.id=si.latest_observation_id AND o.tenant_id=si.tenant_id
            WHERE si.platform='windows' AND si.removed_at IS NULL
              AND (o.id IS NULL OR EXISTS (SELECT 1 FROM device_apps da
                  WHERE da.device_id=si.device_id AND da.identifier=o.observed_identifier))
              AND si.tenant_id=d.tenant_id AND si.identity_value_normalized=d.resolved_identifier)
        AND NOT EXISTS (
            SELECT 1 FROM software_installations si
            LEFT JOIN software_observations o ON o.id=si.latest_observation_id AND o.tenant_id=si.tenant_id
            WHERE si.platform='windows' AND si.removed_at IS NULL
              AND (o.id IS NULL OR EXISTS (SELECT 1 FROM device_apps da
                  WHERE da.device_id=si.device_id AND da.identifier=o.observed_identifier))
              AND si.tenant_id=d.tenant_id AND si.identity_value_normalized=d.resolved_identifier
              AND NOT COALESCE(
                si.alias_id=d.resolved_alias_id AND si.identity_kind=d.resolved_kind
                AND si.companion_value_normalized=d.resolved_companion
                AND si.resolution_confidence IN ('exact','high')
                AND o.observed_signature_state='valid'
                AND o.observed_authenticode_root_kind IN ('microsoft','public')
                AND o.observed_authenticode_root_thumbprint ~ '^[0-9a-f]{64}$'
                AND ('authenticode:' || o.observed_authenticode_root_thumbprint || ':' ||
                     btrim(regexp_replace(o.observed_authenticode_signer,
                         '[ \t\n\v\f\r\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+',' ','g'),' '))=d.resolved_publisher_key,
                FALSE)
        )
      ), FALSE)
)
AND NOT EXISTS (
    SELECT 1 FROM tenant_software_declarations d
    JOIN software_product_aliases a ON a.id=d.resolved_alias_id
    WHERE d.policy_id=p.id AND d.tenant_id=p.tenant_id
      AND p.policy='approved' AND a.retired_at IS NOT NULL
)
$fn$;

COMMENT ON COLUMN software_product_aliases.retired_at IS
    'PAT-2404. NULL = live. Set when staff withdraw a reviewed alias, cleared when the identity is reviewed again. A retired alias resolves nothing new and confers no declared approval; rows already pointing at it keep their history.';
COMMENT ON TABLE software_catalogue_audit IS
    'PAT-2404: append-only record of every staff review and retirement of a catalogue alias. actor is the server-established identity; claimed_actor is the caller''s untrusted claim.';
COMMENT ON FUNCTION effective_tenant_app_policies(UUID) IS 'tenant_app_policies minus Windows approvals linked to a declaration whose pinned identity and Authenticode publisher are not borne out by every current installation. Also minus approvals linked to a declaration whose resolved alias is retired.';

GRANT SELECT, INSERT ON software_catalogue_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_catalogue_audit_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0226_software_catalogue_review')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
