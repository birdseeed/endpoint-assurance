-- PAT-2393: tenant-owned intent before discovery. Purely additive: two new
-- tables and one read-only function. No existing table, observation, policy, signing
-- evidence or vulnerability finding is altered or rewritten.
--
-- tenant_software_declarations is what a tenant admin declared. It is not an
-- observation and not proof of installation, trust or compliance. It confers
-- nothing until a verified resolution links it (policy_id) to an ordinary row
-- in the existing policy store, tenant_app_policies.
--
-- software_declaration_decisions follows software_approval_decisions (0182):
-- no foreign key to tenants or to the declaration, because a cascading DELETE
-- would hit the append-only trigger and make tenant purge fail (0091/0096).
-- Rows therefore outlive the tenant, like the other decision ledgers. The
-- trigger stops an accidental write; it does not stop the owning role
-- `patched` (AGENTS.md). Do not describe this table as tamper-proof.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0224_software_declarations.sql
BEGIN;

CREATE TABLE tenant_software_declarations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 256),
    publisher TEXT NOT NULL CHECK (char_length(btrim(publisher)) BETWEEN 1 AND 256),
    platform TEXT NOT NULL CHECK (platform IN ('macos','windows')),
    justification TEXT NOT NULL CHECK (char_length(btrim(justification)) BETWEEN 1 AND 1000),
    min_version TEXT CHECK (min_version ~ '^[0-9]{1,9}(\.[0-9]{1,9}){0,7}$'),
    review_date DATE,
    selected_alias_id UUID REFERENCES software_product_aliases(id) ON DELETE RESTRICT,
    resolved_alias_id UUID REFERENCES software_product_aliases(id) ON DELETE RESTRICT,
    -- The policy remains in the existing store. Deletion withdraws its effective
    -- state without erasing the declaration or either decision ledger.
    policy_id BIGINT UNIQUE REFERENCES tenant_app_policies(id) ON DELETE SET NULL,
    resolved_identifier TEXT,
    resolved_kind TEXT,
    resolved_companion TEXT,
    resolved_publisher_key TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    CHECK ((resolved_alias_id IS NULL AND policy_id IS NULL AND resolved_at IS NULL)
        OR (resolved_alias_id IS NOT NULL AND resolved_identifier IS NOT NULL
            AND resolved_kind IS NOT NULL AND resolved_companion IS NOT NULL AND resolved_at IS NOT NULL)),
    CHECK (resolved_publisher_key IS NULL OR platform='windows')
);
CREATE INDEX tenant_software_declarations_tenant_idx ON tenant_software_declarations(tenant_id,created_at,id);
CREATE UNIQUE INDEX tenant_software_declarations_identity_uq
    ON tenant_software_declarations(tenant_id,COALESCE(resolved_alias_id,selected_alias_id))
    WHERE COALESCE(resolved_alias_id,selected_alias_id) IS NOT NULL;
CREATE UNIQUE INDEX tenant_software_declarations_manual_uq
    ON tenant_software_declarations(tenant_id,platform,lower(btrim(name)),lower(btrim(publisher)))
    WHERE selected_alias_id IS NULL AND resolved_alias_id IS NULL;

-- No cascading audit FK: retain the original declaration and resolution
-- snapshot even after policy removal or tenant decommissioning.
CREATE TABLE software_declaration_decisions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    declaration_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('created','resolved')),
    actor_email TEXT NOT NULL CHECK (btrim(actor_email)<>''),
    justification TEXT NOT NULL CHECK (char_length(btrim(justification)) BETWEEN 1 AND 1000),
    declaration JSONB NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX software_declaration_decisions_tenant_idx ON software_declaration_decisions(tenant_id,declaration_id,id);
CREATE FUNCTION reject_software_declaration_decision_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'software_declaration_decisions is append-only';
END;
$$;
CREATE TRIGGER software_declaration_decisions_append_only BEFORE UPDATE OR DELETE OR TRUNCATE
    ON software_declaration_decisions FOR EACH STATEMENT EXECUTE FUNCTION reject_software_declaration_decision_mutation();

-- One conservative eligibility projection for EVERY existing policy resolver.
-- Only Windows approvals linked to a declaration are conditional. The authored
-- store, operator precedence and unrelated historical policy semantics remain.
--
-- A declared Windows approval is effective only while the tenant has at least
-- one current installation of the resolved identifier and every current
-- installation of that identifier is the resolved curated identity, signed by
-- the pinned Authenticode publisher. One unsigned, missing, mismatched or
-- conflicting current installation suspends it; nothing is deleted, and it
-- returns when the evidence does.
--
-- "Current" for Windows needs device_apps as well as removed_at IS NULL: no
-- application scope closes a native Windows software_installations row, so
-- removed_at alone would keep an uninstalled copy suspending (or vouching
-- for) the approval for ever. device_apps is pruned only under the PAT-2063
-- absence authority, so this never reads an incomplete report as a removal.
--
-- Nothing here re-derives a normalised identifier in SQL. The installation is
-- tied to its device_apps row through its latest observation's
-- observed_identifier, which the extractor writes from the same payload field,
-- trimmed the same way, as device_apps.identifier: a byte-for-byte match that
-- no case-folding or whitespace rule, and no database locale, can break. An
-- installation whose observation is gone cannot be shown removed, so it stays
-- current and, having no signature evidence, suspends the approval.
--
-- The publisher key is the one softwaregov.AuthenticodePublisherKey builds:
-- the stored thumbprint (lower-case hex by the 0188 CHECK and the extractor)
-- and the signer with each run of whitespace collapsed to one space. The
-- bracket expression lists Go's unicode.IsSpace set explicitly because
-- [[:space:]] depends on the database locale.
--
-- A function, not a view, and with a string body on purpose. A view would
-- pin today's tenant_app_policies column list and block any later migration
-- or rollback that drops or retypes a column (0201's rollback drops source).
-- This depends only on the table's row type, returns whatever columns the
-- table has when it runs, cannot be read without naming a tenant, and is
-- inlined by the planner (single SELECT, STABLE, no SECURITY DEFINER).
CREATE FUNCTION effective_tenant_app_policies(p_tenant UUID) RETURNS SETOF tenant_app_policies
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
$fn$;
COMMENT ON TABLE tenant_software_declarations IS 'Tenant-declared software intent. Not an observation and not evidence of installation, trust or compliance. Effective only through a verified resolution to tenant_app_policies.';
COMMENT ON TABLE software_declaration_decisions IS 'Append-only creation and resolution history for tenant software declarations. Survives policy removal and tenant purge.';
COMMENT ON FUNCTION effective_tenant_app_policies(UUID) IS 'tenant_app_policies minus Windows approvals linked to a declaration whose pinned identity and Authenticode publisher are not borne out by every current installation.';
GRANT SELECT,INSERT,UPDATE,DELETE ON tenant_software_declarations TO patched;
GRANT SELECT,INSERT ON software_declaration_decisions TO patched;
GRANT USAGE,SELECT ON SEQUENCE software_declaration_decisions_id_seq TO patched;
GRANT EXECUTE ON FUNCTION effective_tenant_app_policies(UUID) TO patched;
INSERT INTO schema_migrations(version) VALUES ('0224_software_declarations') ON CONFLICT (version) DO NOTHING;
COMMIT;
