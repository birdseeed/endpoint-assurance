-- Rollback of 0226 (PAT-2404). Roll the binaries back first: the PAT-2404
-- binaries read software_product_aliases.retired_at on every inventory report.
--
-- Fails closed. A review or a retirement cannot be reconstructed, and dropping
-- retired_at would silently bring every retired alias back to life, so this
-- refuses once the audit table holds a row or any alias is retired. Prefer
-- leaving the additive objects in place.
--
-- The function is restored to the 0224 text exactly.
BEGIN;
LOCK TABLE software_product_aliases, software_catalogue_audit IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM software_catalogue_audit)
       OR EXISTS (SELECT 1 FROM software_product_aliases WHERE retired_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0226: catalogue review history or retired aliases exist';
    END IF;
END $$;
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
$fn$;
COMMENT ON FUNCTION effective_tenant_app_policies(UUID) IS 'tenant_app_policies minus Windows approvals linked to a declaration whose pinned identity and Authenticode publisher are not borne out by every current installation.';
DROP TABLE software_catalogue_audit;
DROP FUNCTION reject_software_catalogue_audit_mutation();
ALTER TABLE software_product_aliases DROP COLUMN retired_at;
DELETE FROM schema_migrations WHERE version = '0226_software_catalogue_review';
COMMIT;
