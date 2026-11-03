-- 0219: publish the seeded Chrome and Firefox lifecycle mappings (PAT-2171).
--
-- They were seeded proposed by 0196 because the ordinary rule reads every
-- current browser install as "Ending within 90 days". With the rolling rule
-- (0218) in place they are ready to drive customer output.
--
-- Publishes only rows that are still proposed, were seeded by 0196, name the
-- chrome or firefox slug and have the rolling rule set, so it cannot publish
-- a browser mapping on the ordinary rule. A row staff already published or
-- rejected is left alone, and a second run changes nothing. Each row published
-- gets a 'publish' audit row (actor migration:0219), the same trail the admin
-- route writes.
--
-- Publishing through the admin route refuses a slug with no fetched cycles.
-- This cannot check that. A slug with no fetched data reads Unknown
-- ("lifecycle data not yet fetched"), never Supported, so it is safe. The
-- nightly lifecycle sync fetches every slug a proposed mapping names
-- (lifecycle.ActiveSlugs), so chrome and firefox are fetched once 0196 has
-- been deployed and a sync has run.
--
-- Deploy order: this file publishes the mappings, and the API binary that
-- understands rolling_window_days ships in the same deploy. In the seconds
-- between the migration and the binary restart, or if the binary is rolled
-- back and this file is not, an older binary reads the published browser
-- mappings on the ordinary rule: every current browser reads "Ending within
-- 90 days" again. That is noisy, not a false Supported.
--
-- Known gap: the source has no cycle for Chrome Extended Stable, which runs
-- each major for eight weeks. An Extended Stable install reads Unsupported once
-- it is two or more majors behind. Firefox ESR is separate in the source and
-- is not affected.
BEGIN;

WITH published AS (
    UPDATE lifecycle_mappings
       SET status = 'published', reviewed_by = 'migration:0219', reviewed_at = now(), updated_at = now()
     WHERE proposed_by = 'migration:0196'
       AND status = 'proposed'
       AND identity_kind <> 'os'
       AND eol_slug IN ('chrome', 'firefox')
       AND rolling_window_days IS NOT NULL
    RETURNING id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
              eol_slug, version_rule, rolling_window_days
)
INSERT INTO lifecycle_mapping_audit (mapping_id, action, actor, before, after)
SELECT id, 'publish', 'migration:0219',
       jsonb_build_object('status', 'proposed'),
       jsonb_build_object('status', 'published', 'eol_slug', eol_slug, 'version_rule', version_rule,
                          'rolling_window_days', rolling_window_days,
                          'platform', platform, 'identity_kind', identity_kind,
                          'identity_value_normalized', identity_value_normalized,
                          'companion_value_normalized', companion_value_normalized)
FROM published;

INSERT INTO schema_migrations (version) VALUES ('0219_lifecycle_publish_browser_mappings')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
