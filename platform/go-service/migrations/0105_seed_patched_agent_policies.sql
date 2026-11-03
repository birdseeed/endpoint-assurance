-- patched.im — 0105_seed_patched_agent_policies.sql
-- PAT-1318: one-time backfill approving every first-party Patched Agent
-- identity (internal/agentidentity/agentidentity.go) for every tenant that
-- already existed before that code shipped.
--
-- Tenants created from now on are seeded by
-- agentidentity.EnsurePatchedAgentPolicies, called from CreateTenantHandler
-- (internal/handlers/admin.go) inside the tenant-creation transaction. The
-- extraction sweep (internal/extractor/new_apps.go, doDetectNewTenantApps)
-- also calls it for every tenant in a batch before running its "for review"
-- candidate query, so any tenant created out of band self-heals on its next
-- extraction cycle. This migration only needs to cover the gap: tenants
-- that existed, and may already have accumulated tenant_new_apps "for
-- review" rows for these identities, before either code path ran for them.
--
-- Identities, enforcement_tier, policy and the notes marker mirror
-- internal/agentidentity/agentidentity.go exactly — there is no code
-- generation linking the two, so keep them in sync by hand if either
-- changes.
--
-- ON CONFLICT DO NOTHING is idempotent (safe to re-run) and never overwrites
-- a row an operator already created for one of these identities — same
-- reasoning as EnsurePatchedAgentPolicies's doc comment: any existing row,
-- whatever its policy value, is a deliberate operator decision and already
-- keeps the identity out of the "for review" queue.
--
-- This migration also resolves any pre-existing tenant_new_apps "for
-- review" rows for these identities — it does NOT delete them. Deleting a
-- row an operator may already be looking at would be silent and wrong; this
-- ticket's acceptance line is "Patched Agent entries do not appear as
-- tenant review findings", which for a tenant that predates this backfill
-- means resolving the finding, not hiding it. So the UPDATE below records a
-- decision instead: decision = 'approve', decided_by =
-- 'system:PAT-1318' — visibly not a human decision, and deliberately using
-- the same ticket reference as the tenant_app_policies notes marker above
-- so both are greppable together — decided_at/updated_at = now(). An
-- operator looking at the queue afterwards sees a resolved, attributed
-- finding rather than a row that silently vanished.
--
-- Identity match for the UPDATE: the macOS pair matches on app_identity
-- directly — extractor/new_apps.go's candidatesSQL "keyed" CTE builds it as
-- 'bundle:' || lower(ta.identifier), so 'bundle:im.patched.updater.menubar'
-- and 'bundle:im.patched.updater.selfservice' are exactly the stored,
-- already-lower-cased form (both identifiers here are already all-lowercase,
-- so lower() is a no-op on them, but the literals below are written
-- lower-cased regardless, matching what the SQL actually produces). The
-- Windows agent has no such stable app_identity to match on — its
-- device_apps.identifier is a per-release MSI ProductCode GUID that WiX
-- regenerates on every version (see internal/agentidentity/agentidentity.go),
-- so any pre-existing row for it is matched on platform + case-insensitive
-- display name instead, same as the seed's own identity for it.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0105_seed_patched_agent_policies.sql

BEGIN;

INSERT INTO tenant_app_policies
    (tenant_id, bundle_id, name, platform, policy, enforcement_tier, notes)
SELECT
    t.id, agent.bundle_id, agent.name, agent.platform,
    'approved', 'report_deploy',
    'PAT-1318: first-party Patched Agent, auto-approved'
FROM tenants t
CROSS JOIN (
    VALUES
        ('im.patched.updater.menubar'::text,     NULL::text,             'macos'::text),
        ('im.patched.updater.selfservice'::text, NULL::text,             'macos'::text),
        (NULL::text,                             'Patched Agent'::text,  'windows'::text)
) AS agent(bundle_id, name, platform)
ON CONFLICT (tenant_id,
    COALESCE(team_id, ''),
    COALESCE(bundle_id, ''),
    COALESCE(lower(name), ''),
    platform)
DO NOTHING;

UPDATE tenant_new_apps
SET decision   = 'approve',
    decided_by = 'system:PAT-1318',
    decided_at = now(),
    updated_at = now()
WHERE decision IS NULL
  AND (
        app_identity IN ('bundle:im.patched.updater.menubar', 'bundle:im.patched.updater.selfservice')
        OR (platform = 'windows' AND lower(name) = 'patched agent')
      );

INSERT INTO schema_migrations (version) VALUES ('0105_seed_patched_agent_policies')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
