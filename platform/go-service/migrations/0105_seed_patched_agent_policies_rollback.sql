-- patched.im — rollback for 0105_seed_patched_agent_policies.sql (PAT-1318)
--
-- Deletes ONLY tenant_app_policies rows carrying the PAT-1318 seed notes
-- marker — never an operator-created row, even one that happens to cover
-- the same identity as a seeded row. An operator row would have been
-- written through TenantAppPoliciesPutHandler's DO UPDATE path (or created
-- before this migration ever ran) and would not carry this marker; a seeded
-- row an operator has since edited via that same PUT handler also loses the
-- marker at that point (the PUT handler overwrites notes), so this rollback
-- correctly leaves it alone too.
--
-- Reverts ONLY tenant_new_apps rows carrying decided_by = 'system:PAT-1318'
-- back to undecided (decision/decided_by/decided_at all NULL) — never a row
-- a human actually decided. A human decision always carries a human's
-- decided_by value (the admin UI requires one — see
-- TenantNewAppsPutHandler), so it can never collide with this marker.
--
-- HONEST LIMIT: this rollback only actually holds if the Go code is reverted
-- too. Both statements above delete/revert rows by content (the notes
-- marker; the decided_by marker) rather than by "was written by this
-- migration specifically", because the two are indistinguishable by design
-- — agentidentity.EnsurePatchedAgentPolicies (internal/agentidentity/seed.go)
-- writes byte-identical tenant_app_policies rows (same notes marker) at
-- runtime from CreateTenantHandler and from every extraction batch, and
-- there is no separate marker for "written by the 0105 migration" vs
-- "written by the running service". So: if this rollback runs while the
-- PAT-1318 code is still deployed, the extractor's next sweep for each
-- affected tenant simply re-seeds the tenant_app_policies rows this
-- statement just deleted (EnsurePatchedAgentPolicies is idempotent and
-- unconditional) — the rollback will appear to have "not worked" on the
-- next observation, though the tenant_new_apps decisions it reverted stay
-- reverted (nothing re-applies those; a new "for review" row is created
-- fresh instead). To actually roll this back, revert/undeploy the code
-- first, then run this migration.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0105_seed_patched_agent_policies_rollback.sql

BEGIN;

DELETE FROM tenant_app_policies
WHERE notes = 'PAT-1318: first-party Patched Agent, auto-approved';

UPDATE tenant_new_apps
SET decision   = NULL,
    decided_by = NULL,
    decided_at = NULL,
    updated_at = now()
WHERE decided_by = 'system:PAT-1318';

DELETE FROM schema_migrations WHERE version = '0105_seed_patched_agent_policies';

COMMIT;
