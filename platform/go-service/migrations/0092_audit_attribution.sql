-- patched.im — 0092_audit_attribution.sql
-- PAT-1135: honest attribution for admin audit writes.
--
-- Every admin audit row today stores an `actor`/`changed_by`/`admin_id`
-- value taken verbatim from the caller's JSON body, defaulting to "system"
-- when omitted. But /admin/* has NO per-person identity — it is guarded by
-- one shared bearer secret, ADMIN_API_TOKEN (see requireAdminToken,
-- cmd/patched-api/main.go). Anyone holding that token is indistinguishable
-- to the server from anyone else holding it. Recording the caller-supplied
-- string in the authoritative actor column therefore recorded "what the
-- caller claimed", not "who actually did it" — an audit trail that looks
-- attributable but isn't.
--
-- The fix (see internal/handlers/audit_attribution.go): the existing
-- actor-type column on each table below now always receives the one
-- identity the server CAN vouch for — the constant "admin_shared_token" —
-- and two new nullable columns record what the server can additionally
-- observe without trusting it:
--
--   source_addr    the client IP the request was actually seen from
--                   (rightmost X-Forwarded-For hop, the one Caddy itself
--                   appended, port stripped) — see the source_addr note
--                   below and internal/handlers/audit_attribution.go for
--                   why that differs from inventory.go / provenance.go's
--                   extraction, which runs on a router with chi's RealIP
--                   middleware mounted and this one does not.
--   claimed_actor   the caller-supplied string, unmodified, kept ONLY
--                   under this clearly-untrusted name — never in the
--                   existing actor/changed_by/admin_id column.
--
-- Both are nullable: a request with no source IP available, or no claimed
-- actor supplied, still writes a valid audit row. Neither column is used
-- for any control-flow decision anywhere in the codebase — same
-- "documentation, not authority" posture as tenant_decommission.reason
-- (see 0091's header comment).
--
-- This migration does NOT rename or drop any existing actor-type column —
-- existing readers (dashboards, reports, direct SQL) depend on it staying
-- present, populated, and NOT NULL where it already was. It only changes,
-- at the Go call sites (not here), what value newly-written rows receive.
--
-- BACKFILL (review finding, second round): the ADD COLUMNs above only
-- change the shape of the table — every row written before this migration
-- still holds the pre-PAT-1135 value (caller-claimed, or a hardcoded
-- literal) in the authoritative actor column, while every row written
-- after it holds "admin_shared_token". Left alone, that is a silent mixed-
-- semantics column: two eras of rows that look identical but mean
-- different things, with nothing in the schema saying so. The backfill
-- below makes the split explicit instead of silent, uniformly across all
-- six tables:
--
--   UPDATE <table> SET claimed_actor = <authcol>, <authcol> = 'legacy_unauthenticated';
--
-- This preserves every pre-existing recorded value verbatim in
-- claimed_actor (exactly the same "untrusted claim" home a live request's
-- caller-supplied string gets going forward — these were equally
-- unauthenticated, just not labelled as such before now) and marks the
-- authoritative column with a distinct, greppable sentinel
-- ('legacy_unauthenticated') that can never collide with
-- 'admin_shared_token' or any real caller-supplied string. A row with
-- actor='legacy_unauthenticated' means "written before PAT-1135, actor
-- unverified by construction, whatever claimed_actor says is the original
-- unverified value"; a row with actor='admin_shared_token' means "written
-- after PAT-1135, by the shared-token principal, whatever claimed_actor
-- says is a separate unverified claim". Neither is a stronger identity
-- claim than the other — 'legacy_unauthenticated' just says so honestly
-- where 'admin_shared_token' was already saying so via this migration's
-- header comment before the backfill existed. On a fresh database (zero
-- rows in these tables, e.g. a scratch test DB) every backfill UPDATE is a
-- no-op affecting zero rows — safe by construction.
--
-- Six tables, matching the six admin audit-writing handlers PAT-1135
-- touches:
--   tenant_decommission_audit    (internal/handlers/agent_decommission.go)
--   tenant_tier_changes          (internal/handlers/admin.go)
--   tenant_platform_changes      (internal/handlers/tenant_platforms.go)
--   tenant_rule_changes          (internal/handlers/tenant_rules.go)
--   tenant_app_policy_changes    (internal/handlers/app_update_policy.go)
--   device_revocations           (internal/handlers/admin_enrolled_devices.go)
--
-- See also docs/AUDIT_STORE.md ("Actor attribution is not authenticated
-- (PAT-1135)") and docs/API.md ("Admin audit attribution (PAT-1135)", under
-- Auth model) for the full statement of this finding, and PAT-700
-- (DASHBOARD_OPERATORS), which is what would eventually give the admin
-- surface real per-person identity and make claimed_actor obsolete.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0092_audit_attribution.sql
BEGIN;

ALTER TABLE tenant_decommission_audit
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN tenant_decommission_audit.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN tenant_decommission_audit.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative actor column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go.';

-- tenant_decommission_audit (uniquely among the six tables) is append-only
-- by DB trigger, not just convention: trg_tenant_decommission_audit_append_only
-- (0091_agent_decommission.sql) REJECTS every UPDATE and DELETE, including
-- from the table-owning `patched` role that this migration itself runs as
-- (see that trigger's header comment -- it fires for every session
-- specifically so ownership can't bypass it). The backfill UPDATE below
-- would otherwise be rejected outright with "tenant_decommission_audit is
-- append-only". This is the one legitimate, deliberate exception to that
-- rule: a one-time, same-transaction, forward-migration backfill that
-- relabels existing rows' actor semantics without altering anything else
-- about them (old_mode/new_mode/expires_at/purge/reason/directive_version/
-- changed_at are all untouched). Disable the trigger for the duration of
-- this single statement, then re-enable it in the SAME transaction before
-- COMMIT, so the append-only guarantee is intact again before any other
-- session can observe it lifted.
ALTER TABLE tenant_decommission_audit DISABLE TRIGGER trg_tenant_decommission_audit_append_only;

UPDATE tenant_decommission_audit
    SET claimed_actor = actor,
        actor = 'legacy_unauthenticated';

ALTER TABLE tenant_decommission_audit ENABLE TRIGGER trg_tenant_decommission_audit_append_only;

ALTER TABLE tenant_tier_changes
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN tenant_tier_changes.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN tenant_tier_changes.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative changed_by column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go.';

UPDATE tenant_tier_changes
    SET claimed_actor = changed_by,
        changed_by = 'legacy_unauthenticated';

ALTER TABLE tenant_platform_changes
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN tenant_platform_changes.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN tenant_platform_changes.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative changed_by column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go.';

UPDATE tenant_platform_changes
    SET claimed_actor = changed_by,
        changed_by = 'legacy_unauthenticated';

ALTER TABLE tenant_rule_changes
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN tenant_rule_changes.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN tenant_rule_changes.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative changed_by column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go.';

UPDATE tenant_rule_changes
    SET claimed_actor = changed_by,
        changed_by = 'legacy_unauthenticated';

ALTER TABLE tenant_app_policy_changes
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN tenant_app_policy_changes.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN tenant_app_policy_changes.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative changed_by column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go.';

UPDATE tenant_app_policy_changes
    SET claimed_actor = changed_by,
        changed_by = 'legacy_unauthenticated';

ALTER TABLE device_revocations
    ADD COLUMN source_addr   TEXT,
    ADD COLUMN claimed_actor TEXT;

COMMENT ON COLUMN device_revocations.source_addr IS
    'Observed client IP for this write (rightmost X-Forwarded-For hop, port stripped), best-effort. Never used for control flow.';
COMMENT ON COLUMN device_revocations.claimed_actor IS
    'Caller-supplied claim for rows written after PAT-1135; original pre-PAT-1135 recorded value for migrated rows -- unverified either way. The authoritative admin_id column always holds "admin_shared_token" (post-PAT-1135) or "legacy_unauthenticated" (backfilled) instead; see internal/handlers/audit_attribution.go. RevokeDeviceHandler currently accepts no request body at all, so claimed_actor is NULL for every row written by it going forward; the column exists so a future body field has somewhere honest to land without ever touching admin_id.';

UPDATE device_revocations
    SET claimed_actor = admin_id,
        admin_id = 'legacy_unauthenticated';

INSERT INTO schema_migrations (version) VALUES ('0092_audit_attribution')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
