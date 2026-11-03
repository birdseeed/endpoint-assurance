-- patched.im — 0091_agent_decommission.sql
-- PAT-1108: server-side contract + persistence for agent decommissioning —
-- the platform's only irreversible command. Once an agent removes itself
-- there is no channel left to correct a mistake, so every table here is
-- built around one rule: fail closed means DO NOT REMOVE. Unknown, missing,
-- or malformed state must never be read as "go ahead" — see
-- internal/agentconfig/signing.go:safeDecommissionPolicy for the same
-- invariant enforced again at the point the directive is signed.
--
-- Three tables:
--
--   1. tenant_decommission — the CURRENT tenant-wide directive, one row per
--      tenant. Set only through PUT /admin/tenants/{tenantID}/decommission
--      (internal/handlers/agent_decommission.go), never as a side effect of
--      DELETE /admin/tenants/{tenantID} (soft-revoke, RevokeTenantHandler in
--      admin.go) or DELETE /admin/tenants/{tenantID}/purge
--      (PurgeTenantHandler) — this migration does not touch either handler,
--      and neither of them writes this table. mode='none' (the default) is
--      the safe/inert value; a row need not exist for a tenant to be inert —
--      dbGetAgentConfig (agent_config.go) treats a missing row identically
--      to an explicit mode='none' row via a LEFT JOIN, the same
--      "absence is safe" contract app_control already uses for tenants
--      without an Application Control row.
--
--      DELIBERATELY NO EXPIRY OR CLEANUP ON THIS TABLE. A device can be
--      offline for months — a laptop in a drawer — and must still see and
--      act on the directive the moment it reconnects, however long that
--      takes. No TTL, retention sweep, or cleanup job may ever be added
--      against this table's rows: the directive must outlive any plausible
--      offline window by construction, not by a policy someone has to
--      remember to configure generously enough.
--
--   2. tenant_decommission_audit — append-only log of every write to
--      tenant_decommission, mirroring the tenant_platform_changes pattern
--      (0010): actor and timestamp on every row, never UPDATEd or DELETEd.
--      This is the "explicit, audited action" the directive-setting
--      endpoint is required to produce — every call to the PUT handler
--      writes one row here, whether or not the resulting directive differs
--      from the previous one, because re-confirming an irreversible
--      directive is itself an event worth a durable record (same choice
--      tenant_platforms.go already makes for the platform-switch audit).
--
--   3. device_decommission_state — per-device reported state, one row per
--      device, written only by POST /v1/agent-decommission-status — the
--      two-phase status-report endpoint: "acknowledged" before the agent
--      attempts removal, then the genuine terminal outcome ("removed" or
--      "failed") after the attempt finishes, with the agent destroying its
--      own uploader only once that second report has gone through (PAT-1108
--      fourth-round finding P1-B; see contracts/agent-config-schema.md). No
--      row for a device means it has never reported ANY decommission
--      status — critically, this must read as 'pending', not as an error
--      or an empty result, when a tenant
--      admin asks "how many of my devices have been decommissioned" right
--      after setting a directive. The admin read path
--      (report.FetchTenantDecommissionDevices) therefore LEFT JOINs FROM
--      devices, never INNER JOINs from this table, so a device that has
--      never checked in since the directive was set is still counted and
--      shown as pending — "12 of 40 removed, 28 pending", not "12 of 12
--      removed".
--
-- status values are exactly: pending, acknowledged, removed, failed,
-- expired_unreachable. 'pending' is never written to a row directly — it is
-- the meaning of a device's ABSENT row, applied by the LEFT JOIN read path
-- (COALESCE(status, 'pending')). The CHECK constraint below still lists it
-- for documentation, and so a future direct write of 'pending' (e.g. an
-- explicit "I have seen the directive but not yet acted" ack) is not
-- rejected by the schema if that need arises later.
--
-- directive_version (PAT-1108 review findings 1 and 5): both
-- tenant_decommission and device_decommission_state carry a directive_version
-- column, which is the tenant's agent_config.config_version value AT THE
-- MOMENT the directive was written — the SAME anti-rollback counter
-- agent_config already uses (internal/handlers/agent_config.go), not a new
-- parallel one. TenantDecommissionPutHandler (internal/handlers/
-- agent_decommission.go) bumps agent_config.config_version whenever the
-- effective directive changes (mode, expires_at, or purge; a reason-only
-- edit is not a directive change, matching "reason never affects
-- control flow") and stamps the resulting value onto
-- tenant_decommission.directive_version in the same transaction. Every
-- device_decommission_state row records which directive_version it was
-- reported against. The read path (report.FetchTenantDecommissionDevices)
-- treats a device row whose directive_version is behind the tenant's current
-- one as 'pending', not as its stale outcome — otherwise cancelling a
-- directive and later issuing a new one would show devices as already
-- acknowledged/removed/failed against a directive they have never seen.
--
-- PAT-1108 sixth-round finding P2: every directive_version column in this
-- migration (tenant_decommission, tenant_decommission_audit,
-- device_decommission_state) is CHECKed >= 0. AgentDecommissionStatusHandler
-- reserves the in-memory sentinel unattributedDirectiveVersion = -1 for "the
-- agent did not say which envelope it verified"; that sentinel is only safe
-- because it can never equal a stored directive_version, and before this
-- constraint existed nothing enforced that at the schema level.
--
-- device_id / tenant_id both cascade on delete, matching device_agent_health
-- (0090) and tenant_platform_changes (0010) respectively — these tables have
-- no independent lifecycle from the device/tenant they describe. Cascading
-- tenant_decommission on tenant delete is safe specifically because it only
-- fires on PurgeTenantHandler's hard `DELETE FROM tenants` (irreversible by
-- design already, and only reachable after a soft-revoke); RevokeTenantHandler
-- never deletes the tenants row, so a soft-revoke can never silently drop a
-- decommission directive.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0091_agent_decommission.sql
BEGIN;

CREATE TABLE tenant_decommission (
    tenant_id         uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode              text        NOT NULL DEFAULT 'none' CHECK (mode IN ('none', 'expiry', 'immediate')),
    expires_at        timestamptz,                          -- RFC3339 UTC; required by the write-path validator when mode='expiry'
    purge             boolean     NOT NULL DEFAULT false,
    reason            text,                                 -- operator-supplied context; recorded/surfaced only, NEVER a control-flow input
    set_by            text        NOT NULL DEFAULT 'system',
    set_at            timestamptz NOT NULL DEFAULT now(),
    directive_version integer     NOT NULL DEFAULT 0,        -- agent_config.config_version at the moment this directive was written; see the directive_version note above
    CONSTRAINT tenant_decommission_expiry_needs_expires_at
        CHECK (mode <> 'expiry' OR expires_at IS NOT NULL),
    -- PAT-1108 sixth-round finding P2: this is the SOURCE-OF-TRUTH
    -- directive_version AgentDecommissionStatusHandler reads as
    -- currentDirectiveVersion. The handler separately reserves the
    -- in-memory sentinel unattributedDirectiveVersion = -1 to mean "the
    -- agent could not say which envelope it verified", and relies on that
    -- value being unable to equal any REAL directive_version (see
    -- unattributedDirectiveVersion's doc comment). That invariant held only
    -- because nothing had ever written a negative directive_version here --
    -- nothing in the CHECK constraint above enforced it. A malformed or
    -- hand-written row with directive_version = -1 would make an
    -- unattributed report compare EQUAL to the tenant's current directive
    -- and could return "proceed" for an immediate directive, defeating the
    -- fail-closed handling of the unattributed case on the irreversible
    -- removal path. This constraint makes that impossible at the source.
    CONSTRAINT tenant_decommission_directive_version_non_negative
        CHECK (directive_version >= 0)
);

COMMENT ON TABLE tenant_decommission IS
    'Current tenant-wide agent-decommission directive (PAT-1108), one row per tenant. Absence of a row means mode=none (inert) -- the same contract as an explicit none row, see internal/handlers/agent_config.go:dbGetAgentConfig. Set only via PUT /admin/tenants/{tenantID}/decommission; never a side effect of tenant revoke or purge. No TTL or cleanup job may ever be added against this table.';
COMMENT ON COLUMN tenant_decommission.mode IS
    'none = inert (default). expiry = the agent may remove itself once expires_at has passed. immediate = the agent may remove itself on next successful verification of this directive.';
COMMENT ON COLUMN tenant_decommission.reason IS
    'Operator-supplied free text, recorded and surfaced for audit/operator visibility only. Must NEVER be evaluated as a control-flow input, here or on the agent.';
COMMENT ON COLUMN tenant_decommission.directive_version IS
    'agent_config.config_version at the moment this directive was last written (bumped only when the effective directive -- mode/expires_at/purge -- actually changes). Stamped onto every device_decommission_state row reported against this directive, so a stale report from an earlier directive can be told apart from a current one. See the directive_version note near the top of this file.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_decommission TO patched;

CREATE TABLE tenant_decommission_audit (
    id                bigserial   PRIMARY KEY,
    tenant_id         uuid        NOT NULL,
    actor             text        NOT NULL DEFAULT 'system',
    old_mode          text,                                 -- NULL on the tenant's first-ever directive write
    new_mode          text        NOT NULL,
    expires_at        timestamptz,
    purge             boolean     NOT NULL,
    reason            text,
    directive_version integer     NOT NULL DEFAULT 0,        -- agent_config.config_version this row's new_mode/expires_at/purge took effect at; see the note below
    changed_at        timestamptz NOT NULL DEFAULT now(),
    -- PAT-1108 sixth-round finding P2: this is the OTHER source-of-truth
    -- directive-generation column -- dbResolveDirectiveForEnvelopeVersion
    -- (agent_decommission.go) resolves an agent-reported envelope version
    -- to whichever row here has the greatest directive_version <= that
    -- envelope version, and that resolved value is compared directly
    -- against tenant_decommission.directive_version. Same reasoning as
    -- that table's identically-named constraint: this must never be able
    -- to hold -1, the unattributedDirectiveVersion in-memory sentinel, or
    -- an unattributed report could resolve to a real, matching directive.
    CONSTRAINT tenant_decommission_audit_directive_version_non_negative
        CHECK (directive_version >= 0)
);

CREATE INDEX idx_tdecomaudit_tenant_time ON tenant_decommission_audit(tenant_id, changed_at DESC);

-- PAT-1108 third-round finding A: resolves an agent-reported envelope
-- config_version to the directive generation that was actually in effect at
-- that version — see AgentDecommissionStatusHandler's resolution query
-- (internal/handlers/agent_decommission.go), which orders by
-- (directive_version DESC, changed_at DESC) to find the newest audit row at
-- or below the reported version.
CREATE INDEX idx_tdecomaudit_tenant_directive_version ON tenant_decommission_audit(tenant_id, directive_version DESC, changed_at DESC);

COMMENT ON TABLE tenant_decommission_audit IS
    'Append-only audit trail of every write to tenant_decommission (PAT-1108), mirroring tenant_platform_changes (0010). One row per PUT /admin/tenants/{tenantID}/decommission call, whether or not the resulting directive differs from the previous one. UPDATE, DELETE, and TRUNCATE are all REJECTED (trg_tenant_decommission_audit_append_only for UPDATE/DELETE, trg_tenant_decommission_audit_append_only_truncate for TRUNCATE -- PAT-1108 fourth/fifth-round findings P2/P1-C), not merely documented against -- this holds even for the owning role.';
COMMENT ON COLUMN tenant_decommission_audit.actor IS
    'Identity of the staff member or automation that set the directive: email address, API key label, or "system".';
COMMENT ON COLUMN tenant_decommission_audit.directive_version IS
    'agent_config.config_version in force for this row''s new_mode/expires_at/purge at the moment it was written -- the SAME value stamped onto tenant_decommission.directive_version by that PUT (identical for every audit row from the same PUT, including reason-only/no-op repeats that do not bump the counter). PAT-1108 third-round finding A: because directive_version only increases and a directive stays in effect until the next row with a HIGHER directive_version, "the directive generation in effect at reported envelope version V" is exactly the row with the greatest directive_version <= V -- see AgentDecommissionStatusHandler''s resolution query. This is what lets the agent report the envelope config_version it actually observed (the only version it can observe) while the server still recovers which DIRECTIVE that was, even if unrelated agent-config writes (app_control, tier, etc.) bumped config_version further in between without touching the directive.';

GRANT SELECT, INSERT ON TABLE tenant_decommission_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_decommission_audit_id_seq TO patched;

-- PAT-1108 fourth-round finding P2: this migration runs as role `patched`
-- (see "Apply with" at the top of this file), which makes `patched` the
-- OWNER of every table it creates here, including this one. Table
-- ownership is not something GRANT/REVOKE can take away from the owner --
-- an owner always retains implicit UPDATE/DELETE regardless of what
-- privileges are explicitly granted or withheld. The GRANT above
-- (SELECT, INSERT only, no UPDATE/DELETE) therefore documents intent but
-- enforces nothing against the very role that will actually be making
-- every write here in production -- the "append-only" claim in this file's
-- header comment and in the table comment below was not backed by
-- anything a client could not simply override with an UPDATE or DELETE
-- statement. A BEFORE trigger is the correct mechanism here specifically
-- because triggers fire for every session including the table owner's,
-- unlike privilege checks. It RAISEs rather than silently no-opping (an
-- old-style rule with DO INSTEAD NOTHING would let an application bug that
-- attempts to "correct" an audit row vanish without a trace, which is
-- worse than failing loudly for a table whose entire purpose is being a
-- trustworthy record of an irreversible-action trail) -- matching this
-- file's fail-closed posture everywhere else. The legitimate INSERT path
-- (TenantDecommissionPutHandler) is unaffected: the trigger only fires
-- BEFORE UPDATE OR DELETE.
CREATE FUNCTION reject_tenant_decommission_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_decommission_audit is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_decommission_audit_append_only
    BEFORE UPDATE OR DELETE ON tenant_decommission_audit
    FOR EACH ROW
    EXECUTE FUNCTION reject_tenant_decommission_audit_mutation();

-- PAT-1108 fifth-round finding P1-C: the trigger above is ROW-level
-- (FOR EACH ROW), and PostgreSQL never fires row-level triggers for
-- TRUNCATE -- TRUNCATE has no per-row execution at all, so it bypasses
-- BEFORE UPDATE OR DELETE entirely regardless of what those triggers
-- reject. That left the owning `patched` role able to erase the ENTIRE
-- audit trail in a single TRUNCATE statement, defeating the append-only
-- guarantee the trigger above exists to provide. TRUNCATE requires its own
-- STATEMENT-level trigger (FOR EACH STATEMENT, BEFORE TRUNCATE) with its
-- own function, because a statement-level trigger fires once for the whole
-- statement with no row in context, so it cannot reference OLD/NEW at all
-- (unlike the row-level function above, which needs OLD.id).
CREATE FUNCTION reject_tenant_decommission_audit_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_decommission_audit is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_decommission_audit_append_only_truncate
    BEFORE TRUNCATE ON tenant_decommission_audit
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_tenant_decommission_audit_truncate();

CREATE TABLE device_decommission_state (
    device_id              uuid        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    status                 text        NOT NULL CHECK (status IN ('pending', 'acknowledged', 'removed', 'failed', 'expired_unreachable')),
    last_reported_outcome  text        NOT NULL DEFAULT '',  -- free-text detail from the agent, e.g. an error message on 'failed'
    directive_version      integer     NOT NULL DEFAULT 0,   -- tenant_decommission.directive_version this report was made against; see the directive_version note above
    phase1_observed        boolean     NOT NULL DEFAULT false, -- true iff an "acknowledged" report for THIS SAME directive_version was recorded before (or as) this row's current status; see the column comment below and PAT-1108 fifth-round finding P1-E
    first_reported_at      timestamptz NOT NULL DEFAULT now(),
    last_reported_at       timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- PAT-1108 sixth-round finding P2. Unlike the two tables above, this
    -- column is the one AgentDecommissionStatusHandler could, in principle,
    -- write the unattributedDirectiveVersion (-1) sentinel into for an
    -- unattributed report -- an earlier round's doc comment on that
    -- constant said exactly that. Verified against the CURRENT write path
    -- before adding this constraint (per the instruction not to blanket-
    -- apply it over a genuine sentinel write): the single INSERT into this
    -- table only executes when shouldPersist is true, which requires
    -- resolvedDirectiveVersion == currentDirectiveVersion; an unattributed
    -- report sets resolvedDirectiveVersion to -1, and currentDirectiveVersion
    -- is read from tenant_decommission.directive_version, which the
    -- CONSTRAINT above now guarantees is always >= 0 -- so the two can
    -- never be equal, and the INSERT is provably never reached with a
    -- negative value. The -1 sentinel therefore never actually lands here;
    -- it exists only in memory during resolution. Constraining this column
    -- too closes the same class of bug for good, rather than only where
    -- the current code happens not to trip it.
    CONSTRAINT device_decommission_state_directive_version_non_negative
        CHECK (directive_version >= 0)
);

COMMENT ON TABLE device_decommission_state IS
    'Per-device decommission state (PAT-1108), written only by POST /v1/agent-decommission-status -- the two-phase status-report call (acknowledged before the agent attempts removal, the genuine terminal outcome after -- PAT-1108 fourth-round finding P1-B; see contracts/agent-config-schema.md). No row for a device means it has never reported any status, which the admin read path (report.FetchTenantDecommissionDevices) treats as pending via a LEFT JOIN FROM devices, never an INNER JOIN from this table, so never-acknowledged devices are still counted for a tenant. A row whose directive_version is behind the tenant''s current tenant_decommission.directive_version is also read as pending -- it describes an earlier directive, not the current one.';
COMMENT ON COLUMN device_decommission_state.status IS
    'pending | acknowledged | removed | failed | expired_unreachable. pending is never written directly -- it is the meaning applied by the read path to a device with no row at all, OR to a row whose directive_version predates the tenant''s current directive. removed, failed, and expired_unreachable are TERMINAL: once written, no later report may regress the status (see AgentDecommissionStatusHandler); acknowledged is not terminal.';
COMMENT ON COLUMN device_decommission_state.phase1_observed IS
    'PAT-1108 fifth-round finding P1-E. The documented protocol (contracts/agent-config-schema.md) requires phase 1 ("acknowledged") before phase 2 (the terminal outcome), but the server does NOT reject a terminal report that arrives with no observed phase 1 for its directive_version -- rejecting would discard a genuine last word from a device whose earlier acknowledged report was merely lost in transit, trading a false removed for a lost real one, which is worse (see AgentDecommissionStatusHandler). Instead this column records what was ACTUALLY observed, so the record stays honest without being thrown away: true when the write is itself an acknowledged report (self-observed), or when a PRIOR acknowledged report for the SAME directive_version is what is being upgraded to a terminal status; false when a terminal report is accepted with no such acknowledgement on record for its directive_version -- a manufactured or short-circuited removal is then visibly anomalous (see report.FetchTenantDecommissionDevices''s terminal_without_acknowledgement field) rather than indistinguishable from a clean two-phase removal.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE device_decommission_state TO patched;

INSERT INTO schema_migrations (version) VALUES ('0091_agent_decommission')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
