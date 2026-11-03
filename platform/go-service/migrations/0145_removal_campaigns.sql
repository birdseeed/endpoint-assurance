-- patched.im — 0145_removal_campaigns.sql
-- PAT-1598: authorised removal — platform data model only.
--
-- ── What this migration is, and deliberately is not ───────────────────────
-- This is the platform half of authorised removal: a campaign record, an
-- append-only dry-run preview snapshot, and an append-only authorisation
-- record. It carries NO delivery mechanism. Nothing in this migration, and
-- nothing in internal/handlers/removal_campaigns.go built on it, is read by
-- any agent-facing route: an authorised campaign is a governance record that
-- a human can act on through the customer's own management platform, not an
-- instruction queued for an endpoint.
--
-- That is by construction, not by a flag. PAT-1598's own rule is that no
-- removal ships to a customer before the MSA contract language exists
-- (PAT-112, not delivered). A capability flag would satisfy that rule only
-- as long as nobody flipped it; having no agent-facing path at all satisfies
-- it whatever any flag says. The follow-up that wires delivery is where the
-- managed-tier gate and fail-closed capability flags get designed.
--
-- This is also NOT the legacy execution path. tenant_allowlists'
-- marked_for_uninstall (0023) and device_removals (agent-facing, quarantined
-- behind legacyExecutionEnabled) are the old install/patch-era mechanism.
-- Removal is architecturally different — no vendor source, no version
-- treadmill, one decision with evidence attached — so this is a new
-- subsystem and touches neither of those tables.
--
-- ── Product identity ──────────────────────────────────────────────────────
-- team_id / bundle_id / name / platform, exactly the identity columns and
-- precedence tenant_app_policies (0032) already uses, and exactly what
-- protectedsoftware.Identity consumes. Reusing that convention is what lets
-- the PAT-1801 protected-software check be called on a campaign target with
-- no translation layer — an identity scheme of this table's own would have
-- created a second way to say "this product", and a second way for the
-- protected check to be pointed at the wrong thing. Identity is not
-- packaging (root AGENTS.md): none of these columns is an installer, a
-- package label or a catalogue entry.
--
-- ── Evidence and decisions are separate ───────────────────────────────────
-- removal_campaigns is the mutable working record (status moves, a campaign
-- can be cancelled). removal_campaign_dry_runs and
-- removal_campaign_authorizations are append-only evidence: a preview that
-- could be edited after the fact could not support the authorisation that
-- cites it, and an authorisation that could be edited is not a record of who
-- authorised what.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0145_removal_campaigns.sql
--
-- Rollback: migrations/0145_removal_campaigns_rollback.sql

BEGIN;

-- ── Campaigns ─────────────────────────────────────────────────────────────
-- One campaign targets exactly one product. Scope (which devices, which
-- versions) is NOT stored here: it is computed from live inventory at
-- dry-run time, because a stored scope is a claim about the estate that goes
-- stale silently, and a stale claim about what will be deleted is the exact
-- failure this ticket exists to prevent.
--
-- policy_id is the governance decision this campaign implements — the
-- tenant_app_policies row marking the product unapproved. Nullable at
-- creation (an operator can draft a campaign before the policy exists), but
-- authorisation requires one and requires it to be 'unapproved': you may not
-- authorise removing a product your own governance record calls approved,
-- mandatory or unmanaged. ON DELETE SET NULL keeps the campaign readable if
-- the policy row is later deleted; the authorisation record below keeps its
-- own immutable snapshot, so evidence does not depend on this pointer.
CREATE TABLE removal_campaigns (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Product identity — same columns and precedence as tenant_app_policies.
    team_id           TEXT,        -- Apple Developer Team ID / Windows Authenticode signer
    bundle_id         TEXT,        -- CFBundleIdentifier / Windows MSI ProductCode
    name              TEXT,        -- display name fallback (matched case-insensitively)
    platform          TEXT         NOT NULL DEFAULT 'any'
                          CHECK (platform IN ('macos', 'windows', 'any')),
    policy_id         BIGINT       REFERENCES tenant_app_policies(id) ON DELETE SET NULL,
    -- State machine: draft -> dry_run -> authorized, with cancelled
    -- reachable from draft and dry_run only. There is no transition out of
    -- authorized: un-authorising is not a mutation of this row (the
    -- authorisation record is append-only and would still stand), and there
    -- is nothing to revoke while no delivery path exists. Revocation is
    -- designed in the same follow-up that adds delivery.
    status            TEXT         NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft', 'dry_run', 'authorized', 'cancelled')),
    reason            TEXT         NOT NULL DEFAULT '',
    created_by        TEXT         NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status_changed_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    cancelled_by      TEXT,
    cancelled_reason  TEXT,
    cancelled_at      TIMESTAMPTZ,
    CONSTRAINT removal_campaigns_has_identity CHECK (
        team_id IS NOT NULL OR bundle_id IS NOT NULL OR name IS NOT NULL
    ),
    CONSTRAINT removal_campaigns_cancel_fields CHECK (
        (status <> 'cancelled' AND cancelled_by IS NULL AND cancelled_at IS NULL) OR
        (status =  'cancelled' AND cancelled_by IS NOT NULL AND cancelled_at IS NOT NULL)
    )
);

CREATE INDEX idx_removal_campaigns_tenant ON removal_campaigns (tenant_id, status, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON TABLE removal_campaigns TO patched;

-- ── Dry-run previews (append-only) ────────────────────────────────────────
-- One row per preview computation. Re-running a dry run appends a new row;
-- it never edits the previous one, so "what did the authoriser actually
-- see" survives every later recomputation.
--
-- inventory_watermark is max(devices.last_seen) across the WHOLE tenant at
-- compute time, not just across the matched devices. Tenant-wide is the
-- correct scope: a device that installed the product after the preview ran
-- was not in the matched set, so a matched-devices-only watermark would not
-- notice it — and that device is exactly the one a stale preview would fail
-- to warn about. NULL means the tenant had no devices at all at compute
-- time, which is itself a staleness input (see the Go staleness rule).
--
-- protected_match is NULL when the target matched no protected_software row
-- for this tenant, and the matched row (id, category, vendor, product_name,
-- is_baseline) when it did. Protection is scoped to a product and a tenant,
-- never to a device, so exclusion is all-or-nothing: a protected match means
-- every candidate device is excluded and the campaign can never be
-- authorised.
--
-- artefact_enumeration_complete is false in every row this ticket can write.
-- The platform can report the bundle paths it has actually observed
-- (device_apps.path) and the community path known_app_bundles has learned,
-- and nothing more — it has no vendor uninstall manifest. Absence requires
-- authority (root AGENTS.md): an incomplete artefact list must never read as
-- the complete list of what will be deleted, so the flag is stored per-row
-- rather than assumed by the reader.
CREATE TABLE removal_campaign_dry_runs (
    id                            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id                   UUID         NOT NULL REFERENCES removal_campaigns(id) ON DELETE CASCADE,
    tenant_id                     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    computed_at                   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    computed_by                   TEXT         NOT NULL DEFAULT '',
    device_count                  INT          NOT NULL DEFAULT 0 CHECK (device_count >= 0),
    -- [{"version": "1.2.3", "device_count": 4}, ...]; a NULL/absent reported
    -- version is carried as the literal "unknown" bucket, never dropped.
    version_spread                JSONB        NOT NULL DEFAULT '[]',
    -- [{"device_id": ..., "hostname": ..., "os": ..., "versions": [...],
    --   "paths": [...], "evidence_basis": "identifier_match"|"name_match_only"}, ...]
    devices                       JSONB        NOT NULL DEFAULT '[]',
    -- Weakest-instance evidence grade across every matched device, same
    -- vocabulary as AppPolicyRow.EvidenceBasis (PAT-1725).
    evidence_basis                TEXT         NOT NULL DEFAULT 'unknown'
                                      CHECK (evidence_basis IN ('identifier_match', 'name_match_only', 'unknown')),
    -- Tenant devices that have never reported a single application row. They
    -- are neither in nor out of scope — the platform has no authority to say
    -- the product is absent from them.
    devices_without_app_inventory INT          NOT NULL DEFAULT 0 CHECK (devices_without_app_inventory >= 0),
    artefacts                     JSONB        NOT NULL DEFAULT '[]',
    artefact_basis                TEXT         NOT NULL DEFAULT 'none'
                                      CHECK (artefact_basis IN ('observed_paths', 'known_app_bundles', 'observed_and_known', 'none')),
    artefact_enumeration_complete BOOLEAN      NOT NULL DEFAULT false,
    -- What removal leaves behind. Always reported as residue, never as
    -- removed: the platform does not delete user data and must not imply it.
    residue                       JSONB        NOT NULL DEFAULT '[]',
    protected_match               JSONB,
    excluded_device_count         INT          NOT NULL DEFAULT 0 CHECK (excluded_device_count >= 0),
    inventory_watermark           TIMESTAMPTZ
);

CREATE INDEX idx_removal_campaign_dry_runs_campaign
    ON removal_campaign_dry_runs (campaign_id, computed_at DESC);

GRANT SELECT, INSERT ON TABLE removal_campaign_dry_runs TO patched;

-- ── Authorisations (append-only) ──────────────────────────────────────────
-- One authorisation per campaign (UNIQUE campaign_id): a second authoriser
-- is a second campaign, so the log always reads left-to-right as the true
-- sequence — the same rule tenant_software_exceptions' no-un-accept path
-- follows (0142).
--
-- The row is only ever written by the authorise handler, which refuses
-- unless: the cited dry run is the campaign's most recent AND is not stale,
-- the target matches no protected_software row for this tenant (re-checked
-- inside the same transaction, not trusted from the dry run), and
-- authorized_by, authorization_clause and a policy decision are all present.
-- The NOT NULL + non-blank CHECKs below are the database's own copy of the
-- last of those: a blank authoriser or clause cannot be stored even by a
-- caller that bypasses the handler.
--
-- policy_id carries no foreign key on purpose. policy_snapshot holds the
-- tenant_app_policies row as it stood at the moment of authorisation, so the
-- record answers "what decision was this removal authorised against" even
-- after the policy is edited or deleted. A live FK would answer "what does
-- that policy say now", which is a different and weaker question.
CREATE TABLE removal_campaign_authorizations (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id          UUID         NOT NULL UNIQUE REFERENCES removal_campaigns(id) ON DELETE CASCADE,
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dry_run_id           UUID         NOT NULL REFERENCES removal_campaign_dry_runs(id) ON DELETE CASCADE,
    authorized_by        TEXT         NOT NULL CHECK (btrim(authorized_by) <> ''),
    authorization_clause TEXT         NOT NULL CHECK (btrim(authorization_clause) <> ''),
    policy_id            BIGINT,
    policy_snapshot      JSONB        NOT NULL DEFAULT '{}',
    authorized_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_removal_campaign_authorizations_tenant
    ON removal_campaign_authorizations (tenant_id, authorized_at DESC);

GRANT SELECT, INSERT ON TABLE removal_campaign_authorizations TO patched;

-- ── Append-only enforcement ───────────────────────────────────────────────
-- Same intent as tenant_software_exception_changes (0142) and
-- tenant_shadow_it_policy_changes (0104), with one deliberate addition: the
-- DELETE branch permits the row to go when its tenant row has already been
-- deleted in the same transaction.
--
-- Why that exemption exists: these tables cascade from tenants, and a
-- BEGIN..DELETE FROM tenants..COMMIT runs the cascade as an AFTER trigger,
-- by which point the tenants row is gone. Without the exemption, tenant
-- erasure would fail outright wherever a campaign had ever been previewed.
-- With it, erasing a tenant still erases their records, while every ordinary
-- delete is refused — including deleting the parent campaign, which cascades
-- here, finds the tenant still present, and is therefore blocked. That last
-- part matters: an authorisation you could erase by deleting its campaign
-- would not be append-only in any sense that survives contact with someone
-- who wants it gone.
CREATE FUNCTION reject_removal_evidence_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        -- Tenant erasure: the owning tenant row is already gone in this
        -- transaction, so this is a cascade from that erasure, not an edit.
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only: % is not permitted on row id=%', TG_TABLE_NAME, TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION reject_removal_evidence_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: TRUNCATE is not permitted', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_removal_campaign_dry_runs_append_only
    BEFORE UPDATE OR DELETE ON removal_campaign_dry_runs
    FOR EACH ROW EXECUTE FUNCTION reject_removal_evidence_mutation();

CREATE TRIGGER trg_removal_campaign_dry_runs_append_only_truncate
    BEFORE TRUNCATE ON removal_campaign_dry_runs
    FOR EACH STATEMENT EXECUTE FUNCTION reject_removal_evidence_truncate();

CREATE TRIGGER trg_removal_campaign_authorizations_append_only
    BEFORE UPDATE OR DELETE ON removal_campaign_authorizations
    FOR EACH ROW EXECUTE FUNCTION reject_removal_evidence_mutation();

CREATE TRIGGER trg_removal_campaign_authorizations_append_only_truncate
    BEFORE TRUNCATE ON removal_campaign_authorizations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_removal_evidence_truncate();

COMMENT ON TABLE removal_campaigns IS
    'PAT-1598: an authorised-removal campaign targeting one product for one tenant. Platform record only — no agent-facing delivery path reads this table.';
COMMENT ON TABLE removal_campaign_dry_runs IS
    'PAT-1598: append-only preview snapshot of what a removal would affect, computed from live inventory. Cited by an authorisation, which is refused if the snapshot is stale.';
COMMENT ON TABLE removal_campaign_authorizations IS
    'PAT-1598: append-only record of who authorised a removal, under which contract clause, against which governance decision and which preview.';

INSERT INTO schema_migrations (version) VALUES ('0145_removal_campaigns')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
