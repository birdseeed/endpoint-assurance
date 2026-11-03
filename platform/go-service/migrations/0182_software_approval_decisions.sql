-- patched.im - 0182_software_approval_decisions.sql
-- PAT-2007: audit of software approval decisions made through the customer
-- portal (PUT /v1/portal/software-approvals).
--
-- The decision itself is written into the existing policy store
-- (tenant_app_policies for applications, tenant_extension_policies for
-- browser extensions); this table only records each change: who (the
-- verified portal email), when, the previous state, the new state and the
-- optional reason. One row per product whose state actually changed. A write
-- that leaves a product in the state it was already in records nothing.
--
-- State vocabulary is the portal's, not the storage one:
--   unreviewed  no policy row for the product
--   approved    policy 'approved'
--   unapproved  policy 'unapproved'
--   ignored     policy 'unmanaged' (applications) or 'ignored' (extensions)
--   mandatory   previous_state only: an operator-set mandatory row. The
--               portal refuses to change those, so it never appears as a
--               new_state and in practice not as a previous_state either.
--
-- tenant_id deliberately has NO foreign key to tenants, following
-- tenant_decommission_audit (0091): an ON DELETE CASCADE would be a real
-- DELETE that the append-only trigger below rejects, which would make tenant
-- purge fail (0096 documents that conflict for four older tables).
--
-- Append-only (0096 pattern): UPDATE, DELETE and TRUNCATE are rejected by
-- trigger. As AGENTS.md records for the other audit ledgers, this stops an
-- accidental write. It does not stop the owning role, `patched`, which runs
-- both the migrations and the application and so can disable the trigger or
-- drop the table. Do not describe this table as tamper-proof.
--
-- Apply with:
--   psql -h 127.0.0.1 -U patched -d patched -v ON_ERROR_STOP=1 -f migrations/0182_software_approval_decisions.sql

BEGIN;

CREATE TABLE software_approval_decisions (
    id                BIGSERIAL   PRIMARY KEY,
    tenant_id         UUID        NOT NULL,
    -- One bulk call shares one batch_id, so a history reader can see which
    -- changes were made together.
    batch_id          UUID        NOT NULL,
    product_type      TEXT        NOT NULL CHECK (product_type IN ('application', 'browser_extension')),
    -- Stable lookup key for one product's history, built by the API from the
    -- normalised identity below:
    --   application:<platform>:<lower(identifier)>[:<TEAMID>]
    --   browser_extension:<browser>:<extension_id>
    product_key       TEXT        NOT NULL CHECK (btrim(product_key) <> '' AND length(product_key) <= 700),
    platform          TEXT        CHECK (platform IN ('macos', 'windows')),
    identifier        TEXT        NOT NULL CHECK (btrim(identifier) <> '' AND length(identifier) <= 512),
    team_id           TEXT        CHECK (team_id IS NULL OR length(team_id) <= 64),
    browser           TEXT        CHECK (browser IN ('chrome', 'edge', 'firefox', 'safari', 'any')),
    previous_state    TEXT        NOT NULL
                                  CHECK (previous_state IN ('unreviewed', 'approved', 'unapproved', 'ignored', 'mandatory')),
    new_state         TEXT        NOT NULL
                                  CHECK (new_state IN ('unreviewed', 'approved', 'unapproved', 'ignored')),
    reason            TEXT        CHECK (reason IS NULL OR (btrim(reason) <> '' AND char_length(reason) <= 1000)),
    actor_email       TEXT        NOT NULL CHECK (actor_email = lower(actor_email) AND btrim(actor_email) <> ''),
    source            TEXT        NOT NULL DEFAULT 'portal' CHECK (source IN ('portal')),
    -- True when a product on the tenant's effective protected-software list
    -- (PAT-1801) was set to unapproved. The write still succeeded.
    protected_warning BOOLEAN     NOT NULL DEFAULT FALSE,
    decided_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (previous_state <> new_state),
    CHECK ((product_type = 'application' AND platform IS NOT NULL AND browser IS NULL)
        OR (product_type = 'browser_extension' AND platform IS NULL AND team_id IS NULL AND browser IS NOT NULL))
);

CREATE INDEX software_approval_decisions_tenant_idx
    ON software_approval_decisions (tenant_id, decided_at DESC, id DESC);
CREATE INDEX software_approval_decisions_product_idx
    ON software_approval_decisions (tenant_id, product_key, decided_at DESC, id DESC);

CREATE FUNCTION reject_software_approval_decisions_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_approval_decisions is append-only: % is not permitted on row id=%', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_software_approval_decisions_append_only
    BEFORE UPDATE OR DELETE ON software_approval_decisions
    FOR EACH ROW
    EXECUTE FUNCTION reject_software_approval_decisions_mutation();

CREATE FUNCTION reject_software_approval_decisions_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'software_approval_decisions is append-only: TRUNCATE is not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_software_approval_decisions_append_only_truncate
    BEFORE TRUNCATE ON software_approval_decisions
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_software_approval_decisions_truncate();

COMMENT ON TABLE software_approval_decisions IS
    'Append-only audit of customer portal software approval decisions (PAT-2007). UPDATE, DELETE and TRUNCATE are rejected by trigger, including for the owning role; the owning role can still disable the trigger, so this is not tamper-proof. No FK to tenants on purpose (survives tenant purge, 0091 pattern).';

GRANT SELECT, INSERT ON TABLE software_approval_decisions TO patched;
GRANT USAGE, SELECT ON SEQUENCE software_approval_decisions_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0182_software_approval_decisions')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
