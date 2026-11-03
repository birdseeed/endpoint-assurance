-- 0192: automatic CPE mapping proposals (PAT-2138)
--
-- A product with no app_cpe_mappings row is never CVE-matched: it reads
-- "not assessed" until someone hand-maps it, and there are 46 application
-- mappings for about 107 distinct installed names on patched-api-01. This
-- migration adds the durable state for proposing mappings automatically
-- without letting a guess become a CVE claim:
--
--   cpe_mapping_proposals        one row per normalised (platform, name) with
--                                no mapping. The extractor records it inside
--                                the ingest transaction (no network); the
--                                proposer worker (internal/cpepropose) later
--                                adds NVD CPE dictionary candidates, the
--                                model's choice among them and the signer
--                                evidence, and either auto-publishes it or
--                                leaves it needs_review for staff.
--   cpe_mapping_proposal_audit   append-only who/when/before/after for every
--                                state change, automatic or staff.
--   cpe_dictionary_cache         NVD /cpes/2.0 keyword-search results, so a
--                                repeat query never reaches NVD again inside
--                                the TTL.
--   cpe_vendor_aliases           the curated signer -> CPE vendor table the
--                                auto-publish gate uses for deterministic
--                                corroboration, outside the model. Seeded
--                                below with the evidence for each row.
--   cpe_proposer_status          the worker's own health (ok, degraded with a
--                                reason such as model_unavailable, disabled)
--                                and the review digest's Linear issue state,
--                                so a silent failure is visible on the admin
--                                API, not only in a log line.
--   cpe_nvd_budget               one row: when any proposer process last sent
--                                an NVD CPE dictionary request, so the
--                                proposer's NVD budget (a tenth of NVD's
--                                limit) is shared across processes and never
--                                starves patched-cve-sync.
--   cpe_proposal_origins         which tenant's ingest admitted each
--                                proposal, for the per-tenant admission caps
--                                (new per 24 hours, open at once). Internal
--                                only; the proposal row stays tenant-free.
--
-- Two existing constraints are widened (supersets: every current row still
-- satisfies them):
--
--   app_cpe_mappings.review_state      gains 'auto': a mapping the proposer
--                                      published because the model chose it
--                                      with high confidence AND a signer or
--                                      publisher alias corroborated its
--                                      vendor. Application mappings only.
--   device_cve_findings.mapping_basis  gains 'auto': a finding produced only
--                                      by 'auto' mappings. NULL on an
--                                      application finding still means a
--                                      hand-curated mapping produced it.
--
-- app_cpe_mappings and device_cve_findings are owned by patched on
-- patched-api-01 (checked 2026-09-25), which runs migrations, and both
-- constraint names were read from the live catalogue on 2026-09-25:
-- app_cpe_mappings_review_state_check and
-- device_cve_findings_mapping_basis_check (both created by 0168, above
-- MIGRATION_FLOOR, so the live shape matches the migrations). No foreign key
-- references app_cpe_mappings: a proposal records the mapping id it
-- published, and a mapping removed by any path is detected by the worker.
--
-- Additive only. No existing row changes.
BEGIN;

-- The one product-name normalisation (PAT-2138 re-review, P3-b), identical
-- to cpepropose.NormalizeName and cpepropose's token form in Go and
-- independent of the database collation: ASCII A-Z lowered (translate, not
-- lower(), whose non-ASCII behaviour depends on the collation), runs of ASCII
-- whitespace (space, tab, LF, CR, FF, VT) collapsed to one space, trimmed.
-- Non-ASCII letters and Unicode spaces are left as they are, on both sides.
-- Inlinable SQL functions, so expression indexes on them are used.
CREATE FUNCTION cpe_normalize_name(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN btrim(regexp_replace(translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),
                                '[ \t\n\r\f\v]+', ' ', 'g'));
-- The word-token form an automatic mapping's coverage compares: ASCII
-- lowered, every run of characters other than a-z and 0-9 one space.
CREATE FUNCTION cpe_name_tokens(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN btrim(regexp_replace(translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),
                                '[^a-z0-9]+', ' ', 'g'));
GRANT EXECUTE ON FUNCTION cpe_normalize_name(text), cpe_name_tokens(text) TO patched;

ALTER TABLE app_cpe_mappings
    DROP CONSTRAINT app_cpe_mappings_review_state_check,
    ADD CONSTRAINT app_cpe_mappings_review_state_check
        CHECK (review_state IN ('curated', 'auto_seeded', 'auto')),
    ADD CONSTRAINT app_cpe_mappings_auto_is_app_name
        CHECK (review_state <> 'auto' OR source_type = 'app_name');

ALTER TABLE device_cve_findings
    DROP CONSTRAINT device_cve_findings_mapping_basis_check,
    ADD CONSTRAINT device_cve_findings_mapping_basis_check
        CHECK (mapping_basis IN ('curated', 'auto_seeded', 'auto'));

COMMENT ON COLUMN device_cve_findings.mapping_basis IS
    'PAT-2023/PAT-2138: curated or auto_seeded on Homebrew findings; auto on an application finding produced only by an automatically published CPE mapping (PAT-2138). NULL on an application finding = a hand-curated mapping produced it.';

CREATE TABLE cpe_mapping_proposals (
    id                  BIGSERIAL PRIMARY KEY,
    platform            TEXT NOT NULL CHECK (platform IN ('macos', 'windows')),
    -- lower(btrim()) with whitespace runs collapsed: the identity a proposal
    -- is recorded once for.
    normalized_name     TEXT NOT NULL CHECK (
                            normalized_name <> ''
                            AND normalized_name = cpe_normalize_name(normalized_name)
                            AND char_length(normalized_name) <= 200),
    -- The first-seen display name, used as match_name when published.
    display_name        TEXT NOT NULL CHECK (btrim(display_name) <> '' AND char_length(display_name) <= 200),
    state               TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
                            'pending', 'needs_review', 'auto_published',
                            'approved', 'rejected', 'superseded', 'expired')),
    state_reason        TEXT CHECK (state_reason IS NULL OR state_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    candidates          JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(candidates) = 'array'),
    candidates_fetched_at TIMESTAMPTZ,
    model_id            TEXT CHECK (model_id IS NULL OR char_length(model_id) <= 100),
    -- "vendor:product" from the candidate list, or 'none'.
    model_choice        TEXT CHECK (model_choice IS NULL OR char_length(model_choice) <= 300),
    model_confidence    TEXT CHECK (model_confidence IS NULL OR model_confidence IN ('high', 'medium', 'low')),
    model_rationale     TEXT CHECK (model_rationale IS NULL OR char_length(model_rationale) <= 600),
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence) = 'object'),
    chosen_cpe_vendor   TEXT,
    chosen_cpe_product  TEXT,
    mapping_id          BIGINT,
    attempts            INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error          TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 500),
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    proposed_at         TIMESTAMPTZ,
    decided_at          TIMESTAMPTZ,
    decided_by          TEXT,
    -- When an auto_published proposal's evidence was last re-checked
    -- against the gate (the worker demotes it when it no longer passes).
    rechecked_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform, normalized_name),
    CONSTRAINT cpe_mapping_proposals_chosen_pair
        CHECK ((chosen_cpe_vendor IS NULL) = (chosen_cpe_product IS NULL)),
    CONSTRAINT cpe_mapping_proposals_published_shape CHECK (
        (state IN ('auto_published', 'approved')) = (mapping_id IS NOT NULL)
        AND (state NOT IN ('auto_published', 'approved') OR chosen_cpe_vendor IS NOT NULL))
);
CREATE INDEX cpe_mapping_proposals_work_idx
    ON cpe_mapping_proposals (next_attempt_at, id) WHERE state = 'pending';
CREATE INDEX cpe_mapping_proposals_state_idx
    ON cpe_mapping_proposals (state, first_seen_at);
CREATE INDEX cpe_mapping_proposals_due_review_idx
    ON cpe_mapping_proposals (next_attempt_at, id)
    WHERE state = 'needs_review' AND state_reason IN ('model_unavailable', 'single_tenant', 'corroboration_lost');
CREATE INDEX cpe_mapping_proposals_recheck_idx
    ON cpe_mapping_proposals (rechecked_at NULLS FIRST, id) WHERE state = 'auto_published';

COMMENT ON TABLE cpe_mapping_proposals IS
    'PAT-2138: one automatic CPE mapping proposal per normalised (platform, product name) with no mapping. Global: carries no tenant, device or person identifier. evidence holds only the normalised name, signer values that are in cpe_vendor_aliases and aggregate counts; affected counts on the admin API are computed live.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cpe_mapping_proposals TO patched;
GRANT USAGE, SELECT ON SEQUENCE cpe_mapping_proposals_id_seq TO patched;

CREATE TABLE cpe_mapping_proposal_audit (
    id            BIGSERIAL PRIMARY KEY,
    proposal_id   BIGINT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN (
                      'auto_publish', 'needs_review', 'approve', 'reject',
                      'revoke', 'supersede', 'demote', 'expire', 'reopen')),
    actor         TEXT NOT NULL,
    claimed_actor TEXT,
    source_addr   TEXT,
    before        JSONB,
    after         JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cpe_mapping_proposal_audit_proposal_idx
    ON cpe_mapping_proposal_audit (proposal_id, at);

-- Same append-only shape and the same known limitation as
-- homebrew_review_audit (0176): the triggers stop an accidental write, not
-- the owning role.
CREATE FUNCTION reject_cpe_mapping_proposal_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'cpe_mapping_proposal_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_cpe_mapping_proposal_audit_reject_update
    BEFORE UPDATE OR DELETE ON cpe_mapping_proposal_audit
    FOR EACH ROW EXECUTE FUNCTION reject_cpe_mapping_proposal_audit_mutation();
CREATE TRIGGER trg_cpe_mapping_proposal_audit_reject_truncate
    BEFORE TRUNCATE ON cpe_mapping_proposal_audit
    FOR EACH STATEMENT EXECUTE FUNCTION reject_cpe_mapping_proposal_audit_mutation();

COMMENT ON TABLE cpe_mapping_proposal_audit IS
    'PAT-2138: append-only audit of every CPE mapping proposal state change (automatic publish, needs_review, staff approve/reject, revoke, supersede, and demote: an automatic mapping removed by the re-check or found deleted).';

GRANT SELECT, INSERT ON cpe_mapping_proposal_audit TO patched;
GRANT USAGE, SELECT ON SEQUENCE cpe_mapping_proposal_audit_id_seq TO patched;

CREATE TABLE cpe_dictionary_cache (
    query          TEXT PRIMARY KEY CHECK (query <> '' AND char_length(query) <= 200),
    results        JSONB NOT NULL CHECK (jsonb_typeof(results) = 'array'),
    total_results  INT NOT NULL CHECK (total_results >= 0),
    fetched_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cpe_dictionary_cache TO patched;

CREATE TABLE cpe_vendor_aliases (
    id           BIGSERIAL PRIMARY KEY,
    platform     TEXT NOT NULL CHECK (platform IN ('macos', 'windows')),
    alias_kind   TEXT NOT NULL CHECK (alias_kind IN ('macos_team_id', 'windows_subject_org')),
    alias_value  TEXT NOT NULL CHECK (btrim(alias_value) <> '' AND char_length(alias_value) <= 200),
    cpe_vendor   TEXT NOT NULL CHECK (cpe_vendor ~ '^[a-z0-9][a-z0-9_.\-]*$'),
    evidence     TEXT NOT NULL CHECK (btrim(evidence) <> ''),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (alias_kind, alias_value, cpe_vendor),
    CHECK ((alias_kind = 'macos_team_id' AND platform = 'macos' AND alias_value ~ '^[A-Z0-9]{10}$')
        OR (alias_kind = 'windows_subject_org' AND platform = 'windows'))
);

COMMENT ON TABLE cpe_vendor_aliases IS
    'PAT-2138: curated signer -> NVD CPE vendor aliases. The auto-publish gate requires every current installation''s signer to resolve through this table to the chosen CPE vendor. Reviewed data; the application only reads it.';

GRANT SELECT ON TABLE cpe_vendor_aliases TO patched;
GRANT USAGE, SELECT ON SEQUENCE cpe_vendor_aliases_id_seq TO patched;

-- Seed. Evidence was checked on 2026-09-25. "estate" means the Team ID or
-- Subject DN was read from patched-api-01 software_observations (latest
-- observation of current installations) against the named products;
-- "public" means an independent published source. An alias is fail-safe:
-- a wrong or missing value only sends a proposal to staff review, and a
-- value can only corroborate the one vendor it is recorded against.
INSERT INTO cpe_vendor_aliases (platform, alias_kind, alias_value, cpe_vendor, evidence) VALUES
    ('macos', 'macos_team_id', 'UBF8T346G9', 'microsoft',
     'estate: Edge, Excel, Microsoft Defender, Microsoft Error Reporting signed UBF8T346G9 (patched-api-01, 2026-09-25)'),
    ('macos', 'macos_team_id', 'EQHXZ8M8AV', 'google',
     'estate: Chrome, Google Drive, Google Docs, Google Sheets, Gemini signed EQHXZ8M8AV (patched-api-01, 2026-09-25)'),
    ('macos', 'macos_team_id', '43AQ936H96', 'mozilla',
     'estate: Firefox signed 43AQ936H96 on 3 devices (patched-api-01, 2026-09-25)'),
    ('macos', 'macos_team_id', 'BJ4HAAB9B3', 'zoom',
     'estate: Zoom, ZoomClips, ZoomAutoUpdater signed BJ4HAAB9B3 (patched-api-01, 2026-09-25)'),
    ('macos', 'macos_team_id', 'BQR82RBBHL', 'slack',
     'estate: Slack signed BQR82RBBHL (patched-api-01, 2026-09-25)'),
    ('macos', 'macos_team_id', 'BQR82RBBHL', 'salesforce',
     'estate: Slack signed BQR82RBBHL (patched-api-01, 2026-09-25); Slack is a Salesforce product and NVD files some Slack CVEs under salesforce'),
    ('macos', 'macos_team_id', '74J34U3R6X', 'apple',
     'estate: Numbers and Pages signed 74J34U3R6X (patched-api-01, 2026-09-25); public: App ID 74J34U3R6X.com.apple.iWork.Pages'),
    ('macos', 'macos_team_id', 'JQ525L2MZD', 'adobe',
     'public: Developer ID Application: Adobe Inc. (JQ525L2MZD) on Acrobat and Creative Cloud (community.adobe.com, appcatalog.cloud); not yet observed in the estate'),
    ('macos', 'macos_team_id', 'VB5E2TV963', 'oracle',
     'public: Developer ID Application: Oracle America, Inc. (VB5E2TV963) on VirtualBox and Oracle JDK (forums.virtualbox.org, community.jamf.com); not yet observed in the estate'),
    ('windows', 'windows_subject_org', 'Microsoft Corporation', 'microsoft',
     'estate: Authenticode valid, root_kind microsoft, Subject O=Microsoft Corporation on Microsoft Edge, Microsoft Visual Studio Code, PowerToys (patched-api-01, 2026-09-25)')
ON CONFLICT (alias_kind, alias_value, cpe_vendor) DO NOTHING;

CREATE TABLE cpe_proposer_status (
    component     TEXT PRIMARY KEY CHECK (component IN ('proposer', 'digest')),
    status        TEXT NOT NULL CHECK (status IN ('ok', 'degraded', 'disabled')),
    reason        TEXT CHECK (reason IS NULL OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    detail        JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cpe_proposer_status TO patched;

CREATE TABLE cpe_nvd_budget (
    id               SMALLINT PRIMARY KEY CHECK (id = 1),
    last_request_at  TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00'
);
INSERT INTO cpe_nvd_budget (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE cpe_nvd_budget IS
    'PAT-2138: the CPE proposer''s cross-process NVD request pacing. One row; a proposer process may send an NVD request only when last_request_at is at least its interval ago (6 s with an API key, 60 s without: a tenth of NVD''s limit, leaving the rest to patched-cve-sync).';

GRANT SELECT, UPDATE ON TABLE cpe_nvd_budget TO patched;

CREATE TABLE cpe_proposal_origins (
    proposal_id  BIGINT PRIMARY KEY REFERENCES cpe_mapping_proposals(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admitted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cpe_proposal_origins_tenant_idx
    ON cpe_proposal_origins (tenant_id, admitted_at);

COMMENT ON TABLE cpe_proposal_origins IS
    'PAT-2138: which tenant''s ingest admitted (or reopened) each CPE mapping proposal, for the per-tenant admission caps (new per 24 hours, open at once). Internal only: never returned by the admin API, never sent outside the platform; cpe_mapping_proposals itself stays tenant-free.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE cpe_proposal_origins TO patched;

-- Expression indexes for the proposer's per-name lookups (PAT-2138
-- re-review, performance). Every query that finds a proposal's product in
-- inventory compares the same normalised form (lower case, trimmed,
-- whitespace runs collapsed), or, for the automatic-mapping coverage check,
-- the word-token form; without these each lookup scans all of device_apps.
-- The expressions must stay byte-identical to the queries' (cpepropose,
-- cvepipeline). device_apps and software_installations are owned by patched
-- on patched-api-01 (checked 2026-09-25, 339 and 355 rows), so the plain
-- CREATE INDEX lock is momentary there.
CREATE INDEX device_apps_name_normalized_idx
    ON device_apps ((cpe_normalize_name(name)));
CREATE INDEX device_apps_name_tokens_idx
    ON device_apps ((cpe_name_tokens(name)));
CREATE INDEX software_installations_name_normalized_idx
    ON software_installations (platform, (cpe_normalize_name(current_name)))
    WHERE removed_at IS NULL;

INSERT INTO schema_migrations (version) VALUES ('0192_cpe_mapping_proposals')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
