-- 0216: kernel driver observations and vulnerable driver blocklists (PAT-2263)
--
-- Answers "is a known vulnerable driver present, and is Windows blocking it"
-- (bring your own vulnerable driver attacks), for every vendor, with no
-- connector.
--
-- Device side, from the Windows agent's top-level payload block
-- "kernel_drivers" (see internal/extractor/kernel_drivers.go for the wire
-- shape):
--
--   device_kernel_driver_observations  one header row per report that carried
--                                      the block: status, errors, enforcement
--                                      state and counts, exactly as reported.
--                                      Immutable: UPDATE is rejected by
--                                      trigger. Idempotent on raw_payload_id.
--                                      The driver rows of each report stay in
--                                      the immutable raw_payloads archive.
--   device_kernel_driver_state         one row per device: the newest
--                                      report's header. An older replay never
--                                      overwrites a newer report.
--   device_kernel_drivers              the current driver rows per device,
--                                      keyed by case-folded path (or service
--                                      name when the path was unresolvable).
--                                      complete replaces the set; partial
--                                      upserts and removes nothing;
--                                      unavailable changes nothing.
--
-- Not reported versus unavailable: a device with no state row never sent the
-- block (an agent older than PAT-2263, or macOS); a state row whose
-- collection_status is 'unavailable' is an agent that tried and could not
-- read its driver list. The two are never collapsed.
--
-- List side, refreshed nightly by patched-cve-sync (--mode=scheduled, or
-- --mode=driver-blocklist-sync), package internal/driverblock:
--
--   driver_blocklist_source_state      one row per source (Microsoft
--                                      recommended driver block rules,
--                                      loldrivers.io): the last successful
--                                      fetch time and list version, and the
--                                      latest attempt's outcome. A failed
--                                      refresh records the failure and never
--                                      touches the entries: the last good list
--                                      stays and its age is reported.
--   driver_blocklist_entries           one row per listed hash. Matching is by
--                                      hash only, never by file name. SHA-1 is
--                                      stored only for a list record that has
--                                      no SHA-256 of the same kind. loldrivers
--                                      malicious-driver entries are kept with
--                                      category 'malicious', apart from the
--                                      'vulnerable' ones.
--
-- Global list tables carry no tenant data. Device tables are derived from the
-- immutable raw_payloads archive and can be rebuilt by re-extraction; list
-- tables are rebuilt by the next refresh. The rollback loses nothing either
-- cannot restore.
BEGIN;

CREATE TABLE device_kernel_driver_observations (
    id                           BIGSERIAL PRIMARY KEY,
    tenant_id                    UUID NOT NULL,
    device_id                    UUID NOT NULL,
    raw_payload_id               BIGINT NOT NULL UNIQUE,
    raw_payload_received_at      TIMESTAMPTZ NOT NULL,
    -- the agent's collected_at; NULL when it did not parse
    observed_at                  TIMESTAMPTZ,
    block_schema_version         SMALLINT NOT NULL CHECK (block_schema_version >= 1),
    collection_status            TEXT NOT NULL CHECK (collection_status IN ('complete','partial','unavailable')),
    errors                       TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(errors) <= 16),
    vulnerable_driver_blocklist  TEXT NOT NULL CHECK (vulnerable_driver_blocklist IN ('enabled','disabled','not_set','unknown')),
    hvci                         TEXT NOT NULL CHECK (hvci IN ('running','configured','off','unknown')),
    smart_app_control            TEXT NOT NULL CHECK (smart_app_control IN ('on','evaluation','off','not_present','unknown')),
    code_integrity_policy        TEXT NOT NULL CHECK (code_integrity_policy IN ('enforced','audit','off','unknown')),
    blocklist_enforced           TEXT NOT NULL CHECK (blocklist_enforced IN ('yes','no','unknown')),
    -- NULL when the block was unavailable (no list was sent)
    driver_count                 INTEGER CHECK (driver_count >= 0 AND driver_count <= 1500),
    hashed_count                 INTEGER NOT NULL DEFAULT 0 CHECK (hashed_count >= 0),
    unhashed_count               INTEGER NOT NULL DEFAULT 0 CHECK (unhashed_count >= 0),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    CHECK ((collection_status = 'unavailable') = (driver_count IS NULL))
);
CREATE INDEX device_kernel_driver_observations_device_idx
    ON device_kernel_driver_observations (tenant_id, device_id, raw_payload_received_at DESC, id DESC);

CREATE FUNCTION reject_device_kernel_driver_observation_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'device_kernel_driver_observations evidence is immutable: UPDATE is not permitted on id=%', OLD.id;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_device_kernel_driver_observations_reject_update
    BEFORE UPDATE ON device_kernel_driver_observations
    FOR EACH ROW EXECUTE FUNCTION reject_device_kernel_driver_observation_update();

CREATE TABLE device_kernel_driver_state (
    device_id                    UUID PRIMARY KEY,
    tenant_id                    UUID NOT NULL,
    observation_id               BIGINT NOT NULL REFERENCES device_kernel_driver_observations(id) ON DELETE CASCADE,
    reported_at                  TIMESTAMPTZ NOT NULL,
    observed_at                  TIMESTAMPTZ,
    collection_status            TEXT NOT NULL CHECK (collection_status IN ('complete','partial','unavailable')),
    errors                       TEXT[] NOT NULL DEFAULT '{}',
    vulnerable_driver_blocklist  TEXT NOT NULL,
    hvci                         TEXT NOT NULL,
    smart_app_control            TEXT NOT NULL,
    code_integrity_policy        TEXT NOT NULL,
    blocklist_enforced           TEXT NOT NULL,
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX device_kernel_driver_state_tenant_idx ON device_kernel_driver_state (tenant_id, collection_status);

CREATE TABLE device_kernel_drivers (
    device_id                    UUID NOT NULL,
    tenant_id                    UUID NOT NULL,
    -- 'path:' || lower(path), or 'service:' || lower(service_name)
    driver_key                   TEXT NOT NULL CHECK (char_length(driver_key) <= 530),
    path                         TEXT CHECK (char_length(path) <= 512),
    service_name                 TEXT CHECK (char_length(service_name) <= 256),
    service_type                 TEXT CHECK (service_type IN ('kernel','file_system')),
    start_type                   TEXT CHECK (start_type IN ('boot','system','auto','demand','disabled')),
    -- NULL when the loaded-module list could not be read
    loaded                       BOOLEAN,
    sources                      TEXT[] NOT NULL,
    hash_status                  TEXT NOT NULL CHECK (hash_status IN ('hashed','unhashed')),
    unhashed_reason              TEXT CHECK (char_length(unhashed_reason) <= 64),
    size_bytes                   BIGINT CHECK (size_bytes >= 0),
    sha256                       TEXT CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    sha1                         TEXT CHECK (sha1 ~ '^[0-9a-f]{40}$'),
    authenticode_sha256          TEXT CHECK (authenticode_sha256 ~ '^[0-9a-f]{64}$'),
    authenticode_sha1            TEXT CHECK (authenticode_sha1 ~ '^[0-9a-f]{40}$'),
    version                      TEXT CHECK (char_length(version) <= 32),
    observation_id               BIGINT NOT NULL REFERENCES device_kernel_driver_observations(id) ON DELETE CASCADE,
    reported_at                  TIMESTAMPTZ NOT NULL,
    first_seen_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, driver_key),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE,
    CHECK (path IS NOT NULL OR service_name IS NOT NULL),
    -- a hashed row carries its flat digests; an unhashed row carries none
    CHECK (hash_status <> 'hashed' OR (sha256 IS NOT NULL AND sha1 IS NOT NULL)),
    CHECK (hash_status <> 'unhashed'
           OR (sha256 IS NULL AND sha1 IS NULL AND authenticode_sha256 IS NULL AND authenticode_sha1 IS NULL))
);
CREATE INDEX device_kernel_drivers_tenant_idx ON device_kernel_drivers (tenant_id, device_id);
CREATE INDEX device_kernel_drivers_sha256_idx ON device_kernel_drivers (sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX device_kernel_drivers_sha1_idx ON device_kernel_drivers (sha1) WHERE sha1 IS NOT NULL;
CREATE INDEX device_kernel_drivers_auth_sha256_idx ON device_kernel_drivers (authenticode_sha256) WHERE authenticode_sha256 IS NOT NULL;
CREATE INDEX device_kernel_drivers_auth_sha1_idx ON device_kernel_drivers (authenticode_sha1) WHERE authenticode_sha1 IS NOT NULL;

CREATE TABLE driver_blocklist_source_state (
    source                       TEXT PRIMARY KEY CHECK (source IN ('microsoft_driver_blocklist','loldrivers')),
    source_url                   TEXT NOT NULL,
    -- the latest attempt
    status                       TEXT NOT NULL CHECK (status IN ('succeeded','failed')),
    attempted_at                 TIMESTAMPTZ NOT NULL,
    -- the last successful fetch; kept through later failures
    fetched_at                   TIMESTAMPTZ,
    source_revision              TEXT NOT NULL DEFAULT '' CHECK (char_length(source_revision) <= 128),
    entry_count                  INTEGER NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
    -- a fixed, bounded description of the latest failure; never response content
    last_error                   TEXT CHECK (char_length(last_error) <= 512),
    CHECK (status <> 'succeeded' OR fetched_at IS NOT NULL)
);

CREATE TABLE driver_blocklist_entries (
    source                       TEXT NOT NULL REFERENCES driver_blocklist_source_state(source) ON DELETE CASCADE,
    hash_kind                    TEXT NOT NULL CHECK (hash_kind IN ('sha256','sha1','authenticode_sha256','authenticode_sha1')),
    hash                         TEXT NOT NULL,
    -- the list's own id for the record (SiPolicy Deny ID, loldrivers Id)
    entry_id                     TEXT NOT NULL CHECK (char_length(entry_id) <= 128),
    entry_name                   TEXT NOT NULL DEFAULT '' CHECK (char_length(entry_name) <= 256),
    category                     TEXT NOT NULL CHECK (category IN ('vulnerable','malicious')),
    fetched_at                   TIMESTAMPTZ NOT NULL,
    source_revision              TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source, hash_kind, hash, entry_id),
    CHECK ((hash_kind IN ('sha256','authenticode_sha256') AND hash ~ '^[0-9a-f]{64}$')
        OR (hash_kind IN ('sha1','authenticode_sha1') AND hash ~ '^[0-9a-f]{40}$'))
);
CREATE INDEX driver_blocklist_entries_hash_idx ON driver_blocklist_entries (hash_kind, hash);

COMMENT ON TABLE device_kernel_driver_observations IS
    'PAT-2263: the kernel_drivers block header (status, errors, blocklist enforcement, counts) of one report, as reported. Immutable.';
COMMENT ON TABLE device_kernel_driver_state IS
    'PAT-2263: newest kernel_drivers header per device. No row = never reported. Derived; rebuilt by re-extraction.';
COMMENT ON TABLE device_kernel_drivers IS
    'PAT-2263: current kernel and file-system driver rows per device, with hashes. complete replaces, partial upserts, unavailable leaves. Derived; rebuilt by re-extraction.';
COMMENT ON TABLE driver_blocklist_source_state IS
    'PAT-2263: last good fetch and latest attempt per vulnerable driver list source. A failed refresh never empties the list.';
COMMENT ON TABLE driver_blocklist_entries IS
    'PAT-2263: listed driver hashes from Microsoft recommended driver block rules and loldrivers.io. Match by hash only.';

GRANT SELECT, INSERT ON device_kernel_driver_observations TO patched;
GRANT USAGE, SELECT ON SEQUENCE device_kernel_driver_observations_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE ON device_kernel_driver_state TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_kernel_drivers TO patched;
GRANT SELECT, INSERT, UPDATE ON driver_blocklist_source_state TO patched;
GRANT SELECT, INSERT, DELETE ON driver_blocklist_entries TO patched;

INSERT INTO schema_migrations (version) VALUES ('0216_kernel_drivers_and_driver_blocklists')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
