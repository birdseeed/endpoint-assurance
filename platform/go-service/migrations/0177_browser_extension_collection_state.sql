-- 0177: browser extension completeness (PAT-2055)
--
-- browser_extensions[] is a plain array with no completeness state. A browser
-- profile the agent refused or could not read (PAT-2052 Windows, PAT-2054
-- macOS) sends no rows, and neither does a user crowded out by the macOS
-- collector's 1,000-row cap. The server cannot tell "none" from "could not
-- read", so no absence conclusion drawn from device_browser_extensions has
-- authority behind it.
--
-- The optional payload block browser_extensions_status carries that
-- authority. These two tables store it:
--
--   browser_extension_device_state      one row per device: the newest
--                                       block-level status, whether the
--                                       collector hit its cap, and
--                                       last_complete_at, the newest
--                                       complete or not_present uncapped
--                                       report.
--   browser_extension_collection_state  one row per (device, user, browser):
--                                       the newest status for that pair and
--                                       its own last_complete_at.
--
-- last_complete_at is the same stamp the report wrote into
-- device_browser_extensions.last_seen (clock_timestamp() read under the
-- device row lock), so "a complete report after this extension was last
-- seen" is a direct, strictly-after comparison that orders concurrent
-- extractions by lock acquisition. reported_at is the payload's raw_payloads.received_at and only
-- ever moves forward, so an older replay never writes over a newer report.
--
-- A device with no row here has never sent the block (an agent that predates
-- PAT-2055): its extensions keep the pre-PAT-2055 behaviour exactly.
--
-- Additive only. device_browser_extensions is untouched and still never
-- deletes; raw_payloads keeps every block, so a re-apply plus re-extraction
-- rebuilds these tables.

BEGIN;

CREATE TABLE browser_extension_device_state (
    device_id          UUID PRIMARY KEY,
    tenant_id          UUID NOT NULL,
    collection_status  TEXT NOT NULL
                       CHECK (collection_status IN ('complete','partial','not_present','failed')),
    cap_reached        BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at        TIMESTAMPTZ NOT NULL,
    last_complete_at   TIMESTAMPTZ,
    -- Set when a structurally valid block was inconsistent (with itself or
    -- with the browser_extensions rows): the report was stored as partial
    -- with no authority. A fixed reason token, never a payload value.
    authority_withheld TEXT,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT cap_reached OR collection_status IN ('partial','failed')),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX browser_extension_device_state_tenant_idx
    ON browser_extension_device_state (tenant_id, collection_status);

CREATE TABLE browser_extension_collection_state (
    device_id          UUID NOT NULL,
    tenant_id          UUID NOT NULL,
    -- Bounded exactly like device_browser_extensions.user_account (0085) so
    -- the pair joins on the stored, truncated value.
    user_account       TEXT NOT NULL CHECK (char_length(user_account) BETWEEN 1 AND 128),
    browser            TEXT NOT NULL CHECK (browser IN ('chrome','edge','firefox')),
    collection_status  TEXT NOT NULL
                       CHECK (collection_status IN ('complete','partial','not_present','failed')),
    reported_at        TIMESTAMPTZ NOT NULL,
    last_complete_at   TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, user_account, browser),
    FOREIGN KEY (device_id, tenant_id) REFERENCES devices(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX browser_extension_collection_state_tenant_idx
    ON browser_extension_collection_state (tenant_id);

GRANT SELECT, INSERT, UPDATE ON browser_extension_device_state TO patched;
GRANT SELECT, INSERT, UPDATE ON browser_extension_collection_state TO patched;

INSERT INTO schema_migrations (version) VALUES ('0177_browser_extension_collection_state')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
