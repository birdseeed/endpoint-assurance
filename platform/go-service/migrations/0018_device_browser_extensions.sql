-- Migration 0018: device_browser_extensions
-- Browser extension inventory table with server-side permission-risk
-- classification. Collected by the macOS agent (PAT-125); platform-neutral
-- schema for future Windows follow-on (PAT-336).
--
-- DO NOT APPLY — listed here for Andy to run on patched-api-01:
--   psql -h 127.0.0.1 -U patched -d patched -f migrations/0018_device_browser_extensions.sql

BEGIN;

CREATE TABLE device_browser_extensions (
    id               bigserial    PRIMARY KEY,
    device_id        uuid         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    browser          text         NOT NULL,             -- 'chrome' | 'edge' | 'firefox'
    user_account     text         NOT NULL,             -- OS user account (macOS login name)
    profile          text         NOT NULL,             -- browser profile directory name
    extension_id     text         NOT NULL,
    name             text         NOT NULL,
    version          text,                              -- NULL when not reported
    enabled          boolean      NOT NULL DEFAULT true,
    permissions      jsonb        NOT NULL DEFAULT '[]',
    host_permissions jsonb        NOT NULL DEFAULT '[]',
    risk_level       text         NOT NULL DEFAULT 'normal', -- 'normal' | 'elevated'
    first_seen       timestamptz  NOT NULL DEFAULT now(),
    last_seen        timestamptz  NOT NULL DEFAULT now()
);

-- Primary identity: one row per (device, browser, user, profile, extension).
-- user_account is included so two users with identically-named profiles
-- on the same device don't collide.
CREATE UNIQUE INDEX device_browser_extensions_unique
    ON device_browser_extensions (device_id, browser, user_account, profile, extension_id);

-- Report query: fetch elevated extensions for one device efficiently.
CREATE INDEX device_browser_extensions_risk
    ON device_browser_extensions (device_id, risk_level);

INSERT INTO schema_migrations (version, applied_at)
VALUES ('0018_device_browser_extensions', now());

COMMIT;
