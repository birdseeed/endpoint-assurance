-- patched.im - 0154_hmac_compatibility_telemetry.sql
-- PAT-1872: bounded aggregate evidence for retiring transitional HMAC forms.
--
-- Deliberately absent: tenant/device identifiers, bearer tokens, HMAC secrets,
-- signature bytes, timestamps/nonces from request authentication, request
-- bodies, source addresses and user-agent strings. The writer admits at most
-- 64 distinct sanitised agent-version values and folds further values into
-- the reserved Unknown bucket.

BEGIN;

CREATE TABLE hmac_compatibility_telemetry (
    signing_form    TEXT        NOT NULL,
    agent_version   TEXT        NOT NULL,
    accepted_count  BIGINT      NOT NULL DEFAULT 0,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (signing_form, agent_version),
    CONSTRAINT hmac_compatibility_telemetry_form_valid
        CHECK (signing_form IN ('v3', 'targetless_v2', 'body_only', 'Unknown')),
    CONSTRAINT hmac_compatibility_telemetry_version_bounded
        CHECK (LENGTH(agent_version) BETWEEN 1 AND 32),
    CONSTRAINT hmac_compatibility_telemetry_count_positive
        CHECK (accepted_count > 0),
    CONSTRAINT hmac_compatibility_telemetry_time_order
        CHECK (last_seen_at >= first_seen_at)
);

GRANT SELECT, INSERT, UPDATE ON TABLE hmac_compatibility_telemetry TO patched;

COMMENT ON TABLE hmac_compatibility_telemetry IS
    'Estate-wide accepted HMAC form counts by bounded reported agent version. Contains no tenant/device identity or request authentication material; disable writes with HMAC_COMPATIBILITY_TELEMETRY_ENABLED=false.';

INSERT INTO schema_migrations (version) VALUES ('0154_hmac_compatibility_telemetry')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
