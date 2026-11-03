-- PAT-108: track published collector artifact versions per platform and channel.
-- Used by GET /v1/agent/artifact to resolve the current artifact URL for a given
-- platform/channel combination. Registered by the CI release pipeline.

CREATE TABLE agent_versions (
    id            BIGSERIAL    PRIMARY KEY,
    platform      TEXT         NOT NULL CHECK (platform IN ('macos', 'windows')),
    channel       TEXT         NOT NULL CHECK (channel  IN ('stable', 'beta')),
    version       TEXT         NOT NULL,
    artifact_url  TEXT         NOT NULL,
    artifact_sha256 TEXT       NOT NULL,   -- hex SHA-256 of the tarball
    artifact_hmac TEXT         NOT NULL,   -- hex HMAC-SHA256(tarball, ARTIFACT_SIGNING_KEY)
    released_by   TEXT         NOT NULL DEFAULT 'ci',
    published_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (platform, channel, version)
);

CREATE INDEX agent_versions_latest_idx
    ON agent_versions (platform, channel, published_at DESC);
