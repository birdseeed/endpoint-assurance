-- patched.im — 0102_agent_versions_artifact_envelope.sql
-- PAT-1252: server half of PAT-1248 (Patched-LTD/updater, commit daf68734).
--
-- Windows agent self-update has never worked. The client used to require a
-- symmetric creds\artifact-key that nothing ever wrote. PAT-1248 replaced
-- that verification path with an Ed25519 signed envelope, because the
-- symmetric key (ARTIFACT_SIGNING_KEY) is deliberately absent from
-- patched-api-01 — shipping it to every endpoint would let a single
-- compromised device forge artifacts estate-wide. So the client now expects
-- GET /v1/agent/artifact to carry a signed envelope this table has nowhere
-- to store. This migration adds that column.
--
-- ── Shape: the shared envelope, not a new one ────────────────────────────
--
-- artifact_metadata_signature carries the same {signed_payload, signature,
-- key_id} wire shape as signed_catalogue.envelope (0089) and the
-- agent-config signer (internal/agentconfig/signing.go — see SignBytes'
-- doc comment: "There is deliberately no second signing scheme"). Here,
-- signed_payload base64-decodes to a canonical JSON object carrying
-- version, platform, channel, artifact_url, and artifact_sha256 — the
-- fields PAT-1248's client verifies against the artifact it downloaded.
--
-- ── Why TEXT, not JSONB, not BYTEA ────────────────────────────────────────
--
-- Not BYTEA, unlike signed_catalogue.envelope (0089): that column is
-- streamed back to the client as the ENTIRE raw response body of
-- GET /v1/catalogue, so its own byte-for-byte fidelity to the CI-submitted
-- bytes is the whole design (see 0089's header). This column is instead one
-- field embedded inside a larger Go struct (agentArtifactResp) that
-- GET /v1/agent/artifact always json.Marshal's afresh — version,
-- artifact_url, artifact_sha256, artifact_hmac, and published_at are never
-- passed through raw either. BYTEA would just add an encoding/decoding step
-- (base64 or hex, chosen by us) with no fidelity benefit, since the
-- response is reconstructed either way.
--
-- Not JSONB: Postgres reformats JSONB on write (whitespace stripped, and in
-- general JSONB does not promise to preserve key order or numeric
-- formatting). Round-tripping through JSONB and back out is JSON-equivalent
-- to the input, never guaranteed byte-identical to it — and this repo's own
-- handler code (internal/handlers/agent_artifact.go's
-- AdminRegisterAgentVersionHandler) stores the value as a
-- validated-then-json.Compact'd Go string specifically so GET can serve it
-- back via json.RawMessage with no further transformation. A TEXT column
-- holds exactly those compacted bytes, verbatim; JSONB would silently
-- reintroduce a reformatting step this design goes out of its way to avoid.
-- Nothing here needs Postgres to index into or query the envelope's
-- fields — it is opaque to this server by design (see below) — so JSONB's
-- query/index features buy nothing.
--
-- ── Nullable is required, not incidental ─────────────────────────────────
--
-- Every existing row has no envelope, and no row will until Andy
-- provisions ARTIFACT_SIGNING_KEY and the updater release workflow starts
-- forwarding artifact_metadata_signature (PAT-1255). A NOT NULL column, or
-- any default that fabricated a value, would force this migration to either
-- fail on the existing rows or invent a signature this server cannot
-- produce — patched-api does not hold the Ed25519 private key and must
-- never appear to. GET /v1/agent/artifact omits/nulls the field for any row
-- that has none; that is the designed fail-closed behaviour PAT-1248's
-- client relies on, not a gap to fill in later.
--
-- ── What this server does and does not do with it ────────────────────────
--
-- patched-api validates the envelope's SHAPE on registration (exact three
-- fields, base64-decodable signed_payload/signature, hex-decodable key_id)
-- and, PAT-1256, cross-checks that the decoded signed_payload's own
-- version/platform/channel agree with the same fields on the registration
-- request — see validateArtifactMetadataSignature in
-- internal/handlers/agent_artifact.go — so a malformed value, or a
-- legitimately-signed envelope registered against a row declaring different
-- values, is rejected at the door (400) rather than shipped to every
-- endpoint. It does not, and must not, verify the Ed25519 signature itself:
-- it has no public key to verify against here (unlike CataloguePin for the
-- signed catalogue), and more fundamentally must never become a trust
-- anchor for artifact authenticity — that is the endpoint's job, against
-- its own pinned public key, which is the entire point of PAT-1248's
-- design. The PAT-1256 cross-check only confirms the payload's *contents*
-- agree with the row; it says nothing about whether the payload's
-- *signature* is genuine.
--
-- ── Safe to run against a database with existing rows ────────────────────
--
-- ADD COLUMN with no default and no NOT NULL is a metadata-only change on
-- Postgres 16 (no table rewrite, no per-row work) — every existing row gets
-- NULL, which is the intended "no envelope registered yet" state, and
-- GET /v1/agent/artifact already has to treat that as first-class since it
-- is the state every row is in immediately after this migration applies.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0102_agent_versions_artifact_envelope.sql

BEGIN;

ALTER TABLE agent_versions
    ADD COLUMN IF NOT EXISTS artifact_metadata_signature TEXT
        CHECK (artifact_metadata_signature IS NULL OR length(artifact_metadata_signature) > 0);

COMMENT ON COLUMN agent_versions.artifact_metadata_signature IS
    'PAT-1252/PAT-1248: opaque {signed_payload,signature,key_id} Ed25519 envelope (same shared shape as signed_catalogue.envelope, 0089, and the agent-config signer). signed_payload base64-decodes to a canonical JSON object carrying version, platform, channel, artifact_url, artifact_sha256. Stored as the shape-validated, json.Compact''d request bytes (internal/handlers/agent_artifact.go), served back verbatim via json.RawMessage — never re-derived, never fabricated. NULL means no envelope has been registered for this release (every pre-PAT-1252 row, and any row registered before ARTIFACT_SIGNING_KEY exists, PAT-1255) — GET /v1/agent/artifact omits the field in that case, which is the designed fail-closed behaviour, not a bug. patched-api validates the envelope''s SHAPE only on write and never verifies the Ed25519 signature itself: it does not hold the private key (by design — see PAT-1248) and must never become a trust anchor for artifact authenticity.';

INSERT INTO schema_migrations (version) VALUES ('0102_agent_versions_artifact_envelope')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
