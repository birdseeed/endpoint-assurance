-- patched.im — 0089_signed_catalogue.sql
-- PAT-495: durable storage for the CI-signed, Ed25519-signed global app
-- catalogue (content-hash pinning data) served verbatim at GET /v1/catalogue.
--
-- Single-row table (id is pinned to 1 by the CHECK below): there is exactly
-- one catalogue, global across all tenants (PAT-919 scope claim), signed
-- once nightly by verifier/sign-catalogue.py in the updater repo and pushed
-- here by POST /admin/catalogue/signed (internal/handlers/catalogue_publish.go).
-- Postgres gives us atomic replace on republish (single UPSERT) and survives
-- a patched-api restart — the artifact previously lived nowhere but a GitHub
-- branch, which is why GET /v1/catalogue 404'd for five weeks (PAT-495 finding).
--
-- envelope is stored as the exact, opaque bytes received on ingest and
-- returned byte-for-byte on GET — never re-marshaled. Any re-serialization
-- would change the bytes the Ed25519 signature in the envelope covers and
-- every endpoint's verify-catalogue.py would reject it. content_hash is the
-- SHA-256 hex digest of those same bytes; GET /v1/catalogue re-verifies it
-- against the envelope on every read rather than trusting the column blindly
-- (see internal/handlers/catalogue_signed.go's validateStoredCatalogueRow) —
-- the CHECK constraints below make the worst-case shapes (empty envelope,
-- malformed hash) unrepresentable at the schema level too, defense in depth
-- rather than relying on ingest validation alone.
--
-- generated_at is the signed payload's own generated_at claim (parsed at
-- ingest — internal/handlers/catalogue_publish.go's parseGeneratedAt),
-- carried here so republish can be enforced monotonic: an older artifact
-- must never silently replace a newer one. It also gives operators
-- visibility into the currently-stored catalogue's actual freshness, not
-- just when patched-api last received a publish call (received_at).
--
-- CREATE TABLE IF NOT EXISTS (PAT-495 review): makes this migration safe to
-- re-run after it has already fully committed once — e.g. deploy tooling
-- that unconditionally reapplies every migrations/*.sql file, relying on the
-- ON CONFLICT DO NOTHING bookkeeping insert below for idempotency. Without
-- IF NOT EXISTS, CREATE TABLE on an already-existing relation aborts the
-- whole transaction before that bookkeeping insert is ever reached.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0089_signed_catalogue.sql
BEGIN;

CREATE TABLE IF NOT EXISTS signed_catalogue (
    id           SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    envelope     BYTEA       NOT NULL CHECK (octet_length(envelope) > 0),
    content_hash TEXT        NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    key_id       TEXT        NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE signed_catalogue IS
    'Single-row (id=1) store for the current signed global app catalogue (PAT-495). envelope is the opaque {signed_payload,signature,key_id} JSON bytes exactly as ingested; never re-serialized. Replaced wholesale on each publish via UPSERT, monotonic on generated_at.';
COMMENT ON COLUMN signed_catalogue.envelope IS
    'Raw bytes of the signed envelope as received by POST /admin/catalogue/signed, byte-for-byte identical to what GET /v1/catalogue returns. Never parsed and re-marshaled after ingest validation — that would invalidate the Ed25519 signature it carries. CHECK enforces non-empty.';
COMMENT ON COLUMN signed_catalogue.content_hash IS
    'SHA-256 hex digest of envelope, computed at ingest and re-verified against the envelope bytes on every GET (never trusted blindly). Served verbatim as the GET /v1/catalogue ETag (quoted). CHECK enforces a well-formed 64-char lowercase hex digest.';
COMMENT ON COLUMN signed_catalogue.key_id IS
    'key_id field echoed from the validated envelope, for operator visibility into which signing key produced the currently-stored catalogue.';
COMMENT ON COLUMN signed_catalogue.generated_at IS
    'The signed payload''s own "generated_at" claim (parsed at ingest). Publication is monotonic on this column — POST /admin/catalogue/signed rejects (409) an envelope whose generated_at is older than the currently-stored row, so a stale artifact can never silently replace a newer one.';

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE signed_catalogue TO patched;

INSERT INTO schema_migrations (version) VALUES ('0089_signed_catalogue')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
