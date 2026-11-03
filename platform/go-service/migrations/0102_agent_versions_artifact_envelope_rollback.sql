-- patched.im — 0102_agent_versions_artifact_envelope_rollback.sql
-- Reverses 0102_agent_versions_artifact_envelope.sql.
--
-- Straight DROP COLUMN: the column is nullable and additive, so no data
-- migration or guard is needed the way 0097's rollback needs one for its
-- CHECK narrowing. Any registered envelopes are lost on rollback — expected
-- and safe, since GET /v1/agent/artifact treats "no envelope" as the normal,
-- designed state for every row today (PAT-1255 has not shipped yet).

BEGIN;

ALTER TABLE agent_versions DROP COLUMN IF EXISTS artifact_metadata_signature;

DELETE FROM schema_migrations WHERE version = '0102_agent_versions_artifact_envelope';

COMMIT;
