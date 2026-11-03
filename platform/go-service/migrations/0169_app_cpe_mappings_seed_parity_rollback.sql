-- Rollback for PAT-2047 (0169_app_cpe_mappings_seed_parity.sql).
--
-- Deletes exactly the rows this migration inserted, identified by the
-- 'PAT-2047 seed parity' notes marker it wrote on every one of them -- never
-- by app or key, since some of those (git-scm:git, zoom:zoom) coexist with a
-- pre-existing differently-keyed row for the same app that this migration
-- did not touch and must not remove.

BEGIN;

DELETE FROM app_cpe_mappings WHERE notes = 'PAT-2047 seed parity';

DELETE FROM schema_migrations WHERE version = '0169_app_cpe_mappings_seed_parity';

COMMIT;
