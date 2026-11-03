-- migrate:statement-by-statement
-- 0167: build the PAT-2021 backfill index without blocking writes, and
-- validate the constraints 0166 added NOT VALID (PAT-2021 review P2).
--
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block, so it is
-- the one statement outside BEGIN ... COMMIT. deploy/api-01/deploy.sh applies
-- migrations with `psql -f`, which runs it on its own. The Go test harnesses
-- (integration/helpers_test.go, cmd/patched-kek-backfill) run a file carrying
-- the marker on the first line statement by statement on one connection.
--
-- If the build fails part way it leaves an INVALID index that IF NOT EXISTS
-- would then skip: drop it (DROP INDEX CONCURRENTLY
-- software_installations_kind_value_present_idx;) and re-run this file.
--
-- VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE: reads and writes carry
-- on while each table is scanned. The tables are small today (hundreds to
-- low thousands of rows).
CREATE INDEX CONCURRENTLY IF NOT EXISTS software_installations_kind_value_present_idx
    ON software_installations (identity_kind, identity_value_normalized) WHERE removed_at IS NULL;

BEGIN;

ALTER TABLE software_inventory_runs
    VALIDATE CONSTRAINT software_inventory_runs_authoritative_scopes_check;
ALTER TABLE software_category_tags
    VALIDATE CONSTRAINT software_category_tags_observation_kind_check;
ALTER TABLE software_category_tags
    VALIDATE CONSTRAINT software_category_tags_check;

INSERT INTO schema_migrations (version) VALUES ('0167_tooling_index_and_validate')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
