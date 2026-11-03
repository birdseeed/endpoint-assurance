-- patched.im — 0035_drop_dashboard_tables.sql
-- Drops the six dashboard tables mistakenly created in 0033_dashboard_migration.sql.
-- Dashboard reverted to SQLite (PAT-489); these tables are unused in the go-service DB.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0035_drop_dashboard_tables.sql

BEGIN;

DROP TABLE IF EXISTS public_uploads     CASCADE;
DROP TABLE IF EXISTS scans              CASCADE;
DROP TABLE IF EXISTS clients            CASCADE;
DROP TABLE IF EXISTS public_scans       CASCADE;
DROP TABLE IF EXISTS report_deliveries  CASCADE;
DROP TABLE IF EXISTS conversion_events  CASCADE;

INSERT INTO schema_migrations (version) VALUES ('0035_drop_dashboard_tables');

COMMIT;
