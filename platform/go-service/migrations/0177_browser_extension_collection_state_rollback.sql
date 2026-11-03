-- Rollback for 0177_browser_extension_collection_state (PAT-2055).
--
-- Drops both completeness tables. Nothing else references them. With the
-- tables gone every device reads as one that never sent the block, which is
-- exactly the pre-PAT-2055 presence behaviour, so roll the binaries back
-- first. raw_payloads still holds every browser_extensions_status block, so
-- a re-apply plus re-extraction rebuilds what this drops.

BEGIN;

DROP TABLE IF EXISTS browser_extension_collection_state;
DROP TABLE IF EXISTS browser_extension_device_state;

DELETE FROM schema_migrations WHERE version = '0177_browser_extension_collection_state';

COMMIT;
