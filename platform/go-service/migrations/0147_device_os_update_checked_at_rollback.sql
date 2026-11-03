-- patched.im — rollback for 0147_device_os_update_checked_at.sql
--
-- Deliberately does NOT restore latest_os's NOT NULL constraint: once a
-- real agent has sent latest_os: null (a genuine SOFA/WUA-unreachable
-- report, not a data-quality problem), re-adding NOT NULL would fail
-- outright against any row that already holds that legitimate NULL.
-- Migrations here are additive per this repo's own convention — leaving
-- the column nullable after a rollback is the safe direction; the forward
-- migration is the one meant to stick.

BEGIN;

ALTER TABLE device_os_update DROP COLUMN IF EXISTS checked_at;

DELETE FROM schema_migrations WHERE version = '0147_device_os_update_checked_at';

COMMIT;
