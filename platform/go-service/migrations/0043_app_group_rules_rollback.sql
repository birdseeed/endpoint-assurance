BEGIN;
DELETE FROM schema_migrations WHERE version = '0043_app_group_rules';
DROP TABLE IF EXISTS app_group_rules;
COMMIT;
