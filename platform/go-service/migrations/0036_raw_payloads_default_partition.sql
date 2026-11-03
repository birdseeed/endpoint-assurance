-- patched.im — 0036_raw_payloads_default_partition.sql
-- Adds a DEFAULT partition to raw_payloads so that rows whose received_at falls
-- outside the explicit monthly partitions (0001_initial.sql covers 2026-07 – 2026-08)
-- do not cause INSERT failures.  Also adds monthly partitions for 2026-09 – 2027-12
-- to keep query plans efficient while the default partition acts as a safety net.
--
-- Applied as part of PAT-227 (CI integration tests) — the test suite inserts rows
-- with the current timestamp and would fail once we pass 2026-09-01 without this.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0036_raw_payloads_default_partition.sql
-- Note: 0035_drop_dashboard_tables.sql must have been applied first.

BEGIN;

-- 2026-09 through 2027-12 explicit partitions for efficient pruning / planning.
CREATE TABLE raw_payloads_2026_09 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE raw_payloads_2026_10 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE raw_payloads_2026_11 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE raw_payloads_2026_12 PARTITION OF raw_payloads
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE raw_payloads_2027_01 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE raw_payloads_2027_02 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE raw_payloads_2027_03 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');
CREATE TABLE raw_payloads_2027_04 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-04-01') TO ('2027-05-01');
CREATE TABLE raw_payloads_2027_05 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-05-01') TO ('2027-06-01');
CREATE TABLE raw_payloads_2027_06 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-06-01') TO ('2027-07-01');
CREATE TABLE raw_payloads_2027_07 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-07-01') TO ('2027-08-01');
CREATE TABLE raw_payloads_2027_08 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-08-01') TO ('2027-09-01');
CREATE TABLE raw_payloads_2027_09 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-09-01') TO ('2027-10-01');
CREATE TABLE raw_payloads_2027_10 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-10-01') TO ('2027-11-01');
CREATE TABLE raw_payloads_2027_11 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-11-01') TO ('2027-12-01');
CREATE TABLE raw_payloads_2027_12 PARTITION OF raw_payloads
    FOR VALUES FROM ('2027-12-01') TO ('2028-01-01');

-- Default partition: catches any future row whose timestamp falls outside the
-- explicit monthly partitions above.  Add a new monthly partition at the start
-- of each year so the default stays lean.
CREATE TABLE raw_payloads_default PARTITION OF raw_payloads DEFAULT;

INSERT INTO schema_migrations (version) VALUES ('0036_raw_payloads_default_partition');

COMMIT;
