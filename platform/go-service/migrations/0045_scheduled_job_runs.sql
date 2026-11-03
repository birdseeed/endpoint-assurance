-- PAT-595: Scheduled job run history for background maintenance jobs.

BEGIN;

CREATE TABLE scheduled_job_runs (
    id          BIGSERIAL PRIMARY KEY,
    job_name    TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'running'
                CHECK (status IN ('running', 'success', 'warning', 'failed')),
    output      TEXT,
    error_msg   TEXT
);

CREATE INDEX scheduled_job_runs_job_name_started_at_idx
    ON scheduled_job_runs (job_name, started_at DESC);

GRANT SELECT, INSERT, UPDATE ON scheduled_job_runs TO patched;
GRANT USAGE, SELECT ON SEQUENCE scheduled_job_runs_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0045_scheduled_job_runs');

COMMIT;
