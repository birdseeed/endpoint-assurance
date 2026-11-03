-- patched.im — 0035_drop_dashboard_tables_rollback.sql
-- Rolls back 0035_drop_dashboard_tables.sql (PAT-489).
-- Recreates the six tables verbatim from 0033_dashboard_migration.sql.
BEGIN;

CREATE TABLE IF NOT EXISTS public_uploads (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    upload_type TEXT NOT NULL,
    status TEXT DEFAULT 'processing',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    report_path TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    company TEXT NOT NULL,
    tenant_id TEXT DEFAULT '',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status TEXT,
    error TEXT,
    report_path TEXT,
    device_count INTEGER,
    cve_count INTEGER
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    company TEXT NOT NULL,
    tenant_id TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_scan_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS public_scans (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    company TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL DEFAULT 'pending_verify',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    apps_path TEXT,
    report_path TEXT,
    error TEXT,
    otp TEXT,
    otp_expires_at TIMESTAMP WITH TIME ZONE,
    download_token TEXT,
    sg_contact_id TEXT
);

CREATE TABLE IF NOT EXISTS report_deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tenant_name TEXT,
    report_type TEXT NOT NULL,
    recipient TEXT,
    delivered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    report_path TEXT,
    cve_count INTEGER,
    device_count INTEGER
);

CREATE TABLE IF NOT EXISTS conversion_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

DELETE FROM schema_migrations WHERE version = '0035_drop_dashboard_tables';

COMMIT;
