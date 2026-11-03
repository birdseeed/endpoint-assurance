-- PAT-2035: durable portal feedback queue. Reporter email is platform-only
-- attribution and must never be copied to Linear.
BEGIN;
CREATE TABLE feedback (
 id BIGSERIAL PRIMARY KEY,
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 reference TEXT GENERATED ALWAYS AS ('FB-' || id::text) STORED UNIQUE,
 tenant_display_slug TEXT NOT NULL,
 reporter_email TEXT NOT NULL,
 reporter_role TEXT NOT NULL CHECK (reporter_role IN ('viewer','admin')),
 type TEXT NOT NULL CHECK (type IN ('bug','feature','question')),
 title TEXT NOT NULL CHECK (char_length(title) BETWEEN 5 AND 120),
 description TEXT NOT NULL CHECK (char_length(description) BETWEEN 1 AND 5000),
 severity TEXT CHECK (severity IN ('low','medium','high','critical')),
 route TEXT NOT NULL DEFAULT '' CHECK (char_length(route)<=512 AND position('?' IN route)=0 AND position('#' IN route)=0),
 portal_build TEXT NOT NULL DEFAULT '' CHECK (char_length(portal_build)<=128),
 user_agent TEXT NOT NULL DEFAULT '' CHECK (char_length(user_agent)<=512),
 screenshot BYTEA, screenshot_content_type TEXT CHECK (screenshot_content_type IN ('image/png','image/jpeg')), screenshot_filename TEXT,
 status TEXT NOT NULL DEFAULT 'received' CHECK (status IN ('received','planned','on_the_roadmap','in_progress','shipped','closed_not_planned','closed_merged')),
 linear_state TEXT,
 sync_state TEXT NOT NULL DEFAULT 'pending' CHECK (sync_state IN ('pending','syncing','synced','failed')),
 linear_issue_id TEXT, linear_issue_identifier TEXT, linear_asset_url TEXT,
 sync_attempts INTEGER NOT NULL DEFAULT 0 CHECK (sync_attempts >= 0), next_sync_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), lease_until TIMESTAMPTZ,
 last_error TEXT, screenshot_attempts INTEGER NOT NULL DEFAULT 0 CHECK (screenshot_attempts BETWEEN 0 AND 5),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), status_changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), synced_at TIMESTAMPTZ,
 CHECK ((type='bug' AND severity IS NOT NULL) OR (type IN ('feature','question') AND severity IS NULL)),
 CHECK ((screenshot IS NULL AND screenshot_content_type IS NULL AND screenshot_filename IS NULL) OR (screenshot IS NOT NULL AND screenshot_content_type IS NOT NULL AND screenshot_filename IS NOT NULL))
);
CREATE INDEX feedback_tenant_created ON feedback(tenant_id,created_at DESC);
CREATE INDEX feedback_due ON feedback(next_sync_at) WHERE sync_state IN ('pending','syncing') AND linear_issue_id IS NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON feedback TO patched;
GRANT USAGE, SELECT ON SEQUENCE feedback_id_seq TO patched;
INSERT INTO schema_migrations(version) VALUES ('0206_portal_feedback') ON CONFLICT (version) DO NOTHING;
COMMIT;
