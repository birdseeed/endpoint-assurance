BEGIN;

CREATE TABLE IF NOT EXISTS app_group_rules (
  id              BIGSERIAL PRIMARY KEY,
  bundle_prefix   TEXT NOT NULL UNIQUE,
  canonical_label TEXT NOT NULL,
  canonical_name  TEXT NOT NULL,
  source          TEXT NOT NULL DEFAULT 'manual'
                  CHECK (source IN ('manual', 'installomator_sync')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_app_group_rules_prefix
  ON app_group_rules (bundle_prefix);

COMMENT ON TABLE app_group_rules IS
  'Vendor prefix → canonical app mappings for deduplicating multi-bundle apps (PAT-594).';

-- Seed known multi-bundle vendors
INSERT INTO app_group_rules (bundle_prefix, canonical_label, canonical_name, source) VALUES
  ('us.zoom.',           'zoom',           'Zoom',           'manual'),
  ('com.discord.',       'discord',        'Discord',        'manual'),
  ('com.spotify.',       'spotify',        'Spotify',        'manual')
ON CONFLICT (bundle_prefix) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON app_group_rules TO patched;
GRANT USAGE, SELECT ON SEQUENCE app_group_rules_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0043_app_group_rules') ON CONFLICT DO NOTHING;

COMMIT;
