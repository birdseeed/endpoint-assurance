-- patched.im — 0054_shadow_it.sql
-- PAT-631: Shadow IT catalogue and per-tenant policy overrides.
-- Detection-only Phase 1; per-device enforcement (deny_list agent-config field) is Phase 2.
-- Apply with: psql -h patched-api-01 -U patched -d patched -f migrations/0054_shadow_it.sql

BEGIN;

CREATE TABLE shadow_it_catalogue (
    label       TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL CHECK (category IN ('p2p','gaming','remote_access','consumer_cloud','crypto','ai_unapproved')),
    match_names TEXT[] NOT NULL DEFAULT '{}',
    notes       TEXT
);

CREATE TABLE tenant_shadow_it_policy (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label      TEXT NOT NULL REFERENCES shadow_it_catalogue(label),
    policy     TEXT NOT NULL DEFAULT 'flag' CHECK (policy IN ('flag','allow')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, label)
);

CREATE INDEX tenant_shadow_it_policy_tenant_idx ON tenant_shadow_it_policy(tenant_id);

INSERT INTO shadow_it_catalogue (label, name, category, match_names, notes) VALUES
    ('steam',          'Steam',            'gaming',         ARRAY['Steam'],                   'Valve gaming platform'),
    ('epicgames',      'Epic Games',       'gaming',         ARRAY['Epic Games','Epic Games Launcher'], 'Epic Games store and launcher'),
    ('battlenet',      'Battle.net',       'gaming',         ARRAY['Battle.net','Battlenet','Blizzard'], 'Blizzard entertainment launcher'),
    ('goggalaxy',      'GOG Galaxy',       'gaming',         ARRAY['GOG Galaxy'],              'GOG games client'),
    ('itchio',         'Itch.io',          'gaming',         ARRAY['itch.io','itch'],          'Indie game marketplace'),
    ('ubisoftconnect', 'Ubisoft Connect',  'gaming',         ARRAY['Ubisoft Connect','Uplay'], 'Ubisoft games launcher'),
    ('origin',         'EA App',           'gaming',         ARRAY['Origin','EA app','EA Desktop','Electronic Arts'], 'Electronic Arts launcher'),
    ('bittorrent',     'BitTorrent',       'p2p',            ARRAY['BitTorrent'],              'P2P file sharing client'),
    ('qbittorrent',    'qBittorrent',      'p2p',            ARRAY['qBittorrent'],             'P2P file sharing client'),
    ('utorrent',       'µTorrent',         'p2p',            ARRAY['uTorrent','µTorrent'],     'P2P file sharing client'),
    ('parsec',         'Parsec',           'remote_access',  ARRAY['Parsec'],                  'Unapproved remote access — use AnyDesk or TeamViewer instead'),
    ('logmein',        'LogMeIn',          'remote_access',  ARRAY['LogMeIn'],                 'Unapproved remote access'),
    ('splashtop',      'Splashtop',        'remote_access',  ARRAY['Splashtop'],               'Unapproved remote access'),
    ('mega',           'MEGA',             'consumer_cloud', ARRAY['MEGAsync','MEGA'],         'Consumer cloud storage; may bypass DLP controls'),
    ('coinbase',       'Coinbase',         'crypto',         ARRAY['Coinbase'],                'Cryptocurrency exchange app'),
    ('ledgerlive',     'Ledger Live',      'crypto',         ARRAY['Ledger Live'],             'Cryptocurrency hardware wallet management'),
    ('chatgpt',        'ChatGPT',          'ai_unapproved',  ARRAY['ChatGPT'],                 'OpenAI ChatGPT desktop; flag if org has AI acceptable-use policy');

INSERT INTO schema_migrations (version) VALUES ('0054_shadow_it');

COMMIT;
