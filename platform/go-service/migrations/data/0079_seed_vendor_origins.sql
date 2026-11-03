-- 0079_seed_vendor_origins.sql — PAT-853 starter vendor-origin allowlist.
--
-- Curated first-party download origins for a small set of well-known
-- products, keyed on catalogue_products.product_key (= lower(display_name),
-- set by the review endpoint). This is a DATA migration, deliberately kept
-- OUT of migrations/ so the integration harness never auto-runs it and so
-- production applies it as one deliberate, reviewed operation.
--
-- ORDERING: run anytime after 0079_catalogue_vendor_origins.sql. It is a
-- NO-OP today — no catalogue_products rows exist for these keys yet (nothing
-- has been reviewed) — but becomes correct the moment an operator reviews
-- "Google Chrome" / "Docker Desktop" / etc via POST /admin/catalogue/review,
-- since the INSERT...SELECT only writes a row when the product_key match
-- succeeds. Idempotent: ON CONFLICT (product_id, host, path_prefix) DO
-- NOTHING, so re-running makes no further changes.
--
-- Kept deliberately small and host-only (path_prefix=''): every host below
-- is a genuine first-party vendor domain (not a shared/multi-tenant host
-- per isSharedHost in catalogue_promotion.go), so a host-only allowlist
-- entry is sufficient. Zoom is intentionally omitted — its installer is
-- served from a CDN host that isn't confidently a stable first-party
-- hostname; add it explicitly via POST /admin/catalogue/vendor-origins once
-- confirmed, rather than guessing here.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/data/0079_seed_vendor_origins.sql
BEGIN;

INSERT INTO catalogue_vendor_origins (product_id, host, path_prefix, note, created_by)
SELECT p.id, v.host, '', v.note, 'migration:0079_seed_vendor_origins'
FROM catalogue_products p
JOIN (VALUES
    ('google chrome',   'dl.google.com',            'Google Chrome installer CDN (first-party)'),
    ('docker desktop',  'desktop.docker.com',        'Docker Desktop installer host (first-party)'),
    ('mozilla firefox',  'download.mozilla.org',      'Mozilla Firefox installer redirector (first-party)'),
    ('1password',        'downloads.1password.com',   '1Password installer host (first-party)'),
    ('slack',             'downloads.slack-edge.com',  'Slack installer CDN (first-party)')
) AS v(product_key, host, note) ON v.product_key = p.product_key
ON CONFLICT (product_id, host, path_prefix) DO NOTHING;

COMMIT;
