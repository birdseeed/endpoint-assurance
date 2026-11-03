-- patched.im — 0115_catalogue_product_identity_link.sql
-- PAT-1538 (PAT-1481 ADR-0011 §3): unify catalogue product identity onto the
-- canonical software_products model.
--
-- ADR-0011 §3 requires that execution metadata reference the package-neutral
-- software_products identity rather than maintain a third independent
-- product namespace. This migration adds that link column to
-- catalogue_products. It is nullable: backfilling existing catalogue_products
-- rows to a resolved software_products row is explicitly out of scope here
-- (a separate ticket, per the ADR's migration plan step 2 — "reconcile
-- duplicates and refuse ambiguous backfill rather than guessing").
--
-- Additive / non-actuating: no existing code reads this column yet.
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0115_catalogue_product_identity_link.sql
BEGIN;

ALTER TABLE catalogue_products
    ADD COLUMN software_product_id UUID REFERENCES software_products(id);

CREATE INDEX catalogue_products_software_product_id_idx
    ON catalogue_products (software_product_id)
    WHERE software_product_id IS NOT NULL;

INSERT INTO schema_migrations (version) VALUES ('0115_catalogue_product_identity_link')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
