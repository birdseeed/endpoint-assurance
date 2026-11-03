-- Roll back PAT-1538's catalogue_products -> software_products identity link.
BEGIN;

DROP INDEX IF EXISTS catalogue_products_software_product_id_idx;

ALTER TABLE catalogue_products
    DROP COLUMN software_product_id;

DELETE FROM schema_migrations
WHERE version = '0115_catalogue_product_identity_link';

COMMIT;
