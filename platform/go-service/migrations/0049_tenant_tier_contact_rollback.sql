-- Rollback for 0049_tenant_tier_contact.sql
ALTER TABLE tenants
  DROP COLUMN IF EXISTS tier,
  DROP COLUMN IF EXISTS contact_name,
  DROP COLUMN IF EXISTS contact_email,
  DROP COLUMN IF EXISTS contact_role;
