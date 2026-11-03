-- PAT-110: Tenant provisioning — add tier and primary contact columns.
-- tier: 1=Report, 2=Patch+Deploy, 3=Full Endpoint Management. Defaults to 1.
-- contact_*: primary contact stored at provisioning time. Used for welcome emails
-- and agent install package generation. Additional contacts are added later via
-- the report-config surface (PAT-109).
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS tier          SMALLINT NOT NULL DEFAULT 1 CHECK (tier IN (1, 2, 3)),
  ADD COLUMN IF NOT EXISTS contact_name  TEXT,
  ADD COLUMN IF NOT EXISTS contact_email TEXT,
  ADD COLUMN IF NOT EXISTS contact_role  TEXT;
