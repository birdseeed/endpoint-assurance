-- 0075: tenant email-domain auto-binding for customer portal SSO (PAT-127).
--
-- PAT-127 decision (locked): Microsoft (Entra) + Google are
-- offered as portal SSO options to every tenant via Cloudflare Access, no
-- per-tenant IdP choice. What's still per-tenant is which email DOMAIN maps
-- to which tenant, so that a verified SSO login auto-resolves without an
-- operator having to add every individual user by hand first.
--
-- This is additive to, not a replacement for, portal_users (migration 0059):
--   - portal_users remains the manual-override path — an explicit
--     email -> tenant row always wins. This is how the "consultant on a
--     shared/cross-domain admin email" edge case from the ticket is handled:
--     add one override row, independent of what domain the address is on.
--   - tenant_email_domains is the new default path: a tenant registers its
--     verified email domain(s) once (as part of onboarding, PAT-110), and
--     any SSO login from that domain resolves to it without a per-user row.
--
-- A domain must resolve to at most one active tenant. The partial unique
-- index prevents two tenants from both actively claiming the same domain;
-- portalauth.DBLookup also defensively refuses to resolve an ambiguous
-- domain match (belt and braces — see go-service/internal/portalauth).

BEGIN;

CREATE TABLE tenant_email_domains (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain      TEXT        NOT NULL CHECK (domain = lower(domain)),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ
);

CREATE INDEX idx_tenant_email_domains_tenant ON tenant_email_domains (tenant_id);

-- Only one *active* claim per domain is allowed. Disabled rows are excluded
-- so a domain can be freely re-registered (e.g. moved to a different tenant,
-- or re-enabled) after being disabled.
CREATE UNIQUE INDEX idx_tenant_email_domains_active_domain
    ON tenant_email_domains (domain)
    WHERE disabled_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_email_domains TO patched;
GRANT USAGE, SELECT ON SEQUENCE tenant_email_domains_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('0075_tenant_email_domains')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
