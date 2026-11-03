-- patched.im — 0013_device_certificates_classification.sql
-- Adds EKU, basicConstraints, and self-signed classification fields to
-- device_certificates (PAT-221). Collected by the macOS agent (PAT-220).
--
-- Existing rows backfill via column defaults on the next agent check-in;
-- no explicit data migration is required.
--
-- Rollback: migrations/0013_device_certificates_classification_rollback.sql
--
-- Apply with:
--   psql -h patched-api-01 -U patched -d patched -f migrations/0013_device_certificates_classification.sql
-- Note: 0012_device_certificates.sql must have been applied first.

BEGIN;

ALTER TABLE device_certificates
    ADD COLUMN ext_key_usage        TEXT[]  NOT NULL DEFAULT '{}',
    ADD COLUMN basic_constraints_ca BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN is_self_signed       BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN device_certificates.ext_key_usage IS
    'Extended Key Usage OID strings reported by the agent (PAT-220). Empty array when absent or not set on the certificate.';
COMMENT ON COLUMN device_certificates.basic_constraints_ca IS
    'True when the certificate has the CA:TRUE basicConstraints extension.';
COMMENT ON COLUMN device_certificates.is_self_signed IS
    'True when subject and issuer are identical (self-signed certificate).';

INSERT INTO schema_migrations (version) VALUES ('0013_device_certificates_classification');

COMMIT;
