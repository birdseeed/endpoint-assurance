-- patched.im — 0151_vendor_advisory_titles.sql
-- PAT-1853: retain an upstream vendor advisory title across the separate
-- OS advisory sync and match runs, and preserve the provenance of every CVE
-- description exposed to customers. description_source is part of the value:
-- 'nvd', 'msrc' and 'apple' identify the upstream text source; '' means the
-- description is deliberately absent. The current Apple feed has no per-CVE
-- title, so it remains the explicit empty/empty state.
--
-- Requires PAT-1918's 0150 OS-advisory reconciliation migration. Do not apply
-- this migration to an estate where os_cve_advisories has not first been
-- created/reconciled by that predecessor.

BEGIN;

ALTER TABLE os_cve_advisories
    ADD COLUMN vendor_title TEXT NOT NULL DEFAULT '';

-- description and description_source form one provenance-bearing value. Empty
-- text has an empty source. Existing non-empty descriptions pre-date vendor
-- title fallback and were populated exclusively by the NVD synchroniser.
ALTER TABLE cve_feed_entries
    ADD COLUMN description_source TEXT NOT NULL DEFAULT '';

UPDATE cve_feed_entries
SET description_source = 'nvd'
WHERE BTRIM(description) <> '';

ALTER TABLE cve_feed_entries
    ADD CONSTRAINT cve_feed_entries_description_source_valid
    CHECK (description_source IN ('', 'nvd', 'msrc', 'apple'));

ALTER TABLE cve_feed_entries
    ADD CONSTRAINT cve_feed_entries_description_source_presence
    CHECK (
        (BTRIM(description) = '' AND description_source = '')
        OR (BTRIM(description) <> '' AND description_source <> '')
    );

INSERT INTO schema_migrations (version) VALUES ('0151_vendor_advisory_titles')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
