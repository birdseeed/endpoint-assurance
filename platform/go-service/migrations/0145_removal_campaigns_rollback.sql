-- patched.im — 0145_removal_campaigns_rollback.sql
-- Rolls back 0145_removal_campaigns.sql (PAT-1598).
--
-- Destructive by nature: dropping these tables destroys the append-only
-- dry-run and authorisation evidence they hold. That is acceptable only
-- while no removal has ever been authorised for a real customer, which is
-- the state this ticket ships in (no delivery path exists, and PAT-112's
-- contract language is not yet written). Once an authorisation exists for a
-- customer, treat this file as unusable and migrate forward instead.
--
-- DROP TABLE removes the append-only triggers with the tables; the two
-- trigger functions are dropped explicitly because they are not owned by
-- either table.

BEGIN;

DROP TABLE IF EXISTS removal_campaign_authorizations;
DROP TABLE IF EXISTS removal_campaign_dry_runs;
DROP TABLE IF EXISTS removal_campaigns;

DROP FUNCTION IF EXISTS reject_removal_evidence_mutation();
DROP FUNCTION IF EXISTS reject_removal_evidence_truncate();

DELETE FROM schema_migrations WHERE version = '0145_removal_campaigns';

COMMIT;
