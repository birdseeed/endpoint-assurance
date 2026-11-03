-- 0191: withdrawn, a matcher-correction lifecycle event (PAT-2107)
--
-- PAT-2107 makes the CVE matcher honour CPE platform, exact versions and a
-- three-year age cut for unverified matches, so it stops producing thousands
-- of false findings. Before this migration the lifecycle reconciler could
-- only read a disappeared CVE finding as verified_fixed ("the customer fixed
-- it"), which would write false fixes into the audit ledger customers and
-- assessors read.
--
-- withdrawn records the other truth: Patched retracted a finding while the
-- device still reports the same software at the same version, because the
-- matcher's verdict changed. It is a matcher correction, not a fix.
--
-- Source: withdrawn is written with the new source_type 'matcher'. The
-- decision is Patched's own (a matcher, CVE feed or mapping change). It is
-- not an endpoint observation (nothing on the device changed, so it cannot
-- carry endpoint authority) and not an operator action (no human made it).
-- observed_at stays NULL for the same reason: there is no endpoint evidence
-- time to record. The unchanged-device evidence is in the evidence JSON.
--
-- Authority: finding_lifecycle_authority_shape is unchanged on purpose. It
-- already requires authoritative = (source_type = 'endpoint_observation' AND
-- event_type <> 'verification_unknown'), so every 'matcher' row is forced to
-- authoritative = false. A withdrawn event can never read as authoritative
-- closure evidence.
--
-- Notifications: withdrawn maps to no notification event
-- (internal/notifications/lifecycle.go), so it is never delivered.
--
-- Additive only: three CHECK constraints are widened, existing rows are
-- unaffected and the finding_lifecycle_current view needs no change (its
-- status column is the latest event_type, so it reads 'withdrawn').
-- Constraint names verified against patched-api-01 on 2026-09-25.
BEGIN;

ALTER TABLE finding_lifecycle_events
    DROP CONSTRAINT finding_lifecycle_events_event_type_check,
    DROP CONSTRAINT finding_lifecycle_events_source_type_check,
    DROP CONSTRAINT finding_lifecycle_source_shape;

ALTER TABLE finding_lifecycle_events
    ADD CONSTRAINT finding_lifecycle_events_event_type_check
        CHECK (event_type IN (
            'first_observed', 'currently_observed', 'acknowledged',
            'risk_accepted', 'guidance_issued', 'customer_applied',
            'pending_verification', 'verification_unknown', 'verified_fixed',
            'still_failing', 'recurred', 'withdrawn'
        )),
    ADD CONSTRAINT finding_lifecycle_events_source_type_check
        CHECK (source_type IN (
            'endpoint_observation', 'operator_action', 'migration', 'matcher'
        )),
    ADD CONSTRAINT finding_lifecycle_source_shape CHECK (
        (source_type = 'endpoint_observation'
            AND event_type IN (
                'first_observed', 'currently_observed', 'verification_unknown',
                'verified_fixed', 'still_failing', 'recurred'
            )
            AND observed_at IS NOT NULL) OR
        (source_type IN ('operator_action', 'migration')
            AND event_type IN (
                'acknowledged', 'risk_accepted', 'guidance_issued',
                'customer_applied', 'pending_verification'
            )) OR
        (source_type = 'matcher'
            AND event_type = 'withdrawn'
            AND observed_at IS NULL)
    );

COMMENT ON TABLE finding_lifecycle_events IS
    'PAT-1878 immutable lifecycle ledger. Operator actions can request verification; only authoritative endpoint_observation events can record verified_fixed, still_failing or recurrence. PAT-2107: withdrawn (source matcher, never authoritative) records a matcher correction, not a fix.';

INSERT INTO schema_migrations (version) VALUES ('0191_finding_lifecycle_withdrawn')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
