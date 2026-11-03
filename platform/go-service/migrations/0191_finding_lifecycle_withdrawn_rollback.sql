-- Rollback for 0191 (PAT-2107). finding_lifecycle_events is append-only, so a
-- withdrawn or matcher row cannot be removed, and restoring the 0156
-- constraints over one would fail anyway. Refuse explicitly instead: once any
-- withdrawal exists, this rollback is not possible without discarding audit
-- history. Before that point it restores the exact 0156 constraints.
BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM finding_lifecycle_events
        WHERE event_type = 'withdrawn' OR source_type = 'matcher'
        LIMIT 1
    ) THEN
        RAISE EXCEPTION '0191 rollback refused: withdrawn lifecycle history exists';
    END IF;
END;
$$;

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
            'still_failing', 'recurred'
        )),
    ADD CONSTRAINT finding_lifecycle_events_source_type_check
        CHECK (source_type IN (
            'endpoint_observation', 'operator_action', 'migration'
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
            ))
    );

COMMENT ON TABLE finding_lifecycle_events IS
    'PAT-1878 immutable lifecycle ledger. Operator actions can request verification; only authoritative endpoint_observation events can record verified_fixed, still_failing or recurrence.';

DELETE FROM schema_migrations WHERE version = '0191_finding_lifecycle_withdrawn';

COMMIT;
