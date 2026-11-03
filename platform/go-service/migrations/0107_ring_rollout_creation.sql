-- patched.im — 0107_ring_rollout_creation.sql
-- PAT-1397: owner-created, evidence-bound ring rollouts.
-- This is a one-shot transactional migration. A second application is an
-- operator error and intentionally fails on the existing columns/version row;
-- schema_migrations is evidence of completion, not an idempotency shim.
BEGIN;

ALTER TABLE ring_version_approvals
    ADD COLUMN catalogue_product_id UUID REFERENCES catalogue_products(id),
    ADD COLUMN catalogue_target_id UUID REFERENCES catalogue_platform_targets(id),
    ADD COLUMN catalogue_content_hash TEXT,
    ADD COLUMN catalogue_generated_at TIMESTAMPTZ,
    ADD COLUMN verified_sha256 TEXT,
    ADD COLUMN verified_signer TEXT,
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN rollout_mode TEXT,
    ADD COLUMN reason TEXT,
    ADD COLUMN idempotency_key UUID,
    ADD COLUMN request_fingerprint TEXT,
    ADD COLUMN impact_snapshot JSONB;

ALTER TABLE ring_version_approvals
    ADD CONSTRAINT ring_rollout_creation_mode_check
        CHECK (rollout_mode IS NULL OR rollout_mode = 'staged'),
    ADD CONSTRAINT ring_rollout_creation_hash_check
        CHECK (verified_sha256 IS NULL OR verified_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT ring_rollout_creation_evidence_complete_check
        CHECK ((
            (idempotency_key IS NULL
             AND request_fingerprint IS NULL
             AND catalogue_product_id IS NULL
             AND catalogue_target_id IS NULL
             AND catalogue_content_hash IS NULL
             AND catalogue_generated_at IS NULL
             AND verified_sha256 IS NULL
             AND verified_signer IS NULL
             AND verified_at IS NULL
             AND rollout_mode IS NULL
             AND reason IS NULL
             AND impact_snapshot IS NULL)
            OR
            (idempotency_key IS NOT NULL
             AND request_fingerprint IS NOT NULL
             AND request_fingerprint ~ '^[0-9a-f]{64}$'
             AND catalogue_product_id IS NOT NULL
             AND catalogue_target_id IS NOT NULL
             AND catalogue_content_hash IS NOT NULL
             AND catalogue_content_hash ~ '^[0-9a-f]{64}$'
             AND catalogue_generated_at IS NOT NULL
             AND verified_sha256 IS NOT NULL
             AND verified_sha256 ~ '^[0-9a-f]{64}$'
             AND verified_signer IS NOT NULL
             AND btrim(verified_signer) <> ''
             AND verified_at IS NOT NULL
             AND rollout_mode = 'staged'
             AND reason IS NOT NULL
             AND btrim(reason) <> ''
             AND impact_snapshot IS NOT NULL)
        ) IS TRUE),
    ADD CONSTRAINT ring_rollout_creation_impact_check
        CHECK ((idempotency_key IS NULL) OR (
            jsonb_typeof(impact_snapshot) = 'object'
            AND jsonb_typeof(impact_snapshot->'affected') = 'number'
            AND jsonb_typeof(impact_snapshot->'eligible') = 'number'
            AND jsonb_typeof(impact_snapshot->'excluded') = 'number'
            AND jsonb_typeof(impact_snapshot->'excluded_reasons') = 'object'
            AND (impact_snapshot->>'affected')::integer >= 0
            AND (impact_snapshot->>'eligible')::integer >= 0
            AND (impact_snapshot->>'excluded')::integer >= 0
            AND (impact_snapshot->>'affected')::integer =
                (impact_snapshot->>'eligible')::integer + (impact_snapshot->>'excluded')::integer
            AND COALESCE((impact_snapshot->'excluded_reasons'->>'installed_version_unavailable')::integer, 0) >= 0
            AND COALESCE((impact_snapshot->'excluded_reasons'->>'installed_version_order_ambiguous')::integer, 0) >= 0
            AND COALESCE((impact_snapshot->'excluded_reasons'->>'already_at_or_above_target')::integer, 0) >= 0
            AND COALESCE((impact_snapshot->'excluded_reasons'->>'app_not_installed_or_identity_unverified')::integer, 0) >= 0
            AND (impact_snapshot->>'excluded')::integer =
                COALESCE((impact_snapshot->'excluded_reasons'->>'installed_version_unavailable')::integer, 0)
              + COALESCE((impact_snapshot->'excluded_reasons'->>'installed_version_order_ambiguous')::integer, 0)
              + COALESCE((impact_snapshot->'excluded_reasons'->>'already_at_or_above_target')::integer, 0)
              + COALESCE((impact_snapshot->'excluded_reasons'->>'app_not_installed_or_identity_unverified')::integer, 0)
        ) IS TRUE);

CREATE UNIQUE INDEX ring_rollout_creation_idempotency_idx
    ON ring_version_approvals (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Guards two things, not just the 0107 evidence columns: the target identity
-- (tenant_id/platform/label/version/created_at) that says what a row's
-- evidence is ABOUT, and outright deletion of the row. Neither is a
-- hypothetical gap — no UPDATE anywhere in internal/rings or
-- internal/handlers/ring_rollout*.go ever touches identity columns (grepped
-- before writing this; every real UPDATE sets only approved_ring, state,
-- paused_reason, last_advanced_at, updated_at), and no code path issues a
-- direct DELETE against this table at all. Without this, a row could be
-- UPDATEd to point at a different label/version/platform than the evidence
-- it was verified against, or removed entirely, while its evidence columns
-- stayed byte-for-byte "immutable" — the identity/evidence binding is the
-- actual guarantee PAT-1397 promises, not just the evidence bytes alone.
--
-- DELETE is blocked only at pg_trigger_depth() = 1 (a direct statement
-- against this table), not at the deeper depth an ON DELETE CASCADE from
-- `DELETE FROM tenants` fires at — tenant purge (PurgeTenantHandler,
-- admin.go) legitimately hard-deletes every child row via that cascade and
-- must keep working. Verified empirically against a throwaway parent/child
-- pair (same method 0096_audit_append_only_guards.sql's header describes):
-- a direct DELETE fires this trigger at depth 1 and is rejected; the same
-- row deleted via a parent's ON DELETE CASCADE fires it at depth 2 and is
-- allowed through.
CREATE FUNCTION reject_ring_rollout_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() = 1 THEN
            RAISE EXCEPTION 'ring rollout creation evidence is immutable and may not be deleted directly';
        END IF;
        RETURN OLD;
    END IF;

    IF ROW(NEW.tenant_id, NEW.platform, NEW.label, NEW.version, NEW.created_at,
           NEW.catalogue_product_id, NEW.catalogue_target_id,
           NEW.catalogue_content_hash, NEW.catalogue_generated_at,
           NEW.verified_sha256, NEW.verified_signer, NEW.verified_at,
           NEW.rollout_mode, NEW.reason, NEW.idempotency_key,
           NEW.request_fingerprint, NEW.impact_snapshot)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.platform, OLD.label, OLD.version, OLD.created_at,
           OLD.catalogue_product_id, OLD.catalogue_target_id,
           OLD.catalogue_content_hash, OLD.catalogue_generated_at,
           OLD.verified_sha256, OLD.verified_signer, OLD.verified_at,
           OLD.rollout_mode, OLD.reason, OLD.idempotency_key,
           OLD.request_fingerprint, OLD.impact_snapshot) THEN
        RAISE EXCEPTION 'ring rollout creation evidence is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_ring_rollout_evidence_immutable
    BEFORE UPDATE OR DELETE ON ring_version_approvals
    FOR EACH ROW EXECUTE FUNCTION reject_ring_rollout_evidence_mutation();

-- PAT-1135 established the shared-token attribution contract, but
-- ring_config_changes was not one of migration 0092's six write surfaces.
-- Add the same honest split here: authenticated principal in changed_by,
-- untrusted caller claim and observed address in separate nullable columns.
ALTER TABLE ring_config_changes
    ADD COLUMN source_addr TEXT,
    ADD COLUMN claimed_actor TEXT;

-- This hand-copies migration 0044_emergency_change_type.sql's eleven-value
-- vocabulary (the only other migration that has ever touched this CHECK) and
-- adds 'rollout_created'. Postgres has no ALTER CONSTRAINT for a CHECK's
-- expression, so drop-and-recreate-with-the-full-list is this repo's
-- established pattern (0044 did the same thing to 0042's original list) —
-- there is no single authoritative in-DB source this migration could
-- reference instead. That makes this hand-copy a real drift risk: if this
-- list and the literal change_type values ring_config.go / ring_rollout.go /
-- internal/rings/advance.go actually INSERT ever diverge, an existing write
-- path starts failing with a CHECK violation instead of a compile error.
-- internal/handlers/ring_rollout_create_test.go's
-- TestRingConfigChangesChangeTypeVocabularyMatchesMigration re-derives the
-- Go-side vocabulary from real (non-test) source and asserts every value is
-- still admitted here — that test is the drift detector; keep both in sync.
ALTER TABLE ring_config_changes
    DROP CONSTRAINT IF EXISTS ring_config_changes_change_type_check;
ALTER TABLE ring_config_changes
    ADD CONSTRAINT ring_config_changes_change_type_check CHECK (change_type IN (
        'config_updated', 'device_override_set', 'device_override_cleared',
        'rollout_paused', 'rollout_resumed', 'rollout_skipped',
        'rollout_advanced', 'rollout_auto_paused', 'rollout_completed',
        'rollout_superseded', 'rollout_emergency_deploy', 'rollout_created'
    ));

COMMENT ON COLUMN ring_version_approvals.catalogue_content_hash IS
    'SHA-256 of the exact signed catalogue envelope reverified when this rollout was created.';
COMMENT ON COLUMN ring_version_approvals.impact_snapshot IS
    'Immutable affected/eligible/excluded count and reason snapshot calculated before first-band publication.';
COMMENT ON COLUMN ring_config_changes.claimed_actor IS
    'Unverified caller-supplied actor claim; changed_by remains the authenticated admin_shared_token principal.';
INSERT INTO schema_migrations (version) VALUES ('0107_ring_rollout_creation');
COMMIT;
