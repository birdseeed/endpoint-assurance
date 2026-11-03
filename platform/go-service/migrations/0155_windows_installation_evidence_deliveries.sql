-- PAT-1921: immutable, global installation-evidence delivery history.
-- The API only appends reviewed compiled publications. Tenant policy and
-- execution-catalogue publication never write this table.
BEGIN;

CREATE TABLE windows_installation_evidence_deliveries (
    delivery_version BIGINT PRIMARY KEY CHECK (delivery_version > 0),
    publication JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(publication) = 'object'),
    CHECK ((publication->>'delivery_version')::bigint = delivery_version),
    CHECK (publication ?& ARRAY['catalogue_version','content_hash','delivery_version','expires_at','published_at','schema_version','targets']),
    CHECK (publication->>'content_hash' ~ '^[0-9a-f]{64}$'),
    CHECK ((publication->>'schema_version')::integer = 1),
    CHECK (jsonb_typeof(publication->'targets') = 'array'),
    CHECK (jsonb_array_length(publication->'targets') <= 24),
    CHECK ((publication->>'expires_at')::timestamptz > (publication->>'published_at')::timestamptz)
);

CREATE FUNCTION guard_windows_installation_evidence_deliveries()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE latest BIGINT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Windows installation evidence history is immutable; publish a higher delivery version';
    END IF;
    PERFORM pg_advisory_xact_lock(1921, 1);
    SELECT COALESCE(MAX(delivery_version), 0) INTO latest FROM windows_installation_evidence_deliveries;
    IF NEW.delivery_version - latest <> 1 THEN
        RAISE EXCEPTION 'Windows installation evidence versions must be sequential';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER windows_evidence_append_guard BEFORE INSERT OR UPDATE OR DELETE
ON windows_installation_evidence_deliveries FOR EACH ROW
EXECUTE FUNCTION guard_windows_installation_evidence_deliveries();
CREATE TRIGGER windows_evidence_truncate_guard BEFORE TRUNCATE
ON windows_installation_evidence_deliveries FOR EACH STATEMENT
EXECUTE FUNCTION guard_windows_installation_evidence_deliveries();

GRANT SELECT, INSERT ON windows_installation_evidence_deliveries TO patched;
REVOKE UPDATE, DELETE, TRUNCATE ON windows_installation_evidence_deliveries FROM patched;

INSERT INTO schema_migrations (version) VALUES ('0155_windows_installation_evidence_deliveries') ON CONFLICT DO NOTHING;
COMMIT;
