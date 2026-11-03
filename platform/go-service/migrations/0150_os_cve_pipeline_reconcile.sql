-- patched.im - PAT-1918: restore and operationalise the vendor OS CVE store.
--
-- Production never recorded the grandfathered 0050 migration and has no
-- os_cve_advisories table.  Some development databases do have the exact 0050
-- shape.  Accept those two states only: silently repairing an unknown partial
-- table would make the matcher trust a schema we did not prove.

BEGIN;

DO $pat1918$
DECLARE
    actual_columns TEXT[];
    expected_columns CONSTANT TEXT[] := ARRAY[
        'id|bigint|NO|nextval(''os_cve_advisories_id_seq''::regclass)|64|0',
        'os_platform|text|NO|||-',
        'os_version|text|NO|''''::text||-',
        'os_build|text|NO|''''::text||-',
        'cve_id|text|NO|||-',
        'cvss_v3_score|numeric|YES||4|1',
        'severity|text|YES|||-',
        'fixed_in_build|text|NO|''''::text||-',
        'source|text|NO|||-',
        'advisory_url|text|NO|''''::text||-',
        'published_at|timestamp with time zone|YES|||-',
        'synced_at|timestamp with time zone|NO|now()||-'
    ];
    has_primary_key BOOLEAN;
    has_advisory_unique BOOLEAN;
BEGIN
    IF to_regclass('public.os_cve_advisories') IS NULL THEN
        RETURN;
    END IF;

    SELECT array_agg(format('%s|%s|%s|%s|%s|%s',
               column_name, data_type, is_nullable, COALESCE(column_default, ''),
               COALESCE(numeric_precision::text, ''), COALESCE(numeric_scale::text, '-'))
           ORDER BY ordinal_position)
    INTO actual_columns
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'os_cve_advisories';

    IF actual_columns IS DISTINCT FROM expected_columns THEN
        RAISE EXCEPTION
            'PAT-1918 refuses unknown os_cve_advisories shape: columns=%',
            actual_columns;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_constraint c
        WHERE c.conrelid = 'public.os_cve_advisories'::regclass
          AND c.contype = 'p'
          AND pg_get_constraintdef(c.oid) = 'PRIMARY KEY (id)'
    ) INTO has_primary_key;

    SELECT EXISTS (
        SELECT 1
        FROM pg_constraint c
        WHERE c.conrelid = 'public.os_cve_advisories'::regclass
          AND c.contype = 'u'
          AND pg_get_constraintdef(c.oid) =
              'UNIQUE (os_platform, os_version, os_build, cve_id, source)'
    ) INTO has_advisory_unique;

    IF NOT has_primary_key OR NOT has_advisory_unique THEN
        RAISE EXCEPTION
            'PAT-1918 refuses os_cve_advisories without exact 0050 constraints (primary=%, unique=%)',
            has_primary_key, has_advisory_unique;
    END IF;

    IF pg_get_serial_sequence('public.os_cve_advisories', 'id')
       IS DISTINCT FROM 'public.os_cve_advisories_id_seq' THEN
        RAISE EXCEPTION 'PAT-1918 refuses os_cve_advisories with unexpected id sequence ownership';
    END IF;
END
$pat1918$;

CREATE TABLE IF NOT EXISTS os_cve_advisories (
    id                 BIGSERIAL PRIMARY KEY,
    os_platform        TEXT NOT NULL,
    os_version         TEXT NOT NULL DEFAULT '',
    os_build           TEXT NOT NULL DEFAULT '',
    cve_id             TEXT NOT NULL,
    cvss_v3_score      NUMERIC(4,1),
    severity           TEXT,
    fixed_in_build     TEXT NOT NULL DEFAULT '',
    source             TEXT NOT NULL,
    advisory_url       TEXT NOT NULL DEFAULT '',
    published_at       TIMESTAMPTZ,
    synced_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (os_platform, os_version, os_build, cve_id, source)
);

ALTER TABLE os_cve_advisories
    ADD COLUMN source_document_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN vendor_reference TEXT NOT NULL DEFAULT '';

ALTER TABLE os_cve_advisories
    ADD CONSTRAINT os_cve_advisories_platform_valid
        CHECK (os_platform IN ('macos', 'windows')),
    ADD CONSTRAINT os_cve_advisories_source_valid
        CHECK (source IN ('apple', 'msrc'));

CREATE INDEX IF NOT EXISTS idx_os_cve_platform_version
    ON os_cve_advisories (os_platform, os_version);
CREATE INDEX IF NOT EXISTS idx_os_cve_build
    ON os_cve_advisories (os_platform, os_build);
CREATE INDEX IF NOT EXISTS idx_os_cve_cve
    ON os_cve_advisories (cve_id);
CREATE INDEX IF NOT EXISTS idx_os_cve_source_document
    ON os_cve_advisories (source, source_document_id);

CREATE TABLE os_cve_source_documents (
    source              TEXT NOT NULL,
    document_id         TEXT NOT NULL,
    document_url        TEXT NOT NULL,
    source_revision     TEXT NOT NULL DEFAULT '',
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    advisory_count      INTEGER NOT NULL,
    CONSTRAINT os_cve_source_documents_pkey PRIMARY KEY (source, document_id),
    CONSTRAINT os_cve_source_documents_source_valid CHECK (source IN ('apple', 'msrc')),
    CONSTRAINT os_cve_source_documents_advisory_count_valid CHECK (advisory_count >= 0)
);

CREATE INDEX idx_os_cve_source_documents_fetched_at
    ON os_cve_source_documents (fetched_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON os_cve_advisories TO patched;
GRANT USAGE, SELECT ON SEQUENCE os_cve_advisories_id_seq TO patched;
GRANT SELECT, INSERT, UPDATE, DELETE ON os_cve_source_documents TO patched;

DO $pat1918_verify$
DECLARE
    required_index RECORD;
    actual_columns TEXT[];
BEGIN
    FOR required_index IN
        SELECT * FROM (VALUES
            ('idx_os_cve_platform_version', 'os_cve_advisories', ARRAY['os_platform', 'os_version']::TEXT[]),
            ('idx_os_cve_build', 'os_cve_advisories', ARRAY['os_platform', 'os_build']::TEXT[]),
            ('idx_os_cve_cve', 'os_cve_advisories', ARRAY['cve_id']::TEXT[]),
            ('idx_os_cve_source_document', 'os_cve_advisories', ARRAY['source', 'source_document_id']::TEXT[]),
            ('idx_os_cve_source_documents_fetched_at', 'os_cve_source_documents', ARRAY['fetched_at']::TEXT[])
        ) AS expected(index_name, table_name, column_names)
    LOOP
        SELECT array_agg(a.attname ORDER BY key_position.ordinality)
        INTO actual_columns
        FROM pg_class index_class
        JOIN pg_index index_metadata ON index_metadata.indexrelid = index_class.oid
        JOIN pg_class table_class ON table_class.oid = index_metadata.indrelid
        JOIN LATERAL unnest(index_metadata.indkey) WITH ORDINALITY AS key_position(attnum, ordinality) ON TRUE
        JOIN pg_attribute a ON a.attrelid = table_class.oid AND a.attnum = key_position.attnum
        WHERE index_class.relnamespace = 'public'::regnamespace
          AND index_class.relname = required_index.index_name
          AND table_class.relname = required_index.table_name
          AND index_metadata.indisvalid
          AND index_metadata.indisready
          AND NOT index_metadata.indisunique
          AND index_metadata.indpred IS NULL
          AND index_metadata.indexprs IS NULL;

        IF actual_columns IS DISTINCT FROM required_index.column_names THEN
            RAISE EXCEPTION
                'PAT-1918 refuses missing or incompatible index % on %: columns=%',
                required_index.index_name, required_index.table_name, actual_columns;
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.os_cve_advisories'::regclass
          AND conname = 'os_cve_advisories_platform_valid'
          AND contype = 'c'
          AND pg_get_constraintdef(oid) = 'CHECK ((os_platform = ANY (ARRAY[''macos''::text, ''windows''::text])))'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.os_cve_advisories'::regclass
          AND conname = 'os_cve_advisories_source_valid'
          AND contype = 'c'
          AND pg_get_constraintdef(oid) = 'CHECK ((source = ANY (ARRAY[''apple''::text, ''msrc''::text])))'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.os_cve_source_documents'::regclass
          AND conname = 'os_cve_source_documents_pkey'
          AND contype = 'p'
          AND pg_get_constraintdef(oid) = 'PRIMARY KEY (source, document_id)'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.os_cve_source_documents'::regclass
          AND conname = 'os_cve_source_documents_source_valid'
          AND contype = 'c'
          AND pg_get_constraintdef(oid) = 'CHECK ((source = ANY (ARRAY[''apple''::text, ''msrc''::text])))'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.os_cve_source_documents'::regclass
          AND conname = 'os_cve_source_documents_advisory_count_valid'
          AND contype = 'c'
          AND pg_get_constraintdef(oid) = 'CHECK ((advisory_count >= 0))'
    ) THEN
        RAISE EXCEPTION 'PAT-1918 advisory constraints were not created completely';
    END IF;
END
$pat1918_verify$;

INSERT INTO schema_migrations (version)
VALUES ('0150_os_cve_pipeline_reconcile')
ON CONFLICT (version) DO NOTHING;

COMMIT;
