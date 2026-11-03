-- PAT-2053: normalised, order-independent fingerprint of the public schema.
--
-- One line per schema object, pipe-separated, sorted. Built from the system
-- catalogues rather than from pg_dump text so that column order, pg_dump
-- version, comments, owners and grants never show up as a difference.
--
-- READ-ONLY. Every statement here is a SELECT against pg_catalog. The drift
-- check runs it inside a read-only transaction on patched-api-01 before any
-- migration is applied; it must never gain a write.
--
-- Deliberately excluded, because they are not what the migrations own:
--   * partitions (relispartition): raw_payloads months are created by
--     patched-partitions.timer, and their bounds depend on the session time
--     zone at creation. The partitioned parent and its partition key are kept.
--   * indexes, constraints and triggers inherited by partitions.
--   * objects that belong to an extension (pgcrypto's functions).
--   * NOT NULL catalogue constraints (contype 'n', PostgreSQL 18+); nullability
--     is already carried by the column line.
--   * comments, owners, grants and data.
--
-- Suffixes that only appear when something is off, so healthy lines stay
-- short: '|INVALID' on an index that is not valid or not ready (a failed
-- CREATE INDEX CONCURRENTLY), '|enabled:D' (or R, A) on a trigger that is not
-- in the default enabled state, and '|collate:<name>' on a column whose
-- collation differs from its type's default.
--
-- The first line records the server major version, because view and function
-- deparsing can differ between majors. Compare fingerprints only across the
-- same major (prod and CI both run PostgreSQL 16).

WITH rels AS (
    SELECT c.oid, c.relname, c.relkind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND NOT c.relispartition
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      AND NOT EXISTS (
          SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
      )
),
lines AS (
    SELECT 'server_major|' || (current_setting('server_version_num')::int / 10000)::text AS line

    UNION ALL
    SELECT 'extension|' || e.extname
    FROM pg_extension e
    WHERE e.extname <> 'plpgsql'

    UNION ALL
    SELECT 'relation|' || r.relname || '|' || r.relkind::text FROM rels r

    UNION ALL
    SELECT 'column|' || r.relname || '|' || a.attname || '|'
        || format_type(a.atttypid, a.atttypmod) || '|'
        || CASE WHEN a.attnotnull THEN 'not null' ELSE 'null' END || '|'
        || COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '')
        || CASE WHEN a.attidentity::text <> '' THEN '|identity:' || a.attidentity::text ELSE '' END
        || CASE WHEN a.attgenerated::text <> '' THEN '|generated:' || a.attgenerated::text ELSE '' END
        || CASE WHEN a.attcollation <> 0 AND a.attcollation <> ty.typcollation
                THEN '|collate:' || coll.collname ELSE '' END
    FROM rels r
    JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
    JOIN pg_type ty ON ty.oid = a.atttypid
    LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
    LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
    WHERE r.relkind IN ('r', 'p', 'v', 'm', 'f')

    UNION ALL
    SELECT 'partition_key|' || r.relname || '|' || pg_get_partkeydef(r.oid)
    FROM rels r WHERE r.relkind = 'p'

    UNION ALL
    SELECT 'constraint|' || r.relname || '|' || co.conname || '|' || pg_get_constraintdef(co.oid)
    FROM rels r
    JOIN pg_constraint co ON co.conrelid = r.oid
    WHERE co.contype <> 'n'

    UNION ALL
    SELECT 'index|' || r.relname || '|' || i.relname || '|' || pg_get_indexdef(i.oid)
        || CASE WHEN x.indisvalid AND x.indisready THEN '' ELSE '|INVALID' END
    FROM rels r
    JOIN pg_index x ON x.indrelid = r.oid
    JOIN pg_class i ON i.oid = x.indexrelid

    UNION ALL
    SELECT 'trigger|' || r.relname || '|' || t.tgname || '|' || pg_get_triggerdef(t.oid)
        || CASE t.tgenabled WHEN 'O' THEN '' ELSE '|enabled:' || t.tgenabled::text END
    FROM rels r
    JOIN pg_trigger t ON t.tgrelid = r.oid
    WHERE NOT t.tgisinternal

    UNION ALL
    SELECT 'view|' || r.relname || '|' || md5(pg_get_viewdef(r.oid))
    FROM rels r WHERE r.relkind IN ('v', 'm')

    UNION ALL
    SELECT 'sequence|' || r.relname || '|' || format_type(s.seqtypid, NULL) || '|'
        || s.seqstart || '|' || s.seqincrement || '|' || s.seqmin || '|' || s.seqmax || '|'
        || CASE WHEN s.seqcycle THEN 'cycle' ELSE 'no cycle' END
    FROM rels r
    JOIN pg_sequence s ON s.seqrelid = r.oid
    WHERE r.relkind = 'S'

    UNION ALL
    SELECT 'function|' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')|'
        || p.prokind::text || '|' || md5(pg_get_functiondef(p.oid))
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prokind IN ('f', 'p', 'w')
      AND NOT EXISTS (
          SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
      )

    UNION ALL
    SELECT 'type|' || t.typname || '|' || t.typtype::text || '|'
        || COALESCE((SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)
                     FROM pg_enum e WHERE e.enumtypid = t.oid), '')
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'public'
      AND t.typtype IN ('e', 'd')
      AND NOT EXISTS (
          SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
      )
)
SELECT line FROM lines ORDER BY line COLLATE "C";
