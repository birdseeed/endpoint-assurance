# Migration conventions

Migrations are plain SQL applied in version order with `psql` (no migration
tool at MVP). Applied versions are tracked in the `schema_migrations` table.

## Rules for a NEW migration

CI (`check-hygiene.sh` + `check-grants.sh`, run by
`.github/workflows/migration-*.yml`) enforces these for every migration
numbered **0056 and above**:

1. **Unique version number.** Use the next free `NNNN_` prefix. Never reuse a
   number that already exists in this directory — even for an unrelated table.
2. **Transaction-wrapped.** Wrap the whole migration in `BEGIN; ... COMMIT;` so
   a partial apply cannot leave the schema half-migrated.
3. **Bookkeeping.** End with
   `INSERT INTO schema_migrations (version) VALUES ('NNNN_name') ON CONFLICT (version) DO NOTHING;`
4. **GRANTs.** Any `CREATE TABLE` / `CREATE SEQUENCE` must include
   `GRANT ... TO patched;` in the same file (the app role needs privileges, or
   production 500s with "permission denied" — this has happened twice,
   PAT-579/603). Partitions of an existing parent are reached through the
   parent's grants and don't need their own.
5. **Rollback file.** Provide `NNNN_name_rollback.sql` that reverses the change.

`0109_assessment_artifact_purge_anonymisation.sql` is replay-safe: it verifies
the deterministic 0108 constraint target, normalises named constraints and
triggers, and asserts that the shared PAT-1137 function still contains every
established survivor table. Its rollback is intentionally
fail-closed once any assessment audit row has been anonymised: deleted actor,
recipient and token identifiers cannot be reconstructed. It identifies that
irreversible state only through the migration-owned
`tenant_purge_anonymized_at` marker, never by guessing from nullable identity
fields. Before that point it restores the 0108 constraint and trigger
definitions transactionally and removes the unused marker column.

## Template

```sql
-- NNNN: <what and why> (PAT-XXX)
BEGIN;

CREATE TABLE example (
    id BIGSERIAL PRIMARY KEY,
    ...
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE example TO patched;
GRANT USAGE, SELECT ON SEQUENCE example_id_seq TO patched;

INSERT INTO schema_migrations (version) VALUES ('NNNN_example')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
```

## Grandfathered history (do NOT rewrite)

These already-applied migrations pre-date the conventions and are intentionally
left as-is (rewriting applied history is riskier than the mess):

- **Duplicate version numbers:** `0025`, `0033`, `0036`, `0037`, `0040` each
  appear on more than one file.
- **Missing GRANTs:** caught up idempotently by `0056_grant_all_to_patched.sql`.
- **Missing transaction wrapper / `schema_migrations` insert:** e.g. `0053`.

The CI guards skip everything at or below version `0055` for exactly this
reason. New work must follow the rules above.

## Prod vs. migrations: the schema-drift allowlist

`example-api-host`'s live schema is not guaranteed to be byte-identical to what
these migrations produce from an empty database — early tables were
hand-applied from pre-merge drafts, and `deploy.sh` never re-runs anything
below `MIGRATION_FLOOR`, so a drift introduced below that floor is invisible
to every CI and test database, which are always built from these migrations
from zero (PAT-2051 found `app_cpe_mappings` this way).

`deploy/api-01/schema_drift.py` closes that gap: on every deploy it
fingerprints the live database read-only, rebuilds the fingerprint these
migrations produce at the live database's own recorded head, and compares.
Differences are either accepted, when they are listed in
`deploy/api-01/schema-drift-allowlist.txt` with the reason and ticket that
accepted them (PAT-2053), or reported as unexplained drift and the deploy
stops before applying anything.

That allowlist is the canonical list of every live-vs-migration difference
this repo currently accepts. As of 2026-09-25 (PAT-2029 audit), the
from-zero schema these migrations produce matches `example-api-host` apart
from the entries recorded there.

## Compliance customer copy cleanup (0220)

`0220_compliance_customer_copy.sql` changes only eight exact shipped
`compliance_rules.description` values, guarded by rule key, benchmark and
benchmark version. It removes the parenthetical references from the two macOS
screen saver rules (0129/0130), Windows automatic updates and mandatory ASLR,
and removes the four 0174-owned descriptions' trailing markers entirely.
Fresh 0033 rows already have plain descriptions and remain untouched.
Nonmatching custom descriptions, every other rule field, evaluation history
and tenant-owned software justifications remain unchanged.

Before cleaning each matching row, the same transaction saves its UUID,
composite rule identity and original/cleaned descriptions in the private
`_migration_0220_compliance_copy_backup` table. This holds only global shipped
rule text, not tenant data, and is not exposed by an API. The selected rules
are locked until the update finishes. Replay preserves the original records;
pre-existing clean/custom descriptions are never claimed. The new table has
no foreign key or changes to the existing rule table.

Rollback restores saved descriptions only when the UUID, composite identity
and current cleaned description still match. Later edits and deleted/recreated
rules are preserved. It then drops only the private backup table and removes
0220's bookkeeping. Run **0220's rollback before 0174's rollback** so 0174 can
recognise its own inserted rows; fresh 0033 rows remain unmarked. 0174 still
fails closed if evaluations reference those rows. Reapplying 0220 captures and
cleans restored descriptions again. The binary deployment workflow never
rolls back migrations; this reverse order is for an explicitly chosen manual
DB rollback.

This does not finish PAT-2318: tenant zero's software justifications require an
owner-authorised hand DB write (or an explicit choice to keep the tenant data),
and deployed compliance copy still needs the authenticated production walk.
