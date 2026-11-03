# Schema drift check (PAT-2053)

Prod's schema can differ from what the migrations produce. Early tables were
hand-applied from pre-merge drafts, and `deploy.sh` never re-runs anything
below 0056, so CI and every test database pass while the box differs
(PAT-2051). This check makes that visible before a deploy writes anything.

## Pieces

| File | Role |
| --- | --- |
| `schema_fingerprint.sql` | Catalogue-only SELECT. One sorted line per table, column (type, nullability, default, non-default collation), constraint, index (flagged if invalid), trigger (flagged if not enabled), view, sequence, function, enum and extension in `public`. Ignores partitions, comments, owners, grants and data. |
| `schema_drift.py build-journal` | CI. Applies the forward migrations to an empty PostgreSQL 16 in lexical order and journals the fingerprint after every migration from 0056 on. |
| `schema-drift-check.sh` | The box. Read-only: fingerprints the live DB, rebuilds the expected fingerprint from the 0056+ migrations it records, and compares. Exit 0 clean, 1 drift, 2 refused. |
| `schema-drift-allowlist.txt` | Differences accepted on purpose, each with a reason. |
| `.github/workflows/schema-drift.yml` | Runs the tests against a real PostgreSQL 16, builds the journal, proves a planted column goes red, and uploads the journal as `schema-fingerprint-journal`. |

Run it by hand on `example-api-host` (read-only, safe at any time) with a journal
built from the commit the box is running:

```
/opt/patched-deploy-staging/schema-drift-check.sh --journal /opt/patched-deploy-staging/SCHEMA_FINGERPRINT_JOURNAL
```

## Wiring into the deploy (PAT-2062)

1. `api-build.yml` builds the journal on a `postgres:16` service from the
   migrations in the same checkout, proves it clean against the database it was
   built on, and copies it with `schema_drift.py`, `schema_fingerprint.sql`,
   `schema-drift-check.sh` and `schema-drift-allowlist.txt` into
   `go-service/dist/`. Each gets a `<sha256>  schema-drift:<name>` line in
   `BINARY_MANIFEST` and ships in the `api-01-binaries` artifact.
2. `deploy-api-01.yml` rsyncs those five files flat into
   `/opt/patched-deploy-staging/` with the binaries.
3. `deploy.sh`, after the staged-artefact and unit-contract checks and before
   the CVE timer is stopped or any migration runs, verifies all five against
   `BINARY_MANIFEST` (present, regular file, hash match), then runs
   `schema-drift-check.sh --journal ... --allowlist ...` with `DATABASE_URL`
   from `read_database_url` (never sourced). The check's output is printed
   indented with `| `, with the URL and its password redacted.

The mode is `SCHEMA_DRIFT_ENFORCE_DEFAULT` near the top of `deploy.sh`. Root
production cannot override it from the environment.

- `0`, warn-only: drift (exit 1), a refusal (exit 2 or any
  other non-zero), or check files that fail manifest verification print a
  `::warning::` line and the full output, and the deploy continues.
- `1`, enforce (the default since 2026-09-23): any of those prints `::error::` and stops the deploy before
  the timer is touched or any migration runs. Nothing on the box changes.

**Enforce is on.** It shipped warn-only and was flipped to `1` after the first
deploy that ran it (deploy-api-01 run 35907459408, 2026-09-23) logged
`schema drift check: OK` from `example-api-host` at 0175, with only the 14
allowlisted lines. `test_schema_drift_enforces_by_default` pins it.

**Recovering from a blocked deploy under enforce.** The check runs before
migrations, so under enforce the migration that would repair the drift can
never reach the box: the drift stops the very deploy that ships the fix. A
revert that removes a migration the box has already applied is refused the
same way (the box records a version the new journal does not contain). Two
recoveries, both in the fixing commit itself:

1. Drift the fixing migration reconciles: add `+`/`-` entries for exactly the
   reported lines to `schema-drift-allowlist.txt`, citing the ticket, ship the
   fix, then remove the entries in the next commit (they are reported as
   unmatched notes once the box is clean).
2. Anything the allowlist cannot express, including the unknown-head refusal:
   set `SCHEMA_DRIFT_ENFORCE_DEFAULT=0` in the fixing commit, deploy, confirm
   the log shows `schema drift check: OK`, then restore `1` in the next commit.

There is deliberately no runtime escape hatch. Any switch the deploy could
read at run time is either an environment override, which root production
refuses, or a staged file, which comes from the same CI build as `deploy.sh`
and so is no more audited than editing the constant. A reviewed commit is the
audit trail.

The check is bounded: `deploy.sh` kills it after 600 seconds (`timeout`),
and a timeout counts as a refusal in both modes.

The journal is always built from the commit being deployed. It covers every
0056+ version, so a box that skipped releases is still compared at its own
head.

## Out-of-order migrations

The expected schema is rebuilt from the versions the box actually records in
`schema_migrations`, not from "everything up to the head". If 0175 deployed
before 0174, the check skips 0174's journal step, says so in a note, and
compares against the rest, so it does not block the deploy that fills the gap.
It refuses instead (exit 2, naming the versions) when the skipped migration
touches the same table, function, type or extension as a later one the box has
applied, because then the expected shape would be a guess. It also refuses
when the box records a version the journal does not contain (for example a
binary rollback to an older build).

## Allowlist syntax

`+ <line>` accepts a line present only on the box, `- <line>` one missing from
it. Matching is exact. The only wildcard is a trailing `|*`, which matches
every line that starts with the text before the `*` (every column of one
table, say). `[]`, `?` and `*` elsewhere are literal, since types like
`text[]` appear in lines.

## What the fingerprint does not cover

Out of scope because Patched does not use them today: row-level security
policies and `relrowsecurity`, grants and default privileges, domains' check
constraints, composite types, publications, event triggers, and anything
outside the `public` schema. Owners are also out of scope, which matters for
the `enforcement_audit` postgres-ownership trap (PAT-1202). If any of these
starts to matter, extend `schema_fingerprint.sql`, rebuild the journal, and
re-baseline against prod.
