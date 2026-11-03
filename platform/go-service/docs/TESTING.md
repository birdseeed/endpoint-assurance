# Testing

How the Go service is tested, what coverage exists, and what is deliberately excluded.

---

## How to run

```bash
cd go-service
test -z "$(gofmt -l .)"  # formatting
go test ./...    # unit tests — all packages (no DB required)
go vet ./...     # static analysis
go build ./...   # compile check
```

All four commands run on every push/PR that touches `go-service/` via the `go-test` CI workflow (`.github/workflows/go-test.yml`). No external services required.

The workflow also runs `govulncheck` v1.8.0 (`govulncheck ./...`) at
callable-symbol level for every Go module, and fails on any finding.

Until 2026-09-24 a wrapper (`scripts/govulncheck_policy.py`) temporarily allowed
`GO-2026-6452` for `github.com/xuri/excelize/v2` v2.11.0, because the Go
vulnerability database had not yet recorded that release as fixed. It failed
closed as a stale exception once the database caught up, which is how its
removal was triggered (PAT-2122). If a temporary exception is ever needed again,
use the same shape: pin the exact advisory, module and version, and fail when
the finding disappears, so the exception cannot outlive its reason.

### Integration tests (PAT-227)

Integration tests live in `go-service/integration/` under the `integration` build tag. They require a live Postgres with all migrations applied from zero:

```bash
# Spin up an ephemeral Postgres (Docker) and run migrations + tests.
docker run -d --name patched-test \
  -e POSTGRES_USER=patched -e POSTGRES_PASSWORD=patched_test -e POSTGRES_DB=patched_test \
  -p 5432:5432 postgres:16

export TEST_DATABASE_URL="postgres://patched:patched_test@localhost:5432/patched_test?sslmode=disable"
export AGENT_CONFIG_SIGNING_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
cd go-service
go test -tags=integration -v -timeout=120s ./integration/

docker rm -f patched-test
```

The integration job (`.github/workflows/go-integration-test.yml`) runs automatically on every PR that touches `go-service/` or the migrations directory. It uses a GitHub Actions service container for Postgres — no VPS required.

For local PostgreSQL 16 binaries, `python3 scripts/tenant_readiness_local.py`
creates an owned temporary cluster with a private Unix socket and no TCP
listener. It ignores inherited database URLs and `PG*` settings, applies
migrations and runs the tenant-boundary checks, then stops and removes the
cluster. Use `--full` for the full integration and DB-backed Go package suites:
this mode binds its owned cluster only to `127.0.0.1` on an ephemeral port,
uses a fresh synthetic SCRAM password and UTF-8 `*_test` databases, and runs the
compliance fixtures without changing their loopback safety guards. Ordinary
and `--reproduce-disable` runs remain socket-only unless combined with `--full`.
A failed stop exits nonzero and retains the cluster, never deleting a potentially
running server's data; the log names the retained path for operator recovery.
`--pg-bin /path/to/postgresql/bin` selects the server binaries.

The catalogue audit check requires the migration-owning connection to reach the
mutation-rejecting trigger. It also exercises `SET LOCAL ROLE patched`, where
SQLSTATE `42501` permission denial is a valid refusal. The local harness gives
that application role fewer privileges than CI's initial PostgreSQL owner;
a successful mutation fails either case, and an unavailable role fails the check.

`--reproduce-disable` additionally runs the original PAT-2367 denial checker
alone on a fresh database. Its assertions are unchanged: a disabled explicit
mapping must return `403` for identity and device reads, even when its email
domain points to the same or another tenant. PAT-2379 promotes this checker
to ordinary `integration` coverage and adds revoked-tenant, normalisation,
explicit-override, domain-state, ambiguity and database-error regressions.

All DB-gated Go tests select their scratch database from `TEST_DATABASE_URL`.
Tests that exercise an application entrypoint which reads `DATABASE_URL` set
that application variable from `TEST_DATABASE_URL` with `t.Setenv`; the test
harness never uses `DATABASE_URL` as its gate or DSN source.

**PAT-2095 Unapproved-present summary.** `unapproved_presence_equivalence_test.go`
compares the summary against the full computation (`UnapprovedOverviewFull`,
`PolicyPresenceFull`, kept as the oracle) over randomised estates: 8 seeds of
60 mutation steps each (apps, extensions, Homebrew ingested through the real
extractor, renames, first-seen changes, device os flips, stale and deleted
devices, PAT-2135 retire and unretire decisions, app, extension and Homebrew
policy changes), with the summary brought up to date at random by ingest
refresh, dirty sweep, full rebuild or not at all. Reproduce a failure with the
logged `PATCHED_EQUIV_SEED=<n> PATCHED_EQUIV_SEEDS=1`; widen with
`PATCHED_EQUIV_SEEDS`. `unapproved_presence_concurrency_test.go` covers the
races (ingest during a policy write, rebuild or INSERT conflict, an inventory
transaction committing during refresh, a policy write during rebuild or
between preparation and the raise lock, two marks and two raises at once,
ingest while a mark is queued, durable deferral behind a held alert lock,
and a failed runner pass followed by alert and mail-delivery retry). It also
checks lifecycle deferral, preserved newer queue sequences, superseded absence
authority, the evidence-time gate, and the 0110, 0111 and 0164 migration
prerequisites. Lock synchronisation uses `pg_locks`, without
`pg_stat_activity` query visibility or the `pg_read_all_stats` role.
`unapproved_runner_fairness_test.go` holds real advisory/device locks to prove
independent episode/preparation deadlines and durable retry, preserves checks
through tenant revocation/restoration, and injects 21 failing tenants plus 51
failing batches ahead of healthy work to prove persisted selector rotation
across a fresh runner instance and cleanup after completion.
`unapproved_presence_perf_test.go` is the opt-in 10,000-device latency test
(`PATCHED_PERF_TESTS=1`), run in CI by its own step of `go-integration-test`
on a fresh database. It explicitly analyses the derived presence table after
the initial rebuild and after marking/raising, outside timed sections, so the
same latency budgets test the production-like analysed query plan.

**PAT-2496 encryption state.** `pat2496_encryption_state_test.go` builds its fixture
the way production data arrives: real-shaped macOS and Windows payloads are POSTed
to `/v1/inventory` and run through the extractor, so the signals carry the keys the
agents send (`filevault`, `bitlocker_os_drive`) and the evaluations are the
evaluator's own. It then reads every surface that states a device's encryption over
HTTP (Devices roster, device page, insurance evidence pack as JSON and CSV, the
Encryption & Disk Posture report's CSV) and requires them to agree, with one
encrypted Mac, one Windows device observed off and one device with no readable
state, and a device whose hostname begins with `=` that the pack names and the
CSV writers guard. `internal/report/encryption_state_test.go` and
`encryption_state_db_test.go` cover the one definition (`FetchEncryptionStates`)
itself; do not hand-seed `compliance_signals` under a key an agent does not send,
which is how the pack once passed its test while every Windows device read as unknown.

**What the integration tests cover:**
1. Fresh-DB migration run from zero (all forward migrations applied in order).
2. Every PAT-226 `valid/` + `edge/` fixture round-trips: POST → 200 → extractor → expected rows → admin endpoints return correct shape.
3. Every `invalid/` fixture is rejected with HTTP 400 by the schema validator in the handler.
4. `edge/empty-arrays.json`: `certificates:[]` prunes all cert rows (prune semantics); absent `pending_updates` is a no-op.
5. `valid/only-certificates.json` round-trips through `/admin/tenant/{id}/certs` with the 10-field cert shape.

---

## Test philosophy

**Pure functions get table-driven unit tests.** The evaluator and most extractor helpers are pure or near-pure functions with no side effects. They're fast, deterministic, and easy to parameterise.

**Renderer tests use hand-built fixtures.** The report packages (`internal/report`) have no DB dependency. Tests build `Report` / `ExecutiveSummary` structs directly and call the PDF renderers, asserting that:
- output starts with `%PDF-` (valid PDF magic)
- byte length is above a plausibility floor
- renderers don't panic on empty data (nil evals, nil apps, empty estate)

**Integration tests run in CI on every PR** (PAT-227). The `go-integration-test` CI job spins up an ephemeral Postgres service container, applies all migrations from zero, and exercises the full POST → extract → read-back pipeline using the PAT-226 golden fixtures.

**No live external calls in tests.** macOS `system_profiler` / `csrutil` invocations are never mocked — those paths live in the shell collector and are tested manually on a real Mac.

---

## Coverage by package

### `internal/evaluator` — `evaluator_test.go`

Table-driven tests for every comparator (`eq`, `neq`, `in`, `contains`, `gte`, `lte`) and edge cases:

| Test | What it covers |
|---|---|
| `TestEvaluate_Eq / In / Neq / Contains / GTE / LTE` | Pass and fail cases for each comparator; non-numeric observed value → `error` status for `gte`/`lte` |
| `TestEvaluate_ApplicableArch` | `applicable_arch` gate: arm64-only rule on x86_64 device → `not_applicable`; `ObservedValue` stays nil |
| `TestEvaluate_MissingSignal` | All three `treat_unknown_as` values (`fail`, `pass`, `not_applicable`); documents the fail-safe default |
| `TestEvaluate_ObservedValueRecorded` | Observed value is populated when the signal is present |
| `TestEvaluate_SeverityAndVersionPassthrough` | Severity and benchmark version are copied from the rule into each evaluation |
| `TestEvaluate_BadComparator` | Unknown comparator string → `error` status, no panic |
| `TestEvaluate_RealCISShape` | Smoke test with Andy's actual Mac signals; asserts known-compliant and known-failing controls match expectation |

### `internal/extractor` — `extractor_test.go`

Fixture-based tests using `testdata/sample-payload-v2.json` (a synthetic but realistic schema_v2 payload):

| Test | What it covers |
|---|---|
| `TestPayloadParse` | `json.Unmarshal` of the full fixture; spot-checks `schema_version`, `hw_uuid`, `os.version`, `apps` count, `icloud.signed_in` |
| `TestUUIDRegex` | `uuidRegex` accepts valid UUIDs (upper and lower case), rejects truncated, suffixed, and non-hex forms |
| `TestRenderJSONValue` | Handles quoted strings, numbers, booleans, null (→ not-ok), empty input; embedded escape sequences |
| `TestNullIfHelpers` | `nullIfEmpty` and `nullIfPlaceholder` edge cases (empty string, `"Unknown"`) |
| `TestComplianceRender` | Compliance signals from the fixture survive the JSON-render pass; catches shape changes that would silently drop signals |

Note: `Worker.Run`, `claimBatch`, `upsertDevice`, `upsertApps`, `insertComplianceSignals`, `insertEvaluations` are not covered by automated tests — they require a DB and are validated via the manual integration path.

### `internal/report` — `report_test.go` / `executive_test.go`

Fixture-based tests using hand-built `Report` and `ExecutiveSummary` structs (12 passing / 5 failing evaluations, mirroring Andy's verified extraction):

| Test | What it covers |
|---|---|
| `TestSummary` | `Report.Summary()` counts and percentage calculation |
| `TestRenderPDF_SmokeTest` | Full per-device PDF renders without error; output is a valid PDF |
| `TestRenderPDF_EmptyEvaluations` | Renderer doesn't panic when `Evaluations` is nil; summary degrades to zeros |
| `TestRenderPDF_AllSectionsEmpty` | Renderer handles absent `PendingUpdates`, `PatchHistory`, `Apps` |
| `TestFilterEvals` | `filterEvals` by status returns correct subsets |
| `TestSortAppsForReport` | Developer ID-signed apps sort before Apple-bundled apps; alphabetical within group |
| `TestSignerGroup` | Signer classification for sort ordering |
| `TestTruncate / TestAfterPipe / TestSummariseBenchmarks` | PDF helper utilities |
| `TestRenderExecutiveSummaryPDF_SmokeTest` | Executive summary PDF renders; valid PDF magic |
| `TestRenderExecutiveSummaryPDF_EmptyEstate` | Renderer handles zero-device tenant |
| `TestDeriveRecommendations_Coverage` | At least 3 recommendations generated; first mentions enrolment when MDM is a top failure |
| `TestDeriveRecommendations_NoFailures` | Cadence recommendation always present even for a perfect estate |
| `TestPluralAndTitleCase` | String utilities |

---

## What is deliberately not tested

- **Live Postgres / extractor integration.** `Worker.Run` and the upsert path are tested manually or against the staging DB.
- **macOS collector shell scripts.** `patched-collect.sh` and `patched-upload.sh` are exercised manually on a real Mac; `shellcheck` (CI) and `zsh -n` (CI) catch syntax issues.
- **HTTP handlers end-to-end.** Auth, ingestion, and report handlers are not wired up to an `httptest.Server` yet. The extractor unit tests cover the parsing and upsert logic that handlers depend on.
- **Microsoft Graph / Intune.** The Tier 3 Graph orchestration code (`internal/tier3/*`) was deleted in PAT-911 — nothing to test until it is rebuilt. This is not a statement that Graph is dead in general: it stays the (currently unbuilt) Tier 3 orchestration mechanism. See `go-service/docs/adr/0010-microsoft-graph-scope-reconciliation.md`.

---

## CI

Three workflows trigger on `go-service/**` changes:

| Workflow | File | What runs |
|---|---|---|
| `go-test` | `.github/workflows/go-test.yml` | `gofmt -l .`, rejects direct `DATABASE_URL` reads in Go tests, `go build ./...`, `go vet ./...`, `go test ./...` (ubuntu-latest) |
| `go-integration-test` | `.github/workflows/go-integration-test.yml` | Postgres-backed integration and DB-gated package tests, all selected by `TEST_DATABASE_URL` |
| `shell-lint` | `.github/workflows/shell-lint.yml` | `shellcheck` on bash scripts; `zsh -n` on zsh scripts |
| `acl-validate` | `.github/workflows/acl-validate.yml` | HuJSON validation on the Tailscale ACL file |

Pre-commit hook: `gitleaks protect --staged --redact` — runs on every `git commit` to catch accidental secret commits.
