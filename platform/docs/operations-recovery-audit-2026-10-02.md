# Operations and recovery audit, 2 October 2026

Prepared for PAT-2370 against source
`5fc47a4ffeada452aab074257cc54fb27aee2e10`, branch
`andy/pat-2370-recovery-audit`. Audit completed at `2026-10-02T19:40:42Z`.
This is a bounded source/evidence audit, not completion of the ticket. No SSH,
production operation, backup decryption, customer-data copy or notification was
performed. Requested leaf tier: `gpt-6.1-sol`, medium, fresh context; runtime
model/effort metadata is not exposed. No personal memory is used as proof.

## Evidence provenance

Paths below are repository-relative unless prefixed with `evidence/`.
`evidence/` means the local canonical archive
`/Users/example/Development/Patched.im/.claude/linear-runs/evidence/`.
Stored operating evidence was read during this audit; its host assertions were
not refreshed. Source existence and local test results are current observations.

| Evidence | What it establishes and its limits |
| --- | --- |
| `go-service/docs/architecture.md`, Current state, introduced by docs PR #713 at audit HEAD | Accepted API binary SHA is `25547e40f9fc3fde019d7344ce704f5785ea33a8`, installed `11:16:49Z`, migration `0221_app_usage_evidence`, full CVE activation `11:49:41Z`. Audit HEAD is a later documentation commit, not an installed binary claim. |
| `evidence/PAT-2363/resume20261002/third-live-proof.jsonl` | Workflow `36999490694` deploy success, receipt SHA `25547e40…`, CVE unit hashes match, scheduled result success and timer active. This is earlier 2 October evidence, not a new readback. |
| `evidence/recovery-partial-20261002.json` | Earlier SHA `1396f72d172e8f32962ad280de55e8354a0a149a`: API/extractor active and health 200 while CVE service failed. Demonstrates why health alone cannot prove CVE success; later accepted evidence supersedes it. |
| `evidence/resume-checkpoint-20261002.md`, 12:24 UTC checkpoint and PR #713 correction | Accepted recovery proofs were inspected; missing `LINEAR_API_TOKEN` remained PAT-2138. PR #713 merged before integration finished; subsequent checks passed. No claim that all checks passed before that merge. |
| PAT-2314 latest comment, `2026-09-30T02:21:58.883Z` | Config fix PR #696, merge `338d742`, deploy `36659414715`, service Result=success, config snapshot `f2d6e05b` at 03:21:30 BST includes nginx, Origin certificate/key and two env files. Database retention remains owner-gated. No new snapshot verification here. |
| `api-vps-artefacts/DR_PLAN.md`, restore-test history | Historical API snapshot `f5a69da9`, 4 July: 81 tables, restic 3 s, pg_restore 6 s, 25 s total, recorded source/restored count comparisons. Historical dashboard snapshot `64e0b604`, 10 August: integrity_check=ok, scans=146, clients=3, no observed elapsed time recorded. Neither is a current rehearsal. |

PAT-2370 was re-read In Progress with no blockedBy and no comments. PAT-2314 was
re-read In Review with its existing retention decision outstanding. A factual
evidence gap below is not a claim that access was attempted and failed.

## Source and deployed-path map

Every source path in this table was inspected at the audit SHA. Installed path
names come from source/runbooks; installed-byte equality for monitoring and
backup scripts has not been checked in this audit.

| Host/surface | Source/config | Installed evidence to collect |
| --- | --- | --- |
| `example-api-host`, API/extractor | `api-vps-artefacts/patched-api.service`, `patched-extractor.service`; `go-service/internal/extractor/extractor.go`; `go-service/internal/metrics/`; `alerting/` paths below | `/opt/patched-api/DEPLOYED_BINARIES`, installed binary hashes, unit results/timestamps, health and readiness separately. `/health` proves listening; `/ready` includes a bounded database query. |
| `example-api-host`, Prometheus | `api-vps-artefacts/alerting/prometheus.yml`, `prometheus-rules-patched.yml`, `selector-liveness/` | `/etc/prometheus/prometheus.yml`, `/etc/prometheus/rules/patched.yml`, current target freshness and selector coverage. API :8081; extractor :8083; node-exporter targets labelled with each of the three hostnames. |
| `example-api-host`, alert metrics | `api-vps-artefacts/alerting/patched-alert-metrics.sh`, `.service`, `.timer` | `/usr/local/bin/patched-alert-metrics.sh`; `/var/lib/prometheus/node-exporter/patched_alerts.prom` mtime, collector result and numeric gauges. Collector runs every five minutes. |
| Alert routing | `api-vps-artefacts/alerting/alertmanager.yml.template`, `MESSAGE-GRAMMAR.md` | Rendered config routing hash/validation without reading webhook values to output; receiver delivery proof still unrun. Slack `#alerts` is primary, Telegram disabled in template. Synthetic delivery needs an explicitly approved test destination. |
| `example-prod-host`, independent alerter | `api-vps-artefacts/alerting/prod-01/patched-prod-alerts.sh`, service/timer/env template | `/usr/local/bin/patched-prod-alerts.sh`, `/etc/patched-alerts/env` presence only, unit result/times. Checks dashboard/API health, disk and backup age. Slack credentials missing => hard failure, not silent success. Actual delivery not refreshed. |
| `example-api-host`, backups | `api-vps-artefacts/backup.sh`, `patched-backup.service`, `.timer` | `/opt/patched-api/bin/backup.sh`; `/srv/backup/health/db-r2.json`; nightly custom-format Postgres dump tagged `patched-db`, config includes env/TLS/Prometheus. Restic data-subset check is not a restore. |
| `example-prod-host`, backups/drill | `api-vps-artefacts/prod-01-backup/prod-backup.sh`, `restore-test.sh`, corresponding units | `/usr/local/libexec/patched-prod-backup/{prod-backup,restore-test}.sh`; `/srv/backup/health/{prod-r2,prod-r2-drill}.json`; SQLite, state reports, old reports if present, config. Drill restores to scratch, requires exactly one nonempty DB, integrity_check and scans/clients queries; replication failure is logged but does not invalidate the local restore. |
| `example-portal-host`, backups | `api-vps-artefacts/portal-01-backup/portal-backup.sh`, corresponding service/timer | `/opt/patched-portal-backup/bin/portal-backup.sh` per runbook; `/srv/backup/health/portal-r2.json`; scan SQLite/uploads/reports/config. Optional heartbeat POST logs missing transport configuration; local result can succeed without central receipt. No current host execution/snapshot/restore proof read here. |
| Reports and evaluator | `go-service/internal/reportsched/sweeper.go`; `go-service/internal/extractor/extractor.go`; `go-service/internal/evaluator/` | Scheduler logs generation failure and schedules retry, evaluator runs through extraction. Log/error retention and timestamped operator visibility require direct proof; no dedicated report-generation alert found in the inspected Prometheus rules. Customer reports/PDFs must remain on host during probes. |
| CVE | `go-service/cmd/patched-cve-sync/`; `go-service/internal/metrics/metrics.go`; Prometheus rules | Source includes queue backlog and refreshed-timestamp stale alerts; service/timer failure monitored through systemd rules. Receipt and successful scheduled execution were recorded earlier, but controlled-failure routing proof remains unrun. |

Backup mechanics are in `api-vps-artefacts/BACKUP_DR.md` and recovery scope in
`DR_PLAN.md`; `OPERATIONS.md` and `docs/prod-01-architecture.md` contain additional
runbooks. Their in-place stop/copy/pg_restore examples are disaster procedures,
not permission to perform this audit's rehearsal on production. BACKUP_DR's
July snapshot header still says prod/portal credentials are pending, despite
later recorded operating evidence for prod. Use dated evidence, not that header,
for runtime claims. RTO targets vary across DR_PLAN and
`docs/business-continuity-plan.md`; targets are not measured recovery times.

## Acceptance gaps and reuse

1. **Missing telemetry can look like zero:** `patched-alert-metrics.sh:20-30`
   sets `db_up=1` after a successful dead-letter query, then sets `lag=0` if
   the lag query alone fails. The resulting fresh textfile has no lag-query
   validity bit. When the first query fails, db_up=0 accompanies both zero
   gauges; consumers must honour that guard. No production occurrence claimed.
   Existing `test-patched-alert-metrics.sh` tests first-query failure, not
   second-query-only failure. Parent independently reproduced it locally at
   19:43:58 UTC: the second query exited 1, while the script exited 0 and emitted
   db_up=1 and lag=0. See the adjacent metrics-reproduction JSON for source hash
   and synthetic-only receipt. This is not an installed-host failure claim.
   Recommend a bounded operational fix with separate
   query validity before PAT-1966 consumes the count; dedupe before creating work.
2. **Absence versus staleness:** AlertMetricsStale checks textfile mtime;
   CVEMatchQueueMetricsStale checks a refresh timestamp. These controls do not
   by themselves prove deleted targets or missing individual series become
   unhealthy. Selector-liveness checks base series existence over a window;
   label-specific no-match is informational. Run current live coverage and
   controlled omission cases in isolation before asserting the acceptance.
3. **Time-stamped ingest/report failure and delivery:** prior real CVE failures
   are recorded, and local failure tests pass, but no controlled end-to-end
   ingest/report failure with delivered synthetic notification was performed.
   Recommend reuse of existing metrics/scheduler/alerter with a local capture
   receiver first, then an owner-approved test receiver. Production need not stop.
4. **Restore:** API has historical snapshot/count/time evidence, dashboard has
   historical snapshot/integrity/count evidence without elapsed time, portal
   isolated restore is unrun. Freshness, recovery duration and safe isolated
   target proof remain required. PAT-2314 already owns database pruning;
   do not duplicate it or prune during a drill. PAT-2138 owns the digest token gap.

## Read-only probe proposal, not executed

Parent review is required before executing this exact bounded proposal. Existing
API read-only root transport is known; prod/portal transport has not been tested.
Each host probe must start with `test "$(hostname)" = '<exact-host>' || exit 2`,
capture a UTC observation timestamp, and use allowlisted paths and unit names.
Limit each command to 20 seconds and every result to counts/status/time/hash.

- API: receipt allowlist `DEPLOYED_SHA`, `DEPLOYED_AT`, `MIGRATION_HEAD`; hash the
  three installed binaries and monitor scripts; systemctl show allowlist
  ActiveState/SubState/Result/ExecMainStartTimestamp/ExecMainExitTimestamp for API,
  extractor, CVE, collector and backup units; health/ready HTTP status only.
- All hosts: backup/drill heartbeat JSON allowlist job/status/last_success_at/
  last_run_at, omit free-text detail; heartbeat mtime and configured file presence
  booleans only. Hash static scripts and units, not credential-bearing env files.
- API Prometheus: bounded loopback queries for up, collector mtime, database
  validity and CVE freshness; emit sample count/value/timestamp and required
  coverage booleans, no tenant labels, raw metrics dump or target URLs.
- Restic enumeration needs a separately reviewed on-host wrapper: existing
  repository credentials may be consumed locally, never printed. Output only
  tag/snapshot-id/time/count; no env dump, restic path listing, restore or prune.

No general journal output, arbitrary SQL, environment contents, database rows,
JWTs, webhook URLs, reports, recipient identities or SSH credential discovery.
Errors become a bounded class and exit status, not unfiltered exception text.

## Rehearsal gates and required receipt

Before any restore, name an isolated target and its storage boundary,
source snapshot/tag/time, local credential-consumption mechanism, no external
egress or customer workers, explicit allowed restored data, and cleanup scope.
Prefer synthetic fixture rehearsal first. Restoring customer backups offhost,
decrypting secrets, or creating a scratch DB on shared production PostgreSQL
requires separate exact approval. Never substitute shared-production restore,
service stop/restart or DNS swap for an isolated test. Unknown access/credentials
remain **unverified**, not fabricated access failures.

The accepted receipt must record UTC start/end, elapsed seconds, snapshot ID/time
and age, restored schema/integrity/count/hash checks, recovery readiness outcome,
controlled failure class/detection time/recovery time, local test-receiver proof,
and cleanup verification. Report separate timings for copy, database restore and
service readiness. A backup service success or snapshots list cannot fill this.

## Local verification performed

At this audit timestamp, with temporary synthetic fixtures only:

- `bash api-vps-artefacts/alerting/test-patched-alert-metrics.sh`: exit 0, PASS.
- `DEVELOPER_DIR=/Library/Developer/CommandLineTools python3 -m unittest deploy/api-01/test_pat1790_prod01_backup_db_validation.py`:
  exit 0, 21 tests, including missing required tables and empty restored DB => fail.
- In `api-vps-artefacts/alerting/selector-liveness`,
  `DEVELOPER_DIR=/Library/Developer/CommandLineTools GOPROXY=off go test ./...`:
  exit 0, six packages pass. Loopback test servers are synthetic; no live query.

These prove existing local guards, not current backup integrity, full-system
recovery, delivered alerts or PAT-2370 completion. No implementation or new
tests were added. Follow-ups are proposals only; no tickets were created.

## 3 October evidence supplement

This dated supplement preserves the 2 October audit as historical evidence. The local synthetic receipt at `.claude/linear-runs/evidence/codex-queue-20261003/PAT-2370-synthetic/receipt.json` records a custom-format dump and restore using an owned loopback PostgreSQL 16 cluster with synthetic-only rows. Restored schema/constraints and ordered rows matched the source fixture. This verifies only that isolated synthetic path; it is not a real backup retrieval, production database restore, service recovery, or measured service RTO. The captured alert events were generated through loopback and retained locally; no customer notification or approved external destination was used.

The installed probe recorded an approximate observation time of 20:23 UTC on 3 October. Its installed metrics-script SHA-256 was `40317681ffb1fc224dbbec63646e6fcf7cfb6a185f6716d952432b6a1d320971`, different from the expected source hash; the independently retained installed script is authoritative for that observation. The installed Prometheus rules hash (`c5e87f928e7900b42947fd30911b9c322d220a1321ad2c2e791c990f9a1c566c`) and prod alerter hash (`767caf77afad89e321f59422e87dc5e9fd5bbb6a415e0c8d73fb5d1926729f0a`) matched their recorded expectations. The aggregate result was `count(up)=6; min(up)=1`, meaning six observed targets were up. The newest observed sample was about 0.22 seconds old; this does not establish freshness for every target.

The known lag-query failure remains visible in the synthetic receipt: the collector can emit `patched_db_up=1` with `patched_db_extractor_lag_rows=0` when only the lag query fails. The current acceptance still lacks complete report-generation failure visibility and evaluator database-test evidence; those checks were skipped and must not be represented as passing. PAT-2378 remains on hold.

Preserve PAT-2378's recorded deployed degraded-query operating-proof gate; this supplement neither satisfies nor replaces it. For PAT-2370, the recommendation is an authorised isolated rehearsal using a real backup and named test-notification destination, with service readiness, complete target freshness and the missing report/evaluator evidence captured. No source or production state was changed for this supplement. Probe timestamps above are approximate as recorded; no finer timestamp precision is asserted.
