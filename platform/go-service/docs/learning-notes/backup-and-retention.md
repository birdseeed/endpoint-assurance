# Backup and data retention

**Subsystem:** backup infrastructure, data lifecycle
**Related:** `api-vps-artefacts/BACKUP_DR.md` (full DR runbook), `api-vps-artefacts/OPERATIONS.md §Restic backups`

---

## 3-2-1 model

| Copy | Medium | Where | What |
|---|---|---|---|
| 1 — live | Postgres 16 | `example-api-host` | All inventory, compliance, posture data |
| 2 — off-site | Restic → R2 | Cloudflare R2 `patched-backups` | api-01 Postgres dump |
| 3 — local (retired) | Restic → NVMe | `pat-backup-01` (on-prem LAN, retired, PAT-401 canceled) | Was: GitHub mirrors + api-01 Postgres + prod-01 dashboard |

> **Historical note:** this doc originally described a 3-2-1 strategy with `pat-backup-01` as
> the local leg (copy 3 above). That box was retired (PAT-401
> canceled) and will not be rebuilt — see "Leg 2" below, kept for historical reference. The
> live strategy today is the off-site R2 leg (copy 2) plus Hetzner Cloud snapshots; see
> `api-vps-artefacts/DR_PLAN.md` for the current topology.

---

## Leg 1 — api-01 → Cloudflare R2 (03:00 UTC)

`patched-backup.timer` on `example-api-host` runs `/opt/patched-api/bin/backup.sh` nightly:

1. `pg_dump -Fc patched` piped to `restic backup --stdin --tag postgres`.
2. `restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --prune`.
3. `restic check` (repository integrity).
4. Write heartbeat to `/srv/backup/health/db-r2.json`.

Retention: 7 daily / 4 weekly / 3 monthly snapshots. `restic` uses AES-256 encryption; R2 also encrypts at rest.

---

## Leg 2 — pat-backup-01 (02:30 UTC) — RETIRED, historical

`pat-backup-01` is decommissioned (PAT-401 canceled); this leg no longer runs. Kept here as a
record of how the 3-2-1 model worked when it did.

`patched-backup.timer` on `pat-backup-01` ran `/opt/patched-backup/bin/backup-run.sh` nightly:

1. **GitHub mirrors** — `git clone --mirror` / `git remote update` for all `Patched-LTD` repos + `andybridson-patched/openclaw`. Full commit history preserved.
2. **Postgres pull** — `ssh root@100.64.10.1 'sudo -u postgres pg_dump -Fc patched'` pulled over Tailscale SSH → `/srv/backup/postgres/patched-latest.dump`.
3. **prod-01 dashboard** — `dashboard.db` (SQLite online backup) + `dashboard.env` pulled from `example-prod-host` over Tailscale SSH.
4. **Local Restic snapshot** — all three above snapshotted into `/var/backups/patched-restic` (retention: 14d/8w/12m/3y).
5. **Heartbeat scp** — ships per-leg heartbeat JSONs to `/srv/backup/health/` on `api-01`.

---

## Data retention (database)

| Table | Retention policy |
|---|---|
| `raw_payloads` | Partitioned monthly. Old partitions can be dropped once data is no longer needed (historical analysis). No automated pruning at MVP. |
| `compliance_evaluations` | Append-only, no automated retention. Every evaluation run adds rows; historical posture trends rely on this. |
| `compliance_signals` | Upserted per run (last-write-wins per `(device_id, key)`). Only the most recent signal value is kept in the table. |
| `device_apps` | Upserted per run (last_seen updated; old apps with `last_seen` stale may be pruned in future). |
| `devices` | Never deleted by the extractor. Manual ops if a device is decommissioned. |
| `seen_nonces` | Pruned periodically: rows older than 10 min are deleted to prevent unbounded growth. |

---

## RPO and RTO

| Service | RPO | RTO |
|---|---|---|
| api.patched.im Postgres | 24 h | 2–4 h |
| dashboard.patched.im SQLite | 24 h | 2 h |
| GitHub repos | 24 h | 30 min |

The 24-hour RPO reflects nightly backups. Data loss window is at most the previous night's backup — endpoint agents will re-send their next inventory payload on the next collection cycle (900s), so most recent device state is recoverable from the agents themselves within a day.

---

## Backup health monitoring

The ops dashboard Home → **Service Health** strip shows one row per backup job. A job goes red when the last success is > 26 hours ago. Jobs write heartbeat JSON to `/srv/backup/health/` on api-01; `GET /admin/health` reads them and returns `service_health.backup_jobs`.

```bash
# Quick check
curl -s http://127.0.0.1:8081/admin/health | jq '.service_health.backup_jobs'
```

---

## Key operational commands

```bash
# Check R2 snapshots (on api-01)
source /etc/patched-api/backup.env
restic snapshots

# Force a manual R2 backup run
/opt/patched-api/bin/backup.sh

# pat-backup-01 status check (historical — box retired, PAT-401 canceled; commands no longer reachable)
# ssh andy@100.64.10.3
# sudo cat /srv/backup/health/last-run.json

# Clear a stale restic lock (on api-01)
source /etc/patched-api/backup.env
restic unlock
```

---

## Key files

| File | Role |
|---|---|
| `api-vps-artefacts/backup.sh` | api-01 Restic→R2 script |
| `api-vps-artefacts/patched-backup.{service,timer}` | api-01 systemd units |
| `api-vps-artefacts/pat-backup-01/backup-run.sh` | pat-backup-01 orchestrator (retired, archived — see `pat-backup-01/ARCHIVED.md`) |
| `api-vps-artefacts/pat-backup-01/install.sh` | Idempotent installer for pat-backup-01 (retired, archived) |
| `api-vps-artefacts/BACKUP_DR.md` | Full DR runbook with recovery steps |
