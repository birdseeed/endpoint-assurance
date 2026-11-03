# systemd hardening floor (PAT-991)

A documented minimum for systemd units running on `example-api-host`, `example-prod-host`
and `example-portal-host`, and the `systemd-analyze security` score that goes with each
class. This exists because hardening has repeatedly happened per-unit rather than as a
standard: PAT-878 hardened `patched-backup.service` on api-01 from 9.2 UNSAFE to 6.7
MEDIUM, and its near-identical sibling on portal-01 was stood up unhardened from the
same template *the same morning* PAT-878 closed. A floor that isn't written down can't
be checked against, so nothing catches that at review time.

## Unit classes and score ceilings

| Class | Examples | Ceiling (`systemd-analyze security`) |
| --- | --- | --- |
| Credential-handling | `patched-backup.service`, `patched-prod-backup.service`, `patched-portal-backup.service`, `patched-prod-restore-test.service` | 6.7 MEDIUM |
| Application service | `patched-api.service`, `patched-dashboard.service`, `patched-portal.service`, `patched-extractor.service`, `patched-scan.service` | 6.0 MEDIUM |
| Scheduled maintenance / metrics | `patched-cve-sync.service`, `patched-tooling-cve-refresh.service`, `patched-partitions.service`, `patched-alert-metrics.service`, `patched-dashboard-prune-reports.service`, `patched-prod-alerts.service`, `patched-maintenance-facts.service`, `patched-scan-nvd-refresh.service` | 6.0 MEDIUM |

`patched-scan.service` and `patched-scan-nvd-refresh.service` (portal-01) and
`patched-maintenance-facts.service` itself (all three boxes) were missing from
this table before PAT-1237 added the drift guard below — none of the three had
ever been triaged against the floor. The guard's own unit→class mapping
(`_systemd_hardening_class_for_unit` in each `patched-maintenance-facts.sh`)
must stay in sync with this table; a unit present in one but not the other is
exactly the drift this document exists to prevent.

A credential-handling unit gets the strictest ceiling because compromise there yields
usable secrets (R2 keys, DB credentials) directly, not just service disruption. The
other two classes share a ceiling because a compromised application or maintenance
process is bad regardless of how often it runs - "runs every 5 minutes" is not on its
own a reason for a laxer floor, contrary to how `patched-alert-metrics.service` was
treated before it was hardened (9.6 UNSAFE as of 2026-07-30; see current state below).

`patched-dashboard.service` (3.2 OK) and `patched-portal.service` (4.3 OK) already meet
a stricter bar than this floor requires — the floor is a minimum, not a target to
converge on from above.

## Minimum directive set

Every unit in every class above must set:

```ini
NoNewPrivileges=true          # unless the unit genuinely needs a privilege
                               # transition mid-run (e.g. sudo -u postgres for
                               # peer-auth pg_dump) — record the reason inline
                               # if false, per patched-backup.service's example
PrivateTmp=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=<minimal set, found empirically, not copied from a template>
```

`ReadWritePaths=` should list only the specific paths the unit actually writes to (use
the `-` prefix for a path whose absence must not fail the unit, e.g. an optional
heartbeat file) — never leave the tree broadly writable because narrowing it later felt
risky. `ProtectHome=true` is not currently required across the board (several units run
as root and touch nothing under `/root` or `/home`, so it's a no-op there), but should
be set wherever a unit doesn't specifically need `/root`.

This list is deliberately the directive set already proven on
`patched-backup.service`, `patched-prod-backup.service` and
`patched-portal-backup.service` (PAT-878, PAT-991) — copy that reasoning, not just the
unit file, since `CapabilityBoundingSet` in particular is unit-specific and must be
derived empirically (start minimal, widen only on an actual observed failure, exactly
as `patched-backup.service`'s own comments document).

## Verifying a unit meets the floor

Read the score **live on the box**, never from the unit file in the repo — a deployed
unit can drift from what's committed:

```bash
ssh root@<box> 'systemd-analyze security <unit>.service'
```

The last line reads `Overall exposure level for <unit>.service: <score> <RATING>`.
Compare against the ceiling for that unit's class above.

## Current state (2026-08-19)

`patched-maintenance-facts.service` (all three boxes) — added to the scheduled-
maintenance class under PAT-1237, and hardened under PAT-1439. It had breached this
class's 6.0 ceiling on every box since 2026-08-07 and nothing detected it, because the
triage that produced the previous baseline enumerated the units *known to be bad*
rather than the units *present*.

Before, and after — the second column is the **committed unit file from this repo**,
run on the real box and scored with `systemd-analyze security` there, not a probe and
not a local estimate:

```
prod-01     9.6 UNSAFE  ->  1.8 OK
api-01      6.3 MEDIUM  ->  1.8 OK
portal-01   7.0 MEDIUM  ->  1.8 OK
```

Each of those runs also confirmed `LoadState=loaded`, `Result=success`, exit 0, the
full expected field set in the emitted JSON, `pro_attached: true`, and the output file
still at `0644` — that last one matters on prod-01 specifically, where the dashboard
reads `maintenance.json` as `www-data`.

Two directive choices here were derived empirically rather than copied, per this
document's own instruction to start minimal and widen only on an observed failure:

- `CapabilityBoundingSet=` is **empty**. An earlier candidate granted
  `CAP_DAC_READ_SEARCH`; removing it entirely was tested on all three boxes, changed
  nothing in the output, and improved the score from 2.0 to 1.8. The script runs as
  root and every file it reads is root-owned, so owner DAC permits the read with no
  capability at all. Do not add one back without a run that actually fails without it.
- `/var/lib/patched` comes from `StateDirectory=patched`, **not** a `ReadWritePaths`
  entry. The two are not interchangeable: `StateDirectory` creates the directory when
  absent, whereas `ReadWritePaths` requires it to exist already and fails the whole
  unit with `status=226/NAMESPACE` if it does not — verified live, not assumed. An
  earlier draft dropped `StateDirectory` to make the three units uniform; that traded
  a self-healing mechanism for an assumption about box state.

The three `ubuntu-advantage` entries in `ReadWritePaths` are load-bearing and must not
be trimmed as unused: the bounded `pro api u.pro.status.is_attached.v1` query writes
lock and log files there even for a read-only query. Under `ProtectSystem=strict`, an
unavailable API result must remain `pro_attached: null`, never be presented as a
detached state; PAT-1796 reserves `false` for a successful, well-formed response that
explicitly says it is detached.


## Prior state (2026-08-14)

Hardened, meeting the credential-handling ceiling:

```
patched-backup.service (api-01):             5.1 MEDIUM
patched-prod-backup.service (prod-01):       4.6 OK
patched-portal-backup.service (portal-01):   4.6 OK
patched-prod-restore-test.service (prod-01): 3.4 OK
```

The first three above were hardened under PAT-878/991. `patched-prod-restore-test.service`
is separate: it was 9.6 UNSAFE as of 2026-07-30 (tracked in PAT-1085) and was rescored
live with `systemd-analyze security` on 2026-08-14 at 3.4 OK, comfortably under this
class's 6.7 MEDIUM ceiling.

Hardened, meeting the scheduled maintenance / metrics ceiling (all three were also 9.6
UNSAFE as of 2026-07-30, tracked in PAT-1085; rescored live with `systemd-analyze
security` on 2026-08-14). `patched-alert-metrics.service` and `patched-prod-alerts.service`
were additionally confirmed byte-identical to their repo copies with a most recent run of
`Result=success`, `ExecMainStatus=0`, so hardening did not break them; that check was not
run against `patched-dashboard-prune-reports.service`:

```
patched-alert-metrics.service (api-01):             4.0 OK
patched-dashboard-prune-reports.service (prod-01):  2.9 OK
patched-prod-alerts.service (prod-01):              3.4 OK
```

Not re-checked as part of this doc; include in the next triage pass:

```
patched-installomator-sync.service (api-01)
hc-net-scan.service (prod-01) — possibly orphaned, last ran 2026-12-09 at boot
                                 with no timer; confirm it should exist before
                                 hardening it
```

## The drift guard (PAT-1237)

PAT-991's remaining scope was a guard that fails a maintenance check when a live unit's
score exceeds its class ceiling, or when a new unit lands unhardened. PAT-1237 built it:
each box's `patched-maintenance-facts.sh` now emits a `systemd_hardening` field scoring
every unit under `/etc/systemd/system` whose name starts with `patched-` (a property
test over what's actually installed, not a hardcoded list — see that script's own
comment), and the dashboard's `_systemd_hardening_findings` degrades the box's row when
any scored unit is over its class ceiling *or* is not in the class mapping above at all
— an unclassified unit must never read as passing, since a brand-new unit is by
definition unclassified until someone adds it here.

That guard immediately found what the 2026-08-14 triage below missed:
`patched-maintenance-facts.service` — the emitter script itself — shipped with zero to
14 hardening directives on the three boxes and breached its own scheduled-maintenance
ceiling everywhere: prod-01 9.6 UNSAFE, portal-01 7.0, api-01 6.3 (surveyed
2026-08-19). PAT-1237 deliberately did not fix this — it landed with the guard
correctly reporting the breach, as the acceptance evidence that the guard actually
fires. **PAT-1439 hardens `patched-maintenance-facts.service` on all three boxes and
PAT-1438 gives the unit pair a real deploy path** (dashboard's `sync_box_config()`,
patched.im's `deploy-api-01.yml`, portal's `deploy/install.sh` — each install now
`daemon-reload`s and re-enables/restarts the *timer*, never the oneshot `.service`,
and verifies the timer is still enabled and active afterwards). Until PAT-1439/PAT-1438
land and are deployed, the guard is expected to show this unit degraded on whichever
boxes still carry the old unit file, and that is correct behaviour, not a bug to
silence.
