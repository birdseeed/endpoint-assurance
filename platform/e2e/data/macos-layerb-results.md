# PAT-739 T10 — macOS Layer B state-induction results

Run date: 2026-07-07. VM: `patched-e2e-macos` (Tart, freshly re-cloned from
`ghcr.io/cirruslabs/macos-sequoia-base:latest`, macOS 15.7.7 arm64).

3 real collection cycles were run against the real collector inside the VM:
**baseline → induce → collect (induced) → restore → collect (restored)**,
driven by `e2e/macos/run_layerb.sh`. Full per-rule ledger written to
`e2e/macos/artifacts/layerb-ledger.json` on each run.

## Headline counts (58 rules touched)

| Result | Count | Meaning |
|---|---:|---|
| **PASS** (full round-trip) | 22 | Real state flipped one way, dashboard verdict flipped; state flipped back, verdict flipped back. |
| **PASS** (partial — flip verified, restore blocked) | 1 | Gatekeeper: flip verified; the *revert* step is blocked by macOS itself (see below), not a defect. |
| **PASS** (no flip attempted, stable) | 1 | `sudo_timeout` — already compliant at baseline; left untouched by design, stayed pass all 3 cycles. |
| **BUG_CONFIRMED** | 7 | Real state changed, dashboard verdict did **not** move. Root-caused each one (below) — genuine collector defects, not harness flakiness. |
| **NOT_INDUCIBLE** | 25 | Genuinely can't be exercised in this harness (needs MDM enrolment, hardware/firmware, or is out of scope per the task brief). Baseline asserted honestly. |
| **NOT_EXERCISED** | 1 | Mechanism spot-verified working, but not included in the main 3-cycle batch. |
| **BLOCKED** | 1 | Not attempted — operational safety call (remote_login; see below). |

**23 rules had their dashboard verdict proven to track real endpoint state** (22 full
round-trips + gatekeeper's one-way flip). That is the core PAT-739 T10 assertion and it held.

## The 3 collection cycles (2026-07-07 run)

| Cycle | pass | fail | compliance % |
|---|---:|---:|---:|
| Baseline | 50 | 42 | 54.3% |
| Induced | 39 | 53 | 42.4% |
| Restored | 51 | 41 | 55.4% |

(Restored ≠ baseline exactly: gatekeeper stayed flipped to pass — see below —
so restored has one more pass than baseline.)

## Harness quirk found and worked around (not a collector bug)

`run-collection.sh`'s "wait for extractor" loop only fires when
`EVAL_COUNT == 0`. Once a device already has evaluations from a prior cycle,
`EVAL_COUNT` is never zero again, so the script immediately fetches device
detail without waiting for the *new* payload to be extracted — silently
returning stale (previous-cycle) verdicts. Confirmed by comparing each
evaluation's `evaluated_at` timestamp against the extractor log's
`raw_payload_id` extraction time. Worked around in `run_layerb.sh` via
`fresh_fetch()`, which polls the admin API directly and waits for the marker
rule's `evaluated_at` to change before trusting a read. `run-collection.sh`
itself was not changed (used standalone by other flows where this only
matters on repeat runs against the same device) — the equivalent freshness
fix landed for the Windows harness's `assert_verdicts.ps1` on the same
branch (PAT-739 review pass) and could be ported here as a follow-up if
`run-collection.sh` is used for repeat cycles again.

## Confirmed collector bugs (7) — filed as Linear tickets in the `updater` project

### 1. Sharing-daemon signals never track real state on Sequoia (5 rules)
`cis_macos_2_4_10_screen_sharing`, `cis_macos_2_3_3_2_smbd_disabled`,
`cis_macos_2_3_3_7_internet_sharing_disabled`, `cis_macos_4_2_httpd_disabled`,
`cis_macos_4_3_nfsd_disabled`.

`lib/sharing.sh` greps `launchctl print-disabled system` for the literal
substrings `=> false` / `=> true`. On macOS 15.7 that command instead prints
the words `enabled`/`disabled` — e.g. `"com.apple.smbd" => disabled` — so the
grep pattern **never matches, in either direction**, and every signal always
falls back to its hardcoded default. Verified directly on the VM, outside the
main induction batch: toggled `com.apple.smbd`'s disabled-bit both ways and
confirmed the exact grep pattern the collector uses never matches either
state. **Fix**: match on `=> (true|false|enabled|disabled)` or parse with
`launchctl print-disabled system | awk` more robustly.

### 2. `AUDIT_LOGS_MODE` can never detect a bad log-file permission
`cis_macos_3_5_audit_logs_mode`.

`lib/auth.sh` runs `find "$_AUDIT_DIR" -maxdepth 1 -type f -perm /0337`. The
GNU-style `/mode` ("any of these bits") operator is **not supported by
macOS/BSD `find`**, which errors `illegal mode string` (exit 1) — swallowed
by the trailing `2>/dev/null`, so `grep -q .` sees empty stdin and the signal
silently defaults to "Yes" (pass). Verified directly: created a `chmod 666`
dummy file in `/var/audit` and ran the exact `find` command by hand —
confirmed it errors and produces no output, regardless of the file's actual
permissions. This is a real false-negative on a security check: a
world-writable audit log file can never be detected on any real Mac. The
sibling owner/group checks (`find ! -user root`, `find ! -group wheel`) use
standard BSD-compatible syntax and **do** work correctly — verified in the
same run (`cis_macos_3_5_audit_logs_owner` and `..._group` both flipped
correctly). **Fix**: replace `-perm /0337` with `-perm +0337` (deprecated
BSD any-bit form, still supported) or an explicit `stat`-based bitmask test
matching the pattern already used for `AUDIT_CONTROL_MODE`/`AUDIT_FOLDER_MODE`.

### 3. `update_check_auto` is structurally unable to ever pass on this macOS version
`cis_macos_1_2_update_check_auto`.

`defaults write .../SoftwareUpdate AutomaticCheckEnabled -bool true` sticks
immediately after the write (read-back = `1`), but is silently dropped the
moment *any* `softwareupdate` scan runs — including the collector's **own**
`softwareupdate -l` call, which runs earlier in the very same
`collect_updates()` function, before this signal is read. Reproduced
independently of the induction harness: wrote the key, confirmed it read
back as `1`, ran `sudo softwareupdate -l`, and watched the key vanish from
the domain both mid-scan and after completion. `softwareupdated` appears to
fully rewrite this preference domain on any real scan pass and does not
persist this key on macOS 15.7 — plausibly a deprecated/non-functional
preference on current macOS. Because `collect_updates()` always runs
`softwareupdate -l` before reading `AutomaticCheckEnabled`, **this rule can
never report anything but fail/Unknown on this OS version**, regardless of
true user or MDM configuration.

## PASS with an interesting asymmetry: Gatekeeper

`cis_macos_2_5_2_1_gatekeeper` — baseline fail (disabled) → `spctl
--master-enable` → verdict flipped to pass (verified, real). Restore attempt
(`spctl --master-disable`) failed every time with: *"Globally disabling the
assessment system needs to be confirmed in System Settings."* This is a real
macOS behavior (re-disabling Gatekeeper globally requires interactive GUI
confirmation on this OS version; enabling has no such restriction) — not a
collector defect. The flip itself is fully proven; only the revert-to-baseline
leg is blocked. **The VM was left with Gatekeeper enabled** after this run
(cannot be undone without GUI/VNC access, out of scope here). Run `e2e/macos/vm.sh
reset` before a subsequent run if a pristine VM is needed.

## Blocked (not attempted, by design): remote_login

`cis_macos_2_4_4_remote_login` — baseline fail (On). `systemsetup
-setremotelogin off` requires an interactive `yes/no` confirmation and its
own prompt explicitly warns *"you will lose this connection and can only
turn it back on locally at the server."* This headless Tart VM has no
console/VNC path wired into the harness — SSH is the only control channel
for the rest of the run (including the restore step and the remaining
collection cycles). Tested safely first: ran the command with no stdin
piped in, confirmed it loops the confirmation prompt harmlessly (killed
locally after output-cap; VM state unaffected — remote login stayed On, no
hung process left on the VM side). Given the real risk of permanently
losing VM control mid-run with no way to complete the remaining ledger,
this flip was deliberately not executed. Baseline asserted only.

## Not inducible (25, asserted at baseline honestly)

- **`cis_macos_2_3_3_5_remote_management_disabled`** — attempted (`kickstart
  -activate` succeeded, "Activated Remote Management"), but the signal reads
  `mdmclient QuerySecurityInfo`, which returns empty on any unmanaged Mac
  regardless of ARD/kickstart state — requires real MDM enrolment.
- **7 hardware/firmware/OS-level rules** per the task brief: `filevault`,
  `sip`, `sealed_system_volume`, `secure_boot_arm64`, `amfi_enabled`,
  `mdm_enrolment`, `root_disabled`.
- **17 managed-prefs/Safari rules** — all read via MDM-deployed configuration
  profiles (`NSUserDefaults` managed-domain suite / `profiles -P -o stdout`).
  One local install was attempted: `profiles install -type configuration
  -path e2e/macos/t10-test.mobileconfig` (targeting
  `com.apple.applicationaccess/allowAirDrop`) — refused cleanly by the OS:
  *"profiles tool no longer supports installs. Use System Settings Profiles
  to add configuration profiles."* Confirms local CLI profile installation
  is fully disabled on this macOS version; genuinely not inducible without a
  real MDM server in the loop.

## Not exercised (1)

`cis_macos_3_5_audit_logs_no_acl` — not included in the main batch (the dummy
log file was given bad owner/group/mode but no ACL). Spot-verified separately
that the mechanism works: `chmod +a "everyone deny delete"
/var/audit/t10-dummy.log` was correctly detected by the collector's `ls -le |
grep -E '^\s+[0-9]+:'` pattern. No bug — just outside the 3-cycle batch scope.

## Scripts

- `e2e/macos/induce.sh` — apply\|restore driver; copies `apply_remote.sh` /
  `restore_remote.sh` + `original_pwpolicy.xml` / `induced_pwpolicy.xml` /
  `t10-test.mobileconfig` into the VM and runs the requested phase as root.
- `e2e/macos/apply_remote.sh` / `restore_remote.sh` — the actual per-group
  induction commands, run inside the VM.
- `e2e/macos/run_layerb.sh` — end-to-end orchestrator (baseline → apply →
  collect → restore → collect → ledger). Encodes the extractor-freshness
  poll fix described above.
- `e2e/macos/build_ledger.py` — builds `e2e/macos/artifacts/layerb-ledger.json`
  from the 3 collected JSON snapshots. Note: annotations (group names, bug
  root-causes, reasons) are specific to what was observed on the 2026-07-07
  run and are re-emitted verbatim on re-run — if real observed statuses
  differ after a collector fix, re-derive the `result` fields by hand.

## VM end state after the 2026-07-07 run

The VM (`patched-e2e-macos`) was left running with two residual, expected
divergences from a truly pristine base image:

1. **Gatekeeper is enabled** (could not be reverted via CLI — see above).
2. All other induced state was successfully reverted (firewall,
   printer-sharing, sharing-daemon disabled-bits, software-update prefs,
   screensaver, pwpolicy, audit file/folder perms + ACL + dummy log file,
   auto-login, `/Applications/PatchedTest.app` perms back to 777, sudoers.d
   drop-in removed, ARD deactivated).

Run `e2e/macos/vm.sh reset` before a subsequent run if a pristine VM is needed.
