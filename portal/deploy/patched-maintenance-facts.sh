#!/usr/bin/env bash
# Patched maintenance facts emitter — portal-01 (PAT-989).
#
# Read-only snapshot of patch/reboot/timer drift, written atomically to
# /var/lib/patched/maintenance.json. main.py's /healthz reads this file and
# republishes a bounded, aggregate-only view of it (see _maintenance_info()
# in main.py) - this file itself is never served directly.
#
# Run as root, on an hourly systemd timer (patched-maintenance-facts.timer);
# see patched-maintenance-facts.service alongside this script.
#
#   IMPORTANT: read-only. This script queries package/timer/kernel state and
#   never applies updates, never reboots, never mutates anything on the box
#   other than writing its own output file.
#
# "Never fabricate a healthy-looking default" applies here same as it does
# to main.py's /healthz: any field we cannot actually determine (e.g.
# esm_updates when the box isn't Pro-attached, or pending/security counts if
# apt-check's output doesn't parse) is emitted as JSON null, not 0 or false -
# reporting 0 when it's actually unknown is the exact misleading-zero bug
# this whole initiative exists to kill.
#
# stray_config_backups (PAT-1431) is ported identically -- same field set,
# same naming-match rules, same fail-closed-on-unparseable-mode semantics --
# from the dashboard box's copy (PAT-1408, dashboard/deploy/patched-
# maintenance-facts.sh). See that section below for the full rationale;
# don't let this box's copy drift from it.
#
# systemd_hardening (PAT-1237) lands identically in all three emitters in the
# same change (see the PARITY-BLOCK below), unlike stray_config_backups above
# which was ported one repo at a time. The dashboard-side consumer is
# _systemd_hardening_findings in main.py.
set -euo pipefail

OUT_DIR=/var/lib/patched
# Overridable for tests (PAT-1431, driving this script from Python via
# subprocess against a temp tree the same way api-01's PAT-1423 override
# already does) -- production never sets OUT_FILE, so this defaults to the
# same path as before.
OUT_FILE="${OUT_FILE:-$OUT_DIR/maintenance.json}"

# `id -u`, not $EUID, so a test harness can shim the check by putting a fake
# `id` earlier on PATH (matching how api-01/dashboard's tests do this) --
# $EUID is a bash builtin and can't be intercepted that way. Identical
# real-world behaviour: both read the process's effective UID.
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash deploy/patched-maintenance-facts.sh" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

# ---------------------------------------------------------------------------
# hostname
FACTS_HOSTNAME="$(hostname)"
export FACTS_HOSTNAME

# ---------------------------------------------------------------------------
# pending/security updates - /usr/lib/update-notifier/apt-check writes
# "pending;security" to STDERR (not stdout) and its exit status does not
# indicate success/failure of the check itself, so it must not trip
# `set -e`. If the output doesn't match the expected "N;N" shape (missing
# binary, unexpected format), both counts are left unknown (null) rather
# than guessed at.
APT_CHECK_RAW="$(/usr/lib/update-notifier/apt-check 2>&1 >/dev/null || true)"
FACTS_PENDING=""
FACTS_SECURITY=""
if [[ "$APT_CHECK_RAW" =~ ^([0-9]+)\;([0-9]+)$ ]]; then
  FACTS_PENDING="${BASH_REMATCH[1]}"
  FACTS_SECURITY="${BASH_REMATCH[2]}"
fi
export FACTS_PENDING FACTS_SECURITY

# ---------------------------------------------------------------------------
# ESM updates are only meaningful (and only ever counted) when this box is
# Pro-attached with a valid contract. The former full status query can block
# in canonical-livepatch for over a minute in this unit's systemd sandbox.
# Query the purpose-specific API instead, and bound even that call to 10
# seconds.
#
# FACTS_PRO_ATTACHED is deliberately tri-state: true means the API positively
# confirmed attached *and* contract-valid; false means a successful,
# well-formed API response explicitly said detached; blank becomes JSON null
# in the emitter below and means unknown. In particular, an unavailable pro
# command, timeout, API error, malformed response, or an attached-but-invalid
# contract must never be reported as detached. esm_updates stays null unless
# that first, stronger true condition holds. This preserves the distinction
# between "no ESM updates" and "we could not establish entitlement state".
FACTS_PRO_ATTACHED=""
if PRO_JSON="$(timeout 10s pro api u.pro.status.is_attached.v1 2>/dev/null)"; then
  FACTS_PRO_ATTACHED="$(printf '%s' "$PRO_JSON" | python3 -c '
import json
import sys

try:
    response = json.load(sys.stdin)
    data = response.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    attached = attributes.get("is_attached") if isinstance(attributes, dict) else None
    contract_valid = (
        attributes.get("is_attached_and_contract_valid")
        if isinstance(attributes, dict)
        else None
    )
    well_formed = (
        isinstance(response, dict)
        and response.get("result") == "success"
        and isinstance(response.get("errors"), list)
        and not response["errors"]
        and type(attached) is bool
        and type(contract_valid) is bool
    )
    if not well_formed:
        print("")
    elif attached is False:
        print("false")
    elif contract_valid is True:
        print("true")
    else:
        print("")
except Exception:
    print("")
')"
fi
export FACTS_PRO_ATTACHED

FACTS_ESM=""
if [[ "$FACTS_PRO_ATTACHED" == "true" ]]; then
  FACTS_ESM="$(apt list --upgradable 2>/dev/null | grep -ci esm || true)"
  [[ -z "$FACTS_ESM" ]] && FACTS_ESM="0"
fi
export FACTS_ESM

# ---------------------------------------------------------------------------
# reboot required
FACTS_REBOOT_REQUIRED="false"
[[ -f /var/run/reboot-required ]] && FACTS_REBOOT_REQUIRED="true"
export FACTS_REBOOT_REQUIRED

# ---------------------------------------------------------------------------
# kernels
FACTS_RUNNING_KERNEL="$(uname -r)"
export FACTS_RUNNING_KERNEL

shopt -s nullglob
vmlinuz_files=(/boot/vmlinuz-*)
shopt -u nullglob
FACTS_NEWEST_KERNEL=""
if [[ ${#vmlinuz_files[@]} -gt 0 ]]; then
  FACTS_NEWEST_KERNEL="$(printf '%s\n' "${vmlinuz_files[@]}" \
    | sed 's#.*/vmlinuz-##' \
    | sort -V | tail -n1)"
fi
export FACTS_NEWEST_KERNEL

# ---------------------------------------------------------------------------
# unattended-upgrades automatic reboot
FACTS_AUTO_REBOOT="false"
if apt-config dump | grep -qi 'Unattended-Upgrade::Automatic-Reboot "true"'; then
  FACTS_AUTO_REBOOT="true"
fi
export FACTS_AUTO_REBOOT

# ---------------------------------------------------------------------------
# third-party pending packages - only the two known third-party installs on
# this box's stock image. Only ever reported if actually installed, so a
# future box without qemu-guest-agent (or without tailscale) reports nothing
# for it rather than a fabricated "up to date" entry.
#
# pkg_origin PKG - repository host behind the package's *candidate* version
# (the version table's first/highest-priority entry, from `apt-cache
# policy`), not the installed one.
pkg_origin() {
  local pkg="$1" policy url
  policy="$(apt-cache policy "$pkg" 2>/dev/null || true)"
  url="$(printf '%s\n' "$policy" | awk '
    /Version table:/ { intable=1; next }
    intable && !found && /^[ *]+[^ ]+ [0-9]+$/ { found=1; next }
    intable && found { print $2; exit }
  ')"
  if [[ -z "$url" ]]; then
    return
  fi
  printf '%s\n' "$url" | sed -E 's#^[a-zA-Z]+://([^/]+)/.*#\1#'
}

THIRD_PARTY_LINES=""
for pkg in tailscale qemu-guest-agent; do
  dpkg -s "$pkg" >/dev/null 2>&1 || continue
  policy="$(apt-cache policy "$pkg" 2>/dev/null || true)"
  # Herestring, not a pipe: awk's early `exit` can close its end of a pipe
  # before printf finishes writing, which is a real, reproducible SIGPIPE
  # under set -o pipefail (hit in production on api-01's identical pattern,
  # 2026-08-07). A herestring hands awk a fully-written temp fd with no
  # concurrent writer to race against.
  installed="$(awk -F': ' '/^  Installed:/{print $2; exit}' <<< "$policy")"
  candidate="$(awk -F': ' '/^  Candidate:/{print $2; exit}' <<< "$policy")"
  if [[ -z "$installed" || -z "$candidate" || "$installed" == "$candidate" ]]; then
    continue
  fi
  origin="$(pkg_origin "$pkg")"
  THIRD_PARTY_LINES+="${pkg}"$'\t'"${installed}"$'\t'"${candidate}"$'\t'"${origin}"$'\n'
done
export FACTS_THIRD_PARTY="$THIRD_PARTY_LINES"

# ---------------------------------------------------------------------------
# timers - dynamically enumerated, never hardcoded, so a future
# patched-*.timer or hetzner-*.timer is picked up automatically.
TIMER_LINES=""
while IFS= read -r unit; do
  [[ -z "$unit" ]] && continue

  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  [[ -z "$enabled" ]] && enabled="not-found"

  last_trigger_raw="$(systemctl show "$unit" -p LastTriggerUSec --value 2>/dev/null || true)"
  last_trigger_iso=""
  if [[ -n "$last_trigger_raw" && "$last_trigger_raw" != "n/a" ]]; then
    last_trigger_iso="$(date -u -d "$last_trigger_raw" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  fi

  service="${unit%.timer}.service"
  result="$(systemctl show "$service" -p Result --value 2>/dev/null || true)"
  case "$result" in
    success) last_result="success" ;;
    "") last_result="unknown" ;;
    *) last_result="failed" ;;
  esac

  TIMER_LINES+="${unit}"$'\t'"${enabled}"$'\t'"${last_trigger_iso}"$'\t'"${last_result}"$'\n'
done < <(systemctl list-unit-files 'patched-*.timer' 'hetzner-*.timer' --no-legend 2>/dev/null | awk '{print $1}')
export FACTS_TIMERS="$TIMER_LINES"

# ---------------------------------------------------------------------------
# stray_config_backups (PAT-1408/1431/1433)
# PARITY-BLOCK-BEGIN: stray-config-backups-policy (PAT-1433)
# Byte-identical across all three patched-maintenance-facts.sh copies
# (dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy) from here
# to PARITY-BLOCK-END, checked by each repo's
# test_pat1433_stray_config_backups_parity.py. Edit this block in all three
# copies in the same change, or the parity test fails the next time it runs
# somewhere that can see all three repos (see that test's docstring for
# exactly when that is, and why it can't be a hard CI gate given the repos
# are independent).
#
# Detective guard, not a fix: nothing in any of these three repos' deploy
# scripts writes timestamped copies of live env files into these
# directories -- the historical stray copies found on-box (bak-pat687,
# pre-pat909-..., bak-20260723-pat936) encode ticket ids, meaning they were
# ad-hoc per-ticket human/session commands, not an automated writer. There is
# no script to fix. This scans for that recurring by hand again, so it's
# visible instead of invisible.
#
# Every /etc/patched-* top-level directory that exists on this box is
# scanned (top-level files only, -maxdepth 1) via a glob, not a hardcoded
# list -- a future /etc/patched-<newservice> is picked up automatically, no
# code change needed here (PAT-1433). This is not just future-proofing:
# the old hardcoded three-entry list never scanned /etc/patched-alerts
# (prod-01), /etc/patched-extractor (api-01), or /etc/patched-scan
# (portal-01) -- three real, currently-existing service directories the
# glob now covers from day one, confirmed against the live boxes at
# PAT-1433 review time, not hypothetical future ones. The one deliberate
# exclusion is any directory whose basename ends in "-backup"
# (patched-portal-backup today):
# that is a backup job's own config directory, not a service config
# directory, and its *.bak* contents (e.g. backup.env.bak-preconfig, which
# genuinely exists on portal-01) are legitimate and must not be flagged.
# Losing this exclusion makes this row permanently degraded and therefore
# ignored -- see test_backup_suffixed_dirs_always_excluded.
CONFIG_BACKUP_ROOT="${CONFIG_BACKUP_ROOT:-/etc}"
CONFIG_BACKUP_DIRS=()
shopt -s nullglob
for _cbd in "$CONFIG_BACKUP_ROOT"/patched-*; do
    [ -d "$_cbd" ] || continue
    case "$(basename "$_cbd")" in
        *-backup) continue ;;
    esac
    CONFIG_BACKUP_DIRS+=("$_cbd")
done
shopt -u nullglob

# Exact basenames of the live config files these directories actually serve.
# Never flag these, no matter what the pattern below would otherwise match --
# this is the anchor that keeps the scan "copies of the config", not "any
# file in the directory with a suspicious-looking name". backup.env
# genuinely exists in /etc/patched-api -- flagging it would leave this field
# permanently degraded and get it ignored.
KNOWN_LIVE_CONFIG_BASENAMES=(dashboard.env api.env portal.env env backup.env config.env)

# Broad name matching, because the thing being detected is a human inventing
# a filename ad hoc, not a convention. Catches:
#   - `bak`/`pre` as a dot-, dash-, or bare-separated token (bak-pat687,
#     dashboard.env.bak-pat687, dashboard.env.pre-pat909-...), including
#     glued straight onto a digit (bak20260819). Deliberately also matches a
#     live basename that happened to start with `pre`/`bak` + a digit (e.g.
#     a hypothetical `pre1.env`, PAT-1433 non-author review): no such file
#     exists in KNOWN_LIVE_CONFIG_BASENAMES today, and if one is ever added,
#     the allowlist above is where to exempt it -- narrowing the matcher
#     instead would risk missing the next glued-digit spelling of a real
#     incident.
#   - an explicit `.old`/`.orig`/`.save`/`.backup`/`.copy` suffix, dot- or
#     dash-separated (dashboard.env.old, dashboard.env-backup)
#   - an 8-digit (YYYYMMDD-style) timestamp suffix, with or without a
#     dot/dash separator (dashboard.env.20260819, portal.env20260819). The
#     separator used to be required (PAT-1433 non-author review): the
#     comment already claimed to catch a "bare" timestamp suffix, but the
#     regex demanded `[.-]` before it, so the actually-bare glued form
#     (portal.env20260819) was silently missed -- a check whose comment
#     overstates its own coverage is worse than an honest one, so this was
#     fixed to match what the comment always claimed rather than the other
#     way round.
# A check that only reports clean on a differently-spelled repeat of the
# same incident is worse than no check at all -- it would look like
# coverage while providing none.
_stray_name_matches() {
    local base="$1"
    [[ "$base" =~ ([.-]|^)(bak|pre)([.-]|[0-9]|$) ]] && return 0
    [[ "$base" =~ [.-](old|orig|save|backup|copy)$ ]] && return 0
    [[ "$base" =~ [0-9]{8}$ ]] && return 0
    return 1
}
# PARITY-BLOCK-END

# PARITY-BLOCK-BEGIN: systemd-hardening-ceilings-policy (PAT-1237)
# Byte-identical across all three patched-maintenance-facts.sh copies
# (dashboard/deploy, patched.im/api-vps-artefacts, portal/deploy) from here
# to PARITY-BLOCK-END, checked by each repo's
# test_pat1237_systemd_hardening_parity.py, modeled on PAT-1433's
# test_pat1433_stray_config_backups_parity.py. Edit this block in all three
# copies in the same change, or the parity test fails the next time it runs
# somewhere that can see all three repos (same caveat as PAT-1433's block:
# nowhere in CI, see that test's own docstring for why and where it does run).
#
# patched.im/docs/systemd-hardening-floor.md (PAT-991) is the authority for
# both halves of this policy -- which class each patched-owned unit belongs
# to, and the systemd-analyze security score ceiling per class. That doc
# defines the floor; this block is the guard PAT-991 itself said didn't
# exist yet. It was written because that guard's absence let
# patched-maintenance-facts.service -- the very script this block lives in
# -- ship with zero hardening directives and go undetected for 12 days
# across all three boxes (prod-01 9.6 UNSAFE, portal-01 7.0, api-01 6.3,
# all against a 6.0 scheduled-maintenance ceiling). PAT-1439 hardens those
# three units separately; this guard is deliberately landed and left FIRING
# against the still-unhardened units as its own acceptance evidence -- do
# not "fix" the breach by editing this policy to exempt
# patched-maintenance-facts.service.
#
# _systemd_hardening_class_for_unit is an explicit allowlist, NOT because a
# hardcoded list is the right pattern here -- PAT-1433's own stray-config-
# backups section exists specifically to replace one -- but because *which
# units get scored* is already a property test (see the FragmentPath +
# name-prefix scan outside this block, deliberately NOT a hardcoded list):
# every /etc/systemd/system/patched-*.service unit is scored automatically,
# no code change needed for a new one to be picked up. What genuinely cannot
# be inferred from the filesystem is which CLASS a new unit belongs to and
# therefore which ceiling applies -- that's a judgment call, same as adding
# a row to a table in a doc. The property this block guarantees is the other
# half of PAT-1237's point: a unit the scan finds but this mapping does NOT
# recognise must never be read as passing -- class/ceiling/over_ceiling all
# come back JSON null, and the dashboard consumer
# (_systemd_hardening_findings in main.py) treats all three nulls as
# "unclassified, degraded", never as "no ceiling, therefore fine". A
# brand-new unit landing unclassified is the single most important case this
# guard exists to catch, and by definition it can never already be in this
# list -- silently passing it would make the guard decorative.
#
# patched-scan.service and patched-scan-nvd-refresh.service (portal-01) were
# absent from the floor doc's class table before this ticket -- added here
# as application and scheduled-maintenance respectively, and to the floor
# doc's table in the same change. patched-maintenance-facts.service itself
# was ALSO absent from that table before this ticket -- added here as
# scheduled-maintenance (same class as its sibling hourly/nightly jobs) and
# to the floor doc's table alongside the other two, not exempted just
# because it is the unit that happened to surface the gap.
_systemd_hardening_class_for_unit() {
    local unit="$1"
    case "$unit" in
        patched-backup.service|patched-prod-backup.service|patched-portal-backup.service|patched-prod-restore-test.service)
            printf '%s' "credential-handling" ;;
        patched-api.service|patched-dashboard.service|patched-portal.service|patched-extractor.service|patched-scan.service)
            printf '%s' "application" ;;
        patched-cve-sync.service|patched-tooling-cve-refresh.service|patched-partitions.service|patched-alert-metrics.service|patched-dashboard-prune-reports.service|patched-prod-alerts.service|patched-maintenance-facts.service|patched-scan-nvd-refresh.service)
            printf '%s' "scheduled-maintenance" ;;
        *)
            printf '%s' "" ;;
    esac
}

# Ceiling per class, per patched.im/docs/systemd-hardening-floor.md's "Unit
# classes and score ceilings" table. Credential-handling gets the strictest
# ceiling because compromise there yields usable secrets directly, not just
# service disruption; application and scheduled-maintenance share a ceiling
# because a compromised process is bad regardless of how often it runs --
# see that doc for the full reasoning, not repeated here.
_systemd_hardening_ceiling_for_class() {
    case "$1" in
        credential-handling) printf '%s' "6.7" ;;
        application) printf '%s' "6.0" ;;
        scheduled-maintenance) printf '%s' "6.0" ;;
        *) printf '%s' "" ;;
    esac
}
# PARITY-BLOCK-END

STRAY_LINES=""
for dir in "${CONFIG_BACKUP_DIRS[@]}"; do
  [[ -d "$dir" ]] || continue
  while IFS= read -r -d '' f; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"

    is_live=false
    for live in "${KNOWN_LIVE_CONFIG_BASENAMES[@]}"; do
      if [[ "$base" == "$live" ]]; then
        is_live=true
        break
      fi
    done
    [[ "$is_live" == true ]] && continue

    _stray_name_matches "$base" || continue

    mode="$(stat -c '%a' "$f" 2>/dev/null || true)"
    owner="$(stat -c '%U' "$f" 2>/dev/null || echo "unknown")"
    group="$(stat -c '%G' "$f" 2>/dev/null || echo "unknown")"

    # Last 3 octal digits (owner/group/other) -- robust to stat occasionally
    # reporting a 4th leading digit for setuid/sticky bits. An unparseable
    # `stat` result (empty, or a truncated/garbled value) must NOT quietly
    # become "000" and read as root-only-safe -- that is the exact
    # unknown-reads-as-clean shape this whole ticket exists to close.
    # mode_unknown records that we could not positively confirm this file's
    # permissions at all; downstream consumers must treat that as
    # potentially readable -- fail closed, not open.
    mode3="${mode: -3}"
    mode_unknown="false"
    if [[ ! "$mode3" =~ ^[0-7]{3}$ ]]; then
      mode3="000"
      mode_unknown="true"
    fi
    group_digit="${mode3:1:1}"
    other_digit="${mode3:2:1}"
    group_readable="false"
    world_readable="false"
    [[ "$group_digit" =~ ^[4-7]$ ]] && group_readable="true"
    [[ "$other_digit" =~ ^[4-7]$ ]] && world_readable="true"

    # PAT-1433: a mode we could not read must not leak a "confirmed false"
    # reading in either boolean -- pass the literal token "null" through
    # the \x1f-delimited record instead, so the Python assembly step below
    # can emit JSON null for both rather than false. A future consumer
    # reading these two booleans without checking mode_unknown first cannot
    # then mistake "never determined" for "confirmed not readable".
    if [[ "$mode_unknown" == "true" ]]; then
      group_readable="null"
      world_readable="null"
    fi

    mode_display="0${mode3}"
    [[ "$mode_unknown" == "true" ]] && mode_display="unknown"

    # Field separator is \x1f (ASCII unit separator), not a tab -- unlike
    # the third-party-package/timer lines above, this record's first field
    # is a filesystem path taken directly from a directory this section
    # scans specifically because a human once typed an ad-hoc filename by
    # hand (that's the whole premise of this guard). A tab in such a name
    # is unlikely but not impossible, and a tab-delimited split on a path
    # containing a tab would silently produce the wrong field count -- the
    # Python side below used to `continue` past that, which made the stray
    # vanish from the report with no error, indistinguishable from no stray
    # existing at all. \x1f is not a character a path can realistically
    # contain, so this removes that failure mode outright rather than just
    # detecting it.
    STRAY_LINES+="${f}"$'\x1f'"${mode_display}"$'\x1f'"${owner}"$'\x1f'"${group}"$'\x1f'"${group_readable}"$'\x1f'"${world_readable}"$'\x1f'"${mode_unknown}"$'\n'
  done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null || true)
done
export FACTS_STRAY_CONFIG_BACKUPS="$STRAY_LINES"

# ---------------------------------------------------------------------------
# systemd_hardening (PAT-1237) - scores every patched-owned systemd unit
# against patched.im/docs/systemd-hardening-floor.md's per-class ceiling.
# "patched-owned" is a property test, not a hardcoded list: any unit file
# under /etc/systemd/system whose name starts with "patched-" is scored, so
# a brand-new unit is picked up the next time this timer fires with zero
# code change here - see the PARITY-BLOCK above for the class/ceiling policy
# itself and why a unit this scan finds but that policy does not recognise
# still gets scored but must never read as passing (class/ceiling/
# over_ceiling all JSON null - the dashboard consumer,
# _systemd_hardening_findings in main.py, treats that as degraded, not
# "no ceiling, therefore fine").
#
# systemd-analyze security's exit code is 0 regardless of rating - confirmed
# live on portal-01: exit 0 for a 4.3 OK unit and a 7.0 MEDIUM unit alike.
# The only reliable signal is the final "Overall exposure level for <unit>:
# <score> <RATING>" line, parsed by anchored text match against the known
# unit name, never by exit code or column position. Bounded per-unit with
# `timeout` so one hung invocation cannot wedge the hourly timer.
#
# Each unit's record is \t-delimited (like third-party-package/timer records
# above, not \x1f like the stray-config-backups path records) - a systemd
# unit name is drawn from a fixed, constrained character set
# ([A-Za-z0-9:_.\@-]) that cannot contain a tab, unlike an arbitrary
# filesystem path a human once typed by hand.
FACTS_SYSTEMD_HARDENING_AVAILABLE="false"
HARDENING_LINES=""
HARDENING_CANDIDATE_COUNT=0
HARDENING_PARSED_COUNT=0
if command -v systemd-analyze >/dev/null 2>&1; then
  FACTS_SYSTEMD_HARDENING_AVAILABLE="true"
  # One scratch file for systemd-analyze's stderr, reused (truncated)
  # per unit rather than one mktemp per iteration.
  sa_err_file=$(mktemp)
  while IFS= read -r hunit; do
    [[ -z "$hunit" ]] && continue
    case "$hunit" in
      patched-*) ;;
      *) continue ;;
    esac

    fragpath="$(systemctl show "$hunit" -p FragmentPath --value 2>/dev/null || true)"
    case "$fragpath" in
      /etc/systemd/system/*) ;;
      *) continue ;;
    esac
    HARDENING_CANDIDATE_COUNT=$((HARDENING_CANDIDATE_COUNT + 1))

    hclass="$(_systemd_hardening_class_for_unit "$hunit")"
    hceiling=""
    [[ -n "$hclass" ]] && hceiling="$(_systemd_hardening_ceiling_for_class "$hclass")"

    # Keep stderr, but to a SEPARATE file rather than merged into the
    # parsed output (PAT-1237 non-author review, two rounds). Round one
    # asked for stderr to be kept at all: an unparseable result already
    # surfaces honestly as a null score, and the consumer buckets it as
    # "could not be judged", so it is not a silent failure -- but with
    # 2>/dev/null there was nowhere to learn WHY, and this unit runs
    # under StandardError=journal so the diagnostic is free. Round two
    # then caught that the obvious fix, 2>&1, is wrong: stdout and
    # stderr merge into one pipe unsynchronised, so a warning can land
    # mid-line and corrupt the very score being parsed. Two streams,
    # two destinations -- stdout stays clean for parsing, stderr is
    # available verbatim for the log line below.
    : > "$sa_err_file"
    sa_out="$(timeout 10 systemd-analyze security "$hunit" 2>"$sa_err_file" || true)"
    hscore=""
    hrating=""
    marker="Overall exposure level for ${hunit}:"
    case "$sa_out" in
      *"$marker"*)
        after="${sa_out#*"$marker"}"
        cand_score="$(printf '%s\n' "$after" | awk '{print $1}')"
        cand_rating="$(printf '%s\n' "$after" | awk '{print $2}')"
        if [[ "$cand_score" =~ ^[0-9]+\.[0-9]+$ ]] && [[ "$cand_rating" =~ ^[A-Za-z]+$ ]]; then
          hscore="$cand_score"
          hrating="$cand_rating"
          HARDENING_PARSED_COUNT=$((HARDENING_PARSED_COUNT + 1))
        fi
        ;;
    esac
    if [[ -z "$hscore" ]]; then
      echo "systemd_hardening: no parseable exposure score for $hunit; reporting it unjudged. systemd-analyze stderr: $(tr '\n' ' ' < "$sa_err_file" | cut -c1-200)" >&2
    fi

    over_ceiling=""
    # The ceiling is checked as well as the class (PAT-1237 non-author
    # review): awk compares a numeric score against an EMPTY ceiling as a
    # string, and any non-empty string beats "", so a class present in
    # _systemd_hardening_class_for_unit but missing from
    # _systemd_hardening_ceiling_for_class would report over_ceiling true
    # for every unit of that class -- even a 0.5. Unreachable with today's
    # three classes; a one-word guard against the day a fourth is added to
    # one function and not the other. A missing ceiling then reads as
    # unjudged (null), which is the honest answer.
    if [[ -n "$hclass" && -n "$hscore" && -n "$hceiling" ]]; then
      if awk -v s="$hscore" -v c="$hceiling" 'BEGIN{exit !(s>c)}'; then
        over_ceiling="true"
      else
        over_ceiling="false"
      fi
    fi

    HARDENING_LINES+="${hunit}"$'\t'"${hscore}"$'\t'"${hrating}"$'\t'"${hclass}"$'\t'"${hceiling}"$'\t'"${over_ceiling}"$'\n'
  done < <(systemctl list-unit-files 'patched-*.service' --no-legend 2>/dev/null | awk '{print $1}')
  rm -f "$sa_err_file"

  if [[ "$HARDENING_CANDIDATE_COUNT" -gt 0 && "$HARDENING_PARSED_COUNT" -eq 0 ]]; then
    FACTS_SYSTEMD_HARDENING_AVAILABLE="false"
    HARDENING_LINES=""
  fi
fi
export FACTS_SYSTEMD_HARDENING_AVAILABLE
export FACTS_SYSTEMD_HARDENING="$HARDENING_LINES"

# ---------------------------------------------------------------------------
# Assemble + atomic write. JSON assembly is handed to python3 (already a
# hard dependency of this box) rather than hand-built in bash, so field
# values never need ad hoc shell-side escaping.
export FACTS_OUT_FILE="$OUT_FILE"
python3 - <<'PYEOF'
import json
import os
import tempfile
from datetime import datetime, timezone


def env_bool(name):
    return os.environ.get(name, "false").strip().lower() == "true"


def env_tri_bool(name):
    """Return true/false/null, preserving an emitter's explicit unknown."""
    value = os.environ.get(name, "").strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def env_int_or_none(name):
    value = os.environ.get(name, "").strip()
    if value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def env_str_or_none(name):
    value = os.environ.get(name, "").strip()
    return value or None


third_party = []
for line in os.environ.get("FACTS_THIRD_PARTY", "").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) != 4:
        continue
    pkg, installed, candidate, origin = parts
    third_party.append(
        {
            "package": pkg,
            "installed": installed,
            "candidate": candidate,
            "origin": origin or None,
        }
    )

timers = []
for line in os.environ.get("FACTS_TIMERS", "").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) != 4:
        continue
    unit, enabled, last_trigger, last_result = parts
    timers.append(
        {
            "unit": unit,
            "enabled": enabled,
            "last_trigger": last_trigger or None,
            "last_result": last_result or "unknown",
        }
    )

def _tri_bool(value):
    # PAT-1433: the bash side passes the literal token "null" for
    # group_readable/world_readable when mode_unknown is true -- that must
    # become JSON null here, not Python False, so a consumer reading these
    # two fields without checking mode_unknown first cannot mistake "never
    # determined" for "confirmed not readable".
    if value == "null":
        return None
    return value == "true"


stray_config_backups = []
for line in os.environ.get("FACTS_STRAY_CONFIG_BACKUPS", "").splitlines():
    if not line.strip():
        continue
    # \x1f (ASCII unit separator), not a tab -- the bash side's first field
    # is a filesystem path, and unlike package names/timer units above, a
    # path comes from a directory this section scans specifically because a
    # human once typed an ad-hoc filename by hand. \x1f is not a character a
    # path can realistically contain, so a tab (or any other printable
    # character) inside a stray's filename cannot shift the field count.
    parts = line.split("\x1f")
    if len(parts) != 7:
        # Absence must not read as clean (PAT-912/837/960, and the entire
        # premise of this guard, PAT-1408): a record this parser cannot
        # understand must not just vanish -- that is indistinguishable from
        # no stray existing at all. Surface it as an explicit
        # unparseable/unknown entry instead of silently dropping it. In
        # practice this branch should be unreachable now that \x1f makes
        # the split unambiguous; it exists as a second, independent
        # safeguard in case that assumption is ever wrong.
        stray_config_backups.append(
            {
                "path": line,
                "mode": "unknown",
                "owner": "unknown",
                "group": "unknown",
                # A record the parser itself couldn't split is exactly as
                # unknown as an unparseable stat mode (PAT-1433) -- null,
                # not a confirmed-false reading, for the same reason.
                "group_readable": None,
                "world_readable": None,
                "mode_unknown": True,
            }
        )
        continue
    path, mode, owner, group, group_readable, world_readable, mode_unknown = parts
    stray_config_backups.append(
        {
            "path": path,
            "mode": mode,
            "owner": owner,
            "group": group,
            "group_readable": _tri_bool(group_readable),
            "world_readable": _tri_bool(world_readable),
            "mode_unknown": mode_unknown == "true",
        }
    )


def _num_or_none(value):
    # PAT-1237: the bash side leaves the field blank ("") whenever a score
    # could not be parsed or a unit has no known class -- that must become
    # JSON null here, never 0.0 or a string, so a consumer comparing against
    # a ceiling can't accidentally treat "unknown" as "zero exposure".
    if value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _hardening_tri_bool(value):
    # Mirrors _tri_bool above: "" (blank field) means "never judged" and
    # must stay JSON null, distinct from a positively confirmed False.
    if value == "":
        return None
    return value == "true"


systemd_hardening_units = []
for line in os.environ.get("FACTS_SYSTEMD_HARDENING", "").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) != 6:
        # Same "absence must not read as clean" discipline as the stray-
        # config-backups unparseable-record branch above: a record this
        # parser cannot understand must surface as explicitly unjudged, not
        # silently vanish (which would look identical to "this unit doesn't
        # exist" rather than "we couldn't score it").
        systemd_hardening_units.append(
            {
                "unit": line,
                "score": None,
                "rating": None,
                "class": None,
                "ceiling": None,
                "over_ceiling": None,
            }
        )
        continue
    unit, score, rating, unit_class, ceiling, over_ceiling = parts
    systemd_hardening_units.append(
        {
            "unit": unit,
            "score": _num_or_none(score),
            "rating": rating or None,
            "class": unit_class or None,
            "ceiling": _num_or_none(ceiling),
            "over_ceiling": _hardening_tri_bool(over_ceiling),
        }
    )

systemd_hardening = {
    "available": env_bool("FACTS_SYSTEMD_HARDENING_AVAILABLE"),
    "units": systemd_hardening_units,
}

facts = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "hostname": os.environ.get("FACTS_HOSTNAME", "").strip(),
    "pending_updates": env_int_or_none("FACTS_PENDING"),
    "security_updates": env_int_or_none("FACTS_SECURITY"),
    "esm_updates": env_int_or_none("FACTS_ESM"),
    "pro_attached": env_tri_bool("FACTS_PRO_ATTACHED"),
    "reboot_required": env_bool("FACTS_REBOOT_REQUIRED"),
    "running_kernel": env_str_or_none("FACTS_RUNNING_KERNEL"),
    "newest_kernel": env_str_or_none("FACTS_NEWEST_KERNEL"),
    "automatic_reboot_configured": env_bool("FACTS_AUTO_REBOOT"),
    "third_party_pending": third_party,
    "timers": timers,
    "stray_config_backups": stray_config_backups,
    "systemd_hardening": systemd_hardening,
}

out_file = os.environ["FACTS_OUT_FILE"]
out_dir = os.path.dirname(out_file)
fd, tmp_path = tempfile.mkstemp(prefix=".maintenance.", suffix=".tmp", dir=out_dir)
try:
    with os.fdopen(fd, "w") as f:
        json.dump(facts, f, indent=2)
        f.write("\n")
    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, out_file)
except BaseException:
    os.unlink(tmp_path)
    raise
PYEOF

# Belt-and-braces: os.replace() preserves the temp file's mode across the
# rename, but re-assert it explicitly so a future refactor of the python
# block above can't silently regress the app user's read access.
chmod 0644 "$OUT_FILE"

echo "wrote $OUT_FILE"
