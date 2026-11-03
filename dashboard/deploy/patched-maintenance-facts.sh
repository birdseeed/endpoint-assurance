#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Emit a JSON snapshot of patch/reboot/timer drift for patched-prod-01 (PAT-989)
# ─────────────────────────────────────────────────────────────────────────────
# Designed to live on the box at /opt/patched-dashboard/deploy/ and run hourly
# via systemd timer (patched-maintenance-facts.timer). Also fine to invoke
# ad-hoc by hand (as root — reads /var/run/reboot-required, apt-check, Pro's
# purpose-specific attachment-status API).
#
# Observation-only: every query here is read-only. This script never applies
# updates, never reboots, never mutates package state or systemd units. It
# exists so nobody has to SSH in and look — the dashboard-side checker
# (_run_maintenance_drift_check_tick in main.py) reads the JSON this writes.
#
# Sibling boxes (patched-api-01, patched-portal-01) run their own emitters
# against this identical JSON schema — see main.py's maintenance-drift-check
# for the three-box consumer. Don't change field names here without updating
# all three.
#
# PAT-1408 added `stray_config_backups` (an array of {path, mode, owner,
# group, group_readable, world_readable} — see that section below) to THIS
# box's copy only; the api-01/portal-01 emitters don't have it yet (separate
# follow-up tickets). The dashboard-side consumer treats a missing key as
# "not reported", not as "zero found" — see _stray_config_backup_findings in
# main.py. Add it identically to the other two emitters when their tickets
# land, same discipline as every other field in this schema.
#
# PAT-1237 added `systemd_hardening` ({available, units: [{unit, score,
# rating, class, ceiling, over_ceiling}]}) — this field lands identically in
# all three emitters in the same change (see the PARITY-BLOCK below), unlike
# stray_config_backups above which was ported one repo at a time. The
# dashboard-side consumer is _systemd_hardening_findings in main.py.
#
# Usage:
#   patched-maintenance-facts.sh
#   (no arguments; OUT_FILE overridable via env for local testing.
#   CONFIG_BACKUP_ROOT likewise, default /etc — see stray_config_backups
#   section below; lets a test point the scan at a temp directory tree
#   instead of the real /etc.)
#
# Exit codes:
#   0  success — /var/lib/patched/maintenance.json written
#   1  preflight failure (not running as root, required tool missing)
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail
# Deliberately NOT `set -e`: most of the queries below (grep -c with zero
# matches, `systemctl is-enabled` on a disabled unit, `pro` being absent) exit
# non-zero in their normal, expected-on-this-box case. Each call that can
# legitimately fail is guarded explicitly instead, so a fleet-normal "this
# box has no ESM origin packages pending" can't be mistaken for a real error
# and abort the whole snapshot.

OUT_FILE="${OUT_FILE:-/var/lib/patched/maintenance.json}"

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    echo "ERR: must run as root (reads /var/run/reboot-required, Pro attachment status)." >&2
    exit 1
fi

for tool in jq apt-cache; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERR: $tool not installed." >&2
        exit 1
    fi
done

mkdir -p "$(dirname "$OUT_FILE")"

# ── pending_updates / security_updates ──────────────────────────────────────
# apt-check prints "pending;security" on STDERR, nothing useful on stdout.
# The classic swap trick below sends the original stderr to the command
# substitution (via stdout) and discards the original stdout.
apt_check_raw=""
if [ -x /usr/lib/update-notifier/apt-check ]; then
    apt_check_raw=$( { /usr/lib/update-notifier/apt-check; } 2>&1 1>/dev/null || true )
fi
pending_updates="${apt_check_raw%%;*}"
security_updates="${apt_check_raw##*;}"
[[ "$pending_updates" =~ ^[0-9]+$ ]] || pending_updates=0
[[ "$security_updates" =~ ^[0-9]+$ ]] || security_updates=0

# ── pro_attached / esm_updates ──────────────────────────────────────────────
# pro_attached is deliberately tri-state: true means the bounded Pro API
# positively confirmed both attachment and a valid contract; false means that
# same well-formed API response explicitly says detached; null means the
# status could not be established. esm_updates MUST remain JSON null unless
# Pro is positively attached — "0" would claim a clean ESM check that was
# never actually run.
pro_attached_json="null"
esm_updates_json="null"
if command -v pro >/dev/null 2>&1; then
    # `pro status --format=json` can block for over 90 seconds under this
    # unit's sandbox. This narrow API is proven there in under a second.
    # Keep command/API/shape failures unknown rather than presenting them as
    # an affirmative detached-Pro finding.
    if pro_json=$(timeout 10 pro api u.pro.status.is_attached.v1 2>/dev/null); then
        pro_attachment_state=$(printf '%s' "$pro_json" | jq -r '
            if .result == "success"
               and .errors == []
               and (.data.attributes.is_attached | type) == "boolean"
               and (.data.attributes.is_attached_and_contract_valid | type) == "boolean"
            then
                if .data.attributes.is_attached == true
                   and .data.attributes.is_attached_and_contract_valid == true
                then "attached"
                elif .data.attributes.is_attached == false
                then "detached"
                else "unknown"
                end
            else "unknown"
            end
        ' 2>/dev/null) || pro_attachment_state="unknown"

        case "$pro_attachment_state" in
            attached)
                pro_attached_json="true"
                esm_count=$(apt list --upgradable 2>/dev/null | grep -ci 'esm' || true)
                [[ "$esm_count" =~ ^[0-9]+$ ]] || esm_count=0
                esm_updates_json="$esm_count"
                ;;
            detached)
                pro_attached_json="false"
                ;;
        esac
    fi
fi

# ── reboot_required ──────────────────────────────────────────────────────────
reboot_required_json="false"
[ -f /var/run/reboot-required ] && reboot_required_json="true"

# ── running_kernel / newest_kernel ──────────────────────────────────────────
running_kernel=$(uname -r)
newest_kernel=$(
    { ls /boot/vmlinuz-* 2>/dev/null || true; } \
        | sed 's#.*/vmlinuz-##' \
        | sort -V \
        | tail -n1
)

# ── automatic_reboot_configured ─────────────────────────────────────────────
automatic_reboot_configured_json="false"
if apt-config dump 2>/dev/null | grep -qi 'Unattended-Upgrade::Automatic-Reboot "true"'; then
    automatic_reboot_configured_json="true"
fi

# ── third_party_pending ──────────────────────────────────────────────────────
# Only packages that are (a) installed on this box and (b) currently
# upgradable are reported — skipping absent packages is expected (prod-01
# has docker+nodejs, not grafana; that's fine).
THIRD_PARTY_PACKAGES=(
    tailscale docker-ce docker-ce-cli containerd.io docker-buildx-plugin
    docker-compose-plugin docker-ce-rootless-extras docker-model-plugin
    nodejs grafana
)

# Prints the origin description (repo URL/suite line) for a package's
# candidate version, by matching the Candidate: version against the
# corresponding line in the Version table and reading the line beneath it.
_pkg_candidate_origin() {
    local pkg="$1"
    apt-cache policy "$pkg" 2>/dev/null | awk '
        /^ *Candidate:/ { cand = $2 }
        /^ +[0-9*]/ {
            line = $0
            gsub(/^ *\*\*\* /, "", line)
            gsub(/^ +/, "", line)
            split(line, parts, " ")
            ver = parts[1]
            if (ver == cand && !done) {
                getline originline
                gsub(/^ +/, "", originline)
                print originline
                done = 1
            }
        }
    '
}

third_party_json="[]"
upgradable_list=$(apt list --upgradable 2>/dev/null || true)
for pkg in "${THIRD_PARTY_PACKAGES[@]}"; do
    line=$(echo "$upgradable_list" | grep -E "^${pkg}/" || true)
    [ -z "$line" ] && continue

    candidate=$(echo "$line" | awk '{print $2}')
    installed=$(echo "$line" | sed -n 's/.*\[upgradable from: \(.*\)\]/\1/p')
    origin=$(_pkg_candidate_origin "$pkg")

    third_party_json=$(echo "$third_party_json" | jq \
        --arg pkg "$pkg" --arg installed "$installed" \
        --arg candidate "$candidate" --arg origin "$origin" \
        '. + [{package: $pkg, installed: $installed, candidate: $candidate, origin: $origin}]')
done

# ── timers ────────────────────────────────────────────────────────────────
# Dynamically enumerated — new patched-*/hetzner-*.timer units are picked up
# automatically, no hardcoded unit list to keep in sync.
timers_json="[]"
timer_units=$(systemctl list-unit-files 'patched-*.timer' 'hetzner-*.timer' --no-legend 2>/dev/null | awk '{print $1}' || true)
while IFS= read -r unit; do
    [ -z "$unit" ] && continue

    enabled_state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "not-found")

    last_trigger_raw=$(systemctl show "$unit" -p LastTriggerUSec --value 2>/dev/null || true)
    last_trigger_iso="null"
    if [ -n "$last_trigger_raw" ] && [ "$last_trigger_raw" != "n/a" ] && [ "$last_trigger_raw" != "0" ]; then
        iso=$(date -u -d "$last_trigger_raw" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
        [ -n "$iso" ] && last_trigger_iso="\"$iso\""
    fi

    service_unit="${unit%.timer}.service"
    result=$(systemctl show "$service_unit" -p Result --value 2>/dev/null || true)
    case "$result" in
        success) last_result="success" ;;
        "") last_result="unknown" ;;
        *) last_result="failed" ;;
    esac

    timers_json=$(echo "$timers_json" | jq \
        --arg unit "$unit" --arg enabled "$enabled_state" \
        --argjson last_trigger "$last_trigger_iso" --arg last_result "$last_result" \
        '. + [{unit: $unit, enabled: $enabled, last_trigger: $last_trigger, last_result: $last_result}]')
done <<< "$timer_units"

# ── stray_config_backups (PAT-1408/1431/1433) ───────────────────────────────
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

stray_config_backups_json="[]"
for dir in "${CONFIG_BACKUP_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' f; do
        [ -e "$f" ] || continue
        base="$(basename "$f")"

        is_live=false
        for live in "${KNOWN_LIVE_CONFIG_BASENAMES[@]}"; do
            if [ "$base" = "$live" ]; then
                is_live=true
                break
            fi
        done
        [ "$is_live" = true ] && continue

        _stray_name_matches "$base" || continue

        mode=$(stat -c '%a' "$f" 2>/dev/null || true)
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo "unknown")
        group=$(stat -c '%G' "$f" 2>/dev/null || echo "unknown")

        # Last 3 octal digits (owner/group/other) -- robust to stat
        # occasionally reporting a 4th leading digit for setuid/sticky bits.
        # Known limitation (PAT-1408 non-author review, dismissed as
        # out-of-scope): this reads mode bits only, same as every other
        # permission check in this estate -- a POSIX ACL (setfacl) grant
        # widening access beyond what the mode bits show would be a false
        # negative here. Not fixed here because fixing it in one check only
        # would imply a guarantee the rest of the codebase doesn't make.
        #
        # PAT-1408 non-author review, round 3: an unparseable `stat` result
        # (empty, or a truncated/garbled value) must NOT quietly become
        # "000" and read as root-only-safe -- that is the exact
        # unknown-reads-as-clean shape this whole ticket exists to close,
        # just one level down from the missing-field case the dashboard
        # side already guards. `mode_unknown` records that we could not
        # positively confirm this file's permissions at all; the dashboard
        # consumer (_stray_config_backup_findings in main.py) treats that as
        # potentially readable -- fail closed, not open -- with a reason
        # that says "could not be determined", not "confirmed readable".
        mode3="${mode: -3}"
        mode_unknown_json="false"
        if [[ ! "$mode3" =~ ^[0-7]{3}$ ]]; then
            mode3="000"
            mode_unknown_json="true"
        fi
        group_digit="${mode3:1:1}"
        other_digit="${mode3:2:1}"
        group_readable_json="false"
        world_readable_json="false"
        [[ "$group_digit" =~ ^[4-7]$ ]] && group_readable_json="true"
        [[ "$other_digit" =~ ^[4-7]$ ]] && world_readable_json="true"

        # PAT-1433: a mode we could not read must not leak a "confirmed
        # false" reading in either boolean -- that is the same unknown-
        # reads-as-clean shape as the mode3="000" fallback above, just one
        # field over. Emit JSON null for both instead, so a future consumer
        # that reads these two booleans without checking mode_unknown first
        # (today's _stray_config_backup_findings in main.py does check it
        # first, and has been updated to also treat null explicitly) cannot
        # mistake "we never determined this" for "confirmed not readable".
        if [ "$mode_unknown_json" = "true" ]; then
            group_readable_json="null"
            world_readable_json="null"
        fi

        mode_display="0${mode3}"
        [ "$mode_unknown_json" = "true" ] && mode_display="unknown"

        stray_config_backups_json=$(echo "$stray_config_backups_json" | jq \
            --arg path "$f" --arg mode "$mode_display" \
            --arg owner "$owner" --arg group "$group" \
            --argjson group_readable "$group_readable_json" \
            --argjson world_readable "$world_readable_json" \
            --argjson mode_unknown "$mode_unknown_json" \
            '. + [{path: $path, mode: $mode, owner: $owner, group: $group,
                   group_readable: $group_readable, world_readable: $world_readable,
                   mode_unknown: $mode_unknown}]')
    done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null || true)
done

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

# ── systemd_hardening (PAT-1237) ────────────────────────────────────────────
# Scores every patched-owned systemd unit against patched.im/docs/systemd-
# hardening-floor.md's per-class ceiling. "patched-owned" is a property
# test, not a hardcoded list: any unit file under /etc/systemd/system whose
# name starts with "patched-" is scored, so a brand-new unit is picked up
# the next time this timer fires with zero code change here -- see the
# PARITY-BLOCK below for the class/ceiling policy itself and why a unit this
# scan finds but that policy does not recognise still gets scored but must
# never read as passing (class/ceiling/over_ceiling all JSON null -- the
# dashboard consumer, _systemd_hardening_findings in main.py, treats that as
# degraded, not "no ceiling, therefore fine"). This also auto-excludes the
# Hetzner vendor units on this box (hc-net-scan.service, hc-net-ifup@.service)
# without naming them: both fail the name-prefix test, so they're never
# candidates in the first place.
#
# systemd-analyze security's exit code is 0 regardless of rating -- confirmed
# live on prod-01: exit 0 for a 3.2 OK unit, a 9.6 UNSAFE unit, and even a
# unit name that doesn't exist ("Unit ... not found, cannot analyze.", still
# exit 0). The only reliable signal is the final "Overall exposure level for
# <unit>: <score> <RATING>" line, parsed by anchored text match against the
# known unit name, never by exit code or column position -- this estate's
# three boxes already run two different systemd major versions (255, 259)
# and both emit this exact line shape, but a locale or future version could
# still reflow the detail table above it. Bounded per-unit with `timeout` so
# one hung invocation cannot wedge the hourly timer.
#
# PAT-1237: if systemd-analyze exists but produces zero parseable scores
# across every candidate unit (a systemically broken invocation, as opposed
# to one unit's line failing to parse), the whole field fails closed to
# available=false/units=[] rather than reporting a units array that is
# technically non-empty but useless -- same "don't claim a positive result
# you can't back up" discipline as esm_updates_json above.
systemd_hardening_available_json="false"
hardening_units_json="[]"
hardening_candidate_count=0
hardening_parsed_count=0
if command -v systemd-analyze >/dev/null 2>&1; then
    systemd_hardening_available_json="true"
    hardening_unit_names=$(systemctl list-unit-files 'patched-*.service' --no-legend 2>/dev/null | awk '{print $1}' || true)
    # One scratch file for systemd-analyze's stderr, reused (truncated) per
    # unit rather than one mktemp per iteration.
    sa_err_file=$(mktemp)
    while IFS= read -r hunit; do
        [ -z "$hunit" ] && continue
        case "$hunit" in
            patched-*) ;;
            *) continue ;;
        esac

        fragpath=$(systemctl show "$hunit" -p FragmentPath --value 2>/dev/null || true)
        case "$fragpath" in
            /etc/systemd/system/*) ;;
            *) continue ;;
        esac
        hardening_candidate_count=$((hardening_candidate_count + 1))

        hclass=$(_systemd_hardening_class_for_unit "$hunit")
        hclass_json="null"
        hceiling_json="null"
        if [ -n "$hclass" ]; then
            hclass_json="\"$hclass\""
            hceiling_json=$(_systemd_hardening_ceiling_for_class "$hclass")
        fi

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
        sa_out=$(timeout 10 systemd-analyze security "$hunit" 2>"$sa_err_file" || true)
        hscore_json="null"
        hrating_json="null"
        marker="Overall exposure level for ${hunit}:"
        case "$sa_out" in
            *"$marker"*)
                after="${sa_out#*"$marker"}"
                cand_score=$(printf '%s\n' "$after" | awk '{print $1}')
                cand_rating=$(printf '%s\n' "$after" | awk '{print $2}')
                if [[ "$cand_score" =~ ^[0-9]+\.[0-9]+$ ]] && [[ "$cand_rating" =~ ^[A-Za-z]+$ ]]; then
                    hscore_json="$cand_score"
                    hrating_json="\"$cand_rating\""
                    hardening_parsed_count=$((hardening_parsed_count + 1))
                fi
                ;;
        esac
        if [ "$hscore_json" = "null" ]; then
            echo "ERR: systemd_hardening: no parseable exposure score for $hunit; reporting it unjudged. systemd-analyze stderr: $(tr '\n' ' ' < "$sa_err_file" | cut -c1-200)" >&2
        fi

        over_ceiling_json="null"
        # hceiling_json is checked as well as hclass_json (PAT-1237
        # non-author review): awk compares a numeric score against an EMPTY
        # ceiling as a string, and any non-empty string beats "", so a class
        # present in _systemd_hardening_class_for_unit but missing from
        # _systemd_hardening_ceiling_for_class would report over_ceiling
        # true for every unit of that class -- even a 0.5. Unreachable with
        # today's three classes; a one-word guard against the day a fourth
        # is added to one function and not the other. Missing ceiling then
        # reads as unjudged (null), which is the honest answer.
        if [ "$hclass_json" != "null" ] && [ "$hscore_json" != "null" ] && [ -n "$hceiling_json" ] && [ "$hceiling_json" != "null" ]; then
            if awk -v s="$hscore_json" -v c="$hceiling_json" 'BEGIN{exit !(s>c)}'; then
                over_ceiling_json="true"
            else
                over_ceiling_json="false"
            fi
        fi

        hardening_units_json=$(echo "$hardening_units_json" | jq \
            --arg unit "$hunit" \
            --argjson score "$hscore_json" \
            --argjson rating "$hrating_json" \
            --argjson class "$hclass_json" \
            --argjson ceiling "$hceiling_json" \
            --argjson over_ceiling "$over_ceiling_json" \
            '. + [{unit: $unit, score: $score, rating: $rating, class: $class,
                   ceiling: $ceiling, over_ceiling: $over_ceiling}]')
    done <<< "$hardening_unit_names"
    rm -f "$sa_err_file"

    if [ "$hardening_candidate_count" -gt 0 ] && [ "$hardening_parsed_count" -eq 0 ]; then
        systemd_hardening_available_json="false"
        hardening_units_json="[]"
    fi
fi

systemd_hardening_json=$(jq -n \
    --argjson available "$systemd_hardening_available_json" \
    --argjson units "$hardening_units_json" \
    '{available: $available, units: $units}')

# ── Assemble + write atomically ─────────────────────────────────────────────
tmp_file="${OUT_FILE}.tmp"
jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --argjson pending_updates "$pending_updates" \
    --argjson security_updates "$security_updates" \
    --argjson esm_updates "$esm_updates_json" \
    --argjson pro_attached "$pro_attached_json" \
    --argjson reboot_required "$reboot_required_json" \
    --arg running_kernel "$running_kernel" \
    --arg newest_kernel "$newest_kernel" \
    --argjson automatic_reboot_configured "$automatic_reboot_configured_json" \
    --argjson third_party_pending "$third_party_json" \
    --argjson timers "$timers_json" \
    --argjson stray_config_backups "$stray_config_backups_json" \
    --argjson systemd_hardening "$systemd_hardening_json" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        pending_updates: $pending_updates,
        security_updates: $security_updates,
        esm_updates: $esm_updates,
        pro_attached: $pro_attached,
        reboot_required: $reboot_required,
        running_kernel: $running_kernel,
        newest_kernel: $newest_kernel,
        automatic_reboot_configured: $automatic_reboot_configured,
        third_party_pending: $third_party_pending,
        timers: $timers,
        stray_config_backups: $stray_config_backups,
        systemd_hardening: $systemd_hardening
    }' > "$tmp_file"

chmod 0644 "$tmp_file"
mv -f "$tmp_file" "$OUT_FILE"

echo "patched-maintenance-facts: wrote $OUT_FILE"
