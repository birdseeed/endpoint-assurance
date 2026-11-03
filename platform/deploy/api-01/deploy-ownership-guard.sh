#!/usr/bin/env bash
# deploy-ownership-guard.sh -- PAT-2310. A read-only check, run as root on
# patched-api-01, that nothing root runs, installs or reads from the paths
# deploy-api-01.yml manages is owned by a non-root or unknown uid, or is
# writable by group or other. PAT-2312 added a second path set for
# patched-prod-01 (`check --box prod-01`), for deploy-prod01-backup.yml.
#
# Why it exists. Three rsyncs in deploy-api-01.yml ran `rsync -a` without
# --chown, and -a gives each file the SENDER's uid. The GitHub-hosted runner
# is uid 1001, which has no passwd entry on api-01, so the files they placed
# belonged to a uid nobody held yet:
#   /opt/patched-api/bin/patched-maintenance-facts.sh  root runs it hourly
#   /opt/patched-prometheus-staging/*                  root runs and installs it
#   /etc/apt/apt.conf.d/52-automatic-reboot.conf       apt reads it as root
# The next account created on the box would have been given uid 1001 and
# could have rewritten any of them. Those rsyncs now pass --chown=root:root.
# This check is what notices the next placement that does not, or anything
# else that hands one of these paths to a non-root owner.
#
# prod-01 (PAT-2312). deploy-prod01-backup.yml had the same rsync without
# --chown, so /opt/patched-backup-setup and every file in it were uid 1001,
# which on prod-01 IS an account (`patched`), and root then ran install.sh
# from there. That rsync now passes --chown=root:root too.
#
# How it runs. deploy-api-01.yml pipes the RUNNER's copy of this file to the
# box over SSH (`... bash -s -- check < deploy/api-01/deploy-ownership-guard.sh`),
# once after the staging rsyncs and before root runs anything from them, and
# once after the last file is placed. deploy-prod01-backup.yml pipes it the
# same way with `check --box prod-01`, after its rsync and before install.sh.
# The copy that runs comes from the checkout, never from the box, so nothing
# on the box can edit it into passing. There is deliberately no box copy, and
# so no artefact-manifest.json entry and no copy in api-vps-artefacts/. By
# hand, from a checkout:
#   ssh root@patched-api-01 'bash -s -- check' < deploy/api-01/deploy-ownership-guard.sh
#   ssh root@patched-prod-01 'bash -s -- check --box prod-01' < deploy/api-01/deploy-ownership-guard.sh
#
# Rules, applied to every path under each checked tree and to each checked
# file:
#   1. a symlink fails: root would follow it wherever it points;
#   2. an owner uid with no passwd entry fails;
#   3. a group or other write bit fails (on a directory it lets the holder
#      swap a root-owned file for their own);
#   4. an owner other than root fails, unless the exact path is on the
#      allowlist below with that exact owner, or it is one of the legacy
#      extractor backups described below. Rules 1 to 3 still apply to both.
#      Both exceptions are api-01 paths and apply only to the api-01 set;
#      the prod-01 set has none.
#
# Exit codes: 0 ok, 1 a finding or a path that could not be read, 2 usage.
# The check changes nothing on the box.
#
# Test-only env overrides, refused when running as root (same stance as
# deploy.sh, so a root run cannot be pointed somewhere else):
#   PATCHED_OWNERSHIP_GUARD_PREFIX        prepended to every checked path
#   PATCHED_OWNERSHIP_GUARD_TRUSTED_UID   one more uid treated as root
#   PATCHED_OWNERSHIP_GUARD_SERVICE_USER  stands in for `patched`
#
# Portability: GNU find and stat on the box and in CI, BSD ones on a Mac (the
# tests). Only POSIX find predicates plus -maxdepth are used, and stat's
# flavour is detected once. Every step is an explicit check; nothing relies
# on `set -e`.
set -uo pipefail

OVERRIDE_NAMES="PATCHED_OWNERSHIP_GUARD_PREFIX PATCHED_OWNERSHIP_GUARD_TRUSTED_UID PATCHED_OWNERSHIP_GUARD_SERVICE_USER"

# Path sets, one per box. `check` alone selects api-01, so deploy-api-01.yml
# is unchanged by PAT-2312; `check --box prod-01` selects prod-01.
#
# api-01 (PAT-2310).
# The two service trees must exist; deploy.sh installs the binaries there.
API01_REQUIRED_TREES="/opt/patched-api /opt/patched-extractor"
# Staging trees root runs or installs from. Each is checked when present;
# /opt/patched-deploy-staging only exists between the binary rsync and the
# end of a successful deploy.sh, which deletes it.
API01_OPTIONAL_TREES="/opt/patched-deploy-staging /opt/patched-prometheus-staging /opt/patched-systemd-staging /opt/patched-cve-systemd-staging"
# Single files the workflow places outside those trees.
API01_OPTIONAL_FILES="/etc/apt/apt.conf.d/52-automatic-reboot.conf"
#
# prod-01 (PAT-2312).
# deploy-prod01-backup.yml rsyncs the backup artefacts here and root then
# runs install.sh from it, so it must exist by the time the check runs.
PROD01_REQUIRED_TREES="/opt/patched-backup-setup"
# install.sh installs the two scripts the backup and restore-drill units run
# as root here. It is absent only before the first install, when there is
# nothing in it for root to run.
PROD01_OPTIONAL_TREES="/usr/local/libexec/patched-prod-backup"
PROD01_OPTIONAL_FILES=""

BOX=""
REQUIRED_TREES=""
OPTIONAL_TREES=""
OPTIONAL_FILES=""

MAX_REPORTED=50

PREFIX=""
TRUSTED_UID=""
SERVICE_USER="patched"
FINDINGS=""
FINDING_COUNT=0
READ_FAILED=""
ALLOWED=""
TOLERATED=0
CHECKED=""
ABSENT=""

say() {
    printf 'deploy-ownership-guard: %s\n' "$*"
}

# ::error:: is a workflow command GitHub parses from STDOUT only; on stderr
# it would reach the raw log but not the run page.
err() {
    printf '::error::deploy-ownership-guard: %s\n' "$*"
}

usage() {
    echo "usage: deploy-ownership-guard.sh check [--box api-01|prod-01]" >&2
}

# select_box NAME: load that box's path set. Unknown names are a usage error.
select_box() {
    case "$1" in
        api-01)
            REQUIRED_TREES="$API01_REQUIRED_TREES"
            OPTIONAL_TREES="$API01_OPTIONAL_TREES"
            OPTIONAL_FILES="$API01_OPTIONAL_FILES"
            ;;
        prod-01)
            REQUIRED_TREES="$PROD01_REQUIRED_TREES"
            OPTIONAL_TREES="$PROD01_OPTIONAL_TREES"
            OPTIONAL_FILES="$PROD01_OPTIONAL_FILES"
            ;;
        *) return 1 ;;
    esac
    BOX="$1"
}

# ALLOWLIST: the exact path, then the one owner it may have instead of root.
# An entry is only for a file the service user owns AND runs as itself, so
# root never runs it and its owner can affect nothing beyond its own
# privileges. Never a glob: the pattern is quoted, so `case` compares the
# whole path as a literal string.
#
#   create-partitions.sh: patched-partitions.service runs it with
#   User=patched (api-vps-artefacts/patched-partitions.service, PAT-688).
#   test_pat2310_deploy_ownership_guard.py pins that unit's User= and
#   ExecStart=. If the unit ever runs it as root, delete this entry.
allowlisted_owner() {
    [ "$BOX" = api-01 ] || return 1
    case "$1" in
        "$PREFIX/opt/patched-api/bin/create-partitions.sh") printf '%s\n' "$SERVICE_USER" ;;
        *) return 1 ;;
    esac
}

# Legacy extractor backups. Timestamped copies of the extractor binary
# (patched-extractor.bak-YYYYMMDDTHHMMSSZ, the newest dated 2026-08-15) sit
# beside it owned by the service user, left from before deploy.sh kept its
# backups in root-only /root/patched-deploy-backups. Nothing runs them: every
# unit's ExecStart names the live binary. They are tolerated only in that one
# directory, only under that exact generated name, only as regular files
# owned by the service user, and rules 1 to 3 still apply. That directory
# must itself be root-owned and not group or other writable (rules 3 and 4),
# so the service user cannot add a name to it. Deleting the backups on the
# box retires this exception; remove it then.
is_legacy_extractor_backup() {
    [ "$BOX" = api-01 ] || return 1
    [[ "$1" =~ ^"$PREFIX"/opt/patched-extractor/bin/patched-extractor\.bak-[0-9]{8}T[0-9]{6}Z$ ]]
}

add_finding() {
    FINDINGS="$FINDINGS$1"$'\n'
    FINDING_COUNT=$((FINDING_COUNT + 1))
}

# GNU stat (the box, CI) takes -c; BSD stat (a Mac) takes -f, which GNU
# reads as --file-system, so pick one flavour up front rather than falling
# back per call.
if stat -c %u / >/dev/null 2>&1; then
    STAT_GNU=1
else
    STAT_GNU=0
fi

# path_stat GNU_FORMAT BSD_FORMAT PATH
path_stat() {
    if [ "$STAT_GNU" = 1 ]; then
        stat -c "$1" -- "$3" 2>/dev/null
    else
        stat -f "$2" -- "$3" 2>/dev/null
    fi
}

owner_uid() {
    path_stat '%u' '%u' "$1"
}

owner_name() {
    path_stat '%U' '%Su' "$1"
}

mode_of() {
    path_stat '%A' '%Sp' "$1"
}

# owned_by PATH USER: true when PATH is a regular file owned by USER. An
# unknown USER makes find fail, which reads as false.
owned_by() {
    [ -n "$(find "$1" -maxdepth 0 -type f -user "$2" -print 2>/dev/null)" ]
}

read_failed() {
    case " $READ_FAILED " in
        *" $1 "*) ;;
        *) READ_FAILED="$READ_FAILED $1" ;;
    esac
}

# check_root PATH: apply the four rules to PATH and everything under it.
# find's default -P never follows a symlink, including PATH itself. A find
# that could not read part of the tree has not checked it, so it fails.
check_root() {
    local root="$1" list path uid

    if ! list="$(find "$root" -type l -print)"; then
        read_failed "$root"
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        add_finding "$path is a symlink; root would follow it wherever it points."
    done < <(printf '%s\n' "$list")

    if ! list="$(find "$root" ! -type l -nouser -print)"; then
        read_failed "$root"
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        uid="$(owner_uid "$path")"
        add_finding "$path is owned by uid ${uid:-unknown}, which has no passwd entry; the next account created with that uid would own it."
    done < <(printf '%s\n' "$list")

    if ! list="$(find "$root" ! -type l \( -perm -020 -o -perm -002 \) -print)"; then
        read_failed "$root"
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        add_finding "$path is writable by group or other ($(mode_of "$path"))."
    done < <(printf '%s\n' "$list")

    if [ -n "$TRUSTED_UID" ]; then
        list="$(find "$root" ! -type l ! -nouser ! -uid 0 ! -uid "$TRUSTED_UID" -print)" || read_failed "$root"
    else
        list="$(find "$root" ! -type l ! -nouser ! -uid 0 -print)" || read_failed "$root"
    fi
    local allowed_owner
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        if allowed_owner="$(allowlisted_owner "$path")" && owned_by "$path" "$allowed_owner"; then
            ALLOWED="$ALLOWED $path($allowed_owner)"
            continue
        fi
        if is_legacy_extractor_backup "$path" && owned_by "$path" "$SERVICE_USER"; then
            TOLERATED=$((TOLERATED + 1))
            continue
        fi
        add_finding "$path is owned by $(owner_name "$path") (uid $(owner_uid "$path")), not root; root runs, installs or reads it."
    done < <(printf '%s\n' "$list")

    CHECKED="$CHECKED $root"
}

configure() {
    local name
    if [ "$EUID" -eq 0 ]; then
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        unset BASH_ENV ENV CDPATH
        for name in $OVERRIDE_NAMES; do
            if printenv "$name" >/dev/null 2>&1; then
                err "$name is a test-only override and is refused when running as root. Nothing was checked."
                return 1
            fi
        done
        return 0
    fi
    PREFIX="${PATCHED_OWNERSHIP_GUARD_PREFIX:-}"
    TRUSTED_UID="${PATCHED_OWNERSHIP_GUARD_TRUSTED_UID:-}"
    SERVICE_USER="${PATCHED_OWNERSHIP_GUARD_SERVICE_USER:-patched}"
    case "$PREFIX" in
        '') ;;
        /*)
            if [ ! -d "$PREFIX" ] || [ "$PREFIX" = / ]; then
                err "PATCHED_OWNERSHIP_GUARD_PREFIX must be an existing directory other than /. Nothing was checked."
                return 1
            fi
            ;;
        *)
            err "PATCHED_OWNERSHIP_GUARD_PREFIX must be an absolute path. Nothing was checked."
            return 1
            ;;
    esac
    case "$TRUSTED_UID" in
        *[!0-9]*)
            err "PATCHED_OWNERSHIP_GUARD_TRUSTED_UID must be a numeric uid. Nothing was checked."
            return 1
            ;;
    esac
    return 0
}

cmd_check() {
    local rel root shown line

    if ! configure; then
        return 1
    fi
    # A check with no paths to check would pass on nothing. Refuse it, so a
    # caller that skips the box selection fails rather than reads green.
    if [ -z "$REQUIRED_TREES" ]; then
        err "no box selected, so there is nothing to check. Nothing was checked."
        return 1
    fi

    for rel in $REQUIRED_TREES; do
        root="$PREFIX$rel"
        if [ -L "$root" ] || [ ! -d "$root" ]; then
            err "$root is missing, not a directory, or a symlink. Nothing under it was checked, which is a failure, not a pass."
            read_failed "$root"
            continue
        fi
        check_root "$root"
    done
    for rel in $OPTIONAL_TREES $OPTIONAL_FILES; do
        root="$PREFIX$rel"
        if [ -e "$root" ] || [ -L "$root" ]; then
            check_root "$root"
        else
            ABSENT="$ABSENT $root"
        fi
    done

    say "box: $BOX"
    say "checked:$CHECKED"
    if [ -n "$ABSENT" ]; then
        say "absent, so nothing there for root to run:$ABSENT"
    fi
    if [ -n "$ALLOWED" ]; then
        say "allowlisted (owned and run by the service user, never by root):$ALLOWED"
    fi
    if [ "$TOLERATED" -gt 0 ]; then
        say "tolerated: $TOLERATED legacy patched-extractor.bak-* file(s) owned by $SERVICE_USER in $PREFIX/opt/patched-extractor/bin; nothing runs them."
    fi

    if [ "$FINDING_COUNT" -eq 0 ] && [ -z "$READ_FAILED" ]; then
        say "ok: nothing root runs, installs or reads in the checked paths is a symlink, owned by a non-root or unknown uid, or writable by group or other."
        return 0
    fi

    if [ -n "$READ_FAILED" ]; then
        err "could not read all of:$READ_FAILED. A path this check could not read has not been checked; treating that as a failure."
    fi
    if [ "$FINDING_COUNT" -gt 0 ]; then
        shown=0
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            if [ "$shown" -ge "$MAX_REPORTED" ]; then
                break
            fi
            err "$line"
            shown=$((shown + 1))
        done < <(printf '%s' "$FINDINGS")
        if [ "$FINDING_COUNT" -gt "$shown" ]; then
            err "... and $((FINDING_COUNT - shown)) more."
        fi
        err "$FINDING_COUNT finding(s) in paths root runs, installs or reads on $BOX (PAT-2310). A file this workflow ships is reset by its rsync --chown=root:root on the next deploy; anything else needs its content checked, then chown root:root and chmod go-w by hand. This check changed nothing."
    fi
    return 1
}

main() {
    # Nothing below may read the script's own stdin: when the workflow pipes
    # this file in with `bash -s`, that is where bash is reading it from.
    exec </dev/null
    local box=api-01
    if [ "${1:-}" != check ]; then
        usage
        return 2
    fi
    shift
    case "$#" in
        0) ;;
        2)
            if [ "$1" != --box ]; then
                usage
                return 2
            fi
            box="$2"
            ;;
        *)
            usage
            return 2
            ;;
    esac
    if ! select_box "$box"; then
        usage
        return 2
    fi
    cmd_check
}

main "$@"; exit $?
