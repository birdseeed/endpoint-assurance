#!/usr/bin/env bash
# service-account-hygiene.sh -- PAT-2312. Keeps `patched` on patched-api-01 a
# service account and nothing more: no sudo, no login shell, no SSH key.
#
# Why it exists. `patched` (uid 1000) is the User= of patched-api,
# patched-extractor, patched-partitions, patched-cve-sync and
# patched-tooling-cve-refresh, all with NoNewPrivileges and ProtectHome. It
# was also, from provisioning, a full admin login: a NOPASSWD ALL
# rule in /etc/sudoers.d/patched, membership of `sudo`, /bin/bash as its
# shell and a key in ~/.ssh/authorized_keys. Nobody uses it by hand, but
# agents reached it through a stale SSH config default and a tailnet ACL
# entry, and ad-hoc sessions left binaries, rules files, editor servers and
# shell history in its home. Anything that could log in as the service user
# could replace nothing root runs (PAT-2310 made those root-owned) but could
# still become root through sudo.
#
# Commands.
#   apply  idempotent. Removes /etc/sudoers.d/patched and then requires
#          `visudo -c` to pass; removes `patched` from sudo, admin and wheel;
#          sets its shell to /usr/sbin/nologin unless it is already a
#          nologin or false shell; removes its SSH key files and the
#          leftovers named in LEFTOVERS below. Logs every change it makes.
#   check  read-only. Fails if /etc/sudoers.d/patched exists, if a
#          non-comment line in /etc/sudoers or any file in /etc/sudoers.d
#          names `patched` (or its uid or gid), if it is in sudo, admin or
#          wheel, if its shell is not nologin or false, if an
#          authorized_keys file exists in its home, or if
#          `sudo -l -U patched` lists any command. Prints `ok` otherwise.
#
# What it never does. It does not stop, restart or signal any service, and it
# does not lock or expire the account (no `usermod -L` or `-e`): the password
# is already locked, and systemd User= services must keep starting. Running
# services keep the supplementary groups they started with until their next
# restart; NoNewPrivileges already stops them using sudo. It leaves the home
# directory itself and everything in it that LEFTOVERS does not name.
#
# How it runs. deploy-api-01.yml pipes the RUNNER's copy of this file to the
# box, `apply` and then `check`, after the last ownership re-check and before
# the final readback:
#   ssh root@patched-api-01 \
#     '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --noprofile --norc -s -- check' \
#     < deploy/api-01/service-account-hygiene.sh
# There is no box copy, so nothing on the box can edit it into passing, and
# no artefact-manifest.json entry. `check` is safe to run by hand from a
# checkout the same way.
#
# Exit codes: 0 ok, 1 a finding, a failed change or a state it could not
# read, 2 usage.
#
# Test-only env override, refused when running as root (same stance as
# deploy.sh and deploy-ownership-guard.sh, so a root run cannot be pointed
# somewhere else). A non-root run without it is refused too:
#   PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX  fake root prepended to every
#                                           file path this script reads or
#                                           removes. The account tools
#                                           (getent, id, gpasswd, usermod,
#                                           visudo, sudo) come from PATH,
#                                           which the tests point at shims.
#
# Portability: GNU tools on the box and in CI, BSD ones on a Mac (the tests).
# Every step is an explicit check; nothing relies on `set -e`.
set -uo pipefail

OVERRIDE_NAMES="PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX"

# The account. Fixed, never overridable: the tests fake the account database
# through shims rather than by naming another user.
SERVICE_USER=patched
EXPECTED_HOME=/home/patched
NOLOGIN=/usr/sbin/nologin
# A shell `check` accepts as "cannot log in". An empty passwd shell field
# means /bin/sh, so it is not on this list.
ACCEPTED_SHELLS="/usr/sbin/nologin /sbin/nologin /usr/bin/false /bin/false"
# Groups /etc/sudoers grants on Debian/Ubuntu (sudo, admin) or elsewhere (wheel).
PRIVILEGED_GROUPS="sudo admin wheel"

SUDOERS_FILE=/etc/sudoers
SUDOERS_DIR=/etc/sudoers.d
SUDOERS_DROPIN=/etc/sudoers.d/patched

# LEFTOVERS: what `apply` removes from the home directory, as the kind the
# path must be (f regular file, d directory) and the path under the home
# directory. Exact paths, never a glob. A symlink at any of these paths is
# unlinked, never followed; a path of any other kind than the one listed is
# refused and left alone. .bashrc, .profile, .bash_logout, .cache and the
# home directory itself are deliberately not here.
LEFTOVERS=(
    "f .ssh/authorized_keys"
    "f .ssh/authorized_keys2"
    "f .ssh/known_hosts"
    "f patched-api-new"
    "f patched-rules-new.yml"
    "f rules-dedupe.yml"
    "d .cursor"
    "d .cursor-server"
    "f .bash_history"
    "f .psql_history"
    "f .lesshst"
    "f .sudo_as_admin_successful"
)
# The key files sshd reads by default (AuthorizedKeysFile is unset on api-01).
KEY_FILES=".ssh/authorized_keys .ssh/authorized_keys2"

PREFIX=""
NOTHING_DONE=""
PW_UID=""
PW_GID=""
PW_HOME=""
PW_SHELL=""
HOME_DIR=""
REFUSED_DIRS=""
CHANGES=0
PROBLEMS=0
FINDINGS=0
READ_FAILED=0

say() {
    printf 'service-account-hygiene: %s\n' "$*"
}

# ::error:: is a workflow command GitHub parses from STDOUT only; on stderr
# it would reach the raw log but not the run page.
err() {
    printf '::error::service-account-hygiene: %s\n' "$*"
}

usage() {
    echo "usage: service-account-hygiene.sh apply|check" >&2
}

changed() {
    say "changed: $*"
    CHANGES=$((CHANGES + 1))
}

problem() {
    err "$*"
    PROBLEMS=$((PROBLEMS + 1))
}

finding() {
    err "$*"
    FINDINGS=$((FINDINGS + 1))
}

unreadable() {
    err "$*"
    READ_FAILED=$((READ_FAILED + 1))
}

# rm's flag for "do not cross a mount point": GNU spells it long, BSD -x.
if rm --version >/dev/null 2>&1; then
    RM_ONE_FS=--one-file-system
else
    RM_ONE_FS=-x
fi

configure() {
    local name
    if [ "$EUID" -eq 0 ]; then
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        unset BASH_ENV ENV CDPATH
        for name in $OVERRIDE_NAMES; do
            if printenv "$name" >/dev/null 2>&1; then
                err "$name is a test-only override and is refused when running as root. $NOTHING_DONE"
                return 1
            fi
        done
        PREFIX=""
        return 0
    fi
    PREFIX="${PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX:-}"
    if [ -z "$PREFIX" ]; then
        err "must run as root on patched-api-01. A non-root run is only for the tests, which set PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX. $NOTHING_DONE"
        return 1
    fi
    case "$PREFIX" in
        /*) ;;
        *)
            err "PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX must be an absolute path. $NOTHING_DONE"
            return 1
            ;;
    esac
    # Resolve it once, so the symlink checks below compare against real paths.
    if ! PREFIX="$(cd -P -- "$PREFIX" 2>/dev/null && pwd -P)" || [ "$PREFIX" = / ]; then
        err "PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX must be an existing directory other than /. $NOTHING_DONE"
        return 1
    fi
    return 0
}

# load_account: read the service user's passwd entry. Fails, having said why,
# when there is none or it is malformed.
load_account() {
    local entry name uid gid home shell extra
    if ! entry="$(getent passwd "$SERVICE_USER")" || [ -z "$entry" ]; then
        err "$SERVICE_USER has no passwd entry, so the services that run as it cannot start either. $NOTHING_DONE"
        return 1
    fi
    IFS=: read -r name _ uid gid _ home shell extra <<<"$entry"
    if [ "$name" != "$SERVICE_USER" ] || [ -n "${extra:-}" ] \
        || [[ ! "$uid" =~ ^[0-9]+$ ]] || [[ ! "$gid" =~ ^[0-9]+$ ]]; then
        err "the passwd entry for $SERVICE_USER is not in the shape expected (got: $entry). $NOTHING_DONE"
        return 1
    fi
    PW_UID="$uid"
    PW_GID="$gid"
    PW_HOME="$home"
    PW_SHELL="$shell"
    HOME_DIR="$PREFIX$EXPECTED_HOME"
    return 0
}

accepted_shell() {
    local shell
    for shell in $ACCEPTED_SHELLS; do
        [ "$1" = "$shell" ] && return 0
    done
    return 1
}

in_words() {
    local word
    for word in $2; do
        [ "$word" = "$1" ] && return 0
    done
    return 1
}

kind_of() {
    if [ -L "$1" ]; then
        echo "a symlink"
    elif [ -d "$1" ]; then
        echo "a directory"
    elif [ -f "$1" ]; then
        echo "a regular file"
    elif [ -p "$1" ]; then
        echo "a named pipe"
    elif [ -S "$1" ]; then
        echo "a socket"
    elif [ -b "$1" ] || [ -c "$1" ]; then
        echo "a device node"
    else
        echo "something other than a file or directory"
    fi
}

kind_name() {
    case "$1" in
        f) echo "a regular file" ;;
        d) echo "a directory" ;;
    esac
}

# -- apply -----------------------------------------------------------------

apply_sudoers() {
    local dropin="$PREFIX$SUDOERS_DROPIN" out
    if [ -e "$dropin" ] || [ -L "$dropin" ]; then
        if rm -f -- "$dropin" 2>/dev/null && [ ! -e "$dropin" ] && [ ! -L "$dropin" ]; then
            changed "removed $dropin, the NOPASSWD sudo rule for $SERVICE_USER."
        else
            problem "could not remove $dropin ($(kind_of "$dropin")). $SERVICE_USER can still use sudo."
        fi
    fi
    if out="$(visudo -c 2>&1)"; then
        say "visudo -c: the sudoers configuration parses."
    else
        problem "visudo -c failed: the sudoers configuration does not parse, so what sudo allows is not something to rely on. Fix it by hand. Its output: $(printf '%s' "$out" | tr '\n' ' ')"
    fi
}

apply_groups() {
    local groups group out
    if ! groups="$(id -nG "$SERVICE_USER" 2>/dev/null)"; then
        problem "could not read the groups of $SERVICE_USER, so group membership was not changed."
        return
    fi
    for group in $PRIVILEGED_GROUPS; do
        in_words "$group" "$groups" || continue
        if out="$(gpasswd -d "$SERVICE_USER" "$group" 2>&1)"; then
            changed "removed $SERVICE_USER from group $group."
        else
            problem "gpasswd -d $SERVICE_USER $group failed: $(printf '%s' "$out" | tr '\n' ' ')"
        fi
    done
    if ! groups="$(id -nG "$SERVICE_USER" 2>/dev/null)"; then
        problem "could not re-read the groups of $SERVICE_USER after changing them."
        return
    fi
    for group in $PRIVILEGED_GROUPS; do
        if in_words "$group" "$groups"; then
            problem "$SERVICE_USER is still in group $group. Its only membership may be as its primary group, which gpasswd cannot remove; fix it by hand."
        fi
    done
}

apply_shell() {
    local entry shell
    if accepted_shell "$PW_SHELL"; then
        return
    fi
    if ! usermod -s "$NOLOGIN" "$SERVICE_USER" >/dev/null 2>&1; then
        problem "usermod -s $NOLOGIN $SERVICE_USER failed; its shell is still '${PW_SHELL}'."
        return
    fi
    entry="$(getent passwd "$SERVICE_USER" 2>/dev/null)" || entry=""
    shell="${entry##*:}"
    if [ "$shell" = "$NOLOGIN" ]; then
        changed "set the shell of $SERVICE_USER from '${PW_SHELL}' to $NOLOGIN."
    else
        problem "usermod reported success but the shell of $SERVICE_USER reads back as '${shell}', not $NOLOGIN."
    fi
}

# enter_real_dir DIR: cd into DIR only if it is a directory, not a symlink,
# and the kernel agrees it is where it was asked to be, so a later relative
# rm cannot land anywhere else. Returns 0 entered, 1 refused (reported),
# 2 absent.
enter_real_dir() {
    local dir="$1" real
    if [ -L "$dir" ]; then
        problem "$dir is a symlink to $(readlink -- "$dir" 2>/dev/null || echo '?'), not a directory. Nothing under it was removed: a root rm through it would land wherever it points."
        return 1
    fi
    if [ ! -e "$dir" ]; then
        return 2
    fi
    if [ ! -d "$dir" ]; then
        problem "$dir is $(kind_of "$dir"), not a directory. Nothing under it was removed."
        return 1
    fi
    if ! cd -P -- "$dir" 2>/dev/null; then
        problem "could not enter $dir. Nothing under it was removed."
        return 1
    fi
    real="$(pwd -P)"
    if [ "$real" != "$dir" ]; then
        problem "$dir resolved to $real on entry, so part of that path is a symlink. Nothing under it was removed."
        cd / || true
        return 1
    fi
    return 0
}

# remove_leftover KIND REL: remove one LEFTOVERS entry. Absent is fine.
remove_leftover() {
    local kind="$1" rel="$2" dir name full target rc
    case "$rel" in
        */*) dir="$HOME_DIR/${rel%/*}"; name="${rel##*/}" ;;
        *) dir="$HOME_DIR"; name="$rel" ;;
    esac
    full="$dir/$name"
    # A directory already refused was reported once; say nothing more.
    case " $REFUSED_DIRS " in
        *" $dir "*) return 1 ;;
    esac
    enter_real_dir "$dir"
    rc=$?
    case "$rc" in
        0) ;;
        2) return 0 ;;
        *)
            REFUSED_DIRS="$REFUSED_DIRS $dir"
            return 1
            ;;
    esac
    if [ -L "$name" ]; then
        target="$(readlink -- "$name" 2>/dev/null || echo '?')"
        if rm -f -- "$name" 2>/dev/null && [ ! -L "$name" ]; then
            changed "unlinked $full, a symlink to $target. The link itself was removed; its target was not touched."
        else
            problem "could not unlink the symlink $full."
        fi
    elif [ ! -e "$name" ]; then
        :
    elif [ "$kind" = f ] && [ -f "$name" ]; then
        if rm -f -- "$name" 2>/dev/null && [ ! -e "$name" ] && [ ! -L "$name" ]; then
            changed "removed $full."
        else
            problem "could not remove $full."
        fi
    elif [ "$kind" = d ] && [ -d "$name" ]; then
        if rm -rf "$RM_ONE_FS" -- "$name" 2>/dev/null && [ ! -e "$name" ] && [ ! -L "$name" ]; then
            changed "removed $full and everything in it."
        else
            problem "could not remove all of $full; part of it is still there."
        fi
    else
        problem "$full is $(kind_of "$name"), not $(kind_name "$kind") as expected. Left alone; look at it by hand."
    fi
    cd / || true
    return 0
}

apply_home() {
    local entry kind rel rc
    if [ "$PW_HOME" != "$EXPECTED_HOME" ]; then
        problem "the home directory of $SERVICE_USER is '$PW_HOME', not $EXPECTED_HOME. Nothing in any home directory was removed."
        return
    fi
    # The home directory itself must be real before anything under it is
    # touched; enter_real_dir says so, and every entry re-enters its own
    # directory the same way.
    enter_real_dir "$HOME_DIR"
    rc=$?
    cd / || true
    case "$rc" in
        0) ;;
        2)
            say "$HOME_DIR does not exist; no key files or leftovers to remove."
            return
            ;;
        *) return ;;
    esac
    for entry in "${LEFTOVERS[@]}"; do
        kind="${entry%% *}"
        rel="${entry#* }"
        remove_leftover "$kind" "$rel"
    done
}

cmd_apply() {
    NOTHING_DONE="Nothing was changed."
    if ! configure; then
        return 1
    fi
    if ! load_account; then
        return 1
    fi
    apply_sudoers
    apply_groups
    apply_shell
    apply_home
    cd / || true

    if [ "$PROBLEMS" -gt 0 ]; then
        err "$PROBLEMS problem(s) above; $CHANGES change(s) did succeed and are logged above. $SERVICE_USER on patched-api-01 may still be able to log in or use sudo (PAT-2312)."
        return 1
    fi
    if [ "$CHANGES" -eq 0 ]; then
        say "apply: nothing to change."
    else
        say "apply: $CHANGES change(s) made."
    fi
    return 0
}

# -- check -----------------------------------------------------------------

# sudoers_mentions FILE: a finding for every non-comment line of FILE that
# names the service user, its uid (#uid) or its group id (%#gid). `sudo -l`
# only reports rules for this host, so any rule naming the account counts.
sudoers_mentions() {
    local file="$1" line code padded n=0
    if [ ! -r "$file" ]; then
        unreadable "could not read $file, so it was not checked for rules naming $SERVICE_USER."
        return
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        code="$line"
        # sudoers(5): '#' starts a comment unless a digit follows it, when it
        # is a uid (#1000) or gid (%#1000). #include lines grant nobody.
        if [[ "$code" =~ ^(([^#]|#[0-9])*)#([^0-9].*)?$ ]]; then
            code="${BASH_REMATCH[1]}"
        fi
        padded=" $code "
        if [[ "$padded" =~ [^A-Za-z0-9_.-]"$SERVICE_USER"[^A-Za-z0-9_.-] ]] \
            || [[ "$padded" =~ [^A-Za-z0-9_%:]#"$PW_UID"[^0-9] ]] \
            || [[ "$padded" =~ %:?#"$PW_GID"[^0-9] ]]; then
            finding "$file:$n names $SERVICE_USER: $(printf '%.200s' "$line")"
        fi
    done <"$file"
}

check_sudoers() {
    local dropin="$PREFIX$SUDOERS_DROPIN" dir="$PREFIX$SUDOERS_DIR" list file
    if [ -e "$dropin" ] || [ -L "$dropin" ]; then
        finding "$dropin exists. It is the sudo rule provisioning gave $SERVICE_USER; apply removes it."
    fi
    if [ -e "$PREFIX$SUDOERS_FILE" ] || [ -L "$PREFIX$SUDOERS_FILE" ]; then
        sudoers_mentions "$PREFIX$SUDOERS_FILE"
    else
        unreadable "$PREFIX$SUDOERS_FILE is missing, so the sudoers configuration could not be checked."
    fi
    if [ -d "$dir" ]; then
        if ! list="$(find "$dir" -mindepth 1 -maxdepth 1 ! -type d -print 2>/dev/null)"; then
            unreadable "could not list $dir, so the files in it were not checked."
            return
        fi
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            sudoers_mentions "$file"
        done < <(printf '%s\n' "$list" | LC_ALL=C sort)
    fi
}

check_groups() {
    local groups group
    if ! groups="$(id -nG "$SERVICE_USER" 2>/dev/null)"; then
        unreadable "could not read the groups of $SERVICE_USER."
        return
    fi
    for group in $PRIVILEGED_GROUPS; do
        if in_words "$group" "$groups"; then
            finding "$SERVICE_USER is in group $group, which sudoers grants."
        fi
    done
}

check_shell() {
    if ! accepted_shell "$PW_SHELL"; then
        finding "the shell of $SERVICE_USER is '${PW_SHELL:-(empty, so /bin/sh)}', a login shell. It should be $NOLOGIN."
    fi
}

check_keys() {
    local rel path
    if [ "$PW_HOME" != "$EXPECTED_HOME" ]; then
        finding "the home directory of $SERVICE_USER is '$PW_HOME', not $EXPECTED_HOME, so its SSH key files were not checked."
        return
    fi
    for rel in $KEY_FILES; do
        path="$HOME_DIR/$rel"
        if [ -e "$path" ] || [ -L "$path" ]; then
            finding "$path exists. sshd would accept a key in it as $SERVICE_USER, and a nologin shell still allows port forwarding."
        fi
    done
}

check_sudo_rights() {
    local out rc=0 line listing=""
    out="$(sudo -n -l -U "$SERVICE_USER" 2>&1)" || rc=$?
    if [[ "$out" == *"User $SERVICE_USER may run the following commands"* ]]; then
        while IFS= read -r line; do
            case "$line" in
                "    "*) listing="$listing${listing:+; }${line#"${line%%[![:space:]]*}"}" ;;
            esac
        done < <(printf '%s\n' "${out#*may run the following commands}")
        finding "sudo -l -U $SERVICE_USER lists commands it may run: ${listing:-(none parsed; see sudo -l -U $SERVICE_USER)}"
        return
    fi
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -Eq "^User $SERVICE_USER is not allowed to run sudo on .+\.$"; then
        return
    fi
    unreadable "could not tell from sudo -l -U $SERVICE_USER whether it has sudo rights (exit $rc): $(printf '%.200s' "$(printf '%s' "$out" | tr '\n' ' ')")"
}

cmd_check() {
    NOTHING_DONE="Nothing was checked."
    if ! configure; then
        return 1
    fi
    if ! load_account; then
        return 1
    fi
    check_sudoers
    check_groups
    check_shell
    check_keys
    check_sudo_rights

    if [ "$FINDINGS" -eq 0 ] && [ "$READ_FAILED" -eq 0 ]; then
        say "ok: $SERVICE_USER has no sudo rule, is in none of $PRIVILEGED_GROUPS, has a non-login shell ($PW_SHELL) and no authorized_keys, and sudo -l lists nothing for it."
        return 0
    fi
    if [ "$READ_FAILED" -gt 0 ]; then
        err "$READ_FAILED part(s) of the state could not be read. Something this check could not read has not been checked; treating that as a failure."
    fi
    if [ "$FINDINGS" -gt 0 ]; then
        err "$FINDINGS finding(s): $SERVICE_USER on patched-api-01 can still log in or use sudo (PAT-2312). It is a service account; 'apply' removes these. This check changed nothing."
    fi
    return 1
}

main() {
    # Nothing below may read the script's own stdin: when the workflow pipes
    # this file in with `bash -s`, that is where bash is reading it from.
    exec </dev/null
    if [ "$#" -ne 1 ]; then
        usage
        return 2
    fi
    case "$1" in
        apply) cmd_apply ;;
        check) cmd_check ;;
        *)
            usage
            return 2
            ;;
    esac
}

main "$@"; exit $?
