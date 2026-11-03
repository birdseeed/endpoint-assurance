#!/usr/bin/env bash
# PAT-2307: keep everything root runs or installs on patched-prod-01 out of
# the dashboard service user's reach.
#
# The problem this closes. The dashboard runs as www-data. Root runs
# scripts/deploy.sh out of /opt/patched-dashboard on every deploy (the
# post-receive hook execs it), runs the venv's pip and python and the smoke
# suite from it, installs systemd units, polkit rules and the nginx site
# config from its deploy/ directory, deletes whatever deploy/removed-
# artifacts.txt lists, and runs deploy/hetzner-firewall-apply.sh and
# deploy/patched-maintenance-facts.sh from timers. Until this ticket the
# whole tree was owned by www-data, so anything that could act as www-data
# (the app, an nginx worker) could rewrite any of those and root would run
# or install it next time. The bare mirror the hook lives in
# (/opt/git/dashboard.git) was owned by uid 999, which no longer has a
# passwd entry: the next system user created on the box would inherit the
# directory root's post-receive hook runs from.
#
# The fix: both trees are owned by root with no group or other write bit,
# and everything the app writes at runtime lives in its own state directory
# (/var/lib/patched-dashboard, owned by www-data; the systemd unit's
# StateDirectory= creates it). This script is the one implementation of the
# check and of the lock, used in three places:
#
#   1. .github/workflows/deploy.yml pipes the RUNNER's copy of this file to
#      the box over SSH (`bash -s -- <command> < deploy/code-tree-guard.sh`),
#      before the push that fires the hook and again before the nginx config
#      is installed. That copy comes from GitHub, not from the tree it is
#      checking, so a box-side edit cannot switch it off.
#   2. scripts/deploy.sh checks the tree before it runs anything from it
#      (this is what covers a manual `git push` to the mirror, which never
#      goes through the workflow), and locks and re-checks it after every
#      `git reset --hard`, forward and rollback.
#   3. By hand, as root, when an operator wants to know.
#
# Commands:
#   check               Fail (exit 1) if anything under the code tree or the
#                       bare mirror, any directory above either of them, or
#                       the target of any symlink inside them, is owned by a
#                       non-root user or writable by group or other; or if
#                       either repository carries git config keys or hook
#                       files outside a small allowlist (root runs git in
#                       both). Prints one ::error:: line per offending path
#                       (capped).
#   lock                chown -R root:root and chmod -R go-w both trees,
#                       without following symlinks. Makes DEPLOYED_SHA 0644
#                       so the app can still read the provenance record.
#   prepare-state       Create the state directory if it is missing and copy
#                       the app's runtime data into it (nvd.db, top-level
#                       reports/*.docx). Copies run as the service user,
#                       verify byte for byte, never overwrite, and never
#                       delete or move the originals.
#   adopt               prepare-state, lock, check. The one-time move to a
#                       root-owned tree, and the recovery after anything
#                       re-grants the service user (an scp hotfix that
#                       chowned to www-data, a deploy of a pre-PAT-2307
#                       commit whose deploy.sh still does). Only ever run
#                       because someone dispatched the deploy with
#                       adopt_code_tree=true; a normal deploy only checks.
#   adopt-finish SHA    lock and check, but only if DEPLOYED_SHA records SHA
#                       as confirmed running. Run after the push on an
#                       adopting deploy: the deploy.sh that ran was the
#                       previous commit's, which chowns the tree back to
#                       www-data, and a deploy that rolled back must leave
#                       the old code the tree it expects.
#
# Exit codes: 0 ok, 1 a check or step failed, 2 usage.
#
# Env overrides (tests only; the defaults are the live box):
#   CODE_TREE_DIR, CODE_TREE_MIRROR_DIR, CODE_TREE_OWNER, CODE_TREE_GROUP,
#   CODE_TREE_STATE_DIR, CODE_TREE_SERVICE_USER, CODE_TREE_SERVICE_GROUP,
#   CODE_TREE_RUN_AS_SELF, CODE_TREE_MAX_REPORTED
#
# Portability: runs under GNU coreutils/findutils on the box and BSD ones on
# a Mac (the tests). Only POSIX find predicates, `chown -hR`, `chmod -R` and
# `readlink -f` are used.
#
# Every step is an explicit `if ! cmd`. Nothing relies on `set -e`.
set -uo pipefail

TREE="${CODE_TREE_DIR:-/opt/patched-dashboard}"
MIRROR="${CODE_TREE_MIRROR_DIR:-/opt/git/dashboard.git}"
OWNER="${CODE_TREE_OWNER:-root}"
GROUP="${CODE_TREE_GROUP:-root}"
STATE_DIR="${CODE_TREE_STATE_DIR:-/var/lib/patched-dashboard}"
SERVICE_USER="${CODE_TREE_SERVICE_USER:-www-data}"
SERVICE_GROUP="${CODE_TREE_SERVICE_GROUP:-www-data}"
RUN_AS_SELF="${CODE_TREE_RUN_AS_SELF:-0}"
MAX_REPORTED="${CODE_TREE_MAX_REPORTED:-25}"

err() {
    echo "::error::code-tree-guard: $*" >&2
}

info() {
    echo "code-tree-guard: $*"
}

usage() {
    echo "usage: code-tree-guard.sh check | lock | prepare-state | adopt | adopt-finish <40-hex-sha>" >&2
}

# physical_dir PATH: print PATH with every symlink resolved. Fails unless it
# is an existing directory.
physical_dir() {
    if [ ! -d "$1" ]; then
        return 1
    fi
    (cd -P -- "$1" 2>/dev/null && pwd -P)
}

# owner_uid: the numeric uid this tree is meant to belong to. Root on the
# box; the tests override the owner to themselves.
owner_uid() {
    id -u "$OWNER" 2>/dev/null
}

# tree_offenders DIR: print every non-symlink path under DIR (DIR included)
# owned by anyone other than root or the configured owner, or carrying a
# group or other write bit. Directory write counts: it lets the holder
# rename a root-owned file out of the way and put their own in its place.
# Returns 2 if find could not read the whole tree, which is a failure too:
# a check that skipped part of the tree has not checked it.
tree_offenders() {
    local dir="$1" uid="$2"
    find "$dir" ! -type l \( \( ! -uid 0 ! -uid "$uid" \) -o -perm -020 -o -perm -002 \) -print \
        || return 2
}

# chain_offenders PATH: print PATH and every directory above it that is
# owned by anyone other than root or the configured owner, or is group or
# other writable. A sticky world-writable directory such as /tmp is allowed
# ABOVE the leaf: the sticky bit stops other users renaming or deleting an
# entry they do not own, and the next component down is itself checked.
chain_offenders() {
    local path="$1" uid="$2" leaf=1
    while :; do
        if [ "$leaf" = 1 ]; then
            find "$path" -maxdepth 0 \( \( ! -uid 0 ! -uid "$uid" \) -o -perm -020 -o -perm -002 \) -print \
                || return 2
            leaf=0
        else
            find "$path" -maxdepth 0 \( \( ! -uid 0 ! -uid "$uid" \) -o \( \( -perm -020 -o -perm -002 \) ! -perm -1000 \) \) -print \
                || return 2
        fi
        if [ "$path" = / ]; then
            return 0
        fi
        path="$(dirname -- "$path")"
    done
}

# symlink_offenders DIR PHYS_TREE PHYS_MIRROR: for every symlink under DIR,
# resolve it. A target inside either tree is covered by tree_offenders; any
# other target must exist and pass chain_offenders, or root would follow
# the link into a file the service user controls (venv/bin/python3 ->
# /usr/bin/python3 is the one live example, and passes).
symlink_offenders() {
    local dir="$1" tree="$2" mirror="$3" uid="$4" link target list bad line
    list="$(find "$dir" -type l -print)" || return 2
    [ -n "$list" ] || return 0
    while IFS= read -r link; do
        [ -n "$link" ] || continue
        # A dangling link fails closed: whatever later appears at its target
        # is something root would follow.
        target="$(readlink -f -- "$link" 2>/dev/null)" || target=""
        if [ -z "$target" ] || [ ! -e "$target" ]; then
            echo "$link (dangling symlink)"
            continue
        fi
        case "$target" in
            "$tree"|"$tree"/*|"$mirror"|"$mirror"/*) continue ;;
        esac
        bad="$(chain_offenders "$target" "$uid")" || return 2
        [ -n "$bad" ] || continue
        while IFS= read -r line; do
            echo "$link -> $line"
        done <<< "$bad"
    done <<< "$list"
    return 0
}

# Every name git runs from a hooks directory (githooks(5)). reset --hard
# alone runs reference-transaction, so a hook planted in the checkout would
# run as root on the next deploy.
GIT_HOOK_NAMES="applypatch-msg pre-applypatch post-applypatch pre-commit
pre-merge-commit prepare-commit-msg commit-msg post-commit pre-rebase
post-checkout post-merge pre-push pre-receive update proc-receive
post-receive post-update reference-transaction push-to-checkout pre-auto-gc
post-rewrite sendemail-validate fsmonitor-watchman p4-changelist
p4-prepare-changelist p4-post-changelist p4-pre-submit post-index-change"

# git_offenders GITDIR ALLOWED_HOOKS: what in a repository would make root's
# git run something. Ownership alone cannot answer that on the transition
# deploy: until then the service user could write .git/config and
# .git/hooks, and root's git trusts both. So: any config key outside a small
# allowlist of the keys a clone or `init --bare` writes (core.fsmonitor,
# core.hooksPath, include.path, filter.*, and so on all fail), and any file
# with a hook's name other than the allowed ones. `git config -f` only reads
# the file; --no-includes stops it following an include.
git_offenders() {
    local gitdir="$1" allowed_hooks="$2" keys key name
    if [ -e "$gitdir/config" ]; then
        if ! keys="$(cd / && git config --no-includes -f "$gitdir/config" --name-only --list 2>/dev/null)"; then
            echo "$gitdir/config: git could not parse it"
            keys=""
        fi
        while IFS= read -r key; do
            [ -n "$key" ] || continue
            case "$key" in
                core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates) ;;
                core.ignorecase|core.precomposeunicode|core.symlinks) ;;
                remote.*.url|remote.*.fetch|branch.*.remote|branch.*.merge) ;;
                *) echo "$gitdir/config: key '$key' is not on the allowlist" ;;
            esac
        done <<< "$keys"
    fi
    for name in $GIT_HOOK_NAMES; do
        if [ -e "$gitdir/hooks/$name" ] || [ -L "$gitdir/hooks/$name" ]; then
            case " $allowed_hooks " in
                *" $name "*) ;;
                *) echo "$gitdir/hooks/$name: git runs this as a hook" ;;
            esac
        fi
    done
}

cmd_check() {
    local uid tree mirror offenders git_bad count shown
    uid="$(owner_uid)"
    if [ -z "$uid" ]; then
        err "unknown owner '$OWNER'; nothing was checked."
        return 1
    fi
    if ! tree="$(physical_dir "$TREE")"; then
        err "$TREE is missing or not a directory; nothing was checked."
        return 1
    fi
    if ! mirror="$(physical_dir "$MIRROR")"; then
        err "$MIRROR is missing or not a directory; nothing was checked."
        return 1
    fi

    if ! offenders="$(
        tree_offenders "$tree" "$uid" || exit 2
        tree_offenders "$mirror" "$uid" || exit 2
        # From each tree's own root, so the directories above it get the
        # ancestor rule (a sticky directory is allowed there) and the root
        # itself the strict one (it is also in tree_offenders' output).
        chain_offenders "$tree" "$uid" || exit 2
        chain_offenders "$mirror" "$uid" || exit 2
        symlink_offenders "$tree" "$tree" "$mirror" "$uid" || exit 2
        symlink_offenders "$mirror" "$tree" "$mirror" "$uid" || exit 2
    )"; then
        err "could not read all of $TREE and $MIRROR to check them; treating that as a failure."
        return 1
    fi
    offenders="$(printf '%s\n' "$offenders" | sed '/^$/d' | sort -u)"
    git_bad="$(
        if [ -d "$tree/.git" ]; then
            git_offenders "$tree/.git" ""
        fi
        # The mirror's own post-receive is the deploy hook; nothing else.
        git_offenders "$mirror" "post-receive"
    )"
    git_bad="$(printf '%s\n' "$git_bad" | sed '/^$/d')"

    if [ -z "$offenders" ] && [ -z "$git_bad" ]; then
        info "ok: nothing root runs or installs from $TREE or $MIRROR is owned or writable by a non-root user, and neither repository carries git config or hooks outside the allowlist"
        return 0
    fi

    if [ -n "$git_bad" ]; then
        while IFS= read -r line; do
            err "root's git would act on this: $line"
        done <<< "$git_bad"
        err "the repositories root runs git in carry config or hooks outside the allowlist. Nothing was run. Review and remove them by hand (PAT-2307)."
    fi

    if [ -n "$offenders" ]; then
        count="$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')"
        shown=0
        while IFS= read -r line; do
            if [ "$shown" -ge "$MAX_REPORTED" ]; then
                break
            fi
            err "owned or writable by a non-root user: $line"
            shown=$((shown + 1))
        done <<< "$offenders"
        if [ "$count" -gt "$shown" ]; then
            err "... and $((count - shown)) more."
        fi
        err "$count path(s) that root runs or installs from are owned or writable by a non-root user. Nothing was run from them. If this box has not yet moved to a root-owned tree, or something re-granted the service user, dispatch deploy.yml with adopt_code_tree=true once (PAT-2307)."
    fi
    return 1
}

cmd_lock() {
    local dir
    for dir in "$TREE" "$MIRROR"; do
        if [ -L "$dir" ] || [ ! -d "$dir" ]; then
            err "$dir is missing, not a directory, or a symlink; not locked."
            return 1
        fi
        # -h and the default -P for -R: never follow a symlink, so a link
        # planted in the tree cannot redirect root's chown onto another file.
        if ! chown -hR "$OWNER:$GROUP" "$dir"; then
            err "chown -hR $OWNER:$GROUP $dir failed."
            return 1
        fi
        # chmod -R does not follow symlinks met during the walk.
        if ! chmod -R go-w "$dir"; then
            err "chmod -R go-w $dir failed."
            return 1
        fi
        info "locked $dir: owned by $OWNER:$GROUP, no group or other write"
    done
    # The app reads the provenance record (deploy_drift, main.py). deploy.sh
    # writes it 0644 from PAT-2307 on; earlier versions wrote it 0600 and
    # chowned it to the service user, so make it readable here or the check
    # reads "could not be read" until the next forward deploy.
    if [ -f "$TREE/DEPLOYED_SHA" ] && [ ! -L "$TREE/DEPLOYED_SHA" ]; then
        if ! chmod 0644 "$TREE/DEPLOYED_SHA"; then
            err "chmod 0644 $TREE/DEPLOYED_SHA failed."
            return 1
        fi
    fi
    return 0
}

# The migration below runs as the service user, so it is defined as plain
# functions that the service user's own bash receives verbatim (declare -f).
# Copying as the service user means a symlink or hard link planted in the
# legacy locations can only ever expose what that user could already read:
# a root-run copy out of a directory the service user controls could be
# turned into a way to read or write files it cannot.

# migrate_one SRC DST: copy SRC to DST if DST does not exist yet, verify it
# byte for byte, and leave SRC exactly where it is.
migrate_one() {
    local src="$1" dst="$2" tmp
    if [ -L "$src" ]; then
        echo "code-tree-guard: $src is a symlink; not copied"
        return 0
    fi
    if [ ! -e "$src" ]; then
        return 0
    fi
    if [ ! -f "$src" ]; then
        echo "::error::code-tree-guard: $src is not a regular file; not copied" >&2
        return 1
    fi
    if [ -e "$dst" ] || [ -L "$dst" ]; then
        if cmp -s "$src" "$dst"; then
            echo "code-tree-guard: $dst already matches $src"
        else
            echo "code-tree-guard: $dst already exists and is left as it is; $src was not copied over it"
        fi
        return 0
    fi
    if ! tmp="$(mktemp "$dst.migrate.XXXXXX")"; then
        echo "::error::code-tree-guard: could not create a temporary file next to $dst" >&2
        return 1
    fi
    # -p keeps the modification time, which prune-reports.sh's -mtime
    # retention relies on.
    if ! cp -p "$src" "$tmp"; then
        rm -f "$tmp"
        echo "::error::code-tree-guard: could not copy $src" >&2
        return 1
    fi
    if ! cmp -s "$src" "$tmp"; then
        rm -f "$tmp"
        echo "::error::code-tree-guard: the copy of $src did not match it; nothing was moved into place" >&2
        return 1
    fi
    # ln is an atomic no-clobber: it fails if DST appeared in the meantime.
    if ! ln "$tmp" "$dst"; then
        rm -f "$tmp"
        if [ -e "$dst" ]; then
            echo "code-tree-guard: $dst appeared while copying; left as it is"
            return 0
        fi
        echo "::error::code-tree-guard: could not move the verified copy of $src into $dst" >&2
        return 1
    fi
    rm -f "$tmp"
    if ! cmp -s "$src" "$dst"; then
        echo "::error::code-tree-guard: $dst does not match $src after the move" >&2
        return 1
    fi
    echo "code-tree-guard: copied $src to $dst, verified byte for byte; the original is left in place"
    return 0
}

# migrate_all TREE STATE_DIR: the runtime data the app used to keep in the
# code tree. dashboard.db is not here: it moved to the state directory in
# PAT-994 (DASHBOARD_DB_PATH), and this ticket does not touch it.
migrate_all() {
    local tree="$1" state="$2" rc=0 f
    if [ ! -d "$state/reports" ] && ! mkdir -m 0750 "$state/reports"; then
        echo "::error::code-tree-guard: could not create $state/reports" >&2
        return 1
    fi
    # nvd.db is the local NVD match cache (scanner.py). It is rebuilt from
    # the NVD feed if missing, so it is copied only to spare the first scan
    # that download. The app opens it in SQLite's default rollback-journal
    # mode and only writes it when it does not exist, so a byte-identical
    # copy with no hot journal beside it is a consistent copy.
    if [ -e "$tree/nvd.db-journal" ] || [ -L "$tree/nvd.db-journal" ]; then
        echo "code-tree-guard: $tree/nvd.db has a rollback journal beside it; not copied (the app rebuilds the cache when it is missing)"
    else
        migrate_one "$tree/nvd.db" "$state/nvd.db" || rc=1
    fi
    # Top-level .docx only: the same files prune-reports.sh ages out.
    for f in "$tree"/reports/*.docx; do
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then
            continue
        fi
        migrate_one "$f" "$state/reports/$(basename -- "$f")" || rc=1
    done
    return "$rc"
}

as_service_user() {
    # From /, so the service user's shell never starts in a directory it
    # cannot enter (root's working directory over SSH is /root).
    if [ "$RUN_AS_SELF" = 1 ]; then
        (cd / && "$@" </dev/null)
    else
        (cd / && runuser -u "$SERVICE_USER" -- "$@" </dev/null)
    fi
}

cmd_prepare_state() {
    local defs
    if [ -L "$STATE_DIR" ]; then
        err "$STATE_DIR is a symlink; refusing to use it as the state directory."
        return 1
    fi
    if [ -e "$STATE_DIR" ] && [ ! -d "$STATE_DIR" ]; then
        err "$STATE_DIR exists and is not a directory."
        return 1
    fi
    if [ ! -d "$STATE_DIR" ]; then
        # Normally already there: PAT-994 created it for dashboard.db, and the
        # unit's StateDirectory= creates it on every start from PAT-2307 on.
        if ! install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$STATE_DIR"; then
            err "could not create $STATE_DIR."
            return 1
        fi
        info "created $STATE_DIR ($SERVICE_USER:$SERVICE_GROUP, 0750)"
    fi
    defs="$(declare -f migrate_one migrate_all)"
    if ! as_service_user bash -c "$defs"'
migrate_all "$1" "$2"' code-tree-guard-migrate "$TREE" "$STATE_DIR"; then
        err "copying runtime data into $STATE_DIR did not complete. The originals in $TREE are untouched."
        return 1
    fi
    info "state directory $STATE_DIR is ready"
    return 0
}

cmd_adopt() {
    info "adopting: moving runtime data out, then taking root ownership of $TREE and $MIRROR"
    if ! cmd_prepare_state; then
        return 1
    fi
    if ! cmd_lock; then
        return 1
    fi
    cmd_check
}

cmd_adopt_finish() {
    local expected="$1" record="$TREE/DEPLOYED_SHA" recorded=""
    case "$expected" in
        *[!0-9a-f]*|'') usage; return 2 ;;
    esac
    if [ "${#expected}" -ne 40 ]; then
        usage
        return 2
    fi
    # DEPLOYED_SHA is deploy.sh's record of a commit it has confirmed
    # running (smoke passed, or a completed rollback). Reading it needs no
    # git, so nothing in the not-yet-locked checkout's .git/config is
    # consulted by root here.
    if [ -f "$record" ] && [ ! -L "$record" ]; then
        recorded="$(sed -n 's/^DEPLOYED_SHA=//p' "$record" | tail -n 1)"
    fi
    case "$recorded" in
        *[!0-9a-f]*) recorded="(unreadable)" ;;
    esac
    if [ "$recorded" != "$expected" ]; then
        err "$record names ${recorded:-no commit}, not $expected, so the deploy did not land. The tree was not locked; the code that is running keeps the tree it expects."
        return 1
    fi
    if ! cmd_lock; then
        return 1
    fi
    cmd_check
}

main() {
    # Nothing below may read the script's own stdin: when the workflow pipes
    # this file in with `bash -s`, that is where bash is reading it from.
    exec </dev/null
    if [ "$#" -lt 1 ]; then
        usage
        return 2
    fi
    case "$1" in
        check) [ "$#" -eq 1 ] || { usage; return 2; }; cmd_check ;;
        lock) [ "$#" -eq 1 ] || { usage; return 2; }; cmd_lock ;;
        prepare-state) [ "$#" -eq 1 ] || { usage; return 2; }; cmd_prepare_state ;;
        adopt) [ "$#" -eq 1 ] || { usage; return 2; }; cmd_adopt ;;
        adopt-finish) [ "$#" -eq 2 ] || { usage; return 2; }; cmd_adopt_finish "$2" ;;
        *) usage; return 2 ;;
    esac
}

main "$@"; exit $?
