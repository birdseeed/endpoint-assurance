#!/usr/bin/env bash
# PAT-2311: before the deploy workflow pushes to patched-prod-01, prove that
# the deploy script and the hook root is about to run there are byte for byte
# the ones the repository says they are.
#
# Why. The push fires /opt/git/dashboard.git/hooks/post-receive, which has
# root exec /opt/patched-dashboard/scripts/deploy.sh. That is the copy already
# on the box, not the one being deployed: the reset to the new commit happens
# inside it (PAT-1441). deploy/code-tree-guard.sh proves that no non-root
# user could have changed either file. It cannot tell whether someone with
# root did, by hand, over SSH. This check can:
#
#   scripts/deploy.sh    must match the same file at the commit the box has
#                        checked out, taken from the runner's clone (full
#                        history, so any commit the box can be on is there).
#   hooks/post-receive   must match the repository's deploy/post-receive, or
#                        the pinned hash of the copy live on the box (below).
#
# Which commit "the box has checked out" means: the checkout's own HEAD, read
# from /opt/patched-dashboard/.git as two plain file reads. Not the mirror's
# ref, which still names the pushed commit after a deploy rolls back, and not
# DEPLOYED_SHA, which keeps naming the last confirmed commit while a
# .no-auto-rollback deploy has left a different one checked out. Either would
# fail a box whose deploy.sh is exactly what git put there. And never by
# running git as root in the checkout: `git status` there refreshes the index
# as root, and nothing here needs more than the ref.
#
# Commands:
#   verify TRANSPORT...  On the runner. TRANSPORT is the command that runs a
#                        shell command on the box with this file on stdin
#                        (the workflow passes `ssh ... root@<box>`). Runs the
#                        two box commands below through it, piping in this
#                        file each time exactly as the workflow pipes the code
#                        tree guard, and compares against the runner's clone.
#   box-head             On the box. Prints the 40-hex commit the checkout has.
#   box-check DEPLOY_SHA256 HOOK_SHA256...
#                        On the box. Fails unless scripts/deploy.sh hashes to
#                        DEPLOY_SHA256 and the mirror's post-receive hashes to
#                        one of the HOOK_SHA256 values. Both must be regular
#                        files, not symlinks.
#
# Every failure prints an ::error:: line saying what differed. Exit codes: 0
# ok, 1 a mismatch or anything that could not be read, 2 usage.
#
# Env overrides (tests only; the defaults are the live box):
#   CODE_TREE_DIR, CODE_TREE_MIRROR_DIR (box side, as in code-tree-guard.sh)
#   VERIFY_REPO_DIR (runner side: the clone to compare against)
set -uo pipefail

TREE="${CODE_TREE_DIR:-/opt/patched-dashboard}"
MIRROR="${CODE_TREE_MIRROR_DIR:-/opt/git/dashboard.git}"

# The post-receive hook live on patched-prod-01 was installed from PAT-909's
# deploy/post-receive (commit f0291df) on 2026-07-17 and has not been
# reinstalled since: it is byte for byte `git show f0291df:deploy/post-receive`
# (3001 bytes, root:root 0755, read on the box 2026-09-30). The repository's
# copy has since gained the PAT-1441 comment block (8fce0ef) and nothing
# else, so the two are not byte-identical. Both are accepted: this hash, and
# the repository's current copy, so reinstalling the hook from the repo needs
# no change here. When the live hook is next reinstalled, drop this constant.
LIVE_HOOK_SHA256=2365eb71f67e0efca57aa2d72a4d5b7790aba8cef3c777f3105d76bbcf2d4de2

err() {
    echo "::error::verify-box-deploy-script: $*" >&2
}

usage() {
    echo "usage: verify-box-deploy-script.sh verify TRANSPORT... | box-head | box-check DEPLOY_SHA256 HOOK_SHA256..." >&2
}

is_hex() {
    # is_hex LENGTH VALUE
    case "$2" in
        ''|*[!0-9a-f]*) return 1 ;;
    esac
    [ "${#2}" -eq "$1" ]
}

# sha256_of FILE: the file's sha256, or failure if it is missing, a symlink
# or not a regular file. sha256sum on the box and the runner; shasum on a
# Mac, where the tests run.
sha256_of() {
    local file="$1" sum
    if [ -L "$file" ] || [ ! -f "$file" ]; then
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sum="$(sha256sum < "$file")" || return 1
    else
        sum="$(shasum -a 256 < "$file")" || return 1
    fi
    sum="${sum%% *}"
    is_hex 64 "$sum" || return 1
    printf '%s\n' "$sum"
}

sha256_stdin() {
    local sum
    if command -v sha256sum >/dev/null 2>&1; then
        sum="$(sha256sum)" || return 1
    else
        sum="$(shasum -a 256)" || return 1
    fi
    sum="${sum%% *}"
    is_hex 64 "$sum" || return 1
    printf '%s\n' "$sum"
}

# ── box side ────────────────────────────────────────────────────────────────

cmd_box_head() {
    local gitdir="$TREE/.git" head ref sha=""
    if [ -L "$gitdir" ] || [ ! -d "$gitdir" ]; then
        err "$gitdir is missing or not a directory; cannot tell which commit the box has checked out."
        return 1
    fi
    if [ -L "$gitdir/HEAD" ] || [ ! -f "$gitdir/HEAD" ]; then
        err "$gitdir/HEAD is missing or not a regular file."
        return 1
    fi
    head="$(head -n 1 "$gitdir/HEAD")"
    case "$head" in
        "ref: refs/heads/"*)
            ref="${head#ref: }"
            case "$ref" in
                *..*|*[!A-Za-z0-9._/-]*)
                    err "$gitdir/HEAD names an unexpected ref: $ref"
                    return 1
                    ;;
            esac
            if [ -f "$gitdir/$ref" ] && [ ! -L "$gitdir/$ref" ]; then
                sha="$(head -n 1 "$gitdir/$ref")"
            elif [ -f "$gitdir/packed-refs" ] && [ ! -L "$gitdir/packed-refs" ]; then
                sha="$(awk -v r="$ref" '$2 == r { print $1; exit }' "$gitdir/packed-refs")"
            fi
            ;;
        *)
            # A detached HEAD holds the commit itself.
            sha="$head"
            ;;
    esac
    if ! is_hex 40 "$sha"; then
        err "could not read the commit $TREE has checked out from $gitdir (HEAD: $head)."
        return 1
    fi
    printf '%s\n' "$sha"
}

cmd_box_check() {
    local want_deploy="$1" got_deploy got_hook want rc=0 matched=0
    shift
    if ! got_deploy="$(sha256_of "$TREE/scripts/deploy.sh")"; then
        err "$TREE/scripts/deploy.sh is missing, a symlink, or could not be hashed."
        rc=1
    elif [ "$got_deploy" != "$want_deploy" ]; then
        err "$TREE/scripts/deploy.sh on the box does not match the file at the commit the box has checked out (box sha256 $got_deploy, GitHub sha256 $want_deploy). Someone has changed the script root runs on the next push. Nothing was pushed. Compare it with GitHub's copy before deploying."
        rc=1
    fi
    if ! got_hook="$(sha256_of "$MIRROR/hooks/post-receive")"; then
        err "$MIRROR/hooks/post-receive is missing, a symlink, or could not be hashed."
        rc=1
    else
        for want in "$@"; do
            if [ "$got_hook" = "$want" ]; then
                matched=1
            fi
        done
        if [ "$matched" -ne 1 ]; then
            err "$MIRROR/hooks/post-receive on the box matches neither the repository's deploy/post-receive nor the pinned hash of the hook installed on 2026-07-17 (box sha256 $got_hook, accepted: $*). Nothing was pushed. Compare it with deploy/post-receive before deploying."
            rc=1
        fi
    fi
    if [ "$rc" -eq 0 ]; then
        echo "verify-box-deploy-script: ok: $TREE/scripts/deploy.sh and $MIRROR/hooks/post-receive match GitHub"
    fi
    return "$rc"
}

# ── runner side ─────────────────────────────────────────────────────────────

cmd_verify() {
    local self repo head want_deploy repo_hook
    self="${BASH_SOURCE[0]}"
    repo="${VERIFY_REPO_DIR:-$(cd "$(dirname "$self")/.." && pwd)}"

    # stdin is this file; the transport's stdout is the box's answer.
    if ! head="$("$@" "bash -s -- box-head" < "$self")"; then
        err "could not read which commit the box has checked out (see the lines above). Nothing was pushed."
        return 1
    fi
    if ! is_hex 40 "$head"; then
        err "the box reported '$head' as its checked-out commit, which is not a commit id. Nothing was pushed."
        return 1
    fi
    if ! git -C "$repo" cat-file -e "${head}^{commit}" 2>/dev/null; then
        err "the box has $head checked out, which is not in GitHub's history. Something other than this workflow put it there. Nothing was pushed."
        return 1
    fi
    if ! want_deploy="$(git -C "$repo" cat-file blob "${head}:scripts/deploy.sh" | sha256_stdin)"; then
        err "could not read scripts/deploy.sh at $head from the runner's clone. Nothing was pushed."
        return 1
    fi
    if ! repo_hook="$(sha256_of "$repo/deploy/post-receive")"; then
        err "could not hash $repo/deploy/post-receive. Nothing was pushed."
        return 1
    fi
    echo "verify-box-deploy-script: the box has $head checked out"
    if ! "$@" "bash -s -- box-check $want_deploy $repo_hook $LIVE_HOOK_SHA256" < "$self"; then
        return 1
    fi
    return 0
}

main() {
    local arg
    if [ "$#" -lt 1 ]; then
        usage
        return 2
    fi
    case "$1" in
        verify)
            shift
            [ "$#" -ge 1 ] || { usage; return 2; }
            cmd_verify "$@"
            ;;
        box-head)
            # Nothing on the box may read stdin: under `bash -s` that is
            # where bash is reading this file from.
            exec </dev/null
            [ "$#" -eq 1 ] || { usage; return 2; }
            cmd_box_head
            ;;
        box-check)
            exec </dev/null
            shift
            [ "$#" -ge 2 ] || { usage; return 2; }
            for arg in "$@"; do
                is_hex 64 "$arg" || { usage; return 2; }
            done
            cmd_box_check "$@"
            ;;
        *) usage; return 2 ;;
    esac
}

main "$@"; exit $?
