#!/bin/bash
# Patched.im Dashboard — deploy script.
#
# Two invocation modes:
#
#   1. Hook mode (PAT-909) — invoked by deploy/post-receive on every push to
#      main. The hook already knows the new SHA (from the push it just
#      received) and the previously-deployed SHA (read from the checkout
#      before handing off), and passes both in explicitly:
#        deploy.sh --from-hook <new-sha> --rollback-to <old-sha>
#      This is the automatic path — no `git pull`, the hook already has the
#      new commit in the mirror.
#
#   2. Standalone mode — no flags. Pulls origin/main (the local bare mirror)
#      into the checkout and deploys whatever that resolves to. For a manual
#      on-box redeploy: `sudo scripts/deploy.sh` (or the installed copy, see
#      below).
#
# Both modes: reinstall requirements, sync box-side config (systemd unit,
# polkit rules, superseded-artefact removal — PAT-986), restart the
# service, run the smoke suite, and auto-roll back to the pre-deploy commit
# (code + deps + box config + restart) if anything fails.
#
# NOTE on the code tree (PAT-2307): the checkout and the bare mirror belong
# to root, with no group or other write, and the service user (www-data)
# writes only to its state directory (/var/lib/patched-dashboard, the
# unit's StateDirectory=). Everything this script runs or installs comes out
# of the checkout, so before running anything from it this script checks
# that no non-root user could have changed it (deploy/code-tree-guard.sh
# check), and after every `git reset --hard`, forward or rollback, it locks
# the tree again and re-checks it before pip, box-config sync, restart or
# smoke. It never hands the tree back to the service user; versions before
# PAT-2307 did (`chown -R www-data`), which is the escalation path this
# closes. The guard it uses is a private copy taken at start, so a rollback
# to a commit that predates the guard can still lock the tree. The deploy
# workflow runs the same guard from its own (GitHub) copy of the file
# before the push and before installing the nginx config; this in-script
# check is what covers a manual push to the mirror, which skips the
# workflow.
#
# NOTE on DEPLOYED_SHA (PAT-992): $DEPLOYED_SHA_FILE (default
# $REPO_DIR/DEPLOYED_SHA) is written, atomically, as the LAST step of any
# path that has POSITIVELY VERIFIED the running state — a smoke-passed
# forward deploy, a smoke-skipped-but-restarted forward deploy, or a
# completed rollback (recording what the box rolled BACK to, not what it
# tried to deploy). It is deliberately NOT written on any path that
# verified nothing: the no-op path (nothing to compare, could be sitting on
# a commit a PRIOR smoke failure left behind under .no-auto-rollback), the
# .no-auto-rollback skip itself, or a rollback that fails critically. See
# write_deployed_sha() below for the atomic-write mechanics. The estate's
# dashboard drift check (`deploy_drift` in main.py) reads this file and
# compares it against the local checkout's own HEAD — nothing on the box
# ever reads it back FROM the box's own deploy machinery, this is a
# one-way provenance record for humans (grep it over SSH) and that check.
#
# NOTE on box-config sync (PAT-986): before this, deploy.sh deployed code
# only — anything under deploy/ (the systemd unit, polkit rules) had to be
# installed on the box by hand, so a commit that changed one silently
# drifted from what was actually running until someone remembered to SSH in
# and do it. sync_box_config() (defined below) now installs
# deploy/patched-dashboard.service and deploy/*.rules, and removes anything
# listed in deploy/removed-artifacts.txt, every deploy — idempotently, so a
# box that's already correct is a no-op. It runs from BOTH the forward
# deploy path and rollback(), always immediately before the service
# restart in each: authorisation config has to land before code that
# depends on it restarts, in both directions, or you reproduce the exact
# silent break this ticket exists to close (PAT-931 shipped a hardened
# unit + a polkit rule in the same commit as the code that needs them).
#
# NOTE on the self-referential execution model: because the hook now invokes
# THIS file directly out of the checkout (rather than a separate system copy
# frozen from an earlier commit), a change to this script ships and takes
# effect in the same push that introduces it — there is no longer a manual
# "copy a reviewed version into place" guardrail on deploy-logic changes
# specifically. That trade-off was made deliberately for PAT-909 (one
# implementation, not two copies to keep in sync) since this dashboard is an
# internal ops tool, not a customer-facing endpoint agent — see AGENTS.md's
# "Endpoint-trust and the review gate" section for why that distinction
# matters. For an on-demand redeploy, run this file from the checkout in
# standalone mode. The old standalone copy at /usr/local/bin/patched-deploy.sh
# predated PAT-909 and chowned the tree to www-data; deploy/removed-
# artifacts.txt removes it (PAT-2311). The deploy workflow also checks this
# file's hash on the box against GitHub before every push
# (deploy/verify-box-deploy-script.sh).
#
# Usage:
#   sudo scripts/deploy.sh
#   sudo scripts/deploy.sh --from-hook <new-sha> --rollback-to <old-sha>
#
# Exit codes:
#   0  = success
#   1  = pull/reset, requirements install, or service-restart failed (rolled
#        back unless .no-auto-rollback present, in which case see exit 2)
#   2  = smoke test failed and was rolled back — OR any failure occurred
#        while .no-auto-rollback is present (no rollback attempted)
#   3  = critical: rollback itself failed (service may be down)
#
# To opt out of auto-rollback for a specific deploy (e.g. schema changes
# that can't roll back cleanly), create the file:
#   /opt/patched-dashboard/.no-auto-rollback
# The script will halt without rolling back if anything fails past the pull/
# reset step. Remove the file after the deploy lands.
#
# Env var overrides (test harness only — do not set these for a real
# production deploy; defaults match the live box):
#   DEPLOY_REPO_DIR, DEPLOY_SERVICE, DEPLOY_LOG, DEPLOY_CODE_OWNER,
#   DEPLOY_CODE_GROUP, DEPLOY_MIRROR_DIR, DEPLOY_ENV_FILE,
#   DEPLOY_ALLOW_NONROOT, DEPLOY_SYSTEMD_DIR, DEPLOY_POLKIT_RULES_DIR,
#   DEPLOY_CONFIG_OWNER, DEPLOY_CONFIG_GROUP, DEPLOY_HCLOUD_BIN,
#   DEPLOY_ORIGIN_KEY, and DEPLOY_RETIRED_ACCOUNT{,_UID,_HOME,_TMP_DIRS,
#   _SCAN_ROOT,_TUNNEL_DIR} (honoured only with DEPLOY_ALLOW_NONROOT set, and
#   refused without it; see RETIRED_ACCOUNT below)
# See scripts/test-post-receive-rollback.sh for how these are used to dry-run
# the rollback logic against a scratch clone without touching the real box.

REPO_DIR="${DEPLOY_REPO_DIR:-/opt/patched-dashboard}"
SERVICE="${DEPLOY_SERVICE:-patched-dashboard}"
LOG="${DEPLOY_LOG:-/var/log/patched-deploy.log}"
# PAT-2307: owner of the code tree and of DEPLOYED_SHA. Root on the box;
# the test harness overrides both to the invoking user.
CODE_OWNER="${DEPLOY_CODE_OWNER:-root}"
CODE_GROUP="${DEPLOY_CODE_GROUP:-root}"
# The bare mirror the post-receive hook lives in. Root runs its hooks on
# every push, so the guard holds it to the same standard as the checkout.
MIRROR_DIR="${DEPLOY_MIRROR_DIR:-/opt/git/dashboard.git}"
CODE_TREE_GUARD_SRC="$REPO_DIR/deploy/code-tree-guard.sh"
CODE_TREE_GUARD=""
ENV_FILE="${DEPLOY_ENV_FILE:-/etc/patched-dashboard/dashboard.env}"
SMOKE_RUNNER="$REPO_DIR/scripts/smoke/run_all.py"
PYTHON="$REPO_DIR/venv/bin/python3"
PIP="$REPO_DIR/venv/bin/pip"
NO_AUTO_ROLLBACK_MARKER="$REPO_DIR/.no-auto-rollback"
# PAT-992 — the deployed-SHA provenance record. See write_deployed_sha()
# below for the atomicity/ordering contract.
DEPLOYED_SHA_FILE="${DEPLOY_DEPLOYED_SHA_FILE:-$REPO_DIR/DEPLOYED_SHA}"

# PAT-986 — box-side config sync (systemd unit + polkit rules.d). Owner/
# group default to root:root, matching the real destination dirs; the test
# harness overrides both to the invoking user so it can write scratch
# directories without privilege.
SYSTEMD_DIR="${DEPLOY_SYSTEMD_DIR:-/etc/systemd/system}"
POLKIT_RULES_DIR="${DEPLOY_POLKIT_RULES_DIR:-/etc/polkit-1/rules.d}"
CONFIG_OWNER="${DEPLOY_CONFIG_OWNER:-root}"
CONFIG_GROUP="${DEPLOY_CONFIG_GROUP:-root}"
REMOVED_ARTIFACTS_MANIFEST="$REPO_DIR/deploy/removed-artifacts.txt"
# PAT-2312: the Hetzner CLI that root runs from the firewall-apply units. It
# is not in the repo; sync_box_config only enforces its ownership. The test
# harness points this at a scratch path so it never touches a real binary.
HCLOUD_BIN="${DEPLOY_HCLOUD_BIN:-/usr/local/bin/hcloud}"
# PAT-2312: the Cloudflare Origin Certificate's private key, which only the
# nginx master (root) reads. sync_box_config holds it to root:root 0600.
ORIGIN_KEY="${DEPLOY_ORIGIN_KEY:-/etc/ssl/dashboard.patched.im.key}"
# PAT-2312: the login account retired on patched-prod-01, which
# sync_box_config removes (remove_retired_account). A real deploy always uses
# these values. The DEPLOY_RETIRED_* overrides are for the dry run only: they
# are honoured when DEPLOY_ALLOW_NONROOT is set, and the pre-flight refuses a
# run that sets them without it, so no variable can point a root deploy at
# another account or path. A real deploy also runs the step on a fixed system
# PATH, so nothing earlier on the caller's PATH can stand in for userdel; the
# dry run keeps its own PATH, which is how it shims userdel and friends.
RETIRED_ACCOUNT=patched
RETIRED_ACCOUNT_UID=1001
RETIRED_ACCOUNT_HOME=/home/patched
RETIRED_ACCOUNT_TMP_DIRS="/tmp /var/tmp"
RETIRED_ACCOUNT_SCAN_ROOT=/
RETIRED_ACCOUNT_TUNNEL_DIR=/etc/cloudflared
RETIRED_ACCOUNT_PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ -n "${DEPLOY_ALLOW_NONROOT:-}" ]; then
    RETIRED_ACCOUNT="${DEPLOY_RETIRED_ACCOUNT:-$RETIRED_ACCOUNT}"
    RETIRED_ACCOUNT_UID="${DEPLOY_RETIRED_ACCOUNT_UID:-$RETIRED_ACCOUNT_UID}"
    RETIRED_ACCOUNT_HOME="${DEPLOY_RETIRED_ACCOUNT_HOME:-$RETIRED_ACCOUNT_HOME}"
    RETIRED_ACCOUNT_TMP_DIRS="${DEPLOY_RETIRED_ACCOUNT_TMP_DIRS:-$RETIRED_ACCOUNT_TMP_DIRS}"
    RETIRED_ACCOUNT_SCAN_ROOT="${DEPLOY_RETIRED_ACCOUNT_SCAN_ROOT:-$RETIRED_ACCOUNT_SCAN_ROOT}"
    RETIRED_ACCOUNT_TUNNEL_DIR="${DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR:-$RETIRED_ACCOUNT_TUNNEL_DIR}"
    RETIRED_ACCOUNT_PATH="$PATH"
fi

# Files git and pip create as root must come out without group or other
# write, or the code tree guard below fails the deploy on them.
umask 022

log() {
    local msg
    msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
    echo "$msg"
    echo "$msg" >> "$LOG" 2>/dev/null
}

# code_tree_guard COMMAND: runs this deploy's private copy of
# deploy/code-tree-guard.sh (taken at start, see the pre-flight below)
# against this checkout and mirror, logging its output line by line.
code_tree_guard() {
    local out rc line
    out="$(CODE_TREE_DIR="$REPO_DIR" CODE_TREE_MIRROR_DIR="$MIRROR_DIR" \
        CODE_TREE_OWNER="$CODE_OWNER" CODE_TREE_GROUP="$CODE_GROUP" \
        bash "$CODE_TREE_GUARD" "$@" 2>&1 </dev/null)"
    rc=$?
    while IFS= read -r line; do
        [ -n "$line" ] && log "$line"
    done <<< "$out"
    return "$rc"
}

# lock_code_tree: after any `git reset --hard`, make the checkout and the
# mirror root-owned with no group or other write, then prove it. Returns
# non-zero if either step fails; callers must not run anything from the
# tree after that.
lock_code_tree() {
    if ! code_tree_guard lock; then
        return 1
    fi
    code_tree_guard check
}

# write_deployed_sha SHA — records the commit that is actually running right
# now (PAT-992). This is the single write path for $DEPLOYED_SHA_FILE;
# every call site below only invokes it once whatever it is recording has
# already been positively confirmed (a passed smoke suite, or a completed
# rollback restart) — never as an intention. Ordering at the call site is
# the safety property, same as sync_box_config's header comment: this
# function itself only guarantees the WRITE is atomic, not WHEN it runs.
#
# Atomicity: written to a temp file in the same directory as the
# destination (so `mv` is a same-filesystem rename, not a cross-filesystem
# copy) and moved into place last. A process that dies mid-write (disk
# full, OOM-killed, power loss) leaves the temp file behind — never a
# truncated or half-written $DEPLOYED_SHA_FILE — and the previous value,
# if any, is untouched until the mv succeeds.
#
# Format is deliberately flat key=value lines, trivially greppable over SSH:
#   DEPLOYED_SHA=<full 40-char commit sha>
#   DEPLOYED_AT=<UTC ISO-8601 timestamp>
write_deployed_sha() {
    local sha="$1"
    local tmp
    tmp="$(mktemp "${DEPLOYED_SHA_FILE}.tmp.XXXXXX" 2>>"$LOG")"
    if [ -z "$tmp" ] || [ ! -f "$tmp" ]; then
        log "ERROR: could not create temp file for $DEPLOYED_SHA_FILE; leaving previous value (if any) in place"
        return 1
    fi

    local deployed_at expected
    deployed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    expected="$(printf 'DEPLOYED_SHA=%s\nDEPLOYED_AT=%s\n' "$sha" "$deployed_at")"

    # PAT-992 FIX 3 (independent review): the write itself is checked, not
    # just the mktemp and the mv either side of it. A failure while writing
    # the temp file's content (disk full, quota, filesystem gone read-only
    # mid-deploy) must never let a partial/empty file get renamed over a
    # known-good record — that would convert a good record into a broken
    # one at exactly the moment something is already wrong.
    if ! { printf 'DEPLOYED_SHA=%s\n' "$sha"; printf 'DEPLOYED_AT=%s\n' "$deployed_at"; } > "$tmp"; then
        log "ERROR: write to temp file for $DEPLOYED_SHA_FILE failed; leaving previous value (if any) in place"
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    # Belt-and-braces, and not redundant in practice: some write failures
    # don't reliably surface as a non-zero exit status from the redirect
    # above — confirmed on this codebase's own dev/test bash (3.2, macOS):
    # a redirect that fails to open a permission-denied target reports the
    # error to the terminal but the `if !` on the compound command's exit
    # status does not see it as a failure. ENOSPC surfacing only at
    # close() is the same class of gap on other shells/filesystems. Read
    # the temp file back and require it to hold exactly the intended
    # content before it goes anywhere near the known-good file — a short
    # or garbled temp file must never be promoted just because mktemp and
    # the write both nominally "succeeded".
    if [ "$(cat "$tmp" 2>/dev/null)" != "$expected" ]; then
        log "ERROR: temp file for $DEPLOYED_SHA_FILE did not verify after writing ($(wc -c < "$tmp" 2>/dev/null || echo '?') bytes written); leaving previous value (if any) in place"
        rm -f "$tmp" 2>/dev/null
        return 1
    fi

    # PAT-2307: root's record, not the app's. The app only reads it
    # (deploy_drift in main.py), so it is root-owned and 0644: readable by
    # the service user, never writable by it. mktemp creates it 0600.
    chown "$CODE_OWNER:$CODE_GROUP" "$tmp" 2>/dev/null
    chmod 0644 "$tmp" 2>/dev/null
    if ! mv -f "$tmp" "$DEPLOYED_SHA_FILE"; then
        log "ERROR: failed to move new DEPLOYED_SHA into place; leaving previous value (if any) in place"
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    log "Recorded deployed SHA: $sha"
    return 0
}

usage() {
    cat <<EOF
Usage:
  sudo $0                                            # standalone: pull origin/main, install deps, restart, smoke, auto-rollback
  sudo $0 --from-hook NEW_SHA --rollback-to OLD_SHA   # hook mode: deploy NEW_SHA, roll back to OLD_SHA on failure
EOF
}

FROM_HOOK=""
ROLLBACK_TO=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from-hook)
            FROM_HOOK="$2"
            shift 2
            ;;
        --rollback-to)
            ROLLBACK_TO="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ -n "$FROM_HOOK" ] && [ -z "$ROLLBACK_TO" ]; then
    echo "ERROR: --from-hook requires --rollback-to" >&2
    exit 1
fi
if [ -z "$FROM_HOOK" ] && [ -n "$ROLLBACK_TO" ]; then
    echo "ERROR: --rollback-to requires --from-hook" >&2
    exit 1
fi

restart_service() {
    systemctl restart "$SERVICE" >> "$LOG" 2>&1
    sleep 2
    for _ in 1 2 3 4 5; do
        if systemctl is-active --quiet "$SERVICE"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

install_requirements() {
    if [ ! -f "$REPO_DIR/requirements.txt" ]; then
        log "WARN: requirements.txt not found at $REPO_DIR. Skipping dependency install."
        return 0
    fi
    if [ ! -x "$PIP" ]; then
        log "WARN: venv pip not found at $PIP. Skipping dependency install."
        return 0
    fi
    log "Installing requirements..."
    if ! "$PIP" install -q -r "$REPO_DIR/requirements.txt" >> "$LOG" 2>&1; then
        log "ERROR: pip install failed"
        return 1
    fi
    return 0
}

# sync_box_config — makes on-box systemd/polkit config match whatever is
# currently checked out in $REPO_DIR/deploy. Idempotent: a box that's
# already correct (the state of patched-prod-01 as of 2026-07-26, installed
# by hand) logs "unchanged"/"already absent" for everything and changes
# nothing. Logs every action so a stale-config deploy is never silent
# (acceptance criterion 5): installed, skipped-unchanged, or removed.
#
# Called from TWO places, deliberately:
#   1. The main forward-deploy path, after the checkout is reset to the new
#      commit and requirements are installed, but BEFORE restart_service.
#   2. rollback(), after IT resets the checkout back to $PREVIOUS_COMMIT,
#      also BEFORE restart_service.
# Both call sites read whatever deploy/ currently contains on disk — this
# function never hardcodes "new" or "old", it just converges to whatever
# the checkout's HEAD is right now. That means a rollback naturally reverts
# the systemd unit and polkit rules back to what the previous commit
# shipped, not just the code: PAT-931 shipped a hardened unit + a polkit
# rule in the same commit as the code that depends on them, so if some
# later commit's deploy fails and rolls back across a boundary like that,
# the old code needs its old authorisation config restored, not to be left
# running under the new commit's config.
#
# ORDERING IS THE SAFETY PROPERTY (see file header): this runs before
# restart_service in both call sites, so the service never restarts onto
# code whose authorisation config hasn't landed yet — that's the exact
# silent failure this ticket exists to close.
#
# KNOWN LIMITATION — removed-artifacts.txt deletions do NOT revert on
# rollback. That manifest only ever removes stale files (e.g. a sudoers
# rule superseded by a polkit rule for security reasons); recreating a
# deliberately-superseded, less-secure grant just because an unrelated
# smoke check failed on some later commit would be the wrong trade-off.
# In practice this is a non-issue for any rollback target reachable from
# main today (every commit main can currently roll back to already
# post-dates the PAT-931 sudoers->polkit migration), but it's a real edge
# case for any *future* manifest entry a rolled-back-to commit still
# depends on — whoever adds such an entry should think about that and note
# it in deploy/removed-artifacts.txt. The ownership steps for hcloud and
# the origin TLS key (PAT-2312) are one-directional for the same reason: a
# rollback leaves both root's, and no commit needs otherwise. So is removing
# the retired `patched` account (PAT-2312, remove_retired_account below): a
# rollback never recreates it, and nothing on the box ran as it.
#
# Returns 0 if the box now matches the checkout (including the drift guard
# on the systemd unit and polkit rules), 1 if any install/verify step
# failed.
sync_box_config() (
    local rc=0
    # This array is populated only by the copy sites below. Keep the gate
    # coupled to those sites so unrelated locally-installed services cannot
    # break a dashboard deploy and a newly copied service cannot be omitted.
    local -a hardening_units=()
    local -a systemd_unit_names=()
    local -a systemd_unit_had=()
    local -a systemd_unit_mode=()
    local -a systemd_unit_uid=()
    local -a systemd_unit_gid=()
    local -a changed_systemd_units=()
    local changed_systemd_count=0 hardening_unit_count=0
    local systemd_backup_dir unit_name unit_target unit_index
    local maintenance_timer_enabled=0 maintenance_timer_active=0
    local maintenance_timer_owned=0 hardening_gate_failed=0
    local prune_timer_enabled=0 prune_timer_active=0 prune_timer_owned=0

    # Derive the transaction inventory from regular unit sources this checkout
    # can actually copy. Missing sources are handled by the existing fail-closed
    # no-service gate; they must not create fictional rollback targets.
    for unit_name in patched-dashboard.service patched-dashboard-prune-reports.service patched-dashboard-prune-reports.timer patched-maintenance-facts.service patched-maintenance-facts.timer; do
        if [ -L "$REPO_DIR/deploy/$unit_name" ] || { [ -e "$REPO_DIR/deploy/$unit_name" ] && [ ! -f "$REPO_DIR/deploy/$unit_name" ]; }; then
            log "ERROR: refusing non-regular systemd source $REPO_DIR/deploy/$unit_name"
            rc=1
            continue
        fi
        if [ -f "$REPO_DIR/deploy/$unit_name" ] && [ ! -L "$REPO_DIR/deploy/$unit_name" ]; then
            systemd_unit_names+=("$unit_name")
            if [ "$unit_name" = "patched-maintenance-facts.timer" ]; then
                maintenance_timer_owned=1
            fi
            if [ "$unit_name" = "patched-dashboard-prune-reports.timer" ]; then
                prune_timer_owned=1
            fi
        fi
    done

    systemd_backup_dir="$(mktemp -d)" || {
        log "ERROR: could not create transactional systemd backup directory"
        return 1
    }
    trap 'if [ -n "${systemd_backup_dir:-}" ]; then rm -rf "$systemd_backup_dir"; fi' EXIT
    for unit_index in "${!systemd_unit_names[@]}"; do
        unit_name="${systemd_unit_names[$unit_index]}"
        unit_target="$SYSTEMD_DIR/$unit_name"
        systemd_unit_had[unit_index]=0
        if [ -f "$unit_target" ] && [ ! -L "$unit_target" ]; then
            if ! install -m 0600 "$unit_target" "$systemd_backup_dir/$unit_name" >> "$LOG" 2>&1; then
                log "ERROR: could not back up $unit_target; live units unchanged"
                rm -rf "$systemd_backup_dir"
                return 1
            fi
            systemd_unit_had[unit_index]=1
            systemd_unit_mode[unit_index]="$(stat -c '%a' "$unit_target" 2>/dev/null || stat -f '%Lp' "$unit_target")"
            systemd_unit_uid[unit_index]="$(stat -c '%u' "$unit_target" 2>/dev/null || stat -f '%u' "$unit_target")"
            systemd_unit_gid[unit_index]="$(stat -c '%g' "$unit_target" 2>/dev/null || stat -f '%g' "$unit_target")"
        elif [ -e "$unit_target" ]; then
            log "ERROR: refusing non-regular installed systemd unit $unit_target"
            rm -rf "$systemd_backup_dir"
            return 1
        fi
    done
    if systemctl is-enabled --quiet patched-maintenance-facts.timer >> "$LOG" 2>&1; then
        maintenance_timer_enabled=1
    fi
    if systemctl is-active --quiet patched-maintenance-facts.timer >> "$LOG" 2>&1; then
        maintenance_timer_active=1
    fi
    # PAT-2311: the prune timer's runtime state, snapshotted only when this
    # checkout manages it, so a failed sync can put it back exactly.
    if [ "$prune_timer_owned" = "1" ]; then
        if systemctl is-enabled --quiet patched-dashboard-prune-reports.timer >> "$LOG" 2>&1; then
            prune_timer_enabled=1
        fi
        if systemctl is-active --quiet patched-dashboard-prune-reports.timer >> "$LOG" 2>&1; then
            prune_timer_active=1
        fi
    fi

    # restore_timer_state TIMER WAS_ENABLED WAS_ACTIVE: put a timer's
    # enabled and active state back to what the snapshot above recorded. A
    # disable or stop that fails is only a failure if the timer is in fact
    # still enabled or active afterwards.
    restore_timer_state() {
        local timer="$1" was_enabled="$2" was_active="$3" failed=0
        if [ "$was_enabled" = "1" ]; then
            systemctl enable "$timer" >> "$LOG" 2>&1 || failed=1
        else
            if ! systemctl disable "$timer" >> "$LOG" 2>&1; then
                if systemctl is-enabled --quiet "$timer" >> "$LOG" 2>&1; then failed=1; fi
            fi
        fi
        if [ "$was_active" = "1" ]; then
            systemctl start "$timer" >> "$LOG" 2>&1 || failed=1
        else
            if ! systemctl stop "$timer" >> "$LOG" 2>&1; then
                if systemctl is-active --quiet "$timer" >> "$LOG" 2>&1; then failed=1; fi
            fi
        fi
        return "$failed"
    }

    rollback_systemd_transaction() {
        local restore_failed=0 restore_stage had_before mode_before uid_before gid_before
        trap - HUP INT TERM
        if [ "$changed_systemd_count" -gt 0 ]; then
          for unit_name in "${changed_systemd_units[@]}"; do
            unit_target="$SYSTEMD_DIR/$unit_name"
            had_before=0 mode_before=0644 uid_before="$CONFIG_OWNER" gid_before="$CONFIG_GROUP"
            for unit_index in "${!systemd_unit_names[@]}"; do
                if [ "${systemd_unit_names[$unit_index]}" = "$unit_name" ]; then
                    had_before="${systemd_unit_had[$unit_index]}"
                    if [ "$had_before" = "1" ]; then
                        mode_before="${systemd_unit_mode[$unit_index]}"
                        uid_before="${systemd_unit_uid[$unit_index]}"
                        gid_before="${systemd_unit_gid[$unit_index]}"
                    fi
                    break
                fi
            done
            if [ "$had_before" = "1" ]; then
                restore_stage="$(mktemp "${unit_target}.pat1237-restore.XXXXXX")" || { restore_failed=1; continue; }
                if ! install -m "$mode_before" -o "$uid_before" -g "$gid_before" "$systemd_backup_dir/$unit_name" "$restore_stage" >> "$LOG" 2>&1; then
                    rm -f "$restore_stage"; restore_failed=1; continue
                fi
                if ! mv -f "$restore_stage" "$unit_target" >> "$LOG" 2>&1; then
                    rm -f "$restore_stage"; restore_failed=1
                fi
            elif ! rm -f "$unit_target" >> "$LOG" 2>&1; then
                restore_failed=1
            fi
          done
        fi
        if [ "$changed_systemd_count" -gt 0 ]; then
            systemctl daemon-reload >> "$LOG" 2>&1 || restore_failed=1
        fi
        if [ "$maintenance_timer_owned" = "1" ]; then
            restore_timer_state patched-maintenance-facts.timer \
                "$maintenance_timer_enabled" "$maintenance_timer_active" || restore_failed=1
        fi
        if [ "$prune_timer_owned" = "1" ]; then
            restore_timer_state patched-dashboard-prune-reports.timer \
                "$prune_timer_enabled" "$prune_timer_active" || restore_failed=1
        fi
        return "$restore_failed"
    }
    trap 'if ! rollback_systemd_transaction; then log "CRITICAL: interrupted box-config rollback was incomplete"; fi; exit 130' HUP INT TERM

    # ── application systemd units ──
    # patched-dashboard.service, and (PAT-2307) the reports-pruning oneshot,
    # whose write grant has to follow the reports into the app's state
    # directory. It was hand-installed until then, so a repo change to it
    # never reached the box. A .service change needs only the daemon-reload
    # below: its timer (installed by the block after this loop since
    # PAT-2311) starts whatever definition systemd has loaded when it next
    # fires.
    local app_unit unit_src unit_dst
    for app_unit in patched-dashboard.service patched-dashboard-prune-reports.service; do
        unit_src="$REPO_DIR/deploy/$app_unit"
        unit_dst="$SYSTEMD_DIR/$app_unit"
        if [ ! -f "$unit_src" ] || [ -L "$unit_src" ]; then
            log "WARN: $unit_src not found in checkout; cannot install or verify the systemd unit"
            continue
        fi
        hardening_units+=("$app_unit")
        hardening_unit_count=$((hardening_unit_count + 1))
        if [ -f "$unit_dst" ] && cmp -s "$unit_src" "$unit_dst"; then
            log "systemd unit unchanged ($unit_dst); skipping install and daemon-reload"
        else
            log "Installing systemd unit: $unit_src -> $unit_dst"
            mkdir -p "$SYSTEMD_DIR" >> "$LOG" 2>&1
            if install -m 0644 -o "$CONFIG_OWNER" -g "$CONFIG_GROUP" "$unit_src" "$unit_dst" >> "$LOG" 2>&1; then
                changed_systemd_units+=("$app_unit")
                changed_systemd_count=$((changed_systemd_count + 1))
                # Only reload when the file actually changed — a pointless
                # daemon-reload on every deploy is noise (acceptance
                # criterion 1).
                if systemctl daemon-reload >> "$LOG" 2>&1; then
                    log "daemon-reload complete"
                else
                    log "ERROR: systemctl daemon-reload failed after installing $unit_dst"
                    rc=1
                fi
            else
                log "ERROR: failed to install $unit_dst"
                rc=1
            fi
        fi
        # Drift guard (acceptance criterion 6): whatever happened above,
        # the live file must now match the repo's, or fail loudly instead
        # of silently running stale/wrong config.
        if [ ! -f "$unit_dst" ]; then
            log "ERROR: drift guard failed — $unit_dst is missing after install"
            rc=1
        elif ! cmp -s "$unit_src" "$unit_dst"; then
            log "ERROR: drift guard failed — $unit_dst still differs from $unit_src after install"
            rc=1
        fi
    done

    # ── the reports-pruning timer (PAT-2311) ──
    # Hand-installed on patched-prod-01 since PAT-87 (byte-identical to
    # deploy/patched-dashboard-prune-reports.timer when this block was
    # added), while its .service has been synced above since PAT-2307. Same
    # discipline as the patched-maintenance-facts timer below: a cmp-verified
    # install, then daemon-reload and `enable --now` only when the file
    # changed, and on every run a check that the timer is enabled and
    # active. A checkout without the file (a rollback to a commit from
    # before this block) leaves the installed timer exactly as it is.
    local prune_timer=patched-dashboard-prune-reports.timer
    local prune_timer_src="$REPO_DIR/deploy/$prune_timer"
    local prune_timer_dst="$SYSTEMD_DIR/$prune_timer"
    local prune_timer_changed=0
    if [ "$prune_timer_owned" = "1" ]; then
        if [ -f "$prune_timer_dst" ] && cmp -s "$prune_timer_src" "$prune_timer_dst"; then
            log "systemd unit unchanged ($prune_timer_dst); skipping install"
        else
            log "Installing systemd unit: $prune_timer_src -> $prune_timer_dst"
            mkdir -p "$SYSTEMD_DIR" >> "$LOG" 2>&1
            if install -m 0644 -o "$CONFIG_OWNER" -g "$CONFIG_GROUP" "$prune_timer_src" "$prune_timer_dst" >> "$LOG" 2>&1; then
                prune_timer_changed=1
                changed_systemd_units+=("$prune_timer")
                changed_systemd_count=$((changed_systemd_count + 1))
            else
                log "ERROR: failed to install $prune_timer_dst"
                rc=1
            fi
        fi
        if [ ! -f "$prune_timer_dst" ]; then
            log "ERROR: drift guard failed: $prune_timer_dst is missing after install"
            rc=1
        elif ! cmp -s "$prune_timer_src" "$prune_timer_dst"; then
            log "ERROR: drift guard failed: $prune_timer_dst still differs from $prune_timer_src after install"
            rc=1
        fi
        if [ "$prune_timer_changed" = "1" ]; then
            if systemctl daemon-reload >> "$LOG" 2>&1; then
                log "daemon-reload complete ($prune_timer)"
            else
                log "ERROR: systemctl daemon-reload failed after installing $prune_timer_dst"
                rc=1
            fi
            if systemctl enable --now "$prune_timer" >> "$LOG" 2>&1; then
                log "$prune_timer enabled and started"
            else
                log "ERROR: failed to enable/start $prune_timer after installing its unit"
                rc=1
            fi
        fi
        if ! systemctl is-enabled --quiet "$prune_timer" >> "$LOG" 2>&1; then
            log "ERROR: $prune_timer is not enabled after box-config sync"
            rc=1
        fi
        if ! systemctl is-active --quiet "$prune_timer" >> "$LOG" 2>&1; then
            log "ERROR: $prune_timer is not active after box-config sync"
            rc=1
        fi
    else
        log "WARN: $prune_timer_src not found in checkout; leaving the installed timer as it is"
    fi

    # ── patched-maintenance-facts systemd units (PAT-1439/PAT-1438) ──
    # The facts emitter's .service and .timer previously had NO deploy path
    # at all -- hand-installed once and never touched again, which is
    # exactly how they went 12 days over systemd-hardening-floor.md's
    # ceiling unnoticed (PAT-1237's drift guard caught it; PAT-1439 hardened
    # the unit files themselves). Installed with the same cmp-verified
    # discipline as the dashboard unit above, but unlike that unit this pair
    # needs an explicit daemon-reload PLUS a timer re-enable/restart to
    # actually take effect -- copying the file alone leaves systemd running
    # whatever unit definition it already had loaded in memory. Restart the
    # TIMER, never the oneshot .service directly: `systemctl restart` on a
    # oneshot .service just fires an out-of-schedule run, it does not
    # "activate" anything the way restarting a long-running service would.
    local mf_changed=0
    local mf_name mf_src mf_dst
    for mf_name in patched-maintenance-facts.service patched-maintenance-facts.timer; do
        mf_src="$REPO_DIR/deploy/$mf_name"
        mf_dst="$SYSTEMD_DIR/$mf_name"
        if [ ! -f "$mf_src" ] || [ -L "$mf_src" ]; then
            log "WARN: $mf_src not found in checkout; cannot install or verify it"
            continue
        fi
        if [[ "$mf_name" == *.service ]]; then
            hardening_units+=("$mf_name")
            hardening_unit_count=$((hardening_unit_count + 1))
        fi
        if [ -f "$mf_dst" ] && cmp -s "$mf_src" "$mf_dst"; then
            log "systemd unit unchanged ($mf_dst); skipping install"
        else
            log "Installing systemd unit: $mf_src -> $mf_dst"
            mkdir -p "$SYSTEMD_DIR" >> "$LOG" 2>&1
            if install -m 0644 -o "$CONFIG_OWNER" -g "$CONFIG_GROUP" "$mf_src" "$mf_dst" >> "$LOG" 2>&1; then
                mf_changed=1
                changed_systemd_units+=("$mf_name")
                changed_systemd_count=$((changed_systemd_count + 1))
            else
                log "ERROR: failed to install $mf_dst"
                rc=1
            fi
        fi
        # Drift guard, same discipline as the dashboard unit above.
        if [ ! -f "$mf_dst" ]; then
            log "ERROR: drift guard failed — $mf_dst is missing after install"
            rc=1
        elif ! cmp -s "$mf_src" "$mf_dst"; then
            log "ERROR: drift guard failed — $mf_dst still differs from $mf_src after install"
            rc=1
        fi
    done

    if [ "$mf_changed" = "1" ]; then
        if systemctl daemon-reload >> "$LOG" 2>&1; then
            log "daemon-reload complete (patched-maintenance-facts units)"
        else
            log "ERROR: systemctl daemon-reload failed after installing patched-maintenance-facts units"
            rc=1
        fi

        # Re-enable + (re)start the TIMER only -- see the block comment
        # above for why the oneshot .service must never be restarted here.
        # `enable --now` both re-links the unit past any stale symlink and
        # starts it if it wasn't already running.
        if systemctl enable --now patched-maintenance-facts.timer >> "$LOG" 2>&1; then
            log "patched-maintenance-facts.timer re-enabled and started"
        else
            log "ERROR: failed to enable/start patched-maintenance-facts.timer after installing its unit"
            rc=1
        fi
    fi

    # Verify the result rather than trusting the copy, every run -- not
    # just when something changed above, since a timer that fell out of
    # enabled/active state some OTHER way should also fail this loudly.
    # Check the .service LOADS, not just that the timer is enabled/active
    # (PAT-1439 non-author review). `systemctl enable --now <timer>` succeeds
    # even when the .service it triggers failed to parse -- the timer is a
    # separate unit, and its own state says nothing about whether the thing
    # it fires can run. A malformed directive would then sit green here and
    # only surface as a failed job on the next hourly firing, in journald,
    # which is precisely the invisible-failure shape this deploy path exists
    # to close.
    mf_load_state="$(systemctl show patched-maintenance-facts.service -p LoadState --value 2>/dev/null || true)"
    if [ "$mf_load_state" != "loaded" ]; then
        echo "ERROR: patched-maintenance-facts.service did not load after daemon-reload (LoadState=${mf_load_state:-unknown}); the timer may be enabled but has nothing runnable to fire" >> "$LOG"
        rc=1
        hardening_gate_failed=1
    fi

    if ! systemctl is-enabled --quiet patched-maintenance-facts.timer >> "$LOG" 2>&1; then
        log "ERROR: patched-maintenance-facts.timer is not enabled after box-config sync"
        rc=1
    fi
    if ! systemctl is-active --quiet patched-maintenance-facts.timer >> "$LOG" 2>&1; then
        log "ERROR: patched-maintenance-facts.timer is not active after box-config sync"
        rc=1
    fi

    # A copied, loaded unit can still be materially less sandboxed than the
    # checked-in policy. Score every service this deploy installs, on this
    # box, before allowing the application restart to make the deploy look
    # successful. Missing, unparseable and over-ceiling scores all fail closed.
    # Refresh systemd's in-memory view even when bytes were unchanged, so the
    # score is for the checked-out fragments rather than stale loaded state.
    if [ "$hardening_unit_count" -gt 0 ] && ! systemctl daemon-reload >> "$LOG" 2>&1; then
        log "ERROR: daemon-reload failed before systemd hardening verification"
        rc=1
        hardening_gate_failed=1
    fi
    local hardening_guard="$REPO_DIR/deploy/verify-systemd-hardening-floor.sh"
    if [ "$hardening_unit_count" -eq 0 ]; then
        log "ERROR: no copied systemd services were supplied to the hardening gate"
        rc=1
        hardening_gate_failed=1
    elif [ ! -f "$hardening_guard" ] || [ -L "$hardening_guard" ] || [ ! -x "$hardening_guard" ]; then
        if [ "${DEPLOY_ROLLBACK_SYNC:-0}" = "1" ]; then
            log "Legacy rollback target has no executable hardening guard; restoring its unit bytes without scoring"
        else
            log "ERROR: missing or untrusted systemd hardening guard $hardening_guard"
            rc=1
            hardening_gate_failed=1
        fi
    elif ! "$hardening_guard" "${hardening_units[@]}" >> "$LOG" 2>&1; then
        log "ERROR: systemd hardening floor verification failed after box-config sync"
        rc=1
        hardening_gate_failed=1
    fi

    # A failed gate must not leave the just-loaded unit definitions behind,
    # including on a no-op deploy where checkout rollback has nothing to do.
    # Restore only files this invocation actually promoted.
    if [ "$rc" -ne 0 ]; then
        local restore_failed=0
        rollback_systemd_transaction || restore_failed=1
        rm -rf "$systemd_backup_dir"
        if [ "$restore_failed" -ne 0 ]; then
            log "CRITICAL: box-config failure and changed-unit rollback was incomplete"
        elif [ "$hardening_gate_failed" -eq 1 ]; then
            log "Systemd hardening floor failed; restored changed units and timer state"
        else
            log "Box-config sync failed; restored changed units and timer state"
        fi
    fi

    rm -rf "$systemd_backup_dir"

    # ── polkit rules (deploy/*.rules -> $POLKIT_RULES_DIR, mode 0644
    # root:root). polkitd auto-reloads rules.d on change — no reload step
    # needed here, unlike the systemd unit above (confirmed in
    # deploy/49-patched-ops-fw.rules's own header comment). Don't add a
    # reload call on the strength of this comment alone if that ever
    # changes upstream.
    local rule_src rule_dst
    for rule_src in "$REPO_DIR"/deploy/*.rules; do
        [ -e "$rule_src" ] || continue   # literal glob (no match) guard
        rule_dst="$POLKIT_RULES_DIR/$(basename "$rule_src")"
        if [ -f "$rule_dst" ] && cmp -s "$rule_src" "$rule_dst"; then
            log "polkit rule unchanged ($rule_dst); skipping"
        else
            log "Installing polkit rule: $rule_src -> $rule_dst"
            mkdir -p "$POLKIT_RULES_DIR" >> "$LOG" 2>&1
            if ! install -m 0644 -o "$CONFIG_OWNER" -g "$CONFIG_GROUP" "$rule_src" "$rule_dst" >> "$LOG" 2>&1; then
                log "ERROR: failed to install $rule_dst"
                rc=1
            fi
        fi
        if ! cmp -s "$rule_src" "$rule_dst" 2>/dev/null; then
            log "ERROR: drift guard failed — $rule_dst still differs from $rule_src after install"
            rc=1
        fi
    done

    # ── remove superseded artefacts (declarative manifest, see the file's
    # own header for why removal doesn't reverse on rollback) ──
    if [ -f "$REMOVED_ARTIFACTS_MANIFEST" ]; then
        local path
        while IFS= read -r path; do
            case "$path" in
                ''|'#'*) continue ;;
            esac
            if [ -e "$path" ]; then
                if rm -f "$path"; then
                    log "Removed stale artefact: $path"
                else
                    log "ERROR: failed to remove stale artefact: $path"
                    rc=1
                fi
            else
                log "Stale artefact already absent, skipping: $path"
            fi
        done < "$REMOVED_ARTIFACTS_MANIFEST"
    fi

    # ── ownership of two root-only files (PAT-2312) ──
    # Neither file is in the repo, so this only sets ownership and mode;
    # nothing here installs, replaces or reads either one.
    #
    # $HCLOUD_BIN: root runs it from the hetzner-firewall-apply units, and
    # on patched-prod-01 it was owned by patched, a login account, so
    # whoever could act as patched could change what root runs. 0755.
    #
    # $ORIGIN_KEY: the Cloudflare Origin Certificate's private key. It was
    # 0644, so any local user, www-data (the app and the nginx workers)
    # included, could read it. Only the nginx master, which runs as root,
    # loads it; the workers inherit it, and the backup runs as root too.
    # 0600, as docs/OPERATIONS.md already says. nginx keeps the key it has
    # loaded, so this needs no reload.
    #
    # A symlink is refused, never followed: chown -h would fix the link
    # rather than the file that is used, and chmod follows links. Both
    # parent directories are root's, so nobody else can swap a file for a
    # link between the check and the chmod.
    owner_and_mode() {
        local out
        out="$(stat -c '%U:%G %a' "$1" 2>/dev/null)" \
            || out="$(stat -f '%Su:%Sg %Mp%Lp' "$1" 2>/dev/null)" \
            || out=""
        # BSD stat pads the mode to four digits (0755); GNU does not.
        case "$out" in
            *" 0"???) out="${out% 0*} ${out##* 0}" ;;
        esac
        printf '%s' "$out"
    }
    # enforce_root_file LABEL PATH MODE: make PATH $CONFIG_OWNER:
    # $CONFIG_GROUP with MODE (four octal digits) if it exists, log what
    # changed, and return 1 if it cannot be or is not that afterwards.
    enforce_root_file() {
        local label="$1" path="$2" mode="$3"
        local want="$CONFIG_OWNER:$CONFIG_GROUP ${3#0}" was now
        if [ -L "$path" ]; then
            log "ERROR: $path is a symlink; refusing to change ownership through it. Replace it with a regular file owned by $CONFIG_OWNER:$CONFIG_GROUP (PAT-2312)"
            return 1
        elif [ ! -e "$path" ]; then
            log "$label not installed at $path; no ownership to enforce"
            return 0
        elif [ ! -f "$path" ]; then
            log "ERROR: $path is not a regular file; refusing to change it (PAT-2312)"
            return 1
        fi
        was="$(owner_and_mode "$path")"
        if [ "$was" = "$want" ]; then
            log "$label ownership unchanged ($path is $was)"
        elif chown -h "$CONFIG_OWNER:$CONFIG_GROUP" "$path" >> "$LOG" 2>&1 \
            && chmod "$mode" "$path" >> "$LOG" 2>&1; then
            now="$(owner_and_mode "$path")"
            log "Enforced $label ownership: $path was ${was:-unreadable}, now ${now:-unreadable}"
        else
            log "ERROR: failed to set $path to $want (was ${was:-unreadable})"
        fi
        now="$(owner_and_mode "$path")"
        if [ "$now" != "$want" ]; then
            log "ERROR: $path is ${now:-unreadable} after box-config sync, not $want"
            return 1
        fi
        return 0
    }
    enforce_root_file hcloud "$HCLOUD_BIN" 0755 || rc=1
    enforce_root_file "origin TLS key" "$ORIGIN_KEY" 0600 || rc=1

    # ── the retired `patched` login account (PAT-2312) ──
    # Last, so the manifest above has already deleted its sudoers grant. A
    # guard that does not hold fails the sync and names the reason.
    remove_retired_account "$RETIRED_ACCOUNT" "$RETIRED_ACCOUNT_UID" || rc=1

    return "$rc"
)

# remove_retired_account NAME UID (PAT-2312): remove a retired login account
# and its home, once it is provably safe to.
#
# Andy retired `patched` (uid 1001) on patched-prod-01 on 2026-09-30. Nobody
# used it by hand; agent sessions reached it only through a stale SSH config
# default and a tailnet ACL entry. It was in the sudo group with a
# passwordless grant, which deploy/removed-artifacts.txt deletes. Admin
# access to the box is root over Tailscale and nothing else.
#
# Nothing changes unless every guard holds. Each one that does not is logged
# as an ERROR naming the reason, and the function returns 1:
#   - the account's uid is UID, so it is the account this was written for;
#   - its home in the passwd database is $RETIRED_ACCOUNT_HOME, a directory
#     (not a symlink) that it owns, because userdel -r deletes whatever that
#     entry names;
#   - no process runs as it, by effective or real uid;
#   - it owns nothing on the filesystem of $RETIRED_ACCOUNT_SCAN_ROOT outside
#     its home and the tmp directories, since userdel leaves such files to
#     whichever account is next given the uid;
#   - every *.json under ~/.cloudflared has a byte-identical regular file of
#     the same name in $RETIRED_ACCOUNT_TUNNEL_DIR, so the home never takes
#     the only copy of a tunnel credential with it. On patched-prod-01 the
#     one it holds is the credential the running tunnel reads from
#     /etc/cloudflared (checked 2026-09-30). cert.pem, from `cloudflared
#     tunnel login`, is used by nothing and goes with the home.
#
# Then it deletes what the account owns in the tmp directories, runs
# `userdel -r`, removes the account's group if userdel left it, and proves
# the result before logging it: no passwd entry, no group, in no group's
# member list, no home, and nothing it owns left behind. The state is logged
# before and after.
#
# An account that is already gone is a logged no-op, unless its group, its
# home or a group membership survived a removal that did not finish, which
# fails loudly rather than passing unnoticed on every later deploy.
#
# find never follows a symlink (its default), and -xdev keeps every scan and
# delete on the filesystem it starts on. Like the manifest, this is
# one-directional: a rollback never recreates the account.
remove_retired_account() (
    local name="$1" uid="$2"
    local home="$RETIRED_ACCOUNT_HOME" scan_root="$RETIRED_ACCOUNT_SCAN_ROOT"
    local tunnel_dir="$RETIRED_ACCOUNT_TUNNEL_DIR"
    local -a tmp_dirs=()
    read -r -a tmp_dirs <<< "$RETIRED_ACCOUNT_TMP_DIRS"
    PATH="$RETIRED_ACCOUNT_PATH"
    local -a prune=(-path "$home")
    local dir
    for dir in "${tmp_dirs[@]}"; do
        prune+=(-o -path "$dir")
    done
    local entry group_entry member_of rc failed=0 left="" e_uid e_gid e_home
    if [ -z "$name" ] || [ -z "$uid" ] || [ -z "$home" ] || [ -z "$scan_root" ] || [ "${#tmp_dirs[@]}" -eq 0 ]; then
        log "ERROR: the retired-account step is missing its account name, uid, home, scan root or tmp directories; refusing to run it (PAT-2312)"
        return 1
    fi

    # log_paths LABEL LIST: one log line per path, at most 20.
    log_paths() {
        local path count=0
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            count=$((count + 1))
            if [ "$count" -le 20 ]; then log "  $1: $path"; fi
        done <<< "$2"
        if [ "$count" -gt 20 ]; then log "  ... and $((count - 20)) more"; fi
    }
    # groups_listing: the groups whose member list names the account, space
    # separated. Returns 1 if the group database cannot be read.
    groups_listing() {
        local db line group members out=""
        db="$(getent group)" || return 1
        while IFS= read -r line; do
            IFS=: read -r group _ _ members <<< "$line"
            case ",$members," in
                *",$name,"*) out="$out $group" ;;
            esac
        done <<< "$db"
        printf '%s' "${out# }"
    }
    # owned_outside: what UID owns on the scan root's filesystem outside the
    # home and the tmp directories. owned_under DIR: what it owns under DIR.
    owned_outside() {
        find "$scan_root" -xdev -mindepth 1 \( "${prune[@]}" \) -prune -o -uid "$uid" -print 2>> "$LOG"
    }
    owned_under() {
        find "$1" -xdev -mindepth 1 -uid "$uid" -print 2>> "$LOG"
    }

    if entry="$(getent passwd "$name")"; then rc=0; else rc=$?; fi
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
        log "ERROR: getent passwd $name exited $rc; cannot tell whether the retired account $name still exists (PAT-2312)"
        return 1
    fi

    # ── already gone: check nothing of it survived, change nothing ──
    if [ "$rc" -eq 2 ]; then
        if group_entry="$(getent group "$name")"; then
            left="$left, group $group_entry"
        else
            rc=$?
            if [ "$rc" -ne 2 ]; then
                log "ERROR: getent group $name exited $rc; cannot tell whether the retired account's group survived (PAT-2312)"
                return 1
            fi
        fi
        if [ -e "$home" ] || [ -L "$home" ]; then
            left="$left, home $home"
        fi
        if ! member_of="$(groups_listing)"; then
            log "ERROR: could not read the group database to check the retired account's memberships (PAT-2312)"
            return 1
        fi
        if [ -n "$member_of" ]; then
            left="$left, membership of $member_of"
        fi
        if [ -n "$left" ]; then
            log "ERROR: the retired account $name is gone but its ${left#, } survived. A removal did not finish; check what is left and remove it by hand (PAT-2312)"
            return 1
        fi
        log "Retired account $name already absent; nothing to remove"
        return 0
    fi

    # ── present: log it, then check every guard before changing anything ──
    IFS=: read -r _ _ e_uid e_gid _ e_home _ <<< "$entry"
    if ! member_of="$(groups_listing)"; then
        log "ERROR: could not read the group database to record the retired account's memberships (PAT-2312)"
        return 1
    fi
    log "Retired account $name is present: $entry${member_of:+ (member of $member_of)}"

    if [ "$e_uid" != "$uid" ]; then
        log "ERROR: refusing to remove $name: its uid is $e_uid, not $uid, so it is not the account PAT-2312 retired. Left in place."
        return 1
    fi

    if [ "$e_home" != "$home" ]; then
        log "ERROR: refusing to remove $name: its home is ${e_home:-empty}, not $home, and userdel -r deletes whatever the passwd entry names"
        failed=1
    elif [ -L "$home" ] || [ ! -d "$home" ]; then
        log "ERROR: refusing to remove $name: $home is not a directory (or is a symlink)"
        failed=1
    elif [ -z "$(find "$home" -maxdepth 0 -uid "$uid" -print 2>> "$LOG")" ]; then
        log "ERROR: refusing to remove $name: $home is not owned by uid $uid"
        failed=1
    fi

    local flag pids
    for flag in -u -U; do
        if pids="$(pgrep "$flag" "$uid")"; then
            log "ERROR: refusing to remove $name: process ${pids//$'\n'/ } runs as uid $uid (pgrep $flag)"
            failed=1
        else
            rc=$?
            if [ "$rc" -ne 1 ]; then
                log "ERROR: pgrep $flag $uid exited $rc; cannot prove that no process runs as $name"
                failed=1
            fi
        fi
    done

    local outside
    if outside="$(owned_outside)"; then
        if [ -n "$outside" ]; then
            log "ERROR: refusing to remove $name: it owns files outside $home and ${tmp_dirs[*]}, which userdel would leave to the next account given uid $uid:"
            log_paths "owned by $name" "$outside"
            failed=1
        fi
    else
        log "ERROR: find over $scan_root exited $?; cannot prove $name owns nothing outside its home and the tmp directories"
        failed=1
    fi

    local cloudflared="$home/.cloudflared" jsons json copy
    if [ -L "$cloudflared" ]; then
        log "ERROR: refusing to remove $name: $cloudflared is a symlink"
        failed=1
    elif [ -d "$cloudflared" ]; then
        if jsons="$(find "$cloudflared" -xdev -name '*.json' -print 2>> "$LOG")"; then
            while IFS= read -r json; do
                [ -n "$json" ] || continue
                copy="$tunnel_dir/${json##*/}"
                if [ -L "$json" ] || [ ! -f "$json" ]; then
                    log "ERROR: refusing to remove $name: $json is not a regular file"
                    failed=1
                elif [ -L "$copy" ] || [ ! -f "$copy" ]; then
                    log "ERROR: refusing to remove $name: $json has no regular-file copy at $copy, so deleting the home could lose the only copy of that tunnel credential"
                    failed=1
                elif ! cmp -s "$json" "$copy"; then
                    log "ERROR: refusing to remove $name: $json differs from $copy, so deleting the home could lose a tunnel credential"
                    failed=1
                else
                    log "Tunnel credential $json matches $copy byte for byte"
                fi
            done <<< "$jsons"
        else
            log "ERROR: find over $cloudflared exited $?; cannot check its tunnel credentials"
            failed=1
        fi
    fi

    if [ "$failed" -ne 0 ]; then
        log "Retired account $name left in place; resolve the above and deploy again (PAT-2312)"
        return 1
    fi

    # ── remove: tmp files, the account and its home, the group ──
    local owned
    for dir in "${tmp_dirs[@]}"; do
        [ -d "$dir" ] || continue
        if owned="$(owned_under "$dir")"; then
            [ -n "$owned" ] || continue
        else
            log "ERROR: find over $dir exited $?; cannot list what $name owns there"
            failed=1
            continue
        fi
        log "Deleting what $name owns under $dir:"
        log_paths deleting "$owned"
        # Checked below by listing again, not by find's exit status.
        find "$dir" -xdev -mindepth 1 -uid "$uid" -delete 2>> "$LOG"
        if ! owned="$(owned_under "$dir")" || [ -n "$owned" ]; then
            log "ERROR: could not delete everything $name owns under $dir"
            log_paths "still owned by $name" "$owned"
            failed=1
        fi
    done
    if [ "$failed" -ne 0 ]; then
        log "Retired account $name left in place; its tmp files could not all be removed (PAT-2312)"
        return 1
    fi

    log "Removing retired account $name: userdel -r $name, which deletes $home"
    if userdel -r "$name" >> "$LOG" 2>&1; then
        log "userdel -r $name done"
        if group_entry="$(getent group "$name")"; then
            local g_gid
            IFS=: read -r _ _ g_gid _ <<< "$group_entry"
            if [ "$g_gid" != "$e_gid" ]; then
                log "ERROR: group $name has gid $g_gid, not $name's primary gid $e_gid; leaving it for a human"
                failed=1
            elif groupdel "$name" >> "$LOG" 2>&1; then
                log "Removed group $name, which userdel left behind"
            else
                log "ERROR: groupdel $name exited $?"
                failed=1
            fi
        fi
    else
        log "ERROR: userdel -r $name exited $?"
        failed=1
    fi

    # ── prove it ──
    left=""
    if entry="$(getent passwd "$name")"; then
        left="$left, passwd entry $entry"
    else
        rc=$?
        [ "$rc" -eq 2 ] || left="$left, an unreadable passwd database (getent exited $rc)"
    fi
    if group_entry="$(getent group "$name")"; then
        left="$left, group $group_entry"
    else
        rc=$?
        [ "$rc" -eq 2 ] || left="$left, an unreadable group database (getent exited $rc)"
    fi
    if ! member_of="$(groups_listing)"; then
        left="$left, an unreadable group database"
    elif [ -n "$member_of" ]; then
        left="$left, membership of $member_of"
    fi
    if [ -e "$home" ] || [ -L "$home" ]; then
        left="$left, home $home"
    fi
    if ! owned="$(owned_outside)"; then
        left="$left, an incomplete scan of $scan_root"
    elif [ -n "$owned" ]; then
        left="$left, files owned by uid $uid (listed below)"
    fi
    local stray="$owned"
    for dir in "${tmp_dirs[@]}"; do
        [ -d "$dir" ] || continue
        if ! owned="$(owned_under "$dir")"; then
            left="$left, an incomplete scan of $dir"
        elif [ -n "$owned" ]; then
            left="$left, files owned by uid $uid under $dir (listed below)"
            stray="$stray"$'\n'"$owned"
        fi
    done
    if [ -n "$left" ]; then
        log "ERROR: after removing $name, still there: ${left#, } (PAT-2312)"
        log_paths "owned by uid $uid" "$stray"
        return 1
    fi
    log "Retired account $name removed: no passwd entry, no group, in no group's member list, no $home, and nothing owned by uid $uid on $scan_root or in ${tmp_dirs[*]}"
    return "$failed"
)

# rollback REASON — resets the checkout to $PREVIOUS_COMMIT, reinstalls its
# requirements, resyncs box config to match it, and restarts the service.
# Returns 0 on a clean rollback, 2 if the .no-auto-rollback marker is
# present (nothing done), 3 if the rollback itself failed critically
# (service may be down).
rollback() {
    local reason="$1"
    if [ "$SKIP_AUTO_ROLLBACK" -eq 1 ]; then
        log "Auto-rollback skipped (.no-auto-rollback marker). Reason: $reason."
        log "Service/checkout left on $NEW_COMMIT. Manual intervention required."
        return 2
    fi
    log "Rolling back to $PREVIOUS_COMMIT (reason: $reason)..."
    if ! git reset --hard "$PREVIOUS_COMMIT" >> "$LOG" 2>&1; then
        log "CRITICAL: git reset --hard $PREVIOUS_COMMIT failed during rollback."
        return 3
    fi
    # PAT-2307: the rolled-back tree stays root's. The code from before
    # PAT-2307 runs on it too; only its report and NVD-cache writes, which
    # it made inside the tree, fail until the next forward deploy. What
    # this must never do is run pip, the box-config sync or the restart
    # from a tree the service user may be able to write.
    if ! lock_code_tree; then
        log "CRITICAL: could not lock the code tree after resetting to $PREVIOUS_COMMIT. Refusing to install requirements, sync box config or restart from it. The checkout is on $PREVIOUS_COMMIT; the service was not restarted by the rollback."
        return 3
    fi
    if ! install_requirements; then
        log "WARN: requirements re-install for rollback target $PREVIOUS_COMMIT failed. Restarting anyway."
    fi
    # Sync box config back to whatever $PREVIOUS_COMMIT ships, in the same
    # order (before restart) and for the same reason as the forward path —
    # see sync_box_config's header comment. A sync failure here doesn't
    # abort the rollback (there's nowhere further back to fall to); log it
    # CRITICAL and restart anyway, same posture as the requirements
    # re-install failure immediately above.
    if ! DEPLOY_ROLLBACK_SYNC=1 sync_box_config; then
        log "CRITICAL: box config sync failed while rolling back to $PREVIOUS_COMMIT. Restarting anyway; live config may not match $PREVIOUS_COMMIT."
    fi
    if ! restart_service; then
        log "CRITICAL: rollback restart failed. Service is down on $PREVIOUS_COMMIT."
        return 3
    fi
    log "Rolled back. Service is on $PREVIOUS_COMMIT (pre-deploy state)."
    # PAT-992: the service is now confirmed (systemctl is-active) running
    # PREVIOUS_COMMIT, not NEW_COMMIT — record what is actually running
    # after the rollback, not what the deploy attempted. This is the
    # ordering case the ticket exists for: get this backwards and every
    # rollback leaves DEPLOYED_SHA asserting the bad commit that was just
    # reverted away from.
    write_deployed_sha "$PREVIOUS_COMMIT"
    return 0
}

# ── Pre-flight ──
# PAT-2312: the retired-account overrides belong to the dry run. A run
# without DEPLOY_ALLOW_NONROOT that sets any of them is refused before
# anything happens, rather than quietly removing the account named above.
if [ -z "${DEPLOY_ALLOW_NONROOT:-}" ] && [ -n "${!DEPLOY_RETIRED_*}" ]; then
    echo "ERROR: ${!DEPLOY_RETIRED_*} set without DEPLOY_ALLOW_NONROOT. These are for the dry run only; a real deploy removes only the account named in scripts/deploy.sh (PAT-2312). Nothing was deployed." >&2
    exit 1
fi
if [ "$EUID" -ne 0 ] && [ -z "${DEPLOY_ALLOW_NONROOT:-}" ]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi
if [ ! -d "$REPO_DIR/.git" ]; then
    log "ERROR: $REPO_DIR is not a git checkout"
    exit 1
fi
touch "$LOG" 2>/dev/null
chmod 0644 "$LOG" 2>/dev/null

log "─────────────────────────────────────────────────────"
if [ -n "$FROM_HOOK" ]; then
    log "Deploy invoked by post-receive hook (target $FROM_HOOK, rollback $ROLLBACK_TO)"
else
    log "Deploy invoked by ${SUDO_USER:-unknown} (standalone)"
fi

# ── Code tree guard (PAT-2307), before anything runs from the tree ──
# Take a private copy of the guard first: rollback() resets the checkout to
# the previous commit, which may predate the guard, and must still be able
# to lock the tree. The copy is made before the check, so it is the version
# this deploy started from, the same way this script itself is.
if [ -L "$CODE_TREE_GUARD_SRC" ] || [ ! -f "$CODE_TREE_GUARD_SRC" ]; then
    log "ERROR: $CODE_TREE_GUARD_SRC is missing or not a regular file. Refusing to deploy without the code tree guard."
    exit 1
fi
CODE_TREE_GUARD="$(mktemp)" || { log "ERROR: could not create a private copy of the code tree guard"; exit 1; }
trap 'rm -f "$CODE_TREE_GUARD"' EXIT
if ! cp "$CODE_TREE_GUARD_SRC" "$CODE_TREE_GUARD"; then
    log "ERROR: could not copy $CODE_TREE_GUARD_SRC. Nothing was deployed."
    exit 1
fi
log "Checking that nothing under $REPO_DIR or $MIRROR_DIR is writable by a non-root user..."
if ! code_tree_guard check; then
    log "ERROR: the code tree failed the guard above. Nothing was deployed and nothing was run from it. If the box has not yet moved to a root-owned tree, or a hand edit re-granted the service user, dispatch deploy.yml with adopt_code_tree=true once (PAT-2307)."
    exit 1
fi

# ── Capture pre-deploy state ──
cd "$REPO_DIR" || { log "ERROR: cannot cd to $REPO_DIR"; exit 1; }
ACTUAL_HEAD=$(git rev-parse HEAD 2>/dev/null)
if [ -z "$ACTUAL_HEAD" ]; then
    log "ERROR: cannot read HEAD commit"
    exit 1
fi

if [ -n "$FROM_HOOK" ]; then
    PREVIOUS_COMMIT="$ROLLBACK_TO"
    if [ "$ACTUAL_HEAD" != "$PREVIOUS_COMMIT" ]; then
        log "WARN: checkout HEAD ($ACTUAL_HEAD) does not match the hook's rollback target ($PREVIOUS_COMMIT). Trusting the hook, which read the ref immediately before this push landed. If this keeps happening, something outside the hook is moving the checkout."
    fi
else
    PREVIOUS_COMMIT="$ACTUAL_HEAD"
fi
log "Current commit: $PREVIOUS_COMMIT"

# Check for auto-rollback opt-out marker
SKIP_AUTO_ROLLBACK=0
if [ -f "$NO_AUTO_ROLLBACK_MARKER" ]; then
    log "NOTE: .no-auto-rollback marker present. Will NOT auto-rollback on failure."
    SKIP_AUTO_ROLLBACK=1
fi

# ── Get the new commit into the checkout ──
if [ -n "$FROM_HOOK" ]; then
    log "Fetching + resetting to $FROM_HOOK..."
    if ! git fetch origin >> "$LOG" 2>&1; then
        log "ERROR: git fetch failed"
        exit 1
    fi
    if ! git reset --hard "$FROM_HOOK" >> "$LOG" 2>&1; then
        log "ERROR: git reset --hard $FROM_HOOK failed"
        exit 1
    fi
    NEW_COMMIT=$(git rev-parse HEAD)
    if [ "$NEW_COMMIT" != "$FROM_HOOK" ]; then
        log "ERROR: post-reset HEAD ($NEW_COMMIT) does not match requested $FROM_HOOK"
        exit 1
    fi
else
    log "Pulling from origin/main..."
    if ! git pull --ff-only origin main >> "$LOG" 2>&1; then
        log "ERROR: git pull failed"
        exit 1
    fi
    NEW_COMMIT=$(git rev-parse HEAD)
fi

# ── Keep the code tree root's (PAT-2307) ──
# Straight after the reset and before the box-config sync, which installs
# units and polkit rules out of deploy/ as root. Root's git already writes
# root-owned files under umask 022; this also catches anything else, and
# the check that follows is what proves it. Runs on the no-op path too, for
# the same reason the sync does (PAT-1441): drift needs no commit.
log "Locking the code tree (root-owned, no group or other write)..."
if ! lock_code_tree; then
    log "ERROR: could not lock the code tree"
    if [ "$NEW_COMMIT" = "$PREVIOUS_COMMIT" ]; then
        log "Deploy aborted (code tree lock failed on an otherwise no-op run)."
        exit 1
    fi
    rollback "code tree lock failed"
    RC=$?
    [ "$RC" -eq 0 ] && { log "Deploy aborted."; exit 1; }
    exit "$RC"
fi

# ── Sync box-side config (PAT-986), BEFORE the no-op guard (PAT-1441) ──
# "No new commits" is a fact about the CHECKOUT. sync_box_config answers a
# different question -- does this box's systemd/polkit config match what the
# repo says it should be -- and the two are independent. Box config drifts
# with no commit involved at all: a hand-edited unit, a `systemctl edit`, a
# half-finished manual fix, a restored snapshot. Gating the one function
# written to catch that on "did the checkout move" guaranteed it never ran
# in precisely the situation where nothing else would catch it either.
#
# This bit for real on 2026-08-19. PAT-1439 shipped a hardened
# patched-maintenance-facts.service; the deploy reported success and the box
# stayed 9.6 UNSAFE. Two things compounded: the post-receive hook execs this
# script and the `git reset` to the new commit happens INSIDE it, so the
# RUNNING script is always the previous version and any change here lands one
# deploy late; and re-running the deploy to pick it up hit the guard below and
# exited before sync_box_config could run. The change could then only ever
# land on some later, unrelated commit. Both runs were green throughout.
#
# Running it here costs nothing when there is nothing to do -- it is
# idempotent and says so, logging "unchanged; skipping install and
# daemon-reload" -- and it makes the one-deploy lag recoverable instead of
# permanent, because a second deploy now actually reconciles the box.
log "Syncing box-side config (systemd unit, polkit rules, removed artefacts)..."
if ! sync_box_config; then
    log "ERROR: box config sync failed"
    if [ "$NEW_COMMIT" = "$PREVIOUS_COMMIT" ]; then
        # Nothing was deployed, so there is nothing to roll back to -- the
        # checkout is already where it was. Fail loudly rather than calling
        # rollback(), which would restart the service to "recover" from a
        # deploy that never happened.
        log "Deploy aborted (box config sync failed on an otherwise no-op run)."
        exit 1
    fi
    rollback "box config sync failed"
    RC=$?
    [ "$RC" -eq 0 ] && { log "Deploy aborted."; exit 1; }
    exit "$RC"
fi

if [ "$NEW_COMMIT" = "$PREVIOUS_COMMIT" ]; then
    log "No new commits. Deploy is a no-op (box-side config was still reconciled above). Exiting."
    # PAT-992 (independent review, FIX 1): deliberately NOT writing
    # DEPLOYED_SHA here, even though it's tempting to bootstrap a first
    # record on a quiet box. This path confirms nothing — no restart, no
    # smoke test — it only means "the checkout already matched". If the
    # currently-checked-out commit got there via a smoke failure on the
    # .no-auto-rollback path, it is a KNOWN-BAD commit, and a later no-op
    # run would otherwise overwrite a still-accurate previous record (or
    # write the first-ever record) asserting that bad commit as confirmed
    # — exactly the "confident wrong answer" this ticket exists to end.
    # Only a path that actually verified the running service (a passed
    # smoke suite, or a completed rollback restart) may write this file.
    exit 0
fi
log "Deploying: $PREVIOUS_COMMIT -> $NEW_COMMIT"

# PAT-2307: no `chown -R www-data` here any more. The tree was locked to
# root straight after the reset, above, and stays that way.

# ── Install dependencies ──
if ! install_requirements; then
    log "ERROR: requirements install failed for $NEW_COMMIT"
    rollback "requirements install failed"
    RC=$?
    [ "$RC" -eq 0 ] && { log "Deploy aborted."; exit 1; }
    exit "$RC"
fi

# ── Box-side config already synced above (PAT-1441) ──
# It now runs before the no-op guard so it reconciles the box on every
# invocation, not only when the checkout moved. It still happens after the
# checkout is at the target commit and before the restart below, which is
# the ordering sync_box_config's own header comment requires: the restart
# must come up onto config that is already in place.
log "Box-side config sync complete."

# ── Restart service ──
log "Restarting $SERVICE..."
if ! restart_service; then
    log "ERROR: service failed to come up after restart"
    rollback "service failed to come up after restart"
    RC=$?
    [ "$RC" -eq 0 ] && { log "Deploy aborted."; exit 1; }
    exit "$RC"
fi
log "Service active on new commit."

# ── Smoke suite ──
if [ ! -f "$SMOKE_RUNNER" ]; then
    log "WARN: smoke runner not found at $SMOKE_RUNNER. Skipping."
    # PAT-992: restart_service above already confirmed the service is
    # active on NEW_COMMIT; smoke being absent doesn't change that.
    write_deployed_sha "$NEW_COMMIT"
    log "Deploy successful: $PREVIOUS_COMMIT -> $NEW_COMMIT (smoke skipped)"
    exit 0
fi
if [ ! -x "$PYTHON" ]; then
    log "WARN: venv python not found at $PYTHON. Falling back to system python3."
    PYTHON=python3
fi

read_environment_file_value() {
    # systemd EnvironmentFile syntax is deliberately not shell syntax. Read
    # just the named setting without evaluating any of the file's contents.
    local name="$1" value=""
    if [ -f "$ENV_FILE" ]; then
        value=$(grep -E "^${name}=" "$ENV_FILE" | tail -1 | cut -d= -f2-)
        # Strip one layer of surrounding quotes if present (systemd allows both).
        value="${value#\"}"; value="${value%\"}"
        value="${value#\'}"; value="${value%\'}"
    fi
    printf '%s' "$value"
}

# The dashboard_core and email smoke modules need DASHBOARD_API_KEY to
# exercise the Bearer-auth path. The hook runs in a bare SSH push
# environment that doesn't have it. Read it from the service's
# EnvironmentFile (targeted parsing, not a blind source — systemd env files
# aren't guaranteed shell-safe) and export it for the smoke runner.
# (PAT-866: SMOKE_TEST_TOKEN was only ever needed by the public_scan smoke
# module, removed along with the funnel it tested — now scan.patched.im,
# portal repo.)
if [ -z "${DASHBOARD_API_KEY:-}" ] && [ -f "$ENV_FILE" ]; then
    DASHBOARD_API_KEY="$(read_environment_file_value DASHBOARD_API_KEY)"
    export DASHBOARD_API_KEY
fi
if [ -z "${DASHBOARD_API_KEY:-}" ]; then
    log "WARN: DASHBOARD_API_KEY not found in environment or $ENV_FILE; Bearer-auth smoke checks will fail."
fi

# PAT-994 relocated dashboard.db out of the checkout. The smoke runner is a
# separate process from systemd, so it must receive the same configured path
# explicitly. Retain the canonical production location as a safe fallback for
# the relocation-era deployment path, but never source the EnvironmentFile.
if [ -z "${DASHBOARD_DB_PATH:-}" ]; then
    DASHBOARD_DB_PATH="$(read_environment_file_value DASHBOARD_DB_PATH)"
fi
DASHBOARD_DB_PATH="${DASHBOARD_DB_PATH:-/var/lib/patched-dashboard/dashboard.db}"
log "Running smoke suite..."
if "$PYTHON" "$SMOKE_RUNNER" --db "$DASHBOARD_DB_PATH" >> "$LOG" 2>&1; then
    log "Smoke suite PASSED."
    # PAT-992: last step of a successful deploy, by design — write only
    # after the restart AND the smoke suite have both confirmed the new
    # commit is actually serving, not merely checked out.
    write_deployed_sha "$NEW_COMMIT"
    log "Deploy SUCCESSFUL: $PREVIOUS_COMMIT -> $NEW_COMMIT"
    exit 0
fi

# Smoke suite failed — extract the failing module names from the log for the error line
FAILED_MODULES=$(grep '^FAILED:' "$LOG" | tail -1 | sed 's/^FAILED: //')
log "ERROR: smoke suite FAILED on $NEW_COMMIT. Failing modules: ${FAILED_MODULES:-see log}"
rollback "smoke suite failed"
RC=$?
if [ "$RC" -eq 0 ]; then
    log "Deploy aborted."
    exit 2
fi
exit "$RC"
