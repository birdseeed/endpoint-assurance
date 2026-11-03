#!/usr/bin/env bash
# PAT-2305: install deploy/nginx-dashboard.conf as the live dashboard site
# config, and keep it only if nginx accepts it.
#
# Called by the "Verify deployed revision and refresh nginx config" step of
# .github/workflows/deploy.yml, on patched-prod-01, as root, after that step
# has confirmed the checkout is on the requested commit.
#
# Why this exists: that step used to run
#     cp <repo conf> <live conf>
#     nginx -t && systemctl reload nginx
# which overwrote the live file before testing it, and under `set -e` a
# failure on the left of `&&` does not exit. A config nginx rejected was left
# live, the step exited 0, and the next nginx restart or reboot would have
# taken dashboard.patched.im down.
#
# What it does now:
#   1. copies the current live file to a private backup under /var/tmp. Never
#      under /etc/nginx, where an include glob could load it, and never under
#      /etc/patched-*, where PAT-1408's stray-config-backup check looks;
#   2. copies the repo file over the live file;
#   3. runs `nginx -t`, which tests the full live configuration with the new
#      file in place, exactly as the next reload or restart would load it;
#   4. if nginx rejects it, puts the previous file back byte for byte (or
#      removes the new one on a first install), prints an ::error:: line and
#      exits 1. nginx is not reloaded;
#   5. if nginx accepts it, reloads nginx and removes the backup.
# An EXIT/HUP/INT/TERM trap restores the previous file if the script stops
# for any other reason between steps 2 and 4, for example the SSH session
# dropping mid-deploy.
#
# Every failure path is an explicit `if ! cmd; then ... fi`. Nothing relies
# on `set -e` to stop it, and no command is chained with `&&`
# (tests/test_pat2305_nginx_install.py checks both).
#
# Exit codes:
#   0  new config installed, accepted by nginx -t, and nginx reloaded
#   1  nothing was changed, or the previous config was restored
#   2  nginx -t accepted the new config but the reload failed. The new,
#      tested config stays on disk; the running nginx may still be serving
#      the previous one. The previous file is kept and its path printed
#   3  critical: the previous config could not be restored. The backup path
#      is printed; nginx was not reloaded
#
# Env overrides (test harness only; the defaults are the live box):
#   NGINX_SITE_SOURCE, NGINX_SITE_TARGET, NGINX_SITE_BACKUP_DIR,
#   NGINX_CMD, SYSTEMCTL_CMD

set -euo pipefail

SOURCE="${NGINX_SITE_SOURCE:-/opt/patched-dashboard/deploy/nginx-dashboard.conf}"
TARGET="${NGINX_SITE_TARGET:-/etc/nginx/sites-available/dashboard.patched.im}"
BACKUP_DIR="${NGINX_SITE_BACKUP_DIR:-/var/tmp}"
NGINX="${NGINX_CMD:-nginx}"
SYSTEMCTL="${SYSTEMCTL_CMD:-systemctl}"

had_previous=0
backup=""
# prepare: the live file has not been touched.
# installed: the live file may hold the new, untested config.
# settled: the live file is either tested or restored; the trap does nothing.
state=prepare

err() {
    echo "::error::install-nginx-config: $*" >&2
}

info() {
    echo "install-nginx-config: $*"
}

# drop_backup: remove the backup file, if there is one. A failure here is a
# warning, never a reason to stop before the real outcome has been printed.
drop_backup() {
    if [ -z "$backup" ]; then
        return 0
    fi
    if ! rm -f "$backup"; then
        echo "::warning::install-nginx-config: could not remove the backup at $backup." >&2
    fi
    return 0
}

# restore_previous: put the live file back to what it was before this run.
# Returns non-zero unless it can show that it did. This runs inside `if`
# conditions, where `set -e` is off, so every step is checked by hand.
restore_previous() {
    if [ "$had_previous" = 1 ]; then
        if ! cp "$backup" "$TARGET"; then
            return 1
        fi
        if ! cmp -s "$backup" "$TARGET"; then
            return 1
        fi
        return 0
    fi
    if ! rm -f "$TARGET"; then
        return 1
    fi
    if [ -e "$TARGET" ]; then
        return 1
    fi
    if [ -L "$TARGET" ]; then
        return 1
    fi
    return 0
}

# roll_back MESSAGE: restore the previous file after the new one went live
# and was not accepted. Exits 1 if the restore is proven, 3 if not.
roll_back() {
    state=settled
    if restore_previous; then
        drop_backup
        err "$1. The previous $TARGET has been restored and nginx was not reloaded."
        exit 1
    fi
    if [ -n "$backup" ]; then
        err "$1. CRITICAL: could not restore the previous $TARGET; it is saved at $backup. nginx was not reloaded. Copy it back and run nginx -t before any nginx restart."
    else
        err "$1. CRITICAL: could not remove the new $TARGET, which nginx did not accept. nginx was not reloaded. Remove it and run nginx -t before any nginx restart."
    fi
    exit 3
}

# Invoked by the EXIT trap below, which shellcheck cannot see.
# shellcheck disable=SC2317,SC2329
on_exit() {
    local rc=$?
    if [ "$state" = installed ]; then
        if [ "$rc" = 0 ]; then
            rc=1
        fi
        # roll_back always exits; this only chooses the message.
        roll_back "stopped (exit $rc) before nginx accepted the new config"
    fi
    exit "$rc"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# --- Preconditions: nothing below this block runs unless all of them hold.
if [ -L "$SOURCE" ]; then
    err "$SOURCE is a symlink; refusing to install it. The live nginx config is unchanged."
    exit 1
fi
if [ ! -f "$SOURCE" ]; then
    err "$SOURCE is missing or not a regular file. The live nginx config is unchanged."
    exit 1
fi
# The live file is a regular file, symlinked from sites-enabled/
# (docs/OPERATIONS.md). Anything else is unexpected, and writing through a
# symlink would change a file this script cannot put back.
if [ -L "$TARGET" ]; then
    err "$TARGET is a symlink; refusing to write through it. The live nginx config is unchanged."
    exit 1
fi
if [ -e "$TARGET" ]; then
    if [ ! -f "$TARGET" ]; then
        err "$TARGET exists but is not a regular file. The live nginx config is unchanged."
        exit 1
    fi
    had_previous=1
fi

# --- 1. Back up the live file, and prove the backup matches it.
if [ "$had_previous" = 1 ]; then
    if ! backup="$(mktemp "$BACKUP_DIR/patched-dashboard-nginx-site.XXXXXX")"; then
        err "could not create a backup file in $BACKUP_DIR. The live nginx config is unchanged."
        exit 1
    fi
    if ! cp "$TARGET" "$backup"; then
        drop_backup
        err "could not copy $TARGET to $backup. The live nginx config is unchanged."
        exit 1
    fi
    if ! cmp -s "$TARGET" "$backup"; then
        drop_backup
        err "the backup at $backup does not match $TARGET. The live nginx config is unchanged."
        exit 1
    fi
    info "previous $TARGET saved to $backup"
else
    info "no existing $TARGET; this is a first install"
fi

# --- 2. Put the new file in place.
state=installed
if ! cp "$SOURCE" "$TARGET"; then
    roll_back "could not copy $SOURCE to $TARGET"
fi
if ! cmp -s "$SOURCE" "$TARGET"; then
    roll_back "$TARGET does not match $SOURCE after copying"
fi

# --- 3 and 4. Test the full configuration with the new file live.
info "testing the nginx configuration with the new $TARGET"
# Deliberately not wrapped in coreutils `timeout`: with `timeout` as the
# foreground child, a TERM/INT delivered to this script while the test runs is
# dropped by bash (the trapped signal only fires if that child itself died of
# it), so the interruption restore below would silently not happen
# (test_termination_before_the_test_finishes_restores_the_previous_file caught
# this on Linux CI). The deploy step's SSH session already bounds the run.
if ! "$NGINX" -t; then
    roll_back "nginx -t rejected $SOURCE"
fi
state=settled

# --- 5. Reload, then drop the backup.
if ! "$SYSTEMCTL" reload nginx; then
    if [ -n "$backup" ]; then
        err "nginx -t accepted the new $TARGET but 'systemctl reload nginx' failed. The new config stays on disk; the running nginx may still be serving the previous one, which is saved at $backup."
    else
        err "nginx -t accepted the new $TARGET but 'systemctl reload nginx' failed. The new config stays on disk; the running nginx has not loaded it."
    fi
    exit 2
fi

drop_backup
info "installed $SOURCE as $TARGET and reloaded nginx"
exit 0
