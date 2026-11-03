#!/bin/bash
# PAT-909 — dry-run test for deploy/post-receive + scripts/deploy.sh's
# hook-mode rollback logic, against a scratch git topology (no box, no
# systemd, no real service). Repeatable: run it any time to re-verify the
# rollback mechanics after touching either script.
#
# Topology built under a scratch dir (mirrors production):
#   mirror.git   — bare repo, stands in for /opt/git/dashboard.git
#   checkout/    — clone of mirror.git, stands in for /opt/patched-dashboard
#   src/         — a normal working repo used to push new commits to
#                  mirror.git, stands in for "GitHub Actions / a manual push"
#
# What it proves:
#   1. Forward path — a push whose smoke check passes lands cleanly: the
#      hook exits 0 and checkout HEAD moves to the new commit.
#   2. Rollback path — a push whose smoke check fails is rolled back: the
#      hook exits non-zero (2, per scripts/deploy.sh's documented exit
#      codes — smoke failed and was rolled back) and checkout HEAD ends
#      back at the PREVIOUS commit, not the bad one.
#   3. (PAT-2307) Every deploy and rollback leaves the checkout and mirror
#      with no group- or other-writable path and DEPLOYED_SHA at 0644, and a
#      writable file in the tree stops the deploy before anything runs from
#      it (Tests 11 and 12). The tree's "root" owner is the invoking user
#      here, via DEPLOY_CODE_OWNER.
#   4. (PAT-2312) Every deploy handles the retired `patched` account: absent
#      is a no-op, a failing guard fails the deploy and changes nothing, and
#      a clean removal takes the account, its home and its tmp files (Test
#      14). The account is a scratch one behind shimmed getent, pgrep,
#      userdel and groupdel.
#
# systemctl and pip are stubbed (no real service on a dev machine); the
# git reset/rollback logic under test is real, unmodified scripts/deploy.sh
# and deploy/post-receive from this checkout.
#
# Usage: scripts/test-post-receive-rollback.sh
# Exit codes: 0 = both assertions passed, 1 = a check failed.

set -u
# PAT-2311: this runs in CI as well as on a Mac, so nothing may depend on the
# invoking environment. The code tree guard fails on any group-writable path
# in the scratch mirror and checkout, which an inherited umask of 002 (the
# Ubuntu default for a user with its own group) would create, so pin the
# box's 022. The scratch repositories' branch is pinned below for the same
# reason: a git with no init.defaultBranch (a GitHub runner; macOS's Xcode git
# sets main system-wide) would leave the mirror's HEAD on an unborn master.
umask 022
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POST_RECEIVE="$REPO_ROOT/deploy/post-receive"
DEPLOY_SH="$REPO_ROOT/scripts/deploy.sh"
HARDENING_GUARD="$REPO_ROOT/deploy/verify-systemd-hardening-floor.sh"
CODE_TREE_GUARD="$REPO_ROOT/deploy/code-tree-guard.sh"

FAILURES=0

step() { printf '\n=== %s ===\n' "$1"; }
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf '  PASS: %s (%s)\n' "$desc" "$actual"
    else
        printf '  FAIL: %s (expected %s, got %s)\n' "$desc" "$expected" "$actual"
        FAILURES=$((FAILURES + 1))
    fi
}
assert_ne() {
    local desc="$1" not_expected="$2" actual="$3"
    if [ "$not_expected" != "$actual" ]; then
        printf '  PASS: %s (got %s, != %s)\n' "$desc" "$actual" "$not_expected"
    else
        printf '  FAIL: %s (got %s, expected anything else)\n' "$desc" "$actual"
        FAILURES=$((FAILURES + 1))
    fi
}
assert_log_contains() {
    local desc="$1" needle="$2"
    if grep -q "$needle" "$DEPLOY_LOG"; then
        printf '  PASS: %s\n' "$desc"
    else
        printf '  FAIL: %s (%q not found in %s)\n' "$desc" "$needle" "$DEPLOY_LOG"
        FAILURES=$((FAILURES + 1))
    fi
}
assert_log_not_contains() {
    local desc="$1" needle="$2"
    if grep -q "$needle" "$DEPLOY_LOG"; then
        printf '  FAIL: %s (%q unexpectedly found in %s)\n' "$desc" "$needle" "$DEPLOY_LOG"
        FAILURES=$((FAILURES + 1))
    else
        printf '  PASS: %s\n' "$desc"
    fi
}

if [ ! -x "$POST_RECEIVE" ]; then
    echo "ERROR: $POST_RECEIVE not found or not executable" >&2
    exit 1
fi
if [ ! -x "$DEPLOY_SH" ]; then
    echo "ERROR: $DEPLOY_SH not found or not executable" >&2
    exit 1
fi
if [ ! -x "$HARDENING_GUARD" ]; then
    echo "ERROR: $HARDENING_GUARD not found or not executable" >&2
    exit 1
fi
if [ ! -x "$CODE_TREE_GUARD" ]; then
    echo "ERROR: $CODE_TREE_GUARD not found or not executable" >&2
    exit 1
fi

REAL_MKTEMP="$(command -v mktemp)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

MIRROR="$WORKDIR/mirror.git"
CHECKOUT="$WORKDIR/checkout"
SRC="$WORKDIR/src"
FAKE_BIN="$WORKDIR/bin"
DEPLOY_LOG="$WORKDIR/deploy.log"
# PAT-986 — scratch stand-ins for /etc/systemd/system and
# /etc/polkit-1/rules.d, so the box-config sync exercised below never
# touches the real filesystem.
FAKE_SYSTEMD_DIR="$WORKDIR/etc/systemd/system"
FAKE_POLKIT_DIR="$WORKDIR/etc/polkit-1/rules.d"
# PAT-1439/1438 — every invocation this fake systemctl receives is appended
# here (one line, "$*"), so a test can assert not just that the deploy
# succeeded but that a SPECIFIC systemctl call did or didn't happen —
# e.g. that daemon-reload actually ran, and that the oneshot
# patched-maintenance-facts.service was never directly restarted.
SYSTEMCTL_CALLS="$WORKDIR/systemctl-calls.log"
# PAT-2312: sync_box_config enforces root ownership on the hcloud binary
# and the origin TLS key. Exported once, so every deploy below uses these
# scratch paths and none can reach a real /usr/local/bin/hcloud or /etc/ssl
# on the machine running the dry run.
export DEPLOY_HCLOUD_BIN="$WORKDIR/usr/local/bin/hcloud"
export DEPLOY_ORIGIN_KEY="$WORKDIR/etc/ssl/dashboard.patched.im.key"
# PAT-2312: sync_box_config removes the retired `patched` account. Every
# setting points at scratch, and getent, pgrep, userdel and groupdel (below)
# are shims over a scratch passwd, group and process list, so no deploy in
# this dry run can read or change an account on the machine running it. The
# scan root holds only the directories the step prunes: everything the dry
# run creates is the invoking user's, which is also the scratch account's uid.
RETIRED_ROOT="$WORKDIR/retired-root"
RETIRED_UID="$(id -u)"
export DEPLOY_RETIRED_ACCOUNT="pat2312-dryrun"
export DEPLOY_RETIRED_ACCOUNT_UID="$RETIRED_UID"
export DEPLOY_RETIRED_ACCOUNT_HOME="$RETIRED_ROOT/home-patched"
export DEPLOY_RETIRED_ACCOUNT_TMP_DIRS="$RETIRED_ROOT/tmp $RETIRED_ROOT/var-tmp"
export DEPLOY_RETIRED_ACCOUNT_SCAN_ROOT="$RETIRED_ROOT"
export DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR="$WORKDIR/retired-etc-cloudflared"
export RETIRED_FAKE_DB="$WORKDIR/retired-db"
export RETIRED_FAKE_PROCS="$WORKDIR/retired-procs"
mkdir -p "$RETIRED_ROOT/tmp" "$RETIRED_ROOT/var-tmp" "$DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR" "$RETIRED_FAKE_DB"
: > "$RETIRED_FAKE_DB/passwd"
: > "$RETIRED_FAKE_DB/group"
: > "$RETIRED_FAKE_PROCS"

mkdir -p "$FAKE_BIN"

# PAT-2312: the account shims. getent answers from the scratch passwd and
# group (exit 2 for a key that is not there, as the real one does); pgrep
# from lines of "FLAG UID PID"; userdel -r drops the entry, the user's group
# and memberships, and the home; groupdel drops a group.
cat > "$FAKE_BIN/getent" <<'EOF'
#!/bin/bash
db="$RETIRED_FAKE_DB/$1"
[ -f "$db" ] || exit 1
if [ $# -lt 2 ]; then cat "$db"; exit 0; fi
line="$(awk -F: -v k="$2" '$1 == k { print; exit }' "$db")"
[ -n "$line" ] || exit 2
printf '%s\n' "$line"
EOF
cat > "$FAKE_BIN/pgrep" <<'EOF'
#!/bin/bash
found="$(awk -v f="$1" -v u="$2" '$1 == f && $2 == u { print $3 }' "$RETIRED_FAKE_PROCS")"
[ -n "$found" ] || exit 1
printf '%s\n' "$found"
EOF
cat > "$FAKE_BIN/userdel" <<'EOF'
#!/bin/bash
{ [ "$1" = -r ] && [ $# -eq 2 ]; } || exit 2
name="$2" db="$RETIRED_FAKE_DB"
home="$(awk -F: -v n="$name" '$1 == n { print $6 }' "$db/passwd")"
[ -n "$home" ] || exit 6
awk -F: -v n="$name" '$1 != n' "$db/passwd" > "$db/passwd.new" && mv "$db/passwd.new" "$db/passwd"
awk -F: -v OFS=: -v n="$name" '$1 == n { next } { m = "," $4 ","; gsub("," n ",", ",", m); gsub(/^,+|,+$/, "", m); $4 = m; print }' \
    "$db/group" > "$db/group.new" && mv "$db/group.new" "$db/group"
rm -rf "$home"
EOF
cat > "$FAKE_BIN/groupdel" <<'EOF'
#!/bin/bash
db="$RETIRED_FAKE_DB"
awk -F: -v n="$1" '$1 != n' "$db/group" > "$db/group.new" && mv "$db/group.new" "$db/group"
EOF
chmod +x "$FAKE_BIN/getent" "$FAKE_BIN/pgrep" "$FAKE_BIN/userdel" "$FAKE_BIN/groupdel"

# ── Fake systemctl: no real service to restart/probe on a dev machine.
# restart and is-active both succeed unconditionally — the thing under test
# is the git reset/rollback logic, not systemd.
cat > "$FAKE_BIN/systemctl" <<EOF
#!/bin/bash
echo "\$*" >> "$SYSTEMCTL_CALLS"
# PAT-1439: sync_box_config now asserts the maintenance-facts .service
# actually LOADS after daemon-reload, not merely that its timer is enabled
# -- \`enable --now <timer>\` succeeds even when the .service it fires failed
# to parse. That check reads \`systemctl show -p LoadState --value\`, so this
# stub has to answer it; a bare \`exit 0\` returns an empty string, which the
# check correctly treats as "could not confirm it loaded" and fails on.
# Answering here keeps the stub modelling a healthy box rather than
# weakening the check to accommodate a stub that says nothing.
if [ "\$1" = "show" ]; then
    case "\$*" in
        *LoadState*) echo "loaded" ;;
        *) echo "" ;;
    esac
fi
exit 0
EOF
chmod +x "$FAKE_BIN/systemctl"

# PAT-1237: deploy.sh now invokes the checked-in hardening guard after each
# unit sync. The scratch topology has no systemd, so provide just the stable
# output contract the guard needs: a score within the application's 6.0
# ceiling. This keeps rollback tests about deploy transitions, rather than
# weakening or bypassing the production gate.
cat > "$FAKE_BIN/systemd-analyze" <<'EOF'
#!/bin/bash
unit="${!#}"
printf 'Overall exposure level for %s: 4.0 OK\n' "$unit"
EOF
chmod +x "$FAKE_BIN/systemd-analyze"

# restart_service waits for a real systemd service to settle. The fake
# systemctl above returns active immediately, so keeping the production wait
# in this scratch topology only makes the regression test needlessly slow.
cat > "$FAKE_BIN/sleep" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$FAKE_BIN/sleep"

step "Building scratch topology"
git init -q --bare "$MIRROR"
git -C "$MIRROR" symbolic-ref HEAD refs/heads/main
git init -q "$SRC"
git -C "$SRC" symbolic-ref HEAD refs/heads/main
git -C "$SRC" config user.email "test@patched.im"
git -C "$SRC" config user.name "PAT-909 rollback test"
git -C "$SRC" remote add origin "$MIRROR"

write_commit_files() {
    local dir="$1" smoke_exit="$2" marker="$3"
    # PAT-986 — box-config fixture content. Defaults to a value keyed off
    # $marker (so every commit's fixtures differ, same as before this
    # ticket), but callers can pass identical content across two different
    # commits (different $marker, same $4/$5) to exercise sync_box_config's
    # unchanged-skip path.
    local service_content="${4:-service-$marker}" rules_content="${5:-rules-$marker}"
    mkdir -p "$dir/scripts/smoke" "$dir/deploy"
    cp "$DEPLOY_SH" "$dir/scripts/deploy.sh"
    chmod +x "$dir/scripts/deploy.sh"
    cp "$HARDENING_GUARD" "$dir/deploy/verify-systemd-hardening-floor.sh"
    chmod +x "$dir/deploy/verify-systemd-hardening-floor.sh"
    # PAT-2307: deploy.sh refuses to run without the code tree guard.
    cp "$CODE_TREE_GUARD" "$dir/deploy/code-tree-guard.sh"
    chmod +x "$dir/deploy/code-tree-guard.sh"
    echo "# no real deps needed for this dry run" > "$dir/requirements.txt"
    echo "$marker" > "$dir/VERSION"
    cat > "$dir/scripts/smoke/run_all.py" <<EOF
#!/usr/bin/env python3
import sys
print("stub smoke suite for marker=$marker")
sys.exit($smoke_exit)
EOF
    chmod +x "$dir/scripts/smoke/run_all.py"

    printf '# fake systemd unit fixture: %s\n' "$service_content" > "$dir/deploy/patched-dashboard.service"
    printf '// fake polkit rule fixture: %s\n' "$rules_content" > "$dir/deploy/49-test-pat986.rules"
}

# Commit A — good, smoke passes. This is the bootstrapped baseline: the
# checkout already has a copy of scripts/deploy.sh with hook-mode support,
# same as after PAT-909's own first (raw-hook) deploy lands it on the box.
write_commit_files "$SRC" 0 "A"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit A (good baseline)"
git -C "$SRC" push -q origin HEAD:refs/heads/main

git clone -q "$MIRROR" "$CHECKOUT"
CHECKOUT_INITIAL=$(git -C "$CHECKOUT" rev-parse HEAD)
echo "Checkout bootstrapped at commit A ($CHECKOUT_INITIAL)"

run_hook() {
    local oldrev="$1" newrev="$2"
    PATH="$FAKE_BIN:$PATH" \
    DEPLOY_REPO_DIR="$CHECKOUT" \
    DEPLOY_SERVICE="pat909-dryrun" \
    DEPLOY_LOG="$DEPLOY_LOG" \
    DEPLOY_CODE_OWNER="$(id -un)" \
    DEPLOY_CODE_GROUP="$(id -gn)" \
    DEPLOY_MIRROR_DIR="$MIRROR" \
    DEPLOY_ALLOW_NONROOT=1 \
    DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
    DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
    DEPLOY_CONFIG_OWNER="$(id -un)" \
    DEPLOY_CONFIG_GROUP="$(id -gn)" \
        bash -c "printf '%s %s %s\n' '$oldrev' '$newrev' 'refs/heads/main' | '$POST_RECEIVE'"
}

step "Test 1: forward deploy of a good commit (A -> A2)"
write_commit_files "$SRC" 0 "A2"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit A2 (good)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_A=$(git -C "$SRC" rev-parse HEAD~1)
REV_A2=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
run_hook "$REV_A" "$REV_A2"
HOOK1_EXIT=$?
CHECKOUT_AFTER_1=$(git -C "$CHECKOUT" rev-parse HEAD)

assert_eq "hook exit code for a passing smoke test" "0" "$HOOK1_EXIT"
assert_eq "checkout HEAD moved to the new (good) commit" "$REV_A2" "$CHECKOUT_AFTER_1"
assert_log_contains "log shows Deploy SUCCESSFUL" "Deploy SUCCESSFUL"

# PAT-986 — box config sync must have installed A2's fixture unit before
# the (fake) restart.
assert_log_contains "log shows the systemd unit was installed" "Installing systemd unit"
assert_log_contains "log shows a polkit rule was installed" "Installing polkit rule"
assert_eq "live unit content matches A2's fixture" \
    "# fake systemd unit fixture: service-A2" \
    "$(cat "$FAKE_SYSTEMD_DIR/patched-dashboard.service" 2>/dev/null)"

# PAT-992 — a successful deploy must write DEPLOYED_SHA, atomically, as its
# last step: the full new commit plus a timestamp, trivially greppable.
assert_eq "DEPLOYED_SHA records the newly deployed commit" \
    "DEPLOYED_SHA=$REV_A2" \
    "$(grep '^DEPLOYED_SHA=' "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"
if grep -q '^DEPLOYED_AT=' "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null; then
    printf '  PASS: %s\n' "DEPLOYED_SHA also records a DEPLOYED_AT timestamp"
else
    printf '  FAIL: %s\n' "DEPLOYED_SHA is missing a DEPLOYED_AT timestamp line"
    FAILURES=$((FAILURES + 1))
fi

step "Test 2: rollback on a failing smoke test (A2 -> B)"
write_commit_files "$SRC" 1 "B-bad"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit B (smoke fails)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_B=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
run_hook "$REV_A2" "$REV_B"
HOOK2_EXIT=$?
CHECKOUT_AFTER_2=$(git -C "$CHECKOUT" rev-parse HEAD)

assert_ne "hook exit code for a failing smoke test is non-zero" "0" "$HOOK2_EXIT"
assert_eq "hook exit code matches deploy.sh's documented 'smoke failed, rolled back' code" "2" "$HOOK2_EXIT"
assert_eq "checkout HEAD rolled back to the PREVIOUS commit (A2), not the bad one (B)" "$REV_A2" "$CHECKOUT_AFTER_2"
assert_ne "checkout HEAD did not stay on the bad commit" "$REV_B" "$CHECKOUT_AFTER_2"
assert_log_contains "log shows smoke suite FAILED" "smoke suite FAILED"
assert_log_contains "log shows rollback landed on $REV_A2" "Rolled back. Service is on $REV_A2"

# PAT-986 — the crux of the rollback-interaction reasoning: B-bad's own
# (differently-fixtured) box config was installed before B-bad's restart
# attempt, then rollback() re-ran sync_box_config against the checkout it
# had just reset back to A2 — so the live unit must be back to A2's
# fixture, not left on B-bad's, proving config reverts together with code.
assert_eq "live unit content reverted to A2's fixture after rollback (not B-bad's)" \
    "# fake systemd unit fixture: service-A2" \
    "$(cat "$FAKE_SYSTEMD_DIR/patched-dashboard.service" 2>/dev/null)"

# PAT-992 — the rollback case that matters most: DEPLOYED_SHA must describe
# what's actually running AFTER the rollback (A2, the box's real state), not
# what the deploy attempted (B, the commit that never came up healthy).
# Getting this backwards is the specific regression this ticket exists to
# close.
assert_eq "DEPLOYED_SHA after rollback names the commit actually running (A2), not the failed attempt (B)" \
    "DEPLOYED_SHA=$REV_A2" \
    "$(grep '^DEPLOYED_SHA=' "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

step "Test 3: box config is idempotent, and stale artefacts are removed (PAT-986)"
# A "stale" file left behind by some earlier deploy generation, the way
# /etc/sudoers.d/patched-ops-fw was on the real box before PAT-931/PAT-986.
mkdir -p "$WORKDIR/etc/sudoers.d"
STALE_ARTIFACT="$WORKDIR/etc/sudoers.d/patched-ops-fw-test"
echo "stale" > "$STALE_ARTIFACT"

write_commit_files "$SRC" 0 "C" "shared-v1" "shared-v1"
echo "$STALE_ARTIFACT" > "$SRC/deploy/removed-artifacts.txt"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit C (good, new shared box config, removes stale artefact)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_C=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
run_hook "$REV_A2" "$REV_C"
HOOK3_EXIT=$?

assert_eq "hook exit code for commit C" "0" "$HOOK3_EXIT"
assert_log_contains "log shows the stale artefact was removed" "Removed stale artefact: $STALE_ARTIFACT"
if [ -e "$STALE_ARTIFACT" ]; then
    printf '  FAIL: stale artefact should have been removed but still exists\n'
    FAILURES=$((FAILURES + 1))
else
    printf '  PASS: stale artefact no longer exists on (fake) disk\n'
fi

# Commit C2: identical box config content to C (only VERSION/marker
# differs) — proves sync_box_config's unchanged-skip path, and that
# re-running removal against an already-absent artefact is a clean no-op
# (acceptance criterion 7: safe to run repeatedly / safe when already
# correct).
write_commit_files "$SRC" 0 "C2" "shared-v1" "shared-v1"
echo "$STALE_ARTIFACT" > "$SRC/deploy/removed-artifacts.txt"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit C2 (good, unchanged box config)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_C2=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
run_hook "$REV_C" "$REV_C2"
HOOK4_EXIT=$?

assert_eq "hook exit code for commit C2 (unchanged box config)" "0" "$HOOK4_EXIT"
assert_log_contains "log shows systemd unit unchanged, skipped" "systemd unit unchanged"
assert_log_contains "log shows polkit rule unchanged, skipped" "polkit rule unchanged"
assert_log_not_contains "log does NOT re-install the systemd unit when content is unchanged" "Installing systemd unit"
assert_log_contains "log shows the already-removed artefact is skipped, not re-removed" "already absent, skipping"

step "Test 4: rollback reverts box config together with code (C2 -> D-bad)"
write_commit_files "$SRC" 1 "D-bad" "shared-v2" "shared-v2"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit D (smoke fails, box config changed again)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_D=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
run_hook "$REV_C2" "$REV_D"
HOOK5_EXIT=$?
CHECKOUT_AFTER_5=$(git -C "$CHECKOUT" rev-parse HEAD)

assert_eq "hook exit code matches 'smoke failed, rolled back'" "2" "$HOOK5_EXIT"
assert_eq "checkout HEAD rolled back to C2, not D-bad" "$REV_C2" "$CHECKOUT_AFTER_5"
assert_eq "live unit content reverted to C2's (shared-v1) fixture, not D-bad's (shared-v2)" \
    "# fake systemd unit fixture: shared-v1" \
    "$(cat "$FAKE_SYSTEMD_DIR/patched-dashboard.service" 2>/dev/null)"
assert_eq "live polkit rule content reverted to C2's (shared-v1) fixture, not D-bad's (shared-v2)" \
    "// fake polkit rule fixture: shared-v1" \
    "$(cat "$FAKE_POLKIT_DIR/49-test-pat986.rules" 2>/dev/null)"

# PAT-992 — same rollback (D-bad), checked against the main checkout's own
# DEPLOYED_SHA: must still read C2 (what's running now), never D (what
# failed and was rolled back away from).
assert_eq "DEPLOYED_SHA after Test 4's rollback still names C2, not D-bad" \
    "DEPLOYED_SHA=$REV_C2" \
    "$(grep '^DEPLOYED_SHA=' "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

step "Test 5: a write failure while recording DEPLOYED_SHA never truncates or blanks the file"
# Simulates a crashed/interrupted write (disk full, permission loss, etc.):
# point DEPLOYED_SHA_FILE at a file inside a directory this process cannot
# write into, so mktemp for the atomic temp file fails. A known-good value
# is seeded first (directory made writable to seed it, then locked down) so
# the assertion proves the OLD value survives untouched -- not just that no
# file appears.
SHA_FAIL_DIR="$WORKDIR/sha-write-fails"
mkdir -p "$SHA_FAIL_DIR"
SHA_FAIL_FILE="$SHA_FAIL_DIR/DEPLOYED_SHA"
printf 'DEPLOYED_SHA=PRE-EXISTING-KNOWN-GOOD-VALUE\nDEPLOYED_AT=2026-07-01T00:00:00Z\n' > "$SHA_FAIL_FILE"
chmod 0555 "$SHA_FAIL_DIR"   # read-only dir: mktemp can no longer create a temp file here

write_commit_files "$SRC" 0 "E-good"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit E (good, but DEPLOYED_SHA_FILE dir is unwritable)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_D2=$(git -C "$SRC" rev-parse HEAD~1)
REV_E=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
PATH="$FAKE_BIN:$PATH" \
DEPLOY_REPO_DIR="$CHECKOUT" \
DEPLOY_SERVICE="pat909-dryrun" \
DEPLOY_LOG="$DEPLOY_LOG" \
DEPLOY_CODE_OWNER="$(id -un)" \
DEPLOY_CODE_GROUP="$(id -gn)" \
DEPLOY_MIRROR_DIR="$MIRROR" \
DEPLOY_ALLOW_NONROOT=1 \
DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
DEPLOY_CONFIG_OWNER="$(id -un)" \
DEPLOY_CONFIG_GROUP="$(id -gn)" \
DEPLOY_DEPLOYED_SHA_FILE="$SHA_FAIL_FILE" \
    bash -c "printf '%s %s %s\n' '$REV_D2' '$REV_E' 'refs/heads/main' | '$POST_RECEIVE'"
HOOK6_EXIT=$?
chmod 0755 "$SHA_FAIL_DIR"   # restore so trap cleanup can remove it

assert_eq "hook still exits 0 -- a SHA-recording failure must not fail an otherwise-successful deploy" "0" "$HOOK6_EXIT"
assert_log_contains "log records the write failure loudly rather than silently" "ERROR: could not create temp file"
assert_eq "the previous DEPLOYED_SHA value survives untouched -- never truncated or blanked" \
    "DEPLOYED_SHA=PRE-EXISTING-KNOWN-GOOD-VALUE" \
    "$(grep '^DEPLOYED_SHA=' "$SHA_FAIL_FILE" 2>/dev/null)"
if [ -s "$SHA_FAIL_FILE" ]; then
    printf '  PASS: %s\n' "DEPLOYED_SHA file is not empty after the failed write"
else
    printf '  FAIL: %s\n' "DEPLOYED_SHA file is empty or missing after the failed write"
    FAILURES=$((FAILURES + 1))
fi

step "Test 6: the no-op path must NEVER overwrite DEPLOYED_SHA (PAT-992 FIX 1, independent review)"
# The reviewer's exact scenario: a smoke failure with .no-auto-rollback set
# leaves a KNOWN-BAD commit checked out and running -- deliberately not
# rolled back. DEPLOYED_SHA must still name the last GOOD commit (nothing
# writes it on this skip path). A later standalone retry with nothing new
# to pull takes the no-op path, which restarts nothing and smoke-tests
# nothing -- if that path wrote DEPLOYED_SHA, it would promote the bad
# commit to "confirmed" on the strength of a run that verified nothing.
DEPLOYED_SHA_BEFORE_TEST6="$(cat "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

write_commit_files "$SRC" 1 "G-bad-noauto"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit G (smoke fails, .no-auto-rollback set)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_F=$(git -C "$SRC" rev-parse HEAD~1)
REV_G=$(git -C "$SRC" rev-parse HEAD)

touch "$CHECKOUT/.no-auto-rollback"
: > "$DEPLOY_LOG"
run_hook "$REV_F" "$REV_G" > /dev/null
HOOK7_EXIT=$?
CHECKOUT_AFTER_G="$(git -C "$CHECKOUT" rev-parse HEAD)"

assert_eq "hook exit reflects the .no-auto-rollback skip (exit 2, not rolled back)" "2" "$HOOK7_EXIT"
assert_eq "checkout stays on the bad commit G (auto-rollback disabled)" "$REV_G" "$CHECKOUT_AFTER_G"
assert_eq "DEPLOYED_SHA is untouched by the failed-and-skipped deploy itself" \
    "$DEPLOYED_SHA_BEFORE_TEST6" \
    "$(cat "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

# The no-op retry: nothing new to pull (mirror's main is still at bad G),
# checkout still sitting on G.
: > "$DEPLOY_LOG"
PATH="$FAKE_BIN:$PATH" \
DEPLOY_REPO_DIR="$CHECKOUT" \
DEPLOY_SERVICE="pat909-dryrun" \
DEPLOY_LOG="$DEPLOY_LOG" \
DEPLOY_CODE_OWNER="$(id -un)" \
DEPLOY_CODE_GROUP="$(id -gn)" \
DEPLOY_MIRROR_DIR="$MIRROR" \
DEPLOY_ALLOW_NONROOT=1 \
DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
DEPLOY_CONFIG_OWNER="$(id -un)" \
DEPLOY_CONFIG_GROUP="$(id -gn)" \
    "$CHECKOUT/scripts/deploy.sh"
HOOK8_EXIT=$?
rm -f "$CHECKOUT/.no-auto-rollback"

assert_eq "standalone no-op retry exits 0" "0" "$HOOK8_EXIT"
assert_log_contains "log shows the no-op path was taken" "no-op"
assert_eq "DEPLOYED_SHA STILL names the last GOOD commit after the no-op retry -- never promoted to bad commit G" \
    "$DEPLOYED_SHA_BEFORE_TEST6" \
    "$(cat "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

step "Test 7: a write failure occurring AFTER the temp file is created never truncates DEPLOYED_SHA (PAT-992 FIX 3)"
# Distinct from Test 5 (mktemp itself failing to produce a file at all):
# here mktemp succeeds and the temp file exists, but the write INTO it
# fails -- simulated with a wrapped `mktemp` that revokes write permission
# on the file the instant it creates it. Proves the write's own success is
# checked, not just assumed because mktemp and the later mv both "worked".
MKTEMP_FAIL_BIN="$WORKDIR/bin-mktemp-write-fails"
mkdir -p "$MKTEMP_FAIL_BIN"
cat > "$MKTEMP_FAIL_BIN/mktemp" <<MKTEMPEOF
#!/bin/bash
f="\$("$REAL_MKTEMP" "\$@")" || exit 1
# sync_box_config also uses mktemp for its transaction directory. Only make
# the DEPLOYED_SHA temp file unwritable; otherwise this fixture tests a box
# config failure instead of the intended post-creation SHA-write failure.
case "\$f" in
    *DEPLOYED_SHA.tmp.*) chmod 0444 "\$f" ;;
esac
printf '%s\n' "\$f"
MKTEMPEOF
chmod +x "$MKTEMP_FAIL_BIN/mktemp"

DEPLOYED_SHA_BEFORE_TEST7="$(cat "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"

write_commit_files "$SRC" 0 "H-good"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit H (good, but the temp-file write will fail)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_G2=$(git -C "$SRC" rev-parse HEAD~1)
REV_H=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
PATH="$MKTEMP_FAIL_BIN:$FAKE_BIN:$PATH" \
DEPLOY_REPO_DIR="$CHECKOUT" \
DEPLOY_SERVICE="pat909-dryrun" \
DEPLOY_LOG="$DEPLOY_LOG" \
DEPLOY_CODE_OWNER="$(id -un)" \
DEPLOY_CODE_GROUP="$(id -gn)" \
DEPLOY_MIRROR_DIR="$MIRROR" \
DEPLOY_ALLOW_NONROOT=1 \
DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
DEPLOY_CONFIG_OWNER="$(id -un)" \
DEPLOY_CONFIG_GROUP="$(id -gn)" \
    bash -c "printf '%s %s %s\n' '$REV_G2' '$REV_H' 'refs/heads/main' | '$POST_RECEIVE'"
HOOK9_EXIT=$?

assert_eq "hook still exits 0 -- a SHA-recording failure must not fail an otherwise-successful deploy" "0" "$HOOK9_EXIT"
# Which of the two guards actually catches this is shell/filesystem-
# dependent (confirmed on the bash 3.2 this dev machine ships: a failed
# redirect open on a chmod-0444 file does NOT reliably surface as a
# non-zero exit status from the `{ ... } > "$tmp"` group here, which is
# exactly why the content-verification belt-and-braces check exists and is
# the one that actually fires in this run) -- either is an acceptable,
# equally-safe outcome, so accept both wordings rather than pinning to one.
if grep -qE "ERROR: (write to temp file|temp file for .* did not verify)" "$DEPLOY_LOG"; then
    printf '  PASS: %s\n' "log records the post-creation write failure loudly (one of the two guards fired)"
else
    printf '  FAIL: %s\n' "log does not show either write-failure guard firing"
    FAILURES=$((FAILURES + 1))
fi
assert_eq "DEPLOYED_SHA survives untouched -- never truncated or corrupted by the failed write" \
    "$DEPLOYED_SHA_BEFORE_TEST7" \
    "$(cat "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null)"
if [ -s "$CHECKOUT/DEPLOYED_SHA" ]; then
    printf '  PASS: %s\n' "DEPLOYED_SHA file is not empty after the failed write"
else
    printf '  FAIL: %s\n' "DEPLOYED_SHA file is empty or missing after the failed write"
    FAILURES=$((FAILURES + 1))
fi

step "Test 8: patched-maintenance-facts systemd units get installed with daemon-reload + timer restart (PAT-1439/PAT-1438)"
# Before PAT-1439/PAT-1438, deploy/patched-maintenance-facts.service and
# .timer had NO deploy path at all -- hand-installed once and never touched
# again, which is exactly how they went 12 days over systemd-hardening-
# floor.md's ceiling unnoticed. This proves sync_box_config() installs BOTH
# files, issues a daemon-reload, and re-enables/restarts the TIMER --
# never the oneshot .service, which would just fire an off-schedule run.
mkdir -p "$SRC/deploy"
printf '# fake mf unit fixture: v1\n' > "$SRC/deploy/patched-maintenance-facts.service"
printf '# fake mf timer fixture: v1\n' > "$SRC/deploy/patched-maintenance-facts.timer"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit I (introduce patched-maintenance-facts units)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_H2=$(git -C "$SRC" rev-parse HEAD~1)
REV_I=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
: > "$SYSTEMCTL_CALLS"
run_hook "$REV_H2" "$REV_I"
HOOK10_EXIT=$?

assert_eq "hook exit code for commit I (new mf units)" "0" "$HOOK10_EXIT"
assert_eq "live .service content matches I's fixture" \
    "# fake mf unit fixture: v1" \
    "$(cat "$FAKE_SYSTEMD_DIR/patched-maintenance-facts.service" 2>/dev/null)"
assert_eq "live .timer content matches I's fixture" \
    "# fake mf timer fixture: v1" \
    "$(cat "$FAKE_SYSTEMD_DIR/patched-maintenance-facts.timer" 2>/dev/null)"
assert_log_contains "log shows daemon-reload for the mf units" \
    "daemon-reload complete (patched-maintenance-facts units)"
if grep -qx "daemon-reload" "$SYSTEMCTL_CALLS"; then
    printf '  PASS: %s\n' "systemctl daemon-reload was actually invoked"
else
    printf '  FAIL: %s\n' "systemctl daemon-reload was never invoked"
    FAILURES=$((FAILURES + 1))
fi
if grep -qx "enable --now patched-maintenance-facts.timer" "$SYSTEMCTL_CALLS"; then
    printf '  PASS: %s\n' "systemctl enable --now patched-maintenance-facts.timer was invoked"
else
    printf '  FAIL: %s\n' "systemctl enable --now patched-maintenance-facts.timer was never invoked"
    FAILURES=$((FAILURES + 1))
fi
if grep -q "restart patched-maintenance-facts.service" "$SYSTEMCTL_CALLS"; then
    printf '  FAIL: %s\n' "the oneshot .service must NEVER be restarted directly -- only the timer"
    FAILURES=$((FAILURES + 1))
else
    printf '  PASS: %s\n' "the oneshot .service was never directly restarted"
fi
if grep -qE '^is-enabled --quiet patched-maintenance-facts\.timer$' "$SYSTEMCTL_CALLS" \
    && grep -qE '^is-active --quiet patched-maintenance-facts\.timer$' "$SYSTEMCTL_CALLS"; then
    printf '  PASS: %s\n' "the timer's enabled/active state was verified after install, not just trusted"
else
    printf '  FAIL: %s\n' "sync_box_config did not verify the timer is enabled AND active after install"
    FAILURES=$((FAILURES + 1))
fi

step "Test 9: an unchanged mf deploy does not reinstall units or restart its timer (idempotent)"
git -C "$SRC" commit -q --allow-empty -m "commit I2 (mf units unchanged)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_I2=$(git -C "$SRC" rev-parse HEAD)

: > "$DEPLOY_LOG"
: > "$SYSTEMCTL_CALLS"
run_hook "$REV_I" "$REV_I2"
HOOK11_EXIT=$?

assert_eq "hook exit code for commit I2 (mf units unchanged)" "0" "$HOOK11_EXIT"
assert_log_not_contains "log does NOT reinstall the mf units when content is unchanged" \
    "Installing systemd unit: $CHECKOUT/deploy/patched-maintenance-facts"
if grep -qx "daemon-reload" "$SYSTEMCTL_CALLS"; then
    printf '  PASS: %s\n' "hardening verification refreshed systemd's loaded unit view"
else
    printf '  FAIL: %s\n' "hardening verification did not reload systemd before scoring unchanged units"
    FAILURES=$((FAILURES + 1))
fi
if grep -qx "enable --now patched-maintenance-facts.timer" "$SYSTEMCTL_CALLS"; then
    printf '  FAIL: %s\n' "the timer must not be re-enabled/restarted when nothing changed"
    FAILURES=$((FAILURES + 1))
else
    printf '  PASS: %s\n' "no timer re-enable/restart on an unchanged mf deploy"
fi
if grep -qE '^is-enabled --quiet patched-maintenance-facts\.timer$' "$SYSTEMCTL_CALLS" \
    && grep -qE '^is-active --quiet patched-maintenance-facts\.timer$' "$SYSTEMCTL_CALLS"; then
    printf '  PASS: %s\n' "the timer's enabled/active state is still verified even on a no-op deploy"
else
    printf '  FAIL: %s\n' "sync_box_config skipped verifying the timer on a no-op deploy"
    FAILURES=$((FAILURES + 1))
fi

step "Test 10: a no-op deploy still reconciles drifted box config (PAT-1441)"
# The regression this exists to prevent, which happened for real on
# 2026-08-19: sync_box_config used to sit BEHIND the no-op guard, so a box
# whose systemd unit had drifted from the repo could never be corrected by
# re-running the deploy -- the run exited before the one function written to
# detect that drift. Combined with the hook execing the PREVIOUS deploy.sh
# (the reset to the new commit happens inside it), a box-config change could
# only ever land on some later, unrelated commit. Both runs reported success.
#
# "No new commits" is a fact about the checkout; whether the box's unit
# matches the repo is a different question, and drift needs no commit to
# occur -- a hand-edited unit, a systemctl edit, a restored snapshot.
: > "$DEPLOY_LOG"
# Drift the installed unit without touching the checkout at all.
echo "# hand-edited on the box, not in the repo" >> "$FAKE_SYSTEMD_DIR/patched-dashboard.service"
CHECKOUT_SHA_BEFORE_T10="$(git -C "$CHECKOUT" rev-parse HEAD)"

PATH="$FAKE_BIN:$PATH" \
DEPLOY_REPO_DIR="$CHECKOUT" \
DEPLOY_SERVICE="pat909-dryrun" \
DEPLOY_LOG="$DEPLOY_LOG" \
DEPLOY_CODE_OWNER="$(id -un)" \
DEPLOY_CODE_GROUP="$(id -gn)" \
DEPLOY_MIRROR_DIR="$MIRROR" \
DEPLOY_ALLOW_NONROOT=1 \
DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
DEPLOY_CONFIG_OWNER="$(id -un)" \
DEPLOY_CONFIG_GROUP="$(id -gn)" \
    "$CHECKOUT/scripts/deploy.sh"
T10_EXIT=$?

assert_eq "no-op deploy with drifted box config still exits 0" "0" "$T10_EXIT"
assert_eq "the checkout genuinely did not move (this really was the no-op path)" \
    "$CHECKOUT_SHA_BEFORE_T10" "$(git -C "$CHECKOUT" rev-parse HEAD)"
assert_log_contains "log still shows the no-op path was taken" "no-op"
if diff -q "$CHECKOUT/deploy/patched-dashboard.service" "$FAKE_SYSTEMD_DIR/patched-dashboard.service" >/dev/null 2>&1; then
    T10_RECONCILED=reconciled
else
    T10_RECONCILED=still-drifted
fi
assert_eq "drifted unit is reconciled back to the repo copy on a NO-OP run (PAT-1441)" \
    "reconciled" "$T10_RECONCILED"

step "Test 11: after every deploy and rollback above, the code tree is still locked (PAT-2307)"
# Tests 1 to 10 between them ran forward deploys, smoke-failure rollbacks
# and a no-op reconcile. None of them may have left anything in the
# checkout or the mirror writable by group or other, and DEPLOYED_SHA must
# be readable by the app without being writable by it.
T11_WRITABLE="$(find "$CHECKOUT" "$MIRROR" ! -type l \( -perm -020 -o -perm -002 \) -print | head -5)"
assert_eq "no group- or other-writable path in the checkout or mirror" "" "$T11_WRITABLE"
T11_SHA_MODE="$(stat -c '%a' "$CHECKOUT/DEPLOYED_SHA" 2>/dev/null || stat -f '%Lp' "$CHECKOUT/DEPLOYED_SHA")"
assert_eq "DEPLOYED_SHA is 0644 (root's record, readable by the app)" "644" "$T11_SHA_MODE"
assert_log_contains "the no-op run above locked and re-checked the tree too" "Locking the code tree"

step "Test 12: a writable file in the tree stops the deploy before anything runs (PAT-2307)"
# The escalation this ticket closes: the service user rewrites something
# root will run on the next deploy. deploy.sh must refuse before its reset,
# pip, sync or smoke, and must not quietly lock the file and carry on (that
# would hide exactly the change that needs a human to look at it).
write_commit_files "$SRC" 0 "J-good"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit J (good, but the checkout has a writable script)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_J=$(git -C "$SRC" rev-parse HEAD)
CHECKOUT_SHA_BEFORE_T12="$(git -C "$CHECKOUT" rev-parse HEAD)"
chmod g+w "$CHECKOUT/scripts/smoke/run_all.py"

: > "$DEPLOY_LOG"
run_hook "$CHECKOUT_SHA_BEFORE_T12" "$REV_J"
T12_EXIT=$?

assert_eq "hook exits 1 when the guard fails" "1" "$T12_EXIT"
assert_eq "the checkout did not move" "$CHECKOUT_SHA_BEFORE_T12" "$(git -C "$CHECKOUT" rev-parse HEAD)"
assert_log_contains "the guard names the writable file" "writable by a non-root user: .*scripts/smoke/run_all.py"
assert_log_contains "the refusal points at the adopt path" "adopt_code_tree=true"
assert_log_not_contains "no smoke suite ran" "Running smoke suite"
assert_log_not_contains "no box config was synced" "Syncing box-side config"
if [ -n "$(find "$CHECKOUT/scripts/smoke/run_all.py" -perm -020 -print)" ]; then
    printf '  PASS: %s\n' "the writable file was left as found for a human to inspect, not silently re-locked"
else
    printf '  FAIL: %s\n' "deploy.sh silently re-locked the writable file instead of refusing"
    FAILURES=$((FAILURES + 1))
fi
chmod g-w "$CHECKOUT/scripts/smoke/run_all.py"

step "Test 13: the deploy enforces hcloud's and the origin key's ownership and refuses a symlink (PAT-2312)"
# Root runs hcloud from the firewall-apply units, and only the nginx master
# (root) reads the origin TLS key. The dry run cannot chown
# to another user, so the owner here is the invoking user (as for every
# other box-config file above) and the drift is in the mode; the pytest
# suite covers a group change.
run_standalone_deploy() {
    PATH="$FAKE_BIN:$PATH" \
    DEPLOY_REPO_DIR="$CHECKOUT" \
    DEPLOY_SERVICE="pat909-dryrun" \
    DEPLOY_LOG="$DEPLOY_LOG" \
    DEPLOY_CODE_OWNER="$(id -un)" \
    DEPLOY_CODE_GROUP="$(id -gn)" \
    DEPLOY_MIRROR_DIR="$MIRROR" \
    DEPLOY_ALLOW_NONROOT=1 \
    DEPLOY_SYSTEMD_DIR="$FAKE_SYSTEMD_DIR" \
    DEPLOY_POLKIT_RULES_DIR="$FAKE_POLKIT_DIR" \
    DEPLOY_CONFIG_OWNER="$(id -un)" \
    DEPLOY_CONFIG_GROUP="$(id -gn)" \
        "$CHECKOUT/scripts/deploy.sh"
}
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# Absent (the state of every run above): not an error.
: > "$DEPLOY_LOG"
run_hook "$CHECKOUT_SHA_BEFORE_T12" "$REV_J"
T13_EXIT=$?
assert_eq "a forward deploy with no hcloud installed succeeds" "0" "$T13_EXIT"
assert_log_contains "an absent hcloud is logged, not failed" "hcloud not installed at $DEPLOY_HCLOUD_BIN"
assert_log_contains "an absent origin key is logged, not failed" "origin TLS key not installed at $DEPLOY_ORIGIN_KEY"

# Drifted mode: fixed, and the before state logged. A no-op run, so this
# also shows it reconciles without a new commit (PAT-1441).
mkdir -p "$(dirname "$DEPLOY_HCLOUD_BIN")"
printf '#!/bin/sh\necho fake hcloud\n' > "$DEPLOY_HCLOUD_BIN"
chmod 0775 "$DEPLOY_HCLOUD_BIN"
# The origin key as it is on patched-prod-01: readable by everyone.
mkdir -p "$(dirname "$DEPLOY_ORIGIN_KEY")"
printf 'not a real key\n' > "$DEPLOY_ORIGIN_KEY"
chmod 0644 "$DEPLOY_ORIGIN_KEY"
: > "$DEPLOY_LOG"
run_standalone_deploy
T13B_EXIT=$?
assert_eq "the no-op deploy that fixes hcloud's mode succeeds" "0" "$T13B_EXIT"
assert_eq "hcloud is 0755 after the deploy" "755" "$(file_mode "$DEPLOY_HCLOUD_BIN")"
assert_log_contains "the change is logged with the before state" "Enforced hcloud ownership: $DEPLOY_HCLOUD_BIN was .* 775, now .* 755"
assert_eq "the origin key is 0600 after the deploy" "600" "$(file_mode "$DEPLOY_ORIGIN_KEY")"
assert_log_contains "the key change is logged with the before state" "Enforced origin TLS key ownership: $DEPLOY_ORIGIN_KEY was .* 644, now .* 600"

# Already correct: left alone.
: > "$DEPLOY_LOG"
run_standalone_deploy
assert_eq "a second run with hcloud already correct succeeds" "0" "$?"
assert_log_contains "an unchanged hcloud is logged as unchanged" "hcloud ownership unchanged ($DEPLOY_HCLOUD_BIN is"
assert_log_contains "an unchanged origin key is logged as unchanged" "origin TLS key ownership unchanged ($DEPLOY_ORIGIN_KEY is"

# A symlink: refused, the target left alone, and the no-op run aborts.
HCLOUD_TARGET="$WORKDIR/hcloud-real"
mv "$DEPLOY_HCLOUD_BIN" "$HCLOUD_TARGET"
chmod 0700 "$HCLOUD_TARGET"
ln -s "$HCLOUD_TARGET" "$DEPLOY_HCLOUD_BIN"
: > "$DEPLOY_LOG"
run_standalone_deploy
T13D_EXIT=$?
assert_eq "a symlinked hcloud fails the (no-op) deploy" "1" "$T13D_EXIT"
assert_log_contains "the refusal names the symlink" "ERROR: $DEPLOY_HCLOUD_BIN is a symlink; refusing"
assert_log_contains "the no-op run aborts rather than rolling back" "box config sync failed on an otherwise no-op run"
assert_eq "the symlink's target was not chmodded" "700" "$(file_mode "$HCLOUD_TARGET")"
if [ -L "$DEPLOY_HCLOUD_BIN" ]; then
    printf '  PASS: %s\n' "the symlink was left in place for a human to replace"
else
    printf '  FAIL: %s\n' "the symlink was removed or replaced"
    FAILURES=$((FAILURES + 1))
fi

step "Test 14: the deploy removes the retired account, and refuses while a guard fails (PAT-2312)"
# Every deploy above ran the step against an absent scratch account. Now plant
# one shaped like `patched` on patched-prod-01: a sudo membership, a home
# holding a copy of the tunnel credential /etc/cloudflared also has, and a
# scratch file in /tmp.
rm -f "$DEPLOY_HCLOUD_BIN"   # Test 13's symlink fails every deploy; absent is fine
RETIRED_JSON="5d9bda0f-ac65-4014-aa2c-3e523a3f9139.json"
RETIRED_TMP_FILE="$RETIRED_ROOT/tmp/tmp.FVD6FpE2gb"
printf '%s\n' "someone:x:1000:1000::/home/someone:/bin/bash" \
    "pat2312-dryrun:x:$RETIRED_UID:4242:,,,:$DEPLOY_RETIRED_ACCOUNT_HOME:/bin/bash" > "$RETIRED_FAKE_DB/passwd"
printf '%s\n' "sudo:x:27:pat2312-dryrun" "pat2312-dryrun:x:4242:" "someone:x:1000:" > "$RETIRED_FAKE_DB/group"
mkdir -p "$DEPLOY_RETIRED_ACCOUNT_HOME/.cloudflared"
printf 'placeholder\n' > "$DEPLOY_RETIRED_ACCOUNT_HOME/.cloudflared/cert.pem"
printf '{"TunnelID":"placeholder"}\n' > "$DEPLOY_RETIRED_ACCOUNT_HOME/.cloudflared/$RETIRED_JSON"
cp "$DEPLOY_RETIRED_ACCOUNT_HOME/.cloudflared/$RETIRED_JSON" "$DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR/$RETIRED_JSON"
printf 'scratch\n' > "$RETIRED_TMP_FILE"

# A process still runs as it: the (no-op) deploy refuses and changes nothing.
printf -- '-u %s 4242\n' "$RETIRED_UID" > "$RETIRED_FAKE_PROCS"
: > "$DEPLOY_LOG"
run_standalone_deploy
T14A_EXIT=$?
assert_eq "a deploy with a process running as the retired account fails" "1" "$T14A_EXIT"
assert_log_contains "the refusal names the process" "refusing to remove pat2312-dryrun: process 4242 runs as uid $RETIRED_UID"
assert_log_contains "the no-op run aborts rather than rolling back" "box config sync failed on an otherwise no-op run"
if grep -q '^pat2312-dryrun:' "$RETIRED_FAKE_DB/passwd" && [ -d "$DEPLOY_RETIRED_ACCOUNT_HOME" ] && [ -f "$RETIRED_TMP_FILE" ]; then
    printf '  PASS: %s\n' "the account, its home and its tmp file were all left in place"
else
    printf '  FAIL: %s\n' "a refused removal changed something"
    FAILURES=$((FAILURES + 1))
fi

# The process has gone: a forward deploy through the hook removes it.
: > "$RETIRED_FAKE_PROCS"
write_commit_files "$SRC" 0 "K-good"
git -C "$SRC" add -A
git -C "$SRC" commit -q -m "commit K (good, retired account present)"
git -C "$SRC" push -q origin HEAD:refs/heads/main
REV_K=$(git -C "$SRC" rev-parse HEAD)
: > "$DEPLOY_LOG"
run_hook "$(git -C "$CHECKOUT" rev-parse HEAD)" "$REV_K"
T14B_EXIT=$?
assert_eq "the forward deploy that removes the retired account succeeds" "0" "$T14B_EXIT"
assert_eq "checkout HEAD moved to K" "$REV_K" "$(git -C "$CHECKOUT" rev-parse HEAD)"
assert_log_contains "the state before is logged" "Retired account pat2312-dryrun is present: pat2312-dryrun:x:$RETIRED_UID:4242:"
assert_log_contains "the tmp file is logged as deleted" "deleting: $RETIRED_TMP_FILE"
assert_log_contains "the state after is logged" "Retired account pat2312-dryrun removed: no passwd entry, no group"
assert_eq "no passwd entry is left" "" "$(grep '^pat2312-dryrun:' "$RETIRED_FAKE_DB/passwd")"
assert_eq "no group and no membership is left" "sudo:x:27: someone:x:1000:" "$(tr '\n' ' ' < "$RETIRED_FAKE_DB/group" | sed 's/ $//')"
assert_eq "the home is gone" "absent" "$([ -e "$DEPLOY_RETIRED_ACCOUNT_HOME" ] && echo present || echo absent)"
assert_eq "the tmp file is gone" "absent" "$([ -e "$RETIRED_TMP_FILE" ] && echo present || echo absent)"
assert_eq "the tunnel's own credential is untouched" '{"TunnelID":"placeholder"}' \
    "$(cat "$DEPLOY_RETIRED_ACCOUNT_TUNNEL_DIR/$RETIRED_JSON" 2>/dev/null)"

# Every later deploy: already absent, nothing to do.
: > "$DEPLOY_LOG"
run_standalone_deploy
assert_eq "the next (no-op) deploy succeeds" "0" "$?"
assert_log_contains "the account is logged as already absent" "Retired account pat2312-dryrun already absent; nothing to remove"

step "Result"
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "$FAILURES CHECK(S) FAILED. See log at $DEPLOY_LOG before it's cleaned up (rerun with WORKDIR preserved to inspect)"
    exit 1
fi
