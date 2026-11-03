#!/bin/bash
# test-install-legacy-purge.sh — PAT-1505 regression test for install.sh's
# upgrade-in-place purge of residual pre-assurance-only files.
#
# Real-device verification (2026-09-09, mac-staging) found that an
# upgrade-in-place left three plist files physically present in
# $BUNDLE_DEST (com.patched.install-check.plist,
# com.patched.uninstall-check.plist, com.patched.catalogue-poll.plist —
# already purged from $LAUNCHDAEMONS_DIR by LEGACY_LAUNCHDAEMONS, but never
# from their $BUNDLE_DEST copies) and never purged the stale catalogue
# cache (catalogue.json, catalogue.etag) from $STATE_DIR at all.
#
# The full installer needs root, a signed manifest and real bundle hashes,
# so this does NOT run install.sh. It tests the purge DECISION the same way
# endpoint/test-install-mode.zsh tests the mode-selection decision: it
# extracts the sentinel-delimited PATCHED_LEGACY_PURGE block from the
# SHIPPED install.sh, plus the three LEGACY_* array literals feeding it, and
# drives them directly against fixture BUNDLE_DEST / LAUNCHDAEMONS_DIR /
# STATE_DIR — no root, no cp, no chown, no real launchctl.
#
# Extracting the arrays from the live script (rather than hardcoding the
# filenames here) means a future addition or removal to LEGACY_LAUNCHDAEMONS,
# LEGACY_BUNDLE_FILES or LEGACY_CATALOGUE_FILES is exercised automatically —
# this test creates one fixture file per array element, so it will not miss
# a newly-added name.
#
# Run: bash endpoint/test-install-legacy-purge.sh

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"

pass=0; fail=0
chk() {
    if (( $2 )); then echo "  PASS: $1"; (( pass++ ))
    else echo "  FAIL: $1"; (( fail++ )); fi
}

# --- Extract the three LEGACY_* array literals (source of truth is install.sh) ---
extract_array() {  # extract_array <array-name>
    awk -v name="$1" '
        $0 ~ "^" name "=\\(" { f=1 }
        f { print }
        f && /^\)/ { exit }
    ' "$INSTALL_SH"
}

ARRAYS_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-legacy-purge-arrays.XXXXXX")
{
    extract_array LEGACY_LAUNCHDAEMONS
    extract_array LEGACY_BUNDLE_FILES
    extract_array LEGACY_CATALOGUE_FILES
    extract_array LEGACY_CATALOGUE_DIRS
} > "$ARRAYS_TMP"
if [[ ! -s "$ARRAYS_TMP" ]]; then
    echo "FATAL: could not extract LEGACY_* arrays from $INSTALL_SH"
    exit 1
fi

# --- Extract the sentinel-delimited purge block ---
# PAT-2420: the block calls /bin/launchctl by absolute path, which the
# launchctl function below cannot stand in for, so the extracted copy has that
# path turned back into the bare name. A copy that still names the real
# launchctl is refused.
PURGE_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-legacy-purge-block.XXXXXX")
awk '/PATCHED_LEGACY_PURGE_START/{f=1;next} /PATCHED_LEGACY_PURGE_END/{f=0} f' \
    "$INSTALL_SH" | sed 's#/bin/launchctl #launchctl #g' > "$PURGE_TMP"
if [[ ! -s "$PURGE_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_LEGACY_PURGE block from $INSTALL_SH"
    exit 1
fi
if grep -q '/bin/launchctl' "$PURGE_TMP"; then
    echo "FATAL: extracted purge block still names the real launchctl"
    exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.install-legacy-purge-test.XXXXXX")
trap 'rm -rf "$WORK" "$ARRAYS_TMP" "$PURGE_TMP"' EXIT

BUNDLE_DEST="$WORK/bundle"
LAUNCHDAEMONS_DIR="$WORK/launchdaemons"
STATE_DIR="$WORK/state"
mkdir -p "$BUNDLE_DEST" "$LAUNCHDAEMONS_DIR" "$STATE_DIR"

launchctl() { return 0; }

# Populate the real array contents so the extracted block has something to
# read (the arrays are declared here, not sourced from install.sh's own
# variable assignments elsewhere in the file, since the extraction above
# pulls only the array literals themselves).
# shellcheck disable=SC1090
source "$ARRAYS_TMP"

# One fixture file per legacy name, in the directory the purge loop targets.
for plist in "${LEGACY_LAUNCHDAEMONS[@]}"; do
    : > "$LAUNCHDAEMONS_DIR/$plist"
done
for legacy in "${LEGACY_BUNDLE_FILES[@]}"; do
    : > "$BUNDLE_DEST/$legacy"
done
for cache in "${LEGACY_CATALOGUE_FILES[@]}"; do
    : > "$STATE_DIR/$cache"
done
for cache_dir in "${LEGACY_CATALOGUE_DIRS[@]}"; do
    mkdir -p "$STATE_DIR/$cache_dir"
done

# Decoy current-bundle files that must survive the purge untouched.
: > "$BUNDLE_DEST/patched-update.sh"
: > "$LAUNCHDAEMONS_DIR/com.patched.update.plist"
: > "$STATE_DIR/posture.json"

echo "--- running extracted purge block ---"
# shellcheck disable=SC1090
source "$PURGE_TMP"
echo

for plist in "${LEGACY_LAUNCHDAEMONS[@]}"; do
    chk "$plist removed from LAUNCHDAEMONS_DIR" "$([[ -e "$LAUNCHDAEMONS_DIR/$plist" ]] && echo 0 || echo 1)"
done
for legacy in "${LEGACY_BUNDLE_FILES[@]}"; do
    chk "$legacy removed from BUNDLE_DEST" "$([[ -e "$BUNDLE_DEST/$legacy" ]] && echo 0 || echo 1)"
done
for cache in "${LEGACY_CATALOGUE_FILES[@]}"; do
    chk "$cache removed from STATE_DIR" "$([[ -e "$STATE_DIR/$cache" ]] && echo 0 || echo 1)"
done
for cache_dir in "${LEGACY_CATALOGUE_DIRS[@]}"; do
    chk "$cache_dir removed from STATE_DIR" "$([[ -e "$STATE_DIR/$cache_dir" ]] && echo 0 || echo 1)"
done

chk "current patched-update.sh left in place" "$([[ -e "$BUNDLE_DEST/patched-update.sh" ]] && echo 1 || echo 0)"
chk "current com.patched.update.plist left in place" "$([[ -e "$LAUNCHDAEMONS_DIR/com.patched.update.plist" ]] && echo 1 || echo 0)"
chk "current posture.json left in place" "$([[ -e "$STATE_DIR/posture.json" ]] && echo 1 || echo 0)"

# PAT-1505 real-device gap regression: the three bundle-dir plist copies and
# the two catalogue cache files specifically, by name, so a future edit that
# drops any one of them from its LEGACY_* array is caught by name rather than
# only being found again by a real-device upgrade.
for name in com.patched.install-check.plist com.patched.uninstall-check.plist \
            com.patched.catalogue-poll.plist; do
    chk "$name (bundle-dir copy) is in LEGACY_BUNDLE_FILES and was removed" \
        "$([[ -e "$BUNDLE_DEST/$name" ]] && echo 0 || echo 1)"
done
for name in catalogue.json catalogue.etag; do
    chk "$name is in LEGACY_CATALOGUE_FILES and was removed" \
        "$([[ -e "$STATE_DIR/$name" ]] && echo 0 || echo 1)"
done

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
