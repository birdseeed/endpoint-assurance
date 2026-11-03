#!/bin/zsh
##############################################################################
# test-posture-cache-commit.zsh — PAT-1116 cache readability regression.
#
# Extracts the production commit helper and proves a verifier output created
# by mktemp at 0600 lands atomically as a 0644 decoded posture cache readable
# by the unprivileged desktop apps.
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
FETCH_SH="$SCRIPT_DIR/patched-fetch-posture.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

HELPER="$TEST_ROOT/helper.zsh"
sed -n '/^# >>> PATCHED_POSTURE_CACHE_COMMIT_START$/,/^# <<< PATCHED_POSTURE_CACHE_COMMIT_END$/p' \
    "$FETCH_SH" | sed '/^# >>>/d; /^# <<</d' > "$HELPER"

if [[ ! -s "$HELPER" ]]; then
    echo "FAIL: could not extract production posture cache commit helper"
    exit 1
fi

source "$HELPER"

source_file="$TEST_ROOT/verified.tmp"
destination="$TEST_ROOT/posture.json"
printf '%s\n' '{"schema_version":1,"generated_at":"2026-08-02T16:04:49Z"}' > "$source_file"
chmod 0600 "$source_file"

_posture_commit_verified "$source_file" "$destination"

fail=0
[[ ! -e "$source_file" ]] || { echo "FAIL: source temp still exists after atomic move"; fail=1; }
[[ -f "$destination" ]] || { echo "FAIL: posture cache was not created"; fail=1; }
mode=$(stat -f %Lp "$destination" 2>/dev/null || echo missing)
[[ "$mode" == "644" ]] || { echo "FAIL: posture cache mode is $mode, expected 644"; fail=1; }
grep -q '"schema_version":1' "$destination" \
    || { echo "FAIL: posture cache content changed during commit"; fail=1; }

if (( fail == 0 )); then
    echo "PASS: verified posture cache commits atomically at mode 0644"
fi
exit "$fail"
