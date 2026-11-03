#!/bin/zsh
##############################################################################
# test-posture-cache-one-writer.zsh — PAT-1116 regression guard.
#
# posture.json is a trusted decoded cache consumed by the unprivileged app and
# root-side uninstall gate. Only endpoint/patched-fetch-posture.sh may write
# it, after signature verification. The inventory uploader must never fetch or
# overwrite it with the raw signed envelope.
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"
REPO_ROOT="$SCRIPT_DIR:h"
FETCH_SH="$REPO_ROOT/endpoint/patched-fetch-posture.sh"
pass=0; fail=0

check() {
    local description="$1" ok="$2"
    if (( ok )); then
        (( pass++ ))
        echo "  PASS: $description"
    else
        (( fail++ ))
        echo "  FAIL: $description"
    fi
}

check "uploader source exists" "$([[ -f "$UPLOAD_SH" ]] && echo 1 || echo 0)"

posture_endpoint_hits=$(grep -n '/v1/posture' "$UPLOAD_SH" 2>/dev/null || true)
check "uploader does not fetch posture" "$([[ -z "$posture_endpoint_hits" ]] && echo 1 || echo 0)"
[[ -n "$posture_endpoint_hits" ]] && echo "$posture_endpoint_hits"

posture_file_hits=$(grep -n 'posture\.json\|POSTURE_FILE' "$UPLOAD_SH" 2>/dev/null || true)
check "uploader does not write posture cache" "$([[ -z "$posture_file_hits" ]] && echo 1 || echo 0)"
[[ -n "$posture_file_hits" ]] && echo "$posture_file_hits"

check "verified posture poller source exists" "$([[ -f "$FETCH_SH" ]] && echo 1 || echo 0)"

# Runtime write operations in macos/ and endpoint/ must resolve to the one
# verified commit in patched-fetch-posture.sh. Read-only POSTURE_FILE users and
# uninstall cleanup are intentionally excluded from this write-pattern check.
writer_hits=$(grep -H -E '(mv|cp|install)[[:space:]].*(_posture_file|POSTURE_FILE|posture\.json)|>.*(POSTURE_FILE|posture\.json)' \
    "$REPO_ROOT"/macos/*.sh "$REPO_ROOT"/endpoint/*.sh 2>/dev/null \
    | grep -v '/test-' \
    | grep -v '/uninstall\.sh:' \
    | grep -v '/patched-uninstall\.sh:' \
    || true)
expected_writer="$FETCH_SH:    mv -f \"\$_verified_tmp\" \"\$_posture_file\""
check "verified posture poller is the only runtime posture-cache writer" \
    "$([[ "$writer_hits" == "$expected_writer" ]] && echo 1 || echo 0)"
if [[ "$writer_hits" != "$expected_writer" ]]; then
    echo "Expected: $expected_writer"
    echo "Observed: ${writer_hits:-<none>}"
fi

verify_line=$(grep -n '"\$VERIFIER"' "$FETCH_SH" | head -1 | cut -d: -f1)
validate_line=$(grep -n '"\$VALIDATOR"' "$FETCH_SH" | head -1 | cut -d: -f1)
commit_line=$(grep -n 'if _posture_commit_verified "\$out_tmp" "\$POSTURE_FILE"' "$FETCH_SH" | head -1 | cut -d: -f1)
check "signature verification precedes schema validation and cache commit" \
    "$([[ -n "$verify_line" && -n "$validate_line" && -n "$commit_line" \
          && "$verify_line" -lt "$validate_line" && "$validate_line" -lt "$commit_line" ]] && echo 1 || echo 0)"

echo "RESULT: pass=$pass fail=$fail"
(( fail == 0 ))
