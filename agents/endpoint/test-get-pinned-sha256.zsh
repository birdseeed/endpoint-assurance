#!/bin/zsh
##############################################################################
# test-get-pinned-sha256.zsh: PAT-2245 regression guard for the retired
# signed app catalogue's pin readers.
#
# PAT-2245 removed catalogue_install_gate(), the freshness gate that used to
# refuse installs from a stale catalogue. Clean-up of the cached
# catalogue.json on upgrade is best effort, so a Mac where that delete failed
# could still hold a well-formed pin. The readers must therefore never read
# the cache at all: every label is NO_PIN (exit 3, nothing on stdout) and the
# refusal is logged as "install refused: catalogue retired (PAT-2245)".
#
# Each case plants a fresh-looking catalogue.json (generated_at = now) with a
# valid 64-hex pin and a latest_verified_version for the label, at every path
# the readers could look (CATALOGUE_FILE and $STATE_DIR/catalogue.json), and
# proves the pin never comes back. The wiring from exit 3 to "the engine is
# never invoked" is covered by endpoint/test-run-label-catalogue-wiring.zsh
# and ci/test-install-daemon-endtoend.zsh (Test 5).
#
# Extracts the SHIPPED sentinel blocks from every script that carries a copy.
#
# Run: zsh endpoint/test-get-pinned-sha256.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"

SHIPPED_FILES=(
    "$SCRIPT_DIR/patched-update.sh"
    "$SCRIPT_DIR/patched-install.sh"
)

PYTHON3="/usr/bin/python3"
VALID_HASH=$(printf 'a%.0s' {1..64})

total_pass=0
total_fail=0

chk() {  # chk <desc> <1-for-true, 0-for-false>
    if (( $2 )); then (( total_pass++ )); echo "  PASS: $1"
    else (( total_fail++ )); echo "  FAIL: $1"; fi
}

extract() {  # extract <file> <start> <end> <dest>
    awk "/$2/{f=1;next} /$3/{f=0} f" "$1" > "$4"
    [[ -s "$4" ]]
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.get-pinned-sha256-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
STATE_DIR="$WORK/state"
mkdir -p "$STATE_DIR"
CATALOGUE_FILE="$STATE_DIR/catalogue.json"
now_iso=$("$PYTHON3" -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
cat > "$CATALOGUE_FILE" <<JSON
{"generated_at":"$now_iso","scope":"global","labels":{"slack":{"sha256":"$VALID_HASH","latest_verified_version":"4.41.0"}}}
JSON
chk "fixture: planted catalogue is fresh, valid JSON and pins slack" \
    "$("$PYTHON3" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(1 if len(d["labels"]["slack"]["sha256"])==64 else 0)' "$CATALOGUE_FILE")"

for src in "${SHIPPED_FILES[@]}"; do
    echo
    echo "=== ${src:t} ==="
    blk="$WORK/${src:t}.pin"
    if ! extract "$src" PATCHED_GET_PINNED_SHA256_START PATCHED_GET_PINNED_SHA256_END "$blk"; then
        chk "PATCHED_GET_PINNED_SHA256 block extracted from ${src:t}" 0
        continue
    fi
    source "$blk"
    out=$(get_pinned_sha256 slack 2>"$WORK/err"); rc=$?
    chk "get_pinned_sha256 returns NO_PIN (exit 3) despite a fresh valid pin on disk" "$(( rc == 3 ))"
    chk "get_pinned_sha256 prints no hash" "$([[ -z "$out" ]] && echo 1 || echo 0)"
    chk "get_pinned_sha256 logs the retirement refusal" \
        "$(grep -q 'install refused: catalogue retired (PAT-2245)' "$WORK/err" && echo 1 || echo 0)"
    chk "the ${src:t} pin reader block never references a catalogue file" \
        "$(grep -v '^#' "$blk" | grep -qE 'CATALOGUE_FILE|catalogue\.json|STATE_DIR' && echo 0 || echo 1)"
    unset -f get_pinned_sha256

    if grep -q PATCHED_GET_PINNED_CATALOGUE_METADATA_START "$src"; then
        mblk="$WORK/${src:t}.meta"
        extract "$src" PATCHED_GET_PINNED_CATALOGUE_METADATA_START PATCHED_GET_PINNED_CATALOGUE_METADATA_END "$mblk"
        source "$mblk"
        out=$(get_pinned_catalogue_metadata slack 2>"$WORK/err"); rc=$?
        chk "get_pinned_catalogue_metadata returns exit 3 despite a fresh valid entry" "$(( rc == 3 ))"
        chk "get_pinned_catalogue_metadata prints no hash or version" "$([[ -z "$out" ]] && echo 1 || echo 0)"
        chk "get_pinned_catalogue_metadata logs the retirement refusal" \
            "$(grep -q 'install refused: catalogue retired (PAT-2245)' "$WORK/err" && echo 1 || echo 0)"
        unset -f get_pinned_catalogue_metadata
    fi
done

echo
echo "=== source wiring ==="
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"
INSTALL_SH="$SCRIPT_DIR/patched-install.sh"
chk "patched-update.sh: NO_PIN sets the fail-closed flag" \
    "$(grep -qF '[[ $_pinned_rc -eq 3 ]]' "$UPDATE_SH" && grep -qF 'catalogue_unverified_failclosed=1' "$UPDATE_SH" && echo 1 || echo 0)"
chk "patched-update.sh: the fail-closed flag suppresses the engine" \
    "$(grep -qF '"$catalogue_unverified_failclosed" == 1' "$UPDATE_SH" && echo 1 || echo 0)"
chk "patched-install.sh: NO_PIN refuses the fresh install" \
    "$(grep -qF 'elif [[ $_pinned_rc -eq 3 ]]; then' "$INSTALL_SH" && grep -qF 'install refused: catalogue retired (PAT-2245). ' "$INSTALL_SH" && echo 1 || echo 0)"
chk "patched-install.sh: the refusal is reported as verification_blocked" \
    "$(grep -qF '*"install refused: catalogue retired"*' "$INSTALL_SH" && echo 1 || echo 0)"

echo
echo "=== TOTAL: $total_pass passed, $total_fail failed ==="
(( total_fail == 0 ))
