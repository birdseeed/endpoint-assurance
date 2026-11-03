#!/bin/zsh
##############################################################################
# test-device-id-header-wordsplit.zsh — PAT-1206 regression guard.
#
# THE BUG: every curl call site that attaches the device-id header built it
# as an unquoted, unbraced-array construct:
#
#   ${HW_UUID:+-H "X-Patched-Device-Id: $HW_UUID"}
#
# Under POSIX sh this word-splits into exactly TWO argv words — `-H` and
# `X-Patched-Device-Id: <uuid>` (the header value survives as one word
# because of its OWN inner quotes) — which is what these scripts were
# written and tested against. But every one of these scripts has
# `#!/bin/zsh`, and zsh does NOT word-split unquoted parameter expansions by
# default. So in production zsh passes curl a SINGLE malformed argv word,
# `-H X-Patched-Device-Id: <uuid>`, corrupting the request. The server's
# HMAC verification then fails ("signature does not match") and
# agent-config returns 401 — this has broken agent-config for every macOS
# agent since the device-id header shipped (PAT-1026). Proven by hand:
# same script under `sh` -> accepted; under `zsh` -> 401; `setopt
# shwordsplit` fixes it (not used here — see the fix below).
#
# THE FIX: each call site now builds a zsh array immediately before the
# curl call and expands it quoted ("${device_hdr[@]}"), so each element is
# always its own argv word regardless of the running shell's word-splitting
# behaviour:
#
#   device_hdr=()
#   [[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")
#   ... "${device_hdr[@]}" ...
#
# THIS TEST runs the SHIPPED endpoint/patched-fetch-config.sh as a real zsh
# subprocess (not a hand-rolled reproduction) with a fake `curl` on PATH
# that records every argv element it actually receives, one per line — the
# only way to observe whether the shell handed curl one glued word or two
# clean ones. It must FAIL against the old
# `${HW_UUID:+-H "X-Patched-Device-Id: $HW_UUID"}` construct and PASS after
# the fix (verified by hand: reverting the fix flips both [1] assertions
# from PASS to FAIL).
#
# Only patched-fetch-config.sh is driven end-to-end here; the other eight
# call sites listed in PAT-1206 use the exact same
# `device_hdr=(); [[ -n "$HW_UUID" ]] && device_hdr=(...)` pattern and are
# covered by the static grep assertions in section [3] below, which fail if
# any of them regresses back to the bare `${HW_UUID:+...}` construct.
#
# The script's own `export PATH=...` prelude puts /usr/bin (real curl)
# ahead of anything inherited, so a plain PATH-prepend would not reach our
# stub — a scratch copy with that one line rewritten is used instead, same
# idiom as endpoint/test-mktemp-symlink-refusal.zsh's log-upload section.
# ioreg is stubbed too: it is what the real script uses to populate
# $HW_UUID, and stubbing it is the only way to deterministically drive both
# the HW_UUID-set and HW_UUID-empty cases on one machine.
#
# Run: zsh endpoint/test-device-id-header-wordsplit.zsh
##############################################################################

set -u
export PATCHED_API_URL="http://127.0.0.1:1"

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-fetch-config.sh"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.pat1206-wordsplit-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

BUNDLE_DIR="$WORK/bundle"
STATE_DIR="$WORK/state"
CREDS_DIR="$WORK/creds"
STUB_BIN="$WORK/stubbin"
mkdir -p "$BUNDLE_DIR" "$STATE_DIR" "$CREDS_DIR" "$STUB_BIN"
# PAT-1763: the real shared floor parser; the If-None-Match branch this test
# reaches depends on it classifying the floor below.
cp "$SCRIPT_DIR/agent_config_floor.py" "$BUNDLE_DIR/agent_config_floor.py"

printf '11111111-1111-1111-1111-111111111111\n' > "$CREDS_DIR/tenant-id"
printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$CREDS_DIR/hmac-secret"

# ---------------------------------------------------------------------------
# Stub curl: records every argv element it receives, one per line, then
# answers 304 (consuming stdin first — patched_curl_bearer pipes the bearer
# token in over stdin via `-H @-`, and a stub that never reads it would hang
# the real curl's stdin producer... except here the producer is a `printf`,
# not curl, so this just keeps behaviour clean either way).
# ---------------------------------------------------------------------------
cat > "$STUB_BIN/curl" <<'STUBEOF'
#!/bin/sh
: > "$CURL_ARGV_CAPTURE"
for a in "$@"; do
    printf '%s\n' "$a" >> "$CURL_ARGV_CAPTURE"
done
cat > /dev/null
prev=""
out=""
for a in "$@"; do
    [ "$prev" = "-o" ] && out="$a"
    prev="$a"
done
[ -n "$out" ] && printf '{}' > "$out"
printf '304'
exit 0
STUBEOF
chmod +x "$STUB_BIN/curl"

# ---------------------------------------------------------------------------
# Stub ioreg: the real script populates $HW_UUID from this. Emits a fake
# IOPlatformUUID line (shaped exactly like real ioreg -rd1 output) when
# FAKE_HW_UUID is set, or nothing (-> HW_UUID="") when it is not.
# ---------------------------------------------------------------------------
cat > "$STUB_BIN/ioreg" <<'STUBEOF'
#!/bin/sh
if [ -n "${FAKE_HW_UUID:-}" ]; then
    printf '    | "IOPlatformUUID" = "%s"\n' "$FAKE_HW_UUID"
fi
exit 0
STUBEOF
chmod +x "$STUB_BIN/ioreg"

# Scratch copy of the real script with only its `export PATH=...` prelude
# rewritten, so our stub bin dir is actually reachable ahead of the real
# /usr/bin/curl and /usr/sbin/ioreg. Nothing else in the script is touched —
# the code under test is the shipped code.
COPY="$WORK/patched-fetch-config.sh"
/usr/bin/python3 "$SCRIPT_DIR/../ci/privileged_script_fixture.py" "$TARGET" "$COPY" "$STUB_BIN" || exit 1

# run_fetch_config <fake-hw-uuid|""> <argv-capture-file> <"withversion"|"noversion">
run_fetch_config() {
    local fake_uuid="$1" capture="$2" version_mode="$3"

    rm -rf "$STATE_DIR"; mkdir -p "$STATE_DIR"
    if [[ "$version_mode" == "withversion" ]]; then
        # PAT-1756: If-None-Match is sent only from a floor keyed to the enrolled tenant.
        printf '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":5}' > "$STATE_DIR/agent-config.version"
    fi

    CURL_ARGV_CAPTURE="$capture" \
    FAKE_HW_UUID="$fake_uuid" \
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="http://127.0.0.1:1" \
    PATCHED_LOG_FILE="$WORK/patched-update.log" \
    PATCHED_JSONL_LOG_DIR="$WORK/jsonl-logs" \
    PATH="$STUB_BIN:/usr/bin:/bin:/usr/sbin:/sbin" \
        zsh "$COPY" >"$WORK/last-run.log" 2>&1
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] HW_UUID set: -H and the device-id header land as two separate argv words"
argv1="$WORK/argv-set.txt"
run_fetch_config "DEVICE-UUID-4242" "$argv1" "noversion"

chk "argv capture file was written (curl stub actually ran)" \
    "$([[ -s "$argv1" ]] && echo 1 || echo 0)"
chk "'-H' appears as its own argv line" \
    "$(grep -qxF -- '-H' "$argv1" && echo 1 || echo 0)"
chk "'X-Patched-Device-Id: DEVICE-UUID-4242' appears as its own argv line" \
    "$(grep -qxF -- 'X-Patched-Device-Id: DEVICE-UUID-4242' "$argv1" && echo 1 || echo 0)"
chk "the glued, word-split-broken form is NOT present as a single argv element" \
    "$(grep -qxF -- '-H X-Patched-Device-Id: DEVICE-UUID-4242' "$argv1" && echo 0 || echo 1)"
# Belt and braces: the glued substring must not appear anywhere at all, not
# just fail the exact-line match above.
chk "no argv line even CONTAINS the glued '-H X-Patched-Device-Id:' text" \
    "$(grep -qF -- '-H X-Patched-Device-Id:' "$argv1" && echo 0 || echo 1)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] HW_UUID empty: no device-id header at all (not a stray -H or empty header)"
argv2="$WORK/argv-empty.txt"
run_fetch_config "" "$argv2" "withversion"

chk "argv capture file was written (curl stub actually ran)" \
    "$([[ -s "$argv2" ]] && echo 1 || echo 0)"
chk "no 'X-Patched-Device-Id' header present when HW_UUID is empty" \
    "$(grep -qF -- 'X-Patched-Device-Id' "$argv2" && echo 0 || echo 1)"
# The array must genuinely be empty in this case, not `("")`  — an empty
# array element would show up as a stray blank argv line right after the
# last real flag and before the URL/Accept header, which is exactly the
# kind of subtle breakage `"${device_hdr[@]}"` (vs `"${device_hdr}"`)
# guards against.
chk "no stray blank argv element from an empty device_hdr array" \
    "$(grep -qxF -- '' "$argv2" && echo 0 || echo 1)"
# And the with-version branch (If-None-Match) still worked, proving both
# curl call sites in patched-fetch-config.sh run through the fixed
# construct, not just one of them.
chk "If-None-Match header present (with-version branch reached)" \
    "$(grep -qF -- 'If-None-Match: "5"' "$argv2" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] static guard: no remaining bare \${HW_UUID:+...} construct anywhere in endpoint/ or macos/"
# The exact class of bug PAT-1206 fixes: an unquoted, unbraced \${VAR:+...}
# whose alternate text embeds a literal space outside its own inner quotes.
# Every call site PAT-1206 touched used this construct for the device-id
# header specifically; this guards all of them at once, plus any that get
# added later by copy-paste.
bad_sites=$(grep -rn '\${HW_UUID:+' "$SCRIPT_DIR" "$SCRIPT_DIR/../macos" \
    --exclude='test-device-id-header-wordsplit.zsh' 2>/dev/null)
chk "no file under endpoint/ or macos/ still uses the bare \${HW_UUID:+...} construct" \
    "$([[ -z "$bad_sites" ]] && echo 1 || echo 0)"
if [[ -n "$bad_sites" ]]; then
    echo "$bad_sites"
fi

# ============================================================================
echo "\n============================================"
echo "PASS: $pass   FAIL: $fail"
echo "============================================"
[[ "$fail" -eq 0 ]] || exit 1
exit 0
