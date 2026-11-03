#!/bin/zsh
##############################################################################
# test-hmac-v3.zsh: PAT-1154 v3 vector test.
#
# Proves every macOS v3 HMAC request signer in this repo reproduces the two
# authoritative test vectors, by extracting each function's REAL shipped
# source (not a hand-copied reimplementation) and running it against the
# vectors — so this test fails if any signer drifts from the canonical
# form:
#   signing_input = b"patched-hmac-v3\n" + METHOD + b"\n" + ENDPOINT_ID + b"\n" + TS + b"\n" + NONCE + b"\n" + BODY
#   signature_hex = lowercase_hex(HMAC_SHA256(secret_bytes, signing_input))
#
# Covers:
#   - endpoint/patched-install.sh       hmac_empty, compute_hmac
#   - endpoint/patched-uninstall.sh     hmac_empty, compute_hmac
#   - endpoint/patched-update.sh        compute_hmac
#   - endpoint/patched-log-upload.sh    compute_hmac
#   - endpoint/patched-decommission.sh  compute_hmac (PAT-1109 terminal
#                                        status report, reconciled to v3
#                                        under PAT-1109/PAT-1154)
#   - macos/patched-upload.sh           compute_hmac (also used, unmodified
#                                        call contract, by the browser/app
#                                        control lib/*.sh signers it sources)
#   - macos/patched-bootstrap.sh        bootstrap_hmac_hex_v3 (raw-key variant)
#   - endpoint/patched-fetch-posture.sh    inline GET signer
#   - endpoint/patched-fetch-config.sh     inline GET signer
#
# Run:
#   zsh endpoint/test-hmac-v3.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
PYTHON3="/usr/bin/python3"
ENDPOINT_DIR="$REPO_ROOT/endpoint"
MACOS_DIR="$REPO_ROOT/macos"

pass=0; fail=0
chk() {  # chk <desc> <actual> <expected>
    local desc="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
        echo "        got:      $actual"
        echo "        expected: $expected"
    fi
}

TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/patched-hmac-v3-test.XXXXXX")
trap 'rm -rf "$TMPROOT"' EXIT

# ── Authoritative PAT-1154 v3 vectors ───────────────────────────────────────
TS="1730000000"
NONCE="abc123nonce"
SECRET_ASCII="patched-test-secret"   # literal 19-byte string, NOT base64-decoded

BODY_A="$TMPROOT/body_a.json"
print -rn -- '{"hello":"world"}' > "$BODY_A"
EXPECT_A="e4825ff7d3d56103fb9904615eebb2a317cef582256f066a443bc66974cd75d4"

BODY_B="$TMPROOT/body_b.bin"
: > "$BODY_B"
EXPECT_B="868b6e53c5c2ba9cbf72d0af25e06157eed1fff7ca68148412c2dd0952295d3f"

# Secret file storing base64(SECRET_ASCII) — matches every compute_hmac /
# hmac_empty / inline GET signer, which all base64-decode the credential
# file's contents before use.
SECRET_B64_FILE="$TMPROOT/hmac-secret-b64"
"$PYTHON3" -c 'import base64,sys; open(sys.argv[1],"wb").write(base64.b64encode(sys.argv[2].encode("ascii")))' \
    "$SECRET_B64_FILE" "$SECRET_ASCII"

# Secret file storing the RAW ascii bytes — matches macos/patched-bootstrap.sh's
# bootstrap_hmac_hex_v3, which reads the key file directly (CR/LF stripped,
# no base64 decode), same as its prior bootstrap_hmac_hex.
SECRET_RAW_FILE="$TMPROOT/hmac-secret-raw"
print -rn -- "$SECRET_ASCII" > "$SECRET_RAW_FILE"

# Extracts a shell function named <fn> from <file> (from "<fn>() {" through
# the matching top-level "}") into $TMPROOT/<fn>-<tag>.zsh and sources it.
# Assumes (true for every function below) the function body's heredoc never
# contains a line that is exactly "}" — verified by inspection.
extract_fn() {  # extract_fn <file> <fn> <tag>
    local file="$1" fn="$2" tag="$3"
    local out="$TMPROOT/${fn}-${tag}.zsh"
    sed -n "/^${fn}() {/,/^}/p" "$file" > "$out"
    if [[ ! -s "$out" ]]; then
        echo "FATAL: could not extract ${fn}() from $file"
        exit 1
    fi
    source "$out"
}

# Extracts the inline HMACV3PYEOF-delimited python snippet from <file> into
# a standalone script at $TMPROOT/<tag>.py.
extract_inline_py() {  # extract_inline_py <file> <tag>
    local file="$1" tag="$2"
    local out="$TMPROOT/${tag}.py"
    sed -n "/<<'HMACV3PYEOF'/,/^HMACV3PYEOF$/p" "$file" | sed '1d;$d' > "$out"
    if [[ ! -s "$out" ]]; then
        echo "FATAL: could not extract HMACV3PYEOF snippet from $file"
        exit 1
    fi
    print -r -- "$out"
}

# ── Group 1: compute_hmac(body, ts, nonce) — base64 secret ─────────────────
for spec in \
    "endpoint/patched-install.sh:install" \
    "endpoint/patched-uninstall.sh:uninstall" \
    "endpoint/patched-update.sh:update" \
    "endpoint/patched-log-upload.sh:log-upload" \
    "endpoint/patched-decommission.sh:decommission" \
    "macos/patched-upload.sh:upload" \
    ; do
    relfile="${spec%%:*}"; tag="${spec##*:}"
    absfile="$REPO_ROOT/$relfile"
    CREDS_DIR="$TMPROOT"
    cp "$SECRET_B64_FILE" "$CREDS_DIR/hmac-secret"
    unfunction compute_hmac 2>/dev/null
    extract_fn "$absfile" "compute_hmac" "$tag"
    got_a=$(compute_hmac "$BODY_A" "inventory" "$TS" "$NONCE")
    chk "$relfile compute_hmac vector A" "$got_a" "$EXPECT_A"
    got_diff_nonce=$(compute_hmac "$BODY_A" "inventory" "$TS" "different-nonce")
    chk "$relfile compute_hmac binds nonce (differs from vector A)" \
        "$([[ "$got_diff_nonce" != "$EXPECT_A" ]] && echo "unbound" || echo "$got_diff_nonce")" "unbound"
    got_other_endpoint=$(compute_hmac "$BODY_A" "provenance" "$TS" "$NONCE")
    chk "$relfile compute_hmac binds endpoint ID (differs from inventory)" \
        "$([[ "$got_other_endpoint" != "$EXPECT_A" ]] && echo "bound" || echo "$got_other_endpoint")" "bound"
    unfunction compute_hmac 2>/dev/null
done

# ── Group 2: hmac_empty(ts, nonce) — base64 secret, GET/empty-body ─────────
for spec in \
    "endpoint/patched-install.sh:install" \
    "endpoint/patched-uninstall.sh:uninstall" \
    ; do
    relfile="${spec%%:*}"; tag="${spec##*:}"
    absfile="$REPO_ROOT/$relfile"
    CREDS_DIR="$TMPROOT"
    cp "$SECRET_B64_FILE" "$CREDS_DIR/hmac-secret"
    unfunction hmac_empty 2>/dev/null
    extract_fn "$absfile" "hmac_empty" "$tag"
    got_b=$(hmac_empty "agent_config" "$TS" "$NONCE")
    chk "$relfile hmac_empty vector B" "$got_b" "$EXPECT_B"
    unfunction hmac_empty 2>/dev/null
done

# ── Group 3: macos/patched-bootstrap.sh bootstrap_hmac_hex_v3 — raw secret ──
BOOTSTRAP_SH="$MACOS_DIR/patched-bootstrap.sh"
extract_fn "$BOOTSTRAP_SH" "bootstrap_hmac_hex_v3" "bootstrap"
got_a=$(bootstrap_hmac_hex_v3 "$BODY_A" "POST" "inventory" "$TS" "$NONCE" "$SECRET_RAW_FILE")
chk "macos/patched-bootstrap.sh bootstrap_hmac_hex_v3 vector A" "$got_a" "$EXPECT_A"
got_b=$(bootstrap_hmac_hex_v3 "$BODY_B" "GET" "agent_config" "$TS" "$NONCE" "$SECRET_RAW_FILE")
chk "macos/patched-bootstrap.sh bootstrap_hmac_hex_v3 vector B" "$got_b" "$EXPECT_B"
got_other_method=$(bootstrap_hmac_hex_v3 "$BODY_A" "GET" "inventory" "$TS" "$NONCE" "$SECRET_RAW_FILE")
chk "macos/patched-bootstrap.sh bootstrap_hmac_hex_v3 binds method" \
    "$([[ "$got_other_method" != "$EXPECT_A" ]] && echo "bound" || echo "$got_other_method")" "bound"

# ── Group 4: inline GET-only signers (posture / config) ──
for spec in \
    "endpoint/patched-fetch-posture.sh:posture" \
    "endpoint/patched-fetch-config.sh:config" \
    ; do
    relfile="${spec%%:*}"; tag="${spec##*:}"
    absfile="$REPO_ROOT/$relfile"
    py_file=$(extract_inline_py "$absfile" "$tag")
    got_b=$("$PYTHON3" "$py_file" "$TS" "$NONCE" "$SECRET_B64_FILE")
    case "$tag" in
        posture) expected="3c88374e96ae1df1d280e6dc4e96eae8fe8918eb008bcbdbe4f92d0dcde96b10" ;;
        config) expected="$EXPECT_B" ;;
    esac
    chk "$relfile inline signer vector B (empty body)" "$got_b" "$expected"
done

echo ""
echo "hmac-v3 vector tests: $pass passed, $fail failed"
(( fail == 0 )) || exit 1
