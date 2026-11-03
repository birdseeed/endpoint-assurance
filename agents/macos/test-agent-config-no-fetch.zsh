#!/bin/zsh
##############################################################################
# test-agent-config-no-fetch.zsh: PAT-1035 regression guard.
#
# macos/patched-upload.sh used to fetch and write its own unverified copy of
# agent-config.json (fetch_agent_config, PAT-552). PAT-1035 deleted that
# fetch; endpoint/patched-fetch-config.sh (Ed25519-verified) is now the only
# writer, and patched-upload.sh is a pure reader gated on that file's
# presence and freshness.
#
# This test is the tripwire: it asserts the shipped uploader (source) contains
# no request to GET /v1/agent-config and no write/move targeting
# agent-config.json. This is the specific regression PAT-1035 exists to
# prevent, so it must keep failing loudly if anyone re-adds the fetch.
#
# macos/build-bundle.sh does not produce dist/patched-upload.sh at this
# commit — bundling the uploader is PAT-1027's job, which inlines the
# lib/*.sh enforcement modules into the bundle (a bundle has no lib/
# directory at runtime) rather than copying patched-upload.sh verbatim. So
# this test does NOT build the bundle and does not require it to exist: if
# macos/dist/patched-upload.sh is present it runs the identical assertions
# against it too; if it is absent it says so loudly and moves on. See the
# "bundle: SKIPPED" branch below — that skip must never read as a quiet pass.
#
# Run: zsh macos/test-agent-config-no-fetch.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"
BUNDLE_SH="$SCRIPT_DIR/dist/patched-upload.sh"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# assert_no_fetch <label> <file>
#   Fails if <file> requests GET /v1/agent-config, or writes/moves anything
#   onto a path ending in agent-config.json (or the AC_CONFIG_FILE variable
#   that holds that same path). Matching is intentionally loose (no anchoring
#   to the old function name) so a rewritten fetch under a new name is still
#   caught.
#
# PAT-1035 round-3 review: the original write_hits pattern required the
# LITERAL string "agent-config.json" on an mv/cp line. The deleted code's
# actual line was `mv -f "$cfg_tmp" "$AC_CONFIG_FILE"` — the destination was
# the variable, not the literal filename — so that exact reintroduction would
# have passed the old guard while restoring the defect. The write_hits
# pattern below now also matches mv/cp (and redirects) whose DESTINATION is
# $AC_CONFIG_FILE, not just the literal filename. Destination is checked by
# anchoring the variable/filename at end-of-line (optionally followed by a
# trailing quote and/or a comment) so `cp "$AC_CONFIG_FILE" "$staged"` — the
# PAT-1035 finding-1 staging copy, which legitimately reads AC_CONFIG_FILE as
# its SOURCE, not its destination — does not false-positive.
assert_no_fetch() {
    local label="$1" file="$2"
    if [[ ! -f "$file" ]]; then
        chk "$label: file exists to check" 0
        return
    fi
    chk "$label: file exists to check" 1

    local request_hits write_hits
    request_hits=$(grep -nE '/v1/agent-config' "$file" 2>/dev/null)
    chk "$label: no reference to /v1/agent-config endpoint" "$([[ -z "$request_hits" ]] && echo 1 || echo 0)"
    [[ -n "$request_hits" ]] && echo "$request_hits"

    # mv/cp/redirect targeting AC_CONFIG_FILE-as-destination or the literal
    # agent-config.json path (the write side). Reading AC_CONFIG_FILE (as an
    # mv/cp SOURCE, or in a bare [[ -f ... ]]/shasum/variable-assignment
    # check) is excluded deliberately: reading the path is exactly what the
    # gate and the staging copy legitimately do; writing to it, or moving
    # something else onto it, is the regression this guards against.
    write_hits=$(grep -nE \
        '\b(mv|cp)\b.*(\$\{?AC_CONFIG_FILE\}?|agent-config\.json)"?[[:space:]]*\\?[[:space:]]*(#.*)?$|>>?[[:space:]]*"?\$?\{?AC_CONFIG_FILE|>>?[[:space:]]*"[^"]*agent-config\.json' \
        "$file" 2>/dev/null)
    chk "$label: no write/move targeting agent-config.json or \$AC_CONFIG_FILE" "$([[ -z "$write_hits" ]] && echo 1 || echo 0)"
    [[ -n "$write_hits" ]] && echo "$write_hits"
}

# assert_no_get <label> <file>
#   PAT-1035 round-3 review: request_hits above matches the literal substring
#   "/v1/agent-config" — it would miss a reintroduced fetch that assembles
#   the URL from a variable (e.g. an endpoint segment held in its own
#   variable and concatenated in), since that literal substring would never
#   appear together in the source. This is an allowlist check instead of a
#   blocklist one, so it does not depend on how the URL text is spelled: the
#   uploader is now a pure upload/enforcement process: PAT-1035 removed its
#   agent-config GET and PAT-1116 removed its posture GET. Any `-X GET` call,
#   to any target however its URL is built, is therefore a second fetch path
#   around a verified endpoint poller and must fail this guard.
assert_no_get() {
    local label="$1" file="$2"
    if [[ ! -f "$file" ]]; then
        chk "$label: file exists to check" 0
        return
    fi

    local get_lines get_count
    get_lines=$(grep -nE '\-X[[:space:]]+GET' "$file" 2>/dev/null)
    get_count=$(echo -n "$get_lines" | grep -c '^' 2>/dev/null)
    [[ -z "$get_lines" ]] && get_count=0
    chk "$label: no -X GET request in the uploader" "$([[ "$get_count" -eq 0 ]] && echo 1 || echo 0)"
    [[ "$get_count" -ne 0 ]] && echo "$get_lines"
}

echo "[1] source: macos/patched-upload.sh"
assert_no_fetch "source" "$UPLOAD_SH"
assert_no_get "source" "$UPLOAD_SH"

echo "[2] built bundle: macos/dist/patched-upload.sh"
if [[ -f "$BUNDLE_SH" ]]; then
    assert_no_fetch "bundle" "$BUNDLE_SH"
    assert_no_get "bundle" "$BUNDLE_SH"
else
    echo "  ################################################################"
    echo "  # SKIPPED: macos/dist/patched-upload.sh does not exist at this"
    echo "  # commit. build-bundle.sh does not produce a bundled uploader"
    echo "  # until PAT-1027 ships it (inlined lib/*.sh enforcement modules,"
    echo "  # not a verbatim copy). Only the SOURCE file was checked above —"
    echo "  # bundle coverage for this regression guard is NOT active."
    echo "  # This is expected right now, not a passing check: do not read"
    echo "  # this run as having verified the bundle."
    echo "  ################################################################"
fi

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
