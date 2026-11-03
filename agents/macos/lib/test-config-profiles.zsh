#!/bin/zsh
##############################################################################
# test-config-profiles.zsh — unit tests for the PAT-1667 configuration
# profiles / MDM server collector (collect_config_profiles) in
# config_profiles.sh.
#
# Sources the live function out of config_profiles.sh (no top-level side
# effects at source time) so the tests exercise the real code, not a copy.
# `_config_profiles_list_xml` is overridden per test case to drive the
# collector's inputs (a fixture plist, garbage output, simulated rate-limit
# text) without needing a real Mac in any of those states. Run:
#   zsh macos/lib/test-config-profiles.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/config_profiles.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# profile_field <json-array-file> <index> <field> -> value at profiles[index][field]
profile_field() {
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
v = d[int(sys.argv[2])].get(sys.argv[3])
print(v if v is not None else '')
" "$1" "$2" "$3"
}

# run_case <fixture-plist-xml-file-or-''> [<raw-text-override>] -- builds a
# fresh scratch STATE_DIR/PATCHED_TMPDIR pair (unless _KEEP_STATE_DIR is set
# by the caller, for the cache-carryover tests), points
# _config_profiles_list_xml at either a real fixture file's bytes or a raw
# literal string, then runs the real collector.
run_case() {
    local fixture="$1" raw_override="${2:-}"
    PATCHED_TMPDIR=$(mktemp -d)
    if [[ -z "${_KEEP_STATE_DIR:-}" ]]; then
        STATE_DIR=$(mktemp -d)
    fi

    if [[ -n "$raw_override" ]]; then
        eval "_config_profiles_list_xml() { _CONFIG_PROFILES_EXIT=1; printf '%s' '$raw_override'; }"
    else
        eval "_config_profiles_list_xml() { _CONFIG_PROFILES_EXIT=0; cat '$fixture'; }"
    fi

    collect_config_profiles
}

##############################################################################
# 1. Zero MDM enrollment: `profiles list -output stdout-xml` on an unenrolled
#    Mac returns an empty <dict/> (verified live on macOS 26.6.2) -- must
#    report absence cleanly, not error.
##############################################################################
echo "--- 1. Zero MDM enrollment (empty _computerlevel)"

EMPTY_FIXTURE=$(mktemp)
"$PYTHON3" -c "
import plistlib
with open('$EMPTY_FIXTURE', 'wb') as f:
    plistlib.dump({}, f)
"
run_case "$EMPTY_FIXTURE"

chk_eq "status ok" "ok" "$CONFIG_PROFILES_STATUS"
chk_eq "count zero" "0" "$CONFIG_PROFILES_COUNT"
chk_eq "mdm_server_url empty" "" "$MDM_SERVER_URL"
EMPTY_VALID=$("$PYTHON3" -c "import json; print('OK' if json.load(open('$CONFIG_PROFILES_JSON_TMP')) == [] else 'BAD')")
chk_eq "empty profiles serialise as []" "OK" "$EMPTY_VALID"

##############################################################################
# 2. Populated case: one device-scope profile carrying a com.apple.mdm
#    payload -> identifier/display_name/organization reported, ServerURL
#    extracted, small payload not capped. Also seeds the last-known-good
#    cache used by test 4.
##############################################################################
echo "--- 2. Populated profile with com.apple.mdm ServerURL"

CACHE_STATE_DIR=$(mktemp -d)
STATE_DIR="$CACHE_STATE_DIR"
_KEEP_STATE_DIR=1

POPULATED_FIXTURE=$(mktemp)
"$PYTHON3" -c "
import plistlib
pl = {
    '_computerlevel': [
        {
            'ProfileIdentifier': 'com.patched.test.mdm',
            'ProfileDisplayName': 'Test MDM Enrollment',
            'ProfileOrganization': 'Acme Corp',
            'ProfileItems': [
                {
                    'PayloadType': 'com.apple.mdm',
                    'PayloadContent': {'ServerURL': 'https://mdm.acme.example/mdm'},
                },
            ],
        },
    ],
}
with open('$POPULATED_FIXTURE', 'wb') as f:
    plistlib.dump(pl, f)
"
run_case "$POPULATED_FIXTURE"

chk_eq "status ok" "ok" "$CONFIG_PROFILES_STATUS"
chk_eq "count one" "1" "$CONFIG_PROFILES_COUNT"
chk_eq "mdm_server_url extracted" "https://mdm.acme.example/mdm" "$MDM_SERVER_URL"
chk_eq "identifier reported" "com.patched.test.mdm" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 identifier)"
chk_eq "display_name reported" "Test MDM Enrollment" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 display_name)"
chk_eq "organization reported" "Acme Corp" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 organization)"
chk_eq "small payload not capped" "False" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 payload_capped)"
chk_eq "cache file written" "yes" "$([[ -f "$CACHE_STATE_DIR/.config-profiles-last-good.json" ]] && echo yes || echo no)"

# Stop pinning STATE_DIR to the cache dir now that it's seeded -- test 3 must
# not overwrite CACHE_STATE_DIR's cache before test 4 reads it back.
unset _KEEP_STATE_DIR

##############################################################################
# 3. Oversized payload: a single ProfileItems payload well over the 2048-byte
#    cap must be truncated and flagged, never dropped or left to blow up the
#    payload.
##############################################################################
echo "--- 3. Oversized payload capped"

OVERSIZED_FIXTURE=$(mktemp)
"$PYTHON3" -c "
import plistlib
pl = {
    '_computerlevel': [
        {
            'ProfileIdentifier': 'com.patched.test.big',
            'ProfileDisplayName': 'Big Payload',
            'ProfileOrganization': 'Acme Corp',
            'ProfileItems': [
                {'PayloadType': 'com.apple.something', 'PayloadContent': {'blob': 'x' * 5000}},
            ],
        },
    ],
}
with open('$OVERSIZED_FIXTURE', 'wb') as f:
    plistlib.dump(pl, f)
"
run_case "$OVERSIZED_FIXTURE"

chk_eq "oversized payload flagged capped" "True" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 payload_capped)"
PAYLOAD_LEN=$("$PYTHON3" -c "
import json
d = json.load(open('$CONFIG_PROFILES_JSON_TMP'))
print(len(d[0]['payload'].encode('utf-8', errors='ignore')))
")
CAP_OK="no"
[[ "$PAYLOAD_LEN" -le 2048 ]] && CAP_OK="yes"
chk_eq "capped payload within 2048 bytes" "yes" "$CAP_OK"

##############################################################################
# 4. Rate-limited: `profiles list` returns non-plist text matching the
#    documented client-side rate-limiter wording. Must not fail the run and
#    must fall back to the last-known-good cache seeded by test 2 (still
#    pointed at CACHE_STATE_DIR).
##############################################################################
echo "--- 4. Rate-limited: falls back to last-known-good cache"

STATE_DIR="$CACHE_STATE_DIR"
_KEEP_STATE_DIR=1
run_case "" "Error: Fetch operation happened too quickly - try again later"
unset _KEEP_STATE_DIR

chk_eq "status rate_limited" "rate_limited" "$CONFIG_PROFILES_STATUS"
chk_eq "falls back to cached count" "1" "$CONFIG_PROFILES_COUNT"
chk_eq "falls back to cached mdm_server_url" "https://mdm.acme.example/mdm" "$MDM_SERVER_URL"
chk_eq "falls back to cached identifier" "com.patched.test.mdm" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 identifier)"

##############################################################################
# 5. Generic failure with no cache available: unparseable output that does
#    NOT match rate-limit wording (e.g. a future macOS format change) must
#    report "unavailable", not "rate_limited", and still produce valid empty
#    JSON rather than erroring.
##############################################################################
echo "--- 5. Generic unparseable output, no cache -> unavailable, empty, no crash"

run_case "" "profiles: unexpected internal error 42"

chk_eq "status unavailable" "unavailable" "$CONFIG_PROFILES_STATUS"
chk_eq "count zero with no cache" "0" "$CONFIG_PROFILES_COUNT"
GENERIC_VALID=$("$PYTHON3" -c "import json; print('OK' if json.load(open('$CONFIG_PROFILES_JSON_TMP')) == [] else 'BAD')")
chk_eq "falls back to empty array cleanly" "OK" "$GENERIC_VALID"

##############################################################################
# 6. A garbage (non-dict) entry mixed into _computerlevel alongside a valid
#    profile must be skipped, not abort the whole collection -- the valid
#    entry after it still gets processed and counted.
##############################################################################
echo "--- 6. Garbage entry in _computerlevel does not break the run"

MIXED_FIXTURE=$(mktemp)
"$PYTHON3" -c "
import plistlib
pl = {
    '_computerlevel': [
        'not-a-profile-dict',
        {
            'ProfileIdentifier': 'com.patched.test.after-garbage',
            'ProfileDisplayName': 'Survives Garbage Entry',
            'ProfileOrganization': 'Acme Corp',
            'ProfileItems': [],
        },
    ],
}
with open('$MIXED_FIXTURE', 'wb') as f:
    plistlib.dump(pl, f)
"
run_case "$MIXED_FIXTURE"

chk_eq "status still ok" "ok" "$CONFIG_PROFILES_STATUS"
chk_eq "garbage entry skipped, valid one counted" "1" "$CONFIG_PROFILES_COUNT"
chk_eq "valid entry after garbage still reported" "com.patched.test.after-garbage" "$(profile_field "$CONFIG_PROFILES_JSON_TMP" 0 identifier)"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
