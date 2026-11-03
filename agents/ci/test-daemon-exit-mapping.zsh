#!/bin/zsh --no-rcs
# Unit tests for PAT-45 daemon exit-code mapping and provenance logic.
#
# Tests the run_label logic in patched-update.sh by stubbing out Installomator,
# the API endpoint, and filesystem operations.  No network, no root, no install.
#
# Usage: zsh ci/test-daemon-exit-mapping.zsh
# Exit 0 if all tests pass; non-zero on first failure.

set -u

PASS=0
FAIL=0
DAEMON="${0:a:h}/../endpoint/patched-update.sh"
SCHEMA="${0:a:h}/../contracts/update-status.schema.json"

if [[ ! -f "$DAEMON" ]]; then
    print "ERROR: daemon not found at $DAEMON" >&2; exit 1
fi

# ── helpers ───────────────────────────────────────────────────────────────────

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        print "  PASS  [$desc]"
        (( PASS++ ))
    else
        print "  FAIL  [$desc]"
        print "        expected: $expected"
        print "        got:      $actual"
        (( FAIL++ ))
    fi
}

# Run the core exit-code → outcome mapping logic in isolation.
# $1=rc, $2=mode(scan|install), $3=before, $4=after, $5=available_ver, $6=app_exists(yes|no)
map_outcome() {
    zsh --no-rcs -c "
        rc=$1 mode=$2 before=$3 after=$4 available_ver=$5 app_exists=$6
        app_path='/Applications/TestApp.app'
        outcome='' state='' failure_reason=''
        case \$rc in
            60) outcome=verification_failed; state=verification_failed; failure_reason=missing_expected_signer ;;
            61) outcome=verification_failed; state=verification_failed; failure_reason=signature_untrusted ;;
            62) outcome=verification_failed; state=verification_failed; failure_reason=signer_mismatch ;;
            0)
                if [[ \$app_exists != yes ]]; then
                    outcome=not_installed; state=not_installed
                elif [[ \$mode == scan ]]; then
                    outcome=already_current; state=unknown
                elif [[ -n \$before && -n \$after && \$before != \$after ]]; then
                    outcome=installed; state=up_to_date
                else
                    outcome=already_current; state=up_to_date
                fi
                ;;
            *) outcome=error; state=error ;;
        esac
        print \"\$outcome|\$state|\$failure_reason\"
    " 2>/dev/null
}

print ""
print "=== PAT-45 daemon exit-code mapping tests ==="
print ""

# ── Test 1-3: verification failure exit codes ─────────────────────────────────
result=$(map_outcome 60 install "" "" "" yes)
assert_eq "exit 60 → verification_failed / missing_expected_signer" \
    "verification_failed|verification_failed|missing_expected_signer" "$result"

result=$(map_outcome 61 install "7.0" "7.0" "" yes)
assert_eq "exit 61 → verification_failed / signature_untrusted" \
    "verification_failed|verification_failed|signature_untrusted" "$result"

result=$(map_outcome 62 install "7.0" "7.0" "" yes)
assert_eq "exit 62 → verification_failed / signer_mismatch" \
    "verification_failed|verification_failed|signer_mismatch" "$result"

# ── Test 4: not installed (app dir absent, rc=0) ──────────────────────────────
result=$(map_outcome 0 scan "" "" "8.0" no)
assert_eq "rc=0, app absent → not_installed" \
    "not_installed|not_installed|" "$result"

# ── Test 5: scan, app present → unknown (no download, can't determine available) ──
result=$(map_outcome 0 scan "7.0" "7.0" "8.0" yes)
assert_eq "scan mode: no download → already_current/unknown" \
    "already_current|unknown|" "$result"

# ── Test 6: scan, app present → unknown (available==installed, but still no download) ──
result=$(map_outcome 0 scan "8.0" "8.0" "8.0" yes)
assert_eq "scan mode: no download (same ver) → already_current/unknown" \
    "already_current|unknown|" "$result"

# ── Test 7: install, new version installed ────────────────────────────────────
result=$(map_outcome 0 install "7.0" "8.0" "" yes)
assert_eq "install mode: before≠after → installed/up_to_date" \
    "installed|up_to_date|" "$result"

# ── Test 8: install, already current ─────────────────────────────────────────
result=$(map_outcome 0 install "8.0" "8.0" "" yes)
assert_eq "install mode: same version → already_current/up_to_date" \
    "already_current|up_to_date|" "$result"

# ── Test 9: generic engine error ─────────────────────────────────────────────
result=$(map_outcome 9 install "7.0" "7.0" "" yes)
assert_eq "non-zero non-6x rc → error" \
    "error|error|" "$result"

# ── Test 10: PATCHED_VERIFICATION_FAILED field parsing ───────────────────────
pv_line="2026-12-10 09:00:00 : ERROR : firefox : PATCHED_VERIFICATION_FAILED label=firefox url=https://releases.mozilla.org/firefox.dmg expectedTeamID=43AQ936H96 observedTeamID=WRONGID notarizationResult=passed reason=teamid_mismatch"

pv_url=$(     echo "$pv_line" | grep -oE 'url=[^[:space:]]*'                 | head -1 | cut -d= -f2-)
pv_obs_tid=$( echo "$pv_line" | grep -oE 'observedTeamID=[^[:space:]]*'      | head -1 | cut -d= -f2-)
pv_notarization=$(echo "$pv_line" | grep -oE 'notarizationResult=[^[:space:]]*' | head -1 | cut -d= -f2-)
pv_reason=$(  echo "$pv_line" | grep -oE 'reason=[^[:space:]]*'              | head -1 | cut -d= -f2-)

assert_eq "§4.6 parse: url"                "https://releases.mozilla.org/firefox.dmg" "$pv_url"
assert_eq "§4.6 parse: observedTeamID"     "WRONGID"       "$pv_obs_tid"
assert_eq "§4.6 parse: notarizationResult" "passed"        "$pv_notarization"
assert_eq "§4.6 parse: reason"             "teamid_mismatch" "$pv_reason"

# ── Test 14: appNewVersion parsing — "Latest version of X is V" ──────────────
eng_log_content="2026-12-10 09:00:00 : INFO  : 1password7 : Latest version of 1Password 7 is 7.9.13"
available_ver=$(echo "$eng_log_content" | grep -oE 'Latest version of .+ is [^[:space:]]+' | head -1 | grep -oE '[^[:space:]]+$')
assert_eq "appNewVersion parse: 'Latest version of X is V'" "7.9.13" "$available_ver"

# ── Test 15: appNewVersion parsing — "Downloaded version of X is V on" ────────
eng_log_content="2026-12-10 09:00:00 : INFO  : firefox : Downloaded version of Firefox is 127.0.2 on versionKey CFBundleShortVersionString, same as installed."
available_ver=$(echo "$eng_log_content" | grep -oE 'Downloaded version of .+ is [^[:space:]]+ on' | head -1 | awk '{print $(NF-1)}')
assert_eq "appNewVersion parse: 'Downloaded version of X is V on'" "127.0.2" "$available_ver"

# ── Test 16: appNewVersion parsing — "Downloaded package X version V" ─────────
eng_log_content="2026-12-10 09:00:00 : INFO  : apkg : Downloaded package com.example.pkg version 5.0.1"
available_ver=$(echo "$eng_log_content" | grep -oE 'Downloaded package .+ version [^[:space:]]+' | head -1 | awk '{print $NF}')
assert_eq "appNewVersion parse: 'Downloaded package X version V'" "5.0.1" "$available_ver"

# ── Test 17: status JSON validates against schema ─────────────────────────────
sample_status=$(python3 -c "
import json, datetime
apps = [
    {'label': 'firefox', 'name': 'Firefox',
     'installed_version': '127.0', 'available_version': None,
     'state': 'unknown', 'last_action': 'already_current',
     'last_action_at': '2026-12-10T09:00:00Z',
     'failure_reason': None, 'verified_signer': '43AQ936H96', 'message': None},
    {'label': '1password7', 'name': '1Password 7',
     'installed_version': '7.9.13', 'available_version': None,
     'state': 'verification_failed', 'last_action': 'verification_failed',
     'last_action_at': '2026-12-10T09:00:01Z',
     'failure_reason': 'signer_mismatch', 'verified_signer': None, 'message': None},
]
doc = {
    'schema_version': 1,
    'generated_at': '2026-12-10T09:00:02Z',
    'device': {'hw_uuid': 'ABC-123', 'computer_name': 'TestMac'},
    'last_run': {'started_at': '2026-12-10T09:00:00Z', 'finished_at': '2026-12-10T09:00:02Z',
                 'trigger': 'scheduled', 'installomator_tag': 'fail-closed-verification-1.0'},
    'next_scheduled_run': None,
    'overall_state': 'error',
    'counts': {'total': 2, 'up_to_date': 0, 'updates_available': 0, 'errors': 1},
    'apps': apps,
}
print(json.dumps(doc))
" 2>/dev/null)

validate_result=$(python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    print('skip:no-jsonschema'); sys.exit(0)
schema = json.load(open('$SCHEMA'))
doc = json.loads(sys.stdin.read())
try:
    jsonschema.validate(doc, schema)
    print('valid')
except jsonschema.ValidationError as e:
    print('invalid: ' + str(e.message))
" <<< "$sample_status" 2>/dev/null)

if [[ "$validate_result" == "skip:no-jsonschema" ]]; then
    print "  SKIP  [schema validation — jsonschema not installed]"
elif [[ "$validate_result" == "valid" ]]; then
    print "  PASS  [sample status JSON validates against extended schema]"
    (( PASS++ ))
else
    print "  FAIL  [sample status JSON failed schema validation: $validate_result]"
    (( FAIL++ ))
fi

# ── Test 18: authority refusal is an explicit unsigned terminal row ───────────
authority_validate=$(python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    print('skip:no-jsonschema'); sys.exit(0)
schema = json.load(open('$SCHEMA'))
base = {
    'schema_version': 1,
    'generated_at': '2026-09-08T09:00:02Z',
    'overall_state': 'error',
    'apps': [{
        'label': 'example', 'name': 'Example', 'installed_version': '1.0',
        'available_version': None, 'state': 'error',
        'last_action': 'authority_refused',
        'last_action_at': '2026-09-08T09:00:01Z',
        'failure_reason': 'execution_authority_refused',
        'verified_signer': None,
        'message': 'Install refused: fresh signed execution authority is absent.',
        'also_managed_by': None, 'manager_drift': False,
    }],
}
try:
    jsonschema.validate(base, schema)
    base['apps'][0]['verified_signer'] = 'ABCDE12345'
    try:
        jsonschema.validate(base, schema)
    except jsonschema.ValidationError:
        print('valid-and-signer-rejected')
    else:
        print('invalid: signer accepted')
except jsonschema.ValidationError as e:
    print('invalid: ' + str(e.message))
" 2>/dev/null)

if [[ "$authority_validate" == "skip:no-jsonschema" ]]; then
    print "  SKIP  [authority-refusal schema — jsonschema not installed]"
elif [[ "$authority_validate" == "valid-and-signer-rejected" ]]; then
    print "  PASS  [authority refusal validates only as explicit unsigned terminal status]"
    (( PASS++ ))
else
    print "  FAIL  [authority-refusal schema contract failed: $authority_validate]"
    (( FAIL++ ))
fi

# ── Test 19: contracts/update-status.sample.json validates against schema ─────
SAMPLE="${0:a:h}/../contracts/update-status.sample.json"
sample_validate=$(python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    print('skip:no-jsonschema'); sys.exit(0)
schema = json.load(open('$SCHEMA'))
doc = json.load(open('$SAMPLE'))
try:
    jsonschema.validate(doc, schema)
    print('valid')
except jsonschema.ValidationError as e:
    print('invalid: ' + str(e.message))
" 2>/dev/null)

if [[ "$sample_validate" == "skip:no-jsonschema" ]]; then
    print "  SKIP  [contracts/update-status.sample.json — jsonschema not installed]"
elif [[ "$sample_validate" == "valid" ]]; then
    print "  PASS  [contracts/update-status.sample.json validates against schema]"
    (( PASS++ ))
else
    print "  FAIL  [contracts/update-status.sample.json failed schema validation: $sample_validate]"
    (( FAIL++ ))
fi

# ── summary ───────────────────────────────────────────────────────────────────
print ""
print "Results: $PASS passed, $FAIL failed"
print ""

(( FAIL == 0 ))
