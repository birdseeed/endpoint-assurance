#!/bin/zsh
##############################################################################
# test-app-control.zsh — unit tests for the PAT-880 "last admin" floor fix in
# ac_enforce_admins (app_control.sh).
#
# Sources the live function out of app_control.sh (no top-level side effects
# at source time) so the tests exercise the real code, not a copy. dscl and
# stat are shadowed with zsh functions of the same name before sourcing —
# zsh resolves a function before an external command, so ac_enforce_admins's
# calls to `dscl . -read /Groups/admin GroupMembership` and
# `stat -f %Su /dev/console` transparently hit the fixture instead of the
# real machine's admin group / console user. PATCHED_DRY_RUN=1 keeps every
# case non-destructive (no real dscl -delete, no network POST). Run:
#   zsh macos/lib/test-app-control.zsh
#
# Background: PAT-880 replaced the "keep >= 1 admin" floor's basis. It used
# to count the TOTAL admin-group membership (_admin_count, including root /
# _mbsetupuser / the console user) instead of the removable pool. The fixed
# code (_removable_count + _protected_present) computes the floor from the
# removable pool only, and skips the floor entirely once any protected
# account is confirmed present (root / _mbsetupuser / console user already
# guarantees an admin remains). See app_control.sh:_ac_is_protected_admin.
#
# PAT-1417 addition: cases (g) onward cover the enforcement-audit POST
# outcome now being recorded into the shared agent-health store (PAT-1065)
# instead of only logged and dropped. These run ac_enforce_admins /
# ac_check_app_violations with PATCHED_DRY_RUN=0 (dry-run returns before the
# POST is ever reached) and shadow compute_hmac / patched_curl_bearer the
# same way dscl/stat are shadowed above, so the real POST-outcome case
# statement in app_control.sh runs against a controlled fake HTTP response
# instead of a real network call.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

# ── Fixture doubles for dscl/stat, set per-case via run_case() ─────────────
MOCK_DSCL_MEMBERS=""
MOCK_CONSOLE_USER=""
dscl() { print -r -- "GroupMembership: $MOCK_DSCL_MEMBERS"; }
stat() { print -r -- "$MOCK_CONSOLE_USER"; }

# ── Fixture doubles for compute_hmac/patched_curl_bearer, set per-case via
# run_case_live() / run_violation_case_live() below. Neither is exercised by
# the dry-run cases (a)-(f) above (dry-run returns before either is called),
# only by the PAT-1417 live-POST cases (g) onward.
MOCK_HTTP_CODE=""
compute_hmac() { print -rn -- "test-signature"; return 0; }
patched_curl_bearer() {
    # MOCK_HTTP_CODE="NETWORK_ERROR" simulates curl itself failing (timeout,
    # DNS, connection refused) - no stdout, non-zero exit - matching how
    # app_control.sh's own `|| _http_code=""` fallback behaves for a real
    # network failure.
    if [[ "$MOCK_HTTP_CODE" == "NETWORK_ERROR" ]]; then
        return 1
    fi
    print -rn -- "$MOCK_HTTP_CODE"
    return 0
}

# Required by ac_enforce_admins/ac_check_app_violations under `set -u` once
# they reach the live POST path; the shadowed patched_curl_bearer above
# ignores their actual values.
API_URL="https://api.test.invalid"
BEARER_TOKEN="test-bearer-token"
CREDS_DIR="/tmp"
HW_UUID="TEST-HW-UUID"

source "$SCRIPT_DIR/app_control.sh"
source "$SCRIPT_DIR/agent_health.sh"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

CASE_OUTPUT=""

# run_case <dscl-members> <console-user> <approved-admins-json-array>
# Runs ac_enforce_admins in dry-run mode against the fixture and captures
# its combined stdout/stderr into $CASE_OUTPUT for assertions.
run_case() {
    MOCK_DSCL_MEMBERS="$1"
    MOCK_CONSOLE_USER="$2"
    local approved_json="$3"

    local cfg
    cfg=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-cfg.XXXXXX")
    printf '{"app_control": {"enabled": true, "approved_admins": %s}}' "$approved_json" > "$cfg"

    PATCHED_AC_CONFIG="$cfg"
    PATCHED_DRY_RUN=1
    CASE_OUTPUT=$(ac_enforce_admins 2>&1)
    rm -f "$cfg"
}

run_raw_config_case() {  # run_raw_config_case <raw config JSON>
    MOCK_DSCL_MEMBERS="bob carol"
    MOCK_CONSOLE_USER=""
    local cfg
    cfg=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-cfg.XXXXXX")
    print -r -- "$1" > "$cfg"
    PATCHED_AC_CONFIG="$cfg"
    PATCHED_DRY_RUN=1
    CASE_OUTPUT=$(ac_enforce_admins 2>&1)
    rm -f "$cfg"
}

run_raw_allowlist_config_case() {  # run_raw_allowlist_config_case <raw config JSON>
    local cfg
    cfg=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-cfg.XXXXXX")
    print -r -- "$1" > "$cfg"
    PATCHED_AC_CONFIG="$cfg"
    PATCHED_DRY_RUN=1
    CASE_OUTPUT=$(ac_check_app_violations 2>&1)
    rm -f "$cfg"
}

removed() {  # removed <member> -> true if $CASE_OUTPUT shows it was (would be) removed
    [[ "$CASE_OUTPUT" == *"would remove admin: $1"* ]]
}

kept_as_last_admin() {  # kept_as_last_admin <member>
    [[ "$CASE_OUTPUT" == *"SKIP $1 (protected: last remaining admin)"* ]]
}

kept_as_protected() {  # kept_as_protected <member> <reason>
    [[ "$CASE_OUTPUT" == *"SKIP $1 (protected: $2)"* ]]
}

# ── PAT-1417 helpers: drive a real (non-dry-run) POST and read back the
# agent-health store's JSON that patched_agent_health_record_failure/
# _record_success wrote, the same way patched_agent_health_emit_degraded_json
# reads it in production (macos/lib/agent_health.sh).
CASE_RC=0
AH_STORE=""

run_case_live() {  # run_case_live <dscl-members> <console-user> <approved-admins-json-array> <http-code>
    MOCK_DSCL_MEMBERS="$1"
    MOCK_CONSOLE_USER="$2"
    local approved_json="$3"
    MOCK_HTTP_CODE="$4"

    local cfg
    cfg=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-cfg.XXXXXX")
    printf '{"app_control": {"enabled": true, "approved_admins": %s}}' "$approved_json" > "$cfg"

    AH_STORE=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-health.XXXXXX")
    rm -f "$AH_STORE"   # a fresh, not-yet-existing store is the clean-start case

    PATCHED_AC_CONFIG="$cfg"
    PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
    PATCHED_DRY_RUN=0
    CASE_OUTPUT=$(ac_enforce_admins 2>&1)
    CASE_RC=$?
    rm -f "$cfg"
}

run_violation_case_live() {  # run_violation_case_live <app-allowlist-json-array> <http-code>
    local allowlist_json="$1"
    MOCK_HTTP_CODE="$2"

    local cfg
    cfg=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-cfg.XXXXXX")
    printf '{"app_control": {"enabled": true, "app_allowlist": %s}}' "$allowlist_json" > "$cfg"

    AH_STORE=$(mktemp "${TMPDIR:-/tmp}/patched-ac-test-health.XXXXXX")
    rm -f "$AH_STORE"

    PATCHED_AC_CONFIG="$cfg"
    PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
    PATCHED_DRY_RUN=0
    CASE_OUTPUT=$(ac_check_app_violations 2>&1)
    CASE_RC=$?
    rm -f "$cfg"
}

# ah_active_reason <kind> <subject> -> the "reason" field of that active
# entry, or "" if absent/unreadable. Reads $AH_STORE, set by the run_*_live
# helpers above.
ah_active_reason() {
    "$PYTHON3" -c '
import json, sys
store, kind, subject = sys.argv[1:4]
try:
    with open(store) as f:
        data = json.load(f)
    entry = data.get("active", {}).get(kind + "|" + subject)
    print(entry.get("reason", "") if isinstance(entry, dict) else "")
except Exception:
    print("")
' "$AH_STORE" "$1" "$2"
}

# ah_active_present <kind> <subject> -> "1" if that key is in `active`, else "0"
ah_active_present() {
    "$PYTHON3" -c '
import json, sys
store, kind, subject = sys.argv[1:4]
try:
    with open(store) as f:
        data = json.load(f)
    print("1" if (kind + "|" + subject) in data.get("active", {}) else "0")
except Exception:
    print("0")
' "$AH_STORE" "$1" "$2"
}

# ah_ever_succeeded <kind> <subject> -> "1" if the persistent ledger has it
# true, else "0"
ah_ever_succeeded() {
    "$PYTHON3" -c '
import json, sys
store, kind, subject = sys.argv[1:4]
try:
    with open(store) as f:
        data = json.load(f)
    print("1" if data.get("ever_succeeded", {}).get(kind + "|" + subject) is True else "0")
except Exception:
    print("0")
' "$AH_STORE" "$1" "$2"
}

##############################################################################
# (a) All current admins unauthorized, none protected present.
# -> all but one removed; the last is kept by the genuine last-admin floor.
##############################################################################
echo "--- (a) all admins unauthorized, none protected present ---"
run_case "bob carol dave" "" '["nobody-currently-an-admin"]'
chk "bob removed"                          "$(removed bob && echo 1 || echo 0)"
chk "carol removed"                        "$(removed carol && echo 1 || echo 0)"
chk "dave kept (genuinely last admin)"     "$(kept_as_last_admin dave && echo 1 || echo 0)"

##############################################################################
# (b) Unauthorized admins alongside a protected console user.
# -> all unauthorized removed; the protected console user already covers
#    the floor, so it must not block removing the rest.
##############################################################################
echo "--- (b) unauthorized admins + protected console user ---"
run_case "alice bob carol" "alice" '["alice"]'
chk "bob removed (protected console user covers the floor)"   "$(removed bob && echo 1 || echo 0)"
chk "carol removed (protected console user covers the floor)" "$(removed carol && echo 1 || echo 0)"

##############################################################################
# (c) Exactly one unauthorized admin, no protected accounts present.
# -> kept: existing floor behaviour preserved when it is genuinely the last
#    admin on the box (removing it would leave zero admins).
##############################################################################
echo "--- (c) exactly one unauthorized admin, no protected accounts ---"
run_case "eve" "" '["nobody-currently-an-admin"]'
chk "eve kept (genuinely the last admin)" "$(kept_as_last_admin eve && echo 1 || echo 0)"

##############################################################################
# (d) Only admins are root + _mbsetupuser + console user + one UNAUTHORIZED
# admin. The unauthorized admin must still be demoted: root/_mbsetupuser/
# console-user are protected-but-never-removable, so they must never be
# counted as if they were the "one admin" the floor is allowed to keep in
# place of the unauthorized account.
##############################################################################
echo "--- (d) root + _mbsetupuser + console-user + one unauthorized admin ---"
run_case "root _mbsetupuser alice bob" "alice" '["alice"]'
chk "root left in place (protected: root)"                  "$(kept_as_protected root root && echo 1 || echo 0)"
chk "_mbsetupuser left in place (protected: _mbsetupuser)"  "$(kept_as_protected _mbsetupuser _mbsetupuser && echo 1 || echo 0)"
chk "bob (the unauthorized admin) is demoted"                "$(removed bob && echo 1 || echo 0)"

##############################################################################
# (e) The console user is itself unauthorized (not in approved_admins) — it
# must still be protected from removal via the explicit "primary console
# user" safety rail message, distinct from being merely approved.
##############################################################################
echo "--- (e) unauthorized console user is protected from removal ---"
run_case "alice bob" "alice" '["nobody-currently-an-admin"]'
chk "alice (unauthorized console user) kept as protected console user" \
    "$(kept_as_protected alice "primary console user" && echo 1 || echo 0)"
chk "bob removed (protected console user already covers the floor)" \
    "$(removed bob && echo 1 || echo 0)"

##############################################################################
# (f) PAT-920 regression guard: no in-loop `local` redeclaration should leak
# a bare `varname=value` line to stdout/stderr. Reuses case (a)'s multi-
# removal scenario (2 removal-loop iterations + 2 event-loop iterations)
# since the leak only shows up on the 2nd+ iteration of a loop that
# redeclares an already-local name.
##############################################################################
echo "--- (f) no varname=value leak from in-loop local redeclaration ---"
run_case "bob carol dave" "" '["nobody-currently-an-admin"]'
chk "no bare _remaining= line leaked" \
    "$([[ "$CASE_OUTPUT" != *$'\n'_remaining=* ]] && echo 1 || echo 0)"
chk "no bare _did_remove= line leaked" \
    "$([[ "$CASE_OUTPUT" != *$'\n'_did_remove=* ]] && echo 1 || echo 0)"
chk "no bare _event_dry_run= line leaked" \
    "$([[ "$CASE_OUTPUT" != *$'\n'_event_dry_run=* ]] && echo 1 || echo 0)"
chk "no bare _event= line leaked" \
    "$([[ "$CASE_OUTPUT" != *$'\n'_event=* ]] && echo 1 || echo 0)"

##############################################################################
# (f.1) Ambiguous JSON members must not turn a signed-cache parse into admin
# enforcement. The policy readers fail closed before any removal can be planned.
##############################################################################
echo "--- (f.1) ambiguous policy JSON fails closed ---"
run_raw_config_case '{"app_control":{"enabled":true,"approved_admins":["nobody"]},"app_control":{"enabled":true,"approved_admins":["bob"]}}'
chk "exact duplicate app_control key prevents admin enforcement" \
    "$([[ "$CASE_OUTPUT" != *"would remove admin:"* ]] && echo 1 || echo 0)"
run_raw_config_case '{"app_control":{"enabled":true,"approved_admins":["nobody"]},"APP_CONTROL":{"enabled":false}}'
chk "case-colliding app_control key prevents admin enforcement" \
    "$([[ "$CASE_OUTPUT" != *"would remove admin:"* ]] && echo 1 || echo 0)"
run_raw_config_case '{"app_control":{"enabled":true,"Enabled":false,"approved_admins":["nobody"]}}'
chk "case-colliding nested enabled key prevents admin enforcement" \
    "$([[ "$CASE_OUTPUT" != *"would remove admin:"* ]] && echo 1 || echo 0)"
run_raw_allowlist_config_case '{"app_control":{"enabled":true,"Enabled":false,"app_allowlist":["com.patched.test"]}}'
chk "case-colliding nested enabled key prevents allowlist enforcement" \
    "$([[ "$CASE_OUTPUT" != *"checking installed apps against allowlist"* ]] && echo 1 || echo 0)"

##############################################################################
# (g) PAT-1417: a 401 on the admin-enforcement audit POST records a failure
# in the agent-health store, with a reason distinguishing it as a credential
# problem (config defect), and the function still returns 0.
##############################################################################
echo "--- (g) admin-enforcement audit POST 401 -> recorded as a credential failure ---"
run_case_live "bob carol dave" "" '["nobody-currently-an-admin"]' "401"
chk "function returns 0 on a 401" "$(( CASE_RC == 0 ))"
chk "log line names the credential defect, not a generic non-fatal" \
    "$([[ "$CASE_OUTPUT" == *"audit POST -> 401 (device credential cannot write enforcement audit"* ]] && echo 1 || echo 0)"
chk "store has an active audit_post_failed|admin_enforcement entry" \
    "$([[ "$(ah_active_present audit_post_failed admin_enforcement)" == "1" ]] && echo 1 || echo 0)"
chk "reason names the credential rejection with the http code" \
    "$([[ "$(ah_active_reason audit_post_failed admin_enforcement)" == "credential_rejected_http_401" ]] && echo 1 || echo 0)"
rm -f "$AH_STORE"

##############################################################################
# (h) PAT-1417: a 500 (at-minimum-one-5xx per the ticket) on the same POST
# records a failure too, but with a DIFFERENT reason than the 401 case above
# - a 401/403 must never be folded in with 5xx/network noise.
##############################################################################
echo "--- (h) admin-enforcement audit POST 500 -> recorded distinctly from 401 ---"
run_case_live "bob carol dave" "" '["nobody-currently-an-admin"]' "500"
chk "function returns 0 on a 500" "$(( CASE_RC == 0 ))"
chk "log line is the generic non-fatal form, not the credential wording" \
    "$([[ "$CASE_OUTPUT" == *"audit POST -> 500 (non-fatal)"* ]] && echo 1 || echo 0)"
chk "store has an active audit_post_failed|admin_enforcement entry" \
    "$([[ "$(ah_active_present audit_post_failed admin_enforcement)" == "1" ]] && echo 1 || echo 0)"
chk "reason names the http code without claiming a credential defect" \
    "$([[ "$(ah_active_reason audit_post_failed admin_enforcement)" == "post_failed_http_500" ]] && echo 1 || echo 0)"
rm -f "$AH_STORE"

##############################################################################
# (i) PAT-1417: a 2xx records success - clears any active entry and marks
# ever_succeeded true in the persistent ledger.
##############################################################################
echo "--- (i) admin-enforcement audit POST 200 -> recorded as success ---"
run_case_live "bob carol dave" "" '["nobody-currently-an-admin"]' "200"
chk "function returns 0 on a 200" "$(( CASE_RC == 0 ))"
chk "log line reports ok" \
    "$([[ "$CASE_OUTPUT" == *"audit POST -> 200 (ok)"* ]] && echo 1 || echo 0)"
chk "no active audit_post_failed|admin_enforcement entry after success" \
    "$([[ "$(ah_active_present audit_post_failed admin_enforcement)" == "0" ]] && echo 1 || echo 0)"
chk "ever_succeeded is true for audit_post_failed|admin_enforcement" \
    "$([[ "$(ah_ever_succeeded audit_post_failed admin_enforcement)" == "1" ]] && echo 1 || echo 0)"
rm -f "$AH_STORE"

##############################################################################
# (j) PAT-1417: curl itself failing (network error/timeout, empty http code)
# is recorded too, with its own reason distinct from both 401 and 500 above.
##############################################################################
echo "--- (j) admin-enforcement audit POST network error -> recorded as a failure ---"
run_case_live "bob carol dave" "" '["nobody-currently-an-admin"]' "NETWORK_ERROR"
chk "function returns 0 on a network error" "$(( CASE_RC == 0 ))"
chk "log line reports network error or timeout" \
    "$([[ "$CASE_OUTPUT" == *"audit POST -> network error or timeout"* ]] && echo 1 || echo 0)"
chk "reason names the network failure" \
    "$([[ "$(ah_active_reason audit_post_failed admin_enforcement)" == "network_error_or_timeout" ]] && echo 1 || echo 0)"
rm -f "$AH_STORE"

##############################################################################
# (k) PAT-1417: the second POST site (ac_check_app_violations) records under
# its own subject (app_allowlist), never colliding with admin_enforcement's
# key above even on the same shared store. Relies on the real /Applications
# on the test host having at least one already-indexed app that will not
# match the deliberately-bogus allowlist below - true on every macOS
# development machine and the macos-latest CI runner this suite runs on
# (test-app-control.yml), both of which ship pre-installed, pre-indexed
# apps (e.g. Safari.app).
##############################################################################
echo "--- (k) app-allowlist violation POST 401 -> recorded under its own subject ---"
run_violation_case_live '["com.patched.test.definitely-not-installed-anywhere"]' "401"
chk "at least one violation was found against the bogus allowlist" \
    "$([[ "$CASE_OUTPUT" != *"app_allowlist: 0 unlisted app(s) found"* && "$CASE_OUTPUT" == *"unlisted app(s) found"* ]] && echo 1 || echo 0)"
chk "function returns 0 on a 401" "$(( CASE_RC == 0 ))"
chk "log line names the credential defect" \
    "$([[ "$CASE_OUTPUT" == *"violation POST -> 401 (device credential cannot write enforcement audit"* ]] && echo 1 || echo 0)"
chk "store records under audit_post_failed|app_allowlist, not admin_enforcement" \
    "$([[ "$(ah_active_present audit_post_failed app_allowlist)" == "1" && "$(ah_active_present audit_post_failed admin_enforcement)" == "0" ]] && echo 1 || echo 0)"
chk "reason names the credential rejection with the http code" \
    "$([[ "$(ah_active_reason audit_post_failed app_allowlist)" == "credential_rejected_http_401" ]] && echo 1 || echo 0)"
rm -f "$AH_STORE"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
