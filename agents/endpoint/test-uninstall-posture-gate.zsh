#!/bin/zsh
##############################################################################
# test-uninstall-posture-gate.zsh — unit tests for resolve_user_removable in
# patched-uninstall.sh (PAT-910). Proves the FAIL-CLOSED posture gate:
#
#   - A VERIFIED posture (tenant_id matches) gates removal on user_removable:
#       * mandatory app (user_removable=false) -> "false" (refuse)
#       * removable app (user_removable=true)  -> "true"
#       * app absent from policy               -> "true"
#   - An UNVERIFIED / ABSENT posture takes the SAFE branch (-> "false"):
#       * missing posture file
#       * unparseable posture
#       * wrong-tenant posture (binding cannot be verified)
#       * empty local tenant id
#   - A MALFORMED (signed-shape-broken) posture also refuses (gate finding,
#     PR #319 — malformed shapes must never raise past a "false"):
#       * app_policy null / missing / a string
#       * apps not a list / apps entries as strings
#       * matching entry without a boolean user_removable
#   - CALLER contract: allow ONLY on the exact string "true" — an empty value
#     from a killed helper must refuse (simulated with PYTHON3=/usr/bin/false).
#
# This is the estate-review fail-open, now closed: a missing, forged, or
# malformed posture can no longer unlock a root-privileged removal a mandatory
# policy forbids.
#
# Sources the live resolve_user_removable function out of patched-uninstall.sh
# (between stable markers) so the test exercises the real code, not a copy. Run:
#   zsh endpoint/test-uninstall-posture-gate.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-uninstall.sh"

# resolve_user_removable shells out to $PYTHON3 — provide the production value
# (the CONFIG section that sets it is not sourced by this harness).
PYTHON3="/usr/bin/python3"

WORKDIR="$(mktemp -d /tmp/.patched-posture-gate-test.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# Extract just the resolve_user_removable function between its markers.
FUNCS="$(mktemp /tmp/.patched-posture-gate-funcs.XXXXXX)"
awk '
  /^# --- BEGIN resolve_user_removable \(PAT-910\) ---/{f=1; next}
  /^# --- END resolve_user_removable \(PAT-910\) ---/{f=0}
  f{print}
' "$TARGET" > "$FUNCS"
source "$FUNCS"
rm -f "$FUNCS"

if ! typeset -f resolve_user_removable > /dev/null; then
    echo "FATAL: extraction did not capture resolve_user_removable() from $TARGET — marker drift?"
    exit 1
fi

TENANT="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
OTHER_TENANT="00000000-0000-0000-0000-000000000000"

# --- Fixtures ---------------------------------------------------------------
verified_mandatory="$WORKDIR/verified-mandatory.json"
cat > "$verified_mandatory" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[{"app_name":"Zoom","user_removable":false}]}}
JSON

verified_removable="$WORKDIR/verified-removable.json"
cat > "$verified_removable" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[{"app_name":"Zoom","user_removable":true}]}}
JSON

verified_nopolicy="$WORKDIR/verified-nopolicy.json"
cat > "$verified_nopolicy" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[]}}
JSON

wrong_tenant="$WORKDIR/wrong-tenant.json"
cat > "$wrong_tenant" <<JSON
{"tenant_id":"$OTHER_TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[{"app_name":"Zoom","user_removable":true}]}}
JSON

corrupt="$WORKDIR/corrupt.json"
printf '{ this is not json' > "$corrupt"

missing="$WORKDIR/does-not-exist.json"   # intentionally never created

# --- Malformed-shape fixtures (gate finding, PR #319) ------------------------
# tenant_id matches in every one; the SHAPE is what must trip the refusal.
ap_null="$WORKDIR/ap-null.json"
cat > "$ap_null" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z","app_policy":null}
JSON

ap_missing="$WORKDIR/ap-missing.json"
cat > "$ap_missing" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z"}
JSON

ap_string="$WORKDIR/ap-string.json"
cat > "$ap_string" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z","app_policy":"bogus"}
JSON

apps_not_list="$WORKDIR/apps-not-list.json"
cat > "$apps_not_list" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z","app_policy":{"apps":"Zoom"}}
JSON

apps_string_entries="$WORKDIR/apps-string-entries.json"
cat > "$apps_string_entries" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z","app_policy":{"apps":["Zoom","Slack"]}}
JSON

removable_not_bool="$WORKDIR/removable-not-bool.json"
cat > "$removable_not_bool" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[{"app_name":"Zoom","user_removable":"yes"}]}}
JSON

removable_missing="$WORKDIR/removable-missing.json"
cat > "$removable_missing" <<JSON
{"tenant_id":"$TENANT","issued_at":"2026-07-16T12:00:00Z",
 "app_policy":{"apps":[{"app_name":"Zoom"}]}}
JSON

pass=0; fail=0
chk() {  # chk <desc> <expected> <posture_file> <app_name> <tenant>
    local desc="$1" exp="$2" pf="$3" app="$4" ten="$5" got
    got=$(resolve_user_removable "$pf" "$app" "$ten")
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc -> $got"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

echo "--- VERIFIED posture gates on user_removable"
chk "mandatory app refused"            "false" "$verified_mandatory" "Zoom" "$TENANT"
chk "removable app allowed"            "true"  "$verified_removable" "Zoom" "$TENANT"
chk "app absent from policy allowed"   "true"  "$verified_nopolicy"  "Zoom" "$TENANT"
chk "case-insensitive app match"       "false" "$verified_mandatory" "zoom" "$TENANT"

echo "--- UNVERIFIED / ABSENT posture takes the SAFE (refuse) branch"
chk "missing posture refused"          "false" "$missing"            "Zoom" "$TENANT"
chk "corrupt posture refused"          "false" "$corrupt"            "Zoom" "$TENANT"
chk "wrong-tenant posture refused"     "false" "$wrong_tenant"       "Zoom" "$TENANT"
chk "empty local tenant refused"       "false" "$verified_removable" "Zoom" ""

echo "--- MALFORMED posture shapes refuse (never raise past 'false')"
chk "app_policy null refused"          "false" "$ap_null"             "Zoom" "$TENANT"
chk "app_policy missing refused"       "false" "$ap_missing"          "Zoom" "$TENANT"
chk "app_policy string refused"        "false" "$ap_string"           "Zoom" "$TENANT"
chk "apps non-list refused"            "false" "$apps_not_list"       "Zoom" "$TENANT"
chk "apps string entries refused"      "false" "$apps_string_entries" "Zoom" "$TENANT"
chk "non-bool user_removable refused"  "false" "$removable_not_bool"  "Zoom" "$TENANT"
chk "missing user_removable refused"   "false" "$removable_missing"   "Zoom" "$TENANT"

echo "--- CALLER contract: only the exact string 'true' allows"
# chk_caller_refuses drives resolve_user_removable and applies the caller's
# rule from patched-uninstall.sh ([[ value != "true" ]] -> refuse): anything
# other than exactly "true" — including EMPTY output from a killed helper —
# must refuse.
chk_caller_refuses() {  # <desc> <posture_file> <app_name> <tenant>
    local desc="$1" pf="$2" app="$3" ten="$4" got
    got=$(resolve_user_removable "$pf" "$app" "$ten")
    if [[ "$got" != "true" ]]; then (( pass++ )); echo "  PASS: $desc -> refused (value='${got}')"
    else (( fail++ )); echo "  FAIL: $desc -> caller would allow (value='true')"; fi
}

# Killed/broken helper: PYTHON3 pointing at a binary that exits non-zero with
# no output. resolve_user_removable emits nothing; the caller must refuse.
_SAVED_PYTHON3="$PYTHON3"
PYTHON3="/usr/bin/false"
chk_caller_refuses "killed helper (empty output) refused" "$verified_removable" "Zoom" "$TENANT"
PYTHON3="$_SAVED_PYTHON3"

# Sanity: the same caller rule still allows on a genuine verified "true".
got=$(resolve_user_removable "$verified_removable" "Zoom" "$TENANT")
if [[ "$got" == "true" ]]; then (( pass++ )); echo "  PASS: caller allows only on exact 'true' -> allowed"
else (( fail++ )); echo "  FAIL: verified removable app no longer resolves to 'true' (got '${got}')"; fi

echo ""
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
