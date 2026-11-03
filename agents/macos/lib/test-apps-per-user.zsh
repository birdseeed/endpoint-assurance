#!/bin/zsh
# PAT-2075: real collector + real payload expressions, isolated synthetic roots.
# Run: zsh macos/lib/test-apps-per-user.zsh
# Native macOS plutil/PlistBuddy are required; this never reads real home apps.
set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="${PYTHON3:-/usr/bin/python3}"
# Optional queue fixture guard, portable when unset. This grants no source authority.
"$PYTHON3" - <<'PY' || exit 2
import json, os
p, n = os.getenv('QUEUE_RUN_TEST_OWNER_PATH'), os.getenv('QUEUE_RUN_TEST_OWNER_NONCE')
if p is not None or n is not None:
    if not p or not n:
        raise SystemExit('Both queue fixture guard values must be nonempty')
    if json.load(open(p)).get('owner_nonce') != n:
        raise SystemExit('Queue fixture owner mismatch')
PY
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/apps.sh"
PATCHED_TMPDIR=$(mktemp -d) || exit 2
trap 'chmod -R u+rwx "$PATCHED_TMPDIR"; rm -rf "$PATCHED_TMPDIR"' EXIT
QUEUE_DIR="$PATCHED_TMPDIR/queue"
mkdir -p "$QUEUE_DIR"
TS_FILE=synthetic2075
pass=0; fail=0
# Stub only OS account/signing/metering boundaries. Real find and plist parsing.
/usr/bin/mdutil() { print -r -- '/: Indexing disabled.'; }
stat() {
    if [[ "${@[-1]}" == /dev/console ]]; then print -r -- loginwindow
    else command stat "$@"; fi
}
codesign() { return 1; }
lipo() { print -r -- 'arm64'; }
read_metering() { print -r -- '||unavailable'; }
APPS_ROOTS=()
_apps_scan_roots() { reply=("${APPS_ROOTS[@]}"); }
# Proposed identity seam: success+empty = machine; success+account = user;
# nonzero = unresolved (must not produce a machine row or complete user scope).
# The directory alias intentionally differs from the actual account short name.
_apps_user_account_for_root() {
    case "$1" in
        "$CASE_DIR/Applications") return 0 ;;
        "$CASE_DIR/Users/profile-alias/Applications") print -r -- synthetic_alice ;;
        "$CASE_DIR/Users/bob-home/Applications") print -r -- synthetic_bob ;;
        *) return 1 ;;
    esac
}
certs_collection_status() { print -r -- unavailable; }
safari_extensions_collection_status() { print -r -- unavailable; }
APPS_LINE=$(grep -E '^  "apps": ' "$SCRIPT_DIR/../patched-collect.sh")
STATUS_LINE=$(grep -E '^  "collection_status": ' "$SCRIPT_DIR/../patched-collect.sh")
[[ -n "$APPS_LINE" && -n "$STATUS_LINE" ]] || { print 'Harness: payload expressions missing'; exit 2; }
new_case() {
    CASE_DIR="$PATCHED_TMPDIR/$1"
    mkdir -p "$CASE_DIR/Applications" "$CASE_DIR/Users/profile-alias/Applications" "$CASE_DIR/Users/bob-home/Applications"
    APPS_ROOTS=("$CASE_DIR/Applications" "$CASE_DIR/Users/profile-alias/Applications" "$CASE_DIR/Users/bob-home/Applications")
    APPS_JSON_FILE="$CASE_DIR/stub.json"
    print -r -- '[]' > "$APPS_JSON_FILE"
    APPS_COLLECTION_STATUS=unavailable
}
make_app() {
    mkdir -p "$1/$2.app/Contents"
    cat > "$1/$2.app/Contents/Info.plist" <<PLIST
<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleName</key><string>$2</string>
<key>CFBundleIdentifier</key><string>com.synthetic.$2</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>
PLIST
}
collect_payload() {
    collect_apps > "$CASE_DIR/stdout" 2> "$CASE_DIR/stderr"
    {
        print -r -- '{'
        eval "cat <<PAYLOAD_EOF
$APPS_LINE
${STATUS_LINE%,}
PAYLOAD_EOF"
        print -r -- '}'
    } > "$CASE_DIR/payload.json"
    "$PYTHON3" -m json.tool "$CASE_DIR/payload.json" >/dev/null || exit 2
}
check() {
    if "$PYTHON3" - "$CASE_DIR/payload.json" "$2" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert eval(sys.argv[2], {'p': p}), json.dumps(p, sort_keys=True)
PY
    then ((pass++)); print -r -- "PASS: $1"
    else ((fail++)); print -r -- "FAIL: $1"; fi
}
new_case clean
make_app "$APPS_ROOTS[1]" Shared
make_app "$APPS_ROOTS[2]" Shared
make_app "$APPS_ROOTS[3]" Shared
collect_payload
check 'same bundle retains three scopes and original identifier' 'sorted(a.get("user_account", "") for a in p["apps"] if a["identifier"] == "com.synthetic.Shared") == ["", "synthetic_alice", "synthetic_bob"]'
check 'actual resolved accounts each have complete authority' 'sorted((u["user_account"], u["collection_status"]) for u in p["collection_status"].get("apps_users", [])) == [("synthetic_alice", "complete"), ("synthetic_bob", "complete")]'
check 'machine completeness preserved' 'p["collection_status"]["apps"] == "complete"'
new_case malformed
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[2]" Readable
make_app "$APPS_ROOTS[2]" Corrupt
print -r -- '<plist><dict>' > "$APPS_ROOTS[2]/Corrupt.app/Contents/Info.plist"
collect_payload
check 'corrupt user cannot prune but empty sibling can' 'sorted((u["user_account"], u["collection_status"]) for u in p["collection_status"].get("apps_users", [])) == [("synthetic_alice", "partial"), ("synthetic_bob", "complete")]'
check 'corrupt user does not degrade machine authority' 'p["collection_status"]["apps"] == "complete"'
check 'readable app retained in partial user scope' 'any(a["identifier"] == "com.synthetic.Readable" and a.get("user_account") == "synthetic_alice" for a in p["apps"])'
new_case omitted
APPS_ROOTS=("$APPS_ROOTS[1]" "$APPS_ROOTS[3]")
collect_payload
check 'unlisted user has no authority, scanned empty sibling does' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"].get("apps_users", [])] == [("synthetic_bob", "complete")]'
check 'no invented row for unlisted user' 'p["apps"] == []'
print -r -- "PAT-2075: $pass passed; $fail failed"
(( fail == 0 ))
