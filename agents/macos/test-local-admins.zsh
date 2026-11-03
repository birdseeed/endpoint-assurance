#!/bin/zsh
##############################################################################
# test-local-admins.zsh — PAT-1974 standing local-admin contract tests.
#
# Sources macos/lib/auth.sh and drives _collect_local_admins and
# local_admins_payload directly, with `dscl` shadowed by a shell function so
# every failure route runs on any Mac and on CI. No root daemon, queue,
# credentials or network.
#
# The regression this guards is a real defect that shipped: the old
#   dscl . read /Groups/admin GroupMembership 2>/dev/null | awk ... | wc -l
# swallowed a failed read and counted 0 from the empty output, so a Mac whose
# directory service could not be read reported the same "0" as a Mac with no
# standing admins — and 0 passes the CIS 5.8 `lte 2` rule outright. Every
# "unavailable" case below therefore asserts BOTH that the count is JSON null
# and that it is not 0, and that the accounts key is absent rather than [].
#
# Run: zsh macos/test-local-admins.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.local-admins-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
PATCHED_TMPDIR="$WORK"

source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/auth.sh"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# The two payload fragments patched-collect.sh's heredoc emits, assembled into
# one object so each case is checked as the JSON that actually ships.
fragment() {
    printf '{"compliance":{"local_admin_count":%s},"local_admins":%s}' \
        "$(json_int_or_notconfigured "$LOCAL_ADMIN_COUNT")" \
        "$(local_admins_payload)"
}

# json_eval <python expression over `obj`>
json_eval() {
    fragment | "$PYTHON3" -c 'import json,sys; obj=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null
}

is_true() { [[ "$(json_eval "$1")" == "True" ]] && echo 1 || echo 0; }

# plist_with <string-element lines...> — a dscl -plist GroupMembership reply.
plist_with() {
    print -r -- '<?xml version="1.0" encoding="UTF-8"?>'
    print -r -- '<plist version="1.0"><dict><key>dsAttrTypeStandard:GroupMembership</key><array>'
    local member
    for member in "$@"; do print -r -- "<string>$member</string>"; done
    print -r -- '</array></dict></plist>'
}

# Every case below drives a shadowed `dscl`, so the suite is meaningful on the
# Linux runner too. This first block is the only one that needs a real Mac, and
# it announces the skip rather than passing quietly (the PAT-1035 rule: a skip
# must never read as a pass).
if [[ -x /usr/bin/dscl ]]; then
    echo "--- real read of this machine's admin group"
    _collect_local_admins
    chk "real read produces valid JSON" "$(is_true 'isinstance(obj, dict)')"
    chk "real read is complete on a working Mac" "$(is_true 'obj["local_admins"]["collection_status"] == "complete"')"
    chk "real read excludes root from the roster" "$(is_true '"root" not in [a["name"] for a in obj["local_admins"]["accounts"]]')"
    chk "real count equals the roster length" "$(is_true 'obj["compliance"]["local_admin_count"] == len(obj["local_admins"]["accounts"])')"
else
    echo "--- real read of this machine's admin group: SKIPPED (no /usr/bin/dscl; not a Mac)"
fi

echo "--- a failed dscl read is unavailable, never a fabricated 0"
dscl() { return 56 }
_collect_local_admins
chk "count is JSON null" "$(is_true 'obj["compliance"]["local_admin_count"] is None')"
chk "count is NOT 0" "$(is_true 'obj["compliance"]["local_admin_count"] != 0')"
chk "collection_status is unavailable" "$(is_true 'obj["local_admins"]["collection_status"] == "unavailable"')"
chk "accounts key is omitted, not []" "$(is_true '"accounts" not in obj["local_admins"]')"
unfunction dscl

echo "--- a record with no GroupMembership attribute is unavailable, not zero"
# dscl prints "No such key" to stdout and still exits 0, and membership can be
# recorded as GroupMembers (GeneratedUIDs) alone, so absence is not proof.
dscl() { print -r -- '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>' }
_collect_local_admins
chk "count is JSON null" "$(is_true 'obj["compliance"]["local_admin_count"] is None')"
chk "count is NOT 0" "$(is_true 'obj["compliance"]["local_admin_count"] != 0')"
chk "accounts key is omitted" "$(is_true '"accounts" not in obj["local_admins"]')"
unfunction dscl

echo "--- unparseable output is unavailable, not zero"
dscl() { print -r -- 'No such key: GroupMembership' }
_collect_local_admins
chk "count is JSON null" "$(is_true 'obj["compliance"]["local_admin_count"] is None')"
chk "collection_status is unavailable" "$(is_true 'obj["local_admins"]["collection_status"] == "unavailable"')"
unfunction dscl

echo "--- a successful read reports every member, root excluded"
dscl() { plist_with root alice bob }
_collect_local_admins
chk "count excludes root" "$(is_true 'obj["compliance"]["local_admin_count"] == 2')"
chk "count is a JSON integer, not a string" "$(is_true 'isinstance(obj["compliance"]["local_admin_count"], int)')"
chk "names are reported in order" "$(is_true '[a["name"] for a in obj["local_admins"]["accounts"]] == ["alice","bob"]')"
chk "every entry is principal_type user" "$(is_true 'all(a["principal_type"] == "user" for a in obj["local_admins"]["accounts"])')"
chk "every entry is builtin false" "$(is_true 'all(a["builtin"] is False for a in obj["local_admins"]["accounts"])')"
chk "entries carry the platform-neutral key set" "$(is_true 'all(sorted(a) == ["builtin","name","principal_type"] for a in obj["local_admins"]["accounts"])')"
unfunction dscl

echo "--- a name needing JSON escaping does not corrupt the payload"
dscl() { plist_with root 'bo&quot;b' 'carol dee' }
_collect_local_admins
chk "payload still parses" "$(is_true 'len(obj["local_admins"]["accounts"]) == 2')"
chk "the quote is escaped, not dropped" "$(is_true 'obj["local_admins"]["accounts"][0]["name"] == chr(98)+chr(111)+chr(34)+chr(98)')"
unfunction dscl

echo "--- a genuinely empty admin group is a real reading of zero"
dscl() { plist_with root }
_collect_local_admins
chk "count is 0" "$(is_true 'obj["compliance"]["local_admin_count"] == 0')"
chk "status is complete, with an empty accounts array" "$(is_true 'obj["local_admins"]["collection_status"] == "complete" and obj["local_admins"]["accounts"] == []')"
unfunction dscl

echo "--- a control character in a member name is not sent verbatim"
dscl() { plist_with root 'al&#9;ice' }
_collect_local_admins
chk "collection is unavailable rather than carrying the raw byte" "$(is_true 'obj["local_admins"]["collection_status"] == "unavailable"')"
unfunction dscl

echo "--- the collector wires the helpers into the payload"
COLLECT_SH="$SCRIPT_DIR/patched-collect.sh"
chk "local_admin_count goes through json_int_or_notconfigured" \
    "$(grep -qE '"local_admin_count":[[:space:]]+\$\(json_int_or_notconfigured' "$COLLECT_SH" && echo 1 || echo 0)"
chk "the old fabricated-zero default is gone" \
    "$(grep -q 'LOCAL_ADMIN_COUNT:-0' "$COLLECT_SH" && echo 0 || echo 1)"
chk "the payload emits local_admins" \
    "$(grep -qE '"local_admins":[[:space:]]+\$\(local_admins_payload\)' "$COLLECT_SH" && echo 1 || echo 0)"

echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
