#!/bin/zsh
# PAT-2075: apps_users[].home, /Users/Shared as a machine root, and the limits
# of the per-user symlink guard. Sources the immutable collector harness, then
# swaps its identity stub for the real _apps_user_account_for_root so the
# /Users/Shared classification under test is the shipping one.
# Run: zsh macos/lib/test-apps-per-user-home.zsh
source "${0:A:h}/test-apps-per-user.zsh"

note() {
    if eval "$2"; then ((pass++)); print -r -- "PASS: $1"
    else ((fail++)); print -r -- "FAIL: $1"; fi
}
warned() { grep -q -- "$1" "$CASE_DIR/stderr"; }
DENIED_ROOT=""
find() {
    local arg
    if [[ -n "$DENIED_ROOT" ]]; then
        for arg in "$@"; do [[ "$arg" == "$DENIED_ROOT" ]] && return 1; done
    fi
    command find "$@"
}

# --- home, with the harness identity stub ------------------------------------
new_case home
make_app "$APPS_ROOTS[2]" Alice
collect_payload
check 'each user entry carries the directory its folder was found in' '{u["user_account"]: u.get("home", "").rsplit("/Users/", 1)[-1] for u in p["collection_status"]["apps_users"]} == {"synthetic_alice": "profile-alias", "synthetic_bob": "bob-home"} and all(u["home"].startswith("/") and "/Users/" in u["home"] for u in p["collection_status"]["apps_users"])'
check 'home is not derived from the account name' 'all(not u["home"].endswith(u["user_account"]) for u in p["collection_status"]["apps_users"])'
check 'entry keys are the contract and nothing else' 'all(sorted(u) == ["collection_status", "home", "user_account"] for u in p["collection_status"]["apps_users"])'
check 'home has no trailing slash' 'all(not u["home"].endswith("/") for u in p["collection_status"]["apps_users"])'
note 'the walk leaves no scratch file in the queue directory' '[[ -z "$(command find "$QUEUE_DIR" -name ".apps-*" -print -quit)" ]]'

# One account found in two directories owns neither with certainty.
new_case twohomes
_apps_user_account_for_root() {
    case "$1" in
        "$CASE_DIR/Applications") return 0 ;;
        "$CASE_DIR/Users/"*) print -r -- synthetic_alice ;;
        *) return 1 ;;
    esac
}
make_app "$APPS_ROOTS[2]" Alice
collect_payload
check 'an account resolved from two homes sends no home' '[(u["user_account"], "home" in u) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", False)]'

# --- real identity function from here ----------------------------------------
source "$SCRIPT_DIR/apps.sh"
read_metering() { print -r -- '||unavailable'; }
_apps_scan_roots
REAL_ROOTS=("${reply[@]}")
note 'the shipping root list starts with the machine roots' '[[ "$REAL_ROOTS[1]" == /Applications && "$REAL_ROOTS[2]" == /Applications/Utilities ]]'
if [[ -d /Users/Shared/Applications ]]; then
    note 'the shipping root list includes /Users/Shared/Applications' '(( ${REAL_ROOTS[(Ie)/Users/Shared/Applications]} ))'
fi
_apps_scan_roots() { reply=("${APPS_ROOTS[@]}"); }
DS_FAIL=false
/usr/bin/dscl() {
    [[ "$DS_FAIL" == true ]] && return 1
    "$PYTHON3" - <<'PY'
import plistlib, sys
plistlib.dump([
    {'dsAttrTypeStandard:RecordName': ['synthetic_alice'], 'dsAttrTypeStandard:NFSHomeDirectory': ['/Users/profile-alias']},
    {'dsAttrTypeStandard:RecordName': ['synthetic_carol'], 'dsAttrTypeStandard:NFSHomeDirectory': ['/Users/carol-home']},
    {'dsAttrTypeStandard:RecordName': ['daemon'], 'dsAttrTypeStandard:NFSHomeDirectory': ['/var/root']},
], sys.stdout.buffer)
PY
}
DS_FAIL=true
value=$(_apps_user_account_for_root /Users/Shared/Applications); rc=$?
note '/Users/Shared/Applications is a machine root, with no directory lookup' '(( rc == 0 )) && [[ -z "$value" ]]'
value=$(_apps_user_account_for_root /Users/shared-lookalike/Applications); rc=$?
note 'only the exact Shared folder is exempt from identity' '(( rc != 0 )) && [[ -z "$value" ]]'
DS_FAIL=false
value=$(_apps_user_account_for_root /Users/Shared/Applications); rc=$?
note 'no account can claim /Users/Shared' '(( rc == 0 )) && [[ -z "$value" ]]'

# Fixture roots stand in for /Users/...: the shipping function decides the scope.
functions -c _apps_user_account_for_root _real_apps_user_account_for_root
_apps_user_account_for_root() {
    if [[ "$1" == "$CASE_DIR/Users/"* ]]; then
        _real_apps_user_account_for_root "/Users/${1#$CASE_DIR/Users/}"
    else
        _real_apps_user_account_for_root "$1"
    fi
}
shared_case() {
    new_case "$1"
    mkdir -p "$CASE_DIR/Users/Shared"
    APPS_ROOTS=("$CASE_DIR/Applications" "$CASE_DIR/Users/Shared/Applications" "$CASE_DIR/Users/profile-alias/Applications")
}

shared_case shared
mkdir -p "$APPS_ROOTS[2]"
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[2]" SharedTool
make_app "$APPS_ROOTS[3]" Alice
collect_payload
check 'an app in /Users/Shared/Applications is reported, machine scope' '[a.get("user_account", "") for a in p["apps"] if a["identifier"] == "com.synthetic.SharedTool"] == [""]'
check 'its path is reported as found' 'any(a["path"].endswith("/Users/Shared/Applications/SharedTool.app") for a in p["apps"])'
check 'machine complete covers the scanned Shared root' 'p["collection_status"]["apps"] == "complete"'
check 'Shared is never a user scope' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", "complete")]'
check 'the real user still resolves beside it, with its home' 'any(a["identifier"] == "com.synthetic.Alice" and a.get("user_account") == "synthetic_alice" for a in p["apps"]) and p["collection_status"]["apps_users"][0]["home"].endswith("/Users/profile-alias")'
note 'the Shared root is not dropped as unresolved' '! warned account_unresolved'

shared_case shareddenied
mkdir -p "$APPS_ROOTS[2]"
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[2]" SharedTool
DENIED_ROOT="$APPS_ROOTS[2]"
collect_payload
DENIED_ROOT=""
check 'machine complete is not claimed when the Shared root could not be listed' 'p["collection_status"]["apps"] != "complete"'
check 'a failed Shared listing does not degrade the user scope' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", "complete")]'

shared_case sharedlink
mkdir -p "$CASE_DIR/elsewhere"
make_app "$CASE_DIR/elsewhere" Hidden
ln -s "$CASE_DIR/elsewhere" "$APPS_ROOTS[2]"
make_app "$APPS_ROOTS[1]" Machine
collect_payload
check 'a linked Shared root is not followed' 'not any(a["identifier"] == "com.synthetic.Hidden" for a in p["apps"])'
check 'machine complete is not claimed over a linked root that was never read' 'p["collection_status"]["apps"] == "partial"'
check 'the rest of the machine scope is still reported' 'any(a["identifier"] == "com.synthetic.Machine" for a in p["apps"])'
note 'the linked machine root is named in a warning' 'warned "section=apps status=partial reason=machine_root_link"'

shared_case sharedabsent
make_app "$APPS_ROOTS[1]" Machine
APPS_ROOTS=("$APPS_ROOTS[1]" "$APPS_ROOTS[3]")
collect_payload
check 'no Shared folder: machine complete as before' 'p["collection_status"]["apps"] == "complete" and len(p["apps"]) == 1'

DS_FAIL=true
shared_case sharednodirectory
mkdir -p "$APPS_ROOTS[2]"
make_app "$APPS_ROOTS[2]" SharedTool
make_app "$APPS_ROOTS[3]" Alice
collect_payload
DS_FAIL=false
check 'a failed directory lookup withholds the user, not the Shared root' 'p["collection_status"]["apps"] == "complete" and [a["identifier"] for a in p["apps"]] == ["com.synthetic.SharedTool"] and p["collection_status"]["apps_users"] == []'
note 'the unresolved user is named in a warning' 'warned account_unresolved'

# --- the per-user symlink guard looks for hidden inventory, not bundle internals
shared_case frameworklinks
make_app "$APPS_ROOTS[3]" Alice
mkdir -p "$APPS_ROOTS[3]/Alice.app/Contents/Frameworks/Synthetic.framework/Versions/A"
ln -s A "$APPS_ROOTS[3]/Alice.app/Contents/Frameworks/Synthetic.framework/Versions/Current"
collect_payload
check 'links inside a bundle do not withhold its user' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", "complete")]'

shared_case linkedfolder
make_app "$APPS_ROOTS[3]" Alice
mkdir -p "$CASE_DIR/hidden" "$APPS_ROOTS[3]/Group"
make_app "$CASE_DIR/hidden" Hidden
ln -s "$CASE_DIR/hidden" "$APPS_ROOTS[3]/Group/linked-folder"
collect_payload
check 'a linked folder below the root still withholds its user' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", "partial")]'

shared_case linkedbundle
mkdir -p "$CASE_DIR/hidden"
make_app "$CASE_DIR/hidden" Hidden
mkdir -p "$APPS_ROOTS[3]"
ln -s "$CASE_DIR/hidden/Hidden.app" "$APPS_ROOTS[3]/Hidden.app"
collect_payload
check 'a linked bundle still withholds its user and is not reported' '[(u["user_account"], u["collection_status"]) for u in p["collection_status"]["apps_users"]] == [("synthetic_alice", "partial")] and p["apps"] == []'

# --- every resolved home is listed, with or without an Applications folder ----
APPS_HOMES=()
_apps_scan_homes() { reply=("${APPS_HOMES[@]}"); }
users_are() { print -r -- "sorted((u[\"user_account\"], u[\"collection_status\"], u.get(\"home\", \"\").rsplit(\"/Users/\", 1)[-1]) for u in p[\"collection_status\"][\"apps_users\"]) == $1"; }
homes_case() {
    shared_case "$1"
    mkdir -p "$CASE_DIR/Users/carol-home" "$CASE_DIR/Users/ghost-home" "$APPS_ROOTS[3]"
    APPS_ROOTS=("$CASE_DIR/Applications" "$APPS_ROOTS[3]")
    APPS_HOMES=("$CASE_DIR/Users/Shared" "$CASE_DIR/Users/profile-alias" "$CASE_DIR/Users/carol-home" "$CASE_DIR/Users/ghost-home")
}

homes_case nofolder
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[2]" Alice
collect_payload
check 'a resolved user with no Applications folder is complete, with home' "$(users_are '[("synthetic_alice", "complete", "profile-alias"), ("synthetic_carol", "complete", "carol-home")]')"
check 'and has no rows' 'not any(a.get("user_account") == "synthetic_carol" for a in p["apps"]) and len(p["apps"]) == 2'
check 'a home that resolves to no account is not listed' 'all("ghost" not in u.get("home", "") for u in p["collection_status"]["apps_users"])'
check 'Shared is not a user even with no folder' 'all("Shared" not in u.get("home", "") for u in p["collection_status"]["apps_users"])'
check 'machine scope is unaffected' 'p["collection_status"]["apps"] == "complete"'
note 'a folderless unresolved home is not a warning' '! warned account_unresolved'

homes_case folderunreadable
mkdir -p "$CASE_DIR/Users/carol-home/Applications"
make_app "$CASE_DIR/Users/carol-home/Applications" Carol
APPS_ROOTS+=("$CASE_DIR/Users/carol-home/Applications")
DENIED_ROOT="$CASE_DIR/Users/carol-home/Applications"
collect_payload
DENIED_ROOT=""
check 'a user whose Applications folder cannot be read is partial' "$(users_are '[("synthetic_alice", "complete", "profile-alias"), ("synthetic_carol", "partial", "carol-home")]')"

homes_case folderlinked
mkdir -p "$CASE_DIR/elsewhere"
make_app "$CASE_DIR/elsewhere" Hidden
ln -s "$CASE_DIR/elsewhere" "$CASE_DIR/Users/carol-home/Applications"
collect_payload
check 'a linked Applications entry is never read as "no folder"' 'not any(u["user_account"] == "synthetic_carol" and u["collection_status"] == "complete" for u in p["collection_status"]["apps_users"]) and not any(a["identifier"] == "com.synthetic.Hidden" for a in p["apps"])'

homes_case homeunreadable
chmod 000 "$CASE_DIR/Users/carol-home"
collect_payload
chmod 755 "$CASE_DIR/Users/carol-home"
if [[ "$(id -u)" != 0 ]]; then
    check 'a home that cannot be searched does not prove the folder absent' "$(users_are '[("synthetic_alice", "complete", "profile-alias"), ("synthetic_carol", "partial", "carol-home")]')"
fi

# Machine scope unavailable: user rows still go out, machine rows never do.
homes_case machineunavailable
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[2]" Alice
collect_apps > "$CASE_DIR/stdout" 2> "$CASE_DIR/stderr"
APPS_COLLECTION_STATUS=unavailable
rows=$(apps_payload_array | "$PYTHON3" -c 'import json,sys; print(",".join(sorted(a.get("user_account", "MACHINE") for a in json.load(sys.stdin))))')
note 'under machine unavailable only user-scoped rows are sent' '[[ "$rows" == synthetic_alice ]]'

homes_case nodirectory
DS_FAIL=true
collect_payload
DS_FAIL=false
check 'no directory service: no folderless user is invented' 'p["collection_status"]["apps_users"] == []'

homes_case linkedhome
rmdir "$CASE_DIR/Users/carol-home"
mkdir -p "$CASE_DIR/real-carol"
ln -s "$CASE_DIR/real-carol" "$CASE_DIR/Users/carol-home"
collect_payload
check 'a linked home is not a resolved home' "$(users_are '[("synthetic_alice", "complete", "profile-alias")]')"

print -r -- "PAT-2075 home total: $pass passed; $fail failed"
(( fail == 0 ))
