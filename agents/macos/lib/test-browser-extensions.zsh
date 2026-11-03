#!/bin/zsh
##############################################################################
# test-browser-extensions.zsh — PAT-2054 browser extension collector tests.
#
# Sources macos/lib/browser_extensions.sh and runs the real
# collect_browser_extensions against home directories and Safari search roots
# built in a scratch directory. No root, no browser and no network needed.
#
#   [wire]     a realistic two-user estate (Chrome, Edge, Firefox, Safari)
#              produces exactly the rows the pre-PAT-2054 collector produced;
#              GOLDEN below was captured from origin/main's script
#   [locale]   a manifest default_locale that climbs out of the extension with
#              ../ cannot make root read another user's messages.json; the
#              name falls back to the extension id
#   [symlink]  a symlinked extension or profile directory into another home
#              is refused
#   [manifest] a symlinked manifest.json, extensions.json, Safari Info.plist
#              or Safari manifest.json is refused
#   [nan]      NaN, Infinity or a wrong-typed field in a user's file cannot
#              put invalid JSON or a wrong type on the wire
#   [newline]  a newline in a directory name cannot inject a Safari bundle
#              path from outside the search root into find's list
#   [safari-*] a malformed bundle or an unreadable pluginkit list costs only
#              its own rows
#   [race]     a directory swapped for a symlink between its check and its
#              read is not read through (the PAT-2033 race hook)
#   [static]   every python open is O_NOFOLLOW from / or relative to a walked
#              directory, and no path is statted, listed or opened whole
#
# PAT-2065, the browser_extensions_status block (every block below is also
# run through [contract]):
#   [status-complete]     the [wire] estate: complete, per user and browser
#   [status-not-present]  no browser anywhere: not_present, no rows
#   [status-partial]      a refused profile, link or unparseable file makes
#                         exactly its (user, browser) partial
#   [status-cap]          the row cap: cap_reached, partial, and a fair share
#                         per user so one user cannot crowd out the rest
#   [status-failed]       an unlistable /Users or a dead parser is failed; a
#                         home that cannot be entered fails that user
#   [safari-status]       PAT-2067, collection_status.safari_extensions:
#                         complete only for a clean walk with no cap; partial
#                         for a refused, truncated or missing bundle
#                         Info.plist, an unlistable root or home root, a
#                         hidden find or refusal-log failure, a symlinked
#                         root, .app, .appex or PlugIns, a cap; and
#                         unavailable for a walk that fails before any row.
#                         PAT-2079: an appex under Contents/plugins in any
#                         case, at any depth, is found; a deep link that
#                         could hide one, or more links than the cap, is
#                         partial; deep helper apps with no appex stay
#                         complete
#                         None of them changes the Chrome, Edge and Firefox
#                         block (the PAT-2065 coupling is gone)
#   [safari-contract]     the value passes the vendored schema, and a port of
#                         the platform's trust rule (resolveSafariSignal)
#   [safari-payload]      the payload member, unavailable by default
#   [status-payload]      the payload member is the block, failed by default
#   [firefox-origins]     Firefox host permissions come from
#                         userPermissions.origins, with legacy hosts (PAT-2073)
#   [contract]            each block passes the vendored platform schema
#                         (contracts/inventory-browser-extensions-status
#                         .schema.json) and the platform's consistency rules
#                         (a port of browserExtensionsStatusProblem)
#   [contract-drift]      the vendored schema matches patched.im's own file,
#                         when a patched.im checkout is present
#
# Run: zsh macos/lib/test-browser-extensions.zsh
#
# Recapturing GOLDEN (only if the wire contract changes on purpose):
#   git show origin/main:macos/lib/browser_extensions.sh > /tmp/be-old.sh
#   BX_PRINT_WITH=/tmp/be-old.sh zsh macos/lib/test-browser-extensions.zsh
# prints what that script produces for the [wire] fixture and exits.
##############################################################################

set -u
setopt NULL_GLOB   # as patched-collect.sh
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/browser_extensions.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.browser-ext-test.XXXXXX")
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
WORK=${WORK:A}

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if [[ -n "$ok" && "$ok" != *[^1]* ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }
# plist <path> <python dict literal>
plist() {
    mkdir -p "${1:h}"
    "$REAL_PYTHON3" -c 'import plistlib,sys,ast; plistlib.dump(ast.literal_eval(sys.argv[2]), open(sys.argv[1],"wb"))' "$1" "$2"
}

# build_tree: the realistic estate. Every name and value on the wire is fixed,
# so the output does not depend on where the scratch directory is.
build_tree() {
    rm -rf "$WORK/Users" "$WORK/Applications"
    U="$WORK/Users"
    APPS="$WORK/Applications"
    mkdir -p "$U/Shared/Library/Application Support/Google/Chrome/Default/Extensions/sharedext/1.0" "$U/carol/Documents"
    write_file "$U/Shared/Library/Application Support/Google/Chrome/Default/Extensions/sharedext/1.0/manifest.json" '{"name":"Shared","version":"1.0"}'

    # alice: Chrome Default and Profile 2, Edge Default, one Firefox profile.
    local cr="$U/alice/Library/Application Support/Google/Chrome"
    local ext="$cr/Default/Extensions"
    # uBlock-like: __MSG_ name from _locales/en, MV2 host patterns in permissions,
    # two versions (the later wins), web store update URL.
    write_file "$ext/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.60.0_0/manifest.json" '{"manifest_version":2,"name":"__MSG_extName__","default_locale":"en","version":"1.60.0","permissions":["storage","tabs","<all_urls>","http://*/*"],"update_url":"https://clients2.google.com/service/update2/crx"}'
    write_file "$ext/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.60.0_0/_locales/en/messages.json" '{"extName":{"message":"uBlock Origin","description":"name"}}'
    write_file "$ext/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.59.0_0/manifest.json" '{"manifest_version":2,"name":"old"}'
    # MV3 with separate host_permissions, disabled in Secure Preferences.
    write_file "$ext/nngceckbapebfimnlniiiahkandclblb/2024.1.0_0/manifest.json" '{"manifest_version":3,"name":"Bitwarden","version":"2024.1.0","permissions":["tabs","storage"],"host_permissions":["https://*/*"],"update_url":"https://clients2.google.com/service/update2/crx"}'
    # Unpacked (no update_url), __MSG_ with an uppercase key and en_GB locale.
    write_file "$ext/devextdevextdevextdevextdevextde/0.1/manifest.json" '{"manifest_version":3,"name":"__MSG_APP_NAME__","default_locale":"en_GB","version":"0.1"}'
    write_file "$ext/devextdevextdevextdevextdevextde/0.1/_locales/en_GB/messages.json" '{"app_name":{"message":"Dev Helper"}}'
    # Chrome's own Temp directory with no manifest is skipped.
    mkdir -p "$ext/Temp"
    write_file "$cr/Default/Secure Preferences" '{"extensions":{"settings":{"nngceckbapebfimnlniiiahkandclblb":{"state":0},"cjpalhdlnbpafiamejdnhcphjbkeiagm":{"state":1}}}}'
    write_file "$cr/Profile 2/Extensions/aapbdbdomjkkjkaonfhkkikfgjllcleb/2.0.16_0/manifest.json" '{"manifest_version":2,"name":"Google Translate","version":"2.0.16","permissions":["activeTab","contextMenus"],"update_url":"https://update.googleapis.com/service/update2/crx"}'
    write_file "$cr/Profile 2/Preferences" '{"extensions":{"settings":{}}}'
    mkdir -p "$cr/System Profile" "$cr/Guest Profile"
    write_file "$U/alice/Library/Application Support/Microsoft Edge/Default/Extensions/odfafepnkmbhccpbejgmiehpchacaeak/1.58.0_0/manifest.json" '{"manifest_version":3,"name":"uBlock Origin","version":"1.58.0","permissions":["storage"],"host_permissions":["<all_urls>"],"update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"}'
    local ff="$U/alice/Library/Application Support/Firefox/Profiles"
    write_file "$ff/abcd1234.default-release/extensions.json" '{"schemaVersion":36,"addons":[{"id":"uBlock0@raymondhill.net","type":"extension","version":"1.60.0","active":true,"userDisabled":false,"defaultLocale":{"name":"uBlock Origin"},"permissions":["storage"],"userPermissions":{"permissions":["tabs"],"hosts":["<all_urls>"]},"updateURL":"https://addons.mozilla.org/update"},{"id":"default-theme@mozilla.org","type":"theme","version":"1.4"},{"id":"noname@example.com","type":"extension","version":"0.2","active":false}]}'

    # bob: Chrome Default and two Firefox profiles, one with no extensions.json.
    write_file "$U/bob/Library/Application Support/Google/Chrome/Default/Extensions/ghbmnnjooekpmoecnnnilnnbdlolhkhi/1.80.0_0/manifest.json" '{"manifest_version":3,"name":"Google Docs Offline","version":"1.80.0","permissions":["alarms","storage"],"update_url":"https://clients2.google.com/service/update2/crx"}'
    write_file "$U/bob/Library/Application Support/Firefox/Profiles/zzzz9999.default/extensions.json" '{"addons":[{"id":"{446900e4-71c2-419f-a6a7-df9c091e268b}","type":"extension","version":"2024.1.0","active":true,"userDisabled":true,"defaultLocale":{"name":"Bitwarden"},"permissions":[],"userPermissions":{"permissions":["storage"],"hosts":["https://*/*"]}}]}'
    mkdir -p "$U/bob/Library/Application Support/Firefox/Profiles/aaaa0000.dev-edition-default"

    # Safari: a system app with a web extension (manifest.json nested under
    # Resources) and a Mac App Store app with a legacy extension; a user app
    # under ~/Applications with a web extension.
    plist "$APPS/Vendor/Host.app/Contents/Info.plist" "{'CFBundleName': 'Vendor Host'}"
    plist "$APPS/Vendor/Host.app/Contents/PlugIns/Web.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.vendor.web', 'CFBundleDisplayName': 'Vendor Web', 'CFBundleShortVersionString': '2.1', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.web-extension'}}"
    write_file "$APPS/Vendor/Host.app/Contents/PlugIns/Web.appex/Contents/Resources/ext/manifest.json" '{"manifest_version":2,"permissions":["tabs","https://*/*"]}'
    plist "$APPS/Mas.app/Contents/Info.plist" "{'CFBundleName': 'Mas App'}"
    mkdir -p "$APPS/Mas.app/Contents/_MASReceipt"
    plist "$APPS/Mas.app/Contents/PlugIns/Legacy.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.mas.legacy', 'CFBundleName': 'Mas Legacy', 'CFBundleShortVersionString': '3.0', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension', 'SFSafariWebsiteAccess': {'Level': 'Some', 'Allowed Domains': ['example.com']}}}"
    plist "$U/alice/Applications/Mine.app/Contents/Info.plist" "{'CFBundleName': 'Mine'}"
    plist "$U/alice/Applications/Mine.app/Contents/PlugIns/MineExt.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.alice.mine', 'CFBundleName': 'Mine Ext', 'CFBundleShortVersionString': '0.9', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.web-extension'}}"
    write_file "$U/alice/Applications/Mine.app/Contents/PlugIns/MineExt.appex/Contents/Resources/manifest.json" '{"manifest_version":3,"permissions":["activeTab"],"host_permissions":["https://example.org/*"]}'
    SAFARI_ROOTS=("$APPS" "$U/alice/Applications")
}

# run: the real collector against the tree; output lands in $OUT, the
# collect-log lines in $LOG.
run() {
    QUEUE_DIR=$(mktemp -d "$WORK/queue.XXXXXX")
    TS_FILE="test"
    _BX_USERS_ROOT="$U"
    _BX_SAFARI_ROOTS=("${SAFARI_ROOTS[@]}")
    collect_browser_extensions 2> "$WORK/last.log"
    OUT="$BROWSER_EXTENSIONS_JSON_FILE"
    LOG="$WORK/last.log"
}

# The old script hard-codes /Users and the real app locations; point both at
# the fixture so its output can be compared.
if [[ -n "${BX_PRINT_WITH:-}" ]]; then
    build_tree
    sed -e "s|/Users/|$U/|g" \
        -e "s|(/Applications /Applications/Utilities $U/\\*/Applications)|(\"\${SAFARI_ROOTS[@]}\")|" \
        "$BX_PRINT_WITH" > "$WORK/old.sh"
    source "$WORK/old.sh"
    QUEUE_DIR=$(mktemp -d "$WORK/queue.XXXXXX"); TS_FILE="test"
    collect_browser_extensions 2>/dev/null
    cat "$BROWSER_EXTENSIONS_JSON_FILE"
    exit 0
fi

source "$MODULE"

# jq_py <python expression over `rows`> against the last run's output.
jq_py() {
    "$REAL_PYTHON3" -c 'import json,sys; rows=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$OUT" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }
no_leak() { [[ -s "$OUT" ]] && ! grep -qi leaked "$OUT" && echo 1 || echo 0; }

##############################################################################
echo "[wire] a realistic estate produces exactly the pre-PAT-2054 rows"
GOLDEN='[
{"browser":"chrome","profile":"Default","user_account":"alice","extension_id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","name":"uBlock Origin","version":"1.60.0_0","enabled":true,"permissions":["storage","tabs"],"host_permissions":["<all_urls>","http://*/*"],"from_webstore":true,"update_url":"https://clients2.google.com/service/update2/crx"}
,{"browser":"chrome","profile":"Default","user_account":"alice","extension_id":"devextdevextdevextdevextdevextde","name":"Dev Helper","version":"0.1","enabled":true,"permissions":[],"host_permissions":[],"from_webstore":false}
,{"browser":"chrome","profile":"Default","user_account":"alice","extension_id":"nngceckbapebfimnlniiiahkandclblb","name":"Bitwarden","version":"2024.1.0_0","enabled":false,"permissions":["tabs","storage"],"host_permissions":["https://*/*"],"from_webstore":true,"update_url":"https://clients2.google.com/service/update2/crx"}
,{"browser":"chrome","profile":"Profile 2","user_account":"alice","extension_id":"aapbdbdomjkkjkaonfhkkikfgjllcleb","name":"Google Translate","version":"2.0.16_0","enabled":true,"permissions":["activeTab","contextMenus"],"host_permissions":[],"from_webstore":true,"update_url":"https://update.googleapis.com/service/update2/crx"}
,{"browser":"edge","profile":"Default","user_account":"alice","extension_id":"odfafepnkmbhccpbejgmiehpchacaeak","name":"uBlock Origin","version":"1.58.0_0","enabled":true,"permissions":["storage"],"host_permissions":["<all_urls>"],"from_webstore":false,"update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"}
,{"browser":"firefox","profile":"abcd1234.default-release","user_account":"alice","extension_id":"uBlock0@raymondhill.net","name":"uBlock Origin","version":"1.60.0","enabled":true,"permissions":["storage","tabs"],"host_permissions":["<all_urls>"],"from_webstore":true,"update_url":"https://addons.mozilla.org/update"}
,{"browser":"firefox","profile":"abcd1234.default-release","user_account":"alice","extension_id":"noname@example.com","name":"noname@example.com","version":"0.2","enabled":false,"permissions":[],"host_permissions":[],"from_webstore":false}
,{"browser":"chrome","profile":"Default","user_account":"bob","extension_id":"ghbmnnjooekpmoecnnnilnnbdlolhkhi","name":"Google Docs Offline","version":"1.80.0_0","enabled":true,"permissions":["alarms","storage"],"host_permissions":[],"from_webstore":true,"update_url":"https://clients2.google.com/service/update2/crx"}
,{"browser":"firefox","profile":"zzzz9999.default","user_account":"bob","extension_id":"{446900e4-71c2-419f-a6a7-df9c091e268b}","name":"Bitwarden","version":"2024.1.0","enabled":false,"permissions":["storage"],"host_permissions":["https://*/*"],"from_webstore":false}
,{"browser":"safari","profile":null,"user_account":null,"extension_id":"com.mas.legacy","name":"Mas Legacy","version":"3.0","enabled":null,"permissions":[],"host_permissions":["example.com"],"from_webstore":true,"vendor":"Mas App"}
,{"browser":"safari","profile":null,"user_account":null,"extension_id":"com.vendor.web","name":"Vendor Web","version":"2.1","enabled":null,"permissions":["tabs"],"host_permissions":["https://*/*"],"from_webstore":false,"vendor":"Vendor Host"}
,{"browser":"safari","profile":null,"user_account":null,"extension_id":"com.alice.mine","name":"Mine Ext","version":"0.9","enabled":null,"permissions":["activeTab"],"host_permissions":["https://example.org/*"],"from_webstore":false,"vendor":"Mine"}
]'
build_tree
run
chk "output is byte-identical to the pre-PAT-2054 collector" "$([[ "$(cat "$OUT")" == "$GOLDEN" ]] && echo 1 || echo 0)"
[[ "$(cat "$OUT")" == "$GOLDEN" ]] || diff <(print -r -- "$GOLDEN") "$OUT"
chk "twelve rows, nothing refused on a clean estate" "$([[ "$EXT_COUNT" == 12 ]] && ! grep -q refused "$LOG" && echo 1 || echo 0)"

##############################################################################
echo "[locale] a default_locale that climbs out of the extension does not leak another user's JSON"
# bob's own extension carries a messages.json whose key matches alice's
# __MSG_ name. alice's manifest points default_locale at it with ../ enough to
# reach / from anywhere, then down into bob's home.
build_tree
BOB_EXT="$U/bob/Library/Application Support/Google/Chrome/Default/Extensions/bobbobbobbobbobbobbobbobbobbobbo/1.0"
write_file "$BOB_EXT/manifest.json" '{"manifest_version":3,"name":"Bob Tool","version":"1.0"}'
write_file "$BOB_EXT/_locales/en/messages.json" '{"appName":{"message":"LEAKED bob private message"}}'
UP=""; for i in {1..40}; do UP="$UP../"; done
TRAVERSAL="${UP}${BOB_EXT#/}/_locales/en"
ALICE_EXT="$U/alice/Library/Application Support/Google/Chrome/Default/Extensions/travtravtravtravtravtravtravtrav/1.0"
mkdir -p "$ALICE_EXT/_locales"
write_file "$ALICE_EXT/manifest.json" "{\"manifest_version\":3,\"name\":\"__MSG_appName__\",\"default_locale\":\"$TRAVERSAL\",\"version\":\"1.0\"}"
[[ -f "$ALICE_EXT/_locales/$TRAVERSAL/messages.json" ]] && TRAV_REAL=1 || TRAV_REAL=0
chk "the traversal really resolves to bob's messages.json (so the test can fail)" "$TRAV_REAL"
run
chk "bob's message is not reported as alice's extension name" "$(no_leak)"
chk "the name falls back to the extension id" \
    "$(is_true '[r["name"] for r in rows if r["extension_id"] == "travtravtravtravtravtravtravtrav"] == ["travtravtravtravtravtravtravtrav"]')"
chk "the unsafe locale is written to the collect log" "$(grep -q 'unsafe_default_locale' "$LOG" && echo 1 || echo 0)"
# Absolute and single-dot forms are refused too; a plain locale still resolves.
for bad in "/etc" "." ".." "en/../../x" "" "$(printf 'e%.0s' {1..40})"; do
    chk "default_locale '${bad[1,20]}' is not a plain component" \
        "$("$REAL_PYTHON3" -c 'import re,sys; ok=re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$", sys.argv[1]); print(0 if ok else 1)' "$bad")"
done
chk "the locale rule in the collector is the one tested above" \
    "$(grep -qF 'LOCALE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")' "$MODULE" && echo 1 || echo 0)"

##############################################################################
echo "[symlink] a symlinked extension or profile directory into another home is refused"
build_tree
BOB_CHROME="$U/bob/Library/Application Support/Google/Chrome/Default"
write_file "$BOB_CHROME/Extensions/secretsecretsecretsecretsecretse/1.0/manifest.json" '{"manifest_version":3,"name":"Bob Secret Ext","version":"1.0"}'
ln -s "$BOB_CHROME/Extensions/secretsecretsecretsecretsecretse" \
    "$U/alice/Library/Application Support/Google/Chrome/Default/Extensions/linklinklinklinklinklinklinklink"
ln -s "$BOB_CHROME" "$U/alice/Library/Application Support/Microsoft Edge/Profile 1"
ln -s "$U/bob/Library/Application Support/Firefox/Profiles/zzzz9999.default" \
    "$U/alice/Library/Application Support/Firefox/Profiles/linked.default"
run
chk "no row from bob's extension appears under alice" "$(is_true 'not any(r["user_account"] == "alice" and r["name"] == "Bob Secret Ext" for r in rows)')"
chk "no row for the linked extension id" "$(is_true 'not any(r["extension_id"] == "linklinklinklinklinklinklinklink" for r in rows)')"
chk "no Edge row for the linked Profile 1" "$(is_true 'not any(r["profile"] == "Profile 1" for r in rows)')"
chk "no Firefox row for the linked profile" "$(is_true 'not any(r["profile"] == "linked.default" for r in rows)')"
chk "alice's real rows are still sent" "$(is_true 'sum(1 for r in rows if r["user_account"] == "alice") == 7')"
chk "the refusals are written to the collect log" "$(grep -q 'refused .* symlink_not_followed' "$LOG" && echo 1 || echo 0)"

##############################################################################
echo "[manifest] a symlinked manifest, extensions.json or Safari bundle file is refused"
build_tree
write_file "$WORK/secret/fake-manifest.json" '{"manifest_version":3,"name":"LEAKED root-only manifest","version":"6.6.6","permissions":["LEAKED"]}'
write_file "$WORK/secret/extensions.json" '{"addons":[{"id":"leaked@example.com","type":"extension","version":"1","defaultLocale":{"name":"LEAKED"}}]}'
plist "$WORK/secret/Info.plist" "{'CFBundleIdentifier': 'com.leaked.plist', 'CFBundleName': 'LEAKED plist', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension', 'SFSafariWebsiteAccess': {'Level': 'All'}}}"
MFDIR="$U/alice/Library/Application Support/Google/Chrome/Default/Extensions/mfmfmfmfmfmfmfmfmfmfmfmfmfmfmfmf/1.0"
mkdir -p "$MFDIR"; ln -s "$WORK/secret/fake-manifest.json" "$MFDIR/manifest.json"
FFL="$U/alice/Library/Application Support/Firefox/Profiles/mfmf.default"
mkdir -p "$FFL"; ln -s "$WORK/secret/extensions.json" "$FFL/extensions.json"
EVIL="$U/alice/Applications/Evil.app/Contents/PlugIns/Evil.appex/Contents"
mkdir -p "$EVIL"; ln -s "$WORK/secret/Info.plist" "$EVIL/Info.plist"
MINE_RES="$U/alice/Applications/Mine.app/Contents/PlugIns/MineExt.appex/Contents/Resources"
rm "$MINE_RES/manifest.json"; ln -s "$WORK/secret/fake-manifest.json" "$MINE_RES/manifest.json"
run
chk "nothing from the linked files reaches the output" "$(no_leak)"
chk "no Chrome row for the extension whose manifest is a link" "$(is_true 'not any(r["extension_id"] == "mfmfmfmfmfmfmfmfmfmfmfmfmfmfmfmf" for r in rows)')"
chk "no Firefox row for the profile whose extensions.json is a link" "$(is_true 'not any(r["profile"] == "mfmf.default" for r in rows)')"
chk "no Safari row for the bundle whose Info.plist is a link" "$(is_true 'not any(r["extension_id"] == "com.leaked.plist" for r in rows)')"
chk "the Safari extension with a linked manifest.json sends no permissions from it" \
    "$(is_true '[(r["permissions"], r["host_permissions"]) for r in rows if r["extension_id"] == "com.alice.mine"] == [([], [])]')"
chk "the refusals are written to the collect log" "$(grep -q 'refused' "$LOG" && echo 1 || echo 0)"

##############################################################################
echo "[race] a directory swapped for a symlink between its check and the read is not read through (PAT-2033)"
# A test-only sitecustomize.py swaps one directory for a symlink to a decoy the
# moment the collector's lstat has reported it a directory: the window between
# a check and the open that follows it. Every leaked marker lives in the decoy.
# The first check proves the swap happened, so this cannot pass by never
# reaching the race.
mkdir -p "$WORK/race-hook"
cat > "$WORK/race-hook/sitecustomize.py" <<'HOOKEOF'
import os
import stat

_dir = os.environ.get("PATCHED_RACE_DIR")
_decoy = os.environ.get("PATCHED_RACE_DECOY")
_lstat = os.lstat
_fired = []


def _is_target(path, dir_fd):
    if not isinstance(path, str):
        return False
    if dir_fd is None:
        return os.path.normpath(path) == _dir
    if path != os.path.basename(_dir):
        return False
    try:
        return os.fstat(dir_fd).st_ino == _lstat(os.path.dirname(_dir)).st_ino
    except OSError:
        return False


def _hooked_lstat(path, *, dir_fd=None):
    st = _lstat(path, dir_fd=dir_fd)
    if not _fired and stat.S_ISDIR(st.st_mode) and _is_target(path, dir_fd):
        _fired.append(True)
        os.rename(_dir, _dir + ".checked")
        os.symlink(_decoy, _dir)
    return st


if _dir and _decoy:
    os.lstat = _hooked_lstat
HOOKEOF
race_run() {
    export PYTHONPATH="$WORK/race-hook" PATCHED_RACE_DIR="$1" PATCHED_RACE_DECOY="$2"
    run
    unset PYTHONPATH PATCHED_RACE_DIR PATCHED_RACE_DECOY
}
swapped() { [[ -L "$1" && -d "$1.checked" ]] && echo 1 || echo 0; }

build_tree
RACE_DECOY="$WORK/race-decoy"; rm -rf "$RACE_DECOY"
write_file "$RACE_DECOY/decoydecoydecoydecoydecoydecoyde/1.0/manifest.json" '{"manifest_version":3,"name":"LEAKED race decoy","version":"1.0"}'
RACE_DIR="$U/alice/Library/Application Support/Google/Chrome/Default/Extensions"
race_run "$RACE_DIR" "$RACE_DECOY"
chk "the Extensions directory was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "nothing was read through the swapped-in link" "$(no_leak)"
chk "the refusal is written to the collect log" "$(grep -q 'refused' "$LOG" && echo 1 || echo 0)"
chk "the rest of the estate is still sent" "$(is_true 'sum(1 for r in rows if r["user_account"] == "bob") == 2')"

##############################################################################
echo "[nan] a non-finite number or a wrong-typed field cannot put invalid JSON on the wire"
# json.loads accepts NaN and Infinity and json.dumps writes them back bare,
# which is not JSON: the server then rejects the device's whole inventory
# every cycle. A file carrying one is unparseable; a field of the wrong type
# is dropped; a list keeps only its strings.
build_tree
CRX="$U/alice/Library/Application Support/Google/Chrome/Default/Extensions"
write_file "$CRX/nannannannannannannannannannanna/1.0/manifest.json" '{"manifest_version":3,"name":"NaN Ext","version":"1.0","host_permissions":[NaN]}'
write_file "$CRX/typedtypedtypedtypedtypedtypedty/1.0/manifest.json" '{"manifest_version":3,"name":{"x":1},"version":"1.0","permissions":["storage",5,null],"host_permissions":["https://a.example/*",7,{"h":1}],"update_url":7}'
FFP="$U/alice/Library/Application Support/Firefox/Profiles"
write_file "$FFP/nan.default/extensions.json" '{"addons":[{"id":"nan@example.com","type":"extension","version":"1","defaultLocale":{"name":{"evil":NaN}}}]}'
write_file "$FFP/typed.default/extensions.json" '{"addons":[{"id":"typed@example.com","type":"extension","version":3,"defaultLocale":{"name":{"evil":1}},"permissions":["a",1],"userPermissions":{"permissions":[true],"hosts":[null,"<all_urls>"]},"updateURL":5},{"id":9,"type":"extension"}]}'
plist "$APPS/Inf.app/Contents/PlugIns/Inf.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.inf.ext', 'CFBundleName': 'Inf Ext', 'CFBundleShortVersionString': 1e999, 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension', 'SFSafariWebsiteAccess': {'Level': 'Some', 'Allowed Domains': ['example.net', -1e999]}}}"
run
STRICT=$("$REAL_PYTHON3" -c '
import json, sys
def refuse(c):
    raise ValueError(c)
json.loads(open(sys.argv[1]).read(), parse_constant=refuse)
print(1)' "$OUT" 2>/dev/null)
chk "the output is strict JSON (no NaN or Infinity anywhere)" "$([[ "$STRICT" == 1 ]] && echo 1 || echo 0)"
chk "the manifest with a NaN host permission is dropped" "$(is_true 'not any(r["extension_id"] == "nannannannannannannannannannanna" for r in rows)')"
chk "a non-string name falls back to the id; non-string list items and update_url are dropped" \
    "$(is_true '[(r["name"], r["permissions"], r["host_permissions"], "update_url" in r) for r in rows if r["extension_id"] == "typedtypedtypedtypedtypedtypedty"] == [("typedtypedtypedtypedtypedtypedty", ["storage"], ["https://a.example/*"], False)]')"
chk "the Firefox profile with a NaN name is dropped" "$(is_true 'not any(r["profile"] == "nan.default" for r in rows)')"
chk "Firefox: a non-string name and version are dropped, lists keep only strings, a non-string id drops the row" \
    "$(is_true '[(r["extension_id"], r["name"], r["version"], r["permissions"], r["host_permissions"], "update_url" in r) for r in rows if r["profile"] == "typed.default"] == [("typed@example.com", "typed@example.com", "", ["a"], ["<all_urls>"], False)]')"
chk "Safari: an infinite version is dropped and a non-string domain is left out" \
    "$(is_true '[(r["version"], r["host_permissions"]) for r in rows if r["extension_id"] == "com.inf.ext"] == [("", ["example.net"])]')"
chk "the rest of the estate is still sent" "$(is_true 'sum(1 for r in rows if r["user_account"] == "bob") == 2')"

##############################################################################
echo "[newline] a newline in a directory name cannot inject a path outside the Safari search root"
# alice makes a directory whose name ends in a newline, and below it the
# components of the absolute path to a bundle she cannot otherwise make root
# read. Split on newlines, find's output line becomes that path.
NL=$(mktemp -d /tmp/.bxnl.XXXXXX); NL=${NL:A}
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK" "$NL"' EXIT
plist "$NL/Contents/PlugIns/P.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.bob.PRIVATE', 'CFBundleName': 'LEAKED private bundle', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension'}}"
mkdir -p "$NL/alice/Applications/X"$'\n'"$NL/Contents/PlugIns/P.appex"
LISTED=$(find "$NL/alice/Applications" -iname "*.appex" -ipath "*/Contents/PlugIns/*" | grep -cxF "$NL/Contents/PlugIns/P.appex")
chk "find's newline-split output really names the private bundle (so the test can fail)" "$([[ "$LISTED" == 1 ]] && echo 1 || echo 0)"
U="$NL/no-users"; SAFARI_ROOTS=("$NL/alice/Applications")
run
chk "the private bundle outside the search root is not read" "$(is_true 'not any(r["extension_id"] == "com.bob.PRIVATE" for r in rows)')"
chk "nothing from it reaches the output" "$(no_leak)"

##############################################################################
echo "[safari-malformed] one malformed bundle costs its own row, not every Safari row sorted after it"
# The appex list is sorted, so a bundle a user names to sort first used to
# end every Safari row after it, other users' ~/Applications included.
build_tree
plist "$APPS/Aa.app/Contents/PlugIns/ListRoot.appex/Contents/Info.plist" "['not', 'a', 'dict']"
plist "$APPS/Ab.app/Contents/PlugIns/StrExt.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.bad.str', 'NSExtension': 'not a dict'}"
plist "$APPS/Ac.app/Contents/PlugIns/BadAccess.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.bad.access', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension', 'SFSafariWebsiteAccess': ['x']}}"
run
chk "every well-formed Safari row is still sent" \
    "$(is_true 'sorted(r["extension_id"] for r in rows if r["browser"] == "safari") == ["com.alice.mine", "com.mas.legacy", "com.vendor.web"]')"
chk "the malformed bundles are written to the collect log" "$([[ "$(grep -o 'malformed_bundle' "$LOG" | wc -l | tr -d ' ')" -ge 1 ]] && grep -q 'ListRoot.appex' "$LOG" && echo 1 || echo 0)"

echo "[safari-fd] an unreadable pluginkit list does not drop every Safari row"
build_tree
find "$APPS" -iname "*.appex" -ipath "*/Contents/PlugIns/*" -print0 > "$WORK/appex.list"
# A directory on fd 4 makes os.read fail with EISDIR.
FD_ROWS=$(_bx_python safari "$APPS" 3<"$WORK/appex.list" 4<"$WORK" 2>/dev/null | wc -l | tr -d ' ')
chk "both Safari rows are still sent, with enabled unknown" "$([[ "$FD_ROWS" == 2 ]] && echo 1 || echo 0)"

##############################################################################
echo "[static] every python read is walked from / with no path left to swap"
PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 300 ))"
chk "exactly one python program in the module" "$([[ "$(grep -cE '<<.PYEOF.( &)?$' "$MODULE")" == 1 ]] && echo 1 || echo 0)"
chk "every os.open is O_NOFOLLOW: / itself, or relative to a walked directory" \
    "$([[ "$(grep -c 'os\.open(' "$PY_PART")" == 4 \
        && -z "$(grep 'os\.open(' "$PY_PART" | grep -vE 'os\.open\("/", DIR_FLAGS\)|os\.open\((part|name), (DIR|FILE)_FLAGS, dir_fd=')" ]] && echo 1 || echo 0)"
hits=$(grep -nE '(^|[^.A-Za-z_])open\(|os\.(lstat|readlink|scandir|listdir|stat|access|chdir|walk)\(|os\.path\.(exists|lexists|isdir|isfile|islink|getsize|join|realpath)\(|follow_symlinks=True' "$PY_PART" \
    | grep -vE 'os\.(lstat|readlink)\((part|name), dir_fd=[a-z_]+(\[-1\])?\)|os\.scandir\(fd\)')
chk "no builtin open, and no stat, readlink, listing or join given a whole path" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"

##############################################################################
# PAT-2065: browser_extensions_status
CONTRACT="$SCRIPT_DIR/../../contracts/inventory-browser-extensions-status.schema.json"
cat > "$WORK/check.py" <<'CHECKEOF'
"""check.py <schema> <status-block> <rows>: prints OK, or the first problem.

Structure: the vendored platform schema, over the block and the Chrome, Edge
and Firefox rows. (The platform's row schema types profile and user_account as
strings, which the Safari rows, null in both since PAT-821, have never matched;
that pre-dates PAT-2065 and the rows are unchanged here, so Safari rows are
left out of the schema half.)

Consistency: a line-for-line port of browserExtensionsStatusProblem in
patched.im go-service/internal/extractor/validate_browser_extensions_status.go.
Any reason it returns means the platform would withhold the block's authority.
"""
import json, sys
import jsonschema

schema = json.load(open(sys.argv[1]))
block = json.load(open(sys.argv[2]))
rows = json.load(open(sys.argv[3]))

doc = {"browser_extensions_status": block,
       "browser_extensions": [r for r in rows if r.get("browser") != "safari"]}
errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=str)
if errors:
    print("schema: " + errors[0].message + " at " + "/".join(map(str, errors[0].absolute_path)))
    sys.exit(0)

BROWSERS = ("chrome", "edge", "firefox")
def fits(parent, child):
    if parent == "complete":
        return child in ("complete", "not_present")
    if parent == "not_present":
        return child == "not_present"
    return True

def problem(st):
    status = st["collection_status"]
    if status == "failed":
        return ""
    # Structural rule from validateBrowserExtensionsStatus, not in the schema.
    if "cap_reached" not in st or "users" not in st:
        return "structure: cap_reached and users are required unless failed"
    for u in st["users"]:
        if u["collection_status"] != "failed" and any(b not in u["browsers"] for b in BROWSERS):
            return "structure: every browser is required unless the user is failed"
    if st["cap_reached"] and status != "partial":
        return "cap_reached_not_partial"
    if len(st["users"]) > 500:
        return "too_many_users"
    pairs, seen = {}, set()
    for u in st["users"]:
        if u["user"] in seen:
            return "duplicate_user"
        seen.add(u["user"])
        if not fits(status, u["collection_status"]):
            return "user_status_inconsistent"
        for b in BROWSERS:
            s = u["browsers"].get(b)
            if s is None:
                continue
            if not fits(status, s) or not fits(u["collection_status"], s):
                return "browser_status_inconsistent"
            pairs[(u["user"], b)] = s
    for r in rows:
        if not r.get("user_account") or r.get("browser") not in BROWSERS:
            continue
        key = (r["user_account"], r["browser"])
        pst = pairs.get(key)
        if status == "not_present":
            return "rows_listed_when_not_present"
        if pst == "not_present":
            return "row_under_not_present_pair"
        if status == "complete" and pst != "complete":
            return "row_not_reported_complete"
    return ""

reason = problem(block)
# Opt-in: PATCHED_BX_STATUS_DUMP=<dir> keeps every checked payload, so it can also be
# run through patched.im's own Go validator.
import os, uuid
if os.environ.get("PATCHED_BX_STATUS_DUMP"):
    with open(os.path.join(os.environ["PATCHED_BX_STATUS_DUMP"], "mac-" + uuid.uuid4().hex + ".json"), "w") as f:
        json.dump({"browser_extensions_status": block, "browser_extensions": rows}, f)
print("OK" if not reason else "withheld: " + reason)
CHECKEOF
# contract_ok: the last run's block and rows pass the schema and grant authority.
contract_ok() {
    local verdict
    verdict=$("$REAL_PYTHON3" "$WORK/check.py" "$CONTRACT" "$BROWSER_EXTENSIONS_STATUS_FILE" "$OUT" 2>&1)
    if [[ "$verdict" == "OK" ]]; then echo 1; else echo "$verdict" >&2; echo 0; fi
}
# st_py <python expression over `st`> against the last run's block.
st_py() {
    "$REAL_PYTHON3" -c 'import json,sys; st=json.load(open(sys.argv[1])); users={u["user"]: u for u in st.get("users", [])}; print(eval(sys.argv[2]))' "$BROWSER_EXTENSIONS_STATUS_FILE" "$1" 2>/dev/null
}
st_true() { [[ "$(st_py "$1")" == "True" ]] && echo 1 || echo 0; }
# pair <user> <browser>: that pair's status in the last block.
pair() { st_py "users[\"$1\"][\"browsers\"][\"$2\"]"; }

# PAT-2067: collection_status.safari_extensions after the last run.
sx_is() { [[ "$(safari_extensions_collection_status)" == "$1" ]] && echo 1 || { echo "    safari_extensions=$(safari_extensions_collection_status)" >&2; echo 0; }; }
# block_untouched: the last block is the [wire] estate's, complete and uncapped,
# whatever the Safari walk did.
block_untouched() { st_true 'st["collection_status"] == "complete" and st["cap_reached"] is False'; }
# sx_verdict [value] [block-json | none] [row-count]: what the platform makes of
# a safari_extensions value (default: the last run's) beside a block (default:
# the last run's; "none" for no block) and rows (default: the last run's, or
# that many). "authoritative", "withheld: <reason>", "none" (grants nothing),
# or "schema: <error>" against the vendored collection_status schema. A port of
# resolveSafariSignal in patched.im go-service/internal/extractor/
# safari_authority.go, for a schema v3 payload that sends the array.
sx_verdict() {
    "$REAL_PYTHON3" - "$CONTRACT" "${1:-$(safari_extensions_collection_status)}" "${2:-}" "$BROWSER_EXTENSIONS_STATUS_FILE" "$OUT" "${3:-}" <<'SXEOF'
import json, sys
import jsonschema
schema_path, value, block_arg, block_file, rows_file, nrows = sys.argv[1:7]
schema = json.load(open(schema_path))
errors = list(jsonschema.Draft202012Validator(schema).iter_errors({"collection_status": {"safari_extensions": value}}))
if errors:
    print("schema: " + errors[0].message); sys.exit(0)
block = None if block_arg == "none" else json.loads(block_arg) if block_arg else json.load(open(block_file))
rows = [{}] * int(nrows) if nrows else json.load(open(rows_file))
if value == "complete":
    if block is None:
        print("withheld: complete_without_browser_extensions_status")
    elif block.get("cap_reached") is True:
        print("withheld: cap_reached")
    elif len(rows) >= 1000:
        print("withheld: row_cap_full")
    else:
        print("authoritative")
elif value == "unavailable" and any(r.get("browser") == "safari" for r in rows):
    print("withheld: unavailable_with_safari_rows_listed")
else:
    print("none")
SXEOF
}

##############################################################################
echo "[contract] the checker itself goes red on each rule it ports (so it can fail)"
build_tree
run
GOOD_BLOCK="$BROWSER_EXTENSIONS_STATUS_FILE"
chk "the [wire] estate passes" "$(contract_ok)"
mutate() {
    "$REAL_PYTHON3" -c 'import json,sys; st=json.load(open(sys.argv[1])); users={u["user"]: u for u in st["users"]}; exec(sys.argv[2]); json.dump(st, open(sys.argv[3], "w"))' \
        "$GOOD_BLOCK" "$1" "$WORK/mutated.json"
    "$REAL_PYTHON3" "$WORK/check.py" "$CONTRACT" "$WORK/mutated.json" "$OUT" 2>&1
}
chk "complete with a row under a partial pair is withheld" \
    "$([[ "$(mutate 'users["bob"]["browsers"]["firefox"]="partial"')" == "withheld: browser_status_inconsistent" ]] && echo 1 || echo 0)"
chk "a row under a not_present pair is withheld" \
    "$([[ "$(mutate 'st["collection_status"]="partial"; users["bob"]["collection_status"]="partial"; users["bob"]["browsers"]["chrome"]="not_present"')" == "withheld: row_under_not_present_pair" ]] && echo 1 || echo 0)"
chk "a complete block missing a user with rows is withheld" \
    "$([[ "$(mutate 'st["users"]=[u for u in st["users"] if u["user"] != "bob"]')" == "withheld: row_not_reported_complete" ]] && echo 1 || echo 0)"
chk "a user whose case differs from the rows is withheld" \
    "$([[ "$(mutate 'users["bob"]["user"]="Bob"')" == "withheld: row_not_reported_complete" ]] && echo 1 || echo 0)"
chk "cap_reached on a complete block is withheld" \
    "$([[ "$(mutate 'st["cap_reached"]=True')" == "withheld: cap_reached_not_partial" ]] && echo 1 || echo 0)"
chk "an unknown key fails the schema" \
    "$([[ "$(mutate 'st["safari"]="complete"')" == schema:* ]] && echo 1 || echo 0)"
chk "a Safari browser key fails the schema" \
    "$([[ "$(mutate 'users["bob"]["browsers"]["safari"]="complete"')" == schema:* ]] && echo 1 || echo 0)"

echo "[contract-drift] the vendored schema matches patched.im's payload.schema.json"
PLATFORM_REPO="${PATCHED_PLATFORM_REPO:-$SCRIPT_DIR/../../../patched.im}"
if git -C "$PLATFORM_REPO" rev-parse --verify -q origin/main >/dev/null 2>&1; then
    git -C "$PLATFORM_REPO" show origin/main:go-service/docs/payload.schema.json > "$WORK/platform-schema.json" 2>/dev/null
    chk "browser_extensions_status, browser_extensions and collection_status are identical to the platform's" "$("$REAL_PYTHON3" -c '
import json, sys
v = json.load(open(sys.argv[1]))["properties"]
p = json.load(open(sys.argv[2]))["properties"]
print(int(all(v[k] == p[k] for k in ("browser_extensions_status", "browser_extensions", "collection_status"))))' "$CONTRACT" "$WORK/platform-schema.json")"
else
    echo "  SKIP: no patched.im checkout at $PLATFORM_REPO (set PATCHED_PLATFORM_REPO)"
fi

##############################################################################
echo "[status-complete] the [wire] estate is complete, pair by pair"
build_tree
run
chk "rows are still byte-identical to GOLDEN" "$([[ "$(cat "$OUT")" == "$GOLDEN" ]] && echo 1 || echo 0)"
chk "the block is complete and not capped" "$(st_true 'st["collection_status"] == "complete" and st["cap_reached"] is False')"
chk "alice: all three complete" "$(st_true 'users["alice"]["collection_status"] == "complete" and users["alice"]["browsers"] == {"chrome": "complete", "edge": "complete", "firefox": "complete"}')"
chk "bob: no Edge user-data directory is not_present, the rest complete" \
    "$(st_true 'users["bob"]["browsers"] == {"chrome": "complete", "edge": "not_present", "firefox": "complete"} and users["bob"]["collection_status"] == "complete"')"
chk "carol: a home with no browsers is not_present for all three" \
    "$(st_true 'users["carol"]["collection_status"] == "not_present" and set(users["carol"]["browsers"].values()) == {"not_present"}')"
chk "Shared is not a user, and Safari is not in the block" "$(st_true 'sorted(users) == ["alice", "bob", "carol"] and "safari" not in json.dumps(st)')"
chk "user_id is the uid that owns each home" \
    "$([[ "$(st_py '[u["user_id"] for u in st["users"]]')" == "$("$REAL_PYTHON3" -c 'import os,sys; print([str(os.lstat(sys.argv[1] + "/" + n).st_uid) for n in ("alice", "bob", "carol")])' "$U")" ]] && echo 1 || echo 0)"
chk "the block passes the contract" "$(contract_ok)"

echo "[status-not-present] no browser anywhere"
rm -rf "$WORK/np"; mkdir -p "$WORK/np/Users/dave/Documents" "$WORK/np/Users/erin"
U="$WORK/np/Users"; SAFARI_ROOTS=("$WORK/np/Users/erin")
run
chk "the block is not_present with both users listed and no rows" \
    "$(st_true 'st["collection_status"] == "not_present" and sorted(users) == ["dave", "erin"] and not st["cap_reached"]')"
chk "the array is empty" "$([[ "$EXT_COUNT" == 0 ]] && echo 1 || echo 0)"
chk "the block passes the contract" "$(contract_ok)"
rm -rf "$WORK/np/Users/dave" "$WORK/np/Users/erin"
mkdir -p "$WORK/np/Applications"; SAFARI_ROOTS=("$WORK/np/Applications")
run
chk "no users at all is not_present with an empty roster" "$(st_true 'st == {"collection_status": "not_present", "cap_reached": False, "users": []}')"

##############################################################################
echo "[status-partial] a refusal makes exactly its own (user, browser) partial"
build_tree
BOB_CHROME="$U/bob/Library/Application Support/Google/Chrome/Default"
ln -s "$BOB_CHROME" "$U/alice/Library/Application Support/Microsoft Edge/Profile 1"
run
chk "alice's Edge, with a linked profile, is partial" "$([[ "$(pair alice edge)" == partial ]] && echo 1 || echo 0)"
chk "alice's Chrome and Firefox stay complete" "$([[ "$(pair alice chrome)$(pair alice firefox)" == completecomplete ]] && echo 1 || echo 0)"
chk "alice is partial, bob complete, the block partial and not capped" \
    "$(st_true 'users["alice"]["collection_status"] == "partial" and users["bob"]["collection_status"] == "complete" and st["collection_status"] == "partial" and st["cap_reached"] is False')"
chk "the rows are unchanged by the refusal" "$([[ "$(cat "$OUT")" == "$GOLDEN" ]] && echo 1 || echo 0)"
chk "the block passes the contract" "$(contract_ok)"

build_tree
ln -s "$BOB_CHROME/Extensions/ghbmnnjooekpmoecnnnilnnbdlolhkhi" \
    "$U/alice/Library/Application Support/Google/Chrome/Default/Extensions/linklinklinklinklinklinklinklink"
run
chk "a linked extension directory makes alice's Chrome partial" "$([[ "$(pair alice chrome)" == partial ]] && echo 1 || echo 0)"
chk "the block passes the contract" "$(contract_ok)"

build_tree
ln -s "$U/bob/Library/Application Support/Firefox/Profiles/zzzz9999.default" \
    "$U/alice/Library/Application Support/Firefox/Profiles/linked.default"
run
chk "a linked Firefox profile makes alice's Firefox partial" "$([[ "$(pair alice firefox)" == partial ]] && echo 1 || echo 0)"

build_tree
rm -rf "$U/bob/Library/Application Support/Google"
ln -s "$U/alice/Library/Application Support/Google" "$U/bob/Library/Application Support/Google"
run
chk "a linked user-data directory is partial, never not_present" "$([[ "$(pair bob chrome)" == partial ]] && echo 1 || echo 0)"
chk "and nothing of alice's is reported as bob's" "$(is_true 'not any(r["user_account"] == "bob" and r["browser"] == "chrome" for r in rows)')"

build_tree
write_file "$U/bob/Library/Application Support/Firefox/Profiles/zzzz9999.default/extensions.json" '{ not json'
write_file "$U/alice/Library/Application Support/Google/Chrome/Default/Extensions/brokenbrokenbrokenbrokenbrokenbr/1.0/manifest.json" '{ not json'
run
chk "an unparseable extensions.json makes bob's Firefox partial" "$([[ "$(pair bob firefox)" == partial ]] && echo 1 || echo 0)"
chk "an unparseable manifest makes alice's Chrome partial" "$([[ "$(pair alice chrome)" == partial ]] && echo 1 || echo 0)"
chk "the block passes the contract" "$(contract_ok)"

# PAT-2068: an add-on list or entry that cannot be read makes the pair partial,
# as on Windows; the rest of the list and alice's other profile are still read.
GOOD_ADDON='{"id":"good@example.com","type":"extension","version":"1"}'
for bad_json in \
    "{\"addons\":[$GOOD_ADDON,{\"type\":\"extension\",\"version\":\"1\"}]}" \
    "{\"addons\":[$GOOD_ADDON,{\"id\":\"\",\"type\":\"extension\"}]}" \
    "{\"addons\":[$GOOD_ADDON,{\"id\":7,\"type\":\"extension\"}]}" \
    "{\"addons\":[$GOOD_ADDON,{\"id\":null,\"type\":\"extension\"}]}" \
    "{\"addons\":[$GOOD_ADDON,\"not an object\"]}" \
    "{\"addons\":[$GOOD_ADDON,42]}"; do
    build_tree
    write_file "$U/alice/Library/Application Support/Firefox/Profiles/bad.default/extensions.json" "$bad_json"
    run
    chk "Firefox entry $bad_json: alice's Firefox partial, the good entry and her other profile still read" \
        "$([[ "$(pair alice firefox)" == partial ]] && echo 1 || echo 0)$(is_true 'any(r["extension_id"] == "good@example.com" for r in rows) and any(r["extension_id"] == "uBlock0@raymondhill.net" for r in rows)')"
    chk "  and the block passes the contract" "$(contract_ok)"
done
for bad_json in '{"addons":null}' '{"addons":""}' '{"addons":{}}' '{"addons":{"x":1}}' '{"addons":"x"}' '[]' '42'; do
    build_tree
    write_file "$U/alice/Library/Application Support/Firefox/Profiles/bad.default/extensions.json" "$bad_json"
    run
    chk "Firefox list $bad_json: alice's Firefox partial, her other profile still read" \
        "$([[ "$(pair alice firefox)" == partial ]] && echo 1 || echo 0)$(is_true 'any(r["extension_id"] == "uBlock0@raymondhill.net" for r in rows)')"
done

build_tree
write_file "$U/alice/Library/Application Support/Firefox/Profiles/filtered.default/extensions.json" \
    '{"addons":[{"id":"default-theme@mozilla.org","type":"theme","location":"app-builtin"},{"id":"en-GB@dictionaries.addons.mozilla.org","type":"dictionary"},{"id":"langpack-fr@firefox.mozilla.org","type":"locale","location":"app-system-defaults"},{"id":"odd@example.com","type":3},{"id":"untyped@example.com"},{"type":"theme"}]}'
write_file "$U/alice/Library/Application Support/Firefox/Profiles/empty.default/extensions.json" '{}'
run
chk "filtered add-on types and a missing addons list keep alice's Firefox complete" "$([[ "$(pair alice firefox)" == complete ]] && echo 1 || echo 0)"
chk "  and add no rows" "$([[ "$(cat "$OUT")" == "$GOLDEN" ]] && echo 1 || echo 0)"

# PAT-2068: active and userDisabled that are not JSON booleans read as their
# defaults (active true, userDisabled false), as the Windows reader does.
build_tree
write_file "$U/alice/Library/Application Support/Firefox/Profiles/bools.default/extensions.json" \
    '{"addons":[{"id":"zero@example.com","type":"extension","active":0,"userDisabled":1},{"id":"str@example.com","type":"extension","active":"false","userDisabled":"true"},{"id":"real@example.com","type":"extension","active":true,"userDisabled":true}]}'
run
chk "non-boolean active and userDisabled read as the defaults; real booleans are honoured" \
    "$(is_true '{r["extension_id"]: r["enabled"] for r in rows if r["profile"] == "bools.default"} == {"zero@example.com": True, "str@example.com": True, "real@example.com": False}')"
chk "  and alice's Firefox stays complete" "$([[ "$(pair alice firefox)" == complete ]] && echo 1 || echo 0)"

##############################################################################
echo "[status-cap] the row cap, with a fair share per user"
# Real cap, real constant: alice has 1,100 Firefox add-ons. Three users share
# 1,000 rows: alice may use 333, and bob and carol are still read in full.
build_tree
"$REAL_PYTHON3" -c '
import json, sys
addons = [{"id": "a%04d@example.com" % i, "type": "extension", "version": "1"} for i in range(1100)]
json.dump({"addons": addons}, open(sys.argv[1], "w"))' "$U/alice/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json"
run
chk "the constant is still 1,000" "$([[ "$MAX_EXTENSIONS" == 1000 ]] && echo 1 || echo 0)"
chk "alice stops at her share: 333 rows, her 5 Chrome and Edge plus 328 Firefox" \
    "$(is_true 'sum(1 for r in rows if r["user_account"] == "alice") == 333 and sum(1 for r in rows if r["user_account"] == "alice" and r["browser"] == "firefox") == 328')"
chk "bob is not crowded out: both his rows are sent and he is complete" \
    "$(is_true 'sum(1 for r in rows if r["user_account"] == "bob") == 2')"
chk "cap_reached, partial, alice's Firefox partial, bob complete" \
    "$(st_true 'st["cap_reached"] is True and st["collection_status"] == "partial" and users["alice"]["browsers"]["firefox"] == "partial" and users["alice"]["browsers"]["chrome"] == "complete" and users["bob"]["collection_status"] == "complete"')"
chk "Safari still gets the rows left over" "$(is_true 'sum(1 for r in rows if r["browser"] == "safari") == 3')"
chk "the block passes the contract" "$(contract_ok)"

# A small cap to see every edge: 4 rows over three users. alice may use 1 and
# is cut inside Chrome, so her Edge and Firefox were never read; bob may use 1
# and is cut inside Firefox; carol has nothing. Safari fills the last 2 rows
# and is cut too.
build_tree
_BX_MAX_EXTENSIONS=4
run
_BX_MAX_EXTENSIONS=1000
chk "exactly 4 rows: 1 alice, 1 bob, 2 Safari" \
    "$(is_true '[r["user_account"] for r in rows] == ["alice", "bob", None, None]')"
chk "alice: Chrome cut, Edge and Firefox never read, all partial" \
    "$(st_true 'users["alice"]["browsers"] == {"chrome": "partial", "edge": "partial", "firefox": "partial"}')"
chk "bob: Chrome complete (one row fitted), Edge not_present, Firefox cut" \
    "$(st_true 'users["bob"]["browsers"] == {"chrome": "complete", "edge": "not_present", "firefox": "partial"}')"
chk "carol keeps not_present; the block is partial and capped" \
    "$(st_true 'users["carol"]["collection_status"] == "not_present" and st["collection_status"] == "partial" and st["cap_reached"] is True')"
chk "the block passes the contract" "$(contract_ok)"

# 21 rows over three users: alice's share is 7, exactly her 7 rows, so every
# user is read in full; 15 more Safari bundles make Safari overrun the rest.
build_tree
for i in {10..24}; do
    plist "$APPS/Extra$i.app/Contents/PlugIns/E.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.extra.e$i', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension'}}"
done
_BX_MAX_EXTENSIONS=21
run
_BX_MAX_EXTENSIONS=1000
chk "a cap only Safari hits still sets cap_reached and partial, users complete" \
    "$(st_true 'st["cap_reached"] is True and st["collection_status"] == "partial" and all(u["collection_status"] in ("complete", "not_present") for u in st["users"])')"
chk "the block passes the contract" "$(contract_ok)"

##############################################################################
echo "[status-failed] a collector that cannot read is failed"
build_tree
U="$WORK/no-such-users-root"
run
chk "an unlistable users root sends only collection_status failed" "$(st_true 'st == {"collection_status": "failed"}')"
chk "the block passes the contract" "$(contract_ok)"

build_tree
cat > "$WORK/dead-python" <<DEADEOF
#!/bin/zsh
exit 1
DEADEOF
chmod +x "$WORK/dead-python"
PYTHON3="$WORK/dead-python"
run
PYTHON3="$REAL_PYTHON3"
chk "a parser that dies sends only collection_status failed" "$(st_true 'st == {"collection_status": "failed"}')"
chk "and the failure is written to the collect log" "$(grep -q 'could not compose the status block' "$LOG" && echo 1 || echo 0)"

build_tree
mv "$U/bob" "$WORK/bob-real"; ln -s "$WORK/bob-real" "$U/bob"
run
chk "a linked home fails that user: failed, all three browsers failed" \
    "$(st_true 'users["bob"] ["collection_status"] == "failed" and set(users["bob"]["browsers"].values()) == {"failed"}')"
chk "the others are unaffected and the block is partial" \
    "$(st_true 'users["alice"]["collection_status"] == "complete" and st["collection_status"] == "partial"')"
chk "the block passes the contract" "$(contract_ok)"
rm -f "$U/bob"; mv "$WORK/bob-real" "$U/bob"

##############################################################################
# A test-only hook makes the parser's read of the appex list (fd 3) fail:
# PATCHED_FD3=oserror is an OSError (an unreadable or oversized list),
# PATCHED_FD3=crash an unexpected exception outside any one bundle, and
# PATCHED_FD3=late lets the Safari parser print one row, then kills it.
mkdir -p "$WORK/fd3-hook"
cat > "$WORK/fd3-hook/sitecustomize.py" <<'HOOKEOF'
import os, sys
_mode = os.environ.get("PATCHED_FD3")
_read = os.read
def _hooked(fd, n):
    # Only the Safari parser's appex list: the users walk opens files too,
    # and its first one can land on fd 3.
    if fd == 3 and sys.argv[1:2] == ["safari"]:
        if _mode == "oserror":
            raise OSError(5, "hooked")
        if _mode == "crash":
            raise RuntimeError("hooked")
    return _read(fd, n)
if _mode:
    os.read = _hooked
if _mode == "late" and sys.argv[1:2] == ["safari"]:
    import builtins
    _print = builtins.print
    def _print_once(*a, **k):
        _print(*a, **k)
        sys.stdout.flush()
        os._exit(1)
    builtins.print = _print_once
HOOKEOF
fd3_run() { export PYTHONPATH="$WORK/fd3-hook" PATCHED_FD3="$1"; run; unset PYTHONPATH PATCHED_FD3; }

echo "[safari-status] collection_status.safari_extensions, and the block no longer follows Safari (PAT-2067)"
# Before PAT-2067 the platform's device-level block authority covered Safari
# rows, so any incomplete Safari walk made the block partial. The platform now
# keeps Safari out of the block (PAT-2064) and reads Safari's own signal, so a
# Safari failure changes collection_status.safari_extensions and nothing else.
# Every case also checks the Chrome, Edge and Firefox block stays complete.
build_tree
run
chk "a clean Safari walk is complete" "$(sx_is complete)"
chk "  the platform would trust it" "$([[ "$(sx_verdict)" == authoritative ]] && echo 1 || echo 0)"
chk "  and the collect log names it" "$(grep -q 'safari_extensions=complete' "$LOG" && echo 1 || echo 0)"

rm -rf "$WORK/nosafari"; mkdir -p "$WORK/nosafari/Applications/Plain.app/Contents"
SAFARI_ROOTS=("$WORK/nosafari/Applications")
run
chk "no Safari extension anywhere is complete with no Safari rows (an empty list is a claim)" \
    "$([[ "$(sx_is complete)" == 1 && "$(is_true 'not any(r["browser"] == "safari" for r in rows)')" == 1 ]] && echo 1 || echo 0)"

build_tree
plist "$APPS/Aa.app/Contents/PlugIns/ListRoot.appex/Contents/Info.plist" "['not', 'a', 'dict']"
run
chk "an unreadable (malformed) appex is partial" "$(sx_is partial)"
chk "  decoupled: the block stays complete and not capped" "$(block_untouched)"
chk "  the block passes the contract" "$(contract_ok)"
chk "  every readable Safari row is still sent" "$(is_true 'sum(1 for r in rows if r["browser"] == "safari") == 3')"

build_tree
plist "$APPS/Trunc.app/Contents/Info.plist" "{'CFBundleName': 'Trunc'}"
mkdir -p "$APPS/Trunc.app/Contents/PlugIns/T.appex/Contents"
printf 'bplist00\x01\x02' > "$APPS/Trunc.app/Contents/PlugIns/T.appex/Contents/Info.plist"
run
chk "an appex whose own Info.plist is truncated is partial" "$(sx_is partial)"
chk "  decoupled: the block stays complete" "$(block_untouched)"
chk "  and it is written to the collect log" "$(grep -q 'malformed_bundle.*T.appex' "$LOG" && echo 1 || echo 0)"

build_tree
mkdir -p "$APPS/NoPlist.app/Contents/PlugIns/N.appex/Contents"
run
chk "an appex with no Info.plist at all is partial" "$(sx_is partial)"
chk "  decoupled: the block stays complete" "$(block_untouched)"

build_tree
SAFARI_ROOTS=("$APPS" "$WORK/no-such-safari-root")
run
chk "a search root find cannot list is partial" "$(sx_is partial)"
chk "  decoupled: the block stays complete" "$(block_untouched)"
chk "  and find's error reaches the collect log, not /dev/null" "$(grep -q 'find exited 1.*no-such-safari-root' "$LOG" && echo 1 || echo 0)"

# A find that lists everything but exits non-zero with nothing on stderr: the
# exit status alone must decide, whatever the list holds.
build_tree
find() { command find "$@"; return 1; }
run
unfunction find
chk "a hidden find failure (full list, exit 1, silent) is not complete" "$(sx_is partial)"
chk "  every Safari row is still sent" "$(is_true 'sum(1 for r in rows if r["browser"] == "safari") == 3')"
chk "  decoupled: the block stays complete" "$(block_untouched)"

# The refusal log could not be read: grep exits 2, which proved "no refusal"
# before PAT-2067.
build_tree
grep() { if [[ "${@[-1]}" == *safari-appex-err* ]]; then return 2; fi; command grep "$@"; }
run
unfunction grep
chk "a refusal log that cannot be read is not complete" "$(sx_is partial)"
chk "  and says so in the collect log" "$(grep -q 'could not read the refusal log' "$LOG" && echo 1 || echo 0)"

# The default roots: the app roots plus "$_BX_USERS_ROOT"/*/Applications.
# Under NULL_GLOB a home root that cannot be listed expands to no ~/Applications
# at all, which must not read as a complete walk.
build_tree
SAFARI_ROOTS=()
_BX_SAFARI_APP_ROOTS=("$APPS")
run
chk "the default roots find ~/Applications through the home root, and are complete" \
    "$([[ "$(sx_is complete)" == 1 && "$(is_true 'sorted(r["extension_id"] for r in rows if r["browser"] == "safari") == ["com.alice.mine", "com.mas.legacy", "com.vendor.web"]')" == 1 ]] && echo 1 || echo 0)"
chmod 000 "$U"
run
chmod 755 "$U"
chk "a home root that cannot be listed is not complete" "$(sx_is partial)"
chk "  and says so in the collect log" "$(grep -q 'Safari: cannot list' "$LOG" && echo 1 || echo 0)"
_BX_SAFARI_APP_ROOTS=(/Applications /Applications/Utilities)

# find follows no symlink, so whatever sits behind a linked search root, .app,
# .appex or PlugIns directory is never listed, and find still exits 0. Each is
# partial, never a complete walk that reads the hidden extension as removed.
# $WORK/linked holds a real app with a Safari appex, outside every root.
link_fixture() {
    rm -rf "$WORK/linked"
    plist "$WORK/linked/Real.app/Contents/Info.plist" "{'CFBundleName': 'Real'}"
    plist "$WORK/linked/Real.app/Contents/PlugIns/R.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.linked.real', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension'}}"
}
build_tree; link_fixture
mv "$U/alice/Applications" "$WORK/linked/alice-apps"
ln -s "$WORK/linked/alice-apps" "$U/alice/Applications"
SAFARI_ROOTS=()
_BX_SAFARI_APP_ROOTS=("$APPS")
run
chk "a symlinked ~/Applications (default roots) is partial" "$(sx_is partial)"
chk "  and says so in the collect log" "$(grep -q 'refused symlinked search root' "$LOG" && echo 1 || echo 0)"
_BX_SAFARI_APP_ROOTS=(/Applications /Applications/Utilities)
SAFARI_ROOTS=("$APPS" "$U/alice/Applications")
run
chk "a configured search root that is a symlink is partial" "$(sx_is partial)"

build_tree; link_fixture
ln -s "$WORK/linked/Real.app" "$APPS/E.app"
run
chk "a symlinked .app is partial" "$(sx_is partial)"
chk "  and the link is named in the collect log" "$(grep -q 'symlinked path(s) that could hide a bundle.*E.app' "$LOG" && echo 1 || echo 0)"
chk "  decoupled: the block stays complete" "$(block_untouched)"

build_tree; link_fixture
mkdir -p "$APPS/Host.app/Contents"
plist "$APPS/Host.app/Contents/Info.plist" "{'CFBundleName': 'Host'}"
ln -s "$WORK/linked/Real.app/Contents/PlugIns" "$APPS/Host.app/Contents/PlugIns"
run
chk "a symlinked PlugIns directory is partial" "$(sx_is partial)"

build_tree
mkdir -p "$APPS/Fw.app/Contents/Frameworks/X.framework/Versions/A"
ln -s A "$APPS/Fw.app/Contents/Frameworks/X.framework/Versions/Current"
ln -s Versions/Current/X "$APPS/Fw.app/Contents/Frameworks/X.framework/X"
run
chk "framework Versions/Current links in a normal app stay complete" "$(sx_is complete)"

# A matching link is ignored only when its fully resolved target is inside the
# same top-level .app (find walks that real path anyway) or under the
# SIP-protected /System tree (a fixture here: CI has no /System).
build_tree
FW="$APPS/Fw.app/Contents/Frameworks/S.framework"
plist "$FW/Versions/B/Updater.app/Contents/Info.plist" "{'CFBundleName': 'Updater'}"
mkdir -p "$FW/Versions/B/PlugIns"
ln -s B "$FW/Versions/Current"
ln -s Versions/Current/Updater.app "$FW/Updater.app"
ln -s Versions/Current/PlugIns "$FW/PlugIns"
run
chk "framework-internal Updater.app and PlugIns links stay complete" "$(sx_is complete)"

# As on a current Mac: /Applications/Safari.app -> ../System/Cryptexes/App/...,
# and /System/Cryptexes/App -> ../../System/Volumes/Preboot/Cryptexes/App.
build_tree
rm -rf "$WORK/System"
mkdir -p "$WORK/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents" "$WORK/System/Cryptexes"
ln -s ../Volumes/Preboot/Cryptexes/App "$WORK/System/Cryptexes/App"
ln -s ../System/Cryptexes/App/System/Applications/Safari.app "$APPS/Safari.app"
_BX_SAFARI_SYSTEM_ROOT="$WORK/System"
run
chk "the Safari-like Cryptex link (through /System/Cryptexes into Preboot) stays complete" "$(sx_is complete)"
_BX_SAFARI_SYSTEM_ROOT="$WORK/elsewhere-sys"
run
_BX_SAFARI_SYSTEM_ROOT=/System
chk "  the same link is partial when that tree is not the /System root (so the rule can fail)" "$(sx_is partial)"
if [[ -d /System/Library/CoreServices/Finder.app ]]; then
    build_tree
    ln -s /System/Library/CoreServices/Finder.app "$APPS/Finder.app"
    run
    chk "a link into the real /System stays complete" "$(sx_is complete)"
fi

build_tree
mkdir -p "$WORK/elsewhere/X.app/Contents"
ln -s "$WORK/elsewhere/X.app" "$APPS/X.app"
run
chk "an .app link to a directory elsewhere is partial" "$(sx_is partial)"
chk "  and the log names the link and its target" "$(grep -q "X.app -> $WORK/elsewhere/X.app" "$LOG" && echo 1 || echo 0)"

build_tree
ln -s "$WORK/no-such-target.app" "$APPS/Gone.app"
run
chk "a dangling .app link is partial" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/Fw.app/Contents/Frameworks/S.framework/Versions/B"
ln -s Versions/B/Missing.app "$APPS/Fw.app/Contents/Frameworks/S.framework/Updater.app"
run
chk "a dangling link inside its own bundle is partial too" "$(sx_is partial)"
build_tree
ln -s Loop2.app "$APPS/Loop1.app"; ln -s Loop1.app "$APPS/Loop2.app"
run
chk "a looping .app link is partial" "$(sx_is partial)"

build_tree; link_fixture
FW="$APPS/Fw.app/Contents/Frameworks/S.framework"
mkdir -p "$FW"
ln -s "$WORK/linked/Real.app" "$FW/Updater.app"
run
chk "a link inside a framework that points outside the bundle is partial" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/Fw.app/Contents" "$APPS/Other.app/Contents/PlugIns"
ln -s ../../Other.app/Contents/PlugIns "$APPS/Fw.app/Contents/PlugIns"
run
chk "a PlugIns link into a different top-level app is partial" "$(sx_is partial)"

# P1: zsh :A does not follow firmlinks, so /System/Volumes/Data/... is the
# writable data volume under a /System prefix. Only the allowlist is harmless.
build_tree
mkdir -p "$WORK/System/Volumes/Data/stash/Hidden.app/Contents"
ln -s "$WORK/System/Volumes/Data/stash/Hidden.app" "$APPS/Hidden.app"
_BX_SAFARI_SYSTEM_ROOT="$WORK/System"
run
chk "a link into <System>/Volumes/Data is partial" "$(sx_is partial)"
build_tree
mkdir -p "$WORK/System/Volumes/Data/Users/me/Stash"
mv "$U/alice/Applications" "$WORK/alice-apps-moved"
ln -s "$WORK/System/Volumes/Data/Users/me/Stash" "$U/alice/Applications"
SAFARI_ROOTS=(); _BX_SAFARI_APP_ROOTS=("$APPS")
run
chk "a ~/Applications root linked into <System>/Volumes/Data is partial (the reproduced case)" "$(sx_is partial)"
_BX_SAFARI_APP_ROOTS=(/Applications /Applications/Utilities)
build_tree
mkdir -p "$WORK/System/Library/Caches/stash.app/Contents"
ln -s "$WORK/System/Library/Caches/stash.app" "$APPS/Cached.app"
run
chk "a link into a firmlinked <System>/Library subtree (Caches) is partial" "$(sx_is partial)"
_BX_SAFARI_SYSTEM_ROOT=/System

# P2a: a PlugIns link must land on a */Contents/PlugIns path find lists from.
build_tree
plist "$APPS/A.app/Contents/Info.plist" "{'CFBundleName': 'A'}"
plist "$APPS/A.app/Contents/Resources/stash/X.appex/Contents/Info.plist" "{'CFBundleIdentifier': 'com.stash.x', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension'}}"
ln -s Resources/stash "$APPS/A.app/Contents/PlugIns"
run
chk "Contents/PlugIns -> Resources/stash inside the same bundle is partial (the reproduced case)" "$(sx_is partial)"
chk "  and find listed no appex from it" "$(is_true 'not any(r["extension_id"] == "com.stash.x" for r in rows)')"
build_tree
mkdir -p "$APPS/D.app/Contents/Deep/a/b/c/d/e/f/g/Contents/PlugIns"
ln -s Deep/a/b/c/d/e/f/g/Contents/PlugIns "$APPS/D.app/Contents/PlugIns"
run
chk "a PlugIns link to a deep in-bundle Contents/PlugIns stays complete (find has no depth limit)" "$(sx_is complete)"
build_tree
mkdir -p "$APPS/Ok.app/Contents/Real/Contents/PlugIns"
ln -s Real/Contents/PlugIns "$APPS/Ok.app/Contents/PlugIns"
run
chk "a PlugIns link to an in-bundle Contents/PlugIns stays complete" "$(sx_is complete)"

# PAT-2079: the walk misses nothing APFS would load, and says so when it must.
# safari_ext <bundle.appex> <id>: a Safari extension's Info.plist.
safari_ext() { plist "$1/Contents/Info.plist" "{'CFBundleIdentifier': '$2', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension'}}"; }
sx_row() { is_true "any(r[\"extension_id\"] == \"$1\" for r in rows)"; }
build_tree
plist "$APPS/Low.app/Contents/Info.plist" "{'CFBundleName': 'Low'}"
safari_ext "$APPS/Low.app/Contents/plugins/L.appex" com.low.plugins
run
chk "an appex under a lowercase Contents/plugins is found and sent (APFS loads it)" "$(sx_row com.low.plugins)"
chk "  and the walk is complete" "$(sx_is complete)"

build_tree
mkdir -p "$APPS/Mc.app/Contents/Real/Contents/PLUGINS"
safari_ext "$APPS/Mc.app/Contents/Real/Contents/PLUGINS/M.appex" com.mixed.case
ln -s Real/Contents/PLUGINS "$APPS/Mc.app/Contents/PLUGINS"
run
chk "a PLUGINS link to an in-bundle Contents/PLUGINS stays complete, as PlugIns does" "$(sx_is complete)"
chk "  and the appex behind it is sent from its real path" "$(sx_row com.mixed.case)"
build_tree
mkdir -p "$APPS/Ms.app/Contents/Resources/stash"
ln -s Resources/stash "$APPS/Ms.app/Contents/PLUGINS"
run
chk "  a PLUGINS link to Resources/stash is partial, as PlugIns is" "$(sx_is partial)"

build_tree
safari_ext "$APPS/a/b/c/d/e/f/Deep.app/Contents/PlugIns/D.appex" com.deep.ten
safari_ext "$APPS/a/b/c/d/e/f/g/h/Edge.app/Contents/PlugIns/E.appex" com.deep.twelve
run
chk "an appex at depth 10 is found and sent" "$(sx_row com.deep.ten)"
chk "  and one at depth 12" "$(sx_row com.deep.twelve)"
chk "  and the walk is complete" "$(sx_is complete)"

# The reviewer's case: an app at depth 11 puts its appex at depth 14.
build_tree
safari_ext "$APPS/a/b/c/d/e/f/g/h/i/j/Far.app/Contents/PlugIns/F.appex" com.deep.fourteen
run
chk "an appex at depth 14 is found and sent" "$(sx_row com.deep.fourteen)"
chk "  and the walk is complete" "$(sx_is complete)"
build_tree
mkdir -p "$APPS/a/b/c/d/e/f/g/h/i/j/k/l" "$WORK/games/G.app/Contents"
ln -s "$WORK/games" "$APPS/a/b/c/d/e/f/g/h/i/j/k/l/Linked"
run
chk "a linked folder at depth 13 pointing outside is partial" "$(sx_is partial)"
chk "  and the link is named in the collect log" "$(grep -q 'symlinked path(s) that could hide a bundle.*Linked' "$LOG" && echo 1 || echo 0)"

# As Chrome ships: helper apps deep inside a framework, with no appex, and a
# deep node_modules tree inside an app.
build_tree
H="$APPS/Chrome.app/Contents/Frameworks/C Framework.framework/Versions/153.0/Helpers"
for n in 'Helper' 'Helper (GPU)' 'Helper (Renderer)'; do
    plist "$H/$n.app/Contents/Info.plist" "{'CFBundleName': 'H'}"
    mkdir -p "$H/$n.app/Contents/MacOS" "$H/$n.app/Contents/Resources/x/y/z"
done
mkdir -p "$APPS/Node.app/Contents/Resources/app/node_modules/@a/b/lib/node_modules/c/d/e/f/g"
mkdir -p "$APPS/Node.app/Contents/Resources/app/node_modules/@a/b/lib/node_modules/Deep Tool.app/Contents/MacOS"
run
chk "deep helper apps and deep folders with no appex stay complete" "$(sx_is complete)"

rm -rf "$WORK/lc"; mkdir -p "$WORK/lc/Plain.app/Contents"
print -r -- x > "$WORK/lc-file"
for i in 1 2 3 4 5; do ln -s "$WORK/lc-file" "$WORK/lc/link$i"; done
SAFARI_ROOTS=("$WORK/lc")
_BX_SAFARI_MAX_LINKS=5
run
chk "5 harmless links under a cap of 5 stay complete" "$(sx_is complete)"
ln -s "$WORK/lc-file" "$WORK/lc/link6"
run
chk "6 links over a cap of 5 are partial" "$(sx_is partial)"
chk "  and the log says the links were not all checked" "$(grep -q 'stopped checking them' "$LOG" && echo 1 || echo 0)"
_BX_SAFARI_MAX_LINKS=100000
SAFARI_ROOTS=("$APPS" "$U/alice/Applications")

# P2b: linked folders and bundle Contents.
build_tree
mkdir -p "$WORK/games/G.app/Contents"
ln -s "$WORK/games" "$APPS/Games"
run
chk "a linked folder of apps directly in a search root is partial" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/Sub" "$WORK/games/G.app/Contents"
ln -s "$WORK/games" "$APPS/Sub/Games"
run
chk "a linked folder deeper in a search root is partial" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/C.app" "$WORK/elsewhere-c/Contents/PlugIns"
ln -s "$WORK/elsewhere-c/Contents" "$APPS/C.app/Contents"
run
chk "a top-level .app whose Contents is a link is partial" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/C2.app/Other/PlugIns"
ln -s Other "$APPS/C2.app/Contents"
run
chk "  even when that Contents stays inside the bundle" "$(sx_is partial)"
build_tree
mkdir -p "$APPS/F.app/Contents/Frameworks" "$WORK/games/G.app/Contents"
ln -s "$WORK/games" "$APPS/F.app/Contents/Frameworks/Foo"
run
chk "a folder link inside a bundle that points outside it is partial" "$(sx_is partial)"
build_tree
print -r -- "x" > "$WORK/a-file"
ln -s "$WORK/a-file" "$APPS/ReadMe"
ln -s "$WORK/nothing-here" "$APPS/Dangling"
run
chk "a link to a file, or a dangling link with another name, hides nothing: complete" "$(sx_is complete)"

# P3: a newline in a link target cannot forge a collect-log line.
build_tree
mkdir -p "$WORK/nl"$'\n'"FORGED"
ln -s "$WORK/nl"$'\n'"FORGED" "$WORK/nl-root"
SAFARI_ROOTS=("$APPS" "$WORK/nl-root")
run
chk "a root link whose target has a newline is partial and forges no log line" \
    "$([[ "$(sx_is partial)" == 1 ]] && ! grep -q '^FORGED' "$LOG" && echo 1 || echo 0)"

build_tree
fd3_run oserror
chk "an appex list that cannot be read is unavailable" "$(sx_is unavailable)"
chk "  no Safari rows were invented" "$(is_true 'not any(r["browser"] == "safari" for r in rows)')"
chk "  decoupled: the block stays complete" "$(block_untouched)"
build_tree
fd3_run crash
chk "a Safari walk that crashes before any row is unavailable" "$(sx_is unavailable)"
chk "  decoupled: the block stays complete" "$(block_untouched)"
chk "  and it is written to the collect log" "$(grep -q 'safari_walk_failed' "$LOG" && echo 1 || echo 0)"
build_tree
fd3_run late
chk "a Safari walk that dies after sending a row is partial, not unavailable" \
    "$([[ "$(sx_is partial)" == 1 && "$(is_true 'sum(1 for r in rows if r["browser"] == "safari") == 1')" == 1 ]] && echo 1 || echo 0)"
build_tree
fd3_run none
chk "the hook itself changes nothing when off (so the ones above can fail)" "$(sx_is complete)"

build_tree
PYTHON3="$WORK/dead-python"
run
PYTHON3="$REAL_PYTHON3"
chk "a parser that dies outright is unavailable" "$(sx_is unavailable)"

# The cap. Safari is walked last under the shared 1,000-row cap.
build_tree
_BX_MAX_EXTENSIONS=4
run
_BX_MAX_EXTENSIONS=1000
chk "a cap that cuts Safari is partial, never complete" "$(sx_is partial)"
# carol, read last, has 1,100 add-ons and the budget alice and bob left her,
# so the users walk fills all 1,000 rows and Safari is never walked.
build_tree
mkdir -p "$U/carol/Library/Application Support/Firefox/Profiles/c.default"
"$REAL_PYTHON3" -c '
import json, sys
addons = [{"id": "c%04d@example.com" % i, "type": "extension", "version": "1"} for i in range(1100)]
json.dump({"addons": addons}, open(sys.argv[1], "w"))' "$U/carol/Library/Application Support/Firefox/Profiles/c.default/extensions.json"
run
chk "a cap that leaves Safari unwalked is partial" \
    "$([[ "$(sx_is partial)" == 1 && "$(is_true 'not any(r["browser"] == "safari" for r in rows)')" == 1 ]] && echo 1 || echo 0)"
build_tree
"$REAL_PYTHON3" -c '
import json, sys
addons = [{"id": "a%04d@example.com" % i, "type": "extension", "version": "1"} for i in range(1100)]
json.dump({"addons": addons}, open(sys.argv[1], "w"))' "$U/alice/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json"
run
chk "a user's fair-share cap is partial even when every Safari row fitted" \
    "$([[ "$(sx_is partial)" == 1 && "$(is_true 'sum(1 for r in rows if r["browser"] == "safari") == 3')" == 1 && "$(st_true 'st["cap_reached"] is True')" == 1 ]] && echo 1 || echo 0)"

echo "[safari-contract] the value on the wire and the platform's trust rule"
# sx_verdict ports resolveSafariSignal (patched.im safari_authority.go): a
# complete is trusted only on schema v3, beside a browser_extensions array and
# a block without cap_reached, and under 1,000 rows. It must go red on each.
build_tree
run
chk "the value passes the vendored collection_status schema" "$([[ "$(sx_verdict)" == authoritative ]] && echo 1 || echo 0)"
chk "  a capped block would be withheld" "$([[ "$(sx_verdict complete '{"collection_status":"partial","cap_reached":true,"users":[]}')" == "withheld: cap_reached" ]] && echo 1 || echo 0)"
chk "  no block would be withheld" "$([[ "$(sx_verdict complete none)" == "withheld: complete_without_browser_extensions_status" ]] && echo 1 || echo 0)"
chk "  a full array would be withheld" "$([[ "$(sx_verdict complete '' 1000)" == "withheld: row_cap_full" ]] && echo 1 || echo 0)"
chk "  an unknown value fails the schema" "$([[ "$(sx_verdict Complete)" == schema:* ]] && echo 1 || echo 0)"
chk "  partial and unavailable grant nothing" "$([[ "$(sx_verdict partial)$(sx_verdict unavailable '' 0)" == nonenone ]] && echo 1 || echo 0)"

echo "[safari-payload] the payload member"
chk "the payload heredoc sends safari_extensions in the top-level collection_status" \
    "$(grep -qF '"collection_status": {"certificates": $(json_escape "$(certs_collection_status)"), "apps": $(json_escape "$(apps_collection_status)"), "apps_users": $(apps_users_collection_status), "safari_extensions": $(json_escape "$(safari_extensions_collection_status)")},' "$SCRIPT_DIR/../patched-collect.sh" && echo 1 || echo 0)"
chk "patched-collect.sh starts it as unavailable, before any collector runs" \
    "$(awk '/^SAFARI_EXTENSIONS_COLLECTION_STATUS="unavailable"$/ {s=NR} /^collect_browser_extensions$/ {c=NR} END {print (s && c && s < c) ? 1 : 0}' "$SCRIPT_DIR/../patched-collect.sh")"
(
    unset SAFARI_EXTENSIONS_COLLECTION_STATUS
    [[ "$(safari_extensions_collection_status)" == unavailable ]] || exit 1
    SAFARI_EXTENSIONS_COLLECTION_STATUS=bogus
    [[ "$(safari_extensions_collection_status)" == unavailable ]]
) && NEVER_RAN=1 || NEVER_RAN=0
chk "a collector that never ran, or an unknown value, sends unavailable" "$NEVER_RAN"

##############################################################################
echo "[status-payload] the payload member"
chk "the payload heredoc carries browser_extensions_status beside browser_extensions" \
    "$(grep -qxF '  "browser_extensions_status": $(browser_extensions_status_payload),' "$SCRIPT_DIR/../patched-collect.sh" && echo 1 || echo 0)"
chk "patched-collect.sh starts the block as failed" \
    "$(grep -qF "printf '{\"collection_status\":\"failed\"}' > \"\$BROWSER_EXTENSIONS_STATUS_FILE\"" "$SCRIPT_DIR/../patched-collect.sh" && echo 1 || echo 0)"
(
    unset BROWSER_EXTENSIONS_STATUS_FILE
    [[ "$(browser_extensions_status_payload)" == '{"collection_status":"failed"}' ]]
) && NEVER_RAN=1 || NEVER_RAN=0
chk "a collector that never ran sends failed" "$NEVER_RAN"
build_tree
run
chk "after a run the member is the composed block" \
    "$([[ "$(browser_extensions_status_payload)" == "$(cat "$BROWSER_EXTENSIONS_STATUS_FILE")" && "$(st_py 'st["collection_status"]')" == complete ]] && echo 1 || echo 0)"

##############################################################################
echo "[firefox-origins] host permissions come from userPermissions.origins, with legacy hosts (PAT-2073)"
# Current Firefox writes granted host permissions under userPermissions.origins;
# "hosts" is only on old profiles. Both are read, unioned in first-seen order.
# optionalPermissions.origins are not granted and are left out, as Chromium's
# optional_host_permissions are. Mirrors the Windows
# ScanUserProfile_Firefox_HostPermissionsFromOriginsAndLegacyHosts and
# ScanUserProfile_Firefox_WrongTypedOrigins_KeepTheRow_StayComplete.
build_tree
write_file "$U/alice/Library/Application Support/Firefox/Profiles/cur.default-release/extensions.json" '{"schemaVersion":36,"addons":[
{"id":"current@example.com","type":"extension","version":"1.60.0","active":true,"userDisabled":false,"defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"permissions":["dns","storage","tabs"],"origins":["<all_urls>","http://*/*","https://*/*"],"data_collection":[]},"optionalPermissions":{"permissions":[],"origins":["file:///*"]},"updateURL":null},
{"id":"legacy@example.com","type":"extension","version":"1.0","userPermissions":{"permissions":["tabs"],"hosts":["*://*/*"]}},
{"id":"both@example.com","type":"extension","version":"1.0","userPermissions":{"origins":["https://a.example/*","<all_urls>"],"hosts":["<all_urls>","https://b.example/*","https://b.example/*"]}},
{"id":"optional-only@example.com","type":"extension","version":"1.0","userPermissions":{"permissions":[],"origins":[]},"optionalPermissions":{"permissions":["tabs"],"origins":["<all_urls>"]}}]}'
write_file "$U/alice/Library/Application Support/Firefox/Profiles/typedorigins.default/extensions.json" '{"addons":[
{"id":"str@example.com","type":"extension","userPermissions":{"origins":"<all_urls>","hosts":["https://h.example/*"]}},
{"id":"mixed@example.com","type":"extension","userPermissions":{"origins":[null,7,"<all_urls>",{"o":1},["x"]],"hosts":{"h":1}}},
{"id":"arr@example.com","type":"extension","userPermissions":["<all_urls>"]}]}'
run
hp() { is_true "[r[\"host_permissions\"] for r in rows if r[\"extension_id\"] == \"$1\"] == [$2]"; }
chk "current Firefox: origins are the host permissions" "$(hp current@example.com '["<all_urls>", "http://*/*", "https://*/*"]')"
chk "current Firefox: userPermissions.permissions still read" \
    "$(is_true '[r["permissions"] for r in rows if r["extension_id"] == "current@example.com"] == [["dns", "storage", "tabs"]]')"
chk "legacy Firefox: hosts still read" "$(hp legacy@example.com '["*://*/*"]')"
chk "origins and hosts together: union, first-seen order, no repeats" "$(hp both@example.com '["https://a.example/*", "<all_urls>", "https://b.example/*"]')"
chk "optionalPermissions.origins are not host permissions" "$(hp optional-only@example.com '[]')"
chk "a string origins reads as empty, hosts still read" "$(hp str@example.com '["https://h.example/*"]')"
chk "non-string origins items and a non-list hosts are dropped" "$(hp mixed@example.com '["<all_urls>"]')"
chk "a non-object userPermissions keeps the row with no host permissions" "$(hp arr@example.com '[]')"
chk "wrong-typed origins keep alice's Firefox complete" "$([[ "$(pair alice firefox)" == complete ]] && echo 1 || echo 0)"

##############################################################################
echo "[tcc] a folder macOS privacy protection denies is tcc_denied, partial, and an agent_health entry (PAT-2096)"
# Running as root without Full Disk Access, TCC lets the walk lstat Chrome's,
# Edge's or Firefox's data folder but refuses open() with EPERM. A test-only
# sitecustomize.py does exactly that: os.open of a named directory, reached
# relative to its parent as the walk reaches everything, raises the errno in
# PATCHED_DENY_ERRNO. lstat is left alone, as TCC leaves it.
mkdir -p "$WORK/deny-hook"
cat > "$WORK/deny-hook/sitecustomize.py" <<'HOOKEOF'
import os

_targets = [t for t in os.environ.get("PATCHED_DENY_DIRS", "").split("\n") if t]
_errno = int(os.environ.get("PATCHED_DENY_ERRNO", "1"))
_open = os.open
_lstat = os.lstat
_hits = os.environ.get("PATCHED_DENY_HITS")


def _denied(path, dir_fd):
    if not isinstance(path, str) or dir_fd is None:
        return False
    for t in _targets:
        if path != os.path.basename(t):
            continue
        try:
            if os.fstat(dir_fd).st_ino == _lstat(os.path.dirname(t)).st_ino:
                return True
        except OSError:
            pass
    return False


def _hooked_open(path, flags, mode=0o777, *, dir_fd=None):
    if _denied(path, dir_fd):
        if _hits:
            with open(_hits, "a") as f:
                f.write(path + "\n")
        raise OSError(_errno, os.strerror(_errno))
    return _open(path, flags, mode, dir_fd=dir_fd)


if _targets:
    os.open = _hooked_open
HOOKEOF
# deny_run <errno> <dir ...>: run with os.open of each dir failing with errno.
deny_run() {
    local _e="$1"; shift
    : > "$WORK/deny-hits"
    export PYTHONPATH="$WORK/deny-hook" PATCHED_DENY_ERRNO="$_e" PATCHED_DENY_DIRS="${(F)@}" PATCHED_DENY_HITS="$WORK/deny-hits"
    run
    unset PYTHONPATH PATCHED_DENY_ERRNO PATCHED_DENY_DIRS PATCHED_DENY_HITS
}
hook_fired() { [[ -s "$WORK/deny-hits" ]] && echo 1 || echo 0; }
TCC_WARN='macOS privacy protection denied access to'
TCC_WHY='(Full Disk Access is not granted to the Patched collector)'
EPERM=$("$REAL_PYTHON3" -c 'import errno; print(errno.EPERM)')
EACCES=$("$REAL_PYTHON3" -c 'import errno; print(errno.EACCES)')
EIO=$("$REAL_PYTHON3" -c 'import errno; print(errno.EIO)')
ALICE_CHROME="$U/alice/Library/Application Support/Google/Chrome"
BOB_FIREFOX="$U/bob/Library/Application Support/Firefox"
AH_STORE="$WORK/agent-health/.agent-health.json"
export PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
# ah_py <python expression over `active` and `ever`> against the store.
ah_py() {
    "$REAL_PYTHON3" -c 'import json,sys; d=json.load(open(sys.argv[1])); active=d["active"]; ever=d["ever_succeeded"]; print(eval(sys.argv[2]))' "$AH_STORE" "$1" 2>/dev/null
}
ah_true() { [[ "$(ah_py "$1")" == "True" ]] && echo 1 || echo 0; }
TCC_KEY='"tcc_denied|browser_extensions"'

build_tree
ALICE_CHROME="$U/alice/Library/Application Support/Google/Chrome"
BOB_FIREFOX="$U/bob/Library/Application Support/Firefox"
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$ALICE_CHROME" "$BOB_FIREFOX"
chk "EPERM: the hook really denied the opens (so the test can fail)" "$(hook_fired)"
chk "without agent_health.sh loaded the collector writes no store" "$([[ ! -e "$AH_STORE" ]] && echo 1 || echo 0)"

source "$SCRIPT_DIR/agent_health.sh"
# The health entry is the LaunchDaemon run's alone (parent PID 1); the tests
# run under another parent, so they stand in for launchd until the manual
# trigger case below.
_BX_HEALTH_PPID=1

echo "  -- EPERM on alice's Chrome folder and bob's Firefox folder"
build_tree
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$ALICE_CHROME" "$BOB_FIREFOX"
chk "the hook denied the opens" "$(hook_fired)"
chk "the collect log says macOS privacy protection denied 2 browser data folders, and why" \
    "$(grep -qF "WARN: browser_extensions: $TCC_WARN 2 browser data folder(s) $TCC_WHY" "$LOG" && echo 1 || echo 0)"
chk "  naming alice's Chrome folder once, not once per path under it" \
    "$([[ "$(grep -F "$TCC_WARN" "$LOG" | grep -oF "$ALICE_CHROME;" | wc -l | tr -d ' ')" == 1 ]] && echo 1 || echo 0)"
chk "  and bob's Firefox profiles folder" "$(grep -F "$TCC_WARN" "$LOG" | grep -qF "$BOB_FIREFOX/Profiles;" && echo 1 || echo 0)"
chk "a denial is not called a symlink or unsafe name, nor unreadable" \
    "$(! grep -q 'symlink or unsafe name' "$LOG" && ! grep -q 'could not be read or parsed' "$LOG" && echo 1 || echo 0)"
chk "alice's Chrome and bob's Firefox are partial, never not_present" \
    "$([[ "$(pair alice chrome)$(pair bob firefox)" == partialpartial ]] && echo 1 || echo 0)"
chk "the rest stays complete" \
    "$([[ "$(pair alice edge)$(pair alice firefox)$(pair bob chrome)" == completecompletecomplete ]] && echo 1 || echo 0)"
chk "the block is partial and passes the contract" "$(st_true 'st["collection_status"] == "partial"')$(contract_ok)"
chk "no row from a denied folder, every other row still sent" \
    "$(is_true 'not any(r["user_account"] == "alice" and r["browser"] == "chrome" for r in rows) and not any(r["user_account"] == "bob" and r["browser"] == "firefox" for r in rows) and len(rows) == 7')"
chk "the agent_health store holds tcc_denied / browser_extensions / full_disk_access_missing" \
    "$(ah_true "active[$TCC_KEY][\"kind\"] == \"tcc_denied\" and active[$TCC_KEY][\"subject\"] == \"browser_extensions\" and active[$TCC_KEY][\"reason\"] == \"full_disk_access_missing\" and active[$TCC_KEY][\"count\"] == 1")"
DEGRADED=$(patched_agent_health_emit_degraded_json)
chk "  and the uploader's degraded array carries it, never succeeded" \
    "$("$REAL_PYTHON3" -c 'import json,sys; d=json.loads(sys.argv[1]); print(1 if [(e["kind"], e["subject"], e["reason"], e["ever_succeeded"]) for e in d] == [("tcc_denied", "browser_extensions", "full_disk_access_missing", False)] else 0)' "$DEGRADED")"
deny_run "$EPERM" "$ALICE_CHROME" "$BOB_FIREFOX"
chk "a second denied run counts up, one entry" "$(ah_true "active[$TCC_KEY][\"count\"] == 2 and len(active) == 1")"

echo "  -- EPERM on one profile's Extensions, and on Firefox/Profiles itself (the list_dir path)"
build_tree
deny_run "$EPERM" "$ALICE_CHROME/Default/Extensions" "$BOB_FIREFOX/Profiles"
chk "the hook denied the opens" "$(hook_fired)"
chk "both are tcc_denied, one each" \
    "$(grep -qF "$TCC_WARN 2 browser data folder(s)" "$LOG" && grep -F "$TCC_WARN" "$LOG" | grep -qF "$ALICE_CHROME/Default/Extensions;" && grep -F "$TCC_WARN" "$LOG" | grep -qF "$BOB_FIREFOX/Profiles;" && echo 1 || echo 0)"
chk "alice's other Chrome profile is still read" "$(is_true 'any(r["profile"] == "Profile 2" for r in rows)')"
chk "alice's Chrome and bob's Firefox are partial" "$([[ "$(pair alice chrome)$(pair bob firefox)" == partialpartial ]] && echo 1 || echo 0)"

echo "  -- EACCES and EIO are unreadable, not a privacy denial"
for e in "$EACCES" "$EIO"; do
    build_tree
    deny_run "$e" "$ALICE_CHROME" "$BOB_FIREFOX"
    chk "errno $e: the hook denied the opens" "$(hook_fired)"
    chk "errno $e: refused as unreadable, with no privacy wording" \
        "$(grep -qF 'WARN: browser_extensions: refused' "$LOG" && grep 'could not be read or parsed' "$LOG" | grep -qF "unreadable $ALICE_CHROME" && ! grep -qF "$TCC_WARN" "$LOG" && ! grep -q tcc_denied "$LOG" && echo 1 || echo 0)"
    chk "errno $e: still partial" "$([[ "$(pair alice chrome)$(pair bob firefox)" == partialpartial ]] && echo 1 || echo 0)"
done
chk "a run with no privacy denial clears the entry, and the ledger says it once worked" \
    "$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"

echo "  -- a clean walk"
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$ALICE_CHROME"
chk "set up: a denied run recorded the entry" "$(ah_true "$TCC_KEY in active")"
build_tree
run
chk "a clean walk is complete with no refusal logged" \
    "$(st_true 'st["collection_status"] == "complete"')$([[ "$(cat "$OUT")" == "$GOLDEN" ]] && ! grep -q 'WARN: browser_extensions' "$LOG" && echo 1 || echo 0)"
chk "and clears the tcc_denied entry" "$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"
chk "the degraded array is then empty" "$([[ "$(patched_agent_health_emit_degraded_json)" == "[]" ]] && echo 1 || echo 0)"

echo "  -- a users walk that fails outright is no opinion"
deny_run "$EPERM" "$ALICE_CHROME"
U_SAVED="$U"; U="$WORK/no-such-users-root"
run
U="$U_SAVED"
chk "a failed block neither records nor clears the entry" \
    "$(st_true 'st["collection_status"] == "failed"')$(ah_true "active[$TCC_KEY][\"count\"] == 1")"

echo "  -- EPERM on a file (the open_regular path) is tcc_denied too, and never clears the entry"
rm -rf "$WORK/agent-health"
build_tree
deny_run "$EPERM" "$BOB_FIREFOX/Profiles/zzzz9999.default/extensions.json" "$ALICE_CHROME/Default/Secure Preferences"
chk "the hook denied the file opens" "$(hook_fired)$(grep -qxF 'extensions.json' "$WORK/deny-hits" && grep -qxF 'Secure Preferences' "$WORK/deny-hits" && echo 1 || echo 0)"
chk "both files are tcc_denied, with no unreadable wording" \
    "$(grep -qF "$TCC_WARN 2 browser data folder(s)" "$LOG" && grep -F "$TCC_WARN" "$LOG" | grep -qF "zzzz9999.default/extensions.json;" && ! grep -q 'could not be read or parsed' "$LOG" && echo 1 || echo 0)"
chk "bob's Firefox and alice's Chrome are partial" "$([[ "$(pair bob firefox)$(pair alice chrome)" == partialpartial ]] && echo 1 || echo 0)"
chk "a run with only file denials records the entry" "$(ah_true "active[$TCC_KEY][\"reason\"] == \"full_disk_access_missing\"")"
deny_run "$EPERM" "$BOB_FIREFOX/Profiles/zzzz9999.default/extensions.json"
chk "  and a second one counts it up rather than clearing it" "$(ah_true "active[$TCC_KEY][\"count\"] == 2")"
deny_run "$EACCES" "$BOB_FIREFOX/Profiles/zzzz9999.default/extensions.json"
chk "EACCES on a file stays unreadable" \
    "$(grep 'could not be read or parsed' "$LOG" | grep -qF "unreadable $BOB_FIREFOX/Profiles/zzzz9999.default/extensions.json" && ! grep -qF "$TCC_WARN" "$LOG" && echo 1 || echo 0)"

echo "  -- a Safari denial never feeds the Full Disk Access entry or its WARN"
rm -rf "$WORK/agent-health"
build_tree
deny_run "$EPERM" "$U/alice/Applications/Mine.app/Contents/PlugIns/MineExt.appex/Contents"
chk "the hook denied the Safari bundle" "$(hook_fired)"
chk "no privacy WARN; the Safari refusal is logged with the unreadable paths" \
    "$(! grep -qF "$TCC_WARN" "$LOG" && grep 'could not be read or parsed' "$LOG" | grep -qF 'tcc_denied' && echo 1 || echo 0)"
chk "  and the Chrome, Edge and Firefox walk, clean, clears rather than records" "$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"

echo "  -- a Safari Resources folder that cannot be listed is logged, never skipped in silence (PAT-2100)"
# find_manifest used to return "no manifest" for a folder it could not list,
# so the bundle's row went out with no permissions and Safari read complete.
VENDOR_RES="$APPS/Vendor/Host.app/Contents/PlugIns/Web.appex/Contents/Resources"
vendor_perms() { is_true '[(r["permissions"], r["host_permissions"]) for r in rows if r["extension_id"] == "com.vendor.web"] == [([], [])]'; }
for e in "$EACCES" "$EPERM"; do
    rm -rf "$WORK/agent-health"
    build_tree
    deny_run "$e" "$VENDOR_RES/ext"
    code=unreadable; (( e == EPERM )) && code=tcc_denied
    chk "errno $e: the hook denied the nested Resources folder" "$(hook_fired)"
    chk "errno $e: the refusal is logged as $code with its path" \
        "$(grep 'could not be read or parsed' "$LOG" | grep -qF "$code $VENDOR_RES/ext" && echo 1 || echo 0)"
    chk "errno $e: the row goes out without permissions, and Safari is partial, not complete" \
        "$(vendor_perms)$([[ "$SAFARI_EXTENSIONS_COLLECTION_STATUS" == partial ]] && echo 1 || echo 0)"
    chk "errno $e: no Full Disk Access WARN, and the Chrome/Edge/Firefox walk clears rather than records" \
        "$(! grep -qF "$TCC_WARN" "$LOG" && echo 1 || echo 0)$(ah_true "$TCC_KEY not in active")"
done
build_tree
rm -rf "$VENDOR_RES"
run
chk "a web extension with no Resources folder at all is no refusal: Safari stays complete" \
    "$(vendor_perms)$([[ "$SAFARI_EXTENSIONS_COLLECTION_STATUS" == complete ]] && ! grep -q 'WARN: browser_extensions' "$LOG" && echo 1 || echo 0)"

echo "  -- only the LaunchDaemon run (parent PID 1) writes or clears the entry"
rm -rf "$WORK/agent-health"
_BX_HEALTH_PPID=4242
build_tree
deny_run "$EPERM" "$ALICE_CHROME"
chk "a manual run still logs the WARN" "$(grep -qF "$TCC_WARN 1 browser data folder(s)" "$LOG" && echo 1 || echo 0)"
chk "  but records nothing, and says why" "$([[ ! -e "$AH_STORE" ]] && grep -q 'not the LaunchDaemon run (parent 4242)' "$LOG" && echo 1 || echo 0)"
_BX_HEALTH_PPID=1
deny_run "$EPERM" "$ALICE_CHROME"
chk "set up: the daemon run records it" "$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_BX_HEALTH_PPID=4242
run
chk "a clean manual run leaves the daemon's entry in place" "$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
unset _BX_HEALTH_PPID
run
chk "with no override the real parent decides (these tests are not under launchd)" \
    "$([[ "$PPID" != 1 ]] && echo 1 || echo 0)$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_BX_HEALTH_PPID=1

echo "  -- a walk that never reached every folder does not clear the entry"
deny_run "$EPERM" "$ALICE_CHROME"
chk "set up: recorded" "$(ah_true "active[$TCC_KEY][\"count\"] == 2")"
build_tree
_BX_MAX_EXTENSIONS=4
run
_BX_MAX_EXTENSIONS=1000
chk "a walk cut by the row budget leaves it" \
    "$(st_true 'st["cap_reached"] is True')$(ah_true "active[$TCC_KEY][\"count\"] == 2")"
build_tree
ln -s "$U/bob" "$U/dave"
run
chk "a walk with a home that could not be entered leaves it" \
    "$(st_true 'users["dave"]["collection_status"] == "failed"')$(ah_true "active[$TCC_KEY][\"count\"] == 2")"
build_tree
run
chk "a full clean walk clears it" "$(ah_true "$TCC_KEY not in active")"
unset _BX_HEALTH_PPID
unset PATCHED_AGENT_HEALTH_STORE

echo "[tcc-collector] patched-collect.sh loads agent_health.sh, so the entry can be written at all"
# collector_loads_health <collect-script>: the script sources agent_health.sh
# from LIB_DIR before collect_browser_extensions runs, and a built bundle of
# it defines patched_agent_health_record_failure.
collector_loads_health() {
    local _c="$1" _d
    _d=$(mktemp -d "$WORK/bundle.XXXXXX")
    mkdir -p "$_d/lib"
    cp "$SCRIPT_DIR"/*.sh "$_d/lib/"
    cp "$SCRIPT_DIR/../build-bundle.sh" "$SCRIPT_DIR/../patched-upload.sh" "$SCRIPT_DIR/../patched-version.json" "$_d/" 2>/dev/null
    cp "$_c" "$_d/patched-collect.sh"
    ( cd "$_d" && zsh ./build-bundle.sh --agent-version 0.0.1 >/dev/null 2>&1 )
    awk '/^source "\$\{LIB_DIR\}\/agent_health\.sh"$/ {s=NR} /^collect_browser_extensions$/ {c=NR} END {exit !(s && c && s < c)}' "$_c" \
        && grep -q '^patched_agent_health_record_failure() {' "$_d/dist/patched-collect.sh" 2>/dev/null \
        && echo 1 || echo 0
}
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
chk "the collector sources agent_health.sh, and its bundle defines patched_agent_health_record_failure" "$(collector_loads_health "$COLLECT_SH")"
grep -v '^source "${LIB_DIR}/agent_health.sh"$' "$COLLECT_SH" > "$WORK/collect-no-health.sh"
chk "the check goes red with the source line removed (so it can fail)" \
    "$([[ "$(collector_loads_health "$WORK/collect-no-health.sh")" == 0 ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
