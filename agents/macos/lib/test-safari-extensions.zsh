#!/bin/zsh
##############################################################################
# test-safari-extensions.zsh — unit tests for the PAT-821 Safari App Extension
# collector (collect_safari_app_extensions) in browser_extensions.sh.
#
# Sources the live function out of browser_extensions.sh (no top-level side
# effects at source time) so the tests exercise the real code, not a copy.
# collect_safari_app_extensions accepts optional search-root overrides
# specifically so this file can point it at a synthetic fixture tree instead
# of the real /Applications. Run:
#   zsh macos/lib/test-safari-extensions.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/browser_extensions.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# run_collector <fixture-applications-dir> -> writes a closed JSON array to
# $1/out.json, mirroring how collect_browser_extensions wraps the call. Sets
# COLLECTOR_EXIT to collect_safari_app_extensions's own exit status (captured
# immediately, before the trailing "]" write would otherwise clobber $?).
run_collector() {
    local fixture_apps="$1"
    QUEUE_DIR=$(mktemp -d)
    TS_FILE="test"
    BROWSER_EXTENSIONS_JSON_FILE="$QUEUE_DIR/out.json"
    echo "[" > "$BROWSER_EXTENSIONS_JSON_FILE"
    FIRST_EXT=true
    EXT_COUNT=0
    MAX_EXTENSIONS=1000
    collect_safari_app_extensions "$fixture_apps"
    COLLECTOR_EXIT=$?
    echo "]" >> "$BROWSER_EXTENSIONS_JSON_FILE"
}

##############################################################################
# 1. Populated case: web-extension (manifest.json permissions), legacy
#    extension (SFSafariWebsiteAccess), a Mac-App-Store host (from_webstore),
#    and a non-Safari appex that must be filtered out.
##############################################################################
echo "--- 1. Populated Safari extension inventory"

FIXTURE=$(mktemp -d)
APPS="$FIXTURE/Applications"
mkdir -p "$APPS/FakeVendor/HostApp.app/Contents/PlugIns/WebExt.appex/Contents/Resources"
mkdir -p "$APPS/FakeVendor/HostApp.app/Contents/PlugIns/LegacyExt.appex/Contents"
mkdir -p "$APPS/FakeVendor/HostApp.app/Contents/PlugIns/NotSafari.appex/Contents"
mkdir -p "$APPS/MasApp.app/Contents/PlugIns/MasExt.appex/Contents"
mkdir -p "$APPS/MasApp.app/Contents/_MASReceipt"

"$PYTHON3" - "$APPS" <<'PYEOF'
import plistlib, json, sys
apps = sys.argv[1]

def w(path, data):
    with open(path, 'wb') as f:
        plistlib.dump(data, f)

w(f"{apps}/FakeVendor/HostApp.app/Contents/Info.plist",
  {'CFBundleName': 'FakeVendor Host', 'CFBundleIdentifier': 'com.fakevendor.host'})

w(f"{apps}/FakeVendor/HostApp.app/Contents/PlugIns/WebExt.appex/Contents/Info.plist",
  {'CFBundleIdentifier': 'com.fakevendor.webext', 'CFBundleDisplayName': 'Fake Web Ext',
   'CFBundleShortVersionString': '2.0',
   'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.web-extension'}})
with open(f"{apps}/FakeVendor/HostApp.app/Contents/PlugIns/WebExt.appex/Contents/Resources/manifest.json", 'w') as f:
    json.dump({"manifest_version": 3, "permissions": ["tabs"], "host_permissions": ["<all_urls>"]}, f)

w(f"{apps}/FakeVendor/HostApp.app/Contents/PlugIns/LegacyExt.appex/Contents/Info.plist",
  {'CFBundleIdentifier': 'com.fakevendor.legacyext', 'CFBundleName': 'Fake Legacy Ext',
   'CFBundleShortVersionString': '1.5',
   'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension',
                    'SFSafariWebsiteAccess': {'Level': 'Some', 'Allowed Domains': ['example.com']}}})

w(f"{apps}/FakeVendor/HostApp.app/Contents/PlugIns/NotSafari.appex/Contents/Info.plist",
  {'CFBundleIdentifier': 'com.fakevendor.notsafari',
   'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.share-services'}})

w(f"{apps}/MasApp.app/Contents/Info.plist", {'CFBundleName': 'Mas App'})
w(f"{apps}/MasApp.app/Contents/PlugIns/MasExt.appex/Contents/Info.plist",
  {'CFBundleIdentifier': 'com.masapp.ext', 'CFBundleName': 'Mas Ext',
   'CFBundleShortVersionString': '3.0',
   'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.Safari.extension',
                    'SFSafariWebsiteAccess': {'Level': 'All'}}})
PYEOF

run_collector "$APPS"

chk_eq "3 Safari extensions found (non-Safari appex excluded)" "3" "$EXT_COUNT"

RESULT="$("$PYTHON3" - "$BROWSER_EXTENSIONS_JSON_FILE" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    entries = json.load(f)
by_id = {e['extension_id']: e for e in entries}

checks = []
checks.append(('ids match expected set',
                sorted(by_id) == ['com.fakevendor.legacyext', 'com.fakevendor.webext', 'com.masapp.ext']))

w = by_id.get('com.fakevendor.webext', {})
checks.append(('webext browser=safari', w.get('browser') == 'safari'))
checks.append(('webext name', w.get('name') == 'Fake Web Ext'))
checks.append(('webext version', w.get('version') == '2.0'))
checks.append(('webext vendor', w.get('vendor') == 'FakeVendor Host'))
checks.append(('webext permissions from manifest.json', w.get('permissions') == ['tabs']))
checks.append(('webext host_permissions from manifest.json', w.get('host_permissions') == ['<all_urls>']))
checks.append(('webext from_webstore false (no _MASReceipt)', w.get('from_webstore') is False))
checks.append(('webext enabled unknown -> null (no console user in CI)', w.get('enabled') is None))
checks.append(('webext profile null (not per-profile like Chrome)', w.get('profile') is None))
checks.append(('webext user_account null (not per-user like Chrome)', w.get('user_account') is None))

l = by_id.get('com.fakevendor.legacyext', {})
checks.append(('legacy host_permissions from SFSafariWebsiteAccess', l.get('host_permissions') == ['example.com']))
checks.append(('legacy permissions empty (no manifest concept)', l.get('permissions') == []))

m = by_id.get('com.masapp.ext', {})
checks.append(('mas host_permissions Level=All -> <all_urls>', m.get('host_permissions') == ['<all_urls>']))
checks.append(('mas from_webstore true (_MASReceipt present)', m.get('from_webstore') is True))

for desc, ok in checks:
    print(f"{'OK' if ok else 'BAD'}\t{desc}")
PYEOF
)"

while IFS=$'\t' read -r chk_status desc; do
    [[ -z "$chk_status" ]] && continue
    if [[ "$chk_status" == "OK" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
done <<< "$RESULT"

##############################################################################
# 2. Empty case: fixture with no .appex bundles at all. Must not error, and
#    must produce a valid (empty) JSON array — this is the "Safari absent"
#    path every non-Safari-using endpoint hits in production.
##############################################################################
echo "--- 2. Empty Safari extension inventory (no extensions installed)"

EMPTY_FIXTURE=$(mktemp -d)
EMPTY_APPS="$EMPTY_FIXTURE/Applications"
mkdir -p "$EMPTY_APPS/PlainApp.app/Contents"
"$PYTHON3" -c "
import plistlib
with open('$EMPTY_APPS/PlainApp.app/Contents/Info.plist', 'wb') as f:
    plistlib.dump({'CFBundleName': 'Plain App'}, f)
"

run_collector "$EMPTY_APPS"

chk_eq "no extensions counted" "0" "$EXT_COUNT"
chk_eq "collector exits cleanly on empty inventory" "0" "$COLLECTOR_EXIT"

EMPTY_VALID=$("$PYTHON3" -c "
import json
with open('$BROWSER_EXTENSIONS_JSON_FILE') as f:
    data = json.load(f)
print('OK' if data == [] else 'BAD')
")
chk_eq "empty inventory serializes as valid []" "OK" "$EMPTY_VALID"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
