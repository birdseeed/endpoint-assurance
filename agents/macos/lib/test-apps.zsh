#!/bin/zsh
##############################################################################
# test-apps.zsh — unit tests for the installed application collector
# (collect_apps) in apps.sh: collection_status.apps (PAT-2066, platform half
# PAT-2063).
#
# Sources the live functions out of apps.sh (no top-level side effects at
# source time) so the tests exercise the real code, not a copy. Boundaries:
#
#   _apps_scan_roots   redefined to walk fixture directories under
#                      $PATCHED_TMPDIR instead of /Applications.
#   /usr/bin/mdutil    shadowed to report indexing disabled, so no Spotlight
#                      reads run. zsh resolves a function before an external
#                      command even when the command word is an absolute path.
#   codesign, lipo     shadowed: the fixtures are not signed binaries and the
#                      status rules do not depend on either. codesign prints
#                      $CODESIGN_STUB_OUT and exits $CODESIGN_STUB_RC.
#   spctl              _APPS_SPCTL points at stub scripts (real processes, so
#                      the timeout really kills one) or at a missing file.
#   codesign --verify  _APPS_CODESIGN (the trust-anchor check, PAT-2117)
#                      points at stub scripts the same way. By default one
#                      that accepts, so a signed fixture stays signed.
# Signing and notarisation (PAT-2112) are checked twice: the parsers against
# codesign and spctl output captured on a real Mac, and collect_apps end to
# end through the payload.
#   find, PlistBuddy   NOT shadowed: the real find exit status and the real
#                      plist parse are what the status rules depend on.
#
# The payload checks render the REAL "apps" and "collection_status" lines of
# the patched-collect.sh heredoc with the collector's current state.
# Run:
#   zsh macos/lib/test-apps.zsh
# APPS_SH_UNDER_TEST=<path> runs the same tests against another apps.sh.
# COLLECT_SH_UNDER_TEST=<path> reads the payload lines from another
# patched-collect.sh.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/common.sh"
source "${APPS_SH_UNDER_TEST:-$SCRIPT_DIR/apps.sh}"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

PATCHED_TMPDIR=$(mktemp -d)
trap 'chmod -R u+rwx "$PATCHED_TMPDIR" 2>/dev/null; rm -rf "$PATCHED_TMPDIR"' EXIT
QUEUE_DIR="$PATCHED_TMPDIR/queue"
mkdir -p "$QUEUE_DIR"
TS_FILE="test"

# ── Boundary doubles ───────────────────────────────────────────────────────
/usr/bin/mdutil() { print -r -- "/: Indexing disabled."; }
# codesign: what the case sets (PAT-2112), by default a signed, non-Developer
# ID app so no default case ever runs spctl.
CODESIGN_STUB_OUT=$'CodeDirectory v=20400 size=1 flags=0x0(none) hashes=1+0 location=embedded\nAuthority=Test Authority\nTeamIdentifier=TESTTEAM01'
CODESIGN_STUB_RC=0
codesign() { print -r -- "$CODESIGN_STUB_OUT"; return $CODESIGN_STUB_RC; }
lipo() { print -r -- "Non-fat file: $2 is architecture: arm64"; }
# The anchor check (PAT-2117): a real process that logs its arguments and
# exits by the bundle's name, so the timeout really kills one.
mkdir -p "$PATCHED_TMPDIR/bin"
VERIFY_STUB="$PATCHED_TMPDIR/bin/codesign-verify"
cat > "$VERIFY_STUB" <<'VEOF'
#!/bin/zsh
print -r -- "$*" >> "$0.args"
case "${@[-1]:t}" in
    Fake.app)     exit 3 ;;
    Tampered.app) exit 1 ;;
    Usage.app)    exit 2 ;;
    Hang.app)     exec /bin/sleep 30 ;;
esac
exit 0
VEOF
chmod +x "$VERIFY_STUB"
_APPS_CODESIGN="$VERIFY_STUB"

FIXTURE_ROOTS=()
_apps_scan_roots() { reply=("${FIXTURE_ROOTS[@]}"); }
# PAT-2075: no real home is enumerated, so no real account is ever looked up.
_apps_scan_homes() { reply=(); }

# make_app <root> <name> <bundle-id>: a minimal well-formed top-level bundle.
make_app() {
    local dir="$1/$2.app"
    mkdir -p "$dir/Contents/MacOS"
    cat > "$dir/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$2</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
  <key>CFBundleIdentifier</key><string>$3</string>
  <key>CFBundleExecutable</key><string>$2</string>
</dict>
</plist>
PLIST
    print -r -- "binary" > "$dir/Contents/MacOS/$2"
}

# new_case <name>: fresh fixture roots and the patched-collect.sh stub state.
CASE_DIR=""
new_case() {
    echo "--- $1"
    CASE_DIR="$PATCHED_TMPDIR/case-$1"
    mkdir -p "$CASE_DIR/Applications" "$CASE_DIR/UserApps"
    FIXTURE_ROOTS=("$CASE_DIR/Applications" "$CASE_DIR/UserApps")
    APPS_JSON_FILE=$(mktemp "$PATCHED_TMPDIR/apps-stub.XXXXXX")
    printf '[]' > "$APPS_JSON_FILE"
    APPS_COLLECTION_STATUS="unavailable"
    rm -f "$QUEUE_DIR/.apps-$TS_FILE.tmp"
}

run_collect() {
    collect_apps 2> "$PATCHED_TMPDIR/stderr.log" > /dev/null
}
warning_line() { grep "^PATCHED_COLLECTION_WARNING" "$PATCHED_TMPDIR/stderr.log" 2>/dev/null || true; }

# payload_eval <python-expr over d>: the real payload lines, closed into an object.
COLLECT_SH="${COLLECT_SH_UNDER_TEST:-$SCRIPT_DIR/../patched-collect.sh}"
APPS_LINE=$(grep -E '^  "apps": ' "$COLLECT_SH")
STATUS_LINE=$(grep -E '^  "collection_status": \{"certificates": ' "$COLLECT_SH")
METERING_LINE=$(grep -E '^  "metering_status": ' "$COLLECT_SH")
if [[ "$APPS_LINE" != '  "apps": $(apps_payload_array),' \
      || "$STATUS_LINE" != *'"apps": $(json_escape "$(apps_collection_status)")'* ]]; then
    echo "FAIL: patched-collect.sh does not emit apps through apps_payload_array and collection_status.apps"
    echo "  apps line:   $APPS_LINE"
    echo "  status line: $STATUS_LINE"
    exit 1
fi
certs_collection_status() { print -r -- "complete"; }
# PAT-2067: collection_status.safari_extensions is covered by
# test-browser-extensions.zsh; stubbed so the status line renders.
safari_extensions_collection_status() { print -r -- "unavailable"; }
payload_eval() {
    local obj="$PATCHED_TMPDIR/payload.json"
    {
        print -r -- "{"
        eval "cat <<PAYLOAD_EOF
$APPS_LINE
$METERING_LINE
${STATUS_LINE%,}
PAYLOAD_EOF"
        print -r -- "}"
    } > "$obj" 2>/dev/null
    if [[ "${METERING_CAPTURE:-false}" == true && -n "${PATCHED_USAGE_DUMP:-}" ]]; then
        mkdir -p "$PATCHED_USAGE_DUMP"
        cp "$obj" "$PATCHED_USAGE_DUMP/macos-${pass}-${fail}.json"
    fi
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
print($1)
" "$obj" 2>/dev/null || echo "JSON_ERROR"
}
payload_status() { payload_eval 'd["collection_status"]["apps"]'; }
payload_ids() { payload_eval '",".join(sorted(a["identifier"] for a in d["apps"]))'; }

# ── 1. Clean walk: complete ────────────────────────────────────────────────
new_case clean
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_app "$CASE_DIR/UserApps" Beta com.example.beta
# A helper nested inside another bundle is scope, not a skipped app.
make_app "$CASE_DIR/Applications/Alpha.app/Contents/Frameworks" "Alpha Helper" com.example.alpha.helper
run_collect
chk_eq "clean walk: status complete" "complete" "$APPS_COLLECTION_STATUS"
chk_eq "clean walk: payload collection_status.apps complete" "complete" "$(payload_status)"
chk_eq "clean walk: every top-level bundle sent, nested helper left out" "com.example.alpha,com.example.beta" "$(payload_ids)"
chk_eq "clean walk: collection_status keeps certificates" "complete" "$(payload_eval 'd["collection_status"]["certificates"]')"
chk_eq "clean walk: no collection warning" "" "$(warning_line)"

# ── 2. Clean walk of empty roots: complete with [] ─────────────────────────
new_case empty
run_collect
chk_eq "empty walk: status complete" "complete" "$(payload_status)"
chk_eq "empty walk: apps is []" "0" "$(payload_eval 'len(d["apps"])')"

# ── 3. Bundle with no Info.plist: partial ──────────────────────────────────
new_case noplist
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
mkdir -p "$CASE_DIR/Applications/Broken.app/Contents"
run_collect
chk_eq "missing Info.plist: status partial" "partial" "$(payload_status)"
chk_eq "missing Info.plist: readable bundles still sent" "com.example.alpha" "$(payload_ids)"
chk_eq "missing Info.plist: warning names the reason" \
    "PATCHED_COLLECTION_WARNING section=apps status=partial reason=bundle_unreadable skipped=1" "$(warning_line)"

# ── 4. Info.plist that does not parse: partial ─────────────────────────────
new_case badplist
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_app "$CASE_DIR/UserApps" Garbled com.example.garbled
print -r -- "<plist><dict><key>CFBundleName" > "$CASE_DIR/UserApps/Garbled.app/Contents/Info.plist"
run_collect
chk_eq "unparseable Info.plist: status partial" "partial" "$(payload_status)"
chk_eq "unparseable Info.plist: garbled bundle left out" "com.example.alpha" "$(payload_ids)"

# ── 4b. Out of scope: a .app that is not a directory ──────────────────────
new_case scope
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
print -r -- "alias data" > "$CASE_DIR/Applications/Uninstaller.app"
run_collect
chk_eq "non-directory .app: out of scope, status complete" "complete" "$(payload_status)"
chk_eq "non-directory .app: sends no row" "com.example.alpha" "$(payload_ids)"
chk_eq "non-directory .app: logs no warning" "" "$(warning_line)"

# ── 4c. iOS and iPadOS wrapper apps are in scope (PAT-2072) ───────────────
# make_ios_app <root> <name> <plist-body>: the Apple silicon layout, a flat
# bundle at Wrapper/<name>.app with its Info.plist at the bundle root, no
# Contents/, and a WrappedBundle symlink beside it.
make_ios_app() {
    local dir="$1/$2.app"
    mkdir -p "$dir/Wrapper/$2.app"
    cat > "$dir/Wrapper/$2.app/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
$3
</dict>
</plist>
PLIST
    print -r -- "binary" > "$dir/Wrapper/$2.app/$2"
    ln -s "Wrapper/$2.app" "$dir/WrappedBundle"
}
payload_app() {  # payload_app <identifier> <field>
    payload_eval "[a.get('$2') for a in d['apps'] if a['identifier'] == '$1'][0]"
}

new_case ios
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_ios_app "$CASE_DIR/Applications" Phone '
  <key>CFBundleIdentifier</key><string>com.example.phone</string>
  <key>CFBundleDisplayName</key><string>Phone Display</string>
  <key>CFBundleName</key><string>PhoneName</string>
  <key>CFBundleShortVersionString</key><string>4.5.6</string>
  <key>CFBundleVersion</key><string>202607011</string>
  <key>CFBundleExecutable</key><string>Phone</string>'
# Only CFBundleName and CFBundleVersion: each falls back one step.
make_ios_app "$CASE_DIR/UserApps" Tablet '
  <key>CFBundleIdentifier</key><string>com.example.tablet</string>
  <key>CFBundleName</key><string>TabletName</string>
  <key>CFBundleVersion</key><string>77</string>'
run_collect
chk_eq "iOS wrapper: status complete" "complete" "$(payload_status)"
chk_eq "iOS wrapper: rows sent beside the Mac app" \
    "com.example.alpha,com.example.phone,com.example.tablet" "$(payload_ids)"
chk_eq "iOS wrapper: display name wins" "Phone Display" "$(payload_app com.example.phone name)"
chk_eq "iOS wrapper: short version wins" "4.5.6" "$(payload_app com.example.phone version)"
chk_eq "iOS wrapper: bundle_id matches identifier" "com.example.phone" "$(payload_app com.example.phone bundle_id)"
chk_eq "iOS wrapper: path is the outer bundle" "$CASE_DIR/Applications/Phone.app" "$(payload_app com.example.phone path)"
chk_eq "iOS wrapper: executable read from the flat inner bundle" "arm64" "$(payload_app com.example.phone architecture)"
chk_eq "iOS wrapper: name falls back to CFBundleName" "TabletName" "$(payload_app com.example.tablet name)"
chk_eq "iOS wrapper: version falls back to CFBundleVersion" "77" "$(payload_app com.example.tablet version)"
chk_eq "iOS wrapper: no warning" "" "$(warning_line)"

new_case iosbad
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_ios_app "$CASE_DIR/Applications" Garbled '<key>CFBundleIdentifier'
run_collect
chk_eq "iOS wrapper with unparseable Info.plist: status partial" "partial" "$(payload_status)"
chk_eq "iOS wrapper with unparseable Info.plist: other rows still sent" "com.example.alpha" "$(payload_ids)"
chk_eq "iOS wrapper with unparseable Info.plist: warning names the reason" \
    "PATCHED_COLLECTION_WARNING section=apps status=partial reason=bundle_unreadable skipped=1" "$(warning_line)"

new_case iosnoplist
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_ios_app "$CASE_DIR/Applications" Gone '<key>CFBundleIdentifier</key><string>com.example.gone</string>'
rm "$CASE_DIR/Applications/Gone.app/Wrapper/Gone.app/Info.plist"
run_collect
chk_eq "iOS wrapper with no Info.plist: status partial" "partial" "$(payload_status)"

new_case iosempty
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
mkdir -p "$CASE_DIR/UserApps/Tablet.app/Wrapper"
run_collect
chk_eq "iOS wrapper with no inner app: status partial" "partial" "$(payload_status)"
chk_eq "iOS wrapper with no inner app: other rows still sent" "com.example.alpha" "$(payload_ids)"

new_case iostwo
make_ios_app "$CASE_DIR/Applications" Phone '<key>CFBundleIdentifier</key><string>com.example.phone</string>'
mkdir -p "$CASE_DIR/Applications/Phone.app/Wrapper/Other.app"
run_collect
chk_eq "iOS wrapper with two inner apps: status partial" "partial" "$(payload_status)"

if (( EUID != 0 )); then
    new_case iosunreadable
    make_app "$CASE_DIR/Applications" Alpha com.example.alpha
    make_ios_app "$CASE_DIR/Applications" Locked '<key>CFBundleIdentifier</key><string>com.example.locked</string>'
    chmod 000 "$CASE_DIR/Applications/Locked.app/Wrapper/Locked.app/Info.plist"
    run_collect
    chmod 644 "$CASE_DIR/Applications/Locked.app/Wrapper/Locked.app/Info.plist"
    chk_eq "iOS wrapper with unreadable Info.plist: status partial" "partial" "$(payload_status)"
    chk_eq "iOS wrapper with unreadable Info.plist: other rows still sent" "com.example.alpha" "$(payload_ids)"
else
    echo "  SKIP: unreadable iOS Info.plist (running as root, permissions do not bind)"
fi

# PlistBuddy exits 0 on a plist it cannot open; the gate must still catch it.
if (( EUID != 0 )); then
    new_case macunreadable
    make_app "$CASE_DIR/Applications" Alpha com.example.alpha
    make_app "$CASE_DIR/Applications" Locked com.example.locked
    chmod 000 "$CASE_DIR/Applications/Locked.app/Contents/Info.plist"
    run_collect
    chmod 644 "$CASE_DIR/Applications/Locked.app/Contents/Info.plist"
    chk_eq "Mac bundle with unreadable Info.plist: status partial" "partial" "$(payload_status)"
    chk_eq "Mac bundle with unreadable Info.plist: no garbage row" "com.example.alpha" "$(payload_ids)"
else
    echo "  SKIP: unreadable Mac Info.plist (running as root, permissions do not bind)"
fi

# A directory with Contents/ is a real bundle even beside a Wrapper/.
new_case realbundle
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
mkdir -p "$CASE_DIR/Applications/Odd.app/Contents" "$CASE_DIR/Applications/Odd.app/Wrapper"
run_collect
chk_eq "bundle with Contents/ and no Info.plist: still partial" "partial" "$(payload_status)"

# ── 5. Failed directory listing: partial ───────────────────────────────────
new_case missingroot
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
FIXTURE_ROOTS+=("$CASE_DIR/NoSuchRoot")
run_collect
chk_eq "root that cannot be listed: status partial" "partial" "$(payload_status)"
chk_eq "root that cannot be listed: rows found elsewhere still sent" "com.example.alpha" "$(payload_ids)"
chk_eq "root that cannot be listed: warning names the reason" \
    "PATCHED_COLLECTION_WARNING section=apps status=partial reason=listing_failed skipped=0" "$(warning_line)"

if (( EUID != 0 )); then
    new_case unlistable
    make_app "$CASE_DIR/Applications" Alpha com.example.alpha
    mkdir -p "$CASE_DIR/UserApps/Locked"
    make_app "$CASE_DIR/UserApps/Locked" Hidden com.example.hidden
    chmod 000 "$CASE_DIR/UserApps/Locked"
    run_collect
    chmod 755 "$CASE_DIR/UserApps/Locked"
    chk_eq "subdirectory find cannot list: status partial" "partial" "$(payload_status)"
    chk_eq "subdirectory find cannot list: visible rows still sent" "com.example.alpha" "$(payload_ids)"
else
    echo "  SKIP: unlistable subdirectory (running as root, permissions do not bind)"
fi

# ── 6. Stub path: unavailable, apps [] ─────────────────────────────────────
new_case stub
chk_eq "stub before collection: status unavailable" "unavailable" "$(payload_status)"
chk_eq "stub before collection: apps is []" "0" "$(payload_eval 'len(d["apps"])')"

# collect_apps giving up before its walk (here: no temp file for the listing)
# leaves the stub in place and the status unavailable.
new_case earlyexit
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
mktemp() { return 1; }
run_collect
unfunction mktemp
chk_eq "collection that exits early: status unavailable" "unavailable" "$(payload_status)"
chk_eq "collection that exits early: apps is []" "0" "$(payload_eval 'len(d["apps"])')"

# Defence in depth: rows in the file never go out under unavailable.
new_case mismatch
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
run_collect
APPS_COLLECTION_STATUS="unavailable"
chk_eq "unavailable with rows on disk: apps is []" "0" "$(payload_eval 'len(d["apps"])')"

for bad in "" "Complete" "bogus"; do
    APPS_COLLECTION_STATUS="$bad"
    chk_eq "status '$bad': collection_status unavailable" "unavailable" "$(payload_status)"
done
unset APPS_COLLECTION_STATUS
chk_eq "status unset: collection_status unavailable" "unavailable" "$(payload_status)"

# ── 7. patched-collect.sh defaults the status before any collector runs ────
chk_eq "patched-collect.sh stubs collection_status.apps unavailable" "1" \
    "$(grep -c '^APPS_COLLECTION_STATUS="unavailable"$' "$COLLECT_SH")"

# ── 8. Signing and notarisation evidence (PAT-2112) ────────────────────────
# Output captured on macOS 26 (the PAT-2112 test Mac), trimmed of lines the
# parsers do not read. Every field is read after the CodeDirectory line
# (PAT-2115), so that line is kept in each. Chrome is stapled; VLC is notarised but not stapled,
# which only spctl can see.
CS_CHROME='Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
Identifier=com.google.Chrome
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=765 flags=0x12a00(kill,restrict,library-validation,runtime) hashes=13+7 location=embedded
Signature size=8989
Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=22 Sep 2026 at 06:31:19
Notarization Ticket=stapled
Info.plist entries=44
TeamIdentifier=EQHXZ8M8AV'
CS_VLC='Executable=/Applications/VLC.app/Contents/MacOS/VLC
Identifier=org.videolan.vlc
Format=app bundle with Mach-O thin (x86_64)
CodeDirectory v=20500 size=796 flags=0x10000(runtime) hashes=14+7 location=embedded
Signature size=9046
Authority=Developer ID Application: VideoLAN (75GAHG3SZQ)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=18 Dec 2025 at 05:28:32
Info.plist entries=40
TeamIdentifier=75GAHG3SZQ'
CS_SAFARI='Executable=/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari
Identifier=com.apple.Safari
Format=app bundle with Mach-O universal (x86_64 arm64e arm64e.x1)
CodeDirectory v=20400 size=457 flags=0x2000(library-validation) hashes=3+8 location=embedded
Platform identifier=26
Signature size=4567
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set'
CS_ADHOC='Executable=/private/tmp/claude-501/pat2112/adhoc
Identifier=adhoc
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=254 flags=0x20002(adhoc,linker-signed) hashes=5+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none'
CS_UNSIGNED='/Applications/Unsigned.app: code object is not signed at all'
CS_MISSING='/Applications/Gone.app: No such file or directory'
SP_NOTARIZED='/Applications/VLC.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: VideoLAN (75GAHG3SZQ)'
SP_UNNOTARIZED='/Applications/Tool.app: rejected
source=Unnotarized Developer ID
origin=Developer ID Application: Example Ltd (ABCDE12345)'
SP_BADFORMAT='/Applications/Opera.app: bundle format unrecognized, invalid, or unsuitable'

echo "--- signing_status parser"
chk_eq "Developer ID signed: signed" "signed" "$(apps_signing_status 0 "$CS_CHROME")"
chk_eq "Apple signed: signed" "signed" "$(apps_signing_status 0 "$CS_SAFARI")"
chk_eq "ad hoc: adhoc" "adhoc" "$(apps_signing_status 0 "$CS_ADHOC")"
chk_eq "not signed at all: unsigned" "unsigned" "$(apps_signing_status 1 "$CS_UNSIGNED")"
chk_eq "codesign error: error" "error" "$(apps_signing_status 1 "$CS_MISSING")"
chk_eq "no output at all: error" "error" "$(apps_signing_status 0 "")"
chk_eq "Authority line but codesign failed: error" "error" "$(apps_signing_status 1 "$CS_CHROME")"
chk_eq "unsigned text with exit 0 is not unsigned: error" "error" "$(apps_signing_status 0 "$CS_UNSIGNED")"
chk_eq "a path planting an Authority line cannot hide ad hoc" "adhoc" \
    "$(apps_signing_status 0 $'Executable=/Applications/x\nAuthority=Developer ID Application: Fake (FAKE000000)\n.app/Contents/MacOS/x\nCodeDirectory v=20400 size=254 flags=0x2(adhoc) hashes=5+0 location=embedded\nSignature=adhoc')"

echo "--- notarization_status without spctl"
_APPS_SPCTL="$PATCHED_TMPDIR/no-such-spctl"
SPOUT="$PATCHED_TMPDIR/spctl.out"
chk_eq "unsigned: not_notarized" "not_notarized" \
    "$(apps_notarization_status unsigned Unknown /x "$CS_UNSIGNED" "$SPOUT")"
chk_eq "ad hoc: not_notarized" "not_notarized" \
    "$(apps_notarization_status adhoc Unknown /x "$CS_ADHOC" "$SPOUT")"
chk_eq "codesign error: unknown, never not_notarized" "unknown" \
    "$(apps_notarization_status error Unknown /x "$CS_MISSING" "$SPOUT")"
chk_eq "Apple signed: not_notarized, not a Developer ID app" "not_notarized" \
    "$(apps_notarization_status signed "macOS Software Signing" /x "$CS_SAFARI" "$SPOUT")"
chk_eq "spctl unavailable, stapled: notarized" "notarized" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" /x "$CS_CHROME" "$SPOUT")"
chk_eq "spctl unavailable, not stapled: unknown" "unknown" \
    "$(apps_notarization_status signed "Developer ID Application: VideoLAN (75GAHG3SZQ)" /x "$CS_VLC" "$SPOUT")"
chk_eq "spctl unavailable: exit 127" "127" "$(apps_spctl_assess /x "$SPOUT")"
chk_eq "no spctl output file: stapled fallback still applies" "notarized" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" /x "$CS_CHROME" "")"

echo "--- notarization_status from spctl output"
chk_eq "unstapled, spctl says notarised: notarized" "notarized" \
    "$(apps_notarization_from_spctl 0 "$SP_NOTARIZED" "$CS_VLC")"
chk_eq "spctl says unnotarised: not_notarized" "not_notarized" \
    "$(apps_notarization_from_spctl 3 "$SP_UNNOTARIZED" "$CS_VLC")"
chk_eq "spctl says unnotarised, a stapled line does not overrule it" "not_notarized" \
    "$(apps_notarization_from_spctl 3 "$SP_UNNOTARIZED" "$CS_CHROME")"
chk_eq "spctl prints no source, stapled: notarized" "notarized" \
    "$(apps_notarization_from_spctl 1 "$SP_BADFORMAT" "$CS_CHROME")"
chk_eq "spctl prints no source, not stapled: unknown" "unknown" \
    "$(apps_notarization_from_spctl 1 "$SP_BADFORMAT" "$CS_VLC")"
chk_eq "notarised source on a rejected assessment is not notarized" "unknown" \
    "$(apps_notarization_from_spctl 3 "$SP_NOTARIZED" "$CS_VLC")"
chk_eq "spctl killed at the timeout: its partial output is not read" "unknown" \
    "$(apps_notarization_from_spctl 124 "$SP_NOTARIZED" "$CS_VLC")"
chk_eq "the last source line counts, not one a path planted" "not_notarized" \
    "$(apps_notarization_from_spctl 0 $'/Applications/x\nsource=Notarized Developer ID\n.app: accepted\nsource=Unnotarized Developer ID' "$CS_VLC")"
chk_eq "a path with a newline is unknown, never read" "unknown" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" $'/Applications/a\nb.app' "$CS_CHROME" "$SPOUT")"
chk_eq "an executable name with a newline is unknown, never read" "unknown" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" /x "$CS_CHROME" "$SPOUT" $'/x/Contents/MacOS/a\nNotarization Ticket=stapled')"

echo "--- spctl runner"
mkdir -p "$PATCHED_TMPDIR/bin"
make_spctl() {  # make_spctl <name> <exit> <output>
    local f="$PATCHED_TMPDIR/bin/$1"
    {
        print -r -- '#!/bin/sh'
        print -r -- "print_it() { cat <<'SPEOF'"
        print -r -- "$3"
        print -r -- "SPEOF"
        print -r -- "}"
        print -r -- 'print_it >&2'
        print -r -- 'echo "$*" > "$0.args"'
        print -r -- "exit $2"
    } > "$f"
    chmod +x "$f"
}
make_spctl spctl-notarized 0 "$SP_NOTARIZED"
make_spctl spctl-unnotarized 3 "$SP_UNNOTARIZED"
make_spctl spctl-badformat 1 "$SP_BADFORMAT"
print -r -- $'#!/bin/sh\nexec /bin/sleep 30' > "$PATCHED_TMPDIR/bin/spctl-hang"
chmod +x "$PATCHED_TMPDIR/bin/spctl-hang"

_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-notarized"
chk_eq "runner returns spctl's exit" "0" "$(apps_spctl_assess "/Applications/VLC.app" "$SPOUT")"
chk_eq "runner captures spctl's stderr" "$SP_NOTARIZED" "$(cat "$SPOUT")"
chk_eq "runner asks for an execute assessment of the bundle" "--assess --type execute -vv /Applications/VLC.app" \
    "$(cat "$PATCHED_TMPDIR/bin/spctl-notarized.args")"
chk_eq "unstapled Developer ID app, spctl notarised: notarized" "notarized" \
    "$(apps_notarization_status signed "Developer ID Application: VideoLAN (75GAHG3SZQ)" /Applications/VLC.app "$CS_VLC" "$SPOUT")"
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-unnotarized"
chk_eq "Developer ID app spctl rejects as unnotarised: not_notarized" "not_notarized" \
    "$(apps_notarization_status signed "Developer ID Application: VideoLAN (75GAHG3SZQ)" /Applications/VLC.app "$CS_VLC" "$SPOUT")"
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-badformat"
chk_eq "spctl cannot assess, stapled: notarized" "notarized" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" /Applications/Opera.app "$CS_CHROME" "$SPOUT")"

zmodload zsh/datetime
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-hang"
_APPS_SPCTL_TIMEOUT_SECONDS=1
sp_started=$EPOCHREALTIME
sp_rc=$(apps_spctl_assess /Applications/VLC.app "$SPOUT")
sp_elapsed=$(( EPOCHREALTIME - sp_started ))
chk_eq "a hung spctl is killed: exit 124" "124" "$sp_rc"
chk_eq "a hung spctl is killed near the timeout, not waited for" "1" "$(( sp_elapsed < 5 ))"
chk_eq "a hung spctl, not stapled: unknown" "unknown" \
    "$(apps_notarization_status signed "Developer ID Application: VideoLAN (75GAHG3SZQ)" /Applications/VLC.app "$CS_VLC" "$SPOUT")"
chk_eq "a hung spctl, stapled: notarized" "notarized" \
    "$(apps_notarization_status signed "Developer ID Application: Google LLC (EQHXZ8M8AV)" /Applications/Chrome.app "$CS_CHROME" "$SPOUT")"
_APPS_SPCTL_TIMEOUT_SECONDS=10

echo "--- signing and notarisation through collect_apps and the payload"
# Each app gets its own codesign output through a per-path stub.
codesign() {
    case "${2:t}" in
        Vlc.app)       print -r -- "$CS_VLC" ;;
        Chrome.app)    print -r -- "$CS_CHROME" ;;
        Apple.app)     print -r -- "$CS_SAFARI" ;;
        Adhoc.app)     print -r -- "$CS_ADHOC" ;;
        Unsigned.app)  print -r -- "$CS_UNSIGNED"; return 1 ;;
        Broken.app)    print -r -- "$CS_MISSING"; return 1 ;;
    esac
}
new_case signing
for n in Vlc Chrome Apple Adhoc Unsigned Broken; do
    make_app "$CASE_DIR/Applications" "$n" "com.example.${(L)n}"
done
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-notarized"
rm -f "$PATCHED_TMPDIR/bin/spctl-notarized.args"
run_collect
chk_eq "signing: status complete" "complete" "$(payload_status)"
typeset -A want_sig want_not want_bool
want_sig=(vlc signed chrome signed apple signed adhoc adhoc unsigned unsigned broken error)
want_not=(vlc notarized chrome notarized apple not_notarized adhoc not_notarized unsigned not_notarized broken unknown)
want_bool=(vlc True chrome True apple False adhoc False unsigned False broken False)
for n in vlc chrome apple adhoc unsigned broken; do
    chk_eq "payload $n: signing_status" "${want_sig[$n]}" "$(payload_app com.example.$n signing_status)"
    chk_eq "payload $n: notarization_status" "${want_not[$n]}" "$(payload_app com.example.$n notarization_status)"
    chk_eq "payload $n: notarized boolean" "${want_bool[$n]}" "$(payload_app com.example.$n notarized)"
done
chk_eq "payload unsigned: signed_by stays Unknown" "Unknown" "$(payload_app com.example.unsigned signed_by)"
chk_eq "payload vlc: signed_by unchanged" "Developer ID Application: VideoLAN (75GAHG3SZQ)" "$(payload_app com.example.vlc signed_by)"
chk_eq "payload: the spctl output file is cleaned up" "0" "$(print -l "$PATCHED_TMPDIR"/apps-spctl.*(N) | grep -c .)"

new_case signinghang
make_app "$CASE_DIR/Applications" Vlc com.example.vlc
make_app "$CASE_DIR/Applications" Chrome com.example.chrome
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-hang"
_APPS_SPCTL_TIMEOUT_SECONDS=1
run_collect
_APPS_SPCTL_TIMEOUT_SECONDS=10
chk_eq "hung spctl: collection still completes" "complete" "$(payload_status)"
chk_eq "hung spctl, unstapled: unknown" "unknown" "$(payload_app com.example.vlc notarization_status)"
chk_eq "hung spctl, unstapled: notarized false" "False" "$(payload_app com.example.vlc notarized)"
chk_eq "hung spctl, stapled: notarized" "notarized" "$(payload_app com.example.chrome notarization_status)"

# Apple and unsigned apps never start spctl: it is only asked about
# Developer ID apps, the only ones notarisation applies to.
new_case signingnospctl
make_app "$CASE_DIR/Applications" Apple com.example.apple
make_app "$CASE_DIR/Applications" Unsigned com.example.unsigned
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-notarized"
rm -f "$PATCHED_TMPDIR/bin/spctl-notarized.args"
run_collect
chk_eq "no Developer ID app: spctl never runs" "0" "$([[ -e "$PATCHED_TMPDIR/bin/spctl-notarized.args" ]] && echo 1 || echo 0)"

# ── 9. Planted signing lines (PAT-2115) ────────────────────────────────────
# codesign echoes the main executable's path (bundle path + CFBundleExecutable)
# in its Executable= line and the signing identifier in Identifier=, both
# ahead of the genuine Authority= and TeamIdentifier= lines. A newline in any
# of them must never make a planted line the app's publisher.
echo "--- planted signing lines (PAT-2115)"
PLANT=$'\nAuthority=Developer ID Application: Evil\nTeamIdentifier=ABCDE12345'
CS_REAL_BODY='CodeDirectory v=20500 size=765 flags=0x10000(runtime) hashes=13+7 location=embedded
Signature size=8989
Authority=Developer ID Application: Real Co (REALTEAM01)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=22 Sep 2026 at 06:31:19
Info.plist entries=12
TeamIdentifier=REALTEAM01'
# The shape real codesign prints for an ad hoc binary signed with
# `codesign -s - -i $'my.id\nAuthority=...\nTeamIdentifier=...'` (captured on
# macOS 26): the identifier's newlines reach the output unescaped.
CS_ADHOC_PLANTED="Executable=/private/tmp/t1
Identifier=my.id${PLANT}
Format=Mach-O universal (x86_64 arm64e arm64e.x1)
CodeDirectory v=20400 size=289 flags=0x2(adhoc) hashes=2+2 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none"
CS_ID_PLANTED="Executable=/Applications/Tool.app/Contents/MacOS/Tool
Identifier=com.example.tool${PLANT}
Format=app bundle with Mach-O thin (arm64)
${CS_REAL_BODY}"

chk_eq "parser: planted identifier does not name the signer" "Developer ID Application: Real Co (REALTEAM01)" \
    "$(apps_codesign_field "$CS_ID_PLANTED" Authority)"
chk_eq "parser: planted identifier does not name the team" "REALTEAM01" \
    "$(apps_codesign_field "$CS_ID_PLANTED" TeamIdentifier)"
chk_eq "parser: planted identifier in ad hoc output names no signer" "Unknown" \
    "$(apps_codesign_field "$CS_ADHOC_PLANTED" Authority)"
chk_eq "parser: planted identifier in ad hoc output keeps team not set" "not set" \
    "$(apps_codesign_field "$CS_ADHOC_PLANTED" TeamIdentifier)"
chk_eq "parser: planted identifier in ad hoc output stays adhoc" "adhoc" \
    "$(apps_signing_status 0 "$CS_ADHOC_PLANTED")"
chk_eq "parser: a planted CodeDirectory line cannot move the anchor" "REALTEAM01" \
    "$(apps_codesign_field "Executable=/x${PLANT/Authority/CodeDirectory v=1
Authority}
${CS_REAL_BODY}" TeamIdentifier)"
chk_eq "parser: an error with the path in it names no signer" "Unknown" \
    "$(apps_codesign_field "/Applications/x${PLANT}.app: No such file or directory" Authority)"
chk_eq "parser: an error with the path in it names no team" "Unknown" \
    "$(apps_codesign_field "/Applications/x${PLANT}.app: No such file or directory" TeamIdentifier)"
chk_eq "parser: a planted stapled line is not read as notarised" "unknown" \
    "$(apps_notarization_from_spctl 124 "" "Executable=/x
Identifier=x
Notarization Ticket=stapled
${CS_REAL_BODY}")"

# Real codesign's shape: Executable= carries the bundle path and the
# CFBundleExecutable read from the bundle, Identifier= the stub's identifier
# ($CS_STUB_ID), then the genuine body. Every call is logged.
CS_STUB_ID="com.example.id"
codesign() {
    local exe
    exe=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$2/Contents/Info.plist" 2>/dev/null)
    print -r -- "$2" >> "$PATCHED_TMPDIR/codesign.calls"
    print -r -- "Executable=$2/Contents/MacOS/$exe"
    print -r -- "Identifier=$CS_STUB_ID"
    print -r -- "Format=app bundle with Mach-O thin (arm64)"
    print -r -- "$CS_REAL_BODY"
}
lipo() { print -r -- "$2" >> "$PATCHED_TMPDIR/lipo.calls"; print -r -- "Non-fat file: $2 is architecture: arm64"; }
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-notarized"
# make_app_exec <root> <dir-name> <bundle-id> <executable>: like make_app, but
# the bundle directory and CFBundleExecutable are given separately and may hold
# newlines (the plist value is written through PlistBuddy so it is exact).
make_app_exec() {
    local dir="$1/$2.app"
    mkdir -p "$dir/Contents/MacOS"
    /usr/bin/plutil -create xml1 "$dir/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Add :CFBundleName string Planted" \
        -c "Add :CFBundleShortVersionString string 1.0" \
        -c "Add :CFBundleIdentifier string $3" "$dir/Contents/Info.plist" >/dev/null
    /usr/bin/plutil -insert CFBundleExecutable -string "$4" "$dir/Contents/Info.plist"
    print -r -- "binary" > "$dir/Contents/MacOS/$4"
}
payload_valid() { payload_eval '"ok"'; }

new_case plantdir
: > "$PATCHED_TMPDIR/codesign.calls"; : > "$PATCHED_TMPDIR/lipo.calls"
make_app "$CASE_DIR/Applications" Alpha com.example.alpha
make_app_exec "$CASE_DIR/UserApps" "Tool${PLANT}" com.example.plantdir Tool
run_collect
chk_eq "bundle name with planted lines: JSON stays valid" "ok" "$(payload_valid)"
chk_eq "bundle name with planted lines: the row is still sent" "com.example.alpha,com.example.plantdir" "$(payload_ids)"
chk_eq "bundle name with planted lines: path reported exactly" "$CASE_DIR/UserApps/Tool${PLANT}.app" "$(payload_app com.example.plantdir path)"
chk_eq "bundle name with planted lines: team_id Unknown" "Unknown" "$(payload_app com.example.plantdir team_id)"
chk_eq "bundle name with planted lines: signed_by Unknown" "Unknown" "$(payload_app com.example.plantdir signed_by)"
chk_eq "bundle name with planted lines: signing_status error" "error" "$(payload_app com.example.plantdir signing_status)"
chk_eq "bundle name with planted lines: notarization_status unknown" "unknown" "$(payload_app com.example.plantdir notarization_status)"
chk_eq "bundle name with planted lines: notarized false" "False" "$(payload_app com.example.plantdir notarized)"
chk_eq "bundle name with planted lines: sha256 still read" "$(print -r -- binary | shasum -a 256 | awk '{print $1}')" "$(payload_app com.example.plantdir sha256)"
chk_eq "bundle name with planted lines: codesign never run on it" "0" "$(grep -c Evil "$PATCHED_TMPDIR/codesign.calls")"
chk_eq "bundle name with planted lines: lipo never run on it" "0" "$(grep -c Evil "$PATCHED_TMPDIR/lipo.calls")"
chk_eq "bundle name with planted lines: the clean app keeps its real signer" "REALTEAM01" "$(payload_app com.example.alpha team_id)"
chk_eq "bundle name with planted lines: status complete" "complete" "$(payload_status)"

new_case plantexec
: > "$PATCHED_TMPDIR/codesign.calls"; : > "$PATCHED_TMPDIR/lipo.calls"
make_app_exec "$CASE_DIR/UserApps" Tool com.example.plantexec "Tool${PLANT}"
run_collect
chk_eq "CFBundleExecutable with planted lines: JSON stays valid" "ok" "$(payload_valid)"
chk_eq "CFBundleExecutable with planted lines: the row is still sent" "com.example.plantexec" "$(payload_ids)"
chk_eq "CFBundleExecutable with planted lines: team_id Unknown" "Unknown" "$(payload_app com.example.plantexec team_id)"
chk_eq "CFBundleExecutable with planted lines: signed_by Unknown" "Unknown" "$(payload_app com.example.plantexec signed_by)"
chk_eq "CFBundleExecutable with planted lines: signing_status error" "error" "$(payload_app com.example.plantexec signing_status)"
chk_eq "CFBundleExecutable with planted lines: notarization_status unknown" "unknown" "$(payload_app com.example.plantexec notarization_status)"
chk_eq "CFBundleExecutable with planted lines: codesign never run" "0" "$(grep -c . "$PATCHED_TMPDIR/codesign.calls")"
chk_eq "CFBundleExecutable with planted lines: architecture Unknown, lipo never run" "Unknown/0" \
    "$(payload_app com.example.plantexec architecture)/$(grep -c . "$PATCHED_TMPDIR/lipo.calls")"

new_case plantid
CS_STUB_ID="com.example.plantid${PLANT}"
make_app "$CASE_DIR/UserApps" Tool com.example.plantid
run_collect
CS_STUB_ID="com.example.id"
chk_eq "signing identifier with planted lines: JSON stays valid" "ok" "$(payload_valid)"
chk_eq "signing identifier with planted lines: real team" "REALTEAM01" "$(payload_app com.example.plantid team_id)"
chk_eq "signing identifier with planted lines: real signer" "Developer ID Application: Real Co (REALTEAM01)" "$(payload_app com.example.plantid signed_by)"
chk_eq "signing identifier with planted lines: signed" "signed" "$(payload_app com.example.plantid signing_status)"

# Other control characters are refused too, not only a newline.
new_case plantcr
make_app_exec "$CASE_DIR/UserApps" $'Tool\rAuthority=X' com.example.plantcr Tool
run_collect
chk_eq "bundle name with a CR: JSON stays valid" "ok" "$(payload_valid)"
chk_eq "bundle name with a CR: signing_status error" "error" "$(payload_app com.example.plantcr signing_status)"

# ── 10. Trust anchor (PAT-2117) ────────────────────────────────────────────
# codesign -dvv names the leaf certificate without evaluating trust. This is
# what it printed on the PAT-2117 test Mac (macOS 27) for a copy of
# Calculator re-signed with a self-signed certificate named like a
# Developer ID: an Authority line and nothing to say it is not trusted.
echo "--- trust anchor (PAT-2117)"
CS_SELFSIGNED='Executable=/private/tmp/claude-501/pat2117/ident/Calc.app/Contents/MacOS/Calculator
Identifier=com.apple.calculator
Format=app bundle with Mach-O universal (arm64e arm64e.x1)
CodeDirectory v=20400 size=3501 flags=0x0(none) hashes=103+3 location=embedded
Signature size=1862
Authority=Developer ID Application: Test (ABCDE12345)
Signed Time=24 Sep 2026 at 20:49:25
Info.plist entries=35
TeamIdentifier=not set
Sealed Resources version=2 rules=13 files=9
Internal requirements count=1 size=96
Total signatures=1
Chosen signature=1'
chk_eq "self-signed Developer ID name: -dvv alone says signed" "signed" "$(apps_signing_status 0 "$CS_SELFSIGNED")"

chk_eq "anchor passes: signed" "signed" "$(apps_signing_trust signed 0)"
chk_eq "anchor requirement fails: untrusted" "untrusted" "$(apps_signing_trust signed 3)"
chk_eq "signature does not verify: invalid" "invalid" "$(apps_signing_trust signed 1)"
chk_eq "verify timed out: error, never signed" "error" "$(apps_signing_trust signed 124)"
chk_eq "codesign missing: error" "error" "$(apps_signing_trust signed 127)"
chk_eq "codesign usage error: error" "error" "$(apps_signing_trust signed 2)"
chk_eq "no exit status: error" "error" "$(apps_signing_trust signed "")"
for st in adhoc unsigned error; do
    chk_eq "$st is not re-judged by the anchor check" "$st" "$(apps_signing_trust "$st" 0)"
done

rm -f "$VERIFY_STUB.args"
chk_eq "verify runner: passes codesign's exit" "3" "$(apps_codesign_verify /Applications/Fake.app)"
chk_eq "verify runner: static check of the anchor requirement, no --deep" \
    "--verify --ignore-resources -R =anchor apple generic /Applications/Fake.app" "$(cat "$VERIFY_STUB.args")"
chk_eq "verify runner: accepted" "0" "$(apps_codesign_verify /Applications/Real.app)"
chk_eq "verify runner: broken signature" "1" "$(apps_codesign_verify /Applications/Tampered.app)"
_APPS_CODESIGN="$PATCHED_TMPDIR/no-such-codesign"
chk_eq "verify runner: codesign missing is 127" "127" "$(apps_codesign_verify /Applications/Real.app)"
_APPS_CODESIGN="$VERIFY_STUB"
_APPS_VERIFY_TIMEOUT_SECONDS=1
vf_started=$EPOCHREALTIME
vf_rc=$(apps_codesign_verify /Applications/Hang.app)
vf_elapsed=$(( EPOCHREALTIME - vf_started ))
_APPS_VERIFY_TIMEOUT_SECONDS=10
chk_eq "a hung verify is killed: exit 124" "124" "$vf_rc"
chk_eq "a hung verify is killed near the timeout, not waited for" "1" "$(( vf_elapsed < 5 ))"

_APPS_SPCTL="$PATCHED_TMPDIR/no-such-spctl"
chk_eq "untrusted: not_notarized, it cannot be notarised" "not_notarized" \
    "$(apps_notarization_status untrusted "Developer ID Application: Test (ABCDE12345)" /x "$CS_SELFSIGNED" "$SPOUT")"
chk_eq "invalid: unknown, even with a stapled ticket" "unknown" \
    "$(apps_notarization_status invalid "Developer ID Application: Google LLC (EQHXZ8M8AV)" /x "$CS_CHROME" "$SPOUT")"

echo "--- trust anchor through collect_apps and the payload"
codesign() {
    case "${2:t}" in
        Chrome.app|Tampered.app|Hang.app|Usage.app) print -r -- "$CS_CHROME" ;;
        Fake.app)      print -r -- "$CS_SELFSIGNED" ;;
        Apple.app)     print -r -- "$CS_SAFARI" ;;
        Adhoc.app)     print -r -- "$CS_ADHOC" ;;
        Unsigned.app)  print -r -- "$CS_UNSIGNED"; return 1 ;;
    esac
}
new_case trust
for n in Chrome Fake Tampered Hang Usage Apple Adhoc Unsigned; do
    make_app "$CASE_DIR/Applications" "$n" "com.example.${(L)n}"
done
make_app_exec "$CASE_DIR/UserApps" $'Evil\nAuthority=X' com.example.refused Tool
_APPS_SPCTL="$PATCHED_TMPDIR/bin/spctl-notarized"
rm -f "$PATCHED_TMPDIR/bin/spctl-notarized.args" "$VERIFY_STUB.args"
_APPS_VERIFY_TIMEOUT_SECONDS=1
run_collect
_APPS_VERIFY_TIMEOUT_SECONDS=10
chk_eq "trust: status complete" "complete" "$(payload_status)"
typeset -A want_sig want_not
want_sig=(chrome signed fake untrusted tampered invalid hang error usage error apple signed adhoc adhoc unsigned unsigned refused error)
want_not=(chrome notarized fake not_notarized tampered unknown hang unknown usage unknown apple not_notarized adhoc not_notarized unsigned not_notarized refused unknown)
for n in chrome fake tampered hang usage apple adhoc unsigned refused; do
    chk_eq "trust payload $n: signing_status" "${want_sig[$n]}" "$(payload_app com.example.$n signing_status)"
    chk_eq "trust payload $n: notarization_status" "${want_not[$n]}" "$(payload_app com.example.$n notarization_status)"
done
chk_eq "trust payload fake: notarized false" "False" "$(payload_app com.example.fake notarized)"
chk_eq "trust payload fake: signed_by is still the certificate's name, as display text" \
    "Developer ID Application: Test (ABCDE12345)" "$(payload_app com.example.fake signed_by)"
chk_eq "trust payload fake: team_id stays not set" "not set" "$(payload_app com.example.fake team_id)"
chk_eq "trust: verified exactly the bundles -dvv called signed" \
    "Apple.app,Chrome.app,Fake.app,Hang.app,Tampered.app,Usage.app" \
    "$(awk '{ n = split($0, p, "/"); print p[n] }' "$VERIFY_STUB.args" | sort | paste -sd, -)"
chk_eq "trust: a refused bundle never reaches the verify" "0" "$(grep -c Evil "$VERIFY_STUB.args")"
chk_eq "trust: spctl is asked about the trusted Developer ID app only" \
    "--assess --type execute -vv $CASE_DIR/Applications/Chrome.app" "$(cat "$PATCHED_TMPDIR/bin/spctl-notarized.args")"

# PAT-2328: exercise Spotlight evidence through the real app-row and payload
# emitters. Only OS reads are doubled; no production data or user context runs.
# PATCHED_USAGE_DUMP preserves these generated fragments for canonical schema validation.
METERING_CAPTURE=true
/usr/bin/mdutil() { print -r -- "/: Indexing enabled."; }
stat() {
    if [[ "${@[-1]}" == /dev/console ]]; then print -r -- metering_fixture
    else command stat "$@"; fi
}
id() {
    if [[ "$*" == '-u metering_fixture' ]]; then print -r -- 501
    else command id "$@"; fi
}
_mdls_read() {
    local attr="$1" app_name="${2:t}"
    case "$app_name:$attr" in
        Recorded.app:kMDItemLastUsedDate) print -r -- '2026-09-30 12:00:00 +0000' ;;
        Recorded.app:kMDItemUseCount) print -r -- 8 ;;
        CountOnly.app:kMDItemLastUsedDate) print -r -- '(null)' ;;
        CountOnly.app:kMDItemUseCount) print -r -- 3 ;;
        ZeroCount.app:kMDItemUseCount) print -r -- 0 ;;
        Sentinel.app:kMDItemLastUsedDate) print -r -- '1980-01-01 00:00:00 +0000' ;;
        Failed.app:*) print -r -- '(null)'; return 1 ;;
        Malformed.app:*) print -r -- 'could not find fixture' ;;
        Partial.app:kMDItemLastUsedDate) return 1 ;;
        Partial.app:kMDItemUseCount) print -r -- 8 ;;
        *) print -r -- '(null)' ;;
    esac
}
new_case usage-evidence
CODESIGN_STUB_OUT=''; CODESIGN_STUB_RC=1
for n in Recorded CountOnly NoRecord ZeroCount Sentinel Failed Malformed Partial; do
    make_app "$CASE_DIR/Applications" "$n" "com.example.${n:l}"
done
run_collect
chk_eq "metering: readable launch has recorded evidence" recorded "$(payload_app com.example.recorded usage_evidence)"
chk_eq "metering: recorded timestamp survives" '2026-09-30T12:00:00Z' "$(payload_app com.example.recorded last_used_at)"
chk_eq "metering: recorded count survives" 8 "$(payload_app com.example.recorded launch_count)"
chk_eq "metering: positive count alone is recorded" recorded "$(payload_app com.example.countonly usage_evidence)"
chk_eq "metering: successful null reads are no_record" no_record "$(payload_app com.example.norecord usage_evidence)"
chk_eq "metering: successful zero is no_record" no_record "$(payload_app com.example.zerocount usage_evidence)"
chk_eq "metering: successful zero retains the factual count" 0 "$(payload_app com.example.zerocount launch_count)"
for n in sentinel failed malformed partial; do
    chk_eq "metering: $n is unavailable" unavailable "$(payload_app com.example.$n usage_evidence)"
done
chk_eq "metering: failed read never invents a last launch" None "$(payload_app com.example.failed last_used_at)"
chk_eq "metering: failed read never invents a launch count" None "$(payload_app com.example.failed launch_count)"

new_case usage-early-exit
mktemp() { return 1; }
run_collect
unfunction mktemp
chk_eq "metering: incomplete collection is unavailable, not disabled or ok" unavailable "$(payload_eval 'd["metering_status"]')"

# With Spotlight disabled there can be no per-app absence evidence.
/usr/bin/mdutil() { print -r -- "/: Indexing disabled."; }
new_case usage-disabled
make_app "$CASE_DIR/Applications" NoRecord com.example.norecord
run_collect
chk_eq "metering: confirmed disabled source keeps its reason" spotlight_disabled "$(payload_eval 'd["metering_status"]')"
chk_eq "metering: disabled source is unavailable per app" unavailable "$(payload_app com.example.norecord usage_evidence)"

/usr/bin/mdutil() { print -r -- '/: Indexing disabled.'; return 1; }
new_case usage-probe-failed
make_app "$CASE_DIR/Applications" NoRecord com.example.norecord
run_collect
chk_eq "metering: failed probe is not a confirmed disabled source" unavailable "$(payload_eval 'd["metering_status"]')"
chk_eq "metering: failed probe makes per-app evidence unavailable" unavailable "$(payload_app com.example.norecord usage_evidence)"

/usr/bin/mdutil() { print -r -- '/: Indexing enabled.'; }
stat() {
    if [[ "${@[-1]}" == /dev/console ]]; then print -r -- loginwindow
    else command stat "$@"; fi
}
new_case usage-no-session
make_app "$CASE_DIR/Applications" Recorded com.example.recorded
run_collect
chk_eq "metering: no user retains its source reason" no_user_session "$(payload_eval 'd["metering_status"]')"
chk_eq "metering: no user cannot report a fixture launch from the root context" unavailable "$(payload_app com.example.recorded usage_evidence)"
chk_eq "metering: no user does not read root launch metadata" None "$(payload_app com.example.recorded launch_count)"

echo
echo "RESULT: pass=$pass fail=$fail"
(( fail == 0 ))
