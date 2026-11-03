#!/bin/zsh
##############################################################################
# test-uninstall-path-resolution.zsh — unit tests for the PAT-806 middle
# resolution step in resolve_canonical_app_path (patched-uninstall.sh):
#
#   1. curated labels-allowlist.txt (lookup_labels_app_path)  -- reviewed/EULA'd
#   2. known_app_bundles via the pending-removals queue        -- auto-populated
#   3. caller's own raw "${app_name}.app" name-guess fallback  -- unchanged, not
#      part of resolve_canonical_app_path itself
#
# Sources the live lookup_labels_app_path / lookup_known_app_bundle_path /
# resolve_canonical_app_path functions out of patched-uninstall.sh (between
# stable markers) so the tests exercise the real code, not a copy. Run:
#   zsh endpoint/test-uninstall-path-resolution.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-uninstall.sh"

WORKDIR="$(mktemp -d /tmp/.patched-uninstall-path-test.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# Extract lookup_labels_app_path through the end of resolve_canonical_app_path
# (this also captures lookup_known_app_bundle_path, defined between them).
FUNCS="$(mktemp /tmp/.patched-uninstall-path-funcs.XXXXXX)"
awk '
  /^lookup_labels_app_path\(\) \{/{f=1}
  f{print}
  /^resolve_canonical_app_path\(\) \{/{r=1}
  r && /^}$/{exit}
' "$TARGET" > "$FUNCS"
source "$FUNCS"
rm -f "$FUNCS"

# Sanity check the extraction actually pulled in all four functions —
# an empty/partial FUNCS file would otherwise make every test below fail for
# the wrong reason (function not found rather than a real logic mismatch).
for _fn in lookup_labels_app_path lookup_known_app_bundle_path register_known_path resolve_canonical_app_path; do
    if ! typeset -f "$_fn" > /dev/null; then
        echo "FATAL: extraction did not capture $_fn() from $TARGET — marker drift?"
        exit 1
    fi
done

# GitHub-Non-Author-Review/PAT-806: lookup_known_app_bundle_path constrains a resolved known_path
# to KNOWN_APP_BUNDLE_ROOTS. Production defaults this in the script's CONFIG
# section, which this harness does not source (it extracts only the resolver
# functions), so establish the production default here. The positive known_path
# tests below point it at $WORKDIR so their sandbox .app fixtures are in-root;
# the negative boundary tests restore/keep the real default to prove rejection.
KNOWN_APP_BUNDLE_ROOTS=(/Applications /Applications/Utilities /System/Applications)

pass=0; fail=0
chk() {  # chk <desc> <expected_path_or_empty> <app_name>
    local desc="$1" exp="$2" app_name="$3" got
    got=$(resolve_canonical_app_path "$app_name")
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc -> ${got:-<empty>}"
    else (( fail++ )); echo "  FAIL: $desc -> got=${got:-<empty>} want=${exp:-<empty>}"; fi
}

# Real directories standing in for installed .app bundles — resolve_canonical_app_path
# and its helpers do a `-d` existence check, so these must exist on disk.
CURATED_BUNDLE="$WORKDIR/CuratedApp.app";      mkdir -p "$CURATED_BUNDLE"
KNOWN_BUNDLE="$WORKDIR/zoom.us.app";           mkdir -p "$KNOWN_BUNDLE"
STALE_BUNDLE="$WORKDIR/WillBeRemoved.app";     mkdir -p "$STALE_BUNDLE"
rmdir "$STALE_BUNDLE"   # existed a moment ago, gone now — simulates a stale/renamed mapping

echo "--- 1. curated allowlist match wins even when known_path is ALSO present"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist.XXXXXX")"
printf 'curatedlabel\tCuratedApp\tTEAMID1234\t%s\tinstalled\t\t\n' "$CURATED_BUNDLE" > "$LABELS_ALLOWLIST"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_PATH_MAP[curatedapp]="$KNOWN_BUNDLE"   # deliberately a DIFFERENT (also-real) path
chk "curated path wins over known_path" "$CURATED_BUNDLE" "CuratedApp"

echo "--- 2. known_path used when curated allowlist has NO match, and the path exists on disk"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty.XXXXXX")"
: > "$LABELS_ALLOWLIST"   # no rows at all — no curated match possible
typeset -gA KNOWN_PATH_MAP=()
KNOWN_APP_BUNDLE_ROOTS=("$WORKDIR")   # sandbox fixtures live directly under $WORKDIR
KNOWN_PATH_MAP[zoom]="$KNOWN_BUNDLE"
chk "known_path resolves the Zoom/zoom.us.app mismatch" "$KNOWN_BUNDLE" "Zoom"

echo "--- 3. falls through (empty result) when known_path is stale/nonexistent on disk"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty2.XXXXXX")"
: > "$LABELS_ALLOWLIST"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_PATH_MAP[willberemoved]="$STALE_BUNDLE"   # directory no longer exists
chk "stale known_path is not trusted — resolves empty (caller falls through to name-guess)" "" "WillBeRemoved"

echo "--- 4. existing behavior unchanged when known_path is entirely absent (no KNOWN_PATH_MAP entry)"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty3.XXXXXX")"
: > "$LABELS_ALLOWLIST"
typeset -gA KNOWN_PATH_MAP=()
chk "no curated row, no known_path -> resolves empty, same as pre-PAT-806" "" "SomeUnknownApp"

echo "--- 5. curated allowlist row present but its path is stale -> known_path still tried (not just 'first match wins')"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-stale.XXXXXX")"
printf 'stalelabel\tStaleCuratedApp\tTEAMID5678\t%s\tinstalled\t\t\n' "$STALE_BUNDLE" > "$LABELS_ALLOWLIST"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_APP_BUNDLE_ROOTS=("$WORKDIR")   # sandbox fixtures live directly under $WORKDIR
KNOWN_PATH_MAP[stalecuratedapp]="$KNOWN_BUNDLE"
chk "stale curated row falls through to known_path" "$KNOWN_BUNDLE" "StaleCuratedApp"

echo "--- 6. case-insensitive name matching preserved for known_path lookup"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty4.XXXXXX")"
: > "$LABELS_ALLOWLIST"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_APP_BUNDLE_ROOTS=("$WORKDIR")   # sandbox fixtures live directly under $WORKDIR
KNOWN_PATH_MAP[mixedcaseapp]="$KNOWN_BUNDLE"
chk "known_path lookup is case-insensitive" "$KNOWN_BUNDLE" "MixedCaseApp"

# --- register_known_path: the queue-parsing gate that feeds KNOWN_PATH_MAP ---
# Found in review: KNOWN_PATH_MAP is keyed by app name ALONE (not
# name+platform). Without this platform gate, a windows-platform queue entry
# sharing a macos entry's app name could overwrite the correct macos path in
# the shared global map for a later lookup of that same name (e.g. from
# run_device_removal_tasks, which runs after the tenant-wide queue loop and
# shares this same map).

echo "--- 7. register_known_path: macos-platform entry IS registered"
typeset -gA KNOWN_PATH_MAP=()
register_known_path "macos" "RegisterApp" "$KNOWN_BUNDLE"
if [[ "${KNOWN_PATH_MAP[registerapp]:-}" == "$KNOWN_BUNDLE" ]]; then
    (( pass++ )); echo "  PASS: macos entry registered -> ${KNOWN_PATH_MAP[registerapp]}"
else
    (( fail++ )); echo "  FAIL: macos entry not registered (got '${KNOWN_PATH_MAP[registerapp]:-<unset>}')"
fi

echo "--- 8. register_known_path: windows-platform entry is NOT registered (cross-platform overwrite guard)"
typeset -gA KNOWN_PATH_MAP=()
register_known_path "windows" "RegisterApp" '/Applications/should-not-be-registered.app'
if [[ -z "${KNOWN_PATH_MAP[registerapp]:-}" ]]; then
    (( pass++ )); echo "  PASS: windows entry not registered"
else
    (( fail++ )); echo "  FAIL: windows entry was registered (got '${KNOWN_PATH_MAP[registerapp]}') — cross-platform overwrite risk"
fi

echo "--- 9. register_known_path: a prior macos registration survives a same-named windows entry processed after it"
typeset -gA KNOWN_PATH_MAP=()
register_known_path "macos" "RegisterApp" "$KNOWN_BUNDLE"
register_known_path "windows" "RegisterApp" '/Applications/should-not-overwrite.app'
if [[ "${KNOWN_PATH_MAP[registerapp]:-}" == "$KNOWN_BUNDLE" ]]; then
    (( pass++ )); echo "  PASS: macos registration survives a later windows entry for the same name"
else
    (( fail++ )); echo "  FAIL: macos registration was overwritten (got '${KNOWN_PATH_MAP[registerapp]:-<unset>}')"
fi

echo "--- 10. register_known_path: empty known_path is a no-op regardless of platform"
typeset -gA KNOWN_PATH_MAP=()
register_known_path "macos" "RegisterApp" ""
if [[ -z "${KNOWN_PATH_MAP[registerapp]:-}" ]]; then
    (( pass++ )); echo "  PASS: empty known_path registers nothing"
else
    (( fail++ )); echo "  FAIL: empty known_path unexpectedly registered '${KNOWN_PATH_MAP[registerapp]}'"
fi

# --- GitHub-Non-Author-Review/PAT-806 boundary: server-supplied known_path must be a
# non-symlink *.app whose parent is EXACTLY one of KNOWN_APP_BUNDLE_ROOTS.
# These prove the security constraint that turns an "uninstall" into a root
# rm -rf: a bad inventory value must resolve EMPTY (fall through), never a
# path outside the app-bundle allowlist. ---

echo "--- 11. boundary: known_path OUTSIDE the configured roots resolves empty (rejected)"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty5.XXXXXX")"
: > "$LABELS_ALLOWLIST"
KNOWN_APP_BUNDLE_ROOTS=(/Applications /Applications/Utilities /System/Applications)  # real default
EVIL_BUNDLE="$WORKDIR/Evil.app"; mkdir -p "$EVIL_BUNDLE"   # exists, is a .app, but wrong root
typeset -gA KNOWN_PATH_MAP=()
KNOWN_PATH_MAP[evilapp]="$EVIL_BUNDLE"
chk "known_path outside allowed roots is rejected" "" "EvilApp"

echo "--- 12. boundary: symlink known_path (even to a valid in-root .app) is rejected"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty6.XXXXXX")"
: > "$LABELS_ALLOWLIST"
KNOWN_APP_BUNDLE_ROOTS=("$WORKDIR")   # parent IS in-root, so only the symlink check can reject
SYMTARGET="$WORKDIR/SymTarget.app"; mkdir -p "$SYMTARGET"
SYMLINK="$WORKDIR/SymLink.app"; ln -s "$SYMTARGET" "$SYMLINK"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_PATH_MAP[symlinkapp]="$SYMLINK"
chk "symlink known_path is rejected" "" "SymlinkApp"

echo "--- 13. boundary: nested known_path (parent != configured root) is rejected (maxdepth-1)"
LABELS_ALLOWLIST="$(mktemp "$WORKDIR/labels-allowlist-empty7.XXXXXX")"
: > "$LABELS_ALLOWLIST"
KNOWN_APP_BUNDLE_ROOTS=("$WORKDIR")   # nested parent is $WORKDIR/sub, not $WORKDIR itself
NESTED_BUNDLE="$WORKDIR/sub/Nested.app"; mkdir -p "$NESTED_BUNDLE"
typeset -gA KNOWN_PATH_MAP=()
KNOWN_PATH_MAP[nestedapp]="$NESTED_BUNDLE"
chk "nested known_path is rejected" "" "NestedApp"

# --- PAT-855: is_safe_app_name — reject any server-supplied app_name that
# could escape a path via a separator or traversal sequence BEFORE it is used
# in ANY path construction. execute_uninstall_macos's app_bundle support-path
# loop interpolates app_name directly into rm -rf targets run as root; this
# guard is what stands between a crafted name and that loop. ---

SAFE_FUNC="$(mktemp /tmp/.patched-uninstall-safe-funcs.XXXXXX)"
awk '/^is_safe_app_name\(\) \{/{f=1} f{print} f && /^}$/{exit}' "$TARGET" > "$SAFE_FUNC"
source "$SAFE_FUNC"
rm -f "$SAFE_FUNC"

if ! typeset -f is_safe_app_name > /dev/null; then
    echo "FATAL: extraction did not capture is_safe_app_name() from $TARGET — marker drift?"
    exit 1
fi

chk_safe() {  # chk_safe <desc> <expect: safe|unsafe> <app_name>
    local desc="$1" expect="$2" name="$3" got
    if is_safe_app_name "$name"; then got=safe; else got=unsafe; fi
    if [[ "$got" == "$expect" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> is_safe_app_name says $got, want $expect"; fi
}

echo "--- 14. is_safe_app_name: multi-segment traversal to an /etc-style target is rejected"
chk_safe "../../../../private/etc rejected" unsafe "../../../../private/etc"

echo "--- 15. is_safe_app_name: traversal mixed with plausible-looking segments is rejected"
chk_safe "foo/../../bar rejected" unsafe "foo/../../bar"

echo "--- 16. is_safe_app_name: a bare path separator is rejected"
chk_safe "a/b rejected" unsafe "a/b"

echo "--- 17. is_safe_app_name: a normal app name is still accepted"
chk_safe "Google Chrome accepted" safe "Google Chrome"

echo "--- 18. is_safe_app_name: an empty name is rejected"
chk_safe "empty name rejected" unsafe ""

echo "--- 19. is_safe_app_name: a backslash is rejected"
chk_safe "backslash rejected" unsafe 'evil\name'

echo "--- 20. is_safe_app_name: shell/glob metacharacters outside the allowlist are rejected"
chk_safe "semicolon-and-shell-command rejected" unsafe 'x; rm -rf /'

echo "--- 21. is_safe_app_name: names with dots/hyphens/plus (real vendor names) are still accepted"
chk_safe "Adobe Acrobat Reader DC accepted" safe "Adobe Acrobat Reader DC"
chk_safe "1Password 7 - Password Manager accepted" safe "1Password 7 - Password Manager"

echo "--- 22. is_safe_app_name: a lone '.' is rejected (collapses onto the parent dir when interpolated)"
chk_safe "single dot rejected" unsafe "."

echo "--- 23. is_safe_app_name: an all-space name is rejected (strips to empty via safe_name, same collapse)"
chk_safe "all-space name rejected" unsafe "   "

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
