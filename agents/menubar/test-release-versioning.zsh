#!/bin/zsh
##############################################################################
# test-release-versioning.zsh — PAT-1229 menu-bar release metadata gate.
#
# Exercises the actual XcodeGen/Xcode metadata path used by release-menubar:
# resolve a sentinel release version, build the real application with its
# settings, and inspect the resulting app Info.plist. Invalid tag forms must
# fail before an archive can be made.
#
# Run: zsh menubar/test-release-versioning.zsh
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
RESOLVER="$SCRIPT_DIR/resolve-release-version.sh"
METADATA_VERIFIER="$SCRIPT_DIR/verify-release-metadata.sh"
RELEASE_WORKFLOW="$SCRIPT_DIR/../.github/workflows/release-menubar.yml"
SENTINEL_VERSION="97.41.3"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/patched-menubar-version-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then
        (( pass++ ))
        echo "  PASS: $desc"
    else
        (( fail++ ))
        echo "  FAIL: $desc"
    fi
}

expect_failure() {
    local version="$1" output="$WORK/invalid-$RANDOM.log"
    if "$RESOLVER" "$version" > "$output" 2>&1; then
        chk "invalid version '$version' exits non-zero" 0
    else
        chk "invalid version '$version' exits non-zero" 1
        chk "invalid version '$version' reports validation failure" \
            "$(grep -qF 'expected numeric X.Y.Z' "$output" && echo 1 || echo 0)"
    fi
}

plist_value() {
    local plist="$1" key="$2"
    /usr/libexec/PlistBuddy -c "Print :$key" "$plist"
}

echo "[1] resolve strict release metadata"
resolved=$("$RESOLVER" "$SENTINEL_VERSION")
chk "resolver emits the exact marketing version" \
    "$(print -r -- "$resolved" | grep -qxF "version=$SENTINEL_VERSION" && echo 1 || echo 0)"
chk "resolver emits a deterministic monotonic bundle version" \
    "$(print -r -- "$resolved" | grep -qxF "bundle_version=$SENTINEL_VERSION" && echo 1 || echo 0)"
chk "release workflow invokes the shared strict resolver" \
    "$(grep -qF 'menubar/resolve-release-version.sh "$V"' "$RELEASE_WORKFLOW" && echo 1 || echo 0)"
chk "release workflow passes both version settings to every archive" \
    "$([[ "$(grep -cF 'MARKETING_VERSION="$RELEASE_MARKETING_VERSION"' "$RELEASE_WORKFLOW")" == "2" && "$(grep -cF 'CURRENT_PROJECT_VERSION="$RELEASE_BUNDLE_VERSION"' "$RELEASE_WORKFLOW")" == "2" ]] && echo 1 || echo 0)"
chk "release workflow verifies staged app metadata before packaging" \
    "$(grep -qF 'menubar/verify-release-metadata.sh "$STAGE" "$V" "$BUNDLE_VERSION"' "$RELEASE_WORKFLOW" && echo 1 || echo 0)"

echo "[2] invalid release versions fail before builds"
expect_failure 01.2.3
expect_failure 1.2
expect_failure 1.2.3-rc1

echo "[3] the real app bundle receives the release metadata"
cd "$SCRIPT_DIR"
xcodegen generate > "$WORK/xcodegen.log"
stage="$WORK/release-stage"
mkdir -p "$stage"

scheme=PatchedUpdater
xcodebuild \
    -project PatchedUpdater.xcodeproj \
    -scheme "$scheme" \
    -configuration Release \
    -derivedDataPath "$WORK/DerivedData" \
    build \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGNING_ALLOWED=NO \
    MARKETING_VERSION="$SENTINEL_VERSION" \
    CURRENT_PROJECT_VERSION="$SENTINEL_VERSION" \
    > "$WORK/$scheme.log"

app="$WORK/DerivedData/Build/Products/Release/$scheme.app"
plist="$app/Contents/Info.plist"
chk "$scheme app bundle exists" "$(test -f "$plist" && echo 1 || echo 0)"
chk "$scheme CFBundleShortVersionString is the release version" \
    "$([[ "$(plist_value "$plist" CFBundleShortVersionString)" == "$SENTINEL_VERSION" ]] && echo 1 || echo 0)"
chk "$scheme CFBundleVersion is the deterministic release build version" \
    "$([[ "$(plist_value "$plist" CFBundleVersion)" == "$SENTINEL_VERSION" ]] && echo 1 || echo 0)"
cp -R "$app" "$stage/$scheme.app"

if "$METADATA_VERIFIER" "$stage" "$SENTINEL_VERSION" "$SENTINEL_VERSION" > "$WORK/verify.log" 2>&1; then
    chk "staged release metadata verification succeeds" 1
else
    chk "staged release metadata verification succeeds" 0
    cat "$WORK/verify.log"
fi

/usr/libexec/PlistBuddy -c 'Set :CFBundleShortVersionString 0.0.1' \
    "$stage/PatchedUpdater.app/Contents/Info.plist"
if "$METADATA_VERIFIER" "$stage" "$SENTINEL_VERSION" "$SENTINEL_VERSION" > "$WORK/mismatch.log" 2>&1; then
    chk "mismatched staged app metadata fails before packaging" 0
else
    chk "mismatched staged app metadata fails before packaging" 1
    chk "mismatched staged app metadata reports the mismatch" \
        "$(grep -qF 'PatchedUpdater version mismatch' "$WORK/mismatch.log" && echo 1 || echo 0)"
fi

echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
