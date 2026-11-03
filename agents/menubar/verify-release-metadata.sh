#!/usr/bin/env bash
# Verify the staged menu-bar application carries the metadata resolved for
# this release. Called before the archive is zipped, signed, or published.
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
    echo "usage: $0 STAGE_DIR MARKETING_VERSION BUNDLE_VERSION" >&2
    exit 64
fi

stage_dir="$1"
marketing_version="$2"
bundle_version="$3"

app_name="PatchedUpdater"
app_plist="$stage_dir/$app_name.app/Contents/Info.plist"
if [[ ! -f "$app_plist" ]]; then
    echo "ERROR: $app_name archive has no Info.plist at $app_plist" >&2
    exit 1
fi

short_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app_plist")
actual_build_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app_plist")
if [[ "$short_version" != "$marketing_version" || "$actual_build_version" != "$bundle_version" ]]; then
    echo "ERROR: $app_name version mismatch: expected short=$marketing_version build=$bundle_version; got short=$short_version build=$actual_build_version" >&2
    exit 1
fi
echo "Verified $app_name metadata: short=$short_version build=$actual_build_version"
