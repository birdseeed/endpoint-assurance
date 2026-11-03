#!/usr/bin/env bash
# Resolve the one strict numeric menu-bar release version into the two plist
# settings used by both applications. CFBundleVersion accepts dot-separated
# numeric components; keeping the X.Y.Z release value unchanged preserves the
# same component-wise ordering for marketing and build metadata.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
    echo "usage: $0 X.Y.Z" >&2
    exit 64
fi

release_version="$1"

# Release tags and manual releases share this boundary. Leading zeroes and
# suffixes would make ordering ambiguous, so reject them before any archive
# work or release publication begins.
if ! [[ "$release_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "invalid menu-bar release version '$release_version': expected numeric X.Y.Z" >&2
    exit 65
fi

printf '%s\n' \
    "version=$release_version" \
    "bundle_version=$release_version"
