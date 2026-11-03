#!/bin/bash
# tools/build-pkg.sh — build the Patched Updater endpoint .pkg from dist/patched-updater.
#
# Usage:
#   bash tools/build-pkg.sh --version 1.0.0 --pkg patched-updater-1.0.0.pkg [--sign IDENTITY]
#
# Without --sign, produces an unsigned .pkg (CI dry-runs before PAT-7 lands).
# With --sign, the identity is passed straight to pkgbuild and must match a
# Developer ID Installer cert in the active keychain. CI passes the 10-char
# Apple Team ID ($APPLE_TEAM_ID), which uniquely matches the cert by its CN
# substring — so the signing account transfer is a pure secret swap, with no
# hardcoded org name. A full identity string ("Developer ID Installer: <Org>
# (TEAMID)") also works if you need to disambiguate multiple certs.
#
# Prereq: run tools/build-bundle.sh first to populate dist/patched-updater/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=""
PKG_OUTPUT=""
SIGN_IDENTITY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --pkg)     PKG_OUTPUT="$2"; shift 2 ;;
        --sign)    SIGN_IDENTITY="$2"; shift 2 ;;
        *)         echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$VERSION" || -z "$PKG_OUTPUT" ]]; then
    echo "Usage: $0 --version VERSION --pkg OUTPUT.pkg [--sign IDENTITY]" >&2
    exit 1
fi

BUNDLE_DIR="$REPO_ROOT/dist/patched-updater"
SCRIPTS_DIR="$REPO_ROOT/tools/pkg-scripts"

if [[ ! -d "$BUNDLE_DIR" ]]; then
    echo "ERROR: $BUNDLE_DIR not found. Run tools/build-bundle.sh first." >&2
    exit 1
fi

if [[ ! -x "$SCRIPTS_DIR/postinstall" ]]; then
    echo "ERROR: $SCRIPTS_DIR/postinstall not found or not executable." >&2
    exit 1
fi

PKGBUILD_ARGS=(
    --root              "$BUNDLE_DIR"
    --install-location  /usr/local/patched-updater
    --identifier        com.patched.updater
    --version           "$VERSION"
    --scripts           "$SCRIPTS_DIR"
)

if [[ -n "$SIGN_IDENTITY" ]]; then
    PKGBUILD_ARGS+=(--sign "$SIGN_IDENTITY" --timestamp)
    echo "Signing with: $SIGN_IDENTITY"
else
    echo "No signing identity supplied — building unsigned .pkg."
fi

pkgbuild "${PKGBUILD_ARGS[@]}" "$PKG_OUTPUT"

echo ""
echo "=== Built: $PKG_OUTPUT ==="
pkgutil --payload-files "$PKG_OUTPUT" | head -20
