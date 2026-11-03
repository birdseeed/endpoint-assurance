#!/bin/sh
# sync-brand.sh — vendor the Patched brand kit from Patched-LTD/branding.
#
# Usage:
#   ./sync-brand.sh [dest-dir]
#
# Environment variables:
#   REF          git ref to fetch (tag, branch, or SHA).
#                  Defaults to the version recorded in an already-vendored
#                  kit/VERSION (as "brand-vX.Y.Z"), then falls back to "main".
#                  For reproducible builds always set REF explicitly, e.g.:
#                    REF=brand-v1.0.0 ./sync-brand.sh
#   DEST         destination directory (overrides the positional argument).
#                  Defaults to "vendor/brand".
#   BRAND_REPO   SSH or HTTPS URL of the branding repository.
#                  Defaults to git@github.com:Patched-LTD/branding.git
#
# Examples:
#   REF=brand-v1.0.0 ./sync-brand.sh
#   REF=brand-v1.0.0 ./sync-brand.sh static/brand
#   BRAND_REPO=https://github.com/Patched-LTD/branding.git REF=brand-v1.0.0 ./sync-brand.sh

set -eu

DEST="${1:-${DEST:-vendor/brand}}"
BRAND_REPO="${BRAND_REPO:-git@github.com:Patched-LTD/branding.git}"

# Determine REF: explicit env var → existing vendored VERSION → "main"
if [ -z "${REF:-}" ]; then
  if [ -f "$DEST/VERSION" ]; then
    REF="brand-v$(cat "$DEST/VERSION" | tr -d '[:space:]')"
    echo "sync-brand: no REF set — reusing vendored version $REF"
  else
    REF=main
    echo "sync-brand: no REF set and no existing $DEST/VERSION — defaulting to main"
    echo "sync-brand: (for reproducible builds set REF=brand-vX.Y.Z)"
  fi
fi

# Require git
if ! command -v git > /dev/null 2>&1; then
  echo "sync-brand: error: git not found in PATH" >&2
  exit 1
fi

# Portable temp directory
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT INT TERM

echo "sync-brand: cloning ref '$REF' from $BRAND_REPO …"

# Shallow-clone the requested ref into a temp directory.
# Works with branches, lightweight tags, and annotated tags.
if ! git clone --quiet --depth 1 --branch "$REF" -- "$BRAND_REPO" "$tmpdir/branding" 2>&1; then
  echo "sync-brand: error: could not clone ref '$REF' from $BRAND_REPO" >&2
  echo "sync-brand: verify the ref exists (git ls-remote $BRAND_REPO refs/tags/$REF)" >&2
  exit 1
fi

# Sanity-check that kit/ is present in the cloned tree
if [ ! -d "$tmpdir/branding/kit" ]; then
  echo "sync-brand: error: kit/ directory not found in ref '$REF' — is this the right branch/tag?" >&2
  exit 1
fi

# Idempotent: remove the old vendored tree and copy the fresh one.
rm -rf "$DEST"
mkdir -p "$DEST"

cp -r "$tmpdir/branding/kit/." "$DEST/"

echo "sync-brand: done — brand kit written to $DEST/ (ref: $REF)"
echo "sync-brand: kit version: $(cat "$DEST/VERSION" | tr -d '[:space:]')"
