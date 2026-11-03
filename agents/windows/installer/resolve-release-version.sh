#!/usr/bin/env bash
# Maps the Windows release tag version to the version representations consumed
# by the MSI and .NET publish steps. Keep this as the single release boundary:
# Windows Installer compares only the first three numeric fields.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 X.Y.Z full-commit-sha" >&2
  exit 64
fi

release_version=$1
commit_sha=$2

# MSI ProductVersion accepts exactly three numeric fields. Its first two fields
# are limited to 255 and its final field to 65535. Beta tags X.Y.Z-beta.N map
# to installable identity X.Y.Z.N; stable promotion retains that identity.
#
# The old MSI was permanently stamped 1.0.0. Reserve the first two MSI major
# versions as installer epochs and map semantic X.Y.Z to MSI (X + 2).Y.(Z*100).
# This makes every accepted semantic version newer than the legacy MSI while
# preserving its ordering for all future releases. Reserve 100 MSI patch
# values per semantic patch: X.Y.Z maps to (X+2).Y.(Z*100), while beta N maps
# to (X+2).Y.(Z*100+N), for N=1..99. Thus revisions order strictly and the
# next base patch is greater than every beta revision. This is collision-free
# but bounds semantic patch Z to 654 (654*100+99=65499); the existing +2 epoch
# and AssemblyVersion/FileVersion fourth-field convention remain intact.
# AssemblyVersion and FileVersion use the same epoch so Windows Installer can replace the legacy
# 1.0.0.0 binaries before RemoveExistingProducts. InformationalVersion keeps
# the installable identity and commit provenance.
channel=stable
if [[ "$release_version" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})-beta\.([1-9][0-9]?)$ ]]; then
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; revision=${BASH_REMATCH[4]}
  release_version="$major.$minor.$patch.$revision"
  channel=beta
elif [[ "$release_version" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.([1-9][0-9]?)$ ]]; then
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; revision=${BASH_REMATCH[4]}
  channel=beta
elif [[ "$release_version" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]]; then
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; revision=0
else
  echo "invalid release version '$release_version': expected X.Y.Z or X.Y.Z-beta.N (1..99)" >&2
  exit 65
fi

if [ "$major" -gt 253 ] || [ "$minor" -gt 255 ] || { [ "$channel" = beta ] && [ "$patch" -gt 654 ]; } || { [ "$channel" = stable ] && [ "$patch" -gt 655 ]; }; then
  echo "invalid release version '$release_version': exceeds encoded MSI limits (253.255.655; beta patch max 654, revision max 99)" >&2
  exit 65
fi

msi_major=$((major + 2))
msi_patch=$((patch * 100 + revision))

if ! [[ "$commit_sha" =~ ^[0-9A-Fa-f]{40}$ ]]; then
  echo "invalid commit SHA: expected the full 40-character Git SHA" >&2
  exit 65
fi

printf '%s\n' \
  "version=$release_version" \
  "channel=$channel" \
  "tag_version=$1" \
  "msi_product_version=$msi_major.$minor.$msi_patch" \
  "file_version=$msi_major.$minor.$msi_patch.0" \
  "informational_version=$release_version+$commit_sha"
