#!/usr/bin/env bash
# CI guard — migration hygiene, forward-only (M: migration hygiene).
#
# We do NOT rewrite already-applied migration history: versions 0025/0033/0036/
# 0037/0040 have duplicate numbers, and several early files omit a transaction
# wrapper or a schema_migrations insert. Those are grandfathered. This guard
# enforces the conventions on NEW migrations (version > baseline) so the mess
# does not grow:
#
#   1. Unique version number — no new migration may reuse an NNNN_ prefix that
#      already exists anywhere in the directory.
#   2. Transaction-wrapped — must contain BEGIN and COMMIT.
#   3. Bookkeeping — must INSERT its version into schema_migrations.
#
# See migrations/README.md for the full convention.
set -euo pipefail

MIG_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE=55   # files with version > 55 are "new" and must obey the conventions
fail=0

# All existing version prefixes (non-rollback), for duplicate detection.
# printf on the glob (not `ls`) keeps shellcheck happy and handles odd names.
all_versions="$(printf '%s\n' "$MIG_DIR"/*.sql | grep -vE '_rollback\.sql$' | sed -E 's#.*/([0-9]+)_.*#\1#')"

for f in "$MIG_DIR"/*.sql; do
    base="$(basename "$f")"
    case "$base" in
        *_rollback.sql) continue ;;
    esac

    ver="$(printf '%s' "$base" | sed -E 's/^0*([0-9]+)_.*/\1/')"
    verpref="$(printf '%s' "$base" | sed -E 's/^([0-9]+)_.*/\1/')"
    case "$ver" in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$ver" -le "$BASELINE" ] && continue

    # 1. Unique version number.
    count="$(printf '%s\n' "$all_versions" | grep -cx "$verpref" || true)"
    if [ "$count" -gt 1 ]; then
        echo "ERROR: $base reuses migration version $verpref (must be unique)."
        fail=1
    fi

    # 2. Transaction-wrapped.
    if ! grep -qiE '^[[:space:]]*BEGIN[[:space:]]*;' "$f" || ! grep -qiE '^[[:space:]]*COMMIT[[:space:]]*;' "$f"; then
        echo "ERROR: $base must be wrapped in BEGIN; ... COMMIT;"
        fail=1
    fi

    # 3. schema_migrations bookkeeping.
    if ! grep -qiE 'INSERT[[:space:]]+INTO[[:space:]]+schema_migrations' "$f"; then
        echo "ERROR: $base must INSERT its version INTO schema_migrations."
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "Migration hygiene check FAILED — see migrations/README.md."
    exit 1
fi
echo "Migration hygiene check passed."
