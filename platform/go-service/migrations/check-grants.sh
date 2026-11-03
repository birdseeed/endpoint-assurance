#!/usr/bin/env bash
# CI guard (M-INFRA-3 / PAT-579, PAT-603): every migration that creates a table
# or a sequence must GRANT the needed privileges to the `patched` app role in
# the SAME file. Missing GRANTs have caused production 500s ("permission
# denied") twice.
#
# Enforced for migrations numbered above the baseline; older files are
# legacy-exempt and covered by the catch-up migration
# 0057_grant_all_to_patched.sql. New migrations must carry their own grant.
set -euo pipefail

MIG_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE=56   # enforce on 0056 and later
fail=0

for f in "$MIG_DIR"/*.sql; do
    base="$(basename "$f")"
    case "$base" in
        *_rollback.sql) continue ;;
    esac

    ver="$(printf '%s' "$base" | sed -E 's/^0*([0-9]+)_.*/\1/')"
    case "$ver" in
        ''|*[!0-9]*) continue ;;   # not a NNNN_ file
    esac
    [ "$ver" -lt "$BASELINE" ] && continue

    # Non-partition table creation, or sequence creation, needs a grant.
    # (Partitions of an existing parent are reached via the parent's grants.)
    creates="$(grep -iE 'CREATE (TABLE|SEQUENCE)' "$f" | grep -viE 'PARTITION OF' || true)"
    [ -z "$creates" ] && continue

    if ! grep -qiE 'GRANT[[:space:]].*TO[[:space:]]+patched' "$f"; then
        echo "ERROR: $base creates a table/sequence but has no 'GRANT ... TO patched;'"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "Migration GRANT check FAILED — add 'GRANT ... TO patched;' for the new table(s)/sequence(s)."
    exit 1
fi
echo "Migration GRANT check passed."
