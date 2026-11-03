#!/usr/bin/env bash
# PAT-2053: READ-ONLY schema drift check for patched-api-01.
#
# Compares a normalised fingerprint of the live database with the fingerprint
# the migrations produce at the live database's own recorded head, using the
# journal CI builds (schema_drift.py build-journal) and the allowlist of
# accepted differences. Meant to run before deploy.sh applies migrations, so a
# drifted table stops the deploy before anything is written.
#
# It never writes: every query runs in a session whose transactions are forced
# read-only (default_transaction_read_only=on), and the fingerprint is a pure
# catalogue SELECT. It never prints DATABASE_URL.
#
# Usage:
#   schema-drift-check.sh --journal FILE [--allowlist FILE] [--env-file FILE]
#
# DATABASE_URL is taken from the environment when set (deploy.sh already holds
# it), otherwise parsed from --env-file (default /etc/patched-api/env) by
# reading the single DATABASE_URL= line. The env file is never sourced.
#
# Exit: 0 clean, 1 unexplained drift, 2 refused (could not compare).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
journal=""
allowlist="$here/schema-drift-allowlist.txt"
env_file="/etc/patched-api/env"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --journal) journal="${2:-}"; shift 2 ;;
    --allowlist) allowlist="${2:-}"; shift 2 ;;
    --env-file) env_file="${2:-}"; shift 2 ;;
    *) echo "schema-drift-check: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$journal" && -f "$journal" ]] || { echo "schema-drift-check: --journal FILE is required and must exist" >&2; exit 2; }
[[ -f "$allowlist" ]] || { echo "schema-drift-check: allowlist not found: $allowlist" >&2; exit 2; }

if [[ -z "${DATABASE_URL:-}" ]]; then
  [[ -r "$env_file" ]] || { echo "schema-drift-check: DATABASE_URL unset and $env_file is not readable" >&2; exit 2; }
  matches="$(grep -c '^DATABASE_URL=' "$env_file" || true)"
  [[ "$matches" == "1" ]] || { echo "schema-drift-check: $env_file must hold exactly one DATABASE_URL line" >&2; exit 2; }
  DATABASE_URL="$(grep '^DATABASE_URL=' "$env_file" | cut -d= -f2- | tr -d '"')"
  [[ "$DATABASE_URL" =~ ^postgres(ql)?:// ]] || { echo "schema-drift-check: DATABASE_URL in $env_file is not a postgres URL" >&2; exit 2; }
fi
export DATABASE_URL

exec python3 "$here/schema_drift.py" check --journal "$journal" --allowlist "$allowlist" --dsn-env DATABASE_URL
