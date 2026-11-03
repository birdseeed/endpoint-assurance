#!/usr/bin/env bash
# Synthetic only: no inherited DB URLs or production services are used.
set -euo pipefail
cd "$(dirname "$0")/.."
pg_bin="${PAT2369_PG_BIN:-/opt/homebrew/opt/postgresql@16/bin}"
for tool in postgres initdb pg_ctl psql pg_dump pg_restore; do
  test -x "$pg_bin/$tool" || { echo "missing PostgreSQL tool: $pg_bin/$tool" >&2; exit 1; }
done
cluster=$(mktemp -d /tmp/pat2369-pg.XXXXXX)
cleanup() {
  "$pg_bin/pg_ctl" -D "$cluster/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$cluster"
}
trap cleanup EXIT
mkdir "$cluster/socket"
"$pg_bin/initdb" -D "$cluster/data" -A trust --no-locale >/dev/null
# Private mode-0700 socket directory and no TCP listener; another cluster cannot
# collide with this socket even when it uses the same port number.
"$pg_bin/pg_ctl" -D "$cluster/data" -l "$cluster/postgres.log" -o "-k $cluster/socket -p 5432 -c listen_addresses=''" -w start >/dev/null
"$pg_bin/psql" -h "$cluster/socket" -d postgres -v ON_ERROR_STOP=1 -c 'CREATE ROLE patched' -c 'CREATE DATABASE lifecycle' -c 'CREATE DATABASE restored' >/dev/null
export TEST_DATABASE_URL="postgresql:///lifecycle?host=$cluster/socket"
export PAT2369_RESTORE_DATABASE_URL="postgresql:///restored?host=$cluster/socket"
export PAT2369_PRIVATE_CLUSTER=1 PAT2369_PG_BIN="$pg_bin"
export TMPDIR="$cluster"
unset PATCHED_KEK
go test -tags integration ./integration -run '^(TestCustomerLifecycleReadiness|TestTenantExport)$' -count=1 -v
go test ./internal/handlers -run '^(TestTenantLifecycleDB|TestQuarantine.*|TestAssessmentPurge.*|TestPurge.*|TestTenantPurgeDBTimeoutConfiguration)$' -count=1 -v
