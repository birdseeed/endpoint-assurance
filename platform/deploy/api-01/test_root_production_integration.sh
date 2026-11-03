#!/usr/bin/env bash
# Linux/root fixed-path integration inside a disposable, unprivileged container.
set -euo pipefail
# Say where a failure happened. Most assertions below are bare `[[ ... ]]`, which
# exit non-zero silently under set -e, so without this the CI log shows only
# "exit code 1". An EXIT trap rather than ERR: several steps deliberately capture
# an expected failure under `set +e`, and ERR would report those as failures.
report_failure() {
  local rc=$?
  [[ "$rc" -eq 0 ]] || echo "root production integration FAILED (exit ${rc}) at line ${LINENO}: ${BASH_COMMAND}" >&2
}
trap report_failure EXIT
[[ "$(uname -s)" == Linux ]] || { echo "root production integration skipped: Linux required"; exit 0; }
[[ "$EUID" -eq 0 ]] || { echo "root production integration requires root" >&2; exit 1; }
[[ "${PATCHED_ROOT_HARNESS_CONTAINER:-}" == "1" && -f /.dockerenv ]] || {
  echo "root production integration must run in the disposable CI container" >&2
  exit 1
}
[[ -c /dev/null && "$(stat -c '%t:%T' /dev/null)" == "1:3" ]] || {
  echo "container /dev/null is not the expected character device" >&2
  exit 1
}

# The container itself is the disposable root filesystem. It has no host
# mounts except the read-only checkout and receives no Linux capabilities.
ROOTFS=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$ROOTFS"/{bin,usr/bin,opt,etc,fakes,dev,root} "$ROOTFS/etc/systemd/system"
mkdir -p "$ROOTFS/opt/patched-api/bin" "$ROOTFS/opt/patched-extractor/bin" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync" \
  "$ROOTFS/opt/patched-deploy-staging/migrations" \
  "$ROOTFS/opt/patched-emergency-api" "$ROOTFS/etc/patched-api"
printf 'DATABASE_URL=postgres://integration\n' > "$ROOTFS/etc/patched-api/env"

# Bootstrap runs first on a clean host. Its staged binary is bound to the
# explicit checkout SHA by the same CI manifest format as production deploy.
printf bootstrap-cve > "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync"
cp "$REPO_ROOT/api-vps-artefacts/patched-cve-sync.service" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service"
# The real unit is staged unmodified. bootstrap-cve-sync.sh requires ExecStart to
# be exactly "<managed binary> --mode=scheduled" (PAT-1918), so rewriting it to
# add a test argument, as this harness did under the older executable-token-only
# rule, is rejected before the bootstrap reaches its install and rollback phases
# and none of the assertions below that depend on those phases can pass.
cp "$REPO_ROOT/api-vps-artefacts/patched-cve-sync.timer" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.timer"
cp "$REPO_ROOT/deploy/api-01/bootstrap-cve-sync.sh" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh"
bootstrap_hash="$(sha256sum "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync" | awk '{print $1}')"
{
  printf 'GITHUB_SHA=%040d\n' 1
  printf '%s  patched-cve-sync\n' "$bootstrap_hash"
} > "$ROOTFS/opt/patched-bootstrap-cve-sync/BINARY_MANIFEST"
chmod 0755 "$ROOTFS/opt/patched-bootstrap-cve-sync" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh"
chmod 0644 "$ROOTFS/opt/patched-bootstrap-cve-sync/BINARY_MANIFEST" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.timer"

printf old-api > "$ROOTFS/opt/patched-api/bin/patched-api"
printf old-extractor > "$ROOTFS/opt/patched-extractor/bin/patched-extractor"
printf 'old-receipt\n' > "$ROOTFS/opt/patched-api/DEPLOYED_BINARIES"
printf new-api > "$ROOTFS/opt/patched-deploy-staging/patched-api"
printf new-extractor > "$ROOTFS/opt/patched-deploy-staging/patched-extractor"
printf new-cve > "$ROOTFS/opt/patched-deploy-staging/patched-cve-sync"
printf 'SELECT 1;\n' > "$ROOTFS/opt/patched-deploy-staging/migrations/0105_test_migration.sql"
chmod 0755 "$ROOTFS/opt/patched-api" "$ROOTFS/opt/patched-api/bin" "$ROOTFS/opt/patched-extractor" \
  "$ROOTFS/opt/patched-extractor/bin" "$ROOTFS/opt/patched-api/bin/"* \
  "$ROOTFS/opt/patched-extractor/bin/"* "$ROOTFS/opt/patched-deploy-staging/"patched-*
cp "$REPO_ROOT/deploy/api-01/deploy.sh" "$ROOTFS/opt/patched-deploy-staging/deploy.sh"
cp "$REPO_ROOT/deploy/api-01/verify-systemd-hardening-floor.sh" \
  "$ROOTFS/opt/patched-deploy-staging/verify-systemd-hardening-floor.sh"
api_hash="$(sha256sum "$ROOTFS/opt/patched-deploy-staging/patched-api" | awk '{print $1}')"
extractor_hash="$(sha256sum "$ROOTFS/opt/patched-deploy-staging/patched-extractor" | awk '{print $1}')"
cve_hash="$(sha256sum "$ROOTFS/opt/patched-deploy-staging/patched-cve-sync" | awk '{print $1}')"
migration_hash="$(sha256sum "$ROOTFS/opt/patched-deploy-staging/migrations/0105_test_migration.sql" | awk '{print $1}')"
# PAT-2062: manifest-bound stand-ins for the schema drift check. The stub proves
# root mode hands the check the parsed DATABASE_URL and runs it before migrations.
for drift_file in SCHEMA_FINGERPRINT_JOURNAL schema_drift.py schema_fingerprint.sql schema-drift-allowlist.txt; do
  printf 'stub %s\n' "$drift_file" > "$ROOTFS/opt/patched-deploy-staging/$drift_file"
done
cat > "$ROOTFS/opt/patched-deploy-staging/schema-drift-check.sh" <<'EOF'
#!/bin/bash
[[ "${DATABASE_URL:-}" == postgres://integration ]] || { echo "REFUSED: DATABASE_URL was not passed"; exit 2; }
[[ ! -s /opt/psql-integration.log ]] || { echo "REFUSED: psql ran before the drift check"; exit 2; }
echo "OK: live schema matches the migrations"
EOF
chmod 0644 "$ROOTFS/opt/patched-deploy-staging/"SCHEMA_FINGERPRINT_JOURNAL "$ROOTFS/opt/patched-deploy-staging/"schema*
{
  printf 'GITHUB_SHA=%040d\n' 1
  printf 'MIGRATION_HEAD=0105_test_migration\n'
  printf '%s  patched-api\n%s  patched-extractor\n%s  patched-cve-sync\n' "$api_hash" "$extractor_hash" "$cve_hash"
  printf '%s  migration:0105_test_migration.sql\n' "$migration_hash"
  (cd "$ROOTFS/opt/patched-deploy-staging" && sha256sum SCHEMA_FINGERPRINT_JOURNAL schema_drift.py \
    schema_fingerprint.sql schema-drift-check.sh schema-drift-allowlist.txt) | sed 's#  #  schema-drift:#'
} > "$ROOTFS/opt/patched-deploy-staging/BINARY_MANIFEST"
chmod 0755 "$ROOTFS/opt/patched-deploy-staging" \
  "$ROOTFS/opt/patched-deploy-staging/verify-systemd-hardening-floor.sh"
chmod 0644 "$ROOTFS/opt/patched-deploy-staging/BINARY_MANIFEST" \
  "$ROOTFS/opt/patched-deploy-staging/migrations/0105_test_migration.sql"

# Prepare the fixed-path break-glass staging set before normal deploy cleanup
# removes only /opt/patched-deploy-staging.
printf emergency-api > "$ROOTFS/opt/patched-emergency-api/patched-api"
cp "$REPO_ROOT/deploy/api-01/emergency-api-only.sh" \
  "$ROOTFS/opt/patched-emergency-api/emergency-api-only.sh"
emergency_hash="$(sha256sum "$ROOTFS/opt/patched-emergency-api/patched-api" | awk '{print $1}')"
{
  printf 'GITHUB_SHA=%040d\n' 1
  printf 'MIGRATION_HEAD=0105_test_migration\n'
  printf '%s  patched-api\n%s  patched-extractor\n%s  patched-cve-sync\n' \
    "$emergency_hash" "$extractor_hash" "$cve_hash"
} > "$ROOTFS/opt/patched-emergency-api/BINARY_MANIFEST"
chmod 0755 "$ROOTFS/opt/patched-emergency-api" \
  "$ROOTFS/opt/patched-emergency-api/patched-api" \
  "$ROOTFS/opt/patched-emergency-api/emergency-api-only.sh"
chmod 0644 "$ROOTFS/opt/patched-emergency-api/BINARY_MANIFEST"

cat > "$ROOTFS/fakes/systemctl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /opt/systemctl-integration.log
if [[ "$1" == enable && -f /opt/bootstrap-fail-enable ]]; then
  exit 1
fi
if [[ "$1" == show && "$*" == *User*WorkingDirectory* ]]; then
  [[ "$2" == patched-extractor.service ]] && working=/opt/patched-extractor || working=/opt/patched-api
  printf 'User=patched\nWorkingDirectory=%s\nProtectSystem=strict\nReadWritePaths=/var/log/patched\nReadWriteDirectories=\n' "$working"
elif [[ "$1" == show && "$*" == *ActiveState* ]]; then printf 'ActiveState=inactive\nSubState=dead\n'
elif [[ "$1" == show && "$*" == *InvocationID* ]]; then printf 'integration-invocation\n'
elif [[ "$1" == show && "$*" == *ExecStart* ]]; then printf '{ path=/opt/patched-api/bin/patched-cve-sync ; argv[]=/opt/patched-api/bin/patched-cve-sync ; }\n'
elif [[ "$1" == show && "$*" == *LoadState* ]]; then printf 'loaded\n'
fi
exit 0
EOF
# PAT-1237: verify-systemd-hardening-floor.sh's own bootstrap check requires
# a real systemd-analyze on PATH, and this rootfs has no init system to score
# real units against -- fake fixed scores at or under every class ceiling
# (6.0 application/scheduled-maintenance, 6.7 credential-handling) for the
# exact three units deploy.sh's guard call names, in systemd's real "Overall
# exposure level for <unit>: <score> <descriptor>" sentence shape.
cat > "$ROOTFS/fakes/systemd-analyze" <<'EOF'
#!/bin/bash
unit="${*: -1}"
printf 'Overall exposure level for %s: 2.0 OK :-)\n' "$unit"
EOF
cat > "$ROOTFS/fakes/busctl" <<'EOF'
#!/bin/bash
printf 't %s000000\n' "$(( $(date +%s) + 3600 ))"
EOF
cat > "$ROOTFS/fakes/psql" <<'EOF'
#!/bin/bash
case " $* " in
  *' -d postgres://integration '*) ;;
  *) exit 88 ;;
esac
printf '%s\n' "$*" >> /opt/psql-integration.log
if [[ "$*" == *"SELECT version FROM schema_migrations"* ]]; then
  printf ''
elif [[ "$*" == *"SELECT EXISTS"* ]]; then
  printf 't\n'
elif [[ "$*" == *to_regclass* ]]; then
  printf 'device_agent_health\n'
fi
EOF
cat > "$ROOTFS/fakes/curl" <<'EOF'
#!/bin/bash
printf 200
EOF
chmod 0755 "$ROOTFS/fakes/"*
for fake_command in systemctl systemd-analyze busctl psql curl; do
  cp "$ROOTFS/fakes/$fake_command" "$ROOTFS/usr/bin/$fake_command"
done

run_fixture() { /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@"; }

# Multiple ExecStart entries are ambiguous and must be rejected even if the
# first executable is the expected binary.
cp "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service.single"
printf 'ExecStart=/opt/patched-api/bin/patched-cve-sync --second-entry\n' >> \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service"
set +e
bootstrap_multi_output="$(run_fixture /bin/bash /opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh "$(printf '%040d' 1)" 2>&1)"
bootstrap_multi_status=$?
set -e
[[ "$bootstrap_multi_status" -ne 0 && "$bootstrap_multi_output" == *"ExecStart is not the exact scheduled CVE pipeline command"* ]]
mv "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service.single" \
  "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service"

touch "$ROOTFS/opt/bootstrap-fail-enable"
set +e
bootstrap_failure="$(run_fixture /bin/bash /opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh "$(printf '%040d' 1)" 2>&1)"
bootstrap_failure_status=$?
set -e
[[ "$bootstrap_failure_status" -ne 0 && "$bootstrap_failure" == *"removed partial binary, units and timer enablement"* ]]
[[ ! -e "$ROOTFS/opt/patched-api/bin/patched-cve-sync" ]]
[[ ! -e "$ROOTFS/etc/systemd/system/patched-cve-sync.service" ]]
[[ ! -e "$ROOTFS/etc/systemd/system/patched-cve-sync.timer" ]]
[[ -z "$(find "$ROOTFS/opt/patched-api/bin" "$ROOTFS/etc/systemd/system" -name '*.new' -print -quit)" ]]
grep -q '^disable --now patched-cve-sync.timer$' "$ROOTFS/opt/systemctl-integration.log"
rm "$ROOTFS/opt/bootstrap-fail-enable"

bootstrap_output="$(run_fixture /bin/bash /opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh "$(printf '%040d' 1)")"
[[ "$bootstrap_output" == *"bootstrapped patched-cve-sync from verified commit"* ]]
[[ "$(sha256sum "$ROOTFS/opt/patched-api/bin/patched-cve-sync" | awk '{print $1}')" == "$bootstrap_hash" ]]
[[ "$(stat -c '%U:%G %a' "$ROOTFS/opt/patched-api/bin/patched-cve-sync")" == "root:root 755" ]]
[[ "$(stat -c '%U:%G %a' "$ROOTFS/etc/systemd/system/patched-cve-sync.service")" == "root:root 644" ]]
[[ "$(stat -c '%U:%G %a' "$ROOTFS/etc/systemd/system/patched-cve-sync.timer")" == "root:root 644" ]]
cmp -s "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.service" "$ROOTFS/etc/systemd/system/patched-cve-sync.service"
cmp -s "$ROOTFS/opt/patched-bootstrap-cve-sync/patched-cve-sync.timer" "$ROOTFS/etc/systemd/system/patched-cve-sync.timer"
grep -q '^enable --now patched-cve-sync.timer$' "$ROOTFS/opt/systemctl-integration.log"
if grep -q '^start patched-cve-sync.service$' "$ROOTFS/opt/systemctl-integration.log"; then
  echo "bootstrap unexpectedly started patched-cve-sync.service" >&2
  exit 1
fi

set +e
bootstrap_refusal="$(run_fixture /bin/bash /opt/patched-bootstrap-cve-sync/bootstrap-cve-sync.sh "$(printf '%040d' 1)" 2>&1)"
bootstrap_refusal_status=$?
set -e
[[ "$bootstrap_refusal_status" -ne 0 && "$bootstrap_refusal" == *"already bootstrapped"* ]]

set +e
override_output="$(run_fixture /usr/bin/env PATCHED_API_BIN=/tmp/forbidden /bin/bash /opt/patched-deploy-staging/deploy.sh 2>&1)"
override_status=$?
set -e
[[ "$override_status" -ne 0 && "$override_output" == *"forbidden for root production invocation"* ]]
[[ -f "$ROOTFS/opt/patched-deploy-staging/deploy.sh" ]]

chmod 0775 "$ROOTFS/opt/patched-deploy-staging"
set +e
printf 'touch /opt/bash-env-was-sourced\n' > "$ROOTFS/opt/malicious-bash-env"
deploy_staging_output="$(BASH_ENV=/opt/malicious-bash-env /bin/bash --noprofile --norc /opt/patched-deploy-staging/deploy.sh 2>&1)"
deploy_staging_status=$?
set -e
[[ "$deploy_staging_status" -ne 0 && "$deploy_staging_output" == *"root production staging must be root:root 0755"* ]]
[[ -e "$ROOTFS/opt/bash-env-was-sourced" ]]
[[ "$(cat "$ROOTFS/opt/patched-api/bin/patched-api")" == old-api ]]
chmod 0755 "$ROOTFS/opt/patched-deploy-staging"

rm "$ROOTFS/opt/bash-env-was-sourced"
deploy_output="$(run_fixture /bin/bash --noprofile --norc /opt/patched-deploy-staging/deploy.sh)"
[[ ! -e "$ROOTFS/opt/bash-env-was-sourced" ]]
[[ "$deploy_output" == *"production binary deploy completed successfully"* ]]
[[ "$deploy_output" == *"schema drift check: OK"* && "$deploy_output" != *"::warning::"* ]]
[[ "$(cat "$ROOTFS/opt/patched-api/bin/patched-api")" == new-api ]]
grep -q -- '-f /opt/patched-deploy-staging/migrations/0105_test_migration.sql' "$ROOTFS/opt/psql-integration.log"
grep -q '^patched-cve-sync=' "$ROOTFS/opt/patched-api/DEPLOYED_BINARIES"
[[ ! -e "$ROOTFS/opt/patched-deploy-staging" ]]

# Root emergency mode must ignore no inherited path overrides, reject a
# non-root-controlled fixed staging directory before backup/mutation, then run
# the real fixed-path install and write the reduced-scope primary receipt.
set +e
emergency_override_output="$(run_fixture /usr/bin/env PATCHED_EMERGENCY_API_BIN=/tmp/forbidden \
  /bin/bash /opt/patched-emergency-api/emergency-api-only.sh "$(printf '%040d' 1)" integration \
  migrations-applied=0105_test_migration 2>&1)"
emergency_override_status=$?
set -e
[[ "$emergency_override_status" -ne 0 && "$emergency_override_output" == *"forbidden for root emergency invocation"* ]]

chmod 0775 "$ROOTFS/opt/patched-emergency-api"
set +e
emergency_invariant_output="$(run_fixture /bin/bash /opt/patched-emergency-api/emergency-api-only.sh \
  "$(printf '%040d' 1)" integration migrations-applied=0105_test_migration 2>&1)"
emergency_invariant_status=$?
set -e
[[ "$emergency_invariant_status" -ne 0 && "$emergency_invariant_output" == *"staging must be root:root 0755"* ]]
[[ "$(cat "$ROOTFS/opt/patched-api/bin/patched-api")" == new-api ]]

chmod 0755 "$ROOTFS/opt/patched-emergency-api"
emergency_output="$(run_fixture /bin/bash /opt/patched-emergency-api/emergency-api-only.sh \
  "$(printf '%040d' 1)" integration migrations-applied=0105_test_migration)"
[[ "$emergency_output" == *"REDUCED_SCOPE=true"* ]]
[[ "$(cat "$ROOTFS/opt/patched-api/bin/patched-api")" == emergency-api ]]
grep -q '^REDUCED_SCOPE=true$' "$ROOTFS/opt/patched-api/DEPLOYED_BINARIES"
grep -q '^previous_receipt=/root/patched-emergency-api-backups/DEPLOYED_BINARIES.emergency-bak-' \
  "$ROOTFS/opt/patched-api/DEPLOYED_BINARIES"
[[ "$(stat -c '%U:%G %a' "$ROOTFS/root/patched-emergency-api-backups")" == "root:root 700" ]]

# PAT-2312: service-account-hygiene.sh edits sudoers and the account database
# as root, so as root it must refuse its test-only prefix, even an empty one,
# before it reads or changes anything. It is piped in exactly as the workflow
# runs it. The fake prefix holds what `apply` would otherwise remove.
hygiene_prefix="$(mktemp -d)"
mkdir -p "$hygiene_prefix/etc/sudoers.d" "$hygiene_prefix/home/patched/.ssh"
printf 'patched ALL=(ALL) NOPASSWD: ALL\n' > "$hygiene_prefix/etc/sudoers.d/patched"
printf 'placeholder\n' > "$hygiene_prefix/home/patched/.ssh/authorized_keys"
for hygiene_value in "$hygiene_prefix" ""; do
  for hygiene_command in apply check; do
    set +e
    hygiene_output="$(run_fixture /usr/bin/env PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX="$hygiene_value" \
      /bin/bash --noprofile --norc -s -- "$hygiene_command" \
      < "$REPO_ROOT/deploy/api-01/service-account-hygiene.sh" 2>&1)"
    hygiene_status=$?
    set -e
    [[ "$hygiene_status" -eq 1 && "$hygiene_output" == *"PATCHED_SERVICE_ACCOUNT_HYGIENE_PREFIX is a test-only override and is refused when running as root"* ]]
  done
done
[[ -f "$hygiene_prefix/etc/sudoers.d/patched" && -f "$hygiene_prefix/home/patched/.ssh/authorized_keys" ]]
echo "root production integration passed"
