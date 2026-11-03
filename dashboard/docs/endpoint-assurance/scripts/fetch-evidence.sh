#!/usr/bin/env bash
# Endpoint Assurance evidence-fetch (PAT-1502).
#
# Pulls one tenant's collected evidence from the patched.im admin API
# (and, for standing local-admin, a read-only query against the same
# Postgres database over SSH, since no JSON route exists for that report
# yet) and writes it as a single JSON bundle. That bundle is the input to
# docs/endpoint-assurance/scripts/draft-report-prompt.md.
#
# This is operator tooling for a specialist compiling an assessment report.
# It is not a dashboard feature: no new route, no UI, no scheduled job.
#
# Usage:
#   ADMIN_API_TOKEN=<token> ./fetch-evidence.sh <tenant-id> [output-file]
#
# Obtaining ADMIN_API_TOKEN: it lives in /etc/patched-api/env on
# patched-api-01 and is never written to a repo. Read it directly, e.g.:
#   ssh root@patched-api-01 'grep "^ADMIN_API_TOKEN=" /etc/patched-api/env'
# Export the value in your own shell; do not paste it into a prompt, a
# ticket, or this script.
#
# API base: the internal admin listener is Tailscale-only, reached at
# patched-api-01.example-tailnet.ts.net:8443 (Caddy reverse-proxies it to
# 127.0.0.1:8081 on the box). Override with PATCHED_API_INTERNAL_URL if
# needed. Its certificate is not in the local trust store (Tailscale-only,
# never meant to be publicly issued), so this script uses curl --insecure
# for it - the same pattern already used in deploy/prod-backup.sh in this
# repo for the same reason: the transport is authenticated by the
# Tailscale network boundary and the bearer token, not by the cert chain.
#
# Local-admin fetch talks to patched-api-01 over SSH and runs a read-only
# psql query using the box's own DATABASE_URL from /etc/patched-api/env.
# It touches no other table, writes nothing, and mirrors the same query
# patched.im/go-service/internal/report/local_admin.go already runs for
# the PDF report.

set -euo pipefail

usage() {
  echo "Usage: ADMIN_API_TOKEN=<token> $0 <tenant-id> [output-file]" >&2
  exit 1
}

TENANT_ID="${1:-}"
[[ -n "$TENANT_ID" ]] || usage

UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
if [[ ! "$TENANT_ID" =~ $UUID_RE ]]; then
  echo "error: tenant id '$TENANT_ID' is not a UUID" >&2
  exit 1
fi

: "${ADMIN_API_TOKEN:?ADMIN_API_TOKEN is not set - see the header of this script for how to obtain it}"

BASE_URL="${PATCHED_API_INTERNAL_URL:-https://patched-api-01.example-tailnet.ts.net:8443}"
ADMIN_SSH_HOST="${PATCHED_API_SSH_HOST:-root@patched-api-01}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_OUT_DIR="$SCRIPT_DIR/../runs"
mkdir -p "$DEFAULT_OUT_DIR"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${2:-$DEFAULT_OUT_DIR/evidence-${TENANT_ID}-${TIMESTAMP}.json}"

command -v curl >/dev/null || { echo "error: curl not found" >&2; exit 1; }
command -v jq   >/dev/null || { echo "error: jq not found" >&2; exit 1; }

api_get() {
  local path="$1"
  curl --silent --show-error --fail --insecure --max-time 30 \
    -H "Authorization: Bearer $ADMIN_API_TOKEN" \
    "${BASE_URL}${path}"
}

echo "Fetching evidence for tenant $TENANT_ID from $BASE_URL ..." >&2

devices_json="$(api_get "/admin/tenants/${TENANT_ID}/devices?limit=1000")"
device_count="$(echo "$devices_json" | jq '.devices | length')"
echo "  devices: $device_count" >&2

cis_findings_json="$(api_get "/admin/tenants/${TENANT_ID}/findings?limit=1000")"
echo "  CIS findings: $(echo "$cis_findings_json" | jq '.findings | length')" >&2

shadow_it_json="$(api_get "/admin/tenants/${TENANT_ID}/shadow-it/findings")"
echo "  shadow-IT findings fetched" >&2

# Per-device apps (usage/metering signal) and per-device CVE findings
# (with match_confidence). Built as {"<device_id>": [...]} maps so the
# drafting prompt can join them against the device list by id.
device_apps_json="{}"
device_cve_json="{}"

device_ids="$(echo "$devices_json" | jq -r '.devices[].id')"
for device_id in $device_ids; do
  apps="$(api_get "/admin/devices/${device_id}/apps")"
  cve="$(api_get "/admin/devices/${device_id}/cve-findings")"
  device_apps_json="$(jq --arg id "$device_id" --argjson v "$apps" '. + {($id): $v}' <<<"$device_apps_json")"
  device_cve_json="$(jq --arg id "$device_id" --argjson v "$cve" '. + {($id): $v}' <<<"$device_cve_json")"
done
echo "  per-device apps and CVE findings fetched for $device_count device(s)" >&2

# Standing local-admin: no JSON route exists (only a PDF handler). Read-only
# query against the same table the PDF report reads
# (patched.im/go-service/internal/report/local_admin.go), run on the box
# over SSH using its own DATABASE_URL. Never writes, never touches another
# tenant's rows (tenant id is regex-validated above before use).
echo "  local-admin (read-only SSH query to patched-api-01) ..." >&2
local_admin_json="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$ADMIN_SSH_HOST" bash -s <<REMOTE
set -euo pipefail
source /etc/patched-api/env
psql "\$DATABASE_URL" -X -q -A -t -c "
  SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)
  FROM (
    SELECT d.id AS device_id, d.hostname, d.os,
           cs.value AS admin_count_raw
    FROM devices d
    LEFT JOIN LATERAL (
      SELECT cs2.value
      FROM compliance_signals cs2
      WHERE cs2.device_id = d.id
        AND cs2.key = 'local_admin_count'
      ORDER BY cs2.observed_at DESC
      LIMIT 1
    ) cs ON true
    WHERE d.tenant_id = '${TENANT_ID}'
    ORDER BY d.hostname
  ) t
"
REMOTE
)"

if ! echo "$local_admin_json" | jq -e . >/dev/null 2>&1; then
  echo "error: local-admin query did not return valid JSON:" >&2
  echo "$local_admin_json" >&2
  exit 1
fi
echo "  local-admin rows: $(echo "$local_admin_json" | jq 'length')" >&2

jq -n \
  --arg tenant_id "$TENANT_ID" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg base_url "$BASE_URL" \
  --argjson devices "$devices_json" \
  --argjson device_apps "$device_apps_json" \
  --argjson device_cve_findings "$device_cve_json" \
  --argjson cis_findings "$cis_findings_json" \
  --argjson shadow_it_findings "$shadow_it_json" \
  --argjson local_admin "$local_admin_json" \
  '{
    tenant_id: $tenant_id,
    generated_at: $generated_at,
    source: {
      api_base_url: $base_url,
      local_admin_via: "read-only ssh+psql against patched-api-01, mirrors internal/report/local_admin.go"
    },
    devices: $devices,
    device_apps: $device_apps,
    device_cve_findings: $device_cve_findings,
    cis_findings: $cis_findings,
    shadow_it_findings: $shadow_it_findings,
    local_admin: $local_admin
  }' > "$OUT_FILE"

echo "Evidence bundle written: $OUT_FILE" >&2
echo "$OUT_FILE"
