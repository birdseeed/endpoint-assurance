#!/bin/zsh
##############################################################################
# patched-uninstall.sh — app removal engine for the Patched allowlist.
#
# Run by the LaunchDaemon `com.patched.uninstall-check` (as root). On each
# run it:
#   1. Verifies its own bundle integrity (same SHA-256 manifest as the
#      updater — closes the same attack surface on the removal path).
#   2. Gates on the managed agent tier for allowlist enforcement (PAT-112).
#   3. Fetches the tenant's pending-removal queue from the platform
#      (GET /v1/allowlist/pending-removals) — only entries the admin marked
#      for removal ≥ 24 h ago are returned; the hold window is server-side.
#   4. For each queued app: resolve an uninstall method, check the app is not
#      actively running, execute with timeout, verify by re-inspection (not
#      exit code), classify transient vs hard failures, emit a provenance
#      record per attempt.
#   5. Writes /Library/Application Support/Patched/uninstall-status.json
#      atomically.
#
# CONVENTIONS (shared with patched-update.sh):
#   - `set -u` only. NOT `set -euo pipefail` — codesign/pkgutil return
#     non-zero on stubbed or partially-installed bundles.
#   - /usr/bin/python3 hardcoded (sudo strips PATH on macOS).
#   - Never use `path` / `fpath` / `cdpath` / `manpath` / `infopath` as
#     variable names (zsh typeset -T trap — silently corrupts $PATH).
#
# GitHub-Non-Author-Review: write path, drives agent behaviour on customer endpoints.
# Tier 2+, MSA-authorised (PAT-112). GitHub-Non-Author-Review gate before first ship.
##############################################################################

set -u

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
# Optional: --app-id <identifier>
# When provided (user-initiated via patched-uninstall-trigger.sh), the engine
# restricts processing to the entry matching that identifier in the server queue.
# If the identifier is not in the queue it is not policy-removable (or not yet
# queued); the engine exits with an error rather than silently doing nothing.

FILTER_APP_ID=""
while [[ $# -gt 0 ]]; do
    case "${1:-}" in
        --app-id) FILTER_APP_ID="${2:-}"; shift 2 ;;
        *)        echo "WARN: unknown argument: ${1:-}"; shift ;;
    esac
done

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BUNDLE_DIR="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}"
MANIFEST="$BUNDLE_DIR/manifest.sha256"
LABELS_ALLOWLIST="$BUNDLE_DIR/labels-allowlist.txt"

STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
UNINSTALL_STATUS_FILE="$STATE_DIR/uninstall-status.json"
AGENT_CONFIG_FILE="$STATE_DIR/agent-config.json"
AGENT_CONFIG_SHA256_FILE="$STATE_DIR/agent-config.sha256"
AGENT_CONFIG_HEARTBEAT_FILE="$STATE_DIR/agent-config.checked"
# PAT-781: server-assigned device UUID lives in the cached posture (device.id),
# distinct from the IOPlatformUUID. Needed to address the per-device removal-task
# endpoints (/v1/devices/{deviceID}/removal-tasks/*).
POSTURE_FILE="$STATE_DIR/posture.json"

PROV_QUEUE="${PATCHED_PROV_QUEUE:-/var/db/patched/provenance-queue}"
CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-uninstall.log}"

PROXY_RESOLVE="$BUNDLE_DIR/patched-proxy-resolve.py"
FETCH_CONFIG="$BUNDLE_DIR/patched-fetch-config.sh"

PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] || { echo "FATAL: /usr/bin/python3 missing"; exit 1; }
LEGACY_APP_EXECUTION_GATE="$BUNDLE_DIR/patched-legacy-app-execution-gate.py"
# Private parent/child protocol: the update daemon recognises this as a
# terminal authority refusal and records the consumed trigger's local status
# and provenance before deleting it. Other failures retain their old handling.
LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42

# >>> PATCHED_LEGACY_APP_EXECUTION_ENABLED_START
# Evaluated at every legacy removal seam from one hash-and-parse snapshot.
# legacy_app_execution_gate_file_covered <manifest-name> <path>
legacy_app_execution_gate_file_covered() {
    local _name="$1" _file="$2"
    [[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || return 1
    [[ -f "$_file" && ! -L "$_file" ]] || return 1
    local _want="" _hash _rel _extra _matches=0
    while read -r _hash _rel _extra; do
        [[ "$_rel" == "$_name" && -z "${_extra:-}" ]] || continue
        _want="$_hash"
        (( _matches++ )) || true
    done < "$MANIFEST"
    [[ $_matches -eq 1 && ${#_want} -eq 64 && "$_want" != *[^[:xdigit:]]* ]] || return 1
    local _got
    _got=$(shasum -a 256 "$_file" 2>/dev/null | awk '{print $1}')
    [[ "${_got:l}" == "${_want:l}" ]]
}

# PAT-1773: the helper loads agent_config_tenant.py from the bundle in-process,
# so that module's current bytes need the same exact manifest entry.
legacy_app_execution_gate_manifest_covered() {
    legacy_app_execution_gate_file_covered "patched-legacy-app-execution-gate.py" "$LEGACY_APP_EXECUTION_GATE" || return 1
    legacy_app_execution_gate_file_covered "agent_config_tenant.py" "$BUNDLE_DIR/agent_config_tenant.py"
}

legacy_app_execution_enabled() {
    [[ "$LEGACY_APP_EXECUTION_GATE" == "$BUNDLE_DIR/patched-legacy-app-execution-gate.py" ]] || return 1
    [[ -f "$LEGACY_APP_EXECUTION_GATE" && ! -L "$LEGACY_APP_EXECUTION_GATE" ]] || return 1
    legacy_app_execution_gate_manifest_covered || return 1
    "$PYTHON3" "$LEGACY_APP_EXECUTION_GATE" "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" \
        "$AGENT_CONFIG_HEARTBEAT_FILE" "$CREDS_DIR/suspended"
}
# <<< PATCHED_LEGACY_APP_EXECUTION_ENABLED_END

# >>> PATCHED_AGENT_CONFIG_TENANT_SCOPE_START
# PAT-1773: agent-config.json is not keyed by tenant. After re-enrolment into
# another tenant it still holds the old tenant's verified config until the new
# tenant's first accepted config. agent_config_tenant_scope runs once per run,
# after the config refresh, and asks agent_config_tenant.py (manifest-covered)
# whether the cached config belongs to the enrolled tenant. Every reader tests
# agent_config_present instead of the file, so a config that does not belong
# to the enrolled tenant takes that reader's existing no-config default. The
# block is identical in every endpoint script that reads the cached config;
# endpoint/test-agent-config-tenant-scope.zsh checks that.
AGENT_CONFIG_TENANT_MODULE="$BUNDLE_DIR/agent_config_tenant.py"
AGENT_CONFIG_FOR_TENANT=0

agent_config_tenant_scope() {
    AGENT_CONFIG_FOR_TENANT=0
    local _tenant_state=""
    if [[ -f "$AGENT_CONFIG_TENANT_MODULE" && ! -L "$AGENT_CONFIG_TENANT_MODULE" ]]; then
        _tenant_state=$("$PYTHON3" "$AGENT_CONFIG_TENANT_MODULE" cached-state \
            "$AGENT_CONFIG_FILE" "$CREDS_DIR/tenant-id" 2>/dev/null) || _tenant_state=""
    fi
    case "$_tenant_state" in
        applies) AGENT_CONFIG_FOR_TENANT=1 ;;
        absent) ;;
        # PAT-1814: no enrolled tenant yet (pre-enrolment, or the tenant-id
        # credential is missing/blank) is a normal, expected state, not a
        # check failure — say so distinctly instead of the generic
        # "does not belong to the enrolled tenant" wording below, which
        # implies a real tenant mismatch or a read failure.
        no_enrolled_tenant) echo "agent-config: cached config at $AGENT_CONFIG_FILE is not used this run: no enrolled tenant is configured yet; every reader applies its no-config default" ;;
        *) echo "agent-config: cached config at $AGENT_CONFIG_FILE is not used this run: it does not belong to the enrolled tenant (${_tenant_state:-tenant check unavailable}); every reader applies its no-config default" ;;
    esac
    return 0
}

# agent_config_present: true only for a cached config agent_config_tenant_scope
# found to belong to the enrolled tenant, and only while the file exists.
agent_config_present() {
    (( AGENT_CONFIG_FOR_TENANT )) && [[ -f "$AGENT_CONFIG_FILE" ]]
}
# <<< PATCHED_AGENT_CONFIG_TENANT_SCOPE_END

# PAT-806: per-run cache of the known_app_bundles paths carried alongside the
# tenant-wide pending-removals queue (section 3 below), keyed by lowercased
# app name. Declared globally (not just inside the guarded allowlist block)
# because run_device_removal_tasks (section 8) also calls
# resolve_canonical_app_path and always runs, independent of whether the
# tenant-wide allowlist fetch succeeded this cycle. Empty is the correct
# default: resolve_canonical_app_path's PAT-806 middle step simply has
# nothing to offer and falls through to the raw name-guess, same as today.
typeset -gA KNOWN_PATH_MAP

# PAT-66/PAT-806: the exact set of parent directories a server-supplied
# known_path is allowed to resolve under (see lookup_known_app_bundle_path).
# This mirrors the roots the raw name-guess fallback already searches
# (`find /Applications /Applications/Utilities /System/Applications
# -maxdepth 1 ...`). A pre-set value wins so the unit-test harness can point
# it at its sandbox; production never sets it and gets this secure default.
# `${+name}` is used (not `${#name[@]}`) so the set-test does not trip `set -u`
# on the unset array.
(( ${+KNOWN_APP_BUNDLE_ROOTS} )) || \
    KNOWN_APP_BUNDLE_ROOTS=(/Applications /Applications/Utilities /System/Applications)

mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR" "$PROV_QUEUE"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== patched-uninstall run started $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

RUN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# 1. BUNDLE INTEGRITY
# ---------------------------------------------------------------------------

verify_bundle() {
    if [[ ! -f "$MANIFEST" ]]; then
        echo "FATAL: integrity manifest missing ($MANIFEST)"
        return 1
    fi
    local rc=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        local want="${line%% *}"
        local rel="${line##* }"
        local got
        got=$(shasum -a 256 "$BUNDLE_DIR/$rel" 2>/dev/null | awk '{print $1}')
        if [[ "$got" != "$want" ]]; then
            echo "FATAL: integrity check failed for $rel (expected $want, got ${got:-<missing>})"
            rc=1
        fi
    done < "$MANIFEST"
    return $rc
}

if ! verify_bundle; then
    echo "Aborting: bundle integrity verification failed."
    exit 1
fi
echo "Bundle integrity OK."

# ---------------------------------------------------------------------------
# CREDENTIALS
# ---------------------------------------------------------------------------

for _cf in tenant-id bearer-token hmac-secret; do
    [[ -f "$CREDS_DIR/$_cf" ]] || { echo "ERROR: $CREDS_DIR/$_cf missing"; exit 1; }
done
TENANT_ID=$(head -1 "$CREDS_DIR/tenant-id" | tr -d '[:space:]')
BEARER_TOKEN=$(head -1 "$CREDS_DIR/bearer-token" | tr -d '[:space:]')

# ---------------------------------------------------------------------------
# SAFE-CREDENTIAL HELPER (PAT-922; endpoint/ counterpart to macos/'s PAT-881)
# ---------------------------------------------------------------------------
# Kept inline, not sourced from lib/ — tools/build-bundle.sh copies endpoint/
# scripts individually by filename with no lib/ directory, so a sourced
# dependency would fatal on every deployed release build.
#
# WHY: `-H "Authorization: Bearer $TOKEN"` puts the live bearer token on
# argv, readable by any local user via `ps -ww` for the life of the curl
# process. Feed it to curl over stdin instead (`-H @-`) so it never appears
# there.
#
# >>> PATCHED_CREDS_HELPERS_START (keep in sync with macos/patched-upload.sh, macos/patched-bootstrap.sh)
patched_curl_bearer() {
    local _token="$1"; shift
    printf 'Authorization: Bearer %s\n' "$_token" | curl -H @- "$@"
}
# <<< PATCHED_CREDS_HELPERS_END

# ---------------------------------------------------------------------------
# 2. AGENT CONFIG / TIER GATE
# ---------------------------------------------------------------------------

if [[ -x "$FETCH_CONFIG" ]]; then
    "$FETCH_CONFIG" || true
else
    echo "WARN: patched-fetch-config.sh not found; skipping config refresh"
fi

# PAT-1773: another tenant's cached config leaves the tier at its no-config
# default.
agent_config_tenant_scope
AGENT_TIER="assurance"
if agent_config_present; then
    AGENT_TIER=$("$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get('tier','assurance'))
except Exception:
    print('assurance')
" "$AGENT_CONFIG_FILE" 2>/dev/null || echo "assurance")
fi

# Allowlist enforcement requires the managed tier.
# >>> PATCHED_UNINSTALL_TIER_GATE_START
# A requested-app child has a distinct parent protocol for authenticated
# authority refusal. Check it before the ordinary tier no-op so a refresh that
# just moved the device to report/revoked cannot be misreported as success.
if [[ -n "$FILTER_APP_ID" ]] && ! legacy_app_execution_enabled; then
    echo "Legacy app-execution gate disabled for requested app — refusing removal."
    exit "$LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT"
fi
case "$AGENT_TIER" in
    managed) ;;
    *)
        echo "Tier gate: $AGENT_TIER is not managed; skipping removal run."
        exit 0
        ;;
esac
echo "Tier gate OK: $AGENT_TIER"
# <<< PATCHED_UNINSTALL_TIER_GATE_END

# PAT-1481: direct/Self Service, scheduled pending-removal and per-device
# removal-task execution all pass this one root-process entry point. The
# explicit signed grant is necessary but the existing tier, posture, baseline,
# queue and planner gates below remain mandatory.
if ! legacy_app_execution_enabled; then
    echo "Legacy app-execution gate disabled — skipping removal run."
    if [[ -n "$FILTER_APP_ID" ]]; then
        exit "$LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# LOCK — one run at a time
# ---------------------------------------------------------------------------

LOCK_DIR="$STATE_DIR/.patched-uninstall.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "Lock held by another instance — skipping."
    exit 0
fi
_lock_cleanup() { rm -rf "$LOCK_DIR"; }
trap _lock_cleanup EXIT

# ---------------------------------------------------------------------------
# DEVICE INFO
# ---------------------------------------------------------------------------

HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
COMPUTER_NAME=$(scutil --get ComputerName 2>/dev/null || echo "unknown")

# ---------------------------------------------------------------------------
# PROXY RESOLUTION  (mirrors patched-fetch-config.sh)
# ---------------------------------------------------------------------------

with_proxy() {
    local _target="$1"; shift
    local _json _parsed _pmode _purl _durl _noproxy _pwarn

    if [[ -x "${PROXY_RESOLVE:-}" ]]; then
        _json=$("$PYTHON3" "$PROXY_RESOLVE" "$_target" "${AGENT_CONFIG_FILE:-}" 2>/dev/null) \
            || _json='{"mode":"direct"}'
        _parsed=$(printf '%s' "$_json" | "$PYTHON3" -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: d = {}
fields = [d.get("mode","direct"), d.get("url",""), d.get("display_url",""),
          d.get("no_proxy",""), d.get("warning","")]
sys.stdout.write("\t".join(f if isinstance(f,str) else str(f) for f in fields))
' 2>/dev/null)
        IFS=$'\t' read -r _pmode _purl _durl _noproxy _pwarn <<< "$_parsed"
    fi
    _pmode="${_pmode:-direct}"; _purl="${_purl:-}"; _noproxy="${_noproxy:-}"
    if [[ "$_pmode" == "proxy" && -n "$_purl" ]]; then
        HTTP_PROXY="$_purl" HTTPS_PROXY="$_purl" ALL_PROXY="$_purl" NO_PROXY="$_noproxy" \
        http_proxy="$_purl" https_proxy="$_purl" all_proxy="$_purl" no_proxy="$_noproxy" \
        "$@"
    else
        HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" NO_PROXY="" \
        http_proxy="" https_proxy="" all_proxy="" no_proxy="" \
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# HMAC over empty body (GET has no request body)
# ---------------------------------------------------------------------------

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body so a captured
# signed request cannot be replayed. Signing input is:
#   b"patched-hmac-v3\nMETHOD\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body
# ts and nonce MUST be the exact strings sent in the X-Patched-Timestamp /
# X-Patched-Nonce headers for this same request — callers generate ts+nonce
# FIRST, then pass them into these helpers AND into the headers.

# hmac_empty <endpoint-id> <ts> <nonce>
hmac_empty() {
    "$PYTHON3" - "$1" "$2" "$3" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
msg = b"patched-hmac-v3\nGET\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n"
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# HMAC over a file (for provenance POST bodies). compute_hmac <body-file> <endpoint-id> <ts> <nonce>
compute_hmac() {
    "$PYTHON3" - "$1" "$2" "$3" "$4" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
body_path, endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
with open(body_path, 'rb') as f: body = f.read()
msg = b"patched-hmac-v3\nPOST\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n" + body
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# ---------------------------------------------------------------------------
# PROVENANCE
# ---------------------------------------------------------------------------

PROVENANCE_QUEUE_MAX_RECORDS=128
PROVENANCE_QUEUE_MAX_BYTES=$(( 2 * 1024 * 1024 ))
PROVENANCE_RECORD_MAX_BYTES=$(( 64 * 1024 ))
PROVENANCE_NETWORK_MAX_ATTEMPTS=4
PROVENANCE_HTTP_MAX_SECONDS=5
typeset -gi PROVENANCE_NETWORK_ATTEMPTS=0

_provenance_network_slot() {
    (( PROVENANCE_NETWORK_ATTEMPTS < PROVENANCE_NETWORK_MAX_ATTEMPTS )) || return 1
    (( PROVENANCE_NETWORK_ATTEMPTS++ )) || true
    return 0
}

queue_provenance() {
    local result
    result=$("$PYTHON3" - "$PROV_QUEUE" "$PROVENANCE_QUEUE_MAX_RECORDS" \
        "$PROVENANCE_QUEUE_MAX_BYTES" "$PROVENANCE_RECORD_MAX_BYTES" "$@" <<'PYEOF'
import os, stat, sys, tempfile, time
queue_dir = sys.argv[1]
max_records = int(sys.argv[2])
max_bytes = int(sys.argv[3])
max_record_bytes = int(sys.argv[4])
sources = sys.argv[5:]
queued = dropped = evicted = 0
os.makedirs(queue_dir, exist_ok=True)
for source in sources:
    temporary = ''
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        try:
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise ValueError('not regular')
            body = os.read(source_fd, max_record_bytes + 1)
        finally:
            os.close(source_fd)
        if len(body) > max_record_bytes:
            raise ValueError('oversized')
        temporary_fd, temporary = tempfile.mkstemp(prefix='.prov-', dir=queue_dir)
        with os.fdopen(temporary_fd, 'wb') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        destination = os.path.join(queue_dir, f"prov-{time.time_ns()}-{os.path.basename(temporary)[6:]}.json")
        os.replace(temporary, destination)
        temporary = ''
        queued += 1
    except Exception:
        dropped += 1
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
records = []
for entry in os.scandir(queue_dir):
    if not entry.name.startswith('prov-') or not entry.name.endswith('.json'):
        continue
    try:
        metadata = entry.stat(follow_symlinks=False)
    except OSError:
        continue
    if stat.S_ISREG(metadata.st_mode):
        records.append((metadata.st_mtime_ns, entry.name, metadata.st_size, entry.path))
records.sort()
total_bytes = sum(item[2] for item in records)
while records and (len(records) > max_records or total_bytes > max_bytes):
    _, _, record_bytes, record_path = records.pop(0)
    try:
        os.unlink(record_path)
        total_bytes -= record_bytes
        evicted += 1
    except OSError:
        pass
print(f'queued={queued} dropped={dropped} evicted={evicted} retained={len(records)} bytes={total_bytes}')
PYEOF
    ) || result="queue-helper-failed"
    echo "  provenance queue: $result"
}

emit_provenance() {  # emit_provenance <json-body-file>
    local body_file="$1"
    if ! _provenance_network_slot; then
        queue_provenance "$body_file"
        echo "  provenance POST deferred: per-cycle network budget exhausted"
        return 0
    fi
    local ts; ts=$(date -u +%s)
    local nonce; nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    local sig; sig=$(compute_hmac "$body_file" "provenance" "$ts" "$nonce")
    local code
    code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time "$PROVENANCE_HTTP_MAX_SECONDS" \
        -X POST "$API_URL/v1/provenance" \
        -H "X-Patched-Signature: $sig" \
        -H "X-Patched-Timestamp: $ts" \
        -H "X-Patched-Nonce: $nonce" \
        -H "Content-Type: application/json" \
        --data-binary "@$body_file" 2>/dev/null)
    if [[ "$code" == 2* ]]; then
        echo "  provenance POST -> $code"
    else
        queue_provenance "$body_file"
        echo "  provenance POST -> ${code:-network-error}; queued locally"
    fi
}

drain_provenance_queue() {
    [[ -d "$PROV_QUEUE" ]] || return 0
    queue_provenance >/dev/null
    local -a _files
    _files=("$PROV_QUEUE"/prov-*.json(N))
    [[ ${#_files} -gt 0 ]] || return 0
    local total=${#_files[@]} drained=0 failed=0 attempted=0
    for _f in "${_files[@]}"; do
        [[ -f "$_f" ]] || continue
        _provenance_network_slot || break
        (( attempted++ )) || true
        local sig ts nonce code
        ts=$(date -u +%s)
        nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
        sig=$(compute_hmac "$_f" "provenance" "$ts" "$nonce")
        code=$(with_proxy "$API_URL" \
            patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time "$PROVENANCE_HTTP_MAX_SECONDS" \
            -X POST "$API_URL/v1/provenance" \
            -H "X-Patched-Signature: $sig" \
            -H "X-Patched-Timestamp: $ts" \
            -H "X-Patched-Nonce: $nonce" \
            -H "Content-Type: application/json" \
            --data-binary "@$_f" 2>/dev/null)
        if [[ "$code" == 2* ]]; then
            rm -f "$_f"
            (( drained++ )) || true
        else
            (( failed++ )) || true
        fi
    done
    echo "provenance queue drain: queued=$total attempted=$attempted drained=$drained failed=$failed budget=$PROVENANCE_NETWORK_MAX_ATTEMPTS"
}

# ---------------------------------------------------------------------------
# 3. FETCH PENDING REMOVALS
# ---------------------------------------------------------------------------

# _run_allowlist gates the tenant-wide allowlist path below. A failed or empty
# allowlist fetch no longer exits the script: it falls through so the per-device
# removal-task path (PAT-781, section 8) still runs on the same scheduled pass.
_run_allowlist=1

_ts=$(date -u +%s)
_nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
_sig=$(hmac_empty "pending_removals" "$_ts" "$_nonce")
_resp_file=$(mktemp /tmp/.patched-removals-resp.XXXXXX)
_removals_code=$(with_proxy "$API_URL" \
    patched_curl_bearer "$BEARER_TOKEN" -s -o "$_resp_file" -w "%{http_code}" --max-time 30 \
    -H "X-Patched-Signature: $_sig" \
    -H "X-Patched-Timestamp: $_ts" \
    -H "X-Patched-Nonce: $_nonce" \
    -H "Accept: application/json" \
    "$API_URL/v1/allowlist/pending-removals" 2>/dev/null) || _removals_code="000"

if [[ "$_removals_code" != "200" ]]; then
    echo "pending-removals fetch failed: HTTP $_removals_code — will retry next run."
    rm -f "$_resp_file"
    _run_allowlist=0
fi

if [[ $_run_allowlist -eq 1 ]]; then
    _item_count=$("$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d.get('items', [])))
except Exception:
    print(0)
" "$_resp_file" 2>/dev/null || echo "0")

    echo "Pending removals: $_item_count"
    if [[ "$_item_count" -eq 0 ]]; then
        rm -f "$_resp_file"
        echo "Nothing to do."
        _run_allowlist=0
    fi
fi

# ---------------------------------------------------------------------------
# macOS SAFETY GUARD — never remove Apple-signed baseline apps
# ---------------------------------------------------------------------------

_NEVER_REMOVE=(
    "Finder" "Spotlight" "System Preferences" "System Settings"
    "System Information" "App Store" "Software Update"
    "Safari" "Mail" "Calendar" "Contacts" "Reminders" "Notes"
    "Messages" "FaceTime" "Maps" "Photos" "Music" "TV" "Books"
    "Podcasts" "News" "Stocks" "Weather" "Voice Memos" "QuickTime Player"
    "TextEdit" "Preview" "Calculator" "Clock" "Font Book" "Stickies"
    "Dictionary" "Screenshot" "Image Capture" "Terminal"
    "Activity Monitor" "Disk Utility" "Console" "Keychain Access"
    "Directory Utility" "Migration Assistant" "Time Machine"
    "Automator" "Script Editor" "ColorSync Utility"
    "Digital Color Meter" "Grapher" "Xcode"
)

is_baseline_protected() {
    local check="$1"
    for _protected in "${_NEVER_REMOVE[@]}"; do
        if [[ "${check:l}" == "${_protected:l}" ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# APP NAME VALIDATION (PAT-855)
# ---------------------------------------------------------------------------
# app_name is server-supplied — the pending-removals queue `name` field, or a
# device-task app_name — and gets interpolated directly into filesystem paths
# in execute_uninstall_macos's app_bundle support-path loop, which then
# rm -rf's the result as root. Nothing upstream validates the *name* itself:
# is_baseline_protected only compares it against a fixed display-name list,
# and is_installed_macos validates the *resolved path* (via the curated
# labels-allowlist or KNOWN_PATH_MAP), not this raw field — so a crafted name
# can ride along with an unrelated, legitimately-resolved known_path and
# still reach the support-path loop unfiltered. Reject anything that could
# escape the intended parent directory BEFORE it is used in any path
# construction: no path separators, no literal "..", and nothing outside a
# conservative printable-name charset.
is_safe_app_name() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    case "$name" in
        *..*|*/*|*'\'*) return 1 ;;
    esac
    # A name that is nothing but dots and/or spaces (e.g. ".", "   ") passes
    # the two checks above yet still collapses onto its parent directory once
    # interpolated — "/Library/Application Support/." IS "/Library/Application
    # Support", and an all-space name strips to "" via safe_name, giving
    # "/Library/Application Support/" (same thing). Require at least one
    # character outside that set.
    case "$name" in
        *[^.\ ]*) ;;
        *) return 1 ;;
    esac
    local stripped="${name//[A-Za-z0-9 ._+-]/}"
    [[ -z "$stripped" ]]
}

# ---------------------------------------------------------------------------
# BUNDLE PATH RESOLUTION
# ---------------------------------------------------------------------------

# Looks up a queued app's authoritative app_path in the tenant's
# labels-allowlist.txt (columns: label, name, expected_team_id, app_path,
# download_method, mirror_url, pinned_sha256), matching on `name` case-
# insensitively. Echoes the raw path from the manifest with NO existence
# check — a queued app's display `name` (e.g. "Zoom") does not always match
# its installed bundle filename (Zoom installs as zoom.us.app), so this is
# the one place that mapping is resolved; callers that need to know whether
# the bundle currently exists must check `-d` themselves (verify_removal_macos
# needs the path to check for *absence* after a removal, so baking an
# existence check in here would be wrong for that caller). Prints nothing if
# the allowlist is missing or has no matching row.
lookup_labels_app_path() {
    local app_name="$1"
    local name_lower="${app_name:l}"
    [[ -f "$LABELS_ALLOWLIST" ]] || return 0

    local line _label _name _team _path _rest
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        IFS=$'\t' read -r _label _name _team _path _rest <<< "$line"
        if [[ "${_name:l}" == "$name_lower" ]]; then
            [[ -n "$_path" ]] && echo "$_path"
            return 0
        fi
    done < "$LABELS_ALLOWLIST"
}

# Looks up an app's on-disk path in KNOWN_PATH_MAP (PAT-806): the
# known_app_bundles data the platform now attaches to each pending-removals
# queue entry (name -> known_path), populated once per run in section 5/8
# below. Distinct from lookup_labels_app_path above: that table is
# manually-curated (EULA/mirror Catalogue review); this one is auto-populated
# from every tenant's inventory scans and only covers apps already queued for
# removal. Echoes the path ONLY when it currently exists on disk right now —
# a stale mapping (e.g. after a vendor renames its bundle across a major
# version) must silently fail to resolve rather than being trusted blindly;
# the platform intentionally keeps no expiry logic on its side and relies on
# this existence check instead.
#
# PAT-66/PAT-806 boundary: existence-on-disk is NOT sufficient — known_path
# is unreviewed, server-supplied inventory data, and this value ultimately
# reaches `rm -rf` as root (execute_uninstall_macos). It is therefore
# constrained to the exact same app-bundle allowlist the raw name-guess
# fallback already enforces elsewhere in this file (`find /Applications
# /Applications/Utilities /System/Applications -maxdepth 1 -iname "*.app"`):
# not a symlink, basename ends in `.app`, and parent dir EXACTLY one of the
# roots in KNOWN_APP_BUNDLE_ROOTS (those three in production). Anything that
# fails these checks returns nothing and falls through to that same
# name-guess fallback, exactly as if no known_path had been supplied.
lookup_known_app_bundle_path() {
    local app_name="$1"
    local name_lower="${app_name:l}"
    local candidate="${KNOWN_PATH_MAP[$name_lower]:-}"
    [[ -n "$candidate" && -d "$candidate" && ! -L "$candidate" ]] || return 0
    # Basename must be an app bundle, and the parent must be EXACTLY one of
    # the allowed roots — compared by per-element string equality, NOT a
    # `case /Applications/*.app` glob. zsh's `*` matches `/`, so a glob would
    # wrongly admit a nested path like `/Applications/evil/x.app`; the exact
    # match is what enforces the fallback's implicit maxdepth-1 boundary.
    [[ "${candidate:t}" == *.app ]] || return 0
    local _parent="${candidate:h}" _root
    for _root in "${KNOWN_APP_BUNDLE_ROOTS[@]}"; do
        [[ "$_parent" == "$_root" ]] && { echo "$candidate"; return 0; }
    done
}

# Registers one pending-removals queue entry's known_path into
# KNOWN_PATH_MAP, called once per entry while parsing the queue (section 5).
# ONLY macos-platform entries are registered: KNOWN_PATH_MAP is keyed by name
# alone (not name+platform), and this script has no legitimate use for a
# windows-platform known_path anyway — admitting one would risk a same-named
# windows entry overwriting a correct macos path for a LATER lookup of that
# same name (e.g. in run_device_removal_tasks, section 8, which shares this
# same global map and runs after the tenant-wide queue loop). No-op when
# known_path is empty (nothing to register) or the entry isn't macos.
register_known_path() {
    local entry_platform="$1" app_name="$2" known_path="$3"
    [[ -n "$known_path" && "$entry_platform" == "macos" ]] || return 0
    KNOWN_PATH_MAP[${app_name:l}]="$known_path"
}

# Same lookup, but only echoes the path when it currently exists on disk —
# for callers asking "is this app installed / where's its bundle right now"
# (install detection, method resolution, removal execution). Everything
# above `resolve_canonical_app_path` explains why this mapping matters
# (Zoom/zoom.us.app-style display-name-vs-bundle-filename mismatches). See
# PAT-771.
#
# Resolution precedence (PAT-806 added the middle step):
#   1. curated labels-allowlist.txt (lookup_labels_app_path)   -- reviewed/EULA'd apps
#   2. known_app_bundles via the pending-removals queue        -- auto-populated, unreviewed
#   3. (caller's own raw "${app_name}.app" name-guess fallback -- not done here)
resolve_canonical_app_path() {
    local app_name="$1"
    local resolved_path
    resolved_path=$(lookup_labels_app_path "$app_name")
    if [[ -n "$resolved_path" && -d "$resolved_path" ]]; then
        echo "$resolved_path"
        return 0
    fi
    resolved_path=$(lookup_known_app_bundle_path "$app_name")
    [[ -n "$resolved_path" ]] && echo "$resolved_path"
}

# ---------------------------------------------------------------------------
# INSTALL / RUNNING DETECTION
# ---------------------------------------------------------------------------

# Returns 0 if the app appears installed (bundle or receipt).
is_installed_macos() {
    local app_name="$1"
    local canonical_path
    canonical_path=$(resolve_canonical_app_path "$app_name")
    [[ -n "$canonical_path" ]] && return 0
    if find /Applications /Applications/Utilities /System/Applications \
            -maxdepth 1 -iname "${app_name}.app" 2>/dev/null | grep -q .; then
        return 0
    fi
    if pkgutil --pkgs 2>/dev/null | grep -qi "${app_name:l}"; then
        return 0
    fi
    return 1
}

# Returns 0 if any process matching the app name is running.
is_running_macos() {
    local app_name="$1"
    pgrep -if "$app_name" > /dev/null 2>&1
}

# Asks the app to quit gracefully; waits up to 20 s.
# Returns 0 when quit, 1 when still running, 2 when execution authority refused.
request_quit_macos() {
    local app_name="$1"
    echo "  Requesting quit: $app_name"
    # Quitting a running app changes endpoint state too. Do not let a queue
    # pass retain an earlier grant while a refresh has suspended the device or
    # its verified-config heartbeat has gone stale.
    if ! legacy_app_execution_enabled; then
        echo "  REFUSING: legacy app-execution gate disabled before quit request."
        return 2
    fi
    /usr/bin/osascript -e "tell application \"${app_name}\" to quit" 2>/dev/null || true
    local waited=0
    while [[ $waited -lt 20 ]]; do
        is_running_macos "$app_name" || return 0
        sleep 2
        (( waited += 2 )) || true
    done
    return 1
}

# ---------------------------------------------------------------------------
# METHOD RESOLUTION
# ---------------------------------------------------------------------------
#
# Sets UNINSTALL_METHOD and UNINSTALL_METHOD_DETAIL.
# Returns 0 on success, 1 for unresolvable.

resolve_uninstall_macos() {
    local app_name="$1"
    local name_lower="${app_name:l}"
    UNINSTALL_METHOD="unresolvable"
    UNINSTALL_METHOD_DETAIL=""

    # 1. pkg receipts — most reliable for pkg-installed apps
    local first_receipt=""
    local receipt_count=0
    while IFS= read -r _r; do
        if [[ "${_r:l}" == *"$name_lower"* ]]; then
            [[ -z "$first_receipt" ]] && first_receipt="$_r"
            (( receipt_count++ )) || true
        fi
    done < <(pkgutil --pkgs 2>/dev/null || true)
    if [[ $receipt_count -gt 0 ]]; then
        UNINSTALL_METHOD="pkg_receipts"
        UNINSTALL_METHOD_DETAIL="$first_receipt"
        return 0
    fi

    # 2. Locate .app bundle — prefer the catalogue's authoritative app_path
    # (handles display-name/bundle-filename mismatches, e.g. Zoom/zoom.us.app)
    # over guessing "${app_name}.app".
    local app_bundle=""
    app_bundle=$(resolve_canonical_app_path "$app_name")
    if [[ -z "$app_bundle" ]]; then
        app_bundle=$(find /Applications /Applications/Utilities -maxdepth 1 \
            -iname "${app_name}.app" -type d 2>/dev/null | head -1)
    fi

    # 3. Vendor uninstaller inside the bundle or in Utilities
    if [[ -n "$app_bundle" ]]; then
        local vendor_ui
        vendor_ui=$(find "$app_bundle" "/Applications/Utilities" \
            -maxdepth 4 -iname "*uninstall*" \( -type f -o -type d \) 2>/dev/null | head -1)
        if [[ -n "$vendor_ui" ]]; then
            UNINSTALL_METHOD="vendor_uninstaller"
            UNINSTALL_METHOD_DETAIL="$vendor_ui"
            return 0
        fi
    fi

    # 4. Catalogue label override (engine/labels/<label>.json with matching name)
    local labels_dir="$BUNDLE_DIR/labels"
    if [[ -d "$labels_dir" ]]; then
        local label_file
        label_file=$("$PYTHON3" - "$labels_dir" "$app_name" <<'PYEOF'
import os, json, sys
labels_dir, target = sys.argv[1], sys.argv[2].lower()
for fn in os.listdir(labels_dir):
    if not fn.endswith('.json'):
        continue
    try:
        d = json.load(open(os.path.join(labels_dir, fn)))
        if d.get('name', '').lower() == target:
            print(os.path.join(labels_dir, fn))
            break
    except Exception:
        pass
PYEOF
        2>/dev/null || true)
        if [[ -n "$label_file" ]]; then
            UNINSTALL_METHOD="catalogue"
            UNINSTALL_METHOD_DETAIL="$label_file"
            return 0
        fi
    fi

    # 5. App bundle fallback — remove bundle + known support paths
    if [[ -n "$app_bundle" ]]; then
        UNINSTALL_METHOD="app_bundle"
        UNINSTALL_METHOD_DETAIL="$app_bundle"
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# EXECUTE UNINSTALL
# ---------------------------------------------------------------------------

execute_uninstall_macos() {
    local app_name="$1"
    local method="$2"
    local method_detail="$3"

    # Both tenant-wide and per-device removal paths converge here. Re-evaluate
    # immediately before privileged removal commands, rather than relying on a
    # grant observed before a long queue pass.
    if ! legacy_app_execution_enabled; then
        echo "  REFUSING: legacy app-execution gate disabled immediately before removal."
        return 2
    fi

    # A method can enumerate or wait before it mutates state. Every command
    # below that can remove, forget, launch an uninstaller, or open one must
    # pass this final check itself so a 401/suspension or stale heartbeat that
    # lands during that work prevents the next mutation.
    legacy_removal_action_allowed() {
        if legacy_app_execution_enabled; then
            return 0
        fi
        echo "  REFUSING: legacy app-execution gate disabled before this removal action."
        return 2
    }

    # Defense in depth (PAT-855): every caller already rejects an unsafe
    # app_name before reaching here, but this is the single choke point where
    # app_name is interpolated into filesystem paths across every method
    # below — refuse again here so a future caller can't reintroduce the bug
    # by skipping the upstream check.
    if ! is_safe_app_name "$app_name"; then
        echo "  REFUSING: '$app_name' failed path-safety validation — no removal performed."
        return 1
    fi

    # PAT-916: every bundle/support-path removal below resolves a path (via
    # resolve_canonical_app_path, a catalogue-supplied app_path, or a fixed
    # support-path template) then acts on the original string with
    # `rm -rf <path>` — the same resolve-then-act shape PAT-856's review
    # gate rejected for a TOCTOU symlink race. Analyzed and confirmed NOT
    # exploitable here (unlike PAT-856), for two independent reasons:
    #   1. Every target is a single leaf directly under a fixed root — no
    #      attacker-writable intermediate path component to pivot through,
    #      unlike PAT-856's recursion under /Users/<user>/.... Empirically
    #      confirmed on macOS: `rm -rf <symlink-to-directory>` unlinks the
    #      symlink itself only; it never follows it or touches the target's
    #      contents. A leaf-level symlink swap has no recursion window to
    #      redirect.
    #   2. Root permissions (confirmed on a real Mac): /Applications is
    #      root:admin 0775 (group-admin-writable — an admin COULD swap an
    #      entry there), but /Library/Application Support and
    #      /Library/Preferences are root:wheel/root:admin 0755 — NOT
    #      group-writable, so no local user can plant or swap anything
    #      there. /Library/Caches is 1777 (world-writable) but sticky-bit
    #      protected: anyone can create a new entry, but only the owner (or
    #      root) can delete/replace an EXISTING one. Combined with (1), even
    #      the most permissive root here offers no path to deleting anything
    #      outside the three allowed roots.
    # Left as string-path rm -rf (not ported to PAT-856's O_NOFOLLOW fd-walk)
    # since there is nothing here for that mechanism to protect against.

    case "$method" in
        pkg_receipts)
            local name_lower="${app_name:l}"
            while IFS= read -r receipt; do
                [[ "${receipt:l}" == *"$name_lower"* ]] || continue
                echo "  Forgetting receipt: $receipt"
                legacy_removal_action_allowed || return 2
                pkgutil --forget "$receipt" 2>/dev/null || true
            done < <(pkgutil --pkgs 2>/dev/null || true)
            # Remove .app bundle too if present — prefer the catalogue's
            # authoritative app_path over guessing "${app_name}.app" (PAT-771).
            local bundle
            bundle=$(resolve_canonical_app_path "$app_name")
            if [[ -z "$bundle" ]]; then
                bundle=$(find /Applications /Applications/Utilities -maxdepth 1 \
                    -iname "${app_name}.app" -type d 2>/dev/null | head -1)
            fi
            if [[ -n "$bundle" ]]; then
                echo "  Removing bundle: $bundle"
                legacy_removal_action_allowed || return 2
                rm -rf "$bundle" || true
            fi
            ;;

        vendor_uninstaller)
            echo "  Running vendor uninstaller: $method_detail"
            if [[ -f "$method_detail" && -x "$method_detail" ]]; then
                legacy_removal_action_allowed || return 2
                timeout 120 "$method_detail" 2>/dev/null || true
            elif [[ -d "$method_detail" && "$method_detail" == *.app ]]; then
                # Uninstaller is itself an .app — open it via open(1)
                legacy_removal_action_allowed || return 2
                open -W "$method_detail" 2>/dev/null || true
            else
                echo "  WARN: vendor uninstaller not executable — falling back to bundle removal"
                local bundle
                bundle=$(resolve_canonical_app_path "$app_name")
                if [[ -z "$bundle" ]]; then
                    bundle=$(find /Applications /Applications/Utilities -maxdepth 1 \
                        -iname "${app_name}.app" -type d 2>/dev/null | head -1)
                fi
                if [[ -n "$bundle" ]]; then
                    legacy_removal_action_allowed || return 2
                    rm -rf "$bundle" || true
                fi
            fi
            ;;

        catalogue)
            local app_path
            app_path=$("$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get('app_path',''))
except Exception:
    print('')
" "$method_detail" 2>/dev/null || echo "")
            if [[ -n "$app_path" && -d "$app_path" ]]; then
                echo "  Removing catalogue-identified bundle: $app_path"
                legacy_removal_action_allowed || return 2
                rm -rf "$app_path" || true
            else
                # Fall back to the allowlist's app_path, then a name-based search
                local bundle
                bundle=$(resolve_canonical_app_path "$app_name")
                if [[ -z "$bundle" ]]; then
                    bundle=$(find /Applications /Applications/Utilities -maxdepth 1 \
                        -iname "${app_name}.app" -type d 2>/dev/null | head -1)
                fi
                if [[ -n "$bundle" ]]; then
                    legacy_removal_action_allowed || return 2
                    rm -rf "$bundle" || true
                fi
            fi
            ;;

        app_bundle)
            echo "  Removing bundle: $method_detail"
            legacy_removal_action_allowed || return 2
            rm -rf "$method_detail" || true
            # Known support path under /Library/Application Support/
            local safe_name="${app_name// /}"
            for support_path in \
                "/Library/Application Support/${app_name}" \
                "/Library/Application Support/${safe_name}" \
                "/Library/Caches/${app_name}" \
                "/Library/Preferences/com.${safe_name:l}.plist"; do
                if [[ -e "$support_path" ]]; then
                    # Defense in depth (PAT-855): even with a validated
                    # app_name, assert the resolved realpath's parent is
                    # EXACTLY the intended root before deleting — mirrors the
                    # exact-parent containment check in
                    # lookup_known_app_bundle_path. This also catches a
                    # symlink planted at $support_path pointing somewhere
                    # else, which app_name validation alone cannot.
                    #
                    # PAT-916: this resolve-then-act shape is analyzed (and
                    # confirmed not exploitable) in the comment block at the
                    # top of execute_uninstall_macos, above.
                    local expected_root=""
                    case "$support_path" in
                        "/Library/Application Support/"*) expected_root="/Library/Application Support" ;;
                        "/Library/Caches/"*) expected_root="/Library/Caches" ;;
                        "/Library/Preferences/"*) expected_root="/Library/Preferences" ;;
                    esac
                    local resolved_support="${support_path:A}"
                    if [[ -z "$expected_root" || "${resolved_support:h}" != "$expected_root" ]]; then
                        echo "  REFUSING support path outside allowed root: $support_path -> $resolved_support"
                        continue
                    fi
                    echo "  Removing support path: $support_path"
                    legacy_removal_action_allowed || return 2
                    rm -rf "$support_path" || true
                fi
            done
            ;;
    esac
}

# ---------------------------------------------------------------------------
# VERIFY REMOVAL
# ---------------------------------------------------------------------------
# Returns one of: gone | residual | still_present

verify_removal_macos() {
    local app_name="$1"
    local name_lower="${app_name:l}"

    local bundle_present="no"
    local labels_path
    labels_path=$(lookup_labels_app_path "$app_name")
    if [[ -n "$labels_path" ]]; then
        [[ -d "$labels_path" ]] && bundle_present="yes"
    elif find /Applications /Applications/Utilities /System/Applications \
            -maxdepth 1 -iname "${app_name}.app" -type d 2>/dev/null | grep -q .; then
        bundle_present="yes"
    fi

    local receipts_present="no"
    if pkgutil --pkgs 2>/dev/null | grep -qi "$name_lower"; then
        receipts_present="yes"
    fi

    if [[ "$bundle_present" == "no" && "$receipts_present" == "no" ]]; then
        echo "gone"
    elif [[ "$bundle_present" == "no" && "$receipts_present" == "yes" ]]; then
        echo "residual"
    else
        echo "still_present"
    fi
}

# ---------------------------------------------------------------------------
# CLASSIFY FAILURE
# ---------------------------------------------------------------------------
# transient: retry next cycle (app in use, locked, needs restart)
# hard: surface as finding, no further attempts

classify_failure() {
    local verify_result="$1"
    local app_name="$2"
    # If bundle is still present after removal attempt, check if it's
    # system-protected (inside /System/) — those are always hard.
    if find /System/Applications -maxdepth 1 \
            -iname "${app_name}.app" 2>/dev/null | grep -q .; then
        echo "hard"
        return 0
    fi
    # MDM-managed apps typically live in /private/var/db/... — check by absence
    # of user-writable bundle. If we can't write into /Applications, likely MDM.
    local mdm_bundle
    mdm_bundle=$(find /Applications -maxdepth 1 -iname "${app_name}.app" \
        2>/dev/null | head -1)
    if [[ -n "$mdm_bundle" ]] && ! test -w "$mdm_bundle" 2>/dev/null; then
        echo "hard"
        return 0
    fi
    # Default: transient (retry next cycle)
    echo "transient"
}

# ---------------------------------------------------------------------------
# 4. PROCESS EACH REMOVAL
# ---------------------------------------------------------------------------

# Accumulate per-removal status as JSON lines (one per removal).
# Each call to process_one_removal appends one line via Python (env-var approach
# matches the provenance record pattern; avoids shell-quoting risks on app names).
# _result_file is created inside the allowlist-guarded block below (section 5) so
# it is not leaked on runs where the allowlist path is skipped (PAT-781).

process_one_removal() {
    local entry_id="$1"
    local app_name="$2"
    local publisher="$3"
    local platform="$4"
    local match_mode="$5"
    local queued_at="$6"

    echo "--- Processing: $app_name (entry $entry_id, queued $queued_at) ---"

    local outcome="unknown"
    local verify_result="not_checked"
    local failure_class=""
    local method="none"
    local method_detail=""
    local recorded_at; recorded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Safety: reject any app_name that could escape a path via a separator or
    # traversal sequence, BEFORE any path is built from it (PAT-855). Must
    # run ahead of is_baseline_protected/is_installed_macos below — those
    # check the display name against a fixed list and the *resolved* path
    # respectively, neither of which validates this raw field.
    if ! is_safe_app_name "$app_name"; then
        echo "  REJECT: '$app_name' contains disallowed characters — refusing to process."
        outcome="rejected_invalid_name"
        failure_class="hard"
        _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
            "$platform" "$match_mode" "$queued_at" \
            "none" "" "$outcome" "$verify_result" "$failure_class"
        _append_result "$entry_id" "$app_name" "$outcome" "$verify_result" "$method" "$recorded_at"
        return 0
    fi

    # Safety: never remove baseline-protected Apple apps
    if is_baseline_protected "$app_name"; then
        echo "  SKIP: $app_name is baseline-protected — ignoring removal intent"
        outcome="skipped_baseline_protected"
        failure_class="hard"
    # Check if installed at all
    elif ! is_installed_macos "$app_name"; then
        echo "  Not installed — already removed."
        outcome="already_removed"
        verify_result="gone"
    else
        # Check if running; request quit or defer
        if is_running_macos "$app_name"; then
            echo "  App is running — requesting quit."
            local quit_rc=0
            request_quit_macos "$app_name" || quit_rc=$?
            if [[ $quit_rc -eq 2 ]]; then
                echo "  Execution authority refused before quit request — removal is terminally refused."
                outcome="authority_refused"
                failure_class="hard"
                _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
                    "$platform" "$match_mode" "$queued_at" \
                    "none" "" "$outcome" "$verify_result" "$failure_class"
                _append_result "$entry_id" "$app_name" "$outcome" "$verify_result" "$method" "$recorded_at"
                return 0
            elif [[ $quit_rc -ne 0 ]]; then
                echo "  App still running after quit request — deferring to next cycle."
                outcome="deferred_app_running"
                failure_class="transient"
                # Record and return without executing
                _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
                    "$platform" "$match_mode" "$queued_at" \
                    "none" "" "$outcome" "$verify_result" "$failure_class"
                _append_result "$entry_id" "$app_name" "$outcome" "$verify_result" "$method" "$recorded_at"
                return 0
            fi
        fi

        # Resolve method
        if resolve_uninstall_macos "$app_name"; then
            method="$UNINSTALL_METHOD"
            method_detail="$UNINSTALL_METHOD_DETAIL"
            echo "  Method: $method ($method_detail)"

            # Execute
            local execute_rc=0
            execute_uninstall_macos "$app_name" "$method" "$method_detail" || execute_rc=$?
            if [[ $execute_rc -eq 2 ]]; then
                echo "  Execution authority refused before removal action — removal is terminally refused."
                outcome="authority_refused"
                failure_class="hard"
                _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
                    "$platform" "$match_mode" "$queued_at" \
                    "$method" "$method_detail" "$outcome" "$verify_result" "$failure_class"
                _append_result "$entry_id" "$app_name" "$outcome" "$verify_result" "$method" "$recorded_at"
                return 0
            fi

            # Verify
            verify_result=$(verify_removal_macos "$app_name")
            echo "  Verify: $verify_result"

            case "$verify_result" in
                gone)
                    outcome="removed"
                    ;;
                residual)
                    outcome="removed_residual"
                    failure_class="transient"
                    ;;
                still_present)
                    failure_class=$(classify_failure "$verify_result" "$app_name")
                    if [[ "$failure_class" == "hard" ]]; then
                        outcome="failed_hard"
                    else
                        outcome="failed_transient"
                    fi
                    ;;
            esac
        else
            echo "  No removal method found — manual action required."
            outcome="manual_removal_required"
            failure_class="hard"
        fi
    fi

    echo "  Outcome: $outcome"

    _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
        "$platform" "$match_mode" "$queued_at" \
        "$method" "$method_detail" "$outcome" "$verify_result" "${failure_class:-}"

    _append_result "$entry_id" "$app_name" "$outcome" "$verify_result" "$method" "$recorded_at"
}

_append_result() {
    local eid="$1" name="$2" outcome="$3" verify="$4" method="$5" recorded_at="$6"
    PATCHED_R_EID="$eid" PATCHED_R_NAME="$name" PATCHED_R_OUTCOME="$outcome" \
    PATCHED_R_VERIFY="$verify" PATCHED_R_METHOD="$method" PATCHED_R_TS="$recorded_at" \
    "$PYTHON3" - "$_result_file" <<'PYEOF'
import json, os, sys
g = lambda k: os.environ.get(k, '')
row = {'entry_id': int(g('PATCHED_R_EID') or 0), 'name': g('PATCHED_R_NAME'),
       'outcome': g('PATCHED_R_OUTCOME'), 'verify_result': g('PATCHED_R_VERIFY'),
       'method': g('PATCHED_R_METHOD'), 'recorded_at': g('PATCHED_R_TS')}
with open(sys.argv[1], 'a') as f:
    f.write(json.dumps(row) + '\n')
PYEOF
}

_emit_uninstall_provenance() {
    local entry_id="$1" app_name="$2" publisher="$3" platform_field="$4"
    local match_mode="$5" queued_at="$6"
    local method="$7" method_detail="$8"
    local outcome="$9" verify_result="${10}" failure_class="${11}"

    local prov
    prov=$(mktemp /tmp/.patched-uninst-prov.XXXXXX)

    PATCHED_TENANT_ID="$TENANT_ID" \
    PATCHED_HW_UUID="$HW_UUID" \
    PATCHED_COMPUTER_NAME="$COMPUTER_NAME" \
    PATCHED_ENTRY_ID="$entry_id" \
    PATCHED_APP_NAME="$app_name" \
    PATCHED_APP_PUBLISHER="$publisher" \
    PATCHED_APP_PLATFORM="$platform_field" \
    PATCHED_APP_MATCH_MODE="$match_mode" \
    PATCHED_QUEUED_AT="$queued_at" \
    PATCHED_METHOD="$method" \
    PATCHED_METHOD_DETAIL="$method_detail" \
    PATCHED_OUTCOME="$outcome" \
    PATCHED_VERIFY_RESULT="$verify_result" \
    PATCHED_FAILURE_CLASS="$failure_class" \
    "$PYTHON3" - "$prov" <<'PYEOF'
import json, datetime, os, sys
g = lambda k: os.environ.get(k, '')
rec = {
    'record_type': 'app_uninstall',
    'schema_version': 1,
    'tenant_id': g('PATCHED_TENANT_ID'),
    'device': {'hw_uuid': g('PATCHED_HW_UUID'), 'computer_name': g('PATCHED_COMPUTER_NAME')},
    'app': {
        'entry_id': int(g('PATCHED_ENTRY_ID') or 0),
        'name': g('PATCHED_APP_NAME'),
        'publisher': g('PATCHED_APP_PUBLISHER') or None,
        'platform': g('PATCHED_APP_PLATFORM'),
        'match_mode': g('PATCHED_APP_MATCH_MODE'),
    },
    'uninstall': {
        'method': g('PATCHED_METHOD'),
        'method_detail': g('PATCHED_METHOD_DETAIL') or None,
        'queued_at': g('PATCHED_QUEUED_AT'),
        'window_hours': 24,
    },
    'outcome': g('PATCHED_OUTCOME'),
    'verify_result': g('PATCHED_VERIFY_RESULT') or None,
    'failure_class': g('PATCHED_FAILURE_CLASS') or None,
    'recorded_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
}
with open(sys.argv[1], 'w') as f: json.dump(rec, f)
PYEOF

    emit_provenance "$prov"
    rm -f "$prov"
}

# ---------------------------------------------------------------------------
# PER-DEVICE REMOVAL TASKS — decision + reporting (PAT-781)
# ---------------------------------------------------------------------------
# The operator queues a removal for one app on one device. The agent polls the
# device-scoped queue, runs the SAME resolve/execute/verify/classify engine as
# the allowlist path, and reports the resulting state back to the server (the
# task row is the source of truth — no local status file). Agent-reportable
# states, per the server contract: in-progress | removed | residual | manual |
# failed. Terminal states mirror into the enforcement audit trail server-side.

# Runs the engine for one app and sets _DT_STATE / _DT_DETAIL (globals, so the
# engine's own progress echoes still reach the log rather than being captured).
_device_task_decide() {
    local app_name="$1"
    local method method_detail verify_result failure_class
    _DT_STATE=""
    _DT_DETAIL=""

    # Reject any app_name that could escape a path via a separator or
    # traversal sequence, BEFORE any path is built from it (PAT-855). See the
    # matching guard (and its rationale) in process_one_removal above.
    if ! is_safe_app_name "$app_name"; then
        echo "  REJECT: '$app_name' contains disallowed characters — refusing to process."
        _DT_STATE="failed"
        _DT_DETAIL="invalid app_name: contains disallowed characters (path traversal guard)"
        return 0
    fi

    # Hard safety invariant: never remove an Apple-signed baseline app, even when
    # an operator explicitly queued it. Reported as 'manual' (needs a human).
    if is_baseline_protected "$app_name"; then
        echo "  SKIP: $app_name is baseline-protected — refusing removal."
        _DT_STATE="manual"
        _DT_DETAIL="baseline-protected: refusing to remove an OS baseline app"
        return 0
    fi

    # Idempotent: not installed → the desired end state (absent) already holds.
    if ! is_installed_macos "$app_name"; then
        echo "  Not installed — already removed."
        _DT_STATE="removed"
        _DT_DETAIL="not installed at run time (already removed)"
        return 0
    fi

    # Running → ask it to quit; defer (retry next cycle) if it won't.
    if is_running_macos "$app_name"; then
        echo "  App is running — requesting quit."
        local quit_rc=0
        request_quit_macos "$app_name" || quit_rc=$?
        if [[ $quit_rc -eq 2 ]]; then
            echo "  Execution authority refused before quit request — task fails terminally."
            _DT_STATE="failed"
            _DT_DETAIL="execution authority refused before quit request"
            return 0
        elif [[ $quit_rc -ne 0 ]]; then
            echo "  Still running after quit request — deferring to next cycle."
            _DT_STATE="in-progress"
            _DT_DETAIL="app was running and did not quit; will retry next cycle"
            return 0
        fi
    fi

    if ! resolve_uninstall_macos "$app_name"; then
        echo "  No removal method resolved — manual action required."
        _DT_STATE="manual"
        _DT_DETAIL="no removal method could be resolved"
        return 0
    fi
    method="$UNINSTALL_METHOD"
    method_detail="$UNINSTALL_METHOD_DETAIL"
    echo "  Method: $method ($method_detail)"

    local execute_rc=0
    execute_uninstall_macos "$app_name" "$method" "$method_detail" || execute_rc=$?
    if [[ $execute_rc -eq 2 ]]; then
        echo "  Execution authority refused before removal action — task fails terminally."
        _DT_STATE="failed"
        _DT_DETAIL="execution authority refused before removal action"
        return 0
    fi

    verify_result=$(verify_removal_macos "$app_name")
    echo "  Verify: $verify_result"
    case "$verify_result" in
        gone)
            _DT_STATE="removed"
            _DT_DETAIL="removed via $method"
            ;;
        residual)
            _DT_STATE="residual"
            _DT_DETAIL="app bundle removed; package receipts remain (method $method)"
            ;;
        still_present)
            failure_class=$(classify_failure "$verify_result" "$app_name")
            if [[ "$failure_class" == "hard" ]]; then
                _DT_STATE="failed"
                _DT_DETAIL="still present after $method; OS/MDM-protected"
            else
                # Transient — keep the task live (in-progress) so it is retried.
                _DT_STATE="in-progress"
                _DT_DETAIL="still present after $method; will retry next cycle"
            fi
            ;;
        *)
            _DT_STATE="failed"
            _DT_DETAIL="unexpected verify result: ${verify_result:-unknown}"
            ;;
    esac
}

# Polls GET /v1/devices/{deviceID}/removal-tasks/pending, executes each task via
# the engine, and POSTs the batch of results to .../removal-tasks/report.
run_device_removal_tasks() {
    echo "--- Per-device removal tasks (PAT-781) ---"

    local device_id
    device_id=$("$PYTHON3" - "$POSTURE_FILE" 2>/dev/null <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get('device', {}).get('id', '') or '', end='')
except Exception:
    print('', end='')
PYEOF
    )
    if [[ -z "$device_id" ]]; then
        echo "  No device id in posture cache ($POSTURE_FILE) — skipping device-task poll."
        return 0
    fi

    local base="$API_URL/v1/devices/$device_id/removal-tasks"

    # --- Fetch pending tasks (GET; HMAC over empty body) ---
    local sig ts nonce resp code
    ts=$(date -u +%s)
    nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    sig=$(hmac_empty "device_removal_tasks_pending" "$ts" "$nonce")
    resp=$(mktemp /tmp/.patched-dt-resp.XXXXXX)
    code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o "$resp" -w "%{http_code}" --max-time 30 \
        -H "X-Patched-Signature: $sig" \
        -H "X-Patched-Timestamp: $ts" \
        -H "X-Patched-Nonce: $nonce" \
        -H "Accept: application/json" \
        "$base/pending" 2>/dev/null) || code="000"

    if [[ "$code" != "200" ]]; then
        echo "  removal-tasks/pending fetch failed: HTTP $code — will retry next run."
        rm -f "$resp"
        return 0
    fi

    local items
    items=$(mktemp /tmp/.patched-dt-items.XXXXXX)
    "$PYTHON3" - "$resp" <<'PYEOF' > "$items"
import json, sys
try:
    tasks = json.load(open(sys.argv[1])).get('tasks', [])
except Exception:
    tasks = []
for t in tasks:
    tid = str(t.get('task_id', '') or '')
    name = t.get('app_name', '') or ''
    if tid and name:
        print('\x1f'.join([tid, name]))
PYEOF
    rm -f "$resp"

    local n
    n=$(awk 'NF{c++} END{print c+0}' "$items")
    echo "  Pending device removal tasks: $n"
    if [[ "$n" -eq 0 ]]; then
        rm -f "$items"
        return 0
    fi

    # --- Execute each task; accumulate reports ---
    local reports
    reports=$(mktemp /tmp/.patched-dt-reports.XXXXXX)
    local task_id app_name
    while IFS=$'\x1f' read -r task_id app_name; do
        [[ -z "$task_id" || -z "$app_name" ]] && continue
        echo "  Task $task_id: $app_name"
        _device_task_decide "$app_name"
        echo "  -> state=$_DT_STATE"
        printf '%s\x1f%s\x1f%s\n' "$task_id" "$_DT_STATE" "$_DT_DETAIL" >> "$reports"
    done < "$items"
    rm -f "$items"

    # --- Build + POST the report body ---
    local body
    body=$(mktemp /tmp/.patched-dt-body.XXXXXX)
    "$PYTHON3" - "$reports" "$body" <<'PYEOF'
import json, sys
out = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip('\n')
        if not line:
            continue
        parts = line.split('\x1f')
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        out.append({'task_id': parts[0], 'state': parts[1],
                    'detail': parts[2] if len(parts) > 2 else ''})
with open(sys.argv[2], 'w') as f:
    json.dump({'reports': out}, f)
PYEOF
    rm -f "$reports"

    local rsig rts rnonce rcode
    rts=$(date -u +%s)
    rnonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    rsig=$(compute_hmac "$body" "device_removal_tasks_report" "$rts" "$rnonce")
    rcode=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time 30 \
        -X POST "$base/report" \
        -H "X-Patched-Signature: $rsig" \
        -H "X-Patched-Timestamp: $rts" \
        -H "X-Patched-Nonce: $rnonce" \
        -H "Content-Type: application/json" \
        --data-binary "@$body" 2>/dev/null) || rcode="000"
    rm -f "$body"

    if [[ "$rcode" == 2* ]]; then
        echo "  removal-tasks/report POST -> $rcode"
    else
        echo "  removal-tasks/report POST -> ${rcode:-network-error} (results will be re-reported next run)"
    fi
}

# --- BEGIN resolve_user_removable (PAT-910) ---------------------------------
# resolve_user_removable — decide, FAIL CLOSED, whether an app may be removed,
# by reading the cached posture's app_policy.user_removable. Prints exactly
# "true" (removable) on the single verified-allow path; ANY other outcome
# (including "false", empty output from a killed interpreter, or garbage) means
# refuse — callers MUST allow only on the exact string "true", never refuse
# only on "false".
#
# The posture cache is written only by the verified fetch path
# (patched-fetch-posture.sh -> verify-posture.py: Ed25519 signature + tenant
# binding + anti-rollback, then structural validation). This read re-checks the
# tenant binding as defence in depth and treats an UNVERIFIED posture as
# ABSENT. The ENTIRE resolution runs inside try/except and every shape is
# validated (posture an object, app_policy an object, apps a list, entries
# objects), so a malformed shape can never raise past a "false" — a missing,
# unparseable, wrong-tenant, or malformed posture all yield "false" (refuse).
# That closes the estate-review fail-open where a missing or forged posture
# unlocked a root-privileged removal a mandatory policy forbids — an absent
# posture takes the SAFE branch (refuse), never fail-open. Removal is permitted
# only when a VERIFIED posture (tenant_id matches the local credential) is
# well-formed AND the app is either not policy-listed or carries a literal
# user_removable: true.
#
# Args: <posture_file> <app_name> <expected_tenant_id>
resolve_user_removable() {
    local _pf="$1" _app="$2" _tenant="$3"
    "$PYTHON3" - "$_pf" "$_app" "$_tenant" 2>/dev/null <<'PYEOF'
import json, sys

def refuse():
    print("false")
    sys.exit(0)

try:
    pf, name, tenant = sys.argv[1], sys.argv[2].lower(), sys.argv[3]
    if not tenant:
        refuse()                       # no local tenant to bind against -> SAFE (refuse)
    posture = json.load(open(pf))
    if not isinstance(posture, dict):
        refuse()                       # malformed root -> SAFE (refuse)
    if posture.get("tenant_id") != tenant:
        refuse()                       # unverified/wrong-tenant -> treat as absent -> SAFE (refuse)
    ap = posture.get("app_policy")
    if not isinstance(ap, dict):
        refuse()                       # app_policy null/missing/non-object -> SAFE (refuse)
    apps = ap.get("apps")
    if not isinstance(apps, list):
        refuse()                       # apps missing/non-list -> SAFE (refuse)
    for a in apps:
        if not isinstance(a, dict):
            refuse()                   # malformed entry -> SAFE (refuse)
        an = a.get("app_name")
        if isinstance(an, str) and an.lower() == name:
            # Only a literal JSON true permits removal; false, missing, or any
            # other type refuses.
            print("true" if a.get("user_removable") is True else "false")
            sys.exit(0)
    print("true")                      # verified well-formed posture, app not policy-listed -> removable
except SystemExit:
    raise
except Exception:
    print("false")                     # ANY unexpected error -> SAFE (refuse)
PYEOF
}
# --- END resolve_user_removable (PAT-910) -----------------------------------

# ---------------------------------------------------------------------------
# 5. ITERATE OVER PENDING REMOVALS  (tenant-wide allowlist path)
# ---------------------------------------------------------------------------

if [[ $_run_allowlist -eq 1 ]]; then

# Per-removal status accumulator (drained into uninstall-status.json below).
_result_file=$(mktemp /tmp/.patched-removals-result.XXXXXX)

# Parse the JSON response into a flat text file (unit separator \\x1f as
# field delimiter) so the while-read loop can iterate without a subshell.
# known_path (PAT-806, 7th field) is the app's known_app_bundles path when
# the platform found one for this entry's (name, platform); empty string
# when absent/null — never trust it blindly, existence is re-checked on disk
# by lookup_known_app_bundle_path before any caller sees it.
_items_file=$(mktemp /tmp/.patched-removals-items.XXXXXX)
"$PYTHON3" - "$_resp_file" <<'PYEOF' > "$_items_file"
import json, sys
items = json.load(open(sys.argv[1])).get('items', [])
for item in items:
    fields = [
        str(item.get('entry_id', '')),
        item.get('name', ''),
        item.get('publisher', '') or '',
        item.get('platform', 'any'),
        item.get('match_mode', 'exact_name'),
        item.get('queued_at', ''),
        item.get('known_path') or '',
    ]
    print('\x1f'.join(fields))
PYEOF
rm -f "$_resp_file"

# ---------------------------------------------------------------------------
# FILTER BY --app-id (user-initiated runs only)
# ---------------------------------------------------------------------------
# When an identifier was requested, restrict to the matching queue entry.
# Absence from the server queue means not queued or not policy-removable.

if [[ -n "$FILTER_APP_ID" ]]; then
    _filtered_file=$(mktemp "$STATE_DIR/.patched-removals-filtered.XXXXXX")
    _filter_found=0
    while IFS=$'\x1f' read -r _feid _fname _fpub _fplat _fmm _fqa _fkp; do
        [[ -z "$_fname" ]] && continue
        if [[ "${_fname:l}" == "${FILTER_APP_ID:l}" ]]; then
            printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
                "$_feid" "$_fname" "$_fpub" "$_fplat" "$_fmm" "$_fqa" "$_fkp" >> "$_filtered_file"
            _filter_found=1
        fi
    done < "$_items_file"
    rm -f "$_items_file"
    _items_file="$_filtered_file"
    if [[ $_filter_found -eq 0 ]]; then
        echo "ERROR: '$FILTER_APP_ID' is not in the pending-removals queue — not queued or not policy-removable."
        rm -f "$_items_file"
        exit 1
    fi
fi

while IFS=$'\x1f' read -r entry_id app_name publisher platform_field match_mode queued_at known_path; do
    [[ -z "$app_name" ]] && continue

    # PAT-806: register this entry's known_app_bundles path (if any — and if
    # macos-platform, see register_known_path's doc comment) so
    # resolve_canonical_app_path's middle step can find it below.
    register_known_path "$platform_field" "$app_name" "$known_path"

    # PAT-910: engine-side user_removable policy gate, enforced FAIL CLOSED in the
    # daemon (not only the UI). resolve_user_removable reads the cached posture,
    # re-checks the tenant binding, and refuses whenever posture is absent,
    # unparseable, malformed, or bound to a different tenant — so a missing or
    # forged posture can never unlock a root-privileged removal a mandatory
    # policy forbids. This replaces the previous fail-open flagged in the estate
    # review. Removal therefore requires a verified posture, which flows once
    # posture-poll is wired (the deliberate follow-up — see the PR body).
    #
    # The check is allow-listed on the EXACT string "true": if the helper is
    # killed, its interpreter is missing, or it emits anything unexpected, the
    # value is not "true" and the removal is refused — never gate on == "false".
    _user_removable=$(resolve_user_removable "$STATE_DIR/posture.json" "$app_name" "$TENANT_ID")
    if [[ "$_user_removable" != "true" ]]; then
        echo "SKIP: $app_name is not confirmed user_removable in a verified posture — removal refused."
        _emit_uninstall_provenance "$entry_id" "$app_name" "$publisher" \
            "$platform_field" "$match_mode" "$queued_at" \
            "none" "" "skipped_user_policy" "not_checked" "hard"
        _append_result "$entry_id" "$app_name" "skipped_user_policy" "not_checked" "none" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        continue
    fi

    process_one_removal "$entry_id" "$app_name" "$publisher" "$platform_field" "$match_mode" "$queued_at" || true
done < "$_items_file"
rm -f "$_items_file"

# ---------------------------------------------------------------------------
# 6. WRITE UNINSTALL STATUS
# ---------------------------------------------------------------------------

RUN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

"$PYTHON3" - "$UNINSTALL_STATUS_FILE" "$RUN_STARTED_AT" "$RUN_FINISHED_AT" "$_result_file" <<'PYEOF'
import json, sys, datetime, os
status_file, started_at, finished_at, result_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
doc = {
    'schema_version': 1,
    'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'last_run': {'started_at': started_at, 'finished_at': finished_at},
    'removals': [],
}
try:
    with open(result_file) as rf:
        for line in rf:
            line = line.strip()
            if line:
                try:
                    doc['removals'].append(json.loads(line))
                except Exception:
                    pass
except FileNotFoundError:
    pass
tmp = status_file + '.tmp'
with open(tmp, 'w') as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, status_file)
PYEOF
rm -f "$_result_file"

echo "Uninstall run complete. Status: $UNINSTALL_STATUS_FILE"

fi  # _run_allowlist

# ---------------------------------------------------------------------------
# 8. PER-DEVICE REMOVAL TASKS  (PAT-781)
# ---------------------------------------------------------------------------
# Distinct from the tenant-wide allowlist above: an operator queues a removal
# for THIS specific device via the dashboard. Runs on every scheduled pass
# (skipped on user-initiated --app-id allowlist triggers), reusing the same
# resolve/execute/verify/classify engine functions defined above.

if [[ -z "$FILTER_APP_ID" ]]; then
    run_device_removal_tasks || echo "WARN: device removal-task phase errored — will retry next run."
fi

# ---------------------------------------------------------------------------
# 9. DRAIN PROVENANCE QUEUE
# ---------------------------------------------------------------------------

drain_provenance_queue

echo "=== patched-uninstall run finished $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
