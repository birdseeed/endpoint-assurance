#!/bin/zsh
##############################################################################
# patched-install.sh — catalogue-driven app install engine for the Patched
#                      pending-installs queue.
#
# Run by the LaunchDaemon `com.patched.install-check` (as root). On each
# run it:
#   1. Verifies its own bundle integrity (same SHA-256 manifest as
#      patched-update.sh — closes the same attack surface on the install path).
#   2. Gates on the managed agent tier, same as the uninstall engine
#      (patched-uninstall.sh, PAT-376/PAT-379).
#   3. Fetches the tenant's pending-install queue from the platform
#      (GET /v1/allowlist/pending-installs) — PAT-659.
#   4. For each queued app: checks local inventory first (idempotent — already
#      installed = skip), then dispatches to the correct install engine:
#        - package_source=vendor: Installomator label dispatch (PAT-463).
#        - package_source=mas:    Mac App Store via the `mas` CLI.
#        - package_source=winget: Windows-only; skipped on macOS.
#   5. Reports each outcome as a structured audit event to POST /v1/events
#      (PAT-651, remapped from the never-working POST /v1/agent-logs call
#      under PAT-1243 — see report_install_event() below).
#   6. Emits PAT-652 JSON-lines log entries to
#      /Library/Logs/Patched/install.jsonl alongside the plain-text log.
#
# CONVENTIONS (shared with patched-update.sh and patched-uninstall.sh):
#   - `set -u` only. NOT `set -euo pipefail` — codesign/pkgutil return
#     non-zero on stubbed or partially-installed bundles.
#   - /usr/bin/python3 hardcoded (sudo strips PATH on macOS).
#   - Never use `path` / `fpath` / `cdpath` / `manpath` / `infopath` as
#     variable names (zsh typeset -T trap — silently corrupts $PATH).
#
# PAT-661: install-side twin of the uninstall queue (PAT-376/PAT-379).
# Tier 2+, MSA-authorised (PAT-112). GitHub-Non-Author-Review gate before first ship.
##############################################################################

set -u

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BUNDLE_DIR="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}"
INSTALLOMATOR="$BUNDLE_DIR/Installomator.sh"
ALLOWLIST="$BUNDLE_DIR/labels-allowlist.txt"
MANIFEST="$BUNDLE_DIR/manifest.sha256"

STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
INSTALL_STATUS_FILE="$STATE_DIR/install-status.json"
AGENT_CONFIG_FILE="$STATE_DIR/agent-config.json"
AGENT_CONFIG_SHA256_FILE="$STATE_DIR/agent-config.sha256"
AGENT_CONFIG_HEARTBEAT_FILE="$STATE_DIR/agent-config.checked"

CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-install.log}"

# PAT-1243: same ring-buffer queue and override name as patched-update.sh's
# EVENTS_QUEUE (PAT-499) — both scripts share one queue and one directory
# convention, and patched-update.sh's drain_events_queue() sweeps whatever
# either script wrote on every update cycle.
EVENTS_QUEUE="${PATCHED_EVENTS_QUEUE:-/var/db/patched/events-queue}"

# PAT-652: structured JSON-lines log alongside the existing plain-text log.
JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_FILE="$JSONL_LOG_DIR/install.jsonl"
JSONL_COMPONENT="install"

PROXY_RESOLVE="$BUNDLE_DIR/patched-proxy-resolve.py"
FETCH_CONFIG="$BUNDLE_DIR/patched-fetch-config.sh"

PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] || { echo "FATAL: /usr/bin/python3 missing"; exit 1; }
LEGACY_APP_EXECUTION_GATE="$BUNDLE_DIR/patched-legacy-app-execution-gate.py"

# >>> PATCHED_LEGACY_APP_EXECUTION_ENABLED_START
# Evaluated at each legacy execution seam from a single hash-and-parse snapshot.
# Require the root helper's current bytes to have one exact manifest entry.
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

mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR" "$EVENTS_QUEUE"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== patched-install run started $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

RUN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# PAT-652: STRUCTURED LOGGING HELPERS
# Writes JSON-lines to /Library/Logs/Patched/install.jsonl alongside the
# existing plain-text log. Never log bearer_token, hmac_secret, or proxy creds.
# ---------------------------------------------------------------------------

_init_jsonl_log() {
    install -d -m 755 "$JSONL_LOG_DIR" 2>/dev/null \
        || mkdir -p "$JSONL_LOG_DIR" 2>/dev/null || return 0
    touch "$JSONL_LOG_FILE" 2>/dev/null && chmod 644 "$JSONL_LOG_FILE" 2>/dev/null || true
    local _sz; _sz=$(wc -c < "$JSONL_LOG_FILE" 2>/dev/null | tr -d '[:space:]') || _sz=0
    (( _sz > 10485760 )) && : > "$JSONL_LOG_FILE" || true
    find "$JSONL_LOG_DIR" -maxdepth 1 -name "$(basename "$JSONL_LOG_FILE")" \
        -mtime "+14" -delete 2>/dev/null || true
}

log_jsonl() {
    # log_jsonl <level> <msg> [<fields-json>]
    local _lvl="$1" _msg="$2" _fields="${3:-}"
    [[ -n "$_fields" ]] || _fields="{}"
    PATCHED_LOG_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    PATCHED_LOG_LEVEL="$_lvl" \
    PATCHED_LOG_COMPONENT="$JSONL_COMPONENT" \
    PATCHED_LOG_MSG="$_msg" \
    PATCHED_LOG_FIELDS="$_fields" \
    "$PYTHON3" -c '
import json, os, re, sys
_REDACT = [
    (re.compile(r"/Users/[^/\s\"]+/"), "/Users/[REDACTED]/"),
    (re.compile(r"/home/[^/\s\"]+/"), "/home/[REDACTED]/"),
    (re.compile(r"https?://[^:@\s\"]+:[^@\s\"]+@"), "https://[REDACTED]@"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{10,}"), r"\1[REDACTED]"),
]
def _r(s):
    for pat, rep in _REDACT:
        s = pat.sub(rep, s)
    return s
try:
    raw_fields = os.environ.get("PATCHED_LOG_FIELDS") or "{}"
    try:
        fields = json.loads(raw_fields)
    except Exception:
        fields = {"_raw": raw_fields}
    if isinstance(fields, dict):
        fields = {k: _r(v) if isinstance(v, str) else v for k, v in fields.items()}
    rec = {
        "ts":        os.environ["PATCHED_LOG_TS"],
        "level":     os.environ["PATCHED_LOG_LEVEL"],
        "component": os.environ["PATCHED_LOG_COMPONENT"],
        "msg":       _r(os.environ["PATCHED_LOG_MSG"]),
        "fields":    fields,
    }
    os.makedirs(os.path.dirname(sys.argv[1]), exist_ok=True)
    with open(sys.argv[1], "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
except Exception:
    pass
' "$JSONL_LOG_FILE" 2>/dev/null || true
}

_init_jsonl_log
log_jsonl "info" "install run started"

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
    log_jsonl "error" "bundle integrity failed — aborting"
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

# Catalogue install requires the managed tier, matching the uninstall engine
# (patched-uninstall.sh) gate for allowlist enforcement.
# >>> PATCHED_INSTALL_TIER_GATE_START
case "$AGENT_TIER" in
    managed) ;;
    *)
        echo "Tier gate: $AGENT_TIER is not managed; skipping install run."
        log_jsonl "info" "tier gate: skipping" "{\"tier\":\"$AGENT_TIER\"}"
        exit 0
        ;;
esac
echo "Tier gate OK: $AGENT_TIER"
# <<< PATCHED_INSTALL_TIER_GATE_END

# PAT-1481: this direct pending-install executor stays quarantined unless the
# signed explicit containment grant is present. This is additional to the tier,
# catalogue, provenance and per-operation gates below, never a replacement.
if ! legacy_app_execution_enabled; then
    echo "Legacy app-execution gate disabled — skipping pending-install run."
    log_jsonl "info" "legacy app-execution gate: skipping pending install" "{}"
    exit 0
fi

# ---------------------------------------------------------------------------
# LOCK — one run at a time
# ---------------------------------------------------------------------------

LOCK_DIR="$STATE_DIR/.patched-install.lock"
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
# PROXY RESOLUTION  (mirrors patched-uninstall.sh / patched-update.sh)
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
# HMAC HELPERS
# ---------------------------------------------------------------------------

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body so a captured
# signed request cannot be replayed. Signing input is:
#   b"patched-hmac-v3\nPOST\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body
# ts and nonce MUST be the exact strings sent in the X-Patched-Timestamp /
# X-Patched-Nonce headers for this same request — callers generate ts+nonce
# FIRST, then pass them into these helpers AND into the headers.

# HMAC over empty body (GET has no request body). hmac_empty <endpoint-id> <ts> <nonce>
hmac_empty() {
    "$PYTHON3" - "$1" "$2" "$3" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
msg = b"patched-hmac-v3\nGET\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n"
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# HMAC over a file (for POST bodies). compute_hmac <body-file> <endpoint-id> <ts> <nonce>
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
# INSTALLED-APP CHECK
# ---------------------------------------------------------------------------

# Returns 0 if the app appears installed by display_name (bundle or receipt).
# Used as a fallback when no label JSON is available; prefer is_installed_vendor
# for vendor-source apps where the package_id label is known.
is_installed_macos() {
    local app_name="$1"
    if find /Applications /Applications/Utilities /System/Applications \
            -maxdepth 1 -iname "${app_name}.app" -type d 2>/dev/null | grep -q .; then
        return 0
    fi
    # pkgutil fallback: pkg receipts use reversed-domain notation (com.google.Chrome).
    # Use the last word of the display name — usually the most app-specific token
    # (e.g. "Chrome" from "Google Chrome") — to avoid false-negatives from spaces.
    local _last_word="${app_name##* }"
    if [[ -n "$_last_word" ]] && pkgutil --pkgs 2>/dev/null | grep -qi "$_last_word"; then
        return 0
    fi
    return 1
}

# Resolves the canonical app_path for a vendor (Installomator) label from the
# bundled label JSON at $BUNDLE_DIR/labels/<label>.json. Prints the path and
# returns 0 on success; prints nothing and returns 0 when no label JSON exists
# or it has no app_path field (callers must handle the empty-string case).
resolve_label_app_path() {
    local _label="$1"
    local _label_file="$BUNDLE_DIR/labels/${_label}.json"
    [[ -f "$_label_file" ]] || return 0
    "$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get('app_path', ''), end='')
except Exception:
    print('', end='')
" "$_label_file" 2>/dev/null || true
}

# Returns 0 if the vendor (Installomator-label) app is installed.
# Prefers the label manifest's app_path (stable, bundle-name-independent) over
# a display_name search. Falls back to is_installed_macos when no label JSON
# is deployed (e.g. a newly added label not yet in the local bundle).
# Used for the PRE-INSTALL idempotent check only. For post-install outcome
# determination use vendor_presence(), which distinguishes the "can't verify"
# case from the "authoritatively absent" case.
is_installed_vendor() {
    local _label="$1" _display_name="$2"
    local _app_path
    _app_path=$(resolve_label_app_path "$_label")
    if [[ -n "$_app_path" ]]; then
        # Label manifest has an authoritative path — use it directly.
        [[ -d "$_app_path" ]] && return 0 || return 1
    fi
    # Fallback: display_name bundle search (handles labels without a local JSON).
    is_installed_macos "$_display_name"
}

# vendor_presence <label> <display_name>
# Echoes one of three signals:
#   present  — app is confirmed present (authoritative app_path hit, or display_name match)
#   absent   — label JSON exists with an authoritative app_path AND that path is missing
#   unknown  — no label JSON (or no app_path field) AND display_name fallback also negative
#
# "unknown" means we have no authoritative signal to contradict the installer's exit code.
# Callers (the VENDOR post-install branch) use this to avoid reporting "failed" — and
# triggering perpetual reinstall churn — when the only evidence of failure is a fragile
# display_name search that can't resolve apps whose bundle basename differs from their
# server display_name (e.g. label "zoom" → /Applications/zoom.us.app vs "Zoom").
vendor_presence() {
    local _label="$1" _display_name="$2"
    local _app_path
    _app_path=$(resolve_label_app_path "$_label")
    if [[ -n "$_app_path" ]]; then
        # Authoritative path from label manifest JSON — trust it directly.
        [[ -d "$_app_path" ]] && echo "present" || echo "absent"
        return 0
    fi
    # No authoritative path (no label JSON or no app_path field in it).
    # Fall back to display_name bundle search.
    if is_installed_macos "$_display_name"; then
        echo "present"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# PAT-1236: PINNED SHA-256 LOOKUP (fresh-install path)
#
# Byte-identical copy of get_pinned_sha256() from patched-update.sh (same
# sentinel markers). Retired with the signed app catalogue in PAT-2245: it
# never reads a catalogue file and every label is NO_PIN (exit 3), which the
# fresh-install path below refuses. Covered by
# endpoint/test-get-pinned-sha256.zsh (sentinel-extracted, not a copy).
# >>> PATCHED_GET_PINNED_SHA256_START
# PAT-2245: the signed app catalogue is retired, so there is no trustworthy
# pin for any label. This deliberately never reads CATALOGUE_FILE: cache
# clean-up on upgrade is best effort, and with the freshness gate gone a
# leftover catalogue.json could otherwise hand back a stale but well-formed
# pin. Every label is NO_PIN (exit 3, nothing on stdout), which every caller
# already refuses, so this quarantined install path cannot install anything.
get_pinned_sha256() {  # get_pinned_sha256 <label>
    echo "install refused: catalogue retired (PAT-2245): ${1:-}" >&2
    return 3
}
# <<< PATCHED_GET_PINNED_SHA256_END

# Returns 0 if the MAS app (by numeric App Store ID) is installed.
# Uses `mas list` if the `mas` CLI is available; falls back to false (will attempt install).
is_installed_mas() {
    local app_id="$1"
    local mas_bin
    mas_bin=$(command -v mas 2>/dev/null || true)
    [[ -z "$mas_bin" ]] && return 1   # no mas CLI — can't determine, treat as absent
    mas list 2>/dev/null | grep -q "^${app_id}[[:space:]]" && return 0 || return 1
}

# Max events to keep on disk (ring-buffer cap) — same value as
# patched-update.sh's EVENTS_QUEUE_MAX; the two scripts share the queue.
EVENTS_QUEUE_MAX=1000

# ---------------------------------------------------------------------------
# >>> PATCHED_REPORT_INSTALL_EVENT_START
# PAT-651/PAT-1243: REPORT INSTALL OUTCOME AS AN AUDIT EVENT (POST /v1/events)
#
# PAT-651 originally posted a custom catalogue_install payload to
# POST /v1/agent-logs. That endpoint is exclusively the on-demand gzipped
# log-bundle request path (it requires an X-Patched-Log-Request-ID this call
# never sent) and correctly rejected every call with HTTP 400 — no
# successful install outcome ever reached the server audit trail (PAT-1243).
#
# Fixed by mapping onto the SAME closed /v1/events audit-event contract
# patched-update.sh's emit_audit_event() already ships (PAT-499; see
# docs/audit-events-contract.md and go-service/internal/handlers/events.go
# for the closed field/event_type set). Writes go into the same durable
# ring-buffer queue ($EVENTS_QUEUE) patched-update.sh's drain_events_queue()
# already sweeps on every update cycle, so this script does not need its own
# drain function — a failed delivery here is retried there.
# ---------------------------------------------------------------------------

report_install_event() {
    # report_install_event <package_id> <package_source> <outcome> [<error>]
    #
    # package_source is accepted for call-site compatibility but is not part
    # of the closed /v1/events envelope and is not sent.
    local pkg_id="$1"
    local outcome="$3"
    local error_msg="${4:-}"

    # PAT-1243: mirrors emit_audit_event's (patched-update.sh, PAT-499)
    # millisecond-timestamp + mktemp-trailing-X + rename pattern exactly.
    # BSD/macOS mktemp only substitutes a TRAILING X run, so the template
    # must end in X's or the returned path is unsubstituted and predictable
    # (PAT-1079). rename(2) never follows a destination symlink — but mv(1)
    # is not guaranteed to inherit that — which is why this goes through
    # mktemp-then-mv rather than a single mv. See emit_audit_event's
    # comments in patched-update.sh for the full history of both traps.
    local ev_ms
    ev_ms=$("$PYTHON3" -c 'import time; print(int(time.time()*1000))' 2>/dev/null)
    [[ -n "$ev_ms" ]] || ev_ms="$(date -u +%s)000"
    local ev_tmp; ev_tmp=$(mktemp "$EVENTS_QUEUE/evt-${ev_ms}-XXXXXX") || return 0
    local ev_file="${ev_tmp}.json"
    mv "$ev_tmp" "$ev_file" 2>/dev/null || { rm -f "$ev_tmp"; return 0; }

    # Ring-buffer cap: drop oldest if over limit. Same policy as
    # emit_audit_event — this queue is shared by both scripts.
    local -a _existing
    _existing=("$EVENTS_QUEUE"/evt-*.json(N))
    if (( ${#_existing} >= EVENTS_QUEUE_MAX )); then
        rm -f "${_existing[1]}" || true
    fi

    # PAT-1243 (mirrors PAT-1079's refusal in emit_audit_event): refuse to
    # write through a symlink planted at $ev_file in the window between the
    # mktemp/rename above and this check. $EVENTS_QUEUE is 0755 root:wheel
    # (created by the bare `mkdir -p` above under the daemon's default
    # umask; nothing chmods it looser), so this guards the pattern rather
    # than a live hole today.
    if [[ -L "$ev_file" ]]; then
        echo "WARN: install audit event temp path is a symlink — refusing to write through it; event dropped"
        rm -f "$ev_file"
        return 0
    fi

    # Outcome -> event_type mapping (PAT-1243 deliberate call): "success"
    # and "already_installed" both mean the app is present and verified
    # right now, so both map to install_completed — the audit trail should
    # reflect real-world state, not whether THIS run performed the install
    # action. Anything else (only "failed" today) fails closed to
    # install_failed rather than risk silently reporting success.
    local ev_type="install_failed"
    [[ "$outcome" == "success" || "$outcome" == "already_installed" ]] && ev_type="install_completed"

    PATCHED_EV_TYPE="$ev_type" \
    PATCHED_INSTALL_PKG_ID="$pkg_id" \
    PATCHED_INSTALL_ERROR="$error_msg" \
    PATCHED_TENANT_ID="${TENANT_ID:-}" \
    PATCHED_HW_UUID="${HW_UUID:-}" \
    "$PYTHON3" -c '
import json, datetime, os, sys
g = lambda k: os.environ.get(k, "") or None
rec = {
    "event_type":      os.environ["PATCHED_EV_TYPE"],
    "tenant_id":       g("PATCHED_TENANT_ID"),
    "device_id":       g("PATCHED_HW_UUID"),
    "label":           g("PATCHED_INSTALL_PKG_ID"),
    "version":         None,
    "verified_signer": None,
    "reason":          g("PATCHED_INSTALL_ERROR"),
    "expected":        None,
    "actual":          None,
    "platform":        "macos",
    "timestamp":       datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(sys.argv[1], "w") as f: json.dump(rec, f)
' "$ev_file" 2>/dev/null || { rm -f "$ev_file"; return 0; }

    local sig ts nonce http_code
    ts=$(date -u +%s)
    nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    sig=$(compute_hmac "$ev_file" "events" "$ts" "$nonce")

    http_code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time 30 \
        -X POST "$API_URL/v1/events" \
        -H "X-Patched-Signature: $sig" \
        -H "X-Patched-Timestamp: $ts" \
        -H "X-Patched-Nonce: $nonce" \
        -H "Content-Type: application/json" \
        --data-binary "@$ev_file" 2>/dev/null) || http_code="000"

    if [[ "$http_code" == 2* ]]; then
        rm -f "$ev_file"
        echo "  events POST -> $http_code ($ev_type/$pkg_id)"
    else
        echo "  WARN: events POST -> ${http_code:-network-error} ($ev_type/$pkg_id) — left queued for drain_events_queue on next patched-update.sh run"
    fi
}
# <<< PATCHED_REPORT_INSTALL_EVENT_END

# ---------------------------------------------------------------------------
# 3. FETCH PENDING INSTALLS
# ---------------------------------------------------------------------------

_ts=$(date -u +%s)
_nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
_sig=$(hmac_empty "pending_installs" "$_ts" "$_nonce")
_resp_file=$(mktemp /tmp/.patched-installs-resp.XXXXXX)

_installs_code=$(with_proxy "$API_URL" \
    patched_curl_bearer "$BEARER_TOKEN" -s -o "$_resp_file" -w "%{http_code}" --max-time 30 \
    -H "X-Patched-Signature: $_sig" \
    -H "X-Patched-Timestamp: $_ts" \
    -H "X-Patched-Nonce: $_nonce" \
    -H "Accept: application/json" \
    "$API_URL/v1/allowlist/pending-installs" 2>/dev/null) || _installs_code="000"

if [[ "$_installs_code" != "200" ]]; then
    echo "pending-installs fetch failed: HTTP $_installs_code — will retry next run."
    log_jsonl "warn" "pending-installs fetch failed" "{\"http_code\":\"$_installs_code\"}"
    rm -f "$_resp_file"
    exit 0
fi

_item_count=$("$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d.get('installs', [])))
except Exception:
    print(0)
" "$_resp_file" 2>/dev/null || echo "0")

echo "Pending installs: $_item_count"
if [[ "$_item_count" -eq 0 ]]; then
    rm -f "$_resp_file"
    echo "Nothing to do."
    log_jsonl "info" "install run complete: no pending installs"
    exit 0
fi

log_jsonl "info" "pending installs fetched" "{\"count\":$_item_count}"

# ---------------------------------------------------------------------------
# 4. PROCESS EACH INSTALL
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ALLOWLIST GATE (PAT-66 authorization_bypass fix)
#
# label_in_allowlist <label>
#   Returns 0 if <label> appears as the first tab-delimited column in the
#   bundle-integrity-protected $ALLOWLIST (labels-allowlist.txt, covered by
#   manifest.sha256 — same file and path as patched-update.sh).  Returns 1
#   when the label is absent, or when the allowlist file itself is missing
#   (fail-closed in both cases).
#
# This mirrors the control in patched-update.sh: that script iterates the
# allowlist as the authoritative label source so the server can only FILTER
# labels already pinned locally — it can never EXTEND the runnable set.
# patched-install.sh adopts the same invariant: a server-supplied package_id
# may only be dispatched to Installomator if it is already in the
# bundle-pinned allowlist.
# ---------------------------------------------------------------------------

label_in_allowlist() {
    local _lbl="$1"
    [[ -f "$ALLOWLIST" ]] || return 1
    local _al_label _rest
    while IFS=$'\t' read -r _al_label _rest; do
        [[ -z "$_al_label" || "$_al_label" == \#* ]] && continue
        [[ "$_al_label" == "$_lbl" ]] && return 0
    done < "$ALLOWLIST"
    return 1
}

_result_file=$(mktemp /tmp/.patched-installs-result.XXXXXX)

process_one_install() {
    local package_id="$1"
    local package_source="$2"
    local display_name="$3"

    echo "--- Processing: $display_name ($package_id, source=$package_source) ---"
    log_jsonl "info" "processing install" \
        "{\"package_id\":\"$package_id\",\"package_source\":\"$package_source\",\"display_name\":\"$display_name\"}"

    local outcome="unknown"
    local error_msg=""
    local recorded_at; recorded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    case "$package_source" in
        winget)
            # winget is a Windows-only source; skip on macOS without failure.
            echo "  SKIP: package_source=winget is Windows-only — not applicable on macOS"
            log_jsonl "info" "skipped: winget source on macOS" "{\"package_id\":\"$package_id\"}"
            return 0
            ;;

        mas)
            # Mac App Store: check via `mas list` first, then install via `mas install`.
            if is_installed_mas "$package_id"; then
                echo "  Already installed (MAS ID $package_id) — skipping."
                outcome="already_installed"
            else
                echo "  Attempting MAS install: mas install $package_id"
                local mas_bin
                mas_bin=$(command -v mas 2>/dev/null || true)
                if [[ -z "$mas_bin" ]]; then
                    error_msg="mas CLI not found — cannot install MAS apps"
                    echo "  ERROR: $error_msg"
                    outcome="failed"
                else
                    local mas_rc=0
                    # `timeout` is not available on macOS without GNU coreutils; mas
                    # has its own network timeout so no wrapper is needed.
                    if ! legacy_app_execution_enabled; then
                        error_msg="legacy app-execution gate disabled immediately before MAS install"
                        echo "  BLOCKED: $error_msg"
                        outcome="authority_refused"
                    else
                    "$mas_bin" install "$package_id" 2>&1 || mas_rc=$?
                    if [[ $mas_rc -eq 0 ]]; then
                        # FINDING 4: verify by re-inspection — never trust the exit code.
                        # Mirrors the uninstall engine's "verify is authoritative" stance.
                        if is_installed_mas "$package_id"; then
                            outcome="success"
                            echo "  Install verified: MAS $package_id is now installed."
                        else
                            # mas exited 0 but app not confirmed present — treat as failed
                            # so the next run retries (idempotent, fail-recoverable).
                            error_msg="mas install exited 0 but $package_id not confirmed in mas list — will retry"
                            echo "  WARN: $error_msg"
                            outcome="failed"
                        fi
                    else
                        error_msg="mas install exited $mas_rc"
                        echo "  FAILED: $error_msg"
                        outcome="failed"
                    fi
                    fi
                fi
            fi
            ;;

        vendor)
            # PAT-66 authorization_bypass fix: cross-check the server-supplied
            # Installomator label against the bundle-integrity-protected local
            # allowlist (labels-allowlist.txt, covered by manifest.sha256 — same
            # file and path used by patched-update.sh).  The server may only trigger
            # installs of labels already pinned locally; it can never EXTEND the set.
            # Fail-closed: a label absent from (or when the allowlist file itself is
            # missing) is refused before Installomator is invoked.
            if ! label_in_allowlist "$package_id"; then
                error_msg="label '$package_id' not in bundle-pinned allowlist — refusing server-driven install (PAT-66 authorization_bypass)"
                echo "  BLOCKED: $error_msg"
                log_jsonl "error" "allowlist gate blocked" \
                    "{\"package_id\":\"$package_id\",\"reason\":\"label not in bundle-pinned allowlist\"}"
                outcome="failed"
            # Vendor source: Installomator label dispatch.
            # package_id is the Installomator label (e.g. "googlechrome", "slack").
            # FINDING 3: use is_installed_vendor (label-manifest app_path first) rather than
            # is_installed_macos (display_name-based find) so apps whose bundle basename
            # differs from display_name are detected reliably and not re-installed every cycle.
            elif is_installed_vendor "$package_id" "$display_name"; then
                echo "  Already installed ($display_name) — skipping."
                outcome="already_installed"
            else
                # PAT-1236: fresh install is the highest-value moment for the
                # SHA-256 content-hash pin — there is no prior known-good
                # install to compare against, unlike the update path. Mirror
                # patched-update.sh's PAT-1028-hardened fail-closed behaviour
                # (not PAT-495's original fail-open design): refuse entirely
                # rather than install without a verified hash.
                local _pinned_sha256="" _pinned_rc=0
                _pinned_sha256=$(get_pinned_sha256 "$package_id"); _pinned_rc=$?
                if [[ $_pinned_rc -eq 2 ]]; then
                    error_msg="get_pinned_sha256: $package_id: catalogue.json is malformed — refusing fresh install (fail-closed)"
                    echo "  BLOCKED: $error_msg"
                    outcome="failed"
                elif [[ $_pinned_rc -eq 3 ]]; then
                    error_msg="$package_id: install refused: catalogue retired (PAT-2245). The signed app catalogue no longer exists, so no app has a verified hash and this legacy install path refuses every install."
                    echo "  BLOCKED: $error_msg"
                    outcome="failed"
                else
                    echo "  Attempting Installomator install: $package_id"
                    if [[ ! -x "$INSTALLOMATOR" ]]; then
                        error_msg="Installomator not found at $INSTALLOMATOR"
                        echo "  ERROR: $error_msg"
                        outcome="failed"
                    else
                        local inst_rc=0
                        # NOTIFY=silent: suppress interactive dialogs (daemon has no GUI session).
                        # BLOCKING_PROCESS_ACTION=tell_user: safe default — never force-quit.
                        # `timeout` is not available on macOS without GNU coreutils; Installomator
                        # has its own BPP / blocking-process timeout internals (mirrors patched-update.sh).
                        # PINNED_SHA256: content-hash pin from the catalogue (verified above,
                        # guaranteed non-empty on this path) — see PAT-495/PAT-1236.
                        if ! legacy_app_execution_enabled; then
                            error_msg="legacy app-execution gate disabled immediately before Installomator"
                            echo "  BLOCKED: $error_msg"
                            outcome="authority_refused"
                        else
                        "$INSTALLOMATOR" "$package_id" \
                            "NOTIFY=silent" \
                            "BLOCKING_PROCESS_ACTION=tell_user" \
                            "LOGGING=INFO" \
                            "PINNED_SHA256=${_pinned_sha256}" 2>&1 || inst_rc=$?

                        # FINDING 4 (revised): post-install presence check distinguishes three cases:
                        #
                        #   present  — app is confirmed present (authoritative app_path or display_name
                        #              match). Report success regardless of exit code.
                        #   absent   — label JSON with an authoritative app_path exists AND the path is
                        #              missing after exit 0. We can contradict the installer — report
                        #              failed so the next run retries (this is Finding 4's improvement
                        #              where we can actually verify).
                        #   unknown  — no label JSON staged and display_name search came up empty.
                        #              We have NO authoritative signal to contradict exit 0, so we must
                        #              not manufacture a failure and cause perpetual reinstall churn
                        #              (e.g. zoom label → zoom.us.app, display_name "Zoom" doesn't find
                        #              it). Trust the exit code: exit 0 → success, non-zero → failed.
                        #
                        # The MAS branch can always fail on unverified state because `mas list` is always
                        # authoritative. The vendor branch cannot make that guarantee without label JSON.
                        local _presence
                        _presence=$(vendor_presence "$package_id" "$display_name")

                        if [[ "$_presence" == "present" ]]; then
                            outcome="success"
                            echo "  Install verified: $display_name is now present."
                        elif [[ $inst_rc -ne 0 ]]; then
                            error_msg="Installomator exited $inst_rc"
                            echo "  FAILED: $error_msg"
                            outcome="failed"
                        elif [[ "$_presence" == "absent" ]]; then
                            # Authoritative label JSON confirms app_path is missing after exit 0.
                            # Retry next run — do not trust an exit 0 that contradicts the manifest.
                            error_msg="Installomator exited 0 but $display_name not found at authoritative app_path — will retry"
                            echo "  WARN: $error_msg"
                            outcome="failed"
                        else
                            # _presence == "unknown": no label JSON, display_name search also negative.
                            # No authoritative signal to contradict exit 0 — trust the installer.
                            outcome="success"
                            echo "  Install complete: trusting Installomator exit 0 (no label JSON available for post-install verification)."
                        fi
                        fi
                    fi
                fi
            fi
            ;;

        *)
            echo "  WARN: unknown package_source '$package_source' — skipping"
            log_jsonl "warn" "unknown package_source" \
                "{\"package_id\":\"$package_id\",\"package_source\":\"$package_source\"}"
            return 0
            ;;
    esac

    echo "  Outcome: $outcome"
    log_jsonl "info" "install outcome" \
        "{\"package_id\":\"$package_id\",\"package_source\":\"$package_source\",\"outcome\":\"$outcome\"}"

    # Report to POST /v1/events (PAT-651/PAT-1243).
    report_install_event "$package_id" "$package_source" "$outcome" "$error_msg"

    # Platform-neutral Self Service classification. Keep raw detail in the
    # status contract for operators, while both native UIs render fixed concise
    # copy from this typed value rather than exposing daemon logs.
    local failure_kind=""
    if [[ "$outcome" == "authority_refused" ]]; then
        failure_kind="execution_authority_refused"
    elif [[ "$outcome" == "failed" ]]; then
        case "$error_msg" in
            *"not in bundle-pinned allowlist"*|*"catalogue.json is malformed"*|*"install refused: catalogue retired"*|*"Installomator exited 60"*|*"Installomator exited 61"*|*"Installomator exited 62"*|*"Installomator exited 63"*|*"Installomator exited 64"*)
                failure_kind="verification_blocked"
                ;;
            *)
                failure_kind="install_failed"
                ;;
        esac
    fi

    # Append to per-run result file.
    PATCHED_R_PKG_ID="$package_id" \
    PATCHED_R_PKG_SRC="$package_source" \
    PATCHED_R_DISPLAY="$display_name" \
    PATCHED_R_OUTCOME="$outcome" \
    PATCHED_R_FAILURE_KIND="$failure_kind" \
    PATCHED_R_ERROR="$error_msg" \
    PATCHED_R_TS="$recorded_at" \
    "$PYTHON3" - "$_result_file" <<'PYEOF'
import json, os, sys
g = lambda k: os.environ.get(k, '')
row = {
    'package_id':     g('PATCHED_R_PKG_ID'),
    'package_source': g('PATCHED_R_PKG_SRC'),
    'display_name':   g('PATCHED_R_DISPLAY'),
    'outcome':        g('PATCHED_R_OUTCOME'),
    'recorded_at':    g('PATCHED_R_TS'),
}
if row['outcome'] in ('failed', 'authority_refused'):
    row['failure_kind'] = g('PATCHED_R_FAILURE_KIND')
    row['error_message'] = g('PATCHED_R_ERROR')
with open(sys.argv[1], 'a') as f:
    f.write(json.dumps(row) + '\n')
PYEOF
}

# ---------------------------------------------------------------------------
# 5. ITERATE OVER PENDING INSTALLS
# ---------------------------------------------------------------------------

# Parse the JSON response into a flat text file (unit separator \x1f as
# field delimiter) so the while-read loop can iterate without a subshell.
_items_file=$(mktemp /tmp/.patched-installs-items.XXXXXX)
"$PYTHON3" - "$_resp_file" <<'PYEOF' > "$_items_file"
import json, sys
installs = json.load(open(sys.argv[1])).get('installs', [])
for item in installs:
    fields = [
        item.get('package_id', ''),
        item.get('package_source', ''),
        item.get('display_name', '') or item.get('package_id', ''),
    ]
    print('\x1f'.join(fields))
PYEOF
rm -f "$_resp_file"

while IFS=$'\x1f' read -r package_id package_source display_name; do
    [[ -z "$package_id" ]] && continue
    process_one_install "$package_id" "$package_source" "$display_name" || true
done < "$_items_file"
rm -f "$_items_file"

# ---------------------------------------------------------------------------
# 6. WRITE INSTALL STATUS
# ---------------------------------------------------------------------------

RUN_FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

"$PYTHON3" - "$INSTALL_STATUS_FILE" "$RUN_STARTED_AT" "$RUN_FINISHED_AT" "$_result_file" <<'PYEOF'
import json, sys, datetime, os
status_file, started_at, finished_at, result_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
doc = {
    'schema_version': 1,
    'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'last_run': {'started_at': started_at, 'finished_at': finished_at},
    'installs': [],
}
try:
    with open(result_file) as rf:
        for line in rf:
            line = line.strip()
            if line:
                try:
                    doc['installs'].append(json.loads(line))
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

log_jsonl "info" "install run complete" "{\"processed\":$_item_count}"
echo "Install run complete. Status: $INSTALL_STATUS_FILE"
echo "=== patched-install run finished $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
