#!/bin/zsh
##############################################################################
# patched-fetch-config.sh — fetch, verify, and cache per-tenant agent config.
#
# Runs in two contexts:
#   1. Called at the top of each patched-update.sh scan run (config refresh).
#   2. Called by the com.patched.config-poll LaunchDaemon (15-min ETag poll).
#
# On each run it:
#   1. Acquires a mkdir-based lock so the two callers cannot interleave
#      fetch→verify→commit and corrupt state.
#   2. Computes HMAC-SHA256 over an empty body — same bearer+HMAC scheme as
#      /v1/inventory and /v1/provenance, but GET has no request body.
#   3. Sends If-None-Match: "<last_version>" when a cached version exists.
#   4. On 304 Not Modified: exits 0, nothing written (cached config unchanged).
#   5. On 200: calls verify-agent-config.py to check Ed25519 sig + anti-rollback
#      and atomically replaces agent-config.json on success, then writes the
#      version-file — config and version cannot diverge across a crash.
#   6. On any other response or error: exits 0 (fail-safe — keep last-good).
#
# CONVENTIONS (shared with patched-update.sh):
#   - set -u only (not set -euo pipefail).
#   - /usr/bin/python3 hardcoded (sudo strips PATH on macOS).
#   - No zsh reserved var names: path/fpath/cdpath/manpath/infopath.
##############################################################################

set -u

# PAT-2394: root command lookup must never include Homebrew, inherited PATH
# or a test override. Runtime failure is fatal before logging or state writes.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] && "$PYTHON3" -I -c 'pass' >/dev/null 2>&1 || { printf '%s\n' "FATAL: trusted /usr/bin/python3 runtime unavailable or unusable; no work performed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BUNDLE_DIR="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}"
STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-update.log}"

# PAT-652: structured JSON-lines log alongside the existing plain-text log.
JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_FILE="$JSONL_LOG_DIR/daemon.jsonl"
JSONL_COMPONENT="daemon"

AGENT_CONFIG_FILE="$STATE_DIR/agent-config.json"
# PAT-1756: the anti-rollback floor, keyed by tenant because config_version is
# monotonic per tenant on the server. Format and rules are documented in the
# ANTI-ROLLBACK FLOOR section below and in verify-agent-config.py.
AGENT_CONFIG_VERSION_FILE="$STATE_DIR/agent-config.version"
# PAT-1035: liveness signal for macos/patched-upload.sh's enforcement gate.
# Written whenever the server confirms the cached config is current (a
# verified 200 commit or a 304 Not Modified), never on a failure path, so the
# gate can tell a healthy stable tenant (unchanged config, old file mtime)
# apart from a poller that has actually stopped.
AGENT_CONFIG_HEARTBEAT_FILE="$STATE_DIR/agent-config.checked"
# A newer Ed25519-verified, tenant-bound response can revoke execution while
# still being rejected as a complete policy (for example, an unrelated nested
# duplicate key). Keep the diagnostic last-good cache, but persist that
# authenticated revocation separately so no actuator can use its old grant.
# PAT-1763: the marker carries the tenant whose policy revoked execution, and
# its floors apply only to that tenant (format in verify-agent-config.py).
AGENT_CONFIG_EXECUTION_DENY_FILE="$STATE_DIR/agent-config.execution-denied"
# PAT-1035 finding 2: SHA-256 of the config bytes as of the last verified
# commit (200 path). If-None-Match is sent from AGENT_CONFIG_VERSION_FILE, so
# a 304 only proves the server thinks our recorded VERSION is current — it
# says nothing about whether AGENT_CONFIG_FILE's bytes are still the verified
# ones. In the mixed-version window an old, unverified uploader can overwrite
# agent-config.json without touching the version sidecar, so a naive 304
# handler would stamp a fresh heartbeat onto unverified bytes. The 304 path
# below recomputes the on-disk hash and only writes the heartbeat when it
# still matches this recorded value.
AGENT_CONFIG_SHA256_FILE="$STATE_DIR/agent-config.sha256"
# PAT-1035 finding 2 liveness trap: if a 304 ever finds the hash mismatched,
# the ETag keeps producing 304s forever (nothing changed server-side) and no
# 200 would ever arrive to re-verify and re-record the hash, so enforcement
# would stay off permanently. This sentinel forces the NEXT poll to suppress
# If-None-Match and do a full fetch instead, so it can re-verify the bytes.
# It only ever suppresses the header — AGENT_CONFIG_VERSION_FILE itself is
# never touched here; the verifier still uses it as the anti-rollback floor.
AGENT_CONFIG_FORCE_REFETCH_FILE="$STATE_DIR/.agent-config.force-refetch"
# PAT-1040: on a confirmed 304 hash mismatch, the unverified on-disk config is
# moved aside here rather than left readable at AGENT_CONFIG_FILE for the rest
# of the poll cycle. Fixed name (not timestamped) — a repeat mismatch just
# overwrites the previous quarantine copy; this exists so the mismatched bytes
# are still available for inspection, not as a full audit trail.
AGENT_CONFIG_QUARANTINE_FILE="${AGENT_CONFIG_FILE}.quarantined"
VERIFIER="$BUNDLE_DIR/verify-agent-config.py"
# PAT-1763: the one anti-rollback floor parser, shared by the verifier, the
# If-None-Match choice, the decommission gate and patched-enroll.sh.
AGENT_CONFIG_FLOOR_MODULE="$BUNDLE_DIR/agent_config_floor.py"
PROXY_RESOLVE="$BUNDLE_DIR/patched-proxy-resolve.py"  # PAT-278

# ---------------------------------------------------------------------------
# STRUCTURED LOGGING HELPERS (PAT-652)
# Writes JSON-lines to /Library/Logs/Patched/daemon.jsonl alongside the
# existing plain-text log. Tee approach: both destinations receive output.
# Never log bearer_token, hmac_secret, or proxy credentials.
# ---------------------------------------------------------------------------

_init_jsonl_log() {
    install -d -m 755 "$JSONL_LOG_DIR" 2>/dev/null \
        || mkdir -p "$JSONL_LOG_DIR" 2>/dev/null || return 0
    touch "$JSONL_LOG_FILE" 2>/dev/null && chmod 644 "$JSONL_LOG_FILE" 2>/dev/null || true
    # Truncate-and-recreate when file exceeds 10 MiB.
    local _sz; _sz=$(wc -c < "$JSONL_LOG_FILE" 2>/dev/null | tr -d '[:space:]') || _sz=0
    (( _sz > 10485760 )) && : > "$JSONL_LOG_FILE" || true
    # Purge stale jsonl files older than 14 days.
    find "$JSONL_LOG_DIR" -maxdepth 1 -name "$(basename "$JSONL_LOG_FILE")" \
        -mtime "+14" -delete 2>/dev/null || true
}

log_jsonl() {
    # log_jsonl <level> <msg> [<fields-json>]
    # Appends one compact JSON-lines record to JSONL_LOG_FILE. Never fails.
    # Redact /Users/<name>/ → /Users/[REDACTED]/ before passing msg or fields.
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
        # Malformed fields JSON must not cost us the whole record.
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

mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR"
exec >> "$LOG_FILE" 2>&1

echo "=== patched-fetch-config $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
log_jsonl "info" "fetch-config poll started"

# ---------------------------------------------------------------------------
# SUSPENDED STATE CHECK (PAT-544, revised PAT-1042): server rejected this
# device's authentication or its enrollment. Written by patched-enroll.sh
# (terminal failure) or by us on a 401, whose cause the server does not
# disclose (PAT-1745); cleared by _agent_config_commit_verified below on the next
# signature-verified 200.
#
# PAT-1042 design change: this used to `exit 0` here, stopping ALL outbound
# calls while suspended — which made the file a one-way latch, since nothing
# ever ran again to notice the platform had reinstated the device. That is
# deliberately no longer the posture. A suspended device must keep PROBING
# agent-config so a verified 200 can clear the marker (the standard
# quarantine-but-keep-checking-in pattern). For an already-enrolled device
# suspended by a 401 (has a bearer-token, no enrollment-token) this config
# fetch really is the only outbound call it makes. Non-author review (round
# 3) caught that this was overstated for the OTHER device class the same
# marker covers: a device suspended by a TERMINAL ENROLLMENT failure
# (enrollment-token present, no bearer-token yet — see patched-enroll.sh)
# hits the ENROLLMENT block just below first and retries `POST /v1/enrol`
# every poll before it could ever reach this fetch at all (it has no
# bearer-token to fetch agent-config with in the first place). Either way,
# the device does NOT resume enforcement or collection on its own —
# patched-update.sh and macos/patched-upload.sh's AC gate each check this
# same $CREDS_DIR/suspended marker independently and keep refusing until it
# is actually gone, so a suspended device still enforces nothing while this
# fetch (or the enrollment retry) runs. Outcomes from here (post-enrollment
# device class):
#   - Verified 200: _agent_config_commit_verified clears the marker below —
#     the device resumes normal operation on its very next enforcement run.
#   - 401: the handler further down re-affirms the marker — still suspended.
#   - Any other error/non-200: keeps last-good state — still suspended.
# ---------------------------------------------------------------------------
if [[ -f "$CREDS_DIR/suspended" ]]; then
    echo "agent-config: device suspended — probing for reinstatement (fetch continues; no enforcement resumes until the marker actually clears)"
    log_jsonl "warn" "fetch-config: device suspended — probing agent-config for reinstatement"
fi

# >>> PATCHED_CREDS_USABLE_START (keep in sync with endpoint/patched-fetch-config.sh, endpoint/patched-fetch-posture.sh)
# PAT-1760: patched_device_credentials_usable <creds-dir>
#   Returns 0 only when bearer-token has a non-blank first line (the line the
#   request sends) and hmac-secret has non-blank content. A missing, empty or
#   whitespace-only bearer-token would otherwise go out as a bare
#   "Authorization: Bearer" header, and the 401 it draws says nothing about this
#   device's credentials. Checks presence only: neither value is read into a
#   variable or printed.
patched_device_credentials_usable() {
    local _creds_dir="$1"
    head -1 "$_creds_dir/bearer-token" 2>/dev/null | grep -q '[^[:space:]]' || return 1
    grep -q '[^[:space:]]' "$_creds_dir/hmac-secret" 2>/dev/null || return 1
    return 0
}
# <<< PATCHED_CREDS_USABLE_END

# ---------------------------------------------------------------------------
# ENROLLMENT (PAT-544) — exchange single-use token on first run.
# Runs before the config-fetch lock: enrollment is a one-shot operation and
# does not need to be serialised with config fetch/verify/commit.
#
# PAT-1765: "not enrolled" is no usable credential pair, not a missing
# bearer-token file. An empty or whitespace bearer-token (or hmac-secret) next
# to an enrolment token used to skip enrolment forever, and the guard below
# then sent nothing every poll. Same rule as the Windows agent (PAT-1760
# DeviceCredentials.Present) and patched-enroll.sh.
#
# PAT-1814: the gate below used to check only that the enrollment-token FILE
# exists, not that it has usable content. A blank/whitespace-only
# enrollment-token still passed that check and invoked patched-enroll.sh every
# poll; patched-enroll.sh's own PAT-1765 empty-token guard no-ops safely
# rather than sending an empty token, but the wasted subprocess + lock/unlock
# cycle ran every cycle regardless. Same "usable" rule as
# patched_device_credentials_usable above and Windows's
# CredentialStore.IsUsableEnrollmentToken: non-empty after stripping
# whitespace. Presence and usability are both required, so keep them as
# separate checks below — $(<file) on a missing file would abort under -u.
patched_enrollment_token_usable() {
    grep -q '[^[:space:]]' "$1" 2>/dev/null
}
# ---------------------------------------------------------------------------
if [[ -f "$CREDS_DIR/enrollment-token" ]] \
    && patched_enrollment_token_usable "$CREDS_DIR/enrollment-token" \
    && ! patched_device_credentials_usable "$CREDS_DIR"; then
    ENROLL_SCRIPT="$BUNDLE_DIR/patched-enroll.sh"
    if [[ -x "$ENROLL_SCRIPT" ]]; then
        if ! "$ENROLL_SCRIPT"; then
            echo "agent-config: enrollment failed terminally — suspended"
            exit 0
        fi
    else
        echo "WARN: patched-enroll.sh not found in bundle ($ENROLL_SCRIPT)"
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# LOCK — prevent concurrent fetch+verify+commit from both daemons.
# mkdir is atomic on APFS/HFS+; the directory acts as a mutex.
# If the lock is held, skip this run — the holder will finish shortly.
# ---------------------------------------------------------------------------

LOCK_DIR="$STATE_DIR/.patched-config-fetch.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "agent-config: lock held by another instance — skipping this run"
    log_jsonl "info" "fetch-config skipped: lock held by another instance"
    exit 0
fi
_lock_cleanup() { rm -rf "$LOCK_DIR"; }
trap _lock_cleanup EXIT

# ---------------------------------------------------------------------------
# CREDENTIALS
# ---------------------------------------------------------------------------

for cred_file in tenant-id bearer-token hmac-secret; do
    if [[ ! -f "$CREDS_DIR/$cred_file" ]]; then
        echo "ERROR: $CREDS_DIR/$cred_file missing — cannot fetch agent config"
        log_jsonl "error" "fetch-config skipped: credential file missing, no request sent" "{\"credential_file\":\"$cred_file\"}"
        exit 1
    fi
done

# An empty credential file is not a credential. No request is sent, so nothing
# here can write or clear the suspended marker: a marker is only ever written in
# response to a request that carried a real token.
if ! patched_device_credentials_usable "$CREDS_DIR"; then
    echo "agent-config: bearer-token or hmac-secret in $CREDS_DIR is empty, so this device has no usable credentials; no request sent, suspended marker unchanged"
    log_jsonl "warn" "fetch-config skipped: device credentials empty, no request sent"
    exit 0
fi

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

# PAT-513: device identity header — forward-compatible; server ignores until
# per-device token enforcement is live in the platform.
HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}') || HW_UUID=""

# ---------------------------------------------------------------------------
# HMAC over empty body (GET has no request body)
# ---------------------------------------------------------------------------

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body (empty body
# here, GET request) so a captured signed request cannot be replayed. TS and
# NONCE are generated FIRST so the exact same strings go into both the
# signature and the X-Patched-Timestamp / X-Patched-Nonce headers below.
TS=$(date -u +%s)
NONCE=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
SIG=$("$PYTHON3" - "$TS" "$NONCE" "$CREDS_DIR/hmac-secret" <<'HMACV3PYEOF'
import sys, hmac, hashlib, base64
ts, nonce, secret_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
msg = b"patched-hmac-v3\nGET\nagent_config\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n"
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
HMACV3PYEOF
)

# ---------------------------------------------------------------------------
# PROXY RESOLUTION  (PAT-278) — mirrors with_proxy from patched-update.sh.
# ---------------------------------------------------------------------------

with_proxy() {
    local _target="$1"; shift
    local _json _parsed _pmode _purl _durl _noproxy _pwarn

    if [[ -x "${PROXY_RESOLVE:-}" ]]; then
        _json=$("$PYTHON3" "$PROXY_RESOLVE" "$_target" "${AGENT_CONFIG_FILE:-}" 2>/dev/null) \
            || _json='{"mode":"direct"}'
        # Parse the resolver output WITHOUT putting the credential-bearing URL on
        # argv (it would be visible in `ps`): feed the JSON via stdin, and emit a
        # single tab-separated line so a plain `read` captures every field
        # (reading newline-separated output takes only the first line). The
        # warning field is last so any spaces in it stay in the final field.
        _parsed=$(printf '%s' "$_json" | "$PYTHON3" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
fields = [d.get("mode", "direct"), d.get("url", ""), d.get("display_url", ""),
          d.get("no_proxy", ""), d.get("warning", "")]
sys.stdout.write("\t".join(f if isinstance(f, str) else str(f) for f in fields))
' 2>/dev/null)
        IFS=$'\t' read -r _pmode _purl _durl _noproxy _pwarn <<< "$_parsed"
    fi

    _pmode="${_pmode:-direct}"; _purl="${_purl:-}"; _durl="${_durl:-$_purl}"; _noproxy="${_noproxy:-}"; _pwarn="${_pwarn:-}"

    # Diagnostics go to stderr: callers capture this function's stdout
    # (e.g. http_code=$(with_proxy ... curl -w '%{http_code}')), so a stray
    # stdout line here would corrupt the captured value.
    [[ -n "$_pwarn" ]] && echo "  proxy: warning: $_pwarn" >&2

    if [[ "$_pmode" == "proxy" && -n "$_purl" ]]; then
        echo "  proxy: $_durl" >&2
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
# ANTI-ROLLBACK FLOOR (PAT-1756)
#
# AGENT_CONFIG_VERSION_FILE holds one line of JSON:
#
#   {"tenant_id":"<tenant id>","config_version":<non-negative integer>}
#
# exactly those two members (the Windows agent uses the same format). The
# tenant is always the one bound in the signature-verified payload that set it.
# A legacy bare integer (the pre-PAT-1756 format) is the floor for the
# currently enrolled tenant only, and is rewritten in the keyed format on the
# next commit. No If-None-Match is sent from a legacy floor: it carries no
# tenant, so it may be another tenant's (a device re-provisioned without
# running patched-enroll.sh), and a matching version would draw a 304 that
# keeps that tenant's cached config. A floor keyed to another tenant does not apply: this tenant
# starts fresh. Anything else is corrupt: the verifier refuses every config
# and no If-None-Match is sent, until a successful enrolment (patched-enroll.sh)
# removes the file or an operator does. Sentinel-wrapped so
# endpoint/test-agent-config-commit.zsh can extract and drive it.
# ---------------------------------------------------------------------------
# >>> PATCHED_CONFIG_FLOOR_START
# _agent_config_floor_state <floor-file> <tenant-id>
#   Prints exactly one of:
#     absent             no floor file
#     applies <version>  a keyed floor for <tenant-id>
#     legacy <version>   a pre-PAT-1756 bare integer
#     other_tenant       a keyed floor for a different tenant
#     corrupt            unreadable or malformed
#   Parsing lives in AGENT_CONFIG_FLOOR_MODULE (agent_config_floor.py,
#   PAT-1763), shared with verify-agent-config.py, patched-enroll.sh and
#   _decommission_check below. A reader that fails or prints anything else
#   is corrupt.
_agent_config_floor_state() {
    local floor_file="$1" floor_tenant="$2" floor_out
    floor_out=$("$PYTHON3" "$AGENT_CONFIG_FLOOR_MODULE" fetch-state "$floor_file" "$floor_tenant" 2>/dev/null) \
        || floor_out="corrupt"
    case "$floor_out" in
        absent|other_tenant|corrupt) printf '%s\n' "$floor_out" ;;
        "applies "<->|"legacy "<->) printf '%s\n' "$floor_out" ;;
        *) printf 'corrupt\n' ;;
    esac
}

# _agent_config_conditional_get_version <floor-state>
#   Sets LAST_VERSION (the If-None-Match validator) from a
#   _agent_config_floor_state result, and logs why none is sent. Only a floor
#   keyed to this device's enrolled tenant may be sent: another tenant's
#   version could equal this tenant's current version and draw a 304 that
#   keeps a stale config, a legacy floor carries no tenant to check, and a
#   corrupt floor has no trustworthy version at all. Anything unexpected is
#   treated as an unusable floor: no validator, and an error is logged. That
#   only decides the header. Acceptance never uses this result: the verifier
#   reads the floor itself and refuses every config for a floor it cannot
#   parse, and any verifier failure is a rejection.
_agent_config_conditional_get_version() {
    local floor_result="$1"
    LAST_VERSION=""
    case "$floor_result" in
        "applies "<->)
            LAST_VERSION="${floor_result#applies }"
            ;;
        absent)
            : # no floor yet (fresh install or reset by enrolment): nothing to send
            ;;
        "legacy "<->)
            echo "agent-config: stored anti-rollback floor is in the legacy format with no tenant; no If-None-Match sent, the next accepted config re-keys it to tenant $TENANT_ID"
            log_jsonl "info" "fetch-config: legacy anti-rollback floor; no If-None-Match sent" "{\"tenant_id\":\"$TENANT_ID\"}"
            ;;
        other_tenant)
            echo "agent-config: stored anti-rollback floor belongs to another tenant; tenant $TENANT_ID starts a fresh floor, no If-None-Match sent"
            log_jsonl "info" "fetch-config: anti-rollback floor belongs to another tenant; no If-None-Match sent" "{\"tenant_id\":\"$TENANT_ID\"}"
            ;;
        corrupt)
            echo "agent-config: stored anti-rollback floor at $AGENT_CONFIG_VERSION_FILE is unusable; no If-None-Match sent, and configs for tenant $TENANT_ID are refused until the device re-enrols or the file is removed"
            log_jsonl "error" "fetch-config: anti-rollback floor is unusable; configs refused until re-enrolment or removal" "{\"tenant_id\":\"$TENANT_ID\"}"
            ;;
        *)
            local shown="${${floor_result[1,80]}//[^[:print:]]/?}"
            echo "agent-config: ERROR: anti-rollback floor state was unexpected ($shown); treating the floor as unusable, no If-None-Match sent"
            log_jsonl "error" "fetch-config: unexpected anti-rollback floor state ($shown); treated as unusable, no If-None-Match sent" "{\"tenant_id\":\"$TENANT_ID\"}"
            ;;
    esac
}
# <<< PATCHED_CONFIG_FLOOR_END

# ---------------------------------------------------------------------------
# FETCH
# ---------------------------------------------------------------------------

# Read the anti-rollback floor for the ETag header (PAT-1756); see
# _agent_config_conditional_get_version for which floors may be sent.
FLOOR_STATE=$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" "$TENANT_ID")
_agent_config_conditional_get_version "$FLOOR_STATE"

# PAT-1035 finding 2: a prior run's 304 hash-check may have found the on-disk
# config no longer matches the last verified hash and left the force-refetch
# sentinel behind. Suppress If-None-Match this run so the server has to send
# a full body we can re-verify, instead of looping on 304s forever.
if [[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]]; then
    echo "agent-config: forcing full fetch (prior hash mismatch) — suppressing If-None-Match"
    log_jsonl "warn" "forcing full agent-config fetch after prior hash mismatch"
    LAST_VERSION=""
fi

# PAT-1042 P1 (non-author review, round 3): revocation is a per-DEVICE auth
# flag, not a change to the tenant's agent-config CONTENT — the realistic
# reinstatement case (an admin re-permits the device) does not bump
# config_version at all. Without this, a suspended device's probe would keep
# sending If-None-Match, the server would keep answering 304 Not Modified
# (content genuinely hasn't changed), and _agent_config_handle_304 never
# touches $CREDS_DIR/suspended — so a fully reinstated device would stay
# suspended forever, the exact bug class this ticket exists to fix, just one
# response code later than the original inert-feature bug. Suppress
# If-None-Match while suspended (same mechanism as the force-refetch case
# above) so the server is FORCED to answer with a full, verifiable 200 the
# moment credentials work again — a still-revoked device gets 401 either way
# (marker stays), a reinstated one now gets a verifiable 200
# _agent_config_commit_verified can act on. Only suppressed while suspended:
# the normal (non-suspended) path keeps sending the conditional GET, so this
# does not regress bandwidth in the common healthy-device case.
if [[ -f "$CREDS_DIR/suspended" ]]; then
    echo "agent-config: device suspended — suppressing If-None-Match so a reinstated device gets a verifiable 200 instead of a 304 that would never clear the marker"
    log_jsonl "warn" "fetch-config: suppressing If-None-Match while suspended (reinstatement probe needs a full 200)"
    LAST_VERSION=""
fi

resp_file=$(mktemp /tmp/.patched-config-resp.XXXXXX)
# PAT-1109 P2 D: capture response headers alongside the body so the
# decommission gate can bound how far the local wall clock is trusted
# against the server's own `Date` header — see AGENT_CONFIG_CLOCK_SKEW_SECONDS
# below. Captured on every fetch, 200 or 304, since a 304 still carries a
# fresh Date header and this is deliberately the freshest signal available
# (never a value persisted from a prior poll).
header_file=$(mktemp /tmp/.patched-config-headers.XXXXXX)

device_hdr=()
[[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")

if [[ -n "$LAST_VERSION" ]]; then
    http_code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o "$resp_file" -D "$header_file" -w "%{http_code}" --max-time 30 \
        -H "X-Patched-Signature: $SIG" \
        -H "X-Patched-Timestamp: $TS" \
        -H "X-Patched-Nonce: $NONCE" \
        "${device_hdr[@]}" \
        -H "Accept: application/json" \
        -H "If-None-Match: \"$LAST_VERSION\"" \
        "$API_URL/v1/agent-config" 2>/dev/null) || http_code="000"
else
    http_code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o "$resp_file" -D "$header_file" -w "%{http_code}" --max-time 30 \
        -H "X-Patched-Signature: $SIG" \
        -H "X-Patched-Timestamp: $TS" \
        -H "X-Patched-Nonce: $NONCE" \
        "${device_hdr[@]}" \
        -H "Accept: application/json" \
        "$API_URL/v1/agent-config" 2>/dev/null) || http_code="000"
fi

# PAT-1109 P2 D: local_clock_minus_server_clock, in seconds, measured from
# THIS response's `Date` header (RFC 1123, per HTTP spec — not RFC3339).
# Positive means the local clock is ahead of the server. Empty means
# unmeasurable this poll (header missing/unparseable, or curl failed before
# any header arrived) — the decommission gate (P1-A, non-author review)
# treats "unmeasurable" as a FAULT for mode=expiry, deferring that poll's
# evaluation rather than falling back to the untrusted local clock. It costs
# nothing: the same directive is re-evaluated on a later poll once server
# time is available again.
#
# PROXY-DATE TRUST (non-author review, second round): curl's -D dump can
# contain MULTIPLE response header blocks for one logical request — through
# a configured HTTPS proxy, curl first dumps the CONNECT tunnel's own
# "HTTP/1.1 200 Connection established" response block, THEN the origin's
# real (TLS-protected) response block. Taking the first `Date:` line in the
# whole dump, as this used to do, would trust the PROXY's clock instead of
# the origin server's — reopening the exact fail-open P1-A closed, because a
# fast local clock racing a fast/complicit proxy clock would sail straight
# past the skew bound undetected. Fixed: split the dump into blocks on blank
# lines, drop any 1xx/CONNECT-established block, and take Date only from the
# LAST remaining (origin) block. A direct connection (no proxy) has exactly
# one block, so this is a no-op in the common case. No identifiable origin
# block still yields "" (unmeasurable) — same fail-closed default as always.
AGENT_CONFIG_CLOCK_SKEW_SECONDS=$("$PYTHON3" -c '
# >>> PATCHED_CLOCK_SKEW_PARSE_START (keep in sync with any future copy; see endpoint/test-decommission-gate.zsh)
import email.utils, sys, time

def is_connect_block(block):
    # A block that is not a well-formed "HTTP/x.y CODE ..." status line, or
    # whose code is 1xx (100 Continue etc.) or a 200 CONNECT-tunnel-established
    # response, is never a real origin response — never trust its Date.
    if not block:
        return True
    parts = block[0].split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        return True
    try:
        code = int(parts[1])
    except Exception:
        return True
    if 100 <= code < 200:
        return True
    if code == 200 and len(parts) >= 3 and "connection established" in parts[2].lower():
        return True
    return False

try:
    with open(sys.argv[1]) as f:
        raw = f.read()

    blocks = []
    current = []
    for line in raw.splitlines():
        if line.strip() == "":
            if current:
                blocks.append(current)
                current = []
        else:
            current.append(line)
    if current:
        blocks.append(current)

    origin_blocks = [b for b in blocks if not is_connect_block(b)]

    date_val = None
    if origin_blocks:
        for line in origin_blocks[-1]:
            if line.lower().startswith("date:"):
                date_val = line.split(":", 1)[1].strip()
                break

    if date_val is None:
        print(""); raise SystemExit
    server_dt = email.utils.parsedate_to_datetime(date_val)
    if server_dt.tzinfo is None:
        import datetime
        server_dt = server_dt.replace(tzinfo=datetime.timezone.utc)
    print(int(time.time() - server_dt.timestamp()))
except SystemExit:
    raise
except Exception:
    print("")
# <<< PATCHED_CLOCK_SKEW_PARSE_END
' "$header_file" 2>/dev/null) || AGENT_CONFIG_CLOCK_SKEW_SECONDS=""
rm -f "$header_file"

# ---------------------------------------------------------------------------
# HANDLE RESPONSE
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# LOG UPLOAD TRIGGER (PAT-287)
#
# Fired from inside the two success paths below, never from a shared
# call site at the bottom of the script: _agent_config_commit_verified
# (200 path) fires it only after publish + version-file + sha256-file +
# heartbeat have ALL durably succeeded (PAT-1035 round 6 finding 2), and
# _agent_config_handle_304 (304 path) fires it only when the hash check
# confirms the cached bytes are still the verified ones (PAT-1035 finding
# 2). This so a log_request directive takes effect immediately on the next
# poll cycle, but only for a poll that actually ended in a confirmed config.
#
# Not fired on fetch failures — the cached config is unchanged in that case
# and the trigger would redundantly re-check a directive we already acted
# on. Not fired on verification failure or a failed/partial 200 commit
# (mv failure, unreadable config_version/digest, or either sidecar file
# write failing) — round 6 finding: the trigger used to run unconditionally
# at the end of the script regardless of commit outcome, so a failed or
# raced commit could still cause patched-log-upload.sh to act on a config
# we never confirmed. Not fired on a 304 hash mismatch either: at that point
# the cached config is confirmed NOT to be the bytes we verified, so acting
# on any directive in it — including uploading endpoint logs — would be
# acting on an unverified payload, which is exactly what the hash check
# above exists to prevent.
# ---------------------------------------------------------------------------
_trigger_log_upload() {
    local log_upload_script="$BUNDLE_DIR/patched-log-upload.sh"
    if [[ -x "$log_upload_script" ]]; then
        "$log_upload_script" || true
    fi
}

# PAT-1035 finding 2 (round 5 test gap): the 200-path commit sequence and the
# 304 decision path are where both P0s in this ticket actually lived, and
# both were previously inline top-level script code — untestable without
# root and a live server. They are now the two functions below
# (_agent_config_commit_verified, _agent_config_handle_304), sentinel-wrapped
# together with their helpers, so endpoint/test-agent-config-commit.zsh can
# extract this whole block and drive both flows directly against a temp dir,
# no root, by shadowing mv and stubbing _trigger_log_upload/log_jsonl.
# >>> PATCHED_CONFIG_COMMIT_START
# PAT-1035: write the heartbeat. Called only from the 200-verified-and-committed
# path and the 304 path below, both of which mean the server just confirmed the
# cached config is current. Temp file lives in STATE_DIR so the mv is an atomic
# rename on the same filesystem, same pattern as the config/version commit above.
_write_agent_config_heartbeat() {
    local hb_tmp
    hb_tmp=$(mktemp "$STATE_DIR/.agent-config.checked.XXXXXX") || return 1
    date -u +%Y-%m-%dT%H:%M:%SZ > "$hb_tmp"
    chmod 644 "$hb_tmp"
    mv -f "$hb_tmp" "$AGENT_CONFIG_HEARTBEAT_FILE"
}

# PAT-1035 finding 2: bind the heartbeat to the actual verified bytes, not
# just the ETag. Both functions depend only on the two plain path variables
# set above, no path hardcoded inside, so endpoint/test-agent-config-hash-gate.zsh
# can extract this block and drive it directly against a temp dir, no root.
# >>> PATCHED_CONFIG_HASH_CHECK_START
# _agent_config_sha256 <file>
#   SHA-256 hex digest of <file>, empty string if it can't be read. Uses the
#   `shasum -a 256 | awk` idiom already used elsewhere in this codebase
#   (install.sh, patched-update.sh) rather than a fresh python invocation.
_agent_config_sha256() {
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
}

# _agent_config_hash_matches
#   True (0) only when AGENT_CONFIG_FILE's current on-disk bytes hash to the
#   value recorded in AGENT_CONFIG_SHA256_FILE at the last verified commit.
#   False (1) if either file is missing/unreadable or the hashes differ —
#   including the case where AGENT_CONFIG_SHA256_FILE predates this fix and
#   has never been written, which must not be treated as a pass.
_agent_config_hash_matches() {
    [[ -f "$AGENT_CONFIG_FILE" && -f "$AGENT_CONFIG_SHA256_FILE" ]] || return 1
    local recorded actual
    recorded=$(head -1 "$AGENT_CONFIG_SHA256_FILE" | tr -d '[:space:]')
    actual=$(_agent_config_sha256 "$AGENT_CONFIG_FILE")
    [[ -n "$recorded" && -n "$actual" && "$recorded" == "$actual" ]]
}
# <<< PATCHED_CONFIG_HASH_CHECK_END

# _write_agent_config_sha256 <digest>
#   Writes the caller-supplied digest to AGENT_CONFIG_SHA256_FILE. Called
#   only from the 200-verified-and-committed path, after AGENT_CONFIG_FILE is
#   durably in place, so a later 304 has something real to check against.
#
#   PAT-1035 finding (round 5): this used to re-hash AGENT_CONFIG_FILE off
#   disk at this point, AFTER the publish mv. Anything that replaced
#   agent-config.json between the mv and this call got its bytes hashed and
#   recorded as "verified" — the digest and the file would agree, but neither
#   would be what the verifier produced. The caller now computes the digest
#   from the verifier's own output file, before the mv, and passes it in
#   here, so this function only ever writes a digest that is provably the
#   digest of bytes the verifier produced. It takes the digest as a
#   parameter rather than a path so it can't be tempted to re-derive it from
#   disk.
_write_agent_config_sha256() {
    local digest="$1" sha_tmp
    [[ -n "$digest" ]] || return 1
    sha_tmp=$(mktemp "$STATE_DIR/.agent-config.sha256.XXXXXX") || return 1
    printf '%s\n' "$digest" > "$sha_tmp"
    chmod 644 "$sha_tmp"
    mv -f "$sha_tmp" "$AGENT_CONFIG_SHA256_FILE"
}

# _write_agent_config_version <tenant-id> <version>
#   Writes the tenant-keyed floor {"tenant_id":...,"config_version":...}
#   (PAT-1756, format in the ANTI-ROLLBACK FLOOR section) to
#   AGENT_CONFIG_VERSION_FILE via a temp file in STATE_DIR + atomic rename,
#   same pattern as _write_agent_config_sha256 and
#   _write_agent_config_heartbeat above. <tenant-id> must be the tenant bound
#   in the verified payload being committed.
#
#   PAT-1035 (round 7 finding 1): this used to write with a truncating
#   redirect (`printf '%s' "$version" > "$AGENT_CONFIG_VERSION_FILE"`), which
#   truncates the file before writing it. A crash or write failure in that
#   window leaves the file empty. AGENT_CONFIG_VERSION_FILE is the verifier's
#   anti-rollback floor, and an empty file reads back as version 0 — which
#   permits replay of any older validly-signed config, exactly what this file
#   exists to stop. Writing to a temp file and renaming into place means the
#   file is always either the old version or the new one, never empty.
_write_agent_config_version() {
    local floor_tenant="$1" version="$2" ver_tmp
    [[ -n "$floor_tenant" && "$version" == <-> ]] || return 1
    ver_tmp=$(mktemp "$STATE_DIR/.agent-config.version.XXXXXX") || return 1
    if ! "$PYTHON3" -c '
import json, sys
tenant, version, dest = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(dest, "w", encoding="utf-8") as fh:
    fh.write(json.dumps({"tenant_id": tenant, "config_version": version}, separators=(",", ":")))
' "$floor_tenant" "$version" "$ver_tmp" 2>/dev/null; then
        rm -f "$ver_tmp"
        return 1
    fi
    chmod 644 "$ver_tmp"
    mv -f "$ver_tmp" "$AGENT_CONFIG_VERSION_FILE"
}

# _write_agent_config_execution_denial
#   Atomically publishes the cross-version denial marker. The marker contains
#   no policy and grants nothing; its existence alone is fail-closed. The
#   verifier's distinct exit 42 is the only production caller allowed to reach
#   this helper.
_write_agent_config_execution_denial() {
    local verified_denial_tmp="$1" denial_size
    [[ -f "$verified_denial_tmp" && ! -L "$verified_denial_tmp" ]] || return 1
    denial_size=$(wc -c < "$verified_denial_tmp" 2>/dev/null | tr -d '[:space:]') \
        || return 1
    [[ "$denial_size" == <-> && "$denial_size" -gt 0 && "$denial_size" -le 1024 ]] \
        || return 1
    chmod 600 "$verified_denial_tmp" || return 1
    mv -f "$verified_denial_tmp" "$AGENT_CONFIG_EXECUTION_DENY_FILE"
}

# _agent_config_record_authenticated_denial
#   Preserve config/version/hash as diagnostic last-good state while denying
#   every execution consumer immediately. Removing the heartbeat also protects
#   older mixed-version App Control readers that do not know this marker yet.
_agent_config_record_authenticated_denial() {
    local verified_denial_tmp="$1"
    if ! _write_agent_config_execution_denial "$verified_denial_tmp"; then
        echo "agent-config: CRITICAL: authenticated execution revocation could not be persisted at $AGENT_CONFIG_EXECUTION_DENY_FILE"
        log_jsonl "error" "CRITICAL: authenticated execution revocation marker write failed"
        return 1
    fi

    # Keep forcing a full signed response until a completely valid policy can
    # replace this denial. Failure here does not weaken the marker-aware gates.
    if ! : > "$AGENT_CONFIG_FORCE_REFETCH_FILE" 2>/dev/null; then
        echo "agent-config: CRITICAL: execution is denied, but the force-refetch sentinel could not be written"
        log_jsonl "error" "CRITICAL: authenticated execution revocation could not force a full refetch"
    fi

    rm -f "$AGENT_CONFIG_HEARTBEAT_FILE" 2>/dev/null || true
    if [[ -e "$AGENT_CONFIG_HEARTBEAT_FILE" || -L "$AGENT_CONFIG_HEARTBEAT_FILE" ]]; then
        echo "agent-config: CRITICAL: authenticated execution revocation is marked, but the old heartbeat could not be removed"
        log_jsonl "error" "CRITICAL: authenticated execution revocation could not remove prior heartbeat"
        return 1
    fi

    echo "agent-config: authenticated newer policy revoked execution authority but was otherwise rejected; last-good cache retained for diagnostics; actuation denied"
    log_jsonl "warn" "authenticated rejected policy revoked execution authority; actuation denied"
    return 0
}

# _agent_config_handle_verifier_rejection <exit-code> <denial-metadata-file>
#   Exit 42 is a manifest-covered verifier assertion that authentication,
#   tenant binding, newer-version ordering and authority revocation all passed.
#   Every other exit is untrusted input and must leave trusted state untouched.
_agent_config_handle_verifier_rejection() {
    local verifier_rc="$1" verified_denial_tmp="$2"
    if [[ "$verifier_rc" == "42" ]]; then
        _agent_config_record_authenticated_denial "$verified_denial_tmp"
        return $?
    fi
    echo "agent-config: verification failed; keeping last-good config"
    log_jsonl "error" "config verification failed"
    return 1
}

# _agent_config_commit_verified <out_tmp>
#   The 200-path publish sequence: hash <out_tmp> AND extract its
#   config_version (the verified digest and version, PAT-1035 finding round
#   5 for the digest, round 6 for config_version — both taken from the
#   verifier's own output, before publish, never re-derived from
#   AGENT_CONFIG_FILE after the mv), publish it, write the captured
#   config_version, write the digest, clear any pending force-refetch
#   sentinel, stamp the heartbeat, clear the PAT-1042 suspended marker if one
#   is present (this fetch is proof the device's credentials work again), and
#   — only once every one of those has succeeded — fire the log-upload
#   trigger (PAT-1035 round 6 finding 2; same precedent as the 304 path
#   below, which already gates the trigger on a confirmed-good outcome).
#   Each step's own success gates the next (PAT-1035 finding 3) so a partial
#   failure never reports success, advances the heartbeat, or triggers log
#   upload. See "Commit order (crash-safe)" above this section for the full
#   ordering rationale and crash-window analysis.
#   Depends only on the plain path variables (AGENT_CONFIG_FILE,
#   AGENT_CONFIG_VERSION_FILE, AGENT_CONFIG_SHA256_FILE,
#   AGENT_CONFIG_FORCE_REFETCH_FILE, STATE_DIR, AGENT_CONFIG_HEARTBEAT_FILE,
#   CREDS_DIR) and PYTHON3, plus the helpers above (and _trigger_log_upload,
#   defined just above this sentinel block), so it has no path hardcoded
#   inside.
#   Returns 0 only when every step through the heartbeat write succeeded (a
#   failure to clear the suspended marker is logged CRITICAL but does not by
#   itself turn an otherwise-durable commit into a reported failure — see the
#   inline comment at that step).
_agent_config_commit_verified() {
    local out_tmp="$1" new_ver new_tenant verified_floor commit_ok verified_digest

    # PAT-1035 finding (round 5): hash BEFORE publish, from a path nothing
    # else writes to — see the "Commit order" comment above for why this
    # can't move below the mv.
    verified_digest=$(_agent_config_sha256 "$out_tmp")
    if [[ -z "$verified_digest" ]]; then
        echo "agent-config: could not hash verifier output at $out_tmp — not publishing, keeping last-good config"
        log_jsonl "error" "config commit failed: could not hash verifier output"
        rm -f "$out_tmp"
        return 1
    fi

    # PAT-1035 finding (round 6): extract config_version from $out_tmp too,
    # BEFORE publish, for the same reason as the digest above. This used to
    # be read back from AGENT_CONFIG_FILE after the mv below, which let
    # anything that swapped the published file in the window between the mv
    # and this read choose the value written to AGENT_CONFIG_VERSION_FILE —
    # the verifier's anti-rollback floor.
    #
    # PAT-1756: the tenant_id is taken from the same verified output, because
    # the floor is keyed by the tenant bound in the payload being committed.
    verified_floor=$("$PYTHON3" -c '
import json, sys
config = json.load(open(sys.argv[1]))
version, tenant = config["config_version"], config["tenant_id"]
if (not isinstance(version, int) or isinstance(version, bool) or version < 0
        or not isinstance(tenant, str) or not tenant.strip()
        or any(ch in tenant for ch in "\t\r\n")):
    raise SystemExit(1)
print(f"{version}\t{tenant}")
' "$out_tmp" 2>/dev/null) || verified_floor=""
    new_ver="${verified_floor%%$'\t'*}"
    new_tenant="${verified_floor#*$'\t'}"
    if [[ -z "$verified_floor" || "$new_ver" != <-> || -z "$new_tenant" || "$new_tenant" == "$verified_floor" ]]; then
        echo "agent-config: could not read config_version and tenant_id out of verifier output at $out_tmp, not publishing, keeping last-good config"
        log_jsonl "error" "config commit failed: could not read config_version and tenant_id from verifier output"
        rm -f "$out_tmp"
        return 1
    fi
    # Defence in depth: the verifier already refuses a payload bound to any
    # tenant but PATCHED_TENANT_ID. The floor is keyed by this tenant, so
    # refuse to publish, and never write a floor, for output bound elsewhere
    # or when the enrolled tenant is not known here.
    if [[ -z "${TENANT_ID:-}" || "$new_tenant" != "$TENANT_ID" ]]; then
        echo "agent-config: ERROR: verifier output is bound to a different tenant than the enrolled tenant ${TENANT_ID:-<unset>}, not publishing, keeping last-good config"
        log_jsonl "error" "config commit refused: verifier output tenant does not match the enrolled tenant"
        rm -f "$out_tmp"
        return 1
    fi

    if ! mv -f "$out_tmp" "$AGENT_CONFIG_FILE"; then
        echo "agent-config: verified config could not be committed — mv to $AGENT_CONFIG_FILE failed, keeping last-good config"
        log_jsonl "error" "config commit failed: mv to AGENT_CONFIG_FILE failed"
        rm -f "$out_tmp"
        return 1
    fi

    # Config is durably in place; now advance the version-file using the
    # value captured from $out_tmp above, before publish — never re-derived
    # from AGENT_CONFIG_FILE here (see Commit order above). Written via
    # _write_agent_config_version's temp-file + atomic-rename so a failed or
    # interrupted write can never leave this file empty (PAT-1035 round 7
    # finding 1 — an empty file is read back as version 0, the anti-rollback
    # floor's disarmed state).
    commit_ok=1
    if ! _write_agent_config_version "$new_tenant" "$new_ver"; then
        commit_ok=0
        echo "agent-config: config committed to $AGENT_CONFIG_FILE but writing $AGENT_CONFIG_VERSION_FILE failed — not reporting success"
        log_jsonl "error" "config commit failed: version-file write failed" "{\"version\":\"$new_ver\"}"
    fi
    (( commit_ok )) || return 1

    # PAT-1035 finding 2: record $verified_digest — computed from $out_tmp
    # before publish above — not a fresh hash of AGENT_CONFIG_FILE here.
    if ! _write_agent_config_sha256 "$verified_digest"; then
        echo "agent-config: config committed to $AGENT_CONFIG_FILE but writing $AGENT_CONFIG_SHA256_FILE failed — not reporting success"
        log_jsonl "error" "config commit failed: sha256 write failed" "{\"version\":\"${new_ver:-unknown}\"}"
        return 1
    fi

    # This fetch just did the full re-verification the sentinel existed to
    # force, so clear it now that the commit is fully durable.
    rm -f "$AGENT_CONFIG_FORCE_REFETCH_FILE"
    echo "agent-config: updated and cached ($AGENT_CONFIG_FILE)"
    log_jsonl "info" "config updated and cached" "{\"version\":\"${new_ver:-unknown}\"}"
    _write_agent_config_heartbeat || return 1

    # A completely accepted config supersedes authenticated revocation floors
    # only when it is strictly newer than every recorded authority floor. A
    # same-version full denial is safe to cache, but it must not erase the only
    # durable evidence that makes a later conflicting same-version grant fail.
    #
    # PAT-1763: the marker is keyed by the tenant whose signed policy revoked
    # execution, because its floors are that tenant's config_version numbers.
    # A marker keyed to a different tenant than the one this verified config
    # is bound to ($new_tenant, already proven equal to the enrolled tenant)
    # is superseded by this commit: the device now belongs to another tenant,
    # whose version numbers say nothing about the old tenant's. A marker with
    # no tenant_id (written before PAT-1763) is the enrolled tenant's, the same
    # rule as a legacy anti-rollback floor, and keeps the version comparison.
    # A tenant_id that is not a non-empty string never clears. Enrolment never
    # removes the marker.
    local denial_may_clear=0
    if [[ -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" || -L "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]]; then
        "$PYTHON3" - "$AGENT_CONFIG_EXECUTION_DENY_FILE" "$AGENT_CONFIG_FILE" "$new_tenant" <<'PYEOF' >/dev/null 2>&1
import json, sys
MAX_DENIAL_BYTES = 1024
LEGACY_FLOOR = 'legacy_app_execution_revoked_at'
APP_CONTROL_FLOOR = 'app_control_revoked_at'
DENIAL_TENANT = 'tenant_id'
committed_tenant = sys.argv[3]

def reject_ambiguous_keys(pairs):
    parsed = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate or case-colliding denial key')
        seen.add(folded)
        parsed[key] = value
    return parsed

with open(sys.argv[1], 'rb') as handle:
    raw_denial = handle.read(MAX_DENIAL_BYTES + 1)
if len(raw_denial) > MAX_DENIAL_BYTES:
    raise SystemExit(1)
denial = json.loads(
    raw_denial.decode('utf-8'), object_pairs_hook=reject_ambiguous_keys
)
config = json.load(open(sys.argv[2]))
denied_version = denial.get('config_version') if isinstance(denial, dict) else None
config_version = config.get('config_version') if isinstance(config, dict) else None
if (not isinstance(denied_version, int) or isinstance(denied_version, bool)
        or not isinstance(config_version, int) or isinstance(config_version, bool)):
    raise SystemExit(1)
if DENIAL_TENANT in denial:
    marker_tenant = denial[DENIAL_TENANT]
    if not isinstance(marker_tenant, str) or not marker_tenant.strip() or not committed_tenant:
        raise SystemExit(1)
    if marker_tenant != committed_tenant:
        raise SystemExit(0)
floor_values = []
if LEGACY_FLOOR not in denial and APP_CONTROL_FLOOR not in denial:
    floor_values = [denied_version, denied_version]
else:
    for key in (LEGACY_FLOOR, APP_CONTROL_FLOOR):
        value = denial.get(key)
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool):
                raise SystemExit(1)
            floor_values.append(value)
    if not floor_values or denied_version != max(floor_values):
        raise SystemExit(1)
raise SystemExit(0 if config_version > max(floor_values) else 1)
PYEOF
        denial_may_clear=$?
    fi
    if [[ $denial_may_clear -eq 0 ]]; then
        rm -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" 2>/dev/null || true
    else
        : > "$AGENT_CONFIG_FORCE_REFETCH_FILE" 2>/dev/null || true
        rm -f "$AGENT_CONFIG_HEARTBEAT_FILE" 2>/dev/null || true
        echo "agent-config: accepted policy does not supersede authenticated execution revocation; actuation remains denied"
        log_jsonl "warn" "accepted policy did not supersede authenticated execution revocation"
        return 1
    fi
    if [[ -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" || -L "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]]; then
        echo "agent-config: CRITICAL: verified config committed but prior execution-denial marker could not be cleared; actuation remains denied"
        log_jsonl "error" "CRITICAL: verified config could not clear prior execution-denial marker"
        return 1
    fi

    # PAT-1042: a signature-verified 200 is proof this device has working
    # credentials again — the mirror image of the 401 handler below that
    # writes $CREDS_DIR/suspended. Clear only here, after every commit step
    # above has fully succeeded (never on a bare/unverified 200, and never
    # from the 304 path, which proves nothing about credentials). Resume
    # NORMAL operation immediately on clear, symmetric with the immediate
    # suspend on 401 — no consecutive-success threshold — which also
    # self-heals a transient or mistaken 401 for free. A failure to remove
    # the marker is reported loudly but does not fail this otherwise-durable
    # commit. Non-author review (round 3) caught a stale claim here: an
    # earlier comment said this "cannot self-heal without operator
    # intervention" because the SUSPENDED STATE CHECK above "still exits
    # before ever reaching a fetch" — that was true pre-PAT-1042 but is false
    # now. The check no longer exits; the very next poll re-reaches this same
    # fetch/verify/commit path, re-verifies, and retries the `rm` on its own,
    # no operator required. Only a poll that keeps failing this specific `rm`
    # forever (e.g. the marker's parent directory itself is permanently
    # unwritable) would need operator intervention, and that failure mode is
    # loud (CRITICAL, below) precisely so it gets noticed if it ever persists.
    if [[ -f "$CREDS_DIR/suspended" ]]; then
        if rm -f "$CREDS_DIR/suspended"; then
            echo "agent-config: device reinstated — suspended marker cleared"
            log_jsonl "info" "device reinstated — suspended marker cleared"
        else
            echo "agent-config: CRITICAL — verified config committed but could not remove $CREDS_DIR/suspended; device stays suspended until this path is writable, but the next poll will automatically retry the removal (no operator action needed unless this keeps recurring)"
            log_jsonl "error" "CRITICAL: reinstatement failed — could not clear suspended marker after a verified commit; will retry automatically on the next poll" "{\"file\":\"$CREDS_DIR/suspended\"}"
        fi
    fi

    # PAT-1035 round 6 finding 2: only fire the trigger once the commit is
    # fully durable (heartbeat included) — same precedent as
    # _agent_config_handle_304 below, which only fires it on a confirmed
    # hash match. A failed or partial commit must not cause
    # patched-log-upload.sh to act on a config we did not confirm.
    _trigger_log_upload

    # PAT-1109: decommission is evaluated last, same precedent as the
    # log-upload trigger above — only once the commit is fully durable, so
    # the bytes _decommission_poll_hook reads back off AGENT_CONFIG_FILE are
    # provably the ones just Ed25519-verified by verify-agent-config.py.
    _decommission_poll_hook
    return 0
}

# _agent_config_handle_304
#   Decision logic for a 304 response. A 304 only proves the server thinks
#   our recorded VERSION is current (If-None-Match) — it says nothing about
#   whether AGENT_CONFIG_FILE's on-disk bytes are still the ones that were
#   actually verified (an old, unverified uploader can overwrite the config
#   without touching the version sidecar — PAT-1035 finding 2). Only stamp
#   the heartbeat and fire the log-upload trigger when
#   _agent_config_hash_matches confirms the bytes are still the verified
#   ones. On a mismatch: withhold the heartbeat, skip the log-upload trigger
#   (PAT-1035 finding 1 — acting on a directive in unverified bytes would
#   defeat the hash check that just caught them), quarantine the unverified
#   bytes out of AGENT_CONFIG_FILE's canonical path so nothing else on the
#   box can read them in the meantime (PAT-1040 — the mismatch used to be
#   detected but the file left in place and readable for the rest of the poll
#   cycle), and set the force-refetch sentinel so the next poll suppresses
#   If-None-Match and re-verifies
#   instead of looping on 304s forever.
#   Returns 0 only on a confirmed match with a durable heartbeat write, 1 on
#   a mismatch or on a heartbeat write failure.
_agent_config_handle_304() {
    # A 304 for the diagnostic last-good version cannot supersede a newer
    # authenticated rejected-policy revocation. Withhold the heartbeat and
    # keep forcing a full response until one passes complete verification.
    if [[ -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" || -L "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]]; then
        rm -f "$AGENT_CONFIG_HEARTBEAT_FILE" 2>/dev/null || true
        : > "$AGENT_CONFIG_FORCE_REFETCH_FILE" 2>/dev/null || true
        echo "agent-config: 304 received while authenticated execution denial is active; heartbeat withheld; full refetch still required"
        log_jsonl "warn" "304 cannot supersede authenticated execution denial; heartbeat withheld"
        return 1
    fi

    if _agent_config_hash_matches; then
        # PAT-1035 (round 7 finding 2): this call used to be unchecked, same
        # gap the 200 path already closed (round 6 finding 2, above:
        # `_write_agent_config_heartbeat || return 1`). If this write fails
        # silently here, the heartbeat ages past the freshness window on a
        # device that is polling successfully, and the uploader's
        # enforcement gate quietly stops enforcing with nothing in the log
        # to explain why. Check it, log it plainly, and do not fire the
        # trigger or report success on a failure.
        if ! _write_agent_config_heartbeat; then
            echo "agent-config: 304 with a confirmed hash match, but writing $AGENT_CONFIG_HEARTBEAT_FILE failed — not stamping heartbeat, enforcement gate may go stale"
            log_jsonl "error" "304 heartbeat write failed despite confirmed hash match — enforcement gate may go stale"
            return 1
        fi
        _trigger_log_upload
        # PAT-1109: same confirmed-hash-match precondition _trigger_log_upload
        # above already relies on — see the PATCHED_DECOMMISSION_GATE block
        # below for why that precondition is load-bearing for this call, not
        # decorative.
        _decommission_poll_hook
        return 0
    fi

    echo "agent-config: 304 but on-disk config does not match the last verified hash — withholding heartbeat, forcing full re-fetch next poll"
    log_jsonl "warn" "304 response but cached config hash mismatch — heartbeat withheld"

    # PAT-1040: the hash mismatch just detected above means AGENT_CONFIG_FILE
    # holds bytes nobody verified — an old, unverified uploader can overwrite
    # it without touching the version sidecar (see the function doc comment).
    # Move it aside rather than leaving it readable at its canonical path for
    # the rest of this poll cycle (up to ~15 minutes until the next poll).
    # AGENT_CONFIG_QUARANTINE_FILE is a fixed path alongside AGENT_CONFIG_FILE
    # under the same STATE_DIR, so this mv is an atomic rename, not a
    # copy+delete, and a repeat mismatch simply overwrites the previous
    # quarantine copy — the ticket asks for the mismatched bytes to still be
    # on disk for inspection, not a full audit trail of every quarantine
    # event. This is an addition, not a gate: failure here must not prevent
    # the force-refetch sentinel below from being written.
    # TODO(PAT-1029): once the agent_health.degraded channel exists, this
    # quarantine event (and its failure below) should also feed that channel.
    # Today it is local-log-only.
    #
    # Round-1 non-author review finding (P1): a CRITICAL log line alone was
    # not enough here — nothing is watching these logs automatically until
    # PAT-1029's channel exists, so a quarantine-move failure used to leave
    # the unverified bytes exactly as exposed at the canonical path as if
    # this whole ticket had never shipped. The actual security property this
    # ticket exists to deliver is that the daemon sees "absent", not
    # "unverified-but-present" — evidence preservation is a nice-to-have on
    # top of that, not a substitute for it. So on a failed mv, fall back to
    # rm -f: losing the on-disk quarantine copy is an acceptable trade for
    # guaranteeing AGENT_CONFIG_FILE is gone. Only if even that fails (e.g.
    # STATE_DIR itself unwritable — truly exceptional) do we fall through to
    # the CRITICAL log as the last resort, now naming both failures.
    if mv -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_QUARANTINE_FILE" 2>/dev/null; then
        echo "agent-config: quarantined unverified config to $AGENT_CONFIG_QUARANTINE_FILE — $AGENT_CONFIG_FILE is now absent"
        log_jsonl "warn" "config quarantined after 304 hash mismatch" "{\"quarantine_file\":\"$AGENT_CONFIG_QUARANTINE_FILE\"}"
    elif rm -f "$AGENT_CONFIG_FILE" 2>/dev/null && [[ ! -f "$AGENT_CONFIG_FILE" ]]; then
        echo "agent-config: could not quarantine unverified config to $AGENT_CONFIG_QUARANTINE_FILE — force-removed $AGENT_CONFIG_FILE instead so it is absent (no quarantine copy preserved this time)"
        log_jsonl "error" "config quarantine move failed after 304 hash mismatch — fell back to force-removing the file so it is at least absent (no quarantine copy preserved)" "{\"file\":\"$AGENT_CONFIG_FILE\",\"quarantine_file\":\"$AGENT_CONFIG_QUARANTINE_FILE\"}"
    else
        echo "agent-config: CRITICAL — could not quarantine unverified config from $AGENT_CONFIG_FILE to $AGENT_CONFIG_QUARANTINE_FILE, AND could not force-remove it either, after detecting a 304 hash mismatch. The unverified config remains readable at its canonical path, exactly as exposed as if this quarantine step did not exist."
        log_jsonl "error" "CRITICAL: config quarantine move AND force-remove fallback both failed after hash mismatch — unverified config remains at canonical path" "{\"file\":\"$AGENT_CONFIG_FILE\",\"quarantine_file\":\"$AGENT_CONFIG_QUARANTINE_FILE\"}"
    fi

    # PAT-1035 (round 7 finding 3): this sentinel is the only thing that
    # turns a detected mismatch back into a full fetch — if its creation
    # fails, the server keeps answering 304, the mismatch is re-detected
    # forever, the heartbeat is never stamped, and enforcement stays off
    # permanently with no path back. That is the one case in this script
    # that cannot self-heal, so it must be the loudest thing in the log
    # rather than a discarded error.
    if : > "$AGENT_CONFIG_FORCE_REFETCH_FILE" 2>/dev/null; then
        chmod 644 "$AGENT_CONFIG_FORCE_REFETCH_FILE" 2>/dev/null || true
    else
        echo "agent-config: CRITICAL — could not create force-refetch sentinel at $AGENT_CONFIG_FORCE_REFETCH_FILE after detecting a config hash mismatch. This poll cannot self-heal: every future 304 will re-detect the same mismatch, the heartbeat will never be stamped, and enforcement will stay OFF PERMANENTLY until a write to this path succeeds."
        log_jsonl "error" "CRITICAL: force-refetch sentinel write failed after hash mismatch — mismatch cannot self-heal, enforcement stays off permanently until this write succeeds" "{\"file\":\"$AGENT_CONFIG_FORCE_REFETCH_FILE\"}"
    fi
    return 1
}
# <<< PATCHED_CONFIG_COMMIT_END

# ---------------------------------------------------------------------------
# DECOMMISSION GATE (PAT-1109)
#
# Evaluates the signed `decommission` object (PAT-1108,
# contracts/agent-config.schema.json) on every poll that reaches a confirmed
# state — the 200-commit path above and the 304-hash-match branch of
# _agent_config_handle_304 above, and ONLY those two, never anywhere else.
# That restriction is the entire security property: this is the single most
# destructive action in the product (irreversible; no channel left to
# correct a mistake once the agent is gone), and PAT-1035 is the precedent
# for what happens when a destructive directive rides a channel without
# point-of-action verification (patched-upload.sh cached agent-config with
# no signature check and overwrote the verified copy).
#
# FAIL CLOSED, in the opposite direction from a tier gate: there, "unknown"
# means don't enforce; here, "unknown" means don't delete. Every branch below
# that is not a confident, verified "act" leaves the agent exactly as it was.
#
# _decommission_check's FIRST line of defence is _agent_config_hash_matches
# (defined above, inside PATCHED_CONFIG_COMMIT — it is why this block is
# ordered after that one) — not decorative here: it is what makes "nothing
# in this path is triggerable by an unsigned or locally-modified config file
# on disk" true, because AGENT_CONFIG_SHA256_FILE is only ever written (in
# _agent_config_commit_verified above) from a digest taken BEFORE publish, of
# bytes verify-agent-config.py already Ed25519-verified. A config file that
# was ever written by anything else — a hand-edited file, an old
# unverified uploader, a partially-applied attack — fails that check and
# _decommission_check returns "fault" without reading anything else.
#
# On top of that inherited guarantee, this block independently re-checks
# tenant_id and config_version at the point of action (not merely trusting
# that verify-agent-config.py checked them minutes/hours ago at commit time)
# per the ticket's explicit list of point-of-action verification rules.
# expires_at sanity (unparseable, or absurd — earlier than
# DECOMMISSION_BUILD_FLOOR) is new logic: verify-agent-config.py's JSON
# Schema `format: date-time` is descriptive only and not enforced
# client-side, so this is the first place expires_at is actually validated.
#
# >>> PATCHED_DECOMMISSION_GATE_START (keep in sync with any future copy)
# DECOMMISSION_BUILD_FLOOR: a fixed sanity floor, not a precise build
# timestamp — decommission mode did not exist before PAT-1108, so any
# expires_at earlier than this is definitionally malformed or the product of
# a badly wrong on-device clock, never a legitimate directive. Bump forward
# at future release cuts if desired; there is no live stamping mechanism for
# this today (a gap worth a follow-up ticket, not a blocker for this one).
DECOMMISSION_BUILD_FLOOR="${PATCHED_DECOMMISSION_BUILD_FLOOR:-2026-07-01T00:00:00Z}"
DECOMMISSION_DIR="${PATCHED_DECOMMISSION_DIR:-/Library/Application Support/Patched/.decommission}"
DECOMMISSION_DAEMON_LABEL="com.patched.decommission"
DECOMMISSION_DAEMON_PLIST="${PATCHED_DECOMMISSION_DAEMON_PLIST:-/Library/LaunchDaemons/${DECOMMISSION_DAEMON_LABEL}.plist}"

# DECOMMISSION_MAX_CLOCK_SKEW_SECONDS (PAT-1109 P2 D): how far the local
# wall clock is allowed to run ahead of the server's own clock (measured via
# the /v1/agent-config response's Date header, freshest-available, THIS
# poll only — see AGENT_CONFIG_CLOCK_SKEW_SECONDS in the FETCH section
# above) before an expiry evaluation refuses to trust "now" at all. A device
# whose clock is set far enough ahead would otherwise decommission itself
# before its real expiry — irreversibly. Generous (5 minutes) to absorb
# normal NTP jitter and request latency without false-faulting a healthy
# device; the point is catching "wildly wrong", not enforcing tight sync.
DECOMMISSION_MAX_CLOCK_SKEW_SECONDS="${PATCHED_DECOMMISSION_MAX_CLOCK_SKEW_SECONDS:-300}"

# _decommission_check
#   Sets DECOMMISSION_DECISION to one of:
#     none  — no directive, or mode="none" (the steady-state default)
#     wait  — mode="expiry", expires_at valid and sane, not yet due
#     fault — anything unverifiable or malformed; DECOMMISSION_REASON names it
#     act   — a verified, due directive; DECOMMISSION_PURGE (0/1),
#             DECOMMISSION_OPERATOR_REASON (audit-only, never evaluated) and
#             DECOMMISSION_CONFIG_VERSION (the config_version this decision
#             was made against — captured HERE, at the point of acting, not
#             read back later from a file that may already be deleted by the
#             time anyone wants it) are also set.
#
#   PAT-1109 second-round finding P1 A (TOCTOU): everything below happens
#   inside ONE python3 process that opens AGENT_CONFIG_FILE exactly ONCE,
#   hashes those exact in-memory bytes, and — only if that hash matches
#   AGENT_CONFIG_SHA256_FILE — parses every field (mode, expires_at, purge,
#   reason, tenant_id, config_version) from that SAME in-memory snapshot.
#   The path is never re-opened. The previous shape of this function called
#   _agent_config_hash_matches (which re-reads the file to hash it) and then
#   separately re-opened AGENT_CONFIG_FILE two more times to parse fields —
#   three separate opens of an untrusted local path, each its own window for
#   a concurrent local writer to swap the bytes between the hash check and a
#   parse. A hash pin proves nothing about bytes it did not itself read.
#
#   Cheap in the overwhelmingly common "none"/"wait" case: one bounded
#   python3 invocation, no network, no filesystem writes beyond the reads
#   named above.
_decommission_check() {
    DECOMMISSION_DECISION="fault"
    DECOMMISSION_REASON="unknown"

    local py_out tag
    py_out=$("$PYTHON3" -c '
import hashlib, json, sys
from datetime import datetime, timezone

config_path, sha_path, tenant_path, version_path, floor_str, skew_str, max_skew_str, floor_module_path = sys.argv[1:9]

def parse_rfc3339(s):
    if not isinstance(s, str) or not s:
        return None
    s2 = s.strip()
    if s2.endswith("Z") or s2.endswith("z"):
        s2 = s2[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s2)
    except Exception:
        return None
    if dt.tzinfo is None:
        return None
    try:
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

# ---- SINGLE READ of the untrusted subject (PAT-1109 P1 A / TOCTOU fix) ----
# AGENT_CONFIG_FILE is opened exactly once, right here. Every later step —
# the hash check AND the JSON parse AND every field read below — uses THIS
# SAME in-memory byte string. The path is never opened again in this
# process. A concurrent writer that replaces the file on disk after this
# read has no effect on this evaluation: there is nothing left to race.
try:
    with open(config_path, "rb") as f:
        config_bytes = f.read()
except FileNotFoundError:
    print("none:config_absent"); sys.exit(0)
except Exception:
    print("fault:config_unreadable"); sys.exit(0)

try:
    with open(sha_path) as f:
        recorded_hash = f.readline().strip()
except Exception:
    recorded_hash = ""

actual_hash = hashlib.sha256(config_bytes).hexdigest()
if not recorded_hash or actual_hash != recorded_hash:
    # Covers both "never verified" (no sha file / empty) and "verified once,
    # then something else wrote to the canonical path since" (PAT-1035
    # shape) -- either way, config_bytes above is NOT provably the bytes
    # verify-agent-config.py Ed25519-verified, so nothing past this point
    # may act on its contents.
    print("fault:config_not_confirmed_verified"); sys.exit(0)

try:
    config = json.loads(config_bytes)
except Exception:
    print("fault:config_unreadable"); sys.exit(0)
if not isinstance(config, dict):
    print("fault:config_not_object"); sys.exit(0)

decomm = config.get("decommission")
if not isinstance(decomm, dict):
    print("none:absent"); sys.exit(0)

mode = decomm.get("mode")
if mode not in ("none", "expiry", "immediate"):
    print("fault:mode_unrecognised"); sys.exit(0)
if mode == "none":
    print("none:mode_none"); sys.exit(0)

purge = "1" if decomm.get("purge") is True else "0"
reason = decomm.get("reason")
reason = reason if isinstance(reason, str) else ""
# reason is audit-only, NEVER evaluated as control flow — tab/newline-strip
# only so it cannot break the tab-separated line this prints.
reason = reason.replace("\t", " ").replace("\n", " ")[:200]

# ---- point-of-action re-checks: tenant_id + anti-rollback, from the SAME
#      in-memory config parsed above, independent of (not merely trusting)
#      the checks the verifier already made at commit time ----
cfg_tenant = config.get("tenant_id") or ""
try:
    with open(tenant_path) as f:
        local_tenant = f.readline().strip()
except Exception:
    local_tenant = ""
if not cfg_tenant or not local_tenant or cfg_tenant != local_tenant:
    print("fault:tenant_id_mismatch"); sys.exit(0)

cfg_version = config.get("config_version")
# PAT-1756: the anti-rollback floor is keyed by tenant. It counts here only when
# it is a legacy bare integer (the floor of the enrolled tenant) or keyed to
# local_tenant, which the check above already proved equals cfg_tenant. A
# missing, unreadable, corrupt or other-tenant floor cannot vouch for this
# config: fault. PAT-1763: parsed by agent_config_floor.py, loaded by path
# without a bytecode cache, the same parser the verifier used at commit time.
# A module that cannot be loaded vouches for nothing either.
try:
    import importlib.util
    sys.dont_write_bytecode = True
    floor_spec = importlib.util.spec_from_file_location("patched_agent_config_floor", floor_module_path)
    floor_module = importlib.util.module_from_spec(floor_spec)
    floor_spec.loader.exec_module(floor_module)
except Exception:
    print("fault:rollback_floor_reader_unavailable"); sys.exit(0)
try:
    recorded_version = floor_module.recorded_version_for_tenant(
        floor_module.read_floor(version_path), local_tenant)
except Exception:
    recorded_version = None
if recorded_version is None:
    print("fault:rollback_floor_unusable"); sys.exit(0)
if not isinstance(cfg_version, int) or isinstance(cfg_version, bool) or cfg_version < recorded_version:
    print("fault:config_version_regressed"); sys.exit(0)

if mode == "immediate":
    print(f"act:immediate\t{purge}\t{reason}\t{cfg_version}"); sys.exit(0)

# ---- mode == "expiry" ----
floor = parse_rfc3339(floor_str)
exp = parse_rfc3339(decomm.get("expires_at"))
if exp is None:
    print("fault:expires_at_unparseable"); sys.exit(0)
if floor is not None and exp < floor:
    print("fault:expires_at_absurd"); sys.exit(0)

# ---- clock-skew bound (PAT-1109 P2 D, hardened P1-A) ----
# skew_str is local_clock_minus_server_clock as measured on this same poll
# HTTP response (see AGENT_CONFIG_CLOCK_SKEW_SECONDS in the FETCH section) —
# never a value persisted from an earlier, possibly-stale poll.
#
# P1-A (non-author review finding): skew UNMEASURABLE this poll (empty —
# e.g. header capture failed) used to be treated as "not itself a fault"
# and fell through to comparing expires_at against the untrusted LOCAL wall
# clock. That fails OPEN: a device whose local clock is set far enough
# ahead can make a legitimately-future expires_at look due, and
# DECOMMISSION_BUILD_FLOOR only catches a clock that is wrong in the
# BACKDATED direction (an absurdly early expires_at) — never a fast one
# racing toward a real, still-future expires_at. Fixed: when server time
# cannot be established this poll, DEFER for mode=expiry — fault, not act,
# not even wait (we do not know if it is due, so we do not claim either
# answer). This costs nothing: the very same directive is re-evaluated on
# the next poll, and nothing about it is lost or cancelled by deferring.
# mode=immediate never reaches this code (it returns above, before this
# block) so it is correctly unaffected — it is not a wall-clock comparison.
try:
    skew = int(skew_str) if skew_str else None
except Exception:
    skew = None
if skew is None:
    print("fault:clock_skew_unmeasurable"); sys.exit(0)
try:
    max_skew = int(max_skew_str)
except Exception:
    max_skew = 300
if skew > max_skew:
    print("fault:local_clock_implausibly_ahead"); sys.exit(0)

if datetime.now(timezone.utc) >= exp:
    print(f"act:expiry_due\t{purge}\t{reason}\t{cfg_version}")
else:
    print("wait:expiry_not_due")
' "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" "$CREDS_DIR/tenant-id" "$AGENT_CONFIG_VERSION_FILE" \
      "$DECOMMISSION_BUILD_FLOOR" "${AGENT_CONFIG_CLOCK_SKEW_SECONDS:-}" "$DECOMMISSION_MAX_CLOCK_SKEW_SECONDS" \
      "$AGENT_CONFIG_FLOOR_MODULE" 2>/dev/null) || py_out=""
    [[ -n "$py_out" ]] || py_out="fault:evaluator_error"

    tag="${py_out%%$'\t'*}"
    case "$tag" in
        none:*) DECOMMISSION_DECISION="none";  DECOMMISSION_REASON="${tag#none:}";  return 0 ;;
        wait:*) DECOMMISSION_DECISION="wait";  DECOMMISSION_REASON="${tag#wait:}";  return 0 ;;
        fault:*) DECOMMISSION_DECISION="fault"; DECOMMISSION_REASON="${tag#fault:}"; return 0 ;;
        act:*) : ;;
        *) DECOMMISSION_DECISION="fault"; DECOMMISSION_REASON="evaluator_unexpected_output"; return 0 ;;
    esac

    local rest purge_field rest2 reason_field version_field
    rest="${py_out#*$'\t'}"
    purge_field="${rest%%$'\t'*}"
    rest2="${rest#*$'\t'}"
    reason_field="${rest2%%$'\t'*}"
    version_field="${rest2#*$'\t'}"

    if ! [[ "$version_field" =~ ^[0-9]+$ ]]; then
        # Defensive: the evaluator only ever emits a numeric cfg_version on
        # an "act:" line (it already validated it as an int above), but
        # never trust a downstream parse of upstream output blindly on the
        # single most destructive path in the product.
        DECOMMISSION_DECISION="fault"; DECOMMISSION_REASON="evaluator_unexpected_output"
        return 0
    fi

    DECOMMISSION_DECISION="act"
    DECOMMISSION_REASON="${tag#act:}"
    DECOMMISSION_PURGE=$( [[ "$purge_field" == "1" ]] && echo 1 || echo 0 )
    DECOMMISSION_OPERATOR_REASON="$reason_field"
    # Captured by the SAME atomic read above — at the point of deciding to
    # act — per the platform contract for POST /v1/agent-decommission-status:
    # the terminal-status report must carry the config_version the directive
    # was actually acted on, not whatever is newest when the report is
    # finally sent (a delayed report reading this back off a file could
    # easily see a newer, or no, value by then).
    DECOMMISSION_CONFIG_VERSION="$version_field"
    return 0
}

# _decommission_trigger_removal <purge 0|1> <operator_reason> <trigger_reason> <config_version>
#   Stages a detached, self-contained removal (patched-decommission.sh plus
#   byte-identical copies of endpoint/uninstall.sh and macos/uninstall.sh,
#   renamed to avoid a filename collision in the flat staging dir) into
#   DECOMMISSION_DIR, then bootstraps it under its OWN LaunchDaemon label
#   (com.patched.decommission) — never this job's own label. A daemon cannot
#   `launchctl bootout` its own label and survive to finish, and
#   endpoint/uninstall.sh's own teardown list includes com.patched.config-poll
#   (this job), so the removal work cannot run inline here.
#
#   DECOMMISSION_DIR is deliberately NOT touched by endpoint/uninstall.sh or
#   macos/uninstall.sh (neither lists it, and this is intentional — do not
#   "fix" that by adding it to either script's cleanup list). Those scripts
#   run staged, byte-identical COPIES of themselves from inside
#   DECOMMISSION_DIR as part of this same flow; if either script also tore
#   down DECOMMISSION_DIR or the com.patched.decommission LaunchDaemon, it
#   would delete or kill its own caller (patched-decommission.sh) mid-run,
#   stranding the parts of the removal that had not run yet. Only
#   patched-decommission.sh's own final self-cleanup step (after both
#   uninstall engines have fully completed) removes DECOMMISSION_DIR and its
#   LaunchDaemon.
#
#   Idempotent: if com.patched.decommission is already loaded, does nothing
#   (the already-running/scheduled detached daemon owns completion from here).
_decommission_trigger_removal() {
    local purge="$1" operator_reason="$2" trigger_reason="$3" config_version="$4"
    local asset src

    if launchctl print "system/$DECOMMISSION_DAEMON_LABEL" >/dev/null 2>&1; then
        echo "decommission: $DECOMMISSION_DAEMON_LABEL already staged — not restaging"
        log_jsonl "warn" "decommission already in progress — not restaging"
        return 0
    fi

    echo "decommission: directive due ($trigger_reason) — staging detached removal at $DECOMMISSION_DIR"
    log_jsonl "warn" "decommission triggered" \
        "{\"reason\":\"$trigger_reason\",\"purge\":$( [[ "$purge" == 1 ]] && echo true || echo false ),\"config_version\":\"$config_version\"}"

    if ! install -d -o root -g wheel -m 700 "$DECOMMISSION_DIR"; then
        echo "decommission: CRITICAL could not create $DECOMMISSION_DIR — cannot stage removal, agent stays installed"
        log_jsonl "error" "decommission staging failed: could not create DECOMMISSION_DIR"
        return 1
    fi

    for asset in "patched-decommission.sh" "endpoint-uninstall.sh" "macos-uninstall.sh" "com.patched.decommission.plist"; do
        src="$BUNDLE_DIR/$asset"
        if [[ ! -f "$src" ]]; then
            echo "decommission: CRITICAL missing bundle asset $src — cannot stage removal, agent stays installed"
            log_jsonl "error" "decommission staging failed: missing bundle asset" "{\"asset\":\"$asset\"}"
            return 1
        fi
        if ! cp "$src" "$DECOMMISSION_DIR/$asset"; then
            echo "decommission: CRITICAL could not copy $asset into $DECOMMISSION_DIR — cannot stage removal, agent stays installed"
            log_jsonl "error" "decommission staging failed: copy failed" "{\"asset\":\"$asset\"}"
            return 1
        fi
    done
    chown root:wheel "$DECOMMISSION_DIR"/*.sh "$DECOMMISSION_DIR"/*.plist 2>/dev/null
    chmod 700 "$DECOMMISSION_DIR/patched-decommission.sh" "$DECOMMISSION_DIR/endpoint-uninstall.sh" "$DECOMMISSION_DIR/macos-uninstall.sh"
    chmod 644 "$DECOMMISSION_DIR/com.patched.decommission.plist"

    local info_tmp
    info_tmp=$(mktemp "$DECOMMISSION_DIR/.info.XXXXXX") || { echo "decommission: CRITICAL could not create info temp file"; log_jsonl "error" "decommission staging failed: info mktemp failed"; return 1; }
    if ! "$PYTHON3" -c '
import json, sys
json.dump({
    "mode": sys.argv[1], "purge": sys.argv[2] == "1", "reason": sys.argv[3],
    "directive_version": int(sys.argv[4]), "triggered_at": sys.argv[5],
}, open(sys.argv[6], "w"))
' "$trigger_reason" "$purge" "$operator_reason" "$config_version" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$info_tmp"; then
        echo "decommission: CRITICAL could not write decommission-info.json"
        log_jsonl "error" "decommission staging failed: info write failed"
        rm -f "$info_tmp"
        return 1
    fi
    chmod 600 "$info_tmp"
    # non-author review, third round: this mv used to be unchecked. If it
    # fails (destination is a directory, cross-device rename, disk full,
    # permission race) while an OLDER decommission-info.json from a prior
    # attempt/version remains on disk, the code below would go on to
    # bootstrap the daemon against that STALE directive — wrong mode, wrong
    # purge flag, wrong config_version, whatever an earlier attempt happened
    # to leave behind. The daemon must only ever bootstrap against a
    # freshly-verified directive. So: on failure, do NOT proceed to install
    # the plist or bootstrap anything, and remove whatever is at the
    # destination path too — either this publish lands atomically and
    # verified, or nothing usable is left there at all. Safe to do: this
    # function is only ever reached when no decommission daemon is
    # CURRENTLY loaded (see the launchctl print guard above), and
    # _decommission_check re-verifies the directive fresh on every poll, so
    # a later poll that re-triggers republishes cleanly from scratch.
    if ! mv -f "$info_tmp" "$DECOMMISSION_DIR/decommission-info.json"; then
        echo "decommission: CRITICAL could not publish decommission-info.json (mv failed) — cannot stage removal, agent stays installed"
        log_jsonl "error" "decommission staging failed: info publish (mv) failed"
        rm -f "$info_tmp" "$DECOMMISSION_DIR/decommission-info.json"
        return 1
    fi

    if ! cp "$DECOMMISSION_DIR/com.patched.decommission.plist" "$DECOMMISSION_DAEMON_PLIST"; then
        echo "decommission: CRITICAL could not install $DECOMMISSION_DAEMON_PLIST — removal not started"
        log_jsonl "error" "decommission staging failed: plist install failed"
        rm -f "$DECOMMISSION_DIR/decommission-info.json"
        return 1
    fi
    chown root:wheel "$DECOMMISSION_DAEMON_PLIST"
    chmod 644 "$DECOMMISSION_DAEMON_PLIST"

    launchctl bootout "system/$DECOMMISSION_DAEMON_LABEL" 2>/dev/null || true
    if ! launchctl bootstrap system "$DECOMMISSION_DAEMON_PLIST"; then
        echo "decommission: CRITICAL could not bootstrap $DECOMMISSION_DAEMON_LABEL — removal not started"
        log_jsonl "error" "decommission staging failed: bootstrap failed"
        # non-author review, third round: a plist sitting in
        # /Library/LaunchDaemons that launchd does not currently have
        # loaded can still be picked up by launchd on a LATER boot
        # (RunAtLoad=true), running a directive this function just reported
        # as removal-not-started — armed even though nothing here believes
        # it is armed. Remove the plist just installed, and the
        # decommission-info.json just published (same "never leave a stale
        # directive behind a failed publish" principle as the mv-failure
        # branch above), so launchd cannot auto-run it later. A later poll
        # that re-verifies and re-triggers republishes both from scratch.
        rm -f "$DECOMMISSION_DAEMON_PLIST"
        rm -f "$DECOMMISSION_DIR/decommission-info.json"
        return 1
    fi

    echo "decommission: $DECOMMISSION_DAEMON_LABEL bootstrapped — removal proceeding out-of-process"
    log_jsonl "warn" "decommission handed off to detached daemon"
    return 0
}

# _decommission_poll_hook
#   Called only from the two confirmed-good call sites described above.
#   Dispatches on _decommission_check's decision. The "none" case — the
#   overwhelmingly common one, forever, for every tenant without an active
#   directive — logs nothing and calls nothing beyond the cheap check
#   already performed: behaviour is byte-for-byte unchanged from before this
#   ticket for a config with no decommission object.
_decommission_poll_hook() {
    _decommission_check
    case "$DECOMMISSION_DECISION" in
        act)
            _decommission_trigger_removal "$DECOMMISSION_PURGE" "$DECOMMISSION_OPERATOR_REASON" "$DECOMMISSION_REASON" "$DECOMMISSION_CONFIG_VERSION"
            ;;
        fault)
            echo "decommission: fault — $DECOMMISSION_REASON — leaving agent running (fail closed)"
            log_jsonl "error" "decommission fault — leaving agent running" "{\"reason\":\"$DECOMMISSION_REASON\"}"
            ;;
        wait)
            log_jsonl "info" "decommission expiry not yet due"
            ;;
        none|*)
            : # steady state — no-op, no log line, matches pre-PAT-1109 behaviour
            ;;
    esac
}
# <<< PATCHED_DECOMMISSION_GATE_END

if [[ "$http_code" == "304" ]]; then
    echo "agent-config: not modified (304) — cached config unchanged"
    log_jsonl "info" "config not modified (304)"
    _agent_config_handle_304
    rm -f "$resp_file"
    exit 0
fi

if [[ "$http_code" == "401" ]]; then
    # PAT-1745: the server returns the same bare 401 for every authentication
    # failure on purpose, so the response never leaks why. Revocation is only
    # one of those causes; asserting it here misdirected PAT-1604's diagnosis
    # of a lost credential. Log what is actually known. The suspend below is
    # unchanged. Kept word-for-word in step with the Windows line in
    # windows/src/Service/AgentConfigFetcher.cs (AuthRejectedLogMessage).
    echo "PATCHED_AUTH_REJECTED: /v1/agent-config returned HTTP 401. The server does not disclose the reason. Possible causes: credential expired or unknown, tenant or device revoked, clock skew outside the replay window, nonce replay, or bearer token and HMAC secret mismatch. Entering suspended state until a signature-verified 200"
    log_jsonl "warn" "authentication rejected by server (401, reason not disclosed); entering suspended state" '{"event":"PATCHED_AUTH_REJECTED","http_code":"401"}'
    install -d -o root -g wheel -m 700 "$CREDS_DIR"
    touch "$CREDS_DIR/suspended"
    chmod 600 "$CREDS_DIR/suspended"
    chown root:wheel "$CREDS_DIR/suspended"
    rm -f "$resp_file"
    exit 0
fi

if [[ "$http_code" != "200" ]]; then
    echo "agent-config: fetch returned HTTP $http_code — keeping last-good config"
    log_jsonl "warn" "config fetch failed" "{\"http_code\":\"$http_code\"}"
    rm -f "$resp_file"
    exit 0
fi

# ---------------------------------------------------------------------------
# VERIFY AND CACHE
#
# Commit order (crash-safe):
#   1. Verifier writes verified config to a temp file, $out_tmp
#      (output-file arg).
#   2. Shell hashes $out_tmp — the verified digest — AND extracts its
#      config_version, BEFORE anything is published. PAT-1035 finding (round
#      5 for the digest, round 6 for config_version): both of these used to
#      happen after the mv below, by re-reading AGENT_CONFIG_FILE off disk.
#      Anything that replaced agent-config.json in the window between that
#      mv and the read got its bytes/version recorded as "verified" instead
#      of the verifier's actual output — and for config_version specifically,
#      that value is the anti-rollback floor the verifier checks the NEXT
#      poll against, so a swap in that window let an attacker choose it.
#      Deriving both from $out_tmp here — a path nothing but this script
#      writes to, before publish — means the recorded digest and version can
#      only ever be what the verifier actually produced. If either can't be
#      derived, nothing is published at all; the last-good config is kept.
#   3. Shell atomically mv's $out_tmp into place (AGENT_CONFIG_FILE).
#   4. Shell writes the config_version captured in step 2 to
#      AGENT_CONFIG_VERSION_FILE.
#   5. Shell writes the digest computed in step 2 to
#      AGENT_CONFIG_SHA256_FILE (PAT-1035 finding 2) — binds the next 304's
#      heartbeat to the bytes actually verified in step 1, not to whatever
#      is on disk when this step runs, and not just to the version-file's
#      ETag value.
#
# Crash safety, by boundary:
#
# Between 1 and 2 (verifier succeeded, digest/version not yet taken):
# $out_tmp sits under /tmp, nothing published, nothing recorded. Next run
# starts clean and refetches. Harmless.
#
# Between 2 and 3 (digest and version known, not yet published): same as
# above — nothing published, nothing recorded yet, $out_tmp still under
# /tmp. Next run refetches from scratch. Harmless.
#
# Between 3 and 4 (published, version-file not yet written): the config is
# at new_version but the version-file still holds old_version. On the next
# run the ETag will be old_version, the server returns 200, the verifier
# accepts (new >= old), and the version-file is written from that run's
# $out_tmp. No config is ever locked to a stale version. AGENT_CONFIG_SHA256_FILE
# still holds the PRIOR verified digest at this point (step 5 hasn't run), so
# if anything reads the config before the next successful commit, the hash
# check correctly fails closed rather than treating the not-yet-recorded new
# config as verified.
#
# Between 4 and 5 (version-file written, hash-file not yet updated):
# AGENT_CONFIG_SHA256_FILE is stale (or, on a first-ever run, absent). The
# next 304's hash check then finds a mismatch (or a missing hash file),
# correctly withholds the heartbeat, and forces a full re-fetch — fail-safe,
# not a hang, and it self-heals within one poll.
#
# Between 5 and the heartbeat write (see below): the hash file is current
# but the heartbeat isn't stamped yet. A concurrent reader sees a missing or
# stale heartbeat and fails closed until the heartbeat is written — never a
# false "healthy". The log-upload trigger only fires after the heartbeat
# write succeeds (PAT-1035 round 6 finding 2), so a crash in this window
# also means no trigger fires for this poll.
# ---------------------------------------------------------------------------

[[ -x "$VERIFIER" ]] || { echo "ERROR: verifier missing at $VERIFIER"; rm -f "$resp_file"; exit 1; }

out_tmp=$(mktemp /tmp/.patched-config-out.XXXXXX)
denial_tmp=$(mktemp /tmp/.patched-config-denial.XXXXXX)

PATCHED_TENANT_ID="$TENANT_ID" \
"$PYTHON3" "$VERIFIER" \
       --response-file "$resp_file" \
       --version-file  "$AGENT_CONFIG_VERSION_FILE" \
       --current-config-file "$AGENT_CONFIG_FILE" \
       --current-config-sha256-file "$AGENT_CONFIG_SHA256_FILE" \
       --execution-denial-file "$AGENT_CONFIG_EXECUTION_DENY_FILE" \
       --output-file   "$out_tmp" \
       --execution-denial-output-file "$denial_tmp"
verifier_rc=$?

if [[ $verifier_rc -eq 0 ]]; then
    rm -f "$denial_tmp"
    chmod 644 "$out_tmp"
    # PAT-1035 finding 3 / finding (round 5): the commit sequence itself
    # lives in _agent_config_commit_verified (defined above, extracted and
    # tested directly by endpoint/test-agent-config-commit.zsh) — hash
    # out_tmp, mv, write version, write hash, clear the force-refetch
    # sentinel, stamp the heartbeat, each step gating the next. See "Commit
    # order (crash-safe)" above for the full ordering rationale and
    # crash-window analysis.
    _agent_config_commit_verified "$out_tmp"
else
    _agent_config_handle_verifier_rejection "$verifier_rc" "$denial_tmp" || true
    rm -f "$out_tmp" "$denial_tmp"
fi

# No unconditional _trigger_log_upload call here (PAT-1035 round 6 finding
# 2): the log-upload trigger now fires from inside
# _agent_config_commit_verified (200 path, only on a fully durable commit)
# and _agent_config_handle_304 (304 path, only on a confirmed hash match)
# above, so a failed verification, a failed commit, or an unconfirmed 304
# never reaches patched-log-upload.sh.
rm -f "$resp_file"
exit 0
