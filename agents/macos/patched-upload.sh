#!/bin/zsh
##############################################################################
# patched-upload
#
# Drains /var/db/patched/queue/ and POSTs each inventory JSON to the patched.im
# ingestion endpoint with HMAC + bearer auth.
#
# v1 deployment:
#   - LaunchDaemon `com.patched.upload` runs this every 900s (15 min).
#   - The 15-minute schedule IS the retry interval — no in-process exponential
#     backoff or sidecar state. Files older than MAX_AGE_DAYS get dropped.
#
# Credentials are loaded from /etc/patched/ (mode 600, root-owned):
#   /etc/patched/tenant-id     — UUID, informational only
#   /etc/patched/bearer-token  — opaque string from POST /admin/tenants
#   /etc/patched/hmac-secret   — base64-encoded HMAC key
#
# Override the target URL for local testing:
#   sudo PATCHED_API_URL=http://127.0.0.1:8080 ./patched-upload.sh
##############################################################################

set -u

# Sudo may strip PATH to a value that doesn't include /bin or /usr/bin.
# Force a fixed PATH so basic Unix utilities resolve.
#
# SECURITY (H10): this daemon runs as root. We exclude /usr/local/{sbin,bin}
# (non-root-writable on many Macs) and do NOT append the inherited ${PATH},
# so a local attacker cannot shadow curl/openssl/etc.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

API_URL="${PATCHED_API_URL:-https://api.patched.im}"
QUEUE_DIR="/var/db/patched/queue"
LOG_FILE="/var/log/patched-upload.log"
CREDS_DIR="/etc/patched"
MAX_AGE_DAYS=7

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== patched-upload run started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "API target: $API_URL"

# Resolve python3 to an absolute path (sudo strips PATH; lookup is unreliable).
# Apple's stock python3 at /usr/bin/python3 is always present with the
# Command Line Tools, so it is the only path we use; no package-manager
# fallback.
PYTHON3="/usr/bin/python3"
if [[ ! -x "$PYTHON3" ]]; then
    echo "FATAL: no usable python3 found at $PYTHON3"
    exit 1
fi

# Directory this script lives in, used to source the lib/*.sh enforcement
# modules further down when running from a source-tree checkout (lib/
# present next to this script). The release-built dist/patched-upload.sh
# (via build-bundle.sh) has those modules inlined instead — no lib/
# directory ships in that tarball, so the sourcing below never runs there.
SCRIPT_DIR_UPLOAD="${0:A:h}"

# SECURITY (H11): per-run, root-owned, 0700, unpredictably named scratch dir
# under $STATE_DIR (parent is /var/db, root-owned) for HMAC request bodies and
# the curl response file — never world-writable /tmp with a predictable
# PID-based name that a local attacker could pre-create and symlink-redirect.
STATE_DIR="/var/db/patched"
mkdir -p "$STATE_DIR"
PATCHED_TMPDIR=$(mktemp -d "$STATE_DIR/.upload.XXXXXXXX") || {
    echo "FATAL: could not create secure temp dir under $STATE_DIR"
    exit 1
}
chmod 700 "$PATCHED_TMPDIR"
trap 'rm -rf "$PATCHED_TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# LOAD CREDENTIALS
# ---------------------------------------------------------------------------

for f in tenant-id bearer-token hmac-secret; do
    if [[ ! -f "$CREDS_DIR/$f" ]]; then
        echo "ERROR: $CREDS_DIR/$f missing — aborting"
        exit 1
    fi
done

BEARER_TOKEN=$(head -1 "$CREDS_DIR/bearer-token" | tr -d '[:space:]')

# PAT-513: device identity header — forward-compatible; server ignores until
# per-device token enforcement is live in the platform.
#
# Empty, not "Unknown", is the failure value here (PAT-1724): every consumer
# (the inventory POST below, app_control.sh, browser_extension_control.sh,
# browser_extension_removal.sh) treats empty HW_UUID as "no device id" and
# omits the X-Patched-Device-Id header / audit device_id. A literal "Unknown"
# would be sent as a device identity. The collector's hardware.sh uses
# "Unknown" because the payload field is non-nullable; that is a different
# contract. ioreg's output and exit status are captured before parsing, since
# in `ioreg | awk || fallback` the fallback tests awk's status, not ioreg's.
# The sentinels let macos/lib/test-hardware.zsh extract and exercise this block.
# >>> PATCHED_HW_UUID_START
patched_hw_uuid() {
    local hw_ioreg=""
    hw_ioreg=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null) || return 0
    print -r -- "$hw_ioreg" | awk -F'"' '/IOPlatformUUID/ {print $4; exit}'
}
# <<< PATCHED_HW_UUID_END
HW_UUID=$(patched_hw_uuid)

# ---------------------------------------------------------------------------
# SAFE-CREDENTIAL HELPERS (PAT-881)
# ---------------------------------------------------------------------------
#
# Kept INLINE, not in a sourced lib/ file, so patched-upload.sh stays
# self-contained: the release tarball ships this script WITHOUT a lib/ directory
# ("no lib/ needed at runtime"), so a sourced dependency would break every
# upload on a release-deployed Mac. The lib/*.sh enforcement modules sourced
# further down inherit these definitions via shell scope. patched-bootstrap.sh
# carries a byte-compatible standalone copy of the same two mechanisms.
#
# WHY: passing a secret as an argv token exposes it to any local user. `ps -ww`
# shows every process's full command line. So the bearer token is fed to curl
# over stdin (`-H @-`), and the HMAC key is read from a file inside Python,
# never as an argument.
#
# The sentinel markers below delimit the block that macos/lib/test-patched-creds.zsh
# extracts and exercises directly, so the shipped code itself is under test.
# >>> PATCHED_CREDS_HELPERS_START (keep in sync with patched-bootstrap.sh)

# patched_hmac_hex <body-file> <secret-file> <encoding>
#   HMAC-SHA256(body, key) as lowercase hex, no trailing newline. The key is
#   read from <secret-file> inside Python, never on argv. <encoding>:
#     base64: base64-decode the file contents (the collector's hmac-secret is
#              stored base64-encoded; matches the historical compute_hmac).
#     raw:    file bytes directly, CR/LF stripped (openssl `-hmac "$KEY"`
#              semantics). Pure Python, avoids the openssl-key-on-argv trap.
patched_hmac_hex() {
    "$PYTHON3" - "$1" "$2" "$3" <<'PYEOF'
import sys, hmac, hashlib, base64
body_path, secret_path, encoding = sys.argv[1], sys.argv[2], sys.argv[3]
with open(secret_path, 'rb') as f:
    raw = f.read()
if encoding == 'base64':
    key = base64.b64decode(raw.strip())
else:  # raw: match the shell's `tr -d '\n\r'` on the credential
    key = raw.translate(None, b'\r\n')
with open(body_path, 'rb') as f:
    body = f.read()
print(hmac.new(key, body, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# compute_hmac <body-file> <endpoint-id> <ts> <nonce>
#   Collector request HMAC, PAT-1154 v3 canonical form:
#     HMAC-SHA256(b"patched-hmac-v3\n" + method + b"\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body)
#   using the base64 hmac-secret in $CREDS_DIR/hmac-secret. ts and nonce MUST
#   be the exact strings sent in the X-Patched-Timestamp / X-Patched-Nonce
#   headers for this same request, so a captured signed body cannot be
#   replayed. The lib/*.sh enforcement modules call this by name — callers
#   generate ts+nonce FIRST, then pass them here AND into the headers.
#   Deliberately bypasses patched_hmac_hex (which hashes raw body bytes only
#   and stays untouched as a general-purpose primitive under test) so the
#   v2 domain-prefixed message never has to round-trip through a temp file.
compute_hmac() {
    "$PYTHON3" - "$1" "$2" "$3" "$4" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
body_path, endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path, 'rb') as f:
    secret = base64.b64decode(f.read().strip())
with open(body_path, 'rb') as f:
    body = f.read()
msg = b"patched-hmac-v3\nPOST\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n" + body
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# patched_curl_bearer <bearer-token> [curl args...]
#   curl with `Authorization: Bearer <token>` supplied over stdin (`-H @-`) so
#   the token never appears on argv. All other args pass through unchanged;
#   request bodies come from files (`--data-binary @file`) or are absent (GET),
#   so stdin is free for the header.
patched_curl_bearer() {
    local _token="$1"
    shift
    printf 'Authorization: Bearer %s\n' "$_token" | curl -H @- "$@"
}
# <<< PATCHED_CREDS_HELPERS_END

POSTURE_DIR="/Library/Application Support/Patched"
OS_UPDATE_STATUS_FILE="$POSTURE_DIR/update-status.json"

# PAT-1833: carry the OS-update verdict the endpoint daemon already computed
# into the inventory payload. The daemon runs daily at 03:00: a value computed
# at today's run stays within the 48h window through a single missed run
# tomorrow, up to the following day's scheduled run — two consecutive missed
# runs are what it takes for evidence to actually go stale and be omitted.
# This is upload freshness only; it is not a claim that an OS verdict remains
# substantively current for 48 hours. Future checked_at values are rejected,
# and a valid value is copied unchanged so the platform retains the source
# computation time rather than the upload time.
#
# Kept inline because the release bundle ships patched-upload.sh as a single
# file. The sentinel lets macos/test-os-update-payload.zsh exercise these exact
# shipped bytes without credentials, root, a queue daemon, or network access.
# >>> PATCHED_OS_UPDATE_PAYLOAD_START
OS_UPDATE_MAX_AGE_SECS=$(( 48 * 60 * 60 ))

# patched_os_update_merge_into_payload <source-payload> <update-status> <output> [now-epoch]
#
# The queued collector payload is never edited. The output always starts from
# that payload with any pre-existing os_update member removed, then receives the
# local status file's block only when it matches the endpoint contract and its
# checked_at is within the bounded freshness window. Missing, unreadable,
# malformed, partial, type-invalid, stale and future evidence are all omission,
# never guessed defaults. now-epoch is a deterministic test seam; production
# omits it and uses the current UTC time.
patched_os_update_merge_into_payload() {
    local _source_payload="$1"
    local _update_status="$2"
    local _output_payload="$3"
    local _now_epoch="${4:-}"

    "$PYTHON3" - "$_source_payload" "$_update_status" "$_output_payload" \
        "$OS_UPDATE_MAX_AGE_SECS" "$_now_epoch" <<'PYEOF'
import datetime
import json
import sys

source_path, status_path, output_path, max_age_raw, now_raw = sys.argv[1:]
max_age = int(max_age_raw)
now = (datetime.datetime.fromtimestamp(float(now_raw), datetime.timezone.utc)
       if now_raw else datetime.datetime.now(datetime.timezone.utc))

# target_os is optional and nullable (PAT-2123/PAT-2133): with no policy target
# and no known latest version there is no target, and the state is unknown.
required = {
    'installed_os', 'state', 'severity', 'security_relevant',
    'actively_exploited', 'deferrals_remaining', 'checked_at',
}
allowed = required | {'target_os', 'latest_os', 'deadline', 'release_age_days'}
states = {
    'up_to_date', 'update_recommended', 'update_required', 'deadline_passed',
    'unsupported_hardware', 'unknown',
}
severities = {'none', 'low', 'medium', 'high', 'critical'}

def reject_duplicate_keys(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate key')
        seen.add(folded)
        result[key] = value
    return result

def parse_datetime(value):
    if not isinstance(value, str):
        raise ValueError('not a string')
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone missing')
    return parsed.astimezone(datetime.timezone.utc)

def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)

def validate(block):
    if not isinstance(block, dict):
        return 'unavailable'
    if set(block) - allowed or required - set(block):
        return 'partial or has unknown fields'
    if not isinstance(block['installed_os'], str):
        return 'invalid OS version type'
    if 'target_os' in block and block['target_os'] is not None and not isinstance(block['target_os'], str):
        return 'invalid target_os type'
    if 'latest_os' in block and block['latest_os'] is not None and not isinstance(block['latest_os'], str):
        return 'invalid latest_os type'
    if (not isinstance(block['state'], str) or block['state'] not in states
            or not isinstance(block['severity'], str) or block['severity'] not in severities):
        return 'invalid state or severity'
    if type(block['security_relevant']) is not bool or type(block['actively_exploited']) is not bool:
        return 'invalid security flag type'
    if not is_int(block['deferrals_remaining']) or block['deferrals_remaining'] < 0:
        return 'invalid deferrals_remaining'
    if 'release_age_days' in block:
        release_age = block['release_age_days']
        if release_age is not None and (not is_int(release_age) or release_age < 0):
            return 'invalid release_age_days'
    if 'deadline' in block and block['deadline'] is not None:
        try:
            parse_datetime(block['deadline'])
        except (TypeError, ValueError):
            return 'invalid deadline'
    try:
        checked_at = parse_datetime(block['checked_at'])
    except (TypeError, ValueError):
        return 'invalid checked_at'
    age = (now - checked_at).total_seconds()
    if age < 0:
        return 'future checked_at'
    if age > max_age:
        return 'stale checked_at'
    return None

with open(source_path, encoding='utf-8') as source_file:
    payload = json.load(source_file, object_pairs_hook=reject_duplicate_keys)
if not isinstance(payload, dict):
    raise ValueError('inventory payload is not an object')

# A queued payload may have been produced by a different collector version.
# Never let an old os_update member bypass the current status-file validation.
payload.pop('os_update', None)

reason = None
try:
    with open(status_path, encoding='utf-8') as status_file:
        status = json.load(status_file, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(status, dict):
        reason = 'status is not an object'
    else:
        block = status.get('os_update')
        reason = validate(block)
        if reason is None:
            payload['os_update'] = block
except FileNotFoundError:
    reason = 'status absent'
except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
    reason = 'status unreadable or malformed: ' + type(exc).__name__

with open(output_path, 'w', encoding='utf-8') as output_file:
    json.dump(payload, output_file, separators=(',', ':'))

if reason is None:
    print('os_update included from local update-status.json')
else:
    print('os_update omitted: ' + reason)
PYEOF
}
# <<< PATCHED_OS_UPDATE_PAYLOAD_END

# agent-config.json is written only by endpoint/patched-fetch-config.sh (the
# com.patched.config-poll daemon), which does full Ed25519 verification against
# the pinned key_id, tenant binding, and anti-rollback before committing
# anything (PAT-1035). This script used to fetch and write its own unverified
# copy; it is now a pure reader, gated below. AC_HEARTBEAT_FILE is the
# liveness signal that daemon writes on every confirmed-current poll (a 200
# it verifies and commits, or a 304 telling it the cache is still current).
AC_CONFIG_FILE="$POSTURE_DIR/agent-config.json"
AC_HEARTBEAT_FILE="$POSTURE_DIR/agent-config.checked"
# PAT-1035 finding 2 (upload side): SHA-256 sidecar endpoint/patched-fetch-config.sh
# writes next to AC_CONFIG_FILE on every verified commit. The heartbeat above
# only proves a recent successful poll happened; it says nothing about
# whether AC_CONFIG_FILE's current on-disk bytes are still the ones that poll
# verified. ac_gate_check hashes them and compares against this file so a
# fresh heartbeat cannot vouch for bytes nobody verified.
AC_CONFIG_SHA256_FILE="$POSTURE_DIR/agent-config.sha256"
# Written only by the manifest-covered endpoint config poller after its
# verifier authenticates a newer tenant policy that revokes execution but
# rejects elsewhere. This outranks a still-fresh diagnostic last-good cache.
AC_EXECUTION_DENY_FILE="$POSTURE_DIR/agent-config.execution-denied"
# PAT-1035 finding 2 (round 4): written by endpoint/patched-fetch-config.sh
# (and endpoint/patched-enroll.sh) when the server rejects this device: a
# 401 from the signed agent-config endpoint, or a terminal enrollment
# failure. The 401 does not say why (revocation, expired or unknown
# credential, clock skew, nonce replay and secret mismatch all look the same,
# PAT-1745), but every one of them means the platform is not accepting this
# device right now. Checked first in ac_gate_check, ahead of the heartbeat/hash
# checks, because it outranks them: an otherwise-fresh, hash-matching
# heartbeat says nothing once the server has stopped accepting the device. Same
# $CREDS_DIR default the rest of this script uses for credentials.
AC_SUSPENDED_FILE="$CREDS_DIR/suspended"
# PAT-1773: the enrolled tenant. agent-config.json is not keyed by tenant, so
# after re-enrolment into another tenant it still holds the old tenant's
# verified config until the new tenant's first accepted config. The staged
# copy must belong to this tenant or no config applies.
AC_TENANT_ID_FILE="$CREDS_DIR/tenant-id"

# ---------------------------------------------------------------------------
# AGENT-CONFIG ENFORCEMENT GATE (PAT-1035)
# ---------------------------------------------------------------------------
#
# This script no longer fetches or writes agent-config.json. It only reads
# the file endpoint/patched-fetch-config.sh (the com.patched.config-poll
# daemon) maintains, which does full Ed25519 verification against the pinned
# key_id, tenant binding, and anti-rollback before committing anything. This
# function decides whether the three enforcement blocks below may trust that
# file, and produces one of these distinct outcomes:
#
#   suspended (refuse) - AC_SUSPENDED_FILE exists. The platform rejected
#     this device's authentication (a 401 from the signed agent-config
#     endpoint, cause not disclosed, PAT-1745) or its enrollment failed
#     terminally (endpoint/patched-fetch-config.sh,
#     endpoint/patched-enroll.sh).
#     Checked first, ahead of every other check: a suspended device's last
#     heartbeat can stay inside the 24h freshness window for up to 24 hours
#     after the rejection, and that heartbeat proves nothing about a device
#     the platform has since stopped accepting. Enforcement stops immediately,
#     not on the next stale timeout.
#   absent (refuse)   - AC_CONFIG_FILE does not exist. No verified config has
#     ever landed on this device. This means com.patched.config-poll is not
#     installed or has never completed a successful fetch. This is a never
#     synced state, not a transient failure, so it is logged as such; there
#     is no cache to fall back to, and enforcement is skipped outright.
#   missing (refuse)  - AC_CONFIG_FILE exists but AC_HEARTBEAT_FILE does not.
#     See below — this is the fail-closed default, not a permissive one.
#   stale (refuse)    - AC_CONFIG_FILE exists but AC_HEARTBEAT_FILE is older
#     than AC_GATE_MAX_AGE_SECS. The poller runs every 900s, so anything past
#     24h means it has stopped. Enforcement is skipped and the age is logged.
#   future (refuse)   - AC_HEARTBEAT_FILE has an mtime later than this
#     machine's clock. That is either a future-dated heartbeat or local clock
#     rollback, neither of which can establish freshness for root actions.
#   hash mismatch (refuse) - AC_HEARTBEAT_FILE is fresh, but AC_CONFIG_FILE's
#     current on-disk bytes do not hash to the value recorded in
#     AC_CONFIG_SHA256_FILE at the last verified commit (or that sidecar is
#     missing). A fresh heartbeat only proves a recent poll happened, not
#     that nothing wrote to AC_CONFIG_FILE afterward — an old, unverified
#     uploader binary still present on a partially upgraded machine is
#     exactly the kind of write this catches. Enforcement is paused, not
#     skipped permanently: the config daemon re-verifies and re-records the
#     hash on its next poll (endpoint/patched-fetch-config.sh, PAT-1035
#     finding 2), which self-heals this within one 15-minute cycle.
#   fresh (allow)     - AC_HEARTBEAT_FILE is recent and AC_CONFIG_FILE's bytes
#     match the recorded hash. Enforce, once ac_gate_stage_config below has
#     staged the bytes and confirmed they belong to the enrolled tenant.
#   other tenant (refuse) - checked by ac_gate_stage_config on the staged
#     copy (PAT-1773). The verified config's tenant_id is not the tenant in
#     AC_TENANT_ID_FILE, is missing or invalid, the config does not parse, or
#     there is no enrolled tenant. The config is treated exactly as absent (the
#     never-synced outcome above): no tenant policy applies yet, so enforcement
#     is skipped until a signed config for the enrolled tenant is accepted.
#
# AC_HEARTBEAT_FILE missing is deliberately fail-closed, not fail-open. An
# agent-config.json already sitting on an endpoint may be a file the OLD,
# unverified uploader wrote before this device's endpoint daemon was upgraded
# to the build that writes this heartbeat (collector and endpoint upgrades
# are not ordered together). Treating "no heartbeat" as "enforce anyway"
# would drive root-level admin demotion and extension deletion from exactly
# the unverified artifact PAT-1035 exists to stop trusting — a hole in
# precisely the mixed-version window that matters. The two failure modes are
# not symmetric: enforcement pausing is visible and recoverable, and it
# self-heals within one 15-minute poll once the endpoint daemon is upgraded
# and writes its first heartbeat. Acting as root on an unverified config is
# neither visible nor recoverable. When the risks are this asymmetric, fail
# closed.
#
# Freshness is read from AC_HEARTBEAT_FILE's own mtime, never
# AC_CONFIG_FILE's. patched-fetch-config.sh returns early on HTTP 304 and
# writes nothing to AC_CONFIG_FILE in that case, so a config that is
# perfectly current but simply unchanged would otherwise carry an
# arbitrarily old mtime and get wrongly flagged stale on a healthy, stable
# tenant.
#
# Depends only on AC_SUSPENDED_FILE, AC_EXECUTION_DENY_FILE, AC_CONFIG_FILE,
# AC_HEARTBEAT_FILE, AC_CONFIG_SHA256_FILE, AC_TENANT_ID_FILE and PYTHON3, all
# plain variables set above (no path hardcoded inside this block), so
# macos/test-agent-config-gate.zsh can extract this block and drive it
# directly, without root, just by setting those variables before sourcing it.
# >>> PATCHED_AC_GATE_START
AC_GATE_MAX_AGE_SECS=$(( 24 * 60 * 60 ))

ac_gate_check() {
    if [[ -e "$AC_EXECUTION_DENY_FILE" || -L "$AC_EXECUTION_DENY_FILE" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: authenticated policy rejection. A newer signed tenant policy revoked execution authority but was rejected elsewhere. Diagnostic last-good config is retained, but all App Control actuation remains paused until a complete policy verifies."
        return 1
    fi

    # PAT-1035 finding 2 (round 4): outranks every other check — see the
    # "suspended" outcome documented above.
    if [[ -f "$AC_SUSPENDED_FILE" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: suspended. $AC_SUSPENDED_FILE exists. This device is suspended because the platform rejected its authentication (HTTP 401, reason not disclosed) or its enrollment failed terminally. Enforcement stops until a signature-verified agent-config clears the marker."
        return 1
    fi

    if [[ ! -f "$AC_CONFIG_FILE" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: never synced. No verified agent-config has ever been written at $AC_CONFIG_FILE. The config daemon (com.patched.config-poll, installed by endpoint/install.sh) is not present on this device or has never completed successfully. Enforcement skipped."
        return 1
    fi

    if [[ ! -f "$AC_HEARTBEAT_FILE" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: heartbeat missing. $AC_HEARTBEAT_FILE does not exist, so this cached config's freshness cannot be confirmed — the endpoint daemon on this device needs upgrading to a build that writes the heartbeat (com.patched.config-poll, endpoint/patched-fetch-config.sh). Enforcement is paused, not skipped permanently: it resumes automatically on the first poll after the endpoint daemon is upgraded and writes its first heartbeat."
        return 1
    fi

    local hb_mtime now age
    hb_mtime=$(stat -f %m "$AC_HEARTBEAT_FILE" 2>/dev/null) || hb_mtime=0
    now=$(date -u +%s)
    age=$(( now - hb_mtime ))

    if (( age < 0 )); then
        AC_GATE_REASON="AGENT-CONFIG GATE: future heartbeat. The config-poll heartbeat at $AC_HEARTBEAT_FILE is $(( -age ))s in the future relative to this machine's clock; future-dated heartbeat or local clock rollback. Freshness cannot be confirmed for root-level enforcement. Enforcement skipped."
        return 1
    fi

    if (( age > AC_GATE_MAX_AGE_SECS )); then
        AC_GATE_REASON="AGENT-CONFIG GATE: stale. The config-poll heartbeat at $AC_HEARTBEAT_FILE is $(( age / 3600 ))h old, past the 24h freshness window. The poller runs every 900s, so this means it stopped running. Enforcement skipped."
        return 1
    fi

    # PAT-1035 finding 2 (upload side): the heartbeat proves a recent
    # verified poll happened; it does not prove AC_CONFIG_FILE's current
    # bytes are still the ones that poll verified. Checked last, after the
    # cheap absent/missing/stale checks above, because it is the most
    # expensive check (a shasum over the file) and the least common outcome —
    # so the common pass path stays cheap, and a mismatch here reports this
    # specific reason instead of falling through to the generic "fresh" one.
    local recorded actual
    recorded=""
    [[ -f "$AC_CONFIG_SHA256_FILE" ]] && recorded=$(head -1 "$AC_CONFIG_SHA256_FILE" | tr -d '[:space:]')
    actual=$(shasum -a 256 "$AC_CONFIG_FILE" 2>/dev/null | awk '{print $1}')
    if [[ -z "$recorded" || -z "$actual" || "$recorded" != "$actual" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: hash mismatch. $AC_CONFIG_FILE's on-disk bytes do not match the SHA-256 recorded at the last verified commit, or $AC_CONFIG_SHA256_FILE was never written. The cached config is not confirmed to be the file that was verified — something else, e.g. an old uploader binary still present on a partially upgraded machine, wrote to it since. Enforcement is paused, not skipped permanently: it resumes automatically once the config daemon (com.patched.config-poll) re-verifies it, which it will do on its next poll."
        return 1
    fi

    AC_GATE_REASON="AGENT-CONFIG GATE: fresh. Config-poll heartbeat is $(( age / 60 ))m old. Enforcing."
    return 0
}

# _ac_cached_config_tenant_state <config-file> <tenant-id-file>
#   PAT-1773. Prints "applies" only when the config belongs to the enrolled
#   tenant, otherwise one line naming why not (no_enrolled_tenant, unreadable,
#   malformed, no_tenant, invalid_tenant, other_tenant). The collector ships
#   separately from the endpoint bundle, so this is the collector's copy of
#   endpoint/agent_config_tenant.py's rule, not a load of that file:
#     - enrolled tenant: first line of the tenant-id credential with ASCII
#       whitespace removed (what `head -1 | tr -d '[:space:]'` reads); missing,
#       unreadable, empty, oversized or non-UTF-8 is no enrolled tenant;
#     - the config applies only as a JSON object with no member name repeated
#       ignoring case, whose tenant_id is a non-empty string exactly equal to
#       the enrolled tenant.
#   macos/test-agent-config-gate.zsh runs this over the same fixtures as the
#   module (endpoint/fixtures/agent-config-tenant.json) so they cannot drift.
_ac_cached_config_tenant_state() {
    "$PYTHON3" -c '
import json, sys
MAX_CONFIG_BYTES = 1024 * 1024
MAX_TENANT_ID_BYTES = 4096
SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@+-")
def reject_duplicate_keys(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError("duplicate key")
        seen.add(folded)
        result[key] = value
    return result
def state():
    try:
        with open(sys.argv[1], "rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return "absent"
    except OSError as exc:
        return "unreadable " + type(exc).__name__
    enrolled = None
    try:
        with open(sys.argv[2], "rb") as fh:
            tenant_raw = fh.read(MAX_TENANT_ID_BYTES + 1)
        if len(tenant_raw) <= MAX_TENANT_ID_BYTES:
            first = tenant_raw.split(b"\n", 1)[0]
            enrolled = bytes(b for b in first if b not in b" \t\n\r\v\f").decode("utf-8") or None
    except (OSError, UnicodeDecodeError):
        enrolled = None
    if not enrolled:
        return "no_enrolled_tenant"
    if len(raw) > MAX_CONFIG_BYTES:
        return "malformed"
    try:
        config = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except Exception:
        return "malformed"
    if not isinstance(config, dict):
        return "malformed"
    if "tenant_id" not in config:
        return "no_tenant"
    tenant = config["tenant_id"]
    if not isinstance(tenant, str) or not tenant.strip():
        return "invalid_tenant"
    if tenant != enrolled:
        return "other_tenant " + "".join(c if c in SAFE else "?" for c in tenant[:64])
    return "applies"
print(state())
' "$1" "$2" 2>/dev/null
}

# ac_gate_stage_config: close the TOCTOU window between ac_gate_check
# reporting "fresh" and the three enforcement modules below actually reading
# AC_CONFIG_FILE. Without this, ac_gate_check verifies the bytes once and
# each module independently reopens the same shared, well-known path — a
# write landing anywhere in between (or between one module's read and the
# next's) hands root-level enforcement unverified policy, even though the
# gate already reported fresh.
#
# Copies the verified bytes into $PATCHED_TMPDIR (per-run, root-owned, 0700,
# unpredictably named, cleaned up by the EXIT trap — see H11 above) and
# points PATCHED_AC_CONFIG at the copy. All three lib/*.sh modules already
# read "${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}",
# so exporting it here is the only seam needed; no module code changes.
#
# PAT-1035 finding 1 (round 4): both hashes taken here — before the copy and
# after it — are checked against AC_CONFIG_SHA256_FILE, the digest recorded
# by endpoint/patched-fetch-config.sh's verified commit path, never against
# each other. Comparing the pre-copy hash to the post-copy hash (the earlier
# shape of this function) only proves the file did not change *during the
# copy*; it says nothing about whether it was already swapped before this
# function ever ran. A swap landing between ac_gate_check returning and this
# function taking its pre-copy hash would produce a pre_hash and a post_hash
# that agree with each other while both reflect the attacker's bytes — the
# old comparison would pass. Anchoring both hashes to the independently
# recorded digest instead means the only bytes that can ever reach
# PATCHED_AC_CONFIG are bytes whose hash matches what the verifier committed,
# no matter when a swap lands relative to this function.
#
# Depends only on AC_CONFIG_FILE, AC_CONFIG_SHA256_FILE and PATCHED_TMPDIR,
# all plain variables set above, so macos/test-agent-config-gate.zsh can
# drive it directly without root by pointing all three at a scratch
# directory it owns.
ac_gate_stage_config() {
    local recorded pre_hash post_hash staged

    recorded=""
    [[ -f "$AC_CONFIG_SHA256_FILE" ]] && recorded=$(head -1 "$AC_CONFIG_SHA256_FILE" | tr -d '[:space:]')
    if [[ -z "$recorded" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: staging failed. No recorded SHA-256 at $AC_CONFIG_SHA256_FILE to stage against. Enforcement skipped."
        return 1
    fi

    pre_hash=$(shasum -a 256 "$AC_CONFIG_FILE" 2>/dev/null | awk '{print $1}')
    if [[ -z "$pre_hash" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: staging failed. Could not hash $AC_CONFIG_FILE immediately before copying it into the per-run verified scratch copy. Enforcement skipped."
        return 1
    fi
    if [[ "$pre_hash" != "$recorded" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: staging failed. $AC_CONFIG_FILE's bytes immediately before staging do not match the recorded SHA-256 at $AC_CONFIG_SHA256_FILE — something swapped the file after ac_gate_check passed but before staging began. Enforcement skipped."
        return 1
    fi

    staged="$PATCHED_TMPDIR/agent-config.verified.json"
    if ! cp "$AC_CONFIG_FILE" "$staged" 2>/dev/null; then
        AC_GATE_REASON="AGENT-CONFIG GATE: staging failed. Could not copy $AC_CONFIG_FILE into $PATCHED_TMPDIR. Enforcement skipped."
        return 1
    fi

    post_hash=$(shasum -a 256 "$staged" 2>/dev/null | awk '{print $1}')
    if [[ -z "$post_hash" || "$post_hash" != "$recorded" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: staging failed. The scratch copy's SHA-256 does not match the recorded digest at $AC_CONFIG_SHA256_FILE — something wrote to $AC_CONFIG_FILE while the copy was in flight. Enforcement skipped."
        rm -f "$staged"
        return 1
    fi

    # PAT-1773: checked on the staged copy, the exact bytes enforcement will
    # read. A config that does not belong to the enrolled tenant is treated as
    # absent, the never-synced outcome: enforcement is skipped.
    local tenant_state
    tenant_state=$(_ac_cached_config_tenant_state "$staged" "$AC_TENANT_ID_FILE") || tenant_state=""
    if [[ "$tenant_state" != "applies" ]]; then
        AC_GATE_REASON="AGENT-CONFIG GATE: not the enrolled tenant's config. The verified config at $AC_CONFIG_FILE does not belong to the tenant in $AC_TENANT_ID_FILE (${tenant_state:-tenant check failed}), so it is treated as never synced: no agent-config applies to this tenant yet. Enforcement skipped until a signed config for the enrolled tenant is accepted."
        rm -f "$staged"
        return 1
    fi

    PATCHED_AC_CONFIG="$staged"
    export PATCHED_AC_CONFIG
    AC_GATE_REASON="$AC_GATE_REASON Verified copy staged at $staged for enforcement reads."
    return 0
}

# PAT-1481: App Control authority is separate from the projected package tier.
# The three retained App Control paths split into two authority levels:
#
#   - Destructive / irreversible (admin demotion via dscl, extension-artifact
#     removal): 'enforce' only. There is nothing to roll back once these run,
#     so they stay behind the highest bar.
#   - Reversible / preventive (the browser managed-policy blocklist): 'block'
#     or 'enforce'. Undoing a blocklist entry is just writing a different
#     policy value, not restoring something already deleted, so it is
#     permitted one tier lower than the other two.
#
# Reporting (ac_check_app_violations, alert-only) is unaffected by either gate
# and keeps running at every tier — root AGENTS.md: advisory findings are the
# Tier 3 sales surface.
#
# This is not the ADR-0011 macOS executor and does not authorise Installomator,
# patched-update/install/uninstall, catalogue work, mandatory installs, or any
# other legacy package operation. Those paths remain independently fail-closed
# behind legacy_app_execution_enabled and their existing gates.
#
# Both gates read app_control_authority from PATCHED_AC_CONFIG (the staged, hash-verified copy
# ac_gate_stage_config produces), never the canonical mutable path — these
# functions are only meaningful once ac_gate_check/ac_gate_stage_config have
# already passed, so the caller must gate the call on AC_GATE_ALLOWED.
#
# Missing, null, malformed, noncanonical, duplicate-key ambiguous, and unknown
# authority values resolve to report and refuse actuation. There is no permissive
# branch.
#
# Depends only on PATCHED_AC_CONFIG and PYTHON3, both plain variables set
# above, so macos/test-agent-config-gate.zsh can extract this block and
# drive it directly, without root, by pointing PATCHED_AC_CONFIG at a
# scratch file it owns.
PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY="enforce"
PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES=("block" "enforce")

# _ac_read_app_control_authority <config_file>
# Prints a canonical authority value. JSON is parsed with duplicate keys
# rejected, and the field name and value must match the lowercase wire contract;
# any error or noncanonical value resolves to report.
_ac_read_app_control_authority() {
    "$PYTHON3" -c "
import json, sys
def reject_duplicate_keys(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate key')
        seen.add(folded)
        result[key] = value
    return result
try:
    with open(sys.argv[1], encoding='utf-8') as config_file:
        cfg = json.load(config_file, object_pairs_hook=reject_duplicate_keys)
    authority = cfg.get('app_control_authority')
    print(authority if authority in {'report', 'block', 'enforce'} else 'report')
except Exception:
    print('report')
" "$1" 2>/dev/null
}

# ac_authority_gate_check: the destructive-path gate. Allows only
# PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY ('enforce'). Gates ac_enforce_admins (dscl admin
# demotion) and ber_remove_extensions (extension-artifact removal).
ac_authority_gate_check() {
    local _config_file _authority

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"

    if [[ ! -f "$_config_file" ]]; then
        AC_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: no staged agent-config at $_config_file. Resolving to report and refusing destructive actuation."
        return 1
    fi

    _authority=$(_ac_read_app_control_authority "$_config_file") || _authority="report"

    if [[ "$_authority" != "$PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY" ]]; then
        AC_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: '$_authority' does not permit destructive endpoint actuation (admin demotion, extension removal); enforce is required. Refusing."
        return 1
    fi

    AC_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: '$_authority' permits destructive actuation."
    return 0
}

# ac_blocklist_authority_gate_check: the reversible/preventive-path gate. Allows
# any authority in PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES ('block' or 'enforce'). Gates
# whether bec_enforce_extension_blocklist may PUSH new blocklist entries;
# below this tier it must still run and reconcile its managed state to empty
# (PAT-1038 follow-up) rather than being skipped, so a downgrade tears down
# whatever it previously wrote instead of stranding it.
ac_blocklist_authority_gate_check() {
    local _config_file _authority _allowed_authority

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"

    if [[ ! -f "$_config_file" ]]; then
        AC_BLOCKLIST_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: no staged agent-config at $_config_file. Resolving to report and reconciling blocklist state to empty."
        return 1
    fi

    _authority=$(_ac_read_app_control_authority "$_config_file") || _authority="report"

    for _allowed_authority in "${PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES[@]}"; do
        if [[ "$_authority" == "$_allowed_authority" ]]; then
            AC_BLOCKLIST_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: '$_authority' permits browser-extension blocklist actuation."
            return 0
        fi
    done

    AC_BLOCKLIST_AUTHORITY_GATE_REASON="APP CONTROL AUTHORITY: '$_authority' does not permit browser-extension blocklist actuation; report reconciles managed blocklist state to empty. Refusing."
    return 1
}
# <<< PATCHED_AC_GATE_END

# Evaluate the gate once; its reason is logged here, not once per block, and
# every enforcement block below checks $AC_GATE_ALLOWED. A pass here also
# stages a verified copy into $PATCHED_TMPDIR and points PATCHED_AC_CONFIG at
# it (ac_gate_stage_config, PAT-1035 finding 1 round 3) so the three modules
# below read bytes that were just hashed and verified, from a path no other
# process on the machine writes to, rather than each reopening the shared
# well-known path independently.
if ac_gate_check && ac_gate_stage_config; then
    AC_GATE_ALLOWED=1
else
    AC_GATE_ALLOWED=0
fi
echo "$AC_GATE_REASON"

# PAT-1481: evaluate both App Control authority gates for App Control's
# endpoint-actuating paths, once the PAT-1035 gate above has verified and
# staged the config — authority is read from that same staged copy
# (PATCHED_AC_CONFIG), never the canonical mutable path. When the PAT-1035
# gate itself refused, there is no staged config to trust, so both tier
# gates stay closed without needing to run.
#
# Two gates, not one: AC_AUTHORITY_ALLOWED ('enforce' only) gates the
# destructive paths (admin removal, extension removal); AC_BLOCKLIST_AUTHORITY_ALLOWED
# ('block' or 'enforce') gates the
# reversible/preventive browser-extension blocklist, one tier lower.
if (( AC_GATE_ALLOWED )); then
    if ac_authority_gate_check; then
        AC_AUTHORITY_ALLOWED=1
    else
        AC_AUTHORITY_ALLOWED=0
    fi
    echo "$AC_AUTHORITY_GATE_REASON"

    if ac_blocklist_authority_gate_check; then
        AC_BLOCKLIST_AUTHORITY_ALLOWED=1
    else
        AC_BLOCKLIST_AUTHORITY_ALLOWED=0
    fi
    echo "$AC_BLOCKLIST_AUTHORITY_GATE_REASON"
else
    AC_AUTHORITY_ALLOWED=0
    AC_BLOCKLIST_AUTHORITY_ALLOWED=0
fi

# PAT-1065: sentinel-delimited so endpoint/test-agent-health-capability.zsh
# can extract and source this exact shipped block directly (requires
# SCRIPT_DIR_UPLOAD and AC_GATE_ALLOWED set by the caller first), the same
# extraction-and-direct-call convention this repo uses elsewhere (e.g.
# endpoint/test-agent-tier-default.zsh) to test real shipped code rather than
# a hand-written copy.
# >>> PATCHED_AGENT_HEALTH_CAPABILITY_START
# ---------------------------------------------------------------------------
# AGENT HEALTH — shared degraded-capability store (PAT-1065)
# ---------------------------------------------------------------------------
#
# Provides patched_agent_health_record_failure / _record_success /
# _emit_degraded_json (macos/lib/agent_health.sh), used below by the two
# lib-missing checks (capability_missing faults) and by the MAIN LOOP just
# before each /v1/inventory POST (the agent_health emission site). Sourced
# unconditionally of AC_GATE_ALLOWED: whether the enforcement CODE is present
# on disk is not a tenant-policy question, so it must stay recordable even on
# a run where the AC gate denies enforcement.
if [[ -f "$SCRIPT_DIR_UPLOAD/lib/agent_health.sh" ]]; then
    source "$SCRIPT_DIR_UPLOAD/lib/agent_health.sh"
else
    echo "agent_health: lib/agent_health.sh not found — degraded-capability reporting unavailable this run"
fi

# ---------------------------------------------------------------------------
# APP CONTROL — approved-admins + app-allowlist enforcement (PAT-552)
# ---------------------------------------------------------------------------
#
# Run after posture fetch and the agent-config gate (creds already loaded)
# and before the upload loop.
# ac_enforce_admins: diff local admins against approved list, remove extras via
#   dscl, and POST audit events to /v1/inventory/enforcement-audit.
# ac_check_app_violations: compare /Applications against app_allowlist, report
#   violations as app_block_skipped events (alert-only in v1).
# Fail-safe: any error inside either function is non-fatal.
#
# PAT-1038: ac_enforce_admins changes endpoint state (demotes a local admin
# as root), so it additionally requires AC_AUTHORITY_ALLOWED. ac_check_app_violations
# changes nothing (alert-only, app_control.sh:285) so it keeps running at
# every tier, gated on AC_GATE_ALLOWED alone, same as before this ticket.

if [[ -f "$SCRIPT_DIR_UPLOAD/lib/app_control.sh" ]]; then
    if (( AC_GATE_ALLOWED )); then
        source "$SCRIPT_DIR_UPLOAD/lib/app_control.sh"
        if (( AC_AUTHORITY_ALLOWED )); then
            ac_enforce_admins || true
        fi
        ac_check_app_violations || true
    fi
else
    echo "app_control: lib/app_control.sh not found — skipping enforcement"
fi

# ---------------------------------------------------------------------------
# BROWSER EXTENSION CONTROL — managed-policy blocklist enforcement (PAT-828)
# ---------------------------------------------------------------------------
#
# Pushes Chrome/Edge/Firefox managed policy blocking the tenant's unapproved
# extensions (app_control.extension_blocklist in the signed agent-config) and
# posts one enforcement_audit event per browser it changes. Device-global, so a
# single push covers every user and browser profile. Fail-safe: non-fatal.
#
# PAT-1481: reversible/preventive, so this requires AC_BLOCKLIST_AUTHORITY_ALLOWED
# ('block' or 'enforce') alongside the existing AC_GATE_ALLOWED check — one
# tier lower than the destructive paths below. PAT-1038 follow-up: below that
# tier, this must still run rather than be skipped outright — a downgrade
# that merely stops NEW pushes would strand whatever was already written as a
# permanent, silent enforcement leak. bec_enforce_extension_blocklist takes
# whether blocklist actuation is allowed as its first argument and, when not
# allowed, reconciles its managed state down to empty (tearing down anything
# it previously pushed) instead of skipping — the same shape Windows'
# BrowserExtensionBlocklistEnforcer.Enforce(policy, actuationAllowed) uses.
if [[ -f "$SCRIPT_DIR_UPLOAD/lib/browser_extension_control.sh" ]]; then
    # PAT-1065: the blocklist capability is present and loaded — the success
    # counterpart to the "not found" fault below. Distinct subject from the
    # removal lib below (extension_blocklist vs extension_removal): they are
    # two independently-failable capabilities (a deploy can lose one lib
    # file without the other), so collapsing them into one (kind, subject)
    # key would let whichever call runs last in a given run silently
    # overwrite the other's outcome even within the same invocation.
    if typeset -f patched_agent_health_record_success >/dev/null 2>&1; then
        patched_agent_health_record_success "capability_missing" "extension_blocklist"
    fi
    if (( AC_GATE_ALLOWED )); then
        source "$SCRIPT_DIR_UPLOAD/lib/browser_extension_control.sh"
        bec_enforce_extension_blocklist "$AC_BLOCKLIST_AUTHORITY_ALLOWED" || true
    fi
else
    echo "ext_blocklist: lib/browser_extension_control.sh not found — skipping enforcement"
    # PAT-1065: a single-line && call, not an if/fi block — build-bundle.sh's
    # guarded-lib collapse (see its own header comment) tracks exactly one
    # fi ending this else-branch; a second, inner fi here would be
    # mistaken for that one and the block-closing fi below would print as
    # an orphaned line in the bundle (confirmed: this exact shape broke
    # dist/patched-upload.sh's zsh -n check in CI). A bare && has no fi of
    # its own, so the bundler's naive first-fi-ends-else assumption still
    # holds. Source-tree behavior is identical either way.
    typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
        patched_agent_health_record_failure "capability_missing" "extension_blocklist" "lib_not_installed"
fi

# ---------------------------------------------------------------------------
# BROWSER EXTENSION CONTROL — profile-aware, audited removal (PAT-829)
# ---------------------------------------------------------------------------
#
# The destructive escalation path after the blocklist: deletes the tenant's listed
# extensions (app_control.extension_removals in the signed agent-config) from the
# user profiles each directive's scope selects, and posts one extension_removed
# enforcement_audit event per artifact actually removed. Fail-safe: non-fatal.
#
# PAT-1481: destructive/irreversible, so it requires AC_AUTHORITY_ALLOWED
# ('enforce' only) alongside the existing AC_GATE_ALLOWED check — a removed
# extension is not reinstalled, so unlike the blocklist above there is no
# reconciliation-on-downgrade concern here; skipping outright below tier is
# correct, not a leak.
if [[ -f "$SCRIPT_DIR_UPLOAD/lib/browser_extension_removal.sh" ]]; then
    # PAT-1065: matches the vocabulary table's documented
    # capability_missing/extension_removal/lib_not_installed triple exactly.
    if typeset -f patched_agent_health_record_success >/dev/null 2>&1; then
        patched_agent_health_record_success "capability_missing" "extension_removal"
    fi
    if (( AC_GATE_ALLOWED && AC_AUTHORITY_ALLOWED )); then
        source "$SCRIPT_DIR_UPLOAD/lib/browser_extension_removal.sh"
        ber_remove_extensions || true
    fi
else
    echo "ext_removal: lib/browser_extension_removal.sh not found — skipping removal"
    # PAT-1065: single-line && call, not an if/fi block — see the matching
    # comment on the browser_extension_control else-branch above for why.
    typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
        patched_agent_health_record_failure "capability_missing" "extension_removal" "lib_not_installed"
fi
# <<< PATCHED_AGENT_HEALTH_CAPABILITY_END

# >>> PATCHED_ENDPOINT_DECOMMISSION_HEALTH_START (own sentinel block, kept
# separate from PATCHED_AGENT_HEALTH_CAPABILITY above so
# test-agent-health-capability.zsh's extraction of that PAT-1029 block is
# unaffected by this one; macos/test-endpoint-decommission-health.zsh
# extracts and drives this block on its own.)
# ---------------------------------------------------------------------------
# ENDPOINT DECOMMISSION-CAPABILITY CHECK (PAT-1126)
# ---------------------------------------------------------------------------
# macos/install.sh now always installs the endpoint/ bundle alongside this
# collector, so collector-only should no longer be a reachable end state —
# but a stale pre-PAT-1126 install, or a bundling step bypassed some other
# way, could still leave a box with no decommission mechanism at all: it
# would never see an expiry/decommission directive and never self-remove,
# silently, forever. This is the safety net for exactly that: a cheap,
# periodic (every patched-upload.sh cycle, same cadence as the checks
# above) presence/loaded check for com.patched.config-poll — the endpoint/
# decommission-poll daemon (it is the periodic poller that picks up a
# decommission directive from agent-config; see
# endpoint/patched-fetch-config.sh) — reported as a capability_missing fault
# via the same shared store, rather than staying silently inert.
#
# Overridable via PATCHED_ENDPOINT_CONFIG_POLL_PLIST / _LABEL for tests;
# production always uses the real LaunchDaemon path/label.
ENDPOINT_CONFIG_POLL_PLIST="${PATCHED_ENDPOINT_CONFIG_POLL_PLIST:-/Library/LaunchDaemons/com.patched.config-poll.plist}"
ENDPOINT_CONFIG_POLL_LABEL="${PATCHED_ENDPOINT_CONFIG_POLL_LABEL:-com.patched.config-poll}"

if [[ -f "$ENDPOINT_CONFIG_POLL_PLIST" ]] && launchctl print "system/$ENDPOINT_CONFIG_POLL_LABEL" >/dev/null 2>&1; then
    if typeset -f patched_agent_health_record_success >/dev/null 2>&1; then
        patched_agent_health_record_success "capability_missing" "endpoint_decommission_daemon"
    fi
elif [[ -f "$ENDPOINT_CONFIG_POLL_PLIST" ]]; then
    echo "endpoint_decommission: $ENDPOINT_CONFIG_POLL_LABEL plist present but not loaded"
    typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
        patched_agent_health_record_failure "capability_missing" "endpoint_decommission_daemon" "launchdaemon_not_loaded"
else
    echo "endpoint_decommission: $ENDPOINT_CONFIG_POLL_PLIST not found — this box has no decommission mechanism"
    typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
        patched_agent_health_record_failure "capability_missing" "endpoint_decommission_daemon" "launchdaemon_absent"
fi
# <<< PATCHED_ENDPOINT_DECOMMISSION_HEALTH_END

# ---------------------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------------------

setopt NULL_GLOB
FILES=("$QUEUE_DIR"/inventory-*.json)

if (( ${#FILES[@]} == 0 )); then
    echo "Queue empty — nothing to upload."
    exit 0
fi
echo "Found ${#FILES[@]} queued file(s)."

EXIT_CODE=0
RESP_FILE=$(mktemp "$PATCHED_TMPDIR/upload-response.XXXXXX")  # H11: root-owned 0700 dir, not /tmp

for file in "${FILES[@]}"; do
    # Drop files older than retention window
    AGE_DAYS=$(( ($(date +%s) - $(stat -f %m "$file")) / 86400 ))
    if (( AGE_DAYS > MAX_AGE_DAYS )); then
        echo "DROP $file (age ${AGE_DAYS}d, > ${MAX_AGE_DAYS}d retention)"
        rm -f "$file"
        continue
    fi

    # PAT-1065: merge the current agent_health snapshot into the queued
    # payload immediately before signing/POSTing it, rather than at
    # collect-time (patched-collect.sh, a separately-scheduled run, already
    # wrote $file to the queue before any of this run's capability_missing
    # checks above ran). Always inject the key, even as {"degraded": []},
    # per the absent-vs-present-empty contract
    # (go-service/docs/PAYLOAD_SCHEMA.md agent_health section) — an agent
    # that speaks this protocol must never omit the key. $file itself is
    # left untouched (only deleted on a confirmed 2xx below, same as before
    # this change); UPLOAD_FILE is disposable scratch regenerated fresh on
    # every attempt, so a retry of the same queued file always carries the
    # CURRENT active-fault snapshot, never a stale one from an earlier try.
    HEALTH_MERGED_FILE=$(mktemp "$PATCHED_TMPDIR/inventory-health.XXXXXX")
    MERGE_OK=0
    if typeset -f patched_agent_health_merge_into_payload >/dev/null 2>&1; then
        patched_agent_health_merge_into_payload "$file" "$HEALTH_MERGED_FILE" && MERGE_OK=1
    fi
    if (( ! MERGE_OK )); then
        echo "ERROR  $file — could not merge agent_health into payload (lib unavailable or malformed queue file?); skipping this attempt, will retry next run"
        rm -f "$HEALTH_MERGED_FILE"
        EXIT_CODE=1
        continue
    fi

    # PAT-1833: update-status.json is written atomically by patched-update.sh.
    # Merge its contract-valid, fresh os_update verdict only after the queued
    # payload has been copied to scratch and before HMAC signing. Invalid or
    # unavailable evidence is intentionally omitted; the queue file remains
    # unchanged, so a later retry can use a newly computed verdict.
    UPLOAD_FILE=$(mktemp "$PATCHED_TMPDIR/inventory-merged.XXXXXX")
    if ! patched_os_update_merge_into_payload \
        "$HEALTH_MERGED_FILE" "$OS_UPDATE_STATUS_FILE" "$UPLOAD_FILE"; then
        echo "ERROR  $file — os_update merge step itself failed (not a validation omission, which returns 0 and proceeds without os_update); skipping this attempt, will retry next run"
        rm -f "$HEALTH_MERGED_FILE" "$UPLOAD_FILE"
        EXIT_CODE=1
        continue
    fi
    rm -f "$HEALTH_MERGED_FILE"

    TIMESTAMP=$(date -u +%s)
    NONCE=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    SIGNATURE=$(compute_hmac "$UPLOAD_FILE" "inventory" "$TIMESTAMP" "$NONCE") || {
        echo "ERROR  $file — hmac compute failed"
        rm -f "$UPLOAD_FILE"
        EXIT_CODE=1
        continue
    }

    device_hdr=()
    [[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")

    HTTP_CODE=$(patched_curl_bearer "$BEARER_TOKEN" -s -o "$RESP_FILE" -w "%{http_code}" \
        --max-time 30 \
        -X POST "$API_URL/v1/inventory" \
        -H "X-Patched-Signature: $SIGNATURE" \
        -H "X-Patched-Timestamp: $TIMESTAMP" \
        -H "X-Patched-Nonce: $NONCE" \
        "${device_hdr[@]}" \
        -H "Content-Type: application/json" \
        --data-binary "@$UPLOAD_FILE" \
        2>/dev/null)

    rm -f "$UPLOAD_FILE"

    case "$HTTP_CODE" in
        2*)
            BYTES=$(stat -f %z "$file")
            echo "OK     $file -> $HTTP_CODE (${BYTES} bytes)"
            rm -f "$file"
            ;;
        4*)
            echo "CLIENT $file -> $HTTP_CODE (will retry next run; check auth/payload)"
            cat "$RESP_FILE" 2>/dev/null; echo
            EXIT_CODE=1
            ;;
        "")
            echo "NET    $file -> network error or timeout (will retry next run)"
            EXIT_CODE=1
            ;;
        *)
            echo "SERVER $file -> $HTTP_CODE (will retry next run)"
            cat "$RESP_FILE" 2>/dev/null; echo
            EXIT_CODE=1
            ;;
    esac
done

rm -f "$RESP_FILE"

if (( EXIT_CODE == 0 )); then
    echo "All queued uploads succeeded."
else
    echo "Some uploads failed — will retry on next LaunchDaemon tick."
fi

exit "$EXIT_CODE"
