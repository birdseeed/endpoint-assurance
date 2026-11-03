#!/bin/bash
##############################################################################
# patched-bootstrap.sh — macOS self-updating bootstrap loader (PAT-108)
#
# Thin entry point deployed by Intune/MDM. On each invocation:
#   1. Fetches signed agent-config to get update_channel + pinned_version
#   2. Checks if a newer collector version is available
#   3. Downloads + HMAC-verifies the tarball if an update is available
#   4. Atomically installs the versioned collector under /var/lib/patched/collector/
#   5. Runs current/patched-collect.sh → current/patched-upload.sh
#
# Never updates mid-cycle (download completes before collect starts).
# Rolls back to N-1 if the new version fails the post-install health check.
#
# CREDS: /etc/patched/{bearer-token,hmac-secret,tenant-id,artifact-key}
# INSTALL_BASE: /var/lib/patched/collector/
##############################################################################

set -u

# SECURITY (PAT-881, H10): this loader runs as root via com.patched.bootstrap.
# Force a fixed PATH of SIP-protected system dirs only. We deliberately exclude
# /usr/local/bin and /opt/homebrew/bin (admin-writable once Homebrew is present)
# and do NOT append the inherited PATH, so a local user cannot shadow a
# bare-name binary (curl/tar/uuidgen/...) and gain root execution. Mirrors the
# same H10 rationale in patched-collect.sh / patched-upload.sh. Belt-and-braces
# with the plist PATH: this holds even if the script is run outside the daemon.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CREDS_DIR="/etc/patched"
COLLECTOR_BASE="/var/lib/patched/collector"
CURRENT_LINK="$COLLECTOR_BASE/current"
VERSION_FILE="$CURRENT_LINK/patched-version.json"
DEFAULT_API_URL="https://api.patched.im"
API_URL="${PATCHED_API_URL:-$DEFAULT_API_URL}"
KEEP_VERSIONS=2   # number of versioned collector directories to retain (current + N-1)

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
die() {
    printf 'patched-bootstrap: ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf 'patched-bootstrap: %s\n' "$*"
}

# ---------------------------------------------------------------------------
# Read a credential file, stripping trailing newlines.
# Returns empty string if the file is missing (caller decides if fatal).
# ---------------------------------------------------------------------------
load_cred() {
    local credfile="$CREDS_DIR/$1"
    if [ -f "$credfile" ]; then
        tr -d '\n\r' < "$credfile"
    else
        printf ''
    fi
}

# ---------------------------------------------------------------------------
# Load credentials from /etc/patched/
# ---------------------------------------------------------------------------
BEARER_TOKEN=$(load_cred "bearer-token")
HMAC_SECRET=$(load_cred "hmac-secret")
TENANT_ID=$(load_cred "tenant-id")
ARTIFACT_KEY=$(load_cred "artifact-key")

[ -n "$BEARER_TOKEN" ] || die "bearer-token not found in $CREDS_DIR"
[ -n "$HMAC_SECRET"  ] || die "hmac-secret not found in $CREDS_DIR"
[ -n "$TENANT_ID"    ] || die "tenant-id not found in $CREDS_DIR"
# ARTIFACT_KEY absence is non-fatal — update check is skipped without it

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Safe-credential helpers (PAT-881). Byte-compatible standalone copies of the
# same two mechanisms defined inline in patched-upload.sh (the
# PATCHED_CREDS_HELPERS block): this loader runs before any collector bundle is
# on disk, so it can share nothing at runtime. Keep the two in sync: same
# argv-free mechanisms (token over stdin; HMAC key read from a file in Python).

# bootstrap_hmac_hex <body-file> <secret-file>
#   HMAC-SHA256(body, raw-key) as lowercase hex, no trailing newline. The key is
#   read from <secret-file> inside Python (never on argv) and used as raw bytes
#   with CR/LF stripped, byte-identical to the previous
#   `openssl dgst -sha256 -hmac "$KEY"` over the same credential.
bootstrap_hmac_hex() {
    /usr/bin/python3 - "$1" "$2" <<'PYEOF'
import sys, hmac, hashlib
body_path, secret_path = sys.argv[1], sys.argv[2]
with open(secret_path, 'rb') as f:
    key = f.read().translate(None, b'\r\n')   # match shell `tr -d '\n\r'`
with open(body_path, 'rb') as f:
    body = f.read()
print(hmac.new(key, body, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# bootstrap_hmac_hex_v3 <body-file> <method> <endpoint-id> <ts> <nonce> <secret-file>
#   PAT-1154: v3 canonical request signing:
#     HMAC-SHA256(b"patched-hmac-v3\n" + method + b"\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body)
#   over the raw key bytes at <secret-file> (CR/LF stripped, same key handling
#   as bootstrap_hmac_hex). ts and nonce MUST be the exact strings sent in the
#   X-Patched-Timestamp / X-Patched-Nonce headers for this same request, so a
#   captured signed request cannot be replayed.
#   Kept SEPARATE from bootstrap_hmac_hex, which stays a plain body-only HMAC:
#   verify_artifact_hmac below also calls bootstrap_hmac_hex to check a
#   downloaded tarball against the server's artifact HMAC — an integrity
#   check unrelated to request replay-binding that must not change.
bootstrap_hmac_hex_v3() {
    /usr/bin/python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PYEOF'
import sys, hmac, hashlib
body_path, method, endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path, 'rb') as f:
    key = f.read().translate(None, b'\r\n')   # match shell `tr -d '\n\r'`
with open(body_path, 'rb') as f:
    body = f.read()
msg = b"patched-hmac-v3\n" + method.encode('ascii') + b"\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n" + body
print(hmac.new(key, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# bootstrap_curl_bearer <bearer-token> [curl args...]
#   curl with `Authorization: Bearer <token>` fed over stdin (`-H @-`) so the
#   token never appears on argv. All other args pass through unchanged.
bootstrap_curl_bearer() {
    local _token="$1"
    shift
    printf 'Authorization: Bearer %s\n' "$_token" | /usr/bin/curl -H @- "$@"
}

# Parse a single top-level field from a JSON string using Python.
# Returns empty string if field is absent or on any parse error.
parse_json_field() {
    local json="$1" field="$2"
    /usr/bin/python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    v = d.get(sys.argv[2])
    print('' if v is None else str(v))
except Exception:
    print('')
" "$json" "$field" 2>/dev/null || true
}

# URL-encode a string (percent-encode path/query-unsafe characters).
url_encode() {
    /usr/bin/python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1" 2>/dev/null || printf '%s' "$1"
}

# Require the exact authenticated artifact-store route on the configured API
# origin. Parse components rather than using shell patterns so a test API URL
# with a trailing slash or glob metacharacters cannot weaken this boundary.
is_expected_artifact_download_url() {
    /usr/bin/python3 -c '
import sys, urllib.parse
url, api, channel, version = sys.argv[1:]
u, a = urllib.parse.urlsplit(url), urllib.parse.urlsplit(api)
expected_path = a.path.rstrip("/") + "/v1/agent/artifact/download"
q = urllib.parse.parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
ok = (u.scheme == "https" and u.scheme == a.scheme and u.netloc == a.netloc and
      u.path == expected_path and not u.fragment and
      q == {"platform": ["macos"], "channel": [channel], "version": [version]})
raise SystemExit(0 if ok else 1)
' "$1" "$API_URL" "$UPDATE_CHANNEL" "$AVAILABLE_VERSION" 2>/dev/null
}

# HMAC-SHA256 a file and compare to the expected hex digest.
# Returns 0 (true) on match, 1 (false) on mismatch.
# The artifact key is read from $CREDS_DIR/artifact-key inside Python (PAT-881),
# never passed on argv. Byte-identical to the previous openssl computation.
verify_artifact_hmac() {
    local tarball="$1" expected_hmac="$2"
    local actual_hmac
    actual_hmac=$(bootstrap_hmac_hex "$tarball" "$CREDS_DIR/artifact-key") || return 1
    [ "$actual_hmac" = "$expected_hmac" ]
}

# List versioned collector directories under COLLECTOR_BASE, newest-first.
# Only directories whose name starts with a digit (semver-style) are included.
list_versions_newest_first() {
    /usr/bin/python3 -c "
import os, sys
base = sys.argv[1]
try:
    vers = [d for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d)) and d[:1].isdigit()]
    vers.sort(
        key=lambda v: [int(x) if x.isdigit() else x for x in v.split('.')],
        reverse=True)
    for v in vers:
        print(os.path.join(base, v))
except Exception:
    pass
" "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Step 1: Fetch signed agent-config
# ---------------------------------------------------------------------------
log "Fetching agent-config from $API_URL"

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
NONCE=$(/usr/bin/uuidgen 2>/dev/null || /usr/bin/python3 -c "import uuid; print(uuid.uuid4())")
SIG=$(bootstrap_hmac_hex_v3 /dev/null "GET" "agent_config" "$TIMESTAMP" "$NONCE" "$CREDS_DIR/hmac-secret")

CONFIG_RESPONSE=$(bootstrap_curl_bearer "$BEARER_TOKEN" -sf \
    -H "X-Patched-Signature: $SIG" \
    -H "X-Patched-Timestamp: $TIMESTAMP" \
    -H "X-Patched-Nonce: $NONCE" \
    -H "X-Patched-Tenant: $TENANT_ID" \
    --max-time 30 \
    "$API_URL/v1/agent-config" 2>/dev/null) || true

UPDATE_CHANNEL="stable"
PINNED_VERSION=""

# PAT-2005: no decode-only or unsigned authority. The installed manifest-covered
# helper verifies the pinned signature, tenant, floor and canonical server ID.
# It re-verifies durable original envelopes after restart/network failure.
UPDATE_POLICY_HELPER="/usr/local/patched-updater/agent_update_channel.py"
UPDATE_POLICY_CACHE="/Library/Application Support/Patched/update-channel.json"
if [ -f "$UPDATE_POLICY_HELPER" ]; then
    UPDATE_POLICY=$(printf '%s' "$CONFIG_RESPONSE" | /usr/bin/python3 "$UPDATE_POLICY_HELPER" select \
        --cache "$UPDATE_POLICY_CACHE" --tenant-file "$CREDS_DIR/tenant-id" \
        --device-file "$CREDS_DIR/device-id" --floor-file "/Library/Application Support/Patched/agent-config.version")
    _ch=$(parse_json_field "$UPDATE_POLICY" "effective_channel")
    _pv=$(parse_json_field "$UPDATE_POLICY" "pinned_version")
    case "$_ch" in stable|beta) UPDATE_CHANNEL="$_ch";; esac
    PINNED_VERSION="${_pv:-}"
else
    log "WARN: verified update policy helper missing — using stable defaults"
fi

log "Update channel: $UPDATE_CHANNEL${PINNED_VERSION:+, pinned: $PINNED_VERSION}"

# ---------------------------------------------------------------------------
# Step 2: Read the currently installed version
# ---------------------------------------------------------------------------
CURRENT_VERSION=""
if [ -f "$VERSION_FILE" ]; then
    _vf_content=$(cat "$VERSION_FILE" 2>/dev/null) || true
    CURRENT_VERSION=$(parse_json_field "$_vf_content" "version") || true
fi
log "Current version: ${CURRENT_VERSION:-<none>}"

# ---------------------------------------------------------------------------
# Step 3: Fetch artifact metadata
# ---------------------------------------------------------------------------
_encoded_channel=$(url_encode "$UPDATE_CHANNEL")
ARTIFACT_ENDPOINT="$API_URL/v1/agent/artifact?platform=macos&channel=$_encoded_channel"
if [ -n "$PINNED_VERSION" ]; then
    ARTIFACT_ENDPOINT="${ARTIFACT_ENDPOINT}&version=$(url_encode "$PINNED_VERSION")"
fi

log "Checking artifact metadata: $ARTIFACT_ENDPOINT"

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
NONCE=$(/usr/bin/uuidgen 2>/dev/null || /usr/bin/python3 -c "import uuid; print(uuid.uuid4())")
SIG=$(bootstrap_hmac_hex_v3 /dev/null "GET" "agent_artifact" "$TIMESTAMP" "$NONCE" "$CREDS_DIR/hmac-secret")

ARTIFACT_RESPONSE=$(bootstrap_curl_bearer "$BEARER_TOKEN" -sf \
    -H "X-Patched-Signature: $SIG" \
    -H "X-Patched-Timestamp: $TIMESTAMP" \
    -H "X-Patched-Nonce: $NONCE" \
    -H "X-Patched-Tenant: $TENANT_ID" \
    --max-time 30 \
    "$ARTIFACT_ENDPOINT" 2>/dev/null) || true

AVAILABLE_VERSION=""
DOWNLOAD_URL=""
ARTIFACT_HMAC=""

if [ -z "$ARTIFACT_RESPONSE" ]; then
    log "WARN: failed to fetch artifact metadata — skipping update check"
else
    AVAILABLE_VERSION=$(parse_json_field "$ARTIFACT_RESPONSE" "version")
    DOWNLOAD_URL=$(parse_json_field "$ARTIFACT_RESPONSE" "artifact_url")
    ARTIFACT_HMAC=$(parse_json_field "$ARTIFACT_RESPONSE" "artifact_hmac")
fi

# ---------------------------------------------------------------------------
# Step 4–9: Download, verify, extract, symlink (only if a newer version exists)
# ---------------------------------------------------------------------------
UPDATED=0

if [ -z "$AVAILABLE_VERSION" ]; then
    log "No artifact version information — skipping update check"
elif [ "$AVAILABLE_VERSION" = "$CURRENT_VERSION" ]; then
    log "Already at version $AVAILABLE_VERSION — no update needed"
else
    log "Update available: ${CURRENT_VERSION:-<none>} → $AVAILABLE_VERSION"

    if [ -z "$ARTIFACT_KEY" ]; then
        log "WARN: artifact-key absent from $CREDS_DIR — skipping update (require signed artifacts)"
    elif [ -z "$DOWNLOAD_URL" ]; then
        log "WARN: artifact response missing artifact_url — skipping update"
    elif [ -z "$ARTIFACT_HMAC" ]; then
        log "WARN: artifact response missing artifact_hmac — skipping update (require HMAC)"
    elif ! printf '%s' "$DOWNLOAD_URL" | grep -Eq '^https://'; then
        # Require HTTPS: never download a root-installed agent artifact over
        # cleartext or a non-https scheme.
        log "WARN: artifact_url is not https (${DOWNLOAD_URL%%:*}://…) — skipping update"
    elif [ "$(printf '%s' "$DOWNLOAD_URL" | awk -F/ '{print $3}')" != "$(printf '%s' "$API_URL" | awk -F/ '{print $3}')" ]; then
        # Constrain the download host to the API origin that served the
        # (authenticated) artifact metadata, so a tampered artifact_url cannot
        # redirect this root download to an attacker-controlled host.
        log "WARN: artifact_url host $(printf '%s' "$DOWNLOAD_URL" | awk -F/ '{print $3}') != API host $(printf '%s' "$API_URL" | awk -F/ '{print $3}') — skipping update"
    elif ! is_expected_artifact_download_url "$DOWNLOAD_URL"; then
        # The metadata is useful only when it resolves to the authenticated,
        # per-device artifact-store route. Refuse same-host redirects to other
        # paths, including GitHub-style or arbitrary API resources.
        log "WARN: artifact_url is not the authenticated artifact download route — skipping update"
    else
        # Step 5: Download tarball to a temp location
        BOOTSTRAP_TMP=$(mktemp -d "/tmp/patched-bootstrap.XXXXXX")
        TARBALL_TMP="$BOOTSTRAP_TMP/patched-agent-macos-${AVAILABLE_VERSION}.tar.gz"

        log "Downloading tarball"
        TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
        NONCE=$(/usr/bin/uuidgen 2>/dev/null || /usr/bin/python3 -c "import uuid; print(uuid.uuid4())")
        SIG=$(bootstrap_hmac_hex_v3 /dev/null "GET" "agent_artifact_download" "$TIMESTAMP" "$NONCE" "$CREDS_DIR/hmac-secret")
        if bootstrap_curl_bearer "$BEARER_TOKEN" -sf \
            -H "X-Patched-Signature: $SIG" \
            -H "X-Patched-Timestamp: $TIMESTAMP" \
            -H "X-Patched-Nonce: $NONCE" \
            -H "X-Patched-Tenant: $TENANT_ID" \
            --max-time 300 -o "$TARBALL_TMP" "$DOWNLOAD_URL" 2>/dev/null; then

            # Step 6: Verify HMAC-SHA256 of the downloaded tarball
            if verify_artifact_hmac "$TARBALL_TMP" "$ARTIFACT_HMAC"; then
                log "HMAC-SHA256 verified"

                # Step 7: Extract to /var/lib/patched/collector/<version>/
                VERSION_DIR="$COLLECTOR_BASE/$AVAILABLE_VERSION"
                mkdir -p "$VERSION_DIR"

                # Tarball contains a single top-level directory (patched-agent-macos-<v>/)
                # --strip-components=1 extracts the contents directly into VERSION_DIR.
                if /usr/bin/tar xzf "$TARBALL_TMP" -C "$VERSION_DIR" --strip-components=1 2>/dev/null; then
                    log "Extracted to $VERSION_DIR"
                else
                    log "WARN: --strip-components failed; retrying without stripping"
                    /usr/bin/tar xzf "$TARBALL_TMP" -C "$VERSION_DIR" 2>/dev/null || true
                fi

                chmod +x "$VERSION_DIR/patched-collect.sh" 2>/dev/null || true
                chmod +x "$VERSION_DIR/patched-upload.sh"  2>/dev/null || true

                # Write the version file into the versioned directory
                _installed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
                printf '{"version":"%s","platform":"macos","installed_at":"%s"}\n' \
                    "$AVAILABLE_VERSION" "$_installed_at" \
                    > "$VERSION_DIR/patched-version.json"

                # Step 8: Atomically swap the 'current' symlink
                ln -sfn "$VERSION_DIR" "$COLLECTOR_BASE/.current.tmp"
                mv -f "$COLLECTOR_BASE/.current.tmp" "$CURRENT_LINK"
                CURRENT_VERSION="$AVAILABLE_VERSION"
                UPDATED=1
                log "Symlinked current → $AVAILABLE_VERSION"

            else
                log "ERROR: HMAC mismatch for version $AVAILABLE_VERSION — discarding download"
            fi

            rm -f "$TARBALL_TMP" || true
        else
            log "WARN: download failed — proceeding with current version"
        fi

        rmdir "$BOOTSTRAP_TMP" 2>/dev/null || true

        # Step 9: Prune old versions — keep only KEEP_VERSIONS most recent
        if [ "$UPDATED" -eq 1 ]; then
            _count=0
            while IFS= read -r _vdir; do
                _count=$((_count + 1))
                if [ "$_count" -gt "$KEEP_VERSIONS" ]; then
                    log "Removing old version: $(basename "$_vdir")"
                    rm -rf "$_vdir" || true
                fi
            done <<EOF
$(list_versions_newest_first "$COLLECTOR_BASE")
EOF
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 10: Identify N-1 version for potential rollback
# ---------------------------------------------------------------------------
PREV_VERSION_DIR=""
_rank=0
while IFS= read -r _vdir; do
    _rank=$((_rank + 1))
    if [ "$_rank" -eq 2 ]; then
        PREV_VERSION_DIR="$_vdir"
        break
    fi
done <<EOF
$(list_versions_newest_first "$COLLECTOR_BASE")
EOF

# ---------------------------------------------------------------------------
# Step 11: Ensure collector is present before running
# ---------------------------------------------------------------------------
[ -f "$CURRENT_LINK/patched-collect.sh" ] || die "patched-collect.sh not found at $CURRENT_LINK — no collector installed"
[ -f "$CURRENT_LINK/patched-upload.sh"  ] || die "patched-upload.sh not found at $CURRENT_LINK — no collector installed"

# ---------------------------------------------------------------------------
# Step 12: Run patched-collect.sh then patched-upload.sh
# ---------------------------------------------------------------------------
COLLECT_OK=0
UPLOAD_OK=0

log "Running patched-collect.sh"
if /bin/bash "$CURRENT_LINK/patched-collect.sh" 2>&1; then
    COLLECT_OK=1
    log "Collect succeeded"
else
    log "ERROR: patched-collect.sh failed"
fi

if [ "$COLLECT_OK" -eq 1 ]; then
    log "Running patched-upload.sh"
    if /bin/bash "$CURRENT_LINK/patched-upload.sh" 2>&1; then
        UPLOAD_OK=1
        log "Upload succeeded"
    else
        log "ERROR: patched-upload.sh failed"
    fi
fi

# ---------------------------------------------------------------------------
# Step 13: Roll back to N-1 if the freshly-installed version failed
# ---------------------------------------------------------------------------
if [ "$UPDATED" -eq 1 ] && { [ "$COLLECT_OK" -eq 0 ] || [ "$UPLOAD_OK" -eq 0 ]; }; then
    if [ -n "$PREV_VERSION_DIR" ] && [ -d "$PREV_VERSION_DIR" ]; then
        log "Rolling back to previous version: $(basename "$PREV_VERSION_DIR")"
        ln -sfn "$PREV_VERSION_DIR" "$COLLECTOR_BASE/.current.tmp"
        mv -f "$COLLECTOR_BASE/.current.tmp" "$CURRENT_LINK"

        log "Retrying collect + upload with previous version"
        /bin/bash "$CURRENT_LINK/patched-collect.sh" 2>&1 || true
        /bin/bash "$CURRENT_LINK/patched-upload.sh"  2>&1 || true
    else
        log "WARN: no previous version available for rollback"
    fi
fi

log "Bootstrap cycle complete"
