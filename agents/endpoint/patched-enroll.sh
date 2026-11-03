#!/bin/zsh
##############################################################################
# patched-enroll.sh — first-run enrollment token exchange.  (PAT-544)
#
# Called by patched-fetch-config.sh and patched-update.sh when
# /etc/patched/enrollment-token exists but /etc/patched/bearer-token does not
# (patched-fetch-config.sh, PAT-1765: or it or hmac-secret is empty or whitespace).
# Exchanges the single-use token for per-device credentials via POST /v1/enrol,
# writes them atomically to /etc/patched/, then deletes the token.
#
# Exit codes:
#   0 — enrolled successfully, already enrolled (no-op), or transient error
#       (token retained; caller continues / retries on next poll)
#   1 — terminal failure (HTTP 410 or 401, or a 200 whose body or returned
#       credentials cannot be used): caller must enter suspended state
#
# CONVENTIONS (shared with patched-fetch-config.sh / patched-update.sh):
#   - set -u only.
#   - /usr/bin/python3 hardcoded (sudo strips PATH on macOS).
#   - Never use zsh reserved var names (path/fpath/cdpath/manpath/infopath).
##############################################################################

set -u

# PAT-2394: root command lookup must never include Homebrew, inherited PATH
# or a test override. Runtime failure is fatal before logging or state writes.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] && "$PYTHON3" -I -c 'pass' >/dev/null 2>&1 || { printf '%s\n' "FATAL: trusted /usr/bin/python3 runtime unavailable or unusable; no work performed" >&2; exit 1; }

CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"

ENROLL_TOKEN_FILE="$CREDS_DIR/enrollment-token"
BEARER_FILE="$CREDS_DIR/bearer-token"
SUSPENDED_FILE="$CREDS_DIR/suspended"
# PAT-1756: agent-config anti-rollback floor, reset on a successful enrolment.
AGENT_CONFIG_VERSION_FILE="$STATE_DIR/agent-config.version"
ENROLL_LOCK="$CREDS_DIR/.enroll-lock"
# PAT-1763: the one anti-rollback floor parser, shipped in the same bundle.
AGENT_CONFIG_FLOOR_MODULE="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}/agent_config_floor.py"

# >>> PATCHED_ENROL_FLOOR_STATE_START
# _enrol_floor_state <floor-file> <tenant-id>
#   Sets floor_state to the parser's classification (absent, unreadable
#   <reason>, legacy, corrupt, same_tenant or other_tenant) and floor_reader_rc
#   to its exit status. A reader that exits non-zero sets floor_state to
#   reader_failed. Extracted and driven by endpoint/test-agent-config-floor.py.
_enrol_floor_state() {
    floor_state=$("$PYTHON3" "$AGENT_CONFIG_FLOOR_MODULE" enrol-state "$1" "$2" 2>/dev/null)
    floor_reader_rc=$?
    if (( floor_reader_rc != 0 )); then
        floor_state="reader_failed"
    fi
}
# <<< PATCHED_ENROL_FLOOR_STATE_END

# Already enrolled — skip silently (idempotent).
# PAT-1765: enrolled means a usable pair, a bearer-token whose first line is not
# blank and an hmac-secret that is not blank, the same rule patched-fetch-config.sh
# (patched_device_credentials_usable) and the Windows agent apply. An empty or
# whitespace bearer-token file used to count as enrolled, so a device holding an
# enrolment token next to it never enrolled.
if head -1 "$BEARER_FILE" 2>/dev/null | grep -q '[^[:space:]]' \
    && grep -q '[^[:space:]]' "$CREDS_DIR/hmac-secret" 2>/dev/null; then
    exit 0
fi

# No enrollment token — nothing to do
[[ -f "$ENROLL_TOKEN_FILE" ]] || exit 0

# Mutex — patched-fetch-config.sh and patched-update.sh both run at startup
# (RunAtLoad) and both call this script.  The second caller must not POST
# /v1/enrol with the same single-use token and falsely trigger a 410 suspension.
# mkdir is atomic on APFS/HFS+, same pattern as patched-fetch-config.sh's lock.
install -d -o root -g wheel -m 700 "$CREDS_DIR"
if ! mkdir "$ENROLL_LOCK" 2>/dev/null; then
    echo "patched-enroll: enrollment already in progress — skipping"
    exit 0
fi
payload_file=""
trap '[[ -z "$payload_file" ]] || rm -f "$payload_file"; rmdir "$ENROLL_LOCK" 2>/dev/null || true' EXIT

ENROLLMENT_TOKEN=$(head -1 "$ENROLL_TOKEN_FILE" | tr -d '[:space:]')
if [[ -z "$ENROLLMENT_TOKEN" ]]; then
    echo "WARN patched-enroll: enrollment-token file is empty"
    exit 0
fi

# Device UUID (same source used in provenance records and PAT-513 device header)
HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
    | awk -F'"' '/IOPlatformUUID/{print $4}') || HW_UUID=""

echo "=== patched-enroll: exchanging enrollment token (device ${HW_UUID:-unknown}) ==="

# Read the canonical token again in the payload builder. Only its path and the
# public device identifier enter argv; JSON travels over curl's standard input.
payload_file=$(mktemp /tmp/.patched-enroll-payload.XXXXXX) || exit 0
"$PYTHON3" -c "
import json, sys
with open(sys.argv[1]) as fh:
    token = ''.join(fh.readline().split())
print(json.dumps({'enrollment_token': token, 'device_id': sys.argv[2]}))
" "$ENROLL_TOKEN_FILE" "${HW_UUID:-unknown}" > "$payload_file" 2>/dev/null || {
    echo "WARN patched-enroll: failed to build request payload"
    exit 0
}
resp_file=$(mktemp /tmp/.patched-enroll-resp.XXXXXX) || exit 0
http_code=$(curl -s -o "$resp_file" -w "%{http_code}" --max-time 30 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data-binary @- \
    "$API_URL/v1/enrol" < "$payload_file" 2>/dev/null) || http_code="000"
rm -f "$payload_file"
payload_file=""

echo "  POST /v1/enrol → HTTP $http_code"

# ---------------------------------------------------------------------------
# _enrol_suspend_and_set_token_aside: the terminal path for a token the server
# rejected (410/401) or consumed with a 200 that could not be used (PAT-1779).
# Writes the suspended marker, moves the token aside and exits 1. Never returns.
# ---------------------------------------------------------------------------
_enrol_suspend_and_set_token_aside() {
    install -d -o root -g wheel -m 700 "$CREDS_DIR"
    touch "$SUSPENDED_FILE"
    chmod 600 "$SUSPENDED_FILE"
    chown root:wheel "$SUSPENDED_FILE"

    # PAT-1203: move the spent token out of the canonical path instead of
    # leaving it in place. Without this, the caller's enrollment gate
    # (enrollment-token present and no usable credential pair, in both
    # patched-fetch-config.sh and patched-update.sh) stays true forever, so
    # every future poll re-invokes this script, which re-reads the SAME
    # single-use token from disk and gets a 410/401 again — a busy
    # retry-with-a-known-dead-token loop with no way to stop short of an
    # operator deleting the file by hand. Renaming (not deleting) keeps the
    # value around for forensics. Best-effort: a failure here must not abort
    # suspension (SUSPENDED_FILE above is already written; set -u is the only
    # shell safety net in this file per the header, so every step here is
    # independently best-effort). The moment an admin drops a FRESH token at
    # the canonical $ENROLL_TOKEN_FILE path — install.sh's provisioning write
    # is an atomic .tmp+mv that unconditionally overwrites that path
    # regardless of what (if anything) currently sits there — the very next
    # poll picks it up normally with no other change needed: this script
    # always re-reads the token file from disk on every invocation, it never
    # caches it in memory across runs.
    mv -f "$ENROLL_TOKEN_FILE" "$ENROLL_TOKEN_FILE.rejected" 2>/dev/null || true

    rm -f "$resp_file"
    exit 1
}

# ---------------------------------------------------------------------------
# 200 — enrolled successfully
# ---------------------------------------------------------------------------
if [[ "$http_code" == "200" ]]; then
    # PAT-1779 (macOS parity for PAT-1765 item 11): a 200 means the server has
    # consumed the single-use token, whatever the body holds. A body that does
    # not parse, or lacks a usable tenant_id, bearer_token, hmac_secret or
    # device_id, used to "retain the token for retry": the next poll resent the
    # consumed token, drew a 410 and suspended the device with the real cause
    # gone from the log. Each is now terminal, the same as a rejected token:
    # logged, nothing stored, marker written, token moved aside (never resent).
    # The parser prints the four values tab-separated and exits 0, or prints a
    # fixed description of the problem (never a response value) and exits 3.
    # A value is usable only as a string with non-whitespace content and no tab,
    # CR or LF, since the shell split below and the one-line credential files
    # cannot carry those.
    parsed=$("$PYTHON3" -c "
import json, sys
FIELDS = ('tenant_id', 'bearer_token', 'hmac_secret', 'device_id')
try:
    with open(sys.argv[1], 'rb') as fh:
        d = json.loads(fh.read().decode('utf-8'))
except Exception:
    print('the response body is not JSON')
    sys.exit(3)
if not isinstance(d, dict):
    print('the response body is not a JSON object')
    sys.exit(3)
for field in FIELDS:
    v = d.get(field)
    if not isinstance(v, str):
        print('the response has no string ' + field)
        sys.exit(3)
    if not v.strip():
        print('the response carried an empty or whitespace ' + field)
        sys.exit(3)
    if any(c in v for c in '\t\r\n'):
        print('the response carried a ' + field + ' containing a tab or line break')
        sys.exit(3)
print('\t'.join(d[field] for field in FIELDS))
" "$resp_file" 2>/dev/null)
    parse_rc=$?
    if (( parse_rc != 0 )); then
        if (( parse_rc == 3 )) && [[ -n "$parsed" ]]; then
            unusable_reason="$parsed"
        else
            unusable_reason="the response body could not be parsed (parser exit $parse_rc)"
        fi
        parsed=""
        echo "PATCHED_ENROLLMENT_UNUSABLE_RESPONSE: the enrollment token was consumed by the server (HTTP 200) but $unusable_reason. Nothing was stored. The device is not enrolled and the consumed token cannot be used again; re-provision the device with a fresh enrollment token. Entering suspended state"
        _enrol_suspend_and_set_token_aside
    fi

    tenant_id="${parsed%%	*}"
    _rest="${parsed#*	}"
    bearer_token="${_rest%%	*}"
    _rest="${_rest#*	}"
    hmac_secret="${_rest%%	*}"
    device_id="${_rest#*	}"

    # Atomic write: write each to .tmp, set permissions, then mv into place.
    # Same pattern as verify-agent-config.py so creds and token deletion
    # cannot diverge across a crash. device-id is an identifier, not a secret,
    # but it still gets the same 600/root:wheel treatment as tenant-id — the
    # platform device id must not be world-readable or tamperable by a
    # non-root user on the endpoint.
    #
    # set -u is the only shell safety net in this file (see header); no
    # printf/chmod/chown/mv here aborts the script on failure by itself, so
    # every step's exit status is tracked explicitly in creds_write_ok. The
    # The enrollment token was consumed server-side by the verified HTTP 200
    # above, regardless of whether the local writes succeed. It must never be
    # resent after this point. A failed write therefore enters the same suspended
    # recovery state as any other consumed-token failure and moves the token to
    # the existing .rejected forensic path. Before a 200, transient/local failures
    # still retain the canonical token for a possible retry.
    install -d -o root -g wheel -m 700 "$CREDS_DIR"

    creds_tmp_files=(
        "$CREDS_DIR/tenant-id.tmp"
        "$CREDS_DIR/bearer-token.tmp"
        "$CREDS_DIR/hmac-secret.tmp"
        "$CREDS_DIR/device-id.tmp"
    )

    creds_write_ok=1
    printf '%s\n' "$tenant_id"    > "$CREDS_DIR/tenant-id.tmp"    || creds_write_ok=0
    printf '%s\n' "$bearer_token" > "$CREDS_DIR/bearer-token.tmp" || creds_write_ok=0
    printf '%s\n' "$hmac_secret"  > "$CREDS_DIR/hmac-secret.tmp"  || creds_write_ok=0
    printf '%s\n' "$device_id"    > "$CREDS_DIR/device-id.tmp"    || creds_write_ok=0

    if [[ $creds_write_ok -eq 1 ]]; then
        chmod 600 "${creds_tmp_files[@]}" || creds_write_ok=0
    fi
    if [[ $creds_write_ok -eq 1 ]]; then
        chown root:wheel "${creds_tmp_files[@]}" || creds_write_ok=0
    fi
    if [[ $creds_write_ok -eq 1 ]]; then
        mv -f "$CREDS_DIR/tenant-id.tmp"    "$CREDS_DIR/tenant-id"    || creds_write_ok=0
        mv -f "$CREDS_DIR/bearer-token.tmp" "$CREDS_DIR/bearer-token" || creds_write_ok=0
        mv -f "$CREDS_DIR/hmac-secret.tmp"  "$CREDS_DIR/hmac-secret"  || creds_write_ok=0
        mv -f "$CREDS_DIR/device-id.tmp"    "$CREDS_DIR/device-id"    || creds_write_ok=0
    fi

    if [[ $creds_write_ok -ne 1 ]]; then
        # Honest about the state left behind: this endpoint may already hold
        # some credential files from an earlier partial write (this is not
        # necessarily a first attempt), and this attempt may have landed a
        # different subset. Never claim "Enrolled" here and never resend the
        # token: the server consumed it before these local writes began.
        echo "ERROR patched-enroll: failed to persist one or more credential files after HTTP 200 — the consumed enrollment token cannot be retried"
        echo "ERROR patched-enroll: endpoint may hold a partial/mixed set of credential files from this or a prior attempt"
        rm -f "${creds_tmp_files[@]}"
        _enrol_suspend_and_set_token_aside
    fi

    # PAT-1756: a successful enrolment is an admin-authorised act (a
    # single-use token), and this device may now belong to a tenant whose
    # config_version sequence is behind whatever floor is on disk. Now that
    # every credential file has landed (never before, and never on the
    # failed-write path above), remove the agent-config anti-rollback floor
    # only when it cannot be this tenant's own: a legacy bare integer (which
    # the agent otherwise has to treat as the enrolled tenant's, the
    # WIN-STAGING shape), a corrupt file, or a floor keyed to another tenant.
    # A floor that exists but cannot be read is kept too (its content is
    # unknown). A floor keyed to the tenant just enrolled is kept, so re-enrolling into
    # the same tenant does not let an older signed config for that tenant be
    # replayed. The file is classified by agent_config_floor.py (PAT-1763),
    # the same parser patched-fetch-config.sh and verify-agent-config.py use.
    # A failure is logged and does not undo the enrolment. This read-then-remove is not serialised with a commit: the
    # config-poll daemon's own patched-fetch-config.sh can verify and commit a
    # config for the new tenant as soon as bearer-token exists (and
    # patched-fetch-config.sh runs this script before taking its lock). If that
    # commit writes the new tenant's floor between the read below and the rm,
    # the floor is lost and the device runs one poll without a floor for this
    # tenant, the same worst case as the Windows agent's gap between its last
    # read and the delete. It never causes a rejected config.
    # Only a floor the parser positively classified may be removed. A reader
    # that crashed (non-zero exit: a signal, an unhandled exception, a missing
    # module) or printed something unexpected tells us nothing about the file,
    # so it is kept.
    _enrol_floor_state "$AGENT_CONFIG_VERSION_FILE" "$tenant_id"
    case "$floor_state" in
        absent)
            echo "  patched-enroll: no agent-config anti-rollback floor on disk; the first signed config for tenant $tenant_id sets it"
            ;;
        same_tenant)
            echo "  patched-enroll: agent-config anti-rollback floor kept; it already belongs to enrolled tenant $tenant_id"
            ;;
        "unreadable "*)
            # Never delete what could not be read: it may be this tenant's own
            # floor. It keeps failing closed until it can be read or is removed.
            echo "ERROR patched-enroll: agent-config anti-rollback floor at $AGENT_CONFIG_VERSION_FILE kept after enrolling into tenant $tenant_id: it could not be read (${floor_state#unreadable }), so it is not removed"
            ;;
        reader_failed)
            echo "ERROR patched-enroll: agent-config anti-rollback floor at $AGENT_CONFIG_VERSION_FILE kept after enrolling into tenant $tenant_id: the floor reader failed (exit $floor_reader_rc), so it is not removed"
            ;;
        legacy|other_tenant|corrupt)
            if rm -f "$AGENT_CONFIG_VERSION_FILE" 2>/dev/null && [[ ! -e "$AGENT_CONFIG_VERSION_FILE" ]]; then
                echo "  patched-enroll: agent-config anti-rollback floor removed ($floor_state) for enrolled tenant $tenant_id"
            else
                echo "ERROR patched-enroll: could not remove the agent-config anti-rollback floor ($floor_state) at $AGENT_CONFIG_VERSION_FILE after enrolling into tenant $tenant_id; a config for this tenant below the old floor will be rejected until the file is removed"
            fi
            ;;
        *)
            echo "ERROR patched-enroll: agent-config anti-rollback floor at $AGENT_CONFIG_VERSION_FILE kept after enrolling into tenant $tenant_id: the floor reader returned an unexpected result (${${floor_state[1,80]}//[^[:print:]]/?}), so it is not removed"
            ;;
    esac

    # Credential files landed; retire the token that the server already consumed.
    rm -f "$ENROLL_TOKEN_FILE"

    echo "  Enrolled: tenant $tenant_id"
    rm -f "$resp_file"
    exit 0
fi

# ---------------------------------------------------------------------------
# 410 or 401 — terminal failure; caller must enter suspended state
# ---------------------------------------------------------------------------
if [[ "$http_code" == "410" ]]; then
    echo "PATCHED_ENROLLMENT_EXPIRED: enrollment token consumed or expired — entering suspended state"
elif [[ "$http_code" == "401" ]]; then
    echo "PATCHED_ENROLLMENT_INVALID: enrollment token rejected (401) — entering suspended state"
fi

if [[ "$http_code" == "410" || "$http_code" == "401" ]]; then
    _enrol_suspend_and_set_token_aside
fi

# ---------------------------------------------------------------------------
# All other codes (5xx, 000, etc.) — transient; retain token, retry next poll
# ---------------------------------------------------------------------------
echo "  patched-enroll: transient error (HTTP $http_code) — retaining token for next poll"
rm -f "$resp_file"
exit 0
