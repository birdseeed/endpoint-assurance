#!/bin/zsh
##############################################################################
# patched-update.sh — privileged update wrapper around the Patched fork of
#                      Installomator.
#
# Run by the LaunchDaemon `com.patched.update` (as root). On each run it:
#   1. Verifies its own bundle (Installomator + allowlist + this script)
#      against a pinned SHA-256 manifest BEFORE executing anything.   (review §4.5)
#   2. Determines the label set: a targeted set from a trigger file
#      (self-service), or the full allowlist (admin-scheduled).
#   3. Runs Installomator per label. Installomator verifies each artifact
#      against Apple's code-signing PKI (Team ID + notarization).      (review §2)
#   4. Records a provenance record per app and POSTs it to the ingestion
#      API with the same bearer + HMAC auth the inventory agent uses.  (review §4.6)
#   5. Writes /Library/Application Support/Patched/update-status.json
#      atomically — the contract the menu bar app reads.
#
# CONVENTIONS (shared with the macOS inventory agent):
#   - `set -u` only. NOT `set -euo pipefail` — codesign/lipo return non-zero
#     on macOS "fake binary" app stubs and would abort the run.
#   - python3 hardcoded to /usr/bin/python3 (sudo strips PATH).
#   - Never use `path` / `fpath` / etc. as variable names (zsh typeset -T trap).
#
# STATUS: production update daemon (44 commits/PRs and counting since the
#         initial build). Any remaining TODO markers flag specific open items,
#         not the overall maturity of the script.
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
INSTALLOMATOR="$BUNDLE_DIR/Installomator.sh"
ALLOWLIST="$BUNDLE_DIR/labels-allowlist.txt"
MANIFEST="$BUNDLE_DIR/manifest.sha256"
# PAT-687: pinned SHA-256 of manifest.sha256, stamped by tools/build-bundle.sh
# at release time. verify_bundle() checks the on-disk manifest against this pin
# BEFORE trusting the per-file hashes it lists, so an attacker who swaps a
# bundled script AND regenerates the sibling manifest is still caught. The daemon
# is intentionally absent from the manifest (it carries this pin); its own
# integrity is anchored at install time by install.sh's EXPECTED_DAEMON_HASH.
# Left as the literal placeholder in dev/source checkouts → pin check is skipped.
EXPECTED_MANIFEST_HASH="__MANIFEST_HASH__"

STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
STATUS_FILE="$STATE_DIR/update-status.json"
TRIGGER_DIR="$STATE_DIR/triggers"                 # sticky, mode 1733
PROV_QUEUE="${PATCHED_PROV_QUEUE:-/var/db/patched/provenance-queue}"
EVENTS_QUEUE="${PATCHED_EVENTS_QUEUE:-/var/db/patched/events-queue}"  # PAT-499
SOFA_CACHE="$STATE_DIR/sofa-cache.json"           # PAT-273: SOFA feed cache (6-hour TTL)
OS_POLICY_FILE="$STATE_DIR/os-update-policy.plist" # PAT-273: per-tenant nudge policy
PROXY_RESOLVE="$BUNDLE_DIR/patched-proxy-resolve.py" # PAT-278: PAC-aware proxy resolver
MIRROR_MANIFEST_FILE="$STATE_DIR/mirror-manifest.json"  # PAT-500: mirror manifest from CDN (fetched at run start)
# PAT-896: hoisted above the mirror-manifest refresh (which calls with_proxy,
# and with_proxy reads this) so that first with_proxy call resolves the
# tenant's real proxy.mode instead of an empty path. Previously assigned
# further down, which was harmless only because that call site crashed
# before ever reaching the resolver.
AGENT_CONFIG_FILE="$STATE_DIR/agent-config.json"
# PAT-1076: the hash file patched-fetch-config.sh writes on every verified
# commit (see that script's AGENT_CONFIG_SHA256_FILE / _write_agent_config_sha256).
# Same path formula as that script: "$STATE_DIR/agent-config.sha256".
AGENT_CONFIG_SHA256_FILE="$STATE_DIR/agent-config.sha256"
AGENT_CONFIG_HEARTBEAT_FILE="$STATE_DIR/agent-config.checked"

CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-update.log}"

# PAT-652: structured JSON-lines log alongside the existing plain-text log.
JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_FILE="$JSONL_LOG_DIR/update.jsonl"
JSONL_COMPONENT="update"

# Installomator fork tag this bundle was built from (stamped at build time).
INSTALLOMATOR_TAG="${PATCHED_INSTALLOMATOR_TAG:-fail-closed-verification-1.0}"

mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR" "$PROV_QUEUE" "$EVENTS_QUEUE"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== patched-update run started $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

LEGACY_APP_EXECUTION_GATE="$BUNDLE_DIR/patched-legacy-app-execution-gate.py"
LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42

# >>> PATCHED_LEGACY_APP_EXECUTION_ENABLED_START
# Evaluated at each legacy execution seam after the config refresh. The shared
# helper opens the config once, then hashes and parses that same immutable
# in-memory snapshot. Before executing the root helper, require one exact
# manifest entry whose hash still covers its current bytes. A stray or replaced
# helper can never become an execution-authority oracle.
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

# ---------------------------------------------------------------------------
# STRUCTURED LOGGING HELPERS (PAT-652)
# Writes JSON-lines to /Library/Logs/Patched/update.jsonl alongside the
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
log_jsonl "info" "update run started"

# ---------------------------------------------------------------------------
# 1. BUNDLE INTEGRITY  (review §4.5 — closes T6)
# ---------------------------------------------------------------------------
# The manifest lists "SHA256␣␣relative/path" for every trusted component.
# If any component fails to match, abort BEFORE running Installomator — a
# tampered script could otherwise remove the Team ID verification itself.

verify_bundle() {
    if [[ ! -f "$MANIFEST" ]]; then
        echo "FATAL: integrity manifest missing ($MANIFEST)"
        return 1
    fi

    # PAT-687: pin the manifest itself. Verify manifest.sha256 matches the hash
    # baked into this daemon before trusting the per-file hashes it lists — a
    # tampered manifest+script pair would otherwise pass. Skipped only when the
    # pin is unstamped (dev/source checkout), so local test runs still work.
    if [[ "$EXPECTED_MANIFEST_HASH" == "__MANIFEST_HASH__" ]]; then
        echo "WARN: manifest hash pin not stamped (dev build) — skipping manifest pin check"
    else
        local _manifest_hash
        _manifest_hash=$(shasum -a 256 "$MANIFEST" 2>/dev/null | awk '{print $1}')
        if [[ "$_manifest_hash" != "$EXPECTED_MANIFEST_HASH" ]]; then
            echo "FATAL: manifest.sha256 hash mismatch — tampered or mismatched bundle."
            echo "  Expected: $EXPECTED_MANIFEST_HASH"
            echo "  Got:      ${_manifest_hash:-<missing>}"
            return 1
        fi
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
# SUSPENDED STATE CHECK (PAT-544): server rejected this device's
# authentication (a 401 whose cause is not disclosed, PAT-1745) or enrollment.
# ---------------------------------------------------------------------------
if [[ -f "$CREDS_DIR/suspended" ]]; then
    echo "Device suspended (server rejected authentication or enrollment; see patched-fetch-config log); update run aborted"
    exit 0
fi

# ---------------------------------------------------------------------------
# ENROLLMENT (PAT-544) — exchange single-use token on first run.
# ---------------------------------------------------------------------------
if [[ -f "$CREDS_DIR/enrollment-token" && ! -f "$CREDS_DIR/bearer-token" ]]; then
    ENROLL_SCRIPT="$BUNDLE_DIR/patched-enroll.sh"
    if [[ -x "$ENROLL_SCRIPT" ]]; then
        if ! "$ENROLL_SCRIPT"; then
            echo "Enrollment failed terminally — update run aborted"
            exit 0
        fi
    else
        echo "WARN: patched-enroll.sh not found in bundle ($ENROLL_SCRIPT) — update run aborted"
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# CREDENTIALS + HMAC  (same scheme as patched-upload.sh)
# ---------------------------------------------------------------------------

for f in tenant-id bearer-token hmac-secret; do
    [[ -f "$CREDS_DIR/$f" ]] || { echo "ERROR: $CREDS_DIR/$f missing"; exit 1; }
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
# PROXY RESOLUTION  (PAT-278)
#
# with_proxy <target-url> <command...>
# Resolves the effective proxy for <target-url> via agent-config (mode:
# system|manual|off) and sets HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY
# for <command>.  On direct/off: clears those vars to neutralise any inherited
# proxy from the parent environment.  Logs display_url (creds redacted).
# Fails open: if the resolver is absent or crashes, runs command directly.
#
# PAT-896: moved above its call sites (was defined 537 lines after the
# earliest use in the mirror-manifest refresh below, which made every such
# call a zsh "command not found" that the caller swallowed as a network
# error). No behavior change - same body, earlier position.
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

    # Diagnostics go to stderr: several callers capture this function's stdout
    # (e.g. code=$(with_proxy ... curl -w '%{http_code}')), so a stray stdout
    # line here would corrupt the captured value.
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
# AGENT CONFIG  (PAT-282) — refresh then apply tier gate.
# patched-fetch-config.sh is fail-safe: network errors keep last-good config.
# ---------------------------------------------------------------------------

FETCH_CONFIG="$BUNDLE_DIR/patched-fetch-config.sh"
if [[ -x "$FETCH_CONFIG" ]]; then
    "$FETCH_CONFIG" || true
else
    echo "WARN: patched-fetch-config.sh not found; skipping config refresh"
fi

# PAT-500: fetch the Patched CDN mirror manifest (mirrors/manifest.json).
# The manifest maps label → {version, url, sha256} for artifacts published by
# the Phase 2 mirror pipeline. MIRROR_CDN_BASE is the public CDN root URL;
# empty (the default) means the mirror is not yet configured and the endpoint
# always falls through to the direct vendor download path.
#
# Fail-open: network failure or absent manifest does not block the run; direct
# vendor download is always the fallback and must always work.
#
# HARD FAIL (by design): once a label has patched.mirror=true and a pinned_sha256,
# a SHA-256 mismatch between the downloaded artifact and pinned_sha256 aborts the
# install and emits a PATCHED_VERIFICATION_FAILED log line. This is intentional —
# a mismatch means the CDN artifact was tampered with or rotated without a pipeline run.
MIRROR_CDN_BASE="${PATCHED_MIRROR_CDN_BASE:-}"
MIRROR_MANIFEST_CACHE_TTL=21600   # 6 hours (mirror pipeline runs daily)

# PAT-1079: sentinel-wrapped (bare code, not a function — same pattern as
# PATCHED_AGENT_TIER_DEFAULT below and PATCHED_INSTALL_MODE in install.sh) so
# endpoint/test-mktemp-symlink-refusal.zsh can extract and drive this block
# directly, with no root and no network, and prove the symlink refusal below
# actually fires. This ticket does not change what the block does on the happy
# path — it only fixes the mktemp template and adds the refusal.
# >>> PATCHED_MIRROR_MANIFEST_REFRESH_START
if [[ -n "$MIRROR_CDN_BASE" ]]; then
    MIRROR_MANIFEST_URL="${MIRROR_CDN_BASE%/}/mirrors/manifest.json"
    _mirror_fetch_needed=1
    if [[ -f "$MIRROR_MANIFEST_FILE" ]]; then
        _mirror_age=$(( $(date -u +%s) - $(stat -f %m "$MIRROR_MANIFEST_FILE" 2>/dev/null || echo 0) ))
        (( _mirror_age < MIRROR_MANIFEST_CACHE_TTL )) && _mirror_fetch_needed=0
    fi

    if (( _mirror_fetch_needed )); then
        # PAT-1079: template ends in X's. macOS/BSD mktemp only substitutes a
        # TRAILING X run, so ".patched-mirror-manifest.XXXXXX.json" was not a
        # template at all — mktemp handed back that literal, permanently
        # predictable path in world-writable /tmp. Any local user could
        # pre-create it and permanently deny this refresh (mktemp then fails
        # "File exists" on every run). The .json extension was cosmetic: the
        # file is only written by curl, parsed by path, and renamed below.
        _mirror_tmp=$(mktemp /tmp/.patched-mirror-manifest.XXXXXX)
        # Refuse to write through a symlink. mktemp created this file with
        # O_CREAT|O_EXCL, which refuses any pre-existing entry (symlink
        # included), and the name is now genuinely random, so nothing can be
        # pre-planted here. This covers the narrower case of the entry being
        # swapped for a symlink between that create and curl's own, separate,
        # later open by path. Check-then-use is two syscalls and is not atomic:
        # this narrows the race, it does not eliminate it. /tmp's sticky bit
        # already stops a non-root user unlinking this root-owned file, so the
        # swap is not reachable in practice today — this guards the pattern.
        if [[ -L "$_mirror_tmp" ]]; then
            rm -f "$_mirror_tmp"
            echo "WARN: mirror manifest temp path is a symlink — refusing to write through it; keeping cached copy"
        elif with_proxy "$MIRROR_MANIFEST_URL" \
            curl -fsSL --max-time 30 -o "$_mirror_tmp" "$MIRROR_MANIFEST_URL" 2>/dev/null; then
            # Validate it's parseable JSON before replacing the cached copy.
            if "$PYTHON3" -c "import json,sys; json.load(open(sys.argv[1]))" "$_mirror_tmp" 2>/dev/null; then
                mv "$_mirror_tmp" "$MIRROR_MANIFEST_FILE"
                echo "Mirror manifest refreshed from $MIRROR_MANIFEST_URL"
            else
                rm -f "$_mirror_tmp"
                echo "WARN: mirror manifest at $MIRROR_MANIFEST_URL was not valid JSON — keeping cached copy"
            fi
        else
            rm -f "$_mirror_tmp"
            echo "WARN: could not fetch mirror manifest (network error) — using cached copy if present"
        fi
    fi
else
    echo "MIRROR_CDN_BASE not set — mirror path inactive; using direct vendor downloads"
fi
# <<< PATCHED_MIRROR_MANIFEST_REFRESH_END

# PAT-1773: decide once, after the config refresh above, whether the cached
# config belongs to the enrolled tenant. Every reader below asks
# agent_config_present.
agent_config_tenant_scope

# PAT-1040: a confirmed 304 hash mismatch (endpoint/patched-fetch-config.sh,
# _agent_config_handle_304) now quarantines AGENT_CONFIG_FILE out of its
# canonical path rather than leaving unverified bytes in place, which puts
# this daemon's own read of the config into the "absent" branch below for the
# rest of that poll cycle. Sentinel-wrapped (bare code, not a function, same
# pattern as PATCHED_INSTALL_MODE in install.sh) so
# endpoint/test-agent-tier-default.zsh can extract and drive this decision
# directly, no root, proving the pre-existing absent/malformed/invalid-tier
# default was and remains assurance (scan-only) — this ticket does not
# change this block's behavior, only adds a new way the "absent" branch gets
# exercised in practice.
# >>> PATCHED_AGENT_TIER_DEFAULT_START
# Read tier from cached config; default to assurance (scan-only, no patching).
#
# PAT-1076: this daemon runs as root and actually installs software, so it
# should not trust AGENT_CONFIG_FILE's bytes on patched-fetch-config.sh's
# gatekeeping alone — that is cheap to verify independently right here.
# Before the AGENT_TIER value below is read from AGENT_CONFIG_FILE, its
# current on-disk bytes must hash to the value patched-fetch-config.sh
# recorded in AGENT_CONFIG_SHA256_FILE at the last verified commit (same
# file/format that script's own _agent_config_hash_matches checks — see
# PATCHED_CONFIG_HASH_CHECK block in patched-fetch-config.sh). A missing
# config, a missing/unreadable hash file, or a hash mismatch all fall
# through to the exact same branch as a fully absent config (AGENT_TIER
# stays "assurance") — not a separate, parallel fallback.
AGENT_TIER="assurance"
config_hash_recorded=""
config_hash_actual=""
if agent_config_present && [[ -f "$AGENT_CONFIG_SHA256_FILE" ]]; then
    config_hash_recorded=$(head -1 "$AGENT_CONFIG_SHA256_FILE" 2>/dev/null | tr -d '[:space:]')
    config_hash_actual=$(shasum -a 256 "$AGENT_CONFIG_FILE" 2>/dev/null | awk '{print $1}')
    if [[ -z "$config_hash_actual" ]]; then
        echo "CRITICAL: shasum failed or produced no output while hashing $AGENT_CONFIG_FILE — treating config as absent (AGENT_TIER stays assurance)" >&2
        log_jsonl "error" "CRITICAL: shasum failed to hash AGENT_CONFIG_FILE — config treated as absent" "{\"file\":\"$AGENT_CONFIG_FILE\"}"
    fi
fi
if agent_config_present && [[ -n "$config_hash_recorded" && -n "$config_hash_actual" \
      && "$config_hash_recorded" == "$config_hash_actual" ]]; then
    AGENT_TIER=$("$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    t = d.get('tier', 'assurance')
    # PAT-1807: the tier vocabulary is now just assurance/managed (PAT-1599
    # already made this the Windows-agent behavior; this completes it here).
    # Any other value (the retired 'report_deploy'/'patch' names included)
    # falls back to the safe default, same as an absent or malformed config.
    print(t if t in ('assurance', 'managed') else 'assurance')
except Exception:
    print('assurance')
" "$AGENT_CONFIG_FILE" 2>/dev/null || echo "assurance")
elif agent_config_present && [[ -n "$config_hash_recorded" && -n "$config_hash_actual" ]]; then
    echo "CRITICAL: config hash mismatch for $AGENT_CONFIG_FILE — recorded hash does not match actual; treating config as absent (AGENT_TIER stays assurance)" >&2
    log_jsonl "error" "CRITICAL: AGENT_CONFIG_FILE hash mismatch — treating config as absent, not a missing config" "{\"file\":\"$AGENT_CONFIG_FILE\"}"
fi
# <<< PATCHED_AGENT_TIER_DEFAULT_END
echo "Agent tier: $AGENT_TIER"

HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
COMPUTER_NAME=$(scutil --get ComputerName 2>/dev/null || echo "unknown")

# >>> PATCHED_BLOCKED_VERSION_PREFLIGHT_START
# PAT-1238: blocked_versions is a privileged refusal. A non-empty signed
# policy for a label checks the candidate version from the local, signature-
# verified catalogue before the normal engine invocation can download, mount,
# prompt, stop a process, or install. The catalogue version and PINNED_SHA256
# describe the same verifier-approved artifact, avoiding vendor re-resolution.
#
# blocked_version_policy_state <label> [version]
# stdout: no_policy | preflight_required | allowed | blocked | invalid
# An absent label or explicit empty list preserves normal behaviour. A malformed
# active policy is invalid and must fail closed rather than bypass the kill switch.
blocked_version_policy_state() {
    local _bv_label="$1" _bv_version="${2:-}"
    agent_config_present || { print -r -- "no_policy"; return 0; }
    PATCHED_BV_LABEL="$_bv_label" PATCHED_BV_VERSION="$_bv_version" \
    "$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import json, os, sys

label = os.environ.get("PATCHED_BV_LABEL", "")
version = os.environ.get("PATCHED_BV_VERSION", "")
try:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
except Exception:
    print("invalid")
    raise SystemExit

if not isinstance(cfg, dict):
    print("invalid")
    raise SystemExit

blocked_versions = cfg.get("blocked_versions")
if blocked_versions is None:
    print("no_policy")
    raise SystemExit
if not isinstance(blocked_versions, dict):
    print("invalid")
    raise SystemExit

versions = blocked_versions.get(label)
if versions is None or versions == []:
    print("no_policy")
    raise SystemExit
if (not isinstance(versions, list) or
        any(not isinstance(item, str) or not item or any(ch.isspace() for ch in item)
            for item in versions)):
    print("invalid")
    raise SystemExit

if not version:
    print("preflight_required")
else:
    print("blocked" if version in versions else "allowed")
PYEOF
}

# <<< PATCHED_BLOCKED_VERSION_PREFLIGHT_END

# ---------------------------------------------------------------------------
# PER-APP UPDATE POLICY  (PAT-383 — macOS parity with the Windows PAT-381 path)
#
# per_app_patch (PAT-364 store) rides inside the signed agent config: a
# estate-wide on/off default plus optional per-app overrides. An override matches
# this app when its identifier equals EITHER the Installomator label OR the
# macOS bundle ID (case-insensitive) — the same "winget id OR label" join the
# Windows resolver (PerAppPatchPolicy.Allows) uses, so one policy row authored
# against either identity actuates both platforms.
#
# Resolution (identical to the Windows resolver and the original PAT-365 script):
#   1. a matching override's enabled flag wins;
#   2. else estate_default_enabled (fleet_default_enabled field);
#   3. null / absent / malformed → fail-open (all enabled) so a policy that can't
#      be read never silently halts patching.
#
# Honoured for installs only (scan never installs) and recorded in provenance
# only — never in the tray status.json, whose schema (additionalProperties:false;
# last_action has no skipped_policy member) cannot carry it. This mirrors the
# Windows path keeping PolicySource/PolicyDisabled [JsonIgnore].
# ---------------------------------------------------------------------------

POLICY_DEFAULT_ENABLED=1               # 1 = updates on by default, 0 = off
typeset -A POLICY_OVERRIDE             # [lowercased identifier] = 1|0

load_per_app_policy() {
    agent_config_present || { echo "per_app_patch: no agent config for the enrolled tenant — estate default enabled"; return; }
    local parsed
    parsed=$("$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)                       # fail-open: emit nothing -> estate default on
pap = cfg.get('per_app_patch')
# Wire shape is null | bool | object (matches the Windows PerAppPatchPolicyConverter).
if pap is None:
    sys.exit(0)
if pap is True:
    print('default 1'); sys.exit(0)
if pap is False:
    print('default 0'); sys.exit(0)
if not isinstance(pap, dict):
    sys.exit(0)
print('default', '0' if pap.get('fleet_default_enabled', True) is False else '1')
for o in pap.get('overrides', []):
    if not isinstance(o, dict) or o.get('platform') != 'macos':
        continue
    ident = o.get('identifier')
    if not ident:
        continue
    # enabled defaults to True; only an explicit false disables (o.get('enabled', True)).
    print('override', str(ident).lower(), '0' if o.get('enabled', True) is False else '1')
PYEOF
    ) || { echo "per_app_patch: parse error — estate default enabled (fail-open)"; return; }

    # Lines are "default <0|1>" (value in field 2) or "override <ident> <0|1>"
    # (value in field 3). Read all three fields and pick the right one per kind.
    local kind key val n=0
    while IFS=' ' read -r kind key val; do
        [[ -z "$kind" ]] && continue
        case "$kind" in
            default)  POLICY_DEFAULT_ENABLED="$key" ;;
            override) POLICY_OVERRIDE[$key]="$val"; (( n++ )) ;;
        esac
    done <<< "$parsed"
    echo "per_app_patch: fleet_default_enabled=$POLICY_DEFAULT_ENABLED overrides=$n"
}

# policy_allows <label> <bundle_id>: returns 0 (true) if updates are enabled for
# this app. An override keyed by label or bundle ID wins; else the estate default.
policy_allows() {
    local lbl="${1:l}" bid="${2:l}"
    if [[ -n "$lbl" && -v POLICY_OVERRIDE[$lbl] ]]; then
        (( POLICY_OVERRIDE[$lbl] == 1 ))
    elif [[ -n "$bid" && -v POLICY_OVERRIDE[$bid] ]]; then
        (( POLICY_OVERRIDE[$bid] == 1 ))
    else
        (( POLICY_DEFAULT_ENABLED == 1 ))
    fi
}

# policy_source <label> <bundle_id>: "override" if a row matched, else "fleet_default".
policy_source() {
    local lbl="${1:l}" bid="${2:l}"
    if { [[ -n "$lbl" ]] && [[ -v POLICY_OVERRIDE[$lbl] ]]; } || { [[ -n "$bid" ]] && [[ -v POLICY_OVERRIDE[$bid] ]]; }; then
        echo "override"
    else
        echo "fleet_default"
    fi
}

load_per_app_policy

# ---------------------------------------------------------------------------
# DEPLOYMENT RING POLICY  (PAT-506)
#
# ring (0=internal, 1=canary, 2=early-adopter, 3=GA) from signed agent-config
# gates whether a device may install a version that has not yet soaked through
# the earlier rings. The platform advances approved_ring from 0→3 as each ring
# soak succeeds; endpoints only install if device_ring <= approved_ring.
#
# Legacy ring_promotions is retained for pre-PAT-1134 agents. Current agents
# prefer ring_promotions_scoped when it is present. Its explicit
# approval="nobody" representation is a fail-closed pause, including a pause
# before ring 0 is approved.
# ---------------------------------------------------------------------------

DEVICE_RING=3              # 0=internal … 3=GA; absent from config = most permissive
typeset -A RING_PROMOTION  # [label_lowercase] = approved_ring (0-3)
typeset -A RING_SCOPED_APPROVAL # [label_lowercase] = up_to_ring|nobody
typeset -A RING_SCOPED_RING     # [label_lowercase] = approved_ring
RING_SCOPED_PRESENT=0
RING_SCOPED_PLATFORM_INVALID=0

load_ring_policy() {
	RING_PROMOTION=()
	RING_SCOPED_APPROVAL=()
	RING_SCOPED_RING=()
	RING_SCOPED_PRESENT=0
	RING_SCOPED_PLATFORM_INVALID=0
    agent_config_present || return 0
    local parsed
    parsed=$("$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import json, sys
def emit(*fields):
    print(*fields, sep='\t')
try:
    cfg = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
ring = cfg.get('ring')
if isinstance(ring, int) and 0 <= ring <= 3:
    emit('ring', ring)
scoped = cfg.get('ring_promotions_scoped')
if isinstance(scoped, dict):
    emit('scoped_present')
    if 'macos' in scoped and not isinstance(scoped['macos'], dict):
        # An explicitly present but malformed platform section is not the
        # same as an absent platform. It must not permit every label.
        emit('scoped_platform_invalid')
    else:
        platform = scoped.get('macos')
        if isinstance(platform, dict):
            for label, entry in platform.items():
                if not isinstance(label, str) or '\t' in label or '\r' in label or '\n' in label or not isinstance(entry, dict):
                    continue
                approval = entry.get('approval')
                approved = entry.get('approved_ring')
                if approval == 'nobody':
                    emit('scoped_deny', label.lower())
                elif approval == 'up_to_ring' and isinstance(approved, int) and 0 <= approved <= 3:
                    emit('scoped_allow', label.lower(), approved)
                else:
                    # A signed but malformed scoped entry must not become an
                    # accidental allow. Treat this label as explicitly denied.
                    emit('scoped_deny', label.lower())
for label, entry in (cfg.get('ring_promotions') or {}).items():
    if not isinstance(entry, dict):
        continue
    approved = entry.get('approved_ring')
    if isinstance(approved, int) and 0 <= approved <= 3:
        if isinstance(label, str) and '\t' not in label and '\r' not in label and '\n' not in label:
            emit('promotion', label.lower(), approved)
PYEOF
    ) || return 0
    local kind key val n=0
    while IFS=$'\t' read -r kind key val; do
        [[ -z "$kind" ]] && continue
        case "$kind" in
            ring)      DEVICE_RING="$key" ;;
            promotion) RING_PROMOTION[$key]="$val"; (( n++ )) ;;
		scoped_present) RING_SCOPED_PRESENT=1 ;;
		scoped_platform_invalid) RING_SCOPED_PLATFORM_INVALID=1 ;;
		scoped_deny)  RING_SCOPED_APPROVAL[$key]="nobody" ;;
		scoped_allow) RING_SCOPED_APPROVAL[$key]="up_to_ring"
		               RING_SCOPED_RING[$key]="$val" ;;
        esac
    done <<< "$parsed"
    echo "ring_policy: device_ring=$DEVICE_RING promotions=$n scoped=$RING_SCOPED_PRESENT"
}

# ring_allows <label>: returns 0 (allow) if device_ring <= approved_ring for this
# label, or if no ring gate exists for the label (fail-open).
ring_allows() {
    local lbl="${1:l}"
	if [[ "$RING_SCOPED_PRESENT" == "1" ]]; then
		[[ "$RING_SCOPED_PLATFORM_INVALID" == "0" ]] || return 1
		[[ -v RING_SCOPED_APPROVAL[$lbl] ]] || return 0
		[[ "${RING_SCOPED_APPROVAL[$lbl]}" == "up_to_ring" ]] || return 1
		(( DEVICE_RING <= RING_SCOPED_RING[$lbl] ))
		return
	fi
    [[ -v RING_PROMOTION[$lbl] ]] || return 0
    (( DEVICE_RING <= RING_PROMOTION[$lbl] ))
}

load_ring_policy

# ---------------------------------------------------------------------------
# BLOCKING-PROCESS POLICY  (PAT-296)
#
# Reads blocking_process_policy from the signed agent config and surfaces four
# shell variables consumed by run_label during install-mode runs:
#
#   BPP_MESSAGE           — user-facing copy (empty = use built-in default)
#   BPP_TIMEOUT_SECONDS   — seconds to wait before action_on_timeout (default 300)
#   BPP_MAX_DEFERRALS     — max user deferrals per app per cycle (default 2)
#   BPP_DEFER_WINDOW_SECS — deferral postpone window in seconds (default 3600)
#   BPP_ACTION_ON_TIMEOUT — notify_only | prompt_then_quit | skip_run, or empty
#                           (empty = fail-closed: no valid policy was loaded)
#
# FAIL CLOSED. When the signed policy cannot be established as a valid, known
# action, BPP_ACTION_ON_TIMEOUT is left EMPTY and bpp_map_action degrades it to
# silent_fail — the install is refused while the app is running (no prompt, no
# quit, no install-through); it proceeds normally only when the app is not
# running. This applies when:
#   - the agent-config file is absent
#   - the config cannot be parsed / verified
#   - the blocking_process_policy block is absent or not an object
#   - action_on_timeout is an unexpected/unrecognised value
# A validly-parsed block whose action_on_timeout is omitted/null is treated as the
# tenant's notify_only default (the platform coerces + signs that before delivery).
#
# NEVER silently force-quit a running app — no path force-quits/kills, and any
# doubt about the policy resolves to the fail-closed silent_fail (refuse), which
# is strictly safer than prompting.
#
# Deferral state is persisted across daemon runs in:
#   $STATE_DIR/blocking-deferrals-<label>.json
# Format: {"count": N, "last_deferred_at": "ISO8601"}
# Reset on successful update (outcome=installed).
# ---------------------------------------------------------------------------

BPP_MESSAGE=""
BPP_TIMEOUT_SECONDS=300
BPP_MAX_DEFERRALS=2
BPP_DEFER_WINDOW_SECS=3600
# Fail-closed default: empty until a valid, known policy action is loaded.
# bpp_map_action maps empty -> silent_fail (refuse), never a prompt/quit.
BPP_ACTION_ON_TIMEOUT=""

load_blocking_process_policy() {
    # Reset to fail-closed defaults first, so a reload never inherits stale state
    # and every early return (absent/unparseable config, absent/malformed block)
    # leaves BPP_ACTION_ON_TIMEOUT empty -> bpp_map_action -> silent_fail.
    BPP_MESSAGE=""
    BPP_TIMEOUT_SECONDS=300
    BPP_MAX_DEFERRALS=2
    BPP_DEFER_WINDOW_SECS=3600
    BPP_ACTION_ON_TIMEOUT=""
    agent_config_present || { echo "blocking_process_policy: no agent config for the enrolled tenant — fail closed (silent_fail on blocking apps)"; return; }
    local parsed
    parsed=$("$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import json, sys, re
SAFE_ACTIONS = {"notify_only", "prompt_then_quit", "skip_run"}
try:
    cfg = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)          # fail-safe: emit nothing -> keep shell (fail-closed) defaults
bpp = cfg.get('blocking_process_policy')
if bpp is None or not isinstance(bpp, dict):
    sys.exit(0)          # block absent or malformed -> keep shell (fail-closed) defaults
# Newline-delimited, line-indexed protocol the shell reads with ${(@f)}. The
# LOAD-BEARING scalar fields come FIRST so a tenant-controlled `message` can NEVER
# shift them; the free-text message is emitted LAST. Belt-and-braces, the message
# is also stripped of control chars (incl. newlines) here so it stays a single
# line — a config whose message embeds newlines cannot inject a different action:
#   line 1: action_on_timeout   (empty = fail closed)
#   line 2: timeout_seconds
#   line 3: max_deferrals
#   line 4: defer_window_seconds
#   line 5: message             (single line; may be empty)
msg     = str(bpp.get('message', '') or '')
# Sanitise the tenant message ONCE, here, with the SAME rules as bpp_sanitize_message
# so a single safe value serves BOTH the line-indexed protocol AND the osascript
# dialog. Strip control chars incl. newlines (protocol-safe: cannot add lines or
# shift the field indices) and the dialog-breaking characters " \ ` $ (osascript-
# safe), then cap the length. The shell bpp_sanitize_message re-applies these and
# is idempotent on the result (defence in depth).
msg     = re.sub(r'[\x00-\x1f\x7f]+', ' ', msg)
msg     = re.sub(r'["\\`$]', '', msg)
msg     = msg[:240]
def _clamp_int(v, default, lo, hi):
    # Reject bool (a subclass of int in Python) and non-ints; else clamp to [lo,hi].
    if isinstance(v, bool) or not isinstance(v, int):
        return default
    return max(lo, min(hi, v))
timeout = _clamp_int(bpp.get('timeout_seconds'),      300,  30, 86400)
dwin    = _clamp_int(bpp.get('defer_window_seconds'), 3600, 60, 86400)
# Omitted/null action in a valid block -> the tenant's notify_only default (the
# platform coerces + signs that before delivery). An unexpected/unrecognised VALUE
# is NOT coerced to notify_only — it is emitted empty so the shell fails closed.
action  = str(bpp.get('action_on_timeout', 'notify_only') or 'notify_only')
# FAIL CLOSED on an unexpected action value: emit empty so bpp_map_action -> silent_fail.
if action not in SAFE_ACTIONS:
    action = ''
# max_deferrals GATES the quit escalation (bpp_should_escalate compares the deferral
# count against it), so it is validated STRICTLY and never silently coerced. A bool
# (bool is an int subclass — False -> 0), a non-int, or a NEGATIVE value is malformed
# and must NOT become 0 and enable an immediate quit prompt on the first blocking
# run. Malformed -> fail the whole policy closed (action=''). Absent -> safe default
# 2. A genuine non-negative int (including a deliberate 0) is honoured.
_md = bpp.get('max_deferrals', 2)
if isinstance(_md, bool) or not isinstance(_md, int) or _md < 0:
    action = ''          # malformed max_deferrals -> non-quitting (fail closed)
    maxdef = 2
else:
    maxdef = min(86400, _md)
# Scalars first (fixed positions, immune to message content), message last.
for field in [action, str(timeout), str(maxdef), str(dwin), msg]:
    print(field)
PYEOF
    ) || { echo "blocking_process_policy: parse error — fail closed (silent_fail on blocking apps)"; return; }

    [[ -z "$parsed" ]] && { echo "blocking_process_policy: block absent/malformed — fail closed (silent_fail on blocking apps)"; return; }

    # Read each field by line index into an array to avoid IFS-split edge cases.
    # zsh arrays are 1-indexed; field order matches the Python print sequence above:
    # the action is field 1 (load-bearing, first) and the message is field 5 (last),
    # so message content can never shift the action / scalar fields.
    local -a _bpp_fields
    _bpp_fields=("${(@f)parsed}")   # split on newlines into array
    # Empty 1st field (unexpected action value) -> fail closed (silent_fail).
    BPP_ACTION_ON_TIMEOUT="${_bpp_fields[1]:-}"
    BPP_TIMEOUT_SECONDS="${_bpp_fields[2]:-300}"
    BPP_MAX_DEFERRALS="${_bpp_fields[3]:-2}"
    BPP_DEFER_WINDOW_SECS="${_bpp_fields[4]:-3600}"
    BPP_MESSAGE="${_bpp_fields[5]:-}"
    echo "blocking_process_policy: action_on_timeout=${BPP_ACTION_ON_TIMEOUT:-<fail-closed>} timeout=${BPP_TIMEOUT_SECONDS}s max_deferrals=$BPP_MAX_DEFERRALS defer_window=${BPP_DEFER_WINDOW_SECS}s"
}

# bpp_deferral_count <label>
# Returns current deferral count for the label (0 if no state file).
bpp_deferral_count() {
    local lbl="$1"
    local sf="$STATE_DIR/blocking-deferrals-${lbl}.json"
    [[ -f "$sf" ]] || { echo 0; return; }
    "$PYTHON3" -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int(d.get('count', 0)))
except Exception:
    print(0)
" "$sf" 2>/dev/null || echo 0
}

# bpp_record_deferral <label>
# Increments the deferral count and stamps last_deferred_at.
bpp_record_deferral() {
    local lbl="$1"
    local sf="$STATE_DIR/blocking-deferrals-${lbl}.json"
    "$PYTHON3" - "$sf" <<'PYEOF'
import json, sys, datetime
sf = sys.argv[1]
try:
    d = json.load(open(sf))
except Exception:
    d = {'count': 0}
d['count'] = int(d.get('count', 0)) + 1
d['last_deferred_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
with open(sf, 'w') as f:
    json.dump(d, f)
PYEOF
}

# bpp_reset_deferrals <label>
# Removes the deferral state file (called after a successful install).
bpp_reset_deferrals() {
    local lbl="$1"
    rm -f "$STATE_DIR/blocking-deferrals-${lbl}.json"
}

# bpp_defer_window_elapsed <label>
# Returns 0 (true) if the deferral postpone window has elapsed since the last
# deferral, so the agent should re-prompt. Returns 1 (false) if we are still
# within the defer window and should skip this run silently.
bpp_defer_window_elapsed() {
    local lbl="$1"
    local sf="$STATE_DIR/blocking-deferrals-${lbl}.json"
    [[ -f "$sf" ]] || return 0    # no state -> window has elapsed (first run)
    PATCHED_DEFER_WINDOW="$BPP_DEFER_WINDOW_SECS" \
    "$PYTHON3" - "$sf" <<'PYEOF'
import json, sys, datetime, os
sf = sys.argv[1]
try:
    d = json.load(open(sf))
    last = d.get('last_deferred_at', '')
    if not last:
        sys.exit(0)   # no timestamp -> treat as elapsed
    t = datetime.datetime.fromisoformat(last.replace('Z','+00:00'))
    now = datetime.datetime.now(datetime.timezone.utc)
    window = int(os.environ.get('PATCHED_DEFER_WINDOW', '3600'))
    elapsed = (now - t).total_seconds() >= window
    sys.exit(0 if elapsed else 1)
except Exception:
    sys.exit(0)   # parse error -> treat as elapsed (fail-open)
PYEOF
}

# Agent's built-in default blocking-process prompt copy. Shown when the tenant
# policy message (BPP_MESSAGE) is null/empty. Deliberately neutral and reassuring.
# BPP_DEFAULT_MESSAGE is the soft, deferrable copy; BPP_FINAL_MESSAGE is the
# more-urgent copy used once a prompt_then_quit policy has exhausted its
# deferrals and is presenting the final "must decide now" ask.
BPP_DEFAULT_MESSAGE="A pending security update is ready for this app. Please save your work and quit the app to update. You can keep working for now and it will be offered again later."
BPP_FINAL_MESSAGE="A pending security update can no longer be postponed. Please save your work and quit this app now to finish updating. Choose Not Now to be asked again shortly."

# bpp_sanitize_message <raw>
# Renders a tenant-supplied (or default) message safe to interpolate into the
# AppleScript string the engine builds with:
#     osascript -e "... display dialog \"$message\" ..."
# The agent-config is platform-signed, so this is defence-in-depth, not the sole
# control: we strip the characters that could terminate the AppleScript string
# literal or introduce shell/AppleScript syntax (" \ ` $), fold control chars
# (incl. newlines) to spaces, and cap the length. The result can NEVER break out
# of the dialog string.
bpp_sanitize_message() {
    emulate -L zsh
    local raw="$1"
    raw="${raw//[[:cntrl:]]/ }"      # CR/LF/tabs/other control chars -> space
    raw="${raw//[\"\\\`\$]/}"        # drop quote/backslash/backtick/dollar
    raw="${raw[1,240]}"              # cap length (dialogs are not essays)
    print -r -- "$raw"
}

# bpp_effective_message [<escalate>]
# Echoes the sanitised message to display: the tenant BPP_MESSAGE if it is a
# non-blank string (the tenant owns the copy in every state), otherwise the
# agent's built-in default — the soft deferrable copy normally, or the urgent
# final-notice copy when <escalate>=1 (a prompt_then_quit policy that has
# exhausted its deferrals and is presenting the final user-confirmation quit).
bpp_effective_message() {
    local escalate="${1:-0}"
    local msg="$BPP_MESSAGE"
    if [[ -z "${msg//[[:space:]]/}" ]]; then
        if [[ "$escalate" == "1" ]]; then msg="$BPP_FINAL_MESSAGE"; else msg="$BPP_DEFAULT_MESSAGE"; fi
    fi
    bpp_sanitize_message "$msg"
}

# bpp_map_action <action_on_timeout> [<escalate>]
# Maps the signed-policy action (+ escalation state) to an Installomator
# BLOCKING_PROCESS_ACTION.
#
# The ONLY path that ever presents a quit-capable prompt is prompt_then_quit AFTER
# its deferral budget is exhausted (<escalate>=1). This is the exact scope of the
# GitHub-Non-Author-Review carve-out (patched.im PR #270 / PAT-296): a tenant-configured quit is
# permitted only for prompt_then_quit, only after the configured deferrals are
# spent, and only via the user's explicit final confirmation.
#
# Everything else maps to silent_fail — the app is NEVER quit or killed:
#   * notify_only               — the GitHub-Non-Author-Review criteria require notify_only to NEVER
#                                 quit, so it does not present a quit-capable prompt
#                                 at all; it refuses the install while the app runs.
#   * prompt_then_quit (deferrable, escalate=0) — must not quit before deferrals
#                                 are exhausted, so while deferrable it also refuses.
#   * skip_run                  — skip the update while the app runs.
#   * empty / unknown / malformed — FAIL CLOSED (absent/unparseable/malformed
#                                 policy or unexpected value): refuse; never prompt.
# silent_fail still allows a normal install when the app is NOT running.
#
# SAFE INVARIANT: the agent NEVER emits a force-quit/kill directive. The only
# non-silent_fail action emitted is prompt_user (quit ONLY on explicit consent;
# decline/timeout aborts). The SIGKILL-capable actions (kill, quit_kill, tell_user,
# tell_user_then_kill, prompt_user_then_kill) are never emitted.
#
# Installomator semantics (engine/Installomator.sh checkRunningProcesses):
#   prompt_user   dialog with "Not Now"/"Quit and Update"; "Not Now" -> rc10
#                 abort, timeout -> rc25 abort, quit ONLY on explicit consent.
#                 (prompt_then_quit, escalated only)
#   silent_fail   rc12: exits WITHOUT prompt or install; app untouched, install
#                 does NOT proceed. (everything else)
bpp_map_action() {
    local action="$1" escalate="${2:-0}"
    if [[ "$action" == "prompt_then_quit" && "$escalate" == "1" ]]; then
        print -r -- "prompt_user"
    else
        print -r -- "silent_fail"
    fi
}

# bpp_should_escalate <action_on_timeout> <deferral_count>
# Echoes 1 when a prompt_then_quit policy has exhausted its deferral budget and
# must present the FINAL user-confirmation quit prompt on every run (no more
# silent within-window skips) until the user confirms the quit or the app closes;
# otherwise echoes 0. This is the ONLY condition under which bpp_map_action emits
# a quit-capable action (prompt_user).
#
# ONLY prompt_then_quit escalates. notify_only, skip_run, and any empty/unknown
# policy never escalate — they map to silent_fail (never quit) in every state. The
# escalated quit still requires the user's explicit "Quit and Update"; declining or
# timing out aborts without quitting; never a SIGKILL. This bounded, user-confirmed
# escalation is the exact scope sanctioned by the GitHub-Non-Author-Review carve-out (patched.im
# PR #270 / PAT-296) — quit only for prompt_then_quit, only after deferrals are
# exhausted, only on explicit final confirmation.
bpp_should_escalate() {
    local action="$1" count="${2:-0}"
    if [[ "$action" == "prompt_then_quit" ]] && (( count >= BPP_MAX_DEFERRALS )); then
        print -r -- 1
    else
        print -r -- 0
    fi
}

load_blocking_process_policy

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body so a captured
# signed request cannot be replayed. Signing input is:
#   b"patched-hmac-v3\nPOST\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body
# ts and nonce MUST be the exact strings sent in the X-Patched-Timestamp /
# X-Patched-Nonce headers for this same request — callers generate ts+nonce
# FIRST, then pass them into compute_hmac AND into the headers.
compute_hmac() {  # compute_hmac <body-file> <endpoint-id> <ts> <nonce>
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
# PROVENANCE  (review §4.6) — one authenticated record per app action.
# POSTs to /v1/provenance; on failure leaves a queued file for retry.
# ---------------------------------------------------------------------------

# >>> PATCHED_PROVENANCE_QUEUE_START
# One daemon cycle may spend at most four five-second attempts on provenance.
# Refusal bursts queue first and share this same drain budget, so a hostile
# 32-identifier trigger cannot turn one root cycle into 32 serial timeouts.
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

# queue_provenance <json-file> [...]
# Atomically copies bounded regular-file snapshots into a bounded disk ring.
# The newest evidence is retained when count or byte limits require eviction.
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
        destination = os.path.join(
            queue_dir,
            f"prov-{time.time_ns()}-{os.path.basename(temporary)[6:]}.json",
        )
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
    local body="$1"
    if ! _provenance_network_slot; then
        queue_provenance "$body"
        echo "  provenance POST deferred: per-cycle network budget exhausted"
        return 0
    fi
    local ts; ts=$(date -u +%s)
    local nonce; nonce=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
    local sig; sig=$(compute_hmac "$body" "provenance" "$ts" "$nonce")
    local code
    local -a device_hdr; device_hdr=()
    [[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")
    code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time "$PROVENANCE_HTTP_MAX_SECONDS" \
        -X POST "$API_URL/v1/provenance" \
        -H "X-Patched-Signature: $sig" \
        -H "X-Patched-Timestamp: $ts" \
        -H "X-Patched-Nonce: $nonce" \
        "${device_hdr[@]}" \
        -H "Content-Type: application/json" \
        --data-binary "@$body" 2>/dev/null)
    if [[ "$code" == 2* ]]; then
        echo "  provenance POST -> $code"
    else
        queue_provenance "$body"
        echo "  provenance POST -> ${code:-network-error}; queued locally"
    fi
}

# ---------------------------------------------------------------------------
# PROVENANCE QUEUE DRAIN  (PAT-291)
#
# Retries only the remaining per-cycle network budget. Queue pruning runs
# first, so both retry work and retained storage stay bounded across outages.
#
# Manual flush: force a full agent run (which includes this drain) via
#   sudo launchctl start com.patched.update
# Or call drain_provenance_queue directly in a one-off invocation of this
# script with PATCHED_PROV_QUEUE set to the queue directory.
# ---------------------------------------------------------------------------

drain_provenance_queue() {
    # Nothing to do if the queue directory is absent or empty.
    [[ -d "$PROV_QUEUE" ]] || return 0
    # Prune historic pre-cap state even when this cycle emitted no new record.
    queue_provenance >/dev/null
    # (N) glob qualifier: return empty array instead of a fatal nomatch error
    # when the queue is empty — zsh exits on unmatched globs by default.
    local -a files
    files=("$PROV_QUEUE"/prov-*.json(N))
    [[ ${#files} -gt 0 ]] || return 0

    local total=${#files[@]} drained=0 failed=0 attempted=0
    local f sig ts nonce code
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        _provenance_network_slot || break
        (( attempted++ )) || true
        ts=$(date -u +%s)
        nonce=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
        sig=$(compute_hmac "$f" "provenance" "$ts" "$nonce")
        code=$(with_proxy "$API_URL" \
            patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time "$PROVENANCE_HTTP_MAX_SECONDS" \
            -X POST "$API_URL/v1/provenance" \
            -H "X-Patched-Signature: $sig" \
            -H "X-Patched-Timestamp: $ts" \
            -H "X-Patched-Nonce: $nonce" \
            -H "Content-Type: application/json" \
            --data-binary "@$f" 2>/dev/null)
        if [[ "$code" == 2* ]]; then
            rm -f "$f"
            (( drained++ )) || true
        else
            (( failed++ )) || true
        fi
    done
    echo "provenance queue drain: queued=$total attempted=$attempted drained=$drained failed=$failed budget=$PROVENANCE_NETWORK_MAX_ATTEMPTS"
}
# <<< PATCHED_PROVENANCE_QUEUE_END

# ---------------------------------------------------------------------------
# AUDIT EVENT SHIPPING  (PAT-499)
#
# emit_audit_event <event-type> <label> <version> [<reason>]
#   Writes a JSON event to the ring-buffer queue (max 1000 files; oldest
#   dropped on overflow) and attempts an immediate HMAC-signed POST to
#   /v1/events. Fails open — never blocks or errors the caller.
#
# drain_events_queue
#   Retries all evt-*.json files in $EVENTS_QUEUE. Called once per run.
# ---------------------------------------------------------------------------

# Max events to keep on disk (ring-buffer cap).
EVENTS_QUEUE_MAX=1000

emit_audit_event() {  # emit_audit_event <type> <label> <version> [reason]
    local ev_type="$1" ev_label="${2:-}" ev_version="${3:-}" ev_reason="${4:-}"

    # PAT-1079: mktemp's template must end in X's — macOS/BSD only substitutes
    # a TRAILING X run, so "evt-<ms>-XXXXXX.json" was never a template: mktemp
    # returned it literally, unsubstituted. Two events emitted inside the same
    # millisecond therefore collided, and the second hard-failed ("mkstemp
    # failed ...: File exists") and dropped the event silently via the
    # `|| return 0` below.
    #
    # Unlike the other three sites in this ticket, the .json extension here IS
    # load-bearing and must be preserved: the ring-buffer cap and
    # drain_events_queue both glob evt-*.json, docs/audit-events-contract.md
    # pins the on-disk name as evt-<timestamp>-<random>.json, and the Windows
    # agent (windows/src/Service/AuditEventShipper.cs) writes and globs the
    # same shape. So mktemp creates the file under a trailing-X template and
    # we rename it into place.
    #
    # On the destination and symlinks, precisely: the rename(2) SYSCALL never
    # follows a symlink at the destination — it replaces the directory entry.
    # `mv(1)` is not the same thing and must not be assumed to inherit that.
    # Verified by hand on macOS 15 (BSD mv): with `link -> some-dir`,
    # `mv src link` moves src INSIDE some-dir as some-dir/src rather than
    # replacing the link — mv stat()s the destination first and treats a
    # symlink-to-directory as a directory. So a symlinked destination here
    # would be followed, not replaced.
    #
    # It is not reachable today: $EVENTS_QUEUE is 0755 root:wheel (see the
    # refusal comment below), so no unprivileged user can create an entry in
    # it at all, and the destination name is derived from mktemp's random
    # component and so is not predictable. Stated exactly rather than as
    # "rename does not follow symlinks", so nobody over-trusts this pattern if
    # it is ever copied into a genuinely writable directory.
    #
    # PAT-1079: the timestamp component was `date +%s%3N`. BSD/macOS date has
    # no %N, so it emitted the literal string "3N" after the epoch seconds —
    # the on-disk name carried "<epoch-seconds>3N", not milliseconds. The
    # contract (docs/audit-events-contract.md) and the Windows agent's
    # ToUnixTimeMilliseconds() both specify milliseconds, so compute them for
    # real. Uniqueness never depended on this (mktemp's random suffix supplies
    # that); the correctness of the timestamp did.
    local ev_ms; ev_ms=$("$PYTHON3" -c 'import time; print(int(time.time()*1000))' 2>/dev/null)
    # Fallback if that ever fails: seconds scaled to milliseconds. Still a
    # genuine millisecond value, just zeroed below the second.
    [[ -n "$ev_ms" ]] || ev_ms="$(date -u +%s)000"
    local ev_tmp; ev_tmp=$(mktemp "$EVENTS_QUEUE/evt-${ev_ms}-XXXXXX") || return 0
    local ev_file="${ev_tmp}.json"
    mv "$ev_tmp" "$ev_file" 2>/dev/null || { rm -f "$ev_tmp"; return 0; }

    # Enforce ring-buffer cap: drop oldest if over limit.
    local -a _existing
    _existing=("$EVENTS_QUEUE"/evt-*.json(N))
    if (( ${#_existing} >= EVENTS_QUEUE_MAX )); then
        rm -f "${_existing[1]}" || true
    fi

    # PAT-1079: refuse to write through a symlink at $ev_file.
    #
    # mktemp created the underlying file with O_CREAT|O_EXCL and the rename
    # above replaced (rather than followed) anything at the destination, so
    # nothing can be pre-planted at this now-random path. This covers the
    # narrower case of the entry being swapped for a symlink in the window
    # before the separate, later open() the Python block below performs by
    # path. Check-then-use is two syscalls and is not atomic: this narrows the
    # race, it does not eliminate it.
    #
    # $EVENTS_QUEUE is /var/db/patched/events-queue, 0755 root:wheel in
    # practice (created by the bare `mkdir -p` above under the daemon's
    # default 022 umask, with no chmod anywhere that loosens it), so no
    # unprivileged user can create anything in it at all. This guards the
    # pattern rather than a live hole — the same reasoning PAT-1043 recorded
    # for its sidecar state write. The check lives on the shell side, not in
    # the Python block, because that block's stderr is sent to /dev/null and
    # a silent refusal is worse than none.
    if [[ -L "$ev_file" ]]; then
        echo "WARN: audit event temp path is a symlink — refusing to write through it; event dropped"
        rm -f "$ev_file"
        return 0
    fi

    PATCHED_EV_TYPE="$ev_type" \
    PATCHED_EV_LABEL="$ev_label" \
    PATCHED_EV_VERSION="$ev_version" \
    PATCHED_EV_REASON="$ev_reason" \
    PATCHED_TENANT_ID="${TENANT_ID:-}" \
    PATCHED_HW_UUID="${HW_UUID:-}" \
    "$PYTHON3" -c '
import json, datetime, os, sys
g = lambda k: os.environ.get(k, "") or None
rec = {
    "event_type":  os.environ["PATCHED_EV_TYPE"],
    "tenant_id":   g("PATCHED_TENANT_ID"),
    "device_id":   g("PATCHED_HW_UUID"),
    "label":       g("PATCHED_EV_LABEL"),
    "version":     g("PATCHED_EV_VERSION"),
    "reason":      g("PATCHED_EV_REASON"),
    "platform":    "macos",
    "timestamp":   datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(sys.argv[1], "w") as f: json.dump(rec, f)
' "$ev_file" 2>/dev/null || { rm -f "$ev_file"; return 0; }

    # Attempt immediate delivery; queue stays on disk for drain if this fails.
    local ts; ts=$(date -u +%s)
    local nonce; nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    local sig; sig=$(compute_hmac "$ev_file" "events" "$ts" "$nonce")
    local code
    code=$(with_proxy "$API_URL" \
        patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time 15 \
        -X POST "$API_URL/v1/events" \
        -H "X-Patched-Signature: $sig" \
        -H "X-Patched-Timestamp: $ts" \
        -H "X-Patched-Nonce: $nonce" \
        -H "Content-Type: application/json" \
        --data-binary "@$ev_file" 2>/dev/null)
    if [[ "$code" == 2* ]]; then
        rm -f "$ev_file"
        echo "  audit event shipped: $ev_type/$ev_label"
    fi
    # If POST failed, the file stays in EVENTS_QUEUE for drain_events_queue.
}

drain_events_queue() {
    [[ -d "$EVENTS_QUEUE" ]] || return 0
    local -a files
    files=("$EVENTS_QUEUE"/evt-*.json(N))
    [[ ${#files} -gt 0 ]] || return 0

    local total=${#files[@]} drained=0 failed=0
    local f sig ts nonce code
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        ts=$(date -u +%s)
        nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
        sig=$(compute_hmac "$f" "events" "$ts" "$nonce")
        code=$(with_proxy "$API_URL" \
            patched_curl_bearer "$BEARER_TOKEN" -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST "$API_URL/v1/events" \
            -H "X-Patched-Signature: $sig" \
            -H "X-Patched-Timestamp: $ts" \
            -H "X-Patched-Nonce: $nonce" \
            -H "Content-Type: application/json" \
            --data-binary "@$f" 2>/dev/null)
        if [[ "$code" == 2* ]]; then
            rm -f "$f"
            (( drained++ )) || true
        else
            (( failed++ )) || true
        fi
    done
    echo "events queue drain: queued=$total drained=$drained failed=$failed"
}

# ---------------------------------------------------------------------------
# PAT-495: pinned SHA-256 for a label, once read from the signed app
# catalogue. Retired with the catalogue in PAT-2245; see below.
# ---------------------------------------------------------------------------
# Covered by endpoint/test-get-pinned-sha256.zsh (sentinel-extracted, not a
# copy).
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

# >>> PATCHED_GET_PINNED_CATALOGUE_METADATA_START
# PAT-1238 used this to read a paired version and hash when a blocked_versions
# policy is active. PAT-2245 retired the signed app catalogue: it never reads
# CATALOGUE_FILE and always returns 3 (no usable hash), which the caller
# treats as blocked_version_resolution_failed and refuses.
get_pinned_catalogue_metadata() {  # get_pinned_catalogue_metadata <label>
    echo "install refused: catalogue retired (PAT-2245): ${1:-}" >&2
    return 3
}
# <<< PATCHED_GET_PINNED_CATALOGUE_METADATA_END

# ---------------------------------------------------------------------------
# PAT-500: mirror manifest helpers — look up a label in the CDN mirror manifest
# published by the Phase 2 mirror pipeline.
#
# get_mirror_url <label>
#   stdout: CDN URL (${MIRROR_CDN_BASE}/<label>/<version>/<filename>), or empty
#   if the manifest is absent, unparseable, or has no entry for the label.
#   Fail-open: returns empty so the caller falls through to vendor download.
#
# get_mirror_pinned_sha256 <label>
#   stdout: pinned_sha256 hex from the CDN manifest entry, or empty if absent.
#
# verify_mirror_artifact <label> <artifact-path>
#   HARD FAIL function (not fail-open): if pinned_sha256 is present in the
#   manifest and the downloaded artifact does not match, returns 1 and emits a
#   PATCHED_VERIFICATION_FAILED log line. The caller must treat rc=1 as an abort.
#   If no pinned_sha256 is in the manifest (label not yet pinned), returns 0
#   so the direct-download path continues to work normally.
# ---------------------------------------------------------------------------

get_mirror_url() {  # get_mirror_url <label>
    local _lbl="$1"
    [[ -z "$MIRROR_CDN_BASE" ]] && return 0
    [[ -f "$MIRROR_MANIFEST_FILE" ]] || return 0
    "$PYTHON3" - "$MIRROR_MANIFEST_FILE" "$_lbl" <<'PYEOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
    for entry in doc.get("entries", []):
        if entry.get("label") == sys.argv[2]:
            print(entry.get("url") or "", end="")
            break
    else:
        print("", end="")
except Exception:
    print("", end="")
PYEOF
}

get_mirror_pinned_sha256() {  # get_mirror_pinned_sha256 <label>
    local _lbl="$1"
    [[ -z "$MIRROR_CDN_BASE" ]] && return 0
    [[ -f "$MIRROR_MANIFEST_FILE" ]] || return 0
    "$PYTHON3" - "$MIRROR_MANIFEST_FILE" "$_lbl" <<'PYEOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
    for entry in doc.get("entries", []):
        if entry.get("label") == sys.argv[2]:
            print(entry.get("sha256") or "", end="")
            break
    else:
        print("", end="")
except Exception:
    print("", end="")
PYEOF
}

# >>> PATCHED_MIRROR_SIGNED_CATALOGUE_GATE_START
# With an active blocked_versions policy, the local signature-verified
# catalogue is the sole authority for BOTH the refused candidate version and
# its bytes. A mirror remains only an optional transport: it may be selected
# only when its manifest repeats exactly that verified version and SHA-256.
# An absent, malformed, or divergent mirror entry is deliberately not an
# install failure: retaining the catalogue pin and using the vendor path is
# safer and keeps the kill switch operable during mirror lag.
# stdout: matching mirror URL. exit 0 only for an exact match; exit 1 otherwise.
mirror_url_matching_signed_catalogue() {  # <label> <catalogue-sha256> <catalogue-version>
    local _lbl="$1" _catalogue_sha="$2" _catalogue_ver="$3"
    [[ -n "$MIRROR_CDN_BASE" && -f "$MIRROR_MANIFEST_FILE" ]] || return 1

    local _metadata
    _metadata=$("$PYTHON3" - "$MIRROR_MANIFEST_FILE" "$_lbl" <<'PYEOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
    for entry in doc.get("entries", []):
        if entry.get("label") != sys.argv[2]:
            continue
        url, sha, version = entry.get("url"), entry.get("sha256"), entry.get("version")
        if all(isinstance(v, str) and v and not any(c.isspace() for c in v)
               for v in (url, sha, version)):
            print(f"{url}\t{sha}\t{version}", end="")
        break
except Exception:
    pass
PYEOF
)
    local _mirror_url _mirror_sha _mirror_ver
    IFS=$'\t' read -r _mirror_url _mirror_sha _mirror_ver <<< "$_metadata"
    [[ -n "$_mirror_url" && "$_mirror_sha" == "$_catalogue_sha" && "$_mirror_ver" == "$_catalogue_ver" ]] || return 1
    printf '%s' "$_mirror_url"
}
# <<< PATCHED_MIRROR_SIGNED_CATALOGUE_GATE_END

verify_mirror_artifact() {  # verify_mirror_artifact <label> <artifact-path>
    # HARD FAIL when pinned_sha256 is present and mismatches.
    # Returns 0 if: no pinned hash in manifest (label not yet pinned), or hash matches.
    # Returns 1 if: hash is present AND does not match — caller must ABORT the install.
    local _lbl="$1" _path="$2"
    local _expected
    _expected=$(get_mirror_pinned_sha256 "$_lbl")
    [[ -z "$_expected" ]] && return 0   # no pinned hash in manifest — pass through
    [[ -f "$_path" ]] || { echo "  verify_mirror_artifact: artifact not found: $_path"; return 1; }
    local _got
    _got=$(shasum -a 256 "$_path" 2>/dev/null | awk '{print $1}')
    if [[ "$_got" == "$_expected" ]]; then
        echo "  mirror pinned_sha256 verified OK: $_lbl ($_got)"
        return 0
    else
        echo "PATCHED_VERIFICATION_FAILED label=$_lbl reason=mirror_pinned_sha256_mismatch expected=${_expected} observed=${_got:-<empty>}"
        emit_audit_event "verification_failed" "$_lbl" "" "mirror_pinned_sha256_mismatch"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# RUN ONE LABEL
# ---------------------------------------------------------------------------
# Allowlist row format (tab-separated; see labels-allowlist.txt):
#   label <TAB> App Name <TAB> expectedTeamID <TAB> /Applications/App.app <TAB> url_method
#
# Installomator itself performs the Team ID + notarization verification; this
# wrapper records the result. STATE_RESULT / OUT_VERSION are returned via
# globals so the caller can assemble the status JSON without a subshell.

run_label() {  # run_label <label> <name> <expectedTeamID> <appPath> <mode:scan|install> [policy_source] [policy_disabled] [ring_gated]
    local label="$1" name="$2" expected_tid="$3" app_path="$4" mode="$5"
    local policy_source_in="${6:-}" policy_disabled="${7:-0}" ring_gated="${8:-0}"
    local before after rc outcome state failure_reason available_ver verified_signer message
    local pv_line pv_url pv_obs_tid pv_notarization pv_reason
    # PAT-296: deferral flag, reserved exclusively for blocking-process state.
    local _deferred=0
    # PAT-1481: an install request that loses execution authority remains an
    # install-mode audit event. It must never be rewritten as a successful
    # read-only scan or overloaded onto blocking-process deferral state.
    local _execution_authority_refused=0

    # This is the last mode decision before the legacy engine path. Re-check
    # for every label so a current refresh can revoke a long-running pass.
    if [[ "$mode" == "install" ]] && ! legacy_app_execution_enabled; then
        echo "Legacy app-execution authority refused install for $label"
        log_jsonl "warn" "legacy app-execution authority refused install" \
            "{\"label\":\"$label\",\"mode\":\"install\"}"
        _execution_authority_refused=1
    fi

    # PAT-383: a policy skip suppresses the engine run (an install) the same way
    # scan mode does — no download, no install — but is reported as skipped_policy.
    local policy_skip=0
    [[ "$policy_disabled" == "1" && "$mode" == "install" ]] && policy_skip=1
    # PAT-506: a ring gate similarly suppresses the install — version not yet approved
    # for this device's deployment ring; reported as ring_gated in provenance.
    local ring_skip=0
    [[ "$ring_gated" == "1" && "$mode" == "install" ]] && ring_skip=1
    # PAT-296: FAIL CLOSED — when no valid signed blocking-process policy was loaded
    # (absent/unparseable/malformed config, unknown action, or malformed
    # max_deferrals), BPP_ACTION_ON_TIMEOUT is empty. Refuse the update ENTIRELY:
    # suppress the install the same way a policy skip does — no download, no install,
    # even when the app is not running. Only a valid signed policy (which the
    # platform now always delivers, defaulting to notify_only) lets an install
    # proceed. Reported as fail_closed_policy in provenance.
    local bpp_failclosed=0
    [[ -z "$BPP_ACTION_ON_TIMEOUT" && "$mode" == "install" ]] && bpp_failclosed=1

    # PAT-1028 round 3, P0: read the pinned hash (and its shape-error signal)
    # up front, before the scan/install branch, so a malformed catalogue
    # entry for THIS label can suppress the download the same way a policy
    # skip does. Mirrors bpp_failclosed immediately above. get_pinned_sha256
    # returns exit 2 for a SHAPE ERROR (catalogue, "labels", or this label's
    # own entry is not even shaped like a catalogue) and, since round 5,
    # exit 3 for NO_PIN (this label has no usable pin right now: absent,
    # null, or malformed sha256 all refuse identically, per the round-5
    # P0(b) investigation that closed PAT-495's original fail-open). Scan
    # mode never downloads anything, so the pin is meaningless there. Only
    # call out to python when mode is install, same performance
    # characteristics as before round 3 (which only ever read it inside the
    # install branch).
    local _pinned_sha256="" _pinned_rc=0
    local catalogue_shape_failclosed=0
    local catalogue_unverified_failclosed=0
    local blocked_version_refused=0
    local blocked_version_preflight_failed=0
    local blocked_version_policy_active=0
    if [[ "$mode" == "install" ]]; then
        local _bv_policy_state _catalogue_metadata
        _bv_policy_state=$(blocked_version_policy_state "$label")
        if [[ "$_bv_policy_state" == "preflight_required" ]]; then
            blocked_version_policy_active=1
            # One local, signature-verified catalogue read gives us the exact
            # version AND SHA-256 for the same artifact. Never ask the vendor
            # for a version here: it could drift after verification and create
            # a version/hash TOCTOU before the engine has a chance to pin it.
            _catalogue_metadata=$(get_pinned_catalogue_metadata "$label"); _pinned_rc=$?
            if [[ $_pinned_rc -eq 0 ]]; then
                IFS=$'\t' read -r _pinned_sha256 available_ver <<< "$_catalogue_metadata"
                _bv_policy_state=$(blocked_version_policy_state "$label" "$available_ver")
                if [[ "$_bv_policy_state" == "blocked" ]]; then
                    blocked_version_refused=1
                    echo "PATCHED_VERIFICATION_FAILED label=$label version=$available_ver reason=blocked_version"
                elif [[ "$_bv_policy_state" != "allowed" ]]; then
                    blocked_version_preflight_failed=1
                    echo "PATCHED_VERIFICATION_FAILED label=$label reason=blocked_version_resolution_failed"
                fi
            elif [[ $_pinned_rc -eq 2 || $_pinned_rc -eq 3 || $_pinned_rc -eq 4 ]]; then
                # A malformed entry, missing pin, or missing version means an
                # active kill switch cannot decide safely. Keep this distinct
                # from the generic catalogue state so durable audit evidence
                # identifies the blocked-version decision boundary that failed.
                blocked_version_preflight_failed=1
                echo "PATCHED_VERIFICATION_FAILED label=$label reason=blocked_version_resolution_failed"
            fi
        else
            _pinned_sha256=$(get_pinned_sha256 "$label"); _pinned_rc=$?
            if [[ "$_bv_policy_state" != "no_policy" ]]; then
                blocked_version_preflight_failed=1
                echo "PATCHED_VERIFICATION_FAILED label=$label reason=blocked_version_resolution_failed"
            fi
        fi
        [[ $_pinned_rc -eq 2 ]] && catalogue_shape_failclosed=1
        if [[ $_pinned_rc -eq 3 ]]; then
            catalogue_unverified_failclosed=1
            # PAT-1028 round 5: honest, actionable, and specific. Never a
            # raw error, never implying anything is broken when the far
            # more common case is simply "not reached yet". A newly
            # onboarded label is uninstallable until its first successful
            # verify run, which is the known, expected consequence stated
            # here so it is visible from the log alone.
            echo "  $label: install refused: catalogue retired (PAT-2245). The signed app catalogue no longer exists, so no app has a verified hash and this legacy install path refuses every install."
        fi
    fi

    before=$(/usr/bin/defaults read "${app_path}/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "")

    if [[ "$mode" == "scan" || "$_execution_authority_refused" == 1 || "$policy_skip" == 1 || "$ring_skip" == 1 || "$bpp_failclosed" == 1 || "$blocked_version_refused" == 1 || "$blocked_version_preflight_failed" == 1 || "$catalogue_shape_failclosed" == 1 || "$catalogue_unverified_failclosed" == 1 ]]; then
        # Scan mode: determine installed version only; do NOT download any artifact.
        # The engine has no clean no-download version-resolution path for all labels;
        # a future versiononly capability will enable lightweight version polling
        # without a full download. For now, report available_version: null and state
        # unknown. Verification failures (60/61/62) surface only at deploy time.
        rc=0
        after="$before"
        [[ -n "$available_ver" ]] || available_ver=""
        pv_url="" pv_obs_tid="" pv_notarization="" pv_reason=""
    else
        # Install mode: run engine with fail-closed verification.
        # LOGGING=INFO captures version lines (INFO) and PATCHED_VERIFICATION_FAILED
        # (ERROR). stdin is /dev/null: runs inside a `while read` loop over allowlist.
        local eng_log; eng_log=$(mktemp /tmp/.patched-eng.XXXXXX)

        # PAT-296: blocking-process policy — honour the tenant-configured action
        # rather than the previous hardcoded BLOCKING_PROCESS_ACTION=kill.
        #
        # action_on_timeout -> Installomator BLOCKING_PROCESS_ACTION (via
        # bpp_map_action; see that function for the full Installomator semantics):
        #   prompt_then_quit -> silent_fail while deferrable, then prompt_user once
        #                       deferrals are exhausted (bpp_should_escalate): the
        #                       final consent-quit ask — quit ONLY on explicit "Quit
        #                       and Update", abort on decline/timeout. NEVER
        #                       force-quits/kills. This is the ONLY quit-capable path,
        #                       and exactly the GitHub-Non-Author-Review carve-out scope (PAT-296).
        #   notify_only      -> silent_fail   (GitHub-Non-Author-Review criteria: notify_only must
        #                       NEVER quit, so it does not present a quit-capable
        #                       prompt; the install is skipped while the app runs and
        #                       proceeds normally when it is not — a valid tenant
        #                       choice.)
        #   skip_run         -> silent_fail   (skip the install while the app runs;
        #                       proceed when it is not.)
        # We only reach here with a VALID policy: the fail-closed case (empty
        # BPP_ACTION_ON_TIMEOUT — absent/unparseable/malformed config, unknown action,
        # or malformed max_deferrals) was already hard-refused above (bpp_failclosed:
        # no engine, no install at all, even when the app is not running). The empty
        # -> silent_fail branch in bpp_map_action is belt-and-braces only.
        local _bpp_action="$BPP_ACTION_ON_TIMEOUT"

        # Deferral gate. Controls from the signed policy:
        #   * max_deferrals — how many times prompt_then_quit defers (via silent
        #     skips) before escalating to the final user-confirmation quit. ONLY
        #     prompt_then_quit escalates (bpp_should_escalate); notify_only and
        #     skip_run never escalate (always silent_fail).
        #   * defer_window_seconds — while inside the window promised at the last
        #     deferral, skip this run silently so we do not re-nag every poll cycle.
        # Once prompt_then_quit is exhausted we STOP honouring silent within-window
        # skips: the final consent-quit prompt is shown on every run until the user
        # confirms the quit ("Quit and Update") or the app closes on its own.
        # Declining/timing out at the final prompt aborts the run WITHOUT quitting.
        local _def_count; _def_count=$(bpp_deferral_count "$label")
        local _escalate; _escalate=$(bpp_should_escalate "$_bpp_action" "$_def_count")
        if [[ "$_escalate" == "1" ]]; then
            # prompt_then_quit, deferrals exhausted — present the final ask now;
            # do NOT silent-skip even if a defer window is nominally still open.
            echo "  $label: deferrals exhausted (count=$_def_count max=$BPP_MAX_DEFERRALS) — final quit confirmation"
        elif ! bpp_defer_window_elapsed "$label"; then
            # Inside the promised defer window (soft/deferrable state) — skip
            # silently; the deferral was already recorded when it was made.
            echo "  $label: within deferral window (count=$_def_count max=$BPP_MAX_DEFERRALS) — skipping run"
            _deferred=1
        fi
        # else: window elapsed, deferrals remain — run the engine and re-prompt.

        # Map the policy action (+ escalation) to an Installomator
        # BLOCKING_PROCESS_ACTION. The ONLY quit-capable result is prompt_then_quit
        # once escalated (_escalate=1); every other case — notify_only, skip_run,
        # prompt_then_quit while still deferrable, and any empty/unknown/malformed
        # policy — maps to silent_fail and NEVER quits/kills.
        local _bpa; _bpa=$(bpp_map_action "$_bpp_action" "$_escalate")

        # Tenant (or agent-default) prompt copy, sanitised so it can never break
        # out of the engine's osascript dialog string. When escalated and no tenant
        # message is set, use the urgent final-notice copy. Passed to the engine as
        # an ENVIRONMENT variable, NOT a key=value argument — the engine re-evaluates
        # its allowlisted args with `eval`, which would word-split/execute free
        # text; the environment path is assigned literally and is injection-safe.
        local _bpp_msg; _bpp_msg=$(bpp_effective_message "$_escalate")

        # PAT-495: pinned hash was already read above (before the scan/install
        # branch, alongside catalogue_shape_failclosed). $_pinned_sha256 is
        # already in scope here. Nothing to do in this branch any more.

        # PAT-500: check for a mirror entry. If MIRROR_CDN_BASE is set and the
        # CDN manifest has an entry for this label, override the download URL so
        # Installomator fetches the Patched-published artifact instead of the
        # vendor URL. The CDN URL format is:
        #   ${MIRROR_CDN_BASE}/<label>/<version>/<label>-<version>.<ext>
        # After download, verify_mirror_artifact() checks SHA-256 against the
        # pinned_sha256 in the manifest — this is a HARD FAIL (not fail-open):
        # a mismatch aborts the install and emits a PATCHED_VERIFICATION_FAILED
        # log line so the SIEM picks it up. If MIRROR_CDN_BASE is empty or the
        # manifest has no entry for this label, the direct vendor download proceeds
        # normally.
        local _mirror_url="" _mirror_sha256=""
        if (( blocked_version_policy_active )); then
            # PAT-1238 P0: never let a stale or divergent mirror replace the
            # exact signed version/hash pair used for the preflight decision.
            _mirror_url=$(mirror_url_matching_signed_catalogue "$label" "$_pinned_sha256" "$available_ver") || _mirror_url=""
            if [[ -n "$_mirror_url" ]]; then
                _mirror_sha256="$_pinned_sha256"
                echo "  mirror: signed-catalogue-matched artifact available for $label -> $_mirror_url"
            elif [[ -n "$MIRROR_CDN_BASE" || -n "${LABEL_MIRROR_URL:-}" ]]; then
                echo "  mirror: bypassed for $label because its version/SHA-256 does not exactly match the signed catalogue; using the signed catalogue pin with the vendor path"
            fi
        else
            _mirror_url=$(get_mirror_url "$label") || _mirror_url=""
            # PAT-647: fall back to mirror_url baked into the allowlist by the mirror
            # pipeline pin step, so endpoints work even when MIRROR_CDN_BASE is not set.
            [[ -z "$_mirror_url" && -n "${LABEL_MIRROR_URL:-}" ]] && _mirror_url="$LABEL_MIRROR_URL"
            if [[ -n "$_mirror_url" ]]; then
                _mirror_sha256=$(get_mirror_pinned_sha256 "$label") || _mirror_sha256=""
                [[ -z "$_mirror_sha256" && -n "${LABEL_PINNED_SHA256:-}" ]] && _mirror_sha256="$LABEL_PINNED_SHA256"
                echo "  mirror: CDN artifact available for $label -> $_mirror_url"
                # Outside an active kill switch, mirror pipeline metadata remains
                # the normal source of the mirror artifact pin.
                [[ -n "$_mirror_sha256" ]] && _pinned_sha256="$_mirror_sha256"
            fi
        fi

        # The final executable seam is below. A scan can take long enough for
        # the current config heartbeat to become stale or for a 401 suspension
        # to land after run_label selected install mode, so check once more
        # immediately before that engine branch.
        if [[ "$mode" == "install" ]] && ! legacy_app_execution_enabled; then
            echo "Legacy app-execution authority refused immediately before Installomator — skipping $label"
            log_jsonl "warn" "legacy app-execution authority refused Installomator" \
                "{\"label\":\"$label\",\"mode\":\"install\"}"
            _execution_authority_refused=1
        fi

        if (( _deferred || _execution_authority_refused )); then
            # No engine invocation. The mapping below keeps authority refusal
            # terminal and auditable, distinct from retryable process deferral.
            rc=0
            after="$before"
            available_ver=""
            pv_url="" pv_obs_tid="" pv_notarization="" pv_reason=""
            rm -f "${eng_log:-}"
        else
            # PAT-500: When MIRROR_CDN_BASE is configured and the manifest has an
            # entry for this label, pass OVERRIDE_DOWNLOAD_URL to the engine so it
            # fetches the Patched-published artifact from the CDN. The engine then
            # re-checks PINNED_SHA256 against the downloaded artifact's SHA-256.
            #
            # After the engine returns, verify_mirror_artifact() runs a second
            # independent SHA-256 check against the manifest's pinned hash. This
            # catches any case where the engine skipped its internal check.
            # A mismatch aborts the install (rc forced to 62 = signer_mismatch).
            # PAT-296: BLOCKING_PROCESS_MESSAGE is exported (not passed as an arg)
            # so it survives the engine's `eval`-based arg re-read; it is inherited
            # by the engine and consumed by checkRunningProcesses. PROMPT_TIMEOUT is
            # a pure integer (clamped 30..86400) and is safe as an allowlisted arg;
            # it bounds the prompt_user dialog (Installomator defaults to 86400s).
            export BLOCKING_PROCESS_MESSAGE="$_bpp_msg"
            with_proxy "${_mirror_url:-https://api.github.com}" \
                "$INSTALLOMATOR" "$label" "NOTIFY=silent" "BLOCKING_PROCESS_ACTION=${_bpa}" \
                "PROMPT_TIMEOUT=${BPP_TIMEOUT_SECONDS}" \
                "LOGGING=INFO" ${_pinned_sha256:+"PINNED_SHA256=${_pinned_sha256}"} \
                ${_mirror_url:+"OVERRIDE_DOWNLOAD_URL=${_mirror_url}"} >"$eng_log" 2>&1 </dev/null
            rc=$?
            unset BLOCKING_PROCESS_MESSAGE

            # PAT-500: post-download SHA-256 verification for mirror artifacts.
            # Only runs when (a) we used a mirror URL and (b) the engine log
            # indicates it successfully downloaded the artifact (rc=0 or install
            # path). The engine keeps the artifact on disk during install; we
            # locate it from the log to verify.  This is a belt-and-suspenders
            # check — hard fail on mismatch (rc forced to 62).
            if [[ -n "$_mirror_url" && $rc -eq 0 && -n "$_mirror_sha256" ]]; then
                local _eng_artifact
                _eng_artifact=$(grep -oE '/tmp/[^ ]+\.(dmg|pkg|zip|tbz)' "$eng_log" 2>/dev/null | head -1)
                if [[ -n "$_eng_artifact" && -f "$_eng_artifact" ]]; then
                    if ! verify_mirror_artifact "$label" "$_eng_artifact"; then
                        echo "FATAL: mirror pinned_sha256 mismatch for $label — aborting install (rc forced to 62)"
                        rc=62
                    fi
                else
                    # Artifact not on disk (already installed and cleaned up by engine) —
                    # the engine's own PINNED_SHA256 check already ran; trust it.
                    echo "  mirror: artifact not on disk for post-install verify (engine cleaned up) — trusting engine PINNED_SHA256 check"
                fi
            fi

            after=$(/usr/bin/defaults read "${app_path}/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "")

            # Parse appNewVersion from engine log.
            available_ver=$(grep -oE 'Latest version of .+ is [^[:space:]]+' "$eng_log" 2>/dev/null \
                | head -1 | grep -oE '[^[:space:]]+$')
            if [[ -z "$available_ver" ]]; then
                available_ver=$(grep -oE 'Downloaded version of .+ is [^[:space:]]+ on' "$eng_log" 2>/dev/null \
                    | head -1 | awk '{print $(NF-1)}')
            fi
            if [[ -z "$available_ver" ]]; then
                available_ver=$(grep -oE 'Downloaded package .+ version [^[:space:]]+' "$eng_log" 2>/dev/null \
                    | head -1 | awk '{print $NF}')
            fi

            # Parse §4.6 fields from the PATCHED_VERIFICATION_FAILED log line emitted by
            # the fork on exit 60/61/62. These come from the engine's view of the rejected
            # artifact — NOT from codesign on the installed app (which would mislead: the
            # install was refused, so the on-disk app is the prior valid one).
            pv_line=$(grep 'PATCHED_VERIFICATION_FAILED' "$eng_log" 2>/dev/null | tail -1)
            pv_url=$(         echo "$pv_line" | grep -oE 'url=[^[:space:]]*'                 | head -1 | cut -d= -f2-)
            pv_obs_tid=$(     echo "$pv_line" | grep -oE 'observedTeamID=[^[:space:]]*'      | head -1 | cut -d= -f2-)
            pv_notarization=$(echo "$pv_line" | grep -oE 'notarizationResult=[^[:space:]]*'  | head -1 | cut -d= -f2-)
            pv_reason=$(      echo "$pv_line" | grep -oE 'reason=[^[:space:]]*'              | head -1 | cut -d= -f2-)
            # eng_log is kept alive until after the case block so failure_reason
            # extraction can read it for non-60/61/62 exit codes.

            # PAT-296: the engine aborted because the app is a blocking process.
            # rc12 = silent_fail (notify_only, skip_run, prompt_then_quit while
            # deferrable, or the fail-closed default); rc10/rc25/rc11 = the escalated
            # prompt_then_quit prompt (user declined / timed out / could not quit).
            # Record a deferral and report the run as deferred rather than a hard
            # error, so the next cycle re-skips or escalates per policy.
            #
            # Recording policy differs by action so the escalation is well-defined:
            #   * prompt_then_quit — cap recording at max_deferrals. Each deferrable
            #     (silent_fail) run advances the count; once it reaches the cap the
            #     count STOPS advancing (frozen timestamp), so bpp_should_escalate
            #     stays true and the final consent-quit prompt re-appears every run
            #     until resolved.
            #   * notify_only / skip_run / fail-closed — keep recording (refreshing
            #     the window) so they never escalate: they simply keep refusing while
            #     the app runs. None ever quits/kills.
            case $rc in
                10|11|12|25)
                    if [[ "$_bpp_action" == "prompt_then_quit" ]]; then
                        (( _def_count < BPP_MAX_DEFERRALS )) && bpp_record_deferral "$label"
                    else
                        bpp_record_deferral "$label"
                    fi
                    _deferred=1
                    ;;
            esac
        fi
    fi

    # Map exit codes to outcome/state.
    # Neutral failure_reason vocabulary (Windows parity — macOS maps 60/61/62 onto
    # these; Windows will map Authenticode failures onto the same three values).
    failure_reason="" verified_signer="" message=""
    if (( _execution_authority_refused )); then
        outcome="authority_refused"; state="error"
        failure_reason="execution_authority_refused"
        message="Install refused: this endpoint does not currently hold fresh signed execution authority."
    elif (( policy_skip )); then
        # PAT-383: the engine never ran. Report the true installed state (we can't
        # know availability without a download, hence unknown) and mark the action
        # skipped_policy — recorded in provenance; the tray row maps it to null.
        outcome="skipped_policy"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    elif (( ring_skip )); then
        # PAT-506: version not yet approved for this device's deployment ring.
        # Engine never ran; report installed state only, mark ring_gated in provenance.
        outcome="ring_gated"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    elif (( bpp_failclosed )); then
        # PAT-296: no valid signed blocking-process policy — fail closed. The engine
        # never ran and NOTHING was installed. Report installed state only.
        outcome="fail_closed_policy"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    elif (( blocked_version_refused )); then
        # PAT-1238: the signed catalogue's latest_verified_version matched this
        # label's signed blocked_versions entry. The engine never ran.
        outcome="version_blocked"; state="verification_failed"
        failure_reason="blocked_version"
    elif (( blocked_version_preflight_failed )); then
        # A block applies, but its paired catalogue version was unavailable or
        # malformed. Refuse rather than create a kill-switch bypass.
        outcome="verification_failed"; state="verification_failed"
        failure_reason="blocked_version_resolution_failed"
    elif (( catalogue_shape_failclosed )); then
        # PAT-1028 round 3, P0: get_pinned_sha256 returned a SHAPE ERROR for
        # this label (the catalogue/labels/entry itself is not even shaped
        # like a catalogue). The engine never ran and NOTHING was
        # installed. Report installed state only.
        outcome="fail_closed_catalogue"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    elif (( catalogue_unverified_failclosed )); then
        # PAT-1028 round 5: get_pinned_sha256 returned NO_PIN for this
        # label (absent, null, or malformed sha256 all reach here
        # identically). The engine never ran and NOTHING was installed.
        # This is the actual privileged refusal that closes PAT-495's
        # original fail-open, not just an honest UI affordance.
        outcome="fail_closed_unverified"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    elif [[ "${_deferred:-0}" == "1" ]]; then
        # PAT-296: within deferral window — report current installed state, skip update.
        outcome="deferred_blocking_process"
        if [[ -d "$app_path" ]]; then state="unknown"; else state="not_installed"; fi
    else
    case $rc in
        60) outcome="verification_failed"; state="verification_failed"
            failure_reason="missing_expected_signer" ;;
        61) outcome="verification_failed"; state="verification_failed"
            failure_reason="signature_untrusted" ;;
        62) outcome="verification_failed"; state="verification_failed"
            failure_reason="signer_mismatch" ;;
        # rc=23: engine refuses because app was previously installed via App Store;
        # this is an operational refusal, not a verification failure.
        23) outcome="error"; state="error"
            failure_reason="app_store_managed" ;;
        0)
            if [[ ! -d "$app_path" ]]; then
                outcome="not_installed"; state="not_installed"
                failure_reason="installed_path_not_found"
            elif [[ "$mode" == "scan" ]]; then
                # Can't determine available_version without a download; report unknown.
                outcome="already_current"; state="unknown"
                verified_signer="$expected_tid"
            elif [[ -n "$before" && -n "$after" && "$before" != "$after" ]]; then
                outcome="installed"; state="up_to_date"
                verified_signer="$expected_tid"
                # PAT-296: successful install — reset deferral count for this label.
                bpp_reset_deferrals "$label"
            else
                outcome="already_current"; state="up_to_date"
                verified_signer="$expected_tid"
            fi
            ;;
        *)  outcome="error"; state="error"
            local _eng_err
            _eng_err=$(grep -iE '(error|failed|fail)[[:space:]]' "${eng_log:-/dev/null}" 2>/dev/null \
                | tail -3 | tr '\n' ' ' | cut -c1-200)
            failure_reason="${_eng_err:-engine_rc_${rc}}"
            ;;
    esac

    fi
    # Delete eng_log after the case block so failure_reason extraction above can read it.
    rm -f "${eng_log:-}"

    # Provenance record (§4.6) — install mode only; scan mode performs no verification.
    # All dynamic values marshalled via env, not string interpolation, to prevent
    # injection from log-parsed fields (pv_url etc.) breaking the JSON or Python.
    if [[ "$mode" == "install" ]]; then
        local prov; prov=$(mktemp /tmp/.patched-prov.XXXXXX)
        PATCHED_TENANT_ID="$TENANT_ID" \
        PATCHED_HW_UUID="$HW_UUID" \
        PATCHED_COMPUTER_NAME="$COMPUTER_NAME" \
        PATCHED_INSTALLOMATOR_TAG="$INSTALLOMATOR_TAG" \
        PATCHED_LABEL="$label" \
        PATCHED_NAME="$name" \
        PATCHED_BEFORE="$before" \
        PATCHED_AFTER="$after" \
        PATCHED_AVAIL_VER="$available_ver" \
        PATCHED_EXPECTED_TID="$expected_tid" \
        PATCHED_OUTCOME="$outcome" \
        PATCHED_FAILURE_REASON="$failure_reason" \
        PATCHED_MODE="$mode" \
        PATCHED_RC="$rc" \
        PATCHED_PV_URL="$pv_url" \
        PATCHED_PV_OBS_TID="$pv_obs_tid" \
        PATCHED_PV_NOTARIZATION="$pv_notarization" \
        PATCHED_PV_REASON="$pv_reason" \
        PATCHED_BREW_COEX_TMP="${BREW_COEX_TMP:-}" \
        PATCHED_POLICY_SOURCE="$policy_source_in" \
        PATCHED_POLICY_DISABLED="$policy_disabled" \
        "$PYTHON3" - "$prov" <<'PYEOF'
import json, datetime, os, sys
g = lambda k: os.environ.get(k, '')
is_vf = g('PATCHED_OUTCOME') == 'verification_failed'
brew_file = g('PATCHED_BREW_COEX_TMP')
also_managed_by = None
if brew_file and os.path.exists(brew_file):
    try:
        also_managed_by = json.load(open(brew_file)).get(
            'by_label', {}).get(g('PATCHED_LABEL'), {}).get('also_managed_by')
    except Exception:
        pass
rec = {
  'record_type': 'third_party_update',
  'schema_version': 1,
  'tenant_id': g('PATCHED_TENANT_ID'),
  'device': {'hw_uuid': g('PATCHED_HW_UUID'), 'computer_name': g('PATCHED_COMPUTER_NAME')},
  'installomator_tag': g('PATCHED_INSTALLOMATOR_TAG'),
  'app': {
    'label': g('PATCHED_LABEL'),
    'name': g('PATCHED_NAME'),
    'version_before': g('PATCHED_BEFORE') or None,
    'version_after': g('PATCHED_AFTER') or None,
    'available_version': g('PATCHED_AVAIL_VER') or None,
    'also_managed_by': also_managed_by,
  },
  'verification': {
    'expected_team_id': g('PATCHED_EXPECTED_TID') or None,
    'observed_team_id': g('PATCHED_PV_OBS_TID') if is_vf else None,
    'notarization_result': g('PATCHED_PV_NOTARIZATION') if is_vf else None,
    'source_url': g('PATCHED_PV_URL') if is_vf else None,
    'reason': g('PATCHED_PV_REASON') if is_vf else None,
  },
  'outcome': g('PATCHED_OUTCOME'),
  'failure_reason': g('PATCHED_FAILURE_REASON') or None,
  'installomator_exit': int(g('PATCHED_RC') or 0),
  'run_mode': g('PATCHED_MODE'),
  # PAT-383: per-tenant app-update policy decision (null when no policy applied).
  # 'enabled' is the resolved toggle; outcome == 'skipped_policy' when an install
  # was suppressed. Mirrors the Windows path's PolicySource/PolicyDisabled.
  'policy': ({
    'source':  g('PATCHED_POLICY_SOURCE'),
    'enabled': g('PATCHED_POLICY_DISABLED') != '1',
  } if g('PATCHED_POLICY_SOURCE') else None),
  'recorded_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
}
with open(sys.argv[1], 'w') as f: json.dump(rec, f)
PYEOF
        emit_provenance "$prov"
        rm -f "$prov"

        # PAT-499: ship a structured audit event to /v1/events for SIEM.
        local _ev_type
        case "$outcome" in
            installed)            _ev_type="install_completed" ;;
            already_current)      _ev_type="verification_passed" ;;
            verification_failed)  _ev_type="verification_failed" ;;
            version_blocked)      _ev_type="version_blocked" ;;
            authority_refused)    _ev_type="install_failed" ;;
            error)                _ev_type="install_failed" ;;
            *)                    _ev_type="" ;;
        esac
        if [[ -n "$_ev_type" ]]; then
            # A preflight refusal has no installed version transition. Preserve the
            # refused, catalogue-verified candidate in the security event.
            local _ev_version="${after:-$before}"
            [[ "$outcome" == "version_blocked" && -n "$available_ver" ]] && _ev_version="$available_ver"
            emit_audit_event "$_ev_type" "$label" "$_ev_version" "$failure_reason"
        fi
    fi

    typeset -g STATE_RESULT="$state"
    typeset -g OUT_VERSION_BEFORE="$before"
    typeset -g OUT_VERSION_AFTER="$after"
    typeset -g OUT_AVAILABLE_VERSION="$available_ver"
    typeset -g OUT_OUTCOME="$outcome"
    typeset -g OUT_FAILURE_REASON="$failure_reason"
    typeset -g OUT_VERIFIED_SIGNER="$verified_signer"
    typeset -g OUT_MESSAGE="$message"
    echo "  $label ($name): $outcome  rc=$rc  ${before:-?} -> ${after:-?}  avail=${available_ver:-?}"
    log_jsonl "info" "label processed" \
        "{\"label\":\"$label\",\"mode\":\"$mode\",\"outcome\":\"$outcome\",\"rc\":\"$rc\",\"before\":\"${before:-}\",\"after\":\"${after:-}\"}"
}

# ---------------------------------------------------------------------------
# GATEKEEPER PREFLIGHT (PAT-498)
# Soft warning — non-blocking. Gatekeeper disabled is legitimate on some MDM
# configs; the Team ID gate in Installomator (exit 62) remains the hard
# security invariant. This surfaces a posture signal for audit logs and the
# Self Service UI posture score.
# ---------------------------------------------------------------------------

if /usr/sbin/spctl --status 2>/dev/null | grep -q "disabled"; then
    echo "PATCHED_POSTURE_WARNING reason=gatekeeper_disabled hw_uuid=${HW_UUID:-unknown}"
fi

# ---------------------------------------------------------------------------
# 2. DETERMINE LABEL SET — trigger file (self-service) or full allowlist
# ---------------------------------------------------------------------------

RUN_MODE="scan"          # scan = scheduled refresh; install = act on updates
TRIGGER_LABELS=""        # space-separated; empty = whole allowlist
typeset -a TRIGGER_IDENTIFIERS=() # exact bounded identifiers for child handoff
RUN_TRIGGER="scheduled"
DEPLOY_REQUESTED=0       # set only after a consumed deploy trigger is parsed

# >>> PATCHED_UNINSTALL_TRIGGER_REFUSAL_START
# record_uninstall_trigger_authority_refusal <trigger-file> [remaining identifiers...]
#
# A refused uninstall trigger is consumed before the removal engine can resolve
# tenant allowlist rows. entry_id 0 is therefore the documented sentinel for a
# requested identifier with no resolved tenant allowlist entry. This helper is
# deliberately reporting-only: every failure is logged and leaves the refusal
# in place; it never invokes the removal engine or any other executor.
record_uninstall_trigger_authority_refusal() {
    local refusal_trigger_file="$1" refusal_started_at refusal_status_file
    local refusal_provenance_dir refusal_provenance
    shift
    # A trigger is local-user writable. Bound its reporting path as well as
    # refusing execution, so one trigger cannot hold the daemon with an
    # unbounded status document or provenance POST/queue workload.
    local -i refusal_max_trigger_bytes=65536
    local -i refusal_max_examined_elements=128
    local -i refusal_max_identifiers=32
    local -i refusal_max_identifier_characters=256
    local -i refusal_max_identifier_utf8_bytes=256
    refusal_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    refusal_status_file="$STATE_DIR/uninstall-status.json"
    refusal_provenance_dir=$(mktemp -d /tmp/.patched-uninstall-refusal-prov.XXXXXX) || {
        echo "WARN: could not create provenance records for refused uninstall trigger"
        return 0
    }

    if ! PATCHED_REFUSAL_STATUS_FILE="$refusal_status_file" \
        PATCHED_REFUSAL_STARTED_AT="$refusal_started_at" \
        PATCHED_REFUSAL_PROVENANCE_DIR="$refusal_provenance_dir" \
        PATCHED_REFUSAL_MAX_TRIGGER_BYTES="$refusal_max_trigger_bytes" \
        PATCHED_REFUSAL_MAX_EXAMINED_ELEMENTS="$refusal_max_examined_elements" \
        PATCHED_REFUSAL_MAX_IDENTIFIERS="$refusal_max_identifiers" \
        PATCHED_REFUSAL_MAX_IDENTIFIER_CHARACTERS="$refusal_max_identifier_characters" \
        PATCHED_REFUSAL_MAX_IDENTIFIER_UTF8_BYTES="$refusal_max_identifier_utf8_bytes" \
        PATCHED_TENANT_ID="$TENANT_ID" \
        PATCHED_HW_UUID="$HW_UUID" \
        PATCHED_COMPUTER_NAME="$COMPUTER_NAME" \
        "$PYTHON3" - "$refusal_trigger_file" "$@" <<'PYEOF'
import datetime, json, os, stat, sys, tempfile

status_file = os.environ['PATCHED_REFUSAL_STATUS_FILE']
started_at = os.environ['PATCHED_REFUSAL_STARTED_AT']
provenance_dir = os.environ['PATCHED_REFUSAL_PROVENANCE_DIR']
max_trigger_bytes = int(os.environ['PATCHED_REFUSAL_MAX_TRIGGER_BYTES'])
max_examined_elements = int(os.environ['PATCHED_REFUSAL_MAX_EXAMINED_ELEMENTS'])
max_identifiers = int(os.environ['PATCHED_REFUSAL_MAX_IDENTIFIERS'])
max_identifier_characters = int(os.environ['PATCHED_REFUSAL_MAX_IDENTIFIER_CHARACTERS'])
max_identifier_utf8_bytes = int(os.environ['PATCHED_REFUSAL_MAX_IDENTIFIER_UTF8_BYTES'])

# Read at most one byte beyond the accepted envelope before JSON expansion.
# Oversized, malformed and wrong-shaped inputs deliberately produce an empty
# terminal refusal document rather than consuming unbounded memory or work.
explicit_remaining = len(sys.argv) > 2
labels = sys.argv[2:] if explicit_remaining else []
if not explicit_remaining:
    try:
        trigger_fd = os.open(
            sys.argv[1],
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0),
        )
        try:
            if not stat.S_ISREG(os.fstat(trigger_fd).st_mode):
                raise ValueError('trigger is not a regular file')
            raw_trigger = os.read(trigger_fd, max_trigger_bytes + 1)
        finally:
            os.close(trigger_fd)
        if len(raw_trigger) > max_trigger_bytes:
            raise ValueError('trigger exceeds byte limit')
        trigger = json.loads(raw_trigger)
        candidate_labels = trigger.get('labels') if isinstance(trigger, dict) else None
        if not isinstance(candidate_labels, list):
            raise ValueError('labels must be an array')
        labels = candidate_labels
    except Exception:
        # The byte envelope is already enforced. Any decode/shape failure is the
        # same safe terminal refusal and must not prevent the status replacement.
        labels = []

# Preserve supplied order while reporting each valid identifier only once.
# Bound examined elements independently from distinct output so a duplicate
# flood cannot force an unbounded scan before the emitted-row cap is reached.
requested_identifiers = []
seen_identifiers = set()
for label in labels[:max_examined_elements]:
    if not isinstance(label, str) or not label:
        continue
    try:
        label_utf8 = label.encode('utf-8')
    except UnicodeError:
        continue
    if (len(label) > max_identifier_characters
            or len(label_utf8) > max_identifier_utf8_bytes
            or label in seen_identifiers):
        continue
    seen_identifiers.add(label)
    requested_identifiers.append(label)
    if len(requested_identifiers) >= max_identifiers:
        break
recorded_at = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
get_env = lambda key: os.environ.get(key, '')
preserved_rows = []
if explicit_remaining:
    try:
        previous = json.load(open(status_file))
        rows = previous.get('removals') if isinstance(previous, dict) else None
        if isinstance(rows, list):
            refused_names = set(requested_identifiers)
            preserve_limit = max(0, max_identifiers - len(requested_identifiers))
            terminal_outcomes = {
                'removed', 'removed_residual', 'already_removed',
                'manual_removal_required', 'failed_hard',
                'authority_refused', 'skipped_baseline_protected',
            }
            verify_results = {'gone', 'residual', 'still_present', 'not_checked', None}
            methods = {
                'pkg_receipts', 'vendor_uninstaller', 'catalogue', 'app_bundle',
                'registry_quiet_uninstall', 'registry_uninstall', 'winget', 'msi',
                'none', 'unresolvable',
            }
            required_keys = {
                'entry_id', 'name', 'outcome', 'verify_result', 'method',
                'recorded_at',
            }
            def completed_terminal_row(row):
                return (
                    isinstance(row, dict)
                    and set(row) == required_keys
                    and isinstance(row.get('entry_id'), int)
                    and not isinstance(row.get('entry_id'), bool)
                    and isinstance(row.get('name'), str)
                    and row.get('name')
                    and row.get('name') not in refused_names
                    and row.get('outcome') in terminal_outcomes
                    and row.get('verify_result') in verify_results
                    and row.get('method') in methods
                    and isinstance(row.get('recorded_at'), str)
                    and row.get('recorded_at')
                )
            preserved_rows = [
                row for row in rows if completed_terminal_row(row)
            ][:preserve_limit]
    except Exception:
        preserved_rows = []
document = {
    'schema_version': 1,
    'generated_at': recorded_at,
    'last_run': {'started_at': started_at, 'finished_at': recorded_at},
    'removals': preserved_rows + [{
        # 0 is the contract sentinel for refusal before allowlist resolution.
        'entry_id': 0,
        'name': requested_identifier,
        'outcome': 'authority_refused',
        'verify_result': 'not_checked',
        'method': 'none',
        'recorded_at': recorded_at,
    } for requested_identifier in requested_identifiers],
}

# Build all provenance from the same immutable trigger parse as local status.
# recorded_at is used for queued_at because the user-controlled trigger time is
# not an authenticated server queue timestamp.
for index, requested_identifier in enumerate(requested_identifiers):
    record = {
        'record_type': 'app_uninstall',
        'schema_version': 1,
        'tenant_id': get_env('PATCHED_TENANT_ID'),
        'device': {
            'hw_uuid': get_env('PATCHED_HW_UUID'),
            'computer_name': get_env('PATCHED_COMPUTER_NAME'),
        },
        'app': {
            'entry_id': 0,
            'name': requested_identifier,
            'publisher': None,
            'platform': 'macos',
            'match_mode': 'trigger_identifier',
        },
        'uninstall': {
            'method': 'none',
            'method_detail': None,
            'queued_at': recorded_at,
            'window_hours': 24,
        },
        'outcome': 'authority_refused',
        'verify_result': 'not_checked',
        'failure_class': 'hard',
        'recorded_at': recorded_at,
    }
    with open(os.path.join(provenance_dir, f'{index}.json'), 'w') as handle:
        json.dump(record, handle)

state_dir = os.path.dirname(status_file)
temporary_fd, temporary_file = tempfile.mkstemp(
    prefix='.uninstall-status.', dir=state_dir)
try:
    with os.fdopen(temporary_fd, 'w') as handle:
        json.dump(document, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_file, 0o644)
    os.replace(temporary_file, status_file)
    temporary_file = ''
    try:
        directory_fd = os.open(state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass
finally:
    if temporary_file:
        try:
            os.unlink(temporary_file)
        except FileNotFoundError:
            pass
PYEOF
    then
        echo "WARN: could not record refused uninstall trigger status at $refusal_status_file"
        for refusal_provenance in "$refusal_provenance_dir"/*.json(N); do
            rm -f "$refusal_provenance"
        done
        rmdir "$refusal_provenance_dir" 2>/dev/null || true
        return 0
    fi
    # Queue the whole refusal cohort locally in one bounded operation. Delivery
    # happens through drain_provenance_queue's shared four-attempt/five-second
    # cycle budget, never as 32 synchronous POSTs on this trigger path.
    queue_provenance "$refusal_provenance_dir"/*.json(N) || true
    for refusal_provenance in "$refusal_provenance_dir"/*.json(N); do
        rm -f "$refusal_provenance"
    done
    rmdir "$refusal_provenance_dir" 2>/dev/null || true
}
# <<< PATCHED_UNINSTALL_TRIGGER_REFUSAL_END

# >>> PATCHED_TRIGGER_PARSE_START
# parse_trigger <trigger-file-path>
#
# PAT-1059: parses one already-consumed .trigger file and sets TRIG_TYPE,
# TRIGGER_LABELS, RUN_MODE, RUN_TRIGGER. Extracted into a callable function
# (sentinel-delimited, the repo's extracted-block convention) so
# endpoint/test-trigger-parsing.zsh can source and exercise it directly
# against the code that actually ships.
#
# Fixes two related P0 fail-opens, both root-privileged installs triggered
# by a syntactically minimal or malformed trigger file dropped into the
# world-writable-with-sticky-bit $TRIGGER_DIR:
#
#   1. Type parsing used to funnel EVERY value that wasn't literally "scan"
#      or "uninstall" into RUN_MODE="install", including a wholly missing
#      "type" key (legitimate — the retired Self Service deploy historically wrote no
#      "type" at all, see Part A of PAT-1059) AND any garbage/unrecognised
#      value (typo, corruption, or a crafted trigger with "type":"anything").
#      PAT-1620 retired the deploy trigger type along with the Self Service
#      applications that used to write it, so "scan" and "uninstall" are now
#      the ONLY accepted values, explicitly enumerated below; anything else —
#      a missing type, a non-string type like `123` or `null` (which
#      stringify to "123"/"None"), or the now-retired "deploy" itself — is
#      REJECTED: RUN_MODE stays "scan", RUN_TRIGGER becomes
#      "trigger_type_rejected" so this is observably distinct in
#      logs/provenance from both a real trigger and no trigger at all,
#      following the tier_gated downgrade precedent a few lines below this
#      block.
#   2. Missing/invalid "labels" always produced TRIGGER_LABELS="", which the
#      loop-side filter (see "If this is a targeted (trigger) run" below)
#      reads as "no filter — act on the whole allowlist". That is correct
#      for scan mode (read-only, never installs) but was ALSO applied when
#      RUN_MODE=="install", meaning a syntactically minimal trigger like {}
#      or {"type":"whatever"} would install every policy-enabled label as
#      root. This function only surfaces the parsed labels unchanged — the
#      actual fix (empty TRIGGER_LABELS in install mode means zero labels,
#      never the whole allowlist) lives at the loop-side filter, since
#      that's the real privileged boundary.
parse_trigger() {
    local _trig="$1"
    local _parsed _decoded _encoded_identifier
    local -a _parsed_lines
    local -i _identifier_count=0 _framing_valid=1
    TRIGGER_IDENTIFIERS=()

    # Trigger files are unprivileged input. Read one bounded snapshot, then
    # bound the label work and representation before returning anything to zsh.
    # Malformed and oversized snapshots are rejected rather than inheriting the
    # historical missing-type deploy default.
    _parsed=$(PATCHED_TRIGGER_MAX_BYTES=65536 \
        PATCHED_TRIGGER_MAX_EXAMINED_ELEMENTS=128 \
        PATCHED_TRIGGER_MAX_IDENTIFIERS=32 \
        PATCHED_TRIGGER_MAX_IDENTIFIER_CHARACTERS=256 \
        PATCHED_TRIGGER_MAX_IDENTIFIER_UTF8_BYTES=256 \
        "$PYTHON3" - "$_trig" <<'PYEOF'
import base64, json, os, stat, sys

max_bytes = int(os.environ['PATCHED_TRIGGER_MAX_BYTES'])
max_examined = int(os.environ['PATCHED_TRIGGER_MAX_EXAMINED_ELEMENTS'])
max_identifiers = int(os.environ['PATCHED_TRIGGER_MAX_IDENTIFIERS'])
max_characters = int(os.environ['PATCHED_TRIGGER_MAX_IDENTIFIER_CHARACTERS'])
max_utf8_bytes = int(os.environ['PATCHED_TRIGGER_MAX_IDENTIFIER_UTF8_BYTES'])

try:
    trigger_fd = os.open(
        sys.argv[1],
        os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(trigger_fd).st_mode):
            raise ValueError('trigger is not a regular file')
        raw_trigger = os.read(trigger_fd, max_bytes + 1)
    finally:
        os.close(trigger_fd)
    if len(raw_trigger) > max_bytes:
        raise ValueError('trigger exceeds byte limit')
    trigger = json.loads(raw_trigger)
    if not isinstance(trigger, dict):
        raise ValueError('trigger root must be an object')
except Exception:
    # The bounded snapshot may still be syntactically or structurally hostile.
    # Treat every parser failure as an invalid trigger, never a deploy default.
    trigger = {'type': 'trigger_invalid', 'labels': []}

trigger_type = trigger.get('type', 'trigger_invalid')
if not isinstance(trigger_type, str):
    trigger_type = 'trigger_invalid'

labels = trigger.get('labels', [])
if not isinstance(labels, list):
    labels = []

requested = []
seen = set()
for label in labels[:max_examined]:
    if not isinstance(label, str) or not label or '\x00' in label:
        continue
    try:
        label_utf8 = label.encode('utf-8')
    except UnicodeError:
        continue
    if (len(label) > max_characters
            or len(label_utf8) > max_utf8_bytes
            or label in seen):
        continue
    seen.add(label)
    requested.append(label)
    if len(requested) >= max_identifiers:
        break

print(base64.b64encode(trigger_type.encode('utf-8')).decode('ascii'))
print(len(requested))
for label in requested:
    print(base64.b64encode(label.encode('utf-8')).decode('ascii'))
raise SystemExit(0)
PYEOF
    )
    _parsed_lines=("${(@f)_parsed}")
    if (( ${#_parsed_lines} < 2 )) || [[ "${_parsed_lines[2]:-}" != <-> ]]; then
        _framing_valid=0
    else
        _identifier_count=${_parsed_lines[2]}
        if (( _identifier_count > 32
                || ${#_parsed_lines} != _identifier_count + 2 )); then
            _framing_valid=0
        fi
    fi

    if (( _framing_valid )); then
        _decoded=$("$PYTHON3" -c '
import base64, binascii, sys
try:
    raw = base64.b64decode(sys.argv[1], validate=True)
    value = raw.decode("utf-8")
except (ValueError, UnicodeError, binascii.Error):
    raise SystemExit(1)
sys.stdout.write(value + "\x1e")
' "${_parsed_lines[1]}") || _framing_valid=0
        if (( _framing_valid )) && [[ "$_decoded" == *$'\x1e' ]]; then
            TRIG_TYPE="${_decoded%$'\x1e'}"
        else
            _framing_valid=0
        fi
    fi

    if (( _framing_valid )); then
        for _encoded_identifier in "${_parsed_lines[@][3,-1]}"; do
            _decoded=$("$PYTHON3" -c '
import base64, binascii, sys
try:
    raw = base64.b64decode(sys.argv[1], validate=True)
    value = raw.decode("utf-8")
except (ValueError, UnicodeError, binascii.Error):
    raise SystemExit(1)
if (not value or "\x00" in value or len(value) > 256
        or len(raw) > 256):
    raise SystemExit(1)
sys.stdout.write(value + "\x1e")
' "$_encoded_identifier") || { _framing_valid=0; break; }
            if [[ "$_decoded" != *$'\x1e' ]]; then
                _framing_valid=0
                break
            fi
            TRIGGER_IDENTIFIERS+=("${_decoded%$'\x1e'}")
        done
    fi

    if (( ! _framing_valid || ${#TRIGGER_IDENTIFIERS} != _identifier_count )); then
        TRIG_TYPE="trigger_invalid"
        TRIGGER_IDENTIFIERS=()
    fi
    # Retain the historical label-filter representation for install/scan.
    # Uninstall never consumes this lossy joined value; it uses the exact array.
    TRIGGER_LABELS="${(j: :)TRIGGER_IDENTIFIERS}"

    if [[ "$TRIG_TYPE" == "scan" ]]; then
        RUN_MODE="scan"
        RUN_TRIGGER="manual"
    elif [[ "$TRIG_TYPE" == "uninstall" ]]; then
        # Actuate the removal engine for each identifier in the trigger, then
        # fall through to a scan pass so the status file reflects the change.
        RUN_MODE="scan"
        RUN_TRIGGER="manual"
        _uninst_engine="$BUNDLE_DIR/patched-uninstall.sh"
        if ! legacy_app_execution_enabled; then
            echo "Legacy app-execution gate disabled — not actuating uninstall trigger"
            # The trigger is deliberately consumed and the assurance scan below
            # continues. Record the refusal explicitly rather than letting a
            # successful daemon exit be mistaken for a successful removal.
            log_jsonl "warn" "legacy app-execution gate: refusing uninstall trigger" \
                "{\"trigger\":\"uninstall\",\"mode\":\"scan\"}"
            record_uninstall_trigger_authority_refusal "$_trig"
        elif [[ -x "$_uninst_engine" ]]; then
            local -i _uninstall_index=1
            for _uid in "${TRIGGER_IDENTIFIERS[@]}"; do
                echo "Uninstall trigger: invoking removal engine for '$_uid'"
                local _uninst_rc=0
                "$_uninst_engine" --app-id "$_uid" || _uninst_rc=$?
                if [[ $_uninst_rc -eq $LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT ]]; then
                    echo "Uninstall child observed revoked execution authority; recording terminal refusal before trigger consumption"
                    log_jsonl "warn" "legacy app-execution authority revoked inside uninstall child" \
                        "{\"trigger\":\"uninstall\",\"mode\":\"scan\"}"
                    record_uninstall_trigger_authority_refusal "$_trig" \
                        "${TRIGGER_IDENTIFIERS[@][$_uninstall_index,-1]}"
                    break
                fi
                (( _uninstall_index++ )) || true
            done
        else
            echo "WARN: patched-uninstall.sh not found at $BUNDLE_DIR — uninstall trigger not actuated"
        fi
    else
        # PAT-1620: deploy is retired along with the Self Service applications
        # that used to request it. An unrecognised or missing type — deploy
        # included — is rejected outright, never treated as an implicit
        # install. Do not set RUN_MODE="install" here.
        echo "WARN: trigger $_trig declared type='$TRIG_TYPE' — not one of scan/uninstall (deploy is retired, PAT-1620); rejecting rather than defaulting to install"
        RUN_MODE="scan"
        RUN_TRIGGER="trigger_type_rejected"
    fi
}
# <<< PATCHED_TRIGGER_PARSE_END

# >>> PATCHED_TRIGGER_CONSUME_START
if [[ -d "$TRIGGER_DIR" ]]; then
    # Consume at most one app-update trigger per run (rate-limit, review §5 / risk T8).
    # os_defer markers are NOT consumed here — they persist as deferral evidence for
    # the PAT-273 OS-update section and are tallied/cleaned by compute_os_update below.
    # PAT-1623: removal_defer markers get the identical exemption, for the identical
    # reason — they are the removal notify/defer surface's own deferral evidence
    # (menubar/PatchedUpdater/StatusStore.swift's requestRemovalDefer), a distinct
    # per-app budget from os_update's global deferrals_remaining. They must never be
    # tallied against each other, so this is a new "type" value rather than reusing
    # os_defer (PAT-1620 narrowed accepted trigger types; this is the minimal,
    # documented extension it asks for rather than an unreviewed new channel — the
    # marker is still just a JSON file an unprivileged writer drops, same shape,
    # same directory, same narrow validation). Nothing in this script currently
    # tallies removal_defer markers into a budget (that accounting is out of this
    # ticket's scope, see PAT-1623's report) — this exemption exists purely so the
    # marker is not silently deleted by the one-trigger-per-run consumption below
    # before any such accounting could ever read it.
    trig=$("$PYTHON3" -c '
import os, json, stat, sys
td = sys.argv[1]
max_bytes = 65536
if not os.path.isdir(td):
    sys.exit(0)
trigs = []
for fn in os.listdir(td):
    if not fn.endswith(".trigger"):
        continue
    fp = os.path.join(td, fn)
    try:
        trigger_fd = os.open(
            fp,
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(trigger_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("trigger is not a regular file")
            raw = os.read(trigger_fd, max_bytes + 1)
        finally:
            os.close(trigger_fd)
        if len(raw) > max_bytes:
            raise ValueError("trigger exceeds byte limit")
        d = json.loads(raw)
        if not isinstance(d, dict) or d.get("type") not in ("os_defer", "removal_defer"):
            trigs.append((metadata.st_mtime, fp))
    except Exception:
        # Invalid and oversized app triggers must still be consumed. Otherwise
        # the newest hostile file can remain forever while avoiding all work.
        try:
            trigs.append((os.lstat(fp).st_mtime, fp))
        except OSError:
            pass
if trigs:
    print(sorted(trigs, reverse=True)[0][1])
' "$TRIGGER_DIR" 2>/dev/null)
    if [[ -n "$trig" ]]; then
        echo "Consuming trigger: $trig"
        parse_trigger "$trig"
        rm -f "$trig"                           # delete only this trigger (not os_defer/removal_defer markers)
    fi
fi
# <<< PATCHED_TRIGGER_CONSUME_END

# Tier gate: managed updating requires tier=managed, the sole actuating
# tier (PAT-1807). assurance tenants get scan-only runs even if a trigger
# file was dropped.
if [[ "$AGENT_TIER" != "managed" && "$RUN_MODE" == "install" ]]; then
    echo "Tier gate: tier=$AGENT_TIER — downgrading install to scan (tenant not managed-tier)"
    RUN_MODE="scan"
    RUN_TRIGGER="tier_gated"
fi

# PAT-1059: with the type/labels fail-opens closed, an install-mode run can
# still legitimately end up with zero valid labels (e.g. a deploy trigger
# whose "labels" was missing or empty). That is intentional — see the
# loop-side filter below — but it must be visible in logs/provenance that
# nothing was installed and why, not silently indistinguishable from "ran
# fine, nothing needed updating".
if [[ "$RUN_MODE" == "install" && -z "$TRIGGER_LABELS" ]]; then
    echo "PAT-1059: install run has zero valid labels (trigger \"labels\" was missing or empty) — no packages will be installed this run"
fi

# ---------------------------------------------------------------------------
# PACKAGE ALLOWLIST PRESENCE  (PAT-1505)
# ---------------------------------------------------------------------------
# The assurance-only bundle ships no labels-allowlist.txt: its only producer
# was ci/validate-labels.py --emit-allowlist and its only consumers were the
# quarantined deployment engine and the scan loop below. The daemon itself is
# retained and must keep running cleanly without it.
#
# This is not cosmetic. The scan loop ends in a bare `done < "$ALLOWLIST"`, and
# this script runs `set -u` without `set -e`, so a missing path there prints a
# raw "no such file or directory" from the shell and then runs zero iterations
# and carries on. That is the exact failure shape AGENTS.md calls out: a
# degraded run that is indistinguishable in the log from a healthy one. Redirect
# from /dev/null instead, so the zero-label outcome is stated and intentional
# rather than incidental, and no raw shell error appears in a log a customer may
# read. Installomator is invoked only from inside that loop, so zero iterations
# is also what keeps the (absent) engine unreachable.
if [[ ! -f "$ALLOWLIST" ]]; then
    echo "No package allowlist in bundle ($ALLOWLIST): assurance-only bundle (PAT-1505), scanning zero labels this run"
    log_jsonl "info" "no package allowlist in bundle (assurance-only); scanning zero labels" \
        "{\"allowlist\":\"$ALLOWLIST\"}"
    ALLOWLIST="/dev/null"
fi

# ---------------------------------------------------------------------------
# BREW COEXISTENCE DETECTION  (PAT-277)
#
# Best-effort, non-fatal. Runs once before the label loop. Detects Homebrew
# and maps its casks against our allowlist by app bundle name, producing a
# per-label also_managed_by / brew_version map used by the row builder below.
# Output: $BREW_COEX_TMP — JSON {homebrew_present, homebrew_prefix, by_label}.
# ---------------------------------------------------------------------------

BREW_COEX_TMP=$(mktemp /tmp/.patched-brew.XXXXXX)
# PAT-464: detect cask-managed apps via Caskroom filesystem reads — no brew binary.
# Reads .metadata/{version}/*/config.json inside each installed cask directory to
# obtain the app artifact list without executing brew.
"$PYTHON3" - "$ALLOWLIST" "$BREW_COEX_TMP" <<'PYEOF'
import json, os, sys

allowlist_file = sys.argv[1]
output_file    = sys.argv[2]

result = {'homebrew_present': False, 'homebrew_prefix': None, 'by_label': {}}

try:
    brew_prefix = None
    caskroom    = None
    for candidate_pfx, candidate_room in [
        ('/opt/homebrew',        '/opt/homebrew/Caskroom'),
        ('/usr/local/Homebrew',  '/usr/local/Caskroom'),
    ]:
        if os.path.isdir(candidate_room):
            brew_prefix = candidate_pfx
            caskroom    = candidate_room
            break

    if not caskroom:
        with open(output_file, 'w') as f:
            json.dump(result, f)
        sys.exit(0)

    result['homebrew_present'] = True
    result['homebrew_prefix']  = brew_prefix

    # Build: app bundle filename → {token, brew_version} from Caskroom on disk.
    # For each installed cask read .metadata/{version}/*/config.json to get the
    # artifact list — no brew binary required.
    app_name_to_cask = {}
    try:
        for token in os.listdir(caskroom):
            token_dir = os.path.join(caskroom, token)
            if not os.path.isdir(token_dir) or token.startswith('.'):
                continue

            # Installed version: non-hidden subdirs that are not .metadata, newest first.
            versions = sorted(
                [d for d in os.listdir(token_dir)
                 if not d.startswith('.')
                 and os.path.isdir(os.path.join(token_dir, d))],
                reverse=True,
            )
            version = versions[0] if versions else ''

            app_names = []
            if version:
                ver_meta = os.path.join(token_dir, '.metadata', version)
                if os.path.isdir(ver_meta):
                    for ts_entry in os.listdir(ver_meta):
                        cfg = os.path.join(ver_meta, ts_entry, 'config.json')
                        if os.path.isfile(cfg):
                            try:
                                with open(cfg) as fh:
                                    cdata = json.load(fh)
                                for artifact in cdata.get('artifacts', []):
                                    if not isinstance(artifact, dict):
                                        continue
                                    for app_entry in artifact.get('app', []):
                                        if isinstance(app_entry, str):
                                            app_names.append(app_entry)
                            except Exception:
                                pass
                            break  # first readable config is enough

            for app_name in app_names:
                app_name_to_cask[app_name] = {'token': token, 'brew_version': version}

    except Exception:
        pass

    # Match each allowlist entry against the cask map by app bundle filename.
    # Format: label TAB name TAB team_id TAB app_path TAB url_method
    by_label = {}
    with open(allowlist_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            label, app_path = parts[0], parts[3]
            bundle   = os.path.basename(app_path)  # e.g. "Google Chrome.app"
            cask_hit = app_name_to_cask.get(bundle)
            if cask_hit:
                by_label[label] = {'also_managed_by': 'homebrew',
                                   'brew_version':    cask_hit['brew_version']}
            else:
                by_label[label] = {'also_managed_by': None, 'brew_version': None}

    result['by_label'] = by_label

except Exception:
    pass  # non-fatal; result stays with homebrew_present=True, by_label={}

with open(output_file, 'w') as f:
    json.dump(result, f)
PYEOF
echo "Brew coexistence detection complete (homebrew_present=$("$PYTHON3" -c "import json,sys; print(json.load(open(sys.argv[1])).get('homebrew_present','?'))" "$BREW_COEX_TMP" 2>/dev/null || echo '?'))"

# ---------------------------------------------------------------------------
# 3. ITERATE
# ---------------------------------------------------------------------------

RUN_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
APPS_NDJSON=$(mktemp /tmp/.patched-apps.XXXXXX)   # one JSON object per line
_JSONL_LABEL_COUNT=0
log_jsonl "info" "update scan started" "{\"mode\":\"$RUN_MODE\",\"trigger\":\"$RUN_TRIGGER\"}"

while IFS=$'\t' read -r label name expected_tid app_path url_method allowlist_mirror_url allowlist_pinned_sha256; do
    [[ -z "$label" || "$label" == \#* ]] && continue

    # If this is a targeted (trigger) run, skip labels not requested.
    # PAT-1059: an empty TRIGGER_LABELS means two different things depending
    # on RUN_MODE, and conflating them was the P0 — a scan run with no
    # trigger legitimately has empty TRIGGER_LABELS and means "no filter, act
    # on the whole allowlist" (harmless: scan is read-only, never installs).
    # An INSTALL-mode run reaching here with empty TRIGGER_LABELS means the
    # trigger's "labels" was missing/empty/invalid, and must mean "install
    # nothing" — never silently fall back to the whole allowlist, which
    # would install every policy-enabled app as root from a trigger with
    # missing/empty labels. PAT-1620 retired the deploy trigger type itself,
    # so a trigger can no longer reach install mode at all; this guard stays
    # as defence for the RUN_MODE=install path pending its own removal
    # ticket. This is distinct from TRIGGER_LABELS
    # literally being the string "*", which is a deliberate, non-empty
    # value meaning "run everything" — documented as a real caller contract
    # at menubar/PatchedUpdater/StatusStore.swift's requestUpdate(labels:)
    # ("Pass a specific Installomator label or ["*"] to run all pending
    # updates"). The round-1 fix for this ticket collapsed that wildcard
    # case into the empty case for install mode too, which would have
    # silently turned a documented "install everything" call into "install
    # nothing" — the same fail-safe-is-invisible shape this ticket exists to
    # close, just one level down. The "*" escape hatch is therefore honored
    # in BOTH branches below; only genuinely empty TRIGGER_LABELS is
    # treated differently by RUN_MODE. Sentinel-wrapped (see parse_trigger()
    # above) so endpoint/test-trigger-parsing.zsh can extract and exercise
    # the exact shipped filter inside its own loop wrapper.
    # >>> PATCHED_TRIGGER_LABEL_FILTER_START
    if [[ "$RUN_MODE" == "install" ]]; then
        if [[ -z "$TRIGGER_LABELS" ]]; then
            continue   # PAT-1059: install-mode trigger with no valid labels means nothing, never the whole allowlist
        fi
        if [[ "$TRIGGER_LABELS" != "*" ]]; then
            [[ " $TRIGGER_LABELS " == *" $label "* ]] || continue
        fi
    elif [[ -n "$TRIGGER_LABELS" && "$TRIGGER_LABELS" != "*" ]]; then
        [[ " $TRIGGER_LABELS " == *" $label "* ]] || continue
    fi
    # <<< PATCHED_TRIGGER_LABEL_FILTER_END

    # PAT-383: resolve the macOS bundle ID (when the app is installed) so a policy
    # override keyed by either the Installomator label or the bundle ID matches,
    # then gate installs by the per-tenant toggle. Scan runs are never gated.
    _bundle_id=$(/usr/bin/defaults read "${app_path}/Contents/Info" CFBundleIdentifier 2>/dev/null || echo "")
    _pol_src=$(policy_source "$label" "$_bundle_id")
    _pol_disabled=0
    if [[ "$RUN_MODE" == "install" ]] && ! policy_allows "$label" "$_bundle_id"; then
        _pol_disabled=1
        echo "Policy gate: $label (${_bundle_id:-no-bundle-id}) disabled by per-tenant policy (source=$_pol_src) — install suppressed"
    fi

    # PAT-506: ring gate — only gate if policy hasn't already suppressed the install.
    _ring_gated=0
    if [[ "$RUN_MODE" == "install" && "$_pol_disabled" == "0" ]]; then
        if ! ring_allows "$label"; then
            _ring_gated=1
            echo "Ring gate: $label device_ring=$DEVICE_RING approved_ring=${RING_PROMOTION[${label:l}]:-none} — skipping install"
        fi
    fi

    # PAT-647: expose allowlist-embedded CDN URL + pinned hash to run_label.
    LABEL_MIRROR_URL="${allowlist_mirror_url:-}"
    LABEL_PINNED_SHA256="${allowlist_pinned_sha256:-}"
    run_label "$label" "$name" "$expected_tid" "$app_path" "$RUN_MODE" "$_pol_src" "$_pol_disabled" "$_ring_gated"
    (( _JSONL_LABEL_COUNT++ )) || true
    LABEL_MIRROR_URL=""
    LABEL_PINNED_SHA256=""

    # The tray status contract has no members for policy/ring/catalogue skips,
    # so those remain provenance-only. Authority refusal is deliberately kept
    # as a typed terminal action and must not be hidden like a deferral.
    _tray_last_action="$OUT_OUTCOME"
    [[ "$_tray_last_action" == "skipped_policy" ]] && _tray_last_action=""
    [[ "$_tray_last_action" == "deferred_blocking_process" ]] && _tray_last_action=""
    [[ "$_tray_last_action" == "ring_gated" ]] && _tray_last_action=""
    [[ "$_tray_last_action" == "fail_closed_policy" ]] && _tray_last_action=""
    [[ "$_tray_last_action" == "fail_closed_catalogue" ]] && _tray_last_action=""
    [[ "$_tray_last_action" == "fail_closed_unverified" ]] && _tray_last_action=""

    PATCHED_LABEL="$label" \
    PATCHED_NAME="$name" \
    PATCHED_INST_VER="${OUT_VERSION_AFTER:-${OUT_VERSION_BEFORE:-}}" \
    PATCHED_AVAIL_VER="${OUT_AVAILABLE_VERSION:-}" \
    PATCHED_STATE="$STATE_RESULT" \
    PATCHED_OUTCOME="$_tray_last_action" \
    PATCHED_FAILURE_REASON="${OUT_FAILURE_REASON:-}" \
    PATCHED_VERIFIED_SIGNER="${OUT_VERIFIED_SIGNER:-}" \
    PATCHED_MESSAGE="${OUT_MESSAGE:-}" \
    "$PYTHON3" - "$APPS_NDJSON" "${BREW_COEX_TMP:-}" <<'PYEOF'
import json, datetime, os, sys
g = lambda k: os.environ.get(k, '')
brew_file = sys.argv[2] if len(sys.argv) > 2 else ''
brew_info = {}
if brew_file and os.path.exists(brew_file):
    try:
        brew_info = json.load(open(brew_file)).get('by_label', {}).get(g('PATCHED_LABEL'), {})
    except Exception:
        pass
also_managed_by = brew_info.get('also_managed_by')
brew_version    = brew_info.get('brew_version')
installed_ver   = g('PATCHED_INST_VER') or None
manager_drift   = bool(also_managed_by and brew_version and installed_ver
                       and installed_ver != brew_version)
row = {
  'label': g('PATCHED_LABEL'),
  'name': g('PATCHED_NAME'),
  'installed_version': installed_ver,
  'available_version': g('PATCHED_AVAIL_VER') or None,
  'state': g('PATCHED_STATE'),
  'last_action': g('PATCHED_OUTCOME') or None,
  'last_action_at': datetime.datetime.now(
        datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
  'failure_reason': g('PATCHED_FAILURE_REASON') or None,
  'verified_signer': g('PATCHED_VERIFIED_SIGNER') or None,
  'message': g('PATCHED_MESSAGE') or None,
  'also_managed_by': also_managed_by,
  'manager_drift': manager_drift,
}
with open(sys.argv[1], 'a') as f: f.write(json.dumps(row) + '\n')
PYEOF
done < "$ALLOWLIST"

RUN_FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# A consumed deploy request is not successful merely because the privileged
# daemon reached the end of its allowlist loop. Every requested label must have
# produced an authoritative result row. A stale caller can still send bundle
# identifiers, and a newer caller can race an allowlist change; both cases must
# fail visibly without weakening the label-only join.
# >>> PATCHED_DEPLOY_RESULT_RECONCILE_START
reconcile_deploy_results() {  # reconcile_deploy_results <apps-ndjson> <requested-labels> <finished-at>
    local _apps_file="$1" _requested_labels="$2" _finished_at="$3"
    PATCHED_REQUESTED_LABELS="$_requested_labels" \
    PATCHED_RECONCILED_AT="$_finished_at" \
    "$PYTHON3" - "$_apps_file" <<'PYEOF'
import json, os, sys

apps_file = sys.argv[1]
requested = []
for label in os.environ.get('PATCHED_REQUESTED_LABELS', '').split():
    if label not in requested:
        requested.append(label)

rows = []
try:
    with open(apps_file) as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
except FileNotFoundError:
    pass

seen = {row.get('label') for row in rows if isinstance(row, dict)}
if not requested:
    missing = ['*']
    messages = {'*': 'Install request refused: the trigger did not contain any valid labels.'}
elif '*' in requested:
    missing = ['*'] if not rows else []
    messages = {'*': 'Install all request refused: no allowlisted apps produced a result.'}
else:
    missing = [label for label in requested if label not in seen]
    messages = {
        label: "Install request refused: requested label is not in this endpoint's allowlist."
        for label in missing
    }

with open(apps_file, 'a') as fh:
    for label in missing:
        row = {
            'label': label,
            'name': 'Install request' if label == '*' else label,
            'installed_version': None,
            'available_version': None,
            'state': 'error',
            'last_action': 'error',
            'last_action_at': os.environ.get('PATCHED_RECONCILED_AT') or None,
            'failure_reason': None,
            'verified_signer': None,
            'message': messages[label],
            'also_managed_by': None,
            'manager_drift': False,
        }
        fh.write(json.dumps(row) + '\n')
if missing:
    print(f"Install request refusal recorded for {len(missing)} requested label(s); see update-status.json")
PYEOF
}
# <<< PATCHED_DEPLOY_RESULT_RECONCILE_END

if [[ "$DEPLOY_REQUESTED" == "1" ]]; then
    reconcile_deploy_results "$APPS_NDJSON" "$TRIGGER_LABELS" "$RUN_FINISHED"
fi

# Derive next_scheduled_run from the LaunchDaemon plist.
# StartInterval (every-N-seconds) is wired; StartCalendarInterval (cron-style)
# requires computing the next matching calendar slot — left as a TODO.
NEXT_RUN_ISO=""
_plist="${PATCHED_LAUNCHDAEMON_PLIST:-/Library/LaunchDaemons/com.patched.update.plist}"
if [[ -f "$_plist" ]]; then
    _interval=$(plutil -extract StartInterval raw -o - "$_plist" 2>/dev/null || echo "")
    if [[ -n "$_interval" && "$_interval" =~ ^[0-9]+$ ]]; then
        NEXT_RUN_ISO=$(PATCHED_INTERVAL="$_interval" "$PYTHON3" -c "
import datetime, os
nxt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=int(os.environ['PATCHED_INTERVAL']))
print(nxt.strftime('%Y-%m-%dT%H:%M:%SZ'))
" 2>/dev/null || echo "")
    fi
    # TODO(next-scheduled-run): parse StartCalendarInterval for cron-style schedules
fi

# ---------------------------------------------------------------------------
# 3b. OS UPDATE AWARENESS  (PAT-273)
#
# Fetches/caches the SOFA feed, reads the optional per-tenant policy plist,
# tallies os_defer markers, and computes the os_update section. The result is
# written to OS_UPDATE_TMP and injected into the status JSON below.
#
# Fallback: if SOFA is unreachable, uses the last-cached data.  State is
# capped at update_recommended when SOFA data is stale (no invented deadline).
# No MDM/DDM/profile dependency anywhere in this block.
# ---------------------------------------------------------------------------

# Resolve proxy for SOFA (separate origin from the API — settings may differ).
_sofa_proxy_url=""
if [[ -x "${PROXY_RESOLVE:-}" ]]; then
    _sofa_proxy_json=$("$PYTHON3" "$PROXY_RESOLVE" "https://sofafeed.macadmins.io" "${AGENT_CONFIG_FILE:-}" 2>/dev/null) \
        || _sofa_proxy_json='{"mode":"direct"}'
    # JSON via stdin (not argv) so the credential-bearing URL is never in `ps`.
    # Emit url<TAB>warning; surface any warning on stderr so it lands in the log.
    _sofa_parsed=$(printf '%s' "$_sofa_proxy_json" | "$PYTHON3" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
url = d.get("url", "") if d.get("mode") == "proxy" else ""
sys.stdout.write(url + "\t" + (d.get("warning", "") or ""))
' 2>/dev/null) || _sofa_parsed=""
    IFS=$'\t' read -r _sofa_proxy_url _sofa_warn <<< "$_sofa_parsed"
    [[ -n "${_sofa_warn:-}" ]] && echo "  proxy (sofa): warning: $_sofa_warn" >&2
fi

OS_UPDATE_TMP=$(mktemp /tmp/.patched-osupdate.XXXXXX)
PATCHED_STATE_DIR="$STATE_DIR" \
PATCHED_TRIGGER_DIR="$TRIGGER_DIR" \
PATCHED_SOFA_CACHE="$SOFA_CACHE" \
PATCHED_OS_POLICY_FILE="$OS_POLICY_FILE" \
HTTP_PROXY="${_sofa_proxy_url:-}" \
HTTPS_PROXY="${_sofa_proxy_url:-}" \
http_proxy="${_sofa_proxy_url:-}" \
https_proxy="${_sofa_proxy_url:-}" \
"$PYTHON3" - "$OS_UPDATE_TMP" <<'PYEOF'
import json, os, sys, datetime, subprocess, plistlib
try:
    from urllib.request import urlopen
    from urllib.error import URLError
except ImportError:
    urlopen = None

g = lambda k, d=None: os.environ.get(k, d)
state_dir    = g('PATCHED_STATE_DIR', '/Library/Application Support/Patched')
trigger_dir  = g('PATCHED_TRIGGER_DIR', os.path.join(state_dir, 'triggers'))
sofa_cache   = g('PATCHED_SOFA_CACHE', os.path.join(state_dir, 'sofa-cache.json'))
policy_path  = g('PATCHED_OS_POLICY_FILE', os.path.join(state_dir, 'os-update-policy.plist'))
output_file  = sys.argv[1]
fmt_dt       = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None
now          = datetime.datetime.now(datetime.timezone.utc)

# --- Version helpers ---------------------------------------------------------

def parse_ver(v):
    if not v:
        return (0,)
    try:
        return tuple(int(x) for x in str(v).split('.'))
    except Exception:
        return (0,)

def ver_ge(a, b):
    """Return True if version string a >= b."""
    av, bv = parse_ver(a), parse_ver(b)
    n = max(len(av), len(bv))
    av = av + (0,) * (n - len(av))
    bv = bv + (0,) * (n - len(bv))
    return av >= bv

# --- Installed OS ------------------------------------------------------------

try:
    installed_os = subprocess.check_output(
        ['/usr/bin/sw_vers', '-productVersion'], text=True, timeout=10).strip()
except Exception:
    installed_os = ''

if not installed_os:
    result = {
        'installed_os': '', 'latest_os': None,
        'state': 'unknown', 'severity': 'none',
        'security_relevant': False, 'actively_exploited': False,
        'deadline': None, 'deferrals_remaining': 5,
        'release_age_days': None, 'checked_at': fmt_dt(now),
    }
    with open(output_file, 'w') as f:
        json.dump(result, f)
    sys.exit(0)

installed_major = parse_ver(installed_os)[0]

# --- SOFA feed (6-hour cache) ------------------------------------------------

SOFA_URL = 'https://sofafeed.macadmins.io/v1/macos_data_feed.json'
SOFA_TTL = 6 * 3600
sofa_data = None
sofa_from_cache = False

try:
    if os.path.exists(sofa_cache):
        age = now.timestamp() - os.path.getmtime(sofa_cache)
        if age < SOFA_TTL:
            with open(sofa_cache) as f:
                sofa_data = json.load(f)
            sofa_from_cache = True

    if sofa_data is None and urlopen is not None:
        resp = urlopen(SOFA_URL, timeout=15)
        raw  = resp.read()
        sofa_data = json.loads(raw)
        tmp = sofa_cache + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(raw)
        os.rename(tmp, sofa_cache)
        sofa_from_cache = False
except Exception:
    if sofa_data is None and os.path.exists(sofa_cache):
        try:
            with open(sofa_cache) as f:
                sofa_data = json.load(f)
            sofa_from_cache = True
        except Exception:
            pass

# Extract latest info for the installed major from SOFA
latest_os          = None
release_date       = None
release_age_days   = None
actively_exploited_cves = []
cve_count          = 0

if sofa_data:
    for entry in sofa_data.get('OSVersions', []):
        latest = entry.get('Latest', {})
        pv = latest.get('ProductVersion', '')
        if not pv:
            continue
        if parse_ver(pv)[0] == installed_major:
            latest_os = pv
            rd = latest.get('ReleaseDate', '')
            if rd:
                try:
                    release_date = datetime.datetime.strptime(
                        rd[:10], '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
                    release_age_days = (now - release_date).days
                except Exception:
                    pass
            actively_exploited_cves = latest.get('ActivelyExploitedCVEs', [])
            cve_count = len(latest.get('CVEs', {}))
            break

security_relevant = cve_count > 0
actively_exploited = bool(actively_exploited_cves)

# --- Policy plist ------------------------------------------------------------

policy = {}
if os.path.exists(policy_path):
    try:
        with open(policy_path, 'rb') as f:
            policy = plistlib.load(f)
    except Exception:
        pass

# PAT-2133: the target is the policy target, else the SOFA latest, else
# unknown (None). Never the installed version: that made ver_ge() below true
# by construction, so a Mac whose latest version was unknown read up_to_date.
_policy_target = policy.get('target_os')
_policy_target = str(_policy_target).strip() if _policy_target is not None else ''
target_os           = _policy_target or latest_os or None
min_age_days        = int(policy.get('minimum_age_days', 7))
grace_days          = int(policy.get('grace_days', 14))
deferral_budget     = int(policy.get('deferral_budget', 5))
blocking_window_days= int(policy.get('blocking_window_days', 3))
exploited_overrides = bool(policy.get('exploited_overrides_age', True))
absolute_deadline   = policy.get('deadline')  # str or None

# --- Deferral tally ----------------------------------------------------------

os_defer_count = 0
if os.path.isdir(trigger_dir):
    for fn in os.listdir(trigger_dir):
        if not fn.endswith('.trigger'):
            continue
        try:
            with open(os.path.join(trigger_dir, fn)) as f:
                d = json.load(f)
            if d.get('type') == 'os_defer':
                os_defer_count += 1
        except Exception:
            pass

deferrals_remaining = max(0, deferral_budget - os_defer_count)

# --- Deadline computation ----------------------------------------------------

deadline = None
if absolute_deadline:
    try:
        dl = str(absolute_deadline)
        try:
            deadline = datetime.datetime.fromisoformat(dl).replace(
                tzinfo=datetime.timezone.utc)
        except Exception:
            deadline = datetime.datetime.strptime(dl[:10], '%Y-%m-%d').replace(
                tzinfo=datetime.timezone.utc)
    except Exception:
        pass
elif release_date:
    exploited_skips = exploited_overrides and actively_exploited
    effective_grace = max(1, grace_days // 2) if exploited_skips else grace_days
    deadline = release_date + datetime.timedelta(days=effective_grace)

# When SOFA data is from a stale cache and we fetched nothing live, cap the
# state at update_recommended — don't invent a deadline from stale data.
stale_sofa = sofa_from_cache and sofa_data is not None and not (
    sofa_data is None)
if sofa_from_cache and os.path.exists(sofa_cache):
    cache_age = now.timestamp() - os.path.getmtime(sofa_cache)
    stale_sofa = cache_age >= SOFA_TTL

# --- State + severity --------------------------------------------------------

exploited_skips = exploited_overrides and actively_exploited

if target_os is not None and ver_ge(installed_os, target_os):
    # Device is at or above target — clean up old os_defer markers for this cycle
    if os.path.isdir(trigger_dir):
        for fn in os.listdir(trigger_dir):
            if not fn.endswith('.trigger'):
                continue
            try:
                fp = os.path.join(trigger_dir, fn)
                with open(fp) as f:
                    d = json.load(f)
                if d.get('type') == 'os_defer':
                    os.unlink(fp)
            except Exception:
                pass
    state    = 'up_to_date'
    severity = 'none'
    security_relevant  = False
    actively_exploited = False
    deadline           = None
    release_age_days   = None

elif latest_os is None:
    state    = 'unknown'
    severity = 'none'

else:
    within_min_age = (
        release_age_days is not None
        and release_age_days < min_age_days
        and not exploited_skips
    )

    if within_min_age or stale_sofa:
        state    = 'update_recommended'
        severity = 'high' if actively_exploited else ('medium' if security_relevant else 'low')
        deadline = None  # no deadline from stale/new data
    elif deadline and now >= deadline:
        state    = 'deadline_passed'
        severity = 'critical'
    elif deadline:
        days_left = (deadline - now).days
        if days_left <= blocking_window_days or deferrals_remaining == 0:
            state    = 'update_required'
            severity = 'critical' if actively_exploited else 'high'
        else:
            state    = 'update_required'
            severity = 'high' if actively_exploited else ('medium' if security_relevant else 'low')
    else:
        # No deadline computable (no release_date and no policy deadline)
        state    = 'update_recommended'
        severity = 'high' if actively_exploited else ('medium' if security_relevant else 'low')

# --- Output ------------------------------------------------------------------

result = {
    'installed_os':       installed_os,
    'latest_os':          latest_os,
    'state':              state,
    'severity':           severity,
    'security_relevant':  security_relevant,
    'actively_exploited': actively_exploited,
    'deadline':           fmt_dt(deadline),
    'deferrals_remaining':deferrals_remaining,
    'release_age_days':   release_age_days,
    'checked_at':         fmt_dt(now),
}
# PAT-2133: an unknown target is omitted, never "None", "" or installed_os.
if target_os is not None:
    result['target_os'] = target_os
with open(output_file, 'w') as f:
    json.dump(result, f)
PYEOF

_os_state=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","?"))' "$OS_UPDATE_TMP" 2>/dev/null || echo '?')
echo "OS update section computed (state=$_os_state)"

# ---------------------------------------------------------------------------
# 4. WRITE STATUS FILE  (atomic; the menu bar app's contract)
# ---------------------------------------------------------------------------

STATUS_TMP=$(mktemp /tmp/.patched-status.XXXXXX)
PATCHED_RUN_FINISHED="$RUN_FINISHED" \
PATCHED_HW_UUID="$HW_UUID" \
PATCHED_COMPUTER_NAME="$COMPUTER_NAME" \
PATCHED_RUN_STARTED="$RUN_STARTED" \
PATCHED_RUN_TRIGGER="$RUN_TRIGGER" \
PATCHED_INSTALLOMATOR_TAG="$INSTALLOMATOR_TAG" \
PATCHED_NEXT_RUN_ISO="${NEXT_RUN_ISO:-}" \
"$PYTHON3" - "$APPS_NDJSON" "$STATUS_TMP" "${OS_UPDATE_TMP:-}" "${BREW_COEX_TMP:-}" <<'PYEOF'
import json, os, sys
g = lambda k: os.environ.get(k, '')
apps = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def n(state): return sum(1 for a in apps if a['state'] == state)
counts = {
  'total': len(apps),
  'up_to_date': n('up_to_date'),
  'updates_available': n('update_available'),
  'errors': n('error') + n('verification_failed'),
}
if counts['errors']:              overall = 'error'
elif counts['updates_available']: overall = 'updates_available'
elif n('unknown') and not counts['up_to_date']: overall = 'unknown'
elif counts['total']:             overall = 'up_to_date'
else:                             overall = 'unknown'
doc = {
  'schema_version': 1,
  'generated_at': g('PATCHED_RUN_FINISHED'),
  'device': {'hw_uuid': g('PATCHED_HW_UUID'), 'computer_name': g('PATCHED_COMPUTER_NAME')},
  'last_run': {
    'started_at': g('PATCHED_RUN_STARTED'), 'finished_at': g('PATCHED_RUN_FINISHED'),
    'trigger': g('PATCHED_RUN_TRIGGER'), 'installomator_tag': g('PATCHED_INSTALLOMATOR_TAG'),
  },
  'next_scheduled_run': g('PATCHED_NEXT_RUN_ISO') or None,
  'overall_state': overall,
  'counts': counts,
  'apps': apps,
}
# PAT-273: inject os_update section if available
os_update_file = sys.argv[3] if len(sys.argv) > 3 else ''
if os_update_file and os.path.exists(os_update_file):
    try:
        with open(os_update_file) as f:
            doc['os_update'] = json.load(f)
    except Exception:
        pass
# PAT-277: coexistence summary
brew_file = sys.argv[4] if len(sys.argv) > 4 else ''
managers_present = []
if brew_file and os.path.exists(brew_file):
    try:
        brew_data = json.load(open(brew_file))
        if brew_data.get('homebrew_present'):
            managers_present.append('homebrew')
    except Exception:
        pass
doc['coexistence'] = {
    'managers_present': managers_present,
    'also_managed_count': sum(1 for a in apps if a.get('also_managed_by') is not None),
}
# PAT-300: compliance findings — disk encryption
import subprocess
compliance_findings = []
try:
    r = subprocess.run(['/usr/bin/fdesetup', 'status'], capture_output=True, text=True, timeout=5)
    if 'FileVault is Off' in r.stdout:
        compliance_findings.append({'id': 'disk_encryption_off', 'severity': 'critical'})
except Exception:
    pass
# PAT-481: compliance findings — unencrypted removable storage
# Snapshot only: reflects volumes mounted at collect time. Volumes inserted after the
# run are not detected until the next scheduled scan. Third-party encryption (VeraCrypt)
# and hardware self-encrypting drives report as plaintext from the filesystem layer
# (diskutil cannot see their encryption) -- provenance_source records the tool used.
# No Full Disk Access required: diskutil info is readable by any process.
removable_vols = []
try:
    import plistlib
    dl = subprocess.run(
        ['/usr/sbin/diskutil', 'list', '-plist', 'external'],
        capture_output=True, timeout=10)
    if dl.returncode == 0 and dl.stdout:
        dl_data = plistlib.loads(dl.stdout)
        # AllDisks includes both whole-disk (disk3) and slice (disk3s1) entries.
        # We inspect each entry individually; diskutil info skips whole-disk nodes
        # that aren't mounted, so this is safe.
        for dev_id in dl_data.get('AllDisks', []):
            info_r = subprocess.run(
                ['/usr/sbin/diskutil', 'info', '-plist', dev_id],
                capture_output=True, timeout=10)
            if info_r.returncode != 0 or not info_r.stdout:
                continue
            info = plistlib.loads(info_r.stdout)
            mount = info.get('MountPoint', '') or ''
            # Only consider mounted, non-root volumes.
            if not mount or mount == '/':
                continue
            # Only external volumes (Internal == False or absent).
            if info.get('Internal', True):
                continue
            fs = info.get('FilesystemType', '') or ''
            fs_lower = fs.lower()
            filevault = info.get('FileVault', False)
            # FAT32 (msdos) / exFAT / HFS+ have no native encryption layer.
            # APFS without FileVault is stored in plaintext.
            if fs_lower in ('msdos', 'exfat', 'hfs'):
                enc_state = 'plaintext'
            elif fs_lower == 'apfs' and not filevault:
                enc_state = 'apfs_unencrypted'
            else:
                continue  # encrypted or filesystem type unknown -- not a finding
            removable_vols.append({
                'mount_point':       mount,
                'filesystem':        fs if fs else 'unknown',
                'encryption_state':  enc_state,
                'provenance_source': 'diskutil',
            })
except Exception:
    pass
if removable_vols:
    compliance_findings.append({
        'id':       'removable_storage_unencrypted',
        'severity': 'medium',
        'volumes':  removable_vols,
    })
if compliance_findings:
    doc['compliance_findings'] = compliance_findings
with open(sys.argv[2], 'w') as f: json.dump(doc, f, indent=2)
PYEOF

# World-readable so the user-scope menu bar app can read it; root-owned.
chmod 644 "$STATUS_TMP"
mv -f "$STATUS_TMP" "$STATUS_FILE"
rm -f "$APPS_NDJSON" "${OS_UPDATE_TMP:-}" "${BREW_COEX_TMP:-}"

echo "Status written to $STATUS_FILE"

# Drain any queued provenance records — covers failures from this run and
# all prior runs.  Runs after the status file is committed so a restart of
# this daemon mid-drain doesn't leave the status file in a partial state.
drain_provenance_queue
drain_events_queue  # PAT-499: flush SIEM audit event ring-buffer queue

log_jsonl "info" "update run completed" \
    "{\"mode\":\"$RUN_MODE\",\"trigger\":\"$RUN_TRIGGER\",\"labels_processed\":\"$_JSONL_LABEL_COUNT\"}"
echo "=== patched-update run finished $RUN_FINISHED ==="
