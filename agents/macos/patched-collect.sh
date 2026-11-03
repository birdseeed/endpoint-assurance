#!/bin/zsh
##############################################################################
# patched-collect
#
# macOS endpoint inventory + compliance collector.
# v1 component of the three-piece agent (collect / queue / upload).
#
# Deployment:
#   - Intune Platform Script, runs as root, recurring (daily).
#   - For unmanaged onboarding (v2), wrapped into a signed .pkg.
#
# Outputs:
#   /var/db/patched/queue/inventory-YYYYMMDD-HHMMSS.json   (one file per run)
#   /var/log/patched-collect.log                            (run history)
#
# The uploader (patched-upload, separate LaunchDaemon) drains the queue and
# POSTs to api.patched.im with HMAC + bearer auth. Each file is removed after
# successful upload.
#
# Tenant identity is provided via /etc/patched/tenant-id at install time
# (Intune deploys this as a configuration profile or via the same Platform
# Script). For testing it falls back to "UNKNOWN".
#
# Schema version 2 — adds hardware specs, extended CIS L1 compliance signals,
# detected security tools, system extensions, background items, iCloud state.
#
# Agent 0.3.0 adds (still schema_version 2 — fields are optional, old
# extractors silently ignore them):
#   pending_updates  — detailed list from `softwareupdate -l`
#   patches          — installed history from `softwareupdate --history --all`
#
# Agent 0.4.0 bumps to schema_version 3 — adds T2 compliance signals:
#   §5.2 pwpolicy_*       — 5 signals parsed from existing password_policy_raw
#   §1   update_*/_auto   — 5 signals from com.apple.SoftwareUpdate prefs
#
# Agent 0.5.0 stays on schema_version 3 — adds T2 batch 2 signals (schema_version
# unchanged because the compliance bag uses additionalProperties:true):
#   §2.3 sharing cluster  — smbd_disabled, printer_sharing_disabled,
#                           remote_management_disabled, internet_sharing_disabled
#   §4   network services — httpd_disabled, nfsd_disabled
#   §5   access control   — amfi_enabled, root_disabled
#
# Agent 0.7.0 stays on schema_version 3 — adds certificates:
#   certificates[]  — system keychain cert inventory with expiry visibility
#
# Agent 0.8.0 stays on schema_version 3 — adds hardware health:
#   hardware_health.battery    — battery cycle count, condition, max capacity %
#   hardware_health.storage[]  — real mounted volumes with byte counts and used_pct
#   hardware_health.disks[]    — physical disks with SMART status, internal, solid_state
#
# Agent 0.6.0 stays on schema_version 3 — adds T2 batch 3 signals:
#   §2.10 screensaver     — screensaver_delay_seconds (rule uses existing signal)
#   §2.9  power mgmt      — power_nap_disabled, wake_on_network_disabled
#   §3.5  audit perms     — audit_control_*(4), audit_folder_*(4), audit_logs_*(4)
#   §5.4/5.5 sudo         — sudo_timeout_minutes, sudo_timestamp_type
#
# Agent 0.11.0 stays on schema_version 3 — adds 38 CIS L1 gap signals (PAT-586):
#   lib/managed_prefs.sh — 16 signals via read_managed_pref JXA:
#     update_deferral_days, firewall_stealth_mode, airdrop_disabled,
#     airplay_receiver_disabled, time_server_host, time_server_enforced,
#     wifi_menu_visible, bluetooth_menu_visible, siri_disabled,
#     personalized_ads_disabled, loginwindow_text_set, loginwindow_fullname_prompt,
#     loginwindow_password_hints, guest_account_disabled, dictation_on_device,
#     firewall_logging
#     PAT-1720: each also has a <key>_enforced_by_profile companion (JSON
#     true/false from objectIsForcedForKey, null when the read failed); the
#     signal itself stays the effective value
#   lib/safari.sh — 6 signals via profiles -P -o stdout:
#     safari_auto_open_downloads_disabled, safari_fraudulent_warning,
#     safari_cross_site_tracking_blocked, safari_private_measurement,
#     safari_full_url_shown, safari_status_bar_shown
#   lib/filesystem.sh — 3 find-based signals:
#     home_folders_mode, system_apps_world_writable, system_folder_world_writable
#   lib/user_prefs.sh — 3 per-console-user signals:
#     bluetooth_sharing_disabled, show_file_extensions, terminal_secure_keyboard
#   sharing.sh additions — timed_running, smb_guest_disabled, time_machine_encrypted
#   security.sh additions — guest_folder_absent, xprotect_running
#   auth.sh additions — screensaver_unlock_group, system_prefs_admin_lock,
#     audit_retention_expire, install_log_retention_days, password_hints_absent
#
# Agent 0.10.0 stays on schema_version 3 — adds software metering (optional,
# additive per-app fields):
#   apps[].last_used_at  — Spotlight kMDItemLastUsedDate (ISO 8601); null = no
#                          recorded usage / metering unavailable
#   apps[].launch_count  — Spotlight kMDItemUseCount (lifetime cumulative)
#   metering_status      — ok | spotlight_disabled | no_user_session | unavailable.
#   apps[].usage_evidence — recorded | no_record | unavailable; no_record is not non-use.
#                          Distinguishes a successful empty read from an unavailable
#                          source. Neither state proves that software is unused.
#
# Agent 0.13.0 stays on schema_version 3 — adds compliance_findings[] (PAT-743),
# mirrored from the Windows agent's ComplianceFinding contract:
#   compliance_findings[]  — always present (empty array when clean). Only
#                            ever contains real violations:
#     disk_encryption_off              — FileVault reported "Off" (critical)
#     removable_storage_unencrypted    — unencrypted mounted removable volume(s)
#                                         detected via diskutil (medium);
#                                         includes volumes[] detail
#
# Agent 0.14.0 stays on schema_version 3 — adds backup_status (PAT-679):
#   backup_status  — Time Machine last-backup detection via tmutil, with
#                     OneDrive/iCloud flagged as sync_only (sync != backup)
#                     and third-party tools (Backblaze/Arq/CCC) detected by
#                     presence. stale=true when last_backup_days_ago > 7.
#
# Agent 0.15.0 stays on schema_version 3 — adds compliance_assessments (PAT-913,
# Option B). schema_version is deliberately UNCHANGED: this is an optional
# additive field that old servers ignore and old agents omit, the same
# precedent as the 0.3.0 and 0.5.0 optional additions above. The canonical
# schema for this field (payload.schema.json + PAYLOAD_SCHEMA.md) and its
# server-side enforcement (ValidatePayload rejects out-of-enum control IDs)
# live in Patched-LTD/patched.im PR #293 — that repo's contract is the
# authority; nothing here duplicates it.
#   compliance_assessments  — {"controls_assessed": [<finding-control ids>]}.
#                             Positive per-control attestation: the sole source
#                             of a Pass server-side (Pass iff a control is in
#                             controls_assessed AND absent from
#                             compliance_findings, which stays violations-only).
#                             An erroring sub-check drops its control from the
#                             list; the server then scores it Unknown, which for
#                             the critical disk-encryption rule fails
#                             (migration 0083, treat_unknown_as='fail').
#     controls_assessed[]  — subset of {disk_encryption_off,
#                             removable_storage_unencrypted} that ran a
#                             determination this cycle
#
# Agent 0.16.0 stays on schema_version 3 — adds applied_configuration (PAT-1667),
# vendor-agnostic and additive (old servers ignore it, old agents omit it):
#   applied_configuration.profiles[]      — device-scope configuration
#                             profiles applied to this Mac (identifier,
#                             display_name, organization, capped payload).
#                             This is APPLIED state, not authored MDM policy,
#                             and is only ever collected from Macs running
#                             this agent (not an estate coverage denominator).
#   applied_configuration.mdm_server_url  — ServerURL from the com.apple.mdm
#                             payload, if any (null when unenrolled)
#   applied_configuration.collection_status — ok | rate_limited | unavailable.
#                             rate_limited/unavailable fall back to the last
#                             successfully-collected result cached at
#                             $STATE_DIR/.config-profiles-last-good.json
#                             rather than failing the run.
#   applied_configuration.mdm_supervised  — from mdmclient DumpManagementStatus
#                             (undocumented, fail-soft; Unknown on any error)
#
# PAT-1767 (schema_version unchanged): compliance signals distinguish "the
# setting is absent" from "the read failed". A read that succeeded and found
# no setting now sends the exact string "NotConfigured" where it used to send
# null (or "Unknown" for the software update settings); a failed read still
# sends null (or "Unknown"). The server must accept and evaluate
# "NotConfigured" (treat_not_configured_as, defaulting to treat_unknown_as)
# before an agent carrying this change is released. Signals covered: see
# macos/README.md "Not configured versus not read".
#
# PAT-1775 (schema_version unchanged): numeric compliance signals follow the
# same contract. update_deferral_days, screensaver_idle_seconds and
# install_log_retention_days send a bare JSON integer, the JSON string
# "NotConfigured", or null, emitted through json_int_or_notconfigured
# (lib/common.sh) so a string never lands unquoted in the payload.
#
# PAT-1752 (schema_version unchanged): macOS now emits the platform-neutral
# mdm_enrolled = Yes|No|Unknown signal used by both endpoint platforms, with
# mdm_enrolled_via_dep as separate enrolment provenance. The combined
# mdm_enrolment string remains for one compatibility release only.
#
# Structure:
#   This file is the thin orchestrator. Collection logic lives in lib/*.sh,
#   each of which defines one collect_<module>() function. The deployed
#   artifact (dist/patched-collect.sh) is a single-file bundle produced by
#   build-bundle.sh which inlines the lib/*.sh content.
##############################################################################

# Strict-mode bash is too brittle here — macOS ships many "fake binaries"
# (Google Docs/Sheets/Slides shortcuts, alias-style apps) that trip tools like
# `lipo` with non-zero exits, which would silently abort the run under
# `set -euo pipefail`. We keep `-u` to catch genuinely undefined variables,
# but tolerate non-zero exits from external tooling.
set -u

# Silence "no matches found" errors on globs that may legitimately match
# zero files (e.g. the BTM background-items file doesn't exist on a Mac
# that has never approved a third-party background item).
setopt NULL_GLOB

# Sudo on some macOS configurations strips PATH to a value that doesn't
# include /bin or /usr/bin (this has been observed on systems with custom
# /etc/sudoers or MDM-managed sudoers configs). Force a fixed PATH so basic
# Unix utilities resolve reliably regardless of what we inherit.
#
# SECURITY (H10): this daemon runs as root. We deliberately exclude
# /usr/local/{sbin,bin} (writable by non-root users on many Macs) and do NOT
# append the inherited ${PATH}, so a local attacker cannot shadow a system
# binary (curl/dscl/security/openssl) we invoke by name.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

STATE_DIR="/var/db/patched"
QUEUE_DIR="$STATE_DIR/queue"
LOG_FILE="/var/log/patched-collect.log"
TENANT_ID_FILE="/etc/patched/tenant-id"

mkdir -p "$QUEUE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# SECURITY (H11): all intermediate files (collector-module scratch, JSON
# assembly, diagnostics) live in a per-run, root-owned, 0700, unpredictably
# named directory under $STATE_DIR — never in world-writable /tmp with a
# predictable PID-based name. That closes the symlink/TOCTOU window where a
# local attacker could pre-create /tmp/.patched-*.$$ and have this root daemon
# follow it. mktemp -d yields 0700 and an unguessable name; the EXIT trap
# removes the whole tree. $STATE_DIR is under /var/db (root-owned), so the
# parent cannot be hijacked. Modules use: mktemp "$PATCHED_TMPDIR/<name>.XXXXXX".
PATCHED_TMPDIR=$(mktemp -d "$STATE_DIR/.run.XXXXXXXX") || {
    echo "FATAL: could not create secure temp dir under $STATE_DIR" >&2
    exit 1
}
chmod 700 "$PATCHED_TMPDIR"
trap 'rm -rf "$PATCHED_TMPDIR"' EXIT

exec > >(tee -a "$LOG_FILE") 2>&1

TS_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TS_FILE=$(date -u +%Y%m%d-%H%M%S)
OUT="$QUEUE_DIR/inventory-$TS_FILE.json"
TMP="$QUEUE_DIR/.inventory-$TS_FILE.tmp"

echo "=== patched-collect run started at $TS_UTC ==="

# ---------------------------------------------------------------------------
# PYTHON3 RESOLUTION
# ---------------------------------------------------------------------------
#
# Sudo strips PATH. Rather than rely on PATH lookup, we resolve python3 to an
# absolute path once and reference it explicitly throughout. Apple's stock
# python3 at /usr/bin/python3 is always present with the Command Line Tools,
# so it is the only path we use; no package-manager fallback.

PYTHON3="/usr/bin/python3"
if [[ ! -x "$PYTHON3" ]]; then
    echo "FATAL: no usable python3 found at $PYTHON3"
    exit 1
fi
echo "Using python3 at: $PYTHON3"

# ---------------------------------------------------------------------------
# STRUCTURED LOGGING HELPERS (PAT-652)
# Writes JSON-lines to /Library/Logs/Patched/collect.jsonl alongside the
# existing plain-text log. Never log bearer_token, hmac_secret, or proxy creds.
# ---------------------------------------------------------------------------

JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_FILE="$JSONL_LOG_DIR/collect.jsonl"
JSONL_COMPONENT="collect"

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

# ---------------------------------------------------------------------------
# TENANT IDENTITY
# ---------------------------------------------------------------------------

if [[ -f "$TENANT_ID_FILE" ]]; then
    TENANT_ID=$(head -1 "$TENANT_ID_FILE" | tr -d '[:space:]')
else
    TENANT_ID="UNKNOWN"
fi

# ---------------------------------------------------------------------------
# MODULE SOURCES
# ---------------------------------------------------------------------------

SCRIPT_DIR="${0:A:h}"
LIB_DIR="$SCRIPT_DIR/lib"

source "${LIB_DIR}/common.sh"
# PAT-2096: the shared agent_health store, so a collector can record a fault
# (browser_extensions: Full Disk Access missing) that patched-upload.sh then
# reports as agent_health.degraded. Functions only; needs PYTHON3, set above.
source "${LIB_DIR}/agent_health.sh"
source "${LIB_DIR}/hardware.sh"
source "${LIB_DIR}/os.sh"
source "${LIB_DIR}/security.sh"
source "${LIB_DIR}/compliance_findings.sh"
source "${LIB_DIR}/updates.sh"
source "${LIB_DIR}/sharing.sh"
source "${LIB_DIR}/screensaver.sh"
source "${LIB_DIR}/auth.sh"
source "${LIB_DIR}/sectools.sh"
source "${LIB_DIR}/certs.sh"
source "${LIB_DIR}/inventory.sh"
source "${LIB_DIR}/backup.sh"
source "${LIB_DIR}/apps.sh"
source "${LIB_DIR}/hardware_health.sh"
source "${LIB_DIR}/browser_extensions.sh"
source "${LIB_DIR}/managed_prefs.sh"
source "${LIB_DIR}/safari.sh"
source "${LIB_DIR}/filesystem.sh"
source "${LIB_DIR}/user_prefs.sh"
source "${LIB_DIR}/config_profiles.sh"
source "${LIB_DIR}/homebrew.sh"
source "${LIB_DIR}/ide_extensions.sh"
source "${LIB_DIR}/package_managers.sh"
source "${LIB_DIR}/local_models.sh"
source "${LIB_DIR}/mcp_servers.sh"

# ---------------------------------------------------------------------------
# COLLECTION
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DEFENSIVE PRE-INITIALISATION (PAT-706 — robustness layer)
#
# Initialise EVERY variable referenced in the JSON-assembly heredoc to a
# schema-correct default BEFORE running any collect_* module.  Each module
# overwrites these with real values when it succeeds; if a module fails
# entirely on macOS 26 (source failure, early function exit, command-not-
# found) the heredoc still produces valid JSON — no empty fields, no set -u
# abort.
#
# File-path variables (consumed via $(cat "$VAR")): stub file created with
# content appropriate for the field's schema type.  collect_* functions that
# own these vars overwrite the variable to point at their real output file;
# the stub file is cleaned up by the EXIT trap on $PATCHED_TMPDIR.
#
# String/numeric defaults follow the field's JSON schema type:
#   required string  → "Unknown" (json_escape → "Unknown")
#   optional signal  → ""        (json_or_null → null)
#   numeric          → already guarded in the heredoc via ${VAR:-0/null}
#   boolean-string   → "Unknown" (or schema-appropriate "No"/"Yes")
# ---------------------------------------------------------------------------

# --- File-path stub vars (consumed via $(cat "$VAR") in the heredoc) -------
SECURITY_TOOLS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/sectools-stub.XXXXXX")
printf '[]' > "$SECURITY_TOOLS_JSON_TMP"
CERTS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/certs-stub.XXXXXX")
printf '[]' > "$CERTS_JSON_TMP"
# PAT-1709 / PAT-1732: the stub is not a reading. Until collect_certs has read
# the System keychain, certs_payload_member omits the "certificates" key and
# collection_status.certificates is "unavailable" (server writes nothing),
# rather than sending [] (server prunes every row).
CERTS_COLLECTION_STATUS="unavailable"
CERTS_COLLECTED_COUNT=0
# PAT-1720: the stub is not a reading either. Every section is unavailable
# until collect_hardware_health replaces it, so the server keeps its stored
# battery, storage and disk rows instead of treating the empty stub as "none".
HARDWARE_HEALTH_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/hw-health-stub.XXXXXX")
printf '{"battery":{"present":false},"storage":[],"disks":[],"collection_status":{"battery":"unavailable","storage":"unavailable","disks":"unavailable"}}' > "$HARDWARE_HEALTH_JSON_TMP"
BROWSER_EXTENSIONS_JSON_FILE=$(mktemp "$PATCHED_TMPDIR/browser-ext-stub.XXXXXX")
printf '[]' > "$BROWSER_EXTENSIONS_JSON_FILE"
# PAT-2065: the stub is not a reading. Until collect_browser_extensions has
# composed the block, browser_extensions_status says failed, which grants the
# server no absence authority, rather than letting [] read as "none".
BROWSER_EXTENSIONS_STATUS_FILE=$(mktemp "$PATCHED_TMPDIR/browser-ext-status-stub.XXXXXX")
printf '{"collection_status":"failed"}' > "$BROWSER_EXTENSIONS_STATUS_FILE"
# PAT-2067: nor is it a Safari reading. collection_status.safari_extensions
# is unavailable until the Safari walk has finished, so a collector that dies
# first never tells the server every stored Safari extension is gone.
SAFARI_EXTENSIONS_COLLECTION_STATUS="unavailable"
COMPLIANCE_FINDINGS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/compliance-findings-stub.XXXXXX")
printf '[]' > "$COMPLIANCE_FINDINGS_JSON_TMP"
# compliance_assessments stub: empty controls_assessed = attests nothing, which
# scores every finding-control Unknown (fail-unknown on the critical rules).
# collect_compliance_findings overwrites this once it has run its determinations.
COMPLIANCE_ASSESSMENTS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/compliance-assessments-stub.XXXXXX")
printf '{"controls_assessed": []}' > "$COMPLIANCE_ASSESSMENTS_JSON_TMP"
BACKUP_STATUS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/backup-status-stub.XXXXXX")
printf '{"has_backup":false,"backup_type":null,"last_backup_at":null,"last_backup_days_ago":null,"stale":false,"sync_only":false,"notes":null}' > "$BACKUP_STATUS_JSON_TMP"
# APPS_JSON_FILE: stub with an empty array; collect_apps() overwrites the var.
APPS_JSON_FILE=$(mktemp "$PATCHED_TMPDIR/apps-stub.XXXXXX")
printf '[]' > "$APPS_JSON_FILE"
# PAT-2066: the stub is not a reading. Until collect_apps has finished its
# walk, collection_status.apps is unavailable and apps is sent as [], so the
# server keeps every stored app rather than reading [] as "all removed".
APPS_COLLECTION_STATUS="unavailable"
APPS_USERS_JSON='[]'
CONFIG_PROFILES_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/config-profiles-stub.XXXXXX")
printf '[]' > "$CONFIG_PROFILES_JSON_TMP"

# --- collect_hardware -------------------------------------------------------
SERIAL="Unknown"
HW_UUID="Unknown"
HOSTNAME="Unknown"
COMPUTER_NAME="Unknown"
HW_MODEL="Unknown"
ARCH="Unknown"
CPU_MODEL="Unknown"
CPU_CORES=0
RAM_GB=0
DISK_TOTAL_GB=0
DISK_FREE_GB=0

# --- collect_os -------------------------------------------------------------
OS_NAME="Unknown"
OS_VERSION="Unknown"
OS_BUILD="Unknown"
LAST_BOOT_ISO="Unknown"
POWER_NAP_DISABLED="Unknown"
WAKE_ON_NETWORK_DISABLED="Unknown"

# --- collect_security -------------------------------------------------------
FILEVAULT="Unknown"
SIP="Unknown"
GATEKEEPER="Unknown"
FW_STATE="Unknown"
XPROTECT_VER="Unknown"
MRT_VER="Unknown"
SSV="Unknown"
SECURE_BOOT="Unknown"
AMFI_ENABLED="Unknown"
GUEST_FOLDER_ABSENT="Unknown"
XPROTECT_RUNNING="Unknown"

# --- collect_updates --------------------------------------------------------
PENDING_UPDATES_COUNT=0
PENDING_UPDATES_JSON="[]"
PATCHES_JSON="[]"
AUTO_SECURITY_UPDATES="Unknown"
UPDATE_CHECK_AUTO="Unknown"
UPDATE_DOWNLOAD_AUTO="Unknown"
APP_UPDATES_AUTO_INSTALL="Unknown"
XPROTECT_DATA_AUTO_UPDATE="Unknown"
CRITICAL_UPDATES_AUTO_INSTALL="Unknown"

# --- collect_sharing --------------------------------------------------------
REMOTE_APPLE_EVENTS="Unknown"
REMOTE_LOGIN="Unknown"
SCREEN_SHARING="Unknown"
SMBD_DISABLED="Unknown"
PRINTER_SHARING_DISABLED="Unknown"
REMOTE_MANAGEMENT_DISABLED="Unknown"
INTERNET_SHARING_DISABLED="Unknown"
HTTPD_DISABLED="Unknown"
NFSD_DISABLED="Unknown"
TIMED_RUNNING="Unknown"
SMB_GUEST_DISABLED="Unknown"
TIME_MACHINE_ENCRYPTED=""   # null until read; "NotConfigured" when TM has no destinations (PAT-1767)

# --- collect_screensaver ----------------------------------------------------
SCREENSAVER_PASSWORD="Unknown"
SCREENSAVER_DELAY_SECONDS=""   # null when key absent from plist
SCREENSAVER_IDLE_SECONDS=""    # PAT-1753: null when not positively read; 99999 = never; "NotConfigured" when unset (PAT-1775)
SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE=""

# --- collect_auth -----------------------------------------------------------
MDM_ENROLMENT="Unknown"
AUDIT_LOGGING="Unknown"
AUTO_LOGIN_USER="None"
# PAT-1974: the stub is not a reading. Until _collect_local_admins has read
# /Groups/admin the count is null (json_int_or_notconfigured of "") and
# local_admins is "unavailable" with no accounts key, rather than a 0 that
# passes CIS 5.8 and an [] that prunes the stored roster.
LOCAL_ADMIN_COUNT=""
LOCAL_ADMIN_ACCOUNTS=()
LOCAL_ADMIN_COLLECTION_STATUS="unavailable"
PW_POLICY_PRESENT="Unknown"
PW_POLICY_IS_DEFAULT="Unknown"
PW_POLICY_RAW=""
PWPOLICY_LOCKOUT_THRESHOLD=""
PWPOLICY_LOCKOUT_RESET_MINUTES=""
PWPOLICY_MIN_LENGTH=""
PWPOLICY_MAX_AGE_DAYS=""
PWPOLICY_HISTORY_DEPTH=""
ROOT_DISABLED="Unknown"
AUDIT_CONTROL_NO_ACL=""
AUDIT_CONTROL_OWNER=""
AUDIT_CONTROL_GROUP=""
AUDIT_CONTROL_MODE=""
AUDIT_FOLDER_NO_ACL=""
AUDIT_FOLDER_OWNER=""
AUDIT_FOLDER_GROUP=""
AUDIT_FOLDER_MODE=""
AUDIT_LOGS_NO_ACL=""
AUDIT_LOGS_OWNER=""
AUDIT_LOGS_GROUP=""
AUDIT_LOGS_MODE=""
SUDO_TIMEOUT_MINUTES=""
SUDO_TIMESTAMP_TYPE=""
SCREENSAVER_UNLOCK_GROUP=""
SYSTEM_PREFS_ADMIN_LOCK=""
AUDIT_RETENTION_EXPIRE=""
INSTALL_LOG_RETENTION_DAYS=""   # null until read; "NotConfigured" when no ttl is set (PAT-1775)
PASSWORD_HINTS_ABSENT=""

# --- collect_inventory ------------------------------------------------------
SYSEXT_JSON="[]"
BACKGROUND_ITEMS_JSON="[]"
ICLOUD_SIGNED_IN="Unknown"

# --- collect_apps (METERING_STATUS; APPS_JSON_FILE stubbed above) -----------
# A collector that did not finish says unavailable, never that indexing is off.
METERING_STATUS="unavailable"

# --- collect_managed_prefs --------------------------------------------------
UPDATE_DEFERRAL_DAYS=""   # null until read; "NotConfigured" when no deferral is set (PAT-1775)
FIREWALL_STEALTH_MODE=""
AIRDROP_DISABLED=""
AIRPLAY_RECEIVER_DISABLED=""
TIME_SERVER_HOST=""
TIME_SERVER_ENFORCED=""
WIFI_MENU_VISIBLE=""
BLUETOOTH_MENU_VISIBLE=""
SIRI_DISABLED=""
PERSONALIZED_ADS_DISABLED=""
LOGINWINDOW_TEXT_SET=""
LOGINWINDOW_FULLNAME_PROMPT=""
LOGINWINDOW_PASSWORD_HINTS=""
GUEST_ACCOUNT_DISABLED=""
DICTATION_ON_DEVICE=""
FIREWALL_LOGGING=""
# PAT-1720: companion <SIGNAL>_ENFORCED_BY_PROFILE flags. "" emits null
# (undetermined), so a module that never ran never claims "not enforced".
UPDATE_DEFERRAL_DAYS_ENFORCED_BY_PROFILE=""
FIREWALL_STEALTH_MODE_ENFORCED_BY_PROFILE=""
AIRDROP_DISABLED_ENFORCED_BY_PROFILE=""
AIRPLAY_RECEIVER_DISABLED_ENFORCED_BY_PROFILE=""
TIME_SERVER_HOST_ENFORCED_BY_PROFILE=""
TIME_SERVER_ENFORCED_ENFORCED_BY_PROFILE=""
WIFI_MENU_VISIBLE_ENFORCED_BY_PROFILE=""
BLUETOOTH_MENU_VISIBLE_ENFORCED_BY_PROFILE=""
SIRI_DISABLED_ENFORCED_BY_PROFILE=""
PERSONALIZED_ADS_DISABLED_ENFORCED_BY_PROFILE=""
LOGINWINDOW_TEXT_SET_ENFORCED_BY_PROFILE=""
LOGINWINDOW_FULLNAME_PROMPT_ENFORCED_BY_PROFILE=""
LOGINWINDOW_PASSWORD_HINTS_ENFORCED_BY_PROFILE=""
GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE=""
DICTATION_ON_DEVICE_ENFORCED_BY_PROFILE=""
FIREWALL_LOGGING_ENFORCED_BY_PROFILE=""

# --- collect_safari ---------------------------------------------------------
# These are set in both if/else branches of collect_safari(); the explicit
# pre-init here guarantees a bound value if the module fails on macOS 26
# (e.g. profiles command absent or output format changed — see Layer 2 note
# in safari.sh).  Empty string → json_or_null → null in payload.
SAFARI_AUTO_OPEN_DOWNLOADS_DISABLED=""
SAFARI_FRAUDULENT_WARNING=""
SAFARI_CROSS_SITE_TRACKING_BLOCKED=""
SAFARI_PRIVATE_MEASUREMENT=""
SAFARI_FULL_URL_SHOWN=""
SAFARI_STATUS_BAR_SHOWN=""

# --- collect_filesystem -----------------------------------------------------
HOME_FOLDERS_MODE=""
SYSTEM_APPS_WORLD_WRITABLE=""
SYSTEM_FOLDER_WORLD_WRITABLE=""

# --- collect_user_prefs -----------------------------------------------------
BLUETOOTH_SHARING_DISABLED=""
SHOW_FILE_EXTENSIONS=""
TERMINAL_SECURE_KEYBOARD=""

# --- collect_config_profiles (PAT-1667; CONFIG_PROFILES_JSON_TMP stubbed
# by the module itself since it needs PATCHED_TMPDIR, which exists by now) --
CONFIG_PROFILES_COUNT=0
CONFIG_PROFILES_TRUNCATED="false"
CONFIG_PROFILES_STATUS="unavailable"
MDM_SERVER_URL=""
MDM_SUPERVISED="Unknown"

# --- collect_homebrew (PAT-2012) --------------------------------------------
# The stub is not a reading: failed until collect_homebrew has read the
# prefixes, so a module that never ran can never look like "no packages".
# On the wire since PAT-2032 (see lib/homebrew.sh).
HOMEBREW_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/homebrew-stub.XXXXXX")
printf '{"collection_status": "failed"}' > "$HOMEBREW_JSON_TMP"
HOMEBREW_COLLECTION_STATUS="failed"
HOMEBREW_FORMULA_COUNT=0
HOMEBREW_CASK_COUNT=0
HOMEBREW_TAP_COUNT=0

# --- collect_ide_extensions (PAT-2017) ---------------------------------------
# Same stub rule: failed until collect_ide_extensions has read the homes, so a
# module that never ran can never look like "no extensions". On the wire since
# PAT-2225 (see lib/ide_extensions.sh).
IDE_EXTENSIONS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/ide-extensions-stub.XXXXXX")
printf '{"collection_status": "failed"}' > "$IDE_EXTENSIONS_JSON_TMP"
IDE_EXTENSIONS_COLLECTION_STATUS="failed"
IDE_EXTENSIONS_COUNT=0
IDE_EXTENSIONS_PROFILE_COUNT=0
IDE_EXTENSIONS_USER_COUNT=0

# --- collect_package_managers (PAT-2018) -------------------------------------
# Same stub rule: failed until collect_package_managers has read the homes, so
# a module that never ran can never look like "no packages". On the wire since
# PAT-2225 (see lib/package_managers.sh).
PACKAGE_MANAGERS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/package-managers-stub.XXXXXX")
printf '{"collection_status": "failed"}' > "$PACKAGE_MANAGERS_JSON_TMP"
PACKAGE_MANAGERS_COLLECTION_STATUS="failed"

# --- collect_local_models (PAT-2019) -----------------------------------------
# Same stub rule: failed until collect_local_models has read the machine and
# the homes, so a module that never ran can never look like "no models". On
# the wire since PAT-2225 (see lib/local_models.sh).
LOCAL_MODELS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/local-models-stub.XXXXXX")
printf '{"collection_status": "failed"}' > "$LOCAL_MODELS_JSON_TMP"
LOCAL_MODELS_COLLECTION_STATUS="failed"

# --- collect_mcp_servers (PAT-2020) ------------------------------------------
# Same stub rule: failed until collect_mcp_servers has read the homes, so a
# module that never ran can never look like "no MCP servers". On the wire
# since PAT-2225 (see lib/mcp_servers.sh).
MCP_SERVERS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/mcp-servers-stub.XXXXXX")
printf '{"collection_status": "failed"}' > "$MCP_SERVERS_JSON_TMP"
MCP_SERVERS_COLLECTION_STATUS="failed"

log_jsonl "info" "collect scan started"
collect_hardware
collect_os
collect_security

# Patched: PAT-493 Item 5 — Gatekeeper preflight posture signal.
# spctl --status output is already captured in $GATEKEEPER by collect_security
# (lib/security.sh) and included in the "gatekeeper" field of the compliance
# payload below. This block adds an explicit stderr warning when Gatekeeper is
# disabled, so the warning appears in /var/log/patched-collect.log regardless
# of the upload outcome. Non-fatal: Gatekeeper may be legitimately disabled on
# MDM-managed devices that use a different enforcement mechanism.
if [[ "${GATEKEEPER:-}" == "disabled" ]]; then
    echo "PATCHED_POSTURE_WARNING reason=gatekeeper_disabled hw_uuid=${HW_UUID:-unknown}" >&2
fi

collect_compliance_findings
collect_updates
collect_sharing
collect_screensaver
collect_auth
collect_sectools
collect_certs
collect_inventory
collect_backup_status
collect_apps
collect_hardware_health
collect_browser_extensions
collect_managed_prefs
collect_safari
collect_filesystem
collect_user_prefs
collect_config_profiles
collect_homebrew
collect_ide_extensions
collect_package_managers
collect_local_models
collect_mcp_servers

# ---------------------------------------------------------------------------
# PRIMARY USER (PAT-116)
# Collect the current console user as this run's primary-user sample.
# Filter out root, loginwindow, and empty string — same pattern as
# apps.sh:65-71 (METERING_CONSOLE_USER) to avoid misleading entries.
#
# TODO(PAT-116): implement 30-day most-frequent aggregation. For v1 we emit
# today's console user as a single sample; daily windowing will layer on
# once the field is flowing end-to-end.
# ---------------------------------------------------------------------------
PRIMARY_USER_ACCOUNT=$(console_user)
case "$PRIMARY_USER_ACCOUNT" in
    root|loginwindow|"") PRIMARY_USER_ACCOUNT="" ;;
esac

# ---------------------------------------------------------------------------
# ASSEMBLE FINAL JSON
# ---------------------------------------------------------------------------

cat > "$TMP" <<EOF
{
  "schema_version": 3,
  "platform": "macos",
  "agent": "patched-collect",
  "agent_version": "__PATCHED_AGENT_VERSION__",
  "tenant_id":     $(json_escape "${TENANT_ID:-UNKNOWN}"),
  "collected_at":  $(json_escape "${TS_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"),
  "metering_status": $(json_escape "${METERING_STATUS:-unavailable}"),
  "primary_user": {
    "account": $(json_escape "$PRIMARY_USER_ACCOUNT"),
    "source":  "console"
  },
  "device": {
    "serial":        $(json_escape "$SERIAL"),
    "hw_uuid":       $(json_escape "$HW_UUID"),
    "hostname":      $(json_escape "$HOSTNAME"),
    "computer_name": $(json_escape "$COMPUTER_NAME"),
    "hw_model":      $(json_escape "$HW_MODEL"),
    "arch":          $(json_escape "$ARCH"),
    "last_boot":     $(json_escape "$LAST_BOOT_ISO")
  },
  "hardware": {
    "cpu_model":     $(json_escape "$CPU_MODEL"),
    "cpu_cores":     ${CPU_CORES:-0},
    "ram_gb":        ${RAM_GB:-0},
    "disk_total_gb": ${DISK_TOTAL_GB:-0},
    "disk_free_gb":  ${DISK_FREE_GB:-0}
  },
  "os": {
    "name":    $(json_escape "$OS_NAME"),
    "version": $(json_escape "$OS_VERSION"),
    "build":   $(json_escape "$OS_BUILD")
  },
  "compliance": {
    "filevault":                   $(json_escape "$FILEVAULT"),
    "sip":                         $(json_escape "$SIP"),
    "gatekeeper":                  $(json_escape "$GATEKEEPER"),
    "firewall":                    $(json_escape "$FW_STATE"),
    "xprotect_version":            $(json_escape "$XPROTECT_VER"),
    "mrt_version":                 $(json_escape "$MRT_VER"),
    "pending_updates_count":       ${PENDING_UPDATES_COUNT:-0},
    "mdm_enrolled":                $(json_escape "$MDM_ENROLLED"),
    "mdm_enrolled_via_dep":        $(json_escape "$MDM_ENROLLED_VIA_DEP"),
    "mdm_enrolment":               $(json_escape "$MDM_ENROLMENT"),
    "secure_boot":                 $(json_escape "$SECURE_BOOT"),
    "auto_security_updates":       $(json_escape "$AUTO_SECURITY_UPDATES"),
    "audit_logging":               $(json_escape "$AUDIT_LOGGING"),
    "remote_apple_events":         $(json_escape "$REMOTE_APPLE_EVENTS"),
    "remote_login":                $(json_escape "$REMOTE_LOGIN"),
    "screen_sharing":              $(json_escape "$SCREEN_SHARING"),
    "sealed_system_volume":        $(json_escape "$SSV"),
    "screensaver_password":        $(json_escape "$SCREENSAVER_PASSWORD"),
    "screensaver_delay_seconds":   ${SCREENSAVER_DELAY_SECONDS:-null},
    "screensaver_idle_seconds":    $(json_int_or_notconfigured "$SCREENSAVER_IDLE_SECONDS"),
    "screensaver_idle_seconds_enforced_by_profile": $(json_bool_or_null "${SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE}"),
    "auto_login_user":             $(json_escape "$AUTO_LOGIN_USER"),
    "local_admin_count":           $(json_int_or_notconfigured "$LOCAL_ADMIN_COUNT"),
    "password_policy_present":       $(json_escape "$PW_POLICY_PRESENT"),
    "password_policy_is_default":    $(json_escape "$PW_POLICY_IS_DEFAULT"),
    "password_policy_raw":           $(json_escape "$PW_POLICY_RAW"),
    "pwpolicy_lockout_threshold":    ${PWPOLICY_LOCKOUT_THRESHOLD:-null},
    "pwpolicy_lockout_reset_minutes": ${PWPOLICY_LOCKOUT_RESET_MINUTES:-null},
    "pwpolicy_min_length":           ${PWPOLICY_MIN_LENGTH:-null},
    "pwpolicy_max_age_days":         ${PWPOLICY_MAX_AGE_DAYS:-null},
    "pwpolicy_history_depth":        ${PWPOLICY_HISTORY_DEPTH:-null},
    "update_check_auto":             $(json_escape "$UPDATE_CHECK_AUTO"),
    "update_download_auto":          $(json_escape "$UPDATE_DOWNLOAD_AUTO"),
    "app_updates_auto_install":      $(json_escape "$APP_UPDATES_AUTO_INSTALL"),
    "xprotect_data_auto_update":     $(json_escape "$XPROTECT_DATA_AUTO_UPDATE"),
    "critical_updates_auto_install": $(json_escape "$CRITICAL_UPDATES_AUTO_INSTALL"),
    "smbd_disabled":              $(json_escape "$SMBD_DISABLED"),
    "printer_sharing_disabled":   $(json_escape "$PRINTER_SHARING_DISABLED"),
    "remote_management_disabled": $(json_escape "$REMOTE_MANAGEMENT_DISABLED"),
    "internet_sharing_disabled":  $(json_escape "$INTERNET_SHARING_DISABLED"),
    "httpd_disabled":             $(json_escape "$HTTPD_DISABLED"),
    "nfsd_disabled":              $(json_escape "$NFSD_DISABLED"),
    "amfi_enabled":               $(json_escape "$AMFI_ENABLED"),
    "root_disabled":              $(json_escape "$ROOT_DISABLED"),
    "power_nap_disabled":         $(json_escape "$POWER_NAP_DISABLED"),
    "wake_on_network_disabled":   $(json_escape "$WAKE_ON_NETWORK_DISABLED"),
    "audit_control_no_acl":       $(json_or_null "$AUDIT_CONTROL_NO_ACL"),
    "audit_control_owner":        $(json_or_null "$AUDIT_CONTROL_OWNER"),
    "audit_control_group":        $(json_or_null "$AUDIT_CONTROL_GROUP"),
    "audit_control_mode":         $(json_or_null "$AUDIT_CONTROL_MODE"),
    "audit_folder_no_acl":        $(json_or_null "$AUDIT_FOLDER_NO_ACL"),
    "audit_folder_owner":         $(json_or_null "$AUDIT_FOLDER_OWNER"),
    "audit_folder_group":         $(json_or_null "$AUDIT_FOLDER_GROUP"),
    "audit_folder_mode":          $(json_or_null "$AUDIT_FOLDER_MODE"),
    "audit_logs_no_acl":          $(json_or_null "$AUDIT_LOGS_NO_ACL"),
    "audit_logs_owner":           $(json_or_null "$AUDIT_LOGS_OWNER"),
    "audit_logs_group":           $(json_or_null "$AUDIT_LOGS_GROUP"),
    "audit_logs_mode":            $(json_or_null "$AUDIT_LOGS_MODE"),
    "sudo_timeout_minutes":       ${SUDO_TIMEOUT_MINUTES:-null},
    "sudo_timestamp_type":        $(json_or_null "$SUDO_TIMESTAMP_TYPE"),
    "screensaver_unlock_group":   $(json_or_null "$SCREENSAVER_UNLOCK_GROUP"),
    "system_prefs_admin_lock":    $(json_or_null "$SYSTEM_PREFS_ADMIN_LOCK"),
    "audit_retention_expire":     $(json_or_null "$AUDIT_RETENTION_EXPIRE"),
    "install_log_retention_days": $(json_int_or_notconfigured "$INSTALL_LOG_RETENTION_DAYS"),
    "password_hints_absent":      $(json_or_null "$PASSWORD_HINTS_ABSENT"),
    "update_deferral_days":       $(json_int_or_notconfigured "$UPDATE_DEFERRAL_DAYS"),
    "firewall_stealth_mode":      $(json_or_null "$FIREWALL_STEALTH_MODE"),
    "airdrop_disabled":           $(json_or_null "$AIRDROP_DISABLED"),
    "airplay_receiver_disabled":  $(json_or_null "$AIRPLAY_RECEIVER_DISABLED"),
    "time_server_host":           $(json_or_null "$TIME_SERVER_HOST"),
    "time_server_enforced":       $(json_or_null "$TIME_SERVER_ENFORCED"),
    "wifi_menu_visible":          $(json_or_null "$WIFI_MENU_VISIBLE"),
    "bluetooth_menu_visible":     $(json_or_null "$BLUETOOTH_MENU_VISIBLE"),
    "siri_disabled":              $(json_or_null "$SIRI_DISABLED"),
    "personalized_ads_disabled":  $(json_or_null "$PERSONALIZED_ADS_DISABLED"),
    "loginwindow_text_set":       $(json_or_null "$LOGINWINDOW_TEXT_SET"),
    "loginwindow_fullname_prompt": $(json_or_null "$LOGINWINDOW_FULLNAME_PROMPT"),
    "loginwindow_password_hints": $(json_or_null "$LOGINWINDOW_PASSWORD_HINTS"),
    "guest_account_disabled":     $(json_or_null "$GUEST_ACCOUNT_DISABLED"),
    "dictation_on_device":        $(json_or_null "$DICTATION_ON_DEVICE"),
    "firewall_logging":           $(json_or_null "$FIREWALL_LOGGING"),
    "update_deferral_days_enforced_by_profile": $(json_bool_or_null "${UPDATE_DEFERRAL_DAYS_ENFORCED_BY_PROFILE}"),
    "firewall_stealth_mode_enforced_by_profile": $(json_bool_or_null "${FIREWALL_STEALTH_MODE_ENFORCED_BY_PROFILE}"),
    "airdrop_disabled_enforced_by_profile": $(json_bool_or_null "${AIRDROP_DISABLED_ENFORCED_BY_PROFILE}"),
    "airplay_receiver_disabled_enforced_by_profile": $(json_bool_or_null "${AIRPLAY_RECEIVER_DISABLED_ENFORCED_BY_PROFILE}"),
    "time_server_host_enforced_by_profile": $(json_bool_or_null "${TIME_SERVER_HOST_ENFORCED_BY_PROFILE}"),
    "time_server_enforced_enforced_by_profile": $(json_bool_or_null "${TIME_SERVER_ENFORCED_ENFORCED_BY_PROFILE}"),
    "wifi_menu_visible_enforced_by_profile": $(json_bool_or_null "${WIFI_MENU_VISIBLE_ENFORCED_BY_PROFILE}"),
    "bluetooth_menu_visible_enforced_by_profile": $(json_bool_or_null "${BLUETOOTH_MENU_VISIBLE_ENFORCED_BY_PROFILE}"),
    "siri_disabled_enforced_by_profile": $(json_bool_or_null "${SIRI_DISABLED_ENFORCED_BY_PROFILE}"),
    "personalized_ads_disabled_enforced_by_profile": $(json_bool_or_null "${PERSONALIZED_ADS_DISABLED_ENFORCED_BY_PROFILE}"),
    "loginwindow_text_set_enforced_by_profile": $(json_bool_or_null "${LOGINWINDOW_TEXT_SET_ENFORCED_BY_PROFILE}"),
    "loginwindow_fullname_prompt_enforced_by_profile": $(json_bool_or_null "${LOGINWINDOW_FULLNAME_PROMPT_ENFORCED_BY_PROFILE}"),
    "loginwindow_password_hints_enforced_by_profile": $(json_bool_or_null "${LOGINWINDOW_PASSWORD_HINTS_ENFORCED_BY_PROFILE}"),
    "guest_account_disabled_enforced_by_profile": $(json_bool_or_null "${GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE}"),
    "dictation_on_device_enforced_by_profile": $(json_bool_or_null "${DICTATION_ON_DEVICE_ENFORCED_BY_PROFILE}"),
    "firewall_logging_enforced_by_profile": $(json_bool_or_null "${FIREWALL_LOGGING_ENFORCED_BY_PROFILE}"),
    "timed_running":              $(json_or_null "$TIMED_RUNNING"),
    "smb_guest_disabled":         $(json_or_null "$SMB_GUEST_DISABLED"),
    "time_machine_encrypted":     $(json_or_null "$TIME_MACHINE_ENCRYPTED"),
    "xprotect_running":           $(json_or_null "$XPROTECT_RUNNING"),
    "guest_folder_absent":        $(json_or_null "$GUEST_FOLDER_ABSENT"),
    "home_folders_mode":          $(json_or_null "$HOME_FOLDERS_MODE"),
    "system_apps_world_writable": $(json_or_null "$SYSTEM_APPS_WORLD_WRITABLE"),
    "system_folder_world_writable": $(json_or_null "$SYSTEM_FOLDER_WORLD_WRITABLE"),
    "bluetooth_sharing_disabled": $(json_or_null "$BLUETOOTH_SHARING_DISABLED"),
    "show_file_extensions":       $(json_or_null "$SHOW_FILE_EXTENSIONS"),
    "terminal_secure_keyboard":   $(json_or_null "$TERMINAL_SECURE_KEYBOARD"),
    "safari_auto_open_downloads_disabled": $(json_or_null "$SAFARI_AUTO_OPEN_DOWNLOADS_DISABLED"),
    "safari_fraudulent_warning":  $(json_or_null "$SAFARI_FRAUDULENT_WARNING"),
    "safari_cross_site_tracking_blocked": $(json_or_null "$SAFARI_CROSS_SITE_TRACKING_BLOCKED"),
    "safari_private_measurement": $(json_or_null "$SAFARI_PRIVATE_MEASUREMENT"),
    "safari_full_url_shown":      $(json_or_null "$SAFARI_FULL_URL_SHOWN"),
    "safari_status_bar_shown":    $(json_or_null "$SAFARI_STATUS_BAR_SHOWN")
  },
  "compliance_findings": $(cat "$COMPLIANCE_FINDINGS_JSON_TMP"),
  "compliance_assessments": $(cat "$COMPLIANCE_ASSESSMENTS_JSON_TMP"),
  "security_tools":     $(cat "$SECURITY_TOOLS_JSON_TMP"),
  "system_extensions":  ${SYSEXT_JSON:-[]},
  "background_items":   ${BACKGROUND_ITEMS_JSON:-[]},
  "icloud": {
    "signed_in": $(json_escape "${ICLOUD_SIGNED_IN:-Unknown}")
  },
  "backup_status": $(cat "$BACKUP_STATUS_JSON_TMP"),
  "applied_configuration": {
    "profiles":           $(cat "$CONFIG_PROFILES_JSON_TMP"),
    "profiles_count":     ${CONFIG_PROFILES_COUNT:-0},
    "profiles_truncated": ${CONFIG_PROFILES_TRUNCATED:-false},
    "collection_status":  $(json_escape "${CONFIG_PROFILES_STATUS:-unavailable}"),
    "mdm_server_url":     $(json_or_null "$MDM_SERVER_URL"),
    "mdm_supervised":     $(json_escape "${MDM_SUPERVISED:-Unknown}")
  },
  "pending_updates":  ${PENDING_UPDATES_JSON:-[]},
  "patches":          ${PATCHES_JSON:-[]},
  "apps": $(apps_payload_array),
  $(homebrew_payload_member)
  $(ide_extensions_payload_member)
  $(package_managers_payload_member)
  $(local_models_payload_member)
  $(mcp_servers_payload_member)
  $(certs_payload_member)
  "collection_status": {"certificates": $(json_escape "$(certs_collection_status)"), "apps": $(json_escape "$(apps_collection_status)"), "apps_users": $(apps_users_collection_status), "safari_extensions": $(json_escape "$(safari_extensions_collection_status)")},
  "local_admins":       $(local_admins_payload),
  "hardware_health":    $(cat "$HARDWARE_HEALTH_JSON_TMP"),
  "browser_extensions_status": $(browser_extensions_status_payload),
  "browser_extensions": $(cat "$BROWSER_EXTENSIONS_JSON_FILE")
}
EOF

rm -f "$SECURITY_TOOLS_JSON_TMP"
rm -f "$CERTS_JSON_TMP"
rm -f "$HARDWARE_HEALTH_JSON_TMP"
rm -f "$BROWSER_EXTENSIONS_JSON_FILE"
rm -f "$BROWSER_EXTENSIONS_STATUS_FILE"
rm -f "$COMPLIANCE_FINDINGS_JSON_TMP"
rm -f "$COMPLIANCE_ASSESSMENTS_JSON_TMP"
rm -f "$BACKUP_STATUS_JSON_TMP"
rm -f "$CONFIG_PROFILES_JSON_TMP"
rm -f "$HOMEBREW_JSON_TMP"
rm -f "$IDE_EXTENSIONS_JSON_TMP"
rm -f "$PACKAGE_MANAGERS_JSON_TMP"
rm -f "$LOCAL_MODELS_JSON_TMP"
rm -f "$MCP_SERVERS_JSON_TMP"

# Validate before committing to the queue
if "$PYTHON3" -c "import json,sys; json.load(open('$TMP'))" 2>/dev/null; then
    mv "$TMP" "$OUT"
    chmod 644 "$OUT"
    rm -f "$APPS_JSON_FILE"
    echo "Collection complete -> $OUT"
    APP_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT'))['apps']))")
    BG_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT'))['background_items']))")
    SE_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT'))['system_extensions']))")
    ST_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT'))['security_tools']))")
    PU_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT')).get('pending_updates', [])))")
    PA_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT')).get('patches', [])))")
    BE_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$OUT')).get('browser_extensions', [])))")
    echo "Apps: $APP_COUNT | bg: $BG_COUNT | sysexts: $SE_COUNT | sectools: $ST_COUNT | pending macOS updates: $PU_COUNT | patch history: $PA_COUNT | browser extensions: $BE_COUNT"
    log_jsonl "info" "collect scan completed" \
        "{\"apps_count\":\"$APP_COUNT\",\"hw_uuid\":\"${HW_UUID:-unknown}\"}"
    exit 0
else
    echo "ERROR: generated JSON failed validation. Leaving tmp file at $TMP for inspection."
    log_jsonl "error" "collect scan failed: JSON validation error"
    # SECURITY (H11): run the diagnostic script from stdin, never from a file
    # written into world-writable /tmp and then re-executed as root — a local
    # attacker could pre-create/replace /tmp/.patched-diag.$$ and get root to
    # run arbitrary Python. Piping the script via `python3 - <arg>` keeps the
    # code path entirely in-memory.
    "$PYTHON3" - "$TMP" << 'PYEOF' || true
import json, re, sys
path = sys.argv[1]
try:
    data = open(path, encoding='utf-8', errors='replace').read()
    json.loads(data)
    print("re-validation passed — encoding issue suspected")
    sys.exit(0)
except json.JSONDecodeError as e:
    keys = re.findall(r'"([^"\\]+)"\s*:', data[:e.pos])
    last_key = keys[-1] if keys else '(unknown)'
    start = max(0, e.pos - 120)
    snippet = repr(data[start:e.pos]) + " >>ERR<< " + repr(data[e.pos:e.pos+80])
    print(f"  at char {e.pos} (line {e.lineno}, col {e.colno}): {e.msg}")
    print(f"  last JSON key before error: {repr(last_key)}")
    print(f"  context: {snippet}")
except Exception as exc:
    print(f"  diagnostic error: {exc}")
PYEOF
    exit 1
fi
