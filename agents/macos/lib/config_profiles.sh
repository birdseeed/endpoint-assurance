# config_profiles.sh — installed device-scope configuration profiles and the
# enrolled MDM server URL (PAT-1667).
#
# This reports APPLIED configuration: what actually landed on this Mac, not
# the authored policy object an admin edited in the MDM console. The two can
# diverge (a pending push, a profile removed locally, a stale cached push),
# so never relabel this as "authored policy" downstream. It is also only
# ever collected from Macs running this agent -- do not treat profiles_count
# or mdm_server_url presence as an estate-wide coverage denominator.
#
# Vendor-agnostic by construction: `profiles` and `mdmclient` are stock macOS
# tools that work identically whether the enrolling server is Jamf, Intune,
# Mosyle, Kandji, or nothing (unenrolled Macs just report an empty list and a
# null mdm_server_url -- not an error).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, STATE_DIR, PYTHON3 (set by main script before sourcing)

# Same raw-payload cap size as lib/auth.sh's PW_POLICY_RAW (`tail -c 2048`
# there). We cap from the HEAD instead of the tail: auth.sh's pwpolicy blob is
# opaque either way, but a profile payload's identifying keys (PayloadType,
# PayloadIdentifier) sit at the front of the serialised object, and losing
# those to a tail-cap would make a capped payload useless for triage.
_CONFIG_PROFILES_PAYLOAD_CAP_BYTES=2048

# Same array-cap style as lib/inventory.sh's background_items ([:500]) --
# an unbounded profile count would grow the payload unboundedly on a
# heavily-managed estate Mac.
_CONFIG_PROFILES_MAX_COUNT=500

# Wraps `profiles list -output stdout-xml` (the modern subcommand form;
# verified live on macOS 26.6.2 to return an already-decoded XML plist, not a
# PKCS#7/CMS blob, even on an unenrolled Mac: an empty <dict/>, exit 0). This
# indirection exists so tests can override the function to simulate the
# documented client-side 23-hour rate limiter (macOS 12.3+, applies to the
# `profiles show`/`profiles validate` family, backed by a SIP-protected timer
# file -- https://derflounder.wordpress.com/2022/03/22/) without a real
# rate-limited machine. Prints stdout+stderr combined (rate-limit text has
# been observed on both channels across macOS versions) and sets the global
# _CONFIG_PROFILES_EXIT to the command's exit status.
_config_profiles_list_xml() {
    _CONFIG_PROFILES_EXIT=0
    profiles list -output stdout-xml 2>&1
    _CONFIG_PROFILES_EXIT=$?
}

collect_config_profiles() {
    # Explicit defaults up front (PAT-706 style): if anything below fails
    # early, these stay bound and the JSON heredoc in patched-collect.sh
    # still produces valid output.
    CONFIG_PROFILES_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/config-profiles-stub.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    printf '[]' > "$CONFIG_PROFILES_JSON_TMP"
    CONFIG_PROFILES_COUNT=0
    CONFIG_PROFILES_TRUNCATED="false"
    CONFIG_PROFILES_STATUS="unavailable"
    MDM_SERVER_URL=""
    MDM_SUPERVISED="Unknown"

    # Cache of the last successfully-parsed result, used when this cycle's
    # `profiles list` call is rate-limited or otherwise unparseable. Computed
    # from $STATE_DIR at call time (not at source time) so tests can point it
    # at a scratch directory by setting STATE_DIR before calling this
    # function -- same convention test-compliance-findings.zsh uses for
    # PATCHED_TMPDIR.
    local _cache_file="${STATE_DIR:-/var/db/patched}/.config-profiles-last-good.json"

    # Device-scope profiles need root. This daemon already runs as root
    # (H10 -- see patched-collect.sh's PATH-hardening comment), so no sudo or
    # special invocation is needed here, same as auth.sh's bare
    # `profiles status -type enrollment` and sharing.sh's bare `mdmclient`.
    local _raw_tmp
    _raw_tmp=$(mktemp "$PATCHED_TMPDIR/config-profiles-raw.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    _config_profiles_list_xml > "$_raw_tmp" 2>/dev/null
    if [[ "${_CONFIG_PROFILES_EXIT:-0}" -ne 0 ]]; then
        echo "config_profiles: 'profiles list' exited ${_CONFIG_PROFILES_EXIT} (classification below is based on output content, not this alone)"
    fi

    local _parsed_tmp
    _parsed_tmp=$(mktemp "$PATCHED_TMPDIR/config-profiles-parsed.XXXXXX")  # H11: root-owned 0700 dir, not /tmp

    if "$PYTHON3" - "$_raw_tmp" "$_parsed_tmp" "$_CONFIG_PROFILES_PAYLOAD_CAP_BYTES" "$_CONFIG_PROFILES_MAX_COUNT" <<'PYEOF'
import json, plistlib, sys

raw_path, out_path, cap_bytes_s, max_count_s = sys.argv[1:5]
cap_bytes = int(cap_bytes_s)
max_count = int(max_count_s)


def build_payload(items):
    """items: a profile's ProfileItems list (its payload dicts). Returns
    (payload_str, capped_bool): the payload serialised to text and capped at
    cap_bytes (head-truncated -- see module header comment)."""
    try:
        full = json.dumps(items, default=str)
    except Exception:
        full = str(items)
    encoded = full.encode("utf-8", errors="replace")
    if len(encoded) > cap_bytes:
        return encoded[:cap_bytes].decode("utf-8", errors="ignore"), True
    return full, False


try:
    with open(raw_path, "rb") as f:
        pl = plistlib.load(f)
except Exception:
    # Not a parseable plist at all (rate-limited/error text, truncated
    # output, or a future macOS output-format change). Signal failure to the
    # shell side via exit code; it decides rate-limited vs. generic failure
    # from the raw text and falls back to the last-known-good cache.
    sys.exit(2)

device_profiles = pl.get("_computerlevel", []) if isinstance(pl, dict) else []
if not isinstance(device_profiles, list):
    device_profiles = []

truncated = len(device_profiles) > max_count

profiles_out = []
mdm_server_url = None

for prof in device_profiles[:max_count]:
    if not isinstance(prof, dict):
        continue
    try:
        items = prof.get("ProfileItems", []) or []
        payload_str, capped = build_payload(items)
        profiles_out.append({
            "identifier":     prof.get("ProfileIdentifier") or "",
            "display_name":   prof.get("ProfileDisplayName") or "",
            "organization":   prof.get("ProfileOrganization") or "",
            "payload":        payload_str,
            "payload_capped": capped,
        })
        if mdm_server_url is None and isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                if item.get("PayloadType") == "com.apple.mdm":
                    content = item.get("PayloadContent") or {}
                    if isinstance(content, dict):
                        url = content.get("ServerURL")
                        if url:
                            mdm_server_url = str(url)
                    break
    except Exception:
        # One malformed/undecodable profile (e.g. an unexpected payload
        # shape) must not drop the whole run -- record it, keep going.
        profiles_out.append({
            "identifier":     prof.get("ProfileIdentifier", "") if isinstance(prof, dict) else "",
            "display_name":   "",
            "organization":   "",
            "payload":        "",
            "payload_capped": False,
            "decode_error":   True,
        })

with open(out_path, "w") as f:
    json.dump({
        "profiles":        profiles_out,
        "mdm_server_url":  mdm_server_url,
        "truncated":       truncated,
    }, f)
PYEOF
    then
        # Parsed cleanly -- extract each field by path so nothing here embeds
        # untrusted content into a python source string.
        "$PYTHON3" -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d['profiles']))" "$_parsed_tmp" > "$CONFIG_PROFILES_JSON_TMP" 2>/dev/null \
            || printf '[]' > "$CONFIG_PROFILES_JSON_TMP"

        # Validate before accepting, same defensive pattern as
        # backup.sh's collect_backup_status.
        if ! "$PYTHON3" -c "import json,sys; json.load(open(sys.argv[1]))" "$CONFIG_PROFILES_JSON_TMP" 2>/dev/null; then
            printf '[]' > "$CONFIG_PROFILES_JSON_TMP"
        fi

        MDM_SERVER_URL=$("$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
u = d.get('mdm_server_url')
print(u if u else '')
" "$_parsed_tmp" 2>/dev/null) || MDM_SERVER_URL=""

        if "$PYTHON3" -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get('truncated') else 1)" "$_parsed_tmp" 2>/dev/null; then
            CONFIG_PROFILES_TRUNCATED="true"
        else
            CONFIG_PROFILES_TRUNCATED="false"
        fi

        CONFIG_PROFILES_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$CONFIG_PROFILES_JSON_TMP'))))" 2>/dev/null) || CONFIG_PROFILES_COUNT=0
        CONFIG_PROFILES_STATUS="ok"

        # Persist as this run's last-known-good, atomically (mktemp in the
        # same directory + mv), same idiom patched-collect.sh's own final
        # payload write uses for $TMP -> $OUT.
        local _cache_tmp
        if _cache_tmp=$(mktemp "${_cache_file}.XXXXXX" 2>/dev/null); then
            _CONFIG_PROFILES_MDM_URL="$MDM_SERVER_URL" "$PYTHON3" -c "
import json, os, sys
profiles = json.load(open(sys.argv[1]))
url = os.environ.get('_CONFIG_PROFILES_MDM_URL') or None
json.dump({'profiles': profiles, 'mdm_server_url': url}, open(sys.argv[2], 'w'))
" "$CONFIG_PROFILES_JSON_TMP" "$_cache_tmp" 2>/dev/null && \
                mv -f "$_cache_tmp" "$_cache_file" 2>/dev/null && \
                chmod 600 "$_cache_file" 2>/dev/null
            rm -f "$_cache_tmp" 2>/dev/null
        fi
    else
        # `profiles list` did not return a parseable plist this cycle.
        # Classify rate-limited vs. generic failure from the captured text,
        # but either way: do NOT retry (the 23h limiter's timer file is
        # SIP-protected -- a retry in this same run cannot help and only
        # spends this cycle's time budget) and do NOT fail the run --
        # fall back to the last-known-good cache if one exists.
        if grep -qiE 'rate.?limit|too quickly|try again|already been run|already run' "$_raw_tmp" 2>/dev/null; then
            CONFIG_PROFILES_STATUS="rate_limited"
        else
            CONFIG_PROFILES_STATUS="unavailable"
        fi

        if [[ -f "$_cache_file" ]]; then
            "$PYTHON3" -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d.get('profiles', [])))" "$_cache_file" > "$CONFIG_PROFILES_JSON_TMP" 2>/dev/null \
                || printf '[]' > "$CONFIG_PROFILES_JSON_TMP"
            MDM_SERVER_URL=$("$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
u = d.get('mdm_server_url')
print(u if u else '')
" "$_cache_file" 2>/dev/null) || MDM_SERVER_URL=""
            CONFIG_PROFILES_COUNT=$("$PYTHON3" -c "import json; print(len(json.load(open('$CONFIG_PROFILES_JSON_TMP'))))" 2>/dev/null) || CONFIG_PROFILES_COUNT=0
        fi
    fi

    rm -f "$_raw_tmp" "$_parsed_tmp"

    # --- Optional richer detail: mdmclient DumpManagementStatus -----------
    # Undocumented private Apple tool, no man page (same caveat as
    # sharing.sh's QuerySecurityInfo call). Guarded identically: bare
    # invocation, 2>/dev/null, grep a known key, default "Unknown" on any
    # failure, missing binary, or an unmanaged/unenrolled device. Never lets
    # a missing or changed mdmclient break the collection run. Only the
    # IsSupervised key is parsed here -- DumpManagementStatus's other keys
    # are not verified stable across macOS versions (same "needs VM
    # verification" caveat safari.sh documents for `profiles -P -o stdout`).
    local _dms
    _dms=$(mdmclient DumpManagementStatus 2>/dev/null || true)
    if printf '%s' "$_dms" | grep -q 'IsSupervised = 1'; then
        MDM_SUPERVISED="Yes"
    elif printf '%s' "$_dms" | grep -q 'IsSupervised = 0'; then
        MDM_SUPERVISED="No"
    fi
}
