# app_control.sh — Application Control: approved-admins enforcement (PAT-604)
#
# Sourced by patched-upload.sh; not executable directly.
#
# Requires (set by caller before sourcing):
#   PYTHON3      — absolute path to python3 (/usr/bin/python3)
#   API_URL      — base URL, e.g. https://api.patched.im
#   BEARER_TOKEN — opaque bearer credential
#   CREDS_DIR    — /etc/patched (for hmac-secret)
#   HW_UUID      — device UUID (may be empty; forwarded as X-Patched-Device-Id)
#
# The compute_hmac and patched_curl_bearer helpers must be in scope; the caller
# (patched-upload.sh) defines them inline and sources this module afterwards.
# Every authenticated request goes through patched_curl_bearer so the bearer
# token is passed to curl over stdin, never on argv (PAT-881).
#
# Environment overrides:
#   PATCHED_DRY_RUN=1   — log what would happen; skip dscl writes and POST
#   PATCHED_AC_CONFIG   — override agent-config path (for testing)
#
# Safety rails (never removed regardless of policy):
#   - root
#   - _mbsetupuser
#   - current console user (primary user — stat /dev/console)
#   - last remaining admin (always keep ≥ 1)
#
# PAT-1417: both enforcement-audit POST sites below (ac_enforce_admins and
# ac_check_app_violations) now record their outcome into the shared
# agent-health store (macos/lib/agent_health.sh, PAT-1065) instead of only
# logging it. Found on MAC-STAGING 2026-08-17: a device held a tenant-scoped
# credential against this device-scoped endpoint, every audit POST 401'd,
# and the agent logged "(non-fatal)" and returned 0 - enforcement_audit had
# zero rows estate-wide, forever, and an empty table read for months as
# "App Control has never been exercised" when it actually meant "we cannot
# tell". Decision (orchestrator): this implements the degraded health
# signal only, not a spool-and-retry queue. The ticket's own minimum is
# "at minimum surface a degraded health signal"; a durable spool is a new
# subsystem with its own failure modes on the audit path, while
# agent_health.sh is the already-shipped mechanism built for exactly this
# shape of fault (PAT-1065/PAT-1064). Spool-and-retry is a deliberate
# follow-up, not an oversight here. Every call is guarded with
# `typeset -f ... >/dev/null 2>&1` because this file can be sourced without
# agent_health.sh having loaded first (see patched-upload.sh's own guard
# around lib/agent_health.sh) - a missing health store must never turn a
# fail-safe audit path into a fatal one.

# _ac_is_protected_admin <member> <console_user>
# True (0) if <member> is a safety-rail account that ac_enforce_admins can
# never remove: root, _mbsetupuser, or the current console/primary user.
# Shared by the removable-pool count and the removal loop below so the two
# can never disagree about which accounts are actually removable. See
# PAT-880 (the "last admin" floor previously counted these protected
# accounts as part of the removable pool, letting the floor be satisfied by
# an account that could never be removed).
_ac_is_protected_admin() {
    local _candidate="$1" _console="$2"
    [[ "$_candidate" == "root" ]] && return 0
    [[ "$_candidate" == "_mbsetupuser" ]] && return 0
    [[ -n "$_console" && "$_candidate" == "$_console" ]] && return 0
    return 1
}

ac_enforce_admins() {
    local _config_file _dry_run _ac_enabled _approved_raw _approved_list
    local _current_raw _member _current_list _console_user
    local _unauthorized_list _removal_list _events_json _occurred_at
    local _audit_body_tmp _audit_sig _audit_ts _audit_nonce _http_code

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"
    _dry_run=0
    [[ "${PATCHED_DRY_RUN:-0}" == "1" ]] && _dry_run=1

    # ── 1. Verify agent-config exists and is readable ──────────────────────────
    if [[ ! -f "$_config_file" ]]; then
        echo "app_control: no agent-config at $_config_file — skipping"
        return 0
    fi

    # ── 2. Read app_control.enabled ────────────────────────────────────────────
    _ac_enabled=$("$PYTHON3" -c "
import json, sys
def reject_ambiguous_keys(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate or case-colliding JSON key')
        seen.add(folded)
        result[key] = value
    return result
try:
    cfg = json.load(open(sys.argv[1]), object_pairs_hook=reject_ambiguous_keys)
    ac = cfg.get('app_control')
    if not isinstance(ac, dict):
        print('false')
        sys.exit(0)
    print('true' if ac.get('enabled') else 'false')
except Exception:
    print('false')
" "$_config_file" 2>/dev/null) || _ac_enabled="false"

    if [[ "$_ac_enabled" != "true" ]]; then
        echo "app_control: disabled in agent-config — skipping"
        return 0
    fi

    # ── 3. Read app_control.approved_admins ────────────────────────────────────
    # If the list is empty or missing, exit silently (lockout protection).
    _approved_raw=$("$PYTHON3" -c "
import json, sys
def reject_ambiguous_keys(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate or case-colliding JSON key')
        seen.add(folded)
        result[key] = value
    return result
try:
    cfg = json.load(open(sys.argv[1]), object_pairs_hook=reject_ambiguous_keys)
    ac = cfg.get('app_control', {})
    admins = ac.get('approved_admins', [])
    if not isinstance(admins, list) or len(admins) == 0:
        sys.exit(0)
    for u in admins:
        if isinstance(u, str) and u.strip():
            print(u.strip())
except Exception:
    sys.exit(0)
" "$_config_file" 2>/dev/null) || _approved_raw=""

    if [[ -z "$_approved_raw" ]]; then
        echo "app_control: approved_admins is empty — skipping (lockout protection)"
        return 0
    fi

    # Build approved set as newline-separated list for membership testing
    _approved_list=$(printf '%s\n' "$_approved_raw")

    # ── 4. Enumerate current local admin group members via dscl ───────────────
    _current_raw=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null || true)
    if [[ -z "$_current_raw" ]]; then
        echo "app_control: could not read /Groups/admin — skipping"
        return 0
    fi
    # dscl output format: "GroupMembership: user1 user2 user3"
    # Strip the "GroupMembership:" label then split on whitespace.
    _current_list=$(printf '%s' "$_current_raw" | awk '{for(i=2;i<=NF;i++) print $i}')

    # ── 5. Detect console user (primary user — safety rail) ────────────────────
    _console_user=$(stat -f %Su /dev/console 2>/dev/null || echo "")

    # ── 6. Compute unauthorized = current - approved ───────────────────────────
    # A member is unauthorized if they are NOT in the approved list.
    _unauthorized_list=""
    while IFS= read -r _member; do
        [[ -z "$_member" ]] && continue
        if ! printf '%s\n' "$_approved_list" | grep -qxF "$_member"; then
            _unauthorized_list="${_unauthorized_list}${_member}
"
        fi
    done <<< "$_current_list"

    if [[ -z "$_unauthorized_list" ]]; then
        echo "app_control: all current admins are approved — no action needed"
        return 0
    fi

    # ── 7. Apply safety rails and build removal list ───────────────────────────
    # The "keep >= 1 admin" floor must only ever gate removal when NO
    # protected account (root / _mbsetupuser / console user) is present in
    # the current admin group. A protected account already guarantees an
    # admin remains, so it must not be counted toward (or need) the floor.
    # PAT-880: previously the floor was computed from the TOTAL admin count
    # (including root/_mbsetupuser/console user), which let those protected,
    # never-removable accounts "cover" the floor on paper while the actual
    # last unauthorized/removable admin was left in place.
    local _removable_count=0 _protected_present=0
    while IFS= read -r _member; do
        [[ -z "$_member" ]] && continue
        if _ac_is_protected_admin "$_member" "$_console_user"; then
            _protected_present=1
        else
            (( _removable_count++ ))
        fi
    done <<< "$_current_list"

    # Track how many we've committed to removing so we always keep >= 1
    # admin in the removable pool when no protected account is present.
    local _removal_count=0
    local _remaining
    _removal_list=""

    while IFS= read -r _member; do
        [[ -z "$_member" ]] && continue

        # Safety rail: never remove root / _mbsetupuser / the console user.
        # Routed through the same _ac_is_protected_admin predicate used for
        # _protected_present above, so the two can never drift apart if a
        # protected category is ever added or changed here.
        if _ac_is_protected_admin "$_member" "$_console_user"; then
            case "$_member" in
                root)         echo "app_control: SKIP $_member (protected: root)" ;;
                _mbsetupuser) echo "app_control: SKIP $_member (protected: _mbsetupuser)" ;;
                *)            echo "app_control: SKIP $_member (protected: primary console user)" ;;
            esac
            continue
        fi

        # Safety rail: always keep at least one admin. Only applies when no
        # protected account is present. If one is, it already satisfies the
        # invariant and every unauthorized/removable admin can go.
        if (( ! _protected_present )); then
            _remaining=$(( _removable_count - _removal_count ))
            if (( _remaining <= 1 )); then
                echo "app_control: SKIP $_member (protected: last remaining admin)"
                continue
            fi
        fi

        _removal_list="${_removal_list}${_member}
"
        (( _removal_count++ )) || true
    done <<< "$_unauthorized_list"

    if [[ -z "$_removal_list" ]]; then
        echo "app_control: all unauthorized admins are protected by safety rails — no action"
        return 0
    fi

    # ── 8. Execute removals and build audit events ──────────────────────────────
    _occurred_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    _events_json="["
    local _first_event=1
    local _did_remove _event_dry_run _event

    while IFS= read -r _member; do
        [[ -z "$_member" ]] && continue

        _did_remove=0
        _event_dry_run="false"

        if (( _dry_run )); then
            echo "app_control: DRY_RUN — would remove admin: $_member"
            _event_dry_run="true"
            _did_remove=1
        else
            echo "app_control: removing admin: $_member"
            if dscl . -delete /Groups/admin GroupMembership "$_member" 2>/dev/null; then
                echo "app_control: removed admin: $_member"
                _did_remove=1
            else
                echo "app_control: WARN — dscl delete failed for $_member (may have already been removed)"
            fi
        fi

        if (( _did_remove )); then
            _event=$(printf '{"event_type":"admin_removed","subject":"%s","details":{"method":"dscl","dry_run":%s},"occurred_at":"%s"}' \
                "$_member" "$_event_dry_run" "$_occurred_at")
            if (( _first_event )); then
                _events_json="${_events_json}${_event}"
                _first_event=0
            else
                _events_json="${_events_json},${_event}"
            fi
        fi
    done <<< "$_removal_list"

    _events_json="${_events_json}]"

    # ── 9. POST audit events to /v1/inventory/enforcement-audit ───────────────
    # Skip if no events were collected.
    if (( _first_event )); then
        echo "app_control: no audit events to POST"
        return 0
    fi

    if (( _dry_run )); then
        echo "app_control: DRY_RUN — would POST audit events: $_events_json"
        return 0
    fi

    _audit_body_tmp=$(mktemp "/tmp/patched-ac-audit.XXXXXX") || {
        echo "app_control: WARN — could not create tmp file for audit POST"
        return 0
    }

    # Build the JSON body
    printf '{"events":%s}' "$_events_json" > "$_audit_body_tmp"

    _audit_ts=$(date -u +%s)
    _audit_nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    _audit_sig=$(compute_hmac "$_audit_body_tmp" "enforcement_audit" "$_audit_ts" "$_audit_nonce") || {
        echo "app_control: WARN — hmac compute failed; skipping audit POST"
        rm -f "$_audit_body_tmp"
        return 0
    }

    local -a _device_hdr; _device_hdr=()
    [[ -n "$HW_UUID" ]] && _device_hdr=(-H "X-Patched-Device-Id: ${HW_UUID}")

    _http_code=$(patched_curl_bearer "${BEARER_TOKEN}" -s -o /dev/null -w "%{http_code}" \
        --max-time 30 \
        -X POST "${API_URL}/v1/inventory/enforcement-audit" \
        -H "X-Patched-Signature: ${_audit_sig}" \
        -H "X-Patched-Timestamp: ${_audit_ts}" \
        -H "X-Patched-Nonce: ${_audit_nonce}" \
        "${_device_hdr[@]}" \
        -H "Content-Type: application/json" \
        --data-binary "@${_audit_body_tmp}" \
        2>/dev/null) || _http_code=""

    rm -f "$_audit_body_tmp"

    # PAT-1417: record outcome into agent-health so a run of non-2xx
    # responses is a durable, queryable degraded signal instead of a line in
    # a local log nobody reads. See the file header comment for the fix
    # decision and why this is a degraded-signal record rather than a retry.
    case "$_http_code" in
        2*)
            echo "app_control: audit POST -> $_http_code (ok)"
            typeset -f patched_agent_health_record_success >/dev/null 2>&1 && \
                patched_agent_health_record_success "audit_post_failed" "admin_enforcement"
            ;;
        401|403)
            # PAT-1417: a 401/403 here means the device's credential cannot
            # write this audit record - a configuration defect (e.g. a
            # tenant-scoped credential against this device-scoped endpoint),
            # not a transient fault. Kept distinguishable from the generic
            # non-2xx branch below on purpose: it must never be folded in
            # with 5xx/network noise.
            echo "app_control: audit POST -> $_http_code (device credential cannot write enforcement audit - config defect, not transient)"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "admin_enforcement" "credential_rejected_http_${_http_code}"
            ;;
        "")
            echo "app_control: audit POST -> network error or timeout"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "admin_enforcement" "network_error_or_timeout"
            ;;
        *)
            echo "app_control: audit POST -> $_http_code (non-fatal)"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "admin_enforcement" "post_failed_http_${_http_code}"
            ;;
    esac

    return 0
}

# ---------------------------------------------------------------------------
# ac_check_app_violations — app allowlist check (PAT-552, alert-only v1).
#
# Reads app_control.app_allowlist from the cached agent-config and scans
# /Applications (+ ~/Applications if present) for bundle IDs not in the list.
# Reports each unlisted app as an app_block_skipped event (alert-only — no
# actual blocking in v1). POSTs the batch to /v1/inventory/enforcement-audit.
#
# Fail-safe: any error is logged and the function returns 0.
# ---------------------------------------------------------------------------
ac_check_app_violations() {
    local _config_file _ac_enabled _allowlist_raw _dry_run

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"
    _dry_run=0
    [[ "${PATCHED_DRY_RUN:-0}" == "1" ]] && _dry_run=1

    # ── 1. Verify agent-config exists ──────────────────────────────────────────
    if [[ ! -f "$_config_file" ]]; then
        echo "app_allowlist: no agent-config at $_config_file — skipping"
        return 0
    fi

    # ── 2. Check app_control.enabled ──────────────────────────────────────────
    _ac_enabled=$("$PYTHON3" -c "
import json, sys
def reject_ambiguous_keys(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate or case-colliding JSON key')
        seen.add(folded)
        result[key] = value
    return result
try:
    cfg = json.load(open(sys.argv[1]), object_pairs_hook=reject_ambiguous_keys)
    ac = cfg.get('app_control')
    if not isinstance(ac, dict):
        print('false')
        sys.exit(0)
    print('true' if ac.get('enabled') else 'false')
except Exception:
    print('false')
" "$_config_file" 2>/dev/null) || _ac_enabled="false"

    if [[ "$_ac_enabled" != "true" ]]; then
        echo "app_allowlist: app_control disabled — skipping app check"
        return 0
    fi

    # ── 3. Read app_allowlist (one bundle ID per line) ─────────────────────────
    _allowlist_raw=$("$PYTHON3" -c "
import json, sys
def reject_ambiguous_keys(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError('duplicate or case-colliding JSON key')
        seen.add(folded)
        result[key] = value
    return result
try:
    cfg = json.load(open(sys.argv[1]), object_pairs_hook=reject_ambiguous_keys)
    ac = cfg.get('app_control', {})
    al = ac.get('app_allowlist', [])
    if not isinstance(al, list) or len(al) == 0:
        sys.exit(0)
    for entry in al:
        if isinstance(entry, str) and entry.strip():
            print(entry.strip())
except Exception:
    pass
" "$_config_file" 2>/dev/null) || _allowlist_raw=""

    if [[ -z "$_allowlist_raw" ]]; then
        echo "app_allowlist: app_allowlist is empty — skipping app check"
        return 0
    fi

    echo "app_allowlist: checking installed apps against allowlist"

    # ── 4. Scan /Applications (+ user Applications) for bundle IDs ────────────
    # Use mdls to read kMDItemCFBundleIdentifier — same source as apps.sh.
    # Violations are collected in a Python-friendly format via a heredoc script.

    local _occurred_at
    _occurred_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local _events_json
    _events_json=$("$PYTHON3" - "$_allowlist_raw" "$_occurred_at" <<'PYEOF'
import subprocess, json, sys, os

allowlist_raw = sys.argv[1]
occurred_at   = sys.argv[2]

allowlist = set()
for line in allowlist_raw.strip().splitlines():
    s = line.strip().lower()
    if s:
        allowlist.add(s)

events = []

search_dirs = ['/Applications']
try:
    home      = os.path.expanduser('~')
    user_apps = os.path.join(home, 'Applications')
    if os.path.isdir(user_apps):
        search_dirs.append(user_apps)
except Exception:
    pass

for search_dir in search_dirs:
    try:
        entries = os.listdir(search_dir)
    except OSError:
        continue
    for entry in entries:
        if not entry.endswith('.app'):
            continue
        app_path = os.path.join(search_dir, entry)
        try:
            r = subprocess.run(
                ['/usr/bin/mdls', '-name', 'kMDItemCFBundleIdentifier', '-raw', app_path],
                capture_output=True, text=True, timeout=5
            )
            bundle_id = r.stdout.strip()
        except Exception:
            continue

        if not bundle_id or bundle_id == '(null)':
            continue

        if bundle_id.lower() not in allowlist:
            events.append({
                'event_type':  'app_block_skipped',
                'subject':     bundle_id,
                'details': {
                    'app_name':  entry[:-4],
                    'app_path':  app_path,
                    'reason':    'alert_only_v1',
                },
                'occurred_at': occurred_at,
            })

print(json.dumps(events))
PYEOF
    ) || _events_json="[]"

    local _violation_count
    _violation_count=$("$PYTHON3" -c "
import json, sys
try:
    evts = json.loads(sys.argv[1])
    print(len(evts))
except Exception:
    print(0)
" "$_events_json" 2>/dev/null) || _violation_count=0

    echo "app_allowlist: $_violation_count unlisted app(s) found"

    if (( _violation_count == 0 )); then
        echo "app_allowlist: no violations — estate is compliant"
        return 0
    fi

    if (( _dry_run )); then
        echo "app_allowlist: DRY_RUN — would POST $_violation_count violation event(s)"
        return 0
    fi

    # ── 5. POST violation events to /v1/inventory/enforcement-audit ────────────
    local _body_tmp _sig _ts _nonce _http_code
    _body_tmp=$(mktemp "/tmp/patched-ac-app-audit.XXXXXX") || {
        echo "app_allowlist: WARN — could not create tmp file for POST"
        return 0
    }

    printf '{"events":%s}' "$_events_json" > "$_body_tmp"

    _ts=$(date -u +%s)
    _nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    _sig=$(compute_hmac "$_body_tmp" "enforcement_audit" "$_ts" "$_nonce") || {
        echo "app_allowlist: WARN — hmac compute failed; skipping violation POST"
        rm -f "$_body_tmp"
        return 0
    }

    local -a _device_hdr; _device_hdr=()
    [[ -n "$HW_UUID" ]] && _device_hdr=(-H "X-Patched-Device-Id: ${HW_UUID}")

    _http_code=$(patched_curl_bearer "${BEARER_TOKEN}" -s -o /dev/null -w "%{http_code}" \
        --max-time 30 \
        -X POST "${API_URL}/v1/inventory/enforcement-audit" \
        -H "X-Patched-Signature: ${_sig}" \
        -H "X-Patched-Timestamp: ${_ts}" \
        -H "X-Patched-Nonce: ${_nonce}" \
        "${_device_hdr[@]}" \
        -H "Content-Type: application/json" \
        --data-binary "@${_body_tmp}" \
        2>/dev/null) || _http_code=""

    rm -f "$_body_tmp"

    # PAT-1417: same fix as ac_enforce_admins's audit POST above - record
    # outcome into agent-health rather than only logging it. See the file
    # header comment for the fix decision.
    case "$_http_code" in
        2*)
            echo "app_allowlist: violation POST -> $_http_code (ok)"
            typeset -f patched_agent_health_record_success >/dev/null 2>&1 && \
                patched_agent_health_record_success "audit_post_failed" "app_allowlist"
            ;;
        401|403)
            # PAT-1417: config defect, not transient - see the matching
            # comment on ac_enforce_admins's audit POST above.
            echo "app_allowlist: violation POST -> $_http_code (device credential cannot write enforcement audit - config defect, not transient)"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "app_allowlist" "credential_rejected_http_${_http_code}"
            ;;
        "")
            echo "app_allowlist: violation POST -> network error or timeout"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "app_allowlist" "network_error_or_timeout"
            ;;
        *)
            echo "app_allowlist: violation POST -> $_http_code (non-fatal)"
            typeset -f patched_agent_health_record_failure >/dev/null 2>&1 && \
                patched_agent_health_record_failure "audit_post_failed" "app_allowlist" "post_failed_http_${_http_code}"
            ;;
    esac

    return 0
}
