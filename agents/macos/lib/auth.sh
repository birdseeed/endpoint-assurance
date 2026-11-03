# auth.sh — authentication, account policy, and MDM enrolment signals.
# Sourced by patched-collect.sh; not executable directly.

# MDM enrolment status from `profiles status -type enrollment`.
#
# MDM_ENROLLED is the platform-neutral compliance fact: Yes, No or Unknown.
# MDM_ENROLLED_VIA_DEP is separate provenance about how enrolment happened and
# must never be required for the neutral MDM rule to pass. MDM_ENROLMENT keeps
# the old combined value for one compatibility release (PAT-1752); remove it
# after the platform's bounded legacy fallback has covered that release.
#
# A failed profiles read makes all three values Unknown. On a successful read,
# the two neutral fields are parsed independently: a missing DEP line must not
# erase a valid MDM observation. The legacy combined value is emitted only when
# both source lines are present, preserving its previous fail-closed contract.
collect_mdm_enrolment() {
    local _mdm_raw="" _mdm_value="" _dep_value=""
    MDM_ENROLMENT="Unknown"
    MDM_ENROLLED="Unknown"
    MDM_ENROLLED_VIA_DEP="Unknown"
    if _mdm_raw=$(profiles status -type enrollment 2>/dev/null); then
        _dep_value=$(print -r -- "$_mdm_raw" | awk -F': ' '/Enrolled via DEP/ {value=$2} END {print value}')
        _mdm_value=$(print -r -- "$_mdm_raw" | awk -F': ' '/MDM enrollment/ {value=$2} END {print value}')

        case "$_mdm_value" in
            Yes|"Yes ("*) MDM_ENROLLED="Yes" ;;
            No)             MDM_ENROLLED="No" ;;
        esac
        case "$_dep_value" in
            Yes) MDM_ENROLLED_VIA_DEP="Yes" ;;
            No)  MDM_ENROLLED_VIA_DEP="No" ;;
        esac

        if [[ -n "$_dep_value" && -n "$_mdm_value" ]]; then
            MDM_ENROLMENT="dep=$_dep_value mdm=$_mdm_value"
        fi
    fi
}

# §3.4: Audit log retention ≥ 60 days (PAT-1767 three-state contract).
# _audit_retention_expire <audit_control path>
# Parses expire-after from audit_control and converts it to days. Sets
# AUDIT_RETENTION_EXPIRE to:
#   "Yes" / "No"     an expire-after line with a value was read
#   "NotConfigured"  audit_control was read (grep exit 1) and has no
#                    expire-after line
#   "" (null)        no audit_control at all (unchanged: whether auditing is
#                    configured is not decided here), grep could not read the
#                    file (exit 2), or the expire-after line has no value
_audit_retention_expire() {
    local ac_file="$1" ac_line="" ac_rc=0 _expire_raw _expire_num _expire_unit
    AUDIT_RETENTION_EXPIRE=""
    [[ -f "$ac_file" ]] || return 0
    # First matching line, the same line awk '/^expire-after/{...; exit}' took.
    ac_line=$(grep -m 1 '^expire-after' "$ac_file" 2>/dev/null) || ac_rc=$?
    case "$ac_rc" in
        0) ;;
        1) AUDIT_RETENTION_EXPIRE="NotConfigured"; return 0 ;;
        *) log_warn "auth: audit_retention_expire undetermined (grep exited $ac_rc reading $ac_file)"; return 0 ;;
    esac
    # awk -F: '{print $2}' | tr -d ' \t': the text between the first and second
    # colon, spaces and tabs removed.
    _expire_raw="${ac_line#*:}"
    [[ "$ac_line" == *:* ]] || _expire_raw=""
    _expire_raw="${_expire_raw%%:*}"
    _expire_raw="${_expire_raw//[ $'\t']/}"
    [[ -n "$_expire_raw" ]] || return 0
    _expire_num=$(printf '%s' "$_expire_raw" | grep -oE '^[0-9]+' || echo "0")
    _expire_unit=$(printf '%s' "$_expire_raw" | sed 's/^[0-9]*//' | head -c 1 | tr '[:upper:]' '[:lower:]')
    case "${_expire_unit:-d}" in
        d) ;;
        y) (( _expire_num = _expire_num * 365 )) ;;
        m) (( _expire_num = _expire_num * 30 ))  ;;
    esac
    if (( _expire_num >= 60 )); then AUDIT_RETENTION_EXPIRE="Yes"; else AUDIT_RETENTION_EXPIRE="No"; fi
}

# §3.3: install.log retention days, CIS ODV >= 365 (PAT-1775 three-state).
# _install_log_retention_days <ASL config path>
# Reads the ttl= value from the ASL config for com.apple.install. Sets
# INSTALL_LOG_RETENTION_DAYS to:
#   <whole number>   the first ttl=<digits> in the file, the same value the
#                    earlier grep | head -1 | grep pipeline took
#   "NotConfigured"  the file was read (grep exit 1) and has no ttl= at all,
#                    in any letter case,
#                    so no retention is set (stock macOS 26.6.2 ships the
#                    file with rotation limits and no ttl)
#   "" (null)        no config file at all (unchanged, as for
#                    audit_retention_expire: whether install logging is
#                    configured is not decided here), grep could not read the
#                    file (exit 2), or a ttl= that is never followed by a
#                    number (a set value of the wrong shape, not an absent
#                    one)
_install_log_retention_days() {
    local il_file="$1" il_out="" il_rc=0
    INSTALL_LOG_RETENTION_DAYS=""
    [[ -f "$il_file" ]] || return 0
    # -m 1 stops after the first matching line; -o can still print more than
    # one match from it, and the first is the one the old pipeline kept.
    il_out=$(grep -m 1 -oE 'ttl=[0-9]+' "$il_file" 2>/dev/null) || il_rc=$?
    case "$il_rc" in
        0)
            il_out="${il_out%%$'\n'*}"
            il_out="${il_out#ttl=}"
            [[ "$il_out" =~ '^[0-9]+$' ]] && INSTALL_LOG_RETENTION_DAYS="$il_out"
            return 0
            ;;
        1) ;;
        *)
            log_warn "auth: install_log_retention_days undetermined (grep exited $il_rc reading $il_file)"
            return 0
            ;;
    esac
    il_rc=0
    # Any ttl= in any case blocks NotConfigured: whether ASL honours TTL= is
    # not verified, so it is not treated as proof of absence.
    grep -qi 'ttl=' "$il_file" 2>/dev/null || il_rc=$?
    case "$il_rc" in
        1) INSTALL_LOG_RETENTION_DAYS="NotConfigured" ;;
        0) log_warn "auth: install_log_retention_days undetermined (ttl= without a number in $il_file)" ;;
        *) log_warn "auth: install_log_retention_days undetermined (grep exited $il_rc reading $il_file)" ;;
    esac
    return 0
}

# §5.8 — standing local administrator accounts (PAT-1974).
#
# Sets:
#   LOCAL_ADMIN_COUNT              the number of admin group members excluding
#                                  root, or "" when the enumeration failed, so
#                                  json_int_or_notconfigured writes null
#   LOCAL_ADMIN_ACCOUNTS           array of member names, root excluded
#   LOCAL_ADMIN_COLLECTION_STATUS  "complete" or "unavailable"
#
# ABSENCE REQUIRES AUTHORITY. The previous form was
#   ADMIN_MEMBERS=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | awk ...)
#   LOCAL_ADMIN_COUNT=$(echo "$ADMIN_MEMBERS" | tr ' ' '\n' | grep -v '^root$' | ... | wc -l)
# which swallowed a failed read and then counted 0 from the empty output. A Mac
# whose directory service could not be read reported the same "0" as a Mac with
# no standing admins, and 0 passes the CIS 5.8 rule outright. dscl's exit status
# is now checked and three separate outcomes are unavailable rather than zero:
#   - dscl exited non-zero (56 / eDSRecordNotFound, a broken DirectoryService)
#   - its output could not be parsed as the expected plist shape
#   - the record was read but carries no GroupMembership attribute. Membership
#     can be recorded as GroupMembers (GeneratedUIDs) alone, which this read
#     does not resolve, so a missing GroupMembership is not proof of zero.
# The -plist form is read rather than the old `GroupMembership: a b c` line
# because dscl prints "No such key: GroupMembership" to stdout and still exits
# 0 for an absent attribute: only the plist tells an absent attribute (an empty
# dict) apart from a present one, and it delimits names itself rather than by
# spaces.
#
# The roster itself goes out in the separate top-level local_admins object
# (local_admins_payload below), never into the flat compliance bag, whose
# values are scalars only.
_collect_local_admins() {
    LOCAL_ADMIN_COUNT=""
    LOCAL_ADMIN_ACCOUNTS=()
    LOCAL_ADMIN_COLLECTION_STATUS="unavailable"

    local _la_raw="" _la_rc=0 _la_parsed="" _la_name _la_tmp
    local -a _la_names=()

    _la_raw=$(dscl -plist . read /Groups/admin GroupMembership 2>/dev/null) || _la_rc=$?
    if (( _la_rc != 0 )); then
        log_warn "auth: local_admins unavailable (dscl exited $_la_rc reading /Groups/admin)"
        return 0
    fi

    # The plist goes through a file, not a pipe: `"$PYTHON3" - <<'PYEOF'` already
    # uses stdin for the program, so piping the data in as well silently hands
    # python the plist as its source and every run reports unavailable. Same
    # root-owned 0700 temp dir the pwpolicy parse above uses (H11), never /tmp.
    _la_tmp=$(mktemp "$PATCHED_TMPDIR/localadmins.XXXXXX")
    printf '%s' "$_la_raw" > "$_la_tmp"

    # Exit 2: the attribute is absent. Exit 3: the output is not the expected
    # plist shape, a value is not a string, a name carries a control character
    # (a line-delimited handoff cannot carry one safely), or there are more
    # names than a real admin group would hold. Every one of them is a read
    # this run cannot vouch for, so none of them becomes a count.
    _la_parsed=$("$PYTHON3" - "$_la_tmp" <<'PYEOF'
import plistlib, sys
MAX_MEMBERS = 512
try:
    with open(sys.argv[1], "rb") as fh:
        data = plistlib.load(fh)
except Exception:
    sys.exit(3)
if not isinstance(data, dict):
    sys.exit(3)
key = "dsAttrTypeStandard:GroupMembership"
if key not in data:
    sys.exit(2)
names = data[key]
if not isinstance(names, list) or len(names) > MAX_MEMBERS:
    sys.exit(3)
for name in names:
    if not isinstance(name, str):
        sys.exit(3)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        sys.exit(3)
    print(name)
PYEOF
    ) || _la_rc=$?
    rm -f "$_la_tmp"

    case "$_la_rc" in
        0) ;;
        2) log_warn "auth: local_admins unavailable (/Groups/admin has no GroupMembership attribute; membership may be recorded as GroupMembers only)"; return 0 ;;
        *) log_warn "auth: local_admins unavailable (unparseable dscl output, exit $_la_rc)"; return 0 ;;
    esac

    # root is the built-in superuser, not a provisioned standing admin. It is
    # excluded from the roster exactly as it has always been from the count.
    while IFS= read -r _la_name; do
        [[ -n "$_la_name" ]] || continue
        [[ "$_la_name" == "root" ]] && continue
        _la_names+=("$_la_name")
    done <<< "$_la_parsed"

    LOCAL_ADMIN_ACCOUNTS=("${_la_names[@]}")
    LOCAL_ADMIN_COUNT=${#_la_names[@]}
    LOCAL_ADMIN_COLLECTION_STATUS="complete"
}

# local_admins_payload
#   Prints the whole top-level `local_admins` object for the payload heredoc.
#
#   The accounts key is omitted entirely unless the enumeration completed. An
#   empty array under a failed read would say "this Mac genuinely has no
#   standing admins", which is a different and false claim, and the server
#   would prune the roster it holds. Mirrors certs_payload_member and
#   hardware_health's per-section collection_status.
#
#   Each entry carries the platform-neutral shape the Windows agent emits:
#   name, principal_type and builtin. macOS reads /Groups/admin's local record,
#   whose GroupMembership holds individual account short names, so every entry
#   is principal_type "user"; root, the one built-in, is filtered out above, so
#   builtin is false for everything that remains. Windows additionally sends a
#   sid, which macOS has no equivalent of and omits.
local_admins_payload() {
    local _lp_first=1 _lp_name
    if [[ "${LOCAL_ADMIN_COLLECTION_STATUS:-unavailable}" != "complete" ]]; then
        printf '{"collection_status": "unavailable"}'
        return 0
    fi
    printf '{"collection_status": "complete", "accounts": ['
    for _lp_name in "${LOCAL_ADMIN_ACCOUNTS[@]}"; do
        (( _lp_first )) || printf ','
        _lp_first=0
        printf '{"name": %s, "principal_type": "user", "builtin": false}' "$(json_escape "$_lp_name")"
    done
    printf ']}'
}

collect_auth() {
    # MDM enrolment status
    collect_mdm_enrolment

    # Audit logging present (CIS 3.1)
    AUDIT_LOGGING="Unknown"
    if [[ -f "/etc/security/audit_control" ]]; then
        AUDIT_LOGGING="enabled"
    elif [[ -f "/etc/security/audit_control.example" ]]; then
        AUDIT_LOGGING="disabled"
    fi

    # Auto-login disabled (CIS 5.1)
    AUTO_LOGIN_USER=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "")
    [[ -z "$AUTO_LOGIN_USER" ]] && AUTO_LOGIN_USER="None"

    # Local admin count and roster (CIS 5.8 — excludes root). See
    # _collect_local_admins above for the failed-read contract.
    _collect_local_admins

    # Password policy.
    # `pwpolicy -getaccountpolicies` returns Apple's default localised
    # 4-character fallback on un-MDM-managed Macs — multi-language, useless,
    # huge. Detect that default and emit a flag instead of the bytes; for real
    # MDM-set policies keep the raw payload (capped) for server-side parsing.
    PW_POLICY_RAW_FULL=$(pwpolicy -getaccountpolicies 2>/dev/null || echo "")
    PW_POLICY_PRESENT="No"
    PW_POLICY_IS_DEFAULT="Unknown"
    PW_POLICY_RAW=""
    if [[ -n "$PW_POLICY_RAW_FULL" ]]; then
        PW_POLICY_PRESENT="Yes"
        if echo "$PW_POLICY_RAW_FULL" | grep -q "com.apple.defaultpasswordpolicy"; then
            PW_POLICY_IS_DEFAULT="Yes"
            PW_POLICY_RAW="(apple-default-4char-fallback)"
        else
            PW_POLICY_IS_DEFAULT="No"
            PW_POLICY_RAW=$(echo "$PW_POLICY_RAW_FULL" | tail -c 2048)
        fi
    fi

    # T2 batch 1 — parse numeric policy fields from the already-collected XML.
    # Empty string emits null, so treat_unknown_as = 'fail' applies on the
    # server. No new shell commands.
    #
    # These stay null for an unset value, never "NotConfigured" (PAT-1775):
    # a key missing from this output is not evidence the setting is absent.
    #   - Only the global policy is read. A per-user policy
    #     (pwpolicy -u <user>) can set the same limits while the global one
    #     is empty.
    #   - The same control can be expressed without these parameter keys: on
    #     macOS 26.6.2 Apple's own default policy sets a minimum length as
    #     policyContent "policyAttributePassword matches '.{4,}+'", with no
    #     policyAttributeMinimumLength anywhere.
    #   - PW_POLICY_IS_DEFAULT is a substring match, so output carrying the
    #     Apple default alongside a real policy skips this parse entirely.
    #   - A failed pwpolicy (exit status non-zero, e.g. 1 with "Error: ...")
    #     and an empty successful read both leave PW_POLICY_RAW_FULL empty
    #     through the "|| echo" fallback, and the output of a Mac with no
    #     policy at all could not be captured here to tell them apart.
    PWPOLICY_LOCKOUT_THRESHOLD=""
    PWPOLICY_LOCKOUT_RESET_MINUTES=""
    PWPOLICY_MIN_LENGTH=""
    PWPOLICY_MAX_AGE_DAYS=""
    PWPOLICY_HISTORY_DEPTH=""
    if [[ "$PW_POLICY_IS_DEFAULT" == "No" && -n "$PW_POLICY_RAW_FULL" ]]; then
        _PWPOL_TMP=$(mktemp "$PATCHED_TMPDIR/pwpol.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
        printf '%s' "$PW_POLICY_RAW_FULL" > "$_PWPOL_TMP"
        _PW_PARSED=$("$PYTHON3" - "$_PWPOL_TMP" <<'PYEOF'
import re, sys
try:
    with open(sys.argv[1]) as f:
        xml = f.read()
    def xi(key, div=1):
        m = re.search(r'<key>' + re.escape(key) + r'</key>\s*<integer>(\d+)</integer>', xml)
        return str(int(m.group(1)) // div) if m else ""
    print(xi('policyAttributeMaximumFailedAuthentications'))
    print(xi('autoEnableInSeconds', 60))
    print(xi('policyAttributeMinimumLength'))
    print(xi('policyAttributeExpiresEveryNDays'))
    print(xi('policyAttributePasswordHistoryDepth'))
except Exception:
    for _ in range(5): print("")
PYEOF
        ) || true
        rm -f "$_PWPOL_TMP"
        PWPOLICY_LOCKOUT_THRESHOLD=$(printf '%s' "$_PW_PARSED" | awk 'NR==1')
        PWPOLICY_LOCKOUT_RESET_MINUTES=$(printf '%s' "$_PW_PARSED" | awk 'NR==2')
        PWPOLICY_MIN_LENGTH=$(printf '%s' "$_PW_PARSED" | awk 'NR==3')
        PWPOLICY_MAX_AGE_DAYS=$(printf '%s' "$_PW_PARSED" | awk 'NR==4')
        PWPOLICY_HISTORY_DEPTH=$(printf '%s' "$_PW_PARSED" | awk 'NR==5')
    fi

    # Root account disabled (CIS T2 / mSCP §5.6)
    # A root shell of /usr/bin/false means root login is blocked (the correct state).
    # If dscl fails or /Users/root is absent, default "Yes" (assume disabled).
    ROOT_DISABLED="Yes"
    local _ROOT_SHELL
    _ROOT_SHELL=$(dscl . -read /Users/root UserShell 2>/dev/null || true)
    if [[ -n "$_ROOT_SHELL" ]] && ! printf '%s\n' "$_ROOT_SHELL" | grep -q "/usr/bin/false"; then
        ROOT_DISABLED="No"
    fi

    # §3.5 — Control access to audit records.
    # One pass: resolve the audit log directory from audit_control, then check the
    # control file, the log folder, and all log files for ACL, ownership, group,
    # and mode. Empty string → null in JSON → treat_unknown_as='fail'.
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
    local _AUDIT_DIR _AC_OWNER _AC_GROUP _AC_MODE _AF_OWNER _AF_GROUP _AF_MODE

    if [[ -f "/etc/security/audit_control" ]]; then
        _AUDIT_DIR=$(awk -F: '/^dir/{print $2}' /etc/security/audit_control 2>/dev/null | tr -d '[:space:]' || true)

        # audit_control file: ACL, owner (uid 0 = root), group (gid 0 = wheel), mode ≤ 440
        AUDIT_CONTROL_NO_ACL="Yes"
        if ls -le /etc/security/audit_control 2>/dev/null | grep -qE '^\s+[0-9]+:'; then
            AUDIT_CONTROL_NO_ACL="No"
        fi
        _AC_OWNER=$(stat -f '%u' /etc/security/audit_control 2>/dev/null || true)
        if [[ "$_AC_OWNER" == "0" ]]; then AUDIT_CONTROL_OWNER="Yes"; else AUDIT_CONTROL_OWNER="No"; fi
        _AC_GROUP=$(stat -f '%g' /etc/security/audit_control 2>/dev/null || true)
        if [[ "$_AC_GROUP" == "0" ]]; then AUDIT_CONTROL_GROUP="Yes"; else AUDIT_CONTROL_GROUP="No"; fi
        _AC_MODE=$(stat -f '%A' /etc/security/audit_control 2>/dev/null || true)
        if [[ -n "$_AC_MODE" ]]; then
            if (( _AC_MODE <= 440 )); then AUDIT_CONTROL_MODE="Yes"; else AUDIT_CONTROL_MODE="No"; fi
        fi

        # audit log folder
        if [[ -n "$_AUDIT_DIR" && -d "$_AUDIT_DIR" ]]; then
            AUDIT_FOLDER_NO_ACL="Yes"
            if ls -led "$_AUDIT_DIR" 2>/dev/null | grep -qE '^\s+[0-9]+:'; then
                AUDIT_FOLDER_NO_ACL="No"
            fi
            _AF_OWNER=$(stat -f '%u' "$_AUDIT_DIR" 2>/dev/null || true)
            if [[ "$_AF_OWNER" == "0" ]]; then AUDIT_FOLDER_OWNER="Yes"; else AUDIT_FOLDER_OWNER="No"; fi
            _AF_GROUP=$(stat -f '%g' "$_AUDIT_DIR" 2>/dev/null || true)
            if [[ "$_AF_GROUP" == "0" ]]; then AUDIT_FOLDER_GROUP="Yes"; else AUDIT_FOLDER_GROUP="No"; fi
            _AF_MODE=$(stat -f '%A' "$_AUDIT_DIR" 2>/dev/null || true)
            if [[ -n "$_AF_MODE" ]]; then
                if (( _AF_MODE <= 700 )); then AUDIT_FOLDER_MODE="Yes"; else AUDIT_FOLDER_MODE="No"; fi
            fi

            # audit log files: ACL check via ls -le listing, owner/group/mode via find
            AUDIT_LOGS_NO_ACL="Yes"
            if ls -le "$_AUDIT_DIR" 2>/dev/null | grep -qE '^\s+[0-9]+:'; then
                AUDIT_LOGS_NO_ACL="No"
            fi
            AUDIT_LOGS_OWNER="Yes"
            if find "$_AUDIT_DIR" -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q .; then
                AUDIT_LOGS_OWNER="No"
            fi
            AUDIT_LOGS_GROUP="Yes"
            if find "$_AUDIT_DIR" -maxdepth 1 -type f ! -group wheel 2>/dev/null | grep -q .; then
                AUDIT_LOGS_GROUP="No"
            fi
            # -perm +0337: any owner-write, owner-exec, group-write, group-exec, or other bit.
            # BSD find (macOS) doesn't support GNU's "/mode" any-bit syntax (errors
            # "illegal mode string", silently swallowed by 2>/dev/null below — the
            # check always no-opped). BSD find's own "+mode" syntax is the documented
            # equivalent: "true if any of the bits in mode are set in the file's mode
            # bits" (see `man find`), so it's a drop-in portable replacement.
            AUDIT_LOGS_MODE="Yes"
            if find "$_AUDIT_DIR" -maxdepth 1 -type f -perm +0337 2>/dev/null | grep -q .; then
                AUDIT_LOGS_MODE="No"
            fi
        fi
    fi

    # §5.4/5.5 — sudo configuration (timeout and per-TTY timestamp).
    SUDO_TIMEOUT_MINUTES=""
    SUDO_TIMESTAMP_TYPE=""
    local _SUDO_V
    _SUDO_V=$(sudo -V 2>/dev/null || true)
    if [[ -n "$_SUDO_V" ]]; then
        SUDO_TIMEOUT_MINUTES=$(printf '%s\n' "$_SUDO_V" | awk -F': ' '/Authentication timestamp timeout/{gsub(/ minutes.*/,"",$2); print int($2)+0}')
        SUDO_TIMESTAMP_TYPE=$(printf '%s\n' "$_SUDO_V" | awk -F': ' '/Type of authentication timestamp record/{print $2}' | tr -d ' \t')
    fi

    # §5.7 — Screensaver unlock requires session owner only (not admin).
    # Reads the authorizationdb right and extracts the 'group' key value.
    # CIS-compliant value is 'authenticate-session-owner'; the default Apple value
    # 'authenticate-session-owner-or-admin' allows admins to unlock any session.
    SCREENSAVER_UNLOCK_GROUP=""
    local _ss_authdb_tmp
    _ss_authdb_tmp=$(mktemp "$PATCHED_TMPDIR/authdb-ss.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    if security authorizationdb read system.login.screensaver > "$_ss_authdb_tmp" 2>/dev/null; then
        SCREENSAVER_UNLOCK_GROUP=$("$PYTHON3" - "$_ss_authdb_tmp" <<'PYEOF'
import re, sys
try:
    xml = open(sys.argv[1]).read()
    m = re.search(r'<key>group</key>\s*<string>([^<]+)</string>', xml)
    print(m.group(1) if m else '')
except Exception:
    print('')
PYEOF
        ) || true
    fi
    rm -f "$_ss_authdb_tmp"

    # §2.6.8 — System-wide preferences require admin authorisation.
    # Checks 8 preference-pane auth rights; shared=absent or shared=false means
    # admin is required. Any right with shared=true is non-compliant.
    SYSTEM_PREFS_ADMIN_LOCK=""
    SYSTEM_PREFS_ADMIN_LOCK=$("$PYTHON3" - <<'PYEOF'
import subprocess, re, sys

rights = [
    'system.preferences',
    'system.preferences.network',
    'system.preferences.security',
    'system.preferences.sharing',
    'system.preferences.energysaver',
    'system.preferences.bluetooth',
    'system.preferences.printing',
    'system.preferences.datetime',
]

def is_locked(right):
    try:
        r = subprocess.run(
            ['security', 'authorizationdb', 'read', right],
            capture_output=True, text=True, timeout=5
        )
        xml = r.stdout
        if not xml:
            return None
        m = re.search(r'<key>shared</key>\s*(<[^>]+/>)', xml)
        if m is None:
            return True   # absent = not shared = admin required (good)
        return m.group(1).strip() == '<false/>'
    except Exception:
        return None

results = [is_locked(r) for r in rights]
if any(v is None for v in results):
    print('')
elif all(results):
    print('Yes')
else:
    print('No')
PYEOF
    ) || true

    # §3.4: Audit log retention ≥ 60 days (see _audit_retention_expire above).
    _audit_retention_expire /etc/security/audit_control

    # §3.3 — install.log retention days (see _install_log_retention_days above).
    _install_log_retention_days /etc/asl/com.apple.install

    # §2.11.1 — Password hints absent from all user accounts.
    # dscl -list /Users hint prints username + hint only for users that have one set.
    # Checking awk $2 for any non-empty field reveals hint existence without capturing content.
    PASSWORD_HINTS_ABSENT="Yes"
    if dscl . -list /Users hint 2>/dev/null | awk '{print $2}' | grep -q .; then
        PASSWORD_HINTS_ABSENT="No"
    fi
}
