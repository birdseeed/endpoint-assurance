# inventory.sh — system extensions, background items, and iCloud presence.
# Requires: FIRST_USER (set by collect_hardware), PYTHON3
# Sourced by patched-collect.sh; not executable directly.

collect_inventory() {
    # Explicit defaults: bound before any command runs so an early function exit
    # (e.g. PATCHED_TMPDIR unavailable, BTM parse error on macOS 26) leaves
    # these variables set and the JSON heredoc valid.
    SYSEXT_JSON="[]"
    BACKGROUND_ITEMS_JSON="[]"
    ICLOUD_SIGNED_IN="Unknown"

    # --- System extensions ---
    SYSEXT_TMP=$(mktemp "$PATCHED_TMPDIR/sysexts.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    systemextensionsctl list 2>/dev/null > "$SYSEXT_TMP" || true

    SYSEXT_JSON=$("$PYTHON3" - "$SYSEXT_TMP" <<'PYEOF'
import sys, json, re
out = []
try:
    with open(sys.argv[1]) as f:
        for line in f:
            # macOS 26 format uses * and - markers for enabled/active columns:
            # *       *       TEAMID  bundleID (version)      Name    [state]
            # *       -       ...  (enabled but not active)
            # -       -       ...  (disabled)
            m = re.match(
                r'^([*\-])\s+([*\-])\s+(\S+)\s+(\S+)\s+\(([^)]+)\)\s+(.+?)\s*\[(.+?)\]\s*$',
                line.strip(),
            )
            if m:
                out.append({
                    "enabled":   m.group(1) == "*",
                    "active":    m.group(2) == "*",
                    "team_id":   m.group(3),
                    "bundle_id": m.group(4),
                    "version":   m.group(5),
                    "name":      m.group(6).strip(),
                    "state":     m.group(7),
                })
except Exception:
    pass
print(json.dumps(out), end='')
PYEOF
    )
    rm -f "$SYSEXT_TMP"

    # --- Background items (macOS 13+, BTM-tracked Login Items + LaunchAgents) ---
    BTM_FILE=$(ls -t /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm 2>/dev/null | head -1)
    BACKGROUND_ITEMS_JSON="[]"
    if [[ -n "$BTM_FILE" && -f "$BTM_FILE" ]]; then
        BACKGROUND_ITEMS_JSON=$("$PYTHON3" - "$BTM_FILE" <<'PYEOF'
import sys, json, plistlib
try:
    with open(sys.argv[1], 'rb') as f:
        pl = plistlib.load(f)
    items = []
    for store in pl.get('store', []) if isinstance(pl, dict) else []:
        for uid_entries in store.get('itemsByUserIdentifier', {}).values():
            for entry in uid_entries:
                items.append({
                    "name":        entry.get('name', '') or '',
                    "identifier":  entry.get('identifier', '') or '',
                    "team_id":     entry.get('teamIdentifier', '') or '',
                    "url":         str(entry.get('url', '')),
                    "type":        entry.get('type', 0),
                    "disposition": entry.get('disposition', 0),
                })
    print(json.dumps(items[:500]), end='')  # cap at 500 for sanity
except Exception:
    print("[]", end='')
PYEOF
        )
    fi

    # --- iCloud / Apple ID presence ---
    # ICLOUD_SIGNED_IN is pre-set to "Unknown" above; overwrite when we can read
    # the accounts plist.  Use Python plistlib (more robust than plutil -extract
    # across macOS versions): plutil -extract Accounts raw may output differently
    # on macOS 26 (returns plist XML for arrays rather than a bare count).
    if [[ -n "$FIRST_USER" ]]; then
        local _USER_HOME _ACCOUNTS_PLIST
        _USER_HOME=$(dscl . read /Users/"$FIRST_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
        _ACCOUNTS_PLIST="$_USER_HOME/Library/Preferences/MobileMeAccounts.plist"
        if [[ -f "$_ACCOUNTS_PLIST" ]]; then
            ICLOUD_SIGNED_IN=$("$PYTHON3" - "$_ACCOUNTS_PLIST" <<'PYEOF'
import sys, plistlib
try:
    with open(sys.argv[1], 'rb') as f:
        pl = plistlib.load(f)
    accounts = pl.get('Accounts', [])
    print('Yes' if len(accounts) > 0 else 'No')
except Exception:
    print('Unknown')
PYEOF
            ) || ICLOUD_SIGNED_IN="Unknown"
        else
            ICLOUD_SIGNED_IN="No"
        fi
    fi
}
