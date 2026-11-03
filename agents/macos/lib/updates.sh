# updates.sh — pending software updates, patch history, and auto-update setting.
# softwareupdate -l phones home to Apple's server and can be slow; it runs once
# and the output is shared between the count signal and the detail list.
#
# Software update setting signals (auto_security_updates, update_check_auto,
# update_download_auto, app_updates_auto_install, xprotect_data_auto_update,
# critical_updates_auto_install) are, per PAT-1767:
#   "On" / "Off"     the key reads 1 / 0
#   "NotConfigured"  `defaults read` reported the key missing and the
#                    SoftwareUpdate plist is absent or a readable dictionary
#                    (defaults prints the same "does not exist" line for a
#                    corrupt or unreadable plist; see common.sh)
#   "Unknown"        the read failed, the plist could not be confirmed
#                    readable, or the value is not 0 / 1. These signals keep
#                    their existing "Unknown" spelling for a failed read.
# Requires: PATCHED_TMPDIR, PYTHON3; prefs_defaults_read,
# prefs_plists_readable and log_warn (common.sh)
# Sourced by patched-collect.sh; not executable directly.

# _updates_su_plist: the SoftwareUpdate preferences plist every setting below
# is read from. A function so the tests can point it at a fixture.
_updates_su_plist() {
    print -r -- "/Library/Preferences/com.apple.SoftwareUpdate.plist"
}

# _su_setting <key>
# Reads one SoftwareUpdate key and sets _SU_SETTING to On / Off /
# NotConfigured / Unknown (see header).
_su_setting() {
    local su_plist
    su_plist=$(_updates_su_plist)
    # defaults is given the path without .plist, as before.
    prefs_defaults_read defaults read "${su_plist%.plist}" "$1"
    case "$PREFS_READ_STATE:$PREFS_READ_VALUE" in
        value:1) _SU_SETTING="On" ;;
        value:0) _SU_SETTING="Off" ;;
        absent:*)
            if prefs_plists_readable "$su_plist"; then
                _SU_SETTING="NotConfigured"
            else
                _SU_SETTING="Unknown"
                log_warn "updates: $1 undetermined ($PREFS_PLIST_REASON)"
            fi
            ;;
        *) _SU_SETTING="Unknown" ;;
    esac
}

collect_updates() {
    local _SU_SETTING
    # Read AutomaticCheckEnabled BEFORE `softwareupdate -l` runs below. On macOS
    # 15.7+, running `softwareupdate -l` clobbers/removes this preference key, so
    # reading it afterwards (as CIS §1.2 does further down) always reports
    # "Unknown". Capture it first and reuse the value later. (PAT-753)
    local _UPDATE_CHECK_AUTO_RAW
    _su_setting AutomaticCheckEnabled
    _UPDATE_CHECK_AUTO_RAW="$_SU_SETTING"

    # --- Pending updates (CIS 1.1) ---
    SU_LIST_TMP=$(mktemp "$PATCHED_TMPDIR/su-list.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    softwareupdate -l > "$SU_LIST_TMP" 2>&1 || true
    PENDING_UPDATES_COUNT=$(grep -c "^[[:space:]]*\* Label:" "$SU_LIST_TMP" 2>/dev/null || true)
    PENDING_UPDATES_COUNT=${PENDING_UPDATES_COUNT:-0}

    PENDING_UPDATES_JSON=$("$PYTHON3" - "$SU_LIST_TMP" <<'PYEOF'
import json, re, sys
out = []
try:
    with open(sys.argv[1]) as f:
        text = f.read()
except Exception:
    print("[]", end='')
    sys.exit(0)

# Each pending update is two lines:
#   * Label: SomeLabel-1.2.3
#       Title: Display Name, Version: 1.2.3, Size: NNNK[, Action: shut down|restart][, Recommended: YES]
pattern = re.compile(
    r'^\* Label:\s*(.+?)\s*\n'
    r'\s+Title:\s*(.+?),\s*Version:\s*(.+?),\s*Size:\s*\S+'
    r'(?:,\s*Action:\s*(.+?))?'
    r'(?:,\s*Recommended:\s*(\w+))?'
    r'\s*$',
    re.MULTILINE
)
for m in pattern.finditer(text):
    label, title, version, action, recommended = m.groups()
    out.append({
        "label":       label.strip(),
        "title":       title.strip(),
        "version":     version.strip(),
        "action":      (action.strip() if action else None),
        "recommended": (recommended or "").strip().upper() == "YES",
    })
print(json.dumps(out), end='')
PYEOF
    )
    rm -f "$SU_LIST_TMP"

    # --- Installed patch history ---
    # Dates are locale-dependent; force C locale and try multiple formats.
    SU_HISTORY_TMP=$(mktemp "$PATCHED_TMPDIR/su-history.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    LC_ALL=C softwareupdate --history --all > "$SU_HISTORY_TMP" 2>&1 || true

    PATCHES_JSON=$("$PYTHON3" - "$SU_HISTORY_TMP" <<'PYEOF'
import json, re, sys
from datetime import datetime

out = []
try:
    with open(sys.argv[1]) as f:
        text = f.read()
except Exception:
    print("[]", end='')
    sys.exit(0)

date_patterns = [
    "%m/%d/%Y, %H:%M:%S",
    "%d/%m/%Y, %H:%M:%S",
    "%Y-%m-%d, %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d %b %Y at %H:%M:%S",
]
row_re = re.compile(r'^(.+?)\s{2,}(\S+)\s{2,}(.+)$')

for line in text.splitlines():
    line = line.rstrip()
    if not line or line.startswith("Display Name") or line.startswith("Software Update Tool"):
        continue
    m = row_re.match(line)
    if not m:
        continue
    name, version, date_str = (g.strip() for g in m.groups())
    if not re.search(r'[A-Za-z0-9]', name):
        continue
    iso = None
    for fmt in date_patterns:
        try:
            iso = datetime.strptime(date_str, fmt).strftime("%Y-%m-%dT%H:%M:%SZ")
            break
        except ValueError:
            continue
    out.append({
        "name":         name,
        "version":      version,
        "installed_at": iso,
        "date_raw":     date_str,
    })
print(json.dumps(out), end='')
PYEOF
    )
    rm -f "$SU_HISTORY_TMP"

    # --- Auto-install security updates (CIS 1.4 / T1) ---
    _su_setting AutomaticallyInstallMacOSUpdates
    AUTO_SECURITY_UPDATES="$_SU_SETTING"

    # --- T2 batch 1: additional software-update enforcement signals (CIS §1.2/1.3/1.5/1.6) ---
    # All read from the same SoftwareUpdate preferences domain; 0/1 → Off/On.

    UPDATE_CHECK_AUTO="$_UPDATE_CHECK_AUTO_RAW"

    _su_setting AutomaticDownload
    UPDATE_DOWNLOAD_AUTO="$_SU_SETTING"

    _su_setting AutomaticallyInstallAppUpdates
    APP_UPDATES_AUTO_INSTALL="$_SU_SETTING"

    _su_setting ConfigDataInstall
    XPROTECT_DATA_AUTO_UPDATE="$_SU_SETTING"

    _su_setting CriticalUpdateInstall
    CRITICAL_UPDATES_AUTO_INSTALL="$_SU_SETTING"
}
