# common.sh — shared helpers sourced by every collector module.
# Sourced by patched-collect.sh; not executable directly.
# Requires: PYTHON3 (set by main script before sourcing)

# Escape an arbitrary string for safe inclusion in JSON. Returns the JSON-encoded
# string including surrounding quotes.
json_escape() {
    local _result
    _result=$(printf '%s' "$1" | "$PYTHON3" -c 'import json,sys; print(json.dumps(sys.stdin.buffer.read().decode("utf-8", errors="replace")), end="")' 2>/dev/null)
    if [[ -z "$_result" ]]; then
        printf '""'
    else
        printf '%s' "$_result"
    fi
}

# Read a managed NSUserDefaults preference and whether a configuration
# profile enforces it, in ONE osascript JXA invocation.
# Usage: managed_pref_read <domain> <key>
# On success returns 0 and sets:
#   MANAGED_PREF_VALUE   the effective value, exactly as read_managed_pref
#                        prints it (the full NSUserDefaults search list, so a
#                        value set locally reads the same as a forced one);
#                        empty when the key is not set
#   MANAGED_PREF_FORCED  "true" when objectIsForcedForKey says a profile
#                        enforces the key (Managed Preferences), else "false"
#   MANAGED_PREF_SET     "true" when objectForKey returned a value (of any
#                        type, including an empty string), "false" when it
#                        returned nil (PAT-1767). nil is also what
#                        NSUserDefaults returns for a corrupt or unreadable
#                        plist, so "false" alone is not proof of absence: see
#                        prefs_plists_readable below.
# Returns non-zero with all three variables empty when osascript fails or its
# output is not the expected shape, so a caller can tell "read succeeded, not
# forced" from "could not read" and never turns a failure into "false".
# Reports forced-ness alongside the effective value rather than instead of it:
# a forced-only read would fail CIS rules on genuinely configured Macs with no
# MDM, which Patched must not require (PAT-1720).
# domain and key are only ever hard-coded literals from managed_prefs.sh;
# anything outside [A-Za-z0-9._-] is refused before it reaches the JXA source.
managed_pref_read() {
    local domain="$1" key="$2" _out _header
    MANAGED_PREF_VALUE=""
    MANAGED_PREF_FORCED=""
    MANAGED_PREF_SET=""
    [[ "$domain" =~ '^[A-Za-z0-9._-]+$' && "$key" =~ '^[A-Za-z0-9._-]+$' ]] || return 1
    # First output line is "<forced> <set|unset>"; everything after the first
    # newline is the value. String(v) prints scalars (booleans, numbers,
    # strings) exactly as osascript prints objectForKey(...).js on its own;
    # undefined (key not set) prints nothing. "set" / "unset" is carried
    # separately because an empty string value and an unset key print the
    # same empty value (PAT-1767).
    _out=$(/usr/bin/osascript -l JavaScript 2>/dev/null <<EOS
var d = \$.NSUserDefaults.alloc.initWithSuiteName('${domain}');
var v = d.objectForKey('${key}').js;
(d.objectIsForcedForKey('${key}') ? 'true' : 'false') + ' ' + (v === undefined ? 'unset' : 'set') + '\n' + (v === undefined ? '' : String(v))
EOS
) || return 1
    _header="${_out%%$'\n'*}"
    [[ "$_header" =~ '^(true|false) (set|unset)$' ]] || return 1
    MANAGED_PREF_FORCED="${match[1]}"
    if [[ "${match[2]}" == "set" ]]; then MANAGED_PREF_SET="true"; else MANAGED_PREF_SET="false"; fi
    # Command substitution strips the trailing newline, so an unset key (or
    # an empty string value) arrives as the bare header with no separator.
    if [[ "$_out" == *$'\n'* ]]; then
        MANAGED_PREF_VALUE="${_out#*$'\n'}"
    fi
    return 0
}

# Read a managed NSUserDefaults preference via osascript JXA.
# Usage: read_managed_pref <domain> <key>
# Prints the effective value (the full NSUserDefaults search list, so a value
# set locally reads the same as one a profile forces) or nothing when the key
# is not set. Returns non-zero, printing nothing, when osascript itself fails,
# so a caller can tell "read succeeded, key absent" from "could not read".
# Use managed_pref_read when the caller also needs forced-ness.
read_managed_pref() {
    managed_pref_read "$1" "$2" || return 1
    print -r -- "$MANAGED_PREF_VALUE"
}

# ── Absent versus failed preference reads (PAT-1767) ───────────────────────
# Compliance signal contract: every value is a real value, the exact string
# "NotConfigured" (the read succeeded and the setting is absent), or
# null / "Unknown" (the read itself failed). A failed read must never become
# "NotConfigured".
#
# Neither preference reader can tell those apart on its own. Verified on
# macOS 26.6.2: `defaults read <domain> <key>` exits 1 with the identical
# stderr line "The domain/default pair of (<domain>, <key>) does not exist"
# for a missing key, a missing domain, a missing plist, a plist it has no
# permission to read, a corrupt plist and a plist whose root is not a
# dictionary. NSUserDefaults objectForKey returns nil for the same cases.
#
# So "absent" is only claimed with two pieces of evidence:
#   1. the reader ran and reported the key missing: `defaults` exited
#      non-zero with exactly that stderr line (prefs_defaults_read), or the
#      managed_pref_read JXA call exited 0 with a well-formed "unset" header;
#   2. every plist the reader could have taken the key from either does not
#      exist, or is a readable regular file, in searchable directories, whose
#      contents parse as a dictionary (prefs_plists_readable). The caller
#      names those plists, because only it knows which domain it read.
# Any other outcome (a different exit or error text, sudo failing, an
# unreadable or corrupt plist, no scratch directory for stderr) is a failed
# read. The plist check only runs after a read reports absence, so it never
# changes a value that was actually read.

# prefs_defaults_read <command...>
# Runs a `defaults read` command line (optionally behind `sudo -u <user>`)
# and sets:
#   PREFS_READ_STATE  "value"   exit 0; PREFS_READ_VALUE is its stdout
#                     "absent"  exit non-zero and stderr carried the
#                               "does not exist" line; still needs
#                               prefs_plists_readable before it is trusted
#                     "failed"  anything else
#   PREFS_READ_VALUE  stdout on "value", else empty
# stderr goes to a scratch file under PATCHED_TMPDIR (H11), never mixed into
# the value. Returns 0 unless the state is "failed".
prefs_defaults_read() {
    local pd_err="" pd_rc=0
    PREFS_READ_VALUE=""
    PREFS_READ_STATE="failed"
    [[ -n "${PATCHED_TMPDIR:-}" && -d "${PATCHED_TMPDIR:-}" ]] || return 1
    pd_err=$(mktemp "$PATCHED_TMPDIR/prefs-read.XXXXXX" 2>/dev/null) || return 1
    PREFS_READ_VALUE=$("$@" 2>"$pd_err") || pd_rc=$?
    if (( pd_rc == 0 )); then
        PREFS_READ_STATE="value"
    else
        PREFS_READ_VALUE=""
        if grep -qE '^The domain/default pair of \(.*\) does not exist$' "$pd_err" 2>/dev/null; then
            PREFS_READ_STATE="absent"
        fi
    fi
    rm -f "$pd_err"
    [[ "$PREFS_READ_STATE" != "failed" ]]
}

# prefs_plists_readable <plist...>
# Returns 0 when every named plist either does not exist or is a readable
# regular file whose contents parse (plistlib) as a dictionary, and no
# existing ancestor directory of any of them is unsearchable (which would
# hide whether the plist exists). Otherwise returns 1 and sets
# PREFS_PLIST_REASON. With no arguments it returns 0.
prefs_plists_readable() {
    local pp_file pp_dir
    local -a pp_existing
    PREFS_PLIST_REASON=""
    for pp_file in "$@"; do
        pp_dir="${pp_file:h}"
        while [[ "$pp_dir" != "/" && ! -e "$pp_dir" ]]; do pp_dir="${pp_dir:h}"; done
        if [[ ! -d "$pp_dir" || ! -x "$pp_dir" ]]; then
            PREFS_PLIST_REASON="directory not searchable: $pp_dir"
            return 1
        fi
        [[ -e "$pp_file" || -L "$pp_file" ]] || continue
        if [[ ! -f "$pp_file" || ! -r "$pp_file" ]]; then
            PREFS_PLIST_REASON="unreadable plist: $pp_file"
            return 1
        fi
        pp_existing+=( "$pp_file" )
    done
    (( ${#pp_existing[@]} )) || return 0
    if ! "$PYTHON3" -c '
import plistlib, sys
for p in sys.argv[1:]:
    with open(p, "rb") as f:
        if not isinstance(plistlib.load(f), dict):
            sys.exit(1)
' "${pp_existing[@]}" >/dev/null 2>&1; then
        PREFS_PLIST_REASON="unparseable plist among: ${pp_existing[*]}"
        return 1
    fi
    return 0
}

# Return the primary console user (the user logged in at the GUI, not root).
# Uses stat on /dev/console — works under sudo without TCC.
console_user() {
    stat -f %Su /dev/console 2>/dev/null || echo ""
}

# Write a warning to stderr (captured by the log redirect in main).
log_warn() {
    echo "WARN: $*" >&2
}

# patched_tcc_health <subject> <denied-count> <verdict>
#   The agent_health entry tcc_denied / <subject> / full_disk_access_missing
#   for a collector whose walk macOS privacy protection (TCC) refused
#   (PAT-2100, the PAT-2096 rule browser_extensions.sh applies itself in
#   _bx_record_tcc_health). A no-op when agent_health.sh is not loaded.
#   verdict is the collector's own reading of its walk:
#     denied   some folder or file was refused with EPERM: record
#     reached  the walk ran to the end and every folder it would read was
#              opened: clear
#     unknown  anything else (failed, truncated, a folder that could not be
#              opened for another reason): no opinion, the entry stays
#   Only the LaunchDaemon run (parent PID 1) touches the entry: a run a user
#   starts has a different TCC attribution, so its result says nothing about
#   the daemon's access. It still logs the WARN. _PATCHED_TCC_HEALTH_PPID
#   overrides $PPID for tests only.
patched_tcc_health() {
    local _th_subject="$1" _th_count="$2" _th_verdict="$3"
    if [[ "$_th_verdict" == denied ]]; then
        log_warn "$_th_subject: macOS privacy protection denied access to $_th_count folder(s) or file(s) (Full Disk Access is not granted to the Patched collector)"
    fi
    if ! typeset -f patched_agent_health_record_failure >/dev/null 2>&1 \
        || ! typeset -f patched_agent_health_record_success >/dev/null 2>&1; then
        echo "$_th_subject: the agent_health store functions are not loaded; the tcc_denied entry is left as it was" >&2
        return 0
    fi
    if [[ "${_PATCHED_TCC_HEALTH_PPID:-$PPID}" != 1 ]]; then
        echo "$_th_subject: not the LaunchDaemon run (parent ${_PATCHED_TCC_HEALTH_PPID:-$PPID}); the tcc_denied agent_health entry is left as it was" >&2
        return 0
    fi
    case "$_th_verdict" in
        denied) patched_agent_health_record_failure tcc_denied "$_th_subject" full_disk_access_missing >&2 ;;
        reached) patched_agent_health_record_success tcc_denied "$_th_subject" >&2 ;;
    esac
    return 0
}

# patched_tcc_summary <parser-summary-file>
#   Prints "<denied-count> <verdict>" from the collector parser's line that
#   starts "tcc " (PAT-2100), found by its prefix so another line cannot
#   shift it. A missing, repeated or garbled line prints "0 unknown": no
#   opinion, so patched_tcc_health leaves the store as it was.
patched_tcc_summary() {
    local -a _ts_lines _ts_f
    _ts_lines=("${(@f)$(grep '^tcc ' "$1" 2>/dev/null)}")
    _ts_f=(${=_ts_lines[1]:-})
    if (( ${#_ts_lines} == 1 && ${#_ts_f} == 3 )) && [[ "${_ts_f[1]}" == tcc && "${_ts_f[2]}" == <-> \
        && "${_ts_f[3]}" == (denied|reached|unknown) ]]; then
        print -r -- "${_ts_f[2]} ${_ts_f[3]}"
    else
        print -r -- "0 unknown"
    fi
}

# patched_block_within_budget <subject> <block-file> <max-bytes>
#   The byte budget for a tooling block (PAT-2225). Succeeds when the block
#   file, which the payload member emits unchanged, is at most max-bytes
#   bytes. Otherwise it logs a WARN with the size and the budget, rewrites the
#   file as {"collection_status": "failed"} and fails, and the caller marks
#   the block failed. The server truncates an inventory body at 6 MiB and the
#   HMAC check then fails on every check-in, so one oversized block would cost
#   the device all of its inventory. The platform's tooling contract has no
#   size_limit truncation reason (homebrew's does), so an oversized block
#   cannot be cut down and sent partial: failed is the one status the platform
#   accepts that sends no item list and grants no absence authority. A file
#   that cannot be measured counts as over the budget.
patched_block_within_budget() {
    local _bb_subject="$1" _bb_file="$2" _bb_max="$3" _bb_size
    _bb_size=$(wc -c < "$_bb_file" 2>/dev/null) || _bb_size=""
    _bb_size=${_bb_size//[[:space:]]/}
    if [[ "$_bb_size" == <-> && "$_bb_max" == <-> ]] && (( _bb_size <= _bb_max )); then
        return 0
    fi
    log_warn "$_bb_subject: block is ${_bb_size:-unmeasurable} bytes, over the ${_bb_max}-byte budget; sent as failed"
    printf '{"collection_status": "failed"}' > "$_bb_file"
    return 1
}

# Return $1 if non-empty, else $2.
default_or() {
    if [[ -n "$1" ]]; then
        echo "$1"
    else
        echo "$2"
    fi
}

# Emit the bare JSON boolean for $1 when it is exactly "true" or "false",
# else emit null (undetermined). Never quote-free anything else into JSON.
json_bool_or_null() {
    case "$1" in
        true|false) printf '%s' "$1" ;;
        *)          printf 'null' ;;
    esac
}

# Emit a JSON string for $1 if non-empty, else emit the bare token null.
# Use instead of json_escape for optional signals that should be absent (null)
# when the collector couldn't determine the value.
json_or_null() {
    if [[ -n "$1" ]]; then
        json_escape "$1"
    else
        printf 'null'
    fi
}

# Emit a numeric compliance signal (PAT-1775, the PAT-1767 contract for
# numbers): a bare JSON integer when $1 is a whole number, the JSON string
# "NotConfigured" when $1 is exactly that, else the bare token null (empty
# included, so a module that never ran stays undetermined). Leading zeros are
# dropped because 0365 is not a valid JSON number, and more than 18 digits is
# null rather than a number a signed 64-bit reader would overflow on. Nothing
# else is ever written unquoted into the payload.
json_int_or_notconfigured() {
    local jn_value="$1"
    if [[ "$jn_value" == "NotConfigured" ]]; then
        printf '"NotConfigured"'
    elif [[ "$jn_value" =~ '^[0-9]{1,18}$' ]]; then
        while [[ "$jn_value" == 0?* ]]; do jn_value="${jn_value#0}"; done
        printf '%s' "$jn_value"
    else
        printf 'null'
    fi
}
