# browser_extensions.sh — browser extension inventory.
# Sets BROWSER_EXTENSIONS_JSON_FILE (path to the temp JSON array file), constructed
# from QUEUE_DIR and TS_FILE globals set by the main script.
# Sourced by patched-collect.sh; not executable directly.
#
# Runs as root; iterates all human users under /Users/* (skipping Shared and Guest).
# Covers Chrome, Edge (Chromium-based), and Firefox per-user, plus Safari (PAT-821).
#
# Safari: modern Safari extensions are App Extensions bundled inside a host .app's
# Contents/PlugIns/*.appex — one shared copy per Mac, not one per user profile like
# Chrome/Firefox — so collect_safari_app_extensions() runs once, filesystem-only
# (no TCC-protected per-user container involved, unlike the legacy
# ~/Library/Safari/Extensions/ path this intentionally still does not touch).
# Per-user enabled/disabled election state is only obtainable via `pluginkit` run
# inside an actual login session, so it's best-effort (console user only, mirroring
# the Spotlight-metering pattern in apps.sh) and reported as null when unknown.
#
# JSON parsing of manifest.json / Secure Preferences / extensions.json is done via
# inline Python3 — the agent already depends on /usr/bin/python3 and we must not
# shell-parse JSON. Safari's Info.plist / appex parsing uses the same Python3
# program via the stdlib plistlib module (no PlistBuddy dependency).
#
# EVERY TREE HERE CAN BE WRITTEN BY AN ORDINARY USER AND THIS RUNS AS ROOT
# (PAT-2054). Browser profiles live in the user's home, and ~/Applications is
# one of the Safari search roots. So every file and directory is reached
# through the PAT-2033 walk helpers, copied verbatim from ide_extensions.sh:
# each open starts at / and opens every directory relative to the one before
# with O_NOFOLLOW, and every file must be a regular file with one link under
# a size cap, opened O_NONBLOCK. A symlinked home, profile, extension or
# version directory, manifest, preferences file or bundle is refused and
# costs only that subtree's rows, never a read of another user's or a
# root-only file, and a directory swapped for a symlink between its check and
# its read is refused too. test-package-managers.zsh [drift] keeps the helper
# copies byte-identical. A manifest's default_locale must be one plain path
# component (see LOCALE_RE) before it is joined into a path, so
# "../../Users/bob/..." cannot point the name lookup at another user's JSON;
# anything else falls back to the extension id as the name.
#
# Refusals are written to the collect log (WARN on stderr), grouped by reason
# (see _bx_log_refusals). Running as root without Full Disk Access, macOS
# privacy protection (TCC) lets the walk lstat another app's data folder
# (Chrome, Edge, Firefox) but refuses to open it with EPERM. That is logged
# as tcc_denied rather than unreadable, and recorded as the agent_health
# entry tcc_denied / browser_extensions / full_disk_access_missing
# (PAT-2096). It is still a refusal like any other: no rows from that folder,
# and the pair is partial, never not_present. A refused subtree
# sends no rows, and the browser_extensions_status block (PAT-2065, the agent
# half of PAT-2055) says so: per user, Chrome, Edge and Firefox are each
#   complete     every profile was read in full, and every row is listed
#   not_present  the browser has no user-data directory for that user
#   partial      a profile or file was refused, unreadable or unparseable, or
#                the user's share of the row cap cut the read short
#   failed       the read of that browser threw (or the home itself could not
#                be entered, which fails all three)
# and the block as a whole is failed when /Users cannot be listed or the
# parser dies. Safari is not in the block (its rows carry no user), and since
# PAT-2064 the platform's block authority covers Chrome, Edge and Firefox rows
# only, so the Safari walk never changes the block's status (PAT-2067). The
# one exception is the shared row cap: a cap hit anywhere, Safari included, is
# cap_reached and a partial block, because the array was cut.
# The array itself is unchanged: the block is a sibling key.
#
# Safari has its own signal, top-level collection_status.safari_extensions
# (PAT-2067), which is the only thing that lets the platform mark a stored
# Safari row removed. SAFARI_EXTENSIONS_COLLECTION_STATUS holds it:
#   complete     find listed every search root with no error (and, with the
#                default roots, the home root could be listed), no search
#                root and no .app, .appex or PlugIns in the walk is a symlink
#                (find follows none, so what is behind one is unseen), the parser
#                read every listed bundle with nothing refused and ran to the
#                end, and every row it found was sent: no row cap anywhere in
#                the array (cap_reached false). An empty list is complete.
#   partial      a root, bundle or file could not be read or was refused, or
#                the row cap cut the array; the rows that were read are sent
#   unavailable  the walk failed outright: the parser died or could not read
#                the appex list before sending any Safari row, or the
#                collector never ran (the default)
# find has no depth limit (PAT-2079): an appex in an app nested any number
# of folders deep is found and sent, and every symlink in the walk is judged.
# More than _BX_SAFARI_MAX_LINKS links is partial, which bounds the link work;
# a user who fills their own ~/Applications with a huge tree slows only their
# own device's collection. Contents/PlugIns is matched without regard to
# case, as APFS resolves it.
#
# Row cap and fair share (PAT-2065). MAX_EXTENSIONS stays 1,000 for the whole
# array. Each user may emit at most (budget left) / (users left) rows, so one
# user with a pathological profile cannot crowd out the users after them. A
# user who hits their share stops there: that browser and the ones not yet
# read are partial and cap_reached is true.
#
# Fail-safe semantics mirror apps.sh: set -u only (inherited from main script),
# || true defaults, skip unreadable dirs, never abort the loop. As before
# PAT-2054, a profile whose files do not have the expected JSON shape stops
# that profile's rows, not the whole collection.
# Array capped at MAX_EXTENSIONS to bound payload size.

# Where home directories live, and Safari search roots to use in place of the
# real app locations (empty means the defaults in collect_safari_app_extensions).
# Tests reassign these after sourcing.
_BX_USERS_ROOT=/Users
_BX_SAFARI_ROOTS=()
# The machine-wide app locations searched when _BX_SAFARI_ROOTS is empty, next
# to "$_BX_USERS_ROOT"/*/Applications. Tests point it at a fixture.
_BX_SAFARI_APP_ROOTS=(/Applications /Applications/Utilities)
# A symlink whose resolved target is under this SIP-protected tree hides no
# third-party Safari extension (see _bx_safari_link_harmless). Tests point it
# at a fixture, because CI has no /System.
_BX_SAFARI_SYSTEM_ROOT=/System
# The row cap for the whole array (see header). Tests lower it; nothing else
# should.
_BX_MAX_EXTENSIONS=1000
# How many symlinks in the Safari walk are judged before it gives up and
# reports partial (PAT-2079). Tests lower it; nothing else should.
_BX_SAFARI_MAX_LINKS=100000

# _bx_append <json-line> — appends one row to BROWSER_EXTENSIONS_JSON_FILE.
_bx_append() {
    if [[ "$FIRST_EXT" == "false" ]]; then
        printf ',' >> "$BROWSER_EXTENSIONS_JSON_FILE"
    fi
    FIRST_EXT=false
    printf '%s\n' "$1" >> "$BROWSER_EXTENSIONS_JSON_FILE"
    EXT_COUNT=$((EXT_COUNT + 1))
}

# safari_extensions_collection_status: the wire value for
# collection_status.safari_extensions. Anything other than complete or partial
# (unset, a collector that never ran, a typo) is unavailable, so the server
# never treats an unknown state as a reading.
safari_extensions_collection_status() {
    case "${SAFARI_EXTENSIONS_COLLECTION_STATUS:-}" in
        complete|partial) print -r -- "$SAFARI_EXTENSIONS_COLLECTION_STATUS" ;;
        *) print -r -- "unavailable" ;;
    esac
}

# _bx_safari_system_allowed <resolved-path>
#   Succeeds when the path is inside a SIP-protected subtree that holds no
#   third-party Safari extension: $_BX_SAFARI_SYSTEM_ROOT/Applications,
#   /Library, /Cryptexes, and /Volumes/Preboot/Cryptexes (where
#   /Applications/Safari.app resolves through /System/Cryptexes/App). Not
#   "anything under /System": zsh :A does not follow firmlinks, so a link to
#   /System/Volumes/Data/... keeps that prefix while pointing at the writable
#   data volume (/Users, /Applications, /Volumes). For the same reason the
#   /System/Library subtrees firmlinked to the data volume (/usr/share/firmlinks)
#   are excluded, compared case-insensitively since APFS is.
_bx_safari_system_allowed() {
    local _p="$1" _s="${_BX_SAFARI_SYSTEM_ROOT:A}" _a
    for _a in Library/Caches Library/Assets Library/PreinstalledAssets Library/AssetsV2 \
              Library/PreinstalledAssetsV2 Library/CoreServices/CoreTypes.bundle/Contents/Library Library/Speech; do
        [[ "${_p:l}" == "${_s:l}/${_a:l}" || "${_p:l}" == "${_s:l}/${_a:l}"/* ]] && return 1
    done
    for _a in Applications Library Cryptexes Volumes/Preboot/Cryptexes; do
        [[ "$_p" == "$_s/$_a" || "$_p" == "$_s/$_a"/* ]] && return 0
    done
    return 1
}

# _bx_safari_link_harmless <kind> <link> <search-root ...>
#   Succeeds when a symlink in the Safari walk hides no extension that find
#   would otherwise have listed. find follows no link (and must not, as root),
#   so what a link points at is never walked through it. The link is resolved
#   once, with zsh's :A (realpath(3)) plus a stat of the result; nothing it
#   points at is opened, listed or walked. The result is left in
#   _BX_LINK_REAL for the caller's log line. A stat under a stale network
#   mount (/Volumes) can block until that mount times out; not handled here.
#
#   <kind> root: a search root that is a link. Harmless only when its target
#   is a directory in the /System allowlist (_bx_safari_system_allowed).
#   Otherwise, by the link's name, with "bundle" the top-level .app the link
#   sits in (the first .app below the search root, the link itself excluded):
#     PlugIns under     harmless when the target exists and is in the /System
#       Contents, or    allowlist, or is inside the same bundle on a
#       *.appex         */Contents/PlugIns path (any case), since find lists an appex only on a */Contents/PlugIns/*
#                       path ($bundle/Contents/PlugIns -> Resources/stash
#                       hides every appex in it). A PlugIns elsewhere, such as
#                       a framework's own, is on no such path and takes the
#                       generic rule
#     *.app             harmless when the target exists and is in the /System
#                       allowlist, or is inside the same bundle, which find
#                       walks by its real path (framework Versions/Current,
#                       Sparkle's Updater.app)
#     Contents under    harmless only in the /System allowlist: a bundle's
#       a .app          Contents moved elsewhere takes its PlugIns off every
#                       */Contents/PlugIns/* path
#     anything else     harmless unless it resolves to a directory; a
#                       directory is harmless in the /System allowlist or
#                       inside the same bundle (framework internals), and
#                       outside any bundle only in the allowlist, since a
#                       linked folder of apps hides them all
#   A dangling, looping or unresolvable link with one of the first three
#   names is never harmless.
_bx_safari_link_harmless() {
    local _kind="$1" _link="$2"; shift 2
    local _real="${_link:A}" _name="${${_link:t}:l}" _parent="${${_link:h}:t:l}"
    local _r _root="" _rest _bundle="" _i
    local -a _parts
    _BX_LINK_REAL="$_real"
    local _exists=0
    [[ -n "$_real" && -e "$_real" && ! -L "$_real" ]] && _exists=1
    if [[ "$_kind" == root ]]; then
        (( _exists )) && [[ -d "$_real" ]] && _bx_safari_system_allowed "$_real"
        return
    fi
    for _r in "$@"; do
        [[ "$_link" == "$_r"/* && ${#_r} -gt ${#_root} ]] && _root="$_r"
    done
    if [[ -n "$_root" ]]; then
        _rest="${_link#"$_root"/}"
        _parts=("${(@s:/:)_rest}")
        for (( _i = 1; _i < ${#_parts}; _i++ )); do
            if [[ "${_parts[_i]:l}" == *.app ]]; then
                _bundle="$_root/${(j:/:)_parts[1,_i]}"
                break
            fi
        done
        # A bundle that is itself a link is judged on its own; never trust
        # the tree behind it.
        [[ -n "$_bundle" && -L "$_bundle" ]] && _bundle=""
        [[ -n "$_bundle" ]] && _bundle="${_bundle:A}"
    fi

    # Only a PlugIns directly under Contents, or an .appex under a
    # Contents/PlugIns, is on a path find lists appexes from; a framework's
    # own PlugIns link (Xcode's) is not, and falls through to the generic
    # rule below.
    local _listable=0
    case "$_name" in
        plugins) [[ "${_link:l}" == */contents/plugins || "${_link:l}" == */contents/plugins/* ]] && _listable=1 ;;
        *.appex) [[ "${_link:l}" == */contents/plugins/* ]] && _listable=1 ;;
    esac
    case "$_name" in
        plugins|*.appex)
            (( _listable )) || { [[ "$_name" == plugins ]] && _name=other; }
            ;;
    esac
    case "$_name" in
        plugins|*.appex)
            (( _exists )) || return 1
            _bx_safari_system_allowed "$_real" && return 0
            [[ -n "$_bundle" ]] || return 1
            [[ "$_real" == "$_bundle"/* ]] || return 1
            # The target must itself be on a path find lists appexes from,
            # compared without regard to case as find's -ipath does (APFS
            # resolves Contents/plugins as Contents/PlugIns).
            if [[ "$_name" == plugins ]]; then
                [[ "${_real:l}" == */contents/plugins || "${_real:l}" == */contents/plugins/* ]] || return 1
            else
                [[ "${_real:l}" == */contents/plugins/* ]] || return 1
            fi
            # find has no depth limit, so it walks that real path.
            return 0
            ;;
        *.app)
            (( _exists )) || return 1
            _bx_safari_system_allowed "$_real" && return 0
            [[ -n "$_bundle" ]] && [[ "$_real" == "$_bundle" || "$_real" == "$_bundle"/* ]]
            return
            ;;
    esac
    if [[ "$_name" == contents && "$_parent" == *.app ]]; then
        (( _exists )) && _bx_safari_system_allowed "$_real"
        return
    fi
    # Any other name hides nothing unless it is a directory.
    (( _exists )) && [[ -d "$_real" ]] || return 0
    _bx_safari_system_allowed "$_real" && return 0
    [[ -n "$_bundle" ]] && [[ "$_real" == "$_bundle" || "$_real" == "$_bundle"/* ]]
}

# _bx_log_refusals <stderr-file> [users|safari] — WARN lines to the collect
# log, one per kind of refusal, each naming how many paths and the first few
# of them, then removes the file (PAT-2096 split them by reason):
#   tcc_denied      users walk only (Chrome, Edge, Firefox): macOS privacy
#                   protection (TCC) denied root a browser data folder or
#                   file, because Full Disk Access is not granted to the
#                   collector. Counted once per path into _BX_TCC_DENIED for
#                   the agent_health entry (_bx_record_tcc_health). The Safari
#                   walk ("safari") never feeds that count; a tcc_denied there
#                   is logged with the unreadable paths
#   symlink_not_followed, not_regular, unsafe_default_locale,
#   outside_search_root
#                   a symlink, something that is not a plain file or
#                   directory, or an unsafe name
#   anything else   a path that could not be read or parsed (unreadable, which
#                   includes a hard link and a file over its size cap, a
#                   malformed bundle, a row that would not serialise)
_bx_log_refusals() {
    local _f="$1" _mode="${2:-users}" _n _tcc _links='symlink_not_followed|not_regular|unsafe_default_locale|outside_search_root'
    [[ -f "$_f" ]] || return 0
    _tcc='^tcc_denied$'
    [[ "$_mode" == users ]] || _tcc='^$'
    _n=$(awk -F'\t' -v t="$_tcc" '$1 == "refused" && $2 ~ t && !seen[$3]++ { n++ } END { print n + 0 }' "$_f" 2>/dev/null) || _n=0
    if (( _n > 0 )); then
        _BX_TCC_DENIED=$(( ${_BX_TCC_DENIED:-0} + _n ))
        echo "WARN: browser_extensions: macOS privacy protection denied access to $_n browser data folder(s) (Full Disk Access is not granted to the Patched collector); first: $(awk -F'\t' -v t="$_tcc" '$1 == "refused" && $2 ~ t && !seen[$3]++ { print $3 }' "$_f" | head -5 | tr '\n' ';')" >&2
    fi
    _n=$(awk -F'\t' -v l="^($_links)\$" '$1 == "refused" && $2 ~ l { n++ } END { print n + 0 }' "$_f" 2>/dev/null) || _n=0
    if (( _n > 0 )); then
        echo "WARN: browser_extensions: refused $_n path(s) that were not plain files or directories (symlink or unsafe name); first: $(awk -F'\t' -v l="^($_links)\$" '$1 == "refused" && $2 ~ l' "$_f" | head -5 | cut -f2- | tr '\t\n' ' ;')" >&2
    fi
    _n=$(awk -F'\t' -v l="^($_links)\$" -v t="$_tcc" '$1 == "refused" && $2 !~ l && $2 !~ t { n++ } END { print n + 0 }' "$_f" 2>/dev/null) || _n=0
    if (( _n > 0 )); then
        echo "WARN: browser_extensions: refused $_n path(s) that could not be read or parsed (unreadable, a hard link, over the size cap, or malformed); first: $(awk -F'\t' -v l="^($_links)\$" -v t="$_tcc" '$1 == "refused" && $2 !~ l && $2 !~ t' "$_f" | head -5 | cut -f2- | tr '\t\n' ' ;')" >&2
    fi
    rm -f "$_f"
}

# _bx_record_tcc_health <status-block-file> — the agent_health entry for a
# Full Disk Access denial (PAT-2096): kind tcc_denied, subject
# browser_extensions, reason full_disk_access_missing. A collect log line
# that nothing reads is not evidence, so the denial is also recorded in the
# shared agent_health store (agent_health.sh), which patched-upload.sh sends
# as agent_health.degraded. A no-op when agent_health.sh is not loaded.
#
# Only the LaunchDaemon run touches the entry: launchd is the collector's
# parent (PPID 1). A run a signed-in user starts from the menu bar (sudo via
# patched-collect-trigger.sh) or any other parent has a different TCC
# attribution, so its result says nothing about the daemon's access and
# would flap the entry; it still logs the WARN. _BX_HEALTH_PPID overrides
# $PPID for tests only.
#
# Recorded when the users walk saw any tcc_denied path (folder or file).
# Cleared only when the users walk ran to the end having reached every
# folder it would read: a composed block, not failed, no cap_reached (a pair
# cut by the row budget was never read), and no user or browser failed (a
# home that could not be entered was never read). Anything else is no
# opinion and leaves the entry as it was.
_bx_record_tcc_health() {
    local _bx_reached
    typeset -f patched_agent_health_record_failure >/dev/null 2>&1 || return 0
    if [[ "${_BX_HEALTH_PPID:-$PPID}" != 1 ]]; then
        echo "browser_extensions: not the LaunchDaemon run (parent ${_BX_HEALTH_PPID:-$PPID}); the tcc_denied agent_health entry is left as it was" >&2
        return 0
    fi
    if (( ${_BX_TCC_DENIED:-0} > 0 )); then
        patched_agent_health_record_failure tcc_denied browser_extensions full_disk_access_missing >&2
        return 0
    fi
    _bx_reached=$("$PYTHON3" -c '
import json, sys
b = json.load(open(sys.argv[1]))
users = b.get("users")
ok = (b.get("collection_status") in ("complete", "partial", "not_present")
      and b.get("cap_reached") is False and isinstance(users, list)
      and all(isinstance(u, dict) and u.get("collection_status") != "failed"
              and isinstance(u.get("browsers"), dict)
              and "failed" not in u["browsers"].values() for u in users))
print("yes" if ok else "no")' "$1" 2>/dev/null) || _bx_reached=no
    if [[ "$_bx_reached" == yes ]]; then
        patched_agent_health_record_success tcc_denied browser_extensions >&2
    fi
    return 0
}

collect_browser_extensions() {
    BROWSER_EXTENSIONS_JSON_FILE="$QUEUE_DIR/.browser-extensions-$TS_FILE.tmp"
    echo "[" > "$BROWSER_EXTENSIONS_JSON_FILE"

    FIRST_EXT=true
    EXT_COUNT=0
    MAX_EXTENSIONS=$_BX_MAX_EXTENSIONS

    # Chrome, Edge and Firefox for every user, in the order the per-user
    # shell loops used before PAT-2054: users by name, then per user Chrome
    # profiles (Default, then "Profile N" by name), Edge profiles, Firefox
    # profiles by name.
    # PAT-2065: the status block. It starts as failed and is only replaced by
    # a block the parser composed from a users walk that ran to the end.
    BROWSER_EXTENSIONS_STATUS_FILE="$QUEUE_DIR/.browser-extensions-status-$TS_FILE.tmp"
    printf '{"collection_status":"failed"}' > "$BROWSER_EXTENSIONS_STATUS_FILE"
    _BX_CAPPED=0
    _BX_SAFARI_OK=0
    # PAT-2096: paths macOS privacy protection denied this run.
    _BX_TCC_DENIED=0
    # PAT-2067: unavailable until the Safari walk has said otherwise.
    SAFARI_EXTENSIONS_COLLECTION_STATUS="unavailable"
    local _bx_users="$QUEUE_DIR/.browser-extensions-users-$TS_FILE.tmp"
    local _bx_block="$QUEUE_DIR/.browser-extensions-block-$TS_FILE.tmp"
    rm -f "$_bx_users" "$_bx_block"

    local _bx_err="$QUEUE_DIR/.browser-extensions-err-$TS_FILE.tmp"
    : > "$_bx_err"
    while IFS= read -r EXT_LINE; do
        [[ -z "$EXT_LINE" ]] && continue
        # The parser keeps within its budget, so this only trips if it did not.
        if [[ $EXT_COUNT -ge $MAX_EXTENSIONS ]]; then _BX_CAPPED=1; break; fi
        _bx_append "$EXT_LINE"
    done < <(_bx_python users "$_BX_USERS_ROOT" "$MAX_EXTENSIONS" 5>"$_bx_users" 2>>"$_bx_err") || true
    _bx_log_refusals "$_bx_err"

    # --- Safari App Extensions (system-wide, not per-user; see header) -------
    if [[ $EXT_COUNT -lt $MAX_EXTENSIONS ]]; then
        collect_safari_app_extensions "${_BX_SAFARI_ROOTS[@]}"
    else
        # Safari was never walked: whatever it holds is past the cap.
        _BX_CAPPED=1
        _BX_SAFARI_OK=0
        SAFARI_EXTENSIONS_COLLECTION_STATUS="partial"
    fi

    echo "]" >> "$BROWSER_EXTENSIONS_JSON_FILE"

    # PAT-2067: the Safari walk no longer feeds the block (see header).
    if [[ -f "$_bx_users" ]] && _bx_python status "$_BX_CAPPED" 5<"$_bx_users" > "$_bx_block" 2>/dev/null \
        && [[ -s "$_bx_block" ]]; then
        mv -f "$_bx_block" "$BROWSER_EXTENSIONS_STATUS_FILE"
    else
        echo "WARN: browser_extensions: could not compose the status block; sending collection_status failed" >&2
    fi
    rm -f "$_bx_users" "$_bx_block"

    # A cap anywhere in the array, including a user's fair share that only the
    # users walk saw, is cap_reached, and the platform ignores a Safari
    # complete beside it. Only a block that says cap_reached false in so many
    # words (or a failed block, which carries none) leaves complete standing.
    local _bx_block_capped
    _bx_block_capped=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("cap_reached", False) is not False)' "$BROWSER_EXTENSIONS_STATUS_FILE" 2>/dev/null) || _bx_block_capped=unknown
    if [[ "$SAFARI_EXTENSIONS_COLLECTION_STATUS" == complete ]]; then
        if (( _BX_CAPPED != 0 || _BX_SAFARI_OK != 1 )) || [[ "$_bx_block_capped" != False ]]; then
            SAFARI_EXTENSIONS_COLLECTION_STATUS="partial"
        fi
    fi
    _bx_record_tcc_health "$BROWSER_EXTENSIONS_STATUS_FILE"
    echo "browser_extensions: rows=$EXT_COUNT status=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("collection_status"))' "$BROWSER_EXTENSIONS_STATUS_FILE" 2>/dev/null) cap_reached=$_BX_CAPPED safari_extensions=$SAFARI_EXTENSIONS_COLLECTION_STATUS" >&2
}

# browser_extensions_status_payload: the block for the payload heredoc. A
# missing or empty status file (collect_browser_extensions never ran) is
# failed, never absent and never a claim.
browser_extensions_status_payload() {
    if [[ -n "${BROWSER_EXTENSIONS_STATUS_FILE:-}" && -s "$BROWSER_EXTENSIONS_STATUS_FILE" ]]; then
        cat "$BROWSER_EXTENSIONS_STATUS_FILE"
    else
        printf '{"collection_status":"failed"}'
    fi
}

# collect_safari_app_extensions [search-root ...] — appends Safari App Extension
# entries to BROWSER_EXTENSIONS_JSON_FILE. Shares FIRST_EXT/EXT_COUNT/MAX_EXTENSIONS
# state with collect_browser_extensions(), which must have already initialised
# them. Search roots default to the real app locations; callers may override
# them (test-safari-extensions.zsh does, to point at a fixture tree).
#
# find(1) only lists candidate paths. It follows no symlink, including a
# symlinked search root, and writes them NUL-separated, because a directory
# name may contain a newline and a newline-split list would let a user inject
# a path to any bundle on the Mac (PAT-2054 review). The parser also refuses a
# listed path that is not under the search root it came from, or that has a
# "." or ".." component. Every read of a listed bundle then goes through the
# walk helpers, so a bundle under a user's ~/Applications that is, or
# becomes, a symlink is refused.
collect_safari_app_extensions() {
    local -a SAFARI_SEARCH_ROOTS
    # PAT-2067: with the default roots, "$_BX_USERS_ROOT"/*/Applications is a
    # glob, and under NULL_GLOB a home root that cannot be listed expands to
    # nothing at all, silently dropping every user's ~/Applications. So the
    # home root must be a listable directory for the walk to be complete.
    local _bx_homes_ok=1 _bx_root
    if [[ $# -gt 0 ]]; then
        SAFARI_SEARCH_ROOTS=("$@")
    else
        if [[ ! -d "$_BX_USERS_ROOT" || ! -r "$_BX_USERS_ROOT" || ! -x "$_BX_USERS_ROOT" ]]; then
            _bx_homes_ok=0
            echo "WARN: browser_extensions: Safari: cannot list $_BX_USERS_ROOT; no ~/Applications was searched" >&2
        fi
        SAFARI_SEARCH_ROOTS=("${_BX_SAFARI_APP_ROOTS[@]}" "$_BX_USERS_ROOT"/*/Applications)
    fi
    # find follows no symlink (and must not, as root), so a search root that
    # is a symlink, a ~/Applications link included, is listed as nothing and
    # exits 0. What it holds was not searched: the walk is not complete.
    # A root that is a link is searched only when it resolves into the
    # /System allowlist (see _bx_safari_link_harmless).
    for _bx_root in "${SAFARI_SEARCH_ROOTS[@]}"; do
        if [[ -L "$_bx_root" ]] && ! _bx_safari_link_harmless root "$_bx_root"; then
            _bx_homes_ok=0
            echo "WARN: browser_extensions: Safari: refused symlinked search root ${_bx_root//[[:cntrl:]]/?} -> ${_BX_LINK_REAL//[[:cntrl:]]/?}; it was not searched" >&2
        fi
    done

    # PAT-2065/PAT-2067: _BX_SAFARI_OK is 1 only when find listed every root
    # without an error, the refusal log was read and held no refusal, and the
    # parser ran to the end. It and the row cap set
    # SAFARI_EXTENSIONS_COLLECTION_STATUS (see header); it never feeds the
    # browser_extensions_status block, and never the rows.
    _BX_SAFARI_OK=0
    SAFARI_EXTENSIONS_COLLECTION_STATUS="unavailable"
    local _bx_find_rc=0 _bx_find_err="$QUEUE_DIR/.safari-find-err-$TS_FILE.tmp"
    local _bx_walk="$QUEUE_DIR/.safari-walk-$TS_FILE.tmp"
    SAFARI_APPEX_LIST="$QUEUE_DIR/.safari-appex-$TS_FILE.tmp"
    # One pass (PAT-2079) with no depth limit: every symlink and every appex
    # on a Contents/PlugIns path, however deep, so no extension lies silently
    # beyond the walk. -ipath, not -path: APFS is case-insensitive, so an
    # appex under Contents/plugins loads as one under Contents/PlugIns.
    # find's errors go to a file, not /dev/null, so an unreadable root or
    # subtree is named in the collect log; its exit status decides.
    find \
        "${SAFARI_SEARCH_ROOTS[@]}" \
        \( -type l -print0 \) \
        -o \( -iname "*.appex" -ipath "*/Contents/PlugIns/*" -print0 \) \
        2>"$_bx_find_err" > "$_bx_walk" || _bx_find_rc=$?
    if (( _bx_find_rc != 0 )); then
        echo "WARN: browser_extensions: Safari: find exited $_bx_find_rc; some search roots were not listed in full; first: $(head -3 "$_bx_find_err" 2>/dev/null | tr '\n' ';')" >&2
    fi
    # Each record is a link (judged here) or an appex (passed on to the
    # parser as the appex list), told apart by a fresh lstat. A symlinked
    # .app, .appex, PlugIns, bundle Contents or folder hides every appex
    # behind it, and find still exits 0, so any link that could hide an
    # extension makes the walk partial (_bx_safari_link_harmless has the
    # rules). Framework links inside a bundle that stay inside it, such as
    # Versions/Current, are harmless and are in every app. The judging is
    # bounded by _BX_SAFARI_MAX_LINKS: past it the rest go unjudged, so any
    # of them could hide an extension and the walk is partial. Appexes past
    # the cap are still listed.
    local _bx_rec _bx_bad_links=0 _bx_first_links="" _bx_nlinks=0 _bx_split_ok=0 _bx_write_err=0
    {
        while IFS= read -r -d '' _bx_rec || [[ -n "$_bx_rec" ]]; do
            if [[ -L "$_bx_rec" ]]; then
                _bx_nlinks=$((_bx_nlinks + 1))
                (( _bx_nlinks > _BX_SAFARI_MAX_LINKS )) && continue
                _bx_safari_link_harmless link "$_bx_rec" "${SAFARI_SEARCH_ROOTS[@]}" && continue
                _bx_bad_links=$((_bx_bad_links + 1))
                (( _bx_bad_links <= 3 )) && _bx_first_links+="${_bx_rec//[[:cntrl:]]/?} -> ${_BX_LINK_REAL//[[:cntrl:]]/?};"
            else
                print -rn -u5 -- "$_bx_rec"$'\0' || _bx_write_err=1
            fi
        done
        _bx_split_ok=1
    } < "$_bx_walk" 5> "$SAFARI_APPEX_LIST"
    if (( _bx_split_ok != 1 || _bx_write_err != 0 )); then
        _bx_homes_ok=0
        echo "WARN: browser_extensions: Safari: could not split the walk into links and appexes; the walk is not complete" >&2
    fi
    if (( _bx_nlinks > _BX_SAFARI_MAX_LINKS )); then
        _bx_homes_ok=0
        echo "WARN: browser_extensions: Safari: $_bx_nlinks symlinks in the walk, more than $_BX_SAFARI_MAX_LINKS; stopped checking them, the walk is not complete" >&2
    fi
    if (( _bx_bad_links > 0 )); then
        _bx_homes_ok=0
        echo "WARN: browser_extensions: Safari: refused $_bx_bad_links symlinked path(s) that could hide a bundle (symlink_not_followed), not searched; first: $_bx_first_links" >&2
    fi
    if (( _bx_homes_ok == 0 && _bx_find_rc == 0 )); then _bx_find_rc=1; fi
    rm -f "$_bx_walk"
    rm -f "$_bx_find_err"

    if [[ ! -s "$SAFARI_APPEX_LIST" ]]; then
        rm -f "$SAFARI_APPEX_LIST"
        if (( _bx_find_rc == 0 )); then
            # Every root listed with no error, and no bundle in any of them.
            _BX_SAFARI_OK=1
            SAFARI_EXTENSIONS_COLLECTION_STATUS="complete"
        else
            SAFARI_EXTENSIONS_COLLECTION_STATUS="partial"
        fi
        return
    fi

    # Best-effort enabled/disabled election state via pluginkit, console user only
    # (mirrors METERING_CONSOLE_USER in apps.sh). No console user -> every entry
    # reports enabled:null rather than guessing.
    SAFARI_CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null || echo "")
    case "$SAFARI_CONSOLE_USER" in root|loginwindow|"") SAFARI_CONSOLE_USER="" ;; esac
    SAFARI_PLUGINKIT_RAW="$QUEUE_DIR/.safari-pluginkit-$TS_FILE.tmp"
    : > "$SAFARI_PLUGINKIT_RAW"
    if [[ -n "$SAFARI_CONSOLE_USER" ]]; then
        SAFARI_CONSOLE_UID=$(id -u "$SAFARI_CONSOLE_USER" 2>/dev/null || echo "")
        if [[ -n "$SAFARI_CONSOLE_UID" ]]; then
            for SAFARI_EXT_POINT in com.apple.Safari.web-extension com.apple.Safari.extension; do
                launchctl asuser "$SAFARI_CONSOLE_UID" sudo -u "$SAFARI_CONSOLE_USER" \
                    /usr/bin/pluginkit -m -v -p "$SAFARI_EXT_POINT" >> "$SAFARI_PLUGINKIT_RAW" 2>/dev/null || true
            done
        fi
    fi

    # The two lists are root's own files; they reach the parser as open
    # descriptors 3 and 4, so it never opens a path it was not walked to.
    local _bx_err="$QUEUE_DIR/.safari-appex-err-$TS_FILE.tmp"
    local _bx_safari_done=0 _bx_safari_rows=0 _bx_refused_rc
    : > "$_bx_err"
    while IFS= read -r EXT_LINE; do
        [[ -z "$EXT_LINE" ]] && continue
        # "#done" follows the last row only when the parser exited cleanly.
        # Rows are JSON objects, so no row can be this line.
        if [[ "$EXT_LINE" == "#done" ]]; then _bx_safari_done=1; continue; fi
        if [[ $EXT_COUNT -ge $MAX_EXTENSIONS ]]; then _BX_CAPPED=1; break; fi
        _bx_append "$EXT_LINE"
        _bx_safari_rows=$((_bx_safari_rows + 1))
    done < <(_bx_python safari "${SAFARI_SEARCH_ROOTS[@]}" 3<"$SAFARI_APPEX_LIST" 4<"$SAFARI_PLUGINKIT_RAW" 2>>"$_bx_err" && print -r -- "#done") || true
    # grep exits 1 for "no refusal". 0 is a refusal, and 2 (the log could not
    # be read) proves nothing, so neither can leave the walk complete.
    _bx_refused_rc=0
    grep -q $'^refused\t' "$_bx_err" 2>/dev/null || _bx_refused_rc=$?
    if (( _bx_find_rc == 0 && _bx_safari_done == 1 && _bx_refused_rc == 1 )); then
        _BX_SAFARI_OK=1
        SAFARI_EXTENSIONS_COLLECTION_STATUS="complete"
    elif (( _bx_safari_done == 0 && _bx_safari_rows == 0 && _BX_CAPPED == 0 )); then
        # The parser died (or could not read the appex list) before it sent
        # a single Safari row: the walk failed outright.
        SAFARI_EXTENSIONS_COLLECTION_STATUS="unavailable"
    else
        SAFARI_EXTENSIONS_COLLECTION_STATUS="partial"
    fi
    if (( _bx_refused_rc > 1 )); then
        echo "WARN: browser_extensions: Safari: could not read the refusal log; the walk is not complete" >&2
    fi
    _bx_log_refusals "$_bx_err" safari

    rm -f "$SAFARI_APPEX_LIST" "$SAFARI_PLUGINKIT_RAW"
}

# _bx_python users <users-root> <budget>
#                                 Chrome, Edge and Firefox rows, one per line,
#                                 at most <budget> of them shared fairly across
#                                 users; the per-user, per-browser statuses are
#                                 written as JSON to fd 5 at the end.
# _bx_python safari <root ...>    Safari rows; the NUL-separated appex list
#                                 find wrote for those roots on fd 3, pluginkit
#                                 output on fd 4.
# _bx_python status <capped 0|1>
#                                 prints the browser_extensions_status block
#                                 from the users statuses on fd 5.
# Refusals go to stderr as "refused<TAB>code<TAB>path" lines.
_bx_python() {
    "$PYTHON3" - "$@" <<'PYEOF'
import errno
import json
import os
import plistlib
import re
import stat
import sys

PREFS_CAP = 64 * 1024 * 1024        # Secure Preferences / Preferences / extensions.json
MANIFEST_CAP = 16 * 1024 * 1024     # manifest.json, messages.json, Info.plist
LIST_CAP = 64 * 1024 * 1024         # the appex list and pluginkit output (root's own)
MAX_RESOURCE_DEPTH = 32
SKIP_HOMES = {"Shared", "Guest"}
CHROMIUM_BROWSERS = (("Google/Chrome", "chrome"), ("Microsoft Edge", "edge"))
# A Chrome locale directory name (en, en_GB, zh_CN, pt-BR): one plain path
# component, never "/", "." or "..", never empty, at most 32 characters.
LOCALE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class Abort(Exception):
    """A directory could not be listed; the caller skips it."""


class Capped(BaseException):
    """The current user's share of the row cap is used up (PAT-2065). A
    BaseException, so the per-profile "except Exception" guards cannot
    swallow it and read on past the cap."""


# PAT-2065: the (user, browser) being read. Every refusal while it is set, and
# every file that could not be parsed, makes that pair partial.
SCOPE = {"partial": False, "active": False}
# The current user's row allowance; emit() raises Capped past it.
BUDGET = {"quota": None, "used": 0}


def mark_partial():
    if SCOPE["active"]:
        SCOPE["partial"] = True


def log_path(p):
    return p if isinstance(p, str) and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in p) else "<unprintable>"


def refused(code, where):
    mark_partial()
    sys.stderr.write("refused\t" + code + "\t" + log_path(where) + "\n")


def denied_code(err_no):
    """The refusal code for a path that could not be read: tcc_denied when the
    errno is EPERM, else unreadable (PAT-2096). As root, EPERM on an open or
    lstat here is macOS privacy protection (TCC): without Full Disk Access,
    root may lstat another app's data folder but not open it. Either way the
    subtree sends no rows and its (user, browser) is partial."""
    return "tcc_denied" if err_no == errno.EPERM else "unreadable"


def abort_errno(abort):
    """The errno of the OSError list_dir raised Abort from, or None."""
    return getattr(abort.__cause__, "errno", None)


def note(k, where, err_no=None):
    """Record a path whose lstat kind is a symlink or unreadable. err_no is
    lstat_kind's errno for an error kind."""
    if k in ("symlink", "error", "other"):
        refused({"symlink": "symlink_not_followed", "other": "not_regular"}.get(k) or denied_code(err_no), where)


# --- file-safety helpers copied verbatim from ide_extensions.sh ------------
# test-package-managers.zsh [drift] fails if any of these stops matching its
# twin there, so a hardening fix to one cannot silently skip the other.

# Every read goes through open_parent: each directory on the way down is
# opened relative to the one above it with O_NOFOLLOW, so there is never a path
# for a user to swap for a symlink between a check and a use (PAT-2033). The
# lstat checks callers make first decide what to report; they are not what
# keeps a read inside the tree.
DIR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_LINK_HOPS = 32
# The links under / that the walk follows, each with the text macOS gives it.
SYSTEM_LINKS = {"tmp": "private/tmp", "var": "private/var", "etc": "private/etc"}


class LinkRefused(OSError):
    """A directory on the way down is a symlink the walk does not follow."""


def open_parent(path):
    """(fd, name): an open descriptor for the directory holding the last
    component of the absolute path, and that component's name. The caller
    closes fd. The only symlinks followed on the way down are the system's
    own /tmp, /var and /etc, right under /, root's, and pointing where macOS
    points them (SYSTEM_LINKS); any other raises LinkRefused. Ownership and
    mode bits cannot say who may replace a link, because a macOS ACL can
    grant that without them, so the rule is an allowlist (PAT-2040). A
    missing directory or a file where a directory should be raises
    FileNotFoundError or NotADirectoryError, anything else OSError."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise OSError("not an absolute path")
    head, _, name = path.rpartition("/")
    if name in ("", ".", ".."):
        raise OSError("no final component")
    todo = [p for p in reversed(head.split("/")) if p not in ("", ".")]
    stack = [os.open("/", DIR_FLAGS)]
    hops = 0
    try:
        while todo:
            part = todo.pop()
            if part == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                continue
            try:
                stack.append(os.open(part, DIR_FLAGS, dir_fd=stack[-1]))
                continue
            except OSError as err:
                failure = err
            # macOS reports an O_NOFOLLOW|O_DIRECTORY open of a symlink as
            # ENOTDIR, the same as a regular file, so lstat tells them apart:
            # a symlink must never read as "absent".
            try:
                link = os.lstat(part, dir_fd=stack[-1])
            except OSError:
                raise failure
            if not stat.S_ISLNK(link.st_mode):
                raise failure
            if (hops >= MAX_LINK_HOPS or len(stack) != 1 or part not in SYSTEM_LINKS
                    or link.st_uid != 0):
                raise LinkRefused("symlink not followed")
            target = os.readlink(part, dir_fd=stack[-1])
            if target != SYSTEM_LINKS[part]:
                raise LinkRefused("symlink not followed")
            hops += 1
            if target.startswith("/"):
                while len(stack) > 1:
                    os.close(stack.pop())
            todo.extend(p for p in reversed(target.split("/")) if p not in ("", "."))
        return stack.pop(), name
    finally:
        for fd in stack:
            os.close(fd)


def lstat_at(path):
    """os.stat_result of the last component itself, never following it.
    Raises as open_parent does."""
    fd, name = open_parent(path)
    try:
        return os.lstat(name, dir_fd=fd)
    finally:
        os.close(fd)


def read_link(path):
    """The text of the symlink at path, never followed. Raises OSError."""
    fd, name = open_parent(path)
    try:
        return os.readlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def open_dir(path):
    """A descriptor for the directory at path; a symlink there, or on the way
    down, is refused. Raises OSError. The caller closes it."""
    fd, name = open_parent(path)
    try:
        return os.open(name, DIR_FLAGS, dir_fd=fd)
    finally:
        os.close(fd)


def open_regular_errno(path, cap):
    """(status, fd, errno): status is open, missing or unreadable. Never
    follows a symlink, never blocks on a FIFO, refuses anything but a regular
    file with one link and at most cap bytes. The caller closes fd. errno is
    the failing call's errno for an unreadable file that could not be opened
    or statted (EPERM: macOS privacy protection, PAT-2096), else None; a file
    refused for its type, links or size carries None."""
    # O_NONBLOCK is deliberate: opening a FIFO for read blocks until a writer
    # appears, so without it a planted FIFO would hang the collector before the
    # fstat S_ISREG check below could refuse it.
    try:
        dir_fd, name = open_parent(path)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None, None
    except OSError as err:
        return "unreadable", None, err.errno
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return "missing", None, None
    except OSError as err:
        return "unreadable", None, err.errno
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
    except OSError as err:
        os.close(fd)
        return "unreadable", None, err.errno
    # A hard link to a file the user cannot read is still a regular file that
    # O_NOFOLLOW opens, so more than one link is refused like a symlink.
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > cap:
        os.close(fd)
        return "unreadable", None, None
    return "open", fd, None


def open_regular(path, cap):
    """(status, fd): open_regular_errno without the errno."""
    return open_regular_errno(path, cap)[:2]


def read_file_errno(path, cap):
    """(status, bytes, errno): status is read, missing or unreadable; errno
    as open_regular_errno gives it, or a failed read's."""
    status, fd, err_no = open_regular_errno(path, cap)
    if status != "open":
        return status, None, err_no
    try:
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                return "unreadable", None, None
            chunks.append(chunk)
        return "read", b"".join(chunks), None
    except OSError as err:
        return "unreadable", None, err.errno
    finally:
        os.close(fd)


def read_file(path, cap):
    """(status, bytes): read_file_errno without the errno."""
    return read_file_errno(path, cap)[:2]


def lstat_kind(path):
    """(kind, errno). kind is absent, dir, symlink, file, other or error, from
    lstat (never follows); a symlink the walk refuses on the way down is
    error, never absent. errno is the failing call's errno when kind is error
    (None for a refused link), else None. The errno only names the failure:
    EPERM here is macOS privacy protection (TCC) denying root a directory it
    may lstat but not open, which callers can report as such (PAT-2096)."""
    try:
        st = lstat_at(path)
    except FileNotFoundError:
        return "absent", None
    except NotADirectoryError:
        return "absent", None
    except OSError as err:
        return "error", err.errno
    if stat.S_ISLNK(st.st_mode):
        return "symlink", None
    if stat.S_ISDIR(st.st_mode):
        return "dir", None
    if stat.S_ISREG(st.st_mode):
        return "file", None
    return "other", None


def kind(path):
    """absent, dir, symlink, file, other or error: lstat_kind without the
    errno."""
    return lstat_kind(path)[0]


def list_dir(path, hidden=False):
    """Sorted (name, kind) never following a symlink; an entry whose type
    cannot be read is "error", never dropped. Raises Abort when the directory
    itself cannot be listed, with the OSError as its __cause__ so a caller can
    read the errno (PAT-2096); Abort's own args stay empty."""
    try:
        fd = open_dir(path)
    except OSError as err:
        raise Abort() from err
    try:
        with os.scandir(fd) as it:
            rows = []
            for entry in it:
                if not hidden and entry.name.startswith("."):
                    continue
                try:
                    if entry.is_symlink():
                        k = "symlink"
                    elif entry.is_dir(follow_symlinks=False):
                        k = "dir"
                    elif entry.is_file(follow_symlinks=False):
                        k = "file"
                    else:
                        k = "other"
                except OSError:
                    k = "error"
                rows.append((entry.name, k))
            return sorted(rows)
    except OSError as err:
        raise Abort() from err
    finally:
        os.close(fd)

# --- end of the verbatim copy -------------------------------------------------


def no_constant(name):
    """json parse_constant hook: NaN, Infinity and -Infinity are not JSON,
    and json.dumps would write them back bare, which the server rejects along
    with the whole inventory. A file carrying one is unparseable."""
    raise ValueError("non-finite number " + name)


def parse_json(data):
    return json.loads(data.decode("utf-8", errors="replace"), parse_constant=no_constant)


def read_json(path, cap):
    """The parsed JSON at path, or None. Decoded as the pre-PAT-2054 text-mode
    open did (UTF-8, errors replaced, no BOM stripping). A path the walk
    refuses is logged."""
    status, data, err_no = read_file_errno(path, cap)
    if status == "unreadable":
        refused(denied_code(err_no), path)
    if status != "read":
        return None
    try:
        return parse_json(data)
    except (ValueError, RecursionError):
        # Callers whose rows depend on the file mark the pair partial; a
        # messages.json that will not parse only costs the display name.
        return None


def emit(entry):
    """Print one row, or drop and log it if it cannot be written as strict
    JSON (a non-finite float from a plist, say)."""
    try:
        line = json.dumps(entry, separators=(',', ':'), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        refused("unserialisable_row", str(entry.get('browser')) + ' ' + str(entry.get('extension_id')))
        return
    if BUDGET["quota"] is not None:
        if BUDGET["used"] >= BUDGET["quota"]:
            raise Capped()
        BUDGET["used"] += 1
    print(line)


def text(value, default=''):
    """value when it is a str, else default: a malformed field is dropped."""
    return value if isinstance(value, str) else default


def str_list(value):
    """The str items of a list; anything else is an empty list."""
    return [p for p in value if isinstance(p, str)] if isinstance(value, list) else []


def unique(items):
    """items with repeats removed, first-seen order kept."""
    seen = set()
    return [p for p in items if not (p in seen or seen.add(p))]


def plain_locale(value):
    return isinstance(value, str) and LOCALE_RE.match(value) is not None


# --- Chrome and Edge ---------------------------------------------------------

def chromium_profile(profile_dir, browser, user_account):
    # Read Secure Preferences (preferred) or Preferences (fallback) for
    # enabled/disabled state of each extension in this profile.
    settings = {}
    for prefs_name in ('Secure Preferences', 'Preferences'):
        prefs_path = profile_dir + '/' + prefs_name
        status, data, err_no = read_file_errno(prefs_path, PREFS_CAP)
        if status == "missing":
            continue
        if status != "read":
            refused(denied_code(err_no), prefs_path)
            continue
        try:
            d = parse_json(data)
            settings = d.get('extensions', {}).get('settings', {})
            break
        except Exception:
            pass

    extensions_dir = profile_dir + '/Extensions'
    profile_name = profile_dir.rsplit('/', 1)[-1]

    try:
        ext_entries = list_dir(extensions_dir, hidden=True)
    except Abort as abort:
        refused(denied_code(abort_errno(abort)), extensions_dir)
        return

    for ext_id, ext_kind in ext_entries:
        ext_path = extensions_dir + '/' + ext_id
        if ext_kind != "dir":
            note(ext_kind, ext_path)
            continue

        # Find the latest version directory (lexicographic sort, take last).
        manifest_path = ''
        version = ''
        try:
            versions = list_dir(ext_path, hidden=True)
        except Abort as abort:
            refused(denied_code(abort_errno(abort)), ext_path)
            continue
        for ver, ver_kind in versions:
            if ver_kind != "dir":
                note(ver_kind, ext_path + '/' + ver)
                continue
            m = ext_path + '/' + ver + '/manifest.json'
            mk, mk_errno = lstat_kind(m)
            if mk == "file":
                manifest_path = m
                version = ver
            else:
                note(mk, m, mk_errno)
        if not manifest_path:
            continue

        mf = read_json(manifest_path, MANIFEST_CAP)
        if mf is None:
            mark_partial()
            continue

        # Resolve __MSG_ i18n name via the extension's default locale. The
        # locale comes from a user-written file, so it must be one plain path
        # component before it is joined into a path (PAT-2054).
        name = text(mf.get('name', '')) or ext_id
        if name.startswith('__MSG_') and mf.get('default_locale'):
            locale = mf['default_locale']
            if plain_locale(locale):
                key = name[6:].rstrip('_').lower()
                msgs_path = (manifest_path.rsplit('/', 1)[0] + '/_locales/' + locale
                             + '/messages.json')
                msgs = read_json(msgs_path, MANIFEST_CAP)
                try:
                    for k, v in msgs.items():
                        if k.lower() == key:
                            name = text(v.get('message', name), name)
                            break
                except Exception:
                    pass
            else:
                refused("unsafe_default_locale", manifest_path)
        if not name or name.startswith('__MSG_'):
            name = ext_id

        # Enabled state: Secure Preferences extensions.settings.<id>.state
        # state 1 = enabled, state 0 = disabled; absent = assume enabled.
        ext_s = settings.get(ext_id, {})
        enabled = (ext_s.get('state', 1) == 1)

        # Split permissions vs host_permissions by manifest version.
        # MV2 bundles host patterns inside the permissions array; MV3 separates them.
        mv = mf.get('manifest_version', 2)
        raw_perms = str_list(mf.get('permissions'))
        host_perms = str_list(mf.get('host_permissions'))
        if mv == 2:
            api_perms, extra_hosts = [], []
            for p in raw_perms:
                if p.startswith('http') or p.startswith('*') or p == '<all_urls>':
                    extra_hosts.append(p)
                else:
                    api_perms.append(p)
            raw_perms = api_perms
            host_perms = extra_hosts + host_perms

        update_url = text(mf.get('update_url'))
        from_ws = ('clients2.google.com' in update_url or
                   'update.googleapis.com' in update_url)

        entry = {
            'browser':          browser,
            'profile':          profile_name,
            'user_account':     user_account,
            'extension_id':     ext_id,
            'name':             name,
            'version':          version,
            'enabled':          enabled,
            'permissions':      raw_perms,
            'host_permissions': host_perms,
            'from_webstore':    from_ws,
        }
        if update_url:
            entry['update_url'] = update_url
        emit(entry)


def chromium_profiles(base):
    """Profile directories under a Chromium browser's base: Default, then
    every "Profile N" by name. A symlink in either place is refused."""
    out = []
    k, k_errno = lstat_kind(base + '/Default')
    # PAT-2096: without Full Disk Access, the EPERM on Default comes from
    # opening base on the way down, and listing base fails the same way.
    # That is one denied folder, so it is reported once, as base, unless
    # base turns out to be listable after all.
    default_denied = k == "error" and k_errno == errno.EPERM
    if k == "dir":
        out.append(base + '/Default')
    elif not default_denied:
        note(k, base + '/Default', k_errno)
    try:
        entries = list_dir(base)
    except Abort as abort:
        refused(denied_code(abort_errno(abort)), base)
        return out
    if default_denied:
        note(k, base + '/Default', k_errno)
    for name, k in entries:
        if not name.startswith('Profile '):
            continue
        if k == "dir":
            out.append(base + '/' + name)
        else:
            note(k, base + '/' + name)
    return out


# --- Firefox -----------------------------------------------------------------

def firefox_profile(profile_dir, user_account):
    data = read_json(profile_dir + '/extensions.json', PREFS_CAP)
    if data is None:
        mark_partial()
        return

    # PAT-2068: the same shapes the Windows reader marks partial. A top level
    # that is not an object, or an "addons" that is present but not a list,
    # lists nothing and is partial; a missing "addons" is an empty list.
    if not isinstance(data, dict):
        mark_partial()
        return
    addons = data.get('addons', [])
    if not isinstance(addons, list):
        mark_partial()
        return

    profile_name = profile_dir.rsplit('/', 1)[-1]

    for addon in addons:
        # An entry that cannot be read is partial, and the rest of the list is
        # still read. A type other than "extension" (theme, dictionary, locale)
        # is out of scope, never partial.
        if not isinstance(addon, dict):
            mark_partial()
            continue
        if addon.get('type') != 'extension':
            continue
        ext_id = addon.get('id')
        if not isinstance(ext_id, str) or not ext_id:
            mark_partial()
            continue

        default_locale = addon.get('defaultLocale')
        name = (text(default_locale.get('name', '')) if isinstance(default_locale, dict) else '') or ext_id
        version = text(addon.get('version', ''))
        # As the Windows reader: a value that is not a JSON boolean is the default.
        active = addon.get('active', True)
        if not isinstance(active, bool):
            active = True
        user_disabled = addon.get('userDisabled', False)
        if not isinstance(user_disabled, bool):
            user_disabled = False
        enabled = active and not user_disabled

        user_perms = addon.get('userPermissions')
        if not isinstance(user_perms, dict):
            user_perms = {}
        permissions = (str_list(addon.get('permissions')) +
                       str_list(user_perms.get('permissions')))
        # PAT-2073: current Firefox writes granted host permissions under
        # userPermissions.origins; "hosts" is the older key, still read for old
        # profiles. The union keeps first-seen order. Optional permissions
        # (optionalPermissions.origins) are not granted and are left out, as
        # the Chromium reader leaves out optional_host_permissions. A wrong
        # type reads as empty and keeps the row, never partial (PAT-2068).
        host_permissions = unique(str_list(user_perms.get('origins')) +
                                  str_list(user_perms.get('hosts')))

        update_url = text(addon.get('updateURL', ''))
        from_ws = 'addons.mozilla.org' in update_url

        entry = {
            'browser':          'firefox',
            'profile':          profile_name,
            'user_account':     user_account,
            'extension_id':     ext_id,
            'name':             name,
            'version':          version,
            'enabled':          enabled,
            'permissions':      permissions,
            'host_permissions': host_permissions,
            'from_webstore':    from_ws,
        }
        if update_url:
            entry['update_url'] = update_url
        emit(entry)


def chromium_browser(support, dir_name, browser, user_account):
    """One user's Chrome or Edge. Returns the pair's status."""
    base = support + '/' + dir_name
    k, k_errno = lstat_kind(base)
    if k == "absent":
        return "not_present"
    if k != "dir":
        # A link, an unreadable path or a file where the user-data directory
        # should be: refused, never "no browser".
        note(k, base, k_errno)
        mark_partial()
        return None
    for profile_dir in chromium_profiles(base):
        k, k_errno = lstat_kind(profile_dir + '/Extensions')
        if k == "absent":
            continue
        if k != "dir":
            note(k, profile_dir + '/Extensions', k_errno)
            mark_partial()
            continue
        # As before PAT-2054, a profile whose files are not the expected
        # shape ends that profile's rows, nothing more; it is partial.
        try:
            chromium_profile(profile_dir, browser, user_account)
        except Exception:
            mark_partial()
    return None


def firefox_browser(support, user_account):
    """One user's Firefox. Profiles on macOS live under
    ~/Library/Application Support/Firefox/Profiles/ (not ~/.mozilla/firefox)."""
    ff_profiles = support + '/Firefox/Profiles'
    k, k_errno = lstat_kind(ff_profiles)
    if k == "absent":
        return "not_present"
    if k != "dir":
        note(k, ff_profiles, k_errno)
        mark_partial()
        return None
    try:
        profiles = list_dir(ff_profiles)
    except Abort as abort:
        refused(denied_code(abort_errno(abort)), ff_profiles)
        return None
    for name, k in profiles:
        profile_dir = ff_profiles + '/' + name
        if k != "dir":
            note(k, profile_dir)
            continue
        k, k_errno = lstat_kind(profile_dir + '/extensions.json')
        if k == "absent":
            continue
        if k != "file":
            note(k, profile_dir + '/extensions.json', k_errno)
            mark_partial()
            continue
        try:
            firefox_profile(profile_dir, user_account)
        except Exception:
            mark_partial()
    return None


BROWSER_ORDER = ("chrome", "edge", "firefox")


def user_status(browsers):
    values = [browsers[b] for b in BROWSER_ORDER]
    if all(v == "not_present" for v in values):
        return "not_present"
    if all(v in ("complete", "not_present") for v in values):
        return "complete"
    return "partial"


def write_status(doc):
    """The users walk's statuses, to root's own file handed over on fd 5."""
    data = json.dumps(doc, separators=(',', ':')).encode("utf-8")
    while data:
        data = data[os.write(5, data):]


def run_users(users_root, budget):
    try:
        homes = list_dir(users_root)
    except Abort as abort:
        refused(denied_code(abort_errno(abort)), users_root)
        write_status({"failed": True})
        return
    candidates = [(u, k) for u, k in homes if u not in SKIP_HOMES and k != "file"]
    users = []
    capped = False
    remaining = budget
    for index, (user_account, home_kind) in enumerate(candidates):
        home = users_root.rstrip('/') + '/' + user_account
        try:
            uid = lstat_at(home).st_uid
        except OSError:
            uid = None
        urow = {"user": user_account, "user_id": str(uid) if uid is not None else None}
        users.append(urow)
        if home_kind != "dir":
            # A home that is a link, or cannot be read, is never entered: the
            # user's read failed, all three browsers with it.
            note(home_kind, home)
            urow["collection_status"] = "failed"
            urow["browsers"] = {b: "failed" for b in BROWSER_ORDER}
            continue
        support = home + '/Library/Application Support'
        # Fair share: what is left, split over this user and those after.
        BUDGET["quota"] = remaining // (len(candidates) - index)
        BUDGET["used"] = 0
        browsers = {}
        cut = False
        for browser in BROWSER_ORDER:
            if cut:
                # Never read: the share ran out on an earlier browser.
                browsers[browser] = "partial"
                continue
            SCOPE["partial"] = False
            SCOPE["active"] = True
            try:
                if browser == "firefox":
                    result = firefox_browser(support, user_account)
                else:
                    dir_name = dict((b, d) for d, b in CHROMIUM_BROWSERS)[browser]
                    result = chromium_browser(support, dir_name, browser, user_account)
                if result is None:
                    result = "partial" if SCOPE["partial"] else "complete"
            except Capped:
                result = "partial"
                cut = True
                capped = True
            except Exception:
                result = "failed"
            finally:
                SCOPE["active"] = False
            browsers[browser] = result
        remaining -= BUDGET["used"]
        urow["collection_status"] = user_status(browsers)
        urow["browsers"] = browsers
    BUDGET["quota"] = None
    write_status({"failed": False, "capped": capped, "users": users})


MAX_STATUS_USERS = 500


def run_status(shell_capped):
    """The browser_extensions_status block from the users walk's statuses
    (root's own file, on fd 5) and whether the shell stopped at the cap.
    Missing or unparseable statuses are a failed block. The Safari walk has
    its own signal, collection_status.safari_extensions (PAT-2067), and does
    not change this block."""
    try:
        doc = json.loads(read_fd_text(5))
        if doc.get("failed") is not False or not isinstance(doc.get("users"), list):
            raise ValueError("users walk failed")
    except Exception:
        print(json.dumps({"collection_status": "failed"}, separators=(',', ':')))
        return
    users = doc["users"]
    capped = bool(doc.get("capped")) or shell_capped
    over = len(users) > MAX_STATUS_USERS
    users = users[:MAX_STATUS_USERS]
    statuses = [u["collection_status"] for u in users]
    if capped or over or any(v not in ("complete", "not_present") for v in statuses):
        status = "partial"
    elif all(v == "not_present" for v in statuses):
        status = "not_present"
    else:
        status = "complete"
    block = {"collection_status": status, "cap_reached": capped, "users": users}
    print(json.dumps(block, separators=(',', ':'), allow_nan=False))


# --- Safari ------------------------------------------------------------------

WEB_EXT_POINT = 'com.apple.Safari.web-extension'
LEGACY_EXT_POINT = 'com.apple.Safari.extension'


def read_fd_text(fd):
    """The text of one of root's own lists handed over on an open fd, or None
    when it could not be read in full (over LIST_CAP, or a read error). None
    is never an empty list: the caller decides what an unread list costs."""
    chunks, total = [], 0
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > LIST_CAP:
                return None
            chunks.append(chunk)
    except OSError:
        return None
    return b"".join(chunks).decode("utf-8", errors="replace")


def read_plist(path):
    status, data, err_no = read_file_errno(path, MANIFEST_CAP)
    if status == "unreadable":
        refused(denied_code(err_no), path)
    if status != "read":
        raise OSError("not read")
    return plistlib.loads(data)


def find_manifest(top, depth=0):
    """(found, path) of the first manifest.json under top, top-down with each
    directory's own files before its subdirectories, as os.walk did. A
    manifest.json that is not a plain file is found and then refused."""
    if depth > MAX_RESOURCE_DEPTH:
        return False, None
    try:
        entries = list_dir(top, hidden=True)
    except Abort as abort:
        # PAT-2100: a folder that is there but cannot be listed loses the
        # bundle's permissions, so it is refused (and the Safari walk is then
        # not complete), never skipped in silence. One that is not there, or
        # is a file, has no manifest to lose.
        k, k_errno = lstat_kind(top)
        if k == "dir":
            refused(denied_code(abort_errno(abort)), top)
        else:
            note(k, top, k_errno)
        return False, None
    if any(name == 'manifest.json' and k != "dir" for name, k in entries):
        return True, top + '/manifest.json'
    for name, k in entries:
        if k == "dir":
            found, path = find_manifest(top + '/' + name, depth + 1)
            if found:
                return found, path
        elif k == "symlink":
            note(k, top + '/' + name)
    return False, None


def within_root(path, roots):
    """True when path is strictly below one of the search roots and has no
    empty, "." or ".." component there."""
    for root in roots:
        if path.startswith(root + '/'):
            rest = path[len(root) + 1:].split('/')
            if rest and all(p not in ('', '.', '..') for p in rest):
                return True
    return False


def safari_bundle(appex_path, election):
    """Emit the row for one listed .appex, if it is a Safari extension."""
    try:
        mf = read_plist(appex_path + '/Contents/Info.plist')
    except Exception:
        # Missing, unreadable or unparseable (mid-update, a truncated binary
        # plist): the row is lost, so the Safari walk is not complete
        # (PAT-2065 review). read_plist has already logged an unreadable file.
        refused("malformed_bundle", appex_path)
        return

    if not isinstance(mf, dict):
        refused("malformed_bundle", appex_path)
        return
    extension = mf.get('NSExtension') or {}
    if not isinstance(extension, dict):
        refused("malformed_bundle", appex_path)
        return
    ext_point = extension.get('NSExtensionPointIdentifier', '')
    if ext_point not in (WEB_EXT_POINT, LEGACY_EXT_POINT):
        return

    ext_id = text(mf.get('CFBundleIdentifier', '')) or appex_path.rsplit('/', 1)[-1]
    name = text(mf.get('CFBundleDisplayName')) or text(mf.get('CFBundleName')) or ext_id
    version = text(mf.get('CFBundleShortVersionString', ''))

    # Host app = nearest ancestor ".app" bundle, walking up from
    # .../Contents/PlugIns/X.appex (host apps may themselves be nested, e.g.
    # /Applications/Vendor/Host.app/Contents/PlugIns/X.appex).
    parts = appex_path.split('/')
    host_app_path = appex_path
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].endswith('.app'):
            host_app_path = '/'.join(parts[:i + 1])
            break

    vendor = ''
    from_store = False
    try:
        host_mf = read_plist(host_app_path + '/Contents/Info.plist')
        vendor = text(host_mf.get('CFBundleName')) or text(host_mf.get('CFBundleDisplayName'))
    except Exception:
        pass
    # Mac App Store installs carry a receipt inside the host bundle; use that as
    # the from_webstore-equivalent "official distribution channel" signal.
    receipt = host_app_path + '/Contents/_MASReceipt'
    receipt_kind, receipt_errno = lstat_kind(receipt)
    from_store = receipt_kind == "dir"
    note(receipt_kind, receipt, receipt_errno)

    permissions = []
    host_permissions = []
    if ext_point == WEB_EXT_POINT:
        # safari-web-extension-converter output bundles a Chrome-style
        # manifest.json somewhere under Contents/Resources.
        manifest = None
        found, manifest_path = find_manifest(appex_path + '/Contents/Resources')
        if found:
            manifest = read_json(manifest_path, MANIFEST_CAP)
        if manifest:
            raw_perms = str_list(manifest.get('permissions'))
            host_permissions = str_list(manifest.get('host_permissions'))
            if not host_permissions:
                # MV2-style: host patterns live inside permissions.
                host_permissions = [p for p in raw_perms
                                     if p.startswith('http') or p.startswith('*') or p == '<all_urls>']
                raw_perms = [p for p in raw_perms if p not in host_permissions]
            permissions = raw_perms
    else:
        # Legacy Safari App Extension: website access is declared directly in
        # Info.plist, not a bundled manifest.
        site_access = extension.get('SFSafariWebsiteAccess') or {}
        if site_access.get('Level') == 'All':
            host_permissions = ['<all_urls>']
        else:
            host_permissions = str_list(site_access.get('Allowed Domains'))

    entry = {
        'browser':          'safari',
        'profile':          None,
        'user_account':     None,
        'extension_id':     ext_id,
        'name':             name,
        'version':          version,
        'enabled':          election.get(ext_id),
        'permissions':      permissions,
        'host_permissions': host_permissions,
        'from_webstore':    from_store,
    }
    if vendor:
        entry['vendor'] = vendor
    emit(entry)


def run_safari(search_roots):
    # --- Parse pluginkit's per-line election-state output into a bundle-id map. --
    # Each line: "<state><ws>bundle-id(version)<tab>uuid<tab>date<tab>path", where
    # state is one of +(use)/-(ignore)/!(debug)/=(superseded)/?(unknown) or blank.
    # Only +/- map to a definite True/False; anything else is left unset (unknown).
    election = {}
    # An unreadable pluginkit list only costs the enabled state (null).
    pluginkit = read_fd_text(4) or ''
    for line in pluginkit.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        if not line.strip():
            continue
        if line[0] in '+-!=?':
            state, rest = line[0], line[1:]
        else:
            state, rest = ' ', line
        field = rest.split('\t', 1)[0].strip()
        bundle_id = field.rsplit('(', 1)[0].strip() if '(' in field else field
        if not bundle_id:
            continue
        if state == '+':
            election[bundle_id] = True
        elif state == '-':
            election[bundle_id] = False

    # find wrote one NUL-terminated record per path, so a newline in a
    # directory name stays inside its own path. Sorted and de-duplicated here
    # (byte order, as sort -u in the C locale launchd gives the collector).
    roots = [r.rstrip('/') for r in search_roots if r.startswith('/')]
    appex_paths = []
    listed = read_fd_text(3)
    if listed is None:
        # The appex list could not be read in full: no bundle was seen, so
        # the Safari walk failed outright (PAT-2065 review, PAT-2067). The
        # non-zero exit keeps "#done" from the caller.
        refused("unreadable", "<appex list>")
        sys.exit(1)
    for record in sorted(set(listed.split('\0'))):
        if not record:
            continue
        if not within_root(record, roots):
            refused("outside_search_root", record)
            continue
        appex_paths.append(record)

    for appex_path in appex_paths:
        # One malformed bundle costs its own row only. The list is sorted, so
        # without this a user could blank every bundle that sorts after theirs.
        try:
            safari_bundle(appex_path, election)
        except Exception:
            refused("malformed_bundle", appex_path)


if sys.argv[1] == 'users':
    run_users(sys.argv[2], int(sys.argv[3]))
elif sys.argv[1] == 'status':
    run_status(sys.argv[2] == '1')
elif sys.argv[1] == 'safari':
    # Each bundle is guarded in run_safari. A failure outside them ends the
    # walk early, so it exits non-zero: the caller then never sees "#done"
    # and the Safari walk is not complete (PAT-2065 review).
    try:
        run_safari(sys.argv[2:])
    except Exception:
        refused("safari_walk_failed", "<safari>")
        sys.exit(1)
PYEOF
}
