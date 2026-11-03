# apps.sh — installed application inventory.
# Sets APPS_JSON_FILE (path to the temp JSON array file), constructed from
# QUEUE_DIR and TS_FILE globals set by the main script.
# The temp file is consumed by the main script's JSON assembly and cleaned up
# after a successful validation + mv.
# Sourced by patched-collect.sh; not executable directly.
#
# set -euo pipefail is intentionally NOT used here: lipo and codesign return
# non-zero on launcher stubs and alias-style apps. Per-iteration || true
# defaults handle failures without aborting the loop.
#
# ABSENCE REQUIRES AUTHORITY (PAT-2066, platform half PAT-2063). The top-level
# `collection_status.apps` value tells the server whether the `apps` array is
# the whole machine-wide inventory; apps_users independently covers each user:
#   complete    -> every application root was listed without error and every
#                  top-level bundle found was read into a row. The server
#                  prunes every stored app not listed, even when apps is [].
#   partial     -> a root listing failed (find exited non-zero), or a bundle
#                  had no readable, parseable Info.plist and was left out. The
#                  server upserts the rows sent and prunes nothing.
#   unavailable -> collect_apps never finished (the patched-collect.sh stub).
#                  apps is sent as [] and the server writes nothing.
# Scope, not failure (never inventoried, so never pruned, never partial):
# bundles nested inside another .app (helpers of their parent) and a `.app`
# that is not a directory (an alias or other file). A directory with
# Contents/ whose Info.plist is missing or unparseable is partial.
# iOS and iPadOS apps on Apple silicon are in scope (PAT-2072): a directory
# with no Contents/ and a WrappedBundle or Wrapper/ is read from the one
# Wrapper/*.app/Info.plist inside it and sent as an ordinary row. A wrapper
# with no inner app, more than one, or an Info.plist that is missing or
# unparseable is partial.
# complete covers the machine roots only: /Applications, /Applications/Utilities
# and /Users/Shared/Applications (nobody's home, so machine scope). It is claimed
# only when every one of them that exists was actually listed: a machine root
# that is a symlink is not followed by find, so it makes the scope partial.
# Every other /Users/*/Applications is an independently resolved per-user scope
# (PAT-2075), reported with the home directory it was found in.
# There is no row cap. Anything other than complete logs one
# PATCHED_COLLECTION_WARNING line to stderr naming the reason.

# _apps_scan_roots
#   Sets reply to the directories the walk lists. A function so the tests can
#   point the walk at fixtures. (N) drops /Users/*/Applications when no user
#   has one, instead of passing find a literal pattern it cannot open.
_apps_scan_roots() {
    reply=(/Applications /Applications/Utilities /Users/*/Applications(N))
}

# _apps_scan_homes
#   Sets reply to the candidate user home directories. Real directories only: a
#   linked home is never a resolved home. A function so the tests can point it
#   at fixtures.
_apps_scan_homes() {
    reply=(/Users/*(N/))
}

# apps_collection_status
#   Prints the wire value for collection_status.apps. Anything other than
#   complete or partial (unset, the stub, a typo) is unavailable, so the server
#   never treats an unknown state as a reading.
apps_collection_status() {
    case "${APPS_COLLECTION_STATUS:-}" in
        complete|partial) print -r -- "$APPS_COLLECTION_STATUS" ;;
        *) print -r -- "unavailable" ;;
    esac
}

# apps_payload_array
#   Prints the committed apps array. Machine-unavailable alone emits [], unless
#   the scope merge committed independently observed user scopes. An unfinished
#   collection has no user authority and cannot publish partially assembled rows.
apps_payload_array() {
    if { [[ "$(apps_collection_status)" == "unavailable" ]] && [[ "${APPS_USERS_JSON:-[]}" == '[]' ]]; } \
        || [[ -z "${APPS_JSON_FILE:-}" || ! -s "$APPS_JSON_FILE" ]]; then
        print -r -- "[]"
        return 0
    fi
    if [[ "$(apps_collection_status)" == "unavailable" ]]; then
        # Machine scope was not read: only rows a user scope observed may go out,
        # whatever the file holds. Unparseable content sends nothing.
        "$PYTHON3" - "$APPS_JSON_FILE" <<'PYUSERROWS' || print -r -- "[]"
import json, sys
with open(sys.argv[1]) as source:
    rows = json.load(source)
if not isinstance(rows, list): raise SystemExit(1)
json.dump([row for row in rows if isinstance(row, dict) and row.get('user_account')], sys.stdout)
PYUSERROWS
        return 0
    fi
    cat "$APPS_JSON_FILE"
}

# --- Signing and notarisation evidence (PAT-2112) ----------------------------
# Two per-app fields, macOS only, beside the unchanged signed_by and team_id:
#
#   signing_status       signed | untrusted | invalid | adhoc | unsigned |
#                        error. `codesign -dvv`'s exit status and output say
#                        whether there is a signature and whose name it
#                        carries; "Unknown" in signed_by used to cover adhoc,
#                        unsigned and error alike. A signature -dvv shows with
#                        an Authority is then checked against a trust anchor
#                        (PAT-2117, below), because -dvv does not evaluate
#                        trust: signed means that check passed.
#   notarization_status  notarized | not_notarized | unknown. codesign never
#                        prints "Notarized", so the old grep reported every app
#                        false. Notarisation only exists for Developer ID
#                        signed code, so:
#                          unsigned, adhoc, untrusted -> not_notarized
#                          invalid, error            -> unknown
#                          signed, not Developer ID  -> not_notarized (Apple
#                            system and Mac App Store apps are not notarised)
#                          signed, Developer ID      -> Gatekeeper, below
#   notarized stays a boolean for older servers: true only when
#   notarization_status is notarized.
#
# For a Developer ID app, `spctl --assess --type execute -vv` is the
# authority: an accepted assessment whose source is "Notarized Developer ID"
# is notarized, any other source line is not_notarized. Many notarised apps
# are not stapled (VLC, Zed, zoom on the PAT-2112 test Mac), so codesign's
# `Notarization Ticket=stapled` line is only the fallback, used when spctl
# timed out, is missing, or printed no source (Opera: "bundle format
# unrecognized"). With neither, the answer is unknown, never not_notarized.
# spctl can make a network request, so it runs under a hard timeout: the
# collection must never hang on it. An unstapled app assessed while offline
# can read not_notarized; the server reads not_notarized and unknown alike as
# "not confirmed", never as a verdict against the app.

# --- Trust anchor (PAT-2117) -------------------------------------------------
# `codesign -dvv` prints the leaf certificate's name without evaluating
# trust, so a self-signed certificate named "Developer ID Application: Google
# LLC (EQHXZ8M8AV)" read as signed by Google. Every signature -dvv shows with
# an Authority is therefore verified against the requirement
# `anchor apple generic`: the certificate chain ends at Apple's root. That
# covers Developer ID, Mac App Store, iOS-on-Mac and Apple's own software
# (Safari, Calculator and Chrome all pass it on macOS 27), and it is anchored
# on the root certificate itself, never on a name. The exit status decides:
#   0            signed     valid and chained to Apple's root
#   3            untrusted  structurally valid, but the requirement failed:
#                           self-signed, or chained to another root
#   1            invalid    the signature does not validate against the code
#                           (a modified executable or Info.plist, a broken
#                           signature). -dvv read that same signature moments
#                           before, so this is the code, not a missing file.
#   anything     error      a usage error, a missing codesign, or the
#   else                    timeout: never signed
# The output is not read, only the exit status, so no path or identifier text
# can steer the answer.
#
# Scope: `--verify --ignore-resources`, without --deep and without --strict.
# That checks the CodeDirectory, its CMS signature and certificate chain, the
# main executable's pages in every architecture and the bound Info.plist. It
# does not hash the bundle's resource files or nested code: measured over the
# 81 bundles on the PAT-2117 test Mac (macOS 27), full resource validation
# took 39s a run with Xcode alone at 10-12s, against 13s and a 1.4s maximum
# without it. --strict was dropped because it rejects zoom.us for Finder
# metadata (xattr detritus) that Gatekeeper accepts, which would read as a
# tampered app. For Developer ID apps spctl still assesses the whole bundle.
_APPS_VERIFY_REQUIREMENT='=anchor apple generic'
# Seconds one verification may take before it is killed; 1.4s was the most
# any bundle took on the PAT-2117 test Mac.
_APPS_VERIFY_TIMEOUT_SECONDS=10
# A variable so the tests can point it at stubs or at a missing file.
_APPS_CODESIGN=/usr/bin/codesign

# Seconds one spctl assessment may take before it is killed. Chrome took
# 6.6s cold on the PAT-2112 test Mac; most Developer ID apps take under 1s.
_APPS_SPCTL_TIMEOUT_SECONDS=10
# A variable so the tests can point it at stubs or at a missing file.
_APPS_SPCTL=/usr/sbin/spctl

# --- Attacker-controlled text in codesign output (PAT-2115) ------------------
# `codesign -dvv` prints, in this order:
#   Executable=<path>            the main executable's path: the bundle path
#                                plus CFBundleExecutable, both of which any
#                                user who can write ~/Applications chooses
#   Identifier=<id>              the signing identifier, which `codesign -s -
#                                -i` accepts with embedded newlines
#   Format=...
#   CodeDirectory v=...          the first line codesign writes itself after
#                                the two above
#   ... Signature=adhoc | Authority=... (leaf first) ... TeamIdentifier=...
# and its error lines carry the path too. A newline in any of those values
# plants lines of its own, such as "Authority=Developer ID Application: X"
# and "TeamIdentifier=<a trusted team>", ahead of the genuine ones, which a
# first-match read took as the app's publisher. Two defences:
#   1. collect_apps refuses to run codesign, spctl or lipo at all on a bundle
#      whose path or executable path holds a control character
#      (apps_has_control_char); the row is still sent, with signed_by and
#      team_id "Unknown", signing_status error and notarization_status
#      unknown.
#   2. Every field is read only from the lines after the LAST
#      "CodeDirectory v=" line (apps_codesign_body). The genuine one follows
#      both attacker-controlled lines, so injected text can only add
#      CodeDirectory lines before it, never after it. That also covers the
#      signing identifier, which defence 1 cannot see before codesign runs.
# Output with no CodeDirectory line (an error, an unsigned bundle) has no
# body, so signed_by and team_id are "Unknown".

# apps_has_control_char <string>
#   Succeeds when the string holds a control character: C0 (0x01-0x1f) or DEL
#   in any locale, and C1 as well under a UTF-8 one.
apps_has_control_char() {
    [[ "$1" == *[[:cntrl:]]* ]]
}

# apps_codesign_body <codesign-output>
#   Sets reply to the lines after the last "CodeDirectory v=" line, or to an
#   empty array when there is none.
apps_codesign_body() {
    local -a cs_lines
    cs_lines=("${(@f)1}")
    local cd_idx=${cs_lines[(I)CodeDirectory v=*]}
    reply=()
    (( cd_idx > 0 )) && reply=("${(@)cs_lines[cd_idx+1,-1]}")
    return 0
}

# apps_codesign_field <codesign-output> <key>
#   Prints the value of the first "<key>=" line in the codesign body, or
#   "Unknown". For Authority that is the leaf certificate's name.
apps_codesign_field() {
    local reply
    apps_codesign_body "$1"
    local -a cs_body
    cs_body=("${reply[@]}")
    local f_idx=${cs_body[(i)$2=?*]}
    if (( f_idx <= ${#cs_body} )); then
        print -r -- "${cs_body[$f_idx]#$2=}"
    else
        print -r -- "Unknown"
    fi
}

# apps_signing_status <codesign-exit> <codesign-output>
#   Prints signing_status for one `codesign -dvv` run. Signature=adhoc and
#   Authority= are read only from the codesign body (see above), and ad hoc is
#   checked first. "not signed at all" is codesign's last line, after the path.
apps_signing_status() {
    local cs_rc="$1" cs_out="$2"
    local -a cs_lines cs_body
    local reply
    cs_lines=("${(@f)cs_out}")
    apps_codesign_body "$cs_out"
    cs_body=("${reply[@]}")
    if (( cs_rc != 0 )) && [[ "${cs_lines[-1]:-}" == *": code object is not signed at all" ]]; then
        print -r -- "unsigned"
    elif (( cs_rc == 0 )) && (( ${cs_body[(I)Signature=adhoc]} )); then
        print -r -- "adhoc"
    elif (( cs_rc == 0 )) && (( ${cs_body[(I)Authority=?*]} )); then
        print -r -- "signed"
    else
        print -r -- "error"
    fi
}

# apps_run_bounded <timeout-seconds> <output-file> <command> [args...]
#   Runs <command> with a hard timeout and prints its exit status: the
#   command's own, 124 when it was killed at the timeout, 127 when it is not
#   there or could not be started. Its combined output is left in
#   <output-file>. The same background-and-poll bound the local_models,
#   ide_extensions and package_managers parsers use: the collector has no
#   timeout helper and macOS ships no timeout(1).
apps_run_bounded() {
    local rb_limit="$1" out_file="$2"
    shift 2
    local rb_pid rb_rc=0 rb_ticks=0
    if [[ "$out_file" != /dev/null ]]; then
        : > "$out_file" 2>/dev/null || { print -r -- 127; return 0; }
    fi
    [[ -x "$1" ]] || { print -r -- 127; return 0; }
    "$@" < /dev/null > "$out_file" 2>&1 &
    rb_pid=$!
    while kill -0 "$rb_pid" 2>/dev/null; do
        if (( rb_ticks >= rb_limit * 10 )); then
            kill -9 "$rb_pid" 2>/dev/null
            wait "$rb_pid" 2>/dev/null
            print -r -- 124
            return 0
        fi
        sleep 0.1
        (( rb_ticks++ ))
    done
    wait "$rb_pid" 2>/dev/null || rb_rc=$?
    print -r -- "$rb_rc"
}

# apps_spctl_assess <target> <output-file>
#   Runs the Gatekeeper assessment under _APPS_SPCTL_TIMEOUT_SECONDS and
#   prints its exit status as apps_run_bounded does.
apps_spctl_assess() {
    apps_run_bounded "$_APPS_SPCTL_TIMEOUT_SECONDS" "$2" \
        "$_APPS_SPCTL" --assess --type execute -vv "$1"
}

# apps_codesign_verify <target>
#   Verifies the signature against the trust anchor (PAT-2117, above) under
#   _APPS_VERIFY_TIMEOUT_SECONDS and prints codesign's exit status, 124 on the
#   timeout or 127 when codesign is missing. The output is discarded.
apps_codesign_verify() {
    apps_run_bounded "$_APPS_VERIFY_TIMEOUT_SECONDS" /dev/null \
        "$_APPS_CODESIGN" --verify --ignore-resources \
        -R "$_APPS_VERIFY_REQUIREMENT" "$1"
}

# apps_signing_trust <signing-status> <verify-exit>
#   Prints the final signing_status. Only signed is re-judged, from the anchor
#   check's exit status; every other status passes through unchanged.
apps_signing_trust() {
    if [[ "$1" != "signed" ]]; then
        print -r -- "$1"
        return 0
    fi
    case "$2" in
        0) print -r -- "signed" ;;
        3) print -r -- "untrusted" ;;
        1) print -r -- "invalid" ;;
        *) print -r -- "error" ;;
    esac
}

# apps_notarization_from_spctl <spctl-exit> <spctl-output> <codesign-output>
#   Prints notarization_status for a Developer ID signed app from a finished
#   (or killed) assessment, falling back to the stapled ticket.
apps_notarization_from_spctl() {
    local sp_rc="$1" sp_out="$2" cs_out="$3"
    local -a sp_lines cs_lines
    local sp_source="" reply
    sp_lines=("${(@f)sp_out}")
    # The stapled ticket line is read from the codesign body only (PAT-2115).
    apps_codesign_body "$cs_out"
    cs_lines=("${reply[@]}")
    if (( sp_rc != 124 && sp_rc != 127 )); then
        # The last source line: spctl prints the path first, so a path could
        # only add lines before the genuine one.
        local sp_idx=${sp_lines[(I)source=*]}
        (( sp_idx > 0 )) && sp_source="${sp_lines[$sp_idx]#source=}"
    fi
    if [[ "$sp_source" == "Notarized Developer ID" ]] && (( sp_rc == 0 )); then
        print -r -- "notarized"
    elif [[ -n "$sp_source" && "$sp_source" != "Notarized Developer ID" ]]; then
        print -r -- "not_notarized"
    elif (( ${cs_lines[(I)Notarization Ticket=stapled]} )); then
        print -r -- "notarized"
    else
        print -r -- "unknown"
    fi
}

# apps_notarization_status <signing-status> <signed-by> <target> <codesign-output> <spctl-output-file> [executable-path]
#   Prints notarization_status for one app, running spctl only for a
#   Developer ID signed app.
apps_notarization_status() {
    local sig="$1" signer="$2" target="$3" cs_out="$4" out_file="$5" exec_file="${6:-}"
    local sp_rc
    case "$sig" in
        # untrusted: notarisation needs an Apple-issued Developer ID, which
        # an untrusted signature is not. invalid falls to unknown below.
        unsigned|adhoc|untrusted) print -r -- "not_notarized"; return 0 ;;
        signed) ;;
        *) print -r -- "unknown"; return 0 ;;
    esac
    if [[ "$signer" != "Developer ID Application:"* ]]; then
        print -r -- "not_notarized"
        return 0
    fi
    # Both tools echo the path (codesign the executable's), so a path with a
    # newline could plant a "source=" or "Notarization Ticket=stapled" line of
    # its own.
    if [[ "$target" == *$'\n'* || "$exec_file" == *$'\n'* ]]; then
        print -r -- "unknown"
        return 0
    fi
    if [[ -z "$out_file" ]]; then
        sp_rc=127
    else
        sp_rc=$(apps_spctl_assess "$target" "$out_file")
    fi
    apps_notarization_from_spctl "$sp_rc" "$(cat "$out_file" 2>/dev/null)" "$cs_out"
}

# --- Software metering (Spotlight usage metadata) ---------------------------
# Per-app usage signals come from Spotlight: kMDItemLastUsedDate (last launch)
# and kMDItemUseCount (lifetime cumulative launch count). Two hard caveats,
# both handled below (see ADR-0005):
#   1. The data lives in the PER-USER Spotlight store, written by LaunchServices
#      in the logged-in user's session. A root global-context read returns
#      nulls, so reads run in the console user's context via `launchctl asuser`.
#   2. If Spotlight indexing is disabled on the volume the store is dead and
#      every app reads null. We probe `mdutil -s /` once and skip the reads
#      entirely when indexing is off. Per-app usage_evidence distinguishes a
#      successful null read from an unavailable source; neither proves non-use.
# Absolute tool paths per the repo's "sudo strips PATH" convention.

# _mdls_read <attribute> <app-path> — echoes the raw -raw value or "(null)".
_mdls_read() {
    if [[ -n "$METERING_CONSOLE_UID" ]]; then
        launchctl asuser "$METERING_CONSOLE_UID" sudo -u "$METERING_CONSOLE_USER" \
            /usr/bin/mdls -raw -name "$1" "$2" 2>/dev/null
    else
        /usr/bin/mdls -raw -name "$1" "$2" 2>/dev/null
    fi
}

# read_metering <app-path>: last-used|count|evidence. Both numeric/date values
# may be empty, but a failed read is never the same evidence as a successful null.
read_metering() {
    if [[ "$METERING_ENABLED" != "true" || -z "$METERING_CONSOLE_UID" ]]; then
        print -r -- '||unavailable'
        return 0
    fi

    local last count last_rc count_rc evidence=no_record
    last=$(_mdls_read "kMDItemLastUsedDate" "$1"); last_rc=$?
    count=$(_mdls_read "kMDItemUseCount" "$1"); count_rc=$?
    if (( last_rc != 0 )); then
        last=""; evidence=unavailable
    elif [[ "$last" == "(null)" ]]; then
        last=""
    elif [[ -z "$last" ]]; then
        evidence=unavailable
    else
        last=$(date -j -u -f "%Y-%m-%d %H:%M:%S %z" "$last" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
        if [[ -z "$last" || "$last" == 1980-01-01T* ]]; then
            last=""; evidence=unavailable
        fi
    fi
    if (( count_rc != 0 )); then
        count=""; evidence=unavailable
    elif [[ "$count" == "(null)" ]]; then
        count=""
    elif [[ "$count" != <-> || ${#count} -gt 10 ]]; then
        count=""; evidence=unavailable
    elif (( 10#$count > 2147483647 )); then
        count=""; evidence=unavailable
    else
        count=$(( 10#$count ))
    fi
    if [[ "$evidence" != unavailable && ( -n "$last" || ( -n "$count" && "$count" != 0 ) ) ]]; then
        evidence=recorded
    fi
    print -r -- "${last}|${count}|${evidence}"
}

_apps_collect_roots() {
    # Explicit default: bound before any command runs so a set -u abort or
    # unexpected macOS 26 behaviour leaves METERING_STATUS set.
    # NOTE: do NOT pre-set APPS_JSON_FILE here — patched-collect.sh pre-inits
    # it to a stub file with "[]" content.  This function overwrites it (below)
    # only once the real queue file's array is closed; if this function fails
    # early the stub remains valid and the heredoc produces well-formed JSON.
    # PAT-2066: the status is unavailable until the walk has finished, so a
    # crash part way through can never be read as a complete inventory.
    METERING_STATUS="unavailable"
    APPS_COLLECTION_STATUS="unavailable"

    # Metering setup, computed once before the per-app loop. Resolve the console user for user-context reads;
    # treat root/loginwindow/no-session as "no interactive user" and skip usage
    # reads. Probe Spotlight indexing to avoid 100s of
    # pointless mdls calls when the store is disabled.
    METERING_CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null || echo "")
    case "$METERING_CONSOLE_USER" in
        root|loginwindow|"") METERING_CONSOLE_USER="" ;;
    esac
    METERING_CONSOLE_UID=""
    [[ -n "$METERING_CONSOLE_USER" ]] && \
        METERING_CONSOLE_UID=$(id -u "$METERING_CONSOLE_USER" 2>/dev/null || echo "")

    METERING_ENABLED=false
    local apps_metering_source_status=unavailable apps_mdutil_out apps_mdutil_rc
    apps_mdutil_out=$(/usr/bin/mdutil -s / 2>/dev/null); apps_mdutil_rc=$?
    if (( apps_mdutil_rc == 0 )) && [[ "$apps_mdutil_out" == *"Indexing enabled"* ]]; then
        METERING_ENABLED=true
        if [[ -n "$METERING_CONSOLE_UID" ]]; then
            apps_metering_source_status=ok
        else
            apps_metering_source_status=no_user_session
        fi
    elif (( apps_mdutil_rc == 0 )) && [[ "$apps_mdutil_out" == *"Indexing disabled"* ]]; then
        apps_metering_source_status=spotlight_disabled
    fi
    # Commit the source status only after the collection finishes. A failed
    # mdutil probe or an early abort must never claim Spotlight was disabled.

    # Rows go to their own file and APPS_JSON_FILE is only pointed at it once
    # the array is closed, so an early exit leaves the stub in place.
    local apps_out="$QUEUE_DIR/.apps-$TS_FILE.tmp"
    local apps_list apps_sorted apps_find_rc apps_sort_rc
    local -a apps_roots apps_inner
    local apps_exec_dir apps_sign_target apps_refused
    local apps_fail_reason="" apps_skip_reason="" apps_skipped=0
    apps_list=$(mktemp "$PATCHED_TMPDIR/apps-list.XXXXXX") || return 0
    apps_sorted=$(mktemp "$PATCHED_TMPDIR/apps-sorted.XXXXXX") || { rm -f "$apps_list"; return 0; }
    # spctl's output for one app at a time. Without it notarisation falls back
    # to the stapled ticket, then unknown; it never stops the walk.
    local apps_spctl_out
    apps_spctl_out=$(mktemp "$PATCHED_TMPDIR/apps-spctl.XXXXXX") || apps_spctl_out=""
    echo "[" > "$apps_out"

    FIRST_APP=true

    # find exits non-zero when any root or directory under it could not be
    # listed. Its output is then not the whole set of bundles, so the
    # collection is partial. The listing goes through a file, not a pipe, so
    # that status is not lost to the pipeline.
    apps_roots=("$@")
    # NUL-separated (PAT-2115): a path is any bytes but NUL, so a bundle
    # whose name holds a newline is one entry, not several fragments that
    # each fail the directory test below and leave the bundle silently out
    # of a run still reported complete.
    find "${apps_roots[@]}" -iname "*.app" -maxdepth 4 -print0 > "$apps_list" 2>/dev/null
    apps_find_rc=$?
    (( apps_find_rc != 0 )) && apps_fail_reason="listing_failed"
    # A non-following find can succeed while a link hides user inventory.
    # Keep the existing read guards; linked user roots/bundles grant no absence.
    if [[ "${_APPS_USER_SCOPE:-false}" == true ]]; then
        local apps_link_file apps_link_rc
        apps_link_file=$(mktemp "$PATCHED_TMPDIR/apps-links.XXXXXX") || return 0
        # Same depth as the listing, and never inside a bundle: every framework
        # bundle carries Versions/Current links, which hide no inventory. A
        # linked .app itself is caught per bundle below.
        find "${apps_roots[@]}" -maxdepth 4 \( -iname "*.app" -prune \) -o \( -type l -print -quit \) \
            > "$apps_link_file" 2>/dev/null
        apps_link_rc=$?
        if (( apps_link_rc != 0 )) || [[ -s "$apps_link_file" ]]; then
            apps_fail_reason="user_links_or_listing_failed"
        fi
        rm -f "$apps_link_file"
    fi

    # Sorted+deduped: /Applications/Utilities is itself inside /Applications, so
    # both root args match anything under Utilities, producing an exact-duplicate
    # path from `find` for every app there (independent of the nested-bundle
    # filter below, which handles a different kind of duplicate).
    sort -z -u "$apps_list" > "$apps_sorted"
    apps_sort_rc=$?
    (( apps_sort_rc != 0 )) && apps_fail_reason="listing_failed"

    # Read from fd 3, not stdin: commands in the loop body (launchctl asuser,
    # sudo, PlistBuddy) inherit stdin, and one that read it would silently eat
    # rows while the run still reported complete (PAT-2066 review).
    while IFS= read -r -d '' -u 3 APP
    do
        # Skip bundles nested inside another .app (Electron/Chromium-style
        # GPU/Renderer/Plugin helper processes under Contents/Frameworks, or
        # Contents/Library/LoginItems helpers, etc.) — these are internal
        # implementation details of the parent app, not separately installed
        # software. A real top-level app has exactly one ".app" path
        # component; anything with a second ".app" earlier in the path is
        # nested. This was previously unfiltered, so every Electron-based app
        # (Slack, Discord, Teams, Zoom, Claude, ...) reported 3-14 duplicate
        # "installed apps" for its own internal helpers.
        [[ "$APP" == *.app/*.app ]] && continue

        # Scope, not failure: a `.app` that is not a directory (a Finder alias
        # or other file) is not a bundle. It has never been inventoried, so it
        # is never pruned, and it never makes the collection partial.
        [[ -d "$APP" ]] || continue
        if [[ "${_APPS_USER_SCOPE:-false}" == true ]] && { [[ -L "$APP" ]] || [[ -L "$APP/Contents" ]]; }; then
            (( apps_skipped++ )); apps_skip_reason="user_link_unreadable"; continue
        fi

        # An iOS or iPadOS app on Apple silicon (PAT-2072) has no Contents/;
        # its identity lives in the flat bundle at Wrapper/<name>.app. It is in
        # scope, so a wrapper this run cannot identify is partial, not skipped.
        if [[ ! -e "$APP/Contents" ]] \
            && [[ -e "$APP/WrappedBundle" || -L "$APP/WrappedBundle" || -d "$APP/Wrapper" ]]; then
            apps_inner=("$APP"/Wrapper/*.app(N/))
            if (( ${#apps_inner} != 1 )); then
                (( apps_skipped++ ))
                apps_skip_reason="bundle_unreadable"
                continue
            fi
            INFO_PLIST="${apps_inner[1]}/Info.plist"
            apps_exec_dir="${apps_inner[1]}"
            apps_sign_target="${apps_inner[1]}"
        else
            INFO_PLIST="$APP/Contents/Info.plist"
            apps_exec_dir="$APP/Contents/MacOS"
            apps_sign_target="$APP"
        fi

        # A real bundle with no Info.plist, or one that cannot be read or
        # parsed, is an installed app this run could not identify. It is left
        # out, as before, and the collection is partial so the server does not
        # read its absence as a removal. The gate is plutil, not PlistBuddy:
        # PlistBuddy treats a plist it cannot open as a new empty one and
        # exits 0 (PAT-2072), so an unreadable bundle passed the gate and went
        # out as a row named by PlistBuddy's own message.
        if [[ ! -f "$INFO_PLIST" ]] \
            || ! /usr/bin/plutil -lint -s "$INFO_PLIST" >/dev/null 2>&1; then
            (( apps_skipped++ ))
            apps_skip_reason="bundle_unreadable"
            continue
        fi

        if [[ "$apps_sign_target" == "$APP" ]]; then
            NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$INFO_PLIST" 2>/dev/null || basename "$APP" .app)
            VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFO_PLIST" 2>/dev/null || echo "Unknown")
        else
            # iOS bundles often carry only CFBundleDisplayName or only
            # CFBundleVersion, so each falls back one step before the default.
            NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleDisplayName" "$INFO_PLIST" 2>/dev/null \
                || /usr/libexec/PlistBuddy -c "Print :CFBundleName" "$INFO_PLIST" 2>/dev/null \
                || basename "$APP" .app)
            VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFO_PLIST" 2>/dev/null \
                || /usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$INFO_PLIST" 2>/dev/null \
                || echo "Unknown")
        fi
        BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$INFO_PLIST" 2>/dev/null || echo "Unknown")

        # du prints the path after the size, so only the first line's first
        # field is the size: a newline in the path would add lines, and
        # SIZE_BYTES is spliced into an awk program and a bare JSON number.
        SIZE_BYTES=$(du -sk "$APP" 2>/dev/null | awk 'NR == 1 { print $1 * 1024; exit }')
        [[ "$SIZE_BYTES" == <-> ]] || SIZE_BYTES=0
        SIZE_MB=$(awk "BEGIN { printf \"%.2f\", ${SIZE_BYTES}/1024/1024 }")

        MODIFIED_DATE=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$APP" 2>/dev/null || echo "Unknown")

        EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$INFO_PLIST" 2>/dev/null || echo "")
        EXEC_PATH="$apps_exec_dir/$EXECUTABLE"

        # PAT-2115: codesign, spctl and lipo echo the path they were given, so
        # a control character in it could plant lines in their output. Such a
        # bundle is still reported, but nothing is read from those tools.
        apps_refused=false
        apps_has_control_char "$APP$apps_sign_target$EXEC_PATH" && apps_refused=true

        APP_ARCH="Unknown"
        SHA256="Unknown"
        if [[ -f "$EXEC_PATH" ]]; then
            if [[ "$apps_refused" == "false" ]]; then
                ARCH_RAW=$(lipo -info "$EXEC_PATH" 2>/dev/null | sed 's/.*are://' | sed 's/Non-fat file:.*is architecture://' | xargs 2>/dev/null || true)
                [[ -n "$ARCH_RAW" ]] && APP_ARCH="$ARCH_RAW"
            fi

            # Hashed from stdin: shasum names the file after the digest and
            # escapes a newline in it by prefixing the digest with "\".
            SHA_RAW=$(shasum -a 256 < "$EXEC_PATH" 2>/dev/null | awk 'NR == 1 { print $1 }' || true)
            [[ "$SHA_RAW" =~ '^[0-9a-f]{64}$' ]] && SHA256="$SHA_RAW"
        fi

        if [[ "$apps_refused" == "true" ]]; then
            TEAM_ID="Unknown"
            SIGNED_BY="Unknown"
            SIGNING_STATUS="error"
            NOTARIZATION_STATUS="unknown"
        else
            CODESIGN_OUTPUT=$(codesign -dvv "$apps_sign_target" 2>&1)
            CODESIGN_RC=$?
            # Read from the codesign body only (PAT-2115, see above).
            TEAM_ID=$(apps_codesign_field "$CODESIGN_OUTPUT" TeamIdentifier)
            SIGNED_BY=$(apps_codesign_field "$CODESIGN_OUTPUT" Authority)

            # PAT-2112: see "Signing and notarisation evidence" above.
            SIGNING_STATUS=$(apps_signing_status "$CODESIGN_RC" "$CODESIGN_OUTPUT")
            # PAT-2117: a named signer is only signed once its chain is
            # anchored at Apple's root (see "Trust anchor" above).
            if [[ "$SIGNING_STATUS" == "signed" ]]; then
                SIGNING_STATUS=$(apps_signing_trust signed \
                    "$(apps_codesign_verify "$apps_sign_target")")
            fi
            NOTARIZATION_STATUS=$(apps_notarization_status "$SIGNING_STATUS" "$SIGNED_BY" \
                "$apps_sign_target" "$CODESIGN_OUTPUT" "$apps_spctl_out" "$EXEC_PATH")
        fi
        NOTARIZED="false"
        [[ "$NOTARIZATION_STATUS" == "notarized" ]] && NOTARIZED="true"

        METERING=$(read_metering "$APP")
        LAST_USED="${METERING%%|*}"
        USAGE_EVIDENCE="${METERING##*|}"
        METERING="${METERING%|*}"
        LAUNCH_COUNT="${METERING##*|}"
        if [[ -n "$LAST_USED" ]]; then
            LAST_USED_JSON=$(json_escape "$LAST_USED")
        else
            LAST_USED_JSON="null"
        fi
        [[ -z "$LAUNCH_COUNT" ]] && LAUNCH_COUNT="null"

        if [[ "$FIRST_APP" == "false" ]]; then
            echo "," >> "$apps_out"
        fi
        FIRST_APP=false

        cat >> "$apps_out" <<EOF
{
  "name":          $(json_escape "$NAME"),
  "version":       $(json_escape "$VERSION"),
  "identifier":    $(json_escape "$BUNDLE_ID"),
  "bundle_id":     $(json_escape "$BUNDLE_ID"),
  "path":          $(json_escape "$APP"),
  "size_mb":       $SIZE_MB,
  "modified_at":   $(json_escape "$MODIFIED_DATE"),
  "architecture":  $(json_escape "$APP_ARCH"),
  "sha256":        $(json_escape "$SHA256"),
  "team_id":       $(json_escape "$TEAM_ID"),
  "signed_by":     $(json_escape "$SIGNED_BY"),
  "notarized":     $NOTARIZED,
  "signing_status": $(json_escape "$SIGNING_STATUS"),
  "notarization_status": $(json_escape "$NOTARIZATION_STATUS"),
  "last_used_at":  $LAST_USED_JSON,
  "launch_count":  $LAUNCH_COUNT,
  "usage_evidence": $(json_escape "$USAGE_EVIDENCE")
}
EOF
    done 3< "$apps_sorted"

    echo "]" >> "$apps_out"
    rm -f "$apps_list" "$apps_sorted"
    [[ -n "$apps_spctl_out" ]] && rm -f "$apps_spctl_out"
    APPS_JSON_FILE="$apps_out"
    METERING_STATUS="$apps_metering_source_status"

    local apps_warning_section=apps
    [[ "${_APPS_USER_SCOPE:-false}" == true ]] && apps_warning_section=apps_users
    if [[ -n "$apps_fail_reason" ]]; then
        APPS_COLLECTION_STATUS="partial"
        echo "PATCHED_COLLECTION_WARNING section=$apps_warning_section status=partial reason=${apps_fail_reason} skipped=${apps_skipped}" >&2
    elif (( apps_skipped > 0 )); then
        APPS_COLLECTION_STATUS="partial"
        echo "PATCHED_COLLECTION_WARNING section=$apps_warning_section status=partial reason=${apps_skip_reason} skipped=${apps_skipped}" >&2
    else
        APPS_COLLECTION_STATUS="complete"
    fi
}


# Account identity is DirectoryService metadata, never a home-folder basename.
# Only the default user roots need this lookup; machine roots return empty success.
# Failed/ambiguous identity returns nonzero so a user root cannot become machine scope.
_apps_user_account_for_root() {
    local root="$1" metadata account rc
    [[ "$root" == /Users/*/Applications ]] || return 0
    # /Users/Shared is nobody's home directory. Its Applications folder is a
    # machine root, covered by machine authority, never dropped as unresolved.
    [[ "$root" == /Users/Shared/Applications ]] && return 0
    [[ "${root:h:h}" == /Users && ! -L "${root:h}" ]] || return 1
    metadata=$(mktemp "$PATCHED_TMPDIR/apps-accounts.XXXXXX") || return 1
    /usr/bin/dscl -plist . -readall /Users RecordName NFSHomeDirectory > "$metadata" 2>/dev/null
    rc=$?
    if (( rc != 0 )); then rm -f "$metadata"; return 1; fi
    account=$("$PYTHON3" - "$metadata" "${root:h}" <<'PYACCOUNT'
import plistlib, sys
try:
    with open(sys.argv[1], 'rb') as source:
        records = plistlib.load(source)
    if not isinstance(records, list): raise ValueError('invalid account listing')
    matches = []
    for record in records:
        if not isinstance(record, dict): raise ValueError('invalid account record')
        homes = record.get('dsAttrTypeStandard:NFSHomeDirectory', [])
        names = record.get('dsAttrTypeStandard:RecordName', [])
        if not isinstance(homes, list) or any(not isinstance(home, str) for home in homes):
            raise ValueError('invalid home metadata')
        if sys.argv[2] not in homes: continue
        if not isinstance(names, list) or not names: raise ValueError('missing account name')
        name = names[0]
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or name != name.strip():
            raise ValueError('invalid account name')
        if any(ord(c) < 32 or ord(c) == 127 for c in name): raise ValueError('control character')
        matches.append(name)
    if len(matches) != 1: raise ValueError('missing or ambiguous home identity')
    print(matches[0])
except Exception:
    sys.exit(1)
PYACCOUNT
    ); rc=$?
    rm -f "$metadata"
    (( rc == 0 )) || return 1
    print -r -- "$account"
}

apps_users_collection_status() { print -r -- "${APPS_USERS_JSON:-[]}"; }

# Collect the unchanged bundle observations once per independent scope. A failed
# user's source affects only that user; no status survives an unfinished merge.
collect_apps() {
    METERING_STATUS=unavailable
    APPS_COLLECTION_STATUS=unavailable
    APPS_USERS_JSON='[]'
    local reply root account rc group_status machine_status=unavailable home
    local manifest combined states part stub user_scope staging_ok=true machine_link=false
    local -a roots machine_roots user_roots user_accounts homes folderless_homes folderless_accounts
    manifest=$(mktemp "$PATCHED_TMPDIR/apps-scopes.XXXXXX") || return 0
    combined=$(mktemp "$PATCHED_TMPDIR/apps-combined.XXXXXX") || { rm -f "$manifest"; return 0; }
    states=$(mktemp "$PATCHED_TMPDIR/apps-users.XXXXXX") || { rm -f "$manifest" "$combined"; return 0; }
    _apps_scan_roots
    roots=("${reply[@]}")
    for root in "${roots[@]}"; do
        account=$(_apps_user_account_for_root "$root"); rc=$?
        if (( rc != 0 )); then
            print -r -- 'PATCHED_COLLECTION_WARNING section=apps_users status=partial reason=account_unresolved' >&2
            continue
        fi
        if [[ -z "$account" ]]; then
            # find does not follow a linked root: it would list nothing and still
            # exit 0, and the scope would claim complete over a root never read.
            if [[ -L "$root" ]]; then machine_link=true; else machine_roots+=("$root"); fi
        elif (( ${#account} > 128 )) || apps_has_control_char "$account"; then
            print -r -- 'PATCHED_COLLECTION_WARNING section=apps_users status=partial reason=account_invalid' >&2
        else user_roots+=("$root"); user_accounts+=("$account")
        fi
    done
    # A resolved user whose home has no Applications folder has no per-user apps.
    # That is a reading, not a gap: the user is listed complete with no rows, so
    # the server can resolve what it still stores for that home. A home with an
    # Applications entry of any kind is one of the roots above. A home that does
    # not resolve to exactly one account is not listed, and holds no inventory to
    # warn about.
    _apps_scan_homes
    homes=("${reply[@]}")
    for home in "${homes[@]}"; do
        [[ -d "$home" && ! -L "$home" ]] || continue
        [[ -e "$home/Applications" || -L "$home/Applications" ]] && continue
        account=$(_apps_user_account_for_root "$home/Applications") || continue
        [[ -n "$account" ]] || continue
        (( ${#account} > 128 )) && continue
        apps_has_control_char "$account" && continue
        folderless_homes+=("$home"); folderless_accounts+=("$account")
    done
    # Each line of the manifest is JSON, so neither paths nor names are delimiters.
    local i=0
    while (( i <= ${#user_roots} )); do
        account=""
        local -a group_roots
        if (( i == 0 )); then
            group_roots=("${machine_roots[@]}"); user_scope=false
        else
            group_roots=("${user_roots[$i]}"); account="${user_accounts[$i]}"; user_scope=true
        fi
        (( i++ ))
        (( ${#group_roots} > 0 )) || continue
        stub=$(mktemp "$PATCHED_TMPDIR/apps-scope-stub.XXXXXX") || { staging_ok=false; break; }
        print -r -- '[]' > "$stub"
        APPS_JSON_FILE="$stub"
        APPS_COLLECTION_STATUS=unavailable
        if [[ "$user_scope" == true && -L "${group_roots[1]}" ]]; then
            APPS_COLLECTION_STATUS=partial
            print -r -- 'PATCHED_COLLECTION_WARNING section=apps_users status=partial reason=user_link_unreadable' >&2
        else
            local _APPS_USER_SCOPE="$user_scope"
            _apps_collect_roots "${group_roots[@]}"
        fi
        group_status=$(apps_collection_status)
        if [[ "$user_scope" == false ]]; then
            if [[ "$machine_link" == true && "$group_status" == complete ]]; then
                group_status=partial
                print -r -- 'PATCHED_COLLECTION_WARNING section=apps status=partial reason=machine_root_link' >&2
            fi
            machine_status="$group_status"
        elif [[ "$group_status" != complete ]]; then group_status=partial
        fi
        part=$(mktemp "$PATCHED_TMPDIR/apps-scope-rows.XXXXXX") || { staging_ok=false; break; }
        cp "$APPS_JSON_FILE" "$part" || { rm -f "$part"; staging_ok=false; break; }
        # The scope's rows now live in $part; the walk's own output file would
        # otherwise be left behind in the queue directory on every run.
        [[ "$APPS_JSON_FILE" != "$stub" ]] && rm -f "$APPS_JSON_FILE"
        # home is the directory this user's Applications folder was found in, the
        # same string the account was resolved from. Empty for the machine scope.
        home=""
        [[ "$user_scope" == true ]] && home="${group_roots[1]:h}"
        printf '{"file":%s,"user_account":%s,"collection_status":%s,"home":%s}\n' \
            "$(json_escape "$part")" "$(json_escape "$account")" "$(json_escape "$group_status")" \
            "$(json_escape "$home")" >> "$manifest" \
            || { staging_ok=false; break; }
        rm -f "$stub"
    done
    i=1
    while [[ "$staging_ok" == true ]] && (( i <= ${#folderless_homes} )); do
        home="${folderless_homes[$i]}"; account="${folderless_accounts[$i]}"; (( i++ ))
        # Absence of the folder is only known when the home itself can be searched.
        group_status=complete
        if [[ ! -r "$home" || ! -x "$home" ]]; then
            group_status=partial
            print -r -- 'PATCHED_COLLECTION_WARNING section=apps_users status=partial reason=home_unreadable' >&2
        fi
        part=$(mktemp "$PATCHED_TMPDIR/apps-scope-rows.XXXXXX") || { staging_ok=false; break; }
        print -r -- '[]' > "$part" || { rm -f "$part"; staging_ok=false; break; }
        printf '{"file":%s,"user_account":%s,"collection_status":%s,"home":%s}\n' \
            "$(json_escape "$part")" "$(json_escape "$account")" "$(json_escape "$group_status")" \
            "$(json_escape "$home")" >> "$manifest" \
            || { staging_ok=false; break; }
    done
    # No partial manifest is authoritative if staging a scope failed.
    APPS_COLLECTION_STATUS=unavailable
    APPS_USERS_JSON='[]'
    if [[ "$staging_ok" != true ]]; then
        METERING_STATUS=unavailable
        rm -f "$manifest" "$combined" "$states"; return 0
    fi
    "$PYTHON3" - "$manifest" "$combined" "$states" <<'PYSCOPES'
import json, os, sys
rows, users, homes = [], {}, {}
try:
    with open(sys.argv[1]) as source:
        for line in source:
            item = json.loads(line)
            with open(item['file']) as part:
                apps = json.load(part)
            os.unlink(item['file'])
            if not isinstance(apps, list): raise ValueError('invalid app array')
            account, state = item['user_account'], item['collection_status']
            if account:
                users[account] = 'partial' if state != 'complete' or users.get(account) == 'partial' else 'complete'
                if item.get('home'): homes.setdefault(account, set()).add(item['home'])
                for app in apps: app['user_account'] = account
            rows.extend(apps)
    with open(sys.argv[2], 'w') as output: json.dump(rows, output)
    with open(sys.argv[3], 'w') as output:
        # home is sent only when the account was found in exactly one directory:
        # an account resolved from two homes owns neither with certainty.
        json.dump([{'user_account': name, 'collection_status': state,
                    **({'home': next(iter(homes[name]))} if len(homes.get(name, ())) == 1 else {})}
                   for name, state in users.items()], output)
except Exception:
    sys.exit(1)
PYSCOPES
    rc=$?
    if (( rc == 0 )); then
        APPS_JSON_FILE="$combined"
        APPS_USERS_JSON=$(cat "$states")
        APPS_COLLECTION_STATUS="$machine_status"
    else
        rm -f "$combined"
        print -r -- 'PATCHED_COLLECTION_WARNING section=apps status=unavailable reason=scope_merge_failed' >&2
    fi
    rm -f "$manifest" "$states"
}
