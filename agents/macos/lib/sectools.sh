# sectools.sh — third-party security tool detection (AV / EDR).
# Sets SECURITY_TOOLS_JSON_TMP (path to the temp JSON array file).
# The temp file is consumed by the main script's JSON assembly and cleaned up
# after the heredoc runs.
# Sourced by patched-collect.sh; not executable directly.
#
# Two detection bases, both emitting the same {id, name} entries (the payload
# contract has no other field):
#   1. The path table in collect_sectools (presence of known install paths).
#   2. PAT-2234: signed Endpoint Security system extensions, by Apple Team ID,
#      from `systemextensionsctl list`. macOS only activates a system extension
#      that is Developer ID signed and notarised, and sysextd reports the
#      Team ID from that signature, so this is signing identity rather than a
#      path anyone could create. See _sectools_team_ids for the seed table.

# The command collect_sectools reads system extensions from. Absolute path:
# sudo strips PATH on macOS. Tests point it at a fixture.
_SECTOOLS_SYSEXTCTL="/usr/bin/systemextensionsctl"

# _sectools_team_ids
# Prints the seeded Team ID table, one "<TEAMID>\t<id>\t<name>" row per vendor.
# A vendor is only seeded from evidence: a Developer ID signature inspected
# with `codesign -dv` on a real install, chained to Apple's root. Never from
# memory or a vendor web page alone. Only vendors whose Team ID signs nothing
# but security products are listed; a shared Team ID (Microsoft's UBF8T346G9
# signs Office, Edge and Defender alike) would turn "vendor present" into a
# false coverage claim, and those stay on the path table.
#   GUNFMW623Y  Bitdefender SRL. tenant-zero 2026-09-28: AntivirusforMac.app,
#               BitdefenderAgent.app and CoreSecurity.app all carry
#               "Developer ID Application: Bitdefender SRL (GUNFMW623Y)" and
#               pass `codesign --verify -R '=anchor apple generic and
#               certificate leaf[subject.OU] = "GUNFMW623Y"'`; the ES extension
#               is com.bitdefender.agentui.sp. Bitdefender VPN.app is signed
#               by the same team, which is why only an Endpoint Security
#               extension counts (a VPN ships a network extension).
# Keep the id and name equal to an existing path-table entry so both bases
# report one tool, and keep every row aligned with the platform's
# protected_software baseline (patched.im migration
# 0212_protected_software_bitdefender.sql: team_id GUNFMW623Y, product_name
# "Bitdefender"), which matches reported tools by name. test-sectools.zsh
# pins this table so a change here is a deliberate one.
_sectools_team_ids() {
    printf '%s\t%s\t%s\n' "GUNFMW623Y" "bitdefender" "Bitdefender"
}

_emit_tool() {
    local id="$1"
    local name="$2"
    # One entry per id, whichever detection basis found it first.
    if (( ${_SECTOOLS_EMITTED[(Ie)$id]} )); then
        return
    fi
    _SECTOOLS_EMITTED+=("$id")
    if [[ "$_SECTOOLS_FIRST" == "false" ]]; then
        echo "," >> "$SECURITY_TOOLS_JSON_TMP"
    fi
    _SECTOOLS_FIRST=false
    cat >> "$SECURITY_TOOLS_JSON_TMP" <<EOF
{"id": $(json_escape "$id"), "name": $(json_escape "$name")}
EOF
}

# _sectools_blocked_ancestor <candidate>
# Sets _SECTOOLS_BLOCKED to the nearest existing ancestor directory of
# <candidate> when that directory cannot be searched (so `[[ -e ]]` on the
# candidate proves nothing), else to empty.
_sectools_blocked_ancestor() {
    local dir="${1:h}"
    while [[ "$dir" != "/" && ! -e "$dir" ]]; do dir="${dir:h}"; done
    if [[ -d "$dir" && ! -x "$dir" ]]; then _SECTOOLS_BLOCKED="$dir"; else _SECTOOLS_BLOCKED=""; fi
}

_check_for_tool() {
    local id="$1"
    local name="$2"
    shift 2
    # NB: do NOT name this loop variable "path" — in zsh, `path` is tied to
    # the PATH array via `typeset -T PATH path`. Assigning to it silently
    # corrupts PATH for the rest of the script, breaking every external
    # command lookup downstream.
    local candidate
    for candidate in "$@"; do
        if [[ -e "$candidate" ]]; then
            _emit_tool "$id" "$name"
            return
        fi
    done
    # Not found. If a candidate sits under a directory the collector cannot
    # search, the tool's absence is undetermined, not proven. The payload
    # contract (security_tools items are {id, name} only) has no way to say
    # so, so the reason goes to the collector log (PAT-1710).
    for candidate in "$@"; do
        _sectools_blocked_ancestor "$candidate"
        if [[ -n "$_SECTOOLS_BLOCKED" ]]; then
            log_warn "sectools: $id absence undetermined, cannot search $_SECTOOLS_BLOCKED"
            return
        fi
    done
}

# _sectools_sysext_scan
# Emits a tool for every seeded Team ID with an enabled, active Endpoint
# Security system extension. A read that fails, or output this parser cannot
# account for, is undetermined: the payload has no field for that (items are
# {id, name}, additionalProperties false), so it is never turned into "no
# tools"; the path table still runs and the reason goes to the collector log,
# as PAT-1710 does for an unsearchable directory.
_sectools_sysext_scan() {
    local out_file err_file parsed_file rc kind team rest
    local -A seeded_id seeded_name
    local row_team row_id row_name
    while IFS=$'\t' read -r row_team row_id row_name; do
        [[ -n "$row_team" ]] || continue
        seeded_id[$row_team]="$row_id"
        seeded_name[$row_team]="$row_name"
    done < <(_sectools_team_ids)

    if [[ ! -x "$_SECTOOLS_SYSEXTCTL" ]]; then
        log_warn "sectools: system extension read failed (not executable), Team ID detection undetermined"
        return
    fi
    out_file=$(mktemp "$PATCHED_TMPDIR/sectools-sysext.XXXXXX") || { log_warn "sectools: system extension read failed (no temp file), Team ID detection undetermined"; return; }
    err_file=$(mktemp "$PATCHED_TMPDIR/sectools-sysext-err.XXXXXX") || { rm -f "$out_file"; log_warn "sectools: system extension read failed (no temp file), Team ID detection undetermined"; return; }
    parsed_file=$(mktemp "$PATCHED_TMPDIR/sectools-sysext-parsed.XXXXXX") || { rm -f "$out_file" "$err_file"; log_warn "sectools: system extension read failed (no temp file), Team ID detection undetermined"; return; }
    "$_SECTOOLS_SYSEXTCTL" list > "$out_file" 2> "$err_file"
    rc=$?
    if (( rc != 0 )); then
        log_warn "sectools: system extension read failed (exit $rc), Team ID detection undetermined: $(head -c 200 "$err_file" | tr -d '\000-\037')"
        rm -f "$out_file" "$err_file" "$parsed_file"
        return
    fi

    # Data goes to python through a file argument, never a pipe alongside the
    # heredoc program (footgun: the pipe would become python's program).
    "$PYTHON3" - "$out_file" ${(k)seeded_id} > "$parsed_file" <<'PYEOF'
import re, sys
ES = "com.apple.system_extension.endpoint_security"
seeded = set(sys.argv[2:])
team_re = re.compile(r'^[A-Z0-9]{10}$')
row_re = re.compile(r'^([*\-])\s+([*\-])\s+(\S+)\s+(\S+)\s+\(([^)]+)\)\s+(.+?)\s*\[(.+?)\]\s*$')
def safe(s):
    return re.sub(r'[^A-Za-z0-9._ -]', '?', s)[:120]
count = None
category = None
rows = 0
try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            m = re.match(r'^(\d+) extension\(s\)$', line)
            if m:
                count = int(m.group(1))
                continue
            m = re.match(r'^--- (\S+)', line)
            if m:
                category = m.group(1)
                continue
            m = row_re.match(line)
            if not m:
                continue
            enabled, active, team, bundle, _ver, _name, state = m.groups()
            if not team_re.match(team):
                continue
            rows += 1
            if category is None:
                if team in seeded:
                    print("nocategory\t%s" % team)
                continue
            if category != ES:
                continue
            if team in seeded:
                if enabled == "*" and active == "*" and state.strip() == "activated enabled":
                    print("match\t%s" % team)
                else:
                    print("inactive\t%s\t%s" % (team, safe(state)))
            else:
                print("unrecognised\t%s\t%s" % (team, safe(bundle)))
except Exception:
    count = None
print("status\t%s" % ("ok" if count is not None and count == rows else "unparseable"))
PYEOF
    rc=$?
    if (( rc != 0 )); then
        log_warn "sectools: system extension output unparseable, Team ID detection undetermined"
        rm -f "$out_file" "$err_file" "$parsed_file"
        return
    fi

    local saw_status=false
    while IFS=$'\t' read -r kind team rest; do
        case "$kind" in
            match)
                [[ -n "${seeded_id[$team]:-}" ]] && _emit_tool "${seeded_id[$team]}" "${seeded_name[$team]}"
                ;;
            inactive)
                log_warn "sectools: ${seeded_id[$team]:-unknown} endpoint security extension $team is not running ($rest), not reported"
                ;;
            unrecognised)
                log_warn "sectools: unrecognised endpoint security extension $team $rest, not reported (seed its Team ID from evidence)"
                ;;
            nocategory)
                log_warn "sectools: system extension category not stated for $team, Team ID detection undetermined"
                ;;
            status)
                saw_status=true
                [[ "$team" == "ok" ]] || log_warn "sectools: system extension output unparseable, Team ID detection undetermined"
                ;;
        esac
    done < "$parsed_file"
    [[ "$saw_status" == "true" ]] || log_warn "sectools: system extension output unparseable, Team ID detection undetermined"
    rm -f "$out_file" "$err_file" "$parsed_file"
}

collect_sectools() {
    SECURITY_TOOLS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/sectools.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    _SECTOOLS_FIRST=true
    _SECTOOLS_EMITTED=()
    echo "[" > "$SECURITY_TOOLS_JSON_TMP"

    _check_for_tool "crowdstrike-falcon"     "CrowdStrike Falcon"                  "/Applications/Falcon.app" "/Library/CS/falconctl"
    _check_for_tool "sentinelone"            "SentinelOne"                         "/Applications/SentinelOne/SentinelOne Extensions.app" "/usr/local/bin/sentinelctl" "/Library/Sentinel"
    _check_for_tool "sophos-endpoint"        "Sophos Endpoint"                     "/Library/Sophos Anti-Virus" "/Applications/Sophos Endpoint.app"
    _check_for_tool "defender-for-endpoint"  "Microsoft Defender for Endpoint"     "/Applications/Microsoft Defender.app" "/Library/Application Support/Microsoft/Defender"
    _check_for_tool "jamf-protect"           "Jamf Protect"                        "/Applications/JamfProtect.app" "/Library/Application Support/JamfProtect"
    _check_for_tool "huntress"               "Huntress"                            "/Library/Application Support/Huntress"
    _check_for_tool "malwarebytes"           "Malwarebytes"                        "/Applications/Malwarebytes.app"
    _check_for_tool "carbon-black"           "VMware Carbon Black"                 "/Applications/CbDefense.app"
    _check_for_tool "bitdefender"            "Bitdefender"                         "/Library/Bitdefender/AVP"
    _check_for_tool "eset-endpoint"          "ESET Endpoint Security"              "/Applications/ESET Endpoint Security.app"

    _sectools_sysext_scan

    echo "]" >> "$SECURITY_TOOLS_JSON_TMP"
}
