#!/bin/zsh
##############################################################################
# test-sectools.zsh — unit tests for the third-party AV / EDR detection
# collector (collect_sectools) in sectools.sh (PAT-1696).
#
# Sources the live functions out of common.sh (json_escape) and sectools.sh
# (no top-level side effects at source time) so the tests exercise the real
# code, not a copy. Detection is a bare `[[ -e <absolute path> ]]` test, and
# a file test cannot be shadowed the way a command can. So the boundary here
# is the candidate path list: _check_for_tool is wrapped (the real function
# is kept under another name and still does the existence test and the JSON
# emit) and every candidate path is re-rooted under a scratch fixture tree.
# The real tool table in collect_sectools (ids, names, candidate paths) is
# what runs, and nothing on the runner's own filesystem can change a result.
# The second basis (PAT-2234, Team ID from Endpoint Security system
# extensions) reads "$_SECTOOLS_SYSEXTCTL list", which every case points at a
# fixture script (fake_sysextctl), so the runner's own extensions never leak in.
#
# KNOWN-GAP checks record current behaviour that breaks the "absent evidence
# is never a pass" rule. They pass today and FAIL LOUDLY if the behaviour
# changes, so a fix must update the assertion in the same change. The gaps
# left here cannot close in the collector alone: payload.schema.json fixes
# security_tools items to {id, name} (additionalProperties: false) and makes
# the array required, so there is no field for a health state and no way to
# say "could not check". PAT-1710 added the reason to the collector log. Run:
#   zsh macos/lib/test-sectools.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/sectools.sh"

pass=0; fail=0; gaps=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}
# chk_known_gap <desc> <current-behaviour> <actual>
chk_known_gap() {
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); (( gaps++ )); echo "  KNOWN-GAP: $desc"
    else (( fail++ )); echo "  FAIL: KNOWN-GAP behaviour changed, update this assertion: $desc -> got=$got was=$exp"; fi
}

# st <python-expr over d> -> evaluated against the current SECURITY_TOOLS_JSON_TMP
st() {
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
print($1)
" "$SECURITY_TOOLS_JSON_TMP" 2>/dev/null || echo "JSON_ERROR"
}

# ── Boundary: re-root candidate paths under FIXTURE_ROOT ───────────────────
functions[_real_check_for_tool]=$functions[_check_for_tool]
CHECKED_IDS=()
_check_for_tool() {
    local id="$1" name="$2"
    shift 2
    local -a rerooted
    local candidate
    for candidate in "$@"; do rerooted+=("$FIXTURE_ROOT$candidate"); done
    CHECKED_IDS+=("$id")
    _real_check_for_tool "$id" "$name" "${rerooted[@]}"
}

# ── Boundary: systemextensionsctl (PAT-2234) ────────────────────────────────
# collect_sectools runs "$_SECTOOLS_SYSEXTCTL list". Every case points it at a
# fake that prints a fixture and exits with a chosen status, so the runner's
# own system extensions (tenant-zero has Bitdefender's) never reach a result.
# fake_sysextctl <exit-status> <fixture-text>
fake_sysextctl() {
    local rc="$1" text="$2"
    print -r -- "$text" > "$FIXTURE_ROOT/sysextctl.out"
    cat > "$FIXTURE_ROOT/sysextctl" <<EOF
#!/bin/zsh
[[ "\$1" == "list" ]] || exit 64
cat "$FIXTURE_ROOT/sysextctl.out"
echo "fixture stderr" >&2
exit $rc
EOF
    chmod 755 "$FIXTURE_ROOT/sysextctl"
    _SECTOOLS_SYSEXTCTL="$FIXTURE_ROOT/sysextctl"
}
NO_SYSEXTS='0 extension(s)'

run_case() {
    PATCHED_TMPDIR=$(mktemp -d)
    CHECKED_IDS=()
    collect_sectools
}

new_root() {
    FIXTURE_ROOT=$(mktemp -d)
    fake_sysextctl 0 "$NO_SYSEXTS"
}
plant_dir()  { mkdir -p "$FIXTURE_ROOT$1"; }
plant_file() { mkdir -p "$FIXTURE_ROOT${1:h}"; print -r -- "fixture" > "$FIXTURE_ROOT$1"; }

##############################################################################
# 1. No supported tool installed: empty array, every tool in the table was
#    checked.
##############################################################################
echo "--- 1. No tools present"

new_root
run_case

chk_eq "output is valid JSON array" "list" "$(st 'type(d).__name__')"
chk_eq "no tools reported" "0" "$(st 'len(d)')"
chk_eq "all 10 table entries checked" "10" "${#CHECKED_IDS[@]}"
chk_eq "table order" "crowdstrike-falcon sentinelone sophos-endpoint defender-for-endpoint jamf-protect huntress malwarebytes carbon-black bitdefender eset-endpoint" "${CHECKED_IDS[*]}"

##############################################################################
# 2. One tool present via its first candidate path.
##############################################################################
echo "--- 2. Tool present (first candidate path)"

new_root
plant_dir "/Applications/Falcon.app/Contents"
run_case

chk_eq "one tool reported" "1" "$(st 'len(d)')"
chk_eq "id" "crowdstrike-falcon" "$(st 'd[0]["id"]')"
chk_eq "name" "CrowdStrike Falcon" "$(st 'd[0]["name"]')"

##############################################################################
# 3. Present via a later candidate only, and via two candidates at once:
#    reported exactly once either way.
##############################################################################
echo "--- 3. Tool present (later candidate, and both candidates)"

new_root
plant_file "/Library/CS/falconctl"
run_case
chk_eq "later candidate detected" "crowdstrike-falcon" "$(st '",".join(t["id"] for t in d)')"

new_root
plant_dir "/Applications/Falcon.app"
plant_file "/Library/CS/falconctl"
run_case
chk_eq "two matching candidates -> one entry" "1" "$(st 'len(d)')"

##############################################################################
# 4. Several tools, including candidate paths containing spaces.
##############################################################################
echo "--- 4. Multiple tools, paths with spaces"

new_root
plant_dir "/Library/Sophos Anti-Virus"
plant_dir "/Library/Application Support/Microsoft/Defender"
plant_dir "/Applications/ESET Endpoint Security.app"
plant_dir "/Library/Application Support/Huntress"
run_case

chk_eq "four tools reported in table order" "sophos-endpoint,defender-for-endpoint,huntress,eset-endpoint" \
    "$(st '",".join(t["id"] for t in d)')"
chk_eq "display name with spaces" "Microsoft Defender for Endpoint" "$(st 'd[1]["name"]')"

##############################################################################
# 5. Present but unhealthy. The collector has no health state: an entry is
#    only {id, name}. An empty leftover directory (typical after a partial
#    uninstall) produces exactly the entry a working install does, so
#    "present and unhealthy" cannot be told from "present and healthy".
##############################################################################
echo "--- 5. Present-and-healthy vs present-and-unhealthy"

new_root
plant_file "/usr/local/bin/sentinelctl"
plant_dir "/Applications/SentinelOne/SentinelOne Extensions.app/Contents/MacOS"
plant_dir "/Library/Sentinel/sentinel-agent"
run_case
HEALTHY=$(cat "$SECURITY_TOOLS_JSON_TMP")
chk_eq "installed SentinelOne reported" "sentinelone" "$(st 'd[0]["id"]')"

new_root
plant_dir "/Library/Sentinel"
run_case
chk_known_gap "per-tool keys are only id,name: no health or running state (_emit_tool; contract has no field)" \
    "id,name" "$(st '",".join(sorted(d[0].keys()))')"
chk_known_gap "empty leftover /Library/Sentinel is byte-identical to a full install (_check_for_tool presence test)" \
    "$HEALTHY" "$(cat "$SECURITY_TOOLS_JSON_TMP")"

##############################################################################
# 6. Absent vs could-not-check. A candidate inside a directory the collector
#    cannot search yields `[[ -e ]]` false, and the tool is simply omitted:
#    identical to a machine where it is genuinely absent. No undetermined
#    state exists in the payload; the reason is logged to stderr. (Root
#    ignores directory permissions, so this case needs a non-root runner;
#    GitHub macOS runners are non-root.)
##############################################################################
echo "--- 6. Absent vs unreadable"

SECTOOLS_ERR=$(mktemp)
new_root
run_case 2> "$SECTOOLS_ERR"
ABSENT=$(cat "$SECURITY_TOOLS_JSON_TMP")
chk_eq "genuinely absent tools log no warning" "0" "$(wc -l < "$SECTOOLS_ERR" | tr -d ' ')"

if (( EUID == 0 )); then
    echo "  SKIP: running as root, directory permissions cannot hide a path"
else
    new_root
    plant_file "/Library/CS/falconctl"
    chmod 000 "$FIXTURE_ROOT/Library/CS"
    run_case 2> "$SECTOOLS_ERR"
    chmod 755 "$FIXTURE_ROOT/Library/CS"
    chk_known_gap "unsearchable install dir reported byte-identical to 'no tools' (contract has no undetermined state)" \
        "$ABSENT" "$(cat "$SECURITY_TOOLS_JSON_TMP")"
    chk_eq "unsearchable install dir logs absence undetermined with the blocking dir" "1" \
        "$(grep -F -c -- "sectools: crowdstrike-falcon absence undetermined, cannot search $FIXTURE_ROOT/Library/CS" "$SECTOOLS_ERR")"
    chk_eq "only the blocked tool warns" "1" "$(wc -l < "$SECTOOLS_ERR" | tr -d ' ')"
fi

##############################################################################
# 7. Team ID detection from signed system extensions (PAT-2234).
#    The fixtures are real `systemextensionsctl list` output shapes from
#    macOS 26 (tenant-zero, 2026-09-28): category headers, then
#    enabled/active markers, Team ID, bundle ID (version), name, [state].
#    A seeded vendor is reported only for an enabled, active Endpoint
#    Security extension; no candidate path is planted in these cases.
##############################################################################
echo "--- 7. System extension Team ID detection"

TAB=$'\t'
BD_ES_ROW="*${TAB}*${TAB}GUNFMW623Y${TAB}com.bitdefender.agentui.sp (1.7.2/1.7.2.433)${TAB}Bitdefender.SPSE${TAB}[activated enabled]"
ES_HDR="--- com.apple.system_extension.endpoint_security (Go to 'System Settings > General > Login Items & Extensions > Endpoint Security Extensions' to modify these system extension(s))"
NE_HDR="--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))"
COL_HDR="enabled${TAB}active${TAB}teamID${TAB}bundleID (version)${TAB}name${TAB}[state]"
TS_NE_ROW="*${TAB}*${TAB}W5364U7YZB${TAB}io.tailscale.ipn.macsys.network-extension (1.102.4/101.102.4)${TAB}Tailscale Network Extension${TAB}[activated enabled]"
TENANT_ZERO="3 extension(s)
$NE_HDR
$COL_HDR
$TS_NE_ROW
*${TAB}*${TAB}4P645293E8${TAB}com.ui.uid.standard-desktop.network-extension (0.0.18/1)${TAB}IdentityWireGuardProvider${TAB}[activated enabled]
$ES_HDR
$COL_HDR
$BD_ES_ROW"

# 7a. Seed table is exactly what the platform baseline is aligned to
#     (patched.im migration 0212_protected_software_bitdefender.sql seeds
#     team_id GUNFMW623Y with product_name "Bitdefender"). Changing a row here
#     means changing that baseline in the same change.
chk_eq "seeded Team ID table" "GUNFMW623Y${TAB}bitdefender${TAB}Bitdefender" "$(_sectools_team_ids)"

# 7b. Tenant-zero's real output: Bitdefender reported from its ES extension.
new_root
fake_sysextctl 0 "$TENANT_ZERO"
run_case 2> "$SECTOOLS_ERR"
chk_eq "Bitdefender ES extension (GUNFMW623Y) detected with no install path" "bitdefender" "$(st '",".join(t["id"] for t in d)')"
chk_eq "Bitdefender display name" "Bitdefender" "$(st 'd[0]["name"]')"
chk_eq "Bitdefender entry keeps the contract shape {id,name}" "id,name" "$(st '",".join(sorted(d[0].keys()))')"
chk_eq "a clean read logs no sectools warning" "0" "$(grep -c 'sectools:' "$SECTOOLS_ERR")"

# 7c. Found by both path and Team ID: reported once.
new_root
plant_dir "/Library/Bitdefender/AVP"
fake_sysextctl 0 "$TENANT_ZERO"
run_case
chk_eq "path + Team ID -> one bitdefender entry" "bitdefender" "$(st '",".join(t["id"] for t in d)')"

# 7d. Same Team ID in another category (Bitdefender VPN ships a network
#     extension under GUNFMW623Y): vendor presence is not malware protection.
new_root
fake_sysextctl 0 "1 extension(s)
$NE_HDR
$COL_HDR
*${TAB}*${TAB}GUNFMW623Y${TAB}com.bitdefender.vpn.ne (5.0/5.0)${TAB}Bitdefender VPN${TAB}[activated enabled]"
run_case
chk_eq "seeded Team ID outside endpoint_security is not reported" "0" "$(st 'len(d)')"

# 7e. Endpoint Security extension present but not running: not reported, and
#     the reason is logged so the evidence is not silently dropped.
for NOT_RUNNING in \
    "*${TAB}-${TAB}GUNFMW623Y${TAB}com.bitdefender.agentui.sp (1.7.2/1.7.2.433)${TAB}Bitdefender.SPSE${TAB}[activated waiting for user]" \
    "-${TAB}-${TAB}GUNFMW623Y${TAB}com.bitdefender.agentui.sp (1.7.2/1.7.2.433)${TAB}Bitdefender.SPSE${TAB}[terminated waiting to uninstall on reboot]" \
    "*${TAB}*${TAB}GUNFMW623Y${TAB}com.bitdefender.agentui.sp (1.7.2/1.7.2.433)${TAB}Bitdefender.SPSE${TAB}[activated disabled]"; do
    new_root
    fake_sysextctl 0 "1 extension(s)
$ES_HDR
$COL_HDR
$NOT_RUNNING"
    run_case 2> "$SECTOOLS_ERR"
    chk_eq "inactive ES extension not reported (${NOT_RUNNING##*\[}" "0" "$(st 'len(d)')"
    chk_eq "inactive ES extension logged" "1" "$(grep -c 'sectools: bitdefender endpoint security extension GUNFMW623Y is not running' "$SECTOOLS_ERR")"
done

# 7f. An ES extension from an unseeded Team ID is not guessed into a tool, but
#     is logged so it can be seeded from evidence.
new_root
fake_sysextctl 0 "1 extension(s)
$ES_HDR
$COL_HDR
*${TAB}*${TAB}ZZZZZZZZZ9${TAB}com.example.es (1.0/1)${TAB}Example ES${TAB}[activated enabled]"
run_case 2> "$SECTOOLS_ERR"
chk_eq "unseeded ES Team ID not reported" "0" "$(st 'len(d)')"
chk_eq "unseeded ES Team ID logged" "1" "$(grep -c 'sectools: unrecognised endpoint security extension ZZZZZZZZZ9 com.example.es' "$SECTOOLS_ERR")"

##############################################################################
# 8. A failed or unreadable systemextensionsctl read is undetermined, never
#    "no security tools". The contract has no field for it (security_tools
#    items are {id, name}, additionalProperties false), so the path table
#    still runs and the reason goes to the collector log, as PAT-1710 does
#    for an unsearchable directory.
##############################################################################
echo "--- 8. Failed system extension reads"

# 8a. Non-zero exit (e.g. sysextd unreachable), even with Bitdefender rows on
#     stdout: nothing from that read is trusted.
new_root
plant_dir "/Library/Sophos Anti-Virus"
fake_sysextctl 1 "$TENANT_ZERO"
run_case 2> "$SECTOOLS_ERR"
chk_eq "failed read: path detection still runs" "sophos-endpoint" "$(st '",".join(t["id"] for t in d)')"
chk_eq "failed read logs Team ID detection undetermined" "1" "$(grep -c 'sectools: system extension read failed (exit 1), Team ID detection undetermined' "$SECTOOLS_ERR")"

# 8b. Binary missing.
new_root
_SECTOOLS_SYSEXTCTL="$FIXTURE_ROOT/no-such-systemextensionsctl"
run_case 2> "$SECTOOLS_ERR"
chk_eq "missing systemextensionsctl: valid empty array" "0" "$(st 'len(d)')"
chk_eq "missing systemextensionsctl logs undetermined" "1" "$(grep -c 'sectools: system extension read failed (not executable), Team ID detection undetermined' "$SECTOOLS_ERR")"

# 8c. Exit 0 but output this parser cannot read: the count line says there
#     are extensions and no row parsed.
new_root
fake_sysextctl 0 "1 extension(s)
$ES_HDR
GUNFMW623Y com.bitdefender.agentui.sp some future layout"
run_case 2> "$SECTOOLS_ERR"
chk_eq "unparseable output: nothing reported" "0" "$(st 'len(d)')"
chk_eq "unparseable output logs undetermined" "1" "$(grep -c 'sectools: system extension output unparseable, Team ID detection undetermined' "$SECTOOLS_ERR")"

# 8d. Exit 0 with no count line at all (empty stdout).
new_root
fake_sysextctl 0 ""
run_case 2> "$SECTOOLS_ERR"
chk_eq "empty output logs undetermined" "1" "$(grep -c 'sectools: system extension output unparseable, Team ID detection undetermined' "$SECTOOLS_ERR")"

# 8e. Rows with no category header (an older layout): the category cannot be
#     read, so a seeded Team ID is not reported and the gap is logged.
new_root
fake_sysextctl 0 "1 extension(s)
$COL_HDR
$BD_ES_ROW"
run_case 2> "$SECTOOLS_ERR"
chk_eq "row with no category header not reported" "0" "$(st 'len(d)')"
chk_eq "row with no category header logged" "1" "$(grep -c 'sectools: system extension category not stated for GUNFMW623Y, Team ID detection undetermined' "$SECTOOLS_ERR")"

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
