#!/bin/zsh
##############################################################################
# test-hardware-health.zsh — unit tests for the battery / storage / disk
# health collector (collect_hardware_health) in hardware_health.sh
# (PAT-1696).
#
# Sources the live functions out of hardware_health.sh (no top-level side
# effects at source time) so the tests exercise the real code, not a copy.
# `system_profiler`, `df` and `diskutil` are shadowed with zsh functions of
# the same name before any case runs; zsh resolves a function before an
# external command, so the collector parses fixture text instead of the
# runner's own battery, volumes and disks.
#
# PAT-1720 closed every KNOWN-GAP this file carried: a failed read is now
# reported through hardware_health.collection_status (complete / partial /
# unavailable) instead of collapsing to "no battery", "no volumes" or "no
# disks". chk_known_gap stays for any future gap. Run:
#   zsh macos/lib/test-hardware-health.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/hardware_health.sh"

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

# hh <python-expr over d> -> evaluated against the current HARDWARE_HEALTH_JSON_TMP
hh() {
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
print($1)
" "$HARDWARE_HEALTH_JSON_TMP" 2>/dev/null || echo "JSON_ERROR"
}

# status_of <section> -> hardware_health.collection_status.<section>
status_of() { hh "d[\"collection_status\"][\"$1\"]"; }
# all_statuses -> "battery,storage,disks" statuses in that order
all_statuses() { hh '",".join(d["collection_status"][k] for k in ("battery", "storage", "disks"))'; }

# ── Boundary doubles ───────────────────────────────────────────────────────
# Each MOCK_*_EXIT non-zero means the command failed with no stdout, except
# df with MOCK_DF_PRINT_ON_FAIL=1, which prints MOCK_DF and then fails (what
# df does when one mount, such as a stale network share, cannot be statted).
MOCK_SP_POWER=""; MOCK_SP_EXIT=0
MOCK_DF=""; MOCK_DF_EXIT=0; MOCK_DF_PRINT_ON_FAIL=0
MOCK_DU_LIST=""; MOCK_DU_LIST_EXIT=0
typeset -A MOCK_DU_INFO   # device node (/dev/diskN) -> `diskutil info` text

system_profiler() {
    [[ "$1" == "SPPowerDataType" ]] || return 1
    (( MOCK_SP_EXIT == 0 )) || return "$MOCK_SP_EXIT"
    print -r -- "$MOCK_SP_POWER"
}
df() {
    if (( MOCK_DF_EXIT != 0 )); then
        (( MOCK_DF_PRINT_ON_FAIL )) && print -r -- "$MOCK_DF"
        return "$MOCK_DF_EXIT"
    fi
    print -r -- "$MOCK_DF"
}
diskutil() {
    case "$1" in
        list)
            (( MOCK_DU_LIST_EXIT == 0 )) || return "$MOCK_DU_LIST_EXIT"
            print -r -- "$MOCK_DU_LIST" ;;
        info)
            (( ${+MOCK_DU_INFO[$2]} )) || return 1
            print -r -- "${MOCK_DU_INFO[$2]}" ;;
        *) return 1 ;;
    esac
}

reset_mocks() {
    MOCK_SP_POWER=""; MOCK_SP_EXIT=0
    MOCK_DF=""; MOCK_DF_EXIT=0; MOCK_DF_PRINT_ON_FAIL=0
    MOCK_DU_LIST=""; MOCK_DU_LIST_EXIT=0
    MOCK_DU_INFO=()
}

run_case() {
    PATCHED_TMPDIR=$(mktemp -d)
    # stdout captured, not shown: collect_hardware_health writes only to
    # HARDWARE_HEALTH_JSON_TMP, so anything here is a leak (PAT-1708 was a
    # zsh `local` re-declaration printing `name=value` from inside a loop).
    collect_hardware_health > "$PATCHED_TMPDIR/collector-stdout.log"
}
collector_stdout() { cat "$PATCHED_TMPDIR/collector-stdout.log"; }

# envelope_valid -> "valid" when the whole file is a JSON object carrying all
# four keys and a collection_status whose three values are each a known status.
envelope_valid() {
    "$PYTHON3" -c '
import json, sys
d = json.load(open(sys.argv[1]))
ok = (isinstance(d, dict)
      and sorted(d.keys()) == ["battery", "collection_status", "disks", "storage"]
      and isinstance(d["battery"], dict) and isinstance(d["battery"].get("present"), bool)
      and isinstance(d["storage"], list) and isinstance(d["disks"], list)
      and sorted(d["collection_status"].keys()) == ["battery", "disks", "storage"]
      and all(v in ("complete", "partial", "unavailable") for v in d["collection_status"].values()))
print("valid" if ok else "invalid-shape")
' "$HARDWARE_HEALTH_JSON_TMP" 2>/dev/null || echo "invalid-json"
}

# disks_raw_valid -> "valid" when _hw_disks's own stdout parses as a JSON
# array. Checked separately because collect_hardware_health replaces
# invalid disk JSON with [], which hides corruption from the envelope.
disks_raw_valid() {
    _hw_disks 2>/dev/null | "$PYTHON3" -c '
import json, sys
v = json.loads(sys.stdin.read())
print("valid" if isinstance(v, list) else "not-a-list")
' 2>/dev/null || echo "invalid"
}

# ── Fixture text (shapes taken from macOS 26.6.2 output) ───────────────────
battery_text() {  # battery_text <cycles> <condition> <capacity-line>
    cat <<EOF
Power:

    Battery Information:

      Model Information:
          Device Name: bq40z651
      Charge Information:
          Fully Charged: Yes
      Health Information:
          Cycle Count: $1
          Condition: $2
          $3

    System Power Settings:

      AC Power:
          System Sleep Timer (Minutes): 0
EOF
}

DESKTOP_POWER=$'Power:\n\n    System Power Settings:\n\n      AC Power:\n          System Sleep Timer (Minutes): 0'

DF_TEXT=$(cat <<'EOF'
Filesystem     1024-blocks      Used Available Capacity iused     ifree %iused  Mounted on
/dev/disk3s3s1   482797652  12342736  29622112    30%  458732 296221120    0%   /
devfs                  202       202         0   100%     702         0  100%   /dev
/dev/disk3s6     482797652   5243532  29622112    16%       5 296221120    0%   /System/Volumes/VM
map auto_home            0         0         0   100%       0         0     -   /System/Volumes/Data/home
/dev/disk5s1        100000     75000     25000    75%      10       100    9%   /Volumes/My Backup
EOF
)

# One physical disk plus a synthesized container (which must be ignored).
DU_LIST_TEXT=$(cat <<'EOF'
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.3 GB   disk0
/dev/disk3 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
EOF
)

# Two physical disks (internal + external).
DU_LIST_TWO_TEXT=$(cat <<'EOF'
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
/dev/disk3 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
/dev/disk4 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
EOF
)

disk_info() {  # disk_info <device> <smart-line-or-empty> <internal-lines>
    print -r -- "   Device Identifier:         $1"
    [[ -n "$2" ]] && print -r -- "   SMART Status:              $2"
    print -r -- "$3"
    print -r -- "   Solid State:               Yes"
}

##############################################################################
# 1. Healthy: battery Normal at 96%, verified SMART, real volumes only.
##############################################################################
echo "--- 1. Healthy battery, disks and storage"

reset_mocks
MOCK_SP_POWER=$(battery_text 120 "Normal" "Maximum Capacity: 96%")
MOCK_DF="$DF_TEXT"
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Internal:                  Yes")
run_case

chk_eq "envelope keys" "battery,collection_status,disks,storage" "$(hh '",".join(sorted(d.keys()))')"
chk_eq "envelope valid" "valid" "$(envelope_valid)"
chk_eq "every section complete" "complete,complete,complete" "$(all_statuses)"
chk_eq "battery present" "True" "$(hh 'd["battery"]["present"]')"
chk_eq "cycle_count" "120" "$(hh 'd["battery"]["cycle_count"]')"
chk_eq "condition Normal" "Normal" "$(hh 'd["battery"]["condition"]')"
chk_eq "max_capacity_pct" "96" "$(hh 'd["battery"]["max_capacity_pct"]')"
chk_eq "only the physical disk enumerated" "disk0" "$(hh '",".join(x["device"] for x in d["disks"])')"
chk_eq "SMART Verified" "Verified" "$(hh 'd["disks"][0]["smart_status"]')"
chk_eq "internal disk flagged internal" "True" "$(hh 'd["disks"][0]["internal"]')"
chk_eq "solid_state parsed" "True" "$(hh 'd["disks"][0]["solid_state"]')"
chk_eq "pseudo filesystems excluded" "/,/System/Volumes/VM,/Volumes/My Backup" "$(hh '",".join(x["mount"] for x in d["storage"])')"
chk_eq "root total_bytes" "494384795648" "$(hh 'd["storage"][0]["total_bytes"]')"
chk_eq "mount with spaces used_pct" "75" "$(hh 'd["storage"][2]["used_pct"]')"

##############################################################################
# 2. Degraded: battery Service Recommended at 71%, a failing SMART disk.
##############################################################################
echo "--- 2. Degraded battery and failing disk"

reset_mocks
MOCK_SP_POWER=$(battery_text 1104 "Service Recommended" "Maximum Capacity: 71 %")
MOCK_DF="$DF_TEXT"
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Failing" "   Internal:                  No")
run_case

chk_eq "condition Service Recommended" "Service Recommended" "$(hh 'd["battery"]["condition"]')"
chk_eq "max_capacity_pct 71 (space before %)" "71" "$(hh 'd["battery"]["max_capacity_pct"]')"
chk_eq "cycle_count 1104" "1104" "$(hh 'd["battery"]["cycle_count"]')"
chk_eq "SMART Failing reported verbatim" "Failing" "$(hh 'd["disks"][0]["smart_status"]')"
chk_eq "Internal: No -> internal false" "False" "$(hh 'd["disks"][0]["internal"]')"

##############################################################################
# 3. Field missing from system_profiler output: the battery section exists
#    but Condition and Maximum Capacity lines do not. Those fields must be
#    null (undetermined), never a healthy default.
##############################################################################
echo "--- 3. Battery fields missing from system_profiler output"

reset_mocks
MOCK_SP_POWER=$'Power:\n\n    Battery Information:\n\n      Health Information:\n          Cycle Count: 55\n'
run_case

chk_eq "battery present" "True" "$(hh 'd["battery"]["present"]')"
chk_eq "cycle_count still parsed" "55" "$(hh 'd["battery"]["cycle_count"]')"
chk_eq "missing condition -> null" "None" "$(hh 'd["battery"]["condition"]')"
chk_eq "missing max capacity -> null" "None" "$(hh 'd["battery"]["max_capacity_pct"]')"
chk_eq "system_profiler succeeded: battery complete (nulls are per-field unknowns)" "complete" "$(status_of battery)"

##############################################################################
# 4. Missing input: system_profiler, df and diskutil all fail. Output stays
#    valid JSON, and each section is marked unavailable, so the placeholder
#    value is never read as a machine with no battery, volumes or disks.
##############################################################################
echo "--- 4. Collector inputs missing or failing"

reset_mocks
MOCK_SP_POWER="$DESKTOP_POWER"
run_case
DESKTOP_BATTERY=$(hh 'json.dumps(d["battery"], sort_keys=True)')
chk_eq "desktop (no battery section) -> present false" "False" "$(hh 'd["battery"]["present"]')"
chk_eq "desktop with no battery, system_profiler succeeded -> battery complete" "complete" "$(status_of battery)"
chk_eq "desktop envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_SP_EXIT=1; MOCK_DF_EXIT=1; MOCK_DU_LIST_EXIT=1
run_case
chk_eq "failed inputs still produce valid JSON" "battery,collection_status,disks,storage" "$(hh '",".join(sorted(d.keys()))')"
chk_eq "failed inputs: envelope valid" "valid" "$(envelope_valid)"
chk_eq "system_profiler failure -> battery unavailable, not a desktop's complete" \
    "unavailable" "$(status_of battery)"
chk_eq "system_profiler failure -> schema-valid placeholder battery" \
    "$DESKTOP_BATTERY" "$(hh 'json.dumps(d["battery"], sort_keys=True)')"
chk_eq "df failure -> storage unavailable" "unavailable" "$(status_of storage)"
chk_eq "df failure -> storage []" "[]" "$(hh 'json.dumps(d["storage"])')"
chk_eq "diskutil list failure -> disks unavailable" "unavailable" "$(status_of disks)"
chk_eq "diskutil list failure -> disks []" "[]" "$(hh 'json.dumps(d["disks"])')"
chk_eq "failed inputs: collector wrote nothing to stdout" "" "$(collector_stdout)"

# Each failure on its own, so one section's status cannot mask another's.
reset_mocks
MOCK_SP_EXIT=1; MOCK_DF="$DF_TEXT"; MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Internal:                  Yes")
run_case
chk_eq "only system_profiler fails: statuses" "unavailable,complete,complete" "$(all_statuses)"
chk_eq "only system_profiler fails: envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_SP_POWER="$DESKTOP_POWER"; MOCK_DF_EXIT=1; MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Internal:                  Yes")
run_case
chk_eq "only df fails: statuses" "complete,unavailable,complete" "$(all_statuses)"
chk_eq "only df fails: envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_SP_POWER="$DESKTOP_POWER"; MOCK_DF="$DF_TEXT"; MOCK_DU_LIST_EXIT=1
run_case
chk_eq "only diskutil list fails: statuses" "complete,complete,unavailable" "$(all_statuses)"
chk_eq "only diskutil list fails: envelope valid" "valid" "$(envelope_valid)"

# system_profiler exiting 0 with no output at all is not a desktop either.
reset_mocks
MOCK_SP_POWER=""
run_case
chk_eq "system_profiler succeeded but printed nothing -> battery unavailable" "unavailable" "$(status_of battery)"

# df lists the mounts it could stat and exits non-zero when one fails.
reset_mocks
MOCK_DF="$DF_TEXT"; MOCK_DF_EXIT=1; MOCK_DF_PRINT_ON_FAIL=1
run_case
chk_eq "df exits non-zero with rows -> storage partial" "partial" "$(status_of storage)"
chk_eq "df exits non-zero with rows -> rows it did list are sent" \
    "/,/System/Volumes/VM,/Volumes/My Backup" "$(hh '",".join(x["mount"] for x in d["storage"])')"
chk_eq "df partial: envelope valid" "valid" "$(envelope_valid)"

# A /dev/ row that does not parse is left out and the section is partial.
reset_mocks
MOCK_DF="$DF_TEXT"$'\n/dev/disk7s1   garbled   rows'$'\n/dev/disk8s1   notanumber   1   2   50%   1   2   0%   /Volumes/Odd'
run_case
chk_eq "unparseable /dev/ rows -> storage partial" "partial" "$(status_of storage)"
chk_eq "unparseable /dev/ rows left out, good rows kept" \
    "/,/System/Volumes/VM,/Volumes/My Backup" "$(hh '",".join(x["mount"] for x in d["storage"])')"

##############################################################################
# 5. Disk fields missing from diskutil output. An explicit "Not Supported"
#    is reported verbatim; a missing SMART line is "Undetermined", never
#    "Not Supported". A disk missing a field its row requires (identifier,
#    internal, solid state) is left out and the section is partial.
#    macOS 26 `diskutil info` prints "Device Location: Internal" with no
#    "Internal:" line; the parser falls back to it (PAT-1708).
##############################################################################
echo "--- 5. Disk fields missing from diskutil output"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Not Supported" "   Internal:                  Yes")
run_case
EXPLICIT_NOT_SUPPORTED=$(hh 'd["disks"][0]["smart_status"]')
chk_eq "explicit Not Supported reported" "Not Supported" "$EXPLICIT_NOT_SUPPORTED"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "" "   Internal:                  Yes")
run_case
chk_eq "missing SMART line -> Undetermined, not 'Not Supported'" \
    "Undetermined" "$(hh 'd["disks"][0]["smart_status"]')"
chk_eq "missing SMART line: disk still sent, section complete" "disk0 complete" \
    "$(hh 'd["disks"][0]["device"] + " " + d["collection_status"]["disks"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$'   Device Identifier:         disk0\n   SMART Status:              Verified\n   Solid State:               Yes'
run_case
chk_eq "no Internal: and no Device Location: line -> disk left out, not internal=false" \
    "[] partial" "$(hh 'json.dumps(d["disks"]) + " " + d["collection_status"]["disks"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$'   Device Identifier:         disk0\n   SMART Status:              Verified\n   Device Location:           Internal'
run_case
chk_eq "no Solid State: line -> disk left out, not solid_state=false" \
    "[] partial" "$(hh 'json.dumps(d["disks"]) + " " + d["collection_status"]["disks"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$'   SMART Status:              Verified\n   Device Location:           Internal\n   Solid State:               Yes'
run_case
chk_eq "no Device Identifier: line -> disk left out, not device=\"\"" \
    "[] partial" "$(hh 'json.dumps(d["disks"]) + " " + d["collection_status"]["disks"]')"
chk_eq "missing disk fields: envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Device Location:           Internal")
run_case
chk_eq "macOS 26 'Device Location: Internal' (no 'Internal:' line) -> internal true" \
    "True" "$(hh 'd["disks"][0]["internal"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Device Location:           External")
run_case
chk_eq "macOS 26 'Device Location: External' -> internal false" \
    "False" "$(hh 'd["disks"][0]["internal"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" $'   Device Location:           Internal\n   Internal:                  No')
run_case
chk_eq "explicit 'Internal:' line wins over 'Device Location'" \
    "False" "$(hh 'd["disks"][0]["internal"]')"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" $'   Internal:   \n   Device Location:           Internal')
run_case
chk_eq "empty 'Internal:' value falls back to 'Device Location: Internal'" \
    "True" "$(hh 'd["disks"][0]["internal"]')"

##############################################################################
# 6. Multiple physical disks (PAT-1708). zsh re-running `local info` /
#    `local entry` on a second loop iteration printed the previous value
#    into _hw_disks's stdout, corrupting the array so the collector reported
#    zero disks. Loop variables are now declared once, above the loop. A disk
#    whose `diskutil info` fails is left out and the section marked partial
#    (PAT-1720), so the server keeps that disk's stored row.
##############################################################################
echo "--- 6. Multiple physical disks"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TWO_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Internal:                  Yes")
MOCK_DU_INFO[/dev/disk4]=$(disk_info disk4 "Failing" "   Internal:                  No")
chk_eq "two disks: _hw_disks stdout is a valid JSON array" "valid" "$(disks_raw_valid)"
run_case
chk_eq "two disks: both enumerated in order" "disk0,disk4" "$(hh '",".join(x["device"] for x in d["disks"])')"
chk_eq "two disks: per-disk smart_status kept" "Verified,Failing" "$(hh '",".join(x["smart_status"] for x in d["disks"])')"
chk_eq "two disks: per-disk internal kept" "True,False" "$(hh '",".join(str(x["internal"]) for x in d["disks"])')"
chk_eq "two disks: collector wrote nothing to stdout" "" "$(collector_stdout)"

DU_LIST_THREE_TEXT=$(cat <<'EOF'
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
/dev/disk3 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
/dev/disk4 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
/dev/disk6 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
EOF
)

reset_mocks
MOCK_DU_LIST="$DU_LIST_THREE_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Device Location:           Internal")
MOCK_DU_INFO[/dev/disk4]=$(disk_info disk4 "Verified" "   Device Location:           External")
MOCK_DU_INFO[/dev/disk6]=$(disk_info disk6 "Not Supported" "   Device Location:           External")
chk_eq "three disks: _hw_disks stdout is a valid JSON array" "valid" "$(disks_raw_valid)"
run_case
chk_eq "three disks: all enumerated, synthesized excluded" "disk0,disk4,disk6" "$(hh '",".join(x["device"] for x in d["disks"])')"
chk_eq "three disks: macOS 26 Device Location per disk" "True,False,False" "$(hh '",".join(str(x["internal"]) for x in d["disks"])')"
chk_eq "three disks: whole envelope file is valid JSON" "valid" "$(envelope_valid)"
chk_eq "three disks: every disk read -> disks complete" "complete" "$(status_of disks)"
chk_eq "three disks: collector wrote nothing to stdout" "" "$(collector_stdout)"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TWO_TEXT"
MOCK_DU_INFO[/dev/disk0]=$(disk_info disk0 "Verified" "   Internal:                  Yes")
run_case
chk_eq "second disk's 'diskutil info' fails: readable disk still sent" \
    "disk0" "$(hh '",".join(x["device"] for x in d["disks"])')"
chk_eq "second disk's 'diskutil info' fails: disks partial" "partial" "$(status_of disks)"
chk_eq "second disk's 'diskutil info' fails: _hw_disks stdout still a valid JSON array" "valid" "$(disks_raw_valid)"
chk_eq "second disk's 'diskutil info' fails: envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TWO_TEXT"
MOCK_DU_INFO[/dev/disk4]=$(disk_info disk4 "Failing" "   Internal:                  No")
run_case
chk_eq "first disk's 'diskutil info' fails: later disk still sent" \
    "disk4" "$(hh '",".join(x["device"] for x in d["disks"])')"
chk_eq "first disk's 'diskutil info' fails: disks partial" "partial" "$(status_of disks)"

reset_mocks
MOCK_DU_LIST="$DU_LIST_TEXT"
run_case
chk_eq "sole disk's 'diskutil info' fails: disks [] and partial, never a complete zero" \
    "[] partial" "$(hh 'json.dumps(d["disks"]) + " " + d["collection_status"]["disks"]')"
chk_eq "sole disk's 'diskutil info' fails: envelope valid" "valid" "$(envelope_valid)"

reset_mocks
MOCK_DU_LIST=$'/dev/disk3 (synthesized):\n   #:  TYPE NAME  SIZE  IDENTIFIER'
run_case
chk_eq "diskutil list succeeded with no physical disks -> [] complete" \
    "[] complete" "$(hh 'json.dumps(d["disks"]) + " " + d["collection_status"]["disks"]')"

##############################################################################
# 7. The patched-collect.sh stub, used when collect_hardware_health never
#    runs, is valid JSON that marks every section unavailable.
##############################################################################
echo "--- 7. Collector stub"

STUB_JSON=$(sed -n "s/^printf '\({\"battery\".*}\)' > \"\$HARDWARE_HEALTH_JSON_TMP\"\$/\1/p" "$SCRIPT_DIR/../patched-collect.sh")
HARDWARE_HEALTH_JSON_TMP=$(mktemp)
print -r -- "$STUB_JSON" > "$HARDWARE_HEALTH_JSON_TMP"
chk_eq "stub envelope valid" "valid" "$(envelope_valid)"
chk_eq "stub marks every section unavailable" "unavailable,unavailable,unavailable" "$(all_statuses)"
rm -f "$HARDWARE_HEALTH_JSON_TMP"

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
