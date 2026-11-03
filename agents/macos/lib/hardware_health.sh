# hardware_health.sh — battery health, disk SMART status, and storage pressure.
# Sets HARDWARE_HEALTH_JSON_TMP (path to the temp JSON object file).
# The temp file is consumed by the main script's JSON assembly and cleaned up
# after the heredoc runs.
# Sourced by patched-collect.sh; not executable directly.
#
# PAT-1720: every section also reports how much of it was actually read, in
# hardware_health.collection_status.{battery,storage,disks}:
#   complete     the source command succeeded and every row it listed was read
#   partial      some rows were read and are sent; others could not be read
#                and are left out (the server upserts what is sent, deletes none)
#   unavailable  the source command failed; the section value is a placeholder
#                the server ignores (it writes nothing for that section)
# A failed read is never reported as "no battery", "no volumes" or "no disks".
#
# Each _hw_* helper prints its section JSON on stdout and returns the status
# as its exit code, so the value and the status travel together out of the
# command substitution:
HW_RC_COMPLETE=0
HW_RC_PARTIAL=3
# Any other exit code (including 1 from an unexpected failure) is unavailable.

# _hw_status_name <exit-code> -> complete | partial | unavailable
_hw_status_name() {
    case "$1" in
        "$HW_RC_COMPLETE") print -r -- "complete" ;;
        "$HW_RC_PARTIAL")  print -r -- "partial" ;;
        *)                 print -r -- "unavailable" ;;
    esac
}

# Prints a JSON battery object. Returns complete when system_profiler ran and
# its output was parsed (a desktop with no Battery Information section is a
# real, complete "present": false). Returns unavailable, printing a
# placeholder {"present": false}, when system_profiler or the parser failed.
_hw_battery() {
    set +x 2>/dev/null || true
    local sp_raw out
    if ! sp_raw=$(system_profiler SPPowerDataType 2>/dev/null) || [[ -z "$sp_raw" ]]; then
        # system_profiler failed, or succeeded with no output at all (it
        # always prints a "Power:" header when it works): not evidence of a
        # battery-less machine.
        printf '{"present": false}'
        return 1
    fi

    if ! out=$(printf '%s' "$sp_raw" | "$PYTHON3" -c '
import sys, json, re

text = sys.stdin.read()
if not re.search(r"Battery Information", text, re.IGNORECASE):
    print(json.dumps({"present": False}))
    sys.exit(0)

def first_match(pattern, text):
    m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None

cycle_raw    = first_match(r"Cycle Count:\s*(\d+)", text)
capacity_raw = first_match(r"Maximum Capacity:\s*(\d+)\s*%", text)
condition    = first_match(r"Condition:\s*([^\n]+)", text)

result = {
    "present":          True,
    "cycle_count":      int(cycle_raw)    if cycle_raw    else None,
    "condition":        condition.strip() if condition    else None,
    "max_capacity_pct": int(capacity_raw) if capacity_raw else None,
}
print(json.dumps(result))
' 2>/dev/null) || [[ -z "$out" ]]; then
        printf '{"present": false}'
        return 1
    fi
    printf '%s' "$out"
    return "$HW_RC_COMPLETE"
}

# Prints a JSON array of real mounted volumes.
# Excludes pseudo filesystems: devfs, map auto*, and anything not on a /dev/ node.
# complete: df succeeded and every /dev/ row parsed.
# partial:  some /dev/ rows are sent, but df exited non-zero (it still lists
#           the mounts it could stat when one, such as a stale network mount,
#           fails) or a /dev/ row did not parse.
# unavailable: df printed nothing, or the parser failed; prints [].
_hw_storage() {
    set +x 2>/dev/null || true
    local df_raw df_rc out py_rc
    df_raw=$(df -k 2>/dev/null)
    df_rc=$?

    if [[ -z "$df_raw" ]]; then
        printf '[]'
        return 1
    fi

    out=$(printf '%s' "$df_raw" | "$PYTHON3" -c '
import sys, json

lines = sys.stdin.read().strip().split("\n")
results = []
partial = False
for line in lines[1:]:  # skip header
    parts = line.split()
    if not parts or not parts[0].startswith("/dev/"):
        continue
    if len(parts) < 6:
        partial = True
        continue
    try:
        total_bytes = int(parts[1]) * 1024
        free_bytes  = int(parts[3]) * 1024
        used        = total_bytes - free_bytes
        used_pct    = round(used / total_bytes * 100) if total_bytes > 0 else 0
        # join remaining fields in case mount path contains spaces
        mount       = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
        results.append({
            "mount":       mount,
            "total_bytes": total_bytes,
            "free_bytes":  free_bytes,
            "used_pct":    used_pct,
        })
    except (ValueError, ZeroDivisionError):
        partial = True
        continue
print(json.dumps(results))
sys.exit(3 if partial else 0)
' 2>/dev/null)
    py_rc=$?

    if [[ -z "$out" ]] || (( py_rc != 0 && py_rc != HW_RC_PARTIAL )); then
        printf '[]'
        return 1
    fi
    printf '%s' "$out"
    if (( df_rc != 0 || py_rc == HW_RC_PARTIAL )); then
        return "$HW_RC_PARTIAL"
    fi
    return "$HW_RC_COMPLETE"
}

# Prints a JSON array of physical disk entries.
# Only enumerates disks listed as (physical) by diskutil list.
# complete: `diskutil list` succeeded and every physical disk was read.
# partial:  at least one physical disk could not be read (its `diskutil info`
#           call failed, or its output lacked a field the row needs). That
#           disk is left out of the array rather than sent with guessed
#           values; see the note in the loop.
# unavailable: `diskutil list` failed; prints [].
_hw_disks() {
    set +x 2>/dev/null || true
    local disk_list
    if ! disk_list=$(diskutil list 2>/dev/null) || [[ -z "$disk_list" ]]; then
        printf '[]'
        return 1
    fi

    local phys_disks
    phys_disks=$(printf '%s\n' "$disk_list" | awk '/^\/dev\/disk[0-9]+.*physical/{print $1}')

    if [[ -z "$phys_disks" ]]; then
        printf '[]'
        return "$HW_RC_COMPLETE"
    fi

    local entries=""
    local _HW_DISKS_FIRST=true
    local _hw_disks_partial=false
    # PAT-1708: declare every loop variable once, here, never inside the loop.
    # In zsh, re-running `local x` on a name that is already local prints
    # `x=<previous value>` to stdout. This function's stdout is the JSON
    # array, so a second iteration corrupted it and the caller fell back to
    # [] (any Mac with two or more physical disks reported zero disks).
    local diskdev info entry

    while IFS= read -r diskdev; do
        [[ -z "$diskdev" ]] && continue

        # PAT-1720: a disk that could not be read is left out and the section
        # marked partial, never sent with guessed values. The row contract
        # requires `internal` and `solid_state` booleans and has no null for
        # them, so any value would be a claim: internal=false on the boot
        # disk, solid_state=false on an SSD. The server upserts every row a
        # partial section sends, so a guessed row would overwrite the stored,
        # correct one; a left-out row is kept as stored, and partial stops the
        # server deleting it as if the disk were gone.
        if ! info=$(diskutil info "$diskdev" 2>/dev/null) || [[ -z "$info" ]]; then
            _hw_disks_partial=true
            continue
        fi

        # The parser exits non-zero, printing nothing, when the output lacks a
        # device identifier or either boolean; the disk is then left out as
        # above. A missing SMART Status line is "Undetermined": diskutil
        # prints that line for every whole physical disk it can describe
        # ("Verified", "Failing", or "Not Supported" for enclosures that do
        # not pass SMART through, confirmed on macOS 26.6), so its absence is
        # output we do not understand, not diskutil saying "Not Supported".
        if ! entry=$(printf '%s' "$info" | "$PYTHON3" -c '
import sys, json, re

text = sys.stdin.read()

def parse_field(pattern, text):
    m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None

# [ \t] not \s: an empty value must not let the capture run onto the next line.
device       = parse_field(r"^[ \t]*Device Identifier:[ \t]*(.*)$", text)
smart_status = parse_field(r"^[ \t]*SMART Status:[ \t]*(.*)$", text)
internal_raw = parse_field(r"^[ \t]*Internal:[ \t]*(.*)$", text)
location_raw = parse_field(r"^[ \t]*Device Location:[ \t]*(.*)$", text)
ss_raw       = parse_field(r"^[ \t]*Solid State:[ \t]*(.*)$", text)

# PAT-1708: macOS 26 `diskutil info` prints "Device Location: Internal" and
# no "Internal:" line. Prefer the explicit "Internal:" line when present,
# otherwise fall back to "Device Location".
if internal_raw:
    internal = internal_raw.lower().startswith("yes")
elif location_raw:
    internal = location_raw.lower().startswith("internal")
else:
    sys.exit(3)

if not device or not ss_raw:
    sys.exit(3)

print(json.dumps({
    "device":       device,
    "smart_status": smart_status or "Undetermined",
    "internal":     internal,
    "solid_state":  ss_raw.lower().startswith("yes"),
}))
' 2>/dev/null) || [[ -z "$entry" ]]; then
            _hw_disks_partial=true
            continue
        fi

        if [[ "$_HW_DISKS_FIRST" == "false" ]]; then
            entries+=",$entry"
        else
            entries="$entry"
            _HW_DISKS_FIRST=false
        fi
    done <<< "$phys_disks"

    printf '[%s]' "$entries"
    if [[ "$_hw_disks_partial" == "true" ]]; then
        return "$HW_RC_PARTIAL"
    fi
    return "$HW_RC_COMPLETE"
}

# _hw_json_is <object|array> -> exit 0 when stdin is JSON of that type.
_hw_json_is() {
    "$PYTHON3" -c '
import json, sys
v = json.loads(sys.stdin.read())
want = dict if sys.argv[1] == "object" else list
sys.exit(0 if isinstance(v, want) else 1)
' "$1" 2>/dev/null
}

collect_hardware_health() {
    HARDWARE_HEALTH_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/hardware-health.XXXXXX")  # H11: root-owned 0700 dir, not /tmp

    local battery_json storage_json disks_json
    local battery_status storage_status disks_status

    # Each helper's exit code is its section status. A section whose output
    # is not valid JSON of the right type is unavailable, whatever the helper
    # returned: fail closed, never to complete.
    battery_json=$(_hw_battery 2>/dev/null)
    battery_status=$(_hw_status_name "$?")
    if ! printf '%s' "${battery_json:-}" | _hw_json_is object; then
        battery_json='{"present": false}'
        battery_status="unavailable"
    fi

    storage_json=$(_hw_storage 2>/dev/null)
    storage_status=$(_hw_status_name "$?")
    if ! printf '%s' "${storage_json:-}" | _hw_json_is array; then
        storage_json='[]'
        storage_status="unavailable"
    fi

    disks_json=$(_hw_disks 2>/dev/null)
    disks_status=$(_hw_status_name "$?")
    if ! printf '%s' "${disks_json:-}" | _hw_json_is array; then
        disks_json='[]'
        disks_status="unavailable"
    fi

    cat > "$HARDWARE_HEALTH_JSON_TMP" <<EOF
{"battery": $battery_json, "storage": $storage_json, "disks": $disks_json, "collection_status": {"battery": "$battery_status", "storage": "$storage_status", "disks": "$disks_status"}}
EOF

    return 0
}
