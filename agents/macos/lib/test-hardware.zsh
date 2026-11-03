#!/bin/zsh
##############################################################################
# test-hardware.zsh — unit tests for the device identity collector
# (collect_hardware) in hardware.sh (PAT-1723).
#
# Sources the live function out of hardware.sh (no top-level side effects at
# source time) so the tests exercise the real code, not a copy. Every external
# command collect_hardware calls (ioreg, scutil, sysctl, dscl, df, uname,
# hostname) is shadowed with a zsh function of the same name (zsh resolves a
# function before an external command), so the runner's own hardware is never
# read.
#
# SERIAL and HW_UUID must be "Unknown" whenever ioreg fails or yields no
# value. Before PAT-1723 (HW_UUID) and PAT-1724 (SERIAL) the
# `ioreg | awk || echo Unknown` shape tested awk's exit status, so a failed or
# empty ioreg left them empty.
#
# patched-upload.sh reads HW_UUID separately and its failure value is empty,
# not "Unknown", because every consumer treats empty as "no device id" and
# omits the X-Patched-Device-Id header (PAT-1724). Its patched_hw_uuid block is
# extracted from the shipped script by sentinel and tested below. Run:
#   zsh macos/lib/test-hardware.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MACOS_DIR="${SCRIPT_DIR:h}"

source "$SCRIPT_DIR/hardware.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# ── Boundary doubles ───────────────────────────────────────────────────────
MOCK_UUID="5F9A2B1C-3D4E-5F6A-7B8C-9D0E1F2A3B4C"
MOCK_SERIAL="MOCKSERIAL01"
MOCK_IOREG_MODE="ok"   # ok | fail | fail_with_output | empty | no_uuid_line | no_serial_line | empty_values
IOREG_FIXTURE='+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000213, registered, matched, active, busy 0 (0 ms), retain 34>
    {
      "IOPlatformSerialNumber" = "'"$MOCK_SERIAL"'"
      "IOPlatformUUID" = "'"$MOCK_UUID"'"
      "model" = <"MacBookPro18,2">
    }'
ioreg() {
    case "$MOCK_IOREG_MODE" in
        ok)               print -r -- "$IOREG_FIXTURE" ;;
        fail)             return 1 ;;
        fail_with_output) print -r -- "$IOREG_FIXTURE"; return 1 ;;
        empty)            return 0 ;;
        no_uuid_line)     print -r -- "${IOREG_FIXTURE//\"IOPlatformUUID\"*$'\n'/}" ;;
        no_serial_line)   print -r -- "$IOREG_FIXTURE" | grep -v IOPlatformSerialNumber ;;
        empty_values)     print -r -- "${${IOREG_FIXTURE//$MOCK_SERIAL/}//$MOCK_UUID/}" ;;
    esac
}
scutil()   { print -r -- "mock-host"; }
hostname() { print -r -- "mock-host"; }
sysctl()   { print -r -- "0"; }
uname()    { print -r -- "arm64"; }
dscl()     { print -r -- "alice 501"; }
df()       { print -r -- "/dev/disk3s5 1000000 1 500000 1% /System/Volumes/Data"; }

run_case() {
    MOCK_IOREG_MODE="$1"
    HW_UUID="__unset__"
    SERIAL="__unset__"
    collect_hardware
}

echo "--- HW_UUID"

run_case ok
chk_eq "ioreg succeeds -> the IOPlatformUUID" "$MOCK_UUID" "$HW_UUID"

run_case fail
chk_eq "ioreg fails with no output -> Unknown" "Unknown" "$HW_UUID"

run_case fail_with_output
chk_eq "ioreg fails even with parseable output -> Unknown" "Unknown" "$HW_UUID"

run_case empty
chk_eq "ioreg succeeds with empty output -> Unknown" "Unknown" "$HW_UUID"

run_case no_uuid_line
chk_eq "fixture without IOPlatformUUID really lacks the key" "0" "$(ioreg | grep -c IOPlatformUUID)"
chk_eq "ioreg output without IOPlatformUUID -> Unknown" "Unknown" "$HW_UUID"

echo "--- SERIAL"

run_case ok
chk_eq "ioreg succeeds -> the IOPlatformSerialNumber" "$MOCK_SERIAL" "$SERIAL"

run_case fail
chk_eq "ioreg fails with no output -> Unknown" "Unknown" "$SERIAL"

run_case fail_with_output
chk_eq "ioreg fails even with parseable output -> Unknown" "Unknown" "$SERIAL"

run_case empty
chk_eq "ioreg succeeds with empty output -> Unknown" "Unknown" "$SERIAL"

run_case no_serial_line
chk_eq "fixture without IOPlatformSerialNumber really lacks the key" "0" "$(ioreg | grep -c IOPlatformSerialNumber)"
chk_eq "ioreg output without IOPlatformSerialNumber -> Unknown" "Unknown" "$SERIAL"
chk_eq "missing serial does not disturb HW_UUID" "$MOCK_UUID" "$HW_UUID"

run_case empty_values
chk_eq "empty IOPlatformSerialNumber value -> Unknown" "Unknown" "$SERIAL"
chk_eq "empty IOPlatformUUID value -> Unknown" "Unknown" "$HW_UUID"

echo "--- patched-upload.sh patched_hw_uuid (empty on failure, never Unknown)"

UPLOAD_SH="$MACOS_DIR/patched-upload.sh"
HWU_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-hw-uuid.XXXXXX")
awk '/PATCHED_HW_UUID_START/{f=1;next} /PATCHED_HW_UUID_END/{f=0} f' \
    "$UPLOAD_SH" > "$HWU_TMP"
if [[ ! -s "$HWU_TMP" ]]; then
    rm -f "$HWU_TMP"
    echo "FATAL: could not extract PATCHED_HW_UUID block from $UPLOAD_SH"
    exit 1
fi
source "$HWU_TMP"
rm -f "$HWU_TMP"
chk_eq "upload script assigns HW_UUID from patched_hw_uuid" "1" \
    "$(grep -c '^HW_UUID=\$(patched_hw_uuid)$' "$UPLOAD_SH")"

upload_case() {  # upload_case <ioreg mode> -> sets UP_UUID
    MOCK_IOREG_MODE="$1"
    UP_UUID=$(patched_hw_uuid)
}

upload_case ok
chk_eq "upload: ioreg succeeds -> the IOPlatformUUID" "$MOCK_UUID" "$UP_UUID"
upload_case fail
chk_eq "upload: ioreg fails with no output -> empty" "" "$UP_UUID"
upload_case fail_with_output
chk_eq "upload: ioreg fails even with parseable output -> empty" "" "$UP_UUID"
upload_case empty
chk_eq "upload: ioreg succeeds with empty output -> empty" "" "$UP_UUID"
upload_case no_uuid_line
chk_eq "upload: ioreg output without IOPlatformUUID -> empty" "" "$UP_UUID"
upload_case empty_values
chk_eq "upload: empty IOPlatformUUID value -> empty" "" "$UP_UUID"

# The consumer contract the empty value relies on: no header when empty.
upload_case fail
HW_UUID="$UP_UUID"
device_hdr=()
[[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")
chk_eq "upload: empty HW_UUID sends no device-id header" "0" "${#device_hdr[@]}"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
