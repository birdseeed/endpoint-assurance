#!/bin/zsh
##############################################################################
# test-compliance-findings.zsh — unit tests for compliance_findings.sh
# (collect_compliance_findings) covering the PAT-913 Option B attestation
# contract.
#
# Sources the live functions out of compliance_findings.sh (no top-level side
# effects at source time) so the tests exercise the real code, not a copy.
# The removable-storage volume enumeration talks to diskutil, so the tests
# override _removable_storage_volumes_json with a stub to drive its three
# outcomes: valid-empty (assessed, no finding), valid-populated (assessed +
# finding), and errored (empty output -> control dropped). FILEVAULT is set
# directly to drive the disk_encryption_off sub-check.
#
# Key assertion (PAT-913): an erroring sub-check must DROP its control from
# controls_assessed, so the server scores it Unknown (fail-unknown) rather
# than a false Pass. Run:
#   zsh macos/lib/test-compliance-findings.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/compliance_findings.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# controls_assessed_ids <assessments-json-file> -> sorted comma-joined control
# ids, so a test can assert on the set regardless of emission order.
controls_assessed_ids() {
    "$PYTHON3" -c "import json,sys; d=json.load(open(sys.argv[1])); print(','.join(sorted(d['controls_assessed'])))" "$1"
}
# finding_ids <findings-json-file> -> sorted comma-joined finding ids.
finding_ids() {
    "$PYTHON3" -c "import json,sys; d=json.load(open(sys.argv[1])); print(','.join(sorted(f['id'] for f in d)))" "$1"
}

# run_case <filevault-state> <enumerator-output> — sets FILEVAULT, overrides the
# volume enumerator to print the given string (empty string simulates a genuine
# enumeration error), runs collect_compliance_findings into a scratch tmpdir.
run_case() {
    local fv="$1" enum_out="$2"
    PATCHED_TMPDIR=$(mktemp -d)
    FILEVAULT="$fv"
    # Override the enumerator for this case. An empty string models the sub-check
    # erroring (Python failed / non-zero) — collect must then drop the control.
    eval "_removable_storage_volumes_json() { printf '%s' '$enum_out'; }"
    collect_compliance_findings
}

##############################################################################
# 1. Both sub-checks assessed, both clean: controls_assessed lists both, no findings.
##############################################################################
echo "--- 1. Both assessed clean (FileVault On, no removable volumes)"
run_case "On" "[]"
chk_eq "controls_assessed = both" "disk_encryption_off,removable_storage_unencrypted" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings empty" "" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

##############################################################################
# 2. disk_encryption_off sub-check ERRORED (FileVault Unknown) -> control dropped.
#    removable assessed clean, still listed.
##############################################################################
echo "--- 2. Disk sub-check errored (FileVault Unknown) drops disk_encryption_off"
run_case "Unknown" "[]"
chk_eq "controls_assessed = removable only" "removable_storage_unencrypted" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings empty" "" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

##############################################################################
# 3. removable sub-check ERRORED (enumerator returns empty) -> control dropped.
#    disk assessed clean, still listed.
##############################################################################
echo "--- 3. Removable sub-check errored drops removable_storage_unencrypted"
run_case "On" ""
chk_eq "controls_assessed = disk only" "disk_encryption_off" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings empty" "" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

##############################################################################
# 4. disk finding present AND attested: FileVault Off -> control assessed AND a
#    finding emitted (server: finding wins over attestation).
##############################################################################
echo "--- 4. FileVault Off: control attested and finding emitted"
run_case "Off" "[]"
chk_eq "controls_assessed = both" "disk_encryption_off,removable_storage_unencrypted" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings = disk" "disk_encryption_off" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

##############################################################################
# 5. removable finding present AND attested: enumerator returns a volume.
##############################################################################
echo "--- 5. Unencrypted removable volume: attested and finding emitted"
run_case "On" '[{"mount_point":"/Volumes/USB","filesystem":"exfat","encryption_state":"plaintext","provenance_source":"diskutil"}]'
chk_eq "controls_assessed = both" "disk_encryption_off,removable_storage_unencrypted" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings = removable" "removable_storage_unencrypted" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

##############################################################################
# 6. Both sub-checks errored: controls_assessed empty (attests nothing),
#    no findings. Server scores both Unknown -> fail-unknown on the critical rule.
##############################################################################
echo "--- 6. Both sub-checks errored: attests nothing"
run_case "Unknown" ""
chk_eq "controls_assessed empty" "" "$(controls_assessed_ids "$COMPLIANCE_ASSESSMENTS_JSON_TMP")"
chk_eq "findings empty" "" "$(finding_ids "$COMPLIANCE_FINDINGS_JSON_TMP")"

echo
echo "compliance-findings tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
