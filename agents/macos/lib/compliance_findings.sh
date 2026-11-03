# compliance_findings.sh — maps posture signals to the shared compliance_findings[]
# and compliance_assessments wire contract (PAT-743, PAT-913). Mirrors the Windows
# agent's StatusWriter.DetectComplianceFindings() / DetectRemovableStorageFindings()
# and InventoryPoster.BuildPayload() (windows/src/...).
#
# Two related outputs (PAT-913, Option B — positive per-control attestation):
#
#   compliance_findings[]              — violations only. An element is present
#                                        ONLY when a control is genuinely violated.
#                                        Never carries "Pass". Server flattens each
#                                        into a "Fail" signal.
#
#   compliance_assessments             — {"controls_assessed": [<control ids>]}. The
#                                        finding-controls this run actually ran a
#                                        determination for. This is the SOLE source
#                                        of a positive "Pass" server-side: a control
#                                        passes only when it is in controls_assessed
#                                        AND absent from compliance_findings.
#
# Server-side semantics (go-service migration 0083_critical_findings_fail_unknown.sql):
# the finding rules now treat_unknown_as='fail'. A control the agent does NOT attest
# (absent from controls_assessed) is Unknown, which for the critical
# full-disk-encryption rule fails. So a control MUST be listed in controls_assessed
# only when its detection genuinely ran to a determination — an erroring sub-check
# drops its control from the list, and the server then scores it Unknown rather than
# a false Pass. Never append a "Pass" entry to compliance_findings, and never fire a
# finding on "Unknown" (a detection failure is not evidence of a violation).
#
# Sets COMPLIANCE_FINDINGS_JSON_TMP and COMPLIANCE_ASSESSMENTS_JSON_TMP (paths to
# the temp JSON files). Requires: FILEVAULT (set by collect_security, lib/security.sh)
# — run collect_security before collect_compliance_findings.
# Sourced by patched-collect.sh; not executable directly.

# disk_encryption_off assessment. The FileVault sub-check ran to a determination
# iff FILEVAULT holds a concrete state (e.g. "On"/"Off"), not "Unknown".
# "Unknown" means fdesetup failed — the control was NOT assessed and must be
# dropped from controls_assessed.
_disk_encryption_assessed() {
    [[ "${FILEVAULT:-Unknown}" != "Unknown" ]]
}

# Prints a JSON array of unencrypted removable-storage volumes on success
# (possibly []), or nothing and returns non-zero on a genuine enumeration
# error — the caller treats a non-zero/empty/invalid result as "sub-check did
# not run" (control dropped from controls_assessed), never a false finding.
#
# Enumerates mounted volumes under /Volumes and, for each, asks
# `diskutil info -plist` whether it is genuinely external + removable +
# physical media:
#   - Internal == false                       (excludes the boot volume)
#   - RemovableMediaOrExternalDevice == true   (USB/Thunderbolt/SD, etc.)
#   - BusProtocol != "Disk Image"              (excludes hdiutil-mounted
#                                                virtual media)
# Non-disk mounts (e.g. network shares under /Volumes) make `diskutil info`
# fail non-zero and are skipped.
#
# Encryption: APFS volumes expose an explicit Encryption/FileVault boolean
# in the plist. Non-APFS removable filesystems (exFAT/FAT32/NTFS — the
# common case for off-the-shelf USB drives) have no disk-level encryption
# mechanism at all, so the absence of both keys is treated as unencrypted:
# that is a real violation, not an "Unknown".
#
# If /Volumes itself cannot be listed, the enumeration genuinely failed:
# exit non-zero so the control is dropped from controls_assessed rather than
# being recorded as an assessed-clean pass.
#
# Verified live against a real attached USB drive (NTFS, unencrypted) on
# 2026-07-08: correctly detected as a finding while the internal boot
# volume and an unrelated network share under /Volumes were both excluded.
# The "no removable media attached" (empty array) path was also verified.
_removable_storage_volumes_json() {
    "$PYTHON3" <<'PYEOF' 2>/dev/null
import json, os, plistlib, subprocess, sys

findings = []
try:
    entries = os.listdir("/Volumes")
except Exception:
    # Enumeration genuinely failed — signal error, do NOT print an empty array.
    sys.exit(1)

for name in sorted(entries):
    mount = "/Volumes/%s" % name
    if not os.path.ismount(mount):
        continue
    try:
        proc = subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", mount],
            capture_output=True, timeout=10,
        )
        if proc.returncode != 0 or not proc.stdout:
            continue
        info = plistlib.loads(proc.stdout)
    except Exception:
        continue

    if info.get("Internal", True):
        continue
    if not info.get("RemovableMediaOrExternalDevice", False):
        continue
    if info.get("BusProtocol") == "Disk Image":
        continue

    encrypted = bool(info.get("Encryption", info.get("FileVault", False)))
    if encrypted:
        continue

    findings.append({
        "mount_point":       mount,
        "filesystem":        info.get("FilesystemName") or info.get("FilesystemType") or "unknown",
        "encryption_state":  "plaintext",
        "provenance_source": "diskutil",
    })

print(json.dumps(findings))
PYEOF
}

collect_compliance_findings() {
    COMPLIANCE_FINDINGS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/compliance-findings.XXXXXX")             # H11: root-owned 0700 dir, not /tmp
    COMPLIANCE_ASSESSMENTS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/compliance-assessments.XXXXXX")

    # findings and controls are built as comma-joined JSON fragments, then
    # wrapped into an array / object at the end. first_* flags gate the comma,
    # matching the accumulation style of the rest of the collector.
    local findings="" controls="" first_f=true first_c=true

    # --- disk_encryption_off ---
    # Assessed iff the FileVault determination ran (FILEVAULT != Unknown). A
    # finding fires only on a definite "Off".
    if _disk_encryption_assessed; then
        if [[ "$first_c" == "true" ]]; then controls='"disk_encryption_off"'; first_c=false; else controls="$controls,\"disk_encryption_off\""; fi
        if [[ "${FILEVAULT:-Unknown}" == "Off" ]]; then
            local entry='{"id": "disk_encryption_off", "severity": "critical"}'
            if [[ "$first_f" == "true" ]]; then findings="$entry"; first_f=false; else findings="$findings,$entry"; fi
        fi
    fi

    # --- removable_storage_unencrypted ---
    # Assessed iff the volume enumeration ran and produced valid JSON (even []).
    # A non-zero/empty/invalid result means the sub-check errored: drop the
    # control (no attestation) rather than recording a false pass or a false
    # finding.
    local volumes_json
    volumes_json=$(_removable_storage_volumes_json)
    if [[ -n "$volumes_json" ]] && \
       printf '%s' "$volumes_json" | "$PYTHON3" -c "import json,sys; json.loads(sys.stdin.read())" >/dev/null 2>&1; then
        if [[ "$first_c" == "true" ]]; then controls='"removable_storage_unencrypted"'; first_c=false; else controls="$controls,\"removable_storage_unencrypted\""; fi
        if [[ "$volumes_json" != "[]" ]]; then
            local rentry="{\"id\": \"removable_storage_unencrypted\", \"severity\": \"medium\", \"volumes\": $volumes_json}"
            if [[ "$first_f" == "true" ]]; then findings="$rentry"; first_f=false; else findings="$findings,$rentry"; fi
        fi
    fi

    printf '[%s]' "$findings" > "$COMPLIANCE_FINDINGS_JSON_TMP"
    printf '{"controls_assessed": [%s]}' "$controls" > "$COMPLIANCE_ASSESSMENTS_JSON_TMP"
}
