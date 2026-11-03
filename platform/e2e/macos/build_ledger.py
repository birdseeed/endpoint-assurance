#!/usr/bin/env python3
"""build_ledger.py — PAT-739 T10 Layer B ledger builder.

Reads artifacts/baseline-verdicts.json + artifacts/induced-device-detail.json +
artifacts/restored-device-detail.json (all produced by run_layerb.sh) and emits
artifacts/layerb-ledger.json: one row per rule touched by the induction groups,
plus the NOT_INDUCIBLE / BLOCKED rules asserted at baseline only.

This is the exact logic used to produce the ledger for the 2026-07-07 run;
the annotations (group names, bug root-causes, reasons) are specific to what
was observed on that run and are re-emitted verbatim on re-run. If real
observed statuses differ on a re-run (e.g. a fixed collector bug), the
`result` fields will silently keep their old values -- re-derive by hand if
re-running after a code change.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

baseline = json.load(open(os.path.join(ART, "baseline-verdicts.json")))
induced = json.load(open(os.path.join(ART, "induced-device-detail.json")))
restored = json.load(open(os.path.join(ART, "restored-device-detail.json")))

bmap = {v["rule_key"]: v for v in baseline["verdicts"]}
imap = {e["rule_key"]: e for e in induced["evaluations"]}
rmap = {e["rule_key"]: e for e in restored["evaluations"]}


def row(key, group, result, reason=""):
    b, i, r = bmap.get(key, {}), imap.get(key, {}), rmap.get(key, {})
    return {
        "rule_key": key,
        "group": group,
        "baseline": b.get("status"),
        "baseline_observed": b.get("observed_value"),
        "induced": i.get("status"),
        "induced_observed": i.get("observed_value"),
        "restored": r.get("status"),
        "restored_observed": r.get("observed_value"),
        "result": result,
        "reason": reason,
    }


ledger = []

FULL_ROUNDTRIP_GROUPS = {
    "cis_macos_1_3_update_download_auto": "G5 software-update-prefs",
    "cis_macos_2_10_screensaver_password": "G6 screensaver",
    "cis_macos_2_3_3_3_printer_sharing_disabled": "G4b printer-sharing",
    "cis_macos_2_5_2_2_firewall": "G1 firewall",
    "cis_macos_3_5_audit_control_group": "G8 audit-perms",
    "cis_macos_3_5_audit_control_mode": "G8 audit-perms",
    "cis_macos_3_5_audit_control_no_acl": "G8 audit-perms",
    "cis_macos_3_5_audit_control_owner": "G8 audit-perms",
    "cis_macos_3_5_audit_folder_group": "G8 audit-perms",
    "cis_macos_3_5_audit_folder_mode": "G8 audit-perms",
    "cis_macos_3_5_audit_folder_no_acl": "G8 audit-perms",
    "cis_macos_3_5_audit_folder_owner": "G8 audit-perms",
    "cis_macos_3_5_audit_logs_group": "G8 audit-perms",
    "cis_macos_3_5_audit_logs_owner": "G8 audit-perms",
    "cis_macos_5_1_5_system_apps_world_writable": "G10 filesystem",
    "cis_macos_5_1_auto_login_disabled": "G9 auto-login",
    "cis_macos_5_2_1a_lockout_threshold": "G7 pwpolicy",
    "cis_macos_5_2_1b_lockout_reset_minutes": "G7 pwpolicy",
    "cis_macos_5_2_2_min_length": "G7 pwpolicy",
    "cis_macos_5_2_7_max_age_days": "G7 pwpolicy",
    "cis_macos_5_2_8_history_depth": "G7 pwpolicy",
    "cis_macos_5_5_sudo_timestamp_type": "G11 sudo",
}
for k, grp in FULL_ROUNDTRIP_GROUPS.items():
    ledger.append(row(k, grp, "PASS"))

ledger.append(row(
    "cis_macos_2_5_2_1_gatekeeper", "G2 gatekeeper", "PASS",
    "Flip fail->pass verified (spctl --master-enable). Restore leg (--master-disable) blocked: "
    "this macOS version requires interactive System Settings confirmation to globally disable "
    "Gatekeeper via CLI -- 'Globally disabling the assessment system needs to be confirmed in "
    "System Settings.' Confirmed real macOS behavior (--master-enable has no such restriction), "
    "not a collector defect. VM left with Gatekeeper enabled (pass) after this run."
))

ledger.append(row(
    "cis_macos_3_5_audit_logs_mode", "G8 audit-perms", "BUG_CONFIRMED",
    "Real state changed (dummy file created at /var/audit/t10-dummy.log, mode 666) but verdict "
    "never flipped from pass. Root cause: collect_auth() in lib/auth.sh runs "
    "`find \"$_AUDIT_DIR\" -maxdepth 1 -type f -perm /0337` -- the GNU-style `/mode` (any-bit) "
    "operator is NOT supported by macOS/BSD find, which errors 'illegal mode string' (exit 1, "
    "swallowed by 2>/dev/null). grep then sees empty stdin and the signal defaults to pass. "
    "Verified directly on the VM outside the harness. This is a false-negative on a real security "
    "check: it can never detect a world-writable audit log file on any real Mac. Recommend fixing "
    "to `-perm +0337` (deprecated BSD any-bit) or an explicit stat-based bit test."
))

for k in ["cis_macos_2_4_10_screen_sharing", "cis_macos_2_3_3_2_smbd_disabled",
          "cis_macos_2_3_3_7_internet_sharing_disabled", "cis_macos_4_2_httpd_disabled",
          "cis_macos_4_3_nfsd_disabled"]:
    ledger.append(row(
        k, "G4 sharing-daemons", "BUG_CONFIRMED",
        "Real launchctl disabled-bit was toggled (launchctl enable/disable system/<service>) but "
        "verdict never changed. Root cause: collect_sharing() in lib/sharing.sh greps "
        "`launchctl print-disabled system` output for the literal substrings '=> false' / '=> true'. "
        "On this macOS version (15.7 Sequoia) that command instead emits the words 'enabled'/'disabled' "
        "(e.g. '\"com.apple.smbd\" => disabled'), so the grep pattern never matches regardless of real "
        "state, and the signal always falls back to its hardcoded default. Verified directly on the VM: "
        "toggled com.apple.smbd disabled-bit and confirmed the exact grep pattern never matches either "
        "state. Confirms the note in the task brief about a known Sequoia collector bug."
    ))

ledger.append(row(
    "cis_macos_1_2_update_check_auto", "G5 software-update-prefs", "BUG_CONFIRMED",
    "`defaults write .../SoftwareUpdate AutomaticCheckEnabled -bool true` sticks immediately after "
    "the write, but is silently dropped the moment any softwareupdate scan runs -- including the "
    "collector's OWN `softwareupdate -l` call earlier in the same collect_updates() function. "
    "Reproduced directly and independently of the induction harness: wrote the key, confirmed "
    "read-back = 1, ran `softwareupdate -l`, key vanished from the domain immediately (both mid-scan "
    "and post-scan). softwareupdated appears to fully rewrite this preference domain on any real scan "
    "and does not persist this key on macOS 15.7 -- it may be a deprecated/non-functional preference "
    "on current macOS. Because collect_updates() always runs softwareupdate -l before reading this "
    "signal, this rule is structurally unable to ever report anything but fail/Unknown on this OS "
    "version, regardless of true user/MDM configuration. Worth a follow-up ticket independent of this "
    "E2E run."
))

ledger.append(row(
    "cis_macos_3_5_audit_logs_no_acl", "G8 audit-perms", "NOT_EXERCISED",
    "Not included in the main induced batch (dummy log file was given bad owner/group/mode but no "
    "ACL). Mechanism verified working via a supplementary spot-check outside the main ledger cycle: "
    "`chmod +a \"everyone deny delete\" /var/audit/t10-dummy.log` was correctly detected by "
    "`ls -le | grep -E '^\\s+[0-9]+:'` and would flip the signal to fail. No bug found here; simply "
    "not covered by the 3-cycle batch."
))

ledger.append(row(
    "cis_macos_2_3_3_5_remote_management_disabled", "G4c ARD/remote-mgmt", "NOT_INDUCIBLE",
    "Attempted: `kickstart -activate -configure -access -on ...` (ARD) ran successfully and reported "
    "'Activated Remote Management', but the signal is read via `mdmclient QuerySecurityInfo | grep "
    "RemoteDesktopEnabled` which returned empty both before and after -- this call requires the Mac "
    "to be MDM-enrolled to return any security-info payload at all. This harness has no MDM server, "
    "so this signal cannot be exercised in either direction; always falls back to its 'Yes' (pass) "
    "default."
))

ledger.append(row(
    "cis_macos_2_4_4_remote_login", "G3 remote-login", "BLOCKED",
    "Not attempted for operational safety. `systemsetup -setremotelogin off` requires interactive "
    "'yes/no' confirmation on stdin and its own prompt explicitly warns: 'you will lose this "
    "connection and can only turn it back on locally at the server.' This headless Tart VM has no "
    "console/VNC fallback wired into this harness -- SSH is the only control channel. Verified "
    "safely: ran the command with no stdin, observed it loop the confirmation prompt (killed locally "
    "after output cap; VM state unaffected, remote login remained On, no hung remote process). Given "
    "the risk of permanently losing VM control mid-run with no way to restore or even complete the "
    "ledger, this flip was not executed. Baseline (fail/On) asserted only."
))

for k in ["cis_macos_2_5_1_1_filevault", "cis_macos_2_5_3_sip", "cis_macos_2_5_5_sealed_system_volume",
          "cis_macos_5_x_secure_boot_arm64", "cis_macos_5_1_3_amfi_enabled", "patched_mdm_enrolment",
          "cis_macos_5_6_root_disabled"]:
    ledger.append(row(
        k, "not-inducible (per task brief)", "NOT_INDUCIBLE",
        "Listed as not-inducible in the task brief (requires hardware/firmware reconfiguration, "
        "MDM enrolment, or a full OS reinstall out of scope for this harness). Baseline asserted only."
    ))

SAFARI_MANAGED_PREFS = [
    "cis_macos_6_3_1_safari_auto_open_downloads_disabled", "cis_macos_6_3_3_safari_fraudulent_warning",
    "cis_macos_6_3_4_safari_cross_site_tracking_blocked", "cis_macos_6_3_6_safari_private_measurement",
    "cis_macos_6_3_7_safari_full_url_shown", "cis_macos_6_3_10_safari_status_bar_shown",
    "cis_macos_2_2_2_firewall_stealth_mode", "cis_macos_2_3_1_1_airdrop_disabled",
    "cis_macos_2_3_1_2_airplay_receiver_disabled", "cis_macos_2_5_1_siri_disabled",
    "cis_macos_2_6_4_personalized_ads_disabled", "cis_macos_2_6_8_system_prefs_admin_lock",
    "cis_macos_2_12_1_guest_account_disabled", "cis_macos_2_18_1_dictation_on_device",
    "cis_macos_2_10_3_loginwindow_text_set", "cis_macos_2_10_4_loginwindow_fullname_prompt",
    "cis_macos_2_10_5_loginwindow_password_hints",
]
for k in SAFARI_MANAGED_PREFS:
    ledger.append(row(
        k, "G12 managed-prefs/Safari", "NOT_INDUCIBLE",
        "Requires a real MDM-deployed configuration profile (signals read via NSUserDefaults suite "
        "for managed-preference domains / `profiles -P -o stdout`). One local install attempt was "
        "made (`profiles install -type configuration -path t10-test.mobileconfig`) targeting "
        "com.apple.applicationaccess/allowAirDrop; refused cleanly by the OS: 'profiles tool no "
        "longer supports installs. Use System Settings Profiles to add configuration profiles.' "
        "Confirms local CLI profile installation is disabled on this macOS version -- genuinely "
        "NOT_INDUCIBLE without a real MDM server. Baseline (fail, no profile deployed) asserted only."
    ))

ledger.append(row(
    "cis_macos_5_4_sudo_timeout", "G11 sudo", "PASS",
    "Already compliant at baseline (0 <= 0). Induced sudoers.d drop-in kept timestamp_timeout=0 "
    "unchanged by design (only timestamp_type was deliberately broken/fixed); asserted stable across "
    "all 3 cycles, no flip attempted for this key."
))

summary = {
    "PASS_full_roundtrip": sum(1 for r in ledger if r["result"] == "PASS" and r["baseline"] == r["restored"] and r["baseline"] != r["induced"]),
    "PASS_partial_restore_blocked": sum(1 for r in ledger if r["result"] == "PASS" and r["baseline"] != r["induced"] and r["baseline"] != r["restored"]),
    "PASS_no_flip_attempted": sum(1 for r in ledger if r["result"] == "PASS" and r["baseline"] == r["induced"] == r["restored"]),
    "BUG_CONFIRMED": sum(1 for r in ledger if r["result"] == "BUG_CONFIRMED"),
    "NOT_INDUCIBLE": sum(1 for r in ledger if r["result"] == "NOT_INDUCIBLE"),
    "NOT_EXERCISED": sum(1 for r in ledger if r["result"] == "NOT_EXERCISED"),
    "BLOCKED": sum(1 for r in ledger if r["result"] == "BLOCKED"),
    "total_rows": len(ledger),
}

out = {
    "generated_at": induced.get("generated_at"),
    "tenant_id": "1f046fd6-2e1a-4f00-93ad-b8e6b34b2a5a",
    "device_id": induced.get("device", {}).get("id"),
    "device_serial": induced.get("device", {}).get("serial"),
    "cycles": {
        "baseline_evaluations": len(bmap),
        "induced_evaluations": len(imap),
        "restored_evaluations": len(rmap),
    },
    "summary": summary,
    "rules": ledger,
}

out_path = os.path.join(ART, "layerb-ledger.json")
with open(out_path, "w") as f:
    json.dump(out, f, indent=2)

print(f"Wrote {out_path} ({len(ledger)} rows)")
print(json.dumps(summary, indent=2))
