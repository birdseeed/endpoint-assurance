#!/bin/bash
# apply_remote.sh — runs INSIDE the Tart VM as root (via sudo bash).
# Applies the induced ("bad"/"good" as needed) state for every Layer B group.
# Must be idempotent-ish; logs each step so failures are visible in the
# transcript captured by induce.sh on the host.
set -u
echo "=== APPLY: begin $(date -u +%FT%TZ) ==="

FIRST_USER_HOME="/Users/admin"
SS_PLIST="$FIRST_USER_HOME/Library/Preferences/com.apple.screensaver.plist"

step() { echo "--- [$1] ---"; }

# G1 — firewall: baseline PASS(enabled) -> induce OFF -> expect FAIL
step "G1 firewall: disable"
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off

# G2 — gatekeeper: baseline FAIL(disabled) -> induce ON -> expect PASS
step "G2 gatekeeper: enable"
spctl --master-enable

# G3 — remote_login: BLOCKED. Not attempted (see RESULTS.md). No-op.
step "G3 remote_login: SKIPPED (blocked, see RESULTS.md)"

# G4 — sharing daemons (collector-bug candidates): flip real disabled-bit anyway
# so the run demonstrates the bug end-to-end (baseline PASS -> real state now
# "enabled"/running-capable -> expect collector STILL reports pass = bug proof).
step "G4 sharing daemons: launchctl enable (real state -> running-capable)"
launchctl enable system/com.apple.smbd
launchctl enable system/com.apple.screensharing
launchctl enable system/com.apple.InternetSharing
launchctl enable system/org.apache.httpd
launchctl enable system/com.apple.nfsd

# G4b — printer sharing (cupsctl, NOT part of the launchctl bug): baseline
# PASS(Yes) -> induce ON -> expect FAIL
step "G4b printer sharing: enable"
cupsctl --share-printers

# G4c — remote management / ARD (low confidence, mdmclient needs MDM enrolment)
step "G4c ARD kickstart -activate (low confidence attempt)"
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
    -activate -configure -access -on -privs -all -clientopts -setvnclegacy -vnclegacy yes -restart -agent -menu 2>&1 || echo "kickstart attempt failed/non-fatal"

# G5 — software update prefs: baseline update_check_auto=FAIL(Unknown),
# update_download_auto=FAIL(Off); others already pass. Set all 6 true.
step "G5 software update prefs: set all true"
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true

# G6 — screensaver: baseline FAIL(No) -> induce askForPassword=true -> expect PASS
step "G6 screensaver: askForPassword=1"
# Key is stored as <integer> on this VM (plutil -p shows "askForPassword" => 0),
# not <true/>/<false/> bool -- PlistBuddy "Set :askForPassword true" fails with
# "Unrecognized Integer Format" against an integer-typed key. Use the numeric
# form so the existing type is preserved.
/usr/libexec/PlistBuddy -c "Set :askForPassword 1" "$SS_PLIST" 2>&1
chown admin:staff "$SS_PLIST" 2>/dev/null || true

# G7 — pwpolicy: consolidated XML breaking 4 currently-passing signals and
# fixing the 1 currently-failing signal (max_age). See induced_pwpolicy.xml.
step "G7 pwpolicy: apply induced accountpolicies"
pwpolicy -setaccountpolicies /tmp/t10-induce/induced_pwpolicy.xml 2>&1

# G8 — audit file/folder/log perms: break ACL/owner/group/mode on the control
# file and the audit folder; create one badly-permissioned dummy log file.
step "G8 audit perms: break control file"
chmod +a "everyone deny delete" /etc/security/audit_control 2>&1 || echo "ACL add failed (non-fatal)"
chown admin:staff /etc/security/audit_control
chmod 644 /etc/security/audit_control

step "G8 audit perms: break audit folder"
chmod +a "everyone deny delete" /var/audit 2>&1 || echo "ACL add failed (non-fatal)"
chown admin:staff /var/audit
chmod 755 /var/audit

step "G8 audit perms: bad dummy log file"
touch /var/audit/t10-dummy.log
chown admin:staff /var/audit/t10-dummy.log
chmod 666 /var/audit/t10-dummy.log

# G9 — auto-login: baseline PASS(None) -> induce admin -> expect FAIL
step "G9 auto-login: set autoLoginUser=admin"
defaults write /Library/Preferences/com.apple.loginwindow autoLoginUser -string admin

# G10 — filesystem: baseline FAIL (PatchedTest.app is world-writable 777) ->
# induce chmod 755 (remove world+group write) -> expect PASS
step "G10 filesystem: fix world-writable PatchedTest.app"
chmod 755 /Applications/PatchedTest.app

# G11 — sudo: baseline sudo_timeout=PASS(0), sudo_timestamp_type=FAIL(global).
# Add a sudoers.d file that sorts after patched-e2e and flips timestamp_type.
step "G11 sudo: add induced sudoers.d drop-in"
cat > /tmp/t10-induce/zzz-t10-induce <<'SUDOEOF'
Defaults timestamp_timeout=0
Defaults timestamp_type=tty
SUDOEOF
chmod 440 /tmp/t10-induce/zzz-t10-induce
if visudo -c -f /tmp/t10-induce/zzz-t10-induce; then
    cp /tmp/t10-induce/zzz-t10-induce /etc/sudoers.d/zzz-t10-induce
    chown root:wheel /etc/sudoers.d/zzz-t10-induce
    chmod 440 /etc/sudoers.d/zzz-t10-induce
    echo "sudoers.d drop-in installed"
    if sudo -v 2>&1; then
        echo "sudo -v OK after induce"
    else
        echo "sudo -v FAILED after induce -- rolling back immediately"
        rm -f /etc/sudoers.d/zzz-t10-induce
    fi
else
    echo "visudo -c FAILED -- NOT installing induced sudoers.d file"
fi

# G12 — managed prefs / Safari (single mobileconfig attempt; rest NOT_INDUCIBLE)
step "G12 mobileconfig install attempt (expect refusal on unmanaged Mac)"
profiles install -type configuration -path /tmp/t10-induce/t10-test.mobileconfig 2>&1 || echo "profiles install failed/refused (expected)"

echo "=== APPLY: end $(date -u +%FT%TZ) ==="
