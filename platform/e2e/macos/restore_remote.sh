#!/bin/bash
# restore_remote.sh — runs INSIDE the Tart VM as root (via sudo bash).
# Reverts every induced state back to the original baseline observed before
# G1 apply. See apply_remote.sh for the paired forward actions.
set -u
echo "=== RESTORE: begin $(date -u +%FT%TZ) ==="

FIRST_USER_HOME="/Users/admin"
SS_PLIST="$FIRST_USER_HOME/Library/Preferences/com.apple.screensaver.plist"

step() { echo "--- [$1] ---"; }

step "G1 firewall: re-enable"
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

step "G2 gatekeeper: disable"
spctl --master-disable

step "G3 remote_login: SKIPPED (blocked, never touched)"

step "G4 sharing daemons: launchctl disable (restore original disabled-bit)"
launchctl disable system/com.apple.smbd
launchctl disable system/com.apple.screensharing
launchctl disable system/com.apple.InternetSharing
launchctl disable system/org.apache.httpd
launchctl disable system/com.apple.nfsd

step "G4b printer sharing: disable"
cupsctl --no-share-printers

step "G4c ARD kickstart: deactivate"
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>&1 || echo "kickstart deactivate failed/non-fatal"

step "G5 software update prefs: restore original values"
defaults delete /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>&1 || true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true

step "G6 screensaver: askForPassword=0"
# See apply_remote.sh: key is <integer>-typed on this VM, not bool.
/usr/libexec/PlistBuddy -c "Set :askForPassword 0" "$SS_PLIST" 2>&1

step "G7 pwpolicy: restore original accountpolicies"
pwpolicy -setaccountpolicies /tmp/t10-induce/original_pwpolicy.xml 2>&1

step "G8 audit perms: restore control file"
chmod -a "everyone deny delete" /etc/security/audit_control 2>&1 || true
chown root:wheel /etc/security/audit_control
chmod 440 /etc/security/audit_control

step "G8 audit perms: restore audit folder"
chmod -a "everyone deny delete" /var/audit 2>&1 || true
chown root:wheel /var/audit
chmod 700 /var/audit

step "G8 audit perms: remove dummy log file"
rm -f /var/audit/t10-dummy.log

step "G9 auto-login: remove autoLoginUser"
defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1 || true

step "G10 filesystem: restore world-writable PatchedTest.app"
chmod 777 /Applications/PatchedTest.app

step "G11 sudo: remove induced sudoers.d drop-in"
rm -f /etc/sudoers.d/zzz-t10-induce
sudo -v 2>&1 && echo "sudo -v OK after restore" || echo "sudo -v FAILED after restore"

step "G12 mobileconfig: remove installed profile if present"
PROFILE_ID=$(profiles list 2>/dev/null | grep -B2 "T10 Layer B" | grep "profileIdentifier" | awk '{print $NF}')
if [[ -n "${PROFILE_ID:-}" ]]; then
    profiles remove -identifier "$PROFILE_ID" 2>&1 || echo "profiles remove failed (non-fatal)"
else
    echo "no installed T10 profile found (expected if install was refused)"
fi

echo "=== RESTORE: end $(date -u +%FT%TZ) ==="
