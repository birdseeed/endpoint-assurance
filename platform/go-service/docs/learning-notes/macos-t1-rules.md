# macOS CIS L1 — T1 rule learning notes

**Scope:** the 17 always-on macOS T1 rules + the `patched.im baseline` rule. These evaluate for every managed macOS device on every inventory POST, regardless of per-tenant `tenant_rules` settings.
**Reference:** `go-service/docs/CIS_RULES.md` for rule catalogue; `migrations/0003_compliance_rules.sql` for the seeding SQL.

---

## `cis_macos_2_5_1_1_filevault` — Enable FileVault

**Severity:** critical | **Signal:** `filevault` eq `["On"]`

**Why it matters:** FileVault encrypts the startup disk with XTS-AES-128. Without it, someone who steals a laptop or removes the SSD can read every file — including credential stores, tokens cached by browser keychains, email, and documents — without ever needing the login password. This is the most commonly exploited physical-access control gap in SME estates; full-disk encryption is a baseline Cyber Essentials requirement.

**What failure looks like:** A Mac with FileVault off fails this rule with `status = 'fail'`. In practice: the user set up the Mac without enabling FileVault, or an MDM policy that should enforce it was misconfigured. The device passes on the next inventory after FileVault is turned on and the encryption progress completes (the collector reads the live protection status, not the progress percentage).

**Implementation note:** The collector queries FileVault status via `fdesetup status`. On Apple Silicon the value is `"FileVault is On."` (note the period); on Intel it may vary by minor OS version. The extractor normalises the signal to `"On"` / `"Off"` for comparability. The `eq ["On"]` comparator catches the normalised form.

---

## `cis_macos_2_5_3_sip` — Enable System Integrity Protection (SIP)

**Severity:** high | **Signal:** `sip` eq `["enabled"]`

**Why it matters:** SIP prevents any process — even one running as root — from modifying protected files and directories (`/System`, `/sbin`, `/usr`, kernel extensions). Without SIP, malware that achieves root can persistently modify the OS, replace system binaries, or remove the agent itself. Apple's Gatekeeper and XProtect enforcement paths also rely on SIP being intact.

**What failure looks like:** A developer may have disabled SIP to load unsigned kernel extensions. Corporate image builds that carry legacy kernel extensions (e.g. some VPN drivers) sometimes ship SIP-off; this creates an unintended compliance hole. Failure is `status = 'fail'` until SIP is re-enabled (requires booting into Recovery).

**Implementation note:** The collector reads `csrutil status`. macOS 26 changes the output format (`*`/`-` markers instead of "enabled"/"disabled" in some locales) — the `lib/sip.sh` module normalises the output. The signal value is `"enabled"` or `"disabled"` (lowercase).

---

## `cis_macos_2_5_2_1_gatekeeper` — Enable Gatekeeper

**Severity:** high | **Signal:** `gatekeeper` in `["enabled","assessments"]`

**Why it matters:** Gatekeeper enforces Apple's requirement that apps be from the App Store or carry a notarised Developer ID. Without it, macOS will execute any downloaded binary regardless of provenance. This is the first-line defence against drive-by malware delivered via email attachments, browser downloads, or phishing links. Disabling Gatekeeper is the first thing malware installation instructions ask the user to do — it should never be persistently disabled on managed endpoints.

**What failure looks like:** A developer may have run `spctl --master-disable` to test unsigned code, forgetting to re-enable it. The comparator accepts `"enabled"` or `"assessments"` (the legacy name used before macOS 15). Both reflect Gatekeeper in the enforced state.

**Implementation note:** The collector reads `spctl --status`. Output is `"assessments enabled"` pre-macOS 15 and `"enabled"` in later versions — the extractor normalises this by checking for the presence of either string. The multi-value `in` comparator handles both forms.

---

## `cis_macos_2_5_2_2_firewall` — Enable the Application Layer Firewall

**Severity:** high | **Signal:** `firewall` eq `["enabled"]`

**Why it matters:** The macOS Application Layer Firewall (ALF) blocks unsolicited inbound connections per-application, independent of the network-layer firewall. In an office or on a VPN, endpoints can reach each other directly; without ALF, a compromised machine can probe services on every other device on the same network segment. ALF also limits the blast radius when a service unintentionally listens on a broader interface than intended.

**What failure looks like:** macOS ships with the ALF off by default on clean installs (unlike iOS). Without an MDM profile enforcing it, most Macs fail this rule. The fix is a single MDM profile or `socketfilterfw --setglobalstate on`.

**Implementation note:** The collector reads `socketfilterfw --getglobalstate`. The signal is `"enabled"` / `"disabled"` (normalised from the verbose output). Note: this is distinct from the `pf` packet filter firewall — the ALF operates at a higher layer.

---

## `cis_macos_2_5_5_sealed_system_volume` — Sealed System Volume integrity intact

**Severity:** high | **Signal:** `sealed_system_volume` in `["enabled","true"]`

**Why it matters:** The Sealed System Volume (SSV), introduced in macOS Big Sur, is a read-only snapshot of `/System` that is cryptographically signed by Apple. Every file is hashed; the OS verifies the entire tree at boot. Any modification — by malware, a bad update, or an accidental root-level write — causes boot failure rather than silent corruption. This makes persistent OS-level modification by attackers technically infeasible.

**What failure looks like:** Uncommon in practice. Some third-party tools (e.g. certain kernel extension workarounds, legacy patching tools) require disabling SSV, which also requires disabling SIP first. Any device with both SIP and SSV off has lost macOS's strongest tamper-protection layer.

**Implementation note:** The collector reads `diskutil apfs list` and checks the `Sealed` field for the system volume. Returns `"enabled"` (macOS 12+) or `"true"` (macOS 11 normalisation). The comparator accepts both.

---

## `cis_macos_1_4_auto_security_updates` — Auto-install macOS security updates

**Severity:** high | **Signal:** `auto_security_updates` eq `["On"]`

**Why it matters:** Apple ships Rapid Security Responses and OS security updates that patch exploited-in-the-wild vulnerabilities — sometimes with same-day response to zero-days. A device that requires manual update approval can remain vulnerable for days or weeks. For most SME endpoints, the risk of a minor update causing instability is far lower than the risk of running a known-exploited kernel or browser engine.

**What failure looks like:** Users who deny automatic update prompts repeatedly, or organisations that set an update deadline policy but don't enforce auto-install, produce endpoints that fall behind. The pending updates count (`cis_macos_1_1_pending_security_updates`) will typically also be non-zero on the same devices.

**Implementation note:** The collector reads `com.apple.SoftwareUpdate` preference key `AutomaticallyInstallMacOSUpdates`. The signal is `"On"` / `"Off"`. This covers OS updates specifically; App Store app auto-updates are a separate signal (`app_updates_auto_install`, T2 rule `cis_macos_1_5_app_updates_auto`).

---

## `cis_macos_3_x_audit_logging` — Enable audit logging

**Severity:** medium | **Signal:** `audit_logging` eq `["enabled"]`

**Why it matters:** macOS's BSM (Basic Security Module) audit framework creates a tamper-evident record of security-relevant events: login/logout, privilege use, file accesses, process launches. Without it, post-incident forensics have no OS-level event record. Many compliance frameworks (SOC 2, ISO 27001) require demonstrable audit trail capability. The `auditd` process is also the mechanism through which `sudo` commands are recorded.

**What failure looks like:** `auditd` is off by default on clean macOS installs. Without an MDM profile or manual enablement, all managed Macs fail this rule. `launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist` enables it.

**Implementation note:** The collector checks `launchctl list com.apple.auditd` for a running state. Returns `"enabled"` / `"disabled"`. The T2 batch 3 rules (`cis_macos_3_5_*`) cover the permissions on the audit log files themselves — these complement this T1 rule.

---

## `cis_macos_2_4_1_remote_apple_events` — Disable Remote Apple Events

**Severity:** medium | **Signal:** `remote_apple_events` eq `["Off"]`

**Why it matters:** Remote Apple Events allows remote applications to send Apple Events to processes on the Mac, enabling remote automation and control. This is a rarely-used feature in modern MDM-managed estates; leaving it enabled adds an unnecessary inbound network attack surface. It is distinct from SSH and ARD (Remote Management) and is often overlooked.

**What failure looks like:** Remote Apple Events is off by default; failure usually means a user or script explicitly enabled it. The fix is toggling it off in System Settings → Sharing, or via MDM profile.

**Implementation note:** The collector reads `systemsetup -getremoteappleevents`. Returns `"On"` / `"Off"`.

---

## `cis_macos_2_4_4_remote_login` — Disable Remote Login (SSH)

**Severity:** high | **Signal:** `remote_login` eq `["Off"]`

**Why it matters:** SSH on a managed laptop is a remote code execution surface. An attacker with network access and a stolen or guessed password can log in directly. Managed endpoints should not need SSH access — administrators use MDM for remote management, and developers can use terminal locally. Leaving SSH open also enables brute-force and credential-stuffing attacks from anyone who can reach the device on the network.

**What failure looks like:** A developer enabled Remote Login for convenience and never turned it off. In SME estates, IT sometimes enables SSH for one-off scripted tasks and forgets it. Devices connecting to public Wi-Fi are particularly exposed if SSH is open.

**Implementation note:** The collector reads `systemsetup -getremotelogin`. Returns `"Remote Login: On"` / `"Remote Login: Off"` — normalised to `"On"` / `"Off"` by the collector. The comparator expects `"Off"`.

---

## `cis_macos_2_4_10_screen_sharing` — Disable Screen Sharing

**Severity:** medium | **Signal:** `screen_sharing` eq `["Off"]`

**Why it matters:** Screen Sharing (VNC-backed) allows any network-reachable user with the password to take full graphical control of the Mac. VNC is a notoriously weak protocol for authentication and traffic confidentiality — even when macOS encrypts it, the attack surface is much wider than SSH. Remote desktop access to managed employee laptops should go through MDM remote tools, not open VNC.

**What failure looks like:** Screen Sharing enabled for convenience during an IT support session and not turned back off. Also commonly left on in shared office environments where it was set up for informal screen-to-screen sharing.

**Implementation note:** The collector reads `launchctl list com.apple.screensharing`. Returns `"On"` / `"Off"`.

---

## `cis_macos_2_10_screensaver_password` — Require password to wake from screen saver / sleep

**Severity:** medium | **Signal:** `screensaver_password` in `["Yes","DefaultAssumed"]`

**Why it matters:** Without a password requirement after sleep or screen saver, anyone with physical access to an unlocked or unattended Mac can access its data and applications without authentication. This is the "left my laptop open in a café" scenario. Password-on-wake is one of the most basic physical access controls and is expected by every compliance framework.

**What failure looks like:** A user who disabled the password requirement to avoid repeated authentication throughout the day. Also seen on shared-use machines that were set up for convenience.

**Implementation note:** The collector reads `com.apple.screensaver askForPassword`. On macOS 26, the `askForPassword` key may be absent from the user-facing `com.apple.screensaver` plist — the collector treats absence as `"DefaultAssumed"` (the OS default is secure: require password). The comparator accepts `"Yes"` (explicitly set) and `"DefaultAssumed"` as passing values. See CLAUDE.md (macOS 26 parser changes).

---

## `cis_macos_5_1_auto_login_disabled` — Disable automatic login at boot

**Severity:** high | **Signal:** `auto_login_user` eq `["None"]`

**Why it matters:** Automatic login boots the Mac directly into a user session without any authentication challenge. If the device is lost or stolen, the attacker has immediate desktop access to everything the logged-in user can access — email, browser sessions, documents, SSH keys, and any unencrypted credential stores. It also bypasses FileVault's pre-boot authentication on some configurations.

**What failure looks like:** Auto-login was set up on a shared office Mac or by a user who found the login screen annoying. Note that macOS disables auto-login automatically when FileVault is enabled — so a device with FileVault on should always pass this rule. A fail here often signals FileVault was enabled after auto-login was set, or auto-login was re-enabled after the fact.

**Implementation note:** The collector reads the `autoLoginUser` key from `/Library/Preferences/com.apple.loginwindow.plist`. If no user is configured for auto-login, the key is absent — the collector emits `"None"`. The rule expects `eq ["None"]`.

---

## `cis_macos_5_8_local_admin_count` — Limit local administrator accounts

**Severity:** medium | **Signal:** `local_admin_count` lte `["2"]`

**Why it matters:** Each local administrator account is a privilege escalation target. If an attacker compromises a standard user account and finds that account has admin rights (or there are multiple admin accounts), lateral movement within the device is easier. Best practice is one named IT admin account and no more — the end user should not be a local administrator on managed devices.

**What failure looks like:** A Mac with 3+ admin accounts — typical on self-managed devices, shared office Macs, or devices where IT added themselves without removing the previous admin account. Count of 1 (sole user is admin, common on small businesses) passes the `lte 2` rule; 0 is unusual (shouldn't happen — MDM usually creates an admin).

**Implementation note:** The collector counts users in the `admin` group via `dscl . read /Groups/admin GroupMembership`. The signal is the raw integer as a string. The `lte` comparator handles numeric comparison.

---

## `cis_macos_5_x_password_policy_non_default` — Password policy must not be the Apple-default 4-character fallback

**Severity:** medium | **Signal:** `password_policy_is_default` eq `["No"]`

**Why it matters:** macOS ships with a permissive default password policy (4-character minimum, no complexity, no expiry). On managed endpoints, IT should push a stricter policy via MDM. This rule doesn't enforce a specific policy — it checks that *some* non-default policy is in place. The specific controls (minimum length, max age, history) are covered by the T2 password policy rules.

**What failure looks like:** Devices that were never given an MDM password profile, or where the profile was removed/deactivated. A device with `password_policy_is_default = "Yes"` has the permissive Apple default and is likely missing other password controls too.

**Implementation note:** The collector reads `pwpolicy -getaccountpolicies` and detects whether the output matches the Apple default template fingerprint (empty or minimal policy). Returns `"Yes"` (is default / no custom policy) or `"No"` (custom policy present). The rule expects `"No"` to pass.

---

## `cis_macos_1_1_pending_security_updates` — No outstanding macOS security updates

**Severity:** medium | **Signal:** `pending_updates_count` eq `["0"]`

**Why it matters:** Outstanding security updates represent known, published vulnerabilities that the device has not yet mitigated. An attacker reading Apple's security notes knows exactly which CVEs a device is vulnerable to, down to the kernel call site. Even one pending security update means the device is exposed to the specific CVEs it patches. This rule enforces the end-state: updates should be installed promptly, not just enabled.

**What failure looks like:** Any device that has been offered but not yet installed a security update. Common during the first few days after a macOS security release, especially on devices not configured for auto-install. A device can have `auto_security_updates = "On"` but still temporarily fail this rule while an update is downloaded.

**Implementation note:** The collector runs `softwareupdate -l` and counts pending updates. The signal is the count as a string. The rule uses `eq ["0"]` (exact zero), not `lte`, because any pending security update is a finding regardless of count.

---

## `cis_macos_5_x_secure_boot_arm64` — Apple Silicon: Secure Boot integrity intact

**Severity:** high | **Signal:** `secure_boot` in `["Full Security","Valid"]` | **Arch:** arm64 only

**Why it matters:** Apple Silicon Macs use a hardware root-of-trust chain that validates every boot stage — from the Secure Enclave through the iBoot ROM to the OS kernel. "Full Security" means only Apple-signed OS versions are bootable. Downgrading to "Permissive Security" (allowing unsigned kernelcaches) removes this protection and enables booting modified or malicious OS images. This is one of the strongest supply-chain controls on any laptop platform; its presence on Apple Silicon is a genuine security differentiator.

**What failure looks like:** A developer who intentionally lowered security to boot a custom kernel or Linux (rare, but it happens on developer machines). The fix requires booting into recoveryOS and running `bputil` to restore Full Security.

**Implementation note:** macOS 26 changes the output format of `bputil --display-all-policies` — parse "Pairing Integrity" rather than "Secure Boot" as the field name. The `lib/secure_boot.sh` module handles both formats. This rule only evaluates on `arm64` architecture; Intel Macs do not have the equivalent hardware chain and are excluded (`applicable_arch = ['arm64']`).

---

## `patched_mdm_enrolment` — Device is MDM-enrolled

**Severity:** medium | **Signal:** `mdm_enrolled` equals `["Yes"]`

**Why it matters:** MDM enrolment is the prerequisite for every other managed control — BitLocker/FileVault enforcement, profile-deployed certificates, app deployment, password policy push. A device that has left MDM enrolment loses all of these controls silently. Detecting de-enrolment via the Patched inventory ensures it surfaces in the compliance dashboard before IT notices the missing policy pushes.

**What failure looks like:** A user enrolled their personal device then manually removed the MDM profile, or a device was re-imaged without being re-enrolled. IT often doesn't notice until they try to push a policy and it fails. This patched.im baseline rule catches it at the next inventory cycle.

**Implementation note:** The collector reads `profiles status -type enrollment` and emits the neutral `mdm_enrolled` value as `Yes`, `No` or `Unknown`. DEP/Automated Device Enrolment is separate in `mdm_enrolled_via_dep` and does not affect this rule. The deprecated combined `mdm_enrolment` value is accepted only through the evaluator's explicit one-release PAT-1752 compatibility fallback when the neutral key is absent; a present `Unknown` fails closed and never falls back.
