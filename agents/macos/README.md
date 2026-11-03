# macOS agent

Three-piece agent that collects endpoint inventory + compliance signals and delivers them to `api.patched.im`.

```
patched-collect.sh   →   /var/db/patched/queue/   →   patched-upload.sh   →   api.patched.im
  (collector)              (file queue)               (LaunchDaemon)          (ingestion service)
```

---

## What it collects

| Field / group | Source command | Why it matters |
|---|---|---|
| **Hardware identity** | | |
| `device.serial` | `ioreg -l \| awk /IOPlatformSerialNumber/` | Stable device identity across OS reinstalls |
| `device.hw_uuid` | `ioreg -l \| awk /IOPlatformUUID/` | Primary upsert key; more stable than serial on Apple Silicon |
| `device.hostname` | `scutil --get LocalHostName` | Display name in reports |
| `device.computer_name` | `scutil --get ComputerName` | Human-friendly name from System Preferences |
| `device.hw_model` | `sysctl -n hw.model` | Model identifier (e.g. `Mac14,2`) |
| `device.arch` | `uname -m` | Architecture gate for rules (e.g. Secure Boot check is arm64-only) |
| **Hardware specs** | | |
| `hardware.cpu_model` | `sysctl -n machdep.cpu.brand_string` | Fleet reporting |
| `hardware.cpu_cores` | `sysctl -n hw.ncpu` | Fleet reporting |
| `hardware.ram_gb` | `sysctl -n hw.memsize` | Fleet reporting |
| `hardware.disk_total_gb` | `df -k /System/Volumes/Data` | Fleet reporting |
| `hardware.disk_free_gb` | `df -k /System/Volumes/Data` | Low-disk alerting |
| **OS** | | |
| `os.version` | `sw_vers -productVersion` | CVE matching baseline |
| `os.build` | `sw_vers -buildVersion` | Security bulletin correlation |
| `device.last_boot` | `sysctl -n kern.boottime` | Uptime / reboot-required signal |
| **CIS L1 compliance signals** | | |
| `filevault` | `fdesetup status` | CIS 2.5.1.1 — disk encryption |
| `sip` | `csrutil status` | CIS 2.5.3 — System Integrity Protection |
| `gatekeeper` | `spctl --status` | CIS 2.5.2.1 — binary execution control |
| `firewall` | `socketfilterfw --getglobalstate` | CIS 2.5.2.2 — application layer firewall |
| `sealed_system_volume` | `csrutil authenticated-root status` | CIS 2.5.5 — tamper detection |
| `auto_security_updates` | `defaults read com.apple.SoftwareUpdate` | CIS 1.4, auto-patch. `On`/`Off`, `NotConfigured` when the key is not set, `Unknown` when the read failed |
| `pending_updates_count` | `softwareupdate -l` (count) | CIS 1.1 — outstanding updates |
| `audit_logging` | `/etc/security/audit_control` presence | CIS 2.x — event logging |
| `remote_apple_events` | `systemsetup -getremoteappleevents` | CIS 2.4.1 — attack surface |
| `remote_login` | `systemsetup -getremotelogin` | CIS 2.4.4 — SSH disabled |
| `screen_sharing` | `launchctl print-disabled system` | CIS 2.4.10 — screen sharing off |
| `screensaver_password` | macOS 13+: `sysadminctl -screenLock status` as the console user; macOS 12 and earlier: `PlistBuddy com.apple.screensaver.plist` | CIS 2.10.x — lock on idle |
| `screensaver_delay_seconds` | same source | CIS 2.10.x — lock delay |
| `screensaver_idle_seconds` | `com.apple.screensaver` `idleTime` via JXA `NSUserDefaults`, run as the console user (profile-forced value wins over the user's own) | CIS 2.10.1 — screen saver inactivity interval. Positive integer; `99999` when idleTime is `0` ("never", the Windows no-limit sentinel) so `lte 1200` fails; `"NotConfigured"` when idleTime is not set and every plist in the user's search list is absent or a readable dictionary; null when not positively read, or when an unset key cannot be confirmed |
| `screensaver_idle_seconds_enforced_by_profile` | same call, `objectIsForcedForKey` | `true`/`false`, null when the read failed (PAT-1720 convention) |
| `auto_login_user` | `defaults read com.apple.loginwindow` | CIS 5.1 — no auto-login |
| `local_admin_count` | `dscl -plist . read /Groups/admin GroupMembership` | CIS 5.8 — limit admins. Whole number excluding `root`; null when the enumeration failed (dscl exited non-zero, its output did not parse, or the record carries no `GroupMembership` attribute), never a fabricated `0` (PAT-1974) |
| `password_policy_present` | `pwpolicy -getaccountpolicies` | CIS 5.x — policy present |
| `password_policy_is_default` | Apple token in policy output | CIS 5.x — not the weak default |
| `mdm_enrolled` | `profiles status -type enrollment` | Platform-neutral MDM fact: `Yes`, `No` or `Unknown` |
| `mdm_enrolled_via_dep` | `profiles status -type enrollment` | Separate DEP/Automated Device Enrolment detail: `Yes`, `No` or `Unknown`; does not affect the neutral MDM rule |
| `mdm_enrolment` | `profiles status -type enrollment` | Deprecated combined compatibility value, retained for one PAT-1752 release only |
| `secure_boot` (arm64 only) | `bputil --display-all-policies` (Pairing Integrity) | Apple Silicon secure boot |
| **Inventory** | | |
| `security_tools` | Path presence for 10 known AV/EDR agents | Third-party security tool coverage |
| `system_extensions` | `systemextensionsctl list` | Kernel extension inventory |
| `background_items` | BTM plist `/var/db/com.apple.backgroundtaskmanagement/` | Persistence / startup item audit |
| `icloud.signed_in` | `MobileMeAccounts.plist` presence | iCloud sign-in state |
| `apps[]` | `find /Applications -name '*.app'` + PlistBuddy + codesign | Full application inventory. Every payload also carries top-level `collection_status.apps`: `complete` (every root listed without error and every top-level bundle read; the server prunes stored apps not listed, even when the array is `[]`), `partial` (`find` could not list a root or a directory under one, or a bundle had no readable, parseable `Info.plist` and was left out; the server prunes nothing) or `unavailable` (the collector never finished its walk; `apps` is sent as `[]` and the server writes nothing). Bundles nested inside another `.app` and a `.app` that is not a directory are left out by scope, not as a failure. iOS and iPadOS apps on Apple silicon (`WrappedBundle` or `Wrapper/`, no `Contents/`) are in scope (PAT-2072): each is read from its one `Wrapper/*.app/Info.plist` (`CFBundleIdentifier`; `CFBundleShortVersionString`, else `CFBundleVersion`; `CFBundleDisplayName`, else `CFBundleName`) and sent as an ordinary row with the outer bundle as its `path`, and a wrapper with no inner app, more than one, or an `Info.plist` that is missing, unreadable or unparseable is `partial`. `Info.plist` readability is checked with `plutil -lint`, because PlistBuddy exits 0 on a file it cannot open. Anything but `complete` logs `PATCHED_COLLECTION_WARNING section=apps status=partial reason=<listing_failed\|bundle_unreadable> skipped=N` (PAT-2066). |
| `pending_updates[]` | `softwareupdate -l` (detailed) | Outstanding update details for report |
| `patches[]` | `softwareupdate --history --all` | Installed update history |
| `certificates[]` | `security find-certificate -a -p /Library/Keychains/System.keychain` + `openssl x509` | System keychain cert expiry visibility; mirrors Entra ID client-secret tracking. Each entry has `subject_cn`, `issuer_cn`, `sha1` (hex, no colons, lowercase), `not_after` (ISO 8601 UTC), `days_until_expiry` (integer, negative when expired), `ext_key_usage` (JSON array of Extended Key Usage OID strings in dotted notation, e.g. `"1.3.6.1.5.5.7.3.3"`; empty array when the extension is absent), `basic_constraints_ca` (boolean; `true` only when the Basic Constraints extension is present and its cA flag is TRUE), `is_self_signed` (boolean; `true` when the certificate's full subject DN equals its full issuer DN). EKU and Basic Constraints are read from the certificate's DER bytes (`openssl x509 -outform DER | od`, walked in awk against the X.509 outline, extensions located by position inside TBSCertificate), never from `-text` or `asn1parse`, which print subject strings and string extensions verbatim, newlines included; stock `/usr/bin/openssl` is LibreSSL and has no `-ext` (PAT-1735, PAT-1740). A repeated or malformed Basic Constraints or EKU, or DER that does not walk cleanly, skips that certificate. Every payload also carries top-level `collection_status.certificates`: `complete` (whole keychain read, every certificate parsed; the array is sent, `[]` included), `partial` (the keychain was read but one or more certificates could not be parsed; those are left out, the rest are sent and the server prunes nothing, and the key is omitted when nothing parsed) or `unavailable` (a missing, unopenable or malformed store; the key is omitted and the server writes nothing). Anything but `complete` logs `PATCHED_COLLECTION_WARNING section=certificates status=<partial\|unavailable> reason=...` instead of sending `[]` (PAT-1709, PAT-1732). |
| **Hardware health** | | |
| `hardware_health.battery` | `system_profiler SPPowerDataType` | Battery presence and health. `present: false` on desktops or when `system_profiler` returns no Battery Information section. When present: `cycle_count` (int), `condition` (string, e.g. `"Normal"`), `max_capacity_pct` (int, `%` stripped). Any unparseable field emits `null`; `present` remains `true`. When `system_profiler` fails the value is a placeholder `{"present": false}` and `collection_status.battery` is `unavailable`. |
| `hardware_health.storage[]` | `df -k` | One entry per real mounted volume (only `/dev/` nodes; devfs, map, and autofs entries excluded). Each entry: `mount` (string), `total_bytes` (int, 1K-block × 1024), `free_bytes` (int), `used_pct` (int, 0–100). `collection_status.storage` is `unavailable` (with `[]`) when `df` prints nothing, `partial` when `df` exits non-zero or a `/dev/` row does not parse. |
| `hardware_health.disks[]` | `diskutil list` + `diskutil info` | One entry per physical disk. Each entry: `device` (e.g. `"disk0"`), `smart_status` (string from SMART Status line, e.g. `"Verified"`, `"Not Supported"`), `internal` (bool, from the `Internal:` line, or `Device Location:` when that line is absent as on macOS 26), `solid_state` (bool). Virtual / synthesized entries are excluded. A missing SMART Status line is `"Undetermined"`. `collection_status.disks` is `unavailable` (with `[]`) when `diskutil list` fails, and `partial` when a disk's `diskutil info` fails or lacks its identifier, internal or solid-state line; that disk is left out rather than sent with guessed booleans. |
| `hardware_health.collection_status` | (derived) | `{"battery", "storage", "disks"}`, each `complete`, `partial` or `unavailable` (PAT-1720). The server replaces stored rows only for a `complete` section, upserts without deleting for `partial`, and writes nothing for `unavailable`. |
| `local_admins` | `dscl -plist . read /Groups/admin GroupMembership` | Top-level object carrying the roster behind `local_admin_count` (PAT-1974). `collection_status` is `complete` or `unavailable`; `accounts` is present only when `complete` and is omitted, never sent as `[]`, otherwise, so a failed read cannot read as "no standing admins" or prune the stored roster. Each entry: `name` (account short name), `principal_type` (always `user` on macOS — `/Groups/admin`'s `GroupMembership` holds individual account names), `builtin` (always `false`; `root` is filtered out of the roster as it is out of the count). Windows sends the same object plus a `sid` per entry, and also uses `group` and `unresolved` principal types. |

### Not configured versus not read (PAT-1767)

A compliance signal is a real value, the exact string `"NotConfigured"` (the read succeeded and the setting is absent), or null / `"Unknown"` (the read failed). The macOS agent sends null for a failed read, except the signals that already sent `"Unknown"` (the software update settings), which keep that spelling. The server rule decides what an absent setting means through `treat_not_configured_as`, which defaults to the rule's `treat_unknown_as`.

`defaults read` and NSUserDefaults report a missing key, a corrupt plist and an unreadable plist the same way (verified on macOS 26.6.2), so the collector only sends `"NotConfigured"` when the read reported the key missing and every plist it could have come from is absent or a readable dictionary (`prefs_defaults_read` and `prefs_plists_readable` in `lib/common.sh`). Signals that emit it today: the boolean and enum managed preferences (`firewall_stealth_mode`, `airdrop_disabled`, `airplay_receiver_disabled`, `time_server_host`, `time_server_enforced`, `wifi_menu_visible`, `bluetooth_menu_visible`, `siri_disabled`, `personalized_ads_disabled`, `loginwindow_fullname_prompt`, `loginwindow_password_hints`, `guest_account_disabled`, `dictation_on_device`, `firewall_logging`), the per-user preferences (`bluetooth_sharing_disabled`, `show_file_extensions`, `terminal_secure_keyboard`), the software update settings (`auto_security_updates`, `update_check_auto`, `update_download_auto`, `app_updates_auto_install`, `xprotect_data_auto_update`, `critical_updates_auto_install`), `time_machine_encrypted` (no Time Machine destinations) and `audit_retention_expire` (no `expire-after` line). `update_deferral_days` (no deferral set), `screensaver_idle_seconds` (idleTime not set for the subject user) and `install_log_retention_days` (`/etc/asl/com.apple.install` read and has no `ttl=`, as stock macOS 26.6.2 ships it; no file at all stays null) send it too (PAT-1775).

Numeric signals are written into the payload by `json_int_or_notconfigured` (`lib/common.sh`): a value that was read is a bare JSON integer, `"NotConfigured"` is a JSON string, and anything else is null. The `pwpolicy_*` signals still send null for an unset value: they parse parameter keys out of the global `pwpolicy -getaccountpolicies` output only, and a missing key there is not proof the control is absent (a per-user policy can set it, and a policy can express the same limit as a `policyContent` rule, as Apple's own default minimum length does), so `"NotConfigured"` would be a false claim (see `collect_auth` in `lib/auth.sh`).

---

## The three components

### 1. `patched-collect.sh` — collector (zsh)

Runs as root (Intune Platform Script or manual). On each run:
1. Reads `TENANT_ID` from `/etc/patched/tenant-id`; falls back to `"UNKNOWN"`.
2. Calls each `collect_<module>()` function (see `lib/` below).
3. Assembles a JSON file at `/var/db/patched/queue/inventory-YYYYMMDD-HHMMSS.json`.
4. Validates the output with Python's `json.load`; leaves a `.tmp` file for inspection if validation fails.

**Modular structure:** collection logic lives in `lib/*.sh` (one file per CIS section group, one `collect_<module>()` function each). `patched-collect.sh` is a thin orchestrator that sources the lib files and calls the functions in order.

| Module | File | Signals |
|---|---|---|
| common | `lib/common.sh` | `json_escape`, `read_managed_pref`, `console_user`, `log_warn`, `prefs_defaults_read`, `prefs_plists_readable` helpers |
| hardware | `lib/hardware.sh` | `SERIAL`, `HW_UUID`, `HOSTNAME`, `COMPUTER_NAME`, `HW_MODEL`, `ARCH`, `FIRST_USER`, CPU/RAM/disk specs |
| os | `lib/os.sh` | `OS_NAME`, `OS_VERSION`, `OS_BUILD`, `LAST_BOOT_ISO` |
| security | `lib/security.sh` | `FILEVAULT`, `SIP`, `GATEKEEPER`, `FW_STATE`, `XPROTECT_VER`, `MRT_VER`, `SSV`, `SECURE_BOOT` |
| updates | `lib/updates.sh` | `PENDING_UPDATES_COUNT`, `PENDING_UPDATES_JSON`, `PATCHES_JSON`, `AUTO_SECURITY_UPDATES` |
| sharing | `lib/sharing.sh` | `REMOTE_APPLE_EVENTS`, `REMOTE_LOGIN`, `SCREEN_SHARING` |
| screensaver | `lib/screensaver.sh` | `SCREENSAVER_PASSWORD`, `SCREENSAVER_DELAY_SECONDS`, `SCREENSAVER_IDLE_SECONDS`, `SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE` |
| auth | `lib/auth.sh` | `MDM_ENROLLED`, `MDM_ENROLLED_VIA_DEP`, deprecated `MDM_ENROLMENT`, `AUDIT_LOGGING`, `AUTO_LOGIN_USER`, `LOCAL_ADMIN_COUNT` / `LOCAL_ADMIN_ACCOUNTS` / `LOCAL_ADMIN_COLLECTION_STATUS` (set by `_collect_local_admins`; `local_admins_payload` emits the top-level object), `PW_POLICY_*` |
| sectools | `lib/sectools.sh` | `SECURITY_TOOLS_JSON_TMP` (10 AV/EDR path checks) |
| certs | `lib/certs.sh` | `CERTS_JSON_TMP` (system keychain cert array with expiry), `CERTS_COLLECTION_STATUS` (`complete`, `partial` or `unavailable`; `certs_payload_member` emits the key when `complete`, or `partial` with at least one certificate read, and `certs_collection_status` supplies `collection_status.certificates`) |
| inventory | `lib/inventory.sh` | `SYSEXT_JSON`, `BACKGROUND_ITEMS_JSON`, `ICLOUD_SIGNED_IN` |
| apps | `lib/apps.sh` | `APPS_JSON_FILE` (find /Applications loop), `APPS_COLLECTION_STATUS` (`complete`, `partial` or `unavailable`; stubbed `unavailable`; `apps_payload_array` sends `[]` under `unavailable` and `apps_collection_status` supplies `collection_status.apps`) |
| hardware_health | `lib/hardware_health.sh` | `HARDWARE_HEALTH_JSON_TMP` (battery, storage[], disks[] from system_profiler / df / diskutil) |

**Deployment artifact:** `dist/patched-collect.sh` is a single-file bundle produced by `build-bundle.sh` (inlines all `lib/*.sh` contents and stamps the collector's release `agent_version`). The `lib/` directory is not required at runtime. `dist/` is gitignored.

```bash
cd macos && bash build-bundle.sh --agent-version 0.15.0
```

The version is mandatory and must be numeric `X.Y.Z`. The release workflow
passes its resolved tag version; the builder rejects a missing, duplicated, or
mismatched collector version field rather than producing an artifact with stale
inventory provenance.

Important implementation notes:
- Uses `set -u` only (not `set -euo pipefail`) — macOS ships "fake binary" app stubs that trip `lipo` and `codesign` with non-zero exits.
- Hardcodes `python3` to `/usr/bin/python3` (Apple stock Python, always present with CLT) because `sudo` strips `PATH`.
- Never uses `path`, `cdpath`, etc. as variable names — zsh's `typeset -T` binds these to the `PATH` array silently.
- `FIRST_USER` is computed in `hardware.sh` (not inline) so `inventory.sh`, `backup.sh` and `screensaver.sh` can read it. `screensaver.sh` reads the console user and uses `FIRST_USER` only when nobody is logged in (PAT-1723).

### 2. File queue — `/var/db/patched/queue/`

`inventory-YYYYMMDD-HHMMSS.json` files persist until `patched-upload.sh` delivers them. The queue is the retry buffer: if the upload fails (network error, server unreachable), the file stays and is retried on the next LaunchDaemon tick. Files older than 7 days are dropped by the uploader.

### 3. `patched-upload.sh` + `com.patched.upload.plist` — uploader (LaunchDaemon)

The LaunchDaemon runs every 900 seconds (15 minutes). On each tick:
1. Loads credentials from `/etc/patched/` (see [Configuration](#configuration)).
2. Iterates `inventory-*.json` files in the queue.
3. For each file: computes HMAC-SHA256 of the body → POSTs to `api.patched.im/v1/inventory`.
4. **2xx:** removes the file (success).
5. **4xx:** logs the error, leaves the file for manual inspection. Auth failures need operator attention.
6. **5xx or network error:** leaves the file; it will retry on the next tick.
7. Drops files older than `MAX_AGE_DAYS=7`.

The 15-minute schedule is the retry interval — there is no exponential backoff or in-process retry loop. Files failing repeatedly will keep attempting for up to 7 days before being dropped.

### The updater (`patched-update.sh`) lives in the `updater` repo — not here

This repo is the **inventory agent** (collect + upload). The managed third-party
updater — which fetches the per-tenant app-update policy, runs the pinned
Installomator fork, and honours the `per_app_patch` per-app toggle — is the
hardened endpoint daemon in **`Patched-LTD/updater`** at `endpoint/patched-update.sh`
(+ `endpoint/com.patched.update.plist`). That daemon does bundle-integrity
verification and Team-ID/notarization-gated installs; deploy it from the
`updater` release bundle, not from here.

> A duplicate `patched-update.sh` briefly lived in this directory (PAT-365). It
> was a divergent re-implementation against stock Installomator and was removed
> in PAT-383; the per-app toggle now ships in the canonical `updater` daemon.

---

## Deployment via Intune

The v1 agent is deployed as an Intune Platform Script (runs as root, bypasses Gatekeeper — notarisation not required).

**What goes into Intune:**

| Component | Intune mechanism | Target location |
|---|---|---|
| `dist/patched-collect.sh` | Platform Script (run as root, daily recurring) | Executes directly from Intune's temp path |
| `patched-upload.sh` | Platform Script (run once, copies to `/Library/Patched/`) | `/Library/Patched/patched-upload.sh` |
| `com.patched.upload.plist` | Custom Configuration Profile or Platform Script | `/Library/LaunchDaemons/com.patched.upload.plist` |
| Tenant credentials | Custom Configuration Profile (file delivery) | `/etc/patched/tenant-id`, `bearer-token`, `hmac-secret` |

> The managed updater (`patched-update.sh` / `com.patched.update.plist`) is deployed
> separately from the `Patched-LTD/updater` release bundle — see that repo's
> `endpoint/README.md`. It is not part of this inventory-agent deployment.
>
> **PAT-1126: deploy it anyway, every time.** A Mac running only this
> collector has no expiry/decommission mechanism at all — it never sees a
> decommission directive and never self-removes. That matters most for
> Endpoint Assurance assessment installs, which are supposed to expire
> cleanly after 2-4 weeks. Collector-only is no longer a supported end
> state for any deployment method, Intune included: always push the
> `endpoint/` bundle's Platform Script alongside this one. There is no
> code-level guardrail against a collector-only Intune profile (this repo
> does not control the Intune console), so treat this as a hard deployment
> rule, not a suggestion — and see "Degraded-health signal" below for the
> safety net that catches it if it's ever missed.

**Credential files** must be created at `/etc/patched/` with permissions `600` (root-owned). The Intune configuration profile that delivers them should run before the collect script, or the collector falls back to `UNKNOWN` tenant ID.

**LaunchDaemon loading:**
```bash
sudo launchctl load -w /Library/LaunchDaemons/com.patched.upload.plist
```
Or via Intune after the plist is in place.

---

## Deployment via GitHub Release (interim, unsigned)

For machines not managed by Intune — tenant-zero, your own Macs, consenting early users — the agent ships as an **unsigned GitHub Release tarball**. This is the interim path until the signed `.pkg` (Apple Developer ID + notarisation) lands post-incorporation. Unsigned shell scripts run fine when an admin executes them in a terminal; Gatekeeper only blocks Finder-launched, quarantined downloads. **This is not a public self-service installer** — it targets endpoints you control.

**Build + publish a release** (CI, `.github/workflows/macos-agent-release.yml`):

```bash
git tag macos-agent-v0.6.0 && git push origin macos-agent-v0.6.0
# or run the workflow manually with a version input
```

The workflow lints the installer scripts, runs `build-bundle.sh --agent-version <resolved-release-version>`, and attaches `patched-agent-macos-<version>.tar.gz` (plus `SHA256SUMS`) to the Release. The tarball contains the bundled collector stamped with that exact version, the uploader, **both** collector LaunchDaemons, `install.sh` / `uninstall.sh`, **and the endpoint bundle** (`patched-updater/`, `endpoint-install.sh`, `endpoint-uninstall.sh`, hash-pinned by `tools/build-bundle.sh` — the same bundler `release-endpoint.yml` uses). `install.sh` always installs both halves; there is no collector-only artifact (PAT-1126).

**Install on a target** (admin, in Terminal — do not double-click):

```bash
tar xzf patched-agent-macos-0.6.0.tar.gz
cd patched-agent-macos-0.6.0
sudo ./install.sh \
  --tenant-id   <uuid> \
  --bearer-token <token> \
  --hmac-secret  <base64-32-bytes>
```

Credentials may instead come from the environment (`PATCHED_TENANT_ID` / `PATCHED_BEARER_TOKEN` / `PATCHED_HMAC_SECRET`), from `--creds-dir DIR`, or interactive prompts. Override the endpoint with `--api-url` (persisted into the uploader daemon's environment). The same run also installs `patched-updater/` (endpoint bundle) via the bundled `endpoint-install.sh` — no separate step needed, and `install.sh` refuses to proceed collector-only if that sibling script is missing from the tarball.

**Where the entrypoints live (PAT-2395).** `install.sh` installs `patched-collect.sh` and `patched-upload.sh` to `/Library/Patched`, and the LaunchDaemons execute them from there. They used to live in `/usr/local/bin`, which Homebrew hands to the logged-in user on many Macs: a root-owned script in a directory someone else owns can be replaced by that directory's owner, so file ownership alone protected nothing. Before writing anything the installer checks that every component of `/Library/Patched` (`/`, `/Library`, and the tree itself if it already exists) is a real directory, owned by root, and not writable by group or other. A symlink, a user-owned component or a writable one stops the install with nothing written, and an existing install is left as it was. A `/Library/Patched` that already exists but fails the check is refused, not repaired.

The same check reads each component's ACL (PAT-2398). An ACL entry that lets anyone other than root add, delete or change things in one of those directories stops the install in the same way, with the directory and the principal named. Entries for groups count, `admin` and `wheel` included; deny entries and read-only entries do not. `install.sh` and `uninstall.sh` also ignore the PATH they are started with: they reset it to the system directories and call every tool by its full system path.

Upgrading over an older release moves the entrypoints: once the new tree is installed and the daemons are loaded from the new plists, the installer deletes `/usr/local/bin/patched-collect.sh` and `/usr/local/bin/patched-upload.sh` (and, from a source-tree install, its own modules in `/usr/local/bin/lib`, removing that directory only if it is then empty). It never changes the owner or mode of `/usr/local` or `/usr/local/bin`, and touches nothing else in them. Credentials in `/etc/patched` and the queue in `/var/db/patched` are kept. `uninstall.sh` removes `/Library/Patched` and the same legacy files.

`com.patched.bootstrap.plist` also names `/Library/Patched/patched-bootstrap.sh` now, but nothing in this repository installs that plist or script, so there is no migration for it: whatever deploys the bootstrap loader has to place the script in `/Library/Patched` itself. The versioned collector tree it runs from (`/var/lib/patched/collector`) and the endpoint bundle in `/usr/local/patched-updater` are not covered by this check.

**Key difference from the Intune path:** this path installs a **collector LaunchDaemon** (`com.patched.collect`, runs at load + daily) because there's no Intune Platform Script to trigger collection. The Intune path does not install it.

```bash
sudo launchctl list | grep com.patched   # com.patched.collect + com.patched.upload
sudo ./uninstall.sh                       # remove (add --purge to drop creds + queue;
                                           # also removes the endpoint bundle installed
                                           # alongside it, if present)
```

`uninstall.sh` checks the ancestry of `/Library/Patched` the same way before deleting it (PAT-2420). If a component of that path is a symlink, is not owned by root, or can be written by someone else, the directory is left in place and named, everything else is still removed (the daemons are stopped and unloaded), and the script exits with status 2. Repair the named component and run it again.

---

## Degraded-health signal for a stale collector-only box (PAT-1126)

Every install path in this repo now always installs the `endpoint/` bundle, so
collector-only should not be reachable through `install.sh` or the release
tarball. It can still happen in the field: a box installed before PAT-1126, or
an Intune deployment that only pushed the collector's Platform Script (see the
warning in the Intune section above). `patched-upload.sh` checks for this on
every run — `/Library/LaunchDaemons/com.patched.config-poll.plist` present
*and* loaded — and reports a `capability_missing` / `endpoint_decommission_daemon`
fault through the shared `agent_health` store (`macos/lib/agent_health.sh`,
PAT-1065) when it isn't, rather than staying silently inert. See
`macos/test-endpoint-decommission-health.zsh`.

---

## Local testing on a dev Mac

```bash
# 1. Write test credentials (replace with your actual local-test tenant values)
sudo mkdir -p /etc/patched
sudo bash -c 'echo "YOUR-TENANT-UUID" > /etc/patched/tenant-id'
sudo bash -c 'echo "YOUR-BEARER-TOKEN" > /etc/patched/bearer-token'
sudo bash -c 'echo "YOUR-HMAC-SECRET-B64" > /etc/patched/hmac-secret'
sudo chmod 600 /etc/patched/*

# 2. Run the collector manually
sudo /path/to/patched-collect.sh

# 3. Inspect the generated payload before uploading
ls -la /var/db/patched/queue/
cat /var/db/patched/queue/inventory-*.json | python3 -m json.tool | head -50

# 4. Upload manually (or override the API URL for local testing)
sudo PATCHED_API_URL=http://127.0.0.1:8080 /path/to/patched-upload.sh
```

**Verify on the server side (via Tailscale):**
```bash
ssh root@example-api-host
psql -h 127.0.0.1 -U patched -d patched -c \
  "SELECT id, received_at, length(body::text) AS bytes FROM raw_payloads ORDER BY received_at DESC LIMIT 3;"
```

---

## Configuration

All configuration lives under `/etc/patched/` (root-owned, mode `600`).

| File | Contents | Who reads it |
|---|---|---|
| `/etc/patched/tenant-id` | UUID (one line, no trailing whitespace) | `patched-collect.sh` |
| `/etc/patched/bearer-token` | Opaque bearer token from `POST /admin/tenants` | `patched-upload.sh` |
| `/etc/patched/hmac-secret` | Base64-encoded 32-byte HMAC secret from `POST /admin/tenants` | `patched-upload.sh` |

The uploader decodes the base64 HMAC secret in Python before use — the file contains the base64 form, not the raw bytes.

The target API URL defaults to `https://api.patched.im`. Override for local/staging:
```bash
sudo PATCHED_API_URL=http://127.0.0.1:8080 ./patched-upload.sh
```

---

## Debugging customer issues

**Log locations:**

| Log | Contents |
|---|---|
| `/var/log/patched-collect.log` | Collector run output (tee'd) |
| `/var/log/patched-upload.log` | Uploader run output (tee'd) |
| `/var/log/patched-upload.out` | LaunchDaemon stdout |
| `/var/log/patched-upload.err` | LaunchDaemon stderr |

**Queue inspection:**
```bash
sudo ls -lht /var/db/patched/queue/    # pending files (ordered by time)
sudo ls /var/db/patched/queue/ | wc -l # how many are queued
```

**Common failure modes:**

| Symptom | Cause | Fix |
|---|---|---|
| Upload logs `CLIENT ... -> 401` | Wrong bearer token or HMAC secret | Re-deploy `/etc/patched/bearer-token` and `/etc/patched/hmac-secret` from the original `POST /admin/tenants` response |
| Upload logs `NET ... -> network error or timeout` | Device offline or `api.patched.im` unreachable | Check device internet connectivity; verify `curl https://api.patched.im/health` |
| Collector produces `UNKNOWN` tenant ID | `/etc/patched/tenant-id` missing or unreadable | Re-deploy the file; check permissions (`ls -la /etc/patched/`) |
| Queue files accumulate and never clear | LaunchDaemon not loaded | `sudo launchctl list com.patched.upload` — if not found, load the plist |
| Collector exits 0 but queue file has `.tmp` extension | JSON validation failed | Inspect `/var/db/patched/queue/.inventory-*.tmp`; check the log |
| Upload succeeds but device missing from dashboard | Extractor lag | Check `raw_payloads.extraction_error` on the server side |

---

## v1 → v2 roadmap

**v1 (current):** unsigned shell scripts. Two delivery paths, same scripts:
- **Intune** — Platform Scripts run as root, bypassing Gatekeeper.
- **GitHub Release** (interim) — unsigned tarball + `install.sh`, run by an admin in a terminal (see [Deployment via GitHub Release](#deployment-via-github-release-interim-unsigned)). Adds a collector LaunchDaemon since there's no Intune trigger.

Neither path is safe for unmanaged user-self-install — macOS blocks unsigned scripts downloaded and launched from Finder.

**v2 (gated on incorporation):** once Patched.im Ltd. is incorporated and an Apple Developer ID is issued:
- Wrap collector + uploader in a signed `.pkg` with a `postinstall` script.
- The `.pkg` satisfies Gatekeeper for self-install + direct download scenarios.
- The LaunchDaemon plist moves into the `.pkg` `Scripts/` folder and loads at install time.
- Notarised packages can be distributed outside the App Store.

The shell scripts themselves won't change substantively — the v2 change is the packaging and signing layer only.
