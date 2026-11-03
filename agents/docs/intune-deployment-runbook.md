# Patched Agent — Intune Deployment Runbook

> **Current path (v1 — Platform Script, unsigned).**
> Once the signed `.pkg` ships (gated on incorporation, PAT-9), this runbook gains an "Add .pkg as a Line of Business App" section and the PPPC profile step is simplified. Mark with a TODO where noted.

---

## Prerequisites

| Item | Where to get it |
|---|---|
| Microsoft Intune admin access | Your Azure tenant — Global Admin or Intune Service Admin role |
| `dist/patched-collect.sh` | Latest GitHub Release — `patched-agent-macos-<version>.tar.gz` → extract → `patched-collect.sh` |
| `patched-upload.sh` | Same tarball |
| `com.patched.upload.plist` | Same tarball |
| Tenant credentials | From Patched onboarding: `tenant-id`, `bearer-token`, `hmac-secret` |
| Target device group | An Entra ID group containing your pilot Macs |

---

## Step 1 — Create the credential Configuration Profile

The agent reads credentials from `/etc/patched/`. The profile delivers these files before the collector runs.

1. In Intune: **Devices → macOS → Configuration Profiles → Create → New Policy**
2. **Profile type:** Templates → Custom
3. **Name:** `Patched Agent Credentials`
4. Upload a `.mobileconfig` that delivers three files as `com.apple.configurationprofile` payloads:

   ```xml
   <!-- Minimal skeleton — use Apple Configurator 2 or Jamf Profile Builder for the full envelope -->
   <key>PayloadContent</key>
   <array>
     <!-- /etc/patched/tenant-id -->
     <dict>
       <key>PayloadType</key>  <string>com.apple.managed-file</string>
       <key>DestinationPath</key> <string>/etc/patched/tenant-id</string>
       <key>Content</key>         <string>YOUR-TENANT-UUID</string>
       <key>Permissions</key>     <string>0600</string>
       <key>Owner</key>           <string>root:wheel</string>
     </dict>
     <!-- repeat for bearer-token and hmac-secret -->
   </array>
   ```

   > **Important:** set `Permissions: 0600` and `Owner: root:wheel` on each file. Patched validates these at startup; a world-readable credential file fails the check.

5. **Assignment:** assign to your pilot device group. **Do not** assign to all devices yet.
6. Click **Review + create**.

---

## Step 2 — Deploy the upload LaunchDaemon

The uploader runs every 15 minutes as a LaunchDaemon (root context).

1. **Devices → macOS → Shell scripts → Add**
2. **Name:** `Patched Agent — Install Uploader`
3. **Script content:** paste `patched-upload.sh` (from the release tarball) or upload it directly.
4. **Run as:** root
5. **Frequency:** Once (not recurring — it's an install script; the LaunchDaemon provides the recurring schedule)
6. **Assignment:** same pilot group as the credential profile.

> **Install path changed (PAT-2395).** The uploader runs as root from `/Library/Patched/patched-upload.sh`, the path `com.patched.upload.plist` now names. It used to be `/usr/local/bin/patched-upload.sh`; that directory is user-owned on Macs with Homebrew, so its owner could replace the script root runs. Three things outside this repository must change together with the plist, or the daemon will point at a file that is not there:
>
> 1. The Intune install script must create `/Library/Patched` as `root:wheel`, mode `0755`, and copy `patched-upload.sh` into it (`root:wheel`, `0755`), instead of copying to `/usr/local/bin`. It must not `chown` or `chmod` `/usr/local/bin`.
> 2. Any sudoers entry that pins the collector paths for `patched-collect-trigger.sh` must name `/Library/Patched/patched-collect.sh` and `/Library/Patched/patched-upload.sh`.
> 3. On devices that already have the old copy, the script should delete `/usr/local/bin/patched-upload.sh` after the new one is in place and the daemon has been reloaded.
>
> The release tarball's `install.sh` does all of this itself and verifies the directory's ancestry first; the Intune script is a separate rail and does not get that check for free.

> **Ordering matters:** the credential profile must be installed before this script runs. Use a custom attribute or a scripted check at the top of `patched-upload.sh` to abort cleanly if `/etc/patched/bearer-token` is missing.

---

## Step 3 — Deploy the LaunchDaemon plist

1. **Devices → macOS → Shell scripts → Add**
2. **Name:** `Patched Agent — Load Upload LaunchDaemon`
3. **Script:**

   ```bash
   #!/bin/bash
   set -u

   PLIST_DST="/Library/LaunchDaemons/com.patched.upload.plist"
   PLIST_SRC="$(dirname "$0")/com.patched.upload.plist"

   # Deploy the plist
   install -o root -g wheel -m 644 "$PLIST_SRC" "$PLIST_DST"

   # Load (or reload) it
   launchctl bootout system "$PLIST_DST" 2>/dev/null || true
   launchctl bootstrap system "$PLIST_DST"
   ```

   In practice this is simplest as a Platform Script that embeds the plist content inline rather than referencing a relative path — embed the plist XML directly in the script and write it to `$PLIST_DST`.

4. **Run as:** root; **Frequency:** Once
5. **Assignment:** same pilot group

---

## Step 4 — Deploy the collector (Platform Script)

The collector runs daily (or manually) as a Intune Platform Script.

1. **Devices → macOS → Shell scripts → Add**
2. **Name:** `Patched Agent Collector`
3. **Script content:** paste `dist/patched-collect.sh` (the bundled single-file version from the release tarball — **not** the `macos/` source, which requires the `lib/` directory).
4. **Run as:** root
5. **Frequency:** Daily (Intune re-runs Platform Scripts on a daily schedule when set to recurring)
6. **Assignment:** pilot group

---

## Step 5: Full Disk Access (not yet supported)

The collector runs as root, but root is not exempt from macOS privacy protection (TCC). Without Full Disk Access, macOS lets the collector see that Chrome, Edge and Firefox data folders exist but refuses to open them. Browser extension inventory for those browsers is then reported as partial, and the collect log says `macOS privacy protection denied access to N browser data folder(s) (Full Disk Access is not granted to the Patched collector)`. When the collector runs as its LaunchDaemon (`macos/install.sh`), the device also reports the agent health entry `tcc_denied` / `browser_extensions` / `full_disk_access_missing`. A collector run as an Intune shell script (Step 4) logs the same line but does not write that entry, because only the LaunchDaemon run records it.

There is no supported way to grant it yet. The collector is a script, and a Full Disk Access grant has to name a signed executable. A supported grant needs a dedicated, signed Patched collector binary, which is tracked as a follow-up and depends on Developer ID signing (PAT-7, PAT-9). Until then, expect partial Chrome, Edge and Firefox coverage on these Macs.

> **Do not grant Full Disk Access to `/bin/zsh`, `/bin/bash` or Terminal to work around this.** Any local user can run those, so the grant would let any user on the Mac read every other user's private data.

Earlier versions of this runbook suggested a PPPC profile naming `com.patched.collect` as a bundle ID. That granted nothing: `com.patched.collect` is a launchd label, not the identifier of a signed bundle. Remove any such profile.

---

## Step 6 — Verify the pilot

Allow 30–60 minutes for Intune to check in and apply all scripts.

**On a test device (in Terminal or via Remote Desktop):**

```bash
# Check credentials landed
ls -la /etc/patched/

# Run collector manually
sudo /path/to/patched-collect.sh

# Verify queue file was produced
sudo ls -lh /var/db/patched/queue/

# Run uploader manually
sudo /Library/Patched/patched-upload.sh

# Logs
tail -f /var/log/patched-upload.log
tail -f /var/log/patched-collect.log
```

**In the Patched dashboard:**
- Navigate to **Devices** — your pilot device should appear within a few minutes of a successful upload.
- Check **last seen** timestamp and inventory fields (OS version, FileVault, Gatekeeper) to confirm the payload is being processed.

---

## Step 7 — Expand rollout

Once the pilot is clean (no 401s in upload log, devices appear in dashboard):

1. Update each policy's **Assignment** from the pilot group to a broader group or **All Devices**.
2. Do this in order: credentials profile first, then collector, then uploader.
3. Monitor `Upload failures` in the Patched dashboard for the first 24 hours.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Device not appearing in dashboard | Upload failing or not yet run | Check `/var/log/patched-upload.log` on device |
| `401 Unauthorized` in upload log | Wrong bearer token or HMAC secret | Redeploy credential profile with correct values |
| `NET ... connection refused` | `api.patched.im:443` blocked by firewall | Whitelist `api.patched.im:443` (TLS, no inspection) |
| Collector exits 0, no queue file | JSON validation error | Check `/var/log/patched-collect.log`; look for `.tmp` files in queue dir |
| Upload LaunchDaemon not running | Plist not loaded | `sudo launchctl list com.patched.upload`; reload if absent |
| `/etc/patched` files missing | Credential profile not applied yet | Check Intune device status for the credential profile |
| `ERROR: tenant-id not found` in collector | Credential profile applied after collector ran | Wait for next daily run, or trigger manually |
| `macOS privacy protection denied access to N browser data folder(s)` in collector log | Full Disk Access not granted to the collector | Expected until the signed collector binary lands (see Step 5); Chrome, Edge and Firefox coverage stays partial and the log line and any `tcc_denied` agent health entry persist. Do not grant Full Disk Access to a shell or Terminal |

---

## Uninstall

```bash
# Remove LaunchDaemon
sudo launchctl bootout system /Library/LaunchDaemons/com.patched.upload.plist
sudo rm /Library/LaunchDaemons/com.patched.upload.plist

# Remove agent scripts
sudo rm -rf /Library/Patched
# Devices installed before PAT-2395 also have the old copy:
sudo rm -f /usr/local/bin/patched-upload.sh

# Remove credentials (caution — confirms removal before proceeding)
sudo rm -rf /etc/patched/

# Remove queue and logs (optional — contains inventory history)
sudo rm -rf /var/db/patched/ /var/log/patched-*.log /var/log/patched-*.out /var/log/patched-*.err
```

In Intune, remove the device from the pilot/target group and delete the Platform Script assignments. The scripts will not re-run after removal from the group.

---

## Version history

| Version | Notes |
|---|---|
| v1 (current) | Platform Script path — unsigned, requires explicit root execution |
| v2 (planned, PAT-9) | Signed `.pkg` + Gatekeeper notarisation — simplifies PPPC, enables Finder-install |
| PAT-2096 | The earlier PPPC example naming `com.patched.collect` as a bundle ID is withdrawn: it named a launchd label rather than a signed bundle and granted nothing. Full Disk Access waits for a signed collector binary |
