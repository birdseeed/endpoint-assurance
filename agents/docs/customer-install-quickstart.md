# Patched Agent — Install / Uninstall Quickstart

One-page reference for a customer admin deploying the Patched macOS agent via Intune.
For the full step-by-step runbook, see `docs/intune-deployment-runbook.md`.

---

## What you need

- Intune admin access (Intune Service Admin or Global Admin)
- The release tarball: `patched-agent-macos-<version>.tar.gz` (from your Patched onboarding email or the Patched dashboard)
- Your tenant credentials: `tenant-id`, `bearer-token`, `hmac-secret` (from the Patched dashboard → Settings → API Credentials)
- An Entra ID device group for your pilot Macs

---

## Deploy — 5 steps

**1. Credentials Configuration Profile**
Create a macOS Custom Configuration Profile that writes three files to `/etc/patched/` (`root:wheel 0600`):
- `/etc/patched/tenant-id` — your tenant UUID
- `/etc/patched/bearer-token` — your bearer token
- `/etc/patched/hmac-secret` — your HMAC secret (base64)

Assign to your pilot group. Apply this **before** the scripts below.

**2. Full Disk Access: nothing to deploy yet**
There is no supported Full Disk Access grant for the collector yet; see "Full Disk Access" below. Skip this step, and do not grant it to a shell or Terminal instead.

**3. Collector (Platform Script, recurring daily)**
Upload `dist/patched-collect.sh` as a Platform Script (run as root, **daily**). This gathers inventory and drops it to `/var/db/patched/queue/`.

**4. Uploader script + LaunchDaemon (Platform Script, once)**
Upload `patched-upload.sh` as a Platform Script (run as root, **once**). This installs the uploader at `/Library/Patched/patched-upload.sh` (a root-owned directory; see the runbook for why it is no longer `/usr/local/bin`) and loads `com.patched.upload.plist` as a LaunchDaemon. The daemon fires every 15 minutes to POST the queue to `api.patched.im`.

**5. Verify**
Wait 30–60 minutes, then check: the device should appear in the Patched dashboard under **Devices**.

---

## Full Disk Access

The collector runs as root, and macOS still asks for Full Disk Access before root can read another app's data, such as browser profiles. Without it, Chrome, Edge and Firefox extension inventory is reported as partial, the collect log says `macOS privacy protection denied access to N browser data folder(s) (Full Disk Access is not granted to the Patched collector)`, and a Mac running the collector LaunchDaemon shows the agent health entry `tcc_denied` / `browser_extensions`.

A supported grant needs a dedicated, signed Patched collector binary, which is tracked as a follow-up. Until it ships there is nothing to deploy, through MDM or by hand.

**Do not grant Full Disk Access to `/bin/zsh`, `/bin/bash` or Terminal to work around this.** Any local user can run those, so the grant would let any user on the Mac read every other user's private data.

Earlier guidance suggested a PPPC profile naming `com.patched.collect` as a bundle ID. That granted nothing, because `com.patched.collect` is a launchd label and not a signed bundle. Remove any such profile.

---

## Verify on a device

```bash
# Credentials delivered?
ls -la /etc/patched/

# Run collector manually (skip waiting for daily Intune trigger)
sudo /path/to/patched-collect.sh

# Check queue has a file
sudo ls /var/db/patched/queue/

# Force an upload
sudo /Library/Patched/patched-upload.sh

# Check logs for errors
tail /var/log/patched-upload.log
```

---

## Expand rollout

Once pilot devices appear in the dashboard with correct data:
1. Update each Intune policy assignment from the pilot group to **All Devices** (or your broader target group).
2. Order: credentials profile → collector → uploader.

---

## Uninstall

In Intune: remove device from the target group and delete the script assignments.

On device (if manual removal is needed):

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.patched.upload.plist
sudo rm /Library/LaunchDaemons/com.patched.upload.plist
sudo rm -rf /Library/Patched
sudo rm -f /usr/local/bin/patched-upload.sh   # only present on installs made before the path moved
sudo rm -rf /etc/patched/                # removes credentials
sudo rm -rf /var/db/patched/            # removes queue (optional)
```

---

## Common errors

| Error in upload log | Fix |
|---|---|
| `401 Unauthorized` | Re-deploy credential profile — bearer token or HMAC secret is wrong |
| `Connection refused` / `network error` | Whitelist `api.patched.im:443` in your firewall |
| Device missing from dashboard | Check `/var/log/patched-upload.log` on the device |
| `tenant-id: UNKNOWN` in upload log | `/etc/patched/tenant-id` missing — credential profile not yet applied |
