# Patched Agent — Windows Intune Deployment Runbook

> **Current paths (v1 — MSI Win32 app, unsigned).**
> The MSI is unsigned pending Authenticode OV/EV certificate acquisition (PAT-50). Windows
> Defender SmartScreen will warn on manual install; Intune Win32 deployments bypass SmartScreen
> (the package is pushed silently by the management plane, not run interactively). A signed MSI
> will be available once PAT-50 lands — this runbook gains a "signed/notarised" note then.

For the macOS runbook, see `docs/intune-deployment-runbook.md`.

---

## Prerequisites

| Item | Where to get it |
|---|---|
| Microsoft Intune admin access | Your Azure tenant — Global Admin or Intune Service Admin role |
| `PatchedAgent-<version>.msi` | Latest GitHub Release (`windows-agent-v*`) — `PatchedAgent-<version>.msi` |
| `SHA256SUMS` | Same release — verify before uploading to Intune |
| Enrolment token | From Patched onboarding: a single-use `ENROLLMENT_TOKEN`, minted per deployment and consumed the first time a device enrols. Recommended; see the warning below if you need the raw `tenant-id` / `bearer-token` / `hmac-secret` set instead. |
| Microsoft Win32 Content Prep Tool | Required for Path B only — [download from Microsoft](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool) |
| Target device group | An Entra ID group containing your pilot Windows devices |

**Verify the MSI before uploading:**

```powershell
# PowerShell — compare against the hash in the GitHub release notes
(Get-FileHash 'PatchedAgent-<version>.msi' -Algorithm SHA256).Hash.ToLower()
```

Or use the bundled verify tool. It checks the release's HMAC-SHA256 signature
(PAT-892) as the primary check, plus SHA-256 as a secondary check; ask Andy
for the `ARTIFACT_SIGNING_KEY` value out of band and supply it via
`--key-file` or the `ARTIFACT_SIGNING_KEY` environment variable, never as a
plain argument:

```sh
ARTIFACT_SIGNING_KEY=... python3 tools/verify-agent-release.py \
  --release windows-agent-v<version> \
  --file PatchedAgent-<version>.msi
```

Exit 0 = verified. Do not deploy a release whose HMAC signature you have not
independently verified - the MSI is unsigned in this interim release, so
integrity depends entirely on the published signature, not the hash alone.
See `docs/agent-release-runbook.md` for the full verification procedure.

---

## Delivery method comparison

| | Path A — Platform Script | Path B — Win32 App (.intunewin) |
|---|---|---|
| Complexity | Lower | Higher |
| Intune license required | Intune P1 or higher | Intune P1 or higher |
| Install runs as | SYSTEM (enforced by Intune) | SYSTEM (Win32 default) |
| Credential delivery | PowerShell script sets registry env vars | `ENROLLMENT_TOKEN` property → credential file store → Credential Manager |
| Detection rule | Intune script output / service presence | Registry / file presence |
| Recommended for | Most tenants — simpler to maintain | Tenants needing Win32 app lifecycle (reporting, supersedence, uninstall via Intune) |

---

## Path A — Platform Script (recommended)

> **Note:** Live Intune portal steps verified against Intune admin centre — portal UI may vary. Confirm each step in your tenant.

This path deploys the Patched Agent MSI via an Intune Platform Script (PowerShell). The script
runs silently as SYSTEM, passes the enrolment token to `msiexec` as a secure property, and starts
the `Patched Agent` Windows service automatically.

### Step A1 — Prepare the install script

Create a PowerShell script that:

1. Downloads or embeds the MSI (or copies from a UNC share / Azure Blob).
2. Passes the enrolment token to `msiexec` as a secure property. A deferred custom action writes it
   to `%ProgramData%\Patched\creds\enrollment-token`; the agent exchanges it for per-device
   credentials, moves them into Windows Credential Manager (DPAPI-protected) on its first run cycle
   and deletes the token file.
3. Starts the service (the MSI `ServiceControl` element starts it automatically on install, so
   this is a belt-and-braces check).

```powershell
#Requires -RunAsAdministrator
<#
  Patched Agent — silent install script for Intune Platform Script deployment.
  The enrolment token is passed as an msiexec property. The installer writes it to
  HKLM\SOFTWARE\Patched\Enrollment; on first service start the agent exchanges it for
  per-device credentials via POST /v1/enrol and stores those in Windows Credential
  Manager (DPAPI-protected). Nothing is written to disk in plaintext.
#>

param()

# ── Configuration ─────────────────────────────────────────────────────────────
# Replace this with your tenant's single-use enrolment token from the Patched
# dashboard (Settings → API Credentials → New enrolment token). In production,
# inject it via Intune script parameters or retrieve it from a secrets store
# (e.g. Azure Key Vault). Mint a fresh token per deployment; it is consumed on
# first use.
$EnrollmentToken = '<YOUR-ENROLLMENT-TOKEN>'

# MSI source — either a URL (downloaded below) or a local/UNC path.
$MsiUrl  = '`Patched-LTD/updater`/PatchedAgent-<version>.msi'
$MsiPath = Join-Path $env:TEMP 'PatchedAgent.msi'
# ──────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'Stop'

# Download MSI if not already present (e.g. from a UNC deployment share, skip this block).
Write-Host 'Downloading Patched Agent MSI...'
Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing

# Silent install. The enrolment token is exchanged for credentials on first service start.
Write-Host 'Installing Patched Agent...'
$msiArgs = @(
    '/qn',
    '/i', $MsiPath,
    "ENROLLMENT_TOKEN=`"$EnrollmentToken`""
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "msiexec exited $($proc.ExitCode) — check %TEMP%\MSI*.LOG for details."
}

# Belt-and-braces: confirm service is running.
$svc = Get-Service -Name 'Patched Agent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') {
    Start-Service -Name 'Patched Agent'
}

Write-Host 'Patched Agent installed successfully.'
```

> **Credential security:** the enrolment token is held in memory only for the duration of the
> installer process, then written by a deferred custom action to
> `%ProgramData%\Patched\creds\enrollment-token`, which allows SYSTEM and Administrators only. The
> agent deletes that file once it has exchanged the token and moved the resulting credentials into
> Windows Credential Manager (DPAPI-protected, `CRED_PERSIST_LOCAL_MACHINE`). Neither the agent nor
> a verbose (`/l*v`) MSI log records the token (PAT-1755). Do not store the script itself in a
> world-readable location, treat it as a secret, and mint a fresh token per deployment.

> **There is no raw-credential install option (PAT-1755).** `TENANT_ID`, `BEARER_TOKEN` and
> `HMAC_SECRET` were removed as MSI properties on 2026-09-15: they are long-lived, unlike the
> single-use 24-hour enrolment token, and putting them on an `msiexec` command line exposed them to
> process listings, command-line process-creation auditing, endpoint security telemetry and the
> logs of whatever tool ran `msiexec`. Passing them now does nothing at all; the install proceeds
> as a bare install.
>
> Provision a device that genuinely cannot use an enrolment token after a bare install, as SYSTEM
> on the device:
>
> ```powershell
> cmdkey /generic:PatchedAgent/TenantId    /user:PatchedAgent /pass:<tenant-id>
> cmdkey /generic:PatchedAgent/BearerToken /user:PatchedAgent /pass:<bearer-token>
> cmdkey /generic:PatchedAgent/HmacSecret  /user:PatchedAgent /pass:<hmac-secret>
> ```
>
> The service picks these up within 5 minutes, with no restart. See
> `windows/installer/README-install.md`, "Post-install credential provisioning".
>
> Treat any log that may have recorded a raw-credential install from an older MSI as secret:
> restrict who can read it, do not attach it to tickets, and rotate the credentials
> (`docs/credential-storage.md`) if such a log has been shared.

### Step A2 — Upload the script to Intune

1. In Intune: **Devices → Windows → PowerShell scripts → Add**
2. **Name:** `Patched Agent — Install`
3. **Description:** `Installs the Patched Agent MSI silently and provisions credentials.`
4. Upload the script prepared in Step A1.
5. Under **Script settings:**
   - **Run this script using the logged-on credentials:** No (run as SYSTEM)
   - **Enforce script signature check:** No (script is unsigned in this interim release — see the AV/Defender note below)
   - **Run script in 64-bit PowerShell host:** Yes
6. **Scope tags:** apply as appropriate for your organisation.
7. Click **Next → Assignments.**

### Step A3 — Assign to pilot group

1. **Assignments → Add group → Required**
2. Select your pilot device group. **Do not** assign to All Devices yet.
3. Click **Next → Review + create → Create**.

### Step A4 — Verify script execution

After 30–60 minutes (next Intune check-in cycle):

1. In Intune: **Devices → Windows → PowerShell scripts → Patched Agent — Install**
2. Under **Device status**, find your pilot device — status should be **Success**.
3. On the device (as an administrator), confirm the service is running:

```powershell
Get-Service -Name 'Patched Agent' | Select-Object Status, StartType
# Expected: Status=Running, StartType=Automatic
```

4. Confirm credentials were written to Credential Manager:

```powershell
# Lists all Patched credential entries — blobs are not shown
cmdkey /list | Select-String 'PatchedAgent'
# Expected after the first run cycle: three entries: PatchedAgent/TenantId,
# PatchedAgent/BearerToken, PatchedAgent/HmacSecret. Before enrolment the device holds only
# %ProgramData%\Patched\creds\enrollment-token, which the agent deletes once it has exchanged it.
```

5. Check the service log for a successful inventory POST:

```powershell
Get-Content "$env:ProgramData\Patched\logs\patched-agent.log" -Tail 40
# Look for: "Run cycle start" and "update-status.json written — overall=UpToDate" (or UpdatesAvailable)
# Look for: HTTP POST to /v1/inventory with a 2xx response
```

### Step A5 — Verify ingest in the Patched dashboard

1. Open the Patched dashboard → **Devices**.
2. Your pilot device should appear within a few minutes of a successful inventory POST.
3. Check **Last seen** and inventory fields (OS version, BitLocker status, Defender status) to
   confirm the payload is being processed correctly.

### Step A6 — Expand rollout

Once the pilot is clean:

1. Return to **Devices → Windows → PowerShell scripts → Patched Agent — Install**.
2. Under **Assignments**, add a broader group or **All Devices**.
3. Monitor `Upload failures` and device **Last seen** in the Patched dashboard for 24 hours.

---

## Path B — Win32 App (.intunewin wrapper)

> **Note:** Live Intune portal steps verified against Intune admin centre — portal UI may vary. Confirm each step in your tenant.

This path packages the MSI as a `.intunewin` Win32 app. Use this when you need the full Intune
Win32 app lifecycle: assignment reporting, supersedence, uninstall-via-portal, and Enrollment
Status Page (ESP) blocking.

### Step B1 — Package the MSI with the Win32 Content Prep Tool

1. Place `PatchedAgent-<version>.msi` in a staging folder, e.g. `C:\PatchedStaging\`.
2. Run the Win32 Content Prep Tool:

```cmd
IntuneWinAppUtil.exe ^
  -c "C:\PatchedStaging" ^
  -s "PatchedAgent-<version>.msi" ^
  -o "C:\PatchedOutput"
```

This produces `PatchedAgent-<version>.intunewin` in `C:\PatchedOutput\`.

### Step B2 — Create the Win32 app in Intune

1. In Intune: **Apps → Windows → Add**
2. **App type:** Windows app (Win32)
3. Click **Select → App package file** and upload `PatchedAgent-<version>.intunewin`.
4. Intune reads the MSI metadata automatically (name, publisher, version).

**App information:**

| Field | Value |
|---|---|
| Name | `Patched Agent` |
| Description | `Patched endpoint management agent — inventory collection and managed app updates.` |
| Publisher | `Patched` |
| App version | `<version>` (from the release tag, e.g. `0.3.0`) |

### Step B3 — Configure install and uninstall commands

**Install command:**

```cmd
msiexec /qn /i PatchedAgent-<version>.msi ENROLLMENT_TOKEN="<your-enrollment-token>"
```

> The install command is stored encrypted in Intune and delivered over the management channel.
> It is not exposed in the Windows process listing after the installer exits. The installer writes
> the token to `%ProgramData%\Patched\creds\enrollment-token` (SYSTEM and Administrators only);
> on its first run cycle the agent exchanges it for per-device credentials, moves them into Windows
> Credential Manager and deletes the file. Mint a fresh token per deployment. It is single-use and
> expires within 24 hours.

> **No raw-credential install (PAT-1755).** `TENANT_ID`, `BEARER_TOKEN` and `HMAC_SECRET` are no
> longer MSI properties, so passing them does nothing. Provision a device that cannot use an
> enrolment token after a bare install, with `cmdkey` as SYSTEM; see
> `windows/installer/README-install.md`, "Post-install credential provisioning".

**Uninstall command:**

```cmd
msiexec /qn /x PatchedAgent-<version>.msi
```

> **Uninstall wipes the device identity (PAT-1764).** A full uninstall removes the agent
> credentials from Credential Manager, the credential file store and the registry. That includes
> an Intune uninstall assignment, a supersedence rule set to uninstall the previous app, and any
> `msiexec /x` or `REMOVE=ALL`. An upgrade to a newer MSI keeps them. After such an uninstall, a
> reinstall needs a fresh enrollment token, because a token that was already consumed cannot enrol
> the device again. Mint a new token for every deployment and never reuse one, including in the
> install command of a superseding app.

Or by product code (more reliable across version upgrades — find it with `Get-WmiObject Win32_Product`):

```cmd
msiexec /qn /x {A1B2C3D4-E5F6-7890-ABCD-000000000311}
```

**Install behaviour:** Install silently

**Device restart behaviour:** Determine behaviour based on return codes (MSI handles this)

**Return codes:** leave as Intune defaults (0 = success, 1707 = success, 3010 = soft reboot, 1641 = hard reboot, 1618 = retry)

### Step B4 — Set the detection rule

The Patched Agent MSI registers the service and lays down a log directory. Use a file-based
detection rule for the most reliable result:

**Detection rule type:** File

| Field | Value |
|---|---|
| Path | `%ProgramFiles%\Patched` |
| File or folder | `Patched.Service.exe` |
| Detection method | File or folder exists |
| Associated with a 32-bit app on 64-bit clients | No |

Alternatively, use the Windows Service detection (custom script):

```powershell
$svc = Get-Service -Name 'Patched Agent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') { exit 0 } else { exit 1 }
```

> **MSI product code:** The MSI UpgradeCode is `{A1B2C3D4-E5F6-7890-ABCD-000000000311}`.
> Intune can also auto-detect installation state from the MSI product code — if Intune's
> MSI detection tab is available in your tenant, entering this code is sufficient.

### Step B5 — Configure requirements

**Operating system architecture:** 64-bit

**Minimum operating system:** Windows 10 2H22 (22H2) or later (the agent targets `net8.0-windows10.0.22621.0`)

### Step B6 — Assign to pilot group

1. Under **Assignments → Required**, click **Add group**.
2. Select your pilot device group.
3. **Do not** assign to All Devices at this stage.
4. Click **Next → Review + create → Create**.

### Step B7 — Monitor the deployment

1. In Intune: **Apps → Windows → Patched Agent → Device install status**
2. Installation state should move from **Pending** to **Installed** within one Intune check-in
   cycle (up to 60 minutes).
3. On a pilot device, confirm as in Step A4 above (service running, credentials in Credential
   Manager, log shows successful inventory POST).

### Step B8 — Enrollment Status Page (ESP) considerations

If your tenant uses an Enrollment Status Page to block the device desktop until required apps
are installed:

- Add **Patched Agent** to the ESP app list under **Devices → Windows → Enrollment → Enrollment
  Status Page → [your profile] → Settings → Block device use until all apps and profiles are
  installed → Select apps**.
- Set a reasonable timeout (15–20 minutes) to handle slow MSI installs on first-run provisioning.
- The MSI starts the `Patched Agent` service automatically on install, so ESP will unblock as
  soon as the detection rule passes.

### Step B9 — Expand rollout

Once the pilot is clean (devices appear in dashboard, no `401` errors in the log):

1. Return to **Apps → Windows → Patched Agent → Assignments**.
2. Add a broader Required assignment group (or All Devices).
3. Monitor device install status and the Patched dashboard for 24 hours.

---

## Credential delivery: Intune vs. post-install provisioning

The recommended Intune path (both A and B) passes a single-use enrolment token to `msiexec` at
install time. A deferred custom action running as LocalSystem writes it to
`%ProgramData%\Patched\creds\enrollment-token`, a directory that allows SYSTEM and Administrators
only; on its first run cycle the agent exchanges it for per-device credentials via `POST /v1/enrol`
and writes those to **Windows Credential Manager** (DPAPI-protected, `CRED_PERSIST_LOCAL_MACHINE`,
readable by `SYSTEM`), then deletes the token file. That token is the only credential the installer
accepts (PAT-1755).

If you cannot pass a token to `msiexec` (e.g. your secrets management policy prohibits embedding
credentials in Intune script/app config), install the agent bare and provision credentials
separately via a follow-up PowerShell script:

```powershell
# Post-install credential provisioning — run as SYSTEM or Administrator
cmdkey /generic:PatchedAgent/TenantId    /user:PatchedAgent /pass:<tenant-id>
cmdkey /generic:PatchedAgent/BearerToken /user:PatchedAgent /pass:<bearer-token>
cmdkey /generic:PatchedAgent/HmacSecret  /user:PatchedAgent /pass:<hmac-secret>
```

After provisioning, restart the service so it picks up the new credentials:

```powershell
Restart-Service -Name 'Patched Agent'
```

The agent reads credentials on startup only — a service restart is required after post-install
provisioning.

**Credential fallback chain:** Credential Manager → `HKLM\...\Services\PatchedAgent\Environment`
(env vars) → `%ProgramData%\Patched\creds\` (files). The file fallback is ACL-hardened to
SYSTEM + Administrators only. See `docs/credential-storage.md` for the full model and rotation
runbook.

---

## Defender / AV considerations

The `Patched.Service.exe` binary is unsigned in this interim release (Authenticode signing is
blocked on OV/EV certificate acquisition, tracked as PAT-50). Microsoft Defender will scan it
on first execution. In most tenants this completes without issue; occasionally Defender's
heuristic engine may flag a newly-seen unsigned service binary.

**If Defender quarantines the binary:**

1. Add an exclusion for the install path:

```powershell
Add-MpPreference -ExclusionPath 'C:\Program Files\Patched'
```

Deploy this as an Intune PowerShell script before the Patched Agent install script, or deliver
it via an Intune Defender Antivirus Configuration Profile (Endpoint security → Antivirus →
Windows Defender Antivirus exclusions).

2. Once PAT-50 lands and the MSI is Authenticode-signed, remove the exclusion — a signed binary
   with a trusted chain does not require a Defender exclusion.

> **SmartScreen:** Intune Win32 deployments bypass Windows SmartScreen (the MSI is pushed
> silently by the management plane). SmartScreen warnings only appear on interactive installs
> (double-click). If admins are installing manually for testing, click **More info → Run anyway**.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Device not appearing in dashboard | Service not running or inventory POST failing | Check `%ProgramData%\Patched\logs\patched-agent.log` on device |
| `401 Unauthorized` in agent log | Wrong bearer token or HMAC secret | Reprovision credentials via `cmdkey` (see above); restart service |
| `Missing credential 'PatchedAgent/TenantId'` in log | Device never enrolled, so no credentials were written | Run `cmdkey /list` to verify; drop a fresh token as `%ProgramData%\Patched\creds\enrollment-token`, or use post-install cmdkey |
| `NET ... connection refused` or HTTP timeout | `api.patched.im:443` blocked by firewall | Whitelist `api.patched.im:443` (TLS, no TLS inspection) |
| Intune script status: Failed | Script error — check Intune script output | In Intune portal: device status → expand device → copy error output; check for msiexec exit code |
| Service present but not starting | Credential Manager entries missing (fresh install, no token passed to msiexec) | The service should run and report no identity rather than fail to start (PAT-1766); use post-install cmdkey provisioning above and check Event Viewer for service start errors |
| Install fails with `WriteEnrollmentToken` non-zero in a verbose log | The token could not be provisioned: `%ProgramData%\Patched` or its `creds` child is a reparse point, is owned by someone other than SYSTEM or Administrators, or the token was malformed | Read the reason in Event Viewer under the source `Patched Agent`; the install deliberately fails rather than leaving a device that can never enrol |
| Defender quarantined `Patched.Service.exe` | Unsigned binary flagged by heuristic scan | Add Defender exclusion for `C:\Program Files\Patched` (see AV section above) |
| Service runs but no data in dashboard | Inventory POST succeeding but platform not processing | Check tenant status in Patched dashboard; confirm `tenant-id` matches the dashboard's expected UUID |

**Windows Event Log:** The `Patched Agent` service writes to the Windows Application Event Log
under source `Patched Agent`. Filter by source in Event Viewer
(`eventvwr.msc → Windows Logs → Application`) or via PowerShell:

```powershell
Get-EventLog -LogName Application -Source 'Patched Agent' -Newest 50
```

**Agent log file:** `%ProgramData%\Patched\logs\patched-agent.log` — rolling plaintext log of
every run cycle, HTTP request result, and any errors.

---

## Uninstall

**Via Intune (Win32 app path):**

Reassign the app as **Uninstall** from the target group in Intune. The MSI uninstall command
removes the service, binaries, and the agent credentials (Credential Manager, the credential file
store and the Enrollment registry key). A later reinstall needs a fresh enrollment token; see the
note under Step B3. Log files are preserved under
`%ProgramData%\Patched\logs\` — remove manually if a clean wipe is required.

**On device (if manual removal is needed):**

```powershell
# Silent uninstall by product code
msiexec /qn /x '{A1B2C3D4-E5F6-7890-ABCD-000000000311}'

# Or by MSI file (if available)
msiexec /qn /x PatchedAgent-<version>.msi

# Remove credentials from Credential Manager
cmdkey /delete:PatchedAgent/TenantId
cmdkey /delete:PatchedAgent/BearerToken
cmdkey /delete:PatchedAgent/HmacSecret

# Remove logs (optional — contains inventory history)
Remove-Item -Recurse -Force "$env:ProgramData\Patched"
```

In Intune (Platform Script path), remove the device from the target group and delete the
Platform Script assignment. The script will not re-run after removal from the group; the service
and MSI remain installed until manually uninstalled or removed via a Win32 app assignment.

---

## Version history

| Version | Notes |
|---|---|
| v1 (current) | MSI Win32 path — unsigned pending PAT-50 OV/EV cert. Platform Script path also documented. |
| v2 (planned, PAT-50) | Authenticode-signed MSI — removes SmartScreen warning, removes Defender exclusion requirement. |
