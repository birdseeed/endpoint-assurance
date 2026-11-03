# Patched Agent — Windows MSI Installer

## Unsigned interim release

**PatchedAgent.msi is unsigned (interim pilot release). Windows SmartScreen will show a warning.**

To proceed: click **More info** then **Run anyway** in the SmartScreen dialog.

Authenticode-signed leg is blocked on incorporation and OV/EV certificate acquisition (tracked as TODO in `sign-hook.bat`).

---

## Install

**GUI (double-click):**

```
PatchedAgent.msi
```

Accept the SmartScreen warning as described above.

**Silent (no UI) — the enrollment token is the only credential the installer accepts:**

```cmd
msiexec /qn /i PatchedAgent.msi ENROLLMENT_TOKEN="<your-enrollment-token>"
```

`ENROLLMENT_TOKEN` is optional. A bare install is valid: the service starts, reports that the
device has no identity, and picks up credentials as soon as they are provisioned (see
[A device with no identity](#a-device-with-no-identity-pat-1766)).

The installer writes the token to `%ProgramData%\Patched\creds\enrollment-token`, from a deferred
custom action running as LocalSystem. That directory allows SYSTEM and Administrators only, with
inheritance from `%ProgramData%` blocked, so no standard user or app package can read a token
waiting there. On its first run cycle the agent exchanges the token for per-device credentials via
`POST /v1/enrol`, moves those into Windows Credential Manager (DPAPI-protected) and deletes the
token file.

If the install is given a token it cannot write, it fails and rolls back rather than completing
with a device that could never enrol. The reason is in the Application event log under the source
`Patched Agent`, and the custom action's exit code is in a verbose (`/l*v`) log against
`WriteEnrollmentToken`.

A token only enrols a device that has no agent credentials. If the device already holds
credentials, for example from an earlier install that was not fully uninstalled or an MDM that
re-pushes the install, the agent keeps its existing identity, deletes the unused token and logs a
warning. To enrol such a device again, uninstall the agent first (see [Uninstall](#uninstall)) and
then install with the new token.

> **Raw credentials are no longer an install-time option (PAT-1755).** `TENANT_ID`,
> `BEARER_TOKEN` and `HMAC_SECRET` were removed as MSI properties. They put two long-lived secrets
> on an `msiexec` command line, where an enrollment token is single-use and expires within 24
> hours. A device that genuinely cannot use a token is provisioned after install instead, through
> Credential Manager or the credential file store, both described under **Post-install credential
> provisioning** below. Nothing about how the service reads credentials changed.

> **ARM64 note:** the provisioning custom action runs the installed service binary, not a DLL, so
> it works on x64 and ARM64. The old DLL-based custom action failed with error 1603/1154 on ARM64
> (PAT-599).

Run from an elevated (Administrator) command prompt or via your MDM/Intune deployment policy.

### Credentials and install logs

A verbose install log (`/l*v`) does not record the enrollment token at all (PAT-1755). Two
different mechanisms are needed for that, and they are easy to confuse:

- `ENROLLMENT_TOKEN` is a hidden MSI property, so Windows Installer replaces its value with
  `**********` on the `Command Line:` entry, on every `PROPERTY CHANGE` entry and in the closing
  `Property(S)` dump.
- The action that writes the token carries `HideTarget`, so the execute-script op that performs
  the write is logged with its command line masked. A property being hidden does not do this. The
  earlier design wrote the token with a WiX `RegistryValue`, and the op that performed it logged
  the token in clear text on every install, including a bare upgrade:
  `Executing op: RegAddValue(Name=EnrollmentToken,Value=<token>,)`.

The MSI cannot hide a value from anything that records a process command line before Windows
Installer sees it. That includes process listings while the install runs, Windows
process-creation auditing with command-line logging turned on, endpoint security telemetry, and
the logs or scripts of whatever tool launches `msiexec`. Two command lines carry the token during
an install: `msiexec` itself, and the provisioning action's own short-lived process. Both exist
only for the duration of the install and neither is written to disk by the installer.

That residual exposure is accepted for a token because the token is single-use, expires within 24
hours, and is consumed the first time the agent enrols, so a copy captured that way cannot enrol
another device afterwards. It was not acceptable for the long-lived raw credentials, which is why
they are no longer install-time properties at all.

**PAT-1793 investigated closing this gap and did not find a fix.** The idea considered was an MSI-
written handoff file: have the provisioning action write the token to an intermediate file instead
of passing it to `--write-enrollment-token`, so the process that receives the real
`--write-enrollment-token-from-file` invocation never has the token as an argument. That does not
remove the exposure, it only relocates it: MSI has no way to hand a property's value to an EXE-type
deferred custom action other than substituting it into `CustomActionData`/`ExeCommand`, which is
exactly what becomes that process's own command line. Writing the handoff file still needs one
process launched with the token as an argument, so the count of short-lived processes that carry
the token in their command line is unchanged (one), and a second process is added for no reduction
in exposure. The only mechanism that removes a deferred custom action's target from `CreateProcess`'s
argument list entirely is a DLL-type action reading `CustomActionData` in-process — the option PAT-599
already ruled out on ARM64 (error 1603/1154) and that this design deliberately does not reintroduce.
This residual exposure is therefore the practical floor for an EXE-type deferred custom action and
is not expected to close further without revisiting the ARM64 constraint.

Treat any log that recorded a raw-credential install from an older MSI (a deployment tool log, a
script transcript, an older verbose MSI log) as a secret: restrict who can read it, do not attach
it to tickets, and delete it once the install is confirmed. If such a log has been shared, rotate
the credentials (see `docs/credential-storage.md`).

The guard `windows/installer/test_hidden_credentials.py` runs in the `windows-build`,
`windows-msi-build` and `windows-agent-release` workflows (the last two through the shared
`.github/actions/windows-agent-msi` action). It fails if the token property loses `Secure` or
`Hidden`, if a raw-credential property comes back, if the provisioning action loses `HideTarget`
or stops failing the install on a failed write, or if anything starts writing the token through a
component again.

**Post-install credential provisioning** (the route for a device that cannot use an enrollment
token):

```cmd
cmdkey /generic:PatchedAgent/TenantId    /user:PatchedAgent /pass:<tenant-id>
cmdkey /generic:PatchedAgent/BearerToken /user:PatchedAgent /pass:<bearer-token>
cmdkey /generic:PatchedAgent/HmacSecret  /user:PatchedAgent /pass:<hmac-secret>
```

Or drop plaintext credential files (ACL-hardened to SYSTEM + Administrators):
```
%ProgramData%\Patched\creds\tenant-id
%ProgramData%\Patched\creds\bearer-token
%ProgramData%\Patched\creds\hmac-secret
```

A fresh enrollment token can be dropped the same way, as
`%ProgramData%\Patched\creds\enrollment-token`. That is the same file the installer writes, so a
post-install drop and an install-time token are the same path.

The service re-reads these every 5 minutes while it has no identity, so neither route needs a
service restart. See `docs/credential-storage.md` for the full credential model, environment
variable fallback, and rotation runbook.

---

## Uninstall

**Silent:**

```cmd
msiexec /qn /x PatchedAgent.msi
```

Or from **Settings > Apps > Installed apps**, find **Patched Agent** and click **Uninstall**.

Logs are preserved on uninstall (under `%ProgramData%\Patched\logs\`). Remove that directory manually if a clean wipe is required.

**Credentials on uninstall and upgrade (PAT-1764):**

- **Full uninstall removes the agent credentials.** The uninstall runs
  `Patched.Service.exe --purge-credentials` as SYSTEM, which deletes the `PatchedAgent/TenantId`,
  `PatchedAgent/BearerToken`, `PatchedAgent/HmacSecret` and `PatchedAgent/EnrollmentToken` entries
  from SYSTEM's Credential Manager, the `tenant-id`, `bearer-token`, `hmac-secret`,
  `enrollment-token` and `suspended` files in `%ProgramData%\Patched\creds\`, and the
  `HKLM\SOFTWARE\Patched\Enrollment` key an older installer used. A later install with a new
  `ENROLLMENT_TOKEN` then enrols as a new device.
- **Any full uninstall wipes the device identity, including one run by an MDM.** An Intune
  uninstall assignment, a supersedence rule set to uninstall the previous app, or any
  `msiexec /x` or `REMOVE=ALL` removes the credentials. The next install needs a fresh enrollment
  token: a token that was already consumed cannot enrol the device again. Mint a new token for
  every deployment and never reuse one.
- **Upgrades keep the credentials.** Installing a newer MSI over an existing one (including the
  agent's own self-update) removes the old version as part of the upgrade, and that removal never
  purges credentials, so the device keeps its identity.
- **Upgrades keep an enrollment token that has not been used yet (PAT-1766).** The token file in
  `%ProgramData%\Patched\creds\` belongs to no MSI component, so removing the old version during
  an upgrade cannot delete it and a bare upgrade such as the agent's self-update leaves it exactly
  where it was. A token passed on the upgrade command line replaces it. Before PAT-1755 the token
  was a component-owned registry value that the upgrade's removal step deleted, and the MSI had to
  read it back and rewrite it to survive; that machinery is gone with the registry write.
- **A rolled-back uninstall leaves the device without an identity.** The purge runs during the
  uninstall and cannot be undone, so if the uninstall fails after it and Windows Installer rolls
  back, the agent is restored with no credentials. Nothing stages the secrets to put them back,
  on purpose. The service then runs in the not-provisioned state described below. To recover,
  provision it as described there.
- **A failed purge does not block the uninstall.** The purge exits with code 1, which appears in a
  verbose (`/l*v`) uninstall log for the `PurgeAgentCredentials` action, and writes the targets it
  could not remove (never their values) to the Application event log under the source
  `Patched Agent`. Remove any that remain with `cmdkey /delete:<target>` run as SYSTEM before
  reinstalling.
- **Decommission with `purge=false` keeps the credentials.** The decommission handoff uninstalls
  with `PATCHED_RETAIN_CREDENTIALS=1`, which skips the purge, matching the macOS agent's
  non-purge removal. Passing the same property to a manual `msiexec /x` does the same.

---

## A device with no identity (PAT-1766)

If the service finds no usable agent credentials and no enrollment token (installed without
`ENROLLMENT_TOKEN`, or left without an identity by a rolled-back uninstall), it keeps running
rather than stopping. It collects and sends nothing, logs a Critical entry to the Application
event log (source `Patched Agent`) and the agent log saying the device has no agent identity,
repeats it once a day, and checks for a token or credentials every 5 minutes. An install or
upgrade onto such a device therefore completes instead of failing with error 1920 and rolling
back.

To provision it without a restart, do one of these as an administrator:

- Save a fresh enrollment token as `%ProgramData%\Patched\creds\enrollment-token`. The agent
  enrols with it within 5 minutes and deletes the file.
- Add credentials as described under **Post-install credential provisioning** above. The agent
  picks them up within 5 minutes.

Installing the MSI again with `ENROLLMENT_TOKEN` over an installed agent does not write the token:
the provisioning action is conditioned on a first install or a major upgrade, never a repair or
modify. Uninstall first, then install with the token, or drop the token file directly as above.

---

## What gets installed

| Item | Location |
|---|---|
| Service binary | `%ProgramFiles%\Patched\Patched.Service.exe` (explicit ACL, see below) |
| State + logs | `%ProgramData%\Patched\` |
| Trigger drop dir | `%ProgramData%\Patched\triggers\` (ACL-hardened) |
| Credential store | `%ProgramData%\Patched\creds\` (SYSTEM + Administrators only) |

**Windows Service:** `Patched Agent`
- Auto-start, runs as LocalSystem.
- Recovery: restart on 1st and 2nd failure (60 s delay), no action on 3rd; counter resets after 1 day.

The Windows agent is headless (PAT-2352). It has no taskbar or notification-area icon,
local status flyout, or local **Scan now** button. The service still owns scheduled
collection, upload, health reporting, signed self-update and decommission. The
existing trigger watcher and its ACL remain available to retained integrations.

### Install directory ACL

The MSI sets an explicit, protected ACL on `%ProgramFiles%\Patched` and on
`Patched.Service.exe` (PAT-2399). Before that release the directory carried nothing of its
own and inherited every entry from Program Files. The macOS equivalent is PAT-2395 and
PAT-2398.

| Principal | Access | Why |
|---|---|---|
| `NT AUTHORITY\SYSTEM` | Full control | The service, and Windows Installer |
| `BUILTIN\Administrators` | Full control | Repair, uninstall, inspection |
| `BUILTIN\Users` | Read and execute | Reading the file version |

TrustedInstaller, `CREATOR OWNER` and the two application-package principals are left out
on purpose: Windows servicing does not touch this directory, every installer operation runs
as SYSTEM, and nothing in the package runs in an AppContainer.

To read it on a device, from an elevated PowerShell:

```powershell
$dir = "$env:ProgramFiles\Patched"
(Get-Acl $dir).Sddl
icacls $dir
icacls "$dir\Patched.Service.exe"
```

What it must look like. The SDDL has `D:PAI` (protected) and exactly three entries, and
`icacls` shows no `(I)` on any line, because nothing is inherited:

```text
O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)

C:\Program Files\Patched NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                         BUILTIN\Administrators:(OI)(CI)(F)
                         BUILTIN\Users:(OI)(CI)(RX)

C:\Program Files\Patched\Patched.Service.exe NT AUTHORITY\SYSTEM:(F)
                                              BUILTIN\Administrators:(F)
                                              BUILTIN\Users:(RX)
```

The owner must be SYSTEM or Administrators (the `O:` and `G:` parts can differ from the
example). A device installed by an older MSI shows the inherited Program Files ACL instead,
every line marked `(I)`, with TrustedInstaller, `CREATOR OWNER` and the application-package
principals present. That is still accepted by the service; it becomes the ACL above at the
next upgrade.

The service checks both objects at every start and before each self-update check: owner
SYSTEM, Administrators or TrustedInstaller, no write access for anyone else (including
inherit-only entries, which would reach every file created there), not a reparse point. If
the check fails the service keeps running and keeps uploading inventory, logs an error, and
reports `install_integrity` / `install_directory` or `service_executable` /
`untrusted_owner`, `untrusted_acl`, `reparse_point` or `unverifiable` in agent health. It
then refuses to apply or stage a self-update and to start its evidence helpers until the ACL
is repaired. Reinstalling the MSI resets it. The check is re-read each time, so no restart
is needed once it is fixed.

This check is detection, not the control. If the directory really is writable by an
attacker the executable may already have been replaced, and a replaced executable does not
run the check. The control is the ACL the MSI sets.

The source guard (`test_install_directory_acl.py`) and the build's `MsiLockPermissionsEx`
assertion show the ACL is in the package. Neither shows what Windows Installer does with it,
so release verification must read the ACL on a device after a fresh install and after an
upgrade over a real prior version.

### Upgrade from a release with the tray

The normal MSI major upgrade removes the old tray binary and its registered startup
component. Credentials and service configuration retain their existing upgrade behaviour.
Because a SYSTEM-run upgrade may not reach another user's HKCU, the new service also
checks loaded hives at startup and every 15 minutes: every SID key under `HKEY_USERS`
(local, domain and Entra `S-1-12-1-…` accounts) and `.DEFAULT`, where a SYSTEM-context
install wrote the value. `HKU\S-1-5-18` is a registry link to `.DEFAULT`; a hive key
that is itself a link is skipped as an alias, not a failure, because its target is
checked under its own name (PAT-2416). It removes only the
`PatchedTray` Run value when it is a plain string containing the exact installed
`%ProgramFiles%\Patched\PatchedTray.exe` path, optionally quoted, with no arguments.
Other values and differently configured same-name entries are left alone. Registry
links are refused at every path component below the hive key. No offline profile hive is loaded or edited;
a stale entry in an unloaded hive waits until that user logs on and a later pass runs.

The cleanup stops only processes whose opened handle reports that exact installed image
path, after checking the protected installation. It never kills by process name alone,
executes a Run value, deletes another application's files, or adds a cleanup command-line
mode. MSI owns binary removal. Each pass handles at most 64 loaded hives and 64 processes.
Refusals and failures are warnings in the agent log and appear in agent health as
`retired_component_cleanup` / `windows_tray` / `cleanup_incomplete`; collection continues.
An MSI rollback can restore the old package, but the best-effort service cleanup does not
restore a Run value it already removed or relaunch a stopped tray.

Release verification must install over a real tray-bearing prior MSI, including a
SYSTEM-context upgrade with an interactive user. Confirm the tray process and binary are
gone, the exact old Run value is removed (including a later logon), unrelated Run values
survive, the service remains auto-started as LocalSystem, and fresh inventory is uploaded.
The source and File-table guards alone do not establish these installed results.

---

## Build from source

Pre-publish the service binary, then build the MSI:

```cmd
dotnet publish windows\src\Service\Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:Version=0.3.1 -p:AssemblyVersion=2.3.1.0 -p:FileVersion=2.3.1.0 -p:InformationalVersion=0.3.1+0123456789abcdef0123456789abcdef01234567 -p:IncludeSourceRevisionInInformationalVersion=false
dotnet build   windows\installer\Patched.wixproj  -c Release -p:ProductVersion=2.3.1
```

Release tags must be strict numeric `X.Y.Z` versions within the semantic
`253.255.65535` limits. The legacy MSI was permanently stamped `1.0.0`, so the
release workflow reserves the first two MSI major-version epochs and maps each
semantic release `X.Y.Z` to MSI ProductVersion `(X + 2).Y.Z`. This ensures
semantic releases such as `0.13.1` install as MSI `2.13.1` and upgrade the
legacy package. Executable AssemblyVersion and FileVersion use the same epoched
numeric version with a fourth `.0` field, while informational version metadata
retains the semantic release and full commit SHA. Disable the SDK's automatic
source-revision suffix when supplying that explicit informational version, or
the same commit is appended twice.

Do not pass raw semantic `X.Y.Z` to `-p:ProductVersion`: that recreates the
legacy-upgrade failure. The release workflow derives the MSI value with
`windows/installer/resolve-release-version.sh`; manual builds must use the same
`(X + 2).Y.Z` mapping for ProductVersion, AssemblyVersion, and FileVersion. The
numeric executable versions append `.0`, so the `0.3.1` example uses `2.3.1.0`.
This is required for Windows Installer to replace legacy `1.0.0.0` binaries;
the informational version alone is not used for file replacement.

Only the self-contained service executable is included in the MSI. The retained tray
source and tests are quarantined from release publishing and are not installed.

No separate CredentialsCA build step is needed — the DLL custom action was removed in PAT-599, and its
retained-for-rollback source was deleted in PAT-1793 once PAT-599 had proven stable in production.

Requires:
- .NET 8 SDK
- WiX Toolset v5 (`dotnet tool install --global wix`)
