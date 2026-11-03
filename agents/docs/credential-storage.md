# Credential storage and deployment model (PAT-19)

Three credentials are required on every enrolled Patched endpoint:

| Credential | Contents | Notes |
|---|---|---|
| `tenant-id` | UUID that identifies the tenant | Read-only after enrolment |
| `bearer-token` | Opaque token for `Authorization: Bearer` | Rotatable per PAT-339 |
| `hmac-secret` | Base64-encoded 32-byte HMAC-SHA256 key | Rotatable per PAT-339 |

Both credentials are issued by `POST /admin/tenants` when the tenant is created; rotation is separate (PAT-339).

---

## macOS

**Storage:** three plain-text files under `/etc/patched/`:

```
/etc/patched/
  tenant-id       # one UUID, no trailing whitespace
  bearer-token    # opaque string
  hmac-secret     # base64-encoded 32 bytes
```

Owner: `root:wheel`. Permissions: `600`. The directory itself is `700`.

The inventory agent (`patched-upload.sh`) and the updater daemon (`patched-update.sh`) both read from this directory. Neither caches credentials in memory beyond the current run — they re-read on every LaunchDaemon tick.

**Deployment decision: Option A — bootstrap parameters at install time.**

`install.sh` accepts `--tenant-id`, `--bearer-token`, `--hmac-secret` (or the equivalent `PATCHED_*` environment variables) and writes the files atomically before loading LaunchDaemons. For Intune deployment the Configuration Profile delivers the credential files directly to `/etc/patched/` before the collect script fires, so they are never passed on a command line visible to other processes.

The "credentials visible in Intune script config" concern from Option A does not apply to the production path — the Intune Configuration Profile file-delivery mechanism writes files directly without exposing them as environment variables or process arguments.

**ACL hardening:**

```bash
sudo mkdir -p /etc/patched
sudo chmod 700 /etc/patched
sudo chown root:wheel /etc/patched
# after writing each file:
sudo chmod 600 /etc/patched/{tenant-id,bearer-token,hmac-secret}
sudo chown root:wheel /etc/patched/{tenant-id,bearer-token,hmac-secret}
```

The `install.sh` script applies these permissions automatically.

---

## Windows

**Storage, runtime fallback, read in priority order by `CredentialStore.LoadForStartup()`
(`windows/src/Shared/Auth/CredentialStore.cs`):**

| Tier | Mechanism | At-rest protection | Typical use |
|---|---|---|---|
| 1 (primary) | Windows Credential Manager | DPAPI (`CRED_PERSIST_LOCAL_MACHINE`) | MSI install, production |
| 2 (env var fallback) | `HKLM\SYSTEM\...\Services\PatchedAgent\Environment` | Windows registry ACL | Headless / SSH provisioning |
| 3 (file fallback) | `%ProgramData%\Patched\creds\{tenant-id,bearer-token,hmac-secret}` | ACL: SYSTEM + Administrators only | Pilot / SSH provisioning |

A fourth, transient source exists only for a device installed by an MSI that predates PAT-1755:
`HKLM\SOFTWARE\Patched\Enrollment` (see "Deployment decision" below). It is checked last, and only
during service startup. Once `LoadForStartup()` finds credentials or an enrolment token there it
migrates them to Credential Manager (tier 1) and deletes the registry key, so the key does not
persist as an ongoing storage tier. Nothing in the current installer writes it.

**Credential Manager targets:**

```
PatchedAgent/TenantId
PatchedAgent/BearerToken
PatchedAgent/HmacSecret
```

All three are `CRED_TYPE_GENERIC` blobs stored with `CRED_PERSIST_LOCAL_MACHINE` so they survive reboot and are readable by `LocalSystem` (the service account the Patched Agent service runs as). DPAPI encrypts the blob at rest; credentials never touch a plaintext file on the production path.

**Environment variable names (tier 2):**

```
PATCHED_TENANT_ID
PATCHED_BEARER_TOKEN
PATCHED_HMAC_SECRET
```

Set these under `HKLM\SYSTEM\CurrentControlSet\Services\PatchedAgent\Environment` for headless provisioning where the DPAPI interactive context is unavailable.

**File fallback layout (tier 3):**

```
%ProgramData%\Patched\creds\
  tenant-id
  bearer-token
  hmac-secret
  enrollment-token
```

The directory ACL allows only `SYSTEM` and `Administrators` (full control, no inheritance from
parent). The WiX `CompCredsDir` component creates the directory with those ACEs via
`util:PermissionEx`, which merges into the DACL inherited from `%ProgramData%` rather than replacing
it, so that is an install-time baseline and not the definitive ACL. Two things establish the
definitive protected DACL: the `WriteEnrollmentToken` custom action before it provisions a token
(PAT-1755), and `StateDirectoryBootstrap` on every service start for the state root. Both refuse a
reparse point or a directory owned by anyone but SYSTEM or Administrators rather than repairing it.

`enrollment-token` is written by the installer (PAT-1755) and deleted by the agent once the token
has been exchanged. `tenant-id`, `bearer-token` and `hmac-secret` are populated manually
(`cmdkey`-equivalent file drop) for pilot or SSH provisioning, so re-apply the ACL by hand if you
recreate the directory outside the installer.

**Deployment decision: Option A — one MSI property at install time.**

The installer accepts a single-use enrolment token, minted per deployment, and nothing else
(PAT-1755, Andy's ruling 2026-09-15). It is the `ENROLLMENT_TOKEN` MSI property
(`Secure="yes" Hidden="yes"` in `Product.wxs`).

```cmd
msiexec /qn /i PatchedAgent.msi ENROLLMENT_TOKEN="<opaque-token>"
```

A deferred, non-impersonated `WriteEnrollmentToken` custom action runs the installed service binary
as LocalSystem (`Patched.Service.exe --write-enrollment-token <token>`), which writes the token to
`%ProgramData%\Patched\creds\enrollment-token` after establishing the protected DACL on the state
root and the creds directory. On its first run cycle the agent exchanges the token for per-device
credentials via `POST /v1/enrol`, writes those to Windows Credential Manager, and deletes the token
file. The action is `Return="check"`, so an install that was handed a token it could not write fails
and rolls back rather than leaving a device that can never enrol.

The raw-credential install path was removed. `TENANT_ID`, `BEARER_TOKEN` and `HMAC_SECRET` are no
longer MSI properties: they put two long-lived secrets on an `msiexec` command line, and a leaked
bearer token or HMAC secret is a standing credential until rotated, whereas the enrolment token is
single-use and expires within 24 hours. A device that genuinely cannot use a token is provisioned
after install through tier 1, 2 or 3 above, all of which the service still reads unchanged.

This custom action is an EXE action on a file installed with the product, not a DLL. Before
PAT-599 a `WriteCredentials` managed DLL custom action wrote credentials to Credential
Manager directly; it was removed because a WiX in-process DLL custom action compiled as x64 cannot
load on ARM64 Windows (error 1603/1154, the emulation boundary blocks in-process DLL loading).
PAT-599's replacement was a WiX `RegistryValue` write, which PAT-1755 replaced in turn for the
logging reason below; an EXE action on the service binary keeps PAT-599's ARM64 property. The old
DLL source was kept at `windows/installer/CredentialsCA/` for reference and potential rollback
until PAT-1793 (2026-09-16) deleted it, once PAT-599 had proven stable in production across both
x64 and ARM64 deployments and there was nothing left in the file for a rollback to restore.

**Verbose install logs.** As of PAT-1755 a verbose (`/l*v`) install log records no credential at
all. Two mechanisms are needed for that, and only together:

- `Hidden="yes"` on `ENROLLMENT_TOKEN` masks the value as `**********` on the log's
  `Command Line:` entry, on every `PROPERTY CHANGE` entry and in the closing `Property(S)` dump.
  `Secure="yes"` masks nothing; it only lets the value cross into the elevated execute sequence.
- `HideTarget="yes"` on `WriteEnrollmentToken` masks the action's own target, which is its command
  line. Nothing else does: with the token `Hidden` and written by a WiX `RegistryValue`, the op
  that performed the write still logged it in clear text once per install, observed on WIN-STAGING
  on 2026-09-15 during a bare upgrade as
  `Executing op: RegAddValue(Name=EnrollmentToken,Value=<token>,)`.

Anything that records a process command line before Windows Installer sees it (process listings
while the install runs, command-line process-creation auditing, endpoint security telemetry, or the
logs of whatever tool launches `msiexec`) can still capture the token from `msiexec`'s own command
line or from the provisioning action's short-lived process. That is accepted for a single-use,
24-hour token and was the reason the long-lived raw credentials were removed rather than hidden.
See `windows/installer/README-install.md`, "Credentials and install logs", for the operator
guidance.

A post-install provisioning path is available for tenants that cannot pass properties to `msiexec`: run the installer bare (no properties), then write credentials directly to Credential Manager with `cmdkey`:

```cmd
msiexec /qn /i PatchedAgent.msi
cmdkey /generic:PatchedAgent/TenantId    /user:PatchedAgent /pass:<tenant-id>
cmdkey /generic:PatchedAgent/BearerToken /user:PatchedAgent /pass:<bearer-token>
cmdkey /generic:PatchedAgent/HmacSecret  /user:PatchedAgent /pass:<hmac-secret>
```

---

## Cross-platform consistency

| Property | macOS | Windows |
|---|---|---|
| Credential names | `tenant-id`, `bearer-token`, `hmac-secret` (files) | `PatchedAgent/TenantId`, `PatchedAgent/BearerToken`, `PatchedAgent/HmacSecret` (CM targets) |
| At-rest protection | Unix file permissions (root 600) | DPAPI blob (CRED_PERSIST_LOCAL_MACHINE) |
| File fallback path | N/A (files are the primary) | `%ProgramData%\Patched\creds\` |
| Deployment mechanism | `install.sh` args or Intune Configuration Profile file delivery | MSI properties or post-install `cmdkey` |
| Provisioning timing | Before LaunchDaemon loads | At install (enrolment token written to the credential file store by a deferred custom action, exchanged for credentials in Credential Manager on the first run cycle) or post-install |
| Rotation | Re-run `install.sh` or redeploy config profile | Re-run `cmdkey` or re-deploy MSI with new properties |

---

## Rotation (PAT-339)

Credential rotation replaces the at-rest values without reinstalling the agent. The agent re-reads credentials on every run so no service restart is required after rotation.

- **macOS:** overwrite the three files (preserve permissions); the next LaunchDaemon tick picks them up.
- **Windows:** `cmdkey /delete:PatchedAgent/*` then re-add, or redeploy the MSI with updated properties.

Full rotation runbook lives in PAT-339.
