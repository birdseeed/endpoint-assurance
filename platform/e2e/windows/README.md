# Windows E2E Layer B — Implementation Notes (PAT-739)

## What this harness does

Runs the real `Patched.Service.exe` Windows agent on a `windows-latest` GitHub Actions
runner against a fully self-contained platform stack (Postgres, `patched-api`, `patched-extractor`)
built from source in the same job. Induces every inducible compliance signal into a known
state, triggers a scan via the trigger-file mechanism, waits for extraction, and asserts
that the server-side evaluator produced the correct verdict for every rule.

The two-phase cycle:
1. **Compliant** — baseline state inducement → scan trigger → assert all inducible rules pass
2. **NonCompliant** — non-compliant state inducement → scan trigger → assert all inducible rules fail

---

## Agent-config signing answer

The agent's `Ed25519Verifier` has two compile-time constants (source:
`updater/windows/src/Shared/Config/Ed25519Verifier.cs`):

```
PinnedPubKeyBase64 = "a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0="
PinnedKeyId        = "ecd47f2c5b3d5705"
```

A key pair generated locally in the workflow (`AGENT_CONFIG_SIGNING_KEY` env var) will
produce a different key_id. `AgentConfigFetcher.cs` checks key_id first
(`key_id != Ed25519Verifier.PinnedKeyId` → reject, log warning, return null). The agent
then holds the last-good config in memory, or falls back to `AgentConfig.Defaults` if no
cache exists:

```
AgentConfig.Defaults = new AgentConfig() → Tier="report_deploy", ScanCadence="daily"
```

**Consequence for E2E:** the agent will run with `AgentConfig.Defaults` for the entire
run. This is acceptable because:
- `AgentConfig.Defaults.Tier = "report_deploy"` — all compliance collection runs
- `AgentConfig.Defaults.ScanCadence = "daily"` — the scan still runs (first-run and trigger-driven)
- The config only controls *gating* of update actions, not compliance signal collection

Compliance signals, evaluations, and all assert_verdicts checks are unaffected by the
config-signing mismatch. The harness cannot use the real Ed25519 private key (it is a
production secret); this is the designed fallback.

---

## Service vs console execution

**Decision: run in console mode (no `sc.exe` install).**

`Program.cs` calls `builder.Services.AddWindowsService()`. The .NET 8 implementation
auto-detects the execution context:
- Running under SCM (Service Control Manager) → `WindowsServiceLifetime`
- Running as a console process (not under SCM) → `ConsoleLifetime`

The agent binary launched with `Start-Process` in the workflow is a console process.
`AddWindowsService()` detects this and falls back to `ConsoleLifetime`, giving the same
lifecycle as a normal console application.

**Code citation:** `updater/windows/src/Service/Service.csproj`:
```xml
<UseWindowsService>true</UseWindowsService>
```

This sets `AddWindowsService()` in the generated Program.cs host builder. Console fallback
is the designed behaviour for development and testing.

---

## Credential provisioning

`CredentialStore.LoadForStartup()` (source: `CredentialStore.cs` lines 170-202) checks in
priority order:
1. Windows Credential Manager — absent on a fresh runner
2. Environment variables: `PATCHED_TENANT_ID`, `PATCHED_BEARER_TOKEN`, `PATCHED_HMAC_SECRET`
3. File store: `%ProgramData%\Patched\creds\*`
4. Registry: `HKLM\SOFTWARE\Patched\Enrollment`

The harness uses **priority 2 (environment variables)**, set machine-scope via
`[System.Environment]::SetEnvironmentVariable(name, value, 'Machine')` in `provision.ps1`
before the agent process is started.

`PathConstants.ApiUrl` is a static readonly field initialized at class-load time:
```csharp
// PathConstants.cs line 92
public static readonly string ApiUrl =
    Environment.GetEnvironmentVariable("PATCHED_API_URL") ?? "https://api.patched.im";
```

`PATCHED_API_URL=http://localhost:8080` must be present in the agent process environment
when the CLR first loads `Patched.Shared.Paths.PathConstants`. It is both set machine-scope
by `provision.ps1` AND injected into the `Start-Process -Environment` hashtable in the
workflow.

---

## Cross-repo token requirement

The agent source lives in `Patched-LTD/updater`, which is a separate private repository.
The workflow checks it out with:

```yaml
- uses: actions/checkout@v4
  with:
    repository: Patched-LTD/updater
    token: ${{ secrets.UPDATER_CHECKOUT_TOKEN }}
```

**Required secret:** `UPDATER_CHECKOUT_TOKEN` — a fine-grained Personal Access Token (PAT)
or classic PAT stored as a repository or organization secret on the `patched.im` repo.

**Required permissions on the PAT:**
- `contents: read` on `Patched-LTD/updater`

Classic PAT scope: `repo` (for private repos). Fine-grained PAT: grant read-only access to
the `updater` repository.

---

## Trigger-file mechanism

The agent's `TriggerWatcher` polls `%ProgramData%\Patched\triggers\` every 15 seconds
(`Worker.TriggerPollInterval`). A file named `<uuid>.trigger` containing JSON
`{"type":"scan",...}` causes `IsScanRequest = true`, which triggers `RunCycleAsync`.

**Owner validation** (`TriggerOwnerPolicy.cs`): the file's OS owner SID is checked. The
following SIDs are rejected: null, Everyone (`S-1-1-0`), Local (`S-1-2-0`), Console Logon
(`S-1-2-1`), Anonymous Logon (`S-1-5-7`). The runner's admin user SID is none of these, so
trigger files written by the runner are accepted.

---

## Non-inducible signals — exclusion list

The following Windows signals are **excluded from both phase assertions** because they
cannot be safely induced or controlled on a `windows-latest` GitHub Actions runner:

| Signal key | Rule ID | Reason not inducible |
|---|---|---|
| `bitlocker_os_drive` | cis_win_18_10_11_bitlocker_os_drive | WMI `Win32_EncryptableVolume` — no BitLocker on runner VM |
| `bitlocker_cipher_256bit` | nist_win_sc28_bitlocker_cipher_256bit | WMI BitLocker cipher — no BitLocker on runner VM |
| `tpm_ready` | nist_win_si7_tpm_ready | WMI `Win32_Tpm` — no physical/firmware TPM in GitHub runner VM |
| `secure_boot_enabled` | nist_win_si7_secure_boot_enabled | UEFI `SecureBoot\Setup\SecureBootEnabled` — not accessible in runner VM |
| `vbs_enabled` | nist_win_sc39_vbs_enabled | Virtualization-Based Security requires hardware feature |
| `hvci_enabled` | nist_win_si16_hvci_enabled | HVCI requires hardware VBS feature |
| `kernel_dma_protection` | nist_win_sc41_kernel_dma_protection | UEFI Kernel DMA Protection — UEFI hardware required |
| `defender_realtime` | cis_win_18_9_45_defender_realtime | Tamper Protection prevents registry writes to Defender policy |
| `defender_definition_age_days` | nist_win_si3_defender_definition_age | Live WMI definition timestamp — cannot meaningfully fake age |
| `disk_encryption_off` | patched_win_disk_encryption_off | WMI BitLocker per-volume check — no BitLocker installed |
| `removable_storage_unencrypted` | patched_win_removable_storage_unencrypted | WMI BitLocker To Go — no removable drives on runner |

These signals all have `treat_unknown_as` set to either `pass` or `fail` in `rules.csv`.
Those with `treat_unknown_as=pass` will evaluate as `pass` in both phases (expected, benign).
Those with `treat_unknown_as=fail` will evaluate as `fail` in both phases — this is
accepted noise; the assertion skips them so the `fail` doesn't count as a test failure.

---

## State induction scripts (`induce/`)

Sixteen scripts, one per compliance group. Each accepts `-Mode Baseline|NonCompliant|Restore`.

| Script | Signals covered | Mechanism |
|---|---|---|
| `firewall.ps1` | `windows_firewall_{domain,private,public}` | HKLM registry `EnableFirewall` DWORD |
| `uac.ps1` | `uac_enabled` | HKLM registry `EnableLUA` DWORD |
| `autoupdate.ps1` | `auto_updates_enabled` | GPO `NoAutoUpdate` DWORD |
| `rdp.ps1` | `remote_desktop_enabled` | HKLM `fDenyTSConnections` DWORD |
| `smb-signing.ps1` | `smb_signing_required` | HKLM LanmanWorkstation `RequireSecuritySignature` |
| `screensaver.ps1` | `screensaver_{enabled,password_required,timeout_seconds}` | GPO Desktop key string values |
| `mdm.ps1` | `mdm_enrolled` | Fake enrollment subkey under HKLM Enrollments |
| `security-options.ps1` | 8 signals: `block_microsoft_accounts`, `restrict_anonymous_sam`, `no_lm_hash`, `lan_manager_auth_level`, `uac_admin_approval_builtin`, `audit_force_subcategory_policy`, `dont_display_last_username`, `machine_inactivity_limit_seconds` | HKLM Policies\System + Lsa DWORDs |
| `services-features.ps1` | `smbv1_disabled`, `llmnr_disabled`, `autoplay_disabled`, `always_install_elevated_disabled`, `remote_assistance_disabled`, `wdigest_cleartext_disabled` | Various HKLM registry keys |
| `defender-policy.ps1` | 6 Defender signals + `asr_{psexec_wmi_block,ransomware}_enabled` | HKLM Windows Defender policy + ASR GUID values |
| `tls-fips.ps1` | `fips_mode_enabled`, 6 TLS 1.0/1.1/1.2 signals | HKLM SCHANNEL + FIPSAlgorithmPolicy |
| `eventlog.ps1` | `security_log_max_size_kb` | GPO EventLog Security `MaxSize` DWORD |
| `laps.ps1` | `laps_enrolled` | Legacy LAPS registry key `AdmPwdEnabled` |
| `aslr.ps1` | `mandatory_aslr_enabled` | HKLM Memory Management `MoveImages` DWORD |
| `account-policy.ps1` | 9 password/lockout signals | `secedit /configure` with `.inf` template |
| `audit-policy.ps1` | 10 audit subcategory signals | `auditpol /set /subcategory:...` + `auditpol /backup|restore` |

---

## Assertion engine (`assert_verdicts.ps1`)

Queries `GET /admin/devices/{deviceID}` (internal `:8081` listener, admin bearer auth)
and compares each Windows rule's `status` field against the expected verdict for the phase.

- **Compliant phase:** all inducible rules must have `status = "pass"`
- **NonCompliant phase:** all inducible rules must have `status = "fail"`
- **Skipped:** non-inducible signals (see table above) + `not_applicable` evaluations
  (architecture gate or platform disabled)

The evaluator always produces one row per rule (`evaluator.go:Evaluate` iterates all rules).
Absent signals evaluate via `treat_unknown_as`. `evaluated_at` is set to
`row.ReceivedAt` (the API ingestion timestamp) so evaluations can be correlated to the
specific scan that produced them.

Emits a JSON ledger file at `LedgerPath` for diagnostic upload.
Exits non-zero if `failures > 0`.

---

## Postgres on windows-latest

The `windows-latest` runner includes Postgres 16 preinstalled but stopped. The workflow:
1. Starts the service via `Start-Service` (service name matches `postgresql*`)
2. Polls `pg_isready` until ready
3. Creates the `patched` role (required by GRANT statements in migrations 0010–0057)
4. Creates the `patched` database
5. Applies all `go-service/migrations/*.sql` in filename sort order

Default credentials: user `postgres`, password `root`. Connection string:
`postgres://postgres:root@localhost:5432/patched?sslmode=disable`

---

## Admin API auth

All `POST /admin/tenants` and `GET /admin/...` calls require:
```
Authorization: Bearer <ADMIN_API_TOKEN>
```

If `ADMIN_API_TOKEN` is empty the service returns 503 for all admin routes.
The workflow sets `ADMIN_API_TOKEN = "e2e-admin-${github.run_id}"` (a non-secret
pseudo-random value sufficient for a loopback test).

The internal admin listener is `127.0.0.1:8081`. It is NOT proxied; the workflow talks
to it directly via `http://localhost:8081`.
