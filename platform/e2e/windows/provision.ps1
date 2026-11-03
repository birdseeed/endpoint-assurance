<#
.SYNOPSIS
  Provision the Patched agent for E2E testing: set machine-level environment
  variables and create required directories.

.DESCRIPTION
  Called from the workflow before starting the agent binary. Writes credentials
  to Machine-scope environment variables so that CredentialStore.LoadForStartup()
  picks them up via the Environment fallback path (priority 2 — after Windows
  Credential Manager, which is empty on a fresh runner).

  Registry path used by LoadForStartup (priority 4, the WiX installer path):
    HKLM\SOFTWARE\Patched\Enrollment — not used here; we prefer env vars which
    are simpler and don't require a registry migration step.

  PathConstants.ApiUrl is a static readonly field in the agent, read at
  class-load time from PATCHED_API_URL in the process environment. It must be
  present in the agent process's environment when the CLR first loads
  Patched.Shared.Paths.PathConstants.

  Credential source priority verified from CredentialStore.cs lines 172-174:
    1. Windows Credential Manager (absent on runner)
    2. Environment variables PATCHED_TENANT_ID / PATCHED_BEARER_TOKEN / PATCHED_HMAC_SECRET
    3. File store %ProgramData%\Patched\creds\*
    4. Registry HKLM\SOFTWARE\Patched\Enrollment

.PARAMETER TenantId     UUID returned by POST /admin/tenants
.PARAMETER BearerToken  Plaintext bearer token returned by POST /admin/tenants
.PARAMETER HmacSecret   Base64 HMAC-SHA256 key returned as hmac_secret_b64
.PARAMETER ApiUrl       API base URL (e.g. http://localhost:8080)
#>
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$BearerToken,

    [Parameter(Mandatory)]
    [string]$HmacSecret,

    [Parameter(Mandatory)]
    [string]$ApiUrl
)
$ErrorActionPreference = 'Stop'

Write-Host "Provisioning agent credentials (Machine env vars)…"

# Machine-scope env vars survive new-process spawns on the same session.
# The agent process inherits these when started with Start-Process (no -Environment override).
[System.Environment]::SetEnvironmentVariable('PATCHED_TENANT_ID',    $TenantId,    'Machine')
[System.Environment]::SetEnvironmentVariable('PATCHED_BEARER_TOKEN', $BearerToken, 'Machine')
[System.Environment]::SetEnvironmentVariable('PATCHED_HMAC_SECRET',  $HmacSecret,  'Machine')
[System.Environment]::SetEnvironmentVariable('PATCHED_API_URL',      $ApiUrl,      'Machine')

Write-Host "  PATCHED_TENANT_ID    set (Machine)"
Write-Host "  PATCHED_BEARER_TOKEN set (Machine)"
Write-Host "  PATCHED_HMAC_SECRET  set (Machine)"
Write-Host "  PATCHED_API_URL      = $ApiUrl (Machine)"

# Create required directories that the agent expects to exist.
# TriggerAcl.EnsureTriggerDirectory() creates the triggers dir with a hardened
# DACL, but creating it before the agent starts avoids a first-run race.
$stateDir   = "$env:ProgramData\Patched"
$credsDir   = "$stateDir\creds"
$triggersDir = "$stateDir\triggers"
$logsDir    = "$stateDir\logs"

foreach ($dir in @($stateDir, $credsDir, $triggersDir, $logsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir"
    }
}

# Ensure the suspended sentinel does NOT exist (a leftover from a prior run
# would halt all scan cycles — IsSuspended checks for this file).
$suspendedFile = "$credsDir\suspended"
if (Test-Path $suspendedFile) {
    Remove-Item $suspendedFile -Force
    Write-Host "  Removed stale suspended sentinel."
}

Write-Host "Provisioning complete."
