<#
.SYNOPSIS  Induce/restore CIS §1.1/§1.2 account and password policy.

.DESCRIPTION
  Signals (verified against AccountPolicyParser.cs and ComplianceCollector.cs
  AddAccountPolicy() lines 244-292):

  The collector runs `secedit /export /areas SECURITYPOLICY` and parses the
  [System Access] section. Signal keys and rules:

    password_history_count        ← PasswordHistorySize   (rule gte 24)
    password_max_age_days         ← MaximumPasswordAge     (rule lte 365; 0/-1→99999 sentinel)
    password_min_age_days         ← MinimumPasswordAge     (rule gte 1)
    password_min_length           ← MinimumPasswordLength  (rule gte 14)
    password_complexity_enabled   ← PasswordComplexity     (1=Yes; rule eq "Yes")
    password_reversible_encryption_disabled ← ClearTextPassword (0=Yes; rule eq "Yes")
    account_lockout_duration_minutes ← LockoutDuration     (rule gte 15)
    account_lockout_threshold        ← LockoutBadCount     (rule lte 5; 0→999 sentinel)
    account_lockout_reset_minutes    ← ResetLockoutCount   (rule gte 15)

  Baseline (compliant) values:
    PasswordHistorySize=24, MaximumPasswordAge=365, MinimumPasswordAge=1,
    MinimumPasswordLength=14, PasswordComplexity=1, ClearTextPassword=0,
    LockoutDuration=15, LockoutBadCount=3, ResetLockoutCount=15

  NonCompliant values:
    PasswordHistorySize=0, MaximumPasswordAge=0 (→99999), MinimumPasswordAge=0,
    MinimumPasswordLength=8, PasswordComplexity=0, ClearTextPassword=1,
    LockoutDuration=0, LockoutBadCount=0 (→999), ResetLockoutCount=0

  Implementation: secedit /configure /db with a temp security template .inf.
  The collector re-runs secedit on each scan, so changes take effect immediately.
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile     = "$env:TEMP\patched-e2e-account-policy-state.cfg"
$StateSentinel = "$env:TEMP\patched-e2e-account-policy-saved.flag"
$TempDb        = "$env:TEMP\patched-e2e-secedit.sdb"
$TempInf       = "$env:TEMP\patched-e2e-secedit.inf"

function Save-State {
    if (Test-Path $StateSentinel) { return }
    # Export current security policy to the state file.
    $null = secedit /export /cfg $StateFile /areas SECURITYPOLICY 2>&1
    New-Item -ItemType File -Path $StateSentinel -Force | Out-Null
    Write-Host "  [account-policy] State exported to $StateFile."
}

function Write-SecEditInf([string]$path, [hashtable]$values) {
    $lines = @(
        '[Unicode]',
        'Unicode=yes',
        '[Version]',
        'signature="$CHICAGO$"',
        'Revision=1',
        '[System Access]'
    )
    foreach ($kv in $values.GetEnumerator()) {
        $lines += "$($kv.Key) = $($kv.Value)"
    }
    $lines | Set-Content -Path $path -Encoding Unicode
}

function Apply-SecEdit([string]$infPath, [switch]$WarnOnly) {
    $null = secedit /configure /db $TempDb /cfg $infPath /areas SECURITYPOLICY /overwrite /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        # PAT-1750: a rejected template applies nothing, so the next scan
        # reports the previous policy and the phase's assertions test nothing.
        # Fail here with secedit's own reason instead of warning past it.
        $log = Join-Path $env:windir 'security\logs\scesrv.log'
        Get-Content $log -Tail 40 -ErrorAction SilentlyContinue | Write-Host
        if ($WarnOnly) { Write-Warning "secedit returned $LASTEXITCODE restoring $infPath."; return }
        throw "[account-policy] secedit /configure returned $LASTEXITCODE for $infPath"
    }
}

function Set-Baseline {
    Write-SecEditInf $TempInf @{
        PasswordHistorySize    = 24
        MaximumPasswordAge     = 365
        MinimumPasswordAge     = 1
        MinimumPasswordLength  = 14
        PasswordComplexity     = 1
        ClearTextPassword      = 0
        LockoutDuration        = 15
        LockoutBadCount        = 3
        ResetLockoutCount      = 15
    }
    Apply-SecEdit $TempInf
    Write-Host "  [account-policy] Baseline applied."
}

function Set-NonCompliant {
    Write-SecEditInf $TempInf @{
        PasswordHistorySize    = 0
        # -1 → MaximumPasswordAge "never expires" → parser sentinel 99999 → fails lte 365
        MaximumPasswordAge     = -1
        MinimumPasswordAge     = 0
        MinimumPasswordLength  = 8
        PasswordComplexity     = 0
        ClearTextPassword      = 1
        # 0 → LockoutBadCount "never" → parser sentinel 999 → fails lte 5.
        # LockoutDuration and ResetLockoutCount are omitted: with no lockout
        # threshold they do not apply, and secedit rejects the template when
        # they are set to 0 (PAT-1750: run 34830393299 applied nothing).
        LockoutBadCount        = 0
    }
    Apply-SecEdit $TempInf
    Write-Host "  [account-policy] NonCompliant applied."
}

function Restore-State {
    if (-not (Test-Path $StateSentinel)) { Write-Warning "[account-policy] No state; skipping."; return }
    if (Test-Path $StateFile) {
        Apply-SecEdit $StateFile -WarnOnly
        Write-Host "  [account-policy] Restored from saved policy export."
    }
    Remove-Item $StateSentinel -Force -ErrorAction SilentlyContinue
    Remove-Item $TempDb        -Force -ErrorAction SilentlyContinue
    Remove-Item $TempInf       -Force -ErrorAction SilentlyContinue
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
