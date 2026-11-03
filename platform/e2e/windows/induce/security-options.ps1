<#
.SYNOPSIS  Induce/restore CIS §2.3 Security Options compliance state.

.DESCRIPTION
  Signals and their registry sources (verified against SecurityOptionsParser.cs
  and ComplianceCollector.cs AddSecurityOptions() lines 327-356):

  From HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:
    NoConnectedUser          → block_microsoft_accounts       (3=Yes, else No)
    DontDisplayLastUserName  → dont_display_last_username     (1=Yes, else No)
    InactivityTimeoutSecs    → machine_inactivity_limit_seconds (0→99999; rule lte 900)
    FilterAdministratorToken → uac_admin_approval_builtin    (1=Yes, else No)

  From HKLM\SYSTEM\CurrentControlSet\Control\Lsa:
    SCENoApplyLegacyAuditPolicy → audit_force_subcategory_policy (1=Yes, else No)
    RestrictAnonymousSAM        → restrict_anonymous_sam         (1=Yes, else No)
    NoLMHash                    → no_lm_hash                     (1=Yes, else No)
    LmCompatibilityLevel        → lan_manager_auth_level         (raw int; rule gte 5)

  Baseline compliant values:
    NoConnectedUser=3, DontDisplayLastUserName=1, InactivityTimeoutSecs=600,
    FilterAdministratorToken=1, SCENoApplyLegacyAuditPolicy=1,
    RestrictAnonymousSAM=1, NoLMHash=1, LmCompatibilityLevel=5

  NonCompliant values:
    NoConnectedUser=0, DontDisplayLastUserName=0, InactivityTimeoutSecs=0 (→99999 sentinel),
    FilterAdministratorToken=0, SCENoApplyLegacyAuditPolicy=0,
    RestrictAnonymousSAM=0, NoLMHash=0, LmCompatibilityLevel=0
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile   = "$env:TEMP\patched-e2e-security-options-state.json"
$PoliciesKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$LsaKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$PoliciesValues = @('NoConnectedUser','DontDisplayLastUserName','InactivityTimeoutSecs','FilterAdministratorToken')
$LsaValues      = @('SCENoApplyLegacyAuditPolicy','RestrictAnonymousSAM','NoLMHash','LmCompatibilityLevel')

function Read-Values {
    $state = @{}
    foreach ($v in $PoliciesValues) {
        $state["Policies_$v"] = (Get-ItemProperty -LiteralPath $PoliciesKey -Name $v -ErrorAction SilentlyContinue).$v
    }
    foreach ($v in $LsaValues) {
        $state["Lsa_$v"] = (Get-ItemProperty -LiteralPath $LsaKey -Name $v -ErrorAction SilentlyContinue).$v
    }
    return $state
}

function Save-State {
    if (Test-Path $StateFile) { return }
    (Read-Values) | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [security-options] State saved."
}

function Set-DWord([string]$keyPath, [string]$name, [int]$value) {
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $keyPath -Name $name -Value $value -Type DWord
}

function Set-Baseline {
    Set-DWord $PoliciesKey 'NoConnectedUser'           3
    Set-DWord $PoliciesKey 'DontDisplayLastUserName'   1
    Set-DWord $PoliciesKey 'InactivityTimeoutSecs'     600
    Set-DWord $PoliciesKey 'FilterAdministratorToken'  1
    Set-DWord $LsaKey 'SCENoApplyLegacyAuditPolicy'    1
    Set-DWord $LsaKey 'RestrictAnonymousSAM'           1
    Set-DWord $LsaKey 'NoLMHash'                       1
    Set-DWord $LsaKey 'LmCompatibilityLevel'           5
    Write-Host "  [security-options] Baseline applied."
}

function Set-NonCompliant {
    Set-DWord $PoliciesKey 'NoConnectedUser'           0
    Set-DWord $PoliciesKey 'DontDisplayLastUserName'   0
    # 0 → InactivityTimeoutSecs sentinel 99999 → fails lte 900
    Set-DWord $PoliciesKey 'InactivityTimeoutSecs'     0
    Set-DWord $PoliciesKey 'FilterAdministratorToken'  0
    Set-DWord $LsaKey 'SCENoApplyLegacyAuditPolicy'   0
    Set-DWord $LsaKey 'RestrictAnonymousSAM'           0
    Set-DWord $LsaKey 'NoLMHash'                       0
    Set-DWord $LsaKey 'LmCompatibilityLevel'           0
    Write-Host "  [security-options] NonCompliant applied."
}

function Restore-Value([string]$keyPath, [string]$name, $value) {
    if ($null -eq $value) {
        Remove-ItemProperty -LiteralPath $keyPath -Name $name -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
        Set-ItemProperty -LiteralPath $keyPath -Name $name -Value ([int]$value) -Type DWord
    }
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[security-options] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    foreach ($v in $PoliciesValues) { Restore-Value $PoliciesKey $v $s."Policies_$v" }
    foreach ($v in $LsaValues)      { Restore-Value $LsaKey      $v $s."Lsa_$v" }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [security-options] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
