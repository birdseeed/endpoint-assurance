<#
.SYNOPSIS  Induce/restore SMB signing compliance state.

.DESCRIPTION
  Signal: smb_signing_required
  Rule:   cis_win_2_3_8_1_smb_signing expects eq "Yes"
  Source: ComplianceCollector.cs AddSmbSigning() lines 181-196.

    HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature
      1 → "Yes" (signing required — compliant)
      0 → "No"  (signing not required — non-compliant)
      absent → "Unknown"

  Baseline:     RequireSecuritySignature = 1
  NonCompliant: RequireSecuritySignature = 0
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-smb-signing-state.json"
$KeyPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$ValueName = 'RequireSecuritySignature'

function Read-Value { (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName }

function Save-State {
    if (Test-Path $StateFile) { return }
    @{ RequireSecuritySignature = (Read-Value) } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [smb-signing] State saved."
}

function Set-Value([int]$val) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value $val -Type DWord
}

function Set-Baseline     { Set-Value 1; Write-Host "  [smb-signing] Baseline (RequireSecuritySignature=1)." }
function Set-NonCompliant { Set-Value 0; Write-Host "  [smb-signing] NonCompliant (RequireSecuritySignature=0)." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[smb-signing] No state file; skipping."; return }
    $state = Get-Content $StateFile | ConvertFrom-Json
    if ($null -eq $state.RequireSecuritySignature) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-Value ([int]$state.RequireSecuritySignature)
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [smb-signing] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
