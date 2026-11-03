<#
.SYNOPSIS  Induce/restore Remote Desktop compliance state.

.DESCRIPTION
  Signal: remote_desktop_enabled
  Rule:   cis_win_18_10_56_2_rdp_disabled expects eq "disabled" (RDP must be off)
  Source: ComplianceCollector.cs AddRemoteDesktop() lines 164-179.

    HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
      0 → "enabled"  (RDP accepting connections — NON-COMPLIANT; rule expects "disabled")
      1 → "disabled" (RDP blocked — COMPLIANT)
      absent → "Unknown"

  Baseline:     fDenyTSConnections = 1  → "disabled" (pass)
  NonCompliant: fDenyTSConnections = 0  → "enabled"  (fail)
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-rdp-state.json"
$KeyPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$ValueName = 'fDenyTSConnections'

function Read-Value {
    (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
}

function Save-State {
    if (Test-Path $StateFile) { return }
    @{ fDenyTSConnections = (Read-Value) } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [rdp] State saved."
}

function Set-Value([int]$val) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value $val -Type DWord
}

function Set-Baseline     { Set-Value 1; Write-Host "  [rdp] Baseline (fDenyTSConnections=1 → disabled)." }
function Set-NonCompliant { Set-Value 0; Write-Host "  [rdp] NonCompliant (fDenyTSConnections=0 → enabled)." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[rdp] No state file; skipping."; return }
    $state = Get-Content $StateFile | ConvertFrom-Json
    if ($null -eq $state.fDenyTSConnections) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-Value ([int]$state.fDenyTSConnections)
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [rdp] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
