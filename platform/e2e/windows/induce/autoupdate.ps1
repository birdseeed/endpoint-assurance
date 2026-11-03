<#
.SYNOPSIS  Induce/restore Windows Auto Update compliance state.

.DESCRIPTION
  Signal: auto_updates_enabled
  Source: ComplianceCollector.cs AddAutoUpdates() lines 140-162.

  The collector checks the GPO key FIRST:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate
      0 → "Yes" (updates enabled, pass for eq "Yes")
      1 → "No"  (updates disabled, fail)
    absent → falls back to AUOptions key.

  For induction we use the GPO key (reliable, no fallback ambiguity).

  Baseline:     NoAutoUpdate = 0  → auto_updates_enabled = "Yes"
  NonCompliant: NoAutoUpdate = 1  → auto_updates_enabled = "No"
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-autoupdate-state.json"
$KeyPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$ValueName = 'NoAutoUpdate'

function Read-NoAutoUpdate {
    (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
}

function Save-State {
    if (Test-Path $StateFile) { return }
    # Save both the value and whether the key existed (to properly restore absent state).
    $keyExists = Test-Path $KeyPath
    @{
        KeyExisted    = $keyExists
        NoAutoUpdate  = (Read-NoAutoUpdate)
    } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [autoupdate] State saved (keyExists=$keyExists)."
}

function Set-GPOValue([int]$val) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value $val -Type DWord
}

function Set-Baseline     { Set-GPOValue 0; Write-Host "  [autoupdate] Baseline (NoAutoUpdate=0)." }
function Set-NonCompliant { Set-GPOValue 1; Write-Host "  [autoupdate] NonCompliant (NoAutoUpdate=1)." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[autoupdate] No state file; skipping."; return }
    $state = Get-Content $StateFile | ConvertFrom-Json
    if (-not $state.KeyExisted) {
        Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($null -eq $state.NoAutoUpdate) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value ([int]$state.NoAutoUpdate) -Type DWord
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [autoupdate] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
