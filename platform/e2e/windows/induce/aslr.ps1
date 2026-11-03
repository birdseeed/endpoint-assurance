<#
.SYNOPSIS  Induce/restore Mandatory ASLR (ForceRelocateImages) compliance state.

.DESCRIPTION
  Signal: mandatory_aslr_enabled
  Rule:   nist_win_si16_mandatory_aslr expects eq "Yes" (treat_unknown_as=pass)
  Source: ComplianceCollector.cs AddExploitProtection() lines 540-546.

    HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImages
    null / absent → "Unknown" → treat_unknown_as=pass
    0             → "No"
    any other int → "Yes"

  Baseline:     MoveImages = 1  → "Yes" (compliant)
  NonCompliant: MoveImages = 0  → "No"  (fail for eq "Yes")
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-aslr-state.json"
$KeyPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$ValueName = 'MoveImages'

function Read-Val { (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName }

function Save-State {
    if (Test-Path $StateFile) { return }
    @{ MoveImages = (Read-Val) } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [aslr] State saved."
}

function Set-Val([int]$val) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value $val -Type DWord
}

function Set-Baseline     { Set-Val 1; Write-Host "  [aslr] Baseline (MoveImages=1)." }
function Set-NonCompliant { Set-Val 0; Write-Host "  [aslr] NonCompliant (MoveImages=0)." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[aslr] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    if ($null -eq $s.MoveImages) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-Val ([int]$s.MoveImages)
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [aslr] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
