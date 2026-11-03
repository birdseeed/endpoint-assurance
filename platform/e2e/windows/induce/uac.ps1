<#
.SYNOPSIS  Induce/restore UAC compliance state.

.DESCRIPTION
  Signal: uac_enabled
  Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
  Source: ComplianceCollector.cs AddUac() lines 125-138.
    EnableLUA = 1 → "Yes" (pass for eq "Yes")
    EnableLUA = 0 → "No"  (fail)
    absent         → "Unknown"

  WARNING: setting EnableLUA=0 disables UAC on the runner. It is restored
  immediately after the scan by Restore mode. The agent runs as admin so the
  runner session is not disrupted between scan trigger and restore.
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-uac-state.json"
$KeyPath   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ValueName = 'EnableLUA'

function Read-EnableLUA {
    $v = (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    return $v
}

function Save-State {
    if (Test-Path $StateFile) { return }
    @{ EnableLUA = (Read-EnableLUA) } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [uac] State saved."
}

function Set-Baseline {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value 1 -Type DWord
    Write-Host "  [uac] Baseline applied (EnableLUA=1)."
}

function Set-NonCompliant {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value 0 -Type DWord
    Write-Host "  [uac] NonCompliant applied (EnableLUA=0)."
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[uac] No state file; skipping."; return }
    $state = Get-Content $StateFile | ConvertFrom-Json
    if ($null -eq $state.EnableLUA) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value ([int]$state.EnableLUA) -Type DWord
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [uac] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
