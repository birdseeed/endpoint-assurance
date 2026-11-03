<#
.SYNOPSIS  Induce/restore screensaver compliance state.

.DESCRIPTION
  Signals controlled:
    screensaver_enabled          → ScreenSaveActive  ("1"/"0")
    screensaver_password_required → ScreenSaverIsSecure ("1"/"0")
    screensaver_timeout_seconds  → ScreenSaveTimeOut (integer)

  Source: ComplianceCollector.cs AddScreensaver() lines 199-225.
  NOTE: the collector reads HKLM (not HKCU) because HKCU is unavailable
  under SYSTEM context. The key is the machine-level GPO key:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop

  Rules (rules.csv):
    screensaver_enabled          eq "Yes"       (pass when "1")
    screensaver_password_required eq "Yes"      (pass when "1")
    screensaver_timeout_seconds  lte "900"      (pass when ≤900 seconds)

  Baseline:     ScreenSaveActive="1", ScreenSaverIsSecure="1", ScreenSaveTimeOut="600"
  NonCompliant: ScreenSaveActive="0", ScreenSaverIsSecure="0", ScreenSaveTimeOut="9999"
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-screensaver-state.json"
$KeyPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'

function Read-Values {
    $p = Get-ItemProperty -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    @{
        KeyExisted         = (Test-Path $KeyPath)
        ScreenSaveActive   = $p.ScreenSaveActive
        ScreenSaveTimeOut  = $p.ScreenSaveTimeOut
        ScreenSaverIsSecure = $p.ScreenSaverIsSecure
    }
}

function Save-State {
    if (Test-Path $StateFile) { return }
    (Read-Values) | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [screensaver] State saved."
}

function Apply([string]$active, [string]$secure, [string]$timeout) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaveActive    -Value $active  -Type String
    Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaverIsSecure -Value $secure  -Type String
    Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaveTimeOut   -Value $timeout -Type String
}

function Set-Baseline     { Apply '1' '1' '600';  Write-Host "  [screensaver] Baseline applied." }
function Set-NonCompliant { Apply '0' '0' '9999'; Write-Host "  [screensaver] NonCompliant applied." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[screensaver] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    if (-not $s.KeyExisted) {
        Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
        if ($null -ne $s.ScreenSaveActive)   { Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaveActive    -Value $s.ScreenSaveActive   -Type String }
        if ($null -ne $s.ScreenSaverIsSecure){ Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaverIsSecure -Value $s.ScreenSaverIsSecure -Type String }
        if ($null -ne $s.ScreenSaveTimeOut)  { Set-ItemProperty -LiteralPath $KeyPath -Name ScreenSaveTimeOut   -Value $s.ScreenSaveTimeOut  -Type String }
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [screensaver] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
