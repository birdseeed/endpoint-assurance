<#
.SYNOPSIS  Induce/restore Security event log maximum size compliance state.

.DESCRIPTION
  Signal: security_log_max_size_kb
  Rule:   nist_win_au11_security_log_max_size expects gte "196608" (192 MB)
  Source: ComplianceCollector.cs AddEventLogSecurity() lines 560-569.

  The collector checks GPO key first:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize  (value in KB)
  Then falls back to:
    HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize    (value in bytes → /1024)

  For induction we use the GPO key (MaxSize in KB):
    Baseline:     MaxSize = 262144  (256 MB, comfortably ≥ 196608 KB threshold)
    NonCompliant: MaxSize = 1024    (1 MB, fails gte 196608)
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-eventlog-state.json"
$KeyPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$ValueName = 'MaxSize'

function Read-Val { (Get-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName }

function Save-State {
    if (Test-Path $StateFile) { return }
    @{
        KeyExisted = (Test-Path $KeyPath)
        MaxSize    = (Read-Val)
    } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [eventlog] State saved."
}

function Set-Val([int]$val) {
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $KeyPath -Name $ValueName -Value $val -Type DWord
}

function Set-Baseline     { Set-Val 262144; Write-Host "  [eventlog] Baseline (MaxSize=262144 KB)." }
function Set-NonCompliant { Set-Val 1024;   Write-Host "  [eventlog] NonCompliant (MaxSize=1024 KB)." }

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[eventlog] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    if (-not $s.KeyExisted) {
        Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($null -eq $s.MaxSize) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    } else {
        Set-Val ([int]$s.MaxSize)
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [eventlog] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
