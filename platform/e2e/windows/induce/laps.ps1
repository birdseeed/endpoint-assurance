<#
.SYNOPSIS  Induce/restore LAPS enrollment compliance state.

.DESCRIPTION
  Signal: laps_enrolled
  Rule:   nist_win_ac2_laps_enrolled expects eq "Yes" (treat_unknown_as=pass)
  Source: ComplianceCollector.cs AddLaps() lines 549-557.

  The collector checks modern LAPS first:
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config\BackupDirectory
    > 0 → "Yes"

  Then legacy LAPS extension:
    HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled = 1 → "Yes"

  else → "No"

  Baseline:     Set AdmPwdEnabled=1 (legacy LAPS — simpler to fake than modern LAPS)
  NonCompliant: Remove both paths so the collector sees "No"
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile  = "$env:TEMP\patched-e2e-laps-state.json"
$ModernKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
$LegacyKey  = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'

function Read-Val([string]$path, [string]$name) {
    (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
}

function Save-State {
    if (Test-Path $StateFile) { return }
    @{
        ModernKeyExisted   = (Test-Path $ModernKey)
        BackupDirectory    = (Read-Val $ModernKey 'BackupDirectory')
        LegacyKeyExisted   = (Test-Path $LegacyKey)
        AdmPwdEnabled      = (Read-Val $LegacyKey 'AdmPwdEnabled')
    } | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [laps] State saved."
}

function Set-Baseline {
    # Use the legacy path — creating a real LAPS computer object in AD is
    # not feasible on a runner; the registry value is the collector's check.
    if (-not (Test-Path $LegacyKey)) { New-Item -Path $LegacyKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $LegacyKey -Name 'AdmPwdEnabled' -Value 1 -Type DWord
    Write-Host "  [laps] Baseline applied (AdmPwdEnabled=1)."
}

function Set-NonCompliant {
    # Remove legacy LAPS value
    Remove-ItemProperty -LiteralPath $LegacyKey -Name 'AdmPwdEnabled' -ErrorAction SilentlyContinue
    # Remove modern LAPS BackupDirectory if present
    Remove-ItemProperty -LiteralPath $ModernKey -Name 'BackupDirectory' -ErrorAction SilentlyContinue
    Write-Host "  [laps] NonCompliant applied (no LAPS enrollment indicators)."
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[laps] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    if (-not $s.LegacyKeyExisted) {
        Remove-Item -LiteralPath $LegacyKey -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($null -eq $s.AdmPwdEnabled) {
        Remove-ItemProperty -LiteralPath $LegacyKey -Name 'AdmPwdEnabled' -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $LegacyKey)) { New-Item -Path $LegacyKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $LegacyKey -Name 'AdmPwdEnabled' -Value ([int]$s.AdmPwdEnabled) -Type DWord
    }
    if ($null -ne $s.BackupDirectory) {
        if (-not (Test-Path $ModernKey)) { New-Item -Path $ModernKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $ModernKey -Name 'BackupDirectory' -Value ([int]$s.BackupDirectory) -Type DWord
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [laps] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
