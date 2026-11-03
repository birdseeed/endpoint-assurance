<#
.SYNOPSIS  Induce/restore CIS §18.9.47 Defender policy and ASR rule state.

.DESCRIPTION
  Signals, registry paths, and absent-semantics (verified against
  DefenderPolicyParser.cs and ComplianceCollector.cs AddDefenderPolicy() /
  AddAsrRules() lines 397-419 and 594-619):

  Base path for Defender policy (GPO):
    $def = HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

  defender_cloud_protection    → $def\Spynet\SpynetReporting  (absent="No"; 1/2="Yes")
  defender_sample_submission   → $def\Spynet\SubmitSamplesConsent (absent="No"; 1/3="Yes")
  defender_pua_protection      → $def\PUAProtection (absent="No"; 1="Yes")
  defender_behavior_monitoring → $def\Real-Time Protection\DisableBehaviorMonitoring
                                   absent="Yes"; 0="Yes"; 1="No"
  defender_scan_removable_drives→$def\Scan\DisableRemovableDriveScanning (absent="No"; 0="Yes")
  defender_archive_scanning    → $def\Scan\DisableArchiveScanning (absent="Yes"; 0="Yes"; 1="No")

  ASR rules (GPO path preferred; Collector.cs ReadAsrRule checks GPO then cfg):
  asr_ransomware_enabled       → $def\Windows Defender Exploit Guard\ASR\Rules
                                   value = "c1db55ab-c21a-4637-bb3f-a12568109d35"
                                   "1" = block = "Yes" (compliant)
  asr_psexec_wmi_block_enabled → value = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

  Baseline:     set all to compliant values (SpynetReporting=2, consent=1, PUA=1,
                DisableBehaviorMonitoring=0, DisableRemovableDriving=0,
                DisableArchiveScanning=0, ASR rules="1")
  NonCompliant: set all to non-compliant (remove present-by-default signals,
                set explicit disable values for the rest, ASR rules="0")
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-defender-policy-state.json"
$Def       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$Spynet    = "$Def\Spynet"
$RTP       = "$Def\Real-Time Protection"
$Scan      = "$Def\Scan"
$AsrRules  = "$Def\Windows Defender Exploit Guard\ASR\Rules"
$AsrGuid1  = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
$AsrGuid2  = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'

function Read-Val([string]$path, [string]$name) {
    (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
}

function Save-State {
    if (Test-Path $StateFile) { return }
    $s = @{
        SpynetReporting                = (Read-Val $Spynet  'SpynetReporting')
        SubmitSamplesConsent           = (Read-Val $Spynet  'SubmitSamplesConsent')
        PUAProtection                  = (Read-Val $Def     'PUAProtection')
        DisableBehaviorMonitoring      = (Read-Val $RTP     'DisableBehaviorMonitoring')
        DisableRemovableDriveScanning  = (Read-Val $Scan    'DisableRemovableDriveScanning')
        DisableArchiveScanning         = (Read-Val $Scan    'DisableArchiveScanning')
        AsrRule1                       = (Read-Val $AsrRules $AsrGuid1)
        AsrRule2                       = (Read-Val $AsrRules $AsrGuid2)
    }
    $s | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [defender-policy] State saved."
}

function EnsureKey([string]$path) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}
function Set-DW([string]$path, [string]$name, [int]$val) { EnsureKey $path; Set-ItemProperty -LiteralPath $path -Name $name -Value $val -Type DWord }
function Set-Str([string]$path, [string]$name, [string]$val) { EnsureKey $path; Set-ItemProperty -LiteralPath $path -Name $name -Value $val -Type String }
function Del-Val([string]$path, [string]$name) { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue }

function Set-Baseline {
    Set-DW  $Spynet  'SpynetReporting'               2
    Set-DW  $Spynet  'SubmitSamplesConsent'           1
    Set-DW  $Def     'PUAProtection'                  1
    Set-DW  $RTP     'DisableBehaviorMonitoring'      0
    Set-DW  $Scan    'DisableRemovableDriveScanning'  0
    Set-DW  $Scan    'DisableArchiveScanning'         0
    EnsureKey $AsrRules
    Set-Str $AsrRules $AsrGuid1 '1'
    Set-Str $AsrRules $AsrGuid2 '1'
    Write-Host "  [defender-policy] Baseline applied."
}

function Set-NonCompliant {
    Del-Val $Spynet 'SpynetReporting'
    Del-Val $Spynet 'SubmitSamplesConsent'
    Del-Val $Def    'PUAProtection'
    Set-DW  $RTP    'DisableBehaviorMonitoring'      1
    Set-DW  $Scan   'DisableRemovableDriveScanning'  1
    Set-DW  $Scan   'DisableArchiveScanning'         1
    if (Test-Path $AsrRules) {
        Set-Str $AsrRules $AsrGuid1 '0'
        Set-Str $AsrRules $AsrGuid2 '0'
    }
    Write-Host "  [defender-policy] NonCompliant applied."
}

function Restore-Val([string]$path, [string]$name, $val, [bool]$isString = $false) {
    if ($null -eq $val) { Del-Val $path $name }
    else {
        EnsureKey $path
        if ($isString) { Set-ItemProperty -LiteralPath $path -Name $name -Value $val -Type String }
        else           { Set-ItemProperty -LiteralPath $path -Name $name -Value ([int]$val) -Type DWord }
    }
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[defender-policy] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    Restore-Val $Spynet  'SpynetReporting'               $s.SpynetReporting
    Restore-Val $Spynet  'SubmitSamplesConsent'           $s.SubmitSamplesConsent
    Restore-Val $Def     'PUAProtection'                  $s.PUAProtection
    Restore-Val $RTP     'DisableBehaviorMonitoring'      $s.DisableBehaviorMonitoring
    Restore-Val $Scan    'DisableRemovableDriveScanning'  $s.DisableRemovableDriveScanning
    Restore-Val $Scan    'DisableArchiveScanning'         $s.DisableArchiveScanning
    Restore-Val $AsrRules $AsrGuid1                       $s.AsrRule1 $true
    Restore-Val $AsrRules $AsrGuid2                       $s.AsrRule2 $true
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [defender-policy] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
