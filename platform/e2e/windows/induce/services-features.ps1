<#
.SYNOPSIS  Induce/restore CIS §18 Services and Features compliance state.

.DESCRIPTION
  Signals, registry paths, and absent-semantics (verified against
  ServicesFeaturesParser.cs and ComplianceCollector.cs AddServicesFeatures()
  lines 374-395):

  smbv1_disabled:
    HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start
    absent → "Yes" (driver not installed); 4 → "Yes"; other → "No"
    Baseline: set Start=4;  NonCompliant: set Start=2

  llmnr_disabled:
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast
    absent → "No"; 0 → "Yes"
    Baseline: 0;  NonCompliant: delete key (absent=No=non-compliant)

  autoplay_disabled:
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun
    255 → "Yes"; absent → "No"
    Baseline: 255;  NonCompliant: delete value

  always_install_elevated_disabled:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    absent → "Yes"; 1 → "No"
    Baseline: delete value;  NonCompliant: set to 1

  remote_assistance_disabled:
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp
    0 → "Yes"; absent → "No"
    Baseline: 0;  NonCompliant: delete value

  wdigest_cleartext_disabled:
    HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
    absent → "Yes"; 1 → "No"
    Baseline: delete value;  NonCompliant: set to 1
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-services-features-state.json"

$Keys = @{
    mrxsmb10          = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    llmnr             = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    autoplay          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    installer         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
    remoteAssist      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    wdigest           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
}

function Read-Val([string]$path, [string]$name) {
    (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
}

function Save-State {
    if (Test-Path $StateFile) { return }
    $s = @{
        mrxsmb10_Start         = (Read-Val $Keys.mrxsmb10     'Start')
        llmnr_EnableMulticast  = (Read-Val $Keys.llmnr        'EnableMulticast')
        autoplay_NoDriveType   = (Read-Val $Keys.autoplay     'NoDriveTypeAutoRun')
        installer_AIE          = (Read-Val $Keys.installer     'AlwaysInstallElevated')
        remoteAssist_fAllow    = (Read-Val $Keys.remoteAssist 'fAllowToGetHelp')
        wdigest_UseLogon       = (Read-Val $Keys.wdigest      'UseLogonCredential')
    }
    $s | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [services-features] State saved."
}

function Set-DW([string]$path, [string]$name, [int]$val) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -LiteralPath $path -Name $name -Value $val -Type DWord
}
function Del-Val([string]$path, [string]$name) {
    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
}

function Set-Baseline {
    # smbv1: disable driver (Start=4 = SERVICE_DISABLED). Set-DW creates the key
    # via New-Item -Force if the mrxsmb10 service isn't present on this runner
    # image — a Test-Path guard here would silently no-op the induction.
    Set-DW $Keys.mrxsmb10 'Start' 4
    # llmnr: explicitly disable
    Set-DW $Keys.llmnr 'EnableMulticast' 0
    # autoplay: all drive types
    Set-DW $Keys.autoplay 'NoDriveTypeAutoRun' 255
    # always_install_elevated: absent = compliant; remove to be safe
    Del-Val $Keys.installer 'AlwaysInstallElevated'
    # remote assistance: disable
    Set-DW $Keys.remoteAssist 'fAllowToGetHelp' 0
    # wdigest: absent = compliant; remove to be safe
    Del-Val $Keys.wdigest 'UseLogonCredential'
    Write-Host "  [services-features] Baseline applied."
}

function Set-NonCompliant {
    # smbv1: enable (Start=2 = SERVICE_AUTO_START)
    Set-DW $Keys.mrxsmb10 'Start' 2
    # llmnr: remove key → absent = LLMNR enabled (non-compliant default)
    Del-Val $Keys.llmnr 'EnableMulticast'
    # autoplay: remove value → absent = not disabled (non-compliant)
    Del-Val $Keys.autoplay 'NoDriveTypeAutoRun'
    # always_install_elevated: 1 = enabled (non-compliant)
    Set-DW $Keys.installer 'AlwaysInstallElevated' 1
    # remote assistance: remove → absent = enabled (non-compliant)
    Del-Val $Keys.remoteAssist 'fAllowToGetHelp'
    # wdigest: 1 = cache plaintext creds (non-compliant)
    Set-DW $Keys.wdigest 'UseLogonCredential' 1
    Write-Host "  [services-features] NonCompliant applied."
}

function Restore-Val([string]$path, [string]$name, $val) {
    if ($null -eq $val) { Del-Val $path $name }
    else {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -LiteralPath $path -Name $name -Value ([int]$val) -Type DWord
    }
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[services-features] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json
    Restore-Val $Keys.mrxsmb10    'Start'                  $s.mrxsmb10_Start
    Restore-Val $Keys.llmnr       'EnableMulticast'        $s.llmnr_EnableMulticast
    Restore-Val $Keys.autoplay    'NoDriveTypeAutoRun'     $s.autoplay_NoDriveType
    Restore-Val $Keys.installer   'AlwaysInstallElevated'  $s.installer_AIE
    Restore-Val $Keys.remoteAssist 'fAllowToGetHelp'       $s.remoteAssist_fAllow
    Restore-Val $Keys.wdigest     'UseLogonCredential'     $s.wdigest_UseLogon
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [services-features] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
