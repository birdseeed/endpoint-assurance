<#
.SYNOPSIS  Induce/restore Windows Firewall compliance state.

.DESCRIPTION
  Signals controlled:
    windows_firewall_domain  — HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall
    windows_firewall_private — …\StandardProfile\EnableFirewall
    windows_firewall_public  — …\PublicProfile\EnableFirewall

  Source: ComplianceCollector.cs AddFirewall() / ReadFirewallProfile() (lines 83-104).
  Registry path verified against the collector string literal:
    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

  Compliant value:  EnableFirewall = 1  → "enabled"   (pass for eq "enabled")
  Non-compliant:    EnableFirewall = 0  → "disabled"  (fail for eq "enabled")
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile = "$env:TEMP\patched-e2e-firewall-state.json"
$FwBase    = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
$Profiles  = @{
    Domain  = "$FwBase\DomainProfile"
    Private = "$FwBase\StandardProfile"
    Public  = "$FwBase\PublicProfile"
}

function Read-EnableFirewall([string]$keyPath) {
    $v = (Get-ItemProperty -LiteralPath $keyPath -Name EnableFirewall -ErrorAction SilentlyContinue).EnableFirewall
    return $v  # int or $null
}

function Save-State {
    if (Test-Path $StateFile) { return }
    $state = @{}
    foreach ($p in $Profiles.Keys) {
        $state[$p] = Read-EnableFirewall $Profiles[$p]
    }
    $state | ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [firewall] State saved."
}

function Set-EnableFirewall([string]$keyPath, [int]$value) {
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    Set-ItemProperty -LiteralPath $keyPath -Name EnableFirewall -Value $value -Type DWord
}

function Set-Baseline {
    foreach ($p in $Profiles.Keys) { Set-EnableFirewall $Profiles[$p] 1 }
    Write-Host "  [firewall] Baseline applied (all profiles enabled)."
}

function Set-NonCompliant {
    foreach ($p in $Profiles.Keys) { Set-EnableFirewall $Profiles[$p] 0 }
    Write-Host "  [firewall] NonCompliant applied (all profiles disabled)."
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[firewall] No state file found; skipping restore."; return }
    $state = Get-Content $StateFile | ConvertFrom-Json
    foreach ($p in $Profiles.Keys) {
        $original = $state.$p
        if ($null -eq $original) {
            # Value was absent — remove it.
            Remove-ItemProperty -LiteralPath $Profiles[$p] -Name EnableFirewall -ErrorAction SilentlyContinue
        } else {
            Set-EnableFirewall $Profiles[$p] ([int]$original)
        }
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [firewall] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
