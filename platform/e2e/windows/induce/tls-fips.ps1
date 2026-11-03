<#
.SYNOPSIS  Induce/restore FIPS mode and TLS protocol compliance state.

.DESCRIPTION
  Signals and registry sources (verified against ComplianceCollector.cs
  AddFipsAndTls() lines 424-474):

  fips_mode_enabled:
    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled
    1="Yes" (compliant); 0="No" (non-compliant)

  TLS 1.0/1.1 disabled:
    HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\
      TLS 1.0\Client\Enabled  (0=Yes/disabled; 1=No/re-enabled; absent=Unknown)
      TLS 1.0\Server\Enabled
      TLS 1.1\Client\Enabled
      TLS 1.1\Server\Enabled

  TLS 1.2 enabled:
    TLS 1.2\Client\Enabled  (1=Yes/enabled; 0=No/disabled; absent=Unknown)
    TLS 1.2\Server\Enabled

  An absent key does not pass (PAT-1749). The collector emits the literal
  signal "Unknown", and the evaluator applies treat_unknown_as only when a
  signal is missing altogether, so "Unknown" fails an eq ["Yes"] rule. That is
  also the honest outcome: TLS 1.0/1.1 are on by default on Windows 10 and
  Server 2022, so an absent key is not evidence they are off.

  Baseline:
    FIPS Enabled=1; TLS 1.0/1.1 Enabled=0 + DisabledByDefault=1;
    TLS 1.2 Enabled=1 + DisabledByDefault=0

  NonCompliant:
    FIPS Enabled=0; TLS 1.0/1.1 re-enabled (Enabled=1); TLS 1.2 disabled (Enabled=0)

  WARNING: enabling FIPS mode (Enabled=1) applies a system-wide cryptography
  policy. It is reverted by Restore mode immediately after the scan phase.
  The agent itself is unaffected because it is already running.
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile  = "$env:TEMP\patched-e2e-tls-fips-state.json"
$FipsKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
$SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

$TlsProfiles = @(
    @{ Path="$SchannelBase\TLS 1.0\Client";  Role='Disabled' }
    @{ Path="$SchannelBase\TLS 1.0\Server";  Role='Disabled' }
    @{ Path="$SchannelBase\TLS 1.1\Client";  Role='Disabled' }
    @{ Path="$SchannelBase\TLS 1.1\Server";  Role='Disabled' }
    @{ Path="$SchannelBase\TLS 1.2\Client";  Role='Enabled'  }
    @{ Path="$SchannelBase\TLS 1.2\Server";  Role='Enabled'  }
)

function Read-Val([string]$path, [string]$name) {
    (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
}

function Save-State {
    if (Test-Path $StateFile) { return }
    $s = @{
        FipsEnabled = (Read-Val $FipsKey 'Enabled')
        Tls         = @{}
    }
    foreach ($p in $TlsProfiles) {
        $key = $p.Path.Replace('\', '_')
        $s.Tls[$key] = @{
            Enabled           = (Read-Val $p.Path 'Enabled')
            DisabledByDefault = (Read-Val $p.Path 'DisabledByDefault')
            KeyExisted        = (Test-Path $p.Path)
        }
    }
    $s | ConvertTo-Json -Depth 5 | Set-Content $StateFile
    Write-Host "  [tls-fips] State saved."
}

function Set-Baseline {
    # FIPS: enable
    if (-not (Test-Path $FipsKey)) { New-Item -Path $FipsKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $FipsKey -Name 'Enabled' -Value 1 -Type DWord

    # Set the compliant state explicitly. Removing the keys used to be the
    # baseline, but an absent key reads "Unknown", which fails (PAT-1749).
    foreach ($p in $TlsProfiles) {
        if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
        $enabled = if ($p.Role -eq 'Enabled') { 1 } else { 0 }
        Set-ItemProperty -LiteralPath $p.Path -Name 'Enabled' -Value $enabled -Type DWord
        Set-ItemProperty -LiteralPath $p.Path -Name 'DisabledByDefault' -Value (1 - $enabled) -Type DWord
    }
    Write-Host "  [tls-fips] Baseline applied."
}

function Set-NonCompliant {
    # FIPS: disable
    if (-not (Test-Path $FipsKey)) { New-Item -Path $FipsKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $FipsKey -Name 'Enabled' -Value 0 -Type DWord

    # TLS 1.0/1.1: re-enable (Enabled=1 → collector returns "No" for disabled rule)
    foreach ($p in $TlsProfiles | Where-Object { $_.Role -eq 'Disabled' }) {
        if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
        Set-ItemProperty -LiteralPath $p.Path -Name 'Enabled' -Value 1 -Type DWord
    }
    # TLS 1.2: disable (Enabled=0 → collector returns "No")
    foreach ($p in $TlsProfiles | Where-Object { $_.Role -eq 'Enabled' }) {
        if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
        Set-ItemProperty -LiteralPath $p.Path -Name 'Enabled' -Value 0 -Type DWord
        Set-ItemProperty -LiteralPath $p.Path -Name 'DisabledByDefault' -Value 1 -Type DWord
    }
    Write-Host "  [tls-fips] NonCompliant applied."
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[tls-fips] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json

    # FIPS
    if ($null -eq $s.FipsEnabled) {
        Remove-ItemProperty -LiteralPath $FipsKey -Name 'Enabled' -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $FipsKey)) { New-Item -Path $FipsKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $FipsKey -Name 'Enabled' -Value ([int]$s.FipsEnabled) -Type DWord
    }

    # TLS profiles
    foreach ($p in $TlsProfiles) {
        $key   = $p.Path.Replace('\', '_')
        $entry = $s.Tls.$key
        if ($null -eq $entry) { continue }
        if (-not $entry.KeyExisted) {
            Remove-Item -LiteralPath $p.Path -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
            if ($null -ne $entry.Enabled) {
                Set-ItemProperty -LiteralPath $p.Path -Name 'Enabled' -Value ([int]$entry.Enabled) -Type DWord
            }
            if ($null -ne $entry.DisabledByDefault) {
                Set-ItemProperty -LiteralPath $p.Path -Name 'DisabledByDefault' -Value ([int]$entry.DisabledByDefault) -Type DWord
            }
        }
    }

    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [tls-fips] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
