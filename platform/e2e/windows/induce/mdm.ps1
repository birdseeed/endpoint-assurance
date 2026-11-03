<#
.SYNOPSIS  Induce/restore MDM enrollment compliance state.

.DESCRIPTION
  Signal: mdm_enrolled
  Rule:   patched_win_mdm_enrolled expects eq "Yes"
  Source: ComplianceCollector.cs AddMdmEnrolment() lines 227-241.

  The collector reports "Yes" only for a sub-key of
  HKLM\SOFTWARE\Microsoft\Enrollments with EnrollmentState=1, a ProviderID
  that is not a built-in local authority, and a DiscoveryServiceFullURL
  (updater PAT-1751). Windows' own sub-keys on an unenrolled device read "No".

  Baseline:     Create a fake enrollment sub-key (e2e-fake-enrollment).
  NonCompliant: Remove the fake enrollment sub-key.
  Restore:      Remove the fake key (or restore real keys from saved state).

  NOTE: On a real Intune-enrolled machine this script would NOT be run in
  NonCompliant mode (it would destroy real enrollment state). On a GitHub
  Actions runner, the machine is ephemeral and not MDM-enrolled.
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile   = "$env:TEMP\patched-e2e-mdm-state.json"
$KeyPath     = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$FakeSubkey  = 'e2e-fake-enrollment'
$FakeKeyPath = "$KeyPath\$FakeSubkey"

function Read-SubkeyNames {
    if (-not (Test-Path $KeyPath)) { return @() }
    (Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue).PSChildName
}

function Save-State {
    if (Test-Path $StateFile) { return }
    $names = Read-SubkeyNames
    @{ SubkeyNames = $names; KeyExisted = (Test-Path $KeyPath) } |
        ConvertTo-Json | Set-Content $StateFile
    Write-Host "  [mdm] State saved (existing sub-keys: $($names -join ', '))."
}

function Set-Baseline {
    # Ensure the parent key exists.
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    # Create the fake enrollment sub-key if not already present.
    if (-not (Test-Path $FakeKeyPath)) { New-Item -Path $FakeKeyPath -Force | Out-Null }
    # PAT-1751: the collector no longer counts a bare sub-key (Windows ships
    # built-in ones on unenrolled devices). An enrollment counts only with
    # EnrollmentState=1, a non-built-in ProviderID and a discovery URL.
    Set-ItemProperty -LiteralPath $FakeKeyPath -Name 'ProviderID' -Value 'MS DM Server' -Type String
    Set-ItemProperty -LiteralPath $FakeKeyPath -Name 'EnrollmentState' -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $FakeKeyPath -Name 'DiscoveryServiceFullURL' -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -Type String
    Write-Host "  [mdm] Baseline applied (fake enrollment sub-key created)."
}

function Set-NonCompliant {
    # Remove only the fake enrollment. The runner is not MDM-enrolled, and
    # since PAT-1751 Windows' built-in sub-keys read "No", so deleting them
    # (as this used to) is unnecessary and could not make them read "No" anyway.
    Remove-Item -LiteralPath $FakeKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [mdm] NonCompliant applied (fake enrollment sub-key removed)."
}

function Restore-State {
    if (-not (Test-Path $StateFile)) { Write-Warning "[mdm] No state file; skipping."; return }
    $s = Get-Content $StateFile | ConvertFrom-Json

    # Remove the fake key we may have created.
    Remove-Item -LiteralPath $FakeKeyPath -Recurse -Force -ErrorAction SilentlyContinue

    # If original state had no key, ensure it's absent.
    if (-not $s.KeyExisted -and (Test-Path $KeyPath)) {
        $remaining = (Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue).Count
        if ($remaining -eq 0) {
            Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [mdm] State restored."
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
