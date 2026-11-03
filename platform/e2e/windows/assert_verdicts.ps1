<#
.SYNOPSIS  Assert that compliance rule verdicts match the expected phase outcome.

.DESCRIPTION
  Queries GET /admin/tenants/{TenantId}/devices (to find the device) then
  GET /admin/devices/{DeviceId} (to fetch evaluations), then compares
  each Windows rule's observed verdict against the expected value for the
  given Phase.

  Phase Compliant    → every inducible rule must evaluate as "pass"
  Phase NonCompliant → every inducible rule must evaluate as "fail"

  Non-inducible signals are excluded from the check (they are hardware-
  or WMI-dependent and cannot be controlled on a runner).

  Emits a JSON ledger file and exits non-zero if any assertion fails.

  API is on the internal admin listener (:8081); the caller supplies the
  base URL (e.g. http://localhost:8081).

.PARAMETER TenantId
  UUID of the test tenant, returned by POST /admin/tenants.

.PARAMETER AdminApiBaseUrl
  Internal admin listener base URL, e.g. http://localhost:8081.

.PARAMETER AdminApiToken
  Value of ADMIN_API_TOKEN; sent as Bearer token.

.PARAMETER Phase
  "Compliant" or "NonCompliant". Determines expected verdict for each rule.

.PARAMETER LedgerPath
  Path to write the JSON ledger (default: $env:TEMP\patched-e2e-ledger-$Phase.json).

.PARAMETER MaxWaitSeconds
  How long to poll for evaluations to appear (default 150 s, extractor lag).
  The "Enable all T2 rules" step means a full scan now evaluates the whole
  Windows rule set (~73 rules) rather than just T1, so this has more margin
  than the original 90 s default.

.PARAMETER SinceUtc
  ISO-8601 UTC timestamp of this phase's scan trigger. compliance_evaluations
  is append-only (rows from the prior phase are never deleted), so this
  phase's evaluations are only "ready" once every returned row's evaluated_at
  is at or after this timestamp — otherwise we'd read stale rows left over
  from the previous phase.
#>
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AdminApiBaseUrl,
    [Parameter(Mandatory)] [string] $AdminApiToken,
    [Parameter(Mandatory)] [ValidateSet('Compliant','NonCompliant')] [string] $Phase,
    [Parameter(Mandatory)] [string] $SinceUtc,
    [string] $LedgerPath = '',
    [int]    $MaxWaitSeconds = 150
)
$ErrorActionPreference = 'Stop'
$sinceUtcTime = [DateTime]::Parse($SinceUtc).ToUniversalTime()

if ($LedgerPath -eq '') {
    $LedgerPath = "$env:TEMP\patched-e2e-ledger-$Phase.json"
}

# ---------------------------------------------------------------------------
# Non-inducible signal keys — excluded from assertion.
# These are hardware/WMI/tamper-protected signals that cannot be reliably
# controlled on a GitHub Actions windows-latest runner. They will evaluate
# according to treat_unknown_as (mostly fail for hardware-absent, pass for
# WMI signals that are absent when BitLocker is not installed).
#
# Source: verified against ComplianceCollector.cs and rules.csv.
# ---------------------------------------------------------------------------
$NonInducible = [System.Collections.Generic.HashSet[string]]@(
    'bitlocker_os_drive'          # WMI Win32_EncryptableVolume — no BitLocker on runner
    'bitlocker_cipher_256bit'     # WMI BitLocker cipher — no BitLocker on runner
    'tpm_ready'                   # WMI Win32_Tpm — no TPM on VM
    'secure_boot_enabled'         # UEFI SecureBoot — not available in runner VM
    'vbs_enabled'                 # VBS hardware feature — hypervisor required
    'hvci_enabled'                # HVCI hardware feature — hypervisor required
    'kernel_dma_protection'       # Kernel DMA protection — UEFI hardware required
    'defender_realtime'           # Tamper-protection prevents registry writes
    'defender_definition_age_days'# Live WMI definition timestamp — can't safely fake
    'disk_encryption_off'         # WMI BitLocker per-volume — no BitLocker on runner
    'removable_storage_unencrypted'# WMI BitLocker To Go — no removable drives on runner
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Invoke-AdminGet([string]$path) {
    $headers = @{ Authorization = "Bearer $AdminApiToken" }
    $resp = Invoke-WebRequest -Uri "$AdminApiBaseUrl$path" -Headers $headers -UseBasicParsing
    $resp.Content | ConvertFrom-Json
}

# ---------------------------------------------------------------------------
# Step 1: discover the device
# ---------------------------------------------------------------------------
Write-Host "[$Phase] Fetching device list for tenant $TenantId ..."

$devices = $null
$deadline = [DateTime]::UtcNow.AddSeconds($MaxWaitSeconds)
while ($true) {
    try {
        $resp = Invoke-AdminGet "/admin/tenants/$TenantId/devices"
        if ($resp.devices -and $resp.devices.Count -gt 0) {
            $devices = $resp.devices
            break
        }
    } catch {
        Write-Verbose "  [assert] Device list poll error: $_"
    }
    if ([DateTime]::UtcNow -gt $deadline) {
        throw "[assert] Timed out waiting for device to appear in tenant $TenantId."
    }
    Write-Host "  [assert] No devices yet — waiting 5 s ..."
    Start-Sleep -Seconds 5
}

$device = $devices[0]
$DeviceId = $device.id
Write-Host "[$Phase] Device: $DeviceId  ($($device.hostname))"

# ---------------------------------------------------------------------------
# Step 2: poll until evaluations appear (extractor lag)
# ---------------------------------------------------------------------------
Write-Host "[$Phase] Waiting for compliance evaluations to be written ..."

$detail   = $null
$deadline = [DateTime]::UtcNow.AddSeconds($MaxWaitSeconds)
while ($true) {
    try {
        $detail = Invoke-AdminGet "/admin/devices/$DeviceId"
        if ($detail.evaluations -and $detail.evaluations.Count -gt 0) {
            $stale = $detail.evaluations | Where-Object {
                [DateTime]::Parse($_.evaluated_at).ToUniversalTime() -lt $sinceUtcTime
            }
            if (-not $stale) { break }
        }
    } catch {
        Write-Verbose "  [assert] Poll error: $_"
    }
    if ([DateTime]::UtcNow -gt $deadline) {
        throw "[assert] Timed out waiting for fresh (post-$SinceUtc) evaluations for device $DeviceId."
    }
    Write-Host "  [assert] Evaluations not yet fresh — waiting 5 s ..."
    Start-Sleep -Seconds 5
}

$evaluations = $detail.evaluations
Write-Host "[$Phase] Got $($evaluations.Count) evaluation(s)."

# ---------------------------------------------------------------------------
# Step 3: build evaluation index: rule_key → {status, observed_value}
# ---------------------------------------------------------------------------
$evalIndex = @{}
foreach ($e in $evaluations) {
    $evalIndex[$e.rule_key] = $e
}

# ---------------------------------------------------------------------------
# Step 4: load Windows rules from the rules.csv in the e2e/data directory.
# The file is relative to this script's location (same repo checkout).
# Fall back to the caller's working directory if the sibling path doesn't exist.
# ---------------------------------------------------------------------------
# Script lives at e2e/windows/assert_verdicts.ps1; data lives at e2e/data/rules.csv.
# PSScriptRoot = …/e2e/windows; parent = …/e2e; join with data\rules.csv.
$rulesCsvPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\rules.csv'
if (-not (Test-Path $rulesCsvPath)) {
    # Fallback: caller's working directory (e.g. repo root checkout)
    $rulesCsvPath = Join-Path $PWD 'e2e\data\rules.csv'
}
if (-not (Test-Path $rulesCsvPath)) {
    throw "[assert] rules.csv not found. Expected at: $(Split-Path $PSScriptRoot -Parent)\data\rules.csv"
}

Write-Host "[$Phase] Loading rules from $rulesCsvPath ..."
$allRules    = Import-Csv -Path $rulesCsvPath -Header rule_id,platform,tier,signal_key,comparator,expected_values,applicable_arch,treat_unknown_as,severity,benchmark
$windowsRules = $allRules | Where-Object { $_.platform -eq 'windows' }

# ---------------------------------------------------------------------------
# Step 5: assert per rule
# ---------------------------------------------------------------------------
$expectedStatus = if ($Phase -eq 'Compliant') { 'pass' } else { 'fail' }

$ledger   = [System.Collections.Generic.List[psobject]]::new()
$failures = 0
$skipped  = 0
$checked  = 0

foreach ($rule in $windowsRules) {
    $ruleId    = $rule.rule_id
    $signalKey = $rule.signal_key

    # Skip non-inducible signals
    if ($NonInducible.Contains($signalKey)) {
        $ledger.Add([pscustomobject]@{
            rule_id      = $ruleId
            signal_key   = $signalKey
            phase        = $Phase
            verdict      = 'skip'
            reason       = 'non-inducible'
            observed     = $null
            api_status   = $null
        })
        $skipped++
        continue
    }

    $entry = $evalIndex[$ruleId]
    if (-not $entry) {
        # Rule not in evaluations — extractor hasn't written it (unexpected).
        $ledger.Add([pscustomobject]@{
            rule_id      = $ruleId
            signal_key   = $signalKey
            phase        = $Phase
            verdict      = 'MISSING'
            reason       = 'no evaluation row returned by API'
            observed     = $null
            api_status   = $null
        })
        Write-Warning "[assert] MISSING evaluation for $ruleId (signal: $signalKey)"
        $failures++
        continue
    }

    $apiStatus = $entry.status
    $observed  = $entry.observed_value

    if ($apiStatus -eq $expectedStatus) {
        $verdict = 'OK'
    } elseif ($apiStatus -eq 'not_applicable') {
        # Architecture gate or similar — accept silently.
        $verdict = 'skip'
        $reason  = 'not_applicable (arch gate or platform disabled)'
        $skipped++
    } else {
        $verdict = 'FAIL'
        $failures++
    }

    # Note: for 'skip' (not_applicable), $reason was already set above when
    # $verdict was assigned — don't overwrite it here.
    if ($verdict -eq 'FAIL') {
        $reason = "Expected '$expectedStatus' but got '$apiStatus' (observed: $observed)"
    } elseif ($verdict -eq 'OK') {
        $reason = ''
    }

    $ledger.Add([pscustomobject]@{
        rule_id      = $ruleId
        signal_key   = $signalKey
        phase        = $Phase
        verdict      = $verdict
        reason       = $reason
        observed     = $observed
        api_status   = $apiStatus
    })

    if ($verdict -eq 'OK') { $checked++ }
    if ($verdict -eq 'FAIL') {
        Write-Warning "[assert] FAIL $ruleId — expected '$expectedStatus', got '$apiStatus' (signal: $signalKey, observed: $observed)"
    }
}

# ---------------------------------------------------------------------------
# Step 6: emit JSON ledger
# ---------------------------------------------------------------------------
# A rule set that evaluates to zero checked rules (empty filter, renamed rule
# set, upstream contract change, or every rule skipped/missing) must not read
# as a pass just because $failures happens to be 0 — that is "nothing was
# verified", not "everything verified and passed". See PAT-1348.
$noCoverage = ($checked -le 0)

$summary = [pscustomobject]@{
    phase          = $Phase
    device_id      = $DeviceId
    tenant_id      = $TenantId
    total_rules    = $windowsRules.Count
    checked        = $checked
    skipped        = $skipped
    failures       = $failures
    pass           = if ($failures -eq 0 -and -not $noCoverage) { $true } else { $false }
    generated_at   = [DateTime]::UtcNow.ToString('o')
    entries        = $ledger
}

$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
Write-Host "[$Phase] Ledger written to $LedgerPath"
Write-Host "[$Phase] Checked=$checked  Skipped=$skipped  Failures=$failures"

if ($failures -gt 0) {
    Write-Error "[$Phase] $failures assertion failure(s). See ledger at $LedgerPath."
    exit 1
}

if ($noCoverage) {
    Write-Error "[$Phase] Zero rules checked (skipped=$skipped, failures=$failures) — no assertions were actually evaluated, so this is NOT a pass. Nothing was verified. See ledger at $LedgerPath."
    exit 1
}

Write-Host "[$Phase] All assertions passed ($checked checked, $skipped skipped)."
