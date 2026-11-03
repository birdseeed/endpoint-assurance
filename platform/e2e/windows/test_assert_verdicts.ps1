<#
.SYNOPSIS
  Self-contained smoke test for the PAT-1348 zero-checked guard in
  assert_verdicts.ps1.

.DESCRIPTION
  This repo has no PowerShell test harness (no Pester, no *.Tests.ps1
  anywhere) and repo-specific AGENTS.md doesn't name one; the closest
  existing convention is e2e/ui/test_rendered_verdicts.py, a standalone
  test_<name> script runnable directly with its interpreter, not wired
  into CI. This mirrors that shape for PowerShell rather than introducing
  a new heavyweight framework for one script.

  Runs the real assert_verdicts.ps1 end to end, once per case, in a
  throwaway child pwsh process with Invoke-WebRequest and Import-Csv
  stubbed out (no live admin API or on-disk rules.csv needed):

    1. Empty rule set   -> must fail (non-zero exit), ledger checked=0,
       pass=false, and a message that clearly says nothing was checked
       (distinct from the real-failures message).
    2. Normal all-pass  -> must still succeed (exit 0), ledger checked>0,
       pass=true, "All assertions passed" in the output — proves the new
       guard does not regress a genuinely healthy run.

  Run:
    /opt/homebrew/bin/pwsh -NoProfile -File e2e/windows/test_assert_verdicts.ps1
#>
$ErrorActionPreference = 'Stop'
$scriptUnderTest = Join-Path $PSScriptRoot 'assert_verdicts.ps1'
$failCount = 0

# Single-quoted (no-interpolation) template. Placeholders are substituted
# with literal .Replace() below, not -replace, so JSON payload content is
# never treated as a regex pattern.
$runnerTemplate = @'
$ErrorActionPreference = "Stop"
$fakeRules = ConvertFrom-Json -InputObject '__RULES_JSON__'
$fakeEvaluations = ConvertFrom-Json -InputObject '__EVALS_JSON__'
if ($fakeRules -isnot [System.Array]) { $fakeRules = @($fakeRules) }
if ($fakeEvaluations -isnot [System.Array]) { $fakeEvaluations = @($fakeEvaluations) }

function Import-Csv {
    param($Path, $Header)
    return $fakeRules
}

function Invoke-WebRequest {
    param($Uri, $Headers, [switch]$UseBasicParsing)
    if ($Uri -match '/devices$') {
        $body = @{ devices = @(@{ id = 'dev-1'; hostname = 'test-host' }) } | ConvertTo-Json -Compress -Depth 5
    } else {
        $body = @{ evaluations = $fakeEvaluations } | ConvertTo-Json -Compress -Depth 5
    }
    return [pscustomobject]@{ Content = $body }
}

& '__SCRIPT_PATH__' -TenantId 'tenant-1' -AdminApiBaseUrl 'http://fake' -AdminApiToken 'tok' -Phase Compliant -SinceUtc '2020-01-01T00:00:00Z' -LedgerPath '__LEDGER_PATH__' -MaxWaitSeconds 5
if ($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 0 }
'@

function Invoke-Case {
    param(
        [string]   $Name,
        [array]    $Rules,
        [array]    $Evaluations,
        [int]      $ExpectedExit,
        [string[]] $ExpectedOutputContains,
        [bool]     $ExpectedPass,
        [int]      $ExpectedChecked
    )

    $ledgerPath = [System.IO.Path]::GetTempFileName()
    $runnerPath = [System.IO.Path]::GetTempFileName() + '.ps1'

    $rulesJson = $Rules | ConvertTo-Json -Compress -Depth 5
    if (-not $rulesJson) { $rulesJson = '[]' }
    $evalsJson = $Evaluations | ConvertTo-Json -Compress -Depth 5
    if (-not $evalsJson) { $evalsJson = '[]' }

    $runnerContent = $runnerTemplate.
        Replace('__RULES_JSON__', $rulesJson).
        Replace('__EVALS_JSON__', $evalsJson).
        Replace('__SCRIPT_PATH__', $scriptUnderTest).
        Replace('__LEDGER_PATH__', $ledgerPath)

    Set-Content -Path $runnerPath -Value $runnerContent -Encoding UTF8

    $output = & pwsh -NoProfile -File $runnerPath 2>&1 | Out-String
    $actualExit = $LASTEXITCODE

    $ok = $true

    if ($actualExit -ne $ExpectedExit) {
        Write-Host "FAIL [$Name]: exit code $actualExit, expected $ExpectedExit"
        $ok = $false
    }

    foreach ($needle in $ExpectedOutputContains) {
        if ($output -notlike "*$needle*") {
            Write-Host "FAIL [$Name]: output missing expected text: $needle"
            $ok = $false
        }
    }

    if (Test-Path $ledgerPath) {
        $ledger = Get-Content $ledgerPath -Raw | ConvertFrom-Json
        if ($ledger.pass -ne $ExpectedPass) {
            Write-Host "FAIL [$Name]: ledger.pass = $($ledger.pass), expected $ExpectedPass"
            $ok = $false
        }
        if ($ledger.checked -ne $ExpectedChecked) {
            Write-Host "FAIL [$Name]: ledger.checked = $($ledger.checked), expected $ExpectedChecked"
            $ok = $false
        }
    } else {
        Write-Host "FAIL [$Name]: ledger not written at $ledgerPath"
        $ok = $false
    }

    Remove-Item -Path $runnerPath, $ledgerPath -ErrorAction SilentlyContinue

    if ($ok) {
        Write-Host "PASS [$Name]"
    } else {
        Write-Host "--- captured output for [$Name] ---"
        Write-Host $output
        Write-Host "--- end captured output ---"
        $script:failCount++
    }
}

# Case 1: empty rule set (bad filter / renamed rule set / upstream contract
# change). The wait-for-evaluations poll still needs one fresh, unrelated
# evaluation row to break its loop; it must not match any CSV rule, so the
# per-rule loop still evaluates nothing.
Invoke-Case -Name 'empty rule set fails, does not silently pass' `
    -Rules @() `
    -Evaluations @(
        @{ rule_key = 'UNRELATED-999'; status = 'pass'; observed_value = 'true'; evaluated_at = (Get-Date).ToUniversalTime().ToString('o') }
    ) `
    -ExpectedExit 1 `
    -ExpectedOutputContains @('Zero rules checked', 'not a pass') `
    -ExpectedPass $false `
    -ExpectedChecked 0

# Case 2: normal run, all rules present and matching the expected verdict.
# Guards against the new zero-checked guard regressing a genuinely healthy
# run into a failure.
Invoke-Case -Name 'normal all-pass run still passes' `
    -Rules @(
        @{ rule_id = 'WIN-001'; platform = 'windows'; tier = 'T1'; signal_key = 'sig1'; comparator = 'equals'; expected_values = 'true'; applicable_arch = 'x64'; treat_unknown_as = 'fail'; severity = 'high'; benchmark = 'CIS' },
        @{ rule_id = 'WIN-002'; platform = 'windows'; tier = 'T1'; signal_key = 'sig2'; comparator = 'equals'; expected_values = 'true'; applicable_arch = 'x64'; treat_unknown_as = 'fail'; severity = 'high'; benchmark = 'CIS' }
    ) `
    -Evaluations @(
        @{ rule_key = 'WIN-001'; status = 'pass'; observed_value = 'true'; evaluated_at = (Get-Date).ToUniversalTime().ToString('o') },
        @{ rule_key = 'WIN-002'; status = 'pass'; observed_value = 'true'; evaluated_at = (Get-Date).ToUniversalTime().ToString('o') }
    ) `
    -ExpectedExit 0 `
    -ExpectedOutputContains @('All assertions passed') `
    -ExpectedPass $true `
    -ExpectedChecked 2

if ($failCount -gt 0) {
    Write-Host "$failCount case(s) failed."
    exit 1
}

Write-Host "All test_assert_verdicts.ps1 cases passed."
exit 0
