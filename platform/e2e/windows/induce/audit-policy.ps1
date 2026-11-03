<#
.SYNOPSIS  Induce/restore CIS §17 Advanced Audit Policy subcategory state.

.DESCRIPTION
  Signals (verified against AuditPolicyParser.cs and rules.csv):

  auditpol subcategory display name → signal key → required Inclusion Setting
    "Credential Validation"     → audit_credential_validation     → "Success and Failure"  (eq)
    "User Account Management"   → audit_user_account_management   → "Success and Failure"  (eq)
    "Security Group Management" → audit_security_group_management → contains "Success"
    "Process Creation"          → audit_process_creation          → contains "Success"
    "Logon"                     → audit_logon                     → "Success and Failure"  (eq)
    "Account Lockout"           → audit_account_lockout           → contains "Failure"
    "Audit Policy Change"       → audit_policy_change             → contains "Success"
    "Sensitive Privilege Use"   → audit_sensitive_privilege_use   → "Success and Failure"  (eq)
    "System Integrity"          → audit_system_integrity          → "Success and Failure"  (eq)
    "Security State Change"     → audit_security_state_change     → contains "Success"

  All have treat_unknown_as=fail; absent subcategory → signal omitted → server fails.

  Baseline:      success+failure for all ten subcategories.
  NonCompliant:  "No Auditing" for all ten (auditpol /success:disable /failure:disable).

  Save/restore uses `auditpol /backup` and `auditpol /restore` for fidelity.
#>
param(
    [ValidateSet('Baseline', 'NonCompliant', 'Restore')]
    [string]$Mode = 'Baseline'
)
$ErrorActionPreference = 'Stop'

$StateFile     = "$env:TEMP\patched-e2e-audit-policy-state.csv"
$StateSentinel = "$env:TEMP\patched-e2e-audit-policy-saved.flag"

# Subcategories to manage, in auditpol display-name form.
$Subcategories = @(
    'Credential Validation'
    'User Account Management'
    'Security Group Management'
    'Process Creation'
    'Logon'
    'Account Lockout'
    'Audit Policy Change'
    'Sensitive Privilege Use'
    'System Integrity'
    'Security State Change'
)

function Save-State {
    if (Test-Path $StateSentinel) { return }
    # auditpol /backup saves the *full* system audit policy in CSV format.
    # We use this for a clean restore, avoiding the need to parse output ourselves.
    $null = auditpol /backup /file:$StateFile 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed with exit code $LASTEXITCODE" }
    New-Item -ItemType File -Path $StateSentinel -Force | Out-Null
    Write-Host "  [audit-policy] State backed up to $StateFile."
}

function Set-AuditSubcategory([string]$name, [string]$success, [string]$failure) {
    # auditpol /set /subcategory:"<name>" /success:{enable|disable} /failure:{enable|disable}
    $null = auditpol /set /subcategory:$name /success:$success /failure:$failure 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  auditpol /set '$name' returned $LASTEXITCODE (may be a category alias — continuing)."
    }
}

function Set-Baseline {
    foreach ($sub in $Subcategories) {
        Set-AuditSubcategory $sub 'enable' 'enable'
    }
    Write-Host "  [audit-policy] Baseline applied (Success and Failure for all subcategories)."
}

function Set-NonCompliant {
    foreach ($sub in $Subcategories) {
        Set-AuditSubcategory $sub 'disable' 'disable'
    }
    Write-Host "  [audit-policy] NonCompliant applied (No Auditing for all subcategories)."
}

function Restore-State {
    if (-not (Test-Path $StateSentinel)) { Write-Warning "[audit-policy] No state; skipping."; return }
    if (Test-Path $StateFile) {
        $null = auditpol /restore /file:$StateFile 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol /restore returned $LASTEXITCODE (non-fatal)." }
        Write-Host "  [audit-policy] State restored from backup."
    }
    Remove-Item $StateSentinel -Force -ErrorAction SilentlyContinue
}

switch ($Mode) {
    'Baseline'     { Save-State; Set-Baseline }
    'NonCompliant' { Save-State; Set-NonCompliant }
    'Restore'      { Restore-State }
}
