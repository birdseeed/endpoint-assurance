using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1110. Pure content assertions on the generated removal script — the shape and
/// ordering of what runs in the detached scheduled task. Cannot exercise the script
/// AGAINST a real Windows service/MSI/Task Scheduler from this (or any) CI host; see
/// the PAT-1110 report for exactly which acceptance criteria require a real Windows
/// VM. This proves the generator emits the right instructions in the right order,
/// not that PowerShell/msiexec/schtasks actually do what the instructions say.
/// </summary>
public class DecommissionHandoffScriptTests
{
    private const string TaskName        = "PatchedAgentDecommission";
    private const string StateDir        = @"C:\ProgramData\Patched";
    private const string ReportCredsFile = @"C:\ProgramData\Patched\decommission\report-creds.json";
    private const string DecommissionDir = @"C:\ProgramData\Patched\decommission";

    private static string BuildScript(bool purge = false, string stateDir = StateDir, int directiveVersion = 7) =>
        DecommissionHandoffScript.Build(TaskName, purge, stateDir, directiveVersion, ReportCredsFile);

    [Fact]
    public void Build_StopsAndDisablesServiceBeforeRemovingAnything()
    {
        string script = BuildScript();

        int disableIdx = script.IndexOf("Set-Service -Name $serviceName -StartupType Disabled", StringComparison.Ordinal);
        int stopIdx    = script.IndexOf("Stop-Service -Name $serviceName", StringComparison.Ordinal);
        int msiexecIdx = script.IndexOf("Start-Process msiexec.exe", StringComparison.Ordinal);

        Assert.True(disableIdx >= 0 && stopIdx >= 0 && msiexecIdx >= 0);
        // Reboot-safety invariant: startup must be disabled AND the service stopped
        // strictly before msiexec ever runs, so an interruption between these steps
        // can never leave a registered, auto-starting service pointing at binaries
        // msiexec is mid-way through deleting.
        Assert.True(disableIdx < msiexecIdx);
        Assert.True(stopIdx < msiexecIdx);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 2a): core removal verification must check
    // THREE independent signals -- MSI Uninstall key, service registration, and
    // the installed binary -- not the Uninstall key alone. msiexec can defer to a
    // reboot-pending state and return before the other two are actually gone.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_CoreRemovalVerification_ChecksMsiKey_Service_AndBinary_AllThree()
    {
        string script = BuildScript();

        // 4a: MSI Uninstall key (pre-existing, round-1 hardened).
        Assert.Contains("$msiKeyPresent = $false", script);
        Assert.Contains("$msiKeyPresent = $true", script);

        // 4b: the Windows service registration itself, distinct from the Uninstall key.
        Assert.Contains("$serviceStillRegistered = $false", script);
        Assert.Contains("Get-Service -Name $serviceName -ErrorAction Stop", script);
        Assert.Contains("$serviceStillRegistered = $true", script);
        // Fail closed: a Get-Service error OTHER than "not found" must NOT be read
        // as "service is gone".
        Assert.Contains("FullyQualifiedErrorId -notlike 'NoServiceFoundForGivenName*'", script);

        // 4c: the installed binary on disk, independent of both registry checks.
        Assert.Contains("Join-Path $env:ProgramFiles 'Patched'", script);
        Assert.Contains("$serviceExeName", script);
        Assert.Contains("$binaryStillPresent = Test-Path $serviceBinaryPath", script);

        // All three combine into one fail-closed gate.
        Assert.Contains(
            "$coreRemovalVerified = -not ($msiKeyPresent -or $serviceStillRegistered -or $binaryStillPresent -or $verifyFailed)",
            script);
    }

    [Fact]
    public void Build_CoreRemovalVerification_AnySingleSignalStillPresent_FailsClosed()
    {
        string script = BuildScript();

        int verifiedIdx = script.IndexOf("$coreRemovalVerified = -not (", StringComparison.Ordinal);
        int exitIdx      = script.IndexOf("if (-not $coreRemovalVerified) {", StringComparison.Ordinal);
        int exit1Idx     = script.IndexOf("exit 1", exitIdx, StringComparison.Ordinal);

        Assert.True(verifiedIdx >= 0 && exitIdx > verifiedIdx && exit1Idx > exitIdx);
    }

    [Fact]
    public void Build_VerifiesByReinspectionBeforeSelfDeletingTask()
    {
        string script = BuildScript();

        int msiexecIdx      = script.IndexOf("Start-Process msiexec.exe", StringComparison.Ordinal);
        int stillPresentIdx = script.IndexOf("$msiKeyPresent = $true", StringComparison.Ordinal);
        int exitIdx         = script.IndexOf("if (-not $coreRemovalVerified) {", StringComparison.Ordinal);
        int deleteTaskIdx   = script.IndexOf("schtasks.exe /Delete", StringComparison.Ordinal);

        Assert.True(msiexecIdx < stillPresentIdx);
        Assert.True(stillPresentIdx < exitIdx);
        // Self-deleting the scheduled task must come AFTER the re-inspection check,
        // and the script must exit early (leaving the task registered to retry on
        // next boot) when the product is still present — never unconditionally.
        Assert.True(exitIdx < deleteTaskIdx);
        Assert.Contains("exit 1", script);
    }

    [Fact]
    public void Build_ResolvesProductCodeByDisplayName_Not_Hardcoded()
    {
        string script = BuildScript();

        // ProductCode is regenerated per WiX build (only UpgradeCode is pinned in
        // Product.wxs), so the script must resolve it at run time via the same
        // DisplayName match RegistryUninstallLookup.cs uses for third-party apps,
        // not embed a fixed GUID.
        Assert.Contains("CurrentVersion\\Uninstall", script);
        Assert.Contains("$productName", script);
        Assert.DoesNotContain("{B0000001", script); // not a hardcoded component/product GUID
    }

    [Fact]
    public void Build_PurgeTrue_RemovesStateDir()
    {
        string script = BuildScript(purge: true);

        Assert.Contains("$purge              = $true", script);
        Assert.Contains("Remove-Item -Path $_.FullName -Recurse -Force", script);
    }

    [Fact]
    public void Build_PurgeFalse_NeverRemovesStateDir()
    {
        string script = BuildScript(purge: false);

        Assert.Contains("$purge              = $false", script);
        Assert.Contains("if ($purge) {", script);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 2b): the decommission directory (script,
    // report-creds snapshot, log, attempt counter) must survive the purge sweep,
    // or the terminal report could never authenticate and a next-boot retry would
    // have no script left to run.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_PurgeSweep_ExcludesDecommissionDirectory()
    {
        string script = BuildScript(purge: true);

        Assert.Contains("Where-Object {", script);
        Assert.Contains("$_.FullName -ne $decommissionDir", script);
        // The purge sweep must NOT be a blanket "remove everything under
        // $stateDir" the way round-1's implementation was -- that literal call is
        // gone, replaced by the filtered Get-ChildItem | Where-Object | ForEach-Object.
        Assert.DoesNotContain("Remove-Item -Path $stateDir -Recurse -Force -ErrorAction SilentlyContinue", script);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 3): purge must be VERIFIED, not
    // fire-and-forget. If not verified, the task must NOT be deregistered and the
    // terminal report must NOT be sent.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_PurgeTrue_IsVerifiedAfterRemoval_NotFireAndForget()
    {
        string script = BuildScript(purge: true);

        Assert.Contains("$purgeVerified = $true", script);

        // stateDir emptiness (besides the surviving decommission dir).
        Assert.Contains("$remaining = @(Get-ChildItem -Path $stateDir", script);
        Assert.Contains("$purgeVerified = $false", script);

        // Each Credential Manager target's actual unresolvability, via cmdkey /list:.
        Assert.Contains("cmdkey.exe /list:$credTarget", script);
        Assert.Contains("-match 'Target:'", script);

        // Registry provisioning key absence.
        Assert.Contains("if (Test-Path $credRegistryKey) {", script);

        // If purge could not be verified: exit 1 (retry path), same as core
        // removal's own fail-closed gate -- and this must come BEFORE the
        // terminal-report section, not after.
        int purgeVerifiedGateIdx = script.IndexOf("if (-not $purgeVerified) {", StringComparison.Ordinal);
        int reportSectionIdx     = script.IndexOf("# 6. Report the VERIFIED terminal status.", StringComparison.Ordinal);
        Assert.True(purgeVerifiedGateIdx >= 0 && reportSectionIdx > purgeVerifiedGateIdx);
    }

    [Fact]
    public void Build_PurgeFalse_SkipsPurgeVerification_ReportStillReachable()
    {
        string script = BuildScript(purge: false);

        // purge=false takes the "else" branch and never touches $purgeVerified —
        // reporting after verified core removal alone is fine per the brief.
        int elseIdx   = script.IndexOf("} else {", script.IndexOf("if ($purge) {", StringComparison.Ordinal), StringComparison.Ordinal);
        int reportIdx = script.IndexOf("# 6. Report the VERIFIED terminal status.", StringComparison.Ordinal);
        Assert.True(elseIdx > 0 && reportIdx > elseIdx);
    }

    [Fact]
    public void Build_SelfDeletesScheduledTaskOnlyAfterVerifiedComplete()
    {
        string script = BuildScript();

        Assert.Contains($"schtasks.exe /Delete /TN $taskName /F", script);
    }

    [Fact]
    public void Build_EscapesEmbeddedSingleQuotesInStateDir()
    {
        string script = BuildScript(stateDir: @"C:\Program Data\It's Patched");
        Assert.Contains("It''s Patched", script);
    }

    [Fact]
    public void Build_DecommissionDirIsReportCredsFilesParent_ComputedWithoutOsPathApi()
    {
        // Regression guard: this was computed via System.IO.Path.GetDirectoryName
        // in an earlier draft, which resolves separators using the HOST OS's own
        // convention -- on a non-Windows test host that silently returns "" for a
        // backslash-only Windows path instead of throwing, which would have shipped
        // a script that could never find its own script/creds/log directory. The
        // computation must be OS-independent (a literal backslash split), so this
        // test -- run on macOS -- is itself the regression proof.
        string script = BuildScript();
        Assert.Contains($"$decommissionDir    = '{DecommissionDir}'", script);
        Assert.DoesNotContain("$decommissionDir    = ''", script);
    }

    // -------------------------------------------------------------------------
    // Second contract round: two-phase status reporting. The terminal "removed"
    // report is now this script's job (the .NET service reporting "acknowledged"
    // is stopped partway through this same script and can never verify the
    // outcome itself), so its ordering relative to verification/purge/self-delete
    // matters as much as msiexec's does.
    // -------------------------------------------------------------------------

    [Fact]
    public void Build_ReportsTerminalStatus_OnlyAfterVerifiedComplete_BeforePurgeAndSelfDelete()
    {
        string script = BuildScript();

        int verifiedIdx   = script.IndexOf("core removal verified complete", StringComparison.Ordinal);
        int reportIdx     = script.IndexOf("Invoke-WebRequest -Uri \"$($creds.api_url)", StringComparison.Ordinal);
        int purgeIdx      = script.IndexOf("if ($purge) {", StringComparison.Ordinal);
        int deleteTaskIdx = script.IndexOf("schtasks.exe /Delete", StringComparison.Ordinal);

        Assert.True(verifiedIdx >= 0 && reportIdx >= 0 && purgeIdx >= 0 && deleteTaskIdx >= 0);

        // Never post a terminal status you have not verified: the report step must
        // come strictly after the core-removal verification concludes success.
        Assert.True(verifiedIdx < reportIdx);

        // Report before the task self-deletes.
        Assert.True(reportIdx < deleteTaskIdx);
    }

    [Fact]
    public void Build_PurgeTrue_ReportsOnlyAfterPurgeVerified_NotBeforePurge()
    {
        // Non-author review round 2 (item 2b): for purge=true, the report must come
        // AFTER purge (and its verification), never before -- reporting "removed"
        // before an explicitly-requested purge is actually confirmed complete is
        // the same unverified-report bug the second contract round already closed
        // for core removal, recurring one step later.
        string script = BuildScript(purge: true);

        int purgeStartIdx  = script.IndexOf("if ($purge) {", StringComparison.Ordinal);
        int purgeVerifyIdx = script.IndexOf("Log \"purge verified complete\"", StringComparison.Ordinal);
        int reportIdx      = script.IndexOf("Invoke-WebRequest -Uri \"$($creds.api_url)", StringComparison.Ordinal);

        Assert.True(purgeStartIdx >= 0 && purgeVerifyIdx > purgeStartIdx && reportIdx > purgeVerifyIdx);
    }

    [Fact]
    public void Build_TerminalReport_UsesAcknowledgedStatusNever_ReportsRemoved()
    {
        string script = BuildScript();

        Assert.Contains("status             = 'removed'", script);
        Assert.DoesNotContain("status = 'acknowledged'", script);
        Assert.DoesNotContain("status = 'removing'", script); // pre-contract-update status name must be gone
    }

    [Fact]
    public void Build_TerminalReport_SendsDirectiveVersion()
    {
        string script = DecommissionHandoffScript.Build(TaskName, purge: false, StateDir, directiveVersion: 42, ReportCredsFile);

        Assert.Contains("$directiveVersion   = 42", script);
        Assert.Contains("directive_version  = $directiveVersion", script);
    }

    [Fact]
    public void Build_TerminalReport_ComputesV3HmacOverMethodEndpointTimestampNonceAndBody()
    {
        // PAT-1154: the platform verifies v3 signatures: HMAC over
        // "patched-hmac-v3\nPOST\nagent_decommission_status\n" + ts + "\n" + nonce + "\n" + body, never the body
        // alone. This script authenticates its own terminal-status POST after the
        // .NET service (and HmacSigner.cs) is long gone, so it must build the exact
        // same signing input by hand rather than over just $bodyBytes.
        string script = BuildScript();

        Assert.Contains("HMACSHA256", script);
        Assert.Contains("[Convert]::FromBase64String($creds.hmac_secret)", script);
        Assert.Contains("patched-hmac-v3", script);
        Assert.Contains("X-Patched-Signature", script);
        Assert.Contains("X-Patched-Timestamp", script);
        Assert.Contains("X-Patched-Nonce", script);

        // The signing input must be built from prefix + method + endpoint + timestamp + nonce +
        // body, in that order, and the HMAC must be computed over that combined
        // buffer ($signingInput), not $bodyBytes alone.
        int tsIdx        = script.IndexOf("$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()", StringComparison.Ordinal);
        int nonceIdx     = script.IndexOf("$nonce     = [guid]::NewGuid().ToString('N')", StringComparison.Ordinal);
        int prefixIdx    = script.IndexOf("patched-hmac-v3", StringComparison.Ordinal);
        int signingIdx   = script.IndexOf("$signingInput = $prefixBytes + $methodBytes + $endpointBytes + $tsBytes + $nonceBytes + $bodyBytes", StringComparison.Ordinal);
        int computeIdx   = script.IndexOf("$hmac.ComputeHash($signingInput)", StringComparison.Ordinal);

        Assert.True(tsIdx >= 0 && nonceIdx >= 0 && prefixIdx >= 0 && signingIdx >= 0 && computeIdx >= 0);
        Assert.True(tsIdx < signingIdx);
        Assert.True(nonceIdx < signingIdx);
        Assert.True(prefixIdx < signingIdx);
        Assert.True(signingIdx < computeIdx);
        Assert.DoesNotContain("$hmac.ComputeHash($bodyBytes)", script);
    }

    // -------------------------------------------------------------------------
    // Non-author review (P0): the report-creds snapshot is DPAPI-protected at
    // rest (DecommissionHandoff.WriteReportCredsSnapshot), matching the
    // protection level CredentialStore already gives this exact bearer
    // token/HMAC secret via Windows Credential Manager, rather than relying on
    // the decommission directory's ACLs alone. This script is the only reader,
    // so it must decrypt with the SAME scope (LocalMachine — it runs as SYSTEM
    // via the scheduled task, not as whatever user was logged in when the
    // service staged the file) before ever treating the file's bytes as JSON.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_TerminalReport_DecryptsReportCredsWithDpapiLocalMachineScope_BeforeParsingJson()
    {
        string script = BuildScript();

        Assert.Contains("Add-Type -AssemblyName System.Security", script);
        Assert.Contains("[System.IO.File]::ReadAllBytes($reportCredsFile)", script);
        Assert.Contains("[System.Security.Cryptography.ProtectedData]::Unprotect(", script);
        Assert.Contains("[System.Security.Cryptography.DataProtectionScope]::LocalMachine", script);

        int addTypeIdx    = script.IndexOf("Add-Type -AssemblyName System.Security", StringComparison.Ordinal);
        int readBytesIdx  = script.IndexOf("[System.IO.File]::ReadAllBytes($reportCredsFile)", StringComparison.Ordinal);
        int unprotectIdx  = script.IndexOf("[System.Security.Cryptography.ProtectedData]::Unprotect(", StringComparison.Ordinal);
        int getStringIdx  = script.IndexOf("[System.Text.Encoding]::UTF8.GetString($decryptedCredsBytes)", StringComparison.Ordinal);
        int convertJsonIdx = script.IndexOf("$creds = $credsJson | ConvertFrom-Json", StringComparison.Ordinal);

        Assert.True(addTypeIdx >= 0 && readBytesIdx > addTypeIdx);
        Assert.True(unprotectIdx > readBytesIdx);
        Assert.True(getStringIdx > unprotectIdx);
        Assert.True(convertJsonIdx > getStringIdx);

        // Never fall back to reading the file as plaintext JSON directly.
        Assert.DoesNotContain("Get-Content -Path $reportCredsFile -Raw | ConvertFrom-Json", script);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (P2): a failed terminal report must NOT destroy
    // the report-creds snapshot or deregister the task -- it must retry across
    // boots, bounded, before giving up.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_TerminalReport_RetriesAcrossBoots_BoundedBudget_BeforeGivingUp()
    {
        string script = BuildScript();

        // A persistent, cross-boot attempt counter, incremented BEFORE attempting
        // (so a mid-POST crash still counts against the bound).
        Assert.Contains("$reportAttemptsFile = Join-Path $decommissionDir 'report-attempts.count'", script);
        Assert.Contains("Set-Content -Path $reportAttemptsFile -Value \"$bootAttempt\" -Force", script);
        Assert.Contains($"$maxCrossBootReportAttempts = {DecommissionHandoffScript.MaxCrossBootReportAttempts}", script);

        // Not delivered and budget not exhausted -> exit 1 (retry next boot), and
        // this exit must come BEFORE the creds snapshot is ever removed.
        int notDeliveredIdx = script.IndexOf("if (-not $giveUp) {", StringComparison.Ordinal);
        int exitIdx         = script.IndexOf("exit 1", notDeliveredIdx, StringComparison.Ordinal);
        int removeCredsIdx  = script.IndexOf("Remove-Item -Path $reportCredsFile -Force -ErrorAction SilentlyContinue", StringComparison.Ordinal);
        int deleteTaskIdx   = script.IndexOf("schtasks.exe /Delete", StringComparison.Ordinal);

        Assert.True(notDeliveredIdx >= 0 && exitIdx > notDeliveredIdx);
        Assert.True(exitIdx < removeCredsIdx);
        Assert.True(exitIdx < deleteTaskIdx);

        // Budget IS part of the give-up decision (delivered OR exhausted).
        Assert.Contains("$giveUp = $reported -or ($bootAttempt -ge $maxCrossBootReportAttempts)", script);
    }

    [Fact]
    public void Build_TerminalReport_NoCredsFileAtAll_GivesUpImmediately_DoesNotLoopForever()
    {
        // A genuinely missing report-creds file (distinct from "POST failed") is
        // not retried -- there is nothing that will ever fix itself without the
        // .NET service re-staging, which will not happen once committed.
        string script = BuildScript();

        int noFileIdx = script.IndexOf("Log \"no report-creds file found -- terminal status unreported\"", StringComparison.Ordinal);
        Assert.True(noFileIdx >= 0);
        int giveUpTrueIdx = script.IndexOf("$giveUp = $true", noFileIdx, StringComparison.Ordinal);
        Assert.True(giveUpTrueIdx > noFileIdx && giveUpTrueIdx < noFileIdx + 100);
    }

    [Fact]
    public void Build_TerminalReport_DeletesCredsSnapshot_OnlyOnceGivenUp()
    {
        // The finally-style cleanup must remove the single-use creds snapshot
        // (and the attempt counter) only once $giveUp is true (delivered, no file
        // existed, or budget exhausted) -- never on a not-yet-exhausted failure,
        // which exits early instead (see the test above).
        string script = BuildScript();

        int giveUpCheckIdx = script.IndexOf("if (-not $giveUp) {", StringComparison.Ordinal);
        int removeCredsIdx = script.IndexOf("Remove-Item -Path $reportCredsFile -Force", StringComparison.Ordinal);
        int removeAttemptsIdx = script.IndexOf("Remove-Item -Path $reportAttemptsFile -Force", StringComparison.Ordinal);

        Assert.True(giveUpCheckIdx >= 0 && removeCredsIdx > giveUpCheckIdx && removeAttemptsIdx > removeCredsIdx);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 2b / P2 combined): the decommission
    // directory itself (holding the now-consumed creds snapshot and log) is only
    // removed, for purge=true, as the very LAST action -- after self-deleting the
    // scheduled task, never before (or the task's own target script would vanish
    // while it might still need to run/retry).
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_PurgeTrue_RemovesDecommissionDirectory_AsVeryLastStep()
    {
        string script = BuildScript(purge: true);

        int deleteTaskIdx = script.IndexOf("schtasks.exe /Delete /TN $taskName /F", StringComparison.Ordinal);
        int removeDirIdx  = script.IndexOf("Remove-Item -Path $decommissionDir -Recurse -Force", StringComparison.Ordinal);

        Assert.True(deleteTaskIdx >= 0 && removeDirIdx > deleteTaskIdx);
    }

    [Fact]
    public void Build_PurgeFalse_NeverRemovesDecommissionDirectory()
    {
        string script = BuildScript(purge: false);

        // The removal call is shared code inside "if ($purge) {" at the very end —
        // present in the text (gated at runtime) but only reachable when $purge is
        // true.
        Assert.Contains("Remove-Item -Path $decommissionDir -Recurse -Force -ErrorAction SilentlyContinue", script);
        int lastPurgeIfIdx = script.LastIndexOf("if ($purge) {", StringComparison.Ordinal);
        int removeDirIdx   = script.IndexOf("Remove-Item -Path $decommissionDir -Recurse -Force", StringComparison.Ordinal);
        Assert.True(lastPurgeIfIdx >= 0 && removeDirIdx > lastPurgeIfIdx);
    }

    [Fact]
    public void Build_LogFile_LivesInsideDecommissionDir_SurvivesPurgeSweep()
    {
        // The log used to live under $stateDir\logs, which the purge sweep would
        // delete along with everything else -- moved inside $decommissionDir
        // (excluded from that sweep) so the operational record of what actually
        // happened survives purge, consistent with never destroying evidence of
        // what was verified.
        string script = BuildScript();
        Assert.Contains("$logFile            = Join-Path $decommissionDir 'decommission.log'", script);
        Assert.DoesNotContain("Join-Path $stateDir 'logs\\decommission.log'", script);
    }

    // -------------------------------------------------------------------------
    // Non-author review round 2 (item 3): purge Credential Manager cleanup, now
    // generated from CredentialStore.cs's own constants (round-1 P1-D), still
    // present and unchanged in shape.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_PurgeTrue_RemovesCredentialManagerEntries_GeneratedFromCredentialStore()
    {
        string script = BuildScript(purge: true);

        Assert.Contains("'PatchedAgent/TenantId'", script);
        Assert.Contains("'PatchedAgent/BearerToken'", script);
        Assert.Contains("'PatchedAgent/HmacSecret'", script);
        Assert.Contains("'PatchedAgent/CanonicalDeviceIdentity'", script);
        Assert.Contains("'PatchedAgent/EnrollmentToken'", script);
        Assert.Contains("cmdkey.exe /delete:$credTarget", script);

        int purgeIdx        = script.IndexOf("if ($purge) {", StringComparison.Ordinal);
        int credCleanupIdx  = script.IndexOf("cmdkey.exe /delete:$credTarget", StringComparison.Ordinal);
        int elseIdx         = script.IndexOf("} else {", purgeIdx, StringComparison.Ordinal);
        Assert.True(purgeIdx >= 0 && credCleanupIdx >= 0 && elseIdx >= 0);
        Assert.True(purgeIdx < credCleanupIdx);
        Assert.True(credCleanupIdx < elseIdx);
    }

    [Fact]
    public void Build_PurgeTrue_RemovesRegistryProvisioningKey()
    {
        string script = BuildScript(purge: true);

        Assert.Contains(@"HKLM:\SOFTWARE\Patched\Enrollment", script);
        Assert.Contains("Remove-Item -Path $credRegistryKey -Recurse -Force", script);
    }

    [Fact]
    public void Build_PurgeFalse_NeverTouchesCredentialManagerOrRegistry()
    {
        string script = BuildScript(purge: false);

        int purgeIdx = script.IndexOf("if ($purge) {", StringComparison.Ordinal);
        int elseIdx  = script.IndexOf("} else {", purgeIdx, StringComparison.Ordinal);
        int credIdx  = script.IndexOf("cmdkey.exe /delete:$credTarget", StringComparison.Ordinal);
        int regIdx   = script.IndexOf("Remove-Item -Path $credRegistryKey", StringComparison.Ordinal);

        Assert.True(purgeIdx >= 0 && elseIdx > purgeIdx);
        Assert.True(credIdx > purgeIdx && credIdx < elseIdx);
        Assert.True(regIdx > purgeIdx && regIdx < elseIdx);
    }

    // PAT-1764: a full uninstall purges the agent credentials unless the MSI is told to
    // retain them. purge=false retains credentials by contract, so it must opt out.
    [Fact]
    public void Build_PurgeFalse_TellsMsiToRetainCredentials()
    {
        string script = BuildScript(purge: false);

        Assert.Contains(
            "Start-Process msiexec.exe -ArgumentList \"/x $productCode /qn /norestart PATCHED_RETAIN_CREDENTIALS=1\"",
            script);
        Assert.Equal("PATCHED_RETAIN_CREDENTIALS", DecommissionHandoffScript.RetainCredentialsMsiProperty);
    }

    [Fact]
    public void Build_PurgeTrue_LetsMsiPurgeCredentials()
    {
        string script = BuildScript(purge: true);

        Assert.Contains("Start-Process msiexec.exe -ArgumentList \"/x $productCode /qn /norestart\"", script);
        Assert.DoesNotContain("PATCHED_RETAIN_CREDENTIALS", script);
    }
}
