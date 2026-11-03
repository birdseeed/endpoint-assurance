using System.Linq;
using Patched.Shared.Auth;

namespace Patched.Service;

/// <summary>
/// PAT-1110. Builds the PowerShell script the detached scheduled task runs to finish
/// what the running service cannot do to itself: stop the service, remove the MSI,
/// and (per <c>purge</c>) wipe local state — see <see cref="DecommissionHandoff"/> for
/// how this gets staged and registered.
///
/// CLEARED FOR CUSTOMER ENDPOINTS, 2026-08-14, PAT-1344. This path previously carried
/// a do-not-ship-until-reviewed warning, and the review it named had never actually
/// been performed — PR #407's body narrates review rounds, but the only machine-recorded
/// review signal on it is a scan that failed to complete, merged over. The review was
/// therefore run for real under PAT-1344: the whole decommission path, this file
/// included, in front of three independent non-author reviewers, every finding checked
/// against the code, and the one real defect (a silently-failing pre-purge credential
/// snapshot on the macOS side) fixed in the same change. Full record in the header of
/// updater/endpoint/patched-decommission.sh. Read it as "reviewed", not as "an enforced
/// upstream gate passed": the patched/non-author-review rulesets are disabled
/// estate-wide, so this is the compensating local review.
///
/// It remains strictly more destructive than the existing app-removal daemon, which is
/// still gated: this removes the agent itself, the one channel that could otherwise
/// correct a mistake.
///
/// Pure string generation, kept separate from <see cref="DecommissionHandoff"/> (which
/// does the actual file/schtasks.exe I/O) so the SHAPE of the script — what it does
/// and in what order — is unit-testable on any OS without touching a real Windows
/// service or Windows Installer.
///
/// Design notes (see PAT-1110 brief for the full reasoning; round-2 non-author review
/// items in parentheses):
///   - PAT-599 precedent: a custom action DLL failed 1603/1154 on ARM64 and cost real
///     debugging time. This script is invoked by a scheduled task, never an MSI
///     custom action, precisely to avoid that trap.
///   - Reboot mid-removal: the service is stopped AND its StartupType set to Disabled
///     BEFORE msiexec runs, so a reboot between those two steps can never leave a
///     registered service pointing at binaries msiexec is mid-way through deleting.
///     The scheduled task itself is registered with an ONSTART trigger (by
///     <see cref="DecommissionHandoff"/>), so an interruption anywhere in this script
///     resumes automatically on next boot; every step here is idempotent (safe to
///     re-run from scratch), and the task deletes itself only once every step below
///     it depends on has been independently VERIFIED, never assumed from an exit code.
///   - ProductCode resolution mirrors RegistryUninstallLookup.cs's own DisplayName
///     match against the Uninstall registry hives, rather than hardcoding a
///     ProductCode — WiX/MSI regenerates ProductCode per build; only UpgradeCode is
///     pinned in Product.wxs.
///   - Core-removal verification (item 2a) checks THREE independent signals, not
///     just one: the MSI Uninstall registry entry, the Windows service registration
///     itself, AND the installed service binary on disk. msiexec can defer file/
///     service removal to a reboot-pending state while still returning success, so
///     the Uninstall key alone is not proof any of the other two are actually gone.
///   - Two-phase status reporting (second contract round, 2026-08): the .NET
///     service reports a non-terminal "acknowledged" status and gets a proceed/abort
///     decision from the platform BEFORE this script ever runs (see
///     DecommissionStatusReporter). Only THIS script, only after core removal is
///     verified — and, for purge=true, only after purge is ALSO independently
///     verified (items 2b/3) — reports the genuine terminal "removed" status. The
///     service that would otherwise report it is stopped partway through this same
///     script, so it can never observe or verify the outcome itself.
///   - purge=true is verified, not fire-and-forget (item 3): $stateDir emptiness
///     (besides the surviving decommission directory — see below), every Credential
///     Manager target's actual unresolvability, and the registry provisioning key's
///     absence are all re-checked after the removal attempts. If any is not
///     confirmed, the terminal report is NOT sent and the scheduled task is NOT
///     deregistered — exactly the same fail-closed retry-next-boot path core
///     removal already uses.
///   - The decommission directory (this script, the report-credentials snapshot,
///     the log, and the cross-boot report-attempt counter) is DELIBERATELY EXCLUDED
///     from the purge sweep and removed separately, last (item 2b): if it were wiped
///     along with the rest of $stateDir before the terminal report is confirmed
///     delivered, the credentials needed to authenticate that report would be gone,
///     and a next-boot ONSTART retry would have no script left to run.
///   - The terminal report itself retries across BOOTS, not just within one process
///     invocation (P2): a failed POST does not destroy the report-credentials
///     snapshot or deregister the task — removal (and purge, if requested) already
///     genuinely completed by this point, so destroying the only way to ever report
///     that on a single transient network failure would strand the platform
///     believing the directive is still merely "acknowledged", forever. Retries are
///     bounded (<see cref="MaxCrossBootReportAttempts"/>) so an unreachable platform
///     cannot keep the scheduled task (and stray credentials) around indefinitely
///     either; once exhausted, the outcome is recorded locally as unreported and
///     cleanup proceeds — the removal itself already happened regardless.
/// </summary>
public static class DecommissionHandoffScript
{
    /// <summary>Must match ServiceInstall Name AND Package Name in windows/installer/Product.wxs.</summary>
    public const string ServiceName = "Patched Agent";

    /// <summary>Must match the DisplayName the MSI publishes to the Uninstall registry hives.</summary>
    public const string ProductDisplayName = "Patched Agent";

    /// <summary>
    /// Must match the service binary's Name in the ServiceBinaries component group
    /// (windows/installer/Product.wxs) — checked directly on disk under
    /// %ProgramFiles%\Patched as the third leg of core-removal verification
    /// (item 2a), independent of the MSI Uninstall key and the service registration.
    /// </summary>
    public const string ServiceExecutableName = "Patched.Service.exe";

    /// <summary>
    /// Bound on how many separate boots (ONSTART re-invocations of this idempotent
    /// script) will retry an undelivered terminal report before giving up and
    /// recording it locally as unreported (P2, round-2 non-author review). Each
    /// invocation also gets its own small in-process retry (2 attempts) on top of
    /// this — see step 6 below. Deliberately generous (removal itself is already
    /// complete by the time this budget is even consulted; the only thing at stake
    /// is how long the scheduled task and the credential snapshot are kept around
    /// waiting for a flaky network to recover) but still bounded, so a permanently
    /// unreachable platform cannot keep both armed forever.
    /// </summary>
    public const int MaxCrossBootReportAttempts = 10;

    /// <summary>
    /// PAT-1764: MSI property that stops the uninstall custom action from purging the
    /// agent credentials. Must match the PurgeCredentials condition in
    /// windows/installer/Product.wxs. Passed only for purge=false, which retains
    /// credentials by contract (ADR-0007 parity with macOS).
    /// </summary>
    public const string RetainCredentialsMsiProperty = "PATCHED_RETAIN_CREDENTIALS";

    public static string Build(
        string taskName, bool purge, string stateDir, int directiveVersion, string reportCredsFile)
    {
        // stateDir/taskName/reportCredsFile are interpolated into single-quoted
        // PowerShell strings; all are agent-controlled constants (PathConstants.*,
        // the fixed task name), never operator/attacker-controlled input, so no
        // further escaping is performed beyond doubling any embedded single quote
        // defensively.
        string escapedStateDir       = stateDir.Replace("'", "''");
        string escapedTaskName       = taskName.Replace("'", "''");
        string escapedReportCredsFile = reportCredsFile.Replace("'", "''");
        string purgeLiteral          = purge ? "$true" : "$false";

        // The decommission directory (this script, the report-creds snapshot, the
        // log, and the report-attempt counter) is reportCredsFile's own parent —
        // computed here rather than passed as a separate parameter so there is no
        // way for the two to drift apart. See the class doc comment for why it must
        // survive the purge sweep.
        //
        // Deliberately NOT System.IO.Path.GetDirectoryName: that API resolves
        // separators using the HOST OS's convention, and this class is explicitly
        // designed to be unit-tested on any OS (no [SupportedOSPlatform] gate, no
        // real file I/O) — on a non-Windows test host, GetDirectoryName silently
        // fails to recognise '\' as a separator at all and returns "" instead of
        // throwing, which very nearly shipped here undetected. reportCredsFile is
        // ALWAYS a Windows-style backslash path by construction (PathConstants.*),
        // so the parent is found with an explicit backslash split instead, which
        // behaves identically regardless of the host OS this code happens to run on.
        int lastSep = reportCredsFile.LastIndexOf('\\');
        if (lastSep <= 0)
            throw new ArgumentException(
                "reportCredsFile must be an absolute Windows path with a parent directory",
                nameof(reportCredsFile));
        string decommissionDir = reportCredsFile[..lastSep];
        string escapedDecommissionDir = decommissionDir.Replace("'", "''");

        // purge=true credential cleanup: generated from CredentialStore.cs's own
        // Credential Manager target constants, not re-typed here, so a future
        // credential added there cannot be silently missed by this script. All
        // targets — including EnrollmentToken, which is normally already consumed by
        // enrolment but is harmless to attempt anyway — are cleared, plus the
        // pre-enrolment registry provisioning fallback (PAT-599) for a machine
        // decommissioned before its first successful start ever migrated it to
        // Credential Manager.
        string credManagerTargetsPs = string.Join(", ", CredentialStore.AgentCredentialTargets
            .Select(t => $"'{t.Replace("'", "''")}'"));
        // PAT-1764: purge=false retains credentials, so its msiexec /x opts out of the
        // MSI's uninstall credential purge. purge=true lets the MSI purge them and then
        // re-checks every target itself in step 5.
        string msiexecArguments = purge
            ? "/x $productCode /qn /norestart"
            : $"/x $productCode /qn /norestart {RetainCredentialsMsiProperty}=1";

        string escapedRegistryProvisioningKey =
            ("HKLM:\\" + CredentialStore.RegistryProvisioningKey).Replace("'", "''");

        return $$"""
        # Patched Agent decommission handoff — generated by DecommissionHandoff.
        #
        # Cleared for customer endpoints 2026-08-14 under PAT-1344, after an
        # independent non-author security review of the whole decommission path
        # (the review the previous do-not-ship warning named had never actually
        # been run). This is still the ONLY irreversible action in the product:
        # once it completes there is no channel left to correct a mistake.
        #
        # Idempotent and reboot-safe: every step below can be re-run from scratch
        # (including after a mid-run reboot, via the ONSTART trigger the scheduled
        # task is registered with) without leaving the machine worse off than when
        # it started.
        $ErrorActionPreference = 'SilentlyContinue'
        $serviceName        = '{{ServiceName}}'
        $serviceExeName     = '{{ServiceExecutableName}}'
        $productName        = '{{ProductDisplayName}}'
        $taskName           = '{{escapedTaskName}}'
        $purge              = {{purgeLiteral}}
        $stateDir           = '{{escapedStateDir}}'
        $directiveVersion   = {{directiveVersion}}
        $reportCredsFile    = '{{escapedReportCredsFile}}'
        $decommissionDir    = '{{escapedDecommissionDir}}'
        $reportAttemptsFile = Join-Path $decommissionDir 'report-attempts.count'
        $maxCrossBootReportAttempts = {{MaxCrossBootReportAttempts}}
        $credManagerTargets = @({{credManagerTargetsPs}})
        $credRegistryKey    = '{{escapedRegistryProvisioningKey}}'
        # Deliberately INSIDE $decommissionDir (not $stateDir\logs) so the log
        # survives a purge=true sweep along with the rest of that directory — see
        # the class doc comment.
        $logFile            = Join-Path $decommissionDir 'decommission.log'

        function Log([string]$msg) {
            try {
                $line = "$(Get-Date -Format o) $msg"
                Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
            } catch {}
        }

        Log "decommission handoff started (purge=$purge)"

        # 1. Stop AND disable the service BEFORE touching anything else. Disabling
        #    startup first means even a reboot landing between these two lines can
        #    never let Windows try to restart a service whose binaries msiexec is
        #    about to remove.
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Log "service stopped and startup disabled"
        } else {
            Log "service not present (already removed, or removal already ran)"
        }

        # 2. Resolve the installed ProductCode by DisplayName — mirrors
        #    RegistryUninstallLookup.cs's own match, since WiX regenerates
        #    ProductCode per build (only UpgradeCode is pinned in Product.wxs).
        $productCode = $null
        foreach ($hive in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props -and $props.DisplayName -eq $productName) {
                    $productCode = $_.PSChildName
                }
            }
        }

        # 3. Remove the MSI. Idempotent by construction: if $productCode is null
        #    (already removed) this is skipped; if msiexec fails against a
        #    partially-removed product, re-running this whole script (next boot, via
        #    the ONSTART trigger) tries again — success is judged by re-inspection
        #    below, never by this exit code.
        #    PAT-1764: a full uninstall removes the agent credentials by default.
        #    purge=false must keep them (step 5), so it tells the MSI to leave them.
        if ($productCode) {
            Log "removing product $productCode via msiexec"
            Start-Process msiexec.exe -ArgumentList "{{msiexecArguments}}" -Wait -ErrorAction SilentlyContinue
        } else {
            Log "no installed ProductCode found for '$productName', already removed"
        }

        # 4. VERIFY core removal by re-inspection, never by msiexec's exit code.
        #    Round-2 non-author review (item 2a): the MSI Uninstall registry entry
        #    ALONE is not proof of removal — msiexec can defer to a reboot-pending
        #    state (files still in use) and return before the service/binaries are
        #    actually gone. "Verified" now requires ALL THREE, independently: the
        #    MSI Uninstall key absent, the Windows service itself unregistered, AND
        #    the installed service binary gone from disk. Any one still present (or
        #    unconfirmable) fails the whole check closed — same discipline as
        #    round-1's registry-read hardening (an enumeration/read error is treated
        #    exactly like "still present", never like "nothing found").
        $verifyFailed = $false

        # 4a. MSI Uninstall registry entry.
        $msiKeyPresent = $false
        foreach ($hive in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            if (-not (Test-Path $hive)) {
                # Genuinely absent on this architecture/OS -- not an error, nothing
                # to enumerate, and NOT the same thing as a failed read.
                continue
            }
            try {
                $children = Get-ChildItem $hive -ErrorAction Stop
            } catch {
                Log "verification: failed to enumerate ${hive}: $_"
                $verifyFailed = $true
                continue
            }
            foreach ($child in $children) {
                try {
                    $props = Get-ItemProperty $child.PSPath -ErrorAction Stop
                } catch {
                    Log "verification: failed to read $($child.PSPath): $_"
                    $verifyFailed = $true
                    continue
                }
                if ($props -and $props.DisplayName -eq $productName) {
                    $msiKeyPresent = $true
                }
            }
        }

        # 4b. The Windows service registration itself -- msiexec can defer service
        #     removal to a reboot-pending state, so the Uninstall key alone proves
        #     nothing about it.
        $serviceStillRegistered = $false
        try {
            $svcCheck = Get-Service -Name $serviceName -ErrorAction Stop
            $serviceStillRegistered = $true
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoServiceFoundForGivenName*') {
                Log "verification: Get-Service failed for an unrecognised reason (not 'service not found') -- treating as NOT verified: $_"
                $verifyFailed = $true
            }
        }

        # 4c. The installed binary itself -- belt and braces alongside 4a/4b: a
        #     reboot-pending removal can leave the Uninstall key AND the service
        #     gone while files are still scheduled for deletion on next restart.
        $installDir = Join-Path $env:ProgramFiles 'Patched'
        $serviceBinaryPath = Join-Path $installDir $serviceExeName
        $binaryStillPresent = Test-Path $serviceBinaryPath

        $coreRemovalVerified = -not ($msiKeyPresent -or $serviceStillRegistered -or $binaryStillPresent -or $verifyFailed)

        if (-not $coreRemovalVerified) {
            if ($verifyFailed) {
                Log "verification could not be completed (read error) -- not proven removed, leaving the scheduled task registered to retry"
            } else {
                Log "still present after msiexec (msi-key=$msiKeyPresent service=$serviceStillRegistered binary=$binaryStillPresent) -- leaving the scheduled task registered to retry"
            }
            exit 1
        }

        Log "core removal verified complete (MSI key, service registration, and binary all confirmed absent)"

        # 5. purge semantics -- MUST match macOS --purge exactly (ADR-0007, parity is
        #    a release gate): credentials and queue removed when true, retained when
        #    false. The MSI itself never removes %ProgramData%\Patched (no
        #    RemoveFolder in Product.wxs, by design, so a non-purge decommission
        #    leaves local evidence/state intact) -- this step is what performs the
        #    Windows-side equivalent of macOS's credentials+queue purge: both
        #    Windows Credential Manager (the authoritative post-enrolment store) and
        #    the pre-enrolment registry provisioning fallback (PAT-599) are cleared,
        #    alongside $stateDir itself.
        #
        #    Round-2 non-author review (items 2b/3): purge is now VERIFIED, not
        #    fire-and-forget -- a transient failure (locked file, cmdkey/registry
        #    error) must never be reported to the platform as a clean purge. And
        #    $decommissionDir (this script, the report-creds snapshot, the log, and
        #    the report-attempt counter) is DELIBERATELY EXCLUDED from the sweep --
        #    if it were wiped before the terminal report is confirmed delivered, the
        #    credentials needed to authenticate that report would be gone, and a
        #    next-boot ONSTART retry would have no script left to run. It is removed
        #    separately, as the very last action (step 7), once there is nothing
        #    left to retry.
        $purgeVerified = $true
        if ($purge) {
            Log "purge=true: removing $stateDir (except $decommissionDir)"
            Get-ChildItem -Path $stateDir -Force -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -ne $decommissionDir
            } | ForEach-Object {
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }

            Log "purge=true: removing Credential Manager entries"
            foreach ($credTarget in $credManagerTargets) {
                cmdkey.exe /delete:$credTarget 2>&1 | Out-Null
            }

            Log "purge=true: removing registry provisioning key"
            Remove-Item -Path $credRegistryKey -Recurse -Force -ErrorAction SilentlyContinue

            # VERIFY purge -- never trust the fire-and-forget calls above.
            if (Test-Path $stateDir) {
                $remaining = @(Get-ChildItem -Path $stateDir -Force -ErrorAction SilentlyContinue | Where-Object {
                    $_.FullName -ne $decommissionDir
                })
                if ($remaining.Count -gt 0) {
                    Log "purge verify: $($remaining.Count) item(s) remain under $stateDir besides $decommissionDir"
                    $purgeVerified = $false
                }
            }

            foreach ($credTarget in $credManagerTargets) {
                $listOutput = (cmdkey.exe /list:$credTarget 2>&1 | Out-String)
                if ($listOutput -match 'Target:') {
                    Log "purge verify: Credential Manager target still resolvable: $credTarget"
                    $purgeVerified = $false
                }
            }

            if (Test-Path $credRegistryKey) {
                Log "purge verify: registry provisioning key still present: $credRegistryKey"
                $purgeVerified = $false
            }

            if (-not $purgeVerified) {
                Log "purge could not be verified -- leaving the scheduled task registered to retry; terminal status NOT reported"
                exit 1
            }
            Log "purge verified complete"
        } else {
            Log "purge=false: local state and credentials retained ($stateDir, Credential Manager)"
        }

        # 6. Report the VERIFIED terminal status. Phase 2 of the two-phase report
        #    contract (PAT-1110 second round): the .NET service already reported a
        #    non-terminal "acknowledged" status and got a proceed/abort decision
        #    from the platform BEFORE it ever triggered this script -- see
        #    DecommissionStatusReporter.ReportAcknowledgedAsync. That service is
        #    stopped by step 1 above, so only THIS script, only after core removal
        #    is verified (step 4) AND -- for purge=true -- purge is ALSO verified
        #    (step 5), reports the genuine terminal outcome. An unverified terminal
        #    report is exactly the bug the second contract round closed; reporting
        #    "removed" before an explicitly-requested purge is actually confirmed
        #    complete would be the same bug recurring one step later.
        #
        #    Round-2 non-author review (P2): a failed POST must NOT destroy the
        #    report-creds snapshot or deregister the task -- removal (and purge, if
        #    requested) already genuinely completed by this point; only the REPORT
        #    of that fact is unconfirmed, and destroying the ability to retry on the
        #    first transient network failure would strand the platform believing
        #    the directive is still merely "acknowledged", forever. Retries persist
        #    ACROSS BOOTS (the ONSTART trigger re-runs this idempotent script every
        #    boot), bounded by $maxCrossBootReportAttempts so a permanently
        #    unreachable platform cannot keep the task and the credential snapshot
        #    armed indefinitely either.
        $reported = $false
        $giveUp   = $false
        $bootAttempt = 0

        if (Test-Path $reportCredsFile) {
            $priorAttempts = 0
            if (Test-Path $reportAttemptsFile) {
                $priorAttemptsRaw = Get-Content -Path $reportAttemptsFile -Raw -ErrorAction SilentlyContinue
                if ($priorAttemptsRaw) {
                    [void][int]::TryParse($priorAttemptsRaw.Trim(), [ref]$priorAttempts)
                }
            }
            $bootAttempt = $priorAttempts + 1
            # Recorded BEFORE attempting, not after -- a crash mid-POST must still
            # count against the bounded budget (fail toward eventually stopping,
            # never an unbounded retry loop).
            Set-Content -Path $reportAttemptsFile -Value "$bootAttempt" -Force -ErrorAction SilentlyContinue

            try {
                # The report-creds snapshot is DPAPI-protected at rest (LocalMachine
                # scope — see DecommissionHandoff.WriteReportCredsSnapshot's own doc
                # comment for why: this script runs as SYSTEM via the scheduled task,
                # not as whatever principal was logged in when the .NET service staged
                # the file, so CurrentUser scope would not decrypt here). Matches the
                # same protection level CredentialStore already gives this exact
                # bearer token/HMAC secret via Windows Credential Manager, rather than
                # relying on the decommission directory's ACLs alone.
                Add-Type -AssemblyName System.Security -ErrorAction Stop
                $encryptedCredsBytes = [System.IO.File]::ReadAllBytes($reportCredsFile)
                $decryptedCredsBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $encryptedCredsBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                $credsJson = [System.Text.Encoding]::UTF8.GetString($decryptedCredsBytes)
                $creds = $credsJson | ConvertFrom-Json
                $bodyObj = [ordered]@{
                    status             = 'removed'
                    directive_version  = $directiveVersion
                    detail             = 'uploader removed, service unregistered'
                }
                $bodyJson  = $bodyObj | ConvertTo-Json -Compress
                $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)

                $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $nonce     = [guid]::NewGuid().ToString('N')

                # PAT-1154 v3 canonical signing input, identical to HmacSigner.cs /
                # compute_hmac() on macOS: prefix + POST + agent_decommission_status +
                # timestamp + nonce + body (ASCII/UTF-8 bytes), NOT the body alone. ts and nonce
                # here MUST be the exact strings sent in the headers below.
                $prefixBytes = [System.Text.Encoding]::ASCII.GetBytes("patched-hmac-v3`n")
                $methodBytes = [System.Text.Encoding]::ASCII.GetBytes("POST`n")
                $endpointBytes = [System.Text.Encoding]::ASCII.GetBytes("agent_decommission_status`n")
                $tsBytes     = [System.Text.Encoding]::ASCII.GetBytes("$timestamp`n")
                $nonceBytes  = [System.Text.Encoding]::ASCII.GetBytes("$nonce`n")
                $signingInput = $prefixBytes + $methodBytes + $endpointBytes + $tsBytes + $nonceBytes + $bodyBytes

                $secretBytes = [Convert]::FromBase64String($creds.hmac_secret)
                $hmac = New-Object System.Security.Cryptography.HMACSHA256
                $hmac.Key = $secretBytes
                $sigBytes = $hmac.ComputeHash($signingInput)
                $sigHex = ([System.BitConverter]::ToString($sigBytes) -replace '-', '').ToLower()

                $headers = @{
                    'Authorization'       = "Bearer $($creds.bearer_token)"
                    'X-Patched-Signature' = $sigHex
                    'X-Patched-Timestamp' = "$timestamp"
                    'X-Patched-Nonce'     = $nonce
                }

                # Small in-process retry (2 attempts) on top of the cross-boot
                # budget above -- covers a transient blip within THIS run; the
                # cross-boot counter covers a platform unreachable for longer.
                for ($attempt = 1; $attempt -le 2 -and -not $reported; $attempt++) {
                    try {
                        Invoke-WebRequest -Uri "$($creds.api_url)/v1/agent-decommission-status" `
                            -Method Post -Headers $headers -ContentType 'application/json' `
                            -Body $bodyJson -UseBasicParsing -ErrorAction Stop | Out-Null
                        $reported = $true
                        Log "terminal status 'removed' reported (directive_version=$directiveVersion, boot attempt $bootAttempt)"
                    } catch {
                        Log "terminal status report attempt $attempt (boot attempt $bootAttempt) failed: $_"
                        if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
                    }
                }
            } catch {
                Log "terminal status report failed to prepare: $_"
            }

            $giveUp = $reported -or ($bootAttempt -ge $maxCrossBootReportAttempts)
        } else {
            Log "no report-creds file found -- terminal status unreported"
            $giveUp = $true
        }

        if (-not $giveUp) {
            Log "terminal status not yet delivered (boot attempt $bootAttempt/$maxCrossBootReportAttempts) -- leaving report-creds snapshot and scheduled task in place to retry next boot"
            exit 1
        }

        if (-not $reported) {
            Log "terminal status ultimately unreported -- giving up (removal itself is already complete regardless)"
        }

        # Single-use bridging material -- removed once there is nothing left to
        # retry (report delivered, no snapshot ever existed, or the bounded
        # cross-boot budget above is exhausted).
        Remove-Item -Path $reportCredsFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $reportAttemptsFile -Force -ErrorAction SilentlyContinue

        # 7. Self-cleanup: only once nothing is left to retry (terminal status
        #    delivered or its cross-boot budget exhausted, AND -- for purge=true --
        #    purge itself was verified complete back in step 5). $decommissionDir
        #    (this script, log, and the now-removed report-creds/attempts files) is
        #    removed here, for purge=true, rather than by the purge sweep in step 5
        #    -- see that step's comment for why it had to survive until now.
        Log "removal complete, deleting scheduled task"
        schtasks.exe /Delete /TN $taskName /F | Out-Null
        if ($purge) {
            Remove-Item -Path $decommissionDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        """;
    }
}
