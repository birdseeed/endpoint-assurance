// DEPRECATED — PAT-1531: retained source for a separately reviewed future boundary;
// excluded from the Windows assurance-only Service build.
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Engine;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Installation;
using Patched.Shared.Paths;
using Patched.Verifier;

namespace Patched.Service;

/// <summary>
/// PAT-661 install-execution engine — the Windows parity mirror of the macOS
/// patched-install.sh (PAT-661). On the scheduled enforcement run it:
///   1. Fetches the pending-install queue from GET /v1/allowlist/pending-installs;
///   2. For each winget-source entry: checks if already installed (idempotent) via
///      winget CLI, then executes winget install if absent;
///   3. Reports each outcome to POST /v1/agent-logs with the structured
///      catalogue_install event payload (PAT-651);
///   4. Writes %ProgramData%\Patched\install-status.json atomically.
///
/// Source routing (mirrors macOS patched-install.sh):
///   winget  — handled here via WingetCliEngine.
///   mas     — Mac App Store only; skipped on Windows.
///   vendor  — Installomator only; skipped on Windows.
/// </summary>
[SupportedOSPlatform("windows")]
internal class InstallRunner
{
    private static readonly JsonSerializerOptions EventJsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy   = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly ILogger<InstallRunner>  _log;
    private readonly PendingInstallsFetcher  _fetcher;
    private readonly IPackageEngine          _engine;
    private readonly CredentialStore         _creds;
    private readonly IHttpClientFactory      _httpFactory;
    private readonly AllowlistLoader         _allowlist;
    private readonly AuthenticodeVerifier    _verifier;
    private readonly AgentHealthStore        _agentHealth;

    public InstallRunner(
        ILogger<InstallRunner>  log,
        PendingInstallsFetcher  fetcher,
        IPackageEngine          engine,
        CredentialStore         creds,
        IHttpClientFactory      httpFactory,
        AllowlistLoader         allowlist,
        AuthenticodeVerifier    verifier,
        AgentHealthStore        agentHealth)
    {
        _log         = log;
        _fetcher     = fetcher;
        _engine      = engine;
        _creds       = creds;
        _httpFactory = httpFactory;
        _allowlist   = allowlist;
        _verifier    = verifier;
        _agentHealth = agentHealth;
    }

    /// <summary>
    /// Looks up the signed Windows allowlist entry for <paramref name="packageId"/>.
    /// Returns null when the package is not in the allowlist — callers must block the
    /// install (fail-closed). Virtual to allow test overrides without real allowlist files.
    /// </summary>
    protected virtual WindowsAllowlistEntry? ResolveAllowlistEntry(string packageId) =>
        _allowlist.FindByWingetId(packageId);

    /// <summary>
    /// Authenticode-verifies the resolved installer binary. Returns null on success;
    /// returns a human-readable failure reason when verification fails. Virtual to allow
    /// test overrides that skip the P/Invoke WinVerifyTrust call.
    /// </summary>
    protected virtual string? AuthenticodeCheck(string installPath, string expectedPublisher)
    {
        var result = _verifier.Verify(installPath, expectedPublisher);
        if (result.IsValid) return null;
        return $"Authenticode: {result.FailureReason} (expected publisher: {expectedPublisher})";
    }

    /// <summary>
    /// PAT-844: MSIX variant of <see cref="AuthenticodeCheck"/>. An .msix is a signed
    /// ZIP container, not a PE image, so it needs <see cref="AuthenticodeVerifier.VerifyMsix"/>
    /// (WinVerifyTrust via the AppX SIP + AppxSignature.p7x publisher extraction)
    /// rather than the PE-only <see cref="AuthenticodeVerifier.Verify"/>. Returns null
    /// on success; a human-readable failure reason otherwise. Virtual so tests can
    /// override it without the P/Invoke WinVerifyTrust call, exactly like
    /// <see cref="AuthenticodeCheck"/>.
    /// </summary>
    protected virtual string? AuthenticodeCheckMsix(string installPath, string expectedPublisher)
    {
        var result = _verifier.VerifyMsix(installPath, expectedPublisher);
        if (result.IsValid) return null;
        return $"Authenticode: {result.FailureReason} (expected publisher: {expectedPublisher})";
    }

    /// <summary>
    /// Process the full pending-installs queue. Fail-safe: never throws into the worker.
    /// </summary>
    public async Task RunAsync(CancellationToken ct, AgentConfig config)
    {
        // PAT-1481: an authenticated exact-true containment grant is required
        // before the retained executor even reads the pending-install queue.
        // It is additional to, never a replacement for, every verification and
        // provenance gate below. The published Windows assurance build excludes
        // this class; retaining this guard makes the source fail closed if a
        // separately reviewed future boundary reintroduces it.
        if (!LegacyAppExecutionGate.Allows(config))
        {
            _log.LogWarning("Legacy app-execution gate disabled — skipping pending-install execution");
            return;
        }

        var startedAt = DateTimeOffset.UtcNow;
        var items     = await _fetcher.FetchAsync(ct).ConfigureAwait(false);

        if (items.Count == 0)
        {
            _log.LogInformation("Install: no pending installs.");
            return;
        }

        // Filter to winget-source entries only — mas and vendor are macOS-only.
        var wingetItems = items
            .Where(i => string.Equals(i.PackageSource, "winget", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var skippedPlatform = items.Count - wingetItems.Count;
        if (skippedPlatform > 0)
            _log.LogInformation("Install: {Skipped} non-winget items skipped (macOS-only sources).", skippedPlatform);

        _log.LogInformation("Install: {Count} winget items to process.", wingetItems.Count);

        var results = new List<InstallResult>(wingetItems.Count);
        foreach (var item in wingetItems)
        {
            ct.ThrowIfCancellationRequested();
            var result = await ProcessOneAsync(item, ct).ConfigureAwait(false);
            results.Add(result);
        }

        WriteStatus(startedAt, DateTimeOffset.UtcNow, results);
        _log.LogInformation("Install run complete: {Count} processed.", results.Count);
    }

    /// <summary>
    /// PAT-1066: re-checks winget/Chocolatey availability every cycle via the same
    /// static probes <see cref="FallbackPackageEngine"/> uses once at DI construction
    /// time. Deliberately independent of that constructor-time choice (see that
    /// class's doc comment — "the active engine is chosen once at construction...
    /// rather than per call") — this exists purely to give agent_health a per-cycle,
    /// re-evaluated signal, since the constructor-time choice never refreshes for
    /// the life of the process. Records capability_missing/package_engine success
    /// when either engine is available, or failure (reason no_engine_available)
    /// when neither is. Never throws into the caller.
    ///
    /// PAT-1066 P2 non-author-review: internal (not private) so <c>Worker.cs</c> can
    /// call it directly on cycles where the full catalogue-install engine is gated
    /// out by tier/mode — otherwise a report-tier tenant's agent would assert
    /// <c>degraded: []</c> on every cycle, because the code that would ever detect
    /// and record a real fault (this method, previously only reachable via
    /// <see cref="RunAsync"/>) would never run at all below the actuating tier. No
    /// longer called from the top of <see cref="RunAsync"/> itself — the caller
    /// (Worker.cs) is now responsible for calling it exactly once per cycle either
    /// way, so it is never double-counted alongside a full <see cref="RunAsync"/> pass.
    /// </summary>
    internal void RecordPackageEngineAvailability()
    {
        try
        {
            if (WingetCliEngine.IsAvailable() || ChocolateyEngine.IsAvailable())
            {
                _agentHealth.RecordSuccess("capability_missing", "package_engine");
            }
            else
            {
                _agentHealth.RecordFailure("capability_missing", "package_engine", "no_engine_available");
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Install: package-engine availability probe failed unexpectedly — skipping agent_health recording this cycle");
        }
    }

    private async Task<InstallResult> ProcessOneAsync(PendingInstall item, CancellationToken ct)
    {
        _log.LogInformation("Install: processing {DisplayName} ({PackageId}, source={Source})",
            item.DisplayName, item.PackageId, item.PackageSource);

        InstallOutcome outcome;
        string?        errorMessage = null;

        try
        {
            // 1. Idempotent check: is the package already installed?
            var check = await _engine.CheckAsync(item.PackageId, ct).ConfigureAwait(false);
            if (check.IsInstalled)
            {
                _log.LogInformation("Install: {PackageId} already installed (version {Version}) — skipping.",
                    item.PackageId, check.InstalledVersion);
                outcome = InstallOutcome.AlreadyInstalled;
            }
            else
            {
                // 2. Not installed — verify before install (mirrors InventoryCollector deploy path).
                // Security gate: the package MUST be in the signed local allowlist so we know
                // its expected Authenticode publisher. Fail-closed: packages absent from the
                // signed allowlist cannot be verified and MUST NOT be installed (PAT-305).
                var allowlistEntry = ResolveAllowlistEntry(item.PackageId);
                if (allowlistEntry is null)
                {
                    errorMessage = $"Package '{item.PackageId}' is not in the signed Windows allowlist — blocking install (fail-closed)";
                    _log.LogError("Install: {Message}", errorMessage);
                    outcome = InstallOutcome.Failed;
                }
                else if (allowlistEntry.IsVendorPinned)
                {
                    // PAT-840: pin-vendor path. The installer is NOT re-hosted; the
                    // agent downloads directly from the vendor's own pinned HTTPS URL
                    // (pinned_url), hard-verifies SHA-256 + Authenticode, and runs it
                    // (msiexec). winget/choco are NEVER invoked for a pinned label —
                    // there is no unpinned fallback. Checked before Mirror because the
                    // two modes are mutually exclusive (schema forbids both).
                    (outcome, errorMessage) = await VendorPinnedInstallAsync(item, allowlistEntry, ct).ConfigureAwait(false);
                }
                else if (allowlistEntry.Mirror)
                {
                    // PAT-823: mirror-execute path. The installer is served from the
                    // Patched-controlled CDN, not the public winget/Chocolatey source.
                    // Fetch it directly over HTTPS, hard-verify SHA-256 + Authenticode,
                    // and run it ourselves (msiexec). winget/choco are NEVER invoked for
                    // mirrored labels. Non-mirrored labels fall through to the winget path.
                    (outcome, errorMessage) = await MirrorInstallAsync(item, allowlistEntry, ct).ConfigureAwait(false);
                }
                else
                {
                    // 2a. Resolve the installer path winget would download (required by IPackageEngine contract).
                    var installPath = await _engine.ResolveInstallPathAsync(item.PackageId, ct).ConfigureAwait(false);
                    if (installPath is null)
                    {
                        errorMessage = $"Could not resolve installer path for '{item.PackageId}' — blocking install";
                        _log.LogError("Install: {Message}", errorMessage);
                        outcome = InstallOutcome.Failed;
                    }
                    else
                    {
                        // 2b. Authenticode-verify the resolved installer (fail-closed — PAT-305).
                        var authError = AuthenticodeCheck(installPath, allowlistEntry.ExpectedPublisher);
                        if (authError is not null)
                        {
                            errorMessage = authError + " — blocking install";
                            _log.LogError("Install: Authenticode FAILED for {PackageId}: {Error}", item.PackageId, authError);
                            outcome = InstallOutcome.Failed;
                        }
                        else
                        {
                            // 2c. Install — pin to the exact version resolved above so the install cannot
                            // pull a different/newer artifact than the one that passed Authenticode
                            // verification (H6 contract from IPackageEngine.InstallAsync).
                            _log.LogInformation("Install: {PackageId} not installed — attempting winget install.", item.PackageId);
                            var installResult = await _engine.InstallAsync(
                                item.PackageId, ct,
                                pinnedVersion: check.AvailableVersion).ConfigureAwait(false);

                            if (installResult.Success)
                            {
                                _log.LogInformation("Install: {PackageId} installed successfully.", item.PackageId);
                                outcome = InstallOutcome.Success;
                            }
                            else
                            {
                                errorMessage = installResult.ErrorMessage ?? "winget install failed";
                                _log.LogWarning("Install: {PackageId} failed: {Error}", item.PackageId, errorMessage);
                                outcome = InstallOutcome.Failed;
                            }
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            _log.LogError(ex, "Install: unexpected error for {PackageId}", item.PackageId);
            outcome = InstallOutcome.Failed;
        }

        // 3. Report outcome to POST /v1/agent-logs (PAT-651).
        await PostAgentLogEventAsync(item, outcome, errorMessage, ct).ConfigureAwait(false);

        return new InstallResult
        {
            PackageId     = item.PackageId,
            PackageSource = item.PackageSource,
            DisplayName   = item.DisplayName,
            Outcome       = outcome,
            ErrorMessage  = errorMessage,
            FailureKind   = outcome == InstallOutcome.Failed
                ? ClassifyFailure(errorMessage)
                : null,
            RecordedAt    = DateTimeOffset.UtcNow,
        };
    }

    private static InstallFailureKind ClassifyFailure(string? errorMessage)
    {
        var text = errorMessage ?? "";
        if (text.Contains("signed Windows allowlist", StringComparison.OrdinalIgnoreCase)
         || text.Contains("Authenticode", StringComparison.OrdinalIgnoreCase)
         || text.Contains("SHA-256 mismatch", StringComparison.OrdinalIgnoreCase)
         || text.Contains("no pinned_sha256", StringComparison.OrdinalIgnoreCase)
         || text.Contains("missing or not HTTPS", StringComparison.OrdinalIgnoreCase))
            return InstallFailureKind.VerificationBlocked;
        return InstallFailureKind.InstallFailed;
    }

    // -------------------------------------------------------------------------
    // PAT-823 / PAT-840 — verified direct-install paths (mirror + pin-vendor)
    // -------------------------------------------------------------------------

    /// <summary>
    /// PAT-823 mirror-execute: install a mirrored label from the Patched CDN
    /// (mirror_url). Thin wrapper over <see cref="VerifiedDirectInstallAsync"/>.
    /// </summary>
    private Task<(InstallOutcome, string?)> MirrorInstallAsync(
        PendingInstall item, WindowsAllowlistEntry entry, CancellationToken ct) =>
        VerifiedDirectInstallAsync(item, entry, "mirror", entry.MirrorUrl, "mirror_url", ct);

    /// <summary>
    /// PAT-840 pin-vendor: install a pinned label directly from the vendor's own
    /// HTTPS URL (pinned_url) WITHOUT re-hosting. Thin wrapper over
    /// <see cref="VerifiedDirectInstallAsync"/> — identical gates, different source URL.
    /// </summary>
    private Task<(InstallOutcome, string?)> VendorPinnedInstallAsync(
        PendingInstall item, WindowsAllowlistEntry entry, CancellationToken ct) =>
        VerifiedDirectInstallAsync(item, entry, "vendor-pinned", entry.PinnedUrl, "pinned_url", ct);

    /// <summary>
    /// Shared verified direct-install core for both mirror (mirror_url, Patched CDN)
    /// and pin-vendor (pinned_url, vendor domain) modes: download the artifact from
    /// <paramref name="sourceUrl"/> over HTTPS, hard-verify SHA-256 against the pinned
    /// hash AND Authenticode against the expected publisher, then run it (msiexec).
    /// Returns (outcome, errorMessage). Fail-closed at every gate: the installer only
    /// runs once the bytes are proven to match the pinned hash AND are signed by the
    /// expected publisher. winget/choco are NEVER called on either path — there is no
    /// unpinned fallback. <paramref name="mode"/> / <paramref name="urlField"/> only
    /// shape the log/error text; the gates are identical for both modes.
    /// </summary>
    private async Task<(InstallOutcome, string?)> VerifiedDirectInstallAsync(
        PendingInstall item, WindowsAllowlistEntry entry,
        string mode, string? sourceUrl, string urlField, CancellationToken ct)
    {
        // Gate 0: supported installer types are msiexec-installable ('msi', 'wix'),
        // exe-family ('exe', 'nullsoft', 'inno' — PAT-842, run via a silent-install
        // invocation instead of msiexec), and, as of PAT-844, 'msix' (run via
        // Add-AppxProvisionedPackage). Every other type (appx, msixbundle, burn,
        // portable, zip, …) is refused fail-closed.
        var isMsiexec = IsMsiexecInstallable(entry.InstallerType);
        var isExe     = IsExeInstallable(entry.InstallerType);
        var isMsix    = IsMsixInstallable(entry.InstallerType);
        if (!isMsiexec && !isExe && !isMsix)
        {
            var msg = $"{mode} install blocked for '{item.PackageId}': installer_type "
                    + $"'{entry.InstallerType ?? "(none)"}' is not supported (msi/wix/exe/nullsoft/inno/msix only)";
            _log.LogError("Install: {Message}", msg);
            return (InstallOutcome.Failed, msg);
        }

        // PAT-842: for exe-family types, resolve the silent-install args BEFORE
        // downloading/executing anything — a generic 'exe' with no per-app
        // override and no framework default must fail closed rather than guess
        // a flag, and it must do so before any process launches.
        string? silentArgs = null;
        if (isExe)
        {
            silentArgs = ResolveSilentArgs(entry);
            if (silentArgs is null)
            {
                var msg = $"{mode} install blocked for '{item.PackageId}': installer_type "
                        + $"'{entry.InstallerType}' has no silent_args and no framework default — "
                        + "refusing to guess silent-install flags";
                _log.LogError("Install: {Message}", msg);
                return (InstallOutcome.Failed, msg);
            }
        }

        // Gate 1: the entry MUST carry an HTTPS source URL and a pinned hash. Missing
        // either means the pipeline has not produced a verified artifact yet; we must
        // NOT fall back to an unpinned pull.
        if (string.IsNullOrWhiteSpace(sourceUrl) ||
            !sourceUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var msg = $"{mode} install blocked for '{item.PackageId}': {urlField} is missing or not HTTPS";
            _log.LogError("Install: {Message}", msg);
            return (InstallOutcome.Failed, msg);
        }
        if (string.IsNullOrWhiteSpace(entry.PinnedSha256))
        {
            var msg = $"{mode} install blocked for '{item.PackageId}': no pinned_sha256 for the pinned artifact";
            _log.LogError("Install: {Message}", msg);
            return (InstallOutcome.Failed, msg);
        }

        var fileExtension  = isMsix ? ".msix" : isExe ? ".exe" : ".msi";
        var installerPath = await DownloadArtifactAsync(sourceUrl, fileExtension, ct).ConfigureAwait(false);
        if (installerPath is null)
        {
            var msg = $"{mode} install blocked for '{item.PackageId}': download from {sourceUrl} failed";
            _log.LogError("Install: {Message}", msg);
            return (InstallOutcome.Failed, msg);
        }

        try
        {
            // Gate 2: SHA-256 must match the pinned hash exactly (the hash the pipeline
            // published + cross-corroborated). A mismatch means the served bytes are not
            // what was verified — abort. (For pin-vendor this also fail-closes when the
            // vendor rotates the artifact at an evergreen URL until the pipeline re-pins.)
            var actualHash = ComputeSha256(installerPath);
            if (!actualHash.Equals(entry.PinnedSha256, StringComparison.OrdinalIgnoreCase))
            {
                var msg = $"{mode} install blocked for '{item.PackageId}': SHA-256 mismatch "
                        + $"(expected {entry.PinnedSha256}, got {actualHash})";
                _log.LogError("Install: {Message}", msg);
                return (InstallOutcome.Failed, msg);
            }

            // Gate 3: Authenticode publisher must match (independent cryptographic proof
            // the vendor signed these exact bytes — same gate the winget path uses).
            // MSIX is a signed ZIP container (not a PE image) so it needs the MSIX
            // verifier variant; msi/wix/exe stay on the PE-file check unchanged.
            var authError = isMsix
                ? AuthenticodeCheckMsix(installerPath, entry.ExpectedPublisher)
                : AuthenticodeCheck(installerPath, entry.ExpectedPublisher);
            if (authError is not null)
            {
                var msg = authError + $" — blocking {mode} install";
                _log.LogError("Install: Authenticode FAILED for {PackageId}: {Error}", item.PackageId, authError);
                return (InstallOutcome.Failed, msg);
            }

            bool    ok;
            string? execError;
            if (isMsix)
            {
                _log.LogInformation(
                    "Install: {PackageId} verified {Mode} artifact (sha256+Authenticode) — provisioning MSIX for all users.",
                    item.PackageId, mode);
                (ok, execError) = await ExecuteMsixAsync(installerPath, ct).ConfigureAwait(false);
                if (!ok)
                {
                    var msg = execError ?? "msix install failed";
                    _log.LogWarning("Install: {PackageId} msix install failed: {Error}", item.PackageId, msg);
                    return (InstallOutcome.Failed, msg);
                }
            }
            else if (isExe)
            {
                var successExitCodes = (entry.SuccessExitCodes is { Length: > 0 })
                    ? entry.SuccessExitCodes
                    : DefaultSuccessExitCodes;
                _log.LogInformation(
                    "Install: {PackageId} verified {Mode} artifact (sha256+Authenticode) — running silent exe install.",
                    item.PackageId, mode);
                (ok, execError) = await ExecuteExeAsync(installerPath, silentArgs!, successExitCodes, ct).ConfigureAwait(false);
                if (!ok)
                {
                    var msg = execError ?? "exe install failed";
                    _log.LogWarning("Install: {PackageId} exe install failed: {Error}", item.PackageId, msg);
                    return (InstallOutcome.Failed, msg);
                }
            }
            else
            {
                _log.LogInformation(
                    "Install: {PackageId} verified {Mode} artifact (sha256+Authenticode) — running msiexec.",
                    item.PackageId, mode);
                (ok, execError) = await ExecuteMsiAsync(installerPath, ct).ConfigureAwait(false);
                if (!ok)
                {
                    var msg = execError ?? "msiexec install failed";
                    _log.LogWarning("Install: {PackageId} msiexec failed: {Error}", item.PackageId, msg);
                    return (InstallOutcome.Failed, msg);
                }
            }

            _log.LogInformation("Install: {PackageId} installed successfully ({Mode}).", item.PackageId, mode);
            return (InstallOutcome.Success, null);
        }
        finally
        {
            try { File.Delete(installerPath); } catch { /* best-effort temp cleanup */ }
        }
    }

    /// <summary>
    /// Download the artifact from <paramref name="url"/> (HTTPS only) to a temp file;
    /// returns the path, or null on any failure. Serves both mirror (mirror.patched.im)
    /// and pin-vendor (vendor domain) sources. Routed through the agent's configured
    /// egress proxy via the "patched" HttpClient. Virtual so tests can supply a local
    /// file without network I/O.
    ///
    /// Abuse-resistance (GitHub-Non-Author-Review): the download is bounded by <see cref="MaxArtifactBytes"/>
    /// BEFORE buffering — an over-large Content-Length is rejected up front, and the
    /// same cap is re-enforced while streaming (in case the header is absent or lies),
    /// so a malicious/misbehaving vendor URL, redirect, or proxy cannot make the
    /// endpoint consume unbounded disk before the fail-closed hash check runs.
    ///
    /// <paramref name="fileExtension"/> (e.g. ".msi", ".exe") is used for the temp
    /// file name — Windows dispatches an executable by its extension, so an
    /// exe-family installer must NOT be saved under a ".msi" name (PAT-842).
    /// </summary>
    protected virtual async Task<string?> DownloadArtifactAsync(string url, string fileExtension, CancellationToken ct)
    {
        var tmpPath = Path.Combine(Path.GetTempPath(), $"patched-mirror-{Guid.NewGuid():N}{fileExtension}");
        try
        {
            var client = _httpFactory.CreateClient("patched");
            using var resp = await client
                .GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                _log.LogError("Install: artifact download HTTP {Status} for {Url}", (int)resp.StatusCode, url);
                return null;
            }

            // Size cap BEFORE buffering: reject an over-large declared Content-Length
            // up front so we never even start streaming a multi-GB body.
            var declaredLength = resp.Content.Headers.ContentLength;
            if (declaredLength is long dl && dl > MaxArtifactBytes)
            {
                _log.LogError("Install: artifact at {Url} declares {Bytes} bytes > {Cap}-byte cap — refusing",
                    url, dl, MaxArtifactBytes);
                return null;
            }

            // Bounded copy: re-enforce the cap while streaming (the header may be
            // absent or lie), aborting the instant we exceed it.
            var oversize = false;
            await using (var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var dst = File.Create(tmpPath))
            {
                var buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await src.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > MaxArtifactBytes) { oversize = true; break; }
                    await dst.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                }
            }
            if (oversize)
            {
                _log.LogError("Install: artifact download from {Url} exceeded the {Cap}-byte cap — aborting",
                    url, MaxArtifactBytes);
                TryDelete(tmpPath);
                return null;
            }
            return tmpPath;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            TryDelete(tmpPath);
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Install: artifact download failed for {Url}", url);
            TryDelete(tmpPath);
            return null;
        }
    }

    /// <summary>
    /// Run the MSI installer silently (msiexec /i &lt;path&gt; /quiet /norestart).
    /// Returns (success, errorMessage). Virtual so tests can avoid launching msiexec.
    /// </summary>
    protected virtual async Task<(bool ok, string? error)> ExecuteMsiAsync(string installerPath, CancellationToken ct)
    {
        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = "msiexec.exe",
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                },
            };
            proc.StartInfo.ArgumentList.Add("/i");
            proc.StartInfo.ArgumentList.Add(installerPath);
            proc.StartInfo.ArgumentList.Add("/quiet");
            proc.StartInfo.ArgumentList.Add("/norestart");

            proc.Start();
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            // msiexec exit 0 = success; 3010 = success but a reboot is required.
            if (proc.ExitCode is 0 or 3010)
                return (true, null);
            return (false, $"msiexec exited {proc.ExitCode}");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (false, $"msiexec launch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Run an exe-family installer (exe/nullsoft/inno) silently, using the resolved
    /// <paramref name="silentArgs"/> (verbatim per-app override or the framework
    /// default — see <see cref="ResolveSilentArgs"/>). Returns (success, errorMessage).
    /// Virtual so tests can avoid launching a real process.
    ///
    /// <paramref name="silentArgs"/> are trusted signed-allowlist flag tokens (no
    /// embedded spaces), so splitting on whitespace into <c>ArgumentList</c> is
    /// correct and safer than the raw <c>Arguments</c> string (avoids shell-style
    /// re-parsing/quoting pitfalls).
    /// </summary>
    protected virtual async Task<(bool ok, string? error)> ExecuteExeAsync(
        string installerPath, string silentArgs, IReadOnlyCollection<int> successExitCodes, CancellationToken ct)
    {
        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = installerPath,
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                },
            };
            foreach (var token in silentArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                proc.StartInfo.ArgumentList.Add(token);

            proc.Start();
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            if (successExitCodes.Contains(proc.ExitCode))
                return (true, null);
            return (false, $"installer exited {proc.ExitCode}");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (false, $"installer launch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// PAT-844: install a verified .msix package for ALL users via
    /// <c>Add-AppxProvisionedPackage -Online</c>. Returns (success, errorMessage).
    /// Virtual so tests can avoid launching PowerShell.
    ///
    /// We provision (all-users, machine image) rather than <c>Add-AppxPackage</c>
    /// (per-user side-load) because the agent runs as SYSTEM with no interactive
    /// user context: a per-user Add-AppxPackage would either fail (no user hive) or
    /// stage the app for only the SYSTEM account, not the humans who log in.
    /// <c>-Online</c> provisioning is valid for SYSTEM and makes the package install
    /// for every current and future user of the machine — the managed-endpoint intent.
    ///
    /// Every argument (including the package path) is passed via <c>ArgumentList</c>,
    /// never string-interpolated into a shell command line, so a hostile path cannot
    /// break out of the argument. The whole PowerShell script is one <c>-Command</c>
    /// argument.
    /// </summary>
    protected virtual async Task<(bool ok, string? error)> ExecuteMsixAsync(string installerPath, CancellationToken ct)
    {
        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName               = "powershell.exe",
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                },
            };
            proc.StartInfo.ArgumentList.Add("-NoProfile");
            proc.StartInfo.ArgumentList.Add("-NonInteractive");
            proc.StartInfo.ArgumentList.Add("-ExecutionPolicy");
            proc.StartInfo.ArgumentList.Add("Bypass");
            proc.StartInfo.ArgumentList.Add("-Command");
            // -PackagePath value is a single-quoted PowerShell string literal; any
            // embedded single quote is doubled per PowerShell quoting rules so the
            // path can never terminate the literal early. The whole script is one arg.
            //
            // $ErrorActionPreference='Stop' promotes any error (including a
            // NON-terminating DISM/cmdlet error) to a terminating one, so an
            // unhandled failure makes powershell.exe exit non-zero. Without it a
            // non-terminating Add-AppxProvisionedPackage error would leave the
            // process exit code 0 and we would falsely report the install as success.
            var psPath = installerPath.Replace("'", "''");
            proc.StartInfo.ArgumentList.Add(
                "$ErrorActionPreference='Stop'; "
                + $"Add-AppxProvisionedPackage -Online -PackagePath '{psPath}' -SkipLicense");

            proc.Start();
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            if (proc.ExitCode == 0)
                return (true, null);

            var detail = string.Join(" | ",
                new[] { stderr, stdout }
                    .Select(s => s?.Trim())
                    .Where(s => !string.IsNullOrEmpty(s)));
            return (false, $"Add-AppxProvisionedPackage exited {proc.ExitCode}"
                         + (string.IsNullOrEmpty(detail) ? "" : $": {detail}"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (false, $"powershell launch failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Maximum bytes the agent will download for a single installer artifact before
    /// verification (GitHub-Non-Author-Review abuse-resistance size cap). 2 GB — parity with the CI
    /// mirror pipeline's MAX_BYTES. Windows MSIs are well under this (Chrome ~157 MB,
    /// 1Password ~230 MB); the cap exists to bound a hostile/misbehaving source.
    /// </summary>
    private const long MaxArtifactBytes = 2L * 1024 * 1024 * 1024;

    /// <summary>
    /// True when the installer_type is one the mirror-execute path can run via
    /// `msiexec /i`: "msi" or "wix". A winget 'wix' InstallerType is a WiX-toolset-built
    /// .msi (not a distinct package format), so it is installed identically to 'msi'.
    /// Any other type (e.g. exe-family) is handled by <see cref="IsExeInstallable"/>
    /// or refused fail-closed.
    /// </summary>
    private static bool IsMsiexecInstallable(string? installerType) =>
        string.Equals(installerType, "msi", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(installerType, "wix", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// PAT-842: true when the installer_type is exe-family — "exe", "nullsoft" (NSIS),
    /// or "inno" (Inno Setup) — installed via a silent-invocation of the verified
    /// EXE itself (<see cref="ExecuteExeAsync"/>) rather than msiexec. MSIX/APPX/Burn/
    /// portable/zip and any other type remain refused fail-closed (not this ticket's
    /// scope — MSIX is a separate ticket).
    /// </summary>
    private static bool IsExeInstallable(string? installerType) =>
        string.Equals(installerType, "exe", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(installerType, "nullsoft", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(installerType, "inno", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// PAT-844: true when the installer_type is "msix" — installed by provisioning
    /// the verified package for all users via <see cref="ExecuteMsixAsync"/>
    /// (Add-AppxProvisionedPackage) rather than msiexec or a silent EXE. Only the
    /// single-file "msix" type is supported here; "appx" and "msixbundle" remain
    /// refused fail-closed (the new Microsoft Teams ships as a single .msix).
    /// </summary>
    private static bool IsMsixInstallable(string? installerType) =>
        string.Equals(installerType, "msix", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Default installer exit codes treated as success when an allowlist entry does
    /// not carry an explicit <see cref="WindowsAllowlistEntry.SuccessExitCodes"/>:
    /// 0 (success) and 3010 (success, reboot required) — parity with msiexec's
    /// convention, applied to exe-family installers too.
    /// </summary>
    private static readonly int[] DefaultSuccessExitCodes = { 0, 3010 };

    /// <summary>
    /// PAT-842: resolve the silent-install command-line flags for an exe-family
    /// entry. Precedence: (1) the per-app <see cref="WindowsAllowlistEntry.SilentArgs"/>
    /// override, used verbatim when non-null/non-whitespace; (2) a framework default
    /// keyed on installer_type ("nullsoft" → "/S", "inno" → "/VERYSILENT
    /// /SUPPRESSMSGBOXES /NORESTART /SP-"); (3) null for a generic "exe" with neither —
    /// the caller MUST fail closed on null rather than guess a flag.
    /// </summary>
    private static string? ResolveSilentArgs(WindowsAllowlistEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.SilentArgs))
            return entry.SilentArgs;

        if (string.Equals(entry.InstallerType, "nullsoft", StringComparison.OrdinalIgnoreCase))
            return "/S";
        if (string.Equals(entry.InstallerType, "inno", StringComparison.OrdinalIgnoreCase))
            return "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-";

        return null;
    }

    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* best-effort */ }
    }

    /// <summary>
    /// POST a structured catalogue_install event to /v1/agent-logs (PAT-651).
    /// Fail-open: network errors are logged but do not abort the install run.
    /// Mirrors the macOS patched-install.sh report_install_event() function.
    /// Virtual to allow test doubles (no HTTP exercised in unit tests).
    /// </summary>
    protected virtual async Task PostAgentLogEventAsync(
        PendingInstall item,
        InstallOutcome outcome,
        string?        errorMessage,
        CancellationToken ct)
    {
        var outcomeStr = outcome switch
        {
            InstallOutcome.Success          => "success",
            InstallOutcome.AlreadyInstalled => "already_installed",
            _                              => "failed",
        };

        var evt = new CatalogueInstallEvent
        {
            PackageId     = item.PackageId,
            PackageSource = item.PackageSource,
            Outcome       = outcomeStr,
            Error         = string.IsNullOrEmpty(errorMessage) ? null : errorMessage,
        };

        var bodyBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(evt, EventJsonOpts));
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce     = Guid.NewGuid().ToString("N");
        var sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "POST", HmacSigner.EndpointAgentLogs, timestamp, nonce, bodyBytes);

        try
        {
            var client  = _httpFactory.CreateClient("patched");
            using var content = new ByteArrayContent(bodyBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/agent-logs")
            {
                Content = content,
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
            request.Headers.Add(HmacSigner.SignatureHeader, sig);
            request.Headers.Add("X-Patched-Timestamp", timestamp);
            request.Headers.Add("X-Patched-Nonce", nonce);

            var response = await client.SendAsync(request, ct).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
                _log.LogInformation("Install: agent-logs POST OK for {PackageId} ({Outcome})", item.PackageId, outcomeStr);
            else
                _log.LogWarning("Install: agent-logs POST returned {Status} for {PackageId}", (int)response.StatusCode, item.PackageId);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fail-open: a reporting failure must not block the install run.
            _log.LogWarning(ex, "Install: agent-logs POST failed for {PackageId} — will retry next run", item.PackageId);
        }
    }

    /// <summary>
    /// Returns the path for the install-status.json file.
    /// Virtual to allow test doubles to redirect writes to a temp directory.
    /// </summary>
    protected virtual string GetStatusFilePath() => PathConstants.InstallStatusFile;

    private void WriteStatus(DateTimeOffset started, DateTimeOffset finished, IReadOnlyList<InstallResult> results)
    {
        try
        {
            var status = new InstallStatus
            {
                SchemaVersion = 1,
                GeneratedAt   = DateTimeOffset.UtcNow,
                LastRun       = new InstallRunInfo { StartedAt = started, FinishedAt = finished },
                Installs      = results,
            };
            var statusFilePath = GetStatusFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(statusFilePath)!);
            // FINDING 1: use ContractJsonOptions.Write (matches the uninstall twin RemovalRunner)
            // so InstallOutcome enum values serialize as snake_case strings ("already_installed")
            // rather than integers (0/1/2). macOS patched-install.sh writes "outcome":"success".
            string json = JsonSerializer.Serialize(status, ContractJsonOptions.Write);
            string tmp  = statusFilePath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, statusFilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Install: failed to write install-status.json");
        }
    }
}
