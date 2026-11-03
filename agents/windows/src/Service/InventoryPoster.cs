using Patched.Shared.Apps;
using Patched.Shared.Metering;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.KernelDrivers;
using Patched.Shared.Paths;
using Patched.Shared.InstallationEvidence;

namespace Patched.Service;

/// <summary>
/// Assembles and POSTs the schema v3 inventory payload to POST /v1/inventory.
/// Auth: Authorization: Bearer {token} + X-Patched-Signature: {hmac-sha256 hex}.
///
/// On any failure the payload is written to the on-disk retry queue
/// (<c>%ProgramData%\Patched\inventory-queue\inv-*.json</c>) by the
/// <see cref="InventoryQueuePump"/>. Queued payloads are retried both after a
/// full inventory post and independently from PatchedWorker's 15-second tick,
/// so a startup rate limit does not leave evidence waiting for the next scan.
///
/// All upload attempts, HTTP statuses, and exceptions are logged to the rolling
/// file log so failures are visible without access to Windows Event Viewer.
/// </summary>
internal sealed class InventoryPoster
{
    private const string AgentName    = "patched-agent-win";
    // PAT-913: compliance_assessments (controls_assessed attestation) wired into
    // /v1/inventory. schema_version stays 3 -- optional additive field, same
    // precedent as prior optional additions (browser_extensions in 0.13.0/PAT-827).
    // The canonical contract for the field (payload.schema.json + PAYLOAD_SCHEMA.md)
    // and its server-side enforcement (ValidatePayload rejects out-of-enum control
    // IDs) live in Patched-LTD/patched.im PR #293; that repo's contract is the
    // authority -- nothing here duplicates it.
    //
    // PAT-1959: 0.15.0 adds device_class, installation_type and os_caption. Additive and
    // optional, so schema_version stays 3 (same precedent as 0.13.0/PAT-827 and
    // 0.14.0/PAT-913); agent_version is what tells the platform whether a device could
    // have sent a class at all. An agent below 0.15.0 simply omits the keys, which the
    // server reads as class unknown.
    //
    // PAT-2238: the version is read from this build's InformationalVersion (stamped by the
    // release workflow as <semver>+<sha>), never written here as a literal. A hardcoded
    // 0.15.0 shipped inside every 0.14.5 build, so the platform's version gates could not
    // tell the two apart. A dev or unstamped build reports DevAgentVersion, never a guess.
    internal const string DevAgentVersion = "0.0.0-dev";

    internal static readonly string AgentVersion = AgentVersionFrom(
        typeof(InventoryPoster).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    internal static string AgentVersionFrom(string? informationalVersion) =>
        InstalledAppScanner.SemanticReleaseFromInformationalVersion(informationalVersion) ?? DevAgentVersion;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // PAT-743: ComplianceFinding.Severity is a ComplianceSeverity enum; without this
        // converter it serializes as its raw int value (Critical = 3), but the go-service
        // extractor's complianceFinding.Severity is a plain Go string and migration
        // 0033_compliance_findings_rules.sql's severity values are lowercase strings
        // ("critical", "medium") — matches ContractJsonOptions' convention for the same
        // enum on the local status-file contract.
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    private readonly ILogger<InventoryPoster>     _log;
    private readonly CredentialStore              _creds;
    private readonly DeviceCollector              _deviceCollector;
    private readonly ComplianceCollector          _complianceCollector;
    private readonly InstalledAppScanner          _appScanner;
    private readonly SecurityToolDetector         _securityTools;
    private readonly MeteringCollector            _metering;
    private readonly AgentConfigManager           _configManager;
    private readonly CertCollector                _certCollector;
    private readonly LocalAdminCollector          _localAdmins;
    private readonly HardwareHealthCollector      _hardwareHealth;
    private readonly BackupCollector              _backupCollector;
    private readonly BrowserExtensionScanner      _browserExtensions;
    private readonly IdeExtensionScanner          _ideExtensions;
    private readonly PackageManagerScanner        _packageManagers;
    private readonly LocalModelScanner            _localModels;
    private readonly McpServerScanner             _mcpServers;
    private readonly KernelDriverCollector        _kernelDrivers;
    private readonly AgentHealthStore             _agentHealthStore;
    private readonly InventoryQueuePump           _pump;

    /// <summary>
    /// <paramref name="pumpOverride"/> exists purely for test isolation — a
    /// unit test can hand this an <see cref="InventoryQueuePump"/> already
    /// pointed at a temp queue directory (with a fake HTTP handler and
    /// injectable clock, via that pump's own constructor) instead of the real
    /// %ProgramData%\Patched\inventory-queue pump this class builds by
    /// default. Production DI resolves this constructor with no registered
    /// InventoryQueuePump service, so the container falls back to the default
    /// (null) and every real instance builds its own pump against
    /// <see cref="PathConstants.InventoryQueueDir"/> — the same seam
    /// ProvenancePoster's pumpOverride provides for its own pump (PAT-1249).
    /// </summary>
    public InventoryPoster(
        ILogger<InventoryPoster>  log,
        IHttpClientFactory        httpFactory,
        CredentialStore           creds,
        DeviceCollector           deviceCollector,
        ComplianceCollector       complianceCollector,
        InstalledAppScanner       appScanner,
        SecurityToolDetector      securityTools,
        MeteringCollector         metering,
        AgentConfigManager        configManager,
        CertCollector             certCollector,
        LocalAdminCollector       localAdmins,
        HardwareHealthCollector   hardwareHealth,
        BackupCollector           backupCollector,
        BrowserExtensionScanner   browserExtensions,
        IdeExtensionScanner       ideExtensions,
        PackageManagerScanner     packageManagers,
        LocalModelScanner         localModels,
        McpServerScanner          mcpServers,
        KernelDriverCollector     kernelDrivers,
        AgentHealthStore          agentHealthStore,
        InventoryQueuePump?       pumpOverride = null)
    {
        _log                 = log;
        _creds               = creds;
        _deviceCollector     = deviceCollector;
        _complianceCollector = complianceCollector;
        _appScanner          = appScanner;
        _securityTools       = securityTools;
        _metering            = metering;
        _configManager       = configManager;
        _certCollector       = certCollector;
        _localAdmins         = localAdmins;
        _hardwareHealth      = hardwareHealth;
        _backupCollector     = backupCollector;
        _browserExtensions   = browserExtensions;
        _ideExtensions       = ideExtensions;
        _packageManagers     = packageManagers;
        _localModels         = localModels;
        _mcpServers          = mcpServers;
        _kernelDrivers       = kernelDrivers;
        _agentHealthStore    = agentHealthStore;

        // Queue pump shares the same logger so all upload output appears under
        // the InventoryPoster category in the rolling file log.
        _pump = pumpOverride ?? new InventoryQueuePump(log, httpFactory, creds, PathConstants.InventoryQueueDir);
    }

    /// <summary>
    /// Builds and POSTs a fresh inventory payload, then drains any queued
    /// retry payloads that accumulated from previous failed cycles.
    ///
    /// <paramref name="complianceFindings"/> (PAT-743) and
    /// <paramref name="controlsAssessed"/> (PAT-913) are the same already-computed
    /// <c>StatusWriter.DetectComplianceFindings()</c> result Worker.cs passes into
    /// <c>StatusWriter.Build</c> for the local tray status file — threaded through
    /// here rather than re-querying WMI, so findings and attestation are always
    /// consistent within a cycle.
    /// <paramref name="osUpdate"/> (PAT-1833) is likewise the exact result already
    /// computed for update-status.json; inventory never re-queries WUA or creates a
    /// default verdict when that result is unavailable.
    ///
    /// Never throws: all exceptions are caught, logged (with stack trace), and
    /// surfaced to the rolling file log before returning.
    /// </summary>
    public async Task PostAsync(
        IReadOnlyList<ComplianceFinding> complianceFindings,
        IReadOnlyList<string>            controlsAssessed,
        OsUpdateInfo?                    osUpdate,
        CancellationToken                ct)
    {
        // PAT-1765: nothing is collected, sent or queued without the credential pair.
        // The payload carries the enrolled tenant_id and the pump signs with the stored
        // pair, so an unusable pair could only produce an invalidly signed POST (or a
        // queued payload with no tenant). The next cycle after enrolment posts fresh.
        if (!DeviceCredentials.Present(_creds))
        {
            _log.LogWarning("Inventory POST skipped: device credentials not present (no usable bearer token and HMAC secret); nothing collected, sent or queued");
            return;
        }

        byte[] body;
        try
        {
            var payload = await BuildPayloadAsync(complianceFindings, controlsAssessed, osUpdate)
                .ConfigureAwait(false);
            body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, JsonOpts));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Inventory POST aborted — BuildPayloadAsync threw unexpectedly");
            return;
        }

        await _pump.SendOrEnqueueAsync(body, ct).ConfigureAwait(false);
        await _pump.DrainAsync(ct).ConfigureAwait(false);
        ReportQueueHealth();
    }

    /// <summary>
    /// Retries one persisted inventory payload. This deliberately does not
    /// collect inventory or build a fresh payload, and fairly rotates each tick
    /// across retained files so a backlog cannot exhaust the shared limiter.
    /// </summary>
    public async Task DrainQueueAsync(CancellationToken ct)
    {
        // PAT-1765: the worker already gates its drain tick on this; checked here too so
        // every caller of the sender gets it. Queued payloads are kept for later.
        if (!DeviceCredentials.Present(_creds))
            return;

        await _pump.DrainOneAsync(ct).ConfigureAwait(false);
        ReportQueueHealth();
    }

    /// <summary>
    /// PAT-1270 (mirrors ProvenancePoster.ReportQueueHealth exactly, added by
    /// PAT-1249): reports two independent degraded signals so the inventory
    /// retry queue's depth is never invisible the way it was before this
    /// ticket — ProvenancePoster already had a queue_backlog signal;
    /// InventoryPoster (PAT-1266) had only auth_failure, so a persistent
    /// rate limit or any other non-auth transient failure becoming permanent
    /// could back the queue up on disk with zero warning anywhere.
    ///
    ///   - kind="queue_backlog": the pump's current on-disk queue depth,
    ///     whenever it is non-zero — cleared once the depth reaches zero
    ///     again. Same shape as ProvenancePoster's signal of the same kind.
    ///
    ///   - kind="auth_failure" (PAT-1266): whether the most recently
    ///     completed send hit HTTP 401/403 — see
    ///     InventoryQueuePump.LastAttemptWasAuthFailure. Deliberately a
    ///     separate signal, not folded into queue_backlog: an auth failure is
    ///     never enqueued (see that same doc comment for why), so a broken
    ///     credential can produce a SMALL or EMPTY queue while still being
    ///     actively degraded — the opposite shape of queue_backlog, so it
    ///     needs its own kind or it would be invisible exactly when the
    ///     queue looks healthiest. The two signals are independent and can
    ///     both be active at once — they are not mutually exclusive.
    ///
    /// Called after every send/enqueue attempt and after every drain attempt
    /// so both signals track the pump's real state from both directions.
    /// </summary>
    private void ReportQueueHealth()
    {
        var depth = _pump.QueueDepth();
        if (depth > 0)
        {
            _agentHealthStore.RecordFailure("queue_backlog", "inventory",
                $"{depth} record(s) queued for retry (cap {InventoryQueuePump.MaxQueuedRecords})");
        }
        else
        {
            _agentHealthStore.RecordSuccess("queue_backlog", "inventory");
        }

        if (_pump.LastAttemptWasAuthFailure)
        {
            _agentHealthStore.RecordFailure("auth_failure", "inventory",
                "inventory POST rejected with HTTP 401/403 — credential appears invalid or rotated");
        }
        else
        {
            _agentHealthStore.RecordSuccess("auth_failure", "inventory");
        }
    }

    internal async Task<InventoryPayload> BuildPayloadAsync(
        IReadOnlyList<ComplianceFinding> complianceFindings,
        IReadOnlyList<string>            controlsAssessed,
        OsUpdateInfo?                    osUpdate)
    {
        // PAT-380: fold UserAssist software-metering into the apps[] array and set the
        // device-level metering_status, using the same neutral columns as macOS.
        var metering = _metering.Collect();
        // PAT-2066: the rows and collection_status.apps come from one scan, so the status
        // can only ever describe the rows it is sent with. ScanWithStatus never throws; a
        // failed scan is unavailable with apps [].
        var appScan = _appScanner.ScanWithStatus();
        var apps = AppMeteringEvidence.Apply(appScan.Apps, metering.ByIdentifier);

        // PAT-1732: certificates and collection_status.certificates come from one result,
        // so an unreadable store is omitted and marked unavailable, never sent as [].
        var certs = _certCollector.Collect();

        // PAT-1974: the local administrator group is read once and feeds two places —
        // the local_admin_count scalar in the flat compliance bag and the structured
        // local_admins roster — from one result, so the count and the roster can never
        // disagree about what this run actually saw. Same shape as the metering read
        // above, which folds one collection into apps[] and metering_status.
        var localAdmins = _localAdmins.Collect();

        // The bag is built by ComplianceCollector and the one signal that needs the
        // roster's evidence is set here rather than read a second time inside it.
        var compliance = _complianceCollector.Collect();
        compliance["local_admin_count"] = localAdmins.CountSignal;
        var evidenceCatalogue = InstallationEvidenceStore.LoadForInventory(_configManager.Current);
        var evidencePreflight = new HelperPreflightReporter(_log, _agentHealthStore,
            HelperPreflightReporter.InstallationEvidenceSubject);
        var installationEvidence = await InstallationEvidenceCollector.CollectVerifiedAsync(apps,
            evidenceCatalogue, (target, budget) => InstallationEvidenceProbe.CollectAsync(evidenceCatalogue!, target, budget,
                evidencePreflight.Observe))
            .ConfigureAwait(false);
        // PAT-2116: Authenticode evidence for every other app row, bounded by
        // AppSignatureCoverage's per-step and per-scan budgets. Rows that already carry
        // reviewed-target evidence keep it. Same apps[].installation_evidence location, so
        // the platform ingests it unchanged; its status rides in the summary's coverage.
        // A refused helper preflight is logged and recorded in agent-health (same cycle: the
        // agent_health section is built below), and its rows say helper_preflight_refused.
        var coveragePreflight = new HelperPreflightReporter(_log, _agentHealthStore,
            HelperPreflightReporter.AppSignaturesSubject);
        var coverage = await AppSignatureCoverage.CollectAsync(installationEvidence.Apps, AppSignatureCoverageProbe.Cache,
            (request, budget) => AppSignatureCoverageProbe.RunSessionAsync(request, budget, coveragePreflight.Observe))
            .ConfigureAwait(false);

        // PAT-1959: one read of the machine class per cycle. A failed or unrecognised
        // source yields "unknown" and an omitted string, never an inferred default.
        var deviceClass = _deviceCollector.CollectDeviceClass();

        // PAT-2065: the rows and the status block come from one collection, so the block can
        // only ever describe the rows it is sent with.
        var browserExtensions = _browserExtensions.Collect();

        return new()
        {
            Agent              = AgentName,
            AgentVersion       = AgentVersion,
            TenantId           = _creds.TenantId,
            CollectedAt        = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Device             = _deviceCollector.CollectDevice(),
            Hardware           = _deviceCollector.CollectHardware(),
            Os                 = _deviceCollector.CollectOs(),
            DeviceClass        = deviceClass.DeviceClass,
            InstallationType   = deviceClass.InstallationType,
            OsCaption          = deviceClass.OsCaption,
            OsUpdate           = osUpdate,
            Compliance         = compliance,
            ComplianceFindings = complianceFindings,
            // PAT-913: positive per-control attestation. Always present for parity
            // with the macOS collector; an empty controls_assessed attests nothing.
            ComplianceAssessments = new ComplianceAssessments { ControlsAssessed = controlsAssessed },
            SecurityTools      = _securityTools.Detect(deviceClass.DeviceClass),
            Apps               = coverage.Apps,
            InstallationEvidence = installationEvidence.Summary with { Coverage = coverage.Summary },
            MeteringStatus     = metering.Status,
            MeteringUserHiveCount = metering.UserHiveCount,
            MeteringRecordCount = metering.RecordCount,
            Certificates       = certs.Certificates,
            CollectionStatus   = new InventoryCollectionStatus { Certificates = certs.Status, Apps = appScan.Status, AppsUsers = appScan.Users },
            LocalAdmins        = localAdmins.Payload,
            HardwareHealth     = _hardwareHealth.Collect(),
            // PAT-2262: always sent. A failed or empty read is an unavailable block, never
            // an omitted key, which the platform would read as an agent that predates it.
            Firmware           = _deviceCollector.CollectFirmware(),
            // PAT-2263: always sent, within its byte budget; past it the block is sent as
            // unavailable with the same enforcement reads. HVCI is this cycle's compliance
            // read of Win32_DeviceGuard, not a second query.
            KernelDrivers      = KernelDriversWithinBudget(_kernelDrivers.Collect(_complianceCollector.LastHvciStatus)),
            BackupStatus       = _backupCollector.Collect(),
            BrowserExtensions  = browserExtensions.Extensions,
            // PAT-2065: always sent; failed when the collection could not read.
            BrowserExtensionsStatus = browserExtensions.Status,
            // PAT-2017, on the wire since PAT-2225 within its byte budget; past it the block
            // is sent as failed (see ToolingBlockBudget).
            IdeExtensions      = WithinBudget("ide_extensions", _ideExtensions.Collect(),
                ToolingBlockBudget.IdeExtensionsMaxBytes,
                () => new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed }),
            // PAT-2018, on the wire since PAT-2225 within its byte budget; past it the block
            // is sent as failed (see ToolingBlockBudget).
            PackageManagers    = WithinBudget("package_managers", _packageManagers.Collect(),
                ToolingBlockBudget.PackageManagersMaxBytes,
                () => new InventoryPackageManagers { CollectionStatus = PackageCollectionStatus.Failed }),
            // PAT-2019, on the wire since PAT-2225 within its byte budget; past it the block
            // is sent as failed (see ToolingBlockBudget).
            LocalModels        = WithinBudget("local_models", _localModels.Collect(),
                ToolingBlockBudget.LocalModelsMaxBytes,
                () => new InventoryLocalModels { CollectionStatus = PackageCollectionStatus.Failed }),
            // PAT-2020, on the wire since PAT-2225 within its byte budget; past it the block
            // is sent as failed (see ToolingBlockBudget).
            McpServers         = WithinBudget("mcp_servers", _mcpServers.Collect(),
                ToolingBlockBudget.McpServersMaxBytes,
                () => new InventoryMcpServers { CollectionStatus = PackageCollectionStatus.Failed }),
            // PAT-1066: degraded-capability channel. Nullable — see InventoryPayload.
            // AgentHealth's doc comment for the absent-vs-present-empty contract.
            AgentHealth = _agentHealthStore.BuildPayloadSection(_creds.TenantId, _creds.CanonicalDeviceId),
        };
    }

    /// <summary>
    /// PAT-2263: the kernel driver block when it serialises within
    /// <see cref="KernelDriverBudget.MaxBlockBytes"/>, else an unavailable block carrying the
    /// same enforcement reads and <c>block_over_budget</c>, which grants no absence authority.
    /// </summary>
    private InventoryKernelDrivers KernelDriversWithinBudget(InventoryKernelDrivers block) =>
        WithinBudget("kernel_drivers", block, KernelDriverBudget.MaxBlockBytes,
            () => KernelDriverInventoryLogic.Unavailable(block.Enforcement, KernelDriverErrorCode.BlockOverBudget));

    /// <summary>
    /// PAT-2225: <paramref name="block"/> when it serialises, with the options the payload is
    /// sent with, within <paramref name="maxBytes"/>; otherwise the failed block, with a WARN
    /// naming the size and the budget (the macOS collectors log the same line).
    /// </summary>
    private T WithinBudget<T>(string subject, T block, int maxBytes, Func<T> failed)
    {
        var fit = ToolingBlockBudget.Fit(block, maxBytes, JsonOpts, failed);
        if (fit.OverBudget)
            _log.LogWarning("{Subject}: block is {Bytes} bytes, over the {MaxBytes}-byte budget; sent as failed",
                subject, fit.Bytes, maxBytes);
        return fit.Block;
    }

}
