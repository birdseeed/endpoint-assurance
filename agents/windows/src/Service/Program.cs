using Microsoft.Extensions.Logging.EventLog;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Paths;
using Patched.Shared.Proxy;
using Patched.Shared.Security;
using Patched.Shared.Verification;
using Patched.Verifier;

// Read-only evidence helper exits before credentials, state bootstrap or hosted services.
if (args.Length > 0 && args[0] == InstallationEvidenceProbe.Command)
    return InstallationEvidenceProbe.RunCommand(args);
// PAT-2116: the all-apps Authenticode coverage helper, same boundary as the one above.
if (args.Length > 0 && args[0] == AppSignatureCoverageProbe.Command)
    return AppSignatureCoverageProbe.RunCommand(args, Console.In, Console.Out);

// PAT-1764: installer commands are dispatched before anything below runs. The MSI's
// uninstall custom action runs "Patched.Service.exe --purge-credentials" and its install
// custom action runs "Patched.Service.exe --write-enrollment-token <token>" (PAT-1755);
// each must do its one job and exit without bootstrapping state directories or starting
// the host.
return ServiceEntryPoint.Run(
    args,
    CredentialPurgeCommand.RunProduction,
    EnrollmentTokenProvisionCommand.RunProduction,
    () => RunServiceHost(args));

static int RunServiceHost(string[] args)
{
    // PAT-1223: this is deliberately the first state-directory operation. The bootstrap
    // is tier-independent and runs before logging, hosted services, or decommission can
    // write beneath StateDir. It creates a missing root with the protected DACL and repairs
    // only the MSI-created, SYSTEM/Administrators-owned root; a pre-planted/reparse or
    // untrusted-owner path still fails closed rather than being trusted at service startup.
    // PAT-2396: the result says whether the root carried a non-admin write-capable DACL
    // until this call. It is reported once logging exists (below); it is not a gate.
    bool stateRootDaclRepaired = StateDirectoryBootstrap.EnsureHardened();

    var logDir = Path.GetDirectoryName(PathConstants.LogFile)!;
    SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(logDir);

    var builder = Host.CreateApplicationBuilder(args);

    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = "Patched Agent";
    });

    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "Patched Agent";
    });

    // PAT-705: add a rolling file logger so upload errors are visible from
    // C:\ProgramData\Patched\logs\patched-agent-YYYY-MM-DD-<session>.log without needing
    // to inspect Windows Event Viewer. Retains the last 30 days of safe regular logs.
    // A legacy writable StateDir could have a predictable daily name pre-planted as a
    // reparse point or hard link, so session names are the permanent contract rather
    // than a one-start recovery mode.
    builder.Logging.AddProvider(new RollingFileLoggerProvider(logDir));

    // Credentials — loaded once at start. LoadForStartup tolerates the enrollment-
    // pending state (enrollment token present, no bearer-token yet); the worker
    // calls AgentEnroller before the first run cycle to exchange the token.
    builder.Services.AddSingleton<CredentialStore>(sp =>
        CredentialStore.LoadForStartup(sp.GetRequiredService<ILoggerFactory>().CreateLogger<CredentialStore>()));

    // Core assurance services. PAT-1531 deliberately excludes the legacy package
    // engine and its status collector from this build: Windows observations are sent
    // through InventoryPoster, while remediation stays with the customer's management
    // or ticketing platform.
    builder.Services.AddSingleton<StatusWriter>();
    builder.Services.AddSingleton<ProvenancePoster>();
    builder.Services.AddSingleton<AuditEventShipper>();  // PAT-499: SIEM audit event ring-buffer
    builder.Services.AddSingleton<TriggerAcl>();
    builder.Services.AddSingleton<TriggerWatcher>();

    // Inventory egress (PAT-336): collect device/compliance/apps + POST /v1/inventory.
    builder.Services.AddSingleton<DeviceCollector>();
    builder.Services.AddSingleton<ComplianceCollector>();
    builder.Services.AddSingleton<InstalledAppScanner>();
    builder.Services.AddSingleton<SecurityToolDetector>();
    // PAT-380: software metering via UserAssist (parity with macOS Spotlight metering).
    builder.Services.AddSingleton<UserAssistReader>();
    builder.Services.AddSingleton<MeteringCollector>();
    // PAT-641: machine cert expiry (parity with macos/lib/certs.sh).
    builder.Services.AddSingleton<CertCollector>();
    // PAT-1974: standing local administrator roster (parity with macos/lib/auth.sh).
    builder.Services.AddSingleton<LocalAdminCollector>();
    // PAT-685: hardware health (battery/SMART/storage — parity with macOS hardware_health).
    builder.Services.AddSingleton<HardwareHealthCollector>();
    // PAT-680: backup status (File History/OneDrive/Acronis/Veeam — parity with macOS backup_status).
    builder.Services.AddSingleton<BackupCollector>();
    // PAT-827: browser extension inventory (Chrome/Edge/Firefox — parity with macOS browser_extensions).
    builder.Services.AddSingleton<BrowserExtensionScanner>();
    // PAT-2017: IDE extension inventory (VS Code family + JetBrains — parity with macOS ide_extensions).
    builder.Services.AddSingleton<IdeExtensionScanner>();
    // PAT-2018: npm global, pip user and pipx inventory (parity with macOS package_managers).
    builder.Services.AddSingleton<PackageManagerScanner>();
    // PAT-2019: local model runtimes and model stores (parity with macOS local_models).
    builder.Services.AddSingleton<LocalModelScanner>();
    // PAT-2020: MCP server configurations, name/executable/package/host only (parity with macOS mcp_servers).
    builder.Services.AddSingleton<McpServerScanner>();
    // PAT-2263: kernel and file-system drivers by hash, plus vulnerable driver blocklist state.
    builder.Services.AddSingleton<KernelDriverCollector>();
    // PAT-1066: agent_health degraded-capability store (parity with macOS agent_health.sh, PAT-1065).
    builder.Services.AddSingleton<AgentHealthStore>();
    // PAT-2352: bounded retirement of the old tray; independent of collection or identity.
    builder.Services.AddHostedService<RetiredTrayCleanup>();
    builder.Services.AddSingleton<AssuranceCapabilityHealth>();
    builder.Services.AddSingleton<InventoryPoster>();

    // Posture cache (desktop chain U0): fetch GET /v1/posture + atomically cache
    // world-readable posture.json for the tray. Reuses the inventory
    // credential path; no second secret path.
    builder.Services.AddSingleton<PostureFetcher>();

    // Enrollment exchange (PAT-545): POST /v1/enrol with single-use token to get
    // per-device credentials; runs at startup before the first run cycle.
    builder.Services.AddSingleton<AgentEnroller>();

    // Agent-config consumer (PAT-310): fetch + Ed25519-verify + cache + 15-min poll.
    builder.Services.AddSingleton<AgentConfigFetcher>();
    builder.Services.AddSingleton<AgentConfigManager>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentConfigManager>());

    // PAT-308: OS update awareness via WUA IUpdateSearcher.
    builder.Services.AddSingleton<OsUpdateChecker>();

    // PAT-1110: agent-decommission directive — evaluates the signed decommission block
    // every cycle and, when due, reports terminal status then hands off to the detached
    // removal script (a Windows service cannot msiexec /x itself while running).
    builder.Services.AddSingleton<DecommissionStatusReporter>();
    builder.Services.AddSingleton<IDecommissionStatusReporter>(sp => sp.GetRequiredService<DecommissionStatusReporter>());
    builder.Services.AddSingleton<IDecommissionHandoff, DecommissionHandoff>();
    builder.Services.AddSingleton<DecommissionRunner>();

    // PAT-552: Application Control enforcement.
    // AdminEnforcer: removes unauthorised local admin accounts (approved-admins list).
    // AppAllowlistEnforcer: reports unlisted installed apps (alert-only v1).
    builder.Services.AddSingleton<AdminEnforcer>();
    builder.Services.AddSingleton<AppAllowlistEnforcer>();
    // PAT-828: BrowserExtensionBlocklistEnforcer — pushes Chrome/Edge/Firefox
    // managed policy blocking the tenant's unapproved extensions.
    builder.Services.AddSingleton<BrowserExtensionBlocklistEnforcer>();
    // PAT-829: BrowserExtensionRemover — profile-aware destructive removal of the
    // tenant's listed extensions (the escalation path after the blocklist).
    builder.Services.AddSingleton<BrowserExtensionRemover>();

    // PAT-1293: registers the one-shot scheduled task that bounces the service so
    // PendingUpdateApplier (below) gets a chance to actually apply what BootstrapUpdater
    // stages — see PendingUpdateRestartScheduler's class doc comment for why nothing
    // else in the product ever performed this restart before now.
    builder.Services.AddSingleton<IPendingUpdateRestartScheduler, PendingUpdateRestartScheduler>();

    // PAT-108: bootstrap self-update check. Runs at service start via PatchedWorker.
    builder.Services.AddSingleton<BootstrapUpdater>();

    // PAT-1261: applies the pending-update marker BootstrapUpdater stages but never
    // consumed on its own — see PendingUpdateApplier's class doc comment. Runs at
    // service start via PatchedWorker, before/independently of the BootstrapUpdater
    // check above.
    // PAT-2400: the applier's owner/DACL verifier is deliberately not registered here.
    // Its public constructor wires the real one, so no registration can replace it.
    builder.Services.AddSingleton<IPendingUpdateLauncher, MsiexecPendingUpdateLauncher>();
    // PAT-2399: verifies the install directory and this executable before the two lines of
    // self-update work above and below are allowed to run; reports degraded, never exits.
    builder.Services.AddSingleton<InstallIntegrityGate>();
    builder.Services.AddSingleton<PendingUpdateApplier>();

    builder.Services.AddHostedService<PatchedWorker>();

    // Proxy resolver (PAT-309, parity with macOS PAT-278): resolves the egress
    // proxy per request from the verified agent-config — system (WinHTTP/PAC),
    // manual (host/port + Credential Manager creds), or off (force direct).
    builder.Services.AddSingleton<ProxyResolver>();

    // PAT-513: adds X-Patched-Device-Id to every outgoing platform request.
    // PAT-736: the handler must be transient (the HttpClientFactory rejects reused
    // DelegatingHandlers on pipeline rebuild); the WMI UUID is cached in the
    // singleton DeviceIdProvider.
    builder.Services.AddSingleton<DeviceIdProvider>();
    builder.Services.AddTransient<DeviceIdentityHandler>();

    // The "patched" HttpClient routes through the proxy via DynamicWebProxy, which
    // re-resolves on every request so a config-poll change takes effect without a
    // service restart. UseProxy=true + a per-request IWebProxy lets us honour
    // manual/system/off and the no_proxy bypass list.
    builder.Services.AddHttpClient("patched", (_, client) =>
    {
        client.BaseAddress = new Uri(PathConstants.ApiUrl);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("PatchedAgent/1.0 (Windows)");
        client.Timeout = PatchedHttpClientTimeouts.Default;
    })
    .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
    {
        Proxy = new DynamicWebProxy(
            sp.GetRequiredService<ProxyResolver>(),
            sp.GetRequiredService<AgentConfigManager>(),
            sp.GetRequiredService<ILogger<DynamicWebProxy>>()),
        UseProxy          = true,
        AllowAutoRedirect = false,
    })
    .AddHttpMessageHandler<DeviceIdentityHandler>();

    // PAT-1260: a second named client, used ONLY for the artifact byte download
    // (BootstrapUpdater). Same base address, user agent, proxy resolution and
    // device-identity header as "patched" above - the only difference is the
    // Timeout. HttpClient.Timeout bounds the whole operation including reading
    // the response body (even under HttpCompletionOption.ResponseHeadersRead),
    // so the 30s budget that is correct for "patched"'s small JSON calls would
    // require >5.3 MB/s sustained throughput to pull a ~160 MB MSI - it fails on
    // any ordinary connection. See PatchedHttpClientTimeouts for the ceiling and
    // its reasoning. Kept as a distinct client rather than a per-request timeout
    // override because HttpClient has no supported way to relax Timeout for a
    // single call on a shared instance.
    builder.Services.AddHttpClient("patched-artifact", (_, client) =>
    {
        client.BaseAddress = new Uri(PathConstants.ApiUrl);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("PatchedAgent/1.0 (Windows)");
        client.Timeout = PatchedHttpClientTimeouts.Artifact;
    })
    .ConfigurePrimaryHttpMessageHandler(sp => new SocketsHttpHandler
    {
        Proxy = new DynamicWebProxy(
            sp.GetRequiredService<ProxyResolver>(),
            sp.GetRequiredService<AgentConfigManager>(),
            sp.GetRequiredService<ILogger<DynamicWebProxy>>()),
        UseProxy          = true,
        AllowAutoRedirect = false,
    })
    .AddHttpMessageHandler<DeviceIdentityHandler>();

    var host = builder.Build();

    // PAT-2396: never fatal, never a trust decision. Nothing below StateDir is trusted
    // because of the repair, or distrusted only when it happened: a root repaired on an
    // earlier start reports false here with its old contents still in place. Each
    // privileged consumer authenticates what it uses (PendingUpdateApplier verifies the
    // signed envelope). This line exists so a device that had a writable root says so.
    try
    {
        var bootstrapLog = host.Services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Patched.Service.StateDirectoryBootstrap");
        if (stateRootDaclRepaired)
        {
            bootstrapLog.LogWarning(
                "state-directory: {Dir} carried a write-capable DACL for a non-admin principal and was " +
                "repaired at this start; files already under it are not trusted on that basis",
                PathConstants.StateDir);
        }
        else
        {
            bootstrapLog.LogInformation(
                "state-directory: {Dir} DACL was already protected at this start", PathConstants.StateDir);
        }
    }
    catch (Exception)
    {
        // Reporting only; must not affect startup.
    }

    // PAT-2245: the signed app catalogue is retired. Remove the cache an older release's
    // catalogue sync left in StateDir. Best effort, logged, never fatal, and never
    // through a reparse point; see RetiredCatalogueCleanup.
    try
    {
        RetiredCatalogueCleanup.RunProduction(
            host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Patched.Service.RetiredCatalogueCleanup"));
    }
    catch (Exception)
    {
        // RetiredCatalogueCleanup never throws; this guards the logger lookup only.
    }

    // PAT-1766: a device with no identity no longer exits here (PAT-1764 exited 2,
    // which failed the MSI's StartServices and rolled back the install or upgrade).
    // CredentialStore.LoadForStartup returns a store that is AwaitingProvisioning and
    // PatchedWorker reports it and polls until a token or credentials appear.
    host.Run();
    return 0;
}
