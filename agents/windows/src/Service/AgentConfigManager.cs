using Patched.Shared.Config;

namespace Patched.Service;

/// <summary>
/// Owns the agent-config lifecycle (PAT-310, parity with the macOS config-poll
/// LaunchDaemon): load the cached config at start, fetch immediately, then poll
/// roughly every 15 minutes. Always exposes the last-known-good config (or safe
/// defaults) so the worker can read it without blocking on the network.
/// </summary>
public sealed class AgentConfigManager : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(15);

    /// <summary>
    /// PAT-1754: how often the loop rechecks for a bearer token while the device
    /// has not enrolled yet. The check is a local in-memory read, not a network
    /// call, so it uses the same 15-second cadence PatchedWorker already uses for
    /// its local trigger and suspended-marker checks. This bounds the gap between
    /// a successful /v1/enrol and the first signed agent-config to about 15
    /// seconds instead of a full <see cref="PollInterval"/>.
    /// </summary>
    internal static readonly TimeSpan EnrolmentRecheckInterval = TimeSpan.FromSeconds(15);

    private readonly ILogger<AgentConfigManager> _log;
    private readonly AgentConfigFetcher          _fetcher;
    private readonly TimeSpan                    _pollInterval;
    private readonly TimeSpan                    _enrolmentRecheckInterval;
    private readonly Func<bool>                  _hasDeviceCredentials;
    private readonly Func<string>                _enrolledTenantId;
    private readonly string                      _cachedConfigFile;

    // Reference assignment is atomic in .NET; volatile guarantees readers see the
    // latest published config without a lock.
    private volatile AgentConfig _current = AgentConfig.Defaults;

    // PAT-1763: the last config Current refused for belonging to another tenant,
    // so that refusal is logged once per config rather than on every read.
    private AgentConfig? _mismatchLoggedFor;

    public AgentConfigManager(ILogger<AgentConfigManager> log, AgentConfigFetcher fetcher)
        : this(log, fetcher, PollInterval, EnrolmentRecheckInterval, () => fetcher.HasDeviceCredentials)
    {
    }

    /// <summary>
    /// Test seam for the loop cadence and the enrolment check. Production always
    /// uses the public constructor, which binds the check to the fetcher's own
    /// CredentialStore. Internal constructors are not considered by DI.
    /// </summary>
    internal AgentConfigManager(
        ILogger<AgentConfigManager> log,
        AgentConfigFetcher          fetcher,
        TimeSpan                    pollInterval,
        TimeSpan                    enrolmentRecheckInterval,
        Func<bool>                  hasDeviceCredentials)
    {
        _log                      = log;
        _fetcher                  = fetcher;
        _pollInterval             = pollInterval;
        _enrolmentRecheckInterval = enrolmentRecheckInterval;
        _hasDeviceCredentials     = hasDeviceCredentials;
        // PAT-1763: the cache path and the enrolled tenant both come from the
        // fetcher, so the manager starts from the file the fetcher commits to and
        // judges it against the same credential the fetcher binds configs to.
        _enrolledTenantId         = () => fetcher.EnrolledTenantId;
        _cachedConfigFile         = fetcher.CachedConfigFile;
        _current = LoadCached() ?? AgentConfig.Defaults;
    }

    /// <summary>
    /// Last-known-good config for the tenant this device is enrolled in, or safe
    /// defaults if none has been verified for it yet.
    ///
    /// PAT-1763: a config for any other tenant is never returned. The start-up
    /// load already refuses one (<see cref="LoadCached"/>); this also covers a
    /// device re-enrolled into another tenant while the service runs, which would
    /// otherwise keep the old tenant's config until the new tenant's first
    /// accepted config. The refusal is logged once per config.
    /// </summary>
    public AgentConfig Current
    {
        get
        {
            var current = _current;
            if (ReferenceEquals(current, AgentConfig.Defaults))
                return current;
            string enrolledTenant = _enrolledTenantId();
            if (BelongsToTenant(current, enrolledTenant))
                return current;
            if (!ReferenceEquals(Interlocked.Exchange(ref _mismatchLoggedFor, current), current))
            {
                _log.LogWarning(
                    "AgentConfigManager: the config in effect (version {Version}) belongs to tenant {ConfigTenant}, not enrolled tenant {EnrolledTenant}; " +
                    "it is no longer used and the agent runs on defaults until a signed config for the enrolled tenant is accepted",
                    current.ConfigVersion, DescribeTenant(current.TenantId), DescribeTenant(enrolledTenant));
            }
            return AgentConfig.Defaults;
        }
    }

    /// <summary>
    /// PAT-1763: a config applies only to a non-empty enrolled tenant that it
    /// names exactly. A config with no tenant_id cannot be shown to belong to
    /// anyone, so it never applies.
    /// </summary>
    internal static bool BelongsToTenant(AgentConfig config, string enrolledTenantId) =>
        !string.IsNullOrEmpty(enrolledTenantId) &&
        !string.IsNullOrEmpty(config.TenantId) &&
        string.Equals(config.TenantId, enrolledTenantId, StringComparison.Ordinal);

    private static string DescribeTenant(string? tenantId) =>
        string.IsNullOrEmpty(tenantId) ? "(none)" : tenantId;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation("AgentConfigManager starting — initial tier={Tier} version={Version}",
            _current.Tier, _current.ConfigVersion);

        bool waitingForEnrolment = false;

        // Fetch immediately on start (once enrolled), then on the poll interval.
        while (!ct.IsCancellationRequested)
        {
            TimeSpan delay;

            // PAT-1754: this service starts alongside PatchedWorker, which runs
            // enrolment. Until a bearer token exists, send nothing and recheck
            // on the short local cadence, so the first fetch follows enrolment
            // within seconds rather than a full poll interval later.
            if (!_hasDeviceCredentials())
            {
                if (!waitingForEnrolment)
                {
                    _log.LogInformation(
                        "AgentConfigManager: device not enrolled yet, no agent-config request sent; rechecking every {Interval}",
                        _enrolmentRecheckInterval);
                    waitingForEnrolment = true;
                }
                else
                {
                    _log.LogDebug("AgentConfigManager: still not enrolled, skipping agent-config fetch");
                }
                delay = _enrolmentRecheckInterval;
            }
            else
            {
                if (waitingForEnrolment)
                {
                    _log.LogInformation("AgentConfigManager: device credentials now present, fetching agent-config now");
                    waitingForEnrolment = false;
                }

                try
                {
                    var fetched = await _fetcher.FetchAsync(ct).ConfigureAwait(false);
                    if (fetched is not null)
                    {
                        _current = fetched;
                        _log.LogInformation("AgentConfigManager applied config version={Version} tier={Tier}",
                            fetched.ConfigVersion, fetched.Tier);
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // Fetcher is already fail-safe; this is a last-resort guard so the
                    // poll loop never dies.
                    _log.LogError(ex, "AgentConfigManager: unexpected error during fetch — keeping last-good config");
                }

                delay = _pollInterval;
            }

            try
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
        }

        _log.LogInformation("AgentConfigManager stopping");
    }

    /// <summary>
    /// Loads the cached agent-config.json written by the last accepted config.
    ///
    /// PAT-1763: the cache is not keyed by tenant, so after a device is moved to
    /// another tenant it still holds the old tenant's config. A cached config
    /// whose tenant_id is not the enrolled tenant, or that has no tenant_id at
    /// all, is not used: the agent starts from defaults and logs why. The file
    /// is left in place; the enrolled tenant's first accepted config replaces it.
    /// </summary>
    private AgentConfig? LoadCached()
    {
        AgentConfig? cached;
        try
        {
            if (!File.Exists(_cachedConfigFile))
                return null;
            byte[] bytes = File.ReadAllBytes(_cachedConfigFile);
            cached = AgentConfig.Deserialize(bytes);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "AgentConfigManager: failed to load cached agent-config.json — using defaults");
            return null;
        }

        if (cached is null)
            return null;

        string enrolledTenant = _enrolledTenantId();
        if (string.IsNullOrEmpty(cached.TenantId))
        {
            _log.LogWarning(
                "AgentConfigManager: cached agent-config.json at {Path} (version {Version}) has no tenant_id, so it cannot be shown to belong to enrolled tenant {EnrolledTenant}; " +
                "treated as another tenant's config and not used. Starting from defaults until a signed config for the enrolled tenant is accepted",
                _cachedConfigFile, cached.ConfigVersion, DescribeTenant(enrolledTenant));
            return null;
        }
        if (!BelongsToTenant(cached, enrolledTenant))
        {
            _log.LogWarning(
                "AgentConfigManager: cached agent-config.json at {Path} (version {Version}) belongs to tenant {ConfigTenant}, not enrolled tenant {EnrolledTenant}; " +
                "not used. Starting from defaults until a signed config for the enrolled tenant is accepted",
                _cachedConfigFile, cached.ConfigVersion, cached.TenantId, DescribeTenant(enrolledTenant));
            return null;
        }
        // Other existing policy readers retain the legacy cache behaviour, but
        // self-update gets authority only from a reverified exact-byte proof.
        return _fetcher.LoadVerifiedUpdateAuthority() ?? cached;
    }
}
