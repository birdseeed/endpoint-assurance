using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.LocalModels;

namespace Patched.Shared.KernelDrivers;

/// <summary>PAT-2263: one Services subkey, read raw.</summary>
internal sealed record DriverServiceEntry(string Name, RegistryRead Type, RegistryRead ImagePath, RegistryRead Start);

/// <summary>
/// PAT-2263: HKLM\SYSTEM\CurrentControlSet\Services. <paramref name="Failed"/> when the key
/// could not be opened or its subkeys listed; <paramref name="UnreadableEntries"/> counts
/// subkeys that were listed but could not be opened.
/// </summary>
internal readonly record struct DriverServiceEnumeration(bool Failed, IReadOnlyList<DriverServiceEntry> Services, int UnreadableEntries = 0)
{
    public static DriverServiceEnumeration Unreadable => new(true, []);
}

/// <summary>PAT-2263: the full paths of the *.sys files directly in %SystemRoot%\System32\drivers.</summary>
internal readonly record struct DriverDirectoryListing(bool Failed, IReadOnlyList<string> Files)
{
    public static DriverDirectoryListing Unreadable => new(true, []);
}

/// <summary>PAT-2263: the kernel's loaded-module names, as the kernel spells them.</summary>
internal readonly record struct LoadedModuleList(bool Failed, IReadOnlyList<string> Names)
{
    public static LoadedModuleList Unreadable => new(true, []);
}

internal sealed record KernelDriverSources(
    string? SystemRoot,
    DriverDirectoryListing Directory,
    DriverServiceEnumeration Services,
    LoadedModuleList Loaded,
    InventoryDriverEnforcement Enforcement);

internal enum DriverOpenOutcome { Opened, Missing, ReparsePoint, NotRegularFile, Failed, PathUnsupported }

/// <summary>
/// PAT-2263: an opened driver file, or why it was not opened. <see cref="Lease"/> holds
/// whatever keeps the file from being swapped while it is read (on Windows, the locked chain
/// of directory handles) and is disposed with the stream.
/// </summary>
internal sealed class DriverFileOpen(DriverOpenOutcome outcome, Stream? stream = null, IDisposable? lease = null) : IDisposable
{
    public DriverOpenOutcome Outcome { get; } = outcome;
    public Stream? Stream { get; } = stream;

    public void Dispose()
    {
        Stream?.Dispose();
        lease?.Dispose();
    }
}

/// <summary>
/// PAT-2263: opens one driver file for reading without following a reparse point anywhere
/// on its path. Must not throw.
/// </summary>
internal delegate DriverFileOpen DriverFileOpener(string path);

internal sealed record KernelDriverLimits(int MaxDrivers, long MaxFileBytes, long MaxTotalBytes, TimeSpan TimeBudget)
{
    public static KernelDriverLimits Default => new(
        KernelDriverBudget.MaxDrivers, KernelDriverBudget.MaxFileBytes,
        KernelDriverBudget.MaxTotalBytes, KernelDriverBudget.HashingTimeBudget);
}

/// <summary>
/// PAT-2263: builds the <c>kernel_drivers</c> block from the three driver sources, the
/// enforcement reads and a file opener. Every rule lives here, off Windows, so it is tested
/// on any OS; the Service supplies the Windows reads.
///
/// Sources: every *.sys directly in %SystemRoot%\System32\drivers; every Services subkey of
/// Type 1 (kernel driver) or 2 (file-system driver), at its ImagePath or, with none, the I/O
/// manager's default; and every module in the kernel's loaded-module list. Rows are
/// deduplicated by resolved path, ignoring case.
///
/// Bounds: at most <see cref="KernelDriverLimits.MaxDrivers"/> rows (loaded and service rows
/// first, then directory-only rows, each by path); per file
/// <see cref="KernelDriverLimits.MaxFileBytes"/>; across the cycle
/// <see cref="KernelDriverLimits.MaxTotalBytes"/> and <see cref="KernelDriverLimits.TimeBudget"/>.
/// Hashing runs on its own thread and the budget is enforced from outside it, so a read that
/// blocks (an oplock held by another process, a stalled volume) costs the cycle the budget and
/// no more: whatever was not hashed by then is sent unhashed as <c>time_budget</c>.
///
/// Status: unavailable when all three sources failed (or %SystemRoot% is unusable); partial
/// when any source failed, any entry was unreadable or unusable, the row cap cut the list, or
/// any row is unhashed for a reason other than <c>file_missing</c>; else complete.
/// </summary>
internal static class KernelDriverInventoryLogic
{
    private sealed class Row
    {
        public string? Path;
        public bool InDirectory, InService, InLoaded;
        public string? ServiceName, ServiceType, StartType;
        public string? FixedUnhashedReason;
    }

    private sealed record HashOutcome(string? UnhashedReason, long? Size, DriverHashes? Hashes, string? Version);

    public static InventoryKernelDrivers Build(KernelDriverSources sources, DriverFileOpener open, KernelDriverLimits limits)
    {
        var errors = new List<string>();
        void Error(string code)
        {
            if (!errors.Contains(code)) errors.Add(code);
        }

        var systemRoot = sources.SystemRoot?.TrimEnd('\\');
        if (systemRoot is null || !DriverPathResolver.IsLocalDrivePath(systemRoot))
            return Unavailable(sources.Enforcement, KernelDriverErrorCode.CollectionFailed);

        if (sources.Directory.Failed) Error(KernelDriverErrorCode.DriversDirectoryUnreadable);
        if (sources.Services.Failed) Error(KernelDriverErrorCode.ServicesUnreadable);
        if (sources.Loaded.Failed) Error(KernelDriverErrorCode.LoadedModulesUnreadable);
        if (sources.Directory.Failed && sources.Services.Failed && sources.Loaded.Failed)
            return Unavailable(sources.Enforcement, errors.ToArray());
        if (!sources.Services.Failed && sources.Services.UnreadableEntries > 0) Error(KernelDriverErrorCode.ServiceEntryUnreadable);

        var byPath = new Dictionary<string, Row>(StringComparer.OrdinalIgnoreCase);
        var pathless = new List<Row>();
        Row At(string path) => byPath.TryGetValue(path, out var r) ? r : byPath[path] = new Row { Path = path };

        if (!sources.Directory.Failed)
        {
            foreach (var file in sources.Directory.Files)
            {
                if (DriverPathResolver.IsLocalDrivePath(file)) At(file).InDirectory = true;
                else Error(KernelDriverErrorCode.DriversDirectoryEntryUnusable);
            }
        }

        if (!sources.Services.Failed)
        {
            foreach (var service in sources.Services.Services.OrderBy(s => s.Name, StringComparer.Ordinal))
            {
                string? serviceType;
                if (service.Type.State == RegistryReadState.Absent) continue;
                if (!service.Type.TryGetInt(out var type))
                {
                    Error(KernelDriverErrorCode.ServiceEntryUnreadable);
                    continue;
                }
                if (type == 1) serviceType = "kernel";
                else if (type == 2) serviceType = "file_system";
                else continue;

                if (!UsableName(service.Name))
                {
                    Error(KernelDriverErrorCode.ServiceValueUnusable);
                    continue;
                }

                string? path = null;
                string? fixedReason = null;
                switch (service.ImagePath.State)
                {
                    case RegistryReadState.Absent:
                        path = DriverPathResolver.DefaultImagePath(service.Name, systemRoot);
                        break;
                    case RegistryReadState.Present when service.ImagePath.Value is string raw:
                        path = DriverPathResolver.Resolve(raw, systemRoot);
                        break;
                    default:
                        Error(KernelDriverErrorCode.ServiceEntryUnreadable);
                        fixedReason = KernelDriverUnhashedReason.ReadFailed;
                        break;
                }
                fixedReason ??= path is null ? KernelDriverUnhashedReason.PathUnsupported : null;

                var row = path is null ? new Row() : At(path);
                if (path is null) pathless.Add(row);
                row.FixedUnhashedReason ??= fixedReason;
                row.InService = true;
                if (row.ServiceName is null)
                {
                    row.ServiceName = service.Name;
                    row.ServiceType = serviceType;
                    row.StartType = service.Start.TryGetInt(out var start) ? start switch
                    {
                        0 => "boot",
                        1 => "system",
                        2 => "auto",
                        3 => "demand",
                        4 => "disabled",
                        _ => null,
                    } : null;
                }
            }
        }

        if (!sources.Loaded.Failed)
        {
            foreach (var name in sources.Loaded.Names)
            {
                // A loaded module's name always carries a root; a bare name is not relative
                // to %SystemRoot% the way an ImagePath is, so it is not resolved.
                var path = name is { Length: > 0 } && name.Contains('\\')
                    ? DriverPathResolver.Resolve(name, systemRoot)
                    : null;
                if (path is null)
                {
                    Error(KernelDriverErrorCode.LoadedPathUnresolved);
                    continue;
                }
                At(path).InLoaded = true;
            }
        }

        // Row cap: what is running or configured to run matters most.
        var ordered = byPath.Values
            .OrderBy(r => r.InLoaded || r.InService ? 0 : 1)
            .ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .Concat(pathless.OrderBy(r => r.ServiceName, StringComparer.Ordinal))
            .ToList();
        if (ordered.Count > limits.MaxDrivers)
        {
            Error(KernelDriverErrorCode.DriverCountLimit);
            ordered = ordered.Take(limits.MaxDrivers).ToList();
        }

        var outcomes = HashAll(ordered, open, limits);

        var drivers = new List<InventoryKernelDriver>(ordered.Count);
        for (var i = 0; i < ordered.Count; i++)
        {
            var row = ordered[i];
            var outcome = row.FixedUnhashedReason is { } fixedReason
                ? new HashOutcome(fixedReason, null, null, null)
                : outcomes[i] ?? new HashOutcome(KernelDriverUnhashedReason.TimeBudget, null, null, null);
            if (outcome.UnhashedReason is { } reason && reason != KernelDriverUnhashedReason.FileMissing)
                Error(KernelDriverErrorCode.DriverUnhashed);

            var sourcesSeen = new List<string>(3);
            if (row.InDirectory) sourcesSeen.Add(KernelDriverSource.DriversDirectory);
            if (row.InService) sourcesSeen.Add(KernelDriverSource.Service);
            if (row.InLoaded) sourcesSeen.Add(KernelDriverSource.Loaded);

            drivers.Add(new InventoryKernelDriver
            {
                Path = row.Path,
                Sources = sourcesSeen,
                ServiceName = row.ServiceName,
                ServiceType = row.ServiceType,
                StartType = row.StartType,
                Loaded = sources.Loaded.Failed ? null : row.InLoaded,
                HashStatus = outcome.Hashes is null ? KernelDriverHashStatus.Unhashed : KernelDriverHashStatus.Hashed,
                UnhashedReason = outcome.Hashes is null ? outcome.UnhashedReason : null,
                SizeBytes = outcome.Size,
                Sha256 = outcome.Hashes?.Sha256,
                Sha1 = outcome.Hashes?.Sha1,
                AuthenticodeSha256 = outcome.Hashes?.AuthenticodeSha256,
                AuthenticodeSha1 = outcome.Hashes?.AuthenticodeSha1,
                Version = outcome.Version,
            });
        }

        drivers.Sort((a, b) =>
        {
            if ((a.Path is null) != (b.Path is null)) return a.Path is null ? 1 : -1;
            var byPathOrder = string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            return byPathOrder != 0 ? byPathOrder : string.CompareOrdinal(a.ServiceName, b.ServiceName);
        });

        return new InventoryKernelDrivers
        {
            CollectionStatus = errors.Count == 0 ? KernelDriverCollectionStatus.Complete : KernelDriverCollectionStatus.Partial,
            Errors = errors.Take(KernelDriverErrorCode.MaxErrors).ToArray(),
            Enforcement = sources.Enforcement,
            Drivers = drivers,
        };
    }

    /// <summary>The block when nothing about the driver list could be read.</summary>
    public static InventoryKernelDrivers Unavailable(InventoryDriverEnforcement enforcement, params string[] errors) => new()
    {
        CollectionStatus = KernelDriverCollectionStatus.Unavailable,
        Errors = errors.Distinct().Take(KernelDriverErrorCode.MaxErrors).ToArray(),
        Enforcement = enforcement,
        Drivers = null,
    };

    /// <summary>
    /// Hashes every row that has a path, on its own thread, within the limits. A slot left
    /// null ran out of time. The worker is abandoned, not awaited, once the budget is spent: a
    /// read it is blocked in cannot hold the cycle, and anything it records after the snapshot
    /// is ignored.
    /// </summary>
    private static readonly object InFlightLock = new();
    private static Thread? _inFlight;

    /// <summary>
    /// True while a hashing worker from an earlier cycle is still blocked in a read. That
    /// cycle has already reported its unfinished rows as <c>time_budget</c>; while the worker
    /// is stuck no new one is started, so a read that never returns costs one thread, not one
    /// per cycle.
    /// </summary>
    internal static bool EarlierWorkerStillRunning
    {
        get { lock (InFlightLock) return _inFlight is { IsAlive: true }; }
    }

    private static HashOutcome?[] HashAll(IReadOnlyList<Row> rows, DriverFileOpener open, KernelDriverLimits limits)
    {
        var results = new HashOutcome?[rows.Count];
        lock (InFlightLock)
        {
            if (_inFlight is { IsAlive: true }) return results;
        }
        var cancel = new CancellationTokenSource();
        var worker = new Thread(() =>
        {
            long total = 0;
            for (var i = 0; i < rows.Count; i++)
            {
                if (cancel.IsCancellationRequested) return;
                var row = rows[i];
                if (row.Path is null || row.FixedUnhashedReason is not null) continue;
                var outcome = HashOne(row.Path, open, limits, ref total, cancel.Token);
                Volatile.Write(ref results[i], outcome);
            }
        })
        {
            IsBackground = true,
            Name = "patched-kernel-driver-hash",
        };
        lock (InFlightLock)
        {
            if (_inFlight is { IsAlive: true }) return results;
            _inFlight = worker;
            worker.Start();
        }
        worker.Join(limits.TimeBudget);
        cancel.Cancel();
        var snapshot = new HashOutcome?[rows.Count];
        for (var i = 0; i < rows.Count; i++) snapshot[i] = Volatile.Read(ref results[i]);
        return snapshot;
    }

    private static HashOutcome HashOne(string path, DriverFileOpener open, KernelDriverLimits limits, ref long total,
        CancellationToken cancellation)
    {
        DriverFileOpen? file = null;
        try
        {
            file = open(path);
            switch (file.Outcome)
            {
                case DriverOpenOutcome.Opened when file.Stream is not null:
                    break;
                case DriverOpenOutcome.Missing:
                    return new(KernelDriverUnhashedReason.FileMissing, null, null, null);
                case DriverOpenOutcome.ReparsePoint:
                    return new(KernelDriverUnhashedReason.ReparsePoint, null, null, null);
                case DriverOpenOutcome.NotRegularFile:
                    return new(KernelDriverUnhashedReason.NotRegularFile, null, null, null);
                case DriverOpenOutcome.PathUnsupported:
                    return new(KernelDriverUnhashedReason.PathUnsupported, null, null, null);
                default:
                    return new(KernelDriverUnhashedReason.ReadFailed, null, null, null);
            }

            var stream = file.Stream;
            var length = stream.Length;
            if (length > limits.MaxFileBytes) return new(KernelDriverUnhashedReason.SizeLimit, length, null, null);
            if (total + length > limits.MaxTotalBytes) return new(KernelDriverUnhashedReason.ByteBudget, length, null, null);
            total += length;

            var hashes = DriverFileHasher.Hash(stream, cancellation);
            var (status, version) = PeVersionReader.Read((offset, destination) =>
            {
                stream.Position = offset;
                return stream.Read(destination);
            }, fileVersion: true);
            return new(null, hashes.Length, hashes, status == "read" ? version : null);
        }
        catch (OperationCanceledException)
        {
            return new(KernelDriverUnhashedReason.TimeBudget, null, null, null);
        }
        catch (Exception)
        {
            return new(KernelDriverUnhashedReason.ReadFailed, null, null, null);
        }
        finally
        {
            try { file?.Dispose(); } catch { }
        }
    }

    private static bool UsableName(string name) =>
        name.Length is > 0 and <= KernelDriverBudget.MaxServiceNameLength &&
        name == name.Trim() && !name.Any(char.IsControl) && name.IndexOfAny(['\\', '/']) < 0;
}
