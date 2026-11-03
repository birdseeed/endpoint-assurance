using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Patched.Service;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Xunit;

namespace Patched.Service.Tests;

public sealed class RetiredTrayCleanupTests
{
    private const string Tray = @"C:\Program Files\Patched\PatchedTray.exe";
    private const string UserSid = "S-1-5-21-1-2-3-1001";

    private sealed class Key : RetiredTrayCleanup.IRegistryKey
    {
        internal readonly Dictionary<string, Key> Children = new();
        internal (RegistryValueKind Kind, object? Value)? Value;
        internal Func<(RegistryValueKind Kind, object? Value)?>? Read;
        internal bool Deleted, Disposed;
        internal Exception? LinkCheckFailure;
        private bool _isLink;
        public bool IsLink { get => LinkCheckFailure is null ? _isLink : throw LinkCheckFailure; set => _isLink = value; }
        internal readonly Dictionary<string, Exception> OpenFailures = new();
        internal readonly List<string> Opened = [];
        public RetiredTrayCleanup.IRegistryKey? OpenChild(string name, bool writable)
        {
            Opened.Add(name);
            return OpenFailures.TryGetValue(name, out var failure) ? throw failure : Children.GetValueOrDefault(name);
        }
        public string[] GetSubKeyNames() => Children.Keys.ToArray();
        public (RegistryValueKind Kind, object? Value)? ReadRunValue() => Read is null ? Value : Read();
        public void DeleteRunValue() { Deleted = true; Value = null; }
        public void Dispose() => Disposed = true;
    }

    private sealed class Process(string imagePath) : RetiredTrayCleanup.ITrayProcess
    {
        internal bool Terminated, Disposed;
        internal bool RefuseQuery;
        public string ImagePath => RefuseQuery ? throw new IOException("unavailable") : imagePath;
        public void Terminate() => Terminated = true;
        public void Dispose() => Disposed = true;
    }

    private sealed class Lease : IDisposable
    {
        internal bool Disposed;
        public void Dispose() => Disposed = true;
    }

    private static Key AddRun(Key root, string hive = UserSid, object? value = null,
        RegistryValueKind kind = RegistryValueKind.String)
    {
        var current = root;
        foreach (var name in new[] { hive, "Software", "Microsoft", "Windows", "CurrentVersion", "Run" })
        {
            var next = new Key();
            current.Children.Add(name, next);
            current = next;
        }
        current.Value = (kind, value ?? Tray);
        return current;
    }

    private static bool Run(Key root, params Process[] processes) => RetiredTrayCleanup.RunPass(
        NullLogger.Instance, Tray, () => new Lease(), root, () => processes);

    [Theory]
    [InlineData(Tray)]
    [InlineData("\"" + Tray + "\"")]
    [InlineData(@"c:\program files\patched\patchedtray.exe")]
    public void RemovesOnlyOurExactStartupValueAndStopsOnlyOurImage(string value)
    {
        var root = new Key();
        var run = AddRun(root, value: value);
        var own = new Process(Tray);
        var foreign = new Process(@"C:\Users\Someone\PatchedTray.exe");
        Assert.True(Run(root, own, foreign));
        Assert.True(run.Deleted);
        Assert.True(own.Terminated);
        Assert.False(foreign.Terminated);
        Assert.True(own.Disposed && foreign.Disposed && run.Disposed);
    }

    [Theory]
    [InlineData(@"C:\Users\Someone\PatchedTray.exe", RegistryValueKind.String)]
    [InlineData(Tray + " --anything", RegistryValueKind.String)]
    [InlineData("\"" + Tray + "\" --anything", RegistryValueKind.String)]
    [InlineData(" \"" + Tray + "\"", RegistryValueKind.String)]
    [InlineData(Tray + "\n", RegistryValueKind.String)]
    [InlineData(@"%ProgramFiles%\Patched\PatchedTray.exe", RegistryValueKind.ExpandString)]
    [InlineData(Tray, RegistryValueKind.ExpandString)]
    [InlineData(Tray, RegistryValueKind.MultiString)]
    public void ForeignOrModifiedStartupValueIsUntouched(string value, RegistryValueKind kind)
    {
        var root = new Key();
        var run = AddRun(root, value: value, kind: kind);
        Assert.True(Run(root));
        Assert.False(run.Deleted);
    }

    [Fact]
    public void ValueReplacedDuringReadIsNotDeleted()
    {
        var root = new Key();
        var run = AddRun(root);
        var reads = 0;
        run.Read = () => (RegistryValueKind.String, ++reads == 1 ? Tray : @"C:\another.exe");
        Assert.True(Run(root));
        Assert.False(run.Deleted);
    }

    // The hive root itself is the PAT-2416 alias case, covered separately below.
    [Theory]
    [InlineData("Software")]
    [InlineData("Microsoft")]
    [InlineData("Windows")]
    [InlineData("CurrentVersion")]
    [InlineData("Run")]
    public void LinkAtAnyComponentRefusesMutationAndDisposesTheOpenedLink(string link)
    {
        var root = new Key();
        var run = AddRun(root);
        var node = root;
        foreach (var name in new[] { UserSid, "Software", "Microsoft", "Windows", "CurrentVersion", "Run" })
        {
            node = node.Children[name];
            if (name == link) break;
        }
        node.IsLink = true;
        Assert.False(Run(root));
        Assert.False(run.Deleted);
        Assert.True(node.Disposed);
    }

    [Theory]
    [InlineData(".DEFAULT")]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-19")]
    [InlineData("S-1-5-20")]
    public void PriorSystemContextMsiRunValueIsAlsoRemoved(string hive)
    {
        var root = new Key();
        var run = AddRun(root, hive);
        Assert.True(Run(root));
        Assert.True(run.Deleted);
    }

    // PAT-2416: on a real device HKU\S-1-5-18 is a registry link to HKU\.DEFAULT.
    // The alias is skipped (its target is walked under its own name), every real
    // hive in the selection is still cleaned, and a link below a hive root is
    // still refused.
    private const string EntraSid = "S-1-12-1-1111-2222-3333-4444";
    private const string Foreign = @"C:\Program Files\Other\PatchedTray.exe";

    private sealed class Device
    {
        internal readonly Key Root = new();
        internal readonly Key Alias = new() { IsLink = true };
        internal readonly Key Default, Local, Entra;
        internal Device(object? system = null, object? local = null, object? entra = null)
        {
            Root.Children.Add("S-1-5-18", Alias);
            Default = AddRun(Root, ".DEFAULT", system ?? Foreign);
            AddRun(Root, UserSid + "_Classes");
            Local = AddRun(Root, UserSid, local ?? Foreign);
            Entra = AddRun(Root, EntraSid, entra ?? Foreign);
        }
    }

    private sealed class Levels : ILogger
    {
        internal readonly List<(LogLevel Level, string Text)> Entries = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, formatter(state, exception)));
    }

    // Runs one pass against a store that already holds the reason, as the affected
    // device does, and returns whether the reason is still reported afterwards.
    private static (bool Complete, bool ReasonReported) PassWithRecordedReason(Key root, ILogger? log = null)
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        try
        {
            var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(dir, "agent-health.json"));
            health.RecordFailure("retired_component_cleanup", "windows_tray", "cleanup_incomplete");
            Assert.Single(health.BuildPayloadSection()!.Degraded);
            var complete = RetiredTrayCleanup.RunPass(log ?? NullLogger.Instance, Tray, () => new Lease(), root, () => []);
            RetiredTrayCleanup.RecordOutcome(NullLogger.Instance, health, complete);
            return (complete, health.BuildPayloadSection()!.Degraded.Any(d =>
                d.Kind == "retired_component_cleanup" && d.Subject == "windows_tray"));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void LocalSystemAliasLinkIsSkippedSoCleanHivesReportCompleteAndTheRecordedReasonClears()
    {
        var device = new Device();
        var log = new Levels();
        var (complete, reasonReported) = PassWithRecordedReason(device.Root, log);
        Assert.True(complete);
        Assert.False(reasonReported);
        Assert.True(device.Alias.Disposed);
        Assert.Empty(device.Alias.Opened); // Never followed or walked through the link.
        Assert.False(device.Default.Deleted || device.Local.Deleted || device.Entra.Deleted);
        Assert.DoesNotContain(log.Entries, e => e.Level >= LogLevel.Warning);
    }

    [Fact]
    public void AliasSkipIsNotLoggedAsAWarningOnAnyPass()
    {
        var log = new Levels();
        for (var pass = 0; pass < 3; pass++)
            Assert.True(RetiredTrayCleanup.RunPass(log, Tray, () => new Lease(), new Device().Root, () => []));
        Assert.DoesNotContain(log.Entries, e => e.Level >= LogLevel.Warning);
        Assert.True(log.Entries.Count(e => e.Level == LogLevel.Information && e.Text.Contains("S-1-5-18")) <= 1);
    }

    [Fact]
    public void SystemHiveHoldingOurRunValueIsCleanedUnderItsOwnNameBesideTheAlias()
    {
        var device = new Device(system: Tray);
        var (complete, reasonReported) = PassWithRecordedReason(device.Root);
        Assert.True(complete);
        Assert.False(reasonReported);
        Assert.True(device.Default.Deleted);
        Assert.False(device.Local.Deleted || device.Entra.Deleted);
    }

    [Fact]
    public void EntraAccountHiveHoldingOurRunValueIsCleanedBesideTheAlias()
    {
        var device = new Device(entra: Tray);
        var (complete, reasonReported) = PassWithRecordedReason(device.Root);
        Assert.True(complete);
        Assert.False(reasonReported);
        Assert.True(device.Entra.Deleted);
        Assert.False(device.Default.Deleted || device.Local.Deleted);
    }

    [Theory]
    [InlineData(".DEFAULT", typeof(IOException))]
    [InlineData(UserSid, typeof(UnauthorizedAccessException))]
    [InlineData(EntraSid, typeof(System.ComponentModel.Win32Exception))]
    public void HiveThatCannotBeOpenedIsStillIncompleteAndKeepsTheReason(string hive, Type failure)
    {
        var device = new Device(system: Tray, local: Tray, entra: Tray);
        device.Root.OpenFailures.Add(hive, (Exception)Activator.CreateInstance(failure)!);
        var (complete, reasonReported) = PassWithRecordedReason(device.Root);
        Assert.False(complete);
        Assert.True(reasonReported);
        // One refused hive does not stop the others.
        Assert.Equal(2, new[] { device.Default, device.Local, device.Entra }.Count(run => run.Deleted));
    }

    [Fact]
    public void HiveWhoseLinkCheckFailsIsIncompleteNotTreatedAsAnAlias()
    {
        var device = new Device(local: Tray);
        device.Root.Children[UserSid].LinkCheckFailure = new UnauthorizedAccessException();
        var (complete, reasonReported) = PassWithRecordedReason(device.Root);
        Assert.False(complete);
        Assert.True(reasonReported);
        Assert.False(device.Local.Deleted);
    }

    [Theory]
    [InlineData("Software")]
    [InlineData("Microsoft")]
    [InlineData("Windows")]
    [InlineData("CurrentVersion")]
    [InlineData("Run")]
    public void LinkBelowAHiveRootIsStillRefusedBesideTheAlias(string link)
    {
        var device = new Device(local: Tray);
        var node = device.Root.Children[UserSid];
        foreach (var name in new[] { "Software", "Microsoft", "Windows", "CurrentVersion", "Run" })
        {
            node = node.Children[name];
            if (name == link) break;
        }
        node.IsLink = true;
        var log = new Levels();
        var (complete, reasonReported) = PassWithRecordedReason(device.Root, log);
        Assert.False(complete);
        Assert.True(reasonReported);
        Assert.False(device.Local.Deleted);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Text.Contains(UserSid));
    }

    [Theory]
    [InlineData(".DEFAULT")]
    [InlineData(UserSid)]
    [InlineData(EntraSid)]
    public void TopLevelLinkIsNeverEditedOrWalkedEvenWhenItAppearsToHoldOurValue(string hive)
    {
        // A fake link that would expose our value if it were followed.
        var root = new Key();
        var run = AddRun(root, hive);
        root.Children[hive].IsLink = true;
        Assert.True(Run(root));
        Assert.False(run.Deleted);
        Assert.Empty(root.Children[hive].Opened);
        Assert.True(root.Children[hive].Disposed);
    }

    [Theory]
    [InlineData("Software")]
    [InlineData("CurrentVersion")]
    [InlineData("Run")]
    public void HiveWithAMissingRunKeyIsClean(string missing)
    {
        var device = new Device();
        var node = device.Root.Children[UserSid];
        foreach (var name in new[] { "Software", "Microsoft", "Windows", "CurrentVersion", "Run" })
        {
            if (name == missing) { node.Children.Remove(name); break; }
            node = node.Children[name];
        }
        var (complete, reasonReported) = PassWithRecordedReason(device.Root);
        Assert.True(complete);
        Assert.False(reasonReported);
    }

    [Fact]
    public void ForeignRunValuesAreLeftUntouchedInEveryHiveBesideTheAlias()
    {
        var device = new Device();
        var (complete, _) = PassWithRecordedReason(device.Root);
        Assert.True(complete);
        Assert.All(new[] { device.Default, device.Local, device.Entra }, run =>
        {
            Assert.False(run.Deleted);
            Assert.Equal((RegistryValueKind.String, (object?)Foreign), run.Value);
        });
    }

    [Fact]
    public void UntrustedInstallCausesNoRegistryOrProcessMutation()
    {
        var root = new Key();
        var run = AddRun(root);
        var process = new Process(Tray);
        Assert.Throws<IOException>(() => RetiredTrayCleanup.RunPass(NullLogger.Instance, Tray,
            () => throw new IOException("install_directory_untrusted"), root, () => [process]));
        Assert.False(run.Deleted);
        Assert.False(process.Terminated);
    }

    [Fact]
    public void FailedImageQueryNeverTerminatesAndDoesNotPreventTheNextProcess()
    {
        var refused = new Process(Tray) { RefuseQuery = true };
        var own = new Process(Tray);
        Assert.False(Run(new Key(), refused, own));
        Assert.False(refused.Terminated);
        Assert.True(own.Terminated);
        Assert.True(refused.Disposed && own.Disposed);
    }

    [Fact]
    public void HiveAndProcessWorkIsCappedAndReportsIncomplete()
    {
        var root = new Key();
        var runs = Enumerable.Range(1, RetiredTrayCleanup.PassLimit + 1)
            .Select(i => AddRun(root, $"S-1-5-21-1-2-3-{i}")).ToArray();
        var processes = Enumerable.Range(0, RetiredTrayCleanup.PassLimit + 1).Select(_ => new Process(Tray)).ToArray();
        Assert.False(Run(root, processes));
        Assert.Equal(RetiredTrayCleanup.PassLimit, runs.Count(r => r.Deleted));
        Assert.Equal(RetiredTrayCleanup.PassLimit, processes.Count(p => p.Terminated));
        Assert.All(processes, p => Assert.True(p.Disposed));
    }

    [Fact]
    public void InstallationLockIsHeldUntilBothKindsOfCleanupFinishAndThenDisposed()
    {
        var lease = new Lease();
        var root = new Key();
        var run = AddRun(root);
        run.Read = () => { Assert.False(lease.Disposed); return run.Value; };
        Assert.True(RetiredTrayCleanup.RunPass(NullLogger.Instance, Tray, () => lease, root,
            () => { Assert.False(lease.Disposed); return []; }));
        Assert.True(lease.Disposed);
    }

    [Fact]
    public async Task StartsOnceThenWaitsFifteenMinutesAndCancelsWithoutAnotherPass()
    {
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var passes = 0;
        using var service = new RetiredTrayCleanup(() => Interlocked.Increment(ref passes), async (interval, token) =>
        {
            Assert.Equal(TimeSpan.FromMinutes(15), interval);
            waiting.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
        });
        await service.StartAsync(CancellationToken.None);
        await waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);
        Assert.Equal(1, passes);
    }

    [WindowsFact]
    public void NativeRegistryAdapterRemovesOnlyTheNamedValueInAnIsolatedFixture()
    {
        var fixture = @"Software\PatchedTests\" + Guid.NewGuid().ToString("N");
        try
        {
            using var root = Registry.CurrentUser.CreateSubKey(fixture);
            using var run = root.CreateSubKey(UserSid + @"\Software\Microsoft\Windows\CurrentVersion\Run");
            run.SetValue("PatchedTray", Tray, RegistryValueKind.String);
            run.SetValue("OtherApp", "keep", RegistryValueKind.String);
            using var adapter = new RetiredTrayCleanup.NativeRegistryKey(Registry.CurrentUser.OpenSubKey(fixture, true)!);
            Assert.True(RetiredTrayCleanup.RunPass(NullLogger.Instance, Tray, () => new Lease(), adapter, () => []));
            Assert.Null(run.GetValue("PatchedTray"));
            Assert.Equal("keep", run.GetValue("OtherApp"));
        }
        finally { Registry.CurrentUser.DeleteSubKeyTree(fixture, false); }
    }

    [WindowsFact]
    public void NativeRegistryLinkIsRefusedWithoutChangingItsTarget()
    {
        var fixture = @"Software\PatchedTests\" + Guid.NewGuid().ToString("N");
        const string targetPath = @"target\Microsoft\Windows\CurrentVersion\Run";
        SafeRegistryHandle? link = null;
        var targetReady = false;
        var failures = new List<Exception>();
        void CaptureFailure(Action action)
        {
            var failure = Record.Exception(action);
            if (failure is not null) failures.Add(failure);
        }

        CaptureFailure(() =>
        {
            using var root = Registry.CurrentUser.CreateSubKey(fixture);
            using var hive = root.CreateSubKey(UserSid);
            using var target = root.CreateSubKey(targetPath);
            target.SetValue("PatchedTray", Tray, RegistryValueKind.String);
            targetReady = true;
            // Keep the CREATE_LINK source handle (KEY_ALL_ACCESS includes DELETE).
            // A later name-based delete cannot safely remove a registry link.
            Assert.Equal(0, RegCreateKeyEx(hive.Handle, "Software", 0, null, 2 /* CREATE_LINK */,
                0xF003F, IntPtr.Zero, out link, out _));
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User!.Value;
            var destination = Encoding.Unicode.GetBytes($@"\Registry\User\{sid}\{fixture}\target");
            Assert.Equal(0, RegSetValueEx(link, "SymbolicLinkValue", 0, 6 /* REG_LINK */, destination, destination.Length));
            // Prove this is a working native link, not merely an inert REG_LINK value.
            using (var followed = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                Assert.Equal(Tray, followed?.GetValue("PatchedTray"));
            using var adapter = new RetiredTrayCleanup.NativeRegistryKey(Registry.CurrentUser.OpenSubKey(fixture, true)!);
            Assert.False(RetiredTrayCleanup.RunPass(NullLogger.Instance, Tray, () => new Lease(), adapter, () => []));
            Assert.Equal(Tray, target.GetValue("PatchedTray"));
        });

        var unlinkFailure = Record.Exception(() =>
        {
            using (link)
            {
                if (link is { IsInvalid: false })
                {
                    // Delete exactly the retained source object, without resolving its target.
                    // RegDeleteKeyEx rejects link sources; recursive deletion can follow them.
                    var status = NtDeleteKey(link);
                    Assert.True(status == 0, $"NtDeleteKey({fixture}\\{UserSid}\\Software): NTSTATUS 0x{status:X8}");
                }
            }
        });
        if (unlinkFailure is not null) failures.Add(unlinkFailure);
        else
        {
            // Check the target again after unlinking, before deleting our ordinary fixture keys.
            if (targetReady) CaptureFailure(() =>
            {
                using var target = Registry.CurrentUser.OpenSubKey(fixture + "\\" + targetPath);
                Assert.NotNull(target);
                Assert.Equal(RegistryValueKind.String, target.GetValueKind("PatchedTray"));
                Assert.Equal(Tray, target.GetValue("PatchedTray"));
            });
            CaptureFailure(() =>
            {
                using (var hive = Registry.CurrentUser.OpenSubKey(fixture + "\\" + UserSid))
                    if (hive is not null) Assert.DoesNotContain("Software", hive.GetSubKeyNames());
                Registry.CurrentUser.DeleteSubKeyTree(fixture, false);
                using var remaining = Registry.CurrentUser.OpenSubKey(fixture);
                Assert.Null(remaining);
            });
        }
        // A teardown failure must never replace the security assertion that failed first.
        // If unlinking failed, leave this GUID fixture intact rather than recurse through a link.
        if (failures.Count == 1) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException($"Registry link fixture failed: HKCU\\{fixture}", failures);
    }

    [WindowsFact]
    public void NativeProcessHandleRefusesAnotherImageAndTerminatesTheIdentifiedChild()
    {
        var helper = Path.Combine(AppContext.BaseDirectory, "SpinForeverHelper", "SpinForeverHelper.exe");
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(helper)
        {
            UseShellExecute = false, CreateNoWindow = true,
        })!;
        try
        {
            Assert.True(RetiredTrayCleanup.RunPass(NullLogger.Instance, Tray, () => new Lease(), new Key(),
                () => [new RetiredTrayCleanup.NativeTrayProcess(child.Id)]));
            Assert.False(child.HasExited);
            Assert.True(RetiredTrayCleanup.RunPass(NullLogger.Instance, helper, () => new Lease(), new Key(),
                () => [new RetiredTrayCleanup.NativeTrayProcess(child.Id)]));
            Assert.True(child.WaitForExit(5000));
            Assert.Equal(0, child.ExitCode); // Native cleanup's TerminateProcess exit code.
        }
        finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); } }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = "Requires real Windows registry/process APIs";
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegCreateKeyEx(SafeRegistryHandle key, string subKey, int reserved, string? keyClass,
        int options, int access, IntPtr security, out SafeRegistryHandle result, out int disposition);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegSetValueEx(SafeRegistryHandle key, string name, int reserved, int type, byte[] data, int size);
    [DllImport("ntdll.dll")]
    private static extern int NtDeleteKey(SafeRegistryHandle key);
}
