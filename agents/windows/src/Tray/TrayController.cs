using System.IO;
using System.Windows.Forms;
using System.Windows.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Contract;
using Patched.Shared.Interruption;
using Patched.Shared.Paths;
using Patched.Shared.Posture;
using Patched.Shared.Removal;
using Patched.Shared.Tray;
using Application = System.Windows.Application;

namespace Patched.Tray;

/// <summary>
/// Manages the system tray icon (WinForms NotifyIcon) and the status/deploy window (WPF).
/// Unprivileged: only reads update-status.json and drops trigger files.
/// Icon variants: up_to_date (green), updates_available (amber), error/verificationFailed (red).
///
/// PAT-478 / U4: left-click opens FlyoutWindow (the glanceable posture flyout);
/// double-click and context-menu "Open Patched" open the full StatusWindow.
/// PostureReader reads the Service's last-known-good posture.json cache.
/// </summary>
public sealed class TrayController : IDisposable
{
    private readonly Application  _app;
    private readonly StatusReader _statusReader;
    private readonly TriggerWriter _triggerWriter;
    private readonly PostureReader _postureReader = new();
    private NotifyIcon?           _notifyIcon;
    private StatusWindow?                   _statusWindow;
    private FlyoutWindow?                   _flyoutWindow;
    private DispatcherTimer?                _postureTimer;

    // PAT-1623: removal notify/defer surface. See RemovalPromptEvaluator's own
    // header comment for what this does and does not do — it decides
    // whether to present, it does not detect or retry removal itself.
    private readonly UninstallStatusReader _uninstallStatusReader;
    private readonly RemovalPromptEvaluator _removalPromptEvaluator;
    private RemovalPromptWindow? _removalPromptWindow;
    private DispatcherTimer? _removalRetryTimer;

    // PAT-1661: same seam PromptPresentationGovernor already uses for its own
    // structured events (IInterruptionEventSink). Defaults to the same
    // no-op used everywhere else in this file when nothing is injected, so
    // production behaviour is unchanged unless a real sink is wired in; a
    // test can pass its own to assert on a defer marker write failure.
    private readonly IInterruptionEventSink _events;

    public TrayController(Application app, IInterruptionEventSink? events = null)
    {
        _app           = app;
        // Tray errors surface directly in the UI; NullLogger avoids a
        // PackageReference that the wpftmp shadow project cannot inherit. (PAT-353)
        _statusReader  = new StatusReader(NullLogger<StatusReader>.Instance);
        _triggerWriter = new TriggerWriter(NullLogger<TriggerWriter>.Instance);
        _uninstallStatusReader = new UninstallStatusReader(NullLogger<UninstallStatusReader>.Instance);
        _events        = events ?? NullInterruptionEventSink.Instance;
        _removalPromptEvaluator = new RemovalPromptEvaluator(
            new PromptPresentationGovernor(
                RemovalPromptEvaluator.Surface,
                new InterruptionGate(new WindowsInterruptionSignals()),
                retryInterval: TimeSpan.FromHours(2)));
    }

    public void Initialize()
    {
        _notifyIcon = new NotifyIcon
        {
            Text    = "Patched",
            Visible = true,
            Icon    = LoadIcon("tray-icon.ico"),
        };
        // Left-click: toggle the glanceable flyout (U4).
        // Double-click / context "Open Patched": full StatusWindow.
        _notifyIcon.Click       += (_, e) =>
        {
            if (e is MouseEventArgs me && me.Button == MouseButtons.Left)
                ToggleFlyout();
        };
        _notifyIcon.DoubleClick += (_, _) => ShowStatusWindow();
        _notifyIcon.ContextMenuStrip = BuildContextMenu();

        _statusReader.StatusChanged += OnStatusChanged;
        _statusReader.Start();

        // U4: drive the tray icon + tooltip from the posture cache (glanceable
        // summary), refreshed on a light poll.
        RefreshPostureFlyout();
        _postureTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _postureTimer.Tick += (_, _) => RefreshPostureFlyout();
        _postureTimer.Start();

        // PAT-1623: removal notify/defer surface.
        _uninstallStatusReader.StatusChanged += OnUninstallStatusChanged;
        _uninstallStatusReader.Start();
        // Same 2-hour cadence as the governor's own retry interval, so a
        // suppressed attempt (never-interrupt gate) gets retried and an
        // already-shown prompt is not re-attempted every tick — mirroring
        // StatusStore.scheduleBlockingPromptTimer on macOS.
        _removalRetryTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(2) };
        _removalRetryTimer.Tick += (_, _) => AttemptRemovalPrompt();
        _removalRetryTimer.Start();
    }

    /// <summary>
    /// PAT-1623. Fired on every uninstall-status.json change; also gates on
    /// the live tier from the posture cache before deciding whether this is
    /// even a fresh attempt opportunity — "Managed tier only, fail closed."
    /// </summary>
    private void OnUninstallStatusChanged(object? sender, UninstallStatus? status)
    {
        var tier = _postureReader.Read().Posture?.Tier;
        _removalPromptEvaluator.ApplyTier(tier);
        var isFreshAttempt = _removalPromptEvaluator.ApplyStatus(status);
        if (isFreshAttempt) AttemptRemovalPrompt();
    }

    /// <summary>
    /// The one call site every removal notify/defer prompt goes through.
    /// PAT-1623 "queue, do not stack": removal never presents while the
    /// OS-update blocking prompt currently wants the screen. Windows has no
    /// shipped OS-update blocking-prompt surface yet (no call site exists —
    /// see docs/never-interrupt-gate.md's table), so there is nothing to
    /// arbitrate against today; this parameter is wired to `false` now and
    /// is exactly the seam a future OS-update prompt would flip, without
    /// touching RemovalPromptEvaluator itself (see this ticket's report for
    /// the full explanation).
    /// </summary>
    private void AttemptRemovalPrompt()
    {
        var session = new WindowsUserSessionState();
        var outcome = _removalPromptEvaluator.Evaluate(
            DateTimeOffset.UtcNow, session.IsActiveAndUnlocked, shouldShowOsUpdatePrompt: false);

        if (outcome.Kind != PromptOutcomeKind.Present) return;
        if (_removalPromptEvaluator.Pending is not { } pending) return;
        if (_removalPromptWindow is { IsVisible: true }) return;

        _removalPromptWindow = new RemovalPromptWindow(pending, onDefer: () =>
        {
            // PAT-1661: a failed marker write loses the daemon's only audit
            // evidence that the user was asked to defer, so it is logged.
            // This does not change the dismiss below: RecordDefer() still
            // runs unconditionally on both success and failure, exactly as
            // before.
            var writeError = _triggerWriter.RequestRemovalDefer(pending.EntryId, pending.Name);
            if (writeError is not null)
            {
                _events.Record("error", "removal_defer marker write failed", new Dictionary<string, object>
                {
                    ["error"]    = writeError,
                    ["entry_id"] = pending.EntryId,
                    ["name"]     = pending.Name,
                });
            }
            _removalPromptEvaluator.RecordDefer();
        });
        _removalPromptWindow.Closed += (_, _) => _removalPromptWindow = null;
        _removalPromptWindow.Show();
    }

    /// <summary>Build the glanceable flyout from posture and reflect it on the tray icon.</summary>
    private void RefreshPostureFlyout()
    {
        if (_notifyIcon is null) return;
        TrayFlyoutVm vm;
        try { vm = TrayFlyoutPresenter.Build(_postureReader.Read(), DateTimeOffset.UtcNow); }
        catch { return; }

        // No posture cache yet → leave the status-driven icon/tooltip in place.
        if (vm.IconState == TrayIconState.Unknown) return;

        _notifyIcon.Icon = vm.IconState switch
        {
            TrayIconState.Attention        => LoadIcon("tray-icon-error.ico"),
            TrayIconState.UpdatesAvailable => LoadIcon("tray-icon-update.ico"),
            _                              => LoadIcon("tray-icon.ico"),
        };
        // NotifyIcon.Text is capped at 127 chars.
        var text = $"Patched — {vm.Headline}\n{vm.DetailLine}";
        _notifyIcon.Text = text.Length > 127 ? text[..127] : text;
    }

    /// <summary>
    /// Toggle the glanceable flyout (U4). Opens when closed; closes when open.
    /// Constructs a fresh FlyoutWindow on each open so it always reflects the
    /// latest posture snapshot.
    /// </summary>
    private void ToggleFlyout()
    {
        if (_flyoutWindow is { IsVisible: true })
        {
            _flyoutWindow.Close();
            _flyoutWindow = null;
            return;
        }

        var snapshot = _postureReader.Read();
        var vm = TrayFlyoutPresenter.Build(snapshot, DateTimeOffset.UtcNow);
        _flyoutWindow = new FlyoutWindow(vm, snapshot.Posture,
            () => _triggerWriter.RequestScan("flyout"));
        _flyoutWindow.Closed += (_, _) => _flyoutWindow = null;
        _flyoutWindow.Show();
    }

    private void OnStatusChanged(object? sender, UpdateStatus? status)
    {
        if (_notifyIcon is null) return;

        _notifyIcon.Icon = status?.OverallState switch
        {
            OverallState.UpdatesAvailable => LoadIcon("tray-icon-update.ico"),
            OverallState.Error            => LoadIcon("tray-icon-error.ico"),
            _                             => LoadIcon("tray-icon.ico"),
        };

        _notifyIcon.Text = status?.OverallState switch
        {
            OverallState.UpToDate         => "Patched — All apps up to date",
            OverallState.UpdatesAvailable => $"Patched — {status.Counts?.UpdatesAvailable} update(s) available",
            OverallState.Updating         => "Patched — Updating…",
            OverallState.Error            => "Patched — Error",
            _                             => "Patched",
        };

        // Refresh the open window if it's showing.
        _statusWindow?.UpdateStatus(status);

        // Let posture (the richer source) drive the icon/tooltip when a cache exists.
        RefreshPostureFlyout();
    }

    private void ShowStatusWindow()
    {
        if (_statusWindow is null || !_statusWindow.IsVisible)
        {
            _statusWindow = new StatusWindow(_statusReader);
            _statusWindow.Show();
        }
        else
        {
            _statusWindow.Activate();
        }
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Patched",   null, (_, _) => ShowStatusWindow());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) =>
        {
            _notifyIcon!.Visible = false;
            _app.Shutdown();
        });
        return menu;
    }

    private static System.Drawing.Icon LoadIcon(string filename)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Resources", filename);
        return File.Exists(path)
            ? new System.Drawing.Icon(path)
            : SystemIcons.Application;
    }

    public void Dispose()
    {
        _postureTimer?.Stop();
        _removalRetryTimer?.Stop();
        _notifyIcon?.Dispose();
        _statusReader.Dispose();
        _uninstallStatusReader.Dispose();
    }
}
