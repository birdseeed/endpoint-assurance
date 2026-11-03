using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Patched.Shared.Posture;
using Patched.Shared.Tray;
using Application       = System.Windows.Application;
using Button            = System.Windows.Controls.Button;
using Color             = System.Windows.Media.Color;
using Colors            = System.Windows.Media.Colors;
using FontFamily        = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation       = System.Windows.Controls.Orientation;
using Rectangle         = System.Windows.Shapes.Rectangle;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace Patched.Tray;

/// <summary>
/// Glanceable tray flyout (PAT-478 / U4).
///
/// A borderless WPF window that positions itself above the system tray and
/// renders one of five posture states drawn from <see cref="TrayFlyoutVm"/>:
///   Secure · Updates · Attention · Waiting · Offline
///
/// Design reference: windows/design/agent/PatchedTrayAgent.cs
/// Non-negotiables (binding from CLAUDE.md):
///   • Segoe UI Variable Text system font — not bundled fonts.
///   • Signal orange #F5530A — one accent, ≤ ~2% of surface.
///   • Canonical Patched ring mark in the header.
///   • Header text: "Patched" (word-only; mark beside it).
///   • No remote control — assurance only, read-only surface.
///   • Honest tier gating from posture.tier.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class FlyoutWindow : Window
{
    // ── DWM Mica backdrop ────────────────────────────────────────────────────

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint hwnd, int attr, ref int value, int size);

    private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;
    private const int DWMSBT_MAINWINDOW         = 2;   // Mica

    // ── Brand constants ──────────────────────────────────────────────────────

    private static readonly Color SignalOrange = Color.FromArgb(255, 0xF5, 0x53, 0x0A);
    private static readonly Color Slate        = Color.FromArgb(255, 0x1B, 0x1B, 0x1B);
    private static readonly Color Graphite     = Color.FromArgb(255, 0x38, 0x38, 0x38);
    private static readonly Color Mute         = Color.FromArgb(255, 0x6A, 0x6A, 0x6A);
    private static readonly Color SecureGreen  = Color.FromArgb(255, 0x1A, 0x8A, 0x4E);
    private static readonly Color CriticalRed  = Color.FromArgb(255, 0xD1, 0x34, 0x38);
    private static readonly Color IdleGray     = Color.FromArgb(255, 0x8A, 0x8D, 0x94);

    private static readonly FontFamily SysFont  = new("Segoe UI Variable Text, Segoe UI, sans-serif");
    private static readonly FontFamily MonoFont = new("Cascadia Mono, Consolas, monospace");

    // ── State ────────────────────────────────────────────────────────────────

    private readonly TrayFlyoutVm _vm;
    private readonly Posture?     _posture;
    private readonly Action       _onScanNow;

    /// <param name="vm">View-model from TrayFlyoutPresenter.Build().</param>
    /// <param name="posture">Raw posture for update/finding detail rows (may be null).</param>
    /// <param name="onScanNow">Callback that writes a scan trigger via the service.</param>
    public FlyoutWindow(TrayFlyoutVm vm, Posture? posture, Action onScanNow)
    {
        _vm              = vm;
        _posture         = posture;
        _onScanNow       = onScanNow;
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplyMicaBackdrop();
        FlyoutHost.Content = BuildFlyout();
        PositionAboveTray();
    }

    // ── DWM Mica ─────────────────────────────────────────────────────────────

    private void ApplyMicaBackdrop()
    {
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            int value = DWMSBT_MAINWINDOW;
            DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref value, sizeof(int));
        }
        catch { /* Non-fatal — Mica requires Win11 22H2+; falls back to SurfaceBrush. */ }
    }

    // ── Tray positioning ─────────────────────────────────────────────────────

    private void PositionAboveTray()
    {
        UpdateLayout();   // force measure so ActualHeight is populated
        var area = SystemParameters.WorkArea;
        const double gap = 8;
        Left = area.Right  - ActualWidth  - gap;
        Top  = area.Bottom - ActualHeight - gap;
    }

    // Auto-dismiss when focus leaves (matches native tray flyout behaviour).
    private void Window_Deactivated(object sender, EventArgs e) => Close();

    // ── State router ─────────────────────────────────────────────────────────

    private UIElement BuildFlyout() => _vm.IconState switch
    {
        TrayIconState.Ok               => SecureView(),
        TrayIconState.UpdatesAvailable => UpdatesView(),
        TrayIconState.Attention        => AttentionView(),
        _                              => _vm.IsStale ? OfflineView() : WaitingView(),
    };

    // ── 1 · Secure ───────────────────────────────────────────────────────────

    private UIElement SecureView()
    {
        var stack = VStack();
        Add(stack, Header());
        Add(stack, StatusLine(Dot(SecureGreen), "Protected", _vm.DetailLine), top: 0);
        Add(stack, EvidenceLine(_vm.DetailLine, SecureGreen), top: 4);
        Add(stack, TierNote(_vm.TierLine), top: 2);
        Add(stack, Divider(), top: 0);
        Add(stack, MenuRow("Scan now", () => _onScanNow()),                   top: 0);
        Add(stack, MenuRow("Quit",     () => Application.Current.Shutdown()), top: 0);
        return stack;
    }

    // ── 2 · Updates available ─────────────────────────────────────────────────

    private UIElement UpdatesView()
    {
        var stack = VStack();
        Add(stack, Header());
        Add(stack, StatusLine(Dot(SignalOrange),
            $"{_vm.UpdateCount} update{(_vm.UpdateCount == 1 ? "" : "s")} ready",
            "Recommended — you choose when to install"), top: 0);
        Add(stack, Divider(), top: 10);

        var updates  = _posture?.Updates  ?? [];
        var findings = _posture?.Findings ?? [];
        foreach (var u in updates.Take(3))
        {
            var cve = findings.FirstOrDefault(f => f.AppName == u.AppName);
            Add(stack, UpdateRow(u.AppName, u.CurrentVersion, u.TargetVersion,
                cve?.CveId, u.Source), top: 9);
        }
        if (updates.Count > 3)
            Add(stack, MoreRow(updates.Count - 3), top: 8);

        Add(stack, Note("Nothing installs without your approval."), top: 12);

        var buttons = HStack();
        var later = MakeNeutralBtn("Later");
        later.Click += (_, _) => Close();
        buttons.Children.Add(later);
        Add(stack, buttons, top: 14);
        return stack;
    }

    // ── 3 · Attention (critical findings / drift) ─────────────────────────────

    private UIElement AttentionView()
    {
        var stack = VStack();
        Add(stack, Header());
        Add(stack, StatusLine(Dot(CriticalRed), "Needs attention",
            $"{_vm.AttentionCount} issue{(_vm.AttentionCount == 1 ? "" : "s")} found on this device"), top: 0);
        Add(stack, Divider(), top: 10);

        var critical = (_posture?.Findings ?? [])
            .Where(f => f.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase)
                     || f.Severity.Equals("HIGH",     StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault();
        if (critical is not null)
        {
            Add(stack, FindingCard(
                critical.CveId,
                $"{critical.AppName} {critical.AppVersion}",
                critical.Description,
                $"CVSS {critical.CvssV3Score:F1} · {critical.Severity}",
                CriticalRed), top: 10);
        }

        var drift = _posture?.AppPolicy?.Drift ?? [];
        if (drift.Count > 0)
        {
            var driftText = drift[0].DriftType == "unapproved_present"
                ? $"{drift[0].AppName} is not approved"
                : $"{drift[0].AppName} is required but missing";
            Add(stack, FindingCard("Policy drift", driftText,
                drift.Count > 1 ? $"+ {drift.Count - 1} more" : "",
                "App policy", IdleGray), top: 10);
        }

        Add(stack, Note("Patched guides the fix. Nothing is forced — you stay in control."), top: 12);

        return stack;
    }

    // ── 4 · Waiting for service (no cache) ───────────────────────────────────

    private UIElement WaitingView()
    {
        var stack = VStack();
        Add(stack, Header());
        Add(stack, StatusLine(Dot(IdleGray),
            "Waiting for Patched service",
            "No scan recorded yet on this device"), top: 0);
        Add(stack, Note("The background service is starting up. Check back in a moment."), top: 12);
        return stack;
    }

    // ── 5 · Offline / stale ───────────────────────────────────────────────────

    private UIElement OfflineView()
    {
        var stack = VStack();
        Add(stack, Header());
        Add(stack, StatusLine(Dot(IdleGray),
            "Can't reach Patched",
            $"Last scan: {_vm.DetailLine}"), top: 0);
        Add(stack, Note("Your protection status may be out of date. Check your connection and try again."), top: 12);
        if (_vm.DetailLine.Length > 0)
            Add(stack, EvidenceLine($"Showing last known result · {_vm.DetailLine}", Mute), top: 4);

        var buttons = HStack();
        var retry   = MakeNeutralBtn("Retry now");
        retry.Click += (_, _) => Close();   // re-opening will re-read the cache
        buttons.Children.Add(retry);
        Add(stack, buttons, top: 14);
        return stack;
    }

    // ── Shared header ─────────────────────────────────────────────────────────

    private static UIElement Header()
    {
        var row = HStack();
        row.Margin = new Thickness(0, 0, 0, 13);
        row.Children.Add(new System.Windows.Controls.Image
        {
            Source = new BitmapImage(new Uri(
                "pack://application:,,,/Resources/patched-ring-mark-slate.png",
                UriKind.Absolute)),
            Width = 22,
            Height = 22,
            Stretch = Stretch.Uniform,
            VerticalAlignment = VerticalAlignment.Center,
        });
        var word = new TextBlock
        {
            Text              = "Patched",
            FontFamily        = SysFont,
            FontSize          = 15,
            FontWeight        = FontWeights.SemiBold,
            Foreground        = Solid(Slate),
            VerticalAlignment = VerticalAlignment.Center,
            Margin            = new Thickness(9, 0, 0, 0),
        };
        row.Children.Add(word);
        return row;
    }

    // ── Building blocks ───────────────────────────────────────────────────────

    private static UIElement StatusLine(UIElement indicator, string title, string sub)
    {
        var row = HStack();
        row.VerticalAlignment = VerticalAlignment.Top;
        row.Margin = new Thickness(0, 0, 0, 13);
        row.Children.Add(indicator);
        var col = VStack();
        col.Children.Add(new TextBlock
        {
            Text       = title,
            FontFamily = SysFont,
            FontSize   = 16,
            FontWeight = FontWeights.SemiBold,
            Foreground = Solid(Slate),
            Margin     = new Thickness(11, 0, 0, 0),
        });
        col.Children.Add(new TextBlock
        {
            Text         = sub,
            FontFamily   = SysFont,
            FontSize     = 12,
            Foreground   = Solid(Mute),
            Margin       = new Thickness(11, 3, 0, 0),
            TextWrapping = TextWrapping.Wrap,
        });
        row.Children.Add(col);
        return row;
    }

    private static Ellipse Dot(Color c) => new()
    {
        Width             = 9,
        Height            = 9,
        Fill              = Solid(c),
        Margin            = new Thickness(0, 5, 0, 0),
        VerticalAlignment = VerticalAlignment.Top,
    };

    private static UIElement EvidenceLine(string text, Color tint)
    {
        return new TextBlock
        {
            Text       = text,
            FontFamily = MonoFont,
            FontSize   = 11,
            Foreground = Solid(Graphite),
        };
    }

    private static UIElement TierNote(string tierLine) =>
        new TextBlock
        {
            Text         = tierLine,
            FontFamily   = MonoFont,
            FontSize     = 10.5,
            Foreground   = Solid(Mute),
            TextWrapping = TextWrapping.Wrap,
        };

    private static UIElement UpdateRow(string name, string from, string to,
                                       string? cveId, string source)
    {
        var row = HStack();
        row.VerticalAlignment = VerticalAlignment.Top;
        row.Children.Add(AppTile(name));
        var col = VStack();
        col.Margin = new Thickness(11, 0, 0, 0);
        col.Children.Add(new TextBlock
        {
            Text       = name,
            FontFamily = SysFont,
            FontSize   = 13,
            FontWeight = FontWeights.SemiBold,
            Foreground = Solid(Slate),
        });
        col.Children.Add(new TextBlock
        {
            Text       = $"{from} → {to}",
            FontFamily = MonoFont,
            FontSize   = 11,
            Foreground = Solid(Mute),
            Margin     = new Thickness(0, 2, 0, 0),
        });
        var chips = HStack();
        chips.Margin = new Thickness(0, 6, 0, 0);
        if (cveId is not null)
        {
            chips.Children.Add(Chip(cveId, Graphite, Color.FromArgb(20, 0, 0, 0)));
            AddH(chips, Chip($"Verified · {source}", SecureGreen, Color.FromArgb(26, 0x1A, 0x8A, 0x4E)), left: 6);
        }
        else
        {
            chips.Children.Add(Chip($"Verified · {source}", SecureGreen, Color.FromArgb(26, 0x1A, 0x8A, 0x4E)));
        }
        col.Children.Add(chips);
        row.Children.Add(col);
        return row;
    }

    private static UIElement MoreRow(int count) =>
        new TextBlock
        {
            Text       = $"+ {count} more",
            FontFamily = SysFont,
            FontSize   = 12,
            Foreground = Solid(Mute),
        };

    private static UIElement FindingCard(string badge, string title,
                                         string body, string meta, Color tint)
    {
        var bg   = Color.FromArgb(13, tint.R, tint.G, tint.B);
        var bord = Color.FromArgb(72, tint.R, tint.G, tint.B);
        var inner = VStack();

        var top = HStack();
        top.Children.Add(Chip(badge, Colors.White, tint));
        top.Children.Add(new TextBlock
        {
            Text       = title,
            FontFamily = SysFont,
            FontSize   = 13,
            FontWeight = FontWeights.SemiBold,
            Foreground = Solid(Slate),
            Margin     = new Thickness(8, 0, 0, 0),
        });
        inner.Children.Add(top);

        if (body.Length > 0)
            inner.Children.Add(new TextBlock
            {
                Text         = body,
                FontFamily   = SysFont,
                FontSize     = 12,
                Foreground   = Solid(Graphite),
                TextWrapping = TextWrapping.Wrap,
                Margin       = new Thickness(0, 7, 0, 0),
            });
        if (meta.Length > 0)
            inner.Children.Add(new TextBlock
            {
                Text       = meta,
                FontFamily = MonoFont,
                FontSize   = 10.5,
                Foreground = Solid(Mute),
                Margin     = new Thickness(0, 7, 0, 0),
            });

        return new Border
        {
            Padding         = new Thickness(12),
            CornerRadius    = new CornerRadius(6),
            Background      = Solid(bg),
            BorderThickness = new Thickness(1),
            BorderBrush     = Solid(bord),
            Child           = inner,
        };
    }

    private static Border AppTile(string name)
    {
        var tintColors = new[]
        {
            Color.FromArgb(255, 0x1A, 0x73, 0xE8),
            Color.FromArgb(255, 0x11, 0xA3, 0x6B),
            Color.FromArgb(255, 0x2B, 0x6C, 0xFF),
            Color.FromArgb(255, 0x6B, 0x47, 0xB8),
            Color.FromArgb(255, 0xCA, 0x50, 0x10),
        };
        var tint = tintColors[Math.Abs(name.GetHashCode()) % tintColors.Length];
        var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var initials = parts.Length >= 2
            ? $"{parts[0][0]}{parts[1][0]}"
            : name.Length > 0 ? name[..1] : "?";
        return new Border
        {
            Width        = 30,
            Height       = 30,
            CornerRadius = new CornerRadius(6),
            Background   = Solid(tint),
            Child = new TextBlock
            {
                Text                = initials.ToUpper(),
                Foreground          = Solid(Colors.White),
                FontWeight          = FontWeights.SemiBold,
                FontSize            = 13,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment   = VerticalAlignment.Center,
            },
        };
    }

    private static Border Chip(string text, Color fg, Color bg) => new()
    {
        Background      = Solid(bg),
        CornerRadius    = new CornerRadius(4),
        Padding         = new Thickness(6, 2, 6, 2),
        Child = new TextBlock
        {
            Text       = text,
            FontFamily = MonoFont,
            FontSize   = 10,
            Foreground = Solid(fg),
        },
    };

    private UIElement MenuRow(string label, Action onClick)
    {
        var row = HStack();
        row.Children.Add(new TextBlock
        {
            Text              = label,
            FontFamily        = SysFont,
            FontSize          = 13,
            Foreground        = Solid(Slate),
            VerticalAlignment = VerticalAlignment.Center,
        });
        var btn = new Button
        {
            Content                    = row,
            Style                      = (Style)FindResource("SubtleButton"),
            HorizontalAlignment        = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Height                     = 36,
        };
        btn.Click += (_, _) => onClick();
        return btn;
    }

    private static UIElement Note(string text) =>
        new TextBlock
        {
            Text         = text,
            FontFamily   = SysFont,
            FontSize     = 11.5,
            Foreground   = Solid(Mute),
            TextWrapping = TextWrapping.Wrap,
        };

    private static Border Divider() => new()
    {
        Height     = 1,
        Background = Solid(Color.FromArgb(26, 0, 0, 0)),
        Margin     = new Thickness(-14, 13, -14, 13),
    };

    // ── Buttons ───────────────────────────────────────────────────────────────

    private Button MakeNeutralBtn(string text)
    {
        var btn = new Button { Style = (Style)FindResource("NeutralButton") };
        btn.Content = text;
        return btn;
    }

    // ── Layout helpers ────────────────────────────────────────────────────────

    /// <summary>Vertical StackPanel (WPF — no Spacing property; use Margin on children).</summary>
    private static StackPanel VStack() => new() { Orientation = Orientation.Vertical };

    /// <summary>Horizontal StackPanel with vertical centering.</summary>
    private static StackPanel HStack() =>
        new() { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

    /// <summary>Add a child to a vertical StackPanel with top margin.</summary>
    private static void Add(StackPanel parent, UIElement child, double top = 0)
    {
        if (child is FrameworkElement fe && top > 0)
            fe.Margin = new Thickness(fe.Margin.Left, top, fe.Margin.Right, fe.Margin.Bottom);
        parent.Children.Add(child);
    }

    /// <summary>Add a child to a horizontal StackPanel with left margin.</summary>
    private static void AddH(StackPanel parent, UIElement child, double left = 0)
    {
        if (child is FrameworkElement fe && left > 0)
            fe.Margin = new Thickness(left, fe.Margin.Top, fe.Margin.Right, fe.Margin.Bottom);
        parent.Children.Add(child);
    }

    // ── Brush helper ──────────────────────────────────────────────────────────

    private static SolidColorBrush Solid(Color c) => new(c);
}
