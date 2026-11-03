//  PatchedTrayAgent.cs  —  Patched · Windows System-Tray Agent (WinUI 3 / .NET)
//
//  The Windows counterpart to the macOS MenuBarExtra agent. A NotifyIcon in the
//  system tray opens a Fluent flyout (Mica, rounded corners, Segoe UI) that
//  surfaces Scan · Patch · Prove status and hands off to the Self Service app.
//
//  Branded but native, and platform-neutral by design (shares its status/
//  provenance model with the macOS build):
//   • Nothing depends on a management server. OS updates are user-actioned, never forced.
//   • No remote-control language. Every substantive action opens Self Service.
//   • System font (Segoe UI); Cascadia Mono for evidence (versions, CVE IDs, hashes).
//   • One accent: signal orange #F5530A, used sparingly.
//
//  Tray plumbing uses H.NotifyIcon.WinUI (the standard WinUI tray package).
//  This single file builds the flyout in code for portability; production would
//  template the same tree in XAML. Requires Windows App SDK 1.5+, .NET 8.
//
//  NuGet: H.NotifyIcon.WinUI

using System;
using H.NotifyIcon;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;
using Windows.UI.Text;

namespace Patched.Tray;

// MARK: - Brand

static class Brand
{
    public static readonly Color Signal     = Color.FromArgb(255, 0xF5, 0x53, 0x0A);
    public static readonly Color SignalDeep  = Color.FromArgb(255, 0xC9, 0x3F, 0x04);
    public static readonly Color Slate       = Color.FromArgb(255, 0x1B, 0x1B, 0x1B);
    public static readonly Color Graphite     = Color.FromArgb(255, 0x38, 0x38, 0x38);
    public static readonly Color Mute        = Color.FromArgb(255, 0x6A, 0x6A, 0x6A);
    public static readonly Color Secure      = Color.FromArgb(255, 0x1A, 0x8A, 0x4E);
    public static readonly Color Critical    = Color.FromArgb(255, 0xD1, 0x34, 0x38);
    public static readonly Color Idle        = Color.FromArgb(255, 0x8A, 0x8D, 0x94);

    public const string Sys  = "Segoe UI Variable Text";
    public const string Mono = "Cascadia Mono";
}

// MARK: - State model (platform-neutral; shared with the macOS build)

enum AgentStatus { Secure, Updates, ActionNeeded, Scanning, Offline }

record PendingUpdate(string App, string From, string To, string Cve, string Source, string Badge, Color Tint);

record AgentState
{
    public AgentStatus Status { get; init; } = AgentStatus.Secure;
    public string LastScan { get; init; } = "2 minutes ago";
    public string Compliance { get; init; } = "CIS 142 / 142 · No known CVEs";
    public PendingUpdate[] Updates { get; init; } = System.Array.Empty<PendingUpdate>();

    // Drives the tray icon badge (Secure = none, etc.)
    public TrayBadge Badge => Status switch
    {
        AgentStatus.Updates => TrayBadge.Attention,
        AgentStatus.ActionNeeded => TrayBadge.Critical,
        AgentStatus.Scanning => TrayBadge.Scanning,
        AgentStatus.Offline => TrayBadge.Idle,
        _ => TrayBadge.None,
    };
}

enum TrayBadge { None, Attention, Critical, Scanning, Idle }

// MARK: - Tray service

sealed class TrayAgent
{
    private readonly TaskbarIcon _icon;
    private AgentState _state = new()
    {
        Status = AgentStatus.Updates,
        Updates = new[]
        {
            new PendingUpdate("Microsoft Edge", "125.0", "126.0", "CVE-2026-1842", "Microsoft", "Ed", Color.FromArgb(255,0x1A,0x73,0xE8)),
            new PendingUpdate("Google Chrome",  "125.0", "126.0", "CVE-2026-2011", "Google",    "Ch", Color.FromArgb(255,0x11,0xA3,0x6B)),
            new PendingUpdate("Zoom",           "6.0.10","6.1.2", "CVE-2026-1990", "Zoom",      "Zo", Color.FromArgb(255,0x2B,0x6C,0xFF)),
        },
    };

    public TrayAgent()
    {
        _icon = new TaskbarIcon
        {
            // A monochrome template .ico that Windows tints for light/dark tray.
            // Swap per-state to overlay the badge (see UpdateIcon).
            ToolTipText = "Patched — Protected",
        };
        UpdateIcon();
        _icon.LeftClickCommand = new RelayCommand(ShowFlyout);
        _icon.ForceCreate();
    }

    private void UpdateIcon()
    {
        // Ship 5 pre-rendered template icons (mark + badge overlay) and select here:
        //   patched-tray.ico · patched-tray-attention.ico · -critical · -scanning · -idle
        _icon.IconSource = TrayIcons.For(_state.Badge);
    }

    // The Fluent flyout, anchored above the tray.
    private void ShowFlyout()
    {
        var flyout = new TrayFlyoutWindow(_state);
        flyout.Activate();
    }
}

// MARK: - Flyout window (Mica, ~352px)

sealed class TrayFlyoutWindow : Window
{
    public TrayFlyoutWindow(AgentState state)
    {
        SystemBackdrop = new MicaBackdrop();              // native Mica material
        ExtendsContentIntoTitleBar = true;
        // Size & position to the bottom-right above the tray; omitted for brevity.

        Content = new Border
        {
            Padding = new Thickness(14),
            Child = BuildFlyout(state),
        };
    }

    static UIElement BuildFlyout(AgentState s) => s.Status switch
    {
        AgentStatus.Secure       => SecureView(s),
        AgentStatus.Updates      => UpdatesView(s),
        AgentStatus.ActionNeeded => ActionView(s),
        AgentStatus.Scanning     => ScanningView(s),
        _                        => OfflineView(s),
    };

    // ── Shared header: Patched lockup (pixel-P mark + word) + settings ──
    static FrameworkElement Header()
    {
        var row = Row(spacing: 0);
        row.Children.Add(PatchedLockup(15, Brand.Slate));
        var gear = new Button { Content = Glyph("\uE713"), Padding = new Thickness(3) };  // Settings
        gear.Style = SubtleButton();
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(row, 0); Grid.SetColumn(gear, 1);
        grid.Children.Add(row); grid.Children.Add(gear);
        grid.Margin = new Thickness(0, 0, 0, 13);
        return grid;
    }

    // ── Brand: the word “Patched” in Segoe (no mark in the header) ──
    static UIElement PatchedLockup(double size, Color ink)
    {
        return new TextBlock { Text = "Patched", FontFamily = new FontFamily(Brand.Sys), FontSize = size,
            FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(ink), VerticalAlignment = VerticalAlignment.Center };
    }
    static UIElement PixelPMark(double cell, Color ink)
    {
        int[,] glyph = {
            {1,1,1,1,0},{1,0,0,0,1},{1,0,0,0,1},
            {1,1,1,1,0},{1,0,0,0,0},{1,0,0,0,0},{1,0,0,0,0},
        };
        double gap = cell * 0.18;
        var rows = new StackPanel { Spacing = gap };
        for (int r = 0; r < 7; r++)
        {
            var hr = new StackPanel { Orientation = Orientation.Horizontal, Spacing = gap };
            for (int c = 0; c < 5; c++)
            {
                var fill = glyph[r, c] == 0 ? Colors.Transparent : (r == 3 && c == 3 ? Brand.Signal : ink);
                hr.Children.Add(new Rectangle { Width = cell, Height = cell, RadiusX = cell * 0.12, RadiusY = cell * 0.12, Fill = new SolidColorBrush(fill) });
            }
            rows.Children.Add(hr);
        }
        return rows;
    }

    // ── 1 · Secure ──
    static UIElement SecureView(AgentState s)
    {
        var stack = Stack();
        stack.Children.Add(Header());
        stack.Children.Add(StatusLine(Dot(Brand.Secure), "Protected", $"Last scanned {s.LastScan} · continuous"));
        stack.Children.Add(Evidence("\uE73E", s.Compliance, Brand.Secure));   // checkmark seal
        stack.Children.Add(Divider());
        stack.Children.Add(MenuRow("\uE72C", "Scan now"));        // refresh
        stack.Children.Add(MenuRow("\uE8A7", "Open Patched"));    // open-in-new
        stack.Children.Add(MenuRow("\uE7E8", "Quit"));           // power
        return stack;
    }

    // ── 2 · Updates (Nudge-style) ──
    static UIElement UpdatesView(AgentState s)
    {
        var stack = Stack();
        stack.Children.Add(Header());
        stack.Children.Add(StatusLine(Dot(Brand.Signal), $"{s.Updates.Length} updates ready",
                                      "Recommended — you choose when to install"));
        stack.Children.Add(Divider());
        foreach (var u in s.Updates) stack.Children.Add(UpdateRow(u));
        stack.Children.Add(Note("\uE72E", "Nothing installs without your approval."));   // lock
        var buttons = Row(8);
        buttons.Children.Add(AccentButton("Review in Patched", grow: true));
        buttons.Children.Add(NeutralButton("Later"));
        buttons.Margin = new Thickness(0, 14, 0, 0);
        stack.Children.Add(buttons);
        return stack;
    }

    // ── 3 · Action needed ──
    static UIElement ActionView(AgentState s)
    {
        var stack = Stack();
        stack.Children.Add(Header());
        stack.Children.Add(StatusLine(Dot(Brand.Critical), "Action needed", "1 critical finding on this device"));
        stack.Children.Add(FindingCard(
            "Disk encryption is off",
            "This device’s drive isn’t encrypted. If it’s lost or stolen, your files could be read. Turn on encryption to close this gap.",
            "Benchmark · CIS 2.5.1 · Full-disk encryption (BitLocker)"));
        var b = Row(8); b.Children.Add(AccentButton("Resolve in Patched", grow: true)); b.Margin = new Thickness(0,14,0,0);
        stack.Children.Add(b);
        stack.Children.Add(Note("\uE72B", "You stay in control — Patched guides the fix, nothing is forced."));
        return stack;
    }

    // ── 4 · Scanning (determinate) ──
    static UIElement ScanningView(AgentState s)
    {
        var stack = Stack();
        stack.Children.Add(Header());
        stack.Children.Add(StatusLine(new ProgressRing { IsActive = true, Width = 14, Height = 14 },
                                      "Scanning…", "Checking against live CVE data & CIS benchmarks"));
        stack.Children.Add(Text("Comparing app 118 of 247 against the National Vulnerability Database.", 12.5, Brand.Graphite, top: 14));
        stack.Children.Add(new ProgressBar { Value = 48, Maximum = 100, Foreground = Solid(Brand.Signal), Margin = new Thickness(0, 12, 0, 0) });
        stack.Children.Add(MetaRow("118 / 247 apps · 142 checks", "48%"));
        stack.Children.Add(Divider());
        stack.Children.Add(MenuRow("\uE711", "Cancel scan"));   // cancel
        return stack;
    }

    // ── 5 · Offline / stale ──
    static UIElement OfflineView(AgentState s)
    {
        var stack = Stack();
        stack.Children.Add(Header());
        stack.Children.Add(StatusLine(Dot(Brand.Idle), "Can’t reach Patched", "Last scan 6 days ago"));
        stack.Children.Add(Note("\uEB5E", "Your protection status may be out of date. Check your connection and try again."));
        stack.Children.Add(Evidence("\uE823", "Showing last known result · CIS 141 / 142", Brand.Mute));   // clock
        var b = Row(8);
        b.Children.Add(SlateButton("Retry now"));
        b.Children.Add(NeutralButton("Open Patched"));
        b.Margin = new Thickness(0, 14, 0, 0);
        stack.Children.Add(b);
        return stack;
    }

    // ── Building blocks (concise; production would be XAML styles/templates) ──
    static StackPanel Stack() => new() { Spacing = 0 };
    static StackPanel Row(double spacing) => new() { Orientation = Orientation.Horizontal, Spacing = spacing, VerticalAlignment = VerticalAlignment.Center };

    static FrameworkElement Dot(Color c) => new Ellipse { Width = 9, Height = 9, Fill = Solid(c), Margin = new Thickness(0, 5, 0, 0), VerticalAlignment = VerticalAlignment.Top };

    static UIElement StatusLine(FrameworkElement indicator, string title, string sub)
    {
        var row = Row(11); row.VerticalAlignment = VerticalAlignment.Top;
        row.Children.Add(indicator);
        var col = Stack();
        col.Children.Add(new TextBlock { Text = title, FontFamily = new FontFamily(Brand.Sys), FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Solid(Brand.Slate) });
        col.Children.Add(new TextBlock { Text = sub, FontFamily = new FontFamily(Brand.Sys), FontSize = 12, Foreground = Solid(Brand.Mute), Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap });
        row.Children.Add(col);
        return row;
    }

    static UIElement Evidence(string glyph, string text, Color tint)
    {
        var row = Row(7); row.Margin = new Thickness(0, 13, 0, 0);
        row.Children.Add(Glyph(glyph, 14, tint));
        row.Children.Add(new TextBlock { Text = text, FontFamily = new FontFamily(Brand.Mono), FontSize = 11, Foreground = Solid(Brand.Graphite) });
        return row;
    }

    static UIElement UpdateRow(PendingUpdate u)
    {
        var row = Row(11); row.VerticalAlignment = VerticalAlignment.Top; row.Margin = new Thickness(0, 9, 0, 0);
        row.Children.Add(AppTile(u.Badge, u.Tint));
        var col = Stack();
        col.Children.Add(new TextBlock { Text = u.App, FontFamily = new FontFamily(Brand.Sys), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Solid(Brand.Slate) });
        col.Children.Add(new TextBlock { FontFamily = new FontFamily(Brand.Mono), FontSize = 11, Foreground = Solid(Brand.Mute), Text = $"{u.From} → {u.To}", Margin = new Thickness(0, 2, 0, 0) });
        var chips = Row(6); chips.Margin = new Thickness(0, 7, 0, 0);
        chips.Children.Add(Chip(u.Cve, Brand.Graphite, Color.FromArgb(13, 0, 0, 0)));
        chips.Children.Add(Chip($"Verified · {u.Source}", Brand.Secure, Color.FromArgb(26, 0x1A, 0x8A, 0x4E)));
        col.Children.Add(chips);
        row.Children.Add(col);
        return row;
    }

    static UIElement FindingCard(string title, string body, string meta)
    {
        var card = new StackPanel { Spacing = 7, Padding = new Thickness(12), Margin = new Thickness(0, 13, 0, 0),
            CornerRadius = new CornerRadius(6), Background = Solid(Color.FromArgb(13, 0xD1, 0x34, 0x38)),
            BorderThickness = new Thickness(1), BorderBrush = Solid(Color.FromArgb(72, 0xD1, 0x34, 0x38)) };
        var top = Row(8);
        top.Children.Add(Chip("Critical", Colors.White, Brand.Critical));
        top.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, FontSize = 13, Foreground = Solid(Brand.Slate) });
        card.Children.Add(top);
        card.Children.Add(new TextBlock { Text = body, FontSize = 12, Foreground = Solid(Brand.Graphite), TextWrapping = TextWrapping.Wrap });
        card.Children.Add(new TextBlock { Text = meta, FontFamily = new FontFamily(Brand.Mono), FontSize = 10.5, Foreground = Solid(Brand.Mute) });
        return card;
    }

    static Border AppTile(string letters, Color tint) => new()
    {
        Width = 30, Height = 30, CornerRadius = new CornerRadius(6), Background = Solid(tint),
        Child = new TextBlock { Text = letters, Foreground = Solid(Colors.White), FontWeight = FontWeights.SemiBold, FontSize = 13,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
    };

    static Border Chip(string text, Color fg, Color bg) => new()
    {
        Background = Solid(bg), CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 2, 6, 2),
        Child = new TextBlock { Text = text, FontFamily = new FontFamily(Brand.Mono), FontSize = 10, Foreground = Solid(fg) },
    };

    static UIElement MenuRow(string glyph, string label)
    {
        var row = Row(11); row.Height = 36; row.Padding = new Thickness(10, 0, 10, 0);
        row.Children.Add(Glyph(glyph, 15, Brand.Graphite));
        row.Children.Add(new TextBlock { Text = label, FontSize = 13, Foreground = Solid(Brand.Slate), VerticalAlignment = VerticalAlignment.Center });
        return new Button { Content = row, Style = SubtleButton(), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left };
    }

    static UIElement Note(string glyph, string text)
    {
        var row = Row(7); row.Margin = new Thickness(0, 12, 0, 0); row.VerticalAlignment = VerticalAlignment.Top;
        row.Children.Add(Glyph(glyph, 13, Brand.Mute));
        row.Children.Add(new TextBlock { Text = text, FontSize = 11.5, Foreground = Solid(Brand.Mute), TextWrapping = TextWrapping.Wrap });
        return row;
    }

    static UIElement MetaRow(string left, string right)
    {
        var grid = new Grid { Margin = new Thickness(0, 9, 0, 0) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var l = new TextBlock { Text = left, FontFamily = new FontFamily(Brand.Mono), FontSize = 10.5, Foreground = Solid(Brand.Mute) };
        var r = new TextBlock { Text = right, FontFamily = new FontFamily(Brand.Mono), FontSize = 10.5, Foreground = Solid(Brand.Mute) };
        Grid.SetColumn(r, 1); grid.Children.Add(l); grid.Children.Add(r);
        return grid;
    }

    static TextBlock Text(string t, double size, Color c, double top = 0) =>
        new() { Text = t, FontSize = size, Foreground = Solid(c), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, top, 0, 0) };

    static Border Divider() => new() { Height = 1, Background = Solid(Color.FromArgb(26, 0, 0, 0)), Margin = new Thickness(-14, 13, -14, 13) };

    static FontIcon Glyph(string g, double size = 16, Color? c = null) =>
        new() { Glyph = g, FontFamily = new FontFamily("Segoe Fluent Icons"), FontSize = size, Foreground = Solid(c ?? Brand.Graphite) };

    // Buttons
    static Button AccentButton(string t, bool grow = false) => FilledButton(t, Brand.Signal, Colors.White, grow);
    static Button SlateButton(string t) => FilledButton(t, Brand.Slate, Colors.White, false);
    static Button FilledButton(string text, Color bg, Color fg, bool grow) => new()
    {
        Content = new TextBlock { Text = text, FontWeight = FontWeights.SemiBold, FontSize = 13, Foreground = Solid(fg) },
        Background = Solid(bg), Height = 32, CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(0),
        HorizontalAlignment = HorizontalAlignment.Stretch,
    };
    static Button NeutralButton(string text) => new()
    {
        Content = new TextBlock { Text = text, FontWeight = FontWeights.SemiBold, FontSize = 13, Foreground = Solid(Brand.Slate) },
        Height = 32, CornerRadius = new CornerRadius(4),
    };

    static SolidColorBrush Solid(Color c) => new(c);
    static Style SubtleButton()
    {
        // Maps to the built-in "SubtleButtonStyle" resource in production.
        return (Style)Application.Current.Resources["SubtleButtonStyle"];
    }
}

// Placeholder helpers the app wires to real implementations.
static class TrayIcons { public static object For(TrayBadge b) => null!; }
sealed class RelayCommand : System.Windows.Input.ICommand
{
    private readonly Action _run;
    public RelayCommand(Action run) => _run = run;
    public bool CanExecute(object? p) => true;
    public void Execute(object? p) => _run();
    public event EventHandler? CanExecuteChanged;
}
