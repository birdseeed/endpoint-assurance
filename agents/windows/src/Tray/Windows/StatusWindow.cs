using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Patched.Shared.Contract;
using Brush       = System.Windows.Media.Brush;
using Brushes     = System.Windows.Media.Brushes;
using Button      = System.Windows.Controls.Button;
using Color       = System.Windows.Media.Color;
using FontFamily  = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;

namespace Patched.Tray;

/// <summary>
/// WPF status window.
/// Win11 Mica material applied via DwmSetWindowAttribute.
/// Unprivileged, read-only: reads update-status.json via StatusReader. Assurance
/// only — this window does not write install triggers.
///
/// PAT-300/481: When status.ComplianceFindings contains disk_encryption_off or
/// removable_storage_unencrypted, a compliance finding card is shown above the app list.
/// "How to fix this" navigates to FindingDetailPage.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class StatusWindow : Window
{
    private readonly StatusReader  _reader;

    // PAT-300/481: host panel for the compliance finding card and finding-detail content.
    private ContentControl?  _complianceFindingCard;
    private ContentControl?  _findingDetailHost;
    // The active finding drives both the card content and the detail page navigation.
    // _activeFindingId mirrors the compliance_findings[].id string so StatusWindow.cs
    // never accesses WinConfigFinding.Id — that property is defined in FindingDetailPage.cs
    // which the WPF _wpftmp shadow project doesn't include in its compilation pass.
    private WinConfigFinding? _activeFinding;
    private string?           _activeFindingId;

    public StatusWindow(StatusReader reader)
    {
        _reader = reader;
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplyMicaBackdrop();
        BuildComplianceFindingArea();
        UpdateStatus(_reader.Current);
    }

    // -------------------------------------------------------------------------
    // PAT-300/481: Build the compliance finding card area and finding-detail host
    // and inject them into the XAML layout above AppList.
    // -------------------------------------------------------------------------

    private void BuildComplianceFindingArea()
    {
        // The XAML ScrollViewer holding AppList is in Grid row 2.
        // We insert a ContentControl above row 2 (row 1.5 -- injected into the
        // Grid before the ScrollViewer) to host the finding card or detail page.
        // Because XAML rows are already defined, we add a new row dynamically.
        if (Content is not Border outerBorder || outerBorder.Child is not Grid grid)
            return;

        // Insert a new row between the status summary (row 1) and the app list (row 2).
        grid.RowDefinitions.Insert(2, new RowDefinition { Height = GridLength.Auto });

        // Shift existing rows 2+ down by 1.
        foreach (UIElement child in grid.Children)
        {
            var row = Grid.GetRow(child);
            if (row >= 2) Grid.SetRow(child, row + 1);
        }

        // Finding-detail host: starts hidden; shown when the user taps the CTA.
        _findingDetailHost = new ContentControl
        {
            Margin     = new Thickness(0),
            Visibility = Visibility.Collapsed,
        };
        Grid.SetRow(_findingDetailHost, 2);
        grid.Children.Add(_findingDetailHost);

        // Compliance finding card: content is built dynamically on each UpdateStatus call.
        _complianceFindingCard = new ContentControl { Visibility = Visibility.Collapsed };
        Grid.SetRow(_complianceFindingCard, 2);
        grid.Children.Add(_complianceFindingCard);
    }

    // Build a compact finding card for the given finding.
    // isCritical drives pill colour (red) vs advisory (orange).
    private UIElement BuildFindingCard(WinConfigFinding f, bool isCritical)
    {
        var accentBrush = isCritical
            ? new SolidColorBrush(Color.FromRgb(0xE2, 0x3B, 0x2E))
            : new SolidColorBrush(Color.FromRgb(0xF5, 0x53, 0x0A));
        var pillLabel  = isCritical ? "CRITICAL" : "ADVISORY";
        var muteBrush  = new SolidColorBrush(Color.FromRgb(0x7D, 0x80, 0x89));
        var slateBrush = new SolidColorBrush(Color.FromRgb(0x0F, 0x11, 0x15));
        var mono       = new FontFamily("Cascadia Mono, Consolas, monospace");
        var sys        = new FontFamily("Segoe UI Variable Display, Segoe UI, sans-serif");

        var inner = new StackPanel();

        // Severity pill + "CONFIGURATION FINDING"
        var topRow = new StackPanel
        {
            Orientation       = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin            = new Thickness(0, 0, 0, 8),
        };
        topRow.Children.Add(new Border
        {
            Background   = accentBrush,
            CornerRadius = new CornerRadius(4),
            Padding      = new Thickness(7, 2, 7, 2),
            Margin       = new Thickness(0, 0, 10, 0),
            Child        = new TextBlock
            {
                Text       = pillLabel,
                FontFamily = mono,
                FontSize   = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
            },
        });
        topRow.Children.Add(new TextBlock
        {
            Text              = "CONFIGURATION FINDING · ADVISORY",
            FontFamily        = mono,
            FontSize          = 10,
            Foreground        = muteBrush,
            VerticalAlignment = VerticalAlignment.Center,
        });
        inner.Children.Add(topRow);

        inner.Children.Add(new TextBlock
        {
            Text       = f.Title,
            FontFamily = sys,
            FontSize   = 14,
            FontWeight = FontWeights.Bold,
            Foreground = slateBrush,
            Margin     = new Thickness(0, 0, 0, 8),
        });

        // One-line risk summary for the compact card.
        var summaryText = isCritical
            ? "BitLocker isn't turned on. If this PC is lost or stolen, your files can be read without your sign-in."
            : "One or more USB or external drives are not encrypted. If a drive is lost, anyone can read its contents.";
        inner.Children.Add(new TextBlock
        {
            Text         = summaryText,
            FontFamily   = sys,
            FontSize     = 12,
            Foreground   = slateBrush,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 0, 0, 8),
        });

        // Evidence line (mono CIS ref)
        var evidenceRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 0, 0, 8),
        };
        evidenceRow.Children.Add(new TextBlock
        {
            Text              = "",   // lock glyph -- Segoe Fluent Icons
            FontFamily        = new FontFamily("Segoe Fluent Icons"),
            FontSize          = 12,
            Foreground        = muteBrush,
            VerticalAlignment = VerticalAlignment.Center,
        });
        evidenceRow.Children.Add(new TextBlock
        {
            Text       = $"Benchmark · {f.CisControlRef} · {f.CisControlName}",
            FontFamily = mono,
            FontSize   = 10,
            Foreground = muteBrush,
            Margin     = new Thickness(6, 0, 0, 0),
        });
        inner.Children.Add(evidenceRow);

        inner.Children.Add(new TextBlock
        {
            Text         = "You stay in control -- Patched guides the fix, nothing is forced.",
            FontFamily   = sys,
            FontSize     = 11,
            Foreground   = muteBrush,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 0, 0, 8),
        });

        // CTA -- advisory only, NO "Resolve in Patched"
        var ctaButton = new Button
        {
            Content             = "How to fix this →",
            FontFamily          = sys,
            FontSize            = 13,
            FontWeight          = FontWeights.SemiBold,
            Foreground          = Brushes.White,
            Background          = new SolidColorBrush(Color.FromRgb(0xF5, 0x53, 0x0A)),
            BorderThickness     = new Thickness(0),
            Padding             = new Thickness(14, 7, 14, 7),
            Cursor              = System.Windows.Input.Cursors.Hand,
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        ctaButton.Click += (_, _) => ShowFindingDetail();
        inner.Children.Add(ctaButton);

        return new Border
        {
            Margin          = new Thickness(16, 8, 16, 4),
            Padding         = new Thickness(14),
            CornerRadius    = new CornerRadius(8),
            BorderBrush     = accentBrush,
            BorderThickness = new Thickness(1),
            Background      = new SolidColorBrush(isCritical
                ? Color.FromArgb(18, 0xE2, 0x3B, 0x2E)
                : Color.FromArgb(18, 0xF5, 0x53, 0x0A)),
            Child = inner,
        };
    }

    /// <summary>
    /// Show the finding-detail advisory view in place of the finding card.
    /// Advisory only -- no "Resolve in Patched" / auto-remediation.
    /// Navigates to the detail page for whichever finding is currently active.
    /// </summary>
    private void ShowFindingDetail()
    {
        if (_findingDetailHost is null || _complianceFindingCard is null || _activeFinding is null)
            return;

        _findingDetailHost.Content = FindingDetailPage.Build(
            _activeFinding,
            showPlans: () => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = "https://patched.im/pricing",
                UseShellExecute = true,
            }));
        _findingDetailHost.Visibility     = Visibility.Visible;
        _complianceFindingCard.Visibility = Visibility.Collapsed;

        // Swap the main app-list row out of view so the detail fills the window.
        if (Content is Border outerBorder && outerBorder.Child is Grid grid)
        {
            foreach (UIElement child in grid.Children)
            {
                var row = Grid.GetRow(child);
                // Row 3 = the ScrollViewer holding AppList (after our insert shifted it).
                if (row == 3) child.Visibility = Visibility.Collapsed;
            }
        }
    }

    public void UpdateStatus(UpdateStatus? status)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => UpdateStatus(status));
            return;
        }

        if (status is null)
        {
            StatusSummary.Text  = "Waiting for Patched service…";
            StatusDot.Fill      = Brushes.Gray;
            AppList.ItemsSource = null;
            if (_complianceFindingCard is not null)
                _complianceFindingCard.Visibility = Visibility.Collapsed;
            return;
        }

        // PAT-300/481: show compliance finding card for the highest-priority active finding.
        // Priority: disk_encryption_off (critical) > removable_storage_unencrypted (advisory).
        _activeFinding   = null;
        _activeFindingId = null;
        if (status.ComplianceFindings is { } findings)
        {
            if (findings.Any(f => f.Id == "disk_encryption_off"))
            {
                _activeFinding   = FindingData.BitLockerOff;
                _activeFindingId = "disk_encryption_off";
            }
            else if (findings.Any(f => f.Id == "removable_storage_unencrypted"))
            {
                _activeFinding   = FindingData.RemovableStorageUnencrypted;
                _activeFindingId = "removable_storage_unencrypted";
            }
        }

        if (_complianceFindingCard is not null)
        {
            if (_activeFinding is not null)
            {
                var isCritical = ReferenceEquals(_activeFinding, FindingData.BitLockerOff);
                _complianceFindingCard.Content    = BuildFindingCard(_activeFinding, isCritical);
                _complianceFindingCard.Visibility = Visibility.Visible;
            }
            else
            {
                _complianceFindingCard.Visibility = Visibility.Collapsed;
            }
        }

        (StatusSummary.Text, StatusDot.Fill) = (_activeFindingId, status.OverallState) switch
        {
            ("disk_encryption_off", _) =>
                ("Action needed -- disk encryption is off", new SolidColorBrush(Color.FromRgb(0xC5, 0x0F, 0x1F))),
            ("removable_storage_unencrypted", _) =>
                ("Advisory -- unencrypted removable storage detected", new SolidColorBrush(Color.FromRgb(0xF5, 0x53, 0x0A))),
            (_, OverallState.UpToDate) =>
                ("All apps up to date", new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10))),
            (_, OverallState.UpdatesAvailable) =>
                ($"{status.Counts?.UpdatesAvailable} update(s) available",
                 new SolidColorBrush(Color.FromRgb(0xCA, 0x50, 0x10))),
            (_, OverallState.Error) =>
                ("Error -- see details below",
                 new SolidColorBrush(Color.FromRgb(0xC5, 0x0F, 0x1F))),
            _ => ("Checking…", Brushes.Gray),
        };

        if (status.LastRun?.FinishedAt is { } finishedAt)
        {
            LastRunText.Text = $"Last checked {finishedAt.ToLocalTime():g}";
        }

        AppList.ItemsSource = status.Apps.Select(AppViewModel.From).ToList();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Hide();

    private void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) =>
        DragMove();

    // -------------------------------------------------------------------------
    // Mica material (Windows 11 only; no-op on Windows 10)
    // -------------------------------------------------------------------------

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr,
        ref int pvAttr, int cbAttr);

    private void ApplyMicaBackdrop()
    {
        try
        {
            var hwnd  = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            // DWMWA_SYSTEMBACKDROP_TYPE = 38 (Windows 11 22H2+)
            int mica = 2;
            DwmSetWindowAttribute(hwnd, 38, ref mica, sizeof(int));
            // Also enable DWMWA_MICA_EFFECT = 1029 for older Win11 builds
            int micaOld = 1;
            DwmSetWindowAttribute(hwnd, 1029, ref micaOld, sizeof(int));

            Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        }
        catch
        {
            // Mica not available (Windows 10); keep the default surface brush.
        }
    }
}

/// <summary>View model for one app row in the status window.</summary>
public sealed class AppViewModel
{
    public string  Label        { get; init; } = "";
    public string  Name         { get; init; } = "";
    public string  VersionLine  { get; init; } = "";
    public string  StateLabel   { get; init; } = "";
    public Brush   StateBrush   { get; init; } = Brushes.Gray;

    public static AppViewModel From(AppEntry entry)
    {
        var versionLine = entry.InstalledVersion is not null
            ? entry.AvailableVersion is not null && entry.AvailableVersion != entry.InstalledVersion
                ? $"{entry.InstalledVersion} → {entry.AvailableVersion}"
                : entry.InstalledVersion
            : entry.AvailableVersion is not null
                ? $"Available: {entry.AvailableVersion}"
                : "Not installed";

        var (stateLabel, stateBrush) = entry.State switch
        {
            AppState.UpToDate          => ("Up to date",          new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10))),
            AppState.UpdateAvailable   => ("Update available",     new SolidColorBrush(Color.FromRgb(0xCA, 0x50, 0x10))),
            AppState.Updating          => ("Deploying…",      (Brush)Brushes.DodgerBlue),
            AppState.VerificationFailed=> ("Verification failed",  new SolidColorBrush(Color.FromRgb(0xC5, 0x0F, 0x1F))),
            AppState.Error             => ("Error",                new SolidColorBrush(Color.FromRgb(0xC5, 0x0F, 0x1F))),
            AppState.NotInstalled      => ("Not installed",        Brushes.Gray),
            _                          => ("Unknown",              Brushes.Gray),
        };

        return new AppViewModel
        {
            Label         = entry.Label,
            Name          = entry.Name,
            VersionLine   = versionLine,
            StateLabel    = stateLabel,
            StateBrush    = stateBrush,
        };
    }
}
