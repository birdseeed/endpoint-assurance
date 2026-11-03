//  FindingDetailPage.cs  —  Patched · Windows Tray (WPF / .NET)
//
//  PAT-300 — Advisory configuration finding-detail.
//  The destination for the tray agent's "How to fix this →" CTA.
//
//  ADVISORY VIEW — the honesty rules apply, sharpened:
//   • A configuration / CIS finding (disk encryption off) is advisory only.
//     Patched detects it, explains the risk, and shows the user how to enable
//     BitLocker THEMSELVES. It never performs or implies it performs the fix —
//     there is NO "Resolve in Patched", "Fix for me", or any auto-remediation
//     control in this file. By design.
//   • Enforcement (turning BitLocker on, holding it in place) needs managed
//     config = Full Endpoint Management (Tier 3). Surfaced here as an OPTIONAL
//     upsell, not a paywall — the self-serve steps are complete on Report plan.
//
//  Translates the WinUI 3 stub (PatchedFindingDetail.cs) to WPF:
//    Microsoft.UI.Xaml.Controls.* → System.Windows.Controls.*
//    FontIcon (Segoe Fluent Glyphs) → TextBlock with FontFamily="Segoe Fluent Icons"
//    WinUI InfoBar → WPF Border with amber background
//    Colors: SolidColorBrush(Color.FromRgb(...))

using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using FontWeights = System.Windows.FontWeights;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;
using Thickness = System.Windows.Thickness;
using Visibility = System.Windows.Visibility;

namespace Patched.Tray;

// MARK: - Finding model (platform-neutral; mirrors macOS ConfigFinding)

record WinFixStep(int N, string Title, string Detail);

record WinConfigFinding(
    string Title,           // "Disk encryption is off"
    string Risk,            // plain-language "why it matters"
    string CisControlRef,   // CIS Windows 11 Enterprise Benchmark v3.0.0 control number
    string CisControlName,  // "Full-disk encryption (BitLocker)"
    WinFixStep[] Steps);

static class FindingData
{
    public static readonly WinConfigFinding BitLockerOff = new(
        Title: "Disk encryption is off",
        Risk:  "BitLocker isn't turned on, so the data on this PC is stored unencrypted. If the " +
               "laptop is lost or stolen, someone can remove the drive -- or boot from another device " +
               "-- and read your files, email and saved passwords without your sign-in. Turning " +
               "BitLocker on encrypts the whole drive so the data stays unreadable without your " +
               "credentials or recovery key.",
        CisControlRef:  "18.10.74.1.1",
        CisControlName: "Full-disk encryption (BitLocker)",
        Steps:
        [
            new(1, "Open Settings → Privacy & security → Device encryption",
                "On Windows 11 Home/Pro this is the quickest path. If you don't see Device encryption, use the Control Panel route in the next step instead."),
            new(2, "Or open Control Panel → BitLocker Drive Encryption → Turn on BitLocker",
                "On Windows 11 Pro/Enterprise this gives the full BitLocker options for your operating-system drive. You'll need administrator rights."),
            new(3, "Save your recovery key somewhere safe",
                "Save it to your Microsoft account, a file, or print it -- then also keep a copy in your password manager. It's the only way back in if the TPM check fails or you're locked out."),
            new(4, "Let encryption finish in the background",
                "Your PC stays usable while it encrypts the drive. Patched's next scan confirms the control as passing and updates your compliance record automatically."),
        ]);

    public static readonly WinConfigFinding RemovableStorageUnencrypted = new(
        Title: "Removable storage is not encrypted",
        Risk:  "One or more USB or external drives are not encrypted with BitLocker To Go. If a " +
               "drive is lost or left behind, anyone can read the files on it without your " +
               "credentials. Encrypting each drive keeps your data unreadable without a password -- " +
               "even if the hardware is handed on. Patched detected this from volumes mounted at " +
               "scan time; drives inserted after the scan are not reflected until the next run.",
        CisControlRef:  "18.10.74.3.6",
        CisControlName: "Removable-media encryption (BitLocker To Go)",
        Steps:
        [
            new(1, "Insert the USB or external drive and open File Explorer",
                "Right-click the drive and choose 'Turn on BitLocker'. You need administrator rights. If BitLocker To Go is not available, check that Windows 11 Pro or Enterprise is installed."),
            new(2, "Choose a password to unlock the drive",
                "Select 'Use a password to unlock this drive', enter a strong passphrase, and confirm it. The password is what unlocks the drive on any PC -- choose something you won't forget."),
            new(3, "Save your recovery key somewhere safe",
                "Save it to your Microsoft account, a file, or print it -- then keep a copy in your password manager too. Without it, encrypted data cannot be recovered if the password is lost."),
            new(4, "Let encryption finish in the background",
                "The drive stays usable while it encrypts. Patched's next scan confirms BitLocker To Go as active and clears this finding from your compliance record automatically."),
        ]);
}

// MARK: - Advisory finding-detail page

static class FindingDetailPage
{
    // Brand colours — WPF SolidColorBrush equivalents.
    private static readonly SolidColorBrush Signal   = new(Color.FromRgb(0xF5, 0x53, 0x0A));
    private static readonly SolidColorBrush Critical = new(Color.FromRgb(0xE2, 0x3B, 0x2E));
    private static readonly SolidColorBrush Secure   = new(Color.FromRgb(0x1C, 0x9A, 0x54));
    private static readonly SolidColorBrush Slate    = new(Color.FromRgb(0x0F, 0x11, 0x15));
    private static readonly SolidColorBrush Muted    = new(Color.FromRgb(0x7D, 0x80, 0x89));
    private static readonly SolidColorBrush Card     = new(Color.FromRgb(0xF5, 0xF5, 0xF3));
    private static readonly SolidColorBrush Hair     = new(Color.FromArgb(0x12, 0x00, 0x00, 0x00));
    private static readonly SolidColorBrush White    = new(Colors.White);

    private static readonly FontFamily Sys  = new("Segoe UI Variable Display, Segoe UI, sans-serif");
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas, monospace");
    private static readonly FontFamily FluentIcons = new("Segoe Fluent Icons");

    public static UIElement Build(WinConfigFinding f, Action showPlans)
    {
        var s = new StackPanel { Margin = new Thickness(24) };

        s.Children.Add(Breadcrumb("Compliance", f.Title));

        // 1–3 · Finding-card header
        s.Children.Add(FindingCard(f));

        // 4 · Fix steps
        s.Children.Add(SectionLabel("Here's how to turn it on"));
        var steps = CardList();
        for (int i = 0; i < f.Steps.Length; i++)
        {
            if (i > 0) steps.Children.Add(HairLine());
            steps.Children.Add(StepRow(f.Steps[i]));
        }
        s.Children.Add(new Border
        {
            Child           = steps,
            CornerRadius    = new CornerRadius(8),
            BorderBrush     = Hair,
            BorderThickness = new Thickness(1),
            Background      = Card,
        });
        s.Children.Add(RecoveryKeyCallout());

        // 5 · Tier 3 upsell — optional, not a paywall
        s.Children.Add(SectionLabel("Want this handled for you?"));
        s.Children.Add(Tier3Upsell(showPlans));

        // 6 · Reassurance line — verbatim with the rest of the app
        s.Children.Add(ReassuranceLine("You stay in control — Patched guides the fix, nothing is forced."));

        return new ScrollViewer
        {
            Content                  = s,
            VerticalScrollBarVisibility   = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        };
    }

    // MARK: Finding-card header

    static UIElement FindingCard(WinConfigFinding f)
    {
        // BitLockerOff is critical (red); all other findings are advisory (orange).
        var isCritical = ReferenceEquals(f, FindingData.BitLockerOff);
        var inner = new StackPanel { Margin = new Thickness(20) };

        // Severity pill + advisory category
        var top = new StackPanel
        {
            Orientation       = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
        };
        top.Children.Add(SeverityPill(isCritical ? "CRITICAL" : "ADVISORY", isCritical));
        top.Children.Add(new TextBlock
        {
            Text              = "CONFIGURATION FINDING · ADVISORY",
            FontFamily        = Mono,
            FontSize          = 10.5,
            Foreground        = Muted,
            Margin            = new Thickness(10, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        inner.Children.Add(top);

        inner.Children.Add(new TextBlock
        {
            Text       = f.Title,
            FontFamily = Sys,
            FontSize   = 20,
            FontWeight = FontWeights.Bold,
            Margin     = new Thickness(0, 12, 0, 0),
            Foreground = Slate,
        });

        // 2 · Plain-language risk
        inner.Children.Add(new TextBlock
        {
            Text         = f.Risk,
            FontFamily   = Sys,
            FontSize     = 13,
            Foreground   = Slate,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 8, 0, 0),
        });

        inner.Children.Add(HairLine(new Thickness(0, 14, 0, 0)));

        // 3 · Evidence line — CIS control ref + name
        var ev = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 13, 0, 0),
        };
        ev.Children.Add(new TextBlock
        {
            Text       = "",   // Segoe Fluent Icons lock glyph
            FontFamily = FluentIcons,
            FontSize   = 13,
            Foreground = Muted,
            Margin     = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        ev.Children.Add(new TextBlock
        {
            Text       = $"{f.CisControlRef} · {f.CisControlName}",
            FontFamily = Mono,
            FontSize   = 11.5,
            Foreground = Muted,
        });
        inner.Children.Add(ev);

        // Wrap card with severity-coloured border + wash halo.
        var accentBrush = isCritical ? Critical : Signal;
        var haloAlpha   = (byte)18;
        var haloColor   = isCritical
            ? Color.FromArgb(haloAlpha, 0xE2, 0x3B, 0x2E)
            : Color.FromArgb(haloAlpha, 0xF5, 0x53, 0x0A);
        return new Border
        {
            Child = new Border
            {
                Child           = inner,
                Background      = Card,
                BorderBrush     = accentBrush,
                BorderThickness = new Thickness(1),
                CornerRadius    = new CornerRadius(8),
            },
            Padding      = new Thickness(3),
            Background   = new SolidColorBrush(haloColor),
            CornerRadius = new CornerRadius(8),
            Margin       = new Thickness(0, 0, 0, 20),
        };
    }

    static Border SeverityPill(string text, bool isCritical = true) => new()
    {
        Background   = isCritical ? Critical : Signal,
        CornerRadius = new CornerRadius(4),
        Padding      = new Thickness(8, 3, 8, 3),
        Child        = new TextBlock
        {
            Text       = text,
            FontFamily = Mono,
            FontSize   = 10,
            FontWeight = FontWeights.SemiBold,
            Foreground = White,
        },
    };

    // MARK: Fix-step row

    static UIElement StepRow(WinFixStep step)
    {
        var r = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(16, 13, 16, 13),
        };

        r.Children.Add(new Border
        {
            Width        = 22, Height = 22,
            CornerRadius = new CornerRadius(11),
            Background   = Slate,
            VerticalAlignment = VerticalAlignment.Top,
            Margin       = new Thickness(0, 1, 13, 0),
            Child        = new TextBlock
            {
                Text                = step.N.ToString(),
                FontFamily          = Mono,
                FontSize            = 11.5,
                FontWeight          = FontWeights.Bold,
                Foreground          = White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment   = VerticalAlignment.Center,
            },
        });

        var c = new StackPanel();
        c.Children.Add(new TextBlock
        {
            Text         = step.Title,
            FontFamily   = Sys,
            FontSize     = 13.5,
            FontWeight   = FontWeights.Medium,
            TextWrapping = TextWrapping.Wrap,
        });
        c.Children.Add(new TextBlock
        {
            Text         = step.Detail,
            FontFamily   = Sys,
            FontSize     = 12,
            Foreground   = Muted,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 3, 0, 0),
        });
        r.Children.Add(c);
        return r;
    }

    // MARK: Recovery-key callout (secure-tinted)

    static UIElement RecoveryKeyCallout()
    {
        var r = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 12, 0, 20),
        };
        r.Children.Add(new TextBlock
        {
            Text              = "",   // key glyph from Segoe Fluent Icons
            FontFamily        = FluentIcons,
            FontSize          = 15,
            Foreground        = Secure,
            Margin            = new Thickness(0, 0, 11, 0),
            VerticalAlignment = VerticalAlignment.Top,
        });
        var c = new StackPanel();
        c.Children.Add(new TextBlock
        {
            Text       = "Don't lose your recovery key",
            FontFamily = Sys,
            FontSize   = 13,
            FontWeight = FontWeights.SemiBold,
        });
        c.Children.Add(new TextBlock
        {
            Text         = "Without it — and without your sign-in — encrypted data can't be recovered by anyone, including Patched and Microsoft. Save it before you start.",
            FontFamily   = Sys,
            FontSize     = 12,
            Foreground   = Slate,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 3, 0, 0),
        });
        r.Children.Add(c);

        return new Border
        {
            Child           = new Border { Child = r, Padding = new Thickness(14, 12, 14, 12) },
            Background      = new SolidColorBrush(Color.FromArgb(26, 0x1C, 0x9A, 0x54)),
            BorderBrush     = new SolidColorBrush(Color.FromArgb(56, 0x1C, 0x9A, 0x54)),
            BorderThickness = new Thickness(1),
            CornerRadius    = new CornerRadius(8),
        };
    }

    // MARK: Tier 3 upsell (featured plan-card voice)

    static UIElement Tier3Upsell(Action showPlans)
    {
        var card = new StackPanel { Margin = new Thickness(0, 0, 0, 18) };

        // Tier label pill
        card.Children.Add(new Border
        {
            Background          = Signal,
            CornerRadius        = new CornerRadius(5),
            Padding             = new Thickness(8, 3, 8, 3),
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin              = new Thickness(0, 0, 0, 12),
            Child               = new TextBlock
            {
                Text       = "FULL ENDPOINT MANAGEMENT · TIER 3",
                FontFamily = Mono,
                FontSize   = 9,
                FontWeight = FontWeights.SemiBold,
                Foreground = White,
            },
        });

        var top = new StackPanel { Orientation = Orientation.Horizontal };
        top.Children.Add(new Border
        {
            Width        = 36, Height = 36,
            CornerRadius = new CornerRadius(8),
            Background   = new SolidColorBrush(Color.FromArgb(20, 0xF5, 0x53, 0x0A)),
            Margin       = new Thickness(0, 0, 13, 0),
            VerticalAlignment = VerticalAlignment.Top,
            Child        = new TextBlock
            {
                // checkmark.shield glyph equivalent in Segoe Fluent Icons
                Text                = "",
                FontFamily          = FluentIcons,
                FontSize            = 18,
                Foreground          = Signal,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment   = VerticalAlignment.Center,
            },
        });

        var c = new StackPanel();
        c.Children.Add(new TextBlock
        {
            Text         = "On Full Endpoint Management, Patched enforces this for you",
            FontFamily   = Sys,
            FontSize     = 14,
            FontWeight   = FontWeights.Bold,
            TextWrapping = TextWrapping.Wrap,
        });
        c.Children.Add(new TextBlock
        {
            Text         = "Tier 3 manages configuration across the estate — BitLocker is switched on " +
                           "and held in place, recovery keys are escrowed centrally, and drift is " +
                           "corrected without anyone touching a setting. On your current Report plan, " +
                           "Patched detects and guides; you make the change.",
            FontFamily   = Sys,
            FontSize     = 12.5,
            Foreground   = Slate,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 4, 0, 0),
        });

        var comingSoon = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 0) };
        comingSoon.Children.Add(new TextBlock
        {
            Text       = "",   // clock glyph
            FontFamily = FluentIcons,
            FontSize   = 12,
            Foreground = Muted,
            Margin     = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        comingSoon.Children.Add(new TextBlock
        {
            Text       = "COMING SOON · OPTIONAL, NOT REQUIRED",
            FontFamily = Mono,
            FontSize   = 9.5,
            FontWeight = FontWeights.SemiBold,
            Foreground = Muted,
            VerticalAlignment = VerticalAlignment.Center,
        });
        c.Children.Add(comingSoon);

        top.Children.Add(c);
        card.Children.Add(top);

        // CTA buttons
        var cta = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 14, 0, 0) };
        var compare = AccentButton("Compare tiers");
        compare.Click += (_, _) => showPlans();
        var about = new Button
        {
            Content    = "About Full Endpoint Management",
            FontFamily = Sys,
            Padding    = new Thickness(12, 6, 12, 6),
            Margin     = new Thickness(9, 0, 0, 0),
        };
        about.Click += (_, _) => showPlans();
        cta.Children.Add(compare);
        cta.Children.Add(about);
        card.Children.Add(cta);

        card.Children.Add(new TextBlock
        {
            Text         = "Optional. The steps above are all you need on your current plan — nothing here is gated behind an upgrade.",
            FontFamily   = Sys,
            FontSize     = 11.5,
            Foreground   = Muted,
            TextWrapping = TextWrapping.Wrap,
            Margin       = new Thickness(0, 10, 0, 0),
        });

        return new Border
        {
            Child           = new Border { Child = card, Padding = new Thickness(18, 16, 18, 16) },
            Background      = Card,
            BorderBrush     = new SolidColorBrush(Color.FromArgb(102, 0xF5, 0x53, 0x0A)),
            BorderThickness = new Thickness(1.5),
            CornerRadius    = new CornerRadius(8),
        };
    }

    // MARK: Local helpers

    static UIElement Breadcrumb(string parent, string current)
    {
        var r = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 0, 0, 14),
            VerticalAlignment = VerticalAlignment.Center,
        };
        r.Children.Add(new TextBlock { Text = parent, FontFamily = Sys, FontSize = 12, FontWeight = FontWeights.Medium, Foreground = Slate });
        r.Children.Add(new TextBlock
        {
            Text       = "",   // chevron right
            FontFamily = FluentIcons,
            FontSize   = 10,
            Foreground = Muted,
            Margin     = new Thickness(6, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        r.Children.Add(new TextBlock { Text = current, FontFamily = Sys, FontSize = 12, Foreground = Muted });
        return r;
    }

    static TextBlock SectionLabel(string t) => new()
    {
        Text       = t,
        FontFamily = Sys,
        FontSize   = 12,
        FontWeight = FontWeights.SemiBold,
        Foreground = Muted,
        Margin     = new Thickness(4, 22, 0, 9),
    };

    static StackPanel CardList() => new() { };

    static Border HairLine(Thickness? margin = null) => new()
    {
        Height     = 1,
        Background = Hair,
        Margin     = margin ?? new Thickness(0),
    };

    static Button AccentButton(string text) => new()
    {
        Content         = text,
        FontFamily      = Sys,
        FontSize        = 13,
        FontWeight      = FontWeights.SemiBold,
        Foreground      = White,
        Background      = Signal,
        BorderThickness = new Thickness(0),
        Padding         = new Thickness(14, 7, 14, 7),
        Cursor          = System.Windows.Input.Cursors.Hand,
    };

    static UIElement ReassuranceLine(string text)
    {
        var r = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 18, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        r.Children.Add(new TextBlock
        {
            Text       = "",   // lock glyph
            FontFamily = FluentIcons,
            FontSize   = 13,
            Foreground = Muted,
            Margin     = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        r.Children.Add(new TextBlock
        {
            Text         = text,
            FontFamily   = Sys,
            FontSize     = 12,
            Foreground   = Muted,
            TextWrapping = TextWrapping.Wrap,
        });
        return r;
    }
}
