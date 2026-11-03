using System.Runtime.Versioning;
using System.Windows;
using Patched.Shared.Removal;

namespace Patched.Tray;

/// <summary>
/// PAT-1623: the removal notify/defer prompt window. Plain language only —
/// names the app, says it will be removed once closed, no countdown, no
/// threat. The Defer button is unconditional (see RemovalPromptWindow.xaml's
/// header comment and RemovalPromptPolicy.CanAlwaysDefer): there is no
/// "no deferrals remaining" state for this window under any circumstance.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class RemovalPromptWindow : Window
{
    private readonly PendingRemovalPrompt _pending;
    private readonly Action _onDefer;

    public RemovalPromptWindow(PendingRemovalPrompt pending, Action onDefer)
    {
        _pending = pending;
        _onDefer = onDefer;
        InitializeComponent();

        HeaderText.Text = $"{pending.Name} is still open";
        BodyText.Text =
            $"Your organisation has asked Patched to remove {pending.Name}. " +
            "It will be removed the next time you close it.";
    }

    private void DeferButton_Click(object sender, RoutedEventArgs e)
    {
        _onDefer();
        Close();
    }

    private void OkButton_Click(object sender, RoutedEventArgs e) => Close();
}
