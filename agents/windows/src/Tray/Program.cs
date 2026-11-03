using Patched.Shared.DeviceClassification;
using Patched.Tray;

// PAT-1959: Server Core has no desktop, so the tray does not start there. The decision
// and every rule behind it live in TrayStartupPolicy, which is unit-tested; this is only
// the call site. The service is unaffected and keeps running normally on Server Core.
if (!TrayStartupPolicy.ShouldStart(InstallationTypeProbe.Read()))
{
    return;
}

// Single-instance guard — only one tray app per session.
using var mutex = new Mutex(true, "PatchedAgentTray", out bool isNew);
if (!isNew)
{
    // Surface the existing window rather than spawning a second instance.
    return;
}

// Run both the WPF message loop (for the window) and the WinForms tray icon
// on the same STA thread.
var app = new System.Windows.Application { ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown };

using var trayController = new TrayController(app);
trayController.Initialize();

app.Run();
