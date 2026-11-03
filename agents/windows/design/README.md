# windows/design — Windows design reference

Hi-fi mockups + annotated reference C# (WinUI 3) for the two Windows surfaces.
**Design reference, not production** — the shipping agent is `windows/src/`.

```
agent/
  Patched Tray Agent.html       Annotated board: tray-icon states (light/dark taskbar) + all flyout states
  PatchedTrayAgent.cs           Reference WinUI 3 tray flyout (Segoe UI, Mica; `patched-ring-mark-slate.svg` / `-mono.svg`)
```

The tray flyout header carries the brand **ring mark (`patched-ring-mark-slate.svg` / `-mono.svg`)**
beside "Patched" in Segoe UI 600 (logo lockup).

Open the `.html` files in a browser to review. Platform-neutral content matches
the macOS surfaces (Edge instead of Safari, BitLocker, CIS Windows 11 benchmark).
Windows 11 Fluent idiom: Mica, caption buttons, an orange accent.
