# menubar/design — macOS design reference

Hi-fi mockup + annotated reference Swift for the macOS menu bar surface. **Design
reference, not production** — the shipping app is `menubar/PatchedUpdater/`.

```
agent/
  Patched Menu Bar Agent.html   Annotated board: tray-icon states + all popover states
  PatchedMenuBarAgent.swift     Reference SwiftUI MenuBarExtra (system font; `patched-ring-mark-slate.svg` (light bg) / `-mono.svg` (menu-bar template image))
```

The nav pane carries the brand **ring mark (`patched-ring-mark-slate.svg` / `-mono.svg`)** at the top of the left column
(`patched-ring-mark-slate.svg` (light bg) / `-mono.svg` (menu-bar template image)). Header is the screen title; the
agent popover header: ring mark + “Patched” in Archivo 600 (logo lockup).

Open the `.html` file in a browser to review.
