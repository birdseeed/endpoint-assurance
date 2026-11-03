# The never-interrupt gate (PAT-1624)

The agent must never put a window in front of somebody who is on camera, on a
call, presenting, or in Focus. There is one gate, `canInterruptNow()`, and every
user-facing prompt the agent raises consults it. That is the macOS OS-update
blocking prompt (PAT-273) and, since PAT-1623, the removal notify/defer
prompt on both macOS and Windows — the first surface this gate protects on
Windows at all; Windows still has no OS-update blocking prompt of its own.

The rule is not "camera". Special-casing the camera produces a second gap the
first time somebody dials into a call with video off.

## Where the code is

| Platform | File | What it is |
| --- | --- | --- |
| macOS | `menubar/PatchedUpdater/InterruptionGate.swift` | The four signal readers and the decision. |
| macOS | `menubar/PatchedUpdater/InterruptionPolicy.swift` | The four bounds, defaults, and the managed-tier rule. |
| macOS | `menubar/PatchedUpdater/PromptPresentationGovernor.swift` | Counters, the bounded fallback, the operator signal. |
| macOS | `menubar/PatchedUpdater/UserSessionState.swift` | Active-and-unlocked, so absence is not counted as suppression. |
| macOS | `menubar/PatchedUpdater/AgentEventLog.swift` | JSON-lines suppression events and the operator-signal marker. |
| macOS | `menubar/PatchedUpdater/StatusStore.swift` | Call sites: `attemptBlockingPromptPresentation` (PAT-273) and `attemptRemovalPromptPresentation` (PAT-1623). |
| macOS | `menubar/PatchedUpdater/RemovalPromptPolicy.swift`, `RemovalPromptView.swift`, `UninstallStatus.swift` | PAT-1623: removal's own defer/terminal policy (deliberately not shared with `InterruptionPolicy`), window, and `uninstall-status.json` reader. |
| Windows | `windows/src/Shared/Interruption/` | The same four pieces, content-equivalent. First call site landed PAT-1623 (below) — still no Windows OS-update blocking prompt. |
| Windows | `windows/src/Shared/Removal/RemovalPromptEvaluator.cs`, `RemovalPromptPolicy.cs` | PAT-1623: the removal notify/defer presentation logic and policy, called from `windows/src/Tray/TrayController.cs`. Note: the backend that would populate `uninstall-status.json` in production (`RemovalRunner.cs`/`DeviceRemovalRunner.cs`) is excluded from the shipping `Patched.Service.exe` under PAT-1531 — see that ticket and this ticket's (PAT-1623) report for the gap this leaves. |
| Contract | `contracts/agent-config.schema.json` -> `interruption_policy` | The four tunable numbers. |

## The signals

Each signal answers idle, busy, or unreadable. Any busy suppresses. Any
unreadable also suppresses, because the rule is fail closed toward silence: a
delayed prompt costs a day, a window over a customer demo costs the account.

### macOS

| Signal | How | Notes |
| --- | --- | --- |
| Camera | CoreMediaIO `kCMIODevicePropertyDeviceIsRunningSomewhere` over `kCMIOHardwarePropertyDevices` | No `AVCaptureDevice`, no `AVCaptureSession`, so no TCC consent prompt and no privacy indicator. Verified empirically: clean run, zero TCC.db entry, zero TCC unified-log lines. |
| Microphone | CoreAudio `kAudioDevicePropertyDeviceIsRunningSomewhere` | Filtered to devices with input channels. Without that filter every played track reads as a call and the agent goes silent for good on a machine that plays music. |
| Presenting | `CGDisplayMirrorsDisplay`, plus a frontmost layer-0 window whose bounds cover a whole `CGDisplayBounds` | Geometry only. Window *titles* would need Screen Recording; bounds do not. |
| Focus | `~/Library/DoNotDisturb/DB/Assertions.json`, `data[].storeAssertionRecords` non-empty | Best effort, see below. |

### Windows

| Signal | How |
| --- | --- |
| Camera | `HKCU\...\CapabilityAccessManager\ConsentStore\webcam`, including `NonPackaged`: held when `LastUsedTimeStart` is non-zero and `LastUsedTimeStop` is zero. |
| Microphone | The same under `\microphone`. Needed because a windowed Teams call does not reliably set a busy notification state. |
| Presenting | `SHQueryUserNotificationState`: `QUNS_BUSY`, `QUNS_RUNNING_D3D_FULL_SCREEN`, `QUNS_PRESENTATION_MODE`, `QUNS_APP`. |
| Focus | `SHQueryUserNotificationState`: `QUNS_QUIET_TIME`. |

`QUNS_ACCEPTS_NOTIFICATIONS` is the only state that permits a window.
`QUNS_NOT_PRESENT` is absence, not suppression, and drives the session check
rather than the gate.

### Why Focus on macOS is best effort

macOS has no public, stable API for reading the current Focus mode, and the
ticket rules out adding a TCC-gated permission to get one. The Do Not Disturb
assertion store in the user's own home directory is the only non-private
technique that works, and its shape is undocumented. The rules are chosen so
being wrong is cheap:

* File missing entirely reads as idle. A Mac that has never used Focus has no
  database, and treating that as unreadable would fail closed on every such
  machine and silence the agent permanently.
* File present but unparseable reads as unreadable, which suppresses. If Apple
  changes the file the agent gets quieter, never louder.
* A non-empty `storeAssertionRecords` reads as busy.

A false negative costs nothing extra: camera, microphone and presenting still
carry the gate. A false positive only delays a prompt.

## Behaviour

Suppression **delays**, it never cancels. Each suppressed attempt is retried on
the next tick of `StatusStore.scheduleBlockingPromptTimer` (2 hours) and on the
existing `startUnlockObservation` unlock observer.

Suppression **never consumes, extends or resets the deferral budget**. Nothing
on the suppression path reads or writes `deferrals_remaining` and nothing writes
an `os_defer` marker. Only a human pressing Defer spends a deferral. Otherwise
somebody who is genuinely on camera all day sits past an OS-update deadline by
accident and the deadline stops meaning anything. There is a test that asserts
`update-status.json` is byte-for-byte identical across a full suppressed cycle.

## Bounds

Anchored to what already exists: the blocking reminder interval is 2 hours,
`os_update_policy.blocking_window_days` is 3, `deferral_budget` is 5.

1. Stop presenting after **8 active hours** of unbroken suppression, which is 4
   consecutive suppressed attempts at the 2-hour retry. The hours are the
   policy; the attempt cap is derived from the hours and the live retry
   interval, so changing the retry interval later cannot silently change the
   policy.
2. Then fall back to a **notification, at most once a day**. The OS already
   handles notifications correctly in a call and under Focus: it delivers them
   quietly rather than over the screen share.
3. **Signal the operator after 3 consecutive days** with no successful
   presentation, matching `blocking_window_days`. One busy day is a normal
   calendar and needs no human. Three is a person the agent cannot reach.
4. Counters accrue **only while a user session is active and unlocked**, and
   reset on any successful presentation. Locked or logged out is absence, not
   suppression: a laptop shut in a bag for a day must not arrive at "cannot be
   prompted" having never been near a camera.

These bounds gate presentation, not the deadline. The deadline keeps running
underneath. A device that cannot be prompted for three days inside a three-day
blocking window reaches the deadline with the user never having seen the prompt.
The operator is told and decides. Patched does not force a window over
somebody's call to make a deadline.

## Tier placement

The gate is **unconditional and applies at every tier**, assurance included. It
is a restraint, not a capability, and the OS-update prompt it protects against
has no tier gate anywhere. Shipping the suppression only to managed-tier
customers would leave assurance customers, which is the launch offer, receiving
windows over their calls.

The four numbers above are per-tenant `agent-config` settings at **managed tier
only**, in the `interruption_policy` block:

| Setting | Default | Range |
| --- | --- | --- |
| `suppression_window_hours` | 8 | 1 to 168 |
| `max_suppressed_attempts` | null (derive from the window) | 1 to 1000 |
| `notification_fallback_interval_hours` | 24 | 1 to 168 |
| `operator_signal_after_days` | 3 | 1 to 365 |

An override delivered to a non-managed tier is ignored outright rather than
partially applied. An out-of-range value is dropped field by field and the
default stays, rather than being clamped to something the operator did not ask
for.

## Privacy

The agent evaluates a boolean at decision time and keeps nothing. It does not
record or upload which application held the camera, when, or for how long.
"Camera in use 14:02 to 15:30" is attendance monitoring, and Patched sells to
organisations that will have an employee representative asking exactly this.

A suppression event carries the surface, the reason code, the attempt number,
the attempt cap and the suppressed-day count. Nothing else. The reason codes are
a fixed vocabulary, identical on both platforms, and there are tests on both
sides that fail if an application, bundle, process or duration field is ever
added to an event.

The disclosure copy is in the agent popover, which is the only end-user surface
the agent has left (PAT-1617):

> Patched checks whether your camera or microphone is in use so that it does not
> interrupt you, and records nothing about it.

## Where the events go

macOS writes JSON lines to `~/Library/Logs/Patched/agent.jsonl`, in the same
`{ts, level, component, msg, fields}` shape as
`macos/patched-collect.sh`'s `log_jsonl`, so one parser reads both. The
menu-bar app is unprivileged and cannot write to the root-owned
`/Library/Logs/Patched`.

The operator signal is a marker file in the daemon's trigger directory, which is
the only outbound channel an unprivileged menu-bar app has. The extension is
`.marker`, not `.trigger`: the daemon consumes at most one `*.trigger` per run
and deletes it, so a `.trigger` here would be silently eaten and would displace
a real deploy or scan request. The filename is fixed, so re-signalling overwrites
and the directory never accumulates, and it is removed on the next successful
presentation.

**Known gap.** Nothing on the daemon side folds that marker into the
`agent_health` payload yet, so the signal is durable and local but is not
uploaded. That wiring is a follow-up, not part of PAT-1624.

## Windows call site

There is currently **no agent-raised prompt on Windows to gate**. Everything the
tray shows is user-initiated: `TrayController.ToggleFlyout` on a left click and
`ShowStatusWindow` on a double click or the context menu. There is no OS-update
blocking window (`OsUpdateStateEngine` computes state for the payload and
nothing presents it) and no toast. The gate, the bounds and the policy exist in
`windows/src/Shared/Interruption/` at parity and are fully tested, so the first
Windows prompt that lands consults them in one line rather than shipping without
suppression. Until then this side is deliberately inert.
