# App-launch alerting — real-time process monitoring design (PAT-606)

**Status:** accepted · **Date:** · **Epic:** PAT-551 Application Control

## Context

Application Control Tier 2 adds _app-launch alerting_: when an app not on
`app_control.app_allowlist` launches on a managed device, the agent emits an
audit event.  This is distinct from Tier 1 (approved-admins enforcement via
PAT-604/605), which runs in the existing periodic collection loop.

App-launch alerting fundamentally requires a different architecture: either
real-time OS hooks (EndpointSecurity on macOS, ETW on Windows) or a
high-frequency snapshot-diff approach.  This doc picks the implementation path
for each platform, explains the entitlement/SKU constraints that dictate the
timeline, and defines the event data model.

---

## Mechanism options

### macOS

| Mechanism | Real-time | Entitlement / privilege needed | Production-appropriate |
|---|---|---|---|
| **EndpointSecurity (ES)** | ✅ | `com.apple.developer.endpoint-security.client` — Apple approval required | ✅ (end-state) |
| **Spotlight `kMDItemLastUsedDate` diff** | ❌ (cycle latency) | None | ✅ (interim) |
| `opensnoop` / `fs_usage` | ✅ | Root + SIP-reduced or DTrace entitlement | ❌ (too noisy, high overhead) |
| `launchctl print` snapshot | ❌ (cycle latency) | None | ⚠️ (misses transient launches) |
| **OpenBSM** (`/dev/auditpipe`) | ✅ | Root | ❌ (deprecated, complex, high noise) |

**EndpointSecurity** is the architecturally correct end-state.  ES delivers
`ES_EVENT_TYPE_NOTIFY_EXEC` events in real time with full process metadata
(path, team ID, entitlements).  At Tier 3 the auth-variant
(`ES_AUTH_EVENT_TYPE_AUTH_EXEC`) can block the launch synchronously before
`execve()` returns.

The gate is the `com.apple.developer.endpoint-security.client` entitlement,
which requires:
1. Apple Developer Program membership (have it).
2. **Explicit Apple approval** via the Endpoint Security entitlement request
   form (developer.apple.com/contact/request/endpoint-security/).  Review takes
   2–6 weeks.  Apple evaluates the use-case; security-product vendors are
   routinely approved.
3. A **system extension** bundle (`.systemextension`), not a plain executable.
   System extensions run in user space, signed with the entitlement, and
   deployed via MDM.
4. An Intune **Configuration Profile** with the System Extensions payload
   (`com.apple.security.system-extension`) authorising the bundle ID and Team ID
   on supervised Macs.  UAMDM (User-Approved MDM) enrollment is sufficient;
   supervised enrollment is not required.

**Spotlight diff** (`mdls -name kMDItemLastUsedDate`) is the zero-entitlement
interim: the macOS metering collector already reads `kMDItemLastUsedDate` per
app bundle.  If that date advanced since the previous cycle, the app was
launched during the interval.  Latency equals the cycle interval (typically
15 s for trigger-initiated scans, up to 24 h for scheduled runs).  For Tier 2
_alert-only_ this is acceptable — the event reaches the server within minutes
rather than milliseconds.

### Windows

| Mechanism | Real-time | SKU / privilege needed | Production-appropriate |
|---|---|---|---|
| **ETW kernel process provider** | ✅ | Admin/SYSTEM (have it) | ✅ (end-state) |
| **`Process.GetProcesses()` diff** | ❌ (poll latency) | None | ✅ (interim) |
| WMI `Win32_ProcessStartTrace` | ✅ | Admin (have it) | ⚠️ (higher WMI overhead) |
| Security event log (event 4688) | ✅ | Audit policy must be on | ⚠️ (policy dependency) |
| AppLocker / WDAC | ✅ (block) | Enterprise/Education SKU | ❌ (SKU constraint, Tier 3 only) |

**ETW via `Microsoft-Windows-Kernel-Process`** (GUID
`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`) is the right end-state: low-overhead,
no SKU restriction, agent-owned, no audit-policy dependency.  Process-start
events carry `ImageFileName`, `ProcessId`, `ParentProcessId`, `CommandLine`, and
`UserSid`.  Implementation uses `Microsoft.Diagnostics.Tracing.TraceEvent`
(open-source, MIT, from Microsoft/perfview) or a native PInvoke session.

**`Process.GetProcesses()` diff** requires no new packages.  The Worker runs on
a 15 s trigger-poll; on each tick it diffs the current process list against the
previous snapshot, checking new process `MainModule.FileName` paths against the
allowlist.  Identical latency profile to the macOS Spotlight approach: suitable
for Tier 2 alerting.  This also eliminates the need for the
`Microsoft.Diagnostics.Tracing.TraceEvent` NuGet dependency in the initial
implementation.

**WMI `Win32_ProcessStartTrace`** works without audit policy but incurs higher
overhead and requires the WMI service to be running (it always is on managed
machines).  Not chosen for the interim because `Process.GetProcesses()` is
simpler and avoids WMI.

---

## Decision

### Tier 2 (alert-only) — ship now

**macOS:**  
Extend the collection cycle in `patched-upload.sh` / `patched-collect.sh` to
snapshot `kMDItemLastUsedDate` per app bundle, persist it across cycles in
`/Library/Application Support/Patched/app-launch-state.json`, and emit
`app_blocked` audit events for any app whose date advanced and whose bundle ID
is absent from `app_control.app_allowlist`.

Latency: cycle interval.  No new entitlement.  No system extension.

**Windows:**  
Extend `AdminEnforcer` (or a new `AppLaunchMonitor` service) to diff
`Process.GetProcesses()` on each `Worker` tick, comparing process exe paths
against the allowlist.  Emit `app_blocked` audit events for unapproved
processes.  No new NuGet dependency.

Latency: `TriggerPollInterval` (15 s default).  No SKU constraint.

### Tier 3 (real-time blocking) — future

**macOS:**  
Apply for the ES entitlement, build a Swift system extension, deploy via Intune
System Extensions payload.  Use `ES_AUTH_EVENT_TYPE_AUTH_EXEC` to intercept
launches synchronously.  XPC to the main LaunchDaemon to check the current
signed agent-config before responding `ES_AUTH_RESULT_ALLOW` /
`ES_AUTH_RESULT_DENY`.  Create implementation tickets after entitlement approval.

**Windows:**  
Add `Microsoft.Diagnostics.Tracing.TraceEvent` (or a minimal native
`StartTrace`/`EnableTrace` PInvoke shim), subscribe to the kernel process
provider, and act on process-start events in near-real-time.  For blocking,
Windows Defender Application Control (WDAC) can be pushed via Intune but requires
additional OS policy infrastructure outside the agent; the ETW approach stays
agent-owned and has no SKU dependency.

---

## Event data model

### Server schema extension needed

The `enforcement_audit` table (PAT-603) currently constrains `event_type` to:
`admin_removed`, `admin_removal_skipped`, `app_blocked`, `app_block_skipped`.

For Tier 2 (alert-only, no block taken), the semantically correct event is
`app_blocked` with a `details.alert_only: true` flag.  The event type name
matches the intent at Tier 3; at Tier 2 the flag disambiguates.  This avoids
a server migration for the interim implementation.

A future migration may add `app_launch_detected` as a dedicated Tier 2 type
once the full Tier 2 / Tier 3 split is validated in production.

### Event payload (POST `/v1/inventory/enforcement-audit`)

```json
{
  "events": [
    {
      "event_type": "app_blocked",
      "subject": "com.google.Chrome",
      "details": {
        "platform":       "macos",
        "display_name":   "Google Chrome",
        "bundle_id":      "com.google.Chrome",
        "version":        "126.0.6478.127",
        "last_used_at":   "2026-12-25T11:42:00Z",
        "alert_only":     true,
        "reason":         "not_in_allowlist"
      },
      "occurred_at": "2026-12-25T11:42:00Z"
    }
  ]
}
```

Windows variant — `subject` is the normalised exe name, `bundle_id` is absent:

```json
{
  "event_type": "app_blocked",
  "subject":    "chrome.exe",
  "details": {
    "platform":     "windows",
    "display_name": "Google Chrome",
    "exe_path":     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "pid":          12345,
    "alert_only":   true,
    "reason":       "not_in_allowlist"
  },
  "occurred_at": "2026-12-25T11:42:05Z"
}
```

### Allowlist matching

The `app_control.app_allowlist` from the signed agent-config contains platform-agnostic identifiers.  Agents apply platform-specific resolution:

**macOS:**  
Match `CFBundleIdentifier` of the app bundle (e.g. `com.google.Chrome`).
Fallback: match by display name if bundle ID is unavailable.

**Windows:**  
Match by exe filename (case-insensitive, e.g. `chrome.exe`) or by
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` display name.
The allowlist may contain either form; the agent checks both.  A future
refinement can add publisher name matching via Authenticode signer.

---

## Process exclusion rules

The following are never flagged regardless of policy:

**macOS:**
- Processes signed by Apple (`com.apple.*` bundle IDs, Team ID `Software Update`
  or `0000000000`).
- Processes whose executable path is under `/System/`, `/usr/`, `/bin/`,
  `/sbin/`.
- The Patched agent itself (`com.patched.agent`).
- Active MDM management tools (Intune, Jamf — identified by known bundle IDs).

**Windows:**
- Executables under `%SystemRoot%\System32\` and `%SystemRoot%\SysWOW64\`.
- Windows Defender, Security Center, Intune Management Extension, and known
  MDM-management processes (hardcoded list, updateable via agent-config in
  a future extension).
- The Patched agent itself (`Patched.Service.exe`).
- Parent PID = 4 (System) and parent PID = 0.

---

## Deployment and rollout

1. **Gated by `app_control.enabled`** — same flag as the admin-enforcement
   feature.  No alerting fires unless the tenant has Application Control enabled
   in their signed agent-config.
2. **`PATCHED_DRY_RUN=1`** — suppresses event POSTs; logs what would be emitted.
3. **Allowlist empty → skip all alerting** — parallel to the admin lockout
   protection: an empty `app_allowlist` disables app-launch checking silently,
   preventing spurious alerts before the policy is configured.
4. **Rollout tier:** requires `app_management` or higher tier in agent-config.

---

## Open questions and risks

| # | Question | Risk | Owner |
|---|---|---|---|
| 1 | **macOS ES entitlement approval timeline.** Apple review is 2–6 weeks; rejection is rare for legitimate security tools but possible. | Tier 3 macOS blocking depends on this. Mitigation: submit application now and proceed with the interim Spotlight approach in parallel. | Andy |
| 2 | **Spotlight `kMDItemLastUsedDate` precision on macOS.** Spotlight indexes are updated asynchronously; very short-lived processes (< ~2 s) may not update the metadata before the next cycle snapshot. | Some transient launches are missed at Tier 2. | Implementation |
| 3 | **`Process.GetProcesses()` requires `MainModule` access.** On Windows, reading `MainModule.FileName` for protected processes (e.g. anti-cheat, system services) throws `Win32Exception`. Must be guarded per-process. | Incomplete coverage of highly-protected processes; acceptable for Tier 2. | Implementation |
| 4 | **Allowlist identifier format is ambiguous.** Bundle IDs work cleanly on macOS; Windows exe names and display names diverge. A future agent-config extension may add per-platform overrides. | Some apps are mis-matched or missed. Mitigation: support both exe name and display name matching in Windows agent from the start. | PAT-607 (dashboard AC policy editor) |
| 5 | **Intune system-extension deployment on macOS.** Requires UAMDM enrollment. Customers who enrolled Macs without MDM supervision (rare but possible) cannot receive system extensions. | Tier 3 macOS not universally deployable. Mitigation: document prerequisite in install guide; flag un-supervised Macs in compliance posture. | PAT-604 follow-up |
| 6 | **ETW real-time session requires SeSystemProfilePrivilege.** The Patched service runs as SYSTEM which has this privilege, but explicit documentation should confirm this holds in constrained environments (CIS-hardened or PAM-managed hosts). | ETW session fails silently on some hardened hosts. | Implementation |

---

## Implementation tickets to create (after review)

- **PAT-609** (macOS Tier 2): Spotlight diff approach — extend collection cycle
  to emit `app_blocked` events for newly-launched unapproved apps.
- **PAT-610** (Windows Tier 2): `Process.GetProcesses()` diff on each Worker
  tick — emit `app_blocked` events for unapproved processes.
- **PAT-611** (server): Add `app_launch_detected` event type to
  `enforcement_audit` CHECK constraint (migration follow-up to PAT-603).
- **PAT-612** (macOS Tier 3, pending ES entitlement): Swift system extension +
  `ES_AUTH_EVENT_TYPE_AUTH_EXEC` integration.
- **PAT-613** (Windows Tier 3, future): ETW kernel process subscription.
- **PAT-614**: Apply for ES entitlement — submit application to Apple.
