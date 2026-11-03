# ADR-0005: Software metering data source (macOS)

**Status:** Accepted
**Deciders:** Andy (sole maintainer, pre-incorporation)
**Scope:** macOS only at v1. Windows metering is out of scope here (see "Open items").

---

## Context

The platform captures application *inventory* (what is installed) but not application *usage* (what is actually run). Software metering — last-used date and launch frequency per app — enables "installed but unused" reporting, licence right-sizing, and flagging stale/abandoned software as an attack surface. This ADR records how the macOS agent captures usage and how it flows through the pipeline.

The agent is a root-run script deployed via Intune, restricted to stock macOS CLI tools (no third-party dependencies). That constraint drives the source choice.

## Decision

**Use the macOS Spotlight metadata store as the sole metering source, read via `mdls`.**

Two attributes, read per app bundle:

| Attribute | Column | Meaning |
|---|---|---|
| `kMDItemLastUsedDate` | `device_apps.last_used_at` | Timestamp of the most recent launch via LaunchServices (what Finder shows as "Last opened") |
| `kMDItemUseCount` | `device_apps.launch_count` | **Lifetime cumulative** launch count |

Verified populated and updating in real time on macOS 26.5.1. The data carries **no TCC prompt and needs no Full Disk Access** for bundles in `/Applications` — app bundles are not TCC-protected locations.

### Pipeline changes
- **Agent** (`macos-agent/lib/apps.sh`, collector v0.10.0): two new optional fields per app — `last_used_at` (ISO 8601 or `null`), `launch_count` (integer or `null`) — plus a top-level `metering_status` provenance field (see below). `schema_version` stays at **3** (additive optional fields, consistent with the 0.7.0/0.8.0 precedent).
- **Payload struct** (`payload.go`): `appPart.LastUsedAt`/`LaunchCount` as `*string` / `*int` pointers (absent ≠ real zero); `payload.MeteringStatus` string.
- **DB** (migration `0020`): two nullable `device_apps` columns + `idx_device_apps_last_used_at`, plus `devices.metering_status`.
- **Extractor** (`upsertApps` / `upsertDevice`): `COALESCE(EXCLUDED.x, …)` — a payload that omits a field preserves the stored value rather than nulling it.

### `metering_status` — distinguishing "never launched" from "no data"

A `NULL` usage value is ambiguous on its own: it could mean the app was genuinely never launched, or that no usable data was collected. The agent emits a per-device `metering_status` so consumers can tell them apart:

| Status | Meaning | How to read a NULL app usage value |
|---|---|---|
| `ok` | Indexing on + console user resolved (reliable read) | **Genuinely never launched** |
| `spotlight_disabled` | `mdutil -s /` reports indexing off | Unknown — every app is NULL, no information |
| `no_user_session` | Indexing on but no console user; best-effort root read | Low confidence — per-user store may be invisible |
| *(NULL)* | Older / non-macOS agent | Unknown — metering not collected |

Only `ok` licenses the "installed but unused" interpretation. This is the v1 resolution of what was previously a deferred open item.

## Alternatives rejected

- **LaunchServices / `lsregister -dump`** — a *registration* database (paths, UTIs, handlers). Contains no usage data. Undocumented, unstable output. Useful only as an inventory source.
- **Unified logging (`log show`)** — launch events are derivable (`com.apple.launchservices`, `runningboardd` assertions) but: app names default to `<private>` redaction (needs an `Enable-Private-Data` profile to read), the log store is ~1.5 GB with only days-to-weeks of retention, and the format is noisy/fragile. Reserved for a future need for session duration or sub-day granularity only.
- **Bundle xattrs / quarantine plists** — verified: usage data is *not* an extended attribute on the bundle and not in any plist. It exists only in the Spotlight store, injected by LaunchServices at launch time.

## Key constraints & failure modes

These are inherent to the Spotlight source and are handled in the agent (see `apps.sh` header comment):

1. **Per-user store, root agent.** The metadata is written per-user by LaunchServices in the logged-in user's session. A root global-context `mdls` can return nulls. **Mitigation:** reads run in the console user's context via `launchctl asuser <uid> sudo -u <user> /usr/bin/mdls …`, resolving the console user with `stat -f%Su /dev/console`. No interactive user → best-effort root read.
2. **Spotlight indexing disabled** (`mdutil -i off`, e.g. via MDM) → the store is dead and every app reads null, which would falsely look like "every app unused". **Mitigation:** probe `mdutil -s /` once; skip the reads when indexing is off. (The emitted JSON is still `null` either way — see semantics below.)
3. **`mdls` prints "could not find …" to STDOUT (exit 0)** for an unreadable bundle. **Mitigation:** `launch_count` is accepted only if digits-only; the date is normalised through `date -f` which drops anything unparseable.
4. **LaunchServices-only.** Last-used reflects launches via Finder/Dock/`open`/Spotlight. Apps started by direct `exec` or some login items may under-report.

## Semantics (the important bit for consumers)

- **A `NULL` usage value is "definitely unused" only when `metering_status = "ok"`.** The per-device `metering_status` field (see above) resolves the ambiguity: under `ok`, a `NULL` `last_used_at` is positive evidence of non-use; under `spotlight_disabled` / `no_user_session` / absent, it is *unknown*. Consumers must check `metering_status` before treating a NULL as "unused".
- **`launch_count` is lifetime-cumulative, not windowed.** "Launches in the last N days" must be derived server-side by diffing successive readings. v1 stores the raw count only.

## What this enables / explicitly defers

**v1 captures and stores.** No report or UI consumes the columns yet.

**Open items (follow-up work):**
- Reporting surface: "installed but unused", "last used > N days", per-tenant stale-software view (PDF + admin UI). Must filter on `metering_status = 'ok'` so a Spotlight-disabled device isn't reported as "everything unused".
- Server-side windowed launch deltas (diff successive `launch_count` readings).
- Windows metering (no Spotlight equivalent; candidate sources: `Root\CIMV2` `Win32_*`, UserAssist registry, or AppCompat/Amcache — separate ADR).
