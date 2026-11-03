# Inventory payload schema

This is the canonical reference for the JSON document that `patched-collect.sh` (and future agents) POST to `POST /v1/inventory`.

**Single source of truth.** The same shape is described three ways: this doc (human-readable), `payload.schema.json` (machine-readable JSON Schema for validation), and `internal/extractor/payload.go:payload` (the Go struct the extractor unmarshals into). If they diverge, the Go struct wins — it is the runtime authority.

---

## Schema versioning

The top-level `schema_version` integer lets the extractor detect and reject shapes it hasn't been tested against. Supported range: **2–3**.

| Version | Introduced | Notes |
|---|---|---|
| 1 | internal, never deployed | Pre-release. Not in production. Extractor marks v1 rows with `extraction_error` and skips them. |
| 2 | collector v0.2.0 (2026) | Production macOS shape. `hardware`, `security_tools`, `system_extensions`, `background_items`, `icloud` present and required. `apps` use `bundle_id` as the identifier field. |
| 2 + 0.3.0 additions | collector v0.3.0 | `pending_updates` and `patches` arrays added. Both optional; extractor silently ignores absent arrays. |
| 3 | collector v0.4.0 (planned); Windows agent v0.1.0 | **Two changes folded into one revision:** (1) T2 compliance signals in the `compliance` bag (ADR-0001); (2) Windows compatibility — adds top-level `platform` field, `identifier` replaces `bundle_id` as the primary app identifier, macOS-only sections (`system_extensions`, `background_items`, `icloud`) become optional. See [Schema v3 changes](#schema-v3-changes). |

**Adding a v4:** bump `maxSupportedSchemaVersion` in `internal/extractor/extractor.go`, update `payload.schema.json` enum, update this doc. If new top-level fields are added, update `payload.go` too.

---

## Top-level envelope

| Field | Type | Required | Example | Notes |
|---|---|---|---|---|
| `schema_version` | integer | **yes** | `2` or `3` | Must be 2–3; extractor rejects other values. |
| `platform` | string | v3+ | `"macos"` or `"windows"` | Normalised platform discriminator. **Required in v3; absent in v2.** Extractor defaults absent value to `"macos"`. Used to filter which compliance rules apply to this device. |
| `agent` | string | yes | `"patched-collect"` | Identifies the collector binary. |
| `agent_version` | string | yes | `"0.3.0"` | Semver of the collector script. Stored in `devices.agent_version`. |
| `tenant_id` | string | yes | `"UNKNOWN"` or UUID | Read from `/etc/patched/tenant-id`. Falls back to `"UNKNOWN"` if file absent. |
| `collected_at` | string (ISO 8601 UTC) | yes | `"2026-11-15T14:23:01Z"` | Collection timestamp, UTC. |
| `metering_status` | string | v0.10.0+ | `"ok"` | Software metering provenance (platform-neutral). One of `ok` / `spotlight_disabled` / `no_user_session` / `userassist_unavailable` / `unavailable`. Stored in `devices.metering_status`. Determines how to read null app usage values — see [Software metering](#software-metering-windows-and-macos). Absent on older/non-macOS agents. |
| `device` | object | yes | — | Hardware identity. See [Device object](#device-object). |
| `hardware` | object | yes | — | Hardware specs. See [Hardware object](#hardware-object). |
| `os` | object | yes | — | OS identification. See [OS object](#os-object). |
| `compliance` | object | yes | — | Flat bag of compliance signals. See [Compliance object](#compliance-object). |
| `security_tools` | array | yes | `[]` | Detected third-party AV/EDR agents. Cross-platform. See [Security tools array](#security-tools-array). |
| `system_extensions` | array | v2 only | `[]` | Loaded system extensions (macOS 13+). Required in v2; omit in Windows v3 payloads. See [System extensions array](#system-extensions-array). |
| `background_items` | array | v2 only | `[]` | BTM-tracked login items / launch agents (macOS only). Required in v2; omit in Windows v3 payloads. See [Background items array](#background-items-array). |
| `icloud` | object | v2 only | — | iCloud/Apple ID presence (macOS only). Required in v2; omit in Windows v3 payloads. See [iCloud object](#icloud-object). |
| `pending_updates` | array | no | `[]` | Outstanding software updates. Optional. See [Pending updates array](#pending-updates-array). |
| `patches` | array | no | `[]` | Software update install history. Optional. Added in macOS collector 0.3.0. See [Patches array](#patches-array). |
| `collection_status` | object | no | — | General home for the collection status of top-level array sections. Optional. Added PAT-1732. Recognised keys: `certificates` (PAT-1732), `apps` (PAT-2063), `apps_users` (PAT-2075) and `safari_extensions` (PAT-2067). See [Collection status object](#collection-status-object). |
| `certificates` | array | no | `[]` | System Keychain certificate inventory. Optional. Added in macOS collector 0.7.0 (PAT-216/PAT-220). Each element has `subject_cn`, `issuer_cn`, `sha1`, `not_after`, `days_until_expiry`, `ext_key_usage`, `basic_constraints_ca`, `is_self_signed`, `store` (PAT-1738, see below). Persisted into `device_certificates`. `collection_status.certificates` (PAT-1732) changes how a degraded collection is handled — see [Collection status object](#collection-status-object). |
| `hardware_health` | object | no | — | Battery, storage volume, and physical disk health snapshot. Optional. Added in macOS collector 0.8.0 (PAT-251). See [Hardware health object](#hardware-health-object). |
| `local_admins` | object | no | — | Standing local administrator roster (account names), behind the `local_admin_count` compliance signal. Optional at the schema level for backward compatibility (an agent predating PAT-1974 omits it entirely), but every current Windows and macOS agent sends it unconditionally. See [Local admins object](#local-admins-object). |
| `firmware` | object | no | — | Windows (PAT-2262). BIOS, system and baseboard identity as the firmware reports it, with `collection_status` for the block and each section. Absent means not reported (an older agent, or macOS) and is a strict no-op; `unavailable` means the agent tried and read nothing. Observation only. See [Firmware object](#firmware-object). |
| `kernel_drivers` | object | no | — | Windows (PAT-2263). Installed and loaded kernel and file-system drivers identified by hash, plus the vulnerable driver blocklist enforcement state. Absent means not reported (an older agent, or macOS) and is a strict no-op. See [Kernel drivers object](#kernel-drivers-object). |
| `homebrew` | object | no | — | macOS only. Homebrew formulae, casks and taps read from disk (PAT-2012 agent, PAT-2013 platform), with their own `collection_status`. Absent means an agent that predates the collector or holds it off the wire; a strict no-op. See [Homebrew object](#homebrew-object). |
| `ide_extensions` | object | no | — | Both platforms. Every VS Code, VS Code Insiders, Cursor and Windsurf extension and every JetBrains plugin per local user (PAT-2017 agents, PAT-2021 platform), with its own `collection_status`. See [Tooling objects](#tooling-objects-ide_extensions-package_managers-local_models-mcp_servers). |
| `package_managers` | object | no | — | Both platforms. Global npm, pip user-site and pipx packages per local user (PAT-2018 agents, PAT-2021 platform). See [Tooling objects](#tooling-objects-ide_extensions-package_managers-local_models-mcp_servers). |
| `local_models` | object | no | — | Both platforms. Ollama, LM Studio and llama.cpp installations and the models in their stores, names and sizes only (PAT-2019 agents, PAT-2021 platform). See [Tooling objects](#tooling-objects-ide_extensions-package_managers-local_models-mcp_servers). |
| `mcp_servers` | object | no | — | Both platforms. MCP servers configured in Claude Desktop, Cursor, VS Code, Windsurf and Claude Code, reduced to name, transport, executable, package and host (PAT-2020 agents, PAT-2021 platform). A server entry with any other field rejects the whole payload (privacy guard). See [Tooling objects](#tooling-objects-ide_extensions-package_managers-local_models-mcp_servers). |
| `browser_extensions` | array | no | `[]` | Browser extension inventory (Chrome, Edge, Firefox, Safari). Optional. Added in macOS collector 0.9.0 (PAT-125). Each element has `browser`, `profile`, `user_account`, `extension_id`, `name`, `version`, `enabled`, `permissions`, `host_permissions`, `from_webstore`, `update_url`. `browser`, `profile`, `user_account`, `extension_id` are validated as required keys at ingestion (PAT-871); an entry where one of those has a present-but-empty value passes validation but is skipped and logged by the extractor rather than failing the whole device snapshot, since `device_browser_extensions` declares `user_account`/`profile` NOT NULL. **Safari rows are the one exception (PAT-2064):** Safari extensions live in an app bundle, not a browser user profile, so the agent sends `user_account: null` and no `profile` for them. The extractor stores both as the fixed sentinel `_system` instead of skipping the row — every other browser still requires both fields non-empty. Safari rows are never marked removed by the device-wide completeness report described under [Browser extensions status object](#browser-extensions-status-object), because that report has no Safari vocabulary to be complete about (PAT-2067 tracks giving Safari its own completeness signal). Persisted into `device_browser_extensions`; `risk_level` computed server-side. |
| `browser_extensions_status` | object | no | — | Both platforms. Completeness of `browser_extensions`, per user and browser, plus `cap_reached` (PAT-2055). Absent means an agent that predates it: unknown, and readers keep the pre-PAT-2055 behaviour. See [Browser extensions status object](#browser-extensions-status-object). |
| `compliance_findings` | array | no | `[]` | Configuration/CIS advisory findings (PAT-300/481). Optional — older collectors omit. Carries only violations. See [Compliance findings array](#compliance-findings-array). |
| `compliance_assessments` | object | no | — | Positive per-control attestation (PAT-913). `controls_assessed` lists the finding-control IDs the agent actually evaluated this run. Optional — agents predating PAT-913 omit it, which scores every finding-control as never-attested. See [Compliance assessments object](#compliance-assessments-object). |
| `os_update` | object | no | — | OS-update-currency verdict the agent computes locally (SOFA feed on macOS, WUA COM on Windows). Optional. Both agents send it: the Windows agent on every run, the macOS agent when its local verdict is fresh and passes the contract. Stored in `device_os_update`; the customer portal prefers this explicit OS verdict over legacy `pending_updates` (PAT-2338). See [OS update object](#os-update-object). |
| `apps` | array | yes | — | Installed application inventory. Whether apps it omits count as removed depends on `collection_status.apps` (PAT-2063). See [Apps array](#apps-array). |

---

## Device object

Parsed by `payload.go:devicePart`. Cross-platform fields are required; macOS-only fields are optional in v3.

| Field | Type | Required | macOS source | Windows source |
|---|---|---|---|---|
| `serial` | string | yes | `ioreg` IOPlatformSerialNumber | BIOS serial via WMI |
| `hw_uuid` | string (UUID or `"Unknown"`) | yes | `ioreg` IOPlatformUUID | SMBIOS UUID via WMI |
| `hostname` | string | yes | `scutil --get LocalHostName` | NetBIOS hostname |
| `computer_name` | string | macOS only | `scutil --get ComputerName` | absent on Windows |
| `hw_model` | string | yes | `sysctl -n hw.model` | WMI ComputerSystemProduct.Name |
| `arch` | string | yes | `uname -m` | `"x86_64"` or `"arm64"` |
| `last_boot` | string (ISO 8601 UTC or `"Unknown"`) | yes | `sysctl -n kern.boottime` | WMI Win32_OperatingSystem.LastBootUpTime |

The extractor prefers `hw_uuid` as the stable device identity (upsert key: `UNIQUE(tenant_id, hw_uuid)`). If `hw_uuid` is not a parseable UUID it falls back to `serial`. A payload where both are missing/unparseable is rejected.

---

## Hardware object

Source: `patched-collect.sh` lines 130–140 (`sysctl`, `df`). Stored verbatim as JSONB in `devices.hardware`.

| Field | Type | Example | Source |
|---|---|---|---|
| `cpu_model` | string | `"Apple M2"` | `sysctl -n machdep.cpu.brand_string` |
| `cpu_cores` | integer | `8` | `sysctl -n hw.ncpu` |
| `ram_gb` | integer | `16` | `sysctl -n hw.memsize` ÷ 1 GiB |
| `disk_total_gb` | float | `494.4` | `df -k /System/Volumes/Data` |
| `disk_free_gb` | float | `312.1` | `df -k /System/Volumes/Data` |

---

## OS object

Source: `sw_vers` (macOS). Parsed by `payload.go:osPart`.

| Field | Type | Required | Example |
|---|---|---|---|
| `name` | string | yes | `"macOS"` |
| `version` | string | yes | `"15.4.1"` |
| `build` | string | yes | `"24E263"` |

`device_class`, `installation_type` and `os_caption` (PAT-1960) are **not** part of this object — see "Device class fields (PAT-1960)" below. They moved off `os` deliberately: `device_class` is a property of the machine, not of the operating system, matching where the `devices.device_class` column lives, and `os_caption` is only a sensible field name at the top level (nested under `os` it would just be `caption`).

---

## Device class fields (PAT-1960)

Three **top-level** envelope fields, sibling to `platform`, not nested under `os`. Parsed by `payload.go:payload` (`DeviceClass`, `InstallationType`, `OSCaption`).

| Field | Type | Required | Example |
|---|---|---|---|
| `device_class` | string enum: `workstation` \| `server` \| `domain_controller` \| `unknown` | no | `"server"` |
| `installation_type` | string | no | `"Server Core"` |
| `os_caption` | string | no | `"Microsoft Windows Server 2022 Standard"` |

Optional and additive: the Windows agent side ships under PAT-1959, and macOS never sends them — the envelope stays platform-neutral either way. Persisted to `devices.device_class` / `devices.installation_type` / `devices.os_caption` (migration `0158_device_class.sql`).

`device_class` is what drives rule matching (see "Device-class rule matching (PAT-1960)" below); `installation_type`/`os_caption` are informational only.

`device_class`'s enum includes the literal `"unknown"` — a genuine PAT-1959 report that its source was absent, unreadable or contradictory, never a guess. Three payload shapes all resolve server-side to `devices.device_class = 'unknown'` in `upsertDevice`, and are matched against every enabled rule for the device's platform exactly like a device with no `device_class` column at all before this migration (see the rule-matching section below for why that fallback is deliberate):

- the field absent entirely (pre-PAT-1959 agent),
- the field present with the literal value `"unknown"`,
- an out-of-enum value (never rejected by `ValidatePayload` here — the enum check only rejects a *present* value outside the four-item vocabulary, same posture as `platform`).

Only the first two are indistinguishable from "no new information" for the purpose of an **update**: `upsertDevice` never downgrades an already-known classification (e.g. a stored `server`) back to `unknown` just because a later ingest omits the field or explicitly reports `"unknown"` this run — see `internal/extractor/upsert.go`'s `deviceClassGiven`.

### Device-class rule matching (PAT-1960)

A `compliance_rules` row carries an optional `device_class TEXT[]`. `NULL` means the rule applies to every device class (every macOS rule today, and any future class-agnostic Windows rule); a populated array names the exact `devices.device_class` values it applies to. The existing 53-row CIS Microsoft Windows 11 pack was backfilled to `{workstation}` by migration `0158`, so a Windows Server device no longer scores against it.

A rule applies to a device when:

```
cr.device_class IS NULL
OR d.device_class = ANY(cr.device_class)
OR d.device_class = 'unknown'
```

The third clause is deliberate and load-bearing: every device is `'unknown'` until an agent reports a real class (PAT-1959, Windows-only for now), and `'unknown'` must keep exactly the pre-PAT-1960 behaviour — evaluated against every enabled rule for its platform — rather than instantly flipping the whole existing Windows estate to "not assessed". A device whose class *is* known and matches no enabled rule for its platform (e.g. a `server` device under the workstation-only Windows 11 pack) produces zero evaluations and is reported as "not assessed: no benchmark for this device class" rather than scored — see `go-service/internal/report/executive.go` (`ControlCoverage.NotAssessedDevices`) and the portal `/v1/portal/control-coverage` response.

Applied in `internal/evaluator.LoadRules`/`LoadRulesForTenant` (evaluation time), `internal/report.fetchControlCoverage` and `report.Fetch`'s benchmark-totals query (report time), and the portal control-coverage handler.

---

## Compliance object

A flat object. All values are either strings or integers. The extractor's `buildSignalsMap` (`upsert.go:263`) normalises everything to strings before writing to `compliance_signals`. Numeric fields are therefore stored as their string representation (e.g. `"1"` not `1`).

### Signal value contract (PAT-1767)

Every non-reserved bag value (the reserved finding-control keys use the separate Pass/Fail/Unknown attestation model below, not this one) is exactly one of:

1. **A real value.** The read succeeded and the setting is present. Unchanged from before this contract existed.
2. **The exact string `"NotConfigured"`** (case-sensitive, no spaces). The read succeeded and the setting is absent — no policy key, no managed pref, no registry value. The rule decides what the OS default means for compliance via `compliance_rules.treat_not_configured_as`.
3. **JSON `null`, or the exact string `"Unknown"`.** The read itself failed (command errored, access denied, exception thrown, timeout, unparseable output). Both spellings are accepted. Most established macOS signals use `null` and Windows signals use `"Unknown"`; PAT-1752's new platform-neutral `mdm_enrolled` and `mdm_enrolled_via_dep` fields deliberately use the shared `Yes` / `No` / `Unknown` enum on macOS too.

The evaluator (`internal/evaluator/evaluator.go`) resolves state 2 via the rule's effective `treat_not_configured_as` (falling back to `treat_unknown_as` when unset — `effectiveTreatNotConfiguredAs`, the one place that fallback happens) and never lets `"NotConfigured"` reach a comparator. State 3 always resolves via `treat_unknown_as`: `null` never enters the signals map, so it takes the absent-key path, while the literal `"Unknown"` is recognised as the same failed-read state (PAT-1758). Neither spelling reaches a comparator or produces an observed value.

Rollout order: the server accepts and evaluates `"NotConfigured"` before either agent emits it, so an agent switching to it is never rejected by an un-upgraded server.

**Numeric signals (PAT-1775).** The same three states apply to signals whose real value is a number (`update_deferral_days`, `screensaver_idle_seconds`, `install_log_retention_days`, the `pwpolicy_*` family): a present value stays a bare JSON number, an absent-but-readable setting is the JSON string `"NotConfigured"`, and a failed read is `null`. The evaluator catches `"NotConfigured"` before any numeric comparator (`lte`, `gte` and the rest), so a string never reaches a number parse. Until an agent release emits the string for a given signal, that signal still sends `null` for both states; a rule must not be split into distinct `treat_not_configured_as` and `treat_unknown_as` outcomes until the agent that tells them apart is on the estate.

**Reserved namespace (PAT-913).** The finding-control IDs (`disk_encryption_off`, `removable_storage_unencrypted` — the `compliance_assessments.controls_assessed` enum) may never appear as bag keys. `ValidatePayload` rejects such payloads at ingestion and `buildSignalsMap` skips the keys with a warning on re-extraction of pre-enforcement rows. Violations arrive only via `compliance_findings`; Pass attestation arrives only via `compliance_assessments.controls_assessed`. Without this, `compliance: {"disk_encryption_off": "Pass"}` could pre-seat a forged Pass on a critical rule with no attestation at all. Enforcement uses `findingControlIDs` (`internal/extractor/finding_controls.go`), parsed at init from the embedded `payload.schema.json` — the schema file is the only hand-maintained copy of the enum.

Source: various `patched-collect.sh` sections. Parsed by `payload.go:complianceMap` (heterogeneous map of `json.RawMessage`).

| Signal key | Value type | Example | Source | CIS reference |
|---|---|---|---|---|
| `filevault` | string | `"On"` / `"Off"` / `"NotConfigured"` / `"Unknown"` | `fdesetup status` | CIS 2.5.1.1 |
| `sip` | string | `"enabled"` / `"disabled"` / `"NotConfigured"` / `"Unknown"` | `csrutil status` | CIS 2.5.3 |
| `gatekeeper` | string | `"enabled"` / `"assessments"` / `"disabled"` | `spctl --status` | CIS 2.5.2.1 |
| `firewall` | string | `"enabled"` / `"disabled"` / `"NotConfigured"` / `"Unknown"` | `socketfilterfw --getglobalstate` | CIS 2.5.2.2 |
| `xprotect_version` | string | `"5281"` | `defaults read XProtect.bundle/...` | — |
| `mrt_version` | string | `"1.97"` | `defaults read MRT.app/...` | — |
| `pending_updates_count` | integer | `0` | `softwareupdate -l` (count of `* Label:` lines) | CIS 1.1 |
| `mdm_enrolled` | string | `"Yes"` / `"No"` / `"Unknown"` | Platform-neutral result of the OS MDM enrolment check | patched.im baseline |
| `mdm_enrolled_via_dep` | string | `"Yes"` / `"No"` / `"Unknown"` | macOS `profiles status -type enrollment`; separate DEP/Automated Device Enrolment detail | — |
| `mdm_enrolment` | string | `"dep=Yes mdm=Yes"` | Deprecated macOS compatibility value retained for one PAT-1752 release | — |
| `secure_boot` | string (arm64 only) | `"Full Security"` / `"Valid"` / `"NotConfigured"` / `"Unknown"` | `bputil --display-all-policies` → `Pairing Integrity` | — |
| `auto_security_updates` | string | `"On"` / `"Off"` / `"NotConfigured"` / `"Unknown"` | `defaults read com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates` | CIS 1.4 |
| `audit_logging` | string | `"enabled"` / `"disabled"` / `"NotConfigured"` / `"Unknown"` | presence of `/etc/security/audit_control` | CIS 2.x |
| `remote_apple_events` | string | `"On"` / `"Off"` / `"NotConfigured"` / `"Unknown"` | `systemsetup -getremoteappleevents` | CIS 2.4.1 |
| `remote_login` | string | `"On"` / `"Off"` / `"NotConfigured"` / `"Unknown"` | `systemsetup -getremotelogin` | CIS 2.4.4 |
| `screen_sharing` | string | `"On"` / `"Off"` | `launchctl print-disabled system` | CIS 2.4.10 |
| `sealed_system_volume` | string | `"enabled"` / `"NotConfigured"` / `"Unknown"` | `csrutil authenticated-root status` | CIS 2.5.5 |
| `screensaver_password` | string | `"Yes"` / `"No"` / `"DefaultAssumed"` | `PlistBuddy` on `com.apple.screensaver.plist` | CIS 2.10.x |
| `screensaver_delay_seconds` | integer | `0` or `-1` | same plist | — |
| `screensaver_idle_seconds` | integer or null | `1200` | `com.apple.screensaver` `idleTime`, read via `NSUserDefaults` as the console user (profile-forced value wins); `0` ("never") sent as sentinel `99999`; `null` if the read failed or the key isn't set (PAT-1753, updater PAT-1720) | CIS 2.10.1 |
| `screensaver_idle_seconds_enforced_by_profile` | boolean, `"NotConfigured"`, or null | `true` | `objectIsForcedForKey` from the same `managed_pref_read` call; `"NotConfigured"` (PAT-1767) if the read succeeded but nothing forces the key; `null` if the read itself failed (PAT-1720 convention) | — |
| `auto_login_user` | string | `"None"` or a username | `defaults read com.apple.loginwindow autoLoginUser` | CIS 5.1 |
| `local_admin_count` | integer, `"Unknown"`, or null | `1` | macOS: `dscl -plist . read /Groups/admin GroupMembership` (excl. root); Windows: `NetLocalGroupGetMembers` on `Administrators`, excl. directory-sourced group principals (see [Local admins object](#local-admins-object)) | CIS 5.8 |
| `password_policy_present` | string | `"Yes"` / `"No"` | `pwpolicy -getaccountpolicies` | CIS 5.x |
| `password_policy_is_default` | string | `"Yes"` / `"No"` / `"NotConfigured"` / `"Unknown"` | presence of `com.apple.defaultpasswordpolicy` token | CIS 5.x |
| `password_policy_raw` | string | `"(apple-default-4char-fallback)"` or raw XML | `pwpolicy -getaccountpolicies` tail-2048 | — |

The `icloud.signed_in` field is added as the synthetic key `icloud_signed_in` by the extractor's `buildSignalsMap` — it is NOT in the `compliance` bag itself.

---

## Security tools array

Each element identifies a detected third-party AV/EDR agent. The extractor stores this array verbatim in `devices.security_inventory.security_tools`.

| Field | Type | Example |
|---|---|---|
| `id` | string | `"crowdstrike-falcon"` |
| `name` | string | `"CrowdStrike Falcon"` |

Agents checked: `crowdstrike-falcon`, `sentinelone`, `sophos-endpoint`, `defender-for-endpoint`, `jamf-protect`, `huntress`, `malwarebytes`, `carbon-black`, `bitdefender`, `eset-endpoint`. Detection is presence-based (path check), not process-based.

Since PAT-2234 the macOS agent also reports a vendor from its Apple Team ID when an Endpoint Security system extension signed by that team is enabled and active (`systemextensionsctl list`, category `com.apple.system_extension.endpoint_security`, state `[activated enabled]`). The seeded Team IDs live in updater `macos/lib/sectools.sh` (`_sectools_team_ids`); today that is Bitdefender, `GUNFMW623Y`, reported as `{"id": "bitdefender", "name": "Bitdefender"}`. Each seeded vendor has a matching `protected_software` baseline row (migration 0212 for Bitdefender), because the EDR coverage report matches reported tools by `name` and `id` against that table. The item shape is unchanged: no state field, and no way to say a check could not run. A failed `systemextensionsctl` read goes to the collector log only, so an empty array is never proof of absence.

---

## System extensions array

macOS 13+ kernel extensions managed by the system extension framework. Stored in `devices.security_inventory.system_extensions`.

| Field | Type | Example |
|---|---|---|
| `enabled` | boolean | `true` |
| `active` | boolean | `true` |
| `team_id` | string | `"VB5E2TV963"` |
| `bundle_id` | string | `"com.crowdstrike.falcon.App"` |
| `version` | string | `"7.15.0"` |
| `name` | string | `"CrowdStrike Falcon"` |
| `state` | string | `"[activated enabled]"` |

Source: `systemextensionsctl list`. Parser handles macOS 26+ format (`*`/`-` markers for enabled/active columns).

---

## Background items array

BTM-tracked login items and LaunchAgents (macOS 13+). Capped at 500 entries. Stored in `devices.security_inventory.background_items`.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Display name |
| `identifier` | string | Bundle ID or path |
| `team_id` | string | Apple Team ID |
| `url` | string | File URL |
| `type` | integer | BTM item type |
| `disposition` | integer | BTM disposition flags |

Source: `/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm` (binary plist).

---

## iCloud object

Stored in `devices.security_inventory.icloud`.

| Field | Type | Example |
|---|---|---|
| `signed_in` | string | `"Yes"` / `"No"` / `"Unknown"` |

Source: `~/Library/Preferences/MobileMeAccounts.plist` presence check.

---

## Pending updates array

Added by collector 0.3.0. Optional — absent in payloads from v0.2.0 collectors. Stored in `devices.pending_updates` JSONB.

| Field | Type | Example | Notes |
|---|---|---|---|
| `label` | string | `"macOS15_4_1"` | Software Update label |
| `title` | string | `"macOS 15.4.1"` | Human-readable name |
| `version` | string | `"15.4.1"` | Version string |
| `action` | string or null | `"restart"` | `"restart"`, `"shut down"`, or `null` |
| `recommended` | boolean | `true` | Whether Apple marks it recommended |

Source: `softwareupdate -l` output, Python-parsed.

---

## Patches array

Added by collector 0.3.0. Optional. Upserted into the `patches` table by the extractor (`upsert.go:221`).

| Field | Type | Example | Notes |
|---|---|---|---|
| `name` | string | `"macOS 15.3"` | Display name from update history |
| `version` | string | `"15.3"` | Version |
| `installed_at` | string (ISO 8601 UTC) or null | `"2025-06-02T14:23:08Z"` | null when date parsing failed |
| `date_raw` | string | `"06/02/2025, 14:23:08"` | Original locale-formatted date, kept for diagnostics only (not stored in DB) |

Source: `softwareupdate --history --all`, LC_ALL=C, Python-parsed.

---

## Collection status object

Added PAT-1732. Optional top-level object — the general home for the collection status of top-level array sections that don't have their own nested `collection_status` object. Nested objects such as `hardware_health` keep their own nested `collection_status` key (see [collection_status sub-object](#collection_status-sub-object-pat-1720) below) rather than using this one.

Absent object, or an absent `certificates` key within it, means that section was collected in full (`apps` and `safari_extensions` are different: an absent key means no signal, see [Apps completeness](#apps-completeness-pat-2063) and [Safari extensions completeness](#safari-extensions-completeness-pat-2067)) — old agents that never send this key keep working exactly as before. Exists because a collector that fails to enumerate a top-level section (for example, a Windows collector that cannot enumerate the certificate store) previously had only two options, both bad: send an empty array, which the affected section's own three-way ingestion semantics would read as authoritative absence and prune every stored row, or omit the section's key entirely, which is safe but leaves the failure invisible to the server. This object gives the collector a third option: report the section, but say the collection did not succeed.

| Field | Type | Example | Notes |
|---|---|---|---|
| `certificates` | string | `"unavailable"` | `complete` (or absent) \| `partial` \| `unavailable`. Governs `certificates` array ingestion — see the certificates row in [Top-level envelope](#top-level-envelope). |
| `apps` | string | `"partial"` | `complete` \| `partial` \| `unavailable`. Added PAT-2063. Governs whether machine-wide apps (rows with no `user_account`) missing from the `apps` array are treated as removed. **An absent key is not read as `complete`.** See [Apps completeness](#apps-completeness-pat-2063). |
| `apps_users` | array | `[{"user_account": "alice", "collection_status": "complete", "home": "/Users/alice"}]` | Added PAT-2075. One entry per user whose per-user app inventory the agent tried to read, each `complete` \| `partial` \| `unavailable`, with an optional `home`. The only authority that can prune a per-user app row, and, through `home`, a legacy machine-wide row located in that user's home. Not stored in `devices.collection_status`. See [Per-user apps](#per-user-apps-pat-2075). |
| `safari_extensions` | string | `"complete"` | `complete` \| `partial` \| `unavailable`. Added PAT-2067, macOS. Governs whether Safari rows missing from `browser_extensions` are treated as removed. **An absent key is not read as `complete`.** See [Safari extensions completeness](#safari-extensions-completeness-pat-2067). |

Per-section extractor behaviour for `certificates`:

- **`complete` (or the key/object absent)** — unchanged historical behaviour (`upsertCertificates`, PAT-216): the `certificates` key absent is a no-op; an explicit empty array prunes every stored row for the device; a non-empty array upserts each cert by `(device_id, sha1)` and prunes rows whose `sha1` is not present.
- **`partial`** — upsert only the certs actually sent (matched on `sha1`); delete nothing, even when the array sent is empty. A partial collection's sender list is known to be incomplete by definition, so pruning against it would delete rows for certs the agent simply didn't get to this run, not certs that are actually gone.
- **`unavailable`** — nothing is written at all, even if the `certificates` array sent is non-empty — the array is ignored outright and existing rows are left exactly as they were. Agents are expected to omit the `certificates` key when reporting `unavailable`, but the server does not depend on that.

An unrecognised value fails schema validation the same way any other enum violation does (`ValidatePayload`, `internal/extractor/validate.go`) and is rejected with HTTP 400 before persistence, so the extractor's own `normaliseCollectionStatus` fallback to `unavailable` is defence in depth rather than the primary gate — the same conservative-default pattern `hardware_health.collection_status` (PAT-1720) and `applied_configuration.collection_status` established.

Every non-`complete` section is logged once per ingest (`device_id`, `status`) so a degraded collection is visible in the extractor's logs rather than silently absorbed.

**Persisted, not just logged (PAT-1732, migration `0128`).** Log lines are not queryable, so this object's `certificates`, (PAT-2063) `apps` and (PAT-2067) `safari_extensions` values, `hardware_health`'s own nested `collection_status` values, and (PAT-1974) `local_admins`' own `collection_status` value are all merged into `devices.collection_status` (JSONB) by `extractor.upsertCollectionStatus`, in the same shape this section documents: `{"certificates": "...", "apps": "...", "safari_extensions": "...", "hardware_health": {"battery": "...", "storage": "...", "disks": "..."}, "local_admins": "..."}`. This is a **merge**, not a replace: a payload reporting only `certificates` leaves any previously stored `hardware_health`/`local_admins` statuses untouched, and a payload carrying none of them leaves the column untouched entirely. Stored values are always normalised (an unrecognised value is stored as `"unavailable"`, never `"complete"`). See [`devices.collection_status` in SCHEMA.md](SCHEMA.md#devices) for the column definition.

---

## Certificates array — `store` field

Added PAT-1738 (server-side classification half; agent collection is the coordinated `updater` PAT-1738 change). Each element of the `certificates` array carries an optional `store` string naming which OS certificate store the row was read from:

| Platform | Values | Notes |
|---|---|---|
| Windows | `"My"` \| `"Root"` \| `"CA"` | `LocalMachine\My` (personal store, PAT-641/PAT-1737), `LocalMachine\Root` (trusted roots), `LocalMachine\CA` (intermediate CAs). |
| macOS | `"System"` | `/Library/Keychains/System.keychain`, the only keychain the macOS collector reads (`macos/lib/certs.sh`). Apple's own `SystemRootCertificates.keychain` is not read, so macOS has only one possible value. |

**Optional and backward-compatible.** An older agent, or any payload that omits `store` on a certificate element, defaults server-side to `"My"` — the extractor's pre-PAT-1738 behaviour, since the only source before this change was `LocalMachine\My` / `System.keychain`. This means an un-upgraded agent's payloads keep working unchanged; there is no schema-version bump for this field.

`store` is persisted verbatim into `device_certificates.store` (migration `0136`). It does not by itself mean a row is a "platform root" — a `Root`/`CA` row is classified against the `platform_root_certificates` thumbprint list (migration `0136`, populated by `patched-cve-sync --mode=root-sync`), never by store name or subject text alone. See `internal/platformroot` and `internal/report/cert_expiry.go` for how that classification feeds reporting.

---

## Hardware health object

Added by macOS collector 0.8.0 (PAT-251). Optional — absent in payloads from older collectors; extractor treats absence as a no-op. When present, and `collection_status` is absent or every section in it is `complete`, the extractor upserts a `device_hardware` parent row and replaces the `device_storage_volume` and `device_disk` snapshot arrays in full — see `collection_status sub-object` below for what happens when a source command failed on the endpoint.

### battery sub-object

Source: `system_profiler SPPowerDataType`, Python-parsed.

| Field | Type | Example | Notes |
|---|---|---|---|
| `present` | boolean | `true` | `false` when no battery detected (desktop Mac or tool failure). |
| `cycle_count` | integer or null | `42` | Charge cycle count. null when absent or unreadable. |
| `condition` | string or null | `"Normal"` | Battery condition string (e.g. `"Normal"`, `"Service Recommended"`). null when absent. |
| `max_capacity_pct` | **integer** or null | `94` | Maximum capacity as a whole-number percentage. The collector strips `%` and casts to `int` — **no float values permitted**. null when absent. |

### storage array

Source: `df -k`. Excludes pseudo filesystems (`devfs`, `map auto*`).

| Field | Type | Example | Notes |
|---|---|---|---|
| `mount` | string | `"/"` or `"/System/Volumes/Data"` | Mount point path. |
| `total_bytes` | integer | `494384795648` | Volume size in bytes. |
| `free_bytes` | integer | `309000000000` | Available bytes. |
| `used_pct` | integer | `37` | Used percentage (0–100), rounded. |

### disks array

Source: `diskutil list` + `diskutil info` per physical disk.

| Field | Type | Example | Notes |
|---|---|---|---|
| `device` | string | `"disk0"` | Opaque key, unique per physical disk within one device; the server matches partial-section rows on it. macOS sends the device node (`disk0`). Windows (PAT-1733) sends the trimmed `MSFT_PhysicalDisk.SerialNumber`, or the trimmed `UniqueId` when the serial is empty, never `FriendlyName` (shared by disks of the same model). A Windows disk with no usable identifier (unreadable, empty, containing control characters, or over 128 characters), or whose identifier matches another disk's, is left out and `collection_status.disks` is `partial`. |
| `smart_status` | string | `"Verified"` | SMART status from `diskutil info`, e.g. `"Verified"`, `"Not Supported"`. **`"Undetermined"`** is a third, distinct value (PAT-1720): the agent sends it when the `diskutil info` call itself failed and the SMART line could not be read at all — never confuse this with a genuine `"Not Supported"`, which means the drive answered and does not implement SMART. |
| `internal` | boolean | `true` | `true` when diskutil reports `Internal: Yes`. |
| `solid_state` | boolean | `true` | `true` when diskutil reports `Solid State: Yes`. |

### collection_status sub-object (PAT-1720)

Optional. Absent entirely, or absent per key, means that section was collected in full — old agents that never send this key keep working exactly as before. Exists because a failed source command on the endpoint (a `system_profiler`, `df` or `diskutil` call that errors) used to be indistinguishable from "this device has no battery / no volumes / no disks any more": the agent would send `battery.present: false`, `storage: []` or `disks: []`, and the extractor's replace-in-full ingest would delete rows it already held. That violates absence-requires-authority — a failed collection is not authority that the hardware went away.

| Field | Type | Example | Notes |
|---|---|---|---|
| `battery` | string | `"unavailable"` | `complete` (or absent) \| `partial` \| `unavailable`. |
| `storage` | string | `"partial"` | `complete` (or absent) \| `partial` \| `unavailable`. |
| `disks` | string | `"unavailable"` | `complete` (or absent) \| `partial` \| `unavailable`. |

Per-section extractor behaviour:

- **`complete` (or the key/object absent)** — unchanged historical behaviour. Battery columns on `device_hardware` are overwritten and a `device_hardware_history` row is recorded when at least one metric is readable; `storage`/`disks` are replaced in full (`DELETE` then re-`INSERT`), even when the array sent is empty.
- **`partial`** — battery: the stored `device_hardware` battery columns are left untouched and no history row is written for this run. storage/disks: only the rows actually sent are upserted (matched on `mount` for storage, on device node for disks — there is no unique DB constraint on either, so the extractor looks the row up and updates or inserts inside the same transaction); nothing is deleted.
- **`unavailable`** — battery: same as `partial` (stored values preserved, no history row). storage/disks: nothing is written at all, even if the array sent is non-empty — the array is ignored outright and existing rows are left exactly as they were.
- **PAT-1736 one-off:** a Windows device's disks `partial` branch also prunes any stored `device_node` that is not one of this payload's disk keys and contains whitespace (a FriendlyName, never a trimmed SerialNumber/UniqueId), but only on the first ingest ever to report a `hardware_health.collection_status.disks` value for that device — this clears the pre-PAT-1733 FriendlyName-keyed row left behind by an agent upgrade without ever running again or touching macOS devices.

An unrecognised value fails schema validation the same way any other enum violation does (`ValidatePayload`, `internal/extractor/validate.go`) and is rejected with HTTP 400 before persistence, so the extractor's own `normaliseHWCollectionStatus` fallback to `unavailable` is defence in depth rather than the primary gate — the same conservative-default pattern `applied_configuration.collection_status` established.

Every non-`complete` section is logged once per ingest (`device_id`, `section`, `status`) so a degraded collection is visible in the extractor's logs rather than silently absorbed.

**Also persisted under `devices.collection_status.hardware_health`** (PAT-1732, migration `0128`) — see [Collection status object](#collection-status-object) above for the merge semantics and [`devices.collection_status` in SCHEMA.md](SCHEMA.md#devices) for the column.

---

## Local admins object

Added by both endpoint agents under PAT-1974 (`Patched-LTD/updater` #631, already merged): the standing local-administrator roster behind the `local_admin_count` compliance signal (see the [Compliance object](#compliance-object) table above). `local_admin_count` itself is unchanged — it stays a scalar in the flat compliance bag; the account names are structured data, so they live in this separate top-level object with its own `collection_status`, the same pattern `certificates`/`collection_status.certificates` and `hardware_health`'s own nested `collection_status` already establish. Unlike `hardware_health`, which has three independent sub-sections (battery/storage/disks) and therefore its own per-key `collection_status` object, `local_admins` has exactly one section, so `collection_status` here is a single string directly on the object — the same shape `applied_configuration.collection_status` uses.

Optional at the schema level, for backward compatibility with an agent that predates PAT-1974 (the whole key is simply absent, and the extractor treats that as a no-op — existing `local_admin_accounts` rows are left untouched). Every current Windows and macOS agent sends this key unconditionally, complete or degraded.

| Field | Type | Example | Notes |
|---|---|---|---|
| `collection_status` | string | `"complete"` | `complete` \| `partial` \| `unavailable`. Required whenever `local_admins` is present — both agents always send it explicitly. |
| `accounts` | array | see below | **Omitted entirely (never `[]`) unless `collection_status` is `"complete"`.** An empty array under a degraded read would claim "this device has zero standing admins" — the exact absence-requires-authority violation this ticket exists to close. |

Each element of `accounts`:

| Field | Type | Example | Notes |
|---|---|---|---|
| `name` | string | `"MYPC\\alice"` | The principal as the OS names it: `MACHINE\user` or `DOMAIN\Group Name` on Windows, the account short name on macOS. For a `principal_type: "unresolved"` entry this is the raw SID string, because that is the only name the device has for it. |
| `principal_type` | string | `"user"` | `user` (an individual account, local or directory-sourced) \| `group` (a directory-sourced group principal, e.g. `CONTOSO\Domain Admins` — its own membership is opaque to the device, so it is never counted in `local_admin_count`) \| `unresolved` (a SID that could not be resolved to a name or kind — IS counted, because an unknown principal must never be the thing that lets a device pass a threshold it might actually fail). macOS reads only its local `/Groups/admin` record, so every macOS entry is `"user"`. |
| `builtin` | boolean | `true` | True for the platform's built-in administrator identity — the Windows RID-500 Administrator account, reported rather than silently excluded (its enabled state is exactly the risk this signal exists to surface). macOS filters its own equivalent (`root`) out of the roster entirely before this array is built, so every macOS entry is `false`. |
| `sid` | string | `"S-1-5-21-...-1001"` | **Windows only.** The stable key for a principal whose name can change or fail to resolve. macOS has no equivalent and omits the key. |
| `account_state` | string | `"disabled"` | **Windows only, optional (PAT-1992).** The enabled state of the built-in RID-500 Administrator as the agent read it: `enabled` \| `disabled` \| `unknown`. An absent key, or an explicit `null` (treated identically), means an agent that predates the field, or an entry that was never read (every entry other than the built-in account). `unknown` means the read was attempted and did not establish the state, and is never treated as `disabled`. macOS leaves `root` out of the roster, so no macOS entry carries this key. |

**Persistence.** Ingested into `local_admin_accounts` (migration `0159`) by `internal/extractor/upsert.go:upsertLocalAdmins`, governed by `collection_status` exactly the way `certificates` and `hardware_health`'s storage/disks sections are:

- **`complete`** — replace the roster in full (`DELETE` then re-`INSERT`), even when `accounts` is empty: a genuinely empty roster is a real, evidenced observation, not an absence.
- **`partial`** — upsert only the accounts actually sent (matched by `name`); delete nothing. A partial collection's sender list is known to be incomplete by definition.
- **`unavailable`** — write nothing at all, even if `accounts` is non-empty (a well-behaved agent never sends it under `unavailable`, but the server does not depend on that) — existing rows are left exactly as they were. A failed enumeration must never be read as authority that the roster shrank or is empty.

`account_state` (PAT-1992) is stored in `local_admin_accounts.account_state` (migration `0162`, nullable; NULL is the absent key). Under `complete` the stored value is exactly what was sent, NULL when absent, because the roster is replaced in full. Under `partial` a sent value (including an explicit `unknown`) overwrites the stored one, and an absent key keeps it: a partial run never blanks a recorded state.

**How the report uses `account_state`** (`internal/report/local_admin.go:assessBuiltinAdmin`). The built-in account is an entry with `builtin: true` and a SID ending `-500`, the same RID-500 test the Windows agent applies. On Windows, per built-in entry: `disabled` is low risk and is excluded from the admin count the risk band is assessed on (unless the entry is a `group` principal, which is never in the count); `enabled` is a real finding, stays in the count, is flagged on the device and in the recommendations, and rates the device at least at-risk whatever its count, so it is never counted as compliant; `unknown` or an absent key is neither a pass nor a fail and the entry stays in the count, exactly as before this field existed. Nothing is excluded when there is no usable `local_admin_count`. The PDF states how many devices had a disabled built-in excluded. The adjustment is **Windows-only**: macOS leaves `root` out of the roster, so there is no built-in entry to judge, and a macOS verdict rests on the roster and count as reported. The report says so on each macOS device and in its method note rather than implying a built-in check ran. The CIS rules `cis_win_5_8_local_admin_count` / `cis_macos_5_8_local_admin_count` still evaluate the raw `local_admin_count` signal and are unchanged by this.

An unrecognised `collection_status` value fails schema validation the same way any other enum violation does (`ValidatePayload`, `internal/extractor/validate.go`) and is rejected with HTTP 400 before persistence; the extractor's own fallback to "unavailable" is defence in depth, never the primary gate — the same conservative-default pattern `hardware_health.collection_status` and the top-level `collection_status` object established.

**Also persisted under `devices.collection_status.local_admins`** (reusing the existing PAT-1732/migration `0128` `devices.collection_status` JSONB column that `certificates` and `hardware_health` already merge into) — see [Collection status object](#collection-status-object) above for the merge semantics.

**Field-absent vs. degraded, kept distinct** (mirrors `hardware_health`'s own absent-vs-degraded handling): the whole `local_admins` key being absent from the payload means an agent that predates PAT-1974 — a strict no-op, existing rows untouched, no `devices.collection_status.local_admins` write. A present `local_admins` object with `collection_status: "unavailable"` means a current agent that tried and failed this run — also no write to `local_admin_accounts`, but the degraded status itself is recorded in `devices.collection_status.local_admins` so the failure is visible on the platform rather than silently absorbed.

---

## Firmware object

Added by the Windows agent under PAT-2262, the first, observation-only slice of PAT-1863 (BIOS/firmware assurance). It says what the firmware reports about itself. Nothing in it, and nothing the platform derives from it in this slice, says whether a firmware version is current, outdated or vulnerable; no field name may imply that.

```json
"firmware": {
  "schema_version": 1,
  "collection_status": "partial",
  "errors": ["bios_release_date_unparseable", "baseboard_query_failed"],
  "bios": {
    "collection_status": "partial",
    "manufacturer": "LENOVO",
    "version": "N3HET82W (1.54 )",
    "smbios_version": "3.2",
    "release_date_raw": "20230230000000.000000+000"
  },
  "system": { "collection_status": "complete", "manufacturer": "LENOVO", "model": "20XW0026UK" },
  "baseboard": { "collection_status": "unavailable" }
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | The block's own version, `1`. Anything else is rejected; the platform moves first. |
| `collection_status` | string | `complete`, `partial` or `unavailable`. `unavailable` whenever no usable value was read, including every query succeeding with nothing, so an empty collection can never be stored as complete. An `unavailable` block carries no sections; `complete` and `partial` carry all three. |
| `errors` | array | At most 16 fixed codes matching `^[a-z][a-z0-9_]{0,63}$`, never exception text. The Windows vocabulary: `{bios,system,baseboard}_query_failed` (every read of the class failed), `..._property_failed` (some did), `..._value_unusable` (wrong type, over the bound or not printable), `bios_release_date_unparseable`, `no_firmware_values`. An unknown well-formed code is accepted. |
| `bios` | object | SMBIOS type 0, from `Win32_BIOS`: `manufacturer`, `version` (`SMBIOSBIOSVersion`, not the ACPI `Version`), `smbios_version` (`major.minor`), `release_date` (`YYYY-MM-DD`, the date part of the CIM datetime with no time-zone conversion), `release_date_raw` (only when the date could not be parsed; the section is then `partial`). |
| `system` | object | SMBIOS type 1, from `Win32_ComputerSystem`: `manufacturer`, `model`. |
| `baseboard` | object | SMBIOS type 2, from `Win32_BaseBoard`: `manufacturer`, `product`. |

Each section has its own `collection_status`: `unavailable` when every read of that class failed (no values allowed), `partial` when a read failed or a value was unusable, `complete` otherwise. A null or omitted value in a `complete` section is one the firmware does not populate. Every value is trimmed, non-empty, printable and at most 128 characters (`release_date_raw` 64); the agent drops a value over a bound rather than truncating it, and the validator rejects one. The key walk (PAT-2021) rejects case- and fold-variant keys, and a duplicate `firmware` key, at every level.

**Storage (migration `0213`).** Every present block writes one immutable `device_firmware_observations` row (idempotent on the raw payload id) and updates `device_firmware_current`: the newest report's status and errors always move forward; a `complete` section replaces its stored values, a `partial` one fills in only what it read (release date and raw date move together), and an `unavailable` section or block leaves stored values untouched. An older replay never overwrites a newer report. A device with no row has never reported the block. See `internal/extractor/firmware.go`.

## Kernel drivers object

Added by the Windows agent under PAT-2263. It answers the evidence half of "is a known vulnerable driver present, and is Windows blocking it" (bring your own vulnerable driver attacks): which kernel (`Type` 1) and file-system (`Type` 2) driver files are installed or loaded, identified by hash, and whether Windows enforces Microsoft's vulnerable driver blocklist. The agent makes no vulnerability claim. The platform matches the hashes against Microsoft's recommended driver block rules and loldrivers.io (`internal/driverblock`), by hash only, never by file name.

```json
"kernel_drivers": {
  "schema_version": 1,
  "collection_status": "partial",
  "errors": ["loaded_modules_unreadable", "driver_unhashed"],
  "enforcement": {
    "vulnerable_driver_blocklist": "not_set",
    "hvci": "configured",
    "smart_app_control": "not_present",
    "code_integrity_policy": "unknown",
    "blocklist_enforced": "unknown"
  },
  "drivers": [
    {"path": "C:\\Windows\\System32\\drivers\\flat.sys", "sources": ["drivers_directory"], "hash_status": "unhashed", "unhashed_reason": "reparse_point"},
    {"path": "C:\\Windows\\System32\\drivers\\pe.sys", "sources": ["drivers_directory", "service"], "service_name": "pe", "service_type": "kernel", "start_type": "demand",
     "hash_status": "hashed", "size_bytes": 712, "sha256": "cd6a...", "sha1": "7f7c...", "authenticode_sha256": "8812...", "authenticode_sha1": "49eb...", "version": "10.0.22621.2506"},
    {"sources": ["service"], "service_name": "remote", "service_type": "kernel", "start_type": "disabled", "hash_status": "unhashed", "unhashed_reason": "path_unsupported"}
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | `1`. Anything else is rejected; the platform moves first. |
| `collection_status` | string | Describes `drivers` only. `complete`: every source was read, and every file found was hashed or is genuinely missing (`file_missing`, a stale service entry). `partial`: a source failed, an entry was unusable, the row cap cut the list, or a row is unhashed for any other reason. `unavailable`: no source could be read; `drivers` is omitted. |
| `errors` | array | At most 16 codes matching `^[a-z][a-z0-9_]{0,63}$`. Windows: `drivers_directory_unreadable`, `drivers_directory_entry_unusable`, `services_unreadable`, `service_entry_unreadable`, `service_value_unusable`, `loaded_modules_unreadable`, `loaded_path_unresolved`, `driver_unhashed`, `driver_count_limit`, `block_over_budget`, `collection_failed`. An unknown well-formed code is accepted. |
| `enforcement` | object | Always present, all five keys required. `vulnerable_driver_blocklist`: `CI\Config VulnerableDriverBlocklistEnable` 1 `enabled`, 0 `disabled`, absent `not_set` (never inferred to the Windows 11 22H2 default), else `unknown`. `hvci`: `Win32_DeviceGuard HypervisorEnforcedCodeIntegrityStatus` 2 `running`, 1 `configured`, 0 `off`. `smart_app_control`: `CI\Policy VerifiedAndReputablePolicyState` 1 `on`, 2 `evaluation`, 0 `off`, absent `not_present`. `code_integrity_policy`: `CodeIntegrityPolicyEnforcementStatus` 2 `enforced`, 1 `audit`, 0 `off`. `blocklist_enforced`: `yes` when the blocklist is enabled, HVCI is running or Smart App Control is on; `no` when the blocklist is disabled, HVCI is off or configured, and Smart App Control is off or not present; otherwise `unknown`. |
| `drivers` | array | At most 1,500 rows, sorted by path, deduplicated by path ignoring case. |
| `drivers[].path` | string | Drive-letter path, at most 512 characters. Omitted only when a service's ImagePath could not be resolved to a local path; `service_name` then identifies the row. |
| `drivers[].sources` | array | Distinct values of `drivers_directory` (a `*.sys` directly in `%SystemRoot%\System32\drivers`), `service` (a Services subkey of Type 1 or 2 points here) and `loaded` (the kernel's loaded-module list names it). |
| `drivers[].service_name`, `service_type`, `start_type` | string | From the Services subkey: `kernel` or `file_system`; `boot`, `system`, `auto`, `demand` or `disabled`. |
| `drivers[].loaded` | boolean | Omitted when the loaded-module list could not be read. |
| `drivers[].hash_status` | string | `hashed` or `unhashed`. A hashed row carries `sha256` and `sha1` (lowercase flat digests of the whole file) and, for a PE whose headers hold together, `authenticode_sha256` and `authenticode_sha1` (the PE image with the checksum, the certificate directory entry and the certificate table left out, which is what the SiPolicy `Hash` rules and loldrivers.io `Authentihash` list). An unhashed row carries no hash and an `unhashed_reason`: `file_missing`, `reparse_point`, `not_regular_file`, `read_failed`, `size_limit`, `time_budget`, `byte_budget` or `path_unsupported`. A row the agent could not hash is never dropped. |
| `drivers[].size_bytes`, `version` | integer, string | File size; VS_FIXEDFILEINFO file version `a.b.c.d`. |

The key walk (PAT-2021) rejects case- and fold-variant keys, and a duplicate `kernel_drivers` key, at every level. Nothing here is the Authenticode signer or a WDAC page hash; neither is collected.

**Storage (migration `0216`).** Every present block writes one immutable `device_kernel_driver_observations` header row (status, errors, enforcement, counts; idempotent on the raw payload id) and moves `device_kernel_driver_state` to the newest report. `device_kernel_drivers` holds the current rows: a `complete` report replaces the set, a `partial` one upserts the rows it sent and removes nothing, an `unavailable` one leaves every row as it was. A row the newest report sent unhashed has its hashes cleared, never kept from an older read. An older replay never overwrites a newer report. See `internal/extractor/kernel_drivers.go`.

---

## Homebrew object

Added by the macOS agent under PAT-2012 (`Patched-LTD/updater` #639, `macos/lib/homebrew.sh`) and consumed under PAT-2013. The agent reads `/opt/homebrew` and `/usr/local` off disk and never runs `brew`, `git` or the network. Every level of the object is `additionalProperties: false`, so an unknown key anywhere rejects the payload, the same posture as `local_admins`. Ignored on a non-macOS payload.

| Field | Type | Notes |
|---|---|---|
| `collection_status` | string | `complete` \| `partial` \| `not_present` \| `failed`. Required. |
| `truncated` | boolean | Required unless `failed`. Never `true` with `complete`. |
| `truncation_reason` | string \| null | `time_limit` \| `formula_limit` \| `cask_limit` \| `tap_limit` \| `size_limit`, or `null`. `size_limit` (PAT-2032) means the agent's serialised byte budget for the block was reached. Every reason means truncated, so `partial`. Required unless `failed`. |
| `prefixes[]` | array | `path`, `owner` (string \| null), `owner_uid` (integer \| null), `collection_status` (`complete` \| `partial` \| `failed`), and `formulae`/`casks`/`taps` counts. Required unless `failed`. At most 16. |
| `formulae[]` | array | One entry per keg on disk: `prefix`, `name`, `version`, `tap`, `installed_on_request`, `installed_as_dependency`, `installed_at` (RFC3339), `runtime_dependencies` (string array \| null), `homepage`, `source_url`, `opt_linked`, `receipt_status` (`read` \| `missing` \| `unreadable` \| `unparseable`), `formula_file_status` (`read` \| `missing` \| `unreadable`). Every key is always sent; unknown values are `null`. At most 5,000. |
| `casks[]` | array | `prefix`, `token`, `version` (string \| null), `versions_on_disk`, `tap`, `installed_on_request`, `installed_at`, `receipt_status`, `apps[]` (`name`, `path` string \| null, `exists` boolean \| null). At most 5,000. |
| `taps[]` | array | `prefix`, `name` (`user/repo` without the `homebrew-` prefix), `directory`, `remote_url` (credentials stripped), `config_status` (`read` \| `missing` \| `unreadable` \| `not_a_directory`). At most 1,000. |
| `issues[]` | array | `code`, `path`. Diagnostics only. At most 50. |

**Status semantics (absence requires authority).**

| Status | Lists on the wire | Stored |
|---|---|---|
| `complete` | all three, possibly empty; never truncated; at least one `prefixes[]` row, every one `complete` | Observations for everything sent; Homebrew installations not in this report are closed (`homebrew` absence scope); the device's current list is replaced. |
| `partial` | all three, what was read | Observations for everything sent; nothing is closed. It only adds or refreshes current entries and never removes one, since it may list a formula without having read every keg. |
| `not_present` | all three and `prefixes` empty; never truncated | No observations; every Homebrew installation on the device is closed and its current list is empty. |
| `failed` | omitted, never `[]` | No package rows at all. Only the status (and any prefixes/issues) is recorded, so `failed` and `not_present` stay distinct. |

`complete` and `not_present` are the two statuses that grant absence authority, so the validator rejects either one describing an incomplete read: `complete` with no prefix rows or with a `partial` or `failed` prefix, or `not_present` that is truncated or carries a prefix row (PAT-2032).

The macOS `apps` snapshot's `all_software` absence scope never closes a Homebrew installation, and the `homebrew` scope never closes an application, so an agent that stops sending the block cannot erase Homebrew history and a brew report cannot erase an app.

**Size policy (PAT-2013).** The ingest body cap stays 6 MB (Caddy and `maxBodyBytes`). The per-section bounds above equal the collector's own, so a conforming agent stops, sets `truncated` and reports `partial` before it reaches them; a block over a bound is rejected as a contract violation. A 5,000-formula block is roughly 2 to 3 MB, which leaves room for the rest of the payload, but the bounds are entry counts, not bytes, so a pathological Mac at every bound could still approach the cap. The agent adds a serialised byte budget before the block goes on the wire (PAT-2032) and reports it as `partial` with `truncation_reason: "size_limit"`.

Storage: formulae, casks and taps are `software_observations` rows with identity kinds `homebrew_formula`, `homebrew_cask` and `homebrew_tap` (value = name or token, companion = tap), with Homebrew-only evidence in `homebrew_observation_details`, per-device status in `homebrew_device_state`, and cask-to-app links in `homebrew_cask_app_links`. See [SOFTWARE_DOMAIN.md](SOFTWARE_DOMAIN.md#homebrew-pat-2013).

## Tooling objects (`ide_extensions`, `package_managers`, `local_models`, `mcp_servers`)

Added by both agents under PAT-2017 to PAT-2020 (`updater` `macos/lib/ide_extensions.sh`, `package_managers.sh`, `local_models.sh`, `mcp_servers.sh`; Windows `windows/src/Shared/Contract/Inventory{IdeExtensions,PackageManagers,LocalModels,McpServers}.cs`) and consumed under PAT-2021. Both agents send the same keys, field for field, so one contract serves both platforms. Everything is read from disk: no editor, package manager, runtime or MCP server is started, and nothing touches the network. Each block is optional (an agent that predates a collector, or holds it off the wire, omits the key: a strict no-op) and strict at every level (`additionalProperties: false`). Validator: `internal/extractor/validate_tooling.go`. Error messages never echo a payload value.

| Block | Items | Read rows | Units | Truncation reasons | Bounds |
|---|---|---|---|---|---|
| `ide_extensions` | `extensions[]` | `profiles[]` (one per user per editor) | none: the block is the unit | `time_limit`, `extension_limit`, `user_limit` | 5,000 extensions |
| `package_managers` | `packages[]` | `locations[]` (npm prefix, site-packages, pipx venv) | `sources`: `npm_global`, `pip_user`, `pipx` | `time_limit`, `package_limit`, `user_limit` | 5,000 per source |
| `local_models` | `models[]`, and `installations[]` of the runtimes | `stores[]` | `runtimes`: `ollama`, `lm_studio`, `llama_cpp` | `time_limit`, `model_limit`, `user_limit` | 5,000 models |
| `mcp_servers` | `servers[]` | `configs[]` | `clients`: `claude_desktop`, `cursor`, `vscode`, `windsurf`, `claude_code` | `time_limit`, `server_limit`, `user_limit` | 2,000 servers |

Every block also carries `collection_status`, `truncated`, `truncation_reason`, `users[]` (`user`, `user_id`, `collection_status`, and a per-unit status map, or `profiles` for `ide_extensions`) and `issues[]` (`code`, `path`, at most 50). `local_models` and `mcp_servers` add `totals`. Users are capped at 500. The per-item fields are listed in `payload.schema.json`; every key is always sent and unknown values are `null`.

**Status rules (absence requires authority, PAT-1710).**

| Status | On the wire | Stored |
|---|---|---|
| `complete` | every key; never truncated; at least one read row and every read row `complete`; every user row, and each of its per-unit statuses, `complete` or `not_present`; every unit `complete` or `not_present`, at least one `complete` (`local_models`: at least one installation or store) | Observations for every item. Authoritative for every unit, so items no longer listed are closed and dropped from the current list. |
| `partial` | every key, what was read | Observations for every item. Adds or refreshes current entries, never removes one. A unit whose own status is `complete` or `not_present` is still authoritative, unless the block is truncated. |
| `not_present` | every key; items and read rows empty; every unit `not_present`; never truncated | No observations. Authoritative: every item of the block on the device is closed. |
| `failed` | the item list omitted, never `[]`; every other key optional (macOS sends a bare `{"collection_status":"failed"}` when its parser dies, Windows sends empty rosters) | Nothing but the status. `failed` and `not_present` stay distinct, and the portal shows `failed` counts as `null`, never 0. |

A unit reported `not_present` may not list items of that unit. A `truncated` block grants no authority at all, even for units reported `complete`: the user bound stops a read without marking any unit truncated. `pip_package` installations are fed by both `pip_user` and `pipx`, so they close only when both are authoritative.

**Privacy guard (`mcp_servers`, PAT-2021).** Defence in depth behind the agent's own reduction (PAT-2020). Before anything else in the payload is validated, every `mcp_servers.servers[]` entry is checked: a field outside `client`, `user`, `user_id`, `config_path`, `scope`, `name`, `transport`, `transport_source`, `executable`, `runner`, `package`, `package_status`, `host`, or an allowlisted field that is not in its reduced form (a `host` with a scheme, userinfo, port, path or query; an `executable` with a directory; a `package` outside the npm, PyPI or image-name pattern; a `name` outside the agent's name pattern; any of them secret-shaped), rejects the **whole payload** with 400. The payload is refused rather than stored with the block dropped because `raw_payloads.body` is the immutable archive: storing the payload would persist the secret. The API increments `patched_mcp_privacy_guard_rejections_total` (alert `McpPrivacyGuardRejected`) and logs `event=mcp_privacy_guard_rejected` with the tenant and fixed violation classes (`env`, `args`, `headers`, `url`, `command`, `path`, `credential`, `other_field`, `host_not_bare`, `executable_not_basename`, `package_not_reduced`, `name_not_reduced`, `secret_shaped_value`). No field name the agent sent and no value appears in the log or the response. Other `mcp_servers` contract errors do not echo key names either. The guard also covers `configs[].path`, `servers[].config_path` and `issues[].path` (a URL or a control character is a hit, `path_not_plain`) and `issues[].code` (a fixed lower_snake token, never secret-shaped, `code_not_plain`). Hosts are accepted exactly as both agents reduce them: a lower-case DNS name that is not secret-shaped, or the inside of an IPv6 literal matching `^[0-9a-f:.]{2,45}$`. Because a hit rejects every check-in from that device, every server rejection on a field the agents fill from user text is a subset of what the agents already drop (their `SECRET_SHAPE_RE` is identical on both platforms and applied to the same values); paths are not secret-checked, because the agents do not secret-check them.

**Case-variant and duplicate keys (PAT-2021 review).** The extractor decodes the stored body into Go structs, which match field names case-insensitively, Unicode folds included (`MCP_SERVERS` and `mcp_ſervers` both fill `mcp_servers`). Before anything else, `ValidatePayload` rejects any key, at any level the struct decoder reads, that differs from a payload field only by case or folding; inside `mcp_servers` (or folding to it) that is a privacy guard hit. A duplicated `homebrew` or tooling block key, or a duplicate key anywhere inside one, is rejected too, because the decoder would merge the copies. Other unknown top-level keys are still accepted: the Windows agent sends a top-level `installation_evidence` summary (with PAT-2116's `coverage`), which has no field. The per-app `apps[].installation_evidence` is decoded (PAT-2113, PAT-2116), so its keys are checked like any other.

**Identity (PAT-1461 seam).** Each item is a `software_observations` row with its own identity kind. These are namespace identifiers, not normalised products; none resolves to a product without a reviewed mapping.

| Identity kind | Value | Companion | PAT-2015 rule it matches |
|---|---|---|---|
| `ide_extension` | extension id, lowercased | marketplace: `vscode_marketplace` (VS Code, Insiders), `open_vsx` (Cursor, Windsurf), `jetbrains_marketplace` (JetBrains) | `ide_extension`, qualifier = marketplace |
| `npm_package` | npm name, PAT-2015 npm normalisation | `''` | `package`, qualifier `npm` |
| `pip_package` | PEP 503 name (`pip_user` and `pipx`) | `''` | `package`, qualifier `pip` |
| `mcp_server` | server name, lowercased | client | `mcp_server` |
| `local_model` | `name[:tag]` | runtime | none |
| `local_model_runtime` | runtime | runtime | none (tag the runtime's app bundle) |

An item the agent saw but could not name (an unreadable manifest, a secret-shaped server key) is kept as `ide_extension_unidentified`, `npm_package_unidentified`, `pip_package_unidentified`, `local_model_unidentified` or `mcp_server_unnamed` at low confidence and never matches a rule. Storage and the portal API: see [SOFTWARE_DOMAIN.md](SOFTWARE_DOMAIN.md#ide-extensions-packages-local-models-and-mcp-servers-pat-2021) and `/v1/portal/ai-tooling/*` in `contracts/portal-api.md`.

## Browser extensions status object

Added under PAT-2055 (platform first; the agent half follows in `updater`). `browser_extensions` is a plain array with no completeness state. A browser profile the agent refused or could not read (PAT-2052 on Windows, PAT-2054 on macOS) sends no rows, and so does every user after the collector reaches its 1,000-row cap, so the array alone cannot tell "none" from "could not read". This optional sibling object says which. The array itself is unchanged, byte for byte.

```json
"browser_extensions_status": {
  "collection_status": "partial",
  "cap_reached": false,
  "users": [
    { "user": "alice", "user_id": "501", "collection_status": "partial",
      "browsers": { "chrome": "complete", "edge": "failed", "firefox": "not_present" } }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `collection_status` | string | `complete` \| `partial` \| `not_present` \| `failed`. Required. |
| `cap_reached` | boolean | The collector stopped at its row cap. Only valid with `partial`. Required unless `failed`. |
| `users[]` | array | At most 500, unique by `user`. Required unless `failed`. Each row: `user` (exactly the `user_account` the agent puts on that user's rows), `user_id` (uid or SID, or `null`), `collection_status`, and `browsers` with `chrome`, `edge` and `firefox`, each `complete` \| `partial` \| `not_present` \| `failed`. Every browser key is required unless the user is `failed`. |

Safari rows carry no user (`user_account: null`), so Safari is outside the per-user vocabulary; the block covers Chrome, Edge and Firefox.

**Status rules (absence requires authority).** The STRUCTURE is strict at every level (`additionalProperties: false`: types, enums, required keys), case- or fold-variant keys are rejected by the PAT-2021 key walk, and a structural error rejects the payload with 400. The rules below are consistency rules, and breaking one does NOT reject the payload, because that would drop the device's whole inventory (apps, CVEs, CIS, `last_seen`) every cycle over a completeness claim. The extractor stores such a block as `partial` with its authority withheld: no completion time moves, no per-pair rows are written, the reason is kept in `browser_extension_device_state.authority_withheld`, a warning is logged with the device id, and `patched_browser_extension_status_withheld_total` (extractor) increments. Reasons: `cap_reached_not_partial`, `too_many_users` (over 500), `duplicate_user`, `user_status_inconsistent`, `browser_status_inconsistent`, `rows_listed_when_not_present`, `row_under_not_present_pair`, `row_not_reported_complete`. Code: `internal/extractor/validate_browser_extensions_status.go`.

| Status | Rules | Authority |
|---|---|---|
| `complete` | every user and browser `complete` or `not_present`; never capped; every Chrome, Edge or Firefox row's (user, browser) is listed `complete` | For the whole device: any extension last seen before this report is gone. |
| `partial` | anything else that was read | None for the device. A (user, browser) reported `complete` or `not_present` is authoritative for that pair, unless the block is capped or the user is `failed`. |
| `not_present` | every user and browser `not_present`; no Chrome, Edge or Firefox rows; never capped | For the whole device. |
| `failed` | `cap_reached` and `users` optional | None. Only the status is recorded. |

A `complete` user may only have `complete` or `not_present` browsers, and a `not_present` user only `not_present` ones. No row may sit under a (user, browser) reported `not_present`. `user` must equal the rows' `user_account` exactly, case included, on both platforms: a Windows agent that sends `alice` in the block and `Alice` on its rows gets its authority withheld rather than letting one account's report prove another's extensions gone.

**What readers may conclude.** `device_browser_extensions` still never deletes. An extension counts as gone only when a report with authority for its device, or for its own user and browser, arrived strictly after its `last_seen` (the report that listed it stamps its `last_seen` and its own authority time with one value, `clock_timestamp()` read under the device row lock, so it never proves itself gone, and two concurrent extractions for one device are ordered by who took the lock, not by who started first). A partial, capped or failed report never makes an extension absent, however long ago it was last seen. A device that has never sent the block keeps each reader's pre-PAT-2055 rule exactly. **A Safari row is never made absent by the device-level branch, regardless of report completeness** (PAT-2064): this block only ever reports on chrome, edge and firefox, so a "complete" claim about those three says nothing about Safari, and treating it as if it did would close a Safari finding with no authority over Safari at all. The shared predicate is `internal/extpresence`. Safari has its own signal instead, below.

### Safari extensions completeness (PAT-2067)

`collection_status.safari_extensions` is the only thing that can prove a Safari app extension gone. The agent walks Safari app-extension locations once for the whole machine, so the claim is per device, not per user.

| Value | Agent sends it when | Server does |
|---|---|---|
| `complete` | every Safari search root was listed with no error, every bundle read, and every Safari row found was emitted (none cut by the row cap) | On schema v3, with `browser_extensions` sent as an array and `browser_extensions_status.cap_reached` not true: every stored Safari row this report does not list is gone. An empty list (no Safari rows) is a valid claim and makes every stored Safari row absent. |
| `partial` | some locations or bundles could not be read | Nothing concluded. |
| `unavailable` | the walk failed outright | Nothing concluded. |
| absent | an agent that predates PAT-2067 | Nothing concluded: Safari rows are never marked absent, exactly as before. |

A `complete` that fails one of those conditions (schema v2, no `browser_extensions` array, a capped report) is logged with a reason and grants nothing; it is not rejected. A malformed value, or a case- or fold-variant key such as `Safari_Extensions`, is a 400. The authority is recorded only for a device that also sends `browser_extensions_status` (current macOS agents send both in the same report); a device with no status block keeps each reader's pre-PAT-2055 rule for every row, Safari included. Chrome, Edge and Firefox authority never marks a Safari row absent, and a Safari `complete` never marks a Chrome, Edge or Firefox row absent.

Stored as `browser_extension_device_state.safari_complete_at` (the report's `last_seen` stamp, compared strictly after, forward-only) and `safari_reported_at` (the payload `received_at`, forward-only, so an older replay never stamps authority). Migration `0179`. Code: `internal/extractor/safari_authority.go`, predicate `internal/extpresence`.

**Storage (migration `0177`).** `browser_extension_device_state` (one row per device: newest status, `cap_reached`, `reported_at`, `last_complete_at`, `authority_withheld`) and `browser_extension_collection_state` (one row per device, user and browser: newest status, `reported_at`, `last_complete_at`). `reported_at` is the payload's `received_at` and only moves forward, so an older replay writes nothing; `last_complete_at` only moves on an authoritative report. See [SCHEMA.md](SCHEMA.md).

## Backup status object

Added by both endpoint agents under PAT-679 (macOS `lib/backup.sh`) / PAT-680 (Windows `InventoryBackupStatus`); server ingestion is PAT-948. Platform-neutral — both agents emit the identical field set, so the extractor takes one shape for both platforms. Optional at the top level — absent in payloads from agents that predate PAT-679/680; the extractor treats absence as a no-op (existing `devices.backup_status` snapshot is preserved). Stored in `devices.backup_status` JSONB, replaced in full per ingest (current-state snapshot, not history — migration `0087`).

Detects Time Machine (macOS) / File History (Windows), OneDrive/iCloud sync, and third-party tools (Backblaze, Arq, Carbon Copy Cloner, Acronis, Veeam, Backup Exec, ...).

| Field | Type | Example | Notes |
|---|---|---|---|
| `has_backup` | boolean | `true` | True when a real backup mechanism (not sync) was detected with reasonable confidence. Required — both agents always emit it, even in the all-false fallback default. |
| `backup_type` | string or null | `"time_machine"` | Which mechanism was detected; null when none found. **Not an enum** — known values today are `time_machine` \| `file_history` \| `onedrive_sync` \| `icloud_sync`, but third-party tool names (e.g. `backblaze`, `arq`, `carbon_copy_cloner`, `acronis`) are free-form strings decided by the collector. |
| `last_backup_at` | string (RFC3339 UTC) or null | `"2026-07-08T09:00:00Z"` | Timestamp of the last completed backup. null when unknown — most third-party tools don't expose a queryable timestamp. |
| `last_backup_days_ago` | integer or null | `2` | Whole days since `last_backup_at`, clamped to >= 0. null whenever `last_backup_at` is null. |
| `stale` | boolean | `false` | True when `has_backup` is true and the backup is more than 7 days old. Always false when `has_backup` is false. Required. |
| `sync_only` | boolean | `false` | True for sync mechanisms (OneDrive, iCloud Drive) — never a substitute for backup. `has_backup` is always false when this is true. Required. |
| `notes` | string or null | `"OneDrive sync detected; sync is not a substitute for backup"` | Free-text detail; null when there's nothing to add. |

**Wire-format quirk (both forms must validate):** macOS always emits every key, using an explicit JSON `null` for absent optional values. Windows omits a null optional field from the wire entirely (`JsonIgnoreCondition.WhenWritingNull`). `payload.schema.json` accepts both — only `has_backup`/`stale`/`sync_only` are `required`.

**Extractor robustness (PAT-948, mirrors the PAT-871 browser_extensions fix).** `payload.BackupStatus` is carried as `json.RawMessage`, not a typed struct field, specifically so a malformed shape (a field present with the wrong JSON type) cannot abort the *entire* payload `json.Unmarshal` in `processRow` — the same isolation `hardware`/`security_tools`/`system_extensions`/`background_items` already get. `parseBackupStatus` (`upsert.go`) decodes it defensively: a decode failure is logged and treated exactly like "absent" (existing `devices.backup_status` value preserved via `COALESCE`), never propagated as a row-level extraction error.

**Fleet aggregation bucket rule (PAT-948, consumed by the `/admin/tenants/overview` PAT-673 fleet-summary feed):** `report.BackupBucket(hasBackup, syncOnly, lastBackupDaysAgo)` classifies a device into `"sync_only"` (checked first — never counted as backed up) → `"none"` (no backup at all) → `"stale"` (`has_backup` and >= 7 days) → `"ok"` (`has_backup` and either < 7 days or no known timestamp). `FetchTenantsOverview`'s SQL `CASE` expressions mirror this rule for the per-tenant aggregate counts and must be kept in lockstep with it.

Source: macOS — `tmutil latestbackup` + presence checks for OneDrive/iCloud/third-party app bundles, Python-parsed. Windows — File History status API, OneDrive sync-root presence, and a fixed list of known third-party backup services.

---

## OS update object

Added under PAT-1806 as the server-side contract for the verdict both endpoint agents compute locally (SOFA feed on macOS, WUA COM on Windows). Both agents now send it (updater `InventoryPayload.OsUpdate` on Windows, `patched_os_update_merge_into_payload` on macOS); an older agent, or a macOS run with no fresh contract-valid local verdict, omits the key.

**Field shape verified against source (PAT-1862).** PAT-1806 originally guessed this shape from the ticket description without `updater`'s `contracts/update-status.schema.json` checked out. That guess had drifted from the real contract in several places — `target_os`/`severity`/`deferrals_remaining`/`checked_at` were wrongly optional or missing, `latest_os` was wrongly required, and the rollup's bucketing SQL hardcoded a `state` value (`"current"`) no real agent ever sends. PAT-1862 reconciled this table and `payload.schema.json` against the real contract; the shape below is now verified, not inferred.

Optional at the top level — absent from a payload whose agent predates this field or had no verdict to send. The extractor treats absence as a no-op: an existing `device_os_update` row is preserved, never zeroed (same COALESCE-preserve discipline `pending_updates`/`hardware`/`backup_status` already get). Stored in `device_os_update`, one row per device, upserted per ingest (current-state snapshot, not history — migration `0144`, `checked_at` added by `0147`).

| Field | Type | Example | Notes |
|---|---|---|---|
| `installed_os` | string | `"15.5"` | The OS version currently installed. Required. |
| `latest_os` | string or null | `"15.6.1"` | The latest version the feed (SOFA / WUA) reports as available. null when the feed is unavailable. |
| `target_os` | string or null | `"15.6.1"` | Minimum acceptable version, from policy or SOFA/WUA latest. Optional and nullable (PAT-2123): absent or null when a pending update's target build isn't resolved yet (e.g. Windows Update reporting `state=update_required` before WUA has determined the exact version) — never rejected, and never a placeholder value. When present, must be a non-empty string. |
| `state` | string | `"update_recommended"` | The agent's own currency verdict. **Not an enum on this platform schema** — a documented vocabulary, not enforced here or at ingestion, so a future agent release reporting a new state is never rejected. The real agent-side contract does enforce a strict enum: `up_to_date`, `update_recommended`, `update_required`, `deadline_passed`, `unsupported_hardware`, `unknown`. The rollup (`report.FetchOSUpdateStatus`) counts exactly `"up_to_date"` as current, `update_recommended`, `update_required`, `deadline_passed` and `unsupported_hardware` as behind, and `unknown` or any other value as not reported (PAT-2295). Required. |
| `severity` | string | `"high"` | Severity of the outstanding update. Not an enum here, same reasoning as `state`. Real agent-side values: `none`, `low`, `medium`, `high`, `critical` (none=current; low=behind non-security; medium=behind security; high=deadline close or exploited; critical=deadline passed or exploited+past grace). Required, never null. |
| `security_relevant` | boolean | `true` | True when the outstanding update addresses a security issue. Required — always emitted, even when `state` is `up_to_date` (then always false). |
| `actively_exploited` | boolean | `false` | Agent-supplied prior verdict input. Required and retained for mixed-version compatibility, but it has no CVE identifier, authoritative source URL or source retrieval time and is therefore not sufficient for a portal or report active-exploitation claim. Platform claims use fresh CISA KEV or SOFA evidence instead (PAT-1871). |
| `deadline` | string (RFC3339 UTC) or null | `"2026-10-01T00:00:00Z"` | Policy deadline for applying the update, when one exists. null when there is no deadline. |
| `deferrals_remaining` | integer | `3` | Remaining allowed deferrals before the update is enforced. Required, never null. |
| `release_age_days` | non-negative integer or null | `42` | Days since the target release shipped. null when the feed doesn't expose a release date for the target version. |
| `checked_at` | string (RFC3339 UTC) | `"2026-09-17T08:00:00Z"` | The agent's own local computation time of this verdict (SOFA/WUA check time) — distinct from the platform's `reported_at` (when the platform received the payload); the two can differ if an agent uploads a stale cached verdict. Required. |

**Wire-format quirk, same as `backup_status`:** `latest_os`/`deadline`/`release_age_days`/`target_os` are independently optional and nullable — expect Windows to omit an absent-null field from the wire entirely and macOS to always emit the key with an explicit JSON `null`. `payload.schema.json` accepts both forms. All other fields — `installed_os`/`state`/`severity`/`security_relevant`/`actively_exploited`/`deferrals_remaining`/`checked_at` — are `required` and never null.

**`target_os` nullability (PAT-2123).** `target_os` was briefly required-and-never-null under PAT-1862's contract-drift fix. It rejoined the nullable group because the Windows agent needs to report a pending update (`state=update_required` et al.) before WUA has resolved which build it is updating to, rather than invent a placeholder version to satisfy a required field. `ValidatePayload` (`internal/extractor/validate.go`) accepts the key absent, explicit `null`, or a non-empty string; an empty string or a wrong-typed value is still rejected — only "we don't know yet" is allowed to mean "say nothing", not "say anything". `upsertOSUpdate` (`internal/extractor/upsert.go`) writes SQL `NULL` for a nil `target_os`, not an empty string, and — because the whole `os_update` block is written as a single unconditional overwrite whenever the block itself is present (never a field-level `COALESCE`) — a fresh report with `target_os` absent or null **clears** any previously-stored target rather than preserving a stale one. This is deliberate: an explicit new report saying "no known target right now" means the old target may no longer be accurate, unlike the whole-block-absent case (an agent that predates `os_update` entirely, or a payload that doesn't carry the block at all), which still preserves the existing `device_os_update` row untouched. No reader treats a `NULL` `target_os` as "up to date" — `report.FetchOSUpdateStatus` buckets purely off `state`, never `target_os`, so this column's nullability cannot perturb the rollup.

**Extractor robustness (PAT-1806, mirrors `backup_status`/PAT-948).** `payload.OSUpdate` is carried as `json.RawMessage`, not a typed struct field, so a malformed shape cannot abort the *entire* payload `json.Unmarshal` in `processRow`. Live ingestion rejects malformed `checked_at` values before raw persistence. `parseOSUpdate` (`upsert.go`) nevertheless decodes defensively for legacy or replay payloads that bypassed that current validation: a decode failure is logged and treated exactly like "absent" (existing `device_os_update` row preserved), never propagated as a row-level extraction error. An unparseable `deadline`, or an unparseable `checked_at` in that defensive path, is logged and stored as SQL `NULL`; it does not fail the rest of the section.

**Rollup.** `report.FetchOSUpdateStatus` (`internal/report/os_update.go`) partitions a tenant's eligible devices (respecting the per-OS master switch, same `enabledOSFilter` every other executive-summary fetcher uses) into four buckets: current, behind, behind-with-a-security-relevant-update-outstanding, and not-reported. A device with no `device_os_update` row at all lands in "not reported", never "current" ("absence requires authority", root `AGENTS.md`; the same discipline PAT-1805 established for `pending_updates`). So does a device whose stored `state` is `unknown` or outside the vocabulary (PAT-2295): the agent saying it could not tell, or a state a later agent release added, is not a claim that the device is behind, and it never counts toward the security-relevant subset even when `security_relevant` is set. Only fresh `update_recommended`, `update_required`, `deadline_passed` and `unsupported_hardware` verdicts count as behind. Verdicts older than seven days land in not-reported (PAT-2338). The vocabulary is interpreted in one place, `osUpdateStates` in `internal/report/os_update.go`, which the portal roster also reads, so the two views cannot disagree about a state. Response field names (`devices_current`, `devices_behind`, `devices_behind_security_relevant`, `devices_not_reported`) are unchanged; `devices_not_reported` now also carries the unknown and unrecognised devices, and `devices_behind` no longer does. Served by `GET /admin/tenants/{tenantID}/os-update-status`.

**Portal reader (PAT-2294, PAT-2338).** `GET /v1/portal/devices` and `GET /v1/portal/devices/{deviceID}` prefer an explicit `device_os_update` row over `devices.pending_updates` on both Windows and macOS. `up_to_date` is `false`; `update_recommended`, `update_required`, `deadline_passed` and `unsupported_hardware` are `true`; `unknown`, unavailable or unrecognised states are `null`. A stale or unknown OS verdict therefore stays unknown even when the legacy list is empty or non-empty. The verdict is dated by `checked_at`, capped at `reported_at` so an agent with a wrong clock cannot keep it fresh, and falls back to `reported_at` for a row written before `0147`. A verdict older than seven days (the portal evidence freshness window) is `null`. `FetchOSUpdateStatus` applies the same vocabulary and freshness gate: stale evidence joins unknown and unrecognised evidence in not-reported, never current or behind. On devices with an OS row the roster and rollup agree. Only when no OS row exists does the portal retain legacy array compatibility: an empty `pending_updates` list is `false`, a non-empty list is `true`, and null is unknown. The OS-specific rollup still reports such devices as not-reported; a legacy software-update list is not an OS currency verdict.

The rollup intentionally does not expose `device_os_update.actively_exploited`.
That legacy input is preserved during reader migration but cannot substantiate
an active-exploitation result without CVE-level CISA KEV or SOFA provenance.

---

## Agent health object

Added by both endpoint agents under PAT-1064 (macOS PAT-1065, Windows PAT-1066); server ingestion is PAT-1064 itself. This is the **degraded-capability channel**: the agent's own admission that it was handed a directive or expected to run a capability it could not carry out. Today that fault is written to a local log and the run continues — nothing upstream ever learns. Three such faults ran silently on a real endpoint for weeks (1,119 / 1,105 / every-run occurrences) while the device reported itself completely healthy on every other signal it sent. `agent_health` exists so that stops happening.

Carried over the existing `POST /v1/inventory` payload, not a new endpoint and not `/v1/posture` — `/v1/posture` is a GET (server hands policy *down* to the agent), the wrong direction for the agent reporting fault state *up*. `/v1/inventory` is the documented platform-neutral seam both agents already implement.

Optional at the top level, and the **absent vs. present-empty distinction is load-bearing**:

- **`agent_health` key absent entirely** — an agent that predates this protocol. Any agent that speaks this protocol always emits the key, even when it has nothing to report, so "absent" means "older agent" in practice. The server treats this as **no opinion** — it does not upsert and does not delete any existing `device_agent_health` rows for the device.
- **`agent_health` present with `degraded: []`** — a current agent has run and found nothing degraded. This is "I am fine right now" and the server treats it as an **explicit all-clear**: every existing `device_agent_health` row for the device is deleted.

Collapsing these two into one Go zero value (as a plain struct or a `[]T` would) would mean a healthy *old* agent looks identical to a healthy *current* agent, and a naive implementation would delete a genuinely degraded record every time an old agent's payload came in. `payload.AgentHealth` is therefore `json.RawMessage`, decoded defensively by `parseAgentHealth` (`internal/extractor/upsert.go`) — the same treatment `backup_status` gets, for the same reason.

The optional `agent_health.update_channel` object is a separate positive observation: `{ "channel": "beta", "source": "device_override", "config_version": 12 }`. The agent copies these values from the exact Ed25519-verified config; missing or malformed values are ignored, never inferred from the effective channel. The extractor binds the observation to the authenticated tenant and resolved device and uses payload `collected_at` as `observed_at`. It can be stored even when `degraded` is absent or null, but never counts as a healthy/degraded snapshot or release-soak evidence.

### `degraded` array

| Field | Type | Example | Notes |
|---|---|---|---|
| `kind` | string | `"directive_skipped"` | Fault category. See vocabulary below. Free-form — **not** enum-enforced, see below. |
| `subject` | string | `"log_upload"` | What the directive or capability was about. Free-form — **not** enum-enforced. |
| `reason` | string | `"device_id_mismatch"` | Why it could not be done. Free-form — **not** enum-enforced. |
| `first_seen` | string (RFC3339) | `"2026-12-01T09:00:00Z"` | When this fault was first observed by the agent. Required. |
| `last_seen` | string (RFC3339) | `"2026-07-28T09:00:00Z"` | When this fault was most recently observed. Required. |
| `count` | integer >= 1 | `1119` | How many times this fault has occurred. Required, must be >= 1. |
| `ever_succeeded` | boolean | `false` | Whether this exact capability has ever worked on this device. Required — see below for why it is explicit rather than inferred. |

One row per device per distinct `(kind, subject)` pair — PAT-1029's "aggregate, never per-run" constraint, the same reason `device_browser_extensions` and `device_certificates` are keyed on identity rather than accumulating a row per ingest. `device_agent_health`'s primary key is `(device_id, kind, subject)`; re-reporting the same fault updates the existing row in place (`reason`/`last_seen`/`count`/`ever_succeeded` refresh) rather than accumulating duplicates.

### Vocabulary (documented convention, not an enum)

The following is the canonical vocabulary both agents draw from today, seeded from the three faults observed in production:

| `kind` | `subject` | `reason` | Meaning |
|---|---|---|---|
| `directive_skipped` | `log_upload` | `device_id_mismatch` | The server issued a log-upload directive naming a `device_id` the agent no longer recognises as itself. |
| `capability_missing` | `extension_removal` | `lib_not_installed` | The server asked the agent to remove a browser extension, but the library/API the agent needs to do that is not installed on this endpoint. |
| `sync_never_succeeded` | `catalogue` | `fetch_failed` | The agent has never once successfully fetched the signed app catalogue. |
| `tcc_denied` | `browser_extensions` | `full_disk_access_missing` | **macOS only.** The root collector could `lstat` another user's browser data folder but `open()` failed with `EPERM`: macOS privacy protection (TCC) denied Full Disk Access, so the Chrome/Edge/Firefox extension walk for that user is incomplete (`browser_extensions_status` for the affected pair stays `partial`, never `not_present`). Added under PAT-2096. |
| `tcc_denied` | `mcp_servers` | `full_disk_access_missing` | **macOS only.** Same TCC/Full Disk Access denial as above, for the MCP client-config walk (`~/Library/Application Support/Claude`, `.../Code/User`). Added under PAT-2100. |
| `tcc_denied` | `ide_extensions` | `full_disk_access_missing` | **macOS only.** Same TCC/Full Disk Access denial, for the IDE-extension walk (`~/Library/Application Support/JetBrains`). Added under PAT-2100. |
| `tcc_denied` | `package_managers` | `full_disk_access_missing` | **macOS only.** Same TCC/Full Disk Access denial, for the package-manager walk (`~/Library/Application Support/fnm`, `.../pipx`). Added under PAT-2100. |
| `device_identity` | `backfill` | `refused_401`, `credential_not_device_scoped`, `endpoint_unavailable`, `tenant_mismatch`, `invalid_device_id`, `malformed_response`, `unreachable`, `rate_limited`, `http_<status>`, `store_failed`, `unexpected_exception` | **Windows only.** The agent holds credentials but no canonical device id, asked `GET /v1/device/identity` and did not get an answer it could store (PAT-2424). Self-update policy for a device-scoped config stays unverified until it does. `credential_not_device_scoped` means the device holds a tenant-level credential and needs re-enrolling. |

**`kind` values in use:** `directive_skipped` \| `capability_missing` \| `sync_never_succeeded` \| `tcc_denied` \| `device_identity`. Expect this list to grow as more failure modes are instrumented on each platform.

**`tcc_denied` is a known macOS-only issue code.** It reports macOS's Transparency, Consent and Control (TCC) privacy protection refusing the collector's LaunchDaemon (running as root, PID 1's child) read access to another user's per-app data folder without Full Disk Access granted to the signed collector binary — see `updater/AGENTS.md` ("Root is not exempt from macOS privacy protection (TCC)"). Only the LaunchDaemon run writes or clears this entry, and only when the run's users walk reached every folder with no refusal does the entry clear; a manual or on-demand collector run never reports or clears it. The Windows agent has no equivalent local-filesystem-privacy model and never sends this `kind`.

**This vocabulary is documented, not enforced.** `ValidatePayload` and `upsertAgentHealth` accept any string for `kind`/`subject`/`reason` — an unrecognised value is stored **verbatim**, never rejected. This is deliberate: if a future agent release introduces a new fault kind and the server rejected payloads containing it, that release would have its *entire inventory upload* silently dropped the moment it started reporting the new fault — the device would stop appearing as healthy AND stop reporting anything at all, the worst of both outcomes. Do not "tighten" this into an enum rejection later without solving that problem first.

### Why `ever_succeeded` is explicit, not inferred

The server cannot compute `ever_succeeded` on its own: it only ever sees the current snapshot, so a fault that has "never worked" and a fault that "stopped working" look identical from a cold server with no prior successful observation on file (e.g. after a device re-enrolls, or before the first successful sync). Only the agent — which has been running continuously on the endpoint and holds its own local history — knows which of the two is true. That distinction is exactly what the current local-log-only behaviour destroys: a log line records that something failed *this run*, with no memory of whether it ever succeeded before. `ever_succeeded` is carried exactly as the agent reports it and the server never recomputes or overrides it.

### Extractor robustness (PAT-871/PAT-948 precedent, applied here)

`payload.AgentHealth` is `json.RawMessage`, not a typed struct field, so a malformed shape cannot abort the *entire* payload `json.Unmarshal` in `processRow`. Within the section, `degraded` is decoded as `[]json.RawMessage` rather than a typed slice, so one malformed element (wrong JSON type on a field) cannot fail the whole array's unmarshal and take every other element down with it — the same "one bad element must not poison the rest" property PAT-871 established for `browser_extensions`, applied one level deeper here because `agent_health` nests its array inside an object rather than exposing it at the top level.

- A malformed **top-level** `agent_health` object (e.g. not an object at all) is logged and treated exactly like "absent" — no opinion, existing rows untouched.
- A malformed **element** within `degraded` — decode failure, empty `kind`/`subject`, a NUL byte in `kind`/`subject`/`reason`, `count < 1`, an unparseable `first_seen`/`last_seen`, or a `null`/absent `ever_succeeded` — is logged and skipped; the rest of the array, and the rest of the payload, ingest normally.
- `kind`/`subject`/`reason` are truncated to 128 runes and the `degraded` array is capped at 64 entries, both **before** any value can become part of the `(device_id, kind, subject)` ON CONFLICT key (PAT-933 precedent — see `truncateExtField` and the `extMax*Len` const block in `internal/extractor/upsert.go`).
- A NUL byte (`\x00`) in `kind`/`subject`/`reason` drops the whole element rather than being stripped or truncated around: PostgreSQL `text` columns reject NUL outright, and left unchecked that error would propagate out of the write and abort the *entire device's* extraction transaction — apps, compliance, extensions, everything — retried forever against the same poisoned payload. Checked before truncation, since truncation could otherwise land exactly on the NUL and mask it.
- `ever_succeeded` is decoded as `*bool` internally specifically so `null` (or an absent key) is distinguishable from a genuine `false`. `encoding/json` would otherwise decode either into the `bool` zero value with no error, silently asserting "this has never worked" — the more alarming of the two states — on no evidence. A `nil` decode drops the element instead.

**Recency (out-of-order payloads) is a separate concern from malformed data, and is also never fatal to the request.** `upsertAgentHealth` locks a per-device watermark row (`device_agent_health_watermark`) before deciding whether to act on `agent_health` at all. If the payload's own `collected_at` is older than that watermark — the extractor's claim/retry ordering is unspecified, so an older payload can genuinely be processed after a newer one — the *entire* `agent_health` section for that ingest is skipped (logged, not erred): no clear, no upsert, no prune, watermark left untouched. This is the only section in the extractor that deletes rows, so it is the only one where out-of-order processing can otherwise falsely resolve a fault a newer payload already recorded; every other section is a harmless last-write-wins overwrite. The watermark is a dedicated table, not derived from `MAX(collected_at)` over `device_agent_health`'s own rows, specifically so it survives a `degraded: []` payload deleting every fault row — a rows-derived watermark disappears at exactly the moment (an all-clear) it is most needed to protect against a later, delayed, older payload resurrecting the faults that all-clear correctly resolved.

**Recency is two-sided: a far-future `collected_at` is rejected too, not just an older one.** `collected_at` is entirely agent-controlled, so the older-than-watermark check alone leaves a gap: a device that reports a `collected_at` far in the future (a broken clock, a timezone bug, or malice) would pass that check, clear or overwrite the device's rows, and persist the far-future value as the new watermark — after which every *legitimate* future payload from that device is judged older than the watermark and silently rejected, forever, until someone hand-edits the database. `upsertAgentHealth` rejects (logs, does not act, leaves the watermark untouched) any payload whose `collected_at` is more than 5 minutes ahead of the server's own clock (`agentHealthFutureTolerance`, `internal/extractor/upsert.go`) — generous enough for ordinary NTP drift, nowhere near generous enough for a meaningfully broken clock to pass through. This rejects rather than clamps to `now()` deliberately: clamping would still let a broken-clock device advance its own watermark on every single upload, reintroducing the same permanent wedge one upload more slowly.

**`first_seen`/`last_seen` are not bounded the same way, because nothing reads them for a decision.** They are parsed (rejected if unparseable — see the extractor-robustness note below) and stored/displayed verbatim; unlike `collected_at`, no code compares them to anything or gates a write on them. A far-future `first_seen`/`last_seen` is therefore not a security or correctness bug the way an unbounded `collected_at` was — it would only render oddly in the dashboard (PAT-1067). Flagged here as a known gap rather than fixed, since fixing it is a display/data-quality concern for the consumer, not a control-flow one for the extractor.

### `ValidatePayload` does not check `agent_health` at all — deliberately

`ValidatePayload` runs at the `POST /v1/inventory` ingestion gate, **before** a payload is ever persisted to `raw_payloads`. Any error it returns rejects the *entire* request — every section, not just the one that failed a check. An earlier version of this validator checked `agent_health`'s shape (that `degraded` items carried all seven expected keys), and that check was itself a bug (review round 3, FIX 9): a single malformed health entry from a misbehaving agent would 400 the device's whole inventory upload. That is precisely the blast radius this document promises never happens for this section ("a malformed entry is skipped and logged, never fatal") — the promise just wasn't kept by the validator.

So: **`docs/payload.schema.json`'s `agent_health` block describes the shape agents are expected to send. It is not what the server enforces at ingestion.** `ValidatePayload` accepts any value at all for the `agent_health` key — right type, wrong type, missing `degraded`, `degraded` items missing every field, anything. The extractor's own defensive decode (`parseAgentHealth`, `sanitizeAgentHealthEntries` in `internal/extractor/upsert.go`) is the *only* code that inspects `agent_health`'s shape, and it runs after the payload is already durably persisted to `raw_payloads` — so whatever it rejects is dropped from this section only, logged, and never turns into an HTTP error. If you are reading `payload.schema.json` to understand what the server will accept or reject, read this paragraph first: for `agent_health`, the schema is a contract for agent authors, not a gate the server runs.

---

## Applied configuration object

Added by the macOS agent under PAT-1667 (`macos/lib/config_profiles.sh`); server ingestion, storage and change detection are PAT-1668. macOS only today — the Windows agent does not emit this key, and the extractor treats its absence as absence, never as "this Windows device has no configuration applied".

**This is applied configuration, not authored policy, and the distinction is the point.** `profiles list` says what actually landed on that Mac. It does not say what an administrator authored in a management console, and the two diverge routinely: a push can be pending, a profile can be removed locally, a stale cached push can linger. Nothing derived from this key may be labelled with a policy name, phrased as "an admin changed X", or merged into the Intune authored-policy path (`internal/intune`, PAT-1662/1664) as though the two described the same record. A Mac enrolled in Intune produces related rows in both places: that is one change with two independent observations, and a report that adds them together double-counts. **They are deliberately left uncorrelated** — correlating them is a product decision about how a joint finding should read, not something to infer in a diff engine.

Vendor-agnostic by construction: `profiles` and `mdmclient` are stock macOS tools that behave identically whether the enrolling server is Jamf, Intune, Mosyle, Kandji or nothing at all. An unenrolled Mac reports an empty list and a null `mdm_server_url` — that is a successful collection, not an error.

| Field | Type | Example | Notes |
|---|---|---|---|
| `profiles` | array | see below | Device-scope configuration profiles observed on this Mac. Capped by the agent at 500 entries. |
| `profiles_count` | integer | `12` | The agent's own count. Can exceed `len(profiles)` when the cap truncated the list. |
| `profiles_truncated` | boolean | `false` | True when more profiles exist than were sent. A truncated list cannot support an absence claim — see below. |
| `collection_status` | string | `"ok"` | `ok` \| `rate_limited` \| `unavailable`. The single most important field in this object. |
| `mdm_server_url` | string or null | `"https://jamf.example.org/mdm"` | `ServerURL` from the `com.apple.mdm` payload; null when unenrolled. |
| `mdm_supervised` | string | `"Yes"` | `Yes` \| `No` \| `Unknown`, from `mdmclient DumpManagementStatus` (undocumented, fail-soft). |

Each element of `profiles`:

| Field | Type | Example | Notes |
|---|---|---|---|
| `identifier` | string | `"org.example.firewall"` | `ProfileIdentifier`. The join key for change detection. Empty string on a profile the agent could not decode. |
| `display_name` | string | `"Firewall"` | `ProfileDisplayName`. A label for the reader, not an identity — profiles get renamed. |
| `organization` | string | `"Example Ltd"` | `ProfileOrganization`. |
| `payload` | string | `"[{\"PayloadType\": \"com.apple.security.firewall\"}]"` | The serialised `ProfileItems` list, **head-capped at 2048 bytes**. A JSON *string*, not a nested object. |
| `payload_capped` | boolean | `false` | True when `payload` is a truncated fragment. |
| `decode_error` | boolean | absent / `true` | Present and true only on a profile the agent could not serialise. Its payload content is unknown, not empty. |

**`payload` is stored verbatim as TEXT, never JSONB.** A head-capped payload is a truncated fragment that is not valid JSON and would be rejected by a JSONB column. Re-serialising it into something JSONB would accept is a lossy reparse — the same rule migration `0124` states for Graph object bodies.

**Three different empties, and only one of them means profiles went away.** Conflating these is how an assurance product manufactures a false mass-removal signal:

- **`collection_status` is `rate_limited` or `unavailable`** — the run happened but could not read the real state. macOS rate-limits the `profiles` family to roughly one call per 23 hours (SIP-protected timer file, so a retry within the run cannot help), and the agent then serves its last-known-good cache rather than failing the whole inventory upload. The profile list in such a payload can look perfectly healthy while being arbitrarily stale. The snapshot is stored and flagged, and `appliedconfig.Diff` **rejects it outright** as a diff input, on either side. Same rule `0124`'s `partial` status carries for the Intune path.
- **`profiles_truncated`, or `profiles_count` above the number of entries sent** — the list is bounded, so a profile missing from it may simply be past the cap. The diff engine suppresses exactly the conclusions that need a complete list (an appearance needs a complete prior list, a disappearance needs a complete current list) and records them in `DiffNotes.SuppressedByTruncation`. Field-level changes to profiles present on both sides are unaffected.
- **The device stopped reporting** — no new snapshot row exists at all. That produces no change entries, because there is nothing new to compare. This stays distinguishable from a failed collection in the data model: a failed collection is a stored row with a non-`ok` status, a silent device is the absence of a row.

**A genuine empty is still evidence.** `collection_status: "ok"` with zero profiles and a null `mdm_server_url` is a real observation of an unenrolled Mac, and a profile leaving that list is a real disappearance. That is why "key absent" and "key present, list empty" must stay distinguishable: an absent key writes no snapshot row at all.

**Extractor robustness.** `payload.AppliedConfiguration` is carried as `json.RawMessage`, not a typed struct field, so a malformed shape cannot abort the *entire* payload `json.Unmarshal` in `processRow` — the same isolation `backup_status` and `agent_health` get, for the same reason. `parseAppliedConfiguration` (`internal/extractor/applied_config.go`) decodes it defensively: a decode failure is logged and treated exactly like absent. `ValidatePayload` does not inspect this key (top-level `additionalProperties: true`), so a malformed section can never 400 a device's whole inventory upload.

**Storage (migration `0127`).** Append-only, never UPDATEd: one immutable `applied_config_snapshots` row per device per collection run, plus one verbatim `applied_config_profiles` row per profile. Re-extracting an already-extracted raw payload is a no-op rather than a duplicate snapshot (`UNIQUE (device_id, raw_payload_id)`). No actor column and no policy identity exists anywhere in that schema, because neither is observable from an endpoint.

**Change detection (`internal/appliedconfig`).** `Diff(prior, current)` compares two `ok` snapshots of one device; `Rollup` / `EstateChanges` group the per-device results so the same profile changing on forty Macs is one finding with an affected-device count and list, not forty findings. Change windows are always two observation timestamps — a change is only ever known to have happened *between* two collection runs, never at an exact instant. The canonical-JSON comparison itself is shared with the Intune path via `internal/configdiff`, so a payload re-serialised with its keys reordered is not a change on either path.

---

## Compliance findings array

Added by collector PAT-300 (disk encryption) and PAT-481 (removable storage). Optional. Each element identifies a configuration **violation** detected by the agent — the array carries Fail state only, never Pass. A control the agent assessed and found clean is reported by its **absence** from this array, not by an entry. The extractor flattens each element into a `Fail` signal in `compliance_signals` for the rule engine. Positive "this control passed" attestation lives in `compliance_assessments` (see below), never here.

**`id` enum enforced at ingestion (PAT-913 round 3).** `ValidatePayload` rejects any finding whose `id` is outside the finding-control enum — findings write Fail-state values into the signal map, so an arbitrary `id` could force a Fail onto any rule signal or clobber a legitimate bag key. Same schema-derived enum set as `controls_assessed` (`findingControlIDs`, parsed from the embedded schema at init).

| Field | Type | Example | Notes |
|---|---|---|---|
| `id` | string | `"disk_encryption_off"` | Machine-readable finding ID. |
| `severity` | string | `"critical"` | `low` | `medium` | `high` | `critical`. |
| `volumes` | array | — | Optional detail for `removable_storage_unencrypted`. |

---

## Compliance assessments object

Added by PAT-913 (Option B — positive per-control attestation). Platform-neutral: macOS and Windows agents both emit it. Optional at the wire level, but its absence is meaningful (see below).

| Field | Type | Example | Notes |
|---|---|---|---|
| `controls_assessed` | array of string | `["disk_encryption_off", "removable_storage_unencrypted"]` | The finding-control IDs the agent actually ran a determination for this run. Same ID space as `compliance_findings[].id`. A control belongs in this list **only** if its detection ran to a clean determination; an errored or skipped sub-check must drop its control from the list. |

**Enum enforced at ingestion.** Entries are restricted to exactly the finding-control enum declared in `payload.schema.json`; `ValidatePayload` (`internal/extractor/validate.go`) rejects any payload naming another ID. This is deliberately stricter than the validator's other nested checks because these entries mint positive Pass signals — accepting an arbitrary string would let a compromised device credential fabricate a Pass for any signal key (`filevault`, `defender_realtime`, ...). The enforcement set is `findingControlIDs` (`internal/extractor/finding_controls.go`), parsed at package init from the embedded `payload.schema.json` and shared by the validator and `buildSignalsMap` (which also skips out-of-enum entries with a warning as defence in depth for rows ingested before this enforcement existed and replayed via re-extraction). The schema file is the only hand-maintained copy of the enum — drift is impossible. Adding a new finding control means editing only the schema, at both enum sites (`controls_assessed` items and `compliance_findings[].id`); the loader asserts the two stay identical and fails closed at startup otherwise.

### Three-state semantics (read together with `compliance_findings`)

For each finding-control the extractor's `buildSignalsMap` resolves one of three states, and `compliance_assessments.controls_assessed` is the **sole** source of a positive Pass:

- **Pass** — the control ID appears in `controls_assessed` **and** has no matching entry in `compliance_findings`. Writes a `"Pass"` signal.
- **Fail** — the control has an entry in `compliance_findings`. Writes a `"Fail"` signal (or the volumes JSON for PAT-481 detail). A finding is always a Fail whether or not the control is also listed in `controls_assessed`.
- **Unknown** — the control is neither flagged nor attested (absent from `controls_assessed`). No signal is written; the evaluator applies the rule's `treat_unknown_as`, which for the four critical/medium finding rules is now `'fail'` (migration 0083).

An empty `controls_assessed: []` and an absent `compliance_assessments` section are equivalent: both attest nothing, so every finding-control scores Unknown and the critical rules fail-unknown.

### Backward compatibility (intended score movement)

Every agent deployed before PAT-913 emits **no** `compliance_assessments` section. Under these semantics such an agent produces no Pass attestations, so its finding-controls all score Unknown and the critical disk-encryption rule fails-unknown rather than passing silently. This is the intended correction: "we did not assess this" must not read as "this passed" on an audit-evidence report. Scores move from pass to fail for stale or non-attesting agents until they are updated to emit `controls_assessed`. Rollout ordering is server-first: the server change is backward-compatible and lands before the agent changes that restore Pass signals.

---

## Apps array

Cross-platform inventory of installed applications. The extractor skips items where neither `identifier` nor `bundle_id` yields a usable value (empty or `"Unknown"`).

### Apps completeness (PAT-2063)

`apps` is required, but a required array is not proof of a complete scan. Before PAT-2063 every ingest deleted each `device_apps` row the payload did not list, so an app scan that failed part way (the macOS collector sends `[]` or a shortened list when `find` or a bundle read fails; the Windows scanner drops a registry hive or key it cannot read) removed the missing apps, pruned their CVE findings through the re-match their removal queued, and closed their `software_installations` through the `all_software` scope. `collection_status.apps` says whether the array is the whole machine-wide inventory (per-user rows have their own authority, see [Per-user apps](#per-user-apps-pat-2075)), and without it a safety valve holds back reports that look truncated. Absence requires authority.

| `collection_status.apps` | Sent apps | Unreported `device_apps` rows | Application absence scopes (`all_software`, `windows_winget`) |
|---|---|---|---|
| `complete` (schema_version 3) | upserted | pruned, even when `apps` is `[]` | granted as before |
| `partial` | upserted | kept | withheld |
| `unavailable` (send no machine-wide rows; before PAT-2075, `apps: []`) | upserted (none machine-wide) | kept | withheld |
| absent (every agent before PAT-2063), or `complete` on schema_version 2 | upserted | pruned unless the safety valve holds; while held, see the release rules below | withheld when the valve holds, otherwise as before |

**Safety valve (no signal).** The report is not trusted to prove removals when it reconfirms none of the device's current application identifiers (an empty or fully skipped list never wipes a device), or when more than 5 identifiers AND more than half of the device's current identifiers would disappear at once. An identifier still reported at a new version counts as present, so a version upgrade never trips it. A genuine uninstall of a few apps (1 of 20, or 5 of 8) still prunes. Constants: `appsPruneValveMinRemoved`, `appsPruneValveMaxFraction` in `internal/extractor/apps_authority.go`. The valve is a backstop: a truncated scan that loses less than half the list still prunes on an agent that sends no status, which is why agents should send the field.

**Release rules while held.** Held rows keep their old `last_seen`, so without these a held device would hold on every later report until an explicit `complete` arrived, and no agent sent one yet.

- On a report the safety valve holds, superseded versions still prune. A stale row whose identifier the report lists at another version is deleted: the app was reconfirmed, just not at that version, so this is not an absence claim. Otherwise every upgrade on a held device left the old version's row, and its CVE finding, in place indefinitely. Under an explicit `partial` or `unavailable` nothing prunes, not even superseded versions, because a side-by-side copy of a reported identifier (two Xcodes share one bundle id) may be exactly what the agent missed; its next `complete` report prunes normally.
- Time release applies only when the valve holds on the size of the drop and the report reconfirms at least one of the device's identifiers. An identifier not seen at any version for 7 days (`appsPruneValveReleaseAfter`) is pruned; the recently seen rest of the vanished set stays held. A report that reconfirms nothing gets no time release: an empty or fully skipped list never deletes anything, and only `complete` clears such a device.
- Both prunes queue CVE re-matches exactly as the normal prune does, so the deleted versions' findings go. Neither grants the application absence scopes for that ingest.
- When every vanished identifier was time-released, nothing recent is held back: the ingest still withholds the scopes, but it does not increment `patched_apps_prune_withheld_total` or log the warning (it logs one info line with `superseded_rows` and `released_identifiers`). The next report finds nothing vanished and prunes normally.

Windows caveat: an MSI identifier is the ProductCode GUID, which changes on a major upgrade, so there an upgrade reads as one identifier removed and another added. The old identifier counts towards the valve and is not caught by the superseded-version rule; the time release bounds how long it can linger.

**Inconsistent status.** A well-formed value that contradicts the array (`unavailable` with apps listed, or `complete` with no `apps` array) is not rejected, since that would drop the device's whole inventory every cycle. It is treated as `partial`. A malformed value (not a string, or outside the enum) is rejected with 400 like any enum violation, and a case- or fold-variant key (`APPS`, `Collection_Status`) or a duplicated `collection_status` object is refused by the PAT-2021 key walk.

**Visibility.** Every withheld prune logs one line with the `device_id`, reason and identifier counts, and increments `patched_apps_prune_withheld_total{reason}` (extractor; reasons `partial`, `unavailable`, `inconsistent`, `safety_valve`). The explicit status is merged into `devices.collection_status.apps`, and each `software_inventory_runs.coverage` records `apps_collection_status` and `apps_absence_withheld`. A CVE finding on a kept app is not re-matched as a removal, and the CVE and software-policy lifecycles record an unknown outcome rather than closing anything from a withheld report.

### Per-user apps (PAT-2075)

Per-user installs register under `HKU\<SID>\...\Uninstall` on Windows and in `~/Applications` on macOS, and a user's hive or home folder is readable only while that user is logged in. A report taken after a user logged off is not evidence that the user's apps were uninstalled, so per-user rows have their own scope and their own authority.

**Wire contract.**

- `apps[].user_account` (optional string): the user whose per-user inventory holds the row. Windows sends the account name the SID resolves to (`DOMAIN\user` or `MACHINE\user`), or the SID string when it cannot be resolved; macOS sends the short name. The server treats it as an opaque key and nothing depends on its form. Empty or absent means a machine-wide row, which is every row an agent before PAT-2075 sends.
- `collection_status.apps_users` (optional array): one `{"user_account", "collection_status"}` entry, with an optional `home`, per user the agent tried to read in this run. `user_account` must match the rows' value exactly; both are trimmed on ingest. At most 128 characters, and never truncated, because two users sharing a 128-character prefix would collapse into one and one user's `complete` could prune the other's rows: a row with a longer `user_account` is dropped with a warning, and an `apps_users` entry with one is ignored, so that user gets no authority, the same as `partial`. `collection_status` is `complete`, `partial` or `unavailable`. List a user as `complete` only when their whole per-user inventory was enumerated without error, and include users with no per-user apps as `complete` with no rows. Do not list a user who was not read.
- `collection_status.apps_users[].home` (optional string, both platforms): the absolute path of the user's home directory exactly as the agent resolved it, no trailing slash. See [Legacy user-located rows](#legacy-user-located-rows-pat-2075). **Deploy order:** a server that predates this field rejects the whole report with 400 (an `apps_users` entry with an extra field), so the server must be deployed before any agent sends `home`.
- `collection_status.apps` now speaks for the machine-wide rows only. `unavailable` with per-user rows but no machine-wide rows is consistent.

**Storage.** `device_apps` stays one row per `(device_id, identifier, version)`. The same app installed machine-wide and per-user, or by two users, is one row, one CVE finding and one installation. `device_apps.machine_wide` says whether the machine-wide scope lists the row, and `device_app_user_scopes` holds one row per user that lists it (migration `0180`). A row is deleted only when no scope asserts it any more.

| Scope | Pruned when | Kept when |
|---|---|---|
| Machine-wide (no `user_account`) | exactly as in [Apps completeness](#apps-completeness-pat-2063): `collection_status.apps` = `complete`, or no signal and the safety valve allows it | `partial`, `unavailable`, or the valve holds |
| Per-user, user U | this report's `apps_users` lists U as `complete` (schema_version 3, `apps` array present) | U is missing from `apps_users` (logged off), listed `partial` or `unavailable`, `apps_users` is absent, or the payload is schema_version 2 |

Pruning a scope drops only that scope's claim. A machine-wide prune of an app that a user still holds keeps the row with `machine_wide = false`; a user's `complete` report without an app that is also machine-wide keeps the row.

**Safety valve.** The PAT-2063 valve counts machine-wide identifiers only, so per-user rows of absent users never inflate the "current" count or the "vanished" count, and a report that reconfirms an identifier only per-user does not count as reconfirming it machine-wide. The superseded-version and time-release rules apply to machine-wide assertions only. Per-user scopes have no valve and no time release: nothing per-user is pruned without an explicit `complete`, which is the stricter of the two PAT-2063 layers. A consequence is that a user whose profile is deleted from the device keeps their rows until an agent reports them `complete` with no apps; the agent should do that for a profile it can see was removed.

**Absence consumers.**

- CVE matching, the event-driven re-match (`ChangedProducts`), the nightly `patched-cve-sync`, reports and the portal read `device_apps`, so a held per-user app stays present for all of them and is never queued as a removal.
- The installation closure for the `all_software` and `windows_winget` scopes skips any installation whose identity fingerprint a remaining `device_app_user_scopes` row still holds.
- The software-policy lifecycle evaluates the report's apps plus the held per-user apps, so an unapproved per-user app of a logged-off user is not verified fixed and a mandatory one is not reported missing.

#### Legacy user-located rows (PAT-2075)

A macOS agent before PAT-2075 walked `/Users/*/Applications` as part of its machine-wide scan, so an app in a user's `~/Applications` is stored as a machine-wide row whose `path` lies in that user's home. An agent that scopes users itself reports the same app under a user scope, and its `collection_status.apps = complete` covers the machine roots only (`/Applications`, `/Applications/Utilities`, `/Users/Shared/Applications`). Its machine-wide report therefore has no authority over such a row.

The rule applies to a report that **carries the `apps_users` key** (an empty array counts) and to a stored machine-wide row whose path is `/Users/<name>/...` with `<name>` other than `Shared`. A report without the key comes from an agent whose `complete` does cover `/Users/*/Applications`, and prunes exactly as before. `/Users/Shared`, a path directly under `/Users`, and a row with no path are ordinary machine-wide rows. Windows never has such rows: its agents never reported per-user hives machine-wide and send no `path`.

| Outcome | When |
|---|---|
| Re-homed | The report lists the same identifier under a user scope, at the row's stored path or for a user whose `home` equals the row's home directory. The same version is the same `device_apps` row: it loses `machine_wide` and keeps the user's scope, under any machine-wide status. Another version at the stored path is the same installation upgraded: the old row is released and the new row inherits its `first_seen`. The same app listed only by a user in a different home is not evidence and changes nothing. |
| Pruned by its owner | An `apps_users` entry is `complete` (schema_version 3, `apps` array present), its `home` equals the row's home directory, and that user did not list the app. Works while the machine-wide scope is `partial`, like any per-user prune. |
| Held | Everything else: the user is `partial`, `unavailable` or not listed, sends no `home`, or sends a `home` that is not the row's. No timer: the machine-wide prune, the superseded-version prune and the time release all skip a held row. |

`home` is compared for equality with the row's home directory (`/Users/<name>`), never as a prefix, and is never inferred from `user_account` or from a path basename: an account name and its home directory name can differ. A `home` that is not exactly `/Users/<name>` (relative, a `.` or `..` segment, a trailing slash, `/`, `/Users`, `/Users/Shared`), a `home` sent by two different users, or a user sending two different homes grants nothing. A non-string `home` is rejected with 400.

A held row stays in `device_apps`, so CVE matching and the unapproved-software alert keep seeing it. The installation closure skips its identity, the software-policy lifecycle evaluates it as present (not verified fixed, not mandatory-missing), and its `usage_evidence_complete` is cleared, because a row no report refreshes cannot support an unused-software conclusion. Each run records the number it held in `software_inventory_runs.coverage.apps_legacy_user_held`, and the extractor logs a warning, so a device stuck holding rows is visible. A device clears the state when the user's folder is read in full by an agent that sends `home`.

A legacy payload (no `user_account`, no `apps_users`) writes only machine-wide rows and no scope rows, and behaves exactly as before. A case- or fold-variant key (`User_Account`, `Apps_Users`, `uſer_account`) is refused with 400 by the PAT-2021 key walk; a non-string `user_account`, or an `apps_users` entry with a missing required field, a field other than `user_account`, `collection_status` and `home`, an out-of-enum status or a non-string `home`, is refused by `ValidatePayload`. Two `apps_users` entries for one user merge, least authoritative wins, and an entry with an empty `user_account` is ignored.

**Identifier field handling:** `identifier` is the canonical cross-platform field (v3+). For v2 macOS payloads that carry `bundle_id`, the extractor falls back to `bundle_id` automatically — no migration of existing payloads needed. The DB column is `device_apps.identifier` in both cases.

| Field | Type | Required | macOS example | Windows example | Notes |
|---|---|---|---|---|---|
| `name` | string | **yes** | `"Safari"` | `"Microsoft Edge"` | Display name |
| `version` | string | **yes** | `"17.4.1"` | `"124.0.2478.97"` | Version string |
| `identifier` | string | v3+ | `"com.apple.Safari"` | `"Microsoft Edge"` | Primary cross-platform identifier. macOS (v3+): `CFBundleIdentifier`. Windows: registry uninstall-key name. Extractor prefers this over `bundle_id`. |
| `bundle_id` | string | v2 | `"com.apple.Safari"` | absent | macOS `CFBundleIdentifier`. v2 legacy field — extractor falls back to this when `identifier` is absent. |
| `publisher` | string | no | absent | `"Microsoft Corporation"` | Application publisher. Windows: registry `Publisher` value. macOS: typically absent. |
| `path` | string | no | `"/Applications/Safari.app"` | absent | Absolute installation path (macOS) |
| `size_mb` | float | no | `64.32` | absent | `du -sk` → MB (macOS) |
| `modified_at` | string (ISO 8601 UTC) | no | `"2026-10-01T10:00:00Z"` | absent | `stat` modification time (macOS) |
| `architecture` | string | no | `"arm64"`, `"x86_64 arm64"` | `"x86_64"` | CPU architecture |
| `sha256` | string | no | `"abc123..."` | absent | SHA-256 of the main executable (macOS) |
| `team_id` | string | no | `"AAPL"` | absent | `codesign` TeamIdentifier (macOS) |
| `signed_by` | string | no | `"Apple Inc."` | absent | First `Authority=` from `codesign -dvv` (macOS) |
| `notarized` | boolean | no | `true` | absent | macOS. `true` only when `notarization_status` is `notarized` (PAT-2112), otherwise `false`, including when notarisation could not be determined. Kept for older servers; collectors before PAT-2112 sent `false` for every app. |
| `signing_status` | string (enum) | no | `"signed"` | absent | PAT-2112/PAT-2117, macOS only. `signed`, `adhoc`, `unsigned`, `error`, `untrusted` or `invalid`, from `codesign -dvv`. See [Signing and notarisation](#signing-and-notarisation-macos-pat-2112). |
| `notarization_status` | string (enum) | no | `"notarized"` | absent | PAT-2112, macOS only. `notarized`, `not_notarized` or `unknown`, from Gatekeeper (`spctl`) with the stapled ticket as fallback. See [Signing and notarisation](#signing-and-notarisation-macos-pat-2112). |
| `last_used_at` | string (ISO 8601 UTC) or null | v0.10.0+ | `"2026-12-13T09:27:44Z"` | absent | Software metering: Spotlight `kMDItemLastUsedDate` (last launch via LaunchServices). `null` = no recorded usage — never launched, or metering unavailable. See below. |
| `launch_count` | integer or null | v0.10.0+ | `503` | absent | Software metering: Spotlight `kMDItemUseCount`. **Lifetime cumulative** launch count, not windowed. `null` when unavailable. |
| `installation_evidence` | object | no | absent | see below | PAT-2113/PAT-2116, Windows only. Per-installation Authenticode evidence: every app from updater #668, reviewed evidence targets only before. See [Authenticode evidence](#authenticode-evidence-windows-pat-2113). |
| `user_account` | string | no | `"alice"` | `"S-1-5-21-…-1001"` | PAT-2075. The user whose per-user inventory holds the app. Empty or absent = machine-wide. See [Per-user apps](#per-user-apps-pat-2075). |

### Signing and notarisation (macOS, PAT-2112)

Before PAT-2112 `signed_by` was `"Unknown"` whenever `codesign -dvv` printed no `Authority=` line, which covers an unsigned app, an ad hoc signed one and codesign failing alike, and `notarized` was always `false` (the collector looked for the word "Notarized", which codesign never prints). Two optional fields now carry the evidence explicitly. `signed_by`, `team_id` and `notarized` keep their shape.

`signing_status`, from codesign's exit status and output:

| Value | Meaning |
|---|---|
| `signed` | exit 0 and an `Authority=` line: a signing identity that chains to Apple. `signed_by` is its leaf. |
| `adhoc` | exit 0 and `Signature=adhoc`: signed with no identity, so no publisher. |
| `unsigned` | codesign reported `code object is not signed at all`. |
| `error` | anything else: codesign failed or its output could not be read. Not evidence of unsigned. |
| `untrusted` | PAT-2117. exit 0 and an `Authority=` line, but the certificate chain does not anchor to Apple: typically a self-signed certificate whose Subject CN copies the `Developer ID Application: …` naming convention to look legitimate. `signed_by` and `team_id` can still read as a genuine Developer ID; the server never treats either as an established publisher for this status. `notarization_status` is reported `not_notarized`. |
| `invalid` | PAT-2117. The signature does not validate against the code at all: tampered, or broken after signing. `notarization_status` is reported `unknown`. |

`notarization_status`:

| Value | Meaning |
|---|---|
| `notarized` | Gatekeeper (`spctl --assess --type execute -vv`, under a 10 second timeout) accepted the app with source `Notarized Developer ID`; or spctl timed out, is missing or named no source and codesign shows `Notarization Ticket=stapled`. Many notarised apps are not stapled, which only spctl sees. |
| `not_notarized` | The app is not a notarised Developer ID app: unsigned, ad hoc, signed by a non-Developer ID identity (Apple system and Mac App Store apps are never notarised, and spctl is not run for them), or Gatekeeper named another source. An unstapled app assessed while offline can read this. |
| `unknown` | codesign failed, or neither spctl nor a stapled ticket could answer. |

Only `notarized` confirms notarisation. `not_notarized`, `unknown` and an absent field all read as "not confirmed" (PAT-2093's `notarisation_not_confirmed`), never as a verdict against the app. Absent `signing_status` (an older agent) is not reported, never unsigned.

Both fields are macOS only. Windows agents do not send them; Windows signing evidence is `apps[].installation_evidence` (PAT-2113, below). The extractor stores them on `software_observations` (`observed_signing_status`, `observed_notarization_status`, migration 0185, widened by migration 0187 for `untrusted`/`invalid`) for a macOS report only; a Windows row, a string outside the enum and an absent field are all stored as NULL (not reported). A non-string value is refused with 400, because it would otherwise fail the decode of the whole report.

### Authenticode evidence (Windows, PAT-2113)

Before updater #668 the Windows agent attached `installation_evidence` to an app only when its MSI ProductCode matched a reviewed target in the signed `windows_installation_evidence` delivery (PAT-1921; the published target set is empty). From updater #668 (PAT-2116) every app row the scanner reports carries it: the agent resolves one executable per row from the uninstall entry's `DisplayIcon` or `InstallLocation` (inside Program Files only, never guessed) and verifies it in a killable helper. A row whose executable could not be resolved carries `signature_state: "unknown"`, never a guess.

The block also carries `catalogue_version`, `delivery_version`, `content_hash` (reviewed targets only), `collection_status`, `collected_at`, `source` (`windows_authenticode_offline`), `install_path`, `executable_path`, `executable_sha256` and `errors`. The platform reads these members:

| Member | Values | Meaning |
|---|---|---|
| `signature_state` | `valid` | WinVerifyTrust (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) accepted the executable against the device's trust store: its embedded signature, or, only when it has none, a SHA-256 catalog membership (how Windows signs its own binaries). Offline: cache-only URL retrieval and no revocation check, so never current revocation assurance. |
| | `invalid` | `TRUST_E_BAD_DIGEST` only: the file changed after it was signed. |
| | `unsigned` | PAT-2116, conservative: the embedded check returned exactly `TRUST_E_NOSIGNATURE`, the SHA-256 catalog lookup ran and found no catalog, no SHA-1 catalog lists the file either, and the same helper run proved the catalog database works (a known Windows binary was found as a SHA-256 member). Anything short of all four is `unknown`. |
| | `unknown` | Anything else: an untrusted or unreadable chain, a catalog lookup that could not run, verification failing, the file unreadable, no executable resolved. |
| `signer` | string, up to 512 characters | The leaf signer certificate's Subject DN, sent only with `valid` and omitted when it could not be read. On its own it names a publisher but does not pin one: a root in the device's own trust store (an enterprise CA, say) could issue the same name. |
| `signer_thumbprint` | 64 lower-case hex | PAT-2116, only with `valid`. SHA-256 over the leaf certificate's DER. Stored for audit; it changes whenever the certificate renews, so it is not a publisher key. |
| `issuer` | string, up to 512 characters | PAT-2116, only with `valid`. The leaf certificate's Issuer DN. |
| `root_thumbprint` | 64 lower-case hex | PAT-2116, only with `valid`. SHA-256 of the last certificate in WinVerifyTrust's own provider chain: the trust anchor the verdict rests on. Omitted when the chain could not be read (`root_kind` is then `enterprise`). |
| `root_kind` | `microsoft`, `public`, `enterprise` | PAT-2116, only with `valid`. `microsoft`: the root is one of four hard-coded Microsoft roots. `public`: a self-issued root in the registry `AuthRoot` physical store, where Windows' automatic root update places Microsoft Trusted Root Program roots. `enterprise`: anything else (only in `LocalMachine\Root` or a Group Policy or Enterprise store, not self-issued, an unreadable chain, any doubt). |
| `executable_resolution` | `reviewed_target`, `display_icon`, `install_location_single_exe` | PAT-2116. How the executable was tied to the app row. Absent when none was resolved (the reason is in `errors`) and from older agents. Diagnostic only, never read as trust. |

The extractor stores them on `software_observations` (`observed_signature_state`, `observed_authenticode_signer`, migration 0186; `observed_authenticode_signer_thumbprint`, `observed_authenticode_issuer`, `observed_authenticode_root_thumbprint`, `observed_authenticode_root_kind`, `observed_executable_resolution`, migration 0188) for a Windows report only, the four publisher members and the signer only beside `valid`. Each is validated on its own (DNs 1 to 512 characters with no control characters, thumbprints 64 hex characters, lower-cased, `root_kind` in its enum, `executable_resolution` a lower-case code of at most 64 characters); a value that fails, a state outside the enum, a macOS row and an absent block are all stored as NULL (not reported), never refusing the report. A block that is not an object, or a non-string value for any member named above, is refused with 400, because it would otherwise fail the decode of the whole report. The registry `publisher` is unchanged and never read as a signature. The top-level `installation_evidence` summary (with PAT-2116's `coverage`: `collection_status`, `attempted`, `resolved`, `errors`) is accepted and not stored.

### Software metering (Windows and macOS)

Usage is an observation, not proof that an application was never used. Windows
UserAssist and macOS Spotlight cover user launches and can miss services,
runtimes, direct execution and unreadable user stores.

`apps[].usage_evidence` (PAT-2328) is optional and platform-neutral:

| State | Meaning |
| --- | --- |
| `recorded` | A valid `last_used_at` or positive `launch_count` was read. A count without a date cannot establish inactivity. |
| `no_record` | The supported source was readable but contained no matching launch record. This never proves non-use. |
| `unmapped` | The app cannot be mapped to the usage source. It counts as unmetered. |
| `unavailable` | Usage collection failed for the app. It counts as unmetered. |
| absent | Not reported by this agent. It remains NULL and follows the conservative PAT-2327 behaviour. |

`no_record` sends no timestamp and a null, absent or zero count. `unmapped`
sends null or absent timestamps and counts.
`unavailable` may retain a successful partial date/count reading while another
read failed; it still counts as unmetered and cannot prove non-use. `recorded`
requires a RFC3339 timestamp or positive count. State claims alone cannot
invent usage or prove non-use. Null, unknown and empty state values are invalid.

The top-level `metering_status` is `ok`, `spotlight_disabled`, `no_user_session`,
`userassist_unavailable` or `unavailable`. A Windows `ok` requires actual readable
UserAssist records. The optional nullable integer counts
`metering_user_hive_count` (Windows) and `metering_record_count` carry raw
collector counts; absent counts remain NULL, never zero.

The extractor stores the raw per-app state separately from
`usage_evidence_at` (inventory receipt time) and `usage_evidence_complete`
(derived non-use authority: complete app scope and a date in this reading, not an agent claim). A new app observation can
reset the state to NULL/not reported while retaining historical last-use and
launch-count values. Out-of-order extraction does not overwrite newer evidence.
A partial/unavailable or unreported collection scope grants no new non-use
authority; per-user rows need that user's explicit complete scope. All previously
asserted user scopes must be explicitly complete before a new shared app reading
can gain authority. Conflicting readings or several user scopes in one payload
project as unavailable, preserving each original reading in the raw payload.
Windows partial hive reads report global `userassist_unavailable`, even when a
positive app reading survives; an `ok` device status remains required for non-use.

An unused verdict requires a fresh metered device, a non-server installation,
a recorded last-use older than 90 days, and, for newly extracted rows, fresh
per-app observation with complete collection and a timestamp in that raw report.
`no_record`, `unmapped`, `unavailable`, partial scope and a later report without
usage cannot promote a retained timestamp into current non-use. Pre-migration
rows keep PAT-2327's historical readings, but require the app's `last_seen`
to be fresh alongside the device: `COALESCE(usage_evidence_at, last_seen)`
is the per-app freshness clock (PAT-2361). An unrelated device heartbeat
cannot renew an old app observation or make it a removal candidate.
Historical values exposed by the per-device read-back must be interpreted
alongside current evidence state, time and completeness.

`launch_count` is a lifetime cumulative count. It is not a windowed count.

---

## Concrete example — macOS payload (abbreviated)

```json
{
  "schema_version": 2,
  "agent": "patched-collect",
  "agent_version": "0.3.0",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "collected_at": "2026-11-15T14:23:01Z",
  "metering_status": "ok",
  "device": {
    "serial": "C02XK1ZFABCD",
    "hw_uuid": "01234567-89AB-CDEF-0123-456789ABCDEF",
    "hostname": "andys-mbp",
    "computer_name": "Andy's MBP",
    "hw_model": "Mac14,2",
    "arch": "arm64",
    "last_boot": "2026-11-14T09:11:00Z"
  },
  "hardware": {
    "cpu_model": "Apple M2",
    "cpu_cores": 8,
    "ram_gb": 16,
    "disk_total_gb": 494.4,
    "disk_free_gb": 312.1
  },
  "os": {
    "name": "macOS",
    "version": "15.4.1",
    "build": "24E263"
  },
  "compliance": {
    "filevault": "On",
    "sip": "enabled",
    "gatekeeper": "enabled",
    "firewall": "enabled",
    "xprotect_version": "5281",
    "mrt_version": "1.97",
    "pending_updates_count": 0,
    "mdm_enrolled": "Yes",
    "mdm_enrolled_via_dep": "Yes",
    "mdm_enrolment": "dep=Yes mdm=Yes",
    "secure_boot": "Full Security",
    "auto_security_updates": "On",
    "audit_logging": "enabled",
    "remote_apple_events": "Off",
    "remote_login": "Off",
    "screen_sharing": "Off",
    "sealed_system_volume": "enabled",
    "screensaver_password": "Yes",
    "screensaver_delay_seconds": 5,
    "auto_login_user": "None",
    "local_admin_count": 1,
    "password_policy_present": "Yes",
    "password_policy_is_default": "No",
    "password_policy_raw": "<?xml version=\"1.0\"...>"
  },
  "security_tools": [
    { "id": "crowdstrike-falcon", "name": "CrowdStrike Falcon" }
  ],
  "system_extensions": [
    {
      "enabled": true,
      "active": true,
      "team_id": "VB5E2TV963",
      "bundle_id": "com.crowdstrike.falcon.App",
      "version": "7.15.0",
      "name": "CrowdStrike Falcon",
      "state": "[activated enabled]"
    }
  ],
  "background_items": [],
  "icloud": { "signed_in": "Yes" },
  "pending_updates": [],
  "patches": [
    {
      "name": "macOS 15.3",
      "version": "15.3",
      "installed_at": "2025-06-02T14:23:08Z",
      "date_raw": "06/02/2025, 14:23:08"
    }
  ],
  "apps": [
    {
      "name": "Safari",
      "version": "17.4.1",
      "bundle_id": "com.apple.Safari",
      "path": "/Applications/Safari.app",
      "size_mb": 64.32,
      "modified_at": "2026-10-01T10:00:00Z",
      "architecture": "arm64",
      "sha256": "abc123def456...",
      "team_id": "not set",
      "signed_by": "macOS Software Signing",
      "notarized": false,
      "signing_status": "signed",
      "notarization_status": "not_notarized",
      "last_used_at": "2026-12-13T09:27:44Z",
      "launch_count": 503
    }
  ]
}
```

## Schema v3 changes

Schema v3 folds two sets of changes into one envelope revision:

1. **Windows compatibility** — the envelope is now cross-platform. `platform` field added; macOS-only sections (`system_extensions`, `background_items`, `icloud`) become optional; `identifier` replaces `bundle_id` as the primary app identifier; `publisher` added for Windows registry data.
2. **T2 compliance signals** — the `compliance` bag accepts the T2 signal keys from ADR-0001 action item 5. No code change needed — `compliance` is `additionalProperties: true` and the extractor's `complianceMap` is a generic `map[string]json.RawMessage`.

**v2 → v3 differences in brief:**

| Item | v2 | v3 |
|---|---|---|
| `platform` field | absent | `"macos"` or `"windows"` (required) |
| `system_extensions` | required | optional (macOS only; omit in Windows payloads) |
| `background_items` | required | optional (macOS only) |
| `icloud` | required | optional (macOS only) |
| `device.computer_name` | required | optional (macOS only) |
| `apps` identifier | `bundle_id` (required) | `identifier` (required); `bundle_id` kept as optional legacy |
| `apps.publisher` | absent | optional (Windows registry `Publisher`) |
| `compliance` bag | T1 keys only | T1 + T2 keys |

**Transition rules:**
- The extractor accepts both v2 and v3 from the same poll cycle — no flag day required.
- v2 macOS payloads: `platform` absent → extractor defaults to `"macos"`; `bundle_id` used as identifier.
- v3 macOS payloads: emit `platform: "macos"`, use `identifier` (= CFBundleIdentifier), omit macOS-only sections as desired.
- v3 Windows payloads: emit `platform: "windows"`, use `identifier` (= uninstall-key name), omit `system_extensions`, `background_items`, `icloud`.
- Per-tenant T2 activation: governed by `tenant_rules`. A device submitting T2 signals does not mean those signals are evaluated — only tenants with an `enabled = true` row in `tenant_rules` for the rule get a verdict.

**Windows payload example (v3, abbreviated):**

```json
{
  "schema_version": 3,
  "platform": "windows",
  "agent": "patched-collect-win",
  "agent_version": "0.1.0",
  "tenant_id": "22222222-2222-2222-2222-222222222222",
  "collected_at": "2026-11-21T10:00:00Z",
  "device": {
    "serial": "DMT9876543",
    "hw_uuid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
    "hostname": "DESKTOP-ROBWIN",
    "hw_model": "Dell OptiPlex 7090",
    "arch": "x86_64",
    "last_boot": "2026-11-21T08:00:00Z"
  },
  "hardware": { "cpu_model": "Intel Core i7-10700", "cpu_cores": 8, "ram_gb": 16, "disk_total_gb": 476.9, "disk_free_gb": 210.3 },
  "os": { "name": "Windows", "version": "11.0.22631", "build": "22631.3593" },
  "compliance": {
    "bitlocker_os_drive": "On",
    "windows_firewall_domain": "enabled",
    "defender_realtime": "enabled",
    "uac_enabled": "Yes",
    "password_min_length": 14,
    "password_complexity_enabled": "Yes",
    "account_lockout_threshold": 5
  },
  "security_tools": [{ "id": "defender-for-endpoint", "name": "Microsoft Defender for Endpoint" }],
  "apps": [
    {
      "name": "Microsoft Edge",
      "version": "124.0.2478.97",
      "identifier": "Microsoft Edge",
      "publisher": "Microsoft Corporation",
      "architecture": "x86_64"
    },
    {
      "name": "7-Zip 23.01 (x64)",
      "version": "23.01",
      "identifier": "{23170F69-40C1-2702-2301-000001000000}",
      "publisher": "Igor Pavlov",
      "architecture": "x86_64"
    }
  ]
}
```

**macOS T2 compliance signal keys (planned — subject to revision during action item 5 batching):**

Full inventory with CIS references in `go-service/docs/CIS_L1_GAP.md`.

| Signal key | Type | CIS section | Source | Notes |
|---|---|---|---|---|
| `pwpolicy_lockout_threshold` | integer | §5.2.6 | parsed from `password_policy_raw` | Lockout after N failures |
| `pwpolicy_lockout_reset_minutes` | integer | §5.2.6 | parsed from `password_policy_raw` | Reset window |
| `pwpolicy_min_length` | integer | §5.2.3 | parsed from `password_policy_raw` | Min password length |
| `pwpolicy_max_age_days` | integer | §5.2.5 | parsed from `password_policy_raw` | Max password age |
| `pwpolicy_history_depth` | integer | §5.2.8 | parsed from `password_policy_raw` | Password history depth |
| `update_check_auto` | string | §1.2 | `softwareupdate` prefs | `"On"` / `"Off"` |
| `update_download_auto` | string | §1.3 | `softwareupdate` prefs | `"On"` / `"Off"` |
| `app_updates_auto_install` | string | §1.4 | `softwareupdate` prefs | `"On"` / `"Off"` |
| `xprotect_data_auto_update` | string | §1.4 | `softwareupdate` prefs | `"On"` / `"Off"` |
| `critical_updates_auto_install` | string | §1.4 | `softwareupdate` prefs | `"On"` / `"Off"` |
| `firewall_stealth_mode` | string | §2.5.2.2 | `socketfilterfw` | `"enabled"` / `"disabled"` |
| `airdrop_disabled` | string | §2.4.6 | `defaults` / managed prefs | `"Yes"` / `"No"` |
| `airplay_receiver_disabled` | string | §2.4.x | managed prefs | `"Yes"` / `"No"` |
| `internet_sharing_disabled` | string | §2.4.8 | `launchctl` | `"Off"` / `"On"` |
| `printer_sharing_disabled` | string | §2.4.3 | `launchctl` | `"Off"` / `"On"` |
| `remote_management_disabled` | string | §2.4.5 | `launchctl` | `"Off"` / `"On"` |
| `bluetooth_sharing_disabled` | string | §2.4.13 | `launchctl` | `"Off"` / `"On"` |
| `time_server_host` | string | §2.2.1 | `systemsetup -getnetworktimeserver` | NTP host |
| `time_server_enforced` | string | §2.2.1 | managed prefs | `"Yes"` / `"No"` |
| `timed_running` | string | §2.2.x | `launchctl` | `"Yes"` / `"No"` |
| `smbd_disabled` | string | §2.4.x | `launchctl` | `"Off"` / `"On"` |
| `httpd_disabled` | string | §4.1 | `launchctl` | `"Off"` / `"On"` |
| `nfsd_disabled` | string | §4.2 | `launchctl` | `"Off"` / `"On"` |
| `sudo_timeout_minutes` | integer | §5.4 | `/etc/sudoers` parse | Minutes; 0 = always prompt |
| `sudo_timestamp_type` | string | §5.4 | `/etc/sudoers` parse | `"tty"` / `"global"` / `"ppid"` |
| `root_disabled` | string | §5.6 | `dscl . read /Users/root AuthenticationAuthority` | `"Yes"` / `"No"` |
| `guest_account_disabled` | string | §2.x | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` | `"Yes"` / `"No"` |
| `smb_guest_disabled` | string | §2.x | `defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess` | `"Yes"` / `"No"` |
| `loginwindow_fullname_prompt` | string | §2.x | `defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME` | `"Yes"` / `"No"` |
| `password_hints_absent` | string | §2.x | `defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint` | `"Yes"` (hints off) / `"No"` |
| `siri_disabled` | string | §2.x | managed prefs | `"Yes"` / `"No"` |
| `home_folders_mode` | string | §5.x | `stat` on `/Users/*` | octal mode string |
| `amfi_enabled` | string | §5.x | `nvram` / `csrutil` | `"Yes"` / `"No"` |
| `firewall_logging` | string | §3.x | `socketfilterfw --getloggingmode` | `"detail"` / `"brief"` / `"throttled"` |
| `audit_retention_expire` | string | §3.x | `/etc/security/audit_control` `expire-after` | value string |
| `install_log_retention_days` | integer | §3.x | `asl.conf` / unified log retention | days |
| `xprotect_running` | string | §5.x | `launchctl print-disabled system` XProtect | `"Yes"` / `"No"` |

Signals in §3.5 (audit file permissions) are batched together and detailed in `CIS_L1_GAP.md §3.5`. Signal keys follow the pattern `audit_log_<path_slug>_mode` (e.g. `audit_log_audit_mode`, `audit_log_audit_warn_sh_mode`). All 11 are collected in a single pass.

**Windows T2 compliance signal keys (PAT-405 expansion; batch 1 in `patched-agent-win` v0.4.0):**

Batched plan and parity rationale in `go-service/docs/WINDOWS_T2_GAPMAP.md`. Batch 1 (§1.1/§1.2 account & password policy) is sourced from `secedit /export` `[System Access]`; rules seeded in migration `0024_windows_t2_account_policy.sql`.

| Signal key | Type | CIS section | Source | Notes |
|---|---|---|---|---|
| `password_history_count` | integer | §1.1.1 | `secedit` PasswordHistorySize | Passwords remembered |
| `password_max_age_days` | integer | §1.1.2 | `secedit` MaximumPasswordAge | Collector clamps 0/-1 (never) → `99999` so `lte 365` fails |
| `password_min_age_days` | integer | §1.1.3 | `secedit` MinimumPasswordAge | Min age before change |
| `password_min_length` | integer | §1.1.4 | `secedit` MinimumPasswordLength | Min password length |
| `password_complexity_enabled` | string | §1.1.5 | `secedit` PasswordComplexity | `"Yes"` / `"No"` |
| `password_reversible_encryption_disabled` | string | §1.1.7 | `secedit` ClearTextPassword | `"Yes"` when disabled (compliant) |
| `account_lockout_duration_minutes` | integer | §1.2.1 | `secedit` LockoutDuration | Lockout duration |
| `account_lockout_threshold` | integer | §1.2.2 | `secedit` LockoutBadCount | Collector clamps 0 (never) → `999` so `lte 5` fails |
| `account_lockout_reset_minutes` | integer | §1.2.4 | `secedit` ResetLockoutCount | Reset-counter window |

**Windows T2 batch 2 — Advanced Audit Policy (§17; `auditpol`):** each signal carries the subcategory's verbatim Inclusion Setting (`"No Auditing"` / `"Success"` / `"Failure"` / `"Success and Failure"`); rules use `contains`/`eq`. Migration `0025_windows_t2_audit_policy.sql`.

| Signal key | Type | CIS section | Source | Notes |
|---|---|---|---|---|
| `audit_credential_validation` | string | §17.1.1 | `auditpol` Credential Validation | rule eq `Success and Failure` |
| `audit_user_account_management` | string | §17.2.3 | `auditpol` User Account Management | rule eq `Success and Failure` |
| `audit_security_group_management` | string | §17.2.2 | `auditpol` Security Group Management | rule contains `Success` |
| `audit_process_creation` | string | §17.3.2 | `auditpol` Process Creation | rule contains `Success` |
| `audit_logon` | string | §17.5.4 | `auditpol` Logon | rule eq `Success and Failure` |
| `audit_account_lockout` | string | §17.5.1 | `auditpol` Account Lockout | rule contains `Failure` |
| `audit_policy_change` | string | §17.7.1 | `auditpol` Audit Policy Change | rule contains `Success` |
| `audit_sensitive_privilege_use` | string | §17.8.1 | `auditpol` Sensitive Privilege Use | rule eq `Success and Failure` |
| `audit_system_integrity` | string | §17.9.5 | `auditpol` System Integrity | rule eq `Success and Failure` |
| `audit_security_state_change` | string | §17.9.3 | `auditpol` Security State Change | rule contains `Success` |

**Windows T2 batch 3 — Security Options / UAC (§2.3; registry):** binary controls emit `Yes`/`No` (Yes = compliant); two emit numerics. Migration `0026_windows_t2_security_options.sql`.

| Signal key | Type | CIS section | Source (registry value) | Notes |
|---|---|---|---|---|
| `block_microsoft_accounts` | string | §2.3.1.1 | NoConnectedUser | Yes if 3 |
| `audit_force_subcategory_policy` | string | §2.3.2.1 | SCENoApplyLegacyAuditPolicy | Yes if 1 |
| `dont_display_last_username` | string | §2.3.7.2 | DontDisplayLastUserName | Yes if 1 |
| `machine_inactivity_limit_seconds` | integer | §2.3.7.3 | InactivityTimeoutSecs | rule lte 900; collector clamps 0 → 99999 |
| `restrict_anonymous_sam` | string | §2.3.10.2 | RestrictAnonymousSAM | Yes if 1 |
| `no_lm_hash` | string | §2.3.11.1 | NoLMHash | Yes if 1 |
| `lan_manager_auth_level` | integer | §2.3.11.7 | LmCompatibilityLevel | rule gte 5 |
| `uac_admin_approval_builtin` | string | §2.3.17.4 | FilterAdministratorToken | Yes if 1 |

**Windows T2 batch 4 — Services & features (§18; registry):** the collector always emits `Yes`/`No` per control (per-control absent-semantics in `ServicesFeaturesParser`); rule `eq Yes`. Migration `0027_windows_t2_services_features.sql`.

| Signal key | CIS | Source (HKLM) | absent → |
|---|---|---|---|
| `smbv1_disabled` | §18.4.3 | …\Services\mrxsmb10\Start ==4 | Yes (not installed) |
| `llmnr_disabled` | §18.6.4.1 | …\DNSClient\EnableMulticast ==0 | No |
| `autoplay_disabled` | §18.9.8.2 | …\Explorer\NoDriveTypeAutoRun ==255 | No |
| `always_install_elevated_disabled` | §18.9.85.1 | …\Installer\AlwaysInstallElevated !=1 | Yes |
| `remote_assistance_disabled` | §18.8.36.1 | …\Terminal Services\fAllowToGetHelp ==0 | No |
| `wdigest_cleartext_disabled` | §18.3.7 | …\WDigest\UseLogonCredential !=1 | Yes |

**Windows T2 batch 5 — Defender policy detail (§18.9.47; registry):** the collector always emits `Yes`/`No` per control (per-control absent-semantics in `DefenderPolicyParser`); rule `eq Yes`. Migration `0028_windows_t2_defender_policy.sql`.

| Signal key | CIS | Source (HKLM\…\Windows Defender) | absent → |
|---|---|---|---|
| `defender_cloud_protection` | §18.9.47.4.1 | Spynet\SpynetReporting !=0 | No |
| `defender_sample_submission` | §18.9.47.4.2 | Spynet\SubmitSamplesConsent ∈{1,3} | No |
| `defender_pua_protection` | §18.9.47.8 | PUAProtection ==1 | No |
| `defender_behavior_monitoring` | §18.9.47.9 | Real-Time Protection\DisableBehaviorMonitoring ==0 | Yes |
| `defender_scan_removable_drives` | §18.9.47.12 | Scan\DisableRemovableDriveScanning ==0 | No |
| `defender_archive_scanning` | §18.9.47.11 | Scan\DisableArchiveScanning ==0 | Yes |

This batch completes the Windows T2 expansion → **52 Windows rules, parity with macOS (52)**.

---

## Cross-references

- **Parser:** `go-service/internal/extractor/payload.go` — `payload` struct and nested types, including `backupStatusPart` (PAT-948) and `agentHealthEnvelope`/`agentHealthEntryPart` (PAT-1064)
- **Extraction:** `go-service/internal/extractor/upsert.go` — `upsertDevice`, `upsertApps`, `upsertPatches`, `upsertCertificates`, `upsertHardwareHealth`, `upsertLocalAdmins` (PAT-1974), `parseBackupStatus`, `upsertAgentHealth`, `buildSignalsMap`
- **Applied configuration (PAT-1668):** `go-service/internal/extractor/applied_config.go` (parse + append-only insert), `go-service/internal/appliedconfig/` (diff, estate rollup, read store), `go-service/internal/configdiff/` (canonical-JSON comparison shared with the Intune path)
- **Admin read:** `GET /admin/tenants/{tenantID}/agent-health` — `internal/handlers/agent_health.go`, `internal/report/agent_health.go` (PAT-1064; consumed by the dashboard, PAT-1067)
- **Schema:** `go-service/migrations/0001_initial.sql`, `0002_extraction.sql`, `0004_patching_data.sql`, `0012_device_certificates.sql`, `0014_device_hardware.sql`, `0087_device_backup_status.sql`, `0090_agent_health.sql`, `0127_applied_config_snapshots.sql`, `0159_local_admin_accounts.sql`, `0160_local_admin_pii_and_windows_rule.sql`
- **Collector:** `updater` repo → `macos/patched-collect.sh` (emit side; moved out of this repo under PAT-384)
- **JSON Schema:** `go-service/docs/payload.schema.json`
- **Executable contract (fixtures):** `go-service/testdata/payload-fixtures/` — golden fixtures that both agents (macOS, Windows) must produce; tested in CI by `internal/extractor/fixtures_test.go`. See `README.md` in that directory before editing any fixture.
- **API:** `go-service/docs/API.md`
