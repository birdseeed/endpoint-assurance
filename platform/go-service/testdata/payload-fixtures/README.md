# Payload fixture suite — the executable contract

These fixtures are the **executable contract** between every agent (macOS, Windows) and the `POST /v1/inventory` ingestion backend. The schema they conform to is `go-service/docs/payload.schema.json`.

## Rule: changing a fixture = changing the contract

A fixture change is not a unilateral decision. It requires agreement from **both** sides of the seam:

- **macOS agent:** does the macOS collector still emit this shape?
- **Windows agent:** does the Windows collector need to adjust?
- **Backend:** does the extractor need a migration or code change?

If you are tempted to edit a fixture to make a test pass, stop and ask whether the payload contract itself has changed. If it has, update the schema (`payload.schema.json`) and the prose doc (`PAYLOAD_SCHEMA.md`) at the same time.

## Directories

| Directory | Purpose |
|---|---|
| `valid/` | Payloads that must pass schema validation and ingest cleanly. Cover every top-level key including the full 8-field `certificates` shape. |
| `edge/` | Corner cases (empty arrays vs. absent keys, max-length strings, Unicode CNs). All are *valid* per the schema. |
| `invalid/` | Schema violations — one violation per file so failures are legible. Each must fail schema validation. |

## Files

### valid/

| File | What it covers |
|---|---|
| `full.json` | v2 macOS payload with **every** top-level key, including `certificates` with all 8 fields (`subject_cn`, `issuer_cn`, `sha1`, `not_after`, `days_until_expiry`, `ext_key_usage`, `basic_constraints_ca`, `is_self_signed`), `patches`, and `pending_updates`. |
| `full-v3-windows.json` | v3 Windows payload covering the v3-specific keys: `platform`, app `identifier`, optional T2 compliance signals. Demonstrates that `system_extensions`/`background_items`/`icloud` are absent in v3. |
| `minimal.json` | v2 macOS payload with only the required fields (required top-level + v2-conditional `system_extensions`, `background_items`, `icloud`). Baseline for verifying minimal compliance. |
| `only-certificates.json` | Minimal v2 base + `certificates` array. Exercises all 8 cert fields including the PAT-220 classification fields, plus a backwards-compatible cert (no `ext_key_usage`/booleans). |
| `only-patches.json` | Minimal v2 base + `patches` array. Covers the optional `installed_at` null case (date parse failure). |
| `only-pending-updates.json` | Minimal v2 base + `pending_updates` array. Covers optional `action` field (null and string). |
| `with-backup-status-macos-time-machine.json` | Minimal v2 base + `backup_status`, exact shape emitted by macOS `lib/backup.sh` for a healthy Time Machine backup (PAT-679) — all fields present, `notes` explicit `null`. |
| `with-backup-status-windows-file-history.json` | v3 Windows base + `backup_status`, exact shape emitted by `InventoryBackupStatus` for File History (PAT-680) — `notes` key **omitted** entirely (System.Text.Json `JsonIgnoreCondition.WhenWritingNull`), proving both the always-present-with-null (macOS) and omitted-when-null (Windows) forms validate against the same schema. |
| `with-backup-status-third-party.json` | Minimal v2 base + `backup_status` for a third-party tool (Backblaze) — `has_backup: true` with `last_backup_at`/`last_backup_days_ago` both `null` (no queryable timestamp) and a `notes` explanation. |
| `hardware-health-collection-status-degraded.json` | Minimal v2 base + `hardware_health.collection_status` (PAT-1720) — `battery`/`disks` `unavailable` with empty/absent readings, `storage` `partial` with one volume sent. Schema-valid; the extractor must not read the empty `disks: []` as "no disks" or the `false` battery reading as "no battery". |
| `with-local-admins-account-state-windows.json` | v3 Windows base + `local_admins` carrying `account_state` (PAT-1992): the local built-in RID-500 Administrator `disabled`, a domain RID-500 entry `unknown`, and a non-built-in entry with the key absent. |
| `with-firmware-complete-windows.json` | v3 Windows base + a `complete` `firmware` block (PAT-2262). The block is the Windows agent's own serialisation, copied byte for byte from `updater` `windows/tests/Service.Tests/DeviceCollectorFirmwareTests.cs` (`CompleteJson`, serialised with the real `InventoryPoster.JsonOpts`). Change both together. |
| `with-firmware-partial-windows.json` | Same source (`PartialJson`): BIOS `partial` with an unparseable release date kept raw (System.Text.Json writes its `+` as `\u002B`), system `complete`, baseboard `unavailable`. |
| `with-firmware-unavailable-windows.json` | Same source (`UnavailableJson`): every WMI class failed; `unavailable` with query error codes and no sections. |
| `with-kernel-drivers-complete-windows.json` | v3 Windows base + a `complete` `kernel_drivers` block (PAT-2263). The block is the Windows agent's own serialisation, copied byte for byte from `updater` `windows/tests/Service.Tests/KernelDriverCollectorTests.cs` (`CompleteWire`, serialised with the real `InventoryPoster.JsonOpts`): a hashed non-PE file, a hashed synthetic PE with Authenticode digests and a version, and a missing service file. Change both together. Every hash is of a synthetic file, never a real driver. |
| `with-kernel-drivers-partial-windows.json` | Same source (`PartialWire`): a reparse point refused as an unhashed row, a loaded-module list that could not be read (`loaded` omitted), a service whose ImagePath is a UNC path (row with no `path`), blocklist `not_set` and enforcement `unknown`. |
| `with-kernel-drivers-unavailable-windows.json` | Same source (`UnavailableWire`): every driver source failed; no `drivers` key, enforcement still reported (`blocklist_enforced: no`). |
| `with-homebrew-complete-macos.json` | Minimal v2 base + a `complete` `homebrew` block (PAT-2012 agent, PAT-2013 platform) in the exact shape `updater` `macos/lib/homebrew.sh` emits: an on-request core formula, a dependency-only core formula, a third-party tap formula, a cask whose app Homebrew moved to `/Applications` (`path: null`), and a third-party tap beside `homebrew/core`. |
| `with-tooling-complete-macos.json` | Minimal v2 base + complete `ide_extensions`, `package_managers`, `local_models` and `mcp_servers` blocks (PAT-2017 to PAT-2020 agents, PAT-2021 platform) in the exact shape the macOS collectors emit: VS Code, Cursor and JetBrains extensions; npm global (Homebrew and nvm prefixes) and pip user packages with pipx `not_present`; an Ollama app bundle and two models; three MCP servers (a package runner, an http host, a uvx package). |
| `with-tooling-complete-windows.json` | v3 Windows base + the same four blocks in the Windows agent's shape (`DOMAIN\user` and SIDs, `%APPDATA%` prefixes, `local_programs` Ollama, `npx.cmd`). Both platforms validate against one contract. |
| `with-tooling-failed-macos.json` | Minimal v2 base + all four blocks as the bare `{"collection_status": "failed"}` the macOS agent sends when its parser dies. |
| `with-tooling-failed-windows.json` | v3 Windows base + all four blocks failed in the Windows form: item lists omitted, empty rosters and unit maps sent. |
| `with-homebrew-failed-macos.json` | Minimal v2 base + `homebrew: {"collection_status": "failed"}`, the bare form the agent sends when its parser fails. The lists are omitted, never `[]`. |
| `with-browser-extensions-status-complete.json` | `with-browser-extensions.json` + a `complete` `browser_extensions_status` (PAT-2055): alice's Chrome and Firefox read in full, Edge `not_present`, and a second user with no browsers. Grants absence authority for the device. |
| `with-browser-extensions-status-windows.json` | v3 Windows base + a `partial` block in the Windows agent's form (SID `user_id`): one user's Edge `User Data` refused (PAT-2052) and reported `failed`. Same contract as macOS. |
| `with-browser-extensions-status-failed.json` | The bare `{"collection_status": "failed"}` block. Only the status is recorded. |

### edge/

| File | What it covers |
|---|---|
| `empty-arrays.json` | `security_tools`, `system_extensions`, `background_items`, `apps`, `certificates`, and `patches` are present but empty (`[]`). `pending_updates` is **absent** (not `[]`). Captures the upsert/prune/no-op distinction: `certificates: []` triggers prune-all; `pending_updates` absent is a no-op. |
| `max-length-strings.json` | Long strings in every free-form field. Schema has no `maxLength` constraints; this tests that no silent truncation occurs in the database layer. |
| `unicode-common-names.json` | Unicode in certificate CNs (Japanese, French, German, Spanish) and app/device names. Tests UTF-8 handling in upsert paths and CN column storage. |
| `browser-extension-bad-user-account.json` | One `browser_extensions` entry has an empty (but present) `user_account`. Schema-valid; must ingest cleanly with the malformed entry skipped and the rest of the snapshot (device, apps, other extensions) persisted (PAT-871). |
| `backup-status-windows-onedrive-sync-only.json` | v3 Windows base + `backup_status` for OneDrive sync (PAT-680) — `sync_only: true`, `has_backup: false`, `last_backup_at`/`last_backup_days_ago` omitted (Windows null-omission form). |
| `homebrew-partial-truncated-macos.json` | `homebrew` `partial` and `truncated` (`time_limit`): an unreadable receipt leaves every receipt-derived field `null`, a symlinked `/usr/local` prefix has `owner: null`, and `issues` explains both. Must never prune. |
| `tooling-partial-macos.json` | `ide_extensions` `partial` and truncated (`time_limit`) with an unreadable JetBrains plugin (`id: null`), and `package_managers` `partial` with `pip_user` failed and `npm_global` still complete (a per-unit authority case). Must never prune. |
| `tooling-not-present-windows.json` | `ide_extensions`, `local_models` and `mcp_servers` `not_present` on Windows: every unit `not_present`, every list empty. |
| `homebrew-not-present-macos.json` | `homebrew` `not_present`: every list present and empty. A genuine reading that clears the device's Homebrew state. |
| `browser-extensions-status-partial-capped.json` | `browser_extensions_status` `partial` with `cap_reached` while a pair claims `complete`. A capped read grants no authority at all, so nothing may be treated as gone. |
| `browser-extensions-status-complete-capped-withheld.json` | `browser_extensions_status` `complete` with `cap_reached: true`. Well-formed but inconsistent: accepted, and stored as partial with its authority withheld (`cap_reached_not_partial`). One bad completeness claim must never drop the device's inventory (PAT-2055 review). |
| `browser-extensions-status-row-not-covered-withheld.json` | A `complete` block whose `users` leaves out alice, whose Chrome and Firefox rows are listed. Accepted; authority withheld (`row_not_reported_complete`). |

### invalid/

| File | Violation |
|---|---|
| `missing-required-host.json` | `device.hostname` absent — violates `device.required`. |
| `wrong-type-schema-version.json` | `schema_version: "2"` (string) — violates `type: integer`. |
| `missing-required-apps.json` | `apps` key absent — violates top-level `required`. |
| `unknown-schema-version.json` | `schema_version: 99` — violates `enum: [2, 3]`. |
| `v3-missing-platform.json` | `schema_version: 3` without `platform` — violates the `if/then` clause requiring `platform` in v3. |
| `browser-extension-missing-user-account.json` | `browser_extensions[0]` is missing the `user_account` key entirely — violates `browser_extensions` items required (PAT-871). |
| `browser-extensions-status-case-variant-key.json` | `browser_extensions_status.Collection_Status` beside `collection_status`: a case-variant key the struct decoder would read, rejected by the PAT-2021 key walk (PAT-2055). |
| `browser-extensions-status-bad-browser-status.json` | `browser_extensions_status.users[0].browsers.edge: "mostly"`, not in the status enum. A malformed structure still rejects the payload (PAT-2055). |
| `backup-status-wrong-type-has-backup.json` | `backup_status.has_backup: "yes"` (string) — violates `type: boolean` (PAT-948). |
| `hardware-health-bad-collection-status.json` | `hardware_health.collection_status.disks: "mostly_ok"` — not in enum `["complete", "partial", "unavailable"]` (PAT-1720). |
| `local-admins-bad-account-state.json` | `local_admins.accounts[0].account_state: "Disabled"` — not in enum `["enabled", "disabled", "unknown"]` (PAT-1992; the enum is case-sensitive). |
| `firmware-unavailable-with-section.json` | `firmware.collection_status: "unavailable"` carrying a `bios` section: an unavailable block carries no sections (PAT-2262). |
| `kernel-drivers-unavailable-with-drivers.json` | `kernel_drivers.collection_status: "unavailable"` carrying a `drivers` array: an unavailable block sends no list (PAT-2263). |
| `kernel-drivers-uppercase-hash.json` | A `kernel_drivers` row with an uppercase `sha256`: hashes are lowercase hex, so matching is exact (PAT-2263). |
| `kernel-drivers-hashed-without-hash.json` | A `hashed` `kernel_drivers` row with no `sha256` (PAT-2263). |
| `homebrew-formula-unknown-key.json` | `homebrew.formulae[0]` carries an unknown `cpe` key: every level of the `homebrew` block is `additionalProperties: false` (PAT-2013). |
| `homebrew-bad-collection-status.json` | `homebrew.collection_status: "ok"`, not in `["complete", "partial", "not_present", "failed"]`. |
| `ide-extensions-unknown-key.json` | `ide_extensions.extensions[0]` carries an unknown `marketplace_url` key (PAT-2021: strict at every level). |
| `ide-extensions-failed-with-empty-list.json` | `ide_extensions` `failed` with `extensions: []`: a failed read omits the list. |
| `ide-extensions-complete-truncated.json` | `ide_extensions` `complete` and `truncated`. |
| `ide-extensions-complete-without-evidence.json` | `ide_extensions` `complete` with no profile rows: a complete read must show what it read. |
| `package-managers-bad-source.json` | `package_managers.packages[0].source: "cargo"`, not in `["npm_global", "pip_user", "pipx"]`. |
| `package-managers-not-present-source-lists-package.json` | A `pipx` package although `sources.pipx` is `not_present`. |
| `local-models-complete-with-partial-runtime.json` | `local_models` `complete` with `runtimes.ollama` `partial`. |
| `local-models-negative-size.json` | `local_models.models[0].size_bytes: -1`. |
| `mcp-servers-env-field.json` | An MCP server entry carrying `env`: rejected by the PAT-2021 privacy guard. |
| `mcp-servers-args-field.json` | An MCP server entry carrying `args`: rejected by the privacy guard. |
| `mcp-servers-host-not-bare.json` | An MCP server `host` with a path and query: rejected by the privacy guard. |
| `mcp-servers-failed-with-servers.json` | `mcp_servers` `failed` with a `servers` list. |
| `homebrew-failed-with-empty-lists.json` | `homebrew` `failed` with `formulae: []`. A failed read must omit the lists so it can never look like "no packages". |

## Adding new fixtures

1. Drop a `.json` file in the appropriate directory. The test suite (`internal/extractor/fixtures_test.go`) walks directories automatically — no hardcoded file list.
2. Update the table above.
3. If adding to `valid/` or `edge/`, verify the file passes schema validation locally: the test will enforce this in CI.
4. If adding to `invalid/`, ensure **exactly one** schema constraint is violated so the failure is legible in CI output.
