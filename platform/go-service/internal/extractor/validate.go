package extractor

import (
	"encoding/json"
	"fmt"
	"time"

	"patched.im/api/internal/wingetid"
)

// wingetPackageIdentifierRE is the PackageIdentifier production from
// Microsoft's current Winget manifest schema. It is deliberately
// case-sensitive: inventory preserves the package ID exactly as reported.
func isCanonicalWingetInventoryID(value string) bool {
	return wingetid.Valid(value)
}

// ValidatePayload validates a raw JSON inventory payload against the constraints
// in go-service/docs/payload.schema.json (draft 2020-12).  It implements exactly
// the constraints defined in that schema — no more, no less.
//
// Returns nil when the payload is valid; a descriptive error otherwise.
// Called by the POST /v1/inventory handler to reject schema-invalid payloads
// before persisting to raw_payloads (PAT-227).
//
// Constraints checked (schema section → Go check):
//
//	top-level required        → required fields present
//	schema_version type+enum  → integer 2 or 3
//	platform enum             → "macos" | "windows" when present
//	device.required           → serial, hw_uuid, hostname, hw_model, arch, last_boot
//	hardware.required         → cpu_model, cpu_cores, ram_gb, disk_total_gb, disk_free_gb
//	os.required + addlProps   → name, version, build; no extra keys
//	icloud.required + addlP   → signed_in; no extra keys (when present)
//	security_tools items      → each item has id and name (when items exist)
//	system_extensions items   → each item has required fields (when items exist)
//	background_items items    → each item has required fields (when items exist)
//	if/then (schema_version=3)→ platform required; each app must have identifier
//	if/else (schema_version≠3)→ system_extensions, background_items, icloud required;
//	                             each app must have bundle_id
//	collection_status (optional)→ top-level object (PAT-1732), the general home
//	                             for collection status of top-level array
//	                             sections; additionalProperties:false, keys
//	                             "certificates", "apps" (PAT-2063) and
//	                             "safari_extensions" (PAT-2067), each one of
//	                             "complete"|"partial"|"unavailable"; plus
//	                             "apps_users" (PAT-2075), an array of
//	                             {user_account, collection_status} objects,
//	                             see validateAppsUsers
//	apps[].user_account        → optional string (PAT-2075)
//	hardware_health (optional)→ when present: battery/storage/disks required;
//	                             battery.max_capacity_pct must be integer (not float);
//	                             collection_status (PAT-1720), when present, is an
//	                             object with only battery/storage/disks keys, each
//	                             one of "complete"|"partial"|"unavailable" — this is
//	                             hardware_health's OWN nested collection_status
//	                             object, distinct from the top-level one above
//	local_admins (optional)   → when present: collection_status required, one of
//	                             "complete"|"partial"|"unavailable"; accounts, when
//	                             present, is an array of objects each requiring
//	                             name/principal_type ("user"|"group"|"unresolved")/
//	                             builtin, sid optional (PAT-1974); account_state
//	                             optional, one of "enabled"|"disabled"|"unknown"
//	                             (PAT-1992)
//	homebrew (optional)       → when present: macOS Homebrew inventory (PAT-2012
//	                             agent, PAT-2013 platform); strict at every
//	                             level, see validateHomebrew in
//	                             validate_homebrew.go for the status rules and
//	                             the per-section entry bounds
//	ide_extensions, package_managers, local_models, mcp_servers (optional)
//	                          → when present: PAT-2017..2020 agents, PAT-2021
//	                             platform; strict at every level with status
//	                             invariants, see validate_tooling.go. An
//	                             mcp_servers server entry with any field
//	                             outside the PAT-2020 allowlist is rejected by
//	                             the privacy guard, checked before anything else
//	backup_status (optional)  → when present: has_backup/stale/sync_only required
//	                             booleans, no additional properties; backup_type/
//	                             notes/last_backup_at nullable strings;
//	                             last_backup_days_ago nullable integer (not float)
//	browser_extensions items   → each item has browser, profile, user_account,
//	                             extension_id (when items exist) (PAT-871)
//	agent_health               → NOT validated here, deliberately (PAT-1064,
//	                             review round 3 FIX 9). Any shape at all is
//	                             accepted at this gate; the extractor's own
//	                             defensive decode (parseAgentHealth /
//	                             sanitizeAgentHealthEntries) is the only
//	                             thing that inspects it, AFTER persistence,
//	                             so a malformed section can never reject the
//	                             whole inventory upload the way an earlier
//	                             version of this check did.
//	compliance bag keys        → reserved finding-control IDs rejected (PAT-913
//	                             round 3 — a bag key must never occupy a
//	                             finding-control signal slot)
//	compliance_findings items  → each item has id + severity; id must be in the
//	                             finding-control enum (PAT-913 round 3)
//	compliance_assessments     → when present: object, no extra keys;
//	                             controls_assessed array of strings, each in the
//	                             finding-control enum (strictly enforced — these
//	                             entries mint Pass signals; PAT-913)
func ValidatePayload(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	// PAT-2021 review P1: reject keys that differ from a payload field only
	// by case or Unicode folding (the struct decoder would read them past
	// every exact-key check), and duplicate strict-block keys. See
	// validate_keys.go.
	if err := checkPayloadKeys(data); err != nil {
		return err
	}

	// PAT-2021 MCP privacy guard, first so a hit is always detected and
	// counted even when something else in the payload is also wrong. The
	// payload is rejected before any DB write, so a leaked secret never
	// reaches raw_payloads. See validate_tooling.go.
	if err := mcpPrivacyGuard(m); err != nil {
		return err
	}

	topRequired := []string{
		"schema_version", "agent", "agent_version", "tenant_id",
		"collected_at", "device", "hardware", "os",
		"compliance", "security_tools", "apps",
	}
	if err := schemaCheckRequired(m, "", topRequired); err != nil {
		return err
	}

	sv, err := schemaRequireInt(m, "schema_version")
	if err != nil {
		return err
	}
	if sv != 2 && sv != 3 {
		return fmt.Errorf("schema_version: value %d not in enum [2, 3]", sv)
	}

	if raw, ok := m["platform"]; ok {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("platform: must be a string")
		}
		if s != "macos" && s != "windows" {
			return fmt.Errorf("platform: value %q not in enum [\"macos\", \"windows\"]", s)
		}
	}

	device, err := schemaRequireObject(m, "device")
	if err != nil {
		return err
	}
	if err := schemaCheckRequired(device, "device.", []string{
		"serial", "hw_uuid", "hostname", "hw_model", "arch", "last_boot",
	}); err != nil {
		return err
	}

	hardware, err := schemaRequireObject(m, "hardware")
	if err != nil {
		return err
	}
	if err := schemaCheckRequired(hardware, "hardware.", []string{
		"cpu_model", "cpu_cores", "ram_gb", "disk_total_gb", "disk_free_gb",
	}); err != nil {
		return err
	}

	osObj, err := schemaRequireObject(m, "os")
	if err != nil {
		return err
	}
	if err := schemaCheckRequired(osObj, "os.", []string{"name", "version", "build"}); err != nil {
		return err
	}
	for k := range osObj {
		switch k {
		case "name", "version", "build":
		default:
			return fmt.Errorf("os.%s: additional properties not allowed", k)
		}
	}

	// PAT-1960 (top level, not nested under os — device_class is a property
	// of the machine, not the OS; Windows agent side ships under PAT-1959,
	// macOS never sends these). All three optional.
	if raw, ok := m["device_class"]; ok {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("device_class: must be a string")
		}
		switch s {
		// "unknown" is a genuine PAT-1959 report (source absent, unreadable
		// or contradictory — never a guess), not an omission, so it must
		// validate here even though upsertDevice treats it the same as an
		// absent field for the "don't downgrade a known class" rule.
		case "workstation", "server", "domain_controller", "unknown":
		default:
			return fmt.Errorf("device_class: value %q not in enum [\"workstation\", \"server\", \"domain_controller\", \"unknown\"]", s)
		}
	}
	if raw, ok := m["installation_type"]; ok {
		if _, ok := raw.(string); !ok {
			return fmt.Errorf("installation_type: must be a string")
		}
	}
	if raw, ok := m["os_caption"]; ok {
		if _, ok := raw.(string); !ok {
			return fmt.Errorf("os_caption: must be a string")
		}
	}

	compliance, err := schemaRequireObject(m, "compliance")
	if err != nil {
		return err
	}
	// Reserved namespace (PAT-913, gate round 3): the finding-control IDs may
	// never appear as free-form compliance bag keys. The bag is copied into the
	// signal map verbatim, so compliance:{"disk_encryption_off":"Pass"} would
	// pre-seat a forged Pass on a critical rule with no attestation at all.
	// Findings arrive only via compliance_findings; Pass arrives only via
	// compliance_assessments.controls_assessed.
	for k := range compliance {
		if isFindingControlID(k) {
			return fmt.Errorf("compliance.%s: reserved finding-control ID not allowed as a compliance bag key (report violations via compliance_findings, attestation via compliance_assessments)", k)
		}
	}

	if err := schemaRequireArrayOfObjects(m, "security_tools", []string{"id", "name"}, false); err != nil {
		return err
	}

	apps, err := schemaRequireArray(m, "apps")
	if err != nil {
		return err
	}
	for _, key := range []string{"metering_user_hive_count", "metering_record_count"} {
		if raw, present := m[key]; present && raw != nil {
			n, ok := raw.(float64)
			if !ok || n < 0 || n > 2147483647 || n != float64(int64(n)) {
				return fmt.Errorf("%s: must be a non-negative integer", key)
			}
		}
	}
	// PAT-2075: user_account is optional on every app row. A non-string
	// value would fail the typed decode after storage and lose the whole
	// inventory, so it is refused here instead.
	for i, item := range apps {
		app, ok := item.(map[string]any)
		if !ok {
			continue // reported by the per-schema checks below
		}
		if err := validateAppUsageEvidence(app, i); err != nil {
			return err
		}
		if raw, present := app["user_account"]; present {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("apps[%d].user_account: must be a string", i)
			}
		}
		// PAT-2112: a non-string would fail the extractor's decode of the
		// whole report, so it is refused here. A string outside the enum is
		// accepted and stored as not reported, so a future value never costs
		// a device its inventory.
		for _, key := range []string{"signing_status", "notarization_status"} {
			if raw, present := app[key]; present {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("apps[%d].%s: must be a string", i, key)
				}
			}
		}
		// PAT-2113: installation_evidence is decoded now, so a value the
		// typed decode cannot take would lose the whole report. It must be an
		// object (or null), and the members the extractor reads (PAT-2116
		// added the pinnable publisher and executable_resolution) must be
		// strings. Other members are not decoded and are not checked; a value
		// outside an enum or bound is stored as not reported.
		if raw, present := app["installation_evidence"]; present && raw != nil {
			ev, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("apps[%d].installation_evidence: must be an object", i)
			}
			for _, key := range []string{"signature_state", "signer", "signer_thumbprint", "issuer",
				"root_thumbprint", "root_kind", "executable_resolution"} {
				if v, present := ev[key]; present {
					if _, ok := v.(string); !ok {
						return fmt.Errorf("apps[%d].installation_evidence.%s: must be a string", i, key)
					}
				}
			}
		}
	}

	if sv == 3 {
		if _, ok := m["platform"]; !ok {
			return fmt.Errorf("platform: required when schema_version is 3")
		}
		for i, item := range apps {
			app, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("apps[%d]: must be an object", i)
			}
			if err := schemaCheckRequired(app, fmt.Sprintf("apps[%d].", i), []string{"name", "version", "identifier"}); err != nil {
				return err
			}
			if rawKind, present := app["identifier_kind"]; present {
				kind, ok := rawKind.(string)
				if !ok || (kind != "winget" && kind != "native") {
					return fmt.Errorf("apps[%d].identifier_kind: value must be winget or native", i)
				}
			}
		}
		if rawCaps, present := m["inventory_capabilities"]; present {
			caps, ok := rawCaps.(map[string]any)
			if !ok {
				return fmt.Errorf("inventory_capabilities: must be an object")
			}
			for key := range caps {
				if key != "schema_version" && key != "windows_winget_inventory_complete" {
					return fmt.Errorf("inventory_capabilities.%s: additional property not allowed", key)
				}
			}
			schema, schemaOK := caps["schema_version"].(float64)
			complete, completeOK := caps["windows_winget_inventory_complete"].(bool)
			platform, _ := m["platform"].(string)
			// Missing, false, partial, or unsupported capability declarations are
			// ordinary inventory uploads but confer no absence authority. Only the
			// positive claim is strict and can activate mandatory Windows installs.
			if completeOK && complete && (!schemaOK || schema != 1 || platform != "windows") {
				return fmt.Errorf("inventory_capabilities: Winget completeness requires Windows schema_version 1 and true completeness")
			}
			if completeOK && complete {
				for i, item := range apps {
					app, ok := item.(map[string]any)
					if !ok {
						return fmt.Errorf("apps[%d]: must be an object", i)
					}
					kind, ok := app["identifier_kind"].(string)
					identifier, _ := app["identifier"].(string)
					if !ok || (kind != "winget" && kind != "native") {
						return fmt.Errorf("apps[%d].identifier_kind: complete Winget inventory requires winget or native", i)
					}
					// A malformed per-app Winget ID must not poison the device's
					// unrelated inventory. The typed extractor retains the app but
					// strips its authority and clears the snapshot completeness bit.
					_ = identifier
				}
			}
		}
	} else {
		if err := schemaCheckRequired(m, "", []string{"system_extensions", "background_items", "icloud"}); err != nil {
			return err
		}
		icloud, err := schemaRequireObject(m, "icloud")
		if err != nil {
			return err
		}
		if err := schemaCheckRequired(icloud, "icloud.", []string{"signed_in"}); err != nil {
			return err
		}
		for k := range icloud {
			if k != "signed_in" {
				return fmt.Errorf("icloud.%s: additional properties not allowed", k)
			}
		}
		if err := schemaRequireArrayOfObjects(m, "system_extensions", []string{
			"enabled", "active", "team_id", "bundle_id", "version", "name", "state",
		}, false); err != nil {
			return err
		}
		if err := schemaRequireArrayOfObjects(m, "background_items", []string{
			"name", "identifier", "team_id", "url", "type", "disposition",
		}, false); err != nil {
			return err
		}
		for i, item := range apps {
			app, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("apps[%d]: must be an object", i)
			}
			if err := schemaCheckRequired(app, fmt.Sprintf("apps[%d].", i), []string{"name", "version", "bundle_id"}); err != nil {
				return err
			}
		}
	}

	// collection_status (PAT-1732) — optional top-level object, the general
	// home for collection status of top-level array sections (nested objects
	// such as hardware_health keep their own nested collection_status key,
	// validated separately below). additionalProperties:false; the keys
	// recognised are "certificates" (PAT-1732), "apps" (PAT-2063) and
	// "safari_extensions" (PAT-2067), all using the same three-value enum as
	// hardware_health.collection_status. A case- or fold-variant key
	// ("Safari_Extensions") is rejected earlier by checkPayloadKeys, since the
	// struct decoder would otherwise still read it.
	// A malformed value is a 400; a well-formed apps value that contradicts
	// the apps array is not rejected here, the extractor withholds its
	// authority instead (see apps_authority.go).
	if _, ok := m["collection_status"]; ok {
		cs, err := schemaRequireObject(m, "collection_status")
		if err != nil {
			return err
		}
		for k, raw := range cs {
			switch k {
			case "certificates", "apps", "safari_extensions":
			case "apps_users":
				if err := validateAppsUsers(raw); err != nil {
					return err
				}
				continue
			default:
				return fmt.Errorf("collection_status.%s: additional properties not allowed", k)
			}
			s, ok := raw.(string)
			if !ok {
				return fmt.Errorf("collection_status.%s: must be a string", k)
			}
			switch s {
			case "complete", "partial", "unavailable":
			default:
				return fmt.Errorf("collection_status.%s: value %q not in enum [\"complete\", \"partial\", \"unavailable\"]", k, s)
			}
		}
	}

	if _, ok := m["hardware_health"]; ok {
		hh, err := schemaRequireObject(m, "hardware_health")
		if err != nil {
			return err
		}
		if err := schemaCheckRequired(hh, "hardware_health.", []string{"battery", "storage", "disks"}); err != nil {
			return err
		}
		batt, err := schemaRequireObject(hh, "battery")
		if err != nil {
			return fmt.Errorf("hardware_health.battery: %w", err)
		}
		if err := schemaCheckRequired(batt, "hardware_health.battery.", []string{"present"}); err != nil {
			return err
		}
		if v, ok := batt["max_capacity_pct"]; ok && v != nil {
			f, ok := v.(float64)
			if !ok {
				return fmt.Errorf("hardware_health.battery.max_capacity_pct: must be a number")
			}
			if f != float64(int(f)) {
				return fmt.Errorf("hardware_health.battery.max_capacity_pct: must be an integer (got %v, which is a float)", f)
			}
		}
		if err := schemaRequireArrayOfObjects(hh, "storage", []string{"mount", "total_bytes", "free_bytes", "used_pct"}, false); err != nil {
			return err
		}
		if err := schemaRequireArrayOfObjects(hh, "disks", []string{"device", "smart_status", "internal", "solid_state"}, false); err != nil {
			return err
		}
		// collection_status (PAT-1720) — optional; each of its three keys is
		// optional; additionalProperties:false; values restricted to the
		// same enum as applied_configuration.collection_status.
		if v, ok := hh["collection_status"]; ok {
			cs, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("hardware_health.collection_status: must be an object")
			}
			for k, raw := range cs {
				switch k {
				case "battery", "storage", "disks":
				default:
					return fmt.Errorf("hardware_health.collection_status.%s: additional properties not allowed", k)
				}
				s, ok := raw.(string)
				if !ok {
					return fmt.Errorf("hardware_health.collection_status.%s: must be a string", k)
				}
				switch s {
				case "complete", "partial", "unavailable":
				default:
					return fmt.Errorf("hardware_health.collection_status.%s: value %q not in enum [\"complete\", \"partial\", \"unavailable\"]", k, s)
				}
			}
		}
	}

	// local_admins (PAT-1974) — optional top-level object: the standing
	// local-administrator roster behind the local_admin_count compliance
	// signal. When present, collection_status is required and restricted to
	// the shared complete/partial/unavailable enum; accounts, when present,
	// is an array of objects each requiring name/principal_type (enum
	// user|group|unresolved)/builtin, with sid optional and account_state
	// (PAT-1992) optional, one of enabled|disabled|unknown. Same strictness
	// posture as hardware_health above: additionalProperties rejected at
	// every level.
	if _, ok := m["local_admins"]; ok {
		la, err := schemaRequireObject(m, "local_admins")
		if err != nil {
			return err
		}
		if err := schemaCheckRequired(la, "local_admins.", []string{"collection_status"}); err != nil {
			return err
		}
		for k := range la {
			switch k {
			case "collection_status", "accounts":
			default:
				return fmt.Errorf("local_admins.%s: additional properties not allowed", k)
			}
		}
		cs, ok := la["collection_status"].(string)
		if !ok {
			return fmt.Errorf("local_admins.collection_status: must be a string")
		}
		switch cs {
		case "complete", "partial", "unavailable":
		default:
			return fmt.Errorf("local_admins.collection_status: value %q not in enum [\"complete\", \"partial\", \"unavailable\"]", cs)
		}
		// A complete read that reports genuinely zero admins must say so
		// explicitly (accounts: []), never by omitting the key. Without this,
		// a malformed-but-well-typed payload (complete, no accounts field at
		// all) would pass validation and the extractor's complete branch
		// would then delete the entire stored roster and write nothing back
		// — a fabricated zero, the exact "absence requires authority"
		// violation this ticket exists to close.
		if cs == "complete" {
			if _, ok := la["accounts"]; !ok {
				return fmt.Errorf("local_admins.accounts: required when collection_status is \"complete\"")
			}
		}
		if v, ok := la["accounts"]; ok {
			arr, ok := v.([]any)
			if !ok {
				return fmt.Errorf("local_admins.accounts: must be an array")
			}
			for i, item := range arr {
				obj, ok := item.(map[string]any)
				if !ok {
					return fmt.Errorf("local_admins.accounts[%d]: must be an object", i)
				}
				if err := schemaCheckRequired(obj, fmt.Sprintf("local_admins.accounts[%d].", i), []string{"name", "principal_type", "builtin"}); err != nil {
					return err
				}
				for k := range obj {
					switch k {
					case "name", "principal_type", "builtin", "sid", "account_state":
					default:
						return fmt.Errorf("local_admins.accounts[%d].%s: additional properties not allowed", i, k)
					}
				}
				if _, ok := obj["name"].(string); !ok {
					return fmt.Errorf("local_admins.accounts[%d].name: must be a string", i)
				}
				pt, ok := obj["principal_type"].(string)
				if !ok {
					return fmt.Errorf("local_admins.accounts[%d].principal_type: must be a string", i)
				}
				switch pt {
				case "user", "group", "unresolved":
				default:
					return fmt.Errorf("local_admins.accounts[%d].principal_type: value %q not in enum [\"user\", \"group\", \"unresolved\"]", i, pt)
				}
				if _, ok := obj["builtin"].(bool); !ok {
					return fmt.Errorf("local_admins.accounts[%d].builtin: must be a boolean", i)
				}
				if v, ok := obj["sid"]; ok && v != nil {
					if _, ok := v.(string); !ok {
						return fmt.Errorf("local_admins.accounts[%d].sid: must be a string", i)
					}
				}
				// account_state (PAT-1992): the Windows agent's read of the
				// built-in RID-500 Administrator's enabled state. Absent means
				// an agent that predates the field or an entry that was never
				// read. "unknown" means a read was attempted and did not
				// establish the state; it is never a synonym for "disabled".
				// An explicit null is treated as absent, the same as sid: the
				// entry stays counted exactly as an older agent's would.
				if v, ok := obj["account_state"]; ok && v != nil {
					st, ok := v.(string)
					if !ok {
						return fmt.Errorf("local_admins.accounts[%d].account_state: must be a string", i)
					}
					switch st {
					case "enabled", "disabled", "unknown":
					default:
						return fmt.Errorf("local_admins.accounts[%d].account_state: value %q not in enum [\"enabled\", \"disabled\", \"unknown\"]", i, st)
					}
				}
			}
		}
	}

	if err := validateHomebrew(m); err != nil {
		return err
	}

	// firmware (PAT-2262) — optional top-level object; strictly typed and
	// bounded when present. See firmware.go.
	if _, ok := m["firmware"]; ok {
		if err := validateFirmware(m); err != nil {
			return err
		}
	}

	// kernel_drivers (PAT-2263) — optional top-level object; strictly typed
	// and bounded when present. See kernel_drivers.go.
	if _, ok := m["kernel_drivers"]; ok {
		if err := validateKernelDrivers(m); err != nil {
			return err
		}
	}

	// PAT-2021: ide_extensions, package_managers, local_models, mcp_servers.
	if err := validateToolingBlocks(m); err != nil {
		return err
	}

	// backup_status (PAT-679/680 agents; PAT-948 server ingestion) — optional,
	// but strictly typed when present, same posture as hardware_health above.
	// backup_type/notes/last_backup_at are deliberately NOT enum-restricted:
	// backup_type carries free-form third-party tool names (e.g. "acronis")
	// decided by the collector, not this schema — see docs/payload.schema.json.
	if _, ok := m["backup_status"]; ok {
		bs, err := schemaRequireObject(m, "backup_status")
		if err != nil {
			return err
		}
		if err := schemaCheckRequired(bs, "backup_status.", []string{"has_backup", "stale", "sync_only"}); err != nil {
			return err
		}
		for k := range bs {
			switch k {
			case "has_backup", "backup_type", "last_backup_at", "last_backup_days_ago", "stale", "sync_only", "notes":
			default:
				return fmt.Errorf("backup_status.%s: additional properties not allowed", k)
			}
		}
		if _, ok := bs["has_backup"].(bool); !ok {
			return fmt.Errorf("backup_status.has_backup: must be a boolean")
		}
		if _, ok := bs["stale"].(bool); !ok {
			return fmt.Errorf("backup_status.stale: must be a boolean")
		}
		if _, ok := bs["sync_only"].(bool); !ok {
			return fmt.Errorf("backup_status.sync_only: must be a boolean")
		}
		if v, ok := bs["backup_type"]; ok && v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("backup_status.backup_type: must be a string or null")
			}
		}
		if v, ok := bs["notes"]; ok && v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("backup_status.notes: must be a string or null")
			}
		}
		if v, ok := bs["last_backup_at"]; ok && v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("backup_status.last_backup_at: must be a string or null")
			}
		}
		if v, ok := bs["last_backup_days_ago"]; ok && v != nil {
			f, ok := v.(float64)
			if !ok {
				return fmt.Errorf("backup_status.last_backup_days_ago: must be an integer or null")
			}
			if f != float64(int(f)) {
				return fmt.Errorf("backup_status.last_backup_days_ago: must be an integer (got %v, which is a float)", f)
			}
		}
	}

	// os_update (PAT-1806, server-side receiving half only — neither agent
	// sends this yet) — optional, but strictly typed when present, same
	// posture as backup_status above. Field shape verified against updater's
	// real contracts/update-status.schema.json (PAT-1862): the original
	// PAT-1806 shape here was guessed from the ticket description and had
	// drifted. state/severity are deliberately NOT enum-restricted here even
	// though the real agent-side contract enforces a strict enum on its own
	// wire: they are stored verbatim, so a future agent release reporting a
	// new value is never rejected at the platform boundary.
	// installed_os/state/severity/security_relevant/actively_exploited/
	// deferrals_remaining/checked_at are required — the agent's verdict
	// always knows these, even when there's nothing outstanding.
	// latest_os/deadline/release_age_days/target_os are independently
	// optional AND nullable, same wire-format quirk backup_status documents
	// (Windows omits an absent-null key from the wire entirely; macOS always
	// emits the key with an explicit JSON null — both forms must validate).
	// target_os joined this group under PAT-2123: the Windows agent may
	// report a pending OS update (state=update_required, etc.) before WUA
	// has resolved which build it is updating to, and must be able to say so
	// without inventing a placeholder version.
	if _, ok := m["os_update"]; ok {
		ou, err := schemaRequireObject(m, "os_update")
		if err != nil {
			return err
		}
		if err := schemaCheckRequired(ou, "os_update.", []string{
			"installed_os", "state", "severity",
			"security_relevant", "actively_exploited",
			"deferrals_remaining", "checked_at",
		}); err != nil {
			return err
		}
		for k := range ou {
			switch k {
			case "installed_os", "latest_os", "target_os", "state", "severity",
				"security_relevant", "actively_exploited", "deadline",
				"deferrals_remaining", "release_age_days", "checked_at":
			default:
				return fmt.Errorf("os_update.%s: additional properties not allowed", k)
			}
		}
		if _, ok := ou["installed_os"].(string); !ok {
			return fmt.Errorf("os_update.installed_os: must be a string")
		}
		// target_os (PAT-2123): independently optional AND nullable, same
		// wire-format quirk as latest_os/deadline/release_age_days above —
		// the Windows agent is moving to omitting or null-ing this key when
		// Windows Update reports a pending OS update with no version yet
		// established, rather than continuing to require every agent to
		// invent a value. Absent and explicit null both mean "an update is
		// pending but its target version is not yet known" and are stored as
		// SQL NULL (see upsertOSUpdate). When the key IS present and non-
		// null, it must still be a non-empty string — an agent that knows
		// the target must send a real value, not "" or a wrong-typed one.
		if v, ok := ou["target_os"]; ok && v != nil {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("os_update.target_os: must be a string or null")
			}
			if s == "" {
				return fmt.Errorf("os_update.target_os: must not be empty when present")
			}
		}
		if _, ok := ou["state"].(string); !ok {
			return fmt.Errorf("os_update.state: must be a string")
		}
		if _, ok := ou["severity"].(string); !ok {
			return fmt.Errorf("os_update.severity: must be a string")
		}
		if _, ok := ou["security_relevant"].(bool); !ok {
			return fmt.Errorf("os_update.security_relevant: must be a boolean")
		}
		if _, ok := ou["actively_exploited"].(bool); !ok {
			return fmt.Errorf("os_update.actively_exploited: must be a boolean")
		}
		checkedAt, ok := ou["checked_at"].(string)
		if !ok {
			return fmt.Errorf("os_update.checked_at: must be a string")
		}
		if _, err := time.Parse(time.RFC3339, checkedAt); err != nil {
			return fmt.Errorf("os_update.checked_at: must be an RFC3339 timestamp")
		}
		if f, ok := ou["deferrals_remaining"].(float64); !ok {
			return fmt.Errorf("os_update.deferrals_remaining: must be an integer")
		} else if f != float64(int(f)) {
			return fmt.Errorf("os_update.deferrals_remaining: must be an integer (got %v, which is a float)", f)
		} else if f < 0 {
			return fmt.Errorf("os_update.deferrals_remaining: must be greater than or equal to 0")
		}
		if v := ou["latest_os"]; v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("os_update.latest_os: must be a string or null")
			}
		}
		if v := ou["deadline"]; v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("os_update.deadline: must be a string or null")
			}
		}
		if v := ou["release_age_days"]; v != nil {
			f, ok := v.(float64)
			if !ok {
				return fmt.Errorf("os_update.release_age_days: must be an integer or null")
			}
			if f != float64(int(f)) {
				return fmt.Errorf("os_update.release_age_days: must be an integer (got %v, which is a float)", f)
			}
			if f < 0 {
				return fmt.Errorf("os_update.release_age_days: must be greater than or equal to 0")
			}
		}
	}

	if _, ok := m["pending_updates"]; ok {
		if err := schemaRequireArrayOfObjects(m, "pending_updates", []string{
			"label", "title", "version", "recommended",
		}, false); err != nil {
			return err
		}
	}

	if _, ok := m["patches"]; ok {
		if err := schemaRequireArrayOfObjects(m, "patches", []string{
			"name", "version", "date_raw",
		}, false); err != nil {
			return err
		}
	}

	// browser_extensions items must carry the fields device_browser_extensions
	// requires as NOT NULL or uses as part of its conflict key: browser,
	// profile, user_account, extension_id (PAT-871). This only checks that the
	// keys are present, not that their values are non-empty — an entry with an
	// empty user_account or profile is a valid, schema-conformant JSON shape;
	// upsertBrowserExtensions skips and logs it rather than failing ingestion,
	// so one malformed extension never has to take the whole device snapshot
	// down with it.
	if _, ok := m["browser_extensions"]; ok {
		if err := schemaRequireArrayOfObjects(m, "browser_extensions", []string{
			"browser", "profile", "user_account", "extension_id",
		}, false); err != nil {
			return err
		}
	}

	// PAT-2055: the optional completeness block for browser_extensions.
	// Structure only (strict at every level). A structurally valid block that
	// disagrees with itself or with the array is NOT rejected here, since that
	// would drop the device's whole inventory; the extractor stores it with its
	// authority withheld (browserExtensionsStatusProblem).
	if _, ok := m["browser_extensions_status"]; ok {
		if err := validateBrowserExtensionsStatus(m); err != nil {
			return err
		}
	}

	// agent_health (PAT-1064) is DELIBERATELY not validated here at all — not
	// even a key-presence check like browser_extensions gets immediately
	// above. This is not an oversight; an earlier version of this function
	// did check key presence and shape, and that was itself the bug (review
	// round 3, FIX 9): ValidatePayload runs at the ingestion gate, BEFORE a
	// payload is ever persisted to raw_payloads, so any error it returns
	// rejects the entire POST /v1/inventory request — not just the
	// agent_health section. A single malformed health entry was 400ing the
	// device's whole inventory upload (apps, compliance, extensions,
	// everything), which is exactly the blast radius the browser_extensions
	// key-presence check above was designed to avoid for THAT section, and
	// exactly what PAYLOAD_SCHEMA.md promises will never happen for THIS
	// section ("a malformed entry is skipped and logged, never fatal").
	//
	// The extractor's own defensive path — parseAgentHealth and
	// sanitizeAgentHealthEntries in internal/extractor/upsert.go — is the
	// ONLY thing that inspects agent_health's shape. It runs AFTER the
	// payload is already persisted, so whatever it rejects (a malformed
	// top-level section, a malformed array element) is dropped from THIS
	// section only, never from the rest of the device's snapshot and never
	// from the HTTP response. See docs/payload.schema.json's agent_health
	// description and docs/PAYLOAD_SCHEMA.md's "Agent health object" section
	// for the explicit statement that the JSON Schema describes what agents
	// SHOULD send, not what this validator enforces.
	//
	// Do not add a shape check here later without re-solving this problem:
	// any check added to ValidatePayload can reject the whole payload, and
	// agent_health must never be able to do that.

	// compliance_findings (PAT-743, enum enforcement added in PAT-913 round 3) —
	// optional, but when present each item must carry an id and severity, and
	// the id must be in the finding-control enum. Completes the reserved-
	// namespace partition alongside the compliance-bag check above: findings
	// may only ever name reserved finding-control IDs (they write Fail-state
	// signal values in buildSignalsMap, so an arbitrary id could force a
	// Fail/garbage value onto any rule signal or clobber a legitimate bag key).
	if _, ok := m["compliance_findings"]; ok {
		if err := schemaRequireArrayOfObjects(m, "compliance_findings", []string{"id", "severity"}, false); err != nil {
			return err
		}
		arr, _ := m["compliance_findings"].([]any)
		for i, item := range arr {
			obj, _ := item.(map[string]any)
			id, ok := obj["id"].(string)
			if !ok {
				return fmt.Errorf("compliance_findings[%d].id: must be a string", i)
			}
			if !isFindingControlID(id) {
				return fmt.Errorf("compliance_findings[%d].id: value %q not in the finding-control enum (docs/payload.schema.json)", i, id)
			}
		}
	}

	// compliance_assessments (PAT-913, Option B) — optional, but strictly
	// enforced when present, INCLUDING the controls_assessed enum. These
	// entries mint positive "Pass" compliance signals in buildSignalsMap, so
	// accepting an arbitrary string here would let a compromised device
	// credential attest any signal key (filevault, defender_realtime, ...) and
	// fabricate a Pass on a non-finding control. Unknown IDs are therefore
	// rejected here — the same 400 path as every other schema violation — not
	// silently dropped.
	//
	// The enum lives in docs/payload.schema.json (the authority); this check
	// enforces it via the shared findingControlIDs set (finding_controls.go),
	// which buildSignalsMap also consults, so the two can never drift apart.
	// This validator IS the canonical-schema enforcement point on the ingestion
	// path — it is not a second speculative copy of contract data. Together
	// with the compliance-bag and compliance_findings checks above, all three
	// writers into the signal map are held to the reserved-namespace partition:
	// bag keys never reserved, finding/attestation IDs always reserved.
	if _, ok := m["compliance_assessments"]; ok {
		ca, err := schemaRequireObject(m, "compliance_assessments")
		if err != nil {
			return err
		}
		for k := range ca {
			if k != "controls_assessed" {
				return fmt.Errorf("compliance_assessments.%s: additional properties not allowed", k)
			}
		}
		if _, ok := ca["controls_assessed"]; ok {
			arr, err := schemaRequireArray(ca, "controls_assessed")
			if err != nil {
				return fmt.Errorf("compliance_assessments.%w", err)
			}
			for i, item := range arr {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("compliance_assessments.controls_assessed[%d]: must be a string", i)
				}
				if !isFindingControlID(s) {
					return fmt.Errorf("compliance_assessments.controls_assessed[%d]: value %q not in the finding-control enum (docs/payload.schema.json)", i, s)
				}
			}
		}
	}

	return nil
}

// schemaCheckRequired returns an error if any key in required is absent from m.
func schemaCheckRequired(m map[string]any, prefix string, required []string) error {
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%s%s: required field is missing", prefix, k)
		}
	}
	return nil
}

// schemaRequireObject asserts m[key] exists and is a JSON object.
func schemaRequireObject(m map[string]any, key string) (map[string]any, error) {
	raw, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%s: required field is missing", key)
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be an object", key)
	}
	return obj, nil
}

// schemaRequireArray asserts m[key] exists and is a JSON array.
func schemaRequireArray(m map[string]any, key string) ([]any, error) {
	raw, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%s: required field is missing", key)
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be an array", key)
	}
	return arr, nil
}

// schemaRequireArrayOfObjects asserts m[key] is a JSON array whose items (if any)
// are objects each containing all fields in itemRequired.
// If allowMissing is true and m[key] is absent, the function is a no-op.
func schemaRequireArrayOfObjects(m map[string]any, key string, itemRequired []string, allowMissing bool) error {
	raw, ok := m[key]
	if !ok {
		if allowMissing {
			return nil
		}
		return fmt.Errorf("%s: required field is missing", key)
	}
	arr, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s: must be an array", key)
	}
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d]: must be an object", key, i)
		}
		if err := schemaCheckRequired(obj, fmt.Sprintf("%s[%d].", key, i), itemRequired); err != nil {
			return err
		}
	}
	return nil
}

// schemaRequireInt asserts m[key] is a JSON number that represents an integer value.
func schemaRequireInt(m map[string]any, key string) (int, error) {
	raw, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("%s: required field is missing", key)
	}
	f, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("%s: must be an integer (got %T)", key, raw)
	}
	if f != float64(int(f)) {
		return 0, fmt.Errorf("%s: must be an integer (got %v)", key, f)
	}
	return int(f), nil
}

// validateAppsUsers checks collection_status.apps_users (PAT-2075): an array
// of objects, each with exactly a string user_account and a collection_status
// in the shared three-value enum, plus an optional string home. A case- or fold-variant key is refused
// earlier by checkPayloadKeys. An empty user_account, or two entries for the
// same user, are not rejected: the extractor ignores the first and merges
// the second least-authoritative-wins (appsUserCompleteSet).
func validateAppsUsers(raw any) error {
	list, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("collection_status.apps_users: must be an array")
	}
	for i, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("collection_status.apps_users[%d]: must be an object", i)
		}
		for k := range entry {
			if k != "user_account" && k != "collection_status" && k != "home" {
				return fmt.Errorf("collection_status.apps_users[%d].%s: additional properties not allowed", i, k)
			}
		}
		prefix := fmt.Sprintf("collection_status.apps_users[%d].", i)
		if err := schemaCheckRequired(entry, prefix, []string{"user_account", "collection_status"}); err != nil {
			return err
		}
		if _, ok := entry["user_account"].(string); !ok {
			return fmt.Errorf("%suser_account: must be a string", prefix)
		}
		status, ok := entry["collection_status"].(string)
		if !ok {
			return fmt.Errorf("%scollection_status: must be a string", prefix)
		}
		switch status {
		case "complete", "partial", "unavailable":
		default:
			return fmt.Errorf("%scollection_status: value %q not in enum [\"complete\", \"partial\", \"unavailable\"]", prefix, status)
		}
		// home is optional. Only its type is checked: a string that is not
		// a usable home (relative, "/", a trailing slash, ...) is accepted
		// and grants nothing, see legacyUserHome.
		if home, present := entry["home"]; present {
			if _, ok := home.(string); !ok {
				return fmt.Errorf("%shome: must be a string", prefix)
			}
		}
	}
	return nil
}
