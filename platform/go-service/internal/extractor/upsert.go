package extractor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/publicsuffix"
)

// uuidRegex matches the canonical 8-4-4-4-12 hex UUID form. The macOS
// collector pulls IOPlatformUUID from ioreg, which is always in this form when
// present and "Unknown" when not — anything else means a parse mishap upstream.
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// parseBackupStatus decodes the payload's raw backup_status bytes into a
// typed backupStatusPart. Returns nil when the key was absent/null (older
// agent — no-op, existing devices.backup_status snapshot is preserved) or
// when decoding failed. The latter is logged and treated exactly like
// "absent" so one malformed backup_status section never poisons the rest of
// the device snapshot (PAT-948) — the same defensive posture PAT-871
// established for a malformed browser_extensions array element, applied here
// to a top-level section carried as json.RawMessage for this reason.
func parseBackupStatus(raw json.RawMessage, logger *slog.Logger) *backupStatusPart {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var b backupStatusPart
	if err := json.Unmarshal(raw, &b); err != nil {
		if logger != nil {
			logger.Warn("skipping malformed backup_status section", "err", err)
		}
		return nil
	}
	return &b
}

// parseOSUpdate decodes the payload's raw os_update bytes into a typed
// osUpdatePart (PAT-1806). Returns nil when the key was absent/null (no
// agent has ever sent this yet — no-op, existing device_os_update row is
// preserved) or when decoding failed. The latter is logged and treated
// exactly like "absent" so one malformed os_update section never poisons the
// rest of the device snapshot — the same defensive posture parseBackupStatus
// established above (PAT-948) and PAT-871 established for browser_extensions.
func parseOSUpdate(raw json.RawMessage, logger *slog.Logger) *osUpdatePart {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var o osUpdatePart
	if err := json.Unmarshal(raw, &o); err != nil {
		if logger != nil {
			logger.Warn("skipping malformed os_update section", "err", err)
		}
		return nil
	}
	return &o
}

// validDeviceClasses is the set of real classifications — deliberately
// excludes "unknown" even though the wire schema's device_class enum
// includes it (PAT-1959 agents send the literal "unknown" as a genuine "I
// couldn't tell this run" report). Both an omitted field and an explicit
// "unknown" report resolve through the same not-given path in
// resolveDeviceClass: they're evidentially identical for devices.device_class
// purposes (mirrors the CHECK constraint's full vocabulary in
// migrations/0158_device_class.sql, which does store 'unknown' — just never
// as something this map treats as "given").
var validDeviceClasses = map[string]bool{
	"workstation":       true,
	"server":            true,
	"domain_controller": true,
}

// deviceClassUnknown is the sentinel written when the payload omits
// device_class, sends the literal "unknown", or sends a value outside
// validDeviceClasses — never a guess, and (PAT-1960) matched against every
// enabled rule for the device's platform exactly like the
// pre-device-class behaviour. See evaluator's deviceClassMatchSQL.
const deviceClassUnknown = "unknown"

// resolveDeviceClass reads p.DeviceClass (top level; PAT-1960 moved this off
// the os object — device_class is a property of the machine, not the OS) and
// resolves it to a value that is always safe to write to
// devices.device_class: the reported class when it is one of
// validDeviceClasses, "unknown" otherwise. That "otherwise" covers three
// payload shapes identically — an absent field, the agent's own literal
// "unknown" report (a genuine "source was absent, unreadable or
// contradictory" signal, never a guess), and any unrecognised value — none
// of them name a real class. given distinguishes those three from a genuine
// classification so upsertDevice can decide whether an update should
// overwrite an already-known classification: an older/degraded agent that
// omits the field, or a modern agent that honestly can't tell this run, must
// not downgrade a device's classification back to unknown.
//
// The single source of truth for this resolution: upsertDevice calls it to
// decide what to persist and returns the value actually stored (which
// extractor.go's processRow then uses, AFTER the device upsert, to decide
// which rules apply via evaluator.LoadRules/LoadRulesForTenant — see the
// comment at that call site for why the ordering matters).
func resolveDeviceClass(p *payload) (value string, given bool) {
	raw := strings.TrimSpace(p.DeviceClass)
	if validDeviceClasses[raw] {
		return raw, true
	}
	return deviceClassUnknown, false
}

// upsertDevice inserts-or-updates the devices row for this payload and
// returns the device_id and the device_class actually stored (never a guess:
// "unknown" whenever the payload didn't carry a valid os.device_class, same
// value a fresh row would default to). Two paths: ON CONFLICT
// (tenant_id, hw_uuid) when the payload has a parseable UUID, ON CONFLICT
// (tenant_id, serial) otherwise. Errors if neither identifier is usable.
//
// last_seen is stamped from receivedAt (raw_payloads.received_at — the
// server's own clock at ingest, stamped by the API handler before this row
// ever reaches the extractor queue), not from now() at extraction time
// (PAT-2102). An extractor outage or replay processes old reports late;
// stamping last_seen with the wall-clock time of extraction made a report
// received (and truthfully evidencing) 20 days ago look like it arrived
// today across every reader of devices.last_seen — the silent-device
// buckets, the stale-endpoint report, coverage, Unapproved alerts and
// Cyber Essentials 14-day evidence all trusted a timestamp that measured
// extractor lag, not evidence age. received_at is chosen over the payload's
// own collected_at: it is assigned by our server, so it can't be pushed
// forward by a skewed or malicious endpoint clock, and it was already
// available at every call site with no new plumbing. On conflict the
// column is GREATEST'd against the existing value so replaying an older
// report after a newer one, or two extraction workers racing, never moves
// last_seen backwards.
//
// Always runs inside the caller's transaction.
func upsertDevice(ctx context.Context, tx pgx.Tx, tenantID string, receivedAt time.Time, p *payload, logger *slog.Logger) (string, string, error) {
	serial := strings.TrimSpace(p.Device.Serial)
	hwUUIDRaw := strings.TrimSpace(p.Device.HWUUID)

	hwUUIDValid := uuidRegex.MatchString(hwUUIDRaw)
	if !hwUUIDValid && serial == "" {
		return "", "", fmt.Errorf("device has neither valid hw_uuid (%q) nor serial", hwUUIDRaw)
	}

	// device_class / installation_type / os_caption (PAT-1960; top-level
	// payload fields, Windows agent side is PAT-1959, so only Windows
	// payloads populate these today — the envelope stays platform-neutral,
	// macOS simply omits them). deviceClassGiven distinguishes a
	// resolved-to-unknown payload (field absent, the agent's own literal
	// "unknown" report, or an unrecognised value) from a genuine
	// classification, so an update never downgrades an already-known
	// classification just because a later check-in couldn't reconfirm it.
	deviceClass, deviceClassGiven := resolveDeviceClass(p)

	// security_inventory: sv=2 always includes all four sections and fully
	// replaces the snapshot, same as before. sv=3 (Windows) only ever carries
	// security_tools — system_extensions/background_items/icloud are macOS-only
	// concepts the Windows agent has nothing to report for — so a full
	// overwrite would silently erase those sections on any device row that
	// happens to already carry them. secInvMergeSecurityTools (bound as $28
	// below) tells the upsert to merge {"security_tools": [...]} into the
	// EXISTING jsonb instead of replacing it wholesale (PAT-2269): previously
	// sv=3 passed SQL NULL here unconditionally, which via the plain COALESCE
	// preserved the existing snapshot untouched — meaning Windows
	// security_tools was NEVER stored, and EDR coverage/CE malware-protection
	// saw nothing for every Windows device. secInvArg stays nil (SQL NULL)
	// when the payload itself carries no security_tools value (replay of a
	// pre-validation row, or a malformed re-extraction) — validate.go requires
	// the key on every live ingest, so this is a defensive fallback, not the
	// common path — and NULL here is a no-op under the merge CASE too (merging
	// with an empty object changes nothing).
	var secInvArg any
	secInvMergeSecurityTools := p.SchemaVersion == 3
	if p.SchemaVersion != 3 {
		secInv := securityInventory{
			SecurityTools:    p.SecurityTools,
			SystemExtensions: p.SystemExtensions,
			BackgroundItems:  p.BackgroundItems,
			ICloud:           p.ICloud,
		}
		secInvJSON, err := json.Marshal(secInv)
		if err != nil {
			return "", "", fmt.Errorf("marshal security_inventory: %w", err)
		}
		secInvArg = secInvJSON
	} else if len(p.SecurityTools) > 0 && string(p.SecurityTools) != "null" {
		toolsOnly := struct {
			SecurityTools json.RawMessage `json:"security_tools"`
		}{SecurityTools: p.SecurityTools}
		toolsOnlyJSON, err := json.Marshal(toolsOnly)
		if err != nil {
			return "", "", fmt.Errorf("marshal security_inventory (sv3 security_tools): %w", err)
		}
		secInvArg = toolsOnlyJSON
	}

	// hardware: store as-is. The collector emits a well-formed object.
	// nil RawMessage marshals as `null` from pgx; we want SQL NULL there
	// instead so the column behaves consistently.
	var hardwareArg any
	if len(p.Hardware) > 0 && string(p.Hardware) != "null" {
		hardwareArg = []byte(p.Hardware)
	}

	// pending_updates: same treatment. Older collectors (pre-0.3.0) omit this
	// field entirely; the JSONB column stays unchanged on those ingests.
	var pendingArg any
	if len(p.PendingUpdates) > 0 && string(p.PendingUpdates) != "null" {
		pendingArg = []byte(p.PendingUpdates)
	}

	// backup_status (PAT-679/680 agents; PAT-948 server ingestion). Absent,
	// null, or malformed (see parseBackupStatus) → SQL NULL, same COALESCE-
	// preserve treatment as pending_updates/hardware above: the existing
	// snapshot on the devices row is left untouched rather than clobbered.
	// Re-marshaled (not stored raw) so the column always holds the canonical
	// known-fields shape, never whatever extra keys a future agent might add.
	var backupStatusArg any
	if bs := parseBackupStatus(p.BackupStatus, logger); bs != nil {
		j, err := json.Marshal(bs)
		if err != nil {
			return "", "", fmt.Errorf("marshal backup_status: %w", err)
		}
		backupStatusArg = j
	}

	// serial as SQL NULL when empty — UNIQUE(tenant_id, serial) lets multiple
	// rows have NULL serial in the same tenant.
	var serialArg any
	if serial != "" {
		serialArg = serial
	}
	// hw_uuid likewise NULL when not parseable.
	var hwUUIDArg any
	if hwUUIDValid {
		hwUUIDArg = hwUUIDRaw
	}

	// Resolve primary user: macOS emits a top-level "primary_user" object;
	// Windows emits flat fields inside the "device" block. Prefer the
	// top-level object when present and non-empty; fall back to device-block
	// fields so both collector paths populate the same columns.
	primaryUserAccount := p.Device.PrimaryUserAccount
	primaryUserDisplay := p.Device.PrimaryUserDisplay
	primaryUserSource := p.Device.PrimaryUserSource
	if p.PrimaryUser != nil && p.PrimaryUser.Account != "" {
		primaryUserAccount = p.PrimaryUser.Account
		primaryUserSource = p.PrimaryUser.Source
		// macOS primary_user block does not include a display name in v1.
	}
	wingetInventoryComplete := p.SchemaVersion == 3 && p.Platform == "windows" && p.InventoryCapabilities != nil &&
		p.InventoryCapabilities.SchemaVersion == 1 && p.InventoryCapabilities.WindowsWingetInventoryComplete
	if wingetInventoryComplete {
		for _, app := range p.Apps {
			if app.IdentifierKind == "winget" && !isCanonicalWingetInventoryID(app.Identifier) {
				wingetInventoryComplete = false
				break
			}
		}
	}
	var wingetInventorySchema any
	if wingetInventoryComplete {
		wingetInventorySchema = int16(1)
	}

	// The two upsert statements differ only in which UNIQUE constraint we
	// target. Everything else is identical — kept as two literals rather than
	// a builder to make the SQL grep-able from the worker logs.
	const baseColumns = `
		tenant_id, serial, hw_uuid, hostname, computer_name,
		os, os_version, os_build, hw_model, arch,
		hardware, security_inventory, agent_version, schema_version,
		pending_updates, metering_status, backup_status, metering_user_hive_count, metering_record_count,
		primary_user_account, primary_user_display, primary_user_source, primary_user_last_seen_at,
		windows_winget_inventory_complete, windows_winget_inventory_schema,
		device_class, installation_type, os_caption,
		last_seen
	`
	const baseValues = `
		$1, $2, $3, $4, $5,
		$6, $7, $8, $9, $10,
		$11, $12, $13, $14,
		$15, $16, $17, $29, $30,
		$18, $19, $20, CASE WHEN $18::text IS NOT NULL AND $18::text <> '' THEN now() ELSE NULL END,
		$21, $22,
		$23, $24, $25,
		$27
	`
	const updateSet = `
		serial             = COALESCE(NULLIF(EXCLUDED.serial,''),  devices.serial),
		hw_uuid            = COALESCE(EXCLUDED.hw_uuid,            devices.hw_uuid),
		hostname           = COALESCE(NULLIF(EXCLUDED.hostname,''),devices.hostname),
		computer_name      = COALESCE(NULLIF(EXCLUDED.computer_name,''), devices.computer_name),
		os                 = EXCLUDED.os,
		os_version         = COALESCE(NULLIF(EXCLUDED.os_version,''), devices.os_version),
		os_build           = COALESCE(NULLIF(EXCLUDED.os_build,''), devices.os_build),
		hw_model           = COALESCE(NULLIF(EXCLUDED.hw_model,''), devices.hw_model),
		arch               = COALESCE(NULLIF(EXCLUDED.arch,''),     devices.arch),
		hardware           = COALESCE(EXCLUDED.hardware,           devices.hardware),
		-- security_inventory (PAT-2269): sv=2 fully replaces the snapshot as
		-- before (ELSE branch, unchanged). sv=3 ($28 = secInvMergeSecurityTools)
		-- merges EXCLUDED's {"security_tools": [...]} into the EXISTING jsonb
		-- instead, so a Windows ingest can never wipe macOS-only sections
		-- (system_extensions/background_items/icloud) that happen to already
		-- sit on the same device row — the Windows agent has nothing to report
		-- for those keys, so a full overwrite would silently erase them. jsonb
		-- concatenation (the || operator) on two objects keeps every key from
		-- the left side except where the right side also has it, so old
		-- security_tools is replaced by the
		-- new value and every other key survives untouched. NULL EXCLUDED
		-- values (no security_tools evidence in this ingest) COALESCE to '{}'
		-- on both sides, so merging is a no-op exactly like the old
		-- preserve-via-NULL behaviour.
		security_inventory = CASE
		                          WHEN $28 THEN COALESCE(devices.security_inventory, '{}'::jsonb)
		                                        || COALESCE(EXCLUDED.security_inventory, '{}'::jsonb)
		                          ELSE COALESCE(EXCLUDED.security_inventory, devices.security_inventory)
		                     END,
		agent_version      = COALESCE(NULLIF(EXCLUDED.agent_version,''), devices.agent_version),
		schema_version     = EXCLUDED.schema_version,
		pending_updates    = COALESCE(EXCLUDED.pending_updates,    devices.pending_updates),
		metering_status    = CASE WHEN EXCLUDED.last_seen >= devices.last_seen THEN NULLIF(EXCLUDED.metering_status,'') ELSE devices.metering_status END,
		metering_user_hive_count = CASE WHEN EXCLUDED.last_seen >= devices.last_seen THEN EXCLUDED.metering_user_hive_count ELSE devices.metering_user_hive_count END,
		metering_record_count = CASE WHEN EXCLUDED.last_seen >= devices.last_seen THEN EXCLUDED.metering_record_count ELSE devices.metering_record_count END,
		backup_status      = COALESCE(EXCLUDED.backup_status,      devices.backup_status),
		-- Primary user: only update when the inbound payload carries a non-empty
		-- account. Empty / absent account leaves the prior value intact — same
		-- COALESCE-preserve pattern for backup_status (PAT-116).
		-- PII note: these columns are only surfaced when report_user_attribution
		-- is enabled per-tenant (PAT-112 DPA dependency — default OFF).
		primary_user_account = CASE WHEN EXCLUDED.primary_user_account IS NOT NULL AND EXCLUDED.primary_user_account <> ''
		                            THEN EXCLUDED.primary_user_account
		                            ELSE devices.primary_user_account END,
		primary_user_display = CASE WHEN EXCLUDED.primary_user_account IS NOT NULL AND EXCLUDED.primary_user_account <> ''
		                            THEN EXCLUDED.primary_user_display
		                            ELSE devices.primary_user_display END,
		primary_user_source  = CASE WHEN EXCLUDED.primary_user_account IS NOT NULL AND EXCLUDED.primary_user_account <> ''
		                            THEN EXCLUDED.primary_user_source
		                            ELSE devices.primary_user_source END,
		primary_user_last_seen_at = CASE WHEN EXCLUDED.primary_user_account IS NOT NULL AND EXCLUDED.primary_user_account <> ''
		                                 THEN now()
		                                 ELSE devices.primary_user_last_seen_at END,
		windows_winget_inventory_complete = EXCLUDED.windows_winget_inventory_complete,
		windows_winget_inventory_schema = EXCLUDED.windows_winget_inventory_schema,
		-- device_class (PAT-1960): only overwrite when THIS payload actually
		-- reported a valid class ($26 = deviceClassGiven). Otherwise an older
		-- or degraded agent that omits os.device_class on a later check-in
		-- would downgrade an already-known classification back to
		-- "unknown" — EXCLUDED.device_class is always a concrete value
		-- (never NULL, see baseValues), so a plain COALESCE here would never
		-- preserve the existing row.
		device_class       = CASE WHEN $26 THEN EXCLUDED.device_class ELSE devices.device_class END,
		installation_type  = COALESCE(EXCLUDED.installation_type, devices.installation_type),
		os_caption         = COALESCE(EXCLUDED.os_caption,        devices.os_caption),
		-- last_seen (PAT-2102): $27 is receivedAt (raw_payloads.received_at), not
		-- now(). GREATEST against the existing value so an out-of-order or
		-- replayed extraction never drags last_seen backwards.
		last_seen          = GREATEST(devices.last_seen, EXCLUDED.last_seen)
	`

	args := []any{
		tenantID, serialArg, hwUUIDArg,
		nullIfEmpty(p.Device.Hostname), nullIfEmpty(p.Device.ComputerName),
		p.OS.Name, nullIfEmpty(p.OS.Version), nullIfEmpty(p.OS.Build),
		nullIfEmpty(p.Device.HWModel), nullIfEmpty(p.Device.Arch),
		hardwareArg, secInvArg,
		nullIfEmpty(p.AgentVersion), p.SchemaVersion,
		pendingArg, nullIfEmpty(p.MeteringStatus), backupStatusArg,
		nullIfEmpty(primaryUserAccount), nullIfEmpty(primaryUserDisplay), nullIfEmpty(primaryUserSource),
		wingetInventoryComplete, wingetInventorySchema,
		deviceClass, nullIfEmpty(p.InstallationType), nullIfEmpty(p.OSCaption),
		deviceClassGiven,
		receivedAt,
		secInvMergeSecurityTools,
		p.MeteringUserHiveCount, p.MeteringRecordCount,
	}

	var sqlStmt string
	if hwUUIDValid {
		sqlStmt = `INSERT INTO devices (` + baseColumns + `) VALUES (` + baseValues + `)
			ON CONFLICT (tenant_id, hw_uuid) DO UPDATE SET ` + updateSet + `
			RETURNING id::text, device_class`
	} else {
		sqlStmt = `INSERT INTO devices (` + baseColumns + `) VALUES (` + baseValues + `)
			ON CONFLICT (tenant_id, serial) DO UPDATE SET ` + updateSet + `
			RETURNING id::text, device_class`
	}

	// storedDeviceClass is scanned back from the row rather than returning
	// the local deviceClass variable directly: on an UPDATE that preserves
	// an existing classification (deviceClassGiven=false), EXCLUDED's
	// resolved "unknown" is NOT what ends up on the row — devices.device_class
	// wins via the CASE in updateSet. Returning the local variable here would
	// have reported "unknown" to the caller (and so to evaluator.LoadRules)
	// even though the row, and therefore the correct rule set, stayed at the
	// previously-known class.
	var deviceID, storedDeviceClass string
	if err := tx.QueryRow(ctx, sqlStmt, args...).Scan(&deviceID, &storedDeviceClass); err != nil {
		return "", "", fmt.Errorf("upsert device: %w", err)
	}
	return deviceID, storedDeviceClass, nil
}

// linkRawPayloadToDevice fills raw_payloads.device_id after the device row is
// created/found. Composite PK on the partitioned table means we need both id
// and received_at to address a row.
func linkRawPayloadToDevice(ctx context.Context, tx pgx.Tx, rawID int64, receivedAt any, deviceID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE raw_payloads
		SET device_id = $1
		WHERE id = $2 AND received_at = $3
	`, deviceID, rawID, receivedAt)
	if err != nil {
		return fmt.Errorf("link raw_payload to device: %w", err)
	}
	return nil
}

// helperSuffixes is the ordered list of well-known macOS helper bundle suffixes
// used by Layer A suppression (PAT-594). Longer suffixes must appear before any
// shorter prefix of themselves so we always strip the most-specific match first.
// Apple has used this naming convention since the Chromium/Electron era; it is
// effectively stable.
var helperSuffixes = []string{
	".helper.GPU",
	".helper.Renderer",
	".helper.Plugin",
	".helper",
	".crashpad",
	".SandboxHelper",
	".xpc",
	".agent",
}

// helperNamePrefixes lists display-name prefixes that identify Electron (and
// similar frameworks) helper processes when the bundle_id is absent or
// unhelpful. Checked via strings.HasPrefix on the trimmed app name.
var helperNamePrefixes = []string{
	"Electron Helper",
}

// appGroupRule is a single row from app_group_rules — loaded once per
// extraction batch and applied to every app in Layer B (PAT-594).
type appGroupRule struct {
	BundlePrefix   string
	CanonicalLabel string
	CanonicalName  string
}

// loadAppGroupRules fetches the persisted app_group_rules for a single
// extraction batch. Retirement removes the Installomator fetch/write path, not
// identity evidence already accepted into this table. Keeping all sources
// readable preserves canonical names and existing downstream joins without a
// destructive rematch migration. The table is expected to have fewer than 100
// rows; a full table scan on every batch is intentional and fine.
func loadAppGroupRules(ctx context.Context, db pgxQuerier) ([]appGroupRule, error) {
	rows, err := db.Query(ctx, `SELECT bundle_prefix, canonical_label, canonical_name FROM app_group_rules`)
	if err != nil {
		return nil, fmt.Errorf("load app_group_rules: %w", err)
	}
	defer rows.Close()
	var out []appGroupRule
	for rows.Next() {
		var r appGroupRule
		if err := rows.Scan(&r.BundlePrefix, &r.CanonicalLabel, &r.CanonicalName); err != nil {
			return nil, fmt.Errorf("scan app_group_rule: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate app_group_rules: %w", err)
	}
	return out, nil
}

// pgxQuerier is the minimal interface satisfied by both *pgxpool.Pool and
// pgx.Tx — used by loadAppGroupRules so it can be called with either.
type pgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// isHelperBundle returns true when the entry should be suppressed (Layer A).
// It checks two conditions:
//  1. The bundle ID ends with a well-known helper suffix AND the parent bundle
//     (suffix stripped) exists in the same payload.
//  2. OR the display name starts with a known Electron helper name prefix.
//
// The name check covers cases where bundle IDs are absent or non-descriptive.
// The parent-presence requirement prevents false suppressions: if only the
// helper was installed (edge case), we keep it.
func isHelperBundle(identifier, name string, payload []appPart) bool {
	// Layer A — name-prefix check (fast, no iteration needed).
	trimmedName := strings.TrimSpace(name)
	for _, prefix := range helperNamePrefixes {
		if strings.HasPrefix(trimmedName, prefix) {
			return true
		}
	}

	// Layer A — bundle ID suffix check.
	if identifier == "" {
		return false
	}
	for _, suffix := range helperSuffixes {
		if strings.HasSuffix(identifier, suffix) {
			parent := identifier[:len(identifier)-len(suffix)]
			// Verify the parent exists somewhere else in the payload.
			for _, a := range payload {
				pid := strings.TrimSpace(a.Identifier)
				if pid == "" {
					pid = strings.TrimSpace(a.BundleID)
				}
				if pid != "" && pid == parent {
					return true
				}
			}
			// Parent not found — keep the helper (it's the only entry).
			return false
		}
	}
	return false
}

// applyGroupRule rewrites name to the canonical values from the first matching
// app_group_rules row (Layer B, PAT-594). Returns the (possibly rewritten)
// name unchanged when no rule matches. identifier is unchanged — the UNIQUE
// constraint on device_apps uses the original identifier so we don't create a
// new row on every ingest after a rule is added.
func applyGroupRule(identifier, name string, rules []appGroupRule) (canonicalName string) {
	if identifier == "" || len(rules) == 0 {
		return name
	}
	for _, r := range rules {
		if strings.HasPrefix(identifier, r.BundlePrefix) {
			return r.CanonicalName
		}
	}
	return name
}

// upsertApps inserts-or-touches device_apps rows from the payload's apps array,
// then prunes any device_apps row for this device that this scan did not
// reconfirm (PAT-808), so rows do not accumulate forever (e.g. after a
// collector/catalog fix changes how an app is identified). `apps` is required
// on every supported schema version, but a required array is not a complete
// one: a collector that fails part way still sends it. The prune therefore
// needs absence authority (PAT-2063, apps_authority.go).
//
// Conflict key is the existing UNIQUE(device_id, identifier, version) — a
// distinct (identifier, version) pair is treated as a new install; same pair
// just refreshes last_seen.
//
// Identifier resolution: prefer the v3 `identifier` field; fall back to
// `bundle_id` for v2 macOS payloads. Apps where neither is usable are skipped —
// without an identifier we'd generate near-duplicates on every run.
//
// Two deduplication layers are applied before each upsert (PAT-594):
//   - Layer A: suppress well-known helper bundles (Electron helpers, etc.)
//   - Layer B: rewrite name to canonical values for known vendor prefixes
//
// Also upserts a (name, platform) -> app_path row into known_app_bundles for
// every app that reports a non-empty path (PAT-806) -- a tenant-agnostic,
// auto-populated table the macOS/Windows uninstall engines consult to resolve
// display-name/bundle-filename mismatches (e.g. "Zoom" installs as
// zoom.us.app) for apps that were never manually reviewed into the curated
// EULA/mirror Catalogue. platform must already be resolved to "macos" or
// "windows" (see processRow) -- device_apps spans both and their path shapes
// are unrelated, so the known_app_bundles key includes platform.
//
// PAT-2063: the prune of unreported rows runs only when this report has
// absence authority. signal and withheldReason come from resolveAppsSignal:
// appsSignalComplete prunes, appsSignalIncomplete never does, and
// appsSignalNone (an agent that sends no collection_status.apps) prunes
// unless the safety valve in apps_authority.go holds it. The returned
// decision says which happened; when Pruned is false the caller must also
// withhold the application absence scopes (payload.AppsAbsenceWithheld).
//
// PAT-2075: signal governs the machine-wide scope only (rows with no
// user_account). A row with a user_account is written to device_apps as
// usual and also recorded in device_app_user_scopes for that user;
// completeUsers (appsUserCompleteSet) are the users whose unreported
// per-user rows this report prunes, whatever the machine-wide signal. See
// apps_users.go. legacyHold (resolveLegacyUserHold) withholds the
// machine-wide prune from stored machine-wide rows located in a user's home
// when the report scopes users itself; see apps_legacy_user.go.
func upsertApps(ctx context.Context, tx pgx.Tx, deviceID string, receivedAt time.Time, apps []appPart, groupRules []appGroupRule, platform string, signal appsSignal, withheldReason string, completeUsers []string, legacyHold legacyUserHold) (int, appsPruneDecision, error) {
	var decision appsPruneDecision
	// PAT-2075: the legacy user-located rows as stored, before the upserts
	// below can overwrite a path. Only a report that scopes users itself
	// lacks authority over them (apps_legacy_user.go).
	var legacyRows []legacyUserRow
	legacySightings := map[string][]legacyUserSighting{}
	if legacyHold.Active {
		rows, err := loadLegacyUserRows(ctx, tx, deviceID)
		if err != nil {
			return 0, decision, err
		}
		legacyRows = rows
	}
	current, err := countAppIdentifiers(ctx, tx, deviceID)
	if err != nil {
		return 0, decision, err
	}
	decision.Current = current
	const stmt = `
		INSERT INTO device_apps (
			device_id, name, version, identifier, path,
			size_bytes, sha256, signer, team_id, architecture, notarized, publisher,
			last_used_at, launch_count, usage_evidence, usage_evidence_at, usage_evidence_complete,
			identifier_kind,
			machine_wide,
			last_seen
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11, $12,
			$13::timestamptz, $14, $18, $17, $19,
			$15,
			$16,
			$17
		)
		ON CONFLICT (device_id, identifier, version) DO UPDATE SET
			name         = EXCLUDED.name,
			path         = EXCLUDED.path,
			size_bytes   = EXCLUDED.size_bytes,
			sha256       = COALESCE(NULLIF(EXCLUDED.sha256,''),    device_apps.sha256),
			signer       = COALESCE(NULLIF(EXCLUDED.signer,''),    device_apps.signer),
			team_id      = COALESCE(NULLIF(EXCLUDED.team_id,''),   device_apps.team_id),
			architecture = COALESCE(NULLIF(EXCLUDED.architecture,''), device_apps.architecture),
			notarized    = EXCLUDED.notarized,
			publisher    = COALESCE(NULLIF(EXCLUDED.publisher,''), device_apps.publisher),
			-- Metering: a payload that omits the signal (older/non-macOS agent)
			-- leaves NULL, so COALESCE keeps the last known value rather than
			-- wiping it. When present, the fresh reading wins.
			last_used_at = CASE WHEN EXCLUDED.last_seen >= device_apps.last_seen THEN COALESCE(EXCLUDED.last_used_at, device_apps.last_used_at) ELSE device_apps.last_used_at END,
			launch_count = CASE WHEN EXCLUDED.last_seen >= device_apps.last_seen THEN COALESCE(EXCLUDED.launch_count, device_apps.launch_count) ELSE device_apps.launch_count END,
			usage_evidence = CASE WHEN EXCLUDED.last_seen >= device_apps.last_seen THEN EXCLUDED.usage_evidence ELSE device_apps.usage_evidence END,
			usage_evidence_at = GREATEST(device_apps.usage_evidence_at, EXCLUDED.usage_evidence_at),
			usage_evidence_complete = CASE WHEN EXCLUDED.last_seen >= device_apps.last_seen
                THEN EXCLUDED.usage_evidence_complete
                     AND (NOT device_apps.machine_wide OR $20)
                     AND NOT EXISTS (SELECT 1 FROM device_app_user_scopes us
                         WHERE us.device_app_id = device_apps.id AND NOT (us.user_account = ANY(COALESCE($21::text[], ARRAY[]::text[]))))
                ELSE device_apps.usage_evidence_complete END,
			identifier_kind = EXCLUDED.identifier_kind,
			-- PAT-2075: a per-user sighting never clears a machine-wide
			-- assertion; only the machine-wide prune does.
			machine_wide = device_apps.machine_wide OR EXCLUDED.machine_wide,
			-- last_seen (PAT-2102): $17 is receivedAt (raw_payloads.received_at),
			-- not now() — see upsertDevice's doc comment for why. GREATEST keeps
			-- a replayed/out-of-order extraction from moving it backwards.
			last_seen    = GREATEST(device_apps.last_seen, EXCLUDED.last_seen)
		RETURNING id
	`

	// machineIDs are the rows this report's machine-wide entries upserted.
	// Non-nil, so the SQL array is empty rather than NULL.
	machineIDs := []int64{}
	usageConflicts := appUsageConflicts(apps)
	written := 0
	for _, a := range apps {
		// Prefer v3 identifier; fall back to v2 bundle_id.
		identifier := strings.TrimSpace(a.Identifier)
		if identifier == "" {
			identifier = strings.TrimSpace(a.BundleID)
		}
		if identifier == "" || identifier == "Unknown" {
			continue
		}
		// device_apps.name is NOT NULL; fall back to the identifier if the
		// collector somehow couldn't pull the display name.
		name := strings.TrimSpace(a.Name)
		if name == "" {
			name = identifier
		}

		// Layer A (PAT-594): suppress well-known helper bundles — Electron helpers,
		// crashpad reporters, XPC services, etc. Skip the upsert entirely.
		if isHelperBundle(identifier, name, apps) {
			continue
		}

		// Layer B (PAT-594): rewrite name to canonical value for known vendor
		// bundle prefixes (Zoom, Discord, Spotify, …). identifier is preserved
		// so the UNIQUE constraint remains stable across rule additions.
		name = applyGroupRule(identifier, name, groupRules)
		// Convert MB → bytes, integer. Lossy on the fractional MB, fine for
		// this column (no use case demands sub-MB precision today).
		var sizeBytes any
		if a.SizeMB > 0 {
			sizeBytes = int64(a.SizeMB * 1024 * 1024)
		}
		// Metering: pass NULL when the agent didn't report a signal so the
		// upsert's COALESCE preserves any prior value.
		var lastUsed any
		if a.LastUsedAt != nil && strings.TrimSpace(*a.LastUsedAt) != "" {
			lastUsed = strings.TrimSpace(*a.LastUsedAt)
		}
		var launchCount any
		if a.LaunchCount != nil {
			launchCount = *a.LaunchCount
		}
		identifierKind := a.IdentifierKind
		if identifierKind == "winget" && !isCanonicalWingetInventoryID(identifier) {
			identifierKind = ""
		}
		user, validUser := appsUserKey(a.UserAccount)
		if !validUser {
			// PAT-2075 review: an over-long user_account is never stored
			// or truncated; see appsUserKey.
			decision.DroppedOverlong++
			continue
		}
		evidence := a.UsageEvidence
		completeUsage := usageEvidenceComplete(signal, user, completeUsers) && lastUsed != nil
		if usageConflicts[appUsageKey(a)] {
			unavailable := "unavailable"
			evidence, completeUsage = &unavailable, false
		}
		var appID int64
		err := tx.QueryRow(ctx, stmt,
			deviceID, name, nullIfEmpty(a.Version), identifier, nullIfEmpty(a.Path),
			sizeBytes, nullIfPlaceholder(a.SHA256), nullIfPlaceholder(a.SignedBy),
			nullIfPlaceholder(a.TeamID), nullIfPlaceholder(a.Architecture), a.Notarized,
			nullIfEmpty(a.Publisher),
			lastUsed, launchCount,
			nullIfEmpty(identifierKind),
			user == "",
			receivedAt,
			evidence, completeUsage, signal == appsSignalComplete, completeUsers,
		).Scan(&appID)
		if err != nil {
			return written, decision, fmt.Errorf("upsert app %q@%q: %w", identifier, a.Version, err)
		}
		if user == "" {
			machineIDs = append(machineIDs, appID)
		} else {
			if err := upsertAppUserScope(ctx, tx, appID, deviceID, user,
				deriveObservedSoftwareIdentity(platform, a).Fingerprint, receivedAt); err != nil {
				return written, decision, err
			}
			decision.UserScopesSeen.add(appID, user)
			if len(legacyRows) > 0 {
				legacySightings[identifier] = append(legacySightings[identifier],
					legacyUserSighting{appID: appID, user: user, path: a.Path})
			}
		}

		// PAT-806: feed the tenant-agnostic known_app_bundles table whenever
		// this sighting carries a usable on-disk path. Runs in the same
		// transaction as the device_apps write above, so a failure here aborts
		// the whole ingest exactly like any other upsert failure in this loop.
		if kabPath := strings.TrimSpace(a.Path); kabPath != "" {
			if err := upsertKnownAppBundle(ctx, tx, name, platform, kabPath); err != nil {
				return written, decision, err
			}
		}

		written++
	}

	// PAT-2075: resolve the legacy user-located rows before any prune. The
	// rows left held are excluded from every machine-wide prune below,
	// whatever the machine-wide signal.
	if err := resolveLegacyUserRows(ctx, tx, deviceID, legacyHold, legacyRows, legacySightings, machineIDs, &decision); err != nil {
		return written, decision, err
	}

	// PAT-2075: per-user scopes first, on their own authority. Order does
	// not change the outcome: a row is deleted only once neither scope
	// asserts it.
	if err := pruneCompleteUserScopes(ctx, tx, deviceID, completeUsers, decision.UserScopesSeen, &decision); err != nil {
		return written, decision, err
	}

	vanished, reconfirmed, err := countVanishedIdentifiers(ctx, tx, deviceID, machineIDs)
	if err != nil {
		return written, decision, err
	}
	decision.Removed = vanished
	switch signal {
	case appsSignalComplete:
		// Explicit authority: prune whatever was not reconfirmed.
	case appsSignalIncomplete:
		// No prune at all, not even superseded versions: the agent says it
		// did not read everything, so a side-by-side copy of a reported
		// identifier (two Xcodes share one bundle id) may be the part it
		// missed. The agent's next complete report prunes normally.
		decision.Reason = withheldReason
		return written, decision, nil
	default:
		if appsValveHolds(current, vanished, reconfirmed) {
			if err := pruneSupersededApps(ctx, tx, deviceID, machineIDs, &decision); err != nil {
				return written, decision, err
			}
			// Time release (ratio case only): a report that reconfirms
			// nothing never deletes anything, however old the rows are.
			if reconfirmed > 0 {
				if err := pruneLongUnseenApps(ctx, tx, deviceID, receivedAt, machineIDs, &decision); err != nil {
					return written, decision, err
				}
			}
			// Scopes stay withheld for this ingest either way (Pruned is
			// false). Reason, and with it the metric and warning, is set
			// only when something recently seen is still held back.
			if decision.Removed > decision.Released {
				decision.Reason = "safety_valve"
			}
			return written, decision, nil
		}
	}

	// Prune stale machine-wide rows: every machine-wide row this report
	// listed is in machineIDs, so any other machine-wide row belongs to a
	// prior scan that this one didn't reconfirm. PAT-2075: its machine-wide
	// assertion is dropped, and the row deleted unless a per-user scope
	// still holds it. Deleting inside the same transaction as the rest of
	// the ingest means readers never observe a half-updated inventory (no
	// window where old and new rows coexist).
	if _, _, err := releaseMachineRows(ctx, tx, deviceID, machineIDs, decision.LegacyHeld, ""); err != nil {
		return written, decision, fmt.Errorf("prune stale device_apps for device %s: %w", deviceID, err)
	}
	decision.Pruned = true

	return written, decision, nil
}

// upsertKnownAppBundle upserts one (name, platform) -> app_path mapping into
// known_app_bundles (PAT-806): a tenant-agnostic table auto-populated from
// every tenant's inventory scans, distinct from the manually-curated
// EULA/mirror Catalogue. first_seen_at is immutable across conflicts;
// app_path and last_seen_at refresh on every sighting so a vendor's bundle
// rename eventually supersedes the old path. No expiry/pruning here by
// design -- the consuming shell script verifies the path exists on disk
// before trusting it, so a stale row just silently fails to resolve.
func upsertKnownAppBundle(ctx context.Context, tx pgx.Tx, name, platform, appPath string) error {
	// Conflict target is (LOWER(name), platform) -- matching the unique index
	// known_app_bundles_name_platform_uq (migration 0076), NOT a plain
	// (name, platform) PK. Two sightings of the same app whose reported
	// display-name casing differs (e.g. "Zoom" vs "zoom") must collapse to
	// one row: the reader (GET /v1/allowlist/pending-removals) joins
	// case-insensitively, so a case-sensitive write-side key would let two
	// rows coexist and the join would return both as duplicate items.
	_, err := tx.Exec(ctx, `
		INSERT INTO known_app_bundles (name, platform, app_path, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, now(), now())
		ON CONFLICT (LOWER(name), platform) DO UPDATE SET
			app_path     = EXCLUDED.app_path,
			last_seen_at = now()
	`, name, platform, appPath)
	if err != nil {
		return fmt.Errorf("upsert known_app_bundle %q/%q: %w", name, platform, err)
	}
	return nil
}

// upsertPatches writes the device's macOS update history from
// `softwareupdate --history`. Each (device_id, identifier) pair is unique;
// re-ingests refresh observed_at and the title but do not change installed_at.
// Identifier is "<name>|<version>" — a single name like "Safari" appears
// multiple times in the history, once per version.
//
// Apps where name is empty are skipped — without a usable identifier we'd
// generate dupes on every run.
func upsertPatches(ctx context.Context, tx pgx.Tx, deviceID string, patches []patchPart) (int, error) {
	if len(patches) == 0 {
		return 0, nil
	}

	const stmt = `
		INSERT INTO patches (device_id, identifier, title, installed_at, observed_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (device_id, identifier) DO UPDATE SET
			title       = EXCLUDED.title,
			installed_at = COALESCE(patches.installed_at, EXCLUDED.installed_at),
			observed_at = now()
	`

	written := 0
	for _, p := range patches {
		name := strings.TrimSpace(p.Name)
		version := strings.TrimSpace(p.Version)
		if name == "" {
			continue
		}
		identifier := name
		if version != "" {
			identifier = name + "|" + version
		}
		var installedAt any
		if p.InstalledAt != nil && *p.InstalledAt != "" {
			installedAt = *p.InstalledAt
		}
		if _, err := tx.Exec(ctx, stmt, deviceID, identifier, name, installedAt); err != nil {
			return written, fmt.Errorf("upsert patch %q: %w", identifier, err)
		}
		written++
	}
	return written, nil
}

// buildSignalsMap renders the payload's compliance bag (plus the synthetic
// icloud_signed_in key) into the flat map the evaluator and insertComplianceSignals
// both consume. Pulled out so the two paths see identical key/value pairs —
// any drift between "what we evaluated" and "what we stored" would be
// debugging hell. logger may be nil (falls back to slog.Default()); it is only
// used to warn about reserved-namespace violations skipped below.
//
// Reserved-namespace partition (PAT-913, gate rounds 2-3). The finding-control
// IDs (finding_controls.go, mirroring the docs/payload.schema.json authority)
// are a reserved namespace across the three payload sources that write into
// this map:
//
//   - the free-form compliance bag may write only NON-reserved keys;
//   - compliance_findings may write only reserved keys (Fail state);
//   - controls_assessed may write only reserved keys (Pass state).
//
// This makes the finding/attestation semantics independent of bag contents in
// either loop order: a bag key can never occupy a finding-control slot.
// Without the bag guard, compliance:{"disk_encryption_off":"Pass"} would
// pre-seat a forged Pass that the attestation loop's already-present check
// then leaves untouched — the evaluator would pass the critical rule with no
// attestation at all. ValidatePayload rejects all three violation shapes at
// ingestion; the guards here cover raw_payloads rows ingested before that
// enforcement existed (or via any future bypass) and replayed through
// re-extraction.
func buildSignalsMap(p *payload, logger *slog.Logger) map[string]string {
	if logger == nil {
		logger = slog.Default()
	}
	out := make(map[string]string, len(p.Compliance)+len(p.ComplianceFindings)+len(p.ComplianceAssessments.ControlsAssessed)+1)
	for k, v := range p.Compliance {
		if isFindingControlID(k) {
			logger.Warn("skipping reserved finding-control key in compliance bag",
				"key", k)
			continue
		}
		s, ok := renderJSONValue(v)
		if !ok {
			continue
		}
		out[k] = s
	}
	// Findings + attestation semantics (PAT-913, Option B). A findings-based
	// signal is only ever emitted when a control is *violated*; a clean control
	// is reported by its ABSENCE from compliance_findings, not by a value. That
	// makes "signal absent" ambiguous on its own — it could mean "assessed,
	// clean" or "never assessed". We resolve it with the agent's explicit
	// compliance_assessments.controls_assessed list (the positive attestation)
	// rather than inferring anything from the findings array:
	//   - flagged (has a finding)  → "Fail" (or the volumes JSON for PAT-481)
	//   - attested + not flagged   → positive "Pass"
	//   - not attested (control absent from controls_assessed) → no key at all;
	//     the evaluator then applies treat_unknown_as (now 'fail' for the
	//     critical finding rules, migration 0083).
	//
	// A finding is always a finding: a violation scores Fail whether or not the
	// control was also named in controls_assessed. controls_assessed is the ONLY
	// source of Pass, so an agent that emits findings but no assessment section
	// (every agent deployed before PAT-913) can never produce a false Pass on a
	// critical control — it simply falls through to fail-unknown.
	for _, f := range p.ComplianceFindings {
		if f.ID == "" {
			continue
		}
		// Namespace partition: a finding may only write a reserved
		// finding-control key. An out-of-enum ID could otherwise force a
		// Fail-state value onto an arbitrary rule signal (score-lowering, not
		// fail-open, but still a forgery) or clobber a legitimate bag key.
		if !isFindingControlID(f.ID) {
			logger.Warn("skipping out-of-enum compliance_findings entry",
				"id", f.ID)
			continue
		}
		// A present finding is a "Fail" state. For findings with detailed
		// context (volumes in PAT-481) store the JSON so it can be surfaced in
		// ObservedValue.
		if len(f.Volumes) > 0 && string(f.Volumes) != "null" {
			out[f.ID] = string(f.Volumes)
		} else {
			out[f.ID] = "Fail"
		}
	}
	// Positive attestation: for every control the agent says it actually
	// assessed and did not flag, record an explicit "Pass". This is what lets a
	// genuinely-clean attesting device pass while an unattested control (never
	// in the list) falls through to treat_unknown_as = 'fail'.
	//
	// Belt-and-braces (PAT-913 gate round 2): only IDs in the shared
	// finding-control enum (finding_controls.go, mirroring the
	// docs/payload.schema.json authority) may mint a Pass. ValidatePayload
	// already rejects out-of-enum entries at ingestion, but raw_payloads may
	// hold rows ingested before that enforcement existed (or via any future
	// validation bypass), and re-extraction replays them through here — so an
	// unknown ID is skipped with a warn rather than trusted. Without this, an
	// attacker-controlled controls_assessed could fabricate a Pass for ANY
	// signal key (filevault, defender_realtime, ...).
	for _, control := range p.ComplianceAssessments.ControlsAssessed {
		if control == "" {
			continue
		}
		if !isFindingControlID(control) {
			logger.Warn("skipping out-of-enum controls_assessed entry",
				"control", control)
			continue
		}
		if _, flagged := out[control]; !flagged {
			out[control] = "Pass"
		}
	}
	if p.ICloud.SignedIn != "" {
		out["icloud_signed_in"] = p.ICloud.SignedIn
	}
	return out
}

// insertComplianceSignals appends one row per non-null compliance key from the
// payload. Append-only by design — every collection lands a row, the historical
// series is the audit trail.
func insertComplianceSignals(ctx context.Context, tx pgx.Tx, deviceID string, signals map[string]string, observedAt any) (int, error) {
	if len(signals) == 0 {
		return 0, nil
	}

	rows := make([][]any, 0, len(signals))
	for k, v := range signals {
		rows = append(rows, []any{deviceID, k, v, observedAt})
	}

	// One multi-row COPY keeps round-trips down. compliance_signals.severity
	// is left NULL here — the rule engine writes its severity verdict into
	// compliance_evaluations instead, which is the dashboard-friendly side.
	copyCount, err := tx.CopyFrom(ctx,
		pgx.Identifier{"compliance_signals"},
		[]string{"device_id", "key", "value", "observed_at"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return 0, fmt.Errorf("insert compliance_signals: %w", err)
	}
	return int(copyCount), nil
}

// insertEvaluations writes the rule-engine output. One row per (device, rule)
// per ingest — append-only, same audit-trail discipline as compliance_signals.
func insertEvaluations(ctx context.Context, tx pgx.Tx, deviceID string, evals []eval, evaluatedAt any) (int, error) {
	if len(evals) == 0 {
		return 0, nil
	}

	rows := make([][]any, 0, len(evals))
	for _, e := range evals {
		rows = append(rows, []any{
			deviceID, e.ruleID, e.status, e.observedValue, e.severity, e.benchmarkVersion, evaluatedAt,
		})
	}

	copyCount, err := tx.CopyFrom(ctx,
		pgx.Identifier{"compliance_evaluations"},
		[]string{"device_id", "rule_id", "status", "observed_value", "severity", "benchmark_version", "evaluated_at"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return 0, fmt.Errorf("insert compliance_evaluations: %w", err)
	}
	return int(copyCount), nil
}

// markArtefactsApplied is PAT-1549's auto-detection hook: it flips
// remediation_artefacts.status from 'issued' to 'applied' for every rule
// that just evaluated to 'pass' in this ingest, but only for the CURRENT
// artefact of that (device, rule) pair — a row nothing else's supersedes_id
// points at. A superseded artefact is left exactly as it was; only the tip
// of the supersession chain can ever become 'applied'. Runs in the same
// transaction as insertEvaluations so an artefact can never read 'applied'
// without a passing evaluation actually on record to justify it (root
// AGENTS.md "evidence before actuation" / "absence requires authority" —
// this is the positive-evidence side of that same discipline: only an
// observed pass, never an absence of a later fail, marks an artefact
// applied).
//
// Returns the number of artefacts marked applied (0 is the common case —
// most ingests carry no rule that was both failing-with-an-issued-artefact
// and now passing).
func markArtefactsApplied(ctx context.Context, tx pgx.Tx, deviceID string, evals []eval, observedAt time.Time) (int, error) {
	var passingRuleIDs []string
	for _, e := range evals {
		if e.status == "pass" {
			passingRuleIDs = append(passingRuleIDs, e.ruleID)
		}
	}
	if len(passingRuleIDs) == 0 {
		return 0, nil
	}

	tag, err := tx.Exec(ctx, `
		UPDATE remediation_artefacts a
		SET status = 'applied',
		    applied_observed_at = $3
		WHERE a.device_id = $1::uuid
		  AND a.rule_id = ANY($2::uuid[])
		  AND a.status = 'issued'
		  AND NOT EXISTS (
		      SELECT 1 FROM remediation_artefacts b WHERE b.supersedes_id = a.id
		  )
	`, deviceID, passingRuleIDs, observedAt)
	if err != nil {
		return 0, fmt.Errorf("mark remediation artefacts applied: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// eval is a lightweight, pgx-friendly view of evaluator.Evaluation — pulled
// into the extractor package so upsert.go doesn't need to import the
// evaluator package (which would create a cycle once the evaluator grows).
type eval struct {
	ruleID           string
	status           string
	observedValue    any // *string in evaluator; nil here when signal was absent
	severity         string
	benchmarkVersion string
}

// renderJSONValue turns a json.RawMessage into the string form
// compliance_signals.value expects. Returns false when the value is JSON null
// (caller should skip the row).
func renderJSONValue(v json.RawMessage) (string, bool) {
	t := strings.TrimSpace(string(v))
	if t == "" || t == "null" {
		return "", false
	}
	// JSON string → strip quotes via Unmarshal (handles escape sequences).
	if t[0] == '"' {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s, true
		}
		// Fall through and return the raw form if Unmarshal somehow fails.
	}
	return t, true
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullIfPlaceholder treats common "Unknown" placeholders as SQL NULL so the
// devices_apps columns stay clean — `signer = 'Unknown'` is a worse query
// experience than `signer IS NULL`.
func nullIfPlaceholder(s string) any {
	if s == "" || s == "Unknown" {
		return nil
	}
	return s
}

// upsertOSUpdate persists the os_update verdict to device_os_update
// (PAT-1806, migration 0144; checked_at added by migration 0147, PAT-1862).
// One row per device, upserted — current-state snapshot, same pattern as
// device_hardware, not an append-only history.
//
// o == nil (key absent, JSON null, or malformed — see parseOSUpdate) is a
// no-op: no INSERT/UPDATE at all, so a previously-stored row is left exactly
// as it was. This is the same COALESCE-preserve discipline pending_updates,
// hardware, and backup_status already get in upsertDevice — an agent that
// has never heard of this field must behave exactly as it does today, and a
// device that once reported a verdict must not have it zeroed by a later
// payload that simply doesn't carry the block (e.g. an unrelated retry from
// an older cached agent binary).
//
// deadline and checked_at are parsed as RFC3339 when present. Live ingestion
// rejects a malformed checked_at before raw persistence, but extraction stays
// defensive for legacy or replay payloads that bypassed that current gate: an
// unparseable value is logged and stored as SQL NULL rather than crashing the
// row. An unparseable deadline follows the same posture.
func upsertOSUpdate(ctx context.Context, tx pgx.Tx, deviceID string, o *osUpdatePart, logger *slog.Logger) error {
	if o == nil {
		return nil
	}

	var deadlineArg any
	if o.Deadline != nil {
		t, err := time.Parse(time.RFC3339, *o.Deadline)
		if err != nil {
			if logger != nil {
				logger.Warn("os_update: deadline did not parse as RFC3339; storing NULL",
					"device_id", deviceID, "deadline_raw", *o.Deadline, "err", err)
			}
		} else {
			deadlineArg = t
		}
	}

	var checkedAtArg any
	if o.CheckedAt != "" {
		t, err := time.Parse(time.RFC3339, o.CheckedAt)
		if err != nil {
			if logger != nil {
				logger.Warn("os_update: checked_at did not parse as RFC3339; storing NULL",
					"device_id", deviceID, "checked_at_raw", o.CheckedAt, "err", err)
			}
		} else {
			checkedAtArg = t
		}
	}

	var latestOSArg any
	if o.LatestOS != nil {
		latestOSArg = *o.LatestOS
	}

	// targetOSArg (PAT-2123): nil when the payload's target_os was absent or
	// explicit null — Windows Update reporting a pending update ahead of
	// resolving its target build. Bound as untyped nil so pgx writes SQL
	// NULL, not the empty string. Deliberately NOT wrapped in a
	// COALESCE(target_os, device_os_update.target_os)-style preserve: unlike
	// o == nil (the whole os_update block absent, handled by the early
	// return above, which correctly leaves any existing row untouched), this
	// is a report where the block IS present but the agent is explicitly
	// saying "no known target right now" — that must clear a stale target,
	// not keep it, so a portal reading NULL never shows a version that no
	// longer describes reality. The EXCLUDED.target_os assignment below is
	// already a plain overwrite, not a COALESCE, so this falls out for free.
	var targetOSArg any
	if o.TargetOS != nil {
		targetOSArg = *o.TargetOS
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO device_os_update (
			device_id, installed_os, latest_os, target_os, state, severity,
			security_relevant, actively_exploited, deferrals_remaining,
			release_age_days, deadline, checked_at, reported_at
		) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
		ON CONFLICT (device_id) DO UPDATE SET
			installed_os         = EXCLUDED.installed_os,
			latest_os            = EXCLUDED.latest_os,
			target_os            = EXCLUDED.target_os,
			state                = EXCLUDED.state,
			severity             = EXCLUDED.severity,
			security_relevant    = EXCLUDED.security_relevant,
			actively_exploited   = EXCLUDED.actively_exploited,
			deferrals_remaining  = EXCLUDED.deferrals_remaining,
			release_age_days     = EXCLUDED.release_age_days,
			deadline             = EXCLUDED.deadline,
			checked_at           = EXCLUDED.checked_at,
			reported_at          = now()
	`, deviceID, o.InstalledOS, latestOSArg, targetOSArg, o.State, o.Severity,
		o.SecurityRelevant, o.ActivelyExploited, o.DeferralsRemaining,
		o.ReleaseAgeDays, deadlineArg, checkedAtArg,
	); err != nil {
		return fmt.Errorf("upsert device_os_update: %w", err)
	}
	return nil
}

// upsertHardwareHealth persists the hardware_health snapshot to the three
// hardware tables. Per-section semantics driven by collection_status
// (PAT-1720), independently for battery/storage/disks — absent
// collection_status, or an absent key within it, means "complete" and
// reproduces the historical behaviour exactly:
//
//   - nil pointer (key absent in payload) → no-op; leave existing rows.
//   - section "complete" (or status absent) → today's behaviour: battery
//     columns overwritten, history recorded; storage/disks replaced in full
//     (DELETE + INSERT), even when the array is empty.
//   - section "partial" → battery: stored values kept, no history row.
//     storage/disks: upsert only the rows sent (matched by mount / device
//     node), delete nothing.
//   - section "unavailable" → battery: stored values kept, no history row.
//     storage/disks: write nothing at all — a failed collection must never
//     be read as authority that the volumes/disks are gone.
//
// An unrecognised collection_status value is logged and treated as
// "unavailable", never "complete" — see normaliseHWCollectionStatus.
//
// All writes run inside the caller's transaction.
// Returns the total count of storage + disk rows written or updated (0 on
// no-op, and 0 for any section reported "unavailable").
//
// platform is the payload's already-normalised platform ("macos" or
// "windows", extractor.go's `platform` variable — the same value upsertApps
// takes for its own platform-conditional behaviour). It gates the PAT-1736
// one-off in the disks "partial" branch below: see pruneStaleFriendlyNameDisks.
func upsertHardwareHealth(ctx context.Context, tx pgx.Tx, deviceID, platform string, h *hardwareHealthPart, logger *slog.Logger) (int, error) {
	if h == nil {
		return 0, nil
	}

	battStatus, battKnown := normaliseHWCollectionStatus(hwSectionStatus(h.CollectionStatus, "battery"))
	storageStatus, storageKnown := normaliseHWCollectionStatus(hwSectionStatus(h.CollectionStatus, "storage"))
	disksStatus, disksKnown := normaliseHWCollectionStatus(hwSectionStatus(h.CollectionStatus, "disks"))

	if logger != nil {
		if !battKnown {
			logger.Warn("hardware_health: unrecognised collection_status.battery; treating as unavailable",
				"device_id", deviceID, "collection_status_raw", hwSectionStatus(h.CollectionStatus, "battery"))
		}
		if !storageKnown {
			logger.Warn("hardware_health: unrecognised collection_status.storage; treating as unavailable",
				"device_id", deviceID, "collection_status_raw", hwSectionStatus(h.CollectionStatus, "storage"))
		}
		if !disksKnown {
			logger.Warn("hardware_health: unrecognised collection_status.disks; treating as unavailable",
				"device_id", deviceID, "collection_status_raw", hwSectionStatus(h.CollectionStatus, "disks"))
		}
		for section, status := range map[string]hwCollectionStatus{
			"battery": battStatus, "storage": storageStatus, "disks": disksStatus,
		} {
			if status != hwStatusComplete {
				logger.Info("hardware_health: collection degraded for section",
					"device_id", deviceID, "section", section, "status", string(status))
			}
		}
	}

	battComplete := battStatus == hwStatusComplete

	var hwID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO device_hardware (
			device_id,
			battery_present, battery_cycle_count, battery_condition, battery_max_capacity_pct,
			collected_at
		) VALUES ($1::uuid, $2, $3, $4, $5, now())
		ON CONFLICT (device_id) DO UPDATE SET
			battery_present          = CASE WHEN $6 THEN EXCLUDED.battery_present          ELSE device_hardware.battery_present          END,
			battery_cycle_count      = CASE WHEN $6 THEN EXCLUDED.battery_cycle_count      ELSE device_hardware.battery_cycle_count      END,
			battery_condition        = CASE WHEN $6 THEN EXCLUDED.battery_condition        ELSE device_hardware.battery_condition        END,
			battery_max_capacity_pct = CASE WHEN $6 THEN EXCLUDED.battery_max_capacity_pct ELSE device_hardware.battery_max_capacity_pct END,
			collected_at             = now()
		RETURNING id
	`, deviceID,
		h.Battery.Present, h.Battery.CycleCount, h.Battery.Condition, h.Battery.MaxCapacityPct,
		battComplete,
	).Scan(&hwID); err != nil {
		return 0, fmt.Errorf("upsert device_hardware: %w", err)
	}

	// Battery trend history (PAT-686): one row per device per day; same-day
	// re-extractions refresh today's row. Only devices that report a battery
	// with at least one readable metric — present-but-unreadable batteries
	// would only add all-NULL rows that look like tracked data. Skipped
	// entirely when battery collection was not complete: a partial/
	// unavailable reading must never be recorded as a battery change.
	if battComplete && h.Battery.Present &&
		(h.Battery.CycleCount != nil || h.Battery.Condition != nil || h.Battery.MaxCapacityPct != nil) {
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_hardware_history
				(device_id, recorded_on, battery_cycle_count, battery_condition, battery_max_capacity_pct)
			VALUES ($1::uuid, CURRENT_DATE, $2, $3, $4)
			ON CONFLICT (device_id, recorded_on) DO UPDATE SET
				battery_cycle_count      = EXCLUDED.battery_cycle_count,
				battery_condition        = EXCLUDED.battery_condition,
				battery_max_capacity_pct = EXCLUDED.battery_max_capacity_pct
		`, deviceID, h.Battery.CycleCount, h.Battery.Condition, h.Battery.MaxCapacityPct); err != nil {
			return 0, fmt.Errorf("insert device_hardware_history: %w", err)
		}
	}

	written := 0

	switch storageStatus {
	case hwStatusComplete:
		// Replace storage snapshot in full.
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_storage_volume WHERE device_hardware_id = $1`, hwID,
		); err != nil {
			return 0, fmt.Errorf("prune storage volumes: %w", err)
		}
		for _, v := range h.Storage {
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_storage_volume (device_hardware_id, mount, total_bytes, free_bytes, used_pct)
				VALUES ($1, $2, $3, $4, $5)
			`, hwID, v.Mount, v.TotalBytes, v.FreeBytes, v.UsedPct); err != nil {
				return 0, fmt.Errorf("insert storage volume %q: %w", v.Mount, err)
			}
			written++
		}
	case hwStatusPartial:
		// Upsert only what was sent; delete nothing. There is no unique
		// constraint on (device_hardware_id, mount) to ON CONFLICT against
		// (migrations/0014_device_hardware.sql), so match-then-write inside
		// this transaction, which is safe against a self-race because the
		// caller holds one connection for the whole extraction.
		for _, v := range h.Storage {
			var existingID int64
			err := tx.QueryRow(ctx,
				`SELECT id FROM device_storage_volume WHERE device_hardware_id = $1 AND mount = $2`,
				hwID, v.Mount,
			).Scan(&existingID)
			switch {
			case err == nil:
				if _, err := tx.Exec(ctx, `
					UPDATE device_storage_volume SET total_bytes = $1, free_bytes = $2, used_pct = $3
					WHERE id = $4
				`, v.TotalBytes, v.FreeBytes, v.UsedPct, existingID); err != nil {
					return 0, fmt.Errorf("update storage volume %q: %w", v.Mount, err)
				}
			case errors.Is(err, pgx.ErrNoRows):
				if _, err := tx.Exec(ctx, `
					INSERT INTO device_storage_volume (device_hardware_id, mount, total_bytes, free_bytes, used_pct)
					VALUES ($1, $2, $3, $4, $5)
				`, hwID, v.Mount, v.TotalBytes, v.FreeBytes, v.UsedPct); err != nil {
					return 0, fmt.Errorf("insert storage volume %q: %w", v.Mount, err)
				}
			default:
				return 0, fmt.Errorf("look up storage volume %q: %w", v.Mount, err)
			}
			written++
		}
	case hwStatusUnavailable:
		// Write nothing at all — even a non-empty array is ignored. Existing
		// rows are left exactly as they were.
	}

	switch disksStatus {
	case hwStatusComplete:
		// Replace disk snapshot in full.
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_disk WHERE device_hardware_id = $1`, hwID,
		); err != nil {
			return 0, fmt.Errorf("prune disks: %w", err)
		}
		for _, d := range h.Disks {
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_disk (device_hardware_id, device_node, smart_status, internal, solid_state)
				VALUES ($1, $2, $3, $4, $5)
			`, hwID, d.Device, d.SmartStatus, d.Internal, d.SolidState); err != nil {
				return 0, fmt.Errorf("insert disk %q: %w", d.Device, err)
			}
			written++
		}
	case hwStatusPartial:
		// PAT-1736 one-off: on a Windows device's first-ever ingest of a
		// hardware_health.collection_status.disks value, prune stale
		// FriendlyName-keyed rows left behind by the PAT-1733 device_node key
		// change before upserting this payload's serial/UniqueId-keyed rows
		// below. Runs at most once per device — see pruneStaleFriendlyNameDisks.
		if platform == "windows" {
			stored, err := loadStoredCollectionStatus(ctx, tx, deviceID, logger)
			if err != nil {
				return 0, err
			}
			firstDisksIngest := stored.HardwareHealth == nil || stored.HardwareHealth.Disks == ""
			if firstDisksIngest {
				if err := pruneStaleFriendlyNameDisks(ctx, tx, deviceID, hwID, h.Disks, logger); err != nil {
					return 0, err
				}
			}
		}
		// Upsert only what was sent; delete nothing. Same no-unique-constraint
		// situation as storage — match on device_node inside the transaction.
		for _, d := range h.Disks {
			var existingID int64
			err := tx.QueryRow(ctx,
				`SELECT id FROM device_disk WHERE device_hardware_id = $1 AND device_node = $2`,
				hwID, d.Device,
			).Scan(&existingID)
			switch {
			case err == nil:
				if _, err := tx.Exec(ctx, `
					UPDATE device_disk SET smart_status = $1, internal = $2, solid_state = $3
					WHERE id = $4
				`, d.SmartStatus, d.Internal, d.SolidState, existingID); err != nil {
					return 0, fmt.Errorf("update disk %q: %w", d.Device, err)
				}
			case errors.Is(err, pgx.ErrNoRows):
				if _, err := tx.Exec(ctx, `
					INSERT INTO device_disk (device_hardware_id, device_node, smart_status, internal, solid_state)
					VALUES ($1, $2, $3, $4, $5)
				`, hwID, d.Device, d.SmartStatus, d.Internal, d.SolidState); err != nil {
					return 0, fmt.Errorf("insert disk %q: %w", d.Device, err)
				}
			default:
				return 0, fmt.Errorf("look up disk %q: %w", d.Device, err)
			}
			written++
		}
	case hwStatusUnavailable:
		// Write nothing at all — even a non-empty array is ignored. Existing
		// rows are left exactly as they were.
	}

	return written, nil
}

// pruneStaleFriendlyNameDisks (PAT-1736) removes device_disk rows keyed by
// the pre-PAT-1733 Windows FriendlyName device_node (e.g. "Samsung SSD 980
// PRO 1TB", "Msft Virtual Disk", "QEMU NVMe Ctrl") once, on the first ingest
// that ever reports a hardware_health.collection_status.disks value for this
// device.
//
// Background: PAT-1733 changed the Windows agent's disks[].device key from
// FriendlyName to the trimmed MSFT_PhysicalDisk.SerialNumber (falling back
// to the trimmed UniqueId) — see updater
// windows/src/Shared/HardwareHealth/HardwareHealthLogic.DiskDeviceKey. A
// device whose disks section is "complete" self-heals every ingest via the
// full DELETE+INSERT replace in the hwStatusComplete branch above, which
// already clears any FriendlyName-keyed row. A device whose disks section
// goes straight to "partial" (e.g. one virtual disk with an undetermined
// MediaType, which HardwareHealthLogic.BuildDisks always leaves out) never
// gets that full replace — the partial branch only upserts rows the payload
// actually sent, matched by device_node — so the old FriendlyName row sits
// forever beside the new serial-keyed row for that disk (PAT-1736).
//
// The caller (the hwStatusPartial case above) runs this only for platform ==
// "windows" and only when the device's stored devices.collection_status has
// never recorded a hardware_health.disks status before this ingest — see
// loadStoredCollectionStatus. That makes this a true one-off: after this
// ingest, upsertCollectionStatus (called later in the same transaction by
// extractor.go's processRow) stores a non-empty disks status for the
// device, so every later ingest — partial or otherwise — sees a non-empty
// stored value and this function is not called again.
//
// The stale-row rule is deliberately conservative rather than exact: delete
// a stored device_node only when it is NOT one of the keys this payload's
// disks array carries, AND it contains whitespace. FriendlyName values
// always contain spaces; SerialNumber/UniqueId values are trimmed at both
// ends by the collector (HardwareHealthLogic.NormaliseDiskId) but not
// stripped of internal whitespace, so a real serial containing an internal
// space that this partial payload does not itself report could in theory be
// misidentified and deleted. This residual risk is accepted rather than
// grounds to skip the one-off — see the PAT-1736 implementation report for
// the full reasoning — because leaving the FriendlyName row in place forever
// is the defect this function exists to fix.
func pruneStaleFriendlyNameDisks(ctx context.Context, tx pgx.Tx, deviceID string, hwID int64, disks []diskPart, logger *slog.Logger) error {
	// A partial ingest that reports no disks at all carries no replacement
	// evidence: `device_node <> ALL('{}')` is true for every row, so pruning
	// here would delete every FriendlyName row with nothing keyed in its
	// place. Keep the stale row rather than claim the disk absent.
	if len(disks) == 0 {
		return nil
	}
	keys := make([]string, 0, len(disks))
	for _, d := range disks {
		keys = append(keys, d.Device)
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM device_disk
		WHERE device_hardware_id = $1
		  AND device_node <> ALL($2::text[])
		  AND device_node ~ '\s'
	`, hwID, keys)
	if err != nil {
		return fmt.Errorf("prune stale FriendlyName-keyed disks for device %s: %w", deviceID, err)
	}
	if logger != nil && tag.RowsAffected() > 0 {
		logger.Info("hardware_health: pruned stale FriendlyName-keyed disk rows on first collection_status.disks ingest",
			"device_id", deviceID, "rows_deleted", tag.RowsAffected())
	}
	return nil
}

// browserExtRiskLevel computes a risk_level for one extension's permission set.
// Returns "elevated" when the extension has broad host access (see
// isBroadHostPermission) and/or holds sensitive API permissions (tabs,
// cookies, webRequest/webRequestBlocking, scripting, history, downloads).
// Returns "normal" otherwise.
//
// The rule lives here so it is easy to tune without touching the upsert SQL.
// Both conditions independently trigger elevation — broad host access OR
// sensitive permissions, not just the combination.
//
// TODO(PAT-125): malicious-extension feed cross-reference — source TBD.
func browserExtRiskLevel(perms, hostPerms []string) string {
	for _, h := range hostPerms {
		if isBroadHostPermission(h) {
			return "elevated"
		}
	}
	sensitivePerms := map[string]struct{}{
		"tabs": {}, "cookies": {}, "webRequest": {}, "webRequestBlocking": {},
		"scripting": {}, "history": {}, "downloads": {}, "<all_urls>": {},
	}
	for _, p := range perms {
		if _, ok := sensitivePerms[p]; ok {
			return "elevated"
		}
	}
	return "normal"
}

// isBroadHostPermission reports whether one host_permissions entry grants
// access broad enough to count as "elevated" for browserExtRiskLevel,
// classifying by breadth rather than by "does it contain a wildcard
// character" (PAT-2076). The plain wildcard-character test used before this
// change flagged a narrow single-site pattern like "https://*.example.com/*"
// identically to "<all_urls>", which is wrong today and would misclassify
// most Firefox extensions once Firefox host permissions start arriving
// (PAT-2073 on the agent side) — Firefox manifests routinely list a single
// registrable domain as "*://*.example.com/*" where Chrome/Edge extensions
// asking for the same single-site access rarely bother with the wildcard at
// all. The rule below applies identically to every browser: it looks only at
// the shape of the pattern, never which browser sent it.
//
// Broad (returns true):
//   - "<all_urls>" (case-insensitive on the literal token, matching the
//     leniency already used for API permission string "<all_urls>" below).
//   - a `file://` scheme pattern. Local file access was NOT previously
//     treated specially — the old rule only caught it if the path also
//     happened to contain a "*" — so this also strengthens an existing gap
//     rather than only splitting the wildcard case.
//   - a pattern whose host component is "*" alone, e.g. "*://*/*",
//     "http://*/*", "https://*/*", "*://*": every site, on that scheme.
//   - a "*.<domain>" wildcard host where <domain> IS a public suffix (no
//     registrable label under it), e.g. "*.com", "*.co.uk", "https://*.*/*".
//     Classified with golang.org/x/net/publicsuffix (already a direct
//     module dependency — see internal/oscve/apple.go — so this adds no new
//     dependency): a wildcard is broad exactly when the domain part IS its
//     own public suffix (nothing left to register under it), and NOT broad
//     when the wildcard sits on a registrable domain within some suffix
//     (e.g. "*.example.com" -> public suffix "com" != "example.com" ->
//     narrow; "*.co.uk" -> public suffix "co.uk" == "co.uk" -> broad). This
//     is a full data-driven public suffix list rather than a hardcoded
//     handful of multi-label TLDs, so "co.uk"/"com.au"/etc. are handled
//     without a maintained list.
//   - a wildcard appearing anywhere in the host OTHER than as a "*."
//     subdomain prefix (e.g. a mid-label wildcard). This shape is not one
//     the classifier above can confidently read as domain-scoped, so it is
//     conservatively treated as broad rather than silently under-flagged.
//   - a pattern this function cannot parse into scheme/host (empty string,
//     no discernible host after stripping scheme/path/port). Malformed
//     input is treated as broad: a risk signal that fails open (never flags)
//     on unparseable input is worse than one that fails closed (over-flags),
//     since the whole point of risk_level is not to miss real broad access.
//
// NOT broad (returns false):
//   - a wildcard confined to one registrable domain: "https://*.example.com/*",
//     "*://*.google.com/*", including with an explicit port
//     ("https://*.example.com:8443/*").
//   - an explicit host with no wildcard at all, with or without a wildcard
//     path ("https://example.com/*").
func isBroadHostPermission(pattern string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return true // malformed/empty: conservative, see doc comment above
	}
	if strings.EqualFold(p, "<all_urls>") {
		return true
	}

	lower := strings.ToLower(p)
	host := lower
	if idx := strings.Index(lower, "://"); idx != -1 {
		scheme := lower[:idx]
		rest := lower[idx+3:]
		if scheme == "file" {
			return true
		}
		host = rest
		if slash := strings.Index(host, "/"); slash != -1 {
			host = host[:slash]
		}
	} else if slash := strings.Index(lower, "/"); slash != -1 {
		// A schemeless host pattern that still carries a path, e.g.
		// "*.example.com/*".
		host = lower[:slash]
	}

	// Strip a trailing port, e.g. "*.example.com:8443". Not IPv6-aware, but
	// host_permissions entries are domain patterns, not literal IPv6
	// addresses, so this is not a shape that needs handling here.
	if colon := strings.LastIndex(host, ":"); colon != -1 {
		host = host[:colon]
	}

	if host == "" {
		return true // malformed: scheme with no host at all, conservative
	}
	if host == "*" {
		return true
	}
	if strings.HasPrefix(host, "*.") {
		domain := host[2:]
		if domain == "" {
			return true
		}
		suffix, _ := publicsuffix.PublicSuffix(domain)
		return strings.EqualFold(suffix, domain)
	}
	if strings.Contains(host, "*") {
		return true
	}
	return false
}

// Field-length caps applied to browser_extensions entries at ingestion,
// BEFORE the values are used as the ON CONFLICT key or written to
// device_browser_extensions (PAT-933 gate round 6).
//
// Rounds 1-5 of the PAT-933 adversarial review capped portal_extensions.go's
// READ side (row counts, drill-down counts, and SQL LEFT() on the OUTPUT
// projection only — see internal/report/portal_extensions.go's file doc
// comment parts (a)-(e)). Round 6 correctly pointed out that the read-side
// LEFT() truncation is deliberately never applied to the ident CTE's GROUP
// BY columns (dbe.extension_id, dbe.browser) or the ORDER BY key
// (LOWER(i.name)) — truncating those would let two distinct long identities
// collide into one wrong aggregated row (see the read-side doc comment for
// that reasoning) — which means, prior to this fix, there was NO upper bound
// anywhere on how long a tenant could make extension_id/browser/name/version
// via its own agent uploads: device_browser_extensions stores them as plain
// unbounded `text`. A tenant could stay under the row-count cap
// (portalExtensionsMaxSourceRows) while still forcing Postgres to
// GROUP BY/ORDER BY arbitrarily large text values.
//
// Fixed at the write path (this function), not with another read-side patch:
// this is the one and only place device_browser_extensions is written
// (INSERT ... ON CONFLICT ... DO UPDATE), so a cap here is structural and
// benefits every read path over the table, not just the portal endpoint
// (e.g. the staff-side TenantExtensionPolicyScanHandler,
// internal/handlers/extension_policies.go, joins the same table with the
// same GROUP BY shape).
//
// Values chosen to match internal/report/portal_extensions.go's existing
// read-side display caps (portalExtensionsMaxIDLen=128,
// portalExtensionsMaxNameLen=256, portalExtensionsMaxBrowserLen=32,
// portalExtensionsMaxVersionLen=64) so a legitimate value is never truncated
// twice (once here, again for display) in a way that would make the two
// layers' caps look inconsistent. Duplicated as separate constants here
// rather than imported from internal/report: this codebase has no existing
// convention for constants shared across internal/extractor and
// internal/report, and a generously-sized, independently-declared cap is
// simpler than introducing new cross-package infrastructure for four
// integers. Keep these numerically aligned with report's constants if either
// changes.
//
// Collision-risk reasoning (why truncating is safe here despite these
// fields being part of the ON CONFLICT key): unlike the read side — where
// the full untruncated value is always available to keep as the identity
// and truncation is applied only to a copy used for display — at write time
// there is no equivalent option: the full value IS the unbounded thing this
// gate is complaining about, so the stored (and therefore ON CONFLICT'd)
// value must itself be bounded. Two distinct real extension IDs that happen
// to share an identical prefix at the cap length would collide into the
// same row after truncation. This is judged a genuinely negligible risk in
// practice: real extension IDs are short, fixed-format strings (Chrome/Edge:
// exactly 32 lowercase a-p characters; Firefox: a UUID or an
// `id@domain`-style string, typically well under 100 characters) — nothing
// in a legitimate browser's extension ecosystem produces IDs anywhere near
// 128 characters, let alone two distinct ones sharing a 128-character
// prefix. The 128/256/32/64 caps are generous multiples of realistic
// real-world lengths specifically so a genuine collision is practically
// impossible, while still establishing a hard ceiling that closes the
// round-6 finding.
const (
	extMaxBrowserLen     = 32  // matches report.portalExtensionsMaxBrowserLen
	extMaxIDLen          = 128 // matches report.portalExtensionsMaxIDLen
	extMaxNameLen        = 256 // matches report.portalExtensionsMaxNameLen
	extMaxVersionLen     = 64  // matches report.portalExtensionsMaxVersionLen
	extMaxUserAccountLen = 128 // no read-side counterpart — see below
	extMaxProfileLen     = 128 // no read-side counterpart — see below
)

// safariBrowser is the literal wire value the macOS agent sends for Safari
// app-extension rows, matching the literal comparisons already used
// elsewhere for this browser (e.g. internal/categorytag test fixtures,
// internal/handlers/extension_removals.go).
const safariBrowser = "safari"

// SafariSystemSentinel is the fixed, well-known value device_browser_extensions
// stores in user_account (and, when absent, profile) for a Safari row (PAT-2064).
//
// Safari extensions live in an app bundle, not a browser user profile, so the
// macOS agent has always sent browser_extensions rows for Safari with
// user_account: null (and no meaningful profile). device_browser_extensions
// declares both columns NOT NULL with no default (0018_device_browser_extensions.sql)
// and uses both as part of its ON CONFLICT key alongside browser/extension_id,
// so an empty value must become a single fixed non-empty string rather than
// SQL NULL (a constraint violation) or the row's own genuine empty string
// (nullIfEmpty would turn that back into NULL below). Every Safari row for a
// device therefore groups under one stable identity across ingests instead of
// being silently dropped by browserExtValid, which is what PAT-871's guard
// did to every Safari row before this fix — Safari never reached
// device_browser_extensions, the portal or reports.
//
// Exported (PAT-2071) so every reader that must exclude this sentinel from a
// distinct-user count or listing shares this one definition rather than a
// second string literal — see internal/handlers/portal_tagged_products.go.
const SafariSystemSentinel = "_system"

// extMaxUserAccountLen/extMaxProfileLen (added on correctness review, after
// the round-6/7 fix above): user_account and profile are the OTHER two
// columns in device_browser_extensions' composite unique index
// (device_id, browser, user_account, profile, extension_id — migration
// 0018) and are NOT NULL, exactly like browser/extension_id — but the
// original round-6 fix only bounded browser/extension_id/name/version,
// leaving these two still unbounded text reachable from agent-uploaded
// data. Neither is ever SELECTed or displayed by any read path (grep
// confirms internal/report/portal_extensions.go and
// internal/handlers/extension_policies.go only ever use them in JOIN/WHERE
// predicates, never in SELECT/GROUP BY/ORDER BY output), so there is no
// existing read-side display cap to match — 128 is a generous, independent
// choice: macOS login names and browser profile directory names ("Default",
// "Profile 1", a UUID-ish profile dir) are realistically well under 100
// characters in every real case. Same truncate-not-reject treatment as the
// other four fields, same collision-risk reasoning (genuine values never
// approach the cap, so two distinct real values colliding after truncation
// is practically impossible).

// truncateExtField caps s at maxRunes UTF-8 characters (not bytes), matching
// Postgres LEFT(text, n)'s character-counting semantics — see the byte-vs-
// char note in internal/report/portal_extensions.go's part (c). Truncating
// on a rune boundary (via []rune, not a byte slice) avoids splitting a
// multi-byte UTF-8 character in half, which would otherwise produce invalid
// UTF-8 and store a value neither the original nor length-maxRunes.
func truncateExtField(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes])
}

// upsertBrowserExtensions inserts-or-touches device_browser_extensions rows from
// the payload's browser_extensions array. Mirrors upsertApps: first_seen is set
// at INSERT time and preserved on conflict; last_seen refreshes every ingest,
// to seenAt (PAT-2055: clock_timestamp() read under the device row lock by
// browserExtensionSeenAt, not now(), so concurrent extractions stamp in lock
// order; see that function).
//
// Risk level is computed server-side by browserExtRiskLevel so it can be tuned
// without an agent release.
//
// device_browser_extensions declares user_account and profile NOT NULL
// (0018_device_browser_extensions.sql). An entry with either field empty would
// turn into SQL NULL via nullIfEmpty and fail the INSERT with a constraint
// violation. Left unguarded, that aborts the whole processRow transaction and
// dead-letters the entire device snapshot over one bad extension row
// (PAT-871). browserExtValid mirrors the existing ExtensionID/Browser guard so
// a malformed entry is skipped and logged instead.
//
// Browser/ExtensionID/Name/Version/UserAccount/Profile are truncated (not
// rejected — see truncateExtField and the const block above) to the
// extMax*Len caps before they are used as the ON CONFLICT key or written,
// closing the PAT-933 gate round-6 finding that these fields were unbounded
// at ingestion (UserAccount/Profile added on correctness review after the
// initial round-6 fix — they're the other two columns in the same composite
// unique index and were originally missed). Truncation happens AFTER
// browserExtValid so the emptiness checks there still see the original
// values (truncating to a positive length never turns a non-empty string
// empty, so this ordering has no effect on which entries are accepted).
func upsertBrowserExtensions(ctx context.Context, tx pgx.Tx, deviceID string, exts []browserExtensionPart, seenAt time.Time, logger *slog.Logger) (int, error) {
	if len(exts) == 0 {
		return 0, nil
	}

	const stmt = `
		INSERT INTO device_browser_extensions (
			device_id, browser, user_account, profile, extension_id,
			name, version, enabled, permissions, host_permissions,
			risk_level, last_seen
		) VALUES (
			$1::uuid, $2, $3, $4, $5,
			$6, $7, $8, $9::jsonb, $10::jsonb,
			$11, $12::timestamptz
		)
		ON CONFLICT (device_id, browser, user_account, profile, extension_id) DO UPDATE SET
			name             = EXCLUDED.name,
			version          = COALESCE(NULLIF(EXCLUDED.version, ''), device_browser_extensions.version),
			enabled          = EXCLUDED.enabled,
			permissions      = EXCLUDED.permissions,
			host_permissions = EXCLUDED.host_permissions,
			risk_level       = EXCLUDED.risk_level,
			last_seen        = EXCLUDED.last_seen
	`

	written := 0
	for _, e := range exts {
		if !browserExtValid(e) {
			if logger != nil {
				logger.Warn("skipping malformed browser extension entry",
					"device_id", deviceID, "browser", e.Browser, "extension_id", e.ExtensionID,
					"user_account_empty", e.UserAccount == "", "profile_empty", e.Profile == "",
				)
			}
			continue
		}
		// PAT-933 gate round 6: bound at ingestion, before these values become
		// the ON CONFLICT key or reach the INSERT. See the const block and
		// truncateExtField doc comments above for the exact caps and the
		// collision-risk reasoning.
		browser := truncateExtField(e.Browser, extMaxBrowserLen)
		extID := truncateExtField(e.ExtensionID, extMaxIDLen)
		version := truncateExtField(e.Version, extMaxVersionLen)
		userAccount := truncateExtField(e.UserAccount, extMaxUserAccountLen)
		profile := truncateExtField(e.Profile, extMaxProfileLen)

		// Safari only (PAT-2064): browserExtValid lets an empty user_account
		// and/or profile through for this browser alone. Normalise both to
		// the fixed sentinel here, before nullIfEmpty, so nullIfEmpty sees a
		// non-empty string and the NOT NULL columns get a real, stable value
		// instead of SQL NULL. A Safari row that does carry a real
		// user_account or profile keeps it untouched.
		if browser == safariBrowser {
			if userAccount == "" {
				userAccount = SafariSystemSentinel
			}
			if profile == "" {
				profile = SafariSystemSentinel
			}
		}

		name := truncateExtField(strings.TrimSpace(e.Name), extMaxNameLen)
		if name == "" {
			name = extID
		}

		perms := e.Permissions
		if perms == nil {
			perms = []string{}
		}
		hostPerms := e.HostPermissions
		if hostPerms == nil {
			hostPerms = []string{}
		}
		permsJSON, err := json.Marshal(perms)
		if err != nil {
			return written, fmt.Errorf("marshal permissions for ext %q: %w", e.ExtensionID, err)
		}
		hostPermsJSON, err := json.Marshal(hostPerms)
		if err != nil {
			return written, fmt.Errorf("marshal host_permissions for ext %q: %w", e.ExtensionID, err)
		}

		riskLevel := browserExtRiskLevel(perms, hostPerms)

		if _, err := tx.Exec(ctx, stmt,
			deviceID, browser, nullIfEmpty(userAccount), nullIfEmpty(profile), extID,
			name, nullIfEmpty(version), e.Enabled, permsJSON, hostPermsJSON,
			riskLevel, seenAt,
		); err != nil {
			return written, fmt.Errorf("upsert browser ext %q/%q: %w", browser, extID, err)
		}
		written++
	}
	return written, nil
}

// browserExtValid reports whether a browser_extensions entry has every field
// that device_browser_extensions requires as NOT NULL or uses as part of its
// conflict key: browser, user_account, profile, extension_id. An entry
// missing any of these cannot be inserted (or cannot be identified uniquely)
// and must be skipped rather than passed to the INSERT, where a NOT NULL
// violation on user_account or profile would otherwise abort the whole
// device-processing transaction (PAT-871).
//
// Safari is the one exception (PAT-2064): its extensions live in an app
// bundle, not a browser user profile, so the macOS agent has always sent
// user_account: null (and no profile) for safari rows. Requiring those two
// fields non-empty for every browser meant browserExtValid silently dropped
// every Safari extension the agent ever sent. upsertBrowserExtensions
// normalises Safari's empty user_account/profile to SafariSystemSentinel
// before the INSERT, so this guard only needs to let a Safari row with those
// fields empty through; every other browser keeps the original all-four-
// fields-required rule exactly.
func browserExtValid(e browserExtensionPart) bool {
	if e.ExtensionID == "" || e.Browser == "" {
		return false
	}
	if e.Browser == safariBrowser {
		return true
	}
	return e.UserAccount != "" && e.Profile != ""
}

// upsertCertificates applies the collection_status-driven semantics for the
// certificates array (PAT-1732 generalises the three-way semantics PAT-216
// shipped; cs is the payload's top-level collection_status object — absent
// entirely, or with an absent "certificates" key, normalises to
// statusComplete, which reproduces the historical three-way semantics
// exactly):
//
//   - statusUnavailable                             → write nothing at all, even when certs
//     is non-nil — a failed collection must never be read as authority that
//     the device's certificates are gone. Agents are expected to omit the
//     certificates key in this case, but this must not depend on that.
//   - statusComplete, certs nil (key absent)        → no-op; leave existing rows untouched.
//   - statusComplete, certs non-nil, empty slice    → prune ALL cert rows for this device
//     (unchanged historical behaviour).
//   - statusComplete, certs non-nil, non-empty      → upsert each cert by (device_id, sha1),
//     then delete any rows whose sha1 is not in the new payload.
//   - statusPartial, certs nil (key absent)         → no-op; nothing was sent.
//   - statusPartial, certs non-nil                  → upsert every cert sent (empty or not);
//     delete nothing — a partial collection is never authority for absence.
//
// An unrecognised collection_status value is logged and treated as
// statusUnavailable, never statusComplete — see normaliseCollectionStatus.
//
// All writes run inside the caller's transaction so the device's cert set is
// never partially updated.
func upsertCertificates(ctx context.Context, tx pgx.Tx, deviceID string, certs *[]certPart, cs *collectionStatusPart, logger *slog.Logger) (int, error) {
	raw := ""
	if cs != nil {
		raw = cs.Certificates
	}
	status, known := normaliseCollectionStatus(raw)
	if logger != nil {
		if !known {
			logger.Warn("certificates: unrecognised collection_status.certificates; treating as unavailable",
				"device_id", deviceID, "collection_status_raw", raw)
		}
		if status != statusComplete {
			logger.Info("certificates: collection degraded",
				"device_id", deviceID, "status", string(status))
		}
	}

	if status == statusUnavailable {
		return 0, nil
	}

	if certs == nil {
		// Absent key — older agent that does not report certs, or nothing to
		// add this run. Leave existing rows.
		return 0, nil
	}

	if len(*certs) == 0 {
		if status == statusPartial {
			// Partial collection with nothing sent this run: partial
			// semantics never delete, so an empty array here is a no-op —
			// unlike the statusComplete empty-array case below, it is not an
			// authoritative "found zero certs".
			return 0, nil
		}
		// statusComplete: explicit empty array — agent reported and found
		// zero certs; prune all.
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_certificates WHERE device_id = $1::uuid`,
			deviceID,
		); err != nil {
			return 0, fmt.Errorf("prune all certs for device %s: %w", deviceID, err)
		}
		return 0, nil
	}

	// Non-empty: upsert each cert sent. Pruning stale rows (sha1 not present
	// in this payload) only happens for a complete collection — see below.
	const stmt = `
		INSERT INTO device_certificates (
			device_id, subject_cn, issuer_cn, sha1, not_after,
			days_until_expiry_at_collection, collected_at,
			ext_key_usage, basic_constraints_ca, is_self_signed, store
		) VALUES ($1::uuid, $2, $3, $4, $5, $6, now(), $7, $8, $9, $10)
		ON CONFLICT (device_id, sha1) DO UPDATE SET
			subject_cn                      = EXCLUDED.subject_cn,
			issuer_cn                       = EXCLUDED.issuer_cn,
			not_after                       = EXCLUDED.not_after,
			days_until_expiry_at_collection = EXCLUDED.days_until_expiry_at_collection,
			ext_key_usage                   = EXCLUDED.ext_key_usage,
			basic_constraints_ca            = EXCLUDED.basic_constraints_ca,
			is_self_signed                  = EXCLUDED.is_self_signed,
			store                           = EXCLUDED.store,
			collected_at                    = now()
	`

	sha1s := make([]string, 0, len(*certs))
	for _, c := range *certs {
		notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			return 0, fmt.Errorf("parse not_after for cert sha1=%q: %w", c.SHA1, err)
		}
		eku := c.EKU
		if eku == nil {
			eku = []string{}
		}
		// PAT-1738: absent store defaults to "My" — the only source that
		// existed before this field, so an un-upgraded agent's payloads
		// keep classifying exactly as they did before this change.
		store := c.Store
		if store == "" {
			store = "My"
		}
		if _, err := tx.Exec(ctx, stmt,
			deviceID, c.SubjectCN, c.IssuerCN, c.SHA1, notAfter, c.DaysUntilExpiry,
			eku, c.BasicConstraintsCA, c.IsSelfSigned, store,
		); err != nil {
			return 0, fmt.Errorf("upsert cert sha1=%q: %w", c.SHA1, err)
		}
		sha1s = append(sha1s, c.SHA1)
	}

	// Delete certs that were in the DB for this device but are not in the
	// current payload — they have been removed from the keychain. Only for a
	// complete collection: a partial collection's sender list is known to be
	// incomplete by definition, so pruning against it would delete rows for
	// certs the agent simply didn't get to this run, not certs that are
	// actually gone.
	if status == statusComplete {
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_certificates WHERE device_id = $1::uuid AND sha1 != ALL($2::text[])`,
			deviceID, sha1s,
		); err != nil {
			return 0, fmt.Errorf("prune stale certs for device %s: %w", deviceID, err)
		}
	}

	return len(*certs), nil
}

// upsertLocalAdmins persists the local_admins roster to local_admin_accounts
// (PAT-1974, migration 0159). Governed by the object's own single
// collection_status — local_admins has exactly one section, unlike
// hardware_health's three, so there is no per-key breakdown to track:
//
//   - nil pointer (key absent in payload) → no-op; leave existing rows. An
//     agent that predates PAT-1974.
//   - "complete" (or collection_status absent — defence in depth only; the
//     agent contract always sends it explicitly) → replace the roster in
//     full (DELETE + INSERT), even when accounts is empty: a genuinely empty
//     roster is a real, evidenced observation, the same rule storage/disks
//     follow for hardware_health.
//   - "partial" → upsert only the accounts actually sent (matched by name);
//     delete nothing. A partial collection's sender list is known to be
//     incomplete by definition, so pruning against it would delete rows for
//     admins the agent simply didn't get to this run, not admins who are
//     actually gone.
//
// account_state (PAT-1992, migration 0162) follows the same authority rule.
// "complete" writes exactly what was sent, NULL when the key was absent: the
// roster is replaced in full, and carrying a stale state across onto a fresh
// read would be a claim this run did not make. "partial" writes a sent value
// (including an explicit "unknown", which is newer evidence than whatever was
// stored) but an absent key keeps the stored value: a partial run must never
// blank a previously recorded state.
//   - "unavailable" → write nothing at all, even if accounts is non-empty —
//     a failed enumeration must never be read as authority that the roster
//     shrank or is empty.
//
// An unrecognised collection_status value is logged and treated as
// "unavailable", never "complete" — see normaliseCollectionStatus.
//
// All writes run inside the caller's transaction. Returns the count of rows
// written or updated (0 on no-op, and 0 when the status is "unavailable").
func upsertLocalAdmins(ctx context.Context, tx pgx.Tx, deviceID string, la *localAdminsPart, logger *slog.Logger) (int, error) {
	if la == nil {
		return 0, nil
	}

	status, known := normaliseCollectionStatus(la.CollectionStatus)
	if logger != nil {
		if !known {
			logger.Warn("local_admins: unrecognised collection_status; treating as unavailable",
				"device_id", deviceID, "collection_status_raw", la.CollectionStatus)
		}
		if status != statusComplete {
			logger.Info("local_admins: collection degraded",
				"device_id", deviceID, "status", string(status))
		}
	}

	if status == statusUnavailable {
		return 0, nil
	}

	written := 0

	switch status {
	case statusComplete:
		if _, err := tx.Exec(ctx,
			`DELETE FROM local_admin_accounts WHERE device_id = $1::uuid`, deviceID,
		); err != nil {
			return 0, fmt.Errorf("prune local admin accounts for device %s: %w", deviceID, err)
		}
		for _, a := range la.Accounts {
			if _, err := tx.Exec(ctx, `
				INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin, sid, account_state, collected_at)
				VALUES ($1::uuid, $2, $3, $4, $5, $6, now())
			`, deviceID, a.Name, a.PrincipalType, a.Builtin, a.Sid, a.AccountState); err != nil {
				return 0, fmt.Errorf("insert local admin account %q: %w", a.Name, err)
			}
			written++
		}
	case statusPartial:
		// Upsert only what was sent; delete nothing. There is no unique
		// constraint on (device_id, name) to ON CONFLICT against — match-
		// then-write inside this transaction, the same pattern storage/disks
		// use for their own partial branches (safe against a self-race
		// because the extractor holds one connection for the whole
		// device-processing transaction).
		for _, a := range la.Accounts {
			var existingID int64
			err := tx.QueryRow(ctx,
				`SELECT id FROM local_admin_accounts WHERE device_id = $1::uuid AND name = $2`,
				deviceID, a.Name,
			).Scan(&existingID)
			switch {
			case err == nil:
				if _, err := tx.Exec(ctx, `
					UPDATE local_admin_accounts
					SET principal_type = $1, builtin = $2, sid = $3,
					    account_state = COALESCE($4, account_state),
					    collected_at = now()
					WHERE id = $5
				`, a.PrincipalType, a.Builtin, a.Sid, a.AccountState, existingID); err != nil {
					return 0, fmt.Errorf("update local admin account %q: %w", a.Name, err)
				}
			case errors.Is(err, pgx.ErrNoRows):
				if _, err := tx.Exec(ctx, `
					INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin, sid, account_state, collected_at)
					VALUES ($1::uuid, $2, $3, $4, $5, $6, now())
				`, deviceID, a.Name, a.PrincipalType, a.Builtin, a.Sid, a.AccountState); err != nil {
					return 0, fmt.Errorf("insert local admin account %q: %w", a.Name, err)
				}
			default:
				return 0, fmt.Errorf("look up local admin account %q: %w", a.Name, err)
			}
			written++
		}
	}

	return written, nil
}

// loadStoredCollectionStatus reads and decodes devices.collection_status
// (PAT-1732, migration 0128) inside the caller's transaction. A NULL column
// (the device has never had any collection_status section stored) returns a
// zero-value collectionStatusSnapshot with no error. A malformed stored
// value must not abort the wider ingest — it is logged and treated as empty,
// the same defensive posture PAT-871/PAT-948 established for a malformed
// INBOUND section, applied here to a value this server itself previously
// wrote. Shared by upsertCollectionStatus (to merge this ingest's sections
// into the stored snapshot) and upsertHardwareHealth (to decide, for a
// Windows device, whether this is the first ingest ever to report a
// hardware_health.collection_status.disks value — see
// pruneStaleFriendlyNameDisks, PAT-1736).
func loadStoredCollectionStatus(ctx context.Context, tx pgx.Tx, deviceID string, logger *slog.Logger) (collectionStatusSnapshot, error) {
	var existing []byte
	if err := tx.QueryRow(ctx,
		`SELECT collection_status FROM devices WHERE id = $1::uuid`, deviceID,
	).Scan(&existing); err != nil {
		return collectionStatusSnapshot{}, fmt.Errorf("select existing collection_status for device %s: %w", deviceID, err)
	}
	if len(existing) == 0 {
		return collectionStatusSnapshot{}, nil
	}
	var snap collectionStatusSnapshot
	if err := json.Unmarshal(existing, &snap); err != nil {
		if logger != nil {
			logger.Warn("collection_status: stored value did not decode; resetting",
				"device_id", deviceID, "error", err)
		}
		return collectionStatusSnapshot{}, nil
	}
	return snap, nil
}

// upsertCollectionStatus merges this payload's reported collection_status
// sections into devices.collection_status (PAT-1732, migration 0128), so a
// degraded top-level collection is visible on the platform rather than only
// changing extractor behaviour the way the PAT-1720 precedent did — that
// changed how hardware_health rows were ingested but persisted nothing
// queryable anywhere.
//
// Read-then-write inside the caller's transaction, not a single UPDATE with
// a jsonb `||` merge: `||` only merges at the top level, and
// hardware_health's three sections (battery/storage/disks) need their own
// independent key-level preservation one level deeper — a payload reporting
// only hardware_health.collection_status.battery must never clobber a
// previously stored storage or disks status. The extractor holds one
// connection for the whole device-processing transaction (same reasoning
// upsertHardwareHealth's storage/disk match-then-write gives for why that is
// safe against a self-race), so this read-then-write is safe too.
//
// topCS is the payload's top-level collection_status object; hwCS is
// hardware_health's own nested collection_status object; laStatus is
// local_admins' own collection_status string (PAT-1974), or "" when the
// local_admins key was absent from the payload entirely. topCS/hwCS may be
// nil and laStatus may be empty, independently. A payload carrying none of
// them leaves the column completely untouched — this function does not even
// run the SELECT in that case. Only the keys actually present in whichever
// object(s) the payload does carry are written; every other stored key, at
// either nesting level, is left exactly as it was.
func upsertCollectionStatus(ctx context.Context, tx pgx.Tx, deviceID string, topCS *collectionStatusPart, hwCS *hwCollectionStatusPart, laStatus string, logger *slog.Logger) error {
	if topCS == nil && hwCS == nil && laStatus == "" {
		return nil
	}

	snap, err := loadStoredCollectionStatus(ctx, tx, deviceID, logger)
	if err != nil {
		return err
	}

	changed := false

	if topCS != nil && topCS.Certificates != "" {
		status, known := normaliseCollectionStatus(topCS.Certificates)
		if !known && logger != nil {
			logger.Warn("collection_status.certificates: unrecognised value stored as unavailable",
				"device_id", deviceID, "collection_status_raw", topCS.Certificates)
		}
		snap.Certificates = string(status)
		changed = true
	}

	// PAT-2063: the explicit apps status, stored as sent (normalised). The
	// safety valve's decision is not a wire value and is not stored here;
	// it is in software_inventory_runs.coverage.apps_absence_withheld.
	if topCS != nil && topCS.Apps != "" {
		status, _ := normaliseCollectionStatus(topCS.Apps)
		snap.Apps = string(status)
		changed = true
	}

	// PAT-2067: the explicit Safari extensions status, stored as sent
	// (normalised). Its authority lives on browser_extension_device_state.
	if topCS != nil && topCS.SafariExtensions != "" {
		status, _ := normaliseCollectionStatus(topCS.SafariExtensions)
		snap.SafariExtensions = string(status)
		changed = true
	}

	if laStatus != "" {
		status, known := normaliseCollectionStatus(laStatus)
		if !known && logger != nil {
			logger.Warn("local_admins.collection_status: unrecognised value stored as unavailable",
				"device_id", deviceID, "collection_status_raw", laStatus)
		}
		snap.LocalAdmins = string(status)
		changed = true
	}

	if hwCS != nil {
		if snap.HardwareHealth == nil {
			snap.HardwareHealth = &hwCollectionStatusSnapshot{}
		}
		for _, section := range []struct {
			raw    string
			target *string
			name   string
		}{
			{hwCS.Battery, &snap.HardwareHealth.Battery, "battery"},
			{hwCS.Storage, &snap.HardwareHealth.Storage, "storage"},
			{hwCS.Disks, &snap.HardwareHealth.Disks, "disks"},
		} {
			if section.raw == "" {
				continue
			}
			status, known := normaliseCollectionStatus(section.raw)
			if !known && logger != nil {
				logger.Warn("hardware_health.collection_status: unrecognised value stored as unavailable",
					"device_id", deviceID, "section", section.name, "collection_status_raw", section.raw)
			}
			*section.target = string(status)
			changed = true
		}
		if snap.HardwareHealth.Battery == "" && snap.HardwareHealth.Storage == "" && snap.HardwareHealth.Disks == "" {
			// Nothing was actually set this run (hwCS was present but every
			// key was absent) and nothing was already stored — drop the
			// empty sub-object rather than persisting "hardware_health":{}.
			snap.HardwareHealth = nil
		}
	}

	if !changed {
		// The payload carried a collection_status object, but not one with
		// any key this function recognises (e.g. hardware_health.
		// collection_status present as {}) — nothing to write.
		return nil
	}

	j, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal collection_status for device %s: %w", deviceID, err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE devices SET collection_status = $1 WHERE id = $2::uuid`, j, deviceID,
	); err != nil {
		return fmt.Errorf("update collection_status for device %s: %w", deviceID, err)
	}
	return nil
}

// ── Agent health (PAT-1064) ───────────────────────────────────────────────

const (
	agentHealthMaxEntries  = 64  // PAT-933 precedent: cap the array before values become the ON CONFLICT key.
	agentHealthMaxFieldLen = 128 // kind/subject/reason truncation cap, same precedent.
)

// parseAgentHealth decodes the payload's raw agent_health bytes into a typed
// agentHealthEnvelope. Returns (nil, false) — meaning "no opinion, caller
// must no-op" — in THREE cases, all logged and all treated identically:
//
//  1. The top-level "agent_health" key is absent/null (older agent that
//     doesn't speak this protocol).
//  2. The top-level object failed to decode (malformed shape — same
//     defensive posture parseBackupStatus established for PAT-948, applied
//     here to this section).
//  3. The top-level object decoded fine, but its "degraded" key is absent
//     or explicitly null (review round 4, FIX 13). {} and
//     {"degraded": null} are NOT an agent asserting "nothing is degraded" —
//     they are a section that was written incompletely, by a
//     partially-implemented agent, or that genuinely carries no data. Only
//     an explicit, present, non-null "degraded" array is an assertion about
//     device state. Case 3 is why agentHealthEnvelope.Degraded is
//     *[]json.RawMessage rather than a plain slice — see that type's doc
//     comment for the full reasoning and the exact bug this closes.
//
// Returns (&agentHealthEnvelope{...}, true) — ok=true — ONLY when
// "degraded" is present as a genuine JSON array, EVEN WHEN that array is
// empty ([]): that is the "reporting all clear" case, and turning
// present-with-empty-array into a clear-all-rows delete (rather than a
// no-op) is the caller's job in upsertAgentHealth. Conflating "absent" (or
// "null") with "present empty" here is exactly the bug this ticket exists
// to prevent — see the package-level ticket note and
// upsertBrowserExtensions's early-return, which this function must NOT be
// copied from.
func parseAgentHealth(raw json.RawMessage, logger *slog.Logger) (*agentHealthEnvelope, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var h agentHealthEnvelope
	if err := json.Unmarshal(raw, &h); err != nil {
		if logger != nil {
			logger.Warn("skipping malformed agent_health section", "err", err)
		}
		return nil, false
	}
	if h.Degraded == nil {
		// "degraded" key absent or explicitly null (FIX 13) — not an
		// assertion about device state. Same treatment as a malformed
		// section: log and report absent, never a clear.
		if logger != nil {
			logger.Warn(`skipping agent_health section: "degraded" is absent or null, not an assertion about device state`)
		}
		return nil, false
	}
	return &h, true
}

type updateChannelObservation struct {
	Channel       string `json:"channel"`
	Source        string `json:"source"`
	ConfigVersion int    `json:"config_version"`
}

// decodeUniqueJSONObject is deliberately local to the observation path. A
// malformed agent_health section must not reject the whole inventory upload,
// but an observation is only useful when its exact fields are unambiguous.
// encoding/json otherwise accepts duplicate keys and keeps the last value.
func decodeUniqueJSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		fields[key] = value
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return fields, true
}

// parseUpdateChannelObservation is independent of degraded health semantics.
// Source must be explicitly reported from the signed config; it is never
// guessed from the channel or current server policy.
func parseUpdateChannelObservation(raw json.RawMessage, logger *slog.Logger) (*updateChannelObservation, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	root, ok := decodeUniqueJSONObject(raw)
	if !ok {
		return nil, false
	}
	b, ok := root["update_channel"]
	if !ok || string(b) == "null" {
		return nil, false
	}
	fields, ok := decodeUniqueJSONObject(b)
	if !ok {
		return nil, false
	}
	if len(fields) != 3 {
		return nil, false
	}
	var o updateChannelObservation
	if json.Unmarshal(b, &o) != nil || (o.Channel != "stable" && o.Channel != "beta") ||
		(o.Source != "tenant" && o.Source != "device_override") || o.ConfigVersion <= 0 || int64(o.ConfigVersion) > 2147483647 {
		if logger != nil {
			logger.Warn("skipping malformed agent_health update_channel observation")
		}
		return nil, false
	}
	for _, k := range []string{"channel", "source", "config_version"} {
		if _, exists := fields[k]; !exists {
			return nil, false
		}
	}
	return &o, true
}

func upsertUpdateChannelObservation(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, raw json.RawMessage, collectedAt, receivedAt time.Time, rawPayloadID int64, logger *slog.Logger) error {
	o, ok := parseUpdateChannelObservation(raw, logger)
	// Anchor the future-skew check and the stored received_at to the immutable
	// raw payload timestamp. A delayed extractor run must not turn a payload
	// that was too far in the future at ingestion into valid evidence later.
	if !ok || collectedAt.IsZero() || receivedAt.IsZero() || rawPayloadID <= 0 || agentHealthCollectedAtTooFarFuture(collectedAt, receivedAt) {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO agent_update_channel_observations
		(tenant_id,device_id,channel,source,config_version,observed_at,received_at,raw_payload_id)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8) ON CONFLICT (raw_payload_id) DO NOTHING`,
		tenantID, deviceID, o.Channel, o.Source, o.ConfigVersion, collectedAt, receivedAt, rawPayloadID)
	if err != nil {
		return fmt.Errorf("insert update-channel observation: %w", err)
	}
	return nil
}

// sanitizedAgentHealthEntry is an agent_health.degraded element after
// per-element decode, validation, truncation and timestamp parsing — ready
// to write. Kind/Subject are what upsertAgentHealth uses, together with
// device_id, to compute the reported set for the clear-on-recovery delete.
type sanitizedAgentHealthEntry struct {
	Kind          string
	Subject       string
	Reason        string
	FirstSeen     time.Time
	LastSeen      time.Time
	Count         int64
	EverSucceeded bool
}

// agentHealthSanitizeResult is sanitizeAgentHealthEntries' return value: the
// entries that survived, plus enough information about what did NOT survive
// for the caller to judge whether the surviving set is a trustworthy
// snapshot of "everything currently degraded on this device".
//
// That judgment matters because upsertAgentHealth's clear-on-recovery DELETE
// treats any existing row whose (kind, subject) is absent from the
// surviving set as recovered and removes it. If Dropped > 0 or Capped is
// true, the surviving set is NOT the full picture the agent tried to
// report — a capability could be missing from it only because its entry was
// malformed or got capped away, not because it actually recovered. Pruning
// against an incomplete set would falsely resolve a still-degraded
// capability, which is the exact failure this ticket exists to eliminate.
// upsertAgentHealth must skip the prune whenever either field says the
// snapshot is incomplete (still upserting whatever DID survive).
type agentHealthSanitizeResult struct {
	Entries []sanitizedAgentHealthEntry
	// Dropped is the total number of reported entries that did not make it
	// into Entries: entries removed by the agentHealthMaxEntries cap, plus
	// entries that failed per-element decode or validation. A single combined
	// count — callers that need the prune-safety judgment use Capped
	// specifically; callers that just want "how many entries were lost this
	// ingest" (the extraction summary log line) want the combined number.
	Dropped int
	// Capped is true when the reported degraded array exceeded
	// agentHealthMaxEntries and had to be truncated.
	Capped bool
}

// sanitizeAgentHealthEntries decodes, validates, truncates and caps the raw
// degraded array from one payload. Pure function — no DB access — so it can
// be exercised directly by pure-unit tests with no DATABASE_URL, including
// the reported-set computation upsertAgentHealth uses for its delete.
//
// Ordering matches the PAT-933 gate precedent (see truncateExtField and the
// const block near upsertBrowserExtensions): the array is capped at
// agentHealthMaxEntries BEFORE per-element decode, and each string field is
// truncated to agentHealthMaxFieldLen BEFORE it can become part of the
// device_agent_health (device_id, kind, subject) primary key.
//
// A malformed element — one that fails to json.Unmarshal into
// agentHealthEntryPart, or that decodes but has a NUL byte in kind/subject/
// reason, an empty kind/subject, a count < 1, an unparseable first_seen/
// last_seen, or a null ever_succeeded — is logged and skipped; it never
// fails the whole payload (PAT-871 precedent, documented in validate.go's
// agent_health section). Every entry lost this way, and every entry lost to
// capping, is counted in the returned Dropped/Capped fields — see
// agentHealthSanitizeResult's doc comment for why the caller needs them.
func sanitizeAgentHealthEntries(raw []json.RawMessage, deviceID string, logger *slog.Logger) agentHealthSanitizeResult {
	entries := raw
	capped := false
	droppedByCap := 0
	if len(entries) > agentHealthMaxEntries {
		capped = true
		droppedByCap = len(entries) - agentHealthMaxEntries
		if logger != nil {
			logger.Warn("capping agent_health.degraded entries",
				"device_id", deviceID, "reported", len(entries), "cap", agentHealthMaxEntries)
		}
		entries = entries[:agentHealthMaxEntries]
	}

	out := make([]sanitizedAgentHealthEntry, 0, len(entries))
	droppedMalformed := 0
	for i, elemRaw := range entries {
		var e agentHealthEntryPart
		if err := json.Unmarshal(elemRaw, &e); err != nil {
			if logger != nil {
				logger.Warn("skipping malformed agent_health entry (decode error)",
					"device_id", deviceID, "index", i, "err", err)
			}
			droppedMalformed++
			continue
		}

		// NUL-byte guard (review fix): PostgreSQL text columns reject the NUL
		// byte outright, and Kind/Subject/Reason become bind parameters on the
		// INSERT further down. Left unchecked, one entry containing \x00
		// would make tx.Exec fail, upsertAgentHealth would propagate that
		// error, and processRow would abort the WHOLE transaction — apps,
		// compliance, extensions, everything for that device, retried forever
		// against the same poisoned row. That is exactly the per-entry-
		// isolation guarantee this section exists to provide, defeated by one
		// byte. Checked on the raw decoded strings, BEFORE truncation:
		// truncateExtField's rune-boundary slicing could otherwise land
		// exactly on the NUL and appear to "fix" it by accident, which would
		// still leave a value the agent never actually sent. Reject, don't
		// strip — a NUL means the field isn't what the agent thinks it is, so
		// silently rewriting it would put a corrupted value into the
		// (device_id, kind, subject) primary key.
		if strings.ContainsRune(e.Kind, '\x00') || strings.ContainsRune(e.Subject, '\x00') || strings.ContainsRune(e.Reason, '\x00') {
			if logger != nil {
				logger.Warn("skipping agent_health entry with a NUL byte in kind/subject/reason",
					"device_id", deviceID, "index", i)
			}
			droppedMalformed++
			continue
		}

		kind := truncateExtField(strings.TrimSpace(e.Kind), agentHealthMaxFieldLen)
		subject := truncateExtField(strings.TrimSpace(e.Subject), agentHealthMaxFieldLen)
		reason := truncateExtField(e.Reason, agentHealthMaxFieldLen)

		if kind == "" || subject == "" {
			if logger != nil {
				logger.Warn("skipping agent_health entry with empty kind/subject",
					"device_id", deviceID, "index", i)
			}
			droppedMalformed++
			continue
		}
		if e.Count < 1 {
			if logger != nil {
				logger.Warn("skipping agent_health entry with count < 1",
					"device_id", deviceID, "kind", kind, "subject", subject, "count", e.Count)
			}
			droppedMalformed++
			continue
		}
		firstSeen, err := time.Parse(time.RFC3339, e.FirstSeen)
		if err != nil {
			if logger != nil {
				logger.Warn("skipping agent_health entry with unparseable first_seen",
					"device_id", deviceID, "kind", kind, "subject", subject, "err", err)
			}
			droppedMalformed++
			continue
		}
		lastSeen, err := time.Parse(time.RFC3339, e.LastSeen)
		if err != nil {
			if logger != nil {
				logger.Warn("skipping agent_health entry with unparseable last_seen",
					"device_id", deviceID, "kind", kind, "subject", subject, "err", err)
			}
			droppedMalformed++
			continue
		}
		// ever_succeeded nil guard (review fix): EverSucceeded is *bool
		// specifically so a schema-invalid `"ever_succeeded":null` decodes to
		// nil rather than silently becoming the bool zero value (false) —
		// which would assert "this has never worked", the more alarming of
		// the two states, on no evidence at all. The whole point of this
		// field being explicit rather than inferred is that only the agent
		// knows the answer; a missing answer must be dropped, not invented.
		if e.EverSucceeded == nil {
			if logger != nil {
				logger.Warn("skipping agent_health entry with null ever_succeeded",
					"device_id", deviceID, "kind", kind, "subject", subject)
			}
			droppedMalformed++
			continue
		}

		out = append(out, sanitizedAgentHealthEntry{
			Kind:          kind,
			Subject:       subject,
			Reason:        reason,
			FirstSeen:     firstSeen,
			LastSeen:      lastSeen,
			Count:         e.Count,
			EverSucceeded: *e.EverSucceeded,
		})
	}
	return agentHealthSanitizeResult{
		Entries: out,
		Dropped: droppedByCap + droppedMalformed,
		Capped:  capped,
	}
}

// agentHealthWatermarkSentinel seeds device_agent_health_watermark.collected_at
// for a device seen by this section for the very first time. Deliberately
// the Unix epoch (1970-01-01), not a Postgres '-infinity'::timestamptz and
// not Go's zero time.Time{}:
//
//   - '-infinity' looked like the obvious choice but pgx v5 cannot scan a
//     timestamptz infinity value into a plain time.Time destination — it
//     returns a scan error, which would make lockAgentHealthWatermark fail
//     on literally every device's first-ever agent_health payload. Verified
//     directly against Postgres 17 before shipping this: `SELECT
//     '-infinity'::timestamptz` scanned into time.Time errors with "cannot
//     scan -Infinity into *time.Time".
//   - Go's zero time.Time{} is already used elsewhere as extractor.go's
//     fallback value for a payload whose own collected_at failed to parse
//     (see the caller). Reusing it here would mean a payload with an
//     unparseable collected_at landing on a BRAND NEW device compares equal
//     to (not before) the sentinel — not stale — and would proceed to write
//     fault rows carrying a nonsense year-1 timestamp. Using a distinct
//     sentinel keeps that case correctly falling on the safe "reject, don't
//     act" side: a parse failure (year 1) is before the epoch sentinel, so
//     the section is skipped entirely rather than writing garbage-timestamped
//     data on a device we've never seen agent_health from before.
var agentHealthWatermarkSentinel = time.Unix(0, 0).UTC()

// agentHealthFutureTolerance bounds how far ahead of the SERVER's own clock
// a payload's collected_at may be before it is rejected as untrustworthy
// (review round 5, FIX 14). The recency design (FIX 8/FIX 10) only ever
// checked one side — older than the watermark is rejected, anything newer
// is accepted without limit — because collected_at is entirely
// agent-controlled. A device that reports a far-future collected_at (a
// broken clock, a timezone bug in some future agent build, or malice) would
// therefore: pass the recency check, clear or overwrite the device's
// current rows, and persist that far-future value as the new watermark —
// after which every LEGITIMATE payload from that device is judged "older
// than the watermark" and silently rejected, forever, until someone
// hand-edits the database. That is strictly worse than the false-resolution
// bugs FIX 1/5/8 fixed: those each resolved a fault once and the next
// correct payload un-did it; this one is self-sealing and turns the whole
// degraded-capability channel off for that device permanently, with no row,
// no signal, and nothing in the console to explain why.
//
// 5 minutes: generous enough to absorb ordinary NTP drift and the gap
// between an endpoint's local clock and the server's (real-world skew is
// almost always sub-second to low-single-digit-seconds on a machine with
// working time sync), while nowhere near generous enough to let a
// meaningfully broken clock — hours, days, or 2099 — through. There is no
// legitimate reason for collected_at, which both agents set at the moment
// they finish gathering local state and send it, to be minutes ahead of the
// server that receives it moments later.
//
// Reject, don't clamp: clamping an out-of-bounds collected_at to now()
// would still let a device with a broken clock advance its OWN watermark on
// every single upload (since the clamped value is always "now", which is
// always >= the previous watermark) — the exact same permanent-wedge
// failure, just arriving one upload later instead of immediately.
// Rejecting the whole section leaves the watermark exactly where it was, so
// the NEXT payload — assuming the agent's clock or the underlying bug gets
// fixed — is judged against the last value that was ever trustworthy.
const agentHealthFutureTolerance = 5 * time.Minute

// agentHealthCollectedAtTooFarFuture reports whether collectedAt is more
// than agentHealthFutureTolerance ahead of now. now is a parameter (not
// time.Now() called inline) purely so this stays a pure, deterministic
// function for unit testing; upsertAgentHealth passes time.Now() in
// production.
func agentHealthCollectedAtTooFarFuture(collectedAt, now time.Time) bool {
	return collectedAt.After(now.Add(agentHealthFutureTolerance))
}

// lockAgentHealthWatermark takes the row lock on this device's
// device_agent_health_watermark row (creating it with agentHealthWatermarkSentinel
// on first contact) and returns the currently stored collected_at. Must be
// the FIRST statement upsertAgentHealth issues once it knows agent_health is
// present — before any staleness decision — so the lock is held for the
// rest of the caller's transaction and serialises concurrent agent-health
// writes for this device (review round 3, FIX 10). The
// INSERT ... ON CONFLICT DO UPDATE ... RETURNING form is a single atomic
// statement: it both guarantees the row exists and takes its lock, with no
// separate SELECT FOR UPDATE that could race a concurrent first-insert.
func lockAgentHealthWatermark(ctx context.Context, tx pgx.Tx, deviceID string) (time.Time, error) {
	var watermark time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO device_agent_health_watermark (device_id, collected_at, updated_at)
		VALUES ($1::uuid, $2::timestamptz, now())
		ON CONFLICT (device_id) DO UPDATE SET device_id = device_agent_health_watermark.device_id
		RETURNING collected_at
	`, deviceID, agentHealthWatermarkSentinel).Scan(&watermark); err != nil {
		return time.Time{}, fmt.Errorf("lock agent health watermark for device %s: %w", deviceID, err)
	}
	return watermark, nil
}

// upsertAgentHealth applies the payload's agent_health.degraded array
// (PAT-1064) — the server half of the degraded-capability channel. Three-way
// semantics on the raw section, mirroring upsertCertificates:
//
//   - absent / malformed top-level section → no opinion; existing rows left
//     untouched, watermark untouched, no lock taken (nothing to decide).
//   - present, degraded: []                → agent reports all clear; delete
//     every device_agent_health row for this device (unless the payload is
//     stale — see recency below).
//   - present, degraded: [...]              → upsert the sanitized entries by
//     (device_id, kind, subject), then — ONLY when the sanitized set is a
//     complete, trustworthy picture of what the agent reported (see below) —
//     delete any existing row for this device whose (kind, subject) is NOT
//     in that set. A capability that recovered must stop being reported as
//     degraded.
//
// collectedAt is the producing payload's own collected_at claim (parsed by
// the caller — extractor.go — from the top-level payload field; the zero
// time.Time on a parse failure, which always loses the recency comparison
// below and therefore can never be destructive).
//
// Recency (review round 3, FIX 8 — replaces an earlier, broken design) is
// two-sided (review round 5, FIX 14 added the upper bound):
// whenever agent_health is present, this function's first DB statement
// locks and reads device_agent_health_watermark for this device
// (lockAgentHealthWatermark) — a table that exists independently of
// whether the device currently has any degraded-capability ROWS. Then:
//
//   - Too far in the future (collectedAt more than agentHealthFutureTolerance
//     ahead of the server's own clock) → rejected outright, watermark
//     untouched. Without this, a device with a broken clock could advance
//     its own watermark decades into the future and have every legitimate
//     payload after that silently rejected as "stale" forever — see
//     agentHealthFutureTolerance's doc comment.
//   - Older than the stored watermark → the ENTIRE section is rejected: no
//     clear, no upsert, no prune, and the watermark itself is left
//     untouched.
//   - Otherwise → the section is processed (clear / upsert+prune as
//     appropriate) and the watermark is advanced to collectedAt at the
//     end — updated on every processed section regardless of shape (empty
//     or with entries), because the watermark's job is to record "how
//     recent is the health picture we've accepted for this device", not
//     "how recent is the newest fault row" (rows can be legitimately zero).
//
// An earlier version of this function derived staleness from
// MAX(collected_at) over device_agent_health's own rows, gated per-row
// overwrites with an ON CONFLICT ... WHERE guard, and left the prune as the
// only thing skipped on staleness. That broke two ways: (1) a newer
// degraded: [] payload deletes every row and, with a rows-derived
// watermark, the recency memory along with them — a later, delayed OLDER
// payload then finds no watermark and resurrects resolved faults; (2) the
// per-row WHERE guard only blocks UPDATEs, so an older payload naming a
// (kind, subject) NOT currently present takes the unguarded INSERT path.
// The dedicated watermark table and the "reject the whole section, not just
// the delete" design close both holes.
//
// Returns (written, dropped, err): written is the row count upserted this
// ingest (all sanitized entries — once the section clears the watermark
// gate, every entry writes unconditionally, since staleness has already
// been decided once for the whole payload under the watermark lock);
// dropped is sanitizeAgentHealthEntries' combined capped+malformed count,
// surfaced so extractor.go can log it in the extraction summary alongside
// every other section's counts — a device silently losing health entries
// must show up somewhere even though a single bad entry must never fail the
// whole payload (PAT-871 posture: loud when possible, never fatal).
//
// Do NOT early-return on an empty array the way upsertBrowserExtensions
// does — that early return is precisely the bug this function exists to
// avoid: an agent reporting "all clear" must clear stale rows, not leave a
// stale degraded record standing forever.
//
// Prune safety: the clear-on-recovery DELETE below only runs when
// sanitizeAgentHealthEntries reports Dropped == 0 and Capped == false —
// i.e. the sanitized set is exactly what the agent tried to report, nothing
// lost to a decode failure or the array cap. If any entry was dropped or
// the array was capped, the surviving set is NOT proof that the missing
// (kind, subject) pairs recovered — they may simply be the ones that got
// dropped or capped away. Pruning against an incomplete set would falsely
// resolve a capability that is still degraded, which is exactly the failure
// this ticket exists to eliminate. The fail-safe direction is asymmetric:
// leaving a stale row for one extra ingest cycle is harmless (it clears on
// the next complete payload), but falsely clearing a live fault is not — so
// an incomplete snapshot skips the prune and only upserts what survived.
// (This incomplete-snapshot case still advances the watermark: the payload
// itself was not stale, only some of its entries were unusable.)
//
// If every element of a non-empty degraded array turns out malformed
// (sanitizeAgentHealthEntries returns none), the payload carried no verified
// signal about this device's state — this function leaves existing rows
// untouched rather than treating a garbage submission as equivalent to a
// verified "all clear" (but still advances the watermark, since the payload
// itself was genuinely the freshest one seen — see the watermark-semantics
// paragraph above). Only a genuinely empty degraded array (checked above,
// before sanitization) clears everything.
func upsertAgentHealth(ctx context.Context, tx pgx.Tx, deviceID string, raw json.RawMessage, collectedAt time.Time, logger *slog.Logger) (written int, dropped int, err error) {
	envelope, present := parseAgentHealth(raw, logger)
	if !present {
		return 0, 0, nil
	}

	watermark, err := lockAgentHealthWatermark(ctx, tx, deviceID)
	if err != nil {
		return 0, 0, err
	}

	now := time.Now()
	if agentHealthCollectedAtTooFarFuture(collectedAt, now) {
		// Reject outright — see agentHealthFutureTolerance's doc comment for
		// why this must never clamp or otherwise let collectedAt through:
		// this is the ONLY thing standing between a device with a broken
		// clock and a permanently self-sealed watermark for that device.
		if logger != nil {
			logger.Warn("skipping agent_health section: payload collected_at is implausibly far in the future, treating as untrustworthy",
				"device_id", deviceID, "payload_collected_at", collectedAt, "server_now", now, "tolerance", agentHealthFutureTolerance)
		}
		return 0, 0, nil
	}
	if collectedAt.Before(watermark) {
		if logger != nil {
			logger.Warn("skipping agent_health section: payload is older than this device's recorded watermark",
				"device_id", deviceID, "payload_collected_at", collectedAt, "watermark_collected_at", watermark)
		}
		return 0, 0, nil
	}

	// present==true (checked via parseAgentHealth above) guarantees
	// envelope.Degraded is a non-nil pointer — see agentHealthEnvelope's doc
	// comment (FIX 13): a nil Degraded is exactly the {}/null case
	// parseAgentHealth already turned into present=false. Safe to
	// dereference unconditionally here.
	degraded := *envelope.Degraded

	if len(degraded) == 0 {
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_agent_health WHERE device_id = $1::uuid`,
			deviceID,
		); err != nil {
			return 0, 0, fmt.Errorf("clear agent health for device %s: %w", deviceID, err)
		}
		if err := advanceAgentHealthWatermark(ctx, tx, deviceID, collectedAt); err != nil {
			return 0, 0, err
		}
		return 0, 0, nil
	}

	result := sanitizeAgentHealthEntries(degraded, deviceID, logger)
	if len(result.Entries) > 0 {
		const stmt = `
			INSERT INTO device_agent_health (
				device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at, updated_at
			) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, now())
			ON CONFLICT (device_id, kind, subject) DO UPDATE SET
				reason         = EXCLUDED.reason,
				first_seen     = EXCLUDED.first_seen,
				last_seen      = EXCLUDED.last_seen,
				count          = EXCLUDED.count,
				ever_succeeded = EXCLUDED.ever_succeeded,
				collected_at   = EXCLUDED.collected_at,
				updated_at     = now()
		`

		kinds := make([]string, 0, len(result.Entries))
		subjects := make([]string, 0, len(result.Entries))
		for _, e := range result.Entries {
			if _, err := tx.Exec(ctx, stmt,
				deviceID, e.Kind, e.Subject, e.Reason, e.FirstSeen, e.LastSeen, e.Count, e.EverSucceeded, collectedAt,
			); err != nil {
				return written, result.Dropped, fmt.Errorf("upsert agent health %q/%q: %w", e.Kind, e.Subject, err)
			}
			written++
			kinds = append(kinds, e.Kind)
			subjects = append(subjects, e.Subject)
		}

		if result.Dropped > 0 || result.Capped {
			// Incomplete snapshot — see the prune-safety doc comment above.
			// Upsert what survived, but do not draw any conclusion from what's
			// absent.
			if logger != nil {
				logger.Warn("skipping agent_health clear-on-recovery prune: reported set is incomplete",
					"device_id", deviceID, "dropped", result.Dropped, "capped", result.Capped)
			}
		} else {
			// Clear-on-recovery: delete rows whose (kind, subject) is not
			// among the entries just reported. unnest($2,$3) walks the two
			// parallel arrays as pairs; NOT EXISTS a matching pair means the
			// row is stale — the capability it names has recovered (or the
			// agent stopped tracking it). Only reached when the reported set
			// above is complete (no drops, no capping) — see the
			// prune-safety doc comment. The whole-payload staleness check
			// already happened above (under the watermark lock), so no
			// further recency guard is needed here.
			if _, err := tx.Exec(ctx, `
				DELETE FROM device_agent_health dah
				WHERE dah.device_id = $1::uuid
				AND NOT EXISTS (
					SELECT 1 FROM unnest($2::text[], $3::text[]) AS r(kind, subject)
					WHERE r.kind = dah.kind AND r.subject = dah.subject
				)
			`, deviceID, kinds, subjects); err != nil {
				return written, result.Dropped, fmt.Errorf("prune stale agent health rows for device %s: %w", deviceID, err)
			}
		}
	}

	if err := advanceAgentHealthWatermark(ctx, tx, deviceID, collectedAt); err != nil {
		return written, result.Dropped, err
	}
	return written, result.Dropped, nil
}

// advanceAgentHealthWatermark sets device_agent_health_watermark.collected_at
// to collectedAt for this device. Callers only reach this after already
// confirming collectedAt is not older than the current watermark (under the
// row lock lockAgentHealthWatermark took), so this is always a monotonic,
// non-decreasing move — never a step backward.
func advanceAgentHealthWatermark(ctx context.Context, tx pgx.Tx, deviceID string, collectedAt time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE device_agent_health_watermark
		SET collected_at = $2, updated_at = now()
		WHERE device_id = $1::uuid
	`, deviceID, collectedAt); err != nil {
		return fmt.Errorf("advance agent health watermark for device %s: %w", deviceID, err)
	}
	return nil
}
