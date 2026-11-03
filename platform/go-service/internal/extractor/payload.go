// Package extractor turns rows in raw_payloads into typed rows in
// devices / device_apps / compliance_signals. One row in raw_payloads is one
// snapshot from a single endpoint — the extractor upserts the device, replaces
// the JSONB snapshot columns, appends compliance_signals rows, and upserts
// device_apps. It is intentionally read-many / write-many: idempotent on
// re-runs, safe to crash and restart.
//
// Schema versioning: this package speaks schema_version 2 (collector v0.2.0+).
// Older payloads are rejected with extraction_error rather than partially
// processed — a future migration can backfill them once we decide whether to
// run the v1 extractor in parallel or upcast on the fly.
package extractor

import "encoding/json"

// payload mirrors the JSON document that patched-collect.sh emits.
// Numeric fields use pointer types where the field may be absent — distinguishes
// "key absent / unknown" from "key present, value zero" cleanly.
type payload struct {
	SchemaVersion         int                        `json:"schema_version"`
	Platform              string                     `json:"platform"` // "macos" or "windows"; absent in v2 (defaults to "macos")
	Agent                 string                     `json:"agent"`
	AgentVersion          string                     `json:"agent_version"`
	TenantID              string                     `json:"tenant_id"`
	CollectedAt           string                     `json:"collected_at"`
	InventoryCapabilities *inventoryCapabilitiesPart `json:"inventory_capabilities,omitempty"`

	// device_class / installation_type / os_caption (PAT-1960; Windows agent
	// side is PAT-1959). Top level, deliberately — device_class is a
	// property of the machine, not of the OS, matching where the
	// devices.device_class column lives; os_caption is only a sensible name
	// at this level (inside the "os" object it would just be "caption").
	// Optional and additive: absent on every payload before that agent
	// release, and always absent from macOS payloads — the envelope stays
	// platform-neutral, macOS simply never populates them.
	//
	// DeviceClass: "workstation" | "server" | "domain_controller" | the
	// literal "unknown" (a genuine report the agent's source was absent,
	// unreadable or contradictory — never a guess). An empty/absent field,
	// an unrecognised value, or the literal "unknown" all resolve to
	// devices.device_class = 'unknown' in upsertDevice; only the literal
	// "unknown" and unrecognised values are distinguished from an absent
	// field for the "must not downgrade an already-known classification"
	// rule — see resolveDeviceClass.
	DeviceClass string `json:"device_class,omitempty"`
	// InstallationType is the verbatim Windows registry InstallationType
	// value ("Client" | "Server" | "Server Core"). Informational only —
	// DeviceClass (above), not this field, drives rule matching.
	InstallationType string `json:"installation_type,omitempty"`
	// OSCaption is the verbatim WMI Win32_OperatingSystem.Caption string,
	// e.g. "Microsoft Windows Server 2022 Standard". Informational only.
	OSCaption string `json:"os_caption,omitempty"`

	// Platform-neutral metering collection status. Empty means not reported;
	// no null app reading proves non-use, even when this status is ok.
	MeteringStatus        string `json:"metering_status"`
	MeteringUserHiveCount *int   `json:"metering_user_hive_count"`
	MeteringRecordCount   *int   `json:"metering_record_count"`

	Device           devicePart      `json:"device"`
	OS               osPart          `json:"os"`
	Hardware         json.RawMessage `json:"hardware"` // Stored verbatim in devices.hardware.
	Compliance       complianceMap   `json:"compliance"`
	SecurityTools    json.RawMessage `json:"security_tools"`    // []  →  devices.security_inventory.security_tools
	SystemExtensions json.RawMessage `json:"system_extensions"` // []  →  devices.security_inventory.system_extensions
	BackgroundItems  json.RawMessage `json:"background_items"`  // []  →  devices.security_inventory.background_items
	ICloud           iCloudPart      `json:"icloud"`
	Apps             []appPart       `json:"apps"`
	// AppsPresent is set by processRow from the raw JSON object. It preserves
	// the difference between an authoritative empty application snapshot and
	// an old or malformed payload that omitted the required apps key.
	AppsPresent bool `json:"-"`
	// AppsAbsenceWithheld is set by processRow (PAT-2063) when this report
	// may not be read as evidence that an unreported application is gone:
	// collection_status.apps said partial or unavailable, the status was
	// inconsistent with the array, or an agent that sends no status tripped
	// the prune safety valve. It withholds the device_apps prune and the
	// application absence scopes (all_software, windows_winget). The zero
	// value keeps the historical behaviour, so callers that build a payload
	// by hand are unaffected.
	AppsAbsenceWithheld bool `json:"-"`
	// AppsUserScopesSeen is set by processRow (PAT-2075) from upsertApps:
	// the (device_apps row, user) pairs this report listed. Never decoded.
	AppsUserScopesSeen appUserScopeSet `json:"-"`
	// AppsLegacyHeld is set by processRow (PAT-2075) from upsertApps: the
	// device_apps ids of legacy user-located machine-scope rows this report
	// had no authority over and therefore held. Never decoded.
	AppsLegacyHeld []int64 `json:"-"`

	// Added by collector PAT-300/481. The violations array: an element is only
	// ever present for a control the agent flagged, so this carries Fail state,
	// never Pass. Positive attestation lives in ComplianceAssessments below
	// (PAT-913, Option B) — the two are read together in buildSignalsMap.
	ComplianceFindings []complianceFinding `json:"compliance_findings,omitempty"`

	// Added by PAT-913 (Option B). The set of finding-based controls the agent
	// actually evaluated this run — the sole source of positive "Pass"
	// attestations. A critical finding-control scores Pass ONLY when it appears
	// in ControlsAssessed AND has no matching entry in ComplianceFindings; a
	// control absent from the list is unknown, which for the critical finding
	// rules means fail (treat_unknown_as='fail', migration 0083).
	//
	// A value type, not a pointer: a payload with the key absent — every agent
	// deployed before PAT-913 — unmarshals to the zero value (empty
	// ControlsAssessed), which yields no Pass attestations. That is exactly the
	// intended never-attested behaviour, so there is no case where "section
	// absent" and "controls_assessed: []" must score differently and no
	// nil/empty distinction is needed.
	ComplianceAssessments complianceAssessments `json:"compliance_assessments"`

	// Added by collector 0.3.0. Both optional — older collectors emit neither
	// and the extractor handles their absence gracefully.
	PendingUpdates json.RawMessage `json:"pending_updates,omitempty"` // []  →  devices.pending_updates JSONB
	Patches        []patchPart     `json:"patches,omitempty"`         // → upserted into patches table

	// Added by collector PAT-216 (macOS System Keychain certs). Pointer type
	// is intentional: nil means the key was absent (older agent, no-op) while
	// a non-nil pointer to an empty slice means the agent reported zero certs
	// (prune all existing rows). A plain []certPart would conflate these two
	// cases because both marshal from JSON as the slice zero value.
	Certificates *[]certPart `json:"certificates"`

	// Added by PAT-1732: the general top-level home for the collection status
	// of top-level array sections — today just "certificates". A collector
	// that fails to enumerate a certificate store can now say
	// collection_status.certificates = "unavailable" or "partial" instead of
	// choosing between an empty array (which upsertCertificates' three-way
	// semantics would otherwise read as authoritative absence and prune every
	// stored row) and omitting the certificates key entirely (safe, but
	// invisible to the server — see upsertCertificates for the exact
	// behaviour per status). Optional; absent object, or an absent
	// "certificates" key within it, means "complete" — the historical
	// three-way semantics, unchanged. Nested objects such as hardware_health
	// keep their own nested collection_status object rather than using this
	// one — see hwCollectionStatusPart.
	CollectionStatus *collectionStatusPart `json:"collection_status"`

	// Added by collector PAT-251 (macOS hardware health). Pointer type for the
	// same nil=absent semantics: nil → older agent, no-op; non-nil → replace
	// the device_hardware / device_storage_volume / device_disk snapshot.
	HardwareHealth *hardwareHealthPart `json:"hardware_health"`

	// Added by both endpoint agents under PAT-1974: the standing local-
	// administrator roster behind the local_admin_count compliance signal
	// (local_admin_count itself is unchanged — it stays in Compliance above).
	// Pointer type for the same nil=absent semantics as HardwareHealth/
	// Certificates: nil means the key is absent entirely — an agent that
	// predates PAT-1974 — and is a strict no-op; every current agent (Windows
	// and macOS) sends this key unconditionally, complete or degraded.
	LocalAdmins *localAdminsPart `json:"local_admins"`

	// Added by the Windows agent under PAT-2262 (first slice of PAT-1863):
	// BIOS, system and baseboard identity as the firmware reports it. nil
	// means the key is absent: an agent that predates the block, or macOS,
	// which does not collect it in this slice. That is "not reported", a
	// strict no-op, and a different claim from a present block whose
	// collection_status is "unavailable". See firmware.go.
	Firmware *firmwarePart `json:"firmware"`

	// Added by the Windows agent under PAT-2263: installed and loaded kernel
	// and file-system drivers by hash, plus the vulnerable driver blocklist
	// enforcement state. nil means the key is absent (an older agent, or
	// macOS): "not reported", a strict no-op. See kernel_drivers.go.
	KernelDrivers *kernelDriversPart `json:"kernel_drivers"`

	// Added by the macOS agent under PAT-2012 (updater macos/lib/homebrew.sh),
	// consumed under PAT-2013. Pointer type for nil=absent semantics: nil is
	// an agent that predates the collector or holds it off the wire, and is a
	// strict no-op. Present, it carries its own collection_status and is
	// stored per upsertHomebrewInventory. Ignored on non-macOS payloads.
	Homebrew *homebrewPart `json:"homebrew"`

	// Added by both agents under PAT-2017 to PAT-2020 and consumed under
	// PAT-2021 (see tooling_payload.go). Pointer types for nil=absent: an
	// agent that predates a collector, or holds it off the wire, omits the
	// key and the extractor treats that as a strict no-op. Present, each
	// carries its own collection_status. Both platforms send the same shape.
	IdeExtensions   *ideExtensionsPart   `json:"ide_extensions"`
	PackageManagers *packageManagersPart `json:"package_managers"`
	LocalModels     *localModelsPart     `json:"local_models"`
	McpServers      *mcpServersPart      `json:"mcp_servers"`

	// Added by collector PAT-125 (browser extension inventory). Optional — older
	// agents omit the key; both nil and empty slice are a no-op in the extractor.
	BrowserExtensions []browserExtensionPart `json:"browser_extensions"`
	// BrowserExtensionsPresent is set by processRow from the raw JSON object
	// (PAT-2067): true when browser_extensions was sent as an array, even an
	// empty one. collection_status.safari_extensions = "complete" with no
	// array at all is inconsistent and grants no Safari absence authority.
	BrowserExtensionsPresent bool `json:"-"`

	// PAT-2055: completeness of BrowserExtensions, per user and browser, plus
	// whether the collector hit its row cap. nil = key absent (an agent that
	// predates PAT-2055): unknown, a strict no-op. Validated strictly by
	// validateBrowserExtensionsStatus; stored by upsertBrowserExtensionsStatus.
	BrowserExtensionsStatus *browserExtensionsStatusPart `json:"browser_extensions_status"`

	// Added by collector PAT-116 (primary user attribution). macOS emits this
	// as a top-level "primary_user" object; Windows emits the same data as flat
	// fields inside the "device" block. The extractor merges both into devices
	// columns. Pointer: nil = key absent (older agent), no-op.
	PrimaryUser *primaryUserPart `json:"primary_user,omitempty"`

	// Added by both endpoint agents under PAT-679 (macOS, lib/backup.sh) /
	// PAT-680 (Windows, InventoryBackupStatus) — server ingestion is PAT-948.
	// json.RawMessage, not a typed pointer struct: a malformed shape (a field
	// present with the wrong JSON type) must not abort the ENTIRE payload
	// unmarshal in processRow — the same isolation Hardware/SecurityTools/
	// SystemExtensions/BackgroundItems already get for exactly this reason.
	// Absent/empty/null → older agent, no-op (existing devices.backup_status
	// snapshot preserved). Decoded defensively by parseBackupStatus (upsert.go):
	// a decode failure is logged and treated the same as absent, so one
	// malformed backup_status section never poisons the rest of the device
	// snapshot — matching the robustness PAT-871 established for individual
	// browser_extensions array elements, applied here to a top-level section.
	BackupStatus json.RawMessage `json:"backup_status,omitempty"`

	// Added by both endpoint agents under PAT-1064 (server ingestion; PAT-1065
	// macOS / PAT-1066 Windows agents send it). json.RawMessage, not a typed
	// struct: a malformed shape must not abort the ENTIRE payload unmarshal in
	// processRow — same isolation Hardware/SecurityTools/SystemExtensions/
	// BackgroundItems/BackupStatus already get, for exactly this reason.
	//
	// Critical distinction this type must preserve: "key absent" (an agent
	// that predates this protocol) must be distinguishable from "key present
	// with degraded: []" (a current agent actively reporting "I am fine right
	// now"). Both collapse to the same Go zero value if this were anything
	// other than RawMessage with omitempty — which is why BackupStatus's exact
	// treatment is reused here rather than a plain struct or pointer-to-slice.
	// Decoded defensively by parseAgentHealth (upsert.go): a decode failure on
	// the top-level object is logged and treated the same as absent (no
	// opinion, existing device_agent_health rows preserved); a decode failure
	// on ONE element inside "degraded" is logged and that element alone is
	// skipped, so a single malformed fault report can never take the rest of
	// the device's inventory upload down with it (PAT-871 precedent).
	AgentHealth json.RawMessage `json:"agent_health,omitempty"`

	// Added by the macOS agent under PAT-1667 (lib/config_profiles.sh);
	// server ingestion is PAT-1668. The device-scope configuration profiles
	// actually applied to this Mac, plus the enrolled MDM server URL and
	// supervision state.
	//
	// This is APPLIED configuration, never authored MDM policy. The two
	// diverge routinely (a pending push, a locally removed profile, a stale
	// cached push), so nothing downstream may relabel it as policy or merge
	// it with the Intune authored-policy path (internal/intune, PAT-1662/
	// 1664) into a single record.
	//
	// json.RawMessage, not a typed struct: a malformed shape must not abort
	// the ENTIRE payload unmarshal in processRow — the same isolation
	// Hardware/SecurityTools/BackupStatus/AgentHealth already get. Decoded
	// defensively by parseAppliedConfiguration (applied_config.go); a decode
	// failure is logged and treated exactly like absent.
	//
	// Absence and an empty profile list are NOT the same thing and must stay
	// distinguishable: an absent key means an agent that predates PAT-1667
	// and no snapshot row is written at all, while collection_status "ok"
	// with zero profiles is a real observation of an unenrolled Mac.
	// Similarly, collection_status "rate_limited"/"unavailable" means the
	// run happened but could not read state — recorded, flagged, and never
	// usable as a diff baseline.
	AppliedConfiguration json.RawMessage `json:"applied_configuration,omitempty"`

	// Added under PAT-1806. Server-side receiving/persisting/rollup only —
	// neither endpoint agent sends this key yet (that is a separate
	// follow-up ticket in the `updater` repo, out of scope here). This field
	// exists so the server accepts and stores the block the moment an agent
	// starts sending it, with zero behaviour change for every agent that
	// hasn't heard of it.
	//
	// The OS-update-currency verdict both agents already compute locally
	// (SOFA feed on macOS, WUA COM on Windows) but do not yet upload —
	// installed/latest/target OS, currency state, severity, and whether the
	// gap is security-relevant or actively exploited.
	//
	// json.RawMessage, not a typed struct, for the same reason BackupStatus/
	// AgentHealth/AppliedConfiguration above are: a malformed shape must not
	// abort the ENTIRE payload unmarshal in processRow. Decoded defensively
	// by parseOSUpdate (upsert.go); a decode failure is logged and treated
	// exactly like absent (existing device_os_update row preserved).
	//
	// Absence is a real, distinct state, never inferred as "current" —
	// PAT-1805 established that discipline for pending_updates (a NULL
	// patching state must never be counted as up to date) and this field
	// follows it: a device with no device_os_update row has never reported
	// this block and must land in a "not reported" bucket, never "current".
	OSUpdate json.RawMessage `json:"os_update,omitempty"`
}

// osUpdatePart mirrors the top-level "os_update" object (PAT-1806, fixed
// under PAT-1862 to match the real contract). Field shape verified against
// updater's contracts/update-status.schema.json — this is no longer a guess
// inferred from the ticket description.
//
// InstalledOS/State/Severity/SecurityRelevant/ActivelyExploited/
// DeferralsRemaining are plain (non-pointer) because the real contract
// always sends them: the agent's verdict always knows what's installed, the
// currency state, its severity, whether the gap is security-relevant or
// actively exploited, and its deferral count, even when there is nothing
// outstanding. LatestOS/Deadline/ReleaseAgeDays/TargetOS are independently
// nullable: LatestOS is null when SOFA/WUA is unavailable, Deadline when
// there is no policy deadline, ReleaseAgeDays when the feed doesn't expose a
// release date for the target version.
//
// TargetOS (PAT-2123): flipped from a plain required string to nullable.
// The Windows agent may report a pending update (state=update_required etc.)
// before WUA has resolved which build it is updating to — Windows Update can
// surface "an update is available" ahead of resolving the exact target
// version. Absent-key and explicit-null both decode to nil here and mean
// "pending, target unknown", never "current". upsertOSUpdate (upsert.go)
// writes SQL NULL for nil rather than an empty string, and — because the
// whole os_update block is upserted as one unconditional overwrite whenever
// it is present (never field-level COALESCE) — a fresh report with TargetOS
// nil clears any previously-stored target rather than preserving a stale
// one, exactly as it should: the new report is saying "the old target may
// no longer be right", not "I have nothing to say about the target".
type osUpdatePart struct {
	InstalledOS        string  `json:"installed_os"`
	LatestOS           *string `json:"latest_os"` // nullable: null when SOFA/WUA unavailable
	TargetOS           *string `json:"target_os"` // nullable: null/absent when pending update's target version is not yet known
	State              string  `json:"state"`
	Severity           string  `json:"severity"`
	SecurityRelevant   bool    `json:"security_relevant"`
	ActivelyExploited  bool    `json:"actively_exploited"`
	Deadline           *string `json:"deadline"` // RFC3339 UTC, nullable
	DeferralsRemaining int     `json:"deferrals_remaining"`
	ReleaseAgeDays     *int    `json:"release_age_days"`
	CheckedAt          string  `json:"checked_at"` // RFC3339 UTC, always present
}

// agentHealthEnvelope mirrors the top-level "agent_health" object (PAT-1064).
//
// Degraded is *[]json.RawMessage — a pointer to a slice, not a plain slice —
// for two independent reasons layered on top of each other:
//
//  1. Each element is carried as raw bytes, not unmarshaled straight into
//     []agentHealthEntryPart, so ONE wrong-typed element (e.g. count sent as
//     a JSON string) can't fail the whole slice's json.Unmarshal call and
//     take the entire agent_health section down with it — the same "one bad
//     element poisons everything" failure PAT-871 fixed for
//     browser_extensions. sanitizeAgentHealthEntries (upsert.go) decodes and
//     validates elements one at a time.
//  2. The pointer itself exists to keep "degraded" key absent or explicitly
//     null" distinguishable from "degraded key present with a real array"
//     (review round 4, FIX 13). A plain []json.RawMessage field collapses
//     three distinct wire shapes — {}, {"degraded":null}, and
//     {"degraded":[]} — into the SAME Go zero value (nil, len 0), because
//     encoding/json treats "key absent" and "explicit null" identically for
//     a slice field: neither is an error, both just leave the field at its
//     zero value. upsertAgentHealth used to read that zero value as
//     "degraded: [] — agent asserts all clear" and delete every existing
//     health row for the device, so an agent shipping a bare {} (or
//     explicit null) would silently resolve real faults on every device it
//     ran on, no malformed data or race required. A pointer field keeps the
//     distinction encoding/json DOES preserve for slices: unmarshaling a
//     genuine JSON `[]` always produces a non-nil pointer to an empty
//     slice, while an absent key or explicit `null` leaves the pointer
//     nil — the same *[]T pattern already used by Certificates above for
//     exactly this reason.
type agentHealthEnvelope struct {
	Degraded      *[]json.RawMessage `json:"degraded"`
	UpdateChannel json.RawMessage    `json:"update_channel"`
}

// agentHealthEntryPart mirrors one element of agent_health.degraded: a
// capability the agent could not carry out this run. kind/subject/reason
// vocabulary is documented (not enforced) in docs/PAYLOAD_SCHEMA.md — the
// server stores whatever the agent sends verbatim (after bounds truncation)
// and never rejects on an unrecognised value, so a future agent release with
// a new fault kind never has its entire inventory upload silently dropped.
// EverSucceeded is carried exactly as reported, never inferred server-side:
// the agent is the only party that knows whether a capability has ever
// worked, and today's local-log-only behaviour is exactly what destroys that
// distinction once the log rotates. It is a *bool, not bool, so an explicit
// JSON null is distinguishable from a genuine false: encoding/json decodes
// `"ever_succeeded":null` into the bool zero value (false) without error,
// which would silently assert "this has never worked" — the more alarming
// of the two states — on no evidence at all. sanitizeAgentHealthEntries
// (upsert.go) treats a nil EverSucceeded as a malformed entry and drops it,
// same as any other unusable value; it never defaults the field either way.
type agentHealthEntryPart struct {
	Kind          string `json:"kind"`
	Subject       string `json:"subject"`
	Reason        string `json:"reason"`
	FirstSeen     string `json:"first_seen"` // RFC3339
	LastSeen      string `json:"last_seen"`  // RFC3339
	Count         int64  `json:"count"`
	EverSucceeded *bool  `json:"ever_succeeded"`
}

// backupStatusPart mirrors the top-level "backup_status" object emitted by
// both endpoint agents — macOS lib/backup.sh (PAT-679) and Windows
// InventoryBackupStatus (PAT-680) deliberately share the same field names and
// types, so one Go shape serves both platforms with no per-platform branching.
// Pointer fields are nullable/optional: Windows omits a null field from the
// wire entirely (JsonIgnoreCondition.WhenWritingNull) while macOS always
// emits the key with an explicit JSON null — both forms unmarshal identically
// into a nil pointer here. HasBackup/Stale/SyncOnly are plain bool because
// both agents always emit them, even in the all-false fallback default.
type backupStatusPart struct {
	HasBackup         bool    `json:"has_backup"`
	BackupType        *string `json:"backup_type"`
	LastBackupAt      *string `json:"last_backup_at"`
	LastBackupDaysAgo *int    `json:"last_backup_days_ago"`
	Stale             bool    `json:"stale"`
	SyncOnly          bool    `json:"sync_only"`
	Notes             *string `json:"notes"`
}

// hardwareHealthPart mirrors the top-level "hardware_health" object emitted by
// the macOS agent's hardware health collector (PAT-251).
//
// CollectionStatus (PAT-1720) is optional and, when absent, every section is
// implicitly "complete" — see hwSectionStatus. It exists so a source command
// that fails on the endpoint (battery read, df, diskutil) can say so
// explicitly instead of the agent sending an empty array or
// battery.present=false, which upsertHardwareHealth would otherwise read as
// "this device has no batteries/volumes/disks any more" and delete rows it
// already held. Absence requires authority; a failed collection is not that
// authority.
type hardwareHealthPart struct {
	Battery          batteryPart             `json:"battery"`
	Storage          []storageVolumePart     `json:"storage"`
	Disks            []diskPart              `json:"disks"`
	CollectionStatus *hwCollectionStatusPart `json:"collection_status"`
}

// hwCollectionStatusPart is the optional "hardware_health.collection_status"
// object. Each field is independently optional; an empty string means the
// key was absent from the wire, which hwSectionStatus treats identically to
// an absent CollectionStatus object — both mean "complete".
type hwCollectionStatusPart struct {
	Battery string `json:"battery"`
	Storage string `json:"storage"`
	Disks   string `json:"disks"`
}

// collectionStatus (PAT-1732) enumerates the recognised collection_status
// values, shared by every collection_status object the payload carries: the
// nested hardware_health.collection_status (PAT-1720) and the top-level
// collection_status object (PAT-1732). hwCollectionStatus below is an alias
// of this exact type — hardware_health predates the generalisation and keeps
// its own names so its call sites and tests needed no renaming.
type collectionStatus string

const (
	statusComplete    collectionStatus = "complete"
	statusPartial     collectionStatus = "partial"
	statusUnavailable collectionStatus = "unavailable"
)

// hwCollectionStatus is hardware_health's own name for the shared
// collectionStatus type (PAT-1720 predates PAT-1732's generalisation).
type hwCollectionStatus = collectionStatus

const (
	hwStatusComplete    = statusComplete
	hwStatusPartial     = statusPartial
	hwStatusUnavailable = statusUnavailable
)

// collectionStatusPart is the optional top-level "collection_status" object
// (PAT-1732). Certificates is independently optional, following
// hwCollectionStatusPart's precedent: an empty string means the key was
// absent from the wire, which normaliseCollectionStatus treats identically
// to an absent CollectionStatus object — both mean "complete".
//
// Apps (PAT-2063) is different: an absent apps key is NOT read as complete.
// It means "no signal", the case every agent before PAT-2063 is in, and the
// device_apps prune then falls back to the safety valve in apps_authority.go.
// Only an explicit "complete" on a schema v3 payload grants apps absence
// authority unconditionally.
//
// SafariExtensions (PAT-2067) follows apps: an absent key is "no signal",
// and Safari rows in device_browser_extensions are then never marked absent.
// Only "complete" on a schema v3 payload grants Safari absence authority;
// see safari_authority.go.
//
// PAT-2075: Apps speaks for the machine-wide scope only, the apps rows sent
// with no user_account. AppsUsers is the per-user scope's own authority:
// each entry names one user whose per-user inventory the agent read, and
// only an entry marked "complete" lets this report prune that user's rows.
// A user missing from AppsUsers is never pruned. See apps_users.go.
type collectionStatusPart struct {
	Certificates     string               `json:"certificates"`
	Apps             string               `json:"apps"`
	SafariExtensions string               `json:"safari_extensions"`
	AppsUsers        []appsUserStatusPart `json:"apps_users"`
}

// appsUserStatusPart is one entry of collection_status.apps_users
// (PAT-2075). UserAccount matches apps[].user_account exactly (after the
// same trim, appsUserKey; a value over 128 characters grants nothing).
//
// Home is the optional absolute path of the user's home directory as the
// agent resolved it. It is used only to decide who owns a legacy
// user-located machine-scope row; see apps_legacy_user.go.
type appsUserStatusPart struct {
	UserAccount      string  `json:"user_account"`
	CollectionStatus string  `json:"collection_status"`
	Home             *string `json:"home"`
}

// localAdminsPart mirrors the top-level "local_admins" object emitted by both
// endpoint agents (PAT-1974): the standing local-administrator roster behind
// the local_admin_count compliance signal. Unlike hardware_health, which has
// three independent sub-sections and therefore a nested per-key
// collection_status object, local_admins has exactly one section, so its
// collection_status is a single string field directly on the object — the
// same shape applied_configuration.collection_status uses.
//
// ABSENCE REQUIRES AUTHORITY. Both agents omit the accounts key entirely
// (never send []) whenever CollectionStatus is not "complete": an empty
// array under a degraded read would claim "this device has zero standing
// admins", the exact violation this ticket exists to close. Accounts is a
// plain slice rather than a pointer, unlike Certificates — every current
// agent always sends collection_status explicitly (it is a required field on
// both platforms, never defaulted), so there is no "status absent" ambiguity
// for this object the way there is for the top-level certificates pairing;
// an agent that omits accounts under "complete" is malformed regardless, and
// treating that as an empty roster is the same conservative read the
// certificates "complete" + empty-array case already gets.
type localAdminsPart struct {
	CollectionStatus string           `json:"collection_status"`
	Accounts         []localAdminPart `json:"accounts"`
}

// localAdminPart mirrors one entry of local_admins.accounts. Sid is
// Windows-only (the stable key for a principal whose name can change or fail
// to resolve); macOS omits it entirely, decoding to nil here.
//
// AccountState (PAT-1992) is the Windows agent's read of the built-in RID-500
// Administrator's enabled state: "enabled" | "disabled" | "unknown". nil means
// the key was absent: an agent that predates the field, or an entry the agent
// never read (every non-built-in entry, and every macOS entry, since macOS
// filters root out of the roster). "unknown" means a read was attempted and
// did not establish the state; it must never be treated as "disabled".
type localAdminPart struct {
	Name          string  `json:"name"`
	PrincipalType string  `json:"principal_type"` // "user" | "group" | "unresolved"
	Builtin       bool    `json:"builtin"`
	Sid           *string `json:"sid"`
	AccountState  *string `json:"account_state"`
}

// collectionStatusSnapshot mirrors the shape persisted in
// devices.collection_status (PAT-1732, migration 0128), merged in place per
// ingest by upsertCollectionStatus rather than replaced wholesale — the
// point of the column is that a section this ingest didn't mention keeps
// whatever status an earlier ingest last reported for it. Every field is
// independently optional (omitempty): a key absent from the stored JSON
// means that section has never been reported at all, which the platform
// must not read as "complete" — only a present key with that exact value
// means "complete".
type collectionStatusSnapshot struct {
	Certificates   string                      `json:"certificates,omitempty"`
	HardwareHealth *hwCollectionStatusSnapshot `json:"hardware_health,omitempty"`
	LocalAdmins    string                      `json:"local_admins,omitempty"`
	Apps           string                      `json:"apps,omitempty"`
	// SafariExtensions (PAT-2067) is the wire value as sent (normalised).
	// Whether it granted authority is recorded on
	// browser_extension_device_state, not here.
	SafariExtensions string `json:"safari_extensions,omitempty"`
}

// hwCollectionStatusSnapshot is the nested "hardware_health" object within
// devices.collection_status — one key per hardware_health.collection_status
// section (PAT-1720), independently optional for the same reason as
// collectionStatusSnapshot itself.
type hwCollectionStatusSnapshot struct {
	Battery string `json:"battery,omitempty"`
	Storage string `json:"storage,omitempty"`
	Disks   string `json:"disks,omitempty"`
}

// hwSectionStatus reads the collection status the agent reported for one
// hardware_health section ("battery", "storage" or "disks"), defaulting to
// complete when the collection_status object is absent entirely or the key
// within it is absent — both cases mean an old agent, or a fully-successful
// run, and must behave exactly like today's replace-on-write ingest.
func hwSectionStatus(cs *hwCollectionStatusPart, section string) string {
	if cs == nil {
		return ""
	}
	switch section {
	case "battery":
		return cs.Battery
	case "storage":
		return cs.Storage
	case "disks":
		return cs.Disks
	default:
		return ""
	}
}

// normaliseCollectionStatus maps a raw wire value (or the empty string for
// an absent key) onto a known collectionStatus. An unrecognised, non-empty
// value becomes statusUnavailable rather than statusComplete: a status this
// code does not understand is not evidence collection succeeded, and the
// conservative reading is the one that cannot manufacture a false
// mass-removal signal. The second return says whether the input was
// recognised (an absent key counts as recognised-complete), so a caller can
// log the raw value it dropped. Shared by every collection_status object in
// the payload (PAT-1720 hardware_health, PAT-1732 top-level certificates).
func normaliseCollectionStatus(raw string) (collectionStatus, bool) {
	switch collectionStatus(raw) {
	case "":
		return statusComplete, true
	case statusComplete, statusPartial, statusUnavailable:
		return collectionStatus(raw), true
	default:
		return statusUnavailable, false
	}
}

// normaliseHWCollectionStatus is hardware_health's own name for
// normaliseCollectionStatus (PAT-1720 predates PAT-1732's generalisation).
func normaliseHWCollectionStatus(raw string) (hwCollectionStatus, bool) {
	return normaliseCollectionStatus(raw)
}

// batteryPart is the "battery" sub-object within hardware_health.
// max_capacity_pct is *int (integer percentage, e.g. 94 for 94 %) — the
// collector strips the % sign and casts to int. No float permitted; a float
// value in the payload indicates a parse bug upstream.
type batteryPart struct {
	Present        bool    `json:"present"`
	CycleCount     *int    `json:"cycle_count"`
	Condition      *string `json:"condition"`
	MaxCapacityPct *int    `json:"max_capacity_pct"`
}

// storageVolumePart is one element of the "storage" array within hardware_health.
type storageVolumePart struct {
	Mount      string `json:"mount"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedPct    int    `json:"used_pct"`
}

// diskPart is one element of the "disks" array within hardware_health.
type diskPart struct {
	Device      string `json:"device"`
	SmartStatus string `json:"smart_status"`
	Internal    bool   `json:"internal"`
	SolidState  bool   `json:"solid_state"`
}

// certPart mirrors one element of the "certificates" array emitted by the
// macOS agent's System Keychain collector (PAT-216/PAT-220).
type certPart struct {
	SubjectCN          string   `json:"subject_cn"`
	IssuerCN           string   `json:"issuer_cn"`
	SHA1               string   `json:"sha1"`
	NotAfter           string   `json:"not_after"`            // RFC3339 expiry timestamp
	DaysUntilExpiry    int      `json:"days_until_expiry"`    // agent snapshot, stored as-is; not used for live queries
	EKU                []string `json:"ext_key_usage"`        // PAT-220: Extended Key Usage OID strings
	BasicConstraintsCA bool     `json:"basic_constraints_ca"` // PAT-220: CA:TRUE basicConstraints
	IsSelfSigned       bool     `json:"is_self_signed"`       // PAT-220: subject == issuer
	Store              string   `json:"store"`                // PAT-1738: "My"/"Root"/"CA" (Windows) or "System" (macOS); absent defaults to "My" in upsertCertificates
}

type patchPart struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	InstalledAt *string `json:"installed_at"` // nullable; collector emits null when date parsing failed
	DateRaw     string  `json:"date_raw"`     // kept for diagnostics; not stored
}

type devicePart struct {
	Serial       string `json:"serial"`
	HWUUID       string `json:"hw_uuid"`
	Hostname     string `json:"hostname"`
	ComputerName string `json:"computer_name"`
	HWModel      string `json:"hw_model"`
	Arch         string `json:"arch"`
	LastBoot     string `json:"last_boot"`
	// Primary-user attribution (PAT-116). These fields are emitted by the
	// Windows collector directly in the device block (flat fields). The macOS
	// collector emits a top-level "primary_user" object instead (see
	// primaryUserPart). Either path populates the same devices columns.
	PrimaryUserAccount string `json:"primary_user_account,omitempty"`
	PrimaryUserDisplay string `json:"primary_user_display,omitempty"`
	PrimaryUserSource  string `json:"primary_user_source,omitempty"`
}

// primaryUserPart mirrors the top-level "primary_user" block emitted by the
// macOS collector (PAT-116). The Windows collector emits the same data as flat
// fields inside the device block; the extractor merges both paths.
type primaryUserPart struct {
	Account string `json:"account"`
	Source  string `json:"source"`
}

type osPart struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}

// complianceMap captures the heterogeneous v2 compliance bag. Values are a mix
// of strings and integers; we keep them as json.RawMessage so the extractor
// can render each one as a string for compliance_signals.value without
// losing precision on numeric fields.
type complianceMap map[string]json.RawMessage

type iCloudPart struct {
	SignedIn string `json:"signed_in"`
}

type appPart struct {
	Name           string  `json:"name"`
	Version        string  `json:"version"`
	Identifier     string  `json:"identifier"`                // v3+: cross-platform primary identifier
	IdentifierKind string  `json:"identifier_kind,omitempty"` // PAT-1399: "winget" only for canonical Winget package IDs; "native" otherwise.
	BundleID       string  `json:"bundle_id"`                 // v2 macOS fallback; extractor prefers Identifier
	Publisher      string  `json:"publisher"`                 // Windows: registry Publisher; macOS: may be absent
	Path           string  `json:"path"`
	SizeMB         float64 `json:"size_mb"`
	ModifiedAt     string  `json:"modified_at"`
	Architecture   string  `json:"architecture"`
	SHA256         string  `json:"sha256"`
	TeamID         string  `json:"team_id"`
	SignedBy       string  `json:"signed_by"`
	Notarized      *bool   `json:"notarized"` // pointer: absent from Windows payloads (no codesign concept) must stay distinguishable from a real false, not silently zero-valued (PAT-1828)
	// SigningStatus and NotarizationStatus (PAT-2112, macOS only) are the
	// collector's explicit codesign and Gatekeeper evidence: signed, adhoc,
	// unsigned or error, and notarized, not_notarized or unknown. Empty is
	// not reported; macOSSigningStatus / macOSNotarizationStatus drop any
	// other value.
	SigningStatus      string `json:"signing_status"`
	NotarizationStatus string `json:"notarization_status"`
	// InstallationEvidence (PAT-2113, Windows only) is the agent's
	// per-installation Authenticode evidence: for reviewed evidence targets,
	// and since updater #668 (PAT-2116) for every app row. Only the fields
	// the platform stores are decoded; the agent's other members (catalogue
	// binding, paths, hash, errors) stay in the raw body.
	InstallationEvidence *appInstallationEvidencePart `json:"installation_evidence"`
	// Software metering (v0.10.0+ macOS). Pointers so an absent block (older
	// agents, or non-macOS payloads) is distinguishable from a real zero and
	// never clobbers a previously-stored value on re-extraction.
	UsageEvidence *string `json:"usage_evidence,omitempty"` // PAT-2328: absent = not reported, never non-use
	LastUsedAt    *string `json:"last_used_at"`             // Spotlight kMDItemLastUsedDate (ISO 8601); nil = no recorded usage
	LaunchCount   *int    `json:"launch_count"`             // Spotlight kMDItemUseCount — LIFETIME cumulative; nil = unknown
	// UserAccount (PAT-2075) names the user whose per-user inventory holds
	// this app (Windows HKU\<SID>, macOS ~/Applications). Empty or absent is
	// a machine-wide row, which is every row an agent before PAT-2075 sends.
	// A per-user row is pruned only by a report whose
	// collection_status.apps_users lists the same user as complete.
	UserAccount string `json:"user_account"`
}

// appInstallationEvidencePart is the subset of the Windows agent's
// apps[].installation_evidence (updater windows AppInstallationEvidence) the
// platform stores. windowsSignatureEvidence normalises it.
type appInstallationEvidencePart struct {
	SignatureState string `json:"signature_state"`
	Signer         string `json:"signer"`
	// PAT-2116 (updater #668): the pinnable publisher, sent beside valid
	// only, and how the executable was tied to the row.
	SignerThumbprint     string `json:"signer_thumbprint"`
	Issuer               string `json:"issuer"`
	RootThumbprint       string `json:"root_thumbprint"`
	RootKind             string `json:"root_kind"`
	ExecutableResolution string `json:"executable_resolution"`
}

type inventoryCapabilitiesPart struct {
	SchemaVersion                  int  `json:"schema_version"`
	WindowsWingetInventoryComplete bool `json:"windows_winget_inventory_complete"`
}

// complianceFinding mirrors one element of the "compliance_findings" array
// (PAT-300/481). findings are advisory only at T1/T2.
type complianceFinding struct {
	ID       string          `json:"id"`
	Severity string          `json:"severity"`
	Volumes  json.RawMessage `json:"volumes,omitempty"` // PAT-481 detail
}

// complianceAssessments mirrors the "compliance_assessments" object (PAT-913,
// Option B). controls_assessed lists the finding-control IDs the agent ran a
// determination for this run (a sub-check that errored must NOT list its
// control). It is the sole source of positive "Pass" attestations in
// buildSignalsMap: a control is Pass iff it appears here AND carries no finding.
type complianceAssessments struct {
	ControlsAssessed []string `json:"controls_assessed"`
}

// browserExtensionPart is one element of the "browser_extensions" array emitted
// by the macOS agent's browser-extension collector (PAT-125).
type browserExtensionPart struct {
	Browser         string   `json:"browser"`      // "chrome" | "edge" | "firefox"
	Profile         string   `json:"profile"`      // profile directory name
	UserAccount     string   `json:"user_account"` // macOS login name
	ExtensionID     string   `json:"extension_id"`
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Enabled         bool     `json:"enabled"`
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	FromWebstore    bool     `json:"from_webstore"`
	UpdateURL       string   `json:"update_url,omitempty"`
}

// securityInventory is the shape stored in devices.security_inventory.
// Assembled from the four top-level v2 sections that have no typed home yet.
type securityInventory struct {
	SecurityTools    json.RawMessage `json:"security_tools"`
	SystemExtensions json.RawMessage `json:"system_extensions"`
	BackgroundItems  json.RawMessage `json:"background_items"`
	ICloud           iCloudPart      `json:"icloud"`
}

// homebrewPart mirrors the `homebrew` block (PAT-2012 agent, PAT-2013
// platform). Formulae, Casks and Taps are nil when the key is absent, which
// the agent does only for collection_status "failed".
type homebrewPart struct {
	CollectionStatus string                `json:"collection_status"`
	Truncated        *bool                 `json:"truncated"`
	TruncationReason *string               `json:"truncation_reason"`
	Prefixes         []homebrewPrefixPart  `json:"prefixes"`
	Formulae         []homebrewFormulaPart `json:"formulae"`
	Casks            []homebrewCaskPart    `json:"casks"`
	Taps             []homebrewTapPart     `json:"taps"`
	Issues           []homebrewIssuePart   `json:"issues"`
}

type homebrewPrefixPart struct {
	Path             string  `json:"path"`
	Owner            *string `json:"owner"`
	OwnerUID         *int64  `json:"owner_uid"`
	CollectionStatus string  `json:"collection_status"`
	Formulae         int     `json:"formulae"`
	Casks            int     `json:"casks"`
	Taps             int     `json:"taps"`
}

type homebrewFormulaPart struct {
	Prefix                string   `json:"prefix"`
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	Tap                   *string  `json:"tap"`
	InstalledOnRequest    *bool    `json:"installed_on_request"`
	InstalledAsDependency *bool    `json:"installed_as_dependency"`
	InstalledAt           *string  `json:"installed_at"`
	RuntimeDependencies   []string `json:"runtime_dependencies"`
	Homepage              *string  `json:"homepage"`
	SourceURL             *string  `json:"source_url"`
	OptLinked             *bool    `json:"opt_linked"`
	ReceiptStatus         string   `json:"receipt_status"`
	FormulaFileStatus     string   `json:"formula_file_status"`
}

type homebrewCaskPart struct {
	Prefix             string                `json:"prefix"`
	Token              string                `json:"token"`
	Version            *string               `json:"version"`
	VersionsOnDisk     []string              `json:"versions_on_disk"`
	Tap                *string               `json:"tap"`
	InstalledOnRequest *bool                 `json:"installed_on_request"`
	InstalledAt        *string               `json:"installed_at"`
	ReceiptStatus      string                `json:"receipt_status"`
	Apps               []homebrewCaskAppPart `json:"apps"`
}

type homebrewCaskAppPart struct {
	Name   string  `json:"name"`
	Path   *string `json:"path"`
	Exists *bool   `json:"exists"`
}

type homebrewTapPart struct {
	Prefix       string  `json:"prefix"`
	Name         string  `json:"name"`
	Directory    string  `json:"directory"`
	RemoteURL    *string `json:"remote_url"`
	ConfigStatus string  `json:"config_status"`
}

type homebrewIssuePart struct {
	Code string `json:"code"`
	Path string `json:"path"`
}
