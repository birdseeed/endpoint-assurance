package extractor

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// PAT-2263: the kernel_drivers block. Which kernel and file-system driver
// files are installed or loaded on a Windows device, identified by hash, and
// whether Windows is enforcing the Microsoft vulnerable driver blocklist. The
// agent makes no vulnerability claim; the platform matches the hashes against
// Microsoft's recommended driver block rules and loldrivers.io (package
// driverblock), by hash only, never by file name.
//
// Wire shape (Windows agent: InventoryKernelDrivers, KernelDriverInventoryLogic):
//
//	"kernel_drivers": {
//	  "schema_version": 1,
//	  "collection_status": "complete" | "partial" | "unavailable",
//	  "errors": ["services_unreadable", ...],          // fixed codes, <= 16
//	  "enforcement": {
//	    "vulnerable_driver_blocklist": "enabled|disabled|not_set|unknown",
//	    "hvci": "running|configured|off|unknown",
//	    "smart_app_control": "on|evaluation|off|not_present|unknown",
//	    "code_integrity_policy": "enforced|audit|off|unknown",
//	    "blocklist_enforced": "yes|no|unknown"
//	  },
//	  "drivers": [{                                     // omitted when unavailable
//	    "path", "sources", "service_name", "service_type", "start_type",
//	    "loaded", "hash_status", "unhashed_reason", "size_bytes",
//	    "sha256", "sha1", "authenticode_sha256", "authenticode_sha1", "version"
//	  }]
//	}
//
// Absent block: an agent that predates PAT-2263, or macOS. "Not reported", a
// strict no-op, and a different claim from a present block that says
// "unavailable" (the agent tried and could not read the driver list).
// collection_status describes the driver list only; enforcement is always
// present and each value carries its own "unknown".
//
// Storage (migration 0216): device_kernel_driver_observations, one immutable
// header row per report; device_kernel_driver_state, the newest header per
// device; device_kernel_drivers, the current driver rows. See
// upsertKernelDrivers for the projection rules.

type kernelDriversPart struct {
	SchemaVersion    int                    `json:"schema_version"`
	CollectionStatus string                 `json:"collection_status"`
	Errors           []string               `json:"errors"`
	Enforcement      *driverEnforcementPart `json:"enforcement"`
	Drivers          []kernelDriverPart     `json:"drivers"`
}

type driverEnforcementPart struct {
	VulnerableDriverBlocklist string `json:"vulnerable_driver_blocklist"`
	HVCI                      string `json:"hvci"`
	SmartAppControl           string `json:"smart_app_control"`
	CodeIntegrityPolicy       string `json:"code_integrity_policy"`
	BlocklistEnforced         string `json:"blocklist_enforced"`
}

type kernelDriverPart struct {
	Path               *string  `json:"path"`
	Sources            []string `json:"sources"`
	ServiceName        *string  `json:"service_name"`
	ServiceType        *string  `json:"service_type"`
	StartType          *string  `json:"start_type"`
	Loaded             *bool    `json:"loaded"`
	HashStatus         string   `json:"hash_status"`
	UnhashedReason     *string  `json:"unhashed_reason"`
	SizeBytes          *int64   `json:"size_bytes"`
	SHA256             *string  `json:"sha256"`
	SHA1               *string  `json:"sha1"`
	AuthenticodeSHA256 *string  `json:"authenticode_sha256"`
	AuthenticodeSHA1   *string  `json:"authenticode_sha1"`
	Version            *string  `json:"version"`
}

// Contract bounds, equal to the Windows agent's own (KernelDriverBudget,
// KernelDriverErrorCode.MaxErrors). A conforming agent never exceeds them.
const (
	kernelDriversSchemaVersion   = 1
	kernelDriversMaxDrivers      = 1500
	kernelDriversMaxErrors       = 16
	kernelDriversMaxPathRunes    = 512
	kernelDriversMaxServiceRunes = 256
	kernelDriversMaxFileBytes    = 1 << 40
)

var (
	kernelDriverStatuses       = setOf("complete", "partial", "unavailable")
	kernelDriverSources        = setOf("drivers_directory", "service", "loaded")
	kernelDriverServiceTypes   = setOf("kernel", "file_system")
	kernelDriverStartTypes     = setOf("boot", "system", "auto", "demand", "disabled")
	kernelDriverHashStatuses   = setOf("hashed", "unhashed")
	driverBlocklistValues      = setOf("enabled", "disabled", "not_set", "unknown")
	driverHVCIValues           = setOf("running", "configured", "off", "unknown")
	driverSmartAppValues       = setOf("on", "evaluation", "off", "not_present", "unknown")
	driverCodeIntegrityValues  = setOf("enforced", "audit", "off", "unknown")
	driverBlocklistEnforcedVal = setOf("yes", "no", "unknown")

	kernelDriverCode    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	kernelDriverSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kernelDriverSHA1    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	kernelDriverVersion = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$`)
	kernelDriverPathRe  = regexp.MustCompile(`^[A-Za-z]:\\`)

	kernelDriverFields = []string{"path", "sources", "service_name", "service_type", "start_type", "loaded",
		"hash_status", "unhashed_reason", "size_bytes", "sha256", "sha1", "authenticode_sha256",
		"authenticode_sha1", "version"}
	kernelDriverHashFields = []string{"sha256", "sha1", "authenticode_sha256", "authenticode_sha1"}
)

// validateKernelDrivers checks the STRUCTURE of the kernel_drivers block:
// types, enums, bounds, required and unknown keys, and the rules that make a
// row's hashes trustworthy for matching (lowercase hex of the right length; a
// hashed row carries its flat SHA-256 and SHA-1; an unhashed row carries no
// hash at all). A violation rejects the payload (400) without echoing any
// payload value. An unknown but well-formed error or unhashed_reason code is
// accepted, so a newer agent can add a diagnostic without costing a device
// its inventory.
func validateKernelDrivers(m map[string]any) error {
	const block = "kernel_drivers"
	v := tv{echoKeys: true}
	obj, err := tvObject(m[block], block)
	if err != nil {
		return err
	}
	path := block + "."
	if err := v.keys(path, obj, false, "schema_version", "collection_status", "errors", "enforcement", "drivers"); err != nil {
		return err
	}
	sv, ok := obj["schema_version"].(float64)
	if !ok || sv != kernelDriversSchemaVersion {
		return fmt.Errorf("%sschema_version: required, must be %d", path, kernelDriversSchemaVersion)
	}
	status, err := tvEnum(obj, path, "collection_status", kernelDriverStatuses, false)
	if err != nil {
		return err
	}
	if status == "" {
		return fmt.Errorf("%scollection_status: required field is missing", path)
	}
	if err := validateCodeArray(obj, path, "errors", kernelDriversMaxErrors); err != nil {
		return err
	}

	rawEnf, present := obj["enforcement"]
	if !present {
		return fmt.Errorf("%senforcement: required field is missing", path)
	}
	enf, err := tvObject(rawEnf, path+"enforcement")
	if err != nil {
		return err
	}
	ep := path + "enforcement."
	enfFields := []struct {
		key    string
		values map[string]bool
	}{
		{"vulnerable_driver_blocklist", driverBlocklistValues},
		{"hvci", driverHVCIValues},
		{"smart_app_control", driverSmartAppValues},
		{"code_integrity_policy", driverCodeIntegrityValues},
		{"blocklist_enforced", driverBlocklistEnforcedVal},
	}
	enfKeys := make([]string, 0, len(enfFields))
	for _, f := range enfFields {
		enfKeys = append(enfKeys, f.key)
	}
	if err := v.keys(ep, enf, true, enfKeys...); err != nil {
		return err
	}
	for _, f := range enfFields {
		if _, err := tvEnum(enf, ep, f.key, f.values, false); err != nil {
			return err
		}
	}

	rawDrivers, present := obj["drivers"]
	if status == "unavailable" {
		if present {
			return fmt.Errorf("%sdrivers: not allowed when collection_status is \"unavailable\"", path)
		}
		return nil
	}
	if !present {
		return fmt.Errorf("%sdrivers: required when collection_status is %q", path, status)
	}
	drivers, ok := rawDrivers.([]any)
	if !ok {
		return fmt.Errorf("%sdrivers: must be an array", path)
	}
	if len(drivers) > kernelDriversMaxDrivers {
		return fmt.Errorf("%sdrivers: %d entries exceeds the contract maximum of %d", path, len(drivers), kernelDriversMaxDrivers)
	}
	for i, raw := range drivers {
		if err := validateKernelDriver(v, raw, fmt.Sprintf("%sdrivers[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func validateKernelDriver(v tv, raw any, path string) error {
	obj, err := tvObject(raw, path)
	if err != nil {
		return err
	}
	p := path + "."
	if err := v.keys(p, obj, false, kernelDriverFields...); err != nil {
		return err
	}

	hasPath, hasService := false, false
	if raw, present := obj["path"]; present && raw != nil {
		s, ok := raw.(string)
		if !ok || !kernelDriverUsable(s, kernelDriversMaxPathRunes) || !kernelDriverPathRe.MatchString(s) {
			return fmt.Errorf("%spath: must be a printable drive-letter path of at most %d characters", p, kernelDriversMaxPathRunes)
		}
		hasPath = true
	}
	if raw, present := obj["service_name"]; present && raw != nil {
		s, ok := raw.(string)
		if !ok || !kernelDriverUsable(s, kernelDriversMaxServiceRunes) {
			return fmt.Errorf("%sservice_name: must be a printable string of at most %d characters", p, kernelDriversMaxServiceRunes)
		}
		hasService = true
	}
	if !hasPath && !hasService {
		return fmt.Errorf("%s: a driver needs a path or a service_name", path)
	}

	rawSources, present := obj["sources"]
	if !present {
		return fmt.Errorf("%ssources: required field is missing", p)
	}
	sources, ok := rawSources.([]any)
	if !ok || len(sources) == 0 || len(sources) > len(kernelDriverSources) {
		return fmt.Errorf("%ssources: must be a non-empty array of source names", p)
	}
	seen := map[string]bool{}
	for _, s := range sources {
		name, ok := s.(string)
		if !ok || !kernelDriverSources[name] || seen[name] {
			return fmt.Errorf("%ssources: entries must be distinct values in enum %v", p, SortedEnum(kernelDriverSources))
		}
		seen[name] = true
	}

	if _, err := tvEnum(obj, p, "service_type", kernelDriverServiceTypes, true); err != nil {
		return err
	}
	if _, err := tvEnum(obj, p, "start_type", kernelDriverStartTypes, true); err != nil {
		return err
	}
	if err := tvBool(obj, p, "loaded", true); err != nil {
		return err
	}
	hashStatus, err := tvEnum(obj, p, "hash_status", kernelDriverHashStatuses, false)
	if err != nil {
		return err
	}
	if hashStatus == "" {
		return fmt.Errorf("%shash_status: required field is missing", p)
	}
	if raw, present := obj["unhashed_reason"]; present && raw != nil {
		code, ok := raw.(string)
		if !ok || !kernelDriverCode.MatchString(code) {
			return fmt.Errorf("%sunhashed_reason: must be a code", p)
		}
		if hashStatus != "unhashed" {
			return fmt.Errorf("%sunhashed_reason: only allowed when hash_status is \"unhashed\"", p)
		}
	}
	if raw, present := obj["size_bytes"]; present && raw != nil {
		f, ok := raw.(float64)
		if !ok || f != float64(int64(f)) || f < 0 || f > kernelDriversMaxFileBytes {
			return fmt.Errorf("%ssize_bytes: must be a non-negative integer", p)
		}
	}
	for _, key := range kernelDriverHashFields {
		raw, present := obj[key]
		if !present || raw == nil {
			if hashStatus == "hashed" && (key == "sha256" || key == "sha1") {
				return fmt.Errorf("%s%s: required when hash_status is \"hashed\"", p, key)
			}
			continue
		}
		if hashStatus != "hashed" {
			return fmt.Errorf("%s%s: not allowed when hash_status is %q", p, key, hashStatus)
		}
		s, ok := raw.(string)
		re := kernelDriverSHA256
		if strings.HasSuffix(key, "sha1") {
			re = kernelDriverSHA1
		}
		if !ok || !re.MatchString(s) {
			return fmt.Errorf("%s%s: must be lowercase hex of the digest's length", p, key)
		}
	}
	if raw, present := obj["version"]; present && raw != nil {
		s, ok := raw.(string)
		if !ok || !kernelDriverVersion.MatchString(s) {
			return fmt.Errorf("%sversion: must be a.b.c.d", p)
		}
	}
	return nil
}

// validateCodeArray checks a required array of fixed diagnostic codes.
func validateCodeArray(obj map[string]any, path, key string, max int) error {
	raw, present := obj[key]
	if !present {
		return fmt.Errorf("%s%s: required field is missing", path, key)
	}
	codes, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s%s: must be an array", path, key)
	}
	if len(codes) > max {
		return fmt.Errorf("%s%s: %d entries exceeds the contract maximum of %d", path, key, len(codes), max)
	}
	for i, c := range codes {
		code, ok := c.(string)
		if !ok || !kernelDriverCode.MatchString(code) {
			return fmt.Errorf("%s%s[%d]: must be a code matching %s", path, key, i, kernelDriverCode.String())
		}
	}
	return nil
}

// kernelDriverUsable: valid UTF-8, no surrounding whitespace, not empty, no
// control characters, at most max characters.
func kernelDriverUsable(s string, max int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// kernelDriverKey is the per-device identity of a driver row: its path,
// case-folded (Windows paths are case-insensitive), or for a service whose
// ImagePath could not be resolved, the service name.
func kernelDriverKey(d kernelDriverPart) string {
	if d.Path != nil && *d.Path != "" {
		return "path:" + strings.ToLower(*d.Path)
	}
	if d.ServiceName != nil {
		return "service:" + strings.ToLower(*d.ServiceName)
	}
	return ""
}

// upsertKernelDrivers stores one report's kernel_drivers block (PAT-2263).
//
//   - nil block (key absent): strict no-op. The device stays "not reported"
//     unless an earlier report carried the block.
//   - every present block: one immutable device_kernel_driver_observations
//     header row (status, errors, enforcement, counts), idempotent on
//     raw_payload_id so re-extraction adds nothing. The rows themselves stay
//     in the immutable raw payload, which re-extraction reads again.
//   - device_kernel_driver_state: the newest report's header always moves
//     forward (an older replay, by raw payload received_at, never overwrites a
//     newer report), so enforcement and "unavailable" are current.
//   - device_kernel_drivers (current rows): complete replaces the set, rows
//     the report does not list are removed; partial upserts the rows it sent
//     and removes nothing, because a partial list has no absence authority;
//     unavailable leaves every row as it was. A row the newest report sent
//     unhashed has its hashes cleared, never kept from an older read: a file
//     that could not be read this time is Unknown, not "still the old hash".
func upsertKernelDrivers(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, kd *kernelDriversPart, collectedAt time.Time, logger *slog.Logger) error {
	if kd == nil {
		return nil
	}
	if row.ID <= 0 || row.ReceivedAt.IsZero() {
		if logger != nil {
			logger.Warn("kernel_drivers block not stored: no raw payload identity", "device_id", deviceID)
		}
		return nil
	}
	var observedAt *time.Time
	if !collectedAt.IsZero() {
		observedAt = &collectedAt
	}
	errs := kd.Errors
	if errs == nil {
		errs = []string{}
	}
	enf := kd.Enforcement
	if enf == nil {
		enf = &driverEnforcementPart{}
	}
	hashed, unhashed := 0, 0
	for _, d := range kd.Drivers {
		if d.HashStatus == "hashed" {
			hashed++
		} else {
			unhashed++
		}
	}
	var driverCount *int
	if kd.CollectionStatus != "unavailable" {
		n := len(kd.Drivers)
		driverCount = &n
	}

	var obsID int64
	err := tx.QueryRow(ctx, `INSERT INTO device_kernel_driver_observations (
			tenant_id, device_id, raw_payload_id, raw_payload_received_at, observed_at,
			block_schema_version, collection_status, errors,
			vulnerable_driver_blocklist, hvci, smart_app_control, code_integrity_policy, blocklist_enforced,
			driver_count, hashed_count, unhashed_count)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (raw_payload_id) DO NOTHING
		RETURNING id`,
		row.TenantID, deviceID, row.ID, row.ReceivedAt, observedAt,
		kd.SchemaVersion, kd.CollectionStatus, errs,
		enf.VulnerableDriverBlocklist, enf.HVCI, enf.SmartAppControl, enf.CodeIntegrityPolicy, enf.BlocklistEnforced,
		driverCount, hashed, unhashed,
	).Scan(&obsID)
	if err == pgx.ErrNoRows {
		if err := tx.QueryRow(ctx, `SELECT id FROM device_kernel_driver_observations
			WHERE raw_payload_id = $1 AND device_id = $2::uuid`, row.ID, deviceID).Scan(&obsID); err != nil {
			return fmt.Errorf("kernel driver observation for raw payload %d: %w", row.ID, err)
		}
	} else if err != nil {
		return fmt.Errorf("insert kernel driver observation: %w", err)
	}

	var storedAt time.Time
	err = tx.QueryRow(ctx, `SELECT reported_at FROM device_kernel_driver_state
		WHERE device_id = $1::uuid FOR UPDATE`, deviceID).Scan(&storedAt)
	switch {
	case err == pgx.ErrNoRows:
	case err != nil:
		return fmt.Errorf("read kernel driver state: %w", err)
	case storedAt.After(row.ReceivedAt):
		return nil // an older report: kept as evidence, never the current view
	}

	if _, err := tx.Exec(ctx, `INSERT INTO device_kernel_driver_state (
			device_id, tenant_id, observation_id, reported_at, observed_at, collection_status, errors,
			vulnerable_driver_blocklist, hvci, smart_app_control, code_integrity_policy, blocklist_enforced)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (device_id) DO UPDATE SET
			observation_id              = EXCLUDED.observation_id,
			reported_at                 = EXCLUDED.reported_at,
			observed_at                 = EXCLUDED.observed_at,
			collection_status           = EXCLUDED.collection_status,
			errors                      = EXCLUDED.errors,
			vulnerable_driver_blocklist = EXCLUDED.vulnerable_driver_blocklist,
			hvci                        = EXCLUDED.hvci,
			smart_app_control           = EXCLUDED.smart_app_control,
			code_integrity_policy       = EXCLUDED.code_integrity_policy,
			blocklist_enforced          = EXCLUDED.blocklist_enforced,
			updated_at                  = now()`,
		deviceID, row.TenantID, obsID, row.ReceivedAt, observedAt, kd.CollectionStatus, errs,
		enf.VulnerableDriverBlocklist, enf.HVCI, enf.SmartAppControl, enf.CodeIntegrityPolicy, enf.BlocklistEnforced); err != nil {
		return fmt.Errorf("upsert kernel driver state: %w", err)
	}
	if kd.CollectionStatus == "unavailable" {
		return nil
	}

	keys := make([]string, 0, len(kd.Drivers))
	batch := &pgx.Batch{}
	for _, d := range kd.Drivers {
		key := kernelDriverKey(d)
		if key == "" {
			continue
		}
		keys = append(keys, key)
		sources := d.Sources
		if sources == nil {
			sources = []string{}
		}
		batch.Queue(`INSERT INTO device_kernel_drivers (
				device_id, tenant_id, driver_key, path, service_name, service_type, start_type, loaded, sources,
				hash_status, unhashed_reason, size_bytes, sha256, sha1, authenticode_sha256, authenticode_sha1,
				version, observation_id, reported_at, first_seen_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19)
			ON CONFLICT (device_id, driver_key) DO UPDATE SET
				path = EXCLUDED.path, service_name = EXCLUDED.service_name, service_type = EXCLUDED.service_type,
				start_type = EXCLUDED.start_type, loaded = EXCLUDED.loaded, sources = EXCLUDED.sources,
				hash_status = EXCLUDED.hash_status, unhashed_reason = EXCLUDED.unhashed_reason,
				size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256, sha1 = EXCLUDED.sha1,
				authenticode_sha256 = EXCLUDED.authenticode_sha256, authenticode_sha1 = EXCLUDED.authenticode_sha1,
				version = EXCLUDED.version, observation_id = EXCLUDED.observation_id,
				reported_at = EXCLUDED.reported_at`,
			deviceID, row.TenantID, key, d.Path, d.ServiceName, d.ServiceType, d.StartType, d.Loaded, sources,
			d.HashStatus, d.UnhashedReason, d.SizeBytes, d.SHA256, d.SHA1, d.AuthenticodeSHA256, d.AuthenticodeSHA1,
			d.Version, obsID, row.ReceivedAt)
	}
	if batch.Len() > 0 {
		results := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := results.Exec(); err != nil {
				results.Close()
				return fmt.Errorf("upsert kernel driver row %d: %w", i, err)
			}
		}
		if err := results.Close(); err != nil {
			return fmt.Errorf("close kernel driver batch: %w", err)
		}
	}
	if kd.CollectionStatus == "complete" {
		if _, err := tx.Exec(ctx, `DELETE FROM device_kernel_drivers
			WHERE device_id = $1::uuid AND NOT (driver_key = ANY($2::text[]))`, deviceID, keys); err != nil {
			return fmt.Errorf("prune kernel driver rows: %w", err)
		}
	}
	return nil
}
