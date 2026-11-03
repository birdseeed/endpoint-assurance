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

// PAT-2262 (first slice of PAT-1863, BIOS/firmware assurance): the firmware
// block. What the device's own firmware says it is: BIOS vendor, version,
// SMBIOS version and release date, plus the system and baseboard identity
// strings SMBIOS carries beside them. Observation only. Nothing in this
// slice says whether a firmware version is current, outdated or vulnerable,
// and no stored or exposed field name implies it.
//
// Wire shape (Windows agent: InventoryFirmware, FirmwareInventoryLogic):
//
//	"firmware": {
//	  "schema_version": 1,
//	  "collection_status": "complete" | "partial" | "unavailable",
//	  "errors": ["bios_query_failed", ...],          // fixed codes, <= 16
//	  "bios":      {"collection_status", "manufacturer", "version",
//	                "smbios_version", "release_date", "release_date_raw"},
//	  "system":    {"collection_status", "manufacturer", "model"},
//	  "baseboard": {"collection_status", "manufacturer", "product"}
//	}
//
// Absent block: an agent that predates PAT-2262, or macOS, which does not
// collect it in this slice. "Not reported", a strict no-op, and a different
// claim from a present block that says "unavailable" (the agent tried and
// could not read anything). An unavailable block carries no sections.
//
// Storage (migration 0213): device_firmware_observations, one immutable row
// per report, and device_firmware_current, the per-device projection. See
// upsertFirmware for the projection rules.

type firmwarePart struct {
	SchemaVersion    int                    `json:"schema_version"`
	CollectionStatus string                 `json:"collection_status"`
	Errors           []string               `json:"errors"`
	BIOS             *firmwareBIOSPart      `json:"bios"`
	System           *firmwareSystemPart    `json:"system"`
	Baseboard        *firmwareBaseboardPart `json:"baseboard"`
}

type firmwareBIOSPart struct {
	CollectionStatus string  `json:"collection_status"`
	Manufacturer     *string `json:"manufacturer"`
	Version          *string `json:"version"`
	SMBIOSVersion    *string `json:"smbios_version"`
	ReleaseDate      *string `json:"release_date"`
	ReleaseDateRaw   *string `json:"release_date_raw"`
}

type firmwareSystemPart struct {
	CollectionStatus string  `json:"collection_status"`
	Manufacturer     *string `json:"manufacturer"`
	Model            *string `json:"model"`
}

type firmwareBaseboardPart struct {
	CollectionStatus string  `json:"collection_status"`
	Manufacturer     *string `json:"manufacturer"`
	Product          *string `json:"product"`
}

// Contract bounds, equal to the Windows agent's own
// (FirmwareInventoryLogic.MaxValueLength / MaxRawDateLength,
// FirmwareErrorCode.MaxErrors). A conforming agent drops a value over a
// bound rather than truncating it, so a longer value is a contract violation.
const (
	firmwareSchemaVersion    = 1
	firmwareMaxValueRunes    = 128
	firmwareMaxRawDateRunes  = 64
	firmwareMaxErrors        = 16
	firmwareErrorCodePattern = `^[a-z][a-z0-9_]{0,63}$`
)

var (
	firmwareStatuses  = setOf("complete", "partial", "unavailable")
	firmwareErrorCode = regexp.MustCompile(firmwareErrorCodePattern)
	firmwareSMBIOSVer = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}$`)
	firmwareDate      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

	// Value fields per section, in wire order. collection_status is separate.
	firmwareSectionFields = []struct {
		name   string
		fields []string
	}{
		{"bios", []string{"manufacturer", "version", "smbios_version", "release_date", "release_date_raw"}},
		{"system", []string{"manufacturer", "model"}},
		{"baseboard", []string{"manufacturer", "product"}},
	}
)

// validateFirmware checks the STRUCTURE of the firmware block: types, enums,
// bounds, required and unknown keys. A violation rejects the payload (400)
// without echoing any payload value. The block has already been through the
// PAT-2021 case-variant and duplicate-key walk (checkPayloadKeys,
// strictBlockKeys).
//
// It does not reject a well-formed block whose statuses disagree with each
// other (a "complete" block with a "partial" section, say): the projection
// follows each section's own status, which is always the safer reading, so
// such a block costs nothing and rejecting it would drop the whole device
// inventory. An unknown but well-formed error code is accepted, so a newer
// agent can add a diagnostic without costing a device its inventory.
func validateFirmware(m map[string]any) error {
	const block = "firmware"
	v := tv{echoKeys: true}
	obj, err := tvObject(m[block], block)
	if err != nil {
		return err
	}
	path := block + "."
	if err := v.keys(path, obj, false, "schema_version", "collection_status", "errors", "bios", "system", "baseboard"); err != nil {
		return err
	}

	sv, ok := obj["schema_version"].(float64)
	if !ok || sv != firmwareSchemaVersion {
		return fmt.Errorf("%sschema_version: required, must be %d", path, firmwareSchemaVersion)
	}
	status, err := tvEnum(obj, path, "collection_status", firmwareStatuses, false)
	if err != nil {
		return err
	}
	if status == "" {
		return fmt.Errorf("%scollection_status: required field is missing", path)
	}

	rawErrs, present := obj["errors"]
	if !present {
		return fmt.Errorf("%serrors: required field is missing", path)
	}
	errs, ok := rawErrs.([]any)
	if !ok {
		return fmt.Errorf("%serrors: must be an array", path)
	}
	if len(errs) > firmwareMaxErrors {
		return fmt.Errorf("%serrors: %d entries exceeds the contract maximum of %d", path, len(errs), firmwareMaxErrors)
	}
	for i, e := range errs {
		code, ok := e.(string)
		if !ok || !firmwareErrorCode.MatchString(code) {
			return fmt.Errorf("%serrors[%d]: must be a code matching %s", path, i, firmwareErrorCodePattern)
		}
	}

	for _, sec := range firmwareSectionFields {
		raw, present := obj[sec.name]
		if status == "unavailable" {
			if present {
				return fmt.Errorf("%s%s: not allowed when collection_status is \"unavailable\"", path, sec.name)
			}
			continue
		}
		if !present {
			return fmt.Errorf("%s%s: required when collection_status is %q", path, sec.name, status)
		}
		if err := validateFirmwareSection(v, raw, path+sec.name, sec.fields); err != nil {
			return err
		}
	}
	return nil
}

func validateFirmwareSection(v tv, raw any, path string, fields []string) error {
	obj, err := tvObject(raw, path)
	if err != nil {
		return err
	}
	p := path + "."
	if err := v.keys(p, obj, false, append([]string{"collection_status"}, fields...)...); err != nil {
		return err
	}
	status, err := tvEnum(obj, p, "collection_status", firmwareStatuses, false)
	if err != nil {
		return err
	}
	if status == "" {
		return fmt.Errorf("%scollection_status: required field is missing", p)
	}
	for _, f := range fields {
		raw, present := obj[f]
		if !present || raw == nil {
			continue
		}
		if status == "unavailable" {
			return fmt.Errorf("%s%s: not allowed when the section's collection_status is \"unavailable\"", p, f)
		}
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("%s%s: must be a string or null", p, f)
		}
		max := firmwareMaxValueRunes
		if f == "release_date_raw" {
			max = firmwareMaxRawDateRunes
		}
		if !firmwareUsableString(s, max) {
			return fmt.Errorf("%s%s: must be a trimmed, non-empty, printable string of at most %d characters", p, f, max)
		}
		switch f {
		case "release_date":
			if !firmwareDate.MatchString(s) {
				return fmt.Errorf("%s%s: must be a YYYY-MM-DD date", p, f)
			}
			if _, err := time.Parse(time.DateOnly, s); err != nil {
				return fmt.Errorf("%s%s: must be a real calendar date", p, f)
			}
		case "smbios_version":
			if !firmwareSMBIOSVer.MatchString(s) {
				return fmt.Errorf("%s%s: must be major.minor", p, f)
			}
		}
	}
	return nil
}

// firmwareUsableString is the agent's own acceptance rule for a value: valid
// UTF-8, no surrounding whitespace, not empty, no control characters, at most
// max characters.
func firmwareUsableString(s string, max int) bool {
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

// upsertFirmware stores one report's firmware block (PAT-2262).
//
//   - nil block (key absent): strict no-op. The device stays "not reported"
//     unless an earlier report carried the block.
//   - every present block: one immutable device_firmware_observations row,
//     idempotent on raw_payload_id so re-extraction adds nothing.
//   - device_firmware_current: the newest report's block status, errors and
//     observation always move forward (an older replay, by raw payload
//     received_at, never overwrites a newer report). Per section:
//     complete replaces every value, nulls included; partial fills in only
//     the values it read (the release date and its raw form move as one
//     unit, so an old parsed date never sits beside a new raw one);
//     unavailable, or an unavailable block, leaves stored values and their
//     timestamps untouched. So "unavailable" is visible as the newest status
//     without ever blanking what an earlier report read.
func upsertFirmware(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, fw *firmwarePart, collectedAt time.Time, logger *slog.Logger) error {
	if fw == nil {
		return nil
	}
	if row.ID <= 0 || row.ReceivedAt.IsZero() {
		if logger != nil {
			logger.Warn("firmware block not stored: no raw payload identity", "device_id", deviceID)
		}
		return nil
	}
	var observedAt *time.Time
	if !collectedAt.IsZero() {
		observedAt = &collectedAt
	}
	errs := fw.Errors
	if errs == nil {
		errs = []string{}
	}

	bios, system, baseboard := fw.BIOS, fw.System, fw.Baseboard
	if bios == nil {
		bios = &firmwareBIOSPart{}
	}
	if system == nil {
		system = &firmwareSystemPart{}
	}
	if baseboard == nil {
		baseboard = &firmwareBaseboardPart{}
	}
	releaseDate := firmwareParseDate(bios.ReleaseDate)

	var obsID int64
	err := tx.QueryRow(ctx, `INSERT INTO device_firmware_observations (
			tenant_id, device_id, raw_payload_id, raw_payload_received_at, observed_at,
			block_schema_version, collection_status, errors,
			bios_status, bios_manufacturer, bios_version, smbios_version, bios_release_date, bios_release_date_raw,
			system_status, system_manufacturer, system_model,
			baseboard_status, baseboard_manufacturer, baseboard_product)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (raw_payload_id) DO NOTHING
		RETURNING id`,
		row.TenantID, deviceID, row.ID, row.ReceivedAt, observedAt,
		fw.SchemaVersion, fw.CollectionStatus, errs,
		nullIfEmpty(bios.CollectionStatus), bios.Manufacturer, bios.Version, bios.SMBIOSVersion, releaseDate, bios.ReleaseDateRaw,
		nullIfEmpty(system.CollectionStatus), system.Manufacturer, system.Model,
		nullIfEmpty(baseboard.CollectionStatus), baseboard.Manufacturer, baseboard.Product,
	).Scan(&obsID)
	if err == pgx.ErrNoRows {
		// Re-extraction of a payload already stored: reuse its observation.
		if err := tx.QueryRow(ctx, `SELECT id FROM device_firmware_observations
			WHERE raw_payload_id = $1 AND device_id = $2::uuid`, row.ID, deviceID).Scan(&obsID); err != nil {
			return fmt.Errorf("firmware observation for raw payload %d: %w", row.ID, err)
		}
	} else if err != nil {
		return fmt.Errorf("insert firmware observation: %w", err)
	}

	var storedAt time.Time
	err = tx.QueryRow(ctx, `SELECT reported_at FROM device_firmware_current
		WHERE device_id = $1::uuid FOR UPDATE`, deviceID).Scan(&storedAt)
	switch {
	case err == pgx.ErrNoRows:
	case err != nil:
		return fmt.Errorf("read firmware projection: %w", err)
	case storedAt.After(row.ReceivedAt):
		return nil // an older report: kept as evidence, never the current view
	}

	if _, err := tx.Exec(ctx, `INSERT INTO device_firmware_current (
			device_id, tenant_id, collection_status, errors, observation_id, reported_at, observed_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)
		ON CONFLICT (device_id) DO UPDATE SET
			collection_status = EXCLUDED.collection_status,
			errors            = EXCLUDED.errors,
			observation_id    = EXCLUDED.observation_id,
			reported_at       = EXCLUDED.reported_at,
			observed_at       = EXCLUDED.observed_at,
			updated_at        = now()`,
		deviceID, row.TenantID, fw.CollectionStatus, errs, obsID, row.ReceivedAt, observedAt); err != nil {
		return fmt.Errorf("upsert firmware projection: %w", err)
	}
	if fw.CollectionStatus == "unavailable" {
		return nil
	}

	// The release date and its raw form are one unit.
	dateCols := []firmwareColumn{
		{name: "bios_release_date", value: releaseDate},
		{name: "bios_release_date_raw", value: bios.ReleaseDateRaw},
	}
	if bios.CollectionStatus == "partial" && releaseDate == nil && bios.ReleaseDateRaw == nil {
		dateCols = nil
	}
	sections := []struct {
		prefix, status string
		fill           []firmwareColumn // coalesced under partial
		unit           []firmwareColumn // written together or not at all
	}{
		{"bios", bios.CollectionStatus, []firmwareColumn{
			{name: "bios_manufacturer", value: bios.Manufacturer},
			{name: "bios_version", value: bios.Version},
			{name: "smbios_version", value: bios.SMBIOSVersion},
		}, dateCols},
		{"system", system.CollectionStatus, []firmwareColumn{
			{name: "system_manufacturer", value: system.Manufacturer},
			{name: "system_model", value: system.Model},
		}, nil},
		{"baseboard", baseboard.CollectionStatus, []firmwareColumn{
			{name: "baseboard_manufacturer", value: baseboard.Manufacturer},
			{name: "baseboard_product", value: baseboard.Product},
		}, nil},
	}
	for _, sec := range sections {
		if sec.status != "complete" && sec.status != "partial" {
			continue // unavailable (or missing): stored values stand
		}
		fill := sec.status == "partial"
		set := []string{sec.prefix + "_status = $2", sec.prefix + "_observation_id = $3", sec.prefix + "_reported_at = $4"}
		args := []any{deviceID, sec.status, obsID, row.ReceivedAt}
		for _, c := range sec.fill {
			args = append(args, c.value)
			if fill {
				set = append(set, fmt.Sprintf("%s = COALESCE($%d, %s)", c.name, len(args), c.name))
			} else {
				set = append(set, fmt.Sprintf("%s = $%d", c.name, len(args)))
			}
		}
		for _, c := range sec.unit {
			args = append(args, c.value)
			set = append(set, fmt.Sprintf("%s = $%d", c.name, len(args)))
		}
		// Column names are the fixed identifiers above, never payload data.
		if _, err := tx.Exec(ctx, `UPDATE device_firmware_current SET `+strings.Join(set, ", ")+
			` WHERE device_id = $1::uuid`, args...); err != nil {
			return fmt.Errorf("update firmware %s section: %w", sec.prefix, err)
		}
	}
	return nil
}

type firmwareColumn struct {
	name  string
	value any
}

// firmwareParseDate turns a validated YYYY-MM-DD into a date value; nil when
// absent (or, defensively, unparseable, which ValidatePayload already
// rejects).
func firmwareParseDate(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.DateOnly, *s)
	if err != nil {
		return nil
	}
	return &t
}
