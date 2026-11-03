// Portal device firmware block (PAT-2262, first slice of PAT-1863).
//
// Extends GET /v1/portal/devices/{deviceID} with what the device's firmware
// reports about itself: BIOS vendor, version, SMBIOS version and release
// date, and the system and baseboard identity beside them, read from
// device_firmware_current (migration 0213).
//
// Observation only. No field says whether a firmware version is current,
// outdated or vulnerable, and none may be added here without the advisory
// correlation PAT-1863's later slices own.
package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Firmware status vocabulary. "not_reported" is a device that has never sent
// the block (an agent older than PAT-2262, or macOS, which does not collect
// it yet). "unavailable" is an agent that sent the block and could read
// nothing. They are different claims and are never collapsed.
const (
	portalFirmwareNotReported = "not_reported"
)

// portalDeviceFirmware is the customer-facing firmware block.
//
// status, reported_at, observed_at and errors describe the NEWEST report that
// carried the block. Each section carries the values last read for it and
// the status and time of the report that read them, which can be older than
// the newest report: an unavailable report never blanks what an earlier one
// read. A section is null until some report has read it.
type portalDeviceFirmware struct {
	Status     string                   `json:"status"`
	ReportedAt *time.Time               `json:"reported_at"`
	ObservedAt *time.Time               `json:"observed_at"`
	Errors     []string                 `json:"errors"`
	BIOS       *portalFirmwareBIOS      `json:"bios"`
	System     *portalFirmwareSystem    `json:"system"`
	Baseboard  *portalFirmwareBaseboard `json:"baseboard"`
}

// portalFirmwareBIOS: every value is an explicit null when the firmware did
// not populate it or it could not be read (status "partial" says which may
// apply). release_date is YYYY-MM-DD; release_date_raw is set only when the
// agent could not parse the firmware's date.
type portalFirmwareBIOS struct {
	Status         string    `json:"status"`
	ReportedAt     time.Time `json:"reported_at"`
	Manufacturer   *string   `json:"manufacturer"`
	Version        *string   `json:"version"`
	SMBIOSVersion  *string   `json:"smbios_version"`
	ReleaseDate    *string   `json:"release_date"`
	ReleaseDateRaw *string   `json:"release_date_raw"`
}

type portalFirmwareSystem struct {
	Status       string    `json:"status"`
	ReportedAt   time.Time `json:"reported_at"`
	Manufacturer *string   `json:"manufacturer"`
	Model        *string   `json:"model"`
}

type portalFirmwareBaseboard struct {
	Status       string    `json:"status"`
	ReportedAt   time.Time `json:"reported_at"`
	Manufacturer *string   `json:"manufacturer"`
	Product      *string   `json:"product"`
}

// fetchPortalDeviceFirmware reads one device's firmware projection, scoped to
// the caller's tenant. No row is "not_reported", never an error.
func fetchPortalDeviceFirmware(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (portalDeviceFirmware, error) {
	out := portalDeviceFirmware{Status: portalFirmwareNotReported, Errors: []string{}}

	var (
		status                                   string
		errs                                     []string
		reportedAt                               time.Time
		observedAt                               *time.Time
		biosStatus, systemStatus, baseStatus     *string
		biosAt, systemAt, baseAt                 *time.Time
		biosMaker, biosVersion, smbios, dateRaw  *string
		releaseDate                              *time.Time
		systemMaker, systemModel, baseMaker, bbP *string
	)
	err := pool.QueryRow(ctx, `SELECT collection_status, errors, reported_at, observed_at,
			bios_status, bios_reported_at, bios_manufacturer, bios_version, smbios_version, bios_release_date, bios_release_date_raw,
			system_status, system_reported_at, system_manufacturer, system_model,
			baseboard_status, baseboard_reported_at, baseboard_manufacturer, baseboard_product
		FROM device_firmware_current
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid`, deviceID, tenantID).Scan(
		&status, &errs, &reportedAt, &observedAt,
		&biosStatus, &biosAt, &biosMaker, &biosVersion, &smbios, &releaseDate, &dateRaw,
		&systemStatus, &systemAt, &systemMaker, &systemModel,
		&baseStatus, &baseAt, &baseMaker, &bbP)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}

	out.Status = status
	out.ReportedAt = &reportedAt
	out.ObservedAt = observedAt
	if errs != nil {
		out.Errors = errs
	}
	if biosStatus != nil && biosAt != nil {
		var date *string
		if releaseDate != nil {
			d := releaseDate.Format(time.DateOnly)
			date = &d
		}
		out.BIOS = &portalFirmwareBIOS{
			Status: *biosStatus, ReportedAt: *biosAt,
			Manufacturer: biosMaker, Version: biosVersion, SMBIOSVersion: smbios,
			ReleaseDate: date, ReleaseDateRaw: dateRaw,
		}
	}
	if systemStatus != nil && systemAt != nil {
		out.System = &portalFirmwareSystem{
			Status: *systemStatus, ReportedAt: *systemAt,
			Manufacturer: systemMaker, Model: systemModel,
		}
	}
	if baseStatus != nil && baseAt != nil {
		out.Baseboard = &portalFirmwareBaseboard{
			Status: *baseStatus, ReportedAt: *baseAt,
			Manufacturer: baseMaker, Product: bbP,
		}
	}
	return out, nil
}
