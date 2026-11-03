package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EncryptionRow holds encryption status for one device.
type EncryptionRow struct {
	// DeviceID is devices.id, so a per-device consumer (the insurance
	// evidence pack, PAT-2258) can join on it rather than on a hostname.
	DeviceID string
	Hostname string
	OS       string
	// FileVault and BitLocker are the raw latest compliance signals the agents
	// send: "filevault" on macOS and "bitlocker_os_drive" on Windows (PAT-2496;
	// the key "bitlocker" is not one any agent writes). They are detail to
	// show beside State, never the basis of it.
	FileVault *string
	BitLocker *string
	// State is the device's encryption state, one of the EncryptionState*
	// constants, set by FetchEncryptionStates (encryption_state.go), the one
	// definition the roster, the device page and the insurance evidence pack
	// share (PAT-2496). Counts, the CSV state column and the pack read this
	// field and derive nothing from FileVault or BitLocker.
	State string
}

// EncryptionFinding holds one compliance signal related to encryption.
type EncryptionFinding struct {
	FindingType string
	Details     string
}

// EncryptionPostureReport contains encryption posture data for a tenant.
type EncryptionPostureReport struct {
	GeneratedAt      time.Time
	Tenant           string
	Devices          []EncryptionRow
	Findings         []EncryptionFinding
	EncryptedCount   int
	UnencryptedCount int
	UnknownCount     int
}

// applyStates sets each device's State from a FetchEncryptionStates result and
// derives the three counts from those states, so the PDF's counts, the CSV's
// state column and the insurance evidence pack are all read off one value. A
// device the result does not carry is unknown.
func (r *EncryptionPostureReport) applyStates(states map[string]string) {
	r.EncryptedCount, r.UnencryptedCount, r.UnknownCount = 0, 0, 0
	for i := range r.Devices {
		r.Devices[i].State = encryptionStateOf(states, r.Devices[i].DeviceID)
		switch r.Devices[i].State {
		case EncryptionStateEncrypted:
			r.EncryptedCount++
		case EncryptionStateNotEncrypted:
			r.UnencryptedCount++
		default:
			r.UnknownCount++
		}
	}
}

// FetchEncryptionPostureReport fetches encryption posture data for a tenant.
func FetchEncryptionPostureReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (EncryptionPostureReport, error) {
	var r EncryptionPostureReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	// Query 1: devices with their raw filevault / bitlocker_os_drive signals,
	// shown as detail beside each device's state (PAT-2496). The key the
	// Windows agent writes is bitlocker_os_drive; there is no "bitlocker" key.
	rows, err := pool.Query(ctx, `
		SELECT d.id::text, d.hostname, d.os,
		       (SELECT cs.value FROM compliance_signals cs
		        WHERE cs.device_id = d.id AND cs.key = 'filevault'
		        ORDER BY cs.observed_at DESC LIMIT 1) AS filevault,
		       (SELECT cs.value FROM compliance_signals cs
		        WHERE cs.device_id = d.id AND cs.key = 'bitlocker_os_drive'
		        ORDER BY cs.observed_at DESC LIMIT 1) AS bitlocker
		FROM devices d
		WHERE d.tenant_id = $1
		ORDER BY d.hostname
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("fetch encryption posture: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dev EncryptionRow
		var hostname, osName *string
		if err := rows.Scan(&dev.DeviceID, &hostname, &osName, &dev.FileVault, &dev.BitLocker); err != nil {
			return r, fmt.Errorf("scan encryption row: %w", err)
		}
		// devices.os is nullable; an absent OS reads as "" (PAT-2538).
		dev.OS = derefOrEmpty(osName)
		if hostname != nil {
			dev.Hostname = *hostname
		} else {
			dev.Hostname = "—"
		}
		r.Devices = append(r.Devices, dev)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	rows.Close()

	// State and counts come from the one definition (PAT-2496), the same
	// one the roster and the insurance evidence pack read.
	states, err := FetchEncryptionStates(ctx, pool, tenantID, nil)
	if err != nil {
		return r, err
	}
	r.applyStates(states)

	// Query 2: compliance signals for disk encryption findings
	findingRows, err := pool.Query(ctx, `
		SELECT cs.key, cs.value
		FROM compliance_signals cs
		JOIN devices d ON d.id = cs.device_id
		WHERE d.tenant_id = $1
		  AND cs.key IN ('disk_encryption_off','removable_storage_unencrypted')
		  AND cs.severity IN ('warn','fail')
		ORDER BY cs.observed_at DESC
		LIMIT 100
	`, tenantID)
	if err != nil {
		// compliance_signals may not have all keys; treat errors as empty
		if !strings.Contains(err.Error(), "does not exist") {
			return r, fmt.Errorf("fetch encryption findings: %w", err)
		}
		return r, nil
	}
	defer findingRows.Close()

	findingTypeMap := map[string]string{
		"disk_encryption_off":           "Disk encryption off",
		"removable_storage_unencrypted": "Removable storage unencrypted",
	}
	for findingRows.Next() {
		var key, value string
		if err := findingRows.Scan(&key, &value); err != nil {
			return r, fmt.Errorf("scan encryption finding: %w", err)
		}
		ft := findingTypeMap[key]
		if ft == "" {
			ft = key
		}
		r.Findings = append(r.Findings, EncryptionFinding{FindingType: ft, Details: value})
	}

	return r, findingRows.Err()
}
