package report

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PAT-2496: the one definition of a device's disk-encryption state.
//
// Every surface that states whether a device is encrypted reads it from
// FetchEncryptionStates: the Devices roster, the device page, the Encryption &
// Disk Posture report (counts, CSV state column), and the cyber insurance
// evidence pack. They used to disagree. The pack and the posture report read
// the raw compliance_signals keys "filevault" and "bitlocker", and no agent
// writes "bitlocker" (the Windows agent writes "bitlocker_os_drive"), so every
// Windows device read as unknown there while the roster, which reads the CIS
// rule evaluations, correctly showed it as not encrypted.
//
// Do not add a second reader. A new surface calls FetchEncryptionStates.

// Per-device encryption states. Exactly three outcomes, and nothing else.
const (
	EncryptionStateEncrypted    = "encrypted"
	EncryptionStateNotEncrypted = "not_encrypted"
	EncryptionStateUnknown      = "unknown"
)

// encryptionRuleKeys are the disk-encryption controls whose latest evaluation
// determines a device's encryption state: FileVault on macOS and BitLocker on
// the OS drive on Windows. One code path serves both platforms; a device only
// ever has evaluations for its own platform's rule.
var encryptionRuleKeys = []string{
	"cis_macos_2_5_1_1_filevault",
	"cis_win_18_10_11_bitlocker_os_drive",
}

// FetchEncryptionStates returns the encryption state of devices of tenantID,
// keyed by device id, from each device's latest evaluation of the FileVault or
// BitLocker rule (encryptionRuleKeys), in a single query.
//
// deviceIDs nil means every device of the tenant. A non-nil slice narrows to
// those devices (a one-element slice reads one device). The tenant always
// bounds the answer: an id outside tenantID is simply absent from the map, as
// it would be for an id that does not exist. Every id the map does carry maps
// to exactly one of the EncryptionState* constants. A caller treats an absent
// id as EncryptionStateUnknown (see encryptionStateOf).
//
// The classification is classifyEncryptionEvaluation, the only place it lives.
func FetchEncryptionStates(ctx context.Context, pool *pgxpool.Pool, tenantID string, deviceIDs []string) (map[string]string, error) {
	states := map[string]string{}
	if deviceIDs != nil && len(deviceIDs) == 0 {
		return states, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT d.id::text, enc.status, enc.observed_value
		FROM devices d
		LEFT JOIN LATERAL (
			SELECT e.status, e.observed_value
			FROM compliance_evaluations e
			JOIN compliance_rules r ON r.id = e.rule_id
			WHERE e.device_id = d.id
			  AND r.rule_key = ANY($2)
			ORDER BY e.evaluated_at DESC
			LIMIT 1
		) enc ON true
		WHERE d.tenant_id = $1::uuid
		  AND ($3::uuid[] IS NULL OR d.id = ANY($3::uuid[]))
	`, tenantID, encryptionRuleKeys, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("fetch encryption states: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var status, observed *string
		if err := rows.Scan(&id, &status, &observed); err != nil {
			return nil, fmt.Errorf("scan encryption state: %w", err)
		}
		states[id] = classifyEncryptionEvaluation(status, observed)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate encryption states: %w", err)
	}
	return states, nil
}

// classifyEncryptionEvaluation turns a device's latest FileVault or BitLocker
// rule evaluation into one of the three states. status is nil when the device
// has no evaluation of either rule.
//
//   - pass is encrypted.
//   - fail or error with an observed value is not encrypted: the device was
//     read and the value was not "on". A positively observed off is never
//     unknown.
//   - fail with no observed value is unknown: the signal was absent or the
//     collector's "Unknown" sentinel, so nothing was observed (PAT-1762,
//     isUndeterminedEval). An error with no observed value is unknown for the
//     same reason.
//   - not_applicable, no evaluation, or any status this code does not know is
//     unknown. Absence requires authority: missing evidence never reads as
//     encrypted and never clears a finding.
func classifyEncryptionEvaluation(status, observed *string) string {
	if status == nil {
		return EncryptionStateUnknown
	}
	switch *status {
	case "pass":
		return EncryptionStateEncrypted
	case "fail":
		if isUndeterminedEval(EvalRow{Status: *status, ObservedValue: observed}) {
			return EncryptionStateUnknown
		}
		return EncryptionStateNotEncrypted
	case "error":
		if observed == nil {
			return EncryptionStateUnknown
		}
		return EncryptionStateNotEncrypted
	}
	return EncryptionStateUnknown
}

// encryptionStateOf is the state of deviceID in a FetchEncryptionStates
// result: unknown for a device the result does not carry.
func encryptionStateOf(states map[string]string, deviceID string) string {
	if s, ok := states[deviceID]; ok {
		return s
	}
	return EncryptionStateUnknown
}

// encryptionOKFromState is the portal's tri-state encryption_ok: true when
// encrypted, false when not encrypted, nil (not evaluated, undetermined or not
// applicable) when unknown. Never true off anything but an encrypted state.
func encryptionOKFromState(state string) *bool {
	switch state {
	case EncryptionStateEncrypted:
		v := true
		return &v
	case EncryptionStateNotEncrypted:
		v := false
		return &v
	}
	return nil
}
