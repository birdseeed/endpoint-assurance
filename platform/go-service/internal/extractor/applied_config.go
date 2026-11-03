package extractor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/appliedconfig"
)

// Ingestion for the macOS agent's applied_configuration object (PAT-1667,
// server side PAT-1668). This is configuration OBSERVED on the device — what
// actually landed — and never authored MDM policy. Nothing in this file
// records a policy name or an actor, because the endpoint cannot observe
// either.
//
// The write is append-only: one immutable snapshot row per device per
// collection run, plus one verbatim row per profile. Nothing is ever
// UPDATEd, and re-extracting an already-extracted raw payload is a no-op
// rather than a duplicate snapshot (see the UNIQUE in migration 0127).

// appliedConfigProfileCap bounds how many profile rows one snapshot may
// write. The agent already caps its own list at 500; this is the server-side
// backstop for a malformed or hostile payload claiming far more, matching the
// bounds-checking every other array section in this package applies. A
// payload that trips it still stores the profiles up to the cap and is
// logged — the cap truncating the list is recorded as profiles_truncated so
// the diff engine will not read the missing entries as absence.
const appliedConfigProfileCap = 1000

// appliedConfigPart mirrors the top-level "applied_configuration" object.
//
// Every field is decoded from a json.RawMessage carried on payload, not
// unmarshaled inline, for the reason BackupStatus and AgentHealth already
// are: a malformed shape (a field present with the wrong JSON type) must not
// abort the ENTIRE payload unmarshal in processRow and take a device's whole
// inventory upload down with it.
type appliedConfigPart struct {
	Profiles          []appliedConfigProfilePart `json:"profiles"`
	ProfilesCount     int                        `json:"profiles_count"`
	ProfilesTruncated bool                       `json:"profiles_truncated"`
	CollectionStatus  string                     `json:"collection_status"`
	MDMServerURL      *string                    `json:"mdm_server_url"`
	MDMSupervised     string                     `json:"mdm_supervised"`
}

// appliedConfigProfilePart is one element of applied_configuration.profiles.
//
// Payload is a string, not a nested object: the agent serialises the
// profile's payload items to text and head-caps them at a fixed byte budget,
// so a large profile arrives as a fragment that does not parse as JSON.
// Carrying it as a string and storing it verbatim is the only lossless
// option; decoding it into a structure would fail on exactly the profiles
// that are most worth keeping.
type appliedConfigProfilePart struct {
	Identifier    string `json:"identifier"`
	DisplayName   string `json:"display_name"`
	Organization  string `json:"organization"`
	Payload       string `json:"payload"`
	PayloadCapped bool   `json:"payload_capped"`
	DecodeError   bool   `json:"decode_error"`
}

// parseAppliedConfiguration decodes the applied_configuration section
// defensively. A decode failure is logged and treated exactly like "absent"
// — the device's other sections extract normally and no snapshot row is
// written — rather than propagated as a row-level extraction error. Same
// policy as parseBackupStatus.
//
// Note what absence means here and what it does NOT mean: no snapshot row is
// the record of "this run told us nothing about applied configuration". It
// is not a snapshot claiming zero profiles, and the diff engine can tell the
// two apart because one is a missing row and the other is a stored row with
// an empty profile list.
func parseAppliedConfiguration(raw json.RawMessage, logger *slog.Logger) *appliedConfigPart {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var a appliedConfigPart
	if err := json.Unmarshal(raw, &a); err != nil {
		if logger != nil {
			logger.Warn("skipping malformed applied_configuration section", "err", err)
		}
		return nil
	}
	return &a
}

// insertAppliedConfigSnapshot writes one immutable applied-configuration
// snapshot for the device, inside the caller's transaction. It returns the
// number of profile rows written.
//
// observedAt is the payload's own collected_at — when the device looked like
// this. A payload whose collected_at does not parse falls back to
// receivedAt, which is later than the true observation but never invented:
// the alternative, a zero timestamp, would sort as the oldest possible
// observation and could displace a genuinely older baseline.
func insertAppliedConfigSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	deviceID string,
	rawPayloadID int64,
	receivedAt time.Time,
	observedAt time.Time,
	part *appliedConfigPart,
	logger *slog.Logger,
) (int, error) {
	if part == nil {
		// Absent key — an agent that predates PAT-1667, or a section that
		// did not decode. No opinion: write nothing.
		return 0, nil
	}

	status, known := appliedconfig.NormaliseCollectionStatus(part.CollectionStatus)
	if !known && logger != nil {
		logger.Warn("applied_configuration: unrecognised collection_status; treating as unavailable so it is never used as a diff baseline",
			"device_id", deviceID, "collection_status_raw", part.CollectionStatus)
	}
	supervised, knownSup := appliedconfig.NormaliseSupervision(part.MDMSupervised)
	if !knownSup && logger != nil {
		logger.Warn("applied_configuration: unrecognised mdm_supervised; treating as Unknown",
			"device_id", deviceID, "mdm_supervised_raw", part.MDMSupervised)
	}

	profiles := part.Profiles
	truncated := part.ProfilesTruncated
	if len(profiles) > appliedConfigProfileCap {
		if logger != nil {
			logger.Warn("applied_configuration: profile list exceeded the server-side cap; storing the first entries and marking the snapshot truncated",
				"device_id", deviceID, "reported", len(profiles), "cap", appliedConfigProfileCap)
		}
		profiles = profiles[:appliedConfigProfileCap]
		truncated = true
	}

	// profiles_count is the agent's own count. When the agent reports more
	// profiles than it sent rows for, the list is bounded whatever the
	// truncated flag said — believe the arithmetic, not the flag, because
	// reading a short list as complete is what manufactures a false
	// mass-removal signal.
	reportedCount := part.ProfilesCount
	if reportedCount < len(profiles) {
		reportedCount = len(profiles)
	}
	if reportedCount > len(profiles) {
		truncated = true
	}

	var mdmURL *string
	if part.MDMServerURL != nil && *part.MDMServerURL != "" {
		mdmURL = part.MDMServerURL
	}

	if observedAt.IsZero() {
		observedAt = receivedAt
	}

	var snapshotID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO applied_config_snapshots
			(tenant_id, device_id, raw_payload_id, raw_payload_received_at, observed_at,
			 collection_status, profiles_count, profiles_truncated, mdm_server_url, mdm_supervised)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (device_id, raw_payload_id) DO NOTHING
		RETURNING id
	`, tenantID, deviceID, rawPayloadID, receivedAt, observedAt,
		string(status), reportedCount, truncated, mdmURL, string(supervised)).Scan(&snapshotID)
	if err == pgx.ErrNoRows {
		// This raw payload was already extracted into a snapshot. The table
		// is append-only and the observation is immutable, so a re-run has
		// nothing to add.
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("insert applied_config snapshot for device %s: %w", deviceID, err)
	}

	if len(profiles) == 0 {
		return 0, nil
	}

	batch := &pgx.Batch{}
	for i, p := range profiles {
		batch.Queue(`
			INSERT INTO applied_config_profiles
				(snapshot_id, ordinal, profile_identifier, display_name, organization,
				 payload, payload_capped, decode_error)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, snapshotID, i, p.Identifier, p.DisplayName, p.Organization, p.Payload, p.PayloadCapped, p.DecodeError)
	}
	br := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return 0, fmt.Errorf("insert applied_config profile %d for device %s: %w", i, deviceID, err)
		}
	}
	if err := br.Close(); err != nil {
		return 0, fmt.Errorf("close applied_config profile batch for device %s: %w", deviceID, err)
	}

	return len(profiles), nil
}
