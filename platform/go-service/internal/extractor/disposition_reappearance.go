package extractor

// PAT-1825: the automatic reappearance rule PAT-1595 deferred. A device that
// carries a live (non-superseded) device_dispositions row — someone said it
// was decommissioned, on leave, lost, or unaccounted for — and then reports
// inventory again is a finding, not something to silently re-absorb back
// into "reporting" (root AGENTS.md "absence requires authority" cuts both
// ways: an unexplained reappearance is exactly as much a fact needing
// evidence as an unexplained absence).
//
// This runs inside the same ingest transaction as the rest of processRow
// (extractor.go), immediately after upsertDevice sets devices.last_seen from
// this report's received_at (PAT-2102; no longer now() at extraction time —
// see upsertDevice's doc comment). The "is the report's received_at after
// the disposition's recorded_at" check below (PAT-2108; previously compared
// against time.Now().UTC() at extraction time) is evidence, not process
// timing: a report received before recorded_at is never reappearance, even
// if extraction falls behind and processes it after the disposition was
// recorded. Superseding inside the same transaction means a finding is
// never raised for a device write that itself rolls back.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/devicelifecycle"
)

// checkAndSupersedeReappearedDisposition looks up the device's live
// disposition (if any). When none exists, it is a no-op — the common case,
// and the one that must never fire a spurious finding or write. When one
// exists and receivedAt (the report's raw_payloads.received_at, PAT-2108)
// is after the disposition's recorded_at, this ingest is by construction a
// reappearance (see the package doc above), so it supersedes that
// disposition with reason "reappeared" and raises a
// device_lifecycle_findings row. A report received before recorded_at never
// counts as reappearance, even when extraction itself runs later. Returns
// the finding id (empty if nothing was raised) for the caller to log.
func checkAndSupersedeReappearedDisposition(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, receivedAt time.Time, logger *slog.Logger) (string, error) {
	var dispositionID string
	var recordedAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT id::text, recorded_at FROM device_dispositions
		WHERE device_id = $1::uuid AND superseded_at IS NULL
		FOR UPDATE
	`, deviceID).Scan(&dispositionID, &recordedAt)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load active disposition for device %s: %w", deviceID, err)
	}

	if !devicelifecycle.ReappearedSince(&receivedAt, recordedAt) {
		// This report's received_at is not after the disposition's
		// recorded_at — either it was received before the disposition was
		// recorded (extraction fell behind; not reappearance, PAT-2108) or
		// this is a same-instant race — leave the disposition live rather
		// than guess.
		return "", nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE device_dispositions SET superseded_at = now(), superseded_reason = 'reappeared'
		WHERE id = $1::uuid
	`, dispositionID); err != nil {
		return "", fmt.Errorf("supersede disposition %s on reappearance: %w", dispositionID, err)
	}

	var findingID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO device_lifecycle_findings (tenant_id, device_id, disposition_id, kind, detail)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'reappeared_after_disposition',
		        'device reported inventory after a disposition recorded ' || $4::text)
		RETURNING id::text
	`, tenantID, deviceID, dispositionID, recordedAt.Format(time.RFC3339)).Scan(&findingID); err != nil {
		return "", fmt.Errorf("raise reappearance finding for device %s: %w", deviceID, err)
	}

	if logger != nil {
		logger.Info("device reappeared after disposition; disposition superseded and finding raised",
			"tenant_id", tenantID, "device_id", deviceID, "disposition_id", dispositionID, "finding_id", findingID)
	}
	return findingID, nil
}
