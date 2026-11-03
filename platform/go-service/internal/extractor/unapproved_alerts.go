package extractor

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

// unapprovedAlertTimeout bounds the post-commit unapproved alert check.
const unapprovedAlertTimeout = 20 * time.Second

// raiseUnapprovedObservations raises PAT-2009's observed alert for one device
// after its extraction committed, then applies the PAT-2097 alert lifecycle
// to the device's tracked alerts. It is a reporting side effect: every error
// is logged and dropped, and the extraction result is already durable. A pair
// missed here remains in the durable device-check queue stamped with this
// report's prune decision and evidence-time gate before commit. The runner
// retries detection and lifecycle; their ledgers make replay safe.
//
// appsAbsenceComplete is true only for a report whose collection_status.apps
// was "complete" (schema v3) and whose prune ran. It is the only authority
// under which an application alert may resolve as not observed.
func raiseUnapprovedObservations(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, appsAbsenceComplete bool, logger *slog.Logger) {
	if pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, unapprovedAlertTimeout)
	defer cancel()
	if logger == nil {
		logger = slog.Default()
	}
	// PAT-2095: bring the device's Unapproved-present summary rows up to
	// date. With a 250ms work budget and 1ms lock budget, contention from a
	// rebuild or policy write leaves the device dirty, and readers
	// resolve a dirty device live until the runner refreshes it.
	if err := softwaregov.RefreshDevice(ctx, pool, tenantID, deviceID, time.Now()); err != nil {
		logger.Warn("unapproved software summary refresh failed; extraction unaffected",
			"device_id", deviceID, "err", err)
	}
	res, rec, err := softwaregov.ProcessDeviceCheck(ctx, pool, tenantID, deviceID,
		softwaregov.DeviceAuthority{AppsComplete: appsAbsenceComplete}, time.Now())
	if err != nil {
		logger.Warn("unapproved software alert check failed; extraction unaffected",
			"device_id", deviceID, "err", err)
	} else if len(res.AlertIDs) > 0 {
		logger.Info("unapproved software alerts raised", "device_id", deviceID,
			"alerts", len(res.AlertIDs), "webhooks", res.Webhooks)
	}
	if len(rec.Resolved) > 0 || len(rec.Reopened) > 0 {
		logger.Info("unapproved software alert lifecycle applied", "device_id", deviceID,
			"resolved", len(rec.Resolved), "reopened", len(rec.Reopened))
	}
}
