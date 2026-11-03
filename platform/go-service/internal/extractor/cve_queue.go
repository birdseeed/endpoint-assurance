package extractor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
)

// PAT-2024: the extractor is the home of the event-driven CVE matcher. It is
// already a DB-polling worker with a loopback metrics listener on this box,
// it holds the ingest transaction in which a product change becomes true, and
// it runs continuously, so a queued observation is drained within one poll
// cycle of landing instead of waiting for the 01:00 UTC nightly run.

// cveQueueDrainPerCycle bounds how many observations one poll cycle matches,
// so a large mapping publish cannot starve payload extraction.
const cveQueueDrainPerCycle = 500

// cveQueueMetricsEvery throttles the queue gauge refresh.
const cveQueueMetricsEvery = 30 * time.Second

// withSavepoint runs fn inside a nested transaction. A failure rolls back
// only fn's work, so the CVE queue can never fail or abort an extraction.
func withSavepoint(ctx context.Context, tx pgx.Tx, fn func(pgx.Tx) error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin savepoint: %w", err)
	}
	if err := fn(sp); err != nil {
		_ = sp.Rollback(ctx)
		return err
	}
	return sp.Commit(ctx)
}

// snapshotAppsForCVEQueue captures the device's products before upsertApps.
// nil means the snapshot failed and no delta will be enqueued for this row;
// the affected products then read as pending until the next full match,
// because their assessments no longer match their installed versions.
func snapshotAppsForCVEQueue(ctx context.Context, tx pgx.Tx, deviceID string, logger *slog.Logger) cvepipeline.AppVersions {
	var before cvepipeline.AppVersions
	err := withSavepoint(ctx, tx, func(sp pgx.Tx) error {
		var err error
		before, err = cvepipeline.SnapshotDeviceApps(ctx, sp, deviceID)
		return err
	})
	if err != nil {
		if logger != nil {
			logger.Warn("cve match queue: pre-ingest app snapshot failed; this payload's product changes will wait for the nightly match",
				"device_id", deviceID, "err", err)
		}
		return nil
	}
	return before
}

// enqueueCVEIngestDelta diffs the post-upsert products against before and
// queues the changed, mapped products for matching. Runs in the ingest
// transaction (under a savepoint) so the queue row commits exactly when the
// inventory change does.
//
// PAT-2138: the changed products no mapping covers on the device's platform
// (FilterMapped's rejects) are recorded as CPE mapping proposals in the same
// transaction, under their own nested savepoint so a proposal failure never
// costs the match queue its rows. Database only: candidates and the model
// choice come from the proposer loop (runCPEProposer), never from ingest.
func enqueueCVEIngestDelta(ctx context.Context, tx pgx.Tx, tenantID, deviceID, platform string,
	before cvepipeline.AppVersions, appsPresent bool, logger *slog.Logger) {
	if before == nil {
		return
	}
	var enqueued, dropped, proposed int
	var proposeErr error
	err := withSavepoint(ctx, tx, func(sp pgx.Tx) error {
		after, err := cvepipeline.SnapshotDeviceApps(ctx, sp, deviceID)
		if err != nil {
			return err
		}
		changed := cvepipeline.ChangedProducts(before, after, appsPresent)
		if len(changed) == 0 {
			return nil
		}
		mappings, err := cvepipeline.LoadMappings(ctx, sp)
		if err != nil {
			return err
		}
		// Only products still installed can be proposed: a removal is in
		// changed too, and has nothing to map.
		present := make([]string, 0, len(changed))
		for _, n := range changed {
			if _, ok := after[n]; ok {
				present = append(present, n)
			}
		}
		proposeErr = withSavepoint(ctx, sp, func(psp pgx.Tx) error {
			// Browser web-app wrappers are not products: never proposed.
			names, err := cpepropose.DropWebAppWrappers(ctx, psp, deviceID, present)
			if err != nil {
				return err
			}
			proposed, err = cpepropose.RecordUnmapped(ctx, psp, tenantID, cvematch.NormalizeDevicePlatform(platform), names, mappings)
			return err
		})
		changed = cvepipeline.FilterMapped(changed, mappings)
		enqueued, dropped, err = cvepipeline.EnqueueObservations(ctx, sp, tenantID, deviceID, changed, cvepipeline.SourceIngest)
		return err
	})
	if logger != nil && proposeErr != nil && !cpepropose.IsUndefinedTable(proposeErr) {
		logger.Warn("cpe mapping proposals: recording failed; the backfill or the next report will record them",
			"device_id", deviceID, "err", proposeErr)
	}
	if logger != nil && proposed > 0 {
		logger.Info("cpe mapping proposals recorded", "device_id", deviceID, "count", proposed)
	}
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("cve match queue: enqueue failed; this payload's product changes will wait for the nightly match",
			"device_id", deviceID, "err", err)
		return
	}
	if dropped > 0 {
		logger.Warn("cve match queue at capacity (global or this tenant's share); product changes dropped until the nightly match",
			"device_id", deviceID, "dropped", dropped, "capacity", cvepipeline.QueueCapacity,
			"tenant_id", tenantID, "tenant_capacity", cvepipeline.TenantQueueCapacity)
	}
	if enqueued > 0 {
		logger.Info("cve match observations queued", "device_id", deviceID, "count", enqueued)
	}
}

// snapshotHomebrewForCVEQueue captures the device's current Homebrew match
// input before the payload's Homebrew block is stored (PAT-2023). nil means
// there is nothing to diff: the payload has no Homebrew block, or the
// snapshot failed, in which case changed packages wait for the nightly match.
func snapshotHomebrewForCVEQueue(ctx context.Context, tx pgx.Tx, deviceID string, hb *homebrewPart, logger *slog.Logger) cvepipeline.AppVersions {
	if hb == nil {
		return nil
	}
	var before cvepipeline.AppVersions
	err := withSavepoint(ctx, tx, func(sp pgx.Tx) error {
		var err error
		before, err = cvepipeline.SnapshotDeviceHomebrew(ctx, sp, deviceID)
		return err
	})
	if err != nil {
		if logger != nil {
			logger.Warn("cve match queue: pre-ingest homebrew snapshot failed; this payload's homebrew changes will wait for the nightly match",
				"device_id", deviceID, "err", err)
		}
		return nil
	}
	return before
}

// enqueueCVEHomebrewDelta hands the pre-ingest snapshot to
// cvepipeline.QueueHomebrewDelta inside the ingest transaction (under a
// savepoint, so it can never fail the extraction).
func enqueueCVEHomebrewDelta(ctx context.Context, tx pgx.Tx, tenantID, deviceID string,
	before cvepipeline.AppVersions, logger *slog.Logger) {
	if before == nil {
		return
	}
	var enqueued, dropped int
	err := withSavepoint(ctx, tx, func(sp pgx.Tx) error {
		var err error
		enqueued, dropped, err = cvepipeline.QueueHomebrewDelta(ctx, sp, tenantID, deviceID, before)
		return err
	})
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("cve match queue: homebrew enqueue failed; this payload's homebrew changes will wait for the nightly match",
			"device_id", deviceID, "err", err)
		return
	}
	if dropped > 0 {
		logger.Warn("cve match queue at capacity (global or this tenant's share); homebrew changes dropped until the nightly match",
			"device_id", deviceID, "dropped", dropped, "capacity", cvepipeline.QueueCapacity,
			"tenant_id", tenantID, "tenant_capacity", cvepipeline.TenantQueueCapacity)
	}
	if enqueued > 0 {
		logger.Info("cve match homebrew observations queued", "device_id", deviceID, "count", enqueued)
	}
}

// drainCVEQueue runs one bounded pass of the event-driven matcher and keeps
// the queue gauges fresh. Errors are logged; the loop never stops on them.
func (w *Worker) drainCVEQueue(ctx context.Context, logger *slog.Logger) {
	if _, err := cvepipeline.Drain(ctx, w.Pool, logger.With("component", "cve_match_queue"), cveQueueDrainPerCycle); err != nil {
		logger.Warn("cve match queue drain failed", "err", err)
	}
	if time.Since(w.lastCVEQueueMetrics) >= cveQueueMetricsEvery {
		w.lastCVEQueueMetrics = time.Now()
		if _, err := cvepipeline.RefreshQueueMetrics(ctx, w.Pool); err != nil {
			logger.Warn("cve match queue metrics refresh failed", "err", err)
		}
	}
}
