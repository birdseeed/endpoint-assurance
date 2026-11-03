package appliedconfig

import (
	"context"
	"fmt"
	"time"
)

// Store is the read seam for applied-configuration snapshots. The write side
// deliberately does not live here: snapshots are written by the extractor,
// inside the same transaction as the rest of a device's inventory row
// (internal/extractor/applied_config.go), so that an observation and the
// evidence it was derived from commit together or not at all.
type Store interface {
	// ComparablePairs returns, for each device in the tenant, the two most
	// recent ok snapshots — but only for devices whose newest ok snapshot
	// was observed at or after since.
	//
	// The three exclusions this must enforce, which are the whole reason
	// the query lives behind an interface rather than being inlined:
	//
	//   - a snapshot whose collection_status is not 'ok' is never returned,
	//     so a rate-limited run can neither be diffed nor displace the last
	//     good baseline;
	//   - a device with fewer than two ok snapshots yields no pair;
	//   - a device whose newest ok snapshot predates since yields no pair,
	//     so a device that stopped reporting produces no change entries
	//     rather than appearing to have lost every profile.
	//
	// Pass the zero time for since to consider every device's newest run
	// regardless of age.
	ComparablePairs(ctx context.Context, tenantID string, since time.Time) ([]SnapshotPair, error)
}

// TenantEstateChanges is the end-to-end call: load each device's comparable
// pair of observations, diff them, and roll the results up into grouped
// estate findings.
//
// A plain callable function, with no scheduler behind it — PAT-1668
// deliberately does not decide when this runs.
func TenantEstateChanges(ctx context.Context, store Store, tenantID string, since time.Time) (EstateReport, error) {
	pairs, err := store.ComparablePairs(ctx, tenantID, since)
	if err != nil {
		return EstateReport{}, fmt.Errorf("appliedconfig: load comparable pairs: %w", err)
	}

	sets := make([]DeviceChangeSet, 0, len(pairs))
	for _, p := range pairs {
		set, err := Diff(p.Prior, p.Current)
		if err != nil {
			return EstateReport{}, fmt.Errorf("appliedconfig: device %s: %w", p.Current.DeviceID, err)
		}
		sets = append(sets, set)
	}

	report, err := Rollup(tenantID, sets)
	if err != nil {
		return EstateReport{}, err
	}
	report.ConsideredFrom = since
	report.DevicesCompared = len(pairs)
	return report, nil
}
