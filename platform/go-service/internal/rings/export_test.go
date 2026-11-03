package rings

// Test-only exports. This file is compiled into the package's test binary and
// never into the shipped one, so it adds no public API.
//
// The package's DB-backed tests live in package rings_test (advance_db_test.go)
// and own all the schema/fixture helpers, but queryFailureRate is unexported
// and takes an unexported approvalRow. PAT-1002's second review round needs
// that function's no-observations contract (ErrNoObservations) asserted
// directly rather than only inferred from processApproval's log output, so this
// is the standard export_test.go hatch: a thin wrapper taking plain arguments.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// QueryFailureRateForTest calls queryFailureRate with an approvalRow built from
// plain values. Returns exactly what queryFailureRate returns, including
// ErrNoObservations.
func QueryFailureRateForTest(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, platform, label, version string,
	approvedRing int16,
	lastAdvancedAt time.Time,
) (rate float64, failCount int, observedCount int, eligibleDevices int, err error) {
	return queryFailureRate(ctx, pool, approvalRow{
		TenantID:       tenantID,
		Platform:       platform,
		Label:          label,
		Version:        version,
		ApprovedRing:   approvedRing,
		State:          "rolling",
		LastAdvancedAt: lastAdvancedAt,
	})
}
