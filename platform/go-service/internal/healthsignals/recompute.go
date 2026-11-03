// Package healthsignals computes and stores per-tenant health signal columns
// (PAT-676). The Recompute function is called nightly by the extractor's
// automation loop and on-demand via POST /admin/health-signals/recompute.
package healthsignals

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Recompute refreshes per-tenant health signal columns for every non-revoked
// tenant. Per tenant it:
//
//  1. Computes days_since_last_ingest = days since MAX(device.last_seen).
//  2. Sets ingest_stale = true when days_since_last_ingest > 14.
//  3. Computes compliance_score_current (% passing evaluations, latest per
//     device+rule combination).
//  4. When ≥ 30 days have genuinely elapsed since health_signals_last_rotated_at
//     (PAT-872: a dedicated column, not the general-purpose updated_at that
//     this function also stamps every run), rotates the current score into
//     compliance_score_30d_ago, resets dashboard_logins_last_30d to start a
//     fresh window, and advances health_signals_last_rotated_at.
//  5. Computes health_score + health_bucket from all signals (PAT-677).
//
// Each tenant is updated independently; a failure on one tenant is logged and
// does not abort the sweep.
func Recompute(ctx context.Context, pool *pgxpool.Pool) error {
	logger := slog.With("job", "health_signals_recompute")
	logger.Info("health signals recompute starting")
	start := time.Now()

	rows, err := pool.Query(ctx, `SELECT id::text FROM tenants WHERE revoked_at IS NULL`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var errCount int
	for _, id := range ids {
		if err := recomputeOne(ctx, pool, id); err != nil {
			logger.Warn("recompute failed", "tenant_id", id, "err", err)
			errCount++
		}
	}

	logger.Info("health signals recompute done",
		"tenants", len(ids),
		"errors", errCount,
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
	return nil
}

func recomputeOne(ctx context.Context, pool *pgxpool.Pool, tenantID string) error {
	tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Fetch existing tenant state: current scores for the 30-day rotation
	// decision, plus the health-score signal fields (dashboard logins,
	// payment status, subscription tier).
	//
	// health_signals_last_rotated_at (PAT-872) is the dedicated rotation
	// gate, deliberately NOT updated_at, which this same function also
	// stamps with now() on every run (see the UPDATE below) and would
	// therefore never let 30 real days elapse.
	var currentScore, score30dAgo *int
	var createdAt time.Time
	var lastRotatedAt *time.Time
	var dashLogins int
	var paymentFailed bool
	var subscriptionTier string
	_ = pool.QueryRow(tCtx, `
		SELECT compliance_score_current, compliance_score_30d_ago, created_at,
		       health_signals_last_rotated_at,
		       dashboard_logins_last_30d, payment_failed, subscription_tier
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&currentScore, &score30dAgo, &createdAt, &lastRotatedAt,
		&dashLogins, &paymentFailed, &subscriptionTier)

	// Days since last device ingest.
	var daysSinceIngest *int
	var ingestStale bool
	_ = pool.QueryRow(tCtx, `
		SELECT EXTRACT(DAY FROM now() - MAX(d.last_seen))::int
		FROM devices d
		WHERE d.tenant_id = $1::uuid
	`, tenantID).Scan(&daysSinceIngest)
	if daysSinceIngest != nil && *daysSinceIngest > 14 {
		ingestStale = true
	}

	// Current compliance score.
	var total, passing int64
	_ = pool.QueryRow(tCtx, `
		WITH latest_evals AS (
			SELECT DISTINCT ON (ce.device_id, ce.rule_id)
				ce.status
			FROM compliance_evaluations ce
			JOIN devices d ON d.id = ce.device_id
			WHERE d.tenant_id = $1::uuid
			ORDER BY ce.device_id, ce.rule_id, ce.evaluated_at DESC
		)
		SELECT
			COUNT(*) FILTER (WHERE status NOT IN ('not_applicable')),
			COUNT(*) FILTER (WHERE status = 'pass')
		FROM latest_evals
	`, tenantID).Scan(&total, &passing)

	var newScore *int
	if total > 0 {
		pct := int(math.Round(float64(passing) / float64(total) * 100))
		newScore = &pct
	}

	// 30-day rotation: when it has genuinely been >= 30 days since the last
	// rotation, rotate the current score into the 30d-ago column and start a
	// fresh dashboard-login window before overwriting either.
	//
	// Baseline for "last rotation": health_signals_last_rotated_at when
	// rotation has fired at least once; otherwise created_at, so the very
	// first rotation still waits a genuine 30 days after the tenant started
	// existing rather than firing on whatever run happens to first see a
	// non-nil compliance score.
	rotationBaseline := createdAt
	if lastRotatedAt != nil {
		rotationBaseline = *lastRotatedAt
	}

	var rotated *int
	rotationFired := currentScore != nil && time.Since(rotationBaseline) >= 30*24*time.Hour
	if rotationFired {
		rotated = currentScore
		// For the health-score trend calc below, treat the rotated score as
		// the 30d-ago baseline (it is about to become that in the DB).
		score30dAgo = currentScore
	}

	// Effective current compliance score for the health-score model: use the
	// freshly computed value if available, else fall back to the stored one.
	effectiveScore := newScore
	if effectiveScore == nil {
		effectiveScore = currentScore
	}

	// Compute health score + bucket from all signals (PAT-677).
	sigs := Signals{
		IngestStale:            ingestStale,
		DashboardLoginsLast30d: dashLogins,
		DaysSinceLastIngest:    daysSinceIngest,
		ComplianceScoreCurrent: effectiveScore,
		ComplianceScore30dAgo:  score30dAgo,
		PaymentFailed:          paymentFailed,
		SubscriptionTier:       subscriptionTier,
	}
	healthScore, healthBucket := ComputeScore(sigs)

	// health_signals_last_rotated_at and the dashboard_logins_last_30d reset
	// are both stamped with SQL now()/literal 0 via a CASE on rotationFired
	// (rather than passing a Go time.Now() value) so they share the exact
	// same clock as health_score_computed_at/updated_at in this same UPDATE.
	_, err := pool.Exec(tCtx, `
		UPDATE tenants SET
			days_since_last_ingest          = $2,
			ingest_stale                    = $3,
			compliance_score_current        = COALESCE($4, compliance_score_current),
			compliance_score_30d_ago        = COALESCE($5, compliance_score_30d_ago),
			health_signals_last_rotated_at  = CASE WHEN $6 THEN now() ELSE health_signals_last_rotated_at END,
			dashboard_logins_last_30d       = CASE WHEN $6 THEN 0 ELSE dashboard_logins_last_30d END,
			health_score                    = $7,
			health_bucket                   = $8,
			health_score_computed_at        = now(),
			updated_at                      = now()
		WHERE id = $1::uuid
	`, tenantID, daysSinceIngest, ingestStale, newScore, rotated, rotationFired, healthScore, healthBucket)
	return err
}
