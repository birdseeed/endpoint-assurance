package healthsignals

import "math"

// Signals holds the per-tenant health signal values fed into ComputeScore.
// All pointer fields are nil when the signal has not yet been computed (e.g.
// a new tenant with no devices has DaysSinceLastIngest = nil).
type Signals struct {
	// IngestStale is true when the agent has not reported in more than 14 days.
	// This is the primary staleness flag — a big red signal.
	IngestStale bool

	// DashboardLoginsLast30d is the rolling count of portal logins in the last
	// 30 days. A zero value (no logins) is a disengagement signal.
	DashboardLoginsLast30d int

	// DaysSinceLastIngest is the number of days since the most recent device
	// ingest. Nil when no devices have ever reported for this tenant.
	DaysSinceLastIngest *int

	// ComplianceScoreCurrent is the most-recently-computed compliance score
	// (integer percentage 0–100). Nil when not yet computed.
	ComplianceScoreCurrent *int

	// ComplianceScore30dAgo is the compliance score captured 30 days ago.
	// Nil until the first 30-day rotation has occurred.
	ComplianceScore30dAgo *int

	// PaymentFailed is true when the tenant's Stripe billing status is
	// past_due or suspended.
	PaymentFailed bool

	// SubscriptionTier is the tenant's commercial tier ("assurance",
	// "managed" as of PAT-1599 migration 0138; was "report"/"patch"/
	// "full_endpoint" before). Used for context-sensitive adjustments.
	SubscriptionTier string
}

// ComputeScore computes the weighted health score (0–100) and health bucket
// ("healthy", "watch", or "at_risk") for a tenant from its health signals.
//
// Weighting model v1 (PAT-677). Weights are named constants below — easy to
// tune without changing test logic:
//
//	health_score = 100
//	  − 30  × ingest_stale
//	  − 20  × (dashboard_logins_last_30d == 0)  [skipped for "report" tier]
//	  − 0.5 × max(0, compliance_score_30d_ago − compliance_score_current)
//	  − 15  × payment_failed
//	  − 10  × (days_since_last_ingest > 7)
//	  + 10  × (compliance_score_current > 80)
//
//	Clamped to [0, 100].
//
//	Buckets:
//	  75–100 → "healthy"
//	  50–74  → "watch"
//	  0–49   → "at_risk"
//
// Tier adjustment: for subscription_tier = "assurance", the dashboard-login
// penalty is skipped because assurance-tier customers typically do not log in
// actively. (PAT-1599, migration 0138: was subscription_tier = "report"
// before the tier vocabulary collapsed "report" and "patch" into
// "assurance" — the exemption now covers both former rungs, consistent with
// assurance being defined as changing nothing on the endpoint, so active
// dashboard use isn't expected of it either.)
func ComputeScore(s Signals) (score int, bucket string) {
	// Penalty / bonus weights — tune here, not scattered through the logic.
	const (
		penaltyIngestStale     = 30
		penaltyNoLogins        = 20
		penaltyPaymentFailed   = 15
		penaltyMildStaleness   = 10
		bonusHighScore         = 10
		mildStalenessThreshold = 7  // days
		highScoreThreshold     = 80 // compliance %
		complianceTrendWeight  = 0.5
	)

	score = 100

	// −30: agent not reporting at all (ingest stopped).
	if s.IngestStale {
		score -= penaltyIngestStale
	}

	// −10: mild freshness warning (> 7 days since last ingest, but below the
	// 14-day stale threshold).  These penalties are additive when both apply.
	if s.DaysSinceLastIngest != nil && *s.DaysSinceLastIngest > mildStalenessThreshold {
		score -= penaltyMildStaleness
	}

	// −20: no dashboard logins in the last 30 days (disengagement signal).
	// Skipped for "assurance" tier — those customers do not actively log in.
	if s.SubscriptionTier != "assurance" && s.DashboardLoginsLast30d == 0 {
		score -= penaltyNoLogins
	}

	// −0.5 × decline: compliance score trending down (each percentage-point
	// drop contributes half a point to the penalty).
	if s.ComplianceScoreCurrent != nil && s.ComplianceScore30dAgo != nil {
		decline := *s.ComplianceScore30dAgo - *s.ComplianceScoreCurrent
		if decline > 0 {
			score -= int(math.Round(float64(decline) * complianceTrendWeight))
		}
	}

	// −15: payment failure (Stripe past_due / suspended).
	if s.PaymentFailed {
		score -= penaltyPaymentFailed
	}

	// +10: bonus for a high compliance score (> 80%).
	if s.ComplianceScoreCurrent != nil && *s.ComplianceScoreCurrent > highScoreThreshold {
		score += bonusHighScore
	}

	// Clamp to [0, 100].
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Assign bucket.
	switch {
	case score >= 75:
		bucket = "healthy"
	case score >= 50:
		bucket = "watch"
	default:
		bucket = "at_risk"
	}

	return score, bucket
}
