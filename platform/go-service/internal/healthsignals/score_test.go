package healthsignals

import "testing"

// ptr is a convenience helper to get a pointer to an int literal.
func ptr(v int) *int { return &v }

// TestComputeScore_PerfectTenant verifies that a fully-healthy tenant with a
// high compliance score is clamped at 100 (the bonus would push it above).
func TestComputeScore_PerfectTenant(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 10,
		DaysSinceLastIngest:    ptr(1),
		ComplianceScoreCurrent: ptr(90),
		ComplianceScore30dAgo:  ptr(90),
		PaymentFailed:          false,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// +10 bonus (score > 80), zero penalties → 110 clamped to 100.
	if score != 100 {
		t.Errorf("perfect tenant: want score 100, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("perfect tenant: want bucket healthy, got %q", bucket)
	}
}

// TestComputeScore_IngestStale verifies the −30 ingest-staleness penalty.
func TestComputeScore_IngestStale(t *testing.T) {
	s := Signals{
		IngestStale:            true,
		DashboardLoginsLast30d: 5,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 30 = 70 → "watch"
	if score != 70 {
		t.Errorf("ingest stale: want 70, got %d", score)
	}
	if bucket != "watch" {
		t.Errorf("ingest stale: want watch, got %q", bucket)
	}
}

// TestComputeScore_NoLogins verifies the −20 no-logins penalty for non-report tier.
func TestComputeScore_NoLogins(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 0,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 20 = 80 → "healthy"
	if score != 80 {
		t.Errorf("no logins: want 80, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("no logins: want healthy, got %q", bucket)
	}
}

// TestComputeScore_AssuranceTierSkipsLoginPenalty verifies that the no-login
// penalty is suppressed for the "assurance" tier. (PAT-1599, migration 0138:
// was the "report" tier before the vocabulary collapsed to assurance/managed.)
func TestComputeScore_AssuranceTierSkipsLoginPenalty(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 0,
		SubscriptionTier:       "assurance",
	}
	score, bucket := ComputeScore(s)
	// 100, no login penalty for assurance tier → "healthy"
	if score != 100 {
		t.Errorf("assurance tier no login: want 100, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("assurance tier no login: want healthy, got %q", bucket)
	}
}

// TestComputeScore_ManagedTierAppliesLoginPenalty verifies the penalty applies
// to the "managed" tier (any non-"assurance" tier). (PAT-1599, migration 0138:
// was the "patch" tier before the vocabulary collapse.)
func TestComputeScore_ManagedTierAppliesLoginPenalty(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 0,
		SubscriptionTier:       "managed",
	}
	score, _ := ComputeScore(s)
	// 100 − 20 = 80
	if score != 80 {
		t.Errorf("managed tier no login: want 80, got %d", score)
	}
}

// TestComputeScore_ComplianceTrendDown verifies the 0.5×decline penalty.
func TestComputeScore_ComplianceTrendDown(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 5,
		ComplianceScoreCurrent: ptr(60),
		ComplianceScore30dAgo:  ptr(80),
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 0.5×(80−60) = 100 − 10 = 90 → "healthy"
	if score != 90 {
		t.Errorf("compliance trend down: want 90, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("compliance trend down: want healthy, got %q", bucket)
	}
}

// TestComputeScore_ComplianceTrendUp verifies that an improving score adds no penalty.
func TestComputeScore_ComplianceTrendUp(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 5,
		ComplianceScoreCurrent: ptr(80),
		ComplianceScore30dAgo:  ptr(60),
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 (no decline penalty; score==80 is not >80 so no bonus)
	if score != 100 {
		t.Errorf("compliance trend up: want 100, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("compliance trend up: want healthy, got %q", bucket)
	}
}

// TestComputeScore_PaymentFailed verifies the −15 payment-failure penalty.
func TestComputeScore_PaymentFailed(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 5,
		PaymentFailed:          true,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 15 = 85 → "healthy"
	if score != 85 {
		t.Errorf("payment failed: want 85, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("payment failed: want healthy, got %q", bucket)
	}
}

// TestComputeScore_MildStaleness verifies the −10 mild-staleness penalty
// (days > 7, below the 14-day ingest_stale threshold).
func TestComputeScore_MildStaleness(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 5,
		DaysSinceLastIngest:    ptr(8),
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 10 = 90 → "healthy"
	if score != 90 {
		t.Errorf("mild staleness: want 90, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("mild staleness: want healthy, got %q", bucket)
	}
}

// TestComputeScore_NoMildStalenessAtExactThreshold verifies boundary: 7 days
// is not penalised (strictly greater-than).
func TestComputeScore_NoMildStalenessAtExactThreshold(t *testing.T) {
	s := Signals{
		DashboardLoginsLast30d: 5,
		DaysSinceLastIngest:    ptr(7),
		SubscriptionTier:       "full_endpoint",
	}
	score, _ := ComputeScore(s)
	if score != 100 {
		t.Errorf("7 days: want 100 (no penalty), got %d", score)
	}
}

// TestComputeScore_HighComplianceBonus verifies the +10 bonus for score > 80.
func TestComputeScore_HighComplianceBonus(t *testing.T) {
	s := Signals{
		IngestStale:            false,
		DashboardLoginsLast30d: 5,
		ComplianceScoreCurrent: ptr(85),
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 + 10 = 110 clamped to 100
	if score != 100 {
		t.Errorf("high compliance bonus: want 100 (clamped), got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("high compliance bonus: want healthy, got %q", bucket)
	}
}

// TestComputeScore_HighComplianceNoBonusAt80 verifies the boundary: score == 80
// is not > 80, so no bonus.
func TestComputeScore_HighComplianceNoBonusAt80(t *testing.T) {
	s := Signals{
		DashboardLoginsLast30d: 5,
		ComplianceScoreCurrent: ptr(80),
		SubscriptionTier:       "full_endpoint",
	}
	score, _ := ComputeScore(s)
	if score != 100 {
		t.Errorf("score==80 boundary: want 100 (no bonus), got %d", score)
	}
}

// TestComputeScore_AtRisk tests a tenant that is clearly at-risk with
// multiple overlapping signals active at once.
func TestComputeScore_AtRisk(t *testing.T) {
	s := Signals{
		IngestStale:            true,
		DashboardLoginsLast30d: 0,
		DaysSinceLastIngest:    ptr(20),
		ComplianceScoreCurrent: ptr(30),
		ComplianceScore30dAgo:  ptr(60),
		PaymentFailed:          true,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100
	// − 30 (ingest_stale)
	// − 10 (days_since=20 > 7)
	// − 20 (no logins, full_endpoint)
	// − 0.5×(60−30)=15 (trend down)
	// − 15 (payment)
	// = 10
	if score != 10 {
		t.Errorf("at risk combined: want 10, got %d", score)
	}
	if bucket != "at_risk" {
		t.Errorf("at risk combined: want at_risk, got %q", bucket)
	}
}

// TestComputeScore_BucketBoundaries checks scores that sit exactly on the
// bucket thresholds (75 and 50).
func TestComputeScore_BucketBoundaries(t *testing.T) {
	// Score 75 → "healthy": 100 − 15 (payment) − 10 (mild stale, days=8) = 75.
	s75 := Signals{
		DashboardLoginsLast30d: 5,
		DaysSinceLastIngest:    ptr(8),
		PaymentFailed:          true,
		SubscriptionTier:       "full_endpoint",
	}
	score75, bucket75 := ComputeScore(s75)
	if score75 != 75 {
		t.Errorf("boundary 75: want 75, got %d", score75)
	}
	if bucket75 != "healthy" {
		t.Errorf("boundary 75: want healthy, got %q", bucket75)
	}

	// Score 50 → "watch": 100 − 30 (stale) − 20 (no logins) = 50.
	s50 := Signals{
		IngestStale:            true,
		DashboardLoginsLast30d: 0,
		SubscriptionTier:       "full_endpoint",
	}
	score50, bucket50 := ComputeScore(s50)
	if score50 != 50 {
		t.Errorf("boundary 50: want 50, got %d", score50)
	}
	if bucket50 != "watch" {
		t.Errorf("boundary 50: want watch, got %q", bucket50)
	}

	// Score 35 → "at_risk": 100 − 30 (stale) − 20 (no logins) − 15 (payment) = 35.
	s35 := Signals{
		IngestStale:            true,
		DashboardLoginsLast30d: 0,
		PaymentFailed:          true,
		SubscriptionTier:       "full_endpoint",
	}
	score35, bucket35 := ComputeScore(s35)
	if score35 != 35 {
		t.Errorf("at_risk 35: want 35, got %d", score35)
	}
	if bucket35 != "at_risk" {
		t.Errorf("at_risk 35: want at_risk, got %q", bucket35)
	}
}

// TestComputeScore_ClampLow verifies that the score is clamped to 0 and
// never goes negative even under all penalties at once.
func TestComputeScore_ClampLow(t *testing.T) {
	s := Signals{
		IngestStale:            true,
		DashboardLoginsLast30d: 0,
		DaysSinceLastIngest:    ptr(20),
		ComplianceScoreCurrent: ptr(0),
		ComplianceScore30dAgo:  ptr(100),
		PaymentFailed:          true,
		SubscriptionTier:       "full_endpoint",
	}
	score, bucket := ComputeScore(s)
	// 100 − 30 − 10 − 20 − 50 − 15 = −25 → clamped to 0
	if score != 0 {
		t.Errorf("clamp low: want 0, got %d", score)
	}
	if bucket != "at_risk" {
		t.Errorf("clamp low: want at_risk, got %q", bucket)
	}
}

// TestComputeScore_NilSignals verifies behaviour for a brand-new tenant with
// no devices, no compliance scores, and no explicit tier set.
func TestComputeScore_NilSignals(t *testing.T) {
	// "assurance" tier: no login penalty → 100.
	sAssurance := Signals{SubscriptionTier: "assurance"}
	score, bucket := ComputeScore(sAssurance)
	if score != 100 {
		t.Errorf("nil signals assurance tier: want 100, got %d", score)
	}
	if bucket != "healthy" {
		t.Errorf("nil signals assurance tier: want healthy, got %q", bucket)
	}

	// "managed" tier: no logins → −20 → 80.
	sManaged := Signals{SubscriptionTier: "managed"}
	score2, bucket2 := ComputeScore(sManaged)
	if score2 != 80 {
		t.Errorf("nil signals managed tier: want 80, got %d", score2)
	}
	if bucket2 != "healthy" {
		t.Errorf("nil signals managed tier: want healthy, got %q", bucket2)
	}
}

// TestComputeScore_OddDeclineRoundsCorrectly verifies math.Round is applied
// correctly on a decline that produces a fractional penalty (e.g. 7 × 0.5 = 3.5 → 4).
func TestComputeScore_OddDeclineRoundsCorrectly(t *testing.T) {
	s := Signals{
		DashboardLoginsLast30d: 5,
		ComplianceScoreCurrent: ptr(73),
		ComplianceScore30dAgo:  ptr(80),
		SubscriptionTier:       "full_endpoint",
	}
	score, _ := ComputeScore(s)
	// decline = 7, penalty = round(7 * 0.5) = round(3.5) = 4
	// 100 − 4 = 96
	if score != 96 {
		t.Errorf("odd decline rounding: want 96, got %d", score)
	}
}
