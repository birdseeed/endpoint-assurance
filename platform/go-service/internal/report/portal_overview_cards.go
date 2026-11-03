package report

// Overview information cards (PAT-2207): the read model behind
// GET /v1/portal/overview/cards. It exists so the portal never has to infer
// health from absent or partial platform data. Every card states what it
// knows (state), where it came from (source), how fresh it is (freshness),
// whether it covers the whole scope it names (completeness) and whether that
// scope is the current estate or a bounded window (scope/window).
//
// Each card reuses the query behind the equivalent existing surface
// (FetchExecutiveSummary's section fetchers, fetchPortalCVEAttention,
// FetchPortalExtensions, softwaregov.FetchNewSoftwareUrgency,
// softwaregov.LoadEstate, fetchDegradedDevices). Every one is scoped by the
// tenantID the caller passes, which on the portal is always the
// portalauth-resolved tenant, never client input.
//
// Failure isolation: only the base device query fails the whole read. Any
// other card whose source fails degrades to unavailable with reason
// query_failed. The contract is documented in contracts/portal-api.md.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/softwaregov"
)

// Reporting thresholds. Active matches the overview's devices_reporting_24h;
// silent matches softwaregov.StaleAfter, the 14 days the stale endpoints
// report and the software coverage figures already use.
const (
	OverviewActiveWithin = 24 * time.Hour
	OverviewSilentAfter  = softwaregov.StaleAfter
	// OverviewExceptionReviewDueWithinDays is how close a review date must
	// be, in whole UTC days, to count as due soon.
	OverviewExceptionReviewDueWithinDays = 30
)

// Card states. Distinct on the wire: zero is a checked, authoritative
// nothing; unknown is a working source with no evidence to decide from;
// unavailable is a source that failed, is not supported yet or refused the
// estate; partial is a real figure over incomplete coverage.
const (
	CardStateValue       = "value"
	CardStateZero        = "zero"
	CardStateUnknown     = "unknown"
	CardStateUnavailable = "unavailable"
	CardStatePartial     = "partial"
)

// Card scopes.
const (
	CardScopeSnapshot = "current_snapshot"
	CardScopeWindow   = "bounded_window"
)

// Reason codes (bounded, snake_case).
const (
	CardReasonQueryFailed         = "query_failed"
	CardReasonSourceNotMigrated   = "source_not_migrated"
	CardReasonNotYetSupported     = "not_yet_supported"
	CardReasonNotModelled         = "not_modelled"
	CardReasonNoUpdateEvidence    = "no_update_evidence"
	CardReasonVersionEvidence     = "version_evidence_pending"
	CardReasonNoCompletedMatchRun = "no_completed_match_run"
	CardReasonNoEvaluations       = "no_evaluations"
	CardReasonEstateTooLarge      = "estate_too_large"
	CardReasonTruncated           = "truncated"
	CardReasonCoverageIncomplete  = "coverage_incomplete"
	CardReasonDevicesNotReporting = "devices_not_reporting"
	CardReasonNoDevices           = "no_devices"
)

// OverviewCardWindow bounds a bounded_window card. Days is the longest the
// window can be; Since is where this window actually starts (a more recent
// review shortens it) and Basis says why.
type OverviewCardWindow struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	Days  int       `json:"days"`
	Basis string    `json:"basis"`
}

// OverviewCardFreshness: GeneratedAt is the platform (database) time the
// card was computed; ObservedAt is the newest evidence the figure rests on,
// null when the source records no such time.
type OverviewCardFreshness struct {
	GeneratedAt time.Time  `json:"generated_at"`
	ObservedAt  *time.Time `json:"observed_at"`
}

// OverviewCardCompleteness: Complete is true exactly when State is value or
// zero. Reason is a bounded code, null when complete.
type OverviewCardCompleteness struct {
	Complete bool    `json:"complete"`
	Reason   *string `json:"reason"`
}

// OverviewUnavailableSignal names a signal the card deliberately does not
// carry yet, whatever the card's own state.
type OverviewUnavailableSignal struct {
	Signal string `json:"signal"`
	Reason string `json:"reason"`
}

// OverviewCard is one card. Values is null when State is unknown or
// unavailable, and a card-specific object otherwise.
type OverviewCard struct {
	State              string                      `json:"state"`
	Source             string                      `json:"source"`
	Scope              string                      `json:"scope"`
	Window             *OverviewCardWindow         `json:"window"`
	Freshness          OverviewCardFreshness       `json:"freshness"`
	Completeness       OverviewCardCompleteness    `json:"completeness"`
	Values             any                         `json:"values"`
	UnavailableSignals []OverviewUnavailableSignal `json:"unavailable_signals"`
}

// Card values, one type per card.
type (
	DevicesCardValues struct {
		Total   int `json:"total"`
		Active  int `json:"active"`
		Stale   int `json:"stale"`
		Silent  int `json:"silent"`
		Unknown int `json:"unknown"`
		Retired int `json:"retired"`
	}
	OSUpdatesCardValues struct {
		UpToDate int `json:"up_to_date"`
		Pending  int `json:"pending"`
		Unknown  int `json:"unknown"`
	}
	VulnerabilitiesCardValues struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
	}
	CISPostureCardValues struct {
		Score       float64 `json:"score"`
		Evaluations int     `json:"evaluations"`
	}
	BrowserExtensionsCardValues struct {
		Elevated int `json:"elevated"`
		Total    int `json:"total"`
	}
	HighRiskSoftwareCardValues struct {
		Critical   int `json:"critical"`
		High       int `json:"high"`
		Classified int `json:"classified"`
	}
	AwaitingApprovalCardValues struct {
		Products int `json:"products"`
		Devices  int `json:"devices"`
	}
	ExceptionsReviewCardValues struct {
		ReviewOverdue int `json:"review_overdue"`
		ReviewDueSoon int `json:"review_due_soon"`
		NoReviewDate  int `json:"no_review_date"`
		Unaccepted    int `json:"unaccepted"`
		Total         int `json:"total"`
	}
	AgentHealthCardValues struct {
		DevicesDegraded        int        `json:"devices_degraded"`
		DevicesReporting       int        `json:"devices_reporting"`
		DevicesNotReporting    int        `json:"devices_not_reporting"`
		OldestSuccessfulIngest *time.Time `json:"oldest_successful_ingest"`
	}
)

// OverviewCardThresholds echoes the thresholds the cards were computed with.
type OverviewCardThresholds struct {
	ActiveWithinHours            int `json:"active_within_hours"`
	SilentAfterDays              int `json:"silent_after_days"`
	ExceptionReviewDueWithinDays int `json:"exception_review_due_within_days"`
}

// OverviewCardSet is every card, always all present.
type OverviewCardSet struct {
	Devices                  OverviewCard `json:"devices"`
	OSUpdates                OverviewCard `json:"os_updates"`
	Vulnerabilities          OverviewCard `json:"vulnerabilities"`
	CISPosture               OverviewCard `json:"cis_posture"`
	BrowserExtensions        OverviewCard `json:"browser_extensions"`
	HighRiskSoftware         OverviewCard `json:"high_risk_software"`
	SoftwareAwaitingApproval OverviewCard `json:"software_awaiting_approval"`
	ExceptionsReview         OverviewCard `json:"exceptions_review"`
	AgentHealth              OverviewCard `json:"agent_health"`
	RecentActivity           OverviewCard `json:"recent_activity"`
}

// PortalOverviewCards is the GET /v1/portal/overview/cards response.
type PortalOverviewCards struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Thresholds  OverviewCardThresholds `json:"thresholds"`
	Cards       OverviewCardSet        `json:"cards"`
}

// ---------------------------------------------------------------------------
// Test hook
// ---------------------------------------------------------------------------

var (
	overviewCardFailMu sync.Mutex
	overviewCardFail   = map[string]error{}
)

// SetOverviewCardFailureForTest makes the named Overview card's source fail
// with err until the returned restore func runs (PAT-2207). Test-only,
// exported for the handlers package in the same way as
// SetPortalExtensionsMaxSourceRowsForTest. "devices" fails the base query.
func SetOverviewCardFailureForTest(card string, err error) (restore func()) {
	overviewCardFailMu.Lock()
	prev, had := overviewCardFail[card]
	overviewCardFail[card] = err
	overviewCardFailMu.Unlock()
	return func() {
		overviewCardFailMu.Lock()
		defer overviewCardFailMu.Unlock()
		if had {
			overviewCardFail[card] = prev
		} else {
			delete(overviewCardFail, card)
		}
	}
}

func overviewCardFailure(card string) error {
	overviewCardFailMu.Lock()
	defer overviewCardFailMu.Unlock()
	return overviewCardFail[card]
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

type overviewDeviceBuckets struct {
	now            time.Time
	values         DevicesCardValues
	newest, oldest *time.Time
}

// FetchPortalOverviewCards builds every Overview card for tenantID. It
// returns an error only when the base device query fails.
func FetchPortalOverviewCards(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalOverviewCards, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return PortalOverviewCards{}, err
	}
	b, err := fetchOverviewDeviceBuckets(ctx, pool, tenantID, sw)
	if err != nil {
		return PortalOverviewCards{}, err
	}
	now := b.now
	out := PortalOverviewCards{
		GeneratedAt: now,
		Thresholds: OverviewCardThresholds{
			ActiveWithinHours:            int(OverviewActiveWithin / time.Hour),
			SilentAfterDays:              int(OverviewSilentAfter / (24 * time.Hour)),
			ExceptionReviewDueWithinDays: OverviewExceptionReviewDueWithinDays,
		},
	}
	c := &out.Cards
	c.Devices = devicesCard(now, b)
	c.OSUpdates = osUpdatesCard(ctx, pool, tenantID, sw, now, b)
	c.Vulnerabilities = vulnerabilitiesCard(ctx, pool, tenantID, now)
	c.CISPosture = cisPostureCard(ctx, pool, tenantID, sw, now)
	c.BrowserExtensions = browserExtensionsCard(ctx, pool, tenantID, now)
	c.HighRiskSoftware = highRiskSoftwareCard(ctx, pool, tenantID, now)
	c.SoftwareAwaitingApproval = awaitingApprovalCard(ctx, pool, tenantID, now)
	c.ExceptionsReview = exceptionsReviewCard(ctx, pool, tenantID, now)
	c.AgentHealth = agentHealthCard(ctx, pool, tenantID, sw, now, b)
	c.RecentActivity = unavailableCard(newCard("activity_feed", CardScopeWindow, now), CardReasonNotYetSupported)
	return out, nil
}

func newCard(source, scope string, now time.Time) OverviewCard {
	return OverviewCard{
		Source:             source,
		Scope:              scope,
		Freshness:          OverviewCardFreshness{GeneratedAt: now},
		UnavailableSignals: []OverviewUnavailableSignal{},
	}
}

func completeCard(c OverviewCard, zero bool, values any) OverviewCard {
	c.State = CardStateValue
	if zero {
		c.State = CardStateZero
	}
	c.Completeness = OverviewCardCompleteness{Complete: true}
	c.Values = values
	return c
}

func partialCard(c OverviewCard, reason string, values any) OverviewCard {
	c.State = CardStatePartial
	c.Completeness = OverviewCardCompleteness{Reason: &reason}
	c.Values = values
	return c
}

func unknownCard(c OverviewCard, reason string) OverviewCard {
	c.State = CardStateUnknown
	c.Completeness = OverviewCardCompleteness{Reason: &reason}
	c.Values = nil
	return c
}

// queryFailed degrades a card whose source failed, and logs why: an
// unavailable card must never be a silent failure.
func queryFailed(c OverviewCard, card, tenantID string, err error) OverviewCard {
	slog.Warn("overview card source failed", "card", card, "tenant_id", tenantID, "err", err)
	return unavailableCard(c, CardReasonQueryFailed)
}

func unavailableCard(c OverviewCard, reason string) OverviewCard {
	c.State = CardStateUnavailable
	c.Completeness = OverviewCardCompleteness{Reason: &reason}
	c.Values = nil
	c.Window = nil
	return c
}

// fetchOverviewDeviceBuckets is the base query. The buckets are mutually
// exclusive and sum to total, on the database clock:
//
//	retired  the customer retired it (PAT-2135), whatever its last report
//	unknown  no usable report time: NULL, or later than the database clock
//	active   reported within OverviewActiveWithin
//	stale    older than that, but within OverviewSilentAfter
//	silent   not reported for longer than OverviewSilentAfter
//
// Platform switches apply exactly as for the overview's devices_total.
func fetchOverviewDeviceBuckets(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches) (overviewDeviceBuckets, error) {
	var b overviewDeviceBuckets
	if err := overviewCardFailure("devices"); err != nil {
		return b, fmt.Errorf("overview cards devices: %w", err)
	}
	osFilter := enabledOSFilter(sw)
	v := &b.values
	err := pool.QueryRow(ctx, `
		SELECT now(),
		       COUNT(*)::int,
		       COUNT(*) FILTER (WHERE NOT r.retired AND d.last_seen <= now() AND d.last_seen > now() - ($2::bigint * interval '1 second'))::int,
		       COUNT(*) FILTER (WHERE NOT r.retired AND d.last_seen <= now() - ($2::bigint * interval '1 second') AND d.last_seen >= now() - ($3::bigint * interval '1 second'))::int,
		       COUNT(*) FILTER (WHERE NOT r.retired AND d.last_seen < now() - ($3::bigint * interval '1 second'))::int,
		       COUNT(*) FILTER (WHERE NOT r.retired AND (d.last_seen IS NULL OR d.last_seen > now()))::int,
		       COUNT(*) FILTER (WHERE r.retired)::int,
		       MAX(d.last_seen) FILTER (WHERE NOT r.retired AND d.last_seen <= now()),
		       MIN(d.last_seen) FILTER (WHERE NOT r.retired AND d.last_seen <= now())
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
		  AND `+osFilter+`
	`, tenantID, int64(OverviewActiveWithin/time.Second), int64(OverviewSilentAfter/time.Second)).Scan(&b.now, &v.Total, &v.Active, &v.Stale, &v.Silent,
		&v.Unknown, &v.Retired, &b.newest, &b.oldest)
	if err != nil {
		return b, fmt.Errorf("overview cards devices: %w", err)
	}
	b.now = b.now.UTC()
	if b.newest != nil {
		t := b.newest.UTC()
		b.newest = &t
	}
	if b.oldest != nil {
		t := b.oldest.UTC()
		b.oldest = &t
	}
	return b, nil
}

func devicesCard(now time.Time, b overviewDeviceBuckets) OverviewCard {
	c := newCard("devices.last_seen", CardScopeSnapshot, now)
	c.Freshness.ObservedAt = b.newest
	v := b.values
	return completeCard(c, v.Total == 0, v)
}

// osUpdatesCard uses explicit OS verdicts with a legacy array fallback, but
// these counts do not prove version-level coverage. Until PAT-2133/PAT-2191
// establish that coverage, the card remains partial at best.
func osUpdatesCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, now time.Time, b overviewDeviceBuckets) OverviewCard {
	c := newCard("device_os_update, devices.pending_updates", CardScopeSnapshot, now)
	c.Freshness.ObservedAt = b.newest
	if err := overviewCardFailure("os_updates"); err != nil {
		return queryFailed(c, "os_updates", tenantID, err)
	}
	var ps PatchingStats
	if err := fetchPatchingStats(ctx, pool, tenantID, sw, &ps); err != nil {
		return queryFailed(c, "os_updates", tenantID, err)
	}
	if ps.DevicesUpToDate+ps.DevicesPendingUpdates == 0 {
		return unavailableCard(c, CardReasonNoUpdateEvidence)
	}
	return partialCard(c, CardReasonVersionEvidence, OSUpdatesCardValues{
		UpToDate: ps.DevicesUpToDate, Pending: ps.DevicesPendingUpdates, Unknown: ps.DevicesUpdateStateUnknown,
	})
}

// vulnerabilitiesCard reuses the overview's confirmed critical/high CVE
// count. A zero is authoritative only once the matcher has completed a full
// estate match; before that it is unknown.
func vulnerabilitiesCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) OverviewCard {
	c := newCard("device_cve_findings", CardScopeSnapshot, now)
	if err := overviewCardFailure("vulnerabilities"); err != nil {
		return queryFailed(c, "vulnerabilities", tenantID, err)
	}
	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		return queryFailed(c, "vulnerabilities", tenantID, err)
	}
	if !att.Available {
		return unavailableCard(c, CardReasonSourceNotMigrated)
	}
	lastFull, migrated, err := lastFullMatchAt(ctx, pool)
	if err != nil {
		return queryFailed(c, "vulnerabilities", tenantID, err)
	}
	if !migrated {
		return unavailableCard(c, CardReasonSourceNotMigrated)
	}
	c.Freshness.ObservedAt = lastFull
	v := VulnerabilitiesCardValues{Critical: att.Critical, High: att.High}
	if v.Critical+v.High == 0 && lastFull == nil {
		return unknownCard(c, CardReasonNoCompletedMatchRun)
	}
	return completeCard(c, v.Critical+v.High == 0, v)
}

// lastFullMatchAt is the estate-wide matcher's last completed full match.
// cve_match_runs holds run timestamps only, no tenant data. migrated is
// false when the table does not exist, which is "source not migrated", not
// "no run yet": the card must not present a missing table as a pending run.
func lastFullMatchAt(ctx context.Context, pool *pgxpool.Pool) (at *time.Time, migrated bool, err error) {
	var t time.Time
	err = pool.QueryRow(ctx, `SELECT completed_at FROM cve_match_runs WHERE run_kind = 'full_match'`).Scan(&t)
	if isUndefinedTable(err) {
		return nil, false, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, true, nil
	}
	if err != nil {
		return nil, true, err
	}
	t = t.UTC()
	return &t, true, nil
}

func cisPostureCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, now time.Time) OverviewCard {
	c := newCard("compliance_evaluations", CardScopeSnapshot, now)
	c.UnavailableSignals = append(c.UnavailableSignals,
		OverviewUnavailableSignal{Signal: "material_regression", Reason: CardReasonNotYetSupported})
	if err := overviewCardFailure("cis_posture"); err != nil {
		return queryFailed(c, "cis_posture", tenantID, err)
	}
	var cs ComplianceStats
	if err := fetchComplianceStats(ctx, pool, tenantID, sw, &cs); err != nil {
		return queryFailed(c, "cis_posture", tenantID, err)
	}
	evaluations := cs.PassEvaluations + cs.FailEvaluations + cs.UndeterminedEvaluations
	if evaluations == 0 {
		return unknownCard(c, CardReasonNoEvaluations)
	}
	var latest *time.Time
	if err := pool.QueryRow(ctx, `
		SELECT MAX(e.evaluated_at)
		FROM compliance_evaluations e
		JOIN devices d ON d.id = e.device_id
		WHERE d.tenant_id = $1::uuid
		  AND `+enabledOSFilter(sw)+`
	`, tenantID).Scan(&latest); err != nil {
		return queryFailed(c, "cis_posture", tenantID, err)
	}
	if latest != nil {
		t := latest.UTC()
		latest = &t
	}
	c.Freshness.ObservedAt = latest
	return completeCard(c, false, CISPostureCardValues{Score: cs.OverallPct, Evaluations: evaluations})
}

func browserExtensionsCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) OverviewCard {
	c := newCard("device_browser_extensions", CardScopeSnapshot, now)
	if err := overviewCardFailure("browser_extensions"); err != nil {
		return queryFailed(c, "browser_extensions", tenantID, err)
	}
	res, err := FetchPortalExtensions(ctx, pool, tenantID)
	if err != nil {
		return queryFailed(c, "browser_extensions", tenantID, err)
	}
	if res.EstateTooLarge {
		return unavailableCard(c, CardReasonEstateTooLarge)
	}
	v := BrowserExtensionsCardValues{Total: res.Total}
	for _, e := range res.Extensions {
		if e.RiskLevel == "elevated" {
			v.Elevated++
		}
	}
	if res.Truncated {
		// The row cap cut the list, so elevated is a floor.
		return partialCard(c, CardReasonTruncated, v)
	}
	return completeCard(c, v.Elevated == 0, v)
}

// highRiskSoftwareCard is the overview's newly-found urgency block: products
// first seen within the window, never the whole estate, until PAT-2182.
func highRiskSoftwareCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) OverviewCard {
	c := newCard("software_installations.first_seen_at", CardScopeWindow, now)
	if err := overviewCardFailure("high_risk_software"); err != nil {
		return queryFailed(c, "high_risk_software", tenantID, err)
	}
	ns, err := softwaregov.FetchNewSoftwareUrgency(ctx, pool, tenantID, now)
	if err != nil {
		return queryFailed(c, "high_risk_software", tenantID, err)
	}
	c.Window = &OverviewCardWindow{Since: ns.Since.UTC(), Until: ns.Until.UTC(), Days: ns.WindowDays, Basis: ns.SinceBasis}
	v := HighRiskSoftwareCardValues{Critical: ns.Counts.Critical, High: ns.Counts.High, Classified: ns.Total}
	switch {
	case ns.Truncated:
		return partialCard(c, CardReasonTruncated, v)
	case !ns.Coverage.Complete:
		return partialCard(c, CardReasonCoverageIncomplete, v)
	}
	return completeCard(c, v.Critical+v.High == 0, v)
}

func awaitingApprovalCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) OverviewCard {
	c := newCard("software_governance_estate", CardScopeSnapshot, now)
	if err := overviewCardFailure("software_awaiting_approval"); err != nil {
		return queryFailed(c, "software_awaiting_approval", tenantID, err)
	}
	estate, err := softwaregov.LoadEstate(ctx, pool, tenantID, now)
	if errors.Is(err, softwaregov.ErrEstateTooLarge) {
		return unavailableCard(c, CardReasonEstateTooLarge)
	}
	if err != nil {
		return queryFailed(c, "software_awaiting_approval", tenantID, err)
	}
	products := map[string]bool{}
	devices := map[string]bool{}
	for _, a := range estate.Assessments {
		if a.State != softwaregov.StateUnreviewed {
			continue
		}
		products[a.Type+"\x00"+a.ProductKey] = true
		for _, d := range a.Devices {
			devices[d.DeviceID] = true
		}
	}
	cov := softwaregov.CoverageOf(estate)
	v := AwaitingApprovalCardValues{Products: len(products), Devices: len(devices)}
	if !cov.Complete {
		return partialCard(c, CardReasonCoverageIncomplete, v)
	}
	return completeCard(c, v.Products == 0, v)
}

// exceptionsReviewCard counts review dates against the database's UTC date,
// the same calendar FetchPortalExceptions uses for review_overdue, never a
// browser clock.
func exceptionsReviewCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) OverviewCard {
	c := newCard("tenant_software_exceptions", CardScopeSnapshot, now)
	c.UnavailableSignals = append(c.UnavailableSignals,
		OverviewUnavailableSignal{Signal: "expiry", Reason: CardReasonNotModelled})
	if err := overviewCardFailure("exceptions_review"); err != nil {
		return queryFailed(c, "exceptions_review", tenantID, err)
	}
	var v ExceptionsReviewCardValues
	err := pool.QueryRow(ctx, `
		WITH today AS (SELECT (now() AT TIME ZONE 'UTC')::date AS d)
		SELECT COUNT(*)::int,
		       COUNT(*) FILTER (WHERE e.review_date < t.d)::int,
		       COUNT(*) FILTER (WHERE e.review_date >= t.d AND e.review_date <= t.d + $2::int)::int,
		       COUNT(*) FILTER (WHERE e.review_date IS NULL)::int,
		       COUNT(*) FILTER (WHERE e.status = 'unaccepted')::int
		FROM tenant_software_exceptions e CROSS JOIN today t
		WHERE e.tenant_id = $1::uuid
	`, tenantID, OverviewExceptionReviewDueWithinDays).Scan(&v.Total, &v.ReviewOverdue, &v.ReviewDueSoon, &v.NoReviewDate, &v.Unaccepted)
	if err != nil {
		if isUndefinedTable(err) {
			return unavailableCard(c, CardReasonSourceNotMigrated)
		}
		return queryFailed(c, "exceptions_review", tenantID, err)
	}
	return completeCard(c, v.ReviewOverdue+v.ReviewDueSoon == 0, v)
}

// agentHealthCard: device_agent_health is only as current as each device's
// last report, so a zero is claimed only when no device is silent or
// unknown.
func agentHealthCard(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, now time.Time, b overviewDeviceBuckets) OverviewCard {
	c := newCard("device_agent_health", CardScopeSnapshot, now)
	c.Freshness.ObservedAt = b.newest
	if err := overviewCardFailure("agent_health"); err != nil {
		return queryFailed(c, "agent_health", tenantID, err)
	}
	degraded, available, err := fetchDegradedDevices(ctx, pool, tenantID, enabledOSFilter(sw))
	if err != nil {
		return queryFailed(c, "agent_health", tenantID, err)
	}
	if !available {
		return unavailableCard(c, CardReasonSourceNotMigrated)
	}
	d := b.values
	if d.Total-d.Retired == 0 {
		return unknownCard(c, CardReasonNoDevices)
	}
	v := AgentHealthCardValues{
		DevicesDegraded:        degraded,
		DevicesReporting:       d.Active + d.Stale,
		DevicesNotReporting:    d.Silent + d.Unknown,
		OldestSuccessfulIngest: b.oldest,
	}
	if v.DevicesNotReporting > 0 {
		return partialCard(c, CardReasonDevicesNotReporting, v)
	}
	return completeCard(c, degraded == 0, v)
}
