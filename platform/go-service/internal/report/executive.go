package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTenantNotFound is returned when FetchExecutiveSummary is called with a
// tenant ID that doesn't exist. Handler maps this to 404.
var ErrTenantNotFound = errors.New("tenant not found")

// ExecutiveSummary is the rendered-ready view of one tenant's estate-wide
// compliance posture. Designed for a decision-maker reader (CEO/CFO/auditor
// reviewer) — KPI bands first, top-N tables second, no per-device drill-down.
type ExecutiveSummary struct {
	GeneratedAt time.Time
	Tenant      string

	Estate          EstateStats
	Compliance      ComplianceStats
	TopFailing      []TopFailingControl
	WorstDevices    []WorstDevice
	Patching        PatchingStats
	Coverage        ControlCoverage
	Recommendations []string

	// UserAttributionToggle controls whether primary-user PII is shown in the
	// report. Sourced from agent_config.body->>'report_user_attribution'.
	// Values: "off" (default), "local_part", "full_upn".
	// PII guardrail: default is "off" — no user data rendered unless explicitly
	// enabled by the tenant admin (PAT-116; DPA dependency PAT-112).
	UserAttributionToggle string
}

// EstateStats — the "size and shape of the fleet" band.
type EstateStats struct {
	TotalDevices   int
	MacOSDevices   int
	WindowsDevices int
	OtherDevices   int
	ActiveLast7d   int // devices last_seen within the last 7 days
	ActiveLast24h  int // devices last_seen within the last 24 hours (portal "reporting")
}

// ComplianceStats — the "are we compliant?" band.
type ComplianceStats struct {
	OverallPct      float64 // average per-device compliance %
	PassEvaluations int
	FailEvaluations int
	CriticalFails   int
	HighFails       int
	MediumFails     int
	LowFails        int
	// UndeterminedEvaluations counts the latest-per-(device,rule) rows that
	// evaluated to fail with no observed value (PAT-1758): an absent signal,
	// or a signal present but equal to the collector's "Unknown" sentinel.
	// These are excluded from FailEvaluations/CriticalFails/HighFails/
	// MediumFails/LowFails — an unreadable device is not the same claim as a
	// device that was checked and found non-compliant, and folding the two
	// together would report unmanaged endpoints as unassessed ones (or vice
	// versa).
	//
	// They are NOT excluded from OverallPct's denominator, though. A device
	// that sends no readable evidence for a control must not score the same
	// as, or better than, a device that was actually checked — that is
	// "absence requires authority" and PAT-913's fail-unknown intent applied
	// to scoring: an unreadable device counts as an unresolved fail for the
	// percentage, even though it is reported separately from a real,
	// evidenced fail in the counts above.
	UndeterminedEvaluations int
}

// TopFailingControl — one row in the "which controls fail across the most
// devices?" table.
type TopFailingControl struct {
	RuleKey         string
	Title           string
	Severity        string
	DevicesAffected int
	TotalDevices    int
	PctAffected     float64
	// UndeterminedDevices counts devices whose latest evaluation of this
	// rule is a fail with no observed value (PAT-1758) — evidence the
	// collector could not read, not a real observation of non-compliance.
	// Excluded from DevicesAffected/PctAffected; reported separately so
	// unreadable devices are never silently folded into "unmanaged".
	UndeterminedDevices int
}

// WorstDevice — one row in the "which devices need most attention?" table.
type WorstDevice struct {
	DeviceID      string
	Hostname      string
	OS            string
	OSVersion     string
	CompliancePct float64
	FailingCount  int
	CriticalCount int
	// UndeterminedCount is the number of this device's latest evaluations
	// that failed with no observed value (PAT-1758) — evidence the collector
	// could not read, excluded from FailingCount/CriticalCount above.
	// Reported so the PDF can be honest about it rather than silently
	// dropping it.
	UndeterminedCount int
	// PrimaryUser is the last-known console/logon user for this device (PAT-116).
	// May be empty when the agent has not yet reported a user, or when the
	// report_user_attribution toggle is "off" (PII guardrail — PAT-112 DPA).
	PrimaryUser string
}

// PatchingStats is the three-state update band shared by executive reports
// and the portal Overview card. An explicit device_os_update row takes
// precedence, including when its state is unknown or its verdict is stale.
// Fresh, recognised states count as current or pending; all other explicit
// verdicts count as unknown. Only devices without an OS row may use the
// legacy pending_updates array: empty is current, non-empty is pending,
// and NULL is unknown. This is the same precedence as the portal roster.
type PatchingStats struct {
	DevicesUpToDate           int
	DevicesPendingUpdates     int
	DevicesUpdateStateUnknown int // No usable update verdict; never treated as up to date.
	MedianDaysSinceLastPatch  int // -1 if no patch history at all
}

// ControlCoverage — the "how much of the benchmark are we actually running?"
// band (PAT-1794). Denominated against the tenant's platform mix (a
// macOS-only tenant is never denominated against Windows-only rules, and
// vice versa) via the same enabledOSFilter/platformSwitches plumbing the
// other fetchers use.
//
// ControlsTotal counts every enabled rule across all three collection tiers
// (T1 + T2 + T3) — "total defined" means everything that could apply.
// ControlsEvaluated counts T1 (always evaluated) plus T2 rules with an
// enabled, non-suppressed tenant_rules row for this tenant — computed for
// real each time, not assumed 100% just because PAT-1794 seeds every T2 rule
// on tenant creation, since a tenant can still have a T2 rule
// administratively disabled or suppressed later. ControlsOutOfScope counts
// T3 rules, which are never evaluated by design (see evaluator.go's T1/T2/T3
// handling) — named explicitly as out of scope rather than folded into
// either of the other two counts, so an omitted control never silently
// reads as a pass ("absence requires authority"). Measurements count latest
// device/control evaluations, while identifiers count rule definitions.
// Those units intentionally differ: an identifier does not multiply with
// every device which has evaluated its control.
type ControlCoverage struct {
	ControlsTotal           int
	ControlsEvaluated       int
	ControlsOutOfScope      int
	UndeterminedEvaluations int
	Measurements            ControlCoverageMeasurements
	Identifiers             ControlCoverageIdentifiers
	Platforms               []string
	Benchmarks              []ControlCoverageBenchmark
	TotalZero               bool

	// NotAssessedDevices (PAT-1960) counts devices whose reported
	// device_class matches zero enabled rules for their platform — e.g. a
	// 'server' device under the workstation-only Windows 11 pack. Distinct
	// from both Measurements.Undetermined ("we tried and could not tell")
	// and a pass: these devices produced zero evaluations because no rule
	// applied, so there is nothing to fold into either bucket.
	// NotAssessedReason is the customer-facing explanation, set whenever
	// NotAssessedDevices > 0.
	NotAssessedDevices int
	NotAssessedReason  string

	// DeviceClassUnreportedDevices (PAT-1960) counts devices whose
	// device_class is 'unknown' — no agent has ever reported a real class
	// for them (every device, until the PAT-1959 agent change ships). These
	// devices are scored exactly as before this change (evaluated against
	// every enabled rule for their platform); this count exists only to
	// label that scoring honestly rather than implying "workstation" was
	// evidenced. DeviceClassUnreportedReason is set whenever
	// DeviceClassUnreportedDevices > 0.
	DeviceClassUnreportedDevices int
	DeviceClassUnreportedReason  string
}

// notAssessedReason and deviceClassUnreportedReason are the exact
// customer-facing strings PAT-1960 requires, defined once so the portal
// payload, the executive PDF and the XLSX export can never drift apart.
const (
	notAssessedReason           = "Not assessed: no benchmark for this device class"
	deviceClassUnreportedReason = "Device class not reported"
)

// deviceClassMatch returns the PAT-1960 rule-matching predicate for a query
// that has already joined a devices row (aliased deviceAlias) against a
// compliance_rules row whose device_class column is named ruleDeviceClassCol
// (e.g. "cr.device_class" or "ac.device_class").
//
//	ruleDeviceClassCol IS NULL                        -- rule applies to every class
//	OR deviceAlias.device_class = ANY(ruleDeviceClassCol) -- this device's class is named
//	OR deviceAlias.device_class = 'unknown'           -- device class not yet reported
//
// The third clause is deliberate and load-bearing — see migrations/
// 0158_device_class.sql and evaluator.deviceClassMatchSQL, which applies the
// identical predicate at evaluation time via a bound parameter instead of a
// devices join.
func deviceClassMatch(deviceAlias, ruleDeviceClassCol string) string {
	return fmt.Sprintf(
		"(%s IS NULL OR %s.device_class = ANY(%s) OR %s.device_class = 'unknown')",
		ruleDeviceClassCol, deviceAlias, ruleDeviceClassCol, deviceAlias,
	)
}

// deviceClassMatchParam is deviceClassMatch's counterpart for a query with no
// devices row to join — the single device's class is already known
// (e.g. report.Fetch, which has already loaded the one Device this query is
// about) and bound as the query's paramIndex parameter instead. Same
// predicate and same load-bearing "or unknown" third clause as
// deviceClassMatch and evaluator.deviceClassMatchSQL.
func deviceClassMatchParam(ruleDeviceClassCol string, paramIndex int) string {
	return fmt.Sprintf(
		"(%s IS NULL OR $%d = ANY(%s) OR $%d = 'unknown')",
		ruleDeviceClassCol, paramIndex, ruleDeviceClassCol, paramIndex,
	)
}

// ControlCoverageMeasurements counts latest per-device, per-rule evaluation
// rows. A fail requires an observed value; a missing observation on a fail and
// every evaluator error are undetermined. This leaves not applicable and the
// separately configured out-of-scope dimension visible to the customer.
type ControlCoverageMeasurements struct {
	Pass          int
	Fail          int
	Undetermined  int
	NotApplicable int
}

// ControlCoverageIdentifiers counts enabled rule definitions, never
// evaluations. The CIS namespace is the benchmark names beginning "CIS "; a
// persisted identifier is authoritative and must not be inferred from a rule
// key. Every enabled definition belongs to exactly one bucket.
type ControlCoverageIdentifiers struct {
	CISMapped   int
	CISUnmapped int
	NonCIS      int
}

// ControlCoverageBenchmark is one active benchmark/version pair in a
// tenant's coverage result. A tenant can have more than one pair because the
// rule library intentionally holds platform-specific CIS and Patched baseline
// controls together; callers must never invent a single estate-wide version.
type ControlCoverageBenchmark struct {
	Benchmark               string
	BenchmarkVersion        string
	ControlsTotal           int
	ControlsEvaluated       int
	ControlsOutOfScope      int
	UndeterminedEvaluations int
	Measurements            ControlCoverageMeasurements
	Identifiers             ControlCoverageIdentifiers
}

// topNLimits — how many rows we show in the top-N tables. Five is the
// executive-summary sweet spot: enough to see patterns, few enough to scan
// in one go.
const (
	topFailingControlsLimit = 5
	worstDevicesLimit       = 5
)

// platformSwitches holds the per-tenant master-switch state for the two
// supported platforms. Used to exclude disabled-platform devices from reports.
type platformSwitches struct {
	macOSEnabled   bool
	windowsEnabled bool
}

// FetchExecutiveSummary aggregates the tenant's compliance posture across all
// devices into a single ExecutiveSummary struct. Devices whose platform is
// disabled for the tenant are excluded from all aggregates. Read-mostly; no DB
// writes. Returns ErrTenantNotFound when the tenant ID doesn't resolve.
func FetchExecutiveSummary(ctx context.Context, pool *pgxpool.Pool, tenantID string) (ExecutiveSummary, error) {
	var summary ExecutiveSummary
	summary.GeneratedAt = time.Now().UTC()

	// Tenant existence + name + platform switches.
	var sw platformSwitches
	err := pool.QueryRow(ctx, `
		SELECT name, macos_enabled, windows_enabled
		FROM tenants WHERE id = $1
	`, tenantID).Scan(&summary.Tenant, &sw.macOSEnabled, &sw.windowsEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return summary, ErrTenantNotFound
		}
		return summary, fmt.Errorf("fetch tenant: %w", err)
	}

	// Fetch report_user_attribution toggle from agent_config (PAT-116).
	// Non-fatal: if the row is absent or the key not yet present in body,
	// default to "off" (privacy guardrail).
	var rawToggle *string
	_ = pool.QueryRow(ctx,
		`SELECT body->>'report_user_attribution' FROM agent_config WHERE tenant_id = $1`,
		tenantID,
	).Scan(&rawToggle)
	if rawToggle != nil && (*rawToggle == "local_part" || *rawToggle == "full_upn") {
		summary.UserAttributionToggle = *rawToggle
	} else {
		summary.UserAttributionToggle = "off"
	}

	if err := fetchEstateStats(ctx, pool, tenantID, sw, &summary.Estate); err != nil {
		return summary, err
	}
	if err := fetchComplianceStats(ctx, pool, tenantID, sw, &summary.Compliance); err != nil {
		return summary, err
	}
	if err := fetchTopFailingControls(ctx, pool, tenantID, sw, &summary); err != nil {
		return summary, err
	}
	if err := fetchWorstDevices(ctx, pool, tenantID, sw, &summary.WorstDevices); err != nil {
		return summary, err
	}
	if err := fetchPatchingStats(ctx, pool, tenantID, sw, &summary.Patching); err != nil {
		return summary, err
	}
	coverage, err := fetchControlCoverage(ctx, pool, tenantID, sw)
	if err != nil {
		return summary, err
	}
	summary.Coverage = coverage
	summary.Recommendations = deriveRecommendations(summary)

	return summary, nil
}

// enabledOSFilter returns a SQL fragment suitable for appending after a WHERE
// clause on devices.os, excluding OSes whose master switch is off.
// It always returns at least one clause (so callers can use AND) and produces
// no clause that references unknown OS strings.
func enabledOSFilter(sw platformSwitches) string {
	var excluded []string
	if !sw.macOSEnabled {
		excluded = append(excluded, "'macOS'")
	}
	if !sw.windowsEnabled {
		excluded = append(excluded, "'Windows'")
	}
	if len(excluded) == 0 {
		return "true"
	}
	joined := strings.Join(excluded, ",")
	return "d.os NOT IN (" + joined + ")"
}

// osEvaluationDisabled reports whether a device's OS has its tenant master
// switch turned off (PAT-745). Used by FetchTenantDevices to annotate
// devices that remain visible in the fleet roster despite their platform's
// evaluation/scoring being disabled — the inverse of what enabledOSFilter
// excludes at the SQL layer for aggregate report queries.
func osEvaluationDisabled(sw platformSwitches, os string) bool {
	switch os {
	case "macOS":
		return !sw.macOSEnabled
	case "Windows":
		return !sw.windowsEnabled
	default:
		return false
	}
}

// rulePlatformFilter returns a SQL fragment suitable for appending after a
// WHERE clause on compliance_rules.platform (aliased cr), including only the
// platforms the tenant has enabled. Mirrors enabledOSFilter's devices.os
// exclusion, but expressed as an inclusion over the lowercase
// 'macos'/'windows' vocabulary compliance_rules.platform uses — devices.os
// spells them 'macOS'/'Windows'. Both switches off returns a fragment that
// matches nothing, same "denominator collapses to zero, never negative or
// wrong" behaviour as enabledOSFilter's all-excluded case.
func rulePlatformFilter(sw platformSwitches) string {
	var included []string
	if sw.macOSEnabled {
		included = append(included, "'macos'")
	}
	if sw.windowsEnabled {
		included = append(included, "'windows'")
	}
	if len(included) == 0 {
		return "false"
	}
	return "cr.platform IN (" + strings.Join(included, ",") + ")"
}

// --- Section fetchers ------------------------------------------------------

func fetchEstateStats(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, out *EstateStats) error {
	osFilter := enabledOSFilter(sw)
	err := pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE `+osFilter+`)::int                                                  AS total,
			COUNT(*) FILTER (WHERE os = 'macOS'   AND `+osFilter+`)::int                              AS macos,
			COUNT(*) FILTER (WHERE os = 'Windows' AND `+osFilter+`)::int                              AS windows,
			COUNT(*) FILTER (WHERE os NOT IN ('macOS','Windows') AND `+osFilter+`)::int               AS other,
			COUNT(*) FILTER (WHERE last_seen > now() - interval '7 days' AND `+osFilter+`)::int       AS active_7d,
			COUNT(*) FILTER (WHERE last_seen > now() - interval '24 hours' AND `+osFilter+`)::int     AS active_24h
		FROM devices d
		WHERE tenant_id = $1
	`, tenantID).Scan(&out.TotalDevices, &out.MacOSDevices, &out.WindowsDevices, &out.OtherDevices, &out.ActiveLast7d, &out.ActiveLast24h)
	if err != nil {
		return fmt.Errorf("estate stats: %w", err)
	}
	return nil
}

func fetchComplianceStats(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, out *ComplianceStats) error {
	// Latest evaluation per (device, rule) across the tenant. Compliance % is
	// the average across devices, not the global pass/fail ratio — keeps a
	// fleet of 99 perfect devices and 1 broken one at a representative 99%
	// rather than diluting by total rule count.
	// PAT-1758: a 'fail' row with observed_value IS NULL is undetermined
	// evidence (absent signal, or the collector's "Unknown" sentinel now
	// caught by the evaluator too) rather than a real observation of
	// non-compliance. It is excluded from fail_count/crit_count/high_count/
	// medium_count/low_count and reported on its own as undetermined_count,
	// so the counts above never confuse "unreadable" with "checked and
	// found wanting".
	//
	// device_pcts' denominator is deliberately NOT changed: it stays
	// pass / (pass + fail + error), counting an undetermined fail exactly
	// like any other fail. A device that reports no readable evidence for a
	// control must not score as well as, or better than, one that was
	// actually checked — dropping it from the denominator would let a
	// device sending nothing but "Unknown" sit at a NULL (and so
	// AVG-excluded, i.e. invisible) percentage instead of a low one. That is
	// the fails-safe-looks-healthy shape this whole ticket exists to close,
	// and it would contradict "absence requires authority" (root AGENTS.md)
	// and PAT-913's fail-unknown intent. Unknown must never raise the score.
	osFilter := enabledOSFilter(sw)
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.status, e.severity, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		device_pcts AS (
			SELECT device_id,
			       COUNT(*) FILTER (WHERE status = 'pass')::float
			         / NULLIF(COUNT(*) FILTER (WHERE status IN ('pass','fail','error')), 0)::float * 100.0 AS pct
			FROM latest
			GROUP BY device_id
		)
		SELECT
			COALESCE(AVG(pct), 0)::float                                          AS avg_pct,
			(SELECT COUNT(*) FROM latest WHERE status = 'pass')::int              AS pass_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NOT NULL)::int AS fail_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NOT NULL AND severity = 'critical')::int AS crit_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NOT NULL AND severity = 'high')::int     AS high_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NOT NULL AND severity = 'medium')::int   AS medium_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NOT NULL AND severity = 'low')::int      AS low_count,
			(SELECT COUNT(*) FROM latest WHERE status = 'fail' AND observed_value IS NULL)::int      AS undetermined_count
		FROM device_pcts
	`, tenantID)
	if err != nil {
		return fmt.Errorf("compliance stats: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&out.OverallPct, &out.PassEvaluations, &out.FailEvaluations, &out.CriticalFails, &out.HighFails, &out.MediumFails, &out.LowFails, &out.UndeterminedEvaluations); err != nil {
			return fmt.Errorf("scan compliance stats: %w", err)
		}
	}
	return rows.Err()
}

func fetchTopFailingControls(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, sum *ExecutiveSummary) error {
	// Group failing evaluations by rule, count distinct devices. Total devices
	// in the denominator is the COMPLIANCE-EVALUATED device count, not all
	// tenant devices, so unmanaged collectors that never produce evals don't
	// inflate the denominator and make every rule look "100% affected".
	//
	// PAT-1758: a 'fail' row with observed_value IS NULL is undetermined
	// evidence (absent signal, or the collector's "Unknown" sentinel), not a
	// real observation that the control is non-compliant. devices_affected
	// counts only real fails; undetermined_devices is reported alongside it
	// so an unreadable device is never silently counted as "unmanaged".
	//
	// The HAVING clause drops a rule entirely from this list when EVERY
	// latest-fail row for it is undetermined (devices_affected = 0) — such a
	// rule has no real remediation to report, and without this guard it
	// could sort to devices_affected DESC's tail and still land as
	// TopFailing[0] on a tenant with no real fails at all, producing a
	// nonsensical "Remediate X across 0 of N devices" recommendation. Its
	// undetermined evidence is not lost: ComplianceStats.UndeterminedEvaluations
	// (the Compliance Posture band's "Could not be determined" KPI) already
	// surfaces the tenant-wide total independent of this per-control table.
	osFilter := enabledOSFilter(sw)
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.rule_id, e.status, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		evaluated_devices AS (
			SELECT COUNT(DISTINCT device_id)::int AS n FROM latest
		)
		SELECT
			r.rule_key, r.title, r.severity,
			COUNT(DISTINCT l.device_id) FILTER (WHERE l.observed_value IS NOT NULL)::int AS devices_affected,
			COUNT(DISTINCT l.device_id) FILTER (WHERE l.observed_value IS NULL)::int     AS undetermined_devices,
			(SELECT n FROM evaluated_devices)       AS total_devices
		FROM latest l
		JOIN compliance_rules r ON r.id = l.rule_id
		WHERE l.status = 'fail'
		GROUP BY r.rule_key, r.title, r.severity
		HAVING COUNT(DISTINCT l.device_id) FILTER (WHERE l.observed_value IS NOT NULL) > 0
		ORDER BY devices_affected DESC,
		         CASE r.severity
		             WHEN 'critical' THEN 1
		             WHEN 'high'     THEN 2
		             WHEN 'medium'   THEN 3
		             WHEN 'low'      THEN 4
		             ELSE 5
		         END,
		         r.rule_key
		LIMIT $2
	`, tenantID, topFailingControlsLimit)
	if err != nil {
		return fmt.Errorf("top failing controls: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tc TopFailingControl
		if err := rows.Scan(&tc.RuleKey, &tc.Title, &tc.Severity, &tc.DevicesAffected, &tc.UndeterminedDevices, &tc.TotalDevices); err != nil {
			return fmt.Errorf("scan top failing: %w", err)
		}
		if tc.TotalDevices > 0 {
			tc.PctAffected = float64(tc.DevicesAffected) / float64(tc.TotalDevices) * 100.0
		}
		sum.TopFailing = append(sum.TopFailing, tc)
	}
	return rows.Err()
}

func fetchWorstDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, out *[]WorstDevice) error {
	// Sort by criticality first (any critical fail outranks everything), then
	// by failing-count, then by compliance% ascending. Five rows max.
	//
	// PAT-1758: a 'fail' row with observed_value IS NULL is undetermined
	// evidence (absent signal, or the collector's "Unknown" sentinel), not a
	// real observation of non-compliance — consistent with
	// fetchComplianceStats/fetchTopFailingControls, failing/critical here
	// count only real fails. A device whose ONLY fails are undetermined must
	// not appear in this "needing attention" list at all: it has no
	// evidenced problem, and without this exclusion it could still rank in
	// ahead of a genuinely clean device purely because pct's denominator
	// (unchanged — undetermined still counts as a fail there, same
	// "absence requires authority" reasoning as fetchComplianceStats) makes
	// its percentage look bad. A device with at least one REAL fail is never
	// excluded, however many undetermined fails it also has.
	osFilter := enabledOSFilter(sw)
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.status, e.severity, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		per_device AS (
			SELECT
				device_id,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NOT NULL)::int AS failing,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NOT NULL AND severity = 'critical')::int AS critical,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NULL)::int     AS undetermined,
				COUNT(*) FILTER (WHERE status = 'pass')::float
				  / NULLIF(COUNT(*) FILTER (WHERE status IN ('pass','fail','error')), 0)::float * 100.0 AS pct
			FROM latest
			GROUP BY device_id
		)
		SELECT
			d.id::text,
			COALESCE(d.hostname, '—'),
			COALESCE(d.os, ''),
			COALESCE(d.os_version, ''),
			COALESCE(p.pct, 0)::float,
			COALESCE(p.failing, 0),
			COALESCE(p.critical, 0),
			COALESCE(p.undetermined, 0),
			COALESCE(d.primary_user_account, '') AS primary_user
		FROM devices d
		LEFT JOIN per_device p ON p.device_id = d.id
		WHERE d.tenant_id = $1
		  AND `+osFilter+`
		  AND NOT (COALESCE(p.failing, 0) = 0 AND COALESCE(p.undetermined, 0) > 0)
		ORDER BY
			COALESCE(p.critical, 0) DESC,
			COALESCE(p.failing, 0)  DESC,
			COALESCE(p.pct, 0)      ASC,
			d.hostname
		LIMIT $2
	`, tenantID, worstDevicesLimit)
	if err != nil {
		return fmt.Errorf("worst devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var w WorstDevice
		if err := rows.Scan(&w.DeviceID, &w.Hostname, &w.OS, &w.OSVersion, &w.CompliancePct, &w.FailingCount, &w.CriticalCount, &w.UndeterminedCount, &w.PrimaryUser); err != nil {
			return fmt.Errorf("scan worst device: %w", err)
		}
		*out = append(*out, w)
	}
	return rows.Err()
}

func fetchPatchingStats(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches, out *PatchingStats) error {
	// Keep row presence separate from freshness: filtering stale rows out of
	// the join would permit the legacy array to override unavailable evidence.
	// Exact state lists and the capped seven-day window match the roster and
	// FetchOSUpdateStatus. Legacy NULL checked_at falls back to receipt time.
	osFilter := enabledOSFilter(sw)
	err := pool.QueryRow(ctx, `
		WITH verdicts AS (
			SELECT CASE
				WHEN dou.device_id IS NOT NULL THEN CASE
					WHEN LEAST(COALESCE(dou.checked_at, dou.reported_at), dou.reported_at) >= $4 THEN CASE
						WHEN dou.state = ANY($2::text[]) THEN false
						WHEN dou.state = ANY($3::text[]) THEN true
						ELSE NULL
					END
					ELSE NULL
				END
				WHEN d.pending_updates IS NULL THEN NULL
				ELSE jsonb_array_length(d.pending_updates) > 0
			END AS pending
			FROM devices d
			LEFT JOIN device_os_update dou ON dou.device_id = d.id
			WHERE d.tenant_id = $1 AND `+osFilter+`
		)
		SELECT
			COUNT(*) FILTER (WHERE pending = false)::int,
			COUNT(*) FILTER (WHERE pending = true)::int,
			COUNT(*) FILTER (WHERE pending IS NULL)::int
		FROM verdicts
	`, tenantID, osUpdateStatesFor(osUpdateCurrent), osUpdateStatesFor(osUpdatePending), time.Now().UTC().Add(-portalEvidenceStaleAfter)).Scan(&out.DevicesUpToDate, &out.DevicesPendingUpdates, &out.DevicesUpdateStateUnknown)
	if err != nil {
		return fmt.Errorf("patching stats: %w", err)
	}

	// Median days since most recent installed_at per device.
	// PERCENTILE_CONT over per-device "days since their newest patch".
	row := pool.QueryRow(ctx, `
		WITH per_device AS (
			SELECT
				d.id AS device_id,
				EXTRACT(EPOCH FROM (now() - MAX(p.installed_at))) / 86400.0 AS days_since
			FROM devices d
			JOIN patches p ON p.device_id = d.id
			WHERE d.tenant_id = $1 AND p.installed_at IS NOT NULL
			  AND `+osFilter+`
			GROUP BY d.id
		)
		SELECT COALESCE(
			PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY days_since),
			-1.0
		)
		FROM per_device
	`, tenantID)
	var median float64
	if err := row.Scan(&median); err != nil {
		return fmt.Errorf("median days since patch: %w", err)
	}
	if median < 0 {
		out.MedianDaysSinceLastPatch = -1
	} else {
		out.MedianDaysSinceLastPatch = int(median + 0.5)
	}
	return nil
}

// fetchControlCoverage computes the PAT-1794 coverage band: how much of the
// defined benchmark this tenant is actually running, denominated against its
// platform mix via rulePlatformFilter (same reasoning as every other
// fetcher's enabledOSFilter — a macOS-only tenant must not be denominated
// against Windows-only rules and vice versa).
//
// ControlsEvaluated is computed for real (T1 count + a live join against
// tenant_rules for T2), never assumed 100% — after PAT-1794's seeding, a
// freshly-created tenant's T2-evaluated count equals its T2-total count, but
// an administratively disabled or suppressed T2 rule must show up here as
// soon as it happens, not stay frozen at the seeded value.
func fetchControlCoverage(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches) (ControlCoverage, error) {
	out := ControlCoverage{
		Platforms:  controlCoveragePlatforms(sw),
		Benchmarks: []ControlCoverageBenchmark{},
	}
	platformFilter := rulePlatformFilter(sw)

	// The control denominator comes from the live rule rows, not a migration
	// count or documentation snapshot. The same definition feeds both the
	// executive PDF and the portal API so they cannot drift apart.
	rows, err := pool.Query(ctx, `
		WITH applicable_controls AS (
			SELECT
				cr.id, cr.benchmark, cr.benchmark_version, cr.platform,
				cr.collection_tier, cr.control_identifier, cr.device_class,
				(cr.collection_tier = 'T1' OR (
					cr.collection_tier = 'T2' AND EXISTS (
						SELECT 1
						FROM tenant_rules tr
						WHERE tr.tenant_id = $1::uuid
						  AND tr.rule_id = cr.id
						  AND tr.enabled = true
						  AND (tr.suppressed_until IS NULL OR tr.suppressed_until < now())
					)
				)) AS evaluated
			FROM compliance_rules cr
			WHERE cr.enabled = true AND `+platformFilter+`
		),
		control_counts AS (
			SELECT
				ac.benchmark,
				ac.benchmark_version,
				COUNT(*)::int AS total,
				COUNT(*) FILTER (WHERE ac.evaluated)::int AS evaluated,
				COUNT(*) FILTER (WHERE ac.collection_tier = 'T3')::int AS out_of_scope,
				COUNT(*) FILTER (WHERE ac.benchmark LIKE 'CIS %' AND ac.control_identifier IS NOT NULL)::int AS cis_mapped,
				COUNT(*) FILTER (WHERE ac.benchmark LIKE 'CIS %' AND ac.control_identifier IS NULL)::int AS cis_unmapped,
				COUNT(*) FILTER (WHERE ac.benchmark NOT LIKE 'CIS %')::int AS non_cis
			FROM applicable_controls ac
			GROUP BY ac.benchmark, ac.benchmark_version
		),
		latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				ac.benchmark, ac.benchmark_version,
				e.device_id, e.rule_id, e.status, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			JOIN applicable_controls ac ON ac.id = e.rule_id
			WHERE d.tenant_id = $1::uuid
			  AND `+enabledOSFilter(sw)+`
			  AND ((ac.platform = 'macos' AND d.os = 'macOS')
			    OR (ac.platform = 'windows' AND d.os = 'Windows'))
			  AND `+deviceClassMatch("d", "ac.device_class")+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC, e.id DESC
		),
		measurement_counts AS (
			SELECT
				benchmark,
				benchmark_version,
				COUNT(*) FILTER (WHERE status = 'pass')::int AS pass,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NOT NULL)::int AS fail,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NULL)::int AS undetermined_evaluations,
				COUNT(*) FILTER (WHERE (status = 'fail' AND observed_value IS NULL) OR status = 'error')::int AS undetermined,
				COUNT(*) FILTER (WHERE status = 'not_applicable')::int AS not_applicable
			FROM latest
			GROUP BY benchmark, benchmark_version
		)
		SELECT
			cc.benchmark,
			cc.benchmark_version,
			cc.total,
			cc.evaluated,
			cc.out_of_scope,
			COALESCE(mc.undetermined_evaluations, 0)::int,
			COALESCE(mc.pass, 0)::int,
			COALESCE(mc.fail, 0)::int,
			COALESCE(mc.undetermined, 0)::int,
			COALESCE(mc.not_applicable, 0)::int,
			cc.cis_mapped,
			cc.cis_unmapped,
			cc.non_cis
		FROM control_counts cc
		LEFT JOIN measurement_counts mc
		  ON mc.benchmark = cc.benchmark
		 AND mc.benchmark_version = cc.benchmark_version
		ORDER BY cc.benchmark, cc.benchmark_version
	`, tenantID)
	if err != nil {
		return out, fmt.Errorf("control coverage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var benchmark ControlCoverageBenchmark
		if err := rows.Scan(
			&benchmark.Benchmark,
			&benchmark.BenchmarkVersion,
			&benchmark.ControlsTotal,
			&benchmark.ControlsEvaluated,
			&benchmark.ControlsOutOfScope,
			&benchmark.UndeterminedEvaluations,
			&benchmark.Measurements.Pass,
			&benchmark.Measurements.Fail,
			&benchmark.Measurements.Undetermined,
			&benchmark.Measurements.NotApplicable,
			&benchmark.Identifiers.CISMapped,
			&benchmark.Identifiers.CISUnmapped,
			&benchmark.Identifiers.NonCIS,
		); err != nil {
			return out, fmt.Errorf("scan control coverage: %w", err)
		}
		out.ControlsTotal += benchmark.ControlsTotal
		out.ControlsEvaluated += benchmark.ControlsEvaluated
		out.ControlsOutOfScope += benchmark.ControlsOutOfScope
		out.UndeterminedEvaluations += benchmark.UndeterminedEvaluations
		out.Measurements.Pass += benchmark.Measurements.Pass
		out.Measurements.Fail += benchmark.Measurements.Fail
		out.Measurements.Undetermined += benchmark.Measurements.Undetermined
		out.Measurements.NotApplicable += benchmark.Measurements.NotApplicable
		out.Identifiers.CISMapped += benchmark.Identifiers.CISMapped
		out.Identifiers.CISUnmapped += benchmark.Identifiers.CISUnmapped
		out.Identifiers.NonCIS += benchmark.Identifiers.NonCIS
		out.Benchmarks = append(out.Benchmarks, benchmark)
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate control coverage: %w", err)
	}
	out.TotalZero = out.ControlsTotal == 0

	notAssessed, unreported, err := fetchDeviceClassCoverage(ctx, pool, tenantID, enabledOSFilter(sw))
	if err != nil {
		return out, err
	}
	out.NotAssessedDevices = notAssessed
	if notAssessed > 0 {
		out.NotAssessedReason = notAssessedReason
	}
	out.DeviceClassUnreportedDevices = unreported
	if unreported > 0 {
		out.DeviceClassUnreportedReason = deviceClassUnreportedReason
	}

	return out, nil
}

// fetchDeviceClassCoverage computes the two PAT-1960 device-level counts
// that sit alongside (but are never folded into) the rule-centric coverage
// counts above:
//
//   - notAssessed: devices whose reported (non-'unknown') device_class
//     matches zero enabled rules for their platform — e.g. a 'server'
//     device under the workstation-only Windows 11 pack. These devices
//     produced zero evaluations by design (see evaluator.LoadRules); they
//     must never be counted as a pass, and never folded into
//     Measurements.Undetermined, which means "we tried and could not tell"
//     rather than "we correctly did not try".
//   - unreported: devices whose device_class is still 'unknown' AND whose
//     platform has at least one enabled rule with a non-NULL device_class
//     (i.e. device_class is a meaningful concept for that platform at all —
//     today that means Windows only, since every macOS rule's device_class
//     is NULL). A macOS device defaults to 'unknown' too, but macOS has no
//     workstation/server/domain-controller distinction in this rule
//     library, so labelling it "device class not reported" would be
//     misleading rather than honest; the platform-has-class-scoped-rules
//     guard keeps this count meaningful without hardcoding "windows".
//     These devices are scored exactly as before this whole change; the
//     count exists only to label that scoring honestly.
//
// osFilter is the caller's enabledOSFilter(sw) fragment, so a tenant with a
// platform disabled excludes that platform's devices here exactly as it
// does in every other band.
func fetchDeviceClassCoverage(ctx context.Context, pool *pgxpool.Pool, tenantID, osFilter string) (notAssessed, unreported int, err error) {
	err = pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (
				WHERE d.device_class <> 'unknown'
				  AND NOT EXISTS (
				      SELECT 1 FROM compliance_rules cr
				      WHERE cr.enabled = true
				        AND ((cr.platform = 'macos' AND d.os = 'macOS')
				          OR (cr.platform = 'windows' AND d.os = 'Windows'))
				        AND `+deviceClassMatch("d", "cr.device_class")+`
				  )
			)::int AS not_assessed,
			COUNT(*) FILTER (
				WHERE d.device_class = 'unknown'
				  AND EXISTS (
				      SELECT 1 FROM compliance_rules cr
				      WHERE cr.enabled = true
				        AND ((cr.platform = 'macos' AND d.os = 'macOS')
				          OR (cr.platform = 'windows' AND d.os = 'Windows'))
				        AND cr.device_class IS NOT NULL
				  )
			)::int AS unreported
		FROM devices d
		WHERE d.tenant_id = $1::uuid
		  AND `+osFilter+`
	`, tenantID).Scan(&notAssessed, &unreported)
	if err != nil {
		return 0, 0, fmt.Errorf("device class coverage: %w", err)
	}
	return notAssessed, unreported, nil
}

// FetchControlCoverage returns the live rule-library coverage for one tenant.
// It is the portal's dedicated read model and is deliberately shared with the
// executive summary rather than deriving a second, potentially divergent
// control denominator.
func FetchControlCoverage(ctx context.Context, pool *pgxpool.Pool, tenantID string) (ControlCoverage, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return ControlCoverage{}, err
	}
	return fetchControlCoverage(ctx, pool, tenantID, sw)
}

func controlCoveragePlatforms(sw platformSwitches) []string {
	platforms := make([]string, 0, 2)
	if sw.macOSEnabled {
		platforms = append(platforms, "macos")
	}
	if sw.windowsEnabled {
		platforms = append(platforms, "windows")
	}
	return platforms
}

// deriveRecommendations turns the aggregations into customer-specific
// recommendation strings. Order matters — most impactful first. v1 is
// deterministic-rule-based; v2 could grow to an LLM-summarised version.
func deriveRecommendations(s ExecutiveSummary) []string {
	var recs []string

	// 1. Unmanaged endpoints — derived from any device failing
	//    patched_mdm_enrolment (macOS only; there is no Windows equivalent
	//    wired into this recommendation).
	for _, tc := range s.TopFailing {
		if tc.RuleKey == "patched_mdm_enrolment" && tc.DevicesAffected > 0 {
			recs = append(recs,
				fmt.Sprintf("Enrol %d unmanaged endpoint%s in Jamf, Intune or equivalent MDM. MDM is the centralised lever for nearly every other control in the benchmark.",
					tc.DevicesAffected, plural(tc.DevicesAffected)))
			break
		}
	}

	// 2. Top failing control(s) — the single most impactful remediation.
	if len(s.TopFailing) > 0 {
		top := s.TopFailing[0]
		recs = append(recs,
			fmt.Sprintf("Remediate \"%s\" across %d of %d device%s (%.0f%% of evaluated estate). %s severity.",
				top.Title, top.DevicesAffected, top.TotalDevices, plural(top.TotalDevices), top.PctAffected,
				titleCase(top.Severity)))
	}

	// 3. Pending updates.
	if s.Patching.DevicesPendingUpdates > 0 {
		recs = append(recs,
			fmt.Sprintf("Apply outstanding macOS updates on %d device%s. Enable automatic security updates to keep cadence without operator intervention.",
				s.Patching.DevicesPendingUpdates, plural(s.Patching.DevicesPendingUpdates)))
	}

	// 4. Critical / high posture gap.
	if s.Compliance.CriticalFails > 0 {
		recs = append(recs,
			fmt.Sprintf("Resolve %d critical-severity failure%s as the immediate priority. These typically protect data confidentiality (FileVault, Secure Boot).",
				s.Compliance.CriticalFails, plural(s.Compliance.CriticalFails)))
	} else if s.Compliance.HighFails > 0 {
		recs = append(recs,
			fmt.Sprintf("Resolve %d high-severity failure%s as the next priority window. These typically address attack-surface reduction (firewall, SSH, remote services).",
				s.Compliance.HighFails, plural(s.Compliance.HighFails)))
	}

	// 5. Cadence — always present, last in the list.
	recs = append(recs,
		"Establish a monthly patched.im collection cadence so compliance trend lines and newly-disclosed CVEs surface as part of routine business reporting.")

	return recs
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	// Severity values are always ASCII-lowercase per the CHECK constraint
	// on compliance_rules.severity. Defensive ToUpper covers anything else
	// without breaking on already-capitalised input.
	return strings.ToUpper(s[:1]) + s[1:]
}
