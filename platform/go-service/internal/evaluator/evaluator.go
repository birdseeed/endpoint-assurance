package evaluator

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// deviceClassMatchSQL returns the PAT-1960 rule-matching predicate against a
// compliance_rules query with no device row to join (LoadRules /
// LoadRulesForTenant evaluate one already-known device_class at a time,
// bound as the query's deviceClass parameter at paramIndex rather than
// joined from a devices row). column names the compliance_rules
// device_class column as this query aliases it (unqualified or "cr.").
//
//	device_class IS NULL          -- rule applies to every class
//	OR $N = ANY(device_class)     -- this device's class is named
//	OR $N = 'unknown'             -- device class not yet reported
//
// The third clause is deliberate and load-bearing (see migrations/
// 0158_device_class.sql): every device is 'unknown' until the PAT-1959
// agent change starts reporting a real class, and 'unknown' must keep
// exactly today's behaviour — evaluated against every enabled rule for its
// platform — rather than instantly flipping the whole existing estate to
// "not assessed".
func deviceClassMatchSQL(column string, paramIndex int) string {
	return fmt.Sprintf("(%s IS NULL OR $%d = ANY(%s) OR $%d = 'unknown')", column, paramIndex, column, paramIndex)
}

// LoadRules pulls the T1 (always-evaluate) rule set from compliance_rules for
// the given platform ("macos" or "windows") and device class. Called per-row
// in processRow so platform and device-class filtering take effect without
// restarting the extractor.
func LoadRules(ctx context.Context, pool *pgxpool.Pool, platform, deviceClass string) ([]Rule, error) {
	stmt := `
		SELECT id::text, rule_key, benchmark, benchmark_version, title, severity,
		       signal_key, comparator, expected_values, applicable_arch, treat_unknown_as,
		       platform, treat_not_configured_as
		FROM compliance_rules
		WHERE enabled = true
		  AND collection_tier = 'T1'
		  AND platform = $1
		  AND ` + deviceClassMatchSQL("device_class", 2) + `
		ORDER BY benchmark, rule_key
	`
	rows, err := pool.Query(ctx, stmt, platform, deviceClass)
	if err != nil {
		return nil, fmt.Errorf("query rules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var r Rule
		var treatNotConfiguredAs *string
		if err := rows.Scan(
			&r.ID, &r.RuleKey, &r.Benchmark, &r.BenchmarkVersion, &r.Title, &r.Severity,
			&r.SignalKey, &r.Comparator, &r.ExpectedValues, &r.ApplicableArch, &r.TreatUnknownAs,
			&r.Platform, &treatNotConfiguredAs,
		); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		if treatNotConfiguredAs != nil {
			r.TreatNotConfiguredAs = *treatNotConfiguredAs
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rules: %w", err)
	}
	return out, nil
}

// LoadRulesForTenant returns the T2 rules currently enabled for tenantID,
// platform and device class. A T2 rule is included only when an enabled,
// non-suppressed tenant_rules row exists for the (tenant, rule) pair.
// override_severity in tenant_rules takes precedence over the global rule
// severity. Returns a non-nil empty slice when no T2 rules are configured —
// safe to append directly to LoadRules output.
func LoadRulesForTenant(ctx context.Context, pool *pgxpool.Pool, tenantID, platform, deviceClass string) ([]Rule, error) {
	stmt := `
		SELECT cr.id::text, cr.rule_key, cr.benchmark, cr.benchmark_version, cr.title,
		       COALESCE(tr.override_severity, cr.severity) AS severity,
		       cr.signal_key, cr.comparator, cr.expected_values, cr.applicable_arch,
		       cr.treat_unknown_as, cr.platform, cr.treat_not_configured_as
		FROM compliance_rules cr
		JOIN tenant_rules tr
		  ON tr.rule_id = cr.id
		 AND tr.tenant_id = $1::uuid
		 AND tr.enabled = true
		 AND (tr.suppressed_until IS NULL OR tr.suppressed_until < now())
		WHERE cr.enabled = true
		  AND cr.collection_tier = 'T2'
		  AND cr.platform = $2
		  AND ` + deviceClassMatchSQL("cr.device_class", 3) + `
		ORDER BY cr.benchmark, cr.rule_key
	`
	rows, err := pool.Query(ctx, stmt, tenantID, platform, deviceClass)
	if err != nil {
		return nil, fmt.Errorf("query tenant rules: %w", err)
	}
	defer rows.Close()

	out := []Rule{} // non-nil; safe to append without nil guard
	for rows.Next() {
		var r Rule
		var treatNotConfiguredAs *string
		if err := rows.Scan(
			&r.ID, &r.RuleKey, &r.Benchmark, &r.BenchmarkVersion, &r.Title, &r.Severity,
			&r.SignalKey, &r.Comparator, &r.ExpectedValues, &r.ApplicableArch, &r.TreatUnknownAs,
			&r.Platform, &treatNotConfiguredAs,
		); err != nil {
			return nil, fmt.Errorf("scan tenant rule: %w", err)
		}
		if treatNotConfiguredAs != nil {
			r.TreatNotConfiguredAs = *treatNotConfiguredAs
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant rules: %w", err)
	}
	return out, nil
}

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx (both implement Exec
// with this exact signature) — the same minimal shape as
// agentidentity.Querier (internal/agentidentity/seed.go), defined locally
// here rather than imported so this package does not take on a new
// intra-repo dependency for one interface shape. SeedT2Baseline accepts it
// so callers already inside a transaction (CreateTenantHandler,
// createTrialTenant) can seed as part of tenant creation — a seeding
// failure then rolls the whole tenant creation back rather than
// half-creating a tenant.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// SeedT2Baseline idempotently seeds an enabled tenant_rules row for every T2
// compliance rule not already configured for tenantID (PAT-1794 — every
// assessed tenant gets the full T2 baseline by default, not opt-in). This is
// the single-tenant equivalent of migrations/0135_seed_t2_baseline.sql's
// bulk backfill, called from both tenant-creation paths going forward so new
// tenants never need that migration to catch up.
//
// ON CONFLICT (tenant_id, rule_id) DO NOTHING: never overwrites an existing
// tenant_rules row for this tenant, whatever its enabled/override/
// suppression state — an existing row means a deliberate decision already
// exists for that (tenant, rule) pair (including, in principle, a tenant
// created moments earlier by a concurrent request). Safe to call repeatedly.
func SeedT2Baseline(ctx context.Context, q Querier, tenantID string) error {
	const stmt = `
		INSERT INTO tenant_rules (id, tenant_id, rule_id, enabled, created_at, updated_at)
		SELECT gen_random_uuid(), $1::uuid, cr.id, true, now(), now()
		FROM compliance_rules cr
		WHERE cr.collection_tier = 'T2'
		  AND cr.enabled = true
		ON CONFLICT (tenant_id, rule_id) DO NOTHING
	`
	if _, err := q.Exec(ctx, stmt, tenantID); err != nil {
		return fmt.Errorf("seed T2 baseline for tenant %s: %w", tenantID, err)
	}
	return nil
}

// Evaluate runs every rule against the (signals, arch) pair and returns one
// Evaluation per rule. Pure function — no DB access, fully deterministic given
// inputs. Caller (extractor.processRow) inserts the evaluations.
//
// signals is the map of compliance_signals.key → value the extractor just
// wrote. arch is the device's reported architecture ("arm64", "x86_64").
func Evaluate(rules []Rule, signals map[string]string, arch string) []Evaluation {
	out := make([]Evaluation, 0, len(rules))
	for _, r := range rules {
		out = append(out, evaluateOne(r, signals, arch))
	}
	return out
}

func evaluateOne(r Rule, signals map[string]string, arch string) Evaluation {
	eval := Evaluation{
		RuleID:           r.ID,
		Severity:         r.Severity,
		BenchmarkVersion: r.BenchmarkVersion,
	}

	// Architecture gate first — a rule limited to arm64 emits not_applicable
	// on an Intel mac, without ever touching the signal.
	if len(r.ApplicableArch) > 0 && !contains(r.ApplicableArch, arch) {
		eval.Status = StatusNotApplicable
		return eval
	}

	observed, present := resolveSignal(r, signals)
	// A present-but-Unknown signal is evidence the collector could not read
	// the control (PAT-1710/1751/1752 have both agents emit the literal
	// string "Unknown" on a failed read rather than omitting the key). That
	// is not a real observation — comparing it against expected_values would
	// score an unreadable device exactly like a device that was actually
	// checked and found non-compliant, and the executive report has no way
	// to tell "unmanaged" from "unreadable" apart afterwards. Route it
	// through the same treat_unknown_as fallback as an absent key, and leave
	// ObservedValue nil (never a fabricated "Unknown" observation) so
	// downstream consumers can recognise it as undetermined by observed_value
	// being NULL rather than by string-matching a sentinel.
	if !present || isUnknownSentinel(observed) {
		eval.Status = statusFromUnknown(r.TreatUnknownAs)
		return eval
	}

	// NotConfigured (PAT-1767): the read succeeded and the setting is
	// genuinely absent. Resolved via the rule's effective
	// treat_not_configured_as — never via the comparator, since "NotConfigured"
	// is a state marker, not a value to compare against expected_values.
	//
	// Full evaluation order, for reference (evaluateOne runs these in
	// sequence and returns on the first match):
	//   1. signal_key absent from the map            -> treat_unknown_as, ObservedValue nil
	//   2. present but the literal "Unknown" sentinel -> treat_unknown_as, ObservedValue nil   (PAT-1758)
	//   3. present and exactly "NotConfigured"        -> effectiveTreatNotConfiguredAs, ObservedValue set (this branch)
	//   4. anything else                              -> compare() against expected_values, ObservedValue set
	// null never reaches this function at all (renderJSONValue drops it
	// before the signal enters the map, so it took path 1 above).
	if observed == SignalNotConfigured {
		eval.ObservedValue = &observed
		eval.Status = statusFromUnknown(effectiveTreatNotConfiguredAs(r))
		return eval
	}

	eval.ObservedValue = &observed
	eval.Status = compare(r.Comparator, observed, r.ExpectedValues)
	return eval
}

// legacyMacOSMDMEnrolmentFallbackEnabled is the explicit removal seam for the
// PAT-1752 transition. Keep this true for one macOS agent compatibility
// release, then delete the constant, resolveSignal's special case, its tests,
// and the updater's mdm_enrolment emission together. The exact rule/platform
// guards keep this bridge out of every Windows rule even though Windows uses
// the same neutral mdm_enrolled signal key.
const legacyMacOSMDMEnrolmentFallbackEnabled = true

const (
	macOSMDMRuleKey     = "patched_mdm_enrolment"
	neutralMDMSignalKey = "mdm_enrolled"
	legacyMDMSignalKey  = "mdm_enrolment"
)

// resolveSignal reads a rule's configured signal. The sole exception is the
// bounded PAT-1752 bridge for a macOS agent that predates mdm_enrolled: when
// the new key is absent, the old combined value is converted to the neutral
// Yes/No vocabulary. A present new value, including Unknown, always wins so a
// stale legacy value cannot turn a failed current read into a pass.
func resolveSignal(r Rule, signals map[string]string) (string, bool) {
	observed, present := signals[r.SignalKey]
	if present {
		return observed, true
	}
	if !legacyMacOSMDMEnrolmentFallbackEnabled ||
		r.Platform != "macos" ||
		r.RuleKey != macOSMDMRuleKey ||
		r.SignalKey != neutralMDMSignalKey {
		return "", false
	}

	legacy, present := signals[legacyMDMSignalKey]
	if !present {
		return "", false
	}
	return neutralMDMFromLegacy(legacy), true
}

// neutralMDMFromLegacy parses only the old collector's documented mdm=<state>
// token. It deliberately does not use substring matching: values such as
// mdm=YesPlease must fail closed rather than preserving the legacy rule's
// overly broad contains("mdm=Yes") behaviour.
func neutralMDMFromLegacy(legacy string) string {
	result := ""
	tokenCount := 0
	for _, field := range strings.Fields(legacy) {
		if !strings.HasPrefix(field, "mdm=") {
			continue
		}
		tokenCount++
		value := strings.TrimPrefix(field, "mdm=")
		if value != "Yes" && value != "No" {
			return unknownSentinel
		}
		if tokenCount != 1 {
			return unknownSentinel
		}
		result = value
	}
	if tokenCount != 1 || result == "" {
		return unknownSentinel
	}
	return result
}

// effectiveTreatNotConfiguredAs is the single place (PAT-1767) that applies
// the treat_not_configured_as → treat_unknown_as default: a rule with no
// explicit treat_not_configured_as behaves exactly as it did before this
// column existed, so introducing the column never silently changes an
// existing rule's outcome.
func effectiveTreatNotConfiguredAs(r Rule) string {
	if r.TreatNotConfiguredAs != "" {
		return r.TreatNotConfiguredAs
	}
	return r.TreatUnknownAs
}

// unknownSentinel is the literal value collectors emit for a signal they
// attempted to read but could not (permission denied, API failure, etc).
// Matched case-insensitively after trimming whitespace so "Unknown",
// "unknown", "UNKNOWN" and " Unknown " are all treated the same way.
const unknownSentinel = "unknown"

func isUnknownSentinel(observed string) bool {
	return strings.EqualFold(strings.TrimSpace(observed), unknownSentinel)
}

// compare runs one comparator and returns the resulting status. Unknown
// comparator values fail closed as `error` — the SQL CHECK constraint should
// have caught these at insert time, but we don't trust that as a runtime
// invariant.
func compare(comparator, observed string, expected []string) string {
	switch comparator {
	case ComparatorEq, ComparatorIn:
		if contains(expected, observed) {
			return StatusPass
		}
		return StatusFail

	case ComparatorNeq:
		if contains(expected, observed) {
			return StatusFail
		}
		return StatusPass

	case ComparatorContains:
		if len(expected) == 0 {
			return StatusError
		}
		if strings.Contains(observed, expected[0]) {
			return StatusPass
		}
		return StatusFail

	case ComparatorGTE, ComparatorLTE:
		if len(expected) == 0 {
			return StatusError
		}
		obsN, err := strconv.ParseFloat(observed, 64)
		if err != nil {
			return StatusError
		}
		expN, err := strconv.ParseFloat(expected[0], 64)
		if err != nil {
			return StatusError
		}
		if comparator == ComparatorGTE {
			if obsN >= expN {
				return StatusPass
			}
			return StatusFail
		}
		if obsN <= expN {
			return StatusPass
		}
		return StatusFail
	}
	return StatusError
}

// statusFromUnknown maps a treat_unknown_as (or, via effectiveTreatNotConfiguredAs,
// a treat_not_configured_as) value to the status it produces. Shared because
// both columns share the same value domain.
func statusFromUnknown(treat string) string {
	switch treat {
	case UnknownAsPass:
		return StatusPass
	case UnknownAsNotApplicable:
		return StatusNotApplicable
	default:
		return StatusFail
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
