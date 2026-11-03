package rulepack

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ImportResult summarises what the import did (or would do in dry-run).
type ImportResult struct {
	Inserted int
	Updated  int
	DryRun   bool
	Rules    []RuleResult
}

// RuleResult records the per-rule outcome.
type RuleResult struct {
	RuleKey string
	Action  string // "insert" or "update"
}

const upsertSQL = `
INSERT INTO compliance_rules (
    rule_key, benchmark, benchmark_version, platform,
    title, description, severity, signal_key, comparator,
    expected_values, applicable_arch, treat_unknown_as,
    nist_mappings, iso_mappings, cyber_essentials_mappings,
    enabled, collection_tier, pii_observed, requires_user_consent,
    treat_not_configured_as, control_identifier
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12,
    $13, $14, $15,
    $16, $17, $18, $19,
    $20, $21
)
ON CONFLICT (benchmark, benchmark_version, rule_key) DO UPDATE SET
    platform                  = EXCLUDED.platform,
    title                     = EXCLUDED.title,
    description               = EXCLUDED.description,
    severity                  = EXCLUDED.severity,
    signal_key                = EXCLUDED.signal_key,
    comparator                = EXCLUDED.comparator,
    expected_values           = EXCLUDED.expected_values,
    applicable_arch           = EXCLUDED.applicable_arch,
    treat_unknown_as          = EXCLUDED.treat_unknown_as,
    nist_mappings             = EXCLUDED.nist_mappings,
    iso_mappings              = EXCLUDED.iso_mappings,
    cyber_essentials_mappings = EXCLUDED.cyber_essentials_mappings,
    enabled                   = EXCLUDED.enabled,
    collection_tier           = EXCLUDED.collection_tier,
    pii_observed              = EXCLUDED.pii_observed,
    requires_user_consent     = EXCLUDED.requires_user_consent,
    treat_not_configured_as   = EXCLUDED.treat_not_configured_as,
    control_identifier        = COALESCE(EXCLUDED.control_identifier, compliance_rules.control_identifier)
`

// Import upserts all rules from pack into compliance_rules inside a single
// transaction. When dryRun is true it queries existing rules to compute the
// insert/update plan but writes nothing. Validate must be called first.
func Import(ctx context.Context, pool *pgxpool.Pool, pack *Pack, dryRun bool) (*ImportResult, error) {
	existing, err := fetchExistingKeys(ctx, pool, pack.Benchmark, pack.BenchmarkVersion)
	if err != nil {
		return nil, fmt.Errorf("fetch existing rules: %w", err)
	}

	plan := planImport(existing, pack.Rules)

	result := &ImportResult{DryRun: dryRun, Rules: plan}
	for _, r := range plan {
		if r.Action == "insert" {
			result.Inserted++
		} else {
			result.Updated++
		}
	}

	if dryRun {
		return result, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for _, r := range pack.Rules {
		_, err := tx.Exec(ctx, upsertSQL,
			r.RuleKey,
			pack.Benchmark,
			pack.BenchmarkVersion,
			pack.Platform,
			r.Title,
			nullIfEmpty(r.Description),
			r.Severity,
			r.SignalKey,
			r.Comparator,
			r.ExpectedValues,
			nilIfEmpty(r.ApplicableArch),
			stringDefault(r.TreatUnknownAs, "fail"),
			nilIfEmpty(r.NistMappings),
			nilIfEmpty(r.IsoMappings),
			nilIfEmpty(r.CyberEssentialsMappings),
			boolDefault(r.Enabled, true),
			stringDefault(r.CollectionTier, "T1"),
			nullIfEmpty(r.PiiObserved),
			r.RequiresUserConsent,
			// NULL (not a default like treat_unknown_as's "fail") — an
			// omitted treat_not_configured_as means "use treat_unknown_as",
			// applied by the evaluator, not by import-time substitution.
			nullIfEmpty(r.TreatNotConfiguredAs),
			r.ControlIdentifier,
		)
		if err != nil {
			return nil, fmt.Errorf("upsert rule %q: %w", r.RuleKey, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return result, nil
}

// fetchExistingKeys returns the set of rule_keys already stored for the given
// benchmark+version pair.
func fetchExistingKeys(ctx context.Context, pool *pgxpool.Pool, benchmark, version string) (map[string]bool, error) {
	rows, err := pool.Query(ctx,
		`SELECT rule_key FROM compliance_rules WHERE benchmark = $1 AND benchmark_version = $2`,
		benchmark, version,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// planImport classifies each rule as "insert" or "update" based on the set of
// existing rule_keys for this benchmark+version. Pure function — no DB calls.
func planImport(existing map[string]bool, rules []RuleSpec) []RuleResult {
	out := make([]RuleResult, len(rules))
	for i, r := range rules {
		action := "insert"
		if existing[r.RuleKey] {
			action = "update"
		}
		out[i] = RuleResult{RuleKey: r.RuleKey, Action: action}
	}
	return out
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfEmpty(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	return ss
}

func stringDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func boolDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
