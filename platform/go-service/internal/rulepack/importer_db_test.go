package rulepack

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1858RulepackSchema = "pat1858_rulepack_test"

func pat1858RulepackPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed rule-pack test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1858RulepackSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, statement := range []string{
		`DROP SCHEMA IF EXISTS ` + pat1858RulepackSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1858RulepackSchema,
		`CREATE TABLE ` + pat1858RulepackSchema + `.compliance_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			benchmark TEXT NOT NULL,
			benchmark_version TEXT NOT NULL,
			platform TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			signal_key TEXT NOT NULL,
			comparator TEXT NOT NULL,
			expected_values TEXT[] NOT NULL,
			applicable_arch TEXT[],
			treat_unknown_as TEXT NOT NULL,
			nist_mappings TEXT[],
			iso_mappings TEXT[],
			cyber_essentials_mappings TEXT[],
			enabled BOOLEAN NOT NULL,
			collection_tier TEXT NOT NULL,
			pii_observed TEXT,
			requires_user_consent BOOLEAN NOT NULL,
			treat_not_configured_as TEXT,
			control_identifier TEXT CHECK (control_identifier IS NULL OR btrim(control_identifier) <> ''),
			UNIQUE (benchmark, benchmark_version, rule_key)
		)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("setup rule-pack schema: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1858RulepackSchema+` CASCADE`)
	})
	return pool
}

func TestImport_ControlIdentifierPresenceSemantics(t *testing.T) {
	pool := pat1858RulepackPool(t)
	ctx := context.Background()
	pack := validPack()
	pack.Benchmark = "CIS Apple macOS"
	pack.BenchmarkVersion = "v2.1.0"
	pack.Platform = "macos"
	pack.Rules[0].RuleKey = "test_versioned_rule"
	pack.Rules[0].Title = "Synthetic versioned rule"
	initialIdentifier := "1.2"
	pack.Rules[0].ControlIdentifier = &initialIdentifier

	result, err := Import(ctx, pool, pack, false)
	if err != nil {
		t.Fatalf("initial import: %v", err)
	}
	if result.Inserted != 1 || result.Updated != 0 {
		t.Fatalf("initial import result = inserted %d, updated %d", result.Inserted, result.Updated)
	}

	var identifier *string
	if err := pool.QueryRow(ctx, `
		SELECT control_identifier FROM compliance_rules
		WHERE benchmark = $1 AND benchmark_version = $2 AND rule_key = $3
	`, pack.Benchmark, pack.BenchmarkVersion, pack.Rules[0].RuleKey).Scan(&identifier); err != nil {
		t.Fatalf("query imported identifier: %v", err)
	}
	if identifier == nil || *identifier != "1.2" {
		t.Fatalf("imported control_identifier = %v, want 1.2", identifier)
	}

	// Omission is not an instruction to erase previously evidenced metadata.
	pack.Rules[0].ControlIdentifier = nil
	result, err = Import(ctx, pool, pack, false)
	if err != nil {
		t.Fatalf("omitted-identifier re-import: %v", err)
	}
	if result.Inserted != 0 || result.Updated != 1 {
		t.Fatalf("re-import result = inserted %d, updated %d", result.Inserted, result.Updated)
	}
	if err := pool.QueryRow(ctx, `
		SELECT control_identifier FROM compliance_rules
		WHERE benchmark = $1 AND benchmark_version = $2 AND rule_key = $3
	`, pack.Benchmark, pack.BenchmarkVersion, pack.Rules[0].RuleKey).Scan(&identifier); err != nil {
		t.Fatalf("query preserved identifier: %v", err)
	}
	if identifier == nil || *identifier != "1.2" {
		t.Fatalf("identifier after omission = %v, want preserved 1.2", identifier)
	}

	replacementIdentifier := "4.5"
	pack.Rules[0].ControlIdentifier = &replacementIdentifier
	if _, err := Import(ctx, pool, pack, false); err != nil {
		t.Fatalf("explicit identifier update: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT control_identifier FROM compliance_rules
		WHERE benchmark = $1 AND benchmark_version = $2 AND rule_key = $3
	`, pack.Benchmark, pack.BenchmarkVersion, pack.Rules[0].RuleKey).Scan(&identifier); err != nil {
		t.Fatalf("query replaced identifier: %v", err)
	}
	if identifier == nil || *identifier != "4.5" {
		t.Fatalf("identifier after explicit update = %v, want 4.5", identifier)
	}
}
