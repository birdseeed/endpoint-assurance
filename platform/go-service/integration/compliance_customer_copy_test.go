//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/evaluator"
)

// Apply the real migration chain in two disposable databases. The upgrade
// fixture reproduces the absent 0033 seed that made 0174 own the four rows;
// editing an old seed alone cannot make the upgrade case pass.
func TestComplianceRulesCustomerCopy(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		name := "fresh_install"
		if dirty {
			name = "persisted_backfill_upgrade"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			pool := customerCopyDatabase(t)
			entries, err := os.ReadDir(filepath.Join("..", "migrations"))
			if err != nil {
				t.Fatal(err)
			}
			var beforeRules, beforeEvaluations, beforePolicies string
			var beforeBehaviour map[string][]evaluator.Evaluation
			baseline := false
			for _, entry := range entries {
				file := entry.Name()
				if entry.IsDir() || !strings.HasSuffix(file, ".sql") || strings.HasSuffix(file, "_rollback.sql") {
					continue
				}
				if dirty && file == "0033_compliance_findings_rules.sql" {
					continue
				}
				if file > "0219_lifecycle_publish_browser_mappings.sql" && !baseline {
					customerCopyHistoryFixture(t, pool)
					beforeRules, beforeEvaluations, beforePolicies = customerCopySnapshots(t, pool)
					beforeBehaviour = customerCopyBehaviour(t, pool)
					baseline = true
				}
				sql, err := os.ReadFile(filepath.Join("..", "migrations", file))
				if err != nil {
					t.Fatal(err)
				}
				if err := execMigration(ctx, pool, string(sql)); err != nil {
					t.Fatalf("apply %s: %v", file, err)
				}
			}
			// Before the cleanup exists, capture the same baseline so the red result
			// is customer text, rather than a missing future migration filename.
			if !baseline {
				customerCopyHistoryFixture(t, pool)
				beforeRules, beforeEvaluations, beforePolicies = customerCopySnapshots(t, pool)
				beforeBehaviour = customerCopyBehaviour(t, pool)
			}
			afterRules, afterEvaluations, afterPolicies := customerCopySnapshots(t, pool)
			if beforeRules != afterRules {
				t.Error("description cleanup changed rule IDs, titles, or semantics")
			}
			if beforeEvaluations != afterEvaluations {
				t.Error("description cleanup changed persisted evaluation history")
			}
			if beforePolicies != afterPolicies {
				t.Error("description cleanup changed tenant-owned software justifications")
			}
			if !reflect.DeepEqual(beforeBehaviour, customerCopyBehaviour(t, pool)) {
				t.Error("description cleanup changed pass/fail/unknown evaluation behaviour")
			}
			rows, err := pool.Query(ctx, `SELECT rule_key, title, COALESCE(description, '') FROM compliance_rules ORDER BY rule_key`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			count := 0
			for rows.Next() {
				var key, title, description string
				if err := rows.Scan(&key, &title, &description); err != nil {
					t.Fatal(err)
				}
				count++
				for field, value := range map[string]string{"title": title, "description": description} {
					for _, forbidden := range []string{"pat-", "ticket", "--"} {
						if strings.Contains(strings.ToLower(value), forbidden) {
							t.Errorf("%s %s contains internal copy %q: %s", key, field, forbidden, value)
						}
					}
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if count < 6 {
				t.Fatalf("empty/incomplete rule fixture: %d rules", count)
			}
		})
	}
}

func customerCopyDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	host, database := cfg.ConnConfig.Host, cfg.ConnConfig.Database
	if (host != "localhost" && host != "127.0.0.1" && host != "::1") || !strings.HasSuffix(database, "_test") {
		t.Fatalf("customer copy fixture requires loopback *_test database, got host %q database %q", host, database)
	}
	name := "customer_copy_" + randomHex(8) + "_test"
	if _, err := env.pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := env.pool.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Errorf("drop owned test database: %v", err)
		}
	})
	return pool
}

func customerCopyHistoryFixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
 WITH tenant AS (
  INSERT INTO tenants (name, bearer_token_hash, hmac_secret) VALUES ('customer-copy-test', decode('00', 'hex'), decode('00', 'hex')) RETURNING id
 ), policy AS (
  INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, notes)
  SELECT id, 'Customer-owned justification', 'macos', 'approved', 'PAT-1318 customer justification -- preserve verbatim' FROM tenant
 ), device AS (
  INSERT INTO devices (tenant_id, serial, os) SELECT id, 'customer-copy-history', 'macOS' FROM tenant RETURNING id
 )
 INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
 SELECT device.id, rule.id, 'fail', NULL, rule.severity, rule.benchmark_version FROM device CROSS JOIN compliance_rules rule
 WHERE rule.rule_key IN ('cis_macos_2_10_2_password_after_screensaver_delay', 'cis_macos_2_10_1_screensaver_inactivity',
 'patched_macos_disk_encryption_off', 'patched_win_disk_encryption_off', 'patched_macos_removable_storage_unencrypted', 'patched_win_removable_storage_unencrypted')`)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM compliance_evaluations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("historical fixture has %d evaluations, want 6", count)
	}
}

func customerCopySnapshots(t *testing.T, pool *pgxpool.Pool) (string, string, string) {
	t.Helper()
	var rules, evaluations, policies string
	for table, output := range map[string]*string{"compliance_rules": &rules, "compliance_evaluations": &evaluations, "tenant_app_policies": &policies} {
		row := "to_jsonb(r)"
		if table == "compliance_rules" {
			row += " - 'description'"
		}
		query := fmt.Sprintf("SELECT COALESCE(jsonb_agg(%s ORDER BY r.id), '[]'::jsonb)::text FROM %s r", row, table)
		if err := pool.QueryRow(context.Background(), query).Scan(output); err != nil {
			t.Fatal(err)
		}
	}
	return rules, evaluations, policies
}

func customerCopyBehaviour(t *testing.T, pool *pgxpool.Pool) map[string][]evaluator.Evaluation {
	t.Helper()
	out := map[string][]evaluator.Evaluation{}
	for _, platform := range []string{"macos", "windows"} {
		rules, err := evaluator.LoadRules(context.Background(), pool, platform, "unknown")
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"", "Unknown", "Pass", "Fail", "5", "1200", "99999"} {
			signals := map[string]string{}
			for _, rule := range rules {
				if value != "" {
					signals[rule.SignalKey] = value
				}
			}
			out[platform+"/"+value] = evaluator.Evaluate(rules, signals, "arm64")
		}
	}
	return out
}
