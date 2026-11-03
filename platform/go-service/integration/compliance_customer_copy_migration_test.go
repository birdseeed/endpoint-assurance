//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestComplianceCustomerCopyMigrationLifecycle(t *testing.T) {
	for _, scenario := range []string{"fresh", "backfill", "custom", "preexisting_clean"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			pool := copyMigrationFixture(t, scenario != "fresh")
			if scenario == "custom" {
				copyMigrationExec(t, pool, `UPDATE compliance_rules SET description = description || ' Customer annotation.' WHERE description LIKE '%PAT-%'`)
			}
			if scenario == "preexisting_clean" {
				// Exactly the eventual clean text already exists, without 0220 ownership.
				copyMigrationExec(t, pool, `UPDATE compliance_rules SET description = regexp_replace(description, ' \(PAT-[0-9]+\)| \[PAT-2059/0174 backfill\]', '', 'g') WHERE description LIKE '%PAT-%'`)
			}
			original := copyMigrationDescriptions(t, pool)
			copyMigrationApply(t, pool, "0220_compliance_customer_copy.sql")
			cleaned := copyMigrationDescriptions(t, pool)
			changes := 0
			for key, old := range original {
				if cleaned[key] != old {
					changes++
					if strings.HasSuffix(key.benchmark, " custom") || strings.HasSuffix(key.version, " custom") {
						t.Errorf("cleanup changed unowned rule identity %+v", key)
					}
					for _, internal := range []string{"PAT-", "0174", "backfill"} {
						if strings.Contains(cleaned[key], internal) {
							t.Errorf("cleaned %+v still contains %q", key, internal)
						}
					}
				}
			}
			want := map[string]int{"fresh": 4, "backfill": 8, "custom": 0, "preexisting_clean": 0}[scenario]
			if changes != want {
				t.Fatalf("changed %d descriptions, want %d", changes, want)
			}
			backup := copyMigrationBackup(t, pool, want)
			copyMigrationApply(t, pool, "0220_compliance_customer_copy.sql")
			if !reflect.DeepEqual(cleaned, copyMigrationDescriptions(t, pool)) || backup != copyMigrationBackup(t, pool, want) {
				t.Fatal("forward replay changed descriptions or original provenance")
			}
			copyMigrationApply(t, pool, "0220_compliance_customer_copy_rollback.sql")
			if !reflect.DeepEqual(original, copyMigrationDescriptions(t, pool)) {
				t.Fatal("rollback did not restore exactly the owned descriptions")
			}
			var removed bool
			if err := pool.QueryRow(ctx, `SELECT to_regclass('public._migration_0220_compliance_copy_backup') IS NULL
 AND NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0220_compliance_customer_copy')`).Scan(&removed); err != nil || !removed {
				t.Fatalf("rollback retained provenance or bookkeeping: removed=%v err=%v", removed, err)
			}
			copyMigrationApply(t, pool, "0220_compliance_customer_copy_rollback.sql")
			if !reflect.DeepEqual(original, copyMigrationDescriptions(t, pool)) {
				t.Fatal("rollback replay changed descriptions")
			}
			copyMigrationApply(t, pool, "0220_compliance_customer_copy.sql")
			if !reflect.DeepEqual(cleaned, copyMigrationDescriptions(t, pool)) || backup != copyMigrationBackup(t, pool, want) {
				t.Fatal("reapply did not reproduce cleanup and provenance")
			}
			copyMigrationApply(t, pool, "0220_compliance_customer_copy_rollback.sql")
			copyMigrationApply(t, pool, "0174_compliance_rules_parity_rollback.sql")
			afterLegacyRollback := copyMigrationDescriptions(t, pool)
			wantDeleted := 0
			if scenario == "backfill" {
				wantDeleted = 4
			}
			if deleted := len(original) - len(afterLegacyRollback); deleted != wantDeleted {
				t.Fatalf("0174 rollback deleted %d rows, want %d", deleted, wantDeleted)
			}
			for key, description := range afterLegacyRollback {
				if description != original[key] {
					t.Errorf("reverse-order rollback changed surviving rule %+v", key)
				}
			}
		})
	}
}

func TestComplianceCustomerCopyRollbackPreservesLaterChanges(t *testing.T) {
	for _, scenario := range []string{"edited", "recreated", "identity_changed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			pool := copyMigrationFixture(t, true)
			original := copyMigrationDescriptions(t, pool)
			copyMigrationApply(t, pool, "0220_compliance_customer_copy.sql")
			backup := copyMigrationBackup(t, pool, 8)
			var id, description string
			if err := pool.QueryRow(ctx, `SELECT id, description FROM compliance_rules WHERE rule_key = 'patched_macos_disk_encryption_off' AND benchmark = 'patched.im baseline' AND benchmark_version = 'v1'`).Scan(&id, &description); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "edited":
				description += " Later edit."
				copyMigrationExec(t, pool, `UPDATE compliance_rules SET description = $2 WHERE id = $1`, id, description)
			case "recreated":
				oldID := id
				// Actually delete and recreate the row, retaining its full contents except UUID.
				if err := pool.QueryRow(ctx, `WITH removed AS (
 DELETE FROM compliance_rules WHERE id = $1 RETURNING *
 ) INSERT INTO compliance_rules
 SELECT (jsonb_populate_record(NULL::compliance_rules,
         to_jsonb(removed) || jsonb_build_object('id', gen_random_uuid()))).*
 FROM removed RETURNING id`, id).Scan(&id); err != nil {
					t.Fatal(err)
				}
				if id == oldID {
					t.Fatal("recreated fixture retained the old UUID")
				}
			case "identity_changed":
				copyMigrationExec(t, pool, `UPDATE compliance_rules SET benchmark_version = 'custom version' WHERE id = $1`, id)
			}
			beforeRollback := copyMigrationDescriptions(t, pool)
			copyMigrationApply(t, pool, "0220_compliance_customer_copy.sql")
			if !reflect.DeepEqual(beforeRollback, copyMigrationDescriptions(t, pool)) || backup != copyMigrationBackup(t, pool, 8) {
				t.Fatal("replay overwrote a later change or claimed new ownership")
			}
			copyMigrationApply(t, pool, "0220_compliance_customer_copy_rollback.sql")
			for key, got := range copyMigrationDescriptions(t, pool) {
				want := original[key]
				if key.key == "patched_macos_disk_encryption_off" {
					want = description
				}
				if got != want {
					t.Errorf("rollback %+v: got %q, want %q", key, got, want)
				}
			}
			// The legacy rollback must not acquire ownership of the preserved row.
			copyMigrationApply(t, pool, "0174_compliance_rules_parity_rollback.sql")
			var got string
			if err := pool.QueryRow(ctx, `SELECT description FROM compliance_rules WHERE id = $1`, id).Scan(&got); err != nil || got != description {
				t.Fatalf("reverse-order rollback changed/deleted preserved row: got=%q err=%v", got, err)
			}
		})
	}
}

func copyMigrationFixture(t *testing.T, backfill bool) *pgxpool.Pool {
	t.Helper()
	pool := customerCopyDatabase(t)
	entries, err := os.ReadDir(filepath.Join("..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		file := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(file, ".sql") || strings.HasSuffix(file, "_rollback.sql") || file > "0219_lifecycle_publish_browser_mappings.sql" {
			continue
		}
		if backfill && file == "0033_compliance_findings_rules.sql" {
			continue
		}
		copyMigrationApply(t, pool, file)
	}
	// Same key and shipped text, but different benchmark/version: neither is owned.
	copyMigrationExec(t, pool, `INSERT INTO compliance_rules
 (rule_key, benchmark, benchmark_version, title, description, severity,
  signal_key, comparator, expected_values, platform)
 SELECT rule_key, benchmark || variant.benchmark_suffix,
        benchmark_version || variant.version_suffix, title, description,
        severity, signal_key, comparator, expected_values, platform
 FROM compliance_rules CROSS JOIN
      (VALUES (' custom', ''), ('', ' custom')) AS variant(benchmark_suffix, version_suffix)
 WHERE rule_key = 'cis_macos_2_10_2_password_after_screensaver_delay'
   AND benchmark = 'CIS Apple macOS' AND benchmark_version = 'v3.0.0'`)
	return pool
}

func copyMigrationExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func copyMigrationApply(t *testing.T, pool *pgxpool.Pool, file string) {
	t.Helper()
	sql, err := os.ReadFile(filepath.Join("..", "migrations", file))
	if err != nil {
		t.Fatal(err)
	}
	if err := execMigration(context.Background(), pool, string(sql)); err != nil {
		t.Fatalf("apply %s: %v", file, err)
	}
}

func copyMigrationBackup(t *testing.T, pool *pgxpool.Pool, wantCount int) string {
	t.Helper()
	var count int
	var snapshot string
	if err := pool.QueryRow(context.Background(), `SELECT count(*), COALESCE(jsonb_agg(to_jsonb(b) ORDER BY rule_id), '[]'::jsonb)::text FROM _migration_0220_compliance_copy_backup b`).Scan(&count, &snapshot); err != nil {
		t.Fatal(err)
	}
	if count != wantCount {
		t.Fatalf("captured %d provenance rows, want %d", count, wantCount)
	}
	return snapshot
}

type copyMigrationRuleIdentity struct {
	key, benchmark, version string
}

func copyMigrationDescriptions(t *testing.T, pool *pgxpool.Pool) map[copyMigrationRuleIdentity]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT rule_key, benchmark, benchmark_version, COALESCE(description, '') FROM compliance_rules`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[copyMigrationRuleIdentity]string{}
	for rows.Next() {
		var key copyMigrationRuleIdentity
		var description string
		if err := rows.Scan(&key.key, &key.benchmark, &key.version, &description); err != nil {
			t.Fatal(err)
		}
		result[key] = description
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
