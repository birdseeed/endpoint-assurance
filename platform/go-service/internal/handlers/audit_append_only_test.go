package handlers

// Tests for the append-only guards added by PAT-1133
// (migrations/0096_audit_append_only_guards.sql).
//
// migrations 0091_agent_decommission.sql / agent_decommission_test.go
// established the pattern this file follows for five more audit tables:
// UPDATE, DELETE, and TRUNCATE must all be rejected by DB trigger — not just
// documented against via GRANT — even for the `patched` role that owns
// every table in the database (ownership bypasses GRANT/REVOKE entirely;
// see 0095_owner_catchup_to_patched.sql and 0096's header comment). This
// test therefore deliberately uses the plain application pool (the owning
// role), not some lesser-privileged role, for every mutation attempt below —
// that is exactly the case that was previously unenforced.
//
// DB-backed; skipped when TEST_DATABASE_URL is unset, matching the convention
// used throughout this package (see agent_decommission_test.go, PAT-1108
// finding 6, for why PATCHED_DB_TESTS_REQUIRED escalates that skip to a
// hard failure in the CI job that promises a database).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

func aoConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not — append-only-guard DB coverage would silently evaporate; see go-integration-test.yml's \"internal/handlers DB-gated tests\" step")
		}
		t.Skip("TEST_DATABASE_URL not set — skipping append-only guard DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// aoSeedTenant creates a bare tenant for one test case and registers its
// cleanup. None of the five tables under test here have a foreign key that
// would cascade-delete their rows when this tenant is removed (see 0096's
// header comment for exactly which audit tables DO cascade, and why those
// were excluded from the guard instead), so no additional cleanup is
// needed beyond the tenant row itself.
func aoSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00'::bytea, '\x00'::bytea)
		RETURNING id::text
	`, name).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id)
	})
	return id
}

// TestAuditTablesAppendOnly is the PAT-1133 regression: for every table
// migrations/0096_audit_append_only_guards.sql guards, INSERT must succeed
// (the legitimate write path every handler uses) while UPDATE, DELETE, and
// TRUNCATE must all be rejected — including TRUNCATE, which a row-level
// trigger alone cannot stop (PAT-1108 fifth-round finding P1-C; Postgres
// never fires row-level triggers for TRUNCATE).
func TestAuditTablesAppendOnly(t *testing.T) {
	pool := aoConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	cases := []struct {
		table string
		// insertSQL takes tenant_id as $1 and returns the new row's id::text.
		insertSQL string
		// updateSQL takes the row id (text form) as $1 and mutates one
		// harmless column — any column, since the trigger rejects the
		// statement outright regardless of which column it touches.
		updateSQL string
	}{
		{
			table: "tenant_platform_changes",
			insertSQL: `
				INSERT INTO tenant_platform_changes (tenant_id, platform, changed_by, old_enabled, new_enabled)
				VALUES ($1::uuid, 'macos', 'aoguard-tester', true, false)
				RETURNING id::text`,
			updateSQL: `UPDATE tenant_platform_changes SET changed_by = 'tampered' WHERE id::text = $1`,
		},
		{
			table: "tenant_rule_changes",
			insertSQL: `
				INSERT INTO tenant_rule_changes (tenant_id, rule_id, changed_by, change_type, old_enabled, new_enabled)
				VALUES ($1::uuid, gen_random_uuid(), 'aoguard-tester', 'enabled', true, false)
				RETURNING id::text`,
			updateSQL: `UPDATE tenant_rule_changes SET changed_by = 'tampered' WHERE id::text = $1`,
		},
		{
			table: "tenant_app_policy_changes",
			insertSQL: `
				INSERT INTO tenant_app_policy_changes (tenant_id, changed_by, change_type)
				VALUES ($1::uuid, 'aoguard-tester', 'default_changed')
				RETURNING id::text`,
			updateSQL: `UPDATE tenant_app_policy_changes SET changed_by = 'tampered' WHERE id::text = $1`,
		},
		{
			table: "ring_config_changes",
			insertSQL: `
				INSERT INTO ring_config_changes (tenant_id, change_type, changed_by)
				VALUES ($1::uuid, 'config_updated', 'aoguard-tester')
				RETURNING id::text`,
			updateSQL: `UPDATE ring_config_changes SET changed_by = 'tampered' WHERE id::text = $1`,
		},
		{
			table: "enforcement_audit",
			insertSQL: `
				INSERT INTO enforcement_audit (tenant_id, device_id, event_type, subject, occurred_at)
				VALUES ($1::uuid, 'aoguard-device', 'admin_removed', 'aoguard-tester', now())
				RETURNING id::text`,
			updateSQL: `UPDATE enforcement_audit SET subject = 'tampered' WHERE id::text = $1`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.table, func(t *testing.T) {
			tenantID := aoSeedTenant(t, ctx, pool, "aoguard-"+tc.table)

			// INSERT must succeed — this is the real write path every
			// handler that writes this table uses.
			var rowID string
			if err := pool.QueryRow(ctx, tc.insertSQL, tenantID).Scan(&rowID); err != nil {
				t.Fatalf("INSERT into %s failed, want success: %v", tc.table, err)
			}

			// UPDATE must be rejected, even for the owning `patched` role.
			if _, err := pool.Exec(ctx, tc.updateSQL, rowID); err == nil {
				t.Errorf("UPDATE on %s succeeded, want rejected — the audit trail must be append-only even for the table-owning role", tc.table)
			} else if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("UPDATE on %s error = %v, want an append-only rejection", tc.table, err)
			}

			// DELETE must be rejected, even for the owning `patched` role.
			delSQL := fmt.Sprintf(`DELETE FROM %s WHERE id::text = $1`, tc.table)
			if _, err := pool.Exec(ctx, delSQL, rowID); err == nil {
				t.Errorf("DELETE on %s succeeded, want rejected — the audit trail must be append-only even for the table-owning role", tc.table)
			} else if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("DELETE on %s error = %v, want an append-only rejection", tc.table, err)
			}

			// TRUNCATE must be rejected — a row-level trigger alone does not
			// stop it; this exercises the separate statement-level guard.
			// CASCADE is harmless for tables with no incoming FK (nothing to
			// cascade to) and necessary for enforcement_audit specifically:
			// tenant_extension_removal_targets.audit_event_id references it,
			// so a plain TRUNCATE is rejected by Postgres's own referential-
			// integrity check before our trigger ever gets a chance to run.
			// CASCADE clears that check and lets the statement reach the
			// BEFORE TRUNCATE trigger, which is the thing under test here.
			truncSQL := fmt.Sprintf(`TRUNCATE %s CASCADE`, tc.table)
			if _, err := pool.Exec(ctx, truncSQL); err == nil {
				t.Errorf("TRUNCATE on %s succeeded, want rejected — a row-level trigger alone does not stop TRUNCATE", tc.table)
			} else if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("TRUNCATE on %s error = %v, want an append-only rejection", tc.table, err)
			}

			// The row must be completely unaffected by any of the three
			// rejected attempts.
			var stillThere int
			countSQL := fmt.Sprintf(`SELECT count(*) FROM %s WHERE id::text = $1`, tc.table)
			if err := pool.QueryRow(ctx, countSQL, rowID).Scan(&stillThere); err != nil {
				t.Fatalf("recount %s: %v", tc.table, err)
			}
			if stillThere != 1 {
				t.Errorf("%s row count after rejected mutations = %d, want 1 — the row must survive every rejected attempt untouched", tc.table, stillThere)
			}
		})
	}
}
