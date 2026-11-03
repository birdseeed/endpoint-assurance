//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// PAT-2173: 0197 and 0198 seed live category data, but their audit entries
// are immutable historical evidence. Exercise the dependent rollbacks on the
// migrations-built database, then reapply them. The whole cycle is one
// transaction and rolls back, so it remains isolated from every other test.
func TestSoftwareCategorySeedRollbacksRetainAuditHistory(t *testing.T) {
	ctx := context.Background()
	forward197 := transactionalMigrationBody(t, "0197_remote_access_rmm_category.sql")
	forward198 := transactionalMigrationBody(t, "0198_duplicate_tools_category.sql")
	rollback197 := transactionalMigrationBody(t, "0197_remote_access_rmm_category_rollback.sql")
	rollback198 := transactionalMigrationBody(t, "0198_duplicate_tools_category_rollback.sql")

	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rollback regression transaction: %v", err)
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && err != pgx.ErrTxClosed {
			t.Errorf("rollback regression transaction: %v", err)
		}
	}()
	removeCategorySeedRollbackDependents(t, ctx, tx)

	auditCount := func(actor string) int {
		t.Helper()
		var count int
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM software_category_audit
			WHERE entity_type = 'rule' AND actor = $1`, actor).Scan(&count); err != nil {
			t.Fatalf("count %s audit rows: %v", actor, err)
		}
		return count
	}

	const (
		migration197 = "migration:0197_remote_access_rmm_category"
		migration198 = "migration:0198_duplicate_tools_category"
	)
	audit197, audit198 := auditCount(migration197), auditCount(migration198)
	if audit197 == 0 || audit198 == 0 {
		t.Fatalf("expected seeded audit history, got 0197=%d 0198=%d", audit197, audit198)
	}

	if _, err := tx.Exec(ctx, rollback198); err != nil {
		t.Fatalf("rollback 0198: %v", err)
	}
	assertCategorySeedRollbackState(t, ctx, tx, true, false)
	if got := auditCount(migration197); got != audit197 {
		t.Fatalf("0197 audit rows after 0198 rollback = %d, want %d", got, audit197)
	}
	if got := auditCount(migration198); got != audit198 {
		t.Fatalf("0198 audit rows after rollback = %d, want %d", got, audit198)
	}

	if _, err := tx.Exec(ctx, rollback197); err != nil {
		t.Fatalf("rollback 0197: %v", err)
	}
	assertCategorySeedRollbackState(t, ctx, tx, false, false)
	if got := auditCount(migration197); got != audit197 {
		t.Fatalf("0197 audit rows after rollback = %d, want %d", got, audit197)
	}
	if got := auditCount(migration198); got != audit198 {
		t.Fatalf("0198 audit rows after dependent rollback = %d, want %d", got, audit198)
	}

	if _, err := tx.Exec(ctx, forward197); err != nil {
		t.Fatalf("reapply 0197: %v", err)
	}
	if _, err := tx.Exec(ctx, forward198); err != nil {
		t.Fatalf("reapply 0198: %v", err)
	}
	assertCategorySeedRollbackState(t, ctx, tx, true, true)
	if got := auditCount(migration197); got < audit197 {
		t.Fatalf("0197 audit rows after reapply = %d, want at least %d", got, audit197)
	}
	if got := auditCount(migration198); got < audit198 {
		t.Fatalf("0198 audit rows after reapply = %d, want at least %d", got, audit198)
	}
}

// transactionalMigrationBody removes and validates the file's one outer
// BEGIN/COMMIT pair, allowing the checked-in migration body to execute inside
// this test's transaction rather than committing shared integration state.
func transactionalMigrationBody(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "migrations", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var body strings.Builder
	beginCount, commitCount := 0, 0
	for _, line := range strings.Split(string(contents), "\n") {
		switch strings.TrimSpace(line) {
		case "BEGIN;":
			beginCount++
			continue
		case "COMMIT;":
			commitCount++
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if beginCount != 1 || commitCount != 1 {
		t.Fatalf("%s transaction wrappers = BEGIN:%d COMMIT:%d, want one each", name, beginCount, commitCount)
	}
	return body.String()
}

// removeCategorySeedRollbackDependents clears only rows that FK-block the
// two rollback bodies. This includes rule/product-tag materialisations and
// product tags on the categories being removed; the outer transaction makes
// these test-fixture removals invisible to the shared integration database.
func removeCategorySeedRollbackDependents(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	if _, err := tx.Exec(ctx, `
		DELETE FROM software_category_tags
		WHERE rule_id IN (
			SELECT id FROM software_category_rules
			WHERE created_by IN ('migration:0197_remote_access_rmm_category', 'migration:0198_duplicate_tools_category')
		) OR product_tag_id IN (
			SELECT id FROM software_category_product_tags
			WHERE category_key IN ('remote_access', 'rmm_agent', 'pdf_editor', 'screen_recorder', 'vpn_client', 'password_manager', 'file_sync', 'video_conferencing', 'note_taking')
		)`); err != nil {
		t.Fatalf("remove category-tag rollback dependents: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM software_category_product_tags
		WHERE category_key IN ('remote_access', 'rmm_agent', 'pdf_editor', 'screen_recorder', 'vpn_client', 'password_manager', 'file_sync', 'video_conferencing', 'note_taking')`); err != nil {
		t.Fatalf("remove category product-tag rollback dependents: %v", err)
	}
}

func assertCategorySeedRollbackState(t *testing.T, ctx context.Context, tx pgx.Tx, want197, want198 bool) {
	t.Helper()
	var remoteCategories, duplicateCategories int
	var rules197, rules198, productKey, migration197, migration198 bool
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM software_categories WHERE key IN ('remote_access', 'rmm_agent')),
			(SELECT COUNT(*) FROM software_categories WHERE key IN ('pdf_editor', 'screen_recorder', 'vpn_client', 'password_manager', 'file_sync', 'video_conferencing', 'note_taking')),
			EXISTS (SELECT 1 FROM software_category_rules WHERE created_by = 'migration:0197_remote_access_rmm_category'),
			EXISTS (SELECT 1 FROM software_category_rules WHERE created_by = 'migration:0198_duplicate_tools_category'),
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'software_category_rules' AND column_name = 'product_key'),
			EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0197_remote_access_rmm_category'),
			EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0198_duplicate_tools_category')
	`).Scan(&remoteCategories, &duplicateCategories, &rules197, &rules198, &productKey, &migration197, &migration198); err != nil {
		t.Fatalf("read category seed rollback state: %v", err)
	}
	wantRemoteCategories := 0
	if want197 {
		wantRemoteCategories = 2
	}
	if remoteCategories != wantRemoteCategories || rules197 != want197 || migration197 != want197 {
		t.Fatalf("0197 state categories=%d rules=%v migration=%v, want categories=%d rules/migration=%v", remoteCategories, rules197, migration197, wantRemoteCategories, want197)
	}
	wantDuplicateCategories := 0
	if want198 {
		wantDuplicateCategories = 7
	}
	if duplicateCategories != wantDuplicateCategories || rules198 != want198 || productKey != want198 || migration198 != want198 {
		t.Fatalf("0198 state categories=%d rules=%v product_key=%v migration=%v, want categories=%d rules/product_key/migration=%v", duplicateCategories, rules198, productKey, migration198, wantDuplicateCategories, want198)
	}
}
