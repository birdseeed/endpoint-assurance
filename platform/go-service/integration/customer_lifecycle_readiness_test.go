//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/auth"
)

// This deliberately proves restoration can resurrect purged data. It is not a
// deletion certification or a substitute for deployed staging evidence.
func TestCustomerLifecycleReadiness(t *testing.T) {
	if os.Getenv("PAT2369_PRIVATE_CLUSTER") != "1" {
		t.Skip("run scripts/check-customer-lifecycle.sh to provision private databases")
	}
	ctx := context.Background()
	reportRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", reportRoot)
	forward, err := os.ReadFile("../migrations/0225_software_alert_purge_redaction.sql")
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := os.ReadFile("../migrations/0225_software_alert_purge_redaction_rollback.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := execMigration(ctx, env.pool, string(rollback)); err != nil {
		t.Fatal(err)
	}
	if err := execMigration(ctx, env.pool, string(forward)); err != nil {
		t.Fatal(err)
	}
	create := func(name string) (string, string) {
		t.Helper()
		id, token, _, err := createTestTenant(env.internalSrv.URL, name)
		if err != nil {
			t.Fatal(err)
		}
		return id, token
	}
	a, tokenA := create("PAT-2369 disposable A")
	b, tokenB := create("PAT-2369 preserved B")
	// Both tenants have identifying audit fields, but only A will be purged.
	for _, tenant := range []string{a, b} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_alert_transitions
		(tenant_id, alert_device_id, episode_id, device_id, to_status, actor_kind, actor, note)
		VALUES ($1::uuid, 1, 1, gen_random_uuid(), 'open', 'portal_user', 'synthetic@example.test', 'synthetic identifying note')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	auditShape := func() string {
		t.Helper()
		var shape string
		if err := env.pool.QueryRow(ctx, `SELECT (to_jsonb(t)-'actor'-'note'-'tenant_purge_anonymized_at')::text FROM software_unapproved_alert_transitions t WHERE tenant_id=$1::uuid`, a).Scan(&shape); err != nil {
			t.Fatal(err)
		}
		return shape
	}
	beforeAudit := auditShape()
	// Whole-row snapshot of B (actor, note and marker included) so the purge of A
	// can be shown to leave B byte-for-byte unchanged.
	rowsOf := func(tenant string) string {
		t.Helper()
		var rows string
		if err := env.pool.QueryRow(ctx, `SELECT coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY id), '') FROM software_unapproved_alert_transitions t WHERE tenant_id=$1::uuid`, tenant).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	beforeB := rowsOf(b)
	// Even a caller-set scope cannot authorise direct redaction or mutation.
	for _, sql := range []string{
		`UPDATE software_unapproved_alert_transitions SET actor=NULL,note=NULL,tenant_purge_anonymized_at=transaction_timestamp() WHERE tenant_id=$1::uuid`,
		`DELETE FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`,
		`TRUNCATE software_unapproved_alert_transitions`,
		`INSERT INTO software_unapproved_alert_transitions (tenant_id,alert_device_id,episode_id,device_id,to_status,actor_kind,tenant_purge_anonymized_at) VALUES ($1::uuid,1,1,gen_random_uuid(),'open','portal_user',now())`,
	} {
		for _, role := range []string{"none", "patched"} {
			tx, err := env.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if role == "patched" {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE patched"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('patched.software_alert_purge_tenant',$1,true)`, a); err != nil {
				t.Fatal(err)
			}
			var mutationErr error
			if strings.HasPrefix(sql, "TRUNCATE") {
				_, mutationErr = tx.Exec(ctx, sql)
			} else {
				_, mutationErr = tx.Exec(ctx, sql, a)
			}
			if mutationErr == nil {
				t.Errorf("ordinary mutation unexpectedly succeeded: %s", sql)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, id := range []string{a, b} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO devices (tenant_id, serial, os, primary_user_account) VALUES ($1::uuid, $1, 'macOS', 'synthetic@example.test')`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(ctx, `INSERT INTO raw_payloads (tenant_id, body) VALUES ($1::uuid, '{"synthetic":true}')`, id); err != nil {
			t.Fatal(err)
		}
	}
	request := func(method, suffix string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, env.internalSrv.URL+"/admin/tenants/"+a+suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, suffix, resp.StatusCode, want, body)
		}
		return body
	}
	authenticate := func(pool *pgxpool.Pool, token string, allowed bool) {
		t.Helper()
		_, _, err := auth.LookupTenantByBearer(ctx, pool, "Bearer "+token)
		if allowed && err != nil {
			t.Fatalf("active credential rejected: %v", err)
		}
		if !allowed && !errors.Is(err, auth.ErrUnknownToken) {
			t.Fatalf("disabled credential: want unknown token, got %v", err)
		}
	}
	count := func(pool *pgxpool.Pool, table, id string, want int) {
		t.Helper()
		// table comes only from this test's fixed literals.
		var got int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1::uuid", id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s rows=%d want=%d", table, got, want)
		}
	}
	authenticate(env.pool, tokenA, true)
	request(http.MethodDelete, "/purge", http.StatusConflict)
	request(http.MethodDelete, "", http.StatusOK)
	// A failed/abandoned purge transaction must restore both tenant and PII.
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, a); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if auditShape() != beforeAudit {
		t.Fatal("rolled-back purge changed event evidence")
	}
	var originalActor string
	if err := env.pool.QueryRow(ctx, `SELECT actor FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, a).Scan(&originalActor); err != nil || originalActor != "synthetic@example.test" {
		t.Fatalf("purge rollback did not preserve PII: %v", err)
	}
	authenticate(env.pool, tokenA, false)
	blocked, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", nil)
	if err != nil {
		t.Fatal(err)
	}
	blocked.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := http.DefaultClient.Do(blocked)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked inventory credential returned %d, want 401", resp.StatusCode)
	}
	authenticate(env.pool, tokenB, true)
	count(env.pool, "raw_payloads", a, 1) // disable retains evidence
	var bundle exportBundleShape
	if err := json.Unmarshal(request(http.MethodGet, "/export", http.StatusOK), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.TenantID != a || len(bundle.Devices) != 1 {
		t.Fatalf("revoked export scope wrong: %+v", bundle)
	}
	request(http.MethodPost, "/restore", http.StatusOK)
	authenticate(env.pool, tokenA, true) // soft restore restores existing credential
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_credentials SET revoked_at=now() WHERE tenant_id=$1::uuid`, a); err != nil {
		t.Fatal(err)
	}
	authenticate(env.pool, tokenA, false) // independent credential disable
	request(http.MethodPost, "/restore", http.StatusOK)
	authenticate(env.pool, tokenA, false) // tenant restore does not un-revoke credential
	// Reset only the synthetic credential to model a pre-offboarding backup.
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_credentials SET revoked_at=NULL WHERE tenant_id=$1::uuid`, a); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(t.TempDir(), "before-offboarding.dump")
	pgBin := os.Getenv("PAT2369_PG_BIN")
	for _, args := range [][]string{
		{"pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file=" + dump, "--dbname=" + os.Getenv("TEST_DATABASE_URL")},
		{"pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "--dbname=" + os.Getenv("PAT2369_RESTORE_DATABASE_URL"), dump},
	} {
		if out, err := exec.CommandContext(ctx, filepath.Join(pgBin, args[0]), args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", args[0], err, out)
		}
	}
	request(http.MethodDelete, "", http.StatusOK)
	// Force the audit cleanup to fail (a constraint that rejects the purge
	// marker for A only). The whole purge must roll back: tenant, credentials and
	// the original PII all survive, and the endpoint reports a non-committed result.
	if _, err := env.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE software_unapproved_alert_transitions
		ADD CONSTRAINT pat2380_force_cleanup_failure CHECK (tenant_id <> '%s'::uuid OR tenant_purge_anonymized_at IS NULL) NOT VALID`, a)); err != nil {
		t.Fatal(err)
	}
	failed := request(http.MethodDelete, "/purge", http.StatusInternalServerError)
	if strings.Contains(string(failed), `"purged":true`) {
		t.Fatalf("purge reported success despite cleanup failure: %s", failed)
	}
	if _, err := env.pool.Exec(ctx, `ALTER TABLE software_unapproved_alert_transitions DROP CONSTRAINT pat2380_force_cleanup_failure`); err != nil {
		t.Fatal(err)
	}
	var tenantRows int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id=$1::uuid`, a).Scan(&tenantRows); err != nil || tenantRows != 1 {
		t.Fatalf("failed cleanup did not roll back the purge: rows=%d err=%v", tenantRows, err)
	}
	for _, table := range []string{"raw_payloads", "devices", "tenant_credentials"} {
		count(env.pool, table, a, 1)
	}
	if err := env.pool.QueryRow(ctx, `SELECT actor FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, a).Scan(&originalActor); err != nil || originalActor != "synthetic@example.test" {
		t.Fatalf("failed cleanup left audit PII modified: %v %q", err, originalActor)
	}
	var purged struct {
		Purged bool   `json:"purged"`
		Status string `json:"purge_status"`
	}
	if err := json.Unmarshal(request(http.MethodDelete, "/purge", http.StatusOK), &purged); err != nil {
		t.Fatal(err)
	}
	if !purged.Purged || purged.Status != "committed" {
		t.Fatalf("purge did not commit: %+v", purged)
	}
	for _, table := range []string{"raw_payloads", "devices", "tenant_credentials"} {
		count(env.pool, table, a, 0)
		count(env.pool, table, b, 1)
	}
	authenticate(env.pool, tokenA, false)
	authenticate(env.pool, tokenB, true)
	var retainedActor, retainedNote *string
	if err := env.pool.QueryRow(ctx, `SELECT actor, note FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, a).Scan(&retainedActor, &retainedNote); err != nil {
		t.Fatal(err)
	}
	if retainedActor != nil || retainedNote != nil {
		t.Error("purged tenant retained actor email or note; deletion readiness requires both NULL")
	}
	if auditShape() != beforeAudit {
		t.Fatal("purge changed non-PII event evidence")
	}
	count(env.pool, "software_unapproved_alert_transitions", a, 1)
	var otherActor, otherNote string
	if err := env.pool.QueryRow(ctx, `SELECT actor,note FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, b).Scan(&otherActor, &otherNote); err != nil || otherActor != "synthetic@example.test" || otherNote != "synthetic identifying note" {
		t.Fatalf("purge changed B audit: %v", err)
	}
	if afterB := rowsOf(b); afterB != beforeB || afterB == "" {
		t.Fatalf("purge of A changed tenant B audit rows:\nbefore=%s\nafter=%s", beforeB, afterB)
	}
	if err := execMigration(ctx, env.pool, string(rollback)); err == nil || !strings.Contains(err.Error(), "cannot roll back 0225") {
		t.Fatalf("irreversible schema rollback was not refused: %v", err)
	}
	request(http.MethodGet, "/export", http.StatusNotFound)
	request(http.MethodPost, "/restore", http.StatusNotFound)
	restored, err := pgxpool.New(ctx, os.Getenv("PAT2369_RESTORE_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	count(restored, "raw_payloads", a, 1)
	count(restored, "devices", a, 1)
	authenticate(restored, tokenA, true)
	t.Log("proved: revoke blocks credentials and retains evidence; export scoped; soft restore; credential revoke persists; purge preserves B; pre-offboarding pg_dump restore resurrects A and its credential")
}
