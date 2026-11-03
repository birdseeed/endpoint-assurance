//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// PAT-2380: a tenant purge must anonymise the retained software alert ledger
// (actor, note) for that tenant only, through the real admin purge endpoint,
// while keeping the ledger append-only for every other path. Synthetic data only.
func TestTenantPurgeRedactsSoftwareAlertLedger(t *testing.T) {
	ctx := context.Background()
	reportRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", reportRoot)
	mk := func(name string) string {
		t.Helper()
		id, _, _, err := createTestTenant(env.internalSrv.URL, name)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := mk("PAT-2380 disposable A")
	b := mk("PAT-2380 preserved B")
	c := mk("PAT-2380 failing-cleanup C")
	for _, tenant := range []string{a, b, c} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_alert_transitions
		(tenant_id, alert_device_id, episode_id, device_id, to_status, actor_kind, actor, note)
		VALUES ($1::uuid, 1, 1, gen_random_uuid(), 'open', 'portal_user', 'synthetic@example.test', 'synthetic identifying note')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(ctx, `INSERT INTO devices (tenant_id, serial, os) VALUES ($1::uuid, $1, 'macOS')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	rowsOf := func(tenant string) string {
		t.Helper()
		var rows string
		if err := env.pool.QueryRow(ctx, `SELECT coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY id), '') FROM software_unapproved_alert_transitions t WHERE tenant_id=$1::uuid`, tenant).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	shapeOf := func(tenant string) string {
		t.Helper()
		var shape string
		if err := env.pool.QueryRow(ctx, `SELECT coalesce(string_agg((to_jsonb(t)-'actor'-'note'-'tenant_purge_anonymized_at')::text, '|' ORDER BY id), '') FROM software_unapproved_alert_transitions t WHERE tenant_id=$1::uuid`, tenant).Scan(&shape); err != nil {
			t.Fatal(err)
		}
		return shape
	}
	request := func(tenant, method, suffix string, want int) string {
		t.Helper()
		req, err := http.NewRequest(method, env.internalSrv.URL+"/admin/tenants/"+tenant+suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, suffix, resp.StatusCode, want, body)
		}
		return string(body)
	}
	beforeShapeA, beforeB := shapeOf(a), rowsOf(b)
	if beforeB == "" || beforeShapeA == "" {
		t.Fatal("fixture rows missing")
	}

	// Ordinary mutation stays refused, even imitating the purge scope.
	for _, sql := range []string{
		`UPDATE software_unapproved_alert_transitions SET note=NULL WHERE tenant_id=$1::uuid`,
		`UPDATE software_unapproved_alert_transitions SET actor=NULL,note=NULL,tenant_purge_anonymized_at=transaction_timestamp() WHERE tenant_id=$1::uuid`,
		`DELETE FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`,
		`TRUNCATE software_unapproved_alert_transitions`,
		`INSERT INTO software_unapproved_alert_transitions (tenant_id,alert_device_id,episode_id,device_id,to_status,actor_kind,tenant_purge_anonymized_at) VALUES ($1::uuid,1,1,gen_random_uuid(),'open','portal_user',now())`,
	} {
		for _, role := range []string{"owner", "patched"} {
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
			var mutErr error
			if strings.HasPrefix(sql, "TRUNCATE") {
				_, mutErr = tx.Exec(ctx, sql)
			} else {
				_, mutErr = tx.Exec(ctx, sql, a)
			}
			if mutErr == nil {
				t.Errorf("ordinary mutation unexpectedly succeeded as %s: %s", role, sql)
			}
			_ = tx.Rollback(ctx)
		}
	}
	if shapeOf(a) != beforeShapeA || rowsOf(b) != beforeB {
		t.Fatal("refused mutations changed ledger rows")
	}

	request(a, http.MethodDelete, "", http.StatusOK) // disable before purge
	// Real purge.
	if body := request(a, http.MethodDelete, "/purge", http.StatusOK); !strings.Contains(body, `"purged":true`) {
		t.Fatalf("purge did not commit: %s", body)
	}
	var n int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id=$1::uuid`, a).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant A still present: %d %v", n, err)
	}
	var total, redacted int
	if err := env.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE actor IS NULL AND note IS NULL AND tenant_purge_anonymized_at IS NOT NULL) FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, a).Scan(&total, &redacted); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("purge deleted or duplicated A ledger rows: %d", total)
	}
	if redacted != total {
		t.Error("purged tenant retained actor email or note, or lacks the purge marker")
	}
	if shapeOf(a) != beforeShapeA {
		t.Error("purge changed non-identifying event fields")
	}
	if afterB := rowsOf(b); afterB != beforeB {
		t.Fatalf("purge of A changed tenant B rows:\nbefore=%s\nafter=%s", beforeB, afterB)
	}

	// Atomicity: force the redaction to fail for tenant C (a constraint that
	// rejects the NULL actor redaction writes); the purge must not commit.
	t.Run("failed redaction rolls back the purge", func(t *testing.T) {
		request(c, http.MethodDelete, "", http.StatusOK)
		constraint := "pat2380_force_cleanup_failure"
		if _, err := env.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE software_unapproved_alert_transitions
			ADD CONSTRAINT %s CHECK (tenant_id <> '%s'::uuid OR actor IS NOT NULL) NOT VALID`, constraint, c)); err != nil {
			t.Fatal(err)
		}
		dropped := false
		drop := func() {
			if dropped {
				return
			}
			dropped = true
			if _, err := env.pool.Exec(ctx, `ALTER TABLE software_unapproved_alert_transitions DROP CONSTRAINT `+constraint); err != nil {
				t.Fatal(err)
			}
		}
		defer drop()
		failed := request(c, http.MethodDelete, "/purge", http.StatusInternalServerError)
		if strings.Contains(failed, `"purged":true`) || !strings.Contains(failed, "precommit_failed_restored") {
			t.Fatalf("purge did not report a restored pre-commit failure: %s", failed)
		}
		drop()
		var tenantRows, deviceRows int
		if err := env.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM tenants WHERE id=$1::uuid), (SELECT count(*) FROM devices WHERE tenant_id=$1::uuid)`, c).Scan(&tenantRows, &deviceRows); err != nil || tenantRows != 1 || deviceRows != 1 {
			t.Fatalf("failed cleanup did not roll back the purge: tenants=%d devices=%d err=%v", tenantRows, deviceRows, err)
		}
		var actor string
		if err := env.pool.QueryRow(ctx, `SELECT actor FROM software_unapproved_alert_transitions WHERE tenant_id=$1::uuid`, c).Scan(&actor); err != nil || actor != "synthetic@example.test" {
			t.Fatalf("failed cleanup modified audit actor: %v %q", err, actor)
		}
	})
}
