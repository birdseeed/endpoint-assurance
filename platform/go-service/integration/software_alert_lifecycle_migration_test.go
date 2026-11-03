//go:build integration

package integration

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"patched.im/api/internal/db"
)

// PAT-2097: 0184 on a seeded 0183 state, in a throwaway database. A policy
// that went Unapproved, then Approved, then Unapproved again before 0184 has
// two episodes; the older episode's rows must resolve as superseded, so
// every (policy, device) has at most one active alert. Then rollback and
// re-apply.
func TestSoftwareAlertLifecycleMigrationBackfill(t *testing.T) {
	ctx := context.Background()
	name := "pat2097_backfill_" + randomHex(4)
	if _, err := env.pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create scratch db: %v", err)
	}
	defer func() {
		if _, err := env.pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop scratch db: %v", err)
		}
	}()
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := db.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("connect scratch db: %v", err)
	}
	defer pool.Close()

	dir := filepath.Join("..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".sql") && !strings.HasSuffix(n, "_rollback.sql") && n < "0184" {
			files = append(files, n)
		}
	}
	sort.Strings(files)
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, f := range files {
		if err := execMigration(ctx, pool, read(f)); err != nil {
			t.Fatalf("apply %s: %v", f, err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, bearer_token_hash, hmac_secret)
		VALUES ('11111111-1111-1111-1111-111111111111', 'scratch', 'x', 'y');
		INSERT INTO devices (id, tenant_id, hostname, os) VALUES
		 ('22222222-2222-2222-2222-222222222221', '11111111-1111-1111-1111-111111111111', 'mac-1', 'macOS'),
		 ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'mac-2', 'macOS');
		INSERT INTO tenant_app_policies (id, tenant_id, bundle_id, platform, policy, enforcement_tier) VALUES
		 (9001, '11111111-1111-1111-1111-111111111111', 'com.bad.still', 'macos', 'unapproved', 'report'),
		 (9002, '11111111-1111-1111-1111-111111111111', 'com.bad.nowok', 'macos', 'approved', 'report');
		-- 9001: episode 1, then approved, then episode 4 (Unapproved again).
		INSERT INTO software_unapproved_episodes (id, tenant_id, policy_kind, policy_id, source, marked_at) VALUES
		 (1, '11111111-1111-1111-1111-111111111111', 'application', 9001, 'operator', now() - interval '2 days'),
		 (2, '11111111-1111-1111-1111-111111111111', 'application', 9002, 'operator', now()),
		 (3, '11111111-1111-1111-1111-111111111111', 'application', 9003, 'baseline', now()),
		 (4, '11111111-1111-1111-1111-111111111111', 'application', 9001, 'operator', now());
		INSERT INTO software_unapproved_alerts (id, tenant_id, episode_id, trigger, device_id, payload) VALUES
		 (1, '11111111-1111-1111-1111-111111111111', 1, 'marked', NULL,
		  '{"products":[{"product_key":"application:macos:com.other","name":"Other","devices":[{"device_id":"22222222-2222-2222-2222-222222222221"}]},{"product_key":"application:macos:com.bad.still","name":"Still Bad","devices":[{"device_id":"22222222-2222-2222-2222-222222222222"}]}]}'),
		 (2, '11111111-1111-1111-1111-111111111111', 2, 'observed', '22222222-2222-2222-2222-222222222221',
		  '{"products":[{"product_key":"application:macos:com.bad.nowok","name":"Now OK","devices":[]}]}'),
		 (3, '11111111-1111-1111-1111-111111111111', 4, 'marked', NULL,
		  '{"products":[{"product_key":"application:macos:com.bad.still","name":"Still Bad","devices":[]}]}');
		INSERT INTO software_unapproved_alerted_devices (episode_id, device_id, tenant_id, alert_id, suppressed_baseline) VALUES
		 (1, '22222222-2222-2222-2222-222222222221', '11111111-1111-1111-1111-111111111111', 1, false),
		 (1, '22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 1, false),
		 (2, '22222222-2222-2222-2222-222222222221', '11111111-1111-1111-1111-111111111111', 2, false),
		 (3, '22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', NULL, true),
		 (4, '22222222-2222-2222-2222-222222222221', '11111111-1111-1111-1111-111111111111', 3, false);
	`); err != nil {
		t.Fatalf("seed 0183 state: %v", err)
	}

	forward, rollback := read("0184_software_alert_lifecycle.sql"), read("0184_software_alert_lifecycle_rollback.sql")
	type row struct{ status, reason, evidence, productKey string }
	check := func(stage string) {
		t.Helper()
		want := map[[2]string]row{
			{"1", "22222222-2222-2222-2222-222222222221"}: {"resolved", "superseded", "superseded_episode", "application:macos:com.other"},
			{"1", "22222222-2222-2222-2222-222222222222"}: {"resolved", "superseded", "superseded_episode", "application:macos:com.bad.still"},
			{"2", "22222222-2222-2222-2222-222222222221"}: {"resolved", "approved", "policy_state", "application:macos:com.bad.nowok"},
			{"3", "22222222-2222-2222-2222-222222222222"}: {"resolved", "policy_removed", "policy_state", ""},
			{"4", "22222222-2222-2222-2222-222222222221"}: {"open", "", "", "application:macos:com.bad.still"},
		}
		rows, err := pool.Query(ctx, `
			SELECT ad.episode_id::text, ad.device_id::text, ad.status, COALESCE(ad.resolved_reason, ''),
			       COALESCE((SELECT t.detail->>'evidence' FROM software_unapproved_alert_transitions t
			                 WHERE t.alert_device_id = ad.id AND t.to_status = 'resolved'), ''),
			       COALESCE(ad.product->>'product_key', '')
			FROM software_unapproved_alerted_devices ad`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var ep, dev string
			var got row
			if err := rows.Scan(&ep, &dev, &got.status, &got.reason, &got.evidence, &got.productKey); err != nil {
				t.Fatal(err)
			}
			n++
			if w := want[[2]string{ep, dev}]; got != w {
				t.Errorf("%s: episode %s device %s = %+v, want %+v", stage, ep, dev, got, w)
			}
		}
		if n != len(want) {
			t.Fatalf("%s: %d rows, want %d", stage, n, len(want))
		}
		var dupes int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM (
				SELECT e.policy_kind, e.policy_id, ad.device_id FROM software_unapproved_alerted_devices ad
				JOIN software_unapproved_episodes e ON e.id = ad.episode_id
				WHERE ad.status IN ('open', 'acknowledged')
				GROUP BY 1, 2, 3 HAVING count(*) > 1) d`).Scan(&dupes); err != nil || dupes != 0 {
			t.Fatalf("%s: (policy, device) pairs with more than one active alert = %d %v", stage, dupes, err)
		}
	}

	if _, err := pool.Exec(ctx, forward); err != nil {
		t.Fatalf("apply 0184: %v", err)
	}
	check("apply")
	if _, err := pool.Exec(ctx, rollback); err != nil {
		t.Fatalf("rollback 0184: %v", err)
	}
	var cols, ledger int
	var gone bool
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.columns WHERE table_name = 'software_unapproved_alerted_devices'),
		(SELECT count(*) FROM software_unapproved_alerted_devices),
		to_regclass('software_unapproved_alert_transitions') IS NULL`).Scan(&cols, &ledger, &gone); err != nil {
		t.Fatal(err)
	}
	if cols != 6 || ledger != 5 || !gone {
		t.Fatalf("after rollback: columns %d (want 6), rows %d (want 5), transitions dropped %v", cols, ledger, gone)
	}
	if _, err := pool.Exec(ctx, forward); err != nil {
		t.Fatalf("re-apply 0184: %v", err)
	}
	check("re-apply")
}
