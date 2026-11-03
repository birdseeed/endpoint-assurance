package handlers

// PAT-2071 DB-backed test for user_count on tagged Safari extension products.
//
// device_browser_extensions stores Safari app-extension rows (PAT-2064) under
// the fixed extractor.SafariSystemSentinel user_account, because a Safari
// extension lives in an app bundle rather than a browser user profile. Before
// this ticket fetchTaggedProducts counted that sentinel as a distinct user,
// so a Safari-only product showed one more user than it actually has. This
// inserts software_category_tags rows directly (bypassing the categorytag
// matching engine, which does not yet have a Safari store qualifier — a
// separate, later concern) to exercise fetchTaggedProducts' aggregation in
// isolation: one device reports the sentinel (the common Safari case), a
// second reports a real user_account (the rare case an agent does report
// one), and user_count must reflect only the real one.
//
// DB-backed: requires TEST_DATABASE_URL and is skipped otherwise, reusing
// pat1147BoundedPool/parSeedTenant/rrInsertDeviceOS (see posture_app_policy_db_test.go,
// allowlist_agent_known_path_test.go, ring_rollout_db_test.go).

import (
	"context"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
)

func TestFetchTaggedProducts_SafariExtension_UserCountExcludesSystemSentinel(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat2071-safari-usercount-tenant", "pat2071-safari-usercount-token", "pat2071-safari-usercount-hmac-sec32")
	dev1 := rrInsertDeviceOS(t, pool, tenantID, "88888888-1111-2222-3333-444444444401", 0, "macOS")
	dev2 := rrInsertDeviceOS(t, pool, tenantID, "88888888-1111-2222-3333-444444444402", 0, "macOS")

	extID := "com.pat2071.safariusercount." + time.Now().UTC().Format("20060102150405.000000000")

	// software_category_rules is global; a unique identifier_value keeps this
	// test isolated from any other rule in the shared schema. The rule is
	// inserted directly with a placeholder qualifier: the categorytag engine
	// has no Safari store qualifier yet (StoresForBrowser("safari") == nil),
	// so a real end-to-end ingest cannot produce this tag today. That is a
	// separate, later concern; this test targets fetchTaggedProducts' own
	// user_count aggregation given a tag that already exists.
	var ruleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO software_category_rules
		    (identifier_type, identifier_value, qualifier, platform, category_key, subtype_key, state, created_by, published_at)
		VALUES ('browser_extension', $1, 'chrome_web_store', 'any', 'ai_tooling', 'browser_extension', 'published', 'pat2071-test', now())
		RETURNING id
	`, extID).Scan(&ruleID); err != nil {
		t.Fatalf("insert category rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_category_rules WHERE id = $1`, ruleID)
	})

	// dev1: the common Safari case — empty user_account normalised to the
	// fixed sentinel by the extractor (PAT-2064). Inserted directly here with
	// the exported constant, so this test breaks if the sentinel ever changes
	// without this exclusion being updated to match.
	var extRowID1 int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_browser_extensions
		    (device_id, browser, extension_id, name, version, profile, user_account, permissions, risk_level)
		VALUES ($1::uuid, 'safari', $2, 'Pat2071 Safari Ext', '1.0', $3, $3, '[]'::jsonb, 'standard')
		RETURNING id
	`, dev1, extID, extractor.SafariSystemSentinel).Scan(&extRowID1); err != nil {
		t.Fatalf("insert safari extension row (sentinel): %v", err)
	}

	// dev2: the rare case where the agent does report a real user_account for
	// a Safari row. This must still be counted.
	var extRowID2 int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_browser_extensions
		    (device_id, browser, extension_id, name, version, profile, user_account, permissions, risk_level)
		VALUES ($1::uuid, 'safari', $2, 'Pat2071 Safari Ext', '1.0', 'Default', 'alice', '[]'::jsonb, 'standard')
		RETURNING id
	`, dev2, extID).Scan(&extRowID2); err != nil {
		t.Fatalf("insert safari extension row (real user): %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_browser_extensions WHERE id IN ($1, $2)`, extRowID1, extRowID2)
	})

	for _, row := range []struct {
		deviceID string
		extRowID int64
	}{{dev1, extRowID1}, {dev2, extRowID2}} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO software_category_tags
			    (tenant_id, device_id, observation_kind, browser_extension_id, rule_id)
			VALUES ($1::uuid, $2::uuid, 'browser_extension', $3, $4)
		`, tenantID, row.deviceID, row.extRowID, ruleID); err != nil {
			t.Fatalf("insert category tag for device %s: %v", row.deviceID, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_category_tags WHERE rule_id = $1`, ruleID)
	})

	products, tooLarge, err := fetchTaggedProducts(ctx, pool, tenantID, "ai_tooling", "browser_extension")
	if err != nil {
		t.Fatalf("fetchTaggedProducts: %v", err)
	}
	if tooLarge {
		t.Fatal("fetchTaggedProducts reported estate_too_large unexpectedly")
	}

	var found *portalTaggedProduct
	for i := range products {
		if products[i].Identifier == extID {
			found = &products[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("tagged product for %s not found in %+v", extID, products)
	}
	if found.DeviceCount != 2 {
		t.Errorf("device_count = %d, want 2", found.DeviceCount)
	}
	if found.UserCount == nil {
		t.Fatal("user_count is nil, want a count excluding the sentinel")
	}
	if *found.UserCount != 1 {
		t.Errorf("user_count = %d, want 1 (only 'alice'; the Safari system sentinel must not count as a user)", *found.UserCount)
	}
}
