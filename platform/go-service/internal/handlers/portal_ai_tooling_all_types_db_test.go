package handlers

// PAT-2206 exercises the authoritative all-types AI tooling projection against
// Postgres. It deliberately seeds the two non-tooling sources directly: the
// product tag is materialised server-side, while the app usage join has to be
// exact on the latest observed identifier/version and never on a display name.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/report"
)

func TestPortalAIToolingAllTypesContract(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := now.Format("150405.000000")
	tenantA := parSeedTenant(t, ctx, pool, "pat2206-a-"+suffix, "pat2206-a-token-"+suffix, "pat2206-a-hmac-secret-32-bytes!!")
	tenantB := parSeedTenant(t, ctx, pool, "pat2206-b-"+suffix, "pat2206-b-token-"+suffix, "pat2206-b-hmac-secret-32-bytes!!")
	devA := rrInsertDeviceOS(t, pool, tenantA, "22060000-0000-4000-8000-000000000001", 0, "macOS")
	devUnmetered := rrInsertDeviceOS(t, pool, tenantA, "22060000-0000-4000-8000-000000000002", 0, "macOS")
	devUnknown := rrInsertDeviceOS(t, pool, tenantA, "22060000-0000-4000-8000-000000000003", 0, "macOS")
	devStale := rrInsertDeviceOS(t, pool, tenantA, "22060000-0000-4000-8000-000000000004", 0, "macOS")
	devB := rrInsertDeviceOS(t, pool, tenantB, "22060000-0000-4000-8000-000000000005", 0, "macOS")
	email := "pat2206-" + strings.ReplaceAll(suffix, ".", "") + "@example.test"
	if _, err := pool.Exec(ctx, `INSERT INTO portal_users(email,tenant_id,role) VALUES($1,$2::uuid,'admin')`, email, tenantA); err != nil {
		t.Fatalf("seed portal user: %v", err)
	}

	identifier, version, team := "com.pat2206.ai."+strings.ReplaceAll(suffix, ".", ""), "1.2.3", "PAT2206ABC"
	var ruleID int64
	if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules
		(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at)
		VALUES('macos_bundle_id',$1,'','macos','ai_tooling','desktop_app','published','pat2206-test',now()) RETURNING id`, identifier).Scan(&ruleID); err != nil {
		t.Fatalf("insert desktop rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_category_tags WHERE rule_id IN (SELECT id FROM software_category_rules WHERE created_by='pat2206-test')`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_category_rules WHERE created_by='pat2206-test'`)
	})

	seedApp := func(deviceID string, at time.Time, status *string, usage *time.Time) string {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE devices SET metering_status=$2,last_seen=$3 WHERE id=$1::uuid`, deviceID, status, at); err != nil {
			t.Fatalf("set metering state: %v", err)
		}
		var runID string
		if err := pool.QueryRow(ctx, `INSERT INTO software_inventory_runs
			(tenant_id,device_id,platform,received_at,provenance,authoritative_scopes)
			VALUES($1::uuid,$2::uuid,'macos',$3,'backfill_current_snapshot','{}') RETURNING id::text`, tenantA, deviceID, at).Scan(&runID); err != nil {
			t.Fatalf("insert app run: %v", err)
		}
		fingerprint := pat2205Fingerprint("macos", "macos_bundle_team", identifier, team)
		var observationID int64
		if err := pool.QueryRow(ctx, `INSERT INTO software_observations
			(inventory_run_id,tenant_id,device_id,ordinal,platform,observed_name,observed_version,observed_identifier,observed_identifier_kind,observed_team_id,identity_kind,identity_value_normalized,companion_value_normalized,identity_confidence,identity_fingerprint,observed_at)
			VALUES($1::uuid,$2::uuid,$3::uuid,1,'macos','Pat2206 AI',$4,$5,'bundle_id',$6,'macos_bundle_team',$5,$6,'exact',$7,$8) RETURNING id`, runID, tenantA, deviceID, version, identifier, team, fingerprint, at).Scan(&observationID); err != nil {
			t.Fatalf("insert app observation: %v", err)
		}
		var installationID string
		if err := pool.QueryRow(ctx, `INSERT INTO software_installations
			(tenant_id,device_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,identity_fingerprint,current_name,current_version,first_seen_at,last_seen_at,latest_observation_id,provenance)
			VALUES($1::uuid,$2::uuid,'macos','macos_bundle_team',$3,$4,$5,'Pat2206 AI',$6,$7,$7,$8,'backfill_current_snapshot') RETURNING id::text`, tenantA, deviceID, identifier, team, fingerprint, version, at, observationID).Scan(&installationID); err != nil {
			t.Fatalf("insert app installation: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,installation_id,rule_id) VALUES($1::uuid,$2::uuid,'app',$3::uuid,$4)`, tenantA, deviceID, installationID, ruleID); err != nil {
			t.Fatalf("tag desktop app: %v", err)
		}
		if usage != nil || status != nil {
			if _, err := pool.Exec(ctx, `INSERT INTO device_apps(device_id,name,version,identifier,last_used_at,last_seen) VALUES($1::uuid,'Pat2206 AI',$2,$3,$4,$5)`, deviceID, version, identifier, usage, at); err != nil {
				t.Fatalf("insert app usage evidence: %v", err)
			}
		}
		return installationID
	}
	used := now.Add(-2 * time.Hour)
	statusOK, statusUnavailable := "ok", "spotlight_disabled"
	appInstallation := seedApp(devA, now, &statusOK, &used)
	seedApp(devUnmetered, now, &statusUnavailable, nil)
	seedApp(devUnknown, now, nil, nil)
	seedApp(devStale, now.Add(-31*24*time.Hour), &statusOK, nil)
	// A second published match for this same installation must not create a
	// duplicate report item or consume another entry from the fixed cap.
	var appDuplicateRule int64
	if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at) VALUES('macos_team_id',$1,$2,'macos','ai_tooling','desktop_app','published','pat2206-test',now()) RETURNING id`, team, identifier).Scan(&appDuplicateRule); err != nil {
		t.Fatalf("insert duplicate app match: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,installation_id,rule_id) VALUES($1::uuid,$2::uuid,'app',$3::uuid,$4)`, tenantA, devA, appInstallation, appDuplicateRule); err != nil {
		t.Fatalf("tag duplicate app match: %v", err)
	}
	// App-backed tags outside desktop_app have no launch-metering contract. They
	// must retain explicitly non-applicable fields rather than inheriting the
	// installation's desktop app usage evidence.
	var nonDesktopAppRule int64
	if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at) VALUES('macos_bundle_id',$1,'','macos','ai_tooling','cli','published','pat2206-test',now()) RETURNING id`, identifier).Scan(&nonDesktopAppRule); err != nil {
		t.Fatalf("insert non-desktop app rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,installation_id,rule_id) VALUES($1::uuid,$2::uuid,'app',$3::uuid,$4)`, tenantA, devA, appInstallation, nonDesktopAppRule); err != nil {
		t.Fatalf("tag non-desktop app: %v", err)
	}

	// An ambiguous normalised product must remain non-actionable even though
	// each individual report row can own an exact application target.
	var productID, aliasOne, aliasTwo string
	if err := pool.QueryRow(ctx, `INSERT INTO software_products(canonical_key,canonical_name) VALUES($1,'Pat2206 Ambiguous') RETURNING id::text`, "pat2206-ambiguous-"+strings.ReplaceAll(suffix, ".", "")).Scan(&productID); err != nil {
		t.Fatalf("insert ambiguous product: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_installations WHERE product_id=$1::uuid`, productID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_product_aliases WHERE product_id=$1::uuid`, productID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_products WHERE id=$1::uuid`, productID)
	})
	for i, out := range []*string{&aliasOne, &aliasTwo} {
		value := identifier + ".amb" + string(rune('a'+i))
		if err := pool.QueryRow(ctx, `INSERT INTO software_product_aliases(product_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,match_confidence,provenance) VALUES($1::uuid,'macos','macos_bundle',$2,'','exact','reviewed') RETURNING id::text`, productID, value).Scan(out); err != nil {
			t.Fatalf("insert ambiguous alias: %v", err)
		}
	}
	seedAmbiguous := func(deviceID, identity, aliasID string, ordinal int) {
		var runID string
		if err := pool.QueryRow(ctx, `INSERT INTO software_inventory_runs(tenant_id,device_id,platform,received_at,provenance,authoritative_scopes) VALUES($1::uuid,$2::uuid,'macos',$3,'backfill_current_snapshot','{}') ON CONFLICT(device_id) WHERE provenance='backfill_current_snapshot' DO UPDATE SET received_at=EXCLUDED.received_at RETURNING id::text`, tenantA, deviceID, now).Scan(&runID); err != nil {
			t.Fatalf("insert ambiguous run: %v", err)
		}
		fingerprint := pat2205Fingerprint("macos_bundle", identity)
		var obsID int64
		if err := pool.QueryRow(ctx, `INSERT INTO software_observations(inventory_run_id,tenant_id,device_id,ordinal,platform,observed_name,observed_version,observed_identifier,identity_kind,identity_value_normalized,companion_value_normalized,identity_confidence,identity_fingerprint,observed_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,'macos','Pat2206 Ambiguous','1',$5,'macos_bundle',$5,'','exact',$6,$7) RETURNING id`, runID, tenantA, deviceID, ordinal, identity, fingerprint, now).Scan(&obsID); err != nil {
			t.Fatalf("insert ambiguous observation: %v", err)
		}
		var installationID string
		if err := pool.QueryRow(ctx, `INSERT INTO software_installations(tenant_id,device_id,product_id,alias_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,identity_fingerprint,current_name,current_version,first_seen_at,last_seen_at,latest_observation_id,provenance,resolution_confidence) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,'macos','macos_bundle',$5,'',$6,'Pat2206 Ambiguous','1',$7,$7,$8,'backfill_current_snapshot','exact') RETURNING id::text`, tenantA, deviceID, productID, aliasID, identity, fingerprint, now, obsID).Scan(&installationID); err != nil {
			t.Fatalf("insert ambiguous installation: %v", err)
		}
		var appRule int64
		if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at) VALUES('macos_bundle_id',$1,'','macos','ai_tooling','desktop_app','published','pat2206-test',now()) RETURNING id`, identity).Scan(&appRule); err != nil {
			t.Fatalf("insert ambiguous rule: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,installation_id,rule_id) VALUES($1::uuid,$2::uuid,'app',$3::uuid,$4)`, tenantA, deviceID, installationID, appRule); err != nil {
			t.Fatalf("tag ambiguous app: %v", err)
		}
	}
	seedAmbiguous(devA, identifier+".amba", aliasOne, 2)
	seedAmbiguous(devUnmetered, identifier+".ambb", aliasTwo, 2)

	extID := "pat2206.extension." + strings.ReplaceAll(suffix, ".", "")
	var extensionID, extensionRule int64
	if err := pool.QueryRow(ctx, `INSERT INTO device_browser_extensions(device_id,browser,extension_id,name,version,profile,user_account,permissions,risk_level,last_seen) VALUES($1::uuid,'chrome',$2,'Pat2206 Extension','2.0','Default','alice','[]'::jsonb,'standard',$3) RETURNING id`, devA, extID, now).Scan(&extensionID); err != nil {
		t.Fatalf("insert extension: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at) VALUES('browser_extension',$1,'chrome_web_store','any','ai_tooling','browser_extension','published','pat2206-test',now()) RETURNING id`, extID).Scan(&extensionRule); err != nil {
		t.Fatalf("insert extension rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,browser_extension_id,rule_id) VALUES($1::uuid,$2::uuid,'browser_extension',$3,$4)`, tenantA, devA, extensionID, extensionRule); err != nil {
		t.Fatalf("tag extension: %v", err)
	}
	var extensionDuplicateRule int64
	if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at) VALUES('browser_extension',$1,'edge_addons','any','ai_tooling','browser_extension','published','pat2206-test',now()) RETURNING id`, extID).Scan(&extensionDuplicateRule); err != nil {
		t.Fatalf("insert duplicate extension match: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags(tenant_id,device_id,observation_kind,browser_extension_id,rule_id) VALUES($1::uuid,$2::uuid,'browser_extension',$3,$4)`, tenantA, devA, extensionID, extensionDuplicateRule); err != nil {
		t.Fatalf("tag duplicate extension match: %v", err)
	}
	// The observation's immutable platform, not a later device label, owns the
	// approval target. This deliberately inconsistent fixture catches a
	// projection that overwrites si.platform from devices.os.
	if _, err := pool.Exec(ctx, `UPDATE devices SET os='Windows' WHERE id=$1::uuid`, devA); err != nil {
		t.Fatalf("set mismatched device platform: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_app_policies(tenant_id,bundle_id,platform,policy,enforcement_tier)
		VALUES($1::uuid,$2,'macos','approved','report_deploy'),($1::uuid,$2,'windows','unapproved','report_deploy')`, tenantA, identifier); err != nil {
		t.Fatalf("seed conflicting platform policies: %v", err)
	}

	products, tooLarge, err := fetchTaggedProducts(ctx, pool, tenantA, "ai_tooling", "desktop_app")
	if err != nil || tooLarge {
		t.Fatalf("fetch tagged apps: tooLarge=%v err=%v", tooLarge, err)
	}
	var tagged, ambiguous *portalTaggedProduct
	for i := range products {
		if products[i].Identifier == identifier {
			tagged = &products[i]
		}
		if products[i].ProductKey == "product:"+productID {
			ambiguous = &products[i]
		}
	}
	if tagged == nil || tagged.DeviceCount != 4 || tagged.MeteredInstallationCount != 1 || tagged.UnmeteredInstallationCount != 1 || tagged.StaleMeteringInstallationCount != 1 || tagged.UnknownMeteringInstallationCount != 1 || tagged.MeteringState != "stale" || tagged.LastUsedAt != nil {
		t.Fatalf("tagged app metering = %+v", tagged)
	}
	if ambiguous == nil || ambiguous.ApprovalTarget != nil {
		t.Fatalf("ambiguous product target was guessed: %+v", ambiguous)
	}
	nonDesktopProducts, tooLarge, err := fetchTaggedProducts(ctx, pool, tenantA, "ai_tooling", "cli")
	if err != nil || tooLarge || len(nonDesktopProducts) != 1 {
		t.Fatalf("fetch non-desktop tagged app: products=%+v tooLarge=%v err=%v", nonDesktopProducts, tooLarge, err)
	}
	nonDesktop := nonDesktopProducts[0]
	if nonDesktop.MeteringState != "not_applicable" || nonDesktop.LastUsedAt != nil || nonDesktop.MeteredInstallationCount != 0 || nonDesktop.UnmeteredInstallationCount != 0 || nonDesktop.StaleMeteringInstallationCount != 0 || nonDesktop.UnknownMeteringInstallationCount != 0 {
		t.Fatalf("non-desktop app metering = %+v", nonDesktop)
	}

	rec := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA, "/v1/portal/ai-tooling/devices/"+devA+"/items?limit=100")
	if rec.Code != http.StatusOK {
		t.Fatalf("items status=%d body=%s", rec.Code, rec.Body.String())
	}
	var page report.ToolingEvidencePage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	var app, extension *report.ToolingEvidenceItem
	appRows, extensionRows := 0, 0
	for i := range page.Items {
		switch page.Items[i].EntryKind {
		case "application":
			if page.Items[i].Identity != identifier {
				continue
			}
			appRows++
			app = &page.Items[i]
		case "browser_extension":
			extensionRows++
			extension = &page.Items[i]
		}
	}
	if appRows != 1 || extensionRows != 1 || app == nil || app.Platform != "macos" || app.PolicyState != "approved" || app.MeteringState != "metered" || app.LastUsedAt == nil || !app.LastUsedAt.Equal(used) || app.ApprovalTarget == nil || app.ApprovalTarget.Platform == nil || *app.ApprovalTarget.Platform != "macos" || app.ApprovalTarget.Identifier == nil || *app.ApprovalTarget.Identifier != identifier {
		t.Fatalf("desktop app projection = %+v", app)
	}
	if extension == nil || extension.MeteringState != "not_applicable" || extension.ApprovalTarget == nil || extension.ApprovalTarget.ExtensionID == nil || *extension.ApprovalTarget.ExtensionID != extID {
		t.Fatalf("extension projection = %+v", extension)
	}
	csv := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA, "/v1/portal/ai-tooling/devices/"+devA+"/items?format=csv")
	if csv.Code != http.StatusOK || !strings.Contains(csv.Body.String(), "model_size_bytes,mcp_transport,mcp_runner,mcp_package,mcp_host") || !strings.Contains(csv.Body.String(), "metered") {
		t.Fatalf("CSV parity fields absent: status=%d body=%s", csv.Code, csv.Body.String())
	}
	foreign := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devB, "/v1/portal/ai-tooling/devices/"+devB+"/items")
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign device status=%d", foreign.Code)
	}

	// A complete report strictly after the extension's observation makes the
	// tag disappear. A tag alone cannot preserve a known-absent extension.
	if _, err := pool.Exec(ctx, `INSERT INTO browser_extension_device_state(device_id,tenant_id,collection_status,cap_reached,reported_at,last_complete_at) VALUES($1::uuid,$2::uuid,'complete',false,$3,$4)`, devA, tenantA, now.Add(time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatalf("seed extension absence authority: %v", err)
	}
	rep, err := report.BuildToolingEvidenceForDevice(ctx, pool, tenantA, devA, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("build after extension removal: %v", err)
	}
	for _, item := range rep.Items {
		if item.EntryKind == "browser_extension" && item.Identity == extID {
			t.Fatalf("authoritatively absent extension survived: %+v", item)
		}
	}
}
