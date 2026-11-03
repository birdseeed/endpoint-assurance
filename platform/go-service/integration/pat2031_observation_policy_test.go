//go:build integration

package integration

// PAT-2031 regression coverage for named tooling policy targets. These tests
// deliberately use the production extractor and Postgres projections: the
// relevant guarantees are about current-entry authority, historical rows and
// connection lifetimes, none of which a pure resolver test can establish.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
	"patched.im/api/internal/softwaregov"
)

func TestPAT2031TaggedToolingRequiresCurrentUnitAuthority(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2031-tag-authority-"+sfx)
	packageName := "pat2031-authority-" + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "package", "identifier_value": packageName, "qualifier": "npm",
		"category": "ai_tooling", "subtype": "cli",
	})
	publishCategoryRule(t, rule.ID)

	deviceID := postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx), func(m map[string]any) {
		packages := m["package_managers"].(map[string]any)["packages"].([]any)
		packages[0].(map[string]any)["name"] = packageName
	})
	if _, ok := findTagged(readTagged(t, tn, "?category=ai_tooling&subtype=cli"), packageName); !ok {
		t.Fatal("tagged npm package missing while its unit is authoritative")
	}

	// The installation and tag are intentionally retained. A failed npm unit
	// can no longer attest that the historical package is current, so it must
	// disappear from the current tagged-products read.
	if _, err := env.pool.Exec(context.Background(), `
		UPDATE tooling_device_state
		SET unit_statuses = jsonb_set(unit_statuses, '{npm_global}', '"failed"'::jsonb)
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND block = 'package_managers'`, tn.tenantID, deviceID); err != nil {
		t.Fatalf("withdraw npm unit authority: %v", err)
	}
	if _, ok := findTagged(readTagged(t, tn, "?category=ai_tooling&subtype=cli"), packageName); ok {
		t.Fatal("tagged npm package remained visible after its unit lost current authority")
	}
}

func TestPAT2031ToolingCoverageRequiresEveryAuthoritativeBlock(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2031-tooling-coverage-"+sfx)
	deviceID := postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx), nil)
	// The tooling fixture's app list is not the subject under test. Seed one
	// application projection explicitly so the assertion proves application
	// coverage stays independent from every tooling coverage state below.
	now := time.Now().UTC()
	govInstallation(t, tn.tenantID, deviceID, "macos", "macos_bundle", "im.patched.pat2031.coverage."+sfx, "", "PAT-2031 coverage", now, false)

	var originalUnits string
	if err := env.pool.QueryRow(ctx, `
		SELECT unit_statuses::text FROM tooling_device_state
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND block = 'mcp_servers'`, tn.tenantID, deviceID).Scan(&originalUnits); err != nil {
		t.Fatalf("read complete MCP state: %v", err)
	}
	check := func(wantUnavailable int, label string) {
		t.Helper()
		from := now.Add(-time.Hour)
		got, err := softwaregov.FetchNewSoftwareWindow(ctx, env.pool, tn.tenantID, from, time.Now().UTC().Add(time.Minute))
		if err != nil {
			t.Fatalf("%s: FetchNewSoftwareWindow: %v", label, err)
		}
		if got.Coverage.DevicesWithUnavailableTooling != wantUnavailable || got.Coverage.ToolingEvidenceComplete != (wantUnavailable == 0) {
			t.Fatalf("%s: tooling coverage = %+v, want unavailable=%d", label, got.Coverage, wantUnavailable)
		}
		if !got.Coverage.Complete {
			t.Fatalf("%s: tooling state changed application-only coverage: %+v", label, got.Coverage)
		}
		drift, err := softwaregov.FetchDrift(ctx, env.pool, tn.tenantID, time.Now().UTC())
		if err != nil {
			t.Fatalf("%s: FetchDrift: %v", label, err)
		}
		if drift.Coverage.DevicesWithUnavailableTooling != wantUnavailable ||
			drift.Coverage.ToolingEvidenceComplete != (wantUnavailable == 0) {
			t.Fatalf("%s: drift tooling coverage = %+v, want unavailable=%d", label, drift.Coverage, wantUnavailable)
		}
		if !drift.Coverage.Complete {
			t.Fatalf("%s: tooling state changed drift application-only coverage: %+v", label, drift.Coverage)
		}
		if drift.Coverage.DevicesWithUnavailableTooling != got.Coverage.DevicesWithUnavailableTooling ||
			drift.Coverage.ToolingEvidenceComplete != got.Coverage.ToolingEvidenceComplete ||
			drift.Coverage.Complete != got.Coverage.Complete {
			t.Fatalf("%s: new-software coverage %+v differs from drift coverage %+v", label, got.Coverage, drift.Coverage)
		}
	}
	setMCP := func(status string, truncated bool, units string) {
		t.Helper()
		if _, err := env.pool.Exec(ctx, `
			UPDATE tooling_device_state SET collection_status = $3, truncated = $4, unit_statuses = $5::jsonb
			WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND block = 'mcp_servers'`,
			tn.tenantID, deviceID, status, truncated, units); err != nil {
			t.Fatalf("set MCP state: %v", err)
		}
	}

	// complete and not_present establish absence. Partial, failed, truncation
	// and a failed unit do not. The fourth block is then deleted to exercise
	// the genuinely missing-state path rather than treating it as not_present.
	setMCP("complete", false, originalUnits)
	check(0, "complete")
	setMCP("not_present", false, originalUnits)
	check(0, "not_present")
	setMCP("partial", false, originalUnits)
	check(1, "partial")
	setMCP("failed", false, originalUnits)
	check(1, "failed")
	setMCP("complete", true, originalUnits)
	check(1, "truncated")
	var failedUnits string
	if err := env.pool.QueryRow(ctx, `SELECT jsonb_set($1::jsonb, '{cursor}', '"failed"'::jsonb)::text`, originalUnits).Scan(&failedUnits); err != nil {
		t.Fatalf("build failed-unit state: %v", err)
	}
	setMCP("complete", false, failedUnits)
	check(1, "unit failure")
	if _, err := env.pool.Exec(ctx, `DELETE FROM tooling_device_state WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND block = 'mcp_servers'`, tn.tenantID, deviceID); err != nil {
		t.Fatalf("delete MCP state: %v", err)
	}
	check(1, "missing block")
}

func TestPAT2031ToolingHistoricalFirstSeenAndFirstDevice(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2031-tooling-history-"+sfx)
	oldDevice := postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx), nil)

	var name, source string
	if err := env.pool.QueryRow(ctx, `
		SELECT identity_value_normalized, companion_value_normalized
		FROM software_installations
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND identity_kind = 'npm_package'
		ORDER BY identity_value_normalized LIMIT 1`, tn.tenantID, oldDevice).Scan(&name, &source); err != nil {
		t.Fatalf("find historical npm identity: %v", err)
	}
	historical := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if _, err := env.pool.Exec(ctx, `
		UPDATE software_installations
		SET first_seen_at = $4::timestamptz, last_seen_at = $4::timestamptz, removed_at = $4::timestamptz + interval '1 day'
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND identity_kind = 'npm_package'
		  AND identity_value_normalized = $3`, tn.tenantID, oldDevice, name, historical); err != nil {
		t.Fatalf("make first npm installation historical: %v", err)
	}
	// Same immutable identity on a new device is a reappearance, not new
	// software. The old device remains the historical first device and is no
	// longer installed, which must be stated truthfully on a wider review.
	postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx+"b"), nil)

	wide, err := softwaregov.FetchNewSoftwareWindow(ctx, env.pool, tn.tenantID, historical.Add(-time.Hour), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("wide tooling review: %v", err)
	}
	var target *softwaregov.NewProduct
	for i := range wide.Products {
		p := &wide.Products[i]
		if p.Type == softwaregov.TypeObservation && p.ObservationKind == "npm_package" && p.Identifier == name && p.ObservationSource == source {
			target = p
			break
		}
	}
	if target == nil {
		t.Fatalf("wide review omitted historical npm identity %q/%q", name, source)
	}
	if target.FirstDevice.DeviceID != oldDevice || target.FirstDevice.StillInstalled {
		t.Fatalf("historical first device = %+v, want removed old device %s", target.FirstDevice, oldDevice)
	}

	narrow, err := softwaregov.FetchNewSoftwareWindow(ctx, env.pool, tn.tenantID, historical.Add(2*24*time.Hour), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("narrow tooling review: %v", err)
	}
	for _, p := range narrow.Products {
		if p.Type == softwaregov.TypeObservation && p.ObservationKind == "npm_package" && p.Identifier == name && p.ObservationSource == source {
			t.Fatalf("historical tooling reappearance was called new: %+v", p)
		}
	}
}

func TestPAT2031HomebrewCaskPageWorksWithOnePoolConnection(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2031-cask-pool-"+sfx)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	serial := "PAT2031-CASK-" + sfx
	postInventoryAs(t, bearer, secret, homebrewPayload(t, serial, "pat2031-cask-"+sfx, func(hb map[string]any) {
		casks := hb["casks"].([]any)
		second := map[string]any{
			"prefix": "/opt/homebrew", "token": "firefox-second-" + sfx, "version": "143.0",
			"versions_on_disk": []any{"143.0"}, "tap": "homebrew/cask", "installed_on_request": true,
			"installed_at": "2026-09-10T08:00:00Z", "receipt_status": "read",
			// Both casks deliberately link to the same installed bundle. The
			// resolver must batch page links, not allocate a connection per cask.
			"apps": []any{map[string]any{"name": "Firefox.app", "path": nil, "exists": nil}},
		}
		hb["casks"] = append(casks, second)
		prefix := hb["prefixes"].([]any)[0].(map[string]any)
		prefix["casks"] = 2
	}))

	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("parse test database config: %v", err)
	}
	cfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open one-connection pool: %v", err)
	}
	defer one.Close()
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	page, err := report.FetchHomebrewCasks(deadline, one, tenantID, "", 20, 0)
	if err != nil {
		t.Fatalf("one-connection cask page: %v", err)
	}
	if len(page.Casks) != 2 || page.Total != 2 {
		t.Fatalf("cask page = %+v, want two linked casks", page)
	}
	for _, c := range page.Casks {
		if c.LinkedAppDeviceCount != 1 {
			t.Fatalf("cask %q linked-app device count = %d, want 1", c.Token, c.LinkedAppDeviceCount)
		}
	}
}

func TestPAT2031CaskLinkUpdateDirtiesOldAndNewPairs(t *testing.T) {
	ctx := context.Background()
	g := newGovTenant(t, "pat2031-cask-link", "")
	oldDevice := govDevice(t, g.id, "pat2031-old-cask", "macOS", time.Now())
	newDevice := govDevice(t, g.id, "pat2031-new-cask", "macOS", time.Now())
	seedPair := func(deviceID, suffix string) (string, string) {
		t.Helper()
		at := time.Now().UTC()
		govInstallation(t, g.id, deviceID, "macos", "homebrew_cask", "pat2031-cask-"+suffix, "homebrew/cask", "PAT-2031 cask "+suffix, at, false)
		govInstallation(t, g.id, deviceID, "macos", "macos_bundle", "im.patched.pat2031."+suffix, "", "PAT-2031 app "+suffix, at, false)
		var caskID, appID string
		if err := env.pool.QueryRow(ctx, `SELECT id::text FROM software_installations WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND identity_kind='homebrew_cask'`, g.id, deviceID).Scan(&caskID); err != nil {
			t.Fatalf("find %s cask: %v", suffix, err)
		}
		if err := env.pool.QueryRow(ctx, `SELECT id::text FROM software_installations WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND identity_kind='macos_bundle'`, g.id, deviceID).Scan(&appID); err != nil {
			t.Fatalf("find %s app: %v", suffix, err)
		}
		return caskID, appID
	}
	oldCask, oldApp := seedPair(oldDevice, "old")
	newCask, newApp := seedPair(newDevice, "new")
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO homebrew_cask_app_links (tenant_id, device_id, cask_installation_id, app_installation_id, app_path, link_basis, linked_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, '/Applications/PAT-2031.app', 'reported_path', now())`,
		g.id, oldDevice, oldCask, oldApp); err != nil {
		t.Fatalf("insert old cask link: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `DELETE FROM software_unapproved_presence_dirty WHERE device_id IN ($1::uuid, $2::uuid)`, oldDevice, newDevice); err != nil {
		t.Fatalf("clear setup dirtiness: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		UPDATE homebrew_cask_app_links
		SET device_id = $5::uuid, cask_installation_id = $3::uuid, app_installation_id = $4::uuid
		WHERE cask_installation_id = $1::uuid AND app_installation_id = $2::uuid`, oldCask, oldApp, newCask, newApp, newDevice); err != nil {
		t.Fatalf("move cask link to new pair: %v", err)
	}
	var dirty int
	if err := env.pool.QueryRow(ctx, `SELECT count(*)::int FROM software_unapproved_presence_dirty WHERE device_id IN ($1::uuid, $2::uuid)`, oldDevice, newDevice).Scan(&dirty); err != nil {
		t.Fatalf("read dirty markers: %v", err)
	}
	if dirty != 2 {
		t.Fatalf("cask-link update dirtied %d devices, want both old and new pairs", dirty)
	}
}

func TestPAT2031UrgencyApplicationNotCrowdedOutByTooling(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newUrgencyTenant(t, "pat2031-urgency-"+sfx)
	appName := "PAT-2031 urgency application " + sfx
	appIdentifier := "im.patched.pat2031.urgency." + sfx
	postUrgencyInventory(t, tn, "full.json", newHW(sfx), []map[string]any{
		urgMacApp(appName, appIdentifier, "1.0", "", "", false),
	})
	toolingTenant := cveTestTenant{tenantID: tn.id, bearer: tn.bearer, hmacSecret: tn.secret}
	toolDevice := postTooling(t, toolingTenant, "with-tooling-complete-macos.json", newHW(sfx+"t"), nil)
	var runID string
	if err := env.pool.QueryRow(ctx, `
		SELECT inventory_run_id::text FROM tooling_current_entries
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid LIMIT 1`, tn.id, toolDevice).Scan(&runID); err != nil {
		t.Fatalf("find tooling inventory run: %v", err)
	}
	// More than the full-review cap of newer named identities must never
	// consume any of the application-only urgency candidates.
	const added = softwaregov.MaxNewSoftwareProducts + 1
	if _, err := env.pool.Exec(ctx, `
		WITH nums AS (SELECT n, lpad(to_hex(n), 64, '0') AS fp FROM generate_series(1, $4::int) AS n),
		obs AS (
			INSERT INTO software_observations
			    (inventory_run_id, tenant_id, device_id, ordinal, platform, observed_name,
			     identity_kind, identity_value_normalized, companion_value_normalized,
			     identity_confidence, identity_fingerprint, observed_at)
			SELECT $3::uuid, $1::uuid, $2::uuid, 1000000+n, 'macos', 'PAT-2031 tooling ' || n,
			       'npm_package', 'pat2031-tooling-' || n, '', 'exact', fp, now()
			FROM nums
			RETURNING id, identity_fingerprint, identity_value_normalized
		), inst AS (
			INSERT INTO software_installations
			    (tenant_id, device_id, platform, identity_kind, identity_value_normalized,
			     companion_value_normalized, identity_fingerprint, current_name, first_seen_at,
			     last_seen_at, latest_observation_id, provenance)
			SELECT $1::uuid, $2::uuid, 'macos', 'npm_package', identity_value_normalized,
			       '', identity_fingerprint, identity_value_normalized, now(), now(), id, 'inventory_payload'
			FROM obs
		)
		INSERT INTO tooling_current_entries
		    (device_id, tenant_id, block, unit, entry_kind, entry_key, observation_id, observed_at, inventory_run_id)
		SELECT $2::uuid, $1::uuid, 'package_managers', 'npm_global', 'package', identity_fingerprint, id, now(), $3::uuid
		FROM obs`, tn.id, toolDevice, runID, added); err != nil {
		t.Fatalf("seed %d newer tooling identities: %v", added, err)
	}
	got, err := softwaregov.FetchNewSoftwareUrgency(ctx, env.pool, tn.id, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("fetch application urgency: %v", err)
	}
	found := false
	for _, p := range got.Products {
		if p.Name == appName {
			found = true
		}
	}
	if !found {
		t.Fatalf("application urgency was displaced by tooling: total=%d products=%s", got.Total, fmt.Sprintf("%+v", got.Products))
	}
}

func TestPAT2031ObservationApprovalLifecycleEndToEnd(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	primary := newCVETestTenant(t, "pat2031-observation-policy-"+sfx)
	other := newCVETestTenant(t, "pat2031-observation-policy-other-"+sfx)
	adminEmail := "pat2031-observation-admin-" + sfx + "@approvals.example"
	if got := mapPortalUserWithRole(t, adminEmail, primary.tenantID, "admin"); got.Role != "admin" {
		t.Fatalf("primary admin role = %q, want admin", got.Role)
	}
	adminToken := env.idp.token(t, adminEmail)
	packageName := "pat2031-observation-" + sfx
	from := time.Now().UTC().Add(-time.Hour)
	mutatePackage := func(m map[string]any) {
		packages := m["package_managers"].(map[string]any)["packages"].([]any)
		packages[0].(map[string]any)["name"] = packageName
	}
	primaryDevice := postTooling(t, primary, "with-tooling-complete-macos.json", newHW(sfx), mutatePackage)
	postTooling(t, other, "with-tooling-complete-macos.json", newHW(sfx+"other"), mutatePackage)

	// Capture the actual normalised PAT-2021 tooling identity. The policy is
	// keyed on these three fields, rather than a display label or package rule.
	var kind, name, source string
	if err := env.pool.QueryRow(ctx, `
		SELECT identity_kind, identity_value_normalized, companion_value_normalized
		FROM software_installations
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND identity_value_normalized = $3
		ORDER BY id LIMIT 1`, primary.tenantID, primaryDevice, packageName).Scan(&kind, &name, &source); err != nil {
		t.Fatalf("read live named tooling observation: %v", err)
	}
	if kind != "npm_package" || name != packageName || source != "" {
		t.Fatalf("normalised observation = %q/%q/%q, want npm_package/%q/empty-source", kind, name, source, packageName)
	}
	key := softwaregov.ObservationKey(kind, name, source)
	item := fmt.Sprintf(`{"type":"observation","identity_kind":%q,"name":%q,"source":%q}`, kind, name, source)

	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "package", "identifier_value": name, "qualifier": "npm",
		"category": "ai_tooling", "subtype": "cli",
	})
	publishCategoryRule(t, rule.ID)
	if p, ok := findTagged(readTagged(t, primary, "?category=ai_tooling&subtype=cli"), name); !ok || p.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("primary tagged observation before policy = %+v, found=%v", p, ok)
	}

	reason := "PAT-2031 live named observation review"
	write := mustApprove(t, adminToken, approvalBody("unapproved", reason, item))
	if write.ChangedCount != 1 || len(write.Results) != 1 || !write.Results[0].Changed ||
		write.Results[0].ProductKey != key || write.Results[0].PreviousState != softwaregov.StateUnreviewed ||
		write.Results[0].NewState != softwaregov.StateUnapproved {
		t.Fatalf("unapproved observation write = %+v", write)
	}

	var policy, notes string
	if err := env.pool.QueryRow(ctx, `
		SELECT policy, notes FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid AND identity_kind = $2 AND name = $3 AND source = $4`,
		primary.tenantID, kind, name, source).Scan(&policy, &notes); err != nil {
		t.Fatalf("read exact observation policy key: %v", err)
	}
	if policy != "unapproved" || notes != reason {
		t.Fatalf("observation policy = %q/%q, want unapproved/%q", policy, notes, reason)
	}

	type observationAudit struct {
		ProductType, ProductKey, Kind, Source, Previous, Next, Actor string
		Reason                                                       *string
	}
	audits := func() []observationAudit {
		t.Helper()
		rows, err := env.pool.Query(ctx, `
			SELECT product_type, product_key, observation_kind, observation_source,
			       previous_state, new_state, actor_email, reason
			FROM software_approval_decisions
			WHERE tenant_id = $1::uuid
			ORDER BY id`, primary.tenantID)
		if err != nil {
			t.Fatalf("query observation audit: %v", err)
		}
		defer rows.Close()
		var out []observationAudit
		for rows.Next() {
			var row observationAudit
			if err := rows.Scan(&row.ProductType, &row.ProductKey, &row.Kind, &row.Source,
				&row.Previous, &row.Next, &row.Actor, &row.Reason); err != nil {
				t.Fatalf("scan observation audit: %v", err)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate observation audit: %v", err)
		}
		return out
	}
	assertAudit := func(rows []observationAudit, wantPrevious, wantNext string) {
		t.Helper()
		if len(rows) == 0 {
			t.Fatal("observation decision audit is empty")
		}
		got := rows[len(rows)-1]
		if got.ProductType != softwaregov.TypeObservation || got.ProductKey != key || got.Kind != kind || got.Source != source ||
			got.Previous != wantPrevious || got.Next != wantNext || got.Actor != adminEmail || got.Reason == nil || *got.Reason != reason {
			t.Fatalf("observation audit = %+v, want key/kind/source and %s -> %s", got, wantPrevious, wantNext)
		}
	}
	assertAudit(audits(), softwaregov.StateUnreviewed, softwaregov.StateUnapproved)

	findNew := func(out softwaregov.NewSoftware) *softwaregov.NewProduct {
		for i := range out.Products {
			p := &out.Products[i]
			if p.Type == softwaregov.TypeObservation && p.ProductKey != nil && *p.ProductKey == key {
				return p
			}
		}
		return nil
	}
	newPath := "/v1/portal/software/new?since=" + url.QueryEscape(from.Format(time.RFC3339))
	var newPrimary softwaregov.NewSoftware
	getJSON(t, newPath, primary.token, &newPrimary)
	if p := findNew(newPrimary); p == nil || p.ApprovalState != softwaregov.StateUnapproved ||
		p.ObservationKind != kind || p.Identifier != name || p.ObservationSource != source {
		t.Fatalf("new-software observation after unapproved policy = %+v", p)
	}
	if p, ok := findTagged(readTagged(t, primary, "?category=ai_tooling&subtype=cli"), name); !ok ||
		p.ApprovalState != softwaregov.StateUnapproved {
		t.Fatalf("tagged observation after unapproved policy = %+v, found=%v", p, ok)
	}
	drift, err := softwaregov.FetchDrift(ctx, env.pool, primary.tenantID, time.Now().UTC())
	if err != nil {
		t.Fatalf("FetchDrift after unapproved policy: %v", err)
	}
	var driftProduct *softwaregov.DriftProduct
	for i := range drift.Products {
		if drift.Products[i].ProductKey == key {
			driftProduct = &drift.Products[i]
			break
		}
	}
	if driftProduct == nil || driftProduct.ApprovalState != softwaregov.StateUnapproved ||
		driftProduct.ObservationKind != kind || driftProduct.Identifier != name || driftProduct.ObservationSource != source {
		t.Fatalf("drift observation after unapproved policy = %+v", driftProduct)
	}
	present := false
	for _, p := range drift.UnapprovedPresent {
		if p.ProductKey == key && p.PolicyKind == softwaregov.TypeObservation && p.DeviceCount == 1 {
			present = true
		}
	}
	if !present {
		t.Fatalf("unapproved observation missing from present list: %+v", drift.UnapprovedPresent)
	}
	approved, err := softwaregov.FetchApproved(ctx, env.pool, primary.tenantID, time.Now().UTC())
	if err != nil {
		t.Fatalf("FetchApproved after unapproved policy: %v", err)
	}
	for _, p := range approved.Products {
		if p.ProductKey != nil && *p.ProductKey == key {
			t.Fatalf("unapproved observation leaked into approved list: %+v", p)
		}
	}

	// Same observation identity in a second tenant remains unreviewed: both
	// policy lookup and every portal projection are tenant-scoped.
	var otherPolicies int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*)::int FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid AND identity_kind = $2 AND name = $3 AND source = $4`,
		other.tenantID, kind, name, source).Scan(&otherPolicies); err != nil {
		t.Fatalf("read other tenant observation policies: %v", err)
	}
	if otherPolicies != 0 {
		t.Fatalf("other tenant inherited %d observation policies", otherPolicies)
	}
	var newOther softwaregov.NewSoftware
	getJSON(t, newPath, other.token, &newOther)
	if p := findNew(newOther); p == nil || p.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("other tenant new-software observation = %+v", p)
	}
	if p, ok := findTagged(readTagged(t, other, "?category=ai_tooling&subtype=cli"), name); !ok || p.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("other tenant tagged observation = %+v, found=%v", p, ok)
	}

	// Repeating the same state is a no-op: it neither changes policy nor
	// appends a misleading decision-history row.
	noOp := mustApprove(t, adminToken, approvalBody("unapproved", reason, item))
	if noOp.ChangedCount != 0 || len(noOp.Results) != 1 || noOp.Results[0].Changed {
		t.Fatalf("same-state observation write = %+v, want no-op", noOp)
	}
	if rows := audits(); len(rows) != 1 {
		t.Fatalf("same-state observation write appended audit rows: %+v", rows)
	}

	reset := mustApprove(t, adminToken, approvalBody("unreviewed", reason, item))
	if reset.ChangedCount != 1 || len(reset.Results) != 1 || !reset.Results[0].Changed ||
		reset.Results[0].PreviousState != softwaregov.StateUnapproved || reset.Results[0].NewState != softwaregov.StateUnreviewed {
		t.Fatalf("unreview observation write = %+v", reset)
	}
	var remaining int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*)::int FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid AND identity_kind = $2 AND name = $3 AND source = $4`,
		primary.tenantID, kind, name, source).Scan(&remaining); err != nil {
		t.Fatalf("count policies after unreview: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("unreviewed observation retained %d policy rows", remaining)
	}
	rows := audits()
	if len(rows) != 2 {
		t.Fatalf("observation audit history = %+v, want two append-only decisions", rows)
	}
	assertAudit(rows[:1], softwaregov.StateUnreviewed, softwaregov.StateUnapproved)
	assertAudit(rows[1:], softwaregov.StateUnapproved, softwaregov.StateUnreviewed)

	getJSON(t, newPath, primary.token, &newPrimary)
	if p := findNew(newPrimary); p == nil || p.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("new-software observation after unreview = %+v", p)
	}
	if p, ok := findTagged(readTagged(t, primary, "?category=ai_tooling&subtype=cli"), name); !ok || p.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("tagged observation after unreview = %+v, found=%v", p, ok)
	}
	drift, err = softwaregov.FetchDrift(ctx, env.pool, primary.tenantID, time.Now().UTC())
	if err != nil {
		t.Fatalf("FetchDrift after unreview: %v", err)
	}
	driftProduct = nil
	for i := range drift.Products {
		if drift.Products[i].ProductKey == key {
			driftProduct = &drift.Products[i]
			break
		}
	}
	if driftProduct == nil || driftProduct.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("drift observation after unreview = %+v", driftProduct)
	}
	for _, p := range drift.UnapprovedPresent {
		if p.ProductKey == key {
			t.Fatalf("unreviewed observation remained present as unapproved: %+v", p)
		}
	}
}
