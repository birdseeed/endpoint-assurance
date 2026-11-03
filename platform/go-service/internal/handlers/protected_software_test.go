package handlers

// PAT-1801 DB-backed tests: protected software list enforcement.
//
// Covers:
//   - PAT-2088: a baseline-protected product marked unapproved via
//     TenantAppPoliciesPutHandler is written with a protected warning, the
//     same rule the customer portal applies (protected_unapproved.go); it
//     was refused with 409 before
//   - a non-matching product is NOT treated as protected (fail-closed does
//     not mean over-protecting)
//   - a tenant can freely add its own protection, and that addition is
//     enforced the same way as a baseline row
//   - the audited baseline-override-remove path re-permits the write it was
//     blocking, and records the override + the reason
//   - CVE findings still surface for a protected product — protection is
//     disposition-only, this package/handler never touches the CVE pipeline
//
// PAT-1822 adds direct protectedsoftware.Check DB-integration coverage for
// checkStrong's SQL (bundle_id, signer distinct from team_id, and
// win_publisher+win_product_code together, plus the both-required rule) —
// see the block near the end of this file.
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, reusing
// catConnectOrSkip / catSeedTenant / catWithTenantID (db_test_helpers_test.go)
// rather than inventing new helpers, matching the app_policies_tier_test.go
// convention in this package. Requires migration 0139 to have been applied
// (baseline seed rows included) — like every other DB-gated test here, it
// assumes the target database is already fully migrated.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/notify"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/protectedsoftware"
)

// psWithParams injects both tenantID and baselineID chi URL params, for the
// override-remove route which needs both.
func psWithParams(r *http.Request, tenantID, baselineID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	if baselineID != "" {
		rctx.URLParams.Add("baselineID", baselineID)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// protectedPutResp is the wire shape of the operator PUT response's PAT-2088
// fields, decoded independently of the handler's own type.
type protectedPutResp struct {
	Policy           string `json:"policy"`
	ProtectedWarning bool   `json:"protected_warning"`
	Protected        *struct {
		Category    string `json:"category"`
		Vendor      string `json:"vendor"`
		ProductName string `json:"product_name"`
	} `json:"protected"`
}

// Observed package/display evidence is useful for governance warnings but
// cannot be recast as an MSI ProductCode or an executable identity.
func TestProtectedMatchForAppObservedIdentity(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2088-observed-identity")
	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, hw_uuid)
		VALUES ($1::uuid, 'Windows', gen_random_uuid()) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO protected_software
		(tenant_id, category, vendor, product_name, process_name, win_publisher, win_product_code, team_id)
		VALUES ($1::uuid, 'customer_defined', 'Example', 'Protected Product', 'agent.exe',
		        'Example Publisher', 'Example.Agent', 'TEAMPROTECTED')`, tenantID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{{"Protected Product", true}, {"agent.exe", false}, {"Unrelated Product", false}} {
		match, err := protectedMatchForApp(ctx, tx, tenantID, appProtectionIdentity{Platform: "any", Name: &tc.name})
		if err != nil || (match != nil) != tc.want {
			t.Fatalf("name-only %q: match=%+v err=%v, want protected=%v", tc.name, match, err, tc.want)
		}
	}
	for i, tc := range []struct {
		name, platform, kind, identifier, display, companion string
		want                                                 bool
	}{
		{"display is not executable", "windows", "windows_winget", "Example.Process", "agent.exe", "", false},
		{"winget is not MSI code", "windows", "windows_winget", "Example.Agent", "Unrelated Product", "", false},
		{"protected display product still warned", "windows", "windows_winget", "Example.Protected", "Protected Product", "", true},
		{"failed strong bundle never falls back to display", "macos", "macos_bundle", "com.example.other", "Protected Product", "", false},
		{"observed signing team retained", "macos", "macos_bundle_team", "com.example.security", "Security", "TEAMPROTECTED", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `INSERT INTO software_installations
				(tenant_id, device_id, platform, identity_kind, identity_value_normalized,
				 companion_value_normalized, identity_fingerprint, current_name, current_publisher,
				 first_seen_at, last_seen_at, provenance)
				VALUES ($1::uuid, $2::uuid, $3, $4, lower($5), $6, $7, $8, 'Example Publisher',
				        now(), now(), 'backfill_current_snapshot')`,
				tenantID, deviceID, tc.platform, tc.kind, tc.identifier, tc.companion,
				fmt.Sprintf("%064x", i+1), tc.display); err != nil {
				t.Fatal(err)
			}
			match, err := protectedMatchForApp(ctx, tx, tenantID, appProtectionIdentity{
				Platform: tc.platform, BundleID: &tc.identifier,
			})
			if err != nil {
				t.Fatal(err)
			}
			if (match != nil) != tc.want {
				t.Fatalf("match=%+v, want protected=%v", match, tc.want)
			}
		})
	}
}

// protectedPut runs one operator app-policy PUT and decodes the PAT-2088
// warning fields.
func protectedPut(t *testing.T, h http.HandlerFunc, tenantID, body string) (int, protectedPutResp, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	var resp protectedPutResp
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode PUT response: %v: %s", err, w.Body.String())
		}
	}
	return w.Code, resp, w.Body.String()
}

// TestAppPoliciesPutWarnsAndAllowsBaselineProtectedSoftware proves PAT-2088's
// warn-and-allow on the operator path: a product matching a shared baseline
// protected_software row by name/process fallback (CrowdStrike Falcon Sensor
// has no team_id/bundle_id in the seed — win_publisher +
// process_name/product_name only) is written, and the response names the
// protection, as the portal's does.
func TestAppPoliciesPutWarnsAndAllowsBaselineProtectedSoftware(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1801-baseline-edr-tenant")
	h := TenantAppPoliciesPutHandler(pool, notify.New())

	body := `{"name":"CrowdStrike Falcon Sensor","platform":"any","policy":"unapproved"}`
	code, resp, raw := protectedPut(t, h, tenantID, body)
	if code != http.StatusOK {
		t.Fatalf("want 200 (warn and allow) for protected EDR, got %d: %s", code, raw)
	}
	if !resp.ProtectedWarning || resp.Protected == nil || resp.Protected.Category != "edr" || resp.Policy != "unapproved" {
		t.Fatalf("response lacks the protected warning: %s", raw)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND policy='unapproved'`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("protected unapproved write did not land: count=%d", count)
	}

	// Approving it carries no warning.
	if code, resp, raw := protectedPut(t, h, tenantID, `{"name":"CrowdStrike Falcon Sensor","platform":"any","policy":"approved"}`); code != http.StatusOK || resp.ProtectedWarning || resp.Protected != nil {
		t.Fatalf("approve: %d %s", code, raw)
	}
}

// TestAppPoliciesPutAllowsNonMatchingProduct proves fail-closed does not
// mean over-protecting: a product that matches no protected_software row
// (baseline or tenant) is NOT treated as protected.
func TestAppPoliciesPutAllowsNonMatchingProduct(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1801-nonmatch-tenant")
	h := TenantAppPoliciesPutHandler(pool, notify.New())

	body := `{"name":"Totally Unrelated Spreadsheet App","platform":"any","policy":"unapproved"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for non-protected product, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"protected_warning":true`) {
		t.Fatalf("non-protected product carries a protected warning: %s", w.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND policy='unapproved'`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("non-protected unapproved write did not land: count=%d", count)
	}
}

// TestProtectedSoftwareAdd_TenantOverrideIsEnforced proves a tenant's own
// addition (ProtectedSoftwareAddHandler) to protected_software is treated
// exactly like a baseline row (a protected warning, PAT-2088), via a strong
// identifier (team_id) this time, and only for that tenant.
func TestProtectedSoftwareAdd_TenantOverrideIsEnforced(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1801-tenant-add-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Vault Agent","team_id":"TEAMACME01"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	h := TenantAppPoliciesPutHandler(pool, notify.New())
	putBody := `{"team_id":"TEAMACME01","name":"Acme Vault Agent","platform":"any","policy":"unapproved"}`
	code, resp, raw := protectedPut(t, h, tenantID, putBody)
	if code != http.StatusOK || !resp.ProtectedWarning || resp.Protected == nil || resp.Protected.Category != "customer_defined" {
		t.Fatalf("want 200 with a protected warning for tenant-added protected software, got %d: %s", code, raw)
	}

	// Different tenant, same identity, no protection added there: no warning.
	otherTenantID := catSeedTenant(t, ctx, pool, "pat1801-tenant-add-other-tenant")
	code, resp, raw = protectedPut(t, h, otherTenantID, putBody)
	if code != http.StatusOK || resp.ProtectedWarning {
		t.Fatalf("tenant-scoped protection leaked to a different tenant: got %d: %s", code, raw)
	}

	// Audit row for the add.
	var action, actor string
	if err := pool.QueryRow(ctx, `
		SELECT action, actor FROM protected_software_changes
		WHERE tenant_id=$1::uuid AND action='added' ORDER BY id DESC LIMIT 1
	`, tenantID).Scan(&action, &actor); err != nil {
		t.Fatalf("expected an 'added' audit row: %v", err)
	}
}

// TestProtectedSoftwareOverrideRemove_ReenablesWriteAndIsAudited proves the
// per-tenant baseline override-remove path (a) requires a reason, (b) lifts
// the protection (and so the PAT-2088 warning) for that tenant only, and (c)
// is recorded in protected_software_changes.
func TestProtectedSoftwareOverrideRemove_ReenablesWriteAndIsAudited(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1801-override-tenant")

	var baselineID int64
	if err := pool.QueryRow(ctx, `
		SELECT id FROM protected_software WHERE tenant_id IS NULL AND vendor='CrowdStrike' LIMIT 1
	`).Scan(&baselineID); err != nil {
		t.Fatalf("expected the CrowdStrike baseline seed row to exist: %v", err)
	}

	h := TenantAppPoliciesPutHandler(pool, notify.New())
	putBody := `{"name":"CrowdStrike Falcon Sensor","platform":"any","policy":"unapproved"}`
	if code, resp, raw := protectedPut(t, h, tenantID, putBody); code != http.StatusOK || !resp.ProtectedWarning {
		t.Fatalf("want 200 with a protected warning before override, got %d: %s", code, raw)
	}

	// Missing reason must be rejected before anything is written.
	badOverride := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/protected-software/"+strconv.FormatInt(baselineID, 10)+"/override-remove",
		bytes.NewBufferString(`{"removed_by":"andy"}`))
	badOverride = psWithParams(badOverride, tenantID, strconv.FormatInt(baselineID, 10))
	badW := httptest.NewRecorder()
	ProtectedSoftwareOverrideRemoveHandler(pool)(badW, badOverride)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing reason, got %d: %s", badW.Code, badW.Body.String())
	}

	overrideBody := `{"reason":"tenant runs an approved EDR migration and needs to retire the old Falcon deployment","removed_by":"andy@patched.im"}`
	overrideReq := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/protected-software/"+strconv.FormatInt(baselineID, 10)+"/override-remove",
		bytes.NewBufferString(overrideBody))
	overrideReq = psWithParams(overrideReq, tenantID, strconv.FormatInt(baselineID, 10))
	overrideW := httptest.NewRecorder()
	ProtectedSoftwareOverrideRemoveHandler(pool)(overrideW, overrideReq)
	if overrideW.Code != http.StatusCreated {
		t.Fatalf("override-remove: want 201, got %d: %s", overrideW.Code, overrideW.Body.String())
	}

	if code, resp, raw := protectedPut(t, h, tenantID, putBody); code != http.StatusOK || resp.ProtectedWarning {
		t.Fatalf("want 200 with no protected warning after override for this tenant, got %d: %s", code, raw)
	}

	// The baseline row itself must be untouched — other tenants are still protected.
	otherTenantID := catSeedTenant(t, ctx, pool, "pat1801-override-other-tenant")
	if code, resp, raw := protectedPut(t, h, otherTenantID, putBody); code != http.StatusOK || !resp.ProtectedWarning {
		t.Fatalf("override for one tenant leaked to another tenant: want a protected warning, got %d: %s", code, raw)
	}

	var reason, actor string
	if err := pool.QueryRow(ctx, `
		SELECT reason, removed_by FROM protected_software_overrides WHERE tenant_id=$1::uuid AND baseline_id=$2
	`, tenantID, baselineID).Scan(&reason, &actor); err != nil {
		t.Fatalf("expected an override row: %v", err)
	}
	if reason == "" || actor == "" {
		t.Fatalf("override row missing reason/actor: reason=%q actor=%q", reason, actor)
	}

	var auditAction, auditActor string
	if err := pool.QueryRow(ctx, `
		SELECT action, actor FROM protected_software_changes
		WHERE tenant_id=$1::uuid AND action='baseline_override_removed' ORDER BY id DESC LIMIT 1
	`, tenantID).Scan(&auditAction, &auditActor); err != nil {
		t.Fatalf("expected a 'baseline_override_removed' audit row: %v", err)
	}
	if auditActor != "andy@patched.im" {
		t.Fatalf("audit row actor = %q, want andy@patched.im", auditActor)
	}
}

// TestProtectedProduct_CVEFindingsStillSurface proves protection is
// disposition-only: a protected product's CVE findings still come back
// from GET /admin/tenants/{tenantID}/cve-findings exactly as they would for
// any other product, even though the same product carries a protected
// warning when set unapproved. This handler and internal/protectedsoftware never touch
// device_cve_findings / cve_feed_entries.
func TestProtectedProduct_CVEFindingsStillSurface(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1801-cve-tenant")

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os) VALUES ($1::uuid, 'macOS') RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id=$1::uuid`, deviceID) })

	const cveID = "CVE-2026-1801"
	if _, err := pool.Exec(ctx, `INSERT INTO cve_feed_entries (cve_id, severity) VALUES ($1, 'critical')`, cveID); err != nil {
		t.Fatalf("insert cve_feed_entries: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM cve_feed_entries WHERE cve_id=$1`, cveID) })
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name) VALUES ($1::uuid, $2, 'CrowdStrike Falcon Sensor')
	`, deviceID, cveID); err != nil {
		t.Fatalf("insert device_cve_findings: %v", err)
	}

	// Confirm the same product is indeed protected (warned for unapproved) —
	// establishes that this is genuinely the protected-product case, not an
	// unrelated app that happens to share a CVE.
	h := TenantAppPoliciesPutHandler(pool, notify.New())
	putBody := `{"name":"CrowdStrike Falcon Sensor","platform":"any","policy":"unapproved"}`
	if code, resp, raw := protectedPut(t, h, tenantID, putBody); code != http.StatusOK || !resp.ProtectedWarning {
		t.Fatalf("want 200 with a protected warning, got %d: %s", code, raw)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/cve-findings", nil)
	getReq = catWithTenantID(getReq, tenantID)
	getW := httptest.NewRecorder()
	TenantCVEFindingsHandler(pool)(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("cve-findings: want 200, got %d: %s", getW.Code, getW.Body.String())
	}

	var resp struct {
		Findings []struct {
			CVEID string `json:"cve_id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(getW.Body).Decode(&resp); err != nil {
		t.Fatalf("decode cve-findings response: %v", err)
	}
	found := false
	for _, f := range resp.Findings {
		if f.CVEID == cveID {
			found = true
		}
	}
	if !found {
		t.Fatalf("protected product's CVE finding did not surface: %+v", resp.Findings)
	}
}

// ---------------------------------------------------------------------------
// PAT-1823: GET routes for the protected-software list — console effective
// set + changelog, and the portal per-product status surface.
// ---------------------------------------------------------------------------

// TestTenantProtectedSoftwareGet_BaselineOnly proves a tenant with no
// additions and no overrides sees exactly the shared baseline set, every
// entry tagged source="baseline".
func TestTenantProtectedSoftwareGet_BaselineOnly(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1823-baseline-only-tenant")

	var baselineCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM protected_software WHERE tenant_id IS NULL`).Scan(&baselineCount); err != nil {
		t.Fatalf("count baseline rows: %v", err)
	}
	if baselineCount == 0 {
		t.Fatal("expected the PAT-1801 baseline seed to be present")
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/protected-software", nil)
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	TenantProtectedSoftwareGetHandler(pool)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protectedSoftwareListResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Entries) != baselineCount {
		t.Fatalf("want %d entries (baseline only), got %d", baselineCount, len(resp.Entries))
	}
	for _, e := range resp.Entries {
		if e.Source != "baseline" {
			t.Fatalf("baseline-only tenant got a non-baseline entry: %+v", e)
		}
	}
}

// TestTenantProtectedSoftwareGet_WithTenantAdditions proves a tenant's own
// addition appears in the effective set tagged source="tenant", alongside
// the baseline rows, and does not leak to a different tenant.
func TestTenantProtectedSoftwareGet_WithTenantAdditions(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1823-with-addition-tenant")
	otherTenantID := catSeedTenant(t, ctx, pool, "pat1823-with-addition-other-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Vault Agent","team_id":"TEAM1823ADD"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/protected-software", nil)
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	TenantProtectedSoftwareGetHandler(pool)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp protectedSoftwareListResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var found bool
	for _, e := range resp.Entries {
		if e.Vendor == "Acme" && e.ProductName == "Acme Vault Agent" {
			found = true
			if e.Source != "tenant" {
				t.Fatalf("tenant addition tagged source=%q, want \"tenant\"", e.Source)
			}
		}
	}
	if !found {
		t.Fatalf("tenant addition missing from effective set: %+v", resp.Entries)
	}

	// The addition is tenant-scoped: it must not appear for a different tenant.
	otherReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+otherTenantID+"/protected-software", nil)
	otherReq = catWithTenantID(otherReq, otherTenantID)
	otherW := httptest.NewRecorder()
	TenantProtectedSoftwareGetHandler(pool)(otherW, otherReq)
	if otherW.Code != http.StatusOK {
		t.Fatalf("other tenant want 200, got %d: %s", otherW.Code, otherW.Body.String())
	}
	var otherResp protectedSoftwareListResp
	if err := json.NewDecoder(otherW.Body).Decode(&otherResp); err != nil {
		t.Fatalf("decode other tenant response: %v", err)
	}
	for _, e := range otherResp.Entries {
		if e.Vendor == "Acme" && e.ProductName == "Acme Vault Agent" {
			t.Fatalf("tenant addition leaked to a different tenant: %+v", e)
		}
	}
}

// TestTenantProtectedSoftwareGet_ExcludesOverriddenBaseline proves an
// audited override-remove drops that baseline entry from the effective set
// for the overriding tenant only, while leaving it present (and still
// source="baseline") for every other tenant.
func TestTenantProtectedSoftwareGet_ExcludesOverriddenBaseline(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1823-override-get-tenant")
	otherTenantID := catSeedTenant(t, ctx, pool, "pat1823-override-get-other-tenant")

	var baselineID int64
	if err := pool.QueryRow(ctx, `
		SELECT id FROM protected_software WHERE tenant_id IS NULL AND vendor='SentinelOne' LIMIT 1
	`).Scan(&baselineID); err != nil {
		t.Fatalf("expected the SentinelOne baseline seed row to exist: %v", err)
	}

	overrideBody := `{"reason":"retiring this EDR for a new one under an approved migration plan","removed_by":"andy@patched.im"}`
	overrideReq := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/protected-software/"+strconv.FormatInt(baselineID, 10)+"/override-remove",
		bytes.NewBufferString(overrideBody))
	overrideReq = psWithParams(overrideReq, tenantID, strconv.FormatInt(baselineID, 10))
	overrideW := httptest.NewRecorder()
	ProtectedSoftwareOverrideRemoveHandler(pool)(overrideW, overrideReq)
	if overrideW.Code != http.StatusCreated {
		t.Fatalf("override-remove: want 201, got %d: %s", overrideW.Code, overrideW.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/protected-software", nil)
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	TenantProtectedSoftwareGetHandler(pool)(w, req)
	var resp protectedSoftwareListResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, e := range resp.Entries {
		if e.Vendor == "SentinelOne" {
			t.Fatalf("overridden baseline entry still present for overriding tenant: %+v", e)
		}
	}

	otherReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+otherTenantID+"/protected-software", nil)
	otherReq = catWithTenantID(otherReq, otherTenantID)
	otherW := httptest.NewRecorder()
	TenantProtectedSoftwareGetHandler(pool)(otherW, otherReq)
	var otherResp protectedSoftwareListResp
	if err := json.NewDecoder(otherW.Body).Decode(&otherResp); err != nil {
		t.Fatalf("decode other tenant response: %v", err)
	}
	var stillPresent bool
	for _, e := range otherResp.Entries {
		if e.Vendor == "SentinelOne" {
			stillPresent = true
			if e.Source != "baseline" {
				t.Fatalf("unaffected tenant's baseline row tagged source=%q, want \"baseline\"", e.Source)
			}
		}
	}
	if !stillPresent {
		t.Fatal("override for one tenant removed the baseline row for every tenant")
	}
}

// TestTenantProtectedSoftwareChanges_OrderingAndContent proves the
// changelog returns newest-first and captures both action kinds this
// package writes: 'added' and 'baseline_override_removed'.
func TestTenantProtectedSoftwareChanges_OrderingAndContent(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1823-changes-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Changelog Agent","process_name":"acme-changelog"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	var baselineID int64
	if err := pool.QueryRow(ctx, `
		SELECT id FROM protected_software WHERE tenant_id IS NULL AND vendor='Microsoft' AND category='edr' LIMIT 1
	`).Scan(&baselineID); err != nil {
		t.Fatalf("expected the Microsoft Defender baseline seed row to exist: %v", err)
	}
	overrideBody := `{"reason":"replacing Defender with the tenant's chosen EDR under a signed migration plan","removed_by":"ops@patched.im"}`
	overrideReq := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/protected-software/"+strconv.FormatInt(baselineID, 10)+"/override-remove",
		bytes.NewBufferString(overrideBody))
	overrideReq = psWithParams(overrideReq, tenantID, strconv.FormatInt(baselineID, 10))
	overrideW := httptest.NewRecorder()
	ProtectedSoftwareOverrideRemoveHandler(pool)(overrideW, overrideReq)
	if overrideW.Code != http.StatusCreated {
		t.Fatalf("override-remove: want 201, got %d: %s", overrideW.Code, overrideW.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/protected-software/changes", nil)
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	TenantProtectedSoftwareChangesHandler(pool)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protectedSoftwareChangesResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Changes) != 2 {
		t.Fatalf("want 2 change rows (added + baseline_override_removed), got %d: %+v", len(resp.Changes), resp.Changes)
	}
	// Newest first: the override-remove happened after the add.
	if resp.Changes[0].Action != "baseline_override_removed" {
		t.Fatalf("want newest-first ordering (override first), got %+v", resp.Changes)
	}
	if resp.Changes[0].Actor != "ops@patched.im" {
		t.Fatalf("override change actor = %q, want ops@patched.im", resp.Changes[0].Actor)
	}
	if resp.Changes[1].Action != "added" {
		t.Fatalf("want the add as the second (older) row, got %+v", resp.Changes)
	}
}

// TestTenantProtectedSoftwareChanges_UnknownTenant404s proves the changelog
// route 404s for a tenant that does not exist, matching every other admin
// route in this package.
func TestTenantProtectedSoftwareChanges_UnknownTenant404s(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	unknownTenantID := "00000000-0000-0000-0000-000000000000"
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+unknownTenantID+"/protected-software/changes", nil)
	req = catWithTenantID(req, unknownTenantID)
	w := httptest.NewRecorder()
	TenantProtectedSoftwareChangesHandler(pool)(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown tenant, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPortalProtectedSoftware_AuthModel proves the portal route fails
// closed without a verified portalauth identity in the request context —
// the different auth path from the two admin routes above, which gate on
// ADMIN_API_TOKEN instead.
func TestPortalProtectedSoftware_AuthModel(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/protected-software", nil)
	w := httptest.NewRecorder()
	PortalProtectedSoftwareHandler(pool)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with no portal identity in context, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPortalProtectedSoftware_Shape proves the portal route, once
// authenticated via portalauth.WithIdentity, returns the caller's own
// effective set shaped as protected:true + category — and only the
// caller's own tenant, never another tenant's rows.
func TestPortalProtectedSoftware_Shape(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1823-portal-shape-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Portal Agent","process_name":"acme-portal"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/protected-software", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "portal-user@example.com", TenantID: tenantID}))
	w := httptest.NewRecorder()
	PortalProtectedSoftwareHandler(pool)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp portalProtectedSoftwareResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	var baselineCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM protected_software WHERE tenant_id IS NULL`).Scan(&baselineCount); err != nil {
		t.Fatalf("count baseline rows: %v", err)
	}
	if len(resp.Products) != baselineCount+1 {
		t.Fatalf("want %d products (baseline + 1 tenant addition), got %d: %+v", baselineCount+1, len(resp.Products), resp.Products)
	}

	var found bool
	for _, p := range resp.Products {
		if !p.Protected {
			t.Fatalf("effective-set row returned protected=false: %+v", p)
		}
		if p.Vendor == "Acme" && p.ProductName == "Acme Portal Agent" {
			found = true
			if p.Category != "customer_defined" {
				t.Fatalf("tenant addition category = %q, want customer_defined", p.Category)
			}
		}
	}
	if !found {
		t.Fatalf("tenant addition missing from portal response: %+v", resp.Products)
	}
}

// ---------------------------------------------------------------------------
// PAT-1822: DB-integration coverage for checkStrong's SQL, the query behind
// protectedsoftware.Check's strong-identifier path (team_id/signer,
// bundle_id, win_publisher+win_product_code). The tests above exercise it
// only via process_name/product_name fallback and one team_id case; these
// call protectedsoftware.Check directly against the real pool so each
// column and the OR/AND structure of the WHERE clause is proven against a
// real Postgres rather than only asserted by hasStrongIdentifier's pure
// unit test (internal/protectedsoftware/protectedsoftware_test.go).
// ---------------------------------------------------------------------------

// TestProtectedSoftwareCheckStrong_BundleIDMatch proves a row seeded with
// only bundle_id set (no team_id/signer/win_*) is matched by
// protectedsoftware.Check on that bundle_id alone.
func TestProtectedSoftwareCheckStrong_BundleIDMatch(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1822-bundleid-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Bundle Agent","bundle_id":"com.acme.bundleagent"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	match, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		BundleID: strPtr("com.acme.bundleagent"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if match == nil {
		t.Fatal("want a match on bundle_id, got nil")
	}
	if match.ProductName != "Acme Bundle Agent" || match.Vendor != "Acme" {
		t.Fatalf("matched wrong row: %+v", match)
	}
	if match.IsBaseline {
		t.Fatalf("tenant-added row reported as baseline: %+v", match)
	}
}

// TestProtectedSoftwareCheckStrong_BundleIDNoMatch proves a bundle_id that
// matches no row is NOT treated as protected — the negative complement to
// the match case above (the existing negative-match tests in this file all
// go through the weaker process_name fallback, not a strong bundle_id
// check).
func TestProtectedSoftwareCheckStrong_BundleIDNoMatch(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1822-bundleid-nomatch-tenant")

	match, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		BundleID: strPtr("com.nonexistent.nothing"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if match != nil {
		t.Fatalf("want no match for an unregistered bundle_id, got %+v", match)
	}
}

// TestProtectedSoftwareCheckStrong_SignerMatchDistinctFromTeamID proves the
// OR between ps.team_id and ps.signer genuinely spans both columns: a row
// seeded with signer set and team_id set to a DIFFERENT value still matches
// an identity carrying only the signer value in Identity.TeamID (the field
// checkStrong compares against both columns — see protectedsoftware.go's
// comment on Identity.TeamID). If the match only worked because team_id
// happened to be checked, this would fail; if it only worked by accident of
// team_id equality, changing team_id to a different value here would have
// broken it.
func TestProtectedSoftwareCheckStrong_SignerMatchDistinctFromTeamID(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1822-signer-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Signed Agent","team_id":"TEAMDIFFERENT","signer":"SIGNERONLY01"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	// The identity carries the signer value, NOT the row's team_id value —
	// a match here can only have come from the ps.signer branch of the OR.
	match, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		TeamID: strPtr("SIGNERONLY01"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if match == nil {
		t.Fatal("want a match via the signer column, got nil")
	}
	if match.ProductName != "Acme Signed Agent" {
		t.Fatalf("matched wrong row: %+v", match)
	}

	// Sanity: the row's actual team_id value alone also matches (the other
	// side of the same OR), proving both columns are genuinely reachable.
	teamMatch, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		TeamID: strPtr("TEAMDIFFERENT"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if teamMatch == nil {
		t.Fatal("want a match via the team_id column, got nil")
	}
}

// TestProtectedSoftwareCheckStrong_WinPublisherProductCodeMatch proves a
// row seeded with both win_publisher and win_product_code set is matched
// by protectedsoftware.Check when the identity carries both matching
// values.
func TestProtectedSoftwareCheckStrong_WinPublisherProductCodeMatch(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1822-winpub-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Windows Agent","win_publisher":"Acme Corp","win_product_code":"{ACME-0001-CODE}"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	match, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		WinPublisher:   strPtr("Acme Corp"),
		WinProductCode: strPtr("{ACME-0001-CODE}"),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if match == nil {
		t.Fatal("want a match on win_publisher+win_product_code, got nil")
	}
	if match.ProductName != "Acme Windows Agent" {
		t.Fatalf("matched wrong row: %+v", match)
	}
}

// TestProtectedSoftwareCheckStrong_WinPublisherProductCodeBothRequired
// proves the "both must be set together" rule holds end-to-end through
// protectedsoftware.Check against a real Postgres row that would otherwise
// match: a row exists with both win_publisher and win_product_code set to
// values the identity below carries — but each check supplies only ONE of
// the two fields, and both must come back with no match. This is the
// DB-integration complement to hasStrongIdentifier's pure boundary-logic
// unit test in internal/protectedsoftware/protectedsoftware_test.go: it
// confirms the rule holds against a genuine seeded row, not only in
// isolation.
func TestProtectedSoftwareCheckStrong_WinPublisherProductCodeBothRequired(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "pat1822-winpub-bothreq-tenant")

	addBody := `{"category":"customer_defined","vendor":"Acme","product_name":"Acme Partial Windows Agent","win_publisher":"Acme Partial Corp","win_product_code":"{ACME-0002-CODE}"}`
	addReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/protected-software", bytes.NewBufferString(addBody))
	addReq = catWithTenantID(addReq, tenantID)
	addW := httptest.NewRecorder()
	ProtectedSoftwareAddHandler(pool)(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add protected software: want 201, got %d: %s", addW.Code, addW.Body.String())
	}

	publisherOnly, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		WinPublisher: strPtr("Acme Partial Corp"),
	})
	if err != nil {
		t.Fatalf("Check (publisher only): %v", err)
	}
	if publisherOnly != nil {
		t.Fatalf("win_publisher alone must not match despite a real row sharing it: %+v", publisherOnly)
	}

	productCodeOnly, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		WinProductCode: strPtr("{ACME-0002-CODE}"),
	})
	if err != nil {
		t.Fatalf("Check (product code only): %v", err)
	}
	if productCodeOnly != nil {
		t.Fatalf("win_product_code alone must not match despite a real row sharing it: %+v", productCodeOnly)
	}

	// Sanity: both together do match the same row — confirms the two
	// checks above failed because of the both-required rule, not because
	// the seed values were wrong.
	both, err := protectedsoftware.Check(ctx, pool, tenantID, protectedsoftware.Identity{
		WinPublisher:   strPtr("Acme Partial Corp"),
		WinProductCode: strPtr("{ACME-0002-CODE}"),
	})
	if err != nil {
		t.Fatalf("Check (both): %v", err)
	}
	if both == nil {
		t.Fatal("want a match when both win_publisher and win_product_code are supplied")
	}
}
