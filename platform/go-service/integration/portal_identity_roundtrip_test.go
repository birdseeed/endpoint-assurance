//go:build integration

package integration

// PAT-2104: GET /v1/portal/applications and GET /v1/portal/software now
// carry enough identity (identifier, team_id, product_key) for the portal
// to send a product straight back through PUT /v1/portal/software-approvals
// (PAT-2007) — including to UNAPPROVE something it previously approved,
// which the identifier-less shape these endpoints used to return could
// never do. These tests exercise a read -> write -> read round trip on the
// SAME tenant_app_policies row, on both macOS (with a team_id) and Windows
// (no team_id), assert a name-only policy stays honestly unaddressable, and
// check the software-inventory endpoint's team_id/product_key/policy_state
// resolve the same way the write path and the PAT-2009 alert do.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// policyRowID looks up one tenant_app_policies row's id by its bundle_id,
// so a test can assert a write updated the SAME row rather than creating a
// second one.
func policyRowID(t *testing.T, tenantID, bundleID string) (int64, bool) {
	t.Helper()
	var id int64
	err := env.pool.QueryRow(context.Background(), `
		SELECT id FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND lower(bundle_id) = lower($2)`, tenantID, bundleID).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

func policyRowCount(t *testing.T, tenantID, bundleID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND lower(bundle_id) = lower($2)`, tenantID, bundleID).Scan(&n); err != nil {
		t.Fatalf("count policy rows: %v", err)
	}
	return n
}

func getPortalApplications(t *testing.T, token string) portalApplicationsOut {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/applications", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /v1/portal/applications = %d: %s", resp.StatusCode, b)
	}
	var out portalApplicationsOut
	decodeJSON(t, resp, &out)
	return out
}

// putItemFromRow builds a PUT /v1/portal/software-approvals application item
// from exactly the identity fields GET /v1/portal/applications returned,
// mirroring what the portal client does: no field is invented or looked up
// separately.
func putItemFromRow(row portalApplicationOut) string {
	team := ""
	if row.PolicyTeamID != nil {
		team = *row.PolicyTeamID
	}
	return macApp2(row.Platform, row.Identifier, team)
}

func macApp2(platform, identifier, team string) string {
	if team == "" {
		return `{"type":"application","platform":"` + platform + `","identifier":"` + identifier + `"}`
	}
	return `{"type":"application","platform":"` + platform + `","identifier":"` + identifier + `","team_id":"` + team + `"}`
}

// TestPortalApplicationsIdentityRoundTripMacOS: a macOS policy row read from
// GET /v1/portal/applications must carry the exact identifier/team_id PUT
// /v1/portal/software-approvals needs to find that SAME row again — for
// both directions, approve and unapprove — not create a duplicate.
func TestPortalApplicationsIdentityRoundTripMacOS(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-identity-macos")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	const bundle = "com.example.roundtripmacos"
	const team = "ROUNDTRIP1"
	email := "identity-macos@apps-identity-macos.example"
	mapPortalUserWithRole(t, email, tenantID, "admin")
	token := env.idp.token(t, email)

	// Evidence this tenant has observed the bundle signed by this team, so
	// the write path will confirm identity.
	item := seen(t, tenantID, macApp(bundle, team))
	mustApprove(t, token, approvalBody("approved", "", item))

	rowID, ok := policyRowID(t, tenantID, bundle)
	if !ok {
		t.Fatalf("policy row not created")
	}

	out := getPortalApplications(t, token)
	row, ok := findPortalApplication(out.Applications, bundle)
	if !ok {
		t.Fatalf("row for %s missing from %+v", bundle, out.Applications)
	}
	if row.Identifier != bundle {
		t.Fatalf("identifier = %q, want %q", row.Identifier, bundle)
	}
	if row.PolicyTeamID == nil || *row.PolicyTeamID != team {
		t.Fatalf("policy_team_id = %v, want %q", row.PolicyTeamID, team)
	}
	wantKey := "application:macos:" + bundle + ":" + team
	if row.ProductKey == nil || *row.ProductKey != wantKey {
		t.Fatalf("product_key = %v, want %q", row.ProductKey, wantKey)
	}
	if row.PolicyState != "approved" {
		t.Fatalf("policy_state = %q, want approved", row.PolicyState)
	}

	// Unapprove, using ONLY what the GET response gave back.
	mustApprove(t, token, approvalBody("unapproved", "", putItemFromRow(row)))
	if policyRowCount(t, tenantID, bundle) != 1 {
		t.Fatalf("unapprove created a second row instead of updating rowID %d", rowID)
	}
	if newID, _ := policyRowID(t, tenantID, bundle); newID != rowID {
		t.Fatalf("unapprove changed the row id: was %d, now %d", rowID, newID)
	}
	if policy, _, _, ok := appPolicy(t, tenantID, bundle); !ok || policy != "unapproved" {
		t.Fatalf("policy after unapprove = %q, ok=%v, want unapproved", policy, ok)
	}

	// The audit history must show BOTH writes — the original approve and
	// the round-trip unapprove that used only the identity fields GET gave
	// back — newest first, on the exact product_key those fields compute.
	histFilter := "type=application&platform=macos&identifier=" + bundle + "&team_id=" + team
	histStatus, hist := getHistory(t, token, "?"+histFilter)
	if histStatus != http.StatusOK {
		t.Fatalf("history status = %d, want 200: %v", histStatus, hist)
	}
	decisions, _ := hist["decisions"].([]any)
	if len(decisions) != 2 {
		t.Fatalf("history has %d decisions, want 2 (approve + unapprove): %v", len(decisions), decisions)
	}
	newest, oldest := decisions[0].(map[string]any), decisions[1].(map[string]any)
	if newest["new_state"] != "unapproved" || newest["previous_state"] != "approved" {
		t.Fatalf("newest decision = %v, want unapproved (from approved)", newest)
	}
	if oldest["new_state"] != "approved" {
		t.Fatalf("oldest decision = %v, want approved", oldest)
	}

	// Read again and approve back, again using only what GET returned.
	out = getPortalApplications(t, token)
	row, ok = findPortalApplication(out.Applications, bundle)
	if !ok {
		t.Fatalf("row for %s missing after unapprove", bundle)
	}
	if row.PolicyState != "unapproved" {
		t.Fatalf("policy_state after unapprove = %q, want unapproved", row.PolicyState)
	}
	mustApprove(t, token, approvalBody("approved", "", putItemFromRow(row)))
	if policyRowCount(t, tenantID, bundle) != 1 {
		t.Fatalf("re-approve created a second row instead of updating rowID %d", rowID)
	}
	if newID, _ := policyRowID(t, tenantID, bundle); newID != rowID {
		t.Fatalf("re-approve changed the row id: was %d, now %d", rowID, newID)
	}
}

// TestPortalApplicationsIdentityRoundTripWindows mirrors the macOS test:
// PAT-2007 carries no team_id for a Windows item, so policy_team_id must be
// null, and the round trip must still land on the same row.
func TestPortalApplicationsIdentityRoundTripWindows(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-identity-windows")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	const winID = "Example.RoundTripTool"
	seedWindowsAlias(t, winID)

	email := "identity-windows@apps-identity-windows.example"
	mapPortalUserWithRole(t, email, tenantID, "admin")
	token := env.idp.token(t, email)

	item := `{"type":"application","platform":"windows","identifier":"` + winID + `"}`
	mustApprove(t, token, approvalBody("approved", "", item))

	rowID, ok := policyRowID(t, tenantID, winID)
	if !ok {
		t.Fatalf("policy row not created")
	}

	out := getPortalApplications(t, token)
	row, ok := findPortalApplication(out.Applications, winID)
	if !ok {
		t.Fatalf("row for %s missing from %+v", winID, out.Applications)
	}
	if row.Identifier != winID {
		t.Fatalf("identifier = %q, want %q", row.Identifier, winID)
	}
	if row.PolicyTeamID != nil {
		t.Fatalf("policy_team_id = %v, want nil on windows", *row.PolicyTeamID)
	}
	wantKey := "application:windows:" + strings.ToLower(winID)
	if row.ProductKey == nil || *row.ProductKey != wantKey {
		t.Fatalf("product_key = %v, want %q", row.ProductKey, wantKey)
	}

	mustApprove(t, token, approvalBody("unapproved", "", putItemFromRow(row)))
	if policyRowCount(t, tenantID, winID) != 1 {
		t.Fatalf("unapprove created a second row instead of updating rowID %d", rowID)
	}
	if newID, _ := policyRowID(t, tenantID, winID); newID != rowID {
		t.Fatalf("unapprove changed the row id: was %d, now %d", rowID, newID)
	}
	if policy, _, _, ok := appPolicy(t, tenantID, winID); !ok || policy != "unapproved" {
		t.Fatalf("policy after unapprove = %q, ok=%v, want unapproved", policy, ok)
	}
}

// TestPortalApplicationsIdentityNameOnlyUnaddressable: a policy row with no
// bundle_id or team_id — decided by display name only — must stay
// unaddressable: identifier "" and no product_key, never an invented
// identity the write path would refuse or silently mismatch.
func TestPortalApplicationsIdentityNameOnlyUnaddressable(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-identity-nameonly")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'NameOnlyTool', 'any', 'unapproved', 'app_management')
	`, tenantID); err != nil {
		t.Fatalf("seed name-only policy: %v", err)
	}

	email := "identity-nameonly@apps-identity-nameonly.example"
	mapPortalUserWithRole(t, email, tenantID, "admin")
	token := env.idp.token(t, email)

	out := getPortalApplications(t, token)
	row, ok := findPortalApplication(out.Applications, "NameOnlyTool")
	if !ok {
		t.Fatalf("NameOnlyTool row missing from %+v", out.Applications)
	}
	if row.Identifier != "" {
		t.Fatalf("identifier = %q, want empty for a name-only row", row.Identifier)
	}
	if row.PolicyTeamID != nil {
		t.Fatalf("policy_team_id = %v, want nil for a name-only row", *row.PolicyTeamID)
	}
	if row.ProductKey != nil {
		t.Fatalf("product_key = %v, want nil for a name-only row", *row.ProductKey)
	}

	// Sending that empty identifier back must be refused as name_only, the
	// same refusal the row itself already carries — never silently matched
	// against some other row.
	refused(t, token, approvalBody("approved", "",
		`{"type":"application","platform":"macos","identifier":""}`), http.StatusUnprocessableEntity, "name_only")
}

// TestPortalApplicationsIdentityCrossTenantIsolation: two tenants with
// policy rows for the identical bundle_id/team_id must never let a write
// keyed from one tenant's GET response touch the other tenant's row.
func TestPortalApplicationsIdentityCrossTenantIsolation(t *testing.T) {
	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-identity-isoA")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "portal-apps-identity-isoB")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	cleanupTestTenant(t, tenantB)

	const bundle = "com.example.isolationtool"
	const team = "ISOLATION1"
	emailA := "identity-isoA@apps-identity-iso.example"
	emailB := "identity-isoB@apps-identity-iso.example"
	mapPortalUserWithRole(t, emailA, tenantA, "admin")
	mapPortalUserWithRole(t, emailB, tenantB, "admin")
	tokenA := env.idp.token(t, emailA)
	tokenB := env.idp.token(t, emailB)

	itemA := seen(t, tenantA, macApp(bundle, team))
	mustApprove(t, tokenA, approvalBody("approved", "", itemA))
	itemB := seen(t, tenantB, macApp(bundle, team))
	mustApprove(t, tokenB, approvalBody("approved", "", itemB))

	outA := getPortalApplications(t, tokenA)
	if _, ok := findPortalApplication(outA.Applications, bundle); !ok {
		t.Fatalf("tenant A missing its own row")
	}

	// Unapprove from tenant A must never touch tenant B's identically keyed
	// row.
	mustApprove(t, tokenA, approvalBody("unapproved", "", macApp(bundle, team)))
	if policy, _, _, ok := appPolicy(t, tenantA, bundle); !ok || policy != "unapproved" {
		t.Fatalf("tenant A policy = %q, ok=%v, want unapproved", policy, ok)
	}
	if policy, _, _, ok := appPolicy(t, tenantB, bundle); !ok || policy != "approved" {
		t.Fatalf("tenant B policy = %q, ok=%v, want still approved (leaked from tenant A write)", policy, ok)
	}
}

// TestPortalSoftwareIdentityAndPolicyState: the inventory endpoint's
// team_id/product_key/policy_state must resolve with the SAME resolver the
// write path and the PAT-2009 alert use, agree with the identity
// GET /v1/portal/applications shows for the same product, go nil on
// disagreement, and never appear for a platform the write schema does not
// support.
func TestPortalSoftwareIdentityAndPolicyState(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-identity")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	const macBundle = "com.example.inventoryidentity"
	const macTeam = "INVENTORY1"
	device1 := seedPortalSoftwareDevice(t, tenantID, "identity-mac-1", "ok", time.Now().UTC())
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, 'InventoryIdentityTool', $2, '1.0', $3)`, device1, macBundle, macTeam); err != nil {
		t.Fatalf("seed macOS app: %v", err)
	}

	// Approve the same product via the write path, so policy_state must
	// read "approved" here too.
	email := "identity-software@apps-identity-software.example"
	mapPortalUserWithRole(t, email, tenantID, "admin")
	token := env.idp.token(t, email)
	item := seen(t, tenantID, macApp(macBundle, macTeam))
	mustApprove(t, token, approvalBody("approved", "", item))

	out := getPortalSoftware(t, token)
	product, ok := findPortalSoftware(out.Products, macBundle)
	if !ok {
		t.Fatalf("product %s missing from %+v", macBundle, out.Products)
	}
	if product.TeamID == nil || *product.TeamID != macTeam {
		t.Fatalf("team_id = %v, want %q", product.TeamID, macTeam)
	}
	wantKey := "application:macos:" + macBundle + ":" + macTeam
	if product.ProductKey == nil || *product.ProductKey != wantKey {
		t.Fatalf("product_key = %v, want %q", product.ProductKey, wantKey)
	}
	if product.PolicyState == nil || *product.PolicyState != "approved" {
		t.Fatalf("policy_state = %v, want approved", product.PolicyState)
	}

	// A second product with no policy at all must resolve to a real
	// product_key but a nil policy_state — undecided, not a guess.
	const undecidedBundle = "com.example.inventoryundecided"
	device2 := seedPortalSoftwareDevice(t, tenantID, "identity-mac-2", "ok", time.Now().UTC())
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, 'InventoryUndecidedTool', $2, '1.0', 'UNDECIDED1')`, device2, undecidedBundle); err != nil {
		t.Fatalf("seed undecided app: %v", err)
	}

	out = getPortalSoftware(t, token)
	undecided, ok := findPortalSoftware(out.Products, undecidedBundle)
	if !ok {
		t.Fatalf("product %s missing from %+v", undecidedBundle, out.Products)
	}
	if undecided.PolicyState != nil {
		t.Fatalf("policy_state = %v, want nil (undecided)", *undecided.PolicyState)
	}
	if undecided.ProductKey == nil {
		t.Fatalf("product_key = nil, want a computed key even when undecided")
	}
	if undecided.TeamID == nil || *undecided.TeamID != "UNDECIDED1" {
		t.Fatalf("team_id = %v, want UNDECIDED1 (single consistent observation)", undecided.TeamID)
	}

	// A third product observed on two devices with DISAGREEING team_id must
	// report team_id nil — genuine ambiguity, never averaged or guessed.
	const ambiguousBundle = "com.example.inventoryambiguous"
	device3 := seedPortalSoftwareDevice(t, tenantID, "identity-mac-3a", "ok", time.Now().UTC())
	device4 := seedPortalSoftwareDevice(t, tenantID, "identity-mac-3b", "ok", time.Now().UTC())
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, 'AmbiguousTool', $3, '1.0', 'AMBIGUOUS1'),
		       ($2::uuid, 'AmbiguousTool', $3, '1.0', 'AMBIGUOUS2')`,
		device3, device4, ambiguousBundle); err != nil {
		t.Fatalf("seed ambiguous app: %v", err)
	}
	out = getPortalSoftware(t, token)
	ambiguous, ok := findPortalSoftware(out.Products, ambiguousBundle)
	if !ok {
		t.Fatalf("product %s missing from %+v", ambiguousBundle, out.Products)
	}
	if ambiguous.TeamID != nil {
		t.Fatalf("team_id = %v, want nil on team_id disagreement", *ambiguous.TeamID)
	}

	// A Windows product must never carry a team_id, even if device_apps.team_id
	// happens to hold a value (e.g. an Authenticode signer name).
	winDeviceID := seedWindowsInventoryDevice(t, tenantID, "identity-windows")
	const winBundle = "Example.InventoryWindowsTool"
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, 'InventoryWindowsTool', $2, '1.0', 'Acme Software Ltd')`, winDeviceID, winBundle); err != nil {
		t.Fatalf("seed windows app: %v", err)
	}
	out = getPortalSoftware(t, token)
	win, ok := findPortalSoftware(out.Products, winBundle)
	if !ok {
		t.Fatalf("product %s missing from %+v", winBundle, out.Products)
	}
	if win.TeamID != nil {
		t.Fatalf("team_id = %v, want nil on windows regardless of device_apps.team_id", *win.TeamID)
	}
	wantWinKey := "application:windows:" + strings.ToLower(winBundle)
	if win.ProductKey == nil || *win.ProductKey != wantWinKey {
		t.Fatalf("product_key = %v, want %q", win.ProductKey, wantWinKey)
	}
}

// TestPortalSoftwareMalformedTeamIDNoProductKey: a macOS inventory row whose
// only observed team_id does not have the write schema's required shape
// (10 character Apple Team ID, e.g. from a stored value that predates that
// constraint or was seeded some other way) must get NO product_key. Without
// this guard, softwaregov.ApplicationKey would build a key from that
// malformed value, and a client that sent it straight back through
// PUT /v1/portal/software-approvals would get a 400 from
// approvalTeamIDPattern — a key this endpoint handed out that the write
// path can never accept. policy_state, being read-only evidence, still
// resolves normally.
func TestPortalSoftwareMalformedTeamIDNoProductKey(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-badteam")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	const bundle = "com.example.malformedteam"
	device := seedPortalSoftwareDevice(t, tenantID, "identity-badteam", "ok", time.Now().UTC())
	// Not 10 alphanumeric chars: fails approvalTeamIDPattern /
	// policyRoundTripTeamIDPattern (^[A-Z0-9]{10}$).
	const badTeam = "NOT-A-REAL-TEAM-ID"
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, 'MalformedTeamTool', $2, '1.0', $3)`, device, bundle, badTeam); err != nil {
		t.Fatalf("seed malformed-team app: %v", err)
	}

	email := "identity-badteam@apps-identity-badteam.example"
	mapPortalUserWithRole(t, email, tenantID, "admin")
	token := env.idp.token(t, email)

	out := getPortalSoftware(t, token)
	product, ok := findPortalSoftware(out.Products, bundle)
	if !ok {
		t.Fatalf("product %s missing from %+v", bundle, out.Products)
	}
	if product.ProductKey != nil {
		t.Fatalf("product_key = %q, want nil for a malformed team_id the write path would reject", *product.ProductKey)
	}
	if product.PolicyState != nil {
		t.Fatalf("policy_state = %v, want nil (no policy set); read-only evidence should still resolve, not error", *product.PolicyState)
	}
}

func getPortalSoftware(t *testing.T, token string) portalSoftwareOut {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/software?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /v1/portal/software = %d: %s", resp.StatusCode, b)
	}
	var out portalSoftwareOut
	decodeJSON(t, resp, &out)
	return out
}

func seedWindowsInventoryDevice(t *testing.T, tenantID, suffix string) string {
	t.Helper()
	var deviceID string
	err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, metering_status, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'Windows 11 Pro', '23H2', '22631', 'x64', 'ok', now())
		RETURNING id::text
	`, tenantID, "SER-"+suffix, "host-"+suffix).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed windows device: %v", err)
	}
	return deviceID
}
