package handlers

// PAT-1598 DB-backed tests for the authorised-removal platform surface.
// Skipped unless TEST_DATABASE_URL points at a database with every migration
// applied (same convention as the other *_db_test.go files here).
//
// The gates these prove are the whole point of the feature, so they are
// tested through the real HTTP handlers against a real Postgres rather than
// against mocks: a protected-software refusal that only exists in a fake
// would be indistinguishable from no refusal at all.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/notify"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/removal"
)

func removalTestRouter(pool *pgxpool.Pool) *chi.Mux {
	r := chi.NewRouter()
	r.Put("/admin/tenants/{tenantID}/app-policies", TenantAppPoliciesPutHandler(pool, notify.New()))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns", RemovalCampaignCreateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/removal-campaigns", RemovalCampaignListHandler(pool))
	r.Get("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}", RemovalCampaignGetHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/dry-run", RemovalCampaignDryRunHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/authorize", RemovalCampaignAuthorizeHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/cancel", RemovalCampaignCancelHandler(pool))
	return r
}

func removalDo(t *testing.T, r *chi.Mux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// removalFixture is one tenant with an estate: two macOS devices running the
// target product (on two versions, matched by bundle identifier), one macOS
// device running something else, and one device that has never reported an
// application at all.
type removalFixture struct {
	pool      *pgxpool.Pool
	router    *chi.Mux
	tenantID  string
	deviceA   string
	deviceB   string
	policyID  int64
	product   string
	bundleID  string
	teamID    string
	platform  string
	createdBy string
}

func seedRemovalFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) *removalFixture {
	t.Helper()
	f := &removalFixture{
		pool:      pool,
		router:    removalTestRouter(pool),
		tenantID:  catSeedTenant(t, ctx, pool, "pat1598-"+label),
		product:   "Acme Chat",
		bundleID:  "com.acme.chat",
		teamID:    "ACME123456",
		platform:  "macos",
		createdBy: "andy",
	}

	f.deviceA = seedRemovalDevice(t, ctx, pool, f.tenantID, "mac-a", "macOS")
	f.deviceB = seedRemovalDevice(t, ctx, pool, f.tenantID, "mac-b", "macOS")
	other := seedRemovalDevice(t, ctx, pool, f.tenantID, "mac-c", "macOS")
	// A device that has never reported an application. Not evidence the
	// product is absent from it, which is what the preview must say.
	seedRemovalDevice(t, ctx, pool, f.tenantID, "mac-quiet", "macOS")

	seedRemovalApp(t, ctx, pool, f.deviceA, f.product, "1.0.0", f.bundleID, f.teamID, "/Applications/Acme Chat.app")
	seedRemovalApp(t, ctx, pool, f.deviceB, f.product, "1.1.0", f.bundleID, f.teamID, "/Applications/Acme Chat.app")
	seedRemovalApp(t, ctx, pool, other, "Unrelated", "3.0.0", "com.other.thing", "OTHER99999", "/Applications/Unrelated.app")

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, platform, policy)
		VALUES ($1::uuid, $2, $3, 'macos', 'unapproved') RETURNING id
	`, f.tenantID, f.teamID, f.bundleID).Scan(&f.policyID); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	return f
}

func seedRemovalDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, hostname, os string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, $2, $3) RETURNING id::text
	`, tenantID, hostname, os).Scan(&id); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
	return id
}

func seedRemovalApp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID, name, version, identifier, teamID, path string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, version, identifier, team_id, path)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
	`, deviceID, name, version, identifier, teamID, path); err != nil {
		t.Fatalf("insert device_app %s: %v", name, err)
	}
}

// createCampaign drafts a campaign against the fixture's product.
func (f *removalFixture) createCampaign(t *testing.T) string {
	t.Helper()
	rec := removalDo(t, f.router, http.MethodPost, "/admin/tenants/"+f.tenantID+"/removal-campaigns", map[string]any{
		"bundle_id":  f.bundleID,
		"name":       f.product,
		"platform":   f.platform,
		"policy_id":  f.policyID,
		"reason":     "Unapproved chat client, replaced by the sanctioned one.",
		"created_by": f.createdBy,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create campaign: got %d, body %s", rec.Code, rec.Body.String())
	}
	var c removalCampaignRow
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("decode campaign: %v", err)
	}
	if c.Status != "draft" {
		t.Fatalf("new campaign status = %q, want draft", c.Status)
	}
	return c.ID
}

func (f *removalFixture) dryRun(t *testing.T, campaignID string) removalDryRunJSON {
	t.Helper()
	rec := removalDo(t, f.router, http.MethodPost,
		"/admin/tenants/"+f.tenantID+"/removal-campaigns/"+campaignID+"/dry-run",
		map[string]any{"computed_by": f.createdBy})
	if rec.Code != http.StatusCreated {
		t.Fatalf("dry run: got %d, body %s", rec.Code, rec.Body.String())
	}
	var d removalDryRunJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode dry run: %v", err)
	}
	return d
}

func (f *removalFixture) authorize(t *testing.T, campaignID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return removalDo(t, f.router, http.MethodPost,
		"/admin/tenants/"+f.tenantID+"/removal-campaigns/"+campaignID+"/authorize", body)
}

// adoptPolicy exercises the admin policy writer, whose upsert makes the
// operator the source of the current decision.
func (f *removalFixture) adoptPolicy(t *testing.T) {
	t.Helper()
	rec := removalDo(t, f.router, http.MethodPut, "/admin/tenants/"+f.tenantID+"/app-policies", map[string]any{
		"team_id":          f.teamID,
		"bundle_id":        f.bundleID,
		"platform":         f.platform,
		"policy":           "unapproved",
		"enforcement_tier": "report_deploy",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("adopt policy: got %d, body %s", rec.Code, rec.Body.String())
	}
	var source string
	if err := f.pool.QueryRow(context.Background(), `SELECT source FROM tenant_app_policies WHERE id = $1`, f.policyID).Scan(&source); err != nil {
		t.Fatalf("read adopted policy source: %v", err)
	}
	if source != "operator" {
		t.Fatalf("adopted policy source = %q, want operator", source)
	}
}

// setPortalPolicy exercises the real customer write path. Moving the seeded
// row away from Unapproved first ensures the portal performs a write rather
// than treating an identical state as an idempotent no-op.
func (f *removalFixture) setPortalPolicy(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE tenant_app_policies SET policy = 'approved' WHERE id = $1`, f.policyID); err != nil {
		t.Fatalf("prepare portal policy transition: %v", err)
	}
	email := "removal-" + f.tenantID[:8] + "@portal.example"
	if _, err := f.pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'admin')`, email, f.tenantID); err != nil {
		t.Fatalf("seed portal admin: %v", err)
	}
	body := "{\"state\":\"unapproved\",\"items\":[{\"type\":\"application\",\"platform\":\"macos\",\"identifier\":\"" + f.bundleID + "\",\"team_id\":\"" + f.teamID + "\"}]}"
	req := httptest.NewRequest(http.MethodPut, "/v1/portal/software-approvals", strings.NewReader(body))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: f.tenantID}))
	rec := httptest.NewRecorder()
	PortalSoftwareApprovalsPutHandler(f.pool).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set portal policy: got %d, body %s", rec.Code, rec.Body.String())
	}
	var source string
	if err := f.pool.QueryRow(ctx, `SELECT source FROM tenant_app_policies WHERE id = $1`, f.policyID).Scan(&source); err != nil {
		t.Fatalf("read portal policy source: %v", err)
	}
	if source != "portal" {
		t.Fatalf("portal policy source = %q, want portal", source)
	}
}

// protectedMatchPresent reads the nullable protected_match field. A JSON
// null decodes into a json.RawMessage holding the four bytes "null", not a
// nil slice, so a plain nil check would read every unprotected preview as
// protected.
func protectedMatchPresent(d removalDryRunJSON) bool {
	raw := strings.TrimSpace(string(d.ProtectedMatch))
	return raw != "" && raw != "null"
}

func validAuthorizeBody() map[string]any {
	return map[string]any{
		"authorized_by":        "Jane Doe, IT Director",
		"authorization_clause": "MSA schedule 3, clause 7.2 (authorised software removal)",
	}
}

// ---------------------------------------------------------------------------

// TestRemovalCampaignDryRunComputesScope covers the preview contract: which
// devices, which versions, what would be deleted, what is left behind, and
// what the platform cannot speak for.
func TestRemovalCampaignDryRunComputesScope(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "dryrun")

	campaignID := f.createCampaign(t)
	d := f.dryRun(t, campaignID)

	if d.DeviceCount != 2 {
		t.Fatalf("device_count = %d, want 2 (devices: %s)", d.DeviceCount, d.Devices)
	}

	var spread []struct {
		Version     string `json:"version"`
		DeviceCount int    `json:"device_count"`
	}
	if err := json.Unmarshal(d.VersionSpread, &spread); err != nil {
		t.Fatalf("decode version spread: %v", err)
	}
	if len(spread) != 2 {
		t.Fatalf("version spread = %v, want two versions", spread)
	}
	for _, s := range spread {
		if s.DeviceCount != 1 {
			t.Fatalf("version %s counted %d devices, want 1", s.Version, s.DeviceCount)
		}
	}

	if d.EvidenceBasis != "identifier_match" {
		t.Fatalf("evidence_basis = %q, want identifier_match (matched on bundle id)", d.EvidenceBasis)
	}
	// The device that has never reported an application is neither in nor
	// out of scope, and must be visible as such.
	if d.DevicesWithoutAppInventory != 1 {
		t.Fatalf("devices_without_app_inventory = %d, want 1", d.DevicesWithoutAppInventory)
	}
	if d.ArtefactEnumerationComplete {
		t.Fatal("artefact_enumeration_complete must be false: the platform has no vendor uninstall manifest")
	}
	if !strings.Contains(string(d.Artefacts), "/Applications/Acme Chat.app") {
		t.Fatalf("observed bundle path missing from artefacts: %s", d.Artefacts)
	}
	if len(d.Residue) < 3 {
		t.Fatalf("residue must be reported: %s", d.Residue)
	}
	if protectedMatchPresent(d) {
		t.Fatalf("unprotected product reported a protected match: %s", d.ProtectedMatch)
	}
	if d.ExcludedDeviceCount != 0 {
		t.Fatalf("excluded_device_count = %d, want 0", d.ExcludedDeviceCount)
	}
	if d.Stale {
		t.Fatalf("a preview computed a moment ago is stale: %v", d.StalenessReasons)
	}
	if d.InventoryWatermark == nil {
		t.Fatal("inventory_watermark must be recorded for a tenant with devices")
	}

	// The campaign has moved to dry_run, and only that far.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM removal_campaigns WHERE id = $1::uuid`, campaignID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "dry_run" {
		t.Fatalf("status after dry run = %q, want dry_run", status)
	}
}

// TestRemovalAuthorizeHappyPath proves the whole chain succeeds when every
// gate is satisfied, so the refusal tests below are refusing for their stated
// reason and not because the path never worked.
func TestRemovalAuthorizeHappyPath(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "authorize")

	campaignID := f.createCampaign(t)
	dryRun := f.dryRun(t, campaignID)

	body := validAuthorizeBody()
	body["dry_run_id"] = dryRun.ID
	rec := f.authorize(t, campaignID, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("authorize: got %d, body %s", rec.Code, rec.Body.String())
	}
	var a removalAuthorizationJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode authorization: %v", err)
	}
	if a.DryRunID != dryRun.ID {
		t.Fatalf("authorization cites dry run %s, want %s", a.DryRunID, dryRun.ID)
	}
	if a.PolicyID == nil || *a.PolicyID != f.policyID {
		t.Fatalf("authorization policy_id = %v, want %d", a.PolicyID, f.policyID)
	}
	if !strings.Contains(string(a.PolicySnapshot), "unapproved") {
		t.Fatalf("policy snapshot did not capture the decision: %s", a.PolicySnapshot)
	}

	// A second authorisation is refused: one campaign, one authorisation.
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusConflict {
		t.Fatalf("second authorize: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}

	detail := removalDo(t, f.router, http.MethodGet, "/admin/tenants/"+f.tenantID+"/removal-campaigns/"+campaignID, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail: got %d, body %s", detail.Code, detail.Body.String())
	}
	var got removalCampaignDetailResp
	if err := json.Unmarshal(detail.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if got.Campaign.Status != "authorized" {
		t.Fatalf("campaign status = %q, want authorized", got.Campaign.Status)
	}
	if got.Authorization == nil {
		t.Fatal("detail carries no authorization")
	}
	if got.Delivered {
		t.Fatal("delivered must be false: this slice ships no delivery path at all")
	}
}

// TestRemovalAuthorizeRejectsStaleDryRun is the "a stale preview is worse
// than none" rule, enforced rather than warned about.
func TestRemovalAuthorizeRejectsStaleDryRun(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "stale")

	campaignID := f.createCampaign(t)
	f.dryRun(t, campaignID)

	// A device uploads inventory after the preview was computed. Whatever
	// the preview enumerated, it is no longer a statement about now.
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET last_seen = now() + interval '1 second' WHERE id = $1::uuid`, f.deviceA); err != nil {
		t.Fatalf("bump last_seen: %v", err)
	}

	rec := f.authorize(t, campaignID, validAuthorizeBody())
	if rec.Code != http.StatusConflict {
		t.Fatalf("authorize with stale dry run: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stale") {
		t.Fatalf("refusal does not name staleness: %s", rec.Body.String())
	}

	// Still refused, and the campaign was not moved.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM removal_campaigns WHERE id = $1::uuid`, campaignID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "dry_run" {
		t.Fatalf("status = %q, want dry_run (a refused authorisation must not advance the campaign)", status)
	}

	// Re-running the dry run is the documented remedy, and it works.
	f.dryRun(t, campaignID)
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusCreated {
		t.Fatalf("authorize after re-running the dry run: got %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestRemovalAuthorizeRejectsSupersededDryRun proves a caller cannot pin an
// older preview by citing its id once a newer one exists.
func TestRemovalAuthorizeRejectsSupersededDryRun(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "superseded")

	campaignID := f.createCampaign(t)
	first := f.dryRun(t, campaignID)
	second := f.dryRun(t, campaignID)
	if first.ID == second.ID {
		t.Fatal("re-running a dry run must append a new snapshot, not overwrite")
	}

	body := validAuthorizeBody()
	body["dry_run_id"] = first.ID
	rec := f.authorize(t, campaignID, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("authorize citing a superseded dry run: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRemovalCreateRejectsBaselineProtectedProduct: the shared baseline
// protects the customer's EDR whatever any tenant later decides.
func TestRemovalCreateRejectsBaselineProtectedProduct(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "baseline-protected")

	rec := removalDo(t, f.router, http.MethodPost, "/admin/tenants/"+f.tenantID+"/removal-campaigns", map[string]any{
		"name":       "CrowdStrike Falcon Sensor",
		"platform":   "any",
		"created_by": f.createdBy,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("create campaign against baseline-protected EDR: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "edr") {
		t.Fatalf("refusal does not name the protection category: %s", rec.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM removal_campaigns WHERE tenant_id = $1::uuid AND name = 'CrowdStrike Falcon Sensor'`,
		f.tenantID).Scan(&count); err != nil {
		t.Fatalf("count campaigns: %v", err)
	}
	if count != 0 {
		t.Fatalf("a refused campaign was still written (%d rows)", count)
	}
}

// TestRemovalAuthorizeRejectsTenantProtectedProduct is the untestable-around
// case the ticket asks for: the campaign was legitimate when drafted and
// previewed, and the product became protected afterwards. Authorisation must
// still be impossible, and the refusal must come from the same protected
// list every other governance write path uses.
func TestRemovalAuthorizeRejectsTenantProtectedProduct(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "tenant-protected")

	campaignID := f.createCampaign(t)
	f.dryRun(t, campaignID)

	// The tenant adds their own protection for this product after the fact.
	if _, err := pool.Exec(ctx, `
		INSERT INTO protected_software (tenant_id, category, vendor, product_name, bundle_id, reason, added_by)
		VALUES ($1::uuid, 'customer_defined', 'Acme', $2, $3, 'Required by the finance team', 'test')
	`, f.tenantID, f.product, f.bundleID); err != nil {
		t.Fatalf("insert tenant protection: %v", err)
	}

	rec := f.authorize(t, campaignID, validAuthorizeBody())
	if rec.Code != http.StatusConflict {
		t.Fatalf("authorize protected product: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "protected software") {
		t.Fatalf("refusal does not name the protected list: %s", rec.Body.String())
	}

	var authCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM removal_campaign_authorizations WHERE campaign_id = $1::uuid`, campaignID).Scan(&authCount); err != nil {
		t.Fatalf("count authorizations: %v", err)
	}
	if authCount != 0 {
		t.Fatalf("a protected product was authorised (%d authorisation rows)", authCount)
	}

	// Re-running the dry run now reports the exclusion rather than hiding
	// it, and re-running does not launder the protection away.
	d := f.dryRun(t, campaignID)
	if !protectedMatchPresent(d) {
		t.Fatal("dry run does not report the protected match")
	}
	if d.ExcludedDeviceCount != d.DeviceCount || d.DeviceCount == 0 {
		t.Fatalf("excluded_device_count = %d, device_count = %d: protection excludes every candidate device",
			d.ExcludedDeviceCount, d.DeviceCount)
	}
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusConflict {
		t.Fatalf("authorize after re-running the dry run: got %d, want 409", rec.Code)
	}
}

// TestRemovalAuthorizeRequiresAuthorizerAndClause: a removal cannot be
// authorised anonymously or without pointing at a contract term.
func TestRemovalAuthorizeRequiresAuthorizerAndClause(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "required-fields")

	campaignID := f.createCampaign(t)
	f.dryRun(t, campaignID)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no authorised_by", map[string]any{"authorization_clause": "MSA schedule 3, clause 7.2"}},
		{"no clause", map[string]any{"authorized_by": "Jane Doe"}},
		{"both blank", map[string]any{"authorized_by": "   ", "authorization_clause": "\t"}},
		{"neither field", map[string]any{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := f.authorize(t, campaignID, c.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}

	// The database refuses the same thing independently of the handler.
	var dryRunID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM removal_campaign_dry_runs WHERE campaign_id = $1::uuid`, campaignID).Scan(&dryRunID); err != nil {
		t.Fatalf("read dry run id: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO removal_campaign_authorizations (campaign_id, tenant_id, dry_run_id, authorized_by, authorization_clause)
		VALUES ($1::uuid, $2::uuid, $3::uuid, '  ', 'clause')
	`, campaignID, f.tenantID, dryRunID); err == nil {
		t.Fatal("database accepted a blank authorized_by")
	}
}

// TestRemovalAuthorizeRequiresUnapprovedPolicy: you may not authorise
// removing a product your own governance record calls approved.
func TestRemovalAuthorizeRequiresUnapprovedPolicy(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "policy-state")

	campaignID := f.createCampaign(t)
	f.dryRun(t, campaignID)

	if _, err := pool.Exec(ctx,
		`UPDATE tenant_app_policies SET policy = 'approved' WHERE id = $1`, f.policyID); err != nil {
		t.Fatalf("flip policy: %v", err)
	}
	rec := f.authorize(t, campaignID, validAuthorizeBody())
	if rec.Code != http.StatusConflict {
		t.Fatalf("authorize against an approved policy: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}

	// With no policy cited at all it is a 400, not a silent pass.
	var noPolicyCampaign string
	if err := pool.QueryRow(ctx, `
		INSERT INTO removal_campaigns (tenant_id, bundle_id, name, platform, created_by)
		VALUES ($1::uuid, $2, $3, 'macos', 'andy') RETURNING id::text
	`, f.tenantID, f.bundleID, f.product).Scan(&noPolicyCampaign); err != nil {
		t.Fatalf("insert campaign without policy: %v", err)
	}
	f.dryRun(t, noPolicyCampaign)
	if rec := f.authorize(t, noPolicyCampaign, validAuthorizeBody()); rec.Code != http.StatusBadRequest {
		t.Fatalf("authorize with no policy cited: got %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRemovalCreateRequiresOperatorPolicy refuses a portal decision before a
// campaign exists. An operator can adopt the same decision through the admin
// policy writer, which stamps source = 'operator'.
func TestRemovalCreateRequiresOperatorPolicy(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "portal-create")

	f.setPortalPolicy(t)

	rec := removalDo(t, f.router, http.MethodPost, "/admin/tenants/"+f.tenantID+"/removal-campaigns", map[string]any{
		"bundle_id":  f.bundleID,
		"name":       f.product,
		"platform":   f.platform,
		"policy_id":  f.policyID,
		"reason":     "Unapproved chat client, replaced by the sanctioned one.",
		"created_by": f.createdBy,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("create against portal policy: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "portal") || !strings.Contains(rec.Body.String(), "adopt") {
		t.Fatalf("refusal does not explain operator adoption: %s", rec.Body.String())
	}

	var campaignCount int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM removal_campaigns WHERE tenant_id = $1::uuid`, f.tenantID).Scan(&campaignCount); err != nil {
		t.Fatalf("count campaigns: %v", err)
	}
	if campaignCount != 0 {
		t.Fatalf("portal policy refusal still wrote %d campaign rows", campaignCount)
	}

	f.adoptPolicy(t)
	_ = f.createCampaign(t)
}

// TestRemovalAuthorizeRequiresOperatorPolicy refuses a portal decision without
// changing the previewed campaign or recording an authorisation. Once an
// operator adopts the policy, the existing preview can be authorised.
func TestRemovalAuthorizeRequiresOperatorPolicy(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "portal-authorize")

	campaignID := f.createCampaign(t)
	dryRun := f.dryRun(t, campaignID)
	f.setPortalPolicy(t)

	body := validAuthorizeBody()
	body["dry_run_id"] = dryRun.ID
	rec := f.authorize(t, campaignID, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("authorize against portal policy: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "portal") || !strings.Contains(rec.Body.String(), "adopt") {
		t.Fatalf("refusal does not explain operator adoption: %s", rec.Body.String())
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM removal_campaigns WHERE id = $1::uuid`, campaignID).Scan(&status); err != nil {
		t.Fatalf("read campaign status: %v", err)
	}
	if status != "dry_run" {
		t.Fatalf("status = %q, want dry_run after refused authorisation", status)
	}
	var authorizationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM removal_campaign_authorizations WHERE campaign_id = $1::uuid`, campaignID).Scan(&authorizationCount); err != nil {
		t.Fatalf("count authorizations: %v", err)
	}
	if authorizationCount != 0 {
		t.Fatalf("portal policy refusal still wrote %d authorisation rows", authorizationCount)
	}

	f.adoptPolicy(t)
	if rec := f.authorize(t, campaignID, body); rec.Code != http.StatusCreated {
		t.Fatalf("authorize after operator adoption: got %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestRemovalAuthorizeRequiresDryRun: a draft campaign has no preview, so
// there is nothing to authorise against.
func TestRemovalAuthorizeRequiresDryRun(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "no-dryrun")

	campaignID := f.createCampaign(t)
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusConflict {
		t.Fatalf("authorize a draft campaign: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRemovalEvidenceIsAppendOnly checks the database itself, not the Go
// layer: an authorisation that the application refuses to change but the
// database would happily let anyone edit is not an audit record.
func TestRemovalEvidenceIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "append-only")

	campaignID := f.createCampaign(t)
	dryRun := f.dryRun(t, campaignID)
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusCreated {
		t.Fatalf("authorize: got %d, body %s", rec.Code, rec.Body.String())
	}

	mutations := []struct {
		name string
		sql  string
		args []any
		// want is the substring the refusal must contain. Every case is the
		// append-only trigger except TRUNCATE of the dry-run table, which
		// Postgres refuses earlier: the authorisation table's foreign key
		// references it, so the truncate never reaches a trigger. Both are
		// the database refusing; the test pins which refusal, so a trigger
		// that stopped firing could not hide behind the other message.
		want string
	}{
		{"UPDATE authorization", `UPDATE removal_campaign_authorizations SET authorized_by = 'someone else' WHERE campaign_id = $1::uuid`, []any{campaignID}, "append-only"},
		{"DELETE authorization", `DELETE FROM removal_campaign_authorizations WHERE campaign_id = $1::uuid`, []any{campaignID}, "append-only"},
		{"UPDATE dry run", `UPDATE removal_campaign_dry_runs SET device_count = 0 WHERE id = $1::uuid`, []any{dryRun.ID}, "append-only"},
		{"DELETE dry run", `DELETE FROM removal_campaign_dry_runs WHERE id = $1::uuid`, []any{dryRun.ID}, "append-only"},
		{"TRUNCATE authorizations", `TRUNCATE removal_campaign_authorizations`, nil, "append-only"},
		{"TRUNCATE dry runs", `TRUNCATE removal_campaign_dry_runs`, nil, "cannot truncate a table referenced in a foreign key constraint"},
		// Deleting the parent campaign cascades into the evidence tables, so
		// it has to be refused too. An authorisation you could erase by
		// deleting its campaign is not append-only in any useful sense.
		{"DELETE campaign", `DELETE FROM removal_campaigns WHERE id = $1::uuid`, []any{campaignID}, "append-only"},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, m.sql, m.args...)
			if err == nil {
				t.Fatalf("database permitted %s", m.name)
			}
			if !strings.Contains(err.Error(), m.want) {
				t.Fatalf("%s failed for the wrong reason (want %q): %v", m.name, m.want, err)
			}
		})
	}

	// The record is intact after every attempt.
	var authorizedBy string
	if err := pool.QueryRow(ctx,
		`SELECT authorized_by FROM removal_campaign_authorizations WHERE campaign_id = $1::uuid`, campaignID).Scan(&authorizedBy); err != nil {
		t.Fatalf("read authorization: %v", err)
	}
	if authorizedBy != "Jane Doe, IT Director" {
		t.Fatalf("authorized_by = %q, want the original authoriser", authorizedBy)
	}
}

// TestRemovalEvidenceErasedWithTenant is the deliberate exemption in the
// append-only trigger: erasing a tenant erases their records, while every
// ordinary mutation stays refused (proved above). Without this, deleting a
// tenant would fail outright wherever a campaign had ever been previewed.
func TestRemovalEvidenceErasedWithTenant(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "tenant-erasure")

	campaignID := f.createCampaign(t)
	f.dryRun(t, campaignID)
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusCreated {
		t.Fatalf("authorize: got %d, body %s", rec.Code, rec.Body.String())
	}

	if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, f.tenantID); err != nil {
		t.Fatalf("tenant erasure blocked by the append-only trigger: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM removal_campaign_authorizations WHERE tenant_id = $1::uuid`, f.tenantID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("%d authorisation rows survived tenant erasure", remaining)
	}
}

// TestRemovalDryRunFailsClosedOnOversizedScope: a scope too large to
// enumerate is refused, never truncated. A partial device list presented as
// the removal scope is a false claim about the estate.
func TestRemovalDryRunFailsClosedOnOversizedScope(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "oversized")

	restore := removal.SetMaxMatchedRowsForTest(1)
	defer restore()

	campaignID := f.createCampaign(t)
	rec := removalDo(t, f.router, http.MethodPost,
		"/admin/tenants/"+f.tenantID+"/removal-campaigns/"+campaignID+"/dry-run",
		map[string]any{"computed_by": f.createdBy})
	if rec.Code != http.StatusConflict {
		t.Fatalf("oversized dry run: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM removal_campaign_dry_runs WHERE campaign_id = $1::uuid`, campaignID).Scan(&count); err != nil {
		t.Fatalf("count dry runs: %v", err)
	}
	if count != 0 {
		t.Fatalf("a refused dry run was still recorded (%d rows)", count)
	}
}

// TestRemovalCampaignCancel: a draft or previewed campaign can be abandoned;
// an authorised one cannot, because its authorisation record would stand.
func TestRemovalCampaignCancel(t *testing.T) {
	ctx := context.Background()
	pool := catConnectOrSkip(t)
	defer pool.Close()
	f := seedRemovalFixture(t, ctx, pool, "cancel")

	campaignID := f.createCampaign(t)
	rec := removalDo(t, f.router, http.MethodPost,
		"/admin/tenants/"+f.tenantID+"/removal-campaigns/"+campaignID+"/cancel",
		map[string]any{"cancelled_by": "andy", "reason": "Superseded by a licence renewal."})
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel: got %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := f.authorize(t, campaignID, validAuthorizeBody()); rec.Code != http.StatusConflict {
		t.Fatalf("authorize a cancelled campaign: got %d, want 409", rec.Code)
	}

	authorized := f.createCampaign(t)
	f.dryRun(t, authorized)
	if rec := f.authorize(t, authorized, validAuthorizeBody()); rec.Code != http.StatusCreated {
		t.Fatalf("authorize: got %d, body %s", rec.Code, rec.Body.String())
	}
	rec = removalDo(t, f.router, http.MethodPost,
		"/admin/tenants/"+f.tenantID+"/removal-campaigns/"+authorized+"/cancel",
		map[string]any{"cancelled_by": "andy", "reason": "Changed my mind."})
	if rec.Code != http.StatusConflict {
		t.Fatalf("cancel an authorised campaign: got %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}
