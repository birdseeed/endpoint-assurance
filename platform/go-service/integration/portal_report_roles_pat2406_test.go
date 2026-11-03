//go:build integration

package integration

// PAT-2406 and PAT-2408 item 1: the owner's ruling of 5 October 2026.
// "Viewers can generate reports but only admins change schedules; the Local
// Admin report is admin-only."
//
// These tests go through the real router, the real portalauth middleware and
// real portal_users rows. Each one pins a route a viewer could otherwise use
// to change tenant configuration or to obtain the standing local-administrator
// roster (account names, personal data) that GET /v1/portal/local-admins has
// refused to a viewer since PAT-2215.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/reportsched"
)

const pat2406LocalAdminType = "local-admin"

// pat2406Do sends a portal request and returns the status and whole body.
func pat2406Do(t *testing.T, method, path, token, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	resp := portalDo(t, method, path, token, rd)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}
	return resp.StatusCode, raw
}

// pat2406AssertAdminRequired asserts the refusal every admin-only portal route
// uses: 403 with {"error":"admin_role_required","message":...}.
func pat2406AssertAdminRequired(t *testing.T, label string, status int, body []byte) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Errorf("%s = %d, want 403 (body %.160q)", label, status, body)
		return
	}
	var out struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Error != "admin_role_required" || out.Message == "" {
		t.Errorf("%s body = %.160q, want {error: admin_role_required, message: ...}", label, body)
	}
}

type pat2406ReportList struct {
	Total   int `json:"total"`
	Reports []struct {
		ID         string `json:"id"`
		ReportType string `json:"report_type"`
	} `json:"reports"`
}

func pat2406List(t *testing.T, token, query string) pat2406ReportList {
	t.Helper()
	status, body := pat2406Do(t, http.MethodGet, "/v1/portal/reports"+query, token, "")
	if status != http.StatusOK {
		t.Fatalf("GET /v1/portal/reports%s = %d: %.160q", query, status, body)
	}
	var out pat2406ReportList
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode report list: %v", err)
	}
	return out
}

// pat2406SeedRoster puts one named standing administrator on a new device of
// the tenant and returns the account name, so a test can prove the admin's
// report carries it and no viewer response does.
func pat2406SeedRoster(t *testing.T, e *pat2405Estate) string {
	t.Helper()
	name := "pat2406-roster-" + randomHex(4)
	deviceID := govDevice(t, e.id, "roster-"+randomHex(3), "macOS", time.Now().UTC())
	if _, err := env.pool.Exec(context.Background(),
		`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin) VALUES ($1::uuid, $2, 'user', false)`,
		deviceID, name); err != nil {
		t.Fatalf("seed local_admin_accounts: %v", err)
	}
	return name
}

// pat2406Demote makes an admin a viewer. portal_users stores the address
// lower-cased; the update must change exactly one row or the test that
// follows would pass or fail for the wrong reason.
func pat2406Demote(t *testing.T, email string) {
	t.Helper()
	tag, err := env.pool.Exec(context.Background(),
		`UPDATE portal_users SET role = 'viewer' WHERE email = lower(btrim($1))`, email)
	if err != nil {
		t.Fatalf("demote admin: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("demote admin changed %d rows, want 1", tag.RowsAffected())
	}
}

func pat2406ScheduleCount(t *testing.T, tenantID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM portal_report_schedules WHERE tenant_id = $1::uuid`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count schedules: %v", err)
	}
	return n
}

func pat2406ReportCount(t *testing.T, tenantID, reportType string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM report_records WHERE tenant_id = $1::uuid AND source = 'portal' AND report_type = $2`,
		tenantID, reportType).Scan(&n); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// A. Report schedules: read by every role, changed by an admin only.
// ---------------------------------------------------------------------------

func TestPAT2406OnlyAnAdminChangesReportSchedules(t *testing.T) {
	a := pat2405SeedEstate(t, "roleschedA")
	b := pat2405SeedEstate(t, "roleschedB")
	const weekly = `{"cadence":"weekly","weekday":1,"hour_utc":7,"enabled":true}`
	const viewerAttempt = `{"cadence":"daily","hour_utc":22,"enabled":false}`
	puts := []string{
		"/v1/portal/reports/schedule",
		"/v1/portal/reports/schedules/patch-status",
		"/v1/portal/reports/schedules/" + pat2406LocalAdminType,
	}

	// A viewer cannot create a schedule, on either route.
	for _, path := range puts {
		status, body := pat2406Do(t, http.MethodPut, path, a.viewerToken, weekly)
		pat2406AssertAdminRequired(t, "viewer PUT "+path, status, body)
	}
	if n := pat2406ScheduleCount(t, a.id); n != 0 {
		t.Fatalf("viewer PUTs stored %d schedule row(s), want 0", n)
	}

	// An admin can, on both routes, exactly as before.
	for _, path := range puts {
		status, body := pat2406Do(t, http.MethodPut, path, a.adminToken, weekly)
		if status != http.StatusOK {
			t.Fatalf("admin PUT %s = %d, want 200: %.160q", path, status, body)
		}
	}

	// A viewer cannot change or disable an existing schedule.
	for _, path := range puts {
		status, body := pat2406Do(t, http.MethodPut, path, a.viewerToken, viewerAttempt)
		pat2406AssertAdminRequired(t, "viewer PUT (existing) "+path, status, body)
	}

	// Reading stays open to the viewer, and shows the admin's configuration
	// untouched by the refused writes.
	for _, path := range puts {
		for _, who := range []struct{ label, token string }{{"viewer", a.viewerToken}, {"admin", a.adminToken}} {
			status, body := pat2406Do(t, http.MethodGet, path, who.token, "")
			if status != http.StatusOK {
				t.Fatalf("%s GET %s = %d, want 200: %.160q", who.label, path, status, body)
			}
			var got scheduleResp
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if !got.Configured || !got.Enabled || got.Cadence != "weekly" || got.HourUTC == nil || *got.HourUTC != 7 {
				t.Errorf("%s GET %s = %s, want the admin's weekly 07:00 enabled schedule", who.label, path, body)
			}
		}
	}
	status, body := pat2406Do(t, http.MethodGet, "/v1/portal/reports/schedules", a.viewerToken, "")
	if status != http.StatusOK || bytes.Count(body, []byte(`"report_type"`)) != len(puts) {
		t.Errorf("viewer GET schedules = %d %.200q, want 200 with %d schedules", status, body, len(puts))
	}

	// Role is read at the point of use: a demoted admin is refused at once.
	pat2406Demote(t, a.adminEmail)
	status, body = pat2406Do(t, http.MethodPut, puts[0], a.adminToken, viewerAttempt)
	pat2406AssertAdminRequired(t, "demoted admin PUT", status, body)

	// Cross-tenant behaviour is unchanged: tenant B has no schedule, its
	// viewer is refused on its own tenant, and nothing of A's is visible.
	if n := pat2406ScheduleCount(t, b.id); n != 0 {
		t.Fatalf("tenant B has %d schedule row(s) after tenant A's writes, want 0", n)
	}
	status, body = pat2406Do(t, http.MethodGet, "/v1/portal/reports/schedule", b.viewerToken, "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"configured":false`)) {
		t.Errorf("tenant B viewer GET schedule = %d %.160q, want 200 unconfigured", status, body)
	}
	status, body = pat2406Do(t, http.MethodPut, puts[0], b.viewerToken, weekly)
	pat2406AssertAdminRequired(t, "tenant B viewer PUT", status, body)
}

// A viewer's malformed body is still a 400: validation runs before the role
// read, so the refusal never depends on the database being reachable.
func TestPAT2406ViewerInvalidScheduleBodyIsStill400(t *testing.T) {
	a := pat2405SeedEstate(t, "rolesched400")
	status, body := pat2406Do(t, http.MethodPut, "/v1/portal/reports/schedule", a.viewerToken, `{"cadence":"hourly"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("viewer invalid PUT = %d, want 400: %.160q", status, body)
	}
	status, body = pat2406Do(t, http.MethodPut, "/v1/portal/reports/schedules/no-such-type", a.viewerToken,
		`{"cadence":"daily","hour_utc":7,"enabled":true}`)
	if status != http.StatusBadRequest {
		t.Fatalf("viewer unknown type PUT = %d, want 400: %.160q", status, body)
	}
}

// ---------------------------------------------------------------------------
// B. Generating: open to a viewer, except the Local Admin report.
// ---------------------------------------------------------------------------

func TestPAT2406ViewerGeneratesReportsExceptLocalAdmin(t *testing.T) {
	a := pat2405SeedEstate(t, "rolegen")

	// A viewer still generates an ordinary report.
	status, body := pat2406Do(t, http.MethodPost, "/v1/portal/reports", a.viewerToken, `{"report_type":"executive-summary"}`)
	if status != http.StatusCreated {
		t.Fatalf("viewer generate executive-summary = %d, want 201: %.160q", status, body)
	}
	// ...and every other catalogue type it is offered.
	for _, reportType := range pat2405PortalCatalogueTypes(t, a.viewerToken) {
		status, body := pat2406Do(t, http.MethodPost, "/v1/portal/reports", a.viewerToken,
			fmt.Sprintf(`{"report_type":%q}`, reportType))
		if status != http.StatusCreated {
			t.Errorf("viewer generate %s (offered by its catalogue) = %d, want 201: %.160q", reportType, status, body)
		}
	}

	// The Local Admin report is refused, by either field name.
	for _, req := range []string{
		`{"report_type":"local-admin"}`,
		`{"type":"local-admin"}`,
		`{"report_type":"local-admin","type":"local-admin","name":"Roster"}`,
	} {
		status, body := pat2406Do(t, http.MethodPost, "/v1/portal/reports", a.viewerToken, req)
		pat2406AssertAdminRequired(t, "viewer generate "+req, status, body)
	}
	if n := pat2406ReportCount(t, a.id, pat2406LocalAdminType); n != 0 {
		t.Fatalf("refused viewer requests stored %d local-admin record(s), want 0", n)
	}

	// An admin generates it as before.
	status, body = pat2406Do(t, http.MethodPost, "/v1/portal/reports", a.adminToken, `{"report_type":"local-admin"}`)
	if status != http.StatusCreated {
		t.Fatalf("admin generate local-admin = %d, want 201: %.160q", status, body)
	}
}

// ---------------------------------------------------------------------------
// B. Downloading a stored Local Admin report, however it was generated.
// ---------------------------------------------------------------------------

func TestPAT2406LocalAdminReportDownloadIsAdminOnly(t *testing.T) {
	ctx := context.Background()
	a := pat2405SeedEstate(t, "roledlA")
	b := pat2405SeedEstate(t, "roledlB")
	rosterName := pat2406SeedRoster(t, a)

	manualID := pat2405Generate(t, a.adminToken, pat2406LocalAdminType, "Roster manual")
	otherID := pat2405Generate(t, a.adminToken, "patch-status", "Patch evidence")

	// A record generated by a schedule, not by a person.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO portal_report_schedules (tenant_id, report_type, cadence, weekday, hour_utc, enabled, next_run_at)
		VALUES ($1::uuid, $2, 'weekly', 1, 7, true, $3)`, a.id, pat2406LocalAdminType, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	reportsched.New(env.pool, handlers.PortalReportGenerator(env.pool)).Sweep(ctx)
	var scheduledID string
	if err := env.pool.QueryRow(ctx, `
		SELECT id::text FROM report_records
		WHERE tenant_id = $1::uuid AND source = 'portal' AND report_type = $2 AND schedule_slot IS NOT NULL`,
		a.id, pat2406LocalAdminType).Scan(&scheduledID); err != nil {
		t.Fatalf("no scheduled local-admin record: %v", err)
	}

	formats := []string{"", "format=pdf", "format=csv"}
	for _, rec := range []struct{ label, id string }{{"admin-generated", manualID}, {"scheduled", scheduledID}} {
		// Positive control: the admin's files exist and carry the roster.
		if d := pat2405Get(t, a.adminToken, rec.id, "format=pdf"); d.status != http.StatusOK || !d.isPDF() {
			t.Fatalf("admin pdf of %s record = %d pdf=%v, want 200 PDF", rec.label, d.status, d.isPDF())
		}
		d := pat2405Get(t, a.adminToken, rec.id, "format=csv")
		if d.status != http.StatusOK || !bytes.Contains(d.body, []byte(rosterName)) {
			t.Fatalf("admin csv of %s record = %d, roster name present=%v; the control needs the name in the file",
				rec.label, d.status, bytes.Contains(d.body, []byte(rosterName)))
		}
		// The viewer is refused in every format and gets no file bytes.
		for _, q := range formats {
			d := pat2405Get(t, a.viewerToken, rec.id, q)
			pat2406AssertAdminRequired(t, fmt.Sprintf("viewer GET %s record ?%s", rec.label, q), d.status, d.body)
			if d.isPDF() || bytes.Contains(d.body, []byte(rosterName)) || d.disposition != "" {
				t.Errorf("viewer GET %s record ?%s returned file content (pdf=%v name=%v disposition=%q)",
					rec.label, q, d.isPDF(), bytes.Contains(d.body, []byte(rosterName)), d.disposition)
			}
		}
		// Another tenant, admin or viewer, still sees "not found".
		for _, who := range []struct{ label, token string }{{"admin B", b.adminToken}, {"viewer B", b.viewerToken}} {
			for _, q := range formats {
				if d := pat2405Get(t, who.token, rec.id, q); d.status != http.StatusNotFound {
					t.Errorf("%s GET tenant A %s record ?%s = %d, want 404", who.label, rec.label, q, d.status)
				}
			}
		}
	}

	// Every other report stays downloadable by the viewer.
	if d := pat2405Get(t, a.viewerToken, otherID, "format=pdf"); d.status != http.StatusOK || !d.isPDF() {
		t.Errorf("viewer pdf of patch-status = %d pdf=%v, want 200 PDF", d.status, d.isPDF())
	}
	if d := pat2405Get(t, a.viewerToken, otherID, "format=csv"); d.status != http.StatusOK {
		t.Errorf("viewer csv of patch-status = %d, want 200", d.status)
	}

	// Role is read at the point of use: a demoted admin loses the download.
	pat2406Demote(t, a.adminEmail)
	d := pat2405Get(t, a.adminToken, manualID, "format=csv")
	pat2406AssertAdminRequired(t, "demoted admin GET local-admin csv", d.status, d.body)
}

// ---------------------------------------------------------------------------
// B. Listing and the catalogue: a viewer is not shown what it cannot have.
// ---------------------------------------------------------------------------

func TestPAT2406ViewerListAndCatalogueOmitLocalAdmin(t *testing.T) {
	a := pat2405SeedEstate(t, "rolelist")
	rosterIDs := map[string]bool{
		pat2405Generate(t, a.adminToken, pat2406LocalAdminType, "Roster one"): true,
		pat2405Generate(t, a.adminToken, pat2406LocalAdminType, "Roster two"): true,
	}
	pat2405Generate(t, a.adminToken, "patch-status", "Patch one")
	pat2405Generate(t, a.adminToken, "stale-endpoints", "Stale one")
	pat2405Generate(t, a.adminToken, "patch-status", "Patch two")

	adminList := pat2406List(t, a.adminToken, "")
	if adminList.Total != 5 || len(adminList.Reports) != 5 {
		t.Fatalf("admin list total=%d rows=%d, want 5 and 5", adminList.Total, len(adminList.Reports))
	}
	seen := 0
	for _, r := range adminList.Reports {
		if rosterIDs[r.ID] {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("admin list shows %d local-admin records, want 2", seen)
	}

	viewerList := pat2406List(t, a.viewerToken, "")
	if viewerList.Total != 3 || len(viewerList.Reports) != 3 {
		t.Errorf("viewer list total=%d rows=%d, want 3 and 3 (local-admin records omitted, total consistent)",
			viewerList.Total, len(viewerList.Reports))
	}
	for _, r := range viewerList.Reports {
		if rosterIDs[r.ID] || r.ReportType == pat2406LocalAdminType {
			t.Errorf("viewer list shows local-admin record %s", r.ID)
		}
	}
	// Paging counts the viewer's own rows, so no page is short or empty
	// because a hidden record took its place.
	page := pat2406List(t, a.viewerToken, "?limit=2&offset=0")
	if page.Total != 3 || len(page.Reports) != 2 {
		t.Errorf("viewer page 1 total=%d rows=%d, want 3 and 2", page.Total, len(page.Reports))
	}
	page = pat2406List(t, a.viewerToken, "?limit=2&offset=2")
	if page.Total != 3 || len(page.Reports) != 1 {
		t.Errorf("viewer page 2 total=%d rows=%d, want 3 and 1", page.Total, len(page.Reports))
	}

	type catalogueEntry struct {
		Type      string `json:"type"`
		AdminOnly *bool  `json:"admin_only"`
	}
	catalogue := func(token string) []catalogueEntry {
		t.Helper()
		status, body := pat2406Do(t, http.MethodGet, "/v1/portal/reports/catalogue", token, "")
		if status != http.StatusOK {
			t.Fatalf("GET catalogue = %d: %.160q", status, body)
		}
		var out struct {
			Reports []catalogueEntry `json:"reports"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode catalogue: %v", err)
		}
		return out.Reports
	}

	adminCat := catalogue(a.adminToken)
	if len(adminCat) != 14 {
		t.Errorf("admin catalogue has %d types, want 14", len(adminCat))
	}
	foundAdminOnly := false
	for _, entry := range adminCat {
		flagged := entry.AdminOnly != nil && *entry.AdminOnly
		if flagged != (entry.Type == pat2406LocalAdminType) {
			t.Errorf("admin catalogue %q admin_only = %v, want it set on local-admin only", entry.Type, flagged)
		}
		foundAdminOnly = foundAdminOnly || flagged
	}
	if !foundAdminOnly {
		t.Errorf("admin catalogue does not mark local-admin as admin_only")
	}

	viewerCat := catalogue(a.viewerToken)
	if len(viewerCat) != 13 {
		t.Errorf("viewer catalogue has %d types, want 13 (local-admin omitted)", len(viewerCat))
	}
	for _, entry := range viewerCat {
		if entry.Type == pat2406LocalAdminType || (entry.AdminOnly != nil && *entry.AdminOnly) {
			t.Errorf("viewer catalogue offers admin-only type %q", entry.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// The read-only service identity is never more than a viewer.
// ---------------------------------------------------------------------------

func TestPAT2406ServiceIdentityIsRefusedTheLocalAdminReport(t *testing.T) {
	a := pat2405SeedEstate(t, "rolesvc")
	rosterName := pat2406SeedRoster(t, a)
	rosterID := pat2405Generate(t, a.adminToken, pat2406LocalAdminType, "Service roster")
	otherID := pat2405Generate(t, a.adminToken, "encryption-posture", "Service other")

	const cn = "walker-pat2406.access" // placeholder
	v := portalauth.New(env.idp.issuer, env.idp.audience, env.idp.srv.URL).
		WithService(&portalauth.ServiceIdentity{CommonName: cn, TenantID: a.id})
	r := chi.NewRouter()
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Use(portalauth.Middleware(v, portalauth.DBLookup(env.pool), nil, portalauth.DBAudit(env.pool),
			portalauth.WithServiceTenantCheck(portalauth.DBTenantLive(env.pool))))
		pr.Get("/reports/catalogue", handlers.PortalReportCatalogueHandler(env.pool))
		pr.Get("/reports", handlers.PortalReportsListHandler(env.pool))
		pr.Get("/reports/{id}", handlers.PortalReportDownloadHandler(env.pool))
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	token := env.idp.tokenWith(t, jwt.MapClaims{
		"iss": env.idp.issuer, "aud": env.idp.audience, "common_name": cn,
		"sub": "", "type": "app",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	get := func(path string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set(portalauth.Header, token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	for _, q := range []string{"", "?format=pdf", "?format=csv"} {
		status, body := get("/v1/portal/reports/" + rosterID + q)
		pat2406AssertAdminRequired(t, "service GET local-admin record "+q, status, body)
		if bytes.Contains(body, []byte(rosterName)) {
			t.Errorf("service GET local-admin record %s carried the roster name", q)
		}
	}
	if status, _ := get("/v1/portal/reports/" + otherID + "?format=csv"); status != http.StatusOK {
		t.Errorf("service GET encryption-posture csv = %d, want 200 (unchanged)", status)
	}
	status, body := get("/v1/portal/reports")
	if status != http.StatusOK || bytes.Contains(body, []byte(rosterID)) || !bytes.Contains(body, []byte(otherID)) {
		t.Errorf("service list = %d, local-admin listed=%v, other listed=%v; want 200, false, true",
			status, bytes.Contains(body, []byte(rosterID)), bytes.Contains(body, []byte(otherID)))
	}
	status, body = get("/v1/portal/reports/catalogue")
	if status != http.StatusOK || bytes.Contains(body, []byte(`"local-admin"`)) {
		t.Errorf("service catalogue = %d, offers local-admin=%v; want 200 and false",
			status, bytes.Contains(body, []byte(`"local-admin"`)))
	}
}
