//go:build integration

package integration

// PAT-2009: software governance reporting (new software, drift, approved
// export, overview), the report registry entries, the unapproved software
// alert (admin action and ingest, deduped, tenant-isolated, webhook and
// contact email), and the opt-in daily new software notification.

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/softwaregov"
)

type govTenant struct {
	id, adminEmail, adminToken, viewerToken string
}

func newGovTenant(t *testing.T, label, contact string) *govTenant {
	t.Helper()
	suffix := randomHex(4)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2009-"+label+"-"+suffix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if contact != "" {
		if _, err := env.pool.Exec(context.Background(),
			`UPDATE tenants SET contact_email = $2 WHERE id = $1::uuid`, tenantID, contact); err != nil {
			t.Fatalf("set contact email: %v", err)
		}
	}
	g := &govTenant{id: tenantID, adminEmail: "admin-" + label + "-" + suffix + "@gov.example"}
	viewer := "viewer-" + label + "-" + suffix + "@gov.example"
	mapPortalUserWithRole(t, g.adminEmail, tenantID, "admin")
	mapPortalUserWithRole(t, viewer, tenantID, "")
	g.adminToken = env.idp.token(t, g.adminEmail)
	g.viewerToken = env.idp.token(t, viewer)
	return g
}

func govDevice(t *testing.T, tenantID, host, osName string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, '15.1', $5) RETURNING id::text`,
		tenantID, "GOV-"+randomHex(5), host, osName, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

func govApp(t *testing.T, deviceID, name, identifier, team string) {
	t.Helper()
	var teamArg any
	if team != "" {
		teamArg = team
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, $2, $3, '1.0', $4)`, deviceID, name, identifier, teamArg); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

func govExtension(t *testing.T, deviceID, browser, extID, name string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_browser_extensions (device_id, browser, user_account, profile, extension_id, name)
		VALUES ($1::uuid, $2, 'user', 'Default', $3, $4)`, deviceID, browser, extID, name); err != nil {
		t.Fatalf("seed extension: %v", err)
	}
}

// govInstallation writes one software_installations row, the projection the
// new software view reads.
func govInstallation(t *testing.T, tenantID, deviceID, platform, kind, value, companion, name string, firstSeen time.Time, removed bool) {
	t.Helper()
	sum := sha256.Sum256([]byte(platform + "\x1f" + kind + "\x1f" + value + "\x1f" + companion))
	var removedAt any
	lastSeen := firstSeen
	if removed {
		removedAt = firstSeen.Add(time.Hour)
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO software_installations
		    (tenant_id, device_id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
		     identity_fingerprint, current_name, first_seen_at, last_seen_at, removed_at, provenance)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'inventory_payload')`,
		tenantID, deviceID, platform, kind, value, companion, hex.EncodeToString(sum[:]), name,
		firstSeen, lastSeen, removedAt); err != nil {
		t.Fatalf("seed installation: %v", err)
	}
}

func govWebhook(t *testing.T, tenantID string, events ...string) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO tenant_webhooks (tenant_id, url, secret, events)
		VALUES ($1::uuid, 'https://tickets.example.com/hook', $2, $3) RETURNING id::text`,
		tenantID, strings.Repeat("ab", 32), events).Scan(&id); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	return id
}

type govDelivery struct {
	EventType string          `json:"event_type"`
	TenantID  string          `json:"tenant_id"`
	Data      json.RawMessage `json:"data"`
}

func govDeliveries(t *testing.T, tenantID string) ([]govDelivery, []string) {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT d.payload::text FROM webhook_deliveries d
		JOIN tenant_webhooks w ON w.id = d.webhook_id
		WHERE w.tenant_id = $1::uuid AND d.event_type = 'software.unapproved_detected'
		ORDER BY d.id`, tenantID)
	if err != nil {
		t.Fatalf("query deliveries: %v", err)
	}
	defer rows.Close()
	var out []govDelivery
	var raw []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		var d govDelivery
		if err := json.Unmarshal([]byte(s), &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
		raw = append(raw, s)
	}
	return out, raw
}

type govAlert struct {
	ID         int64
	Trigger    string
	DeviceID   *string
	EmailState string
	Payload    softwaregov.AlertPayload
}

func govAlerts(t *testing.T, tenantID string) []govAlert {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT id, trigger, device_id::text, email_state, payload::text
		FROM software_unapproved_alerts WHERE tenant_id = $1::uuid ORDER BY id`, tenantID)
	if err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	defer rows.Close()
	var out []govAlert
	for rows.Next() {
		var a govAlert
		var payload string
		if err := rows.Scan(&a.ID, &a.Trigger, &a.DeviceID, &a.EmailState, &payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(payload), &a.Payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// fakeMailer records every message the runner sends.
type fakeMailer struct {
	mu   sync.Mutex
	sent []graphmail.Message
	err  error
	// onSend, when set, runs before the send is recorded (PAT-2097: to
	// change state while a digest is in flight).
	onSend func()
}

func (f *fakeMailer) Send(_ context.Context, m graphmail.Message) error {
	if f.onSend != nil {
		f.onSend()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeMailer) From() string { return "noreply@patched.test" }

func (f *fakeMailer) to(addr string) []graphmail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []graphmail.Message
	for _, m := range f.sent {
		for _, to := range m.To {
			if to == addr {
				out = append(out, m)
			}
		}
	}
	return out
}

func runRunner(t *testing.T, mail *fakeMailer, at time.Time) {
	t.Helper()
	r := softwaregov.NewRunner(env.pool, mail, softwaregov.WithClock(func() time.Time { return at }))
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("runner: %v", err)
	}
}

func getJSON(t *testing.T, path, token string, out any) {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, raw)
	}
	decodeJSON(t, resp, out)
}

func getCSV(t *testing.T, path, token string) [][]string {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type = %q", ct)
	}
	rows, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	return rows
}

// ---------------------------------------------------------------------------
// New software
// ---------------------------------------------------------------------------

func TestNewSoftwareSinceLastReview(t *testing.T) {
	g := newGovTenant(t, "new", "")
	now := time.Now().UTC()
	mac := govDevice(t, g.id, "mac-new-01", "macOS", now)
	win := govDevice(t, g.id, "win-new-01", "Windows", now)
	// Evidence for the review: a macOS bundle with its Team ID.
	govApp(t, mac, "Reviewed App", "com.gov.reviewed", "ABCDE12345")

	// Before any review: everything the estate has reported is new.
	govInstallation(t, g.id, mac, "macos", "macos_bundle_team", "com.gov.reviewed", "ABCDE12345", "Reviewed App", now.Add(-10*24*time.Hour), false)
	govInstallation(t, g.id, win, "windows", "windows_native", "{old-before-review}", "", "Old Tool", now.Add(-2*time.Hour), false)
	// Seen long ago on one device and since removed, then seen on another
	// device now: the product is not new to the tenant.
	win2 := govDevice(t, g.id, "win-new-02", "Windows", now)
	govInstallation(t, g.id, win, "windows", "windows_native", "com.gov.returning", "", "Returning", now.Add(-40*24*time.Hour), true)
	govInstallation(t, g.id, win2, "windows", "windows_native", "com.gov.returning", "", "Returning", now.Add(-time.Minute), false)

	var before softwaregov.NewSoftware
	getJSON(t, "/v1/portal/software/new", g.viewerToken, &before)
	if before.SinceBasis != softwaregov.SinceNoReview || before.Since != nil || before.Total != 3 {
		t.Fatalf("before review: basis=%s since=%v total=%d", before.SinceBasis, before.Since, before.Total)
	}

	// The review: an admin decision.
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.reviewed", "ABCDE12345")))
	time.Sleep(20 * time.Millisecond)
	after := time.Now().UTC()
	govInstallation(t, g.id, win, "windows", "windows_winget", "vendor.newtool", "", "New Tool", after, false)
	govInstallation(t, g.id, mac, "macos", "display_name", "mystery", "", "Mystery", after, false)

	var ns softwaregov.NewSoftware
	getJSON(t, "/v1/portal/software/new", g.viewerToken, &ns)
	if ns.SinceBasis != softwaregov.SinceLastReview || ns.LastReviewAt == nil || ns.Since == nil {
		t.Fatalf("basis = %s, last review = %v", ns.SinceBasis, ns.LastReviewAt)
	}
	names := map[string]softwaregov.NewProduct{}
	for _, p := range ns.Products {
		names[p.Name] = p
	}
	if len(ns.Products) != 2 || names["New Tool"].Name == "" || names["Mystery"].Name == "" {
		t.Fatalf("new since review = %+v, want New Tool and Mystery only", ns.Products)
	}
	if _, seen := names["Old Tool"]; seen {
		t.Fatal("a product first seen before the last review was listed as new")
	}
	nt := names["New Tool"]
	if nt.DeviceCount != 1 || nt.FirstDevice.Hostname != "win-new-01" || nt.ProductKey == nil ||
		*nt.ProductKey != "application:windows:vendor.newtool" || nt.ApprovalState != softwaregov.StateUnreviewed {
		t.Fatalf("New Tool = %+v", nt)
	}
	if m := names["Mystery"]; m.IdentityBasis != "name_only" || m.ProductKey != nil {
		t.Fatalf("a name-only product must carry no product key: %+v", m)
	}

	// An explicit date overrides the review.
	var explicit softwaregov.NewSoftware
	getJSON(t, "/v1/portal/software/new?since="+now.Add(-3*time.Hour).Format(time.RFC3339), g.viewerToken, &explicit)
	if explicit.SinceBasis != softwaregov.SinceQuery || explicit.Total != 3 {
		t.Fatalf("explicit since: basis=%s total=%d %+v", explicit.SinceBasis, explicit.Total, explicit.Products)
	}

	rows := getCSV(t, "/v1/portal/software/new?format=csv", g.viewerToken)
	if len(rows) != 3 || rows[0][0] != "first_seen_at" || rows[0][1] != "name" {
		t.Fatalf("csv = %v", rows)
	}

	for _, bad := range []string{"?since=yesterday", "?format=xml", "?tenant_id=" + g.id} {
		resp := portalDo(t, http.MethodGet, "/v1/portal/software/new"+bad, g.viewerToken, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET new%s = %d, want 400", bad, resp.StatusCode)
		}
	}
}

func TestNewSoftwareEmptyStaleAndIsolated(t *testing.T) {
	empty := newGovTenant(t, "new-empty", "")
	var ns softwaregov.NewSoftware
	getJSON(t, "/v1/portal/software/new", empty.viewerToken, &ns)
	if ns.Total != 0 || len(ns.Products) != 0 || ns.Coverage.DevicesTotal != 0 || ns.Coverage.Complete {
		t.Fatalf("empty tenant = %+v", ns)
	}

	g := newGovTenant(t, "new-stale", "")
	now := time.Now().UTC()
	fresh := govDevice(t, g.id, "fresh-01", "macOS", now)
	stale := govDevice(t, g.id, "stale-01", "macOS", now.Add(-30*24*time.Hour))
	govDevice(t, g.id, "silent-01", "Windows", now) // reported no software at all
	govInstallation(t, g.id, fresh, "macos", "macos_bundle", "com.gov.fresh", "", "Fresh", now.Add(-time.Hour), false)
	govInstallation(t, g.id, stale, "macos", "macos_bundle", "com.gov.stale", "", "Stale", now.Add(-31*24*time.Hour), false)
	getJSON(t, "/v1/portal/software/new", g.viewerToken, &ns)
	c := ns.Coverage
	if c.DevicesTotal != 3 || c.DevicesStale != 1 || c.DevicesWithoutInventory != 1 || c.Complete {
		t.Fatalf("partial and stale coverage = %+v", c)
	}

	// Another tenant never sees these products.
	var other softwaregov.NewSoftware
	getJSON(t, "/v1/portal/software/new", empty.viewerToken, &other)
	if other.Total != 0 {
		t.Fatalf("tenant isolation: %+v", other.Products)
	}
}

// ---------------------------------------------------------------------------
// Drift, overview, approved export
// ---------------------------------------------------------------------------

func TestSoftwareDriftOverviewAndApprovedExport(t *testing.T) {
	g := newGovTenant(t, "drift", "")
	other := newGovTenant(t, "drift-other", "")
	now := time.Now().UTC()
	d1 := govDevice(t, g.id, "drift-mac-01", "macOS", now)
	d2 := govDevice(t, g.id, "drift-mac-02", "macOS", now.Add(-20*24*time.Hour)) // stale
	govDevice(t, g.id, "drift-empty", "macOS", now)                              // no inventory
	govApp(t, d1, "Bad App", "com.gov.bad", "BADTEAM123")
	govApp(t, d2, "Bad App", "com.gov.bad", "BADTEAM123")
	govApp(t, d1, "Worse App", "com.gov.worse", "WORSETEAM1")
	govApp(t, d1, "Good App", "com.gov.good", "GOODTEAM12")
	govApp(t, d2, "Quiet App", "com.gov.quiet", "QUIETTEAM1")
	govApp(t, d2, "=HYPERLINK(\"x\")", "com.gov.formula", "")
	govExtension(t, d1, "chrome", "abcdefghijklmnopabcdefghijklmnop", "Nice Extension")

	// Before any decision the overview's figure is a real zero, not null.
	var ov struct {
		UnapprovedPresent      *int `json:"unapproved_present"`
		UnapprovedPresentItems []struct {
			Name        string `json:"name"`
			DeviceCount int    `json:"device_count"`
		} `json:"unapproved_present_items"`
	}
	getJSON(t, "/v1/portal/overview", g.viewerToken, &ov)
	if ov.UnapprovedPresent == nil || *ov.UnapprovedPresent != 0 || len(ov.UnapprovedPresentItems) != 0 {
		t.Fatalf("overview before any decision = %+v", ov)
	}

	mustApprove(t, g.adminToken, approvalBody("unapproved", "not allowed", macApp("com.gov.bad", "BADTEAM123"), macApp("com.gov.worse", "WORSETEAM1")))
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.good", "GOODTEAM12"), extItem("chrome", "abcdefghijklmnopabcdefghijklmnop")))
	mustApprove(t, g.adminToken, approvalBody("ignored", "", macApp("com.gov.quiet", "QUIETTEAM1")))
	// An operator approval keyed by name only: approved_via operator, no actor.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier, notes)
		VALUES ($1::uuid, 'Operator Approved Tool', 'any', 'approved', 'report_deploy', 'licensed')`, g.id); err != nil {
		t.Fatal(err)
	}
	// A recorded capture for last week, as the runner would have written.
	lastWeek := softwaregov.WeekStart(now).AddDate(0, 0, -7)
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO software_governance_weekly (tenant_id, week_start, installed_products, unapproved_products,
		    unreviewed_products, unapproved_devices, devices_total, devices_stale, captured_at)
		VALUES ($1::uuid, $2::date, 6, 0, 6, 0, 3, 0, $3)`, g.id, lastWeek, now.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	var d softwaregov.Drift
	getJSON(t, "/v1/portal/software/drift", g.viewerToken, &d)
	if d.Counts.Unapproved != 2 || d.Counts.Unreviewed != 1 || d.Counts.Approved != 2 || d.Counts.Ignored != 1 ||
		d.Counts.UnapprovedDevices != 2 || d.Counts.InstalledProducts != 6 {
		t.Fatalf("counts = %+v", d.Counts)
	}
	if d.Coverage.DevicesStale != 1 || d.Coverage.DevicesWithoutInventory != 1 || d.Coverage.Complete {
		t.Fatalf("coverage = %+v", d.Coverage)
	}
	for _, p := range d.Products {
		if p.ApprovalState != softwaregov.StateUnapproved && p.ApprovalState != softwaregov.StateUnreviewed {
			t.Fatalf("drift listed a %s product: %+v", p.ApprovalState, p)
		}
	}
	if len(d.Products) != 3 || d.Products[0].ProductKey != "application:macos:com.gov.bad:BADTEAM123" || d.Products[0].StaleDeviceCount != 1 {
		t.Fatalf("drift products = %+v", d.Products)
	}
	if len(d.UnapprovedPresent) != 2 {
		t.Fatalf("unapproved present = %+v", d.UnapprovedPresent)
	}
	bad := d.UnapprovedPresent[0]
	if bad.Name != "Bad App" || bad.DeviceCount != 2 || bad.StaleDeviceCount != 1 || bad.MarkedBy == nil ||
		*bad.MarkedBy != strings.ToLower(g.adminEmail) || bad.MarkedVia != "portal" || bad.MarkedAtBasis != "decision" || bad.Since.IsZero() {
		t.Fatalf("Bad App present = %+v", bad)
	}
	if len(d.TopDevices) != 2 || d.TopDevices[0].Hostname != "drift-mac-01" || d.TopDevices[0].UnapprovedProductCount != 2 {
		t.Fatalf("top devices = %+v", d.TopDevices)
	}
	if len(d.Trend) != softwaregov.TrendWeeks {
		t.Fatalf("trend points = %d", len(d.Trend))
	}
	last, prev, first := d.Trend[len(d.Trend)-1], d.Trend[len(d.Trend)-2], d.Trend[0]
	if !last.Live || !last.Recorded || *last.UnapprovedProducts != 2 {
		t.Fatalf("live week = %+v", last)
	}
	if !prev.Recorded || prev.Live || *prev.UnapprovedProducts != 0 || *prev.UnreviewedProducts != 6 {
		t.Fatalf("recorded week = %+v", prev)
	}
	if first.Recorded || first.UnapprovedProducts != nil {
		t.Fatalf("an unrecorded week must be null, not zero: %+v", first)
	}

	rows := getCSV(t, "/v1/portal/software/drift?format=csv", g.viewerToken)
	if len(rows) != 4 || rows[0][0] != "approval_state" || rows[1][0] != "unapproved" || rows[1][13] != strings.ToLower(g.adminEmail) {
		t.Fatalf("drift csv = %v", rows)
	}
	for _, r := range rows {
		if strings.HasPrefix(r[1], "=") {
			t.Fatalf("formula cell not neutralised: %v", r)
		}
	}

	getJSON(t, "/v1/portal/overview", g.viewerToken, &ov)
	if ov.UnapprovedPresent == nil || *ov.UnapprovedPresent != 2 || len(ov.UnapprovedPresentItems) != 2 ||
		ov.UnapprovedPresentItems[0].Name != "Bad App" || ov.UnapprovedPresentItems[0].DeviceCount != 2 {
		t.Fatalf("overview = %+v", ov)
	}

	var approved softwaregov.ApprovedList
	getJSON(t, "/v1/portal/software/approved", g.viewerToken, &approved)
	byName := map[string]softwaregov.ApprovedProduct{}
	for _, p := range approved.Products {
		byName[p.Name] = p
	}
	// Every tenant starts with the Patched agent pre-approved (PAT-1318); the
	// three decisions above come on top.
	var seeded int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid AND policy = 'approved'`, g.id).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if approved.Total != seeded+1 || approved.Total != len(approved.Products) {
		t.Fatalf("approved total = %d, want every approved application (%d) plus the extension", approved.Total, seeded)
	}
	good := byName["Good App"]
	if good.ApprovedVia != "portal" || good.ApprovedBy == nil || *good.ApprovedBy != strings.ToLower(g.adminEmail) || good.ApprovedAtBasis != "decision" {
		t.Fatalf("portal approval = %+v", good)
	}
	op := byName["Operator Approved Tool"]
	if op.ApprovedVia != "operator" || op.ApprovedBy != nil || op.ApprovedAtBasis != "policy_last_updated" || op.Justification == nil {
		t.Fatalf("operator approval = %+v", op)
	}
	if ext := byName["Nice Extension"]; ext.Type != "browser_extension" || ext.ApprovedVia != "portal" {
		t.Fatalf("extension approval = %+v", ext)
	}
	rows = getCSV(t, "/v1/portal/software/approved?format=csv", g.viewerToken)
	if len(rows) != approved.Total+1 || rows[0][10] != "approved_by" {
		t.Fatalf("approved csv = %v", rows)
	}

	// The other tenant sees none of it.
	var od softwaregov.Drift
	getJSON(t, "/v1/portal/software/drift", other.viewerToken, &od)
	if od.Counts.InstalledProducts != 0 || len(od.UnapprovedPresent) != 0 {
		t.Fatalf("tenant isolation: %+v", od.Counts)
	}
	var oa softwaregov.ApprovedList
	getJSON(t, "/v1/portal/software/approved", other.viewerToken, &oa)
	for _, p := range oa.Products {
		if p.Name == "Good App" || p.Name == "Operator Approved Tool" || p.Name == "Nice Extension" {
			t.Fatalf("tenant isolation: %+v", p)
		}
	}
}

func TestSoftwareGovernanceReportTypesGenerate(t *testing.T) {
	g := newGovTenant(t, "reports", "")
	dev := govDevice(t, g.id, "report-mac-01", "macOS", time.Now())
	govApp(t, dev, "Report App", "com.gov.report", "REPORTTEAM")
	govInstallation(t, g.id, dev, "macos", "macos_bundle", "com.gov.report", "", "Report App", time.Now().Add(-time.Hour), false)
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.report", "REPORTTEAM")))

	for _, rt := range []string{"new-software", "software-drift", "approved-software"} {
		resp := portalDo(t, http.MethodPost, "/v1/portal/reports", g.viewerToken,
			strings.NewReader(fmt.Sprintf(`{"report_type":%q}`, rt)))
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("POST report %s = %d: %s", rt, resp.StatusCode, raw)
		}
		var created struct {
			ID string `json:"id"`
		}
		decodeJSON(t, resp, &created)
		dl := portalDo(t, http.MethodGet, "/v1/portal/reports/"+created.ID, g.viewerToken, nil)
		body, _ := io.ReadAll(dl.Body)
		dl.Body.Close()
		if dl.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "%PDF") {
			t.Fatalf("download %s = %d, pdf=%v", rt, dl.StatusCode, strings.HasPrefix(string(body), "%PDF"))
		}

		adm, err := http.Get(env.internalSrv.URL + "/admin/reports/" + rt + "/" + g.id + ".pdf")
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(adm.Body)
		adm.Body.Close()
		if adm.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "%PDF") {
			t.Fatalf("admin %s pdf = %d", rt, adm.StatusCode)
		}
	}
	missing, err := http.Get(env.internalSrv.URL + "/admin/reports/software-drift/00000000-0000-0000-0000-000000000000.pdf")
	if err != nil {
		t.Fatal(err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant pdf = %d, want 404", missing.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

type notificationSettingsOut struct {
	UnapprovedAlertsEnabled bool    `json:"unapproved_alerts_enabled"`
	NewSoftwareEnabled      bool    `json:"new_software_enabled"`
	IsDefault               bool    `json:"is_default"`
	UpdatedBy               *string `json:"updated_by"`
	UnapprovedAlert         struct {
		EmailRecipient struct {
			Email      *string `json:"email"`
			Configured bool    `json:"configured"`
		} `json:"email_recipient"`
		WebhookEndpoints int `json:"webhook_endpoints"`
	} `json:"unapproved_alert"`
}

func TestSoftwareNotificationSettings(t *testing.T) {
	g := newGovTenant(t, "settings", "it@settings.example")
	govWebhook(t, g.id, "software.unapproved_detected")

	var s notificationSettingsOut
	getJSON(t, "/v1/portal/software-notifications", g.viewerToken, &s)
	if !s.UnapprovedAlertsEnabled || s.NewSoftwareEnabled || !s.IsDefault {
		t.Fatalf("defaults = %+v (unapproved on, new software off)", s)
	}
	if !s.UnapprovedAlert.EmailRecipient.Configured || *s.UnapprovedAlert.EmailRecipient.Email != "it@settings.example" ||
		s.UnapprovedAlert.WebhookEndpoints != 1 {
		t.Fatalf("destinations = %+v", s.UnapprovedAlert)
	}

	resp := portalDo(t, http.MethodPut, "/v1/portal/software-notifications", g.viewerToken, strings.NewReader(`{"new_software_enabled":true}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer PUT = %d, want 403", resp.StatusCode)
	}
	for _, bad := range []string{`{}`, `{"New_Software_Enabled":true}`, `{"new_software_enabled":"yes"}`, `{"tenant_id":"x"}`} {
		resp = portalDo(t, http.MethodPut, "/v1/portal/software-notifications", g.adminToken, strings.NewReader(bad))
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT %s = %d, want 400", bad, resp.StatusCode)
		}
	}
	resp = portalDo(t, http.MethodPut, "/v1/portal/software-notifications", g.adminToken, strings.NewReader(`{"new_software_enabled":true}`))
	decodeJSON(t, resp, &s)
	if !s.NewSoftwareEnabled || !s.UnapprovedAlertsEnabled || s.IsDefault || s.UpdatedBy == nil || *s.UpdatedBy != strings.ToLower(g.adminEmail) {
		t.Fatalf("after admin PUT = %+v", s)
	}

	req, _ := http.NewRequest(http.MethodPut, env.internalSrv.URL+"/admin/tenants/"+g.id+"/software-notifications",
		strings.NewReader(`{"unapproved_alerts_enabled":false}`))
	adm, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var admOut notificationSettingsOut
	if err := json.NewDecoder(adm.Body).Decode(&admOut); err != nil {
		t.Fatal(err)
	}
	adm.Body.Close()
	if admOut.UnapprovedAlertsEnabled || !admOut.NewSoftwareEnabled || admOut.UpdatedBy == nil || *admOut.UpdatedBy != "operator" {
		t.Fatalf("operator PUT = %+v", admOut)
	}
}

// ---------------------------------------------------------------------------
// Unapproved software alert: admin action (a)
// ---------------------------------------------------------------------------

func TestUnapprovedAlertOnPortalMark(t *testing.T) {
	g := newGovTenant(t, "mark", "it@mark.example")
	other := newGovTenant(t, "mark-other", "it@mark-other.example")
	hookSecret := strings.Repeat("ab", 32)
	govWebhook(t, g.id, "software.unapproved_detected")
	govWebhook(t, g.id, "score.changed") // not subscribed: gets nothing
	govWebhook(t, other.id, "software.unapproved_detected")
	now := time.Now().UTC()
	d1 := govDevice(t, g.id, "mark-mac-01", "macOS", now)
	d2 := govDevice(t, g.id, "mark-mac-02", "macOS", now)
	govApp(t, d1, "Torrent Thing", "com.gov.torrent", "TORRENTEAM")
	govApp(t, d2, "Torrent Thing", "com.gov.torrent", "TORRENTEAM")
	govApp(t, d1, "Fine App", "com.gov.fine", "FINETEAM12")
	govApp(t, d1, "Meh App", "com.gov.meh", "MEHTEAM123")
	// A product with identity evidence but installed nowhere now: its only
	// installation has been removed.
	govInstallation(t, g.id, d1, "macos", "macos_bundle_team", "com.gov.gone", "GONETEAM12", "Gone App", now.Add(-48*time.Hour), true)

	// Approved and Ignored raise nothing.
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.fine", "FINETEAM12")))
	mustApprove(t, g.adminToken, approvalBody("ignored", "", macApp("com.gov.meh", "MEHTEAM123")))
	if a := govAlerts(t, g.id); len(a) != 0 {
		t.Fatalf("approved or ignored raised an alert: %+v", a)
	}

	out := mustApprove(t, g.adminToken, approvalBody("unapproved", "no torrents", macApp("com.gov.torrent", "TORRENTEAM")))
	if out.ChangedCount != 1 {
		t.Fatalf("write = %+v", out)
	}
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].Trigger != "marked" || alerts[0].DeviceID != nil || alerts[0].EmailState != "pending" {
		t.Fatalf("alerts = %+v", alerts)
	}
	p := alerts[0].Payload
	if p.DeviceCount != 2 || len(p.Products) != 1 || p.Products[0].Name != "Torrent Thing" ||
		p.Products[0].ProductKey != "application:macos:com.gov.torrent:TORRENTEAM" ||
		p.MarkedBy == nil || *p.MarkedBy != strings.ToLower(g.adminEmail) || p.MarkedVia != "portal" || p.MarkedAt.IsZero() {
		t.Fatalf("payload = %+v", p)
	}
	hosts := map[string]bool{}
	for _, d := range p.Products[0].Devices {
		hosts[d.Hostname] = true
	}
	if !hosts["mark-mac-01"] || !hosts["mark-mac-02"] {
		t.Fatalf("payload devices = %+v", p.Products[0].Devices)
	}

	deliveries, raw := govDeliveries(t, g.id)
	if len(deliveries) != 1 || deliveries[0].EventType != "software.unapproved_detected" || deliveries[0].TenantID != g.id {
		t.Fatalf("webhook deliveries = %+v", deliveries)
	}
	for _, r := range raw {
		if strings.Contains(r, hookSecret) || strings.Contains(strings.ToLower(r), "secret") || strings.Contains(r, "bearer") {
			t.Fatalf("webhook payload carries secret material: %s", r)
		}
	}
	if od, _ := govDeliveries(t, other.id); len(od) != 0 {
		t.Fatalf("another tenant's webhook received this alert: %+v", od)
	}

	// Re-saving the same state changes nothing and raises nothing.
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.torrent", "TORRENTEAM")))
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatal("an unchanged re-save raised a second alert")
	}
	// Unapproved but installed nowhere: an episode is recorded, no alert.
	gone := mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.gone", "GONETEAM12")))
	if gone.ChangedCount != 1 {
		t.Fatalf("gone write = %+v", gone)
	}
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatal("a product installed nowhere raised an alert")
	}

	// Ingest after the mark: both devices are already covered by the admin
	// action's alert, so a report every 15 minutes raises nothing more.
	for i := 0; i < 3; i++ {
		if _, err := softwaregov.DetectOnDevice(context.Background(), env.pool, g.id, d1, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatalf("ingest re-alerted a device the admin action already reported: %+v", govAlerts(t, g.id))
	}

	// The email goes to the tenant contact, immediately, once.
	mail := &fakeMailer{}
	runRunner(t, mail, time.Now())
	sent := mail.to("it@mark.example")
	if len(sent) != 1 || !strings.Contains(sent[0].Subject, "Torrent Thing marked Unapproved and found on 2 devices") ||
		!strings.Contains(sent[0].Body, "mark-mac-01") || !strings.Contains(sent[0].Body, strings.ToLower(g.adminEmail)) {
		t.Fatalf("emails to contact = %+v", sent)
	}
	if len(mail.to("it@mark-other.example")) != 0 {
		t.Fatal("another tenant's contact was emailed")
	}
	for _, m := range mail.sent {
		for _, to := range m.To {
			if strings.HasSuffix(to, "@patched.im") {
				t.Fatalf("an alert went to Patched staff: %v", m.To)
			}
		}
	}
	if a := govAlerts(t, g.id); a[0].EmailState != "sent" {
		t.Fatalf("email state = %s", a[0].EmailState)
	}
	runRunner(t, mail, time.Now())
	if len(mail.to("it@mark.example")) != 1 {
		t.Fatal("the marked email was sent twice")
	}

	// A second transition (approved, then unapproved again) is a new episode.
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.torrent", "TORRENTEAM")))
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.torrent", "TORRENTEAM")))
	if a := govAlerts(t, g.id); len(a) != 2 || a[1].Trigger != "marked" {
		t.Fatalf("a new unapproved episode should alert again: %+v", a)
	}
}

func TestUnapprovedAlertExtensionAndNoRecipient(t *testing.T) {
	g := newGovTenant(t, "ext", "") // no contact email
	govWebhook(t, g.id, "software.unapproved_detected")
	dev := govDevice(t, g.id, "ext-mac-01", "macOS", time.Now())
	govExtension(t, dev, "chrome", "ponmlkjihgfedcbaponmlkjihgfedcba", "Coupon Helper")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", extItem("chrome", "ponmlkjihgfedcbaponmlkjihgfedcba")))
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].Payload.Products[0].Type != "browser_extension" || alerts[0].Payload.Policy.Kind != "browser_extension" {
		t.Fatalf("extension alert = %+v", alerts)
	}
	if d, _ := govDeliveries(t, g.id); len(d) != 1 {
		t.Fatalf("webhook still goes without a contact email, got %d", len(d))
	}
	runRunner(t, &fakeMailer{}, time.Now())
	if a := govAlerts(t, g.id); a[0].EmailState != "no_recipient" {
		t.Fatalf("email state = %s, want no_recipient", a[0].EmailState)
	}
}

func TestUnapprovedAlertOperatorMarkAndDisabled(t *testing.T) {
	g := newGovTenant(t, "operator", "it@operator.example")
	govWebhook(t, g.id, "software.unapproved_detected")
	dev := govDevice(t, g.id, "op-win-01", "Windows", time.Now())
	govApp(t, dev, "Old Remote Tool", "{A1B2-OLD-REMOTE}", "")

	r := chi.NewRouter()
	r.Put("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesPutHandler(env.pool, nil))
	put := func(policy string) {
		t.Helper()
		body := fmt.Sprintf(`{"bundle_id":"{A1B2-OLD-REMOTE}","platform":"windows","policy":%q}`, policy)
		req, _ := http.NewRequest(http.MethodPut, "/admin/tenants/"+g.id+"/app-policies", strings.NewReader(body))
		rec := &responseRecorder{header: http.Header{}}
		r.ServeHTTP(rec, req)
		if rec.status != http.StatusOK && rec.status != 0 {
			t.Fatalf("operator PUT %s = %d: %s", policy, rec.status, rec.body.String())
		}
		drainUnapprovedRaises(t)
	}
	put("unapproved")
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].Payload.MarkedVia != "operator" || alerts[0].Payload.MarkedBy != nil ||
		alerts[0].Payload.Products[0].Platform != "windows" {
		t.Fatalf("operator alert = %+v", alerts)
	}
	put("unapproved") // idempotent re-save: no transition, no alert
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatal("an operator re-save raised a second alert")
	}

	// Turned off: a new transition records nothing outbound.
	if _, err := softwaregov.PutSettings(context.Background(), env.pool, g.id,
		softwaregov.SettingsUpdate{UnapprovedAlertsEnabled: boolPtr(false)}, "operator"); err != nil {
		t.Fatal(err)
	}
	put("approved")
	put("unapproved")
	if len(govAlerts(t, g.id)) != 1 {
		t.Fatal("an alert was raised with the alert turned off")
	}
	if res, err := softwaregov.DetectOnDevice(context.Background(), env.pool, g.id, dev, time.Now()); err != nil || len(res.AlertIDs) != 0 {
		t.Fatalf("ingest raised an alert with the alert turned off: %+v %v", res, err)
	}
}

func boolPtr(b bool) *bool { return &b }

// responseRecorder is a minimal http.ResponseWriter for mounting an admin
// handler that the shared integration router does not carry.
type responseRecorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func (r *responseRecorder) Header() http.Header { return r.header }
func (r *responseRecorder) WriteHeader(s int) {
	if r.status == 0 {
		r.status = s
	}
}
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

// ---------------------------------------------------------------------------
// Unapproved software alert: ingest (b), through the real extractor
// ---------------------------------------------------------------------------

func TestUnapprovedAlertOnIngestDedupedAndDigested(t *testing.T) {
	tn := newCVETestTenant(t, "pat2009-ingest-"+randomHex(3))
	otherTn := newCVETestTenant(t, "pat2009-ingest-other-"+randomHex(3))
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE tenants SET contact_email = 'it@ingest.example' WHERE id = $1::uuid`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	govWebhook(t, tn.tenantID, "software.unapproved_detected")
	govWebhook(t, otherTn.tenantID, "software.unapproved_detected")
	// Already Unapproved before this feature: no episode exists yet.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.gov.ingestbad', 'macos', 'unapproved', 'report_deploy'),
		       ($1::uuid, 'com.gov.ingestgood', 'macos', 'approved', 'report_deploy'),
		       ($1::uuid, 'com.gov.ingestmeh', 'macos', 'unmanaged', 'report_deploy')`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	apps := []cveTestApp{
		{name: "Ingest Bad", version: "1.0", bundle: "com.gov.ingestbad"},
		{name: "Ingest Good", version: "1.0", bundle: "com.gov.ingestgood"},
		{name: "Ingest Meh", version: "1.0", bundle: "com.gov.ingestmeh"},
	}
	hw1 := strings.ToUpper(randomHex(16))
	hw2 := strings.ToUpper(randomHex(16))

	postAppsPayload(t, tn, hw1, apps)
	alerts := govAlerts(t, tn.tenantID)
	if len(alerts) != 1 || alerts[0].Trigger != "observed" || alerts[0].DeviceID == nil ||
		alerts[0].Payload.Products[0].Identifier != "com.gov.ingestbad" || alerts[0].Payload.MarkedVia != "unknown" {
		t.Fatalf("first report alerts = %+v", alerts)
	}

	// The same device reporting again, as it does every 15 minutes.
	postAppsPayload(t, tn, hw1, apps)
	postAppsPayload(t, tn, hw1, apps)
	if a := govAlerts(t, tn.tenantID); len(a) != 1 {
		t.Fatalf("repeat reports re-alerted: %d alerts", len(a))
	}

	// A second device newly observed with it: one more alert.
	postAppsPayload(t, tn, hw2, apps[:1])
	alerts = govAlerts(t, tn.tenantID)
	if len(alerts) != 2 || *alerts[0].DeviceID == *alerts[1].DeviceID {
		t.Fatalf("second device alerts = %+v", alerts)
	}
	if d, _ := govDeliveries(t, tn.tenantID); len(d) != 2 {
		t.Fatalf("webhook deliveries = %d, want one per (product, device)", len(d))
	}

	// The other tenant reports the same bundle but has no such policy.
	postAppsPayload(t, otherTn, strings.ToUpper(randomHex(16)), apps[:1])
	if a := govAlerts(t, otherTn.tenantID); len(a) != 0 {
		t.Fatalf("another tenant's policy leaked: %+v", a)
	}
	if d, _ := govDeliveries(t, otherTn.tenantID); len(d) != 0 {
		t.Fatalf("another tenant's webhook fired: %+v", d)
	}

	// The first digest waits for the 07:00 UTC slot: nothing goes out as soon
	// as the alerts exist.
	mail := &fakeMailer{}
	now := time.Now().UTC()
	runRunner(t, mail, now)
	if got := mail.to("it@ingest.example"); len(got) != 0 {
		t.Fatalf("the first digest went out before its slot: %+v", got)
	}
	// One daily digest for both devices, at the slot, and never twice.
	now = softwaregov.DailySlot(now, softwaregov.DigestHourUTC).Add(24*time.Hour + time.Minute)
	runRunner(t, mail, now)
	digests := mail.to("it@ingest.example")
	if len(digests) != 1 || digests[0].Subject != "Patched: unapproved software found on 2 devices" {
		t.Fatalf("digest = %+v", digests)
	}
	for _, a := range govAlerts(t, tn.tenantID) {
		if a.EmailState != "sent" {
			t.Fatalf("alert %d email state = %s", a.ID, a.EmailState)
		}
	}
	runRunner(t, mail, now.Add(time.Minute))
	if len(mail.to("it@ingest.example")) != 1 {
		t.Fatal("a second digest was sent in the same day")
	}

	// A third device waits for the next slot.
	hw3 := strings.ToUpper(randomHex(16))
	postAppsPayload(t, tn, hw3, apps[:1])
	runRunner(t, mail, now.Add(2*time.Minute))
	if len(mail.to("it@ingest.example")) != 1 {
		t.Fatal("the digest is daily, not per alert")
	}
	runRunner(t, mail, now.Add(24*time.Hour))
	if got := mail.to("it@ingest.example"); len(got) != 2 || got[1].Subject != "Patched: unapproved software found on 1 device" {
		t.Fatalf("next day's digest = %+v", got)
	}
}

// ---------------------------------------------------------------------------
// New software notification (opt-in, daily, PAT-1888 channels)
// ---------------------------------------------------------------------------

func TestNewSoftwareNotificationOffByDefaultAndBatchedDaily(t *testing.T) {
	g := newGovTenant(t, "notify", "")
	channelBody := defaultWebhookChannel("new software")
	channelBody["events"] = []string{"software.first_seen"}
	channelID, _ := createNotificationChannel(t, g.id, channelBody)
	dev := govDevice(t, g.id, "notify-mac-01", "macOS", time.Now())

	now := time.Now().UTC()
	slot := softwaregov.DailySlot(now, softwaregov.DigestHourUTC)
	govInstallation(t, g.id, dev, "macos", "macos_bundle", "com.gov.notify.one", "", "Notify One", slot.Add(-2*time.Hour), false)
	govInstallation(t, g.id, dev, "macos", "macos_bundle", "com.gov.notify.two", "", "Notify Two", slot.Add(-3*time.Hour), false)

	count := func() int {
		var n int
		if err := env.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM notification_deliveries WHERE channel_id = $1::uuid AND event_type = 'software.first_seen'`,
			channelID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	runRunner(t, &fakeMailer{}, now)
	if count() != 0 {
		t.Fatal("the new software notification is off by default and sent anyway")
	}

	if _, err := softwaregov.PutSettings(context.Background(), env.pool, g.id,
		softwaregov.SettingsUpdate{NewSoftwareEnabled: boolPtr(true)}, "operator"); err != nil {
		t.Fatal(err)
	}
	runRunner(t, &fakeMailer{}, now)
	if count() != 1 {
		t.Fatalf("deliveries after turning on = %d, want one batched notification", count())
	}
	var payload struct {
		EventType string `json:"event_type"`
		Data      struct {
			ProductCount int `json:"product_count"`
			Products     []struct {
				Name string `json:"name"`
			} `json:"products"`
		} `json:"data"`
	}
	var raw string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT payload::text FROM notification_deliveries WHERE channel_id = $1::uuid`, channelID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.EventType != "software.first_seen" || payload.Data.ProductCount != 2 || len(payload.Data.Products) != 2 {
		t.Fatalf("notification payload = %s", raw)
	}

	// The same slot again: nothing more. The next day, one more batch.
	runRunner(t, &fakeMailer{}, now.Add(time.Minute))
	if count() != 1 {
		t.Fatal("notified twice in one day")
	}
	govInstallation(t, g.id, dev, "macos", "macos_bundle", "com.gov.notify.three", "", "Notify Three", slot.Add(3*time.Hour), false)
	runRunner(t, &fakeMailer{}, slot.Add(24*time.Hour+time.Minute))
	if count() != 2 {
		t.Fatalf("next day's deliveries = %d, want 2", count())
	}
}

// ---------------------------------------------------------------------------
// No alert burst on deploy: the 0183 baseline seed
// ---------------------------------------------------------------------------

// runBaselineSeed replays the baseline seed section of migration 0183, the
// statements that run at deploy time, against the state a test has built.
func runBaselineSeed(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "migrations", "0183_software_governance_alerts.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	start := strings.Index(sql, "-- BEGIN baseline seed")
	end := strings.Index(sql, "-- END baseline seed")
	if start < 0 || end < start {
		t.Fatal("baseline seed markers missing from 0183")
	}
	if _, err := env.pool.Exec(context.Background(), sql[start:end]); err != nil {
		t.Fatalf("baseline seed: %v", err)
	}
}

// govDeviceHW creates a device the way a report from postAppsPayload would
// identify it, so a later ingest updates this row rather than creating one.
func govDeviceHW(t *testing.T, tenantID, hw string) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, last_seen)
		VALUES ($1::uuid, $2, $3, $4, 'macOS', '15.1', now()) RETURNING id::text`,
		tenantID, "PAT2024"+strings.ToUpper(hw[:8]), hw, "pat2024-"+strings.ToLower(hw[:8])).Scan(&id); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

func TestUnapprovedAlertNoBurstOnDeploy(t *testing.T) {
	tn := newCVETestTenant(t, "pat2009-baseline-"+randomHex(3))
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE tenants SET contact_email = 'it@baseline.example' WHERE id = $1::uuid`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	govWebhook(t, tn.tenantID, "software.unapproved_detected")
	apps := []cveTestApp{{name: "Legacy Bad", version: "1.0", bundle: "com.gov.legacybad"}}

	// Before the migration: the product is already Unapproved and already
	// installed on three devices.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.gov.legacybad', 'macos', 'unapproved', 'report_deploy')`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	var hws []string
	for i := 0; i < 3; i++ {
		hw := strings.ToUpper(randomHex(16))
		hws = append(hws, hw)
		govApp(t, govDeviceHW(t, tn.tenantID, hw), "Legacy Bad", "com.gov.legacybad", "")
	}

	// Names the runtime trims with Go's strings.TrimSpace but btrim does not:
	// a tab, a newline and a no-break space, matched by a name policy.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'Tabby', 'any', 'unapproved', 'report_deploy')`, tn.tenantID); err != nil {
		t.Fatal(err)
	}
	var spaced []string
	for _, name := range []string{"Tabby\t", "\nTabby", "Tabby\u00a0"} {
		d := govDevice(t, tn.tenantID, "spaced-"+randomHex(3), "macOS", time.Now())
		govApp(t, d, name, "com.gov.tabby."+randomHex(3), "")
		spaced = append(spaced, d)
	}

	// Deploy.
	runBaselineSeed(t)

	// The first post-deploy ingest from each device, and the runner.
	for _, hw := range hws {
		postAppsPayload(t, tn, hw, apps)
	}
	for _, d := range spaced {
		if _, err := softwaregov.DetectOnDevice(context.Background(), env.pool, tn.tenantID, d, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	mail := &fakeMailer{}
	runRunner(t, mail, time.Now().UTC().Add(48*time.Hour))
	if a := govAlerts(t, tn.tenantID); len(a) != 0 {
		t.Fatalf("pre-existing pairs alerted on deploy: %d alerts", len(a))
	}
	if d, _ := govDeliveries(t, tn.tenantID); len(d) != 0 {
		t.Fatalf("pre-existing pairs enqueued %d webhooks", len(d))
	}
	if len(mail.to("it@baseline.example")) != 0 {
		t.Fatal("pre-existing pairs were emailed")
	}
	var suppressed int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM software_unapproved_alerted_devices
		WHERE tenant_id = $1::uuid AND suppressed_baseline AND alert_id IS NULL`, tn.tenantID).Scan(&suppressed); err != nil {
		t.Fatal(err)
	}
	if suppressed != 6 {
		t.Fatalf("baseline ledger rows = %d, want 6 (3 by bundle, 3 by whitespace-padded name)", suppressed)
	}

	// A fourth device appearing afterwards alerts once.
	fourth := strings.ToUpper(randomHex(16))
	postAppsPayload(t, tn, fourth, apps)
	postAppsPayload(t, tn, fourth, apps)
	alerts := govAlerts(t, tn.tenantID)
	if len(alerts) != 1 || alerts[0].Trigger != "observed" {
		t.Fatalf("fourth device alerts = %+v", alerts)
	}
	if alerts[0].Payload.MarkedBy != nil || alerts[0].Payload.MarkedVia != "unknown" {
		t.Fatalf("a baseline episode has no recorded actor: %+v", alerts[0].Payload)
	}
	if d, _ := govDeliveries(t, tn.tenantID); len(d) != 1 {
		t.Fatalf("fourth device webhooks = %d, want 1", len(d))
	}
}

// ---------------------------------------------------------------------------
// One email per bulk mark; a failed raise is retried, not lost
// ---------------------------------------------------------------------------

func TestUnapprovedBulkMarkSendsOneEmail(t *testing.T) {
	g := newGovTenant(t, "bulk", "it@bulk.example")
	govWebhook(t, g.id, "software.unapproved_detected")
	dev := govDevice(t, g.id, "bulk-mac-01", "macOS", time.Now())
	items := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		bundle := fmt.Sprintf("com.gov.bulk.%03d", i)
		govApp(t, dev, fmt.Sprintf("Bulk %03d", i), bundle, "BULKTEAM12")
		items = append(items, macApp(bundle, "BULKTEAM12"))
	}
	out := mustApprove(t, g.adminToken, approvalBody("unapproved", "", items...))
	if out.ChangedCount != 200 {
		t.Fatalf("bulk write changed %d", out.ChangedCount)
	}
	if d, _ := govDeliveries(t, g.id); len(d) != 200 {
		t.Fatalf("webhooks = %d, want one per product", len(d))
	}
	mail := &fakeMailer{}
	runRunner(t, mail, time.Now())
	runRunner(t, mail, time.Now().Add(time.Minute))
	sent := mail.to("it@bulk.example")
	if len(sent) != 1 {
		t.Fatalf("bulk mark of 200 products sent %d emails, want 1", len(sent))
	}
	if !strings.Contains(sent[0].Subject, "and 199 other products marked Unapproved and found on 1 device") ||
		!strings.Contains(sent[0].Body, "And 180 more products. The full list is in the Patched portal: https://app.patched.im") {
		t.Fatalf("bulk email:\n%s\n%s", sent[0].Subject, sent[0].Body)
	}
	for _, a := range govAlerts(t, g.id) {
		if a.EmailState != "sent" {
			t.Fatalf("alert %d email state = %s", a.ID, a.EmailState)
		}
	}
}

func TestUnapprovedRemarkRaisedByRunner(t *testing.T) {
	g := newGovTenant(t, "remark", "it@remark.example")
	govWebhook(t, g.id, "software.unapproved_detected")
	dev := govDevice(t, g.id, "remark-mac-01", "macOS", time.Now())
	govApp(t, dev, "Remark App", "com.gov.remark", "REMARKTEAM")
	item := macApp("com.gov.remark", "REMARKTEAM")

	mustApprove(t, g.adminToken, approvalBody("unapproved", "", item))
	if a := govAlerts(t, g.id); len(a) != 1 {
		t.Fatalf("first mark alerts = %d", len(a))
	}
	mail := &fakeMailer{}
	runRunner(t, mail, time.Now())
	mustApprove(t, g.adminToken, approvalBody("approved", "", item))

	// PAT-2095: the re-mark commits and the request returns without raising;
	// the runner owns the raise.
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", item)); status != http.StatusOK {
		t.Fatalf("re-mark = %d: %s", status, b)
	}
	if a := govAlerts(t, g.id); len(a) != 1 {
		t.Fatalf("the request path raised the alert: %d", len(a))
	}

	// Ingest meanwhile neither reuses the old episode's ledger nor
	// pre-empts the marked alert.
	if res, err := softwaregov.DetectOnDevice(context.Background(), env.pool, g.id, dev, time.Now()); err != nil || len(res.AlertIDs) != 0 {
		t.Fatalf("ingest during the unraised window: %+v %v", res, err)
	}

	// The runner raises it.
	runRunner(t, mail, time.Now().Add(softwaregov.UnraisedGrace+time.Minute))
	alerts := govAlerts(t, g.id)
	if len(alerts) != 2 || alerts[1].Trigger != "marked" || alerts[1].Payload.DeviceCount != 1 {
		t.Fatalf("re-mark alerts = %+v", alerts)
	}
	if got := mail.to("it@remark.example"); len(got) != 2 {
		t.Fatalf("emails = %d, want one for the first mark and one for the re-mark", len(got))
	}
	runRunner(t, mail, time.Now().Add(2*softwaregov.UnraisedGrace))
	if len(govAlerts(t, g.id)) != 2 {
		t.Fatal("the episode was raised twice")
	}
}
