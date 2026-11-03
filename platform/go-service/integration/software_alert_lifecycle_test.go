//go:build integration

package integration

// PAT-2097: the unapproved software alert lifecycle. Acknowledge (admin only,
// tenant scoped, idempotent, audited), auto-resolve on an authoritative
// complete report and never without one, resolve on a policy change,
// re-open on reappearance, the operator queue and the overview counts.
// Ingest runs through POST /v1/inventory and the real extractor.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/softwaregov"
)

type lcTransition struct {
	From      *string `json:"from"`
	To        string  `json:"to"`
	ActorKind string  `json:"actor_kind"`
	Actor     *string `json:"actor"`
	Reason    *string `json:"reason"`
	Note      *string `json:"note"`
}

type lcAlert struct {
	ID      int64               `json:"id"`
	Status  string              `json:"status"`
	Trigger string              `json:"trigger"`
	Product softwaregov.Product `json:"product"`
	Device  struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
	} `json:"device"`
	NotificationID *int64         `json:"notification_id"`
	AcknowledgedBy *string        `json:"acknowledged_by"`
	ResolvedReason *string        `json:"resolved_reason"`
	ReopenedCount  int            `json:"reopened_count"`
	History        []lcTransition `json:"history"`
	Changed        *bool          `json:"changed"`
	TenantID       string         `json:"tenant_id"`
	TenantName     string         `json:"tenant_name"`
	AgeSeconds     *int64         `json:"age_seconds"`
}

type lcList struct {
	Total  int `json:"total"`
	Counts struct {
		Open, Acknowledged, Resolved int
	} `json:"counts"`
	Alerts []lcAlert `json:"alerts"`
}

func lcListAlerts(t *testing.T, token, query string) lcList {
	t.Helper()
	var out lcList
	getJSON(t, "/v1/portal/software-alerts"+query, token, &out)
	return out
}

func lcGet(t *testing.T, token string, id int64) lcAlert {
	t.Helper()
	var out lcAlert
	getJSON(t, fmt.Sprintf("/v1/portal/software-alerts/%d", id), token, &out)
	return out
}

func lcAck(t *testing.T, token string, id int64, body string) (int, lcAlert, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	resp := portalDo(t, http.MethodPost, fmt.Sprintf("/v1/portal/software-alerts/%d/acknowledge", id), token, rdr)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out lcAlert
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode ack: %v %s", err, raw)
		}
	}
	return resp.StatusCode, out, string(raw)
}

func lcAdmin(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, env.internalSrv.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// lcRow reads one tracked alert straight from the ledger.
func lcRow(t *testing.T, tenantID, deviceID string) (id int64, status string, reason *string, reopened int, digest bool) {
	t.Helper()
	if err := env.pool.QueryRow(context.Background(), `
		SELECT id, status, resolved_reason, reopened_count, reopen_digest_pending
		FROM software_unapproved_alerted_devices
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid
		ORDER BY id DESC LIMIT 1`, tenantID, deviceID).Scan(&id, &status, &reason, &reopened, &digest); err != nil {
		t.Fatalf("tracked alert for device %s: %v", deviceID, err)
	}
	return
}

func lcTransitions(t *testing.T, id int64) int {
	return countRows(t, `SELECT count(*) FROM software_unapproved_alert_transitions WHERE alert_device_id = $1`, id)
}

// A portal-marked product on two devices: two tracked alerts, readable by a
// viewer, acknowledged only by an admin of the same tenant.
func TestSoftwareAlertAcknowledgeRolesAndTenancy(t *testing.T) {
	g := newGovTenant(t, "ack", "")
	other := newGovTenant(t, "ack-other", "")
	now := time.Now().UTC()
	d1 := govDevice(t, g.id, "ack-mac-01", "macOS", now)
	d2 := govDevice(t, g.id, "ack-mac-02", "macOS", now)
	govApp(t, d1, "Ack Torrent", "com.gov.acktorrent", "ACKTEAM123")
	govApp(t, d2, "Ack Torrent", "com.gov.acktorrent", "ACKTEAM123")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.acktorrent", "ACKTEAM123")))

	list := lcListAlerts(t, g.viewerToken, "")
	if list.Total != 2 || list.Counts.Open != 2 || len(list.Alerts) != 2 {
		t.Fatalf("viewer list = %+v", list)
	}
	a := list.Alerts[0]
	if a.Status != "open" || a.Trigger != "marked" || a.NotificationID == nil ||
		a.Product.ProductKey != "application:macos:com.gov.acktorrent:ACKTEAM123" {
		t.Fatalf("alert = %+v", a)
	}
	if n := lcTransitions(t, a.ID); n != 1 {
		t.Fatalf("a raised alert should carry its opening transition, got %d", n)
	}

	// A viewer cannot acknowledge.
	if code, _, raw := lcAck(t, g.viewerToken, a.ID, `{"note":"seen"}`); code != http.StatusForbidden ||
		!strings.Contains(raw, "admin_role_required") {
		t.Fatalf("viewer ack = %d %s", code, raw)
	}
	// Another tenant's admin gets 404 for this id, on read and on write.
	if code, _, raw := lcAck(t, other.adminToken, a.ID, ""); code != http.StatusNotFound {
		t.Fatalf("cross-tenant ack = %d %s", code, raw)
	}
	resp := portalDo(t, http.MethodGet, fmt.Sprintf("/v1/portal/software-alerts/%d", a.ID), other.adminToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant read = %d", resp.StatusCode)
	}
	if got := lcGet(t, g.adminToken, a.ID); got.Status != "open" {
		t.Fatalf("a refused ack changed the alert: %+v", got)
	}

	// Note length is capped.
	if code, _, _ := lcAck(t, g.adminToken, a.ID, fmt.Sprintf(`{"note":%q}`, strings.Repeat("x", 1001))); code != http.StatusBadRequest {
		t.Fatalf("over-long note = %d", code)
	}

	code, acked, raw := lcAck(t, g.adminToken, a.ID, `{"note":"Raised with the service desk"}`)
	if code != http.StatusOK || acked.Status != "acknowledged" || acked.Changed == nil || !*acked.Changed ||
		acked.AcknowledgedBy == nil || *acked.AcknowledgedBy != strings.ToLower(g.adminEmail) {
		t.Fatalf("admin ack = %d %s", code, raw)
	}
	h := acked.History
	if len(h) != 2 || h[1].To != "acknowledged" || h[1].From == nil || *h[1].From != "open" ||
		h[1].ActorKind != "portal_user" || h[1].Actor == nil || *h[1].Actor != strings.ToLower(g.adminEmail) ||
		h[1].Note == nil || *h[1].Note != "Raised with the service desk" {
		t.Fatalf("history = %+v", h)
	}
	// Idempotent: a second acknowledge changes nothing and records nothing.
	code, again, _ := lcAck(t, g.adminToken, a.ID, "")
	if code != http.StatusOK || again.Changed == nil || *again.Changed || again.Status != "acknowledged" {
		t.Fatalf("second ack = %d %+v", code, again)
	}
	if n := lcTransitions(t, a.ID); n != 2 {
		t.Fatalf("idempotent ack wrote a transition: %d", n)
	}

	// The operator acknowledges the other one through the admin API, scoped
	// to the tenant in the path.
	b := list.Alerts[1]
	if code, _ := lcAdmin(t, http.MethodPost, fmt.Sprintf("/admin/tenants/%s/software-alerts/%d/acknowledge", other.id, b.ID), ""); code != http.StatusNotFound {
		t.Fatalf("operator ack under the wrong tenant = %d", code)
	}
	code, body := lcAdmin(t, http.MethodPost, fmt.Sprintf("/admin/tenants/%s/software-alerts/%d/acknowledge", g.id, b.ID), `{"note":"operator saw it"}`)
	var opAck lcAlert
	_ = json.Unmarshal(body, &opAck)
	if code != http.StatusOK || opAck.Status != "acknowledged" || opAck.AcknowledgedBy == nil || *opAck.AcknowledgedBy != "operator" ||
		opAck.History[len(opAck.History)-1].ActorKind != "operator" || opAck.History[len(opAck.History)-1].Actor != nil {
		t.Fatalf("operator ack = %d %s", code, body)
	}

	// Filters: status and device.
	if l := lcListAlerts(t, g.viewerToken, "?status=open"); l.Total != 0 || l.Counts.Acknowledged != 2 {
		t.Fatalf("status filter = %+v", l)
	}
	if l := lcListAlerts(t, g.viewerToken, "?device_id="+d2); l.Total != 1 || l.Alerts[0].Device.DeviceID != d2 {
		t.Fatalf("device filter = %+v", l)
	}
	if l := lcListAlerts(t, g.viewerToken, "?product_key=application:macos:com.gov.acktorrent:ACKTEAM123&limit=1"); l.Total != 2 || len(l.Alerts) != 1 {
		t.Fatalf("product filter with paging = %+v", l)
	}
	if l := lcListAlerts(t, other.adminToken, ""); l.Total != 0 {
		t.Fatalf("another tenant sees these alerts: %+v", l)
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/software-alerts?status=closed", g.viewerToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad status filter = %d", resp.StatusCode)
	}

	// The transition history is append-only.
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE software_unapproved_alert_transitions SET note = 'x' WHERE alert_device_id = $1`, a.ID); err == nil {
		t.Fatal("transition history accepted an UPDATE")
	}
}

// lcIngest is one device reporting through the real extractor.
type lcIngest struct {
	tn  cveTestTenant
	hw  string
	bad cveTestApp
	fil []cveTestApp
	dev string
}

func newLCIngest(t *testing.T, label string) *lcIngest {
	t.Helper()
	sfx := randomHex(4)
	f := &lcIngest{
		tn:  newCVETestTenant(t, "pat2097-"+label+"-"+sfx),
		hw:  strings.ToUpper(sfx + "-2097-4000-8000-" + randomHex(6)),
		bad: cveTestApp{"Pat2097 Bad " + sfx, "1.0", "com.example.pat2097.bad." + sfx},
	}
	for i := 0; i < 3; i++ {
		f.fil = append(f.fil, cveTestApp{fmt.Sprintf("Pat2097 Filler %d %s", i, sfx), "1.0",
			fmt.Sprintf("com.example.pat2097.filler%d.%s", i, sfx)})
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'macos', 'unapproved', 'report')`, f.tn.tenantID, f.bad.bundle); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *lcIngest) post(t *testing.T, r appsPost) {
	t.Helper()
	mustPostApps(t, f.tn, f.hw, r)
	if f.dev == "" {
		f.dev = deviceIDByHW(t, f.tn.tenantID, f.hw)
	}
}

func (f *lcIngest) withBad() []cveTestApp { return append([]cveTestApp{f.bad}, f.fil...) }

func (f *lcIngest) assertStatus(t *testing.T, want string, wantReason string) int64 {
	t.Helper()
	id, status, reason, _, _ := lcRow(t, f.tn.tenantID, f.dev)
	got := ""
	if reason != nil {
		got = *reason
	}
	if status != want || got != wantReason {
		t.Fatalf("alert %d = %s/%q, want %s/%q", id, status, got, want, wantReason)
	}
	return id
}

// Absence requires authority: a partial, unavailable, no-signal or legacy
// report never resolves an alert, even when the product is already gone from
// the device's inventory. Only an explicit schema v3 complete does.
func TestSoftwareAlertResolvesOnlyOnAuthoritativeCompleteReport(t *testing.T) {
	f := newLCIngest(t, "authority")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	if a := govAlerts(t, f.tn.tenantID); len(a) != 1 || a[0].Trigger != "observed" {
		t.Fatalf("raise = %+v", a)
	}
	id := f.assertStatus(t, "open", "")

	// No signal: the safety valve lets this small drop prune the row, so
	// the product leaves device_apps, but a no-signal report is not
	// authority and the alert stays open.
	f.post(t, appsPost{schemaV3: true, apps: f.fil})
	if countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.dev, f.bad.bundle) != 0 {
		t.Fatal("fixture: the no-signal report was expected to prune the product")
	}
	f.assertStatus(t, "open", "")

	// Partial, unavailable (inconsistent with the apps listed) and a legacy
	// v2 payload claiming complete: none is authority.
	f.post(t, appsPost{schemaV3: true, status: "partial", apps: f.fil})
	f.assertStatus(t, "open", "")
	f.post(t, appsPost{schemaV3: true, status: "unavailable", apps: f.fil})
	f.assertStatus(t, "open", "")
	f.post(t, appsPost{schemaV3: false, status: "complete", apps: f.fil})
	f.assertStatus(t, "open", "")

	// An explicit complete proves it gone.
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil})
	if got := f.assertStatus(t, "resolved", "not_observed"); got != id {
		t.Fatalf("resolved a different row: %d vs %d", got, id)
	}
	var actorKind string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT actor_kind FROM software_unapproved_alert_transitions
		WHERE alert_device_id = $1 AND to_status = 'resolved'`, id).Scan(&actorKind); err != nil || actorKind != "system" {
		t.Fatalf("resolve transition = %q %v", actorKind, err)
	}
}

// A partial report never resolves, even when the product is already gone
// from the device's inventory (as after a PAT-2063 time release under a held
// report): only the report's authority stands between it and a resolve.
func TestSoftwareAlertPartialReportNeverResolves(t *testing.T) {
	f := newLCIngest(t, "partial")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	f.assertStatus(t, "open", "")
	if _, err := env.pool.Exec(context.Background(),
		`DELETE FROM device_apps WHERE device_id = $1::uuid AND identifier = $2`, f.dev, f.bad.bundle); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		f.post(t, appsPost{schemaV3: true, status: "partial", apps: f.fil[:1]})
		f.assertStatus(t, "open", "")
	}
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil})
	f.assertStatus(t, "resolved", "not_observed")
}

// PAT-2075: a per-user install whose user is missing from the report stays
// in the inventory, so its alert stays open under a machine-wide complete.
// A report listing that user as complete, without the product, resolves it.
func TestSoftwareAlertPerUserScopeMissingDoesNotResolve(t *testing.T) {
	f := newLCIngest(t, "peruser")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil,
		userApps: []userAppRows{{pat2075Alice, []cveTestApp{f.bad}}},
		users:    []appsUserStatus{{pat2075Alice, "complete"}}})
	f.assertStatus(t, "open", "")

	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil, users: []appsUserStatus{}})
	f.assertStatus(t, "open", "")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil, users: []appsUserStatus{{pat2075Alice, "partial"}}})
	f.assertStatus(t, "open", "")

	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil, users: []appsUserStatus{{pat2075Alice, "complete"}}})
	f.assertStatus(t, "resolved", "not_observed")
}

// A product proven gone and then reported again, still Unapproved, re-opens
// the same tracked alert: no new row, no new outbound alert, no webhook, and
// it is listed in the next daily digest.
func TestSoftwareAlertReopensOnReappearance(t *testing.T) {
	f := newLCIngest(t, "reopen")
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE tenants SET contact_email = 'it@reopen.example' WHERE id = $1::uuid`, f.tn.tenantID); err != nil {
		t.Fatal(err)
	}
	govWebhook(t, f.tn.tenantID, "software.unapproved_detected")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	id := f.assertStatus(t, "open", "")
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil})
	f.assertStatus(t, "resolved", "not_observed")
	alertsBefore := len(govAlerts(t, f.tn.tenantID))
	hooksBefore, _ := govDeliveries(t, f.tn.tenantID)

	// Send the first digest (the original observed alert) so the next one
	// holds only the re-open.
	mail := &fakeMailer{}
	slot := softwaregov.DailySlot(time.Now().UTC(), softwaregov.DigestHourUTC)
	runRunner(t, mail, slot.Add(24*time.Hour+time.Minute))
	if len(mail.to("it@reopen.example")) != 1 {
		t.Fatal("fixture: expected the first digest")
	}

	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	gotID, status, reason, reopened, digest := lcRow(t, f.tn.tenantID, f.dev)
	if gotID != id || status != "open" || reason != nil || reopened != 1 || !digest {
		t.Fatalf("reopen = id %d (want %d) %s %v reopened=%d digest=%v", gotID, id, status, reason, reopened, digest)
	}
	if n := countRows(t, `SELECT count(*) FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid`, f.dev); n != 1 {
		t.Fatalf("a re-open created a duplicate row: %d", n)
	}
	if a := govAlerts(t, f.tn.tenantID); len(a) != alertsBefore {
		t.Fatalf("a re-open raised a new outbound alert: %d -> %d", alertsBefore, len(a))
	}
	if d, _ := govDeliveries(t, f.tn.tenantID); len(d) != len(hooksBefore) {
		t.Fatal("a re-open sent a webhook")
	}
	var fromTo string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT from_status || '>' || to_status FROM software_unapproved_alert_transitions
		WHERE alert_device_id = $1 ORDER BY id DESC LIMIT 1`, id).Scan(&fromTo); err != nil || fromTo != "resolved>open" {
		t.Fatalf("reopen transition = %q %v", fromTo, err)
	}
	// Repeated reports do not re-open again.
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	if _, _, _, reopened, _ := lcRow(t, f.tn.tenantID, f.dev); reopened != 1 {
		t.Fatalf("reopened_count = %d after a repeat report", reopened)
	}

	// No immediate email; the next digest lists it once.
	runRunner(t, mail, slot.Add(24*time.Hour+2*time.Minute))
	if len(mail.to("it@reopen.example")) != 1 {
		t.Fatal("a re-open sent an email before the digest slot")
	}
	runRunner(t, mail, slot.Add(48*time.Hour+time.Minute))
	got := mail.to("it@reopen.example")
	if len(got) != 2 || !strings.Contains(got[1].Body, "Found again on (1)") {
		t.Fatalf("digest after re-open = %+v", got)
	}
	if _, _, _, _, digest := lcRow(t, f.tn.tenantID, f.dev); digest {
		t.Fatal("the re-open is still pending after its digest")
	}
	runRunner(t, mail, slot.Add(72*time.Hour+time.Minute))
	if len(mail.to("it@reopen.example")) != 2 {
		t.Fatal("the re-open was reported twice")
	}
}

// Approve, ignore and unreviewed (policy removed) from the portal, and the
// operator's app and extension paths, resolve open and acknowledged alerts in
// the policy write's own transaction.
func TestSoftwareAlertResolvesOnPolicyChange(t *testing.T) {
	g := newGovTenant(t, "policy", "")
	now := time.Now().UTC()
	dev := govDevice(t, g.id, "policy-mac-01", "macOS", now)
	cases := []struct{ state, reason, bundle string }{
		{"approved", "approved", "com.gov.policy.approve"},
		{"ignored", "ignored", "com.gov.policy.ignore"},
		{"unreviewed", "policy_removed", "com.gov.policy.remove"},
	}
	for i, c := range cases {
		team := fmt.Sprintf("POLTEAM%03d", i)
		govApp(t, dev, "Policy "+c.state, c.bundle, team)
		mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp(c.bundle, team)))
		key := "application:macos:" + c.bundle + ":" + team
		l := lcListAlerts(t, g.adminToken, "?product_key="+key)
		if l.Total != 1 {
			t.Fatalf("%s: alerts = %+v", c.state, l)
		}
		if c.state == "ignored" {
			// An acknowledged alert resolves too.
			if code, _, raw := lcAck(t, g.adminToken, l.Alerts[0].ID, ""); code != http.StatusOK {
				t.Fatalf("ack = %d %s", code, raw)
			}
		}
		out := mustApprove(t, g.adminToken, approvalBody(c.state, "", macApp(c.bundle, team)))
		if len(out.Results) != 1 {
			t.Fatalf("write = %+v", out)
		}
		a := lcGet(t, g.adminToken, l.Alerts[0].ID)
		if a.Status != "resolved" || a.ResolvedReason == nil || *a.ResolvedReason != c.reason {
			t.Fatalf("%s: alert = %+v", c.state, a)
		}
		last := a.History[len(a.History)-1]
		if last.ActorKind != "portal_user" || last.Reason == nil || *last.Reason != c.reason {
			t.Fatalf("%s: transition = %+v", c.state, last)
		}
		// Resolved alerts cannot be acknowledged.
		if code, _, _ := lcAck(t, g.adminToken, a.ID, ""); code != http.StatusConflict {
			t.Fatalf("%s: ack of a resolved alert = %d", c.state, code)
		}
	}

	// Operator paths: app PUT to approved, app DELETE, extension DELETE.
	r := chi.NewRouter()
	r.Put("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesPutHandler(env.pool, nil))
	r.Delete("/admin/tenants/{tenantID}/app-policies/{entryID}", handlers.TenantAppPoliciesDeleteHandler(env.pool))
	r.Delete("/admin/tenants/{tenantID}/extension-policies/{entryID}", handlers.TenantExtensionPolicyDeleteHandler(env.pool))
	serve := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, path, strings.NewReader(body))
		rec := &responseRecorder{header: http.Header{}}
		r.ServeHTTP(rec, req)
		if rec.status >= 300 {
			t.Fatalf("%s %s = %d: %s", method, path, rec.status, rec.body.String())
		}
		drainUnapprovedRaises(t)
	}
	opPut := func(bundle, policy string) {
		serve(http.MethodPut, "/admin/tenants/"+g.id+"/app-policies",
			fmt.Sprintf(`{"bundle_id":%q,"platform":"macos","policy":%q}`, bundle, policy))
	}
	for _, b := range []string{"com.gov.op.approve", "com.gov.op.delete"} {
		govApp(t, dev, "Op "+b, b, "")
		opPut(b, "unapproved")
	}
	opPut("com.gov.op.approve", "approved")
	var delID int64
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id FROM tenant_app_policies WHERE tenant_id = $1::uuid AND bundle_id = 'com.gov.op.delete'`, g.id).Scan(&delID); err != nil {
		t.Fatal(err)
	}
	serve(http.MethodDelete, fmt.Sprintf("/admin/tenants/%s/app-policies/%d", g.id, delID), "")

	govExtension(t, dev, "chrome", "abcdefghijklmnopabcdefghijklmnop", "Op Coupon")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", extItem("chrome", "abcdefghijklmnopabcdefghijklmnop")))
	var extID int64
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id FROM tenant_extension_policies WHERE tenant_id = $1::uuid AND extension_id = 'abcdefghijklmnopabcdefghijklmnop'`, g.id).Scan(&extID); err != nil {
		t.Fatal(err)
	}
	serve(http.MethodDelete, fmt.Sprintf("/admin/tenants/%s/extension-policies/%d", g.id, extID), "")

	for _, want := range []struct{ key, reason string }{
		{"application:macos:com.gov.op.approve", "approved"},
		{"application:macos:com.gov.op.delete", "policy_removed"},
		{"browser_extension:chrome:abcdefghijklmnopabcdefghijklmnop", "policy_removed"},
	} {
		l := lcListAlerts(t, g.adminToken, "?product_key="+want.key)
		if l.Total != 1 || l.Alerts[0].Status != "resolved" || *l.Alerts[0].ResolvedReason != want.reason {
			t.Fatalf("%s: %+v", want.key, l)
		}
		last := lcGet(t, g.adminToken, l.Alerts[0].ID).History
		if k := last[len(last)-1].ActorKind; k != "operator" {
			t.Fatalf("%s: actor kind %s", want.key, k)
		}
	}
	if l := lcListAlerts(t, g.adminToken, ""); l.Counts.Open != 0 || l.Counts.Acknowledged != 0 {
		t.Fatalf("alerts left active after every policy left Unapproved: %+v", l.Counts)
	}
}

// PAT-2055 through the real extractor: an extension alert resolves only on
// an authoritative browser_extensions_status report after the extension was
// last listed. A capped report is never authority, even for a pair it calls
// complete.
func TestSoftwareAlertExtensionNeedsAbsenceAuthority(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2097-ext-"+sfx)
	extID := chromeID(t)
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', $2, 'Ext Authority', 'unapproved')`, tn.tenantID, extID); err != nil {
		t.Fatal(err)
	}
	hw := newHW(sfx)
	ext := []map[string]any{beExt("chrome", "alice", extID, "Ext Authority "+sfx)}
	dev := bePost(t, tn, hw, ext, beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present")))
	id, status, _, _, _ := lcRow(t, tn.tenantID, dev)
	if status != "open" {
		t.Fatalf("raise = %s", status)
	}
	// Capped: the block is partial with the cap reached, and alice's chrome
	// pair claims complete. The cap withholds authority.
	bePost(t, tn, hw, nil, beStatus("partial", true, beStatusUser("alice", "partial", "complete", "not_present", "not_present")))
	if _, status, _, _, _ := lcRow(t, tn.tenantID, dev); status != "open" {
		t.Fatalf("a capped report resolved the extension alert: %s", status)
	}
	// Partial, uncapped, pair partial: still no authority.
	bePost(t, tn, hw, nil, beStatus("partial", false, beStatusUser("alice", "partial", "partial", "not_present", "not_present")))
	if _, status, _, _, _ := lcRow(t, tn.tenantID, dev); status != "open" {
		t.Fatalf("a partial report resolved the extension alert: %s", status)
	}
	// Complete, uncapped, after last_seen.
	bePost(t, tn, hw, nil, beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present")))
	if gotID, status, reason, _, _ := lcRow(t, tn.tenantID, dev); gotID != id || status != "resolved" || reason == nil || *reason != "not_observed" {
		t.Fatalf("extension alert after authoritative absence = %s %v", status, reason)
	}
}

// The operator queue lists open and acknowledged alerts across tenants, with
// tenant and age, and never resolved ones unless asked.
func TestSoftwareAlertOperatorQueue(t *testing.T) {
	a := newGovTenant(t, "opq-a", "")
	b := newGovTenant(t, "opq-b", "")
	for i, g := range []*govTenant{a, b} {
		dev := govDevice(t, g.id, fmt.Sprintf("opq-mac-%02d", i), "macOS", time.Now())
		team := fmt.Sprintf("OPQTEAM%03d", i)
		govApp(t, dev, "Queue Thing", "com.gov.opq", team)
		mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.opq", team)))
	}
	// Tenant b's product is approved: its alert resolves and leaves the queue.
	mustApprove(t, b.adminToken, approvalBody("approved", "", macApp("com.gov.opq", "OPQTEAM001")))

	code, raw := lcAdmin(t, http.MethodGet, "/admin/software-alerts?limit=500", "")
	if code != http.StatusOK {
		t.Fatalf("operator queue = %d %s", code, raw)
	}
	var q struct {
		Total  int       `json:"total"`
		Alerts []lcAlert `json:"alerts"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	seenA, seenB := false, false
	for _, al := range q.Alerts {
		if al.Status == "resolved" {
			t.Fatalf("resolved alert in the default queue: %+v", al)
		}
		switch al.TenantID {
		case a.id:
			seenA = true
			if al.TenantName == "" || al.AgeSeconds == nil || al.Product.Name != "Queue Thing" {
				t.Fatalf("queue row = %+v", al)
			}
		case b.id:
			seenB = true
		}
	}
	if !seenA || seenB {
		t.Fatalf("queue tenants: a=%v b=%v", seenA, seenB)
	}
	code, raw = lcAdmin(t, http.MethodGet, "/admin/software-alerts?status=resolved&tenant_id="+b.id, "")
	if err := json.Unmarshal(raw, &q); err != nil || code != http.StatusOK || q.Total != 1 || q.Alerts[0].TenantID != b.id {
		t.Fatalf("resolved filter = %d %s", code, raw)
	}
}

// The overview's unapproved_present counts distinct products from live
// inventory; the alert counts are per (product policy, device). In a steady
// state with the alert on, the devices carrying unapproved software are
// exactly the devices with an open or acknowledged alert, acknowledging
// changes neither figure's device set, and approving clears both.
func TestSoftwareAlertOverviewCountsTieOut(t *testing.T) {
	g := newGovTenant(t, "overview", "")
	now := time.Now().UTC()
	d1 := govDevice(t, g.id, "ov-mac-01", "macOS", now)
	d2 := govDevice(t, g.id, "ov-mac-02", "macOS", now)
	govApp(t, d1, "Overview Bad", "com.gov.ovbad", "OVBADTEAM1")
	govApp(t, d2, "Overview Bad", "com.gov.ovbad", "OVBADTEAM1")
	govApp(t, d1, "Overview Worse", "com.gov.ovworse", "OVWORSETM1")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.ovbad", "OVBADTEAM1"), macApp("com.gov.ovworse", "OVWORSETM1")))

	type overview struct {
		Present      *int `json:"unapproved_present"`
		Devices      *int `json:"unapproved_present_devices"`
		Open         *int `json:"unapproved_alerts_open"`
		Acknowledged *int `json:"unapproved_alerts_acknowledged"`
	}
	read := func() overview {
		var ov overview
		getJSON(t, "/v1/portal/overview", g.viewerToken, &ov)
		if ov.Present == nil || ov.Devices == nil || ov.Open == nil || ov.Acknowledged == nil {
			t.Fatalf("overview figures missing: %+v", ov)
		}
		return ov
	}
	activeDevices := func() int {
		return countRows(t, `SELECT count(DISTINCT device_id) FROM software_unapproved_alerted_devices
			WHERE tenant_id = $1::uuid AND status IN ('open', 'acknowledged')`, g.id)
	}
	ov := read()
	if *ov.Present != 2 || *ov.Devices != 2 || *ov.Open != 3 || *ov.Acknowledged != 0 || activeDevices() != *ov.Devices {
		t.Fatalf("steady state = present %d devices %d open %d ack %d active devices %d",
			*ov.Present, *ov.Devices, *ov.Open, *ov.Acknowledged, activeDevices())
	}

	l := lcListAlerts(t, g.adminToken, "?device_id="+d2)
	if code, _, _ := lcAck(t, g.adminToken, l.Alerts[0].ID, ""); code != http.StatusOK {
		t.Fatal("ack failed")
	}
	ov = read()
	if *ov.Present != 2 || *ov.Devices != 2 || *ov.Open != 2 || *ov.Acknowledged != 1 || activeDevices() != *ov.Devices {
		t.Fatalf("after ack = %+v", ov)
	}

	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.ovbad", "OVBADTEAM1"), macApp("com.gov.ovworse", "OVWORSETM1")))
	ov = read()
	if *ov.Present != 0 || *ov.Devices != 0 || *ov.Open != 0 || *ov.Acknowledged != 0 || activeDevices() != 0 {
		t.Fatalf("after approve = %+v", ov)
	}
}

// lcReconcile runs the lifecycle for one device as a complete report would.
func lcReconcile(t *testing.T, tenantID, deviceID string) {
	t.Helper()
	if _, err := softwaregov.ReconcileDevice(context.Background(), env.pool, tenantID, deviceID,
		softwaregov.DeviceAuthority{AppsComplete: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func lcLastTransition(t *testing.T, id int64) (reason string, detail map[string]any) {
	t.Helper()
	var raw []byte
	var r *string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT reason, detail FROM software_unapproved_alert_transitions
		WHERE alert_device_id = $1 ORDER BY id DESC LIMIT 1`, id).Scan(&r, &raw); err != nil {
		t.Fatal(err)
	}
	if r != nil {
		reason = *r
	}
	_ = json.Unmarshal(raw, &detail)
	return reason, detail
}

func lcOperatorRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Put("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesPutHandler(env.pool, nil))
	return r
}

func lcOperatorPut(t *testing.T, tenantID, body string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", strings.NewReader(body))
	rec := &responseRecorder{header: http.Header{}}
	lcOperatorRouter().ServeHTTP(rec, req)
	if rec.status >= 300 {
		t.Fatalf("operator PUT = %d: %s", rec.status, rec.body.String())
	}
	drainUnapprovedRaises(t)
}

// P1-a: a broad operator Unapproved row (name only) and a more specific
// portal Approved row. The product is still installed; the broad row's
// alert must not resolve as not_observed. It resolves as superseded, naming
// the row that now governs the product.
func TestSoftwareAlertStillInstalledUnderAnotherPolicyIsSuperseded(t *testing.T) {
	g := newGovTenant(t, "broad", "")
	dev := govDevice(t, g.id, "broad-mac-01", "macOS", time.Now())
	govApp(t, dev, "Broad Thing", "com.gov.broadthing", "BROADTEAM1")
	lcOperatorPut(t, g.id, `{"name":"Broad Thing","platform":"macos","policy":"unapproved"}`)
	id, status, _, _, _ := lcRow(t, g.id, dev)
	if status != "open" {
		t.Fatalf("raise = %s", status)
	}
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.broadthing", "BROADTEAM1")))
	var specific int64
	if err := env.pool.QueryRow(context.Background(), `SELECT id FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND bundle_id = 'com.gov.broadthing'`, g.id).Scan(&specific); err != nil {
		t.Fatal(err)
	}
	if _, status, _, _, _ := lcRow(t, g.id, dev); status != "open" {
		t.Fatalf("fixture: the specific approval should not touch the broad row's alert, got %s", status)
	}
	lcReconcile(t, g.id, dev)
	_, status, reason, _, _ := lcRow(t, g.id, dev)
	if status != "resolved" || reason == nil || *reason != "superseded" {
		t.Fatalf("still-installed app = %s %v, want resolved superseded", status, reason)
	}
	r, detail := lcLastTransition(t, id)
	if r != "superseded" || detail["evidence"] != "governed_by_other_policy" ||
		detail["winning_state"] != "approved" || detail["winning_policy_id"] != float64(specific) {
		t.Fatalf("transition = %s %+v", r, detail)
	}
	// Still governed by the specific row: no re-open.
	lcReconcile(t, g.id, dev)
	if _, status, _, _, _ := lcRow(t, g.id, dev); status != "resolved" {
		t.Fatalf("a superseded alert re-opened while another row governs it: %s", status)
	}
	// The specific row goes (the product back to Unreviewed on its own
	// key); the broad Unapproved row governs it again, so the same alert
	// re-opens rather than staying silent.
	mustApprove(t, g.adminToken, approvalBody("unreviewed", "", macApp("com.gov.broadthing", "BROADTEAM1")))
	lcReconcile(t, g.id, dev)
	gotID, status, reason, reopened, _ := lcRow(t, g.id, dev)
	if gotID != id || status != "open" || reason != nil || reopened != 1 {
		t.Fatalf("after the specific row left: id %d (want %d) %s %v reopened=%d", gotID, id, status, reason, reopened)
	}
	if n := countRows(t, `SELECT count(*) FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid`, dev); n != 1 {
		t.Fatalf("re-open created a duplicate: %d rows", n)
	}
}

// P1-a: a display-name change under a name-only policy leaves the app
// installed under the same identifier. Not observed would be false.
func TestSoftwareAlertRenameUnderNamePolicyIsNotAbsence(t *testing.T) {
	g := newGovTenant(t, "rename", "")
	dev := govDevice(t, g.id, "rename-mac-01", "macOS", time.Now())
	govApp(t, dev, "Old Name Tool", "com.gov.renamed", "RENAMETM01")
	lcOperatorPut(t, g.id, `{"name":"Old Name Tool","platform":"macos","policy":"unapproved"}`)
	id, status, _, _, _ := lcRow(t, g.id, dev)
	if status != "open" {
		t.Fatalf("raise = %s", status)
	}
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE device_apps SET name = 'New Name Tool' WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	lcReconcile(t, g.id, dev)
	_, status, reason, _, _ := lcRow(t, g.id, dev)
	if status != "resolved" || reason == nil || *reason != "superseded" {
		t.Fatalf("renamed app = %s %v, want resolved superseded", status, reason)
	}
	if _, detail := lcLastTransition(t, id); detail["winning_state"] != "unreviewed" || detail["winning_policy_id"] != nil {
		t.Fatalf("detail = %+v", detail)
	}
	// Actually uninstalled: nothing matches by identifier or name, and a
	// separate alert that is still open resolves as not_observed.
	govApp(t, dev, "Other Tool", "com.gov.othertool", "OTHERTEAM1")
	lcOperatorPut(t, g.id, `{"bundle_id":"com.gov.othertool","platform":"macos","policy":"unapproved"}`)
	if _, err := env.pool.Exec(context.Background(),
		`DELETE FROM device_apps WHERE device_id = $1::uuid AND identifier = 'com.gov.othertool'`, dev); err != nil {
		t.Fatal(err)
	}
	lcReconcile(t, g.id, dev)
	if _, status, reason, _, _ := lcRow(t, g.id, dev); status != "resolved" || *reason != "not_observed" {
		t.Fatalf("uninstalled = %s %v", status, *reason)
	}
}

// P1-b forward rule: opening a new episode for a policy resolves the earlier
// episode's active alerts as superseded in the same transaction, so a
// (policy, device) has at most one active alert.
func TestSoftwareAlertNewEpisodeSupersedesPrior(t *testing.T) {
	g := newGovTenant(t, "episode", "")
	dev := govDevice(t, g.id, "episode-mac-01", "macOS", time.Now())
	govApp(t, dev, "Episode Thing", "com.gov.episode", "EPISODETM1")
	lcOperatorPut(t, g.id, `{"bundle_id":"com.gov.episode","platform":"macos","policy":"unapproved"}`)
	oldID, _, _, _, _ := lcRow(t, g.id, dev)
	var policyID int64
	if err := env.pool.QueryRow(context.Background(), `SELECT id FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND bundle_id = 'com.gov.episode'`, g.id).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	// A second transition recorded while the first episode's alert is open.
	if _, err := softwaregov.RaiseMarks(context.Background(), env.pool, g.id, []softwaregov.Mark{{
		TenantID: g.id, PolicyKind: softwaregov.TypeApplication, PolicyID: policyID, Source: softwaregov.SourceOperator,
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, `SELECT count(*) FROM software_unapproved_alerted_devices
		WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND status IN ('open', 'acknowledged')`, g.id, dev); n != 1 {
		t.Fatalf("active alerts for one (policy, device) = %d, want 1", n)
	}
	var status, reason string
	if err := env.pool.QueryRow(context.Background(), `SELECT status, COALESCE(resolved_reason, '')
		FROM software_unapproved_alerted_devices WHERE id = $1`, oldID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" || reason != "superseded" {
		t.Fatalf("prior episode alert = %s/%s", status, reason)
	}
	if _, detail := lcLastTransition(t, oldID); detail["evidence"] != "superseded_episode" {
		t.Fatalf("detail = %+v", detail)
	}
	// A superseded episode never re-opens, though the product is present
	// and still Unapproved.
	lcReconcile(t, g.id, dev)
	if err := env.pool.QueryRow(context.Background(), `SELECT status FROM software_unapproved_alerted_devices
		WHERE id = $1`, oldID).Scan(&status); err != nil || status != "resolved" {
		t.Fatalf("a superseded episode re-opened: %s %v", status, err)
	}
}

// P2: only an absence re-opens. An alert resolved because its policy became
// Approved stays resolved even if the row is later set back to Unapproved by
// a path that opens no episode.
func TestSoftwareAlertPolicyResolutionNeverReopens(t *testing.T) {
	g := newGovTenant(t, "noreopen", "")
	dev := govDevice(t, g.id, "noreopen-mac-01", "macOS", time.Now())
	govApp(t, dev, "No Reopen", "com.gov.noreopen", "NOREOPENT1")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.noreopen", "NOREOPENT1")))
	mustApprove(t, g.adminToken, approvalBody("approved", "", macApp("com.gov.noreopen", "NOREOPENT1")))
	id, status, reason, _, _ := lcRow(t, g.id, dev)
	if status != "resolved" || *reason != "approved" {
		t.Fatalf("fixture = %s %v", status, reason)
	}
	if _, err := env.pool.Exec(context.Background(), `UPDATE tenant_app_policies SET policy = 'unapproved'
		WHERE tenant_id = $1::uuid AND bundle_id = 'com.gov.noreopen'`, g.id); err != nil {
		t.Fatal(err)
	}
	lcReconcile(t, g.id, dev)
	if gotID, status, _, reopened, _ := lcRow(t, g.id, dev); gotID != id || status != "resolved" || reopened != 0 {
		t.Fatalf("a policy-resolved alert re-opened: %s reopened=%d", status, reopened)
	}
}

// lcReopenedTenant builds a tenant whose one alert has been re-opened, with
// its first digest already sent, and returns it and the digest slot.
func lcReopenedTenant(t *testing.T, label, contact string) (*lcIngest, time.Time, *fakeMailer) {
	t.Helper()
	f := newLCIngest(t, label)
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE tenants SET contact_email = $2 WHERE id = $1::uuid`, f.tn.tenantID, contact); err != nil {
		t.Fatal(err)
	}
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.fil})
	mail := &fakeMailer{}
	slot := softwaregov.DailySlot(time.Now().UTC(), softwaregov.DigestHourUTC)
	runRunner(t, mail, slot.Add(24*time.Hour+time.Minute))
	f.post(t, appsPost{schemaV3: true, status: "complete", apps: f.withBad()})
	if _, _, _, reopened, digest := lcRow(t, f.tn.tenantID, f.dev); reopened != 1 || !digest {
		t.Fatalf("fixture: reopened=%d digest=%v", reopened, digest)
	}
	return f, slot.Add(48 * time.Hour), mail
}

// P3: a digest carrying only re-opens that fails transiently retries like a
// pending alert does, without spending the slot.
func TestSoftwareAlertReopenDigestRetriesTransientFailure(t *testing.T) {
	f, slot, mail := lcReopenedTenant(t, "reopenretry", "it@reopenretry.example")
	mail.err = fmt.Errorf("graph briefly unavailable")
	runRunner(t, mail, slot.Add(time.Minute))
	if _, _, _, _, digest := lcRow(t, f.tn.tenantID, f.dev); !digest {
		t.Fatal("a failed send cleared the re-open")
	}
	mail.err = nil
	runRunner(t, mail, slot.Add(10*time.Minute))
	got := mail.to("it@reopenretry.example")
	if len(got) != 2 || !strings.Contains(got[1].Body, "Found again on (1)") {
		t.Fatalf("the retry within the same slot did not send the re-open: %d emails", len(got))
	}
	if _, _, _, _, digest := lcRow(t, f.tn.tenantID, f.dev); digest {
		t.Fatal("the re-open is still pending after its digest")
	}
}

// P3: a re-open newer than the digest's slot, recorded while the digest is
// being sent, stays pending for the next digest.
func TestSoftwareAlertReopenAfterSlotIsNotLost(t *testing.T) {
	f, slot, mail := lcReopenedTenant(t, "reopenrace", "it@reopenrace.example")
	mail.onSend = func() {
		mail.onSend = nil
		if _, err := env.pool.Exec(context.Background(), `UPDATE software_unapproved_alerted_devices
			SET last_reopened_at = $2, reopened_count = reopened_count + 1 WHERE device_id = $1::uuid`,
			f.dev, slot.Add(2*time.Minute)); err != nil {
			t.Error(err)
		}
	}
	runRunner(t, mail, slot.Add(5*time.Minute))
	if len(mail.to("it@reopenrace.example")) != 2 {
		t.Fatal("fixture: expected the digest")
	}
	if _, _, _, _, digest := lcRow(t, f.tn.tenantID, f.dev); !digest {
		t.Fatal("a re-open newer than the digest slot was cleared without being reported")
	}
}

// P3: reads and counts join only the tenant's own devices. A tracked alert
// pointing at another tenant's device is neither counted nor described with
// that device's hostname.
func TestSoftwareAlertDeviceJoinIsTenantScoped(t *testing.T) {
	g := newGovTenant(t, "devjoin", "")
	other := newGovTenant(t, "devjoin-other", "")
	dev := govDevice(t, g.id, "devjoin-mac-01", "macOS", time.Now())
	foreign := govDevice(t, other.id, "someone-elses-mac", "macOS", time.Now())
	govApp(t, dev, "Join Thing", "com.gov.jointhing", "JOINTEAM01")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.jointhing", "JOINTEAM01")))
	var episode int64
	if err := env.pool.QueryRow(context.Background(), `SELECT episode_id FROM software_unapproved_alerted_devices
		WHERE tenant_id = $1::uuid`, g.id).Scan(&episode); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(context.Background(), `INSERT INTO software_unapproved_alerted_devices
		(episode_id, device_id, tenant_id, suppressed_baseline) VALUES ($1, $2::uuid, $3::uuid, true)`,
		episode, foreign, g.id); err != nil {
		t.Fatal(err)
	}
	var ov struct {
		Open *int `json:"unapproved_alerts_open"`
	}
	getJSON(t, "/v1/portal/overview", g.viewerToken, &ov)
	if ov.Open == nil || *ov.Open != 1 {
		t.Fatalf("overview counted an alert on another tenant's device: %v", ov.Open)
	}
	for _, a := range lcListAlerts(t, g.adminToken, "").Alerts {
		if a.Device.Hostname == "someone-elses-mac" {
			t.Fatal("the alert list disclosed another tenant's device hostname")
		}
	}
}

// P3: the operator cannot acknowledge a revoked tenant's alert, as the
// operator queue does not list it.
func TestSoftwareAlertOperatorAckNeedsActiveTenant(t *testing.T) {
	g := newGovTenant(t, "revoked", "")
	dev := govDevice(t, g.id, "revoked-mac-01", "macOS", time.Now())
	govApp(t, dev, "Revoked Thing", "com.gov.revoked", "REVOKEDTM1")
	mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp("com.gov.revoked", "REVOKEDTM1")))
	id, _, _, _, _ := lcRow(t, g.id, dev)
	if _, err := env.pool.Exec(context.Background(), `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, g.id); err != nil {
		t.Fatal(err)
	}
	if code, body := lcAdmin(t, http.MethodPost, fmt.Sprintf("/admin/tenants/%s/software-alerts/%d/acknowledge", g.id, id), ""); code != http.StatusNotFound {
		t.Fatalf("operator ack on a revoked tenant = %d %s", code, body)
	}
}

// lcRaw sends one portal request and returns the status, the Content-Type and
// the exact body bytes, so two responses can be compared byte for byte.
func lcRaw(t *testing.T, method, path, token, body string) (code int, contentType, raw string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	resp := portalDo(t, method, path, token, rdr)
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
}

// PAT-2442: another tenant's alert id must be indistinguishable from an id
// that does not exist, on read and on acknowledge, and a refused call must
// leave the victim's row and history untouched. The alert id is one global
// sequence, so an id from tenant A is a valid guess in tenant B. The test
// compares the two responses byte for byte and reads the victim's row back
// from the database, so it goes red if either tenant filter is removed.
func TestSoftwareAlertForeignIDIsIndistinguishableFromAbsent(t *testing.T) {
	sfx := randomHex(4)
	victim := newGovTenant(t, "fid-victim", "")
	attacker := newGovTenant(t, "fid-attacker", "")

	host := "pat2442-host-" + sfx
	productName := "Pat2442 Secret Product " + sfx
	bundle := "com.pat2442.secret" + sfx
	team := "T2" + strings.ToUpper(randomHex(4))
	dev := govDevice(t, victim.id, host, "macOS", time.Now().UTC())
	govApp(t, dev, productName, bundle, team)
	mustApprove(t, victim.adminToken, approvalBody("unapproved", "", macApp(bundle, team)))
	victimID, status, _, _, _ := lcRow(t, victim.id, dev)
	if status != "open" {
		t.Fatalf("victim alert status = %q, want open", status)
	}
	transitionsBefore := lcTransitions(t, victimID)
	if transitionsBefore != 1 {
		t.Fatalf("victim alert should carry its opening transition, got %d", transitionsBefore)
	}

	var absentID int64
	if err := env.pool.QueryRow(context.Background(),
		`SELECT COALESCE(max(id), 0) + 100000 FROM software_unapproved_alerted_devices`).Scan(&absentID); err != nil {
		t.Fatalf("pick an absent alert id: %v", err)
	}

	// Anything in the victim's alert that must never reach the attacker.
	markers := []string{host, productName, bundle, team, victim.adminEmail, victim.id, dev}

	// Positive control: the victim's own admin reads the alert, and the markers
	// are really in the body. Without this the test would pass on a server
	// that answers 404 to everything.
	code, _, body := lcRaw(t, http.MethodGet, fmt.Sprintf("/v1/portal/software-alerts/%d", victimID), victim.adminToken, "")
	if code != http.StatusOK {
		t.Fatalf("positive control: victim admin GET = %d %s", code, body)
	}
	for _, m := range []string{host, productName, bundle, team} {
		if !strings.Contains(body, m) {
			t.Fatalf("positive control: victim body lacks marker %q, so the leak check below would prove nothing: %s", m, body)
		}
	}

	noMarkers := func(label, raw string) {
		t.Helper()
		lower := strings.ToLower(raw)
		for _, m := range markers {
			if strings.Contains(lower, strings.ToLower(m)) {
				t.Errorf("%s: response discloses the victim's %q: %s", label, m, raw)
			}
		}
	}
	readPath := func(id int64) string { return fmt.Sprintf("/v1/portal/software-alerts/%d", id) }
	ackPath := func(id int64) string { return fmt.Sprintf("/v1/portal/software-alerts/%d/acknowledge", id) }

	type result struct {
		code        int
		contentType string
		body        string
	}
	// compare issues the same request for the victim's id and for an absent id,
	// and requires the same status, Content-Type and body bytes.
	compare := func(label, method string, path func(int64) string, token, reqBody string, want int, wantSubstr string) {
		t.Helper()
		var got [2]result
		for i, id := range []int64{victimID, absentID} {
			c, ct, b := lcRaw(t, method, path(id), token, reqBody)
			got[i] = result{c, ct, b}
			noMarkers(fmt.Sprintf("%s (id %d)", label, id), b)
			if c != want {
				t.Errorf("%s (id %d): status = %d, want %d: %s", label, id, c, want, b)
			}
			if wantSubstr != "" && !strings.Contains(b, wantSubstr) {
				t.Errorf("%s (id %d): body lacks %q: %s", label, id, wantSubstr, b)
			}
		}
		if got[0].contentType != got[1].contentType {
			t.Errorf("%s: Content-Type differs for a foreign id (%q) and an absent id (%q)", label, got[0].contentType, got[1].contentType)
		}
		if got[0].body != got[1].body {
			t.Errorf("%s: body differs for a foreign id and an absent id:\n  foreign: %s\n  absent:  %s", label, got[0].body, got[1].body)
		}
	}

	compare("attacker admin GET", http.MethodGet, readPath, attacker.adminToken, "", http.StatusNotFound, `"not_found"`)
	compare("attacker viewer GET", http.MethodGet, readPath, attacker.viewerToken, "", http.StatusNotFound, `"not_found"`)
	compare("attacker admin acknowledge", http.MethodPost, ackPath, attacker.adminToken, `{"note":"attacker note"}`, http.StatusNotFound, `"not_found"`)
	compare("attacker viewer acknowledge", http.MethodPost, ackPath, attacker.viewerToken, `{"note":"attacker note"}`, http.StatusForbidden, "admin_role_required")

	// The victim's row, read straight from the database, is untouched.
	var rowStatus string
	var ackedAt *time.Time
	var ackedBy *string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT status, acknowledged_at, acknowledged_by
		FROM software_unapproved_alerted_devices WHERE id = $1`, victimID).Scan(&rowStatus, &ackedAt, &ackedBy); err != nil {
		t.Fatalf("read victim row: %v", err)
	}
	if rowStatus != "open" || ackedAt != nil || ackedBy != nil {
		by := "<null>"
		if ackedBy != nil {
			by = *ackedBy
		}
		t.Errorf("the victim's alert was changed by another tenant: status=%q acknowledged_at=%v acknowledged_by=%s",
			rowStatus, ackedAt, by)
	}
	if n := lcTransitions(t, victimID); n != transitionsBefore {
		t.Errorf("victim transition count = %d after the attack, want %d", n, transitionsBefore)
	}
	if n := countRows(t, `SELECT count(*) FROM software_unapproved_alert_transitions
		WHERE alert_device_id = $1 AND tenant_id = $2::uuid`, victimID, attacker.id); n != 0 {
		t.Errorf("%d transition row(s) for the victim's alert carry the attacker's tenant id", n)
	}
	if got := lcGet(t, victim.adminToken, victimID); got.Status != "open" || len(got.History) != 1 {
		t.Errorf("victim's own view after the attack: status=%q history=%d, want open with 1 transition", got.Status, len(got.History))
	}
}

// PAT-2442: software_unapproved_alerts has its own tenant_id, and the ledger's
// foreign key is on alert_id alone, so the schema does not stop a ledger row
// pointing at another tenant's outbound alert. The alert views read only the
// trigger from that row; it must come from the row's own tenant.
func TestSoftwareAlertViewIgnoresAnotherTenantsAlertRow(t *testing.T) {
	a := newGovTenant(t, "lnk-a", "")
	b := newGovTenant(t, "lnk-b", "")
	mk := func(g *govTenant, label string) (ledgerID int64, deviceID string) {
		deviceID = govDevice(t, g.id, "lnk-"+label+"-mac-01", "macOS", time.Now().UTC())
		bundle := "com.gov.lnk" + label
		team := "LNKTEAM" + strings.ToUpper(label) + "01"
		govApp(t, deviceID, "Lnk Thing "+label, bundle, team)
		mustApprove(t, g.adminToken, approvalBody("unapproved", "", macApp(bundle, team)))
		ledgerID, _, _, _, _ = lcRow(t, g.id, deviceID)
		return ledgerID, deviceID
	}
	aID, aDev := mk(a, "a")
	bID, _ := mk(b, "b")

	outboundOf := func(ledgerID int64) (alertRow int64) {
		if err := env.pool.QueryRow(context.Background(),
			`SELECT alert_id FROM software_unapproved_alerted_devices WHERE id = $1`, ledgerID).Scan(&alertRow); err != nil {
			t.Fatalf("read alert_id of %d: %v", ledgerID, err)
		}
		return alertRow
	}
	aRow, bRow := outboundOf(aID), outboundOf(bID)
	if aRow == bRow {
		t.Fatalf("both tenants share outbound alert %d", aRow)
	}

	// A's own outbound alert becomes 'observed' (a per-device alert, so it
	// carries the device, as the CHECK on the table requires). B's stays
	// 'marked'. An unlinked ledger row reads 'observed', so B's 'marked' is the
	// value that would show if the join followed the foreign row.
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE software_unapproved_alerts SET trigger = 'observed', device_id = $2::uuid WHERE id = $1 AND tenant_id = $3::uuid`,
		aRow, aDev, a.id); err != nil {
		t.Fatalf("set tenant A's alert to observed: %v", err)
	}

	// Control: each tenant reads the trigger of its own outbound alert.
	if got := lcGet(t, a.adminToken, aID); got.Trigger != "observed" {
		t.Fatalf("control: tenant A trigger = %q, want observed", got.Trigger)
	}
	if got := lcGet(t, b.adminToken, bID); got.Trigger != "marked" {
		t.Fatalf("control: tenant B trigger = %q, want marked", got.Trigger)
	}

	// Point A's ledger row at B's outbound alert.
	if _, err := env.pool.Exec(context.Background(),
		`UPDATE software_unapproved_alerted_devices SET alert_id = $2 WHERE id = $1 AND tenant_id = $3::uuid`,
		aID, bRow, a.id); err != nil {
		t.Fatalf("point tenant A's ledger row at tenant B's alert: %v", err)
	}

	if got := lcGet(t, a.adminToken, aID); got.Trigger == "marked" {
		t.Errorf("tenant A's detail shows tenant B's trigger %q", got.Trigger)
	} else if got.Trigger != "observed" {
		t.Errorf("tenant A's detail trigger = %q, want the unlinked fallback observed", got.Trigger)
	}
	list := lcListAlerts(t, a.adminToken, "")
	if len(list.Alerts) != 1 {
		t.Fatalf("tenant A list = %+v", list)
	}
	if list.Alerts[0].Trigger == "marked" {
		t.Errorf("tenant A's list shows tenant B's trigger %q", list.Alerts[0].Trigger)
	} else if list.Alerts[0].Trigger != "observed" {
		t.Errorf("tenant A's list trigger = %q, want the unlinked fallback observed", list.Alerts[0].Trigger)
	}
	// B is unaffected.
	if got := lcGet(t, b.adminToken, bID); got.Trigger != "marked" {
		t.Errorf("tenant B trigger = %q after the mis-link, want marked", got.Trigger)
	}
}
