//go:build integration

package integration

// PAT-2145: Jamf Pro webhook ingest and the portal Jamf coverage API, end to
// end through the real routers: token lifecycle and roles, cross-tenant
// forgery, personal-field dropping (database and logs), body cap, media
// type, subscription, check-in collapsing, rotation, rate limit, and the
// three coverage buckets against a fixture.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/jamfcoverage"
)

// Planted personal values. None may appear in any stored row or log line.
const (
	jamfPlantEmail    = "planted.person.2145@example.invalid"
	jamfPlantUsername = "planteduser2145"
	jamfPlantIP       = "198.51.100.214"
	jamfPlantRealName = "Plantedfirst Plantedlast"
)

type jamfTokenOut struct {
	Action     string `json:"action"`
	Token      string `json:"token"`
	WebhookURL string `json:"webhook_url"`
}

type jamfSetupOut struct {
	Configured     bool    `json:"configured"`
	WebhookURL     *string `json:"webhook_url"`
	CheckInEnabled bool    `json:"check_in_enabled"`
	Token          struct {
		Exists        bool       `json:"exists"`
		LastRotatedAt *time.Time `json:"last_rotated_at"`
		RevokedAt     *time.Time `json:"revoked_at"`
	} `json:"token"`
	Events []struct {
		Event      string `json:"event"`
		Required   bool   `json:"required"`
		Subscribed bool   `json:"subscribed"`
	} `json:"events"`
}

// logCapture tees the default slog logger into a buffer for the test.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(c, os.Stderr), &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return c
}

func jamfComputer(serial, udid string, jssID int, name string) map[string]any {
	return map[string]any{
		"alternateMacAddress": "AA:BB:CC:DD:EE:01", "building": "Planted Building", "department": "Planted Department",
		"deviceName": name, "emailAddress": jamfPlantEmail, "ipAddress": jamfPlantIP, "jssID": jssID,
		"macAddress": "AA:BB:CC:DD:EE:02", "model": "MacBookPro18,3", "osBuild": "24G84", "osVersion": "15.6",
		"phone": "+44 7700 900214", "position": "Planted Position", "realName": jamfPlantRealName,
		"reportedIpAddress": jamfPlantIP, "room": "Planted Room", "serialNumber": serial, "udid": udid,
		"userDirectoryID": "planted-dir-2145", "username": jamfPlantUsername, "managementId": "mgmt-2145",
	}
}

func jamfBody(t *testing.T, typ string, event map[string]any, at time.Time) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"webhook": map[string]any{"eventTimestamp": at.UnixMilli(), "id": 1, "name": "Patched coverage", "webhookEvent": typ},
		"event":   event,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type jamfPost struct {
	url, token, body, contentType, instance, clientIP string
	basic                                             bool
	portalJWT                                         string
}

func (p jamfPost) do(t *testing.T) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, p.url, strings.NewReader(p.body))
	if err != nil {
		t.Fatal(err)
	}
	ct := p.contentType
	if ct == "" {
		ct = "application/json"
	}
	req.Header.Set("Content-Type", ct)
	switch {
	case p.token != "" && p.basic:
		req.SetBasicAuth("jamf", p.token)
	case p.token != "":
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	if p.instance != "" {
		req.Header.Set(jamfcoverage.InstanceHeader, p.instance)
	}
	if p.clientIP != "" {
		req.Header.Set("CF-Connecting-IP", p.clientIP)
	}
	if p.portalJWT != "" {
		req.Header.Set("Cf-Access-Jwt-Assertion", p.portalJWT)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func jamfPortal(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	status, b := portalCall(t, method, path, token, body)
	return status, string(b)
}

// localURL maps the public webhook URL onto the test server.
func localURL(t *testing.T, publicURL string) string {
	t.Helper()
	i := strings.Index(publicURL, "/v1/webhooks/jamf/")
	if i < 0 {
		t.Fatalf("webhook url %q has no /v1/webhooks/jamf/ path", publicURL)
	}
	return env.publicSrv.URL + publicURL[i:]
}

func createJamfToken(t *testing.T, adminToken string) jamfTokenOut {
	t.Helper()
	status, body := jamfPortal(t, http.MethodPost, "/v1/portal/mdm/jamf/token", adminToken, "")
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("POST /mdm/jamf/token = %d: %s", status, body)
	}
	var out jamfTokenOut
	mustJSON(t, []byte(body), &out)
	if !strings.HasPrefix(out.Token, "pjwh_") || out.WebhookURL == "" {
		t.Fatalf("token response malformed: %s", body)
	}
	return out
}

func jamfDeviceCount(t *testing.T, tenantID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM jamf_devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// tenantJamfRowsText is every stored Jamf row of the tenant as JSON text.
func tenantJamfRowsText(t *testing.T, tenantID string) string {
	t.Helper()
	var sb strings.Builder
	for _, q := range []string{
		`SELECT row_to_json(x)::text FROM jamf_devices x WHERE tenant_id = $1::uuid`,
		`SELECT row_to_json(x)::text FROM jamf_webhook_connectors x WHERE tenant_id = $1::uuid`,
		`SELECT row_to_json(x)::text FROM jamf_webhook_audit x WHERE tenant_id = $1::uuid`,
	} {
		rows, err := env.pool.Query(context.Background(), q, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			sb.WriteString(s)
			sb.WriteByte('\n')
		}
		rows.Close()
	}
	return sb.String()
}

func TestJamfWebhookTokenLifecycleAndRoles(t *testing.T) {
	a := newApprovalTenant(t, "jamf-roles", false)

	// Before setup every role reads a not-configured page.
	status, body := jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/setup", a.viewerToken, "")
	if status != http.StatusOK {
		t.Fatalf("viewer GET setup = %d: %s", status, body)
	}
	var setup jamfSetupOut
	mustJSON(t, []byte(body), &setup)
	if setup.Configured || setup.WebhookURL != nil || setup.Token.Exists {
		t.Fatalf("unconfigured setup = %s", body)
	}
	if len(setup.Events) != 4 {
		t.Fatalf("events = %+v", setup.Events)
	}
	for _, e := range setup.Events {
		if (e.Event == jamfcoverage.EventComputerCheckIn) == e.Required || e.Subscribed != e.Required {
			t.Errorf("event %+v: only ComputerCheckIn is optional and it starts unsubscribed", e)
		}
	}
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage", a.viewerToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"not_configured"`) {
		t.Fatalf("viewer GET coverage before setup = %d: %s", status, body)
	}

	// Writes are admin only.
	for _, w := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/portal/mdm/jamf/token", ""},
		{http.MethodDelete, "/v1/portal/mdm/jamf/token", ""},
		{http.MethodPut, "/v1/portal/mdm/jamf/setup", `{"check_in_enabled":true}`},
	} {
		if status, body := jamfPortal(t, w.method, w.path, a.viewerToken, w.body); status != http.StatusForbidden || !strings.Contains(body, "admin_role_required") {
			t.Errorf("viewer %s %s = %d: %s", w.method, w.path, status, body)
		}
	}
	// No connector yet: the subscription write says so.
	if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.adminToken, `{"check_in_enabled":true}`); status != http.StatusConflict {
		t.Fatalf("PUT setup before token = %d: %s", status, body)
	}
	// A body on the token write is refused.
	if status, body := jamfPortal(t, http.MethodPost, "/v1/portal/mdm/jamf/token", a.adminToken, `{"x":1}`); status != http.StatusBadRequest {
		t.Fatalf("POST token with body = %d: %s", status, body)
	}

	tok := createJamfToken(t, a.adminToken)
	if tok.Action != "token_created" {
		t.Fatalf("first action = %q", tok.Action)
	}
	webhookID := tok.WebhookURL[strings.LastIndex(tok.WebhookURL, "/")+1:]
	if len(webhookID) != 32 || strings.Contains(tok.WebhookURL, a.tenantID) {
		t.Fatalf("webhook URL %q must carry an opaque 32-character id, never the tenant id", tok.WebhookURL)
	}
	if !strings.HasPrefix(tok.WebhookURL, handlers.JamfWebhookPublicBaseURL+"/v1/webhooks/jamf/") {
		t.Fatalf("webhook URL %q not built from the configured public base", tok.WebhookURL)
	}
	// Only the hash is stored.
	var stored []byte
	if err := env.pool.QueryRow(context.Background(), `SELECT token_hash FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 32 || strings.Contains(tenantJamfRowsText(t, a.tenantID), strings.TrimPrefix(tok.Token, "pjwh_")) {
		t.Fatal("the token plaintext is stored")
	}
	// Viewers see the URL and status, never the token.
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/setup", a.viewerToken, "")
	if status != http.StatusOK || strings.Contains(body, tok.Token) || !strings.Contains(body, webhookID) {
		t.Fatalf("viewer setup after create = %d: %s", status, body)
	}

	url := localURL(t, tok.WebhookURL)
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02ROLE0001", "", 11, "role-mac"), time.Now())
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("event with the new token = %d: %s", status, body)
	}
	// HTTP Basic with the token as password also authenticates.
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev, basic: true}).do(t); status != http.StatusAccepted {
		t.Fatalf("basic auth event = %d: %s", status, body)
	}

	// Rotation: the old token stops working at once, the new one works,
	// and the URL does not change.
	rot := createJamfToken(t, a.adminToken)
	if rot.Action != "token_rotated" || rot.WebhookURL != tok.WebhookURL || rot.Token == tok.Token {
		t.Fatalf("rotate = %+v", rot)
	}
	if status, _ := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusUnauthorized {
		t.Fatalf("old token after rotation = %d, want 401", status)
	}
	if status, body := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("new token after rotation = %d: %s", status, body)
	}

	// Revoke: every token is refused; revoking again is a no-op.
	status, body = jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/token", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"changed":true`) {
		t.Fatalf("revoke = %d: %s", status, body)
	}
	if status, _ := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d, want 401", status)
	}
	status, body = jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/token", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"changed":false`) {
		t.Fatalf("second revoke = %d: %s", status, body)
	}
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage", a.viewerToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"status":"revoked"`) {
		t.Fatalf("coverage after revoke = %d: %s", status, body)
	}

	// The audit has every change with the admin's email, and is append-only.
	rows, err := env.pool.Query(context.Background(), `SELECT action, actor_email FROM jamf_webhook_audit WHERE tenant_id = $1::uuid ORDER BY id`, a.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for rows.Next() {
		var action, actor string
		if err := rows.Scan(&action, &actor); err != nil {
			t.Fatal(err)
		}
		if actor != a.adminEmail {
			t.Errorf("audit actor = %q, want %q", actor, a.adminEmail)
		}
		actions = append(actions, action)
	}
	rows.Close()
	if got := strings.Join(actions, ","); got != "token_created,token_rotated,token_revoked" {
		t.Fatalf("audit actions = %s", got)
	}
	if _, err := env.pool.Exec(context.Background(), `DELETE FROM jamf_webhook_audit WHERE tenant_id = $1::uuid`, a.tenantID); err == nil {
		t.Fatal("jamf_webhook_audit accepted a DELETE")
	}
}

func TestJamfWebhookForgeryAndExistenceLeak(t *testing.T) {
	a := newApprovalTenant(t, "jamf-forge-a", false)
	b := newApprovalTenant(t, "jamf-forge-b", false)
	ta := createJamfToken(t, a.adminToken)
	tb := createJamfToken(t, b.adminToken)
	urlA, urlB := localURL(t, ta.WebhookURL), localURL(t, tb.WebhookURL)
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02FORGE001", "", 21, "forged"), time.Now())

	const unauthorized = `{"error":"unauthorized"}` + "\n"
	cases := []struct {
		name string
		post jamfPost
	}{
		{"tenant A's valid token on B's endpoint", jamfPost{url: urlB, token: ta.Token, body: ev}},
		{"tenant B's valid token on A's endpoint", jamfPost{url: urlA, token: tb.Token, body: ev}},
		{"wrong token on B's endpoint", jamfPost{url: urlB, token: "pjwh_" + strings.Repeat("A", 43), body: ev}},
		{"no token", jamfPost{url: urlB, body: ev}},
		{"arbitrary hex as the token", jamfPost{url: urlB, token: fmt.Sprintf("%x", []byte("x")), body: ev}},
		{"unknown webhook id, A's token", jamfPost{url: env.publicSrv.URL + "/v1/webhooks/jamf/" + strings.Repeat("Z", 32), token: ta.Token, body: ev}},
		{"malformed webhook id", jamfPost{url: env.publicSrv.URL + "/v1/webhooks/jamf/" + b.tenantID, token: tb.Token, body: ev}},
		{"a valid portal admin identity and no webhook token", jamfPost{url: urlB, body: ev, portalJWT: b.adminToken}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := c.post.do(t)
			if status != http.StatusUnauthorized || body != unauthorized {
				t.Fatalf("status %d body %q, want 401 %q (identical for every auth failure)", status, body, unauthorized)
			}
		})
	}
	if n := jamfDeviceCount(t, b.tenantID); n != 0 {
		t.Fatalf("forged events wrote %d rows for tenant B", n)
	}
	if n := jamfDeviceCount(t, a.tenantID); n != 0 {
		t.Fatalf("forged events wrote %d rows for tenant A", n)
	}
	// Refused authentication is not counted against the tenant either.
	var rejected int
	_ = env.pool.QueryRow(context.Background(), `SELECT events_rejected FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, b.tenantID).Scan(&rejected)
	if rejected != 0 {
		t.Fatalf("unauthenticated requests counted as rejected events: %d", rejected)
	}
	// And B's own token writes only to B.
	if status, body := (jamfPost{url: urlB, token: tb.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("B's own event = %d: %s", status, body)
	}
	if jamfDeviceCount(t, b.tenantID) != 1 || jamfDeviceCount(t, a.tenantID) != 0 {
		t.Fatal("B's event did not land on B alone")
	}
	// Tenant A's coverage never shows B's Mac.
	status, body := jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage?format=csv", a.viewerToken, "")
	if status != http.StatusOK || strings.Contains(body, "C02FORGE001") {
		t.Fatalf("A's coverage shows B's Mac: %d %s", status, body)
	}
}

// TestJamfWebhookDropsPersonalFields plants every personal field Jamf
// documents, through every computer event shape, and asserts none of them
// reaches any stored row or any log line. Verified to fail when the drop is
// removed (see the PAT-2145 report).
func TestJamfWebhookDropsPersonalFields(t *testing.T) {
	logs := captureLogs(t)
	a := newApprovalTenant(t, "jamf-pii", false)
	tok := createJamfToken(t, a.adminToken)
	if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.adminToken, `{"check_in_enabled":true}`); status != http.StatusOK {
		t.Fatalf("enable check-in = %d: %s", status, body)
	}
	url := localURL(t, tok.WebhookURL)
	now := time.Now()
	bodies := []string{
		jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02PII00001", "11111111-2222-3333-4444-555555555555", 31, "pii-mac-1"), now),
		jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer("C02PII00001", "11111111-2222-3333-4444-555555555555", 31, "pii-mac-1"), now),
		jamfBody(t, jamfcoverage.EventComputerCheckIn, map[string]any{
			"computer": jamfComputer("C02PII00002", "", 32, "pii-mac-2"), "trigger": "CHECK_IN", "username": jamfPlantUsername,
		}, now),
		jamfBody(t, jamfcoverage.EventDeviceAddedToDEP, map[string]any{
			"assetTag": "PLANTED-TAG", "description": jamfPlantRealName + "'s Mac", "deviceAssignedDate": now.UnixMilli(),
			"deviceEnrollmentProgramInstanceId": 1, "model": "MacBook Air", "serialNumber": "C02PII00003",
		}, now),
	}
	for i, b := range bodies {
		if status, body := (jamfPost{url: url, token: tok.Token, body: b, instance: "https://acme.jamfcloud.com"}).do(t); status != http.StatusAccepted {
			t.Fatalf("event %d = %d: %s", i, status, body)
		}
	}
	// A refused event (bad type on a kept field) logs no payload either.
	bad := strings.Replace(bodies[0], `"serialNumber":"C02PII00001"`, `"serialNumber":7`, 1)
	if status, _ := (jamfPost{url: url, token: tok.Token, body: bad}).do(t); status != http.StatusBadRequest {
		t.Fatalf("bad event = %d, want 400", status)
	}
	if n := jamfDeviceCount(t, a.tenantID); n != 3 {
		t.Fatalf("jamf devices = %d, want 3", n)
	}

	stored := tenantJamfRowsText(t, a.tenantID)
	logged := logs.String()
	planted := []string{jamfPlantEmail, jamfPlantUsername, jamfPlantIP, jamfPlantRealName, "Plantedfirst",
		"Planted Building", "Planted Department", "Planted Position", "Planted Room", "+44 7700 900214",
		"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "planted-dir-2145", "PLANTED-TAG", "mgmt-2145", "24G84"}
	for _, p := range planted {
		if strings.Contains(stored, p) {
			t.Errorf("planted value %q is stored: %s", p, stored)
		}
		if strings.Contains(logged, p) {
			t.Errorf("planted value %q is logged", p)
		}
	}
	// The identifiers were kept, so the absence above is not an empty table.
	for _, k := range []string{"C02PII00001", "11111111-2222-3333-4444-555555555555", "pii-mac-1", "C02PII00002", "C02PII00003", "MacBook Air", "15.6"} {
		if !strings.Contains(stored, k) {
			t.Errorf("identifier %q was not kept: %s", k, stored)
		}
	}
	if !strings.Contains(logged, `"handler":"jamf_webhook"`) {
		t.Fatal("log capture saw no webhook log lines, so the log assertion proves nothing")
	}
}

func TestJamfWebhookBodyMediaTypeAndSubscription(t *testing.T) {
	a := newApprovalTenant(t, "jamf-limits", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)

	// Body cap.
	huge := map[string]any{"serialNumber": "C02CAP00001", "someFutureField": strings.Repeat("x", 70<<10)}
	if status, body := (jamfPost{url: url, token: tok.Token, body: jamfBody(t, jamfcoverage.EventComputerAdded, huge, time.Now())}).do(t); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d: %s", status, body)
	}
	// XML is refused.
	if status, body := (jamfPost{url: url, token: tok.Token, body: "<xml/>", contentType: "text/xml"}).do(t); status != http.StatusUnsupportedMediaType {
		t.Fatalf("xml = %d: %s", status, body)
	}
	// Unknown event type.
	if status, body := (jamfPost{url: url, token: tok.Token, body: `{"webhook":{"webhookEvent":"MobileDeviceEnrolled"},"event":{}}`}).do(t); status != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported event = %d: %s", status, body)
	}
	// Bad instance header.
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02SUB00001", "", 41, "sub-mac"), time.Now())
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev, instance: "http://insecure.example"}).do(t); status != http.StatusBadRequest {
		t.Fatalf("http instance = %d: %s", status, body)
	}

	// ComputerCheckIn is refused until subscribed.
	checkIn := func(serial string) string {
		return jamfBody(t, jamfcoverage.EventComputerCheckIn, map[string]any{"computer": jamfComputer(serial, "", 42, "ci-mac"), "trigger": "CHECK_IN"}, time.Now())
	}
	status, body := (jamfPost{url: url, token: tok.Token, body: checkIn("C02CHK00001")}).do(t)
	if status != http.StatusUnprocessableEntity || !strings.Contains(body, "event_not_subscribed") {
		t.Fatalf("unsubscribed check-in = %d: %s", status, body)
	}
	if n := jamfDeviceCount(t, a.tenantID); n != 0 {
		t.Fatalf("refused events wrote %d rows", n)
	}
	var rejected int
	var reason string
	if err := env.pool.QueryRow(context.Background(), `SELECT events_rejected, last_rejected_reason FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&rejected, &reason); err != nil {
		t.Fatal(err)
	}
	if rejected != 5 || reason != "event_not_subscribed" {
		t.Fatalf("rejected = %d (%s), want 5 event_not_subscribed", rejected, reason)
	}

	if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.adminToken, `{"check_in_enabled":true}`); status != http.StatusOK || !strings.Contains(body, `"changed":true`) {
		t.Fatalf("enable check-in = %d: %s", status, body)
	}
	// Check-in collapsing: the first check-in writes, the next ones within
	// the hour change nothing.
	if status, body := (jamfPost{url: url, token: tok.Token, body: checkIn("C02CHK00001")}).do(t); status != http.StatusAccepted || !strings.Contains(body, `"accepted"`) {
		t.Fatalf("first check-in = %d: %s", status, body)
	}
	var firstReceived time.Time
	if err := env.pool.QueryRow(context.Background(), `SELECT last_received_at FROM jamf_devices WHERE tenant_id = $1::uuid AND serial_normalized = 'C02CHK00001'`, a.tenantID).Scan(&firstReceived); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if status, body := (jamfPost{url: url, token: tok.Token, body: checkIn("C02CHK00001")}).do(t); status != http.StatusAccepted || !strings.Contains(body, `"collapsed"`) {
			t.Fatalf("repeat check-in %d = %d: %s", i, status, body)
		}
	}
	var after time.Time
	if err := env.pool.QueryRow(context.Background(), `SELECT last_received_at FROM jamf_devices WHERE tenant_id = $1::uuid AND serial_normalized = 'C02CHK00001'`, a.tenantID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(firstReceived) {
		t.Fatalf("a collapsed check-in updated the device: %v -> %v", firstReceived, after)
	}
	// An hour later a check-in writes again.
	if _, err := env.pool.Exec(context.Background(), `UPDATE jamf_devices SET last_received_at = now() - interval '61 minutes' WHERE tenant_id = $1::uuid`, a.tenantID); err != nil {
		t.Fatal(err)
	}
	if status, body := (jamfPost{url: url, token: tok.Token, body: checkIn("C02CHK00001")}).do(t); status != http.StatusAccepted || !strings.Contains(body, `"accepted"`) {
		t.Fatalf("check-in after an hour = %d: %s", status, body)
	}
	// Inventory events are never collapsed.
	inv := jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer("C02CHK00001", "", 42, "ci-mac"), time.Now())
	if status, body := (jamfPost{url: url, token: tok.Token, body: inv}).do(t); status != http.StatusAccepted || !strings.Contains(body, `"accepted"`) {
		t.Fatalf("inventory after check-in = %d: %s", status, body)
	}
}

func jamfLimitsServer(t *testing.T, c handlers.JamfWebhookLimitsConfig) *httptest.Server {
	t.Helper()
	srv, _ := jamfLimitsServerWith(t, c)
	return srv
}

// jamfLimitsServerWith is a fresh process's worth of limits: an empty
// connector cache until RefreshConnectors runs, as at startup.
func jamfLimitsServerWith(t *testing.T, c handlers.JamfWebhookLimitsConfig) (*httptest.Server, *handlers.JamfWebhookLimits) {
	t.Helper()
	limits := handlers.NewJamfWebhookLimits(c)
	r := chi.NewRouter()
	r.Post("/v1/webhooks/jamf/{webhookID}", handlers.JamfWebhookHandler(env.pool, limits))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, limits
}

func (p jamfPost) withIP(ip string) jamfPost { p.clientIP = ip; return p }

func TestJamfWebhookRateLimit(t *testing.T) {
	a := newApprovalTenant(t, "jamf-rate", false)
	tok := createJamfToken(t, a.adminToken)
	webhookID := tok.WebhookURL[strings.LastIndex(tok.WebhookURL, "/")+1:]
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02RATE0001", "", 51, "rate-mac"), time.Now())
	big := handlers.JamfWebhookLimitsConfig{TenantRPM: 1000, TenantBurst: 1000, FailedGlobalRPM: 1000, FailedGlobalBurst: 1000, FailedKeyRPM: 1000, FailedKeyBurst: 1000}

	t.Run("tenant bucket is charged only after authentication", func(t *testing.T) {
		c := big
		c.TenantRPM, c.TenantBurst = 1, 3
		srv := jamfLimitsServer(t, c)
		url := srv.URL + "/v1/webhooks/jamf/" + webhookID
		// A sender holding the leaked ID but not the token cannot spend it.
		for i := 0; i < 20; i++ {
			if status, _ := (jamfPost{url: url, token: "pjwh_wrong", body: ev}).do(t); status != http.StatusUnauthorized {
				t.Fatalf("failed auth %d = %d, want 401", i, status)
			}
		}
		for i := 0; i < 3; i++ {
			if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
				t.Fatalf("event %d after failed auths = %d: %s", i, status, body)
			}
		}
		if status, _ := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusTooManyRequests {
			t.Fatalf("4th authenticated event = %d, want 429", status)
		}
	})

	t.Run("failed auth never blocks a working tenant", func(t *testing.T) {
		c := big
		c.FailedKeyRPM, c.FailedKeyBurst, c.FailedGlobalRPM, c.FailedGlobalBurst = 1, 2, 1, 5
		srv := jamfLimitsServer(t, c)
		url := srv.URL + "/v1/webhooks/jamf/" + webhookID
		// The tenant authenticates once, so its ID is known.
		if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
			t.Fatalf("first event = %d: %s", status, body)
		}
		// Random IDs from many addresses exhaust the global failure bucket.
		for i := 0; i < 10; i++ {
			(jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_x", body: ev}).withIP(fmt.Sprintf("203.0.113.%d", i)).do(t)
		}
		// A new random ID is now refused before the database is read.
		status, body := (jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_x", body: ev}).withIP("198.51.100.1").do(t)
		if status != http.StatusTooManyRequests || !strings.Contains(body, "rate_limited") {
			t.Fatalf("random ID during an attack = %d %s, want 429", status, body)
		}
		// The working tenant, from the same shared egress, still gets through.
		if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).withIP("203.0.113.1").do(t); status != http.StatusAccepted {
			t.Fatalf("known tenant during an attack = %d: %s", status, body)
		}
	})

	t.Run("per-IP failure bucket gates unknown IDs from that IP only", func(t *testing.T) {
		c := big
		c.FailedKeyRPM, c.FailedKeyBurst = 1, 2
		srv := jamfLimitsServer(t, c)
		unknown := func(ip string) int {
			status, _ := (jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_x", body: ev}).withIP(ip).do(t)
			return status
		}
		unknown("192.0.2.10")
		unknown("192.0.2.10")
		if got := unknown("192.0.2.10"); got != http.StatusTooManyRequests {
			t.Fatalf("third failure from one IP = %d, want 429", got)
		}
		if got := unknown("192.0.2.11"); got != http.StatusUnauthorized {
			t.Fatalf("another IP = %d, want 401", got)
		}
	})

	t.Run("after a restart, spam cannot lock out a recently active tenant", func(t *testing.T) {
		c := big
		c.FailedGlobalRPM, c.FailedGlobalBurst = 1, 5
		srv, limits := jamfLimitsServerWith(t, c)
		// Startup: the cache is seeded from the database before serving.
		if err := limits.RefreshConnectors(context.Background(), env.pool); err != nil {
			t.Fatal(err)
		}
		// Malformed IDs and missing tokens cost no database read and
		// charge nothing shared, however many there are.
		for i := 0; i < 200; i++ {
			(jamfPost{url: srv.URL + "/v1/webhooks/jamf/not-an-id-" + randomHex(2), token: "pjwh_x", body: ev}).do(t)
			(jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + webhookID, body: ev}).do(t)
		}
		if limits.FailedGlobal.Blocked("global") {
			t.Fatal("malformed and no-token spam drained the global failure bucket")
		}
		// Failures that do cost a read drain it.
		for i := 0; i < 10; i++ {
			(jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_x", body: ev}).do(t)
		}
		if !limits.FailedGlobal.Blocked("global") {
			t.Fatal("unknown-ID failures did not drain the global bucket")
		}
		// The tenant, never seen by this process, still gets through.
		if status, body := (jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + webhookID, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
			t.Fatalf("seeded tenant during a flood after restart = %d: %s", status, body)
		}
		// And while drained, a failed auth on a real ID answers 429 like an
		// unknown ID does, so the status reveals nothing about liveness.
		for i := 0; i < 4; i++ {
			if status, _ := (jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + webhookID, token: "pjwh_wrong", body: ev}).do(t); status != http.StatusTooManyRequests {
				t.Fatalf("known ID, wrong token, while drained (%d) = %d, want 429", i, status)
			}
			if status, _ := (jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_wrong", body: ev}).do(t); status != http.StatusTooManyRequests {
				t.Fatalf("unknown ID while drained (%d) = %d, want 429", i, status)
			}
		}
	})

	t.Run("per-ID failure bucket gates wrong tokens before the read, never the right token", func(t *testing.T) {
		c := big
		c.FailedKeyRPM, c.FailedKeyBurst, c.ProbeRPM, c.ProbeBurst = 1, 2, 1, 1
		srv, limits := jamfLimitsServerWith(t, c)
		if err := limits.RefreshConnectors(context.Background(), env.pool); err != nil {
			t.Fatal(err)
		}
		url := srv.URL + "/v1/webhooks/jamf/" + webhookID
		want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusTooManyRequests}
		for i, w := range want {
			// Two failures fill the ID bucket, one probe still reaches the
			// read, then the ID is refused before it.
			if status, _ := (jamfPost{url: url, token: "pjwh_wrong", body: ev}).do(t); status != w {
				t.Fatalf("wrong token %d = %d, want %d", i, status, w)
			}
		}
		if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
			t.Fatalf("right token while the ID is flooded = %d: %s", status, body)
		}
	})

	t.Run("failure log lines are rate limited and count what they suppress", func(t *testing.T) {
		logs := captureLogs(t)
		c := big
		c.FailedGlobalRPM, c.FailedGlobalBurst = 1, 3
		srv := jamfLimitsServer(t, c)
		url := srv.URL + "/v1/webhooks/jamf/" + webhookID
		for i := 0; i < 30; i++ {
			(jamfPost{url: url, token: "pjwh_wrong", body: ev}).do(t)
		}
		if n := strings.Count(logs.String(), "jamf webhook auth failed"); n != 3 {
			t.Fatalf("auth failure log lines = %d for 30 failures, want 3 (the bucket's burst)", n)
		}
	})
}

type jamfCoverageResp struct {
	Connector struct {
		Status       string `json:"status"`
		Amber        bool   `json:"amber"`
		JamfInstance struct {
			URL      *string `json:"url"`
			Mismatch bool    `json:"mismatch"`
		} `json:"jamf_instance"`
	} `json:"connector"`
	Basis struct {
		Since     *time.Time `json:"since"`
		Statement string     `json:"statement"`
	} `json:"basis"`
	Counts struct {
		Gap                int            `json:"gap"`
		GapDEPAssignedOnly int            `json:"gap_dep_assigned_only"`
		GapSilent          int            `json:"gap_silent"`
		NotReported        int            `json:"not_reported_by_jamf"`
		NotReportedByState map[string]int `json:"not_reported_by_jamf_by_mdm_state"`
		AgentReportsNoMDM  int            `json:"agent_reports_no_mdm"`
		LegacyUnmanaged    *int           `json:"unmanaged"`
		Covered            int            `json:"covered"`
		RetiredExcluded    int            `json:"retired_excluded"`
		NonMac             int            `json:"non_mac_devices_excluded"`
	} `json:"counts"`
	Gap *struct {
		Total int `json:"total"`
		Rows  []struct {
			Serial     *string `json:"serial"`
			JamfState  string  `json:"jamf_state"`
			DaysSince  int     `json:"days_since_jamf_event"`
			Note       string  `json:"note"`
			DeviceName *string `json:"device_name"`
		} `json:"rows"`
	} `json:"gap"`
	NotReported *struct {
		Total int `json:"total"`
		Rows  []struct {
			DeviceID  string  `json:"device_id"`
			MDMState  string  `json:"mdm_state"`
			MDMVendor *string `json:"mdm_vendor"`
			Note      string  `json:"note"`
		} `json:"rows"`
	} `json:"not_reported_by_jamf"`
	Covered *struct {
		Total int `json:"total"`
		Rows  []struct {
			DeviceID   string `json:"device_id"`
			MatchBasis string `json:"match_basis"`
		} `json:"rows"`
	} `json:"covered"`
}

func seedAppliedConfig(t *testing.T, tenantID, deviceID string, serverURL *string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO applied_config_snapshots (tenant_id, device_id, raw_payload_id, raw_payload_received_at, observed_at,
		                                      collection_status, mdm_server_url)
		VALUES ($1::uuid, $2::uuid, (random() * 1e9)::bigint, now(), now(), 'ok', $3)
	`, tenantID, deviceID, serverURL); err != nil {
		t.Fatalf("seed applied config: %v", err)
	}
}

func seedSignal(t *testing.T, deviceID, key, value string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, $2, $3)
	`, deviceID, key, value); err != nil {
		t.Fatalf("seed signal: %v", err)
	}
}

// The fixture the ticket names: a DEP-only Mac, a Mac enrolled in another
// MDM, an unmanaged Mac, a silent Mac and a retired Mac.
func TestJamfCoverageBuckets(t *testing.T) {
	a := newApprovalTenant(t, "jamf-buckets", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)
	now := time.Now().UTC()
	send := func(body string) {
		t.Helper()
		if status, resp := (jamfPost{url: url, token: tok.Token, body: body, instance: "https://acme.jamfcloud.com"}).do(t); status != http.StatusAccepted {
			t.Fatalf("event = %d: %s", status, resp)
		}
	}

	// Patched side.
	other := seedSelfServiceDevice(t, a.tenantID, "mac-other", "C02OTHER001", "macOS", now)
	intune := "https://i.manage.microsoft.com/DeviceGatewayProxy/ios.ashx"
	seedAppliedConfig(t, a.tenantID, other, &intune)
	unmanaged := seedSelfServiceDevice(t, a.tenantID, "mac-unmanaged", "C02UNMAN001", "macOS", now)
	seedAppliedConfig(t, a.tenantID, unmanaged, nil)
	signalNo := seedSelfServiceDevice(t, a.tenantID, "mac-signal-no", "C02SIGNO001", "macOS", now)
	seedSignal(t, signalNo, "mdm_enrolled", "No")
	unknown := seedSelfServiceDevice(t, a.tenantID, "mac-unknown", "C02UNKN0001", "macOS", now)
	jamfNoEvent := seedSelfServiceDevice(t, a.tenantID, "mac-jamf-quiet", "C02JQUIET01", "macOS", now)
	jamfURL := "https://acme.jamfcloud.com/mdm/ServerURL"
	seedAppliedConfig(t, a.tenantID, jamfNoEvent, &jamfURL)
	both := seedSelfServiceDevice(t, a.tenantID, "mac-both", "C02BOTH0001", "macOS", now)
	udidMac := seedSelfServiceDevice(t, a.tenantID, "mac-udid", "", "macOS", now)
	if _, err := env.pool.Exec(context.Background(), `UPDATE devices SET hw_uuid = '6c1f2e3d-4b5a-4968-8776-a5b4c3d2e1f0' WHERE id = $1::uuid`, udidMac); err != nil {
		t.Fatal(err)
	}
	retired := seedSelfServiceDevice(t, a.tenantID, "mac-retired", "C02RETIRE01", "macOS", now.Add(-60*24*time.Hour))
	retiredAlone := seedSelfServiceDevice(t, a.tenantID, "mac-retired-alone", "C02RETIRE02", "macOS", now.Add(-60*24*time.Hour))
	for _, d := range []string{retired, retiredAlone} {
		if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/devices/"+d+"/retirement", a.adminToken, `{"retired":true}`); status != http.StatusOK {
			t.Fatalf("retire = %d: %s", status, body)
		}
	}
	seedSelfServiceDevice(t, a.tenantID, "PC-WIN-01", "WINSERIAL01", "Windows", now)

	// Jamf side.
	send(jamfBody(t, jamfcoverage.EventDeviceAddedToDEP, map[string]any{"serialNumber": "C02DEPONLY1", "model": "MacBook Air"}, now))
	send(jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02SILENT01", "", 61, "a-silent-mac"), now.Add(-45*24*time.Hour)))
	send(jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02RETIRE01", "", 62, "retired-mac"), now))
	send(jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer("C02BOTH0001", "", 63, "both-mac"), now))
	send(jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("0", "6C1F2E3D-4B5A-4968-8776-A5B4C3D2E1F0", 64, "udid-mac"), now))

	status, body := jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage", a.viewerToken, "")
	if status != http.StatusOK {
		t.Fatalf("coverage = %d: %s", status, body)
	}
	var cov jamfCoverageResp
	mustJSON(t, []byte(body), &cov)

	if cov.Connector.Status != "ok" || cov.Connector.Amber || cov.Connector.JamfInstance.URL == nil ||
		*cov.Connector.JamfInstance.URL != "https://acme.jamfcloud.com" {
		t.Errorf("connector = %+v", cov.Connector)
	}
	if cov.Basis.Since == nil || !strings.HasPrefix(cov.Basis.Statement, "From Jamf webhooks since ") {
		t.Errorf("basis = %+v", cov.Basis)
	}

	// Bucket 1: DEP-only and silent Macs; the retired Mac is excluded.
	gap := map[string]string{}
	for _, r := range cov.Gap.Rows {
		gap[*r.Serial] = r.JamfState + "|" + r.Note
	}
	if len(gap) != 2 || !strings.HasPrefix(gap["C02DEPONLY1"], "dep_assigned_only|assigned to Jamf in Apple Business Manager") ||
		gap["C02SILENT01"] != "enrolled|not heard from Jamf in 45 days" {
		t.Errorf("gap = %v", gap)
	}
	for _, r := range cov.Gap.Rows {
		if strings.Contains(r.Note, "removed") || strings.Contains(r.Note, "unmanaged") {
			t.Errorf("a silent Mac reads as removed or unmanaged: %q", r.Note)
		}
	}
	if cov.Counts.Gap != 2 || cov.Counts.GapDEPAssignedOnly != 1 || cov.Counts.GapSilent != 1 || cov.Counts.RetiredExcluded != 1 {
		t.Errorf("gap counts = %+v", cov.Counts)
	}

	// Bucket 2: classified from the agent's own evidence; retired and
	// Windows devices left out.
	un := map[string]string{}
	for _, r := range cov.NotReported.Rows {
		v := ""
		if r.MDMVendor != nil {
			v = *r.MDMVendor
		}
		un[r.DeviceID] = r.MDMState + ":" + v
	}
	wantUn := map[string]string{
		other: "other_mdm:Microsoft Intune", unmanaged: "unmanaged:", signalNo: "unmanaged:",
		unknown: "unknown:", jamfNoEvent: "jamf_no_event_yet:Jamf",
	}
	if len(un) != len(wantUn) {
		t.Errorf("unmanaged = %v, want %v", un, wantUn)
	}
	for id, want := range wantUn {
		if un[id] != want {
			t.Errorf("unmanaged[%s] = %q, want %q", id, un[id], want)
		}
	}
	// Only the agent's own "no MDM" evidence is called unmanaged; the
	// bucket as a whole is "not reported by Jamf".
	if cov.Counts.NonMac != 1 || cov.Counts.NotReported != 5 || cov.Counts.AgentReportsNoMDM != 2 ||
		cov.Counts.NotReportedByState["unmanaged"] != 2 || cov.Counts.NotReportedByState["other_mdm"] != 1 ||
		cov.Counts.LegacyUnmanaged != nil {
		t.Errorf("not reported counts = %+v", cov.Counts)
	}

	// Bucket 3: serial match and UDID fallback.
	covd := map[string]string{}
	for _, r := range cov.Covered.Rows {
		covd[r.DeviceID] = r.MatchBasis
	}
	if len(covd) != 2 || covd[both] != "serial" || covd[udidMac] != "udid" {
		t.Errorf("covered = %v", covd)
	}

	// Paging and the single-bucket view.
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage?bucket=not_reported_by_jamf&limit=2&offset=1", a.viewerToken, "")
	if status != http.StatusOK {
		t.Fatalf("paged = %d: %s", status, body)
	}
	var paged jamfCoverageResp
	mustJSON(t, []byte(body), &paged)
	if paged.Gap != nil || paged.Covered != nil || paged.NotReported == nil || paged.NotReported.Total != 5 || len(paged.NotReported.Rows) != 2 {
		t.Errorf("paged bucket = %s", body)
	}
	for _, bad := range []string{"?bucket=all", "?bucket=unmanaged", "?limit=0", "?nope=1", "?format=xml"} {
		if status, _ := jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage"+bad, a.viewerToken, ""); status != http.StatusBadRequest {
			t.Errorf("coverage%s = %d, want 400", bad, status)
		}
	}

	// CSV: every row of every bucket, with the basis on each row.
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage?format=csv", a.viewerToken, "")
	if status != http.StatusOK {
		t.Fatalf("csv = %d: %s", status, body)
	}
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(recs) != 1+2+5+2 || recs[0][0] != "bucket" {
		t.Fatalf("csv rows = %d: %s", len(recs), body)
	}
	for _, rec := range recs[1:] {
		if !strings.HasPrefix(rec[19], "From Jamf webhooks since ") {
			t.Fatalf("csv row without basis: %v", rec)
		}
	}

	// A later event claiming another Jamf instance is flagged.
	if status, resp := (jamfPost{url: url, token: tok.Token, instance: "https://evil.jamfcloud.com",
		body: jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer("C02BOTH0001", "", 63, "both-mac"), now)}).do(t); status != http.StatusAccepted {
		t.Fatalf("mismatch event = %d: %s", status, resp)
	}
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage?bucket=gap", a.viewerToken, "")
	mustJSON(t, []byte(body), &cov)
	if !cov.Connector.JamfInstance.Mismatch || !cov.Connector.Amber {
		t.Errorf("instance mismatch not flagged: %s", body)
	}

	// No event for over 24 hours turns the connector amber.
	if _, err := env.pool.Exec(context.Background(), `UPDATE jamf_webhook_connectors SET last_event_at = now() - interval '25 hours', jamf_instance_last_claimed = jamf_instance_url WHERE tenant_id = $1::uuid`, a.tenantID); err != nil {
		t.Fatal(err)
	}
	status, body = jamfPortal(t, http.MethodGet, "/v1/portal/mdm/jamf/coverage?bucket=gap", a.viewerToken, "")
	mustJSON(t, []byte(body), &cov)
	if cov.Connector.Status != "amber" || !cov.Connector.Amber {
		t.Errorf("stale connector = %s", body)
	}
}

// P2: a revoked tenant authenticates nothing, even with its current token.
// A token rotated while its ID is flooded gets through at once (the
// rotation updates the cache), and the old token is gated again.
func TestJamfWebhookRotationDuringFlood(t *testing.T) {
	a := newApprovalTenant(t, "jamf-rotate-flood", false)
	tok := createJamfToken(t, a.adminToken)
	webhookID := tok.WebhookURL[strings.LastIndex(tok.WebhookURL, "/")+1:]
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02ROTFLD01", "", 0, "rot-mac"), time.Now())
	srv, limits := jamfLimitsServerWith(t, handlers.JamfWebhookLimitsConfig{TenantRPM: 1000, TenantBurst: 1000,
		FailedGlobalRPM: 1000, FailedGlobalBurst: 1000, FailedKeyRPM: 1, FailedKeyBurst: 2, ProbeRPM: 1, ProbeBurst: 1})
	if err := limits.RefreshConnectors(context.Background(), env.pool); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/v1/webhooks/jamf/" + webhookID
	for i := 0; i < 4; i++ {
		(jamfPost{url: url, token: "pjwh_wrong", body: ev}).do(t)
	}
	// Rotating in this process updates the cache at once, so the new token
	// gets through even with the probe spent and no refresh yet.
	rot := createJamfToken(t, a.adminToken)
	if status, body := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("new token straight after rotation = %d: %s", status, body)
	}
	if err := limits.RefreshConnectors(context.Background(), env.pool); err != nil {
		t.Fatal(err)
	}
	if status, body := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("new token after refresh = %d: %s", status, body)
	}
	// The old token no longer matches the cache, so it is gated again.
	if status, _ := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusTooManyRequests {
		t.Fatalf("old token while the ID is flooded = %d, want 429", status)
	}
}

func TestJamfWebhookRevokedTenant(t *testing.T) {
	a := newApprovalTenant(t, "jamf-revoked-tenant", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02REVTEN01", "", 71, "rev-mac"), time.Now())
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("before tenant revoke = %d: %s", status, body)
	}
	if _, err := env.pool.Exec(context.Background(), `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, a.tenantID); err != nil {
		t.Fatal(err)
	}
	ev2 := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02REVTEN02", "", 72, "rev-mac-2"), time.Now())
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev2}).do(t); status != http.StatusUnauthorized || body != `{"error":"unauthorized"}`+"\n" {
		t.Fatalf("revoked tenant = %d %q, want the plain 401", status, body)
	}
	if n := jamfDeviceCount(t, a.tenantID); n != 1 {
		t.Fatalf("revoked tenant wrote: %d rows", n)
	}
}

// P2: Jamf moves a UDID and Jamf ID to a Mac with a different serial (a
// logic board swap, a re-used record). This used to hit a unique index and
// answer 500 on every retry; the identifiers now move to the new row.
func TestJamfWebhookIdentifierMovesInsteadOf500(t *testing.T) {
	a := newApprovalTenant(t, "jamf-conflict", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)
	const udid = "0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"
	for i, serial := range []string{"C02OLDBOARD", "C02NEWBOARD"} {
		ev := jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer(serial, udid, 81, "swap-mac"), time.Now())
		if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
			t.Fatalf("event %d (%s) = %d: %s", i, serial, status, body)
		}
	}
	rows, err := env.pool.Query(context.Background(), `
		SELECT serial_normalized, COALESCE(udid_normalized, ''), COALESCE(jamf_id, 0)
		FROM jamf_devices WHERE tenant_id = $1::uuid ORDER BY id`, a.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var s, u string
		var j int64
		if err := rows.Scan(&s, &u, &j); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s|%s|%d", s, u, j))
	}
	rows.Close()
	want := []string{"C02OLDBOARD||0", "C02NEWBOARD|" + udid + "|81"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rows = %v, want %v", got, want)
	}
}

// P2: a tenant's Jamf rows are bounded; a new Mac beyond the cap is refused
// and recorded, never silently dropped, while known Macs still update.
func TestJamfWebhookDeviceCap(t *testing.T) {
	a := newApprovalTenant(t, "jamf-cap", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)
	ev := func(serial string) string {
		return jamfBody(t, jamfcoverage.EventComputerInventoryCompleted, jamfComputer(serial, "", 0, "cap-mac"), time.Now())
	}
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev("C02CAPKNOWN")}).do(t); status != http.StatusAccepted {
		t.Fatalf("known Mac = %d: %s", status, body)
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO jamf_devices (tenant_id, serial, serial_normalized, first_token_generation, last_token_generation,
		                          first_event_type, last_event_type, enrolled)
		SELECT $1::uuid, 'CAPFILL' || g, 'CAPFILL' || g, 1, 1, 'ComputerAdded', 'ComputerAdded', true
		FROM generate_series(1, 49999) g`, a.tenantID); err != nil {
		t.Fatal(err)
	}
	status, body := (jamfPost{url: url, token: tok.Token, body: ev("C02CAPNEW01")}).do(t)
	if status != http.StatusUnprocessableEntity || !strings.Contains(body, "device_cap_reached") {
		t.Fatalf("new Mac over the cap = %d: %s", status, body)
	}
	var reason string
	if err := env.pool.QueryRow(context.Background(), `SELECT last_rejected_reason FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&reason); err != nil || reason != "device_cap_reached" {
		t.Fatalf("rejection not recorded: %q %v", reason, err)
	}
	if n := jamfDeviceCount(t, a.tenantID); n != 50000 {
		t.Fatalf("rows = %d, want 50000", n)
	}
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev("C02CAPKNOWN")}).do(t); status != http.StatusAccepted {
		t.Fatalf("known Mac at the cap = %d: %s", status, body)
	}
	// The admin purge empties it, audited with the count.
	if status, body := jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/devices", a.adminToken, ""); status != http.StatusOK || !strings.Contains(body, `"devices_deleted":50000`) {
		t.Fatalf("purge = %d: %s", status, body)
	}
}

// P2: revoking a token deletes the Macs first recorded under it (what a
// leaked token could have fabricated) and keeps earlier ones; the admin
// purge deletes the rest. Both audited with counts; viewers cannot purge.
func TestJamfRevokeAndPurgeDeleteDevices(t *testing.T) {
	a := newApprovalTenant(t, "jamf-purge", false)
	send := func(url, token, serial string) {
		t.Helper()
		ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer(serial, "", 0, "purge-mac"), time.Now())
		if status, body := (jamfPost{url: url, token: token, body: ev}).do(t); status != http.StatusAccepted {
			t.Fatalf("event %s = %d: %s", serial, status, body)
		}
	}
	first := createJamfToken(t, a.adminToken)
	url := localURL(t, first.WebhookURL)
	send(url, first.Token, "C02GENONE01")
	second := createJamfToken(t, a.adminToken)
	send(url, second.Token, "C02GENTWO01")
	send(url, second.Token, "C02GENONE01") // an earlier Mac updated under the new token is kept

	if status, body := jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/devices", a.viewerToken, ""); status != http.StatusForbidden {
		t.Fatalf("viewer purge = %d: %s", status, body)
	}
	status, body := jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/token", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"devices_deleted":1`) ||
		!strings.Contains(body, "deleted the 1 Jamf device records first seen under this token") || !strings.Contains(body, "refills") {
		t.Fatalf("revoke = %d: %s", status, body)
	}
	var serials []string
	rows, _ := env.pool.Query(context.Background(), `SELECT serial_normalized FROM jamf_devices WHERE tenant_id = $1::uuid`, a.tenantID)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		serials = append(serials, s)
	}
	rows.Close()
	if strings.Join(serials, ",") != "C02GENONE01" {
		t.Fatalf("after revoke rows = %v, want only the Mac first seen under the earlier token", serials)
	}
	status, body = jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/devices", a.adminToken, "")
	if status != http.StatusOK || !strings.Contains(body, `"devices_deleted":1`) || jamfDeviceCount(t, a.tenantID) != 0 {
		t.Fatalf("purge = %d: %s", status, body)
	}
	var audit []string
	rows, _ = env.pool.Query(context.Background(), `SELECT action || ':' || COALESCE(affected_rows::text, '-') FROM jamf_webhook_audit WHERE tenant_id = $1::uuid ORDER BY id`, a.tenantID)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		audit = append(audit, s)
	}
	rows.Close()
	if got := strings.Join(audit, ","); got != "token_created:-,token_rotated:-,token_revoked:1,devices_purged:1" {
		t.Fatalf("audit = %s", got)
	}
}

// P3: rotating the token forgets the pinned Jamf instance, and an admin can
// reset it without rotating.
func TestJamfInstanceClearedOnRotateAndReset(t *testing.T) {
	a := newApprovalTenant(t, "jamf-instance", false)
	tok := createJamfToken(t, a.adminToken)
	url := localURL(t, tok.WebhookURL)
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02INSTNC01", "", 0, "inst-mac"), time.Now())
	pinned := func() string {
		var u *string
		_ = env.pool.QueryRow(context.Background(), `SELECT jamf_instance_url FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&u)
		if u == nil {
			return ""
		}
		return *u
	}
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev, instance: "https://old.jamfcloud.com"}).do(t); status != http.StatusAccepted {
		t.Fatalf("event = %d: %s", status, body)
	}
	if pinned() != "https://old.jamfcloud.com" {
		t.Fatalf("pinned = %q", pinned())
	}
	rot := createJamfToken(t, a.adminToken)
	if pinned() != "" {
		t.Fatalf("rotation kept the pinned instance %q", pinned())
	}
	if status, body := (jamfPost{url: url, token: rot.Token, body: ev, instance: "https://new.jamfcloud.com"}).do(t); status != http.StatusAccepted {
		t.Fatalf("event = %d: %s", status, body)
	}
	if pinned() != "https://new.jamfcloud.com" {
		t.Fatalf("re-pinned = %q", pinned())
	}
	if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.viewerToken, `{"reset_jamf_instance":true}`); status != http.StatusForbidden {
		t.Fatalf("viewer reset = %d: %s", status, body)
	}
	if status, body := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.adminToken, `{"reset_jamf_instance":true}`); status != http.StatusOK || !strings.Contains(body, `"changed":true`) {
		t.Fatalf("reset = %d: %s", status, body)
	}
	if pinned() != "" {
		t.Fatalf("reset kept %q", pinned())
	}
	if status, _ := jamfPortal(t, http.MethodPut, "/v1/portal/mdm/jamf/setup", a.adminToken, `{"reset_jamf_instance":false}`); status != http.StatusBadRequest {
		t.Fatalf("reset false = %d, want 400", status)
	}
}

// A connector created or rotated in this process is in the cache at once,
// so it is not treated as unknown while the global failure bucket is
// drained; a revoked one leaves it at once.
func TestJamfTokenWritesUpdateCacheImmediately(t *testing.T) {
	a := newApprovalTenant(t, "jamf-cache-now", false)
	srv, limits := jamfLimitsServerWith(t, handlers.JamfWebhookLimitsConfig{TenantRPM: 1000, TenantBurst: 1000,
		FailedGlobalRPM: 1, FailedGlobalBurst: 3, FailedKeyRPM: 1000, FailedKeyBurst: 1000})
	ev := jamfBody(t, jamfcoverage.EventComputerAdded, jamfComputer("C02CACHENOW", "", 0, "cache-mac"), time.Now())
	for i := 0; i < 6; i++ {
		(jamfPost{url: srv.URL + "/v1/webhooks/jamf/" + randomHex(16), token: "pjwh_x", body: ev}).do(t)
	}
	if !limits.FailedGlobal.Blocked("global") {
		t.Fatal("global failure bucket not drained")
	}
	// No refresh has run since the token was created.
	tok := createJamfToken(t, a.adminToken)
	url := srv.URL + "/v1/webhooks/jamf/" + tok.WebhookURL[strings.LastIndex(tok.WebhookURL, "/")+1:]
	if status, body := (jamfPost{url: url, token: tok.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("brand-new connector while drained = %d: %s", status, body)
	}
	rot := createJamfToken(t, a.adminToken)
	if status, body := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusAccepted {
		t.Fatalf("just-rotated token while drained = %d: %s", status, body)
	}
	if status, body := jamfPortal(t, http.MethodDelete, "/v1/portal/mdm/jamf/token", a.adminToken, ""); status != http.StatusOK {
		t.Fatalf("revoke = %d: %s", status, body)
	}
	// Gone from the cache: the revoked token is gated like any unknown
	// credential, without a database read.
	if status, _ := (jamfPost{url: url, token: rot.Token, body: ev}).do(t); status != http.StatusTooManyRequests {
		t.Fatalf("revoked token while drained = %d, want 429", status)
	}
}
