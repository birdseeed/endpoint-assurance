package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
)

// -- shared test constants and helpers ----------------------------------------

const (
	eaTestTenantID = "c3b2a1d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6"
	eaTestDeviceID = "d4c3b2a1-f5e6-7a8b-9c0d-e1f2a3b4c5d6"
)

func eaOKAuthFn(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
	return eaTestTenantID, eaTestDeviceID, nil
}

// eaNoopIngestFn records how many events were passed; returns n, nil.
func eaCountingIngestFn(count *int) enforcementAuditIngestFn {
	return func(_ context.Context, _, _ string, events []enforcementAuditEvent) (int, error) {
		*count = len(events)
		return len(events), nil
	}
}

func eaPostJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/inventory/enforcement-audit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// -- POST /v1/inventory/enforcement-audit tests --------------------------------

func TestEnforcementAuditIngestUnknownEventType(t *testing.T) {
	called := false
	ingestFn := func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) {
		called = true
		return 0, nil
	}
	h := newEnforcementAuditIngestHandler(eaOKAuthFn, ingestFn, nil, 0, nil)
	w := eaPostJSON(h, `{"events":[{"event_type":"unknown_type","subject":"bob","occurred_at":"2026-12-25T10:00:00Z"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown event_type, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("ingestFn must not be called for invalid event_type")
	}
}

func TestEnforcementAuditIngestEmptySubject(t *testing.T) {
	called := false
	ingestFn := func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) {
		called = true
		return 0, nil
	}
	h := newEnforcementAuditIngestHandler(eaOKAuthFn, ingestFn, nil, 0, nil)
	w := eaPostJSON(h, `{"events":[{"event_type":"admin_removed","subject":"","occurred_at":"2026-12-25T10:00:00Z"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty subject, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("ingestFn must not be called for empty subject")
	}
}

func TestEnforcementAuditIngestEmptyEvents(t *testing.T) {
	called := false
	ingestFn := func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) {
		called = true
		return 0, nil
	}
	h := newEnforcementAuditIngestHandler(eaOKAuthFn, ingestFn, nil, 0, nil)
	w := eaPostJSON(h, `{"events":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for empty events array, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("ingestFn must not be called for empty events array")
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["ingested"].(float64) != 0 {
		t.Errorf("want ingested=0, got %v", resp["ingested"])
	}
}

func TestEnforcementAuditIngestOK(t *testing.T) {
	var count int
	h := newEnforcementAuditIngestHandler(eaOKAuthFn, eaCountingIngestFn(&count), nil, 0, nil)
	body := `{"events":[
		{"event_type":"admin_removed","subject":"baduser","occurred_at":"2026-12-25T10:00:00Z","details":{"method":"dscl"}},
		{"event_type":"app_blocked","subject":"com.evil.app","occurred_at":"2026-12-25T10:01:00Z"}
	]}`
	w := eaPostJSON(h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if count != 2 {
		t.Errorf("want 2 events passed to ingestFn, got %d", count)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["ingested"].(float64) != 2 {
		t.Errorf("want ingested=2, got %v", resp["ingested"])
	}
}

func TestEnforcementAuditIngestInvalidOccurredAt(t *testing.T) {
	h := newEnforcementAuditIngestHandler(eaOKAuthFn,
		func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) { return 0, nil },
		nil, 0, nil)
	w := eaPostJSON(h, `{"events":[{"event_type":"admin_removed","subject":"bob","occurred_at":"not-a-time"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid occurred_at, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnforcementAuditIngestMissingEventsField(t *testing.T) {
	h := newEnforcementAuditIngestHandler(eaOKAuthFn,
		func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) { return 0, nil },
		nil, 0, nil)
	w := eaPostJSON(h, `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when events field is missing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnforcementAuditIngestAllEventTypes(t *testing.T) {
	validTypes := []string{"admin_removed", "admin_removal_skipped", "app_blocked", "app_block_skipped", "extension_blocklist_pushed", "extension_removed"}
	for _, et := range validTypes {
		t.Run(et, func(t *testing.T) {
			h := newEnforcementAuditIngestHandler(eaOKAuthFn,
				func(_ context.Context, _, _ string, evs []enforcementAuditEvent) (int, error) { return len(evs), nil },
				nil, 0, nil)
			body := `{"events":[{"event_type":"` + et + `","subject":"target","occurred_at":"2026-12-25T10:00:00Z"}]}`
			w := eaPostJSON(h, body)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200 for event_type %q, got %d: %s", et, w.Code, w.Body.String())
			}
		})
	}
}

func TestParseExtensionRemovalEvidence(t *testing.T) {
	tests := []struct {
		name    string
		event   enforcementAuditEvent
		wantOK  bool
		browser string
	}{
		{
			name: "real removal is completion evidence",
			event: enforcementAuditEvent{
				EventType: "extension_removed",
				Details:   json.RawMessage(`{"approved_before":"2026-12-25T10:00:00.123Z","browser":" Chrome ","profile":"Default","user_account":"alice","scope":"one_observation","dry_run":false}`),
			},
			wantOK: true, browser: "chrome",
		},
		{
			name: "dry run never completes a job",
			event: enforcementAuditEvent{
				EventType: "extension_removed",
				Details:   json.RawMessage(`{"approved_before":"2026-12-25T10:00:00.123Z","browser":"chrome","profile":"Default","user_account":"alice","scope":"one_observation","dry_run":true}`),
			},
		},
		{
			name: "missing profile is audit only",
			event: enforcementAuditEvent{
				EventType: "extension_removed",
				Details:   json.RawMessage(`{"browser":"chrome","user_account":"alice","scope":"one_profile"}`),
			},
		},
		{
			name: "blocklist event is not removal evidence",
			event: enforcementAuditEvent{
				EventType: "extension_blocklist_pushed",
				Details:   json.RawMessage(`{"browser":"chrome","profile":"Default","user_account":"alice","scope":"one_profile"}`),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseExtensionRemovalEvidence(tc.event)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tc.wantOK)
			}
			if got.Browser != tc.browser {
				t.Fatalf("browser=%q, want %q", got.Browser, tc.browser)
			}
		})
	}
}

// -- GET /admin/tenants/{tenantID}/enforcement-audit tests --------------------

func TestEnforcementAuditGetInvalidUUID(t *testing.T) {
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/enforcement-audit", nil)
	req = acWithTenantID(req, "not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid tenantID, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnforcementAuditGetOK(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	entry := enforcementAuditEntry{
		ID:         "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		DeviceID:   eaTestDeviceID,
		Hostname:   "macbook-pro",
		EventType:  "admin_removed",
		Subject:    "baduser",
		Details:    json.RawMessage(`{}`),
		OccurredAt: now,
		IngestedAt: now,
	}
	listFn := func(_ context.Context, tenantID string, limit int, before *time.Time, deviceFilter, deviceSearch string, eventTypes []string) ([]enforcementAuditEntry, error) {
		return []enforcementAuditEntry{entry}, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	events, ok := resp["events"].([]any)
	if !ok || len(events) != 1 {
		t.Errorf("want 1 event, got %v", resp["events"])
	}
	event := events[0].(map[string]any)
	if event["hostname"] != "macbook-pro" {
		t.Errorf("want enriched hostname, got %v", event["hostname"])
	}
}

func TestEnforcementAuditGetEmptyResults(t *testing.T) {
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	events, ok := resp["events"].([]any)
	if !ok {
		t.Fatalf("events should be an array, got %T", resp["events"])
	}
	if len(events) != 0 {
		t.Errorf("want empty array, got %v", events)
	}
	if resp["next_before"] != nil {
		t.Errorf("want next_before=null, got %v", resp["next_before"])
	}
}

func TestEnforcementAuditGetLimitCap(t *testing.T) {
	var gotLimit int
	listFn := func(_ context.Context, _ string, limit int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		gotLimit = limit
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?limit=9999", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if gotLimit != 1000 {
		t.Errorf("want limit capped at 1000, got %d", gotLimit)
	}
}

func TestEnforcementAuditGetInvalidLimit(t *testing.T) {
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?limit=bad", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid limit, got %d", w.Code)
	}
}

func TestEnforcementAuditGetInvalidBefore(t *testing.T) {
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?before=not-a-time", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid before, got %d", w.Code)
	}
}

func TestEnforcementAuditGetEventTypeFilter(t *testing.T) {
	var got []string
	var gotSearch string
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _ string, deviceSearch string, eventTypes []string) ([]enforcementAuditEntry, error) {
		got = eventTypes
		gotSearch = deviceSearch
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?event_type=admin_removed,admin_removal_skipped&event_type=extension_removed&device=MacBook", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	want := []string{"admin_removed", "admin_removal_skipped", "extension_removed"}
	if len(got) != len(want) {
		t.Fatalf("event types=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event types=%v, want %v", got, want)
		}
	}
	if gotSearch != "MacBook" {
		t.Fatalf("device search=%q, want MacBook", gotSearch)
	}
}

func TestEnforcementAuditGetRejectsUnknownEventType(t *testing.T) {
	called := false
	listFn := func(_ context.Context, _ string, _ int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		called = true
		return nil, nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?event_type=not_real", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if called {
		t.Fatal("list function must not run for an unknown event type")
	}
}

func TestEnforcementAuditGetNextBeforePresent(t *testing.T) {
	// When exactly `limit` events are returned, next_before should be set.
	now := time.Now().UTC().Truncate(time.Second)
	makeEntries := func(n int) []enforcementAuditEntry {
		out := make([]enforcementAuditEntry, n)
		for i := range out {
			out[i] = enforcementAuditEntry{
				ID:         "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				DeviceID:   eaTestDeviceID,
				EventType:  "app_blocked",
				Subject:    "com.evil.app",
				Details:    json.RawMessage(`{}`),
				OccurredAt: now,
				IngestedAt: now.Add(-time.Duration(i) * time.Minute),
			}
		}
		return out
	}
	listFn := func(_ context.Context, _ string, limit int, _ *time.Time, _, _ string, _ []string) ([]enforcementAuditEntry, error) {
		return makeEntries(limit), nil
	}
	h := newEnforcementAuditGetHandler(listFn)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+eaTestTenantID+"/enforcement-audit?limit=2", nil)
	req = acWithTenantID(req, eaTestTenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["next_before"] == nil {
		t.Error("want next_before set when result count equals limit")
	}
}

// eaIngestBodyBytes builds a minimal valid ingest request body.
func eaIngestBodyBytes(eventType, subject string) []byte {
	b, _ := json.Marshal(map[string]any{
		"events": []map[string]any{
			{
				"event_type":  eventType,
				"subject":     subject,
				"occurred_at": "2026-12-25T10:00:00Z",
			},
		},
	})
	return b
}

func TestEnforcementAuditIngestInvalidJSON(t *testing.T) {
	h := newEnforcementAuditIngestHandler(eaOKAuthFn,
		func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) { return 0, nil },
		nil, 0, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/inventory/enforcement-audit", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid JSON, got %d: %s", w.Code, w.Body.String())
	}
}

// TestEnforcementAuditIngestDeviceCredentialRequiredWireUnchanged is the
// PAT-1417 wire-compatibility proof: LookupDeviceByBearer now distinguishes
// "no such token" (ErrUnknownToken) from "token exists but is tenant-level"
// (ErrDeviceCredentialRequired) so the server can log and count the real
// cause. That distinction MUST NOT reach the client — this asserts the HTTP
// response (status, body, AND headers) for the new ErrDeviceCredentialRequired
// case is byte-identical to the pre-existing ErrUnknownToken response, which
// is exactly what a tenant-level credential produced before this change and
// still must produce for a genuinely unknown token today.
func TestEnforcementAuditIngestDeviceCredentialRequiredWireUnchanged(t *testing.T) {
	unknownTokenAuthFn := func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return "", "", auth.ErrUnknownToken
	}
	deviceCredRequiredAuthFn := func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return "", "", auth.ErrDeviceCredentialRequired
	}
	ingestFn := func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) { return 0, nil }

	hUnknown := newEnforcementAuditIngestHandler(unknownTokenAuthFn, ingestFn, nil, 0, nil)
	hDeviceCredRequired := newEnforcementAuditIngestHandler(deviceCredRequiredAuthFn, ingestFn, nil, 0, nil)

	before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest"))

	wUnknown := eaPostJSON(hUnknown, `{"events":[]}`)
	wDeviceCredRequired := eaPostJSON(hDeviceCredRequired, `{"events":[]}`)

	if wUnknown.Code != http.StatusUnauthorized {
		t.Fatalf("baseline (unknown token) status: got %d want %d", wUnknown.Code, http.StatusUnauthorized)
	}
	if wDeviceCredRequired.Code != wUnknown.Code {
		t.Errorf("status code differs: unknown-token=%d device-credential-required=%d", wUnknown.Code, wDeviceCredRequired.Code)
	}
	if wDeviceCredRequired.Body.String() != wUnknown.Body.String() {
		t.Errorf("response body differs:\nunknown-token:              %q\ndevice-credential-required:  %q",
			wUnknown.Body.String(), wDeviceCredRequired.Body.String())
	}
	if got, want := wDeviceCredRequired.Result().Header, wUnknown.Result().Header; !reflect.DeepEqual(got, want) {
		t.Errorf("response headers differ:\nunknown-token:              %v\ndevice-credential-required:  %v", want, got)
	}

	// Server-side, the two cases ARE distinguishable: the metric only moves
	// for the ErrDeviceCredentialRequired case.
	after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest"))
	if after != before+1 {
		t.Errorf("DeviceCredentialRequiredTotal{handler=enforcement_audit_ingest}: got %v want %v", after, before+1)
	}
}

// TestEnforcementAuditIngestOnlyRecognizedTenantCredentialIncrements proves
// the alert counter cannot be driven by malformed, unknown, expired, or
// revoked credentials. LookupDeviceByBearer maps all but the one successful
// live tenant-level row match to a different error; handlers must preserve
// that distinction for metrics while returning the same generic 401 on wire.
// The real DB-query mapping is covered by auth's
// TestLookupDeviceByBearer_{TenantLevelCredential,UnknownToken,RevokedDeviceCredential,ExpiredDeviceCredential};
// this injected-handler test deliberately verifies the separate metric branch
// for each resulting sentinel without needing a database in this package.
func TestEnforcementAuditIngestOnlyRecognizedTenantCredentialIncrements(t *testing.T) {
	ingestFn := func(_ context.Context, _, _ string, _ []enforcementAuditEvent) (int, error) { return 0, nil }
	cases := []struct {
		name string
		err  error
	}{
		{name: "malformed", err: auth.ErrBadAuthForm},
		{name: "unknown", err: auth.ErrUnknownToken},
		{name: "expired", err: fmt.Errorf("%w: credential expired", auth.ErrUnknownToken)},
		{name: "revoked", err: fmt.Errorf("%w: credential revoked", auth.ErrUnknownToken)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authFn := func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
				return "", "", tc.err
			}
			h := newEnforcementAuditIngestHandler(authFn, ingestFn, nil, 0, nil)
			before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest"))
			w := eaPostJSON(h, `{"events":[]}`)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest")); after != before {
				t.Fatalf("counter moved for %s credential path: got %v, want %v", tc.name, after, before)
			}
		})
	}
}
