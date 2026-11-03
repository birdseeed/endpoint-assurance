package handlers

// Tests for the webhook admin handlers (PAT-134). The tenantID validation
// checks all run before any pool access, so a nil *pgxpool.Pool is safe here —
// mirrors the nil-pool pattern used by extension_removals_test.go and others.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

const whMalformedTenantID = "not-a-uuid"

func whRouteCtx(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestWebhookHandlers_MalformedTenantID400 verifies every webhook admin
// handler rejects a non-UUID tenantID with 400, consistent with every sibling
// admin handler in this package — regression test for the bug where
// WebhookListHandler (and its siblings) passed an unvalidated tenantID
// straight to the DB layer, surfacing a generic 500 instead of a 400.
func TestWebhookHandlers_MalformedTenantID400(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		params  map[string]string
		handler http.HandlerFunc
	}{
		{
			name:    "list",
			method:  http.MethodGet,
			path:    "/admin/tenants/not-a-uuid/webhooks",
			params:  map[string]string{"tenantID": whMalformedTenantID},
			handler: WebhookListHandler(nil),
		},
		{
			name:    "create",
			method:  http.MethodPost,
			path:    "/admin/tenants/not-a-uuid/webhooks",
			params:  map[string]string{"tenantID": whMalformedTenantID},
			handler: WebhookCreateHandler(nil),
		},
		{
			name:    "update",
			method:  http.MethodPut,
			path:    "/admin/tenants/not-a-uuid/webhooks/some-id",
			params:  map[string]string{"tenantID": whMalformedTenantID, "webhookID": "some-id"},
			handler: WebhookUpdateHandler(nil),
		},
		{
			name:    "delete",
			method:  http.MethodDelete,
			path:    "/admin/tenants/not-a-uuid/webhooks/some-id",
			params:  map[string]string{"tenantID": whMalformedTenantID, "webhookID": "some-id"},
			handler: WebhookDeleteHandler(nil),
		},
		{
			name:    "deliveries",
			method:  http.MethodGet,
			path:    "/admin/tenants/not-a-uuid/webhooks/some-id/deliveries",
			params:  map[string]string{"tenantID": whMalformedTenantID, "webhookID": "some-id"},
			handler: WebhookDeliveriesHandler(nil),
		},
		{
			name:    "test",
			method:  http.MethodPost,
			path:    "/admin/tenants/not-a-uuid/webhooks/some-id/test",
			params:  map[string]string{"tenantID": whMalformedTenantID, "webhookID": "some-id"},
			handler: WebhookTestHandler(nil),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = whRouteCtx(req, tc.params)
			rr := httptest.NewRecorder()

			// A nil pool would panic if the handler reached the DB layer;
			// panicking here (rather than a clean 400) is itself proof the
			// validation guard is missing or mis-ordered.
			tc.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: want 400 for malformed tenantID, got %d: %s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestWebhookListHandler_ValidUUIDReachesDB verifies a syntactically valid
// UUID passes the guard and proceeds to the DB call (which panics on the nil
// pool here — proving the validation check did NOT short-circuit a legitimate
// request). This is the fail-before/pass-after counterpart to the malformed
// case above: it would panic identically whether or not the fix is present,
// but it documents that the guard is shape-only, not a UUID allowlist.
func TestWebhookListHandler_ValidUUIDReachesDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("want a panic from the nil-pool DB call — a valid UUID must not be rejected by looksLikeUUID")
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/a1b2c3d4-e5f6-7890-abcd-ef1234567890/webhooks", nil)
	req = whRouteCtx(req, map[string]string{"tenantID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})
	rr := httptest.NewRecorder()

	WebhookListHandler(nil).ServeHTTP(rr, req)
}
