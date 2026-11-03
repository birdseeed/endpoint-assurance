package handlers

// Tests for the Slack alert sent on app-launch-restriction transitions
// (PAT-820): TenantAllowlistAddHandler / TenantAllowlistUpdateHandler
// (enforcement -> launch_restricted) and TenantAppPoliciesPutHandler
// (policy -> unapproved).
//
// DB-backed; require TEST_DATABASE_URL and are skipped otherwise, matching the
// convention in catalogue_test.go.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/notify"
)

// naWithEntryParams injects tenantID and entryID chi URL params.
func naWithEntryParams(r *http.Request, tenantID, entryID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	rctx.URLParams.Add("entryID", entryID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// naSlackCounter starts a test Slack webhook server that counts deliveries
// and points NOTIFY_SLACK_WEBHOOK_URL at it for the duration of the test.
func naSlackCounter(t *testing.T) *int32 {
	t.Helper()
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("NOTIFY_SLACK_WEBHOOK_URL", srv.URL)
	return &count
}

// naWaitForCount polls until *counter reaches want or the timeout elapses.
func naWaitForCount(t *testing.T, counter *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for slack call count = %d, got %d", want, atomic.LoadInt32(counter))
}

// naAssertStableCount asserts *counter stays at want for the given window —
// used to prove a duplicate/idempotent write did NOT trigger an extra alert.
func naAssertStableCount(t *testing.T, counter *int32, want int32, window time.Duration) {
	t.Helper()
	time.Sleep(window)
	if got := atomic.LoadInt32(counter); got != want {
		t.Fatalf("expected slack call count to stay at %d, got %d", want, got)
	}
}

// ---------------------------------------------------------------------------
// Allowlist: POST (new entry directly at launch_restricted)
// ---------------------------------------------------------------------------

func TestAllowlistAddLaunchRestrictedSendsOneSlackAlert(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-add-restrict")
	counter := naSlackCounter(t)
	notifier := notify.New()

	h := TenantAllowlistAddHandler(pool, notifier)
	body := `{"name":"Restricted App","enforcement":"launch_restricted","approved_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/allowlist", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
	naWaitForCount(t, counter, 1, 2*time.Second)
}

// TestAllowlistAddAllowedDoesNotAlert verifies that creating an entry with a
// non-restricted enforcement never triggers the app-launch-restricted alert.
func TestAllowlistAddAllowedDoesNotAlert(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-add-allowed")
	counter := naSlackCounter(t)
	notifier := notify.New()

	h := TenantAllowlistAddHandler(pool, notifier)
	body := `{"name":"Allowed App","enforcement":"allowed","approved_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/allowlist", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
	naAssertStableCount(t, counter, 0, 300*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Allowlist: PUT (existing entry transitioning to launch_restricted)
// ---------------------------------------------------------------------------

func TestAllowlistUpdateFirstTransitionSendsOneSlackAlert(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-update-restrict")

	var entryID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_allowlists (tenant_id, platform, name, match_mode, enforcement, approved_by, notes, approved_at)
		VALUES ($1::uuid, 'any', 'Some App', 'exact_name', 'allowed', 'admin', '', now())
		RETURNING id
	`, tenantID).Scan(&entryID); err != nil {
		t.Fatalf("seed allowlist entry: %v", err)
	}

	counter := naSlackCounter(t)
	notifier := notify.New()
	h := TenantAllowlistUpdateHandler(pool, notifier)

	body := `{"enforcement":"launch_restricted","notes":"restricted by operator"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/allowlist/1", bytes.NewBufferString(body))
	req = naWithEntryParams(req, tenantID, strconv.FormatInt(entryID, 10))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}
	naWaitForCount(t, counter, 1, 2*time.Second)
}

// TestAllowlistUpdateIdempotentReSaveDoesNotSpamSlack verifies that re-saving
// an already-launch_restricted entry does not send a second alert.
func TestAllowlistUpdateIdempotentReSaveDoesNotSpamSlack(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-update-idempotent")

	var entryID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_allowlists (tenant_id, platform, name, match_mode, enforcement, approved_by, notes, approved_at)
		VALUES ($1::uuid, 'any', 'Already Restricted App', 'exact_name', 'launch_restricted', 'admin', '', now())
		RETURNING id
	`, tenantID).Scan(&entryID); err != nil {
		t.Fatalf("seed allowlist entry: %v", err)
	}

	counter := naSlackCounter(t)
	notifier := notify.New()
	h := TenantAllowlistUpdateHandler(pool, notifier)

	body := `{"enforcement":"launch_restricted","notes":"re-saved, still restricted"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/allowlist/1", bytes.NewBufferString(body))
	req = naWithEntryParams(req, tenantID, strconv.FormatInt(entryID, 10))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}
	naAssertStableCount(t, counter, 0, 300*time.Millisecond)
}

// ---------------------------------------------------------------------------
// App policies: PUT (policy -> unapproved)
// ---------------------------------------------------------------------------

func TestAppPoliciesFirstTransitionToUnapprovedSendsOneSlackAlert(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-policy-restrict")
	counter := naSlackCounter(t)
	notifier := notify.New()

	h := TenantAppPoliciesPutHandler(pool, notifier)
	body := `{"name":"Risky App","platform":"any","policy":"unapproved","enforcement_tier":"report"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	naWaitForCount(t, counter, 1, 2*time.Second)
}

// TestAppPoliciesIdempotentReSaveDoesNotSpamSlack verifies that re-saving an
// already-unapproved policy entry does not send a second alert.
func TestAppPoliciesIdempotentReSaveDoesNotSpamSlack(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "notify-test-policy-idempotent")
	counter := naSlackCounter(t)
	notifier := notify.New()

	h := TenantAppPoliciesPutHandler(pool, notifier)
	body := `{"name":"Risky App","platform":"any","policy":"unapproved","enforcement_tier":"report"}`

	// First PUT — this is the genuine first transition, expect exactly one alert.
	req1 := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req1 = catWithTenantID(req1, tenantID)
	w1 := httptest.NewRecorder()
	h(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first PUT: want 200, got %d: %s", w1.Code, w1.Body.String())
	}
	naWaitForCount(t, counter, 1, 2*time.Second)

	// Second PUT — same identity, same policy. Must not add a second alert.
	req2 := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req2 = catWithTenantID(req2, tenantID)
	w2 := httptest.NewRecorder()
	h(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second PUT: want 200, got %d: %s", w2.Code, w2.Body.String())
	}
	naAssertStableCount(t, counter, 1, 300*time.Millisecond)
}

// TestAppPoliciesMissingSlackConfigStillPersists verifies the policy write
// still succeeds when no Slack webhook is configured.
func TestAppPoliciesMissingSlackConfigStillPersists(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()

	tenantID := catSeedTenant(t, context.Background(), pool, "notify-test-policy-no-config")
	// Deliberately do not set NOTIFY_SLACK_WEBHOOK_URL.
	notifier := notify.New()

	h := TenantAppPoliciesPutHandler(pool, notifier)
	body := `{"name":"Risky App","platform":"any","policy":"unapproved","enforcement_tier":"report"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 even with no Slack config, got %d: %s", w.Code, w.Body.String())
	}
}
