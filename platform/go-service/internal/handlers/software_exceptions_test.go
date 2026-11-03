package handlers

// PAT-1824 DB-backed tests: software exception register.
//
// Covers: create, record acceptance (acceptor + history entry), review-date
// renewal (with history entry), review_overdue computation, tenant
// isolation, and the /v1/portal/extensions-style ordering that keeps
// unaccepted/review-overdue rows ahead of everything else (the property the
// portalExceptionsMaxRows cap relies on to never cut a row that needs
// attention — see internal/report/portal_exceptions.go).
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, reusing
// catConnectOrSkip / catSeedTenant / catWithTenantID (db_test_helpers_test.go),
// matching the protected_software_test.go convention in this package.
// Requires migration 0142 to have been applied — like every other DB-gated
// test here, it assumes the target database is already fully migrated.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/portalauth"
)

// excWithParams injects both tenantID and exceptionID chi URL params, for
// the accept/review-date routes which need both.
func excWithParams(r *http.Request, tenantID, exceptionID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	if exceptionID != "" {
		rctx.URLParams.Add("exceptionID", exceptionID)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// excCreate is a small helper: POST the create request and return the
// decoded exceptionRow, failing the test on any non-201.
func excCreate(t *testing.T, h http.HandlerFunc, tenantID, body string) exceptionRow {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var row exceptionRow
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return row
}

func TestExceptionCreate(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-create-tenant")

	h := ExceptionCreateHandler(pool)
	body := `{"product":"LegacyLedger","version":"4.1.0","depends_on":"Finance close needs 4.1",` +
		`"requested_by":"jane@tenant.example"}`
	row := excCreate(t, h, tenantID, body)

	if row.Product != "LegacyLedger" || row.Version != "4.1.0" || row.Type != "application" {
		t.Fatalf("unexpected row: %+v", row)
	}
	if row.Status != "unaccepted" {
		t.Fatalf("status = %q, want unaccepted", row.Status)
	}
	if row.Acceptor != nil {
		t.Fatalf("acceptor = %v, want nil for a freshly created exception", row.Acceptor)
	}

	// A 'requested' history row must have been appended.
	var action, actor string
	if err := pool.QueryRow(ctx, `
		SELECT action, actor FROM tenant_software_exception_changes WHERE exception_id = $1::uuid
	`, row.ID).Scan(&action, &actor); err != nil {
		t.Fatalf("query history: %v", err)
	}
	if action != "requested" || actor != "jane@tenant.example" {
		t.Fatalf("history = (%q, %q), want (requested, jane@tenant.example)", action, actor)
	}
}

func TestExceptionCreateMissingRequiredFields(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-missing-fields-tenant")

	h := ExceptionCreateHandler(pool)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions",
		bytes.NewBufferString(`{"product":"App"}`))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing version/requested_by, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExceptionCreateWithDevicesAndPortalRead(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-devices-tenant")

	var deviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname) VALUES ($1::uuid, 'acme-mbp-frontdesk') RETURNING id::text`,
		tenantID,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	h := ExceptionCreateHandler(pool)
	body := `{"product":"LegacyLedger","version":"4.1.0","requested_by":"jane@tenant.example",` +
		`"device_ids":["` + deviceID + `","` + deviceID + `"]}` // duplicate on purpose
	row := excCreate(t, h, tenantID, body)

	var deviceCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_software_exception_devices WHERE exception_id = $1::uuid`, row.ID,
	).Scan(&deviceCount); err != nil {
		t.Fatal(err)
	}
	if deviceCount != 1 {
		t.Fatalf("device_count = %d, want 1 (duplicate device_ids must dedupe)", deviceCount)
	}

	// Read it back through the portal handler and confirm the device shows
	// up in the response shape the portal consumes.
	getH := PortalExceptionsHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/exceptions", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "specialist@patched.im", TenantID: tenantID}))
	w := httptest.NewRecorder()
	getH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("portal get: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp portalExceptionsResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode portal response: %v", err)
	}
	if len(resp.Exceptions) != 1 {
		t.Fatalf("len(exceptions) = %d, want 1", len(resp.Exceptions))
	}
	got := resp.Exceptions[0]
	if got.DeviceCount != 1 || len(got.Devices) != 1 || got.Devices[0].Hostname != "acme-mbp-frontdesk" {
		t.Fatalf("unexpected device shape: %+v", got)
	}
	if len(got.History) != 1 || got.History[0].Action != "requested" {
		t.Fatalf("unexpected history: %+v", got.History)
	}
}

func TestExceptionCreateRejectsForeignDevice(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantA := catSeedTenant(t, ctx, pool, "pat1824-foreign-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat1824-foreign-b")

	var foreignDeviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantB,
	).Scan(&foreignDeviceID); err != nil {
		t.Fatal(err)
	}

	h := ExceptionCreateHandler(pool)
	body := `{"product":"App","version":"1.0","requested_by":"jane@tenant.example",` +
		`"device_ids":["` + foreignDeviceID + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantA+"/exceptions", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantA)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for a device_id owned by a different tenant, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_software_exceptions WHERE tenant_id = $1::uuid`, tenantA,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("exception row written despite foreign-device rejection: count=%d", count)
	}
}

func TestExceptionAccept(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-accept-tenant")

	createH := ExceptionCreateHandler(pool)
	row := excCreate(t, createH, tenantID,
		`{"product":"App","version":"1.0","requested_by":"jane@tenant.example"}`)

	acceptH := ExceptionAcceptHandler(pool)
	body := `{"acceptor":"Alex Patched","reason":"Approved pending EOL migration"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions/"+row.ID+"/accept",
		bytes.NewBufferString(body))
	req = excWithParams(req, tenantID, row.ID)
	w := httptest.NewRecorder()
	acceptH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var accepted exceptionRow
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "accepted" || accepted.Acceptor == nil || *accepted.Acceptor != "Alex Patched" {
		t.Fatalf("unexpected accepted row: %+v", accepted)
	}
	if accepted.AcceptedAt == nil {
		t.Fatal("accepted_at is nil, want a timestamp")
	}

	var histCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM tenant_software_exception_changes
		WHERE exception_id = $1::uuid AND action = 'accepted' AND actor = 'Alex Patched'
	`, row.ID).Scan(&histCount); err != nil {
		t.Fatal(err)
	}
	if histCount != 1 {
		t.Fatalf("accepted history rows = %d, want 1", histCount)
	}

	// Accepting an already-accepted exception is a conflict, not a silent
	// no-op or a second acceptance record.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions/"+row.ID+"/accept",
		bytes.NewBufferString(body))
	req2 = excWithParams(req2, tenantID, row.ID)
	acceptH(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("re-accept: want 409, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestExceptionAcceptRequiresReasonAndActor(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-accept-validation-tenant")

	createH := ExceptionCreateHandler(pool)
	row := excCreate(t, createH, tenantID, `{"product":"App","version":"1.0","requested_by":"jane@tenant.example"}`)

	acceptH := ExceptionAcceptHandler(pool)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions/"+row.ID+"/accept",
		bytes.NewBufferString(`{"acceptor":"Alex"}`))
	req = excWithParams(req, tenantID, row.ID)
	w := httptest.NewRecorder()
	acceptH(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing reason, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExceptionReviewDateRenewal(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-review-date-tenant")

	createH := ExceptionCreateHandler(pool)
	row := excCreate(t, createH, tenantID,
		`{"product":"App","version":"1.0","requested_by":"jane@tenant.example","review_date":"2026-07-01"}`)

	renewH := ExceptionReviewDateHandler(pool)
	body := `{"review_date":"2027-06-01","actor":"Alex Patched","reason":"renewed for another cycle"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions/"+row.ID+"/review-date",
		bytes.NewBufferString(body))
	req = excWithParams(req, tenantID, row.ID)
	w := httptest.NewRecorder()
	renewH(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("review-date: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp exceptionReviewDateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ReviewDate == nil || *resp.ReviewDate != "2027-06-01" {
		t.Fatalf("review_date = %v, want 2027-06-01", resp.ReviewDate)
	}

	var histCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM tenant_software_exception_changes
		WHERE exception_id = $1::uuid AND action = 'review_date_renewed' AND actor = 'Alex Patched'
	`, row.ID).Scan(&histCount); err != nil {
		t.Fatal(err)
	}
	if histCount != 1 {
		t.Fatalf("review_date_renewed history rows = %d, want 1", histCount)
	}
}

func TestExceptionReviewDateNotFound(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-review-date-404-tenant")

	h := ExceptionReviewDateHandler(pool)
	fakeID := "00000000-0000-0000-0000-000000000000"
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/exceptions/"+fakeID+"/review-date",
		bytes.NewBufferString(`{"review_date":"2027-01-01","actor":"Alex Patched"}`))
	req = excWithParams(req, tenantID, fakeID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown exception, got %d: %s", w.Code, w.Body.String())
	}
}

// TestReviewOverdueComputationAndOrdering proves review_overdue is computed
// server-side (never trusted from the client, which cannot set it at all —
// there is no such field on the create/accept/review-date request shapes),
// is independent of acceptance status (an accepted exception with a lapsed
// review date still reads review_overdue=true), and that the response
// ordering puts unaccepted and review-overdue rows ahead of an
// accepted-and-current row — the property portalExceptionsMaxRows' cap
// relies on to never cut a row that needs attention (the /v1/portal/extensions
// convention named in the ticket).
func TestReviewOverdueComputationAndOrdering(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1824-overdue-ordering-tenant")

	createH := ExceptionCreateHandler(pool)
	acceptH := ExceptionAcceptHandler(pool)

	past := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	future := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")

	// zzz-clean: accepted, review date in the future — should sort last.
	clean := excCreate(t, createH, tenantID,
		`{"product":"zzz-clean","version":"1.0","requested_by":"jane@tenant.example","review_date":"`+future+`"}`)
	acceptReq := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(
		`{"acceptor":"Alex Patched","reason":"fine"}`))
	acceptReq = excWithParams(acceptReq, tenantID, clean.ID)
	acceptH(httptest.NewRecorder(), acceptReq)

	// aaa-overdue: accepted, but review date lapsed — must still need
	// attention despite sorting alphabetically before zzz-clean.
	overdue := excCreate(t, createH, tenantID,
		`{"product":"aaa-overdue","version":"1.0","requested_by":"jane@tenant.example","review_date":"`+past+`"}`)
	overdueAcceptReq := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(
		`{"acceptor":"Alex Patched","reason":"fine"}`))
	overdueAcceptReq = excWithParams(overdueAcceptReq, tenantID, overdue.ID)
	acceptH(httptest.NewRecorder(), overdueAcceptReq)

	// mmm-unaccepted: never accepted at all.
	_ = excCreate(t, createH, tenantID,
		`{"product":"mmm-unaccepted","version":"1.0","requested_by":"jane@tenant.example"}`)

	getH := PortalExceptionsHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/exceptions", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "specialist@patched.im", TenantID: tenantID}))
	w := httptest.NewRecorder()
	getH(w, req)
	var resp portalExceptionsResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Exceptions) != 3 {
		t.Fatalf("len(exceptions) = %d, want 3", len(resp.Exceptions))
	}

	byProduct := map[string]portalExceptionEntry{}
	for _, e := range resp.Exceptions {
		byProduct[e.Product] = e
	}
	if !byProduct["aaa-overdue"].ReviewOverdue {
		t.Fatal("accepted-but-lapsed exception must read review_overdue=true")
	}
	if byProduct["zzz-clean"].ReviewOverdue {
		t.Fatal("accepted exception with a future review date must read review_overdue=false")
	}
	if byProduct["mmm-unaccepted"].Status != "unaccepted" || byProduct["mmm-unaccepted"].ReviewOverdue {
		t.Fatalf("unaccepted row unexpectedly overdue: %+v", byProduct["mmm-unaccepted"])
	}

	// Ordering: unaccepted first, then review-overdue, then the rest —
	// zzz-clean (alphabetically last) must still sort after both, since it
	// needs no attention.
	last := resp.Exceptions[len(resp.Exceptions)-1]
	if last.Product != "zzz-clean" {
		t.Fatalf("last row = %q, want zzz-clean (the only row needing no attention)", last.Product)
	}
}

func TestExceptionTenantIsolation(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantA := catSeedTenant(t, ctx, pool, "pat1824-isolation-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat1824-isolation-b")

	createH := ExceptionCreateHandler(pool)
	excCreate(t, createH, tenantA, `{"product":"AppA","version":"1.0","requested_by":"jane@tenant-a.example"}`)
	excCreate(t, createH, tenantB, `{"product":"AppB","version":"1.0","requested_by":"jane@tenant-b.example"}`)

	getH := PortalExceptionsHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/exceptions", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "a@tenant-a.example", TenantID: tenantA}))
	w := httptest.NewRecorder()
	getH(w, req)
	var resp portalExceptionsResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Exceptions) != 1 || resp.Exceptions[0].Product != "AppA" {
		t.Fatalf("tenant A saw %+v, want only AppA", resp.Exceptions)
	}
}

func TestExceptionCreateUnknownTenant(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	h := ExceptionCreateHandler(pool)
	fakeTenant := "00000000-0000-0000-0000-000000000000"
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+fakeTenant+"/exceptions",
		bytes.NewBufferString(`{"product":"App","version":"1.0","requested_by":"jane@tenant.example"}`))
	req = catWithTenantID(req, fakeTenant)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown tenant, got %d: %s", w.Code, w.Body.String())
	}
}
