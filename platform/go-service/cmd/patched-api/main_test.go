package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// H1 regression: the internal /admin/* surface must require ADMIN_API_TOKEN.
// The router is built with a nil pool; the auth middleware runs before any
// handler, so unauthenticated/misconfigured requests are rejected without ever
// touching the DB.

func TestInternalRouter_AdminAuth(t *testing.T) {
	const token = "s3cret-admin-token"

	t.Run("configured: missing credential is 401", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tenants", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth /admin/tenants: got %d, want 401", rr.Code)
		}
	})

	t.Run("configured: wrong credential is 401", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-auth /admin/tenants: got %d, want 401", rr.Code)
		}
	})

	t.Run("configured: /health stays open", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("/health: got %d, want 200", rr.Code)
		}
	})

	t.Run("configured: correct credential passes the auth gate", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		// Reaches the handler (nil pool -> Recoverer 500). The point is it is
		// NOT rejected by the auth middleware.
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusServiceUnavailable {
			t.Fatalf("correct-auth /admin/tenants was blocked by auth: got %d", rr.Code)
		}
	})

	t.Run("assessment redemption exists only behind the internal auth gate", func(t *testing.T) {
		path := "/admin/assessment-download-tokens/not-a-uuid/redeem"
		internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		internal.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("internal assessment redemption: got %d, want handler validation 400", rr.Code)
		}

		public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
		publicRR := httptest.NewRecorder()
		public.ServeHTTP(publicRR, httptest.NewRequest(http.MethodPost, path, nil))
		if publicRR.Code != http.StatusNotFound {
			t.Fatalf("public assessment redemption surface: got %d, want 404", publicRR.Code)
		}
	})

	t.Run("mandatory install admin routes are authenticated and absent publicly", func(t *testing.T) {
		internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/admin/tenants/00000000-0000-4000-8000-000000000001/mandatory-install-intents/evaluate"},
			{http.MethodPost, "/admin/tenants/00000000-0000-4000-8000-000000000001/mandatory-install-intents/emergency"},
			{http.MethodGet, "/admin/tenants/00000000-0000-4000-8000-000000000001/mandatory-install-intents"},
			{http.MethodPost, "/admin/tenants/00000000-0000-4000-8000-000000000001/mandatory-install-intents/00000000-0000-4000-8000-000000000002/retry"},
		} {
			internalRR := httptest.NewRecorder()
			internal.ServeHTTP(internalRR, httptest.NewRequest(tc.method, tc.path, nil))
			if internalRR.Code != http.StatusUnauthorized {
				t.Errorf("internal %s %s without auth: got %d want 401", tc.method, tc.path, internalRR.Code)
			}
			publicRR := httptest.NewRecorder()
			public.ServeHTTP(publicRR, httptest.NewRequest(tc.method, tc.path, nil))
			if publicRR.Code != http.StatusNotFound {
				t.Errorf("public %s %s: got %d want 404", tc.method, tc.path, publicRR.Code)
			}
		}
	})

	t.Run("unset token: admin surface fails closed with 503", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", "", "", nil, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		req.Header.Set("Authorization", "Bearer anything")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("unset-token /admin/tenants: got %d, want 503", rr.Code)
		}
		// /health must still be reachable even when the token is unset.
		rr2 := httptest.NewRecorder()
		r.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rr2.Code != http.StatusOK {
			t.Fatalf("unset-token /health: got %d, want 200", rr2.Code)
		}
	})

	// PAT-2046: the Homebrew review admin routes sit behind the same
	// requireInternalToken gate as every other /admin/* route, and are
	// absent from the public router.
	t.Run("homebrew review admin routes are authenticated and absent publicly", func(t *testing.T) {
		internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/admin/homebrew/review"},
			{http.MethodPost, "/admin/homebrew/review/1/map"},
			{http.MethodPost, "/admin/homebrew/review/1/accept-suggestion"},
			{http.MethodPost, "/admin/homebrew/review/1/dismiss"},
			// PAT-2138: CVE mapping proposal review, same gate.
			{http.MethodGet, "/admin/cve-mapping-proposals"},
			{http.MethodGet, "/admin/cve-mapping-proposals/1"},
			{http.MethodPost, "/admin/cve-mapping-proposals/1/approve"},
			{http.MethodPost, "/admin/cve-mapping-proposals/1/reject"},
			// PAT-2147: software lifecycle mappings and refresh, same gate.
			{http.MethodGet, "/admin/lifecycle/mappings"},
			{http.MethodPost, "/admin/lifecycle/mappings"},
			{http.MethodPost, "/admin/lifecycle/mappings/1/publish"},
			{http.MethodPost, "/admin/lifecycle/mappings/1/reject"},
			{http.MethodGet, "/admin/lifecycle/products"},
			{http.MethodPost, "/admin/lifecycle/refresh"},
		} {
			internalRR := httptest.NewRecorder()
			internal.ServeHTTP(internalRR, httptest.NewRequest(tc.method, tc.path, nil))
			if internalRR.Code != http.StatusUnauthorized {
				t.Errorf("internal %s %s without auth: got %d want 401", tc.method, tc.path, internalRR.Code)
			}
			publicRR := httptest.NewRecorder()
			public.ServeHTTP(publicRR, httptest.NewRequest(tc.method, tc.path, nil))
			if publicRR.Code != http.StatusNotFound {
				t.Errorf("public %s %s: got %d want 404", tc.method, tc.path, publicRR.Code)
			}
		}
	})
}

func TestInternalRouter_RetiresDuplicateAppUsageSurface(t *testing.T) {
	const token = "s3cret-admin-token"
	r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/admin/tenants/tenant-id/usage-tracking"},
		{http.MethodGet, "/admin/tenants/tenant-id/app-usage"},
		{http.MethodGet, "/admin/tenants/tenant-id/app-usage/App/devices"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s: got %d, want 404", tc.method, tc.path, rr.Code)
		}
	}

	// The authoritative device_apps metering API is a separate contract and
	// must remain routed. With a nil pool it reaches the handler and recovers as
	// 500, which distinguishes it from an accidentally removed 404 route.
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/tenant-id/metering", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatal("authoritative /metering route was removed with duplicate app-usage surface")
	}
}

func TestHMACCompatibilityTelemetrySurfaceIsAuthenticatedAndInternalOnly(t *testing.T) {
	const token = "s3cret-admin-token"
	const path = "/admin/ops/hmac-compatibility"
	internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
	public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)

	unauthenticated := httptest.NewRecorder()
	internal.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("internal route without auth: got %d, want 401", unauthenticated.Code)
	}

	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodGet, path, nil))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("public route: got %d, want 404", publicResponse.Code)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodGet, path, nil)
	authenticatedRequest.Header.Set("Authorization", "Bearer "+token)
	authenticated := httptest.NewRecorder()
	internal.ServeHTTP(authenticated, authenticatedRequest)
	// A nil pool makes the handler panic and Recoverer return 500. Reaching
	// that handler, rather than 401/503, proves the shared admin gate accepted
	// the credential without requiring a live test database.
	if authenticated.Code == http.StatusUnauthorized || authenticated.Code == http.StatusServiceUnavailable || authenticated.Code == http.StatusNotFound {
		t.Fatalf("authenticated route did not reach handler: got %d", authenticated.Code)
	}
}

func TestInternalRouter_RetiresAutomationManualTriggers(t *testing.T) {
	const token = "s3cret-admin-token"
	r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/automations/installomator_sync/trigger", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("retired Installomator trigger: got %d, want 404", rr.Code)
	}
}

// PAT-2246: the signed-catalogue publish (POST) and label read (GET) routes
// are retired, and so is the dedicated publisher credential that was carved
// out for the POST. The path now sits behind the ordinary admin gate like
// every other /admin/* path and resolves to nothing: the old publisher token
// authenticates nothing, and even the admin token only finds a 404.
func TestInternalRouter_SignedCatalogueRoutesRetired(t *testing.T) {
	const adminToken = "s3cret-admin-token"
	const retiredPublisherToken = "s3cret-catalogue-publisher-token"
	const path = "/admin/catalogue/signed"

	serve := func(configuredAdmin, method, token string) *httptest.ResponseRecorder {
		r := newInternalRouter(nil, nil, 0, "", configuredAdmin, "", nil, "", nil)
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method+" without credentials is 401", func(t *testing.T) {
			if rr := serve(adminToken, method, ""); rr.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", rr.Code)
			}
		})
		t.Run(method+" with the retired publisher token is 401", func(t *testing.T) {
			rr := serve(adminToken, method, retiredPublisherToken)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", rr.Code)
			}
			if strings.Contains(rr.Body.String(), retiredPublisherToken) {
				t.Fatalf("auth failure leaked the presented token: %q", rr.Body.String())
			}
		})
		t.Run(method+" with the admin token finds no route", func(t *testing.T) {
			if rr := serve(adminToken, method, adminToken); rr.Code != http.StatusNotFound {
				t.Fatalf("got %d, want 404", rr.Code)
			}
		})
		t.Run(method+" with no admin token configured fails closed", func(t *testing.T) {
			if rr := serve("", method, retiredPublisherToken); rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("got %d, want 503", rr.Code)
			}
		})
	}
}

// PAT-2249: the catalogue review, hosting and discovery pipeline routes are
// retired. With a valid admin token each one must now resolve to no route at
// all, on every method it used to serve. The report catalogue, which shares
// the word but not the pipeline, is the control: it must still answer, which
// proves the 404s come from the missing routes rather than from the auth gate
// or the test harness.
func TestInternalRouter_CatalogueReviewPipelineRoutesRetired(t *testing.T) {
	const adminToken = "s3cret-admin-token"
	r := newInternalRouter(nil, nil, 0, "", adminToken, "", nil, "", nil)

	serve := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	if rr := serve(http.MethodGet, "/admin/reports/catalogue"); rr.Code != http.StatusOK {
		t.Fatalf("control route GET /admin/reports/catalogue: got %d, want 200", rr.Code)
	}

	const tenant = "/admin/tenants/00000000-0000-4000-8000-000000000001"
	retired := []struct{ method, path string }{
		{http.MethodGet, "/admin/catalogue/candidates"},
		{http.MethodGet, "/admin/catalogue/products"},
		{http.MethodGet, "/admin/catalogue/target-operations"},
		{http.MethodPost, "/admin/catalogue/review"},
		{http.MethodPost, "/admin/catalogue/review/bulk"},
		{http.MethodPost, "/admin/catalogue/add"},
		{http.MethodPost, "/admin/catalogue/dismiss"},
		{http.MethodPost, "/admin/catalogue/revoke"},
		{http.MethodGet, "/admin/catalogue/pipeline-ready"},
		{http.MethodPost, "/admin/catalogue/state"},
		{http.MethodPost, "/admin/catalogue/promote"},
		{http.MethodPost, "/admin/catalogue/demote"},
		{http.MethodGet, "/admin/catalogue/vendor-origins"},
		{http.MethodPost, "/admin/catalogue/vendor-origins"},
		{http.MethodDelete, "/admin/catalogue/vendor-origins/00000000-0000-4000-8000-000000000002"},
		{http.MethodGet, "/admin/discovery/jobs"},
		{http.MethodPost, "/admin/discovery/jobs"},
		{http.MethodPost, "/admin/discovery/jobs/state"},
		{http.MethodGet, "/admin/discovery/baseline"},
		{http.MethodGet, "/admin/discovery/runs"},
		{http.MethodPost, "/admin/discovery/runs"},
		{http.MethodGet, tenant + "/execution-policies"},
		{http.MethodPost, tenant + "/execution-policies"},
		{http.MethodDelete, tenant + "/execution-policies/1"},
	}
	for _, tc := range retired {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if rr := serve(tc.method, tc.path); rr.Code != http.StatusNotFound {
				t.Fatalf("got %d, want 404", rr.Code)
			}
		})
	}
}

// PAT-867 regression: shutdown used to cancel the sweeper context and
// immediately proceed to shut down the HTTP servers without ever waiting for
// the webhook-sweeper / report-scheduler goroutines to actually finish — the
// "drain cleanly" doc comment on sweeperCtx was not backed by a WaitGroup, so
// on process exit an in-flight sweeper tick was killed outright rather than
// allowed to complete. waitWithTimeout is the primitive that closes that gap;
// these tests pin its two outcomes directly, without needing a live server.

func TestWaitWithTimeout_FinishesInTime(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
	}()

	if !waitWithTimeout(&wg, time.Second) {
		t.Fatal("want true: wg finished well within the timeout")
	}
}

func TestWaitWithTimeout_TimesOut(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	// Deliberately never call wg.Done() — simulates a stuck in-flight sweeper
	// tick (e.g. a wedged HTTP POST) that shutdown must not hang on forever.
	defer wg.Done() // avoid leaking a goroutine-less but permanently-blocked wg past the test

	if waitWithTimeout(&wg, 20*time.Millisecond) {
		t.Fatal("want false: wg never finished, so the call must time out")
	}
}

// TestRemovalCampaignSurfaceIsAdminOnly (PAT-1598) pins the property the
// authorised-removal slice rests on: the campaign surface exists only behind
// ADMIN_API_TOKEN on the internal listener, and the public listener serves no
// removal route at all.
//
// The second half is the load-bearing one. PAT-1598's gate is that no removal
// reaches a customer endpoint before the MSA contract language exists
// (PAT-112, not delivered). This slice holds that gate structurally rather
// than with a capability flag: there is no agent-facing path to flip. A test
// is how that stays true, because adding one later is a two-line change that
// would otherwise pass review as "just wiring".
func TestRemovalCampaignSurfaceIsAdminOnly(t *testing.T) {
	const token = "s3cret-admin-token"
	const tenant = "00000000-0000-4000-8000-000000000001"
	const campaign = "00000000-0000-4000-8000-000000000002"

	internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
	public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)

	adminRoutes := []struct{ method, path string }{
		{http.MethodPost, "/admin/tenants/" + tenant + "/removal-campaigns"},
		{http.MethodGet, "/admin/tenants/" + tenant + "/removal-campaigns"},
		{http.MethodGet, "/admin/tenants/" + tenant + "/removal-campaigns/" + campaign},
		{http.MethodPost, "/admin/tenants/" + tenant + "/removal-campaigns/" + campaign + "/dry-run"},
		{http.MethodPost, "/admin/tenants/" + tenant + "/removal-campaigns/" + campaign + "/authorize"},
		{http.MethodPost, "/admin/tenants/" + tenant + "/removal-campaigns/" + campaign + "/cancel"},
	}
	for _, tc := range adminRoutes {
		internalRR := httptest.NewRecorder()
		internal.ServeHTTP(internalRR, httptest.NewRequest(tc.method, tc.path, nil))
		if internalRR.Code != http.StatusUnauthorized {
			t.Errorf("internal %s %s without auth: got %d, want 401", tc.method, tc.path, internalRR.Code)
		}
		publicRR := httptest.NewRecorder()
		public.ServeHTTP(publicRR, httptest.NewRequest(tc.method, tc.path, nil))
		if publicRR.Code != http.StatusNotFound {
			t.Errorf("public %s %s: got %d, want 404", tc.method, tc.path, publicRR.Code)
		}
	}

	// No agent-facing shape of this capability exists on the public listener
	// under any plausible spelling an agent would poll.
	for _, path := range []string{
		"/v1/removal-campaigns",
		"/v1/removals/pending",
		"/v1/removal/pending",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rr := httptest.NewRecorder()
			public.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
			if rr.Code != http.StatusNotFound {
				t.Errorf("public %s %s: got %d, want 404 (no agent-facing removal delivery path may exist)", method, path, rr.Code)
			}
		}
	}

	// /v1/portal/* is mounted behind portal auth, which fails closed with 503
	// when the verifier is unconfigured (as it is here), so a 404 is not
	// reachable for that prefix. What matters is that no removal path under it
	// ever succeeds.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rr := httptest.NewRecorder()
		public.ServeHTTP(rr, httptest.NewRequest(method, "/v1/portal/removal-campaigns", nil))
		if rr.Code < 400 {
			t.Errorf("public %s /v1/portal/removal-campaigns: got %d, want a refusal", method, rr.Code)
		}
	}
}

// PAT-2287: listing and revoking bootstrap tokens sit on the internal
// listener behind the same ADMIN_API_TOKEN gate as the mint, and do not exist
// on the public listener. With the token, each route reaches its handler
// (a malformed tenantID is the handler's own 400, which also proves the GET
// is mounted rather than answered 405 by the mint's POST on the same path).
func TestBootstrapTokenAdminRoutesAreInternalOnly(t *testing.T) {
	const token = "s3cret-admin-token"
	const tenant = "00000000-0000-4000-8000-000000000001"
	const tok = "00000000-0000-4000-8000-000000000002"

	internal := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
	public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/admin/tenants/" + tenant + "/bootstrap-tokens"},
		{http.MethodPost, "/admin/tenants/" + tenant + "/bootstrap-tokens/" + tok + "/revoke"},
	} {
		rr := httptest.NewRecorder()
		internal.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("internal %s %s without auth: got %d, want 401", tc.method, tc.path, rr.Code)
		}
		publicRR := httptest.NewRecorder()
		public.ServeHTTP(publicRR, httptest.NewRequest(tc.method, tc.path, nil))
		if publicRR.Code != http.StatusNotFound {
			t.Errorf("public %s %s: got %d, want 404", tc.method, tc.path, publicRR.Code)
		}
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/admin/tenants/not-a-uuid/bootstrap-tokens"},
		{http.MethodPost, "/admin/tenants/not-a-uuid/bootstrap-tokens/" + tok + "/revoke"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		internal.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("authenticated %s %s: got %d, want the handler's 400 for a malformed tenantID", tc.method, tc.path, rr.Code)
		}
	}
}

// PAT-2408: the internal listener must require the Bearer scheme. Before this
// the middleware stripped an optional "Bearer " prefix and compared whatever
// was left, so the admin token presented bare, with no scheme at all, was
// accepted. The secret was still required, so this was strictness rather than
// a bypass, but the only accepted form is now the documented one.
//
// The scheme name is matched case-insensitively (RFC 9110 section 11.1, and
// the same rule auth.LookupTenantByBearer applies on the public listener).
// Exactly one space separates scheme and token, and the token is compared
// byte for byte: no whitespace is trimmed on either side of it.
func TestInternalRouter_AdminAuthRequiresBearerScheme(t *testing.T) {
	const token = "test-admin-token"
	const wrong = "test-wrong-token"

	for _, tc := range []struct {
		name string
		// header is the exact Authorization value; set is false to send none.
		header   string
		set      bool
		accepted bool
	}{
		{name: "correct token with Bearer scheme", header: "Bearer " + token, set: true, accepted: true},
		{name: "lower-case scheme", header: "bearer " + token, set: true, accepted: true},
		{name: "upper-case scheme", header: "BEARER " + token, set: true, accepted: true},
		{name: "bare correct token, no scheme", header: token, set: true},
		{name: "bare wrong token, no scheme", header: wrong, set: true},
		{name: "wrong token with Bearer scheme", header: "Bearer " + wrong, set: true},
		{name: "no Authorization header"},
		{name: "empty Authorization header", header: "", set: true},
		{name: "scheme only", header: "Bearer", set: true},
		{name: "scheme and space only", header: "Bearer ", set: true},
		{name: "Basic scheme with correct token", header: "Basic " + token, set: true},
		{name: "two spaces after scheme", header: "Bearer  " + token, set: true},
		{name: "trailing space after token", header: "Bearer " + token + " ", set: true},
		{name: "trailing tab after token", header: "Bearer " + token + "\t", set: true},
		{name: "leading space before scheme", header: " Bearer " + token, set: true},
		{name: "tab instead of space", header: "Bearer\t" + token, set: true},
		{name: "no separator", header: "Bearer" + token, set: true},
		{name: "scheme repeated", header: "Bearer Bearer " + token, set: true},
		{name: "token then scheme", header: token + " Bearer", set: true},
		{name: "correct token with a suffix", header: "Bearer " + token + "x", set: true},
		{name: "correct token truncated", header: "Bearer " + token[:len(token)-1], set: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
			req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
			if tc.set {
				// Assign directly so the exact bytes reach the middleware.
				req.Header["Authorization"] = []string{tc.header}
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if tc.accepted {
				// A nil pool makes the handler panic and Recoverer answer
				// 500. Reaching the handler is the proof the gate opened.
				if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusServiceUnavailable {
					t.Fatalf("Authorization %q was blocked by the auth gate: got %d", tc.header, rr.Code)
				}
				return
			}
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("Authorization %q: got %d, want 401", tc.header, rr.Code)
			}
			if strings.Contains(rr.Body.String(), token) || (tc.header != "" && strings.Contains(rr.Body.String(), tc.header)) {
				t.Fatalf("auth failure echoed the presented credential: %q", rr.Body.String())
			}
		})
	}

	// The scheme requirement must not weaken the fail-closed posture or the
	// two deliberately open paths.
	t.Run("unset token still fails closed for a bare value", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", "", "", nil, "", nil)
		for _, header := range []string{"", "Bearer ", "Bearer", "anything"} {
			req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
			req.Header["Authorization"] = []string{header}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("unset token, Authorization %q: got %d, want 503", header, rr.Code)
			}
		}
	})
	t.Run("health and metrics stay open without a credential", func(t *testing.T) {
		r := newInternalRouter(nil, nil, 0, "", token, "", nil, "", nil)
		for _, path := range []string{"/health", "/metrics"} {
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: got %d, want 200", path, rr.Code)
			}
		}
	})
}
