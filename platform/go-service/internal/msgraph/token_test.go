package msgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tenantFromTokenPath extracts the {tenantID} segment from
// "/{tenantID}/oauth2/v2.0/token", mirroring how the real Entra token
// endpoint is shaped.
func tenantFromTokenPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func newTestTokenSource(t *testing.T, handler http.HandlerFunc) (*TokenSource, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cert := generateTestCertificate(t, time.Now().Add(24*time.Hour))
	ts := NewTokenSource("client-id", cert)
	ts.AuthorityBase = server.URL
	return ts, server
}

func TestTokenSource_CachesToken(t *testing.T) {
	var hits int32
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		tenant := tenantFromTokenPath(r.URL.Path)
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
			AccessToken: "tok-" + tenant,
			ExpiresIn:   3600,
		})
	})

	ctx := context.Background()
	tok1, err := ts.Token(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	tok2, err := ts.Token(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if tok1 != tok2 {
		t.Errorf("cached token changed between calls: %q vs %q", tok1, tok2)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (second call should be served from cache)", got)
	}
}

func TestTokenSource_RefreshesAfterExpiry(t *testing.T) {
	var hits int32
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
			AccessToken: fmt.Sprintf("tok-%d", n),
			ExpiresIn:   180, // 3 minutes; expirySkew is 2 minutes, so this is
			// long enough to be cached on first fetch but stale well within
			// a small simulated clock advance.
		})
	})

	clock := time.Now()
	ts.now = func() time.Time { return clock }

	ctx := context.Background()
	first, err := ts.Token(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 hit after first fetch, got %d", got)
	}

	// Still well inside the cache window: no refetch.
	clock = clock.Add(30 * time.Second)
	if _, err := ts.Token(ctx, "tenant-a"); err != nil {
		t.Fatalf("Token within cache window: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected still 1 hit inside cache window, got %d", got)
	}

	// Past expires_in - skew (180s - 120s = 60s): must refetch.
	clock = clock.Add(2 * time.Minute)
	second, err := ts.Token(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Token after skew window: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 hits after skew window elapsed, got %d", got)
	}
	if first == second {
		t.Error("expected a new token value after refresh")
	}
}

func TestTokenSource_ClassifiesTokenErrors(t *testing.T) {
	tests := []struct {
		name    string
		codes   []int
		wantErr error
	}{
		{"tenant not found", []int{90002}, ErrTenantNotFound},
		{"tenant id malformed", []int{900023}, ErrTenantNotFound},
		{"consent missing", []int{65001}, ErrConsentRequired},
		{"app not found in tenant (unconsented)", []int{700016}, ErrConsentRequired},
		{"invalid assertion signature", []int{700027}, ErrCertificateInvalid},
		{"assertion time range invalid", []int{700024}, ErrCertificateInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(tokenErrorResponse{
					Error:            "invalid_client",
					ErrorDescription: "AADSTS" + fmt.Sprint(tt.codes[0]) + ": simulated failure",
					ErrorCodes:       tt.codes,
				})
			})

			_, err := ts.Token(context.Background(), "tenant-a")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tt.wantErr)
			}
			var tokErr *TokenError
			if !errors.As(err, &tokErr) {
				t.Errorf("expected *TokenError, got %T", err)
			}
		})
	}
}

func TestTokenSource_CertificateExpiredFailsWithoutNetworkCall(t *testing.T) {
	var hits int32
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	})
	// Overwrite the fixture cert with one that already expired.
	ts.Cert = generateTestCertificate(t, time.Now().Add(-time.Hour))

	_, err := ts.Token(context.Background(), "tenant-a")
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if !errors.Is(err, ErrCertificateInvalid) {
		t.Errorf("errors.Is(err, ErrCertificateInvalid) = false, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expired certificate should fail locally without a network call, got %d calls", got)
	}
}

func TestTokenSource_Throttled(t *testing.T) {
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := ts.Token(context.Background(), "tenant-a")
	if err == nil {
		t.Fatal("expected throttled error")
	}
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("errors.Is(err, ErrThrottled) = false, got %v", err)
	}
	var te *ThrottledError
	if !errors.As(err, &te) {
		t.Fatalf("expected *ThrottledError, got %T", err)
	}
	if te.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter = %v, want 7s", te.RetryAfter)
	}
}

// TestTokenSource_TenantIsolation is the "adding a second tenant needs
// exactly one config row" proof: two tenants get independently cached
// tokens from the same TokenSource/certificate, and expiring one's cache
// entry does not disturb the other's.
func TestTokenSource_TenantIsolation(t *testing.T) {
	var hitsA, hitsB int32
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		tenant := tenantFromTokenPath(r.URL.Path)
		var n int32
		switch tenant {
		case "tenant-a":
			n = atomic.AddInt32(&hitsA, 1)
		case "tenant-b":
			n = atomic.AddInt32(&hitsB, 1)
		default:
			t.Errorf("unexpected tenant in request path: %s", tenant)
		}
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
			AccessToken: fmt.Sprintf("tok-%s-%d", tenant, n),
			ExpiresIn:   180,
		})
	})

	clock := time.Now()
	ts.now = func() time.Time { return clock }

	ctx := context.Background()

	// Fetch tenant-a at t0 (expiresAt = t0+180s).
	tokA1, err := ts.Token(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("tenant-a first fetch: %v", err)
	}

	// Fetch tenant-b later, at t0+100s (expiresAt = t0+280s), so the two
	// tenants' expiry windows are deliberately offset — this is what makes
	// isolation observable instead of both happening to expire together.
	clock = clock.Add(100 * time.Second)
	tokB1, err := ts.Token(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("tenant-b first fetch: %v", err)
	}
	if tokA1 == tokB1 {
		t.Fatal("distinct tenants must not share a cached token value")
	}

	// Advance to t0+140s: tenant-a's refresh threshold (expiresAt-skew =
	// t0+60s) has passed, but tenant-b's (t0+160s) has not.
	clock = clock.Add(40 * time.Second)

	if _, err := ts.Token(ctx, "tenant-a"); err != nil {
		t.Fatalf("tenant-a refetch: %v", err)
	}
	if got := atomic.LoadInt32(&hitsA); got != 2 {
		t.Errorf("tenant-a should have refetched, hits = %d, want 2", got)
	}

	// tenant-b's cache entry must be untouched by tenant-a's refresh.
	tokB2, err := ts.Token(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("tenant-b second call: %v", err)
	}
	if tokB1 != tokB2 {
		t.Error("tenant-b's cached token changed even though only tenant-a's window expired (state bled across tenants)")
	}
	if got := atomic.LoadInt32(&hitsB); got != 1 {
		t.Errorf("tenant-b should still have only 1 hit, got %d", got)
	}
}

func TestTokenSource_ConcurrentTenantsAreIndependent(t *testing.T) {
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		tenant := tenantFromTokenPath(r.URL.Path)
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
			AccessToken: "tok-" + tenant,
			ExpiresIn:   3600,
		})
	})

	tenants := []string{"tenant-a", "tenant-b", "tenant-c", "tenant-d"}
	var wg sync.WaitGroup
	errs := make([]error, len(tenants))
	for i, tenant := range tenants {
		wg.Add(1)
		go func(i int, tenant string) {
			defer wg.Done()
			_, err := ts.Token(context.Background(), tenant)
			errs[i] = err
		}(i, tenant)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("tenant %s: %v", tenants[i], err)
		}
	}
}

// TestTokenSource_RejectsPathUnsafeTenantID guards fetchToken's raw string
// concatenation into the token endpoint URL: a tenant id carrying a path
// separator or similar would silently reshape the request instead of
// failing loudly. No real Entra tenant id (a GUID or verified domain name)
// ever contains these characters.
func TestTokenSource_RejectsPathUnsafeTenantID(t *testing.T) {
	var hits int32
	ts, _ := newTestTokenSource(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{AccessToken: "tok", ExpiresIn: 3600})
	})

	cases := []string{
		"tenant/../other",
		"tenant?admin=1",
		"tenant#fragment",
		"tenant\\backslash",
		" tenant-with-leading-space",
		"tenant-with-trailing-space ",
	}
	for _, tenantID := range cases {
		t.Run(tenantID, func(t *testing.T) {
			_, err := ts.Token(context.Background(), tenantID)
			if err == nil {
				t.Fatalf("Token(%q) succeeded, want an error", tenantID)
			}
		})
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("token endpoint was hit %d times for rejected tenant ids, want 0", got)
	}
}
