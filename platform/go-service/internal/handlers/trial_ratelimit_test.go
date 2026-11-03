package handlers

// PAT-2529: DB-free checks for the POST /v1/trial/provision limiters. The same
// limits driven through the real router, with a counter on database attempts,
// are in cmd/patched-api/trial_provision_ratelimit_test.go.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func trialReq(cfIP string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", strings.NewReader("{}"))
	if cfIP != "" {
		r.Header.Set("CF-Connecting-IP", cfIP)
	}
	return r
}

func TestCloudflareClientIP(t *testing.T) {
	for _, tc := range []struct{ name, header, want string }{
		{"ipv4", "203.0.113.7", "203.0.113.7"},
		{"ipv4 with padding", "  203.0.113.7 ", "203.0.113.7"},
		{"ipv6 keyed on its /64", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"two hosts in one /64 share a key", "2001:db8:1:2:1111:2222:3333:4444", "2001:db8:1:2::/64"},
		{"ipv4 mapped into ipv6", "::ffff:203.0.113.7", "203.0.113.7"},
		{"absent", "", ""},
		{"not an address", "not-an-ip", ""},
		{"address with a port", "203.0.113.7:443", ""},
		{"list", "203.0.113.7, 198.51.100.1", ""},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.header != "" {
			r.Header.Set("CF-Connecting-IP", tc.header)
		}
		if got := cloudflareClientIP(r); got != tc.want {
			t.Errorf("%s: cloudflareClientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Only CF-Connecting-IP is read, and RemoteAddr is not: chi's RealIP rewrites
// it from headers a client controls.
func TestTrialProvisionClientKeyIgnoresClientControlledAddresses(t *testing.T) {
	r := trialReq("203.0.113.7")
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	r.Header.Set("X-Real-IP", "192.0.2.2")
	r.Header.Set("True-Client-IP", "192.0.2.3")
	r.RemoteAddr = "192.0.2.4:5555"
	if got := trialProvisionClientKey(r); got != "ip:203.0.113.7" {
		t.Fatalf("key = %q, want the CF-Connecting-IP bucket", got)
	}

	// With no usable CF-Connecting-IP those same headers must not pick a bucket.
	r = trialReq("")
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	r.Header.Set("X-Real-IP", "192.0.2.2")
	r.Header.Set("True-Client-IP", "192.0.2.3")
	r.RemoteAddr = "192.0.2.4:5555"
	if got := trialProvisionClientKey(r); got != trialProvisionUnattributedKey {
		t.Fatalf("key = %q, want the shared unattributed bucket", got)
	}
}

func TestTrialProvisionLimitsPerClientAndGlobal(t *testing.T) {
	l := NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 2, GlobalPerHour: 3})

	for i := 0; i < 2; i++ {
		if ok, _, _ := l.Allow(trialReq("203.0.113.1")); !ok {
			t.Fatalf("client A request %d refused, want permitted", i+1)
		}
	}
	ok, retry, scope := l.Allow(trialReq("203.0.113.1"))
	if ok || scope != "client" {
		t.Fatalf("client A third request: ok=%v scope=%q, want refused by the client bucket", ok, scope)
	}
	// 2 per hour refills one token every 30 minutes.
	if retry <= 0 || retry > 30*time.Minute {
		t.Fatalf("client retry = %v, want within (0, 30m]", retry)
	}

	if ok, _, _ := l.Allow(trialReq("203.0.113.2")); !ok {
		t.Fatal("client B refused, want permitted (global has one token left)")
	}
	ok, retry, scope = l.Allow(trialReq("203.0.113.3"))
	if ok || scope != "global" {
		t.Fatalf("client C: ok=%v scope=%q, want refused by the global bucket", ok, scope)
	}
	// 3 per hour refills one token every 20 minutes.
	if retry < time.Second || retry > 20*time.Minute {
		t.Fatalf("global retry = %v, want within [1s, 20m]", retry)
	}
}

// Order matters: a client refused by its own bucket must not spend the global
// one, or a single address could lock every other customer out.
func TestTrialProvisionLimitsRefusedClientDoesNotChargeGlobal(t *testing.T) {
	l := NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 1, GlobalPerHour: 3})
	for i := 0; i < 50; i++ {
		l.Allow(trialReq("203.0.113.1"))
	}
	for _, ip := range []string{"203.0.113.2", "203.0.113.3"} {
		if ok, _, scope := l.Allow(trialReq(ip)); !ok {
			t.Fatalf("%s refused (%s) after another client hammered the route", ip, scope)
		}
	}
	if ok, _, scope := l.Allow(trialReq("203.0.113.4")); ok || scope != "global" {
		t.Fatalf("fourth client: ok=%v scope=%q, want the global bucket to be spent by exactly three permitted requests", ok, scope)
	}
}

// With the global bucket empty a request is refused without creating or
// charging a per-client entry, so a spray of distinct addresses cannot grow
// the per-client map.
func TestTrialProvisionLimitsEmptyGlobalLeavesPerClientUntouched(t *testing.T) {
	l := NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 1, GlobalPerHour: 1})
	if ok, _, _ := l.Allow(trialReq("203.0.113.1")); !ok {
		t.Fatal("first request refused")
	}
	// A one-token client bucket reads Blocked once it has been charged.
	if !l.perIP.Blocked("ip:203.0.113.1") {
		t.Fatal("test premise: a charged client bucket should read as blocked")
	}
	if ok, _, scope := l.Allow(trialReq("203.0.113.9")); ok || scope != "global" {
		t.Fatalf("second client: ok=%v scope=%q, want refused by the global bucket", ok, scope)
	}
	if l.perIP.Blocked("ip:203.0.113.9") {
		t.Fatal("a request refused by the empty global bucket still charged a per-client bucket")
	}
}

// A request with no usable client address does not escape the per-client
// limit; all such requests share one allowance.
func TestTrialProvisionLimitsUnattributedRequestsShareOneBucket(t *testing.T) {
	l := NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 2, GlobalPerHour: 100})
	for i := 0; i < 2; i++ {
		r := trialReq("")
		r.RemoteAddr = "192.0.2." + strconv.Itoa(i+1) + ":1000"
		if ok, _, _ := l.Allow(r); !ok {
			t.Fatalf("unattributed request %d refused", i+1)
		}
	}
	r := trialReq("not-an-ip")
	r.RemoteAddr = "192.0.2.77:1000"
	if ok, _, scope := l.Allow(r); ok || scope != "client" {
		t.Fatalf("third unattributed request: ok=%v scope=%q, want refused by the shared client bucket", ok, scope)
	}
}

// A count that is not positive must not mean "unlimited".
func TestTrialProvisionLimitsDefaults(t *testing.T) {
	l := NewTrialProvisionLimits(TrialProvisionLimitsConfig{})
	permitted := 0
	for i := 0; i < DefaultTrialProvisionPerIPPerHour+3; i++ {
		if ok, _, _ := l.Allow(trialReq("203.0.113.1")); ok {
			permitted++
		}
	}
	if permitted != DefaultTrialProvisionPerIPPerHour {
		t.Fatalf("zero config let %d requests through for one client, want the default of %d", permitted, DefaultTrialProvisionPerIPPerHour)
	}
	if DefaultTrialProvisionPerIPPerHour != 5 || DefaultTrialProvisionGlobalPerHour != 30 {
		t.Fatalf("defaults are %d and %d, want 5 and 30", DefaultTrialProvisionPerIPPerHour, DefaultTrialProvisionGlobalPerHour)
	}
	g := NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 1000})
	permitted = 0
	for i := 0; i < DefaultTrialProvisionGlobalPerHour+5; i++ {
		if ok, _, _ := g.Allow(trialReq("198.51.100." + strconv.Itoa(i+1))); ok {
			permitted++
		}
	}
	if permitted != DefaultTrialProvisionGlobalPerHour {
		t.Fatalf("zero global config let %d requests through, want the default of %d", permitted, DefaultTrialProvisionGlobalPerHour)
	}
}

// failOnRead is a request body that records whether anything read it.
type failOnRead struct{ read bool }

func (f *failOnRead) Read([]byte) (int, error) { f.read = true; return 0, http.ErrBodyReadAfterClose }
func (f *failOnRead) Close() error             { return nil }

// A refused request is answered before its body is touched, and before the
// pool is (the pool here is nil, and would panic if reached).
func TestTrialProvisionHandlerRefusesBeforeReadingBody(t *testing.T) {
	h := TrialProvisionHandler(nil, NewTrialProvisionLimits(TrialProvisionLimitsConfig{PerIPPerHour: 1, GlobalPerHour: 100}))

	first := trialReq("203.0.113.1")
	first.Body = http.NoBody
	h.ServeHTTP(httptest.NewRecorder(), first) // spends the one allowance (400: empty body)

	body := &failOnRead{}
	r := trialReq("203.0.113.1")
	r.Body = body
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	if body.read {
		t.Fatal("a refused request had its body read")
	}
	if n, err := strconv.Atoi(rr.Header().Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive number of seconds", rr.Header().Get("Retry-After"))
	}
	if got := rr.Body.String(); !strings.Contains(got, `"error":"rate_limited"`) {
		t.Fatalf("body %q, want the rate_limited JSON error", got)
	}
}

func TestTrialProvisionHandlerFailsClosedWithoutLimits(t *testing.T) {
	rr := httptest.NewRecorder()
	TrialProvisionHandler(nil, nil).ServeHTTP(rr, trialReq("203.0.113.1"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 with no limiter", rr.Code)
	}
}
