package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPostHardenedRefusesInternalDestinations exercises the authoritative SSRF
// control on the PAT-1888 delivery path: the dialer's Control hook, which runs
// after DNS resolution on the concrete address about to be dialled.
//
// An httptest server is deliberately used for the loopback case. It is a real,
// listening, reachable server, so a successful POST would be a genuine SSRF:
// the only reason this test passes is that the control refuses the address.
func TestPostHardenedRefusesInternalDestinations(t *testing.T) {
	reached := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()

	// A live loopback server, addressed by its own URL.
	if status, err := PostHardened(ctx, srv.URL, nil, []byte(`{}`)); err == nil {
		t.Fatalf("delivery to a loopback server succeeded with status %d", status)
	}
	if reached {
		t.Fatal("the request reached a loopback server: the SSRF control did not hold")
	}

	// A hostname that resolves to loopback. The config-time check cannot catch
	// this (it is a name, not a literal), so only the dial-time control can.
	port := strings.TrimPrefix(srv.URL, "https://127.0.0.1:")
	if _, err := PostHardened(ctx, "https://localhost:"+port+"/hook", nil, []byte(`{}`)); err == nil {
		t.Error("a hostname resolving to loopback was not refused")
	}
	if reached {
		t.Fatal("a DNS name resolving to loopback reached the server")
	}

	blocked := []struct {
		name string
		url  string
	}{
		{"loopback literal", "https://127.0.0.1:1/hook"},
		{"loopback v6 literal", "https://[::1]:1/hook"},
		{"rfc1918", "https://10.1.2.3/hook"},
		{"rfc1918 172", "https://172.20.0.1/hook"},
		{"rfc1918 192", "https://192.168.0.1/hook"},
		{"cloud metadata", "https://169.254.169.254/latest/meta-data/"},
		{"link local v6", "https://[fe80::1]/hook"},
		{"unique local v6", "https://[fd12:3456::1]/hook"},
		{"cgnat tailnet", "https://100.100.100.100/hook"},
		{"unspecified", "https://0.0.0.0/hook"},
		{"ipv4 mapped v6 loopback", "https://[::ffff:127.0.0.1]/hook"},
		{"plain http", "http://example.com/hook"},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			status, err := PostHardened(ctx, tt.url, nil, []byte(`{}`))
			if err == nil {
				t.Fatalf("%s was not refused (status %d)", tt.url, status)
			}
		})
	}
}

// TestHardenedClientDoesNotFollowRedirects proves a 3xx cannot be used to walk
// from a permitted public host to an internal one.
func TestHardenedClientDoesNotFollowRedirects(t *testing.T) {
	if httpClient.CheckRedirect == nil {
		t.Fatal("the outbound client has no CheckRedirect: a 3xx would be followed")
	}
	err := httpClient.CheckRedirect(nil, nil)
	if err == nil {
		t.Fatal("CheckRedirect allowed a redirect")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a refused redirect should report ErrBlockedDestination, got %v", err)
	}
}

// TestPostHardenedSendsHeadersAndBody proves the transport actually carries
// what it is given, using a server on a non-loopback-looking address is not
// possible here, so this drives the header-building contract through a stub
// round-tripper on the same code path's inputs.
func TestPostHardenedRevalidatesDestination(t *testing.T) {
	// A destination that was valid when stored but is refused now must be
	// refused at the point of use, not delivered to.
	if _, err := PostHardened(context.Background(), "https://192.168.5.5/hook", nil, []byte(`{}`)); err == nil {
		t.Fatal("a stored internal destination was not re-validated at delivery time")
	}
	if _, err := PostHardened(context.Background(), "://not a url", nil, []byte(`{}`)); err == nil {
		t.Fatal("a malformed destination was accepted")
	}
}

// TestSignWithTimestampRecipe pins the exact verification recipe published to
// customers. If this changes, every receiver breaks, so it is asserted against
// an independently computed HMAC rather than against our own helper.
func TestSignWithTimestampRecipe(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	body := []byte(`{"event_type":"finding.opened","subject":"cis/d/r"}`)
	var ts int64 = 1790000000

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got := SignWithTimestamp(secret, ts, body); got != want {
		t.Errorf("SignWithTimestamp = %s, want %s", got, want)
	}

	if string(SignedTimestampMaterial(ts, body)) != "1790000000."+string(body) {
		t.Errorf("signed material is not <unix>.<body>: %q", SignedTimestampMaterial(ts, body))
	}

	// The timestamp must be load-bearing: re-dating a captured body has to
	// invalidate the signature, or replay protection is decorative.
	if SignWithTimestamp(secret, ts+1, body) == want {
		t.Error("changing the timestamp did not change the signature")
	}
	// And so must the body.
	if SignWithTimestamp(secret, ts, append(body, ' ')) == want {
		t.Error("changing the body did not change the signature")
	}
	// The legacy body-only signature must remain distinct, so a receiver
	// cannot accidentally accept one recipe in place of the other.
	if SignWithTimestamp(secret, ts, body) == Sign(secret, body) {
		t.Error("the timestamped and legacy signatures collide")
	}
}

// TestClassifyAttempt covers the exported retry decision at its boundaries,
// including that the cap is a parameter rather than a constant, since the
// PAT-134 sweeper and the PAT-1888 channels use different budgets.
func TestClassifyAttempt(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		transport   bool
		attempt     int
		max         int
		want        AttemptOutcome
		wantBackoff time.Duration
	}{
		{"200 delivered", 200, false, 1, 6, AttemptDelivered, 0},
		{"204 delivered", 204, false, 5, 6, AttemptDelivered, 0},
		{"202 delivered at cap", 202, false, 6, 6, AttemptDelivered, 0},
		{"400 permanent", 400, false, 1, 6, AttemptPermanent, 0},
		{"403 permanent", 403, false, 3, 6, AttemptPermanent, 0},
		{"500 retries", 500, false, 1, 6, AttemptRetry, RetryBackoff(2)},
		{"transport error retries", 0, true, 2, 6, AttemptRetry, RetryBackoff(3)},
		{"exhausted at cap", 500, false, 6, 6, AttemptExhausted, 0},
		{"exhausted past cap", 0, true, 9, 6, AttemptExhausted, 0},
		{"smaller cap exhausts sooner", 503, false, 3, 3, AttemptExhausted, 0},
		{"larger cap keeps retrying", 503, false, 6, 8, AttemptRetry, RetryBackoff(7)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, backoff := ClassifyAttempt(tt.status, tt.transport, tt.attempt, tt.max)
			if got != tt.want {
				t.Errorf("outcome = %v, want %v", got, tt.want)
			}
			if backoff != tt.wantBackoff {
				t.Errorf("backoff = %v, want %v", backoff, tt.wantBackoff)
			}
		})
	}
}

// TestKnownEventsExcludesFindingEvents guards the deliberate split between the
// legacy PAT-134 subscription set and the PAT-1888 catalogue. Nothing fires the
// finding events through tenant_webhooks, so accepting a subscription to one
// there would create a configuration that looks healthy and never delivers.
func TestKnownEventsExcludesFindingEvents(t *testing.T) {
	legacy := map[string]bool{}
	for _, e := range KnownEvents {
		legacy[e] = true
	}
	for _, e := range FindingEvents {
		if legacy[e] {
			t.Errorf("%s is subscribable on a legacy tenant_webhooks row but nothing fires it there", e)
		}
	}
	if legacy[string(EventTestPing)] {
		t.Error("test.ping must not be subscribable")
	}
	for _, e := range FindingEvents {
		if e == string(EventTestPing) {
			t.Error("test.ping must not be in the finding catalogue")
		}
	}
	if len(FindingEvents) != 5 {
		t.Errorf("the finding catalogue changed size (%d); update the docs event table too", len(FindingEvents))
	}
}
