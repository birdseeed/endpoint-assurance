package handlers

// PAT-2145: DB-free checks for the Jamf webhook's authentication. The end to
// end ingest, PII, rotation, rate limit and bucket tests are in
// integration/jamf_webhook_test.go.

import (
	"context"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/jamfcoverage"
)

func TestJamfTokenMatches(t *testing.T) {
	stored := sha256.Sum256([]byte("pjwh_right"))
	cases := []struct {
		name      string
		stored    []byte
		presented string
		want      bool
	}{
		{"right token", stored[:], "pjwh_right", true},
		{"wrong token", stored[:], "pjwh_wrong", false},
		{"empty token", stored[:], "", false},
		{"no stored hash (unknown or revoked)", nil, "pjwh_right", false},
		{"the dummy hash's own preimage never authenticates", nil, "patched-jamf-webhook-no-such-connector", false},
		{"short stored hash", []byte{1, 2, 3}, "pjwh_right", false},
	}
	for _, c := range cases {
		if got := jamfTokenMatches(c.stored, c.presented); got != c.want {
			t.Errorf("%s: jamfTokenMatches = %v, want %v", c.name, got, c.want)
		}
	}
}

// The token compare must be constant time: jamfTokenMatches calls
// subtle.ConstantTimeCompare, and nothing in the webhook file compares
// bytes with bytes.Equal or reflect.DeepEqual.
func TestJamfTokenCompareIsConstantTime(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "jamf_webhook.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var sawCT bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, _ := sel.X.(*ast.Ident)
			if pkg == nil {
				return true
			}
			name := pkg.Name + "." + sel.Sel.Name
			if name == "subtle.ConstantTimeCompare" && fn.Name.Name == "jamfTokenMatches" {
				sawCT = true
			}
			if name == "bytes.Equal" || name == "reflect.DeepEqual" {
				t.Errorf("%s uses %s; token comparison must be constant time", fn.Name.Name, name)
			}
			return true
		})
		return false
	})
	if !sawCT {
		t.Fatal("jamfTokenMatches does not call subtle.ConstantTimeCompare")
	}
}

func TestJamfPresentedToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer pjwh_abc")
	if got := jamfPresentedToken(r); got != "pjwh_abc" {
		t.Errorf("bearer = %q", got)
	}
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	r.SetBasicAuth("jamf", "pjwh_basic")
	if got := jamfPresentedToken(r); got != "pjwh_basic" {
		t.Errorf("basic = %q", got)
	}
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	if got := jamfPresentedToken(r); got != "" {
		t.Errorf("none = %q", got)
	}
}

func TestJamfWebhookFailsClosedWithoutPoolOrLimiter(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"nil pool":    JamfWebhookHandler(nil, NewJamfWebhookLimits(JamfWebhookLimitsConfig{TenantRPM: 10, TenantBurst: 10})),
		"nil limiter": JamfWebhookHandler(nil, nil),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/webhooks/jamf/x", strings.NewReader("{}")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d, want 503", name, rec.Code)
		}
	}
}

func TestJamfPickTarget(t *testing.T) {
	s := func(v string) *string { return &v }
	n := func(v int64) *int64 { return &v }
	cands := []jamfDeviceRow{
		{id: 1, jamfID: n(9)},
		{id: 2, udidNorm: s("AAAAAAAA-1111-2222-3333-444444444444"), serialNorm: s("OTHERSERIAL")},
		{id: 3, serialNorm: s("C02SERIAL01")},
	}
	pick := func(ev jamfcoverage.Event) int64 {
		if p := jamfPickTarget(cands, ev); p != nil {
			return p.id
		}
		return 0
	}
	if got := pick(jamfcoverage.Event{SerialNormalized: "C02SERIAL01", JamfID: n(9)}); got != 3 {
		t.Errorf("serial wins: got %d", got)
	}
	// A UDID match whose real serial differs from the event's is another Mac.
	if got := pick(jamfcoverage.Event{SerialNormalized: "NEWSERIAL01", UDIDNormalized: "AAAAAAAA-1111-2222-3333-444444444444"}); got != 0 {
		t.Errorf("conflicting serial matched: got %d", got)
	}
	if got := pick(jamfcoverage.Event{UDIDNormalized: "AAAAAAAA-1111-2222-3333-444444444444"}); got != 2 {
		t.Errorf("udid fallback: got %d", got)
	}
	if got := pick(jamfcoverage.Event{JamfID: n(9)}); got != 1 {
		t.Errorf("jamf id fallback: got %d", got)
	}
}

func TestJamfClientIPKeysIPv6OnSlash64(t *testing.T) {
	key := func(h string) string {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("CF-Connecting-IP", h)
		return jamfClientIP(r)
	}
	if a, b := key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb:cccc:dddd:9"); a != b || a != "2001:db8:1:2::/64" {
		t.Errorf("same /64 keyed apart: %q %q", a, b)
	}
	if key("2001:db8:1:3::1") == key("2001:db8:1:2::1") {
		t.Error("different /64s share a key")
	}
	if got := key("203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("IPv4 key = %q", got)
	}
	if got := key("::ffff:203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("mapped IPv4 key = %q", got)
	}
	if got := key("not-an-ip"); got != "" {
		t.Errorf("garbage key = %q", got)
	}
}

func TestJamfSeedWithRetry(t *testing.T) {
	ctx := context.Background()
	calls := 0
	flaky := func(context.Context) error {
		calls++
		if calls < 4 {
			return errors.New("db not ready")
		}
		return nil
	}
	if err := jamfSeedWithRetry(ctx, flaky, 5, time.Millisecond); err != nil || calls != 4 {
		t.Fatalf("recovering seed: err %v after %d calls, want nil after 4", err, calls)
	}
	calls = 0
	down := func(context.Context) error { calls++; return errors.New("db down") }
	if err := jamfSeedWithRetry(ctx, down, 5, time.Millisecond); err == nil || calls != 5 {
		t.Fatalf("failing seed: err %v after %d calls, want an error after 5", err, calls)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	if err := jamfSeedWithRetry(cctx, down, 5, time.Hour); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled seed: err %v after %d calls", err, calls)
	}
	// The production schedule stays around ten seconds in all.
	total, d := time.Duration(0), jamfSeedFirstDelay
	for i := 0; i < jamfSeedTries-1; i++ {
		total += d
		d *= 2
	}
	if total < 5*time.Second || total > 15*time.Second {
		t.Fatalf("seed backoff totals %v, want about 10s", total)
	}
}

func TestJamfConnectorIssuedAndRevokedUpdateLiveCaches(t *testing.T) {
	a := NewJamfWebhookLimits(JamfWebhookLimitsConfig{TenantRPM: 1, TenantBurst: 1})
	b := NewJamfWebhookLimits(JamfWebhookLimitsConfig{TenantRPM: 1, TenantBurst: 1})
	id := "cacheTEST0123456789abcdefghijklm"
	h := sha256.Sum256([]byte("pjwh_new"))
	jamfConnectorIssued(id, h[:])
	for name, l := range map[string]*JamfWebhookLimits{"a": a, "b": b} {
		if got, ok := l.cache.get(id); !ok || string(got) != string(h[:]) {
			t.Fatalf("%s: issued hash not cached", name)
		}
	}
	jamfConnectorRevoked(id)
	for name, l := range map[string]*JamfWebhookLimits{"a": a, "b": b} {
		if _, ok := l.cache.get(id); ok {
			t.Fatalf("%s: revoked ID still cached", name)
		}
	}
}
