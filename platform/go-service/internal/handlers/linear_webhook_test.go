package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const linearWebhookTestSecret = "low-entropy-unit-test-secret"

func signedLinearWebhookRequest(t *testing.T, body string, now time.Time) *http.Request {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(linearWebhookTestSecret))
	_, _ = mac.Write([]byte(body))
	r := httptest.NewRequest(http.MethodPost, "/public/linear-webhook", strings.NewReader(body))
	r.Header.Set("Linear-Signature", hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("Linear-Delivery", "234d1a4e-b617-4388-90fe-adc3633d6b72")
	r.Header.Set("Linear-Event", "Issue")
	return r
}

func webhookBody(now time.Time, action, typ string) string {
	return fmt.Sprintf(`{"action":%q,"type":%q,"webhookTimestamp":%d,"data":{"id":"issue-1","updatedAt":"2026-09-27T12:00:00Z","state":{"name":"Done"},"labels":[]}}`, action, typ, now.UnixMilli())
}

func TestLinearWebhookSecretUnsetFailsClosed(t *testing.T) {
	w := httptest.NewRecorder()
	linearWebhookHandler(nil, "", time.Now)(w, httptest.NewRequest(http.MethodPost, "/public/linear-webhook", strings.NewReader(`not JSON`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", w.Code)
	}
}

func TestLinearWebhookAuthenticatesExactRawBodyBeforeJSON(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, body, signature string
		want                  int
	}{
		{"missing signature", webhookBody(now, "update", "Issue"), "", http.StatusUnauthorized},
		{"malformed signature", webhookBody(now, "update", "Issue"), "not-hex", http.StatusUnauthorized},
		{"wrong signature", webhookBody(now, "update", "Issue"), strings.Repeat("00", sha256.Size), http.StatusUnauthorized},
		{"invalid JSON but correctly signed", `{`, "signed", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := signedLinearWebhookRequest(t, tc.body, now)
			if tc.signature != "signed" {
				r.Header.Set("Linear-Signature", tc.signature)
			}
			w := httptest.NewRecorder()
			linearWebhookHandler(nil, linearWebhookTestSecret, func() time.Time { return now })(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestLinearWebhookTimestampWindowPastAndFuture(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{-60*time.Second - time.Millisecond, 60*time.Second + time.Millisecond} {
		body := webhookBody(now.Add(offset), "update", "Issue")
		w := httptest.NewRecorder()
		linearWebhookHandler(nil, linearWebhookTestSecret, func() time.Time { return now })(w, signedLinearWebhookRequest(t, body, now))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("offset %s status=%d want 401", offset, w.Code)
		}
	}
	for _, offset := range []time.Duration{-60 * time.Second, 60 * time.Second} {
		body := webhookBody(now.Add(offset), "create", "Issue")
		w := httptest.NewRecorder()
		linearWebhookHandler(nil, linearWebhookTestSecret, func() time.Time { return now })(w, signedLinearWebhookRequest(t, body, now))
		if w.Code != http.StatusOK {
			t.Errorf("boundary offset %s status=%d want 200", offset, w.Code)
		}
	}
}

func TestLinearWebhookFiltersAnythingExceptIssueUpdate(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ header, typ, action string }{
		{"Comment", "Issue", "update"}, {"Issue", "Comment", "update"}, {"Issue", "Issue", "create"}, {"Issue", "Issue", "remove"},
	} {
		body := webhookBody(now, tc.action, tc.typ)
		r := signedLinearWebhookRequest(t, body, now)
		r.Header.Set("Linear-Event", tc.header)
		w := httptest.NewRecorder()
		linearWebhookHandler(nil, linearWebhookTestSecret, func() time.Time { return now })(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%+v status=%d want 200", tc, w.Code)
		}
	}
}

func TestLinearWebhookBoundsBody(t *testing.T) {
	now := time.Now().UTC()
	body := strings.Repeat("x", maxLinearWebhookBytes+1)
	w := httptest.NewRecorder()
	linearWebhookHandler(nil, linearWebhookTestSecret, func() time.Time { return now })(w, signedLinearWebhookRequest(t, body, now))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", w.Code)
	}
}

func TestValidLinearSignatureUsesExactBytes(t *testing.T) {
	body := []byte("{\n  \"a\": 1\n}\n")
	mac := hmac.New(sha256.New, []byte(linearWebhookTestSecret))
	_, _ = mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	if !validLinearSignature([]byte(linearWebhookTestSecret), body, sig) {
		t.Fatal("exact body rejected")
	}
	if validLinearSignature([]byte(linearWebhookTestSecret), bytes.TrimSpace(body), sig) {
		t.Fatal("normalised body accepted against exact-body signature")
	}
}

func TestLinearWebhookLabelShapesAreBounded(t *testing.T) {
	for _, raw := range []string{`[{"name":"needs-triage"}]`, `["claude-triaged"]`, `null`} {
		if _, err := linearLabelNames([]byte(raw)); err != nil {
			t.Errorf("valid labels %s: %v", raw, err)
		}
	}
	if _, err := linearLabelNames([]byte(`{"name":"not-an-array"}`)); err == nil {
		t.Fatal("invalid labels accepted")
	}
}
