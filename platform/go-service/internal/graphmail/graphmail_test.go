package graphmail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient wires a Client at a fake Entra + Graph pair. Both endpoints are
// httptest servers, so nothing in this file talks to Microsoft.
func newTestClient(t *testing.T, tokenHandler, mailHandler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	authSrv := httptest.NewServer(tokenHandler)
	graphSrv := httptest.NewServer(mailHandler)

	c, err := New(Config{
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: "super-secret-value",
		From:         "noreply@example.com",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.AuthorityBase = authSrv.URL
	c.GraphBaseURL = graphSrv.URL
	c.HTTPClient = &http.Client{Timeout: 5 * time.Second}

	return c, func() {
		authSrv.Close()
		graphSrv.Close()
	}
}

func okToken(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
}

// TestSendPostsSendMailWithBearerToken proves the whole path: acquire a token,
// then POST the Graph sendMail shape to the configured mailbox.
func TestSendPostsSendMailWithBearerToken(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any

	c, done := newTestClient(t, okToken, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	})
	defer done()

	err := c.Send(context.Background(), Message{
		To:      []string{"owner@example.com"},
		Subject: "Patched: New finding observed",
		Body:    "detail",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotPath != "/users/noreply@example.com/sendMail" {
		t.Errorf("unexpected sendMail path %q", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("unexpected authorization header %q", gotAuth)
	}
	if saved, ok := gotBody["saveToSentItems"].(bool); !ok || saved {
		t.Errorf("saveToSentItems should be false, got %v", gotBody["saveToSentItems"])
	}
	msg, _ := gotBody["message"].(map[string]any)
	if msg["subject"] != "Patched: New finding observed" {
		t.Errorf("subject not carried: %v", msg["subject"])
	}
	body, _ := msg["body"].(map[string]any)
	if body["contentType"] != "Text" {
		t.Errorf("body should be plain text, got %v", body["contentType"])
	}
}

// TestTokenIsCachedBetweenSends proves a burst of notifications does not mint a
// token per message.
func TestTokenIsCachedBetweenSends(t *testing.T) {
	tokenCalls := 0
	c, done := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		okToken(w, r)
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	defer done()

	for i := 0; i < 3; i++ {
		if err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "s", Body: "b"}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if tokenCalls != 1 {
		t.Errorf("expected one token acquisition for three sends, got %d", tokenCalls)
	}
}

// TestSendErrorsCarryNoSecret is the reason this package builds its own errors
// rather than wrapping whatever the transport returned: a Graph or Entra error
// must never carry the client secret into a log line or a stored delivery
// error.
func TestSendErrorsCarryNoSecret(t *testing.T) {
	const secret = "super-secret-value"

	t.Run("graph rejects the send", func(t *testing.T) {
		c, done := newTestClient(t, okToken, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"ErrorAccessDenied","message":"Access to OData is disabled for super-secret-value"}}`))
		})
		defer done()

		err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaked the client secret: %v", err)
		}
		var se *SendError
		if !errors.As(err, &se) {
			t.Fatalf("expected a *SendError, got %T", err)
		}
		if se.Status != http.StatusForbidden || se.Code != "ErrorAccessDenied" {
			t.Errorf("unexpected SendError %+v", se)
		}
		if se.Retriable() {
			t.Error("403 should not be retriable")
		}
	})

	t.Run("entra rejects the token request", func(t *testing.T) {
		c, done := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value super-secret-value, not the client secret ID."}`))
		}, func(w http.ResponseWriter, _ *http.Request) {
			t.Error("sendMail must not be attempted without a token")
			w.WriteHeader(http.StatusAccepted)
		})
		defer done()

		err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
		if err == nil {
			t.Fatal("expected an error")
		}

		// The operator needs to be able to tell a bad credential from a DNS
		// failure from a timeout by reading the dead-lettered delivery alone.
		msg := err.Error()
		if !strings.Contains(msg, "401") {
			t.Errorf("token error should carry the HTTP status: %v", err)
		}
		if !strings.Contains(msg, "invalid_client") {
			t.Errorf("token error should name the OAuth error code: %v", err)
		}
		if !strings.Contains(msg, "AADSTS7000215") {
			t.Errorf("token error should carry the AADSTS code: %v", err)
		}

		// And none of that may come at the cost of echoing the credential or
		// the prose around it, which Entra fills with request detail.
		if strings.Contains(msg, secret) {
			t.Errorf("token error leaked the client secret: %v", err)
		}
		if strings.Contains(msg, "Invalid client secret provided") {
			t.Errorf("token error echoed error_description prose: %v", err)
		}

		var te *TokenError
		if !errors.As(err, &te) {
			t.Fatalf("expected a *TokenError so the dispatcher can classify it as configuration, got %T", err)
		}
		if te.Retriable() {
			t.Error("a rejected credential must not be retriable: the next attempt presents the same secret")
		}
	})

	t.Run("a transport failure keeps its cause and stays retriable", func(t *testing.T) {
		c, done := newTestClient(t, okToken, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		})
		done() // close both servers so the token request cannot connect

		err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if strings.Contains(msg, secret) {
			t.Errorf("transport error leaked the client secret: %v", err)
		}
		if !strings.Contains(msg, "token request failed") {
			t.Errorf("transport error should say which request failed: %v", err)
		}
		if strings.Contains(msg, "http://127.0.0.1") {
			t.Errorf("transport error echoed the request URL: %v", err)
		}
		// Not a TokenError and not a SendError, so the dispatcher treats it as
		// a transport failure and retries rather than dead-lettering.
		var te *TokenError
		if errors.As(err, &te) {
			t.Error("a connection failure must not be classified as a credential rejection")
		}
		var se *SendError
		if errors.As(err, &se) {
			t.Error("a connection failure must not be classified as a Graph rejection")
		}
	})

	t.Run("a sendMail transport failure has an uncertain delivery outcome", func(t *testing.T) {
		c, done := newTestClient(t, okToken, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		})
		if err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "first", Body: "b"}); err != nil {
			t.Fatalf("prime token cache: %v", err)
		}
		done() // token is cached; only the sendMail request now needs the network

		err := c.Send(context.Background(), Message{To: []string{"a@example.com"}, Subject: "second", Body: "b"})
		var uncertain *DeliveryUncertainError
		if !errors.As(err, &uncertain) {
			t.Fatalf("sendMail transport error type=%T want *DeliveryUncertainError: %v", err, err)
		}
		if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "a@example.com") {
			t.Fatalf("uncertain delivery error leaked endpoint or recipient: %v", err)
		}
	})
}

// TestTokenErrorRetriability pins which token failures are worth another
// attempt. Throttling and server faults are; anything about the credential is
// not.
func TestTokenErrorRetriability(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		if !(&TokenError{Status: status}).Retriable() {
			t.Errorf("token status %d should be retriable", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404} {
		if (&TokenError{Status: status}).Retriable() {
			t.Errorf("token status %d should not be retriable", status)
		}
	}
}

// TestTokenErrorFromKeepsOnlyIdentifiers proves the parser extracts the two
// short codes and nothing else, including when the body is malformed or the
// AADSTS code appears outside error_description.
func TestTokenErrorFromKeepsOnlyIdentifiers(t *testing.T) {
	te := tokenErrorFrom(401, []byte(`{"error":"unauthorized_client","error_description":"AADSTS700016: secret sauce here"}`))
	if te.Code != "unauthorized_client" || te.AADSTS != "AADSTS700016" {
		t.Errorf("unexpected parse: %+v", te)
	}
	if strings.Contains(te.Error(), "secret sauce") {
		t.Errorf("error text echoed the description: %s", te.Error())
	}

	// Malformed body: still a usable error carrying the status.
	te = tokenErrorFrom(503, []byte(`<html>gateway timeout</html>`))
	if te.Status != 503 {
		t.Errorf("status lost on a malformed body: %+v", te)
	}
	if !strings.Contains(te.Error(), "503") {
		t.Errorf("error text should carry the status: %s", te.Error())
	}
	if strings.Contains(te.Error(), "html") {
		t.Errorf("error text echoed the raw body: %s", te.Error())
	}

	// An over-long OAuth code is truncated rather than stored whole.
	te = tokenErrorFrom(400, []byte(`{"error":"`+strings.Repeat("x", 200)+`"}`))
	if len(te.Code) != 64 {
		t.Errorf("an over-long error code should be truncated to 64 chars, got %d", len(te.Code))
	}
}

// TestRetriableClassification pins which Graph failures are worth another
// attempt.
func TestRetriableClassification(t *testing.T) {
	retriable := []int{429, 500, 502, 503, 504}
	for _, status := range retriable {
		if !(&SendError{Status: status}).Retriable() {
			t.Errorf("status %d should be retriable", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 413} {
		if (&SendError{Status: status}).Retriable() {
			t.Errorf("status %d should not be retriable", status)
		}
	}
}

// TestNewRequiresCompleteConfiguration proves a half-configured environment
// produces ErrNotConfigured up front rather than a client that looks usable and
// fails only when a real notification needs it.
func TestNewRequiresCompleteConfiguration(t *testing.T) {
	full := Config{TenantID: "t", ClientID: "c", ClientSecret: "s", From: "a@example.com"}

	partials := map[string]Config{
		"no tenant": {ClientID: "c", ClientSecret: "s", From: "a@example.com"},
		"no client": {TenantID: "t", ClientSecret: "s", From: "a@example.com"},
		"no secret": {TenantID: "t", ClientID: "c", From: "a@example.com"},
		"no sender": {TenantID: "t", ClientID: "c", ClientSecret: "s"},
		"blank":     {},
	}
	for name, cfg := range partials {
		if _, err := New(cfg); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s: expected ErrNotConfigured, got %v", name, err)
		}
	}

	bad := full
	bad.From = "not-an-address"
	if _, err := New(bad); err == nil {
		t.Error("an invalid sender address should be rejected")
	}

	if _, err := New(full); err != nil {
		t.Errorf("a complete configuration should build: %v", err)
	}

	// A nil client must still refuse rather than panic.
	var nilClient *Client
	if err := nilClient.Send(context.Background(), Message{To: []string{"a@example.com"}}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("a nil client should return ErrNotConfigured, got %v", err)
	}
}

// TestValidateRecipients bounds and checks an address list at configuration
// time, so a typo becomes a rejected request rather than a permanent
// dead-lettered delivery later.
func TestValidateRecipients(t *testing.T) {
	if err := ValidateRecipients(nil); err == nil {
		t.Error("an empty recipient list should be rejected")
	}
	if err := ValidateRecipients([]string{"a@example.com", "b@example.com"}); err != nil {
		t.Errorf("a valid list was rejected: %v", err)
	}
	if err := ValidateRecipients([]string{"a@example.com", "A@EXAMPLE.COM"}); err == nil {
		t.Error("a case-insensitive duplicate should be rejected")
	}
	if err := ValidateRecipients([]string{"nope"}); err == nil {
		t.Error("a malformed address should be rejected")
	}
	if err := ValidateRecipients([]string{"  "}); err == nil {
		t.Error("a blank address should be rejected")
	}

	tooMany := make([]string, 0, maxRecipients+1)
	for i := 0; i <= maxRecipients; i++ {
		tooMany = append(tooMany, string(rune('a'+i%26))+string(rune('a'+i/26))+"@example.com")
	}
	if err := ValidateRecipients(tooMany); err == nil {
		t.Errorf("a list of %d recipients should be rejected", len(tooMany))
	}
}
