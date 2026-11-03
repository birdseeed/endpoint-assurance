package notifications

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/webhook"
)

// fakeSender records what it was asked to send and returns a scripted error.
type fakeSender struct {
	err  error
	sent []graphmail.Message
}

func (f *fakeSender) Send(_ context.Context, msg graphmail.Message) error {
	f.sent = append(f.sent, msg)
	return f.err
}

func (f *fakeSender) From() string { return "noreply@example.com" }

// TestDeliverWebhookSignsWithTimestampAndIdempotencyKey proves the headers a
// receiver needs are all present, and that the signature actually covers the
// timestamp rather than just travelling beside it.
func TestDeliverWebhookSignsWithTimestampAndIdempotencyKey(t *testing.T) {
	var gotHeaders map[string]string
	var gotBody []byte

	d := NewDispatcher(nil, nil, WithTransport(
		func(_ context.Context, _ string, headers map[string]string, body []byte) (int, error) {
			gotHeaders, gotBody = headers, body
			return http.StatusOK, nil
		}))

	secret := []byte("0123456789abcdef")
	p := pendingDelivery{
		channelType: ChannelWebhook,
		url:         "https://hooks.example.com/patched",
		secret:      secret,
		eventType:   string(webhook.EventFindingOpened),
		idempotency: "deadbeef",
		payload:     []byte(`{"event_type":"finding.opened"}`),
	}

	res := d.deliver(context.Background(), p)
	if res.err != nil || res.status != http.StatusOK {
		t.Fatalf("expected a clean 200, got status=%d err=%v", res.status, res.err)
	}

	for _, h := range []string{"X-Patched-Event", "X-Patched-Timestamp", "X-Patched-Signature", "X-Patched-Idempotency-Key"} {
		if gotHeaders[h] == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if gotHeaders["X-Patched-Idempotency-Key"] != "deadbeef" {
		t.Errorf("idempotency header = %q", gotHeaders["X-Patched-Idempotency-Key"])
	}

	ts, err := strconv.ParseInt(gotHeaders["X-Patched-Timestamp"], 10, 64)
	if err != nil {
		t.Fatalf("timestamp header is not an integer: %v", err)
	}
	want := webhook.SignWithTimestamp(secret, ts, gotBody)
	if gotHeaders["X-Patched-Signature"] != want {
		t.Errorf("signature does not verify against the documented recipe")
	}
	// Re-signing with a different timestamp must not match, or a captured
	// delivery could be re-dated and replayed.
	if webhook.SignWithTimestamp(secret, ts+1, gotBody) == want {
		t.Error("signature does not actually cover the timestamp")
	}
}

// TestDeliverWebhookConfigurationFaultsAreTerminal proves a destination we will
// always refuse, or a channel with nothing to send to, dead-letters at once
// rather than spending the whole retry budget first.
func TestDeliverWebhookConfigurationFaultsAreTerminal(t *testing.T) {
	blocked := NewDispatcher(nil, nil, WithTransport(
		func(context.Context, string, map[string]string, []byte) (int, error) {
			return 0, webhook.ErrBlockedDestination
		}))
	res := blocked.deliver(context.Background(), pendingDelivery{
		channelType: ChannelWebhook, url: "https://rebound.example.com", secret: []byte("s"),
	})
	if !res.permanent || res.reason != ReasonUndeliverable {
		t.Errorf("a blocked destination should be terminal, got permanent=%v reason=%q", res.permanent, res.reason)
	}

	unconfigured := NewDispatcher(nil, nil)
	res = unconfigured.deliver(context.Background(), pendingDelivery{
		channelType: ChannelWebhook, url: "", secret: nil,
	})
	if !res.permanent || res.reason != ReasonUndeliverable {
		t.Errorf("a webhook channel with no destination should be terminal, got %+v", res)
	}
}

// TestDeliverWebhookTransportErrorIsRetriable proves an ordinary network fault
// is not treated as a configuration fault.
func TestDeliverWebhookTransportErrorIsRetriable(t *testing.T) {
	d := NewDispatcher(nil, nil, WithTransport(
		func(context.Context, string, map[string]string, []byte) (int, error) {
			return 0, errors.New("dial tcp: i/o timeout")
		}))
	res := d.deliver(context.Background(), pendingDelivery{
		channelType: ChannelWebhook, url: "https://hooks.example.com", secret: []byte("s"),
	})
	if res.permanent {
		t.Error("a transport timeout should be retriable, not terminal")
	}
	if !res.transport {
		t.Error("a transport failure should be flagged as one")
	}
}

// TestStoredDeliveryErrorNeverLeaksAddress is the PAT-1956 fix: the column an
// owner reads must never carry the hostname, the resolved address or the port
// a webhook delivery dialed, whether the dial was refused by the SSRF guard or
// failed for an ordinary transport reason.
func TestStoredDeliveryErrorNeverLeaksAddress(t *testing.T) {
	// A fixture hostname resolving to a private address, exactly the PAT-1888
	// dead-letter shape found in production evidence: hostnames are accepted
	// at configuration time by design (DNS can change), so the guard only
	// catches this at dial time. This goes through the real default
	// transport (webhook.PostHardened), not a stub, so the error is the
	// genuine nested *url.Error -> *net.OpError chain Go produces, not one
	// this test hand-assembles.
	t.Run("blocked destination via real dial", func(t *testing.T) {
		d := NewDispatcher(nil, nil) // default transport: webhook.PostHardened
		res := d.deliver(context.Background(), pendingDelivery{
			channelType: ChannelWebhook, url: "https://localhost:1/hook", secret: []byte("s"),
		})
		if !errors.Is(res.err, webhook.ErrBlockedDestination) {
			t.Fatalf("expected the SSRF guard to refuse localhost, got %v", res.err)
		}
		if !res.permanent || res.reason != ReasonUndeliverable {
			t.Fatalf("a blocked destination should be terminal/undeliverable, got permanent=%v reason=%q",
				res.permanent, res.reason)
		}

		stored := storedDeliveryError(res.err)
		for _, leak := range []string{"localhost", "127.0.0.1", "::1", ":1"} {
			if strings.Contains(stored, leak) {
				t.Errorf("stored error %q leaks %q", stored, leak)
			}
		}
		if stored != ownerFacingBlockedDestination {
			t.Errorf("stored = %q, want the fixed string %q", stored, ownerFacingBlockedDestination)
		}
	})

	// Any other dial-time failure can carry the same kind of address (Go
	// wraps every dial outcome in *net.OpError with the concrete Addr it
	// tried), so it gets the same treatment even though, on its own, it
	// leaks less than an internal-range refusal.
	t.Run("ordinary dial failure", func(t *testing.T) {
		dialErr := &net.OpError{
			Op:   "dial",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 443},
			Err:  errors.New("connect: connection refused"),
		}
		d := NewDispatcher(nil, nil, WithTransport(
			func(context.Context, string, map[string]string, []byte) (int, error) {
				return 0, dialErr
			}))
		res := d.deliver(context.Background(), pendingDelivery{
			channelType: ChannelWebhook, url: "https://hooks.example.com", secret: []byte("s"),
		})
		if res.permanent {
			t.Error("an ordinary refused connection should stay retriable")
		}

		stored := storedDeliveryError(res.err)
		for _, leak := range []string{"203.0.113.5", "connection refused"} {
			if strings.Contains(stored, leak) {
				t.Errorf("stored error %q leaks %q", stored, leak)
			}
		}
		if stored != ownerFacingConnectionFailed {
			t.Errorf("stored = %q, want the fixed string %q", stored, ownerFacingConnectionFailed)
		}
	})

	// An error that cannot carry a dialed address keeps its useful detail:
	// this is the fallback to redactError, unchanged.
	t.Run("non-address error keeps its detail", func(t *testing.T) {
		stored := storedDeliveryError(errors.New("unknown channel type"))
		if stored != "unknown channel type" {
			t.Errorf("stored = %q, want the original message preserved", stored)
		}
	})

	if storedDeliveryError(nil) != "" {
		t.Error("a nil error should store nothing")
	}
}

// TestDeliverEmailUnconfiguredDeadLetters is the "degraded, not silent" case: a
// platform with no Graph mailer must record a visible failure, never quietly
// succeed or quietly do nothing.
func TestDeliverEmailUnconfiguredDeadLetters(t *testing.T) {
	d := NewDispatcher(nil, nil)
	res := d.deliver(context.Background(), pendingDelivery{
		channelType: ChannelEmail, recipients: []string{"owner@example.com"},
		payload: []byte(`{}`), eventType: string(webhook.EventFindingOpened),
	})
	if !res.permanent || res.reason != ReasonUndeliverable {
		t.Fatalf("expected a terminal undeliverable result, got %+v", res)
	}
	if !errors.Is(res.err, graphmail.ErrNotConfigured) {
		t.Errorf("the recorded error should name the missing configuration, got %v", res.err)
	}
}

// TestDeliverEmailClassifiesGraphFailures separates a throttle or server fault
// (worth retrying) from an authorisation or validation fault (not).
func TestDeliverEmailClassifiesGraphFailures(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantPermanent bool
	}{
		{"throttled is retriable", &graphmail.SendError{Status: 429, Code: "TooManyRequests"}, false},
		{"server fault is retriable", &graphmail.SendError{Status: 503, Code: "ServiceUnavailable"}, false},
		{"uncertain acceptance follows at-least-once retry policy", &graphmail.DeliveryUncertainError{}, false},
		{"forbidden is terminal", &graphmail.SendError{Status: 403, Code: "ErrorAccessDenied"}, true},
		{"bad request is terminal", &graphmail.SendError{Status: 400, Code: "ErrorInvalidRecipients"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := &fakeSender{err: tt.err}
			d := NewDispatcher(nil, sender)
			res := d.deliver(context.Background(), pendingDelivery{
				channelType: ChannelEmail, recipients: []string{"owner@example.com"},
				payload: []byte(`{}`), eventType: string(webhook.EventFindingOpened),
			})
			if res.permanent != tt.wantPermanent {
				t.Errorf("permanent = %v, want %v", res.permanent, tt.wantPermanent)
			}
			if len(sender.sent) != 1 {
				t.Fatalf("expected exactly one send attempt, got %d", len(sender.sent))
			}
		})
	}
}

// TestDeliverEmailTokenFailureIsAConfigurationFault proves a rejected mailer
// credential dead-letters as configuration rather than as a per-message
// permanent error, and without spending the retry budget: the next five
// attempts would present the same bad secret and fail identically.
func TestDeliverEmailTokenFailureIsAConfigurationFault(t *testing.T) {
	sender := &fakeSender{err: &graphmail.TokenError{
		Status: 401, Code: "invalid_client", AADSTS: "AADSTS7000215",
	}}
	d := NewDispatcher(nil, sender)
	res := d.deliver(context.Background(), pendingDelivery{
		channelType: ChannelEmail, recipients: []string{"owner@example.com"},
		payload: []byte(`{}`), eventType: string(webhook.EventFindingOpened),
	})

	if !res.permanent {
		t.Error("a rejected credential should be terminal, not retried")
	}
	if res.reason != ReasonUndeliverable {
		t.Errorf("reason = %q, want %q: a bad credential is configuration, not a message fault",
			res.reason, ReasonUndeliverable)
	}
	// The stored error must still tell the operator what to fix.
	stored := redactError(res.err)
	for _, want := range []string{"401", "invalid_client", "AADSTS7000215"} {
		if !strings.Contains(stored, want) {
			t.Errorf("the stored error should contain %q, got %q", want, stored)
		}
	}

	// A throttled token request is a different matter and stays retriable.
	throttled := &fakeSender{err: &graphmail.TokenError{Status: 429, Code: "temporarily_unavailable"}}
	res = NewDispatcher(nil, throttled).deliver(context.Background(), pendingDelivery{
		channelType: ChannelEmail, recipients: []string{"owner@example.com"},
		payload: []byte(`{}`), eventType: string(webhook.EventFindingOpened),
	})
	if res.permanent {
		t.Error("a throttled token request should be retriable")
	}
}

// TestRenderEmailNeverClaimsAFindingCleared is a product constraint, not a
// formatting preference. A stale-evidence notification that read as "resolved"
// would be Patched asserting a control is healthy on the strength of evidence
// it does not have.
func TestRenderEmailNeverClaimsAFindingCleared(t *testing.T) {
	subject, body := RenderEmail(string(webhook.EventEvidenceStale), []byte(`{"subject":"cis/dev/rule"}`))

	lower := strings.ToLower(subject + " " + body)
	for _, forbidden := range []string{"resolved", "cleared the finding", "no longer affected", "remediated"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("a stale-evidence notification must not say %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(lower, "has not been cleared") {
		t.Errorf("a stale-evidence notification must say the finding is not cleared: %s", body)
	}
	if !strings.Contains(lower, "could not be confirmed") {
		t.Errorf("a stale-evidence subject must say verification could not be confirmed: %s", subject)
	}

	// A test ping must be unmistakably synthetic.
	testSubject, testBody := RenderEmail(string(webhook.EventTestPing), []byte(`{"test":true}`))
	if !strings.Contains(strings.ToLower(testSubject+testBody), "not a finding") {
		t.Errorf("a test notification must say it is not a finding: %s / %s", testSubject, testBody)
	}

	// Every catalogued event renders something, and the event type always
	// appears so a receiver can route on it.
	for _, kind := range webhook.FindingEvents {
		s, b := RenderEmail(kind, []byte(`{}`))
		if s == "" || b == "" {
			t.Errorf("%s rendered an empty subject or body", kind)
		}
		if !strings.Contains(b, kind) {
			t.Errorf("%s body does not name its own event type", kind)
		}
	}
}

// TestRetryBudgetIsBounded pins the attempt cap and the dead-letter boundary
// that MaxAttempts enforces, so a change to either is a deliberate one.
func TestRetryBudgetIsBounded(t *testing.T) {
	for attempt := 1; attempt < MaxAttempts; attempt++ {
		outcome, backoff := webhook.ClassifyAttempt(500, false, attempt, MaxAttempts)
		if outcome != webhook.AttemptRetry {
			t.Fatalf("attempt %d of %d should retry, got %v", attempt, MaxAttempts, outcome)
		}
		if backoff <= 0 {
			t.Errorf("attempt %d scheduled a retry with no backoff", attempt)
		}
	}
	if outcome, _ := webhook.ClassifyAttempt(500, false, MaxAttempts, MaxAttempts); outcome != webhook.AttemptExhausted {
		t.Errorf("attempt %d should exhaust the budget, got %v", MaxAttempts, outcome)
	}
	if outcome, _ := webhook.ClassifyAttempt(404, false, 1, MaxAttempts); outcome != webhook.AttemptPermanent {
		t.Errorf("a 404 should be permanent on the first attempt, got %v", outcome)
	}
}

// TestBuildPayloadCarriesIdempotencyKey proves a receiver that reads only the
// body can still deduplicate, and that the key matches the header's.
func TestBuildPayloadCarriesIdempotencyKey(t *testing.T) {
	const channel = "33333333-3333-3333-3333-333333333333"
	ev := Event{
		TenantID: "44444444-4444-4444-4444-444444444444",
		Type:     webhook.EventFindingOpened,
		Subject:  "cis/device-1/rule@2026-09-20T10:00:00Z",
		Severity: SeverityHigh,
	}
	body, err := BuildPayload(channel, ev)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	want := IdempotencyKey(channel, ev.Type, ev.Subject)
	if !strings.Contains(string(body), want) {
		t.Errorf("payload does not carry its idempotency key: %s", body)
	}
	// A zero timestamp must still render a real one rather than year zero.
	if strings.Contains(string(body), `"timestamp":"0001-01-01`) {
		t.Errorf("payload carried a zero timestamp: %s", body)
	}
}
