package oscve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// discardLogger is a *slog.Logger that never writes anywhere, so retry
// tests don't spam stdout with the WARN lines that are the point of the
// retry (PAT-2039).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// noSleep is a sleep func that records the delays it was asked for and
// returns immediately, so retry tests don't wait out real backoff.
func noSleep(slept *[]time.Duration) func(context.Context, time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return nil
	}
}

func withVendorFetchLogger(t *testing.T, l *slog.Logger) {
	t.Helper()
	orig := vendorFetchLogger
	vendorFetchLogger = l
	t.Cleanup(func() { vendorFetchLogger = orig })
}

// ── 503 then 200 succeeds ───────────────────────────────────────────────────

func TestFetchWithRetryInner_TransientErrorThenSuccess(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	var slept []time.Duration
	body, err := fetchWithRetryInner(context.Background(), srv.Client(), srv.URL, "application/json", "msrc", "2015-Aug", noSleep(&slept))
	if err != nil {
		t.Fatalf("expected success after one transient error, got err: %v", err)
	}
	if calls != 2 {
		t.Errorf("handler called %d times, want 2 (1 failure + 1 success)", calls)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want the 200 payload", body)
	}
	if len(slept) != 1 {
		t.Fatalf("slept %d times, want 1", len(slept))
	}
}

// ── 429 with Retry-After then 200: respects the delay, capped ─────────────

func TestFetchWithRetryInner_RetryAfterHonouredAndCapped(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "2") // seconds
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.Client(), srv.URL, "application/json", "msrc", "2024-Jun", noSleep(&slept))
	if err != nil {
		t.Fatalf("expected success after 429, got err: %v", err)
	}
	if calls != 2 {
		t.Errorf("handler called %d times, want 2", calls)
	}
	if len(slept) != 1 {
		t.Fatalf("slept %d times, want 1", len(slept))
	}
	if slept[0] != 2*time.Second {
		t.Errorf("delay = %v, want the 2s Retry-After honoured exactly (no jitter added on top of an explicit vendor delay)", slept[0])
	}

	// A Retry-After bigger than the cap is clamped, not honoured verbatim.
	var callsBig int
	srvBig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsBig++
		if callsBig == 1 {
			w.Header().Set("Retry-After", "3600") // 1 hour — absurd
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srvBig.Close()

	var sleptBig []time.Duration
	_, err = fetchWithRetryInner(context.Background(), srvBig.Client(), srvBig.URL, "application/json", "msrc", "2024-Jul", noSleep(&sleptBig))
	if err != nil {
		t.Fatalf("expected success after capped 429, got err: %v", err)
	}
	if len(sleptBig) != 1 || sleptBig[0] != vendorRetryAfterCap {
		t.Errorf("delay = %v, want capped at %v", sleptBig, vendorRetryAfterCap)
	}
}

// ── 503 on every attempt fails with the original error ─────────────────────

func TestFetchWithRetryInner_ExhaustsAndFailsWithOriginalError(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.Client(), srv.URL, "application/json", "msrc", "2015-Aug", noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error once retries are exhausted, got nil")
	}
	if calls != vendorFetchMaxAttempts {
		t.Errorf("handler called %d times, want %d (vendorFetchMaxAttempts)", calls, vendorFetchMaxAttempts)
	}
	if len(slept) != vendorFetchMaxAttempts-1 {
		t.Errorf("slept %d times, want %d (one fewer than attempts — no sleep after the last failure)", len(slept), vendorFetchMaxAttempts-1)
	}

	var httpErr *vendorHTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("final error does not wrap the original *vendorHTTPError: %v", err)
	}
	if httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("wrapped StatusCode = %d, want 503", httpErr.StatusCode)
	}
}

// ── 404 is not retried ──────────────────────────────────────────────────────

func TestFetchWithRetryInner_FatalErrorNeverRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.Client(), srv.URL, "application/json", "msrc", "2015-Aug", noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error for a 404, got nil")
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1 — a fatal 4xx must not burn the retry budget", calls)
	}
	if len(slept) != 0 {
		t.Errorf("slept %d times, want 0", len(slept))
	}
}

// A parse/decode-shaped failure (here: a non-200 we don't recognise as
// retryable, verified indirectly via isRetryableVendorError since fetchOnce
// itself has no decode step — decoding is the caller's job, e.g. ParseMSRC)
// must not be retried either.
func TestIsRetryableVendorError_Classification(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		retryable bool
	}{
		{"429", &vendorHTTPError{StatusCode: 429}, true},
		{"500", &vendorHTTPError{StatusCode: 500}, true},
		{"503", &vendorHTTPError{StatusCode: 503}, true},
		{"400", &vendorHTTPError{StatusCode: 400}, false},
		{"404", &vendorHTTPError{StatusCode: 404}, false},
		{"transport", &vendorTransportError{err: errors.New("connection reset by peer")}, true},
		{"generic parse error", errors.New("parse msrc cvrf: unexpected end of JSON input"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableVendorError(tc.err); got != tc.retryable {
				t.Errorf("isRetryableVendorError(%v) = %v, want %v", tc.err, got, tc.retryable)
			}
		})
	}
}

// ── context cancellation stops the retries ─────────────────────────────────

func TestFetchWithRetryInner_ContextCancellationStopsRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	// sleep cancels the context instead of actually waiting, simulating a
	// cancellation that arrives while the retry loop is backed off.
	sleep := func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}

	_, err := fetchWithRetryInner(ctx, srv.Client(), srv.URL, "application/json", "msrc", "2015-Aug", sleep)
	if err == nil {
		t.Fatal("expected an error after context cancellation, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1 — cancellation during the first backoff must stop further attempts", calls)
	}
}

func TestFetchWithRetryInner_AlreadyCancelledContext(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withVendorFetchLogger(t, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var slept []time.Duration
	_, err := fetchWithRetryInner(ctx, srv.Client(), srv.URL, "application/json", "msrc", "2015-Aug", noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error for an already-cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}

// ── vendorFetchDelay bound ──────────────────────────────────────────────────

func TestVendorFetchDelay_NeverBelowBaseOrOverdue(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		d := vendorFetchDelay(attempt)
		idx := attempt
		if idx >= len(vendorFetchBackoff) {
			idx = len(vendorFetchBackoff) - 1
		}
		base := vendorFetchBackoff[idx]
		if d < base {
			t.Errorf("vendorFetchDelay(%d) = %v, want >= base %v", attempt, d, base)
		}
		if d > base+base/2 {
			t.Errorf("vendorFetchDelay(%d) = %v, want <= base+jitter %v", attempt, d, base+base/2)
		}
	}
}

// ── vendor body size cap (PAT-2041) ─────────────────────────────────────────

// withVendorBodyLimit shrinks vendorBodyLimit for the duration of a test so
// the overflow path can be exercised without allocating a multi-hundred-MB
// response body, restoring the real limit afterward.
func withVendorBodyLimit(t *testing.T, n int64) {
	t.Helper()
	orig := vendorBodyLimit
	vendorBodyLimit = n
	t.Cleanup(func() { vendorBodyLimit = orig })
}

func TestFetchOnce_BodyAtLimitSucceeds(t *testing.T) {
	const limit = 16
	withVendorBodyLimit(t, limit)

	payload := make([]byte, limit)
	for i := range payload {
		payload[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	body, err := fetchOnce(context.Background(), srv.Client(), srv.URL, "application/json")
	if err != nil {
		t.Fatalf("body exactly at the limit should succeed, got err: %v", err)
	}
	if len(body) != limit {
		t.Errorf("body length = %d, want %d", len(body), limit)
	}
}

func TestFetchOnce_BodyOverLimitFails(t *testing.T) {
	const limit = 16
	withVendorBodyLimit(t, limit)

	payload := make([]byte, limit+1)
	for i := range payload {
		payload[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	_, err := fetchOnce(context.Background(), srv.Client(), srv.URL, "application/json")
	if err == nil {
		t.Fatal("expected an error for a body one byte over the limit, got nil")
	}
	var tooLarge *vendorBodyTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want a *vendorBodyTooLargeError", err)
	}
	if tooLarge.Limit != limit {
		t.Errorf("Limit = %d, want %d", tooLarge.Limit, limit)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(limit)) {
		t.Errorf("err.Error() = %q, want it to name the limit %d", err.Error(), limit)
	}
}

func TestFetchWithRetryInner_OversizeBodyFailsAfterExactlyOneRequestAndNamesSourceAndLimit(t *testing.T) {
	const limit = 16
	withVendorBodyLimit(t, limit)
	withVendorFetchLogger(t, discardLogger())

	var calls int
	payload := make([]byte, limit+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.Client(), srv.URL, "application/json", "msrc", "2026-Sep", noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error for an oversize body, got nil")
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1 — an oversize body must not be retried", calls)
	}
	if len(slept) != 0 {
		t.Errorf("slept %d times, want 0", len(slept))
	}

	var tooLarge *vendorBodyTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("final error does not wrap *vendorBodyTooLargeError: %v", err)
	}
	if tooLarge.Limit != limit {
		t.Errorf("Limit = %d, want %d", tooLarge.Limit, limit)
	}
	msg := err.Error()
	if !strings.Contains(msg, "msrc") || !strings.Contains(msg, "2026-Sep") {
		t.Errorf("err.Error() = %q, want it to name the source (msrc) and document (2026-Sep)", msg)
	}
	if !strings.Contains(msg, fmt.Sprint(limit)) {
		t.Errorf("err.Error() = %q, want it to name the limit %d", msg, limit)
	}
	if isRetryableVendorError(err) {
		t.Error("a wrapped oversize-body error must classify as fatal, not retryable")
	}
}

// ── Retry-After parsing ──────────────────────────────────────────────────────

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("parseRetryAfter(\"\") = %v, want 0", got)
	}
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Errorf("parseRetryAfter(5) = %v, want 5s", got)
	}
	if got := parseRetryAfter("not-a-value"); got != 0 {
		t.Errorf("parseRetryAfter(garbage) = %v, want 0", got)
	}
	if got := parseRetryAfter("999999"); got != vendorRetryAfterCap {
		t.Errorf("parseRetryAfter(huge) = %v, want capped at %v", got, vendorRetryAfterCap)
	}
}
