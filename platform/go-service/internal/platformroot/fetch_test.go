package platformroot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"patched.im/api/internal/httpretry"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func withFetchLogger(t *testing.T, l *slog.Logger) {
	t.Helper()
	orig := fetchLogger
	fetchLogger = l
	t.Cleanup(func() { fetchLogger = orig })
}

func noSleep(slept *[]time.Duration) func(context.Context, time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return nil
	}
}

// A transient 503 (the same shape as the 2026-09-24 SOFA TLS handshake
// timeout, PAT-2078) is retried and succeeds on the second attempt.
func TestFetchWithRetryInner_TransientErrorThenSuccess(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("csv,data"))
	}))
	defer srv.Close()
	withFetchLogger(t, discardLogger())

	var slept []time.Duration
	body, err := fetchWithRetryInner(context.Background(), srv.URL, SourceMicrosoftCCADB, noSleep(&slept))
	if err != nil {
		t.Fatalf("expected success after one transient error, got err: %v", err)
	}
	if calls != 2 {
		t.Errorf("handler called %d times, want 2", calls)
	}
	if string(body) != "csv,data" {
		t.Errorf("body = %q, want the 200 payload", body)
	}
	if len(slept) != 1 {
		t.Fatalf("slept %d times, want 1", len(slept))
	}
}

// A fatal 4xx (not 429) is never retried.
func TestFetchWithRetryInner_FatalErrorNeverRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	withFetchLogger(t, discardLogger())

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.URL, SourceAppleCCADBTLSServer, noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error for a 404, got nil")
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1 — a fatal 4xx must not burn the retry budget", calls)
	}
	if len(slept) != 0 {
		t.Errorf("slept %d times, want 0", len(slept))
	}
	var httpErr *httpretry.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v, want it to wrap *httpretry.HTTPError{StatusCode: 404}", err)
	}
}

// Persistent failure exhausts all attempts and fails exactly as before.
func TestFetchWithRetryInner_PersistentErrorFailsAfterMaxAttempts(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withFetchLogger(t, discardLogger())

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.URL, SourceMicrosoftCCADB, noSleep(&slept))
	if err == nil {
		t.Fatal("expected an error once retries are exhausted, got nil")
	}
	if calls != httpretry.DefaultMaxAttempts {
		t.Errorf("handler called %d times, want %d", calls, httpretry.DefaultMaxAttempts)
	}
}

// Cancelling the context stops further attempts.
func TestFetchWithRetryInner_ContextCancellationStopsRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withFetchLogger(t, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	sleep := func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}

	_, err := fetchWithRetryInner(ctx, srv.URL, SourceMicrosoftCCADB, sleep)
	if err == nil {
		t.Fatal("expected an error after context cancellation, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}

// PAT-2078 review: an oversized list is refused, not read into memory, and
// not retried.
func TestFetchWithRetryInner_OversizedListRefusedWithoutRetry(t *testing.T) {
	prev := maxListBytes
	maxListBytes = 16
	t.Cleanup(func() { maxListBytes = prev })

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte("0123456789abcdef-over-the-cap"))
	}))
	defer srv.Close()

	var slept []time.Duration
	_, err := fetchWithRetryInner(context.Background(), srv.URL, SourceMicrosoftCCADB, noSleep(&slept))
	if !errors.Is(err, errListTooLarge) {
		t.Fatalf("want errListTooLarge, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("an oversized list must not be retried: %d requests", calls)
	}
}
