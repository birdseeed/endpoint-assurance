package oscve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"patched.im/api/internal/httpretry"
)

// Bounded retry for vendor advisory HTTP fetches (PAT-2039). On 2026-09-23 a
// single HTTP 503 from MSRC on one CVRF document ("2015-Aug") failed the
// whole api-01 deploy's dry-run preflight, even though MSRC recovered minutes
// later. A transient vendor outage — 5xx, 429, or a network-level timeout or
// connection reset — is now absorbed here instead of failing the run
// immediately. A vendor that is genuinely down (retries exhausted), or a
// request we made wrong (4xx other than 429, or a parse/decode failure),
// still fails the run exactly as before.
//
// The actual retry loop (bounded exponential backoff, overall cap,
// cancellation, logging) lives in internal/httpretry, shared with
// internal/exploitation's SOFA/CISA-KEV fetches (PAT-2078) so the mechanism
// is written once. This file keeps its own error types and classification
// (vendorHTTPError/vendorTransportError/vendorBodyTooLargeError,
// isRetryableVendorError) because they predate the split and existing tests
// construct them directly; only the loop itself moved.

const (
	// vendorFetchMaxAttempts is 1 initial try plus up to 3 retries.
	vendorFetchMaxAttempts = httpretry.DefaultMaxAttempts

	// vendorFetchOverallCap bounds total wall-clock (requests plus backoff)
	// spent retrying a single fetch, so a flaky vendor can't hang os-sync
	// indefinitely waiting on one document.
	vendorFetchOverallCap = httpretry.DefaultOverallCap

	// vendorRetryAfterCap bounds how long a single 429 Retry-After header is
	// allowed to make us wait, in case a vendor sends something absurd.
	vendorRetryAfterCap = httpretry.DefaultRetryAfterCap
)

// vendorFetchBackoff is the base delay before retry attempts 2, 3 and 4
// (jitter is added on top by vendorFetchDelay) — roughly 1s / 5s / 20s per
// PAT-2039, for an added worst case of well under the 60s overall cap.
var vendorFetchBackoff = httpretry.DefaultBackoff

// vendorFetchLogger is where retry WARN lines go. A package var (like
// nvdBaseURL in cmd/patched-cve-sync) so it can be swapped in tests without
// changing every exported Fetch* signature.
var vendorFetchLogger = slog.Default()

// vendorHTTPError carries the status code (and any Retry-After) of a
// non-200 vendor response, so isRetryableVendorError classifies by type
// instead of string-matching a formatted message.
type vendorHTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *vendorHTTPError) Error() string { return fmt.Sprintf("http %d", e.StatusCode) }

// vendorTransportError wraps a network-level failure (DNS, connection
// reset, a timeout below the HTTP layer) from the fetch. Same transient
// class as a 5xx.
type vendorTransportError struct{ err error }

func (e *vendorTransportError) Error() string { return fmt.Sprintf("vendor request: %v", e.err) }
func (e *vendorTransportError) Unwrap() error { return e.err }

// vendorBodyTooLargeError signals fetchOnce cut off a vendor response body
// that exceeded vendorBodyLimit (PAT-2041). It is fatal, not retryable: a
// vendor sending an oversize body will send the same oversize body again,
// so retrying just re-reads it. The overflow is never truncated silently —
// this error is the only way fetchOnce returns for that case.
type vendorBodyTooLargeError struct{ Limit int64 }

func (e *vendorBodyTooLargeError) Error() string {
	return fmt.Sprintf("vendor response body exceeds %d byte limit", e.Limit)
}

// isRetryableVendorError classifies a fetchOnce error as retryable or fatal:
//   - 5xx or 429                                       -> retryable
//   - any other 4xx                                    -> fatal
//   - transport error (DNS, reset, timeout)             -> retryable
//   - oversize body (vendorBodyTooLargeError)           -> fatal
//   - parse/validation/decode error, or anything else   -> fatal
func isRetryableVendorError(err error) bool {
	var httpErr *vendorHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= 500
	}
	var transportErr *vendorTransportError
	return errors.As(err, &transportErr)
}

// vendorFetchDelay returns the backoff before retry attempt N (0-indexed: 0
// is the delay before the 2nd try), with up to 50% jitter added on top so
// concurrent fetches don't all retry in lockstep.
func vendorFetchDelay(attempt int) time.Duration {
	return httpretry.Delay(vendorFetchBackoff, attempt)
}

// parseRetryAfter reads a 429 Retry-After header (delta-seconds or an
// HTTP-date), capped at vendorRetryAfterCap. Returns 0 (meaning "use the
// normal backoff schedule instead") when the header is absent or unparsable.
func parseRetryAfter(v string) time.Duration {
	return httpretry.ParseRetryAfter(v, vendorRetryAfterCap)
}

// fetchWithRetry retries fetchOnce on a transient vendor error with bounded
// exponential backoff, up to vendorFetchMaxAttempts total tries and
// vendorFetchOverallCap total wall-clock. source/document are for the WARN
// retry log only (e.g. "msrc"/"2015-Aug") — the response body is never
// logged.
func fetchWithRetry(ctx context.Context, client *http.Client, rawURL, accept, source, document string) ([]byte, error) {
	return fetchWithRetryInner(ctx, client, rawURL, accept, source, document, httpretry.SleepCtx)
}

// fetchWithRetryInner takes the sleep function as a parameter so tests can
// exercise the full retry-then-succeed / retry-then-exhaust / cancellation
// flows without waiting out the real backoff durations.
func fetchWithRetryInner(ctx context.Context, client *http.Client, rawURL, accept, source, document string, sleep func(context.Context, time.Duration) error) ([]byte, error) {
	return httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: vendorFetchMaxAttempts,
		OverallCap:  vendorFetchOverallCap,
		Backoff:     vendorFetchBackoff,
		IsRetryable: isRetryableVendorError,
		RetryAfter: func(err error) time.Duration {
			var httpErr *vendorHTTPError
			if errors.As(err, &httpErr) {
				return httpErr.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var httpErr *vendorHTTPError
			if errors.As(err, &httpErr) {
				return httpErr.StatusCode
			}
			return 0
		},
		WrapFatal: func(err error) error {
			// An oversize body is the one fatal class that's easy to
			// misdiagnose without knowing which vendor/document produced
			// it (the limit alone doesn't say that), so it's the one
			// fatal error type this layer names explicitly. Other fatal
			// classes (4xx, decode errors) return unwrapped exactly as
			// before — no behaviour change for them.
			var tooLarge *vendorBodyTooLargeError
			if errors.As(err, &tooLarge) {
				return fmt.Errorf("fetch %s %s: %w", source, document, err)
			}
			return err
		},
		Logger:    vendorFetchLogger,
		LogAction: "vendor advisory fetch",
		Source:    source,
		Document:  document,
		Sleep:     sleep,
	}, func(ctx context.Context) ([]byte, error) {
		return fetchOnce(ctx, client, rawURL, accept)
	})
}
