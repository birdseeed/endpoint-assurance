// Package httpretry is the bounded exponential-backoff retry engine shared
// by every outbound vendor/source HTTP fetch in the CVE pipeline, so a lone
// transient blip (a 503, a dropped connection, a TLS handshake timeout)
// doesn't fail an entire nightly sync run.
//
// internal/oscve's vendor advisory fetches (MSRC/Apple, PAT-2039) were the
// first user: a single MSRC 503 during the dry-run preflight failed the
// whole api-01 deploy at CVE activation (run 35841096174) although nothing
// was wrong with the release. internal/exploitation's SOFA/CISA-KEV
// exploitation-evidence fetches hit the identical shape on the 2026-09-24
// nightly patched-cve-sync (one SOFA "net/http: TLS handshake timeout"
// failed a run that otherwise did all its work), which is why this engine
// was pulled out into its own package rather than reimplemented a second
// time (PAT-2078).
//
// A caller owns its own single-attempt fetch and its own error
// classification (what counts as retryable vs fatal, and how to read an
// explicit Retry-After); this package owns only the loop: bounded attempts,
// backoff with jitter, an overall wall-clock cap, honouring context
// cancellation, and logging each retry without ever logging the response
// body, a URL query string, or any other request/response content that
// might carry a secret.
package httpretry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// Defaults match PAT-2039's numbers: roughly 1s / 5s / 20s backoff, 4 total
// attempts (1 initial try plus up to 3 retries), bounded to 60s overall
// wall-clock (requests plus backoff), and a 30s cap on honouring any single
// Retry-After header.
const (
	DefaultMaxAttempts   = 4
	DefaultOverallCap    = 60 * time.Second
	DefaultRetryAfterCap = 30 * time.Second
)

// DefaultBackoff is the base delay before retry attempts 2, 3 and 4 (jitter
// is added on top by Delay), for an added worst case of well under
// DefaultOverallCap.
var DefaultBackoff = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	20 * time.Second,
}

// HTTPError carries the status code (and any capped Retry-After) of a
// non-200 response. Available for a caller that has no package-specific
// error type of its own; internal/oscve keeps its own vendorHTTPError for
// history but is otherwise identical in shape.
type HTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string { return fmt.Sprintf("http %d", e.StatusCode) }

// TransportError wraps a network-level failure (DNS, connection reset or
// refused, a timeout below the HTTP layer, a TLS handshake timeout) from the
// fetch. Same transient class as a 5xx.
type TransportError struct{ Err error }

func (e *TransportError) Error() string { return fmt.Sprintf("request: %v", e.Err) }
func (e *TransportError) Unwrap() error { return e.Err }

// IsRetryable classifies an *HTTPError/*TransportError pair as retryable
// (5xx or 429, or a transport-level error) vs fatal (any other 4xx, or an
// error of any other type, e.g. a parse/decode failure). A caller with its
// own error types supplies its own equivalent classifier to Options instead.
func IsRetryable(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= 500
	}
	var transportErr *TransportError
	return errors.As(err, &transportErr)
}

// Delay returns the backoff before retry attempt N (0-indexed: 0 is the
// delay before the 2nd try), with up to 50% jitter added on top so
// concurrent fetches don't all retry in lockstep.
func Delay(schedule []time.Duration, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= len(schedule) {
		attempt = len(schedule) - 1
	}
	base := schedule[attempt]
	jitter := time.Duration(rand.Int63n(int64(base)/2 + 1))
	return base + jitter
}

// ParseRetryAfter reads a 429 Retry-After header (delta-seconds or an
// HTTP-date), capped at cap. Returns 0 (meaning "use the normal backoff
// schedule instead") when the header is absent, unparsable or negative.
func ParseRetryAfter(v string, cap time.Duration) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return capRetryAfter(time.Duration(secs)*time.Second, cap)
	}
	if t, err := http.ParseTime(v); err == nil {
		return capRetryAfter(time.Until(t), cap)
	}
	return 0
}

func capRetryAfter(d, cap time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > cap {
		return cap
	}
	return d
}

// SleepCtx blocks for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation, nil after a full sleep.
func SleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Options configures Do. MaxAttempts, OverallCap, Backoff, IsRetryable,
// Logger, LogAction, Source and Document are required. RetryAfter, Status,
// WrapFatal and Sleep are optional; a nil value means "no override".
type Options struct {
	MaxAttempts int
	OverallCap  time.Duration
	Backoff     []time.Duration

	// IsRetryable classifies an attempt error as transient (retry) or fatal
	// (return immediately). Required.
	IsRetryable func(error) bool

	// RetryAfter optionally extracts an explicit server-requested delay
	// (e.g. a capped 429 Retry-After) from an error, used in place of the
	// normal backoff schedule. Return 0 to fall back to the schedule.
	RetryAfter func(error) time.Duration

	// Status optionally extracts an HTTP status code from an error, for the
	// retry WARN log line only. Return 0 when not applicable.
	Status func(error) int

	// WrapFatal optionally rewrites a non-retryable error before it is
	// returned, e.g. to name the source/document for one specific fatal
	// error worth calling out explicitly. Nil, or returning the error
	// unchanged, leaves it exactly as the attempt function produced it.
	WrapFatal func(error) error

	Logger    *slog.Logger
	LogAction string // e.g. "vendor advisory fetch", "exploitation source fetch"
	Source    string
	Document  string

	// Sleep overrides the real backoff wait, so tests can exercise the
	// retry-then-succeed / retry-then-exhaust / cancellation paths without
	// waiting out real delays. Nil uses SleepCtx.
	Sleep func(context.Context, time.Duration) error
}

// Do runs attempt with bounded exponential backoff retry on a transient
// error, up to opts.MaxAttempts total tries and opts.OverallCap total
// wall-clock (requests plus backoff). A fatal error (opts.IsRetryable
// returns false) returns immediately, optionally rewritten by
// opts.WrapFatal. Cancelling ctx, or ctx going Done while backed off,
// stops further attempts. Never logs the attempt's returned body or any
// URL — only source, document, attempt number, status and delay.
func Do(ctx context.Context, opts Options, attempt func(context.Context) ([]byte, error)) ([]byte, error) {
	sleep := opts.Sleep
	if sleep == nil {
		sleep = SleepCtx
	}
	ctx, cancel := context.WithTimeout(ctx, opts.OverallCap)
	defer cancel()

	var lastErr error
	for i := 0; i < opts.MaxAttempts; i++ {
		body, err := attempt(ctx)
		if err == nil {
			if i > 0 {
				opts.Logger.Info(opts.LogAction+" succeeded after retry",
					"source", opts.Source, "document", opts.Document, "attempt", i+1)
			}
			return body, nil
		}
		lastErr = err

		if !opts.IsRetryable(err) {
			if opts.WrapFatal != nil {
				return nil, opts.WrapFatal(err)
			}
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("fetch %s %s: %w", opts.Source, opts.Document, ctx.Err())
		}
		if i == opts.MaxAttempts-1 {
			// Last attempt failed — no point sleeping just to fall through
			// to the "exhausted" return below.
			break
		}

		delay := Delay(opts.Backoff, i)
		if opts.RetryAfter != nil {
			if ra := opts.RetryAfter(err); ra > 0 {
				delay = ra
			}
		}
		status := 0
		if opts.Status != nil {
			status = opts.Status(err)
		}
		opts.Logger.Warn(opts.LogAction+" transient error, retrying",
			"source", opts.Source, "document", opts.Document, "status", status,
			"attempt", i+1, "max_attempts", opts.MaxAttempts, "delay_ms", delay.Milliseconds())

		if sleepErr := sleep(ctx, delay); sleepErr != nil {
			return nil, fmt.Errorf("fetch %s %s: %w", opts.Source, opts.Document, sleepErr)
		}
	}
	return nil, fmt.Errorf("%s %s %s failed after %d attempts, giving up: %w",
		opts.LogAction, opts.Source, opts.Document, opts.MaxAttempts, lastErr)
}
