package platformroot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"patched.im/api/internal/httpretry"
)

// httpClient mirrors internal/oscve's fetch client: a 30s-timeout client
// shared by both fetchers. The fetchers are deliberately thin — parsing
// (ParseMicrosoftCSV / ParseAppleCSV) is unit-tested against committed
// fixtures without network access.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// fetchLogger is where retry WARN/INFO lines go, mirroring
// internal/oscve's vendorFetchLogger.
var fetchLogger = slog.Default()

// maxListBytes caps a published root list body (the CCADB CSVs run to a
// few MB). An oversized body is refused rather than read into memory, the
// same guard internal/oscve (vendorBodyLimit) and internal/exploitation
// (maxSourceBytes) apply to their sources. A package variable so tests can
// lower it.
var maxListBytes int64 = 32 << 20

// errListTooLarge is not an HTTPError or TransportError, so it is never
// retried.
var errListTooLarge = errors.New("platform-root list exceeds size cap")

// fetchOnce performs a single HTTP GET attempt with no retry. Errors are
// typed (*httpretry.HTTPError / *httpretry.TransportError) so fetchWithRetry
// can classify retryable-vs-fatal without matching a formatted message.
func fetchOnce(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/csv")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpretry.HTTPError{
			StatusCode: resp.StatusCode,
			RetryAfter: httpretry.ParseRetryAfter(resp.Header.Get("Retry-After"), httpretry.DefaultRetryAfterCap),
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	if int64(len(body)) > maxListBytes {
		return nil, errListTooLarge
	}
	return body, nil
}

// fetch retries fetchOnce on a transient error (TLS/dial timeout, connection
// reset/refused, 5xx, 429 honouring Retry-After) with the same bounded
// exponential backoff as internal/oscve's vendor advisory fetches and
// internal/exploitation's source fetches (PAT-2039/PAT-2078): ~1s/5s/20s, up
// to 4 attempts, capped at 60s overall. Any other 4xx is never retried;
// cancelling ctx stops the retries. source names the published list (e.g.
// SourceMicrosoftCCADB) for the retry log only.
func fetch(ctx context.Context, url, source string) ([]byte, error) {
	return fetchWithRetryInner(ctx, url, source, httpretry.SleepCtx)
}

func fetchWithRetryInner(ctx context.Context, url, source string, sleep func(context.Context, time.Duration) error) ([]byte, error) {
	return httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: httpretry.DefaultMaxAttempts,
		OverallCap:  httpretry.DefaultOverallCap,
		Backoff:     httpretry.DefaultBackoff,
		IsRetryable: httpretry.IsRetryable,
		RetryAfter: func(err error) time.Duration {
			var httpErr *httpretry.HTTPError
			if errors.As(err, &httpErr) {
				return httpErr.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var httpErr *httpretry.HTTPError
			if errors.As(err, &httpErr) {
				return httpErr.StatusCode
			}
			return 0
		},
		Logger:    fetchLogger,
		LogAction: "platform-root list fetch",
		Source:    source,
		Document:  source,
		Sleep:     sleep,
	}, func(ctx context.Context) ([]byte, error) {
		return fetchOnce(ctx, url)
	})
}
