package webhook

import (
	"bytes"
	"context"
	"net/http"
	"time"
)

// Exported delivery surface (PAT-1888).
//
// The PAT-1888 notification channels deliver to tenant-supplied URLs too, so
// they must go through exactly the same SSRF-hardened client as PAT-134 rather
// than stand up a second one. A second http.Client is a second place for the
// dialer Control hook to be forgotten, which is how an SSRF control quietly
// stops existing. Shared hardened POST/PUT delivery keeps that boundary in one place.

// PostHardened sends body to rawURL through the SSRF-hardened outbound client
// and returns the HTTP status. A status of 0 with a non-nil error means no
// response was received (blocked destination, DNS failure, timeout).
//
// rawURL is re-validated here even when it was validated at configuration time:
// a row can predate a policy change, and validating at the point of use costs
// one URL parse.
//
// Guarantees inherited from httpClient: the dialer refuses internal
// destinations after DNS resolution (so DNS rebinding does not help), and
// redirects are never followed (so a 3xx to an internal host does not either).
func PostHardened(ctx context.Context, rawURL string, headers map[string]string, body []byte) (int, error) {
	return sendHardened(ctx, http.MethodPost, rawURL, headers, body)
}

// PutHardened uploads bytes through the same HTTPS-only, post-DNS safe dialer
// and no-redirect client as webhook delivery. Callers supply upload headers.
func PutHardened(ctx context.Context, rawURL string, headers map[string]string, body []byte) (int, error) {
	return sendHardened(ctx, http.MethodPut, rawURL, headers, body)
}

func sendHardened(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (int, error) {
	req, err := hardenedRequest(ctx, method, rawURL, headers, body)
	if err != nil {
		return 0, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func hardenedRequest(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*http.Request, error) {
	if err := ValidateDestination(rawURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Patched-Webhook/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// AttemptOutcome classifies one delivery attempt for callers outside this
// package.
type AttemptOutcome int

const (
	// AttemptDelivered — the destination returned 2xx.
	AttemptDelivered AttemptOutcome = iota
	// AttemptPermanent — the destination returned 4xx; retrying cannot help.
	AttemptPermanent
	// AttemptExhausted — retriable, but the attempt budget is spent.
	AttemptExhausted
	// AttemptRetry — retriable; the returned duration is the backoff to wait.
	AttemptRetry
)

// ClassifyAttempt is the shared retry decision, exported for notification
// channels so their semantics cannot drift from the PAT-134 dispatcher and
// sweeper. status is the HTTP status (0 for a transport failure), transportErr
// reports whether the request failed before a response, attempt is the
// 1-indexed number of the attempt just made, and maxAttempts caps the total.
func ClassifyAttempt(status int, transportErr bool, attempt, maxAttempts int) (AttemptOutcome, time.Duration) {
	if !transportErr && status >= 200 && status < 300 {
		return AttemptDelivered, 0
	}
	if status >= 400 && status < 500 {
		return AttemptPermanent, 0
	}
	if attempt >= maxAttempts {
		return AttemptExhausted, 0
	}
	return AttemptRetry, RetryBackoff(attempt + 1)
}
