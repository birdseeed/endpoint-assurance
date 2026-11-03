package msgraph

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultRetryAfter is used when a 429 response is missing or has an
// unparsable Retry-After header. We still back off rather than hammering
// the endpoint with no signal at all.
const defaultRetryAfter = 30 * time.Second

// parseRetryAfter parses a Retry-After header value, which per RFC 9110 is
// either an integer number of seconds or an HTTP-date. Entra and Graph both
// use the integer-seconds form in practice, but both are handled.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultRetryAfter
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return defaultRetryAfter
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return defaultRetryAfter
}
