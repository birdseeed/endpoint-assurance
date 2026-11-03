package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// promClient is a shared HTTP client used to forward Prometheus queries.
// A 10s timeout is generous for a local scrape; 30s would never be hit.
var promClient = &http.Client{Timeout: 10 * time.Second}

// PrometheusProxyHandler forwards query_range requests to the local Prometheus
// instance on behalf of the admin UI browser. Only query/start/end/step are
// forwarded — no other Prometheus API surface is exposed through this handler.
//
// Route: GET /admin/metrics/proxy  (internal :8081 only)
func PrometheusProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		params := url.Values{}
		for _, k := range []string{"query", "start", "end", "step"} {
			if v := q.Get(k); v != "" {
				params.Set(k, v)
			}
		}

		promURL := "http://localhost:9090/api/v1/query_range?" + params.Encode()
		resp, err := promClient.Get(promURL) //nolint:noctx
		if err != nil {
			slog.Error("prometheus proxy failed", "err", err)
			http.Error(w, "prometheus unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}
