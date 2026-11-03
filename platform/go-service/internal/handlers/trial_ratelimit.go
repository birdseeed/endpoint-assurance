package handlers

// PAT-2529: rate limits for POST /v1/trial/provision.
//
// The route is unauthenticated on the public listener and, for an address it
// has not seen, inserts a tenant, its credential and its rule baseline. It had
// no limiter at all, so anyone who found it could create tenants in a loop.
//
// Two token buckets sit in front of the handler, checked before the body is
// read and before any database work:
//
//   - per client: keyed on the Cloudflare-supplied client address;
//   - global: one bucket for the whole route.
//
// Every request is counted, valid or not, so malformed requests cannot be used
// to probe or hammer the handler for free. A request refused by its own client
// bucket does not spend the global bucket, so one abusive address can drain its
// own allowance but cannot lock every other customer out. Once the global
// bucket is empty the per-client map is not touched at all, so a spray of
// distinct addresses cannot grow it.
//
// Both buckets are token buckets whose burst equals the hourly count: the full
// count is available immediately, and one token comes back every hour/count
// (12 minutes at the default of 5 per client per hour). They are in memory and
// reset when the service restarts, like every other limiter in this package.
//
// This is a volume limit only. It does not verify the email address; that is
// a separate decision.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"patched.im/api/internal/ratelimit"
)

const (
	// DefaultTrialProvisionPerIPPerHour and DefaultTrialProvisionGlobalPerHour
	// are the limits used when the environment sets none (or sets a value that
	// is not a positive integer).
	DefaultTrialProvisionPerIPPerHour  = 5
	DefaultTrialProvisionGlobalPerHour = 30

	trialProvisionWindow    = time.Hour
	trialProvisionGlobalKey = "global"
	// trialProvisionUnattributedKey is the one shared per-client bucket for a
	// request with no usable CF-Connecting-IP. Skipping the per-client check
	// for such a request would let it past the only limit that tells clients
	// apart, so these share a single allowance instead. Every request that
	// reaches the origin through Cloudflare carries the header.
	trialProvisionUnattributedKey = "ip:unattributed"
)

// TrialProvisionLimitsConfig sizes the buckets, in requests per hour.
type TrialProvisionLimitsConfig struct {
	PerIPPerHour  int
	GlobalPerHour int
}

// TrialProvisionLimits holds the limiters for POST /v1/trial/provision. Build
// it with NewTrialProvisionLimits.
type TrialProvisionLimits struct {
	perIP  *ratelimit.TenantLimiter
	global *ratelimit.TenantLimiter
	// globalStep is how long the empty global bucket takes to earn one token,
	// the Retry-After for a request refused while it is empty.
	globalStep time.Duration

	// logGate samples the refusal log line so a flood cannot become a log
	// flood; suppressed counts the lines it dropped since the last one.
	logGate    *ratelimit.TenantLimiter
	suppressed atomic.Int64
}

// NewTrialProvisionLimits builds the limiters. A count that is not positive
// falls back to the default rather than meaning "no limit".
func NewTrialProvisionLimits(c TrialProvisionLimitsConfig) *TrialProvisionLimits {
	if c.PerIPPerHour <= 0 {
		c.PerIPPerHour = DefaultTrialProvisionPerIPPerHour
	}
	if c.GlobalPerHour <= 0 {
		c.GlobalPerHour = DefaultTrialProvisionGlobalPerHour
	}
	step := trialProvisionWindow / time.Duration(c.GlobalPerHour)
	if step < time.Second {
		step = time.Second
	}
	return &TrialProvisionLimits{
		perIP:      ratelimit.New(ratelimit.Config{RPM: c.PerIPPerHour, Burst: c.PerIPPerHour, Period: trialProvisionWindow}),
		global:     ratelimit.New(ratelimit.Config{RPM: c.GlobalPerHour, Burst: c.GlobalPerHour, Period: trialProvisionWindow}),
		globalStep: step,
		logGate:    ratelimit.New(ratelimit.Config{RPM: 6, Burst: 3}),
	}
}

// Allow charges one request. It reports whether the request may proceed and,
// when it may not, how long until a retry could succeed and which bucket
// refused it ("client" or "global").
func (l *TrialProvisionLimits) Allow(r *http.Request) (ok bool, retry time.Duration, scope string) {
	// An empty global bucket refuses first, without creating a per-client
	// entry for the request.
	if l.global.Blocked(trialProvisionGlobalKey) {
		return false, l.globalStep, "global"
	}
	if ok, retry := l.perIP.Allow(trialProvisionClientKey(r)); !ok {
		return false, retry, "client"
	}
	if ok, retry := l.global.Allow(trialProvisionGlobalKey); !ok {
		return false, retry, "global"
	}
	return true, 0, ""
}

// refuse answers 429 in the JSON shape the other limiters use and logs the
// refusal, sampled. The client address is not logged.
func (l *TrialProvisionLimits) refuse(w http.ResponseWriter, logger *slog.Logger, retry time.Duration, scope string) {
	if ok, _ := l.logGate.Allow("refusal"); ok {
		logger.Warn("trial provision rate limited", "scope", scope, "suppressed_since_last", l.suppressed.Swap(0))
	} else {
		l.suppressed.Add(1)
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())+1))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate_limited", "message": "rate limit exceeded"})
}

// trialProvisionClientKey is the per-client bucket key for a request.
func trialProvisionClientKey(r *http.Request) string {
	if ip := cloudflareClientIP(r); ip != "" {
		return "ip:" + ip
	}
	return trialProvisionUnattributedKey
}

// cloudflareClientIP is the rate-limit key for the Cloudflare-supplied client
// address. Cloudflare sets CF-Connecting-IP on every proxied request and
// overwrites a client-sent copy, and the origin accepts only Cloudflare
// ranges (Hetzner Cloud Firewall, root AGENTS.md), so it is trusted for rate
// limiting only. IPv6 is keyed on its /64, since one host commonly holds a
// whole /64. "" when absent or not an IP (local runs, tests).
//
// It deliberately reads nothing else. The public router mounts chi's RealIP,
// which rewrites RemoteAddr from True-Client-IP, then X-Real-IP, then the
// leftmost X-Forwarded-For entry. Nothing in this stack overwrites
// True-Client-IP or X-Real-IP, so a client can choose both, and RemoteAddr on
// this router is therefore not a trustworthy key.
func cloudflareClientIP(r *http.Request) string {
	ip := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP")))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
