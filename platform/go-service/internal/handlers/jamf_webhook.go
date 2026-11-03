package handlers

// POST /v1/webhooks/jamf/{webhookID}: Jamf Pro webhook ingest (PAT-2145).
//
// The customer's Jamf Pro pushes ComputerAdded, ComputerInventoryCompleted,
// DeviceAddedToDEP and (opt-in) ComputerCheckIn webhooks here, so Patched
// can reconcile the Macs Jamf manages against the Macs Patched sees without
// ever holding a Jamf API credential (PAT-1666).
//
// Public listener, outside the /v1/portal group: it neither reads nor
// accepts portal credentials. Its only credential is the tenant's webhook
// token, created, rotated and revoked by a portal admin
// (portal_jamf_coverage.go). Endpoint-trust posture:
//
//   - {webhookID} is an opaque 32-character random identifier, never the
//     tenant UUID, and resolves to at most one tenant.
//   - Rate limits (JamfWebhookLimits). An unauthenticated sender must not
//     be able to burn a tenant's budget, make each request cost a database
//     read, or lock other tenants out:
//       * a malformed ID or a missing token is refused 401 before any
//         database work and charges nothing shared (only a log-sampling
//         bucket), so it cannot drain anything that gates real tenants;
//       * a failure that cost a database read (an ID not in the database,
//         or a real ID with a wrong token) is charged to the global failure
//         bucket; while that allows, also to a per-client-IP bucket (IPv6
//         keyed on its /64) and to the "unknown" or per-ID bucket;
//       * the connector cache (jamfConnectorCache) holds every active
//         connector's webhook ID and token hash, seeded at startup and
//         refreshed every minute from the database, and updated on each
//         successful authentication. A request whose token hashes to the
//         cached hash for its ID always reaches the database, so no bucket
//         ever blocks a correctly authenticating tenant, even straight
//         after a restart;
//       * any other request is refused 429 before the database is read
//         while the global, IP, "unknown" or per-ID failure bucket is
//         exhausted. For a cached ID one exception, the probe bucket (a
//         few per minute per ID), still lets a non-matching token reach the
//         database: that is how a token rotated since the last cache
//         refresh gets through during a flood, at a bounded cost;
//       * a failed authentication answers 429 while the global failure
//         bucket is exhausted and 401 otherwise, the same for known and
//         unknown IDs, so the status reveals nothing about liveness;
//       * the tenant's own bucket is charged only after authentication;
//       * failure log lines are emitted only while the buckets allow it,
//         each carrying the count suppressed since the last one.
//   - A revoked tenant (tenants.revoked_at) authenticates nothing.
//   - Token accepted as "Authorization: Bearer <token>" (Jamf Pro Header
//     Authentication) or as the password of HTTP Basic auth. SHA-256 of the
//     presented token is compared with subtle.ConstantTimeCompare against
//     the stored hash; an unknown ID, a malformed ID, a revoked token, a
//     missing token and a wrong token all compare against a fixed dummy
//     hash and all answer the same 401 body, so the response never says
//     whether a tenant or connector exists.
//   - Nothing is read from the body before authentication. After it:
//     Content-Type must be JSON, the body is capped (http.MaxBytesReader),
//     and jamfcoverage.Parse applies the strict schema and keeps
//     identifiers only. Event types the tenant has not subscribed to are
//     refused.
//   - The raw body is never stored or logged, and no log line carries a
//     payload value. Personal fields are dropped inside jamfcoverage.Parse.
//   - ComputerCheckIn is collapsed: at most one device update per device per
//     hour, and the connector's last-event time is touched at most once a
//     minute, so a chatty estate cannot turn check-ins into a write storm.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/jamfcoverage"
	"patched.im/api/internal/ratelimit"
)

const (
	// Jamf Pro webhook bodies are around 1-2 KiB; 64 KiB is generous.
	jamfWebhookMaxBodyBytes = 64 << 10
	// jamfCheckInCollapse: a ComputerCheckIn for a device Jamf reported less
	// than this long ago changes nothing.
	jamfCheckInCollapse = time.Hour
	// jamfConnectorTouchSeconds: the connector's last_event_at is updated at
	// most this often (unless the claimed instance changes).
	jamfConnectorTouchSeconds = 60
)

// jamfWebhookIDPattern is the shape of a webhook ID: 24 random bytes,
// base64url without padding.
var jamfWebhookIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

// jamfDummyHash is compared against when there is no stored hash, so the
// failure paths do the same work as a wrong token.
var jamfDummyHash = sha256.Sum256([]byte("patched-jamf-webhook-no-such-connector"))

// jamfPresentedToken extracts the webhook token from the request: a Bearer
// token, or the password of HTTP Basic auth. "" when neither is present.
func jamfPresentedToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return pass
	}
	return ""
}

// jamfTokenMatches reports whether presented hashes to stored. stored may be
// nil (no connector, or revoked): the compare still runs, against the dummy
// hash, and the result is false. Constant time over fixed-width digests.
func jamfTokenMatches(stored []byte, presented string) bool {
	want := jamfDummyHash[:]
	usable := len(stored) == sha256.Size
	if usable {
		want = stored
	}
	got := sha256.Sum256([]byte(presented))
	eq := subtle.ConstantTimeCompare(want, got[:]) == 1
	return eq && usable && presented != ""
}

type jamfConnectorAuth struct {
	tenantID       string
	tokenHash      []byte
	checkInEnabled bool
	generation     int
}

func jamfUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="patched-jamf-webhook"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":"unauthorized"}`+"\n")
}

func jamfWebhookError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

// JamfWebhookLimits holds the Jamf webhook's rate limiters and connector
// cache. Build it with NewJamfWebhookLimits, then seed and refresh the cache
// with RefreshConnectors / RunConnectorRefresh.
type JamfWebhookLimits struct {
	// Tenant: authenticated events, keyed by tenant id.
	Tenant *ratelimit.TenantLimiter
	// FailedGlobal: failures that cost a database read ("global"), and the
	// shared bucket for IDs not in the database ("unknown").
	FailedGlobal *ratelimit.TenantLimiter
	// FailedKey: the same failures per client IP ("ip:") and per real
	// webhook ID ("id:").
	FailedKey *ratelimit.TenantLimiter
	// Probe: per cached webhook ID, the few non-matching tokens let through
	// to the database while that ID's failure bucket is exhausted.
	Probe *ratelimit.TenantLimiter
	// Malformed: log sampling for requests refused before any database
	// work. Gates nothing else.
	Malformed *ratelimit.TenantLimiter

	cache      *jamfConnectorCache
	suppressed atomic.Int64
}

// JamfWebhookLimitsConfig sizes the limiters.
type JamfWebhookLimitsConfig struct {
	TenantRPM, TenantBurst             int
	FailedGlobalRPM, FailedGlobalBurst int
	FailedKeyRPM, FailedKeyBurst       int
	// ProbeRPM / ProbeBurst default to 6 / 2.
	ProbeRPM, ProbeBurst int
}

// NewJamfWebhookLimits builds the limiters with an empty connector cache.
func NewJamfWebhookLimits(c JamfWebhookLimitsConfig) *JamfWebhookLimits {
	if c.ProbeRPM <= 0 {
		c.ProbeRPM = 6
	}
	if c.ProbeBurst <= 0 {
		c.ProbeBurst = 2
	}
	l := &JamfWebhookLimits{
		Tenant:       ratelimit.New(ratelimit.Config{RPM: c.TenantRPM, Burst: c.TenantBurst}),
		FailedGlobal: ratelimit.New(ratelimit.Config{RPM: c.FailedGlobalRPM, Burst: c.FailedGlobalBurst}),
		FailedKey:    ratelimit.New(ratelimit.Config{RPM: c.FailedKeyRPM, Burst: c.FailedKeyBurst}),
		Probe:        ratelimit.New(ratelimit.Config{RPM: c.ProbeRPM, Burst: c.ProbeBurst}),
		Malformed:    ratelimit.New(ratelimit.Config{RPM: 6, Burst: 3}),
		cache:        &jamfConnectorCache{m: map[string][]byte{}},
	}
	jamfLiveCaches.register(l.cache)
	return l
}

// jamfLiveCaches lets the portal token handlers (same process, no reference
// to the limits) update every connector cache the moment a token is
// created, rotated or revoked, instead of waiting up to a minute for the
// refresh. In production there is one; tests build several.
var jamfLiveCaches = &jamfCacheRegistry{}

type jamfCacheRegistry struct {
	mu     sync.Mutex
	caches []*jamfConnectorCache
}

func (r *jamfCacheRegistry) register(c *jamfConnectorCache) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caches = append(r.caches, c)
}

// jamfConnectorIssued records a newly issued token hash for webhookID in
// every live cache. Call after the issuing transaction commits.
func jamfConnectorIssued(webhookID string, hash []byte) {
	jamfLiveCaches.mu.Lock()
	defer jamfLiveCaches.mu.Unlock()
	for _, c := range jamfLiveCaches.caches {
		c.set(webhookID, hash)
	}
}

// jamfConnectorRevoked drops webhookID from every live cache. Call after
// the revoking transaction commits.
func jamfConnectorRevoked(webhookID string) {
	jamfLiveCaches.mu.Lock()
	defer jamfLiveCaches.mu.Unlock()
	for _, c := range jamfLiveCaches.caches {
		c.del(webhookID)
	}
}

// SeedConnectors is the startup seed: RefreshConnectors, retried up to
// jamfSeedTries times with a doubling delay from jamfSeedFirstDelay (about
// 10 seconds in all) before the listener serves. It returns the last error
// if every try fails; the caller logs it and serves anyway, and the minute
// refresh recovers.
func (l *JamfWebhookLimits) SeedConnectors(ctx context.Context, pool *pgxpool.Pool) error {
	return jamfSeedWithRetry(ctx, func(ctx context.Context) error { return l.RefreshConnectors(ctx, pool) },
		jamfSeedTries, jamfSeedFirstDelay)
}

const (
	jamfSeedTries      = 5
	jamfSeedFirstDelay = 650 * time.Millisecond // 0.65 + 1.3 + 2.6 + 5.2 s between five tries
)

func jamfSeedWithRetry(ctx context.Context, refresh func(context.Context) error, tries int, delay time.Duration) error {
	var err error
	for i := 0; i < tries; i++ {
		if err = refresh(ctx); err == nil {
			return nil
		}
		if i == tries-1 {
			break
		}
		slog.Warn("jamf connector cache seed failed; retrying", "attempt", i+1, "of", tries, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return err
}

const (
	jamfFailedGlobalKey = "global"
	jamfFailedUnknown   = "unknown"
	// jamfConnectorRefresh: how often the connector cache is rebuilt, so a
	// rotated token or a new connector is picked up within this long even
	// if nothing authenticates meanwhile.
	jamfConnectorRefresh = time.Minute
)

// jamfConnectorCache maps each active connector's webhook ID to its token
// hash. Rebuilt wholesale from the database (so revoked and rotated tokens
// drop out) and updated on successful authentication. Its size is the
// number of tenants with an active Jamf token; nothing an unauthenticated
// sender does can add to it.
type jamfConnectorCache struct {
	mu sync.RWMutex
	m  map[string][]byte
}

func (c *jamfConnectorCache) get(id string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.m[id]
	return h, ok
}

func (c *jamfConnectorCache) set(id string, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = hash
}

// correct records what the database says after a failed authentication
// for id, so a stale cached hash (a token rotated or revoked since the last
// refresh) stops bypassing the gates at once.
func (c *jamfConnectorCache) correct(id string, dbHash []byte, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[id]; !ok {
		return
	}
	if !found || len(dbHash) != sha256.Size {
		delete(c.m, id)
		return
	}
	c.m[id] = dbHash
}

func (c *jamfConnectorCache) del(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}

func (c *jamfConnectorCache) replace(m map[string][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = m
}

// RefreshConnectors rebuilds the connector cache from every connector with
// an active token on a non-revoked tenant. Called once at startup, before
// the listener serves, so a restart never empties it.
func (l *JamfWebhookLimits) RefreshConnectors(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT c.webhook_id, c.token_hash
		FROM jamf_webhook_connectors c
		JOIN tenants t ON t.id = c.tenant_id AND t.revoked_at IS NULL
		WHERE c.token_hash IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("jamf connector cache: %w", err)
	}
	defer rows.Close()
	m := map[string][]byte{}
	for rows.Next() {
		var id string
		var h []byte
		if err := rows.Scan(&id, &h); err != nil {
			return fmt.Errorf("jamf connector cache scan: %w", err)
		}
		m[id] = h
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("jamf connector cache: %w", err)
	}
	l.cache.replace(m)
	return nil
}

// RunConnectorRefresh refreshes the cache every jamfConnectorRefresh until
// ctx ends. A failed refresh keeps the previous cache and logs.
func (l *JamfWebhookLimits) RunConnectorRefresh(ctx context.Context, pool *pgxpool.Pool) {
	t := time.NewTicker(jamfConnectorRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.RefreshConnectors(ctx, pool); err != nil && ctx.Err() == nil {
				slog.Error("jamf connector cache refresh failed; keeping the previous cache", "err", err)
			}
		}
	}
}

// jamfClientIP is the rate-limit key for the Cloudflare-supplied client
// address. Cloudflare sets CF-Connecting-IP on every proxied request and
// overwrites a client-sent copy, and the origin accepts only Cloudflare
// ranges (Hetzner Cloud Firewall, root AGENTS.md), so it is trusted for rate
// limiting only. IPv6 is keyed on its /64, since one host commonly holds a
// whole /64. "" when absent or not an IP (local runs, tests): the global
// bucket still applies.
func jamfClientIP(r *http.Request) string {
	return cloudflareClientIP(r)
}

// JamfWebhookHandler serves POST /v1/webhooks/jamf/{webhookID}. A nil pool
// or limits fails closed (503).
func JamfWebhookHandler(pool *pgxpool.Pool, limits *JamfWebhookLimits) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "jamf_webhook")
		if pool == nil || limits == nil {
			http.Error(w, "jamf webhook ingest not configured", http.StatusServiceUnavailable)
			return
		}
		webhookID := chi.URLParam(r, "webhookID")
		validID := jamfWebhookIDPattern.MatchString(webhookID)
		ip := jamfClientIP(r)
		presented := jamfPresentedToken(r)

		tooMany := func(retry time.Duration) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())+1))
			jamfWebhookError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
		}

		// Refused before any database work: charges nothing shared.
		if !validID || presented == "" {
			if ok, _ := limits.Malformed.Allow("malformed"); ok {
				logger.Warn("jamf webhook auth failed", "reason", "malformed_or_no_token",
					"suppressed_since_last", limits.suppressed.Swap(0))
			} else {
				limits.suppressed.Add(1)
			}
			jamfUnauthorized(w)
			return
		}

		presentedHash := sha256.Sum256([]byte(presented))
		cachedHash, cached := limits.cache.get(webhookID)
		matchesCache := cached && len(cachedHash) == sha256.Size &&
			subtle.ConstantTimeCompare(cachedHash, presentedHash[:]) == 1
		idKey := "id:" + webhookID
		if !matchesCache {
			// Not (yet) known to be right: gate before the database read.
			blocked := limits.FailedGlobal.Blocked(jamfFailedGlobalKey) ||
				(ip != "" && limits.FailedKey.Blocked("ip:"+ip))
			if cached {
				blocked = blocked || limits.FailedKey.Blocked(idKey)
				// A token rotated since the last cache refresh, or a
				// flood on this ID: a few per minute still reach the lookup.
				if blocked {
					if ok, _ := limits.Probe.Allow(webhookID); ok {
						blocked = false
					}
				}
			} else {
				blocked = blocked || limits.FailedGlobal.Blocked(jamfFailedUnknown)
			}
			if blocked {
				limits.suppressed.Add(1)
				tooMany(time.Minute)
				return
			}
		}

		// fail charges a failure that cost a database read. While the global
		// bucket allows it, the IP and ID (or shared unknown) buckets are
		// charged too and the answer is 401; once the global bucket is
		// exhausted nothing else is charged (no new per-IP entries) and the
		// answer is 429 for every ID, known or not.
		fail := func(known bool) {
			if g, retry := limits.FailedGlobal.Allow(jamfFailedGlobalKey); !g {
				limits.suppressed.Add(1)
				tooMany(retry)
				return
			}
			ipOK := true
			if ip != "" {
				ipOK, _ = limits.FailedKey.Allow("ip:" + ip)
			}
			var k bool
			if known {
				k, _ = limits.FailedKey.Allow(idKey)
			} else {
				k, _ = limits.FailedGlobal.Allow(jamfFailedUnknown)
			}
			if ipOK && k {
				logger.Warn("jamf webhook auth failed", "webhook_id_valid", validID,
					"suppressed_since_last", limits.suppressed.Swap(0))
			} else {
				limits.suppressed.Add(1)
			}
			jamfUnauthorized(w)
		}

		var conn jamfConnectorAuth
		found := false
		err := pool.QueryRow(ctx, `
			SELECT c.tenant_id::text, c.token_hash, c.check_in_enabled, c.token_generation
			FROM jamf_webhook_connectors c
			JOIN tenants t ON t.id = c.tenant_id AND t.revoked_at IS NULL
			WHERE c.webhook_id = $1
		`, webhookID).Scan(&conn.tenantID, &conn.tokenHash, &conn.checkInEnabled, &conn.generation)
		switch {
		case err == nil:
			found = true
		case errors.Is(err, pgx.ErrNoRows):
		default:
			logger.Error("jamf webhook connector lookup failed", "err", err)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if !jamfTokenMatches(conn.tokenHash, presented) || !found {
			limits.cache.correct(webhookID, conn.tokenHash, found)
			fail(found)
			return
		}
		limits.cache.set(webhookID, conn.tokenHash)
		if ok, retry := limits.Tenant.Allow(conn.tenantID); !ok {
			tooMany(retry)
			return
		}
		logger = logger.With("tenant_id", conn.tenantID)

		reject := func(status int, reason, msg string) {
			jamfRecordRejection(pool, conn.tenantID, reason, logger)
			logger.Warn("jamf webhook event rejected", "reason", reason)
			jamfWebhookError(w, status, reason, msg)
		}

		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			reject(http.StatusUnsupportedMediaType, "unsupported_media_type",
				"send the webhook as JSON (Jamf Pro: Content Type JSON)")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, jamfWebhookMaxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				reject(http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
				return
			}
			jamfWebhookError(w, http.StatusBadRequest, "invalid_request", "could not read the request body")
			return
		}
		instance, err := jamfcoverage.NormalizeInstanceURL(r.Header.Get(jamfcoverage.InstanceHeader))
		if err != nil {
			reject(http.StatusBadRequest, jamfcoverage.ReasonInvalidInstanceURL, err.Error())
			return
		}
		ev, perr := jamfcoverage.Parse(body)
		body = nil
		if perr != nil {
			status := http.StatusBadRequest
			if perr.Reason == jamfcoverage.ReasonUnsupportedEvent {
				status = http.StatusUnprocessableEntity
			}
			reject(status, perr.Reason, perr.Message)
			return
		}
		if jamfcoverage.IsOptionalEvent(ev.Type) && !conn.checkInEnabled {
			reject(http.StatusUnprocessableEntity, jamfcoverage.ReasonEventNotSubscribed,
				ev.Type+" is not subscribed for this connector; turn it on in the Patched portal or remove it from the Jamf webhook")
			return
		}

		collapsed, err := jamfIngestEvent(ctx, pool, conn.tenantID, presented, ev, instance, logger)
		switch {
		case errors.Is(err, errJamfTokenChanged):
			// Rotated or revoked (or the tenant revoked) between the lookup
			// and this transaction: nothing was written.
			limits.cache.correct(webhookID, nil, false)
			fail(true)
			return
		case errors.Is(err, errJamfDeviceCap):
			reject(http.StatusUnprocessableEntity, jamfcoverage.ReasonDeviceCapReached,
				fmt.Sprintf("this connector already holds %d Macs; no new Mac is recorded", jamfMaxDevicesPerTenant))
			return
		}
		if err != nil {
			logger.Error("jamf webhook ingest failed", "err", err, "event_type", ev.Type)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		status := "accepted"
		if collapsed {
			status = "collapsed"
		}
		logger.Info("jamf webhook event", "event_type", ev.Type, "status", status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	}
}

// jamfRecordRejection counts an authenticated event refused for its
// content. Best effort: a failure here only logs.
func jamfRecordRejection(pool *pgxpool.Pool, tenantID, reason string, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `
		UPDATE jamf_webhook_connectors
		SET events_rejected = events_rejected + 1, last_rejected_at = now(), last_rejected_reason = $2
		WHERE tenant_id = $1::uuid
	`, tenantID, reason); err != nil {
		logger.Error("jamf webhook rejection record failed", "err", err)
	}
}

type jamfDeviceRow struct {
	id                           int64
	serialNorm, udidNorm         *string
	jamfID                       *int64
	lastReceivedAt, lastEventAt  time.Time
	enrolled, depAssigned        bool
	deviceName, model, osVersion *string
}

var (
	errJamfTokenChanged = errors.New("jamf webhook token changed before the write")
	errJamfDeviceCap    = errors.New("jamf device cap reached")
)

// jamfMaxDevicesPerTenant bounds jamf_devices per tenant, matching the
// coverage report's estate bound. A new Mac beyond it is refused and
// recorded as device_cap_reached, never dropped silently.
const jamfMaxDevicesPerTenant = 50000

// jamfIngestEvent upserts one event under a per-tenant lock and touches the
// connector. It first re-reads the token hash with FOR SHARE and checks the
// presented token again, so an event that authenticated just before a
// rotate or revoke committed is not written (errJamfTokenChanged): the
// rotate and revoke UPDATEs wait for this lock, and this read waits for
// theirs. It reports collapsed when a check-in changed nothing.
func jamfIngestEvent(ctx context.Context, pool *pgxpool.Pool, tenantID, presented string, ev jamfcoverage.Event, instance string, logger *slog.Logger) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	var storedHash []byte
	var generation int
	err = tx.QueryRow(ctx, `
		SELECT c.token_hash, c.token_generation
		FROM jamf_webhook_connectors c
		JOIN tenants t ON t.id = c.tenant_id AND t.revoked_at IS NULL
		WHERE c.tenant_id = $1::uuid
		FOR SHARE OF c
	`, tenantID).Scan(&storedHash, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errJamfTokenChanged
	}
	if err != nil {
		return false, fmt.Errorf("token re-check: %w", err)
	}
	if !jamfTokenMatches(storedHash, presented) {
		return false, errJamfTokenChanged
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID+"|jamf-devices"); err != nil {
		return false, fmt.Errorf("lock: %w", err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return false, fmt.Errorf("now: %w", err)
	}
	evTime := ev.Time
	if evTime.IsZero() || evTime.After(now) {
		evTime = now
	}

	sn, un := nilIfEmpty(ev.SerialNormalized), nilIfEmpty(ev.UDIDNormalized)
	rows, err := tx.Query(ctx, `
		SELECT id, serial_normalized, udid_normalized, jamf_id, last_received_at, last_event_at,
		       enrolled, dep_assigned, device_name, model, os_version
		FROM jamf_devices
		WHERE tenant_id = $1::uuid
		  AND (($2::text IS NOT NULL AND serial_normalized = $2)
		    OR ($3::text IS NOT NULL AND udid_normalized = $3)
		    OR ($4::bigint IS NOT NULL AND jamf_id = $4))
		ORDER BY id
	`, tenantID, sn, un, ev.JamfID)
	if err != nil {
		return false, fmt.Errorf("find device: %w", err)
	}
	var cands []jamfDeviceRow
	for rows.Next() {
		var d jamfDeviceRow
		if err := rows.Scan(&d.id, &d.serialNorm, &d.udidNorm, &d.jamfID, &d.lastReceivedAt, &d.lastEventAt,
			&d.enrolled, &d.depAssigned, &d.deviceName, &d.model, &d.osVersion); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan device: %w", err)
		}
		cands = append(cands, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate devices: %w", err)
	}

	target := jamfPickTarget(cands, ev)
	isComputer := ev.Type != jamfcoverage.EventDeviceAddedToDEP
	collapsed := false
	if target == nil {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM jamf_devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&n); err != nil {
			return false, fmt.Errorf("count devices: %w", err)
		}
		if n >= jamfMaxDevicesPerTenant {
			return false, errJamfDeviceCap
		}
		// Every candidate left over holds the event's UDID or Jamf ID but a
		// different real serial (jamfPickTarget skipped it). Jamf has moved
		// that identifier to this Mac (a logic board swap, a re-used Jamf
		// record), so it is cleared from the old row first; otherwise the
		// insert would hit a unique index. The old row keeps its serial.
		for _, c := range cands {
			clearUDID := un != nil && c.udidNorm != nil && *c.udidNorm == *un
			clearJamfID := ev.JamfID != nil && c.jamfID != nil && *c.jamfID == *ev.JamfID
			if !clearUDID && !clearJamfID {
				continue
			}
			if _, err := tx.Exec(ctx, `
				UPDATE jamf_devices SET
				    udid = CASE WHEN $2 THEN NULL ELSE udid END,
				    udid_normalized = CASE WHEN $2 THEN NULL ELSE udid_normalized END,
				    jamf_id = CASE WHEN $3 THEN NULL ELSE jamf_id END
				WHERE id = $1
			`, c.id, clearUDID, clearJamfID); err != nil {
				return false, fmt.Errorf("move identifier: %w", err)
			}
			logger.Info("jamf identifier moved to another Mac", "from_row", c.id, "udid", clearUDID, "jamf_id", clearJamfID)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO jamf_devices (tenant_id, serial, serial_normalized, udid, udid_normalized, jamf_id,
			                          device_name, model, os_version, enrolled, dep_assigned,
			                          first_event_type, last_event_type, first_received_at, last_received_at, last_event_at,
			                          first_token_generation, last_token_generation)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $13, $14, $15, $15)
		`, tenantID, jamfSerialToStore(ev), sn, jamfUDIDToStore(ev), un, ev.JamfID,
			nilIfEmpty(ev.DeviceName), nilIfEmpty(ev.Model), nilIfEmpty(ev.OSVersion),
			isComputer, !isComputer, ev.Type, now, evTime, generation); err != nil {
			return false, fmt.Errorf("insert device: %w", err)
		}
	} else if ev.Type == jamfcoverage.EventComputerCheckIn && target.enrolled && now.Sub(target.lastReceivedAt) < jamfCheckInCollapse {
		collapsed = true
	} else {
		// Identifiers are filled, never overwritten, and only when no other
		// row already holds the value (the partial unique indexes).
		fill := func(have *string, want *string, other func(jamfDeviceRow) *string) *string {
			if have != nil || want == nil {
				return have
			}
			for _, c := range cands {
				if c.id != target.id && other(c) != nil && *other(c) == *want {
					return have
				}
			}
			return want
		}
		newSerial := fill(target.serialNorm, sn, func(c jamfDeviceRow) *string { return c.serialNorm })
		newUDID := fill(target.udidNorm, un, func(c jamfDeviceRow) *string { return c.udidNorm })
		newJamfID := target.jamfID
		if newJamfID == nil && ev.JamfID != nil {
			held := false
			for _, c := range cands {
				if c.id != target.id && c.jamfID != nil && *c.jamfID == *ev.JamfID {
					held = true
				}
			}
			if !held {
				newJamfID = ev.JamfID
			}
		}
		setSerialRaw := target.serialNorm == nil && newSerial != nil
		setUDIDRaw := target.udidNorm == nil && newUDID != nil
		if _, err := tx.Exec(ctx, `
			UPDATE jamf_devices SET
			    serial            = CASE WHEN $2 THEN $3 ELSE serial END,
			    serial_normalized = $4,
			    udid              = CASE WHEN $5 THEN $6 ELSE udid END,
			    udid_normalized   = $7,
			    jamf_id           = $8,
			    device_name       = COALESCE($9, device_name),
			    model             = COALESCE($10, model),
			    os_version        = COALESCE($11, os_version),
			    enrolled          = enrolled OR $12,
			    dep_assigned      = dep_assigned OR $13,
			    last_event_type   = $14,
			    last_received_at  = $15,
			    last_event_at     = GREATEST(last_event_at, $16),
			    last_token_generation = $17
			WHERE id = $1
		`, target.id, setSerialRaw, jamfSerialToStore(ev), newSerial, setUDIDRaw, jamfUDIDToStore(ev), newUDID, newJamfID,
			nilIfEmpty(ev.DeviceName), nilIfEmpty(ev.Model), nilIfEmpty(ev.OSVersion),
			isComputer, !isComputer, ev.Type, now, evTime, generation); err != nil {
			return false, fmt.Errorf("update device: %w", err)
		}
	}

	var inst any
	if instance != "" {
		inst = instance
	}
	if _, err := tx.Exec(ctx, `
		UPDATE jamf_webhook_connectors SET
		    first_event_at             = COALESCE(first_event_at, now()),
		    last_event_at              = now(),
		    jamf_instance_url          = COALESCE(jamf_instance_url, $2::text),
		    jamf_instance_last_claimed = COALESCE($2::text, jamf_instance_last_claimed),
		    jamf_instance_mismatch_at  = CASE WHEN $2::text IS NOT NULL AND jamf_instance_url IS NOT NULL
		                                           AND jamf_instance_url <> $2::text
		                                      THEN now() ELSE jamf_instance_mismatch_at END
		WHERE tenant_id = $1::uuid
		  AND (last_event_at IS NULL
		    OR last_event_at < now() - make_interval(secs => $3)
		    OR ($2::text IS NOT NULL AND jamf_instance_last_claimed IS DISTINCT FROM $2::text))
	`, tenantID, inst, jamfConnectorTouchSeconds); err != nil {
		return false, fmt.Errorf("touch connector: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return collapsed, nil
}

// jamfPickTarget chooses the existing row an event updates: the serial
// match first, then UDID, then Jamf ID. A candidate whose real serial
// differs from the event's real serial is a different Mac and is skipped.
func jamfPickTarget(cands []jamfDeviceRow, ev jamfcoverage.Event) *jamfDeviceRow {
	compatible := func(c jamfDeviceRow) bool {
		return ev.SerialNormalized == "" || c.serialNorm == nil || *c.serialNorm == ev.SerialNormalized
	}
	for _, match := range []func(jamfDeviceRow) bool{
		func(c jamfDeviceRow) bool {
			return ev.SerialNormalized != "" && c.serialNorm != nil && *c.serialNorm == ev.SerialNormalized
		},
		func(c jamfDeviceRow) bool {
			return ev.UDIDNormalized != "" && c.udidNorm != nil && *c.udidNorm == ev.UDIDNormalized
		},
		func(c jamfDeviceRow) bool { return ev.JamfID != nil && c.jamfID != nil && *c.jamfID == *ev.JamfID },
	} {
		for i := range cands {
			if match(cands[i]) && compatible(cands[i]) {
				return &cands[i]
			}
		}
	}
	return nil
}

// jamfSerialToStore keeps the serial as sent only when it is a real one.
func jamfSerialToStore(ev jamfcoverage.Event) *string {
	if ev.SerialNormalized == "" {
		return nil
	}
	return nilIfEmpty(ev.Serial)
}

func jamfUDIDToStore(ev jamfcoverage.Event) *string {
	if ev.UDIDNormalized == "" {
		return nil
	}
	return nilIfEmpty(ev.UDID)
}
