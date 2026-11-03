package handlers

// GET /v1/posture — device-authenticated posture read endpoint (PAT-466).
//
// Auth: same bearer + HMAC-SHA256 + replay headers as /v1/inventory and
// /v1/agent-config, but requires a per-device credential (tenant_credentials
// rows with device_id IS NOT NULL). A device can only read its own posture —
// the device is derived from the credential, never from a client-supplied
// parameter.
//
// Security invariants (GitHub-Non-Author-Review evidence):
//   - Device A cannot read device B: device is resolved from the DB, not the
//     request. No URL/query/body parameter can influence which device is returned.
//   - Tenant-level or staff credentials are rejected at the bearer lookup step
//     (LookupDeviceByBearer rejects live rows with device_id IS NULL with its
//     server-side ErrDeviceCredentialRequired result, while the wire response
//     remains the same generic 401 as an unknown credential).
//   - Any auth header tampering, stale timestamp, or replay nonce → uniform 401.
//   - Rate-limited 60 RPM per tenant (burst 10).
//   - Every request audit-logs tenant_id + device_id + req_id.
//
// Reserved fields (populated by later PRs):
//   - app_policy — P6 (app-policy model)
//
// Response integrity (PAT-910): the served posture is Ed25519-signed at parity
// with GET /v1/agent-config. The body is the same {signed_payload, key_id,
// signature} envelope; signed_payload base64-decodes to the canonical posture
// JSON, which carries tenant_id (tenant binding) and issued_at (a monotonic
// anti-rollback value). The endpoint verifies the signature, tenant binding,
// and anti-rollback fail-closed before any root-privileged read of this data
// (e.g. the user_removable removal gate in patched-uninstall.sh). TLS is no
// longer the only integrity guarantee for posture.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/report"
)

// -- Injectable function types (for testing) ----------------------------------

// postureAuthFn resolves tenantID + deviceID from request headers. Returns an
// error on any auth failure; the handler maps all errors to 401.
type postureAuthFn func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (tenantID, deviceID string, err error)

// postureFetchFn loads posture data for a device. Returns ErrDeviceNotFound
// when the device row does not exist.
type postureFetchFn func(ctx context.Context, tenantID, deviceID string) (postureResp, error)

// -- Response types -----------------------------------------------------------

// postureSignedResp is the GET /v1/posture response envelope (PAT-910), at
// parity with agentConfigResp. signed_payload is the base64 of the canonical
// posture JSON the server signed; the endpoint base64-decodes it, verifies the
// Ed25519 signature over those exact bytes, then json-parses the verified bytes
// — no client-side reconstruction.
type postureSignedResp struct {
	SignedPayload string `json:"signed_payload"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
}

type postureResp struct {
	SchemaVersion int               `json:"schema_version"`
	TenantID      string            `json:"tenant_id"` // PAT-910: signed tenant binding — endpoint rejects a posture bound to a different tenant
	IssuedAt      string            `json:"issued_at"` // PAT-910: RFC3339 UTC sign time — the monotonic anti-rollback value the endpoint enforces
	GeneratedAt   time.Time         `json:"generated_at"`
	Device        postureDevice     `json:"device"`
	Tier          string            `json:"tier"`
	AppCount      int               `json:"app_count"`
	Compliance    postureCompliance `json:"compliance"`
	Evidence      postureEvidence   `json:"evidence"`
	Findings      []postureFinding  `json:"findings"`   // CVE findings for installed apps (P2)
	Updates       []postureUpdate   `json:"updates"`    // available app updates from catalog (P3)
	AppPolicy     postureAppPolicy  `json:"app_policy"` // per-app policy resolution + drift (P6)
}

type postureDevice struct {
	ID           string    `json:"id"`
	Serial       string    `json:"serial"`
	HWUUID       string    `json:"hw_uuid"`
	Hostname     string    `json:"hostname"`
	ComputerName string    `json:"computer_name"`
	HWModel      string    `json:"hw_model"`
	Arch         string    `json:"arch"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	OSBuild      string    `json:"os_build"`
	AgentVersion string    `json:"agent_version"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type postureCompliance struct {
	Platform   string             `json:"platform"`
	Benchmarks []postureBenchmark `json:"benchmarks"`
}

type postureBenchmark struct {
	Benchmark        string           `json:"benchmark"`
	BenchmarkVersion string           `json:"benchmark_version"`
	Implemented      int              `json:"implemented"`
	BenchmarkTotal   int              `json:"benchmark_total"`
	Passed           int              `json:"passed"`
	Failed           int              `json:"failed"`
	NotApplicable    int              `json:"not_applicable"`
	Errors           int              `json:"errors"`
	CompliancePct    float64          `json:"compliance_pct"`
	Sections         []postureSection `json:"sections"`
}

type postureSection struct {
	Section  string           `json:"section"`
	Passed   int              `json:"passed"`
	Total    int              `json:"total"`
	Controls []postureControl `json:"controls"`
}

type postureControl struct {
	RuleKey       string    `json:"rule_key"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	ObservedValue *string   `json:"observed_value"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

type postureEvidence struct {
	CoverageWindowDays     int         `json:"coverage_window_days"`
	ScansLogged            int         `json:"scans_logged"`
	LastSignedReportDigest *string     `json:"last_signed_report_digest"`
	RecentScanTimes        []time.Time `json:"recent_scan_times"`
}

// postureFinding is one CVE finding for an installed app, sourced from
// device_cve_findings (populated by the patched-cve-sync worker — PAT-335).
type postureFinding struct {
	CVEID             string     `json:"cve_id"`
	Description       string     `json:"description"`
	DescriptionSource string     `json:"description_source"`
	CVSSScore         *float64   `json:"cvss_v3_score"`
	Severity          string     `json:"severity"`
	PublishedAt       *time.Time `json:"published_at"`
	AppName           string     `json:"app_name"`
	AppVersion        string     `json:"app_version"`
	MatchConfidence   string     `json:"match_confidence"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
}

// postureUpdate describes a single available app update sourced from the
// app_catalog_entries table (the server's projection of the updater catalog).
// linked_cve_ids lists CVE IDs from device_cve_findings that affect this app
// at the installed version — updating to target_version closes them.
type postureUpdate struct {
	AppName        string   `json:"app_name"`
	Identifier     string   `json:"identifier"`
	Label          string   `json:"label"` // Installomator label — the daemon's install trigger matches on this, NOT on identifier (a bundle ID)
	CurrentVersion string   `json:"current_version"`
	TargetVersion  string   `json:"target_version"`
	Source         string   `json:"source"`         // "catalog" | "manual"
	LinkedCVEIDs   []string `json:"linked_cve_ids"` // empty slice when no CVEs link
}

// postureAppPolicy is the resolved per-device app-policy view (P6).
// apps: every installed app with its resolved policy label.
// drift: advisory findings for policy violations (mandatory missing, unapproved present).
type postureAppPolicy struct {
	Apps  []postureAppPolicyEntry `json:"apps"`
	Drift []postureAppDrift       `json:"drift"`
}

// postureAppPolicyEntry resolves the tenant policy for one installed app.
// user_removable is false when policy is "mandatory" (agent should not offer
// to uninstall it). enforcement_tier gates what the caller may do in response.
type postureAppPolicyEntry struct {
	AppName         string `json:"app_name"`
	Identifier      string `json:"identifier"`       // bundle_id / CFBundleIdentifier
	Label           string `json:"label"`            // Installomator catalog label — install/uninstall triggers and the daemon's install-status lookup match on this, NOT on identifier. Empty string when no catalog entry matches (app has a policy but isn't in the install/update catalog) — always present so Swift's non-optional decode never fails.
	Policy          string `json:"policy"`           // mandatory|approved|unapproved|unmanaged
	UserRemovable   bool   `json:"user_removable"`   // false when policy = "mandatory"
	EnforcementTier string `json:"enforcement_tier"` // report_deploy|patch|managed (canonical as of PAT-1250; legacy report/app_management still accepted on write and rewritten to canonical, never emitted here)
}

// postureAppDrift is one drift finding emitted when a policy violation is detected.
// drift_type:
//
//	"mandatory_missing"  — a mandatory app is not installed on this device.
//	"unapproved_present" — an unapproved app is installed on this device.
type postureAppDrift struct {
	DriftType       string `json:"drift_type"` // mandatory_missing|unapproved_present
	AppName         string `json:"app_name"`
	Identifier      string `json:"identifier"`
	Policy          string `json:"policy"`
	EnforcementTier string `json:"enforcement_tier"`
}

// -- Public constructor -------------------------------------------------------

// PostureHandler serves GET /v1/posture on the public listener.
func PostureHandler(pool *pgxpool.Pool, key *agentconfig.SigningKey, rl *ratelimit.TenantLimiter, replaySkew time.Duration) http.HandlerFunc {
	authFn := func(ctx context.Context, authHeader, sigHeader, ts, nonce string, body []byte) (string, string, error) {
		tenantID, deviceID, secret, err := auth.LookupDeviceByBearer(ctx, pool, authHeader)
		if err != nil {
			return "", "", err
		}
		if err := auth.VerifyHMACSigned(secret, http.MethodGet, auth.EndpointPosture, ts, nonce, body, sigHeader); err != nil {
			return "", "", err
		}
		return tenantID, deviceID, nil
	}
	fetchFn := func(ctx context.Context, tenantID, deviceID string) (postureResp, error) {
		return buildPostureResponse(ctx, pool, tenantID, deviceID)
	}
	return newPostureHandlerWithLegacyExecutionCompatibility(authFn, fetchFn, key, rl, replaySkew, pool, false)
}

// newPostureHandler builds the handler with injectable functions for testing.
// rl and pool may be nil in unit tests that stub authFn — replay validation is
// skipped when pool is nil.
func newPostureHandler(
	authFn postureAuthFn,
	fetchFn postureFetchFn,
	key *agentconfig.SigningKey,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	pool *pgxpool.Pool,
) http.HandlerFunc {
	return newPostureHandlerWithLegacyExecutionCompatibility(authFn, fetchFn, key, rl, replaySkew, pool, false)
}

func newPostureHandlerWithLegacyExecutionCompatibility(
	authFn postureAuthFn,
	fetchFn postureFetchFn,
	key *agentconfig.SigningKey,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	pool *pgxpool.Pool,
	legacyExecutionEnabled bool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "posture")

		// GET — body is empty; HMAC is computed over zero bytes.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Warn("read body failed", "err", err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		tenantID, deviceID, err := authFn(r.Context(), r.Header.Get("Authorization"), r.Header.Get("X-Patched-Signature"), r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body)
		if err != nil {
			// This counter is deliberately narrower than all authentication
			// failures: only a live tenant-level credential recognized by
			// LookupDeviceByBearer yields ErrDeviceCredentialRequired. Unknown,
			// malformed, expired, and revoked credentials retain the same generic
			// 401 without incrementing the alerting signal.
			if errors.Is(err, auth.ErrDeviceCredentialRequired) {
				metrics.DeviceCredentialRequiredTotal.WithLabelValues("posture").Inc()
			}
			logger.Warn("auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		logger = logger.With("tenant_id", tenantID, "device_id", deviceID)

		// Per-tenant rate limit.
		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				logger.Warn("rate limit exceeded")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		// Replay protection — pool may be nil in tests.
		if pool != nil {
			if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
				logger.Warn("timestamp validation failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
				logger.Warn("nonce check failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		resp, err := fetchFn(r.Context(), tenantID, deviceID)
		if err != nil {
			if errors.Is(err, report.ErrDeviceNotFound) {
				// Credential references a device that was purged — uniform 401 to
				// avoid leaking the deletion event.
				logger.Warn("device not found for valid credential")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			logger.Error("build posture failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !legacyExecutionEnabled {
			neutraliseLegacyExecutionPosture(&resp)
		}

		// PAT-910: bind the signed body to the authenticated tenant (from the
		// credential, never from the fetch data or any request parameter) and
		// stamp the server sign time as the monotonic anti-rollback value, then
		// Ed25519-sign the canonical posture bytes and return the same envelope
		// shape as GET /v1/agent-config. The endpoint verifies the signature over
		// the transmitted signed_payload bytes as-is (no reconstruction), so
		// field ordering here is irrelevant to verification.
		resp.TenantID = tenantID
		resp.IssuedAt = time.Now().UTC().Format(time.RFC3339)

		canonical, err := json.Marshal(resp)
		if err != nil {
			logger.Error("marshal posture failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sigB64, keyID := agentconfig.SignBytes(key, canonical)
		env := postureSignedResp{
			SignedPayload: base64.StdEncoding.EncodeToString(canonical),
			KeyID:         keyID,
			Signature:     sigB64,
		}

		logger.Info("posture served",
			"benchmark_count", len(resp.Compliance.Benchmarks),
			"key_id", keyID,
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		_ = json.NewEncoder(w).Encode(env)
	}
}

// neutraliseLegacyExecutionPosture preserves the evidence and governance
// record while removing values consumed as endpoint execution authority. Empty
// labels make legacy execution entries inert, but target versions and all other
// update evidence remain intact for assurance and reporting. An absent
// app-policy entry could instead make the verified-uninstall consumer treat an
// app as removable, so every retained entry is explicitly false.
//
// PAT-1599 CARVE-OUT: resp.Tier below is set to the same fixed legacy
// sentinel as conservativeLegacyAgentProjection (agent_config.go) and is
// NOT part of the assurance/managed vocabulary collapse (migration 0138) —
// excluded from that ticket's "zero remaining occurrences" grep sweep for
// the same reason: it is a PAT-1481 legacy-containment value for
// pre-PAT-1134 binaries, independent of the durable tier. Preserve, do not
// extend, per root AGENTS.md's quarantine rule. resp.AppPolicy.*.EnforcementTier
// below is a different, unrelated field (tenant_app_policies.enforcement_tier,
// migrations 0099/0103) explicitly out of this ticket's scope.
func neutraliseLegacyExecutionPosture(resp *postureResp) {
	resp.Tier = "report_deploy" // PAT-1599 carve-out — see comment above, do not change
	for i := range resp.Updates {
		resp.Updates[i].Label = ""
	}
	for i := range resp.AppPolicy.Apps {
		resp.AppPolicy.Apps[i].Label = ""
		resp.AppPolicy.Apps[i].UserRemovable = false
		resp.AppPolicy.Apps[i].EnforcementTier = "report_deploy"
	}
	for i := range resp.AppPolicy.Drift {
		resp.AppPolicy.Drift[i].EnforcementTier = "report_deploy"
	}
}

// -- Data layer ---------------------------------------------------------------

func buildPostureResponse(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (postureResp, error) {
	// Reuse report.Fetch for device metadata + evaluations + app count.
	// The compliance SQL (DISTINCT ON latest-eval-per-rule) lives there; we
	// do not duplicate it.
	rep, err := report.Fetch(ctx, pool, deviceID)
	if err != nil {
		return postureResp{}, err
	}

	tier := fetchTier(ctx, pool, tenantID)

	evidence, err := fetchEvidence(ctx, pool, deviceID)
	if err != nil {
		return postureResp{}, fmt.Errorf("fetch evidence: %w", err)
	}

	benchmarkTotals, err := fetchBenchmarkTotals(ctx, pool, rep.Device.OS)
	if err != nil {
		return postureResp{}, fmt.Errorf("fetch benchmark totals: %w", err)
	}

	findings, err := fetchCVEFindings(ctx, pool, deviceID)
	if err != nil {
		return postureResp{}, fmt.Errorf("fetch cve findings: %w", err)
	}

	updates, err := fetchUpdateAvailability(ctx, pool, deviceID, rep.Device.OS)
	if err != nil {
		return postureResp{}, fmt.Errorf("fetch update availability: %w", err)
	}

	appPolicy, err := fetchAppPolicy(ctx, pool, tenantID, deviceID, rep)
	if err != nil {
		return postureResp{}, fmt.Errorf("fetch app policy: %w", err)
	}

	return postureResp{
		SchemaVersion: 1,
		TenantID:      tenantID, // PAT-910: signed tenant binding (issued_at is stamped at sign time in the handler)
		GeneratedAt:   rep.GeneratedAt,
		Device: postureDevice{
			ID:           rep.Device.ID,
			Serial:       rep.Device.Serial,
			HWUUID:       rep.Device.HWUUID,
			Hostname:     rep.Device.Hostname,
			ComputerName: rep.Device.ComputerName,
			HWModel:      rep.Device.HWModel,
			Arch:         rep.Device.Arch,
			OS:           rep.Device.OS,
			OSVersion:    rep.Device.OSVersion,
			OSBuild:      rep.Device.OSBuild,
			AgentVersion: rep.Device.AgentVersion,
			FirstSeen:    rep.Device.FirstSeen,
			LastSeen:     rep.Device.LastSeen,
		},
		Tier:       tier,
		AppCount:   len(rep.Apps),
		Compliance: buildCompliance(rep, benchmarkTotals),
		Evidence:   evidence,
		Findings:   findings,
		Updates:    updates,
		AppPolicy:  appPolicy,
	}, nil
}

// fetchTier reads the tenant's agent config tier. Returns "assurance" as
// the safe default when no config row exists or parsing fails (PAT-1599:
// was "report_deploy" before migration 0138 collapsed the vocabulary — this
// is the ordinary no-row-yet default, not the neutraliseLegacyExecutionPosture
// legacy sentinel above, so it moves with the rest of the vocabulary).
func fetchTier(ctx context.Context, pool *pgxpool.Pool, tenantID string) string {
	var bodyBytes []byte
	if err := pool.QueryRow(ctx, `
		SELECT body FROM agent_config WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&bodyBytes); err != nil {
		return "assurance"
	}
	var body struct {
		Tier string `json:"tier"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil || body.Tier == "" {
		return "assurance"
	}
	return body.Tier
}

// fetchEvidence counts successful scans in the last 30 days for this device.
func fetchEvidence(ctx context.Context, pool *pgxpool.Pool, deviceID string) (postureEvidence, error) {
	const windowDays = 30
	const recentLimit = 5

	rows, err := pool.Query(ctx, `
		SELECT received_at
		FROM raw_payloads
		WHERE device_id = $1::uuid
		  AND received_at > now() - make_interval(days => $2)
		  AND extracted_at IS NOT NULL
		ORDER BY received_at DESC
		LIMIT $3
	`, deviceID, windowDays, recentLimit)
	if err != nil {
		return postureEvidence{}, err
	}
	defer rows.Close()

	var times []time.Time
	for rows.Next() {
		var t time.Time
		if err := rows.Scan(&t); err != nil {
			return postureEvidence{}, err
		}
		times = append(times, t)
	}
	if err := rows.Err(); err != nil {
		return postureEvidence{}, err
	}

	var total int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM raw_payloads
		WHERE device_id = $1::uuid
		  AND received_at > now() - make_interval(days => $2)
		  AND extracted_at IS NOT NULL
	`, deviceID, windowDays).Scan(&total); err != nil {
		return postureEvidence{}, err
	}

	if times == nil {
		times = []time.Time{}
	}

	// Latest compliance PDF digest — written by ComplianceReportHandler each time
	// a report is generated. Nil when no report has been generated yet.
	var digest *string
	if err := pool.QueryRow(ctx, `
		SELECT sha256
		FROM device_report_digests
		WHERE device_id = $1::uuid AND report_type = 'compliance'
		ORDER BY generated_at DESC
		LIMIT 1
	`, deviceID).Scan(&digest); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return postureEvidence{}, err
	}

	return postureEvidence{
		CoverageWindowDays:     windowDays,
		ScansLogged:            total,
		LastSignedReportDigest: digest,
		RecentScanTimes:        times,
	}, nil
}

// fetchBenchmarkTotals returns the count of enabled compliance_rules per
// (benchmark, benchmark_version) for the device's OS platform.
func fetchBenchmarkTotals(ctx context.Context, pool *pgxpool.Pool, osName string) (map[string]int, error) {
	platform := "macos"
	if strings.EqualFold(osName, "windows") {
		platform = "windows"
	}
	rows, err := pool.Query(ctx, `
		SELECT benchmark, benchmark_version, COUNT(*)
		FROM compliance_rules
		WHERE platform = $1 AND enabled = true
		GROUP BY benchmark, benchmark_version
	`, platform)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totals := map[string]int{}
	for rows.Next() {
		var bm, ver string
		var cnt int
		if err := rows.Scan(&bm, &ver, &cnt); err != nil {
			return nil, err
		}
		totals[bm+"||"+ver] = cnt
	}
	return totals, rows.Err()
}

// fetchCVEFindings reads pre-matched CVE findings from device_cve_findings for
// this device. The findings are populated by the patched-cve-sync worker (PAT-335);
// this function is read-only and never triggers a rescan.
// Returns an empty slice (not nil) when no findings exist, so JSON serialises
// as [] rather than null.
func fetchCVEFindings(ctx context.Context, pool *pgxpool.Pool, deviceID string) ([]postureFinding, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			f.cve_id,
			e.description,
			e.description_source,
			e.cvss_v3_score,
			e.severity,
			e.published_at,
			f.app_name,
			f.app_version,
			f.match_confidence,
			f.last_seen_at
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		WHERE f.device_id = $1::uuid
		ORDER BY e.cvss_v3_score DESC NULLS LAST, f.cve_id
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := []postureFinding{}
	for rows.Next() {
		var f postureFinding
		if err := rows.Scan(
			&f.CVEID, &f.Description, &f.DescriptionSource, &f.CVSSScore, &f.Severity, &f.PublishedAt,
			&f.AppName, &f.AppVersion, &f.MatchConfidence, &f.LastSeenAt,
		); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// fetchUpdateAvailability compares installed app versions against the
// app_catalog_entries table (the server-side projection of the updater catalog).
// An update row is emitted for every app where the installed version differs
// from the catalog's latest_version. linked_cve_ids cross-references existing
// device_cve_findings so the UI can show which CVEs a given update closes.
//
// KNOWN LIMITATION (PAT-1561): app_catalog_entries has had no automated
// refresh since its seed migration (migrations/0030) - see that
// file's header for the full gap. latest_version here is stale, not live.
//
// Join strategy (macOS): signer (team_id = verified_signer) narrows candidates,
// but is never sufficient alone — a vendor's Team ID commonly signs many
// unrelated products (e.g. Microsoft's UBF8T346G9 signs Word, Excel, Teams,
// Edge, VS Code, ...), so team_id-only matching cross-joins one installed app
// against every catalog entry from the same vendor. Always require a name
// match too (substring either direction, to tolerate naming variants like
// "Microsoft Teams classic" vs. catalog "Microsoft Teams"); signer match is an
// additional precision layer on top of that, not a replacement for it.
// Windows: name match only (no verified_signer concept here yet).
// Returns an empty slice (never nil) when no updates are available.
func fetchUpdateAvailability(ctx context.Context, pool *pgxpool.Pool, deviceID, osName string) ([]postureUpdate, error) {
	platform := "macOS"
	if strings.EqualFold(osName, "windows") {
		platform = "Windows"
	}

	rows, err := pool.Query(ctx, `
		SELECT
			da.name,
			da.identifier,
			ace.label,
			da.version AS current_version,
			ace.latest_version AS target_version,
			ace.source,
			COALESCE(
				array_agg(dcf.cve_id ORDER BY dcf.cve_id)
				FILTER (WHERE dcf.cve_id IS NOT NULL),
				'{}'
			) AS linked_cve_ids
		FROM device_apps da
		JOIN app_catalog_entries ace ON (
			ace.platform = $2
			-- Literal substring check (strpos, not LIKE) so a literal '%' or '_'
			-- in either name is never misread as a wildcard. ace.name != '' guards
			-- against a blank catalog name trivially "containing" every app name
			-- (strpos(x, '') is always 1/truthy in Postgres).
			AND ace.name != ''
			AND (
				strpos(lower(da.name), lower(ace.name)) > 0
				OR strpos(lower(ace.name), lower(da.name)) > 0
			)
			AND (ace.verified_signer IS NULL OR da.team_id = ace.verified_signer)
		)
		LEFT JOIN device_cve_findings dcf ON (
			dcf.device_id = $1::uuid
			AND dcf.app_name = da.name
			AND dcf.app_version = da.version
		)
		WHERE da.device_id = $1::uuid
		  AND da.version IS NOT NULL
		  AND da.version != ace.latest_version
		GROUP BY da.name, da.identifier, ace.label, da.version, ace.latest_version, ace.source
		ORDER BY da.name
	`, deviceID, platform)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	updates := []postureUpdate{}
	for rows.Next() {
		var u postureUpdate
		if err := rows.Scan(
			&u.AppName, &u.Identifier, &u.Label, &u.CurrentVersion,
			&u.TargetVersion, &u.Source, &u.LinkedCVEIDs,
		); err != nil {
			return nil, err
		}
		updates = append(updates, u)
	}
	return updates, rows.Err()
}

// mandatoryPolicySatisfied reports whether ANY installed app on the device
// matches every populated identity field in the given mandatory policy
// (case-insensitive). Each mandatory policy is tested independently against
// the full app inventory — not against a single first-resolved policy per
// app — so a mandatory policy is never falsely reported missing just because
// the same installed app also happens to match a different, overlapping
// policy by a different key (PAT-1147: Opera matched 'approved' by
// bundle_id and 'mandatory' by name; the old first-match resolution only
// ever marked one of the two policies as seen).
func mandatoryPolicySatisfied(p tenantPolicy, apps []report.App, deviceOS string) bool {
	for _, app := range apps {
		if policyMatchesInstalledApp(p, installedAppPolicyIdentity{
			TeamID:   app.TeamID,
			BundleID: app.BundleID,
			WingetID: installedWingetID(app.BundleID, app.IdentifierKind, deviceOS),
			Name:     app.Name,
		}) {
			return true
		}
	}
	return false
}

// fetchAppPolicy resolves the tenant app-policy for every installed app on the
// device and computes drift findings (PAT-470).
//
// Every populated stored identity field must match. Exact-platform rows replace
// any-platform rows only for the same full tuple; overlapping matching tuples
// then resolve by field count, stable identity precedence, and a deterministic
// tie-break.
//
// Drift findings:
//
//	mandatory_missing  — a mandatory policy matched by no installed app
//	                      (checked independently per policy — see
//	                      mandatoryPolicySatisfied).
//	unapproved_present — an installed app resolved to the unapproved policy.
func fetchAppPolicy(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, rep report.Report) (postureAppPolicy, error) {
	platform := devicePolicyPlatform(rep.Device.OS)

	// Load all policies for this tenant that are relevant to this platform.
	rows, err := pool.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, source
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid
		  AND (platform = $2 OR platform = 'any')
	`, tenantID, platform)
	if err != nil {
		return postureAppPolicy{}, err
	}
	defer rows.Close()

	var policies []tenantPolicy
	for rows.Next() {
		var p tenantPolicy
		if err := rows.Scan(&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform, &p.Policy, &p.EnforcementTier, &p.MinVersion, &p.Source); err != nil {
			return postureAppPolicy{}, err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return postureAppPolicy{}, err
	}

	// Load the catalog so each policy entry can carry the Installomator label
	// (see postureAppPolicyEntry.Label) — the Self Service App Catalog's
	// install/uninstall triggers and its install-status lookup both match on
	// label, not on identifier (a bundle ID), so without this every "Get"/
	// "Uninstall" action there silently no-ops and installed apps never show
	// as installed. Same signer+name matching as fetchUpdateAvailability
	// (never signer alone — see that function's comment for why).
	catalogPlatform := "macOS"
	if platform == "windows" {
		catalogPlatform = "Windows"
	}
	// ORDER BY makes resolveLabel's substring-fallback tie-break deterministic
	// (shortest/most-specific name first) instead of depending on Postgres's
	// unspecified row order, which can vary run to run without an ORDER BY.
	catalogRows, err := pool.Query(ctx, `
		SELECT label, name, verified_signer FROM app_catalog_entries
		WHERE platform = $1
		ORDER BY length(name), label
	`, catalogPlatform)
	if err != nil {
		return postureAppPolicy{}, err
	}
	defer catalogRows.Close()

	type catalogRow struct {
		Label          string
		Name           string
		VerifiedSigner *string
	}
	var catalog []catalogRow
	for catalogRows.Next() {
		var c catalogRow
		if err := catalogRows.Scan(&c.Label, &c.Name, &c.VerifiedSigner); err != nil {
			return postureAppPolicy{}, err
		}
		catalog = append(catalog, c)
	}
	if err := catalogRows.Err(); err != nil {
		return postureAppPolicy{}, err
	}

	resolveLabel := func(appName, teamID string) string {
		nameLower := strings.ToLower(strings.TrimSpace(appName))
		// Prefer an exact name match to disambiguate when a signer covers
		// multiple unrelated products (e.g. Microsoft's Team ID signs Word,
		// Excel, Teams, Edge, ...).
		for _, c := range catalog {
			if strings.ToLower(c.Name) == nameLower &&
				(c.VerifiedSigner == nil || strings.EqualFold(teamID, *c.VerifiedSigner)) {
				return c.Label
			}
		}
		// Fall back to substring match either direction (tolerates naming
		// variants like "Microsoft Teams classic" vs. catalog "Microsoft Teams").
		for _, c := range catalog {
			cNameLower := strings.ToLower(c.Name)
			// An empty catalog name would trivially "contain" every app name —
			// guard against a malformed/blank row acting as a wildcard match.
			if cNameLower == "" {
				continue
			}
			if (strings.Contains(nameLower, cNameLower) || strings.Contains(cNameLower, nameLower)) &&
				(c.VerifiedSigner == nil || strings.EqualFold(teamID, *c.VerifiedSigner)) {
				return c.Label
			}
		}
		return ""
	}

	// tenant_allowlists is the customer-facing "approve this app" action (the
	// dashboard's Software Catalogue Status column); tenant_app_policies is a
	// separate, more granular mechanism (explicit mandatory/unapproved
	// overrides, enforcement tiers). Approving an app in the allowlist should
	// be sufficient on its own for it to count as "approved" here — it
	// shouldn't require a second, independent action in tenant_app_policies
	// too. Only 'allowed' rows count: 'system_baseline' apps (OS utilities
	// auto-approved by name/prefix) are noise in a customer-facing "your
	// approved software" list, and 'flagged'/'marked_for_uninstall' clearly
	// shouldn't grant approved status. Explicit tenant_app_policies rows
	// (loaded above) still take precedence when both exist — checked first
	// in resolvePolicy below.
	//
	// Scoped to match_mode = 'exact_name' only. name_publisher/publisher_only
	// rows need the same publisher-aware matching the canonical allowlist
	// matcher uses (see TenantAllowlistScanHandler) — naively keying this
	// fallback on name alone would either over-approve (ignoring a
	// name_publisher row's publisher constraint) or under/mis-approve
	// (publisher_only rows carry a placeholder name, not a real match key).
	// exact_name is both the schema default and the common case; the other
	// two modes simply aren't covered by this fallback yet.
	allowlistRows, err := pool.Query(ctx, `
		SELECT LOWER(name)
		FROM tenant_allowlists
		WHERE tenant_id = $1::uuid
		  AND (platform = $2 OR platform = 'any')
		  AND enforcement = 'allowed'
		  AND match_mode = 'exact_name'
	`, tenantID, platform)
	if err != nil {
		return postureAppPolicy{}, err
	}
	defer allowlistRows.Close()

	allowedByName := map[string]bool{}
	for allowlistRows.Next() {
		var name string
		if err := allowlistRows.Scan(&name); err != nil {
			return postureAppPolicy{}, err
		}
		allowedByName[name] = true
	}
	if err := allowlistRows.Err(); err != nil {
		return postureAppPolicy{}, err
	}

	// If no policies are configured for this tenant, return empty but valid slices.
	if len(policies) == 0 && len(allowedByName) == 0 {
		return postureAppPolicy{
			Apps:  []postureAppPolicyEntry{},
			Drift: []postureAppDrift{},
		}, nil
	}

	policyIndex := buildTenantPolicyIndex(policies)

	// Resolve policy for each installed app. Explicit tenant_app_policies
	// entries (by team_id/bundle_id/name) take precedence; an allowlist
	// 'allowed' row is checked only as a fallback so a plain allowlist
	// approval is enough on its own without a redundant app-policy entry.
	resolvePolicy := func(app report.App) (tenantPolicy, bool) {
		if p, ok := policyIndex.resolveAppPolicy(app.TeamID, app.BundleID, app.IdentifierKind, app.Name, rep.Device.OS); ok {
			return p, true
		}
		if allowedByName[strings.ToLower(app.Name)] {
			// PAT-1250: synthesised (not DB-loaded) policy row, so the
			// canonical spelling has to be chosen explicitly here rather
			// than inheriting it from a stored value — "report" would emit
			// the legacy name into this signed response.
			return tenantPolicy{Policy: "approved", EnforcementTier: "report_deploy"}, true
		}
		return tenantPolicy{}, false
	}

	appEntries := make([]postureAppPolicyEntry, 0, len(rep.Apps))
	driftItems := []postureAppDrift{}

	for _, app := range rep.Apps {
		p, matched := resolvePolicy(app)
		if !matched {
			continue // unmanaged by default — omit from per-app list (clean output for agents)
		}

		entry := postureAppPolicyEntry{
			AppName:         app.Name,
			Identifier:      app.BundleID,
			Label:           resolveLabel(app.Name, app.TeamID),
			Policy:          p.Policy,
			UserRemovable:   p.Policy != "mandatory",
			EnforcementTier: p.EnforcementTier,
		}
		appEntries = append(appEntries, entry)

		if p.Policy == "unapproved" {
			driftItems = append(driftItems, postureAppDrift{
				DriftType:       "unapproved_present",
				AppName:         app.Name,
				Identifier:      app.BundleID,
				Policy:          p.Policy,
				EnforcementTier: p.EnforcementTier,
			})
		}
	}

	// Emit mandatory_missing findings for effective mandatory policies with no
	// device match. Platform override is resolved before absence, then each
	// surviving policy is tested independently against the full app inventory
	// (mandatoryPolicySatisfied) rather than against a single first-resolved
	// policy per app, so an overlapping policy on the same app can't mask
	// this one as missing (PAT-1147).
	for _, p := range effectiveTenantPolicies(policies, rep.Device.OS) {
		if p.Policy != "mandatory" {
			continue
		}
		if mandatoryPolicySatisfied(p, rep.Apps, rep.Device.OS) {
			continue
		}
		name := ""
		if p.Name != nil {
			name = *p.Name
		}
		bundleID := ""
		if p.BundleID != nil {
			bundleID = *p.BundleID
		}
		driftItems = append(driftItems, postureAppDrift{
			DriftType:       "mandatory_missing",
			AppName:         name,
			Identifier:      bundleID,
			Policy:          "mandatory",
			EnforcementTier: p.EnforcementTier,
		})
	}

	return postureAppPolicy{
		Apps:  appEntries,
		Drift: driftItems,
	}, nil
}

// buildCompliance groups EvalRows by benchmark, then by section within each
// benchmark, computing aggregate pass/fail counts at both levels.
func buildCompliance(rep report.Report, benchmarkTotals map[string]int) postureCompliance {
	platform := "macOS"
	if strings.EqualFold(rep.Device.OS, "windows") {
		platform = "Windows"
	}

	type bmKey struct{ benchmark, version string }
	type sectionMap map[string][]postureControl

	bmSections := map[bmKey]sectionMap{}
	var bmOrder []bmKey

	for _, ev := range rep.Evaluations {
		k := bmKey{ev.Benchmark, ev.BenchmarkVersion}
		if _, ok := bmSections[k]; !ok {
			bmSections[k] = sectionMap{}
			bmOrder = append(bmOrder, k)
		}
		sec := extractSection(ev.RuleKey)
		bmSections[k][sec] = append(bmSections[k][sec], postureControl{
			RuleKey:       ev.RuleKey,
			Title:         ev.Title,
			Severity:      ev.Severity,
			Status:        ev.Status,
			ObservedValue: ev.ObservedValue,
			EvaluatedAt:   ev.EvaluatedAt,
		})
	}

	benchmarks := make([]postureBenchmark, 0, len(bmOrder))
	for _, k := range bmOrder {
		sm := bmSections[k]

		sectionKeys := make([]string, 0, len(sm))
		for s := range sm {
			sectionKeys = append(sectionKeys, s)
		}
		sort.Strings(sectionKeys)

		sections := make([]postureSection, 0, len(sectionKeys))
		var totPass, totFail, totNA, totErr int

		for _, sec := range sectionKeys {
			controls := sm[sec]
			var secPass int
			for _, c := range controls {
				switch c.Status {
				case "pass":
					totPass++
					secPass++
				case "fail":
					totFail++
				case "not_applicable":
					totNA++
				case "error":
					totErr++
				}
			}
			sections = append(sections, postureSection{
				Section:  sec,
				Passed:   secPass,
				Total:    len(controls),
				Controls: controls,
			})
		}

		// implemented = count of evaluations for this benchmark.
		var implemented int
		for _, ev := range rep.Evaluations {
			if ev.Benchmark == k.benchmark && ev.BenchmarkVersion == k.version {
				implemented++
			}
		}

		bmTotal := benchmarkTotals[k.benchmark+"||"+k.version]

		denom := totPass + totFail + totErr
		var pct float64
		if denom > 0 {
			pct = (float64(totPass) / float64(denom)) * 100.0
		}

		benchmarks = append(benchmarks, postureBenchmark{
			Benchmark:        k.benchmark,
			BenchmarkVersion: k.version,
			Implemented:      implemented,
			BenchmarkTotal:   bmTotal,
			Passed:           totPass,
			Failed:           totFail,
			NotApplicable:    totNA,
			Errors:           totErr,
			CompliancePct:    pct,
			Sections:         sections,
		})
	}

	if benchmarks == nil {
		benchmarks = []postureBenchmark{}
	}
	return postureCompliance{
		Platform:   platform,
		Benchmarks: benchmarks,
	}
}

// extractSection derives the CIS section / chapter prefix from a rule_key so
// buildCompliance can group controls into benchmark sections.
//
// macOS (dot notation):  "cis.1.1" → "1", "cis.2.10.3" → "2", "baseline.foo" → "foo"
// Windows (underscore):  "cis_win_9_1_1_firewall_domain" → "9"
//
//	"cis_win_18_10_11_bitlocker_os_drive" → "18"
//
// Non-CIS (fallback):    "patched_win_mdm_enrolled" → "patched_win_mdm_enrolled"
func extractSection(ruleKey string) string {
	// macOS: prefix.CHAPTER.control — split on first two dots, take second part.
	parts := strings.SplitN(ruleKey, ".", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	// Windows: cis_win_CHAPTER_subsection_..._descriptive_name
	// Split into at most 4 segments on "_". Segment [2] is the CIS chapter.
	winParts := strings.SplitN(ruleKey, "_", 4)
	if len(winParts) >= 3 && winParts[0] == "cis" && winParts[1] == "win" {
		return winParts[2]
	}
	return ruleKey
}
