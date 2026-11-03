package handlers

// PAT-2207 contract tests for GET /v1/portal/overview/cards: the Overview
// information cards read model the portal's Brand v3 Overview (PAT-2190)
// renders from. The contract under test (contracts/portal-api.md):
//
//   - Every card carries an explicit state (value, zero, unknown,
//     unavailable, partial), a named source, freshness timestamps, a
//     completeness signal and a bounded reason whenever it is incomplete.
//   - zero, unknown, unavailable and partial are distinct on the wire.
//   - The tenant comes only from the portalauth identity.
//   - A failing card source degrades that card to unavailable; only the base
//     device query may fail the whole response.
//   - GET /v1/portal/overview is unchanged.
//
// DB-backed: drives the real handler and the real report/softwaregov
// queries against a migrated Postgres. Skipped without TEST_DATABASE_URL
// unless PATCHED_DB_TESTS_REQUIRED says a database was promised.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

const pocPath = "/v1/portal/overview/cards"

// pocCardIDs is every card the contract promises, always present.
var pocCardIDs = []string{
	"devices",
	"os_updates",
	"vulnerabilities",
	"cis_posture",
	"browser_extensions",
	"high_risk_software",
	"software_awaiting_approval",
	"exceptions_review",
	"agent_health",
	"recent_activity",
}

// pocFailableCards are the cards whose source can fail without taking the
// response down. "devices" is the base query and is deliberately absent;
// recent_activity has no source yet.
var pocFailableCards = []string{
	"os_updates",
	"vulnerabilities",
	"cis_posture",
	"browser_extensions",
	"high_risk_software",
	"software_awaiting_approval",
	"exceptions_review",
	"agent_health",
}

var pocStates = map[string]bool{"value": true, "zero": true, "unknown": true, "unavailable": true, "partial": true}
var pocScopes = map[string]bool{"current_snapshot": true, "bounded_window": true}
var pocReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// pocCardKeys are the keys every card object must carry, explicit null
// included, so a consumer never has to infer meaning from a missing key.
var pocCardKeys = []string{"state", "source", "scope", "window", "freshness", "completeness", "values", "unavailable_signals"}

type pocWindow struct {
	Since *time.Time `json:"since"`
	Until *time.Time `json:"until"`
	Days  int        `json:"days"`
	Basis string     `json:"basis"`
}

type pocSignal struct {
	Signal string `json:"signal"`
	Reason string `json:"reason"`
}

type pocCard struct {
	State     string     `json:"state"`
	Source    string     `json:"source"`
	Scope     string     `json:"scope"`
	Window    *pocWindow `json:"window"`
	Freshness struct {
		GeneratedAt *time.Time `json:"generated_at"`
		ObservedAt  *time.Time `json:"observed_at"`
	} `json:"freshness"`
	Completeness struct {
		Complete *bool   `json:"complete"`
		Reason   *string `json:"reason"`
	} `json:"completeness"`
	Values             map[string]json.RawMessage `json:"values"`
	UnavailableSignals []pocSignal                `json:"unavailable_signals"`
}

type pocResp struct {
	GeneratedAt *time.Time `json:"generated_at"`
	Thresholds  struct {
		ActiveWithinHours            int `json:"active_within_hours"`
		SilentAfterDays              int `json:"silent_after_days"`
		ExceptionReviewDueWithinDays int `json:"exception_review_due_within_days"`
	} `json:"thresholds"`
	Cards map[string]pocCard `json:"cards"`
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func pocPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not — PAT-2207 overview cards DB coverage would silently evaporate")
		}
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-2207 overview cards DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func pocSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func pocTenant(t *testing.T, pool *pgxpool.Pool, label string) string {
	t.Helper()
	s := pocSuffix(t)
	return parSeedTenant(t, context.Background(), pool, "pat2207-"+label+"-"+s, "pat2207-token-"+label+"-"+s, "pat2207-hmac-"+label+"-"+s+"-padpadpad")
}

// pocDevice seeds one device. lastSeenSQL is an SQL expression evaluated by
// the database (DB time is the contract's clock, never the test's), and
// pendingUpdates is a JSON array literal or "" for NULL (no update evidence).
func pocDevice(t *testing.T, pool *pgxpool.Pool, tenantID, host, osName, lastSeenSQL, pendingUpdates string) string {
	t.Helper()
	var pending any
	if pendingUpdates != "" {
		pending = pendingUpdates
	}
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen, pending_updates)
		VALUES ($1::uuid, $2, gen_random_uuid(), $2, $3, '15.5', 'arm64', `+lastSeenSQL+`, $4::jsonb)
		RETURNING id::text
	`, tenantID, host+"-"+pocSuffix(t), osName, pending).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", host, err)
	}
	return id
}

func pocExec(t *testing.T, pool *pgxpool.Pool, what, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func pocRetire(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID string) {
	t.Helper()
	pocExec(t, pool, "retire device", `
		INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
		VALUES ($1::uuid, $2::uuid, 'retire', 'admin@pat2207.example')
	`, tenantID, deviceID)
}

// pocEvaluations seeds one pass (FileVault) and one fail (firewall) latest
// evaluation, or two passes when allPass.
func pocEvaluations(t *testing.T, pool *pgxpool.Pool, deviceID string, allPass bool) {
	t.Helper()
	pocExec(t, pool, "seed evaluations", `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
		SELECT $1::uuid, id,
		       CASE WHEN $2 OR rule_key = 'cis_macos_2_5_1_1_filevault' THEN 'pass' ELSE 'fail' END,
		       'observed', severity, benchmark_version
		FROM compliance_rules
		WHERE rule_key IN ('cis_macos_2_5_1_1_filevault', 'cis_macos_2_5_2_2_firewall')
	`, deviceID, allPass)
}

func pocConfirmedCVE(t *testing.T, pool *pgxpool.Pool, deviceID, severity string) {
	t.Helper()
	cveID := "CVE-2099-" + pocSuffix(t)
	pocExec(t, pool, "seed cve entry", `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ($1, 'PAT-2207 test vulnerability', 'nvd', 9.8, $2)
	`, cveID, severity)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cve_feed_entries WHERE cve_id = $1`, cveID)
	})
	pocExec(t, pool, "seed cve finding", `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, cvss_v3_score, severity, match_confidence)
		VALUES ($1::uuid, $2, 'VulnApp', '1.0.0', 9.8, $3, 'version_confirmed')
	`, deviceID, cveID, severity)
}

// pocEnsureFullMatchRun makes sure the estate-wide CVE matcher has a
// completed full match on record, so a zero count is an authoritative zero.
// Insert-if-absent only: cve_match_runs is global and never rolled back here.
func pocEnsureFullMatchRun(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	pocExec(t, pool, "ensure full_match run", `
		INSERT INTO cve_match_runs (run_kind, completed_at) VALUES ('full_match', now())
		ON CONFLICT (run_kind) DO NOTHING
	`)
}

func pocExtension(t *testing.T, pool *pgxpool.Pool, deviceID, extensionID, risk string) {
	t.Helper()
	pocExec(t, pool, "seed browser extension", `
		INSERT INTO device_browser_extensions (device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'user', 'Default', $2, $2, '1.0', $3)
	`, deviceID, extensionID, risk)
}

// pocInstallation seeds one current macOS application installation in the
// normalised projection, first seen firstSeenSQL (a DB expression).
func pocInstallation(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID, bundleID, name, firstSeenSQL string) {
	t.Helper()
	fp := sha256.Sum256([]byte("pat2207\x1f" + deviceID + "\x1f" + bundleID))
	pocExec(t, pool, "seed software installation", `
		INSERT INTO software_installations
			(tenant_id, device_id, platform, identity_kind, identity_value_normalized,
			 identity_fingerprint, current_name, current_version, first_seen_at, last_seen_at, provenance)
		VALUES ($1::uuid, $2::uuid, 'macos', 'macos_bundle', $3, $4, $5, '1.0', `+firstSeenSQL+`, now(), 'inventory_payload')
	`, tenantID, deviceID, bundleID, hex.EncodeToString(fp[:]), name)
}

func pocDeviceApp(t *testing.T, pool *pgxpool.Pool, deviceID, name, bundleID string) {
	t.Helper()
	pocExec(t, pool, "seed device app", `
		INSERT INTO device_apps (device_id, name, identifier, version) VALUES ($1::uuid, $2, $3, '1.0')
	`, deviceID, name, bundleID)
}

func pocApprove(t *testing.T, pool *pgxpool.Pool, tenantID, name string) {
	t.Helper()
	pocExec(t, pool, "seed approved app policy", `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'any', 'approved', 'report')
	`, tenantID, name)
}

// pocException seeds one exception whose review date is reviewSQL (a DB
// date expression, or "NULL").
func pocException(t *testing.T, pool *pgxpool.Pool, tenantID, product, reviewSQL string) {
	t.Helper()
	pocExec(t, pool, "seed exception", `
		INSERT INTO tenant_software_exceptions (tenant_id, product, version, requested_by, review_date)
		VALUES ($1::uuid, $2, '1.0', 'specialist@patched.im', `+reviewSQL+`)
	`, tenantID, product)
}

func pocAgentHealth(t *testing.T, pool *pgxpool.Pool, deviceID string) {
	t.Helper()
	pocExec(t, pool, "seed agent health", `
		INSERT INTO device_agent_health (device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at)
		VALUES ($1::uuid, 'capability_missing', 'log_upload', 'lib_not_installed', now(), now(), 1, false, now())
	`, deviceID)
}

// pocDo calls the handler as the portal identity for tenantID. mutate may
// add client-supplied tenant hints, which must be ignored.
func pocDo(t *testing.T, pool *pgxpool.Pool, tenantID, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if tenantID != "" {
		req = req.WithContext(portalauth.WithIdentity(req.Context(),
			portalauth.Identity{Email: "viewer@pat2207.example", TenantID: tenantID}))
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	PortalOverviewCardsHandler(pool).ServeHTTP(rec, req)
	return rec
}

// pocGet requests the cards as tenantID, requires 200 and a well-formed
// contract, and returns the decoded response.
func pocGet(t *testing.T, pool *pgxpool.Pool, tenantID string, mutate func(*http.Request)) pocResp {
	t.Helper()
	rec := pocDo(t, pool, tenantID, pocPath, mutate)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q)", pocPath, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.Bytes()
	pocCheckContract(t, body)
	var out pocResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// pocCheckContract asserts the invariants that hold for every card in every
// response, whatever the tenant's data.
func pocCheckContract(t *testing.T, body []byte) {
	t.Helper()
	var raw struct {
		GeneratedAt *time.Time                            `json:"generated_at"`
		Cards       map[string]map[string]json.RawMessage `json:"cards"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode contract: %v (body %s)", err, body)
	}
	if raw.GeneratedAt == nil || raw.GeneratedAt.IsZero() {
		t.Errorf("generated_at missing")
	}
	var got []string
	for id := range raw.Cards {
		got = append(got, id)
	}
	sort.Strings(got)
	want := append([]string(nil), pocCardIDs...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("cards = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cards = %v, want exactly %v", got, want)
		}
	}
	for _, id := range pocCardIDs {
		rawCard := raw.Cards[id]
		for _, k := range pocCardKeys {
			if _, ok := rawCard[k]; !ok {
				t.Errorf("card %s: key %q missing (must be present, null when empty)", id, k)
			}
		}
		var c pocCard
		b, _ := json.Marshal(rawCard)
		if err := json.Unmarshal(b, &c); err != nil {
			t.Errorf("card %s: decode: %v", id, err)
			continue
		}
		if !pocStates[c.State] {
			t.Errorf("card %s: state %q not in the contract's state set", id, c.State)
		}
		if c.Source == "" {
			t.Errorf("card %s: source is empty; every card names its source", id)
		}
		if !pocScopes[c.Scope] {
			t.Errorf("card %s: scope %q not in {current_snapshot, bounded_window}", id, c.Scope)
		}
		if c.Freshness.GeneratedAt == nil || c.Freshness.GeneratedAt.IsZero() {
			t.Errorf("card %s: freshness.generated_at missing", id)
		}
		if c.Completeness.Complete == nil {
			t.Errorf("card %s: completeness.complete missing", id)
			continue
		}
		complete := *c.Completeness.Complete
		switch c.State {
		case "value", "zero":
			if !complete {
				t.Errorf("card %s: state %s but complete=false", id, c.State)
			}
			if c.Completeness.Reason != nil {
				t.Errorf("card %s: complete card carries reason %q", id, *c.Completeness.Reason)
			}
		default:
			if complete {
				t.Errorf("card %s: state %s but complete=true", id, c.State)
			}
			if c.Completeness.Reason == nil || !pocReasonPattern.MatchString(*c.Completeness.Reason) {
				t.Errorf("card %s: state %s needs a bounded reason code, got %v", id, c.State, c.Completeness.Reason)
			}
		}
		switch c.State {
		case "unknown", "unavailable":
			if string(rawCard["values"]) != "null" {
				t.Errorf("card %s: state %s must carry values=null, got %s", id, c.State, rawCard["values"])
			}
		default:
			if c.Values == nil {
				t.Errorf("card %s: state %s must carry values", id, c.State)
			}
		}
		if c.Scope == "bounded_window" && c.State != "unavailable" {
			if c.Window == nil || c.Window.Since == nil || c.Window.Until == nil || c.Window.Days <= 0 {
				t.Errorf("card %s: bounded_window card must state its window, got %+v", id, c.Window)
			}
		}
		if c.Scope == "current_snapshot" && string(rawCard["window"]) != "null" {
			t.Errorf("card %s: current_snapshot card must carry window=null, got %s", id, rawCard["window"])
		}
		if c.UnavailableSignals == nil {
			t.Errorf("card %s: unavailable_signals must be an array (possibly empty), got null", id)
		}
		for _, s := range c.UnavailableSignals {
			if s.Signal == "" || !pocReasonPattern.MatchString(s.Reason) {
				t.Errorf("card %s: malformed unavailable signal %+v", id, s)
			}
		}
	}
}

func pocInt(t *testing.T, c pocCard, id, key string) int {
	t.Helper()
	raw, ok := c.Values[key]
	if !ok {
		t.Fatalf("card %s: values.%s missing (values %v)", id, key, c.Values)
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("card %s: values.%s = %s, not an integer", id, key, raw)
	}
	return n
}

func pocWantInt(t *testing.T, c pocCard, id, key string, want int) {
	t.Helper()
	if got := pocInt(t, c, id, key); got != want {
		t.Errorf("card %s: values.%s = %d, want %d", id, key, got, want)
	}
}

func pocWantState(t *testing.T, cards map[string]pocCard, id, want string) pocCard {
	t.Helper()
	c := cards[id]
	if c.State != want {
		reason := "<nil>"
		if c.Completeness.Reason != nil {
			reason = *c.Completeness.Reason
		}
		t.Errorf("card %s: state = %q (reason %s), want %q", id, c.State, reason, want)
	}
	return c
}

func pocWantReason(t *testing.T, c pocCard, id, want string) {
	t.Helper()
	if c.Completeness.Reason == nil || *c.Completeness.Reason != want {
		t.Errorf("card %s: reason = %v, want %q", id, c.Completeness.Reason, want)
	}
}

func pocHasSignal(c pocCard, signal string) bool {
	for _, s := range c.UnavailableSignals {
		if s.Signal == signal {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Populated estate
// ---------------------------------------------------------------------------

// TestPortalOverviewCards_Populated seeds a mixed estate: devices in every
// reporting bucket, a retired device, confirmed CVE exposure, CIS evidence,
// an elevated extension, newly found software, unreviewed software,
// exceptions at each review distance and an admitted agent fault.
func TestPortalOverviewCards_Populated(t *testing.T) {
	pool := pocPool(t)
	tenant := pocTenant(t, pool, "populated")

	activeMac := pocDevice(t, pool, tenant, "active-mac", "macOS", "now() - interval '1 hour'", "[]")
	pocDevice(t, pool, tenant, "active-win", "Windows", "now() - interval '2 hours'", "")
	pocDevice(t, pool, tenant, "stale-mac", "macOS", "now() - interval '3 days'", `[{"label":"macOS 15.6"}]`)
	pocDevice(t, pool, tenant, "silent-mac", "macOS", "now() - interval '30 days'", "")
	// A last_seen ahead of the database clock cannot be classified.
	pocDevice(t, pool, tenant, "future-mac", "macOS", "now() + interval '1 day'", "")
	retired := pocDevice(t, pool, tenant, "retired-mac", "macOS", "now() - interval '40 days'", "")
	pocRetire(t, pool, tenant, retired)

	pocEvaluations(t, pool, activeMac, false)
	pocConfirmedCVE(t, pool, activeMac, "CRITICAL")
	pocExtension(t, pool, activeMac, "pat2207-elevated-"+pocSuffix(t), "elevated")
	pocInstallation(t, pool, tenant, activeMac, "com.example.pat2207.newapp", "PAT2207 New App", "now() - interval '1 day'")
	pocDeviceApp(t, pool, activeMac, "PAT2207 Unreviewed App", "com.example.pat2207.unreviewed")
	pocException(t, pool, tenant, "overdue", "(now() AT TIME ZONE 'UTC')::date - 1")
	pocException(t, pool, tenant, "due-soon", "(now() AT TIME ZONE 'UTC')::date + 10")
	pocException(t, pool, tenant, "later", "(now() AT TIME ZONE 'UTC')::date + 90")
	pocException(t, pool, tenant, "no-review", "NULL")
	pocAgentHealth(t, pool, activeMac)

	out := pocGet(t, pool, tenant, nil)

	if out.Thresholds.ActiveWithinHours != 24 || out.Thresholds.SilentAfterDays != 14 || out.Thresholds.ExceptionReviewDueWithinDays != 30 {
		t.Errorf("thresholds = %+v, want active_within_hours=24 silent_after_days=14 exception_review_due_within_days=30", out.Thresholds)
	}

	t.Run("devices buckets are mutually exclusive and sum to total", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "devices", "value")
		pocWantInt(t, c, "devices", "total", 6)
		pocWantInt(t, c, "devices", "active", 2)
		pocWantInt(t, c, "devices", "stale", 1)
		pocWantInt(t, c, "devices", "silent", 1)
		pocWantInt(t, c, "devices", "unknown", 1)
		pocWantInt(t, c, "devices", "retired", 1)
		if c.Freshness.ObservedAt == nil {
			t.Errorf("devices: freshness.observed_at (newest report) missing")
		}
	})

	t.Run("os updates never claims whole-estate posture", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "os_updates", "partial")
		pocWantInt(t, c, "os_updates", "up_to_date", 1)
		pocWantInt(t, c, "os_updates", "pending", 1)
		if pocInt(t, c, "os_updates", "unknown") < 1 {
			t.Errorf("os_updates: the Windows device has no update evidence and must count as unknown")
		}
	})

	t.Run("vulnerabilities count confirmed critical CVEs", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "vulnerabilities", "value")
		pocWantInt(t, c, "vulnerabilities", "critical", 1)
		pocWantInt(t, c, "vulnerabilities", "high", 0)
	})

	t.Run("cis posture has a score and no regression claim", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "cis_posture", "value")
		var score float64
		if err := json.Unmarshal(c.Values["score"], &score); err != nil || score <= 0 || score >= 100 {
			t.Errorf("cis_posture: score = %s, want strictly between 0 and 100 (one pass, one fail)", c.Values["score"])
		}
		if c.Freshness.ObservedAt == nil {
			t.Errorf("cis_posture: freshness.observed_at (latest evaluation) missing")
		}
		if !pocHasSignal(c, "material_regression") {
			t.Errorf("cis_posture: material_regression must be listed as unavailable, got %+v", c.UnavailableSignals)
		}
	})

	t.Run("browser extensions count elevated risk", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "browser_extensions", "value")
		pocWantInt(t, c, "browser_extensions", "elevated", 1)
		pocWantInt(t, c, "browser_extensions", "total", 1)
	})

	t.Run("high risk software is a bounded newly-found window", func(t *testing.T) {
		c := out.Cards["high_risk_software"]
		if c.Scope != "bounded_window" {
			t.Errorf("high_risk_software: scope = %q, want bounded_window (newly found only until PAT-2182)", c.Scope)
		}
		if c.Window == nil || c.Window.Days != 14 {
			t.Errorf("high_risk_software: window = %+v, want a 14-day window", c.Window)
		}
		// The silent device leaves software coverage incomplete.
		pocWantState(t, out.Cards, "high_risk_software", "partial")
		pocWantReason(t, c, "high_risk_software", "coverage_incomplete")
		if pocInt(t, c, "high_risk_software", "critical")+pocInt(t, c, "high_risk_software", "high") < 1 {
			t.Errorf("high_risk_software: the unsigned-evidence new app must count as critical or high, values %v", c.Values)
		}
	})

	t.Run("software awaiting approval states its coverage", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "software_awaiting_approval", "partial")
		pocWantReason(t, c, "software_awaiting_approval", "coverage_incomplete")
		if pocInt(t, c, "software_awaiting_approval", "products") < 1 {
			t.Errorf("software_awaiting_approval: the unreviewed app must count, values %v", c.Values)
		}
	})

	t.Run("exceptions review is computed on the platform clock", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "exceptions_review", "value")
		pocWantInt(t, c, "exceptions_review", "review_overdue", 1)
		pocWantInt(t, c, "exceptions_review", "review_due_soon", 1)
		pocWantInt(t, c, "exceptions_review", "no_review_date", 1)
		pocWantInt(t, c, "exceptions_review", "total", 4)
		if !pocHasSignal(c, "expiry") {
			t.Errorf("exceptions_review: expiry is not modelled and must be listed as unavailable, got %+v", c.UnavailableSignals)
		}
	})

	t.Run("agent health is partial while devices are not reporting", func(t *testing.T) {
		c := pocWantState(t, out.Cards, "agent_health", "partial")
		pocWantReason(t, c, "agent_health", "devices_not_reporting")
		pocWantInt(t, c, "agent_health", "devices_degraded", 1)
		pocWantInt(t, c, "agent_health", "devices_not_reporting", 2)
	})

	t.Run("recent activity is unavailable until PAT-2197", func(t *testing.T) {
		pocWantState(t, out.Cards, "recent_activity", "unavailable")
	})
}

// ---------------------------------------------------------------------------
// Zero, unknown and the empty tenant
// ---------------------------------------------------------------------------

// TestPortalOverviewCards_Zero proves a checked-and-clean estate serialises
// as zero, distinct from unknown and unavailable.
func TestPortalOverviewCards_Zero(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)

	t.Run("clean estate", func(t *testing.T) {
		tenant := pocTenant(t, pool, "zero")
		mac := pocDevice(t, pool, tenant, "clean-mac", "macOS", "now() - interval '1 hour'", "[]")
		pocEvaluations(t, pool, mac, true)
		pocDeviceApp(t, pool, mac, "PAT2207 Approved App", "com.example.pat2207.approved")
		pocApprove(t, pool, tenant, "PAT2207 Approved App")
		pocInstallation(t, pool, tenant, mac, "com.example.pat2207.approved", "PAT2207 Approved App", "now() - interval '60 days'")

		out := pocGet(t, pool, tenant, nil)

		c := pocWantState(t, out.Cards, "devices", "value")
		pocWantInt(t, c, "devices", "total", 1)
		pocWantInt(t, c, "devices", "active", 1)

		c = pocWantState(t, out.Cards, "vulnerabilities", "zero")
		pocWantInt(t, c, "vulnerabilities", "critical", 0)
		pocWantInt(t, c, "vulnerabilities", "high", 0)
		if c.Freshness.ObservedAt == nil {
			t.Errorf("vulnerabilities: a zero must cite the completed match run it rests on (freshness.observed_at)")
		}

		c = pocWantState(t, out.Cards, "cis_posture", "value")
		var score float64
		if err := json.Unmarshal(c.Values["score"], &score); err != nil || score != 100 {
			t.Errorf("cis_posture: score = %s, want 100", c.Values["score"])
		}

		c = pocWantState(t, out.Cards, "browser_extensions", "zero")
		pocWantInt(t, c, "browser_extensions", "elevated", 0)

		c = pocWantState(t, out.Cards, "high_risk_software", "zero")
		pocWantInt(t, c, "high_risk_software", "critical", 0)
		pocWantInt(t, c, "high_risk_software", "high", 0)

		c = pocWantState(t, out.Cards, "software_awaiting_approval", "zero")
		pocWantInt(t, c, "software_awaiting_approval", "products", 0)

		c = pocWantState(t, out.Cards, "exceptions_review", "zero")
		pocWantInt(t, c, "exceptions_review", "total", 0)

		c = pocWantState(t, out.Cards, "agent_health", "zero")
		pocWantInt(t, c, "agent_health", "devices_degraded", 0)

		// OS update posture has no version-level evidence yet (PAT-2133 /
		// PAT-2191), so even an all-up-to-date macOS estate is never zero.
		c = pocWantState(t, out.Cards, "os_updates", "partial")
		pocWantInt(t, c, "os_updates", "pending", 0)
	})

	t.Run("tenant with no devices", func(t *testing.T) {
		tenant := pocTenant(t, pool, "empty")
		out := pocGet(t, pool, tenant, nil)

		c := pocWantState(t, out.Cards, "devices", "zero")
		pocWantInt(t, c, "devices", "total", 0)
		// No devices means no evidence: these must not read as healthy zeros.
		pocWantState(t, out.Cards, "os_updates", "unavailable")
		pocWantState(t, out.Cards, "cis_posture", "unknown")
		pocWantState(t, out.Cards, "agent_health", "unknown")
	})

	t.Run("no update evidence at all", func(t *testing.T) {
		tenant := pocTenant(t, pool, "winonly")
		pocDevice(t, pool, tenant, "win", "Windows", "now() - interval '1 hour'", "")
		out := pocGet(t, pool, tenant, nil)
		pocWantState(t, out.Cards, "os_updates", "unavailable")
		// A device with no evaluations has no CIS evidence.
		pocWantState(t, out.Cards, "cis_posture", "unknown")
	})
}

// ---------------------------------------------------------------------------
// Unavailable and degraded sources
// ---------------------------------------------------------------------------

// TestPortalOverviewCards_Unavailable covers the estate-too-large extension
// branch and a failing source for every card.
func TestPortalOverviewCards_Unavailable(t *testing.T) {
	pool := pocPool(t)
	tenant := pocTenant(t, pool, "unavail")
	mac := pocDevice(t, pool, tenant, "mac", "macOS", "now() - interval '1 hour'", "[]")

	t.Run("browser extension estate too large", func(t *testing.T) {
		pocExtension(t, pool, mac, "pat2207-big-a-"+pocSuffix(t), "normal")
		pocExtension(t, pool, mac, "pat2207-big-b-"+pocSuffix(t), "elevated")
		restore := report.SetPortalExtensionsMaxSourceRowsForTest(1)
		defer restore()

		out := pocGet(t, pool, tenant, nil)
		c := pocWantState(t, out.Cards, "browser_extensions", "unavailable")
		pocWantReason(t, c, "browser_extensions", "estate_too_large")
		pocWantState(t, out.Cards, "devices", "value")
	})

	for _, card := range pocFailableCards {
		t.Run("failing source degrades only "+card, func(t *testing.T) {
			restore := report.SetOverviewCardFailureForTest(card, errors.New("injected PAT-2207 failure"))
			defer restore()

			out := pocGet(t, pool, tenant, nil)
			c := pocWantState(t, out.Cards, card, "unavailable")
			pocWantReason(t, c, card, "query_failed")
			if c.Source == "" {
				t.Errorf("card %s: an unavailable card still names its source", card)
			}
			d := pocWantState(t, out.Cards, "devices", "value")
			pocWantInt(t, d, "devices", "total", 1)
			for _, other := range pocFailableCards {
				if other != card && out.Cards[other].Completeness.Reason != nil && *out.Cards[other].Completeness.Reason == "query_failed" {
					t.Errorf("failure injected into %s leaked into %s", card, other)
				}
			}
		})
	}

	t.Run("base device query failure fails the response", func(t *testing.T) {
		restore := report.SetOverviewCardFailureForTest("devices", errors.New("injected PAT-2207 base failure"))
		defer restore()
		rec := pocDo(t, pool, tenant, pocPath, nil)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("base failure = %d, want 500", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

// TestPortalOverviewCards_TenantIsolation proves the tenant comes only from
// the portal identity: tenant B's data never appears for tenant A, whatever
// the request says.
func TestPortalOverviewCards_TenantIsolation(t *testing.T) {
	pool := pocPool(t)
	a := pocTenant(t, pool, "iso-a")
	b := pocTenant(t, pool, "iso-b")

	pocDevice(t, pool, a, "a-mac", "macOS", "now() - interval '1 hour'", "[]")

	b1 := pocDevice(t, pool, b, "b-mac-1", "macOS", "now() - interval '1 hour'", "[]")
	pocDevice(t, pool, b, "b-mac-2", "macOS", "now() - interval '5 days'", "[]")
	pocDevice(t, pool, b, "b-mac-3", "macOS", "now() - interval '20 days'", "")
	pocConfirmedCVE(t, pool, b1, "HIGH")
	pocExtension(t, pool, b1, "pat2207-b-ext-"+pocSuffix(t), "elevated")
	pocException(t, pool, b, "b-overdue", "(now() AT TIME ZONE 'UTC')::date - 3")
	pocAgentHealth(t, pool, b1)

	hints := func(r *http.Request) {
		q := r.URL.Query()
		q.Set("tenant_id", b)
		q.Set("tenant", b)
		r.URL.RawQuery = q.Encode()
		r.Header.Set("X-Tenant-ID", b)
		r.Header.Set("X-Patched-Tenant", b)
	}

	for name, mutate := range map[string]func(*http.Request){"plain": nil, "with client tenant hints for B": hints} {
		t.Run(name, func(t *testing.T) {
			out := pocGet(t, pool, a, mutate)
			c := out.Cards["devices"]
			pocWantInt(t, c, "devices", "total", 1)
			pocWantInt(t, c, "devices", "stale", 0)
			pocWantInt(t, c, "devices", "silent", 0)
			if c := out.Cards["vulnerabilities"]; c.Values != nil {
				pocWantInt(t, c, "vulnerabilities", "high", 0)
			}
			pocWantInt(t, out.Cards["browser_extensions"], "browser_extensions", "elevated", 0)
			pocWantInt(t, out.Cards["exceptions_review"], "exceptions_review", "total", 0)
			pocWantInt(t, out.Cards["agent_health"], "agent_health", "devices_degraded", 0)
		})
	}

	t.Run("tenant B sees its own", func(t *testing.T) {
		out := pocGet(t, pool, b, nil)
		c := out.Cards["devices"]
		pocWantInt(t, c, "devices", "total", 3)
		pocWantInt(t, c, "devices", "stale", 1)
		pocWantInt(t, c, "devices", "silent", 1)
		pocWantInt(t, out.Cards["vulnerabilities"], "vulnerabilities", "high", 1)
		pocWantInt(t, out.Cards["browser_extensions"], "browser_extensions", "elevated", 1)
		pocWantInt(t, out.Cards["exceptions_review"], "exceptions_review", "review_overdue", 1)
		pocWantInt(t, out.Cards["agent_health"], "agent_health", "devices_degraded", 1)
	})

	t.Run("no identity is refused", func(t *testing.T) {
		rec := pocDo(t, pool, "", pocPath+"?tenant_id="+b, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("no identity = %d, want 401", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Existing Overview consumers
// ---------------------------------------------------------------------------

// TestPortalOverview_ResponseShapeUnchanged pins GET /v1/portal/overview's
// top-level keys: the cards read model is additive and must not change the
// existing response.
func TestPortalOverview_ResponseShapeUnchanged(t *testing.T) {
	pool := pocPool(t)
	tenant := pocTenant(t, pool, "compat")
	pocDevice(t, pool, tenant, "mac", "macOS", "now() - interval '1 hour'", "[]")

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "viewer@pat2207.example", TenantID: tenant}))
	rec := httptest.NewRecorder()
	PortalOverviewHandler(pool).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d", rec.Code)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	want := []string{
		"tenant_name", "generated_at", "devices_total", "devices_reporting_24h",
		"oldest_successful_ingest", "devices_retired", "devices_degraded",
		"cis_score_current", "cis_trend", "findings_open", "patch_status",
		"cve_attention", "unapproved_present", "unapproved_present_devices",
		"unapproved_present_items", "unapproved_alerts_open",
		"unapproved_alerts_acknowledged", "new_software",
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(want)
	if len(keys) != len(want) {
		t.Fatalf("overview keys = %v, want exactly %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("overview keys = %v, want exactly %v", keys, want)
		}
	}
}
