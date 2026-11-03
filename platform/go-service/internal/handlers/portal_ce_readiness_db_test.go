package handlers

// PAT-1927 contract tests for GET /v1/portal/ce-readiness: the Cyber
// Essentials v3.3 readiness read model. The contract under test
// (contracts/portal-api.md):
//
//   - 14-day rule, per device: every confirmed critical or high CVE whose
//     advisory publication date (cve_feed_entries.published_at) is more than
//     14 days old is an outstanding item, carrying its due date
//     (published_at + 14 days, due_basis advisory_published_plus_14_days: a
//     conservative proxy, the platform stores no fix-release date), age in
//     days and KEV state.
//   - A device that is not reporting (stale, silent, no report time) is
//     unknown, never no_outstanding_items_evidenced.
//   - Controls are evidenced_ok only on a passing rule evaluation (or EDR
//     coverage); a failed evaluation is not_passing; no evaluation is
//     not_evidenced.
//   - No verdict anywhere: no key names or implies pass, compliant or
//     certified, and the estate block is counts only.
//   - The tenant comes only from the portalauth identity.
//   - ?format=csv is one row per device per item, or one row per device with
//     no items, every free-text cell through csvSafe.
//
// DB-backed: drives the real handler against a migrated Postgres. Skipped
// without TEST_DATABASE_URL unless PATCHED_DB_TESTS_REQUIRED is set.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

const cerPath = "/v1/portal/ce-readiness"

var (
	cerDeviceStates  = map[string]bool{"not_passing": true, "unknown": true, "no_outstanding_items_evidenced": true}
	cerControlStates = map[string]bool{"evidenced_ok": true, "not_passing": true, "not_evidenced": true}
	cerBuckets       = map[string]bool{"active": true, "stale": true, "silent": true, "unknown": true}
	cerKEVStates     = map[string]bool{"listed": true, "not_listed": true, "unknown": true}
)

type cerFreshness struct {
	Source     string     `json:"source"`
	ObservedAt *time.Time `json:"observed_at"`
}

type cerKEV struct {
	State     string     `json:"state"`
	Source    string     `json:"source"`
	FetchedAt *time.Time `json:"fetched_at"`
	Reason    *string    `json:"reason"`
}

type cerItem struct {
	Kind             string     `json:"kind"`
	CVEID            string     `json:"cve_id"`
	Severity         string     `json:"severity"`
	Product          string     `json:"product"`
	InstalledVersion string     `json:"installed_version"`
	FixedVersion     *string    `json:"fixed_version"`
	PublishedAt      *time.Time `json:"published_at"`
	DueBasis         string     `json:"due_basis"`
	DueAt            *time.Time `json:"due_at"`
	AgeDays          *int       `json:"age_days"`
	DaysOverdue      *int       `json:"days_overdue"`
	KEV              cerKEV     `json:"kev"`
	Source           string     `json:"source"`
	ObservedAt       *time.Time `json:"observed_at"`
}

type cerControl struct {
	Control    string     `json:"control"`
	Category   string     `json:"category"`
	State      string     `json:"state"`
	Reason     *string    `json:"reason"`
	Source     string     `json:"source"`
	RuleKey    *string    `json:"rule_key"`
	ObservedAt *time.Time `json:"observed_at"`
}

type cerEvidence struct {
	State      string     `json:"state"`
	Reason     *string    `json:"reason"`
	Source     string     `json:"source"`
	ObservedAt *time.Time `json:"observed_at"`
}

type cerDevice struct {
	DeviceID     string   `json:"device_id"`
	Hostname     string   `json:"hostname"`
	Platform     string   `json:"platform"`
	State        string   `json:"state"`
	StateReasons []string `json:"state_reasons"`
	Reporting    struct {
		Bucket     string     `json:"bucket"`
		Source     string     `json:"source"`
		ObservedAt *time.Time `json:"observed_at"`
	} `json:"reporting"`
	CVEEvidence      cerEvidence  `json:"cve_evidence"`
	OSUpdateEvidence cerEvidence  `json:"os_update_evidence"`
	Items            []cerItem    `json:"items"`
	Controls         []cerControl `json:"controls"`
}

type cerResp struct {
	GeneratedAt *time.Time `json:"generated_at"`
	Thresholds  struct {
		UpdateDueAfterDays int `json:"update_due_after_days"`
		ActiveWithinHours  int `json:"active_within_hours"`
		SilentAfterDays    int `json:"silent_after_days"`
	} `json:"thresholds"`
	CVEMatching cerEvidence `json:"cve_matching"`
	Estate      struct {
		DevicesTotal               *int         `json:"devices_total"`
		NotPassing                 *int         `json:"not_passing"`
		WithOutstandingItems       *int         `json:"with_outstanding_items"`
		WithControlsNotPassing     *int         `json:"with_controls_not_passing"`
		Unknown                    *int         `json:"unknown"`
		NoOutstandingItemsEvidence *int         `json:"no_outstanding_items_evidenced"`
		RetiredExcluded            *int         `json:"retired_excluded"`
		Source                     string       `json:"source"`
		Freshness                  cerFreshness `json:"freshness"`
	} `json:"estate"`
	Devices []cerDevice `json:"devices"`
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func cerTenant(t *testing.T, pool *pgxpool.Pool, label string) string {
	t.Helper()
	s := pocSuffix(t)
	return parSeedTenant(t, context.Background(), pool, "pat1927-"+label+"-"+s, "pat1927-token-"+label+"-"+s, "pat1927-hmac-"+label+"-"+s+"-padpadpad")
}

// cerDeviceHost seeds a device with an exact hostname (pocDevice appends a
// suffix to the hostname, which the CSV escaping test cannot use).
func cerDeviceHost(t *testing.T, pool *pgxpool.Pool, tenantID, hostname, osName, lastSeenSQL string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, '15.5', 'arm64', `+lastSeenSQL+`)
		RETURNING id::text
	`, tenantID, "pat1927-"+pocSuffix(t), hostname, osName).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", hostname, err)
	}
	return id
}

// cerCVE seeds one confirmed finding for deviceID against a fresh CVE whose
// advisory was published publishedSQL (a DB expression, "NULL" for none).
// It returns the CVE id.
func cerCVE(t *testing.T, pool *pgxpool.Pool, deviceID, severity, publishedSQL, app, version, fixed string) string {
	t.Helper()
	cveID := "CVE-2099-" + pocSuffix(t)
	pocExec(t, pool, "seed cve entry", `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, published_at)
		VALUES ($1, 'PAT-1927 test vulnerability', 'nvd', 9.8, $2, `+publishedSQL+`)
	`, cveID, severity)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cve_feed_entries WHERE cve_id = $1`, cveID)
	})
	pocExec(t, pool, "seed cve finding", `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, fixed_version, cvss_v3_score, severity, match_confidence)
		VALUES ($1::uuid, $2, $3, $4, $5, 9.8, $6, 'version_confirmed')
	`, deviceID, cveID, app, version, fixed, severity)
	return cveID
}

// cerEval seeds the latest evaluation of ruleKey on deviceID.
func cerEval(t *testing.T, pool *pgxpool.Pool, deviceID, ruleKey, status string) {
	t.Helper()
	pocExec(t, pool, "seed evaluation "+ruleKey, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
		SELECT $1::uuid, id, $3, 'observed', severity, benchmark_version
		FROM compliance_rules WHERE rule_key = $2
	`, deviceID, ruleKey, status)
}

func cerDo(t *testing.T, pool *pgxpool.Pool, tenantID, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if tenantID != "" {
		req = req.WithContext(portalauth.WithIdentity(req.Context(),
			portalauth.Identity{Email: "viewer@pat1927.example", TenantID: tenantID}))
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	PortalCEReadinessHandler(pool).ServeHTTP(rec, req)
	return rec
}

func cerGet(t *testing.T, pool *pgxpool.Pool, tenantID string, mutate func(*http.Request)) (cerResp, []byte) {
	t.Helper()
	rec := cerDo(t, pool, tenantID, cerPath, mutate)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q)", cerPath, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.Bytes()
	var out cerResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	cerCheckContract(t, out)
	return out, body
}

// cerCheckContract asserts the invariants every response holds.
func cerCheckContract(t *testing.T, out cerResp) {
	t.Helper()
	if out.GeneratedAt == nil || out.GeneratedAt.IsZero() {
		t.Errorf("generated_at missing")
	}
	th := out.Thresholds
	if th.UpdateDueAfterDays != 14 || th.ActiveWithinHours != 24 || th.SilentAfterDays != 14 {
		t.Errorf("thresholds = %+v, want 14 / 24 / 14", th)
	}
	if out.CVEMatching.Source == "" {
		t.Errorf("cve_matching.source missing")
	}
	e := out.Estate
	for name, v := range map[string]*int{
		"devices_total": e.DevicesTotal, "not_passing": e.NotPassing, "with_outstanding_items": e.WithOutstandingItems,
		"with_controls_not_passing": e.WithControlsNotPassing, "unknown": e.Unknown,
		"no_outstanding_items_evidenced": e.NoOutstandingItemsEvidence, "retired_excluded": e.RetiredExcluded,
	} {
		if v == nil {
			t.Errorf("estate.%s missing", name)
		}
	}
	if e.DevicesTotal == nil || e.NotPassing == nil || e.Unknown == nil || e.NoOutstandingItemsEvidence == nil {
		return
	}
	if *e.NotPassing+*e.Unknown+*e.NoOutstandingItemsEvidence != *e.DevicesTotal {
		t.Errorf("estate buckets do not sum: not_passing %d + unknown %d + no_outstanding %d != total %d",
			*e.NotPassing, *e.Unknown, *e.NoOutstandingItemsEvidence, *e.DevicesTotal)
	}
	if *e.DevicesTotal != len(out.Devices) {
		t.Errorf("estate.devices_total = %d, devices[] has %d", *e.DevicesTotal, len(out.Devices))
	}
	if e.Source == "" {
		t.Errorf("estate.source missing")
	}
	counts := map[string]int{}
	for _, d := range out.Devices {
		counts[d.State]++
		if !cerDeviceStates[d.State] {
			t.Errorf("device %s: state %q outside the contract", d.DeviceID, d.State)
		}
		if !cerBuckets[d.Reporting.Bucket] || d.Reporting.Source == "" {
			t.Errorf("device %s: reporting %+v malformed", d.DeviceID, d.Reporting)
		}
		if d.StateReasons == nil {
			t.Errorf("device %s: state_reasons must be an array", d.DeviceID)
		}
		if d.Items == nil || d.Controls == nil {
			t.Errorf("device %s: items and controls must be arrays, never null", d.DeviceID)
		}
		if d.CVEEvidence.Source == "" || d.OSUpdateEvidence.Source == "" {
			t.Errorf("device %s: evidence blocks must name their source", d.DeviceID)
		}
		if d.OSUpdateEvidence.State != "unknown" {
			t.Errorf("device %s: os_update_evidence.state = %q; OS version evidence is insufficient until PAT-2133/PAT-2191, so it must be unknown",
				d.DeviceID, d.OSUpdateEvidence.State)
		}
		if d.State == "no_outstanding_items_evidenced" && (len(d.Items) > 0 || d.Reporting.Bucket != "active") {
			t.Errorf("device %s: no_outstanding_items_evidenced with items %d / bucket %s", d.DeviceID, len(d.Items), d.Reporting.Bucket)
		}
		for _, it := range d.Items {
			if it.Source == "" || it.DueBasis == "" || it.KEV.Source == "" || !cerKEVStates[it.KEV.State] {
				t.Errorf("device %s item %s: source/due_basis/kev malformed: %+v", d.DeviceID, it.CVEID, it)
			}
			if it.Severity != "critical" && it.Severity != "high" {
				t.Errorf("device %s item %s: severity %q is not critical or high", d.DeviceID, it.CVEID, it.Severity)
			}
			// An item is past its due date: published more than 14 days ago
			// (whole days, so a 14.5-day-old advisory has age_days 14).
			if it.AgeDays == nil || *it.AgeDays < 14 || it.DueAt == nil || out.GeneratedAt == nil || !it.DueAt.Before(*out.GeneratedAt) {
				t.Errorf("device %s item %s: age_days %v / due_at %v is not past due", d.DeviceID, it.CVEID, it.AgeDays, it.DueAt)
			}
			// days_overdue is never presented without the basis it rests on.
			if it.DaysOverdue != nil && it.DueBasis != "advisory_published_plus_14_days" {
				t.Errorf("device %s item %s: days_overdue %d carried with due_basis %q, want advisory_published_plus_14_days",
					d.DeviceID, it.CVEID, *it.DaysOverdue, it.DueBasis)
			}
		}
		for _, c := range d.Controls {
			if !cerControlStates[c.State] || c.Control == "" || c.Source == "" || c.Category == "" {
				t.Errorf("device %s: malformed control %+v", d.DeviceID, c)
			}
			if c.State == "evidenced_ok" && c.ObservedAt == nil {
				t.Errorf("device %s control %s: evidenced_ok without observed_at", d.DeviceID, c.Control)
			}
			if c.State != "evidenced_ok" && (c.Reason == nil || !pocReasonPattern.MatchString(*c.Reason)) {
				t.Errorf("device %s control %s: state %s needs a bounded reason", d.DeviceID, c.Control, c.State)
			}
		}
	}
	if counts["not_passing"] != *e.NotPassing || counts["unknown"] != *e.Unknown ||
		counts["no_outstanding_items_evidenced"] != *e.NoOutstandingItemsEvidence {
		t.Errorf("estate counts %+v disagree with devices[] %v", e, counts)
	}
}

func cerFind(t *testing.T, out cerResp, deviceID string) cerDevice {
	t.Helper()
	for _, d := range out.Devices {
		if d.DeviceID == deviceID {
			return d
		}
	}
	t.Fatalf("device %s missing from devices[]", deviceID)
	return cerDevice{}
}

func cerControlOf(t *testing.T, d cerDevice, control string) cerControl {
	t.Helper()
	for _, c := range d.Controls {
		if c.Control == control {
			return c
		}
	}
	t.Fatalf("device %s: control %q missing (have %+v)", d.DeviceID, control, d.Controls)
	return cerControl{}
}

// ---------------------------------------------------------------------------
// 14-day rule
// ---------------------------------------------------------------------------

func TestPortalCEReadiness_FourteenDayRule(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "14day")

	overdue := pocDevice(t, pool, tenant, "overdue-mac", "macOS", "now() - interval '1 hour'", "[]")
	critical := cerCVE(t, pool, overdue, "CRITICAL", "now() - interval '20 days'", "VulnApp", "1.0.0", "1.0.5")
	recent := pocDevice(t, pool, tenant, "recent-win", "Windows", "now() - interval '1 hour'", "")
	cerCVE(t, pool, recent, "HIGH", "now() - interval '10 days'", "FreshApp", "2.0", "")

	out, _ := cerGet(t, pool, tenant, nil)

	var published time.Time
	if err := pool.QueryRow(context.Background(), `SELECT published_at FROM cve_feed_entries WHERE cve_id = $1`, critical).Scan(&published); err != nil {
		t.Fatalf("read published_at: %v", err)
	}

	d := cerFind(t, out, overdue)
	if d.State != "not_passing" {
		t.Errorf("20-day-old critical: device state = %q, want not_passing", d.State)
	}
	if len(d.Items) != 1 {
		t.Fatalf("20-day-old critical: items = %+v, want exactly one", d.Items)
	}
	it := d.Items[0]
	if it.CVEID != critical || it.Severity != "critical" || it.Product != "VulnApp" || it.InstalledVersion != "1.0.0" {
		t.Errorf("item identity = %+v", it)
	}
	if it.FixedVersion == nil || *it.FixedVersion != "1.0.5" {
		t.Errorf("fixed_version = %v, want 1.0.5", it.FixedVersion)
	}
	if it.DueBasis != "advisory_published_plus_14_days" {
		t.Errorf("due_basis = %q, want advisory_published_plus_14_days", it.DueBasis)
	}
	if it.PublishedAt == nil || !it.PublishedAt.Equal(published) {
		t.Errorf("published_at = %v, want %v", it.PublishedAt, published)
	}
	if it.DueAt == nil || !it.DueAt.Equal(published.Add(14*24*time.Hour)) {
		t.Errorf("due_at = %v, want published_at + 14 days = %v", it.DueAt, published.Add(14*24*time.Hour))
	}
	if it.AgeDays == nil || *it.AgeDays != 20 {
		t.Errorf("age_days = %v, want 20", it.AgeDays)
	}
	if it.DaysOverdue == nil || *it.DaysOverdue != 6 {
		t.Errorf("days_overdue = %v, want 6", it.DaysOverdue)
	}
	if it.Source != "device_cve_findings" || it.ObservedAt == nil {
		t.Errorf("item source/observed_at = %q / %v", it.Source, it.ObservedAt)
	}
	if it.KEV.Source != "cisa_kev" {
		t.Errorf("kev.source = %q, want cisa_kev", it.KEV.Source)
	}

	r := cerFind(t, out, recent)
	if len(r.Items) != 0 {
		t.Errorf("10-day-old high must not be an item, got %+v", r.Items)
	}
	if r.State == "not_passing" {
		for _, c := range r.Controls {
			if c.State == "not_passing" {
				t.Fatalf("unexpected failing control %+v", c)
			}
		}
		t.Errorf("10-day-old high made the device not_passing")
	}

	e := out.Estate
	if e.WithOutstandingItems == nil || *e.WithOutstandingItems != 1 {
		t.Errorf("estate.with_outstanding_items = %v, want 1", e.WithOutstandingItems)
	}
}

// An unconfirmed (version_unverified) match is not an item, the same
// confirmed-match rule /overview's cve_attention uses.
func TestPortalCEReadiness_UnconfirmedMatchIsNotAnItem(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "unconf")
	dev := pocDevice(t, pool, tenant, "mac", "macOS", "now() - interval '1 hour'", "[]")
	cve := cerCVE(t, pool, dev, "critical", "now() - interval '30 days'", "Maybe", "1.0", "")
	pocExec(t, pool, "mark unverified", `UPDATE device_cve_findings SET match_confidence = 'version_unverified' WHERE cve_id = $1`, cve)

	out, _ := cerGet(t, pool, tenant, nil)
	if d := cerFind(t, out, dev); len(d.Items) != 0 {
		t.Errorf("unconfirmed match became an item: %+v", d.Items)
	}
}

// ---------------------------------------------------------------------------
// Unknown devices
// ---------------------------------------------------------------------------

func TestPortalCEReadiness_UnknownDevices(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "unknown")

	silent := pocDevice(t, pool, tenant, "silent-mac", "macOS", "now() - interval '30 days'", "")
	stale := pocDevice(t, pool, tenant, "stale-mac", "macOS", "now() - interval '3 days'", "")
	active := pocDevice(t, pool, tenant, "active-mac", "macOS", "now() - interval '1 hour'", "[]")
	retired := pocDevice(t, pool, tenant, "retired-mac", "macOS", "now() - interval '40 days'", "")
	pocRetire(t, pool, tenant, retired)

	out, _ := cerGet(t, pool, tenant, nil)

	s := cerFind(t, out, silent)
	if s.State != "unknown" || s.Reporting.Bucket != "silent" {
		t.Errorf("silent device: state %q bucket %q, want unknown / silent", s.State, s.Reporting.Bucket)
	}
	st := cerFind(t, out, stale)
	if st.State != "unknown" || st.Reporting.Bucket != "stale" {
		t.Errorf("stale device: state %q bucket %q, want unknown / stale", st.State, st.Reporting.Bucket)
	}
	a := cerFind(t, out, active)
	if a.State != "no_outstanding_items_evidenced" || a.Reporting.Bucket != "active" {
		t.Errorf("active clean device: state %q bucket %q, want no_outstanding_items_evidenced / active (reasons %v)",
			a.State, a.Reporting.Bucket, a.StateReasons)
	}
	for _, d := range out.Devices {
		if d.DeviceID == retired {
			t.Errorf("retired device must be excluded from devices[]")
		}
	}
	if out.Estate.RetiredExcluded == nil || *out.Estate.RetiredExcluded != 1 {
		t.Errorf("estate.retired_excluded = %v, want 1", out.Estate.RetiredExcluded)
	}
	if out.Estate.Unknown == nil || *out.Estate.Unknown != 2 {
		t.Errorf("estate.unknown = %v, want 2", out.Estate.Unknown)
	}
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

func TestPortalCEReadiness_Controls(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "controls")

	winPass := pocDevice(t, pool, tenant, "win-pass", "Windows", "now() - interval '1 hour'", "")
	cerEval(t, pool, winPass, "cis_win_18_9_45_defender_realtime", "pass")
	winFail := pocDevice(t, pool, tenant, "win-fail", "Windows", "now() - interval '1 hour'", "")
	cerEval(t, pool, winFail, "cis_win_18_9_45_defender_realtime", "fail")
	mac := pocDevice(t, pool, tenant, "mac-noeval", "macOS", "now() - interval '1 hour'", "[]")
	cerEval(t, pool, mac, "cis_macos_2_5_2_1_gatekeeper", "pass")

	out, _ := cerGet(t, pool, tenant, nil)

	p := cerControlOf(t, cerFind(t, out, winPass), "defender_realtime_protection")
	if p.State != "evidenced_ok" || p.Category != "malware_protection" {
		t.Errorf("Defender real-time pass: %+v, want evidenced_ok / malware_protection", p)
	}
	if p.RuleKey == nil || *p.RuleKey != "cis_win_18_9_45_defender_realtime" {
		t.Errorf("Defender real-time rule_key = %v", p.RuleKey)
	}
	fd := cerFind(t, out, winFail)
	f := cerControlOf(t, fd, "defender_realtime_protection")
	if f.State != "not_passing" {
		t.Errorf("Defender real-time fail: state %q, want not_passing", f.State)
	}
	if fd.State != "not_passing" {
		t.Errorf("device with a failing control: state %q, want not_passing", fd.State)
	}
	// Unevaluated Windows controls are not_evidenced, never evidenced_ok.
	if c := cerControlOf(t, cerFind(t, out, winPass), "defender_cloud_protection"); c.State != "not_evidenced" {
		t.Errorf("unevaluated Defender cloud protection: %q, want not_evidenced", c.State)
	}

	md := cerFind(t, out, mac)
	x := cerControlOf(t, md, "xprotect_running")
	if x.State != "not_evidenced" {
		t.Errorf("Mac with no XProtect evaluation: %q, want not_evidenced", x.State)
	}
	if g := cerControlOf(t, md, "gatekeeper"); g.State != "evidenced_ok" || g.Category != "secure_configuration" {
		t.Errorf("Gatekeeper pass: %+v, want evidenced_ok / secure_configuration", g)
	}
	// EDR with no security_tools evidence is not_evidenced, never passing.
	if e := cerControlOf(t, md, "edr_coverage"); e.State != "not_evidenced" {
		t.Errorf("EDR without evidence: %q, want not_evidenced", e.State)
	}
	// A Mac carries no Windows control and vice versa.
	for _, c := range md.Controls {
		if strings.HasPrefix(c.Control, "defender_") {
			t.Errorf("Mac carries Windows control %s", c.Control)
		}
	}
	if out.Estate.WithControlsNotPassing == nil || *out.Estate.WithControlsNotPassing != 1 {
		t.Errorf("estate.with_controls_not_passing = %v, want 1", out.Estate.WithControlsNotPassing)
	}
}

func TestPortalCEReadiness_EDRCoverageIsEvidence(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "edr")
	win := pocDevice(t, pool, tenant, "win-edr", "Windows", "now() - interval '1 hour'", "")
	pocExec(t, pool, "seed security tools", `
		UPDATE devices SET security_inventory = '{"security_tools":[{"id":"crowdstrike","name":"CrowdStrike Falcon Sensor"}]}'::jsonb
		WHERE id = $1::uuid
	`, win)

	out, _ := cerGet(t, pool, tenant, nil)
	c := cerControlOf(t, cerFind(t, out, win), "edr_coverage")
	if c.State != "evidenced_ok" || c.Category != "malware_protection" || c.ObservedAt == nil {
		t.Errorf("covered EDR: %+v, want evidenced_ok / malware_protection with observed_at", c)
	}
}

// ---------------------------------------------------------------------------
// No verdict
// ---------------------------------------------------------------------------

// TestPortalCEReadiness_NoVerdictKeys walks every key in a populated
// response: nothing may name or imply pass, compliant or certified, and no
// value may be a bare verdict word.
func TestPortalCEReadiness_NoVerdictKeys(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "verdict")
	win := pocDevice(t, pool, tenant, "win", "Windows", "now() - interval '1 hour'", "")
	cerEval(t, pool, win, "cis_win_18_9_45_defender_realtime", "pass")
	cerEval(t, pool, win, "cis_win_9_1_1_firewall_domain", "fail")
	cerCVE(t, pool, win, "critical", "now() - interval '25 days'", "App", "1", "2")
	pocDevice(t, pool, tenant, "mac", "macOS", "now() - interval '1 hour'", "[]")

	_, body := cerGet(t, pool, tenant, nil)
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	forbiddenKey := []string{"compliant", "certif", "pass"}
	forbiddenValue := map[string]bool{"pass": true, "passed": true, "passes": true, "passing": true,
		"compliant": true, "certified": true, "ready": true, "fail": true, "failed": true}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				lk := strings.ToLower(k)
				for _, f := range forbiddenKey {
					if strings.Contains(lk, f) && lk != "not_passing" && lk != "with_controls_not_passing" {
						t.Errorf("key %s.%s implies a verdict (%q)", path, k, f)
					}
				}
				walk(path+"."+k, child)
			}
		case []any:
			for _, child := range x {
				walk(path+"[]", child)
			}
		case string:
			if forbiddenValue[strings.ToLower(x)] {
				t.Errorf("value at %s is a bare verdict word %q", path, x)
			}
		}
	}
	walk("$", doc)

	var top map[string]json.RawMessage
	_ = json.Unmarshal(body, &top)
	var estate map[string]json.RawMessage
	_ = json.Unmarshal(top["estate"], &estate)
	for k := range estate {
		switch k {
		case "devices_total", "not_passing", "with_outstanding_items", "with_controls_not_passing", "unknown",
			"no_outstanding_items_evidenced", "retired_excluded", "source", "freshness":
		default:
			t.Errorf("estate carries %q: the estate block is counts only", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

func TestPortalCEReadiness_TenantIsolation(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	a := cerTenant(t, pool, "iso-a")
	b := cerTenant(t, pool, "iso-b")
	aDev := pocDevice(t, pool, a, "a-mac", "macOS", "now() - interval '1 hour'", "[]")
	bDev := pocDevice(t, pool, b, "b-mac", "macOS", "now() - interval '1 hour'", "[]")
	cerCVE(t, pool, bDev, "critical", "now() - interval '40 days'", "BApp", "1", "")

	out, _ := cerGet(t, pool, a, func(r *http.Request) {
		r.Header.Set("X-Tenant-ID", b)
	})
	if len(out.Devices) != 1 || out.Devices[0].DeviceID != aDev {
		t.Fatalf("tenant A sees %+v, want only its own device %s", out.Devices, aDev)
	}
	if n := out.Estate.WithOutstandingItems; n == nil || *n != 0 {
		t.Errorf("tenant A with_outstanding_items = %v, want 0 (tenant B's CVE leaked)", n)
	}

	// A client-supplied tenant parameter is refused, never honoured.
	rec := cerDo(t, pool, a, cerPath+"?tenant_id="+b, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("?tenant_id= answered %d, want 400", rec.Code)
	}
	if rec := cerDo(t, pool, "", cerPath, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no identity answered %d, want 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

func TestPortalCEReadiness_CSV(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "csv")

	evilHost := `=HYPERLINK("http://x","click"),host`
	twoItems := cerDeviceHost(t, pool, tenant, evilHost, "macOS", "now() - interval '1 hour'")
	cerCVE(t, pool, twoItems, "critical", "now() - interval '20 days'", "@SUM(1+1)", "1.0", "")
	cerCVE(t, pool, twoItems, "high", "now() - interval '30 days'", "Plain App", "2.0", "2.1")
	clean := cerDeviceHost(t, pool, tenant, "clean-host", "macOS", "now() - interval '1 hour'")
	silent := cerDeviceHost(t, pool, tenant, "silent-host", "Windows", "now() - interval '30 days'")

	rec := cerDo(t, pool, tenant, cerPath+"?format=csv", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("CSV = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v (body %q)", err, rec.Body.String())
	}
	if len(rows) < 2 {
		t.Fatalf("CSV has %d rows, want a header and data", len(rows))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	for _, h := range []string{"device_id", "hostname", "platform", "device_state", "reporting_bucket", "device_last_seen",
		"row_kind", "cve_id", "severity", "product", "installed_version", "fixed_version", "published_at",
		"due_basis", "due_at", "age_days", "days_overdue", "kev_state", "kev_fetched_at", "item_source", "item_observed_at",
		"controls_not_passing", "controls_not_evidenced", "generated_at"} {
		if _, ok := col[h]; !ok {
			t.Errorf("CSV header missing %q (have %v)", h, rows[0])
		}
	}
	if t.Failed() {
		return
	}
	perDevice := map[string][][]string{}
	for _, r := range rows[1:] {
		perDevice[r[col["device_id"]]] = append(perDevice[r[col["device_id"]]], r)
	}
	if len(perDevice) != 3 {
		t.Errorf("CSV covers %d devices, want 3", len(perDevice))
	}
	if n := len(perDevice[twoItems]); n != 2 {
		t.Errorf("device with two items has %d rows, want 2", n)
	}
	for _, id := range []string{clean, silent} {
		if n := len(perDevice[id]); n != 1 {
			t.Errorf("device %s with no items has %d rows, want exactly 1", id, n)
			continue
		}
		r := perDevice[id][0]
		if r[col["row_kind"]] != "device" || r[col["cve_id"]] != "" {
			t.Errorf("no-item row: row_kind %q cve_id %q, want device / empty", r[col["row_kind"]], r[col["cve_id"]])
		}
	}
	if st := perDevice[silent]; len(st) == 1 && st[0][col["device_state"]] != "unknown" {
		t.Errorf("silent device row state %q, want unknown", st[0][col["device_state"]])
	}
	if cl := perDevice[clean]; len(cl) == 1 && cl[0][col["device_state"]] != "no_outstanding_items_evidenced" {
		t.Errorf("clean device row state %q, want no_outstanding_items_evidenced", cl[0][col["device_state"]])
	}
	products := map[string]bool{}
	for _, r := range perDevice[twoItems] {
		if r[col["hostname"]] != "'"+evilHost {
			t.Errorf("hostname cell %q, want csvSafe-escaped %q", r[col["hostname"]], "'"+evilHost)
		}
		if r[col["row_kind"]] != "item" || r[col["device_state"]] != "not_passing" {
			t.Errorf("item row kind/state = %q / %q", r[col["row_kind"]], r[col["device_state"]])
		}
		if r[col["item_source"]] != "device_cve_findings" || r[col["item_observed_at"]] == "" || r[col["due_at"]] == "" {
			t.Errorf("item row lacks source/freshness: %v", r)
		}
		if r[col["due_basis"]] != "advisory_published_plus_14_days" {
			t.Errorf("due_basis cell %q", r[col["due_basis"]])
		}
		products[r[col["product"]]] = true
	}
	if !products["'@SUM(1+1)"] || !products["Plain App"] {
		t.Errorf("product cells %v, want the formula escaped and the plain name intact", products)
	}
	for _, r := range rows[1:] {
		if r[col["generated_at"]] == "" || r[col["device_last_seen"]] == "" {
			t.Errorf("row lacks freshness: %v", r)
		}
	}
}
