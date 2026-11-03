package handlers

// PAT-1201: end-to-end (HTTP handler -> DB) tests for the paginated
// GET /v1/portal/findings response shape, complementing the pagination-math
// tests on FetchPortalCVEFindingsPage in internal/report. These exist to
// pin down the exact JSON contract (field names, defaults) the portal-side
// implementer builds against.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as internal/report's *_db_test.go files. The pool's
// search_path is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/exploitation"
	"patched.im/api/internal/portalauth"
)

const pat1201HandlerSchema = "pat1201_handler_test"

func pat1201HandlerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1201HandlerSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1201HandlerSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1201HandlerSchema,
		`CREATE TABLE ` + pat1201HandlerSchema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1201HandlerSchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1201HandlerSchema + `.tenants(id),
			hostname  TEXT,
			os        TEXT, -- PAT-2138: the tenant coverage figure reads the platform
			serial    TEXT
		)`,
		`CREATE TABLE ` + pat1201HandlerSchema + `.cve_feed_entries (
			cve_id        TEXT PRIMARY KEY,
			description   TEXT NOT NULL DEFAULT '',
			description_source TEXT NOT NULL DEFAULT '',
			cvss_v3_score NUMERIC(4,1),
			severity      TEXT
		)`,
		`CREATE TABLE ` + pat1201HandlerSchema + `.device_cve_findings (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL REFERENCES ` + pat1201HandlerSchema + `.devices(id),
			cve_id         TEXT NOT NULL REFERENCES ` + pat1201HandlerSchema + `.cve_feed_entries(cve_id),
			app_name       TEXT NOT NULL,
			app_version    TEXT NOT NULL DEFAULT '',
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified',
			fixed_version    TEXT NOT NULL DEFAULT '',
			first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			-- PAT-2023 Homebrew columns FetchPortalCVEFindingsPage aggregates.
			package_source   TEXT,
			install_reason   TEXT,
			confidence_tier  TEXT,
			mapping_basis    TEXT, -- PAT-2138
			UNIQUE (device_id, cve_id, app_name)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1201HandlerSchema+` CASCADE`)
	})
	return pool
}

func pat1201HandlerSeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, findingCount int) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`, name).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	for i := 0; i < findingCount; i++ {
		cveID := "CVE-2024-1201H-" + strconv.Itoa(i)
		if _, err := pool.Exec(ctx, `
			INSERT INTO cve_feed_entries (cve_id, description, cvss_v3_score, severity)
			VALUES ($1, 'seed', $2, 'high')
		`, cveID, 9.0-float64(i)*0.01); err != nil {
			t.Fatalf("insert cve feed entry %s: %v", cveID, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version)
			VALUES ($1::uuid, $2, 'TestApp', '1.0')
		`, deviceID, cveID); err != nil {
			t.Fatalf("insert finding %s: %v", cveID, err)
		}
	}
	return tenantID
}

func pat1201HandlerRequest(tenantID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/findings", nil)
	return req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "test@example.com", TenantID: tenantID}))
}

// TestPortalFindingsHandler_DefaultPageOmitted confirms that with no
// ?limit/?offset query params, the handler applies parsePagination's
// defaults (limit=defaultPageLimit, offset=0) rather than returning the
// full unbounded set — the PAT-1201 backward-compatibility choice: default
// to a bounded first page instead of preserving the old full-set shape,
// since there are no live customers depending on the old response yet.
func TestPortalFindingsHandler_DefaultPageOmitted(t *testing.T) {
	pool := pat1201HandlerPool(t)
	ctx := context.Background()
	tenantID := pat1201HandlerSeed(t, ctx, pool, "PAT-1201 Handler Default Tenant", 3)

	h := PortalFindingsHandler(pool)
	req := pat1201HandlerRequest(tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}

	var resp portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Limit != defaultPageLimit {
		t.Errorf("Limit = %d, want defaultPageLimit (%d)", resp.Limit, defaultPageLimit)
	}
	if resp.Offset != 0 {
		t.Errorf("Offset = %d, want 0", resp.Offset)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3", resp.Total)
	}
	if len(resp.Findings) != 3 {
		t.Errorf("len(Findings) = %d, want 3", len(resp.Findings))
	}
	for _, finding := range resp.Findings {
		if finding.Exploitation.Status != exploitation.StatusUnknown ||
			finding.Exploitation.UnavailableReason != exploitation.UnavailableSourceMissing ||
			finding.Exploitation.Evidence == nil {
			t.Errorf("finding %s exploitation = %#v, want explicit unavailable assessment", finding.CVEID, finding.Exploitation)
		}
	}
}

// TestPortalFindingsHandler_PageBoundaries seeds 5 findings and requests an
// explicit limit=2 page, checking both a full page and the partial last page.
func TestPortalFindingsHandler_PageBoundaries(t *testing.T) {
	pool := pat1201HandlerPool(t)
	ctx := context.Background()
	tenantID := pat1201HandlerSeed(t, ctx, pool, "PAT-1201 Handler Boundaries Tenant", 5)

	h := PortalFindingsHandler(pool)

	// First page: limit=2, offset=0.
	req := pat1201HandlerRequest(tenantID)
	req.URL.RawQuery = "limit=2&offset=0"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var page1 portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &page1); err != nil {
		t.Fatalf("unmarshal page1: %v", err)
	}
	if page1.Total != 5 || page1.Limit != 2 || page1.Offset != 0 || len(page1.Findings) != 2 {
		t.Errorf("page1 = %+v, want Total=5 Limit=2 Offset=0 len(Findings)=2", page1)
	}

	// Last (partial) page: limit=2, offset=4 -> 1 row.
	req = pat1201HandlerRequest(tenantID)
	req.URL.RawQuery = "limit=2&offset=4"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var page3 portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &page3); err != nil {
		t.Fatalf("unmarshal page3: %v", err)
	}
	if page3.Limit != 2 || page3.Offset != 4 || len(page3.Findings) != 1 {
		t.Errorf("page3 = %+v, want Limit=2 Offset=4 len(Findings)=1", page3)
	}

	// Beyond the last page: offset=100 -> empty findings, 200 (not an error).
	req = pat1201HandlerRequest(tenantID)
	req.URL.RawQuery = "limit=2&offset=100"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("beyond-last-page status = %d, want 200", rr.Code)
	}
	var pageBeyond portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &pageBeyond); err != nil {
		t.Fatalf("unmarshal pageBeyond: %v", err)
	}
	if len(pageBeyond.Findings) != 0 {
		t.Errorf("pageBeyond Findings = %+v, want empty", pageBeyond.Findings)
	}
}

// TestPortalFindingsHandler_EmptyTenant confirms a tenant with zero findings
// gets a 200 with an empty findings array and total 0, not an error — the
// existing "degrades gracefully" contract preserved under pagination.
func TestPortalFindingsHandler_EmptyTenant(t *testing.T) {
	pool := pat1201HandlerPool(t)
	ctx := context.Background()
	tenantID := pat1201HandlerSeed(t, ctx, pool, "PAT-1201 Handler Empty Tenant", 0)

	h := PortalFindingsHandler(pool)
	req := pat1201HandlerRequest(tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	var resp portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(resp.Findings))
	}
}

// TestPortalFindingsHandler_FieldContent seeds one finding with known,
// distinct values for every response field and asserts both the decoded Go
// struct AND the raw JSON keys — pinning the exact wire contract
// (cve_id, severity, cvss, app, version, match_confidence, fixed_version,
// devices_affected, first_seen, summary) a portal implementer builds
// against. The existing tests in this
// file only check counts/limit/offset envelopes, never that a given seeded
// row's field values actually make it into the response body.
func TestPortalFindingsHandler_FieldContent(t *testing.T) {
	pool := pat1201HandlerPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`,
		"PAT-1201 Handler Field Content Tenant").Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`,
		tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	const cvss = 7.2
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ('CVE-2024-1201HF-1', 'SQL injection in widget parser', 'msrc', $1, 'MEDIUM')
	`, cvss); err != nil {
		t.Fatalf("insert cve feed entry: %v", err)
	}
	firstSeen := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	// Deliberately NOT "version_unverified" (the column's own default, see
	// pat1201HandlerPool) — a value equal to the default wouldn't prove the
	// query round-trips an explicitly-inserted value rather than just
	// falling back to the default.
	const wantMatchConfidence = "version_confirmed"
	const wantFixedVersion = "5.0.2"
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, first_seen_at, match_confidence, fixed_version)
		VALUES ($1::uuid, 'CVE-2024-1201HF-1', 'Widgetizer', '5.0.1', $2, $3, $4)
	`, deviceID, firstSeen, wantMatchConfidence, wantFixedVersion); err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	h := PortalFindingsHandler(pool)
	req := pat1201HandlerRequest(tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}

	var resp portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(resp.Findings))
	}

	f := resp.Findings[0]
	if f.CVEID != "CVE-2024-1201HF-1" {
		t.Errorf("CVEID = %q, want CVE-2024-1201HF-1", f.CVEID)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want lowercased %q", f.Severity, "medium")
	}
	if f.CVSS == nil || *f.CVSS != cvss {
		t.Errorf("CVSS = %v, want %v", f.CVSS, cvss)
	}
	if f.App != "Widgetizer" {
		t.Errorf("App = %q, want Widgetizer", f.App)
	}
	if f.Version != "5.0.1" {
		t.Errorf("Version = %q, want 5.0.1", f.Version)
	}
	if f.MatchConfidence != wantMatchConfidence {
		t.Errorf("MatchConfidence = %q, want %q", f.MatchConfidence, wantMatchConfidence)
	}
	if f.FixedVersion != wantFixedVersion {
		t.Errorf("FixedVersion = %q, want %q", f.FixedVersion, wantFixedVersion)
	}
	if f.DevicesAffected != 1 {
		t.Errorf("DevicesAffected = %d, want 1", f.DevicesAffected)
	}
	if !f.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen = %v, want %v", f.FirstSeen, firstSeen)
	}
	if f.Summary != "SQL injection in widget parser" {
		t.Errorf("Summary = %q, want %q", f.Summary, "SQL injection in widget parser")
	}
	if f.DescriptionSource != "msrc" {
		t.Errorf("DescriptionSource = %q, want msrc", f.DescriptionSource)
	}

	// Confirm the raw JSON keys are exactly the portal contract's field
	// names — unmarshalling into portalFindingEntry above wouldn't catch a
	// json tag rename, since Go would just leave the Go-side field zero.
	var raw struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if len(raw.Findings) != 1 {
		t.Fatalf("raw findings len = %d, want 1", len(raw.Findings))
	}
	for _, key := range []string{
		"cve_id", "severity", "cvss", "app", "version",
		"match_confidence", "fixed_version",
		"devices_affected", "devices", "devices_truncated", "first_seen", "summary", "description_source",
	} {
		if _, ok := raw.Findings[0][key]; !ok {
			t.Errorf("raw JSON finding missing key %q", key)
		}
	}
}

// TestPortalFindingsHandler_LimitExceedsTotalRows mirrors the report-layer
// case at the HTTP boundary: a requested limit larger than the seeded row
// count must return every row, echo the requested (not total-clamped) limit
// back in the response envelope, and report Total as the true row count.
func TestPortalFindingsHandler_LimitExceedsTotalRows(t *testing.T) {
	pool := pat1201HandlerPool(t)
	ctx := context.Background()
	tenantID := pat1201HandlerSeed(t, ctx, pool, "PAT-1201 Handler Limit Exceeds Total Tenant", 3)

	h := PortalFindingsHandler(pool)
	req := pat1201HandlerRequest(tenantID)
	req.URL.RawQuery = "limit=500&offset=0" // 500 = maxPageLimit, still > the 3 seeded rows
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	var resp portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Limit != 500 {
		t.Errorf("Limit = %d, want 500 (requested limit echoed back, not clamped to total)", resp.Limit)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3 (true row count)", resp.Total)
	}
	if len(resp.Findings) != 3 {
		t.Errorf("len(Findings) = %d, want 3 (all rows returned since limit > total)", len(resp.Findings))
	}
}

// pat1201HandlerPoolNoCVETables sets up the same tenants/devices tables as
// pat1201HandlerPool but deliberately omits cve_feed_entries and
// device_cve_findings — simulating a fresh/pre-migration install where the
// CVE matcher tables don't exist yet.
func pat1201HandlerPoolNoCVETables(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	schema := pat1201HandlerSchema + "_no_cve"
	// Deliberately NOT ",public" (unlike pat1201HandlerPool). Running the
	// full verification gate applies real migrations to the shared
	// TEST_DATABASE_URL's public schema first (integration/helpers_test.go),
	// which creates real (if empty, for an unrelated tenant)
	// cve_feed_entries/device_cve_findings tables there — with "public" in
	// the search_path, an unqualified reference to those two tables would
	// silently resolve to public's copies instead of genuinely failing to
	// resolve, defeating the point of this test (it would pass on an
	// empty-join coincidence, never actually exercising isUndefinedTable).
	// Schema-only search_path makes the two CVE tables genuinely
	// unresolvable regardless of what has or hasn't run against public
	// earlier in the same test session. See pat1953PoolNoCVETables
	// (internal/report/portal_cve_attention_db_test.go) for the identical
	// fix and rationale.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		// Schema-qualified target + explicit public.gen_random_uuid() below:
		// pgcrypto may already be installed (in public, from an earlier
		// migration run against this shared TEST_DATABASE_URL) or may not
		// exist yet on a genuinely fresh database; IF NOT EXISTS makes this
		// a no-op in the former case and installs it into public in the
		// latter, either way leaving gen_random_uuid() resolvable via an
		// explicit public.-qualified call regardless of this pool's
		// schema-only search_path.
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto" SCHEMA public`,
		`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`,
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + schema + `.tenants(id),
			hostname  TEXT,
			os        TEXT, -- PAT-2138: the tenant coverage figure reads the platform
			serial    TEXT
		)`,
		// Deliberately no cve_feed_entries / device_cve_findings — that's
		// the point of this variant.
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	return pool
}

// TestPortalFindingsHandler_TablesNotMigrated confirms the HTTP handler
// degrades exactly the same way report.FetchPortalCVEFindingsPage does when
// the CVE matcher tables don't exist yet (see that package's
// TestFetchPortalCVEFindingsPage_TablesNotMigrated and portal.go's
// isUndefinedTable): 200 with an empty findings array and total 0, not a
// 500 — the same "degrade gracefully" contract already covered for an
// ordinary empty tenant in TestPortalFindingsHandler_EmptyTenant, but here
// triggered by a missing relation instead of a tenant with no rows.
func TestPortalFindingsHandler_TablesNotMigrated(t *testing.T) {
	pool := pat1201HandlerPoolNoCVETables(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`,
		"PAT-1201 Handler Not Migrated Tenant").Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	h := PortalFindingsHandler(pool)
	req := pat1201HandlerRequest(tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degrade, not 500), body=%s", rr.Code, rr.Body.String())
	}
	var resp portalFindingsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(resp.Findings))
	}
}
