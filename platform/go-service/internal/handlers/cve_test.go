package handlers

// DB-backed test for PAT-1831's worst-case match_confidence aggregate on
// TenantCVEFindingsHandler. Same isolated-schema convention as
// device_dispositions_test.go (pat1825Pool): search_path pinned to a
// per-ticket schema, mirroring the subset of 0025_cve_store.sql this
// handler's query touches, rather than requiring that migration to already
// be applied to whatever TEST_DATABASE_URL points at.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1831Schema = "pat1831_handlers_test"

func pat1831Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed CVE-findings test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1831Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1831Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1831Schema,
		`CREATE TABLE ` + pat1831Schema + `.tenants (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1831Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1831Schema + `.tenants(id),
			os        TEXT NOT NULL DEFAULT 'macOS'
		)`,
		`CREATE TABLE ` + pat1831Schema + `.cve_feed_entries (
			cve_id        TEXT PRIMARY KEY,
			cvss_v3_score NUMERIC(4,1),
			severity      TEXT,
			cpe_ranges    JSONB NOT NULL DEFAULT '[]'
		)`,
		`CREATE TABLE ` + pat1831Schema + `.device_cve_findings (
			id               BIGSERIAL PRIMARY KEY,
			device_id        UUID NOT NULL REFERENCES ` + pat1831Schema + `.devices(id),
			cve_id           TEXT NOT NULL REFERENCES ` + pat1831Schema + `.cve_feed_entries(cve_id),
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified',
			first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	return pool
}

// TestTenantCVEFindingsHandler_MatchConfidenceWorstCase (PAT-1831) asserts
// the aggregate: one unverified device among several confirmed ones makes
// the whole CVE row read "version_unverified", never averaged or
// majority-voted to a stronger tier than the weakest real evidence.
func TestTenantCVEFindingsHandler_MatchConfidenceWorstCase(t *testing.T) {
	pool := pat1831Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var devConfirmed1, devConfirmed2, devUnverified string
	for _, dst := range []*string{&devConfirmed1, &devConfirmed2, &devUnverified} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID,
		).Scan(dst); err != nil {
			t.Fatalf("insert device: %v", err)
		}
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, cvss_v3_score, severity)
		VALUES ('CVE-2024-0001', 9.8, 'CRITICAL'), ('CVE-2024-0002', 7.5, 'HIGH')
	`); err != nil {
		t.Fatalf("seed cve_feed_entries: %v", err)
	}

	// CVE-0001: two confirmed devices, one unverified -> worst case wins.
	// CVE-0002: every device confirmed -> aggregate reads confirmed.
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, match_confidence)
		VALUES
			($1::uuid, 'CVE-2024-0001', 'version_confirmed'),
			($2::uuid, 'CVE-2024-0001', 'version_confirmed'),
			($3::uuid, 'CVE-2024-0001', 'version_unverified'),
			($1::uuid, 'CVE-2024-0002', 'version_confirmed'),
			($2::uuid, 'CVE-2024-0002', 'version_vendor_confirmed')
	`, devConfirmed1, devConfirmed2, devUnverified); err != nil {
		t.Fatalf("seed device_cve_findings: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/admin/tenants/{tenantID}/cve-findings", TenantCVEFindingsHandler(pool))

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/cve-findings", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cve-findings: got %d, body: %s", rr.Code, rr.Body.String())
	}

	var out struct {
		Findings []struct {
			CVEID           string `json:"cve_id"`
			MatchConfidence string `json:"match_confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rr.Body.String())
	}

	byID := map[string]string{}
	for _, f := range out.Findings {
		byID[f.CVEID] = f.MatchConfidence
	}

	if got := byID["CVE-2024-0001"]; got != "version_unverified" {
		t.Errorf("CVE-2024-0001 match_confidence = %q, want version_unverified (one unverified device must dominate two confirmed ones)", got)
	}
	// Deterministic, not just "some confirmed value": the handler's CASE
	// checks version_confirmed before falling back to
	// version_vendor_confirmed, so a mix of the two always reports
	// version_confirmed. Pinning the exact value (not either/or) catches a
	// future regression that flips this precedence silently.
	if got := byID["CVE-2024-0002"]; got != "version_confirmed" {
		t.Errorf("CVE-2024-0002 match_confidence = %q, want version_confirmed (deterministic precedence when mixed with version_vendor_confirmed)", got)
	}
}

// TestTenantCVEFindingsHandler_PatchAvailableIgnoresUnboundedRows (PAT-2107):
// cpe_ranges now also holds rows with no version bounds (an exact-version or
// platform-only CPE). patch_available must still mean "some row carries a
// version bound", as a non-empty array did before, not "any row at all".
func TestTenantCVEFindingsHandler_PatchAvailableIgnoresUnboundedRows(t *testing.T) {
	pool := pat1831Pool(t)
	ctx := context.Background()

	var tenantID, deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, severity, cpe_ranges) VALUES
			('CVE-A-BOUNDED',   'HIGH', '[{"vendor":"v","product":"p","vStartIncl":"","vStartExcl":"","vEndIncl":"","vEndExcl":"2.0"}]'),
			('CVE-B-UNBOUNDED', 'HIGH', '[{"vendor":"v","product":"p","vStartIncl":"","vStartExcl":"","vEndIncl":"","vEndExcl":"","targetSW":"windows"}]'),
			('CVE-C-EXACT',     'HIGH', '[{"vendor":"v","product":"p","vStartIncl":"","vStartExcl":"","vEndIncl":"","vEndExcl":"","version":"0.8"}]'),
			('CVE-D-EMPTY',     'HIGH', '[]'),
			('CVE-E-NULL',      'HIGH', 'null'),
			('CVE-F-MIXED',     'HIGH', '[{"vendor":"v","product":"p"},{"vendor":"v","product":"p","vStartIncl":"1.0"}]')
	`); err != nil {
		t.Fatalf("seed cve_feed_entries: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id)
		SELECT $1::uuid, cve_id FROM cve_feed_entries
	`, deviceID); err != nil {
		t.Fatalf("seed device_cve_findings: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/admin/tenants/{tenantID}/cve-findings", TenantCVEFindingsHandler(pool))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/cve-findings", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cve-findings: got %d, body: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Findings []struct {
			CVEID          string `json:"cve_id"`
			PatchAvailable bool   `json:"patch_available"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rr.Body.String())
	}
	got := map[string]bool{}
	for _, f := range out.Findings {
		got[f.CVEID] = f.PatchAvailable
	}
	want := map[string]bool{
		"CVE-A-BOUNDED": true, "CVE-B-UNBOUNDED": false, "CVE-C-EXACT": false,
		"CVE-D-EMPTY": false, "CVE-E-NULL": false, "CVE-F-MIXED": true,
	}
	for id, w := range want {
		if g, ok := got[id]; !ok || g != w {
			t.Errorf("%s patch_available = %v (present %v), want %v", id, g, ok, w)
		}
	}
}
