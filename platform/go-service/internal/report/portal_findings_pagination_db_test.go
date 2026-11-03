package report

// PAT-1201: pagination for FetchPortalCVEFindingsPage, the data layer behind
// GET /v1/portal/findings. Portal's /findings page was rendering every open
// finding in one unpaginated HTML table (709 rows -> 646KB on tenant-zero);
// this endpoint now bounds each response to a page via LIMIT/OFFSET with the
// total row count carried back via COUNT(*) OVER(), the same convention
// FetchTenantDevices and TenantCVEFindingsHandler already use.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as admin_devices_db_test.go (PAT-745). The pool's search_path
// is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/exploitation"
)

const pat1201Schema = "pat1201_test"

func pat1201Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1201Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1201Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1201Schema,
		`CREATE TABLE ` + pat1201Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1201Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1201Schema + `.tenants(id),
			hostname  TEXT,
			serial    TEXT
		)`,
		// Only the columns FetchPortalCVEFindingsPage's query touches.
		`CREATE TABLE ` + pat1201Schema + `.cve_feed_entries (
			cve_id        TEXT PRIMARY KEY,
			description   TEXT NOT NULL DEFAULT '',
			description_source TEXT NOT NULL DEFAULT '',
			cvss_v3_score NUMERIC(4,1),
			severity      TEXT
		)`,
		`CREATE TABLE ` + pat1201Schema + `.device_cve_findings (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL REFERENCES ` + pat1201Schema + `.devices(id),
			cve_id         TEXT NOT NULL REFERENCES ` + pat1201Schema + `.cve_feed_entries(cve_id),
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
		`CREATE TABLE ` + pat1201Schema + `.cve_exploitation_source_state (
			source TEXT PRIMARY KEY,
			source_url TEXT NOT NULL,
			status TEXT NOT NULL,
			attempted_at TIMESTAMPTZ NOT NULL,
			fetched_at TIMESTAMPTZ,
			source_revision TEXT NOT NULL DEFAULT '',
			evidence_count INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE ` + pat1201Schema + `.cve_exploitation_evidence (
			source TEXT NOT NULL REFERENCES ` + pat1201Schema + `.cve_exploitation_source_state(source),
			cve_id TEXT NOT NULL,
			source_url TEXT NOT NULL,
			fetched_at TIMESTAMPTZ NOT NULL,
			source_revision TEXT NOT NULL DEFAULT '',
			match_basis TEXT NOT NULL,
			PRIMARY KEY (source, cve_id, match_basis)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1201Schema+` CASCADE`)
	})
	return pool
}

func TestFetchPortalCVEFindingsPage_ExploitationEvidenceRemainsTenantIsolated(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()
	tenantA, deviceA := pat1201SeedTenant(t, ctx, pool, "PAT-1871 Tenant A")
	_, deviceB := pat1201SeedTenant(t, ctx, pool, "PAT-1871 Tenant B")
	pat1201SeedFinding(t, ctx, pool, deviceA, "CVE-2026-18710", 9.8)
	pat1201SeedFinding(t, ctx, pool, deviceB, "CVE-2026-18711", 9.9)

	fetchedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_exploitation_source_state
			(source,source_url,status,attempted_at,fetched_at,source_revision,evidence_count)
		VALUES ($1,$2,'succeeded',$3,$3,'fixture',2)
	`, exploitation.SourceCISAKEV, exploitation.CISAKEVURL, fetchedAt); err != nil {
		t.Fatalf("seed source state: %v", err)
	}
	for _, cveID := range []string{"CVE-2026-18710", "CVE-2026-18711"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cve_exploitation_evidence
				(source,cve_id,source_url,fetched_at,source_revision,match_basis)
			VALUES ($1,$2,$3,$4,'fixture',$5)
		`, exploitation.SourceCISAKEV, cveID, exploitation.CISAKEVURL, fetchedAt, exploitation.MatchBasisCISAExact); err != nil {
			t.Fatalf("seed exploitation evidence %s: %v", cveID, err)
		}
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantA, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if len(page.Findings) != 1 || page.Findings[0].CVEID != "CVE-2026-18710" {
		t.Fatalf("tenant A findings = %#v", page.Findings)
	}
	if page.Findings[0].Exploitation.Status != exploitation.StatusActivelyExploited {
		t.Fatalf("tenant A exploitation = %#v", page.Findings[0].Exploitation)
	}
	if len(page.Findings[0].Exploitation.Evidence) != 1 ||
		page.Findings[0].Exploitation.Evidence[0].SourceURL != exploitation.CISAKEVURL ||
		page.Findings[0].Exploitation.Evidence[0].MatchBasis != exploitation.MatchBasisCISAExact {
		t.Fatalf("tenant A exploitation provenance = %#v", page.Findings[0].Exploitation.Evidence)
	}
	for _, finding := range page.Findings {
		if finding.CVEID == "CVE-2026-18711" {
			t.Fatal("tenant B finding leaked into tenant A response")
		}
	}
}

// pat1201SeedTenant inserts a tenant and one device, returning both IDs.
func pat1201SeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) (tenantID, deviceID string) {
	t.Helper()
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ($1) RETURNING id::text
	`, name).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return tenantID, deviceID
}

// pat1201SeedFinding inserts a CVE feed entry (if not already present) and
// one device_cve_findings row for it, with a descending CVSS score so
// findings sort in a known, deterministic order (matches the production
// query's ORDER BY cvss_v3_score DESC).
func pat1201SeedFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID, cveID string, cvss float64) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, cvss_v3_score, severity)
		VALUES ($1, 'test finding', $2, 'high')
		ON CONFLICT (cve_id) DO NOTHING
	`, cveID, cvss); err != nil {
		t.Fatalf("insert cve feed entry %s: %v", cveID, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version)
		VALUES ($1::uuid, $2, 'TestApp', '1.0')
	`, deviceID, cveID); err != nil {
		t.Fatalf("insert device cve finding %s: %v", cveID, err)
	}
}

// pat1201SeedDevice inserts one device with the given hostname, returning its
// id.
func pat1201SeedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, hostname string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname) VALUES ($1::uuid, $2) RETURNING id::text
	`, tenantID, hostname).Scan(&deviceID); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
	return deviceID
}

// TestFetchPortalCVEFindingsPage_DeviceDrilldown (PAT-1587) seeds 3 devices
// all reporting the same (cve, app, version) finding, each with a distinct
// hostname, and checks the returned Devices drill-down list contains all
// three, sorted by hostname, with DevicesTruncated false.
func TestFetchPortalCVEFindingsPage_DeviceDrilldown(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, _ := pat1201SeedTenant(t, ctx, pool, "PAT-1587 Drilldown Tenant")

	hostnames := []string{"zeta-host", "alpha-host", "mid-host"}
	deviceIDs := make(map[string]string, len(hostnames))
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, cvss_v3_score, severity)
		VALUES ('CVE-2024-1587-DD', 'drilldown test', 8.0, 'high')
	`); err != nil {
		t.Fatalf("insert cve feed entry: %v", err)
	}
	for _, h := range hostnames {
		deviceID := pat1201SeedDevice(t, ctx, pool, tenantID, h)
		deviceIDs[h] = deviceID
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version)
			VALUES ($1::uuid, 'CVE-2024-1587-DD', 'DrillApp', '1.0')
		`, deviceID); err != nil {
			t.Fatalf("insert finding for %s: %v", h, err)
		}
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if len(page.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(page.Findings))
	}
	f := page.Findings[0]
	if f.DevicesAffected != 3 {
		t.Fatalf("DevicesAffected = %d, want 3", f.DevicesAffected)
	}
	if f.DevicesTruncated {
		t.Errorf("DevicesTruncated = true, want false")
	}
	if len(f.Devices) != 3 {
		t.Fatalf("len(Devices) = %d, want 3", len(f.Devices))
	}

	wantOrder := []string{"alpha-host", "mid-host", "zeta-host"}
	for i, want := range wantOrder {
		if f.Devices[i].Hostname != want {
			t.Errorf("Devices[%d].Hostname = %q, want %q (sorted by hostname)", i, f.Devices[i].Hostname, want)
		}
		if f.Devices[i].DeviceID != deviceIDs[want] {
			t.Errorf("Devices[%d].DeviceID = %q, want %q", i, f.Devices[i].DeviceID, deviceIDs[want])
		}
	}
}

// TestFetchPortalCVEFindingsPage_DeviceDrilldownTruncated (PAT-1587) seeds
// more devices than portalFindingsMaxDevices reporting the same finding and
// checks DevicesTruncated flips true with the list capped at exactly the
// constant, while DevicesAffected stays the exact uncapped count.
func TestFetchPortalCVEFindingsPage_DeviceDrilldownTruncated(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, _ := pat1201SeedTenant(t, ctx, pool, "PAT-1587 Drilldown Truncated Tenant")

	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, cvss_v3_score, severity)
		VALUES ('CVE-2024-1587-DDT', 'drilldown truncation test', 7.0, 'high')
	`); err != nil {
		t.Fatalf("insert cve feed entry: %v", err)
	}

	const seedCount = portalFindingsMaxDevices + 5
	for i := 0; i < seedCount; i++ {
		// Zero-padded so hostname sort order == numeric order, matching the
		// convention integration/portal_test.go already uses for the
		// analogous extensions device cap test.
		hostname := fmt.Sprintf("ddt-host-%03d", i)
		deviceID := pat1201SeedDevice(t, ctx, pool, tenantID, hostname)
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version)
			VALUES ($1::uuid, 'CVE-2024-1587-DDT', 'DrillApp', '1.0')
		`, deviceID); err != nil {
			t.Fatalf("insert finding for %s: %v", hostname, err)
		}
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if len(page.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(page.Findings))
	}
	f := page.Findings[0]
	if f.DevicesAffected != seedCount {
		t.Errorf("DevicesAffected = %d, want %d (exact, uncapped)", f.DevicesAffected, seedCount)
	}
	if !f.DevicesTruncated {
		t.Errorf("DevicesTruncated = false, want true")
	}
	if len(f.Devices) != portalFindingsMaxDevices {
		t.Fatalf("len(Devices) = %d, want %d (capped at portalFindingsMaxDevices)", len(f.Devices), portalFindingsMaxDevices)
	}
	// The cap keeps the FIRST portalFindingsMaxDevices by hostname:
	// ddt-host-000..ddt-host-049 survive, 050+ are cut.
	if got, want := f.Devices[0].Hostname, "ddt-host-000"; got != want {
		t.Errorf("Devices[0].Hostname = %q, want %q", got, want)
	}
	if got, want := f.Devices[len(f.Devices)-1].Hostname, fmt.Sprintf("ddt-host-%03d", portalFindingsMaxDevices-1); got != want {
		t.Errorf("Devices[last].Hostname = %q, want %q", got, want)
	}
}

// TestFetchPortalCVEFindingsPage_Boundaries seeds 5 findings with distinct,
// descending CVSS scores (so ORDER BY is deterministic) and checks page
// boundaries: a full first page, a partial last page, and that total always
// reflects the full unfiltered count regardless of which page was asked for.
func TestFetchPortalCVEFindingsPage_Boundaries(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, deviceID := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Boundaries Tenant")

	// CVE-...-0 has the highest CVSS (9.9) down to CVE-...-4 (9.5), so the
	// production ORDER BY (cvss_v3_score DESC, cve_id, app_name) yields them
	// in seed order: 0,1,2,3,4.
	ids := []string{
		"CVE-2024-1201-0", "CVE-2024-1201-1", "CVE-2024-1201-2",
		"CVE-2024-1201-3", "CVE-2024-1201-4",
	}
	for i, id := range ids {
		pat1201SeedFinding(t, ctx, pool, deviceID, id, 9.9-float64(i)*0.1)
	}

	// Page 1: limit 2, offset 0 -> first two, total 5.
	page1, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 2, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage page1: %v", err)
	}
	if page1.Total != 5 {
		t.Errorf("page1 Total = %d, want 5", page1.Total)
	}
	if len(page1.Findings) != 2 {
		t.Fatalf("page1 len(Findings) = %d, want 2", len(page1.Findings))
	}
	if page1.Findings[0].CVEID != ids[0] || page1.Findings[1].CVEID != ids[1] {
		t.Errorf("page1 CVE order = [%s, %s], want [%s, %s]",
			page1.Findings[0].CVEID, page1.Findings[1].CVEID, ids[0], ids[1])
	}

	// Page 2: limit 2, offset 2 -> next two, total still 5.
	page2, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 2, 2)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage page2: %v", err)
	}
	if page2.Total != 5 {
		t.Errorf("page2 Total = %d, want 5", page2.Total)
	}
	if len(page2.Findings) != 2 {
		t.Fatalf("page2 len(Findings) = %d, want 2", len(page2.Findings))
	}
	if page2.Findings[0].CVEID != ids[2] || page2.Findings[1].CVEID != ids[3] {
		t.Errorf("page2 CVE order = [%s, %s], want [%s, %s]",
			page2.Findings[0].CVEID, page2.Findings[1].CVEID, ids[2], ids[3])
	}

	// Page 3 (last, partial): limit 2, offset 4 -> one row, total still 5.
	page3, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 2, 4)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage page3: %v", err)
	}
	if page3.Total != 5 {
		t.Errorf("page3 Total = %d, want 5", page3.Total)
	}
	if len(page3.Findings) != 1 {
		t.Fatalf("page3 len(Findings) = %d, want 1 (partial last page)", len(page3.Findings))
	}
	if page3.Findings[0].CVEID != ids[4] {
		t.Errorf("page3 CVE = %s, want %s", page3.Findings[0].CVEID, ids[4])
	}

	// Page beyond the last page: offset past total -> empty findings, total
	// still reflects the full count (not 0), so the portal can tell "no more
	// rows here" apart from "no rows at all".
	pageBeyond, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 2, 100)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage pageBeyond: %v", err)
	}
	if len(pageBeyond.Findings) != 0 {
		t.Errorf("pageBeyond len(Findings) = %d, want 0", len(pageBeyond.Findings))
	}
	if pageBeyond.Total != 0 {
		// NOTE: COUNT(*) OVER() only reflects rows that made it into the
		// result set — with zero rows returned (offset past the end), the
		// window function has nothing to count from, so Total falls back to
		// the Go zero value. This is the same behaviour FetchTenantDevices
		// already has (see admin.go) — documented here, not silently
		// assumed, so a portal implementer reading this test doesn't expect
		// total=5 on an empty page.
		t.Errorf("pageBeyond Total = %d, want 0 (COUNT(*) OVER() yields nothing when the page itself is empty)", pageBeyond.Total)
	}
}

// TestFetchPortalCVEFindingsPage_Empty covers a tenant with zero findings —
// must return an empty page and zero total, not an error.
func TestFetchPortalCVEFindingsPage_Empty(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, _ := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Empty Tenant")

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("Total = %d, want 0", page.Total)
	}
	if len(page.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(page.Findings))
	}
}

// TestFetchPortalCVEFindingsPage_TenantIsolation confirms one tenant's
// findings never leak into another tenant's page or total count.
func TestFetchPortalCVEFindingsPage_TenantIsolation(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantA, deviceA := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Tenant A")
	tenantB, _ := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Tenant B")

	pat1201SeedFinding(t, ctx, pool, deviceA, "CVE-2024-1201-A1", 9.0)
	pat1201SeedFinding(t, ctx, pool, deviceA, "CVE-2024-1201-A2", 8.0)

	pageA, err := FetchPortalCVEFindingsPage(ctx, pool, tenantA, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage tenantA: %v", err)
	}
	if pageA.Total != 2 {
		t.Errorf("tenantA Total = %d, want 2", pageA.Total)
	}

	pageB, err := FetchPortalCVEFindingsPage(ctx, pool, tenantB, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage tenantB: %v", err)
	}
	if pageB.Total != 0 {
		t.Errorf("tenantB Total = %d, want 0 (must not see tenantA's findings)", pageB.Total)
	}
	if len(pageB.Findings) != 0 {
		t.Errorf("tenantB len(Findings) = %d, want 0", len(pageB.Findings))
	}
}

// TestFetchPortalCVEFindingsPage_FirstSeenAggregation is a light sanity
// check that the aggregation (MIN(first_seen_at) across devices for the same
// CVE/app/version) still works under LIMIT/OFFSET, matching the unpaginated
// FetchPortalCVEFindings behaviour it was copied from.
func TestFetchPortalCVEFindingsPage_FirstSeenAggregation(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, device1 := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Aggregation Tenant")
	var device2 string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text
	`, tenantID).Scan(&device2); err != nil {
		t.Fatalf("insert second device: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, cvss_v3_score, severity)
		VALUES ('CVE-2024-1201-AGG', 'aggregation test', 7.5, 'high')
	`); err != nil {
		t.Fatalf("insert cve feed entry: %v", err)
	}

	earlier := time.Now().Add(-48 * time.Hour)
	later := time.Now().Add(-1 * time.Hour)
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, first_seen_at)
		VALUES ($1::uuid, 'CVE-2024-1201-AGG', 'TestApp', '1.0', $2)
	`, device1, earlier); err != nil {
		t.Fatalf("insert finding on device1: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, first_seen_at)
		VALUES ($1::uuid, 'CVE-2024-1201-AGG', 'TestApp', '1.0', $2)
	`, device2, later); err != nil {
		t.Fatalf("insert finding on device2: %v", err)
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("Total = %d, want 1 (one CVE/app/version row, aggregated across 2 devices)", page.Total)
	}
	if len(page.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(page.Findings))
	}
	f := page.Findings[0]
	if f.DevicesAffected != 2 {
		t.Errorf("DevicesAffected = %d, want 2", f.DevicesAffected)
	}
	if !f.FirstSeen.Equal(earlier) && f.FirstSeen.Sub(earlier).Abs() > time.Second {
		t.Errorf("FirstSeen = %v, want the earlier of the two (%v)", f.FirstSeen, earlier)
	}
}

// TestFetchPortalCVEFindingsPage_FieldContent seeds one finding with known,
// distinct values for every PortalCVEFinding field (including a
// mixed-case severity, to confirm LOWER() is actually applied, and two
// devices, to confirm DevicesAffected/MIN(first_seen_at) aggregate rather
// than just reflect a single row) and asserts each field on the returned
// struct — the existing boundary/empty/isolation tests above only check
// counts and CVE ordering, never that the field values themselves are
// correct for a known seeded row.
func TestFetchPortalCVEFindingsPage_FieldContent(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, device1 := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Field Content Tenant")
	var device2 string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text
	`, tenantID).Scan(&device2); err != nil {
		t.Fatalf("insert second device: %v", err)
	}

	const cvss = 8.8
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ('CVE-2024-1201-FIELDS', 'Remote code execution in libfoo', 'msrc', $1, 'HIGH')
	`, cvss); err != nil {
		t.Fatalf("insert cve feed entry: %v", err)
	}

	earliest := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	later := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, first_seen_at)
		VALUES ($1::uuid, 'CVE-2024-1201-FIELDS', 'LibFoo', '2.3.4', $2)
	`, device1, earliest); err != nil {
		t.Fatalf("insert finding on device1: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, first_seen_at)
		VALUES ($1::uuid, 'CVE-2024-1201-FIELDS', 'LibFoo', '2.3.4', $2)
	`, device2, later); err != nil {
		t.Fatalf("insert finding on device2: %v", err)
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if len(page.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(page.Findings))
	}

	f := page.Findings[0]
	if f.CVEID != "CVE-2024-1201-FIELDS" {
		t.Errorf("CVEID = %q, want CVE-2024-1201-FIELDS", f.CVEID)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want lowercased %q", f.Severity, "high")
	}
	if f.CVSS == nil || *f.CVSS != cvss {
		t.Errorf("CVSS = %v, want %v", f.CVSS, cvss)
	}
	if f.App != "LibFoo" {
		t.Errorf("App = %q, want LibFoo", f.App)
	}
	if f.Version != "2.3.4" {
		t.Errorf("Version = %q, want 2.3.4", f.Version)
	}
	if f.DevicesAffected != 2 {
		t.Errorf("DevicesAffected = %d, want 2", f.DevicesAffected)
	}
	if !f.FirstSeen.Equal(earliest) {
		t.Errorf("FirstSeen = %v, want the earlier seen time %v", f.FirstSeen, earliest)
	}
	if f.Summary != "Remote code execution in libfoo" {
		t.Errorf("Summary = %q, want %q", f.Summary, "Remote code execution in libfoo")
	}
	if f.DescriptionSource != "msrc" {
		t.Errorf("DescriptionSource = %q, want msrc", f.DescriptionSource)
	}
}

// TestFetchPortalCVEFindingsPage_LimitExceedsTotalRows checks a limit larger
// than the total matching row count: every row must come back on the single
// page, and Total must reflect the true row count, not be silently clamped
// to (or coincidentally equal) limit or len(Findings). The boundary test
// above never exercises limit > total, so this is the only test that would
// catch a mistaken "Total = min(limit, actualTotal)" implementation.
func TestFetchPortalCVEFindingsPage_LimitExceedsTotalRows(t *testing.T) {
	pool := pat1201Pool(t)
	ctx := context.Background()

	tenantID, deviceID := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Limit Exceeds Total Tenant")

	ids := []string{"CVE-2024-1201-LX-0", "CVE-2024-1201-LX-1", "CVE-2024-1201-LX-2"}
	for i, id := range ids {
		pat1201SeedFinding(t, ctx, pool, deviceID, id, 9.0-float64(i)*0.1)
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 1000, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}
	if page.Total != len(ids) {
		t.Errorf("Total = %d, want %d (true row count, not clamped to limit)", page.Total, len(ids))
	}
	if len(page.Findings) != len(ids) {
		t.Fatalf("len(Findings) = %d, want %d (all rows returned since limit > total)", len(page.Findings), len(ids))
	}
	for i, id := range ids {
		if page.Findings[i].CVEID != id {
			t.Errorf("Findings[%d].CVEID = %s, want %s", i, page.Findings[i].CVEID, id)
		}
	}
}

// pat1201PoolNoCVETables sets up the same tenants/devices tables as
// pat1201Pool but deliberately omits cve_feed_entries and
// device_cve_findings — simulating a fresh/pre-migration install where
// patched-cve-sync hasn't run yet and the CVE matcher tables don't exist.
func pat1201PoolNoCVETables(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	schema := pat1201Schema + "_no_cve"
	// Deliberately NOT ",public" (unlike pat1201Pool). Running the full
	// verification gate applies real migrations to the shared
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
	// (portal_cve_attention_db_test.go) for the identical fix and rationale.
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

// TestFetchPortalCVEFindingsPage_TablesNotMigrated mirrors the unpaginated
// FetchPortalCVEFindings' isUndefinedTable degrade path (portal.go, "CVE
// matcher data absent — degrade, don't 500"): on a fresh/pre-migration
// schema where device_cve_findings/cve_feed_entries don't exist yet, the
// query fails with Postgres 42P01, which isUndefinedTable must catch so the
// paginated path degrades to an empty page with a nil error — exactly the
// same behaviour as the unpaginated fetcher, not a new/different one.
func TestFetchPortalCVEFindingsPage_TablesNotMigrated(t *testing.T) {
	pool := pat1201PoolNoCVETables(t)
	ctx := context.Background()

	tenantID, _ := pat1201SeedTenant(t, ctx, pool, "PAT-1201 Not Migrated Tenant")

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v, want nil error (degrade like FetchPortalCVEFindings, not an error)", err)
	}
	if page.Total != 0 {
		t.Errorf("Total = %d, want 0", page.Total)
	}
	if len(page.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(page.Findings))
	}
}
