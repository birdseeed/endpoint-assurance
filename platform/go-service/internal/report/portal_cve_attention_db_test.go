package report

// PAT-1953: GET /v1/portal/overview's CVE-attention summary.
// "Absence requires authority" (root AGENTS.md) applies here exactly like it
// does to fetchPortalCoverage's two signals (portal_coverage_db_test.go):
// these tests pin fetchPortalCVEAttention's confirmed-match, severity and
// availability rules.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as portal_coverage_db_test.go (pat1588Pool) and
// portal_findings_pagination_db_test.go (pat1201Pool). The pool's
// search_path is pinned to an isolated schema so no real data is touched.
//
// The schema here is pat1588Pool's full FetchPortalOverview call-chain
// schema (tenants/devices/compliance_rules/tenant_rules/
// compliance_evaluations/patches/device_agent_health) plus the two CVE
// matcher tables from pat1201Pool (cve_feed_entries/device_cve_findings),
// since FetchPortalOverview's end-to-end tests need the whole chain to
// succeed, not just the CVE tables in isolation.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1953Schema = "pat1953_test"

// pat1953Pool builds the same tables as pat1588Pool (FetchPortalOverview's
// full dependency chain) plus cve_feed_entries and device_cve_findings.
func pat1953Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1953Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1953Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1953Schema,
		`CREATE TABLE ` + pat1953Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1953Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1953Schema + `.tenants(id),
			hostname             TEXT,
			serial               TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1953Schema + `.compliance_rules (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key        TEXT NOT NULL,
			benchmark       TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title           TEXT NOT NULL,
			severity        TEXT NOT NULL DEFAULT 'low',
			platform        TEXT NOT NULL DEFAULT 'macos',
			collection_tier TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			device_class    TEXT[]
		)`,
		// tenant_rules (PAT-1794): see pat1588Pool for why this must exist
		// even with no rows seeded here.
		`CREATE TABLE ` + pat1953Schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + pat1953Schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + pat1953Schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + pat1953Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1953Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_retirement_decisions (PAT-2135): read by the overview's
		// coverage query.
		`CREATE TABLE ` + pat1953Schema + `.device_retirement_decisions (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL,
			device_id   UUID NOT NULL,
			action      TEXT NOT NULL,
			reason      TEXT,
			actor_email TEXT NOT NULL,
			decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1953Schema + `.device_agent_health (
			device_id      UUID NOT NULL REFERENCES ` + pat1953Schema + `.devices(id),
			kind           TEXT NOT NULL,
			subject        TEXT NOT NULL,
			reason         TEXT NOT NULL DEFAULT '',
			first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
			count          BIGINT NOT NULL DEFAULT 1,
			ever_succeeded BOOLEAN NOT NULL DEFAULT false,
			collected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (device_id, kind, subject)
		)`,
		// Only the columns fetchPortalCVEAttention / FetchPortalCVEFindingsPage
		// touch — same minimal shape as pat1201Pool.
		`CREATE TABLE ` + pat1953Schema + `.cve_feed_entries (
			cve_id              TEXT PRIMARY KEY,
			description         TEXT NOT NULL DEFAULT '',
			description_source  TEXT NOT NULL DEFAULT '',
			cvss_v3_score       NUMERIC(4,1),
			severity            TEXT
		)`,
		`CREATE TABLE ` + pat1953Schema + `.device_cve_findings (
			id               BIGSERIAL PRIMARY KEY,
			device_id        UUID NOT NULL REFERENCES ` + pat1953Schema + `.devices(id),
			cve_id           TEXT NOT NULL REFERENCES ` + pat1953Schema + `.cve_feed_entries(cve_id),
			app_name         TEXT NOT NULL,
			app_version      TEXT NOT NULL DEFAULT '',
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified',
			fixed_version    TEXT NOT NULL DEFAULT '',
			first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
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
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1953Schema+` CASCADE`)
	})
	return pool
}

// pat1953PoolNoCVETables is pat1953Pool minus the two CVE matcher tables —
// simulating a fresh/pre-migration install where patched-cve-sync hasn't run
// yet, mirroring pat1201PoolNoCVETables one directory over.
func pat1953PoolNoCVETables(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	schema := pat1953Schema + "_no_cve"
	// Deliberately NOT ",public" (unlike pat1953Pool/pat1953PoolNoCVETables'
	// siblings elsewhere in this codebase). Running the full verification
	// gate applies real migrations to the shared TEST_DATABASE_URL's public
	// schema first (integration/helpers_test.go), which creates real (if
	// empty, for an unrelated tenant) cve_feed_entries/device_cve_findings
	// tables there — with "public" in the search_path, an unqualified
	// reference to those two tables would silently resolve to public's
	// copies instead of genuinely failing to resolve, defeating the point of
	// this test (it would pass on an empty-join coincidence, never actually
	// exercising isUndefinedTable). Schema-only search_path makes the two
	// CVE tables genuinely unresolvable regardless of what has or hasn't run
	// against public earlier in the same test session.
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
			id              UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + schema + `.tenants(id),
			hostname             TEXT,
			serial               TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + schema + `.compliance_rules (
			id              UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			rule_key        TEXT NOT NULL,
			benchmark       TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title           TEXT NOT NULL,
			severity        TEXT NOT NULL DEFAULT 'low',
			platform        TEXT NOT NULL DEFAULT 'macos',
			collection_tier TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			device_class    TEXT[]
		)`,
		`CREATE TABLE ` + schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT public.gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_retirement_decisions (PAT-2135): read by the overview's
		// coverage query.
		`CREATE TABLE ` + schema + `.device_retirement_decisions (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL,
			device_id   UUID NOT NULL,
			action      TEXT NOT NULL,
			reason      TEXT,
			actor_email TEXT NOT NULL,
			decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + schema + `.device_agent_health (
			device_id      UUID NOT NULL REFERENCES ` + schema + `.devices(id),
			kind           TEXT NOT NULL,
			subject        TEXT NOT NULL,
			reason         TEXT NOT NULL DEFAULT '',
			first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
			count          BIGINT NOT NULL DEFAULT 1,
			ever_succeeded BOOLEAN NOT NULL DEFAULT false,
			collected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (device_id, kind, subject)
		)`,
		// cve_feed_entries / device_cve_findings deliberately absent.
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

func pat1953SeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1953 Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

func pat1953SeedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, hostname string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, $2, 'macOS')
		RETURNING id::text
	`, tenantID, hostname).Scan(&deviceID); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
	return deviceID
}

// pat1953SeedCVE inserts a cve_feed_entries row (if not already present) and
// one device_cve_findings row for the given device.
func pat1953SeedCVE(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID, cveID, severity, matchConfidence string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, severity)
		VALUES ($1, 'test finding', $2)
		ON CONFLICT (cve_id) DO NOTHING
	`, cveID, severity); err != nil {
		t.Fatalf("insert cve feed entry %s: %v", cveID, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, match_confidence)
		VALUES ($1::uuid, $2, 'TestApp', '1.0', $3)
	`, deviceID, cveID, matchConfidence); err != nil {
		t.Fatalf("insert device cve finding %s on %s: %v", cveID, deviceID, err)
	}
}

// TestFetchPortalCVEAttention_ConfirmedCriticalCounted proves a critical CVE
// with a version_confirmed match is counted.
func TestFetchPortalCVEAttention_ConfirmedCriticalCounted(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-C1", "critical", "version_confirmed")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if !att.Available {
		t.Fatal("Available = false, want true (CVE tables exist)")
	}
	if att.Critical != 1 {
		t.Errorf("Critical = %d, want 1", att.Critical)
	}
	if att.High != 0 {
		t.Errorf("High = %d, want 0", att.High)
	}
}

// TestFetchPortalCVEAttention_UnverifiedNotCounted proves a critical CVE
// whose only backing match is version_unverified is NOT counted — the
// ticket's explicit "do not count unknown/unsupported matches as confirmed
// exposure" requirement.
func TestFetchPortalCVEAttention_UnverifiedNotCounted(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-U1", "critical", "version_unverified")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if !att.Available {
		t.Fatal("Available = false, want true")
	}
	if att.Critical != 0 {
		t.Errorf("Critical = %d, want 0 (version_unverified is not confirmed exposure)", att.Critical)
	}
	if att.High != 0 {
		t.Errorf("High = %d, want 0", att.High)
	}
}

// TestFetchPortalCVEAttention_VendorConfirmedCounted proves a
// version_vendor_confirmed match (PAT-409 — Apple security releases / MSRC)
// is counted as confirmed, same as version_confirmed. A naive literal
// equality check against "version_confirmed" alone would wrongly exclude
// this — see fetchPortalCVEAttention's doc comment.
func TestFetchPortalCVEAttention_VendorConfirmedCounted(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-VC1", "high", "version_vendor_confirmed")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if att.High != 1 {
		t.Errorf("High = %d, want 1 (version_vendor_confirmed counts as confirmed)", att.High)
	}
}

// TestFetchPortalCVEAttention_MixedConfidenceAcrossDevicesIsUnverified
// proves the "weakest signal wins" rule (PAT-1831 precedent, cve.go): when
// the same CVE is backed by one confirmed device and one unverified device,
// the CVE as a whole is NOT counted — never averaged or majority-voted into
// confirmed by the other device.
func TestFetchPortalCVEAttention_MixedConfidenceAcrossDevicesIsUnverified(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	confirmedDevice := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-confirmed")
	unverifiedDevice := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-unverified")

	pat1953SeedCVE(t, ctx, pool, confirmedDevice, "CVE-2026-1953-MIX", "critical", "version_confirmed")
	pat1953SeedCVE(t, ctx, pool, unverifiedDevice, "CVE-2026-1953-MIX", "critical", "version_unverified")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if att.Critical != 0 {
		t.Errorf("Critical = %d, want 0 (one unverified device makes the whole CVE unverified)", att.Critical)
	}
}

// TestFetchPortalCVEAttention_HomebrewHeadBuildCannotHideVendorConfirmed
// (PAT-2023 review): a vendor-confirmed critical macOS CVE on one Mac, and
// the same CVE matched on another Mac only through a Homebrew HEAD build
// (version_unverified, tier low, no version evidence at all). The HEAD row
// must not win the weakest-signal vote and pull the CVE out of attention.
// A non-Homebrew unverified row still does (MixedConfidence test above).
func TestFetchPortalCVEAttention_HomebrewHeadBuildCannotHideVendorConfirmed(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	macOS := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-macos")
	brew := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-brew-head")

	pat1953SeedCVE(t, ctx, pool, macOS, "CVE-2026-2023-HEAD", "critical", "version_vendor_confirmed")
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, match_confidence,
		                                 package_source, confidence_tier)
		VALUES ($1::uuid, 'CVE-2026-2023-HEAD', 'openssl@3 (Homebrew formula)', 'HEAD-3a0b7c9',
		        'version_unverified', 'homebrew_formula', 'low')
	`, brew); err != nil {
		t.Fatalf("insert homebrew HEAD finding: %v", err)
	}

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if att.Critical != 1 {
		t.Errorf("Critical = %d, want 1 (a Homebrew HEAD build must not hide a vendor-confirmed CVE)", att.Critical)
	}
}

// TestFetchPortalCVEAttention_MediumLowNotCounted proves medium and low
// severity CVEs, even with a confirmed match, are excluded.
func TestFetchPortalCVEAttention_MediumLowNotCounted(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-M1", "medium", "version_confirmed")
	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-L1", "low", "version_confirmed")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if att.Critical != 0 || att.High != 0 {
		t.Errorf("Critical=%d High=%d, want 0/0 (medium/low never count)", att.Critical, att.High)
	}
}

// TestFetchPortalCVEAttention_SameCVEMultipleDevicesCountedOnce proves a
// single critical CVE affecting several devices, all confirmed, counts once
// — distinct CVE risk, not per-device observations.
func TestFetchPortalCVEAttention_SameCVEMultipleDevicesCountedOnce(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)

	for i, hostname := range []string{"dev-01", "dev-02", "dev-03"} {
		deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, hostname)
		_ = i
		pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-SHARED", "critical", "version_confirmed")
	}

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if att.Critical != 1 {
		t.Errorf("Critical = %d, want 1 (one CVE across 3 devices counts once)", att.Critical)
	}
}

// TestFetchPortalCVEAttention_TenantIsolation confirms one tenant's CVE
// findings never leak into another's count.
func TestFetchPortalCVEAttention_TenantIsolation(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantA := pat1953SeedTenant(t, ctx, pool)
	tenantB := pat1953SeedTenant(t, ctx, pool)
	deviceA := pat1953SeedDevice(t, ctx, pool, tenantA, "a-dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceA, "CVE-2026-1953-ISO", "critical", "version_confirmed")

	attB, err := fetchPortalCVEAttention(ctx, pool, tenantB)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention tenantB: %v", err)
	}
	if attB.Critical != 0 {
		t.Errorf("tenantB Critical = %d, want 0 (must not see tenantA's finding)", attB.Critical)
	}
}

// TestFetchPortalCVEAttention_ZeroFindingsIsAvailableZero proves a tenant
// with the CVE tables present but zero real findings gets Available=true,
// Critical=0, High=0 — distinguishable from the tables-absent degrade case
// below, which must show Available=false instead.
func TestFetchPortalCVEAttention_ZeroFindingsIsAvailableZero(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}
	if !att.Available {
		t.Error("Available = false, want true (tables exist, just empty)")
	}
	if att.Critical != 0 || att.High != 0 {
		t.Errorf("Critical=%d High=%d, want 0/0", att.Critical, att.High)
	}
}

// TestFetchPortalCVEAttention_TablesNotMigratedDegradesUnavailable is the
// graceful-degrade case: on a fresh/pre-migration schema without
// cve_feed_entries/device_cve_findings, fetchPortalCVEAttention must catch
// Postgres 42P01 via isUndefinedTable and return Available=false with a nil
// error — never a 500, and never a false "zero" (a customer must not be
// told "you have zero critical CVEs" when the true answer is unknown).
// Mirrors TestFetchPortalCoverage_AgentHealthTableAbsentDegradesToZero and
// TestFetchPortalCVEFindingsPage_TablesNotMigrated's identical pattern.
func TestFetchPortalCVEAttention_TablesNotMigratedDegradesUnavailable(t *testing.T) {
	pool := pat1953PoolNoCVETables(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v, want nil error (degrade, not an error)", err)
	}
	if att.Available {
		t.Error("Available = true, want false (CVE matcher tables absent — must not claim zero)")
	}
	if att.Critical != 0 || att.High != 0 {
		t.Errorf("Critical=%d High=%d, want 0/0 (zero values, but Available=false is what makes them non-authoritative)", att.Critical, att.High)
	}
}

// TestFetchPortalOverview_CarriesCVEAttention is the end-to-end check that
// FetchPortalOverview (not just the unexported fetchPortalCVEAttention
// helper) wires CVEAttention onto PortalOverview.
func TestFetchPortalOverview_CarriesCVEAttention(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)
	deviceID := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")

	pat1953SeedCVE(t, ctx, pool, deviceID, "CVE-2026-1953-E2E", "critical", "version_confirmed")

	ov, err := FetchPortalOverview(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchPortalOverview: %v", err)
	}
	if !ov.CVEAttention.Available {
		t.Fatal("CVEAttention.Available = false, want true")
	}
	if ov.CVEAttention.Critical != 1 {
		t.Errorf("CVEAttention.Critical = %d, want 1", ov.CVEAttention.Critical)
	}
}

// TestFetchPortalOverview_CVEAttentionReconcilesWithFindingsPage is the
// ticket's own acceptance criterion: the overview's CVE attention count must
// match a count derived the same way GET /v1/portal/findings would show it
// — deduplicated by CVE, confirmed match only, critical/high only. This
// seeds a mix of confirmed/unverified and critical/high/medium findings,
// some shared across devices, then independently derives the expected count
// from FetchPortalCVEFindingsPage's own output (the data layer
// /v1/portal/findings is built on) and asserts the overview's
// fetchPortalCVEAttention count is identical.
func TestFetchPortalOverview_CVEAttentionReconcilesWithFindingsPage(t *testing.T) {
	pool := pat1953Pool(t)
	ctx := context.Background()
	tenantID := pat1953SeedTenant(t, ctx, pool)

	dev1 := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-01")
	dev2 := pat1953SeedDevice(t, ctx, pool, tenantID, "dev-02")

	// Confirmed critical, shared across two devices — counts once.
	pat1953SeedCVE(t, ctx, pool, dev1, "CVE-2026-1953-R1", "critical", "version_confirmed")
	pat1953SeedCVE(t, ctx, pool, dev2, "CVE-2026-1953-R1", "critical", "version_confirmed")
	// Confirmed high, single device.
	pat1953SeedCVE(t, ctx, pool, dev1, "CVE-2026-1953-R2", "high", "version_vendor_confirmed")
	// Unverified critical — must not count in either place.
	pat1953SeedCVE(t, ctx, pool, dev1, "CVE-2026-1953-R3", "critical", "version_unverified")
	// Confirmed medium — must not count in either place.
	pat1953SeedCVE(t, ctx, pool, dev1, "CVE-2026-1953-R4", "medium", "version_confirmed")

	att, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCVEAttention: %v", err)
	}

	page, err := FetchPortalCVEFindingsPage(ctx, pool, tenantID, 1000, 0)
	if err != nil {
		t.Fatalf("FetchPortalCVEFindingsPage: %v", err)
	}

	// Derive the expected count the way the portal Findings page would show
	// it: confirmed match, critical/high severity, deduplicated by CVE ID
	// (FetchPortalCVEFindingsPage already returns one row per (cve, app,
	// version), which for this fixture is one row per CVE).
	wantCritical, wantHigh := 0, 0
	for _, f := range page.Findings {
		if f.MatchConfidence == "version_unverified" {
			continue
		}
		switch f.Severity {
		case "critical":
			wantCritical++
		case "high":
			wantHigh++
		}
	}

	if att.Critical != wantCritical {
		t.Errorf("overview Critical = %d, findings-page-derived Critical = %d, want equal", att.Critical, wantCritical)
	}
	if att.High != wantHigh {
		t.Errorf("overview High = %d, findings-page-derived High = %d, want equal", att.High, wantHigh)
	}
	if att.Critical != 1 || att.High != 1 {
		t.Fatalf("sanity: att = %+v, want Critical=1 (R1, deduped across 2 devices) High=1 (R2)", att)
	}
}
