package report

// PAT-1738: classifies device_certificates rows against
// platform_root_certificates. A row whose sha1 matches a known Microsoft/
// Apple platform-root thumbprint (for the device's own platform) is
// excluded from the actionable Certs list and surfaced in
// PlatformRootCerts instead; a row whose subject looks like a platform root
// by name but whose thumbprint does not match is surfaced in
// SuspiciousCerts; an ordinary certificate is untouched, in Certs as
// before this change.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as internal/report/admin_devices_db_test.go. The pool's
// search_path is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1738Schema = "pat1738_test"

func pat1738Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1738Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1738Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1738Schema,
		`CREATE TABLE ` + pat1738Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1738Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1738Schema + `.tenants(id),
			hostname  TEXT,
			os        TEXT NOT NULL
		)`,
		// Mirrors migrations/0012 + 0137: store column, no is_platform_root
		// column (computed live, never stored).
		`CREATE TABLE ` + pat1738Schema + `.device_certificates (
			id                              BIGSERIAL PRIMARY KEY,
			device_id                       UUID NOT NULL REFERENCES ` + pat1738Schema + `.devices(id) ON DELETE CASCADE,
			subject_cn                      TEXT NOT NULL,
			issuer_cn                       TEXT NOT NULL,
			sha1                            TEXT NOT NULL,
			not_after                       TIMESTAMPTZ NOT NULL,
			days_until_expiry_at_collection INTEGER NOT NULL,
			collected_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
			store                           TEXT NOT NULL DEFAULT 'My',
			UNIQUE (device_id, sha1)
		)`,
		// Mirrors migrations/0137.
		`CREATE TABLE ` + pat1738Schema + `.platform_root_certificates (
			thumbprint_sha1 TEXT NOT NULL,
			platform        TEXT NOT NULL CHECK (platform IN ('windows', 'macos')),
			source          TEXT NOT NULL,
			source_url      TEXT,
			fetched_at      TIMESTAMPTZ NOT NULL,
			subject_cn      TEXT,
			PRIMARY KEY (thumbprint_sha1, platform)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1738Schema+` CASCADE`)
	})
	return pool
}

// TestFetchCertExpiryReport_ClassifiesPlatformRootsAndSuspicious is the
// PAT-1738 acceptance test: one ordinary cert, one thumbprint-matched
// platform-root cert, and one suspicious (subject-named but unmatched) cert
// must end up in the report's three distinct buckets, and the KPI counts
// must reflect only the ordinary/actionable bucket.
func TestFetchCertExpiryReport_ClassifiesPlatformRootsAndSuspicious(t *testing.T) {
	pool := pat1738Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1738 Test Tenant') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var winDeviceID, macDeviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'win-01', 'Windows') RETURNING id::text
	`, tenantID).Scan(&winDeviceID); err != nil {
		t.Fatalf("insert windows device: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'mac-01', 'macOS') RETURNING id::text
	`, tenantID).Scan(&macDeviceID); err != nil {
		t.Fatalf("insert macos device: %v", err)
	}

	soon := time.Now().UTC().Add(20 * 24 * time.Hour)

	// 1. Ordinary certificate (Windows, LocalMachine\My) — must stay in Certs.
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_certificates (device_id, subject_cn, issuer_cn, sha1, not_after, days_until_expiry_at_collection, store)
		VALUES ($1::uuid, 'internal-vpn.example.com', 'Contoso Internal CA', 'aaaa111122223333444455556666777788889999', $2, 20, 'My')
	`, winDeviceID, soon); err != nil {
		t.Fatalf("insert ordinary cert: %v", err)
	}

	// 2. Rogue-thumbprint-shaped root cert whose SHA-1 IS in
	// platform_root_certificates for windows — must be classified
	// platform_root and excluded from Certs.
	rootThumb := "bbbb222233334444555566667777888899990000"
	if _, err := pool.Exec(ctx, `
		INSERT INTO platform_root_certificates (thumbprint_sha1, platform, source, source_url, fetched_at, subject_cn)
		VALUES ($1, 'windows', 'microsoft-ccadb', 'https://example.test/msft.csv', now(), 'Microsoft Root Certificate Authority')
	`, rootThumb); err != nil {
		t.Fatalf("insert platform root thumbprint: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_certificates (device_id, subject_cn, issuer_cn, sha1, not_after, days_until_expiry_at_collection, store)
		VALUES ($1::uuid, 'Microsoft Root Certificate Authority', 'Microsoft Root Certificate Authority', $2, $3, 20, 'Root')
	`, winDeviceID, rootThumb, soon); err != nil {
		t.Fatalf("insert platform root cert: %v", err)
	}

	// 3. Suspicious certificate: subject names "Microsoft" on a Windows
	// device, but its thumbprint is NOT in platform_root_certificates.
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_certificates (device_id, subject_cn, issuer_cn, sha1, not_after, days_until_expiry_at_collection, store)
		VALUES ($1::uuid, 'Microsoft Root Certificate Authority', 'Microsoft Root Certificate Authority', 'cccc333344445555666677778888999900001111', $2, 20, 'Root')
	`, winDeviceID, soon); err != nil {
		t.Fatalf("insert suspicious cert: %v", err)
	}

	// 4. Control: a macOS device certificate whose subject contains
	// "Microsoft" must NOT be flagged suspicious — the Windows patterns
	// only apply to Windows devices, macOS uses its own ("Apple") patterns.
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_certificates (device_id, subject_cn, issuer_cn, sha1, not_after, days_until_expiry_at_collection, store)
		VALUES ($1::uuid, 'Microsoft Teams Internal', 'Some Internal CA', 'dddd444455556666777788889999000011112222', $2, 20, 'System')
	`, macDeviceID, soon); err != nil {
		t.Fatalf("insert cross-platform-name cert: %v", err)
	}

	report, err := FetchCertExpiryReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchCertExpiryReport: %v", err)
	}

	if len(report.Certs) != 2 {
		t.Fatalf("len(Certs) = %d, want 2 (ordinary cert + macOS cross-name-but-not-suspicious cert); certs=%+v", len(report.Certs), report.Certs)
	}
	if len(report.PlatformRootCerts) != 1 {
		t.Fatalf("len(PlatformRootCerts) = %d, want 1; got %+v", len(report.PlatformRootCerts), report.PlatformRootCerts)
	}
	if report.PlatformRootCerts[0].SHA1 != rootThumb {
		t.Errorf("PlatformRootCerts[0].SHA1 = %q, want %q", report.PlatformRootCerts[0].SHA1, rootThumb)
	}
	if len(report.SuspiciousCerts) != 1 {
		t.Fatalf("len(SuspiciousCerts) = %d, want 1; got %+v", len(report.SuspiciousCerts), report.SuspiciousCerts)
	}
	if report.SuspiciousCerts[0].SHA1 != "cccc333344445555666677778888999900001111" {
		t.Errorf("SuspiciousCerts[0].SHA1 = %q, unexpected", report.SuspiciousCerts[0].SHA1)
	}

	// The KPI counts must only reflect the actionable (Certs) bucket — the
	// platform-root and suspicious certs must not inflate WarningCount.
	if report.WarningCount != 2 {
		t.Errorf("WarningCount = %d, want 2 (only the two Certs-bucket rows, both ~20 days out)", report.WarningCount)
	}
}

// TestFetchCertExpiryReport_OrdinaryCertsUnaffected is a regression control:
// a tenant with only ordinary (non-root, non-suspicious) certificates must
// see identical Certs/count behaviour to before PAT-1738.
func TestFetchCertExpiryReport_OrdinaryCertsUnaffected(t *testing.T) {
	pool := pat1738Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1738 Control Tenant') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'win-02', 'Windows') RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	expired := time.Now().UTC().Add(-2 * 24 * time.Hour)
	critical := time.Now().UTC().Add(3 * 24 * time.Hour)
	warning := time.Now().UTC().Add(15 * 24 * time.Hour)
	for i, na := range []time.Time{expired, critical, warning} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_certificates (device_id, subject_cn, issuer_cn, sha1, not_after, days_until_expiry_at_collection, store)
			VALUES ($1::uuid, $2, 'Some CA', $3, $4, 20, 'My')
		`, deviceID,
			[]string{"vpn-a.example.com", "vpn-b.example.com", "vpn-c.example.com"}[i],
			[]string{"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1", "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2", "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3"}[i],
			na,
		); err != nil {
			t.Fatalf("insert cert %d: %v", i, err)
		}
	}

	report, err := FetchCertExpiryReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchCertExpiryReport: %v", err)
	}
	if len(report.Certs) != 3 {
		t.Fatalf("len(Certs) = %d, want 3", len(report.Certs))
	}
	if len(report.PlatformRootCerts) != 0 || len(report.SuspiciousCerts) != 0 {
		t.Fatalf("expected no platform-root/suspicious certs, got %d/%d", len(report.PlatformRootCerts), len(report.SuspiciousCerts))
	}
	if report.ExpiredCount != 1 {
		t.Errorf("ExpiredCount = %d, want 1", report.ExpiredCount)
	}
	if report.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", report.CriticalCount)
	}
	if report.WarningCount != 1 {
		t.Errorf("WarningCount = %d, want 1", report.WarningCount)
	}
}
