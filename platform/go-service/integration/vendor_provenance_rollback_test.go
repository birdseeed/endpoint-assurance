//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVendorProvenanceRollbackRefusesLiveVendorData(t *testing.T) {
	ctx := context.Background()
	rollbackSQL, err := os.ReadFile(filepath.Join("..", "migrations", "0151_vendor_advisory_titles_rollback.sql"))
	if err != nil {
		t.Fatalf("read 0151 rollback: %v", err)
	}

	for _, tc := range []struct {
		name   string
		cveID  string
		source string
	}{
		{name: "MSRC-sourced description", cveID: "CVE-2099-18531", source: "msrc"},
		{name: "Apple-sourced description", cveID: "CVE-2099-18532", source: "apple"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := env.pool.Exec(ctx, `
				INSERT INTO cve_feed_entries (cve_id, description, description_source)
				VALUES ($1, 'Vendor advisory title', $2)`, tc.cveID, tc.source); err != nil {
				t.Fatalf("seed vendor-sourced description: %v", err)
			}
			t.Cleanup(func() {
				if _, err := env.pool.Exec(ctx, `DELETE FROM cve_feed_entries WHERE cve_id = $1`, tc.cveID); err != nil {
					t.Errorf("remove vendor-sourced description: %v", err)
				}
			})

			assertRollbackRefused(t, ctx, string(rollbackSQL))
		})
	}

	t.Run("nonblank vendor title", func(t *testing.T) {
		const cveID = "CVE-2099-18533"
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO os_cve_advisories (os_platform, os_version, os_build, cve_id, source, vendor_title)
			VALUES ('windows', '10.0', '19045', $1, 'msrc', 'Microsoft vendor advisory title')`, cveID); err != nil {
			t.Fatalf("seed vendor title: %v", err)
		}
		t.Cleanup(func() {
			if _, err := env.pool.Exec(ctx, `DELETE FROM os_cve_advisories WHERE cve_id = $1 AND source = 'msrc'`, cveID); err != nil {
				t.Errorf("remove vendor title: %v", err)
			}
		})

		assertRollbackRefused(t, ctx, string(rollbackSQL))
	})
}

func assertRollbackRefused(t *testing.T, ctx context.Context, rollbackSQL string) {
	t.Helper()
	_, err := env.pool.Exec(ctx, rollbackSQL)
	if err == nil {
		t.Fatal("rollback succeeded despite live vendor provenance")
	}
	if !strings.Contains(err.Error(), "export cve_feed_entries rows") {
		t.Fatalf("rollback error does not give remediation instruction: %v", err)
	}
}
