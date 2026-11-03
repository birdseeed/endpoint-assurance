package report

import (
	"context"
	"testing"
	"time"
)

// Uses the real migrated scratch database, like the migrated EDR report tests.
// Bootstrap with go test -tags integration ./integration -run '^$' first.
func TestPortalSoftwareLegacyUsageDoesNotRenewFromDeviceHeartbeat(t *testing.T) {
	pool := pat2226MigratedConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenant := pat2226MigratedSeedTenant(t, ctx, pool, "PAT2361 legacy freshness")
	other := pat2226MigratedSeedTenant(t, ctx, pool, "PAT2361 other tenant")
	asOf := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	fresh := asOf.Add(-time.Hour)
	stale := asOf.Add(-31 * 24 * time.Hour)
	oldUse := asOf.Add(-120 * 24 * time.Hour)

	cases := []struct {
		name, status, class, evidence string
		appSeen, deviceSeen           time.Time
		receipt                       *time.Time
		complete                      *bool
		lastUse                       *time.Time
		wantState                     string
		wantUnused, wantStale         int
	}{
		{name: "legacy stale app", status: "ok", class: "workstation", appSeen: stale, deviceSeen: stale, lastUse: &oldUse, wantState: "stale", wantStale: 1},
		{name: "legacy fresh app", status: "ok", class: "workstation", appSeen: fresh, deviceSeen: fresh, lastUse: &oldUse, wantState: "unused", wantUnused: 1},
		{name: "legacy missing use", status: "ok", class: "workstation", appSeen: fresh, deviceSeen: fresh, wantState: "unmetered"},
		{name: "legacy server", status: "ok", class: "server", appSeen: fresh, deviceSeen: fresh, lastUse: &oldUse, wantState: "unmetered"},
		{name: "legacy unmetered", status: "userassist_unavailable", class: "workstation", appSeen: fresh, deviceSeen: fresh, lastUse: &oldUse, wantState: "unmetered"},
		{name: "new recorded complete", status: "ok", class: "workstation", evidence: "recorded", appSeen: fresh, deviceSeen: fresh, receipt: &fresh, complete: boolPtr(true), lastUse: &oldUse, wantState: "unused", wantUnused: 1},
		{name: "new recorded partial", status: "ok", class: "workstation", evidence: "recorded", appSeen: fresh, deviceSeen: fresh, receipt: &fresh, complete: boolPtr(false), lastUse: &oldUse, wantState: "unmetered"},
		{name: "new not reported", status: "ok", class: "workstation", appSeen: fresh, deviceSeen: fresh, receipt: &fresh, complete: boolPtr(false), lastUse: &oldUse, wantState: "unmetered"},
		{name: "new no record", status: "ok", class: "workstation", evidence: "no_record", appSeen: fresh, deviceSeen: fresh, receipt: &fresh, complete: boolPtr(true), lastUse: &oldUse, wantState: "unmetered"},
		{name: "new unavailable", status: "ok", class: "workstation", evidence: "unavailable", appSeen: fresh, deviceSeen: fresh, receipt: &fresh, complete: boolPtr(true), lastUse: &oldUse, wantState: "unmetered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var device string
			if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id,hostname,os,metering_status,device_class,last_seen)
				VALUES ($1::uuid,$2,'Windows',$3,$4,$5) RETURNING id::text`, tenant, tc.name, tc.status, tc.class, tc.deviceSeen).Scan(&device); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO device_apps (device_id,name,identifier,version,last_seen,last_used_at,usage_evidence,usage_evidence_at,usage_evidence_complete)
				VALUES ($1::uuid,$2,$2,'1.0',$3,$4,NULLIF($5,''),$6,$7)`, device, tc.name, tc.appSeen, tc.lastUse, tc.evidence, tc.receipt, tc.complete); err != nil {
				t.Fatal(err)
			}
			assert := func() {
				t.Helper()
				page, err := fetchPortalSoftwareAt(ctx, pool, tenant, device, "", 100, 0, asOf)
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Products) != 1 {
					t.Fatalf("products = %d, want 1", len(page.Products))
				}
				got := page.Products[0]
				if got.UnusedInstallationCount != tc.wantUnused || got.RemovalCandidate != (tc.wantUnused == 1) || got.UsageState != tc.wantState || got.StaleInstallationCount != tc.wantStale {
					t.Errorf("unused=%d removal_candidate=%t state=%q stale=%d; want unused=%d candidate=%t state=%q stale=%d", got.UnusedInstallationCount, got.RemovalCandidate, got.UsageState, got.StaleInstallationCount, tc.wantUnused, tc.wantUnused == 1, tc.wantState, tc.wantStale)
				}
				if page.Coverage.UnusedCount != tc.wantUnused || page.Coverage.StaleCount != tc.wantStale || page.Coverage.InstallationCount != 1 {
					t.Errorf("coverage = %+v; want unused=%d stale=%d installations=1", page.Coverage, tc.wantUnused, tc.wantStale)
				}
				if !got.EvidenceAt.Equal(tc.appSeen) {
					t.Errorf("app evidence timestamp = %v, want retained %v", got.EvidenceAt, tc.appSeen)
				}
				if tc.evidence == "" || tc.evidence == "recorded" {
					if (got.LastUsedAt == nil) != (tc.lastUse == nil) || (got.LastUsedAt != nil && !got.LastUsedAt.Equal(*tc.lastUse)) {
						t.Errorf("last use = %v, want retained %v", got.LastUsedAt, tc.lastUse)
					}
				} else if got.LastUsedAt != nil {
					t.Errorf("current %q evidence promoted historical use: %v", tc.evidence, got.LastUsedAt)
				}
			}
			assert()
			if tc.name == "legacy stale app" {
				// Only the device heartbeat changes. No app usage was collected.
				t.Log("stale device + stale legacy app passed; refreshing only devices.last_seen")
				if _, err := pool.Exec(ctx, `UPDATE devices SET last_seen=$2 WHERE id=$1::uuid`, device, fresh); err != nil {
					t.Fatal(err)
				}
				assert()
			}
			hidden, err := fetchPortalSoftwareAt(ctx, pool, other, device, "", 100, 0, asOf)
			if err != nil || hidden.Total != 0 || hidden.Coverage.InstallationCount != 0 {
				t.Fatalf("cross-tenant page = %+v, error = %v; want no installations", hidden, err)
			}
			var retained *time.Time
			if err := pool.QueryRow(ctx, `SELECT last_used_at FROM device_apps WHERE device_id=$1::uuid`, device).Scan(&retained); err != nil {
				t.Fatal(err)
			}
			if (retained == nil) != (tc.lastUse == nil) || (retained != nil && !retained.Equal(*tc.lastUse)) {
				t.Errorf("stored historical use = %v, want %v", retained, tc.lastUse)
			}
		})
	}
}
