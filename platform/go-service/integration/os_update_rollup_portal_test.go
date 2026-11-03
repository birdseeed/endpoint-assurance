//go:build integration

package integration

// PAT-2295: the staff and admin OS-update rollup (report.FetchOSUpdateStatus)
// used to count every device_os_update.state other than up_to_date as behind,
// including "unknown" and any value outside the updater schema's vocabulary.
// The customer portal roster (PAT-2294) reads the same rows and reports those
// as null ("not reported"), so the two views disagreed about the same device.
//
// This test seeds one tenant with every kind of stored verdict and asserts
// that the rollup and the roster now tell the same story: the rollup's behind
// count equals the number of devices the roster marks patch_pending = true,
// its current count equals the false ones, and its not-reported count equals
// the null ones.
//
// PAT-2338 also covers legacy array conflicts, cached verdicts and receipt-clock
// bounds. Explicit OS evidence has identical freshness semantics in both readers.

import (
	"context"
	"testing"
	"time"

	"patched.im/api/internal/report"
)

type rollupSeed struct {
	hostname       string
	os             string
	hasRow         bool
	state          string
	secRel         bool
	age            time.Duration
	receiptAge     time.Duration
	pendingUpdates string
	wantBucket     string // "current", "behind" or "not_reported"
}

func rollupSeeds() []rollupSeed {
	return []rollupSeed{
		{"rl-current-win", "Windows", true, "up_to_date", false, time.Hour, time.Hour, "NULL", "current"},
		{"rl-recommended-mac", "macOS", true, "update_recommended", false, time.Hour, time.Hour, "NULL", "behind"},
		{"rl-required-win", "Windows", true, "update_required", true, time.Hour, time.Hour, "NULL", "behind"},
		{"rl-deadline-win", "Windows", true, "deadline_passed", true, time.Hour, time.Hour, "NULL", "behind"},
		{"rl-unsupported-win", "Windows", true, "unsupported_hardware", false, time.Hour, time.Hour, "NULL", "behind"},
		// The agent said it could not tell. security_relevant is true on
		// purpose: an unknown verdict must not leak into the behind-security
		// subset either.
		{"rl-unknown-win", "Windows", true, "unknown", true, time.Hour, time.Hour, "NULL", "not_reported"},
		// A state this server does not recognise, as a later agent release
		// might send. Also security_relevant, for the same reason.
		{"rl-banana-mac", "macOS", true, "banana", true, time.Hour, time.Hour, "NULL", "not_reported"},
		{"rl-empty-unknown-mac", "macOS", true, "unknown", true, time.Hour, time.Hour, "'[]'::jsonb", "not_reported"},
		{"rl-empty-pending-mac", "macOS", true, "update_required", true, time.Hour, time.Hour, "'[]'::jsonb", "behind"},
		{"rl-list-current-mac", "macOS", true, "up_to_date", false, time.Hour, time.Hour, `'[{"name":"Safari"}]'::jsonb`, "current"},
		{"rl-stale-current-mac", "macOS", true, "up_to_date", false, 8 * 24 * time.Hour, time.Hour, "'[]'::jsonb", "not_reported"},
		{"rl-stale-pending-win", "Windows", true, "update_required", true, 8 * 24 * time.Hour, time.Hour, "NULL", "not_reported"},
		{"rl-clock-ahead-win", "Windows", true, "up_to_date", false, -30 * 24 * time.Hour, 8 * 24 * time.Hour, "'[]'::jsonb", "not_reported"},
		{"rl-unavailable-mac", "macOS", true, "unavailable", true, time.Hour, time.Hour, "'[]'::jsonb", "not_reported"},
		{"rl-no-row-win", "Windows", false, "", false, time.Hour, time.Hour, "NULL", "not_reported"},
	}
}

func TestOSUpdateRollupAgreesWithPortalRoster(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2295-rollup")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	now := time.Now().UTC()
	seeds := rollupSeeds()
	wantBucketOf := map[string]string{}
	for _, s := range seeds {
		var deviceID string
		if err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen, pending_updates)
			VALUES ($1::uuid, $2, gen_random_uuid(), $2, $3, '15.5', '24F74', 'arm64', $4, `+s.pendingUpdates+`)
			RETURNING id::text
		`, tenantID, s.hostname, s.os, now.Add(-time.Minute)).Scan(&deviceID); err != nil {
			t.Fatalf("seed device %s: %v", s.hostname, err)
		}
		wantBucketOf[s.hostname] = s.wantBucket
		if !s.hasRow {
			continue
		}
		checked := now.Add(-s.age)
		fresh := now.Add(-s.receiptAge)
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO device_os_update
				(device_id, installed_os, latest_os, state, severity, security_relevant, checked_at, reported_at)
			VALUES ($1::uuid, '10.0.26100', '10.0.26200', $2, 'medium', $3, $4, $5)
		`, deviceID, s.state, s.secRel, checked, fresh); err != nil {
			t.Fatalf("seed device_os_update %s: %v", s.hostname, err)
		}
	}

	status, err := report.FetchOSUpdateStatus(ctx, env.pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}

	// Expectations come from the seed table, not from the code under test.
	var wantCurrent, wantBehind, wantBehindSecurity, wantNotReported int
	for _, s := range seeds {
		switch s.wantBucket {
		case "current":
			wantCurrent++
		case "behind":
			wantBehind++
			if s.secRel {
				wantBehindSecurity++
			}
		case "not_reported":
			wantNotReported++
		}
	}
	if status.DevicesCurrent != wantCurrent {
		t.Errorf("DevicesCurrent = %d, want %d", status.DevicesCurrent, wantCurrent)
	}
	if status.DevicesBehind != wantBehind {
		t.Errorf("DevicesBehind = %d, want %d (only the recognised pending states; unknown and unrecognised are not behind)", status.DevicesBehind, wantBehind)
	}
	if status.DevicesBehindSecurityRelevant != wantBehindSecurity {
		t.Errorf("DevicesBehindSecurityRelevant = %d, want %d (an unknown or unrecognised verdict never counts here even when security_relevant is set)", status.DevicesBehindSecurityRelevant, wantBehindSecurity)
	}
	if status.DevicesNotReported != wantNotReported {
		t.Errorf("DevicesNotReported = %d, want %d (no row, unknown and unrecognised)", status.DevicesNotReported, wantNotReported)
	}

	roster, err := report.FetchPortalDevices(ctx, env.pool, tenantID, 500, 0)
	if err != nil {
		t.Fatalf("FetchPortalDevices: %v", err)
	}
	if len(roster.Devices) != len(seeds) {
		t.Fatalf("roster has %d devices, want %d", len(roster.Devices), len(seeds))
	}
	var rosterPending, rosterCurrent, rosterNull int
	for _, d := range roster.Devices {
		var got string
		switch {
		case d.PatchPending == nil:
			rosterNull++
			got = "not_reported"
		case *d.PatchPending:
			rosterPending++
			got = "behind"
		default:
			rosterCurrent++
			got = "current"
		}
		if want := wantBucketOf[d.Hostname]; got != want {
			t.Errorf("roster %s patch_pending reads as %q, want %q", d.Hostname, got, want)
		}
	}
	if status.DevicesBehind != rosterPending {
		t.Errorf("rollup DevicesBehind = %d but the roster marks %d devices patch_pending = true", status.DevicesBehind, rosterPending)
	}
	if status.DevicesCurrent != rosterCurrent {
		t.Errorf("rollup DevicesCurrent = %d but the roster marks %d devices patch_pending = false", status.DevicesCurrent, rosterCurrent)
	}
	if status.DevicesNotReported != rosterNull {
		t.Errorf("rollup DevicesNotReported = %d but the roster leaves %d devices patch_pending null", status.DevicesNotReported, rosterNull)
	}
}
