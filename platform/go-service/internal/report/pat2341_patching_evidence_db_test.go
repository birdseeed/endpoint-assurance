package report

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Separate scratch schema: no migrated public tables or production data are changed.
func pat2341Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "pat2341_test,public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, sql := range []string{
		`DROP SCHEMA IF EXISTS pat2341_test CASCADE`,
		`CREATE SCHEMA pat2341_test`,
		`CREATE TABLE tenants (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, macos_enabled boolean NOT NULL, windows_enabled boolean NOT NULL)`,
		`CREATE TABLE devices (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), hostname text, os text, last_seen timestamptz, pending_updates jsonb)`,
		`CREATE TABLE device_os_update (device_id uuid PRIMARY KEY REFERENCES devices(id), state text NOT NULL, checked_at timestamptz, reported_at timestamptz NOT NULL, security_relevant boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE patches (device_id uuid, installed_at timestamptz)`,
		`CREATE TABLE compliance_rules (id uuid PRIMARY KEY, rule_key text)`,
		`CREATE TABLE compliance_evaluations (device_id uuid, rule_id uuid, status text, observed_value text, evaluated_at timestamptz)`,
	} {
		if _, err := pool.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA pat2341_test CASCADE`) })
	return pool
}

func TestPAT2341PatchingEvidenceReconcilesRosterAndCard(t *testing.T) {
	pool := pat2341Pool(t)
	ctx := context.Background()
	now := time.Now().UTC()
	var tenant, other string
	for _, id := range []*string{&tenant, &other} {
		if err := pool.QueryRow(ctx, `INSERT INTO tenants (name,macos_enabled,windows_enabled) VALUES ('PAT2341',true,true) RETURNING id::text`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	// Expectations are independent of the production classifier. Explicit rows
	// always win; min(checked,receipt) controls freshness, including future clocks.
	cases := []struct {
		name, state, legacy, bucket string
		checkedAge, receiptAge      time.Duration
		noRow, nullChecked          bool
	}{
		{"unknown", "unknown", "[]", "unknown", time.Hour, time.Hour, false, false},
		{"unavailable", "unavailable", "[]", "unknown", time.Hour, time.Hour, false, false},
		{"unrecognised", "banana", "[]", "unknown", time.Hour, time.Hour, false, false},
		{"case", "Up_To_Date", "[]", "unknown", time.Hour, time.Hour, false, false},
		{"recommended", "update_recommended", "[]", "pending", time.Hour, time.Hour, false, false},
		{"required", "update_required", "[]", "pending", time.Hour, time.Hour, false, false},
		{"deadline", "deadline_passed", "[]", "pending", time.Hour, time.Hour, false, false},
		{"unsupported", "unsupported_hardware", "[]", "pending", time.Hour, time.Hour, false, false},
		{"healthy-conflict", "up_to_date", `[{"name":"legacy"}]`, "current", time.Hour, time.Hour, false, false},
		{"stale-current", "up_to_date", "[]", "unknown", 8 * 24 * time.Hour, time.Hour, false, false},
		{"stale-pending", "update_required", "[]", "unknown", time.Hour, 8 * 24 * time.Hour, false, false},
		{"future-clock-old-receipt", "up_to_date", "[]", "unknown", -30 * 24 * time.Hour, 8 * 24 * time.Hour, false, false},
		{"future-clock-fresh-receipt", "update_required", "[]", "pending", -30 * 24 * time.Hour, time.Hour, false, false},
		{"null-checked-fresh", "up_to_date", "[]", "current", 0, time.Hour, false, true},
		{"null-checked-stale", "up_to_date", "[]", "unknown", 0, 8 * 24 * time.Hour, false, true},
		{"legacy-clean", "", "[]", "current", 0, 0, true, false},
		{"legacy-pending", "", `[{"name":"legacy"}]`, "pending", 0, 0, true, false},
		{"legacy-absent", "", "", "unknown", 0, 0, true, false},
	}
	var ids []string
	wantByID := map[string]string{}
	osByID := map[string]string{}
	for _, platform := range []string{"Windows", "macOS"} {
		for _, c := range cases {
			var id string
			var legacy any
			if c.legacy != "" {
				legacy = c.legacy
			}
			if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id,hostname,os,last_seen,pending_updates) VALUES ($1,$2,$3,$4,$5::jsonb) RETURNING id::text`, tenant, platform+"-"+c.name, platform, now, legacy).Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
			wantByID[id], osByID[id] = c.bucket, platform
			if !c.noRow {
				var checked any = now.Add(-c.checkedAge)
				if c.nullChecked {
					checked = nil
				}
				if _, err := pool.Exec(ctx, `INSERT INTO device_os_update (device_id,state,checked_at,reported_at) VALUES ($1,$2,$3,$4)`, id, c.state, checked, now.Add(-c.receiptAge)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Exec(ctx, `INSERT INTO patches (device_id,installed_at) VALUES ($1,$2)`, id, now.Add(-3*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var foreignID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id,hostname,os,last_seen,pending_updates) VALUES ($1,'other-tenant','Windows',$2,'[]') RETURNING id::text`, other, now).Scan(&foreignID); err != nil {
		t.Fatal(err)
	}
	flags, err := fetchPortalDeviceFlags(ctx, pool, tenant, append(ids, foreignID), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := flags[foreignID]; present {
		t.Error("roster leaked other tenant")
	}
	for _, id := range ids {
		got := "unknown"
		if p := flags[id].patchPending; p != nil {
			if *p {
				got = "pending"
			} else {
				got = "current"
			}
		}
		if got != wantByID[id] {
			t.Errorf("roster %s = %s, want %s", id, got, wantByID[id])
		}
	}
	for _, sw := range []platformSwitches{{true, true}, {true, false}, {false, true}, {false, false}} {
		t.Run(map[bool]string{true: "mac", false: "no-mac"}[sw.macOSEnabled]+"/"+map[bool]string{true: "win", false: "no-win"}[sw.windowsEnabled], func(t *testing.T) {
			want := map[string]int{}
			for _, id := range ids {
				if (osByID[id] == "macOS" && sw.macOSEnabled) || (osByID[id] == "Windows" && sw.windowsEnabled) {
					want[wantByID[id]]++
				}
			}
			if _, err := pool.Exec(ctx, `UPDATE tenants SET macos_enabled=$2,windows_enabled=$3 WHERE id=$1`, tenant, sw.macOSEnabled, sw.windowsEnabled); err != nil {
				t.Fatal(err)
			}
			rollup, err := FetchOSUpdateStatus(ctx, pool, tenant)
			if err != nil {
				t.Fatal(err)
			}
			platforms := 0
			if sw.macOSEnabled {
				platforms++
			}
			if sw.windowsEnabled {
				platforms++
			}
			// The dedicated OS rollup intentionally has no legacy fallback:
			// two current, five pending and eleven unavailable per platform.
			if rollup.DevicesCurrent != 2*platforms || rollup.DevicesBehind != 5*platforms || rollup.DevicesNotReported != 11*platforms {
				t.Errorf("OS rollup does not match explicit roster evidence: %+v", rollup)
			}
			var ps PatchingStats
			if err := fetchPatchingStats(ctx, pool, tenant, sw, &ps); err != nil {
				t.Fatal(err)
			}
			if ps.DevicesUpToDate != want["current"] || ps.DevicesPendingUpdates != want["pending"] || ps.DevicesUpdateStateUnknown != want["unknown"] {
				t.Errorf("executive counts = %d/%d/%d, want current/pending/unknown %d/%d/%d", ps.DevicesUpToDate, ps.DevicesPendingUpdates, ps.DevicesUpdateStateUnknown, want["current"], want["pending"], want["unknown"])
			}
			median := 3
			if !sw.macOSEnabled && !sw.windowsEnabled {
				median = -1
			}
			if ps.MedianDaysSinceLastPatch != median {
				t.Errorf("median = %d, want %d", ps.MedianDaysSinceLastPatch, median)
			}
			card := osUpdatesCard(ctx, pool, tenant, sw, now, overviewDeviceBuckets{newest: &now})
			if want["current"]+want["pending"] == 0 {
				if card.State != CardStateUnavailable {
					t.Errorf("empty card state = %s", card.State)
				}
				return
			}
			if card.State != CardStatePartial || card.Completeness.Complete || card.Completeness.Reason == nil || *card.Completeness.Reason != CardReasonVersionEvidence {
				t.Errorf("card must remain partial without version-level evidence: %+v", card)
			}
			values, ok := card.Values.(OSUpdatesCardValues)
			if !ok || values != (OSUpdatesCardValues{UpToDate: want["current"], Pending: want["pending"], Unknown: want["unknown"]}) {
				t.Errorf("card values = %+v, want %v", card.Values, want)
			}
			if !strings.Contains(card.Source, "device_os_update") || !strings.Contains(card.Source, "devices.pending_updates") {
				t.Errorf("card source = %q, must name explicit and legacy evidence", card.Source)
			}
		})
	}
}
