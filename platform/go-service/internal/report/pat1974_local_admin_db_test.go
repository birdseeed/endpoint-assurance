package report

// PAT-1974: FetchLocalAdminReport must include the local_admin_accounts
// roster (account names), not just the local_admin_count scalar it already
// read. Before this change the report could only ever print a number.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as report_db_test.go (pat709Pool). The pool's search_path is
// pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1974Schema = "pat1974_local_admin_test"

func pat1974Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1974Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1974Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1974Schema,
		`CREATE TABLE ` + pat1974Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1974Schema + `.devices (
			id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id         UUID NOT NULL REFERENCES ` + pat1974Schema + `.tenants(id),
			hostname          TEXT,
			os                TEXT,
			collection_status JSONB
		)`,
		`CREATE TABLE ` + pat1974Schema + `.compliance_signals (
			id          BIGSERIAL PRIMARY KEY,
			device_id   UUID NOT NULL REFERENCES ` + pat1974Schema + `.devices(id),
			key         TEXT NOT NULL,
			value       TEXT,
			observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1974Schema + `.local_admin_accounts (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL REFERENCES ` + pat1974Schema + `.devices(id),
			name           TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			builtin        BOOLEAN NOT NULL,
			sid            TEXT,
			account_state  TEXT CHECK (account_state IN ('enabled', 'disabled', 'unknown')),
			collected_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	return pool
}

// TestFetchLocalAdminReportIncludesAccountNames: a device with a complete
// local_admin_accounts roster surfaces the names, not just the count.
func TestFetchLocalAdminReportIncludesAccountNames(t *testing.T) {
	pool := pat1974Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('pat1974-tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'WORKSTATION-1', 'Windows') RETURNING id::text`,
		tenantID,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, 'local_admin_count', '2')`,
		deviceID,
	); err != nil {
		t.Fatalf("insert compliance_signals: %v", err)
	}

	for _, a := range []struct {
		name          string
		principalType string
		builtin       bool
	}{
		{"WORKSTATION-1\\Administrator", "user", true},
		{"WORKSTATION-1\\alice", "user", false},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin) VALUES ($1::uuid, $2, $3, $4)`,
			deviceID, a.name, a.principalType, a.builtin,
		); err != nil {
			t.Fatalf("insert local_admin_accounts %q: %v", a.name, err)
		}
	}

	report, err := FetchLocalAdminReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchLocalAdminReport: %v", err)
	}
	if len(report.Devices) != 1 {
		t.Fatalf("Devices: got %d, want 1", len(report.Devices))
	}
	dev := report.Devices[0]
	if dev.AdminCount != 2 {
		t.Errorf("AdminCount: got %d, want 2", dev.AdminCount)
	}
	wantNames := []string{"WORKSTATION-1\\Administrator", "WORKSTATION-1\\alice"}
	if len(dev.AdminNames) != len(wantNames) {
		t.Fatalf("AdminNames: got %v, want %v", dev.AdminNames, wantNames)
	}
	for i, want := range wantNames {
		if dev.AdminNames[i] != want {
			t.Errorf("AdminNames[%d]: got %q, want %q", i, dev.AdminNames[i], want)
		}
	}
}

// TestFetchLocalAdminReportNoRosterYetIsNotEmptyAdmins: a device with a real
// local_admin_count but no local_admin_accounts rows yet (an older agent
// that predates PAT-1974, or a collection that hasn't completed) must report
// an empty AdminNames slice, never something that reads as "this device
// genuinely has zero admins" — that claim belongs to AdminCount alone.
func TestFetchLocalAdminReportNoRosterYetIsNotEmptyAdmins(t *testing.T) {
	pool := pat1974Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('pat1974-tenant-noroster') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'OLD-AGENT', 'macOS') RETURNING id::text`,
		tenantID,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, 'local_admin_count', '1')`,
		deviceID,
	); err != nil {
		t.Fatalf("insert compliance_signals: %v", err)
	}

	report, err := FetchLocalAdminReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchLocalAdminReport: %v", err)
	}
	if len(report.Devices) != 1 {
		t.Fatalf("Devices: got %d, want 1", len(report.Devices))
	}
	dev := report.Devices[0]
	if dev.AdminCount != 1 {
		t.Errorf("AdminCount: got %d, want 1", dev.AdminCount)
	}
	if len(dev.AdminNames) != 0 {
		t.Errorf("AdminNames: got %v, want empty (no roster ingested yet)", dev.AdminNames)
	}
}

// TestFetchLocalAdminReportAccountsPrincipalTypesAndCollectionStatus (PAT-2215):
// /v1/portal/local-admins needs DeviceID (to link to that device's own
// Compliance tab), the roster's own collection_status (to tell "membership
// unreadable" apart from a real zero), and each principal's own type/sid/
// account_state (to label a directory group as a group and an unresolved
// SID as unresolved, never guessed at from the name string alone).
func TestFetchLocalAdminReportAccountsPrincipalTypesAndCollectionStatus(t *testing.T) {
	pool := pat1974Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('pat2215-tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname, os, collection_status)
		 VALUES ($1::uuid, 'DC-1', 'Windows', '{"local_admins": "complete"}'::jsonb)
		 RETURNING id::text`,
		tenantID,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, 'local_admin_count', '3')`,
		deviceID,
	); err != nil {
		t.Fatalf("insert compliance_signals: %v", err)
	}

	type seed struct {
		name          string
		principalType string
		builtin       bool
		sid           *string
		accountState  *string
	}
	sidGroup := "S-1-5-21-1-2-3-512"
	sidUnresolved := "S-1-5-21-1-2-3-9999"
	sidBuiltin := "S-1-5-21-1-2-3-500"
	disabled := "disabled"
	for _, a := range []seed{
		{"CONTOSO\\Domain Admins", "group", false, &sidGroup, nil},
		{sidUnresolved, "unresolved", false, &sidUnresolved, nil},
		{"DC-1\\Administrator", "user", true, &sidBuiltin, &disabled},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin, sid, account_state)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			deviceID, a.name, a.principalType, a.builtin, a.sid, a.accountState,
		); err != nil {
			t.Fatalf("insert local_admin_accounts %q: %v", a.name, err)
		}
	}

	rep, err := FetchLocalAdminReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchLocalAdminReport: %v", err)
	}
	if len(rep.Devices) != 1 {
		t.Fatalf("Devices: got %d, want 1", len(rep.Devices))
	}
	dev := rep.Devices[0]

	if dev.DeviceID != deviceID {
		t.Errorf("DeviceID: got %q, want %q", dev.DeviceID, deviceID)
	}
	if dev.LocalAdminsCollectionStatus != "complete" {
		t.Errorf("LocalAdminsCollectionStatus: got %q, want %q", dev.LocalAdminsCollectionStatus, "complete")
	}
	// The built-in Administrator is disabled, so it is excluded from the
	// assessed count (PAT-1992): reported 3, assessed 2.
	if dev.ReportedAdminCount != 3 {
		t.Errorf("ReportedAdminCount: got %d, want 3", dev.ReportedAdminCount)
	}
	if dev.AdminCount != 2 {
		t.Errorf("AdminCount (assessed): got %d, want 2", dev.AdminCount)
	}
	if dev.Risk != "compliant" {
		t.Errorf("Risk: got %q, want %q (assessed count <= 2, builtin disabled)", dev.Risk, "compliant")
	}

	if len(dev.AdminAccounts) != 3 {
		t.Fatalf("AdminAccounts: got %d entries, want 3: %+v", len(dev.AdminAccounts), dev.AdminAccounts)
	}
	byName := map[string]LocalAdminAccount{}
	for _, a := range dev.AdminAccounts {
		byName[a.Name] = a
	}

	group, ok := byName["CONTOSO\\Domain Admins"]
	if !ok {
		t.Fatalf("missing group account in %+v", dev.AdminAccounts)
	}
	if group.PrincipalType != "group" {
		t.Errorf("group PrincipalType: got %q, want %q", group.PrincipalType, "group")
	}
	if group.Builtin {
		t.Errorf("group Builtin: got true, want false")
	}
	if group.Sid == nil || *group.Sid != sidGroup {
		t.Errorf("group Sid: got %v, want %q", group.Sid, sidGroup)
	}

	unresolved, ok := byName[sidUnresolved]
	if !ok {
		t.Fatalf("missing unresolved account in %+v", dev.AdminAccounts)
	}
	if unresolved.PrincipalType != "unresolved" {
		t.Errorf("unresolved PrincipalType: got %q, want %q", unresolved.PrincipalType, "unresolved")
	}

	builtin, ok := byName["DC-1\\Administrator"]
	if !ok {
		t.Fatalf("missing builtin account in %+v", dev.AdminAccounts)
	}
	if !builtin.Builtin {
		t.Errorf("builtin Builtin: got false, want true")
	}
	if builtin.AccountState == nil || *builtin.AccountState != "disabled" {
		t.Errorf("builtin AccountState: got %v, want %q", builtin.AccountState, "disabled")
	}

	// AdminNames must stay in exact step with AdminAccounts (same order,
	// same membership) since the PDF renderer still reads AdminNames alone.
	if len(dev.AdminNames) != len(dev.AdminAccounts) {
		t.Fatalf("AdminNames/AdminAccounts length mismatch: %d vs %d", len(dev.AdminNames), len(dev.AdminAccounts))
	}
	for i, acc := range dev.AdminAccounts {
		if dev.AdminNames[i] != acc.Name {
			t.Errorf("AdminNames[%d]=%q does not match AdminAccounts[%d].Name=%q", i, dev.AdminNames[i], i, acc.Name)
		}
	}
}

// TestFetchLocalAdminReportUnreadableCollectionStatus (PAT-2215): a device
// whose local_admins collection failed outright (or has never reported)
// must surface that as its own distinct collection-status value, never
// silently folded into "zero admins" or "unknown count".
func TestFetchLocalAdminReportUnreadableCollectionStatus(t *testing.T) {
	pool := pat1974Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('pat2215-unreadable-tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var failedDeviceID, neverReportedDeviceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname, os, collection_status)
		 VALUES ($1::uuid, 'FAILED-READ', 'Windows', '{"local_admins": "unavailable"}'::jsonb)
		 RETURNING id::text`,
		tenantID,
	).Scan(&failedDeviceID); err != nil {
		t.Fatalf("insert failed-read device: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'NEVER-REPORTED', 'macOS') RETURNING id::text`,
		tenantID,
	).Scan(&neverReportedDeviceID); err != nil {
		t.Fatalf("insert never-reported device: %v", err)
	}

	rep, err := FetchLocalAdminReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchLocalAdminReport: %v", err)
	}
	if len(rep.Devices) != 2 {
		t.Fatalf("Devices: got %d, want 2", len(rep.Devices))
	}
	byID := map[string]LocalAdminDevice{}
	for _, d := range rep.Devices {
		byID[d.DeviceID] = d
	}
	if got := byID[failedDeviceID].LocalAdminsCollectionStatus; got != "unavailable" {
		t.Errorf("failed-read device LocalAdminsCollectionStatus: got %q, want %q", got, "unavailable")
	}
	if got := byID[neverReportedDeviceID].LocalAdminsCollectionStatus; got != "" {
		t.Errorf("never-reported device LocalAdminsCollectionStatus: got %q, want empty", got)
	}
}
