package report

// PAT-1762 regression, extending PAT-1758's executive-report fix to the
// per-device roster and the customer portal: an evaluation that failed
// because the collector could not read the signal (an absent key, or the
// literal "Unknown" sentinel routed through treat_unknown_as, leaving
// observed_value NULL) must not be counted the same way as a real
// observation of non-compliance in:
//
//   - FetchTenantDevices (admin.go) — customer-facing via portal.go's
//     FetchPortalDevices, which embeds TenantDeviceRow into the roster
//     GET /v1/portal/devices reads for cis_score/findings_open.
//   - FetchPortalDevices' own encryption_ok flag (portal.go) — must read
//     "unknown", never "not encrypted", off an undetermined latest
//     evaluation of a disk-encryption rule.
//
// A "NotConfigured" fail (PAT-1767: the read succeeded, the setting is
// genuinely absent) has a non-NULL observed_value and must still be counted
// as a real, evidenced fail throughout.
//
// Report.Summary's own split (the per-device compliance PDF) is covered by
// the plain Go unit tests in report_test.go — it needs no DB, since EvalRow
// already carries ObservedValue from Fetch's existing SELECT.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as pat1758Pool (pat1758_unknown_evidence_db_test.go) and
// pat745Pool (admin_devices_db_test.go). The pool's search_path is pinned to
// an isolated schema so no real data is touched.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1762Schema = "pat1762_test"

func pat1762Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1762Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1762Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1762Schema,
		// Columns FetchTenantDevices/FetchPortalDevices touch — same set as
		// pat745Pool (admin_devices_db_test.go) plus observed_value, which
		// pat745Pool predates (PAT-1758 added the column to the real schema
		// after that test file was written).
		`CREATE TABLE ` + pat1762Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1762Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1762Schema + `.tenants(id),
			serial               TEXT,
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			primary_user_display TEXT,
			pending_updates      JSONB,
			backup_status        JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown',
			os_caption           TEXT
		)`,
		`CREATE TABLE ` + pat1762Schema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			title    TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low'
		)`,
		`CREATE TABLE ` + pat1762Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_retirement_decisions (PAT-2135): FetchPortalDevices reads
		// each device's retirement.
		`CREATE TABLE ` + pat1762Schema + `.device_retirement_decisions (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL,
			device_id   UUID NOT NULL,
			action      TEXT NOT NULL,
			reason      TEXT,
			actor_email TEXT NOT NULL,
			decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_os_update (PAT-2294): FetchPortalDevices falls back to the
		// agent's OS-update verdict when pending_updates is NULL.
		`CREATE TABLE ` + pat1762Schema + `.device_os_update (
			id          BIGSERIAL PRIMARY KEY,
			device_id   UUID NOT NULL UNIQUE,
			state       TEXT NOT NULL,
			checked_at  TIMESTAMPTZ,
			reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1762Schema + `.device_hardware (
			id                       BIGSERIAL PRIMARY KEY,
			device_id                UUID NOT NULL,
			battery_max_capacity_pct INTEGER,
			battery_condition        TEXT,
			battery_cycle_count      INTEGER
		)`,
		`CREATE TABLE ` + pat1762Schema + `.device_storage_volume (
			id                 BIGSERIAL PRIMARY KEY,
			device_hardware_id BIGINT NOT NULL,
			mount              TEXT NOT NULL,
			free_bytes         BIGINT NOT NULL,
			used_pct           INTEGER NOT NULL
		)`,
		`CREATE TABLE ` + pat1762Schema + `.device_disk (
			id                 BIGSERIAL PRIMARY KEY,
			device_hardware_id BIGINT NOT NULL,
			smart_status       TEXT NOT NULL,
			internal           BOOLEAN NOT NULL
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1762Schema+` CASCADE`)
	})
	return pool
}

// insertPAT1762Tenant creates one tenant and returns its id.
func insertPAT1762Tenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name) VALUES ('PAT-1762 Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

// insertPAT1762Device creates one macOS device for tenantID with the given
// hostname (so ORDER BY hostname in FetchTenantDevices is deterministic) and
// returns its id.
func insertPAT1762Device(t *testing.T, pool *pgxpool.Pool, tenantID, hostname string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, $2, 'macOS', '15.0')
		RETURNING id::text
	`, tenantID, hostname).Scan(&deviceID); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
	return deviceID
}

// insertPAT1762Rule creates one compliance rule and returns its id.
func insertPAT1762Rule(t *testing.T, pool *pgxpool.Pool, ruleKey, title, severity string) string {
	t.Helper()
	var ruleID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ($1, $2, $3)
		RETURNING id::text
	`, ruleKey, title, severity).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule %s: %v", ruleKey, err)
	}
	return ruleID
}

// insertPAT1762Eval inserts one latest evaluation for (deviceID, ruleID).
// observedValue == nil stores a SQL NULL (undetermined evidence).
func insertPAT1762Eval(t *testing.T, pool *pgxpool.Pool, deviceID, ruleID, status string, observedValue *string, severity string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
	`, deviceID, ruleID, status, observedValue, severity); err != nil {
		t.Fatalf("insert evaluation (device %s, status %s): %v", deviceID, status, err)
	}
}

// TestFetchTenantDevices_UndeterminedFailExcludedFromCounts is the
// FetchTenantDevices half of the regression. FailCount must count only
// real, evidenced fails (this feeds portal.go's FetchPortalDevices, and so
// GET /v1/portal/devices' findings_open); UndeterminedCount must carry the
// unreadable-evidence fails separately; CompliancePct's denominator must
// still include undetermined fails so missing evidence never raises the
// score; and a NotConfigured fail (non-NULL observed_value) must be counted
// as a real fail, not swept into UndeterminedCount.
func TestFetchTenantDevices_UndeterminedFailExcludedFromCounts(t *testing.T) {
	pool := pat1762Pool(t)
	tenantID := insertPAT1762Tenant(t, pool)
	ruleID := insertPAT1762Rule(t, pool, "pat1762_test_rule", "PAT-1762 Test Rule", "high")

	realFailDevice := insertPAT1762Device(t, pool, tenantID, "a-real-fail")
	insertPAT1762Eval(t, pool, realFailDevice, ruleID, "fail", strPtr("Off"), "high")

	unknownFailDevice := insertPAT1762Device(t, pool, tenantID, "b-unknown-fail")
	insertPAT1762Eval(t, pool, unknownFailDevice, ruleID, "fail", nil, "high")

	notConfiguredDevice := insertPAT1762Device(t, pool, tenantID, "c-not-configured")
	insertPAT1762Eval(t, pool, notConfiguredDevice, ruleID, "fail", strPtr("NotConfigured"), "high")

	res, err := FetchTenantDevices(context.Background(), pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchTenantDevices: %v", err)
	}
	if len(res.Devices) != 3 {
		t.Fatalf("got %d devices, want 3", len(res.Devices))
	}

	byID := map[string]TenantDeviceRow{}
	for _, d := range res.Devices {
		byID[d.ID] = d
	}

	real := byID[realFailDevice]
	if real.FailCount != 1 || real.UndeterminedCount != 0 {
		t.Errorf("real-fail device: FailCount=%d UndeterminedCount=%d, want 1/0", real.FailCount, real.UndeterminedCount)
	}
	if real.CompliancePct != 0 {
		t.Errorf("real-fail device: CompliancePct=%.2f, want 0 (1 fail / 1 evaluated)", real.CompliancePct)
	}

	unknown := byID[unknownFailDevice]
	if unknown.FailCount != 0 || unknown.UndeterminedCount != 1 {
		t.Errorf("unknown-fail device: FailCount=%d UndeterminedCount=%d, want 0/1 (unreadable evidence must not count as a real fail)", unknown.FailCount, unknown.UndeterminedCount)
	}
	// The denominator MUST still include the undetermined fail: pass=0,
	// fail=0, undetermined=1, error=0 → 0/1 = 0%, not the NULL/AVG-excluded
	// "no evaluations" shape and not 100%. Missing evidence must never raise
	// the score (root AGENTS.md "absence requires authority").
	if unknown.CompliancePct != 0 {
		t.Errorf("unknown-fail device: CompliancePct=%.2f, want 0 (undetermined must stay in the denominator, not raise the score)", unknown.CompliancePct)
	}

	notConfigured := byID[notConfiguredDevice]
	if notConfigured.FailCount != 1 || notConfigured.UndeterminedCount != 0 {
		t.Errorf("NotConfigured-fail device: FailCount=%d UndeterminedCount=%d, want 1/0 (a real, evidenced result, not undetermined)", notConfigured.FailCount, notConfigured.UndeterminedCount)
	}
}

// TestFetchPortalDevices_EncryptionUnknownForUndeterminedFail is the
// FetchPortalDevices half of the regression: encryption_ok must read
// "unknown" (nil), never "not encrypted" (false), when the device's latest
// evaluation of an encryption rule is undetermined (unreadable evidence). A
// real, evidenced fail must still read false, and a pass must still read
// true.
func TestFetchPortalDevices_EncryptionUnknownForUndeterminedFail(t *testing.T) {
	pool := pat1762Pool(t)
	tenantID := insertPAT1762Tenant(t, pool)
	ruleID := insertPAT1762Rule(t, pool, encryptionRuleKeys[0], "Enable FileVault", "critical")

	encryptedDevice := insertPAT1762Device(t, pool, tenantID, "d-encrypted")
	insertPAT1762Eval(t, pool, encryptedDevice, ruleID, "pass", strPtr("On"), "critical")

	realFailDevice := insertPAT1762Device(t, pool, tenantID, "e-not-encrypted")
	insertPAT1762Eval(t, pool, realFailDevice, ruleID, "fail", strPtr("Off"), "critical")

	unknownDevice := insertPAT1762Device(t, pool, tenantID, "f-unreadable")
	insertPAT1762Eval(t, pool, unknownDevice, ruleID, "fail", nil, "critical")

	res, err := FetchPortalDevices(context.Background(), pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalDevices: %v", err)
	}
	if len(res.Devices) != 3 {
		t.Fatalf("got %d devices, want 3", len(res.Devices))
	}

	byID := map[string]PortalDeviceRow{}
	for _, d := range res.Devices {
		byID[d.ID] = d
	}

	if got := byID[encryptedDevice].EncryptionOK; got == nil || !*got {
		t.Errorf("encrypted device: EncryptionOK=%v, want true", boolPtrStr(got))
	}
	if got := byID[realFailDevice].EncryptionOK; got == nil || *got {
		t.Errorf("real-fail device: EncryptionOK=%v, want false", boolPtrStr(got))
	}
	if got := byID[unknownDevice].EncryptionOK; got != nil {
		t.Errorf("unreadable-evidence device: EncryptionOK=%v, want nil (unknown, not \"not encrypted\")", boolPtrStr(got))
	}
}

func boolPtrStr(b *bool) string {
	if b == nil {
		return "<nil>"
	}
	if *b {
		return "true"
	}
	return "false"
}

// TestFetchPortalDevices_PatchPendingUnknownForNullPendingUpdates is the
// PAT-1805 regression for the per-device roster flag: patch_pending must
// read nil ("not reported"), never false ("up to date"), for a device whose
// pending_updates is SQL NULL - every Windows device today, since
// pending_updates is populated only by the macOS collector. A real empty
// array must still read false, and a non-empty array must still read true.
func TestFetchPortalDevices_PatchPendingUnknownForNullPendingUpdates(t *testing.T) {
	pool := pat1762Pool(t)
	ctx := context.Background()
	tenantID := insertPAT1762Tenant(t, pool)

	insertDevice := func(hostname, pendingLiteral string) string {
		t.Helper()
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
			VALUES ($1::uuid, $2, 'macOS', '15.0', `+pendingLiteral+`)
			RETURNING id::text
		`, tenantID, hostname).Scan(&deviceID); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return deviceID
	}

	upToDateDevice := insertDevice("g-up-to-date", `'[]'::jsonb`)
	pendingDevice := insertDevice("h-pending", `'[{"name":"Chrome"}]'::jsonb`)
	unknownDevice := insertDevice("i-unknown", `NULL`)

	res, err := FetchPortalDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalDevices: %v", err)
	}
	if len(res.Devices) != 3 {
		t.Fatalf("got %d devices, want 3", len(res.Devices))
	}

	byID := map[string]PortalDeviceRow{}
	for _, d := range res.Devices {
		byID[d.ID] = d
	}

	if got := byID[upToDateDevice].PatchPending; got == nil || *got {
		t.Errorf("empty-array device: PatchPending=%v, want false", boolPtrStr(got))
	}
	if got := byID[pendingDevice].PatchPending; got == nil || !*got {
		t.Errorf("non-empty-array device: PatchPending=%v, want true", boolPtrStr(got))
	}
	if got := byID[unknownDevice].PatchPending; got != nil {
		t.Errorf("NULL pending_updates device: PatchPending=%v, want nil (not reported, not \"up to date\")", boolPtrStr(got))
	}
}

// TestFetchPortalDevices_PatchPendingFromOSUpdateVerdict is the PAT-2294
// report-layer lock: with pending_updates NULL (every Windows device) the
// roster reads a fresh device_os_update verdict, a stale one reads nil, a
// device with pending_updates set prefers the explicit verdict, and
// FetchPortalDeviceSummary returns exactly the roster's figures for each
// device while refusing another tenant's device. The HTTP-level version is
// integration/portal_device_update_state_test.go.
func TestFetchPortalDevices_PatchPendingFromOSUpdateVerdict(t *testing.T) {
	pool := pat1762Pool(t)
	ctx := context.Background()
	tenantID := insertPAT1762Tenant(t, pool)
	otherTenantID := insertPAT1762Tenant(t, pool)

	insertDevice := func(tenant, hostname, os, pendingLiteral string) string {
		t.Helper()
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
			VALUES ($1::uuid, $2, $3, '10.0', `+pendingLiteral+`)
			RETURNING id::text
		`, tenant, hostname, os).Scan(&deviceID); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return deviceID
	}
	insertVerdict := func(deviceID, state string, age time.Duration) {
		t.Helper()
		at := time.Now().UTC().Add(-age)
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_os_update (device_id, state, checked_at, reported_at)
			VALUES ($1::uuid, $2, $3, $3)
		`, deviceID, state, at); err != nil {
			t.Fatalf("insert device_os_update %s: %v", state, err)
		}
	}

	behind := insertDevice(tenantID, "a-win-behind", "Windows", "NULL")
	insertVerdict(behind, "update_required", time.Hour)
	current := insertDevice(tenantID, "b-win-current", "Windows", "NULL")
	insertVerdict(current, "up_to_date", time.Hour)
	stale := insertDevice(tenantID, "c-win-stale", "Windows", "NULL")
	insertVerdict(stale, "update_required", portalEvidenceStaleAfter+time.Hour)
	noRow := insertDevice(tenantID, "d-win-no-row", "Windows", "NULL")
	macPending := insertDevice(tenantID, "e-mac-pending", "macOS", `'[{"name":"Safari"}]'::jsonb`)
	insertVerdict(macPending, "up_to_date", time.Hour)
	foreign := insertDevice(otherTenantID, "f-foreign", "Windows", "NULL")
	insertVerdict(foreign, "update_required", time.Hour)

	want := map[string]string{
		behind: "true", current: "false", stale: "<nil>", noRow: "<nil>", macPending: "false",
	}

	res, err := FetchPortalDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalDevices: %v", err)
	}
	if len(res.Devices) != len(want) {
		t.Fatalf("roster has %d devices, want %d (the other tenant's device must not appear)", len(res.Devices), len(want))
	}
	for _, d := range res.Devices {
		if got := boolPtrStr(d.PatchPending); got != want[d.ID] {
			t.Errorf("roster %s PatchPending = %s, want %s", d.Hostname, got, want[d.ID])
		}

		sum, err := FetchPortalDeviceSummary(ctx, pool, tenantID, d.ID)
		if err != nil {
			t.Fatalf("FetchPortalDeviceSummary %s: %v", d.Hostname, err)
		}
		if boolPtrStr(sum.PatchPending) != boolPtrStr(d.PatchPending) ||
			boolPtrStr(sum.EncryptionOK) != boolPtrStr(d.EncryptionOK) ||
			sum.FindingsOpen != d.FindingsOpen() {
			t.Errorf("summary %s = %+v, roster row says patch=%s enc=%s findings=%d",
				d.Hostname, sum, boolPtrStr(d.PatchPending), boolPtrStr(d.EncryptionOK), d.FindingsOpen())
		}
	}

	// A device outside the tenant is indistinguishable from one that does
	// not exist, whichever tenant asks.
	if _, err := FetchPortalDeviceSummary(ctx, pool, tenantID, foreign); !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("summary of another tenant's device: err = %v, want ErrDeviceNotFound", err)
	}
	if _, err := FetchPortalDeviceSummary(ctx, pool, tenantID, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("summary of an unknown device: err = %v, want ErrDeviceNotFound", err)
	}
}
