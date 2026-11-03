package extractor

// PAT-2269: upsertDevice used to pass SQL NULL for security_inventory
// unconditionally whenever schema_version == 3 (the Windows agent), so the
// plain COALESCE(EXCLUDED.security_inventory, devices.security_inventory)
// left the column exactly as it was on every ingest. That meant Windows
// security_tools was NEVER written to devices.security_inventory, so EDR
// coverage (internal/report/edr_coverage.go) and the Cyber Essentials
// malware-protection control saw no evidence at all for every Windows
// device, however good the agent's detection was.
//
// This file is a DB round-trip test proving:
//  1. an sv=3 ingest carrying security_tools now stores it on
//     devices.security_inventory;
//  2. report.FetchEDRCoverageReport reads that device as covered, using the
//     REAL migration 0212 Bitdefender baseline row — not one this test seeds
//     itself;
//  3. an sv=3 ingest never erases macOS-only security_inventory sections
//     (system_extensions/background_items/icloud) that already sit on the
//     same device row (the merge-not-replace fix);
//  4. sv=2 behaviour is unchanged — still a full replace of all four
//     sections, byte for byte what the pre-fix code produced.
//
// Convention: same as internal/report/edr_coverage_migrated_db_test.go —
// connects to TEST_DATABASE_URL directly with no search_path override, on
// the assumption the target database is already fully migrated. Skips
// (never errors) when TEST_DATABASE_URL is unset or migration
// 0212_protected_software_bitdefender hasn't been applied there, so a plain
// `go test ./...` against an empty/unmigrated database degrades to a skip.
//
// Build a fully-migrated database locally the same way the integration
// suite's TestMain does (apply every migrations/*.sql file in order, skipping
// *_rollback.sql), then point TEST_DATABASE_URL at it.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/report"
)

// pat2269ConnectOrSkip connects to TEST_DATABASE_URL and skips (with a clear
// reason) unless migration 0212_protected_software_bitdefender has actually
// been applied there — the baseline row TestSV3IngestStoresSecurityTools...
// relies on.
func pat2269ConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-2269 sv=3 security_inventory DB round-trip test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var applied bool
	err = pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0212_protected_software_bitdefender')`,
	).Scan(&applied)
	if err != nil {
		pool.Close()
		t.Skipf("TEST_DATABASE_URL does not look like a fully-migrated schema (schema_migrations query failed: %v) — "+
			"point it at a database with every migrations/*.sql file applied", err)
	}
	if !applied {
		pool.Close()
		t.Skip("TEST_DATABASE_URL is missing migration 0212_protected_software_bitdefender — " +
			"point it at a database with every migrations/*.sql file applied")
	}
	return pool
}

// pat2269SeedTenant inserts a real tenants row (bearer_token_hash/hmac_secret
// are NOT NULL from migration 0001 on) and registers cleanup.
func pat2269SeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00', '\x00')
		RETURNING id::text
	`, name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

func pat2269FetchSecurityInventory(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID string) []byte {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT security_inventory FROM devices WHERE id = $1::uuid`, deviceID).Scan(&raw); err != nil {
		t.Fatalf("select security_inventory: %v", err)
	}
	return raw
}

// TestSV3IngestStoresSecurityToolsAndCountsAsEDRCovered is the PAT-2269 red
// test. Pre-fix, upsertDevice passes SQL NULL for security_inventory on every
// sv=3 ingest, so this fresh device's security_inventory column stays NULL —
// FetchEDRCoverageReport then reports EDRStateUnknown, never
// EDRStateCovered, however good the Bitdefender evidence in the payload is.
func TestSV3IngestStoresSecurityToolsAndCountsAsEDRCovered(t *testing.T) {
	pool := pat2269ConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID := pat2269SeedTenant(t, ctx, pool, "pat2269-sv3-bitdefender")

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	p := &payload{
		SchemaVersion: 3,
		Platform:      "windows",
		Agent:         "patched-collect-win",
		AgentVersion:  "pat-2269-test",
		TenantID:      tenantID,
		Device: devicePart{
			Serial:   "PAT2269-SV3-001",
			Hostname: "pat2269-win-host",
			HWModel:  "Dell OptiPlex",
			Arch:     "x86_64",
		},
		OS:            osPart{Name: "Windows", Version: "10.0.19045", Build: "19045"},
		SecurityTools: json.RawMessage(`[{"id":"bitdefender","name":"Bitdefender"}]`),
	}

	deviceID, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), p, nil)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("upsertDevice: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, deviceID) })

	// (1) security_inventory.security_tools is stored.
	raw := pat2269FetchSecurityInventory(t, ctx, pool, deviceID)
	if len(raw) == 0 {
		t.Fatalf("devices.security_inventory is NULL/empty after an sv=3 ingest that carried security_tools — Windows security_tools was not stored")
	}
	var decoded report.DeviceSecurityInventory
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal security_inventory (%s): %v", raw, err)
	}
	if len(decoded.SecurityTools) != 1 || decoded.SecurityTools[0].ID != "bitdefender" || decoded.SecurityTools[0].Name != "Bitdefender" {
		t.Fatalf("security_inventory.security_tools = %+v, want [{bitdefender Bitdefender}]", decoded.SecurityTools)
	}

	// (2) EDR coverage reads the device as covered, via the REAL migration
	// 0212 Bitdefender baseline row — this test seeds no protected_software
	// row of its own.
	r, err := report.FetchEDRCoverageReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchEDRCoverageReport: %v", err)
	}
	if len(r.Devices) != 1 {
		t.Fatalf("FetchEDRCoverageReport returned %d devices, want 1", len(r.Devices))
	}
	dev := r.Devices[0]
	if dev.State != report.EDRStateCovered {
		t.Fatalf("EDR state = %q, want %q (security_tools was reported but the device isn't recognised as covered)", dev.State, report.EDRStateCovered)
	}
}

// TestSV3IngestPreservesExistingMacOSOnlySections proves the merge-not-replace
// fix: an sv=3 ingest onto a device row that already carries macOS-only
// security_inventory sections (system_extensions/background_items/icloud —
// the Windows agent has nothing to report for any of them) must not erase
// those sections, only update security_tools. This is an edge case — a real
// device doesn't switch agent platform between checks-in — but it pins the
// SQL merge behaviour directly: a full JSONB overwrite (the pre-fix bug's
// naive cure) would have wiped these sections the moment a Windows payload
// ever wrote to a row that had them.
func TestSV3IngestPreservesExistingMacOSOnlySections(t *testing.T) {
	pool := pat2269ConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID := pat2269SeedTenant(t, ctx, pool, "pat2269-sv3-preserve-macos-sections")

	serial := "PAT2269-MERGE-001"

	// First ingest: sv=2, all four sections populated.
	sv2 := &payload{
		SchemaVersion: 2,
		Agent:         "patched-collect.sh",
		AgentVersion:  "pat-2269-test",
		TenantID:      tenantID,
		Device: devicePart{
			Serial:   serial,
			Hostname: "pat2269-mac-host",
			HWModel:  "MacBookPro18,1",
			Arch:     "arm64",
		},
		OS:               osPart{Name: "macOS", Version: "15.4", Build: "24E263"},
		SecurityTools:    json.RawMessage(`[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]`),
		SystemExtensions: json.RawMessage(`[{"enabled":true,"active":true,"team_id":"ABC123","bundle_id":"com.sophos.ext","version":"1.0","name":"Sophos Extension","state":"enabled"}]`),
		BackgroundItems:  json.RawMessage(`[{"name":"Dropbox","identifier":"com.dropbox.agent","team_id":"XYZ789","url":"","type":1,"disposition":1}]`),
		ICloud:           iCloudPart{SignedIn: "Yes"},
	}

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	deviceID, _, err := upsertDevice(ctx, tx1, tenantID, time.Now(), sv2, nil)
	if err != nil {
		_ = tx1.Rollback(ctx)
		t.Fatalf("upsertDevice (sv2): %v", err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, deviceID) })

	// Sanity: the macOS sections actually landed before the sv=3 ingest we're
	// testing against.
	before := pat2269FetchSecurityInventory(t, ctx, pool, deviceID)
	var beforeDecoded report.DeviceSecurityInventory
	if err := json.Unmarshal(before, &beforeDecoded); err != nil {
		t.Fatalf("unmarshal security_inventory after sv2 ingest: %v", err)
	}
	if len(beforeDecoded.SystemExtensions) != 1 || len(beforeDecoded.BackgroundItems) != 1 || beforeDecoded.ICloud.SignedIn != "Yes" {
		t.Fatalf("sv2 ingest did not populate the macOS-only sections as expected: %+v", beforeDecoded)
	}

	// Second ingest: sv=3, same device row (same serial, no hw_uuid on
	// either side), carrying a different security_tools value and nothing
	// for the macOS-only sections — exactly what the real Windows agent
	// sends.
	sv3 := &payload{
		SchemaVersion: 3,
		Platform:      "windows",
		Agent:         "patched-collect-win",
		AgentVersion:  "pat-2269-test",
		TenantID:      tenantID,
		Device: devicePart{
			Serial:   serial,
			Hostname: "pat2269-mac-host",
			HWModel:  "MacBookPro18,1",
			Arch:     "arm64",
		},
		OS:            osPart{Name: "Windows", Version: "10.0.19045", Build: "19045"},
		SecurityTools: json.RawMessage(`[{"id":"bitdefender","name":"Bitdefender"}]`),
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	deviceID2, _, err := upsertDevice(ctx, tx2, tenantID, time.Now(), sv3, nil)
	if err != nil {
		_ = tx2.Rollback(ctx)
		t.Fatalf("upsertDevice (sv3): %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit tx2: %v", err)
	}
	if deviceID2 != deviceID {
		t.Fatalf("sv3 ingest created a new device row (%s) instead of updating the existing one (%s)", deviceID2, deviceID)
	}

	after := pat2269FetchSecurityInventory(t, ctx, pool, deviceID)
	var afterDecoded report.DeviceSecurityInventory
	if err := json.Unmarshal(after, &afterDecoded); err != nil {
		t.Fatalf("unmarshal security_inventory after sv3 ingest: %v", err)
	}

	// security_tools was updated to the sv=3 value.
	if len(afterDecoded.SecurityTools) != 1 || afterDecoded.SecurityTools[0].ID != "bitdefender" {
		t.Fatalf("security_tools after sv3 ingest = %+v, want [{bitdefender Bitdefender}]", afterDecoded.SecurityTools)
	}
	// The macOS-only sections from the FIRST (sv2) ingest must survive
	// untouched — this is the merge-not-replace behaviour this test exists
	// to pin.
	if len(afterDecoded.SystemExtensions) != 1 || afterDecoded.SystemExtensions[0].BundleID != "com.sophos.ext" {
		t.Fatalf("system_extensions after sv3 ingest = %+v, want the sv2 ingest's Sophos extension preserved", afterDecoded.SystemExtensions)
	}
	if len(afterDecoded.BackgroundItems) != 1 || afterDecoded.BackgroundItems[0].Identifier != "com.dropbox.agent" {
		t.Fatalf("background_items after sv3 ingest = %+v, want the sv2 ingest's Dropbox item preserved", afterDecoded.BackgroundItems)
	}
	if afterDecoded.ICloud.SignedIn != "Yes" {
		t.Fatalf("icloud.signed_in after sv3 ingest = %q, want the sv2 ingest's \"Yes\" preserved", afterDecoded.ICloud.SignedIn)
	}
}

// TestSV2IngestSecurityInventoryUnchanged pins sv=2 behaviour as
// byte-identical to before this fix: a full replace of all four sections on
// every ingest, never a merge. A later sv=2 ingest with different values for
// every section must overwrite all of them, not merge like sv=3 now does.
func TestSV2IngestSecurityInventoryUnchanged(t *testing.T) {
	pool := pat2269ConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantID := pat2269SeedTenant(t, ctx, pool, "pat2269-sv2-unchanged")
	serial := "PAT2269-SV2-001"

	first := &payload{
		SchemaVersion:    2,
		Agent:            "patched-collect.sh",
		AgentVersion:     "pat-2269-test",
		TenantID:         tenantID,
		Device:           devicePart{Serial: serial, Hostname: "pat2269-sv2-host", HWModel: "MacBookPro18,1", Arch: "arm64"},
		OS:               osPart{Name: "macOS", Version: "15.4", Build: "24E263"},
		SecurityTools:    json.RawMessage(`[{"id":"sophos-endpoint","name":"Sophos Intercept X"}]`),
		SystemExtensions: json.RawMessage(`[{"enabled":true,"active":true,"team_id":"ABC123","bundle_id":"com.sophos.ext","version":"1.0","name":"Sophos Extension","state":"enabled"}]`),
		BackgroundItems:  json.RawMessage(`[{"name":"Dropbox","identifier":"com.dropbox.agent","team_id":"XYZ789","url":"","type":1,"disposition":1}]`),
		ICloud:           iCloudPart{SignedIn: "Yes"},
	}
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	deviceID, _, err := upsertDevice(ctx, tx1, tenantID, time.Now(), first, nil)
	if err != nil {
		_ = tx1.Rollback(ctx)
		t.Fatalf("upsertDevice (first sv2): %v", err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, deviceID) })

	// Second sv2 ingest: no system_extensions/background_items/icloud at all
	// (an agent run that genuinely found none), different security_tools.
	// A plain replace must wipe the sections the first ingest set, exactly
	// like the pre-fix code — sv=2 never merges.
	second := &payload{
		SchemaVersion: 2,
		Agent:         "patched-collect.sh",
		AgentVersion:  "pat-2269-test",
		TenantID:      tenantID,
		Device:        devicePart{Serial: serial, Hostname: "pat2269-sv2-host", HWModel: "MacBookPro18,1", Arch: "arm64"},
		OS:            osPart{Name: "macOS", Version: "15.4", Build: "24E263"},
		SecurityTools: json.RawMessage(`[]`),
		ICloud:        iCloudPart{SignedIn: "No"},
	}
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	deviceID2, _, err := upsertDevice(ctx, tx2, tenantID, time.Now(), second, nil)
	if err != nil {
		_ = tx2.Rollback(ctx)
		t.Fatalf("upsertDevice (second sv2): %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit tx2: %v", err)
	}
	if deviceID2 != deviceID {
		t.Fatalf("second sv2 ingest created a new device row (%s) instead of updating the existing one (%s)", deviceID2, deviceID)
	}

	raw := pat2269FetchSecurityInventory(t, ctx, pool, deviceID)
	var decoded report.DeviceSecurityInventory
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal security_inventory: %v", err)
	}
	if len(decoded.SecurityTools) != 0 {
		t.Fatalf("security_tools after second sv2 ingest = %+v, want empty (full replace, not merge)", decoded.SecurityTools)
	}
	if len(decoded.SystemExtensions) != 0 {
		t.Fatalf("system_extensions after second sv2 ingest = %+v, want wiped (sv2 is a full replace, never a merge)", decoded.SystemExtensions)
	}
	if len(decoded.BackgroundItems) != 0 {
		t.Fatalf("background_items after second sv2 ingest = %+v, want wiped (sv2 is a full replace, never a merge)", decoded.BackgroundItems)
	}
	if decoded.ICloud.SignedIn != "No" {
		t.Fatalf("icloud.signed_in after second sv2 ingest = %q, want %q (full replace)", decoded.ICloud.SignedIn, "No")
	}
}
