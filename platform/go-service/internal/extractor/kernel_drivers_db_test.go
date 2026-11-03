package extractor

// PAT-2263: kernel_drivers ingest against a real database, end to end with
// the driver lists. Skipped without TEST_DATABASE_URL; CI's
// "internal/extractor DB-gated tests" step runs it against the migrated
// schema. The global list tables are isolated in this package's own schema.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/driverblock"
	"patched.im/api/internal/driverblock/driverblocktest"
)

const kdTestSchema = "pat2263_extractor_test"

func kernelDriversFromFixture(t *testing.T, fixture string) *kernelDriversPart {
	t.Helper()
	var p payload
	if err := json.Unmarshal(readFixture(t, "valid", fixture), &p); err != nil {
		t.Fatal(err)
	}
	if p.KernelDrivers == nil {
		t.Fatalf("%s has no kernel_drivers block", fixture)
	}
	return p.KernelDrivers
}

func kdIngest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, row claimedRow, deviceID string, kd *kernelDriversPart) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := upsertKernelDrivers(ctx, tx, row, deviceID, kd, row.ReceivedAt.Add(-time.Minute), nil); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

type kdStoredRow struct {
	HashStatus string
	SHA256     *string
	Reason     *string
}

func kdRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID string) map[string]kdStoredRow {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT driver_key, hash_status, sha256, unhashed_reason
		FROM device_kernel_drivers WHERE device_id = $1::uuid`, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]kdStoredRow{}
	for rows.Next() {
		var k string
		var r kdStoredRow
		if err := rows.Scan(&k, &r.HashStatus, &r.SHA256, &r.Reason); err != nil {
			t.Fatal(err)
		}
		out[k] = r
	}
	return out
}

func kdState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID string) (status, enforced string, reportedAt time.Time) {
	t.Helper()
	if err := pool.QueryRow(ctx, `SELECT collection_status, blocklist_enforced, reported_at
		FROM device_kernel_driver_state WHERE device_id = $1::uuid`, deviceID).Scan(&status, &enforced, &reportedAt); err != nil {
		t.Fatalf("state: %v", err)
	}
	return
}

func kdObservations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deviceID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM device_kernel_driver_observations WHERE device_id = $1::uuid`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func kdDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) (tenantID, deviceID string) {
	t.Helper()
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00', '\x00') RETURNING id::text`, "pat2263-kd-"+label).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, serial, hostname)
		VALUES ($1::uuid, 'Windows', $2, 'KD-HOST') RETURNING id::text`, tenantID, "PAT2263KD-"+label).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return tenantID, deviceID
}

const (
	kdFlat     = `path:c:\windows\system32\drivers\flat.sys`
	kdPe       = `path:c:\windows\system32\drivers\pe.sys`
	kdVendorfs = `path:c:\vendor\vendorfs.sys`
	kdRemote   = `service:remote`
)

func TestKernelDriversProjection(t *testing.T) {
	pool := driverblocktest.Pool(t, kdTestSchema)
	ctx := context.Background()
	tenantID, deviceID := kdDevice(t, ctx, pool, "proj-"+time.Now().Format("150405.000000"))
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)

	// 1. complete: three rows, state complete.
	first := nextFirmwareRow(tenantID, base)
	kdIngest(t, ctx, pool, first, deviceID, kernelDriversFromFixture(t, "with-kernel-drivers-complete-windows.json"))
	rows := kdRows(t, ctx, pool, deviceID)
	if len(rows) != 3 || rows[kdFlat].HashStatus != "hashed" || rows[kdVendorfs].Reason == nil || *rows[kdVendorfs].Reason != "file_missing" {
		t.Fatalf("after complete: %+v", rows)
	}
	if status, enforced, _ := kdState(t, ctx, pool, deviceID); status != "complete" || enforced != "yes" {
		t.Fatalf("state = %s %s", status, enforced)
	}

	// Re-extraction of the same payload adds nothing.
	kdIngest(t, ctx, pool, first, deviceID, kernelDriversFromFixture(t, "with-kernel-drivers-complete-windows.json"))
	if n := kdObservations(t, ctx, pool, deviceID); n != 1 {
		t.Fatalf("observations after re-extraction = %d", n)
	}

	// 2. partial, newer: rows it sent are upserted (flat.sys now unhashed with
	// its old hashes cleared), the pathless service row is added, and
	// vendorfs.sys, which it did not send, is kept: partial has no absence
	// authority.
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, base.Add(10*time.Minute)), deviceID,
		kernelDriversFromFixture(t, "with-kernel-drivers-partial-windows.json"))
	rows = kdRows(t, ctx, pool, deviceID)
	if len(rows) != 4 {
		t.Fatalf("after partial: %+v", rows)
	}
	if r := rows[kdFlat]; r.HashStatus != "unhashed" || r.SHA256 != nil || *r.Reason != "reparse_point" {
		t.Fatalf("flat after partial = %+v", r)
	}
	if _, kept := rows[kdVendorfs]; !kept {
		t.Fatal("a partial report pruned a row it did not send")
	}
	if _, added := rows[kdRemote]; !added {
		t.Fatal("pathless service row not stored")
	}
	if status, enforced, _ := kdState(t, ctx, pool, deviceID); status != "partial" || enforced != "unknown" {
		t.Fatalf("state = %s %s", status, enforced)
	}

	// 3. unavailable, newer: state moves on (enforcement too), rows untouched.
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, base.Add(20*time.Minute)), deviceID,
		kernelDriversFromFixture(t, "with-kernel-drivers-unavailable-windows.json"))
	if got := kdRows(t, ctx, pool, deviceID); len(got) != 4 {
		t.Fatalf("an unavailable report changed rows: %+v", got)
	}
	status, enforced, reportedAt := kdState(t, ctx, pool, deviceID)
	if status != "unavailable" || enforced != "no" {
		t.Fatalf("state = %s %s", status, enforced)
	}

	// 4. an older replay is evidence only.
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, base.Add(5*time.Minute)), deviceID,
		kernelDriversFromFixture(t, "with-kernel-drivers-complete-windows.json"))
	if s, _, at := kdState(t, ctx, pool, deviceID); s != "unavailable" || !at.Equal(reportedAt) {
		t.Fatalf("an older replay overwrote the state: %s %v", s, at)
	}
	if got := kdRows(t, ctx, pool, deviceID); len(got) != 4 || got[kdFlat].HashStatus != "unhashed" {
		t.Fatalf("an older replay overwrote rows: %+v", got)
	}
	if n := kdObservations(t, ctx, pool, deviceID); n != 4 {
		t.Fatalf("observations = %d, want 4", n)
	}

	// 5. complete, newest: the set is replaced and the pathless row pruned.
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, base.Add(30*time.Minute)), deviceID,
		kernelDriversFromFixture(t, "with-kernel-drivers-complete-windows.json"))
	rows = kdRows(t, ctx, pool, deviceID)
	if len(rows) != 3 || rows[kdFlat].HashStatus != "hashed" {
		t.Fatalf("after second complete: %+v", rows)
	}
	if _, stale := rows[kdRemote]; stale {
		t.Fatal("a complete report kept a row it did not send")
	}

	// Observations are immutable.
	if _, err := pool.Exec(ctx, `UPDATE device_kernel_driver_observations SET collection_status = 'complete'
		WHERE device_id = $1::uuid`, deviceID); err == nil {
		t.Fatal("an observation was updated")
	}
}

func TestKernelDriversAbsentBlockIsANoOp(t *testing.T) {
	pool := driverblocktest.Pool(t, kdTestSchema)
	ctx := context.Background()
	tenantID, deviceID := kdDevice(t, ctx, pool, "absent-"+time.Now().Format("150405.000000"))
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, time.Now().UTC()), deviceID, nil)
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM device_kernel_driver_state WHERE device_id = $1::uuid`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 || kdObservations(t, ctx, pool, deviceID) != 0 {
		t.Fatal("an absent block stored something")
	}
}

// TestKernelDriversEndToEnd: the Windows agent's exact bytes, ingested, then
// matched against hand-written lists in each source's real format. The
// agent's synthetic pe.sys is on the Microsoft fixture by Authenticode
// SHA-256; its synthetic flat.sys is on the loldrivers fixture under another
// file name (gdrv.sys), so it matches by hash alone.
func TestKernelDriversEndToEnd(t *testing.T) {
	pool := driverblocktest.Pool(t, kdTestSchema)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Second)
	for _, f := range []struct{ source, file string }{
		{driverblock.SourceMicrosoft, "DriverPolicy_Enforced.xml"},
		{driverblock.SourceLOLDrivers, "drivers.json"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "driverblock", "testdata", f.file))
		if err != nil {
			t.Fatal(err)
		}
		snap, err := driverblock.Parse(f.source, data, fetched)
		if err != nil {
			t.Fatal(err)
		}
		if err := driverblock.ReplaceSnapshot(ctx, pool, snap, fetched); err != nil {
			t.Fatal(err)
		}
	}

	tenantID, deviceID := kdDevice(t, ctx, pool, "e2e-"+time.Now().Format("150405.000000"))
	kdIngest(t, ctx, pool, nextFirmwareRow(tenantID, time.Now().UTC()), deviceID,
		kernelDriversFromFixture(t, "with-kernel-drivers-complete-windows.json"))

	view, err := driverblock.FetchDevice(ctx, pool, tenantID, deviceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "complete" || view.Enforcement.BlocklistEnforced != "yes" || view.Enforcement.VulnerableDriverBlocklist != "enabled" {
		t.Fatalf("header = %s %+v", view.Status, view.Enforcement)
	}
	want := driverblock.DeviceSummary{Drivers: 3, Hashed: 2, Unhashed: 1, Listed: 2, Unknown: 1}
	if view.Summary != want {
		t.Fatalf("summary = %+v, want %+v", view.Summary, want)
	}
	byPath := map[string]driverblock.DriverRow{}
	for _, d := range view.Drivers {
		byPath[*d.Path] = d
	}
	pe := byPath[`C:\Windows\System32\drivers\pe.sys`]
	if pe.MatchStatus != driverblock.MatchListed || len(pe.Matches) != 1 || pe.Matches[0].Source != driverblock.SourceMicrosoft ||
		pe.Matches[0].HashKind != driverblock.HashAuthenticodeSHA256 || pe.Matches[0].ListVersion != "10.0.99999.1" {
		t.Fatalf("pe = %+v", pe)
	}
	flat := byPath[`C:\Windows\System32\drivers\flat.sys`]
	if flat.MatchStatus != driverblock.MatchListed || flat.Matches[0].Source != driverblock.SourceLOLDrivers ||
		flat.Matches[0].EntryName != "gdrv.sys" || flat.Matches[0].Hash != "357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1" {
		t.Fatalf("flat = %+v", flat)
	}
	missing := byPath[`C:\Vendor\vendorfs.sys`]
	if missing.MatchStatus != driverblock.MatchUnknown || *missing.UnknownReason != driverblock.UnknownNotHashed {
		t.Fatalf("vendorfs = %+v", missing)
	}
}
