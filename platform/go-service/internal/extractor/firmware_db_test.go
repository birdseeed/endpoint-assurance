package extractor

// PAT-2262: firmware ingest against a real database. Skipped without
// TEST_DATABASE_URL; CI's "internal/extractor DB-gated tests" step runs it
// against the migrated schema.

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func firmwareTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping firmware DB test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// firmwareTestDevice creates a tenant and a Windows device inside tx.
func firmwareTestDevice(t *testing.T, ctx context.Context, tx pgx.Tx) (tenantID, deviceID string) {
	t.Helper()
	if err := tx.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2262-firmware', '\x00', '\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'Windows', 'PAT2262FW') RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return tenantID, deviceID
}

// firmwareFromFixture decodes the firmware block of one of the fixtures the
// Windows agent's serialisation was copied into.
func firmwareFromFixture(t *testing.T, fixture string) *firmwarePart {
	t.Helper()
	var p payload
	if err := json.Unmarshal(readFixture(t, "valid", fixture), &p); err != nil {
		t.Fatal(err)
	}
	if p.Firmware == nil {
		t.Fatalf("%s has no firmware block", fixture)
	}
	return p.Firmware
}

// Raw payload ids only need to be unique within device_firmware_observations;
// start far above anything the rest of the suite inserts.
var firmwareRawID = time.Now().UnixNano() % 1_000_000_000_000

func nextFirmwareRow(tenantID string, receivedAt time.Time) claimedRow {
	firmwareRawID++
	return claimedRow{ID: firmwareRawID, ReceivedAt: receivedAt, TenantID: tenantID}
}

type firmwareCurrentRow struct {
	CollectionStatus                         string
	Errors                                   []string
	ObservationID                            int64
	ReportedAt                               time.Time
	BIOSStatus, SystemStatus, BaseboardStat  *string
	BIOSManufacturer, BIOSVersion, SMBIOSVer *string
	BIOSReleaseDate                          *time.Time
	BIOSReleaseDateRaw                       *string
	BIOSReportedAt                           *time.Time
	SystemManufacturer, SystemModel          *string
	BaseboardManufacturer, BaseboardProduct  *string
	BaseboardReportedAt                      *time.Time
}

func readFirmwareCurrent(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) (firmwareCurrentRow, bool) {
	t.Helper()
	var r firmwareCurrentRow
	err := tx.QueryRow(ctx, `SELECT collection_status, errors, observation_id, reported_at,
			bios_status, system_status, baseboard_status,
			bios_manufacturer, bios_version, smbios_version, bios_release_date, bios_release_date_raw, bios_reported_at,
			system_manufacturer, system_model, baseboard_manufacturer, baseboard_product, baseboard_reported_at
		FROM device_firmware_current WHERE device_id = $1::uuid`, deviceID).Scan(
		&r.CollectionStatus, &r.Errors, &r.ObservationID, &r.ReportedAt,
		&r.BIOSStatus, &r.SystemStatus, &r.BaseboardStat,
		&r.BIOSManufacturer, &r.BIOSVersion, &r.SMBIOSVer, &r.BIOSReleaseDate, &r.BIOSReleaseDateRaw, &r.BIOSReportedAt,
		&r.SystemManufacturer, &r.SystemModel, &r.BaseboardManufacturer, &r.BaseboardProduct, &r.BaseboardReportedAt)
	if err == pgx.ErrNoRows {
		return r, false
	}
	if err != nil {
		t.Fatalf("read device_firmware_current: %v", err)
	}
	return r, true
}

func countFirmwareObservations(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_firmware_observations WHERE device_id = $1::uuid`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFirmwareIngestAbsentIsNotReported(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)

	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, time.Now()), deviceID, nil, time.Time{}, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if n := countFirmwareObservations(t, ctx, tx, deviceID); n != 0 {
		t.Fatalf("observations = %d, want 0", n)
	}
	if _, ok := readFirmwareCurrent(t, ctx, tx, deviceID); ok {
		t.Fatal("an absent block created a projection row: not reported must stay distinguishable")
	}
}

func TestFirmwareIngestCompleteThenUnavailableThenPartial(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)
	log := slog.Default()

	t0 := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Microsecond)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	// 1. complete: observation + projection with every value.
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t0), deviceID,
		firmwareFromFixture(t, "with-firmware-complete-windows.json"), t0.Add(-time.Minute), log); err != nil {
		t.Fatal(err)
	}
	cur, ok := readFirmwareCurrent(t, ctx, tx, deviceID)
	if !ok {
		t.Fatal("no projection after a complete report")
	}
	if cur.CollectionStatus != "complete" || len(cur.Errors) != 0 {
		t.Fatalf("status = %q errors = %v", cur.CollectionStatus, cur.Errors)
	}
	if fwStr(cur.BIOSVersion) != "N3HET82W (1.54 )" || fwStr(cur.SMBIOSVer) != "3.2" ||
		cur.BIOSReleaseDate == nil || cur.BIOSReleaseDate.Format("2006-01-02") != "2023-05-12" ||
		fwStr(cur.SystemModel) != "20XW0026UK" || fwStr(cur.BaseboardProduct) != "20XW0026UK" {
		t.Fatalf("complete projection = %+v", cur)
	}
	if fwStr(cur.BIOSStatus) != "complete" || !cur.BIOSReportedAt.Equal(t0) {
		t.Fatalf("bios status/reported_at = %s %v", fwStr(cur.BIOSStatus), cur.BIOSReportedAt)
	}
	firstObservation := cur.ObservationID

	// 2. unavailable: stored, and the newest status says so, but it never
	// blanks the values an earlier report read.
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t1), deviceID,
		firmwareFromFixture(t, "with-firmware-unavailable-windows.json"), t1, log); err != nil {
		t.Fatal(err)
	}
	cur, _ = readFirmwareCurrent(t, ctx, tx, deviceID)
	if cur.CollectionStatus != "unavailable" || !cur.ReportedAt.Equal(t1) || cur.ObservationID == firstObservation {
		t.Fatalf("after unavailable: status %q reported_at %v obs %d", cur.CollectionStatus, cur.ReportedAt, cur.ObservationID)
	}
	if strings.Join(cur.Errors, ",") != "bios_query_failed,system_query_failed,baseboard_query_failed" {
		t.Fatalf("errors = %v", cur.Errors)
	}
	if fwStr(cur.BIOSVersion) != "N3HET82W (1.54 )" || fwStr(cur.BIOSStatus) != "complete" || !cur.BIOSReportedAt.Equal(t0) {
		t.Fatalf("unavailable blanked or restamped stored values: %+v", cur)
	}

	// 3. partial: bios partial (date unparseable, raw kept), system
	// complete, baseboard unavailable. The bios values read replace the
	// stored ones, the release date moves as one unit (the old parsed date
	// does not survive beside the new raw one), and the baseboard keeps its
	// stored values and timestamp.
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t2), deviceID,
		firmwareFromFixture(t, "with-firmware-partial-windows.json"), t2, log); err != nil {
		t.Fatal(err)
	}
	cur, _ = readFirmwareCurrent(t, ctx, tx, deviceID)
	if cur.CollectionStatus != "partial" {
		t.Fatalf("status = %q", cur.CollectionStatus)
	}
	if fwStr(cur.BIOSStatus) != "partial" || !cur.BIOSReportedAt.Equal(t2) {
		t.Fatalf("bios status/reported_at = %s %v", fwStr(cur.BIOSStatus), cur.BIOSReportedAt)
	}
	if cur.BIOSReleaseDate != nil || fwStr(cur.BIOSReleaseDateRaw) != "20230230000000.000000+000" {
		t.Fatalf("release date = %v raw %s", cur.BIOSReleaseDate, fwStr(cur.BIOSReleaseDateRaw))
	}
	if fwStr(cur.BIOSVersion) != "N3HET82W (1.54 )" {
		t.Fatalf("bios version = %s", fwStr(cur.BIOSVersion))
	}
	if fwStr(cur.BaseboardStat) != "complete" || fwStr(cur.BaseboardProduct) != "20XW0026UK" || !cur.BaseboardReportedAt.Equal(t0) {
		t.Fatalf("unavailable baseboard section overwrote stored values: %s %s %v",
			fwStr(cur.BaseboardStat), fwStr(cur.BaseboardProduct), cur.BaseboardReportedAt)
	}

	if n := countFirmwareObservations(t, ctx, tx, deviceID); n != 3 {
		t.Fatalf("observations = %d, want 3", n)
	}
}

func TestFirmwareIngestPartialSectionFillsInWithoutBlanking(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)
	log := slog.Default()
	t0 := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)

	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t0), deviceID,
		firmwareFromFixture(t, "with-firmware-complete-windows.json"), t0, log); err != nil {
		t.Fatal(err)
	}
	// A partial system section that could read the manufacturer but not the
	// model: the stored model stays.
	partial := firmwareFromFixture(t, "with-firmware-complete-windows.json")
	partial.CollectionStatus = "partial"
	partial.Errors = []string{"system_property_failed"}
	newMaker := "Lenovo Group"
	partial.System = &firmwareSystemPart{CollectionStatus: "partial", Manufacturer: &newMaker}
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t0.Add(time.Hour)), deviceID, partial, t0, log); err != nil {
		t.Fatal(err)
	}
	cur, _ := readFirmwareCurrent(t, ctx, tx, deviceID)
	if fwStr(cur.SystemManufacturer) != "Lenovo Group" || fwStr(cur.SystemModel) != "20XW0026UK" || fwStr(cur.SystemStatus) != "partial" {
		t.Fatalf("system = %s / %s / %s", fwStr(cur.SystemManufacturer), fwStr(cur.SystemModel), fwStr(cur.SystemStatus))
	}

	// A complete section replaces in full, nulls included.
	complete := firmwareFromFixture(t, "with-firmware-complete-windows.json")
	complete.System = &firmwareSystemPart{CollectionStatus: "complete", Manufacturer: &newMaker}
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, t0.Add(2*time.Hour)), deviceID, complete, t0, log); err != nil {
		t.Fatal(err)
	}
	cur, _ = readFirmwareCurrent(t, ctx, tx, deviceID)
	if cur.SystemModel != nil || fwStr(cur.SystemStatus) != "complete" {
		t.Fatalf("complete section did not replace: model %s status %s", fwStr(cur.SystemModel), fwStr(cur.SystemStatus))
	}
}

func TestFirmwareIngestUnavailableFirstIsDistinctFromNotReported(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)

	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, time.Now()), deviceID,
		firmwareFromFixture(t, "with-firmware-unavailable-windows.json"), time.Now(), slog.Default()); err != nil {
		t.Fatal(err)
	}
	cur, ok := readFirmwareCurrent(t, ctx, tx, deviceID)
	if !ok {
		t.Fatal("an unavailable report left no projection row: it would read as not reported")
	}
	if cur.CollectionStatus != "unavailable" || cur.BIOSStatus != nil || cur.SystemStatus != nil || cur.BaseboardStat != nil ||
		cur.BIOSVersion != nil {
		t.Fatalf("unavailable-first projection = %+v", cur)
	}
}

func TestFirmwareIngestOlderReplayNeverOverwritesNewer(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)
	log := slog.Default()
	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-time.Hour)

	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, newer), deviceID,
		firmwareFromFixture(t, "with-firmware-unavailable-windows.json"), newer, log); err != nil {
		t.Fatal(err)
	}
	if err := upsertFirmware(ctx, tx, nextFirmwareRow(tenantID, older), deviceID,
		firmwareFromFixture(t, "with-firmware-complete-windows.json"), older, log); err != nil {
		t.Fatal(err)
	}
	cur, _ := readFirmwareCurrent(t, ctx, tx, deviceID)
	if cur.CollectionStatus != "unavailable" || !cur.ReportedAt.Equal(newer) || cur.BIOSVersion != nil {
		t.Fatalf("older replay moved the projection: %+v", cur)
	}
	// The older report is still evidence and is kept.
	if n := countFirmwareObservations(t, ctx, tx, deviceID); n != 2 {
		t.Fatalf("observations = %d, want 2", n)
	}
}

func TestFirmwareIngestReextractionIsIdempotentAndObservationsImmutable(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, deviceID := firmwareTestDevice(t, ctx, tx)
	row := nextFirmwareRow(tenantID, time.Now())
	fw := firmwareFromFixture(t, "with-firmware-complete-windows.json")

	for i := 0; i < 2; i++ {
		if err := upsertFirmware(ctx, tx, row, deviceID, fw, time.Now(), slog.Default()); err != nil {
			t.Fatalf("extraction %d: %v", i+1, err)
		}
	}
	if n := countFirmwareObservations(t, ctx, tx, deviceID); n != 1 {
		t.Fatalf("observations after re-extraction = %d, want 1", n)
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT imm`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE device_firmware_observations SET bios_version = 'forged' WHERE device_id = $1::uuid`, deviceID)
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("UPDATE on an observation: err = %v, want the immutability trigger", err)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT imm`); err != nil {
		t.Fatal(err)
	}
}

// End to end through processRow: the Windows agent's complete payload lands
// in both tables; a payload with no block leaves them alone.
func TestFirmwareProcessRowEndToEnd(t *testing.T) {
	pool := firmwareTestPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2262-firmware-e2e', '\x00', '\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE tenant_id = $1::uuid`, tenantID)
	})

	body := fixtureWith(t, "with-firmware-complete-windows.json", func(m map[string]any) {
		dev := m["device"].(map[string]any)
		dev["serial"] = "PAT2262E2E"
		dev["hw_uuid"] = "22622262-0000-4000-8000-" + tenantID[:12]
		m["tenant_id"] = tenantID
	})
	if err := ValidatePayload(body); err != nil {
		t.Fatal(err)
	}
	receivedAt := time.Now().UTC().Truncate(time.Microsecond)
	var rawID int64
	if err := pool.QueryRow(ctx, `INSERT INTO raw_payloads (tenant_id, received_at, body)
		VALUES ($1::uuid, $2, $3::jsonb) RETURNING id`, tenantID, receivedAt, body).Scan(&rawID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Pool: pool, BatchSize: 1}
	if err := w.processRow(ctx, claimedRow{ID: rawID, ReceivedAt: receivedAt, TenantID: tenantID, Body: body}, slog.Default()); err != nil {
		t.Fatalf("processRow: %v", err)
	}

	var deviceID, status, version string
	var obsRawID int64
	if err := pool.QueryRow(ctx, `SELECT c.device_id::text, c.collection_status, c.bios_version, o.raw_payload_id
		FROM device_firmware_current c JOIN device_firmware_observations o ON o.id = c.observation_id
		WHERE c.tenant_id = $1::uuid`, tenantID).Scan(&deviceID, &status, &version, &obsRawID); err != nil {
		t.Fatalf("projection after processRow: %v", err)
	}
	if status != "complete" || version != "N3HET82W (1.54 )" || obsRawID != rawID {
		t.Fatalf("projection = %s %s raw %d (want raw %d)", status, version, obsRawID, rawID)
	}
}

func fwStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
