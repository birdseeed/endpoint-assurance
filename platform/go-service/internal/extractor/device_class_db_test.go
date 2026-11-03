package extractor

// TestDeviceClassIngest is a DB round-trip test for PAT-1960: upsertDevice
// must write device_class/installation_type/os_caption from the payload's
// top-level fields when present, default to 'unknown' when absent (never
// guessed), never downgrade an already-known classification just because a
// later ingest omits the field or reports the literal "unknown", and reject
// nothing an agent doing exactly the right thing might send. It requires a
// real Postgres instance with all migrations applied (including
// 0158_device_class), pointed to by TEST_DATABASE_URL. All writes are
// rolled back at the end.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestDeviceClassIngest -v

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeviceClassIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping device_class DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat1960-device-class-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	// basePayload builds a payload with device_class/installation_type/
	// os_caption at the TOP LEVEL — the real PAT-1959 wire shape (see
	// payload_wire_shape_test.go for the regression pinning this).
	basePayload := func(serial, deviceClass, installationType, osCaption string) *payload {
		return &payload{
			SchemaVersion:    3,
			Platform:         "windows",
			Agent:            "patched-collect-win",
			AgentVersion:     "pat-1960-test",
			TenantID:         tenantID,
			DeviceClass:      deviceClass,
			InstallationType: installationType,
			OSCaption:        osCaption,
			Device: devicePart{
				Serial:   serial,
				Hostname: "device-class-host",
				HWModel:  "Dell OptiPlex",
				Arch:     "x86_64",
			},
			OS: osPart{Name: "Windows", Version: "10.0.20348", Build: "20348"},
		}
	}

	fetchDeviceClass := func(deviceID string) (class string, installType, caption *string) {
		t.Helper()
		if err := tx.QueryRow(ctx, `
			SELECT device_class, installation_type, os_caption FROM devices WHERE id = $1::uuid
		`, deviceID).Scan(&class, &installType, &caption); err != nil {
			t.Fatalf("select device_class fields: %v", err)
		}
		return class, installType, caption
	}

	// ── First ingest: no device_class (older/pre-PAT-1959 agent) → 'unknown' ──
	p1 := basePayload("PAT1960-DC-001", "", "", "")
	deviceID, gotClass, err := upsertDevice(ctx, tx, tenantID, time.Now(), p1, nil)
	if err != nil {
		t.Fatalf("upsertDevice (absent device_class): %v", err)
	}
	if gotClass != "unknown" {
		t.Errorf("upsertDevice returned device_class = %q, want \"unknown\"", gotClass)
	}
	class, installType, caption := fetchDeviceClass(deviceID)
	if class != "unknown" {
		t.Errorf("devices.device_class = %q, want \"unknown\"", class)
	}
	if installType != nil || caption != nil {
		t.Errorf("installation_type/os_caption = %v/%v, want both NULL", installType, caption)
	}

	// ── Second ingest: valid server classification → columns populated ────────
	p2 := basePayload("PAT1960-DC-001", "server", "Server", "Microsoft Windows Server 2022 Standard")
	deviceID2, gotClass2, err := upsertDevice(ctx, tx, tenantID, time.Now(), p2, nil)
	if err != nil {
		t.Fatalf("upsertDevice (valid device_class): %v", err)
	}
	if deviceID2 != deviceID {
		t.Fatalf("device id changed across re-ingest: %s vs %s", deviceID, deviceID2)
	}
	if gotClass2 != "server" {
		t.Errorf("upsertDevice returned device_class = %q, want \"server\"", gotClass2)
	}
	class, installType, caption = fetchDeviceClass(deviceID)
	if class != "server" {
		t.Errorf("devices.device_class after classified ingest = %q, want \"server\"", class)
	}
	if installType == nil || *installType != "Server" {
		t.Errorf("installation_type = %v, want \"Server\"", installType)
	}
	if caption == nil || *caption != "Microsoft Windows Server 2022 Standard" {
		t.Errorf("os_caption = %v, want the Server 2022 caption", caption)
	}

	// ── Third ingest: omits device_class again (degraded/older agent) ─────────
	// Must NOT downgrade the known "server" classification back to "unknown" —
	// the whole point of deviceClassGiven in upsertDevice.
	p3 := basePayload("PAT1960-DC-001", "", "", "")
	deviceID3, gotClass3, err := upsertDevice(ctx, tx, tenantID, time.Now(), p3, nil)
	if err != nil {
		t.Fatalf("upsertDevice (omitted on later check-in): %v", err)
	}
	if deviceID3 != deviceID {
		t.Fatalf("device id changed across re-ingest: %s vs %s", deviceID, deviceID3)
	}
	if gotClass3 != "server" {
		t.Errorf("upsertDevice returned device_class = %q on omitted check-in, want preserved \"server\"", gotClass3)
	}
	class, installType, caption = fetchDeviceClass(deviceID)
	if class != "server" {
		t.Errorf("devices.device_class after omitted-field re-ingest = %q, want preserved \"server\" (must not downgrade to unknown)", class)
	}
	// installation_type/os_caption use the ordinary COALESCE-preserve pattern
	// (same as agent_version etc.) — also expected to survive an omitted field.
	if installType == nil || *installType != "Server" {
		t.Errorf("installation_type after omitted-field re-ingest = %v, want preserved \"Server\"", installType)
	}

	// ── Fourth ingest: agent reports the literal "unknown" (PAT-1959's "I
	// genuinely couldn't tell this run" signal, not an omission) — must
	// ALSO not downgrade the known "server" classification. Same invariant
	// as the omitted-field case, different wire shape.
	p4 := basePayload("PAT1960-DC-001", "unknown", "", "")
	deviceID4, gotClass4, err := upsertDevice(ctx, tx, tenantID, time.Now(), p4, nil)
	if err != nil {
		t.Fatalf("upsertDevice (literal \"unknown\" report): %v", err)
	}
	if deviceID4 != deviceID {
		t.Fatalf("device id changed across re-ingest: %s vs %s", deviceID, deviceID4)
	}
	if gotClass4 != "server" {
		t.Errorf("upsertDevice returned device_class = %q on literal-unknown report, want preserved \"server\"", gotClass4)
	}
	class, _, _ = fetchDeviceClass(deviceID)
	if class != "server" {
		t.Errorf("devices.device_class after literal-unknown re-ingest = %q, want preserved \"server\"", class)
	}

	// ── Rejected value: out-of-enum device_class resolves to "unknown", never errors ──
	p5 := basePayload("PAT1960-DC-002", "laptop", "", "")
	_, gotClass5, err := upsertDevice(ctx, tx, tenantID, time.Now(), p5, nil)
	if err != nil {
		t.Fatalf("upsertDevice must not error on an out-of-enum device_class: %v", err)
	}
	if gotClass5 != "unknown" {
		t.Errorf("upsertDevice with out-of-enum device_class returned %q, want \"unknown\"", gotClass5)
	}
}
