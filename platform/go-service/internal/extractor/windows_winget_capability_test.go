package extractor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWindowsWingetInventoryCapabilityPersistsAndLatestLegacyScanClears(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var tenantID string
	if err := tx.QueryRow(ctx, `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES('pat1399-winget-capability','\x00','\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	base := &payload{SchemaVersion: 3, Platform: "windows", Agent: "patched-collect-win", AgentVersion: "pat-1401-test", TenantID: tenantID,
		Device: devicePart{Serial: "PAT1399-WINGET-CAP", Hostname: "winget-capability"}, OS: osPart{Name: "Windows", Version: "11"},
		InventoryCapabilities: &inventoryCapabilitiesPart{SchemaVersion: 1, WindowsWingetInventoryComplete: true},
		Apps:                  []appPart{{Name: "Firefox", Version: "1.0", Identifier: "mozilla.firefox", IdentifierKind: "winget", SignedBy: "Mozilla Corporation"}}}
	deviceID, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := upsertApps(ctx, tx, deviceID, time.Now(), base.Apps, nil, "windows", appsSignalComplete, "", nil, legacyUserHold{}); err != nil {
		t.Fatal(err)
	}
	var complete bool
	var schema int
	var kind string
	if err := tx.QueryRow(ctx, `SELECT d.windows_winget_inventory_complete,COALESCE(d.windows_winget_inventory_schema,0)::int,a.identifier_kind FROM devices d JOIN device_apps a ON a.device_id=d.id WHERE d.id=$1::uuid`, deviceID).Scan(&complete, &schema, &kind); err != nil || !complete || schema != 1 || kind != "winget" {
		t.Fatalf("persisted capability complete=%t schema=%d kind=%q err=%v", complete, schema, kind, err)
	}
	legacy := *base
	legacy.InventoryCapabilities = nil
	if _, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), &legacy, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT windows_winget_inventory_complete,COALESCE(windows_winget_inventory_schema,0)::int FROM devices WHERE id=$1::uuid`, deviceID).Scan(&complete, &schema); err != nil || complete || schema != 0 {
		t.Fatalf("latest legacy scan retained stale completeness complete=%t schema=%d err=%v", complete, schema, err)
	}
	unsupported := *base
	unsupported.InventoryCapabilities = &inventoryCapabilitiesPart{SchemaVersion: 2, WindowsWingetInventoryComplete: false}
	if _, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), &unsupported, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT windows_winget_inventory_complete,COALESCE(windows_winget_inventory_schema,0)::int FROM devices WHERE id=$1::uuid`, deviceID).Scan(&complete, &schema); err != nil || complete || schema != 0 {
		t.Fatalf("unsupported false capability gained authority complete=%t schema=%d err=%v", complete, schema, err)
	}

	malformed := *base
	malformed.Apps = []appPart{{Name: "Broken Winget identity", Version: "1.0", Identifier: "bad..identifier", IdentifierKind: "winget"},
		{Name: "Native inventory remains", Version: "2.0", Identifier: "{PRODUCT-CODE}", IdentifierKind: "native"}}
	if _, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), &malformed, nil); err != nil {
		t.Fatalf("malformed per-app Winget ID rejected unrelated inventory: %v", err)
	}
	if _, _, err := upsertApps(ctx, tx, deviceID, time.Now(), malformed.Apps, nil, "windows", appsSignalComplete, "", nil, legacyUserHold{}); err != nil {
		t.Fatalf("malformed per-app Winget ID rejected app snapshot: %v", err)
	}
	var malformedKind *string
	if err := tx.QueryRow(ctx, `SELECT d.windows_winget_inventory_complete,a.identifier_kind FROM devices d JOIN device_apps a ON a.device_id=d.id WHERE d.id=$1::uuid AND a.identifier='bad..identifier'`, deviceID).Scan(&complete, &malformedKind); err != nil || complete || malformedKind != nil {
		t.Fatalf("malformed identity retained absence/app authority complete=%t kind=%v err=%v", complete, malformedKind, err)
	}
}
