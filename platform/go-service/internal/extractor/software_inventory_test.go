package extractor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeriveObservedSoftwareIdentityDoesNotCollapseVendorProducts(t *testing.T) {
	word := deriveObservedSoftwareIdentity("macos", appPart{
		Name: "Microsoft Word", Identifier: "com.microsoft.Word", TeamID: "UBF8T346G9",
	})
	edge := deriveObservedSoftwareIdentity("macos", appPart{
		Name: "Microsoft Edge", Identifier: "com.microsoft.edgemac", TeamID: "UBF8T346G9",
	})
	if word.Kind != "macos_bundle_team" || word.Confidence != "exact" {
		t.Fatalf("macOS identity = %#v, want exact bundle plus Team ID", word)
	}
	if word.Fingerprint == edge.Fingerprint {
		t.Fatal("two products signed by one Team ID collapsed to one identity")
	}
}

func TestDeriveObservedSoftwareIdentitySeparatesSameNameByPublisher(t *testing.T) {
	one := deriveObservedSoftwareIdentity("windows", appPart{
		Name: "Agent", Identifier: "{PRODUCT-ONE}", Publisher: "Vendor One Ltd",
	})
	two := deriveObservedSoftwareIdentity("windows", appPart{
		Name: "Agent", Identifier: "{PRODUCT-ONE}", Publisher: "Vendor Two Ltd",
	})
	if one.Fingerprint == two.Fingerprint {
		t.Fatal("same Windows name and identifier from different publishers collapsed")
	}
}

func TestWindowsReleaseIdentifierIsNotAutomaticProductIdentity(t *testing.T) {
	v1 := deriveObservedSoftwareIdentity("windows", appPart{
		Name: "Example", Identifier: "{MSI-PRODUCT-CODE-V1}", Publisher: "Example Ltd",
	})
	v2 := deriveObservedSoftwareIdentity("windows", appPart{
		Name: "Example", Identifier: "{MSI-PRODUCT-CODE-V2}", Publisher: "Example Ltd",
	})
	if v1.Confidence == "exact" || v1.Confidence == "high" || v2.Confidence == "exact" || v2.Confidence == "high" {
		t.Fatal("release-specific Windows native identifier gained automatic product authority")
	}
	if v1.Fingerprint == v2.Fingerprint {
		t.Fatal("different native installation identities should remain distinct observations until curated")
	}
}

// TestDeriveObservedSoftwareIdentityFallsBackWhenNameEmpty is the regression
// test for the PAT-1461 review P1 finding: software_observations.observed_name
// is NOT NULL, but the extractor used to pass app.Name straight through. A
// malformed or drifted collector payload with an empty name would then throw
// a raw DB constraint violation on insert and permanently stall that payload
// (extraction_attempts increments with no way to recover). The fix mirrors
// the device_apps precedent in upsert.go: fall back through path, identifier,
// then a sentinel, so the evidence is still recorded rather than dropped.
func TestDeriveObservedSoftwareIdentityFallsBackWhenNameEmpty(t *testing.T) {
	toPath := deriveObservedSoftwareIdentity("macos", appPart{
		Name: "", Path: "/Applications/Mystery.app", Identifier: "com.example.mystery",
	})
	if toPath.ObservedName == "" {
		t.Fatal("ObservedName must never be empty even when the collector sent no name")
	}
	if toPath.ObservedName != "/Applications/Mystery.app" {
		t.Fatalf("ObservedName = %q, want fallback to path", toPath.ObservedName)
	}

	toIdentifier := deriveObservedSoftwareIdentity("macos", appPart{
		Name: "", Identifier: "com.example.mystery",
	})
	if toIdentifier.ObservedName != "com.example.mystery" {
		t.Fatalf("ObservedName = %q, want fallback to identifier", toIdentifier.ObservedName)
	}

	allEmpty := deriveObservedSoftwareIdentity("macos", appPart{Name: ""})
	if allEmpty.ObservedName == "" {
		t.Fatal("ObservedName must never be empty; expected the sentinel fallback")
	}
	if allEmpty.ObservedName != "unknown software" {
		t.Fatalf("ObservedName = %q, want sentinel fallback", allEmpty.ObservedName)
	}
}

func TestAuthoritativeSoftwareScopesArePlatformSpecific(t *testing.T) {
	if got := authoritativeSoftwareScopes(&payload{AppsPresent: true}, "macos"); len(got) != 1 || got[0] != "all_software" {
		t.Fatalf("macOS scopes = %v, want all_software", got)
	}
	if got := authoritativeSoftwareScopes(&payload{}, "macos"); len(got) != 0 {
		t.Fatalf("macOS payload without apps key gained authority: %v", got)
	}
	partialWindows := &payload{InventoryCapabilities: &inventoryCapabilitiesPart{
		SchemaVersion: 1, WindowsWingetInventoryComplete: false,
	}, AppsPresent: true}
	if got := authoritativeSoftwareScopes(partialWindows, "windows"); len(got) != 0 {
		t.Fatalf("partial Windows scopes = %v, want none", got)
	}
	completeWindows := &payload{
		AppsPresent:           true,
		InventoryCapabilities: &inventoryCapabilitiesPart{SchemaVersion: 1, WindowsWingetInventoryComplete: true},
		Apps: []appPart{
			{Name: "Firefox", Identifier: "Mozilla.Firefox", IdentifierKind: "winget"},
			{Name: "Native Tool", Identifier: "{PRODUCT-CODE}", IdentifierKind: "native"},
		},
	}
	if got := authoritativeSoftwareScopes(completeWindows, "windows"); len(got) != 1 || got[0] != "windows_winget" {
		t.Fatalf("complete Windows scopes = %v, want windows_winget", got)
	}
	completeWindows.Apps[1].IdentifierKind = ""
	if got := authoritativeSoftwareScopes(completeWindows, "windows"); len(got) != 0 {
		t.Fatalf("untyped Windows row retained absence authority: %v", got)
	}
}

func TestSoftwareInventoryPersistenceAndAbsenceAuthority(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	seedTenant := func(name string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
			VALUES($1,'\x00','\x00') RETURNING id::text
		`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	seedDevice := func(tenantID, osName, serial string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,$2,$3)
			RETURNING id::text
		`, tenantID, osName, serial).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	seedRaw := func(tenantID, deviceID string, received time.Time) claimedRow {
		t.Helper()
		var id int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
			VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
		`, tenantID, deviceID, received).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return claimedRow{ID: id, ReceivedAt: received, TenantID: tenantID}
	}
	seedProduct := func(key, name string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO software_products(canonical_key,canonical_name)
			VALUES($1,$2) RETURNING id::text
		`, key, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	seedAlias := func(productID, platform, kind, value, companion string) {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO software_product_aliases(
				product_id,platform,identity_kind,identity_value_normalized,
				companion_value_normalized,match_confidence,provenance
			) VALUES($1::uuid,$2,$3,$4,$5,'exact','reviewed')
		`, productID, platform, kind, value, companion); err != nil {
			t.Fatal(err)
		}
	}

	tenantID := seedTenant("pat1461-primary")
	otherTenantID := seedTenant("pat1461-other")
	macDeviceID := seedDevice(tenantID, "macOS", "PAT1461-MAC")
	wordProductID := seedProduct("microsoft-word-pat1461", "Microsoft Word")
	edgeProductID := seedProduct("microsoft-edge-pat1461", "Microsoft Edge")
	seedAlias(wordProductID, "macos", "macos_bundle_team", "com.microsoft.word", "UBF8T346G9")
	seedAlias(edgeProductID, "macos", "macos_bundle_team", "com.microsoft.edgemac", "UBF8T346G9")
	seedAlias(wordProductID, "windows", "windows_winget", "microsoft.office", "")

	t0 := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Microsecond)
	macPayload := &payload{
		SchemaVersion: 3, Platform: "macos", Agent: "pat1461", AgentVersion: "test",
		CollectedAt: t0.Format(time.RFC3339), AppsPresent: true,
		Apps: []appPart{
			{Name: "Microsoft Word", Version: "1", Identifier: "com.microsoft.Word", TeamID: "UBF8T346G9"},
			{Name: "Microsoft Edge", Version: "1", Identifier: "com.microsoft.edgemac", TeamID: "UBF8T346G9"},
		},
	}
	macRow1 := seedRaw(tenantID, macDeviceID, t0)
	if n, err := upsertSoftwareInventory(ctx, tx, macRow1, macDeviceID, macPayload, "macos"); err != nil || n != 2 {
		t.Fatalf("first macOS inventory: count=%d err=%v", n, err)
	}
	// Reprocessing the same immutable payload must reuse one run and two rows.
	if n, err := upsertSoftwareInventory(ctx, tx, macRow1, macDeviceID, macPayload, "macos"); err != nil || n != 2 {
		t.Fatalf("idempotent macOS inventory: count=%d err=%v", n, err)
	}
	var runs, observations, installations, resolved int
	if err := tx.QueryRow(ctx, `
		SELECT
		 (SELECT count(*) FROM software_inventory_runs WHERE device_id=$1::uuid),
		 (SELECT count(*) FROM software_observations WHERE device_id=$1::uuid),
		 (SELECT count(*) FROM software_installations WHERE device_id=$1::uuid),
		 (SELECT count(*) FROM software_installations WHERE device_id=$1::uuid AND product_id IS NOT NULL)
	`, macDeviceID).Scan(&runs, &observations, &installations, &resolved); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || observations != 2 || installations != 2 || resolved != 2 {
		t.Fatalf("idempotence/resolution counts runs=%d observations=%d installations=%d resolved=%d", runs, observations, installations, resolved)
	}
	immutableTx, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := immutableTx.Exec(ctx, `UPDATE software_observations SET observed_name='tampered' WHERE device_id=$1::uuid`, macDeviceID); err == nil {
		t.Fatal("immutable software observation update was accepted")
	}
	_ = immutableTx.Rollback(ctx)
	var distinctProducts int
	if err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT product_id) FROM software_installations WHERE device_id=$1::uuid
	`, macDeviceID).Scan(&distinctProducts); err != nil || distinctProducts != 2 {
		t.Fatalf("shared Team ID collapsed products: distinct=%d err=%v", distinctProducts, err)
	}

	macRow2 := seedRaw(tenantID, macDeviceID, t0.Add(time.Hour))
	macPayload.Apps = macPayload.Apps[:1]
	if _, err := upsertSoftwareInventory(ctx, tx, macRow2, macDeviceID, macPayload, "macos"); err != nil {
		t.Fatal(err)
	}
	var edgeRemoved bool
	if err := tx.QueryRow(ctx, `
		SELECT removed_at IS NOT NULL FROM software_installations
		WHERE device_id=$1::uuid AND product_id=$2::uuid
	`, macDeviceID, edgeProductID).Scan(&edgeRemoved); err != nil || !edgeRemoved {
		t.Fatalf("authoritative macOS absence did not close Edge: removed=%t err=%v", edgeRemoved, err)
	}

	windowsDeviceID := seedDevice(tenantID, "Windows", "PAT1461-WIN")
	winT0 := t0.Add(10 * time.Minute)
	windowsPayload := &payload{
		SchemaVersion: 3, Platform: "windows", Agent: "pat1461", AgentVersion: "test",
		CollectedAt:           winT0.Format(time.RFC3339),
		AppsPresent:           true,
		InventoryCapabilities: &inventoryCapabilitiesPart{SchemaVersion: 1, WindowsWingetInventoryComplete: false},
		Apps: []appPart{
			{Name: "Microsoft Office", Version: "1", Identifier: "Microsoft.Office", IdentifierKind: "winget"},
			{Name: "Native Agent", Version: "1", Identifier: "{NATIVE-1}", IdentifierKind: "native", Publisher: "Example Ltd"},
		},
	}
	if _, err := upsertSoftwareInventory(ctx, tx, seedRaw(tenantID, windowsDeviceID, winT0), windowsDeviceID, windowsPayload, "windows"); err != nil {
		t.Fatal(err)
	}
	// The explicit reviewed alias joins the Windows and macOS observations to
	// one product. The raw Winget evidence alone remained medium confidence.
	var crossPlatformProduct string
	if err := tx.QueryRow(ctx, `
		SELECT product_id::text FROM software_installations
		WHERE device_id=$1::uuid AND identity_kind='windows_winget'
	`, windowsDeviceID).Scan(&crossPlatformProduct); err != nil || crossPlatformProduct != wordProductID {
		t.Fatalf("cross-platform curated alias product=%q want=%q err=%v", crossPlatformProduct, wordProductID, err)
	}

	windowsPayload.Apps = windowsPayload.Apps[1:]
	winT1 := winT0.Add(time.Hour)
	if _, err := upsertSoftwareInventory(ctx, tx, seedRaw(tenantID, windowsDeviceID, winT1), windowsDeviceID, windowsPayload, "windows"); err != nil {
		t.Fatal(err)
	}
	var wingetRemoved bool
	if err := tx.QueryRow(ctx, `
		SELECT removed_at IS NOT NULL FROM software_installations
		WHERE device_id=$1::uuid AND identity_kind='windows_winget'
	`, windowsDeviceID).Scan(&wingetRemoved); err != nil || wingetRemoved {
		t.Fatalf("incomplete Windows scan closed missing Winget app: removed=%t err=%v", wingetRemoved, err)
	}

	windowsPayload.InventoryCapabilities.WindowsWingetInventoryComplete = true
	winT2 := winT1.Add(time.Hour)
	if _, err := upsertSoftwareInventory(ctx, tx, seedRaw(tenantID, windowsDeviceID, winT2), windowsDeviceID, windowsPayload, "windows"); err != nil {
		t.Fatal(err)
	}
	var nativeRemoved bool
	if err := tx.QueryRow(ctx, `
		SELECT
		 bool_or(removed_at IS NOT NULL) FILTER (WHERE identity_kind='windows_winget'),
		 bool_or(removed_at IS NOT NULL) FILTER (WHERE identity_kind='windows_native_publisher')
		FROM software_installations WHERE device_id=$1::uuid
	`, windowsDeviceID).Scan(&wingetRemoved, &nativeRemoved); err != nil {
		t.Fatal(err)
	}
	if !wingetRemoved || nativeRemoved {
		t.Fatalf("scoped Windows absence wrong: winget_removed=%t native_removed=%t", wingetRemoved, nativeRemoved)
	}

	// The composite device/tenant foreign key rejects a run that attempts to
	// attach another tenant's evidence to this device.
	otherDeviceID := seedDevice(otherTenantID, "macOS", "PAT1461-OTHER")
	otherRow := seedRaw(otherTenantID, otherDeviceID, t0.Add(2*time.Hour))
	isolationTx, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherRow.TenantID = otherTenantID
	if _, err := upsertSoftwareInventory(ctx, isolationTx, otherRow, macDeviceID, macPayload, "macos"); err == nil {
		t.Fatal("cross-tenant software inventory run was accepted")
	}
	_ = isolationTx.Rollback(ctx)
}

// TestSoftwareInventoryPersistsObservationWithEmptyName is the DB-backed
// regression test for the PAT-1461 review P1 finding: software_observations.
// observed_name is NOT NULL. A malformed or schema-drifted collector payload
// with an empty app name must not throw a raw NOT NULL violation (which would
// abort the whole payload's extraction and increment extraction_attempts with
// no path to recovery) -- the observation is still real evidence and must be
// persisted, using the same identifier/path fallback device_apps already
// relies on.
func TestSoftwareInventoryPersistsObservationWithEmptyName(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat1461-empty-name','\x00','\x00') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,'macOS','PAT1461-EMPTY-NAME')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	received := time.Now().UTC().Truncate(time.Microsecond)
	var rawID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
		VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
	`, tenantID, deviceID, received).Scan(&rawID); err != nil {
		t.Fatal(err)
	}
	row := claimedRow{ID: rawID, ReceivedAt: received, TenantID: tenantID}

	p := &payload{
		SchemaVersion: 3, Platform: "macos", Agent: "pat1461", AgentVersion: "test",
		CollectedAt: received.Format(time.RFC3339), AppsPresent: true,
		Apps: []appPart{
			// No Name, no Identifier, no Path: the malformed/schema-drift case
			// the review flagged. Must persist, not error.
			{Version: "1"},
		},
	}
	n, err := upsertSoftwareInventory(ctx, tx, row, deviceID, p, "macos")
	if err != nil {
		t.Fatalf("upsert with empty app name errored (expected no NOT NULL violation): %v", err)
	}
	if n != 1 {
		t.Fatalf("wrote %d observations, want 1", n)
	}

	var observedName string
	if err := tx.QueryRow(ctx, `
		SELECT observed_name FROM software_observations WHERE device_id=$1::uuid
	`, deviceID).Scan(&observedName); err != nil {
		t.Fatal(err)
	}
	if observedName == "" {
		t.Fatal("observed_name persisted as empty string; evidence should carry a non-empty fallback")
	}
	if observedName != "unknown software" {
		t.Fatalf("observed_name = %q, want the sentinel fallback", observedName)
	}
}

// TestNotarizedAbsentPersistsAsNull is the DB-backed regression test for
// PAT-1828: a payload app entry that never reports "notarized" at all (as
// every Windows payload does not, since Windows has no codesign concept)
// must leave device_apps.notarized and software_observations.observed_notarized
// as genuine SQL NULL, not the Go zero-value false. A stored false reads as
// "we checked and it is confirmed not notarized", which is a different claim
// than "this platform/collector never reported a signal" and would be an
// absence pretending to be evidence (see the Hard Constraints in AGENTS.md).
func TestNotarizedAbsentPersistsAsNull(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat1828-notarized-null','\x00','\x00') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,'Windows','PAT1828-WIN')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	received := time.Now().UTC().Truncate(time.Microsecond)
	var rawID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
		VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
	`, tenantID, deviceID, received).Scan(&rawID); err != nil {
		t.Fatal(err)
	}
	row := claimedRow{ID: rawID, ReceivedAt: received, TenantID: tenantID}

	// This app entry is built directly (not via json.Unmarshal), but it
	// exercises exactly what an unmarshalled Windows payload produces: no
	// "notarized" key in the source JSON leaves the *bool field nil, distinct
	// from an explicit `"notarized": false`.
	apps := []appPart{
		{Name: "Notarized-Absent App", Version: "1", Identifier: "PAT1828.NotarizedAbsent", IdentifierKind: "native"},
	}
	p := &payload{
		SchemaVersion: 3, Platform: "windows", Agent: "pat1828", AgentVersion: "test",
		CollectedAt: received.Format(time.RFC3339), AppsPresent: true,
		Apps: apps,
	}

	if _, _, err := upsertApps(ctx, tx, deviceID, time.Now(), apps, nil, "windows", appsSignalComplete, "", nil, legacyUserHold{}); err != nil {
		t.Fatalf("upsertApps: %v", err)
	}
	var deviceAppNotarized *bool
	if err := tx.QueryRow(ctx, `
		SELECT notarized FROM device_apps WHERE device_id=$1::uuid AND identifier=$2
	`, deviceID, apps[0].Identifier).Scan(&deviceAppNotarized); err != nil {
		t.Fatal(err)
	}
	if deviceAppNotarized != nil {
		t.Fatalf("device_apps.notarized = %v, want NULL for a payload that never reported the field", *deviceAppNotarized)
	}

	if _, err := upsertSoftwareInventory(ctx, tx, row, deviceID, p, "windows"); err != nil {
		t.Fatal(err)
	}
	var observedNotarized *bool
	if err := tx.QueryRow(ctx, `
		SELECT observed_notarized FROM software_observations WHERE device_id=$1::uuid
	`, deviceID).Scan(&observedNotarized); err != nil {
		t.Fatal(err)
	}
	if observedNotarized != nil {
		t.Fatalf("software_observations.observed_notarized = %v, want NULL for a payload that never reported the field", *observedNotarized)
	}
}

// PAT-2112: a macOS app's signing_status and notarization_status land on its
// immutable observation; a value outside the enum, and the same keys on a
// Windows report, are stored as not reported (NULL), never refused.
func TestSigningStatusesPersistOnMacOSOnly(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat2112-signing-status','\x00','\x00') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	store := func(platform, os, serial string, apps []appPart) string {
		t.Helper()
		var deviceID string
		if err := tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,$2,$3) RETURNING id::text`,
			tenantID, os, serial).Scan(&deviceID); err != nil {
			t.Fatal(err)
		}
		received := time.Now().UTC().Truncate(time.Microsecond)
		var rawID int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
			VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
		`, tenantID, deviceID, received).Scan(&rawID); err != nil {
			t.Fatal(err)
		}
		p := &payload{SchemaVersion: 3, Platform: platform, Agent: "pat2112", AgentVersion: "test",
			CollectedAt: received.Format(time.RFC3339), AppsPresent: true, Apps: apps}
		if _, err := upsertSoftwareInventory(ctx, tx, claimedRow{ID: rawID, ReceivedAt: received, TenantID: tenantID},
			deviceID, p, platform); err != nil {
			t.Fatal(err)
		}
		return deviceID
	}
	type stored struct{ signing, notarization *string }
	read := func(deviceID string) map[string]stored {
		t.Helper()
		rows, err := tx.Query(ctx, `SELECT observed_name, observed_signing_status, observed_notarization_status
			FROM software_observations WHERE device_id=$1::uuid`, deviceID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]stored{}
		for rows.Next() {
			var name string
			var st stored
			if err := rows.Scan(&name, &st.signing, &st.notarization); err != nil {
				t.Fatal(err)
			}
			out[name] = st
		}
		return out
	}
	str := func(p *string) string {
		if p == nil {
			return "NULL"
		}
		return *p
	}

	mac := store("macos", "macOS 26.0", "PAT2112-MAC", []appPart{
		{Name: "Signed", Version: "1", Identifier: "com.pat2112.signed", SigningStatus: "signed", NotarizationStatus: "notarized"},
		{Name: "Adhoc", Version: "1", Identifier: "com.pat2112.adhoc", SigningStatus: "adhoc", NotarizationStatus: "not_notarized"},
		{Name: "Unsigned", Version: "1", Identifier: "com.pat2112.unsigned", SigningStatus: "unsigned", NotarizationStatus: "not_notarized"},
		{Name: "Error", Version: "1", Identifier: "com.pat2112.error", SigningStatus: "error", NotarizationStatus: "unknown"},
		// PAT-2117: two more macOS signing_status values.
		{Name: "Untrusted", Version: "1", Identifier: "com.pat2117.untrusted", SigningStatus: "untrusted", NotarizationStatus: "not_notarized"},
		{Name: "Invalid", Version: "1", Identifier: "com.pat2117.invalid", SigningStatus: "invalid", NotarizationStatus: "unknown"},
		{Name: "Future", Version: "1", Identifier: "com.pat2112.future", SigningStatus: "Signed", NotarizationStatus: "revoked"},
		{Name: "Legacy", Version: "1", Identifier: "com.pat2112.legacy"},
	})
	got := read(mac)
	for name, want := range map[string][2]string{
		"Signed":    {"signed", "notarized"},
		"Adhoc":     {"adhoc", "not_notarized"},
		"Unsigned":  {"unsigned", "not_notarized"},
		"Error":     {"error", "unknown"},
		"Untrusted": {"untrusted", "not_notarized"},
		"Invalid":   {"invalid", "unknown"},
		"Future":    {"NULL", "NULL"},
		"Legacy":    {"NULL", "NULL"},
	} {
		st, ok := got[name]
		if !ok {
			t.Fatalf("%s: no observation", name)
		}
		if str(st.signing) != want[0] || str(st.notarization) != want[1] {
			t.Errorf("%s: stored %s/%s, want %s/%s", name, str(st.signing), str(st.notarization), want[0], want[1])
		}
	}

	win := store("windows", "Windows 11", "PAT2112-WIN", []appPart{
		{Name: "WinApp", Version: "1", Identifier: "PAT2112.WinApp", IdentifierKind: "native", SigningStatus: "unsigned", NotarizationStatus: "notarized"},
	})
	if st := read(win)["WinApp"]; st.signing != nil || st.notarization != nil {
		t.Errorf("Windows row stored %s/%s, want NULL/NULL: the fields are macOS only", str(st.signing), str(st.notarization))
	}
}

// PAT-2112: a non-string signing_status or notarization_status would fail
// the typed decode of the whole report, so it is refused at ingest; a string
// outside the enum is accepted (stored as not reported).
func TestValidateAppSigningStatusFields(t *testing.T) {
	withApp := func(key string, v any) []byte {
		return fixtureWith(t, "full.json", func(m map[string]any) {
			apps := m["apps"].([]any)
			apps[0].(map[string]any)[key] = v
		})
	}
	for _, key := range []string{"signing_status", "notarization_status"} {
		for _, v := range []any{"signed", "notarized", "some_future_value"} {
			if err := ValidatePayload(withApp(key, v)); err != nil {
				t.Errorf("%s=%v rejected: %v", key, v, err)
			}
		}
		for _, v := range []any{true, 1.0, nil, map[string]any{}} {
			if err := ValidatePayload(withApp(key, v)); err == nil {
				t.Errorf("%s=%v accepted", key, v)
			}
		}
	}
	upper := fixtureWith(t, "full.json", func(m map[string]any) {
		m["apps"].([]any)[0].(map[string]any)["Signing_Status"] = "signed"
	})
	if err := ValidatePayload(upper); err == nil {
		t.Error("case-variant Signing_Status accepted")
	}
}

func TestMacOSSigningStatusNormalisation(t *testing.T) {
	for _, tc := range []struct {
		platform, sig, not string
		wantSig, wantNot   string
	}{
		{"macos", "signed", "notarized", "signed", "notarized"},
		{"macos", " adhoc ", "not_notarized", "adhoc", "not_notarized"},
		{"macos", "unsigned", "unknown", "unsigned", "unknown"},
		{"macos", "error", "", "error", "NULL"},
		// PAT-2117: the two newest values.
		{"macos", "untrusted", "not_notarized", "untrusted", "not_notarized"},
		{"macos", " invalid ", "unknown", "invalid", "unknown"},
		{"macos", "Unsigned", "Notarized", "NULL", "NULL"},
		{"macos", "", "", "NULL", "NULL"},
		{"windows", "untrusted", "notarized", "NULL", "NULL"},
		{"windows", "unsigned", "notarized", "NULL", "NULL"},
	} {
		s, n := macOSSigningStatus(tc.platform, tc.sig), macOSNotarizationStatus(tc.platform, tc.not)
		got := func(p *string) string {
			if p == nil {
				return "NULL"
			}
			return *p
		}
		if got(s) != tc.wantSig || got(n) != tc.wantNot {
			t.Errorf("%s %q/%q -> %s/%s, want %s/%s", tc.platform, tc.sig, tc.not, got(s), got(n), tc.wantSig, tc.wantNot)
		}
	}
}

// PAT-2113: a Windows app's installation_evidence.signature_state lands on
// its immutable observation, the signer only beside valid; a value outside
// the enum, and the same block on a macOS report, store as not reported.
func TestSignatureStatePersistsOnWindowsOnly(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat2113-signature-state','\x00','\x00') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	store := func(platform, os, serial string, apps []appPart) string {
		t.Helper()
		var deviceID string
		if err := tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,$2,$3) RETURNING id::text`,
			tenantID, os, serial).Scan(&deviceID); err != nil {
			t.Fatal(err)
		}
		received := time.Now().UTC().Truncate(time.Microsecond)
		var rawID int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
			VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
		`, tenantID, deviceID, received).Scan(&rawID); err != nil {
			t.Fatal(err)
		}
		p := &payload{SchemaVersion: 3, Platform: platform, Agent: "pat2113", AgentVersion: "test",
			CollectedAt: received.Format(time.RFC3339), AppsPresent: true, Apps: apps}
		if _, err := upsertSoftwareInventory(ctx, tx, claimedRow{ID: rawID, ReceivedAt: received, TenantID: tenantID},
			deviceID, p, platform); err != nil {
			t.Fatal(err)
		}
		return deviceID
	}
	type stored struct{ state, signer *string }
	read := func(deviceID string) map[string]stored {
		t.Helper()
		rows, err := tx.Query(ctx, `SELECT observed_name, observed_signature_state, observed_authenticode_signer
			FROM software_observations WHERE device_id=$1::uuid`, deviceID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]stored{}
		for rows.Next() {
			var name string
			var st stored
			if err := rows.Scan(&name, &st.state, &st.signer); err != nil {
				t.Fatal(err)
			}
			out[name] = st
		}
		return out
	}
	str := func(p *string) string {
		if p == nil {
			return "NULL"
		}
		return *p
	}
	ev := func(state, signer string) *appInstallationEvidencePart {
		return &appInstallationEvidencePart{SignatureState: state, Signer: signer}
	}
	const signer = "CN=Example Corporation, O=Example Corporation, C=US"
	winApp := func(name string, e *appInstallationEvidencePart) appPart {
		return appPart{Name: name, Version: "1", Identifier: "PAT2113." + name, IdentifierKind: "native",
			Publisher: "Registry Claim Ltd", InstallationEvidence: e}
	}

	win := store("windows", "Windows 11", "PAT2113-WIN", []appPart{
		winApp("Valid", ev("valid", signer)),
		winApp("ValidNoSigner", ev("valid", "")),
		winApp("Invalid", ev("invalid", signer)),
		winApp("StateUnknown", ev("unknown", "")),
		winApp("Unsigned", ev("unsigned", signer)),
		winApp("Future", ev("Valid", signer)),
		winApp("Absent", nil),
	})
	got := read(win)
	for name, want := range map[string][2]string{
		"Valid":         {"valid", signer},
		"ValidNoSigner": {"valid", "NULL"},
		"Invalid":       {"invalid", "NULL"},
		"StateUnknown":  {"unknown", "NULL"},
		"Unsigned":      {"unsigned", "NULL"},
		"Future":        {"NULL", "NULL"},
		"Absent":        {"NULL", "NULL"},
	} {
		st, ok := got[name]
		if !ok {
			t.Fatalf("%s: no observation", name)
		}
		if str(st.state) != want[0] || str(st.signer) != want[1] {
			t.Errorf("%s: stored %s/%s, want %s/%s", name, str(st.state), str(st.signer), want[0], want[1])
		}
	}

	mac := store("macos", "macOS 26.0", "PAT2113-MAC", []appPart{
		{Name: "MacApp", Version: "1", Identifier: "com.pat2113.mac", InstallationEvidence: ev("valid", signer)},
	})
	if st := read(mac)["MacApp"]; st.state != nil || st.signer != nil {
		t.Errorf("macOS row stored %s/%s, want NULL/NULL: the evidence is Windows only", str(st.state), str(st.signer))
	}

}

// PAT-2113: installation_evidence is decoded, so a shape the typed decode
// cannot take is refused at ingest; unknown members and an unknown enum
// string are accepted.
func TestValidateAppInstallationEvidence(t *testing.T) {
	withEvidence := func(v any) []byte {
		return fixtureWith(t, "full.json", func(m map[string]any) {
			m["apps"].([]any)[0].(map[string]any)["installation_evidence"] = v
		})
	}
	for _, v := range []any{
		nil,
		map[string]any{},
		map[string]any{"signature_state": "valid", "signer": "CN=Example", "errors": []any{}, "delivery_version": 1.0},
		map[string]any{"signature_state": "some_future_value"},
		map[string]any{"signature_state": "unsigned", "executable_resolution": "install_location_single_exe"},
		map[string]any{"signature_state": "valid", "signer": "CN=Example", "signer_thumbprint": strings.Repeat("a", 64),
			"issuer": "CN=Example CA", "root_thumbprint": strings.Repeat("b", 64), "root_kind": "enterprise",
			"executable_resolution": "display_icon"},
		map[string]any{"signature_state": "valid", "root_kind": "some_future_kind", "root_thumbprint": "not hex"},
	} {
		if err := ValidatePayload(withEvidence(v)); err != nil {
			t.Errorf("installation_evidence=%v rejected: %v", v, err)
		}
	}
	for _, v := range []any{
		"valid", 1.0, true, []any{},
		map[string]any{"signature_state": 1.0},
		map[string]any{"signature_state": nil},
		map[string]any{"signer": map[string]any{}},
		map[string]any{"signer_thumbprint": 1.0},
		map[string]any{"issuer": []any{"CN=Example"}},
		map[string]any{"root_thumbprint": nil},
		map[string]any{"root_kind": true},
		map[string]any{"executable_resolution": map[string]any{}},
	} {
		if err := ValidatePayload(withEvidence(v)); err == nil {
			t.Errorf("installation_evidence=%v accepted", v)
		}
	}
	upper := withEvidence(map[string]any{"Signature_State": "valid"})
	if err := ValidatePayload(upper); err == nil {
		t.Error("case-variant Signature_State accepted")
	}
	for _, key := range []string{"Root_Kind", "ROOT_THUMBPRINT", "Signer_Thumbprint", "Issuer", "Executable_Resolution"} {
		if err := ValidatePayload(withEvidence(map[string]any{key: "x"})); err == nil {
			t.Errorf("case-variant %s accepted", key)
		}
	}
}

func TestWindowsSignatureEvidenceNormalisation(t *testing.T) {
	long := strings.Repeat("a", 513)
	ev := func(state, signer string) *appInstallationEvidencePart {
		return &appInstallationEvidencePart{SignatureState: state, Signer: signer}
	}
	for _, tc := range []struct {
		platform           string
		ev                 *appInstallationEvidencePart
		wantState, wantSig string
	}{
		{"windows", ev("valid", " CN=Example "), "valid", "CN=Example"},
		{"windows", ev("valid", ""), "valid", "NULL"},
		{"windows", ev("valid", long), "valid", "NULL"},
		{"windows", ev("valid", "CN=Ex\u0007ample"), "valid", "NULL"},
		{"windows", ev("valid", "CN=\xff"), "valid", "NULL"},
		{"windows", ev("invalid", "CN=Example"), "invalid", "NULL"},
		{"windows", ev("unknown", "CN=Example"), "unknown", "NULL"},
		// PAT-2116: unsigned is the agent's proven "no signature" verdict.
		{"windows", ev("unsigned", "CN=Example"), "unsigned", "NULL"},
		{"windows", ev("VALID", "CN=Example"), "NULL", "NULL"},
		{"windows", ev("Unsigned", ""), "NULL", "NULL"},
		{"windows", nil, "NULL", "NULL"},
		{"macos", ev("valid", "CN=Example"), "NULL", "NULL"},
		{"macos", ev("unsigned", ""), "NULL", "NULL"},
	} {
		a := windowsSignatureEvidence(tc.platform, tc.ev)
		if nullable(a.State) != tc.wantState || nullable(a.Signer) != tc.wantSig {
			t.Errorf("%s %+v -> %s/%s, want %s/%s", tc.platform, tc.ev, nullable(a.State), nullable(a.Signer), tc.wantState, tc.wantSig)
		}
	}
}

func nullable(p *string) string {
	if p == nil {
		return "NULL"
	}
	return *p
}

// PAT-2116: the pinnable publisher is kept beside valid only, each member
// validated on its own (a bad one is NULL without discarding the rest), and
// executable_resolution is kept whatever the state, on Windows only.
func TestWindowsAuthenticodePublisherNormalisation(t *testing.T) {
	leaf, root := strings.Repeat("1", 64), strings.Repeat("ab", 32)
	full := func(state string) *appInstallationEvidencePart {
		return &appInstallationEvidencePart{SignatureState: state, Signer: "CN=Example Ltd",
			SignerThumbprint: leaf, Issuer: "CN=Example CA, O=Example", RootThumbprint: root,
			RootKind: "public", ExecutableResolution: "display_icon"}
	}
	with := func(state string, mod func(*appInstallationEvidencePart)) *appInstallationEvidencePart {
		e := full(state)
		mod(e)
		return e
	}
	type want struct{ state, signer, leaf, issuer, root, kind, resolution string }
	for _, tc := range []struct {
		name     string
		platform string
		ev       *appInstallationEvidencePart
		want     want
	}{
		{"valid keeps everything", "windows", full("valid"),
			want{"valid", "CN=Example Ltd", leaf, "CN=Example CA, O=Example", root, "public", "display_icon"}},
		{"microsoft root", "windows", with("valid", func(e *appInstallationEvidencePart) { e.RootKind = "microsoft" }),
			want{"valid", "CN=Example Ltd", leaf, "CN=Example CA, O=Example", root, "microsoft", "display_icon"}},
		{"enterprise root", "windows", with("valid", func(e *appInstallationEvidencePart) { e.RootKind = "enterprise" }),
			want{"valid", "CN=Example Ltd", leaf, "CN=Example CA, O=Example", root, "enterprise", "display_icon"}},
		{"upper-case thumbprints are lower-cased", "windows", with("valid", func(e *appInstallationEvidencePart) {
			e.SignerThumbprint, e.RootThumbprint = strings.ToUpper(strings.Repeat("ab", 32)), " "+strings.ToUpper(root)+" "
		}), want{"valid", "CN=Example Ltd", strings.Repeat("ab", 32), "CN=Example CA, O=Example", root, "public", "display_icon"}},
		{"unknown root kind is NULL, the rest stays", "windows", with("valid", func(e *appInstallationEvidencePart) { e.RootKind = "Public" }),
			want{"valid", "CN=Example Ltd", leaf, "CN=Example CA, O=Example", root, "NULL", "display_icon"}},
		{"bad thumbprints and issuer are NULL", "windows", with("valid", func(e *appInstallationEvidencePart) {
			e.SignerThumbprint, e.RootThumbprint, e.Issuer = strings.Repeat("1", 40), strings.Repeat("g", 64), "CN=\u0000"
		}), want{"valid", "CN=Example Ltd", "NULL", "NULL", "NULL", "public", "display_icon"}},
		{"unsigned carries no publisher", "windows", full("unsigned"),
			want{"unsigned", "NULL", "NULL", "NULL", "NULL", "NULL", "display_icon"}},
		{"invalid carries no publisher", "windows", full("invalid"),
			want{"invalid", "NULL", "NULL", "NULL", "NULL", "NULL", "display_icon"}},
		{"unknown carries no publisher", "windows", full("unknown"),
			want{"unknown", "NULL", "NULL", "NULL", "NULL", "NULL", "display_icon"}},
		{"unrecognised state keeps the resolution only", "windows", full("revoked"),
			want{"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "display_icon"}},
		{"bad resolution is NULL", "windows", with("valid", func(e *appInstallationEvidencePart) { e.ExecutableResolution = "Display Icon" }),
			want{"valid", "CN=Example Ltd", leaf, "CN=Example CA, O=Example", root, "public", "NULL"}},
		{"overlong resolution is NULL", "windows", with("unknown", func(e *appInstallationEvidencePart) { e.ExecutableResolution = "a" + strings.Repeat("b", 64) }),
			want{"unknown", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"}},
		{"macOS stores nothing", "macos", full("valid"),
			want{"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := windowsSignatureEvidence(tc.platform, tc.ev)
			got := want{nullable(a.State), nullable(a.Signer), nullable(a.SignerThumbprint), nullable(a.Issuer),
				nullable(a.RootThumbprint), nullable(a.RootKind), nullable(a.ExecutableResolution)}
			if got != tc.want {
				t.Errorf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
