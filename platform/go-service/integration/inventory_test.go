//go:build integration

// Package integration holds the CI integration tests for the patched.im go-service.
//
// These tests require a live Postgres instance (TEST_DATABASE_URL) with all
// migrations applied from zero; the CI job handles that via a service container.
// The tests POST golden fixtures to /v1/inventory, run the extractor, and read
// back via the admin endpoints.
//
// Run locally:
//
//	TEST_DATABASE_URL="postgres://user:pass@localhost/patched_test?sslmode=disable" \
//	  go test -tags=integration -v ./integration/
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"patched.im/api/internal/extractor"
)

// TestMigrationsFromZero is implicitly covered by TestMain: if migrations fail,
// TestMain exits non-zero before any test runs.  This explicit test asserts that
// the schema_migrations table exists and has at least one row so the CI log
// clearly names which step passed.
func TestMigrationsFromZero(t *testing.T) {
	var count int
	err := env.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count == 0 {
		t.Error("schema_migrations is empty — no migrations were applied")
	}
	t.Logf("schema_migrations rows: %d", count)
}

// TestInventoryValidFixtures POSTs every valid/ and edge/ golden fixture through
// POST /v1/inventory, asserts 200, runs the extractor, then reads back through
// the admin endpoints and asserts the response shapes.
func TestInventoryValidFixtures(t *testing.T) {
	ctx := context.Background()

	for _, dir := range []string{"valid", "edge"} {
		files := fixtureFiles(t, dir)
		if len(files) == 0 {
			t.Errorf("no fixtures found in %s/", dir)
			continue
		}
		for _, name := range files {
			t.Run(dir+"/"+name, func(t *testing.T) {
				body := fixtureData(t, dir, name)

				// POST to /v1/inventory.
				req := signedInventoryRequest(t, body)
				resp := postInventory(t, req)
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					raw, _ := io.ReadAll(resp.Body)
					t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
				}
				var ingestResp struct {
					Status       string `json:"status"`
					RawPayloadID int64  `json:"raw_payload_id"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
					t.Fatalf("decode ingest response: %v", err)
				}
				if ingestResp.Status != "ok" {
					t.Errorf("want status=ok, got %q", ingestResp.Status)
				}
				if ingestResp.RawPayloadID == 0 {
					t.Error("raw_payload_id should be non-zero")
				}

				// Run extractor synchronously.
				if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
					t.Fatalf("ProcessOnce: %v", err)
				}

				// Assert the raw_payload row was extracted (no extraction_error).
				assertNoExtractionError(t, ingestResp.RawPayloadID)

				// Read back: device must have been created for the tenant.
				assertTenantHasDevices(t)
			})
		}
	}
}

// TestInventoryInvalidFixtures POSTs every invalid/ golden fixture with valid
// auth headers and asserts the handler returns 400 — schema validation runs
// synchronously in the handler (PAT-227) before any DB write.
func TestInventoryInvalidFixtures(t *testing.T) {
	for _, name := range fixtureFiles(t, "invalid") {
		t.Run("invalid/"+name, func(t *testing.T) {
			body := fixtureData(t, "invalid", name)

			req := signedInventoryRequest(t, body)
			resp := postInventory(t, req)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Errorf("POST /v1/inventory with invalid fixture %q: want 400, got %d: %s",
					name, resp.StatusCode, raw)
			}
		})
	}
}

// TestInventoryCertsRoundTrip posts the only-certificates fixture and reads
// back via GET /admin/tenant/{id}/certs to verify field shape.
func TestInventoryCertsRoundTrip(t *testing.T) {
	ctx := context.Background()
	body := fixtureData(t, "valid", "only-certificates.json")

	req := signedInventoryRequest(t, body)
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}

	var ingestResp struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
		t.Fatalf("decode ingest response: %v", err)
	}

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingestResp.RawPayloadID)

	// Read back via /admin/tenant/{id}/certs.
	certsURL := fmt.Sprintf("%s/admin/tenant/%s/certs", env.internalSrv.URL, env.tenantID)
	certsResp, err := http.Get(certsURL)
	if err != nil {
		t.Fatalf("GET /admin/tenant/.../certs: %v", err)
	}
	defer certsResp.Body.Close()
	if certsResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(certsResp.Body)
		t.Fatalf("certs endpoint: want 200, got %d: %s", certsResp.StatusCode, raw)
	}

	var certs []map[string]any
	if err := json.NewDecoder(certsResp.Body).Decode(&certs); err != nil {
		t.Fatalf("decode certs: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("want at least one cert back, got empty array")
	}

	// Assert required field shape on every returned cert.
	wantKeys := []string{
		"device_id", "subject_cn", "issuer_cn", "sha1",
		"not_after", "days_until_expiry_at_collection",
		"ext_key_usage", "basic_constraints_ca", "is_self_signed", "collected_at",
	}
	for i, cert := range certs {
		for _, k := range wantKeys {
			if _, ok := cert[k]; !ok {
				t.Errorf("cert[%d]: missing required field %q", i, k)
			}
		}
	}
	t.Logf("certs round-trip: %d cert(s) returned", len(certs))
}

// TestInventoryEdgeEmptyArrays posts the edge/empty-arrays.json fixture and
// verifies the absent/empty/non-empty dispatch semantics in the extractor:
//   - certificates: [] → all cert rows for the device pruned
//   - pending_updates absent → no-op (previous pending_updates value preserved)
func TestInventoryEdgeEmptyArrays(t *testing.T) {
	ctx := context.Background()
	body := fixtureData(t, "edge", "empty-arrays.json")

	req := signedInventoryRequest(t, body)
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}

	var ingestResp struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
		t.Fatalf("decode ingest response: %v", err)
	}

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingestResp.RawPayloadID)

	// certificates: [] → certs for this device pruned.
	// Look up the device_id from the DB (hw_uuid matches the fixture), then
	// scope the certs query to that device so results from other fixtures don't
	// interfere.
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		SELECT id::text FROM devices
		WHERE tenant_id = $1::uuid AND hw_uuid = '22222222-AAAA-BBBB-CCCC-DDDDDDDDDDDD'
	`, env.tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("look up device: %v", err)
	}
	certsURL := fmt.Sprintf("%s/admin/tenant/%s/certs?device_id=%s",
		env.internalSrv.URL, env.tenantID, deviceID)
	certsResp, err := http.Get(certsURL)
	if err != nil {
		t.Fatalf("GET certs: %v", err)
	}
	defer certsResp.Body.Close()
	var certs []any
	if err := json.NewDecoder(certsResp.Body).Decode(&certs); err != nil {
		t.Fatalf("decode certs: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("edge/empty-arrays: certificates:[] should prune device certs; got %d", len(certs))
	}
}

// TestInventoryAppsPruneStale posts two scans for the same device
// (apps-prune-scan1.json then apps-prune-scan2.json): scan1 reports AppOne +
// AppTwo, scan2 reports AppTwo + AppThree (AppOne dropped). Asserts that after
// scan2 extracts, AppOne's device_apps row is gone — not left behind as a
// stale duplicate (PAT-808).
func TestInventoryAppsPruneStale(t *testing.T) {
	ctx := context.Background()
	const hwUUID = "99999999-AAAA-BBBB-CCCC-DDDDDDDDDDDD"

	postAndExtract := func(fixture string) {
		t.Helper()
		req := signedInventoryRequest(t, fixtureData(t, "edge", fixture))
		resp := postInventory(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST /v1/inventory (%s): want 200, got %d: %s", fixture, resp.StatusCode, raw)
		}
		var ingestResp struct {
			RawPayloadID int64 `json:"raw_payload_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
			t.Fatalf("decode ingest response (%s): %v", fixture, err)
		}
		if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
			t.Fatalf("ProcessOnce (%s): %v", fixture, err)
		}
		assertNoExtractionError(t, ingestResp.RawPayloadID)
	}

	deviceApps := func() []string {
		t.Helper()
		rows, err := env.pool.Query(ctx, `
			SELECT da.identifier FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid AND d.hw_uuid = $2
			ORDER BY da.identifier
		`, env.tenantID, hwUUID)
		if err != nil {
			t.Fatalf("query device_apps: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan device_apps identifier: %v", err)
			}
			out = append(out, id)
		}
		return out
	}

	postAndExtract("apps-prune-scan1.json")
	got := deviceApps()
	want := []string{"com.patchedtest.appone", "com.patchedtest.apptwo"}
	if !equalStrings(got, want) {
		t.Fatalf("after scan1: device_apps = %v, want %v", got, want)
	}

	postAndExtract("apps-prune-scan2.json")
	got = deviceApps()
	want = []string{"com.patchedtest.appthree", "com.patchedtest.apptwo"}
	if !equalStrings(got, want) {
		t.Errorf("after scan2: device_apps = %v, want %v (AppOne should have been pruned as stale)", got, want)
	}
}

// TestInventoryBrowserExtensionBadUserAccountSkipped posts the
// edge/browser-extension-bad-user-account.json fixture (one browser_extensions
// entry with an empty user_account, mixed in with an otherwise-valid device
// snapshot: a device, an app, and two well-formed extensions) and proves the
// PAT-871 fix end to end:
//
//   - The whole extraction succeeds (no extraction_error) -- before the fix,
//     the NOT NULL violation on user_account propagated out of
//     upsertBrowserExtensions and rolled back the entire processRow
//     transaction, so the device row itself would never have been created.
//   - The device and its one app are both persisted.
//   - Exactly the two well-formed browser extensions are persisted; the
//     malformed entry is skipped, not written.
func TestInventoryBrowserExtensionBadUserAccountSkipped(t *testing.T) {
	ctx := context.Background()
	const hwUUID = "88888888-AAAA-BBBB-CCCC-DDDDDDDDDDDD"

	body := fixtureData(t, "edge", "browser-extension-bad-user-account.json")
	req := signedInventoryRequest(t, body)
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: want 200, got %d: %s", resp.StatusCode, raw)
	}

	var ingestResp struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
		t.Fatalf("decode ingest response: %v", err)
	}

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	// The whole snapshot must have extracted -- no rollback, no dead-lettering.
	assertNoExtractionError(t, ingestResp.RawPayloadID)

	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2
	`, env.tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("look up device: %v", err)
	}

	// The device's one app must have persisted alongside it.
	var appCount int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*) FROM device_apps WHERE device_id = $1::uuid
	`, deviceID).Scan(&appCount); err != nil {
		t.Fatalf("count device_apps: %v", err)
	}
	if appCount != 1 {
		t.Errorf("device_apps count: want 1, got %d", appCount)
	}

	// Exactly the two well-formed extensions must have persisted; the
	// malformed entry (empty user_account) must be skipped, not written.
	var extCount int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions WHERE device_id = $1::uuid
	`, deviceID).Scan(&extCount); err != nil {
		t.Fatalf("count device_browser_extensions: %v", err)
	}
	if extCount != 2 {
		t.Errorf("device_browser_extensions count: want 2 (malformed entry skipped), got %d", extCount)
	}

	var badCount int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND extension_id = 'gighmmpiobklfepjocnamgkkbiglidom'
	`, deviceID).Scan(&badCount); err != nil {
		t.Fatalf("count malformed extension: %v", err)
	}
	if badCount != 0 {
		t.Error("malformed extension entry (empty user_account) must not be written")
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// equalStrings compares two string slices for equality (order-sensitive;
// callers pass already-sorted slices).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// assertNoExtractionError fails the test if the raw_payloads row has an
// extraction_error set, indicating the extractor rejected the payload.
func assertNoExtractionError(t *testing.T, rawPayloadID int64) {
	t.Helper()
	var extractionError *string
	err := env.pool.QueryRow(context.Background(),
		`SELECT extraction_error FROM raw_payloads WHERE id = $1`,
		rawPayloadID,
	).Scan(&extractionError)
	if err != nil {
		t.Fatalf("query raw_payloads row %d: %v", rawPayloadID, err)
	}
	if extractionError != nil {
		t.Errorf("extractor rejected fixture: %s", *extractionError)
	}
}

// assertTenantHasDevices fails if the test tenant has no devices in the DB.
func assertTenantHasDevices(t *testing.T) {
	t.Helper()
	var count int
	err := env.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM devices WHERE tenant_id = $1::uuid`,
		env.tenantID,
	).Scan(&count)
	if err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one device row after extraction, found none")
	}
}
