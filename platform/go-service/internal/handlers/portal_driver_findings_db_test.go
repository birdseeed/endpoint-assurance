package handlers

// PAT-2263: kernel_drivers on GET /v1/portal/devices/{deviceID} and
// GET /v1/portal/driver-findings, against the migrated schema. Skipped
// without TEST_DATABASE_URL. The global list tables are isolated in this
// package's own schema (driverblocktest); tenants isolate the device rows.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/driverblock"
	"patched.im/api/internal/driverblock/driverblocktest"
	"patched.im/api/internal/portalauth"
)

func seedKernelDriverRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, rawID int64,
	enforced, path, sha256 string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	var obsID int64
	if err := pool.QueryRow(ctx, `INSERT INTO device_kernel_driver_observations (tenant_id, device_id, raw_payload_id,
			raw_payload_received_at, block_schema_version, collection_status, vulnerable_driver_blocklist, hvci,
			smart_app_control, code_integrity_policy, blocklist_enforced, driver_count, hashed_count)
		VALUES ($1::uuid, $2::uuid, $3, $4, 1, 'complete', 'enabled', 'running', 'off', 'off', $5, 1, 1) RETURNING id`,
		tenantID, deviceID, rawID, now, enforced).Scan(&obsID); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_kernel_driver_state (device_id, tenant_id, observation_id, reported_at,
			collection_status, vulnerable_driver_blocklist, hvci, smart_app_control, code_integrity_policy, blocklist_enforced)
		VALUES ($1::uuid, $2::uuid, $3, $4, 'complete', 'enabled', 'running', 'off', 'off', $5)`,
		deviceID, tenantID, obsID, now, enforced); err != nil {
		t.Fatalf("insert state: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_kernel_drivers (device_id, tenant_id, driver_key, path, loaded, sources,
			hash_status, sha256, sha1, observation_id, reported_at, first_seen_at)
		VALUES ($1::uuid, $2::uuid, 'path:x', $3, true, '{loaded}', 'hashed', $4, '0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', $5, $6, $6)`,
		deviceID, tenantID, path, sha256, obsID, now); err != nil {
		t.Fatalf("insert driver: %v", err)
	}
}

func TestPortalDriverFindingsAndDeviceDetail(t *testing.T) {
	pool := driverblocktest.Pool(t, "pat2263_handlers_test")
	ctx := context.Background()

	fetched := time.Now().UTC().Truncate(time.Second)
	snap := driverblock.Snapshot{Source: driverblock.SourceLOLDrivers, SourceURL: driverblock.LOLDriversURL, FetchedAt: fetched,
		SourceRevision: "sha256:test", Entries: []driverblock.Entry{{HashKind: driverblock.HashSHA256,
			Hash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", EntryID: "synthetic-1",
			EntryName: "evil.sys", Category: driverblock.CategoryMalicious}}}
	if err := driverblock.ReplaceSnapshot(ctx, pool, snap, fetched); err != nil {
		t.Fatal(err)
	}

	tenantA := catSeedTenant(t, ctx, pool, "pat2263-tenant-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat2263-tenant-b")
	email := "customer-" + tenantA[:8] + "@pat2263.example"
	rawBase := time.Now().UnixNano()%1_000_000_000_000 + 8_000_000_000_000

	listedA := seedFirmwareDevice(t, ctx, pool, tenantA, "PAT2263-A1")
	seedKernelDriverRow(t, ctx, pool, tenantA, listedA, rawBase+1, "yes", `C:\Temp\renamed.sys`,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	notReported := seedFirmwareDevice(t, ctx, pool, tenantA, "PAT2263-A2")
	listedB := seedFirmwareDevice(t, ctx, pool, tenantB, "PAT2263-B1")
	seedKernelDriverRow(t, ctx, pool, tenantB, listedB, rawBase+2, "no", `C:\Temp\b.sys`,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

	asA := func(req *http.Request) *http.Request {
		return req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantA}))
	}

	// Estate findings: tenant A sees its own device only.
	rr := httptest.NewRecorder()
	PortalDriverFindingsHandler(pool).ServeHTTP(rr, asA(httptest.NewRequest(http.MethodGet, "/v1/portal/driver-findings", nil)))
	if rr.Code != http.StatusOK {
		t.Fatalf("findings status = %d: %s", rr.Code, rr.Body.String())
	}
	var findings struct {
		Total    int                     `json:"total"`
		Lists    []driverblock.ListState `json:"lists"`
		Findings []driverblock.Finding   `json:"findings"`
		Summary  driverblock.EstateSummary
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &findings); err != nil {
		t.Fatal(err)
	}
	if findings.Total != 1 || len(findings.Findings) != 1 || findings.Findings[0].DeviceID != listedA {
		t.Fatalf("findings = %s", rr.Body.String())
	}
	f := findings.Findings[0]
	if f.Category != "malicious" || f.BlocklistEnforced != "yes" || len(f.Matches) != 1 ||
		f.Matches[0].ListVersion != "sha256:test" || !f.Matches[0].ListFetchedAt.Equal(fetched) || f.Matches[0].Hash == "" {
		t.Fatalf("finding = %+v", f)
	}
	if len(findings.Lists) != 2 {
		t.Fatalf("lists = %+v", findings.Lists)
	}

	// Device detail carries the same evidence for one device.
	detail := func(deviceID string) (int, map[string]any) {
		req := asA(httptest.NewRequest(http.MethodGet, "/v1/portal/devices/"+deviceID, nil))
		req = withChiParam(req, "deviceID", deviceID)
		rr := httptest.NewRecorder()
		PortalDeviceDetailHandler(pool).ServeHTTP(rr, req)
		var body map[string]any
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code, body
	}
	code, body := detail(listedA)
	if code != http.StatusOK {
		t.Fatalf("detail status = %d", code)
	}
	kd := body["kernel_drivers"].(map[string]any)
	if kd["status"] != "complete" || kd["enforcement"].(map[string]any)["blocklist_enforced"] != "yes" {
		t.Fatalf("kernel_drivers = %+v", kd)
	}
	drivers := kd["drivers"].([]any)
	if len(drivers) != 1 || drivers[0].(map[string]any)["match_status"] != "listed" {
		t.Fatalf("drivers = %+v", drivers)
	}

	code, body = detail(notReported)
	if code != http.StatusOK {
		t.Fatalf("detail status = %d", code)
	}
	if kd := body["kernel_drivers"].(map[string]any); kd["status"] != "not_reported" || kd["enforcement"] != nil ||
		len(kd["drivers"].([]any)) != 0 {
		t.Fatalf("not reported kernel_drivers = %+v", kd)
	}

	// Another tenant's device is indistinguishable from an unknown one.
	if code, _ := detail(listedB); code != http.StatusNotFound {
		t.Fatalf("cross-tenant detail status = %d, want 404", code)
	}
}
