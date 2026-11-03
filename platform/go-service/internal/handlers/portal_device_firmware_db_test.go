package handlers

// PAT-2262: the firmware block on GET /v1/portal/devices/{deviceID}.
// Skipped without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

func seedFirmwareDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, serial string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, hw_model, arch, agent_version)
		VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'Windows', '11.0.22631', '22631', '20XW0026UK', 'x86_64', '0.16.0')
		RETURNING id::text`, tenantID, serial).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

func seedFirmwareObservation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, rawID int64, receivedAt time.Time, status string, errs []string, withValues bool) int64 {
	t.Helper()
	var id int64
	var biosStatus, version, date any
	if withValues {
		biosStatus, version, date = "complete", "N3HET82W (1.54 )", "2023-05-12"
	}
	sectionStatus := biosStatus
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_firmware_observations (tenant_id, device_id, raw_payload_id, raw_payload_received_at, observed_at,
			block_schema_version, collection_status, errors,
			bios_status, bios_manufacturer, bios_version, smbios_version, bios_release_date,
			system_status, system_manufacturer, system_model, baseboard_status)
		VALUES ($1::uuid, $2::uuid, $3, $4, $4, 1, $5, $6, $7, 'LENOVO', $8, '3.2', $9::date, $7, 'LENOVO', '20XW0026UK', $7)
		RETURNING id`, tenantID, deviceID, rawID, receivedAt, status, errs, sectionStatus, version, date).Scan(&id); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	return id
}

func TestPortalDeviceDetail_Firmware(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantA := catSeedTenant(t, ctx, pool, "pat2262-tenant-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat2262-tenant-b")
	email := "customer-" + tenantA[:8] + "@pat2262.example"
	rawBase := time.Now().UnixNano()%1_000_000_000_000 + 7_000_000_000_000

	t0 := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	t1 := t0.Add(time.Hour)

	// 1. An agent that never sent the block (older agent, or macOS).
	notReported := seedFirmwareDevice(t, ctx, pool, tenantA, "PAT2262-NR")

	// 2. A new agent that tried and read nothing, with no earlier values.
	unavailable := seedFirmwareDevice(t, ctx, pool, tenantA, "PAT2262-UA")
	obsUA := seedFirmwareObservation(t, ctx, pool, tenantA, unavailable, rawBase+1, t1, "unavailable",
		[]string{"bios_query_failed", "system_query_failed", "baseboard_query_failed"}, false)
	if _, err := pool.Exec(ctx, `INSERT INTO device_firmware_current (device_id, tenant_id, collection_status, errors, observation_id, reported_at, observed_at)
		VALUES ($1::uuid, $2::uuid, 'unavailable', $3, $4, $5, $5)`,
		unavailable, tenantA, []string{"bios_query_failed", "system_query_failed", "baseboard_query_failed"}, obsUA, t1); err != nil {
		t.Fatalf("insert current (unavailable): %v", err)
	}

	// 3. Read in full once, then unavailable: last-known values stay, with
	// their own time, and the newest status says unavailable.
	known := seedFirmwareDevice(t, ctx, pool, tenantA, "PAT2262-KN")
	obsKnown := seedFirmwareObservation(t, ctx, pool, tenantA, known, rawBase+2, t0, "complete", []string{}, true)
	obsKnownLatest := seedFirmwareObservation(t, ctx, pool, tenantA, known, rawBase+3, t1, "unavailable", []string{"bios_query_failed"}, false)
	if _, err := pool.Exec(ctx, `INSERT INTO device_firmware_current (device_id, tenant_id, collection_status, errors, observation_id, reported_at, observed_at,
			bios_status, bios_observation_id, bios_reported_at, bios_manufacturer, bios_version, smbios_version, bios_release_date,
			system_status, system_observation_id, system_reported_at, system_manufacturer, system_model,
			baseboard_status, baseboard_observation_id, baseboard_reported_at)
		VALUES ($1::uuid, $2::uuid, 'unavailable', '{bios_query_failed}', $3, $4, $4,
			'complete', $5, $6, 'LENOVO', 'N3HET82W (1.54 )', '3.2', '2023-05-12',
			'complete', $5, $6, 'LENOVO', '20XW0026UK',
			'complete', $5, $6)`, known, tenantA, obsKnownLatest, t1, obsKnown, t0); err != nil {
		t.Fatalf("insert current (known): %v", err)
	}

	handler := PortalDeviceDetailHandler(pool)
	get := func(t *testing.T, deviceID, tenantID, email string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/devices/"+deviceID, nil)
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
		req = withChiParam(req, "deviceID", deviceID)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		var body map[string]any
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
		}
		return rr, body
	}
	firmwareOf := func(t *testing.T, body map[string]any) map[string]any {
		t.Helper()
		fw, ok := body["firmware"].(map[string]any)
		if !ok {
			t.Fatalf("response has no firmware object: %v", body["firmware"])
		}
		return fw
	}

	t.Run("never sent is not_reported, with no values", func(t *testing.T) {
		rr, body := get(t, notReported, tenantA, email)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		fw := firmwareOf(t, body)
		if fw["status"] != "not_reported" {
			t.Fatalf("status = %v, want not_reported", fw["status"])
		}
		for _, k := range []string{"reported_at", "observed_at", "bios", "system", "baseboard"} {
			if v, present := fw[k]; !present || v != nil {
				t.Errorf("%s = %v (present %v), want explicit null", k, v, present)
			}
		}
		if errs, ok := fw["errors"].([]any); !ok || len(errs) != 0 {
			t.Errorf("errors = %v, want []", fw["errors"])
		}
	})

	t.Run("tried and failed is unavailable, distinct from not_reported", func(t *testing.T) {
		rr, body := get(t, unavailable, tenantA, email)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		fw := firmwareOf(t, body)
		if fw["status"] != "unavailable" || fw["reported_at"] == nil {
			t.Fatalf("firmware = %v", fw)
		}
		if fw["bios"] != nil || fw["system"] != nil || fw["baseboard"] != nil {
			t.Errorf("sections present on a device that never read any: %v", fw)
		}
		if errs, _ := fw["errors"].([]any); len(errs) != 3 {
			t.Errorf("errors = %v", fw["errors"])
		}
	})

	t.Run("last known values survive an unavailable report with their own time", func(t *testing.T) {
		rr, body := get(t, known, tenantA, email)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		fw := firmwareOf(t, body)
		if fw["status"] != "unavailable" {
			t.Fatalf("status = %v", fw["status"])
		}
		bios, ok := fw["bios"].(map[string]any)
		if !ok {
			t.Fatalf("bios = %v", fw["bios"])
		}
		if bios["version"] != "N3HET82W (1.54 )" || bios["release_date"] != "2023-05-12" || bios["smbios_version"] != "3.2" ||
			bios["manufacturer"] != "LENOVO" || bios["status"] != "complete" {
			t.Errorf("bios = %v", bios)
		}
		if bios["release_date_raw"] != nil {
			t.Errorf("release_date_raw = %v", bios["release_date_raw"])
		}
		rep, _ := time.Parse(time.RFC3339, bios["reported_at"].(string))
		if !rep.Equal(t0) {
			t.Errorf("bios.reported_at = %v, want %v (the report that read it, not the newest)", bios["reported_at"], t0)
		}
		sys := fw["system"].(map[string]any)
		if sys["model"] != "20XW0026UK" || sys["manufacturer"] != "LENOVO" {
			t.Errorf("system = %v", sys)
		}
		bb := fw["baseboard"].(map[string]any)
		if _, present := bb["product"]; !present || bb["product"] != nil {
			t.Errorf("baseboard.product = %v, want explicit null", bb["product"])
		}
		// Observation only: nothing in the block may read as a verdict.
		raw, _ := json.Marshal(fw)
		for _, word := range []string{"outdated", "vulnerable", "current_version", "latest", "compliant", "verdict"} {
			if strings.Contains(string(raw), word) {
				t.Errorf("firmware block carries verdict-like text %q: %s", word, raw)
			}
		}
	})

	t.Run("another tenant's device still 404s", func(t *testing.T) {
		rr, _ := get(t, known, tenantB, "customer-"+tenantB[:8]+"@pat2262.example")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
		if strings.Contains(rr.Body.String(), "N3HET82W") {
			t.Errorf("404 leaked firmware: %s", rr.Body.String())
		}
	})
}
