package handlers

// DB-backed coverage for PAT-2141's identity/hardware blocks on
// GET /v1/portal/devices/{deviceID}. Skipped without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/portalauth"
)

func TestPortalDeviceDetail_IdentityAndHardware(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tenantA := catSeedTenant(t, ctx, pool, "pat2141-tenant-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat2141-tenant-b")
	emailA := "customer-" + tenantA[:8] + "@pat2141.example"

	firstSeen := time.Now().Add(-30 * 24 * time.Hour).UTC()
	lastSeen := time.Now().Add(-5 * time.Minute).UTC()

	// --- Device with full identity + hardware evidence -------------------
	var fullDeviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (
			tenant_id, serial, hw_uuid, hostname, computer_name,
			os, os_version, os_build, hw_model, arch,
			hardware, agent_version, first_seen, last_seen
		) VALUES (
			$1::uuid, 'C02XL0PAT2141', gen_random_uuid(), 'LT-2141', 'PAT-2141 MacBook Pro',
			'macOS', '15.6', '24G84', 'Mac16,1', 'arm64',
			$2::jsonb, '0.19.22', $3, $4
		) RETURNING id::text
	`, tenantA, `{"cpu_model":"Apple M4","cpu_cores":10,"ram_gb":24,"disk_total_gb":460.4,"disk_free_gb":29.9}`,
		firstSeen, lastSeen).Scan(&fullDeviceID); err != nil {
		t.Fatalf("insert full device: %v", err)
	}

	var hwID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_hardware (device_id, battery_present, battery_cycle_count, battery_condition, battery_max_capacity_pct)
		VALUES ($1::uuid, true, 30, 'Normal', 100)
		RETURNING id
	`, fullDeviceID).Scan(&hwID); err != nil {
		t.Fatalf("insert device_hardware: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_storage_volume (device_hardware_id, mount, total_bytes, free_bytes, used_pct)
		VALUES ($1, '/', 494384795648, 32135159808, 93)
	`, hwID); err != nil {
		t.Fatalf("insert device_storage_volume: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_disk (device_hardware_id, device_node, smart_status, internal, solid_state)
		VALUES ($1, 'disk0', 'Verified', true, true)
	`, hwID); err != nil {
		t.Fatalf("insert device_disk: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO raw_payloads (tenant_id, device_id, received_at, body)
		VALUES ($1::uuid, $2::uuid, now(), $3::jsonb)
	`, tenantA, fullDeviceID, `{
		"collected_at": "`+time.Now().Add(-2*time.Minute).UTC().Format(time.RFC3339)+`",
		"collection_status": {"certificates": "complete"},
		"hardware_health": {"collection_status": {"battery": "complete", "storage": "complete", "disks": "complete"}}
	}`); err != nil {
		t.Fatalf("insert raw_payloads (full device): %v", err)
	}

	// --- Device with no hardware collection at all ------------------------
	var bareDeviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, hw_model, arch, agent_version)
		VALUES ($1::uuid, 'C02BAREPAT2141', gen_random_uuid(), 'LT-2141-BARE', 'macOS', '15.6', '24G84', 'Mac16,1', 'arm64', '0.19.22')
		RETURNING id::text
	`, tenantA).Scan(&bareDeviceID); err != nil {
		t.Fatalf("insert bare device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO raw_payloads (tenant_id, device_id, received_at, body)
		VALUES ($1::uuid, $2::uuid, now(), $3::jsonb)
	`, tenantA, bareDeviceID, `{
		"collected_at": "`+time.Now().Add(-2*time.Minute).UTC().Format(time.RFC3339)+`",
		"collection_status": {"certificates": "complete"}
	}`); err != nil {
		t.Fatalf("insert raw_payloads (bare device): %v", err)
	}

	handler := PortalDeviceDetailHandler(pool)

	t.Run("full evidence returns identity and hardware with values and freshness", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/devices/"+fullDeviceID, nil)
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: emailA, TenantID: tenantA}))
		req = withChiParam(req, "deviceID", fullDeviceID)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}

		var resp portalDeviceDetailResp
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		if resp.Identity.Status != portalCollectionComplete {
			t.Errorf("identity.status = %q, want %q", resp.Identity.Status, portalCollectionComplete)
		}
		if resp.Identity.Serial != "C02XL0PAT2141" {
			t.Errorf("identity.serial = %q, want C02XL0PAT2141", resp.Identity.Serial)
		}
		if resp.Identity.HardwareModel != "Mac16,1" {
			t.Errorf("identity.hardware_model = %q, want Mac16,1", resp.Identity.HardwareModel)
		}
		if resp.Identity.ComputerName != "PAT-2141 MacBook Pro" {
			t.Errorf("identity.computer_name = %q, want %q", resp.Identity.ComputerName, "PAT-2141 MacBook Pro")
		}
		if resp.Identity.Architecture != "arm64" {
			t.Errorf("identity.architecture = %q, want arm64", resp.Identity.Architecture)
		}
		if resp.Identity.OSName != "macOS" || resp.Identity.OSVersion != "15.6" || resp.Identity.OSBuild != "24G84" {
			t.Errorf("identity os fields = %q/%q/%q, want macOS/15.6/24G84", resp.Identity.OSName, resp.Identity.OSVersion, resp.Identity.OSBuild)
		}
		if resp.Identity.AgentVersion != "0.19.22" {
			t.Errorf("identity.agent_version = %q, want 0.19.22", resp.Identity.AgentVersion)
		}
		if resp.Identity.FirstSeen == nil || resp.Identity.LastSeen == nil {
			t.Fatalf("identity first_seen/last_seen must be set, got %+v", resp.Identity)
		}
		if resp.Identity.Evidence.Freshness != "fresh" {
			t.Errorf("identity.evidence.freshness = %q, want fresh", resp.Identity.Evidence.Freshness)
		}
		if resp.Identity.Evidence.ObservedAt == nil || resp.Identity.Evidence.ReceivedAt == nil {
			t.Errorf("identity.evidence missing observed_at/received_at: %+v", resp.Identity.Evidence)
		}

		if resp.Hardware.Status != portalCollectionComplete {
			t.Errorf("hardware.status = %q, want %q", resp.Hardware.Status, portalCollectionComplete)
		}
		if resp.Hardware.CPU.Model != "Apple M4" || resp.Hardware.CPU.Cores != 10 {
			t.Errorf("hardware.cpu = %+v, want model Apple M4 / 10 cores", resp.Hardware.CPU)
		}
		if resp.Hardware.Memory.TotalGB != 24 {
			t.Errorf("hardware.memory.total_gb = %v, want 24", resp.Hardware.Memory.TotalGB)
		}
		if resp.Hardware.Disks.Status != portalCollectionComplete || len(resp.Hardware.Disks.Items) != 1 {
			t.Fatalf("hardware.disks = %+v, want 1 complete item", resp.Hardware.Disks)
		}
		if resp.Hardware.Disks.Items[0].Device != "disk0" || resp.Hardware.Disks.Items[0].SMARTStatus != "Verified" {
			t.Errorf("hardware.disks.items[0] = %+v, want disk0/Verified", resp.Hardware.Disks.Items[0])
		}
		if resp.Hardware.Volumes.Status != portalCollectionComplete || len(resp.Hardware.Volumes.Items) != 1 {
			t.Fatalf("hardware.volumes = %+v, want 1 complete item", resp.Hardware.Volumes)
		}
		if resp.Hardware.Volumes.Items[0].Mount != "/" || resp.Hardware.Volumes.Items[0].UsedPct != 93 {
			t.Errorf("hardware.volumes.items[0] = %+v, want mount / at 93%%", resp.Hardware.Volumes.Items[0])
		}
		if resp.Hardware.Battery.Status != portalCollectionComplete {
			t.Errorf("hardware.battery.status = %q, want %q", resp.Hardware.Battery.Status, portalCollectionComplete)
		}
		if resp.Hardware.Battery.Present == nil || !*resp.Hardware.Battery.Present {
			t.Errorf("hardware.battery.present = %v, want true", resp.Hardware.Battery.Present)
		}
		if resp.Hardware.Battery.CycleCount == nil || *resp.Hardware.Battery.CycleCount != 30 {
			t.Errorf("hardware.battery.cycle_count = %v, want 30", resp.Hardware.Battery.CycleCount)
		}
		if resp.Hardware.Battery.MaxCapacityPct == nil || *resp.Hardware.Battery.MaxCapacityPct != 100 {
			t.Errorf("hardware.battery.max_capacity_pct = %v, want 100", resp.Hardware.Battery.MaxCapacityPct)
		}

		if strings.Contains(rr.Body.String(), "hw_uuid") {
			t.Errorf("response body leaked hw_uuid: %s", rr.Body.String())
		}
	})

	t.Run("no hardware collection returns explicit not_collected, not zeros", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/devices/"+bareDeviceID, nil)
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: emailA, TenantID: tenantA}))
		req = withChiParam(req, "deviceID", bareDeviceID)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}

		var resp portalDeviceDetailResp
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		// Identity is still complete (this device reported a payload); only
		// hardware was never collected.
		if resp.Identity.Status != portalCollectionComplete {
			t.Errorf("identity.status = %q, want %q (device has reported)", resp.Identity.Status, portalCollectionComplete)
		}

		if resp.Hardware.Status != portalCollectionNotCollected {
			t.Errorf("hardware.status = %q, want %q", resp.Hardware.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.CPU.Status != portalCollectionNotCollected {
			t.Errorf("hardware.cpu.status = %q, want %q", resp.Hardware.CPU.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.Memory.Status != portalCollectionNotCollected {
			t.Errorf("hardware.memory.status = %q, want %q", resp.Hardware.Memory.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.Disks.Status != portalCollectionNotCollected {
			t.Errorf("hardware.disks.status = %q, want %q", resp.Hardware.Disks.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.Disks.Items == nil || len(resp.Hardware.Disks.Items) != 0 {
			t.Errorf("hardware.disks.items = %+v, want an empty (never null) array", resp.Hardware.Disks.Items)
		}
		if resp.Hardware.Volumes.Status != portalCollectionNotCollected {
			t.Errorf("hardware.volumes.status = %q, want %q", resp.Hardware.Volumes.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.Volumes.Items == nil || len(resp.Hardware.Volumes.Items) != 0 {
			t.Errorf("hardware.volumes.items = %+v, want an empty (never null) array", resp.Hardware.Volumes.Items)
		}
		if resp.Hardware.Battery.Status != portalCollectionNotCollected {
			t.Errorf("hardware.battery.status = %q, want %q", resp.Hardware.Battery.Status, portalCollectionNotCollected)
		}
		if resp.Hardware.Battery.Present != nil {
			t.Errorf("hardware.battery.present = %v, want nil (never a false standing in for absence)", resp.Hardware.Battery.Present)
		}
	})

	t.Run("cross-tenant request for another tenant's device still 404s", func(t *testing.T) {
		emailB := "customer-" + tenantB[:8] + "@pat2141.example"
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/devices/"+fullDeviceID, nil)
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: emailB, TenantID: tenantB}))
		req = withChiParam(req, "deviceID", fullDeviceID)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 for a device belonging to another tenant", rr.Code)
		}
		if strings.Contains(rr.Body.String(), "C02XL0PAT2141") || strings.Contains(rr.Body.String(), "Apple M4") {
			t.Errorf("404 body leaked tenant A's device data: %s", rr.Body.String())
		}
	})
}
