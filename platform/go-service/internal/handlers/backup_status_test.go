package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"patched.im/api/internal/db"
)

// ---------------------------------------------------------------------------
// Pure-logic tests — no DB required
// ---------------------------------------------------------------------------

// TestDeviceBackupSummaryJSONFields verifies deviceBackupSummary marshals the
// full digest, including the derived bucket (PAT-948).
func TestDeviceBackupSummaryJSONFields(t *testing.T) {
	backupType := "time_machine"
	daysAgo := 2
	s := deviceBackupSummary{
		HasBackup:         true,
		BackupType:        &backupType,
		LastBackupDaysAgo: &daysAgo,
		Stale:             false,
		SyncOnly:          false,
		Bucket:            "ok",
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["bucket"] != "ok" {
		t.Errorf("bucket: got %v, want \"ok\"", got["bucket"])
	}
	if got["has_backup"] != true {
		t.Errorf("has_backup: got %v, want true", got["has_backup"])
	}
	if got["backup_type"] != "time_machine" {
		t.Errorf("backup_type: got %v, want \"time_machine\"", got["backup_type"])
	}
	// notes/last_backup_at omitted (omitempty, nil pointer) — must be absent, not null.
	if _, ok := got["notes"]; ok {
		t.Error("notes: should be omitted when nil, not present")
	}
	if _, ok := got["last_backup_at"]; ok {
		t.Error("last_backup_at: should be omitted when nil, not present")
	}
}

// TestTenantBackupStatusCountsJSONFields verifies the aggregate counts block
// always serialises all four buckets, even when zero.
func TestTenantBackupStatusCountsJSONFields(t *testing.T) {
	c := tenantBackupStatusCounts{}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"ok", "stale", "none", "sync_only"} {
		v, ok := got[k]
		if !ok {
			t.Errorf("key %q missing", k)
			continue
		}
		if v != float64(0) {
			t.Errorf("key %q: got %v, want 0", k, v)
		}
	}
}

// ---------------------------------------------------------------------------
// DB round-trip tests — skipped when TEST_DATABASE_URL is not set
// ---------------------------------------------------------------------------

// TestBackupStatusServingAndAggregates is a DB round-trip test covering
// PAT-948's three serving surfaces in one pass: GET /admin/tenants/overview
// (per-tenant aggregate counts), GET /admin/tenants/{id}/devices (per-device
// digest + bucket in the fleet roster), and GET /admin/devices/{id} (full
// backup_status detail + derived bucket). One tenant, five devices — one per
// bucket plus one that predates PAT-679/680 (backup_status NULL) to prove
// that device is excluded from every aggregate count and serves no `backup`
// key at all.
func TestBackupStatusServingAndAggregates(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping backup_status serving DB round-trip test")
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('backup-status-serving-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	insertDevice := func(serial string, backupStatus *string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, os, serial, hostname, backup_status)
			VALUES ($1::uuid, 'macOS', $2, $2, $3::jsonb)
			RETURNING id::text
		`, tenantID, serial, backupStatus).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", serial, err)
		}
		return id
	}
	strp := func(s string) *string { return &s }

	okID := insertDevice("BKSRV-OK", strp(`{"has_backup":true,"backup_type":"time_machine","last_backup_at":"2026-07-08T09:00:00Z","last_backup_days_ago":2,"stale":false,"sync_only":false,"notes":null}`))
	staleID := insertDevice("BKSRV-STALE", strp(`{"has_backup":true,"backup_type":"time_machine","last_backup_at":"2026-12-01T09:00:00Z","last_backup_days_ago":39,"stale":true,"sync_only":false,"notes":null}`))
	noneID := insertDevice("BKSRV-NONE", strp(`{"has_backup":false,"backup_type":null,"last_backup_at":null,"last_backup_days_ago":null,"stale":false,"sync_only":false,"notes":"No backup solution detected"}`))
	syncID := insertDevice("BKSRV-SYNC", strp(`{"has_backup":false,"backup_type":"onedrive_sync","last_backup_at":null,"last_backup_days_ago":null,"stale":false,"sync_only":true,"notes":"OneDrive sync detected; sync is not a substitute for backup"}`))
	absentID := insertDevice("BKSRV-ABSENT", nil)

	// ── GET /admin/tenants/overview — aggregate counts ────────────────────
	t.Run("tenants overview aggregate counts", func(t *testing.T) {
		h := TenantsOverviewHandler(pool)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/overview", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
		}

		var resp tenantsOverviewResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var entry *tenantOverviewEntry
		for i := range resp.Tenants {
			if resp.Tenants[i].ID == tenantID {
				entry = &resp.Tenants[i]
			}
		}
		if entry == nil {
			t.Fatal("tenant not found in overview response")
		}
		if entry.DeviceCount != 5 {
			t.Errorf("device_count: got %d, want 5", entry.DeviceCount)
		}
		want := tenantBackupStatusCounts{OK: 1, Stale: 1, None: 1, SyncOnly: 1}
		if entry.BackupStatusCounts != want {
			t.Errorf("backup_status_counts: got %+v, want %+v (the absent device must contribute to none of the four buckets)", entry.BackupStatusCounts, want)
		}
	})

	// ── GET /admin/tenants/{id}/devices — per-device digest + bucket ──────
	t.Run("tenant devices per-device digest", func(t *testing.T) {
		h := TenantDevicesHandler(pool)
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/devices", nil)
		req = withChiParam(req, "tenantID", tenantID)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
		}

		var resp tenantDevicesResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		byID := map[string]tenantDeviceEntry{}
		for _, d := range resp.Devices {
			byID[d.ID] = d
		}

		cases := []struct {
			id         string
			wantBucket string
			wantNil    bool
		}{
			{okID, "ok", false},
			{staleID, "stale", false},
			{noneID, "none", false},
			{syncID, "sync_only", false},
			{absentID, "", true},
		}
		for _, tc := range cases {
			d, ok := byID[tc.id]
			if !ok {
				t.Errorf("device %s missing from roster", tc.id)
				continue
			}
			if tc.wantNil {
				if d.Backup != nil {
					t.Errorf("device %s: Backup = %+v, want nil (predates PAT-679/680)", tc.id, d.Backup)
				}
				continue
			}
			if d.Backup == nil {
				t.Errorf("device %s: Backup is nil, want bucket %q", tc.id, tc.wantBucket)
				continue
			}
			if d.Backup.Bucket != tc.wantBucket {
				t.Errorf("device %s: bucket = %q, want %q", tc.id, d.Backup.Bucket, tc.wantBucket)
			}
		}
	})

	// ── GET /admin/devices/{id} — full detail + derived bucket ────────────
	t.Run("device detail full backup section", func(t *testing.T) {
		h := DeviceDetailHandler(pool)

		req := httptest.NewRequest(http.MethodGet, "/admin/devices/"+okID, nil)
		req = withChiParam(req, "deviceID", okID)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
		}
		var resp deviceDetailResp
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Backup == nil {
			t.Fatal("Backup is nil for a device with a valid backup_status")
		}
		if !resp.Backup.HasBackup {
			t.Error("HasBackup: want true")
		}
		if resp.Backup.BackupType == nil || *resp.Backup.BackupType != "time_machine" {
			t.Errorf("BackupType: got %v, want \"time_machine\"", resp.Backup.BackupType)
		}
		if resp.Backup.Bucket != "ok" {
			t.Errorf("Bucket: got %q, want \"ok\"", resp.Backup.Bucket)
		}

		// The device that predates PAT-679/680 must omit the backup key
		// entirely (nil, not an empty/zero object).
		req2 := httptest.NewRequest(http.MethodGet, "/admin/devices/"+absentID, nil)
		req2 = withChiParam(req2, "deviceID", absentID)
		rr2 := httptest.NewRecorder()
		h.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Fatalf("got %d, body: %s", rr2.Code, rr2.Body.String())
		}
		var resp2 deviceDetailResp
		if err := json.NewDecoder(rr2.Body).Decode(&resp2); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp2.Backup != nil {
			t.Errorf("Backup: got %+v, want nil for a device that predates PAT-679/680", resp2.Backup)
		}
	})
}
