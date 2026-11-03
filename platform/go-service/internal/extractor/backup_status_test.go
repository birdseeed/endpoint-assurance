package extractor

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// backupStatusFromFixture pulls the "backup_status" sub-object out of a
// payload-fixtures JSON file and returns it as its own json.RawMessage, so
// parseBackupStatus can be exercised against the exact bytes an agent emits
// without dragging the rest of the payload along.
func backupStatusFromFixture(t *testing.T, dir, name string) json.RawMessage {
	t.Helper()
	data := readFixture(t, dir, name)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal fixture %s/%s: %v", dir, name, err)
	}
	bs, ok := m["backup_status"]
	if !ok {
		t.Fatalf("fixture %s/%s has no backup_status key", dir, name)
	}
	return bs
}

// ── parseBackupStatus: absent / null ──────────────────────────────────────────

func TestParseBackupStatus_AbsentOrNull(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{"nil slice (key absent)", nil},
		{"empty slice", json.RawMessage{}},
		{"JSON null", json.RawMessage(`null`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBackupStatus(tc.raw, nil); got != nil {
				t.Errorf("parseBackupStatus(%q) = %+v; want nil", tc.raw, got)
			}
		})
	}
}

// ── parseBackupStatus: real agent shapes ──────────────────────────────────────

// TestParseBackupStatus_MacOSTimeMachine exercises the exact shape emitted by
// macOS lib/backup.sh (PAT-679) for a healthy Time Machine backup — every
// field present, including an explicit JSON null for "notes".
func TestParseBackupStatus_MacOSTimeMachine(t *testing.T) {
	raw := backupStatusFromFixture(t, "valid", "with-backup-status-macos-time-machine.json")

	bs := parseBackupStatus(raw, nil)
	if bs == nil {
		t.Fatal("parseBackupStatus returned nil for a valid macOS Time Machine shape")
	}
	if !bs.HasBackup {
		t.Error("HasBackup: want true")
	}
	if bs.BackupType == nil || *bs.BackupType != "time_machine" {
		t.Errorf("BackupType: want \"time_machine\", got %v", bs.BackupType)
	}
	if bs.LastBackupAt == nil || *bs.LastBackupAt != "2026-07-08T09:00:00Z" {
		t.Errorf("LastBackupAt: got %v", bs.LastBackupAt)
	}
	if bs.LastBackupDaysAgo == nil || *bs.LastBackupDaysAgo != 2 {
		t.Errorf("LastBackupDaysAgo: want 2, got %v", bs.LastBackupDaysAgo)
	}
	if bs.Stale {
		t.Error("Stale: want false")
	}
	if bs.SyncOnly {
		t.Error("SyncOnly: want false")
	}
	if bs.Notes != nil {
		t.Errorf("Notes: want nil, got %v", *bs.Notes)
	}
}

// TestParseBackupStatus_MacOSThirdParty exercises the third-party (Backblaze)
// shape from lib/backup.sh — has_backup true but no queryable timestamp, so
// last_backup_at/last_backup_days_ago are explicit JSON null while notes
// carries the explanation.
func TestParseBackupStatus_MacOSThirdParty(t *testing.T) {
	raw := backupStatusFromFixture(t, "valid", "with-backup-status-third-party.json")

	bs := parseBackupStatus(raw, nil)
	if bs == nil {
		t.Fatal("parseBackupStatus returned nil for a valid macOS third-party shape")
	}
	if !bs.HasBackup {
		t.Error("HasBackup: want true")
	}
	if bs.BackupType == nil || *bs.BackupType != "backblaze" {
		t.Errorf("BackupType: want \"backblaze\", got %v", bs.BackupType)
	}
	if bs.LastBackupAt != nil {
		t.Errorf("LastBackupAt: want nil, got %v", *bs.LastBackupAt)
	}
	if bs.LastBackupDaysAgo != nil {
		t.Errorf("LastBackupDaysAgo: want nil, got %v", *bs.LastBackupDaysAgo)
	}
	if bs.Notes == nil || *bs.Notes != "backblaze detected; last backup timestamp not available" {
		t.Errorf("Notes: got %v", bs.Notes)
	}
}

// TestParseBackupStatus_WindowsFileHistory exercises the exact shape emitted
// by the Windows agent's InventoryBackupStatus (PAT-680) for File History.
// Unlike macOS, Windows omits null fields from the wire entirely
// (JsonIgnoreCondition.WhenWritingNull) rather than emitting an explicit
// null — this fixture has no "notes" key at all, and parseBackupStatus must
// still decode cleanly into a nil Notes pointer.
func TestParseBackupStatus_WindowsFileHistory(t *testing.T) {
	raw := backupStatusFromFixture(t, "valid", "with-backup-status-windows-file-history.json")

	bs := parseBackupStatus(raw, nil)
	if bs == nil {
		t.Fatal("parseBackupStatus returned nil for a valid Windows File History shape")
	}
	if !bs.HasBackup {
		t.Error("HasBackup: want true")
	}
	if bs.BackupType == nil || *bs.BackupType != "file_history" {
		t.Errorf("BackupType: want \"file_history\", got %v", bs.BackupType)
	}
	if bs.LastBackupDaysAgo == nil || *bs.LastBackupDaysAgo != 2 {
		t.Errorf("LastBackupDaysAgo: want 2, got %v", bs.LastBackupDaysAgo)
	}
	if bs.Notes != nil {
		t.Errorf("Notes: want nil (key was absent from the wire), got %v", *bs.Notes)
	}
}

// TestParseBackupStatus_WindowsOneDriveSyncOnly exercises the Windows
// OneDrive sync shape: sync_only true, has_backup false, and
// last_backup_at/last_backup_days_ago both omitted from the wire (not
// explicit null — Windows drops them entirely when null).
func TestParseBackupStatus_WindowsOneDriveSyncOnly(t *testing.T) {
	raw := backupStatusFromFixture(t, "edge", "backup-status-windows-onedrive-sync-only.json")

	bs := parseBackupStatus(raw, nil)
	if bs == nil {
		t.Fatal("parseBackupStatus returned nil for a valid Windows OneDrive shape")
	}
	if bs.HasBackup {
		t.Error("HasBackup: want false — OneDrive is sync, not backup")
	}
	if !bs.SyncOnly {
		t.Error("SyncOnly: want true")
	}
	if bs.BackupType == nil || *bs.BackupType != "onedrive_sync" {
		t.Errorf("BackupType: want \"onedrive_sync\", got %v", bs.BackupType)
	}
	if bs.LastBackupAt != nil {
		t.Errorf("LastBackupAt: want nil (key was absent from the wire), got %v", *bs.LastBackupAt)
	}
	if bs.LastBackupDaysAgo != nil {
		t.Errorf("LastBackupDaysAgo: want nil (key was absent from the wire), got %v", *bs.LastBackupDaysAgo)
	}
}

// ── parseBackupStatus: malformed section does not poison the snapshot ────────

// TestParseBackupStatus_Malformed_ReturnsNil exercises the defensive decode
// path directly: a backup_status object with a wrong-typed field must not
// panic or bubble an error all the way up — it is logged (when a logger is
// given) and treated exactly like "absent" (PAT-948).
func TestParseBackupStatus_Malformed_ReturnsNil(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "has_backup wrong type (string instead of bool)",
			raw:  json.RawMessage(`{"has_backup":"yes","stale":false,"sync_only":false}`),
		},
		{
			name: "last_backup_days_ago wrong type (string instead of int)",
			raw:  json.RawMessage(`{"has_backup":true,"stale":false,"sync_only":false,"last_backup_days_ago":"two"}`),
		},
		{
			name: "not even an object",
			raw:  json.RawMessage(`"time_machine"`),
		},
		{
			name: "truncated / invalid JSON",
			raw:  json.RawMessage(`{"has_backup":true,`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No logger (nil) must not panic.
			if got := parseBackupStatus(tc.raw, nil); got != nil {
				t.Errorf("parseBackupStatus(%s) = %+v; want nil", tc.raw, got)
			}
			// With a logger, still nil — the logger only adds a Warn line.
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			if got := parseBackupStatus(tc.raw, logger); got != nil {
				t.Errorf("parseBackupStatus(%s) with logger = %+v; want nil", tc.raw, got)
			}
		})
	}
}

// TestPayloadUnmarshal_MalformedBackupStatus_DoesNotPoisonOtherFields is the
// struct-unmarshal-level regression test for PAT-948's core robustness
// requirement: BackupStatus is carried as json.RawMessage precisely so that a
// malformed backup_status section (wrong field type) cannot abort the
// json.Unmarshal call in processRow and take the ENTIRE device snapshot down
// with it — the same failure mode PAT-871 fixed for a bad browser_extensions
// array element, applied here to a top-level section.
//
// Before this fix (i.e. if BackupStatus were a typed *backupStatusPart like
// HardwareHealth), this test would fail: json.Unmarshal would return a
// non-nil *json.UnmarshalTypeError, and processRow's "if err != nil { return
// ... }" guard (extractor.go) would reject the whole row before upsertDevice
// ever ran — even though every other field parsed just fine.
func TestPayloadUnmarshal_MalformedBackupStatus_DoesNotPoisonOtherFields(t *testing.T) {
	data := readFixture(t, "valid", "full.json")

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal base fixture: %v", err)
	}
	// Corrupt backup_status with a wrong-typed field — schema-invalid, but we
	// bypass ValidatePayload here deliberately: this test targets the
	// extractor's OWN defensive posture (defense in depth), not the ingestion
	// gate that would normally reject this payload with a 400 before it's
	// ever persisted to raw_payloads.
	m["backup_status"] = map[string]any{
		"has_backup": "yes", // should be bool
		"stale":      false,
		"sync_only":  false,
	}
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal patched fixture: %v", err)
	}

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("json.Unmarshal must succeed despite malformed backup_status (BackupStatus must be json.RawMessage, not a typed struct): %v", err)
	}

	// Every other section must still have unmarshaled correctly.
	if p.Device.Serial == "" {
		t.Error("Device.Serial: empty — other fields were not populated")
	}
	if p.OS.Name == "" {
		t.Error("OS.Name: empty — other fields were not populated")
	}
	if len(p.Apps) == 0 {
		t.Error("Apps: empty — other fields were not populated")
	}
	if p.SchemaVersion == 0 {
		t.Error("SchemaVersion: zero — other fields were not populated")
	}

	// BackupStatus itself carries the raw (malformed) bytes...
	if len(p.BackupStatus) == 0 {
		t.Fatal("BackupStatus: empty — expected the raw malformed bytes to be captured")
	}
	// ...but decoding it defensively yields nil, not a crash or propagated error.
	if bs := parseBackupStatus(p.BackupStatus, nil); bs != nil {
		t.Errorf("parseBackupStatus(malformed) = %+v; want nil", bs)
	}
}

// ── upsertDevice backup_status DB round-trip ──────────────────────────────────

// TestBackupStatusIngest is a DB round-trip test for backup_status through
// upsertDevice. It requires a real Postgres instance with all migrations
// applied (including 0087_device_backup_status), pointed to by TEST_DATABASE_URL.
// All writes are rolled back at the end.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestBackupStatusIngest -v
func TestBackupStatusIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping backup_status DB round-trip test")
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
		VALUES ('backup-status-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	basePayload := func(serial string, backupStatus json.RawMessage, hostname string) *payload {
		return &payload{
			SchemaVersion: 2,
			Agent:         "patched-collect",
			AgentVersion:  "0.14.0",
			TenantID:      tenantID,
			Device: devicePart{
				Serial:   serial,
				Hostname: hostname,
				HWModel:  "Mac14,2",
				Arch:     "arm64",
			},
			OS:           osPart{Name: "macOS", Version: "15.0", Build: "24A335"},
			BackupStatus: backupStatus,
		}
	}

	var deviceID string

	// ── First ingest: no backup_status (older agent) → column stays NULL ──
	p1 := basePayload("BKSTATUS001", nil, "backup-status-host")
	deviceID, _, err = upsertDevice(ctx, tx, tenantID, time.Now(), p1, nil)
	if err != nil {
		t.Fatalf("upsertDevice (absent backup_status): %v", err)
	}

	var backupRaw *string
	if err := tx.QueryRow(ctx, `SELECT backup_status::text FROM devices WHERE id = $1::uuid`, deviceID).Scan(&backupRaw); err != nil {
		t.Fatalf("select backup_status after first ingest: %v", err)
	}
	if backupRaw != nil {
		t.Errorf("backup_status after absent-field ingest: want NULL, got %v", *backupRaw)
	}

	// ── Second ingest: valid Time Machine shape → column populated ────────
	tmRaw := backupStatusFromFixture(t, "valid", "with-backup-status-macos-time-machine.json")
	p2 := basePayload("BKSTATUS001", tmRaw, "backup-status-host")
	deviceID2, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), p2, nil)
	if err != nil {
		t.Fatalf("upsertDevice (valid backup_status): %v", err)
	}
	if deviceID2 != deviceID {
		t.Fatalf("device id changed across re-ingest: %s vs %s", deviceID, deviceID2)
	}

	var gotHasBackup, gotStale, gotSyncOnly bool
	var gotBackupType *string
	var gotDaysAgo *int
	if err := tx.QueryRow(ctx, `
		SELECT (backup_status->>'has_backup')::boolean,
		       (backup_status->>'stale')::boolean,
		       (backup_status->>'sync_only')::boolean,
		       backup_status->>'backup_type',
		       (backup_status->>'last_backup_days_ago')::int
		FROM devices WHERE id = $1::uuid
	`, deviceID).Scan(&gotHasBackup, &gotStale, &gotSyncOnly, &gotBackupType, &gotDaysAgo); err != nil {
		t.Fatalf("select backup_status fields after second ingest: %v", err)
	}
	if !gotHasBackup {
		t.Error("has_backup: want true after Time Machine ingest")
	}
	if gotStale {
		t.Error("stale: want false")
	}
	if gotSyncOnly {
		t.Error("sync_only: want false")
	}
	if gotBackupType == nil || *gotBackupType != "time_machine" {
		t.Errorf("backup_type: want \"time_machine\", got %v", gotBackupType)
	}
	if gotDaysAgo == nil || *gotDaysAgo != 2 {
		t.Errorf("last_backup_days_ago: want 2, got %v", gotDaysAgo)
	}

	// ── Third ingest: malformed backup_status → does not poison the row ───
	// hostname changes in this ingest to prove the REST of upsertDevice still
	// writes correctly even when backup_status can't be parsed; the previous
	// good backup_status snapshot must survive untouched (COALESCE-preserve,
	// same treatment as pending_updates/hardware).
	malformed := json.RawMessage(`{"has_backup":"yes","stale":false,"sync_only":false}`)
	p3 := basePayload("BKSTATUS001", malformed, "backup-status-host-renamed")
	deviceID3, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), p3, nil)
	if err != nil {
		t.Fatalf("upsertDevice must not error on malformed backup_status (PAT-948): %v", err)
	}
	if deviceID3 != deviceID {
		t.Fatalf("device id changed across third ingest: %s vs %s", deviceID, deviceID3)
	}

	var hostnameAfter string
	var backupTypeAfter *string
	var hasBackupAfter bool
	if err := tx.QueryRow(ctx, `
		SELECT hostname, backup_status->>'backup_type', (backup_status->>'has_backup')::boolean
		FROM devices WHERE id = $1::uuid
	`, deviceID).Scan(&hostnameAfter, &backupTypeAfter, &hasBackupAfter); err != nil {
		t.Fatalf("select device after malformed ingest: %v", err)
	}
	if hostnameAfter != "backup-status-host-renamed" {
		t.Errorf("hostname: want the third ingest's value (proving the rest of the row still wrote), got %q", hostnameAfter)
	}
	if backupTypeAfter == nil || *backupTypeAfter != "time_machine" {
		t.Errorf("backup_type after malformed ingest: want the PRESERVED \"time_machine\" value (not clobbered), got %v", backupTypeAfter)
	}
	if !hasBackupAfter {
		t.Error("has_backup after malformed ingest: want true (preserved from the second ingest)")
	}
}
