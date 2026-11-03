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

// osUpdateBasePayload returns a minimal, otherwise-valid v2 payload JSON
// template with the given os_update fragment spliced in (or omitted
// entirely when osUpdate is ""), matching the pattern used across the other
// ValidatePayload table-driven tests in this package (findings_test.go,
// agent_health_test.go).
func osUpdateBasePayload(osUpdate string) []byte {
	body := `{
		"schema_version": 2, "agent": "t", "agent_version": "1", "tenant_id": "t",
		"collected_at": "2026-09-17T00:00:00Z",
		"device": {"serial":"s","hw_uuid":"u","hostname":"h","hw_model":"m","arch":"arm64","last_boot":"2026-09-17T00:00:00Z"},
		"hardware": {"cpu_model":"c","cpu_cores":8,"ram_gb":8,"disk_total_gb":1,"disk_free_gb":1},
		"os": {"name":"macOS","version":"15.5","build":"24F74"},
		"compliance": {}, "security_tools": [], "system_extensions": [], "background_items": [],
		"icloud": {"signed_in":"Yes"},
		"apps": [{"name":"a","version":"1","bundle_id":"b"}]`
	if osUpdate != "" {
		body += `, "os_update": ` + osUpdate
	}
	body += `}`
	return []byte(body)
}

// TestValidatePayload_OSUpdateAbsent_StillValidates is the PAT-1806 contract
// test: a payload that omits os_update entirely — every payload from every
// agent today, since neither endpoint agent sends this key yet — must
// validate exactly as it did before this field existed. The schema addition
// is additive, never breaking.
func TestValidatePayload_OSUpdateAbsent_StillValidates(t *testing.T) {
	if err := ValidatePayload(osUpdateBasePayload("")); err != nil {
		t.Errorf("ValidatePayload with os_update absent: want nil error, got %v", err)
	}
}

func TestValidatePayload_OSUpdate(t *testing.T) {
	cases := []struct {
		name     string
		osUpdate string
		wantErr  bool
	}{
		{
			name: "valid, every field present",
			osUpdate: `{
				"installed_os": "15.5", "latest_os": "15.6.1", "target_os": "15.6.1",
				"state": "update_recommended", "severity": "high",
				"security_relevant": true, "actively_exploited": false,
				"deadline": "2026-10-01T00:00:00Z", "deferrals_remaining": 3, "release_age_days": 42,
				"checked_at": "2026-09-17T00:00:00Z"
			}`,
			wantErr: false,
		},
		{
			name: "valid, latest_os/deadline/release_age_days explicit null (macOS wire shape)",
			osUpdate: `{
				"installed_os": "15.6.1", "latest_os": null, "target_os": "15.6.1",
				"state": "up_to_date", "severity": "none",
				"security_relevant": false, "actively_exploited": false,
				"deadline": null, "deferrals_remaining": 0, "release_age_days": null,
				"checked_at": "2026-09-17T00:00:00Z"
			}`,
			wantErr: false,
		},
		{
			name: "valid, nullable fields omitted entirely (Windows wire shape)",
			osUpdate: `{
				"installed_os": "15.6.1", "target_os": "15.6.1",
				"state": "up_to_date", "severity": "none",
				"security_relevant": false, "actively_exploited": false,
				"deferrals_remaining": 0,
				"checked_at": "2026-09-17T00:00:00Z"
			}`,
			wantErr: false,
		},
		{
			name:     "missing required installed_os",
			osUpdate: `{"target_os":"15.6.1","state":"up_to_date","severity":"none","security_relevant":false,"actively_exploited":false,"deferrals_remaining":0,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "missing required security_relevant",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			// PAT-2123: target_os is independently optional and nullable —
			// the Windows agent reports a pending update
			// (state=update_required) before WUA has resolved the target
			// build, and omits the key entirely in that case.
			name:     "target_os absent (nullable — pending update, target unknown)",
			osUpdate: `{"installed_os":"15.5","state":"update_required","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  false,
		},
		{
			// PAT-2123: explicit null carries the same meaning as absent —
			// macOS's wire-shape convention of always emitting the key.
			name:     "target_os null (nullable — pending update, target unknown)",
			osUpdate: `{"installed_os":"15.5","target_os":null,"state":"update_required","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  false,
		},
		{
			name:     "target_os empty string (still rejected when present)",
			osUpdate: `{"installed_os":"15.5","target_os":"","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "target_os wrong type (number, still rejected when present)",
			osUpdate: `{"installed_os":"15.5","target_os":15.6,"state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "missing required severity",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "severity null (no longer nullable)",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":null,"security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "missing required deferrals_remaining",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "deferrals_remaining null (no longer nullable)",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":null,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "missing required checked_at",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3}`,
			wantErr:  true,
		},
		{
			name:     "security_relevant wrong type",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":"yes","actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "actively_exploited wrong type",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":"no","deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "deferrals_remaining wrong type (float, not integer)",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":1.5,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "deferrals_remaining negative",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":-1,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "release_age_days wrong type (string)",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"release_age_days":"42","checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "release_age_days negative",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"release_age_days":-1,"checked_at":"2026-09-17T00:00:00Z"}`,
			wantErr:  true,
		},
		{
			name:     "checked_at malformed RFC3339 timestamp",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"not-a-timestamp"}`,
			wantErr:  true,
		},
		{
			name:     "additional property rejected",
			osUpdate: `{"installed_os":"15.5","target_os":"15.6.1","state":"update_recommended","severity":"high","security_relevant":true,"actively_exploited":false,"deferrals_remaining":3,"checked_at":"2026-09-17T00:00:00Z","made_up_field":true}`,
			wantErr:  true,
		},
		{
			name:     "not an object",
			osUpdate: `"behind"`,
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(osUpdateBasePayload(tc.osUpdate))
			if tc.wantErr && err == nil {
				t.Error("expected validation to reject payload but it passed")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected validation to pass, got: %v", err)
			}
		})
	}
}

// ── parseOSUpdate: absent / null ───────────────────────────────────────────

func TestParseOSUpdate_AbsentOrNull(t *testing.T) {
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
			if got := parseOSUpdate(tc.raw, nil); got != nil {
				t.Errorf("parseOSUpdate(%q) = %+v; want nil", tc.raw, got)
			}
		})
	}
}

// ── parseOSUpdate: valid shape ─────────────────────────────────────────────

func TestParseOSUpdate_Valid(t *testing.T) {
	raw := json.RawMessage(`{
		"installed_os": "15.5", "latest_os": "15.6.1", "target_os": "15.6.1",
		"state": "update_recommended", "severity": "high",
		"security_relevant": true, "actively_exploited": false,
		"deadline": "2026-10-01T00:00:00Z", "deferrals_remaining": 3, "release_age_days": 42,
		"checked_at": "2026-09-17T00:00:00Z"
	}`)
	o := parseOSUpdate(raw, nil)
	if o == nil {
		t.Fatal("parseOSUpdate: got nil for valid input")
	}
	if o.InstalledOS != "15.5" {
		t.Errorf("InstalledOS = %q, want %q", o.InstalledOS, "15.5")
	}
	if o.LatestOS == nil || *o.LatestOS != "15.6.1" {
		t.Errorf("LatestOS = %v, want \"15.6.1\"", o.LatestOS)
	}
	if o.TargetOS == nil || *o.TargetOS != "15.6.1" {
		t.Errorf("TargetOS = %v, want \"15.6.1\"", o.TargetOS)
	}
	if o.State != "update_recommended" {
		t.Errorf("State = %q, want %q", o.State, "update_recommended")
	}
	if o.Severity != "high" {
		t.Errorf("Severity = %q, want %q", o.Severity, "high")
	}
	if !o.SecurityRelevant {
		t.Error("SecurityRelevant = false, want true")
	}
	if o.ActivelyExploited {
		t.Error("ActivelyExploited = true, want false")
	}
	if o.Deadline == nil || *o.Deadline != "2026-10-01T00:00:00Z" {
		t.Errorf("Deadline = %v, want \"2026-10-01T00:00:00Z\"", o.Deadline)
	}
	if o.DeferralsRemaining != 3 {
		t.Errorf("DeferralsRemaining = %v, want 3", o.DeferralsRemaining)
	}
	if o.ReleaseAgeDays == nil || *o.ReleaseAgeDays != 42 {
		t.Errorf("ReleaseAgeDays = %v, want 42", o.ReleaseAgeDays)
	}
	if o.CheckedAt != "2026-09-17T00:00:00Z" {
		t.Errorf("CheckedAt = %q, want %q", o.CheckedAt, "2026-09-17T00:00:00Z")
	}
}

// TestParseOSUpdate_LatestOSNull covers the one field that flipped direction
// in PAT-1862's contract fix: latest_os is now nullable (null when SOFA/WUA
// is unavailable), unlike severity/deferrals_remaining which flipped the
// other way (nullable -> always present). target_os later rejoined the
// nullable group under PAT-2123 — see TestParseOSUpdate_TargetOSNull below.
func TestParseOSUpdate_LatestOSNull(t *testing.T) {
	raw := json.RawMessage(`{
		"installed_os": "15.5", "latest_os": null, "target_os": "15.6.1",
		"state": "unknown", "severity": "none",
		"security_relevant": false, "actively_exploited": false,
		"deferrals_remaining": 0, "checked_at": "2026-09-17T00:00:00Z"
	}`)
	o := parseOSUpdate(raw, nil)
	if o == nil {
		t.Fatal("parseOSUpdate: got nil for valid input")
	}
	if o.LatestOS != nil {
		t.Errorf("LatestOS = %v, want nil", *o.LatestOS)
	}
}

// TestParseOSUpdate_TargetOSNull is the PAT-2123 counterpart: a Windows
// agent reporting a pending update before WUA has resolved the target build
// sends target_os as null (or omits the key — see the "target_os absent"
// case below). Both must decode to a nil TargetOS, never an empty string,
// so upsertOSUpdate writes SQL NULL rather than "".
func TestParseOSUpdate_TargetOSNull(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "target_os explicit null",
			raw: json.RawMessage(`{
				"installed_os": "15.5", "target_os": null,
				"state": "update_required", "severity": "high",
				"security_relevant": true, "actively_exploited": false,
				"deferrals_remaining": 0, "checked_at": "2026-09-17T00:00:00Z"
			}`),
		},
		{
			name: "target_os absent",
			raw: json.RawMessage(`{
				"installed_os": "15.5",
				"state": "update_required", "severity": "high",
				"security_relevant": true, "actively_exploited": false,
				"deferrals_remaining": 0, "checked_at": "2026-09-17T00:00:00Z"
			}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := parseOSUpdate(tc.raw, nil)
			if o == nil {
				t.Fatal("parseOSUpdate: got nil for valid input")
			}
			if o.TargetOS != nil {
				t.Errorf("TargetOS = %v, want nil", *o.TargetOS)
			}
		})
	}
}

// ── parseOSUpdate: malformed ────────────────────────────────────────────────

func TestParseOSUpdate_Malformed_ReturnsNil(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "security_relevant wrong type (string instead of bool)",
			raw:  json.RawMessage(`{"installed_os":"15.5","latest_os":"15.6","state":"behind","security_relevant":"yes","actively_exploited":false}`),
		},
		{
			name: "not even an object",
			raw:  json.RawMessage(`"behind"`),
		},
		{
			name: "truncated / invalid JSON",
			raw:  json.RawMessage(`{"installed_os":"15.5",`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOSUpdate(tc.raw, nil); got != nil {
				t.Errorf("parseOSUpdate(%s) = %+v; want nil", tc.raw, got)
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			if got := parseOSUpdate(tc.raw, logger); got != nil {
				t.Errorf("parseOSUpdate(%s) with logger = %+v; want nil", tc.raw, got)
			}
		})
	}
}

// TestPayloadUnmarshal_MalformedOSUpdate_DoesNotPoisonOtherFields is the
// struct-unmarshal-level regression test for the same robustness requirement
// backup_status/PAT-948 established: OSUpdate is carried as json.RawMessage
// precisely so a malformed os_update section (wrong field type) cannot abort
// the json.Unmarshal call in processRow and take the entire device snapshot
// down with it.
func TestPayloadUnmarshal_MalformedOSUpdate_DoesNotPoisonOtherFields(t *testing.T) {
	data := readFixture(t, "valid", "full.json")

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal base fixture: %v", err)
	}
	// Bypass ValidatePayload deliberately — this test targets the extractor's
	// own defensive posture (defense in depth), not the ingestion gate that
	// would normally reject this payload with a 400 before persistence.
	m["os_update"] = map[string]any{
		"installed_os":       "15.5",
		"latest_os":          "15.6.1",
		"state":              "behind",
		"security_relevant":  "yes", // should be bool
		"actively_exploited": false,
	}
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal patched fixture: %v", err)
	}

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("json.Unmarshal must succeed despite malformed os_update (OSUpdate must be json.RawMessage, not a typed struct): %v", err)
	}

	if p.Device.Serial == "" {
		t.Error("Device.Serial: empty — other fields were not populated")
	}
	if len(p.Apps) == 0 {
		t.Error("Apps: empty — other fields were not populated")
	}

	if len(p.OSUpdate) == 0 {
		t.Fatal("OSUpdate: empty — expected the raw malformed bytes to be captured")
	}
	if o := parseOSUpdate(p.OSUpdate, nil); o != nil {
		t.Errorf("parseOSUpdate(malformed) = %+v; want nil", o)
	}
}

// TestOSUpdateIngest is the PAT-1806 DB round-trip acceptance test, mirroring
// TestBackupStatusIngest above: absence must never zero a previously-stored
// row, and presence must correctly persist. Requires a real Postgres
// instance with all migrations applied (including
// 0144_device_os_update.sql), pointed to by TEST_DATABASE_URL. All writes are
// rolled back at the end — this test never applies the migration itself.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestOSUpdateIngest -v
func TestOSUpdateIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping os_update DB round-trip test")
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
		VALUES ('os-update-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	p := &payload{
		SchemaVersion: 2,
		Agent:         "patched-collect",
		AgentVersion:  "0.14.0",
		TenantID:      tenantID,
		Device: devicePart{
			Serial:   "OSUPDATE001",
			Hostname: "os-update-host",
			HWModel:  "Mac14,2",
			Arch:     "arm64",
		},
		OS: osPart{Name: "macOS", Version: "15.0", Build: "24A335"},
	}
	deviceID, _, err := upsertDevice(ctx, tx, tenantID, time.Now(), p, nil)
	if err != nil {
		t.Fatalf("upsertDevice: %v", err)
	}

	// ── First ingest: os_update absent → no device_os_update row at all ────
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(nil, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (absent): %v", err)
	}
	var rowCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count device_os_update after absent ingest: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("device_os_update row count after absent-field ingest: want 0, got %d", rowCount)
	}

	// ── Second ingest: valid behind/security-relevant verdict → row created ─
	raw1 := json.RawMessage(`{
		"installed_os": "15.5", "latest_os": "15.6.1", "target_os": "15.6.1",
		"state": "behind", "severity": "high",
		"security_relevant": true, "actively_exploited": false,
		"deadline": "2026-10-01T00:00:00Z", "deferrals_remaining": 3, "release_age_days": 42
	}`)
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(raw1, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (valid): %v", err)
	}

	var gotState string
	var gotSecurityRelevant, gotActivelyExploited bool
	var gotDeferrals *int
	if err := tx.QueryRow(ctx, `
		SELECT state, security_relevant, actively_exploited, deferrals_remaining
		FROM device_os_update WHERE device_id = $1::uuid
	`, deviceID).Scan(&gotState, &gotSecurityRelevant, &gotActivelyExploited, &gotDeferrals); err != nil {
		t.Fatalf("select device_os_update after second ingest: %v", err)
	}
	if gotState != "behind" {
		t.Errorf("state: want \"behind\", got %q", gotState)
	}
	if !gotSecurityRelevant {
		t.Error("security_relevant: want true")
	}
	if gotActivelyExploited {
		t.Error("actively_exploited: want false")
	}
	if gotDeferrals == nil || *gotDeferrals != 3 {
		t.Errorf("deferrals_remaining: want 3, got %v", gotDeferrals)
	}

	// ── Third ingest: os_update absent again → PREVIOUS row untouched ──────
	// This is the load-bearing assertion: an agent payload that doesn't carry
	// os_update (every agent today) must never zero out a previously-stored
	// verdict.
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(nil, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (absent again): %v", err)
	}
	var gotStateAfter string
	if err := tx.QueryRow(ctx, `SELECT state FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&gotStateAfter); err != nil {
		t.Fatalf("select device_os_update after third (absent) ingest: %v", err)
	}
	if gotStateAfter != "behind" {
		t.Errorf("state after absent ingest: want preserved \"behind\", got %q", gotStateAfter)
	}

	// ── Fourth ingest: state flips to current → row updates, not duplicates ─
	raw2 := json.RawMessage(`{
		"installed_os": "15.6.1", "latest_os": "15.6.1",
		"state": "current",
		"security_relevant": false, "actively_exploited": false
	}`)
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(raw2, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (current): %v", err)
	}
	var rowCountAfter int
	var gotStateCurrent string
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&rowCountAfter); err != nil {
		t.Fatalf("count device_os_update after fourth ingest: %v", err)
	}
	if rowCountAfter != 1 {
		t.Errorf("device_os_update row count after fourth ingest: want 1 (upsert, not append), got %d", rowCountAfter)
	}
	if err := tx.QueryRow(ctx, `SELECT state FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&gotStateCurrent); err != nil {
		t.Fatalf("select device_os_update after fourth ingest: %v", err)
	}
	if gotStateCurrent != "current" {
		t.Errorf("state after fourth ingest: want \"current\", got %q", gotStateCurrent)
	}
}

// ── upsertOSUpdate: scratch-schema round trip (no real migration applied) ──
//
// TestOSUpdateIngest above needs a fully-migrated TEST_DATABASE_URL (CI's
// integration job — see docs/TESTING.md); it is not run as part of this
// change since migrations/0144_device_os_update.sql was deliberately never
// applied to any real database per this ticket's brief. This test instead
// exercises upsertOSUpdate directly against a throwaway scratch schema
// defining only the minimal device_os_update shape (same convention
// internal/report's pat1805Pool/pat1806Pool use), gated on
// TEST_DATABASE_URL, so the ON CONFLICT +
// COALESCE-preserve behaviour is actually verified against real Postgres
// without depending on migrations having been applied anywhere.

func pat1806ExtractorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping scratch-schema os_update DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	const schema = "pat1806_extractor_test"
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`,
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		// Mirrors migrations/0144_device_os_update.sql +
		// 0147_device_os_update_checked_at.sql exactly. Migration 0147
		// relaxes latest_os to nullable because a SOFA/WUA outage is a valid
		// agent report, and adds checked_at.
		`CREATE TABLE ` + schema + `.device_os_update (
			id                   BIGSERIAL   PRIMARY KEY,
			device_id            UUID        NOT NULL REFERENCES ` + schema + `.devices(id) ON DELETE CASCADE,
			installed_os         TEXT        NOT NULL,
			latest_os            TEXT,
			target_os            TEXT,
			state                TEXT        NOT NULL,
			severity             TEXT,
			security_relevant    BOOLEAN     NOT NULL DEFAULT false,
			actively_exploited   BOOLEAN     NOT NULL DEFAULT false,
			deferrals_remaining  INTEGER,
			release_age_days     INTEGER,
			deadline             TIMESTAMPTZ,
			checked_at           TIMESTAMPTZ,
			reported_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (device_id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	return pool
}

func TestUpsertOSUpdate_ScratchSchema_AbsentThenPresentThenAbsentPreserves(t *testing.T) {
	pool := pat1806ExtractorPool(t)
	ctx := context.Background()

	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices DEFAULT VALUES RETURNING id::text`).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Absent → no row.
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(nil, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (absent): %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&count); err != nil {
		t.Fatalf("count after absent: %v", err)
	}
	if count != 0 {
		t.Fatalf("row count after absent ingest: want 0, got %d", count)
	}

	// Present → row created with the given fields, including a parsed deadline.
	raw := json.RawMessage(`{
		"installed_os": "15.5", "latest_os": "15.6.1", "target_os": "15.6.1",
		"state": "behind", "severity": "high",
		"security_relevant": true, "actively_exploited": true,
		"deadline": "2026-10-01T00:00:00Z", "deferrals_remaining": 2, "release_age_days": 10
	}`)
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(raw, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (present): %v", err)
	}
	var state, targetOS, severity string
	var secRel, actExp bool
	var deferrals, releaseAge int
	var deadline time.Time
	if err := tx.QueryRow(ctx, `
		SELECT state, target_os, severity, security_relevant, actively_exploited, deferrals_remaining, release_age_days, deadline
		FROM device_os_update WHERE device_id = $1::uuid
	`, deviceID).Scan(&state, &targetOS, &severity, &secRel, &actExp, &deferrals, &releaseAge, &deadline); err != nil {
		t.Fatalf("select after present ingest: %v", err)
	}
	if state != "behind" || targetOS != "15.6.1" || severity != "high" {
		t.Errorf("state/target_os/severity = %q/%q/%q, want behind/15.6.1/high", state, targetOS, severity)
	}
	if !secRel || !actExp {
		t.Errorf("security_relevant/actively_exploited = %v/%v, want true/true", secRel, actExp)
	}
	if deferrals != 2 || releaseAge != 10 {
		t.Errorf("deferrals_remaining/release_age_days = %d/%d, want 2/10", deferrals, releaseAge)
	}
	if deadline.UTC().Format(time.RFC3339) != "2026-10-01T00:00:00Z" {
		t.Errorf("deadline = %v, want 2026-10-01T00:00:00Z", deadline)
	}

	// Absent again → PRESERVED, not zeroed. This is the load-bearing
	// assertion: an agent payload without os_update (every agent today) must
	// never clobber a previously-stored verdict.
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(nil, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate (absent again): %v", err)
	}
	var stateAfter string
	var countAfter int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&countAfter); err != nil {
		t.Fatalf("count after absent-again: %v", err)
	}
	if countAfter != 1 {
		t.Fatalf("row count after absent-again ingest: want 1 (still the one row from the present ingest), got %d", countAfter)
	}
	if err := tx.QueryRow(ctx, `SELECT state FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&stateAfter); err != nil {
		t.Fatalf("select after absent-again: %v", err)
	}
	if stateAfter != "behind" {
		t.Errorf("state after absent-again ingest: want preserved \"behind\", got %q", stateAfter)
	}
}

func TestUpsertOSUpdate_ScratchSchema_NullLatestOSAndCheckedAtPersist(t *testing.T) {
	pool := pat1806ExtractorPool(t)
	ctx := context.Background()

	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices DEFAULT VALUES RETURNING id::text`).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const checkedAtRaw = "2026-09-17T12:34:56.789123Z"
	wantCheckedAt, err := time.Parse(time.RFC3339, checkedAtRaw)
	if err != nil {
		t.Fatalf("parse expected checked_at: %v", err)
	}
	raw := json.RawMessage(`{
		"installed_os": "15.6.1", "latest_os": null, "target_os": "15.6.1",
		"state": "up_to_date", "severity": "none",
		"security_relevant": false, "actively_exploited": false,
		"deferrals_remaining": 0, "checked_at": "` + checkedAtRaw + `"
	}`)
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(raw, nil), nil); err != nil {
		t.Fatalf("upsertOSUpdate: %v", err)
	}

	var latestOS *string
	var gotCheckedAt time.Time
	if err := tx.QueryRow(ctx, `
		SELECT latest_os, checked_at
		FROM device_os_update WHERE device_id = $1::uuid
	`, deviceID).Scan(&latestOS, &gotCheckedAt); err != nil {
		t.Fatalf("select persisted os_update: %v", err)
	}
	if latestOS != nil {
		t.Errorf("latest_os = %q, want NULL", *latestOS)
	}
	if !gotCheckedAt.Equal(wantCheckedAt) {
		t.Errorf("checked_at = %s, want exact instant %s", gotCheckedAt.Format(time.RFC3339Nano), wantCheckedAt.Format(time.RFC3339Nano))
	}
}

func TestUpsertOSUpdate_ScratchSchema_MalformedDeadline_StillPersistsRestOfSection(t *testing.T) {
	pool := pat1806ExtractorPool(t)
	ctx := context.Background()

	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices DEFAULT VALUES RETURNING id::text`).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	raw := json.RawMessage(`{
		"installed_os": "15.5", "latest_os": "15.6.1",
		"state": "behind", "security_relevant": true, "actively_exploited": false,
		"deadline": "not-a-real-timestamp"
	}`)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(raw, logger), logger); err != nil {
		t.Fatalf("upsertOSUpdate must not fail on an unparseable deadline: %v", err)
	}

	var state string
	var deadline *time.Time
	if err := tx.QueryRow(ctx, `SELECT state, deadline FROM device_os_update WHERE device_id = $1::uuid`, deviceID).Scan(&state, &deadline); err != nil {
		t.Fatalf("select: %v", err)
	}
	if state != "behind" {
		t.Errorf("state: want \"behind\" (rest of section must persist), got %q", state)
	}
	if deadline != nil {
		t.Errorf("deadline: want NULL for an unparseable value, got %v", *deadline)
	}
}
