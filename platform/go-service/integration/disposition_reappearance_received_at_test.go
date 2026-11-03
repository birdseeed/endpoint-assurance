//go:build integration

package integration

// PAT-2108: checkAndSupersedeReappearedDisposition
// (internal/extractor/disposition_reappearance.go) must decide reappearance
// against the report's own raw_payloads.received_at, not against
// time.Now().UTC() at the moment the extractor happens to process the row.
// When extraction falls behind, a report that was actually received BEFORE
// a disposition was recorded, but only gets extracted afterwards, must never
// read as evidence of reappearance — that would raise a false finding
// against a decision the customer already made. A report genuinely received
// after the disposition must still raise the finding.
//
// These tests insert into raw_payloads directly (same technique as
// last_seen_received_at_test.go, PAT-2102) because POST /v1/inventory always
// stamps received_at = now() — there is no way to make a live POST arrive
// with a backdated received_at, and inserting directly is exactly the shape
// of a real backlog: the row existed with its true received_at all along,
// only the extractor's processing of it ran late.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
)

func pat2108HWUUID() string {
	h := randomHex(16)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func pat2108Body(t *testing.T, tenantID, hwUUID string, collectedAt time.Time) []byte {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "full.json"), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tenantID
	p["collected_at"] = collectedAt.UTC().Format(time.RFC3339)
	device, ok := p["device"].(map[string]any)
	if !ok {
		t.Fatalf("fixture device block is not an object: %T", p["device"])
	}
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2108" + hwUUID[:8]
	device["hostname"] = "pat2108-" + hwUUID[:8]
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return body
}

func pat2108InsertRawPayload(t *testing.T, tenantID string, receivedAt time.Time, body []byte) int64 {
	t.Helper()
	var id int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO raw_payloads (tenant_id, received_at, body)
		VALUES ($1::uuid, $2, $3::jsonb)
		RETURNING id
	`, tenantID, receivedAt, body).Scan(&id); err != nil {
		t.Fatalf("insert raw_payload: %v", err)
	}
	return id
}

func pat2108DeviceID(t *testing.T, tenantID, hwUUID string) string {
	t.Helper()
	var deviceID string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2::uuid
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("query device id: %v", err)
	}
	return deviceID
}

// pat2108SeedActiveDisposition writes a live (non-superseded) disposition
// for deviceID with an explicit recorded_at, bypassing the admin handler so
// the test controls the timestamp precisely. Returns the disposition id.
func pat2108SeedActiveDisposition(t *testing.T, tenantID, deviceID string, recordedAt time.Time) string {
	t.Helper()
	var dispositionID string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO device_dispositions (tenant_id, device_id, category, reported_by, recorded_at)
		VALUES ($1::uuid, $2::uuid, 'decommissioned', 'pat2108-test', $3)
		RETURNING id::text
	`, tenantID, deviceID, recordedAt).Scan(&dispositionID); err != nil {
		t.Fatalf("seed disposition: %v", err)
	}
	return dispositionID
}

func pat2108DispositionState(t *testing.T, dispositionID string) (supersededAt *time.Time, supersededReason *string) {
	t.Helper()
	if err := env.pool.QueryRow(context.Background(), `
		SELECT superseded_at, superseded_reason FROM device_dispositions WHERE id = $1::uuid
	`, dispositionID).Scan(&supersededAt, &supersededReason); err != nil {
		t.Fatalf("query disposition state: %v", err)
	}
	return supersededAt, supersededReason
}

func pat2108FindingCount(t *testing.T, deviceID string) int {
	t.Helper()
	var count int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM device_lifecycle_findings
		WHERE device_id = $1::uuid AND kind = 'reappeared_after_disposition'
	`, deviceID).Scan(&count); err != nil {
		t.Fatalf("query finding count: %v", err)
	}
	return count
}

// TestReappearanceIgnoresReportReceivedBeforeDisposition is PAT-2108's core
// regression: a disposition recorded at T, and a report that was actually
// received at T-1h but only gets extracted now (well after T) — because the
// extractor fell behind — must not raise a reappearance finding. The old
// code compared time.Now().UTC() (extraction wall-clock time, always after
// T here) against recorded_at and raised a false finding; the fix compares
// the report's own received_at.
func TestReappearanceIgnoresReportReceivedBeforeDisposition(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2108-before")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	hwUUID := pat2108HWUUID()

	// First report creates the device. Received well in the past so it
	// cannot itself look like a reappearance against anything seeded next.
	seedReceivedAt := time.Now().UTC().Add(-3 * time.Hour)
	pat2108InsertRawPayload(t, tenantID, seedReceivedAt, pat2108Body(t, tenantID, hwUUID, seedReceivedAt))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (seed report): %v", err)
	}
	deviceID := pat2108DeviceID(t, tenantID, hwUUID)

	// Disposition recorded at T = now - 30m.
	recordedAt := time.Now().UTC().Add(-30 * time.Minute)
	dispositionID := pat2108SeedActiveDisposition(t, tenantID, deviceID, recordedAt)

	// Report received at T-1h (before the disposition), but its raw_payloads
	// row is only inserted/extracted now — i.e. extraction is running well
	// after T, simulating exactly the backlog scenario the ticket describes.
	reportReceivedAt := recordedAt.Add(-1 * time.Hour)
	pat2108InsertRawPayload(t, tenantID, reportReceivedAt, pat2108Body(t, tenantID, hwUUID, reportReceivedAt))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (backdated report): %v", err)
	}

	supersededAt, supersededReason := pat2108DispositionState(t, dispositionID)
	if supersededAt != nil || supersededReason != nil {
		t.Fatalf("disposition was superseded (at=%v reason=%v) by a report received at %s, before recorded_at %s — extraction time, not received_at, drove the decision",
			supersededAt, supersededReason, reportReceivedAt, recordedAt)
	}
	if n := pat2108FindingCount(t, deviceID); n != 0 {
		t.Fatalf("expected no reappearance finding for a report received before the disposition, got %d", n)
	}
}

// TestReappearanceRaisesForReportReceivedAfterDisposition is the control:
// a report genuinely received after the disposition must still raise the
// finding, proving the received_at comparison isn't just switched off.
func TestReappearanceRaisesForReportReceivedAfterDisposition(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2108-after")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	hwUUID := pat2108HWUUID()

	seedReceivedAt := time.Now().UTC().Add(-3 * time.Hour)
	pat2108InsertRawPayload(t, tenantID, seedReceivedAt, pat2108Body(t, tenantID, hwUUID, seedReceivedAt))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (seed report): %v", err)
	}
	deviceID := pat2108DeviceID(t, tenantID, hwUUID)

	// Disposition recorded at T = now - 2h.
	recordedAt := time.Now().UTC().Add(-2 * time.Hour)
	dispositionID := pat2108SeedActiveDisposition(t, tenantID, deviceID, recordedAt)

	// Report received at T+30m (after the disposition) — a genuine
	// reappearance.
	reportReceivedAt := recordedAt.Add(30 * time.Minute)
	pat2108InsertRawPayload(t, tenantID, reportReceivedAt, pat2108Body(t, tenantID, hwUUID, reportReceivedAt))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (later report): %v", err)
	}

	supersededAt, supersededReason := pat2108DispositionState(t, dispositionID)
	if supersededAt == nil || supersededReason == nil || *supersededReason != "reappeared" {
		t.Fatalf("expected disposition to be auto-superseded with reason 'reappeared', got at=%v reason=%v", supersededAt, supersededReason)
	}
	if n := pat2108FindingCount(t, deviceID); n != 1 {
		t.Fatalf("expected exactly 1 reappearance finding for a report received after the disposition, got %d", n)
	}
}
