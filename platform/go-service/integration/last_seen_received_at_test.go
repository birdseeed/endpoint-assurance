//go:build integration

package integration

// PAT-2102: devices.last_seen must come from the report's own
// raw_payloads.received_at, not from now() at the moment extraction happens
// to run. An extractor outage or a replayed backlog processes old reports
// late; stamping last_seen with extraction wall-clock time made a report
// that was truthfully received (and evidencing) 20 days ago look like it
// arrived today everywhere devices.last_seen is read — the silent-device
// buckets, the stale-endpoint report, coverage, Unapproved alerts and Cyber
// Essentials 14-day evidence. See upsertDevice's doc comment in
// internal/extractor/upsert.go for the fix and the reasoning.
//
// These tests bypass POST /v1/inventory and insert into raw_payloads
// directly, because the handler always writes received_at = now()
// (internal/handlers/inventory.go) — there is no way to make a live POST
// arrive with an old received_at. Inserting directly is exactly the shape
// of a real backlog: the row existed with its true received_at all along;
// only the extractor's processing of it was late.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
	"patched.im/api/internal/report"
)

// pat2102HWUUID returns a fresh hw_uuid in the 8-4-4-4-12 form the extractor
// requires (uuidRegex in internal/extractor/upsert.go), so each test gets
// its own device identity.
func pat2102HWUUID() string {
	h := randomHex(16) // 32 hex chars
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// pat2102Body builds a raw_payloads.body from the full.json golden fixture
// (already proven to extract cleanly end-to-end by TestInventoryValidFixtures)
// with the tenant, device identity and collected_at replaced.
func pat2102Body(t *testing.T, tenantID, hwUUID string, collectedAt time.Time) []byte {
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
	device["serial"] = "PAT2102" + hwUUID[:8]
	device["hostname"] = "pat2102-" + hwUUID[:8]
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return body
}

// pat2102InsertRawPayload inserts one raw_payloads row directly with an
// explicit received_at, simulating a report that has been sitting in the
// backlog since that time. Returns the raw_payload id.
func pat2102InsertRawPayload(t *testing.T, tenantID string, receivedAt time.Time, body []byte) int64 {
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

func pat2102DeviceLastSeen(t *testing.T, tenantID, hwUUID string) time.Time {
	t.Helper()
	var lastSeen time.Time
	if err := env.pool.QueryRow(context.Background(), `
		SELECT last_seen FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2::uuid
	`, tenantID, hwUUID).Scan(&lastSeen); err != nil {
		t.Fatalf("query devices.last_seen: %v", err)
	}
	return lastSeen
}

// TestLastSeenFromReceivedAtNotExtractionTime is PAT-2102's core regression:
// a report that sat in the backlog for 20 days before extraction ran must
// leave the device stale, not freshly seen.
func TestLastSeenFromReceivedAtNotExtractionTime(t *testing.T) {
	ctx := context.Background()
	// No cleanupTestTenant here: full.json's compliance data drives real CIS
	// evaluation, which writes append-only finding_lifecycle_events rows a
	// tenant DELETE cannot cascade through (same reason cve_event_match_test.go
	// and apps_prune_authority_test.go leave their full.json-driven tenants in
	// place — tenant_id scoping keeps them isolated from other tests).
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2102-backlog")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	hwUUID := pat2102HWUUID()
	receivedAt := time.Now().UTC().Add(-20 * 24 * time.Hour)
	pat2102InsertRawPayload(t, tenantID, receivedAt, pat2102Body(t, tenantID, hwUUID, receivedAt))

	// Extraction runs "now" — 20 days after the report's real received_at —
	// exactly the extractor-outage/replay backlog scenario PAT-2102 covers.
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	lastSeen := pat2102DeviceLastSeen(t, tenantID, hwUUID)

	// The bug: last_seen = now() at extraction time (would land within
	// seconds of "now"). The fix: last_seen = received_at.
	if diff := lastSeen.Sub(receivedAt); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("last_seen = %s, want within a minute of received_at %s (diff %s) — looks stamped from extraction wall-clock time instead of received_at",
			lastSeen, receivedAt, diff)
	}
	if time.Since(lastSeen) < 19*24*time.Hour {
		t.Fatalf("last_seen = %s is not stale — a report received 20 days ago looks like it just reported", lastSeen)
	}

	// Silent-device bucket / stale-endpoint report: every "hasn't reported in
	// N days" surface reads devices.last_seen against a threshold.
	// report.FetchStaleEndpointsReport is the concrete instance of that read;
	// a 14-day threshold must catch this device.
	staleReport, err := report.FetchStaleEndpointsReport(ctx, env.pool, tenantID, 14)
	if err != nil {
		t.Fatalf("FetchStaleEndpointsReport: %v", err)
	}
	wantHostname := "pat2102-" + hwUUID[:8]
	found := false
	for _, d := range staleReport.Devices {
		if d.Hostname == wantHostname {
			found = true
			if d.DaysSince < 19 {
				t.Errorf("stale endpoint report days_since = %.1f, want ~20", d.DaysSince)
			}
		}
	}
	if !found {
		t.Fatalf("device with a 20-day-old received_at is missing from the 14-day stale-endpoint report — last_seen was stamped fresh instead of from received_at")
	}
}

// TestLastSeenReplayDoesNotMoveBackwards: a newer report followed later by
// an older, replayed one (out-of-order extraction catching up, or the same
// backlog replayed twice) must never drag last_seen backwards.
func TestLastSeenReplayDoesNotMoveBackwards(t *testing.T) {
	ctx := context.Background()
	// No cleanupTestTenant here either — same append-only finding_lifecycle_events
	// reason as above.
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2102-replay")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	hwUUID := pat2102HWUUID()

	newer := time.Now().UTC().Add(-1 * time.Hour)
	pat2102InsertRawPayload(t, tenantID, newer, pat2102Body(t, tenantID, hwUUID, newer))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (newer report): %v", err)
	}
	afterNewer := pat2102DeviceLastSeen(t, tenantID, hwUUID)
	if diff := afterNewer.Sub(newer); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("last_seen after newer report = %s, want within a minute of %s", afterNewer, newer)
	}

	// A second, OLDER report for the same device arrives and extracts after
	// the newer one already has — a replayed or backlogged report catching
	// up out of order.
	older := time.Now().UTC().Add(-10 * 24 * time.Hour)
	pat2102InsertRawPayload(t, tenantID, older, pat2102Body(t, tenantID, hwUUID, older))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (older/replayed report): %v", err)
	}
	afterOlder := pat2102DeviceLastSeen(t, tenantID, hwUUID)

	if diff := afterOlder.Sub(afterNewer); diff < -time.Second || diff > time.Second {
		t.Fatalf("last_seen changed after replaying an older report: %s -> %s (replayed received_at was %s), want unchanged",
			afterNewer, afterOlder, older)
	}
}

// PAT-2102 follow-up: device_apps.last_seen is now stamped from received_at
// too (upsertApps), which moved a latent bug one level up. pruneLongUnseenApps
// (internal/extractor/apps_authority.go) releases a machine-wide identifier
// the safety valve is holding once it has gone unseen for
// appsPruneValveReleaseAfter (7 days) — but it compared that against now() at
// extraction time. Once last_seen is receivedAt-anchored, comparing it
// against wall-clock now() during a backlogged extraction compares old
// evidence against today's date instead of the report's own date, and can
// release (delete) an installation that, relative to the evidence, was seen
// well inside the 7-day window. That is an absence decision made without
// authority (root AGENTS.md Hard Constraint).

// pat2102AppsBody builds a raw_payloads.body from full.json with the device
// identity and apps array replaced. No collection_status.apps key is set, so
// resolveAppsSignal returns appsSignalNone and the safety valve decides —
// the path pruneLongUnseenApps runs under.
func pat2102AppsBody(t *testing.T, tenantID, hwUUID string, receivedAt time.Time, identifiers []string) []byte {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "full.json"), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tenantID
	p["collected_at"] = receivedAt.UTC().Format(time.RFC3339)
	delete(p, "collection_status")
	device, ok := p["device"].(map[string]any)
	if !ok {
		t.Fatalf("fixture device block is not an object: %T", p["device"])
	}
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2102V" + hwUUID[:8]
	device["hostname"] = "pat2102v-" + hwUUID[:8]
	apps := make([]map[string]any, 0, len(identifiers))
	for _, id := range identifiers {
		apps = append(apps, map[string]any{
			"name": id, "version": "1.0", "bundle_id": "com.pat2102." + id,
			"path": "/Applications/" + id + ".app",
		})
	}
	p["apps"] = apps
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return body
}

// pat2102MachineWideIdentifiers returns the machine-wide device_apps
// identifiers currently on the device.
func pat2102MachineWideIdentifiers(t *testing.T, tenantID, hwUUID string) map[string]bool {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT DISTINCT a.identifier
		FROM device_apps a JOIN devices d ON d.id = a.device_id
		WHERE d.tenant_id = $1::uuid AND d.hw_uuid = $2::uuid AND a.machine_wide
	`, tenantID, hwUUID)
	if err != nil {
		t.Fatalf("query device_apps identifiers: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan identifier: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate identifiers: %v", err)
	}
	return out
}

// TestAppsLongUnseenPruneAnchoredToReceivedAtNotNow reproduces the exact
// backlog scenario from the PAT-2102 follow-up: a report received 30 days
// ago, extracted now, holding an app last confirmed by a report received 31
// days ago (relative to the evidence, seen just one day earlier — well
// inside the 7-day release window). Anchored to now() at extraction time,
// that app is 30+ days "unseen" and gets released; anchored to received_at,
// it is correctly held.
func TestAppsLongUnseenPruneAnchoredToReceivedAtNotNow(t *testing.T) {
	ctx := context.Background()
	// No cleanupTestTenant: full.json drives real CIS evaluation and
	// append-only finding_lifecycle_events, same as the other tests in this
	// file.
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2102-valve")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	hwUUID := pat2102HWUUID()

	// Report A: 10 identifiers, received 31 days ago. Sets every identifier's
	// device_apps.last_seen to that received_at (PAT-2102's own fix).
	all := make([]string, 10)
	for i := range all {
		all[i] = fmt.Sprintf("app%d", i)
	}
	reportA := time.Now().UTC().Add(-31 * 24 * time.Hour)
	pat2102InsertRawPayload(t, tenantID, reportA, pat2102AppsBody(t, tenantID, hwUUID, reportA, all))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (report A): %v", err)
	}
	if got := pat2102MachineWideIdentifiers(t, tenantID, hwUUID); len(got) != 10 {
		t.Fatalf("after report A: %d machine-wide identifiers, want 10 (%v)", len(got), got)
	}

	// Report B: received 30 days ago (one day after report A's evidence),
	// reconfirms only 3 of the 10 (app7-9). The other 7, including app0,
	// vanish: 7 > appsPruneValveMinRemoved(5) and 7 > 50% of current(10), so
	// the safety valve holds and, since 3 were reconfirmed, pruneLongUnseenApps
	// runs. None of the 7 have gone unseen 7 days relative to report B's own
	// received_at (31d evidence vs. 30d report = 1 day), so none should be
	// released — but every one of them IS more than 7 days behind today's
	// wall-clock time, which is exactly the bug.
	reportB := time.Now().UTC().Add(-30 * 24 * time.Hour)
	reconfirmed := []string{"app7", "app8", "app9"}
	pat2102InsertRawPayload(t, tenantID, reportB, pat2102AppsBody(t, tenantID, hwUUID, reportB, reconfirmed))
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (report B): %v", err)
	}

	got := pat2102MachineWideIdentifiers(t, tenantID, hwUUID)
	for _, id := range all {
		reconfirmedNow := id == "app7" || id == "app8" || id == "app9"
		if reconfirmedNow {
			continue
		}
		if !got["com.pat2102."+id] {
			t.Errorf("com.pat2102.%s was released as long-unseen, but relative to its own evidence (report A, received_at 31d ago) it was seen just 1 day before report B (received_at 30d ago) — well inside the 7-day window. pruneLongUnseenApps is anchoring to now() instead of received_at, removing an installation without authority.", id)
		}
	}
}
