//go:build integration

package integration

// PAT-2107: the corrected CVE matcher stops producing false findings. A
// finding it retracts while the device still reports the same software at
// the same version is recorded as withdrawn (a matcher correction), never as
// verified_fixed, and notifies no one, even on a channel subscribed to every
// finding event. A finding that disappears because the software was removed
// is still verified fixed and still notified, through the same channel.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
)

// reviseFeedRanges rewrites one CVE's cpe_ranges and records the feed delta
// exactly as a sync page does, so MatchFeedDelta re-matches its installs.
func reviseFeedRanges(t *testing.T, cveID string, ranges []cvematch.CPERange) {
	t.Helper()
	ctx := context.Background()
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	prior, err := cvepipeline.LoadFeedMatchStates(ctx, tx, []string{cveID})
	if err != nil {
		t.Fatal(err)
	}
	rangesJSON, _ := json.Marshal(ranges)
	if _, err := tx.Exec(ctx, `UPDATE cve_feed_entries SET cpe_ranges = $2::jsonb WHERE cve_id = $1`,
		cveID, string(rangesJSON)); err != nil {
		t.Fatal(err)
	}
	next := prior[cveID]
	next.Ranges = ranges
	if err := cvepipeline.RecordFeedDelta(ctx, tx, cvepipeline.FeedDeltaKeys(prior,
		map[string]cvepipeline.FeedMatchState{cveID: next})); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func cveLifecycleEvents(t *testing.T, tenantID, cveID string) []string {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT event_type FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2 ORDER BY id`,
		tenantID, cveID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// cveDeliveries lists the channel's delivery event types for one CVE. The
// subject is "cve/-/<CVE>@<time>".
func cveDeliveries(t *testing.T, channelID, cveID string) []string {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT event_type FROM notification_deliveries
		WHERE channel_id = $1::uuid AND subject LIKE $2 ORDER BY id`,
		channelID, "cve/-/"+cveID+"@%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// waitForDelivery polls until the channel holds a delivery of eventType for
// cveID. Notifications are enqueued asynchronously after the lifecycle
// commit.
func waitForDelivery(t *testing.T, channelID, cveID, eventType string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		for _, ev := range cveDeliveries(t, channelID, cveID) {
			if ev == eventType {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s delivery for %s; have %v", eventType, cveID, cveDeliveries(t, channelID, cveID))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCVEMatcherCorrectionIsWithdrawnNotFixedAndNotNotified(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2107-withdrawn-"+sfx)
	channelID, _ := createNotificationChannel(t, tn.tenantID, defaultWebhookChannel("pat2107 withdrawn "+sfx))

	// W: an unbounded, platform-less CVE (the OneDrive "Possible" shape)
	// that the corrected feed later scopes to Windows. R: a bounded CVE on an
	// app the device later removes.
	appW, vendorW := "Pat2107 Cloudsync "+sfx, "pat2107w"+sfx
	appR, vendorR := "Pat2107 Removable "+sfx, "pat2107r"+sfx
	cveW, cveR := "CVE-2099-"+sfx+"W", "CVE-2099-"+sfx+"R"
	seedFeedEntry(t, cveW, vendorW, "cloudsync", "", false)
	seedFeedEntry(t, cveR, vendorR, "removable", "2.0", false)
	seedCVEMapping(t, appW, vendorW, "cloudsync")
	seedCVEMapping(t, appR, vendorR, "removable")
	drainCVEQueue(t)

	hw := strings.ToUpper(sfx + "-2107-4000-8000-000000000001")
	w := cveTestApp{appW, "26.163.0823", "com.example.pat2107.w." + sfx}
	r := cveTestApp{appR, "1.5", "com.example.pat2107.r." + sfx}
	// Explicit collection times, a minute apart and well inside the 24-hour
	// freshness window, order the two reports deterministically (collected_at
	// has one-second resolution).
	firstCollected := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	postAppsPayloadAt(t, tn, hw, []cveTestApp{w, r}, firstCollected)
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	var deviceOS string
	if err := env.pool.QueryRow(ctx, `SELECT COALESCE(os, '') FROM devices WHERE id = $1::uuid`, deviceID).Scan(&deviceOS); err != nil {
		t.Fatal(err)
	}
	if cvematch.NormalizeDevicePlatform(deviceOS) != cvematch.PlatformMacOS {
		t.Fatalf("test invalid: fixture device os %q is not macOS", deviceOS)
	}
	drainCVEQueue(t)
	for _, cve := range []string{cveW, cveR} {
		if got := cveLifecycleEvents(t, tn.tenantID, cve); len(got) != 1 || got[0] != "first_observed" {
			t.Fatalf("%s lifecycle before the correction = %v, want [first_observed]", cve, got)
		}
		waitForDelivery(t, channelID, cve, "finding.opened")
	}

	// The corrected feed says W applies only on Windows. The event matcher
	// re-matches the Mac's install and prunes the finding; the app is still
	// installed at the same version.
	reviseFeedRanges(t, cveW, []cvematch.CPERange{{Vendor: vendorW, Product: "cloudsync", TargetSW: "windows"}})
	if _, err := cvepipeline.MatchFeedDelta(ctx, env.pool, nil); err != nil {
		t.Fatalf("MatchFeedDelta: %v", err)
	}
	if n := countRows(t, `SELECT count(*) FROM device_cve_findings WHERE device_id = $1::uuid AND cve_id = $2`, deviceID, cveW); n != 0 {
		t.Fatalf("corrected feed left %d findings for %s", n, cveW)
	}
	if got := cveLifecycleEvents(t, tn.tenantID, cveW); strings.Join(got, ",") != "first_observed,withdrawn" {
		t.Fatalf("%s lifecycle after the correction = %v, want [first_observed withdrawn]", cveW, got)
	}

	// A fresh, complete inventory collected a minute later still reports W
	// unchanged and no longer reports R. R is verified fixed; W stays
	// withdrawn. Then reconcile W twice more: nothing is added.
	postAppsPayloadAt(t, tn, hw, []cveTestApp{w}, firstCollected.Add(time.Minute))
	drainCVEQueue(t)
	cvelifecycleReconcile(t, tn.tenantID, cveW)
	cvelifecycleReconcile(t, tn.tenantID, cveW)
	cvelifecycleReconcile(t, tn.tenantID, cveR)

	if got := cveLifecycleEvents(t, tn.tenantID, cveW); strings.Join(got, ",") != "first_observed,withdrawn" {
		t.Fatalf("%s lifecycle = %v, want exactly [first_observed withdrawn]", cveW, got)
	}
	if got := cveLifecycleEvents(t, tn.tenantID, cveR); got[len(got)-1] != "verified_fixed" {
		t.Fatalf("%s lifecycle = %v, want it to end verified_fixed", cveR, got)
	}

	var source, actor string
	var authoritative bool
	var observedAt *time.Time
	if err := env.pool.QueryRow(ctx, `
		SELECT source_type, actor, authoritative, observed_at FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_key = $2 AND event_type = 'withdrawn'`,
		tn.tenantID, cveW).Scan(&source, &actor, &authoritative, &observedAt); err != nil {
		t.Fatal(err)
	}
	if source != "matcher" || actor != "matcher" || authoritative || observedAt != nil {
		t.Fatalf("withdrawn row = %s/%s/%v/%v, want matcher/matcher/false/NULL", source, actor, authoritative, observedAt)
	}

	// Notifications: R's closure is delivered through this very channel,
	// which proves the channel would have carried a closure for W. Waiting for
	// it also lets every earlier asynchronous enqueue land first.
	waitForDelivery(t, channelID, cveR, "verification.passed")
	if got := cveDeliveries(t, channelID, cveW); strings.Join(got, ",") != "finding.opened" {
		t.Fatalf("%s deliveries = %v, want only the original finding.opened", cveW, got)
	}

	// The portal lifecycle read shows the withdrawal as it is: status
	// withdrawn, not authoritative, with no verified_fixed milestone.
	resp := portalDo(t, http.MethodGet, "/v1/portal/finding-lifecycle?finding_kind=cve&finding_key="+cveW, tn.token, nil)
	var current struct {
		Findings []struct {
			Status              string     `json:"status"`
			StatusAuthoritative bool       `json:"status_authoritative"`
			VerifiedFixedAt     *time.Time `json:"verified_fixed_at"`
		} `json:"findings"`
	}
	decodeJSON(t, resp, &current)
	if len(current.Findings) != 1 || current.Findings[0].Status != "withdrawn" ||
		current.Findings[0].StatusAuthoritative || current.Findings[0].VerifiedFixedAt != nil {
		t.Fatalf("portal lifecycle for %s = %+v, want one withdrawn, non-authoritative row with no verified_fixed_at", cveW, current.Findings)
	}
}
