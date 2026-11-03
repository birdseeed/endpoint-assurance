//go:build integration

package integration

// PAT-2138 re-review, round 2: assessment platform consistency, guarded
// in-place curation and single-run digest.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/cvepipeline"
)

// A product mapped only for Windows is not assessed on a Mac, in the
// device view and in the tenant totals, exactly as the matcher (which
// filters mappings by platform) never matches it there.
func TestAssessmentHonoursMappingPlatform(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2138-winonly-"+sfx)
	app := "Pat2138 Winonly " + sfx
	hw := strings.ToUpper(sfx + "-2138-4000-8000-0000000000f1")
	postSignedAppsPayload(t, tn, hw, []signedApp{{app, "1.0", "com.example.winonly." + sfx, "", ""}}, time.Now())
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)
	before, err := cvepipeline.AssessTenant(ctx, env.pool, tn.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('windows', $1, $2, 'winonly', 'PAT-2138 test: Windows only', 'app_name', 'curated')`,
		app, "pat2138w"+sfx); err != nil {
		t.Fatal(err)
	}
	drainCVEQueue(t)
	a, _ := portalDeviceAssessment(t, tn, deviceID)
	if st, c, _ := productState(t, a, app); st != cvepipeline.StateNotAssessed || c != nil {
		t.Fatalf("Windows-only mapping on a Mac: product = %s/%v, want not_assessed/null", st, c)
	}
	after, err := cvepipeline.AssessTenant(ctx, env.pool, tn.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if after.AssessedProducts+after.PendingProducts != before.AssessedProducts+before.PendingProducts ||
		after.NotAssessedProducts != before.NotAssessedProducts {
		t.Fatalf("tenant totals moved on a Windows-only mapping for a Mac product: before %+v after %+v", before, after)
	}
}

// Approving an automatic proposal curates only the automatic row it
// published: if that row was changed elsewhere meanwhile, approve is a
// conflict and the row is left as it is.
func TestApproveNeverOverwritesAChangedMapping(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2138-curate-"+sfx)
	h := newProposerHarness(t, true)
	a := autoPublishedOn(t, h, []cveTestTenant{tn, newCVETestTenant(t, "pat2138-curate2-"+sfx)}, "curate")
	if _, err := env.pool.Exec(ctx, `UPDATE app_cpe_mappings SET review_state = 'curated', notes = 'changed elsewhere'
		WHERE id = $1`, *a.p.MappingID); err != nil {
		t.Fatal(err)
	}
	cpAdminJSON(t, http.MethodPost, fmt.Sprintf("/admin/cve-mapping-proposals/%d/approve", a.p.ID),
		map[string]string{"actor": "reviewer"}, http.StatusConflict)
	var notes string
	if err := env.pool.QueryRow(ctx, `SELECT notes FROM app_cpe_mappings WHERE id = $1`, *a.p.MappingID).Scan(&notes); err != nil || notes != "changed elsewhere" {
		t.Fatalf("mapping notes = %q, %v; approve overwrote a row changed elsewhere", notes, err)
	}
}

// Two digest runs at once: the second finds the first holding the lock and
// touches nothing, so the issue can never be created twice.
func TestCPEReviewDigestSingleRun(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	if _, err := env.pool.Exec(ctx, `INSERT INTO cpe_mapping_proposals (platform, normalized_name, display_name, state, state_reason)
		VALUES ('macos', $1, $1, 'needs_review', 'no_candidates')`, "pat2138 digestlock "+sfx); err != nil {
		t.Fatal(err)
	}
	holder, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cpepropose.digest', 0))`); err != nil {
		t.Fatal(err)
	}
	tr := &fakeTracker{}
	res, err := cpepropose.RunDigest(ctx, env.pool, tr, time.Now(), nil)
	if err != nil || tr.ops != "" || res.Action != "locked" {
		t.Fatalf("concurrent digest = %+v, %v, tracker ops %q; want locked with no tracker call", res, err, tr.ops)
	}
}
