//go:build integration

package integration

// PAT-2046: the staff admin API for the PAT-2023 Homebrew CPE review queue
// (GET/POST /admin/homebrew/review/*, internal/homebrewreview). map and
// accept-suggestion are exercised end to end through the real PAT-2045
// event path (cvepipeline.Drain / SyncMappingSnapshot), proving a mapping
// curated here reaches an already-ingested device's findings with no new
// payload and no full match, exactly as a mapping published any other way
// does. Names and CVE IDs carry a per-test random suffix: the review queue
// and app_cpe_mappings are both global tables shared with every other test
// in this package.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"patched.im/api/internal/cvematch"
)

// seedHomebrewReviewRow inserts one homebrew_cpe_review_queue row directly,
// standing in for what internal/cvepipeline's nightly recordHomebrewReview
// would have written; the admin API under test starts from that row, not
// from populating the queue itself (that machinery is PAT-2045's own
// coverage, confirmed read-only above).
func seedHomebrewReviewRow(t *testing.T, kind, name string, suggestedKey *string, conflict bool) int64 {
	t.Helper()
	var id int64
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO homebrew_cpe_review_queue (package_kind, name, homepage, suggested_cpe_key, metadata_conflict, metadata_conflict_count)
		VALUES ($1, $2, 'https://example.invalid/'||$2, $3, $4, CASE WHEN $4 THEN 1 ELSE 0 END)
		RETURNING id
	`, kind, name, suggestedKey, conflict).Scan(&id); err != nil {
		t.Fatalf("seed homebrew review row %s: %v", name, err)
	}
	return id
}

func homebrewReviewAuditActions(t *testing.T, reviewID int64) []string {
	t.Helper()
	rows, err := env.pool.Query(context.Background(),
		`SELECT action FROM homebrew_review_audit WHERE review_id = $1 ORDER BY id`, reviewID)
	if err != nil {
		t.Fatalf("query homebrew review audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

type hrReviewResp struct {
	Review struct {
		ID         int64  `json:"id"`
		Status     string `json:"status"`
		Name       string `json:"name"`
		Prevalence int    `json:"estate_prevalence"`
	} `json:"review"`
}

// TestHomebrewReview_RequiresInternalToken proves the routes are reachable
// without crashing when unauthenticated (this harness's buildInternalRouter
// deliberately does not wire requireInternalToken -- see
// TestCatalogueSignedLabels_RequiresInternalToken's comment for why). The
// auth REJECTION itself is asserted against the real middleware in
// cmd/patched-api's TestInternalRouter_AdminAuth
// ("homebrew review admin routes are authenticated and absent publicly"),
// the one place that middleware is importable from.
func TestHomebrewReview_RequiresInternalToken(t *testing.T) {
	resp := getAdminJSON(t, "/admin/homebrew/review")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/homebrew/review (no auth gate in this harness): got %d, want 200", resp.StatusCode)
	}
}

// Map creates a curated app_cpe_mappings row, marks the queue row mapped,
// audits the write, and -- through the real PAT-2045 event path, with no
// new payload and no full match -- gives an already-ingested device holding
// the formula a finding after a drain.
func TestHomebrewReviewMap_CreatesCuratedMappingAndFindingAfterDrain(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2046-map-"+sfx)
	formula := "pat2046map-" + sfx
	vendor := "pat2046m" + sfx
	cveID := "CVE-2099-" + sfx + "M"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)

	hw := sfx + "-2046-4000-8000-00000000000a"
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete",
		[]any{brewFormula(formula, "1.5.0", true, nil, nil)}, nil, nil))
	deviceID := deviceIDByHW(t, tn.tenantID, hw)
	drainCVEQueue(t)
	display := cvematch.HomebrewDisplayName("formula", formula)
	if n := brewFindingCount(t, deviceID, cveID, display); n != 0 {
		t.Fatalf("unmapped formula has %d findings before map", n)
	}

	reviewID := seedHomebrewReviewRow(t, "formula", formula, nil, false)

	var out hrReviewResp
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/map", reviewID),
		map[string]any{"cpe_vendor": vendor, "cpe_product": "tool"}, http.StatusOK, &out)
	if out.Review.Status != "mapped" {
		t.Fatalf("review status = %q, want mapped", out.Review.Status)
	}

	var sourceType, reviewState string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT source_type, review_state FROM app_cpe_mappings
		WHERE lower(match_name) = $1 AND cpe_vendor = $2 AND cpe_product = 'tool'
	`, strings.ToLower(formula), vendor).Scan(&sourceType, &reviewState); err != nil {
		t.Fatalf("curated mapping not found: %v", err)
	}
	if sourceType != cvematch.HomebrewFormulaSource || reviewState != "curated" {
		t.Fatalf("mapping source_type=%s review_state=%s", sourceType, reviewState)
	}

	if actions := homebrewReviewAuditActions(t, reviewID); len(actions) != 1 || actions[0] != "map" {
		t.Fatalf("audit actions = %v, want [map]", actions)
	}

	drainCVEQueue(t)
	if n := brewFindingCount(t, deviceID, cveID, display); n != 1 {
		t.Fatalf("mapped formula has %d findings after drain, want 1", n)
	}

	// Re-mapping an already-mapped row is refused, not silently repeated.
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/map", reviewID),
		map[string]any{"cpe_vendor": vendor, "cpe_product": "tool"}, http.StatusConflict, nil)
}

// An unknown CPE key -- no presence in the local NVD store -- is refused.
func TestHomebrewReviewMap_UnknownCPEKeyRefused(t *testing.T) {
	sfx := randomHex(4)
	formula := "pat2046unk-" + sfx
	reviewID := seedHomebrewReviewRow(t, "formula", formula, nil, false)

	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/map", reviewID),
		map[string]any{"cpe_vendor": "nosuchvendor" + sfx, "cpe_product": "nosuchproduct"}, http.StatusBadRequest, nil)

	var status string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT status FROM homebrew_cpe_review_queue WHERE id = $1`, reviewID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("review row status = %s after refused map, want pending", status)
	}
	if n := countRows(t, `SELECT count(*) FROM homebrew_review_audit WHERE review_id = $1`, reviewID); n != 0 {
		t.Fatalf("refused map wrote %d audit rows, want 0", n)
	}
}

// accept-suggestion is refused on a contested suggestion without
// confirm_conflict, and allowed once the caller confirms both gates: this
// row (deliberately, to isolate the conflict gate) has zero reporting
// tenants, so it also needs confirm_single_reporter (see the P2 tests
// below).
func TestHomebrewReviewAcceptSuggestion_ConflictThenConfirm(t *testing.T) {
	sfx := randomHex(4)
	formula := "pat2046acc-" + sfx
	vendor := "pat2046a" + sfx
	cveID := "CVE-2099-" + sfx + "A"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)
	key := vendor + ":tool"

	reviewID := seedHomebrewReviewRow(t, "formula", formula, &key, true)

	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/accept-suggestion", reviewID),
		nil, http.StatusConflict, nil)

	var out hrReviewResp
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/accept-suggestion", reviewID),
		map[string]any{"confirm_conflict": true, "confirm_single_reporter": true}, http.StatusOK, &out)
	if out.Review.Status != "mapped" {
		t.Fatalf("review status = %q, want mapped", out.Review.Status)
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1 AND cpe_vendor = $2 AND cpe_product = 'tool'`,
		strings.ToLower(formula), vendor); n != 1 {
		t.Fatalf("accept-suggestion produced %d mappings, want 1", n)
	}
	if actions := homebrewReviewAuditActions(t, reviewID); len(actions) != 1 || actions[0] != "accept_suggestion" {
		t.Fatalf("audit actions = %v, want [accept_suggestion]", actions)
	}
}

// P2 (adversarial review of the first cut): metadata_conflict only fires
// when two reports disagree, so a single tenant can be the first and only
// reporter of a rare formula and plant a plausible suggested_cpe_key with no
// conflict ever recorded. accept-suggestion must refuse that suggestion
// (409, no confirm_single_reporter) and accept it once the caller
// explicitly overrides the gate. RED first (no override), then GREEN (with
// it), in the same test so the refusal is proven, not assumed.
func TestHomebrewReviewAcceptSuggestion_SingleReporterRefusedThenConfirmed(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2046-single-"+sfx)
	formula := "pat2046single-" + sfx
	vendor := "pat2046s" + sfx
	cveID := "CVE-2099-" + sfx + "S"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)
	key := vendor + ":tool"

	hw := sfx + "-2046-4000-8000-00000000000b"
	postInventoryAs(t, tn.bearer, tn.hmacSecret, brewCVEPayload(t, tn, hw, "complete",
		[]any{brewFormula(formula, "1.5.0", true, nil, nil)}, nil, nil))

	reviewID := seedHomebrewReviewRow(t, "formula", formula, &key, false)

	// RED: exactly one tenant reports the package, and no override is given.
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/accept-suggestion", reviewID),
		nil, http.StatusConflict, nil)
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1 AND cpe_vendor = $2 AND cpe_product = 'tool'`,
		strings.ToLower(formula), vendor); n != 0 {
		t.Fatalf("refused single-reporter accept-suggestion still created %d mappings", n)
	}

	// GREEN: same row, explicit override.
	var out hrReviewResp
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/accept-suggestion", reviewID),
		map[string]any{"confirm_single_reporter": true}, http.StatusOK, &out)
	if out.Review.Status != "mapped" {
		t.Fatalf("review status = %q, want mapped", out.Review.Status)
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1 AND cpe_vendor = $2 AND cpe_product = 'tool'`,
		strings.ToLower(formula), vendor); n != 1 {
		t.Fatalf("confirmed single-reporter accept-suggestion produced %d mappings, want 1", n)
	}

	var confirmed struct {
		ConfirmedSingleReporter bool `json:"confirmed_single_reporter"`
		ConfirmedConflict       bool `json:"confirmed_conflict"`
	}
	if err := env.pool.QueryRow(context.Background(), `
		SELECT (after->>'confirmed_single_reporter')::bool, (after->>'confirmed_conflict')::bool
		FROM homebrew_review_audit WHERE review_id = $1 AND action = 'accept_suggestion'
	`, reviewID).Scan(&confirmed.ConfirmedSingleReporter, &confirmed.ConfirmedConflict); err != nil {
		t.Fatalf("audit row missing confirmation fields: %v", err)
	}
	if !confirmed.ConfirmedSingleReporter || confirmed.ConfirmedConflict {
		t.Fatalf("audit confirmations = %+v, want single_reporter=true conflict=false", confirmed)
	}
}

// P2, the other half: once a second distinct tenant reports the same
// package, no confirmation is needed at all.
func TestHomebrewReviewAcceptSuggestion_TwoReportersNoConfirmationNeeded(t *testing.T) {
	sfx := randomHex(4)
	formula := "pat2046two-" + sfx
	vendor := "pat2046t" + sfx
	cveID := "CVE-2099-" + sfx + "T"
	seedFeedEntry(t, cveID, vendor, "tool", "2.0", false)
	key := vendor + ":tool"

	formulae := []any{brewFormula(formula, "1.5.0", true, nil, nil)}
	tnA := newCVETestTenant(t, "pat2046-two-a-"+sfx)
	hwA := sfx + "-2046-4000-8000-0000000000c1"
	postInventoryAs(t, tnA.bearer, tnA.hmacSecret, brewCVEPayload(t, tnA, hwA, "complete", formulae, nil, nil))
	tnB := newCVETestTenant(t, "pat2046-two-b-"+sfx)
	hwB := sfx + "-2046-4000-8000-0000000000c2"
	postInventoryAs(t, tnB.bearer, tnB.hmacSecret, brewCVEPayload(t, tnB, hwB, "complete", formulae, nil, nil))

	if n := countRows(t, `SELECT count(DISTINCT tenant_id) FROM homebrew_current_entries WHERE package_kind = 'formula' AND lower(btrim(name)) = $1`, strings.ToLower(formula)); n != 2 {
		t.Fatalf("test invalid: %d distinct tenants report %s, want 2", n, formula)
	}

	reviewID := seedHomebrewReviewRow(t, "formula", formula, &key, false)

	var out hrReviewResp
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/accept-suggestion", reviewID),
		nil, http.StatusOK, &out)
	if out.Review.Status != "mapped" {
		t.Fatalf("review status = %q, want mapped", out.Review.Status)
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE lower(match_name) = $1 AND cpe_vendor = $2 AND cpe_product = 'tool'`,
		strings.ToLower(formula), vendor); n != 1 {
		t.Fatalf("two-reporter accept-suggestion produced %d mappings, want 1", n)
	}
}

// P3: Map rejects a cpe_vendor or cpe_product containing ':', whitespace or
// an empty value, the same shape HomebrewSuggestionCandidates already
// requires of a suggestion candidate.
func TestHomebrewReviewMap_RejectsMalformedCPEComponents(t *testing.T) {
	sfx := randomHex(4)
	for _, tc := range []struct {
		name, vendor, product string
	}{
		{"colon in vendor", "vendor:evil", "product"},
		{"colon in product", "vendor", "product:evil"},
		{"whitespace in vendor", "ven dor", "product"},
		{"whitespace in product", "vendor", "prod uct"},
		{"empty vendor", "", "product"},
		{"empty product", "vendor", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			formula := "pat2046bad-" + sfx + "-" + randomHex(2)
			reviewID := seedHomebrewReviewRow(t, "formula", formula, nil, false)
			adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/map", reviewID),
				map[string]any{"cpe_vendor": tc.vendor, "cpe_product": tc.product}, http.StatusBadRequest, nil)
			if n := countRows(t, `SELECT count(*) FROM homebrew_review_audit WHERE review_id = $1`, reviewID); n != 0 {
				t.Fatalf("%s: refused map wrote %d audit rows, want 0", tc.name, n)
			}
		})
	}
}

// dismiss marks a pending row dismissed and audits it; a second dismiss is
// refused as a conflict.
func TestHomebrewReviewDismiss(t *testing.T) {
	sfx := randomHex(4)
	reviewID := seedHomebrewReviewRow(t, "cask", "pat2046dis-"+sfx, nil, false)

	var out hrReviewResp
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/dismiss", reviewID), nil, http.StatusOK, &out)
	if out.Review.Status != "dismissed" {
		t.Fatalf("review status = %q, want dismissed", out.Review.Status)
	}
	if actions := homebrewReviewAuditActions(t, reviewID); len(actions) != 1 || actions[0] != "dismiss" {
		t.Fatalf("audit actions = %v, want [dismiss]", actions)
	}
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/homebrew/review/%d/dismiss", reviewID), nil, http.StatusConflict, nil)
}

// The list response carries no tenant or device identifier anywhere, only
// the global queue row plus its aggregate estate prevalence.
func TestHomebrewReviewList_NoTenantOrDeviceIDs(t *testing.T) {
	sfx := randomHex(4)
	seedHomebrewReviewRow(t, "formula", "pat2046list-"+sfx, nil, false)

	resp := getAdminJSON(t, "/admin/homebrew/review?status=pending&kind=formula&sort=prevalence")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/homebrew/review: got %d, want 200", resp.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	body := string(raw["reviews"])
	if strings.Contains(body, "tenant_id") || strings.Contains(body, "device_id") {
		t.Fatalf("review list carries a tenant or device identifier: %s", body)
	}

	var page struct {
		Reviews []struct {
			Name             string `json:"name"`
			EstatePrevalence int    `json:"estate_prevalence"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal([]byte(`{"reviews":`+body+`}`), &page); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range page.Reviews {
		if r.Name == "pat2046list-"+sfx {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded row not present in filtered list: %s", body)
	}
}
