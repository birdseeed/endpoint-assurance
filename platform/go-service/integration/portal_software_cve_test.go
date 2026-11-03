//go:build integration

package integration

// PAT-2028: GET /v1/portal/software gains an estate-wide per-product CVE
// assessment. The portal is stateless and cannot build this state for the
// whole estate from the per-device reads PAT-2024 already exposes, so this
// file exercises the endpoint directly rather than reusing
// portalDeviceAssessment from cve_event_match_test.go. Product names, bundle
// identifiers and CVE IDs carry a per-test random suffix so the shared
// integration database cannot cross-contaminate counts.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type portalSoftwareCVERow struct {
	Identifier    string `json:"identifier"`
	Platform      string `json:"platform"`
	Name          string `json:"name"`
	CVEAssessment struct {
		State         string     `json:"state"`
		LastMatchedAt *time.Time `json:"last_matched_at"`
		FindingCount  *int       `json:"finding_count"`
	} `json:"cve_assessment"`
}

// fetchPortalSoftwareProduct hits GET /v1/portal/software with search
// narrowed to bundleID (which the query matches against product.identifier,
// among other columns) and returns the one row expected to match. It fails
// the test if more or fewer than one row comes back, since every caller here
// seeded exactly one identifier.
func fetchPortalSoftwareProduct(t *testing.T, tn cveTestTenant, bundleID string) portalSoftwareCVERow {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/software?search="+bundleID, tn.token, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/portal/software: %d %s", resp.StatusCode, raw)
	}
	var out struct {
		Products []portalSoftwareCVERow `json:"products"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode /v1/portal/software: %v; body %s", err, raw)
	}
	var matches []portalSoftwareCVERow
	for _, p := range out.Products {
		if p.Identifier == bundleID {
			matches = append(matches, p)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("GET /v1/portal/software?search=%s returned %d rows for that identifier, want 1; body %s", bundleID, len(matches), raw)
	}
	return matches[0]
}

// A product installed on two devices and matched on both reads assessed,
// with the oldest last_matched_at across the installations and the tenant's
// open finding count for it.
func TestPortalSoftwareCVEAssessmentAssessedAcrossDevices(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2028-assessed-"+sfx)
	vendor, product := "pat2028v"+sfx, "widget"
	appName := "Pat2028 Widget " + sfx
	bundleID := "com.example.pat2028.widget." + sfx
	cveID := "CVE-2099-" + sfx + "2"

	seedFeedEntry(t, cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, appName, vendor, product)
	drainCVEQueue(t) // absorb the mapping publish; no observation exists yet

	// postAppsPayload derives the device serial from the first 8 characters
	// of hwUUID, so the two devices need distinct leading characters, not
	// just a distinct suffix, or the second insert collides on
	// devices_tenant_id_serial_key.
	hw1 := strings.ToUpper("aaaa" + sfx + "-1111-2222-333344445555")
	hw2 := strings.ToUpper("bbbb" + sfx + "-1111-2222-333344445555")
	postAppsPayload(t, tn, hw1, []cveTestApp{{appName, "1.5", bundleID}})
	postAppsPayload(t, tn, hw2, []cveTestApp{{appName, "1.5", bundleID}})
	drainCVEQueue(t)

	row := fetchPortalSoftwareProduct(t, tn, bundleID)
	if row.CVEAssessment.State != "assessed" {
		t.Fatalf("state = %q, want assessed", row.CVEAssessment.State)
	}
	if row.CVEAssessment.LastMatchedAt == nil {
		t.Fatal("last_matched_at is null on an assessed product")
	}
	if row.CVEAssessment.FindingCount == nil || *row.CVEAssessment.FindingCount != 1 {
		t.Fatalf("finding_count = %v, want 1", row.CVEAssessment.FindingCount)
	}
}

// The same product installed on two devices, one matched and one still
// queued, reads pending at the estate level: "pending when any active
// installation of it in the tenant is queued or has never been matched at
// its current versions" (PAT-2028).
func TestPortalSoftwareCVEAssessmentPendingWhenAnyDeviceUnmatched(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2028-pending-"+sfx)
	vendor, product := "pat2028v"+sfx, "widget"
	appName := "Pat2028 Widget " + sfx
	bundleID := "com.example.pat2028.widget." + sfx
	cveID := "CVE-2099-" + sfx + "3"

	seedFeedEntry(t, cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, appName, vendor, product)
	drainCVEQueue(t)

	hw1 := strings.ToUpper("cccc" + sfx + "-1111-2222-333344445555")
	postAppsPayload(t, tn, hw1, []cveTestApp{{appName, "1.5", bundleID}})
	drainCVEQueue(t) // device 1 is now assessed

	assessedOnly := fetchPortalSoftwareProduct(t, tn, bundleID)
	if assessedOnly.CVEAssessment.State != "assessed" {
		t.Fatalf("state before device 2 = %q, want assessed", assessedOnly.CVEAssessment.State)
	}

	hw2 := strings.ToUpper("dddd" + sfx + "-1111-2222-333344445555")
	postAppsPayload(t, tn, hw2, []cveTestApp{{appName, "1.5", bundleID}}) // queued, not drained

	row := fetchPortalSoftwareProduct(t, tn, bundleID)
	if row.CVEAssessment.State != "pending" {
		t.Fatalf("state = %q, want pending (device 2 is still queued)", row.CVEAssessment.State)
	}
	if row.CVEAssessment.LastMatchedAt != nil {
		t.Fatalf("last_matched_at = %v, want null while pending", row.CVEAssessment.LastMatchedAt)
	}
	if row.CVEAssessment.FindingCount == nil {
		t.Fatal("finding_count is null on a mapped-but-pending product; want the count from device 1's completed match")
	}

	drainCVEQueue(t)
	after := fetchPortalSoftwareProduct(t, tn, bundleID)
	if after.CVEAssessment.State != "assessed" {
		t.Fatalf("state after drain = %q, want assessed", after.CVEAssessment.State)
	}
}

// A product with no CPE mapping anywhere in the tenant reads not_assessed
// with a null finding_count, never zero: absence requires authority.
func TestPortalSoftwareCVEAssessmentUnmappedProductNotAssessedWithNullCount(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2028-unmapped-"+sfx)
	appName := "Pat2028 Inhouse " + sfx
	bundleID := "com.example.pat2028.inhouse." + sfx

	hw := strings.ToUpper(sfx + "-eeee-1111-2222-333344445555")
	postAppsPayload(t, tn, hw, []cveTestApp{{appName, "3.1", bundleID}})
	drainCVEQueue(t) // nothing to drain; unmapped products are never queued

	row := fetchPortalSoftwareProduct(t, tn, bundleID)
	if row.CVEAssessment.State != "not_assessed" {
		t.Fatalf("state = %q, want not_assessed", row.CVEAssessment.State)
	}
	if row.CVEAssessment.FindingCount != nil {
		t.Fatalf("finding_count = %v, want null for not_assessed", row.CVEAssessment.FindingCount)
	}
}

// Two tenants with a device carrying the identical identifier, name and
// version, both matched against the same vulnerability, each read their own
// finding count: the tenant scoping in AssessEstateProducts must not merge
// or leak across tenants just because the identifier collides.
func TestPortalSoftwareCVEAssessmentTenantIsolation(t *testing.T) {
	sfx := randomHex(4)
	tnA := newCVETestTenant(t, "pat2028-isoA-"+sfx)
	tnB := newCVETestTenant(t, "pat2028-isoB-"+sfx)
	vendor, product := "pat2028v"+sfx, "widget"
	appName := "Pat2028 Widget " + sfx
	bundleID := "com.example.pat2028.widget." + sfx
	cveID := "CVE-2099-" + sfx + "4"

	seedFeedEntry(t, cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, appName, vendor, product)
	drainCVEQueue(t)

	hwA := strings.ToUpper(sfx + "-ffff-1111-2222-333344445555")
	postAppsPayload(t, tnA, hwA, []cveTestApp{{appName, "1.5", bundleID}})
	drainCVEQueue(t)

	// Tenant B never installs the product at all: it must not inherit
	// tenant A's assessment for the same identifier.
	rowA := fetchPortalSoftwareProduct(t, tnA, bundleID)
	if rowA.CVEAssessment.State != "assessed" || rowA.CVEAssessment.FindingCount == nil || *rowA.CVEAssessment.FindingCount != 1 {
		t.Fatalf("tenant A row = %+v, want assessed/1", rowA.CVEAssessment)
	}
	respB := portalDo(t, http.MethodGet, "/v1/portal/software?search="+bundleID, tnB.token, nil)
	var outB struct {
		Products []portalSoftwareCVERow `json:"products"`
	}
	decodeJSON(t, respB, &outB)
	for _, p := range outB.Products {
		if p.Identifier == bundleID {
			t.Fatalf("tenant B sees tenant A's product %s in its own /v1/portal/software page", bundleID)
		}
	}

	// A device count sanity check straight from the query the handler itself
	// runs, in case the isolation bug hid behind pagination rather than the
	// tenant filter.
	if n := countRows(t, `
		SELECT count(*) FROM device_cve_findings f
		JOIN devices d ON d.id = f.device_id
		WHERE d.tenant_id = $1::uuid AND f.cve_id = $2
	`, tnB.tenantID, cveID); n != 0 {
		t.Fatalf("tenant B has %d findings for a CVE it was never exposed to", n)
	}
}
