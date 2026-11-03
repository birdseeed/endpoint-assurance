//go:build integration

package integration

// PAT-2138 x PAT-2156: the device-scoped software view
// (GET /v1/portal/software?device_id=) assesses exactly like the estate view,
// scoped to one device: per-platform mappings, exact-token automatic
// mappings, the mapping_under_review / no_mapping reason and the automatic
// mapping basis.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"patched.im/api/internal/cpepropose"
)

func softwareAssessments(t *testing.T, token, path string) map[string]map[string]any {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, raw)
	}
	var page struct {
		Products []struct {
			Identifier    string         `json:"identifier"`
			CVEAssessment map[string]any `json:"cve_assessment"`
		} `json:"products"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, p := range page.Products {
		out[p.Identifier] = p.CVEAssessment
	}
	return out
}

func TestPortalSoftwareDeviceAssessmentMatchesEstate(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	sfx := randomHex(4)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2138-devsoft-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantID)
	device := seedPortalSoftwareDevice(t, tenantID, "pat2138-devsoft-"+sfx, "ok", now)

	review := "Pat2138 Devreview " + sfx
	winOnly := "Pat2138 Devwinonly " + sfx
	autoExact := "Pat2138 Devauto " + sfx
	autoLonger := "Pat2138 Devauto " + sfx + " Helper"
	ids := map[string]string{review: "com.example.devreview." + sfx, winOnly: "com.example.devwinonly." + sfx,
		autoExact: "com.example.devauto." + sfx, autoLonger: "com.example.devautohelper." + sfx}
	for name, id := range ids {
		seedPortalSoftwareApp(t, device, name, id, "1.0", now, nil)
	}
	// An open proposal for one product; a Windows-only curated mapping for
	// another; an automatic mapping whose match_name is a strict prefix of a
	// third product's name.
	if _, err := env.pool.Exec(ctx, `INSERT INTO cpe_mapping_proposals (platform, normalized_name, display_name, state, state_reason)
		VALUES ('macos', $1, $2, 'needs_review', 'no_candidates')`, cpepropose.NormalizeName(review), review); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('windows', $1, 'pat2138dw', 'devwinonly', 'test', 'app_name', 'curated'),
		       ('macos', $2, 'pat2138da', 'devauto', 'test', 'app_name', 'auto')`, winOnly, autoExact); err != nil {
		t.Fatal(err)
	}
	email := "pat2138-devsoft-" + sfx + "@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	onDevice := softwareAssessments(t, token, "/v1/portal/software?device_id="+device)
	estate := softwareAssessments(t, token, "/v1/portal/software")
	check := func(name, state, reason, basis string) {
		t.Helper()
		for label, page := range map[string]map[string]map[string]any{"device": onDevice, "estate": estate} {
			a := page[ids[name]]
			if a == nil {
				t.Errorf("%s view: no row for %s", label, name)
				continue
			}
			if a["state"] != state || str(a["reason"]) != reason || str(a["mapping_basis"]) != basis {
				t.Errorf("%s view: %s = state %v reason %v basis %v; want %s / %q / %q",
					label, name, a["state"], a["reason"], a["mapping_basis"], state, reason, basis)
			}
		}
	}
	check(review, "not_assessed", "mapping_under_review", "")
	check(winOnly, "not_assessed", "no_mapping", "")
	check(autoLonger, "not_assessed", "no_mapping", "")
	check(autoExact, "pending", "", "auto")
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
