//go:build integration

package integration

// PAT-2121: approving a Windows application records the Authenticode
// publisher its own evidence vouches for, and another trusted product from
// that publisher then reads low. Inventory goes through /v1/inventory and the
// extractor, and the approval through the real portal write, so the key is
// derived from what the platform actually stored.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/handlers"
)

func winPolicyPublisherKey(t *testing.T, tenantID, identifier string) *string {
	t.Helper()
	var key *string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT publisher_key FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND platform = 'windows' AND lower(bundle_id) = lower($2)`,
		tenantID, identifier).Scan(&key); err != nil {
		t.Fatalf("read policy publisher_key for %s: %v", identifier, err)
	}
	return key
}

func operatorAppPolicyPut(t *testing.T, tenantID, body string) (int, string) {
	t.Helper()
	r := chi.NewRouter()
	r.Put("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesPutHandler(env.pool, nil))
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestWindowsPublisherApprovalReadsLow(t *testing.T) {
	tn := newUrgencyTenant(t, "win-publisher")
	other := newUrgencyTenant(t, "win-publisher-other")
	admin := "admin-win-publisher-" + randomHex(4) + "@pat2121.example"
	mapPortalUserWithRole(t, admin, tn.id, "admin")
	adminToken := env.idp.token(t, admin)

	sfx := randomHex(4)
	name := func(s string) string { return "Urg Win Publisher " + s + " " + sfx }
	ident := func(s string) string { return "{PAT2121-" + strings.ToUpper(s) + "-" + sfx + "}" }
	signer := "CN=Example " + sfx + " Ltd, O=Example " + sfx + " Ltd, C=GB"
	// The same Subject DN as the agent might report it with a doubled space:
	// the key normalises it, so it is the same publisher.
	signerSpaced := "CN=Example " + sfx + "  Ltd, O=Example " + sfx + " Ltd, C=GB"
	rootMS, rootOther := strings.Repeat("c", 64), strings.Repeat("d", 64)
	wantKey := "authenticode:" + rootMS + ":" + signer

	vendor := "pat2121v" + sfx
	for _, s := range []string{"approved", "sibling", "enterprise", "otherroot", "crosstenant", "mixed"} {
		seedCVEMapping(t, name(s), vendor, s)
	}
	seedWindowsAlias(t, ident("approved"))
	seedWindowsAlias(t, ident("mixed"))

	// 1. The first product is inventoried, then approved through the portal.
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("a1"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppPinned(name("approved"), ident("approved"), "valid", signer, rootMS, "microsoft"),
			urgWinAppPinned(name("mixed"), ident("mixed"), "valid", signer, rootMS, "microsoft"),
		})
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("a2"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			// Mixed: a second installation under an enterprise root.
			urgWinAppPinned(name("mixed"), ident("mixed"), "valid", signer, rootOther, "enterprise"),
		})
	drainCVEQueue(t)

	winItem := func(id string) string {
		return fmt.Sprintf(`{"type":"application","platform":"windows","identifier":%q}`, id)
	}

	// A client-sent publisher key is refused, wherever it is put and however
	// it is spelled, and nothing is written.
	for _, body := range []string{
		fmt.Sprintf(`{"state":"approved","items":[{"type":"application","platform":"windows","identifier":%q,"publisher_key":%q}]}`,
			ident("approved"), wantKey),
		fmt.Sprintf(`{"state":"approved","publisher_key":%q,"items":[%s]}`, wantKey, winItem(ident("approved"))),
		fmt.Sprintf(`{"state":"approved","items":[{"type":"application","platform":"windows","identifier":%q,"Publisher_Key":%q}]}`,
			ident("approved"), wantKey),
	} {
		refused(t, adminToken, body, http.StatusBadRequest, "invalid_request")
	}
	if _, _, _, ok := appPolicy(t, tn.id, ident("approved")); ok {
		t.Fatal("a refused write created a policy row")
	}
	for _, body := range []string{
		fmt.Sprintf(`{"bundle_id":%q,"platform":"windows","policy":"approved","publisher_key":%q}`, ident("approved"), wantKey),
		fmt.Sprintf(`{"bundle_id":%q,"platform":"windows","policy":"approved","PUBLISHER_KEY":null}`, ident("approved")),
	} {
		if code, msg := operatorAppPolicyPut(t, tn.id, body); code != http.StatusBadRequest {
			t.Fatalf("operator PUT with a publisher key = %d %s, want 400", code, msg)
		}
	}
	if _, _, _, ok := appPolicy(t, tn.id, ident("approved")); ok {
		t.Fatal("a refused operator write created a policy row")
	}

	mustApprove(t, adminToken, approvalBody("approved", "", winItem(ident("approved")), winItem(ident("mixed"))))
	if got := winPolicyPublisherKey(t, tn.id, ident("approved")); got == nil || *got != wantKey {
		t.Fatalf("approved row publisher_key = %v, want %q", got, wantKey)
	}
	// Installations that disagree (one enterprise root) record no key.
	if got := winPolicyPublisherKey(t, tn.id, ident("mixed")); got != nil {
		t.Fatalf("mixed-evidence row publisher_key = %q, want NULL", *got)
	}

	// The new software window starts at the last review, so the products
	// under test must be first seen after the approval above.
	time.Sleep(1100 * time.Millisecond)

	// 2. New products arrive after the approval.
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("b1"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppPinned(name("sibling"), ident("sibling"), "valid", signerSpaced, rootMS, "microsoft"),
			urgWinAppPinned(name("enterprise"), ident("enterprise"), "valid", signer, rootOther, "enterprise"),
			urgWinAppPinned(name("otherroot"), ident("otherroot"), "valid", signer, rootOther, "public"),
		})
	// Another tenant: the same publisher, installed, but never approved there.
	postUrgencyInventory(t, other, "full-v3-windows.json", strings.ToUpper("c1"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppPinned(name("crosstenant"), ident("crosstenant"), "valid", signer, rootMS, "microsoft"),
		})
	drainCVEQueue(t)

	got := urgencyByName(fetchUrgency(t, tn))
	for n, w := range map[string]struct{ level, reason string }{
		name("sibling"):    {"low", "authenticode_publisher_has_approved_products"},
		name("enterprise"): {"high", "enterprise_root"},
		name("otherroot"):  {"medium", "trusted_publisher_no_known_cves"},
	} {
		p, ok := got[n]
		if !ok {
			t.Errorf("%s absent from new_software", n)
			continue
		}
		if p.Urgency != w.level || !hasUrgencyReason(p, w.reason) {
			t.Errorf("%s: urgency %q reasons %+v, want %q with %q", n, p.Urgency, p.Reasons, w.level, w.reason)
		}
		if hasUrgencyReason(p, "publisher_has_approved_products") {
			t.Errorf("%s carries the macOS Team ID reason", n)
		}
	}
	gotOther := urgencyByName(fetchUrgency(t, other))
	if p, ok := gotOther[name("crosstenant")]; !ok || p.Urgency != "medium" ||
		!hasUrgencyReason(p, "trusted_publisher_no_known_cves") {
		t.Errorf("cross-tenant product = %+v (present %v), want medium: another tenant's approval must not count", p, ok)
	}

	// 3. Leaving approved clears the key, and the sibling drops back to
	// medium. The operator path derives the key the same way. (Operator
	// writes, unlike portal ones, do not move the last review, so the
	// sibling stays in the window.)
	if code, msg := operatorAppPolicyPut(t, tn.id,
		fmt.Sprintf(`{"bundle_id":%q,"platform":"windows","policy":"unmanaged"}`, ident("approved"))); code != http.StatusOK {
		t.Fatalf("operator ignore = %d %s", code, msg)
	}
	if got := winPolicyPublisherKey(t, tn.id, ident("approved")); got != nil {
		t.Fatalf("ignored row publisher_key = %q, want NULL", *got)
	}
	if p := urgencyByName(fetchUrgency(t, tn))[name("sibling")]; p.Urgency != "medium" {
		t.Fatalf("sibling after the approval was withdrawn: %q %+v, want medium", p.Urgency, p.Reasons)
	}
	if code, msg := operatorAppPolicyPut(t, tn.id,
		fmt.Sprintf(`{"bundle_id":%q,"platform":"windows","policy":"approved"}`, ident("approved"))); code != http.StatusOK {
		t.Fatalf("operator approve = %d %s", code, msg)
	}
	if got := winPolicyPublisherKey(t, tn.id, ident("approved")); got == nil || *got != wantKey {
		t.Fatalf("operator-approved row publisher_key = %v, want %q", got, wantKey)
	}
	if p := urgencyByName(fetchUrgency(t, tn))[name("sibling")]; p.Urgency != "low" {
		t.Fatalf("sibling after the operator approval: %q %+v, want low", p.Urgency, p.Reasons)
	}
	// An operator approval of the enterprise-rooted product records no key.
	if code, msg := operatorAppPolicyPut(t, tn.id,
		fmt.Sprintf(`{"bundle_id":%q,"platform":"windows","policy":"approved"}`, ident("enterprise"))); code != http.StatusOK {
		t.Fatalf("operator approve enterprise = %d %s", code, msg)
	}
	if got := winPolicyPublisherKey(t, tn.id, ident("enterprise")); got != nil {
		t.Fatalf("enterprise-rooted row publisher_key = %q, want NULL", *got)
	}
}
