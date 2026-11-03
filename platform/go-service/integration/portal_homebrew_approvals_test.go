//go:build integration

package integration

// PAT-2058: Homebrew formulae and casks join the software approval model --
// same resolver, same software_approval_decisions audit table, same
// PUT /v1/portal/software-approvals write endpoint as applications and
// browser extensions (PAT-1786/PAT-2007/PAT-2104). This exercises the full
// stack: POST /v1/inventory -> extractor -> approve/unapprove a formula and
// a cask -> approval_state on the Homebrew portal endpoints -> the drift
// report -> the decision audit -> roles -> tenant isolation.

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"patched.im/api/internal/softwaregov"
)

func hbFormulaItem(name, tap string) string {
	if tap == "" {
		return fmt.Sprintf(`{"type":"homebrew_formula","name":%q}`, name)
	}
	return fmt.Sprintf(`{"type":"homebrew_formula","name":%q,"tap":%q}`, name, tap)
}

// TestPortalOverviewHomebrewOnlyUnapproved verifies that the Overview's full
// and summary paths do not discard a tenant whose only Unapproved policies
// are Homebrew formula and cask policies.
func TestPortalOverviewHomebrewOnlyUnapproved(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "overview-homebrew-only")
	ctx := context.Background()
	for _, p := range []struct {
		kind, name, tap string
	}{
		{"formula", "openssl@3", ""},
		{"cask", "firefox", ""},
	} {
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, tap, policy)
			VALUES ($1::uuid, $2, $3, $4, 'unapproved')`, at.tenantID, p.kind, p.name, p.tap); err != nil {
			t.Fatalf("insert %s policy: %v", p.kind, err)
		}
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, at.tenantID, time.Now()); err != nil {
		t.Fatalf("reconcile Homebrew presence: %v", err)
	}

	assertOverview := func(label string, got softwaregov.OverviewSummary, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got.Products != 2 || got.Devices != 1 || len(got.Items) != 2 {
			t.Fatalf("%s = %+v, want two products, one device, and two items", label, got)
		}
		keys := map[string]bool{}
		for _, item := range got.Items {
			if item.DeviceCount != 1 {
				t.Fatalf("%s item = %+v, want one device", label, item)
			}
			keys[item.ProductKey] = true
		}
		for _, want := range []string{"homebrew:formula:openssl@3", "homebrew:cask:firefox"} {
			if !keys[want] {
				t.Fatalf("%s items = %+v, missing %q", label, got.Items, want)
			}
		}
	}

	asOf := time.Now()
	full, err := softwaregov.UnapprovedOverviewFull(ctx, env.pool, at.tenantID, asOf, 0)
	assertOverview("full overview", full, err)
	summary, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, at.tenantID, asOf, 0)
	assertOverview("summary overview", summary, err)
	public, err := softwaregov.UnapprovedOverview(ctx, env.pool, at.tenantID, asOf, 0)
	assertOverview("public overview", public, err)

	var portal struct {
		UnapprovedPresent        *int                       `json:"unapproved_present"`
		UnapprovedPresentDevices *int                       `json:"unapproved_present_devices"`
		UnapprovedPresentItems   []softwaregov.OverviewItem `json:"unapproved_present_items"`
	}
	getJSON(t, "/v1/portal/overview", at.viewerToken, &portal)
	if portal.UnapprovedPresent == nil || *portal.UnapprovedPresent != 2 ||
		portal.UnapprovedPresentDevices == nil || *portal.UnapprovedPresentDevices != 1 ||
		len(portal.UnapprovedPresentItems) != 2 {
		t.Fatalf("portal overview = %+v, want two products, one device, and two items", portal)
	}
	assertOverview("portal overview", softwaregov.OverviewSummary{
		Products: *portal.UnapprovedPresent,
		Devices:  *portal.UnapprovedPresentDevices,
		Items:    portal.UnapprovedPresentItems,
	}, nil)
	if alerts := govAlerts(t, at.tenantID); len(alerts) != 0 {
		t.Fatalf("overview-only Homebrew test created alerts: %+v", alerts)
	}
}

func hbCaskItem(name, tap string) string {
	if tap == "" {
		return fmt.Sprintf(`{"type":"homebrew_cask","name":%q}`, name)
	}
	return fmt.Sprintf(`{"type":"homebrew_cask","name":%q,"tap":%q}`, name, tap)
}

// setUpHomebrewApprovalTenant creates a tenant with ingestion credentials, a
// portal admin and a portal viewer, and posts the standard Homebrew fixture
// (openssl@3 and acme-cli/acme-tools formulae, a firefox cask,
// homebrew/core+cask+acme/tools taps) through POST /v1/inventory and the
// extractor. Unlike newApprovalTenant (PAT-2007), this also keeps the
// tenant's bearer token and HMAC secret, since a Homebrew identity has to be
// confirmed against this tenant's own posted inventory (PAT-2058).
func setUpHomebrewApprovalTenant(t *testing.T, label string) *approvalTenant {
	return setUpHomebrewApprovalTenantWithLink(t, label, false)
}

// setUpHomebrewApprovalTenantWithLink supplies either an ordinary standalone
// cask (for the Homebrew policy lifecycle) or the Firefox bundle-linked cask
// fixture used to prove that a cask inherits its application policy.
func setUpHomebrewApprovalTenantWithLink(t *testing.T, label string, linkedCask bool) *approvalTenant {
	t.Helper()
	suffix := randomHex(4)
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2058-"+label+"-"+suffix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	at := &approvalTenant{
		tenantID:    tenantID,
		bearerToken: bearer,
		hmacSecret:  secret,
		adminEmail:  "admin-hb-" + label + "-" + suffix + "@approvals.example",
		viewerEmail: "viewer-hb-" + label + "-" + suffix + "@approvals.example",
	}
	if got := mapPortalUserWithRole(t, at.adminEmail, tenantID, "admin"); got.Role != "admin" {
		t.Fatalf("admin mapping role = %q", got.Role)
	}
	if got := mapPortalUserWithRole(t, at.viewerEmail, tenantID, ""); got.Role != "viewer" {
		t.Fatalf("viewer mapping role = %q", got.Role)
	}
	at.adminToken = env.idp.token(t, at.adminEmail)
	at.viewerToken = env.idp.token(t, at.viewerEmail)
	postInventoryAs(t, bearer, secret, homebrewPayload(t, "PAT2058-"+label+"-"+suffix, "pat2058-"+label+"-"+suffix, func(hb map[string]any) {
		if linkedCask {
			return
		}
		// The baseline approval lifecycle needs a cask that is an independent
		// decision target. The fixture's normal Firefox app link is covered by
		// TestPortalHomebrewLinkedCaskInheritsApplicationPolicy below.
		for _, raw := range hb["casks"].([]any) {
			raw.(map[string]any)["apps"] = []any{}
		}
	}))
	return at
}

type hbApprovalFormulaeOut struct {
	Formulae []struct {
		Identity      hbIdentityOut `json:"identity"`
		Name          string        `json:"name"`
		ApprovalState string        `json:"approval_state"`
		ProductKey    string        `json:"product_key"`
	} `json:"formulae"`
}

type hbApprovalCasksOut struct {
	Casks []struct {
		Identity      hbIdentityOut `json:"identity"`
		Token         string        `json:"token"`
		ApprovalState string        `json:"approval_state"`
		ProductKey    string        `json:"product_key"`
	} `json:"casks"`
}

type hbApprovalSummaryOut struct {
	UnreviewedCount int `json:"unreviewed_count"`
	UnapprovedCount int `json:"unapproved_count"`
}

func findFormula(out hbApprovalFormulaeOut, name string) (approvalState, productKey string, ok bool) {
	for _, f := range out.Formulae {
		if f.Identity.Name == name {
			return f.ApprovalState, f.ProductKey, true
		}
	}
	return "", "", false
}

func findCask(out hbApprovalCasksOut, token string) (approvalState, productKey string, ok bool) {
	for _, c := range out.Casks {
		if c.Token == token {
			return c.ApprovalState, c.ProductKey, true
		}
	}
	return "", "", false
}

// TestPortalHomebrewApprovalLifecycle approves then unapproves a formula and
// a cask, checking the Unreviewed default, approval_state on the Homebrew
// portal endpoints, the policy row, and the decision audit (actor, previous
// and new state).
func TestPortalHomebrewApprovalLifecycle(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "lifecycle")

	// Unreviewed by default, before any decision.
	var formulae hbApprovalFormulaeOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	state, key, ok := findFormula(formulae, "openssl@3")
	if !ok || state != softwaregov.StateUnreviewed {
		t.Fatalf("openssl@3 initial state = %q (ok=%v), want unreviewed", state, ok)
	}
	if key != "homebrew:formula:openssl@3" {
		t.Fatalf("openssl@3 product_key = %q", key)
	}

	var casks hbApprovalCasksOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/casks", &casks)
	cState, cKey, ok := findCask(casks, "firefox")
	if !ok || cState != softwaregov.StateUnreviewed {
		t.Fatalf("firefox initial state = %q (ok=%v), want unreviewed", cState, ok)
	}
	if cKey != "homebrew:cask:firefox" {
		t.Fatalf("firefox product_key = %q", cKey)
	}

	// Approve the formula and the cask together, tap omitted (default tap).
	out := mustApprove(t, at.adminToken, approvalBody("approved", "trusted build tooling",
		hbFormulaItem("openssl@3", ""), hbCaskItem("firefox", "")))
	if out.ChangedCount != 2 {
		t.Fatalf("changed_count = %d, want 2: %+v", out.ChangedCount, out)
	}
	for _, r := range out.Results {
		if !r.Changed || r.PreviousState != "unreviewed" || r.NewState != "approved" {
			t.Fatalf("result = %+v", r)
		}
	}

	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	if state, _, _ := findFormula(formulae, "openssl@3"); state != "approved" {
		t.Fatalf("openssl@3 state after approve = %q", state)
	}
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/casks", &casks)
	if state, _, _ := findCask(casks, "firefox"); state != "approved" {
		t.Fatalf("firefox state after approve = %q", state)
	}

	// tenant_homebrew_policies rows exist with the right shape.
	var policyCount int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM tenant_homebrew_policies WHERE tenant_id = $1::uuid AND policy = 'approved'`,
		at.tenantID).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 2 {
		t.Fatalf("approved policy rows = %d, want 2", policyCount)
	}

	// Unapprove the formula only; the cask stays approved.
	out = mustApprove(t, at.adminToken, approvalBody("unapproved", "flagged in review", hbFormulaItem("openssl@3", "")))
	if out.ChangedCount != 1 || out.Results[0].PreviousState != "approved" || out.Results[0].NewState != "unapproved" {
		t.Fatalf("unapprove result = %+v", out)
	}
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	if state, _, _ := findFormula(formulae, "openssl@3"); state != "unapproved" {
		t.Fatalf("openssl@3 state after unapprove = %q", state)
	}
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/casks", &casks)
	if state, _, _ := findCask(casks, "firefox"); state != "approved" {
		t.Fatalf("firefox state after formula unapprove = %q, want still approved", state)
	}

	// Audit: one row per changed decision, actor recorded, product_type and
	// product_key match, no platform/team_id/browser leakage.
	audit := auditRows(t, at.tenantID)
	if len(audit) != 3 {
		t.Fatalf("audit rows = %d, want 3: %+v", len(audit), audit)
	}
	last := audit[len(audit)-1]
	if last.ProductType != "homebrew_formula" || last.ProductKey != "homebrew:formula:openssl@3" ||
		last.Prev != "approved" || last.New != "unapproved" || last.Actor != at.adminEmail {
		t.Fatalf("last audit row = %+v", last)
	}
}

// TestPortalHomebrewApprovalBulk approves a formula and a cask in one bulk
// call.
func TestPortalHomebrewApprovalBulk(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "bulk")
	out := mustApprove(t, at.adminToken, approvalBody("unapproved", "bulk flagged",
		hbFormulaItem("openssl@3", "homebrew/core"), hbCaskItem("firefox", "homebrew/cask"),
		hbFormulaItem("acme-cli", "acme/tools")))
	if out.ChangedCount != 3 {
		t.Fatalf("bulk changed_count = %d, want 3: %+v", out.ChangedCount, out)
	}
	keys := map[string]bool{}
	for _, r := range out.Results {
		keys[r.ProductKey] = true
	}
	for _, want := range []string{"homebrew:formula:openssl@3", "homebrew:cask:firefox", "homebrew:formula:acme/tools/acme-cli"} {
		if !keys[want] {
			t.Fatalf("bulk results missing %q: %+v", want, out.Results)
		}
	}
}

// TestPortalHomebrewApprovalFeedsDriftReport: an Unapproved formula and cask
// show up in GET /v1/portal/software/drift the way an application does.
func TestPortalHomebrewApprovalFeedsDriftReport(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "drift")
	mustApprove(t, at.adminToken, approvalBody("unapproved", "", hbFormulaItem("openssl@3", "")))

	var d softwaregov.Drift
	getJSON(t, "/v1/portal/software/drift", at.adminToken, &d)
	if d.Counts.Unapproved < 1 {
		t.Fatalf("drift counts.unapproved = %d, want >= 1: %+v", d.Counts.Unapproved, d.Counts)
	}
	var found *softwaregov.DriftProduct
	for i := range d.Products {
		if d.Products[i].ProductKey == "homebrew:formula:openssl@3" {
			found = &d.Products[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("homebrew formula not in drift products: %+v", d.Products)
	}
	if found.ApprovalState != "unapproved" || found.Type != softwaregov.TypeHomebrewFormula || found.Platform != "macos" {
		t.Fatalf("drift product = %+v", found)
	}

	// unapproved_present carries it too, with device presence.
	var present *softwaregov.UnapprovedPresent
	for i := range d.UnapprovedPresent {
		if d.UnapprovedPresent[i].ProductKey == "homebrew:formula:openssl@3" {
			present = &d.UnapprovedPresent[i]
			break
		}
	}
	if present == nil || present.DeviceCount < 1 {
		t.Fatalf("homebrew formula not in unapproved_present: %+v", d.UnapprovedPresent)
	}
}

// A cask which Homebrew links to an installed application bundle is not a
// separate approval target. Even a legacy direct cask row must not override
// the linked application policy, and writes against the cask are refused so
// it cannot be decided twice.
func TestPortalHomebrewLinkedCaskInheritsApplicationPolicy(t *testing.T) {
	at := setUpHomebrewApprovalTenantWithLink(t, "linked-cask", true)
	mustApprove(t, at.adminToken, approvalBody("unapproved", "application review", macApp("org.mozilla.firefox", "43AQ936H96")))

	// Simulate a pre-inheritance direct cask row. The cask read must still
	// return its application's unapproved state.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, tap, policy)
		VALUES ($1::uuid, 'cask', 'firefox', '', 'approved')`, at.tenantID); err != nil {
		t.Fatalf("seed legacy cask policy: %v", err)
	}
	var casks hbApprovalCasksOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/casks", &casks)
	if state, _, ok := findCask(casks, "firefox"); !ok || state != "unapproved" {
		t.Fatalf("linked firefox state = %q (ok=%v), want inherited unapproved", state, ok)
	}

	errOut := refused(t, at.adminToken, approvalBody("approved", "", hbCaskItem("firefox", "")), http.StatusConflict, "refused")
	if len(errOut.Items) != 1 || errOut.Items[0].Code != "linked_app_policy" {
		t.Fatalf("linked cask refusal = %+v", errOut)
	}
}

// TestPortalHomebrewApprovalSummaryCounts checks the unreviewed/unapproved
// counts on GET /v1/portal/homebrew/summary track decisions.
func TestPortalHomebrewApprovalSummaryCounts(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "summary")
	var before hbApprovalSummaryOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/summary", &before)
	// Fixture ships 3 formulae (openssl@3, ca-certificates, acme-cli) + 1
	// cask (firefox), none decided yet.
	if before.UnreviewedCount != 4 || before.UnapprovedCount != 0 {
		t.Fatalf("summary before decisions = %+v", before)
	}
	mustApprove(t, at.adminToken, approvalBody("unapproved", "", hbFormulaItem("openssl@3", "")))
	mustApprove(t, at.adminToken, approvalBody("approved", "", hbCaskItem("firefox", "")))

	var after hbApprovalSummaryOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/summary", &after)
	if after.UnreviewedCount != 2 || after.UnapprovedCount != 1 {
		t.Fatalf("summary after decisions = %+v, want unreviewed=2 unapproved=1", after)
	}
}

// TestPortalHomebrewApprovalWriteRequiresAdmin: a viewer is refused exactly
// as the existing write path refuses an application write (PAT-2007).
func TestPortalHomebrewApprovalWriteRequiresAdmin(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "role")
	refused(t, at.viewerToken, approvalBody("approved", "", hbFormulaItem("openssl@3", "")), http.StatusForbidden, "admin_role_required")
	var formulae hbApprovalFormulaeOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	if state, _, _ := findFormula(formulae, "openssl@3"); state != softwaregov.StateUnreviewed {
		t.Fatalf("viewer write changed state: %q", state)
	}
	if n := len(auditRows(t, at.tenantID)); n != 0 {
		t.Fatalf("viewer write produced %d audit rows", n)
	}
}

// TestPortalHomebrewApprovalCrossTenantIsolation: a tenant that never
// reported this formula cannot mark it (unconfirmed_identity), and a
// tenant's own decision never leaks into another tenant's view.
func TestPortalHomebrewApprovalCrossTenantIsolation(t *testing.T) {
	a := setUpHomebrewApprovalTenant(t, "iso-a")
	b := newApprovalTenant(t, "hb-iso-b", false) // never posted any Homebrew inventory

	mustApprove(t, a.adminToken, approvalBody("unapproved", "", hbFormulaItem("openssl@3", "")))

	refused(t, b.adminToken, approvalBody("unapproved", "", hbFormulaItem("openssl@3", "")),
		http.StatusUnprocessableEntity, "unconfirmed_identity")

	var bFormulae hbApprovalFormulaeOut
	portalGetJSON(t, b.adminToken, "/v1/portal/homebrew/formulae", &bFormulae)
	if len(bFormulae.Formulae) != 0 {
		t.Fatalf("tenant B sees tenant A's Homebrew inventory: %+v", bFormulae.Formulae)
	}
	if n := len(auditRows(t, b.tenantID)); n != 0 {
		t.Fatalf("tenant B has %d audit rows from tenant A's write", n)
	}
}

// TestPortalHomebrewApprovalUnconfirmedIdentityRefused: a name this tenant's
// own inventory has never reported is refused, even though the shape is
// otherwise valid.
func TestPortalHomebrewApprovalUnconfirmedIdentityRefused(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "unconfirmed")
	refused(t, at.adminToken, approvalBody("approved", "", hbFormulaItem("never-installed-tool", "")),
		http.StatusUnprocessableEntity, "unconfirmed_identity")
}

// homebrewPolicyRow reads back one tenant_homebrew_policies row.
func homebrewPolicyRow(t *testing.T, tenantID, kind, name string) (policy string, ok bool) {
	t.Helper()
	err := env.pool.QueryRow(context.Background(), `
		SELECT policy FROM tenant_homebrew_policies WHERE tenant_id = $1::uuid AND kind = $2 AND name = $3`,
		tenantID, kind, name).Scan(&policy)
	if err != nil {
		return "", false
	}
	return policy, true
}

// TestPortalHomebrewApprovalIgnoredRoundTrip: a formula and a cask can be
// set ignored (stored as 'unmanaged', the same vocabulary tenant_app_
// policies uses) and read back, with the policy row and the audit trail
// both correct.
func TestPortalHomebrewApprovalIgnoredRoundTrip(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "ignored")

	out := mustApprove(t, at.adminToken, approvalBody("ignored", "not relevant to us",
		hbFormulaItem("openssl@3", ""), hbCaskItem("firefox", "")))
	if out.ChangedCount != 2 {
		t.Fatalf("changed_count = %d, want 2: %+v", out.ChangedCount, out)
	}
	for _, r := range out.Results {
		if !r.Changed || r.PreviousState != "unreviewed" || r.NewState != "ignored" {
			t.Fatalf("result = %+v", r)
		}
	}

	// Stored as 'unmanaged', same as an ignored application.
	if policy, ok := homebrewPolicyRow(t, at.tenantID, "formula", "openssl@3"); !ok || policy != "unmanaged" {
		t.Fatalf("formula policy row = %q (ok=%v), want unmanaged", policy, ok)
	}
	if policy, ok := homebrewPolicyRow(t, at.tenantID, "cask", "firefox"); !ok || policy != "unmanaged" {
		t.Fatalf("cask policy row = %q (ok=%v), want unmanaged", policy, ok)
	}

	// Reads back as "ignored" on both Homebrew endpoints.
	var formulae hbApprovalFormulaeOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	if state, _, _ := findFormula(formulae, "openssl@3"); state != "ignored" {
		t.Fatalf("openssl@3 approval_state = %q, want ignored", state)
	}
	var casks hbApprovalCasksOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/casks", &casks)
	if state, _, _ := findCask(casks, "firefox"); state != "ignored" {
		t.Fatalf("firefox approval_state = %q, want ignored", state)
	}

	// Round-trip out of ignored: back to approved.
	out = mustApprove(t, at.adminToken, approvalBody("approved", "", hbFormulaItem("openssl@3", "")))
	if out.ChangedCount != 1 || out.Results[0].PreviousState != "ignored" || out.Results[0].NewState != "approved" {
		t.Fatalf("round-trip out of ignored = %+v", out)
	}

	audit := auditRows(t, at.tenantID)
	if len(audit) != 3 {
		t.Fatalf("audit rows = %d, want 3 (2 to ignored, 1 back out): %+v", len(audit), audit)
	}
	last := audit[len(audit)-1]
	if last.ProductType != "homebrew_formula" || last.Prev != "ignored" || last.New != "approved" {
		t.Fatalf("last audit row = %+v", last)
	}
}

// TestPortalHomebrewApprovalResetToUnreviewedOnFormula: resetting a formula
// to unreviewed deletes its tenant_homebrew_policies row (the same "row
// deleted" rule applications and extensions follow) and the formula reads
// back as Unreviewed again.
func TestPortalHomebrewApprovalResetToUnreviewedOnFormula(t *testing.T) {
	at := setUpHomebrewApprovalTenant(t, "reset")

	mustApprove(t, at.adminToken, approvalBody("unapproved", "flagged", hbFormulaItem("openssl@3", "")))
	if _, ok := homebrewPolicyRow(t, at.tenantID, "formula", "openssl@3"); !ok {
		t.Fatal("expected a policy row after unapprove")
	}

	out := mustApprove(t, at.adminToken, approvalBody("unreviewed", "reopened for review", hbFormulaItem("openssl@3", "")))
	if out.ChangedCount != 1 || out.Results[0].PreviousState != "unapproved" || out.Results[0].NewState != "unreviewed" {
		t.Fatalf("reset result = %+v", out)
	}

	if _, ok := homebrewPolicyRow(t, at.tenantID, "formula", "openssl@3"); ok {
		t.Fatal("unreviewed left a tenant_homebrew_policies row behind")
	}

	var formulae hbApprovalFormulaeOut
	portalGetJSON(t, at.adminToken, "/v1/portal/homebrew/formulae", &formulae)
	state, key, ok := findFormula(formulae, "openssl@3")
	if !ok || state != softwaregov.StateUnreviewed {
		t.Fatalf("openssl@3 state after reset = %q (ok=%v), want unreviewed", state, ok)
	}
	if key != "homebrew:formula:openssl@3" {
		t.Fatalf("product_key after reset = %q", key)
	}

	audit := auditRows(t, at.tenantID)
	if len(audit) != 2 {
		t.Fatalf("audit rows = %d, want 2: %+v", len(audit), audit)
	}
	last := audit[len(audit)-1]
	if last.Prev != "unapproved" || last.New != "unreviewed" {
		t.Fatalf("last audit row = %+v", last)
	}

	// A no-op unreviewed write on an already-unreviewed product changes
	// nothing and writes no further audit row.
	out = mustApprove(t, at.adminToken, approvalBody("unreviewed", "", hbFormulaItem("openssl@3", "")))
	if out.ChangedCount != 0 || out.Results[0].Changed {
		t.Fatalf("no-op unreviewed write reported a change: %+v", out)
	}
	if n := len(auditRows(t, at.tenantID)); n != 2 {
		t.Fatalf("audit rows after no-op = %d, want still 2", n)
	}
}
