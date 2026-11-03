package main

// Platform checks for the staff catalogue review that sit beside the frozen
// acceptance file: Windows installation currency, the narrowing of
// effective_tenant_app_policies against its 0224 text, summary invalidation
// with no inventory report, revival semantics, root-kind mixes, limit bounds
// and the concurrency of review and retirement. Same production routers and
// disposable database as the acceptance file.
//
// Local limitation: the scratch database user is the owning, superuser role,
// so nothing here proves what a non-owner role may do to the audit table.
import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func (f *catalogueFixture) policyVersion(t *testing.T, tenant string) int {
	t.Helper()
	return f.count(t, `SELECT COALESCE((SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id=$1::uuid),0)::int`, tenant)
}

func (f *catalogueFixture) summaryStale(t *testing.T, tenant string) bool {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM software_unapproved_presence_state WHERE tenant_id=$1::uuid AND summary_version<policy_version`, tenant) == 1
}

// A native Windows installation is never closed by an application scope, so
// "current" also needs the device to still list it. An uninstalled bad copy
// must not block a review for ever, and an uninstalled valid copy must not
// qualify one.
func TestPAT2404PlatformUninstalledWindowsCopyNeitherBlocksNorQualifies(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	stale := func(i pat2404Identity, hw int) {
		t.Helper()
		if n := f.count(t, `SELECT count(*) FROM software_installations si JOIN devices d ON d.id=si.device_id WHERE si.tenant_id=$1::uuid AND d.hw_uuid=$2::uuid AND si.identity_value_normalized=$3 AND si.removed_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM device_apps da WHERE da.device_id=si.device_id AND lower(da.identifier)=$3)`, f.tenant, pat2404HW(hw), i.value); n != 1 {
			t.Fatalf("fixture: want the installation on device %d left open with no device_apps row, found %d", hw, n)
		}
	}

	bad := f.win("StaleBad")
	f.reportWin(t, 1, now, bad.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	f.reportWin(t, 2, now, bad.winApp("unsigned", "", ""))
	f.refuse(t, pat2404ReviewBody(bad), 422)
	pat2404Candidate(t, f.candidates(t, "windows"), bad, false, 2, 1)
	f.reportWin(t, 2, now.Add(time.Second))
	stale(bad, 2)
	c := pat2404Candidate(t, f.candidates(t, "windows"), bad, true, 1, 1)
	if states := c["evidence"].(map[string]any)["signing_states"].(map[string]any); states["unsigned"] != nil {
		t.Errorf("an uninstalled copy still counts in the evidence: %v", states)
	}
	f.reviewOf(t, bad)

	good := f.win("StaleValid")
	f.reportWin(t, 3, now, good.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	f.reportWin(t, 4, now, good.winApp("unknown", "", ""))
	pat2404Candidate(t, f.candidates(t, "windows"), good, true, 2, 1)
	f.reportWin(t, 3, now.Add(time.Second))
	stale(good, 3)
	pat2404Candidate(t, f.candidates(t, "windows"), good, false, 1, 1)
	f.refuse(t, pat2404ReviewBody(good), 422)
	// With no device listing it at all, it is not an observed identity.
	f.reportWin(t, 4, now.Add(time.Second))
	stale(good, 4)
	if _, listed := f.candidates(t, "windows")[good.value]; listed {
		t.Error("an identity no device lists any more is still a candidate")
	}
	f.refuse(t, pat2404ReviewBody(good), 404)
}

// A mix of roots among valid installations is allowed when at least one is
// microsoft or public, and the evidence lists every root kind seen. Enterprise
// alone never qualifies.
func TestPAT2404PlatformWindowsRootKindMix(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	mixed, enterprise := f.win("Mixed"), f.win("EnterpriseOnly")
	f.reportWin(t, 1, now, mixed.winApp("valid", "enterprise", "CN=Synthetic Publisher"), enterprise.winApp("valid", "enterprise", "CN=Synthetic Publisher"))
	f.reportWin(t, 2, now, mixed.winApp("valid", "public", "CN=Synthetic Publisher"), enterprise.winApp("valid", "enterprise", "CN=Synthetic Publisher"))
	f.reportWin(t, 3, now, mixed.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	rows := f.candidates(t, "windows")
	c := pat2404Candidate(t, rows, mixed, true, 3, 1)
	evidence := c["evidence"].(map[string]any)
	if got := fmt.Sprint(evidence["root_kinds"]); got != "[enterprise microsoft public]" {
		t.Errorf("root kinds = %s, want all three listed", got)
	}
	// Only the microsoft and public copies yield a publisher key.
	pat2393Equal(t, evidence, "authenticode_publisher_key_count", 1)
	c = pat2404Candidate(t, rows, enterprise, false, 2, 1)
	pat2393Equal(t, c, "blocked_reason", "enterprise_root_only")
	if got := fmt.Sprint(c["evidence"].(map[string]any)["root_kinds"]); got != "[enterprise]" {
		t.Errorf("enterprise-only root kinds = %s", got)
	}
	f.refuse(t, pat2404ReviewBody(enterprise), 422)
	alias, _ := f.reviewOf(t, mixed)
	var stored string
	if e := f.pool.QueryRow(t.Context(), `SELECT evidence->>'root_kinds' FROM software_product_aliases WHERE id=$1::uuid`, alias).Scan(&stored); e != nil || stored != `["enterprise", "microsoft", "public"]` {
		t.Errorf("alias evidence root kinds = %s (%v)", stored, e)
	}
}

// limit is refused outside its bounds, never clamped.
func TestPAT2404PlatformLimitBounds(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	f.reportMac(t, 1, now, f.mac("One").macApp("signed"), f.mac("Two").macApp("signed"), f.mac("Three").macApp(""))
	get := func(path string) (int, map[string]any) {
		rr := f.staff("GET", pat2404Base+path, nil)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	q := "&query=" + url.QueryEscape(f.tok)
	code, out := get("/candidates?platform=macos" + q)
	if code != 200 || len(out["candidates"].([]any)) != 3 || out["has_more"] != false {
		t.Fatalf("default limit: %d %v", code, out)
	}
	code, out = get("/candidates?platform=macos&limit=2" + q)
	if code != 200 || len(out["candidates"].([]any)) != 2 || out["has_more"] != true {
		t.Fatalf("limit=2: %d %v", code, out)
	}
	if code, _ = get("/candidates?platform=macos&limit=200" + q); code != 200 {
		t.Errorf("limit=200 (the maximum) = %d, want 200", code)
	}
	for _, bad := range []string{"0", "-1", "201", "abc", "1.5", "1e2", "%20", "99999999999999999999"} {
		if code, out = get("/candidates?platform=macos&limit=" + bad + q); code != 400 || out["error"] == nil {
			t.Errorf("candidates limit=%s = %d %v, want a 400 refusal", bad, code, out)
		}
	}
	if code, _ = get("/candidates?platform=macos&query=" + strings.Repeat("x", 129)); code != 400 {
		t.Errorf("129 character query = %d, want 400", code)
	}
	if code, _ = get("/aliases?limit=1000"); code != 200 {
		t.Errorf("aliases limit=1000 (the maximum) = %d, want 200", code)
	}
	for _, bad := range []string{"0", "-1", "1001", "abc"} {
		if code, _ = get("/aliases?limit=" + bad); code != 400 {
			t.Errorf("aliases limit=%s = %d, want 400", bad, code)
		}
	}
	if code, _ = get("/aliases?platform=linux"); code != 400 {
		t.Errorf("aliases platform=linux = %d, want 400", code)
	}
}

// declaredPair reviews one macOS and one Windows identity and resolves a
// declaration through each, so both are effective approvals.
func (f *catalogueFixture) declaredPair(t *testing.T, now time.Time) (m, w pat2404Identity, macAlias, winAlias string, macBody map[string]any) {
	t.Helper()
	m, w = f.mac("Editor"), f.win("Editor")
	winApp := w.winApp("valid", "microsoft", "CN=Synthetic Publisher")
	f.reportMac(t, 1, now, m.macApp("signed"))
	f.reportWin(t, 2, now, winApp)
	macAlias, macBody = f.reviewOf(t, m)
	winAlias, _ = f.reviewOf(t, w)
	f.reportMac(t, 1, now.Add(time.Second), m.macApp("signed"))
	f.reportWin(t, 2, now.Add(time.Second), winApp)
	body := pat2393Body("macos")
	body["name"], body["alias_id"] = "Declared mac "+f.tok, macAlias
	f.create(t, body)
	body = pat2393Body("windows")
	body["name"], body["alias_id"] = "Declared win "+f.tok, winAlias
	id := pat2393ID(t, f.create(t, body))
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": winAlias, "justification": "Confirmed publisher"}, 200)
	if f.effective(t, m) != 1 || f.effective(t, w) != 1 {
		t.Fatal("fixture: the declared approvals are not effective")
	}
	return m, w, macAlias, winAlias, macBody
}

// Retiring or reviving an alias changes what the policy resolver returns with
// no policy row and no inventory report changing, so the cached
// Unapproved-present summary of every tenant declared through it must be told.
func TestPAT2404PlatformRetireAndReviveInvalidateSummaryWithoutAReport(t *testing.T) {
	f := pat2404Fixture(t)
	bystander := pat2393Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w, macAlias, winAlias, macBody := f.declaredPair(t, now)
	bystander.reportMac(t, 3, now, m.macApp("signed"))
	// Bring the summary up to date, so "stale" below is this test's doing.
	f.exec(t, `INSERT INTO software_unapproved_presence_state(tenant_id,policy_version,summary_version,policy_changed_at) VALUES($1::uuid,1,1,now())
		ON CONFLICT (tenant_id) DO UPDATE SET summary_version=software_unapproved_presence_state.policy_version`, f.tenant)
	if f.summaryStale(t, f.tenant) {
		t.Fatal("fixture: the summary is already stale")
	}
	reports := f.count(t, `SELECT count(*) FROM raw_payloads WHERE tenant_id=$1::uuid`, f.tenant)
	base, other := f.policyVersion(t, f.tenant), f.policyVersion(t, bystander.tenant)

	for n, alias := range []string{macAlias, winAlias} {
		// A refused retirement invalidates nothing.
		pat2404Refusal(t, "retire with no reason", f.staff("POST", pat2404Base+"/aliases/"+alias+"/retire", map[string]any{"reason": "", "actor": "x"}), 400)
		if got := f.policyVersion(t, f.tenant); got != base+n {
			t.Fatalf("a refused retirement changed the policy version to %d", got)
		}
		if rr := f.retire(t, alias, "retirer-"+f.tok+"@pat2404.invalid"); rr.Code != 200 {
			t.Fatalf("retire = %d: %s", rr.Code, rr.Body.String())
		}
		if got := f.policyVersion(t, f.tenant); got != base+n+1 {
			t.Fatalf("retirement %d left the summary valid: policy version %d, want %d", n+1, got, base+n+1)
		}
		if !f.summaryStale(t, f.tenant) {
			t.Fatal("the summary is not marked for rebuild after a retirement")
		}
	}
	if f.effective(t, m) != 0 || f.effective(t, w) != 0 {
		t.Fatal("the retired approvals are still effective")
	}

	// Revival: effective again, and the summary is told again.
	again := pat2404ReviewBody(m)
	again["canonical_name"], again["vendor_name"] = macBody["canonical_name"], macBody["vendor_name"]
	if revived := f.review(t, again); revived != macAlias {
		t.Fatalf("re-review created alias %s, want the retired row %s revived", revived, macAlias)
	}
	if f.effective(t, m) != 1 || !f.inventoryApproves(t, m) {
		t.Fatal("a declaration resolved through a revived alias is not effective again")
	}
	if got := f.policyVersion(t, f.tenant); got != base+3 {
		t.Fatalf("revival left the summary valid: policy version %d, want %d", got, base+3)
	}
	// A first review of an identity nobody has declared invalidates nothing.
	fresh := f.mac("Fresh")
	bystander.reportMac(t, 4, now, fresh.macApp("signed"))
	f.reviewOf(t, fresh)
	if got := f.policyVersion(t, f.tenant); got != base+3 {
		t.Fatalf("an unrelated review changed the policy version to %d", got)
	}
	// A tenant with no declaration through the alias is untouched, and no
	// inventory report from the declaring tenant was involved.
	if got := bystander.count(t, `SELECT COALESCE((SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id=$1::uuid),0)::int`, bystander.tenant); got != other {
		t.Errorf("a tenant with no declaration through the alias was invalidated: %d -> %d", other, got)
	}
	if n := f.count(t, `SELECT count(*) FROM raw_payloads WHERE tenant_id=$1::uuid`, f.tenant); n != reports {
		t.Fatalf("fixture: %d inventory reports arrived during the test", n-reports)
	}
}

// Re-review revives the retired row in place and only under its own product.
func TestPAT2404PlatformReviveKeepsRowAndProduct(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	i := f.mac("Editor")
	f.reportMac(t, 1, now, i.macApp("signed"))
	alias, body := f.reviewOf(t, i)
	f.reportMac(t, 1, now.Add(time.Second), i.macApp("signed"))
	if rr := f.retire(t, alias, "retirer-"+f.tok+"@pat2404.invalid"); rr.Code != 200 {
		t.Fatalf("retire = %d: %s", rr.Code, rr.Body.String())
	}
	// Another product name: refused, nothing written, still retired.
	f.refuse(t, pat2404ReviewBody(i), 409)
	if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE id=$1::uuid AND retired_at IS NOT NULL AND created_by=$2`, alias, fmt.Sprint(body["actor"])); n != 1 {
		t.Fatal("a refused re-review changed the retired alias")
	}
	again := pat2404ReviewBody(i)
	again["canonical_name"], again["vendor_name"] = strings.ToUpper(fmt.Sprint(body["canonical_name"])), body["vendor_name"]
	rr := f.staff("POST", pat2404Base+"/reviews", again)
	if rr.Code != 201 || !strings.Contains(rr.Body.String(), `"revived":true`) || !strings.Contains(rr.Body.String(), alias) {
		t.Fatalf("re-review = %d %s, want 201 reviving %s", rr.Code, rr.Body.String(), alias)
	}
	var product, createdBy, name string
	var rows int
	if e := f.pool.QueryRow(t.Context(), `SELECT sp.canonical_name,a.created_by,a.product_id::text,(SELECT count(*) FROM software_product_aliases x WHERE x.identity_value_normalized=a.identity_value_normalized)
		FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.id=$1::uuid AND a.retired_at IS NULL`, alias).Scan(&name, &createdBy, &product, &rows); e != nil {
		t.Fatalf("the revived alias is not live: %v", e)
	}
	if name != fmt.Sprint(body["canonical_name"]) || createdBy != fmt.Sprint(again["actor"]) || rows != 1 {
		t.Fatalf("revived alias: product %q, created_by %q, %d rows for the identity", name, createdBy, rows)
	}
	if n := f.audit(t, `alias_id=$1::uuid AND before IS NOT NULL AND before->>'retired_at' IS NOT NULL AND after->>'retired_at' IS NULL AND action='review'`, alias); n != 1 {
		t.Errorf("%d audit rows record the revival with its before and after, want 1", n)
	}
	// The installation that kept its historical link is simply current again.
	if a := f.installAlias(t, i, 1); a != alias {
		t.Fatalf("installation alias = %q, want %s", a, alias)
	}
}

// An existing product is reused only as it stands: active and under the same
// vendor. A vendor that was never recorded is filled in.
func TestPAT2404PlatformProductReuseRules(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	seed := func(lifecycle string, vendor any) string {
		name := "PAT2404 Existing " + pat2393Random()
		f.exec(t, `INSERT INTO software_products(canonical_key,canonical_name,vendor_name,lifecycle_state) VALUES(lower($1),$1,$2,$3)`, name, vendor, lifecycle)
		return name
	}
	i := f.mac("Editor")
	f.reportMac(t, 1, now, i.macApp("signed"))
	for _, tc := range []struct {
		lifecycle string
		vendor    any
	}{{"replaced", "PAT2404 Vendor"}, {"end_of_life", "PAT2404 Vendor"}, {"unknown", "PAT2404 Vendor"}, {"active", "Another Vendor"}} {
		body := pat2404ReviewBody(i)
		name := seed(tc.lifecycle, tc.vendor)
		body["canonical_name"] = name
		before := f.aliasCount(t, body)
		pat2404Refusal(t, "review onto a "+tc.lifecycle+" product", f.staff("POST", pat2404Base+"/reviews", body), 409)
		if f.aliasCount(t, body) != before || f.audit(t, `claimed_actor=$1`, fmt.Sprint(body["actor"])) != 0 {
			t.Errorf("a refused reuse of a %s product wrote something", tc.lifecycle)
		}
		if n := f.count(t, `SELECT count(*) FROM software_products WHERE canonical_name=$1 AND lifecycle_state=$2 AND vendor_name=$3`, name, tc.lifecycle, tc.vendor); n != 1 {
			t.Errorf("a refused reuse changed the %s product", tc.lifecycle)
		}
	}
	body := pat2404ReviewBody(i)
	body["canonical_name"] = seed("active", nil)
	alias := f.review(t, body)
	if n := f.count(t, `SELECT count(*) FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.id=$1::uuid AND sp.vendor_name=$2`, alias, fmt.Sprint(body["vendor_name"])); n != 1 {
		t.Fatal("a product with no recorded vendor did not take the reviewed vendor")
	}
	if !strings.Contains(f.lookup(t, "macos", fmt.Sprint(body["canonical_name"])), alias) {
		t.Fatal("the alias on a reused product is not in the portal lookup")
	}
}

// The replacement of effective_tenant_app_policies is a strict narrowing of
// the 0224 version: for every tenant in the database it returns a subset, and
// what it removes is exactly the approvals declared through a retired alias.
func TestPAT2404PlatformEffectivePoliciesOnlyNarrow0224(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w, macAlias, _, _ := f.declaredPair(t, now)
	// More shapes in the same tenant: an ordinary operator policy, an approval
	// declared through a live alias, and a Windows approval suspended under
	// the 0224 rule by an unsigned copy.
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,bundle_id,team_id,platform,policy,enforcement_tier) VALUES($1::uuid,$2,'SYNTHETIC1','macos','approved','report')`, f.tenant, "com.pat2404.ordinary."+f.tok)
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,name,platform,policy,enforcement_tier) VALUES($1::uuid,$2,'windows','unapproved','report')`, f.tenant, "Unwanted "+f.tok)
	live := f.mac("Live")
	f.reportMac(t, 3, now, live.macApp("signed"))
	liveAlias, _ := f.reviewOf(t, live)
	body := pat2393Body("macos")
	body["name"], body["alias_id"] = "Declared live "+f.tok, liveAlias
	f.create(t, body)
	f.reportWin(t, 4, now, w.winApp("unsigned", "", ""))
	if f.effective(t, w) != 0 {
		t.Fatal("fixture: the Windows approval is not suspended by the unsigned copy")
	}
	if rr := f.retire(t, macAlias, "retirer-"+f.tok+"@pat2404.invalid"); rr.Code != 200 {
		t.Fatalf("retire = %d: %s", rr.Code, rr.Body.String())
	}

	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "0224_software_declarations.sql"))
	if e != nil {
		t.Fatal(e)
	}
	original := regexp.MustCompile(`(?s)CREATE FUNCTION effective_tenant_app_policies\(p_tenant UUID\).*?\$fn\$;`).FindString(string(raw))
	if original == "" {
		t.Fatal("0224 function text not found")
	}
	conn, e := f.pool.Acquire(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	if _, e = conn.Exec(t.Context(), strings.Replace(original, "CREATE FUNCTION effective_tenant_app_policies(", "CREATE FUNCTION pg_temp.pat2404_effective_0224(", 1)); e != nil {
		t.Fatal(e)
	}
	defer conn.Exec(t.Context(), `DROP FUNCTION pg_temp.pat2404_effective_0224(uuid)`)

	var tenants, added, oldRows, newRows int
	if e = conn.QueryRow(t.Context(), `SELECT count(*),
		COALESCE(sum((SELECT count(*) FROM effective_tenant_app_policies(t.id) n WHERE NOT EXISTS (SELECT 1 FROM pg_temp.pat2404_effective_0224(t.id) o WHERE o.id=n.id))),0),
		COALESCE(sum((SELECT count(*) FROM pg_temp.pat2404_effective_0224(t.id))),0),
		COALESCE(sum((SELECT count(*) FROM effective_tenant_app_policies(t.id))),0)
		FROM tenants t`).Scan(&tenants, &added, &oldRows, &newRows); e != nil {
		t.Fatal(e)
	}
	if added != 0 {
		t.Fatalf("the replacement returns %d rows the 0224 version does not, across %d tenants", added, tenants)
	}
	if tenants < 2 || oldRows == 0 || newRows >= oldRows {
		t.Fatalf("the comparison is vacuous: %d tenants, %d rows before, %d after", tenants, oldRows, newRows)
	}
	// Every row removed, in any tenant, is an approval declared through a
	// retired alias; no other row is removed.
	var unexplained, kept int
	if e = conn.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM tenants t, LATERAL pg_temp.pat2404_effective_0224(t.id) o
		  WHERE NOT EXISTS (SELECT 1 FROM effective_tenant_app_policies(t.id) n WHERE n.id=o.id)
		    AND NOT (o.policy='approved' AND EXISTS (SELECT 1 FROM tenant_software_declarations d JOIN software_product_aliases a ON a.id=d.resolved_alias_id
		             WHERE d.policy_id=o.id AND d.tenant_id=o.tenant_id AND a.retired_at IS NOT NULL))),
		(SELECT count(*) FROM tenants t, LATERAL effective_tenant_app_policies(t.id) n
		  WHERE n.policy='approved' AND EXISTS (SELECT 1 FROM tenant_software_declarations d JOIN software_product_aliases a ON a.id=d.resolved_alias_id
		             WHERE d.policy_id=n.id AND d.tenant_id=n.tenant_id AND a.retired_at IS NOT NULL))`).Scan(&unexplained, &kept); e != nil {
		t.Fatal(e)
	}
	if unexplained != 0 || kept != 0 {
		t.Fatalf("%d rows were removed for another reason and %d retired approvals are still returned", unexplained, kept)
	}
	// In this tenant: 0224 returned the two operator rows, the live
	// declaration and the retired macOS one; the replacement drops only the last.
	var before, after int
	if e = conn.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM pg_temp.pat2404_effective_0224($1::uuid)),(SELECT count(*) FROM effective_tenant_app_policies($1::uuid))`, f.tenant).Scan(&before, &after); e != nil || before != 4 || after != 3 {
		t.Fatalf("this tenant: %d rows under 0224, %d under the replacement (%v), want 4 and 3", before, after, e)
	}
	if f.effective(t, m) != 0 || f.effective(t, live) != 1 {
		t.Fatal("the replacement removed the wrong declared approval")
	}
	// An operator who has since set the linked policy to unapproved keeps
	// that decision in force: only approvals are withheld.
	f.exec(t, `UPDATE tenant_app_policies SET policy='unapproved' WHERE tenant_id=$1::uuid AND lower(btrim(bundle_id))=$2`, f.tenant, m.value)
	if n := f.count(t, `SELECT count(*) FROM effective_tenant_app_policies($1::uuid) WHERE lower(btrim(bundle_id))=$2 AND policy='unapproved'`, f.tenant, m.value); n != 1 {
		t.Fatal("an unapproved decision on a retired identity was withheld")
	}
}

// race runs n calls at once and counts the status codes.
func pat2404Race(n int, call func(i int) int) map[int]int {
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = call(i)
		}()
	}
	close(start)
	wg.Wait()
	out := map[int]int{}
	for _, c := range codes {
		out[c]++
	}
	return out
}

// Simultaneous reviews of one identity: one alias, one audit row, the rest 409.
func TestPAT2404PlatformConcurrentReviewsYieldOneAlias(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	for round, i := range []pat2404Identity{f.mac("RaceMac"), f.win("RaceWin")} {
		if i.platform == "macos" {
			f.reportMac(t, 1, now, i.macApp("signed"))
		} else {
			f.reportWin(t, 2, now, i.winApp("valid", "public", "CN=Synthetic Publisher"))
		}
		const n = 8
		bodies := make([]map[string]any, n)
		for k := range bodies {
			bodies[k] = pat2404ReviewBody(i)
			// Half name one product, half each their own: the product row races too.
			if k%2 == 0 {
				bodies[k]["canonical_name"] = "PAT2404 Raced " + f.tok + fmt.Sprint(round)
			}
		}
		got := pat2404Race(n, func(k int) int { return f.staff("POST", pat2404Base+"/reviews", bodies[k]).Code })
		if got[201] != 1 || got[409] != n-1 {
			t.Fatalf("%s review race codes %v, want one 201 and %d 409", i.platform, got, n-1)
		}
		if c := f.aliasCount(t, bodies[0]); c != 1 {
			t.Fatalf("%d alias rows after the race, want 1", c)
		}
		var alias string
		if e := f.pool.QueryRow(t.Context(), `SELECT id::text FROM software_product_aliases WHERE identity_value_normalized=$1`, i.value).Scan(&alias); e != nil {
			t.Fatal(e)
		}
		if c := f.audit(t, `alias_id=$1::uuid`, alias); c != 1 {
			t.Fatalf("%d audit rows after the race, want 1", c)
		}
		// The losers left no product behind.
		winner := f.count(t, `SELECT count(*) FROM software_products sp WHERE sp.canonical_name = ANY($1)`, func() []string {
			names := make([]string, n)
			for k := range bodies {
				names[k] = fmt.Sprint(bodies[k]["canonical_name"])
			}
			return names
		}())
		if winner != 1 {
			t.Fatalf("%d product rows after the race, want only the winner's", winner)
		}
	}
}

// A review racing a retirement of the same alias: whichever order they land
// in, the alias's state always matches the last thing the ledger says
// happened to it, and the ledger alternates.
func TestPAT2404PlatformConcurrentReviewAndRetireStayConsistent(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	i := f.mac("RaceRetire")
	f.reportMac(t, 1, now, i.macApp("signed"))
	alias, body := f.reviewOf(t, i)
	state := func() (live bool, actions string) {
		t.Helper()
		if e := f.pool.QueryRow(t.Context(), `SELECT a.retired_at IS NULL,(SELECT string_agg(l.action,',' ORDER BY l.id) FROM `+pat2404Audit+` l WHERE l.alias_id=a.id)
			FROM software_product_aliases a WHERE a.id=$1::uuid`, alias).Scan(&live, &actions); e != nil {
			t.Fatal(e)
		}
		return live, actions
	}
	outcomes := map[string]int{}
	for round := 0; round < 12; round++ {
		if live, _ := state(); !live {
			again := pat2404ReviewBody(i)
			again["canonical_name"], again["vendor_name"] = body["canonical_name"], body["vendor_name"]
			f.review(t, again)
		}
		reviews := make([]map[string]any, 3)
		for k := range reviews {
			reviews[k] = pat2404ReviewBody(i)
			reviews[k]["canonical_name"], reviews[k]["vendor_name"] = body["canonical_name"], body["vendor_name"]
		}
		got := pat2404Race(6, func(k int) int {
			if k%2 == 0 {
				return f.staff("POST", pat2404Base+"/aliases/"+alias+"/retire", map[string]any{"reason": "Racing", "actor": fmt.Sprintf("retirer-%d-%d@pat2404.invalid", round, k)}).Code
			}
			return f.staff("POST", pat2404Base+"/reviews", reviews[k/2]).Code
		})
		if got[200]+got[201]+got[409] != 6 {
			t.Fatalf("round %d: unexpected status in %v", round, got)
		}
		if got[200] == 0 {
			t.Fatalf("round %d: no retirement succeeded on a live alias: %v", round, got)
		}
		live, actions := state()
		list := strings.Split(actions, ",")
		for k, a := range list {
			want := "review"
			if k%2 == 1 {
				want = "retire"
			}
			if a != want {
				t.Fatalf("round %d: the ledger does not alternate: %s", round, actions)
			}
		}
		if last := list[len(list)-1]; live != (last == "review") {
			t.Fatalf("round %d: alias live=%v but the last audited action is %s (%s)", round, live, last, actions)
		}
		outcomes[fmt.Sprintf("%d retired, %d revived", got[200], got[201])]++
	}
	if c := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE identity_value_normalized=$1`, i.value); c != 1 {
		t.Fatalf("%d alias rows for the identity after the races, want 1", c)
	}
	t.Logf("race outcomes: %v", outcomes)
}

// Another reader of the alias table: the approvals write accepts a Windows
// identifier with no Team ID only when a curated alias vouches for it. A
// retired alias no longer does.
func TestPAT2404PlatformRetiredAliasNoLongerConfirmsApprovalIdentity(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	i := f.win("Approve")
	f.reportWin(t, 1, now, i.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	alias, _ := f.reviewOf(t, i)
	approve := func() *httptest.ResponseRecorder {
		return f.do("PUT", "/v1/portal/software-approvals", f.admin, map[string]any{"state": "approved", "reason": "Needed by the synthetic estate",
			"items": []map[string]any{{"type": "application", "platform": "windows", "identifier": i.value}}})
	}
	withdraw := func() {
		f.exec(t, `DELETE FROM tenant_app_policies WHERE tenant_id=$1::uuid`, f.tenant)
	}
	// Control: with no alias at all the identifier is unconfirmed.
	bare := f.win("Unvouched")
	if rr := f.do("PUT", "/v1/portal/software-approvals", f.admin, map[string]any{"state": "approved", "reason": "Needed",
		"items": []map[string]any{{"type": "application", "platform": "windows", "identifier": bare.value}}}); rr.Code == 200 || !strings.Contains(rr.Body.String(), "unconfirmed_identity") {
		t.Fatalf("fixture: an identifier with no alias answered %d %s, want unconfirmed_identity", rr.Code, rr.Body.String())
	}
	if rr := approve(); rr.Code != 200 {
		t.Fatalf("fixture: approving an identifier vouched for by a live alias = %d: %s", rr.Code, rr.Body.String())
	}
	withdraw()
	if rr := f.retire(t, alias, "retirer-"+f.tok+"@pat2404.invalid"); rr.Code != 200 {
		t.Fatalf("retire = %d: %s", rr.Code, rr.Body.String())
	}
	if rr := approve(); rr.Code == 200 || !strings.Contains(rr.Body.String(), "unconfirmed_identity") {
		t.Fatalf("a retired alias still vouches for an identifier in the approvals write: %d %s", rr.Code, rr.Body.String())
	}
}
