package main

// Platform checks for tenant software declarations that sit beside the frozen
// acceptance file: authorisation on every route, tenant isolation without an
// existence leak, resolution refusals and races, the append-only ledger, and
// the rule that approval never changes inventory, counts or findings. They use
// the same production router and disposable database as the acceptance file.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/softwaregov"
)

// do sends one request and returns the recorder without asserting, so it is
// safe from a goroutine and for comparing refusals byte for byte.
func (f *declarationFixture) do(method, path, token string, body any) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set(portalauth.Header, token)
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, r)
	return rr
}

// observeStatus is the acceptance file's observeFixture with the application
// collection status chosen by the caller, so a partial report can be sent.
func (f *declarationFixture) observeStatus(t *testing.T, fixture, hw, status string, apps []map[string]any, collected time.Time) {
	t.Helper()
	pat2393Owner(t)
	raw, e := os.ReadFile(filepath.Join("..", "..", "testdata", "payload-fixtures", "valid", fixture))
	if e != nil {
		t.Fatal(e)
	}
	var payload map[string]any
	if e = json.Unmarshal(raw, &payload); e != nil {
		t.Fatal(e)
	}
	payload["tenant_id"] = f.tenant
	payload["schema_version"] = 3
	if fixture == "full.json" {
		payload["platform"] = "macos"
	}
	payload["collection_status"] = map[string]any{"apps": status}
	payload["collected_at"] = collected.UTC().Format(time.RFC3339)
	dev := payload["device"].(map[string]any)
	dev["hw_uuid"] = hw
	dev["serial"] = "PAT2393-" + hw
	dev["hostname"] = "pat2393-synthetic"
	payload["apps"] = apps
	if raw, e = json.Marshal(payload); e != nil {
		t.Fatal(e)
	}
	mac := hmac.New(sha256.New, f.secret)
	_, _ = mac.Write(raw)
	r := httptest.NewRequest("POST", "/v1/inventory", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.bearer)
	r.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set("X-Patched-Nonce", pat2393Random())
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("inventory fixture: %d %s", rr.Code, rr.Body.String())
	}
	if e = extractor.ProcessOnce(t.Context(), f.pool); e != nil {
		t.Fatal(e)
	}
	if n := f.count(t, `SELECT count(*) FROM raw_payloads WHERE tenant_id=$1::uuid AND (extracted_at IS NULL OR extraction_error IS NOT NULL)`, f.tenant); n != 0 {
		t.Fatalf("fixture extraction left %d failed/pending rows", n)
	}
}

func pat2393WindowsAppBy(identifier, publisher, signer, state string) map[string]any {
	app := pat2393WindowsApp(identifier, signer, state)
	app["publisher"] = publisher
	return app
}

// declaredWindows creates a Windows declaration that selects a curated,
// publisher-qualified alias and returns the declaration id, alias and identifier.
func (f *declarationFixture) declaredWindows(t *testing.T) (id, alias, identifier string) {
	t.Helper()
	alias, identifier = f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	body := pat2393Body("windows")
	body["alias_id"] = alias
	return pat2393ID(t, f.create(t, body)), alias, identifier
}

func (f *declarationFixture) tenantRows(t *testing.T) [3]int {
	t.Helper()
	return [3]int{
		f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid`, f.tenant),
		f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE tenant_id=$1::uuid`, f.tenant),
		f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid`, f.tenant),
	}
}

// Every write route refuses every identity that is not a live admin of the
// tenant, before the body is read, and leaves nothing behind.
func TestPAT2393PlatformWriteRoutesAdminOnly(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, _ := f.declaredWindows(t)
	before := f.tenantRows(t)
	resolve := map[string]any{"alias_id": alias, "justification": "refused"}
	writes := []struct {
		path string
		body any
	}{
		{declarationPath, pat2393Body("macos")},
		{declarationPath + "/" + id + "/resolve", resolve},
		// A malformed body must not turn a refusal into a validation answer.
		{declarationPath, "not an object"},
		{declarationPath + "/" + id + "/resolve", map[string]any{"tenant_id": f.tenant}},
	}
	for _, w := range writes {
		for name, tc := range map[string]struct {
			token string
			want  int
		}{
			"viewer": {f.viewer, 403}, "service": {f.sign("service"), 403},
			"no token": {"", 401}, "tampered": {f.admin + "x", 401},
		} {
			if got := f.do("POST", w.path, tc.token, w.body).Code; got != tc.want {
				t.Errorf("%s POST %s = %d, want %d", name, w.path, got, tc.want)
			}
		}
		for _, method := range []string{"PUT", "PATCH", "DELETE"} {
			if got := f.do(method, w.path, f.admin, w.body).Code; got < 400 {
				t.Errorf("%s %s = %d: no such write route may exist", method, w.path, got)
			}
		}
	}
	// A disabled admin and an admin of a revoked tenant hold a still-valid JWT.
	f.exec(t, `UPDATE portal_users SET disabled_at=now() WHERE email=$1`, f.email)
	if got := f.do("POST", declarationPath, f.admin, pat2393Body("macos")).Code; got != 403 {
		t.Errorf("disabled admin create = %d, want 403", got)
	}
	f.exec(t, `UPDATE portal_users SET disabled_at=NULL WHERE email=$1`, f.email)
	f.exec(t, `UPDATE tenants SET revoked_at=now() WHERE id=$1::uuid`, f.tenant)
	for _, path := range []string{declarationPath, declarationPath + "/" + id + "/resolve"} {
		if got := f.do("POST", path, f.admin, resolve).Code; got != 403 {
			t.Errorf("revoked tenant POST %s = %d, want 403", path, got)
		}
	}
	if got := f.do("GET", declarationPath, f.admin, nil).Code; got != 403 {
		t.Errorf("revoked tenant read = %d, want 403", got)
	}
	f.exec(t, `UPDATE tenants SET revoked_at=NULL WHERE id=$1::uuid`, f.tenant)
	if after := f.tenantRows(t); after != before {
		t.Fatalf("a refused write changed stored rows: before %v after %v", before, after)
	}
}

// Readers may read; the read-only service identity sees only its own tenant.
func TestPAT2393PlatformReadRoutes(t *testing.T) {
	f := pat2393Fixture(t)
	id := pat2393ID(t, f.create(t, pat2393Body("macos")))
	for _, path := range []string{declarationPath, declarationPath + "/" + id, declarationPath + "/" + id + "/history", "/v1/portal/software-products?platform=macos"} {
		for name, token := range map[string]string{"admin": f.admin, "viewer": f.viewer, "service": f.sign("service")} {
			if got := f.do("GET", path, token, nil).Code; got != 200 {
				t.Errorf("%s GET %s = %d, want 200", name, path, got)
			}
		}
		for name, token := range map[string]string{"no token": "", "tampered": f.viewer + "x"} {
			if got := f.do("GET", path, token, nil).Code; got != 401 {
				t.Errorf("%s GET %s = %d, want 401", name, path, got)
			}
		}
	}
	for _, path := range []string{declarationPath + "?tenant_id=" + f.other, declarationPath + "/" + id + "?tenant_id=" + f.other,
		declarationPath + "/" + id + "/history?tenant_id=" + f.other, "/v1/portal/software-products?platform=macos&tenant_id=" + f.other,
		"/v1/portal/software-products?platform=any", "/v1/portal/software-products"} {
		if got := f.do("GET", path, f.admin, nil).Code; got != 400 {
			t.Errorf("GET %s = %d, want 400", path, got)
		}
	}
}

// The tenant always comes from the verified identity. Another tenant's
// declaration is indistinguishable from one that does not exist, on every
// route, and one tenant's declarations never constrain another's.
func TestPAT2393PlatformCrossTenantFailsClosedWithoutLeak(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	manual := pat2393ID(t, f.create(t, pat2393Body("macos")))
	absent := "00000000-0000-4000-8000-0000000000aa"
	resolve := map[string]any{"alias_id": alias, "justification": "cross tenant"}
	for _, route := range []struct {
		method, suffix string
		body           any
	}{{"GET", "", nil}, {"GET", "/history", nil}, {"POST", "/resolve", resolve}, {"POST", "/resolve", "malformed"}} {
		theirs := f.do(route.method, declarationPath+"/"+manual+route.suffix, f.otherAdmin, route.body)
		missing := f.do(route.method, declarationPath+"/"+absent+route.suffix, f.otherAdmin, route.body)
		if theirs.Code != 404 || missing.Code != 404 || theirs.Body.String() != missing.Body.String() {
			t.Errorf("%s %s: another tenant's declaration answered %d %q, an absent one %d %q", route.method, route.suffix,
				theirs.Code, theirs.Body.String(), missing.Code, missing.Body.String())
		}
	}
	if got := f.do("GET", declarationPath+"/not-a-uuid", f.admin, nil).Code; got != 404 {
		t.Errorf("malformed id = %d, want 404", got)
	}
	pat2393Equal(t, f.row(t, manual), "identity_state", "unmatched")
	if n := f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE declaration_id=$1::uuid`, manual); n != 1 {
		t.Fatalf("cross-tenant resolve wrote history: %d rows", n)
	}

	// A query or body tenant is refused, never honoured.
	for _, path := range []string{declarationPath + "?tenant_id=" + f.other, declarationPath + "/" + manual + "/resolve?tenant_id=" + f.other} {
		if got := f.do("POST", path, f.admin, resolve).Code; got != 400 {
			t.Errorf("POST %s = %d, want 400", path, got)
		}
	}
	for _, key := range []string{"tenant_id", "Tenant_ID", "TENANT_ID", "created_by", "policy_id"} {
		body := pat2393Body("macos")
		body["name"] = "Injected " + key
		body[key] = f.other
		if got := f.do("POST", declarationPath, f.admin, body).Code; got != 400 {
			t.Errorf("create with body %s = %d, want 400", key, got)
		}
		if got := f.do("POST", declarationPath+"/"+manual+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "x", key: f.other}).Code; got != 400 {
			t.Errorf("resolve with body %s = %d, want 400", key, got)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid`, f.other); n != 0 {
		t.Fatalf("a request wrote %d declarations into another tenant", n)
	}

	// The same curated product declared by two tenants: each has its own
	// declaration and its own policy row, and neither sees the other's.
	body := pat2393Body("macos")
	body["name"] = "Shared product"
	body["alias_id"] = alias
	mine := pat2393ID(t, f.create(t, body))
	theirs := pat2393ID(t, pat2393JSON(t, f.request(t, "POST", declarationPath, f.otherAdmin, body, 201)))
	if mine == theirs {
		t.Fatal("two tenants share one declaration")
	}
	for tenant, want := range map[string]string{f.tenant: mine, f.other: theirs} {
		var got string
		if e := f.pool.QueryRow(t.Context(), `SELECT d.id::text FROM tenant_software_declarations d JOIN tenant_app_policies p ON p.id=d.policy_id AND p.tenant_id=d.tenant_id WHERE d.tenant_id=$1::uuid AND p.bundle_id=$2`, tenant, identifier).Scan(&got); e != nil || got != want {
			t.Fatalf("tenant %s policy link = %q (%v), want %q", tenant, got, e, want)
		}
	}
	list := pat2393JSON(t, f.request(t, "GET", declarationPath, f.otherAdmin, nil, 200))
	pat2393Equal(t, list, "total", 1)
	if strings.Contains(fmt.Sprint(list), mine) || strings.Contains(fmt.Sprint(list), manual) {
		t.Fatal("another tenant's declaration appeared in the list")
	}
	approved := f.request(t, "GET", "/v1/portal/software/approved", f.otherAdmin, nil, 200).Body.String()
	if strings.Contains(approved, mine) || strings.Contains(approved, manual) {
		t.Fatal("another tenant's declaration appeared in the approved list")
	}
}

// Same name is not same product: declarations that differ only by publisher
// stay separate and unmatched, and neither confers or inherits approval.
func TestPAT2393PlatformDedupeIsDeterministic(t *testing.T) {
	f := pat2393Fixture(t)
	first := pat2393Body("windows")
	a := pat2393ID(t, f.create(t, first))
	dup := pat2393Body("windows")
	dup["name"], dup["publisher"] = "  synthetic EDITOR ", "SYNTHETIC publisher"
	f.request(t, "POST", declarationPath, f.admin, dup, 409)
	otherPublisher := pat2393Body("windows")
	otherPublisher["publisher"] = "Another Publisher"
	b := pat2393ID(t, f.create(t, otherPublisher))
	otherPlatform := pat2393ID(t, f.create(t, pat2393Body("macos")))
	for _, id := range []string{a, b, otherPlatform} {
		row := f.row(t, id)
		pat2393Equal(t, row, "identity_state", "unmatched")
		pat2393Equal(t, row, "observation_state", "not_observed")
		pat2393Equal(t, row, "effective_approval_state", "unmatched")
	}
	// An unresolved Windows selection dedupes on the alias, whatever was typed.
	alias, _ := f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	selected := pat2393Body("windows")
	selected["name"], selected["alias_id"] = "Selected once", alias
	f.create(t, selected)
	selected["name"] = "Selected twice"
	f.request(t, "POST", declarationPath, f.admin, selected, 409)
	if n := f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid`, f.tenant); n != 0 {
		t.Fatalf("unmatched declarations created %d policy rows", n)
	}
}

// Resolution must refuse, not approve and then suspend, when any current
// installation of the identifier is not the selected identity, even though
// every installation carries the same valid signer.
func TestPAT2393PlatformResolveRefusesIncompatibleSameSignerInstallation(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, identifier := f.declaredWindows(t)
	now := time.Now().Add(-time.Minute)
	good, odd := "12392393-0000-4000-8000-000000000040", "12392393-0000-4000-8000-000000000041"
	f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, now)
	// Same identifier, same valid signer, different registry publisher: a
	// different catalogue identity, so not the product that was selected.
	f.observeFixture(t, "full-v3-windows.json", odd, []map[string]any{pat2393WindowsAppBy(identifier, "Unrelated Vendor", "CN=Synthetic Publisher", "valid")}, now)
	path := declarationPath + "/" + id + "/resolve"
	body := map[string]any{"alias_id": alias, "justification": "Confirmed publisher"}
	f.refused(t, "POST", path, f.admin, body, 422, "unverified_signing_identity")
	row := f.row(t, id)
	pat2393Equal(t, row, "identity_state", "unmatched")
	pat2393Equal(t, row, "observed_installation_count", 0)
	if got := f.tenantRows(t); got != [3]int{1, 1, 0} {
		t.Fatalf("refused resolution left rows %v, want one declaration, one creation event, no policy", got)
	}
	if n := f.count(t, `SELECT count(*) FROM software_approval_decisions WHERE tenant_id=$1::uuid`, f.tenant); n != 0 {
		t.Fatalf("refused resolution recorded %d approval decisions", n)
	}
	// Once the incompatible copy is authoritatively gone, the same request succeeds.
	f.observeFixture(t, "full-v3-windows.json", odd, []map[string]any{}, now.Add(time.Second))
	f.request(t, "POST", path, f.admin, body, 200)
	row = f.row(t, id)
	pat2393Equal(t, row, "identity_state", "matched")
	pat2393Equal(t, row, "effective_approval_state", "active")
	pat2393Equal(t, row, "observed_installation_count", 1)
	// A publisher-less Windows identity can be selected but never resolved.
	winget, _ := f.alias(t, "windows", "windows_winget", "")
	loose := pat2393Body("windows")
	loose["name"], loose["alias_id"] = "Publisher-less", winget
	looseID := pat2393ID(t, f.create(t, loose))
	f.request(t, "POST", declarationPath+"/"+looseID+"/resolve", f.admin, map[string]any{"alias_id": winget, "justification": "no publisher"}, 422)
	pat2393Equal(t, f.row(t, looseID), "identity_state", "unmatched")
}

// Concurrent writers on one tenant: exactly one resolution of a declaration,
// and exactly one declaration per curated identity, whichever request wins.
func TestPAT2393PlatformResolutionRaces(t *testing.T) {
	f := pat2393Fixture(t)
	race := func(n int, call func(i int) int) map[int]int {
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
	policies := func(identifier string) int {
		return f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND bundle_id=$2`, f.tenant, identifier)
	}

	t.Run("two resolves of one declaration", func(t *testing.T) {
		alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
		body := pat2393Body("macos")
		body["name"] = "Race one " + pat2393Random()
		id := pat2393ID(t, f.create(t, body))
		got := race(8, func(int) int {
			return f.do("POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "racing"}).Code
		})
		if got[200] != 1 || got[409] != 7 {
			t.Fatalf("resolve race codes %v, want one 200 and seven 409", got)
		}
		if policies(identifier) != 1 || f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE declaration_id=$1::uuid`, id) != 2 {
			t.Fatal("resolve race left more than one policy row or resolution event")
		}
	})
	t.Run("two declarations resolving to one identity", func(t *testing.T) {
		alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
		ids := make([]string, 6)
		for i := range ids {
			body := pat2393Body("macos")
			body["name"] = fmt.Sprintf("Race two %d %s", i, pat2393Random())
			ids[i] = pat2393ID(t, f.create(t, body))
		}
		got := race(len(ids), func(i int) int {
			return f.do("POST", declarationPath+"/"+ids[i]+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "racing"}).Code
		})
		if got[200] != 1 || got[409] != len(ids)-1 || policies(identifier) != 1 {
			t.Fatalf("identity race codes %v policies %d, want one winner", got, policies(identifier))
		}
		matched := 0
		for _, id := range ids {
			if f.row(t, id)["identity_state"] == "matched" {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("%d declarations matched one identity", matched)
		}
	})
	t.Run("resolve racing a create that selects the same identity", func(t *testing.T) {
		alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
		manual := pat2393Body("macos")
		manual["name"] = "Race three " + pat2393Random()
		id := pat2393ID(t, f.create(t, manual))
		got := race(6, func(i int) int {
			if i == 0 {
				return f.do("POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "racing"}).Code
			}
			body := pat2393Body("macos")
			body["name"] = fmt.Sprintf("Race three create %d %s", i, pat2393Random())
			body["alias_id"] = alias
			return f.do("POST", declarationPath, f.admin, body).Code
		})
		if got[200]+got[201] != 1 || got[409] != 5 || policies(identifier) != 1 {
			t.Fatalf("create/resolve race codes %v policies %d, want one winner", got, policies(identifier))
		}
		if n := f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid AND resolved_alias_id=$2::uuid`, f.tenant, alias); n != 1 {
			t.Fatalf("%d declarations hold one identity", n)
		}
	})
	t.Run("an identity that already has an authored policy", func(t *testing.T) {
		alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
		f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,bundle_id,team_id,platform,policy,enforcement_tier) VALUES($1::uuid,$2,'SYNTHETIC1','macos','unapproved','report')`, f.tenant, identifier)
		body := pat2393Body("macos")
		body["name"], body["alias_id"] = "Already decided "+pat2393Random(), alias
		before := f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid`, f.tenant)
		f.refused(t, "POST", declarationPath, f.admin, body, 409, "existing_policy")
		// The failed resolution rolled the whole create back: no declaration
		// is left holding the alias, and no creation event was recorded.
		if n := f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid`, f.tenant); n != before {
			t.Fatalf("a refused create left a declaration behind: %d rows, was %d", n, before)
		}
		if n := f.count(t, `SELECT count(*) FROM tenant_software_declarations WHERE selected_alias_id=$1::uuid OR resolved_alias_id=$1::uuid`, alias); n != 0 {
			t.Fatalf("%d declarations still hold the alias after a refused create", n)
		}
		if n := f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE tenant_id=$1::uuid AND declaration->>'name'=$2`, f.tenant, body["name"]); n != 0 {
			t.Fatalf("a refused create recorded %d history events", n)
		}
		if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND bundle_id=$2 AND policy='unapproved'`, f.tenant, identifier) != 1 {
			t.Fatal("a declaration overwrote an authored decision")
		}
		// Once the authored decision is withdrawn the same alias can be declared.
		f.exec(t, `DELETE FROM tenant_app_policies WHERE tenant_id=$1::uuid AND bundle_id=$2`, f.tenant, identifier)
		pat2393Equal(t, f.create(t, body), "identity_state", "matched")
	})
}

// Approval is governance, not evidence: it changes no installation, no count
// and no vulnerability finding, whether it is effective or suspended.
func TestPAT2393PlatformApprovalLeavesInventoryAndFindingsUntouched(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, identifier := f.declaredWindows(t)
	now := time.Now().Add(-time.Minute)
	hw, bad := "12392393-0000-4000-8000-000000000050", "12392393-0000-4000-8000-000000000051"
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, now)
	cve := f.seedCVE(t)
	snapshot := func() string {
		t.Helper()
		var out string
		if e := f.pool.QueryRow(t.Context(), `SELECT concat_ws('|',
			(SELECT count(*) FROM devices WHERE tenant_id=$1::uuid),
			(SELECT count(*) FROM device_apps da JOIN devices d ON d.id=da.device_id WHERE d.tenant_id=$1::uuid),
			(SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid),
			(SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND removed_at IS NULL),
			(SELECT count(*) FROM software_observations WHERE tenant_id=$1::uuid),
			(SELECT COALESCE(string_agg(cf.cve_id||':'||cf.severity||':'||cf.match_confidence||':'||COALESCE(cf.app_version,''),',' ORDER BY cf.id),'') FROM device_cve_findings cf JOIN devices d ON d.id=cf.device_id WHERE d.tenant_id=$1::uuid),
			(SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id=$1::uuid))`, f.tenant).Scan(&out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	findings := func() string {
		t.Helper()
		rr := f.request(t, "GET", "/v1/portal/findings", f.viewer, nil, 200)
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || !json.Valid(rr.Body.Bytes()) {
			t.Fatalf("findings response is not JSON (%s): %s", ct, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), cve) {
			t.Fatalf("finding %s is not visible: %s", cve, rr.Body.String())
		}
		return regexp.MustCompile(`"generated_at":"[^"]*"`).ReplaceAllString(rr.Body.String(), "")
	}
	before, findingsBefore := snapshot(), findings()
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	pat2393Equal(t, f.row(t, id), "effective_approval_state", "active")
	if after := snapshot(); after != before {
		t.Fatalf("approval changed inventory or findings:\nbefore %s\nafter  %s", before, after)
	}
	if after := findings(); after != findingsBefore {
		t.Fatalf("approval changed the findings response:\nbefore %s\nafter  %s", findingsBefore, after)
	}
	// Suspended by an unsigned copy elsewhere: the finding is still there.
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{pat2393WindowsApp(identifier, "", "unsigned")}, now.Add(time.Second))
	row := f.row(t, id)
	pat2393Equal(t, row, "effective_approval_state", "suspended")
	pat2393Equal(t, row, "approval_state", "approved")
	if !strings.Contains(findings(), cve) {
		t.Fatal("suspension hid a vulnerability finding")
	}
	if n := f.count(t, `SELECT count(*) FROM device_cve_findings cf JOIN devices d ON d.id=cf.device_id WHERE d.tenant_id=$1::uuid AND cf.cve_id=$2`, f.tenant, cve); n != 1 {
		t.Fatalf("finding rows for %s = %d, want 1", cve, n)
	}
}

// Windows parity for "removing the last install restores Not observed": only an
// authoritative report removes it, the approval and its history survive, and a
// later verified installation is counted again with no new decision.
func TestPAT2393PlatformWindowsLastInstallRemovedKeepsApproval(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, identifier := f.declaredWindows(t)
	hw := "12392393-0000-4000-8000-000000000060"
	now := time.Now().Add(-time.Minute)
	app := pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{app}, now)
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	row := f.row(t, id)
	pat2393Equal(t, row, "observation_state", "observed")
	pat2393Equal(t, row, "observed_installation_count", 1)

	// Absence requires authority: a partial report that lists nothing proves nothing.
	f.observeStatus(t, "full-v3-windows.json", hw, "partial", []map[string]any{}, now.Add(time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "observation_state", "observed")
	pat2393Equal(t, row, "observed_installation_count", 1)
	pat2393Equal(t, row, "effective_approval_state", "active")

	f.observeStatus(t, "full-v3-windows.json", hw, "complete", []map[string]any{}, now.Add(2*time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "observation_state", "not_observed")
	pat2393Equal(t, row, "observed_installation_count", 0)
	pat2393Equal(t, row, "approval_state", "approved")
	pat2393Equal(t, row, "identity_state", "matched")
	// No current evidence backs the pinned publisher, so nothing is vouched for.
	pat2393Equal(t, row, "effective_approval_state", "suspended")
	if got := f.tenantRows(t); got != [3]int{1, 2, 1} {
		t.Fatalf("removal changed governance rows: %v", got)
	}
	approved := f.request(t, "GET", "/v1/portal/software/approved", f.viewer, nil, 200).Body.String()
	if !strings.Contains(approved, id) || !strings.Contains(approved, `"observation_state":"not_observed"`) {
		t.Fatalf("approved list lost the not-observed entry: %s", approved)
	}

	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{app}, now.Add(3*time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "observation_state", "observed")
	pat2393Equal(t, row, "effective_approval_state", "active")
	if n := f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE declaration_id=$1::uuid`, id); n != 2 {
		t.Fatalf("inventory wrote governance history: %d events", n)
	}
}

// macOS: a partial report must not turn an observed entry into Not observed.
func TestPAT2393PlatformPartialInventoryNeverProvesAbsence(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	hw := "12392393-0000-4000-8000-000000000061"
	now := time.Now().Add(-time.Minute)
	f.observe(t, hw, []map[string]any{pat2393App(identifier, "SYNTHETIC1", "2.1")}, now)
	pat2393Equal(t, f.row(t, id), "observed_installation_count", 1)
	for i, status := range []string{"partial", "unavailable"} {
		f.observeStatus(t, "full.json", hw, status, []map[string]any{}, now.Add(time.Duration(i+1)*time.Second))
		row := f.row(t, id)
		pat2393Equal(t, row, "observed_installation_count", 1)
		pat2393Equal(t, row, "observation_state", "observed")
	}
}

// The linked policy row is the authority. Operator changes show through the
// declaration, the approved list never carries a second or stale copy, and
// removing the policy withdraws approval without deleting the declaration.
func TestPAT2393PlatformPolicyRowStaysAuthoritative(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	entries := func() []map[string]any {
		t.Helper()
		var out []map[string]any
		list := pat2393JSON(t, f.request(t, "GET", "/v1/portal/software/approved", f.viewer, nil, 200))
		for _, v := range list["products"].([]any) {
			p := v.(map[string]any)
			if p["declaration_id"] == id || p["identifier"] == identifier {
				out = append(out, p)
			}
		}
		return out
	}
	got := entries()
	if len(got) != 1 {
		t.Fatalf("approved list has %d rows for one declared product: %v", len(got), got)
	}
	for key, want := range map[string]any{"declaration_id": id, "identity_state": "matched", "observation_state": "not_observed",
		"observed_installation_count": 0, "source": "portal", "approved_by": f.email, "approved_at_basis": "decision", "min_version": "2.0", "name": "Synthetic Editor"} {
		pat2393Equal(t, got[0], key, want)
	}
	if fmt.Sprint(got[0]["policy_id"]) == "0" {
		t.Fatal("resolved declaration is not tied to its policy row")
	}
	f.exec(t, `UPDATE tenant_app_policies SET min_version='3.5' WHERE tenant_id=$1::uuid AND bundle_id=$2`, f.tenant, identifier)
	pat2393Equal(t, f.row(t, id), "min_version", "3.5")
	pat2393Equal(t, entries()[0], "min_version", "3.5")
	f.observe(t, "12392393-0000-4000-8000-000000000070", []map[string]any{pat2393App(identifier, "SYNTHETIC1", "3.0")}, time.Now().Add(-time.Minute))
	pat2393Equal(t, f.row(t, id), "outside_constraint_count", 1)

	f.exec(t, `DELETE FROM tenant_app_policies WHERE tenant_id=$1::uuid AND bundle_id=$2`, f.tenant, identifier)
	row := f.row(t, id)
	pat2393Equal(t, row, "approval_state", "unreviewed")
	pat2393Equal(t, row, "identity_state", "matched")
	if len(entries()) != 0 {
		t.Fatal("a declaration with no policy row is still listed as approved")
	}
	history := pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id+"/history", f.viewer, nil, 200))
	if len(history["decisions"].([]any)) != 1 {
		t.Fatalf("policy removal altered declaration history: %v", history)
	}
	rr := f.request(t, "GET", "/v1/portal/software?search="+identifier, f.viewer, nil, 200)
	if strings.Contains(rr.Body.String(), `"policy_state":"approved"`) {
		t.Fatal("a withdrawn declaration still approves the installation")
	}
}

// The creation and resolution ledger is append-only and carries the tenant.
func TestPAT2393PlatformDecisionLedgerIsAppendOnly(t *testing.T) {
	f := pat2393Fixture(t)
	id := pat2393ID(t, f.create(t, pat2393Body("macos")))
	for _, q := range []string{
		`UPDATE software_declaration_decisions SET actor_email='forged@pat2393.invalid' WHERE declaration_id=$1::uuid`,
		`UPDATE software_declaration_decisions SET justification='rewritten' WHERE declaration_id=$1::uuid`,
		`DELETE FROM software_declaration_decisions WHERE declaration_id=$1::uuid`,
	} {
		if _, e := f.pool.Exec(t.Context(), q, id); e == nil || !strings.Contains(e.Error(), "append-only") {
			t.Errorf("%s: err=%v, want an append-only refusal", q, e)
		}
	}
	if _, e := f.pool.Exec(t.Context(), `TRUNCATE software_declaration_decisions`); e == nil || !strings.Contains(e.Error(), "append-only") {
		t.Errorf("TRUNCATE: err=%v, want an append-only refusal", e)
	}
	var actor, tenant, snapshot string
	if e := f.pool.QueryRow(t.Context(), `SELECT actor_email,tenant_id::text,declaration->>'tenant_id' FROM software_declaration_decisions WHERE declaration_id=$1::uuid`, id).Scan(&actor, &tenant, &snapshot); e != nil {
		t.Fatal(e)
	}
	if actor != f.email || tenant != f.tenant || snapshot != f.tenant {
		t.Fatalf("ledger row actor=%s tenant=%s snapshot tenant=%s", actor, tenant, snapshot)
	}
	// Removing the declaration (tenant purge cascades it) must not fail on, or
	// erase, the retained history.
	f.exec(t, `DELETE FROM tenant_software_declarations WHERE id=$1::uuid`, id)
	if n := f.count(t, `SELECT count(*) FROM software_declaration_decisions WHERE declaration_id=$1::uuid`, id); n != 1 {
		t.Fatalf("history rows after declaration removal = %d, want 1", n)
	}
}

// The export neutralises every customer-authored cell a spreadsheet could run.
// The body is read before it is parsed: a ResponseRecorder body is drained by
// the CSV reader.
func TestPAT2393PlatformExportNeutralisesFormulas(t *testing.T) {
	f := pat2393Fixture(t)
	body := pat2393Body("windows")
	body["name"], body["publisher"], body["justification"] = "=HYPERLINK(1)", "@Synthetic Publisher", "+needed for the synthetic estate"
	id := pat2393ID(t, f.create(t, body))
	second := pat2393Body("macos")
	second["name"], second["publisher"] = "-Synthetic Tool", "Plain Publisher"
	f.create(t, second)
	raw := f.request(t, "GET", "/v1/portal/software/approved?format=csv", f.viewer, nil, 200).Body.String()
	records, e := csv.NewReader(strings.NewReader(raw)).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	col := map[string]int{}
	for i, h := range records[0] {
		col[h] = i
	}
	found := false
	for _, cells := range records[1:] {
		for i, cell := range cells {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("column %s carries an unneutralised cell %q", records[0][i], cell)
			}
		}
		if cells[col["declaration_id"]] == id {
			found = true
			for key, want := range map[string]string{"name": "'=HYPERLINK(1)", "publisher": "'@Synthetic Publisher", "justification": "'+needed for the synthetic estate",
				"source": "portal", "identity_state": "unmatched", "observation_state": "not_observed", "observed_installation_count": "0", "min_version": "2.0", "review_date": "2099-12-31"} {
				if cells[col[key]] != want {
					t.Errorf("CSV %s=%q, want %q", key, cells[col[key]], want)
				}
			}
		}
	}
	if !found {
		t.Fatal("declaration missing from the export")
	}
	if !strings.Contains(raw, "'-Synthetic Tool") {
		t.Fatal("leading minus was not neutralised")
	}
}

// Declarations change nothing about the finding lifecycle's authority rules.
// A native Windows report carries no application absence scope, so it records
// no software lifecycle event for an unapproved policy, name-only or keyed on
// the identifier, whether the application is listed or later omitted, and
// whether or not a declared approval on the tenant is suspended meanwhile.
func TestPAT2393PlatformNativeWindowsReportOpensNoUnapprovedFinding(t *testing.T) {
	f := pat2393Fixture(t)
	identifier := "pat2393.lifecycle." + pat2393Random()
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,name,platform,policy,enforcement_tier) VALUES($1::uuid,'Synthetic Editor','windows','unapproved','report')`, f.tenant)
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,bundle_id,platform,policy,enforcement_tier) VALUES($1::uuid,$2,'windows','unapproved','report')`, f.tenant, identifier)
	events := func() int {
		t.Helper()
		return f.count(t, `SELECT count(*) FROM finding_lifecycle_events WHERE tenant_id=$1::uuid AND finding_kind='software'`, f.tenant)
	}
	hw := "12392393-0000-4000-8000-000000000080"
	now := time.Now().Add(-time.Minute)
	// Listed under the name-only policy, then under the identifier policy too.
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp("pat2393.named."+pat2393Random(), "CN=Synthetic Publisher", "valid")}, now)
	if f.count(t, `SELECT count(*) FROM device_apps da JOIN devices d ON d.id=da.device_id WHERE d.tenant_id=$1::uuid AND da.name='Synthetic Editor'`, f.tenant) != 1 {
		t.Fatal("fixture did not report the unapproved application")
	}
	if n := events(); n != 0 {
		t.Fatalf("a native Windows report opened %d software lifecycle events for a name-only unapproved policy", n)
	}
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, now.Add(time.Second))
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{}, now.Add(2*time.Second))
	if n := events(); n != 0 {
		t.Fatalf("native Windows reports recorded %d software lifecycle events", n)
	}
	// A declared approval that is resolved and then suspended does not change that.
	id, alias, declared := f.declaredWindows(t)
	good, bad := "12392393-0000-4000-8000-000000000081", "12392393-0000-4000-8000-000000000082"
	f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{pat2393WindowsApp(declared, "CN=Synthetic Publisher", "valid")}, now)
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{pat2393WindowsApp(declared, "", "unsigned")}, now.Add(time.Second))
	pat2393Equal(t, f.row(t, id), "effective_approval_state", "suspended")
	if n := events(); n != 0 {
		t.Fatalf("a suspended declared approval opened %d software lifecycle events on native Windows reports", n)
	}
}

// The migration is additive, and customer-visible strings keep house style.
func TestPAT2393PlatformMigrationAdditiveAndCopyStyle(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "0224_software_declarations.sql"))
	if e != nil {
		t.Fatal(e)
	}
	var statements []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		statements = append(statements, line)
	}
	sql := strings.Join(statements, "\n")
	for _, forbidden := range []string{`(?im)^\s*ALTER\s`, `(?im)^\s*DROP\s`, `(?im)^\s*UPDATE\s`, `(?im)^\s*DELETE\s`, `(?im)^\s*TRUNCATE\s`, `(?i)CREATE\s+OR\s+REPLACE`, `(?i)\bCASCADE\s*;`} {
		if regexp.MustCompile(forbidden).MatchString(sql) {
			t.Errorf("migration 0224 is not purely additive: matches %s", forbidden)
		}
	}
	for _, created := range regexp.MustCompile(`(?im)^\s*CREATE\s+(?:UNIQUE\s+)?(TABLE|VIEW|INDEX|FUNCTION|TRIGGER)\s+(\S+)`).FindAllStringSubmatch(sql, -1) {
		name, _, _ := strings.Cut(created[2], "(")
		if !strings.Contains(name, "declaration") && name != "effective_tenant_app_policies" {
			t.Errorf("migration 0224 creates an unexpected object %s %s", created[1], created[2])
		}
	}
	for _, file := range []string{filepath.Join("..", "..", "internal", "handlers", "portal_software_declarations.go"), filepath.Join("..", "..", "internal", "softwaregov", "declarations.go")} {
		src, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		for _, literal := range regexp.MustCompile("\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`").FindAllString(string(src), -1) {
			lower := strings.ToLower(literal)
			if strings.Contains(literal, "—") || strings.Contains(lower, "fleet") || regexp.MustCompile(`PAT-\d`).MatchString(literal) {
				t.Errorf("%s: string %s breaks copy rules (em dash, fleet or an internal ticket id)", filepath.Base(file), literal)
			}
		}
	}
}

// Suspension and restoration change what every device resolves to without any
// policy row changing, so the cached Unapproved-present summary must be told.
// A report that does not flip eligibility must not invalidate it.
func TestPAT2393PlatformEligibilityFlipInvalidatesUnapprovedSummary(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, identifier := f.declaredWindows(t)
	now := time.Now().Add(-time.Minute)
	good, bad := "12392393-0000-4000-8000-000000000090", "12392393-0000-4000-8000-000000000091"
	f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, now)
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	version := func() int {
		t.Helper()
		return f.count(t, `SELECT COALESCE((SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id=$1::uuid),0)::int`, f.tenant)
	}
	base := version()
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{pat2393WindowsApp("pat2393.unrelated", "", "unsigned")}, now.Add(time.Second))
	if got := version(); got != base {
		t.Fatalf("an unrelated report changed the policy version %d -> %d", base, got)
	}
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{pat2393WindowsApp(identifier, "", "unsigned")}, now.Add(2*time.Second))
	pat2393Equal(t, f.row(t, id), "effective_approval_state", "suspended")
	if got := version(); got != base+1 {
		t.Fatalf("suspension left the summary valid: policy version %d, want %d", got, base+1)
	}
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{}, now.Add(3*time.Second))
	pat2393Equal(t, f.row(t, id), "effective_approval_state", "active")
	if got := version(); got != base+2 {
		t.Fatalf("restoration left the summary valid: policy version %d, want %d", got, base+2)
	}
}

// The acceptance fixture skips without a database. Where CI promises one, a
// skip would be a green step that tested nothing, so fail instead.
func TestPAT2393PlatformDatabasePromised(t *testing.T) {
	if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" && os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("PATCHED_DB_TESTS_REQUIRED: the software declaration acceptance tests need TEST_DATABASE_URL and migration 0224")
	}
}

// windowsAliasFor inserts a curated publisher-qualified Windows alias for an
// identifier the caller has already normalised.
func (f *declarationFixture) windowsAliasFor(t *testing.T, normalised string) string {
	t.Helper()
	var product, alias string
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_products(canonical_key,canonical_name,vendor_name,lifecycle_state) VALUES($1,'Synthetic Editor','Synthetic Publisher','active') RETURNING id::text`, normalised).Scan(&product); e != nil {
		t.Fatal(e)
	}
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_product_aliases(product_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,match_confidence,provenance) VALUES($1::uuid,'windows','windows_native_publisher',$2,'synthetic publisher','exact','reviewed') RETURNING id::text`, product, normalised).Scan(&alias); e != nil {
		t.Fatal(e)
	}
	return alias
}

// The export carries an ordinary approved policy row and a declaration row
// side by side. The declaration columns of the ordinary row are empty cells or
// zero, never a nil rendering, and every text cell is neutralised.
func TestPAT2393PlatformExportOrdinaryAndDeclarationRows(t *testing.T) {
	f := pat2393Fixture(t)
	ordinary := "com.pat2393.ordinary." + pat2393Random()
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,bundle_id,team_id,platform,policy,enforcement_tier,notes) VALUES($1::uuid,$2,'SYNTHETIC1','macos','approved','report','licensed')`, f.tenant, ordinary)
	body := pat2393Body("windows")
	body["name"], body["publisher"] = "Declared Tool", "=Declared Publisher"
	delete(body, "min_version")
	delete(body, "review_date")
	id := pat2393ID(t, f.create(t, body))
	raw := f.request(t, "GET", "/v1/portal/software/approved?format=csv", f.viewer, nil, 200).Body.String()
	if strings.Contains(raw, "<nil>") || strings.Contains(raw, "0xc0") {
		t.Fatalf("export renders a nil or an address: %s", raw)
	}
	records, e := csv.NewReader(strings.NewReader(raw)).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	col := map[string]int{}
	for i, h := range records[0] {
		col[h] = i
	}
	want := map[string]map[string]string{
		ordinary: {"declaration_id": "", "source": "operator", "identity_state": "", "observation_state": "", "observed_installation_count": "0",
			"effective_approval_state": "", "publisher": "", "min_version": "", "review_date": "", "outside_constraint_count": "0", "unknown_version_count": "0",
			"approved_via": "operator", "justification": "licensed"},
		"Declared Tool": {"declaration_id": id, "source": "portal", "identity_state": "unmatched", "observation_state": "not_observed", "observed_installation_count": "0",
			"effective_approval_state": "unmatched", "publisher": "'=Declared Publisher", "min_version": "", "review_date": "", "outside_constraint_count": "0", "unknown_version_count": "0",
			"policy_id": "0", "identifier": "", "product_key": "", "approved_at_basis": "declaration"},
	}
	seen := 0
	for _, cells := range records[1:] {
		if len(cells) != len(records[0]) {
			t.Fatalf("row has %d cells, header has %d", len(cells), len(records[0]))
		}
		expect, ok := want[cells[col["name"]]]
		if !ok {
			continue
		}
		seen++
		for key, value := range expect {
			if cells[col[key]] != value {
				t.Errorf("%s: %s=%q, want %q", cells[col["name"]], key, cells[col[key]], value)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 expected rows: %s", seen, raw)
	}
}

// The agent may send the root thumbprint in upper case and a signer with
// doubled or non-ASCII spaces. The stored evidence, the pinned key and the
// eligibility function must still agree, or a correctly signed installation
// would suspend its own approval for ever.
func TestPAT2393PlatformPublisherKeyAgreesAcrossGoAndSQL(t *testing.T) {
	f := pat2393Fixture(t)
	id, alias, identifier := f.declaredWindows(t)
	app := pat2393WindowsApp(identifier, "CN=Synthetic  Publisher Ltd,　O=Synthetic Org", "valid")
	app["installation_evidence"].(map[string]any)["root_thumbprint"] = strings.Repeat("C", 64)
	app["installation_evidence"].(map[string]any)["signer_thumbprint"] = strings.Repeat("A", 64)
	now := time.Now().Add(-time.Minute)
	f.observeFixture(t, "full-v3-windows.json", "12392393-0000-4000-8000-0000000000a0", []map[string]any{app}, now)
	var stored string
	if e := f.pool.QueryRow(t.Context(), `SELECT observed_authenticode_root_thumbprint FROM software_observations WHERE tenant_id=$1::uuid AND identity_value_normalized=$2`, f.tenant, identifier).Scan(&stored); e != nil || stored != strings.Repeat("c", 64) {
		t.Fatalf("stored root thumbprint %q (%v), want lower case", stored, e)
	}
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	var key string
	if e := f.pool.QueryRow(t.Context(), `SELECT resolved_publisher_key FROM tenant_software_declarations WHERE id=$1::uuid`, id).Scan(&key); e != nil {
		t.Fatal(e)
	}
	if want := "authenticode:" + strings.Repeat("c", 64) + ":CN=Synthetic Publisher Ltd, O=Synthetic Org"; key != want {
		t.Fatalf("pinned key %q, want %q", key, want)
	}
	row := f.row(t, id)
	pat2393Equal(t, row, "effective_approval_state", "active")
	pat2393Equal(t, row, "observed_installation_count", 1)
	rr := f.request(t, "GET", "/v1/portal/software?search="+identifier, f.viewer, nil, 200)
	if !strings.Contains(rr.Body.String(), `"policy_state":"approved"`) {
		t.Fatalf("a correctly signed installation is not approved: %s", rr.Body.String())
	}
}

// Identifiers are matched as the extractor wrote them, not through a second
// normaliser: mixed case, doubled spaces, a tab and a non-ASCII capital must
// neither hide a current installation nor keep a removed one.
func TestPAT2393PlatformIdentifierSpellingCannotHideOrKeepAnInstallation(t *testing.T) {
	f := pat2393Fixture(t)
	suffix := pat2393Random()
	reported := "PAT2393  Éditor\tSuite " + suffix
	normalised := "pat2393 éditor suite " + suffix
	alias := f.windowsAliasFor(t, normalised)
	body := pat2393Body("windows")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	good, bad := "12392393-0000-4000-8000-0000000000b0", "12392393-0000-4000-8000-0000000000b1"
	now := time.Now().Add(-time.Minute)
	f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{pat2393WindowsApp(reported, "CN=Synthetic Publisher", "valid")}, now)
	if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND identity_value_normalized=$2 AND alias_id=$3::uuid`, f.tenant, normalised, alias); n != 1 {
		t.Fatalf("fixture: %d installations resolved to the alias, want 1", n)
	}
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	row := f.row(t, id)
	pat2393Equal(t, row, "effective_approval_state", "active")
	pat2393Equal(t, row, "observed_installation_count", 1)
	// An unsigned copy reported with another spelling of the same identifier
	// is a current installation and must suspend.
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{pat2393WindowsApp("pat2393 éDITOR   suite\t"+suffix, "", "unsigned")}, now.Add(time.Second))
	pat2393Equal(t, f.row(t, id), "effective_approval_state", "suspended")
	// Authoritatively removed: it stops counting, and the approval returns.
	f.observeFixture(t, "full-v3-windows.json", bad, []map[string]any{}, now.Add(2*time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "effective_approval_state", "active")
	pat2393Equal(t, row, "observed_installation_count", 1)
	f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{}, now.Add(3*time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "observation_state", "not_observed")
	pat2393Equal(t, row, "effective_approval_state", "suspended")
}

// An unmatched declaration says "approved" about itself and about nothing
// else. With the very product installed, same name, same identifier and a
// valid signer, every reader still sees it as undecided: the policy
// function, inventory, governance state, drift, the signed posture and the
// approved export. Covers a manual declaration (name and publisher only, both
// platforms) and a Windows declaration that selected the product but has not
// been resolved.
func TestPAT2393PlatformUnmatchedDeclarationApprovesNothingInAnyReader(t *testing.T) {
	f := pat2393Fixture(t)
	manualWin := pat2393ID(t, f.create(t, pat2393Body("windows")))
	manualMac := pat2393ID(t, f.create(t, pat2393Body("macos")))
	otherPublisher := pat2393Body("windows")
	otherPublisher["publisher"] = "A Different Publisher"
	f.create(t, otherPublisher)
	selected, _, winIdentifier := f.declaredWindows2(t)
	_, macIdentifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	now := time.Now().Add(-time.Minute)
	winHW, macHW := "12392393-0000-4000-8000-0000000000c0", "12392393-0000-4000-8000-0000000000c1"
	f.observeFixture(t, "full-v3-windows.json", winHW, []map[string]any{pat2393WindowsApp(winIdentifier, "CN=Synthetic Publisher", "valid")}, now)
	f.observe(t, macHW, []map[string]any{pat2393App(macIdentifier, "SYNTHETIC1", "2.1")}, now)
	cve := f.seedCVE(t)

	for _, id := range []string{manualWin, manualMac, selected} {
		row := f.row(t, id)
		pat2393Equal(t, row, "approval_state", "approved")
		pat2393Equal(t, row, "identity_state", "unmatched")
		pat2393Equal(t, row, "effective_approval_state", "unmatched")
		pat2393Equal(t, row, "observed_installation_count", 0)
		pat2393Equal(t, row, "policy_id", nil)
	}
	if n := f.count(t, `SELECT count(*) FROM effective_tenant_app_policies($1::uuid)`, f.tenant); n != 0 {
		t.Fatalf("policy readers see %d rows from unmatched declarations", n)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid`, f.tenant); n != 0 {
		t.Fatalf("unmatched declarations wrote %d policy rows", n)
	}
	for _, identifier := range []string{winIdentifier, macIdentifier} {
		// Inventory.
		rr := f.request(t, "GET", "/v1/portal/software?search="+identifier, f.viewer, nil, 200)
		if !strings.Contains(rr.Body.String(), identifier) || strings.Contains(rr.Body.String(), `"policy_state":"approved"`) {
			t.Fatalf("inventory for %s: %s", identifier, rr.Body.String())
		}
	}
	// Governance state and drift.
	estate, e := softwaregov.LoadEstate(t.Context(), f.pool, f.tenant, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	assessed := 0
	for _, a := range estate.Assessments {
		if a.Identifier == winIdentifier || a.Identifier == macIdentifier {
			assessed++
			if a.State != softwaregov.StateUnreviewed {
				t.Fatalf("governance state of %s = %s, want unreviewed", a.Identifier, a.State)
			}
		}
	}
	if assessed != 2 {
		t.Fatalf("governance assessed %d of the 2 installed products", assessed)
	}
	drift := f.request(t, "GET", "/v1/portal/software/drift", f.viewer, nil, 200).Body.String()
	for _, identifier := range []string{winIdentifier, macIdentifier} {
		if !strings.Contains(drift, identifier) {
			t.Fatalf("drift does not list %s as undecided: %s", identifier, drift)
		}
	}
	// Signed posture for each device: no approved entry.
	for _, hw := range []string{winHW, macHW} {
		for _, a := range f.postureApps(t, hw) {
			if a.Policy == "approved" {
				t.Fatalf("posture approves %s on %s", a.Identifier, hw)
			}
		}
	}
	// Approved list and export: declared intent only, no identifier, no installs.
	list := pat2393JSON(t, f.request(t, "GET", "/v1/portal/software/approved", f.viewer, nil, 200))
	for _, v := range list["products"].([]any) {
		p := v.(map[string]any)
		if p["identifier"] == winIdentifier || p["identifier"] == macIdentifier || fmt.Sprint(p["observed_installation_count"]) != "0" || p["identity_state"] != "unmatched" || fmt.Sprint(p["policy_id"]) != "0" {
			t.Fatalf("approved list row claims more than declared intent: %v", p)
		}
	}
	// Findings are untouched.
	if !strings.Contains(f.request(t, "GET", "/v1/portal/findings", f.viewer, nil, 200).Body.String(), cve) {
		t.Fatal("finding hidden")
	}
}

// declaredWindows2 is declaredWindows under a distinct name and publisher, so
// it can sit beside the manual declarations of the same test.
func (f *declarationFixture) declaredWindows2(t *testing.T) (id, alias, identifier string) {
	t.Helper()
	alias, identifier = f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	body := pat2393Body("windows")
	body["name"], body["alias_id"] = "Synthetic Editor (selected)", alias
	return pat2393ID(t, f.create(t, body)), alias, identifier
}

type pat2393PostureApp struct{ Identifier, Policy string }

// postureApps returns the signed posture's application policy list for one
// device, read the way the agent reads it.
func (f *declarationFixture) postureApps(t *testing.T, hw string) []pat2393PostureApp {
	t.Helper()
	var device string
	if e := f.pool.QueryRow(t.Context(), `SELECT id::text FROM devices WHERE tenant_id=$1::uuid AND hw_uuid=$2::uuid`, f.tenant, hw).Scan(&device); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE tenant_credentials SET device_id=$2::uuid WHERE tenant_id=$1::uuid`, f.tenant, device)
	seed := make([]byte, 32)
	seed[0] = 1
	key, e := agentconfig.KeyFromSeed(seed)
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest("GET", "/v1/posture", nil)
	mac := hmac.New(sha256.New, f.secret)
	req.Header.Set("Authorization", "Bearer "+f.bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", pat2393Random())
	rec := httptest.NewRecorder()
	handlers.PostureHandler(f.pool, key, nil, 5*time.Minute).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("posture=%d %s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Payload string `json:"signed_payload"`
	}
	if e = json.Unmarshal(rec.Body.Bytes(), &envelope); e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.DecodeString(envelope.Payload)
	if e != nil {
		t.Fatal(e)
	}
	var posture struct {
		AppPolicy struct {
			Apps []pat2393PostureApp
		} `json:"app_policy"`
	}
	if e = json.Unmarshal(raw, &posture); e != nil {
		t.Fatal(e)
	}
	return posture.AppPolicy.Apps
}

// refused asserts the HTTP status first and then the error code of the JSON
// refusal body, so a different failure cannot satisfy a reason check.
func (f *declarationFixture) refused(t *testing.T, method, path, token string, body any, status int, code string) {
	t.Helper()
	rr := f.request(t, method, path, token, body, status)
	var out struct {
		Error string `json:"error"`
	}
	if e := json.Unmarshal(rr.Body.Bytes(), &out); e != nil || out.Error != code {
		t.Fatalf("%s %s refused with %q (%v), want %q: %s", method, path, out.Error, e, code, rr.Body.String())
	}
}

// A current Windows installation with no observation has no signature
// evidence and cannot be shown removed. It stays in the current set and
// suspends the approval, whether its observation link was never set or the
// observation row has gone. It is not counted as a verified installation.
func TestPAT2393PlatformInstallationWithoutObservationSuspends(t *testing.T) {
	for _, mode := range []string{"latest_observation_id NULL", "observation row deleted"} {
		t.Run(mode, func(t *testing.T) {
			f := pat2393Fixture(t)
			id, alias, identifier := f.declaredWindows(t)
			good, orphan := "12392393-0000-4000-8000-0000000000d0", "12392393-0000-4000-8000-0000000000d1"
			now := time.Now().Add(-time.Minute)
			app := pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")
			f.observeFixture(t, "full-v3-windows.json", good, []map[string]any{app}, now)
			f.observeFixture(t, "full-v3-windows.json", orphan, []map[string]any{app}, now)
			f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
			row := f.row(t, id)
			pat2393Equal(t, row, "effective_approval_state", "active")
			pat2393Equal(t, row, "observed_installation_count", 2)
			scope := `tenant_id=$1::uuid AND identity_value_normalized=$2 AND device_id=(SELECT id FROM devices WHERE tenant_id=$1::uuid AND hw_uuid=$3::uuid)`
			if mode == "latest_observation_id NULL" {
				f.exec(t, `UPDATE software_installations SET latest_observation_id=NULL WHERE `+scope, f.tenant, identifier, orphan)
			} else {
				f.exec(t, `DELETE FROM software_observations WHERE `+scope, f.tenant, identifier, orphan)
			}
			if n := f.count(t, `SELECT count(*) FROM software_installations WHERE removed_at IS NULL AND latest_observation_id IS NULL AND `+scope, f.tenant, identifier, orphan); n != 1 {
				t.Fatalf("fixture: %d current installations without an observation, want 1", n)
			}
			if n := f.count(t, `SELECT count(*) FROM effective_tenant_app_policies($1::uuid) WHERE bundle_id=$2`, f.tenant, identifier); n != 0 {
				t.Fatal("the policy function still returns the approval beside an installation with no evidence")
			}
			row = f.row(t, id)
			pat2393Equal(t, row, "effective_approval_state", "suspended")
			pat2393Equal(t, row, "approval_state", "approved")
			// Only the verified copy is counted; the other is not passed off as verified.
			pat2393Equal(t, row, "observed_installation_count", 1)
			pat2393Equal(t, row, "observation_state", "observed")
			rr := f.request(t, "GET", "/v1/portal/software?search="+identifier, f.viewer, nil, 200)
			if !strings.Contains(rr.Body.String(), identifier) || strings.Contains(rr.Body.String(), `"policy_state":"approved"`) {
				t.Fatalf("inventory still approves the product: %s", rr.Body.String())
			}
			// A fresh, valid report from that device restores it.
			f.observeFixture(t, "full-v3-windows.json", orphan, []map[string]any{app}, now.Add(time.Second))
			row = f.row(t, id)
			pat2393Equal(t, row, "effective_approval_state", "active")
			pat2393Equal(t, row, "observed_installation_count", 2)
		})
	}
}

// With a minimum version, an installed version that is not numeric dotted is
// unknown: never outside the constraint and never inside it.
func TestPAT2393PlatformNonNumericVersionsAreUnknown(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	hw := "12392393-0000-4000-8000-0000000000e0"
	now := time.Now().Add(-time.Minute)
	for i, tc := range []struct {
		version          string
		outside, unknown int
	}{
		{"1.2.3-beta", 0, 1}, {"2024a", 0, 1}, {"v1.0", 0, 1}, {"1.0 (build 7)", 0, 1}, {"0", 1, 0},
		{"1.9.9", 1, 0}, {"2.0", 0, 0}, {"3.0-rc1", 0, 1}, {"10.1", 0, 0},
	} {
		f.observe(t, hw, []map[string]any{pat2393App(identifier, "SYNTHETIC1", tc.version)}, now.Add(time.Duration(i)*time.Second))
		row := f.row(t, id)
		if fmt.Sprint(row["observed_installation_count"]) != "1" || fmt.Sprint(row["outside_constraint_count"]) != fmt.Sprint(tc.outside) || fmt.Sprint(row["unknown_version_count"]) != fmt.Sprint(tc.unknown) {
			t.Errorf("version %q against minimum 2.0: observed=%v outside=%v unknown=%v, want 1/%d/%d", tc.version,
				row["observed_installation_count"], row["outside_constraint_count"], row["unknown_version_count"], tc.outside, tc.unknown)
		}
	}
}
