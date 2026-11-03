package main

// PAT-2404 acceptance: staff review of an observed, signed software identity
// into a reviewed catalogue alias, and its withdrawal. Everything runs through
// the production routers (newInternalRouter for the staff routes,
// newPublicRouter for inventory and the portal) against the disposable
// TEST_DATABASE_URL the PAT-2393 fixture already insists on. Device state is
// only ever created by reporting signed inventory; a catalogue alias is only
// ever created by the review route, except where a test says it is planting a
// pre-existing row.
//
// The database is shared with every other test in the package and aliases are
// global, so each test works on identities and actors that carry its own
// random token and never asserts on a global count.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pat2404Base      = "/admin/software-catalogue"
	pat2404Token     = "synthetic-pat2404-admin-token"
	pat2404Addr      = "203.0.113.24"
	pat2404Team      = "PAT2404TM1"
	pat2404Publisher = "Synthetic Publisher"
	pat2404Audit     = "software_catalogue_audit"
	pat2404Actor     = "admin_shared_token"
)

type catalogueFixture struct {
	*declarationFixture
	internal http.Handler
	tok      string
}

func pat2404Fixture(t *testing.T) *catalogueFixture {
	t.Helper()
	f := pat2393Fixture(t)
	return &catalogueFixture{declarationFixture: f, tok: pat2393Random(),
		internal: newInternalRouter(f.pool, nil, 0, "", pat2404Token, "", nil, "", nil)}
}

// staffAs sends one request to the internal router. The leftmost
// X-Forwarded-For entry is what a caller could forge; the audit trail must
// record the rightmost one.
func (f *catalogueFixture) staffAs(token, method, path string, body any) *httptest.ResponseRecorder {
	var b []byte
	if raw, ok := body.(json.RawMessage); ok {
		b = raw
	} else if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", "198.51.100.9, "+pat2404Addr)
	rr := httptest.NewRecorder()
	f.internal.ServeHTTP(rr, r)
	return rr
}

func (f *catalogueFixture) staff(method, path string, body any) *httptest.ResponseRecorder {
	return f.staffAs(pat2404Token, method, path, body)
}

// pat2404Identity is one software identity as a device reports it and as the
// extractor normalises it.
type pat2404Identity struct {
	platform, kind, name, reported, value, companion string
}

func (f *catalogueFixture) mac(label string) pat2404Identity {
	reported := "Com.PAT2404." + f.tok + "." + label
	return pat2404Identity{"macos", "macos_bundle_team", "PAT2404 " + label + " " + f.tok, reported, strings.ToLower(reported), pat2404Team}
}

func (f *catalogueFixture) win(label string) pat2404Identity {
	reported := "PAT2404." + f.tok + "." + label
	return pat2404Identity{"windows", "windows_native_publisher", "PAT2404 " + label + " " + f.tok, reported, strings.ToLower(reported), strings.ToLower(pat2404Publisher)}
}

// macApp reports the identity with the given codesign verdict; "" leaves
// signing_status out, as an older agent would.
func (i pat2404Identity) macApp(status string) map[string]any {
	app := pat2393App(i.reported, i.companion, "2.1")
	app["name"] = i.name
	if i.companion == "" {
		delete(app, "team_id")
	}
	if status != "" {
		app["signing_status"] = status
	}
	if status != "signed" {
		app["notarized"] = false
	}
	return app
}

// winApp reports the identity with the given Authenticode verdict; state ""
// sends no installation evidence at all, so only the registry publisher is
// known. rootKind and signer matter beside "valid" only.
func (i pat2404Identity) winApp(state, rootKind, signer string) map[string]any {
	app := pat2393WindowsApp(i.reported, signer, state)
	app["name"] = i.name
	if state == "" {
		delete(app, "installation_evidence")
	} else if state == "valid" {
		app["installation_evidence"].(map[string]any)["root_kind"] = rootKind
	}
	return app
}

func pat2404HW(n int) string { return fmt.Sprintf("24042404-0000-4000-8000-%012d", n) }

func (f *declarationFixture) reportMac(t *testing.T, hw int, at time.Time, apps ...map[string]any) {
	t.Helper()
	if apps == nil {
		apps = []map[string]any{}
	}
	f.observe(t, pat2404HW(hw), apps, at)
}

func (f *declarationFixture) reportWin(t *testing.T, hw int, at time.Time, apps ...map[string]any) {
	t.Helper()
	if apps == nil {
		apps = []map[string]any{}
	}
	f.observeFixture(t, "full-v3-windows.json", pat2404HW(hw), apps, at)
}

// reviewBody names a candidate. The four identity fields only say which
// observed identity is meant; the product name and the actor are unique per
// call so a refusal can prove it wrote nothing.
func pat2404ReviewBody(i pat2404Identity) map[string]any {
	return map[string]any{"platform": i.platform, "identity_kind": i.kind, "identity_value_normalized": i.value,
		"companion_value_normalized": i.companion, "canonical_name": "PAT2404 Product " + pat2393Random(),
		"vendor_name": "PAT2404 Vendor", "reason": "Signed on every device that reports it",
		"actor": "reviewer-" + pat2393Random() + "@pat2404.invalid"}
}

func (f *catalogueFixture) aliasCount(t *testing.T, body map[string]any) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM software_product_aliases WHERE platform=$1 AND identity_kind=$2 AND identity_value_normalized=$3 AND companion_value_normalized=$4`,
		fmt.Sprint(body["platform"]), fmt.Sprint(body["identity_kind"]), fmt.Sprint(body["identity_value_normalized"]), fmt.Sprint(body["companion_value_normalized"]))
}

// audit counts audit rows. A missing table is reported as such rather than as
// a zero.
func (f *catalogueFixture) audit(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if e := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pat2404Audit+` WHERE `+where, args...).Scan(&n); e != nil {
		t.Fatalf("%s: %v", pat2404Audit, e)
	}
	return n
}

// review promotes the identity through the staff route and returns the alias
// it created, read back from the table rather than trusted from the response.
func (f *catalogueFixture) review(t *testing.T, body map[string]any) string {
	t.Helper()
	rr := f.staff("POST", pat2404Base+"/reviews", body)
	if rr.Code != 201 {
		t.Fatalf("POST %s/reviews = %d, want 201: %s", pat2404Base, rr.Code, rr.Body.String())
	}
	var id string
	if e := f.pool.QueryRow(t.Context(), `SELECT id::text FROM software_product_aliases WHERE platform=$1 AND identity_kind=$2 AND identity_value_normalized=$3 AND companion_value_normalized=$4 AND provenance='reviewed' AND created_by=$5`,
		body["platform"], body["identity_kind"], body["identity_value_normalized"], body["companion_value_normalized"], body["actor"]).Scan(&id); e != nil {
		t.Fatalf("a 201 review left no reviewed alias attributed to the claimed actor: %v", e)
	}
	if !strings.Contains(rr.Body.String(), id) {
		t.Fatalf("review response does not carry the alias %s: %s", id, rr.Body.String())
	}
	return id
}

func (f *catalogueFixture) reviewOf(t *testing.T, i pat2404Identity) (alias string, body map[string]any) {
	t.Helper()
	body = pat2404ReviewBody(i)
	return f.review(t, body), body
}

// refuse asserts a refusal: one of the allowed statuses, a JSON error body (so
// a router 404 for a route that does not exist can never pass), and nothing
// written: no product, no alias, no audit row.
func (f *catalogueFixture) refuse(t *testing.T, body map[string]any, codes ...int) {
	t.Helper()
	before := f.aliasCount(t, body)
	rr := f.staff("POST", pat2404Base+"/reviews", body)
	pat2404Refusal(t, "POST "+pat2404Base+"/reviews", rr, codes...)
	if n := f.count(t, `SELECT count(*) FROM software_products WHERE canonical_name=$1`, fmt.Sprint(body["canonical_name"])); n != 0 {
		t.Errorf("a refused review left %d product rows", n)
	}
	if after := f.aliasCount(t, body); after != before {
		t.Errorf("a refused review changed the alias rows for the identity: %d -> %d", before, after)
	}
	if n := f.audit(t, `claimed_actor=$1`, fmt.Sprint(body["actor"])); n != 0 {
		t.Errorf("a refused review wrote %d audit rows", n)
	}
}

func pat2404Refusal(t *testing.T, what string, rr *httptest.ResponseRecorder, codes ...int) {
	t.Helper()
	ok := false
	for _, c := range codes {
		ok = ok || rr.Code == c
	}
	var out struct {
		Error string `json:"error"`
	}
	if !ok || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Error == "" {
		t.Fatalf("%s = %d %q, want one of %v with a JSON error body", what, rr.Code, strings.TrimSpace(rr.Body.String()), codes)
	}
}

func (f *catalogueFixture) retire(t *testing.T, alias, actor string) *httptest.ResponseRecorder {
	t.Helper()
	return f.staff("POST", pat2404Base+"/aliases/"+alias+"/retire", map[string]any{"reason": "Publisher changed hands", "actor": actor})
}

// candidates returns the candidate rows for a platform whose identity carries
// this test's token, keyed by identity value.
func (f *catalogueFixture) candidates(t *testing.T, platform string) map[string]map[string]any {
	t.Helper()
	path := pat2404Base + "/candidates?platform=" + platform + "&limit=50&query=" + url.QueryEscape(f.tok)
	rr := f.staff("GET", path, nil)
	if rr.Code != 200 {
		t.Fatalf("GET %s = %d, want 200: %s", path, rr.Code, rr.Body.String())
	}
	var out struct {
		Candidates []map[string]any `json:"candidates"`
	}
	if e := json.Unmarshal(rr.Body.Bytes(), &out); e != nil || out.Candidates == nil {
		t.Fatalf("GET %s: no candidates array (%v): %s", path, e, rr.Body.String())
	}
	rows := map[string]map[string]any{}
	for _, c := range out.Candidates {
		rows[fmt.Sprint(c["identity_value_normalized"])] = c
	}
	return rows
}

func pat2404Keys(rows map[string]map[string]any) []string {
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func pat2404Values(ids ...pat2404Identity) []string {
	out := make([]string, 0, len(ids))
	for _, i := range ids {
		out = append(out, i.value)
	}
	sort.Strings(out)
	return out
}

func pat2404Candidate(t *testing.T, rows map[string]map[string]any, i pat2404Identity, promotable bool, devices, tenants int) map[string]any {
	t.Helper()
	c, ok := rows[i.value]
	if !ok {
		t.Fatalf("candidate %s missing from %v", i.value, pat2404Keys(rows))
	}
	for key, want := range map[string]any{"platform": i.platform, "identity_kind": i.kind, "companion_value_normalized": i.companion,
		"promotable": promotable, "device_count": devices, "tenant_count": tenants} {
		pat2393Equal(t, c, key, want)
	}
	reason, _ := c["blocked_reason"].(string)
	if promotable == (reason != "") {
		t.Errorf("candidate %s promotable=%v with blocked_reason %q", i.value, promotable, reason)
	}
	if !strings.Contains(fmt.Sprint(c["observed_names"]), i.name) {
		t.Errorf("candidate %s observed_names = %v, want the reported name %q", i.value, c["observed_names"], i.name)
	}
	if _, ok := c["evidence"].(map[string]any); !ok {
		t.Errorf("candidate %s carries no evidence summary: %v", i.value, c)
	}
	return c
}

// plantAlias inserts a pre-existing alias directly, standing in for the rows
// the 0120/0122 data migrations wrote. Never used for a reviewed alias.
func (f *catalogueFixture) plantAlias(t *testing.T, i pat2404Identity, provenance string) (alias, productName string) {
	t.Helper()
	productName = "PAT2404 Planted " + pat2393Random()
	var product string
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_products(canonical_key,canonical_name,vendor_name,lifecycle_state) VALUES($1,$2,'PAT2404 Vendor','active') RETURNING id::text`,
		"pat2404 planted "+pat2393Random(), productName).Scan(&product); e != nil {
		t.Fatal(e)
	}
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_product_aliases(product_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,match_confidence,provenance) VALUES($1::uuid,$2,$3,$4,$5,'exact',$6) RETURNING id::text`,
		product, i.platform, i.kind, i.value, i.companion, provenance).Scan(&alias); e != nil {
		t.Fatal(e)
	}
	return alias, productName
}

// installAlias is the alias the tenant's current installations of the identity
// are linked to: "" for unresolved, and a failure if they disagree.
func (f *declarationFixture) installAlias(t *testing.T, i pat2404Identity, hw int) string {
	t.Helper()
	var alias *string
	if e := f.pool.QueryRow(t.Context(), `SELECT si.alias_id::text FROM software_installations si JOIN devices d ON d.id=si.device_id AND d.tenant_id=si.tenant_id
		WHERE si.tenant_id=$1::uuid AND d.hw_uuid=$2::uuid AND si.platform=$3 AND si.identity_kind=$4 AND si.identity_value_normalized=$5 AND si.companion_value_normalized=$6 AND si.removed_at IS NULL`,
		f.tenant, pat2404HW(hw), i.platform, i.kind, i.value, i.companion).Scan(&alias); e != nil {
		t.Fatalf("current installation of %s on device %d: %v", i.value, hw, e)
	}
	if alias == nil {
		return ""
	}
	return *alias
}

// latestResolution is the resolution state of the newest observation of the
// identity in the tenant.
func (f *declarationFixture) latestResolution(t *testing.T, i pat2404Identity) (state, alias string) {
	t.Helper()
	var a *string
	if e := f.pool.QueryRow(t.Context(), `SELECT r.resolution_state,r.alias_id::text FROM software_observations o JOIN software_observation_resolutions r ON r.observation_id=o.id
		WHERE o.tenant_id=$1::uuid AND o.platform=$2 AND o.identity_kind=$3 AND o.identity_value_normalized=$4 AND o.companion_value_normalized=$5 ORDER BY o.id DESC LIMIT 1`,
		f.tenant, i.platform, i.kind, i.value, i.companion).Scan(&state, &a); e != nil {
		t.Fatal(e)
	}
	if a != nil {
		alias = *a
	}
	return state, alias
}

func (f *declarationFixture) lookup(t *testing.T, platform, query string) string {
	t.Helper()
	return f.request(t, "GET", "/v1/portal/software-products?platform="+platform+"&query="+url.QueryEscape(query), f.admin, nil, 200).Body.String()
}

func (f *declarationFixture) effective(t *testing.T, i pat2404Identity) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM effective_tenant_app_policies($1::uuid) WHERE platform=$2 AND lower(btrim(bundle_id))=$3 AND policy='approved'`, f.tenant, i.platform, i.value)
}

func (f *declarationFixture) inventoryApproves(t *testing.T, i pat2404Identity) bool {
	t.Helper()
	body := f.request(t, "GET", "/v1/portal/software?search="+url.QueryEscape(i.value), f.viewer, nil, 200).Body.String()
	if !strings.Contains(strings.ToLower(body), i.value) {
		t.Fatalf("inventory does not list %s: %s", i.value, body)
	}
	return strings.Contains(body, `"policy_state":"approved"`)
}

// --- a. candidates ---------------------------------------------------------

func TestPAT2404CandidatesListObservedUnaliasedIdentitiesWithEvidence(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t) // a second tenant with its own devices
	now := time.Now().Add(-time.Minute)

	signed, unknown, errored := f.mac("Signed"), f.mac("NoStatus"), f.mac("Errored")
	noTeam := f.mac("NoTeam")
	noTeam.companion, noTeam.kind = "", "macos_bundle"
	aliased, removed := f.mac("Aliased"), f.mac("Removed")
	f.plantAlias(t, aliased, "migration")
	f.reportMac(t, 1, now, signed.macApp("signed"), unknown.macApp(""), errored.macApp("error"), noTeam.macApp("signed"), aliased.macApp("signed"))
	f.reportMac(t, 2, now, signed.macApp("signed"))
	g.reportMac(t, 3, now, signed.macApp("signed"))
	f.reportMac(t, 4, now, removed.macApp("signed"))
	f.reportMac(t, 4, now.Add(time.Second))
	if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND identity_value_normalized=$2 AND removed_at IS NOT NULL`, f.tenant, removed.value); n != 1 {
		t.Fatalf("fixture: %d closed installations of the removed identity, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND identity_kind='macos_bundle' AND identity_value_normalized=$2 AND removed_at IS NULL`, f.tenant, noTeam.value); n != 1 {
		t.Fatalf("fixture: %d current bundle-only installations, want 1", n)
	}

	valid, winUnknown, registryOnly, enterprise := f.win("Valid"), f.win("Unknown"), f.win("RegistryOnly"), f.win("Enterprise")
	noPublisher := f.win("NoPublisher")
	bare := noPublisher.winApp("valid", "microsoft", "CN=Synthetic Publisher")
	delete(bare, "publisher")
	f.reportWin(t, 5, now, valid.winApp("valid", "microsoft", "CN=Synthetic Publisher"), winUnknown.winApp("unknown", "", ""),
		registryOnly.winApp("", "", ""), enterprise.winApp("valid", "enterprise", "CN=Synthetic Publisher"), bare)
	f.reportWin(t, 6, now, valid.winApp("valid", "public", "CN=Synthetic Publisher"))
	if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND identity_kind='windows_native' AND identity_value_normalized=$2 AND removed_at IS NULL`, f.tenant, noPublisher.value); n != 1 {
		t.Fatalf("fixture: %d current publisher-less installations, want 1", n)
	}

	macRows := f.candidates(t, "macos")
	if got, want := pat2404Keys(macRows), pat2404Values(signed, unknown, errored); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("macOS candidates = %v, want exactly %v (no bundle-only kind, no aliased identity, no removed installation)", got, want)
	}
	c := pat2404Candidate(t, macRows, signed, true, 3, 2)
	if states, _ := c["evidence"].(map[string]any)["signing_states"].(map[string]any); fmt.Sprint(states["signed"]) != "3" {
		t.Errorf("signed candidate evidence = %v, want signing_states.signed 3", c["evidence"])
	}
	pat2404Candidate(t, macRows, unknown, false, 1, 1)
	pat2404Candidate(t, macRows, errored, false, 1, 1)

	winRows := f.candidates(t, "windows")
	if got, want := pat2404Keys(winRows), pat2404Values(valid, winUnknown, registryOnly, enterprise); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Windows candidates = %v, want exactly %v (no publisher-less kind)", got, want)
	}
	c = pat2404Candidate(t, winRows, valid, true, 2, 1)
	evidence, _ := c["evidence"].(map[string]any)
	kinds := fmt.Sprint(evidence["root_kinds"])
	if states, _ := evidence["signing_states"].(map[string]any); fmt.Sprint(states["valid"]) != "2" || !strings.Contains(kinds, "microsoft") || !strings.Contains(kinds, "public") || fmt.Sprint(evidence["authenticode_publisher_key_count"]) != "1" {
		t.Errorf("valid Windows candidate evidence = %v, want 2 valid, roots microsoft and public, 1 publisher key", evidence)
	}
	pat2404Candidate(t, winRows, winUnknown, false, 1, 1)
	pat2404Candidate(t, winRows, registryOnly, false, 1, 1)
	pat2404Candidate(t, winRows, enterprise, false, 1, 1)

	for _, path := range []string{"/candidates?platform=linux", "/candidates"} {
		pat2404Refusal(t, "GET "+path, f.staff("GET", pat2404Base+path, nil), 400)
	}
}

// --- b. review succeeds above the bar --------------------------------------

func (f *catalogueFixture) assertReviewed(t *testing.T, alias string, i pat2404Identity, body map[string]any) {
	t.Helper()
	var platform, kind, value, companion, confidence, provenance, createdBy, evidence, name, vendor, lifecycle string
	if e := f.pool.QueryRow(t.Context(), `SELECT a.platform,a.identity_kind,a.identity_value_normalized,a.companion_value_normalized,a.match_confidence,a.provenance,COALESCE(a.created_by,''),a.evidence::text,sp.canonical_name,COALESCE(sp.vendor_name,''),sp.lifecycle_state
		FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.id=$1::uuid`, alias).Scan(&platform, &kind, &value, &companion, &confidence, &provenance, &createdBy, &evidence, &name, &vendor, &lifecycle); e != nil {
		t.Fatal(e)
	}
	got := []string{platform, kind, value, companion, confidence, provenance, createdBy, name, vendor, lifecycle}
	want := []string{i.platform, i.kind, i.value, i.companion, "exact", "reviewed", fmt.Sprint(body["actor"]), fmt.Sprint(body["canonical_name"]), fmt.Sprint(body["vendor_name"]), "active"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("reviewed alias = %v, want %v", got, want)
	}
	if evidence == "{}" || !json.Valid([]byte(evidence)) {
		t.Errorf("reviewed alias evidence = %s, want a summary of what qualified it", evidence)
	}
	if n := f.audit(t, `alias_id=$1::uuid`, alias); n != 1 {
		t.Fatalf("%d audit rows for the reviewed alias, want exactly 1", n)
	}
	if n := f.audit(t, `alias_id=$1::uuid AND action='review' AND actor=$2 AND claimed_actor=$3 AND source_addr=$4`, alias, pat2404Actor, fmt.Sprint(body["actor"]), pat2404Addr); n != 1 {
		t.Errorf("the review audit row does not carry actor %s, the claimed actor and source address %s", pat2404Actor, pat2404Addr)
	}
	if n := f.audit(t, `claimed_actor=$1`, fmt.Sprint(body["actor"])); n != 1 {
		t.Errorf("%d audit rows for one review request, want 1", n)
	}
	if _, listed := f.candidates(t, i.platform)[i.value]; listed {
		t.Errorf("%s is still a candidate after review", i.value)
	}
	row := f.listedAlias(t, alias)
	if row["retired_at"] != nil {
		t.Errorf("a new reviewed alias is listed as retired: %v", row)
	}
	for key, w := range map[string]any{"canonical_name": body["canonical_name"], "vendor_name": body["vendor_name"], "created_by": body["actor"], "identity_value_normalized": i.value} {
		pat2393Equal(t, row, key, w)
	}
}

// listedAlias finds one alias in the staff list of reviewed aliases.
func (f *catalogueFixture) listedAlias(t *testing.T, alias string) map[string]any {
	t.Helper()
	rr := f.staff("GET", pat2404Base+"/aliases", nil)
	if rr.Code != 200 {
		t.Fatalf("GET %s/aliases = %d, want 200: %s", pat2404Base, rr.Code, rr.Body.String())
	}
	var out struct {
		Aliases []map[string]any `json:"aliases"`
	}
	if e := json.Unmarshal(rr.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	for _, a := range out.Aliases {
		if a["alias_id"] == alias {
			return a
		}
	}
	t.Fatalf("alias %s is not in the staff alias list", alias)
	return nil
}

func TestPAT2404ReviewSignedMacOSIdentityCreatesReviewedAlias(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t)
	i := f.mac("Editor")
	now := time.Now().Add(-time.Minute)
	// One signed copy qualifies. Copies with no verdict or a collector error
	// elsewhere are missing evidence, not bad evidence, and do not block.
	f.reportMac(t, 1, now, i.macApp("signed"))
	f.reportMac(t, 2, now, i.macApp(""))
	g.reportMac(t, 3, now, i.macApp("error"))
	pat2404Candidate(t, f.candidates(t, "macos"), i, true, 3, 2)
	alias, body := f.reviewOf(t, i)
	f.assertReviewed(t, alias, i, body)
}

func TestPAT2404ReviewValidAuthenticodeWindowsIdentityCreatesReviewedAlias(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t)
	i := f.win("Editor")
	now := time.Now().Add(-time.Minute)
	// Two valid copies under different signing certificates are allowed and
	// reported; a copy with an unknown verdict and one with no evidence at all
	// do not block.
	f.reportWin(t, 1, now, i.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	g.reportWin(t, 2, now, i.winApp("valid", "public", "CN=Synthetic Publisher 2026"))
	f.reportWin(t, 3, now, i.winApp("unknown", "", ""))
	f.reportWin(t, 4, now, i.winApp("", "", ""))
	c := pat2404Candidate(t, f.candidates(t, "windows"), i, true, 4, 2)
	if evidence, _ := c["evidence"].(map[string]any); fmt.Sprint(evidence["authenticode_publisher_key_count"]) != "2" {
		t.Errorf("candidate evidence = %v, want 2 distinct Authenticode publisher keys reported", c["evidence"])
	}
	alias, body := f.reviewOf(t, i)
	f.assertReviewed(t, alias, i, body)
}

// Two platform identities reviewed under one product name and vendor are one
// product with two aliases, never two products that happen to share a name.
func TestPAT2404ReviewReusesProductAcrossPlatforms(t *testing.T) {
	f := pat2404Fixture(t)
	m, w := f.mac("Shared"), f.win("Shared")
	now := time.Now().Add(-time.Minute)
	f.reportMac(t, 1, now, m.macApp("signed"))
	f.reportWin(t, 2, now, w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	macAlias, body := f.reviewOf(t, m)
	second := pat2404ReviewBody(w)
	second["canonical_name"], second["vendor_name"] = "  "+strings.ToUpper(fmt.Sprint(body["canonical_name"])), body["vendor_name"]
	winAlias := f.review(t, second)
	if n := f.count(t, `SELECT count(DISTINCT product_id) FROM software_product_aliases WHERE id IN ($1::uuid,$2::uuid)`, macAlias, winAlias); n != 1 {
		t.Fatalf("two reviews under one product name created %d products, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM software_products WHERE lower(btrim(canonical_name))=lower($1)`, fmt.Sprint(body["canonical_name"])); n != 1 {
		t.Fatalf("%d product rows for one product name, want 1", n)
	}
}

// --- c. review refused ------------------------------------------------------

func TestPAT2404ReviewRefusedBelowEvidenceBar(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t)
	now := time.Now().Add(-time.Minute)
	hw := 0
	next := func() int { hw++; return hw }

	// Positive control: the route exists and this fixture can qualify an
	// identity, so every refusal below is a decision, not a missing route.
	control := f.mac("Control")
	f.reportMac(t, next(), now, control.macApp("signed"))
	_, controlBody := f.reviewOf(t, control)

	t.Run("windows registry publisher with no valid Authenticode", func(t *testing.T) {
		for _, state := range []string{"", "unknown"} {
			i := f.win("Registry" + state)
			f.reportWin(t, next(), now, i.winApp(state, "", ""))
			f.refuse(t, pat2404ReviewBody(i), 422)
		}
	})
	t.Run("macOS with no signed observation", func(t *testing.T) {
		for _, status := range []string{"", "error"} {
			i := f.mac("Unsigned" + status)
			f.reportMac(t, next(), now, i.macApp(status))
			f.refuse(t, pat2404ReviewBody(i), 422)
		}
	})
	t.Run("macOS bad evidence on another current installation", func(t *testing.T) {
		for n, status := range []string{"adhoc", "unsigned", "untrusted", "invalid"} {
			i := f.mac("Bad" + status)
			f.reportMac(t, next(), now, i.macApp("signed"))
			// The bad copy is in the other tenant on odd rounds: the bar is
			// evaluated across every tenant, not only where the good copy is.
			if n%2 == 0 {
				f.reportMac(t, next(), now, i.macApp(status))
			} else {
				g.reportMac(t, next(), now, i.macApp(status))
			}
			f.refuse(t, pat2404ReviewBody(i), 422)
			pat2404Candidate(t, f.candidates(t, "macos"), i, false, 2, 2-(n+1)%2)
		}
	})
	t.Run("windows bad evidence on another current installation", func(t *testing.T) {
		for n, state := range []string{"invalid", "unsigned"} {
			i := f.win("Bad" + state)
			f.reportWin(t, next(), now, i.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
			if n%2 == 0 {
				g.reportWin(t, next(), now, i.winApp(state, "", ""))
			} else {
				f.reportWin(t, next(), now, i.winApp(state, "", ""))
			}
			f.refuse(t, pat2404ReviewBody(i), 422)
		}
	})
	t.Run("bad evidence stops blocking once that installation is removed", func(t *testing.T) {
		i := f.mac("BadThenGone")
		bad := next()
		f.reportMac(t, next(), now, i.macApp("signed"))
		f.reportMac(t, bad, now, i.macApp("adhoc"))
		f.refuse(t, pat2404ReviewBody(i), 422)
		f.reportMac(t, bad, now.Add(time.Second))
		f.reviewOf(t, i)
	})
	t.Run("windows enterprise-only root", func(t *testing.T) {
		i := f.win("Enterprise")
		f.reportWin(t, next(), now, i.winApp("valid", "enterprise", "CN=Synthetic Publisher"))
		f.refuse(t, pat2404ReviewBody(i), 422)
	})
	t.Run("wrong kind", func(t *testing.T) {
		bundleOnly := f.mac("BundleOnly")
		bundleOnly.companion, bundleOnly.kind = "", "macos_bundle"
		f.reportMac(t, next(), now, bundleOnly.macApp("signed"))
		f.refuse(t, pat2404ReviewBody(bundleOnly), 400, 422)

		native := f.win("Native")
		app := native.winApp("valid", "microsoft", "CN=Synthetic Publisher")
		delete(app, "publisher")
		native.companion, native.kind = "", "windows_native"
		f.reportWin(t, next(), now, app)
		f.refuse(t, pat2404ReviewBody(native), 400, 422)

		// A qualifying identity named under any other kind, or the other platform.
		good := f.mac("KindProbe")
		f.reportMac(t, next(), now, good.macApp("signed"))
		for _, kind := range []string{"macos_bundle", "windows_native_publisher", "windows_native", "windows_winget", "windows_msix_publisher",
			"windows_msi_upgrade_publisher", "name_publisher", "display_name", "homebrew_cask", "homebrew_formula", ""} {
			body := pat2404ReviewBody(good)
			body["identity_kind"] = kind
			f.refuse(t, body, 400, 404, 422)
		}
		body := pat2404ReviewBody(good)
		body["platform"] = "windows"
		f.refuse(t, body, 400, 404, 422)
		body = pat2404ReviewBody(good)
		body["platform"] = "linux"
		f.refuse(t, body, 400, 422)
	})
	t.Run("identity not currently observed", func(t *testing.T) {
		f.refuse(t, pat2404ReviewBody(f.mac("NeverSeen")), 404, 422)
		f.refuse(t, pat2404ReviewBody(f.win("NeverSeen")), 404, 422)
	})
	t.Run("malformed Team ID", func(t *testing.T) {
		i := f.mac("ShortTeam")
		i.companion = "SHORT1"
		f.reportMac(t, next(), now, i.macApp("signed"))
		if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND identity_kind='macos_bundle_team' AND identity_value_normalized=$2 AND companion_value_normalized='SHORT1' AND removed_at IS NULL`, f.tenant, i.value); n != 1 {
			t.Fatalf("fixture: %d current installations with the malformed Team ID, want 1", n)
		}
		f.refuse(t, pat2404ReviewBody(i), 400, 422)
		pat2404Candidate(t, f.candidates(t, "macos"), i, false, 1, 1)
	})
	t.Run("unknown or missing body fields", func(t *testing.T) {
		i := f.mac("Fields")
		f.reportMac(t, next(), now, i.macApp("signed"))
		for _, key := range []string{"product_id", "alias_id", "provenance", "match_confidence", "evidence", "created_by", "tenant_id", "canonical_key", "lifecycle_state", "retired_at"} {
			body := pat2404ReviewBody(i)
			body[key] = "forged"
			f.refuse(t, body, 400)
		}
		for _, key := range []string{"canonical_name", "reason", "actor", "identity_value_normalized"} {
			body := pat2404ReviewBody(i)
			body[key] = "  "
			if key == "actor" {
				// The helper's audit check keys on the actor, so check this one by hand.
				before := f.aliasCount(t, body)
				pat2404Refusal(t, "review with a blank actor", f.staff("POST", pat2404Base+"/reviews", body), 400)
				if f.aliasCount(t, body) != before {
					t.Error("a review with a blank actor wrote an alias")
				}
				continue
			}
			f.refuse(t, body, 400, 404, 422)
		}
		pat2404Refusal(t, "review with a malformed body", f.staff("POST", pat2404Base+"/reviews", json.RawMessage(`["not","an","object"]`)), 400)
		// Still promotable after all of that.
		f.reviewOf(t, i)
	})
	t.Run("duplicate", func(t *testing.T) {
		body := pat2404ReviewBody(control)
		f.refuse(t, body, 409)
		if n := f.audit(t, `claimed_actor=$1`, fmt.Sprint(controlBody["actor"])); n != 1 {
			t.Errorf("a duplicate review changed the first review's audit rows: %d", n)
		}
		// Any non-retired alias blocks, whatever wrote it.
		i := f.mac("AlreadyMigrated")
		f.plantAlias(t, i, "migration")
		f.reportMac(t, next(), now, i.macApp("signed"))
		f.refuse(t, pat2404ReviewBody(i), 409)
	})
}

// --- d. the body cannot plant an identity -----------------------------------

func TestPAT2404ReviewBodyCannotPlantIdentity(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	seen := f.mac("Seen")
	f.reportMac(t, 1, now, seen.macApp("signed"))
	// Positive control, on a different identity so `seen` stays unreviewed.
	control := f.mac("Control")
	f.reportMac(t, 2, now, control.macApp("signed"))
	f.reviewOf(t, control)

	plant := func(name string, mutate func(*pat2404Identity)) {
		t.Run(name, func(t *testing.T) {
			i := seen
			mutate(&i)
			f.refuse(t, pat2404ReviewBody(i), 400, 404, 422)
		})
	}
	// A well-known product nobody in any tenant reports.
	plant("plausible identity no device reports", func(i *pat2404Identity) {
		i.value, i.companion = "com.pat2404."+f.tok+".plausible.browser", "EQHXZ8M8AV"
	})
	// The observed bundle under a Team ID no device reported for it.
	plant("observed bundle, another Team ID", func(i *pat2404Identity) { i.companion = "EQHXZ8M8AV" })
	// The observed Team ID with a bundle no device reported.
	plant("observed Team ID, another bundle", func(i *pat2404Identity) { i.value += ".helper" })
	// The value as reported rather than as normalised is not the stored identity.
	plant("un-normalised spelling", func(i *pat2404Identity) { i.value = seen.reported })
	plant("padded value", func(i *pat2404Identity) { i.value = " " + seen.value + " " })
	plant("lower-case Team ID", func(i *pat2404Identity) { i.companion = strings.ToLower(seen.companion) })

	// An identity whose only installation has been authoritatively removed is
	// history, not something a device reports.
	gone := f.mac("Gone")
	f.reportMac(t, 3, now, gone.macApp("signed"))
	f.reportMac(t, 3, now.Add(time.Second))
	t.Run("identity only on a removed installation", func(t *testing.T) {
		f.refuse(t, pat2404ReviewBody(gone), 404, 422)
	})

	// Nothing above created an alias for anything but the control, and the
	// identity that really is observed is still reviewable as observed.
	if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE identity_value_normalized LIKE '%'||$1||'%'`, f.tok); n != 1 {
		t.Fatalf("%d aliases exist for this test's identities, want only the control", n)
	}
	alias, _ := f.reviewOf(t, seen)
	var value, companion string
	if e := f.pool.QueryRow(t.Context(), `SELECT identity_value_normalized,companion_value_normalized FROM software_product_aliases WHERE id=$1::uuid`, alias).Scan(&value, &companion); e != nil || value != seen.value || companion != seen.companion {
		t.Fatalf("alias identity = %q/%q (%v), want the observed %q/%q", value, companion, e, seen.value, seen.companion)
	}
}

// --- e. portal lookup and declarations --------------------------------------

func TestPAT2404ReviewedAliasReachesPortalLookupAndDeclarations(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w := f.mac("Editor"), f.win("Editor")
	f.reportMac(t, 1, now, m.macApp("signed"))
	f.reportWin(t, 2, now, w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	macAlias, macBody := f.reviewOf(t, m)
	winAlias, winBody := f.reviewOf(t, w)
	// The next report links each installation to the reviewed alias.
	f.reportMac(t, 1, now.Add(time.Second), m.macApp("signed"))
	f.reportWin(t, 2, now.Add(time.Second), w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))

	if body := f.lookup(t, "macos", fmt.Sprint(macBody["canonical_name"])); !strings.Contains(body, macAlias) || strings.Contains(body, winAlias) {
		t.Fatalf("macOS lookup does not return exactly the reviewed macOS alias: %s", body)
	}
	if body := f.lookup(t, "windows", fmt.Sprint(winBody["canonical_name"])); !strings.Contains(body, winAlias) {
		t.Fatalf("Windows lookup does not return the reviewed alias: %s", body)
	}

	// macOS: selecting the alias resolves the declaration at creation.
	body := pat2393Body("macos")
	body["name"], body["alias_id"] = "Declared editor "+f.tok, macAlias
	row := f.create(t, body)
	macDeclaration := pat2393ID(t, row)
	for key, want := range map[string]any{"identity_state": "matched", "effective_approval_state": "active", "observed_installation_count": 1, "observation_state": "observed"} {
		pat2393Equal(t, row, key, want)
	}
	if f.effective(t, m) != 1 || !f.inventoryApproves(t, m) {
		t.Fatal("a declaration resolved through the reviewed macOS alias is not an effective approval")
	}

	// Windows: select, then resolve explicitly against current signed evidence.
	body = pat2393Body("windows")
	body["name"], body["alias_id"] = "Declared editor "+f.tok, winAlias
	winDeclaration := pat2393ID(t, f.create(t, body))
	pat2393Equal(t, f.row(t, winDeclaration), "identity_state", "unmatched")
	f.request(t, "POST", declarationPath+"/"+winDeclaration+"/resolve", f.admin, map[string]any{"alias_id": winAlias, "justification": "Confirmed publisher"}, 200)
	row = f.row(t, winDeclaration)
	for key, want := range map[string]any{"identity_state": "matched", "effective_approval_state": "active", "observed_installation_count": 1} {
		pat2393Equal(t, row, key, want)
	}
	if f.effective(t, w) != 1 || !f.inventoryApproves(t, w) {
		t.Fatal("a declaration resolved through the reviewed Windows alias is not an effective approval")
	}
	// A manual declaration can be resolved to the reviewed alias afterwards.
	g := pat2393Fixture(t)
	g.reportMac(t, 3, now, m.macApp("signed"))
	manual := pat2393ID(t, g.create(t, pat2393Body("macos")))
	g.request(t, "POST", declarationPath+"/"+manual+"/resolve", g.admin, map[string]any{"alias_id": macAlias, "justification": "Verified curated tuple"}, 200)
	pat2393Equal(t, g.row(t, manual), "identity_state", "matched")
	_ = macDeclaration
}

// --- f. resolution on the next report, in every tenant ----------------------

func TestPAT2404ReviewedAliasResolvesNextReportInEveryTenant(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w := f.mac("Editor"), f.win("Editor")
	other := f.mac("Unrelated")
	f.reportMac(t, 1, now, m.macApp("signed"), other.macApp("signed"))
	g.reportMac(t, 2, now, m.macApp("signed"))
	f.reportWin(t, 3, now, w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	g.reportWin(t, 4, now, w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	for _, x := range []struct {
		fx *declarationFixture
		i  pat2404Identity
		hw int
	}{{f.declarationFixture, m, 1}, {g, m, 2}, {f.declarationFixture, w, 3}, {g, w, 4}} {
		if a := x.fx.installAlias(t, x.i, x.hw); a != "" {
			t.Fatalf("fixture: %s already resolved to %s before any review", x.i.value, a)
		}
	}
	macAlias, _ := f.reviewOf(t, m)
	winAlias, _ := f.reviewOf(t, w)
	// Review itself rewrites no installation; resolution arrives with evidence.
	if a := g.installAlias(t, m, 2); a != "" {
		t.Fatalf("review rewrote an installation in another tenant: alias %s", a)
	}

	f.reportMac(t, 1, now.Add(time.Second), m.macApp("signed"), other.macApp("signed"))
	g.reportMac(t, 2, now.Add(time.Second), m.macApp("signed"))
	f.reportWin(t, 3, now.Add(time.Second), w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	g.reportWin(t, 4, now.Add(time.Second), w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	// A device that first reports the identity after the review resolves at once.
	g.reportMac(t, 5, now.Add(time.Second), m.macApp(""))
	for _, x := range []struct {
		fx    *declarationFixture
		i     pat2404Identity
		hw    int
		alias string
	}{{f.declarationFixture, m, 1, macAlias}, {g, m, 2, macAlias}, {g, m, 5, macAlias}, {f.declarationFixture, w, 3, winAlias}, {g, w, 4, winAlias}} {
		if a := x.fx.installAlias(t, x.i, x.hw); a != x.alias {
			t.Errorf("%s on device %d resolved to %q after the next report, want the reviewed alias %s", x.i.value, x.hw, a, x.alias)
		}
		if state, a := x.fx.latestResolution(t, x.i); state != "resolved" || a != x.alias {
			t.Errorf("%s latest observation is %s/%q, want resolved through %s", x.i.value, state, a, x.alias)
		}
	}
	var confidence string
	if e := f.pool.QueryRow(t.Context(), `SELECT resolution_confidence FROM software_installations WHERE tenant_id=$1::uuid AND alias_id=$2::uuid`, g.tenant, winAlias).Scan(&confidence); e != nil || confidence != "exact" {
		t.Errorf("resolution confidence = %q (%v), want exact", confidence, e)
	}
	// Only the reviewed identity resolves: the neighbour on the same device does not.
	if a := f.installAlias(t, other, 1); a != "" {
		t.Errorf("an unreviewed identity resolved to %s", a)
	}
}

// --- g. retirement ----------------------------------------------------------

func TestPAT2404RetireWithdrawsAliasWithoutErasingHistory(t *testing.T) {
	f := pat2404Fixture(t)
	g := pat2393Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w := f.mac("Editor"), f.win("Editor")
	winApp := w.winApp("valid", "microsoft", "CN=Synthetic Publisher")
	f.reportMac(t, 1, now, m.macApp("signed"))
	f.reportWin(t, 2, now, winApp)
	macAlias, macBody := f.reviewOf(t, m)
	winAlias, winBody := f.reviewOf(t, w)
	f.reportMac(t, 1, now.Add(time.Second), m.macApp("signed"))
	f.reportWin(t, 2, now.Add(time.Second), winApp)

	body := pat2393Body("macos")
	body["name"], body["alias_id"] = "Declared mac "+f.tok, macAlias
	macDeclaration := pat2393ID(t, f.create(t, body))
	body = pat2393Body("windows")
	body["name"], body["alias_id"] = "Declared win "+f.tok, winAlias
	winDeclaration := pat2393ID(t, f.create(t, body))
	f.request(t, "POST", declarationPath+"/"+winDeclaration+"/resolve", f.admin, map[string]any{"alias_id": winAlias, "justification": "Confirmed publisher"}, 200)

	type surface struct {
		name        string
		i           pat2404Identity
		alias       string
		reviewBody  map[string]any
		declaration string
		hw          int
		report      func(fx *declarationFixture, hw int, at time.Time)
	}
	surfaces := []surface{
		{"macos", m, macAlias, macBody, macDeclaration, 1, func(fx *declarationFixture, hw int, at time.Time) { fx.reportMac(t, hw, at, m.macApp("signed")) }},
		{"windows", w, winAlias, winBody, winDeclaration, 2, func(fx *declarationFixture, hw int, at time.Time) { fx.reportWin(t, hw, at, winApp) }},
	}
	// Before: every surface is an effective approval. Without this the
	// "no longer effective" checks below could pass on a broken fixture.
	for _, s := range surfaces {
		pat2393Equal(t, f.row(t, s.declaration), "effective_approval_state", "active")
		if f.effective(t, s.i) != 1 || !f.inventoryApproves(t, s.i) {
			t.Fatalf("fixture: the %s declaration is not an effective approval before retirement", s.name)
		}
	}
	rowsBefore := f.tenantRows(t)
	decisionsBefore := f.count(t, `SELECT count(*) FROM software_approval_decisions WHERE tenant_id=$1::uuid`, f.tenant)
	if rowsBefore != [3]int{2, 3, 2} {
		t.Fatalf("fixture: declaration, history and policy rows = %v, want [2 3 2]", rowsBefore)
	}

	for n, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			actor := "retirer-" + pat2393Random() + "@pat2404.invalid"
			path := pat2404Base + "/aliases/" + s.alias + "/retire"
			// Refused shapes first; none of them retires anything.
			pat2404Refusal(t, "retire with an unknown field", f.staff("POST", path, map[string]any{"reason": "x", "actor": actor, "retired_at": "2020-01-01T00:00:00Z"}), 400)
			pat2404Refusal(t, "retire with no reason", f.staff("POST", path, map[string]any{"reason": " ", "actor": actor}), 400)
			pat2404Refusal(t, "retire an unknown alias", f.retire(t, "00000000-0000-4000-8000-000000002404", actor), 404)
			if n := f.audit(t, `claimed_actor=$1`, actor); n != 0 {
				t.Fatalf("refused retirements wrote %d audit rows", n)
			}
			if !strings.Contains(f.lookup(t, s.i.platform, fmt.Sprint(s.reviewBody["canonical_name"])), s.alias) {
				t.Fatal("a refused retirement removed the alias from the portal lookup")
			}

			if rr := f.retire(t, s.alias, actor); rr.Code != 200 {
				t.Fatalf("POST %s = %d, want 200: %s", path, rr.Code, rr.Body.String())
			}
			if n := f.audit(t, `alias_id=$1::uuid AND action='retire' AND actor=$2 AND claimed_actor=$3 AND source_addr=$4`, s.alias, pat2404Actor, actor, pat2404Addr); n != 1 {
				t.Errorf("%d retirement audit rows with actor, claimed actor and source address, want 1", n)
			}
			if n := f.audit(t, `alias_id=$1::uuid`, s.alias); n != 2 {
				t.Errorf("%d audit rows for the alias after review and retirement, want 2", n)
			}
			// The second retirement is refused and audits nothing.
			pat2404Refusal(t, "second retirement", f.retire(t, s.alias, actor), 409)
			if n := f.audit(t, `alias_id=$1::uuid`, s.alias); n != 2 {
				t.Errorf("a refused second retirement wrote an audit row: %d rows", n)
			}
			// The row itself is kept, marked, and still in the staff list.
			if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE id=$1::uuid AND provenance='reviewed' AND retired_at IS NOT NULL`, s.alias); n != 1 {
				t.Fatal("the retired alias row is gone or not marked retired")
			}
			if row := f.listedAlias(t, s.alias); row["retired_at"] == nil {
				t.Errorf("the staff list does not show the alias as retired: %v", row)
			}

			// Portal lookup, selection and resolution.
			if strings.Contains(f.lookup(t, s.i.platform, fmt.Sprint(s.reviewBody["canonical_name"])), s.alias) {
				t.Error("the portal lookup still returns the retired alias")
			}
			selecting := pat2393Body(s.i.platform)
			selecting["name"], selecting["alias_id"] = "Selecting retired "+f.tok, s.alias
			g.request(t, "POST", declarationPath, g.admin, selecting, 422)
			manual := pat2393Body(s.i.platform)
			manual["name"] = "Manual " + s.name + " " + f.tok
			manualID := pat2393ID(t, g.create(t, manual))
			s.report(g, 10+n, now.Add(2*time.Second))
			g.request(t, "POST", declarationPath+"/"+manualID+"/resolve", g.admin, map[string]any{"alias_id": s.alias, "justification": "retired"}, 422)
			pat2393Equal(t, g.row(t, manualID), "identity_state", "unmatched")

			// New reports no longer resolve through it; the link already
			// recorded on an installation is history and stays.
			if a := g.installAlias(t, s.i, 10+n); a != "" {
				t.Errorf("a report after retirement resolved through the retired alias %s", a)
			}
			if state, a := g.latestResolution(t, s.i); state != "unresolved" || a != "" {
				t.Errorf("observation after retirement is %s/%q, want unresolved", state, a)
			}
			s.report(f.declarationFixture, s.hw, now.Add(2*time.Second))
			if a := f.installAlias(t, s.i, s.hw); a != s.alias {
				t.Errorf("the already linked installation lost its historical alias: %q", a)
			}
			if state, _ := f.latestResolution(t, s.i); state != "unresolved" {
				t.Errorf("a new observation of a linked installation is %s after retirement, want unresolved", state)
			}

			// The declaration resolved through it confers nothing, in any reader.
			if n := f.effective(t, s.i); n != 0 {
				t.Errorf("effective_tenant_app_policies still returns the %s approval after retirement", s.name)
			}
			if f.inventoryApproves(t, s.i) {
				t.Errorf("inventory still shows the %s installation as approved after retirement", s.name)
			}
			if state := f.row(t, s.declaration)["effective_approval_state"]; state == "active" {
				t.Errorf("the %s declaration still reads as an active approval after retirement", s.name)
			}
			// And the candidate is back for a fresh review.
			if _, listed := f.candidates(t, s.i.platform)[s.i.value]; !listed {
				t.Errorf("%s is not a candidate again after its alias was retired", s.i.value)
			}
		})
	}

	// Nothing was deleted: declarations, their history, their policy rows and
	// the approval decisions are all exactly as they were.
	if after := f.tenantRows(t); after != rowsBefore {
		t.Fatalf("retirement changed declaration, history or policy rows: %v -> %v", rowsBefore, after)
	}
	if n := f.count(t, `SELECT count(*) FROM software_approval_decisions WHERE tenant_id=$1::uuid`, f.tenant); n != decisionsBefore {
		t.Fatalf("retirement changed approval decisions: %d -> %d", decisionsBefore, n)
	}
	for _, s := range surfaces {
		if n := f.count(t, `SELECT count(*) FROM tenant_software_declarations d JOIN tenant_app_policies p ON p.id=d.policy_id AND p.tenant_id=d.tenant_id WHERE d.id=$1::uuid AND d.resolved_alias_id=$2::uuid AND p.policy='approved'`, s.declaration, s.alias); n != 1 {
			t.Errorf("the %s declaration lost its resolution or its authored policy row", s.name)
		}
		f.request(t, "GET", declarationPath+"/"+s.declaration+"/history", f.viewer, nil, 200)
	}
}

// Only a reviewed alias can be retired through the staff route.
func TestPAT2404RetireRefusesAliasesThatWereNotReviewed(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	control := f.mac("Control")
	f.reportMac(t, 1, now, control.macApp("signed"))
	alias, _ := f.reviewOf(t, control)
	actor := "retirer-" + pat2393Random() + "@pat2404.invalid"
	for _, provenance := range []string{"migration", "system"} {
		planted, _ := f.plantAlias(t, f.mac("Planted"+provenance), provenance)
		pat2404Refusal(t, "retire a "+provenance+" alias", f.retire(t, planted, actor), 404, 409, 422)
		if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE id=$1::uuid AND retired_at IS NULL`, planted); n != 1 {
			t.Errorf("a %s alias was retired through the review route", provenance)
		}
	}
	pat2404Refusal(t, "retire a malformed id", f.retire(t, "not-a-uuid", actor), 400, 404)
	if n := f.audit(t, `claimed_actor=$1`, actor); n != 0 {
		t.Fatalf("refused retirements wrote %d audit rows", n)
	}
	if rr := f.retire(t, alias, actor); rr.Code != 200 {
		t.Fatalf("retire the reviewed control = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// A retired identity can be reviewed again, against the evidence as it is now.
func TestPAT2404ReReviewAfterRetirement(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	i := f.mac("Editor")
	f.reportMac(t, 1, now, i.macApp("signed"))
	alias, body := f.reviewOf(t, i)
	if rr := f.retire(t, alias, "retirer-"+f.tok+"@pat2404.invalid"); rr.Code != 200 {
		t.Fatalf("retire = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	live := func() int {
		return f.count(t, `SELECT count(*) FROM software_product_aliases WHERE platform=$1 AND identity_kind=$2 AND identity_value_normalized=$3 AND companion_value_normalized=$4 AND retired_at IS NULL`, i.platform, i.kind, i.value, i.companion)
	}
	if live() != 0 {
		t.Fatal("the identity still has a live alias after retirement")
	}
	// The bar is evaluated afresh: a copy that has since gone bad refuses it.
	f.reportMac(t, 2, now, i.macApp("adhoc"))
	f.refuse(t, pat2404ReviewBody(i), 422)
	f.reportMac(t, 2, now.Add(time.Second))

	again := pat2404ReviewBody(i)
	again["canonical_name"], again["vendor_name"] = body["canonical_name"], body["vendor_name"]
	second := f.review(t, again)
	if live() != 1 {
		t.Fatalf("%d live aliases after re-review, want exactly 1", live())
	}
	if !strings.Contains(f.lookup(t, "macos", fmt.Sprint(body["canonical_name"])), second) {
		t.Fatal("the re-reviewed alias is not in the portal lookup")
	}
	// The whole story stays on the ledger: review, retirement, review.
	var actions string
	if e := f.pool.QueryRow(t.Context(), `SELECT string_agg(action,',' ORDER BY id) FROM `+pat2404Audit+` WHERE alias_id IN (SELECT id FROM software_product_aliases WHERE platform=$1 AND identity_kind=$2 AND identity_value_normalized=$3 AND companion_value_normalized=$4)`,
		i.platform, i.kind, i.value, i.companion).Scan(&actions); e != nil || actions != "review,retire,review" {
		t.Fatalf("audit actions for the identity = %q (%v), want review,retire,review", actions, e)
	}
	f.reportMac(t, 3, now.Add(2*time.Second), i.macApp("signed"))
	if a := f.installAlias(t, i, 3); a != second {
		t.Fatalf("a report after re-review resolved to %q, want %s", a, second)
	}
	f.refuse(t, pat2404ReviewBody(i), 409)
}

// --- h. the audit table is append-only --------------------------------------

func TestPAT2404AuditTableIsAppendOnly(t *testing.T) {
	f := pat2404Fixture(t)
	var exists bool
	if e := f.pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, pat2404Audit).Scan(&exists); e != nil || !exists {
		t.Fatalf("relation %s does not exist (%v)", pat2404Audit, e)
	}
	i := f.mac("Editor")
	f.reportMac(t, 1, time.Now().Add(-time.Minute), i.macApp("signed"))
	alias, body := f.reviewOf(t, i)
	mutations := []string{
		`UPDATE ` + pat2404Audit + ` SET claimed_actor='forged@pat2404.invalid' WHERE alias_id='` + alias + `'`,
		`UPDATE ` + pat2404Audit + ` SET actor='someone_else' WHERE alias_id='` + alias + `'`,
		`DELETE FROM ` + pat2404Audit + ` WHERE alias_id='` + alias + `'`,
		`TRUNCATE ` + pat2404Audit,
	}
	for _, role := range []string{"", "patched"} {
		for _, q := range mutations {
			tx, e := f.pool.Begin(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if role != "" {
				if _, e = tx.Exec(t.Context(), `SET LOCAL ROLE `+role); e != nil {
					_ = tx.Rollback(t.Context())
					t.Fatalf("cannot SET ROLE %s: the application-role check is required (%v)", role, e)
				}
			}
			_, e = tx.Exec(t.Context(), q)
			_ = tx.Rollback(t.Context())
			refused := e != nil && strings.Contains(e.Error(), "append-only")
			// The migration-owning connection must reach the trigger. The
			// application role may instead lack permission for the mutation.
			if !refused && role == "patched" {
				var pgErr *pgconn.PgError
				refused = errors.As(e, &pgErr) && pgErr.Code == "42501"
			}
			if !refused {
				t.Errorf("as %q: %s: err=%v, want an append-only refusal (or application-role SQLSTATE 42501)", role, q, e)
			}
		}
	}
	if n := f.audit(t, `alias_id=$1::uuid AND claimed_actor=$2`, alias, fmt.Sprint(body["actor"])); n != 1 {
		t.Fatalf("the audit row did not survive: %d rows", n)
	}
	// Removing the alias's product or tenant data must not be blocked by, or
	// cascade into, the ledger: it carries no foreign key that could delete it.
	if n := f.count(t, `SELECT count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='f' AND confdeltype IN ('c','n','d')`, pat2404Audit); n != 0 {
		t.Errorf("%s has %d foreign keys that would rewrite or delete audit rows", pat2404Audit, n)
	}
}

// --- i. route placement and authentication ----------------------------------

var pat2404Routes = []struct{ method, path string }{
	{"GET", "/candidates?platform=macos"},
	{"GET", "/aliases"},
	{"POST", "/reviews"},
	{"POST", "/aliases/00000000-0000-4000-8000-000000002404/retire"},
}

// Control: passes before the feature exists and must keep passing after it.
func TestPAT2404StaffRoutesAbsentFromPublicAndPortalRouters(t *testing.T) {
	f := pat2404Fixture(t)
	body := pat2404ReviewBody(f.mac("Editor"))
	for _, route := range pat2404Routes {
		for _, prefix := range []string{pat2404Base, "/v1" + pat2404Base, "/v1/portal" + pat2404Base, "/v1/portal/software-catalogue", "/v1/software-catalogue"} {
			for name, auth := range map[string]func(*http.Request){
				"admin bearer":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+pat2404Token) },
				"portal admin":  func(r *http.Request) { r.Header.Set("Cf-Access-Jwt-Assertion", f.admin) },
				"tenant bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+f.bearer) },
			} {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest(route.method, prefix+route.path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				auth(r)
				rr := httptest.NewRecorder()
				f.router.ServeHTTP(rr, r)
				if rr.Code != 404 && rr.Code != 405 && rr.Code != 401 {
					t.Errorf("public router, %s: %s %s = %d: the staff catalogue routes must not be reachable here", name, route.method, prefix+route.path, rr.Code)
				}
			}
		}
	}
	if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE identity_value_normalized LIKE '%'||$1||'%'`, f.tok); n != 0 {
		t.Fatalf("a public-router request created %d aliases", n)
	}
}

func TestPAT2404StaffRoutesRequireAdminBearerOnInternalRouter(t *testing.T) {
	f := pat2404Fixture(t)
	i := f.mac("Editor")
	f.reportMac(t, 1, time.Now().Add(-time.Minute), i.macApp("signed"))
	body := pat2404ReviewBody(i)
	unconfigured := newInternalRouter(f.pool, nil, 0, "", "", "", nil, "", nil)
	for _, route := range pat2404Routes {
		path := pat2404Base + route.path
		for name, token := range map[string]string{"no token": "", "wrong token": pat2404Token + "x", "tenant bearer": f.bearer, "portal JWT": f.admin} {
			if rr := f.staffAs(token, route.method, path, body); rr.Code != 401 {
				t.Errorf("%s: %s %s = %d, want 401", name, route.method, path, rr.Code)
			}
		}
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(route.method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+pat2404Token)
		rr := httptest.NewRecorder()
		unconfigured.ServeHTTP(rr, r)
		if rr.Code != 503 {
			t.Errorf("unset ADMIN_API_TOKEN: %s %s = %d, want 503 (fail closed)", route.method, path, rr.Code)
		}
	}
	if n := f.aliasCount(t, body); n != 0 {
		t.Fatalf("an unauthenticated request created %d aliases", n)
	}
	// With the token every route is mounted: none answers the router's own
	// 404 or 405, and the read routes answer 200.
	for _, route := range pat2404Routes {
		path := pat2404Base + route.path
		rr := f.staff(route.method, path, map[string]any{"reason": "probe", "actor": "probe@pat2404.invalid"})
		plain := !json.Valid(rr.Body.Bytes())
		if rr.Code == 405 || (rr.Code == 404 && plain) || rr.Code == 401 || rr.Code == 503 || (route.method == "GET" && rr.Code != 200) {
			t.Errorf("authenticated %s %s = %d %q: the route is not mounted on the internal router", route.method, path, rr.Code, strings.TrimSpace(rr.Body.String()))
		}
	}
	// No other verb is a write route.
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		for _, path := range []string{"/reviews", "/aliases", "/aliases/00000000-0000-4000-8000-000000002404", "/aliases/00000000-0000-4000-8000-000000002404/retire", "/candidates"} {
			if rr := f.staff(method, pat2404Base+path, body); rr.Code != 404 && rr.Code != 405 {
				t.Errorf("%s %s = %d: no such route may exist", method, pat2404Base+path, rr.Code)
			}
		}
	}
	f.review(t, body)
}

// --- j. controls that pass today and must keep passing ----------------------

func TestPAT2404ControlLookupEmptyWithoutReviewedAlias(t *testing.T) {
	f := pat2404Fixture(t)
	i, w := f.mac("Editor"), f.win("Editor")
	now := time.Now().Add(-time.Minute)
	f.reportMac(t, 1, now, i.macApp("signed"))
	f.reportWin(t, 2, now, w.winApp("valid", "microsoft", "CN=Synthetic Publisher"))
	// Observed and signed, but nobody has reviewed it: the lookup offers nothing.
	for _, platform := range []string{"macos", "windows"} {
		for _, query := range []string{f.tok, "PAT2404 Editor " + f.tok} {
			out := pat2393JSON(t, f.request(t, "GET", "/v1/portal/software-products?platform="+platform+"&query="+url.QueryEscape(query), f.admin, nil, 200))
			if fmt.Sprint(out["total"]) != "0" {
				t.Fatalf("%s lookup for %q returned products with no reviewed alias: %v", platform, query, out)
			}
		}
	}
	// A migration or system alias is not a reviewed one either.
	for _, provenance := range []string{"migration", "system"} {
		planted := f.mac("Planted" + provenance)
		alias, name := f.plantAlias(t, planted, provenance)
		if body := f.lookup(t, "macos", name); strings.Contains(body, alias) || !strings.Contains(body, `"total":0`) {
			t.Fatalf("lookup offers a %s alias: %s", provenance, body)
		}
		selecting := pat2393Body("macos")
		selecting["name"], selecting["alias_id"] = "Selecting "+provenance+" "+f.tok, alias
		f.request(t, "POST", declarationPath, f.admin, selecting, 422)
	}
	if n := f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND removed_at IS NULL AND alias_id IS NOT NULL`, f.tenant); n != 0 {
		t.Fatalf("%d installations resolved with no alias for their identity", n)
	}
}

func TestPAT2404ControlInventoryStillResolvesThroughMigrationAlias(t *testing.T) {
	f := pat2404Fixture(t)
	now := time.Now().Add(-time.Minute)
	m, w, plain := f.mac("Migrated"), f.win("Migrated"), f.mac("Plain")
	macAlias, _ := f.plantAlias(t, m, "migration")
	winAlias, _ := f.plantAlias(t, w, "system")
	f.reportMac(t, 1, now, m.macApp(""), plain.macApp("signed"))
	f.reportWin(t, 2, now, w.winApp("", "", ""))
	for _, x := range []struct {
		i     pat2404Identity
		hw    int
		alias string
	}{{m, 1, macAlias}, {w, 2, winAlias}} {
		if a := f.installAlias(t, x.i, x.hw); a != x.alias {
			t.Fatalf("%s resolved to %q, want the existing alias %s", x.i.value, a, x.alias)
		}
		if state, a := f.latestResolution(t, x.i); state != "resolved" || a != x.alias {
			t.Fatalf("%s observation is %s/%q, want resolved through %s", x.i.value, state, a, x.alias)
		}
		var product, confidence string
		if e := f.pool.QueryRow(t.Context(), `SELECT si.product_id::text,si.resolution_confidence FROM software_installations si WHERE si.tenant_id=$1::uuid AND si.alias_id=$2::uuid`, f.tenant, x.alias).Scan(&product, &confidence); e != nil || confidence != "exact" {
			t.Fatalf("installation product %q confidence %q (%v), want exact", product, confidence, e)
		}
		if n := f.count(t, `SELECT count(*) FROM software_product_aliases WHERE id=$1::uuid AND product_id=$2::uuid`, x.alias, product); n != 1 {
			t.Fatal("installation product does not match its alias")
		}
	}
	if a := f.installAlias(t, plain, 1); a != "" {
		t.Fatalf("an identity with no alias resolved to %s", a)
	}
	if state, _ := f.latestResolution(t, plain); state != "unresolved" {
		t.Fatalf("an identity with no alias is %s, want unresolved", state)
	}
	// A second report is idempotent about the link.
	f.reportMac(t, 1, now.Add(time.Second), m.macApp(""), plain.macApp("signed"))
	if a := f.installAlias(t, m, 1); a != macAlias {
		t.Fatalf("a second report changed the resolution to %q", a)
	}
}

// --- migration shape --------------------------------------------------------

// The migration adds one column, one table and replaces one function. It
// rewrites no existing row and drops nothing.
func TestPAT2404MigrationIsAdditive(t *testing.T) {
	matches, e := filepath.Glob(filepath.Join("..", "..", "migrations", "0226_*.sql"))
	if e != nil {
		t.Fatal(e)
	}
	var forward []string
	for _, m := range matches {
		if !strings.HasSuffix(m, "_rollback.sql") {
			forward = append(forward, m)
		}
	}
	if len(forward) != 1 || len(matches) != 2 {
		t.Fatalf("want exactly one 0226 migration and its rollback, found %v", matches)
	}
	raw, e := os.ReadFile(forward[0])
	if e != nil {
		t.Fatal(e)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			kept = append(kept, line)
		}
	}
	// The function body is a string; statements are judged outside it.
	sql := regexp.MustCompile(`(?s)\$fn\$.*?\$fn\$`).ReplaceAllString(strings.Join(kept, "\n"), "''")
	for _, forbidden := range []string{`(?im)^\s*DROP\s`, `(?im)^\s*UPDATE\s`, `(?im)^\s*DELETE\s`, `(?im)^\s*TRUNCATE\s`, `(?i)\bCASCADE\s*;`, `(?i)\bDROP\s+(COLUMN|CONSTRAINT)\b`, `(?i)\bALTER\s+COLUMN\b`, `(?i)\bSET\s+(NOT\s+NULL|DEFAULT)\b`} {
		if regexp.MustCompile(forbidden).MatchString(sql) {
			t.Errorf("migration 0226 is not additive: matches %s", forbidden)
		}
	}
	alters := regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\S+)\s+(.*?);`).FindAllStringSubmatch(sql, -1)
	if len(alters) != 1 || alters[0][1] != "software_product_aliases" || !regexp.MustCompile(`(?is)^ADD\s+COLUMN\s+(IF\s+NOT\s+EXISTS\s+)?retired_at\s+TIMESTAMPTZ\s*$`).MatchString(strings.TrimSpace(alters[0][2])) {
		t.Errorf("migration 0226 ALTER TABLE statements = %q, want only a nullable, default-free retired_at TIMESTAMPTZ on software_product_aliases", alters)
	}
	for _, created := range regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`).FindAllStringSubmatch(sql, -1) {
		if created[1] != pat2404Audit {
			t.Errorf("migration 0226 creates an unexpected table %s", created[1])
		}
	}
	replaced := regexp.MustCompile(`(?i)CREATE\s+OR\s+REPLACE\s+(\w+)\s+(\w+)`).FindAllStringSubmatch(sql, -1)
	if len(replaced) != 1 || !strings.EqualFold(replaced[0][1], "FUNCTION") || replaced[0][2] != "effective_tenant_app_policies" {
		t.Errorf("migration 0226 replaces %q, want only FUNCTION effective_tenant_app_policies", replaced)
	}
	if !strings.Contains(sql, "0226_") || !regexp.MustCompile(`(?i)INSERT\s+INTO\s+schema_migrations`).MatchString(sql) {
		t.Error("migration 0226 does not record itself in schema_migrations")
	}
}
