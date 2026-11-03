//go:build integration

package integration

// PAT-2015: software category tags end to end. Rules are entered through the
// real admin API, observations arrive through POST /v1/inventory and the real
// extractor, and results are read through GET /v1/portal/tagged-products with
// a real portal identity. Rule values carry a per-test random suffix because
// the rule tables are global and the integration database is shared.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/categorytag"
	"patched.im/api/internal/extractor"
)

type catApp struct{ name, version, bundle, team string }

type catExt struct{ browser, user, id, name, version string }

// postCategoryPayload posts full.json with its device, apps and browser
// extensions replaced, then runs the extractor exactly as production does.
func postCategoryPayload(t *testing.T, tn cveTestTenant, hwUUID string, apps []catApp, exts []catExt) string {
	t.Helper()
	appList := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		app := map[string]any{"name": a.name, "version": a.version, "bundle_id": a.bundle,
			"path": "/Applications/" + a.name + ".app"}
		if a.team != "" {
			app["team_id"] = a.team
		}
		appList = append(appList, app)
	}
	extList := make([]map[string]any, 0, len(exts))
	for _, e := range exts {
		extList = append(extList, map[string]any{
			"browser": e.browser, "profile": "Default", "user_account": e.user,
			"extension_id": e.id, "name": e.name, "version": e.version, "enabled": true,
			"permissions": []string{}, "host_permissions": []string{}, "from_webstore": true,
		})
	}
	return postCategoryFixture(t, tn, "full.json", hwUUID, appList, extList)
}

// postCategoryFixture posts one fixture with its device, apps and browser
// extensions replaced and runs the extractor.
func postCategoryFixture(t *testing.T, tn cveTestTenant, fixture, hwUUID string, appList, extList []map[string]any) string {
	t.Helper()
	return postCategoryFixtureWith(t, tn, fixture, hwUUID, appList, extList, nil)
}

// postCategoryFixtureWith is postCategoryFixture with extra top-level payload
// keys set (PAT-2055 adds browser_extensions_status this way).
func postCategoryFixtureWith(t *testing.T, tn cveTestTenant, fixture, hwUUID string, appList, extList []map[string]any, extra map[string]any) string {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", fixture), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tn.tenantID
	p["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	device := p["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2015" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2015-" + strings.ToLower(hwUUID[:8])
	if extList == nil {
		extList = []map[string]any{}
	}
	p["apps"] = appList
	p["browser_extensions"] = extList
	for k, v := range extra {
		p[k] = v
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, tn.hmacSecret)
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tn.bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", randomHex(16))
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: %d %s", resp.StatusCode, raw)
	}
	var ingest struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingest); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(context.Background(), env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingest.RawPayloadID)
	return deviceIDByHW(t, tn.tenantID, hwUUID)
}

// newCategoryTenant creates a tenant with a mapped portal user. Like the
// PAT-2024 suite it is not deleted afterwards: an ingested device writes
// append-only finding lifecycle rows that deliberately refuse deletion, and a
// random suffix keeps tenants apart instead.
func newCategoryTenant(t *testing.T, name string) cveTestTenant {
	t.Helper()
	return newCVETestTenant(t, name)
}

func newHW(sfx string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))
}

// chromeID returns a random well-formed Chrome Web Store ID (32 letters a-p).
func chromeID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = 'a' + b[i]%16
	}
	return string(b)
}

// teamID returns a random 10-character Team ID.
func teamID(t *testing.T) string {
	return strings.ToUpper(randomHex(5))
}

func adminJSON(t *testing.T, method, path string, body any, wantStatus int, out any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, env.internalSrv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, resp.StatusCode, wantStatus, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s %s: %v: %s", method, path, err, raw)
		}
	}
}

type catRule struct {
	ID              int64   `json:"id"`
	IdentifierType  string  `json:"identifier_type"`
	IdentifierValue string  `json:"identifier_value"`
	Qualifier       string  `json:"qualifier"`
	Platform        string  `json:"platform"`
	Category        string  `json:"category"`
	Subtype         string  `json:"subtype"`
	Version         int     `json:"version"`
	State           string  `json:"state"`
	CreatedBy       string  `json:"created_by"`
	CreatedClaimed  *string `json:"created_by_claimed"`
}

type catWrite struct {
	Rule     catRule `json:"rule"`
	Backfill struct {
		Tagged  int `json:"tagged"`
		Retired int `json:"retired"`
	} `json:"backfill"`
}

func createCategoryRule(t *testing.T, spec map[string]any) catRule {
	t.Helper()
	var out catWrite
	adminJSON(t, http.MethodPost, "/admin/software-categories/rules", spec, http.StatusCreated, &out)
	if out.Rule.State != "draft" || out.Rule.Version != 1 {
		t.Fatalf("new rule = %+v, want draft v1", out.Rule)
	}
	return out.Rule
}

func publishCategoryRule(t *testing.T, id int64) catWrite {
	t.Helper()
	var out catWrite
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/rules/%d/publish", id), nil, http.StatusOK, &out)
	if out.Rule.State != "published" {
		t.Fatalf("published rule = %+v", out.Rule)
	}
	return out
}

type taggedProduct struct {
	Category        string   `json:"category"`
	Subtype         string   `json:"subtype"`
	ObservationKind string   `json:"observation_kind"`
	ProductKey      string   `json:"product_key"`
	Name            string   `json:"name"`
	Identifier      string   `json:"identifier"`
	Browser         *string  `json:"browser"`
	Platforms       []string `json:"platforms"`
	Versions        []string `json:"versions"`
	DeviceCount     int      `json:"device_count"`
	UserCount       *int     `json:"user_count"`
	FirstSeen       string   `json:"first_seen"`
	ApprovalState   string   `json:"approval_state"`
	MatchBasis      []string `json:"match_basis"`
}

type taggedProductsResp struct {
	Category       *string         `json:"category"`
	Total          int             `json:"total"`
	EstateTooLarge bool            `json:"estate_too_large"`
	Products       []taggedProduct `json:"products"`
}

func readTagged(t *testing.T, tn cveTestTenant, query string) taggedProductsResp {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/tagged-products"+query, tn.token, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("tagged-products = %d: %s", resp.StatusCode, raw)
	}
	var out taggedProductsResp
	decodeJSON(t, resp, &out)
	return out
}

func findTagged(out taggedProductsResp, identifier string) (taggedProduct, bool) {
	for _, p := range out.Products {
		if strings.EqualFold(p.Identifier, identifier) {
			return p, true
		}
	}
	return taggedProduct{}, false
}

// One hand-entered rule, entered through the admin API, shows through the
// portal read API end to end: a draft never matches, publish backfills an
// already-observed product with no new device report, a later ingest tags a
// new device, and approval state is read from the existing policy table.
func TestCategoryTagHandEnteredRuleEndToEnd(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-e2e-"+sfx)
	bundle := "com.pat2015.aidesktop." + sfx
	appName := "Pat2015 AI Desktop " + sfx
	team := teamID(t)

	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundle,
		"category": "ai_tooling", "subtype": "desktop_app",
		"notes": "PAT-2015 integration test rule", "actor": "andy@patched.im",
	})

	dev1 := postCategoryPayload(t, tn, newHW(sfx), []catApp{{appName, "1.0", bundle, team}}, nil)

	if _, ok := findTagged(readTagged(t, tn, "?category=ai_tooling"), bundle); ok {
		t.Fatal("a draft rule tagged an observation")
	}

	// Backfill: publishing tags the already-observed product.
	pub := publishCategoryRule(t, rule.ID)
	if pub.Backfill.Tagged != 1 {
		t.Fatalf("publish backfill tagged %d observations, want 1", pub.Backfill.Tagged)
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL`, dev1, rule.ID); n != 1 {
		t.Fatalf("live tags on device 1 = %d, want 1", n)
	}
	out := readTagged(t, tn, "?category=ai_tooling&subtype=desktop_app")
	p, ok := findTagged(out, bundle)
	if !ok {
		t.Fatalf("published rule's product missing from read API: %+v", out)
	}
	if p.Category != "ai_tooling" || p.Subtype != "desktop_app" || p.ObservationKind != "app" ||
		p.DeviceCount != 1 || p.UserCount != nil || p.ApprovalState != "unreviewed" ||
		len(p.MatchBasis) != 1 || p.MatchBasis[0] != "macos_bundle_id" || p.Name != appName ||
		len(p.Platforms) != 1 || p.Platforms[0] != "macos" || p.FirstSeen == "" {
		t.Fatalf("tagged product = %+v", p)
	}

	// Ingest path: a second device reporting the app after publish is tagged
	// by the extractor, with no backfill.
	postCategoryPayload(t, tn, newHW(sfx), []catApp{{appName, "1.1", bundle, team}}, nil)
	p, _ = findTagged(readTagged(t, tn, "?category=ai_tooling"), bundle)
	if p.DeviceCount != 2 || len(p.Versions) != 2 {
		t.Fatalf("after second device = %+v, want 2 devices on 2 versions", p)
	}

	// Approval state comes from tenant_app_policies, read-only.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, $2, 'macos', 'approved')`, tn.tenantID, bundle); err != nil {
		t.Fatal(err)
	}
	p, _ = findTagged(readTagged(t, tn, ""), bundle)
	if p.ApprovalState != "approved" {
		t.Fatalf("approval_state = %q, want approved", p.ApprovalState)
	}

	// A subtype filter that does not apply hides it.
	if _, ok := findTagged(readTagged(t, tn, "?category=ai_tooling&subtype=cli"), bundle); ok {
		t.Fatal("subtype filter ignored")
	}
}

// Browser extensions are tagged on ingest by store ID, with user counts and
// extension approval state.
func TestCategoryTagBrowserExtensionOnIngest(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-ext-"+sfx)
	extID := chromeID(t)
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "browser_extension", "qualifier": "chrome_web_store",
		"identifier_value": extID, "category": "ai_tooling", "subtype": "browser_extension",
	})
	publishCategoryRule(t, rule.ID)

	postCategoryPayload(t, tn, newHW(sfx), nil, []catExt{
		{"chrome", "alice", extID, "Pat2015 AI Helper", "2.0"},
		{"chrome", "bob", extID, "Pat2015 AI Helper", "2.0"},
		{"chrome", "carol", chromeID(t), "Unrelated", "1.0"},
	})
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'any', $2, 'Pat2015 AI Helper', 'unapproved')`, tn.tenantID, extID); err != nil {
		t.Fatal(err)
	}
	out := readTagged(t, tn, "?category=ai_tooling&subtype=browser_extension")
	if out.Total != 1 {
		t.Fatalf("tagged extensions = %+v, want exactly the one matching extension", out)
	}
	p := out.Products[0]
	if p.Identifier != extID || p.ObservationKind != "browser_extension" || p.DeviceCount != 1 ||
		p.UserCount == nil || *p.UserCount != 2 || p.ApprovalState != "unapproved" ||
		p.Browser == nil || *p.Browser != "chrome" {
		t.Fatalf("tagged extension = %+v", p)
	}
}

// PAT-2074: a Safari app-extension rule tags a Safari row on ingest by its
// bundle identifier. Safari extensions carry no browser-profile user (they
// live in an app bundle, PAT-2064), so the extractor stores the fixed
// extractor.SafariSystemSentinel in user_account, and PAT-2071 makes
// fetchTaggedProducts exclude that sentinel from user_count. Before this
// ticket StoresForBrowser("safari") returned nil, so Keys() never emitted a
// browser_extension key for a Safari observation and no rule could ever
// match one; this proves the full path now works end to end.
func TestCategoryTagSafariExtensionOnIngest(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2074-safari-"+sfx)
	extID := "com.pat2074.safariext." + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "browser_extension", "qualifier": "safari_app_extension",
		"identifier_value": extID, "category": "ai_tooling", "subtype": "browser_extension",
	})
	publishCategoryRule(t, rule.ID)

	// user left empty: the macOS agent has always sent an empty user_account
	// for Safari rows, and browserExtValid+upsertBrowserExtensions normalise
	// that to the sentinel rather than dropping the row.
	postCategoryPayload(t, tn, newHW(sfx), nil, []catExt{
		{"safari", "", extID, "Pat2074 Safari Ext", "1.0"},
	})
	out := readTagged(t, tn, "?category=ai_tooling&subtype=browser_extension")
	if out.Total != 1 {
		t.Fatalf("tagged extensions = %+v, want exactly the one matching Safari extension", out)
	}
	p := out.Products[0]
	if p.Identifier != extID || p.ObservationKind != "browser_extension" || p.DeviceCount != 1 ||
		p.UserCount == nil || *p.UserCount != 0 || p.Browser == nil || *p.Browser != "safari" {
		t.Fatalf("tagged Safari extension = %+v, want device_count 1 and user_count 0 (sentinel excluded)", p)
	}
}

// A retired rule stops matching: its tags are retired (never deleted), the
// read API stops showing the product, and a later ingest does not re-tag it.
// Editing a published rule to a different identifier retires the old match
// with reason rule_changed.
func TestCategoryTagRetiredRuleStopsMatching(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-retire-"+sfx)
	bundleA := "com.pat2015.retire.a." + sfx
	bundleB := "com.pat2015.retire.b." + sfx
	hw := newHW(sfx)
	apps := []catApp{{"Pat2015 A " + sfx, "1.0", bundleA, ""}, {"Pat2015 B " + sfx, "1.0", bundleB, ""}}

	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundleA,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, rule.ID)
	device := postCategoryPayload(t, tn, hw, apps, nil)
	if _, ok := findTagged(readTagged(t, tn, ""), bundleA); !ok {
		t.Fatal("published rule did not tag on ingest")
	}

	// Edit the published rule to point at bundle B.
	var edited catWrite
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", rule.ID), map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundleB,
		"category": "ai_tooling", "subtype": "desktop_app",
	}, http.StatusOK, &edited)
	if edited.Rule.Version != 2 || edited.Backfill.Retired != 1 || edited.Backfill.Tagged != 1 {
		t.Fatalf("edit = %+v, want version 2, one retired, one tagged", edited)
	}
	out := readTagged(t, tn, "")
	if _, ok := findTagged(out, bundleA); ok {
		t.Fatal("edited rule still shows its old match")
	}
	if _, ok := findTagged(out, bundleB); !ok {
		t.Fatal("edited rule's new match missing")
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE rule_id = $1 AND retired_reason = 'rule_changed'`, rule.ID); n != 1 {
		t.Fatalf("rule_changed tags = %d, want 1", n)
	}

	var retired catWrite
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/rules/%d/retire", rule.ID), nil, http.StatusOK, &retired)
	if retired.Rule.State != "retired" || retired.Backfill.Retired != 1 {
		t.Fatalf("retire = %+v, want retired with one tag retired", retired)
	}
	if _, ok := findTagged(readTagged(t, tn, ""), bundleB); ok {
		t.Fatal("retired rule still matches through the read API")
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE rule_id = $1`, rule.ID); n != 2 {
		t.Fatalf("tag rows for the rule = %d, want 2 retired rows kept, not deleted", n)
	}

	// A fresh ingest must not re-tag against a retired rule.
	postCategoryPayload(t, tn, hw, apps, nil)
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL`, device, rule.ID); n != 0 {
		t.Fatalf("live tags after re-ingest = %d, want 0", n)
	}

	// Retired is terminal.
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/rules/%d/publish", rule.ID), nil, http.StatusConflict, nil)
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", rule.ID), map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundleA, "category": "ai_tooling", "subtype": "desktop_app",
	}, http.StatusConflict, nil)
}

// Every rule change is audited with who, when, before and after; the audit
// is append-only in the database.
func TestCategoryRuleChangesAreAudited(t *testing.T) {
	sfx := randomHex(4)
	team := teamID(t)
	bundle := "com.pat2015.audit." + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_team_id", "identifier_value": team, "qualifier": bundle,
		"category": "ai_tooling", "subtype": "desktop_app", "actor": "andy@patched.im",
	})
	if rule.CreatedBy != "admin_shared_token" || rule.CreatedClaimed == nil || *rule.CreatedClaimed != "andy@patched.im" {
		t.Fatalf("created_by = %q / %v, want admin_shared_token with the claim kept separately", rule.CreatedBy, rule.CreatedClaimed)
	}
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", rule.ID), map[string]any{
		"identifier_type": "macos_team_id", "identifier_value": team, "qualifier": bundle,
		"category": "ai_tooling", "subtype": "cli", "notes": "moved " + sfx,
	}, http.StatusOK, nil)
	// A no-op edit writes nothing.
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", rule.ID), map[string]any{
		"identifier_type": "macos_team_id", "identifier_value": strings.ToLower(team), "qualifier": strings.ToUpper(bundle),
		"category": "ai_tooling", "subtype": "cli", "notes": "moved " + sfx,
	}, http.StatusOK, nil)
	publishCategoryRule(t, rule.ID)
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/rules/%d/retire", rule.ID),
		map[string]any{"actor": "reviewer@patched.im"}, http.StatusOK, nil)

	var audit struct {
		Entries []struct {
			Action       string          `json:"action"`
			Actor        string          `json:"actor"`
			ClaimedActor *string         `json:"claimed_actor"`
			Before       json.RawMessage `json:"before"`
			After        json.RawMessage `json:"after"`
			At           time.Time       `json:"at"`
		} `json:"entries"`
	}
	adminJSON(t, http.MethodGet, fmt.Sprintf("/admin/software-categories/rules/%d/audit", rule.ID), nil, http.StatusOK, &audit)
	want := []string{"create", "edit", "publish", "retire"}
	if len(audit.Entries) != len(want) {
		t.Fatalf("audit entries = %+v, want %v", audit.Entries, want)
	}
	for i, e := range audit.Entries {
		if e.Action != want[i] || e.Actor != "admin_shared_token" || e.At.IsZero() || len(e.After) == 0 {
			t.Fatalf("audit[%d] = %+v, want action %s by admin_shared_token", i, e, want[i])
		}
	}
	if string(audit.Entries[0].Before) != "null" {
		t.Fatalf("create audit before = %s, want null", audit.Entries[0].Before)
	}
	var before, after catRule
	_ = json.Unmarshal(audit.Entries[1].Before, &before)
	_ = json.Unmarshal(audit.Entries[1].After, &after)
	if before.Subtype != "desktop_app" || after.Subtype != "cli" || after.Version != 2 {
		t.Fatalf("edit audit before/after = %+v / %+v", before, after)
	}
	if c := audit.Entries[3].ClaimedActor; c == nil || *c != "reviewer@patched.im" {
		t.Fatalf("retire claimed_actor = %v", c)
	}

	if _, err := env.pool.Exec(context.Background(),
		`UPDATE software_category_audit SET actor = 'forged' WHERE entity_type = 'rule' AND entity_id = $1`, rule.ID); err == nil {
		t.Fatal("software_category_audit accepted an UPDATE; it must be append-only")
	}
	if _, err := env.pool.Exec(context.Background(),
		`DELETE FROM software_category_audit WHERE entity_type = 'rule' AND entity_id = $1`, rule.ID); err == nil {
		t.Fatal("software_category_audit accepted a DELETE; it must be append-only")
	}
}

// Tenant A never sees tenant B through the read API, even for the same
// product matched by the same global rule.
func TestCategoryTagReadAPITenantIsolation(t *testing.T) {
	sfx := randomHex(4)
	a := newCategoryTenant(t, "pat2015-iso-a-"+sfx)
	b := newCategoryTenant(t, "pat2015-iso-b-"+sfx)
	shared := "com.pat2015.shared." + sfx
	onlyB := "com.pat2015.onlyb." + sfx
	for _, bundle := range []string{shared, onlyB} {
		r := createCategoryRule(t, map[string]any{
			"identifier_type": "macos_bundle_id", "identifier_value": bundle,
			"category": "ai_tooling", "subtype": "desktop_app",
		})
		publishCategoryRule(t, r.ID)
	}
	extB := chromeID(t)
	extRule := createCategoryRule(t, map[string]any{
		"identifier_type": "browser_extension", "qualifier": "chrome_web_store", "identifier_value": extB,
		"category": "ai_tooling", "subtype": "browser_extension",
	})
	publishCategoryRule(t, extRule.ID)
	postCategoryPayload(t, a, newHW(sfx), []catApp{{"Shared " + sfx, "1.0", shared, ""}}, nil)
	postCategoryPayload(t, b, newHW(sfx), []catApp{{"Shared " + sfx, "1.0", shared, ""}, {"Only B " + sfx, "1.0", onlyB, ""}},
		[]catExt{{"chrome", "bee", extB, "Only B extension", "1.0"}})
	postCategoryPayload(t, b, newHW(sfx), []catApp{{"Shared " + sfx, "1.0", shared, ""}}, nil)

	outA := readTagged(t, a, "")
	if p, ok := findTagged(outA, shared); !ok || p.DeviceCount != 1 {
		t.Fatalf("tenant A shared product = %+v (found %v), want 1 device (its own)", p, ok)
	}
	if _, ok := findTagged(outA, onlyB); ok {
		t.Fatal("tenant A sees a product only tenant B has")
	}
	if _, ok := findTagged(outA, extB); ok {
		t.Fatal("tenant A sees an extension only tenant B has")
	}
	if outA.Total != 1 {
		t.Fatalf("tenant A total = %d, want 1: %+v", outA.Total, outA.Products)
	}
	outB := readTagged(t, b, "")
	if p, ok := findTagged(outB, shared); !ok || p.DeviceCount != 2 {
		t.Fatalf("tenant B shared product = %+v, want 2 devices", p)
	}
	if _, ok := findTagged(outB, extB); !ok {
		t.Fatal("tenant B does not see its own tagged extension")
	}
}

// The global catalogue tables never hold or expose a tenant identifier: no
// tenant column, no foreign key into tenant data.
func TestCategoryGlobalTablesCarryNoTenantID(t *testing.T) {
	global := []string{"software_categories", "software_category_subtypes", "software_category_rules",
		"software_category_product_tags", "software_category_audit"}
	for _, table := range global {
		if n := countRows(t, `SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`, table); n != 1 {
			t.Fatalf("table %s missing", table)
		}
		if n := countRows(t, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1
			  AND (column_name ILIKE '%tenant%' OR column_name ILIKE '%device%')`, table); n != 0 {
			t.Errorf("global table %s has %d tenant or device columns", table, n)
		}
		if n := countRows(t, `
			SELECT count(*) FROM pg_constraint c
			JOIN pg_class src ON src.oid = c.conrelid
			JOIN pg_class dst ON dst.oid = c.confrelid
			WHERE c.contype = 'f' AND src.relname = $1
			  AND dst.relname IN ('tenants', 'devices', 'software_installations', 'software_observations',
			                      'device_browser_extensions', 'software_category_tags')`, table); n != 0 {
			t.Errorf("global table %s has %d foreign keys into tenant data", table, n)
		}
	}
	// And the tenant table is the only one that carries tenant_id.
	if n := countRows(t, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'software_category_tags' AND column_name = 'tenant_id'`); n != 1 {
		t.Fatal("software_category_tags must carry tenant_id")
	}
}

// A tag on a normalised product identity (software_products) tags every
// installation resolved to that product, without a match rule.
func TestCategoryProductTagAttachesByIdentity(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-product-"+sfx)
	bundle := "com.pat2015.product." + sfx
	key := "pat2015-product-" + sfx
	if _, err := env.pool.Exec(context.Background(), `
		WITH product AS (
			INSERT INTO software_products (canonical_key, canonical_name, vendor_name)
			VALUES ($1, 'Pat2015 Product', 'Pat2015 Vendor') RETURNING id
		)
		INSERT INTO software_product_aliases (product_id, platform, identity_kind, identity_value_normalized,
			companion_value_normalized, match_confidence, provenance)
		SELECT id, 'macos', 'macos_bundle', $2, '', 'exact', 'reviewed' FROM product`, key, bundle); err != nil {
		t.Fatal(err)
	}
	postCategoryPayload(t, tn, newHW(sfx), []catApp{{"Pat2015 Product " + sfx, "3.0", bundle, ""}}, nil)

	var created struct {
		ProductTag struct {
			ID    int64  `json:"id"`
			State string `json:"state"`
		} `json:"product_tag"`
		Backfill struct {
			Tagged int `json:"tagged"`
		} `json:"backfill"`
	}
	adminJSON(t, http.MethodPost, "/admin/software-categories/product-tags", map[string]any{
		"canonical_key": key, "category": "ai_tooling", "subtype": "local_runtime",
	}, http.StatusCreated, &created)
	if created.ProductTag.State != "published" || created.Backfill.Tagged != 1 {
		t.Fatalf("product tag create = %+v", created)
	}
	out := readTagged(t, tn, "?category=ai_tooling&subtype=local_runtime")
	if out.Total != 1 || out.Products[0].MatchBasis[0] != "software_product" || !strings.HasPrefix(out.Products[0].ProductKey, "product:") {
		t.Fatalf("product-tagged read = %+v", out)
	}
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/product-tags/%d/retire", created.ProductTag.ID), nil, http.StatusOK, nil)
	if out := readTagged(t, tn, "?category=ai_tooling&subtype=local_runtime"); out.Total != 0 {
		t.Fatalf("retired product tag still shows: %+v", out)
	}
}

// Admin validation: bad input is a 400, a duplicate live rule a 409.
func TestCategoryRuleAdminValidation(t *testing.T) {
	adminJSON(t, http.MethodPost, "/admin/software-categories/rules", map[string]any{
		"identifier_type": "display_name", "identifier_value": "ChatGPT", "category": "ai_tooling", "subtype": "desktop_app",
	}, http.StatusBadRequest, nil)
	adminJSON(t, http.MethodPost, "/admin/software-categories/rules", map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": "com.x", "category": "ai_tooling", "subtype": "no_such_subtype",
	}, http.StatusBadRequest, nil)
	spec := map[string]any{"identifier_type": "mcp_server", "identifier_value": "pat2015-" + randomHex(4),
		"category": "ai_tooling", "subtype": "mcp_server"}
	createCategoryRule(t, spec)
	adminJSON(t, http.MethodPost, "/admin/software-categories/rules", spec, http.StatusConflict, nil)

	var vocab struct {
		Categories []struct {
			Key      string `json:"key"`
			Subtypes []struct {
				Key string `json:"key"`
			} `json:"subtypes"`
		} `json:"categories"`
		IdentifierTypes []string `json:"identifier_types"`
	}
	adminJSON(t, http.MethodGet, "/admin/software-categories", nil, http.StatusOK, &vocab)
	found := false
	for _, c := range vocab.Categories {
		if c.Key == "ai_tooling" && len(c.Subtypes) == 6 {
			found = true
		}
	}
	// PAT-2094 added the "kind" identifier type.
	if !found || len(vocab.IdentifierTypes) != 8 {
		t.Fatalf("vocabulary = %+v", vocab)
	}
}

// A Team ID rule is scoped to one bundle ID: the vendor's other apps, signed
// by the same Team ID, stay untagged. A bare Team ID is refused.
func TestCategoryTeamIDRuleIsBundleScoped(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-team-"+sfx)
	team := teamID(t)
	aiBundle := "com.pat2015.vendor.ai." + sfx
	wordBundle := "com.pat2015.vendor.word." + sfx
	adminJSON(t, http.MethodPost, "/admin/software-categories/rules", map[string]any{
		"identifier_type": "macos_team_id", "identifier_value": team,
		"category": "ai_tooling", "subtype": "desktop_app",
	}, http.StatusBadRequest, nil)
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_team_id", "identifier_value": team, "qualifier": aiBundle,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, rule.ID)
	postCategoryPayload(t, tn, newHW(sfx), []catApp{
		{"Vendor AI " + sfx, "1.0", aiBundle, team}, {"Vendor Word " + sfx, "1.0", wordBundle, team},
	}, nil)
	out := readTagged(t, tn, "")
	if _, ok := findTagged(out, aiBundle); !ok {
		t.Fatalf("Team ID plus bundle rule did not tag its app: %+v", out)
	}
	if _, ok := findTagged(out, wordBundle); ok {
		t.Fatal("Team ID rule tagged a sibling app from the same vendor")
	}
}

// Absence is no opinion. A payload that omits signed_by keeps the live tag
// (same row, no flap, no lost history); a payload carrying a different
// signer retires it as no_longer_matches.
func TestCategoryTagMissingFieldKeepsTagChangedFieldRetires(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-absent-"+sfx)
	name := "Pat2015 Assistant " + sfx
	wingetID := "PAT2015.Assistant" + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "windows_authenticode", "identifier_value": "Pat2015 AI Ltd", "qualifier": name,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, rule.ID)
	hw := newHW(sfx)
	app := func(signer string) []map[string]any {
		a := map[string]any{"name": name, "version": "1.0", "identifier": wingetID,
			"identifier_kind": "winget", "publisher": "Pat2015 AI Ltd", "architecture": "x86_64"}
		if signer != "" {
			a["signed_by"] = signer
		}
		return []map[string]any{a}
	}
	live := func(device string) []int64 {
		rows, err := env.pool.Query(context.Background(), `SELECT id FROM software_category_tags
			WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL ORDER BY id`, device, rule.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		return ids
	}

	device := postCategoryFixture(t, tn, "full-v3-windows.json", hw, app("Pat2015 AI Ltd"), nil)
	first := live(device)
	if len(first) != 1 {
		t.Fatalf("live tags after signed payload = %v, want 1", first)
	}

	postCategoryFixture(t, tn, "full-v3-windows.json", hw, app(""), nil)
	if got := live(device); len(got) != 1 || got[0] != first[0] {
		t.Fatalf("live tags after a payload without signed_by = %v, want the same tag %d kept", got, first[0])
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE rule_id = $1 AND retired_at IS NOT NULL`, rule.ID); n != 0 {
		t.Fatalf("a missing field retired %d tags", n)
	}

	// A payload with no usable display name: the extractor stores the Winget
	// ID as the name. That is no opinion, so the tag is kept.
	noName := app("Pat2015 AI Ltd")
	noName[0]["name"] = ""
	postCategoryFixture(t, tn, "full-v3-windows.json", hw, noName, nil)
	if got := live(device); len(got) != 1 || got[0] != first[0] {
		t.Fatalf("live tags after a payload without a display name = %v, want the same tag %d kept", got, first[0])
	}

	postCategoryFixture(t, tn, "full-v3-windows.json", hw, app("Someone Else Ltd"), nil)
	if got := live(device); len(got) != 0 {
		t.Fatalf("live tags after a different signer = %v, want none", got)
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE id = $1 AND retired_reason = 'no_longer_matches'`, first[0]); n != 1 {
		t.Fatal("changed signer did not retire the tag as no_longer_matches")
	}
}

// A retire that holds its lock while an ingest evaluates the same rule: the
// ingest must wait on FOR SHARE and then see the rule retired, so a retired
// rule never gains a live tag. Deterministic: the ingest is observed blocked
// on the lock before the retire commits.
func TestCategoryRetireRacingIngestNeverLeavesLiveTag(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-race-"+sfx)
	bundle := "com.pat2015.race." + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundle,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	// Observed while the rule is a draft, then published without a backfill,
	// so the device holds a matching observation and no tag yet.
	device := postCategoryPayload(t, tn, newHW(sfx), []catApp{{"Race " + sfx, "1.0", bundle, ""}}, nil)
	if _, err := env.pool.Exec(ctx, `UPDATE software_category_rules SET state = 'published', published_at = now() WHERE id = $1`, rule.ID); err != nil {
		t.Fatal(err)
	}

	retireTx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retireTx.Rollback(ctx) }()
	if _, _, err := categorytag.RetireRule(ctx, retireTx, rule.ID, categorytag.Actor{Actor: "test"}); err != nil {
		t.Fatalf("retire: %v", err)
	}

	type evalResult struct {
		res categorytag.Result
		err error
	}
	done := make(chan evalResult, 1)
	go func() {
		var out evalResult
		out.err = pgx.BeginFunc(ctx, env.pool, func(tx pgx.Tx) error {
			var err error
			out.res, err = categorytag.EvaluateDevice(ctx, tx, tn.tenantID, device)
			return err
		})
		done <- out
	}()

	blocked := false
	for i := 0; i < 100 && !blocked; i++ {
		var n int
		if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		blocked = n > 0
		if !blocked {
			select {
			case r := <-done:
				done <- r
				i = 100
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if !blocked {
		t.Error("ingest evaluation did not wait on the retiring rule's lock")
	}
	if err := retireTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("evaluate: %v", r.err)
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE rule_id = $1 AND retired_at IS NULL`, rule.ID); n != 0 {
		t.Fatalf("retired rule has %d live tags after racing an ingest", n)
	}
}

// Publish backfills in bounded chunks and flips to published only after the
// last chunk commits.
func TestCategoryPublishBackfillsInChunks(t *testing.T) {
	orig := categorytag.BackfillChunkSize
	categorytag.BackfillChunkSize = 1
	t.Cleanup(func() { categorytag.BackfillChunkSize = orig })
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-chunks-"+sfx)
	bundle := "com.pat2015.chunks." + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundle,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	for i := 0; i < 3; i++ {
		postCategoryPayload(t, tn, newHW(sfx), []catApp{{"Chunks " + sfx, "1.0", bundle, ""}}, nil)
	}
	pub := publishCategoryRule(t, rule.ID)
	if pub.Backfill.Tagged != 3 {
		t.Fatalf("chunked publish tagged %d, want 3", pub.Backfill.Tagged)
	}
	if p, ok := findTagged(readTagged(t, tn, ""), bundle); !ok || p.DeviceCount != 3 {
		t.Fatalf("after chunked publish = %+v", p)
	}
}

// An extension not re-reported within the presence window of its device's
// last report no longer counts, though its tag is kept.
func TestCategoryExtensionPresenceWindow(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-presence-"+sfx)
	extID := chromeID(t)
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "browser_extension", "qualifier": "chrome_web_store", "identifier_value": extID,
		"category": "ai_tooling", "subtype": "browser_extension",
	})
	publishCategoryRule(t, rule.ID)
	device := postCategoryPayload(t, tn, newHW(sfx), nil, []catExt{{"chrome", "dee", extID, "Presence " + sfx, "1.0"}})
	if _, ok := findTagged(readTagged(t, tn, ""), extID); !ok {
		t.Fatal("present extension missing")
	}
	if _, err := env.pool.Exec(context.Background(), `UPDATE device_browser_extensions
		SET last_seen = now() - interval '40 days' WHERE device_id = $1::uuid`, device); err != nil {
		t.Fatal(err)
	}
	if _, ok := findTagged(readTagged(t, tn, ""), extID); ok {
		t.Fatal("extension not reported for 40 days still counts as present")
	}
	if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE rule_id = $1 AND retired_at IS NULL`, rule.ID); n != 1 {
		t.Fatalf("presence window retired the tag (live = %d); it must only hide it", n)
	}
}

// Changing what kind of identifier a published rule tests would leave its old
// tags live (the old observations are a different kind, so they neither match
// nor contradict the new definition). It is refused; retire and recreate.
func TestCategoryPublishedRuleKindChangeRefused(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-kind-"+sfx)
	bundle := "com.pat2015.kind." + sfx
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "macos_bundle_id", "identifier_value": bundle,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, rule.ID)
	postCategoryPayload(t, tn, newHW(sfx), []catApp{{"Kind " + sfx, "1.0", bundle, ""}}, nil)
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", rule.ID), map[string]any{
		"identifier_type": "mcp_server", "identifier_value": "pat2015-kind-" + sfx,
		"category": "ai_tooling", "subtype": "mcp_server",
	}, http.StatusConflict, nil)
	winget := createCategoryRule(t, map[string]any{
		"identifier_type": "package", "qualifier": "winget", "identifier_value": "PAT2015.Kind" + sfx,
		"category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, winget.ID)
	adminJSON(t, http.MethodPut, fmt.Sprintf("/admin/software-categories/rules/%d", winget.ID), map[string]any{
		"identifier_type": "package", "qualifier": "npm", "identifier_value": "pat2015-kind" + sfx,
		"category": "ai_tooling", "subtype": "cli",
	}, http.StatusConflict, nil)
	if p, ok := findTagged(readTagged(t, tn, ""), bundle); !ok || len(p.MatchBasis) != 1 || p.MatchBasis[0] != "macos_bundle_id" {
		t.Fatalf("refused edit changed the live tag: %+v (found %v)", p, ok)
	}
}

// A non-ASCII Authenticode signer and product name (a non-breaking space, an
// accented publisher, different case) match through both the publish
// backfill and ingest: the SQL filter is a superset and Go decides.
func TestCategoryAuthenticodeNonASCIIMatchesBackfillAndIngest(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2015-unicode-"+sfx)
	app := func(signer, name string) []map[string]any {
		return []map[string]any{{"name": name, "version": "1.0", "identifier": "PAT2015.Societe" + sfx,
			"identifier_kind": "winget", "publisher": "x", "signed_by": signer, "architecture": "x86_64"}}
	}
	// Observed before publish: must be tagged by the backfill.
	before := postCategoryFixture(t, tn, "full-v3-windows.json", newHW(sfx),
		app("SOCIÉTÉ GÉNÉRALE IA", "Assistant Société "+sfx), nil)
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "windows_authenticode", "identifier_value": "Société Générale IA",
		"qualifier": "assistant société " + sfx, "category": "ai_tooling", "subtype": "desktop_app",
	})
	pub := publishCategoryRule(t, rule.ID)
	if pub.Backfill.Tagged != 1 {
		t.Fatalf("backfill tagged %d non-ASCII observations, want 1", pub.Backfill.Tagged)
	}
	// Observed after publish: must be tagged on ingest.
	after := postCategoryFixture(t, tn, "full-v3-windows.json", newHW(sfx),
		app("Société  Générale\tIA", "ASSISTANT SOCIÉTÉ "+sfx), nil)
	for _, d := range []string{before, after} {
		if n := countRows(t, `SELECT count(*) FROM software_category_tags WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL`, d, rule.ID); n != 1 {
			t.Fatalf("device %s live tags = %d, want 1", d, n)
		}
	}
}

// PAT-2094: Homebrew formulae and casks are ingested onto the same
// software_installations seam apps use (internal/extractor/homebrew_inventory.go,
// identity_kind homebrew_formula / homebrew_cask), but before this ticket
// InstallationObservation's default case swallowed that identity into an
// empty KindApp observation, so a published brew_formula/brew_cask rule
// matched nothing (contracts/portal-api.md called this out: "matchable by
// rule but not yet tagged"). This proves the wiring end to end: an AI
// formula and an AI cask are tagged with the right subtype and observation
// kind, a non-AI formula in the same payload stays untagged, and the tags
// are tenant-scoped.
func TestCategoryTagHomebrewFormulaAndCaskOnIngest(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2094-brew-"+sfx)

	formulaRule := createCategoryRule(t, map[string]any{
		"identifier_type": "package", "qualifier": "brew_formula",
		"identifier_value": "ollama", "category": "ai_tooling", "subtype": "local_runtime",
	})
	publishCategoryRule(t, formulaRule.ID)
	caskRule := createCategoryRule(t, map[string]any{
		"identifier_type": "package", "qualifier": "brew_cask",
		"identifier_value": "lm-studio", "category": "ai_tooling", "subtype": "desktop_app",
	})
	publishCategoryRule(t, caskRule.ID)

	homebrewBlock := func() map[string]any {
		return map[string]any{
			"collection_status": "complete", "truncated": false, "truncation_reason": nil,
			"prefixes": []any{map[string]any{
				"path": "/opt/homebrew", "owner": "alice", "owner_uid": 501,
				"collection_status": "complete", "formulae": 2, "casks": 1, "taps": 0,
			}},
			"formulae": []any{
				map[string]any{
					"prefix": "/opt/homebrew", "name": "ollama", "version": "0.3.10",
					"receipt_status": "read", "formula_file_status": "read",
					"homepage": "https://ollama.com", "source_url": nil, "opt_linked": true,
					"tap": "homebrew/core", "installed_on_request": true, "installed_as_dependency": false,
					"installed_at": "2026-09-01T10:00:00Z", "runtime_dependencies": []any{},
				},
				map[string]any{
					// A non-AI formula in the same payload: must stay untagged.
					"prefix": "/opt/homebrew", "name": "jq", "version": "1.7.1",
					"receipt_status": "read", "formula_file_status": "read",
					"homepage": "https://jqlang.org", "source_url": nil, "opt_linked": true,
					"tap": "homebrew/core", "installed_on_request": true, "installed_as_dependency": false,
					"installed_at": "2026-08-01T09:00:00Z", "runtime_dependencies": []any{},
				},
			},
			"casks": []any{map[string]any{
				"prefix": "/opt/homebrew", "token": "lm-studio", "version": "0.3.2",
				"versions_on_disk": []any{"0.3.2"}, "tap": "homebrew/cask",
				"installed_on_request": true, "installed_at": "2026-09-10T08:00:00Z",
				"receipt_status": "read", "apps": []any{},
			}},
			"taps": []any{}, "issues": []any{},
		}
	}

	hw := newHW(sfx)
	postCategoryFixtureWith(t, tn, "with-homebrew-complete-macos.json", hw, []map[string]any{}, nil,
		map[string]any{"homebrew": homebrewBlock()})

	out := readTagged(t, tn, "?category=ai_tooling")
	formula, ok := findTagged(out, "ollama")
	if !ok || formula.Category != "ai_tooling" || formula.Subtype != "local_runtime" ||
		formula.ObservationKind != "package" || formula.DeviceCount != 1 ||
		len(formula.MatchBasis) != 1 || formula.MatchBasis[0] != "package" {
		t.Fatalf("homebrew formula tag = %+v (ok=%v)", formula, ok)
	}
	cask, ok := findTagged(out, "lm-studio")
	if !ok || cask.Subtype != "desktop_app" || cask.ObservationKind != "package" || cask.DeviceCount != 1 {
		t.Fatalf("homebrew cask tag = %+v (ok=%v)", cask, ok)
	}
	if _, ok := findTagged(out, "jq"); ok {
		t.Fatal("a non-AI Homebrew formula was tagged")
	}

	// Tenant scoping: a second tenant reporting the identical formula and
	// cask gets its own tag, and neither tenant's device_count leaks into
	// the other's.
	other := newCategoryTenant(t, "pat2094-brew-other-"+sfx)
	postCategoryFixtureWith(t, other, "with-homebrew-complete-macos.json", newHW(sfx+"o"), []map[string]any{}, nil,
		map[string]any{"homebrew": homebrewBlock()})
	otherFormula, ok := findTagged(readTagged(t, other, "?category=ai_tooling"), "ollama")
	if !ok || otherFormula.DeviceCount != 1 {
		t.Fatalf("other tenant's own homebrew tag missing or wrong count: %+v (ok=%v)", otherFormula, ok)
	}
	formula, _ = findTagged(readTagged(t, tn, "?category=ai_tooling"), "ollama")
	if formula.DeviceCount != 1 {
		t.Fatalf("tenant isolation: original tenant's device_count changed to %d after another tenant ingested the same formula", formula.DeviceCount)
	}
}

// PAT-2094: an mcp_server rule matches the server name the user chose in
// their own client config, which no product rule can reliably catch, so
// every published mcp_server seed rule only ever caught the one name it
// named. A kind rule (identifier_type "kind", identifier_value "mcp_server")
// tags every mcp_server observation by Observation.Kind, independent of its
// name -- this proves that end to end, including an MCP server with a name
// no rule anywhere names, and that the tag is tenant-scoped.
func TestCategoryTagMCPServerKindRuleOnIngest(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2094-mcp-"+sfx)
	uniqueServerName := "pat2094-unnamed-by-any-rule-" + sfx

	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "kind", "identifier_value": "mcp_server",
		"category": "ai_tooling", "subtype": "mcp_server",
	})
	publishCategoryRule(t, rule.ID)
	// kindRuleKinds allows exactly one identifier_value (mcp_server), so
	// unlike every other rule type this test cannot give its rule a
	// per-test random identifier to keep it out of other tests' way in the
	// shared integration database (the convention this file's header
	// documents). Retire it once this test is done so a later test's own
	// mcp_server observations (e.g. TestToolingCategoryRulesTagEachType)
	// see only their own name-specific rule's match_basis.
	t.Cleanup(func() {
		adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/software-categories/rules/%d/retire", rule.ID), nil, http.StatusOK, nil)
	})

	hw := newHW(sfx)
	dev := postTooling(t, tn, "with-tooling-complete-macos.json", hw, func(m map[string]any) {
		mcp := m["mcp_servers"].(map[string]any)
		servers := mcp["servers"].([]any)
		servers[0].(map[string]any)["name"] = uniqueServerName
	})
	if dev == "" {
		t.Fatal("device not ingested")
	}

	out := readTagged(t, tn, "?category=ai_tooling&subtype=mcp_server")
	p, ok := findTagged(out, uniqueServerName)
	if !ok || p.ObservationKind != "mcp_server" || p.DeviceCount != 1 ||
		len(p.MatchBasis) != 1 || p.MatchBasis[0] != "kind" {
		t.Fatalf("mcp server kind tag = %+v (ok=%v), out=%+v", p, ok, out)
	}

	// Tenant isolation: another tenant's device with the same server name
	// must not appear in this tenant's read, and vice versa.
	other := newCategoryTenant(t, "pat2094-mcp-other-"+sfx)
	postTooling(t, other, "with-tooling-complete-macos.json", newHW(sfx+"o"), func(m map[string]any) {
		mcp := m["mcp_servers"].(map[string]any)
		servers := mcp["servers"].([]any)
		servers[0].(map[string]any)["name"] = uniqueServerName
	})
	otherOut := readTagged(t, other, "?category=ai_tooling&subtype=mcp_server")
	otherP, ok := findTagged(otherOut, uniqueServerName)
	if !ok || otherP.DeviceCount != 1 {
		t.Fatalf("other tenant's own mcp server tag missing or wrong count: %+v (ok=%v)", otherP, ok)
	}
	p, _ = findTagged(readTagged(t, tn, "?category=ai_tooling&subtype=mcp_server"), uniqueServerName)
	if p.DeviceCount != 1 {
		t.Fatalf("tenant isolation: original tenant's device_count changed to %d after another tenant ingested the same server name", p.DeviceCount)
	}
}
