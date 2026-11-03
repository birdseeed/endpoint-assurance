//go:build integration

package integration

// PAT-2093: the overview's new software block, end to end. Inventory is
// posted through /v1/inventory and extracted exactly as production does, so
// the trust evidence is what the extractor really records from the
// collector's fields, not hand-written rows. Names, identifiers, Team IDs and
// CVE IDs carry a random suffix because the integration database is shared.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
)

type urgencyTenant struct {
	id, bearer, viewerToken string
	secret                  []byte
}

func newUrgencyTenant(t *testing.T, label string) urgencyTenant {
	t.Helper()
	sfx := randomHex(4)
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2093-"+label+"-"+sfx)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	viewer := "viewer-" + label + "-" + sfx + "@pat2093.example"
	mapPortalUserWithRole(t, viewer, tenantID, "")
	return urgencyTenant{id: tenantID, bearer: bearer, secret: secret, viewerToken: env.idp.token(t, viewer)}
}

// postUrgencyInventory posts a fixture with its device identity and app list
// replaced, then runs the extractor.
func postUrgencyInventory(t *testing.T, tn urgencyTenant, fixture, hwUUID string, apps []map[string]any) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", fixture), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tn.id
	p["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	device := p["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2093" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2093-" + strings.ToLower(hwUUID[:8])
	p["apps"] = apps
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, tn.secret)
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
}

// macApp is one app as the macOS collector reports it.
func urgMacApp(name, bundle, version, team, signer string, notarized bool) map[string]any {
	app := map[string]any{"name": name, "version": version, "path": "/Applications/" + name + ".app",
		"team_id": team, "signed_by": signer, "notarized": notarized}
	// bundle_id is a required key in a macOS payload; an empty one is how a
	// bundle with no CFBundleIdentifier arrives.
	app["bundle_id"] = bundle
	if bundle != "" {
		app["identifier"] = bundle
	}
	return app
}

// urgMacAppStatus is one app as a PAT-2112 macOS collector reports it, with
// signing_status and notarization_status beside signed_by and notarized
// (true only when notarization_status is notarized).
func urgMacAppStatus(name, bundle, version, team, signer, signing, notarization string) map[string]any {
	app := urgMacApp(name, bundle, version, team, signer, notarization == "notarized")
	app["signing_status"] = signing
	app["notarization_status"] = notarization
	return app
}

// winApp is one app as the Windows collector reports it: no signing fields.
func urgWinApp(name, identifier, version, publisher string) map[string]any {
	// identifier is a required key; empty is how an entry with no uninstall
	// key identity arrives.
	app := map[string]any{"name": name, "version": version, "architecture": "x86_64", "identifier": identifier}
	if publisher != "" {
		app["publisher"] = publisher
	}
	return app
}

func urgencyFeedEntry(t *testing.T, cveID, vendor, product, vEndExcl, severity string) {
	t.Helper()
	ranges, _ := json.Marshal([]map[string]string{{"vendor": vendor, "product": product, "version_end_excluding": vEndExcl}})
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity, cpe_patterns, cpe_ranges)
		VALUES ($1, 'PAT-2093 integration test vulnerability', 'nvd', 5.0, $2, $3, $4)
	`, cveID, severity, []string{strings.ToLower(vendor + ":" + product)}, string(ranges)); err != nil {
		t.Fatalf("seed feed entry %s: %v", cveID, err)
	}
}

type urgencyReason struct {
	Code  string `json:"code"`
	Level string `json:"level"`
}

type urgencyProduct struct {
	Name          string          `json:"name"`
	Platform      string          `json:"platform"`
	Identifier    *string         `json:"identifier"`
	TeamID        *string         `json:"team_id"`
	ProductKey    *string         `json:"product_key"`
	IdentityBasis string          `json:"identity_basis"`
	ApprovalState string          `json:"approval_state"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	DeviceCount   int             `json:"device_count"`
	Urgency       string          `json:"urgency"`
	Reasons       []urgencyReason `json:"reasons"`
	Trust         struct {
		Trusted        bool    `json:"trusted"`
		Signing        string  `json:"signing"`
		Notarisation   string  `json:"notarisation"`
		Publisher      *string `json:"publisher"`
		PublisherBasis string  `json:"publisher_basis"`
	} `json:"trust"`
	CVE struct {
		State        string          `json:"state"`
		FindingCount *int            `json:"finding_count"`
		Severity     *map[string]int `json:"severity"`
	} `json:"cve"`
}

type urgencyBlock struct {
	Since        time.Time        `json:"since"`
	SinceBasis   string           `json:"since_basis"`
	WindowDays   int              `json:"window_days"`
	LastReviewAt *time.Time       `json:"last_review_at"`
	Total        int              `json:"total"`
	Counts       map[string]int   `json:"counts"`
	Excluded     map[string]int   `json:"excluded"`
	Truncated    bool             `json:"truncated"`
	Limit        int              `json:"limit"`
	Products     []urgencyProduct `json:"products"`
}

func fetchUrgency(t *testing.T, tn urgencyTenant) urgencyBlock {
	t.Helper()
	var out struct {
		NewSoftware *urgencyBlock `json:"new_software"`
	}
	getJSON(t, "/v1/portal/overview", tn.viewerToken, &out)
	if out.NewSoftware == nil {
		t.Fatal("overview new_software is null")
	}
	return *out.NewSoftware
}

func urgencyByName(b urgencyBlock) map[string]urgencyProduct {
	m := map[string]urgencyProduct{}
	for _, p := range b.Products {
		m[p.Name] = p
	}
	return m
}

func hasUrgencyReason(p urgencyProduct, code string) bool {
	for _, r := range p.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func TestNewSoftwareUrgencyRulesMacAndWindows(t *testing.T) {
	ctx := context.Background()
	tn := newUrgencyTenant(t, "rules")
	sfx := randomHex(4)
	team := func(tag string) string { return strings.ToUpper(tag + randomHex(4))[:10] }
	approvedTeam, teamNotNot, teamMed, teamMedCVE, teamCrit := team("TA"), team("TB"), team("TC"), team("TD"), team("TE")
	teamNotUnknown, teamLegacyNot := team("TF"), team("TG")
	devID := func(tm string) string { return "Developer ID Application: Example " + tm + " (" + tm + ")" }
	name := func(s string) string { return "Urg " + s + " " + sfx }
	bundle := func(s string) string { return "com.pat2093." + s + "." + sfx }

	// Operator policies, written before anything is installed so no approval
	// decision (and so no "last review") exists: the window stays 14 days.
	for _, pol := range []struct {
		team, bundle, policy string
	}{
		{approvedTeam, bundle("base"), "approved"}, // the publisher's other, approved product
		{"", bundle("approvedapp"), "approved"},
		{"", bundle("ignoredapp"), "unmanaged"},
	} {
		var teamArg any
		if pol.team != "" {
			teamArg = pol.team
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, platform, policy, enforcement_tier)
			VALUES ($1::uuid, $2, $3, 'macos', $4, 'report_deploy')`, tn.id, teamArg, pol.bundle, pol.policy); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}

	// CVE mappings: crit and medcve match a CVE at 1.5; medium and low are
	// mapped with no CVE, so they are assessed clean; notassessed is unmapped.
	vendor := "pat2093v" + sfx
	for _, s := range []string{"crit", "medcve", "medium", "low", "winpub", "xunsigned", "adhoc", "notunknown", "legacynot"} {
		seedCVEMapping(t, name(s), vendor, s)
	}
	urgencyFeedEntry(t, "CVE-2099-"+sfx+"1", vendor, "crit", "2.0", "CRITICAL")
	urgencyFeedEntry(t, "CVE-2099-"+sfx+"2", vendor, "medcve", "2.0", "MEDIUM")
	drainCVEQueue(t)

	// "notarized" is confirmed notarisation (PAT-2112): these are Developer
	// ID apps as a PAT-2112 collector reports them.
	notarised := func(n, b, version, tm string) map[string]any {
		return urgMacAppStatus(n, b, version, tm, devID(tm), "signed", "notarized")
	}
	macApps := []map[string]any{
		notarised(name("crit"), bundle("crit"), "1.5", teamCrit),
		// An agent before PAT-2112: "Unknown" is not evidence of unsigned.
		urgMacApp(name("unsigned"), bundle("unsigned"), "1.0", "Unknown", "Unknown", false),
		urgMacApp(name("unident"), "", "1.0", "Unknown", "Unknown", false),
		urgMacApp(name("notnot"), bundle("notnot"), "1.0", teamNotNot, devID(teamNotNot), false),
		notarised(name("medcve"), bundle("medcve"), "1.5", teamMedCVE),
		notarised(name("notassessed"), bundle("notassessed"), "1.0", approvedTeam),
		notarised(name("medium"), bundle("medium"), "1.0", teamMed),
		notarised(name("low"), bundle("low"), "1.0", approvedTeam),
		// PAT-2112: the collector's explicit signing and notarisation evidence.
		urgMacAppStatus(name("xunsigned"), bundle("xunsigned"), "1.0", "Unknown", "Unknown", "unsigned", "not_notarized"),
		urgMacAppStatus(name("adhoc"), bundle("adhoc"), "1.0", "not set", "Unknown", "adhoc", "not_notarized"),
		urgMacAppStatus(name("cserror"), bundle("cserror"), "1.0", "Unknown", "Unknown", "error", "unknown"),
		urgMacAppStatus(name("notunknown"), bundle("notunknown"), "1.0", teamNotUnknown, devID(teamNotUnknown), "signed", "unknown"),
		// The legacy boolean alone, with no notarization_status, confirms nothing.
		urgMacApp(name("legacynot"), bundle("legacynot"), "1.0", teamLegacyNot, devID(teamLegacyNot), true),
		urgMacApp(name("approvedapp"), bundle("approvedapp"), "1.0", "Unknown", "Unknown", false),
		urgMacApp(name("ignoredapp"), bundle("ignoredapp"), "1.0", "Unknown", "Unknown", false),
		// Patched's own menu bar app: unsigned today, so it would be listed
		// if it were not excluded.
		urgMacApp("Patched", "im.patched.updater.menubar", "1.0", "Unknown", "Unknown", false),
	}
	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("aa"+randomHex(3)+"-1111-2222-3333-444455556666"), macApps)
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("bb"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinApp(name("winpub"), "{"+strings.ToUpper(randomHex(8))+"-0000}", "1.0", "Example Corporation"),
			urgWinApp(name("winnopub"), "{"+strings.ToUpper(randomHex(8))+"-0001}", "1.0", ""),
			urgWinApp(name("winident"), "", "1.0", ""),
			urgWinApp("Patched Agent", "{"+strings.ToUpper(randomHex(8))+"-0002}", "1.0", "Patched"),
		})
	drainCVEQueue(t)

	// An operator un-approves the seeded agent policy: the agent must still be
	// absent, so its exclusion is not just its approval.
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_app_policies SET policy = 'unapproved'
		WHERE tenant_id = $1::uuid AND notes LIKE 'PAT-1318%'`, tn.id); err != nil {
		t.Fatalf("unapprove agent policy: %v", err)
	}

	b := fetchUrgency(t, tn)
	if b.SinceBasis != "default_window" || b.WindowDays != 14 || b.LastReviewAt != nil {
		t.Fatalf("window = %s/%d/%v, want default_window/14/null", b.SinceBasis, b.WindowDays, b.LastReviewAt)
	}
	got := urgencyByName(b)

	want := map[string]struct{ level, reason string }{
		name("crit"):        {"critical", "cve_critical_or_high"},
		name("unsigned"):    {"high", "signing_unknown"},
		name("unident"):     {"critical", "unidentifiable"},
		name("notnot"):      {"high", "notarisation_not_confirmed"},
		name("medcve"):      {"high", "cve_medium"},
		name("notassessed"): {"not_assessed", "cve_not_assessed"},
		name("medium"):      {"medium", "trusted_publisher_no_known_cves"},
		name("low"):         {"low", "publisher_has_approved_products"},
		name("xunsigned"):   {"critical", "unsigned"},
		name("adhoc"):       {"high", "adhoc_signed"},
		name("cserror"):     {"high", "signing_unknown"},
		name("notunknown"):  {"high", "notarisation_not_confirmed"},
		name("legacynot"):   {"high", "notarisation_not_confirmed"},
		name("winpub"):      {"high", "authenticode_not_collected"},
		name("winnopub"):    {"high", "unknown_publisher"},
		name("winident"):    {"critical", "unidentifiable"},
	}
	for n, w := range want {
		p, ok := got[n]
		if !ok {
			t.Errorf("%s absent from new_software", n)
			continue
		}
		if p.Urgency != w.level || !hasUrgencyReason(p, w.reason) {
			t.Errorf("%s: urgency %q reasons %+v, want %q with %q", n, p.Urgency, p.Reasons, w.level, w.reason)
		}
	}
	for _, n := range []string{name("approvedapp"), name("ignoredapp"), "Patched", "Patched Agent"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s is listed; approved, ignored and Patched's own agent are excluded", n)
		}
	}
	if b.Excluded["approved"] < 1 || b.Excluded["ignored"] < 1 || b.Excluded["patched_agent"] != 2 {
		t.Errorf("excluded = %v, want approved>=1 ignored>=1 patched_agent=2", b.Excluded)
	}

	// The unassessed product is trusted and its publisher is approved, yet it
	// never reads as low or as "no CVEs".
	na := got[name("notassessed")]
	if !na.Trust.Trusted || na.CVE.State != "not_assessed" || na.CVE.FindingCount != nil || na.CVE.Severity != nil {
		t.Errorf("not assessed product: trust %+v cve %+v, want trusted with a null CVE statement", na.Trust, na.CVE)
	}
	crit := got[name("crit")]
	if crit.CVE.State != "assessed" || crit.CVE.Severity == nil || (*crit.CVE.Severity)["critical"] != 1 {
		t.Errorf("crit cve = %+v, want assessed with one critical", crit.CVE)
	}
	low := got[name("low")]
	if low.CVE.State != "assessed" || low.CVE.FindingCount == nil || *low.CVE.FindingCount != 0 {
		t.Errorf("low cve = %+v, want assessed with zero findings", low.CVE)
	}

	// Identity fields match the approval write (PAT-2104).
	if low.Identifier == nil || *low.Identifier != bundle("low") || low.TeamID == nil || *low.TeamID != approvedTeam ||
		low.ProductKey == nil || *low.ProductKey != "application:macos:"+bundle("low")+":"+approvedTeam {
		t.Errorf("low identity = %v/%v/%v", low.Identifier, low.TeamID, low.ProductKey)
	}
	unsigned := got[name("unsigned")]
	if unsigned.TeamID != nil || unsigned.ProductKey == nil || *unsigned.ProductKey != "application:macos:"+bundle("unsigned") {
		t.Errorf("unsigned identity = %v/%v", unsigned.TeamID, unsigned.ProductKey)
	}
	// The collector's "Unknown" signer is not evidence of unsigned (PAT-2112).
	if unsigned.Trust.Signing != "unknown" || hasUrgencyReason(unsigned, "unsigned") {
		t.Errorf("unsigned trust = %+v", unsigned.Trust)
	}
	// PAT-2112: each explicit signing_status gives its own verdict, and a
	// notarised Developer ID product with a clean CVE state is trusted.
	for n, want := range map[string]struct{ signing, notarisation string }{
		name("xunsigned"):  {"unsigned", "unknown"},
		name("adhoc"):      {"adhoc", "unknown"},
		name("cserror"):    {"unknown", "unknown"},
		name("notunknown"): {"signed", "not_confirmed"},
		name("legacynot"):  {"signed", "not_confirmed"},
		name("medium"):     {"signed", "confirmed"},
	} {
		p := got[n]
		if p.Trust.Signing != want.signing || p.Trust.Notarisation != want.notarisation {
			t.Errorf("%s trust = %+v, want signing %q notarisation %q", n, p.Trust, want.signing, want.notarisation)
		}
	}
	if p := got[name("xunsigned")]; hasUrgencyReason(p, "signing_unknown") {
		t.Errorf("explicitly unsigned product also reads signing_unknown: %+v", p.Reasons)
	}
	if p := got[name("adhoc")]; hasUrgencyReason(p, "signing_unknown") || hasUrgencyReason(p, "unsigned") {
		t.Errorf("ad hoc product reasons = %+v, want adhoc_signed alone for signing", p.Reasons)
	}
	if p := got[name("medium")]; !p.Trust.Trusted {
		t.Errorf("notarised Developer ID medium product is not trusted: %+v", p.Trust)
	}

	winpub := got[name("winpub")]
	if winpub.TeamID != nil || winpub.ProductKey == nil || !strings.HasPrefix(*winpub.ProductKey, "application:windows:") ||
		winpub.Trust.Signing != "not_collected" || winpub.Trust.PublisherBasis != "registry_publisher_unverified" || winpub.Trust.Trusted {
		t.Errorf("winpub = %+v", winpub)
	}
	// Windows is never trusted, so its clean CVE state cannot make it medium.
	if winpub.CVE.State != "assessed" {
		t.Errorf("winpub cve = %+v, want assessed", winpub.CVE)
	}
	ident := got[name("unident")]
	if ident.Identifier != nil || ident.ProductKey != nil || ident.IdentityBasis != "name_only" {
		t.Errorf("unidentifiable identity = %v/%v/%s", ident.Identifier, ident.ProductKey, ident.IdentityBasis)
	}

	// Counts cover every classified product, ordering is by urgency then
	// newest first, and the list is bounded.
	sum := 0
	for _, level := range []string{"critical", "high", "not_assessed", "medium", "low"} {
		sum += b.Counts[level]
	}
	if sum != b.Total || b.Total != len(b.Products) || b.Limit != 50 {
		t.Errorf("counts %v sum %d, total %d, listed %d, limit %d", b.Counts, sum, b.Total, len(b.Products), b.Limit)
	}
	if b.Counts["critical"] != 4 || b.Counts["not_assessed"] != 1 || b.Counts["medium"] != 1 || b.Counts["low"] != 1 {
		t.Errorf("counts = %v", b.Counts)
	}
	rank := map[string]int{"critical": 5, "high": 4, "not_assessed": 3, "medium": 2, "low": 1}
	for i := 1; i < len(b.Products); i++ {
		if rank[b.Products[i].Urgency] > rank[b.Products[i-1].Urgency] {
			t.Fatalf("products not ordered by urgency at %d: %s after %s", i, b.Products[i].Urgency, b.Products[i-1].Urgency)
		}
	}
}

// The window is 14 days, or since the tenant's last review when that is more
// recent; another tenant's software never appears.
func TestNewSoftwareUrgencyWindowAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	tn := newUrgencyTenant(t, "window")
	other := newUrgencyTenant(t, "other")
	sfx := randomHex(4)
	name := func(s string) string { return "Urg Win " + s + " " + sfx }
	bundle := func(s string) string { return "com.pat2093.window." + s + "." + sfx }

	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("cc"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgMacApp(name("old"), bundle("old"), "1.0", "Unknown", "Unknown", false),
			urgMacApp(name("mid"), bundle("mid"), "1.0", "Unknown", "Unknown", false),
			urgMacApp(name("recent"), bundle("recent"), "1.0", "Unknown", "Unknown", false),
		})
	postUrgencyInventory(t, other, "full.json", strings.ToUpper("dd"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{urgMacApp(name("othertenant"), bundle("othertenant"), "1.0", "Unknown", "Unknown", false)})

	backdate := func(ident string, age time.Duration) {
		t.Helper()
		if _, err := env.pool.Exec(ctx, `
			UPDATE software_installations SET first_seen_at = now() - $3::interval
			WHERE tenant_id = $1::uuid AND identity_value_normalized = $2`,
			tn.id, ident, strconv.Itoa(int(age.Hours()))+" hours"); err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}
	backdate(bundle("old"), 20*24*time.Hour)
	backdate(bundle("mid"), 5*24*time.Hour)

	b := fetchUrgency(t, tn)
	got := urgencyByName(b)
	if b.SinceBasis != "default_window" {
		t.Fatalf("since_basis = %q, want default_window", b.SinceBasis)
	}
	if _, ok := got[name("old")]; ok {
		t.Error("a product first seen 20 days ago is inside the 14-day window")
	}
	for _, n := range []string{name("mid"), name("recent")} {
		if _, ok := got[n]; !ok {
			t.Errorf("%s missing from the 14-day window", n)
		}
	}
	if _, ok := got[name("othertenant")]; ok {
		t.Error("another tenant's product is listed")
	}
	otherBlock := fetchUrgency(t, other)
	if len(otherBlock.Products) != 1 || otherBlock.Products[0].Name != name("othertenant") || otherBlock.Total != 1 {
		t.Errorf("other tenant sees %+v, want only its own product", otherBlock.Products)
	}

	// A review two days ago is more recent than the 14-day start: the window
	// shortens to it, and the product first seen five days ago drops out.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO software_approval_decisions
		    (tenant_id, batch_id, product_type, product_key, platform, identifier, previous_state, new_state, actor_email, decided_at)
		VALUES ($1::uuid, gen_random_uuid(), 'application', $2, 'macos', $3, 'unreviewed', 'unapproved', 'admin@pat2093.example',
		        now() - interval '2 days')`, tn.id, "application:macos:"+bundle("elsewhere"), bundle("elsewhere")); err != nil {
		t.Fatalf("seed decision: %v", err)
	}
	b = fetchUrgency(t, tn)
	got = urgencyByName(b)
	if b.SinceBasis != "last_review" || b.LastReviewAt == nil || !b.Since.Equal(*b.LastReviewAt) {
		t.Fatalf("window = %s since %v last review %v, want last_review", b.SinceBasis, b.Since, b.LastReviewAt)
	}
	if _, ok := got[name("mid")]; ok {
		t.Error("a product first seen before the last review is still listed")
	}
	if _, ok := got[name("recent")]; !ok {
		t.Error("a product first seen after the last review is missing")
	}
}

// urgWinAppEvidence is a Windows app carrying the agent's per-installation
// Authenticode evidence (updater AppInstallationEvidence), as the agent sends
// it for a reviewed evidence target. signer is omitted when empty.
func urgWinAppEvidence(name, identifier, version, publisher, state, signer string) map[string]any {
	app := urgWinApp(name, identifier, version, publisher)
	ev := map[string]any{
		"catalogue_version": "2026.09.20.1", "delivery_version": 1, "content_hash": strings.Repeat("a", 64),
		"collection_status": "partial", "collected_at": time.Now().UTC().Format(time.RFC3339),
		"source": "windows_authenticode_offline", "signature_state": state, "errors": []string{},
	}
	if signer != "" {
		ev["signer"] = signer
		ev["collection_status"] = "complete"
	}
	app["installation_evidence"] = ev
	return app
}

// PAT-2113: Windows urgency from the agent's Authenticode signature_state,
// end to end through ingestion, the extractor and the overview.
func TestNewSoftwareUrgencyWindowsAuthenticode(t *testing.T) {
	tn := newUrgencyTenant(t, "authenticode")
	sfx := randomHex(4)
	name := func(s string) string { return "Urg Win " + s + " " + sfx }
	guid := func(n int) string { return fmt.Sprintf("{%s-%04d}", strings.ToUpper(randomHex(8)), n) }
	signer := "CN=Example " + sfx + " Ltd, O=Example " + sfx + " Ltd, C=GB"

	vendor := "pat2113v" + sfx
	for _, s := range []string{"valid", "validcve", "invalid", "unknown", "absent"} {
		seedCVEMapping(t, name(s), vendor, s)
	}
	urgencyFeedEntry(t, "CVE-2099-"+sfx+"3", vendor, "validcve", "2.0", "CRITICAL")
	drainCVEQueue(t)

	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("cc"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppEvidence(name("valid"), guid(1), "1.0", "Registry Claim Ltd", "valid", signer),
			urgWinAppEvidence(name("validcve"), guid(2), "1.5", "Registry Claim Ltd", "valid", signer),
			urgWinAppEvidence(name("invalid"), guid(3), "1.0", "Registry Claim Ltd", "invalid", ""),
			urgWinAppEvidence(name("unknown"), guid(4), "1.0", "Registry Claim Ltd", "unknown", ""),
			urgWinApp(name("absent"), guid(5), "1.0", "Registry Claim Ltd"),
		})
	drainCVEQueue(t)

	got := urgencyByName(fetchUrgency(t, tn))
	for n, w := range map[string]struct {
		level, reason, signing, basis string
		trusted                       bool
	}{
		name("valid"):    {"medium", "trusted_publisher_no_known_cves", "signed", "authenticode_signer", true},
		name("validcve"): {"critical", "cve_critical_or_high", "signed", "authenticode_signer", true},
		name("invalid"):  {"high", "authenticode_invalid", "invalid", "registry_publisher_unverified", false},
		name("unknown"):  {"high", "authenticode_not_collected", "unknown", "registry_publisher_unverified", false},
		name("absent"):   {"high", "authenticode_not_collected", "not_collected", "registry_publisher_unverified", false},
	} {
		p, ok := got[n]
		if !ok {
			t.Errorf("%s absent from new_software", n)
			continue
		}
		if p.Urgency != w.level || !hasUrgencyReason(p, w.reason) {
			t.Errorf("%s: urgency %q reasons %+v, want %q with %q", n, p.Urgency, p.Reasons, w.level, w.reason)
		}
		if p.Trust.Signing != w.signing || p.Trust.PublisherBasis != w.basis || p.Trust.Trusted != w.trusted {
			t.Errorf("%s: trust %+v, want signing %q basis %q trusted %v", n, p.Trust, w.signing, w.basis, w.trusted)
		}
		if p.Trust.Trusted && (p.Trust.Publisher == nil || *p.Trust.Publisher != signer) {
			t.Errorf("%s: publisher %v, want the Authenticode signer, never the registry claim", n, p.Trust.Publisher)
		}
	}
	if p := got[name("valid")]; hasUrgencyReason(p, "authenticode_not_collected") || p.Urgency == "low" {
		t.Errorf("valid product = %+v", p)
	}
	if p := got[name("invalid")]; hasUrgencyReason(p, "trusted_publisher_no_known_cves") {
		t.Errorf("invalid product reads trusted: %+v", p.Reasons)
	}

	var stored []string
	rows, err := env.pool.Query(context.Background(), `
		SELECT o.observed_name || '=' || COALESCE(o.observed_signature_state, 'NULL') || '/' ||
		       COALESCE(o.observed_authenticode_signer, 'NULL')
		FROM software_observations o WHERE o.tenant_id = $1::uuid ORDER BY 1`, tn.id)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, s)
	}
	rows.Close()
	want := []string{
		name("absent") + "=NULL/NULL",
		name("invalid") + "=invalid/NULL",
		name("unknown") + "=unknown/NULL",
		name("valid") + "=valid/" + signer,
		name("validcve") + "=valid/" + signer,
	}
	// Sorted in Go: ORDER BY follows the database collation, and under
	// en_US the random name suffix can reorder "valid" and "validcve".
	sort.Strings(stored)
	sort.Strings(want)
	if strings.Join(stored, "\n") != strings.Join(want, "\n") {
		t.Errorf("stored observations:\n%s\nwant:\n%s", strings.Join(stored, "\n"), strings.Join(want, "\n"))
	}
}

// PAT-2117: the two newest macOS signing_status values, untrusted and
// invalid, round-trip through ingestion into the immutable
// software_observations evidence and are read back correctly by new software
// urgency. Neither ever counts as trusted or sets a publisher basis, even
// with a Developer-ID-looking signer and a Team ID, and mixing an untrusted
// installation with a properly signed, notarised installation of the same
// product still reads as the worst instance, not medium or low.
func TestNewSoftwareUrgencyMacUntrustedAndInvalidSigning(t *testing.T) {
	tn := newUrgencyTenant(t, "untrustinvalid")
	sfx := randomHex(4)
	name := func(s string) string { return "Urg PAT2117 " + s + " " + sfx }
	bundle := func(s string) string { return "com.pat2117." + s + "." + sfx }
	team := func(tag string) string { return strings.ToUpper(tag + randomHex(4))[:10] }
	devID := func(tm string) string { return "Developer ID Application: Example " + tm + " (" + tm + ")" }

	teamUntrusted, teamInvalid, teamMixed := team("TU"), team("TI"), team("TM")

	untrustedApp := urgMacAppStatus(name("untrusted"), bundle("untrusted"), "1.0",
		teamUntrusted, devID(teamUntrusted), "untrusted", "not_notarized")
	invalidApp := urgMacAppStatus(name("invalid"), bundle("invalid"), "1.0",
		teamInvalid, devID(teamInvalid), "invalid", "unknown")
	// Same product (same bundle id), one installation untrusted and one
	// properly signed and notarised: worst instance wins for the product.
	mixedUntrustedInstall := urgMacAppStatus(name("mixed"), bundle("mixed"), "1.0",
		teamMixed, devID(teamMixed), "untrusted", "not_notarized")
	mixedSignedInstall := urgMacAppStatus(name("mixed"), bundle("mixed"), "1.0",
		teamMixed, devID(teamMixed), "signed", "notarized")

	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("dd"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{untrustedApp, invalidApp, mixedUntrustedInstall})
	postUrgencyInventory(t, tn, "full.json", strings.ToUpper("ee"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{mixedSignedInstall})

	got := urgencyByName(fetchUrgency(t, tn))
	for n, w := range map[string]struct {
		level, reason, signing string
		trusted                bool
	}{
		name("untrusted"): {"high", "untrusted_signer", "untrusted", false},
		name("invalid"):   {"high", "signature_invalid", "invalid", false},
		name("mixed"):     {"high", "untrusted_signer", "untrusted", false},
	} {
		p, ok := got[n]
		if !ok {
			t.Errorf("%s absent from new_software", n)
			continue
		}
		if p.Urgency != w.level || !hasUrgencyReason(p, w.reason) {
			t.Errorf("%s: urgency %q reasons %+v, want %q with %q", n, p.Urgency, p.Reasons, w.level, w.reason)
		}
		if p.Trust.Signing != w.signing || p.Trust.Trusted != w.trusted || p.Trust.PublisherBasis != "none" {
			t.Errorf("%s: trust %+v, want signing %q trusted %v basis none", n, p.Trust, w.signing, w.trusted)
		}
		if p.Trust.Publisher != nil {
			t.Errorf("%s: publisher %v, want nil -- an untrusted or invalid signature never sets a publisher basis",
				n, *p.Trust.Publisher)
		}
	}
	if p := got[name("untrusted")]; p.Urgency == "low" || p.Urgency == "medium" || hasUrgencyReason(p, "trusted_publisher_no_known_cves") {
		t.Errorf("untrusted product reads trusted: %+v", p)
	}
	if p := got[name("mixed")]; p.Urgency == "low" || p.Urgency == "medium" {
		t.Errorf("mixed untrusted+signed product = %+v, want high (worst instance wins)", p)
	}

	// The immutable evidence stored the collector's own values verbatim.
	var stored []string
	rows, err := env.pool.Query(context.Background(), `
		SELECT o.observed_name || '=' || COALESCE(o.observed_signing_status, 'NULL') || '/' ||
		       COALESCE(o.observed_notarization_status, 'NULL')
		FROM software_observations o WHERE o.tenant_id = $1::uuid
		  AND o.observed_name IN ($2, $3) ORDER BY 1`, tn.id, name("untrusted"), name("invalid"))
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, s)
	}
	rows.Close()
	want := []string{
		name("invalid") + "=invalid/unknown",
		name("untrusted") + "=untrusted/not_notarized",
	}
	// Sorted in Go: ORDER BY follows the database collation, and under
	// en_US the random name suffix can reorder "valid" and "validcve".
	sort.Strings(stored)
	sort.Strings(want)
	if strings.Join(stored, "\n") != strings.Join(want, "\n") {
		t.Errorf("stored observations:\n%s\nwant:\n%s", strings.Join(stored, "\n"), strings.Join(want, "\n"))
	}
}

// urgWinAppPinned is urgWinAppEvidence as an updater #668 agent sends it
// (PAT-2116): executable_resolution on every row, and beside valid the
// pinnable publisher (signer and root thumbprints, issuer, root kind).
func urgWinAppPinned(name, identifier, state, signer, root, kind string) map[string]any {
	app := urgWinAppEvidence(name, identifier, "1.0", "Registry Claim Ltd", state, signer)
	ev := app["installation_evidence"].(map[string]any)
	for _, k := range []string{"catalogue_version", "delivery_version", "content_hash"} {
		delete(ev, k)
	}
	ev["executable_resolution"] = "display_icon"
	if state == "valid" {
		ev["signer_thumbprint"] = strings.Repeat("1", 64)
		ev["issuer"] = "CN=Example Code Signing CA, O=Example CA"
		ev["root_thumbprint"] = root
		ev["root_kind"] = kind
	}
	return app
}

// PAT-2116: unsigned and the Authenticode root, end to end through
// ingestion, the extractor, software_observations and the overview.
func TestNewSoftwareUrgencyWindowsAuthenticodePublisher(t *testing.T) {
	tn := newUrgencyTenant(t, "authenticode-publisher")
	sfx := randomHex(4)
	name := func(s string) string { return "Urg Win Pin " + s + " " + sfx }
	guid := func(n int) string { return fmt.Sprintf("{%s-%04d}", strings.ToUpper(randomHex(8)), n) }
	signer := "CN=Example " + sfx + " Ltd, O=Example " + sfx + " Ltd, C=GB"
	msLooking := "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
	rootA, rootB := strings.Repeat("a", 64), strings.Repeat("b", 64)

	vendor := "pat2116v" + sfx
	products := []string{"public", "microsoft", "enterprise", "unsigned", "legacy", "rootsplit", "futurekind"}
	for _, s := range products {
		seedCVEMapping(t, name(s), vendor, s)
	}
	drainCVEQueue(t)

	// Two devices, so the root-disagreement product has two installations.
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("dd"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppPinned(name("public"), guid(1), "valid", signer, rootA, "public"),
			urgWinAppPinned(name("microsoft"), guid(2), "valid", signer, rootA, "microsoft"),
			urgWinAppPinned(name("enterprise"), guid(3), "valid", msLooking, rootB, "enterprise"),
			urgWinAppPinned(name("unsigned"), guid(4), "unsigned", "", "", ""),
			urgWinAppEvidence(name("legacy"), guid(5), "1.0", "Registry Claim Ltd", "valid", signer),
			urgWinAppPinned(name("rootsplit"), "{PAT2116-ROOTSPLIT-"+sfx+"}", "valid", signer, rootA, "public"),
			urgWinAppPinned(name("futurekind"), guid(7), "valid", signer, rootA, "some_future_kind"),
		})
	postUrgencyInventory(t, tn, "full-v3-windows.json", strings.ToUpper("ee"+randomHex(3)+"-1111-2222-3333-444455556666"),
		[]map[string]any{
			urgWinAppPinned(name("rootsplit"), "{PAT2116-ROOTSPLIT-"+sfx+"}", "valid", signer, rootB, "public"),
		})
	drainCVEQueue(t)

	got := urgencyByName(fetchUrgency(t, tn))
	for n, w := range map[string]struct {
		level, reason, signing, basis string
		trusted                       bool
	}{
		name("public"):     {"medium", "trusted_publisher_no_known_cves", "signed", "authenticode_signer", true},
		name("microsoft"):  {"medium", "trusted_publisher_no_known_cves", "signed", "authenticode_signer", true},
		name("enterprise"): {"high", "enterprise_root", "signed", "none", false},
		name("unsigned"):   {"critical", "unsigned", "unsigned", "registry_publisher_unverified", false},
		name("legacy"):     {"medium", "trusted_publisher_no_known_cves", "signed", "authenticode_signer", true},
		name("rootsplit"):  {"high", "unknown_publisher", "signed", "none", false},
		name("futurekind"): {"high", "unknown_publisher", "signed", "none", false},
	} {
		p, ok := got[n]
		if !ok {
			t.Errorf("%s absent from new_software", n)
			continue
		}
		if p.Urgency != w.level || !hasUrgencyReason(p, w.reason) {
			t.Errorf("%s: urgency %q reasons %+v, want %q with %q", n, p.Urgency, p.Reasons, w.level, w.reason)
		}
		if p.Trust.Signing != w.signing || p.Trust.PublisherBasis != w.basis || p.Trust.Trusted != w.trusted {
			t.Errorf("%s: trust %+v, want signing %q basis %q trusted %v", n, p.Trust, w.signing, w.basis, w.trusted)
		}
		if p.Urgency == "low" {
			t.Errorf("%s reached low", n)
		}
	}

	var stored []string
	rows, err := env.pool.Query(context.Background(), `
		SELECT o.observed_name || '=' || concat_ws('/',
		       COALESCE(o.observed_signature_state, 'NULL'),
		       COALESCE(o.observed_authenticode_signer_thumbprint, 'NULL'),
		       COALESCE(o.observed_authenticode_issuer, 'NULL'),
		       COALESCE(o.observed_authenticode_root_thumbprint, 'NULL'),
		       COALESCE(o.observed_authenticode_root_kind, 'NULL'),
		       COALESCE(o.observed_executable_resolution, 'NULL'))
		FROM software_observations o WHERE o.tenant_id = $1::uuid ORDER BY 1`, tn.id)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, s)
	}
	rows.Close()
	leaf, issuer := strings.Repeat("1", 64), "CN=Example Code Signing CA, O=Example CA"
	pinned := func(root, kind string) string {
		return "valid/" + leaf + "/" + issuer + "/" + root + "/" + kind + "/display_icon"
	}
	want := []string{
		name("enterprise") + "=" + pinned(rootB, "enterprise"),
		name("futurekind") + "=valid/" + leaf + "/" + issuer + "/" + rootA + "/NULL/display_icon",
		name("legacy") + "=valid/NULL/NULL/NULL/NULL/NULL",
		name("microsoft") + "=" + pinned(rootA, "microsoft"),
		name("public") + "=" + pinned(rootA, "public"),
		name("rootsplit") + "=" + pinned(rootA, "public"),
		name("rootsplit") + "=" + pinned(rootB, "public"),
		name("unsigned") + "=unsigned/NULL/NULL/NULL/NULL/display_icon",
	}
	// Sorted in Go: ORDER BY follows the database collation, and under
	// en_US the random name suffix can reorder "valid" and "validcve".
	sort.Strings(stored)
	sort.Strings(want)
	if strings.Join(stored, "\n") != strings.Join(want, "\n") {
		t.Errorf("stored observations:\n%s\nwant:\n%s", strings.Join(stored, "\n"), strings.Join(want, "\n"))
	}
}
