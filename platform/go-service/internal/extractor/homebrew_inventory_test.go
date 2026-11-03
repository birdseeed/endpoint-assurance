package extractor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

func TestDeriveHomebrewIdentityIsNamespacedAndNeverProductAuthority(t *testing.T) {
	core := deriveHomebrewIdentity(homebrewFormulaKind, "openssl@3", strp("homebrew/core"))
	thirdParty := deriveHomebrewIdentity(homebrewFormulaKind, "openssl@3", strp("acme/tools"))
	unknownTap := deriveHomebrewIdentity(homebrewFormulaKind, "openssl@3", nil)
	cask := deriveHomebrewIdentity(homebrewCaskKind, "openssl@3", strp("homebrew/core"))
	if core.Fingerprint == thirdParty.Fingerprint || core.Fingerprint == unknownTap.Fingerprint {
		t.Fatal("same formula name from different taps collapsed to one identity")
	}
	if core.Fingerprint == cask.Fingerprint {
		t.Fatal("formula and cask with the same name collapsed")
	}
	for _, id := range []observedSoftwareIdentity{core, thirdParty, unknownTap, cask} {
		if id.Confidence == "exact" || id.Confidence == "high" {
			t.Fatalf("package-namespace identity gained product authority: %#v", id)
		}
	}
	if unknownTap.Confidence != "low" || core.Confidence != "medium" {
		t.Fatalf("confidence core=%s unknownTap=%s", core.Confidence, unknownTap.Confidence)
	}
	if core.Companion != "homebrew/core" || core.Value != "openssl@3" {
		t.Fatalf("identity value/companion = %q/%q", core.Value, core.Companion)
	}
}

type homebrewTestDB struct {
	t        *testing.T
	ctx      context.Context
	tx       pgx.Tx
	tenantID string
	deviceID string
}

func openHomebrewTestDB(t *testing.T) *homebrewTestDB {
	t.Helper()
	return openHomebrewTestDBWith(t, nil)
}

// openHomebrewTestDBWith opens the test transaction on a pool whose
// connections carry tracer (nil for none), so a test can count statements.
func openHomebrewTestDBWith(t *testing.T, tracer pgx.QueryTracer) *homebrewTestDB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if tracer != nil {
		cfg.ConnConfig.Tracer = tracer
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	db := &homebrewTestDB{t: t, ctx: ctx, tx: tx}
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat2013-homebrew','\x00','\x00') RETURNING id::text
	`).Scan(&db.tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,'macOS','PAT2013-MAC')
		RETURNING id::text
	`, db.tenantID).Scan(&db.deviceID); err != nil {
		t.Fatal(err)
	}
	return db
}

// ingest runs the software inventory step for one payload at received.
func (db *homebrewTestDB) ingest(received time.Time, apps []appPart, hb *homebrewPart) {
	db.t.Helper()
	var id int64
	if err := db.tx.QueryRow(db.ctx, `
		INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
		VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
	`, db.tenantID, db.deviceID, received).Scan(&id); err != nil {
		db.t.Fatal(err)
	}
	p := &payload{
		SchemaVersion: 3, Platform: "macos", Agent: "pat2013", AgentVersion: "test",
		CollectedAt: received.Format(time.RFC3339), AppsPresent: apps != nil, Apps: apps, Homebrew: hb,
	}
	row := claimedRow{ID: id, ReceivedAt: received, TenantID: db.tenantID}
	if _, err := upsertSoftwareInventory(db.ctx, db.tx, row, db.deviceID, p, "macos"); err != nil {
		db.t.Fatalf("ingest at %s: %v", received, err)
	}
}

func (db *homebrewTestDB) int(query string, args ...any) int {
	db.t.Helper()
	var n int
	if err := db.tx.QueryRow(db.ctx, query, args...).Scan(&n); err != nil {
		db.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// activeBrew returns active Homebrew installation names keyed "kind:name".
func (db *homebrewTestDB) activeBrew() map[string]bool {
	db.t.Helper()
	rows, err := db.tx.Query(db.ctx, `
		SELECT identity_kind || ':' || identity_value_normalized
		FROM software_installations
		WHERE device_id = $1::uuid AND removed_at IS NULL
		  AND identity_kind IN ('homebrew_formula','homebrew_cask','homebrew_tap')
	`, db.deviceID)
	if err != nil {
		db.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			db.t.Fatal(err)
		}
		out[k] = true
	}
	return out
}

func (db *homebrewTestDB) state() (status string, authorityAt *time.Time) {
	db.t.Helper()
	if err := db.tx.QueryRow(db.ctx, `
		SELECT collection_status, authority_at FROM homebrew_device_state WHERE device_id = $1::uuid
	`, db.deviceID).Scan(&status, &authorityAt); err != nil {
		db.t.Fatal(err)
	}
	return status, authorityAt
}

func testFormula(name, version, tap string, onRequest bool) homebrewFormulaPart {
	return homebrewFormulaPart{
		Prefix: "/opt/homebrew", Name: name, Version: version, Tap: strp(tap),
		InstalledOnRequest: boolp(onRequest), InstalledAsDependency: boolp(!onRequest),
		InstalledAt: strp("2026-09-01T10:00:00Z"), RuntimeDependencies: []string{},
		Homepage: strp("https://example.test/" + name), SourceURL: strp("https://example.test/" + name + ".tar.gz"),
		OptLinked: boolp(true), ReceiptStatus: "read", FormulaFileStatus: "read",
	}
}

func testCask(token, appName string, appPath *string) homebrewCaskPart {
	return homebrewCaskPart{
		Prefix: "/opt/homebrew", Token: token, Version: strp("1.0"), VersionsOnDisk: []string{"1.0"},
		Tap: strp("homebrew/cask"), InstalledOnRequest: boolp(true), InstalledAt: strp("2026-09-01T10:00:00Z"),
		ReceiptStatus: "read", Apps: []homebrewCaskAppPart{{Name: appName, Path: appPath}},
	}
}

func testTap(name string) homebrewTapPart {
	return homebrewTapPart{Prefix: "/opt/homebrew", Name: name, Directory: name, ConfigStatus: "read"}
}

func testBlock(status string, formulae []homebrewFormulaPart, casks []homebrewCaskPart, taps []homebrewTapPart) *homebrewPart {
	return &homebrewPart{
		CollectionStatus: status, Truncated: boolp(status == "partial"),
		Prefixes: []homebrewPrefixPart{{Path: "/opt/homebrew", Owner: strp("alice"), CollectionStatus: "complete"}},
		Formulae: formulae, Casks: casks, Taps: taps, Issues: []homebrewIssuePart{},
	}
}

var firefoxApp = []appPart{{Name: "Firefox", Version: "143.0", Identifier: "org.mozilla.firefox",
	TeamID: "43AQ936H96", Path: "/Applications/Firefox.app"}}

// TestHomebrewStorageFollowsCollectionStatus walks one device through every
// collection_status and checks what each is allowed to write and close.
func TestHomebrewStorageFollowsCollectionStatus(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)

	// complete: everything stored, the homebrew scope granted.
	db.ingest(t0, firefoxApp, testBlock("complete",
		[]homebrewFormulaPart{
			testFormula("openssl@3", "3.5.1", "homebrew/core", true),
			testFormula("wget", "1.25.0", "homebrew/core", true),
			testFormula("acme-cli", "2.1.0", "acme/tools", true),
		},
		[]homebrewCaskPart{testCask("firefox", "Firefox.app", nil)},
		[]homebrewTapPart{testTap("acme/tools"), testTap("homebrew/core")}))
	if got := db.activeBrew(); len(got) != 6 {
		t.Fatalf("after complete: active brew = %v, want 6", got)
	}
	if n := db.int(`SELECT count(*) FROM homebrew_observation_details WHERE device_id=$1::uuid`, db.deviceID); n != 6 {
		t.Fatalf("detail rows = %d, want 6", n)
	}
	if n := db.int(`SELECT count(*) FROM software_inventory_runs WHERE device_id=$1::uuid
		AND authoritative_scopes @> ARRAY['all_software','homebrew']`, db.deviceID); n != 1 {
		t.Fatalf("complete run did not carry all_software+homebrew scopes")
	}
	if n := db.int(`SELECT count(*) FROM software_observation_resolutions r
		JOIN software_observations so ON so.id = r.observation_id
		WHERE so.device_id=$1::uuid AND so.identity_kind LIKE 'homebrew_%' AND r.resolution_state <> 'unresolved'`, db.deviceID); n != 0 {
		t.Fatalf("%d Homebrew observations resolved to a product without a reviewed alias", n)
	}
	if status, auth := db.state(); status != "complete" || auth == nil || !auth.Equal(t0) {
		t.Fatalf("state after complete = %s/%v", status, auth)
	}

	// partial: stores what was sent, closes nothing, authority unchanged.
	t1 := t0.Add(time.Hour)
	db.ingest(t1, firefoxApp, testBlock("partial",
		[]homebrewFormulaPart{testFormula("openssl@3", "3.5.2", "homebrew/core", true)}, nil, nil))
	if got := db.activeBrew(); len(got) != 6 {
		t.Fatalf("partial pruned: active brew = %v", got)
	}
	if status, auth := db.state(); status != "partial" || !auth.Equal(t0) {
		t.Fatalf("state after partial = %s/%v, authority must stay %v", status, auth, t0)
	}

	// failed: no package rows, status recorded, nothing closed.
	before := db.int(`SELECT count(*) FROM software_observations WHERE device_id=$1::uuid AND identity_kind LIKE 'homebrew_%'`, db.deviceID)
	t2 := t1.Add(time.Hour)
	db.ingest(t2, firefoxApp, &homebrewPart{CollectionStatus: "failed"})
	if after := db.int(`SELECT count(*) FROM software_observations WHERE device_id=$1::uuid AND identity_kind LIKE 'homebrew_%'`, db.deviceID); after != before {
		t.Fatalf("failed wrote %d Homebrew observations", after-before)
	}
	if got := db.activeBrew(); len(got) != 6 {
		t.Fatalf("failed closed installations: %v", got)
	}
	if status, auth := db.state(); status != "failed" || !auth.Equal(t0) {
		t.Fatalf("state after failed = %s/%v", status, auth)
	}

	// An agent that stops sending the block (apps only) closes no Homebrew
	// installation: the apps all_software scope is not Homebrew authority.
	t3 := t2.Add(time.Hour)
	db.ingest(t3, firefoxApp, nil)
	if got := db.activeBrew(); len(got) != 6 {
		t.Fatalf("apps-only payload closed Homebrew installations: %v", got)
	}
	if status, _ := db.state(); status != "failed" {
		t.Fatalf("absent block changed state to %s", status)
	}

	// complete again: closes only what it no longer reports.
	t4 := t3.Add(time.Hour)
	db.ingest(t4, firefoxApp, testBlock("complete",
		[]homebrewFormulaPart{testFormula("openssl@3", "3.5.2", "homebrew/core", true)},
		[]homebrewCaskPart{testCask("firefox", "Firefox.app", nil)},
		[]homebrewTapPart{testTap("homebrew/core")}))
	got := db.activeBrew()
	want := map[string]bool{"homebrew_formula:openssl@3": true, "homebrew_cask:firefox": true, "homebrew_tap:homebrew/core": true}
	if len(got) != len(want) {
		t.Fatalf("after second complete: active = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("after second complete: %s missing from %v", k, got)
		}
	}
	// The Homebrew scope never closes an application.
	if n := db.int(`SELECT count(*) FROM software_installations WHERE device_id=$1::uuid
		AND identity_kind = 'macos_bundle_team' AND removed_at IS NULL`, db.deviceID); n != 1 {
		t.Fatalf("Homebrew authority closed the Firefox app installation")
	}

	// An older replay never overwrites newer state or moves authority back.
	db.ingest(t0.Add(30*time.Minute), firefoxApp, &homebrewPart{CollectionStatus: "failed"})
	if status, auth := db.state(); status != "complete" || !auth.Equal(t4) {
		t.Fatalf("old replay overwrote state: %s/%v", status, auth)
	}

	// not_present: a genuine reading that clears every Homebrew installation.
	t5 := t4.Add(time.Hour)
	db.ingest(t5, firefoxApp, testBlock("not_present", []homebrewFormulaPart{}, []homebrewCaskPart{}, []homebrewTapPart{}))
	if got := db.activeBrew(); len(got) != 0 {
		t.Fatalf("not_present left active Homebrew installations: %v", got)
	}
	if status, auth := db.state(); status != "not_present" || !auth.Equal(t5) {
		t.Fatalf("state after not_present = %s/%v", status, auth)
	}
	if n := db.int(`SELECT count(*) FROM software_installations WHERE device_id=$1::uuid
		AND identity_kind = 'macos_bundle_team' AND removed_at IS NULL`, db.deviceID); n != 1 {
		t.Fatalf("not_present closed the Firefox app installation")
	}

	// Reprocessing the same raw payload is idempotent (ordinals follow apps).
	obs := db.int(`SELECT count(*) FROM software_observations WHERE device_id=$1::uuid`, db.deviceID)
	var rawID int64
	var received time.Time
	if err := db.tx.QueryRow(db.ctx, `SELECT raw_payload_id, raw_payload_received_at FROM software_inventory_runs
		WHERE device_id=$1::uuid AND received_at=$2`, db.deviceID, t4).Scan(&rawID, &received); err != nil {
		t.Fatal(err)
	}
	p := &payload{SchemaVersion: 3, Platform: "macos", AppsPresent: true, Apps: firefoxApp,
		Homebrew: testBlock("complete",
			[]homebrewFormulaPart{testFormula("openssl@3", "3.5.2", "homebrew/core", true)},
			[]homebrewCaskPart{testCask("firefox", "Firefox.app", nil)},
			[]homebrewTapPart{testTap("homebrew/core")})}
	if _, err := upsertSoftwareInventory(db.ctx, db.tx, claimedRow{ID: rawID, ReceivedAt: received, TenantID: db.tenantID}, db.deviceID, p, "macos"); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if again := db.int(`SELECT count(*) FROM software_observations WHERE device_id=$1::uuid`, db.deviceID); again != obs {
		t.Fatalf("replay added %d observations", again-obs)
	}
}

// TestHomebrewPartialNeverPrunes is the absence-authority guard on its own:
// a partial report that omits a package already known must neither close its
// installation nor remove it from the stored scope.
func TestHomebrewPartialNeverPrunes(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Microsecond)
	db.ingest(t0, nil, testBlock("complete",
		[]homebrewFormulaPart{testFormula("git", "2.51.0", "homebrew/core", true), testFormula("curl", "8.16.0", "homebrew/core", true)},
		[]homebrewCaskPart{testCask("iterm2", "iTerm.app", nil)},
		[]homebrewTapPart{testTap("acme/tools")}))
	db.ingest(t0.Add(time.Hour), nil, testBlock("partial",
		[]homebrewFormulaPart{testFormula("git", "2.51.0", "homebrew/core", true)}, []homebrewCaskPart{}, []homebrewTapPart{}))
	got := db.activeBrew()
	for _, k := range []string{"homebrew_formula:curl", "homebrew_cask:iterm2", "homebrew_tap:acme/tools"} {
		if !got[k] {
			t.Fatalf("partial report pruned %s (active now %v)", k, got)
		}
	}
	if n := db.int(`SELECT count(*) FROM software_inventory_runs WHERE device_id=$1::uuid
		AND 'homebrew' = ANY(authoritative_scopes)`, db.deviceID); n != 1 {
		t.Fatalf("%d runs carry homebrew authority, want only the complete one", n)
	}
}

// TestHomebrewCaskLinksToAppBundle covers the link rules: default appdir
// when Homebrew moved the app, the reported path when there is one, no link
// on a mismatch, and replacement when the cask's receipt was read.
func TestHomebrewCaskLinksToAppBundle(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Microsecond)
	apps := []appPart{
		firefoxApp[0],
		{Name: "Tool", Version: "1", Identifier: "com.example.tool", TeamID: "ABCDE12345",
			Path: "/opt/homebrew/Caskroom/tool/1.0/Tool.app"},
		{Name: "Other", Version: "1", Identifier: "com.example.other", TeamID: "ABCDE12345",
			Path: "/Applications/Other.app"},
	}
	db.ingest(t0, apps, testBlock("complete", []homebrewFormulaPart{},
		[]homebrewCaskPart{
			testCask("firefox", "Firefox.app", nil),                                         // moved: default appdir
			testCask("tool", "Tool.app", strp("/opt/homebrew/Caskroom/tool/1.0/Tool.app")),  // reported path
			testCask("custom", "Custom.app", nil),                                           // no such app: no link
			testCask("elsewhere", "Other.app", strp("/Users/alice/Applications/Other.app")), // reported path wins, no fallback
		}, []homebrewTapPart{}))

	links := func() map[string]string {
		rows, err := db.tx.Query(db.ctx, `
			SELECT ci.identity_value_normalized, ai.identity_value_normalized || '|' || l.link_basis
			FROM homebrew_cask_app_links l
			JOIN software_installations ci ON ci.id = l.cask_installation_id
			JOIN software_installations ai ON ai.id = l.app_installation_id
			WHERE l.device_id = $1::uuid
		`, db.deviceID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var cask, app string
			if err := rows.Scan(&cask, &app); err != nil {
				t.Fatal(err)
			}
			out[cask] = app
		}
		return out
	}
	got := links()
	want := map[string]string{
		"firefox": "org.mozilla.firefox|default_appdir",
		"tool":    "com.example.tool|reported_path",
	}
	if len(got) != len(want) || got["firefox"] != want["firefox"] || got["tool"] != want["tool"] {
		t.Fatalf("links = %v, want %v", got, want)
	}

	// A later read receipt that no longer lists the app replaces the link.
	noApp := testCask("firefox", "Firefox.app", nil)
	noApp.Apps = []homebrewCaskAppPart{}
	db.ingest(t0.Add(time.Hour), apps, testBlock("partial", []homebrewFormulaPart{}, []homebrewCaskPart{noApp}, []homebrewTapPart{}))
	if _, ok := links()["firefox"]; ok {
		t.Fatal("read receipt without the app did not replace the firefox link")
	}
	// An unreadable receipt adds but never removes.
	db.ingest(t0.Add(2*time.Hour), apps, testBlock("partial", []homebrewFormulaPart{}, []homebrewCaskPart{testCask("firefox", "Firefox.app", nil)}, []homebrewTapPart{}))
	unreadable := testCask("firefox", "Firefox.app", nil)
	unreadable.ReceiptStatus = "unreadable"
	unreadable.Apps = []homebrewCaskAppPart{}
	db.ingest(t0.Add(3*time.Hour), apps, testBlock("partial", []homebrewFormulaPart{}, []homebrewCaskPart{unreadable}, []homebrewTapPart{}))
	if links()["firefox"] != want["firefox"] {
		t.Fatalf("unreadable receipt removed the firefox link: %v", links())
	}
}
