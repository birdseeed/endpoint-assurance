package extractor

// PAT-2032: the server-side Homebrew pre-flip gate. Each test here was run
// red against the PAT-2013 code before the fix it covers.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// statementCounter counts every statement a connection sends: plain queries,
// each query inside a batch, and each COPY.
type statementCounter struct{ n atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}
func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (c *statementCounter) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (c *statementCounter) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {
	c.n.Add(1)
}
func (c *statementCounter) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}
func (c *statementCounter) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceCopyFromStartData) context.Context {
	c.n.Add(1)
	return ctx
}
func (c *statementCounter) TraceCopyFromEnd(context.Context, *pgx.Conn, pgx.TraceCopyFromEndData) {}

// largeHomebrewBlock builds a partial block of kegs formula kegs (two per
// name), casks casks and taps taps.
func largeHomebrewBlock(kegs, casks, taps int) *homebrewPart {
	formulae := make([]homebrewFormulaPart, 0, kegs)
	for i := 0; i < kegs; i++ {
		f := testFormula(fmt.Sprintf("formula-%05d", i/2), fmt.Sprintf("1.%d", i%2), "homebrew/core", i%3 == 0)
		f.OptLinked = boolp(i%2 == 1)
		formulae = append(formulae, f)
	}
	cs := make([]homebrewCaskPart, 0, casks)
	for i := 0; i < casks; i++ {
		cs = append(cs, testCask(fmt.Sprintf("cask-%05d", i), fmt.Sprintf("Cask%05d.app", i), nil))
	}
	ts := make([]homebrewTapPart, 0, taps)
	for i := 0; i < taps; i++ {
		ts = append(ts, testTap(fmt.Sprintf("acme/tap-%05d", i)))
	}
	return testBlock("partial", formulae, cs, ts)
}

// TestHomebrewIngestStatementCountIsBounded: a 5,000-keg payload costs the
// same fixed number of statements as a handful of packages. The PAT-2013
// loop sent about five statements per package inside the one serial ingest
// transaction.
func TestHomebrewIngestStatementCountIsBounded(t *testing.T) {
	measure := func(hb *homebrewPart) int64 {
		counter := &statementCounter{}
		db := openHomebrewTestDBWith(t, counter)
		t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		before := counter.n.Load()
		db.ingest(t0, firefoxApp, hb)
		n := counter.n.Load() - before
		// End this measurement's transaction before the next one opens.
		// Its INSERT INTO tenants holds RowExclusiveLock on tenants until
		// it ends; left open, a DROP TRIGGER ON tenants from another test
		// package (handlers TestTenantLifecycleDB) queues behind it, and the
		// next measurement's INSERT INTO tenants queues behind that DROP.
		// This test would then wait on itself with no lock cycle Postgres
		// can see, and hang until the go test timeout.
		if err := db.tx.Rollback(db.ctx); err != nil {
			t.Fatalf("end measurement transaction: %v", err)
		}
		return n
	}
	small := measure(largeHomebrewBlock(4, 2, 2))
	large := measure(largeHomebrewBlock(homebrewMaxFormulae, 1000, 500))
	t.Logf("statements: small payload %d, 5,000-keg payload %d", small, large)
	const bound = 30
	if large > bound || large != small {
		t.Fatalf("5,000-keg ingest sent %d statements (small payload %d); want a fixed count <= %d", large, small, bound)
	}
}

// installation is one active Homebrew installation row, for assertions.
type installation struct {
	Fingerprint string
	Tap         string
	Version     *string
}

func (db *homebrewTestDB) formulaInstallations(name string) []installation {
	db.t.Helper()
	rows, err := db.tx.Query(db.ctx, `
		SELECT identity_fingerprint, companion_value_normalized, current_version
		FROM software_installations
		WHERE device_id = $1::uuid AND removed_at IS NULL
		  AND identity_kind = 'homebrew_formula' AND identity_value_normalized = $2
		ORDER BY companion_value_normalized
	`, db.deviceID, name)
	if err != nil {
		db.t.Fatal(err)
	}
	defer rows.Close()
	var out []installation
	for rows.Next() {
		var i installation
		if err := rows.Scan(&i.Fingerprint, &i.Tap, &i.Version); err != nil {
			db.t.Fatal(err)
		}
		out = append(out, i)
	}
	return out
}

// TestHomebrewFormulaKegsShareOneIdentity: a keg whose receipt could not be
// read (tap null) joins the tapped identity of the same formula in the same
// prefix instead of becoming a second installation, and current_version is
// the keg opt/ links to, not the string-sort maximum.
func TestHomebrewFormulaKegsShareOneIdentity(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)

	// openssl@3 as reproduced: the current keg's receipt is unreadable.
	oldKeg := testFormula("openssl@3", "3.5.1", "homebrew/core", true)
	oldKeg.OptLinked = boolp(false)
	currentKeg := testFormula("openssl@3", "3.5.2", "", true)
	currentKeg.Tap, currentKeg.ReceiptStatus = nil, "unreadable"
	currentKeg.InstalledOnRequest, currentKeg.InstalledAsDependency, currentKeg.InstalledAt = nil, nil, nil
	// wget: "1.9" sorts after "1.10", but opt/ links 1.10.
	wget110 := testFormula("wget", "1.10", "homebrew/core", true)
	wget19 := testFormula("wget", "1.9", "homebrew/core", true)
	wget19.OptLinked = boolp(false)
	// ambiguous: two taps for one name, so a tap-less keg is not guessed.
	ambA := testFormula("dup", "1", "acme/a", true)
	ambB := testFormula("dup", "2", "acme/b", true)
	ambNil := testFormula("dup", "3", "", true)
	ambNil.Tap = nil
	// same name in another prefix is a different keg directory: not merged.
	intel := testFormula("openssl@3", "3.4.0", "", true)
	intel.Prefix, intel.Tap = "/usr/local", nil

	db.ingest(t0, nil, testBlock("partial",
		[]homebrewFormulaPart{oldKeg, currentKeg, intel, wget110, wget19, ambA, ambB, ambNil}, nil, nil))

	tapped := deriveHomebrewIdentity(homebrewFormulaKind, "openssl@3", strp("homebrew/core"))
	openssl := db.formulaInstallations("openssl@3")
	if len(openssl) != 2 {
		t.Fatalf("openssl@3 installations = %+v, want the tapped one plus the /usr/local keg", openssl)
	}
	var core *installation
	for i := range openssl {
		if openssl[i].Tap == "homebrew/core" {
			core = &openssl[i]
		}
	}
	if core == nil || core.Fingerprint != tapped.Fingerprint {
		t.Fatalf("tap-less /opt/homebrew keg did not join the tapped identity: %+v", openssl)
	}
	if core.Version == nil || *core.Version != "3.5.2" {
		t.Fatalf("openssl@3 current_version = %v, want the linked keg 3.5.2", core.Version)
	}
	// The raw evidence keeps what the agent said: the detail row's tap stays
	// null, and the inferred identity is only low confidence.
	var detailTap *string
	var confidence string
	if err := db.tx.QueryRow(db.ctx, `
		SELECT h.tap, so.identity_confidence
		FROM homebrew_observation_details h
		JOIN software_observations so ON so.id = h.observation_id
		WHERE h.device_id = $1::uuid AND h.name = 'openssl@3' AND h.version = '3.5.2'
	`, db.deviceID).Scan(&detailTap, &confidence); err != nil {
		t.Fatal(err)
	}
	if detailTap != nil || confidence != "low" {
		t.Fatalf("reconciled keg evidence tap=%v confidence=%s, want null/low", detailTap, confidence)
	}

	wget := db.formulaInstallations("wget")
	if len(wget) != 1 || wget[0].Version == nil || *wget[0].Version != "1.10" {
		t.Fatalf("wget installations = %+v, want one at the linked 1.10", wget)
	}
	if dup := db.formulaInstallations("dup"); len(dup) != 3 {
		t.Fatalf("ambiguous tap-less keg was merged: %+v", dup)
	}
}

// TestHomebrewCaskLinkNeedsItsOwnCaskroom: a reported app path links only
// when it lies inside that cask's own Caskroom directory. A path elsewhere is
// where a symlink planted in the Caskroom points, which the agent resolves
// and reports; it is not evidence the cask installed that app.
func TestHomebrewCaskLinkNeedsItsOwnCaskroom(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	apps := []appPart{
		{Name: "Slack", Version: "4", Identifier: "com.tinyspeck.slackmacgap", TeamID: "BQR82RBBHL",
			Path: "/Applications/Slack.app"},
		{Name: "Tool", Version: "1", Identifier: "com.example.tool", TeamID: "ABCDE12345",
			Path: "/opt/homebrew/Caskroom/tool/1.0/Tool.app"},
	}
	db.ingest(t0, apps, testBlock("complete", []homebrewFormulaPart{},
		[]homebrewCaskPart{
			testCask("planted", "Slack.app", strp("/Applications/Slack.app")),                          // symlink target outside
			testCask("sneaky", "Tool.app", strp("/opt/homebrew/Caskroom/tool/1.0/Tool.app")),           // another cask's dir
			testCask("dotdot", "Tool.app", strp("/opt/homebrew/Caskroom/dotdot/../tool/1.0/Tool.app")), // traversal
			testCask("tool", "Tool.app", strp("/opt/homebrew/Caskroom/tool/1.0/Tool.app")),             // its own dir
		}, []homebrewTapPart{}))
	rows, err := db.tx.Query(db.ctx, `
		SELECT ci.identity_value_normalized
		FROM homebrew_cask_app_links l
		JOIN software_installations ci ON ci.id = l.cask_installation_id
		WHERE l.device_id = $1::uuid ORDER BY 1
	`, db.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var linked []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		linked = append(linked, c)
	}
	if strings.Join(linked, ",") != "tool" {
		t.Fatalf("linked casks = %v, want only tool", linked)
	}
}

// currentVersions reads the current-entry projection joined to its evidence:
// "kind:name" -> sorted versions ("" for a tap).
func (db *homebrewTestDB) currentVersions() map[string][]string {
	db.t.Helper()
	rows, err := db.tx.Query(db.ctx, `
		SELECT c.package_kind || ':' || c.name, COALESCE(h.version, '')
		FROM homebrew_current_entries c
		JOIN homebrew_observation_details h
		  ON h.inventory_run_id = c.inventory_run_id AND h.device_id = c.device_id
		 AND h.package_kind = c.package_kind AND h.prefix = c.prefix AND h.name = c.name
		 AND (h.package_kind <> 'formula' OR h.version = c.version_key)
		WHERE c.device_id = $1::uuid
	`, db.deviceID)
	if err != nil {
		db.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			db.t.Fatal(err)
		}
		out[k] = append(out[k], v)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func assertCurrent(t *testing.T, step string, got map[string][]string, want map[string][]string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s: current = %v, want %v", step, got, want)
	}
}

// TestHomebrewCurrentEntriesOnlyAuthorityPrunes (PAT-2032 review): a
// partial report can list a formula without having read every keg of it (the
// formula bound cuts mid-formula, the time check runs per keg, an unreadable
// keg directory is skipped). So a partial report only adds or refreshes
// kegs; it never hides one. Only complete or not_present removes what it did
// not list. A partial-only Mac shows every keg seen since the last authority,
// which is what the evidence supports.
func TestHomebrewCurrentEntriesOnlyAuthorityPrunes(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)
	f := func(name, version string) homebrewFormulaPart {
		return testFormula(name, version, "homebrew/core", true)
	}

	// complete {3.0, 3.1}, then a partial listing only 3.0: both stay.
	db.ingest(t0, nil, testBlock("complete", []homebrewFormulaPart{f("openssl@3", "3.0"), f("openssl@3", "3.1")}, nil, nil))
	db.ingest(t0.Add(time.Hour), nil, testBlock("partial", []homebrewFormulaPart{f("openssl@3", "3.0")}, nil, nil))
	assertCurrent(t, "partial after complete", db.currentVersions(), map[string][]string{
		"formula:openssl@3": {"3.0", "3.1"},
	})
	// Partial-only additions accumulate, and nothing is dropped.
	db.ingest(t0.Add(2*time.Hour), nil, testBlock("partial", []homebrewFormulaPart{f("openssl@3", "3.2"), f("curl", "8.0")}, nil, nil))
	assertCurrent(t, "partial additions", db.currentVersions(), map[string][]string{
		"formula:curl": {"8.0"}, "formula:openssl@3": {"3.0", "3.1", "3.2"},
	})

	// complete: replaces everything.
	t3 := t0.Add(3 * time.Hour)
	db.ingest(t3, nil, testBlock("complete", []homebrewFormulaPart{f("openssl@3", "3.2")}, nil, []homebrewTapPart{testTap("acme/tools")}))
	assertCurrent(t, "complete", db.currentVersions(), map[string][]string{
		"formula:openssl@3": {"3.2"}, "tap:acme/tools": {""},
	})
	// A replay older than the authority cannot bring anything back.
	db.ingest(t3.Add(-30*time.Minute), nil, testBlock("partial", []homebrewFormulaPart{f("curl", "9.0"), f("openssl@3", "3.0")}, nil, nil))
	assertCurrent(t, "old replay", db.currentVersions(), map[string][]string{
		"formula:openssl@3": {"3.2"}, "tap:acme/tools": {""},
	})
	// An empty partial and a failed report change nothing.
	db.ingest(t3.Add(time.Hour), nil, testBlock("partial", []homebrewFormulaPart{}, nil, nil))
	db.ingest(t3.Add(2*time.Hour), nil, &homebrewPart{CollectionStatus: "failed"})
	assertCurrent(t, "empty partial and failed", db.currentVersions(), map[string][]string{
		"formula:openssl@3": {"3.2"}, "tap:acme/tools": {""},
	})
	// not_present clears it.
	db.ingest(t3.Add(3*time.Hour), nil, testBlock("not_present", []homebrewFormulaPart{}, []homebrewCaskPart{}, []homebrewTapPart{}))
	assertCurrent(t, "not_present", db.currentVersions(), map[string][]string{})
}

// TestHomebrewPartialWithoutLinkedKegKeepsCurrentVersion (PAT-2032 review):
// a partial report that did not read the linked keg of a formula must not
// move the installation's current_version to whichever keg it did read. The
// linked keg it skipped may be the vulnerable one.
func TestHomebrewPartialWithoutLinkedKegKeepsCurrentVersion(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Microsecond)
	linked := testFormula("openssl@3", "3.1", "homebrew/core", true)
	older := testFormula("openssl@3", "3.0", "homebrew/core", true)
	older.OptLinked = boolp(false)
	db.ingest(t0, nil, testBlock("complete", []homebrewFormulaPart{older, linked}, nil, nil))
	version := func() string {
		got := db.formulaInstallations("openssl@3")
		if len(got) != 1 || got[0].Version == nil {
			t.Fatalf("openssl@3 installations = %+v", got)
		}
		return *got[0].Version
	}
	if v := version(); v != "3.1" {
		t.Fatalf("after complete current_version = %s, want 3.1", v)
	}
	// partial without the linked keg: keep 3.1.
	db.ingest(t0.Add(time.Hour), nil, testBlock("partial", []homebrewFormulaPart{older}, nil, nil))
	if v := version(); v != "3.1" {
		t.Fatalf("partial without the linked keg moved current_version to %s, want 3.1 kept", v)
	}
	// partial that did read a linked keg: it moves.
	newer := testFormula("openssl@3", "3.2", "homebrew/core", true)
	db.ingest(t0.Add(2*time.Hour), nil, testBlock("partial", []homebrewFormulaPart{newer}, nil, nil))
	if v := version(); v != "3.2" {
		t.Fatalf("partial with a linked keg left current_version at %s, want 3.2", v)
	}
	// complete without a linked keg reads everything, so it may move it.
	db.ingest(t0.Add(3*time.Hour), nil, testBlock("complete", []homebrewFormulaPart{older}, nil, nil))
	if v := version(); v != "3.0" {
		t.Fatalf("complete without a linked keg left current_version at %s, want 3.0", v)
	}
}

// TestHomebrewAliasCheckStillExcludesHomebrewKinds guards the skipped alias
// lookup in recordHomebrewObservations: it is only correct while no
// software_product_aliases row can carry a Homebrew identity kind. Widening
// that CHECK (PAT-2023) must restore the lookup, and this test says so.
func TestHomebrewAliasCheckStillExcludesHomebrewKinds(t *testing.T) {
	db := openHomebrewTestDB(t)
	var productID string
	if err := db.tx.QueryRow(db.ctx, `
		INSERT INTO software_products (canonical_key, canonical_name)
		VALUES ('pat2032-openssl', 'OpenSSL') RETURNING id::text
	`).Scan(&productID); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{homebrewFormulaKind, homebrewCaskKind, homebrewTapKind} {
		sp, err := db.tx.Begin(db.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = sp.Exec(db.ctx, `
			INSERT INTO software_product_aliases (
				product_id, platform, identity_kind, identity_value_normalized,
				companion_value_normalized, match_confidence, provenance
			) VALUES ($1::uuid, 'macos', $2, 'openssl@3', 'homebrew/core', 'high', 'reviewed')
		`, productID, kind)
		_ = sp.Rollback(db.ctx)
		if err == nil || !strings.Contains(err.Error(), "23514") {
			t.Fatalf("alias with identity kind %s: err = %v; the alias CHECK now admits Homebrew kinds, so recordHomebrewObservations must look aliases up again", kind, err)
		}
	}
}

// TestHomebrewConcurrentOlderPartialCannotOutliveNewerComplete (PAT-2032
// review): ProcessOnce can run beside the worker, so an older partial report
// can be extracted while a newer complete one is still uncommitted. Without
// a per-device lock the partial reads the old authority, writes its entries,
// and both commit, leaving evidence older than the device's authority in the
// current list.
func TestHomebrewConcurrentOlderPartialCannotOutliveNewerComplete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var tenantID, deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name,bearer_token_hash,hmac_secret)
		VALUES('pat2032-race','\x00','\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	if err := pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,os,serial) VALUES($1::uuid,'macOS','PAT2032-RACE')
		RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	ingest := func(tx pgx.Tx, received time.Time, hb *homebrewPart) error {
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
			VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id`, tenantID, deviceID, received).Scan(&id); err != nil {
			return err
		}
		p := &payload{SchemaVersion: 3, Platform: "macos", Agent: "pat2032", AgentVersion: "test",
			CollectedAt: received.Format(time.RFC3339), Homebrew: hb}
		_, err := upsertSoftwareInventory(ctx, tx, claimedRow{ID: id, ReceivedAt: received, TenantID: tenantID}, deviceID, p, "macos")
		return err
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	// Newer complete, extracted first but not yet committed.
	txA, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	if err := ingest(txA, t0.Add(time.Minute), testBlock("complete",
		[]homebrewFormulaPart{testFormula("openssl@3", "3.5", "homebrew/core", true)}, []homebrewCaskPart{}, []homebrewTapPart{})); err != nil {
		t.Fatal(err)
	}
	// Older partial on another connection.
	done := make(chan error, 1)
	go func() {
		txB, err := pool.Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = txB.Rollback(ctx) }()
		if err := ingest(txB, t0, testBlock("partial",
			[]homebrewFormulaPart{testFormula("curl", "8.0", "homebrew/core", true)}, nil, nil)); err != nil {
			done <- err
			return
		}
		done <- txB.Commit(ctx)
	}()
	time.Sleep(300 * time.Millisecond)
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var stale int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM homebrew_current_entries c
		JOIN homebrew_device_state s ON s.device_id = c.device_id
		WHERE c.device_id = $1::uuid AND c.observed_at < s.authority_at
	`, deviceID).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("%d current entries older than the device's authority survived the race", stale)
	}
}

// caskInstallations mirrors formulaInstallations for casks.
func (db *homebrewTestDB) caskInstallations(token string) []installation {
	db.t.Helper()
	rows, err := db.tx.Query(db.ctx, `
		SELECT identity_fingerprint, coalesce(companion_value_normalized, ''), current_version
		FROM software_installations
		WHERE device_id = $1::uuid AND removed_at IS NULL
		  AND identity_kind = 'homebrew_cask' AND identity_value_normalized = $2
	`, db.deviceID, token)
	if err != nil {
		db.t.Fatal(err)
	}
	defer rows.Close()
	var out []installation
	for rows.Next() {
		var i installation
		if err := rows.Scan(&i.Fingerprint, &i.Tap, &i.Version); err != nil {
			db.t.Fatal(err)
		}
		out = append(out, i)
	}
	return out
}

// testCaskWithVersion is testCask with the version overridden, nil included
// (the agent reports version null when a cask's receipt is unreadable but
// several versions are still on disk).
func testCaskWithVersion(token, appName string, version *string) homebrewCaskPart {
	c := testCask(token, appName, nil)
	c.Version = version
	if version == nil {
		c.ReceiptStatus = "unreadable"
	}
	return c
}

// TestHomebrewCaskNullVersionNeverOverwritesStoredVersion (PAT-2032b): a cask
// reported with version null is never evidence of a version change, on a
// partial report, a complete report, or on first sight. Only a later
// non-null version may move current_version.
func TestHomebrewCaskNullVersionNeverOverwritesStoredVersion(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Microsecond)
	version := func(token string) *string {
		got := db.caskInstallations(token)
		if len(got) != 1 {
			t.Fatalf("%s installations = %+v, want exactly one", token, got)
		}
		return got[0].Version
	}

	// Stored at 1.2.3, then a partial report with version null: kept.
	db.ingest(t0, nil, testBlock("partial",
		nil, []homebrewCaskPart{testCaskWithVersion("stable-cask", "Stable.app", strp("1.2.3"))}, nil))
	if v := version("stable-cask"); v == nil || *v != "1.2.3" {
		t.Fatalf("stable-cask after first partial = %v, want 1.2.3", v)
	}
	db.ingest(t0.Add(time.Hour), nil, testBlock("partial",
		nil, []homebrewCaskPart{testCaskWithVersion("stable-cask", "Stable.app", nil)}, nil))
	if v := version("stable-cask"); v == nil || *v != "1.2.3" {
		t.Fatalf("partial null version blanked stable-cask to %v, want 1.2.3 kept", v)
	}

	// Same, but the null-version report is complete: still kept, because a
	// null version is never evidence, whatever the report status.
	db.ingest(t0.Add(2*time.Hour), nil, testBlock("complete",
		nil, []homebrewCaskPart{testCaskWithVersion("stable-cask", "Stable.app", nil)}, nil))
	if v := version("stable-cask"); v == nil || *v != "1.2.3" {
		t.Fatalf("complete null version blanked stable-cask to %v, want 1.2.3 kept", v)
	}

	// First-seen null: nothing to keep, stays NULL.
	db.ingest(t0.Add(3*time.Hour), nil, testBlock("partial",
		nil, []homebrewCaskPart{testCaskWithVersion("new-cask", "New.app", nil)}, nil))
	if v := version("new-cask"); v != nil {
		t.Fatalf("first-seen null version stored %v, want NULL", v)
	}

	// A later non-null version still updates.
	db.ingest(t0.Add(4*time.Hour), nil, testBlock("partial",
		nil, []homebrewCaskPart{testCaskWithVersion("new-cask", "New.app", strp("2.0"))}, nil))
	if v := version("new-cask"); v == nil || *v != "2.0" {
		t.Fatalf("non-null version after a null one = %v, want 2.0", v)
	}
	db.ingest(t0.Add(5*time.Hour), nil, testBlock("partial",
		nil, []homebrewCaskPart{testCaskWithVersion("stable-cask", "Stable.app", strp("1.3.0"))}, nil))
	if v := version("stable-cask"); v == nil || *v != "1.3.0" {
		t.Fatalf("non-null version after kept null = %v, want 1.3.0", v)
	}
}
