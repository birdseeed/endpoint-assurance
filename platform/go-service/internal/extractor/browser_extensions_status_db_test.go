package extractor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/extpresence"
)

// An unread profile must keep its previously observed extensions present,
// however old they become. Completeness for another user or browser cannot
// supply the missing authority for that profile.
func TestBrowserExtensionPartialReportNeverAgesOut(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: skipping browser extension partial-report test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Own every fixture in this transaction, including on an assertion failure.
	defer func() { _ = tx.Rollback(ctx) }()
	var tenantID, deviceID string
	if err := tx.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2055-partial-report', '\x00', '\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'PAT2055PARTIAL') RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	s := func(v string) *string { return &v }
	status := func(block, user, browser, result string) *browserExtensionsStatusPart {
		browsers := browserExtensionsStatusBrowserMap{
			Chrome: s("not_present"), Edge: s("not_present"), Firefox: s("not_present"),
		}
		if browser == "chrome" {
			browsers.Chrome = s(result)
		} else {
			browsers.Edge = s(result)
			browsers.Chrome = s("partial")
		}
		userStatus := result
		if browser == "edge" {
			userStatus = "partial"
		}
		return &browserExtensionsStatusPart{CollectionStatus: block, Users: []browserExtensionsStatusUserPart{{
			User: user, CollectionStatus: userStatus, Browsers: browsers,
		}}}
	}
	// Use an old observation so a legacy freshness cutoff would already fail.
	initialSeen := time.Now().UTC().Add(-90 * 24 * time.Hour).Truncate(time.Microsecond)
	seenAt := initialSeen
	extensions := []browserExtensionPart{{Browser: "chrome", Profile: "Unread Profile", UserAccount: "alice",
		ExtensionID: "pat2055-partial-ext", Name: "E"}}
	report := func(st *browserExtensionsStatusPart, rows []browserExtensionPart) {
		t.Helper()
		if _, err := upsertBrowserExtensions(ctx, tx, deviceID, rows, seenAt, nil); err != nil {
			t.Fatal(err)
		}
		if err := upsertBrowserExtensionsStatus(ctx, tx, claimedRow{TenantID: tenantID, ReceivedAt: seenAt},
			deviceID, st, rows, seenAt, nil); err != nil {
			t.Fatal(err)
		}
	}
	assertPresence := func(stage string, wantAbsent bool) {
		t.Helper()
		var lastSeen time.Time
		var absent, present bool
		// QueryRow also fails if ingestion removed the persisted extension row.
		if err := tx.QueryRow(ctx, `SELECT dbe.last_seen, `+extpresence.AbsenceAuthorisedSQL("dbe")+`, `+
			extpresence.PresentSQL("dbe", "dbe.last_seen > now() - interval '30 days'")+`
			FROM device_browser_extensions dbe WHERE dbe.device_id = $1::uuid
			AND dbe.user_account = 'alice' AND dbe.browser = 'chrome'
			AND dbe.profile = 'Unread Profile' AND dbe.extension_id = 'pat2055-partial-ext'`, deviceID).
			Scan(&lastSeen, &absent, &present); err != nil {
			t.Fatalf("%s: persisted extension: %v", stage, err)
		}
		if !lastSeen.Equal(initialSeen) {
			t.Fatalf("%s: omission changed last_seen to %v", stage, lastSeen)
		}
		if absent != wantAbsent || present == wantAbsent {
			t.Fatalf("%s: absence authorised=%v, present=%v; want absence=%v", stage, absent, present, wantAbsent)
		}
	}
	report(status("complete", "alice", "chrome", "complete"), extensions)
	assertPresence("initial complete report lists E", false)
	for _, omission := range []struct {
		name, user, browser, result string
	}{
		{"partial profile omits E", "alice", "chrome", "partial"},
		{"another user completes Chrome", "bob", "chrome", "complete"},
		{"same user completes another browser", "alice", "edge", "complete"},
	} {
		seenAt = seenAt.Add(24 * time.Hour)
		report(status("partial", omission.user, omission.browser, omission.result), nil)
		assertPresence(omission.name, false)
	}
	seenAt = seenAt.Add(24 * time.Hour)
	report(status("complete", "alice", "chrome", "complete"), nil)
	assertPresence("later complete report omits E", true)
}

// Review P3: two extractions for one device serialise on the devices row
// lock, but the transaction that STARTED first can take the lock second. B
// starts first and lists extension E; A starts later, takes the lock first
// and commits a complete report without E (it was collected before E was
// installed). With now() (transaction start) B would stamp E's last_seen
// before A's completion time and E would read as gone although B's report is
// the later one. browserExtensionSeenAt stamps under the lock instead.
func TestBrowserExtensionStampFollowsDeviceLock(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping browser extension lock-order test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var tenantID, deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat2055-lock-order', '\x00', '\x00') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'PAT2055LOCK') RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// B starts first: its now() is fixed here.
	txB, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txB.Rollback(ctx) }()
	var bStart time.Time
	if err := txB.QueryRow(ctx, `SELECT now()`).Scan(&bStart); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	// A starts later, takes the device lock first, reports complete without E.
	txA, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	aSeen, err := browserExtensionSeenAt(ctx, txA, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	s := func(v string) *string { return &v }
	complete := &browserExtensionsStatusPart{CollectionStatus: "complete", Users: []browserExtensionsStatusUserPart{{
		User: "alice", CollectionStatus: "complete",
		Browsers: browserExtensionsStatusBrowserMap{Chrome: s("not_present"), Edge: s("not_present"), Firefox: s("not_present")},
	}}}
	rowA := claimedRow{TenantID: tenantID, ReceivedAt: time.Now().Add(-time.Minute)}
	if err := upsertBrowserExtensionsStatus(ctx, txA, rowA, deviceID, complete, nil, aSeen, nil); err != nil {
		t.Fatal(err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// B takes the lock second and lists E.
	bSeen, err := browserExtensionSeenAt(ctx, txB, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	e := []browserExtensionPart{{Browser: "chrome", Profile: "Default", UserAccount: "alice", ExtensionID: "pat2055-lock-order-ext", Name: "E"}}
	if _, err := upsertBrowserExtensions(ctx, txB, deviceID, e, bSeen, nil); err != nil {
		t.Fatal(err)
	}
	if err := txB.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The race precondition held: with B's transaction-start time, E would
	// have been stamped before A's completion and read as gone.
	if !bStart.Before(aSeen) {
		t.Fatalf("precondition: B started at %v, not before A's stamp %v", bStart, aSeen)
	}
	var absent bool
	if err := pool.QueryRow(ctx, `SELECT `+extpresence.AbsenceAuthorisedSQL("dbe")+`
		FROM device_browser_extensions dbe WHERE dbe.device_id = $1::uuid AND dbe.extension_id = 'pat2055-lock-order-ext'`,
		deviceID).Scan(&absent); err != nil {
		t.Fatal(err)
	}
	if absent {
		t.Fatal("an extension listed by the later-locked report reads as gone")
	}

	// Single report: the report that lists E never proves E gone.
	txC, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txC.Rollback(ctx) }()
	cSeen, err := browserExtensionSeenAt(ctx, txC, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	complete.Users[0].Browsers.Chrome = s("complete")
	if _, err := upsertBrowserExtensions(ctx, txC, deviceID, e, cSeen, nil); err != nil {
		t.Fatal(err)
	}
	if err := upsertBrowserExtensionsStatus(ctx, txC, claimedRow{TenantID: tenantID, ReceivedAt: time.Now()}, deviceID, complete, e, cSeen, nil); err != nil {
		t.Fatal(err)
	}
	if err := txC.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT `+extpresence.AbsenceAuthorisedSQL("dbe")+`
		FROM device_browser_extensions dbe WHERE dbe.device_id = $1::uuid AND dbe.extension_id = 'pat2055-lock-order-ext'`,
		deviceID).Scan(&absent); err != nil {
		t.Fatal(err)
	}
	if absent {
		t.Fatal("a complete report proved its own extension gone")
	}
}
