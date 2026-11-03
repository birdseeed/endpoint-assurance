package driverblock

// PAT-2263: list storage and matching against a real, fully migrated
// database. Skipped without TEST_DATABASE_URL. The global list tables are
// isolated in this package's own schema (driverblocktest); device rows are
// isolated by tenant.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/driverblock/driverblocktest"
)

const dbSchema = "pat2263_driverblock_test"

var rawPayloadSeq = time.Now().UnixNano() % 1_000_000_000_000

type seedDriver struct {
	path, service                string
	hashed                       bool
	sha256, sha1, auth256, auth1 string
	loaded                       *bool
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// seedDevice creates a tenant and a Windows device and stores a kernel
// driver state and rows for it, as the extractor would.
func seedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label, enforced string, drivers []seedDriver) (tenantID, deviceID string) {
	t.Helper()
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00', '\x00') RETURNING id::text`, "pat2263-"+label).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, os, serial, hostname)
		VALUES ($1::uuid, 'Windows', $2, $3) RETURNING id::text`, tenantID, "SER-"+label, "HOST-"+label).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	rawPayloadSeq++
	now := time.Now().UTC().Truncate(time.Second)
	var obsID int64
	if err := pool.QueryRow(ctx, `INSERT INTO device_kernel_driver_observations (tenant_id, device_id, raw_payload_id,
			raw_payload_received_at, block_schema_version, collection_status, vulnerable_driver_blocklist, hvci,
			smart_app_control, code_integrity_policy, blocklist_enforced, driver_count)
		VALUES ($1::uuid, $2::uuid, $3, $4, 1, 'partial', 'disabled', 'off', 'off', 'off', $5, $6) RETURNING id`,
		tenantID, deviceID, rawPayloadSeq, now, enforced, len(drivers)).Scan(&obsID); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_kernel_driver_state (device_id, tenant_id, observation_id, reported_at,
			collection_status, errors, vulnerable_driver_blocklist, hvci, smart_app_control, code_integrity_policy, blocklist_enforced)
		VALUES ($1::uuid, $2::uuid, $3, $4, 'partial', '{driver_unhashed}', 'disabled', 'off', 'off', 'off', $5)`,
		deviceID, tenantID, obsID, now, enforced); err != nil {
		t.Fatalf("insert state: %v", err)
	}
	for i, d := range drivers {
		status := "unhashed"
		var reason *string
		if d.hashed {
			status = "hashed"
		} else {
			r := "read_failed"
			reason = &r
		}
		key := fmt.Sprintf("path:%d", i)
		if _, err := pool.Exec(ctx, `INSERT INTO device_kernel_drivers (device_id, tenant_id, driver_key, path, service_name,
				loaded, sources, hash_status, unhashed_reason, sha256, sha1, authenticode_sha256, authenticode_sha1,
				observation_id, reported_at, first_seen_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, '{drivers_directory}', $7, $8, $9, $10, $11, $12, $13, $14, $14)`,
			deviceID, tenantID, key, strPtr(d.path), strPtr(d.service), d.loaded, status, reason,
			strPtr(d.sha256), strPtr(d.sha1), strPtr(d.auth256), strPtr(d.auth1), obsID, now); err != nil {
			t.Fatalf("insert driver %d: %v", i, err)
		}
	}
	return tenantID, deviceID
}

func loadFixtureLists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fetchedAt time.Time) {
	t.Helper()
	ms, err := ParseMicrosoft(readTestdata(t, "DriverPolicy_Enforced.xml"), fetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	lol, err := ParseLOLDrivers(readTestdata(t, "drivers.json"), fetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, snap := range []Snapshot{ms, lol} {
		if err := ReplaceSnapshot(ctx, pool, snap, fetchedAt); err != nil {
			t.Fatalf("replace %s: %v", snap.Source, err)
		}
	}
}

func countEntries(t *testing.T, ctx context.Context, pool *pgxpool.Pool, source string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM driver_blocklist_entries WHERE source = $1`, source).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDB_ReplaceSnapshot_StoresTheListWithProvenance(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Second)
	loadFixtureLists(t, ctx, pool, fetched)

	states, err := LoadSourceStates(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	ms := states[SourceMicrosoft]
	if ms.Status != "succeeded" || ms.SourceURL != MicrosoftURL || ms.SourceRevision != "10.0.99999.1" ||
		ms.EntryCount != 2 || ms.FetchedAt == nil || !ms.FetchedAt.Equal(fetched) {
		t.Fatalf("microsoft state = %+v", ms)
	}
	if lol := states[SourceLOLDrivers]; lol.EntryCount != 7 || countEntries(t, ctx, pool, SourceLOLDrivers) != 7 {
		t.Fatalf("loldrivers state = %+v", lol)
	}
}

func TestDB_AFailedRefresh_KeepsTheLastGoodList_AndReportsItStale(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	fetched := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	loadFixtureLists(t, ctx, pool, fetched)
	tenantID, deviceID := seedDevice(t, ctx, pool, "stale-"+fmt.Sprint(rawPayloadSeq), "no", []seedDriver{
		{path: `C:\Temp\totally-legit.sys`, hashed: true,
			sha256: "357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1", sha1: "0000000000000000000000000000000000000001"},
	})

	attempted := time.Now().UTC().Truncate(time.Second)
	if err := RecordFailure(ctx, pool, SourceLOLDrivers, attempted, "fetch_or_parse_failed"); err != nil {
		t.Fatal(err)
	}

	states, err := LoadSourceStates(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	lol := states[SourceLOLDrivers]
	goodRevision, _ := ParseLOLDrivers(readTestdata(t, "drivers.json"), fetched)
	if lol.SourceRevision != goodRevision.SourceRevision {
		t.Fatalf("a failure replaced the last good list version: %q", lol.SourceRevision)
	}
	if lol.Status != "failed" || lol.FetchedAt == nil || !lol.FetchedAt.Equal(fetched) || lol.EntryCount != 7 ||
		lol.LastError != "fetch_or_parse_failed" || !lol.AttemptedAt.Equal(attempted) {
		t.Fatalf("state after failure = %+v", lol)
	}
	if n := countEntries(t, ctx, pool, SourceLOLDrivers); n != 7 {
		t.Fatalf("entries after failure = %d, want 7 (never emptied)", n)
	}

	view, err := FetchDevice(ctx, pool, tenantID, deviceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Drivers) != 1 || view.Drivers[0].MatchStatus != MatchListed {
		t.Fatalf("drivers = %+v", view.Drivers)
	}
	m := view.Drivers[0].Matches[0]
	if !m.ListStale || !m.ListFetchedAt.Equal(fetched) || m.Source != SourceLOLDrivers || m.ListVersion != goodRevision.SourceRevision {
		t.Fatalf("match = %+v", m)
	}
	for _, l := range view.Lists {
		if l.Source == SourceLOLDrivers && (!l.Stale || l.Status != "failed" || l.Revision != goodRevision.SourceRevision ||
			l.FetchedAt == nil || !l.FetchedAt.Equal(fetched) || l.AttemptedAt == nil || !l.AttemptedAt.Equal(attempted)) {
			t.Fatalf("list = %+v", l)
		}
	}

	// A first-ever failure records a state with no list at all.
	if err := RecordFailure(ctx, pool, SourceMicrosoft, attempted, "fetch_or_parse_failed"); err != nil {
		t.Fatal(err)
	}
	if n := countEntries(t, ctx, pool, SourceMicrosoft); n != 2 {
		t.Fatalf("microsoft entries after failure = %d, want 2", n)
	}
}

func TestDB_AnImplausiblyShrunkList_IsRefused_AndTheOldOneKept(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Second)
	loadFixtureLists(t, ctx, pool, fetched)

	small := Snapshot{Source: SourceLOLDrivers, SourceURL: LOLDriversURL, FetchedAt: fetched.Add(time.Hour), SourceRevision: "sha256:small",
		Entries: []Entry{{HashKind: HashSHA256, Hash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", EntryID: "x", Category: CategoryMalicious}}}
	err := ReplaceSnapshot(ctx, pool, small, fetched.Add(time.Hour))
	if !errors.Is(err, ErrImplausibleShrink) {
		t.Fatalf("err = %v, want ErrImplausibleShrink", err)
	}
	if n := countEntries(t, ctx, pool, SourceLOLDrivers); n != 7 {
		t.Fatalf("entries = %d, want the old 7", n)
	}
}

func TestDB_MatchingIsByHashOnly(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Second)
	loadFixtureLists(t, ctx, pool, fetched)
	loaded := true
	tenantID, deviceID := seedDevice(t, ctx, pool, "match-"+fmt.Sprint(rawPayloadSeq), "yes", []seedDriver{
		// Renamed: the loldrivers sample is gdrv.sys; the hash is what matches.
		{path: `C:\Temp\totally-legit.sys`, hashed: true, loaded: &loaded,
			sha256: "357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1", sha1: "0000000000000000000000000000000000000002"},
		// Same name as the listed sample, different bytes: not a match.
		{path: `C:\Windows\System32\drivers\gdrv.sys`, hashed: true,
			sha256: "0101010101010101010101010101010101010101010101010101010101010101", sha1: "0101010101010101010101010101010101010101"},
		// Listed by Microsoft by Authenticode SHA-256.
		{path: `C:\Windows\System32\drivers\pe.sys`, hashed: true,
			sha256: "0202020202020202020202020202020202020202020202020202020202020202", sha1: "0202020202020202020202020202020202020202",
			auth256: "8812f0c849e0e9537b5060dd011057885eaf9047af11842840b97d8444eff841"},
		// A SHA-1 the list carried beside a SHA-256: never stored, never matched.
		{path: `C:\Vendor\sha1collide.sys`, hashed: true,
			sha256: "0303030303030303030303030303030303030303030303030303030303030303", sha1: "d348d0ef0d72cf831c6cbfb9479ff27318bc8715"},
		// A SHA-1-only list record: matched on SHA-1.
		{path: `C:\Vendor\old.sys`, hashed: true,
			sha256: "0404040404040404040404040404040404040404040404040404040404040404", sha1: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		// Malicious.
		{path: `C:\Vendor\evil.sys`, hashed: true,
			sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", sha1: "0505050505050505050505050505050505050505"},
		// No hash: Unknown, never clean.
		{path: `C:\Vendor\unreadable.sys`, hashed: false},
	})

	view, err := FetchDevice(ctx, pool, tenantID, deviceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "partial" || view.Enforcement == nil || view.Enforcement.BlocklistEnforced != "yes" {
		t.Fatalf("header = %+v / %+v", view.Status, view.Enforcement)
	}
	want := DeviceSummary{Drivers: 7, Hashed: 6, Unhashed: 1, Listed: 4, ListedMalicious: 1, Unknown: 1}
	if view.Summary != want {
		t.Fatalf("summary = %+v, want %+v", view.Summary, want)
	}
	got := map[string]DriverRow{}
	for _, d := range view.Drivers {
		got[*d.Path] = d
	}
	if len(view.Drivers) != 5 || *view.Drivers[0].Path != `C:\Vendor\evil.sys` {
		t.Fatalf("drivers shown (listed, malicious first, then unknown) = %d, first %v", len(view.Drivers), *view.Drivers[0].Path)
	}
	if _, shown := got[`C:\Windows\System32\drivers\gdrv.sys`]; shown {
		t.Fatal("a same-named file with a different hash was reported")
	}
	if _, shown := got[`C:\Vendor\sha1collide.sys`]; shown {
		t.Fatal("a SHA-1 listed beside a SHA-256 was matched")
	}
	renamed := got[`C:\Temp\totally-legit.sys`]
	if renamed.MatchStatus != MatchListed || len(renamed.Matches) != 1 {
		t.Fatalf("renamed = %+v", renamed)
	}
	if m := renamed.Matches[0]; m.Source != SourceLOLDrivers || m.HashKind != HashSHA256 || m.EntryName != "gdrv.sys" ||
		m.Category != CategoryVulnerable || m.SourceURL != LOLDriversURL || !m.ListFetchedAt.Equal(fetched) || m.ListStale ||
		m.ListVersion == "" {
		t.Fatalf("renamed match = %+v", m)
	}
	if m := got[`C:\Windows\System32\drivers\pe.sys`].Matches[0]; m.Source != SourceMicrosoft || m.HashKind != HashAuthenticodeSHA256 ||
		m.ListVersion != "10.0.99999.1" || m.EntryID != "ID_DENY_SYNTH_PE_SHA256" {
		t.Fatalf("pe match = %+v", m)
	}
	if m := got[`C:\Vendor\old.sys`].Matches[0]; m.HashKind != HashSHA1 {
		t.Fatalf("old match = %+v", m)
	}
	if m := got[`C:\Vendor\evil.sys`].Matches; len(m) != 1 || m[0].Category != CategoryMalicious {
		t.Fatalf("evil matches = %+v", m)
	}
	unread := got[`C:\Vendor\unreadable.sys`]
	if unread.MatchStatus != MatchUnknown || unread.UnknownReason == nil || *unread.UnknownReason != UnknownNotHashed {
		t.Fatalf("unreadable = %+v", unread)
	}
}

func TestDB_WithNoListEverFetched_HashedDriversAreUnknown(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	tenantID, deviceID := seedDevice(t, ctx, pool, "nolist-"+fmt.Sprint(rawPayloadSeq), "unknown", []seedDriver{
		{path: `C:\Vendor\a.sys`, hashed: true,
			sha256: "0606060606060606060606060606060606060606060606060606060606060606", sha1: "0606060606060606060606060606060606060606"},
	})
	view, err := FetchDevice(ctx, pool, tenantID, deviceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Drivers) != 1 || view.Drivers[0].MatchStatus != MatchUnknown || *view.Drivers[0].UnknownReason != UnknownListsUnavailable {
		t.Fatalf("drivers = %+v", view.Drivers)
	}
	for _, l := range view.Lists {
		if l.Status != "never_fetched" || !l.Stale {
			t.Fatalf("list = %+v", l)
		}
	}
}

func TestDB_TenantIsolation(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	loadFixtureLists(t, ctx, pool, time.Now().UTC().Truncate(time.Second))
	listed := []seedDriver{{path: `C:\Vendor\evil.sys`, hashed: true,
		sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", sha1: "0707070707070707070707070707070707070707"}}
	tenantA, deviceA := seedDevice(t, ctx, pool, "iso-a-"+fmt.Sprint(rawPayloadSeq), "yes", listed)
	tenantB, deviceB := seedDevice(t, ctx, pool, "iso-b-"+fmt.Sprint(rawPayloadSeq), "no", listed)

	estateA, err := FetchEstate(ctx, pool, tenantA, 50, 0, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if estateA.Total != 1 || estateA.Findings[0].DeviceID != deviceA || estateA.Summary.DevicesReporting != 1 ||
		estateA.Summary.BlocklistEnforced["yes"] != 1 || estateA.Summary.BlocklistEnforced["no"] != 0 {
		t.Fatalf("tenant A estate = %+v", estateA)
	}
	if f := estateA.Findings[0]; f.Category != CategoryMalicious || f.BlocklistEnforced != "yes" || f.Hostname == "" {
		t.Fatalf("finding = %+v", f)
	}

	// Tenant A asking for tenant B's device sees nothing of it.
	cross, err := FetchDevice(ctx, pool, tenantA, deviceB, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if cross.Status != StatusNotReported || len(cross.Drivers) != 0 || cross.Enforcement != nil {
		t.Fatalf("cross-tenant device view = %+v", cross)
	}
	estateB, err := FetchEstate(ctx, pool, tenantB, 50, 0, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if estateB.Total != 1 || estateB.Findings[0].DeviceID != deviceB {
		t.Fatalf("tenant B estate = %+v", estateB)
	}
}

func TestDB_EstatePagination(t *testing.T) {
	pool := driverblocktest.Pool(t, dbSchema)
	ctx := context.Background()
	loadFixtureLists(t, ctx, pool, time.Now().UTC().Truncate(time.Second))
	tenantID, _ := seedDevice(t, ctx, pool, "page-"+fmt.Sprint(rawPayloadSeq), "unknown", []seedDriver{
		{path: `C:\Vendor\a.sys`, hashed: true, sha256: "357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1", sha1: "0808080808080808080808080808080808080808"},
		{path: `C:\Vendor\b.sys`, hashed: true, sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", sha1: "0909090909090909090909090909090909090909"},
		{path: `C:\Vendor\c.sys`, hashed: false},
	})
	page, err := FetchEstate(ctx, pool, tenantID, 1, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Findings) != 1 || *page.Findings[0].Path != `C:\Vendor\a.sys` {
		t.Fatalf("page = %+v", page)
	}
	if page.Summary.ListedDrivers != 2 || page.Summary.ListedMaliciousDrivers != 1 || page.Summary.DevicesWithUnhashed != 1 ||
		page.Summary.DevicesWithListed != 1 {
		t.Fatalf("summary = %+v", page.Summary)
	}
	beyond, err := FetchEstate(ctx, pool, tenantID, 10, 5, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if beyond.Total != 2 || len(beyond.Findings) != 0 {
		t.Fatalf("beyond = %+v", beyond)
	}
}
