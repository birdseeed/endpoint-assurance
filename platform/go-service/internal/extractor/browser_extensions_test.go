package extractor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Risk-level heuristic ──────────────────────────────────────────────────────

// TestBrowserExtRiskLevelElevated verifies that broad host access and/or
// sensitive permissions each independently trigger "elevated".
func TestBrowserExtRiskLevelElevated(t *testing.T) {
	cases := []struct {
		name      string
		perms     []string
		hostPerms []string
	}{
		{
			name:      "<all_urls> in host_permissions",
			perms:     []string{"storage"},
			hostPerms: []string{"<all_urls>"},
		},
		{
			name:      "wildcard host pattern *://*/*",
			perms:     []string{},
			hostPerms: []string{"*://*/*"},
		},
		{
			name:      "sensitive perm: tabs",
			perms:     []string{"tabs"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: cookies",
			perms:     []string{"cookies"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: webRequest",
			perms:     []string{"webRequest"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: webRequestBlocking",
			perms:     []string{"webRequestBlocking"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: scripting",
			perms:     []string{"scripting"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: history",
			perms:     []string{"history"},
			hostPerms: []string{},
		},
		{
			name:      "sensitive perm: downloads",
			perms:     []string{"downloads"},
			hostPerms: []string{},
		},
		{
			name:      "<all_urls> in permissions (MV2 pattern)",
			perms:     []string{"<all_urls>"},
			hostPerms: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := browserExtRiskLevel(tc.perms, tc.hostPerms)
			if got != "elevated" {
				t.Errorf("browserExtRiskLevel(%v, %v) = %q; want \"elevated\"",
					tc.perms, tc.hostPerms, got)
			}
		})
	}
}

// TestBrowserExtRiskLevelNormal verifies that benign extensions are classified
// as "normal".
func TestBrowserExtRiskLevelNormal(t *testing.T) {
	cases := []struct {
		name      string
		perms     []string
		hostPerms []string
	}{
		{
			name:      "no permissions at all",
			perms:     []string{},
			hostPerms: []string{},
		},
		{
			name:      "storage only",
			perms:     []string{"storage"},
			hostPerms: []string{},
		},
		{
			name:      "specific host (no wildcard)",
			perms:     []string{"storage"},
			hostPerms: []string{"https://example.com/"},
		},
		{
			name:      "notifications + contextMenus",
			perms:     []string{"notifications", "contextMenus"},
			hostPerms: []string{},
		},
		{
			name:      "nil slices",
			perms:     nil,
			hostPerms: nil,
		},
		{
			// PAT-2076: a wildcard confined to one registrable domain is not
			// broad access. This case USED to be classified "elevated" under
			// the old "contains a *" rule (see the regression test below) -
			// it moved here deliberately, it did not stop being tested.
			name:      "domain wildcard *://*.example.com/* (single site, not broad)",
			perms:     []string{},
			hostPerms: []string{"*://*.example.com/*"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := browserExtRiskLevel(tc.perms, tc.hostPerms)
			if got != "normal" {
				t.Errorf("browserExtRiskLevel(%v, %v) = %q; want \"normal\"",
					tc.perms, tc.hostPerms, got)
			}
		})
	}
}

// TestIsBroadHostPermissionOldRuleRegression demonstrates the exact
// regression PAT-2076 fixes: the old rule ("elevated" whenever the pattern
// contained any "*") flagged a single-site wildcard identically to
// "<all_urls>". This test pins the NEW behavior (not broad) for that
// pattern; reverting isBroadHostPermission to `strings.Contains(h, "*")`
// turns it red, which is how the fix was proven before being kept (see the
// verification note in the PAT-2076 report - the old body was restored
// in-place with `git apply -R` on the change, this test run, then
// reinstated).
func TestIsBroadHostPermissionOldRuleRegression(t *testing.T) {
	pattern := "https://*.example.com/*"
	if got := isBroadHostPermission(pattern); got {
		t.Errorf("isBroadHostPermission(%q) = true; want false (single registrable domain is not broad access)", pattern)
	}
}

// TestIsBroadHostPermission is a table-driven test over the host-pattern
// breadth classifier itself (PAT-2076), covering every pattern class named
// in the ticket brief plus the edge cases called out there.
func TestIsBroadHostPermission(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		// -- broad --
		{"<all_urls> literal", "<all_urls>", true},
		{"<all_urls> case-insensitive", "<ALL_URLS>", true},
		{"host is * alone, *://*/*", "*://*/*", true},
		{"host is * alone, http://*/*", "http://*/*", true},
		{"host is * alone, https://*/*", "https://*/*", true},
		{"host is * alone, *://*", "*://*", true},
		{"wildcard host with no registrable domain, *.com", "*.com", true},
		{"wildcard host with no registrable domain, *.co.uk", "*.co.uk", true},
		{"wildcard-wildcard host, https://*.*/*", "https://*.*/*", true},
		{"file scheme, no wildcard at all", "file:///Users/x/secrets.txt", true},
		{"file scheme with wildcard path", "file:///*", true},
		{"uppercase scheme, broad host", "HTTPS://*.CO.UK/*", true},
		{"mid-label wildcard (not a *.domain prefix), conservative", "https://ex*ample.com/*", true},
		{"malformed: empty string", "", true},
		{"malformed: scheme with no host", "https:///*", true},

		// -- not broad --
		{"single registrable domain wildcard", "https://*.example.com/*", false},
		{"single registrable domain wildcard, alt scheme", "*://*.google.com/*", false},
		{"single registrable domain wildcard with port", "https://*.example.com:8443/*", false},
		{"path-only wildcard, explicit host", "https://example.com/*", false},
		{"explicit host, no wildcard anywhere", "https://example.com/", false},
		{"uppercase scheme, single domain", "HTTPS://*.EXAMPLE.COM/*", false},
		{"registrable domain under a multi-label suffix", "*://*.example.co.uk/*", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isBroadHostPermission(tc.pattern)
			if got != tc.want {
				t.Errorf("isBroadHostPermission(%q) = %v; want %v", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestBrowserExtRiskLevelMixedHostPermissions verifies that one broad
// pattern in a host_permissions list elevates the whole extension even when
// every other entry in the list is narrow (PAT-2076).
func TestBrowserExtRiskLevelMixedHostPermissions(t *testing.T) {
	perms := []string{}
	hostPerms := []string{
		"https://*.example.com/*",
		"https://*.google.com/*",
		"<all_urls>",
	}
	if got := browserExtRiskLevel(perms, hostPerms); got != "elevated" {
		t.Errorf("browserExtRiskLevel(%v, %v) = %q; want \"elevated\"", perms, hostPerms, got)
	}
}

// ── Payload parsing ───────────────────────────────────────────────────────────

// TestBrowserExtensionsAbsentKey verifies that a payload without the
// "browser_extensions" key produces a nil/empty slice (no-op in upsert).
func TestBrowserExtensionsAbsentKey(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.BrowserExtensions) != 0 {
		t.Errorf("BrowserExtensions must be empty when key is absent; got len=%d", len(p.BrowserExtensions))
	}
}

// TestBrowserExtensionsPayloadParse verifies that a payload carrying
// browser_extensions unmarshals all fields correctly.
func TestBrowserExtensionsPayloadParse(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["browser_extensions"] = []any{
		map[string]any{
			"browser":          "chrome",
			"profile":          "Default",
			"user_account":     "alice",
			"extension_id":     "cjpalhdlnbpafiamejdnhcphjbkeiagm",
			"name":             "uBlock Origin",
			"version":          "1.57.2",
			"enabled":          true,
			"permissions":      []any{"storage", "tabs"},
			"host_permissions": []any{"<all_urls>"},
			"from_webstore":    true,
			"update_url":       "https://clients2.google.com/service/update2/crx",
		},
		map[string]any{
			"browser":          "firefox",
			"profile":          "default-release",
			"user_account":     "alice",
			"extension_id":     "uBlock0@raymondhill.net",
			"name":             "uBlock Origin",
			"version":          "1.57.0",
			"enabled":          true,
			"permissions":      []any{"storage", "tabs", "webRequest"},
			"host_permissions": []any{"<all_urls>"},
			"from_webstore":    true,
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if got, want := len(p.BrowserExtensions), 2; got != want {
		t.Fatalf("BrowserExtensions len: got %d want %d", got, want)
	}

	ext := p.BrowserExtensions[0]
	if ext.Browser != "chrome" {
		t.Errorf("browser: got %q want chrome", ext.Browser)
	}
	if ext.Profile != "Default" {
		t.Errorf("profile: got %q want Default", ext.Profile)
	}
	if ext.UserAccount != "alice" {
		t.Errorf("user_account: got %q want alice", ext.UserAccount)
	}
	if ext.ExtensionID != "cjpalhdlnbpafiamejdnhcphjbkeiagm" {
		t.Errorf("extension_id: got %q", ext.ExtensionID)
	}
	if ext.Name != "uBlock Origin" {
		t.Errorf("name: got %q want uBlock Origin", ext.Name)
	}
	if !ext.Enabled {
		t.Error("enabled: got false want true")
	}
	if got, want := len(ext.Permissions), 2; got != want {
		t.Errorf("permissions len: got %d want %d", got, want)
	}
	if got, want := len(ext.HostPermissions), 1; got != want {
		t.Errorf("host_permissions len: got %d want %d", got, want)
	}
	if ext.HostPermissions[0] != "<all_urls>" {
		t.Errorf("host_permissions[0]: got %q want <all_urls>", ext.HostPermissions[0])
	}
	if !ext.FromWebstore {
		t.Error("from_webstore: got false want true")
	}
}

// ── upsertBrowserExtensions DB round-trip ─────────────────────────────────────

// TestBrowserExtensionsIngest is a DB round-trip test for upsertBrowserExtensions.
// It requires a real Postgres instance pointed to by TEST_DATABASE_URL.
// All writes are rolled back at the end.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestBrowserExtensionsIngest -v
func TestBrowserExtensionsIngest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping browser extensions DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('ext-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'EXTTEST001')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	// ── Empty slice → no-op ──────────────────────────────────────────────────
	n, err := upsertBrowserExtensions(ctx, tx, deviceID, nil, time.Now(), nil)
	if err != nil {
		t.Fatalf("upsertBrowserExtensions(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("nil exts: want 0 rows written, got %d", n)
	}

	// ── First ingest — writes rows with computed risk_level ──────────────────
	exts := []browserExtensionPart{
		{
			Browser:         "chrome",
			Profile:         "Default",
			UserAccount:     "alice",
			ExtensionID:     "ext-abc123",
			Name:            "uBlock Origin",
			Version:         "1.57.2",
			Enabled:         true,
			Permissions:     []string{"storage", "tabs"},
			HostPermissions: []string{"<all_urls>"},
			FromWebstore:    true,
		},
		{
			Browser:         "chrome",
			Profile:         "Default",
			UserAccount:     "alice",
			ExtensionID:     "ext-benign",
			Name:            "Honey",
			Version:         "14.0.0",
			Enabled:         true,
			Permissions:     []string{"storage"},
			HostPermissions: []string{},
		},
	}

	written, err := upsertBrowserExtensions(ctx, tx, deviceID, exts, time.Now(), nil)
	if err != nil {
		t.Fatalf("first upsertBrowserExtensions: %v", err)
	}
	if written != 2 {
		t.Errorf("first ingest: want 2 rows written, got %d", written)
	}

	// Verify risk_level is correctly computed.
	var elevatedCount, normalCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND risk_level = 'elevated'
	`, deviceID).Scan(&elevatedCount); err != nil {
		t.Fatalf("count elevated: %v", err)
	}
	if elevatedCount != 1 {
		t.Errorf("elevated count: want 1, got %d", elevatedCount)
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND risk_level = 'normal'
	`, deviceID).Scan(&normalCount); err != nil {
		t.Fatalf("count normal: %v", err)
	}
	if normalCount != 1 {
		t.Errorf("normal count: want 1, got %d", normalCount)
	}

	// ── Re-ingest — ON CONFLICT updates mutable columns ─────────────────────
	exts[0].Version = "1.58.0" // version bumped
	exts[0].Enabled = false    // user disabled it

	written2, err := upsertBrowserExtensions(ctx, tx, deviceID, exts, time.Now(), nil)
	if err != nil {
		t.Fatalf("second upsertBrowserExtensions: %v", err)
	}
	if written2 != 2 {
		t.Errorf("second ingest: want 2 rows written, got %d", written2)
	}

	// Row count must not grow — ON CONFLICT is working.
	var totalCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions WHERE device_id = $1::uuid
	`, deviceID).Scan(&totalCount); err != nil {
		t.Fatalf("count total: %v", err)
	}
	if totalCount != 2 {
		t.Errorf("total row count: want 2 (no duplicates), got %d", totalCount)
	}

	// Updated extension should reflect new version + disabled state.
	var gotVersion string
	var gotEnabled bool
	if err := tx.QueryRow(ctx, `
		SELECT version, enabled FROM device_browser_extensions
		WHERE device_id = $1::uuid AND extension_id = 'ext-abc123'
	`, deviceID).Scan(&gotVersion, &gotEnabled); err != nil {
		t.Fatalf("select updated ext: %v", err)
	}
	if gotVersion != "1.58.0" {
		t.Errorf("version after reingest: want 1.58.0, got %q", gotVersion)
	}
	if gotEnabled {
		t.Error("enabled after reingest: want false")
	}
}

// ── Malformed-entry guard (PAT-871) ───────────────────────────────────────────

// TestBrowserExtValid is a pure, no-DB unit test for the guard that decides
// whether a browser_extensions entry is safe to insert. device_browser_extensions
// declares user_account and profile NOT NULL; an entry with either field empty
// must be rejected by this guard before it ever reaches the INSERT, or the
// missing-value case turns into SQL NULL via nullIfEmpty and aborts the whole
// device-processing transaction on a NOT NULL violation.
func TestBrowserExtValid(t *testing.T) {
	base := browserExtensionPart{
		Browser:     "chrome",
		Profile:     "Default",
		UserAccount: "alice",
		ExtensionID: "ext-abc123",
	}

	cases := []struct {
		name string
		mut  func(e browserExtensionPart) browserExtensionPart
		want bool
	}{
		{"fully populated", func(e browserExtensionPart) browserExtensionPart { return e }, true},
		{"empty user_account", func(e browserExtensionPart) browserExtensionPart { e.UserAccount = ""; return e }, false},
		{"empty profile", func(e browserExtensionPart) browserExtensionPart { e.Profile = ""; return e }, false},
		{"empty extension_id", func(e browserExtensionPart) browserExtensionPart { e.ExtensionID = ""; return e }, false},
		{"empty browser", func(e browserExtensionPart) browserExtensionPart { e.Browser = ""; return e }, false},
		// PAT-2064: Safari carries no user_account or profile (app-bundle
		// extension, not a browser profile) — the one exception to the
		// non-empty rule above.
		{"safari with no user_account or profile", func(e browserExtensionPart) browserExtensionPart {
			e.Browser, e.UserAccount, e.Profile = "safari", "", ""
			return e
		}, true},
		{"safari with empty extension_id still rejected", func(e browserExtensionPart) browserExtensionPart {
			e.Browser, e.UserAccount, e.Profile, e.ExtensionID = "safari", "", "", ""
			return e
		}, false},
		{"chrome with no user_account or profile still rejected", func(e browserExtensionPart) browserExtensionPart {
			e.UserAccount, e.Profile = "", ""
			return e
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := browserExtValid(tc.mut(base))
			if got != tc.want {
				t.Errorf("browserExtValid(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestBrowserExtensionsIngestSkipsMalformedEntry is a DB round-trip test
// proving the PAT-871 fix: a payload with one browser extension entry that has
// an empty user_account, mixed in among otherwise-valid entries, no longer
// fails upsertBrowserExtensions (and, by extension, no longer aborts the
// caller's processRow transaction). Only the malformed entry is skipped; the
// valid ones are written.
//
// Before the fix, this test failed: the bad entry produced a NOT NULL
// violation on tx.Exec, upsertBrowserExtensions returned a non-nil error, and
// (in processRow) that would roll back the entire device snapshot.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestBrowserExtensionsIngestSkipsMalformedEntry -v
func TestBrowserExtensionsIngestSkipsMalformedEntry(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping browser extensions DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('ext-poison-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'EXTPOISON001')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	exts := []browserExtensionPart{
		{
			Browser:         "chrome",
			Profile:         "Default",
			UserAccount:     "alice",
			ExtensionID:     "ext-good-one",
			Name:            "uBlock Origin",
			Version:         "1.57.2",
			Enabled:         true,
			Permissions:     []string{"storage"},
			HostPermissions: []string{},
		},
		{
			// Malformed: empty UserAccount. Populated ExtensionID/Browser means
			// the pre-fix guard (ExtensionID/Browser only) let this one through
			// to the INSERT, where user_account NOT NULL rejected it.
			Browser:         "chrome",
			Profile:         "Default",
			UserAccount:     "",
			ExtensionID:     "ext-bad-user-account",
			Name:            "Malformed Extension",
			Version:         "1.0.0",
			Enabled:         true,
			Permissions:     []string{"storage"},
			HostPermissions: []string{},
		},
		{
			Browser:         "chrome",
			Profile:         "Default",
			UserAccount:     "alice",
			ExtensionID:     "ext-good-two",
			Name:            "Honey",
			Version:         "14.0.0",
			Enabled:         true,
			Permissions:     []string{"storage"},
			HostPermissions: []string{},
		},
	}

	written, err := upsertBrowserExtensions(ctx, tx, deviceID, exts, time.Now(), nil)
	if err != nil {
		t.Fatalf("upsertBrowserExtensions must not error on a malformed entry (PAT-871 regression): %v", err)
	}
	if written != 2 {
		t.Errorf("written: want 2 (only the two valid entries), got %d", written)
	}

	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions WHERE device_id = $1::uuid
	`, deviceID).Scan(&count); err != nil {
		t.Fatalf("count device_browser_extensions: %v", err)
	}
	if count != 2 {
		t.Errorf("device_browser_extensions row count: want 2, got %d", count)
	}

	var badCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND extension_id = 'ext-bad-user-account'
	`, deviceID).Scan(&badCount); err != nil {
		t.Fatalf("count malformed entry: %v", err)
	}
	if badCount != 0 {
		t.Error("malformed entry (empty user_account) must not be written")
	}
}

// ── Safari null user_account/profile normalisation (PAT-2064) ────────────────

// TestSafariNullUserAccountAndProfileNormalised is a DB round-trip test
// proving the PAT-2064 fix: a Safari entry with empty UserAccount and Profile
// (exactly what the macOS agent has always sent, since Safari extensions live
// in an app bundle, not a browser user profile) is stored under the fixed
// SafariSystemSentinel rather than being skipped by browserExtValid or
// aborting the transaction on a NOT NULL violation. A second, identical
// ingest upserts the same row rather than duplicating it.
//
// Before the fix, this test failed: browserExtValid rejected the entry
// outright (UserAccount == "" && Profile == ""), so written == 0 and no row
// ever reached device_browser_extensions.
func TestSafariNullUserAccountAndProfileNormalised(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping browser extensions DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('safari-ext-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'SAFARIEXT001')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	safariExt := browserExtensionPart{
		Browser:         "safari",
		Profile:         "",
		UserAccount:     "",
		ExtensionID:     "com.example.safari-ext",
		Name:            "Safari Test Extension",
		Version:         "1.0",
		Enabled:         true,
		Permissions:     []string{},
		HostPermissions: []string{},
	}

	written, err := upsertBrowserExtensions(ctx, tx, deviceID, []browserExtensionPart{safariExt}, time.Now(), nil)
	if err != nil {
		t.Fatalf("upsertBrowserExtensions must not error on a null-user_account Safari entry: %v", err)
	}
	if written != 1 {
		t.Fatalf("written: want 1, got %d", written)
	}

	var gotUserAccount, gotProfile string
	if err := tx.QueryRow(ctx, `
		SELECT user_account, profile FROM device_browser_extensions
		WHERE device_id = $1::uuid AND browser = 'safari' AND extension_id = 'com.example.safari-ext'
	`, deviceID).Scan(&gotUserAccount, &gotProfile); err != nil {
		t.Fatalf("select safari ext: %v", err)
	}
	if gotUserAccount != SafariSystemSentinel {
		t.Errorf("user_account: want %q, got %q", SafariSystemSentinel, gotUserAccount)
	}
	if gotProfile != SafariSystemSentinel {
		t.Errorf("profile: want %q, got %q", SafariSystemSentinel, gotProfile)
	}

	// Re-ingest the identical entry: ON CONFLICT must upsert, not duplicate.
	written2, err := upsertBrowserExtensions(ctx, tx, deviceID, []browserExtensionPart{safariExt}, time.Now(), nil)
	if err != nil {
		t.Fatalf("second upsertBrowserExtensions: %v", err)
	}
	if written2 != 1 {
		t.Errorf("second ingest: want 1 row written, got %d", written2)
	}

	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND browser = 'safari'
	`, deviceID).Scan(&count); err != nil {
		t.Fatalf("count safari rows: %v", err)
	}
	if count != 1 {
		t.Errorf("safari row count after re-ingest: want 1 (no duplicate), got %d", count)
	}
}

// ── Field-length bound at ingestion (PAT-933 gate round 6) ───────────────────

// TestUpsertBrowserExtensionsTruncatesOversizedFields is a DB round-trip test
// proving the PAT-933 round-6 fix: upsertBrowserExtensions truncates
// extension_id, browser, name, and version to their extMax*Len caps BEFORE
// the INSERT/ON CONFLICT, so device_browser_extensions can never accumulate
// a row with an unbounded text field, even below the row-count cap that
// portal_extensions.go's pre-check enforces. Mirrors the assertion shape of
// integration/portal_test.go's TestPortalExtensionsTextFieldTruncation
// (length + prefix check) but on the write side: this test reads the row
// straight back out of device_browser_extensions rather than through the
// portal endpoint.
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestUpsertBrowserExtensionsTruncatesOversizedFields -v
func TestUpsertBrowserExtensionsTruncatesOversizedFields(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping browser extensions DB round-trip test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('ext-oversized-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', 'EXTOVERSIZED001')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	longBrowser := "chrome-" + strings.Repeat("b", 100)    // > extMaxBrowserLen (32)
	longExtID := "ext-" + strings.Repeat("i", 200)         // > extMaxIDLen (128)
	longName := "OversizedExt-" + strings.Repeat("n", 400) // > extMaxNameLen (256)
	longVersion := "1.0.0-" + strings.Repeat("v", 100)     // > extMaxVersionLen (64)
	longUserAccount := "alice-" + strings.Repeat("u", 200) // > extMaxUserAccountLen (128)
	longProfile := "Profile-" + strings.Repeat("p", 200)   // > extMaxProfileLen (128)

	exts := []browserExtensionPart{
		{
			Browser:         longBrowser,
			Profile:         longProfile,
			UserAccount:     longUserAccount,
			ExtensionID:     longExtID,
			Name:            longName,
			Version:         longVersion,
			Enabled:         true,
			Permissions:     []string{"storage"},
			HostPermissions: []string{},
		},
	}

	written, err := upsertBrowserExtensions(ctx, tx, deviceID, exts, time.Now(), nil)
	if err != nil {
		t.Fatalf("upsertBrowserExtensions: %v", err)
	}
	if written != 1 {
		t.Fatalf("written: want 1, got %d", written)
	}

	var gotBrowser, gotExtID, gotName, gotVersion, gotUserAccount, gotProfile string
	if err := tx.QueryRow(ctx, `
		SELECT browser, extension_id, name, version, user_account, profile
		FROM device_browser_extensions
		WHERE device_id = $1::uuid
	`, deviceID).Scan(&gotBrowser, &gotExtID, &gotName, &gotVersion, &gotUserAccount, &gotProfile); err != nil {
		t.Fatalf("select written row: %v", err)
	}

	if got, want := len(gotBrowser), extMaxBrowserLen; got != want {
		t.Errorf("browser length = %d, want %d (extMaxBrowserLen): %q", got, want, gotBrowser)
	}
	if !strings.HasPrefix(longBrowser, gotBrowser) {
		t.Errorf("browser %q is not a prefix of the original %q", gotBrowser, longBrowser)
	}

	if got, want := len(gotExtID), extMaxIDLen; got != want {
		t.Errorf("extension_id length = %d, want %d (extMaxIDLen): %q", got, want, gotExtID)
	}
	if !strings.HasPrefix(longExtID, gotExtID) {
		t.Errorf("extension_id %q is not a prefix of the original %q", gotExtID, longExtID)
	}

	if got, want := len(gotName), extMaxNameLen; got != want {
		t.Errorf("name length = %d, want %d (extMaxNameLen): %q", got, want, gotName)
	}
	if !strings.HasPrefix(longName, gotName) {
		t.Errorf("name %q is not a prefix of the original %q", gotName, longName)
	}

	if got, want := len(gotVersion), extMaxVersionLen; got != want {
		t.Errorf("version length = %d, want %d (extMaxVersionLen): %q", got, want, gotVersion)
	}
	if !strings.HasPrefix(longVersion, gotVersion) {
		t.Errorf("version %q is not a prefix of the original %q", gotVersion, longVersion)
	}

	if got, want := len(gotUserAccount), extMaxUserAccountLen; got != want {
		t.Errorf("user_account length = %d, want %d (extMaxUserAccountLen): %q", got, want, gotUserAccount)
	}
	if !strings.HasPrefix(longUserAccount, gotUserAccount) {
		t.Errorf("user_account %q is not a prefix of the original %q", gotUserAccount, longUserAccount)
	}

	if got, want := len(gotProfile), extMaxProfileLen; got != want {
		t.Errorf("profile length = %d, want %d (extMaxProfileLen): %q", got, want, gotProfile)
	}
	if !strings.HasPrefix(longProfile, gotProfile) {
		t.Errorf("profile %q is not a prefix of the original %q", gotProfile, longProfile)
	}
}

// ── Migration file sanity ─────────────────────────────────────────────────────

// TestMigration0018Files verifies that both migration files for PAT-125 are
// present and contain the expected DDL landmarks.
func TestMigration0018Files(t *testing.T) {
	forward := filepath.Join("..", "..", "migrations", "0018_device_browser_extensions.sql")
	rollback := filepath.Join("..", "..", "migrations", "0018_device_browser_extensions_rollback.sql")

	for _, tc := range []struct {
		file        string
		mustContain []string
	}{
		{
			file: forward,
			mustContain: []string{
				"CREATE TABLE device_browser_extensions",
				"risk_level",
				"permissions",
				"host_permissions",
				"UNIQUE",
				"0018_device_browser_extensions",
			},
		},
		{
			file: rollback,
			mustContain: []string{
				"DROP TABLE IF EXISTS device_browser_extensions",
				"0018_device_browser_extensions",
			},
		},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("migration file not readable (%s): %v", tc.file, err)
			continue
		}
		body := string(b)
		for _, needle := range tc.mustContain {
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing expected SQL fragment %q", tc.file, needle)
			}
		}
	}
}
