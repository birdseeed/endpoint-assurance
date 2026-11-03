package extractor

// PAT-1974: the standing local administrator roster (local_admins), a new
// top-level payload object alongside compliance/hardware_health. Mirrors the
// hardware_health test shapes (extractor_test.go) for the same reasons:
// payload parsing (absent key vs present), and a real-Postgres DB round-trip
// for upsertLocalAdmins covering complete/partial/unavailable semantics.
//
// local_admin_count itself is untouched by this ticket — it keeps flowing
// through the existing flat compliance-bag path — so it is not re-tested
// here.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLocalAdminsPayloadAbsentKey(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.LocalAdmins != nil {
		t.Error("LocalAdmins must be nil when the key is absent — required for no-op semantics (an agent that predates PAT-1974)")
	}
}

// TestLocalAdminsPayloadPresent verifies that a payload carrying the
// local_admins key unmarshals collection_status and accounts correctly,
// including the Windows-only sid field.
func TestLocalAdminsPayloadPresent(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["local_admins"] = map[string]any{
		"collection_status": "complete",
		"accounts": []any{
			map[string]any{"name": "MACHINE\\Administrator", "principal_type": "user", "builtin": true, "sid": "S-1-5-21-1-2-3-500"},
			map[string]any{"name": "alice", "principal_type": "user", "builtin": false},
		},
	}
	patched, _ := json.Marshal(m)

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if p.LocalAdmins == nil {
		t.Fatal("LocalAdmins must be non-nil when the key is present")
	}
	if p.LocalAdmins.CollectionStatus != "complete" {
		t.Errorf("collection_status: got %q want complete", p.LocalAdmins.CollectionStatus)
	}
	if got, want := len(p.LocalAdmins.Accounts), 2; got != want {
		t.Fatalf("accounts len: got %d want %d", got, want)
	}
	a0 := p.LocalAdmins.Accounts[0]
	if a0.Name != "MACHINE\\Administrator" || a0.PrincipalType != "user" || !a0.Builtin {
		t.Errorf("accounts[0]: got %+v", a0)
	}
	if a0.Sid == nil || *a0.Sid != "S-1-5-21-1-2-3-500" {
		t.Errorf("accounts[0].sid: got %v want S-1-5-21-1-2-3-500", a0.Sid)
	}
	a1 := p.LocalAdmins.Accounts[1]
	if a1.Name != "alice" || a1.Builtin {
		t.Errorf("accounts[1]: got %+v", a1)
	}
	if a1.Sid != nil {
		t.Errorf("accounts[1].sid: got %v want nil (macOS omits it)", *a1.Sid)
	}
}

// TestLocalAdminsValidateRequiresAccountsWhenComplete: a payload claiming
// collection_status "complete" but omitting accounts entirely must be
// rejected at the validation gate (400), never accepted and left to reach
// upsertLocalAdmins — where the complete branch would delete the whole
// stored roster and write nothing back, a fabricated zero. partial and
// unavailable have no such requirement: accounts stays optional for both.
func TestLocalAdminsValidateRequiresAccountsWhenComplete(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}

	m["local_admins"] = map[string]any{"collection_status": "complete"}
	patched, _ := json.Marshal(m)
	if err := ValidatePayload(patched); err == nil {
		t.Error("collection_status complete with no accounts key: want a validation error, got nil")
	}

	for _, status := range []string{"partial", "unavailable"} {
		m["local_admins"] = map[string]any{"collection_status": status}
		patched, _ := json.Marshal(m)
		if err := ValidatePayload(patched); err != nil {
			t.Errorf("collection_status %q with no accounts key: want no error, got %v", status, err)
		}
	}

	m["local_admins"] = map[string]any{"collection_status": "complete", "accounts": []any{}}
	patched, _ = json.Marshal(m)
	if err := ValidatePayload(patched); err != nil {
		t.Errorf("collection_status complete with explicit empty accounts: want no error (a real zero is valid), got %v", err)
	}
}

// ── local_admins DB round-trip ────────────────────────────────────────────

func newLocalAdminsTestDevice(t *testing.T, ctx context.Context, tx pgx.Tx, serial string) string {
	t.Helper()

	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('local-admins-test', '\x00', '\x00')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'Windows', $2)
		RETURNING id::text
	`, tenantID, serial).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}
	return deviceID
}

func countLocalAdminAccounts(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM local_admin_accounts WHERE device_id = $1::uuid`, deviceID).Scan(&n); err != nil {
		t.Fatalf("count local_admin_accounts: %v", err)
	}
	return n
}

// TestLocalAdminsIngestCompleteReplacesRoster: nil → no-op; a "complete"
// payload writes the roster; a second "complete" payload with a different
// roster replaces it in full (no stale rows survive).
func TestLocalAdminsIngestCompleteReplacesRoster(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping local_admins DB round-trip test")
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

	deviceID := newLocalAdminsTestDevice(t, ctx, tx, "LATEST001")

	// nil (absent key) → no-op.
	n, err := upsertLocalAdmins(ctx, tx, deviceID, nil, nil)
	if err != nil {
		t.Fatalf("upsertLocalAdmins(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("nil local_admins: want 0 rows written, got %d", n)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 0 {
		t.Errorf("rows after nil no-op: want 0, got %d", got)
	}

	// First complete ingest.
	sid500 := "S-1-5-21-1-2-3-500"
	la1 := &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: "MACHINE\\Administrator", PrincipalType: "user", Builtin: true, Sid: &sid500},
			{Name: "MACHINE\\alice", PrincipalType: "user", Builtin: false, Sid: strPtr("S-1-5-21-1-2-3-1001")},
		},
	}
	written1, err := upsertLocalAdmins(ctx, tx, deviceID, la1, nil)
	if err != nil {
		t.Fatalf("first upsertLocalAdmins: %v", err)
	}
	if written1 != 2 {
		t.Errorf("first ingest written: want 2, got %d", written1)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 2 {
		t.Errorf("rows after first ingest: want 2, got %d", got)
	}

	// Second complete ingest with a different (smaller) roster — old rows
	// must not survive the replace.
	la2 := &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: "MACHINE\\Administrator", PrincipalType: "user", Builtin: true, Sid: &sid500},
		},
	}
	written2, err := upsertLocalAdmins(ctx, tx, deviceID, la2, nil)
	if err != nil {
		t.Fatalf("second upsertLocalAdmins: %v", err)
	}
	if written2 != 1 {
		t.Errorf("second ingest written: want 1, got %d", written2)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 1 {
		t.Errorf("rows after second ingest (replace): want 1 (no stale alice row), got %d", got)
	}

	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM local_admin_accounts WHERE device_id = $1::uuid`, deviceID).Scan(&name); err != nil {
		t.Fatalf("select remaining row: %v", err)
	}
	if name != "MACHINE\\Administrator" {
		t.Errorf("remaining row: got %q want MACHINE\\Administrator", name)
	}
}

// TestLocalAdminsUnavailableNeverFabricatesEmptyRoster: absence requires
// authority. A device with a stored roster that then reports
// collection_status "unavailable" (even carrying a non-empty accounts array,
// which a well-behaved agent never sends but the extractor must not trust)
// must keep its existing rows untouched — never pruned to zero.
func TestLocalAdminsUnavailableNeverFabricatesEmptyRoster(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping local_admins DB round-trip test")
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

	deviceID := newLocalAdminsTestDevice(t, ctx, tx, "LAUNAVAIL001")

	// Seed a stored roster via a complete ingest.
	seed := &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: "MACHINE\\Administrator", PrincipalType: "user", Builtin: true},
		},
	}
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, seed, nil); err != nil {
		t.Fatalf("seed upsertLocalAdmins: %v", err)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 1 {
		t.Fatalf("seeded rows: want 1, got %d", got)
	}

	// A degraded run reporting "unavailable" — even with an accounts array
	// present — must write nothing and must not touch existing rows.
	degraded := &localAdminsPart{
		CollectionStatus: "unavailable",
		Accounts:         []localAdminPart{}, // a well-behaved agent never sends this under "unavailable", but the extractor must not trust it either way
	}
	written, err := upsertLocalAdmins(ctx, tx, deviceID, degraded, nil)
	if err != nil {
		t.Fatalf("upsertLocalAdmins(unavailable): %v", err)
	}
	if written != 0 {
		t.Errorf("unavailable ingest written: want 0, got %d", written)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 1 {
		t.Errorf("rows after unavailable ingest: want 1 (untouched), got %d", got)
	}
}

// TestLocalAdminsPartialUpsertsOnlySentDeletesNothing mirrors the
// hardware_health storage/disks "partial" semantics: only the accounts
// actually sent are upserted, and any previously stored account absent from
// this payload survives — a partial collection's sender list is known to be
// incomplete by definition.
func TestLocalAdminsPartialUpsertsOnlySentDeletesNothing(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping local_admins DB round-trip test")
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

	deviceID := newLocalAdminsTestDevice(t, ctx, tx, "LAPARTIAL001")

	seed := &localAdminsPart{
		CollectionStatus: "complete",
		Accounts: []localAdminPart{
			{Name: "MACHINE\\Administrator", PrincipalType: "user", Builtin: true},
			{Name: "MACHINE\\bob", PrincipalType: "user", Builtin: false},
		},
	}
	if _, err := upsertLocalAdmins(ctx, tx, deviceID, seed, nil); err != nil {
		t.Fatalf("seed upsertLocalAdmins: %v", err)
	}

	// Partial run that only re-sends bob (with an updated principal_type) —
	// Administrator, absent from this payload, must survive.
	partial := &localAdminsPart{
		CollectionStatus: "partial",
		Accounts: []localAdminPart{
			{Name: "MACHINE\\bob", PrincipalType: "unresolved", Builtin: false},
		},
	}
	written, err := upsertLocalAdmins(ctx, tx, deviceID, partial, nil)
	if err != nil {
		t.Fatalf("upsertLocalAdmins(partial): %v", err)
	}
	if written != 1 {
		t.Errorf("partial ingest written: want 1, got %d", written)
	}
	if got := countLocalAdminAccounts(t, ctx, tx, deviceID); got != 2 {
		t.Errorf("rows after partial ingest: want 2 (Administrator survives, unsent), got %d", got)
	}

	var bobType string
	if err := tx.QueryRow(ctx,
		`SELECT principal_type FROM local_admin_accounts WHERE device_id = $1::uuid AND name = 'MACHINE\bob'`,
		deviceID,
	).Scan(&bobType); err != nil {
		t.Fatalf("select bob: %v", err)
	}
	if bobType != "unresolved" {
		t.Errorf("bob principal_type after partial re-ingest: got %q want unresolved (updated in place)", bobType)
	}
}

func strPtr(s string) *string { return &s }
