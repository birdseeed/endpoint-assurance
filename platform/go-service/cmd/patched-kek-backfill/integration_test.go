//go:build integration

// PAT-1697: DB-gated integration tests for the kek-backfill operator tool.
//
// These live in this package (main), not go-service/integration/, because
// backfillColumn, run and the column type are unexported: go-service/integration
// is a separate package and cannot call them without exporting internals well
// beyond what this ticket's "minimal, behaviour-preserving" extraction scope
// allows. This mirrors the existing same-package DB-test convention already
// used for another cmd/ binary — see cmd/patched-cve-sync/checkpoint_test.go.
//
// Convention matched to go-service/integration/helpers_test.go and
// .github/workflows/go-integration-test.yml: TEST_DATABASE_URL selects the
// throwaway Postgres 16 instance, TestMain applies every migrations/*.sql file
// (skipping this run entirely, exit 0, if the env var is unset), and the
// `integration` build tag keeps this file out of the default `go test ./...`.
//
// Wired into go-integration-test.yml as its own "cmd/patched-kek-backfill
// DB-gated tests" step, after "integration tests". It cannot reuse that
// step's patched_test database: this package's TestMain re-applies every
// migrations/*.sql file from scratch (no IF NOT EXISTS guard), so it needs a
// fresh database of its own on the same Postgres service container — the
// step creates patched_kek_backfill_test and points TEST_DATABASE_URL at it
// for that step only. Run locally the same way, against your own throwaway
// database:
//
//	createdb patched_kek_backfill_test_local
//	TEST_DATABASE_URL=postgres://.../patched_kek_backfill_test_local?sslmode=disable \
//	  go test -tags=integration -count=1 -v ./cmd/patched-kek-backfill/...
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/envelope"
)

var testPool *pgxpool.Pool

// Tests that invoke run bridge the test-selected DSN into DATABASE_URL with
// t.Setenv because the production command intentionally reads DATABASE_URL.
func TestMain(m *testing.M) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "TEST_DATABASE_URL not set — skipping patched-kek-backfill integration tests")
		os.Exit(0)
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := applyMigrations(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "migrations: %v\n", err)
		os.Exit(1)
	}

	testPool = pool
	os.Exit(m.Run())
}

// applyMigrations mirrors go-service/integration/helpers_test.go's function of
// the same name: apply every forward migrations/*.sql file in order.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrationsDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, "_rollback.sql") {
			continue
		}
		files = append(files, filepath.Join(migrationsDir, name))
	}
	sort.Strings(files)
	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		if err := execMigration(ctx, pool, string(sql)); err != nil {
			return fmt.Errorf("exec %s: %w", f, err)
		}
	}
	return nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// randomKEK returns a fresh base64-encoded 32-byte KEK, suitable for
// PATCHED_KEK.
func randomKEK(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// insertTestTenant inserts a minimal tenants row and registers cleanup.
// tenant_credentials, tenant_ca and tenant_webhooks all reference
// tenants(id) ON DELETE CASCADE, so deleting the tenant cleans up everything
// created against it.
func insertTestTenant(t *testing.T, pool *pgxpool.Pool, name string, hmacSecret []byte) string {
	t.Helper()
	ctx := context.Background()
	var id string
	bearerHash := make([]byte, 32)
	_, _ = rand.Read(bearerHash)
	err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name, bearer_token_hash, hmac_secret) VALUES ($1, $2, $3) RETURNING id::text`,
		name, bearerHash, hmacSecret,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, id); err != nil {
			t.Errorf("cleanup tenant %s: %v", id, err)
		}
	})
	return id
}

func insertTenantCredentials(t *testing.T, pool *pgxpool.Pool, tenantID string, hmacSecret []byte) string {
	t.Helper()
	ctx := context.Background()
	var id string
	bearerHash := make([]byte, 32)
	_, _ = rand.Read(bearerHash)
	err := pool.QueryRow(ctx,
		`INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		tenantID, bearerHash, hmacSecret,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert tenant_credentials: %v", err)
	}
	return id
}

func insertTenantCA(t *testing.T, pool *pgxpool.Pool, tenantID string, caKeyPEM string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO tenant_ca (tenant_id, ca_cert_pem, ca_key_pem) VALUES ($1::uuid, $2, $3)`,
		tenantID, "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n", caKeyPEM,
	)
	if err != nil {
		t.Fatalf("insert tenant_ca: %v", err)
	}
}

func insertTenantWebhook(t *testing.T, pool *pgxpool.Pool, tenantID string, secret string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO tenant_webhooks (tenant_id, url, secret) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		tenantID, "https://example.test/webhook", secret,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert tenant_webhooks: %v", err)
	}
	return id
}

func readColumnText(t *testing.T, pool *pgxpool.Pool, table, col, pk, pkVal string) string {
	t.Helper()
	var v string
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = $1::uuid`, col, table, pk) //nolint:gosec // test-controlled identifiers
	if err := pool.QueryRow(context.Background(), q, pkVal).Scan(&v); err != nil {
		t.Fatalf("read %s.%s: %v", table, col, err)
	}
	return v
}

func readColumnBytes(t *testing.T, pool *pgxpool.Pool, table, col, pk, pkCast, pkVal string) []byte {
	t.Helper()
	var v []byte
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = $1::%s`, col, table, pk, pkCast) //nolint:gosec // test-controlled identifiers
	if err := pool.QueryRow(context.Background(), q, pkVal).Scan(&v); err != nil {
		t.Fatalf("read %s.%s: %v", table, col, err)
	}
	return v
}

// --------------------------------------------------------------------------
// Case: empty table. Runs first, against the freshly migrated (and hence
// still empty) tenant_webhooks table, before any other test in this file
// inserts rows.
// --------------------------------------------------------------------------

func TestBackfillColumn_EmptyTable(t *testing.T) {
	ctx := context.Background()
	c := column{table: "tenant_webhooks", col: "secret", pk: "id", pkCast: "uuid", bytea: false}
	scanned, updated, err := backfillColumn(ctx, testPool, newTestEnvelope(t), c)
	if err != nil {
		t.Fatalf("backfillColumn on empty table: %v", err)
	}
	if scanned != 0 || updated != 0 {
		t.Fatalf("empty table: got scanned=%d updated=%d, want 0/0", scanned, updated)
	}
}

// --------------------------------------------------------------------------
// Case: plaintext encrypted, marked, round-trips; all four real columns.
// --------------------------------------------------------------------------

func TestRun_RoundTrip_AllFourColumns(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	kekB64 := randomKEK(t)
	t.Setenv("PATCHED_KEK", kekB64)
	t.Setenv("DATABASE_URL", dbURL)

	kekRaw, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		t.Fatalf("decode kek: %v", err)
	}
	verifyEnv, err := envelope.New(kekRaw)
	if err != nil {
		t.Fatalf("envelope.New: %v", err)
	}

	tenantHMAC := []byte("tenants-hmac-secret-plaintext-0123456789")
	tenant := insertTestTenant(t, testPool, "pat1697-roundtrip", tenantHMAC)

	credHMAC := []byte("tenant-credentials-hmac-secret-abcdefgh")
	credID := insertTenantCredentials(t, testPool, tenant, credHMAC)

	caKey := "synthetic-ca-key-text:fixture-ca-key\n"
	insertTenantCA(t, testPool, tenant, caKey)

	webhookSecret := "whsec_roundtrip_fixture_value"
	webhookID := insertTenantWebhook(t, testPool, tenant, webhookSecret)

	if err := run(context.Background(), quietLogger()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// tenants.hmac_secret (BYTEA)
	got := readColumnBytes(t, testPool, "tenants", "hmac_secret", "id", "uuid", tenant)
	if !isEncrypted(got) {
		t.Fatalf("tenants.hmac_secret not marked: %q", got)
	}
	dec, err := verifyEnv.DecryptBytes(got)
	if err != nil || string(dec) != string(tenantHMAC) {
		t.Fatalf("tenants.hmac_secret round-trip: got %q (err %v), want %q", dec, err, tenantHMAC)
	}

	// tenant_credentials.hmac_secret (BYTEA)
	got = readColumnBytes(t, testPool, "tenant_credentials", "hmac_secret", "id", "bigint", credID)
	if !isEncrypted(got) {
		t.Fatalf("tenant_credentials.hmac_secret not marked: %q", got)
	}
	dec, err = verifyEnv.DecryptBytes(got)
	if err != nil || string(dec) != string(credHMAC) {
		t.Fatalf("tenant_credentials.hmac_secret round-trip: got %q (err %v), want %q", dec, err, credHMAC)
	}

	// tenant_ca.ca_key_pem (TEXT)
	gotText := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if !isEncrypted([]byte(gotText)) {
		t.Fatalf("tenant_ca.ca_key_pem not marked: %q", gotText)
	}
	decText, err := verifyEnv.DecryptString(gotText)
	if err != nil || decText != caKey {
		t.Fatalf("tenant_ca.ca_key_pem round-trip: got %q (err %v), want %q", decText, err, caKey)
	}

	// tenant_webhooks.secret (TEXT)
	gotText = readColumnText(t, testPool, "tenant_webhooks", "secret", "id", webhookID)
	if !isEncrypted([]byte(gotText)) {
		t.Fatalf("tenant_webhooks.secret not marked: %q", gotText)
	}
	decText, err = verifyEnv.DecryptString(gotText)
	if err != nil || decText != webhookSecret {
		t.Fatalf("tenant_webhooks.secret round-trip: got %q (err %v), want %q", decText, err, webhookSecret)
	}
}

// --------------------------------------------------------------------------
// Case: already-marked value skipped, byte-identical; running twice gives
// the same DB state as running once.
// --------------------------------------------------------------------------

func TestRun_IdempotentDoubleRun_AlreadyMarkedSkippedByteIdentical(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	kekB64 := randomKEK(t)
	t.Setenv("PATCHED_KEK", kekB64)
	t.Setenv("DATABASE_URL", dbURL)

	kekRaw, _ := base64.StdEncoding.DecodeString(kekB64)
	env, err := envelope.New(kekRaw)
	if err != nil {
		t.Fatalf("envelope.New: %v", err)
	}

	tenant := insertTestTenant(t, testPool, "pat1697-idempotent", []byte("plain-tenant-hmac"))

	// One already-marked webhook secret (pre-encrypted outside the backfill).
	preEncrypted, err := env.EncryptString("already-encrypted-webhook-secret")
	if err != nil {
		t.Fatalf("pre-encrypt: %v", err)
	}
	markedWebhookID := insertTenantWebhook(t, testPool, tenant, preEncrypted)

	// One still-plaintext CA key, to exercise a real encryption during run #1.
	caKey := "synthetic-ca-key-text:fixture-idempotent\n"
	insertTenantCA(t, testPool, tenant, caKey)

	if err := run(context.Background(), quietLogger()); err != nil {
		t.Fatalf("run #1: %v", err)
	}

	afterFirstWebhook := readColumnText(t, testPool, "tenant_webhooks", "secret", "id", markedWebhookID)
	if afterFirstWebhook != preEncrypted {
		t.Fatalf("already-marked value changed by run #1: got %q, want byte-identical %q", afterFirstWebhook, preEncrypted)
	}
	afterFirstCA := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if !isEncrypted([]byte(afterFirstCA)) {
		t.Fatalf("plaintext CA key not encrypted by run #1: %q", afterFirstCA)
	}
	afterFirstTenantHMAC := readColumnBytes(t, testPool, "tenants", "hmac_secret", "id", "uuid", tenant)

	if err := run(context.Background(), quietLogger()); err != nil {
		t.Fatalf("run #2: %v", err)
	}

	afterSecondWebhook := readColumnText(t, testPool, "tenant_webhooks", "secret", "id", markedWebhookID)
	afterSecondCA := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	afterSecondTenantHMAC := readColumnBytes(t, testPool, "tenants", "hmac_secret", "id", "uuid", tenant)

	if afterSecondWebhook != afterFirstWebhook {
		t.Fatalf("run #2 changed already-marked webhook secret: %q -> %q", afterFirstWebhook, afterSecondWebhook)
	}
	if afterSecondCA != afterFirstCA {
		t.Fatalf("run #2 changed already-marked CA key: %q -> %q", afterFirstCA, afterSecondCA)
	}
	if string(afterSecondTenantHMAC) != string(afterFirstTenantHMAC) {
		t.Fatalf("run #2 changed already-marked tenants.hmac_secret: %q -> %q", afterFirstTenantHMAC, afterSecondTenantHMAC)
	}
}

// --------------------------------------------------------------------------
// PAT-1711: a marked-but-corrupt value is refused, not guessed at. isEncrypted
// is a pure prefix check, so a value carrying the Marker prefix that is not
// otherwise valid envelope ciphertext still counts as "already encrypted" and
// is never rewritten — but backfillColumn now verify-decrypts every marked
// value with the loaded KEK and reports (by table, column and row id) any
// that fail, via a *verifyError, rather than silently treating them as done.
// --------------------------------------------------------------------------

func TestBackfillColumn_MarkedButCorrupt_ReportedByIDLeftUntouchedOthersStillProcessed(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)

	corruptTenant := insertTestTenant(t, testPool, "pat1711-corrupt-marker", []byte("plain"))
	corrupt := envelope.Marker + "this-is-not-valid-base64-ciphertext!!!"
	insertTenantCA(t, testPool, corruptTenant, corrupt)

	// Another row in the same column, still plaintext: it must still get
	// backfilled despite the corrupt row sitting alongside it.
	plainTenant := insertTestTenant(t, testPool, "pat1711-corrupt-marker-sibling", []byte("plain"))
	plainKey := "synthetic-ca-key-text:sibling-still-processed\n"
	insertTenantCA(t, testPool, plainTenant, plainKey)

	c := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
	scanned, updated, err := backfillColumn(ctx, testPool, env, c)

	// The process/function returns an error naming the failing row.
	if err == nil {
		t.Fatal("expected backfillColumn to return an error for the marked-but-corrupt row")
	}
	var ve *verifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a *verifyError, got %T: %v", err, err)
	}
	if len(ve.rows) != 1 || !strings.Contains(ve.rows[0], corruptTenant) {
		t.Fatalf("verifyError rows = %v, want exactly one entry naming tenant %s", ve.rows, corruptTenant)
	}
	if !strings.Contains(ve.rows[0], "tenant_ca") || !strings.Contains(ve.rows[0], "ca_key_pem") {
		t.Fatalf("verifyError row %q should name table and column", ve.rows[0])
	}
	if !strings.Contains(err.Error(), corruptTenant) {
		t.Fatalf("error message %q should name the failing row's id", err.Error())
	}

	// scanned covers both rows; updated covers only the plaintext sibling —
	// the corrupt marked row is never rewritten.
	if scanned != 2 || updated != 1 {
		t.Fatalf("got scanned=%d updated=%d, want 2/1", scanned, updated)
	}

	// Left byte-identical.
	got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", corruptTenant)
	if got != corrupt {
		t.Fatalf("corrupt marked value should be left untouched: got %q, want %q", got, corrupt)
	}
	if _, err := env.DecryptString(got); err == nil {
		t.Fatal("expected the corrupt-but-marked value to still fail decryption")
	}

	// Other rows in the same column are still processed: the plaintext
	// sibling was backfilled despite the corrupt row's presence.
	gotPlain := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", plainTenant)
	if !isEncrypted([]byte(gotPlain)) {
		t.Fatalf("sibling plaintext row not backfilled: got %q", gotPlain)
	}
	decPlain, err := env.DecryptString(gotPlain)
	if err != nil || decPlain != plainKey {
		t.Fatalf("sibling round-trip: got %q (err %v), want %q", decPlain, err, plainKey)
	}
}

// --------------------------------------------------------------------------
// PAT-1711: a validly encrypted marked row passes verify cleanly — no error,
// left untouched.
// --------------------------------------------------------------------------

func TestBackfillColumn_ValidlyEncryptedRowPassesVerify(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)

	tenant := insertTestTenant(t, testPool, "pat1711-valid-marker", []byte("plain"))
	plaintext := "synthetic-ca-key-text:valid-marker\n"
	enc, err := env.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("pre-encrypt: %v", err)
	}
	insertTenantCA(t, testPool, tenant, enc)

	c := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
	scanned, updated, err := backfillColumn(ctx, testPool, env, c)
	if err != nil {
		t.Fatalf("backfillColumn: unexpected error for a validly encrypted row: %v", err)
	}
	if scanned != 1 || updated != 0 {
		t.Fatalf("got scanned=%d updated=%d, want 1/0 (left as already-encrypted, not rewritten)", scanned, updated)
	}

	got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if got != enc {
		t.Fatalf("validly encrypted value should be left byte-identical: got %q, want %q", got, enc)
	}
}

// --------------------------------------------------------------------------
// PAT-1711: a value encrypted under a different KEK fails verify — it is
// marked (carries the Marker) but this run's KEK cannot decrypt it.
// --------------------------------------------------------------------------

func TestBackfillColumn_EncryptedUnderDifferentKEKFailsVerify(t *testing.T) {
	ctx := context.Background()
	runKEK := newTestEnvelope(t)
	otherKEK := newTestEnvelope(t)

	tenant := insertTestTenant(t, testPool, "pat1711-wrong-kek", []byte("plain"))
	plaintext := "synthetic-ca-key-text:wrong-kek\n"
	enc, err := otherKEK.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("pre-encrypt under other KEK: %v", err)
	}
	insertTenantCA(t, testPool, tenant, enc)

	c := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
	scanned, updated, err := backfillColumn(ctx, testPool, runKEK, c)

	var ve *verifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a *verifyError for a value encrypted under a different KEK, got %T: %v", err, err)
	}
	if len(ve.rows) != 1 || !strings.Contains(ve.rows[0], tenant) {
		t.Fatalf("verifyError rows = %v, want exactly one entry naming tenant %s", ve.rows, tenant)
	}
	if scanned != 1 || updated != 0 {
		t.Fatalf("got scanned=%d updated=%d, want 1/0 (left untouched, not rewritten)", scanned, updated)
	}

	got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if got != enc {
		t.Fatalf("value should be left byte-identical: got %q, want %q", got, enc)
	}
}

// --------------------------------------------------------------------------
// Case: a failure partway through a column rolls back that column entirely.
// --------------------------------------------------------------------------

func TestBackfillColumn_PartialFailureRollsBackWholeColumn(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)

	shortPlain := "short-ca-key"
	longPlain := strings.Repeat("x", 200) // still plaintext-short, but its ciphertext (base64 + envelope overhead) is much longer

	shortEnc, err := env.EncryptString(shortPlain)
	if err != nil {
		t.Fatalf("measure short ciphertext: %v", err)
	}
	longEnc, err := env.EncryptString(longPlain)
	if err != nil {
		t.Fatalf("measure long ciphertext: %v", err)
	}
	if len(longEnc) <= len(shortEnc) {
		t.Fatalf("test setup invariant broken: long ciphertext (%d) not longer than short (%d)", len(longEnc), len(shortEnc))
	}
	threshold := (len(shortEnc) + len(longEnc)) / 2
	// The constraint is validated against the table's current (plaintext)
	// values the moment it is added, before any encryption runs — so every
	// plaintext value, including longPlain, must already satisfy it.
	if len(longPlain) >= threshold {
		t.Fatalf("test setup invariant broken: longPlain length (%d) must be below threshold (%d) so ADD CONSTRAINT succeeds against the pre-encryption plaintext", len(longPlain), threshold)
	}

	tenantA := insertTestTenant(t, testPool, "pat1697-rollback-a", []byte("plain"))
	tenantB := insertTestTenant(t, testPool, "pat1697-rollback-b", []byte("plain"))
	tenantC := insertTestTenant(t, testPool, "pat1697-rollback-c", []byte("plain"))
	insertTenantCA(t, testPool, tenantA, shortPlain)
	insertTenantCA(t, testPool, tenantB, shortPlain)
	insertTenantCA(t, testPool, tenantC, longPlain) // this one's ciphertext will violate the constraint

	const constraintName = "pat1697_ca_key_len_chk"
	_, err = testPool.Exec(ctx, fmt.Sprintf(
		`ALTER TABLE tenant_ca ADD CONSTRAINT %s CHECK (length(ca_key_pem) <= %d)`, constraintName, threshold))
	if err != nil {
		t.Fatalf("add check constraint: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(),
			fmt.Sprintf(`ALTER TABLE tenant_ca DROP CONSTRAINT IF EXISTS %s`, constraintName)); err != nil {
			t.Errorf("drop check constraint: %v", err)
		}
	})

	c := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
	_, _, err = backfillColumn(ctx, testPool, env, c)
	if err == nil {
		t.Fatal("expected backfillColumn to fail once the constraint rejects the long row's ciphertext")
	}

	// Whole-column rollback: every row in the column, not just the failing
	// one, must still hold its original plaintext.
	for _, tt := range []struct {
		tenant, want string
	}{
		{tenantA, shortPlain},
		{tenantB, shortPlain},
		{tenantC, longPlain},
	} {
		got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tt.tenant)
		if got != tt.want {
			t.Fatalf("tenant %s: ca_key_pem = %q, want unchanged plaintext %q (partial commit leaked past rollback)", tt.tenant, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Case: missing or invalid PATCHED_KEK aborts before any write.
// --------------------------------------------------------------------------

func TestRun_MissingKEK_AbortsBeforeAnyWrite(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("PATCHED_KEK", "")

	tenant := insertTestTenant(t, testPool, "pat1697-missing-kek", []byte("plain"))
	caKey := "synthetic-ca-key-text:untouched\n"
	insertTenantCA(t, testPool, tenant, caKey)

	err := run(context.Background(), quietLogger())
	if err == nil {
		t.Fatal("expected run to fail with PATCHED_KEK unset")
	}

	got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if got != caKey {
		t.Fatalf("row was written despite missing KEK: got %q, want unchanged %q", got, caKey)
	}
}

func TestRun_InvalidKEK_AbortsBeforeAnyWrite(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("PATCHED_KEK", "not-valid-base64!!!")

	tenant := insertTestTenant(t, testPool, "pat1697-invalid-kek", []byte("plain"))
	caKey := "synthetic-ca-key-text:untouched-invalid\n"
	insertTenantCA(t, testPool, tenant, caKey)

	err := run(context.Background(), quietLogger())
	if err == nil {
		t.Fatal("expected run to fail with an invalid PATCHED_KEK")
	}
	if !strings.Contains(err.Error(), envelope.EnvVar) {
		t.Fatalf("error should name %s: %v", envelope.EnvVar, err)
	}

	got := readColumnText(t, testPool, "tenant_ca", "ca_key_pem", "tenant_id", tenant)
	if got != caKey {
		t.Fatalf("row was written despite invalid KEK: got %q, want unchanged %q", got, caKey)
	}
}

// --------------------------------------------------------------------------
// Case: a NULL value in the target column is handled without a panic.
// tenant_webhooks.secret is NOT NULL in production; the constraint is
// relaxed here only for this throwaway test database to exercise the code
// path defensively.
// --------------------------------------------------------------------------

func TestBackfillColumn_NullValueDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)

	tenant := insertTestTenant(t, testPool, "pat1697-null-value", []byte("plain"))

	if _, err := testPool.Exec(ctx, `ALTER TABLE tenant_webhooks ALTER COLUMN secret DROP NOT NULL`); err != nil {
		t.Fatalf("relax NOT NULL: %v", err)
	}
	var webhookID string
	err := testPool.QueryRow(ctx,
		`INSERT INTO tenant_webhooks (tenant_id, url, secret) VALUES ($1::uuid, $2, NULL) RETURNING id::text`,
		tenant, "https://example.test/null-secret",
	).Scan(&webhookID)
	if err != nil {
		t.Fatalf("insert NULL secret row: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("backfillColumn panicked on a NULL column value: %v", r)
		}
	}()

	c := column{table: "tenant_webhooks", col: "secret", pk: "id", pkCast: "uuid", bytea: false}
	scanned, _, err := backfillColumn(ctx, testPool, env, c)
	if err != nil {
		t.Fatalf("backfillColumn with a NULL row: %v", err)
	}
	if scanned < 1 {
		t.Fatalf("expected the NULL row to be scanned, got scanned=%d", scanned)
	}
}

// execMigration applies one migration file. A file whose first line is
// "-- migrate:statement-by-statement" holds a statement that cannot run in a
// transaction block (CREATE INDEX CONCURRENTLY, PAT-2021 0167); a
// multi-statement Exec would run it in an implicit transaction, so such a
// file runs one statement at a time on one connection, the way psql -f does
// in deploy.sh. Statements end with ";" at the end of a line.
func execMigration(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	if !strings.HasPrefix(sql, "-- migrate:statement-by-statement") {
		_, err := pool.Exec(ctx, sql)
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var stmt strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		stmt.WriteString(line)
		stmt.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			if _, err := conn.Exec(ctx, stmt.String()); err != nil {
				return err
			}
			stmt.Reset()
		}
	}
	if strings.TrimSpace(stmt.String()) != "" {
		_, err := conn.Exec(ctx, stmt.String())
		return err
	}
	return nil
}
