package handlers

// PAT-1613 — issued reports are frozen, hashed evidence.
//
// These tests exercise migrations/0126_report_records_issuance_integrity.sql
// itself rather than a hand-copied imitation of it: the isolated schema is
// built with the minimal 0052/0059/0082 shape of report_records, then the real
// migration file is applied on top. A guard is only worth what the shipped
// text does, and a copied trigger in a test proves nothing about the file that
// reaches patched-api-01 (the PAT-1041 shape: a check that passes without
// having checked the thing).
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as internal/intune/postgres_store_test.go.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1613Schema = "pat1613_report_issuance_test"

// pat1613Pool builds the isolated schema and applies the real 0126 migration.
func pat1613Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report issuance test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1613Schema + ",public"
	// Simple protocol so the multi-statement migration file can be executed
	// as one script, the way psql applies it in production.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1613Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1613Schema,
		`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)`,
		`CREATE TABLE tenants (id UUID PRIMARY KEY DEFAULT gen_random_uuid())`,
		// Mirrors report_records as 0052 created it, plus the columns 0059
		// (source), 0082 (schedule_slot), and 0148 (report_type) added.
		// Everything 0126 touches is added by 0126 itself, below.
		`CREATE TABLE report_records (
			id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			schedule_id        UUID,
			name               TEXT        NOT NULL,
			generated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			period_start       DATE,
			period_end         DATE,
			pdf_path           TEXT,
			xlsx_path          TEXT,
			recipient_summary  JSONB       NOT NULL DEFAULT '[]',
			delivery_status    TEXT        NOT NULL DEFAULT 'pending'
			                               CHECK (delivery_status IN ('pending','sent','failed')),
			archived           BOOLEAN     NOT NULL DEFAULT FALSE,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			source             TEXT        NOT NULL DEFAULT 'admin'
			                               CHECK (source IN ('admin','portal')),
			schedule_slot      TIMESTAMPTZ,
			report_type        TEXT        NOT NULL DEFAULT 'executive-summary'
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1613Schema+` CASCADE`)
	})

	applyMigrationFile(t, pool, "../../migrations/0126_report_records_issuance_integrity.sql")
	// PAT-2405: storeReportRecord's finalising UPDATE also sets csv_path and
	// csv_sha256, which 0227 adds.
	applyMigrationFile(t, pool, "../../migrations/0227_report_records_csv.sql")
	return pool
}

func applyMigrationFile(t *testing.T, pool *pgxpool.Pool, path string) {
	t.Helper()
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

func pat1613Tenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

// pat1613Issue walks a row through the real lifecycle: inserted empty to claim
// a UUID, then finalised by the single UPDATE that storeReportFiles runs once
// the bytes are on disk. It returns the issued row's id.
func pat1613Issue(t *testing.T, pool *pgxpool.Pool, tenantID, name string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name, recipient_summary, source)
		VALUES ($1::uuid, $2, '[]', 'admin')
		RETURNING id::text
	`, tenantID, name).Scan(&id); err != nil {
		t.Fatalf("insert placeholder: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE report_records
		SET pdf_path          = $2,
		    pdf_sha256        = $3,
		    coverage_snapshot = $4::jsonb,
		    delivery_status   = 'pending',
		    issued_at         = now()
		WHERE id = $1::uuid
	`, id, name+".pdf",
		"1111111111111111111111111111111111111111111111111111111111111111",
		`{"devices_total": 42}`); err != nil {
		t.Fatalf("finalise (issue) row: %v", err)
	}
	return id
}

// TestReportRecords0126_PreIssuanceWritesStillWork pins the boundary at the
// bottom: the generation path must keep working. A guard that also blocked the
// finalising UPDATE would make every report generation fail, so this is the
// case that proves the freeze starts at issuance and not at INSERT.
func TestReportRecords0126_PreIssuanceWritesStillWork(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)

	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name) VALUES ($1::uuid, 'draft')
		RETURNING id::text
	`, tenantID).Scan(&id); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Repeated, arbitrary writes are fine while issued_at is NULL.
	for _, q := range []string{
		`UPDATE report_records SET name = 'draft 2' WHERE id = $1::uuid`,
		`UPDATE report_records SET pdf_path = 'a.pdf' WHERE id = $1::uuid`,
		`UPDATE report_records SET delivery_status = 'failed' WHERE id = $1::uuid`,
		`UPDATE report_records SET issued_at = now() WHERE id = $1::uuid`,
	} {
		if _, err := pool.Exec(ctx, q, id); err != nil {
			t.Fatalf("pre-issuance update %q rejected: %v", q, err)
		}
	}

	// ...and the last of those issued it, so the next write must fail.
	if _, err := pool.Exec(ctx,
		`UPDATE report_records SET name = 'after' WHERE id = $1::uuid`, id); err == nil {
		t.Fatal("want post-issuance UPDATE rejected, got nil error")
	}
}

// TestReportRecords0126_IssuedEvidenceCannotBeEdited is the ticket's core
// promise: once a report is issued, the file it points at, the hash that proves
// the file, the delivery status and the frozen coverage figure are all beyond
// editing. Each is asserted separately so a partial regression cannot hide
// behind another column still being covered.
func TestReportRecords0126_IssuedEvidenceCannotBeEdited(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	id := pat1613Issue(t, pool, tenantID, "issued")

	for _, tc := range []struct {
		name string
		q    string
	}{
		{"pdf_path", `UPDATE report_records SET pdf_path = 'swapped.pdf' WHERE id = $1::uuid`},
		{"pdf_sha256", `UPDATE report_records SET pdf_sha256 = '` + strings.Repeat("a", 64) + `' WHERE id = $1::uuid`},
		{"delivery_status", `UPDATE report_records SET delivery_status = 'sent' WHERE id = $1::uuid`},
		{"coverage_snapshot", `UPDATE report_records SET coverage_snapshot = '{"devices_total": 9000}' WHERE id = $1::uuid`},
		{"issued_at", `UPDATE report_records SET issued_at = now() WHERE id = $1::uuid`},
		{"archived", `UPDATE report_records SET archived = TRUE WHERE id = $1::uuid`},
		{"name", `UPDATE report_records SET name = 'renamed' WHERE id = $1::uuid`},
		// A statement that changes nothing is still a write against frozen
		// evidence, and is rejected: the guard allows one transition, not
		// "anything that happens to be harmless".
		{"no-op", `UPDATE report_records SET name = name WHERE id = $1::uuid`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tc.q, id)
			if err == nil {
				t.Fatalf("want %s UPDATE rejected on an issued row, got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), "immutable") {
				t.Errorf("error = %v, want it to say the row is immutable", err)
			}
		})
	}

	// The row still reads exactly as issued.
	var pdfPath, status string
	var coverage []byte
	if err := pool.QueryRow(ctx, `
		SELECT pdf_path, delivery_status, coverage_snapshot FROM report_records WHERE id = $1::uuid
	`, id).Scan(&pdfPath, &status, &coverage); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if pdfPath != "issued.pdf" || status != "pending" {
		t.Errorf("row = (%q, %q), want (issued.pdf, pending)", pdfPath, status)
	}
	var snap map[string]any
	if err := json.Unmarshal(coverage, &snap); err != nil {
		t.Fatalf("coverage_snapshot not JSON: %v", err)
	}
	if got := snap["devices_total"]; got != float64(42) {
		t.Errorf("frozen devices_total = %v, want 42", got)
	}
}

// TestReportRecords0126_SupersessionIsTheOnlyPermittedMutation covers the one
// exception, and its edges: the forward link may be set once from NULL, alone,
// and bundling any other change into that same statement is still rejected.
// The bundling case is the one worth having — a guard that only checked "is
// superseded_by_report_id being set?" would wave through an UPDATE that also
// rewrote pdf_path.
func TestReportRecords0126_SupersessionIsTheOnlyPermittedMutation(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)

	original := pat1613Issue(t, pool, tenantID, "original")

	// A correction is a NEW row that points back at the report it replaces.
	var correction string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name, supersedes_report_id)
		VALUES ($1::uuid, 'correction', $2::uuid)
		RETURNING id::text
	`, tenantID, original).Scan(&correction); err != nil {
		t.Fatalf("insert correction: %v", err)
	}

	// Bundling anything else with the allowed field is rejected.
	if _, err := pool.Exec(ctx, `
		UPDATE report_records
		SET superseded_by_report_id = $2::uuid, pdf_path = 'swapped.pdf'
		WHERE id = $1::uuid
	`, original, correction); err == nil {
		t.Fatal("want bundled supersession + pdf_path UPDATE rejected, got nil error")
	}
	// Even bundling a second harmless-looking field is rejected.
	if _, err := pool.Exec(ctx, `
		UPDATE report_records
		SET superseded_by_report_id = $2::uuid, name = 'original (superseded)'
		WHERE id = $1::uuid
	`, original, correction); err == nil {
		t.Fatal("want bundled supersession + name UPDATE rejected, got nil error")
	}

	// The link on its own is accepted.
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = $2::uuid WHERE id = $1::uuid
	`, original, correction); err != nil {
		t.Fatalf("want lone supersession link accepted, got: %v", err)
	}

	// Once set it is settled: neither re-pointing nor clearing is allowed.
	var third string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name) VALUES ($1::uuid, 'third') RETURNING id::text
	`, tenantID).Scan(&third); err != nil {
		t.Fatalf("insert third: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = $2::uuid WHERE id = $1::uuid
	`, original, third); err == nil {
		t.Fatal("want re-pointing superseded_by_report_id rejected, got nil error")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = NULL WHERE id = $1::uuid
	`, original); err == nil {
		t.Fatal("want clearing superseded_by_report_id rejected, got nil error")
	}

	var linked string
	if err := pool.QueryRow(ctx, `
		SELECT superseded_by_report_id::text FROM report_records WHERE id = $1::uuid
	`, original).Scan(&linked); err != nil {
		t.Fatalf("read back link: %v", err)
	}
	if linked != correction {
		t.Errorf("superseded_by_report_id = %s, want %s", linked, correction)
	}
}

// TestReportRecords0126_SupersessionChainIsOneToOne: two corrections claiming
// the same original is a contradiction about which document replaced it, so the
// partial unique index has to reject the second.
func TestReportRecords0126_SupersessionChainIsOneToOne(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	original := pat1613Issue(t, pool, tenantID, "original")

	if _, err := pool.Exec(ctx, `
		INSERT INTO report_records (tenant_id, name, supersedes_report_id)
		VALUES ($1::uuid, 'correction one', $2::uuid)
	`, tenantID, original); err != nil {
		t.Fatalf("first correction: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO report_records (tenant_id, name, supersedes_report_id)
		VALUES ($1::uuid, 'correction two', $2::uuid)
	`, tenantID, original); err == nil {
		t.Fatal("want a second correction of the same report rejected, got nil error")
	}
}

// TestReportRecords0126_MalformedHashRejected: a digest that is not a SHA-256
// is worse than no digest, because it presents as verifiable evidence and is
// not.
func TestReportRecords0126_MalformedHashRejected(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)

	for _, bad := range []string{"", "not-a-hash", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO report_records (tenant_id, name, pdf_sha256) VALUES ($1::uuid, 'bad', $2)
		`, tenantID, bad); err == nil {
			t.Errorf("want pdf_sha256 = %q rejected, got nil error", bad)
		}
	}
}

// TestReportRecords0126_TenantDeleteStillCascades guards the self-reference's
// delete behaviour. ON DELETE SET NULL on the supersession columns would make
// the FK machinery issue an UPDATE against an issued row, which this
// migration's own trigger rejects - deadlocking tenant deletion against a
// guard added to protect it. Cheap to assert, expensive to discover on a
// purge.
func TestReportRecords0126_TenantDeleteStillCascades(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)

	original := pat1613Issue(t, pool, tenantID, "original")
	var correction string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name, supersedes_report_id)
		VALUES ($1::uuid, 'correction', $2::uuid) RETURNING id::text
	`, tenantID, original).Scan(&correction); err != nil {
		t.Fatalf("insert correction: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = $2::uuid WHERE id = $1::uuid
	`, original, correction); err != nil {
		t.Fatalf("link correction: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("tenant delete blocked by the supersession FKs: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM report_records`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Errorf("report_records after tenant delete = %d, want 0", remaining)
	}
}

// TestReportRecords0126_RollbackRestoresMutability applies the rollback file to
// the same schema and proves it actually undoes the guard. A rollback that
// drops the columns while leaving the trigger behind would leave every UPDATE
// failing on a function referencing a column that no longer exists.
func TestReportRecords0126_RollbackRestoresMutability(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	id := pat1613Issue(t, pool, tenantID, "issued")

	applyMigrationFile(t, pool, "../../migrations/0126_report_records_issuance_integrity_rollback.sql")

	if _, err := pool.Exec(ctx,
		`UPDATE report_records SET name = 'editable again' WHERE id = $1::uuid`, id); err != nil {
		t.Fatalf("UPDATE after rollback: %v", err)
	}
	var present int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)::int FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'report_records'
		  AND column_name IN ('pdf_sha256','xlsx_sha256','issued_at','coverage_snapshot',
		                      'supersedes_report_id','superseded_by_report_id')
	`, pat1613Schema).Scan(&present); err != nil {
		t.Fatalf("column check: %v", err)
	}
	if present != 0 {
		t.Errorf("%d PAT-1613 columns survive the rollback, want 0", present)
	}
	var version int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)::int FROM schema_migrations WHERE version = '0126_report_records_issuance_integrity'
	`).Scan(&version); err != nil {
		t.Fatalf("schema_migrations check: %v", err)
	}
	if version != 0 {
		t.Error("rollback left the 0126 schema_migrations row in place")
	}
}

// ─── Source-text guards ───────────────────────────────────────────────────────

// TestReportRecords0126_GuardComparesTheWholeRow pins the two properties of the
// trigger that a later edit is most likely to erode and that no single
// behavioural test would notice: that it compares the whole row rather than an
// allowlist of protected columns (an allowlist silently stops covering the next
// column added), and that it keeps 0109's hardened search_path.
func TestReportRecords0126_GuardComparesTheWholeRow(t *testing.T) {
	sql, err := os.ReadFile("../../migrations/0126_report_records_issuance_integrity.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"LANGUAGE plpgsql SET search_path = pg_catalog, public",
		"(to_jsonb(NEW) - 'superseded_by_report_id')",
		"IS NOT DISTINCT FROM (to_jsonb(OLD) - 'superseded_by_report_id')",
		"IF OLD.issued_at IS NULL THEN",
	} {
		if !strings.Contains(string(sql), required) {
			t.Errorf("0126 no longer contains %q", required)
		}
	}
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

func TestHashReportBytes(t *testing.T) {
	if got := hashReportBytes(nil); got != nil {
		t.Errorf("hashReportBytes(nil) = %v, want nil — no artefact means no digest", *got)
	}
	if got := hashReportBytes([]byte{}); got != nil {
		t.Errorf("hashReportBytes(empty) = %v, want nil", *got)
	}
	got := hashReportBytes([]byte("abc"))
	if got == nil {
		t.Fatal("hashReportBytes(abc) = nil, want a digest")
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if *got != want {
		t.Errorf("hashReportBytes(abc) = %s, want %s", *got, want)
	}
	// Lower-case hex, exactly as the column's CHECK constraint requires.
	if _, err := hex.DecodeString(*got); err != nil || *got != strings.ToLower(*got) || len(*got) != 64 {
		t.Errorf("digest %q is not the 64-char lower-case hex the column accepts", *got)
	}
}
