package handlers

// PAT-1685 — two gaps left by PAT-1613 (migration 0126, PR #460): the
// generate handler had no way to issue a correction, and coverage_snapshot
// carried no findings figure to freeze alongside the coverage figures.
//
// These tests exercise the actual validation, storage and query functions the
// HTTP handlers call (validateSupersessionTarget, storeReportFiles,
// classifyReportRecordsPGError, tenantCVESeverityCounts, addFindingsSnapshot)
// rather than reproducing the whole report-generation pipeline (XLSX/PDF
// rendering needs a much larger device/compliance fixture set unrelated to
// this ticket) behind an HTTP round trip. GenerateReportHandler itself is a
// thin wrapper over exactly these functions, so this is the same contract the
// handler exposes.
//
// Reuses the pat1613 report_records + migration-0126 harness from
// report_issuance_db_test.go for the supersession tests. The findings tests
// build their own minimal devices/cve_feed_entries/device_cve_findings schema
// (pat1685FindingsPool) rather than reusing pat1201HandlerPool's, because that
// one's devices table has no "os" column and TenantCVEFindingsHandler's
// findings query (not just its severity_counts half) selects d.os.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as both harnesses above.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

func pat1685Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

const pat1685FindingsSchema = "pat1685_findings_test"

// pat1685FindingsPool builds a minimal devices/cve_feed_entries/device_cve_findings
// schema — just the columns TenantCVEFindingsHandler's two queries (severity_counts
// and the per-CVE findings list) read, including devices.os and
// cve_feed_entries.cpe_ranges, both absent from the narrower
// pat1201HandlerPool fixture used by the portal findings tests.
func pat1685FindingsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1685FindingsSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1685FindingsSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1685FindingsSchema,
		`CREATE TABLE tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id),
			hostname  TEXT,
			os        TEXT
		)`,
		`CREATE TABLE cve_feed_entries (
			cve_id        TEXT PRIMARY KEY,
			description   TEXT NOT NULL DEFAULT '',
			description_source TEXT NOT NULL DEFAULT '',
			cvss_v3_score NUMERIC(4,1),
			severity      TEXT,
			cpe_ranges    JSONB NOT NULL DEFAULT '[]'
		)`,
		`CREATE TABLE device_cve_findings (
			id               BIGSERIAL PRIMARY KEY,
			device_id        UUID NOT NULL REFERENCES devices(id),
			cve_id           TEXT NOT NULL REFERENCES cve_feed_entries(cve_id),
			app_name         TEXT NOT NULL,
			app_version      TEXT NOT NULL DEFAULT '',
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified',
			fixed_version    TEXT NOT NULL DEFAULT '',
			first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (device_id, cve_id, app_name)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1685FindingsSchema+` CASCADE`)
	})
	return pool
}

// pat1613PoolExtended opens a second connection into the schema pat1613Pool
// already built and migrated, using the ordinary (extended) query protocol.
// pat1613Pool pins DefaultQueryExecMode to SimpleProtocol so it can apply the
// migration file as one multi-statement script; reusing that same pool for a
// []byte query argument (coverage_snapshot's JSONB) sends it as a bytea-hex
// text literal under simple-protocol encoding, which Postgres then refuses to
// cast to jsonb — a test-harness quirk of that mode, not a production one (the
// real service pool never sets SimpleProtocol). storeReportFiles needs the
// ordinary protocol to bind coverage_snapshot the way production does.
func pat1613PoolExtended(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1613Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func assertSupersessionStatus(t *testing.T, err error, want int) {
	t.Helper()
	var sErr *supersessionError
	if !errors.As(err, &sErr) {
		t.Fatalf("error = %v, want a *supersessionError", err)
	}
	if sErr.status != want {
		t.Errorf("status = %d, want %d (msg: %s)", sErr.status, want, sErr.msg)
	}
}

// ─── Gap 1: validateSupersessionTarget ────────────────────────────────────────

func TestValidateSupersessionTarget(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantA := pat1613Tenant(t, pool)
	tenantB := pat1613Tenant(t, pool)

	if err := validateSupersessionTarget(ctx, pool, tenantA, ""); err != nil {
		t.Errorf("empty supersedes_report_id: want nil (today's behaviour), got %v", err)
	}

	assertSupersessionStatus(t,
		validateSupersessionTarget(ctx, pool, tenantA, "not-a-uuid"),
		http.StatusBadRequest)

	assertSupersessionStatus(t,
		validateSupersessionTarget(ctx, pool, tenantA, "00000000-0000-0000-0000-000000000000"),
		http.StatusNotFound)

	original := pat1613Issue(t, pool, tenantA, "original")

	// Cross-tenant must read exactly like unknown-id — never leak that the
	// report exists for someone else.
	assertSupersessionStatus(t,
		validateSupersessionTarget(ctx, pool, tenantB, original),
		http.StatusNotFound)

	var draftID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO report_records (tenant_id, name) VALUES ($1::uuid, 'draft') RETURNING id::text
	`, tenantA).Scan(&draftID); err != nil {
		t.Fatalf("insert draft: %v", err)
	}
	assertSupersessionStatus(t,
		validateSupersessionTarget(ctx, pool, tenantA, draftID),
		http.StatusNotFound)

	if err := validateSupersessionTarget(ctx, pool, tenantA, original); err != nil {
		t.Errorf("valid, unsuperseded target: want nil, got %v", err)
	}

	correction := pat1613Issue(t, pool, tenantA, "correction")
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = $2::uuid WHERE id = $1::uuid
	`, original, correction); err != nil {
		t.Fatalf("link correction: %v", err)
	}
	assertSupersessionStatus(t,
		validateSupersessionTarget(ctx, pool, tenantA, original),
		http.StatusConflict)
}

// ─── Gap 1: storeReportFiles ───────────────────────────────────────────────────

func TestStoreReportFilesSupersession(t *testing.T) {
	pool := pat1613Pool(t)
	extPool := pat1613PoolExtended(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	logger := pat1685Logger()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", root)

	original := pat1613Issue(t, pool, tenantID, "original")

	plain, err := storeReportFiles(ctx, extPool, tenantID, "plain", nil,
		report.ContentTypeFull, time.Time{}, time.Time{}, []byte("pdf-bytes"), nil,
		"admin", "executive-summary", logger, nil, nil, nil)
	if err != nil {
		t.Fatalf("storeReportFiles (omitted supersedes_report_id): %v", err)
	}
	if plain.SupersedesReportID != nil {
		t.Errorf("omitted param: SupersedesReportID = %v, want nil (today's behaviour unchanged)", *plain.SupersedesReportID)
	}

	supersedes := original
	correction, err := storeReportFiles(ctx, extPool, tenantID, "correction", nil,
		report.ContentTypeFull, time.Time{}, time.Time{}, []byte("pdf-bytes"), nil,
		"admin", "executive-summary", logger, nil, nil, &supersedes)
	if err != nil {
		t.Fatalf("storeReportFiles (success-with-link): %v", err)
	}
	if correction.SupersedesReportID == nil || *correction.SupersedesReportID != original {
		t.Fatalf("correction.SupersedesReportID = %v, want %s", correction.SupersedesReportID, original)
	}
	var linkedBy string
	if err := pool.QueryRow(ctx, `
		SELECT superseded_by_report_id::text FROM report_records WHERE id = $1::uuid
	`, original).Scan(&linkedBy); err != nil {
		t.Fatalf("read back original: %v", err)
	}
	if linkedBy != correction.ID {
		t.Errorf("original.superseded_by_report_id = %s, want %s", linkedBy, correction.ID)
	}

	// A second correction of the same already-superseded original is the race
	// defence-in-depth path (validateSupersessionTarget would normally catch
	// this earlier; this proves storeReportFiles itself refuses too).
	supersedesAgain := original
	_, err = storeReportFiles(ctx, extPool, tenantID, "second correction", nil,
		report.ContentTypeFull, time.Time{}, time.Time{}, []byte("pdf-bytes"), nil,
		"admin", "executive-summary", logger, nil, nil, &supersedesAgain)
	assertSupersessionStatus(t, err, http.StatusConflict)
}

// TestStoreReportFilesSupersessionLinkFailureRollsBackIssuance forces the
// forward-link step to fail AFTER the finalising (issuance) UPDATE has
// already succeeded, by directly pre-linking the target's
// superseded_by_report_id to a different, unrelated report between
// "validation" and this call — the exact race described in review: something
// else claims the target in the gap between validateSupersessionTarget's
// check and storeReportFiles's own write. Unlike the "second correction" case
// above, this does NOT collide with the partial unique index on
// supersedes_report_id (no other row claims the same value), so it is the
// finalising UPDATE's own transaction that must catch it via the link step
// and roll back — proving the two statements are no longer independent.
func TestStoreReportFilesSupersessionLinkFailureRollsBackIssuance(t *testing.T) {
	pool := pat1613Pool(t)
	extPool := pat1613PoolExtended(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	logger := pat1685Logger()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", root)

	original := pat1613Issue(t, pool, tenantID, "original")
	decoy := pat1613Issue(t, pool, tenantID, "decoy")

	// Simulate the lost race directly: original gets linked to something else
	// entirely (decoy never claims supersedes_report_id = original, so the
	// unique index is untouched — only original.superseded_by_report_id is
	// non-NULL, which is all the link step's WHERE clause checks).
	if _, err := pool.Exec(ctx, `
		UPDATE report_records SET superseded_by_report_id = $2::uuid WHERE id = $1::uuid
	`, original, decoy); err != nil {
		t.Fatalf("pre-link original to decoy: %v", err)
	}

	const raceName = "race correction"
	supersedes := original
	_, err = storeReportFiles(ctx, extPool, tenantID, raceName, nil,
		report.ContentTypeFull, time.Time{}, time.Time{}, []byte("pdf-bytes"), nil,
		"admin", "executive-summary", logger, nil, nil, &supersedes)
	assertSupersessionStatus(t, err, http.StatusConflict)

	// The race correction's placeholder row must NOT be issued: the
	// finalising UPDATE ran in the same transaction as the failed link and
	// was rolled back with it, leaving the row exactly where an ordinary
	// failed generation already leaves one — present, un-issued, no new
	// cleanup path invented.
	var issuedAt *time.Time
	var pdfPath *string
	if err := pool.QueryRow(ctx, `
		SELECT issued_at, pdf_path FROM report_records WHERE tenant_id = $1::uuid AND name = $2
	`, tenantID, raceName).Scan(&issuedAt, &pdfPath); err != nil {
		t.Fatalf("read back the race correction's placeholder row: %v", err)
	}
	if issuedAt != nil {
		t.Errorf("race correction issued_at = %v, want NULL (rolled back)", *issuedAt)
	}
	if pdfPath != nil {
		t.Errorf("race correction pdf_path = %v, want NULL (finalising UPDATE rolled back)", *pdfPath)
	}

	// original is unchanged: still linked to whatever actually won the race.
	var linkedBy string
	if err := pool.QueryRow(ctx, `
		SELECT superseded_by_report_id::text FROM report_records WHERE id = $1::uuid
	`, original).Scan(&linkedBy); err != nil {
		t.Fatalf("read back original: %v", err)
	}
	if linkedBy != decoy {
		t.Errorf("original.superseded_by_report_id = %s, want %s (unchanged)", linkedBy, decoy)
	}
}

// TestReportRecordsSelfSupersessionRejected proves the DB CHECK constraint
// added by migration 0126 (report_records_no_self_supersession) rejects a
// report that names itself as the report it corrects, and that
// classifyReportRecordsPGError maps that rejection to a clean 409. A
// server-generated UUID cannot practically collide with a caller-supplied one
// (storeReportFiles's own defence-in-depth check covers that path), so this
// proves the ultimate backstop directly with an explicit id.
func TestReportRecordsSelfSupersessionRejected(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)

	var id string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO report_records (id, tenant_id, name, supersedes_report_id)
		VALUES ($1::uuid, $2::uuid, 'self', $1::uuid)
	`, id, tenantID)
	if err == nil {
		t.Fatal("want a self-referencing supersedes_report_id rejected, got nil error")
	}
	status, msg, ok := classifyReportRecordsPGError(err)
	if !ok {
		t.Fatalf("classifyReportRecordsPGError did not recognise: %v", err)
	}
	if status != http.StatusConflict {
		t.Errorf("status = %d, want 409", status)
	}
	if msg == "" {
		t.Error("want a non-empty message")
	}
}

func TestClassifyReportRecordsPGError(t *testing.T) {
	if _, _, ok := classifyReportRecordsPGError(errors.New("boring error")); ok {
		t.Error("want ok=false for a non-Postgres error")
	}
	for _, tc := range []struct {
		name string
		err  *pgconn.PgError
		want int
	}{
		{"supersedes_report_id unique violation", &pgconn.PgError{Code: "23505", ConstraintName: "report_records_supersedes_uq"}, http.StatusConflict},
		{"no-self-supersession check violation", &pgconn.PgError{Code: "23514", ConstraintName: "report_records_no_self_supersession"}, http.StatusConflict},
		{"immutability trigger restrict_violation", &pgconn.PgError{Code: "23001"}, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, msg, ok := classifyReportRecordsPGError(tc.err)
			if !ok {
				t.Fatal("want ok=true")
			}
			if status != tc.want {
				t.Errorf("status = %d, want %d", status, tc.want)
			}
			if msg == "" {
				t.Error("want a non-empty message")
			}
		})
	}
}

// ─── Gap 2: findings figure frozen into coverage_snapshot ─────────────────────

func TestTenantCVESeverityCountsAndFindingsSnapshot(t *testing.T) {
	pool := pat1685FindingsPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'd1', 'macos') RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	for _, cve := range []struct{ id, severity string }{
		{"CVE-2026-0001", "critical"},
		{"CVE-2026-0002", "high"},
		{"CVE-2026-0003", "high"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cve_feed_entries (cve_id, severity) VALUES ($1, $2)
		`, cve.id, cve.severity); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_cve_findings (device_id, cve_id, app_name) VALUES ($1::uuid, $2, 'App')
		`, deviceID, cve.id); err != nil {
			t.Fatal(err)
		}
	}
	// A NULL severity and an unrecognised one ("info") — neither is one of
	// the four known buckets, so both must be dropped from the HTTP
	// severity_counts bar (unchanged behaviour) but folded into "unknown" for
	// the frozen findings_total (the defect this test guards against: a
	// CVE claim that silently undercounts).
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, severity) VALUES ('CVE-2026-0004', NULL)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name) VALUES ($1::uuid, 'CVE-2026-0004', 'App')
	`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, severity) VALUES ('CVE-2026-0005', 'info')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name) VALUES ($1::uuid, 'CVE-2026-0005', 'App')
	`, deviceID); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"critical": 1, "high": 2, "medium": 0, "low": 0}

	counts, unknown, err := tenantCVESeverityCounts(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("tenantCVESeverityCounts: %v", err)
	}
	for sev, wantCount := range want {
		if counts[sev] != wantCount {
			t.Errorf("counts[%s] = %d, want %d", sev, counts[sev], wantCount)
		}
	}
	if unknown != 2 {
		t.Errorf("unknown = %d, want 2 (the NULL-severity and 'info'-severity findings)", unknown)
	}

	// The HTTP response TenantCVEFindingsHandler serves (PAT-402) must be
	// byte-for-byte unchanged by this fix: same keys, same values, the NULL
	// and 'info' findings still silently absent from severity_counts (a
	// pre-existing display gap this ticket does not touch), and no new
	// "unknown" key leaking into a response shape that never had one.
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/cve-findings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	TenantCVEFindingsHandler(pool).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("TenantCVEFindingsHandler status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		SeverityCounts map[string]int `json:"severity_counts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.SeverityCounts) != 4 {
		t.Errorf("HTTP severity_counts has %d keys, want exactly 4 (critical/high/medium/low, no unknown)", len(resp.SeverityCounts))
	}
	if _, ok := resp.SeverityCounts["unknown"]; ok {
		t.Error("HTTP severity_counts must not gain an \"unknown\" key — response shape is unchanged by this fix")
	}
	for sev, wantCount := range want {
		if resp.SeverityCounts[sev] != wantCount {
			t.Errorf("HTTP severity_counts[%s] = %d, want %d", sev, resp.SeverityCounts[sev], wantCount)
		}
	}

	// findings_total frozen into the snapshot must be a TRUE total: the three
	// known-severity findings plus the two unknown-severity ones.
	coverage := map[string]any{"source": "executive_summary"}
	addFindingsSnapshot(ctx, pool, tenantID, coverage, pat1685Logger())
	if got := coverage["findings_total"]; got != 5 {
		t.Errorf("findings_total = %v, want 5 (3 known + 2 unknown)", got)
	}
	bySev, ok := coverage["findings_by_severity"].(map[string]int)
	if !ok {
		t.Fatalf("findings_by_severity has wrong type: %T", coverage["findings_by_severity"])
	}
	for sev, wantCount := range want {
		if bySev[sev] != wantCount {
			t.Errorf("findings_by_severity[%s] = %d, want %d", sev, bySev[sev], wantCount)
		}
	}
	if bySev["unknown"] != 2 {
		t.Errorf("findings_by_severity[unknown] = %d, want 2", bySev["unknown"])
	}
}

// TestAddFindingsSnapshotOmitsUnknownBucketWhenZero pins the other half of the
// "unknown" key's contract: present only when there is at least one such
// finding, never as an always-there zero that would misread as "checked, none
// found" for a bucket this snapshot cannot actually characterise.
func TestAddFindingsSnapshotOmitsUnknownBucketWhenZero(t *testing.T) {
	pool := pat1685FindingsPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'd1', 'macos') RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, severity) VALUES ('CVE-2026-0006', 'critical')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name) VALUES ($1::uuid, 'CVE-2026-0006', 'App')
	`, deviceID); err != nil {
		t.Fatal(err)
	}

	coverage := map[string]any{"source": "executive_summary"}
	addFindingsSnapshot(ctx, pool, tenantID, coverage, pat1685Logger())
	if got := coverage["findings_total"]; got != 1 {
		t.Errorf("findings_total = %v, want 1", got)
	}
	bySev, ok := coverage["findings_by_severity"].(map[string]int)
	if !ok {
		t.Fatalf("findings_by_severity has wrong type: %T", coverage["findings_by_severity"])
	}
	if _, ok := bySev["unknown"]; ok {
		t.Error(`findings_by_severity has an "unknown" key with no unknown-severity findings, want it absent`)
	}
}

// TestAddFindingsSnapshotOmitsKeysOnFetchError pins "absence requires
// authority": a findings fetch that fails must leave the snapshot with no
// findings_total key at all, never a zero that would read as a clean estate.
func TestAddFindingsSnapshotOmitsKeysOnFetchError(t *testing.T) {
	pool := pat1685FindingsPool(t)
	ctx := context.Background()
	coverage := map[string]any{"source": "executive_summary"}
	addFindingsSnapshot(ctx, pool, "not-a-uuid", coverage, pat1685Logger())
	if _, ok := coverage["findings_total"]; ok {
		t.Error("want findings_total omitted when the findings fetch fails, got it present")
	}
	if _, ok := coverage["findings_by_severity"]; ok {
		t.Error("want findings_by_severity omitted when the findings fetch fails, got it present")
	}
}

// TestLegacyCoverageSnapshotHasNoFindingsKey pins the other half of "absence
// requires authority": a report issued before this change has no
// findings_total key at all (frozen, immutable — it can never be backfilled),
// so a reader must render "not captured", never 0.
func TestLegacyCoverageSnapshotHasNoFindingsKey(t *testing.T) {
	pool := pat1613Pool(t)
	ctx := context.Background()
	tenantID := pat1613Tenant(t, pool)
	id := pat1613Issue(t, pool, tenantID, "legacy")

	var raw []byte
	if err := pool.QueryRow(ctx, `
		SELECT coverage_snapshot FROM report_records WHERE id = $1::uuid
	`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("coverage_snapshot not JSON: %v", err)
	}
	if _, ok := snap["findings_total"]; ok {
		t.Error("legacy coverage_snapshot has findings_total, want it absent")
	}
}
