package handlers

// DB-backed tests for PAT-1829's finding disposition endpoints. Same
// isolated-schema convention as device_dispositions_test.go (pat1825Pool):
// search_path pinned to a per-ticket schema, dropped on cleanup, mirroring
// migrations/0146_finding_dispositions.sql by hand rather than requiring
// that migration to already be applied to whatever TEST_DATABASE_URL points
// at.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1829Schema = "pat1829_handlers_test"

func pat1829Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed finding-disposition test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1829Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1829Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1829Schema,
		`CREATE TABLE ` + pat1829Schema + `.tenants (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1829Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1829Schema + `.tenants(id),
			hostname  TEXT
		)`,
		`CREATE TABLE ` + pat1829Schema + `.cve_feed_entries (
			cve_id TEXT PRIMARY KEY
		)`,
		`CREATE TABLE ` + pat1829Schema + `.tenant_app_policies (
			id BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES ` + pat1829Schema + `.tenants(id)
		)`,
		// Mirrors migrations/0146_finding_dispositions.sql, including the
		// two-shape CHECK, the two partial unique indexes and the
		// append-only-with-supersede guard — this schema and that
		// migration are kept in sync by hand, same convention as this
		// package's other DB-backed tests.
		`CREATE TABLE ` + pat1829Schema + `.finding_dispositions (
			id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id           UUID         NOT NULL REFERENCES ` + pat1829Schema + `.tenants(id),
			finding_kind        TEXT         NOT NULL CHECK (finding_kind IN ('cis', 'cve', 'software')),
			device_id           UUID         REFERENCES ` + pat1829Schema + `.devices(id),
			rule_key            TEXT,
			cve_id              TEXT         REFERENCES ` + pat1829Schema + `.cve_feed_entries(cve_id),
			software_key        TEXT,
			status              TEXT         NOT NULL CHECK (status IN ('acknowledged', 'risk_accepted', 'closed', 'guidance_issued', 'customer_applied', 'pending_verification')),
			recorded_by         TEXT         NOT NULL DEFAULT '',
			reason              TEXT         NOT NULL DEFAULT '',
			recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
			supersedes_id       UUID         REFERENCES ` + pat1829Schema + `.finding_dispositions(id),
			superseded_at       TIMESTAMPTZ,
			superseded_reason   TEXT,
			CONSTRAINT pat1829_supersede_fields CHECK (
				(superseded_at IS NULL AND superseded_reason IS NULL) OR
				(superseded_at IS NOT NULL AND superseded_reason IS NOT NULL)
			),
			CONSTRAINT pat1829_kind_shape CHECK (
				(finding_kind = 'cis' AND device_id IS NOT NULL AND rule_key IS NOT NULL AND cve_id IS NULL AND software_key IS NULL) OR
				(finding_kind = 'cve' AND device_id IS NULL AND rule_key IS NULL AND cve_id IS NOT NULL AND software_key IS NULL) OR
				(finding_kind = 'software' AND device_id IS NOT NULL AND rule_key IS NULL AND cve_id IS NULL AND software_key IS NOT NULL)
			)
		)`,
		`CREATE UNIQUE INDEX uq_pat1829_active_cis
			ON ` + pat1829Schema + `.finding_dispositions (tenant_id, device_id, rule_key)
			WHERE superseded_at IS NULL AND finding_kind = 'cis'`,
		`CREATE UNIQUE INDEX uq_pat1829_active_cve
			ON ` + pat1829Schema + `.finding_dispositions (tenant_id, cve_id)
			WHERE superseded_at IS NULL AND finding_kind = 'cve'`,
		`CREATE UNIQUE INDEX uq_pat1829_active_software
			ON ` + pat1829Schema + `.finding_dispositions (tenant_id, device_id, software_key)
			WHERE superseded_at IS NULL AND finding_kind = 'software'`,
		`CREATE TABLE ` + pat1829Schema + `.finding_lifecycle_events (
			id BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES ` + pat1829Schema + `.tenants(id),
			finding_kind TEXT NOT NULL,
			device_id UUID,
			finding_key TEXT NOT NULL,
			event_type TEXT NOT NULL,
			source_type TEXT NOT NULL,
			actor TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			observed_at TIMESTAMPTZ,
			authoritative BOOLEAN NOT NULL DEFAULT false,
			evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
			recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE VIEW ` + pat1829Schema + `.finding_lifecycle_current AS
		WITH ranked AS (
			SELECT e.*, row_number() OVER (
				PARTITION BY tenant_id, finding_kind, device_id, finding_key ORDER BY id DESC
			) AS latest_rank
			FROM ` + pat1829Schema + `.finding_lifecycle_events e
		), grouped AS (
			SELECT tenant_id, finding_kind, device_id, finding_key,
				MIN(observed_at) FILTER (WHERE event_type = 'first_observed') AS first_observed_at,
				MAX(observed_at) FILTER (WHERE event_type IN ('first_observed', 'currently_observed', 'still_failing', 'recurred')) AS currently_observed_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'acknowledged') AS acknowledged_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'risk_accepted') AS risk_accepted_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'guidance_issued') AS guidance_issued_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'customer_applied') AS customer_applied_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'pending_verification') AS pending_verification_at,
				MAX(observed_at) FILTER (WHERE event_type = 'verified_fixed') AS verified_fixed_at,
				MAX(observed_at) FILTER (WHERE event_type = 'still_failing') AS still_failing_at,
				MAX(recorded_at) FILTER (WHERE event_type = 'verification_unknown') AS verification_unknown_at,
				MAX(observed_at) FILTER (WHERE event_type = 'recurred') AS recurred_at,
				COUNT(*) FILTER (WHERE event_type = 'recurred')::int AS recurrence_count,
				COUNT(*)::int AS event_count
			FROM ` + pat1829Schema + `.finding_lifecycle_events
			GROUP BY tenant_id, finding_kind, device_id, finding_key
		)
		SELECT g.*, r.event_type AS status, r.recorded_at AS status_recorded_at,
			r.observed_at AS status_observed_at, r.authoritative AS status_authoritative
		FROM grouped g
		JOIN ranked r ON r.tenant_id = g.tenant_id
		 AND r.finding_kind = g.finding_kind
		 AND r.device_id IS NOT DISTINCT FROM g.device_id
		 AND r.finding_key = g.finding_key
		 AND r.latest_rank = 1`,
		`CREATE FUNCTION ` + pat1829Schema + `.guard_finding_dispositions_mutation() RETURNS trigger AS $$
		BEGIN
			IF TG_OP = 'DELETE' THEN
				RAISE EXCEPTION 'finding_dispositions is append-only: DELETE is not permitted on row id=%', OLD.id;
			END IF;
			IF NEW.id                IS DISTINCT FROM OLD.id
				OR NEW.tenant_id         IS DISTINCT FROM OLD.tenant_id
				OR NEW.finding_kind      IS DISTINCT FROM OLD.finding_kind
				OR NEW.device_id         IS DISTINCT FROM OLD.device_id
				OR NEW.rule_key          IS DISTINCT FROM OLD.rule_key
				OR NEW.cve_id            IS DISTINCT FROM OLD.cve_id
				OR NEW.software_key      IS DISTINCT FROM OLD.software_key
				OR NEW.status            IS DISTINCT FROM OLD.status
				OR NEW.recorded_by       IS DISTINCT FROM OLD.recorded_by
				OR NEW.reason            IS DISTINCT FROM OLD.reason
				OR NEW.recorded_at       IS DISTINCT FROM OLD.recorded_at
				OR NEW.supersedes_id     IS DISTINCT FROM OLD.supersedes_id
			THEN
				RAISE EXCEPTION 'finding_dispositions is append-only: only superseded_at/superseded_reason may change on row id=%', OLD.id;
			END IF;
			IF OLD.superseded_at IS NOT NULL THEN
				RAISE EXCEPTION 'finding_dispositions row id=% is already superseded', OLD.id;
			END IF;
			IF NEW.superseded_at IS NULL OR NEW.superseded_reason IS NULL THEN
				RAISE EXCEPTION 'finding_dispositions update must set both superseded_at and superseded_reason, id=%', OLD.id;
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER trg_pat1829_append_only
			BEFORE UPDATE OR DELETE ON ` + pat1829Schema + `.finding_dispositions
			FOR EACH ROW EXECUTE FUNCTION ` + pat1829Schema + `.guard_finding_dispositions_mutation()`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:min(60, len(s))], err)
		}
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1829Schema+` CASCADE`)
	})
	return pool
}

func pat1829SeedTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

func pat1829SeedDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hostname string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO devices (tenant_id, hostname) VALUES ($1::uuid, $2) RETURNING id::text`,
		tenantID, hostname,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return deviceID
}

func pat1829SeedCVE(t *testing.T, pool *pgxpool.Pool, cveID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO cve_feed_entries (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, cveID,
	); err != nil {
		t.Fatalf("insert cve: %v", err)
	}
}

func pat1829Req(method, target string, body any, tenantID string) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, target, &buf)
	rctx := chi.NewRouteContext()
	if tenantID != "" {
		rctx.URLParams.Add("tenantID", tenantID)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestFindingDispositionCreate_CIS_WritesOneRow(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-1")

	h := FindingDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
		"reason":       "compensating control in place",
	}, tenantID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp findingDispositionCreateResp
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Disposition.FindingKind != "cis" {
		t.Errorf("expected finding_kind=cis, got %q", resp.Disposition.FindingKind)
	}
	if resp.Disposition.DeviceID == nil || *resp.Disposition.DeviceID != deviceID {
		t.Errorf("expected device_id=%q, got %v", deviceID, resp.Disposition.DeviceID)
	}
	if resp.Disposition.RuleKey == nil || *resp.Disposition.RuleKey != "cis_macos_2_5_1_1_filevault" {
		t.Errorf("expected rule_key set, got %v", resp.Disposition.RuleKey)
	}
	if resp.Disposition.CVEID != nil {
		t.Errorf("cis disposition should not carry a cve_id, got %v", *resp.Disposition.CVEID)
	}
	if resp.Disposition.SupersedesID != nil {
		t.Errorf("first-ever disposition should not supersede anything, got %v", *resp.Disposition.SupersedesID)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM finding_dispositions WHERE device_id = $1::uuid AND rule_key = $2`,
		deviceID, "cis_macos_2_5_1_1_filevault",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row, got %d", count)
	}
}

func TestFindingDispositionCreate_CVE_WritesOneRow(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	pat1829SeedCVE(t, pool, "CVE-2026-0001")

	h := FindingDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-2026-0001",
		"status":       "risk_accepted",
		"recorded_by":  "jane@customer.com",
		"reason":       "patch scheduled for next maintenance window",
	}, tenantID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp findingDispositionCreateResp
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Disposition.FindingKind != "cve" {
		t.Errorf("expected finding_kind=cve, got %q", resp.Disposition.FindingKind)
	}
	if resp.Disposition.CVEID == nil || *resp.Disposition.CVEID != "CVE-2026-0001" {
		t.Errorf("expected cve_id set, got %v", resp.Disposition.CVEID)
	}
	if resp.Disposition.DeviceID != nil || resp.Disposition.RuleKey != nil {
		t.Errorf("cve disposition should not carry device_id/rule_key, got device_id=%v rule_key=%v",
			resp.Disposition.DeviceID, resp.Disposition.RuleKey)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM finding_dispositions WHERE cve_id = $1`, "CVE-2026-0001",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row, got %d", count)
	}
}

func TestFindingDispositionCreate_Correction_Supersedes(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-2")

	h := FindingDispositionCreateHandler(pool)

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
		"reason":       "reviewing",
	}, tenantID))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first write: got %d, body: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 findingDispositionCreateResp
	_ = json.NewDecoder(rr1.Body).Decode(&resp1)
	firstID := resp1.Disposition.ID

	// Correction: same identity, different status — must supersede, not edit.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "closed",
		"recorded_by":  "jane@customer.com",
		"reason":       "remediated",
	}, tenantID))
	if rr2.Code != http.StatusCreated {
		t.Fatalf("correction write: got %d, body: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 findingDispositionCreateResp
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	secondRow := resp2.Disposition
	if secondRow.SupersedesID == nil || *secondRow.SupersedesID != firstID {
		t.Fatalf("correction row should have supersedes_id=%q, got %v", firstID, secondRow.SupersedesID)
	}

	// Old row: superseded_at/reason set, substantive fields unchanged
	// byte-for-byte.
	var status, recordedBy, reason, supersededReason string
	var supersededAt *string
	if err := pool.QueryRow(context.Background(), `
		SELECT status, recorded_by, reason, superseded_at::text, superseded_reason
		FROM finding_dispositions WHERE id = $1::uuid
	`, firstID).Scan(&status, &recordedBy, &reason, &supersededAt, &supersededReason); err != nil {
		t.Fatal(err)
	}
	if status != "acknowledged" || recordedBy != "jane@customer.com" || reason != "reviewing" {
		t.Fatalf("old row's substantive fields were changed: status=%q recorded_by=%q reason=%q", status, recordedBy, reason)
	}
	if supersededAt == nil || supersededReason != "correction" {
		t.Fatalf("old row not marked superseded: superseded_at=%v superseded_reason=%q", supersededAt, supersededReason)
	}

	// Only one row is active for this identity — the partial unique index
	// (uq_pat1829_active_cis in this test schema, uq_finding_dispositions_active_cis
	// in the real migration) enforces this; this assertion confirms the
	// handler's supersede path actually produced that state.
	var activeCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM finding_dispositions WHERE device_id = $1::uuid AND rule_key = $2 AND superseded_at IS NULL`,
		deviceID, "cis_macos_2_5_1_1_filevault",
	).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly 1 active disposition after correction, got %d", activeCount)
	}
}

func TestFindingDispositionCreate_CVE_Correction_Supersedes(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	pat1829SeedCVE(t, pool, "CVE-2026-0002")

	h := FindingDispositionCreateHandler(pool)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-2026-0002",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first write: got %d, body: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 findingDispositionCreateResp
	_ = json.NewDecoder(rr1.Body).Decode(&resp1)
	firstID := resp1.Disposition.ID

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-2026-0002",
		"status":       "risk_accepted",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr2.Code != http.StatusCreated {
		t.Fatalf("correction write: got %d, body: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 findingDispositionCreateResp
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	if resp2.Disposition.SupersedesID == nil || *resp2.Disposition.SupersedesID != firstID {
		t.Fatalf("correction row should have supersedes_id=%q, got %v", firstID, resp2.Disposition.SupersedesID)
	}

	var activeCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM finding_dispositions WHERE cve_id = $1 AND superseded_at IS NULL`, "CVE-2026-0002",
	).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly 1 active disposition after correction, got %d", activeCount)
	}

	// The superseded predecessor's substantive fields must survive
	// byte-for-byte next to the correction, same as the CIS supersede test
	// asserts — this is the whole point of append-only-with-supersede over
	// a mutable "current" row.
	var oldStatus, oldRecordedBy string
	if err := pool.QueryRow(context.Background(),
		`SELECT status, recorded_by FROM finding_dispositions WHERE id = $1::uuid`, firstID,
	).Scan(&oldStatus, &oldRecordedBy); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "acknowledged" {
		t.Errorf("superseded row status = %q, want unchanged %q", oldStatus, "acknowledged")
	}
	if oldRecordedBy != "jane@customer.com" {
		t.Errorf("superseded row recorded_by = %q, want unchanged %q", oldRecordedBy, "jane@customer.com")
	}
}

func TestFindingDispositionCreate_KindIdentityMismatch_Returns400(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-3")

	h := FindingDispositionCreateHandler(pool)

	// cis kind carrying a cve_id.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"cve_id":       "CVE-2026-0003",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("cis+cve_id: got %d, want 400, body: %s", rr.Code, rr.Body.String())
	}

	// cve kind carrying a device_id.
	pat1829SeedCVE(t, pool, "CVE-2026-0003")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-2026-0003",
		"device_id":    deviceID,
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("cve+device_id: got %d, want 400, body: %s", rr2.Code, rr2.Body.String())
	}
}

func TestFindingDispositionCreate_InvalidStatus_Returns400(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-4")

	h := FindingDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "ignored-forever",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400, body: %s", rr.Code, rr.Body.String())
	}
}

func TestFindingDispositionCreate_VerifiedFixedIsObservationOnly(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-observation-only")

	rr := httptest.NewRecorder()
	FindingDispositionCreateHandler(pool).ServeHTTP(rr, pat1829Req(http.MethodPost,
		"/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
			"finding_kind": "cis",
			"device_id":    deviceID,
			"rule_key":     "cis_test_rule",
			"status":       "verified_fixed",
			"recorded_by":  "operator@example.test",
		}, tenantID))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rr.Code, rr.Body.String())
	}
}

func TestFindingDispositionCreate_UnknownDevice_Returns404(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)

	h := FindingDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    "00000000-0000-0000-0000-000000000099",
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404, body: %s", rr.Code, rr.Body.String())
	}
}

func TestFindingDispositionCreate_UnknownCVE_Returns404(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)

	h := FindingDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-9999-9999",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404, body: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/finding-dispositions
// ---------------------------------------------------------------------------

func TestFindingDispositionList_ActiveOnly_ExcludesSuperseded(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-list-1")

	ch := FindingDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	// Correction: supersedes the first row.
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "closed",
		"recorded_by":  "jane@customer.com",
	}, tenantID))

	lh := FindingDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1829Req(http.MethodGet, "/admin/tenants/"+tenantID+"/finding-dispositions", nil, tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []findingDispositionRow `json:"dispositions"`
		Total        int                     `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Dispositions) != 1 {
		t.Fatalf("expected only the active row, got total=%d len=%d", resp.Total, len(resp.Dispositions))
	}
	if resp.Dispositions[0].Status != "pending_verification" {
		t.Fatalf("expected closed alias to become pending_verification, got %q", resp.Dispositions[0].Status)
	}
	if resp.Dispositions[0].SupersededAt != nil {
		t.Fatalf("active row should not be superseded, got superseded_at=%v", resp.Dispositions[0].SupersededAt)
	}
}

func TestFindingDispositionList_FilterByFindingKind(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "laptop-list-2")
	pat1829SeedCVE(t, pool, "CVE-2026-0010")

	ch := FindingDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceID,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantID))
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantID+"/finding-dispositions", map[string]any{
		"finding_kind": "cve",
		"cve_id":       "CVE-2026-0010",
		"status":       "risk_accepted",
		"recorded_by":  "jane@customer.com",
	}, tenantID))

	lh := FindingDispositionListHandler(pool)

	rrAll := httptest.NewRecorder()
	lh.ServeHTTP(rrAll, pat1829Req(http.MethodGet, "/admin/tenants/"+tenantID+"/finding-dispositions", nil, tenantID))
	var respAll struct {
		Dispositions []findingDispositionRow `json:"dispositions"`
		Total        int                     `json:"total"`
	}
	_ = json.NewDecoder(rrAll.Body).Decode(&respAll)
	if respAll.Total != 2 {
		t.Fatalf("unfiltered: expected 2 rows, got %d", respAll.Total)
	}

	rrCIS := httptest.NewRecorder()
	lh.ServeHTTP(rrCIS, pat1829Req(http.MethodGet, "/admin/tenants/"+tenantID+"/finding-dispositions?finding_kind=cis", nil, tenantID))
	var respCIS struct {
		Dispositions []findingDispositionRow `json:"dispositions"`
		Total        int                     `json:"total"`
	}
	if err := json.NewDecoder(rrCIS.Body).Decode(&respCIS); err != nil {
		t.Fatal(err)
	}
	if respCIS.Total != 1 || respCIS.Dispositions[0].FindingKind != "cis" {
		t.Fatalf("finding_kind=cis filter: expected 1 cis row, got total=%d", respCIS.Total)
	}

	rrCVE := httptest.NewRecorder()
	lh.ServeHTTP(rrCVE, pat1829Req(http.MethodGet, "/admin/tenants/"+tenantID+"/finding-dispositions?finding_kind=cve", nil, tenantID))
	var respCVE struct {
		Dispositions []findingDispositionRow `json:"dispositions"`
		Total        int                     `json:"total"`
	}
	if err := json.NewDecoder(rrCVE.Body).Decode(&respCVE); err != nil {
		t.Fatal(err)
	}
	if respCVE.Total != 1 || respCVE.Dispositions[0].FindingKind != "cve" {
		t.Fatalf("finding_kind=cve filter: expected 1 cve row, got total=%d", respCVE.Total)
	}
}

func TestFindingDispositionList_TenantIsolation(t *testing.T) {
	pool := pat1829Pool(t)
	tenantA := pat1829SeedTenant(t, pool)
	tenantB := pat1829SeedTenant(t, pool)
	deviceA := pat1829SeedDevice(t, pool, tenantA, "laptop-tenant-a")
	deviceB := pat1829SeedDevice(t, pool, tenantB, "laptop-tenant-b")

	ch := FindingDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantA+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceA,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "acknowledged",
		"recorded_by":  "jane@customer.com",
	}, tenantA))
	ch.ServeHTTP(httptest.NewRecorder(), pat1829Req(http.MethodPost, "/admin/tenants/"+tenantB+"/finding-dispositions", map[string]any{
		"finding_kind": "cis",
		"device_id":    deviceB,
		"rule_key":     "cis_macos_2_5_1_1_filevault",
		"status":       "closed",
		"recorded_by":  "bob@othercustomer.com",
	}, tenantB))

	lh := FindingDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1829Req(http.MethodGet, "/admin/tenants/"+tenantA+"/finding-dispositions", nil, tenantA))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []findingDispositionRow `json:"dispositions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Dispositions) != 1 {
		t.Fatalf("expected exactly 1 disposition for tenant A, got %d", len(resp.Dispositions))
	}
	if resp.Dispositions[0].DeviceID == nil || *resp.Dispositions[0].DeviceID != deviceA {
		t.Fatalf("expected tenant A's device, got %v", resp.Dispositions[0].DeviceID)
	}
}

func TestFindingDispositionCreate_InvalidStatusListsClosedAlias(t *testing.T) {
	tenantID := "10000000-0000-0000-0000-000000000001"
	rr := httptest.NewRecorder()
	FindingDispositionCreateHandler(nil).ServeHTTP(rr, pat1829Req(
		http.MethodPost,
		"/admin/tenants/"+tenantID+"/finding-dispositions",
		map[string]any{
			"finding_kind": "cve",
			"cve_id":       "CVE-2026-1878",
			"status":       "invalid",
			"recorded_by":  "operator@example.test",
		},
		tenantID,
	))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "closed") {
		t.Fatalf("invalid-status response %q does not list the accepted closed alias", rr.Body.String())
	}
}

func TestFindingLifecycleHandlersPagination(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "lifecycle-pagination")
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	for index, key := range []string{"current-a", "current-b", "current-c"} {
		observedAt := t0.Add(time.Duration(index) * time.Hour)
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO finding_lifecycle_events
				(tenant_id, finding_kind, device_id, finding_key, event_type, source_type,
				 observed_at, authoritative, recorded_at)
			VALUES ($1::uuid, 'cis', $2::uuid, $3, 'first_observed', 'endpoint_observation',
			        $4, true, $4)
		`, tenantID, deviceID, key, observedAt); err != nil {
			t.Fatal(err)
		}
	}

	currentRecorder := httptest.NewRecorder()
	FindingLifecycleCurrentHandler(pool).ServeHTTP(currentRecorder, pat1829Req(
		http.MethodGet,
		"/admin/tenants/"+tenantID+"/finding-lifecycle?limit=1&offset=1",
		nil,
		tenantID,
	))
	if currentRecorder.Code != http.StatusOK {
		t.Fatalf("current status=%d body=%q", currentRecorder.Code, currentRecorder.Body.String())
	}
	var currentResponse struct {
		Findings []findingLifecycleCurrentRow `json:"findings"`
		Total    int                          `json:"total"`
		Limit    int                          `json:"limit"`
		Offset   int                          `json:"offset"`
		Returned int                          `json:"returned"`
	}
	if err := json.NewDecoder(currentRecorder.Body).Decode(&currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Total != 1 || currentResponse.Returned != 1 || currentResponse.Limit != 1 || currentResponse.Offset != 1 {
		t.Fatalf("current pagination=%+v, want total/returned/limit/offset 1/1/1/1", currentResponse)
	}
	if len(currentResponse.Findings) != 1 || currentResponse.Findings[0].FindingKey != "current-b" {
		t.Fatalf("current findings=%+v, want second ordered finding current-b", currentResponse.Findings)
	}

	for index, eventType := range []string{"acknowledged", "pending_verification", "verified_fixed"} {
		recordedAt := t0.Add(time.Duration(index+4) * time.Hour)
		var observedAt any
		if eventType == "verified_fixed" {
			observedAt = recordedAt
		}
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO finding_lifecycle_events
				(tenant_id, finding_kind, device_id, finding_key, event_type, source_type,
				 observed_at, authoritative, recorded_at)
			VALUES ($1::uuid, 'cis', $2::uuid, 'history-key', $3, 'endpoint_observation',
			        $4, $5, $6)
		`, tenantID, deviceID, eventType, observedAt, eventType == "verified_fixed", recordedAt); err != nil {
			t.Fatal(err)
		}
	}

	historyRecorder := httptest.NewRecorder()
	FindingLifecycleHistoryHandler(pool).ServeHTTP(historyRecorder, pat1829Req(
		http.MethodGet,
		"/admin/tenants/"+tenantID+"/finding-lifecycle/history?finding_key=history-key&limit=1&offset=1",
		nil,
		tenantID,
	))
	if historyRecorder.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%q", historyRecorder.Code, historyRecorder.Body.String())
	}
	var historyResponse struct {
		Events   []findingLifecycleEventRow `json:"events"`
		Total    int                        `json:"total"`
		Limit    int                        `json:"limit"`
		Offset   int                        `json:"offset"`
		Returned int                        `json:"returned"`
	}
	if err := json.NewDecoder(historyRecorder.Body).Decode(&historyResponse); err != nil {
		t.Fatal(err)
	}
	if historyResponse.Total != 1 || historyResponse.Returned != 1 || historyResponse.Limit != 1 || historyResponse.Offset != 1 {
		t.Fatalf("history pagination=%+v, want total/returned/limit/offset 1/1/1/1", historyResponse)
	}
	if len(historyResponse.Events) != 1 || historyResponse.Events[0].EventType != "pending_verification" {
		t.Fatalf("history events=%+v, want second ordered event pending_verification", historyResponse.Events)
	}
}
