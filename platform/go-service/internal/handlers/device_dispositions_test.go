package handlers

// DB-backed tests for PAT-1825's device disposition endpoint and the
// activeDisposition wiring into DeviceLifecycleHandler. Same isolated-schema
// convention as remediation_artefacts_test.go (pat1549Pool): search_path
// pinned to a per-ticket schema, dropped on cleanup, mirroring
// migrations/0143_device_dispositions.sql by hand rather than requiring that
// migration to already be applied to whatever TEST_DATABASE_URL points at.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1825Schema = "pat1825_handlers_test"

func pat1825Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed device-disposition test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1825Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1825Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1825Schema,
		`CREATE TABLE ` + pat1825Schema + `.tenants (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1825Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1825Schema + `.tenants(id),
			serial    TEXT,
			hw_uuid   UUID,
			hostname  TEXT,
			last_seen TIMESTAMPTZ
		)`,
		// Mirrors migrations/0140_device_lifecycle.sql — needed for
		// DeviceLifecycleHandler's own queries.
		`CREATE TABLE ` + pat1825Schema + `.device_upload_lists (
			id           BIGSERIAL   PRIMARY KEY,
			tenant_id    UUID        NOT NULL REFERENCES ` + pat1825Schema + `.tenants(id),
			uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			uploaded_by  TEXT        NOT NULL DEFAULT '',
			device_count INT         NOT NULL,
			devices      JSONB       NOT NULL
		)`,
		`CREATE TABLE ` + pat1825Schema + `.device_lifecycle_thresholds (
			tenant_id    UUID PRIMARY KEY REFERENCES ` + pat1825Schema + `.tenants(id),
			quiet_days   INT  NOT NULL DEFAULT 3,
			stale_days   INT  NOT NULL DEFAULT 14,
			dormant_days INT  NOT NULL DEFAULT 45
		)`,
		// Mirrors migrations/0143_device_dispositions.sql, including the
		// append-only-with-supersede guard — this schema and that migration
		// are kept in sync by hand, same convention as this package's other
		// DB-backed tests.
		`CREATE TABLE ` + pat1825Schema + `.device_dispositions (
			id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id           UUID         NOT NULL REFERENCES ` + pat1825Schema + `.tenants(id),
			device_id           UUID         NOT NULL REFERENCES ` + pat1825Schema + `.devices(id),
			category            TEXT         NOT NULL CHECK (category IN ('decommissioned', 'on-leave', 'lost', 'unaccounted')),
			reported_by         TEXT         NOT NULL DEFAULT '',
			reported_by_role    TEXT         NOT NULL DEFAULT '',
			channel             TEXT         NOT NULL DEFAULT '',
			note                TEXT         NOT NULL DEFAULT '',
			recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
			cohort_id           UUID,
			supersedes_id       UUID         REFERENCES ` + pat1825Schema + `.device_dispositions(id),
			superseded_at       TIMESTAMPTZ,
			superseded_reason   TEXT,
			CONSTRAINT device_dispositions_supersede_fields CHECK (
				(superseded_at IS NULL AND superseded_reason IS NULL) OR
				(superseded_at IS NOT NULL AND superseded_reason IS NOT NULL)
			)
		)`,
		`CREATE UNIQUE INDEX uq_pat1825_one_active_per_device
			ON ` + pat1825Schema + `.device_dispositions (device_id) WHERE superseded_at IS NULL`,
		`CREATE FUNCTION ` + pat1825Schema + `.guard_device_dispositions_mutation() RETURNS trigger AS $$
		BEGIN
			IF TG_OP = 'DELETE' THEN
				RAISE EXCEPTION 'device_dispositions is append-only: DELETE is not permitted on row id=%', OLD.id;
			END IF;
			IF NEW.id                IS DISTINCT FROM OLD.id
				OR NEW.tenant_id         IS DISTINCT FROM OLD.tenant_id
				OR NEW.device_id         IS DISTINCT FROM OLD.device_id
				OR NEW.category          IS DISTINCT FROM OLD.category
				OR NEW.reported_by       IS DISTINCT FROM OLD.reported_by
				OR NEW.reported_by_role  IS DISTINCT FROM OLD.reported_by_role
				OR NEW.channel           IS DISTINCT FROM OLD.channel
				OR NEW.note              IS DISTINCT FROM OLD.note
				OR NEW.recorded_at       IS DISTINCT FROM OLD.recorded_at
				OR NEW.cohort_id         IS DISTINCT FROM OLD.cohort_id
				OR NEW.supersedes_id     IS DISTINCT FROM OLD.supersedes_id
			THEN
				RAISE EXCEPTION 'device_dispositions is append-only: only superseded_at/superseded_reason may change on row id=%', OLD.id;
			END IF;
			IF OLD.superseded_at IS NOT NULL THEN
				RAISE EXCEPTION 'device_dispositions row id=% is already superseded', OLD.id;
			END IF;
			IF NEW.superseded_at IS NULL OR NEW.superseded_reason IS NULL THEN
				RAISE EXCEPTION 'device_dispositions update must set both superseded_at and superseded_reason, id=%', OLD.id;
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER trg_pat1825_append_only
			BEFORE UPDATE OR DELETE ON ` + pat1825Schema + `.device_dispositions
			FOR EACH ROW EXECUTE FUNCTION ` + pat1825Schema + `.guard_device_dispositions_mutation()`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:min(60, len(s))], err)
		}
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1825Schema+` CASCADE`)
	})
	return pool
}

func pat1825SeedTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

func pat1825SeedDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hostname string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO devices (tenant_id, hostname, last_seen) VALUES ($1::uuid, $2, now()) RETURNING id::text`,
		tenantID, hostname,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return deviceID
}

func pat1825Req(method, target string, body any, tenantID string) *http.Request {
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

func TestDeviceDispositionCreate_SingleDevice_WritesOneRow(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	deviceID := pat1825SeedDevice(t, pool, tenantID, "laptop-1")

	h := DeviceDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":        deviceID,
		"category":         "decommissioned",
		"reported_by":      "jane@customer.com",
		"reported_by_role": "IT manager",
		"channel":          "email",
		"note":             "returned to leasing company",
	}, tenantID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp deviceDispositionCreateResp
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Dispositions) != 1 {
		t.Fatalf("expected 1 disposition, got %d", len(resp.Dispositions))
	}
	if resp.CohortID != nil {
		t.Errorf("single-device write should not carry a cohort_id, got %v", *resp.CohortID)
	}
	row := resp.Dispositions[0]
	if row.SupersedesID != nil {
		t.Errorf("first-ever disposition should not supersede anything, got %v", *row.SupersedesID)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_dispositions WHERE device_id = $1::uuid`, deviceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row in device_dispositions, got %d", count)
	}
}

func TestDeviceDispositionCreate_Correction_Supersedes(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	deviceID := pat1825SeedDevice(t, pool, tenantID, "laptop-2")

	h := DeviceDispositionCreateHandler(pool)

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "lost",
		"reported_by": "jane@customer.com",
		"note":        "not seen since the office move",
	}, tenantID))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first write: got %d, body: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 deviceDispositionCreateResp
	_ = json.NewDecoder(rr1.Body).Decode(&resp1)
	firstID := resp1.Dispositions[0].ID

	// Correction: same device, different category — must supersede, not edit.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "decommissioned",
		"reported_by": "jane@customer.com",
		"note":        "found it — was actually decommissioned properly",
	}, tenantID))
	if rr2.Code != http.StatusCreated {
		t.Fatalf("correction write: got %d, body: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 deviceDispositionCreateResp
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	secondRow := resp2.Dispositions[0]
	if secondRow.SupersedesID == nil || *secondRow.SupersedesID != firstID {
		t.Fatalf("correction row should have supersedes_id=%q, got %v", firstID, secondRow.SupersedesID)
	}

	// Old row: superseded_at/reason set, substantive fields unchanged.
	var category, reportedBy, note, supersededReason string
	var supersededAt *string
	if err := pool.QueryRow(context.Background(), `
		SELECT category, reported_by, note, superseded_at::text, superseded_reason
		FROM device_dispositions WHERE id = $1::uuid
	`, firstID).Scan(&category, &reportedBy, &note, &supersededAt, &supersededReason); err != nil {
		t.Fatal(err)
	}
	if category != "lost" || reportedBy != "jane@customer.com" || note != "not seen since the office move" {
		t.Fatalf("old row's substantive fields were changed: category=%q reported_by=%q note=%q", category, reportedBy, note)
	}
	if supersededAt == nil || supersededReason != "correction" {
		t.Fatalf("old row not marked superseded: superseded_at=%v superseded_reason=%q", supersededAt, supersededReason)
	}

	// Only one row is active for this device.
	var activeCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_dispositions WHERE device_id = $1::uuid AND superseded_at IS NULL`, deviceID,
	).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly 1 active disposition after correction, got %d", activeCount)
	}
}

func TestDeviceDispositionCreate_Cohort_SharesCohortID(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	d1 := pat1825SeedDevice(t, pool, tenantID, "laptop-3")
	d2 := pat1825SeedDevice(t, pool, tenantID, "laptop-4")
	d3 := pat1825SeedDevice(t, pool, tenantID, "laptop-5")

	h := DeviceDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_ids":  []string{d1, d2, d3},
		"category":    "decommissioned",
		"reported_by": "office-closure-project",
	}, tenantID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp deviceDispositionCreateResp
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.CohortID == nil {
		t.Fatal("cohort write should carry a cohort_id")
	}
	if len(resp.Dispositions) != 3 {
		t.Fatalf("expected 3 dispositions, got %d", len(resp.Dispositions))
	}
	var distinctCohorts int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(DISTINCT cohort_id) FROM device_dispositions WHERE device_id = ANY($1::uuid[])
	`, []string{d1, d2, d3}).Scan(&distinctCohorts); err != nil {
		t.Fatal(err)
	}
	if distinctCohorts != 1 {
		t.Fatalf("expected all 3 rows to share one cohort_id, got %d distinct", distinctCohorts)
	}
}

func TestDeviceDispositionCreate_UnknownDevice_Returns404(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)

	h := DeviceDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   "00000000-0000-0000-0000-000000000099",
		"category":    "lost",
		"reported_by": "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404, body: %s", rr.Code, rr.Body.String())
	}
}

func TestDeviceDispositionCreate_InvalidCategory_Returns400(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	deviceID := pat1825SeedDevice(t, pool, tenantID, "laptop-6")

	h := DeviceDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "stolen-by-aliens",
		"reported_by": "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400, body: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/device-dispositions (PAT-1836)
// ---------------------------------------------------------------------------

func TestDeviceDispositionList_ReturnsAllOrderedByRecordedAtDesc(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	d1 := pat1825SeedDevice(t, pool, tenantID, "laptop-list-1")
	d2 := pat1825SeedDevice(t, pool, tenantID, "laptop-list-2")

	ch := DeviceDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   d1,
		"category":    "lost",
		"reported_by": "jane@customer.com",
	}, tenantID))
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   d2,
		"category":    "on-leave",
		"reported_by": "jane@customer.com",
	}, tenantID))

	lh := DeviceDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-dispositions", nil, tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
		Total        int                    `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 || len(resp.Dispositions) != 2 {
		t.Fatalf("expected 2 dispositions, got total=%d len=%d", resp.Total, len(resp.Dispositions))
	}
	// Second write (d2) has the later recorded_at, so it must come first.
	if resp.Dispositions[0].DeviceID != d2 || resp.Dispositions[1].DeviceID != d1 {
		t.Fatalf("expected recorded_at DESC order [%s, %s], got [%s, %s]",
			d2, d1, resp.Dispositions[0].DeviceID, resp.Dispositions[1].DeviceID)
	}
}

func TestDeviceDispositionList_ActiveFilter_ExcludesSuperseded(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	deviceID := pat1825SeedDevice(t, pool, tenantID, "laptop-list-3")

	ch := DeviceDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "lost",
		"reported_by": "jane@customer.com",
	}, tenantID))
	// Correction: supersedes the first row.
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "decommissioned",
		"reported_by": "jane@customer.com",
	}, tenantID))

	lh := DeviceDispositionListHandler(pool)

	// Unfiltered: both rows visible.
	rrAll := httptest.NewRecorder()
	lh.ServeHTTP(rrAll, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-dispositions", nil, tenantID))
	var respAll struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
	}
	if err := json.NewDecoder(rrAll.Body).Decode(&respAll); err != nil {
		t.Fatal(err)
	}
	if len(respAll.Dispositions) != 2 {
		t.Fatalf("unfiltered: expected 2 rows, got %d", len(respAll.Dispositions))
	}

	// ?active=true: only the live row.
	rrActive := httptest.NewRecorder()
	lh.ServeHTTP(rrActive, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-dispositions?active=true", nil, tenantID))
	if rrActive.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rrActive.Code, rrActive.Body.String())
	}
	var respActive struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
		Total        int                    `json:"total"`
	}
	if err := json.NewDecoder(rrActive.Body).Decode(&respActive); err != nil {
		t.Fatal(err)
	}
	if respActive.Total != 1 || len(respActive.Dispositions) != 1 {
		t.Fatalf("active=true: expected 1 row, got total=%d len=%d", respActive.Total, len(respActive.Dispositions))
	}
	if respActive.Dispositions[0].Category != "decommissioned" {
		t.Fatalf("active=true: expected the live row (decommissioned), got %q", respActive.Dispositions[0].Category)
	}
	if respActive.Dispositions[0].SupersededAt != nil {
		t.Fatalf("active=true row should not be superseded, got superseded_at=%v", respActive.Dispositions[0].SupersededAt)
	}
}

func TestDeviceDispositionList_TenantIsolation(t *testing.T) {
	pool := pat1825Pool(t)
	tenantA := pat1825SeedTenant(t, pool)
	tenantB := pat1825SeedTenant(t, pool)
	deviceA := pat1825SeedDevice(t, pool, tenantA, "laptop-tenant-a")
	deviceB := pat1825SeedDevice(t, pool, tenantB, "laptop-tenant-b")

	ch := DeviceDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantA+"/device-dispositions", map[string]any{
		"device_id":   deviceA,
		"category":    "lost",
		"reported_by": "jane@customer.com",
	}, tenantA))
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantB+"/device-dispositions", map[string]any{
		"device_id":   deviceB,
		"category":    "unaccounted",
		"reported_by": "bob@othercustomer.com",
	}, tenantB))

	lh := DeviceDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantA+"/device-dispositions", nil, tenantA))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Dispositions) != 1 {
		t.Fatalf("expected exactly 1 disposition for tenant A, got %d", len(resp.Dispositions))
	}
	if resp.Dispositions[0].DeviceID != deviceA {
		t.Fatalf("expected tenant A's device, got %q", resp.Dispositions[0].DeviceID)
	}
	for _, d := range resp.Dispositions {
		if d.DeviceID == deviceB {
			t.Fatalf("tenant B's disposition leaked into tenant A's list")
		}
	}
}

func TestDeviceDispositionList_Cohort_AllRowsShareCohortID(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	d1 := pat1825SeedDevice(t, pool, tenantID, "laptop-cohort-list-1")
	d2 := pat1825SeedDevice(t, pool, tenantID, "laptop-cohort-list-2")

	ch := DeviceDispositionCreateHandler(pool)
	ch.ServeHTTP(httptest.NewRecorder(), pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_ids":  []string{d1, d2},
		"category":    "decommissioned",
		"reported_by": "office-closure-project",
	}, tenantID))

	lh := DeviceDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-dispositions", nil, tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Dispositions) != 2 {
		t.Fatalf("expected 2 cohort rows, got %d", len(resp.Dispositions))
	}
	if resp.Dispositions[0].CohortID == nil || resp.Dispositions[1].CohortID == nil {
		t.Fatal("expected both rows to carry a cohort_id")
	}
	if *resp.Dispositions[0].CohortID != *resp.Dispositions[1].CohortID {
		t.Fatalf("expected both rows to share one cohort_id, got %q and %q",
			*resp.Dispositions[0].CohortID, *resp.Dispositions[1].CohortID)
	}
}

func TestDeviceDispositionList_CorrectionChainVisible(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	deviceID := pat1825SeedDevice(t, pool, tenantID, "laptop-chain")

	ch := DeviceDispositionCreateHandler(pool)
	rr1 := httptest.NewRecorder()
	ch.ServeHTTP(rr1, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "lost",
		"reported_by": "jane@customer.com",
		"note":        "not seen since the office move",
	}, tenantID))
	var resp1 deviceDispositionCreateResp
	_ = json.NewDecoder(rr1.Body).Decode(&resp1)
	originalID := resp1.Dispositions[0].ID

	rr2 := httptest.NewRecorder()
	ch.ServeHTTP(rr2, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   deviceID,
		"category":    "decommissioned",
		"reported_by": "jane@customer.com",
		"note":        "found it — was actually decommissioned properly",
	}, tenantID))
	var resp2 deviceDispositionCreateResp
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	correctionID := resp2.Dispositions[0].ID

	lh := DeviceDispositionListHandler(pool)
	rr := httptest.NewRecorder()
	lh.ServeHTTP(rr, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-dispositions", nil, tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Dispositions []deviceDispositionRow `json:"dispositions"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Dispositions) != 2 {
		t.Fatalf("expected both the original and its correction in the unfiltered list, got %d", len(resp.Dispositions))
	}

	byID := make(map[string]deviceDispositionRow, len(resp.Dispositions))
	for _, d := range resp.Dispositions {
		byID[d.ID] = d
	}

	original, ok := byID[originalID]
	if !ok {
		t.Fatalf("original row %q missing from list", originalID)
	}
	if original.SupersededAt == nil {
		t.Fatal("original row should have superseded_at populated")
	}
	if original.SupersededReason == nil || *original.SupersededReason != "correction" {
		t.Fatalf("original row should have superseded_reason=\"correction\", got %v", original.SupersededReason)
	}

	correction, ok := byID[correctionID]
	if !ok {
		t.Fatalf("correction row %q missing from list", correctionID)
	}
	if correction.SupersedesID == nil || *correction.SupersedesID != originalID {
		t.Fatalf("correction row should have supersedes_id=%q, got %v", originalID, correction.SupersedesID)
	}
	if correction.SupersededAt != nil {
		t.Fatal("correction row (the live tip) should not itself be superseded")
	}
}

// ---------------------------------------------------------------------------
// ClassifyState wiring through the real handler (not just the unit-tested
// devicelifecycle.ClassifyState in isolation).
// ---------------------------------------------------------------------------

func TestDeviceLifecycleHandler_ActiveDispositionClassifiesRemoved(t *testing.T) {
	pool := pat1825Pool(t)
	tenantID := pat1825SeedTenant(t, pool)
	dispositionedDevice := pat1825SeedDevice(t, pool, tenantID, "removed-device")
	ordinaryDevice := pat1825SeedDevice(t, pool, tenantID, "ordinary-device")

	dh := DeviceDispositionCreateHandler(pool)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, pat1825Req(http.MethodPost, "/admin/tenants/"+tenantID+"/device-dispositions", map[string]any{
		"device_id":   dispositionedDevice,
		"category":    "decommissioned",
		"reported_by": "jane@customer.com",
	}, tenantID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed disposition: got %d, body: %s", rr.Code, rr.Body.String())
	}

	lh := DeviceLifecycleHandler(pool)
	lrr := httptest.NewRecorder()
	lh.ServeHTTP(lrr, pat1825Req(http.MethodGet, "/admin/tenants/"+tenantID+"/device-lifecycle", nil, tenantID))
	if lrr.Code != http.StatusOK {
		t.Fatalf("device-lifecycle: got %d, body: %s", lrr.Code, lrr.Body.String())
	}
	var resp struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			State    string `json:"state"`
			Bucket   string `json:"bucket"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(lrr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	states := make(map[string]string, len(resp.Devices))
	for _, d := range resp.Devices {
		states[d.DeviceID] = d.State
	}
	if states[dispositionedDevice] != "removed" {
		t.Errorf("device with active disposition: got state %q, want \"removed\"", states[dispositionedDevice])
	}
	if states[ordinaryDevice] == "removed" {
		t.Errorf("device with no disposition should not classify as removed, got %q", states[ordinaryDevice])
	}
}
