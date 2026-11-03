package handlers

// DB-backed tests for PAT-1549's remediation-artefact admin endpoints.
// Skipped unless TEST_DATABASE_URL points at a scratch database — same
// isolated-schema convention as tenant_rules_evaluated_devices_db_test.go
// (pat1690Pool): search_path pinned to a per-ticket schema, dropped on
// cleanup, so no real data is touched.

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

const pat1549Schema = "pat1549_handlers_test"

func pat1549Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed remediation-artefact test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1549Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1549Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1549Schema,
		`CREATE TABLE ` + pat1549Schema + `.tenants (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1549Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1549Schema + `.tenants(id)
		)`,
		// Mirrors the columns migrations/0003 + 0019 add; not the full
		// compliance_rules shape (no nist/iso/CE mapping columns — unused here).
		`CREATE TABLE ` + pat1549Schema + `.compliance_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key           TEXT NOT NULL,
			benchmark          TEXT NOT NULL DEFAULT 'CIS Test',
			benchmark_version  TEXT NOT NULL DEFAULT 'v1.0.0',
			title              TEXT NOT NULL,
			description        TEXT,
			severity           TEXT NOT NULL DEFAULT 'high',
			signal_key         TEXT NOT NULL DEFAULT 'test_signal',
			comparator         TEXT NOT NULL DEFAULT 'eq',
			platform           TEXT NOT NULL DEFAULT 'macos'
		)`,
		`CREATE TABLE ` + pat1549Schema + `.compliance_evaluations (
			id            BIGSERIAL PRIMARY KEY,
			device_id     UUID NOT NULL,
			rule_id       UUID NOT NULL,
			status        TEXT NOT NULL,
			observed_value TEXT,
			evaluated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// Mirrors migrations/0141_remediation_artefacts.sql — kept in sync by
		// hand, same convention as this package's other DB-backed tests
		// (e.g. pat1690Schema above it in tenant_rules_evaluated_devices_db_test.go).
		`CREATE TABLE ` + pat1549Schema + `.remediation_artefacts (
			id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id             UUID        NOT NULL REFERENCES ` + pat1549Schema + `.tenants(id) ON DELETE CASCADE,
			device_id             UUID        NOT NULL REFERENCES ` + pat1549Schema + `.devices(id) ON DELETE CASCADE,
			rule_id               UUID        NOT NULL REFERENCES ` + pat1549Schema + `.compliance_rules(id),
			platform              TEXT        NOT NULL CHECK (platform IN ('macos', 'windows')),
			rule_pack_version     TEXT        NOT NULL,
			observed_prior_value  TEXT,
			payload               TEXT        NOT NULL,
			content_hash          TEXT        NOT NULL,
			generated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
			generated_by          TEXT        NOT NULL DEFAULT '',
			status                TEXT        NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'applied')),
			applied_observed_at   TIMESTAMPTZ,
			supersedes_id         UUID        REFERENCES ` + pat1549Schema + `.remediation_artefacts(id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1549Schema+` CASCADE`)
	})
	return pool
}

func pat1549SeedTenantDeviceRule(t *testing.T, pool *pgxpool.Pool, ruleKey, platform string) (tenantID, deviceID, ruleID string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, platform, benchmark_version)
		VALUES ($1, $2, $3, 'v3.0.0') RETURNING id::text
	`, ruleKey, "Test rule "+ruleKey, platform).Scan(&ruleID); err != nil {
		t.Fatalf("insert compliance_rules: %v", err)
	}
	return tenantID, deviceID, ruleID
}

func pat1549SeedEvaluation(t *testing.T, pool *pgxpool.Pool, deviceID, ruleID, status string, observed *string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, deviceID, ruleID, status, observed); err != nil {
		t.Fatalf("insert compliance_evaluations: %v", err)
	}
}

func pat1549Req(method, target string, body any, tenantID, artefactID string) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, target, &buf)
	rctx := chi.NewRouteContext()
	if tenantID != "" {
		rctx.URLParams.Add("tenantID", tenantID)
	}
	if artefactID != "" {
		rctx.URLParams.Add("artefactID", artefactID)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestRemediationArtefactGenerate_Success(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_1_1_filevault", "macos")
	observed := "Off"
	pat1549SeedEvaluation(t, pool, deviceID, ruleID, "fail", &observed)

	handler := RemediationArtefactGenerateHandler(pool)
	req := pat1549Req(http.MethodPost, "/admin/tenants/"+tenantID+"/remediation-artefacts",
		map[string]string{"device_id": deviceID, "rule_id": ruleID, "generated_by": "test-suite"}, tenantID, "")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rr.Code, rr.Body.String())
	}
	var got remediationArtefactDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Platform != "macos" {
		t.Errorf("Platform = %q, want macos", got.Platform)
	}
	if got.Status != "issued" {
		t.Errorf("Status = %q, want issued", got.Status)
	}
	if got.ObservedPriorValue == nil || *got.ObservedPriorValue != "Off" {
		t.Errorf("ObservedPriorValue = %v, want \"Off\"", got.ObservedPriorValue)
	}
	if got.SupersedesID != nil {
		t.Errorf("SupersedesID = %v, want nil for a first generation", got.SupersedesID)
	}
	if got.Payload == "" || !bytesContains(got.Payload, "com.apple.MCX.FileVault2") {
		t.Errorf("payload does not contain the expected PayloadType: %s", got.Payload)
	}
}

func bytesContains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

func TestRemediationArtefactGenerate_Regeneration_Supersedes(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_1_1_filevault", "macos")
	pat1549SeedEvaluation(t, pool, deviceID, ruleID, "fail", nil)

	handler := RemediationArtefactGenerateHandler(pool)
	body := map[string]string{"device_id": deviceID, "rule_id": ruleID, "generated_by": "test-suite"}

	rr1 := httptest.NewRecorder()
	handler(rr1, pat1549Req(http.MethodPost, "/x", body, tenantID, ""))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first generate status = %d, body: %s", rr1.Code, rr1.Body.String())
	}
	var first remediationArtefactDetail
	_ = json.Unmarshal(rr1.Body.Bytes(), &first)

	rr2 := httptest.NewRecorder()
	handler(rr2, pat1549Req(http.MethodPost, "/x", body, tenantID, ""))
	if rr2.Code != http.StatusCreated {
		t.Fatalf("second generate status = %d, body: %s", rr2.Code, rr2.Body.String())
	}
	var second remediationArtefactDetail
	_ = json.Unmarshal(rr2.Body.Bytes(), &second)

	if second.SupersedesID == nil || *second.SupersedesID != first.ID {
		t.Fatalf("second.SupersedesID = %v, want %q", second.SupersedesID, first.ID)
	}
	if second.ID == first.ID {
		t.Fatalf("regeneration must produce a NEW row, not edit the existing one")
	}

	// Both rows must still be present — regeneration never deletes/edits.
	listHandler := RemediationArtefactListHandler(pool)
	rr3 := httptest.NewRecorder()
	listHandler(rr3, pat1549Req(http.MethodGet, "/x", nil, tenantID, ""))
	var listResp struct {
		Artefacts []remediationArtefactSummary `json:"artefacts"`
		Total     int                          `json:"total"`
	}
	if err := json.Unmarshal(rr3.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listResp.Total != 2 {
		t.Fatalf("total = %d, want 2 (both the superseded and the current artefact)", listResp.Total)
	}
}

func TestRemediationArtefactGenerate_UnmappedRule_Returns422(t *testing.T) {
	pool := pat1549Pool(t)
	// SIP has no curated macOS mapping (see internal/remediation/mapping.go).
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_3_sip", "macos")
	pat1549SeedEvaluation(t, pool, deviceID, ruleID, "fail", nil)

	handler := RemediationArtefactGenerateHandler(pool)
	rr := httptest.NewRecorder()
	handler(rr, pat1549Req(http.MethodPost, "/x",
		map[string]string{"device_id": deviceID, "rule_id": ruleID}, tenantID, ""))

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRemediationArtefactGenerate_RuleNotCurrentlyFailing_Returns409(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_1_1_filevault", "macos")
	pat1549SeedEvaluation(t, pool, deviceID, ruleID, "pass", nil)

	handler := RemediationArtefactGenerateHandler(pool)
	rr := httptest.NewRecorder()
	handler(rr, pat1549Req(http.MethodPost, "/x",
		map[string]string{"device_id": deviceID, "rule_id": ruleID}, tenantID, ""))

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRemediationArtefactGenerate_NoEvaluationOnRecord_Returns409(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_1_1_filevault", "macos")
	// No compliance_evaluations row seeded at all — absence must never be
	// treated as "safe to generate".

	handler := RemediationArtefactGenerateHandler(pool)
	rr := httptest.NewRecorder()
	handler(rr, pat1549Req(http.MethodPost, "/x",
		map[string]string{"device_id": deviceID, "rule_id": ruleID}, tenantID, ""))

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRemediationArtefactGenerate_UnknownRuleID_Returns404 stands in for "a
// CVE finding is correctly excluded from generation": device_cve_findings
// keys on cve_id (text), never a compliance_rules UUID, so a CVE finding
// can never produce a rule_id that resolves here at all — the same 404 this
// test exercises for any other unknown/non-existent rule_id.
func TestRemediationArtefactGenerate_UnknownRuleID_Returns404(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, _ := pat1549SeedTenantDeviceRule(t, pool, "cis_macos_2_5_1_1_filevault", "macos")

	handler := RemediationArtefactGenerateHandler(pool)
	rr := httptest.NewRecorder()
	handler(rr, pat1549Req(http.MethodPost, "/x",
		map[string]string{"device_id": deviceID, "rule_id": "00000000-0000-0000-0000-000000000000"}, tenantID, ""))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRemediationArtefactGet_ScopedToTenant(t *testing.T) {
	pool := pat1549Pool(t)
	tenantID, deviceID, ruleID := pat1549SeedTenantDeviceRule(t, pool, "cis_win_18_10_11_bitlocker_os_drive", "windows")
	pat1549SeedEvaluation(t, pool, deviceID, ruleID, "fail", nil)
	otherTenantID, _, _ := pat1549SeedTenantDeviceRule(t, pool, "cis_win_18_10_11_bitlocker_os_drive", "windows")

	genHandler := RemediationArtefactGenerateHandler(pool)
	rr := httptest.NewRecorder()
	genHandler(rr, pat1549Req(http.MethodPost, "/x",
		map[string]string{"device_id": deviceID, "rule_id": ruleID}, tenantID, ""))
	if rr.Code != http.StatusCreated {
		t.Fatalf("generate status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var created remediationArtefactDetail
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	getHandler := RemediationArtefactGetHandler(pool)

	rrOK := httptest.NewRecorder()
	getHandler(rrOK, pat1549Req(http.MethodGet, "/x", nil, tenantID, created.ID))
	if rrOK.Code != http.StatusOK {
		t.Fatalf("get (own tenant) status = %d, body: %s", rrOK.Code, rrOK.Body.String())
	}
	var got remediationArtefactDetail
	_ = json.Unmarshal(rrOK.Body.Bytes(), &got)
	if !bytesContains(got.Payload, "device_vendor_msft_bitlocker_requiredeviceencryption") {
		t.Errorf("payload missing expected settingDefinitionId: %s", got.Payload)
	}

	rrWrongTenant := httptest.NewRecorder()
	getHandler(rrWrongTenant, pat1549Req(http.MethodGet, "/x", nil, otherTenantID, created.ID))
	if rrWrongTenant.Code != http.StatusNotFound {
		t.Fatalf("get (other tenant) status = %d, want 404", rrWrongTenant.Code)
	}
}
