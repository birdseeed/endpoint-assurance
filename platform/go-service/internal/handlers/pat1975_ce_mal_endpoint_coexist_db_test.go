package handlers

// PAT-1975 regression: ce_mal_endpoint_protection moves from pure
// ceSourceAttestation to ceSourceAutoWithAttestationFallback — coexistence,
// not a flip (Andy, 2026-09-21). cis_win_18_9_45_defender_realtime evidence
// resolves the control directly where it exists; a tenant's stored
// attestation remains the fallback where it doesn't, and is never silently
// dropped once evidence takes over — it is surfaced as superseded.
//
// Reuses the pat1776CEPool schema helpers (pat1776_undetermined_ce_db_test.go)
// rather than duplicating the isolated-schema setup: same convention (skip
// unless TEST_DATABASE_URL is set), same minimal table set, same tenant/device
// insert helpers.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pat1975InsertRule inserts a compliance_rules row for ruleKey and returns
// its id.
func pat1975InsertRule(t *testing.T, pool *pgxpool.Pool, ruleKey string) string {
	t.Helper()
	var ruleID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ($1, $1, 'high')
		RETURNING id::text
	`, ruleKey).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule %q: %v", ruleKey, err)
	}
	return ruleID
}

// pat1975InsertAttestation writes a ce_attestations row directly (bypassing
// the PUT handler — these tests are about GET-side resolution).
func pat1975InsertAttestation(t *testing.T, pool *pgxpool.Pool, tenantID, controlID, answer string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ce_attestations (tenant_id, control_id, answer, notes)
		VALUES ($1::uuid, $2, $3, '')
	`, tenantID, controlID, answer); err != nil {
		t.Fatalf("insert attestation (tenant %s, control %s): %v", tenantID, controlID, err)
	}
}

// pat1975CEStatus fetches and decodes the CE status response for tenantID.
func pat1975CEStatus(t *testing.T, pool *pgxpool.Pool, tenantID string) ceStatusResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/ce-status", nil)
	req = catWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantCEStatusHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp ceStatusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return resp
}

// TestCEModelMalEndpointProtectionIsCoexistenceSource is a pure-function
// check (no DB) that the model change landed as specified: coexistence
// source, the Windows Defender real-time rule key only (no EDR presence-match
// keys), and still eligible for attestation PUT writes via
// attestationControlIDs.
func TestCEModelMalEndpointProtectionIsCoexistenceSource(t *testing.T) {
	ctrl := findControl(t, "ce_mal_endpoint_protection")

	if ctrl.Source != ceSourceAutoWithAttestationFallback {
		t.Errorf("ce_mal_endpoint_protection.Source = %q, want %q", ctrl.Source, ceSourceAutoWithAttestationFallback)
	}
	if !hasKeyPrefix(ctrl.RuleKeys, "cis_win_18_9_45_defender_realtime") {
		t.Errorf("ce_mal_endpoint_protection.RuleKeys = %v, want to contain cis_win_18_9_45_defender_realtime", ctrl.RuleKeys)
	}
	if len(ctrl.RuleKeys) != 1 {
		t.Errorf("ce_mal_endpoint_protection.RuleKeys = %v, want exactly the one Windows Defender key (no EDR presence-match keys)", ctrl.RuleKeys)
	}
	if !attestationControlIDs["ce_mal_endpoint_protection"] {
		t.Errorf(`attestationControlIDs["ce_mal_endpoint_protection"] = false, want true (PUT /admin/tenant-attestations must still accept writes for this control)`)
	}
}

// TestTenantCEStatusHandler_MalEndpointProtection_EvidenceOnly: a tenant with
// Windows Defender real-time evidence and no attestation resolves from
// evidence.
func TestTenantCEStatusHandler_MalEndpointProtection_EvidenceOnly(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)
	ruleID := pat1975InsertRule(t, pool, "cis_win_18_9_45_defender_realtime")

	dev := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, dev, ruleID, "pass", nil)

	resp := pat1975CEStatus(t, pool, tenantID)
	ctrl := findCEControl(t, resp, "ce_mal_endpoint_protection")

	if ctrl.Status != "pass" {
		t.Errorf("Status = %q, want \"pass\"", ctrl.Status)
	}
	if ctrl.ResolvedVia != "evidence" {
		t.Errorf("ResolvedVia = %q, want \"evidence\"", ctrl.ResolvedVia)
	}
	if ctrl.AutoEvidence == nil {
		t.Fatalf("AutoEvidence is nil")
	}
	if ctrl.AutoEvidence.PassCount != 1 || ctrl.AutoEvidence.TotalCount != 1 {
		t.Errorf("AutoEvidence = %+v, want PassCount=1 TotalCount=1", ctrl.AutoEvidence)
	}
	if ctrl.Attestation == nil {
		t.Fatalf("Attestation is nil; must still be present (even if empty) for a coexistence control")
	}
	if ctrl.Attestation.Answer != nil {
		t.Errorf("Attestation.Answer = %v, want nil (no attestation was stored)", *ctrl.Attestation.Answer)
	}
	if ctrl.Attestation.Superseded {
		t.Errorf("Attestation.Superseded = true, want false (nothing to supersede)")
	}
}

// TestTenantCEStatusHandler_MalEndpointProtection_AttestationOnly: a tenant
// with an attestation and no evidence resolves from the attestation, exactly
// as the old pure-attestation behaviour did.
func TestTenantCEStatusHandler_MalEndpointProtection_AttestationOnly(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)
	pat1975InsertAttestation(t, pool, tenantID, "ce_mal_endpoint_protection", "yes")

	resp := pat1975CEStatus(t, pool, tenantID)
	ctrl := findCEControl(t, resp, "ce_mal_endpoint_protection")

	if ctrl.Status != "pass" {
		t.Errorf("Status = %q, want \"pass\"", ctrl.Status)
	}
	if ctrl.ResolvedVia != "attestation_fallback" {
		t.Errorf("ResolvedVia = %q, want \"attestation_fallback\"", ctrl.ResolvedVia)
	}
	if ctrl.Attestation == nil || ctrl.Attestation.Answer == nil || *ctrl.Attestation.Answer != "yes" {
		t.Fatalf("Attestation = %+v, want Answer=\"yes\"", ctrl.Attestation)
	}
	if ctrl.Attestation.Superseded {
		t.Errorf("Attestation.Superseded = true, want false (no evidence exists to supersede it)")
	}
}

// TestTenantCEStatusHandler_MalEndpointProtection_EvidenceWinsOverAttestation:
// a tenant with BOTH a real, evidenced fail AND a stored "yes" attestation.
// Evidence wins (status "fail", not "pass"), and the attestation is still
// surfaced in the response, marked superseded rather than hidden or deleted.
func TestTenantCEStatusHandler_MalEndpointProtection_EvidenceWinsOverAttestation(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)
	ruleID := pat1975InsertRule(t, pool, "cis_win_18_9_45_defender_realtime")

	dev := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, dev, ruleID, "fail", strPtr("Off"))
	pat1975InsertAttestation(t, pool, tenantID, "ce_mal_endpoint_protection", "yes")

	resp := pat1975CEStatus(t, pool, tenantID)
	ctrl := findCEControl(t, resp, "ce_mal_endpoint_protection")

	if ctrl.Status != "fail" {
		t.Errorf("Status = %q, want \"fail\" (evidence of a real off-state must win over a stale \"yes\" attestation)", ctrl.Status)
	}
	if ctrl.ResolvedVia != "evidence" {
		t.Errorf("ResolvedVia = %q, want \"evidence\"", ctrl.ResolvedVia)
	}
	if ctrl.AutoEvidence == nil || ctrl.AutoEvidence.FailCount != 1 {
		t.Errorf("AutoEvidence = %+v, want FailCount=1", ctrl.AutoEvidence)
	}
	if ctrl.Attestation == nil || ctrl.Attestation.Answer == nil || *ctrl.Attestation.Answer != "yes" {
		t.Fatalf("Attestation = %+v, want the stored \"yes\" answer to still be present, not deleted or hidden", ctrl.Attestation)
	}
	if !ctrl.Attestation.Superseded {
		t.Errorf("Attestation.Superseded = false, want true (evidence resolved the control instead of this attestation)")
	}
}

// TestTenantCEStatusHandler_MalEndpointProtection_Neither: no evidence and no
// attestation stays needs_attestation, matching the pre-existing no-evidence
// no-attestation status for a pure attestation control.
func TestTenantCEStatusHandler_MalEndpointProtection_Neither(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)

	resp := pat1975CEStatus(t, pool, tenantID)
	ctrl := findCEControl(t, resp, "ce_mal_endpoint_protection")

	if ctrl.Status != "needs_attestation" {
		t.Errorf("Status = %q, want \"needs_attestation\"", ctrl.Status)
	}
	if ctrl.ResolvedVia != "attestation_fallback" {
		t.Errorf("ResolvedVia = %q, want \"attestation_fallback\"", ctrl.ResolvedVia)
	}
	if ctrl.Attestation == nil || ctrl.Attestation.Answer != nil {
		t.Errorf("Attestation = %+v, want Answer=nil", ctrl.Attestation)
	}
	if ctrl.Attestation.Superseded {
		t.Errorf("Attestation.Superseded = true, want false")
	}
}

// TestTenantCEStatusHandler_PureSourceControlsUnaffectedByCoexistence is the
// regression check: a pure ceSourceAuto control (ce_fw_host) and a pure
// ceSourceAttestation control (ce_fw_boundary) must behave exactly as before
// — ceControlStatus and ceControlJSON are shared code paths used by every
// control in the model, so the coexistence branch must be additive only.
func TestTenantCEStatusHandler_PureSourceControlsUnaffectedByCoexistence(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)
	ruleID := pat1975InsertRule(t, pool, "cis_macos_2_5_2_2_firewall")

	dev := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, dev, ruleID, "pass", nil)
	pat1975InsertAttestation(t, pool, tenantID, "ce_fw_boundary", "no")

	resp := pat1975CEStatus(t, pool, tenantID)

	auto := findCEControl(t, resp, "ce_fw_host")
	if auto.Status != "pass" {
		t.Errorf("ce_fw_host.Status = %q, want \"pass\"", auto.Status)
	}
	if auto.ResolvedVia != "evidence" {
		t.Errorf("ce_fw_host.ResolvedVia = %q, want \"evidence\"", auto.ResolvedVia)
	}
	if auto.Attestation != nil {
		t.Errorf("ce_fw_host.Attestation = %+v, want nil (pure ceSourceAuto control has no attestation surface)", auto.Attestation)
	}

	attest := findCEControl(t, resp, "ce_fw_boundary")
	if attest.Status != "fail" {
		t.Errorf("ce_fw_boundary.Status = %q, want \"fail\"", attest.Status)
	}
	if attest.ResolvedVia != "attestation" {
		t.Errorf("ce_fw_boundary.ResolvedVia = %q, want \"attestation\"", attest.ResolvedVia)
	}
	if attest.AutoEvidence != nil {
		t.Errorf("ce_fw_boundary.AutoEvidence = %+v, want nil (pure ceSourceAttestation control has no evidence surface)", attest.AutoEvidence)
	}
	if attest.Attestation == nil || attest.Attestation.Superseded {
		t.Errorf("ce_fw_boundary.Attestation = %+v, want present and Superseded=false (pure attestation controls are never superseded)", attest.Attestation)
	}
}
