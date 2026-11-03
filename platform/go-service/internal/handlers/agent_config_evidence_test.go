package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/evidencecatalogue"
)

func evidenceTestHandler(authFn agentConfigAuthFn, getFn agentConfigGetFn, evidenceFn windowsEvidenceFn) http.HandlerFunc {
	return newAgentConfigHandlerWithEvidence(newTestSigningKey(), authFn, getFn, nil, 0, nil, evidenceFn)
}

func TestAgentConfigEvidenceAuthenticationPrecedesPublicationAndETag(t *testing.T) {
	called := false
	h := evidenceTestHandler(acAuthNever(), acGetEmpty(), func(context.Context) (*evidencecatalogue.WindowsDelivery, error) { called = true; return nil, nil })
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	req.Header.Set("If-None-Match", `"anything"`)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthenticated publication: status=%d called=%v", w.Code, called)
	}
}

func TestAgentConfigEvidenceSignedExactBytesAndOlderAgentCompatibility(t *testing.T) {
	delivery, err := evidencecatalogue.EmbeddedWindowsDelivery()
	if err != nil {
		t.Fatal(err)
	}
	h := evidenceTestHandler(acAuthAlways(acTestTenantID), acGetRow(acTestTenantID, 3), func(context.Context) (*evidencecatalogue.WindowsDelivery, error) { return delivery, nil })
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	var envelope agentConfigResp
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw := decodeSignedPayload(t, envelope, newTestSigningKey())
	var cfg struct {
		Evidence *evidencecatalogue.WindowsDelivery `json:"windows_installation_evidence"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Evidence == nil || cfg.Evidence.ContentHash != evidencecatalogue.WindowsContentHash || len(cfg.Evidence.Targets) != 0 {
		t.Fatalf("invalid delivered evidence: %s", raw)
	}
	// Older parsers verify received bytes then ignore unknown additive fields.
	var older struct {
		TenantID      string `json:"tenant_id"`
		ConfigVersion int    `json:"config_version"`
	}
	if err := json.Unmarshal(raw, &older); err != nil || older.TenantID != acTestTenantID || older.ConfigVersion != 3 {
		t.Fatal("old parser compatibility lost")
	}
	tampered := strings.Replace(string(raw), `"delivery_version":1`, `"delivery_version":2`, 1)
	if agentconfig.Verify(newTestSigningKey().Public, []byte(tampered), envelope.Signature) == nil {
		t.Fatal("unsigned evidence mutation accepted")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	req.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w2 := httptest.NewRecorder()
	h(w2, req)
	if w2.Code != http.StatusNotModified {
		t.Fatal("stable delivery changed ETag")
	}
	delivery.DeliveryVersion++
	w3 := httptest.NewRecorder()
	h(w3, req)
	if w3.Code != http.StatusOK || w3.Header().Get("ETag") == w.Header().Get("ETag") {
		t.Fatal("delivery publication did not invalidate ETag")
	}
}

func TestAgentConfigEvidenceFailureOmitsOnlyFeatureAndCannotUseTenantInjection(t *testing.T) {
	injected, _ := evidencecatalogue.EmbeddedWindowsDelivery()
	injected.DeliveryVersion = 999
	getFn := func(context.Context, string) (agentConfigRow, bool, error) {
		body := agentconfig.DefaultConfigBody()
		body.WindowsInstallationEvidence = injected
		return agentConfigRow{TenantID: acTestTenantID, ConfigVersion: 3, Body: body}, true, nil
	}
	h := evidenceTestHandler(acAuthAlways(acTestTenantID), getFn, func(context.Context) (*evidencecatalogue.WindowsDelivery, error) {
		return nil, errors.New("unavailable or rollback publication")
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("unrelated config unavailable: %d", w.Code)
	}
	var envelope agentConfigResp
	_ = json.Unmarshal(w.Body.Bytes(), &envelope)
	raw := decodeSignedPayload(t, envelope, newTestSigningKey())
	if strings.Contains(string(raw), "windows_installation_evidence") || !strings.Contains(string(raw), `"decommission":`) || !strings.Contains(string(raw), `"update_channel":"stable"`) {
		t.Fatalf("feature isolation failed: %s", raw)
	}
	stored, _ := json.Marshal(getConfigBodyForEvidenceTest(injected))
	if strings.Contains(string(stored), "windows_installation_evidence") {
		t.Fatal("response-only evidence persisted")
	}
}

func getConfigBodyForEvidenceTest(d *evidencecatalogue.WindowsDelivery) agentconfig.ConfigBody {
	body := agentconfig.DefaultConfigBody()
	body.WindowsInstallationEvidence = d
	return body
}

func TestAdminAgentConfigRejectsEvidenceInjectionIncludingNull(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `{"delivery_version":999,"targets":[]}`} {
		h := newAdminAgentConfigPutHandler(newTestSigningKey(), nil, nil, nil)
		req := acWithTenantID(httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(`{"windows_installation_evidence":`+value+`}`)), acTestTenantID)
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "reserved response-only") {
			t.Fatalf("admin injection not rejected: %d %s", w.Code, w.Body.String())
		}
	}
}
