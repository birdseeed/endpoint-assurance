package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMutateBlockedVersionsBodyPreservesUnrelatedFields(t *testing.T) {
	original := []byte(`{
		"tier":"patch",
		"report_user_attribution":"full_upn",
		"proxy":{"mode":"manual","host":"proxy.example"},
		"future_field":{"nested":[1,{"keep":true}]},
		"blocked_versions":{"slack":["4.50.0"],"zoom":["6.0"]}
	}`)

	added, blocked, changed, err := mutateBlockedVersionsBody(original, "add", "slack", "4.51.180")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !changed {
		t.Fatal("add changed=false, want true")
	}
	if got := blocked["slack"]; len(got) != 2 || got[0] != "4.50.0" || got[1] != "4.51.180" {
		t.Fatalf("slack versions after add = %v", got)
	}
	assertJSONFieldEqual(t, original, added, "tier")
	assertJSONFieldEqual(t, original, added, "report_user_attribution")
	assertJSONFieldEqual(t, original, added, "proxy")
	assertJSONFieldEqual(t, original, added, "future_field")

	removed, blocked, changed, err := mutateBlockedVersionsBody(added, "remove", "slack", "4.50.0")
	if err != nil {
		t.Fatalf("remove first version: %v", err)
	}
	if !changed || len(blocked["slack"]) != 1 || blocked["slack"][0] != "4.51.180" {
		t.Fatalf("remove first version: changed=%v blocked=%v", changed, blocked)
	}
	removed, blocked, changed, err = mutateBlockedVersionsBody(removed, "remove", "slack", "4.51.180")
	if err != nil {
		t.Fatalf("remove last slack version: %v", err)
	}
	if !changed {
		t.Fatal("remove last slack version changed=false, want true")
	}
	if _, ok := blocked["slack"]; ok {
		t.Fatalf("empty label retained: %v", blocked)
	}
	if got := blocked["zoom"]; len(got) != 1 || got[0] != "6.0" {
		t.Fatalf("unrelated blocked label changed: %v", blocked)
	}
	assertJSONFieldEqual(t, original, removed, "future_field")
}

func TestMutateBlockedVersionsBodyIsIdempotentAndOmitsEmptyMap(t *testing.T) {
	body := []byte(`{"tier":"patch","blocked_versions":{"slack":["4.51.180"]}}`)

	unchanged, blocked, changed, err := mutateBlockedVersionsBody(body, "add", "slack", "4.51.180")
	if err != nil {
		t.Fatalf("duplicate add: %v", err)
	}
	if changed || string(unchanged) != string(body) || len(blocked["slack"]) != 1 {
		t.Fatalf("duplicate add not idempotent: changed=%v body=%s blocked=%v", changed, unchanged, blocked)
	}

	unchanged, _, changed, err = mutateBlockedVersionsBody(body, "remove", "slack", "absent")
	if err != nil {
		t.Fatalf("absent remove: %v", err)
	}
	if changed || string(unchanged) != string(body) {
		t.Fatalf("absent remove not idempotent: changed=%v body=%s", changed, unchanged)
	}

	empty, blocked, changed, err := mutateBlockedVersionsBody(body, "remove", "slack", "4.51.180")
	if err != nil {
		t.Fatalf("last remove: %v", err)
	}
	if !changed || len(blocked) != 0 {
		t.Fatalf("last remove: changed=%v blocked=%v", changed, blocked)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(empty, &raw); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if _, ok := raw["blocked_versions"]; ok {
		t.Fatalf("empty blocked_versions must be omitted, got %s", empty)
	}
}

func TestValidateBlockedVersionMutationReq(t *testing.T) {
	valid := blockedVersionMutationReq{Action: "add", Label: "google-chrome", Version: "139.0.7258.67"}
	if err := validateBlockedVersionMutationReq(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*blockedVersionMutationReq)
	}{
		{"unknown action", func(r *blockedVersionMutationReq) { r.Action = "replace" }},
		{"empty label", func(r *blockedVersionMutationReq) { r.Label = "" }},
		{"label leading whitespace", func(r *blockedVersionMutationReq) { r.Label = " slack" }},
		{"label path separator", func(r *blockedVersionMutationReq) { r.Label = "../slack" }},
		{"empty version", func(r *blockedVersionMutationReq) { r.Version = "" }},
		{"version trailing whitespace", func(r *blockedVersionMutationReq) { r.Version = "1.0 " }},
		{"version control character", func(r *blockedVersionMutationReq) { r.Version = "1.0\n" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.edit(&req)
			if err := validateBlockedVersionMutationReq(req); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestAdminBlockedVersionsPatchHandler(t *testing.T) {
	var captured blockedVersionMutationReq
	handler := newAdminBlockedVersionsPatchHandler(func(_ context.Context, tenantID string, req blockedVersionMutationReq) (blockedVersionMutationResult, error) {
		if tenantID != acTestTenantID {
			t.Fatalf("tenantID = %q", tenantID)
		}
		captured = req
		return blockedVersionMutationResult{
			BlockedVersions: map[string][]string{"slack": {"4.51.180"}},
			Changed:         true,
			ConfigVersion:   12,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPatch, "/admin/agent-config/"+acTestTenantID+"/blocked-versions", strings.NewReader(`{"action":"add","label":"slack","version":"4.51.180"}`))
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if captured.Action != "add" || captured.Label != "slack" || captured.Version != "4.51.180" {
		t.Errorf("decoded request = %+v", captured)
	}
	var resp blockedVersionMutationResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Changed || resp.ConfigVersion != 12 || resp.TenantID != acTestTenantID {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAdminBlockedVersionsPatchHandlerRejectsInvalidInput(t *testing.T) {
	mutateFn := func(_ context.Context, _ string, _ blockedVersionMutationReq) (blockedVersionMutationResult, error) {
		t.Fatal("mutate must not run")
		return blockedVersionMutationResult{}, nil
	}
	handler := newAdminBlockedVersionsPatchHandler(mutateFn)
	tests := []struct {
		name     string
		tenantID string
		body     string
	}{
		{"invalid tenant", "not-a-uuid", `{"action":"add","label":"slack","version":"1"}`},
		{"unknown field", acTestTenantID, `{"action":"add","label":"slack","version":"1","whole_config":{}}`},
		{"caller actor spoof", acTestTenantID, `{"action":"add","label":"slack","version":"1","updated_by":"andy@patched.im"}`},
		{"trailing JSON", acTestTenantID, `{"action":"add","label":"slack","version":"1"}{}`},
		{"invalid action", acTestTenantID, `{"action":"clear","label":"slack","version":"1"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/admin/agent-config/"+tc.tenantID+"/blocked-versions", strings.NewReader(tc.body))
			req = acWithTenantID(req, tc.tenantID)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestAdminBlockedVersionsPatchHandlerTenantNotFound(t *testing.T) {
	handler := newAdminBlockedVersionsPatchHandler(func(_ context.Context, _ string, _ blockedVersionMutationReq) (blockedVersionMutationResult, error) {
		return blockedVersionMutationResult{}, errBlockedVersionTenantNotFound
	})
	req := httptest.NewRequest(http.MethodPatch, "/admin/agent-config/"+acTestTenantID+"/blocked-versions", strings.NewReader(`{"action":"remove","label":"slack","version":"1"}`))
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminBlockedVersionsPatchHandlerUninitialised(t *testing.T) {
	handler := newAdminBlockedVersionsPatchHandler(func(_ context.Context, _ string, _ blockedVersionMutationReq) (blockedVersionMutationResult, error) {
		return blockedVersionMutationResult{}, errAgentConfigNotInitialised
	})
	req := httptest.NewRequest(http.MethodPatch, "/admin/agent-config/"+acTestTenantID+"/blocked-versions", strings.NewReader(`{"action":"add","label":"slack","version":"1"}`))
	req = acWithTenantID(req, acTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict || strings.TrimSpace(rr.Body.String()) != "agent config not initialised" {
		t.Fatalf("response = %d %q, want 409 agent config not initialised", rr.Code, rr.Body.String())
	}
}

func TestDbMutateBlockedVersionRejectsUninitialisedConfig(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := adSeedTenant(t, ctx, pool, "pat1238-first-write")

	_, err := dbMutateBlockedVersion(ctx, pool, tenantID, blockedVersionMutationReq{Action: "add", Label: "slack", Version: "4.51.180"})
	if !errors.Is(err, errAgentConfigNotInitialised) {
		t.Fatalf("error = %v, want agent config not initialised", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("incident mutation must not synthesise config: count=%d err=%v", count, err)
	}
}

func TestDbMutateBlockedVersionConcurrentAddsAreLossless(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := adSeedTenant(t, ctx, pool, "pat1238-concurrent-adds")

	body := []byte(`{"tier":"managed","report_user_attribution":"full_upn","future_field":{"preserve":true},"blocked_versions":{"zoom":["6.0"]}}`)
	if _, err := pool.Exec(ctx, `INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by) VALUES ($1::uuid, 40, $2::jsonb, now(), 'seed')`, tenantID, body); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	start := make(chan struct{})
	results := make(chan blockedVersionMutationResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, version := range []string{"4.50.0", "4.51.180"} {
		version := version
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := dbMutateBlockedVersion(ctx, pool, tenantID, blockedVersionMutationReq{Action: "add", Label: "slack", Version: version})
			results <- result
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent mutate: %v", err)
		}
	}
	for result := range results {
		if !result.Changed {
			t.Errorf("concurrent effective add reported unchanged: %+v", result)
		}
	}

	var version int
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT config_version, body FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&version, &stored); err != nil {
		t.Fatalf("read final config: %v", err)
	}
	if version != 42 {
		t.Errorf("config_version = %d, want 42", version)
	}
	var updatedBy string
	if err := pool.QueryRow(ctx, `SELECT updated_by FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&updatedBy); err != nil {
		t.Fatalf("read updated_by: %v", err)
	}
	if updatedBy != adminSharedTokenActor {
		t.Errorf("updated_by = %q, want server-established %q", updatedBy, adminSharedTokenActor)
	}
	noOp, err := dbMutateBlockedVersion(ctx, pool, tenantID, blockedVersionMutationReq{Action: "add", Label: "slack", Version: "4.51.180"})
	if err != nil {
		t.Fatalf("repeat add: %v", err)
	}
	if noOp.Changed || noOp.ConfigVersion != 42 {
		t.Errorf("repeat add = %+v, want changed=false config_version=42", noOp)
	}
	var versionAfterNoOp int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&versionAfterNoOp); err != nil {
		t.Fatalf("read config_version after repeat add: %v", err)
	}
	if versionAfterNoOp != 42 {
		t.Errorf("config_version after repeat add = %d, want 42", versionAfterNoOp)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stored, &raw); err != nil {
		t.Fatalf("decode final body: %v", err)
	}
	var blocked map[string][]string
	if err := json.Unmarshal(raw["blocked_versions"], &blocked); err != nil {
		t.Fatalf("decode final blocked_versions: %v", err)
	}
	if !containsAll(blocked["slack"], "4.50.0", "4.51.180") || !containsAll(blocked["zoom"], "6.0") {
		t.Errorf("final blocked_versions lost data: %v", blocked)
	}
	var future map[string]bool
	if err := json.Unmarshal(raw["future_field"], &future); err != nil || !future["preserve"] {
		t.Errorf("future_field not preserved: value=%s err=%v", raw["future_field"], err)
	}
	var attribution string
	if err := json.Unmarshal(raw["report_user_attribution"], &attribution); err != nil || attribution != "full_upn" {
		t.Errorf("report_user_attribution not preserved: value=%s err=%v", raw["report_user_attribution"], err)
	}
}

func TestDbMutateBlockedVersionMissingTenant(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	_, err := dbMutateBlockedVersion(context.Background(), pool, acOtherTenantID, blockedVersionMutationReq{Action: "add", Label: "slack", Version: "1"})
	if !errors.Is(err, errBlockedVersionTenantNotFound) {
		t.Fatalf("error = %v, want tenant not found", err)
	}
}

func assertJSONFieldEqual(t *testing.T, before, after []byte, field string) {
	t.Helper()
	var a, b map[string]interface{}
	if err := json.Unmarshal(before, &a); err != nil {
		t.Fatalf("decode before: %v", err)
	}
	if err := json.Unmarshal(after, &b); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	aRaw, _ := json.Marshal(a[field])
	bRaw, _ := json.Marshal(b[field])
	if string(aRaw) != string(bRaw) {
		t.Errorf("field %q changed: before=%s after=%s", field, aRaw, bRaw)
	}
}

func containsAll(values []string, wants ...string) bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	for _, want := range wants {
		if !set[want] {
			return false
		}
	}
	return true
}
