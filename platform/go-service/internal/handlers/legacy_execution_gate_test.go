package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
	"patched.im/api/internal/automations"
	"patched.im/api/internal/ratelimit"
)

const legacyExecutionCompatibilitySuffix = "ForLegacyExecutionCompatibility"

func legacyExecutionCompatibilityCallName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	default:
		return ""
	}
}

func isLegacyExecutionCompatibilityCall(call *ast.CallExpr) bool {
	return strings.HasSuffix(legacyExecutionCompatibilityCallName(call), legacyExecutionCompatibilitySuffix)
}

func isLegacyExecutionProductionGoFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// TestLegacyExecutionCompatibilityConstructorsHaveNoProductionCallers keeps
// the narrowly named positive seams useful for historical tests while making
// a production reintroduction explicit and reviewable. A copied compatibility
// constructor in any non-test Go file fails this gate.
func TestLegacyExecutionCompatibilityConstructorsHaveNoProductionCallers(t *testing.T) {
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	var callers []string
	err = filepath.WalkDir(moduleRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isLegacyExecutionProductionGoFile(path) {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isLegacyExecutionCompatibilityCall(call) {
				callers = append(callers, path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan production callers: %v", err)
	}
	if len(callers) != 0 {
		t.Fatalf("legacy-execution compatibility constructors used by production code: %v", callers)
	}
}

func TestLegacyExecutionCompatibilityCallScannerMatchesOnlyCalls(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", `package handlers

func PendingInstallsHandlerForLegacyExecutionCompatibility() {}

func route() {
		PendingInstallsHandlerForLegacyExecutionCompatibility()
		handlers.PendingRemovalsHandlerForLegacyExecutionCompatibility()
		PendingInstallsHandlerForLegacyExecutionCompatibilityExtra()
}
`, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	var calls []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isLegacyExecutionCompatibilityCall(call) {
			calls = append(calls, legacyExecutionCompatibilityCallName(call))
		}
		return true
	})

	want := []string{
		"PendingInstallsHandlerForLegacyExecutionCompatibility",
		"PendingRemovalsHandlerForLegacyExecutionCompatibility",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("compatibility calls = %v, want %v", calls, want)
	}
}

func TestLegacyExecutionCompatibilityScannerExcludesTestFiles(t *testing.T) {
	for _, path := range []string{
		"/module/internal/handlers/route.go",
		"/module/internal/handlers/route_test.go",
	} {
		got := isLegacyExecutionProductionGoFile(path)
		want := !strings.HasSuffix(path, "_test.go")
		if got != want {
			t.Errorf("isLegacyExecutionProductionGoFile(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestPendingRemovalsAfterAuth_DisabledReturnsEmptyWithoutQueueRead(t *testing.T) {
	called := false
	items, err := pendingRemovalsAfterAuth(context.Background(), "tenant", false,
		func(context.Context, string) ([]pendingRemovalJSON, error) {
			called = true
			return []pendingRemovalJSON{{Name: "must-not-be-read"}}, nil
		})
	if err != nil {
		t.Fatalf("pendingRemovalsAfterAuth: %v", err)
	}
	if called {
		t.Fatal("disabled compatibility called the legacy removal queue")
	}
	if len(items) != 0 {
		t.Fatalf("disabled compatibility items = %#v, want empty", items)
	}
}

// pendingInstallsAfterAuth / catalogueInstallJSON no longer exist —
// PendingInstallsHandler is a permanent no-op since tenant_catalogue was
// dropped (PAT-1561); see TestDisabledPendingExecutionStillRequiresAuthentication
// below, which still covers its auth behaviour end to end.

func TestPendingExecutionAfterAuth_ExplicitEnableCallsLegacyQueue(t *testing.T) {
	t.Run("removals", func(t *testing.T) {
		called := false
		items, err := pendingRemovalsAfterAuth(context.Background(), "tenant", true,
			func(context.Context, string) ([]pendingRemovalJSON, error) {
				called = true
				return []pendingRemovalJSON{{Name: "allowed"}}, nil
			})
		if err != nil || !called || len(items) != 1 {
			t.Fatalf("enabled removals: called=%t items=%#v err=%v", called, items, err)
		}
	})
}

func TestDeviceRemovalTasksAfterAuth_DisabledReturnsEmptyWithoutQueueRead(t *testing.T) {
	called := false
	tasks, err := deviceRemovalTasksAfterAuth(context.Background(), "device", false,
		func(context.Context, string) ([]removalTaskJSON, error) {
			called = true
			return []removalTaskJSON{{AppName: "must-not-be-read"}}, nil
		})
	if err != nil {
		t.Fatalf("deviceRemovalTasksAfterAuth: %v", err)
	}
	if called {
		t.Fatal("disabled compatibility called the device removal queue")
	}
	if len(tasks) != 0 {
		t.Fatalf("disabled compatibility tasks = %#v, want empty", tasks)
	}
}

func TestAgentConfigDisabled_SignsNonExecutingProjectionAndRetainsAssuranceFields(t *testing.T) {
	key := newTestSigningKey()
	pin := "9.9.9"
	stored := agentconfig.DefaultConfigBody()
	stored.Tier = "managed"
	stored.RingPromotions = json.RawMessage(`{"zoom":{"approved_ring":3}}`)
	stored.RingPromotionsScoped = json.RawMessage(`{"macos":{"zoom":{"approval":"up_to_ring","approved_ring":3}}}`)
	stored.PerAppPatch = json.RawMessage(`{"legacy_executor":"enabled"}`)
	stored.OsUpdatePolicy = json.RawMessage(`{"target_os":"14.5","grace_days":7}`)
	stored.UpdateChannel = "beta"
	stored.PinnedVersion = &pin
	storedBefore, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	row := agentConfigRow{
		TenantID:               acTestTenantID,
		ConfigVersion:          7,
		Body:                   stored,
		IssuedAt:               time.Now().UTC(),
		AppControlEnabled:      true,
		AppControlAdmins:       []string{"approved-admin"},
		AppControlAppAllowlist: []string{"com.example.allowed"},
		ExtensionBlocklist: []agentconfig.ExtensionBlocklistEntry{{
			Browser: "chrome", ExtensionID: "blocked-extension",
		}},
		ExtensionRemovals: []agentconfig.ExtensionRemovalEntry{{
			Browser: "chrome", ExtensionID: "remove-extension", Scope: "one_observation",
		}},
		Decommission: agentconfig.DecommissionPolicy{Mode: "immediate", Purge: true},
	}
	get := func(context.Context, string) (agentConfigRow, bool, error) {
		return row, true, nil
	}
	h := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), get, nil, 0, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	var env agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(decodeSignedPayload(t, env, key), &got); err != nil {
		t.Fatal(err)
	}
	storedAfter, err := json.Marshal(row.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedAfter) != string(storedBefore) {
		t.Fatalf("response projection mutated stored tenant policy:\n before=%s\n  after=%s", storedBefore, storedAfter)
	}
	if row.Body.Tier != "managed" {
		t.Fatalf("stored tier = %q, want managed", row.Body.Tier)
	}
	if got["tier"] != "report_deploy" || got["update_channel"] != "beta" || got["pinned_version"] != "9.9.9" || got["os_update_policy"] == nil {
		t.Fatalf("signed response did not use conservative tier while retaining assurance/self-update fields: %#v", got)
	}
	if got["legacy_app_execution_enabled"] != false {
		t.Fatalf("disabled config legacy_app_execution_enabled = %#v, want false", got["legacy_app_execution_enabled"])
	}
	if got["app_control_authority"] != "enforce" {
		t.Fatalf("app_control_authority = %#v, want enforce from durable managed tier", got["app_control_authority"])
	}
	if got["ring_promotions"] != nil {
		t.Fatalf("legacy ring projection = %#v, want null", got["ring_promotions"])
	}
	scoped, ok := got["ring_promotions_scoped"].(map[string]any)
	if !ok || scoped["macos"] != nil || scoped["windows"] != nil || len(scoped) != 2 {
		t.Fatalf("scoped rollout = %#v, want explicit macos:null and windows:null deny-all", got["ring_promotions_scoped"])
	}
	if got["per_app_patch"] != nil {
		t.Fatalf("old-understood per_app_patch = %#v, want null", got["per_app_patch"])
	}
	appControl, ok := got["app_control"].(map[string]any)
	if !ok || appControl["enabled"] != true {
		t.Fatalf("signed app_control = %#v, want retained enabled policy", got["app_control"])
	}
	admins, adminsOK := appControl["approved_admins"].([]any)
	blocklist, blocklistOK := appControl["extension_blocklist"].([]any)
	removals, removalsOK := appControl["extension_removals"].([]any)
	if !adminsOK || len(admins) != 1 || !blocklistOK || len(blocklist) != 1 || !removalsOK || len(removals) != 1 {
		t.Fatalf("signed application-control policy lost retained exact controls: %#v", appControl)
	}
	if _, present := got["mandatory_install_intents"]; present {
		t.Fatalf("mandatory_install_intents = %#v, want omitted while legacy execution is disabled", got["mandatory_install_intents"])
	}
	decommission, ok := got["decommission"].(map[string]any)
	if !ok || decommission["mode"] != "immediate" || decommission["purge"] != true {
		t.Fatalf("decommission directive was not retained: %#v", got["decommission"])
	}
}

func TestAgentConfigDisabled_DurableTierMapsAuthorityBeforeLegacyProjection(t *testing.T) {
	tests := []struct {
		name, durableTier, wantAuthority string
	}{
		{"report tier", "report_deploy", "report"},
		// PAT-1599 (migration 0138): "patch" is retired/unrecognized input to
		// AppControlAuthorityForDurableTier now, not a rung with its own
		// authority — it fails closed to "report", same as any other
		// unrecognized value. Mirrors the equivalent fix in
		// agentconfig/signing_test.go for the same mapping function.
		{"patch tier", "patch", "report"},
		{"managed tier", "managed", "enforce"},
		{"missing tier", "", "report"},
		{"malformed tier", "not-a-tier", "report"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := newTestSigningKey()
			stored := agentconfig.DefaultConfigBody()
			stored.Tier = tc.durableTier
			row := agentConfigRow{TenantID: acTestTenantID, ConfigVersion: 1, Body: stored, IssuedAt: time.Now().UTC()}
			h := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), func(context.Context, string) (agentConfigRow, bool, error) {
				return row, true, nil
			}, nil, 0, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
			}
			var env agentConfigResp
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(decodeSignedPayload(t, env, key), &got); err != nil {
				t.Fatal(err)
			}
			if got["tier"] != "report_deploy" || got["legacy_app_execution_enabled"] != false || got["app_control_authority"] != tc.wantAuthority {
				t.Fatalf("signed containment projection = %#v, want tier=report_deploy legacy_app_execution_enabled=false app_control_authority=%q", got, tc.wantAuthority)
			}
			if row.Body.Tier != tc.durableTier {
				t.Fatalf("response mutated durable tier = %q, want %q", row.Body.Tier, tc.durableTier)
			}
		})
	}
}

// acceptEqualAgentConfig mirrors the deployed updater verifier's compatibility
// rule: after signature verification, a payload at the persisted floor is
// accepted and only a lower config_version is rejected as rollback. Keeping the
// equal case here is essential to the regression: it demonstrates why changing
// signed authority without changing config_version would permit replay.
func acceptEqualAgentConfig(t *testing.T, env agentConfigResp, key *agentconfig.SigningKey, floor int) (map[string]any, int, bool) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed payload: %v", err)
	}
	if err := agentconfig.Verify(key.Public, raw, env.Signature); err != nil {
		t.Fatalf("verify signed payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode verified payload: %v", err)
	}
	version, ok := payload["config_version"].(float64)
	if !ok {
		t.Fatalf("verified payload has no numeric config_version: %#v", payload["config_version"])
	}
	configVersion := int(version)
	return payload, configVersion, configVersion >= floor
}

func TestAgentConfigQuarantineGenerationRejectsPreviouslySignedExecutingEnvelope(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		bearerToken = "pat1481-quarantine-generation-token"
		hmacSecret  = "pat1481-quarantine-generation-hmac"
		oldVersion  = 7
	)
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-quarantine-generation-tenant", bearerToken, hmacSecret)

	executingBody := agentconfig.DefaultConfigBody()
	executingBody.Tier = "patch"
	executingBody.LegacyAppExecutionEnabled = true
	executingBody.RingPromotions = json.RawMessage(`{"zoom":{"approved_ring":3}}`)
	bodyBytes, err := json.Marshal(executingBody)
	if err != nil {
		t.Fatalf("marshal executing body: %v", err)
	}
	var issuedAt time.Time
	if err := pool.QueryRow(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, $2, $3::jsonb, now(), 'pre_quarantine_test')
		RETURNING issued_at
	`, tenantID, oldVersion, bodyBytes).Scan(&issuedAt); err != nil {
		t.Fatalf("insert pre-quarantine agent config: %v", err)
	}

	key := newTestSigningKey()
	oldSignature, oldKeyID, oldCanonical, err := agentconfig.Sign(
		key, executingBody, oldVersion, issuedAt.UTC().Format(time.RFC3339),
		tenantID, "", 3, agentconfig.AppControlPolicy{}, agentconfig.DefaultDecommissionPolicy(),
	)
	if err != nil {
		t.Fatalf("sign pre-quarantine executing envelope: %v", err)
	}
	oldEnvelope := agentConfigResp{
		SignedPayload: base64.StdEncoding.EncodeToString(oldCanonical),
		KeyID:         oldKeyID,
		Signature:     oldSignature,
	}

	oldPayload, floor, accepted := acceptEqualAgentConfig(t, oldEnvelope, key, 0)
	if !accepted || oldPayload["tier"] != "patch" || oldPayload["legacy_app_execution_enabled"] != true {
		t.Fatalf("precondition: preceding envelope was not accepted executing authority: accepted=%t payload=%#v", accepted, oldPayload)
	}
	if _, _, equalAccepted := acceptEqualAgentConfig(t, oldEnvelope, key, floor); !equalAccepted {
		t.Fatal("precondition: verifier simulation no longer accepts an equal-version replay")
	}

	handler := AgentConfigHandler(pool, key, nil, time.Minute)
	containedRR := httptest.NewRecorder()
	handler.ServeHTTP(containedRR, aadV3Request(t, http.MethodGet, "/v1/agent-config", auth.EndpointAgentConfig, bearerToken, hmacSecret))
	if containedRR.Code != http.StatusOK {
		t.Fatalf("contained GET status = %d: %s", containedRR.Code, containedRR.Body.String())
	}
	var containedEnvelope agentConfigResp
	if err := json.Unmarshal(containedRR.Body.Bytes(), &containedEnvelope); err != nil {
		t.Fatalf("decode contained envelope: %v", err)
	}
	containedPayload, containedVersion, accepted := acceptEqualAgentConfig(t, containedEnvelope, key, floor)
	if !accepted || containedVersion <= oldVersion {
		t.Fatalf("contained generation must advance beyond preceding executable envelope: old=%d contained=%d accepted=%t", oldVersion, containedVersion, accepted)
	}
	if containedPayload["tier"] != "report_deploy" || containedPayload["legacy_app_execution_enabled"] != false {
		t.Fatalf("new generation did not contain legacy execution: %#v", containedPayload)
	}

	var storedVersion, quarantineVersion int
	if err := pool.QueryRow(ctx, `
		SELECT config_version, legacy_execution_quarantine_version
		FROM agent_config
		WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&storedVersion, &quarantineVersion); err != nil {
		t.Fatalf("read durable quarantine generation: %v", err)
	}
	if storedVersion != containedVersion || quarantineVersion != containedVersion {
		t.Fatalf("durable generation mismatch: stored=%d marker=%d contained=%d", storedVersion, quarantineVersion, containedVersion)
	}

	repeatRR := httptest.NewRecorder()
	handler.ServeHTTP(repeatRR, aadV3Request(t, http.MethodGet, "/v1/agent-config", auth.EndpointAgentConfig, bearerToken, hmacSecret))
	if repeatRR.Code != http.StatusOK {
		t.Fatalf("repeat contained GET status = %d: %s", repeatRR.Code, repeatRR.Body.String())
	}
	var repeatEnvelope agentConfigResp
	if err := json.Unmarshal(repeatRR.Body.Bytes(), &repeatEnvelope); err != nil {
		t.Fatalf("decode repeated contained envelope: %v", err)
	}
	_, repeatVersion, repeatAccepted := acceptEqualAgentConfig(t, repeatEnvelope, key, containedVersion)
	if !repeatAccepted || repeatVersion != containedVersion {
		t.Fatalf("ordinary GET advanced or rolled back quarantine generation: first=%d repeat=%d accepted=%t", containedVersion, repeatVersion, repeatAccepted)
	}

	if _, replayVersion, replayAccepted := acceptEqualAgentConfig(t, oldEnvelope, key, containedVersion); replayAccepted || replayVersion != oldVersion {
		t.Fatalf("preceding signed executing envelope replay accepted after quarantine: floor=%d replay=%d accepted=%t", containedVersion, replayVersion, replayAccepted)
	}

	// Simulate an automatic rollback to the old execution-capable binary. It
	// reads the durable patch tier and can sign it at the quarantine marker
	// generation, which the deployed verifier accepts as equal to its floor.
	rollbackRow, found, err := dbGetAgentConfig(ctx, pool, tenantID)
	if err != nil || !found {
		t.Fatalf("read row for automatic binary rollback: found=%t err=%v", found, err)
	}
	rollbackSignature, rollbackKeyID, rollbackCanonical, err := agentconfig.Sign(
		key, rollbackRow.Body, rollbackRow.ConfigVersion,
		rollbackRow.IssuedAt.UTC().Format(time.RFC3339), tenantID, "", 3,
		agentconfig.AppControlPolicy{}, agentconfig.DefaultDecommissionPolicy(),
	)
	if err != nil {
		t.Fatalf("sign rollback executable envelope: %v", err)
	}
	rollbackEnvelope := agentConfigResp{
		SignedPayload: base64.StdEncoding.EncodeToString(rollbackCanonical),
		KeyID:         rollbackKeyID,
		Signature:     rollbackSignature,
	}
	rollbackPayload, rollbackVersion, rollbackAccepted := acceptEqualAgentConfig(t, rollbackEnvelope, key, containedVersion)
	if !rollbackAccepted || rollbackVersion != containedVersion || rollbackPayload["tier"] != "patch" {
		t.Fatalf("precondition: rolled-back binary did not regain equal-version executable authority: accepted=%t version=%d payload=%#v", rollbackAccepted, rollbackVersion, rollbackPayload)
	}

	// A redeployed contained process carries a new activation nonce. Its first
	// GET transaction must advance past the executable envelope above; repeats
	// from that same process then reuse the durable generation.
	redeployActivation := strings.Repeat("b", 64)
	redeployedRow, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, redeployActivation)
	if err != nil || !found {
		t.Fatalf("reactivate contained process after rollback: found=%t err=%v", found, err)
	}
	if redeployedRow.ConfigVersion <= rollbackVersion {
		t.Fatalf("redeployed containment did not advance beyond rollback envelope: rollback=%d redeployed=%d", rollbackVersion, redeployedRow.ConfigVersion)
	}
	redeployedSignature, redeployedKeyID, redeployedCanonical, err := agentconfig.Sign(
		key, conservativeLegacyAgentProjection(redeployedRow.Body), redeployedRow.ConfigVersion,
		redeployedRow.IssuedAt.UTC().Format(time.RFC3339), tenantID, "", 3,
		agentconfig.AppControlPolicy{}, agentconfig.DefaultDecommissionPolicy(),
	)
	if err != nil {
		t.Fatalf("sign redeployed contained envelope: %v", err)
	}
	redeployedEnvelope := agentConfigResp{
		SignedPayload: base64.StdEncoding.EncodeToString(redeployedCanonical),
		KeyID:         redeployedKeyID,
		Signature:     redeployedSignature,
	}
	redeployedPayload, redeployedVersion, redeployedAccepted := acceptEqualAgentConfig(t, redeployedEnvelope, key, containedVersion)
	if !redeployedAccepted || redeployedVersion <= rollbackVersion || redeployedPayload["tier"] != "report_deploy" || redeployedPayload["legacy_app_execution_enabled"] != false {
		t.Fatalf("redeployed contained envelope is not a newer denial: accepted=%t rollback=%d redeployed=%d payload=%#v", redeployedAccepted, rollbackVersion, redeployedVersion, redeployedPayload)
	}
	repeatedRedeploy, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, redeployActivation)
	if err != nil || !found || repeatedRedeploy.ConfigVersion != redeployedVersion {
		t.Fatalf("repeated redeployed-process GET advanced generation: found=%t first=%d repeat=%d err=%v", found, redeployedVersion, repeatedRedeploy.ConfigVersion, err)
	}
}

func TestAgentConfigQuarantineGenerationMaterializesAboveSyntheticDefault(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-quarantine-synthetic-tenant", "pat1481-quarantine-synthetic-token", "pat1481-quarantine-synthetic-hmac")

	activationID := strings.Repeat("a", 64)
	row, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationID)
	if err != nil {
		t.Fatalf("first contained read: %v", err)
	}
	if !found || row.ConfigVersion != syntheticDefaultConfigVersion+1 {
		t.Fatalf("tenant without agent_config row materialized at found=%t version=%d, want version %d", found, row.ConfigVersion, syntheticDefaultConfigVersion+1)
	}
	var marker int
	if err := pool.QueryRow(ctx, `SELECT legacy_execution_quarantine_version FROM agent_config WHERE tenant_id=$1::uuid`, tenantID).Scan(&marker); err != nil {
		t.Fatalf("read materialized quarantine marker: %v", err)
	}
	if marker != row.ConfigVersion {
		t.Fatalf("materialized marker=%d, want config_version=%d", marker, row.ConfigVersion)
	}

	repeated, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationID)
	if err != nil || !found || repeated.ConfigVersion != row.ConfigVersion {
		t.Fatalf("repeated contained read advanced generation: found=%t first=%d repeat=%d err=%v", found, row.ConfigVersion, repeated.ConfigVersion, err)
	}
}

func TestAgentConfigQuarantineGenerationRejectsInvalidActivation(t *testing.T) {
	if _, _, err := dbGetQuarantinedAgentConfig(context.Background(), nil, acTestTenantID, strings.Repeat("z", 64)); err == nil {
		t.Fatal("non-hex process activation was accepted")
	}
}

func TestAgentConfigQuarantineGenerationConcurrentActivationIsOncePerProcess(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool,
		"pat1481-quarantine-concurrency-tenant", "pat1481-quarantine-concurrency-token", "pat1481-quarantine-concurrency-hmac")

	const callers = 8
	activationA := strings.Repeat("c", 64)
	versions := make(chan int, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			row, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationA)
			if err == nil && !found {
				err = errors.New("agent config not found")
			}
			if err != nil {
				errs <- err
				return
			}
			versions <- row.ConfigVersion
		}()
	}
	wg.Wait()
	close(errs)
	close(versions)
	for err := range errs {
		t.Errorf("concurrent same-process activation: %v", err)
	}
	for version := range versions {
		if version != syntheticDefaultConfigVersion+1 {
			t.Errorf("same process advanced more than once: got version %d, want %d", version, syntheticDefaultConfigVersion+1)
		}
	}

	// A second process advances once. Returning to process A after process B
	// must reuse the current generation rather than alternate increments.
	activationB := strings.Repeat("d", 64)
	second, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationB)
	if err != nil || !found || second.ConfigVersion != syntheticDefaultConfigVersion+2 {
		t.Fatalf("second contained process activation: found=%t version=%d err=%v", found, second.ConfigVersion, err)
	}
	againA, found, err := dbGetQuarantinedAgentConfig(ctx, pool, tenantID, activationA)
	if err != nil || !found || againA.ConfigVersion != second.ConfigVersion {
		t.Fatalf("alternating process A request advanced generation: found=%t second=%d againA=%d err=%v", found, second.ConfigVersion, againA.ConfigVersion, err)
	}

	var activationCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM agent_config_legacy_execution_activations
		WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&activationCount); err != nil {
		t.Fatalf("count durable quarantine activations: %v", err)
	}
	if activationCount != 2 {
		t.Fatalf("durable activation count = %d, want 2", activationCount)
	}
}

func TestAgentConfigCompatibilitySeamCannotEnableProductionAuthority(t *testing.T) {
	key := newTestSigningKey()
	get := func(ctx context.Context, _ string) (agentConfigRow, bool, error) {
		r := agentConfigRow{TenantID: acTestTenantID, ConfigVersion: 1, Body: agentconfig.DefaultConfigBody()}
		r.Body.Tier = "patch"
		r.Body.RingPromotionsScoped = json.RawMessage(`{"macos":{"zoom":{"approval":"up_to_ring","approved_ring":3}}}`)
		return r, true, nil
	}
	h := newAgentConfigHandler(key, acAuthAlways(acTestTenantID), get, nil, 0, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil))
	var env agentConfigResp
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(decodeSignedPayload(t, env, key), &got); err != nil {
		t.Fatal(err)
	}
	if got["tier"] != "report_deploy" {
		t.Fatalf("tier = %#v, want report_deploy", got["tier"])
	}
	if got["legacy_app_execution_enabled"] != false {
		t.Fatalf("legacy_app_execution_enabled = %#v, want false", got["legacy_app_execution_enabled"])
	}
	if got["ring_promotions"] != nil {
		t.Fatalf("ring_promotions = %#v, want null", got["ring_promotions"])
	}
}

// TestAdminAgentConfigPutRejectsRetiredPatchTier pins the PAT-1599 (migration
// 0138) cutover: the ticket's ruling is a clean, deliberate break of the old
// three-rung wire vocabulary ("no backward-compatibility requirement...for
// old wire-format tier values" — there are no customers/estate to preserve
// compat for), not a dual-accept migration. This test used to be named
// TestAdminAgentConfigPutAllowsPatchTierAssuranceUpdate and asserted that a
// PUT with tier "patch" was accepted; that premise is now false, so this
// flips from a positive to a negative test: "patch" must be rejected with
// 400, same as any other retired or unrecognized tier value.
func TestAdminAgentConfigPutRejectsRetiredPatchTier(t *testing.T) {
	key := newTestSigningKey()
	var stored agentconfig.ConfigBody
	h := newAdminAgentConfigPutHandler(key,
		func(context.Context, string) (bool, error) { return true, nil },
		acGetEmpty(),
		func(_ context.Context, tenantID, _ string, body agentconfig.ConfigBody) (agentConfigRow, error) {
			stored = body
			return agentConfigRow{TenantID: tenantID, ConfigVersion: 2, Body: body, IssuedAt: time.Now().UTC()}, nil
		},
	)
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-config/"+acTestTenantID, strings.NewReader(`{
		"tier":"patch",
		"proxy":{"mode":"system"},
		"update_channel":"beta",
		"os_update_policy":{"enabled":true,"grace_days":7,"deferral_budget":1,"defer_interval_hours":24,"blocking_window_days":2}
	}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, acWithTenantID(req, acTestTenantID))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	wantErr := `tier must be "assurance" or "managed", got "patch"`
	if body := rr.Body.String(); !strings.Contains(body, wantErr) {
		t.Fatalf("body = %q, want to contain %q", body, wantErr)
	}
	if stored.Tier != "" {
		t.Fatalf("handler must reject before persisting; stored = %#v", stored)
	}
}

func TestAutomationHistoryLifecycleKeepsQuarantinedReportersCompatible(t *testing.T) {
	// The GET handler accepts a retired identity and proceeds to its history
	// query. The record handler rejects before any database work, proving the
	// read-only lifecycle split rather than treating retirement as unknown.
	if !automations.IsKnownJob("installomator_sync") {
		t.Fatal("retired automation identity is not readable")
	}

	record := AutomationRecordHandler(nil)
	recordReq := httptest.NewRequest(http.MethodPost, "/admin/automations/installomator_sync/record", strings.NewReader(`{}`))
	recordReq = recordReq.WithContext(context.WithValue(recordReq.Context(), chi.RouteCtxKey, &chi.Context{URLParams: chi.RouteParams{Keys: []string{"jobName"}, Values: []string{"installomator_sync"}}}))
	rr := httptest.NewRecorder()
	record.ServeHTTP(rr, recordReq)
	if rr.Code != http.StatusConflict {
		t.Fatalf("retired automation record status = %d, want 409", rr.Code)
	}

	// The updater's two manual mirror workflows still contain best-effort
	// reporters. Invalid JSON must therefore reach request validation instead of
	// being rejected as retired before those external steps are removed.
	for _, jobName := range []string{"mirror_pipeline", "mirror_pipeline_windows"} {
		recordReq := httptest.NewRequest(http.MethodPost, "/admin/automations/"+jobName+"/record", strings.NewReader(`{`))
		recordReq = recordReq.WithContext(context.WithValue(recordReq.Context(), chi.RouteCtxKey, &chi.Context{URLParams: chi.RouteParams{Keys: []string{"jobName"}, Values: []string{jobName}}}))
		rr := httptest.NewRecorder()
		record.ServeHTTP(rr, recordReq)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("quarantined automation %q record status = %d, want request validation status 400", jobName, rr.Code)
		}
	}
}

func TestPostureDisabled_SignsNeutralExecutionFields(t *testing.T) {
	fetch := func(context.Context, string, string) (postureResp, error) {
		return postureResp{
			Tier: "managed", Updates: []postureUpdate{{AppName: "Zoom", Identifier: "us.zoom.xos", Label: "zoom", TargetVersion: "6.0", CurrentVersion: "5.0", Source: "catalog", LinkedCVEIDs: []string{"CVE-2026-0001"}}},
			AppPolicy: postureAppPolicy{Apps: []postureAppPolicyEntry{{Label: "zoom", UserRemovable: true, EnforcementTier: "managed"}}, Drift: []postureAppDrift{{EnforcementTier: "managed"}}},
		}, nil
	}
	h := newPostureHandlerWithLegacyExecutionCompatibility(pAuthOK(), fetch, newTestSigningKey(), nil, 0, nil, false)
	rr := postureGet(t, h, "Bearer test")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	var got postureResp
	if err := json.Unmarshal(decodePostureInner(t, rr), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tier != "report_deploy" || got.Updates[0].Label != "" || got.Updates[0].AppName != "Zoom" || got.Updates[0].Identifier != "us.zoom.xos" || got.Updates[0].CurrentVersion != "5.0" || got.Updates[0].TargetVersion != "6.0" || got.Updates[0].Source != "catalog" || len(got.Updates[0].LinkedCVEIDs) != 1 || got.Updates[0].LinkedCVEIDs[0] != "CVE-2026-0001" || got.AppPolicy.Apps[0].Label != "" || got.AppPolicy.Apps[0].UserRemovable || got.AppPolicy.Apps[0].EnforcementTier != "report_deploy" || got.AppPolicy.Drift[0].EnforcementTier != "report_deploy" {
		t.Fatalf("disabled posture retained execution authority: %#v", got)
	}
}

func TestPostureExplicitCompatibilityRetainsLegacyExecutionFields(t *testing.T) {
	fetch := func(context.Context, string, string) (postureResp, error) {
		return postureResp{Tier: "managed", Updates: []postureUpdate{{Label: "zoom", TargetVersion: "6.0"}}, AppPolicy: postureAppPolicy{Apps: []postureAppPolicyEntry{{Label: "zoom", UserRemovable: true, EnforcementTier: "managed"}}}}, nil
	}
	h := newPostureHandlerWithLegacyExecutionCompatibility(pAuthOK(), fetch, newTestSigningKey(), nil, 0, nil, true)
	rr := postureGet(t, h, "Bearer test")
	var got postureResp
	if err := json.Unmarshal(decodePostureInner(t, rr), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tier != "managed" || got.Updates[0].Label != "zoom" || got.Updates[0].TargetVersion != "6.0" || !got.AppPolicy.Apps[0].UserRemovable {
		t.Fatalf("explicit compatibility unexpectedly changed posture: %#v", got)
	}
}

func TestLegacyExecutionWritesFailBeforeDatabaseWork(t *testing.T) {
	for _, tc := range []struct {
		name       string
		handler    http.Handler
		path, body string
	}{
		{"allowlist add", TenantAllowlistAddHandler(nil, nil), "/admin/tenants/" + acTestTenantID + "/allowlist", `{"name":"x","enforcement":"marked_for_uninstall"}`},
		{"allowlist update", TenantAllowlistUpdateHandler(nil, nil), "/admin/tenants/" + acTestTenantID + "/allowlist/1", `{"enforcement":"marked_for_uninstall"}`},
		{"ring config", RingConfigPutHandler(nil), "/admin/tenants/" + acTestTenantID + "/ring-config", `{"enabled":true,"ring_count":2,"percentages":[50,50],"soak_gap_hours":1,"failure_threshold_pct":1,"min_failures_to_pause":1,"min_estate_size":1}`},
		{"ring override", RingDeviceOverridePutHandler(nil), "/admin/tenants/" + acTestTenantID + "/ring-devices/" + pTestDeviceID, `{"ring":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, tc.path, strings.NewReader(tc.body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("tenantID", acTestTenantID)
			if strings.Contains(tc.path, "/allowlist/1") {
				rctx.URLParams.Add("entryID", "1")
			}
			if strings.Contains(tc.path, "/ring-devices/") {
				rctx.URLParams.Add("deviceID", pTestDeviceID)
			}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			tc.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rr.Code)
			}
		})
	}
}

func TestDisabledPendingExecutionStillRequiresAuthentication(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{RPM: 10, Burst: 10})
	for _, tc := range []struct {
		name    string
		handler http.Handler
	}{
		{
			name:    "removals",
			handler: PendingRemovalsHandler(nil, rl, time.Minute),
		},
		{
			name:    "installs",
			handler: PendingInstallsHandler(nil, rl, time.Minute),
		},
		{
			name:    "device removal tasks",
			handler: DeviceRemovalTasksPendingHandler(nil, rl, time.Minute),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated disabled %s status = %d, want %d", tc.name, rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestLegacyExecutionMutations_DisabledFailBeforeNilDatabaseAccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.Handler
		path    string
	}{
		{
			name:    "device removal create",
			handler: DeviceRemovalsCreateHandler(nil),
			path:    "/admin/devices/11111111-1111-4111-8111-111111111111/removals",
		},
		{
			name:    "rollout resume",
			handler: RingRolloutResumeHandler(nil),
			path:    "/admin/tenants/11111111-1111-4111-8111-111111111111/ring-rollouts/22222222-2222-4222-8222-222222222222/resume",
		},
		{
			name:    "rollout skip",
			handler: RingRolloutSkipHandler(nil),
			path:    "/admin/tenants/11111111-1111-4111-8111-111111111111/ring-rollouts/22222222-2222-4222-8222-222222222222/skip",
		},
		{
			name:    "rollout emergency",
			handler: RingRolloutEmergencyHandler(nil),
			path:    "/admin/tenants/11111111-1111-4111-8111-111111111111/ring-rollouts/22222222-2222-4222-8222-222222222222/emergency",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, tc.path, nil))
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("disabled %s status = %d, want %d", tc.name, rr.Code, http.StatusServiceUnavailable)
			}
		})
	}
}
