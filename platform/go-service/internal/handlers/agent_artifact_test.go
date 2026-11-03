package handlers

// Tests for PAT-1233: agent_versions.platform grows a third accepted value,
// "macos-menubar", as its own artifact channel distinct from "macos" (the
// endpoint collector/updater daemon) — the menu-bar apps
// (PatchedUpdater.app / PatchedSelfService.app) are different binaries and
// must never collide with, or overwrite, the endpoint agent's rows.
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, following the
// parConnectOrSkip/parSeedTenant convention already established in this
// package (allowlist_agent_known_path_test.go, agent_health_test.go)
// rather than inventing new scaffolding. agent_versions has no tenant
// scoping of its own (platform/channel/version only), so
// TestAdminRegisterAgentVersionHandler_* seed no tenant; the GET-side test
// needs a tenant purely to obtain a valid bearer+HMAC identity for the
// agent-facing endpoint's auth layer.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/ratelimit"
)

// aavtCleanupVersion registers cleanup of any agent_versions row the test
// creates (directly or via the handler) for the given platform/channel/version.
func aavtCleanupVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, platform, channel, version string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `
			DELETE FROM agent_versions WHERE platform = $1 AND channel = $2 AND version = $3
		`, platform, channel, version)
	})
}

// aavtSignedGET builds a v3-signed GET /v1/agent/artifact request.
func aavtSignedGET(t *testing.T, url, bearerToken, hmacSecret string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", fmt.Sprintf("pat1233-test-nonce-%d", time.Now().UnixNano()))
	req.Header.Set("X-Patched-Signature", agentV3TestSignature([]byte(hmacSecret), req.Method, "agent_artifact", req.Header.Get("X-Patched-Timestamp"), req.Header.Get("X-Patched-Nonce"), nil))
	return req
}

// TestAdminRegisterAgentVersionHandler_MacosMenubarAccepted proves the
// admin registration endpoint accepts the new "macos-menubar" platform
// value end to end (201, row actually persisted).
func TestAdminRegisterAgentVersionHandler_MacosMenubarAccepted(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const platform = "macos-menubar"
	const channel = "beta"
	const version = "1233.0.0-menubar-accept"
	aavtCleanupVersion(t, ctx, pool, platform, channel, version)

	body := fmt.Sprintf(`{
		"platform": %q,
		"channel": %q,
		"version": %q,
		"artifact_url": "https://cdn.patched.im/menubar/1233.0.0/PatchedUpdater.tar.gz",
		"artifact_sha256": "%s",
		"artifact_hmac": "%s"
	}`, platform, channel, version, strings.Repeat("a", 64), strings.Repeat("b", 64))

	req := httptest.NewRequest(http.MethodPost, "/admin/agent-versions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	AdminRegisterAgentVersionHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Platform string `json:"platform"`
		Channel  string `json:"channel"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	if resp.Platform != platform {
		t.Errorf("response platform = %q, want %q", resp.Platform, platform)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM agent_versions WHERE platform = $1 AND channel = $2 AND version = $3
	`, platform, channel, version).Scan(&count); err != nil {
		t.Fatalf("verify row persisted: %v", err)
	}
	if count != 1 {
		t.Errorf("agent_versions row count = %d, want 1 (row should have been persisted)", count)
	}
}

// TestAdminRegisterAgentVersionHandler_InvalidPlatformRejected proves the
// CHECK constraint's widening to three values did not turn the handler's
// validation into an open allowlist — an unrelated platform string must
// still 400 before ever reaching the database.
func TestAdminRegisterAgentVersionHandler_InvalidPlatformRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	body := `{
		"platform": "linux",
		"channel": "stable",
		"version": "1233.0.0-invalid-platform",
		"artifact_url": "https://cdn.patched.im/linux/1233.0.0/agent.tar.gz",
		"artifact_sha256": "` + strings.Repeat("a", 64) + `",
		"artifact_hmac": "` + strings.Repeat("b", 64) + `"
	}`

	req := httptest.NewRequest(http.MethodPost, "/admin/agent-versions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	AdminRegisterAgentVersionHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "macos-menubar") {
		t.Errorf("error body = %q, want it to list macos-menubar among the accepted values", rr.Body.String())
	}
}

// TestAgentArtifactHandler_ResolvesMacosMenubar drives the agent-facing GET
// end to end: a previously-registered macos-menubar/stable row must resolve
// for a platform=macos-menubar query, proving the new platform value is
// wired all the way through validation, the SQL lookup, and the response —
// not just accepted at write time.
func TestAgentArtifactHandler_ResolvesMacosMenubar(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1233-artifact-token"
	hmacSecret := "pat1233-artifact-hmac-secret-32b!"
	parSeedTenant(t, ctx, pool, "pat1233-menubar-tenant", bearerToken, hmacSecret)

	const platform = "macos-menubar"
	const channel = "stable"
	const version = "1233.0.0-resolve"
	aavtCleanupVersion(t, ctx, pool, platform, channel, version)

	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_versions (platform, channel, version, artifact_url, artifact_sha256, artifact_hmac, released_by)
		VALUES ($1, $2, $3, 'https://cdn.patched.im/menubar/1233.0.0/PatchedUpdater.tar.gz', $4, $5, 'ci')
	`, platform, channel, version, strings.Repeat("c", 64), strings.Repeat("d", 64)); err != nil {
		t.Fatalf("seed agent_versions row: %v", err)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactHandler(pool, rl, 5*time.Minute)

	req := aavtSignedGET(t, "/v1/agent/artifact?platform="+platform+"&channel="+channel, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp agentArtifactResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	if resp.Version != version {
		t.Errorf("response version = %q, want %q", resp.Version, version)
	}
}

// TestAgentArtifactHandler_InvalidPlatformRejected proves the GET-side
// validation was updated consistently with the POST side: an unrelated
// platform value must still 400.
func TestAgentArtifactHandler_InvalidPlatformRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1233-invalid-platform-token"
	hmacSecret := "pat1233-invalid-platform-hmac-32b!"
	parSeedTenant(t, ctx, pool, "pat1233-invalid-platform-tenant", bearerToken, hmacSecret)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactHandler(pool, rl, 5*time.Minute)

	req := aavtSignedGET(t, "/v1/agent/artifact?platform=linux&channel=stable", bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "macos-menubar") {
		t.Errorf("error body = %q, want it to list macos-menubar among the accepted values", rr.Body.String())
	}
}
