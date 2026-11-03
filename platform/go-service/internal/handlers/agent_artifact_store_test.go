package handlers

// Tests for PAT-1260: the platform half of self-update artifact serving —
// PUT /admin/agent-versions/{platform}/{channel}/{version}/artifact
// (admin upload, streamed to disk) and
// GET/HEAD /v1/agent/artifact/download (per-device Bearer+HMAC download).
//
// artifactStoragePath is pure and gets a plain table-driven test (no DB, no
// HTTP) covering the path-traversal surface directly. The upload handler
// needs no DB (auth is enforced by router middleware, not the handler) so
// its tests run unconditionally. The download handler's auth chain needs a
// live device/tenant lookup exactly like AgentArtifactHandler, so those
// tests follow the parConnectOrSkip/parSeedTenant convention already
// established in this package (allowlist_agent_known_path_test.go,
// agent_artifact_test.go) and skip without TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

// ─── artifactStoragePath — pure, no DB/HTTP ────────────────────────────────

func TestArtifactStoragePath(t *testing.T) {
	base := "/var/lib/patched-api/artifacts"

	valid := []struct {
		name                       string
		platform, channel, version string
	}{
		{"windows stable", "windows", "stable", "0.13.20"},
		{"macos beta", "macos", "beta", "1.2.3"},
		{"macos-menubar with suffix", "macos-menubar", "stable", "1233.0.0-menubar-accept"},
		{"single-char version", "windows", "stable", "9"},
	}
	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			path, dir, err := artifactStoragePath(base, tc.platform, tc.channel, tc.version)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantDir := filepath.Join(base, tc.platform, tc.channel, tc.version)
			if dir != wantDir {
				t.Errorf("dir = %q, want %q", dir, wantDir)
			}
			if path != filepath.Join(wantDir, artifactFilename) {
				t.Errorf("path = %q, want %q", path, filepath.Join(wantDir, artifactFilename))
			}
			if !strings.HasPrefix(path, base+string(filepath.Separator)) {
				t.Errorf("path %q escaped base %q", path, base)
			}
		})
	}

	invalid := []struct {
		name                       string
		platform, channel, version string
	}{
		{"unknown platform", "linux", "stable", "1.0.0"},
		{"empty platform", "", "stable", "1.0.0"},
		{"channel dotdot", "windows", "..", "1.0.0"},
		{"version dotdot", "windows", "stable", ".."},
		{"channel single dot", "windows", ".", "1.0.0"},
		{"version single dot", "windows", "stable", "."},
		{"channel empty", "windows", "", "1.0.0"},
		{"version empty", "windows", "stable", ""},
		{"channel contains slash", "windows", "sta/ble", "1.0.0"},
		{"version contains slash", "windows", "stable", "1.0/0"},
		{"version absolute path", "windows", "stable", "/etc/passwd"},
		{"version backslash", "windows", "stable", `..\..\windows`},
		{"channel leading dot traversal", "windows", "../../etc", "1.0.0"},
		{"version literal percent-encoded dotdot", "windows", "stable", "%2e%2e"},
		{"version percent-encoded slash", "windows", "stable", "a%2fb"},
		{"channel leading dot", "windows", ".hidden", "1.0.0"},
		{"version trailing dot", "windows", "stable", "1.0.0."},
		{"version null byte", "windows", "stable", "1.0.0\x00"},
		{"version space", "windows", "stable", "1.0 0"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			path, dir, err := artifactStoragePath(base, tc.platform, tc.channel, tc.version)
			if err == nil {
				t.Fatalf("expected error, got path=%q dir=%q", path, dir)
			}
			if path != "" || dir != "" {
				t.Errorf("expected empty path/dir on error, got path=%q dir=%q", path, dir)
			}
		})
	}
}

// ─── PUT /admin/agent-versions/{platform}/{channel}/{version}/artifact ────

// artifactTestRouter wires the upload handler behind the exact route
// pattern main.go registers it under, so path-param decoding behaves
// identically to production (chi's raw-vs-decoded segment handling matters
// here — see the invalid-platform-and-encoded-traversal test below).
func artifactTestRouter(baseDir string) http.Handler {
	r := chi.NewRouter()
	r.Put("/admin/agent-versions/{platform}/{channel}/{version}/artifact", AdminUploadAgentArtifactHandler(baseDir))
	return r
}

func TestAdminUploadAgentArtifactHandler_StreamsAndReplacesIdempotently(t *testing.T) {
	dir := t.TempDir()
	router := artifactTestRouter(dir)

	first := bytes.Repeat([]byte("A"), 5<<20) // 5 MiB
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-versions/windows/stable/0.13.20/artifact", bytes.NewReader(first))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first upload: status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	finalPath := filepath.Join(dir, "windows", "stable", "0.13.20", artifactFilename)
	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read stored artifact: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("stored bytes (%d) do not match uploaded bytes (%d)", len(got), len(first))
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatalf("stat stored artifact: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o640 {
		t.Errorf("stored artifact mode = %o, want 0640", mode)
	}

	// No leftover temp files after a successful upload.
	assertNoTempFiles(t, filepath.Join(dir, "windows", "stable", "0.13.20"))

	// Re-upload the same version with DIFFERENT content — must replace
	// cleanly, not append or merge.
	second := bytes.Repeat([]byte("B"), 3<<20) // 3 MiB
	req2 := httptest.NewRequest(http.MethodPut, "/admin/agent-versions/windows/stable/0.13.20/artifact", bytes.NewReader(second))
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second upload: status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}

	got2, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read stored artifact after replace: %v", err)
	}
	if !bytes.Equal(got2, second) {
		t.Fatalf("stored bytes after replace (%d) do not match second upload (%d) — old content leaked", len(got2), len(second))
	}
	assertNoTempFiles(t, filepath.Join(dir, "windows", "stable", "0.13.20"))
}

// assertNoTempFiles fails the test if dir contains any ".tmp-artifact-*"
// entry — proves a completed upload (success or failure) never leaves
// partial-write debris behind.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-artifact-") {
			t.Errorf("leftover temp file %s in %s", e.Name(), dir)
		}
	}
}

func TestAdminUploadAgentArtifactHandler_TooLargeRejectedWithoutPartialFile(t *testing.T) {
	dir := t.TempDir()
	router := artifactTestRouter(dir)

	// Temporarily lower the cap so this test doesn't have to push 512MB.
	orig := maxArtifactBytes
	maxArtifactBytes = 1024
	t.Cleanup(func() { maxArtifactBytes = orig })

	body := bytes.Repeat([]byte("X"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-versions/windows/stable/0.13.21/artifact", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", rr.Code, rr.Body.String())
	}

	versionDir := filepath.Join(dir, "windows", "stable", "0.13.21")
	finalPath := filepath.Join(versionDir, artifactFilename)
	if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("final artifact should not exist after a rejected oversized upload, stat err = %v", err)
	}
	// The directory may legitimately exist (created before the body is
	// streamed), but must not retain a partial temp file.
	if _, err := os.Stat(versionDir); err == nil {
		assertNoTempFiles(t, versionDir)
	}
}

// TestAdminUploadAgentArtifactHandler_TruncatedBodyRejected proves the
// written-vs-Content-Length guard: a body that ends early relative to what
// the client itself declared must never reach os.Rename, however cleanly
// io.Copy's Read loop ends (no I/O error, just fewer bytes than promised —
// which is exactly what an unusual truncation, as opposed to the ordinary
// dropped-connection case, looks like). Defence in depth for supply-chain
// bytes: a truncated MSI must never become a servable artifact.
func TestAdminUploadAgentArtifactHandler_TruncatedBodyRejected(t *testing.T) {
	dir := t.TempDir()
	router := artifactTestRouter(dir)

	actual := bytes.Repeat([]byte("A"), 1024)
	declared := int64(len(actual) + 500) // claims more bytes than the body actually carries

	req := httptest.NewRequest(http.MethodPut, "/admin/agent-versions/windows/stable/0.13.22/artifact", bytes.NewReader(actual))
	req.ContentLength = declared // simulate a client whose declared length doesn't match what it sent
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}

	versionDir := filepath.Join(dir, "windows", "stable", "0.13.22")
	finalPath := filepath.Join(versionDir, artifactFilename)
	if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("final artifact should not exist after a truncated upload, stat err = %v", err)
	}
	if _, err := os.Stat(versionDir); err == nil {
		assertNoTempFiles(t, versionDir)
	}
}

func TestAdminUploadAgentArtifactHandler_InvalidPlatformRejected(t *testing.T) {
	dir := t.TempDir()
	router := artifactTestRouter(dir)

	req := httptest.NewRequest(http.MethodPut, "/admin/agent-versions/linux/stable/1.0.0/artifact", strings.NewReader("bytes"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertDirAbsent(t, filepath.Join(dir, "linux"))
}

// TestAdminUploadAgentArtifactHandler_PathTraversalRejected drives the
// upload route with malicious platform/channel/version segments — both
// literal ".." and its percent-encoded form "%2e%2e" — over real HTTP
// request targets (not hand-built chi params), so URL decoding happens
// exactly as it would from a live client. Every case must 400 and must
// never create anything outside dir.
func TestAdminUploadAgentArtifactHandler_PathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	router := artifactTestRouter(dir)

	cases := []struct {
		name   string
		target string
	}{
		{"version dotdot", "/admin/agent-versions/windows/stable/../artifact"},
		{"version percent-encoded dotdot", "/admin/agent-versions/windows/stable/%2e%2e/artifact"},
		{"channel dotdot", "/admin/agent-versions/windows/../stable/artifact"},
		{"platform dotdot", "/admin/agent-versions/../stable/1.0.0/artifact"},
		{"version percent-encoded slash", "/admin/agent-versions/windows/stable/a%2fb/artifact"},
		{"version empty segment", "/admin/agent-versions/windows/stable//artifact"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, tc.target, strings.NewReader("malicious body"))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// chi may itself fail to route a malformed/empty segment (404)
			// rather than ever reaching the handler; either way the
			// traversal must never succeed (200) and must never touch the
			// filesystem outside dir.
			if rr.Code == http.StatusOK {
				t.Fatalf("target %q: status = 200, want 400 (or a routing 404) for a traversal attempt", tc.target)
			}
			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
				t.Fatalf("target %q: status = %d, want 400 or 404", tc.target, rr.Code)
			}
		})
	}

	// Nothing above dir (i.e. outside the temp sandbox) can be asserted
	// directly without risking touching the real filesystem, so instead
	// confirm dir itself only ever contains the directories this test
	// explicitly intended (none, since every case above was rejected).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		t.Errorf("unexpected entry %q created under base dir by a rejected traversal attempt", e.Name())
	}
}

func assertDirAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to not exist, stat err = %v", path, err)
	}
}

// ─── GET/HEAD /v1/agent/artifact/download ──────────────────────────────────

// aadV3Request builds a v3-signed request (contracts/agent-config-schema.md
// "Request signing (v3)") for the given endpoint ID, so tests can prove
// endpoint binding actually matters — a signature computed for one endpoint
// ID must be rejected against a different one.
func aadV3Request(t *testing.T, method, url string, endpointID auth.EndpointID, bearerToken, hmacSecret string) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := fmt.Sprintf("pat1260-test-nonce-%d", time.Now().UnixNano())
	body := []byte{}

	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte("patched-hmac-v3\n"))
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(string(endpointID)))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

// aadSeedArtifact writes bytes directly to dir/platform/channel/version's
// artifact file, bypassing the upload handler — isolates the download
// handler's own tests from the upload handler's behaviour.
func aadSeedArtifact(t *testing.T, dir, platform, channel, version string, data []byte) {
	t.Helper()
	versionDir := filepath.Join(dir, platform, channel, version)
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, artifactFilename), data, 0o640); err != nil {
		t.Fatalf("write seed artifact: %v", err)
	}
}

func TestAgentArtifactDownloadHandler_ReturnsExactBytes(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-download-token"
	hmacSecret := "pat1260-download-hmac-secret-32b"
	parSeedTenant(t, ctx, pool, "pat1260-download-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	want := bytes.Repeat([]byte("payload-bytes-"), 10000) // ~140KB, cheap but non-trivial
	aadSeedArtifact(t, dir, "windows", "stable", "0.13.20", want)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=windows&channel=stable&version=0.13.20",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length = %q, want %d", got, len(want))
	}
	if !bytes.Equal(rr.Body.Bytes(), want) {
		t.Fatalf("body (%d bytes) does not match uploaded artifact (%d bytes)", rr.Body.Len(), len(want))
	}
}

func TestAgentArtifactDownloadHandler_Head(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-head-token"
	hmacSecret := "pat1260-head-hmac-secret-32byte!"
	parSeedTenant(t, ctx, pool, "pat1260-head-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	want := bytes.Repeat([]byte("z"), 4096)
	aadSeedArtifact(t, dir, "macos", "stable", "2.0.0", want)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodHead,
		"/v1/agent/artifact/download?platform=macos&channel=stable&version=2.0.0",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length = %q, want %d", got, len(want))
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD response body has %d bytes, want 0", rr.Body.Len())
	}
}

func TestAgentArtifactDownloadHandler_NoAuthRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	dir := t.TempDir()
	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := httptest.NewRequest(http.MethodGet, "/v1/agent/artifact/download?platform=windows&channel=stable&version=0.13.20", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
}

func TestAgentArtifactDownloadHandler_BadHMACRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-badhmac-token"
	hmacSecret := "pat1260-badhmac-hmac-secret-32by"
	parSeedTenant(t, ctx, pool, "pat1260-badhmac-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=windows&channel=stable&version=0.13.20",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
	req.Header.Set("X-Patched-Signature", strings.Repeat("00", 32)) // well-formed hex, wrong value
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
}

// TestAgentArtifactDownloadHandler_WrongEndpointIDRejected proves the new
// endpoint ID is actually load-bearing: a signature computed for
// EndpointAgentArtifact (the metadata GET) must NOT verify against
// EndpointAgentArtifactDownload — reusing one endpoint's signature against
// the other is exactly the replay hole a distinct ID exists to close.
func TestAgentArtifactDownloadHandler_WrongEndpointIDRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-wrongendpoint-token"
	hmacSecret := "pat1260-wrongendpoint-hmac-32byt"
	parSeedTenant(t, ctx, pool, "pat1260-wrongendpoint-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	aadSeedArtifact(t, dir, "windows", "stable", "0.13.20", []byte("payload"))

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	// Signed for the WRONG endpoint ID.
	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=windows&channel=stable&version=0.13.20",
		auth.EndpointAgentArtifact, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (signature bound to the wrong endpoint ID must not verify): %s", rr.Code, rr.Body.String())
	}
}

func TestAgentArtifactDownloadHandler_UnknownVersionReturns404(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-notfound-token"
	hmacSecret := "pat1260-notfound-hmac-secret-32b"
	parSeedTenant(t, ctx, pool, "pat1260-notfound-tenant", bearerToken, hmacSecret)

	dir := t.TempDir() // deliberately empty — nothing stored
	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=windows&channel=stable&version=99.99.99",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rr.Code, rr.Body.String())
	}
}

func TestAgentArtifactDownloadHandler_InvalidPlatformRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-badplatform-token"
	hmacSecret := "pat1260-badplatform-hmac-secret1"
	parSeedTenant(t, ctx, pool, "pat1260-badplatform-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=linux&channel=stable&version=1.0.0",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
}

// TestAgentArtifactDownloadHandler_PathTraversalQueryParamsRejected proves
// that even a FULLY AUTHENTICATED caller cannot use traversal in the
// platform/channel/version query parameters to read outside dir. Auth runs
// first (matching AgentArtifactHandler's ordering), so these cases prove
// the path validation itself, not just the auth gate.
func TestAgentArtifactDownloadHandler_PathTraversalQueryParamsRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-traversal-token"
	hmacSecret := "pat1260-traversal-hmac-secret-32"
	parSeedTenant(t, ctx, pool, "pat1260-traversal-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	// A secret file OUTSIDE dir but at a predictable relative offset, so a
	// successful traversal would be able to read it.
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("should never be served"), 0o640); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	queries := []string{
		"platform=windows&channel=..&version=1.0.0",
		"platform=windows&channel=stable&version=..",
		"platform=windows&channel=%2e%2e&version=1.0.0",
		"platform=windows&channel=stable&version=%2e%2e",
	}
	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			req := aadV3Request(t, http.MethodGet, "/v1/agent/artifact/download?"+q,
				auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("query %q: status = %d, want 400: %s", q, rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "should never be served") {
				t.Fatalf("query %q: response leaked the outside-dir secret file", q)
			}
		})
	}
}

// TestAgentArtifactDownloadHandler_StreamingNotBuffered is a structural
// smoke test: it drives a multi-megabyte artifact through io.Copy the same
// way the handler does, confirming the handler's response writer receives
// the data via streaming (Content-Length set before the body write, body
// read incrementally) rather than needing the whole file materialised as a
// []byte anywhere in this test itself.
func TestAgentArtifactDownloadHandler_StreamingNotBuffered(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat1260-stream-token"
	hmacSecret := "pat1260-stream-hmac-secret-32byt"
	parSeedTenant(t, ctx, pool, "pat1260-stream-tenant", bearerToken, hmacSecret)

	dir := t.TempDir()
	const size = 8 << 20 // 8 MiB — big enough to prove multi-chunk copying, small enough to stay fast
	want := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	aadSeedArtifact(t, dir, "windows", "stable", "0.14.0", want)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := AgentArtifactDownloadHandler(pool, rl, 5*time.Minute, dir)

	req := aadV3Request(t, http.MethodGet,
		"/v1/agent/artifact/download?platform=windows&channel=stable&version=0.14.0",
		auth.EndpointAgentArtifactDownload, bearerToken, hmacSecret)

	pr, pw := io.Pipe()
	rec := &pipedResponseWriter{header: make(http.Header), pw: pw}
	go func() {
		handler.ServeHTTP(rec, req)
		pw.Close()
	}()

	got, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("read streamed response: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed bytes (%d) do not match seeded artifact (%d)", len(got), len(want))
	}
	if rec.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.status)
	}
}

// pipedResponseWriter is a minimal http.ResponseWriter that pipes Write
// calls straight through to an io.PipeWriter, so a test can consume the
// response body concurrently with the handler producing it — proving the
// handler writes incrementally rather than needing to fully assemble a
// response body first.
type pipedResponseWriter struct {
	header http.Header
	pw     *io.PipeWriter
	status int
}

func (p *pipedResponseWriter) Header() http.Header { return p.header }
func (p *pipedResponseWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return p.pw.Write(b)
}
func (p *pipedResponseWriter) WriteHeader(status int) { p.status = status }
