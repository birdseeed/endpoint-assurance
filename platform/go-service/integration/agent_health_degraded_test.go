//go:build integration

package integration

// PAT-2099: the portal device-detail route exposes a device's currently
// open agent_health.degraded entries (PAT-1064) — kind/subject/reason/
// first_seen/last_seen/count — tenant-scoped. This test exercises the real
// ingest → extractor → portal round trip for the macOS tcc_denied kind
// added under PAT-2096/PAT-2100 (browser_extensions subject here; the same
// shape applies to mcp_servers/ide_extensions/package_managers).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
	"patched.im/api/internal/report"
)

// signedInventoryRequestWithAuth is signedInventoryRequest's parameterized
// twin: env.hmacSecretRaw/env.bearerToken are the shared TestMain tenant's
// credentials, but this test needs two independently-created tenants so it
// can prove agent_health_degraded is tenant-scoped, not just device-scoped.
func signedInventoryRequestWithAuth(t *testing.T, bearerToken string, hmacSecret []byte, body []byte) *http.Request {
	t.Helper()

	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

// agentHealthMacOSPayload builds a minimal valid schema_version=2 macOS
// payload (same shape as testdata/payload-fixtures/valid/minimal.json) with
// an agent_health.degraded block. An empty degraded slice is the explicit
// all-clear (PAT-1064): it deletes every existing device_agent_health row
// for the device, not merely "no new entries".
func agentHealthMacOSPayload(hwUUID, hostname string, collectedAt time.Time, degraded []map[string]any) []byte {
	payload := map[string]any{
		"schema_version": 2,
		"agent":          "patched-collect",
		"agent_version":  "0.2.0",
		"tenant_id":      "00000000-0000-0000-0000-000000000000", // informational only; real tenant comes from bearer auth
		"collected_at":   collectedAt.Format(time.RFC3339),
		"device": map[string]any{
			"serial":    hwUUID[:8],
			"hw_uuid":   hwUUID,
			"hostname":  hostname,
			"hw_model":  "Mac14,2",
			"arch":      "arm64",
			"last_boot": collectedAt.Format(time.RFC3339),
		},
		"hardware": map[string]any{
			"cpu_model":     "Apple M2",
			"cpu_cores":     8,
			"ram_gb":        8,
			"disk_total_gb": 256.0,
			"disk_free_gb":  128.0,
		},
		"os": map[string]any{
			"name":    "macOS",
			"version": "15.0",
			"build":   "24A335",
		},
		"compliance":        map[string]any{},
		"security_tools":    []any{},
		"system_extensions": []any{},
		"background_items":  []any{},
		"icloud":            map[string]any{"signed_in": "Unknown"},
		"apps": []any{
			map[string]any{"name": "Safari", "version": "18.4", "bundle_id": "com.apple.Safari"},
		},
		"agent_health": map[string]any{
			"degraded": degraded,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic("marshal agent health payload: " + err.Error())
	}
	return body
}

func tccDeniedEntry(subject string, firstSeen, lastSeen time.Time, count int) map[string]any {
	return map[string]any{
		"kind":           "tcc_denied",
		"subject":        subject,
		"reason":         "full_disk_access_missing",
		"first_seen":     firstSeen.Format(time.RFC3339),
		"last_seen":      lastSeen.Format(time.RFC3339),
		"count":          count,
		"ever_succeeded": false,
	}
}

type agentHealthDegradedOut struct {
	Kind      string    `json:"kind"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// TestPortalDeviceDetail_AgentHealthDegraded proves the macOS tcc_denied
// vocabulary (PAT-2096/PAT-2100) round-trips POST /v1/inventory → extractor
// → GET /v1/portal/devices/{id}, that a device belonging to a different
// tenant never leaks its rows (both at the route's ownership boundary and
// at the report-layer tenant join independently), and that an explicit
// all-clear payload makes the entry stop appearing — the same clear
// semantics device_agent_health already gives every other reader.
func TestPortalDeviceDetail_AgentHealthDegraded(t *testing.T) {
	ctx := context.Background()

	tenantA, bearerA, hmacA, err := createTestTenant(env.internalSrv.URL, "pat2099-tcc-a")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	cleanupTestTenant(t, tenantA)

	tenantB, bearerB, hmacB, err := createTestTenant(env.internalSrv.URL, "pat2099-tcc-b")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	cleanupTestTenant(t, tenantB)

	emailA := "tcc-a@pat2099-tcc-a.example"
	mapPortalUser(t, emailA, tenantA, http.StatusCreated)
	tokenA := env.idp.token(t, emailA)

	emailB := "tcc-b@pat2099-tcc-b.example"
	mapPortalUser(t, emailB, tenantB, http.StatusCreated)
	tokenB := env.idp.token(t, emailB)

	// Truncated to whole seconds: RFC3339 (what the payload carries and what
	// the JSON response decodes) has no sub-second precision, so comparing
	// against a time.Now() value that still has nanoseconds would spuriously
	// fail even though the wire round trip is correct.
	now := time.Now().UTC().Truncate(time.Second)
	firstSeen := now.Add(-48 * time.Hour)
	lastSeen := now.Add(-time.Hour)

	const hwUUIDA = "AAAAAAAA-1111-2222-3333-444444444444"
	const hwUUIDB = "BBBBBBBB-1111-2222-3333-444444444444"

	// Tenant A's device reports the exact PAT-2096 fault: macOS TCC denied
	// Full Disk Access to the browser-extensions walk.
	bodyA := agentHealthMacOSPayload(hwUUIDA, "pat2099-a-host", now.Add(-time.Minute),
		[]map[string]any{tccDeniedEntry("browser_extensions", firstSeen, lastSeen, 5)})
	respA := postInventory(t, signedInventoryRequestWithAuth(t, bearerA, hmacA, bodyA))
	if respA.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(respA.Body)
		respA.Body.Close()
		t.Fatalf("POST tenant A inventory: want 200, got %d: %s", respA.StatusCode, raw)
	}
	respA.Body.Close()

	// Tenant B's device reports the PAT-2100 sibling fault (mcp_servers) so
	// the two tenants' rows are distinguishable if they ever leaked together.
	bodyB := agentHealthMacOSPayload(hwUUIDB, "pat2099-b-host", now.Add(-time.Minute),
		[]map[string]any{tccDeniedEntry("mcp_servers", firstSeen, lastSeen, 2)})
	respB := postInventory(t, signedInventoryRequestWithAuth(t, bearerB, hmacB, bodyB))
	if respB.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(respB.Body)
		respB.Body.Close()
		t.Fatalf("POST tenant B inventory: want 200, got %d: %s", respB.StatusCode, raw)
	}
	respB.Body.Close()

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	var deviceIDA, deviceIDB string
	if err := env.pool.QueryRow(ctx,
		`SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2::uuid`,
		tenantA, hwUUIDA).Scan(&deviceIDA); err != nil {
		t.Fatalf("resolve tenant A device: %v", err)
	}
	if err := env.pool.QueryRow(ctx,
		`SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND hw_uuid = $2::uuid`,
		tenantB, hwUUIDB).Scan(&deviceIDB); err != nil {
		t.Fatalf("resolve tenant B device: %v", err)
	}

	// 1. The tcc_denied entry appears on the owning tenant's device detail,
	// with the exact fields the contract promises.
	resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceIDA, tokenA, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("portal device detail A = %d: %s", resp.StatusCode, body)
	}
	var detailA struct {
		AgentHealthDegraded []agentHealthDegradedOut `json:"agent_health_degraded"`
	}
	decodeJSON(t, resp, &detailA)
	if len(detailA.AgentHealthDegraded) != 1 {
		t.Fatalf("tenant A agent_health_degraded = %+v, want exactly 1 entry", detailA.AgentHealthDegraded)
	}
	entry := detailA.AgentHealthDegraded[0]
	if entry.Kind != "tcc_denied" || entry.Subject != "browser_extensions" ||
		entry.Reason != "full_disk_access_missing" || entry.Count != 5 {
		t.Fatalf("tenant A entry = %+v, want tcc_denied/browser_extensions/full_disk_access_missing count=5", entry)
	}
	if !entry.FirstSeen.Equal(firstSeen) || !entry.LastSeen.Equal(lastSeen) {
		t.Fatalf("tenant A entry timestamps = %+v, want first_seen=%s last_seen=%s", entry, firstSeen, lastSeen)
	}

	// 2. A device of another tenant doesn't leak it — both at the route's
	// existing ownership boundary (404) and, independently, at the
	// report-layer tenant join that backs the handler.
	resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceIDB, tokenA, nil)
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("tenant A reading tenant B's device = %d, want 404: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	leaked, err := report.FetchPortalDeviceAgentHealth(ctx, env.pool, tenantA, deviceIDB)
	if err != nil {
		t.Fatalf("FetchPortalDeviceAgentHealth cross-tenant: %v", err)
	}
	if len(leaked) != 0 {
		t.Fatalf("tenant A queried directly against tenant B's device leaked %d rows: %+v", len(leaked), leaked)
	}

	// Tenant B, reading its own device, sees only its own entry.
	resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceIDB, tokenB, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("portal device detail B = %d: %s", resp.StatusCode, body)
	}
	var detailB struct {
		AgentHealthDegraded []agentHealthDegradedOut `json:"agent_health_degraded"`
	}
	decodeJSON(t, resp, &detailB)
	if len(detailB.AgentHealthDegraded) != 1 || detailB.AgentHealthDegraded[0].Subject != "mcp_servers" {
		t.Fatalf("tenant B agent_health_degraded = %+v, want exactly 1 mcp_servers entry", detailB.AgentHealthDegraded)
	}

	// 3. Clear semantics: a newer payload reporting degraded: [] is the
	// agent's explicit all-clear and deletes the row (device_agent_health,
	// PAT-1064) — the device detail must stop showing it, with no separate
	// "resolved" state to read.
	clearBody := agentHealthMacOSPayload(hwUUIDA, "pat2099-a-host", now, []map[string]any{})
	clearResp := postInventory(t, signedInventoryRequestWithAuth(t, bearerA, hmacA, clearBody))
	if clearResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(clearResp.Body)
		clearResp.Body.Close()
		t.Fatalf("POST tenant A clear inventory: want 200, got %d: %s", clearResp.StatusCode, raw)
	}
	clearResp.Body.Close()

	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce (clear): %v", err)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+deviceIDA, tokenA, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("portal device detail A (after clear) = %d: %s", resp.StatusCode, body)
	}
	var detailACleared struct {
		AgentHealthDegraded []agentHealthDegradedOut `json:"agent_health_degraded"`
	}
	decodeJSON(t, resp, &detailACleared)
	if len(detailACleared.AgentHealthDegraded) != 0 {
		t.Fatalf("tenant A agent_health_degraded after clear = %+v, want empty", detailACleared.AgentHealthDegraded)
	}
}
