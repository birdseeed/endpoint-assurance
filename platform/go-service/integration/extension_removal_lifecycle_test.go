//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
)

type removalLifecycleResponse struct {
	ID               int64  `json:"id"`
	State            string `json:"state"`
	TargetsTotal     int    `json:"targets_total"`
	TargetsCompleted int    `json:"targets_completed"`
}

func seedExtensionRemovalDevice(t *testing.T, suffix string) (deviceID, token string, secret []byte) {
	t.Helper()
	ctx := context.Background()
	token = "extension-removal-" + suffix + "-token"
	secret = []byte("extension-removal-" + suffix + "-secret")
	tokenHash := sha256.Sum256([]byte(token))
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version)
		VALUES ($1::uuid, $2, $3, $4, 'macOS', '15.1')
		RETURNING id::text
	`, env.tenantID, "REMOVAL-"+suffix, "00000000-0000-0000-0000-0000000000"+suffix, "removal-"+suffix).Scan(&deviceID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, env.tenantID, deviceID, tokenHash[:], secret); err != nil {
		t.Fatalf("seed device credential: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
		    (device_id, browser, extension_id, name, version, profile, user_account, permissions)
		VALUES ($1::uuid, 'chrome', 'lifecycle-extension', 'Lifecycle Extension', '1.0', 'Default', 'andy', '[]'::jsonb)
	`, deviceID); err != nil {
		t.Fatalf("seed browser extension: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, deviceID)
	})
	return deviceID, token, secret
}

func postRemovalAudit(t *testing.T, token string, secret, body []byte) *http.Response {
	t.Helper()
	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v2\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory/enforcement-audit", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build audit request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post audit request: %v", err)
	}
	return resp
}

func getSignedRemovalDirectives(t *testing.T, token string, secret []byte) []map[string]any {
	t.Helper()
	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v2\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	req, err := http.NewRequest(http.MethodGet, env.publicSrv.URL+"/v1/agent-config", nil)
	if err != nil {
		t.Fatalf("build agent-config request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get agent-config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("get agent-config: want 200, got %d: %s", resp.StatusCode, body)
	}
	var envelope struct {
		Payload string `json:"signed_payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode agent-config envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode agent-config payload: %v", err)
	}
	var config struct {
		AppControl struct {
			ExtensionRemovals []map[string]any `json:"extension_removals"`
		} `json:"app_control"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("decode signed agent-config: %v", err)
	}
	return config.AppControl.ExtensionRemovals
}

func getRemovalJob(t *testing.T, requestID int64) removalLifecycleResponse {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/admin/tenants/%s/extension-removals?include_history=true", env.internalSrv.URL, env.tenantID))
	if err != nil {
		t.Fatalf("get removal jobs: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Requests []removalLifecycleResponse `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode removal jobs: %v", err)
	}
	for _, job := range out.Requests {
		if job.ID == requestID {
			return job
		}
	}
	t.Fatalf("removal job %d not found", requestID)
	return removalLifecycleResponse{}
}

func TestExtensionRemovalCompletesOnlyAfterEveryCapturedTargetReportsEvidence(t *testing.T) {
	ctx := context.Background()
	_, tokenA, secretA := seedExtensionRemovalDevice(t, "01")
	_, tokenB, secretB := seedExtensionRemovalDevice(t, "02")
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET app_control_enabled = TRUE WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("enable extension control: %v", err)
	}
	defaultConfig, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		t.Fatalf("marshal default agent config: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, 1, $2::jsonb, NOW(), 'integration')
		ON CONFLICT (tenant_id) DO NOTHING
	`, env.tenantID, defaultConfig); err != nil {
		t.Fatalf("seed agent config: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET app_control_enabled = FALSE WHERE id = $1::uuid`, env.tenantID)
	})

	createBody := []byte(`{"browser":"chrome","extension_id":"lifecycle-extension","scope":"all_devices","requested_by":"integration"}`)
	resp, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/extension-removals", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create removal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create removal: want 201, got %d: %s", resp.StatusCode, body)
	}
	var created removalLifecycleResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created removal: %v", err)
	}
	if created.State != "queued" || created.TargetsTotal != 2 {
		t.Fatalf("created removal = %+v, want queued with two exact targets", created)
	}
	deviceDirectives := getSignedRemovalDirectives(t, tokenA, secretA)
	if len(deviceDirectives) != 1 || deviceDirectives[0]["scope"] != "one_observation" ||
		deviceDirectives[0]["user_account"] != "andy" || deviceDirectives[0]["profile"] != "Default" {
		t.Fatalf("device directives = %#v, want one exact-profile directive", deviceDirectives)
	}
	if deviceDirectives[0]["approved_before"] == nil {
		t.Fatalf("device directive lacks an observation approval boundary: %#v", deviceDirectives)
	}
	approvedBefore, ok := deviceDirectives[0]["approved_before"].(string)
	if !ok {
		t.Fatalf("device directive approval boundary is not a timestamp: %#v", deviceDirectives)
	}
	if tenantDirectives := getSignedRemovalDirectives(t, env.bearerToken, env.hmacSecretRaw); len(tenantDirectives) != 0 {
		t.Fatalf("tenant-wide credential received destructive directives: %#v", tenantDirectives)
	}

	baseTime := time.Now().UTC()
	dryRun := []byte(fmt.Sprintf(`{"events":[{"event_type":"extension_removed","subject":"lifecycle-extension","details":{"approved_before":%q,"browser":"chrome","profile":"Default","user_account":"andy","scope":"one_observation","dry_run":true},"occurred_at":%q}]}`, approvedBefore, baseTime.Format(time.RFC3339Nano)))
	dryResp := postRemovalAudit(t, tokenA, secretA, dryRun)
	dryResp.Body.Close()
	if dryResp.StatusCode != http.StatusOK {
		t.Fatalf("dry-run audit: want 200, got %d", dryResp.StatusCode)
	}
	if job := getRemovalJob(t, created.ID); job.TargetsCompleted != 0 || job.State != "queued" {
		t.Fatalf("dry-run advanced removal: %+v", job)
	}

	real := func(at time.Time, boundary string) []byte {
		return []byte(fmt.Sprintf(`{"events":[{"event_type":"extension_removed","subject":"lifecycle-extension","details":{"approved_before":%q,"browser":"chrome","profile":"Default","user_account":"andy","scope":"one_observation","dry_run":false},"occurred_at":%q}]}`, boundary, at.UTC().Format(time.RFC3339Nano)))
	}
	staleResp := postRemovalAudit(t, tokenA, secretA, real(baseTime.Add(-time.Hour), approvedBefore))
	staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusOK {
		t.Fatalf("stale evidence: want 200, got %d", staleResp.StatusCode)
	}
	if job := getRemovalJob(t, created.ID); job.TargetsCompleted != 0 || job.State != "queued" {
		t.Fatalf("pre-request evidence advanced removal: %+v", job)
	}

	firstResp := postRemovalAudit(t, tokenA, secretA, real(baseTime.Add(time.Minute), approvedBefore))
	firstResp.Body.Close()
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("first evidence: want 200, got %d", firstResp.StatusCode)
	}
	if job := getRemovalJob(t, created.ID); job.TargetsCompleted != 1 || job.State != "queued" {
		t.Fatalf("partial evidence state = %+v, want queued 1/2", job)
	}

	secondResp := postRemovalAudit(t, tokenB, secretB, real(baseTime.Add(2*time.Minute), approvedBefore))
	secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("second evidence: want 200, got %d", secondResp.StatusCode)
	}
	if job := getRemovalJob(t, created.ID); job.TargetsCompleted != 2 || job.State != "completed" {
		t.Fatalf("completed evidence state = %+v, want completed 2/2", job)
	}

	// Recreate the same extension after the first request completes and prove
	// simultaneous final-target reports cannot strand a fully-complete request.
	resp2, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/extension-removals", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create concurrent removal: %v", err)
	}
	defer resp2.Body.Close()
	var concurrentJob removalLifecycleResponse
	if err := json.NewDecoder(resp2.Body).Decode(&concurrentJob); err != nil {
		t.Fatalf("decode concurrent removal: %v", err)
	}
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create concurrent removal: want 201, got %d", resp2.StatusCode)
	}
	concurrentDirectives := getSignedRemovalDirectives(t, tokenA, secretA)
	concurrentBoundary, ok := concurrentDirectives[0]["approved_before"].(string)
	if !ok {
		t.Fatalf("concurrent directive approval boundary missing: %#v", concurrentDirectives)
	}

	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, sender := range []struct {
		token  string
		secret []byte
	}{
		{tokenA, secretA}, {tokenB, secretB},
	} {
		wg.Add(1)
		go func(token string, secret []byte) {
			defer wg.Done()
			response := postRemovalAudit(t, token, secret, real(time.Now().UTC().Add(time.Minute), concurrentBoundary))
			defer response.Body.Close()
			statuses <- response.StatusCode
		}(sender.token, sender.secret)
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent evidence: want 200, got %d", status)
		}
	}
	if job := getRemovalJob(t, concurrentJob.ID); job.TargetsCompleted != 2 || job.State != "completed" {
		t.Fatalf("concurrent completion state = %+v, want completed 2/2", job)
	}
}

// TestExtensionRemovalOverlappingRequestsBothCompleteFromOneEvent is the
// PAT-1199 regression test for multi-request target stranding.
//
// Two concurrently-active removal requests with overlapping scope — here
// "one_user andy" and "all_devices" — both capture the same
// (device, andy, Default) install as a target: the unique index on
// tenant_extension_removal_requests only dedupes within a single scope, so
// two distinct scopes are free to both queue the same install. Per the
// PAT-829 agent idempotency contract the agent physically removes the
// extension exactly once and reports exactly one extension_removed audit
// event for it — it has no notion of "two requests", so it can only echo
// back ONE of the two directives' approved_before values.
//
// Before this fix, applyExtensionRemovalEvidence matched a single request
// via an exact r.requested_at = approved_before equality, so only the
// request whose requested_at happened to equal the echoed approved_before
// ever completed; the other was left permanently short of `completed` with
// no path forward except manual cancellation, even though the extension was
// genuinely gone from that device for that user. The fix makes a single
// physical removal satisfy every active request whose scope covers it.
func TestExtensionRemovalOverlappingRequestsBothCompleteFromOneEvent(t *testing.T) {
	ctx := context.Background()
	_, token, secret := seedExtensionRemovalDevice(t, "05")
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET app_control_enabled = TRUE WHERE id = $1::uuid`, env.tenantID); err != nil {
		t.Fatalf("enable extension control: %v", err)
	}
	defaultConfig, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		t.Fatalf("marshal default agent config: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, 1, $2::jsonb, NOW(), 'integration')
		ON CONFLICT (tenant_id) DO NOTHING
	`, env.tenantID, defaultConfig); err != nil {
		t.Fatalf("seed agent config: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `UPDATE tenants SET app_control_enabled = FALSE WHERE id = $1::uuid`, env.tenantID)
	})

	createRequest := func(body string) removalLifecycleResponse {
		t.Helper()
		resp, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/extension-removals", "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatalf("create removal: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("create removal: want 201, got %d: %s", resp.StatusCode, b)
		}
		var out removalLifecycleResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode created removal: %v", err)
		}
		return out
	}

	// Two overlapping-scope requests against the same tenant; both cover the
	// single (device, andy, Default) install seeded above.
	oneUser := createRequest(`{"browser":"chrome","extension_id":"lifecycle-extension","scope":"one_user","user_account":"andy","requested_by":"integration"}`)
	if oneUser.State != "queued" || oneUser.TargetsTotal != 1 {
		t.Fatalf("one_user removal = %+v, want queued with exactly one target", oneUser)
	}
	allDevices := createRequest(`{"browser":"chrome","extension_id":"lifecycle-extension","scope":"all_devices","requested_by":"integration"}`)
	if allDevices.State != "queued" || allDevices.TargetsTotal != 1 {
		t.Fatalf("all_devices removal = %+v, want queued with exactly one target", allDevices)
	}

	// The agent sees two directives for the very same install, differing only
	// in approved_before — exactly the stranding setup from the ticket.
	directives := getSignedRemovalDirectives(t, token, secret)
	if len(directives) != 2 {
		t.Fatalf("directives = %#v, want exactly 2 (one per overlapping request)", directives)
	}
	var approvedBefores []string
	for _, d := range directives {
		if d["scope"] != "one_observation" || d["user_account"] != "andy" || d["profile"] != "Default" {
			t.Fatalf("unexpected directive shape: %#v", d)
		}
		ab, ok := d["approved_before"].(string)
		if !ok {
			t.Fatalf("directive missing approval boundary: %#v", d)
		}
		approvedBefores = append(approvedBefores, ab)
	}
	if approvedBefores[0] == approvedBefores[1] {
		t.Fatalf("expected two directives with distinct approval boundaries (one per request), got %v", approvedBefores)
	}

	// The agent performs ONE physical removal and reports ONE evidence event.
	// It picks one of the two approved_before values to echo back — which one
	// must not matter: a single physical removal satisfies every request
	// whose scope covers it.
	occurredAt := time.Now().UTC().Add(time.Minute)
	body := []byte(fmt.Sprintf(`{"events":[{"event_type":"extension_removed","subject":"lifecycle-extension","details":{"approved_before":%q,"browser":"chrome","profile":"Default","user_account":"andy","scope":"one_observation","dry_run":false},"occurred_at":%q}]}`,
		approvedBefores[0], occurredAt.Format(time.RFC3339Nano)))
	resp := postRemovalAudit(t, token, secret, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("extension_removed audit: want 200, got %d", resp.StatusCode)
	}

	oneUserAfter := getRemovalJob(t, oneUser.ID)
	allDevicesAfter := getRemovalJob(t, allDevices.ID)
	if oneUserAfter.TargetsCompleted != 1 || oneUserAfter.State != "completed" {
		t.Errorf("one_user request after single removal event = %+v, want completed 1/1 (PAT-1199: must not be stranded)", oneUserAfter)
	}
	if allDevicesAfter.TargetsCompleted != 1 || allDevicesAfter.State != "completed" {
		t.Errorf("all_devices request after single removal event = %+v, want completed 1/1 (PAT-1199: must not be stranded)", allDevicesAfter)
	}
}
