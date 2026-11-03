//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInternalAgentReleaseRoutes(t *testing.T) {
	ctx := context.Background()
	tenant := newApprovalTenant(t, "release-http", false)
	device := seedSelfServiceDevice(t, tenant.tenantID, "probe", "release-"+randomHex(6), "macOS", time.Now())
	version := "2004." + randomHex(6)
	request := map[string]any{"platform": "macos-menubar", "channel": "beta", "version": version, "artifact_url": "https://cdn.patched.im/beta/" + version, "artifact_sha256": strings.Repeat("a", 64), "artifact_hmac": strings.Repeat("b", 64)}
	post := func(path string, body any) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(env.internalSrv.URL+path, "application/json", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var response json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, response
	}
	if code, body := post("/admin/agent-versions", request); code != 201 {
		t.Fatalf("register %d %s", code, body)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(ctx, `DELETE FROM agent_versions WHERE platform='macos-menubar' AND version=$1`, version)
	})
	now := time.Now().UTC()
	if code, body := post("/admin/agent-releases/observations", map[string]any{"device_id": device, "platform": "macos-menubar", "version": version, "observed_at": now, "health_complete": true, "fault_keys": []any{}, "provenance": "http-menu-probe"}); code != 200 {
		t.Fatalf("observation %d %s", code, body)
	}
	if code, body := post("/admin/agent-releases/evidence", map[string]any{"platform": "macos-menubar", "version": version, "metric": "enrolment", "window_start": now.Add(-time.Hour), "window_end": now, "attempts": 100, "failures": 0, "provenance": "http-monitor"}); code != 200 {
		t.Fatalf("evidence %d %s", code, body)
	}
	request["channel"] = "stable"
	request["artifact_url"] = "https://cdn.patched.im/stable/" + version
	payload, err := json.Marshal(map[string]any{"version": version, "platform": request["platform"], "channel": "stable", "artifact_url": request["artifact_url"], "artifact_sha256": request["artifact_sha256"]})
	if err != nil {
		t.Fatal(err)
	}
	request["artifact_metadata_signature"] = map[string]any{"signed_payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(make([]byte, 64)), "key_id": "aabbccddeeff0011"}
	if code, body := post("/admin/agent-releases/promote", request); code != 409 {
		t.Fatalf("gate refusal %d %s", code, body)
	}
	var count int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM agent_release_observations WHERE device_id=$1::uuid AND source='internal_probe'`, device).Scan(&count); err != nil || count != 1 {
		t.Fatal("probe provenance", count, err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM agent_versions WHERE platform='macos-menubar' AND channel='stable' AND version=$1`, version).Scan(&count); err != nil || count != 0 {
		t.Fatal("ungated stable publication", count, err)
	}
}

func TestPortalAgentReleaseControls(t *testing.T) {
	ctx := context.Background()
	a := newApprovalTenant(t, "release-a", false)
	b := newApprovalTenant(t, "release-b", false)
	da := seedSelfServiceDevice(t, a.tenantID, "canary", "release-"+randomHex(6), "macOS", time.Now())
	db := seedSelfServiceDevice(t, b.tenantID, "foreign", "release-"+randomHex(6), "Windows", time.Now())
	call := func(token, body string) (int, []byte) {
		return portalCall(t, http.MethodPut, "/v1/portal/agent-releases", token, body)
	}
	request := fmt.Sprintf(`{"action":"device_channels","device_ids":[%q],"channel":"beta"}`, da)
	if code, body := call(a.viewerToken, request); code != 403 {
		t.Fatalf("viewer %d %s", code, body)
	}
	if code, body := call(a.adminToken, fmt.Sprintf(`{"action":"device_channels","device_ids":[%q,%q],"channel":"beta"}`, da, db)); code != 404 {
		t.Fatalf("foreign %d %s", code, body)
	}
	var count int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM agent_device_channels WHERE device_id=$1::uuid`, da).Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign bulk partially wrote", count, err)
	}
	if code, body := call(a.adminToken, request); code != 200 {
		t.Fatalf("admin %d %s", code, body)
	}
	observedAt := time.Now().UTC().Add(-time.Minute)
	if _, err := env.pool.Exec(ctx, `INSERT INTO agent_update_channel_observations(tenant_id,device_id,channel,source,config_version,observed_at,raw_payload_id) VALUES ($1::uuid,$2::uuid,'beta','device_override',7,$3,987654321)`, a.tenantID, da, observedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO agent_update_channel_observations(tenant_id,device_id,channel,source,config_version,observed_at,raw_payload_id) VALUES ($1::uuid,$2::uuid,'stable','tenant',8,$3,987654322)`, b.tenantID, db, observedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO agent_update_channel_observations(tenant_id,device_id,channel,source,config_version,observed_at,raw_payload_id) VALUES ($1::uuid,$2::uuid,'stable','tenant',8,$3,987654323)`, a.tenantID, db, observedAt); err == nil {
		t.Fatal("cross-tenant device observation accepted")
	}
	if code, body := call(a.adminToken, fmt.Sprintf(`{"action":"device_channels","device_ids":[%q],"channel":"stable"}`, da)); code != 400 {
		t.Fatalf("stable override accepted %d %s", code, body)
	}
	if code, body := call(a.adminToken, `{"action":"hold","tenant_id":"`+b.tenantID+`"}`); code != 400 {
		t.Fatalf("accepted tenant field %d %s", code, body)
	}
	code, body := portalCall(t, http.MethodGet, "/v1/portal/agent-releases", a.viewerToken, "")
	if code != 200 || !strings.Contains(string(body), da) || strings.Contains(string(body), db) {
		t.Fatalf("tenant read %d %s", code, body)
	}
	var got struct {
		Devices []struct {
			EffectiveChannel         string `json:"effective_channel"`
			UpdateChannelObservation *struct {
				Channel       string `json:"channel"`
				Source        string `json:"source"`
				ConfigVersion int    `json:"config_version"`
			} `json:"update_channel_observation"`
		}
	}
	mustJSON(t, body, &got)
	if len(got.Devices) != 1 || got.Devices[0].EffectiveChannel != "beta" {
		t.Fatalf("override projection %s", body)
	}
	if got.Devices[0].UpdateChannelObservation == nil || got.Devices[0].UpdateChannelObservation.Channel != "beta" || got.Devices[0].UpdateChannelObservation.Source != "device_override" || got.Devices[0].UpdateChannelObservation.ConfigVersion != 7 {
		t.Fatalf("channel observation missing or mis-scoped: %s", body)
	}
	version := "2004." + randomHex(6)
	for _, platform := range []string{"macos", "windows"} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,published_at) VALUES ($1,'stable',$2,'https://cdn.patched.im/test','test-sha','test-hmac',clock_timestamp()+interval '1 second')`, platform, version); err != nil {
			t.Fatal(err)
		}
		p := platform
		t.Cleanup(func() {
			_, _ = env.pool.Exec(context.Background(), `DELETE FROM agent_versions WHERE platform=$1 AND version=$2`, p, version)
		})
	}
	if code, body := call(a.adminToken, `{"action":"hold"}`); code != 200 {
		t.Fatalf("hold %d %s", code, body)
	}
	code, body = portalCall(t, http.MethodGet, "/v1/portal/agent-releases", a.viewerToken, "")
	if code != 200 || !strings.Contains(string(body), `"hold":true`) || !strings.Contains(string(body), `"pinned_version":"`+version+`"`) {
		t.Fatalf("hold state %d %s", code, body)
	}
	if code, body := call(a.adminToken, `{"action":"approve"}`); code != 200 {
		t.Fatalf("approve %d %s", code, body)
	}
	if code, body := call(a.adminToken, fmt.Sprintf(`{"action":"device_channels","device_ids":[%q],"channel":null}`, da)); code != 200 {
		t.Fatalf("clear %d %s", code, body)
	}
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM agent_release_audit WHERE tenant_id=$1::uuid AND actor=$2 AND source='portal'`, a.tenantID, a.adminEmail).Scan(&count); err != nil || count != 4 {
		t.Fatal("audit actor/actions", count, err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE tenants SET contact_email='recipient@example.test' WHERE id=$1::uuid`, a.tenantID); err != nil {
		t.Fatal(err)
	}
	p0 := map[string]any{"version": version, "banner": "Critical security update scheduled", "scheduled_at": time.Now().Add(25 * time.Hour)}
	raw, _ := json.Marshal(p0)
	resp, err := http.Post(env.internalSrv.URL+"/admin/tenants/"+a.tenantID+"/agent-releases/p0", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("P0 %d", resp.StatusCode)
	}
	if code, body := call(a.adminToken, `{"action":"clear_hold"}`); code != 200 {
		t.Fatalf("clear hold %d %s", code, body)
	}
	code, body = portalCall(t, http.MethodGet, "/v1/portal/agent-releases", a.viewerToken, "")
	if code != 200 || !strings.Contains(string(body), "Critical security update scheduled") {
		t.Fatalf("P0 vanished after customer write %d %s", code, body)
	}
}

func TestPortalP0FloorAllowsLaterApproval(t *testing.T) {
	ctx := context.Background()
	a := newApprovalTenant(t, "p0-floor", false)
	da := seedSelfServiceDevice(t, a.tenantID, "security-update", "p0-"+randomHex(6), "macOS", time.Now())
	base := fmt.Sprintf("2004.%d.0", time.Now().UnixNano())
	higher := strings.TrimSuffix(base, ".0") + ".1"
	for i, v := range []string{base, higher} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,published_at) VALUES ('macos','stable',$1,'https://cdn.patched.im/test','test-sha','test-hmac',$2)`, v, time.Now().Add(time.Duration(i+10)*time.Second)); err != nil {
			t.Fatal(err)
		}
		vv := v
		t.Cleanup(func() {
			_, _ = env.pool.Exec(context.Background(), `DELETE FROM agent_versions WHERE platform='macos' AND version=$1`, vv)
		})
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO agent_release_settings(tenant_id,hold,pinned_version) VALUES ($1::uuid,true,$2)`, a.tenantID, base); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO agent_release_p0_notices(tenant_id,version,banner,actor,created_at,scheduled_at,email_due_at,email_recipient) VALUES ($1::uuid,$2,'Required critical update','test',clock_timestamp()-interval '26 hours',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '26 hours','recipient@example.test')`, a.tenantID, base); err != nil {
		t.Fatal(err)
	}
	code, body := portalCall(t, http.MethodPut, "/v1/portal/agent-releases", a.adminToken, `{"action":"clear_hold"}`)
	if code != 200 {
		t.Fatalf("clear hold %d %s", code, body)
	}
	code, body = portalCall(t, http.MethodGet, "/v1/portal/agent-releases", a.viewerToken, "")
	if code != 200 || !strings.Contains(string(body), `"p0_effective_version":"`+base+`"`) {
		t.Fatalf("clear bypassed floor %d %s", code, body)
	}
	code, body = portalCall(t, http.MethodPut, "/v1/portal/agent-releases", a.adminToken, `{"action":"approve"}`)
	if code != 200 {
		t.Fatalf("approve beyond floor %d %s", code, body)
	}
	code, body = portalCall(t, http.MethodGet, "/v1/portal/agent-releases", a.viewerToken, "")
	if code != 200 || !strings.Contains(string(body), `"p0_effective_version":"`+higher+`"`) || !strings.Contains(string(body), da) {
		t.Fatalf("floor became ceiling %d %s", code, body)
	}
}
