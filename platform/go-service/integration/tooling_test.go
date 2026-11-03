//go:build integration

package integration

// PAT-2021: IDE extensions, npm and pip packages, local models and MCP
// servers go in through POST /v1/inventory, through the real extractor, and
// come back out through /v1/portal/ai-tooling/* and the PAT-2015
// /v1/portal/tagged-products view, tenant-scoped. The MCP privacy guard is
// exercised over HTTP: the payload is refused before it is stored.

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
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/extractor"
	"patched.im/api/internal/metrics"
)

// signedPost posts body for a tenant and returns the status and response.
func signedPost(t *testing.T, tn cveTestTenant, body []byte) (int, []byte) {
	t.Helper()
	mac := hmac.New(sha256.New, tn.hmacSecret)
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tn.bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", randomHex(16))
	resp := postInventory(t, req)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// toolingFixture loads a tooling fixture with the device renamed and the
// payload re-addressed to the tenant; mutate edits it before posting.
func toolingFixture(t *testing.T, tn cveTestTenant, fixture, hwUUID string, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", fixture), &m); err != nil {
		t.Fatal(err)
	}
	m["tenant_id"] = tn.tenantID
	m["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	device := m["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	device["serial"] = "PAT2021" + strings.ToUpper(hwUUID[:8])
	device["hostname"] = "pat2021-" + strings.ToLower(hwUUID[:8])
	if mutate != nil {
		mutate(m)
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// postTooling posts and extracts, returning the device id.
func postTooling(t *testing.T, tn cveTestTenant, fixture, hwUUID string, mutate func(m map[string]any)) string {
	t.Helper()
	status, raw := signedPost(t, tn, toolingFixture(t, tn, fixture, hwUUID, mutate))
	if status != http.StatusOK {
		t.Fatalf("POST /v1/inventory = %d: %s", status, raw)
	}
	var out struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(context.Background(), env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, out.RawPayloadID)
	return deviceIDByHW(t, tn.tenantID, hwUUID)
}

type toolingItemCountsOut struct {
	Installed int `json:"installed"`
	Distinct  int `json:"distinct"`
	Devices   int `json:"devices"`
}

type toolingSummaryOut struct {
	DeviceCount      int `json:"device_count"`
	CollectionStatus map[string]struct {
		Complete    int `json:"complete"`
		Partial     int `json:"partial"`
		NotPresent  int `json:"not_present"`
		Failed      int `json:"failed"`
		NotReported int `json:"not_reported"`
	} `json:"collection_status"`
	IDEExtensions toolingItemCountsOut            `json:"ide_extensions"`
	Packages      map[string]toolingItemCountsOut `json:"packages"`
	LocalModels   struct {
		Models               toolingItemCountsOut `json:"models"`
		RuntimeInstallations toolingItemCountsOut `json:"runtime_installations"`
		TotalBytes           int64                `json:"total_bytes"`
		LowerBoundDevices    int                  `json:"lower_bound_devices"`
	} `json:"local_models"`
	MCPServers         toolingItemCountsOut            `json:"mcp_servers"`
	MCPServersByClient map[string]toolingItemCountsOut `json:"mcp_servers_by_client"`
}

type toolingBlockOut struct {
	CollectionStatus string            `json:"collection_status"`
	Units            map[string]string `json:"units"`
	LowerBound       bool              `json:"lower_bound"`
	ItemCount        *int              `json:"item_count"`
	ItemsByUnit      map[string]*int   `json:"items_by_unit"`
}

type toolingDevicesOut struct {
	Total   int `json:"total"`
	Limit   int `json:"limit"`
	Devices []struct {
		DeviceID        string          `json:"device_id"`
		Platform        string          `json:"platform"`
		IDEExtensions   toolingBlockOut `json:"ide_extensions"`
		PackageManagers toolingBlockOut `json:"package_managers"`
		LocalModels     struct {
			toolingBlockOut
			RuntimeInstallationCount *int   `json:"runtime_installation_count"`
			TotalBytes               *int64 `json:"total_bytes"`
		} `json:"local_models"`
		MCPServers toolingBlockOut `json:"mcp_servers"`
	} `json:"devices"`
}

func intOr(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func TestToolingIngestToPortalEndToEnd(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2021-tooling-"+sfx)
	other := newCVETestTenant(t, "pat2021-tooling-other-"+sfx)

	mac := postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx), nil)
	win := postTooling(t, tn, "with-tooling-complete-windows.json", newHW(sfx), nil)
	// The other tenant reports the same software twice over; none of it may
	// show in the first tenant's views.
	postTooling(t, other, "with-tooling-complete-macos.json", newHW(sfx), nil)
	postTooling(t, other, "with-tooling-complete-macos.json", newHW(sfx), nil)

	var sum toolingSummaryOut
	portalGetJSON(t, tn.token, "/v1/portal/ai-tooling/summary", &sum)
	if sum.DeviceCount != 2 {
		t.Fatalf("device_count = %d, want 2", sum.DeviceCount)
	}
	for _, block := range []string{"ide_extensions", "package_managers", "local_models", "mcp_servers"} {
		if c := sum.CollectionStatus[block]; c.Complete != 2 || c.NotReported != 0 {
			t.Fatalf("%s status counts = %+v, want 2 complete", block, c)
		}
	}
	if sum.IDEExtensions.Installed != 8 || sum.IDEExtensions.Distinct != 4 || sum.IDEExtensions.Devices != 2 {
		t.Fatalf("ide_extensions = %+v, want 8 installed, 4 distinct, 2 devices", sum.IDEExtensions)
	}
	if n := sum.Packages["npm_global"]; n.Installed != 4 || n.Distinct != 2 {
		t.Fatalf("npm packages = %+v", n)
	}
	if n := sum.Packages["pip_user"]; n.Installed != 2 || n.Distinct != 1 {
		t.Fatalf("pip packages = %+v", n)
	}
	if sum.LocalModels.Models.Installed != 4 || sum.LocalModels.Models.Distinct != 2 ||
		sum.LocalModels.RuntimeInstallations.Installed != 2 || sum.LocalModels.TotalBytes != 2*7300000000 {
		t.Fatalf("local_models = %+v", sum.LocalModels)
	}
	if sum.MCPServers.Installed != 6 || sum.MCPServers.Distinct != 3 || sum.MCPServersByClient["cursor"].Installed != 2 {
		t.Fatalf("mcp_servers = %+v by client %+v", sum.MCPServers, sum.MCPServersByClient)
	}

	// Tenant isolation: the other tenant sees only its own two devices.
	var otherSum toolingSummaryOut
	portalGetJSON(t, other.token, "/v1/portal/ai-tooling/summary", &otherSum)
	if otherSum.DeviceCount != 2 || otherSum.MCPServers.Installed != 6 || otherSum.MCPServers.Devices != 2 {
		t.Fatalf("other tenant summary = %+v", otherSum)
	}

	// Per device: the macOS device goes partial on MCP (a failed client) and
	// failed on local models; the Windows device stays complete.
	postTooling(t, tn, "with-tooling-complete-macos.json", deviceHW(t, mac), func(m map[string]any) {
		mcp := m["mcp_servers"].(map[string]any)
		mcp["collection_status"] = "partial"
		mcp["clients"].(map[string]any)["cursor"].(map[string]any)["collection_status"] = "failed"
		mcp["configs"] = mcp["configs"].([]any)[:1]
		mcp["servers"] = mcp["servers"].([]any)[:2]
		users := mcp["users"].([]any)[0].(map[string]any)
		users["collection_status"] = "partial"
		users["clients"].(map[string]any)["cursor"] = "failed"
		m["local_models"] = map[string]any{"collection_status": "failed"}
	})

	var devs toolingDevicesOut
	portalGetJSON(t, tn.token, "/v1/portal/ai-tooling/devices?limit=1", &devs)
	if devs.Total != 2 || len(devs.Devices) != 1 || devs.Limit != 1 {
		t.Fatalf("paging: total=%d len=%d limit=%d", devs.Total, len(devs.Devices), devs.Limit)
	}
	portalGetJSON(t, tn.token, "/v1/portal/ai-tooling/devices", &devs)
	byID := map[string]int{}
	for i, d := range devs.Devices {
		byID[d.DeviceID] = i
	}
	m, w := devs.Devices[byID[mac]], devs.Devices[byID[win]]
	if m.Platform != "macos" || w.Platform != "windows" {
		t.Fatalf("platforms = %s / %s", m.Platform, w.Platform)
	}
	// failed is never shown as none: counts are null.
	if m.LocalModels.CollectionStatus != "failed" || m.LocalModels.ItemCount != nil ||
		m.LocalModels.TotalBytes != nil || m.LocalModels.RuntimeInstallationCount != nil {
		t.Fatalf("failed local_models = %+v", m.LocalModels)
	}
	// partial: a lower bound; the failed client is null, not 0, and its
	// last known server is not counted.
	if m.MCPServers.CollectionStatus != "partial" || !m.MCPServers.LowerBound || intOr(m.MCPServers.ItemCount) != 2 ||
		m.MCPServers.ItemsByUnit["cursor"] != nil || intOr(m.MCPServers.ItemsByUnit["claude_desktop"]) != 2 ||
		m.MCPServers.Units["cursor"] != "failed" {
		t.Fatalf("partial mcp_servers = %+v", m.MCPServers)
	}
	if n := countRows(t, `SELECT count(*)::int FROM software_installations WHERE device_id = $1::uuid
		AND identity_kind = 'mcp_server' AND removed_at IS NULL`, mac); n != 3 {
		t.Fatalf("active MCP installations after partial = %d, want 3 (partial closes nothing)", n)
	}
	if w.LocalModels.CollectionStatus != "complete" || intOr(w.LocalModels.ItemCount) != 2 ||
		w.LocalModels.TotalBytes == nil || *w.LocalModels.TotalBytes != 7300000000 ||
		intOr(w.LocalModels.RuntimeInstallationCount) != 1 || intOr(w.LocalModels.ItemsByUnit["ollama"]) != 2 {
		t.Fatalf("windows local_models = %+v", w.LocalModels)
	}
	if intOr(w.PackageManagers.ItemCount) != 3 || intOr(w.IDEExtensions.ItemCount) != 4 || intOr(w.MCPServers.ItemCount) != 3 {
		t.Fatalf("windows counts = %+v %+v %+v", w.PackageManagers, w.IDEExtensions, w.MCPServers)
	}

	portalGetJSON(t, tn.token, "/v1/portal/ai-tooling/summary", &sum)
	if c := sum.CollectionStatus["local_models"]; c.Failed != 1 || c.Complete != 1 {
		t.Fatalf("local_models statuses = %+v", c)
	}
	if sum.LocalModels.Models.Installed != 2 || sum.LocalModels.TotalBytes != 7300000000 {
		t.Fatalf("summary still counts the failed device's models: %+v", sum.LocalModels)
	}

	// The other tenant's views are unchanged by all of this.
	portalGetJSON(t, other.token, "/v1/portal/ai-tooling/summary", &otherSum)
	if otherSum.CollectionStatus["local_models"].Failed != 0 || otherSum.MCPServers.Installed != 6 {
		t.Fatalf("other tenant summary changed: %+v", otherSum)
	}
	var otherDevs toolingDevicesOut
	portalGetJSON(t, other.token, "/v1/portal/ai-tooling/devices", &otherDevs)
	for _, d := range otherDevs.Devices {
		if d.DeviceID == mac || d.DeviceID == win {
			t.Fatal("another tenant's device is visible")
		}
	}
}

func deviceHW(t *testing.T, deviceID string) string {
	t.Helper()
	var hw string
	if err := env.pool.QueryRow(context.Background(), `SELECT hw_uuid FROM devices WHERE id = $1::uuid`, deviceID).Scan(&hw); err != nil {
		t.Fatal(err)
	}
	return hw
}

// The privacy guard over HTTP: env or args on an MCP server rejects the
// payload with 400 before anything is stored, the response and the error
// carry no value, and the alert counter moves.
func TestToolingMCPPrivacyGuardOverHTTP(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2021-guard-"+sfx)
	const planted = "placeholder-planted-value"
	for _, field := range []string{"env", "args"} {
		t.Run(field, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.MCPPrivacyGuardRejectionsTotal)
			stored := countRows(t, `SELECT count(*)::int FROM raw_payloads WHERE tenant_id = $1::uuid`, tn.tenantID)
			body := toolingFixture(t, tn, "with-tooling-complete-macos.json", newHW(sfx), func(m map[string]any) {
				s := m["mcp_servers"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if field == "env" {
					s["env"] = map[string]any{"GITHUB_TOKEN": planted}
				} else {
					s["args"] = []any{"-y", "@modelcontextprotocol/server-github", "--token", planted}
				}
			})
			status, raw := signedPost(t, tn, body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, raw)
			}
			if strings.Contains(string(raw), planted) || !strings.Contains(string(raw), "privacy guard") {
				t.Fatalf("response = %s", raw)
			}
			if got := testutil.ToFloat64(metrics.MCPPrivacyGuardRejectionsTotal); got != before+1 {
				t.Fatalf("guard counter = %v, want %v", got, before+1)
			}
			if n := countRows(t, `SELECT count(*)::int FROM raw_payloads WHERE tenant_id = $1::uuid`, tn.tenantID); n != stored {
				t.Fatalf("raw_payloads grew from %d to %d: the payload was stored", stored, n)
			}
		})
	}
}

// A PAT-2015 rule of each relevant type tags an ingested item end to end:
// ide_extension per marketplace (Visual Studio Marketplace for VS Code, Open
// VSX for Cursor, JetBrains Marketplace), package per source (npm, pip) and
// mcp_server. Half the rules are published before the device reports
// (ingest tagging), half after (publish backfill). Values carry a random
// suffix because the rule tables are global.
func TestToolingCategoryRulesTagEachType(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2021-tags-"+sfx)
	other := newCVETestTenant(t, "pat2021-tags-other-"+sfx)
	copilot := "github.copilot-" + sfx
	cline := "saoudrizwan.claude-dev-" + sfx
	jb := "com.github.copilot-" + sfx
	npm := "@anthropic-ai/claude-code-" + sfx
	pip := "OpenAI_" + sfx // PEP 503: openai-<sfx>
	server := "filesystem-" + sfx

	rename := func(m map[string]any) {
		exts := m["ide_extensions"].(map[string]any)["extensions"].([]any)
		exts[0].(map[string]any)["id"] = copilot
		exts[2].(map[string]any)["id"] = cline
		exts[3].(map[string]any)["id"] = jb
		pkgs := m["package_managers"].(map[string]any)["packages"].([]any)
		pkgs[0].(map[string]any)["name"] = npm
		pkgs[2].(map[string]any)["name"] = pip
		m["mcp_servers"].(map[string]any)["servers"].([]any)[0].(map[string]any)["name"] = server
	}

	type ruleCase struct {
		spec     map[string]any
		ident    string
		kind     string
		backfill bool
	}
	cases := []ruleCase{
		{map[string]any{"identifier_type": "ide_extension", "identifier_value": copilot, "qualifier": "vscode_marketplace", "subtype": "ide_extension"}, copilot, "ide_extension", false},
		{map[string]any{"identifier_type": "ide_extension", "identifier_value": cline, "qualifier": "open_vsx", "subtype": "ide_extension"}, cline, "ide_extension", true},
		{map[string]any{"identifier_type": "ide_extension", "identifier_value": jb, "qualifier": "jetbrains_marketplace", "subtype": "ide_extension"}, jb, "ide_extension", false},
		{map[string]any{"identifier_type": "package", "identifier_value": npm, "qualifier": "npm", "subtype": "cli"}, npm, "package", true},
		{map[string]any{"identifier_type": "package", "identifier_value": "openai-" + sfx, "qualifier": "pip", "subtype": "cli"}, pip, "package", false},
		{map[string]any{"identifier_type": "mcp_server", "identifier_value": strings.ToUpper(server), "subtype": "mcp_server"}, server, "mcp_server", true},
	}
	ids := make([]int64, len(cases))
	for i, c := range cases {
		c.spec["category"] = "ai_tooling"
		c.spec["actor"] = "andy@patched.im"
		ids[i] = createCategoryRule(t, c.spec).ID
		if !c.backfill {
			publishCategoryRule(t, ids[i])
		}
	}
	// A near miss: the same extension id under the wrong marketplace must
	// not tag. VS Code reports copilot, so an Open VSX rule for it misses.
	miss := createCategoryRule(t, map[string]any{"identifier_type": "ide_extension", "identifier_value": copilot,
		"qualifier": "open_vsx", "category": "ai_tooling", "subtype": "ide_extension", "actor": "andy@patched.im"})
	publishCategoryRule(t, miss.ID)

	dev := postTooling(t, tn, "with-tooling-complete-macos.json", newHW(sfx), rename)
	postTooling(t, other, "with-tooling-complete-windows.json", newHW(sfx), rename)
	for i, c := range cases {
		if c.backfill {
			if pub := publishCategoryRule(t, ids[i]); pub.Backfill.Tagged != 2 {
				t.Fatalf("%s publish backfill tagged %d, want 2 (one per tenant)", c.ident, pub.Backfill.Tagged)
			}
		}
	}
	if n := countRows(t, `SELECT count(*)::int FROM software_category_tags WHERE rule_id = $1 AND retired_at IS NULL`, miss.ID); n != 0 {
		t.Fatalf("wrong-marketplace rule tagged %d items", n)
	}

	out := readTagged(t, tn, "?category=ai_tooling")
	for i, c := range cases {
		p, ok := findTagged(out, c.ident)
		if !ok {
			t.Fatalf("rule %d (%v) tagged nothing: %+v", i, c.spec, out.Products)
		}
		if p.ObservationKind != c.kind || p.DeviceCount != 1 || p.ApprovalState != "unreviewed" ||
			len(p.MatchBasis) != 1 || p.MatchBasis[0] != c.spec["identifier_type"] {
			t.Fatalf("tagged %s = %+v", c.ident, p)
		}
		if n := countRows(t, `SELECT count(*)::int FROM software_category_tags WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL`, dev, ids[i]); n != 1 {
			t.Fatalf("%s live tags = %d, want 1", c.ident, n)
		}
	}
	// Tenant isolation on the tag view: each tenant sees one device.
	otherOut := readTagged(t, other, "?category=ai_tooling")
	if p, ok := findTagged(otherOut, server); !ok || p.DeviceCount != 1 || len(p.Platforms) != 1 || p.Platforms[0] != "windows" {
		t.Fatalf("other tenant's tag = %+v", p)
	}

	// Removal closes the installation and the tag is retired on the next
	// ingest: the MCP server no longer configured, under a complete report.
	postTooling(t, tn, "with-tooling-complete-macos.json", deviceHW(t, dev), func(m map[string]any) {
		rename(m)
		mcp := m["mcp_servers"].(map[string]any)
		mcp["servers"] = mcp["servers"].([]any)[1:]
		mcp["configs"].([]any)[0].(map[string]any)["server_count"] = 1
	})
	if n := countRows(t, `SELECT count(*)::int FROM software_category_tags WHERE device_id = $1::uuid AND rule_id = $2 AND retired_at IS NULL`, dev, ids[5]); n != 0 {
		t.Fatalf("tag on a removed MCP server is still live (%d)", n)
	}
}

// Review P1: a top-level key that differs from a payload field only by case
// or Unicode folding ("MCP_SERVERS", "mcp_ſervers", "Homebrew") is decoded
// into that field by encoding/json, so it must be rejected before storage;
// otherwise it would skip the validator and the privacy guard. The MCP
// variants count as privacy guard hits.
func TestToolingCaseVariantKeysRejectedOverHTTP(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2021-fold-"+sfx)
	for _, tc := range []struct {
		key   string
		guard bool
	}{{"MCP_SERVERS", true}, {"mcp_ſervers", true}, {"Homebrew", false}} {
		t.Run(tc.key, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.MCPPrivacyGuardRejectionsTotal)
			stored := countRows(t, `SELECT count(*)::int FROM raw_payloads WHERE tenant_id = $1::uuid`, tn.tenantID)
			body := toolingFixture(t, tn, "with-tooling-complete-macos.json", newHW(sfx), func(m map[string]any) {
				if tc.guard {
					block := m["mcp_servers"].(map[string]any)
					s := block["servers"].([]any)[1].(map[string]any)
					s["env"] = map[string]any{"GITHUB_TOKEN": "placeholder-planted-value"}
					s["host"] = "user:pw@evil.example.test"
					delete(m, "mcp_servers")
					m[tc.key] = block
					return
				}
				m[tc.key] = map[string]any{"collection_status": "complete", "formulae": "not validated"}
			})
			status, raw := signedPost(t, tn, body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, raw)
			}
			if strings.Contains(string(raw), "placeholder-planted-value") || strings.Contains(string(raw), "evil.example.test") {
				t.Fatalf("response echoes a value: %s", raw)
			}
			want := before
			if tc.guard {
				want++
			}
			if got := testutil.ToFloat64(metrics.MCPPrivacyGuardRejectionsTotal); got != want {
				t.Fatalf("guard counter = %v, want %v", got, want)
			}
			if n := countRows(t, `SELECT count(*)::int FROM raw_payloads WHERE tenant_id = $1::uuid`, tn.tenantID); n != stored {
				t.Fatalf("raw_payloads grew from %d to %d", stored, n)
			}
		})
	}
}
