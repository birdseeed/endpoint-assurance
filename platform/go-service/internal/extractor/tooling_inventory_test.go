package extractor

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"patched.im/api/internal/categorytag"
)

// PAT-2021 ingest tests for the four tooling blocks. They run inside one
// rolled-back transaction on TEST_DATABASE_URL (the Homebrew harness), so
// they need the migrations applied first (the integration suite does that).

// ingestTooling runs the software inventory step for one payload at received.
func (db *homebrewTestDB) ingestTooling(received time.Time, platform string, p *payload) {
	db.t.Helper()
	var id int64
	if err := db.tx.QueryRow(db.ctx, `
		INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
		VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id
	`, db.tenantID, db.deviceID, received).Scan(&id); err != nil {
		db.t.Fatal(err)
	}
	p.SchemaVersion, p.Platform, p.Agent, p.AgentVersion = 3, platform, "pat2021", "test"
	p.CollectedAt = received.Format(time.RFC3339)
	row := claimedRow{ID: id, ReceivedAt: received, TenantID: db.tenantID}
	if _, err := upsertSoftwareInventory(db.ctx, db.tx, row, db.deviceID, p, platform); err != nil {
		db.t.Fatalf("ingest at %s: %v", received, err)
	}
}

// active returns the active installations of one identity kind, keyed
// "value|companion".
func (db *homebrewTestDB) active(kind string) map[string]bool {
	db.t.Helper()
	rows, err := db.tx.Query(db.ctx, `
		SELECT identity_value_normalized || '|' || companion_value_normalized
		FROM software_installations
		WHERE device_id = $1::uuid AND removed_at IS NULL AND identity_kind = $2
	`, db.deviceID, kind)
	if err != nil {
		db.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			db.t.Fatal(err)
		}
		out[k] = true
	}
	return out
}

func (db *homebrewTestDB) currentCount(block string) int {
	db.t.Helper()
	return db.int(`SELECT count(*)::int FROM tooling_current_entries WHERE device_id = $1::uuid AND block = $2`, db.deviceID, block)
}

func (db *homebrewTestDB) toolingState(block string) (status string, authority map[string]string) {
	db.t.Helper()
	var raw []byte
	if err := db.tx.QueryRow(db.ctx, `
		SELECT collection_status, authority FROM tooling_device_state WHERE device_id = $1::uuid AND block = $2
	`, db.deviceID, block).Scan(&status, &raw); err != nil {
		db.t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &authority); err != nil {
		db.t.Fatal(err)
	}
	return status, authority
}

func sp(s string) *string { return &s }

func testIDE(status string, ids ...string) *ideExtensionsPart {
	b := &ideExtensionsPart{CollectionStatus: status, Users: []toolingUserPart{{User: "alice", UserID: sp("501"), CollectionStatus: status}}}
	if status == "failed" {
		return b
	}
	b.Extensions = []ideExtensionPart{}
	if status != "not_present" {
		b.Profiles = []ideProfilePart{{User: "alice", UserID: sp("501"), Family: "vscode", Editor: "vscode", CollectionStatus: "complete"}}
	}
	for _, id := range ids {
		editor, family := "vscode", "vscode"
		switch {
		case len(id) > 7 && id[:7] == "cursor:":
			editor, id = "cursor", id[7:]
		case len(id) > 10 && id[:10] == "jetbrains:":
			editor, family, id = "PyCharm", "jetbrains", id[10:]
		}
		b.Extensions = append(b.Extensions, ideExtensionPart{User: "alice", UserID: sp("501"), Family: family,
			Editor: editor, ID: sp(id), Name: sp(id), Version: sp("1.0.0"), ManifestStatus: sp("read")})
	}
	return b
}

func testPackages(status string, sources map[string]string, pkgs ...[2]string) *packageManagersPart {
	b := &packageManagersPart{CollectionStatus: status, Sources: map[string]packageSourcePart{}}
	for src, st := range sources {
		b.Sources[src] = packageSourcePart{CollectionStatus: st}
	}
	if status == "failed" {
		return b
	}
	b.Packages = []packagePart{}
	for _, p := range pkgs {
		b.Packages = append(b.Packages, packagePart{Source: p[0], Manager: "nvm", Scope: "user", User: sp("alice"),
			UserID: sp("501"), Name: sp(p[1]), Version: sp("1.0"), Prefix: sp("/Users/alice/.nvm"), MetadataStatus: sp("read")})
	}
	return b
}

func allSources(st string) map[string]string {
	return map[string]string{"npm_global": st, "pip_user": st, "pipx": st}
}

func testModels(status string, runtimes map[string]string, models ...[3]string) *localModelsPart {
	b := &localModelsPart{CollectionStatus: status, Runtimes: map[string]localRuntimeSummary{}}
	for rt, st := range runtimes {
		b.Runtimes[rt] = localRuntimeSummary{CollectionStatus: st}
	}
	if status == "failed" {
		return b
	}
	b.Totals = &localModelTotalsPart{ModelCount: len(models), TotalBytes: int64(len(models)) * 1000}
	b.Models = []localModelPart{}
	seen := map[string]bool{}
	for _, m := range models {
		if !seen[m[0]] {
			seen[m[0]] = true
			b.Installations = append(b.Installations, localRuntimeInstallationPart{Runtime: m[0], Scope: "system",
				Kind: "app_bundle", Path: "/Applications/" + m[0] + ".app", Version: sp("1.0"), VersionSource: "info_plist"})
		}
		size := int64(1000)
		b.Models = append(b.Models, localModelPart{Runtime: m[0], User: sp("alice"), UserID: sp("501"),
			StorePath: "/Users/alice/.ollama/models", Name: sp(m[1]), Tag: sp(m[2]), SizeBytes: &size})
	}
	return b
}

func testMCP(status string, clients map[string]string, servers ...[2]string) *mcpServersPart {
	b := &mcpServersPart{CollectionStatus: status, Clients: map[string]mcpClientPart{}}
	for c, st := range clients {
		b.Clients[c] = mcpClientPart{CollectionStatus: st}
	}
	if status == "failed" {
		return b
	}
	b.Servers = []mcpServerPart{}
	for _, s := range servers {
		b.Servers = append(b.Servers, mcpServerPart{Client: s[0], User: sp("alice"), UserID: sp("501"),
			ConfigPath: "/Users/alice/.cursor/mcp.json", Scope: "user", Name: sp(s[1]), Transport: "stdio",
			TransportSource: "inferred", Executable: sp("npx"), Runner: sp("npx"),
			Package: sp("@modelcontextprotocol/server-" + s[1]), PackageStatus: "extracted"})
	}
	return b
}

func allClients(st string) map[string]string {
	return map[string]string{"claude_desktop": st, "cursor": st, "vscode": st, "windsurf": st, "claude_code": st}
}

func allRuntimes(st string) map[string]string {
	return map[string]string{"ollama": st, "lm_studio": st, "llama_cpp": st}
}

// Every block, complete: each item is an observation and an installation of
// its own identity kind, keyed the way the PAT-2015 rule types expect, with
// a current entry, and the report's units are recorded as authority. The
// same shape ingests on Windows.
func TestToolingCompleteIngestEachBlock(t *testing.T) {
	for _, platform := range []string{"macos", "windows"} {
		t.Run(platform, func(t *testing.T) {
			db := openHomebrewTestDB(t)
			t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
			db.ingestTooling(t0, platform, &payload{
				IdeExtensions: testIDE("complete", "GitHub.Copilot", "cursor:saoudrizwan.claude-dev", "jetbrains:com.github.copilot"),
				PackageManagers: testPackages("complete", map[string]string{"npm_global": "complete", "pip_user": "complete", "pipx": "not_present"},
					[2]string{"npm_global", "@Anthropic-AI/Claude-Code"}, [2]string{"pip_user", "Open_AI.Client"}),
				LocalModels: testModels("complete", map[string]string{"ollama": "complete", "lm_studio": "not_present", "llama_cpp": "not_present"},
					[3]string{"ollama", "Llama3.2", "latest"}),
				McpServers: testMCP("complete", map[string]string{"claude_desktop": "not_present", "cursor": "complete",
					"vscode": "not_present", "windsurf": "not_present", "claude_code": "not_present"}, [2]string{"cursor", "GitHub"}),
			})
			wantKinds := map[string]map[string]bool{
				kindIDEExtension: {
					"github.copilot|" + categorytag.MarketplaceVSCode:          true,
					"saoudrizwan.claude-dev|" + categorytag.MarketplaceOpenVSX: true,
					"com.github.copilot|" + categorytag.MarketplaceJetBrains:   true,
				},
				kindNPMPackage:        {"@anthropic-ai/claude-code|": true},
				kindPipPackage:        {"open-ai-client|": true},
				kindLocalModel:        {"llama3.2:latest|ollama": true},
				kindLocalModelRuntime: {"ollama|ollama": true},
				kindMCPServer:         {"github|cursor": true},
			}
			for kind, want := range wantKinds {
				got := db.active(kind)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("%s installations = %v, want %v", kind, got, want)
				}
			}
			if n := db.int(`SELECT count(*)::int FROM software_observations so
				JOIN software_observation_resolutions r ON r.observation_id = so.id
				WHERE so.device_id = $1::uuid AND so.platform = $2 AND r.resolution_state = 'unresolved'
				  AND so.identity_kind IN `+toolingIdentityKindsSQL, db.deviceID, platform); n != 8 {
				t.Errorf("unresolved tooling observations = %d, want 8", n)
			}
			if n := db.int(`SELECT count(*)::int FROM tooling_observation_details WHERE device_id = $1::uuid`, db.deviceID); n != 8 {
				t.Errorf("detail rows = %d, want 8", n)
			}
			for block, want := range map[string]int{toolingBlockIDE: 3, toolingBlockPackages: 2, toolingBlockModels: 2, toolingBlockMCP: 1} {
				if got := db.currentCount(block); got != want {
					t.Errorf("%s current entries = %d, want %d", block, got, want)
				}
			}
			var scopes []string
			if err := db.tx.QueryRow(db.ctx, `SELECT authoritative_scopes FROM software_inventory_runs
				WHERE device_id = $1::uuid ORDER BY received_at DESC LIMIT 1`, db.deviceID).Scan(&scopes); err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{"ide_extensions": true, "packages:npm_global": true, "packages:pip_user": true,
				"packages:pipx": true, "local_models:ollama": true, "local_models:lm_studio": true,
				"local_models:llama_cpp": true, "mcp_servers:cursor": true, "mcp_servers:claude_desktop": true,
				"mcp_servers:vscode": true, "mcp_servers:windsurf": true, "mcp_servers:claude_code": true}
			if platform == "macos" {
				want["all_software"] = false // apps not present in this payload
			}
			for _, s := range scopes {
				if !want[s] {
					t.Errorf("unexpected scope %q", s)
				}
				delete(want, s)
			}
			for s, needed := range want {
				if needed {
					t.Errorf("missing scope %q", s)
				}
			}
			status, auth := db.toolingState(toolingBlockPackages)
			if status != "complete" || len(auth) != 3 {
				t.Errorf("package state = %s %v", status, auth)
			}
			// The MCP detail row carries the allowlist and nothing else.
			var attrs map[string]any
			var raw []byte
			if err := db.tx.QueryRow(db.ctx, `SELECT attributes FROM tooling_observation_details
				WHERE device_id = $1::uuid AND block = 'mcp_servers'`, db.deviceID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &attrs); err != nil {
				t.Fatal(err)
			}
			allowed := setOf(mcpServerAllowed...)
			for k := range attrs {
				if !allowed[k] {
					t.Errorf("stored MCP attribute %q is outside the allowlist", k)
				}
			}
			if len(attrs) != len(mcpServerAllowed) {
				t.Errorf("stored MCP attributes = %d keys, want %d", len(attrs), len(mcpServerAllowed))
			}
		})
	}
}

// Partial never prunes and never closes; failed writes nothing and changes
// nothing; only a complete (or not_present) report removes what it no
// longer lists. Walked for every block.
func TestToolingPartialNeverPrunesFailedChangesNothing(t *testing.T) {
	type step struct {
		status string
		items  []string
	}
	blocks := map[string]struct {
		kind  string
		build func(status string, items []string) *payload
	}{
		toolingBlockIDE: {kindIDEExtension, func(status string, items []string) *payload {
			return &payload{IdeExtensions: testIDE(status, items...)}
		}},
		toolingBlockPackages: {kindNPMPackage, func(status string, items []string) *payload {
			var pk [][2]string
			for _, i := range items {
				pk = append(pk, [2]string{"npm_global", i})
			}
			src := allSources(status)
			if status == "partial" {
				src = map[string]string{"npm_global": "partial", "pip_user": "not_present", "pipx": "not_present"}
			}
			return &payload{PackageManagers: testPackages(status, src, pk...)}
		}},
		toolingBlockModels: {kindLocalModel, func(status string, items []string) *payload {
			var ms [][3]string
			for _, i := range items {
				ms = append(ms, [3]string{"ollama", i, "latest"})
			}
			rt := allRuntimes(status)
			if status == "complete" || status == "partial" {
				rt = map[string]string{"ollama": status, "lm_studio": "not_present", "llama_cpp": "not_present"}
			}
			return &payload{LocalModels: testModels(status, rt, ms...)}
		}},
		toolingBlockMCP: {kindMCPServer, func(status string, items []string) *payload {
			var ss [][2]string
			for _, i := range items {
				ss = append(ss, [2]string{"cursor", i})
			}
			cl := allClients("not_present")
			cl["cursor"] = status
			if status == "failed" || status == "not_present" {
				cl = allClients(status)
			}
			return &payload{McpServers: testMCP(status, cl, ss...)}
		}},
	}
	for block, spec := range blocks {
		t.Run(block, func(t *testing.T) {
			db := openHomebrewTestDB(t)
			t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)
			names := func() int {
				n := 0
				for k := range db.active(spec.kind) {
					_ = k
					n++
				}
				return n
			}
			for i, s := range []struct {
				step
				wantActive, wantCurrent int
				wantStatus              string
			}{
				{step{"complete", []string{"alpha", "beta"}}, 2, 2, "complete"},
				// partial lists only alpha: beta stays active and current.
				{step{"partial", []string{"alpha"}}, 2, 2, "partial"},
				// failed lists nothing and changes nothing.
				{step{"failed", nil}, 2, 2, "failed"},
				// complete lists alpha and gamma: beta goes.
				{step{"complete", []string{"alpha", "gamma"}}, 2, 2, "complete"},
				// not_present: everything goes.
				{step{"not_present", nil}, 0, 0, "not_present"},
			} {
				db.ingestTooling(t0.Add(time.Duration(i)*time.Hour), "macos", spec.build(s.status, s.items))
				if got := names(); got != s.wantActive {
					t.Fatalf("step %d (%s): active %s = %d, want %d (%v)", i, s.status, spec.kind, got, s.wantActive, db.active(spec.kind))
				}
				// Local models also carry their runtime installation entry.
				current := db.int(`SELECT count(*)::int FROM tooling_current_entries
					WHERE device_id = $1::uuid AND block = $2 AND entry_kind <> 'runtime_installation'`, db.deviceID, block)
				if current != s.wantCurrent {
					t.Fatalf("step %d (%s): current entries = %d, want %d", i, s.status, current, s.wantCurrent)
				}
				if status, _ := db.toolingState(block); status != s.wantStatus {
					t.Fatalf("step %d: state = %s, want %s", i, status, s.wantStatus)
				}
			}
		})
	}
}

// Absence authority is per unit, and only when the block is not truncated.
func TestToolingUnitAuthority(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)
	db.ingestTooling(t0, "macos", &payload{PackageManagers: testPackages("complete", allSources("complete"),
		[2]string{"npm_global", "left-pad"}, [2]string{"pip_user", "requests"}, [2]string{"pipx", "llm"})})

	// npm complete, pip_user complete, pipx failed: npm prunes; pip_package
	// is fed by pip_user and pipx, so it must not close llm (pipx only).
	db.ingestTooling(t0.Add(time.Hour), "macos", &payload{PackageManagers: testPackages("partial",
		map[string]string{"npm_global": "complete", "pip_user": "complete", "pipx": "failed"})})
	if got := db.active(kindNPMPackage); len(got) != 0 {
		t.Fatalf("npm packages after an authoritative empty npm source = %v, want none", got)
	}
	if got := db.active(kindPipPackage); !got["requests|"] || !got["llm|"] {
		t.Fatalf("pip packages = %v: a failed pipx source must not let pip_user close them", got)
	}
	// Current entries are per source: pip_user drops requests, pipx keeps llm.
	if n := db.int(`SELECT count(*)::int FROM tooling_current_entries WHERE device_id = $1::uuid AND unit = 'pipx'`, db.deviceID); n != 1 {
		t.Fatalf("pipx current entries = %d, want 1", n)
	}
	if n := db.int(`SELECT count(*)::int FROM tooling_current_entries WHERE device_id = $1::uuid AND unit = 'pip_user'`, db.deviceID); n != 0 {
		t.Fatalf("pip_user current entries = %d, want 0", n)
	}

	// A truncated block grants nothing, even with every unit complete: the
	// user bound can stop a read without marking a unit truncated.
	db.ingestTooling(t0.Add(2*time.Hour), "macos", &payload{McpServers: testMCP("complete", allClients("not_present"), [2]string{"cursor", "github"})})
	trunc := testMCP("partial", allClients("complete"))
	trunc.Clients["claude_desktop"] = mcpClientPart{CollectionStatus: "complete"}
	trunc.Truncated, trunc.TruncationReason = true, sp("user_limit")
	db.ingestTooling(t0.Add(3*time.Hour), "macos", &payload{McpServers: trunc})
	if got := db.active(kindMCPServer); !got["github|cursor"] {
		t.Fatalf("a truncated report closed an MCP server: %v", got)
	}
	if _, auth := db.toolingState(toolingBlockMCP); auth["cursor"] == "" {
		t.Fatal("the earlier complete report's cursor authority was lost")
	}
}

// The macOS apps snapshot (all_software) never closes a tooling installation,
// and a tooling scope never closes an application.
func TestToolingScopesAreSeparateFromApps(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)
	db.ingest(t0, firefoxApp, nil)
	db.ingestTooling(t0.Add(time.Hour), "macos", &payload{AppsPresent: true, Apps: firefoxApp,
		IdeExtensions: testIDE("complete", "github.copilot")})
	// An apps snapshot without the IDE block: the extension stays.
	db.ingest(t0.Add(2*time.Hour), []appPart{}, nil)
	if got := db.active(kindIDEExtension); len(got) != 1 {
		t.Fatalf("all_software closed an IDE extension: %v", got)
	}
	// An IDE block that is not_present, with the app still reported.
	db.ingestTooling(t0.Add(3*time.Hour), "macos", &payload{AppsPresent: true, Apps: firefoxApp,
		IdeExtensions: testIDE("not_present")})
	if n := db.int(`SELECT count(*)::int FROM software_installations WHERE device_id = $1::uuid
		AND removed_at IS NULL AND identity_kind = 'macos_bundle_team'`, db.deviceID); n != 1 {
		t.Fatalf("active apps = %d, want 1", n)
	}
	if got := db.active(kindIDEExtension); len(got) != 0 {
		t.Fatalf("not_present left IDE extensions active: %v", got)
	}
}

// An older replay never moves the state back, and an older partial report
// cannot re-add an item a newer complete report removed.
func TestToolingOlderReplayCannotResurrect(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Microsecond)
	db.ingestTooling(t0.Add(2*time.Hour), "macos", &payload{IdeExtensions: testIDE("complete", "a.one")})
	db.ingestTooling(t0.Add(time.Hour), "macos", &payload{IdeExtensions: testIDE("partial", "a.two")})
	if status, _ := db.toolingState(toolingBlockIDE); status != "complete" {
		t.Fatalf("state = %s, want the newer complete", status)
	}
	if n := db.currentCount(toolingBlockIDE); n != 1 {
		t.Fatalf("current entries = %d, want 1 (the older partial is older than the authority)", n)
	}
}

// Re-extracting the same payload is idempotent.
func TestToolingReextractionIsIdempotent(t *testing.T) {
	db := openHomebrewTestDB(t)
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	var id int64
	if err := db.tx.QueryRow(db.ctx, `INSERT INTO raw_payloads(tenant_id,device_id,received_at,body)
		VALUES($1::uuid,$2::uuid,$3,'{}'::jsonb) RETURNING id`, db.tenantID, db.deviceID, t0).Scan(&id); err != nil {
		t.Fatal(err)
	}
	p := &payload{SchemaVersion: 3, Platform: "macos", CollectedAt: t0.Format(time.RFC3339),
		IdeExtensions: testIDE("complete", "a.one", "a.two"),
		McpServers:    testMCP("complete", allClients("complete"), [2]string{"cursor", "x"})}
	row := claimedRow{ID: id, ReceivedAt: t0, TenantID: db.tenantID}
	for i := 0; i < 2; i++ {
		if _, err := upsertSoftwareInventory(db.ctx, db.tx, row, db.deviceID, p, "macos"); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if n := db.int(`SELECT count(*)::int FROM software_observations WHERE device_id = $1::uuid`, db.deviceID); n != 3 {
		t.Fatalf("observations = %d, want 3", n)
	}
}

// largeToolingPayload builds a payload at every block's contract bound.
func largeToolingPayload(ext, pkgPerSource, models, servers int) *payload {
	var ids []string
	for i := 0; i < ext; i++ {
		ids = append(ids, fmt.Sprintf("pub.ext-%05d", i))
	}
	var pk [][2]string
	for _, src := range packageSources {
		for i := 0; i < pkgPerSource; i++ {
			pk = append(pk, [2]string{src, fmt.Sprintf("%s-pkg-%05d", src, i)})
		}
	}
	var ms [][3]string
	for i := 0; i < models; i++ {
		ms = append(ms, [3]string{localModelRuntimes[i%3], fmt.Sprintf("model-%05d", i), "latest"})
	}
	var ss [][2]string
	for i := 0; i < servers; i++ {
		ss = append(ss, [2]string{mcpClients[i%5], fmt.Sprintf("server-%05d", i)})
	}
	return &payload{
		IdeExtensions:   testIDE("partial", ids...),
		PackageManagers: testPackages("partial", allSources("partial"), pk...),
		LocalModels:     testModels("partial", allRuntimes("partial"), ms...),
		McpServers:      testMCP("partial", allClients("partial"), ss...),
	}
}

// A payload at every bound (5,000 extensions, 15,000 packages, 5,000
// models, 2,000 servers) costs the same fixed number of statements as a
// handful of items.
func TestToolingIngestStatementCountIsBounded(t *testing.T) {
	measure := func(p *payload) int64 {
		counter := &statementCounter{}
		db := openHomebrewTestDBWith(t, counter)
		t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		before := counter.n.Load()
		db.ingestTooling(t0, "macos", p)
		return counter.n.Load() - before
	}
	small := measure(largeToolingPayload(3, 2, 3, 5))
	large := measure(largeToolingPayload(ideMaxExtensions, packageMaxPerSource, localModelMaxModels, mcpMaxServers))
	t.Logf("statements: small payload %d, bound payload %d", small, large)
	const bound = 30
	if large > bound || large != small {
		t.Fatalf("bound-size ingest sent %d statements (small payload %d); want a fixed count <= %d", large, small, bound)
	}
}

// Review round 2 (b): one canonical block order everywhere, equal to the
// SQL lock order (ORDER BY block), and never an empty marketplace.
func TestToolingCanonicalOrderAndMarketplace(t *testing.T) {
	p := &payload{
		PackageManagers: testPackages("complete", allSources("complete")),
		McpServers:      testMCP("complete", allClients("complete")),
		LocalModels:     testModels("not_present", allRuntimes("not_present")),
		IdeExtensions:   testIDE("not_present"),
	}
	blocks, _ := toolingBlocksPresent(p)
	if !sort.StringsAreSorted(blocks) || len(blocks) != 4 {
		t.Fatalf("lock order %v is not the SQL ORDER BY block order", blocks)
	}
	var authOrder []string
	for _, a := range toolingAuthorities(p) {
		if len(authOrder) == 0 || authOrder[len(authOrder)-1] != a.Block {
			authOrder = append(authOrder, a.Block)
		}
	}
	if fmt.Sprint(authOrder) != fmt.Sprint(blocks) {
		t.Fatalf("authority order %v differs from lock order %v", authOrder, blocks)
	}
	var states []string
	for _, st := range toolingStateRows(p, nil) {
		states = append(states, st.Block)
	}
	if fmt.Sprint(states) != fmt.Sprint(blocks) {
		t.Fatalf("state order %v differs from lock order %v", states, blocks)
	}
	for _, e := range []string{"vscode", "vscode_insiders", "cursor", "windsurf", "someday"} {
		if m := ideMarketplace("vscode", e); m == "" {
			t.Fatalf("empty marketplace for %s", e)
		}
	}
	if m := ideMarketplace("vscode", "someday"); m != ideMarketplaceUnknown {
		t.Fatalf("unknown editor marketplace = %q", m)
	}
	if keys := categorytag.Keys(categorytag.Observation{Kind: categorytag.KindIDEExtension, Platform: "macos",
		Identifier: "x.y", Marketplace: ideMarketplaceUnknown}); len(keys) != 0 {
		t.Fatalf("unknown marketplace produced match keys %v", keys)
	}
}
