package handlers

// PAT-2205 contract coverage. This test deliberately drives the PostgreSQL
// projection and HTTP handlers together: an in-memory fixture cannot prove
// tenant predicates, current-entry assessment joins or audited settings.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

type pat2205Seed struct {
	entryKey string
}

func pat2205Fingerprint(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(s[:])
}

func pat2205SeedItem(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, block, unit, entryKind, identityKind, identity, companion, name, version string, attrs map[string]any, ordinal int) pat2205Seed {
	t.Helper()
	// A single inventory payload gives every block item the same received_at.
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Minute)
	var runID string
	if err := pool.QueryRow(ctx, `INSERT INTO software_inventory_runs
		(tenant_id,device_id,platform,received_at,provenance,authoritative_scopes)
		VALUES($1::uuid,$2::uuid,'macos',$3,'backfill_current_snapshot','{}')
		ON CONFLICT(device_id) WHERE provenance='backfill_current_snapshot'
		DO UPDATE SET received_at=EXCLUDED.received_at RETURNING id::text`, tenantID, deviceID, now).Scan(&runID); err != nil {
		t.Fatalf("seed inventory run: %v", err)
	}
	fingerprint := pat2205Fingerprint(identityKind, identity, companion)
	var observationID int64
	if err := pool.QueryRow(ctx, `INSERT INTO software_observations
		(inventory_run_id,tenant_id,device_id,ordinal,platform,observed_name,observed_version,
		 identity_kind,identity_value_normalized,companion_value_normalized,identity_confidence,identity_fingerprint,observed_at)
		VALUES($1::uuid,$2::uuid,$3::uuid,$4,'macos',$5,NULLIF($6,''),$7,$8,$9,'medium',$10,$11)
		RETURNING id`, runID, tenantID, deviceID, ordinal, name, version, identityKind, identity, companion, fingerprint, now).Scan(&observationID); err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	// Current-entry keys are natural-item keys: a version change updates the
	// same projection row and must move assessment authority to the new input.
	entryKey := pat2205Fingerprint(block, unit, entryKind, identity, companion)
	rawAttrs, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("marshal attrs: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tooling_observation_details
		(observation_id,tenant_id,device_id,inventory_run_id,block,unit,entry_kind,entry_key,attributes,observed_at)
		VALUES($1,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9::jsonb,$10)`, observationID, tenantID, deviceID, runID,
		block, unit, entryKind, entryKey, rawAttrs, now); err != nil {
		t.Fatalf("seed tooling detail: %v", err)
	}
	unitStatuses := map[string]string{}
	if unit != "" {
		unitStatuses[unit] = "complete"
	}
	unitJSON, _ := json.Marshal(unitStatuses)
	authority := map[string]string{unit: now.Format(time.RFC3339Nano)}
	authorityJSON, _ := json.Marshal(authority)
	if _, err := pool.Exec(ctx, `INSERT INTO tooling_device_state
		(device_id,tenant_id,block,collection_status,unit_statuses,reported_at,authority)
		VALUES($1::uuid,$2::uuid,$3,'complete',$4::jsonb,$5,$6::jsonb)
		ON CONFLICT(device_id,block) DO UPDATE SET unit_statuses=tooling_device_state.unit_statuses||EXCLUDED.unit_statuses,
		reported_at=GREATEST(tooling_device_state.reported_at,EXCLUDED.reported_at),authority=tooling_device_state.authority||EXCLUDED.authority`,
		deviceID, tenantID, block, unitJSON, now, authorityJSON); err != nil {
		t.Fatalf("seed tooling state: %v", err)
	}
	var installationID string
	if err := pool.QueryRow(ctx, `INSERT INTO software_installations
		(tenant_id,device_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,
		 identity_fingerprint,current_name,current_version,first_seen_at,last_seen_at,latest_observation_id,provenance)
		VALUES($1::uuid,$2::uuid,'macos',$3,$4,$5,$6,$7,NULLIF($8,''),$9,$9,$10,'backfill_current_snapshot')
		ON CONFLICT(device_id,identity_fingerprint) DO UPDATE SET
			current_name=EXCLUDED.current_name,current_version=EXCLUDED.current_version,
			last_seen_at=EXCLUDED.last_seen_at,latest_observation_id=EXCLUDED.latest_observation_id,removed_at=NULL
		RETURNING id::text`, tenantID, deviceID, identityKind, identity, companion, fingerprint, name, version, now, observationID).Scan(&installationID); err != nil {
		t.Fatalf("seed tooling installation: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tooling_current_entries
		(device_id,tenant_id,block,unit,entry_kind,entry_key,observation_id,observed_at,inventory_run_id)
		VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9::uuid)
		ON CONFLICT(device_id,block,entry_key) DO UPDATE SET
			unit=EXCLUDED.unit,entry_kind=EXCLUDED.entry_kind,observation_id=EXCLUDED.observation_id,
			observed_at=EXCLUDED.observed_at,inventory_run_id=EXCLUDED.inventory_run_id`, deviceID, tenantID, block, unit, entryKind, entryKey,
		observationID, now, runID); err != nil {
		t.Fatalf("seed current entry: %v", err)
	}
	if identityKind == "npm_package" {
		var ruleID int64
		if err := pool.QueryRow(ctx, `INSERT INTO software_category_rules
			(identifier_type,identifier_value,qualifier,platform,category_key,subtype_key,state,created_by,published_at)
			VALUES('package',$1,'npm','any','ai_tooling','cli','published','pat2205-test',now())
			ON CONFLICT(identifier_type,platform,qualifier,identifier_value,category_key,subtype_key) WHERE state<>'retired'
			DO UPDATE SET state='published',published_at=COALESCE(software_category_rules.published_at,now()) RETURNING id`, identity).Scan(&ruleID); err != nil {
			t.Fatalf("seed category rule: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO software_category_tags
			(tenant_id,device_id,observation_kind,installation_id,rule_id)
			VALUES($1::uuid,$2::uuid,'package',$3::uuid,$4)
			ON CONFLICT DO NOTHING`, tenantID, deviceID, installationID, ruleID); err != nil {
			t.Fatalf("seed category tag: %v", err)
		}
	}
	return pat2205Seed{entryKey: entryKey}
}

func pat2205Request(t *testing.T, handler http.Handler, tenantID, email, deviceID, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("deviceID", deviceID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestPortalAIToolingContract(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	var statementTriggers, rowTriggers int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE (tgtype & 1)=0)::int,
		count(*) FILTER (WHERE (tgtype & 1)=1)::int
		FROM pg_trigger
		WHERE tgrelid='tooling_current_entries'::regclass
		  AND tgname LIKE 'zzz_trg_tooling_vulnerability_%current_entries_%'`).Scan(&statementTriggers, &rowTriggers); err != nil {
		t.Fatalf("inspect 0210 current-entry triggers: %v", err)
	}
	if statementTriggers != 2 || rowTriggers != 0 {
		t.Fatalf("0210 unlink triggers: statement=%d row=%d, want 2/0", statementTriggers, rowTriggers)
	}
	suffix := time.Now().UTC().Format("150405.000000000")
	tenantA := parSeedTenant(t, ctx, pool, "pat2205-a-"+suffix, "pat2205-a-token-"+suffix, "pat2205-a-hmac-secret-32-bytes!!")
	tenantB := parSeedTenant(t, ctx, pool, "pat2205-b-"+suffix, "pat2205-b-token-"+suffix, "pat2205-b-hmac-secret-32-bytes!!")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM software_category_rules WHERE created_by='pat2205-test' AND identifier_value IN ('@scope/tool','foreign-secret-tool')`)
	})
	devA1 := rrInsertDeviceOS(t, pool, tenantA, "22050000-0000-4000-8000-000000000001", 0, "macOS")
	devA2 := rrInsertDeviceOS(t, pool, tenantA, "22050000-0000-4000-8000-000000000002", 0, "Windows")
	_ = rrInsertDeviceOS(t, pool, tenantA, "22050000-0000-4000-8000-000000000003", 0, "macOS") // no tooling
	devB := rrInsertDeviceOS(t, pool, tenantB, "22050000-0000-4000-8000-000000000004", 0, "Windows")
	email := "pat2205-" + strings.ReplaceAll(suffix, ".", "") + "@example.test"
	if _, err := pool.Exec(ctx, `INSERT INTO portal_users(email,tenant_id,role) VALUES($1,$2::uuid,'admin')`, email, tenantA); err != nil {
		t.Fatalf("seed portal user: %v", err)
	}

	secretAttrs := map[string]any{"manager": "npm", "scope": "global", "version": "1.2.3", "credential": "must-not-leak", "env": map[string]any{"TOKEN": "must-not-leak"}, "url": "https://user:pass@example.test/path?token=must-not-leak"}
	npmA1 := pat2205SeedItem(t, ctx, pool, tenantA, devA1, "package_managers", "npm_global", "package", "npm_package", "@scope/tool", "", "@scope/tool", "1.2.3", secretAttrs, 1)
	_ = pat2205SeedItem(t, ctx, pool, tenantA, devA1, "ide_extensions", "", "extension", "ide_extension", "vendor.extension", "vscode_marketplace", "Vendor Extension", "2.0.0", map[string]any{"family": "vscode", "editor": "vscode", "source": "marketplace", "directory": "/Users/private"}, 2)
	_ = pat2205SeedItem(t, ctx, pool, tenantA, devA1, "local_models", "ollama", "model", "local_model", "llama3:latest", "ollama", "llama3:latest", "", map[string]any{"runtime": "ollama", "tag": "latest", "format": "gguf", "size_bytes": 42, "store_path": "/private/models"}, 3)
	_ = pat2205SeedItem(t, ctx, pool, tenantA, devA1, "local_models", "ollama", "runtime_installation", "local_model_runtime", "ollama", "ollama", "Ollama", "0.5.0", map[string]any{"runtime": "ollama", "scope": "machine", "kind": "binary", "path": "/usr/local/bin/ollama", "version": "0.5.0"}, 4)
	mcpA1 := pat2205SeedItem(t, ctx, pool, tenantA, devA1, "mcp_servers", "claude_desktop", "server", "mcp_server", "filesystem", "claude_desktop", "filesystem", "", map[string]any{"client": "claude_desktop", "scope": "user", "transport": "stdio", "runner": "npx", "package": "@modelcontextprotocol/server-filesystem", "package_status": "extracted", "host": "example.test", "args": []string{"--secret"}, "config_path": "/Users/private/mcp.json"}, 5)
	_ = pat2205SeedItem(t, ctx, pool, tenantA, devA2, "package_managers", "npm_global", "package", "npm_package", "@scope/tool", "", "@scope/tool", "1.2.3", map[string]any{"manager": "npm", "scope": "global", "version": "1.2.3"}, 1)
	_ = pat2205SeedItem(t, ctx, pool, tenantB, devB, "package_managers", "npm_global", "package", "npm_package", "foreign-secret-tool", "", "Foreign Secret Tool", "9.9.9", secretAttrs, 1)

	// Exact current-entry assessment and advisory provenance.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tooling_advisories(source,advisory_id,canonical_cve_id,aliases,summary,severity,raw_document,synced_at)
		VALUES('osv',$1,'CVE-2026-2205',ARRAY['CVE-2026-2205'],'contract advisory','HIGH','{}',now())
		ON CONFLICT(source,advisory_id) DO UPDATE SET synced_at=now()`, "OSV-PAT2205-"+suffix); err != nil {
		t.Fatalf("seed advisory: %v", err)
	}
	var assessmentID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tooling_vulnerability_assessments
		(tenant_id,device_id,subject_kind,ecosystem,package_name,identity_value,companion,version,state,reason,
		 finding_count,highest_severity,observations,current_entry_keys,input_observed_at,assessed_at,active)
		VALUES($1::uuid,$2::uuid,'package','npm','@scope/tool','@scope/tool','npm','1.2.3','assessed',NULL,
		 1,'HIGH','[]',$3::text[],now(),now(),true)
		ON CONFLICT(device_id,subject_kind,identity_value,companion,version) DO UPDATE SET
		 state='assessed',reason=NULL,finding_count=1,highest_severity='HIGH',current_entry_keys=EXCLUDED.current_entry_keys,assessed_at=now(),active=true
		RETURNING id`, tenantA, devA1, []string{npmA1.entryKey}).Scan(&assessmentID); err != nil {
		t.Fatalf("seed assessment: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tooling_vulnerability_findings
		(assessment_id,source,advisory_id,canonical_cve_id,severity,score)
		VALUES($1,'osv',$2,'CVE-2026-2205','HIGH',8.1) ON CONFLICT DO NOTHING`, assessmentID, "OSV-PAT2205-"+suffix); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	// Unresolved MCP rows are assessed by the scheduled matcher, not the
	// direct-entry trigger. Its stored entry-key set is authoritative.
	if _, err := pool.Exec(ctx, `INSERT INTO tooling_vulnerability_assessments
		(tenant_id,device_id,subject_kind,identity_value,companion,version,state,reason,
		 observations,current_entry_keys,input_observed_at,active)
		VALUES($1::uuid,$2::uuid,'mcp_server','filesystem','claude_desktop','unknown','not_assessed',
		 'package_unresolved','[]',$3::text[],now(),true)
		ON CONFLICT(device_id,subject_kind,identity_value,companion,version) DO UPDATE SET
		 state='not_assessed',reason='package_unresolved',current_entry_keys=EXCLUDED.current_entry_keys,active=true`, tenantA, devA1, []string{mcpA1.entryKey}); err != nil {
		t.Fatalf("seed MCP assessment: %v", err)
	}

	// Tagged-product membership is bounded but its distinct count is exact,
	// and the generated target must be accepted by the write validator.
	products, tooLarge, err := fetchTaggedProducts(ctx, pool, tenantA, "ai_tooling", "")
	if err != nil || tooLarge {
		t.Fatalf("fetch tagged products: tooLarge=%v err=%v", tooLarge, err)
	}
	var tagged *portalTaggedProduct
	for i := range products {
		if products[i].Identifier == "@scope/tool" {
			tagged = &products[i]
			break
		}
	}
	if tagged == nil || tagged.DeviceCount != 2 || len(tagged.Devices) != 2 || tagged.DevicesTruncated || tagged.ApprovalTarget == nil {
		t.Fatalf("tagged membership/target = %+v", tagged)
	}
	if _, itemErr := normalizeApprovalItem(*tagged.ApprovalTarget); itemErr != nil {
		t.Fatalf("approval_target does not round-trip: %+v", itemErr)
	}

	summary, err := report.FetchToolingSummary(ctx, pool, tenantA)
	if err != nil || summary.DevicesWithTooling != 2 {
		t.Fatalf("devices_with_tooling=%d err=%v, want exact 2 of 3", summary.DevicesWithTooling, err)
	}

	itemsRec := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA1, "/v1/portal/ai-tooling/devices/"+devA1+"/items?limit=100")
	if itemsRec.Code != http.StatusOK {
		t.Fatalf("items status=%d body=%s", itemsRec.Code, itemsRec.Body.String())
	}
	var page report.ToolingEvidencePage
	if err := json.Unmarshal(itemsRec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if page.Total != 5 || len(page.Items) != 5 {
		t.Fatalf("items total=%d len=%d, want five PAT-2022 item types: %+v", page.Total, len(page.Items), page.Items)
	}
	joined, mcpJoined := false, false
	for _, item := range page.Items {
		if item.Identity == "@scope/tool" && len(item.Assessments) == 1 && len(item.Assessments[0].Advisories) == 1 && item.Assessments[0].Advisories[0].CanonicalCVEID != nil {
			joined = true
		}
		if item.IdentityKind == "mcp_server" && len(item.Assessments) == 1 && item.Assessments[0].SubjectKind == "mcp_server" && item.Assessments[0].State == "not_assessed" {
			mcpJoined = true
		}
	}
	if !joined || !mcpJoined {
		t.Fatalf("exact package/MCP assessment join absent: package=%v mcp=%v items=%+v", joined, mcpJoined, page.Items)
	}
	for _, forbidden := range []string{"must-not-leak", "credential", "config_path", "store_path", "directory", "args", "env", "?token="} {
		if strings.Contains(itemsRec.Body.String(), forbidden) {
			t.Errorf("response leaked forbidden field/value %q: %s", forbidden, itemsRec.Body.String())
		}
	}
	foreignRec := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devB, "/v1/portal/ai-tooling/devices/"+devB+"/items")
	if foreignRec.Code != http.StatusNotFound || strings.Contains(foreignRec.Body.String(), "Foreign") {
		t.Fatalf("foreign device did not fail closed: status=%d body=%s", foreignRec.Code, foreignRec.Body.String())
	}
	// A natural entry key is shared across devices. Assessment attachment must
	// include device identity and never leak A1's advisory onto A2.
	secondDeviceRec := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA2, "/v1/portal/ai-tooling/devices/"+devA2+"/items")
	if secondDeviceRec.Code != http.StatusOK || strings.Contains(secondDeviceRec.Body.String(), "CVE-2026-2205") {
		t.Fatalf("cross-device assessment leak: status=%d body=%s", secondDeviceRec.Code, secondDeviceRec.Body.String())
	}

	// JSON and CSV are projections of the same builder, and the registered
	// PDF report renders that builder rather than re-querying a second model.
	rep, err := report.BuildToolingEvidence(ctx, pool, tenantA, time.Now().UTC())
	if err != nil || len(rep.Items) != 6 { // five on A1, one on A2
		t.Fatalf("build evidence: items=%d err=%v", len(rep.Items), err)
	}
	csvRec := pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA1, "/v1/portal/ai-tooling/devices/"+devA1+"/items?format=csv")
	if csvRec.Code != http.StatusOK || strings.Count(strings.TrimSpace(csvRec.Body.String()), "\n") != 5 {
		t.Fatalf("CSV did not cover the same five item rows: status=%d body=%s", csvRec.Code, csvRec.Body.String())
	}
	if def, ok := report.LookupReportDefinition("ai-tooling-evidence"); !ok || !def.CustomerFacing {
		t.Fatalf("AI evidence report is not registered: %+v ok=%v", def, ok)
	}
	if pdf, err := report.RenderToolingEvidencePDF(rep); err != nil || len(pdf) < 1000 {
		t.Fatalf("render evidence PDF: bytes=%d err=%v", len(pdf), err)
	}

	// Replacing a current entry retires the old version's advisory join and
	// attaches the stable item key to the new pending version. Removing it
	// retires that join too; neither stale version may survive in portal JSON.
	_ = pat2205SeedItem(t, ctx, pool, tenantA, devA1, "package_managers", "npm_global", "package", "npm_package", "@scope/tool", "", "@scope/tool", "1.2.4", map[string]any{"manager": "npm", "scope": "global", "version": "1.2.4"}, 6)
	itemsRec = pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA1, "/v1/portal/ai-tooling/devices/"+devA1+"/items?limit=100")
	if itemsRec.Code != http.StatusOK || strings.Contains(itemsRec.Body.String(), "CVE-2026-2205") {
		t.Fatalf("old version advisory survived replacement: status=%d body=%s", itemsRec.Code, itemsRec.Body.String())
	}
	if !strings.Contains(itemsRec.Body.String(), `"version":"1.2.4"`) || !strings.Contains(itemsRec.Body.String(), `"state":"pending"`) {
		t.Fatalf("new current version lacks pending exact assessment: %s", itemsRec.Body.String())
	}
	var oldActive, newActive bool
	var newKeys []string
	if err := pool.QueryRow(ctx, `SELECT
		COALESCE(bool_or(active) FILTER (WHERE version='1.2.3'),false),
		COALESCE(bool_or(active) FILTER (WHERE version='1.2.4'),false)
		FROM tooling_vulnerability_assessments
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND identity_value='@scope/tool'`, tenantA, devA1).Scan(&oldActive, &newActive); err != nil {
		t.Fatalf("read version assessment authority: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT current_entry_keys FROM tooling_vulnerability_assessments
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND identity_value='@scope/tool' AND version='1.2.4'`, tenantA, devA1).Scan(&newKeys); err != nil {
		t.Fatalf("read new version entry keys: %v", err)
	}
	if oldActive || !newActive || len(newKeys) != 1 || newKeys[0] != npmA1.entryKey {
		t.Fatalf("version authority old_active=%v new_active=%v keys=%v", oldActive, newActive, newKeys)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tooling_current_entries
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND block='package_managers' AND entry_key=$3`, tenantA, devA1, npmA1.entryKey); err != nil {
		t.Fatalf("remove current version: %v", err)
	}
	itemsRec = pat2205Request(t, PortalToolingDeviceItemsHandler(pool), tenantA, email, devA1, "/v1/portal/ai-tooling/devices/"+devA1+"/items?limit=100")
	if itemsRec.Code != http.StatusOK || strings.Contains(itemsRec.Body.String(), "@scope/tool") {
		t.Fatalf("removed current item survived portal projection: status=%d body=%s", itemsRec.Code, itemsRec.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(bool_or(active),false) FROM tooling_vulnerability_assessments
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND identity_value='@scope/tool'`, tenantA, devA1).Scan(&newActive); err != nil || newActive {
		t.Fatalf("removed assessment remained active=%v err=%v", newActive, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tooling_current_entries
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND block='mcp_servers' AND entry_key=$3`, tenantA, devA1, mcpA1.entryKey); err != nil {
		t.Fatalf("remove current MCP item: %v", err)
	}
	var mcpActive bool
	var mcpKeys []string
	if err := pool.QueryRow(ctx, `SELECT active,current_entry_keys FROM tooling_vulnerability_assessments
		WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND subject_kind='mcp_server' AND identity_value='filesystem'`, tenantA, devA1).Scan(&mcpActive, &mcpKeys); err != nil {
		t.Fatalf("read removed MCP authority: %v", err)
	}
	if mcpActive || len(mcpKeys) != 0 {
		t.Fatalf("removed MCP assessment remained authoritative: active=%v keys=%v", mcpActive, mcpKeys)
	}

	// The AI opt-in is audited and leaves the general-software preference and
	// both independent delivery cursors untouched.
	oldSoftwareCursor := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	oldAICursor := oldSoftwareCursor.Add(time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_software_notification_settings
		(tenant_id,new_software_enabled,ai_tooling_notifications_enabled,new_software_notified_through,ai_tooling_notified_through)
		VALUES($1::uuid,false,false,$2,$3) ON CONFLICT(tenant_id) DO UPDATE SET
		new_software_enabled=false,ai_tooling_notifications_enabled=false,new_software_notified_through=$2,ai_tooling_notified_through=$3`, tenantA, oldSoftwareCursor, oldAICursor); err != nil {
		t.Fatalf("seed notification setting: %v", err)
	}
	putReq := httptest.NewRequest(http.MethodPut, "/v1/portal/software-notifications", strings.NewReader(`{"ai_tooling_notifications_enabled":true}`))
	putReq = putReq.WithContext(portalauth.WithIdentity(putReq.Context(), portalauth.Identity{Email: email, TenantID: tenantA}))
	putRec := httptest.NewRecorder()
	PortalSoftwareNotificationsPutHandler(pool).ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("AI notification PUT status=%d body=%s", putRec.Code, putRec.Body.String())
	}
	var generalEnabled, aiEnabled bool
	var softwareCursor, aiCursor time.Time
	if err := pool.QueryRow(ctx, `SELECT new_software_enabled,ai_tooling_notifications_enabled,
		new_software_notified_through,ai_tooling_notified_through FROM tenant_software_notification_settings WHERE tenant_id=$1::uuid`, tenantA).
		Scan(&generalEnabled, &aiEnabled, &softwareCursor, &aiCursor); err != nil {
		t.Fatalf("read notification setting: %v", err)
	}
	if generalEnabled || !aiEnabled || !softwareCursor.Equal(oldSoftwareCursor) || !aiCursor.Equal(oldAICursor) {
		t.Fatalf("AI toggle changed unrelated state: general=%v ai=%v software_cursor=%v ai_cursor=%v", generalEnabled, aiEnabled, softwareCursor, aiCursor)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM ai_tooling_notification_changes
		WHERE tenant_id=$1::uuid AND old_enabled=false AND new_enabled=true AND changed_by=$2`, tenantA, email).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("AI preference audit count=%d err=%v", auditCount, err)
	}
}
