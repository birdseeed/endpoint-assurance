//go:build integration

package integration

// PAT-2089 / PAT-2091: provenance of tenant policy rows (operator | portal).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/softwaregov"
)

func internalDo(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, env.internalSrv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func blocklistStrings(entries []agentconfig.ExtensionBlocklistEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Browser+"/"+e.ExtensionID)
	}
	sort.Strings(out)
	return out
}

type extensionPoliciesList struct {
	AppControlEnabled bool `json:"app_control_enabled"`
	Entries           []struct {
		ID          int64  `json:"id"`
		Browser     string `json:"browser"`
		ExtensionID string `json:"extension_id"`
		Policy      string `json:"policy"`
		Source      string `json:"source"`
	} `json:"entries"`
	PortalSuggestions []struct {
		ID          int64  `json:"id"`
		Browser     string `json:"browser"`
		ExtensionID string `json:"extension_id"`
		Policy      string `json:"policy"`
		Source      string `json:"source"`
	} `json:"portal_suggestions"`
}

func listExtensionPolicies(t *testing.T, tenantID string) extensionPoliciesList {
	t.Helper()
	status, b := internalDo(t, http.MethodGet, "/admin/tenants/"+tenantID+"/extension-policies", "")
	if status != http.StatusOK {
		t.Fatalf("GET extension-policies = %d: %s", status, b)
	}
	var out extensionPoliciesList
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode extension-policies: %v: %s", err, b)
	}
	return out
}

// PAT-2089: a customer marks extensions Unapproved in the portal while App
// Control is off. The operator then switches App Control on (the managed
// tier). The signed blocklist carries the operator's own block and nothing
// the customer set; the operator sees the customer's rows as suggestions.
func TestPortalUnapprovedExtensionsStayOutOfBlocklistWhenAppControlSwitchedOn(t *testing.T) {
	at := newApprovalTenant(t, "acswitch", false)
	token, secret := approvalAgentDevice(t, at.tenantID)
	const portalChrome = "portalchromeunapprovedabcdefghij"
	const portalAny = "portalanyunapprovedabcdefghijklm"
	const operatorExt = "operatorsblockbeforeswitchabcdef"

	mustApprove(t, at.adminToken, approvalBody("unapproved", "Not on our list",
		extItem("chrome", portalChrome), extItem("any", portalAny)))
	// The operator's own block, as the admin API writes it (default source).
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', $2, 'Operator blocked', 'unapproved')`, at.tenantID, operatorExt); err != nil {
		t.Fatalf("seed operator block: %v", err)
	}
	if before := signedAgentAppControl(t, token, secret); before.Enabled || len(before.ExtensionBlocklist) != 0 {
		t.Fatalf("assurance tenant app_control = %+v, want disabled and empty", before)
	}

	status, b := internalDo(t, http.MethodPut, "/admin/tenant-tier/"+at.tenantID, `{"subscription_tier":"managed","updated_by":"pat2089-test"}`)
	if status != http.StatusOK {
		t.Fatalf("switch to managed = %d: %s", status, b)
	}

	operatorOnly := []string{"chrome/" + operatorExt}
	after := signedAgentAppControl(t, token, secret)
	if !after.Enabled {
		t.Fatal("app_control.enabled is false after switching to managed")
	}
	if got := blocklistStrings(after.ExtensionBlocklist); fmt.Sprint(got) != fmt.Sprint(operatorOnly) {
		t.Fatalf("signed blocklist after App Control on = %v, want only the operator's %v", got, operatorOnly)
	}

	list := listExtensionPolicies(t, at.tenantID)
	if !list.AppControlEnabled {
		t.Fatal("extension-policies app_control_enabled = false")
	}
	sources := map[string]string{}
	for _, e := range list.Entries {
		sources[e.Browser+"/"+e.ExtensionID] = e.Source
	}
	for key, want := range map[string]string{
		"chrome/" + portalChrome: "portal", "any/" + portalAny: "portal", "chrome/" + operatorExt: "operator",
	} {
		if sources[key] != want {
			t.Errorf("entry %s source = %q, want %q", key, sources[key], want)
		}
	}
	var suggested []string
	for _, s := range list.PortalSuggestions {
		if s.Source != "portal" || s.Policy != "unapproved" {
			t.Errorf("suggestion %+v", s)
		}
		suggested = append(suggested, s.Browser+"/"+s.ExtensionID)
	}
	sort.Strings(suggested)
	if want := []string{"any/" + portalAny, "chrome/" + portalChrome}; fmt.Sprint(suggested) != fmt.Sprint(want) {
		t.Fatalf("portal_suggestions = %v, want %v", suggested, want)
	}

	t.Run("the customer's own row is not an operator block", func(t *testing.T) {
		mustApprove(t, at.adminToken, approvalBody("approved", "", extItem("chrome", portalChrome)))
		if p, _ := extPolicy(t, at.tenantID, "chrome", portalChrome); p != "approved" {
			t.Fatalf("portal chrome row = %q, want approved", p)
		}
	})

	t.Run("an operator who adopts a suggestion enforces it", func(t *testing.T) {
		var entryID int64
		for _, s := range list.PortalSuggestions {
			if s.ExtensionID == portalAny {
				entryID = s.ID
			}
		}
		status, b := internalDo(t, http.MethodPut, fmt.Sprintf("/admin/tenants/%s/extension-policies/%d", at.tenantID, entryID),
			`{"policy":"unapproved","notes":"adopted"}`)
		if status != http.StatusNoContent {
			t.Fatalf("operator PUT = %d: %s", status, b)
		}
		want := []string{"chrome/" + operatorExt, "chrome/" + portalAny, "edge/" + portalAny, "firefox/" + portalAny}
		sort.Strings(want)
		if got := blocklistStrings(signedAgentAppControl(t, token, secret).ExtensionBlocklist); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("blocklist after adoption = %v, want %v", got, want)
		}
		// The adopted row is the operator's now; the customer's approved
		// chrome row is still theirs and still listed.
		left := listExtensionPolicies(t, at.tenantID).PortalSuggestions
		if len(left) != 1 || left[0].ExtensionID != portalChrome || left[0].Policy != "approved" {
			t.Fatalf("portal_suggestions after adoption = %+v, want only the customer's approved chrome row", left)
		}
	})
}

// migrationBody reads a forward migration with its BEGIN/COMMIT removed, so
// a test can replay it inside a transaction it rolls back.
func migrationBody(t *testing.T, file string) string {
	t.Helper()
	forward, err := os.ReadFile(filepath.Join("..", "migrations", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var body strings.Builder
	for _, line := range strings.Split(string(forward), "\n") {
		switch strings.TrimSpace(line) {
		case "BEGIN;", "COMMIT;":
			continue
		}
		body.WriteString(line + "\n")
	}
	return body.String()
}

// PAT-2089 backfill: a row is 'portal' only when a portal decision for the
// same product set its current state and nothing has written it since.
// Replayed inside a rolled-back transaction on the pre-0200 table shape.
func TestExtensionPolicySourceBackfill(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2089-backfill")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `ALTER TABLE tenant_extension_policies DROP COLUMN source`); err != nil {
		t.Fatalf("return tenant_extension_policies to its pre-0200 shape: %v", err)
	}
	seed := func(browser, extID, policy, updatedAt string) {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, policy, updated_at)
			VALUES ($1::uuid, $2, $3, $4, now() + $5::interval)`, tenantID, browser, extID, policy, updatedAt); err != nil {
			t.Fatalf("seed %s: %v", extID, err)
		}
	}
	decide := func(browser, extID, prev, next string) {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO software_approval_decisions
			    (tenant_id, batch_id, product_type, product_key, identifier, browser, previous_state, new_state, actor_email)
			VALUES ($1::uuid, gen_random_uuid(), 'browser_extension', 'browser_extension:' || $2 || ':' || $3, $3, $2, $4, $5,
			        'customer@backfill.example')`, tenantID, browser, extID, prev, next); err != nil {
			t.Fatalf("seed decision %s: %v", extID, err)
		}
	}
	// Written by the portal (same transaction time as the decision).
	seed("chrome", "portalwritten", "unapproved", "0")
	decide("chrome", "portalwritten", "unreviewed", "unapproved")
	// Never touched by the portal.
	seed("chrome", "operatorwritten", "unapproved", "0")
	// Set by the portal, then edited by the operator afterwards.
	seed("edge", "operatoreditedlater", "unapproved", "1 second")
	decide("edge", "operatoreditedlater", "unreviewed", "unapproved")
	// An operator transaction can start earlier yet take the lock and write
	// later. Its transaction timestamp must not match a newer portal audit.
	seed("edge", "operatorstartedearlier", "unapproved", "-1 second")
	decide("edge", "operatorstartedearlier", "unreviewed", "unapproved")
	// A portal decision whose state is not the row's current one.
	seed("firefox", "statemismatch", "unapproved", "0")
	decide("firefox", "statemismatch", "unreviewed", "approved")
	// A decision for the same extension on another browser.
	seed("any", "otherbrowser", "unapproved", "0")
	decide("chrome", "otherbrowser", "unreviewed", "unapproved")

	if _, err := tx.Exec(ctx, migrationBody(t, "0200_extension_policy_source.sql")); err != nil {
		t.Fatalf("apply 0200: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT extension_id, source FROM tenant_extension_policies WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	got := map[string]string{}
	for rows.Next() {
		var ext, src string
		if err := rows.Scan(&ext, &src); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[ext] = src
	}
	rows.Close()
	want := map[string]string{
		"portalwritten": "portal", "operatorwritten": "operator", "operatoreditedlater": "operator",
		"statemismatch": "operator", "otherbrowser": "operator", "operatorstartedearlier": "operator",
	}
	for ext, src := range want {
		if got[ext] != src {
			t.Errorf("%s source = %q, want %q", ext, got[ext], src)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_extension_policies SET source = 'customer' WHERE tenant_id = $1::uuid`, tenantID); err == nil {
		t.Error("source CHECK accepted 'customer'")
	}
}

// windowsApp is a Windows application approval item.
func windowsApp(identifier string) string {
	return fmt.Sprintf(`{"type":"application","platform":"windows","identifier":%q}`, identifier)
}

// reportWindowsApp records that a Windows device in tenantID reports an app
// with this winget identifier and display name.
func reportWindowsApp(t *testing.T, tenantID, identifier, name string) {
	t.Helper()
	ctx := context.Background()
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'Windows', '11') RETURNING id::text`,
		tenantID, "WIN-"+randomHex(4), "win-"+randomHex(4)).Scan(&deviceID); err != nil {
		t.Fatalf("seed windows device: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, identifier_kind, version)
		VALUES ($1::uuid, $2, $3, 'winget', '6.0')`, deviceID, name, identifier); err != nil {
		t.Fatalf("seed windows app: %v", err)
	}
}

// PAT-2091: the customer approves a Windows app by its curated alias before
// any device reports it, while the operator has it mandatory by name. Once
// the app appears, every resolver-backed surface shows it mandatory, not the
// customer's approval, and the portal refuses further changes to it.
func TestPreInstallPortalApprovalCannotShadowNameKeyedMandatory(t *testing.T) {
	at := newApprovalTenant(t, "preinstall", false)
	ctx := context.Background()
	suffix := randomHex(3)
	identifier := "PAT2091Zoom" + suffix + ".Zoom"
	name := "Zoom Workplace " + suffix
	seedWindowsAlias(t, identifier)
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'any', 'mandatory', 'report_deploy')`, at.tenantID, name); err != nil {
		t.Fatalf("seed name-keyed mandatory: %v", err)
	}

	// Nothing reports the app yet, so the portal cannot know its name and
	// accepts the approval.
	mustApprove(t, at.adminToken, approvalBody("approved", "Standard meeting tool", windowsApp(identifier)))

	reportWindowsApp(t, at.tenantID, identifier, name)

	policies, err := softwaregov.LoadPolicies(ctx, env.pool, at.tenantID)
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	if got := policies.ResolveApp("", identifier, "winget", name, "Windows"); got != "mandatory" {
		t.Fatalf("resolved state once the app appears = %q, want mandatory (the portal approval shadowed the operator's row)", got)
	}

	// The portal now sees the reported name and refuses to touch the app.
	out := refused(t, at.adminToken, approvalBody("unapproved", "", windowsApp(identifier)), http.StatusConflict, "refused")
	if len(out.Items) != 1 || out.Items[0].Code != "operator_managed" {
		t.Fatalf("items = %+v", out.Items)
	}
	var source string
	if err := env.pool.QueryRow(ctx, `
		SELECT source FROM tenant_app_policies WHERE tenant_id = $1::uuid AND bundle_id = $2`,
		at.tenantID, identifier).Scan(&source); err != nil || source != "portal" {
		t.Fatalf("portal row source = %q err %v, want portal", source, err)
	}
}

// PAT-2091: the portal's mandatory check reads every observed identity for
// the identifier. It used to stop at 200 distinct combinations, so a tenant
// whose devices report many names for one identifier could hide the one the
// mandatory row is keyed on.
func TestPortalMandatoryCheckReadsEveryObservedName(t *testing.T) {
	at := newApprovalTenant(t, "manynames", false)
	ctx := context.Background()
	suffix := randomHex(3)
	identifier := "PAT2091Many" + suffix + ".Tool"
	const mandatoryName = "zzzz mandatory tool"
	seedWindowsAlias(t, identifier)
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'windows', 'mandatory', 'report_deploy')`, at.tenantID, mandatoryName); err != nil {
		t.Fatalf("seed mandatory: %v", err)
	}
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'Windows', '11') RETURNING id::text`,
		at.tenantID, "MANY-"+randomHex(4), "many-"+randomHex(4)).Scan(&deviceID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// 300 names that match nothing, one per version (device_apps is unique
	// on device, identifier and version), and the mandatory name, which
	// sorts last.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, identifier_kind, version)
		SELECT $1::uuid, 'Tool variant ' || lpad(g::text, 3, '0'), $2, 'winget', '1.' || g
		FROM generate_series(1, 300) g
		UNION ALL
		SELECT $1::uuid, $3, $2, 'winget', '2.0'`, deviceID, identifier, mandatoryName); err != nil {
		t.Fatalf("seed observed names: %v", err)
	}
	out := refused(t, at.adminToken, approvalBody("approved", "", windowsApp(identifier)), http.StatusConflict, "refused")
	if len(out.Items) != 1 || out.Items[0].Code != "operator_managed" {
		t.Fatalf("items = %+v", out.Items)
	}
	if n := countRows(t, `SELECT COUNT(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid AND bundle_id = $2`, at.tenantID, identifier); n != 0 {
		t.Fatalf("refused approval wrote %d rows", n)
	}
}

// PAT-2091 backfill, the application twin of TestExtensionPolicySourceBackfill.
func TestAppPolicySourceBackfill(t *testing.T) {
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2091-backfill")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `ALTER TABLE tenant_app_policies DROP COLUMN source`); err != nil {
		t.Fatalf("return tenant_app_policies to its pre-0201 shape: %v", err)
	}
	seed := func(teamID, bundleID, name, platform, policy, updatedAt string) {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, name, platform, policy, enforcement_tier, updated_at)
			VALUES ($1::uuid, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), $5, $6, 'report_deploy', now() + $7::interval)`,
			tenantID, teamID, bundleID, name, platform, policy, updatedAt); err != nil {
			t.Fatalf("seed %s%s: %v", bundleID, name, err)
		}
	}
	decide := func(platform, identifier, teamID, next string) {
		t.Helper()
		key := "application:" + platform + ":" + strings.ToLower(identifier)
		if teamID != "" {
			key += ":" + teamID
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO software_approval_decisions
			    (tenant_id, batch_id, product_type, product_key, platform, identifier, team_id, previous_state, new_state, actor_email)
			VALUES ($1::uuid, gen_random_uuid(), 'application', $2, $3, $4, NULLIF($5, ''), 'unreviewed', $6,
			        'customer@backfill.example')`, tenantID, key, platform, identifier, teamID, next); err != nil {
			t.Fatalf("seed decision %s: %v", identifier, err)
		}
	}
	seed("TEAMBACK01", "com.Example.Portal", "", "macos", "approved", "0")
	decide("macos", "com.Example.Portal", "TEAMBACK01", "approved")
	seed("", "Vendor.Ignored", "", "windows", "unmanaged", "0")
	decide("windows", "Vendor.Ignored", "", "ignored")
	seed("", "com.example.operator", "", "macos", "unapproved", "0")
	seed("", "com.example.edited", "", "macos", "approved", "1 second")
	decide("macos", "com.example.edited", "", "approved")
	seed("", "com.example.earliertransaction", "", "macos", "approved", "-1 second")
	decide("macos", "com.example.earliertransaction", "", "approved")
	seed("", "", "Named Tool", "any", "mandatory", "0")
	seed("", "com.example.otherplatform", "", "windows", "approved", "0")
	decide("macos", "com.example.otherplatform", "", "approved")

	if _, err := tx.Exec(ctx, migrationBody(t, "0201_app_policy_source.sql")); err != nil {
		t.Fatalf("apply 0201: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT COALESCE(bundle_id, name), source FROM tenant_app_policies WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	got := map[string]string{}
	for rows.Next() {
		var ident, src string
		if err := rows.Scan(&ident, &src); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[ident] = src
	}
	rows.Close()
	want := map[string]string{
		"com.Example.Portal": "portal", "Vendor.Ignored": "portal", "com.example.operator": "operator",
		"com.example.edited": "operator", "Named Tool": "operator", "com.example.otherplatform": "operator",
		"com.example.earliertransaction": "operator",
	}
	for ident, src := range want {
		if got[ident] != src {
			t.Errorf("%s source = %q, want %q", ident, got[ident], src)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_app_policies SET source = 'customer' WHERE tenant_id = $1::uuid`, tenantID); err == nil {
		t.Error("source CHECK accepted 'customer'")
	}
}
