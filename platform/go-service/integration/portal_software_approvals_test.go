//go:build integration

package integration

// PAT-2007: customer portal software approval writes, portal roles, the
// decision audit and history, and the guarantee that no portal decision
// reaches an agent as something to act on.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/softwaregov"
)

type approvalTenant struct {
	tenantID    string
	bearerToken string
	hmacSecret  []byte
	adminEmail  string
	adminToken  string
	viewerEmail string
	viewerToken string
}

type portalUserResp struct {
	Email    string `json:"email"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// postPortalUser calls POST /admin/portal-users with a raw body.
func postPortalUser(t *testing.T, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(env.internalSrv.URL+"/admin/portal-users", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/portal-users: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func mapPortalUserWithRole(t *testing.T, email, tenantID, role string) portalUserResp {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"tenant_id":%q}`, email, tenantID)
	if role != "" {
		body = fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":%q}`, email, tenantID, role)
	}
	status, b := postPortalUser(t, body)
	if status != http.StatusCreated {
		t.Fatalf("POST /admin/portal-users(%s) = %d: %s", email, status, b)
	}
	var out portalUserResp
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode portal user: %v", err)
	}
	return out
}

func newApprovalTenant(t *testing.T, label string, appControl bool) *approvalTenant {
	t.Helper()
	suffix := randomHex(4)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2007-"+label+"-"+suffix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if appControl {
		if _, err := env.pool.Exec(context.Background(),
			`UPDATE tenants SET app_control_enabled = TRUE WHERE id = $1::uuid`, tenantID); err != nil {
			t.Fatalf("enable app control: %v", err)
		}
	}
	at := &approvalTenant{
		tenantID:    tenantID,
		adminEmail:  "admin-" + label + "-" + suffix + "@approvals.example",
		viewerEmail: "viewer-" + label + "-" + suffix + "@approvals.example",
	}
	if got := mapPortalUserWithRole(t, at.adminEmail, tenantID, "admin"); got.Role != "admin" {
		t.Fatalf("admin mapping role = %q", got.Role)
	}
	if got := mapPortalUserWithRole(t, at.viewerEmail, tenantID, ""); got.Role != "viewer" {
		t.Fatalf("new portal user without role = %q, want viewer", got.Role)
	}
	at.adminToken = env.idp.token(t, at.adminEmail)
	at.viewerToken = env.idp.token(t, at.viewerEmail)
	return at
}

func putApprovals(t *testing.T, token, body string) (int, []byte) {
	t.Helper()
	resp := portalDo(t, http.MethodPut, "/v1/portal/software-approvals", token, strings.NewReader(body))
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

type approvalWriteOut struct {
	BatchID      string `json:"batch_id"`
	State        string `json:"state"`
	ChangedCount int    `json:"changed_count"`
	WarningCount int    `json:"warning_count"`
	Results      []struct {
		Index            int    `json:"index"`
		Type             string `json:"type"`
		ProductKey       string `json:"product_key"`
		PreviousState    string `json:"previous_state"`
		NewState         string `json:"new_state"`
		Changed          bool   `json:"changed"`
		ProtectedWarning bool   `json:"protected_warning"`
		Protected        *struct {
			Category    string `json:"category"`
			ProductName string `json:"product_name"`
		} `json:"protected"`
	} `json:"results"`
}

type approvalErrorOut struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Items   []struct {
		Index int    `json:"index"`
		Code  string `json:"code"`
	} `json:"items"`
}

// mustApprove PUTs an approval and then does what the woken runner does
// straight after (PAT-2095): raise the marked alerts the write queued. Use
// putApprovals to observe the write on its own.
func mustApprove(t *testing.T, token, body string) approvalWriteOut {
	t.Helper()
	status, b := putApprovals(t, token, body)
	if status != http.StatusOK {
		t.Fatalf("PUT software-approvals = %d, want 200: %s", status, b)
	}
	var out approvalWriteOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode write response: %v: %s", err, b)
	}
	drainUnapprovedRaises(t)
	return out
}

// drainUnapprovedRaises runs the runner's raise step (PAT-2095 moved the
// marked alert raise off the request path) without sending any email.
func drainUnapprovedRaises(t *testing.T) {
	t.Helper()
	if err := softwaregov.RaiseUnraised(context.Background(), env.pool, time.Now()); err != nil {
		t.Fatalf("raise queued unapproved alerts: %v", err)
	}
}

func refused(t *testing.T, token, body string, wantStatus int, wantCode string) approvalErrorOut {
	t.Helper()
	status, b := putApprovals(t, token, body)
	if status != wantStatus {
		t.Fatalf("PUT software-approvals = %d, want %d: %s", status, wantStatus, b)
	}
	var out approvalErrorOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode error response: %v: %s", err, b)
	}
	if wantCode != "" && out.Error != wantCode {
		t.Fatalf("error code = %q, want %q (%s)", out.Error, wantCode, out.Message)
	}
	return out
}

func macApp(bundle, team string) string {
	return fmt.Sprintf(`{"type":"application","platform":"macos","identifier":%q,"team_id":%q}`, bundle, team)
}

var approvalEvidenceDevices = map[string]string{}

// seen records inventory evidence that tenantID has observed this macOS
// application item's bundle ID signed by its Team ID (a device_apps row), as
// the portal requires before it accepts a client-supplied Team ID, and
// returns the item unchanged.
func seen(t *testing.T, tenantID, item string) string {
	t.Helper()
	var it struct {
		Identifier string `json:"identifier"`
		TeamID     string `json:"team_id"`
	}
	if err := json.Unmarshal([]byte(item), &it); err != nil {
		t.Fatalf("parse item: %v", err)
	}
	ctx := context.Background()
	deviceID, ok := approvalEvidenceDevices[tenantID]
	if !ok {
		if err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.1') RETURNING id::text`,
			tenantID, "EVID-"+randomHex(4), "evidence-"+randomHex(4)).Scan(&deviceID); err != nil {
			t.Fatalf("seed evidence device: %v", err)
		}
		approvalEvidenceDevices[tenantID] = deviceID
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		VALUES ($1::uuid, $2, $2, '1.0', $3) ON CONFLICT DO NOTHING`, deviceID, it.Identifier, it.TeamID); err != nil {
		t.Fatalf("seed evidence app: %v", err)
	}
	return item
}

func extItem(browser, id string) string {
	return fmt.Sprintf(`{"type":"browser_extension","browser":%q,"extension_id":%q}`, browser, id)
}

func approvalBody(state, reason string, items ...string) string {
	if reason == "" {
		return fmt.Sprintf(`{"state":%q,"items":[%s]}`, state, strings.Join(items, ","))
	}
	return fmt.Sprintf(`{"state":%q,"reason":%q,"items":[%s]}`, state, reason, strings.Join(items, ","))
}

func appPolicy(t *testing.T, tenantID, bundle string) (string, string, string, bool) {
	t.Helper()
	var policy, tier, notes string
	err := env.pool.QueryRow(context.Background(), `
		SELECT policy, enforcement_tier, notes FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND lower(bundle_id) = lower($2)`, tenantID, bundle).Scan(&policy, &tier, &notes)
	if err != nil {
		return "", "", "", false
	}
	return policy, tier, notes, true
}

func extPolicy(t *testing.T, tenantID, browser, extID string) (string, bool) {
	t.Helper()
	var policy string
	err := env.pool.QueryRow(context.Background(), `
		SELECT policy FROM tenant_extension_policies
		WHERE tenant_id = $1::uuid AND browser = $2 AND extension_id = $3`, tenantID, browser, extID).Scan(&policy)
	if err != nil {
		return "", false
	}
	return policy, true
}

type auditRow struct {
	BatchID, ProductType, ProductKey, Prev, New, Actor string
	Reason                                             *string
	Protected                                          bool
	DecidedAt                                          time.Time
}

func auditRows(t *testing.T, tenantID string) []auditRow {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `
		SELECT batch_id::text, product_type, product_key, previous_state, new_state, actor_email,
		       reason, protected_warning, decided_at
		FROM software_approval_decisions WHERE tenant_id = $1::uuid ORDER BY id`, tenantID)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.BatchID, &a.ProductType, &a.ProductKey, &a.Prev, &a.New, &a.Actor,
			&a.Reason, &a.Protected, &a.DecidedAt); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, a)
	}
	return out
}

func seedWindowsAlias(t *testing.T, identifier string) {
	t.Helper()
	ctx := context.Background()
	var productID string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO software_products (canonical_key, canonical_name, vendor_name)
		VALUES ($1, 'Approval Test Tool', 'Acme') RETURNING id::text`, "pat2007-"+strings.ToLower(identifier)).Scan(&productID); err != nil {
		t.Fatalf("seed product: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO software_product_aliases
		    (product_id, platform, identity_kind, identity_value_normalized, match_confidence, provenance)
		VALUES ($1::uuid, 'windows', 'windows_winget', lower($2), 'exact', 'reviewed')`, productID, identifier); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM software_product_aliases WHERE product_id = $1::uuid`, productID)
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM software_products WHERE id = $1::uuid`, productID)
	})
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

// Migration 0181 backfills every portal_users row that exists when it runs
// to admin, and every later row defaults to viewer. Replayed inside a
// transaction that is rolled back, so the shared test database is untouched.
func TestPortalUserRoleMigrationBackfillsExistingUsersToAdmin(t *testing.T) {
	ctx := context.Background()
	forward, err := os.ReadFile(filepath.Join("..", "migrations", "0181_portal_user_roles.sql"))
	if err != nil {
		t.Fatalf("read 0181: %v", err)
	}
	var body strings.Builder
	for _, line := range strings.Split(string(forward), "\n") {
		switch strings.TrimSpace(line) {
		case "BEGIN;", "COMMIT;":
			continue
		}
		body.WriteString(line + "\n")
	}
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2007-backfill")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `ALTER TABLE portal_users DROP COLUMN role`); err != nil {
		t.Fatalf("return portal_users to its 0059 shape: %v", err)
	}
	for _, email := range []string{"staff-one@backfill.example", "pilot-two@backfill.example"} {
		if _, err := tx.Exec(ctx, `INSERT INTO portal_users (email, tenant_id) VALUES ($1, $2::uuid)`, email, tenantID); err != nil {
			t.Fatalf("seed pre-migration user: %v", err)
		}
	}
	if _, err := tx.Exec(ctx, body.String()); err != nil {
		t.Fatalf("apply 0181: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO portal_users (email, tenant_id) VALUES ('newcomer@backfill.example', $1::uuid)`, tenantID); err != nil {
		t.Fatalf("insert post-migration user: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT email, role FROM portal_users WHERE email LIKE '%@backfill.example' ORDER BY email`)
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	got := map[string]string{}
	for rows.Next() {
		var e, r string
		if err := rows.Scan(&e, &r); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[e] = r
	}
	rows.Close()
	want := map[string]string{
		"staff-one@backfill.example": "admin",
		"pilot-two@backfill.example": "admin",
		"newcomer@backfill.example":  "viewer",
	}
	for e, r := range want {
		if got[e] != r {
			t.Errorf("%s role = %q, want %q", e, got[e], r)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE portal_users SET role = 'owner' WHERE email = 'newcomer@backfill.example'`); err == nil {
		t.Error("role CHECK accepted 'owner'")
	}
}

func TestAdminPortalUsersRole(t *testing.T) {
	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "pat2007-role-a")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2007-role-b")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	email := "role-" + randomHex(4) + "@approvals.example"

	if got := mapPortalUserWithRole(t, email, tenantA, ""); got.Role != "viewer" {
		t.Fatalf("new user default role = %q, want viewer", got.Role)
	}
	if got := mapPortalUserWithRole(t, email, tenantA, "admin"); got.Role != "admin" {
		t.Fatalf("admin API role grant = %q, want admin", got.Role)
	}
	if got := mapPortalUserWithRole(t, email, tenantA, ""); got.Role != "admin" {
		t.Fatalf("re-post on same tenant without role = %q, want admin kept", got.Role)
	}
	if got := mapPortalUserWithRole(t, email, tenantB, ""); got.Role != "viewer" {
		t.Fatalf("move to another tenant without role = %q, want viewer (admin must not carry over)", got.Role)
	}
	if got := mapPortalUserWithRole(t, email, tenantB, "viewer"); got.Role != "viewer" {
		t.Fatalf("explicit viewer = %q", got.Role)
	}
	// PAT-1883: an operator can designate an owner only while self-service
	// sign-up is enabled. This harness runs with the flag unset, as production
	// does, so the grant is refused and the row stays as it was. The grant
	// with the flag on, and that owner on one tenant never carries over to
	// another, are covered through the production router in cmd/patched-api
	// (TestPAT1883OperatorOwnerRoleNeedsTheFlag, TestPAT1883OperatorCanDesignateAnOwner).
	if status, b := postPortalUser(t, fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"owner"}`, email, tenantB)); status != http.StatusBadRequest ||
		!strings.Contains(string(b), "self-service sign-up") {
		t.Fatalf("owner grant with self-service sign-up off = %d %s, want 400 naming what the role needs", status, b)
	}
	if got := mapPortalUserWithRole(t, email, tenantB, ""); got.Role != "viewer" {
		t.Fatalf("role after a refused owner grant = %q, want viewer unchanged", got.Role)
	}

	for name, body := range map[string]string{
		// "owner" was this case's invalid role until PAT-1883 made it a real one.
		"invalid role":        fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"superuser"}`, email, tenantA),
		"case-variant role":   fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"Owner"}`, email, tenantA),
		"service role":        fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"service_readonly"}`, email, tenantA),
		"case-variant key":    fmt.Sprintf(`{"email":%q,"tenant_id":%q,"ROLE":"admin"}`, email, tenantA),
		"unicode-fold key":    fmt.Sprintf(`{"email":%q,"tenant_id":%q,"rolE":"admin"}`, email, tenantA),
		"unknown key":         fmt.Sprintf(`{"email":%q,"tenant_id":%q,"is_admin":true}`, email, tenantA),
		"duplicate role key":  fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"viewer","role":"admin"}`, email, tenantA),
		"trailing JSON value": fmt.Sprintf(`{"email":%q,"tenant_id":%q}{}`, email, tenantA),
	} {
		t.Run(name, func(t *testing.T) {
			if status, b := postPortalUser(t, body); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, b)
			}
		})
	}

	resp, err := http.Get(env.internalSrv.URL + "/admin/portal-users?tenant_id=" + tenantB)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var list struct {
		Users []portalUserResp `json:"users"`
	}
	decodeJSON(t, resp, &list)
	if len(list.Users) != 1 || list.Users[0].Role != "viewer" {
		t.Fatalf("list users = %+v, want one viewer", list.Users)
	}
}

func TestPortalMeReportsRole(t *testing.T) {
	at := newApprovalTenant(t, "me", false)
	domain := "me-" + randomHex(4) + ".example"
	mapEmailDomain(t, domain, at.tenantID, http.StatusCreated)

	for _, tc := range []struct {
		name, email, token, role string
	}{
		{"admin", at.adminEmail, at.adminToken, "admin"},
		{"viewer", at.viewerEmail, at.viewerToken, "viewer"},
		{"domain-matched identity", "someone@" + domain, env.idp.token(t, "someone@"+domain), "viewer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := portalDo(t, http.MethodGet, "/v1/portal/me", tc.token, nil)
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				t.Fatalf("status = %d", resp.StatusCode)
			}
			var me map[string]string
			decodeJSON(t, resp, &me)
			if me["email"] != tc.email || me["tenant_id"] != at.tenantID || me["role"] != tc.role || len(me) != 3 {
				t.Fatalf("me = %v, want email %s tenant %s role %s", me, tc.email, at.tenantID, tc.role)
			}
		})
	}

	t.Run("disabled admin row falls back to no access", func(t *testing.T) {
		email := "gone-" + randomHex(4) + "@approvals.example"
		mapPortalUserWithRole(t, email, at.tenantID, "admin")
		disablePortalUser(t, email)
		resp := portalDo(t, http.MethodGet, "/v1/portal/me", env.idp.token(t, email), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
}

func TestPortalApprovalWriteRequiresAdmin(t *testing.T) {
	at := newApprovalTenant(t, "rolegate", false)
	domain := "gate-" + randomHex(4) + ".example"
	mapEmailDomain(t, domain, at.tenantID, http.StatusCreated)
	body := approvalBody("approved", "", seen(t, at.tenantID, macApp("com.example.rolegate", "ABCDE12345")))

	for name, token := range map[string]string{
		"viewer":                  at.viewerToken,
		"domain-matched identity": env.idp.token(t, "person@"+domain),
	} {
		t.Run(name, func(t *testing.T) {
			refused(t, token, body, http.StatusForbidden, "admin_role_required")
			// A viewer is refused before the body is read at all.
			refused(t, token, `not json`, http.StatusForbidden, "admin_role_required")
		})
	}
	if _, _, _, ok := appPolicy(t, at.tenantID, "com.example.rolegate"); ok {
		t.Fatal("viewer write created a policy row")
	}
	if n := len(auditRows(t, at.tenantID)); n != 0 {
		t.Fatalf("viewer write produced %d audit rows", n)
	}

	t.Run("promoted viewer can write", func(t *testing.T) {
		mapPortalUserWithRole(t, at.viewerEmail, at.tenantID, "admin")
		mustApprove(t, at.viewerToken, body)
		mapPortalUserWithRole(t, at.viewerEmail, at.tenantID, "viewer")
		refused(t, at.viewerToken, body, http.StatusForbidden, "admin_role_required")
	})
}

// ---------------------------------------------------------------------------
// Writes and audit
// ---------------------------------------------------------------------------

func TestPortalApprovalSingleWriteLifecycleAndAudit(t *testing.T) {
	at := newApprovalTenant(t, "single", false)
	item := seen(t, at.tenantID, macApp("com.example.Single", "abcde12345"))

	steps := []struct {
		state, reason, wantPolicy, wantPrev string
	}{
		{"approved", "Used by finance", "approved", "unreviewed"},
		{"unapproved", "Replaced by the approved tool", "unapproved", "approved"},
		{"ignored", "", "unmanaged", "unapproved"},
		{"unreviewed", "Reopened for review", "", "ignored"},
	}
	for _, s := range steps {
		out := mustApprove(t, at.adminToken, approvalBody(s.state, s.reason, item))
		if len(out.Results) != 1 || !out.Results[0].Changed || out.Results[0].PreviousState != s.wantPrev ||
			out.Results[0].NewState != s.state || out.ChangedCount != 1 {
			t.Fatalf("%s: result = %+v", s.state, out)
		}
		if out.Results[0].ProductKey != "application:macos:com.example.single:ABCDE12345" {
			t.Fatalf("product key = %q", out.Results[0].ProductKey)
		}
		policy, tier, notes, ok := appPolicy(t, at.tenantID, "com.example.single")
		if s.wantPolicy == "" {
			if ok {
				t.Fatalf("unreviewed left a policy row (%s)", policy)
			}
			continue
		}
		if !ok || policy != s.wantPolicy || tier != "report_deploy" || notes != s.reason {
			t.Fatalf("%s: row = %q tier %q notes %q (ok=%v)", s.state, policy, tier, notes, ok)
		}
	}

	// Same state again: nothing changes, nothing is audited.
	out := mustApprove(t, at.adminToken, approvalBody("unreviewed", "", item))
	if out.ChangedCount != 0 || out.Results[0].Changed {
		t.Fatalf("no-op write reported a change: %+v", out)
	}

	audit := auditRows(t, at.tenantID)
	if len(audit) != len(steps) {
		t.Fatalf("audit rows = %d, want %d", len(audit), len(steps))
	}
	for i, s := range steps {
		a := audit[i]
		if a.Prev != s.wantPrev || a.New != s.state || a.Actor != strings.ToLower(at.adminEmail) ||
			a.ProductType != "application" || a.ProductKey != "application:macos:com.example.single:ABCDE12345" {
			t.Errorf("audit[%d] = %+v", i, a)
		}
		if (s.reason == "") != (a.Reason == nil) || (a.Reason != nil && *a.Reason != s.reason) {
			t.Errorf("audit[%d] reason = %v, want %q", i, a.Reason, s.reason)
		}
		if time.Since(a.DecidedAt) > 5*time.Minute {
			t.Errorf("audit[%d] decided_at = %v", i, a.DecidedAt)
		}
	}

	t.Run("audit is append-only", func(t *testing.T) {
		if _, err := env.pool.Exec(context.Background(),
			`UPDATE software_approval_decisions SET new_state = 'approved' WHERE tenant_id = $1::uuid`, at.tenantID); err == nil ||
			!strings.Contains(err.Error(), "append-only") {
			t.Fatalf("UPDATE on audit: err = %v, want append-only refusal", err)
		}
		if _, err := env.pool.Exec(context.Background(),
			`DELETE FROM software_approval_decisions WHERE tenant_id = $1::uuid`, at.tenantID); err == nil {
			t.Fatal("DELETE on audit succeeded")
		}
	})
}

func TestPortalApprovalBulkWrite(t *testing.T) {
	at := newApprovalTenant(t, "bulk", false)
	winID := "Acme.BulkTool" + randomHex(3)
	seedWindowsAlias(t, winID)

	items := []string{
		seen(t, at.tenantID, macApp("com.example.bulk.one", "BULKTEAM01")),
		seen(t, at.tenantID, macApp("com.example.bulk.two", "BULKTEAM01")),
		fmt.Sprintf(`{"type":"application","platform":"windows","identifier":%q}`, winID),
		extItem("chrome", "abcdefghijklmnopabcdefghijklmnop"),
		extItem("any", "bulk@example.org"),
	}
	out := mustApprove(t, at.adminToken, approvalBody("approved", "Pilot baseline", items...))
	if out.ChangedCount != len(items) || len(out.Results) != len(items) {
		t.Fatalf("bulk result = %+v", out)
	}
	for _, b := range []string{"com.example.bulk.one", "com.example.bulk.two", winID} {
		if p, _, _, ok := appPolicy(t, at.tenantID, b); !ok || p != "approved" {
			t.Errorf("%s policy = %q ok=%v", b, p, ok)
		}
	}
	var winPlatform string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT platform FROM tenant_app_policies WHERE tenant_id = $1::uuid AND bundle_id = $2`, at.tenantID, winID).Scan(&winPlatform); err != nil || winPlatform != "windows" {
		t.Errorf("windows row platform = %q err %v", winPlatform, err)
	}
	if p, ok := extPolicy(t, at.tenantID, "chrome", "abcdefghijklmnopabcdefghijklmnop"); !ok || p != "approved" {
		t.Errorf("chrome extension policy = %q", p)
	}
	audit := auditRows(t, at.tenantID)
	if len(audit) != len(items) {
		t.Fatalf("audit rows = %d, want %d", len(audit), len(items))
	}
	for _, a := range audit {
		if a.BatchID != out.BatchID || a.Prev != "unreviewed" || a.New != "approved" {
			t.Errorf("audit row = %+v, want batch %s", a, out.BatchID)
		}
	}

	// Ignored on extensions is the extension store's own 'ignored'.
	mustApprove(t, at.adminToken, approvalBody("ignored", "", extItem("chrome", "abcdefghijklmnopabcdefghijklmnop")))
	if p, _ := extPolicy(t, at.tenantID, "chrome", "abcdefghijklmnopabcdefghijklmnop"); p != "ignored" {
		t.Errorf("extension ignored policy = %q", p)
	}

	t.Run("exactly 500 items is accepted", func(t *testing.T) {
		many := make([]string, 500)
		for i := range many {
			many[i] = seen(t, at.tenantID, macApp(fmt.Sprintf("com.example.cap.%03d", i), "CAPTEAM001"))
		}
		if out := mustApprove(t, at.adminToken, approvalBody("ignored", "", many...)); out.ChangedCount != 500 {
			t.Fatalf("changed = %d", out.ChangedCount)
		}
		many = append(many, seen(t, at.tenantID, macApp("com.example.cap.500", "CAPTEAM001")))
		refused(t, at.adminToken, approvalBody("approved", "", many...), http.StatusBadRequest, "too_many_items")
		if _, _, _, ok := appPolicy(t, at.tenantID, "com.example.cap.500"); ok {
			t.Fatal("over-cap call wrote a row")
		}
	})
}

func TestPortalApprovalRefusesNameOnlyAndUnconfirmed(t *testing.T) {
	at := newApprovalTenant(t, "nameonly", false)
	valid := seen(t, at.tenantID, macApp("com.example.valid", "VALIDTEAM1"))

	for name, item := range map[string]string{
		"no identifier":    `{"type":"application","platform":"windows"}`,
		"empty identifier": `{"type":"application","platform":"macos","identifier":"  "}`,
	} {
		t.Run(name, func(t *testing.T) {
			out := refused(t, at.adminToken, approvalBody("approved", "", valid, item), http.StatusUnprocessableEntity, "name_only")
			if len(out.Items) != 1 || out.Items[0].Index != 1 || out.Items[0].Code != "name_only" {
				t.Fatalf("items = %+v", out.Items)
			}
		})
	}
	t.Run("identifier with no confirmed identity", func(t *testing.T) {
		for _, item := range []string{
			`{"type":"application","platform":"windows","identifier":"{UNCONFIRMED-PRODUCT-CODE}"}`,
			`{"type":"application","platform":"macos","identifier":"com.example.bundleonly"}`,
		} {
			out := refused(t, at.adminToken, approvalBody("approved", "", valid, item), http.StatusUnprocessableEntity, "unconfirmed_identity")
			if len(out.Items) != 1 || out.Items[0].Code != "unconfirmed_identity" {
				t.Fatalf("items = %+v", out.Items)
			}
		}
	})
	// All or nothing: the valid item beside a refused one was not written.
	if _, _, _, ok := appPolicy(t, at.tenantID, "com.example.valid"); ok {
		t.Fatal("a refused call wrote its valid item")
	}
	if n := len(auditRows(t, at.tenantID)); n != 0 {
		t.Fatalf("refused calls produced %d audit rows", n)
	}
}

func TestPortalApprovalStrictInput(t *testing.T) {
	at := newApprovalTenant(t, "strict", false)
	item := seen(t, at.tenantID, macApp("com.example.strict", "STRICTTM01"))
	longReason := strings.Repeat("r", 1001)
	for name, body := range map[string]string{
		"case-variant top key":      `{"STATE":"approved","items":[` + item + `]}`,
		"unicode-fold top key":      `{"ſtate":"approved","items":[` + item + `]}`,
		"case-variant item key":     `{"state":"approved","items":[{"Type":"application","platform":"macos","identifier":"com.x","team_id":"STRICTTM01"}]}`,
		"unknown item key":          `{"state":"approved","items":[{"type":"application","platform":"macos","identifier":"com.x","team_id":"STRICTTM01","tenant_id":"x"}]}`,
		"unknown top key":           `{"state":"approved","tenant_id":"00000000-0000-0000-0000-000000000000","items":[` + item + `]}`,
		"duplicate key":             `{"state":"unapproved","state":"approved","items":[` + item + `]}`,
		"trailing content":          `{"state":"approved","items":[` + item + `]} {}`,
		"enforcement tier supplied": `{"state":"approved","enforcement_tier":"managed","items":[` + item + `]}`,
		"unknown state":             approvalBody("mandatory", "", item),
		"no items":                  `{"state":"approved","items":[]}`,
		"reason over 1000 chars":    approvalBody("approved", longReason, item),
		"duplicate product":         approvalBody("approved", "", item, macApp("COM.EXAMPLE.STRICT", "strictTM01")),
		"team id on windows":        approvalBody("approved", "", `{"type":"application","platform":"windows","identifier":"x","team_id":"ABCDE12345"}`),
		"extension field on app":    approvalBody("approved", "", `{"type":"application","platform":"macos","identifier":"x","team_id":"ABCDE12345","browser":"chrome"}`),
		"unknown browser":           approvalBody("approved", "", extItem("opera", "abcdefghijklmnopabcdefghijklmnop")),
		"unknown type":              approvalBody("approved", "", `{"type":"homebrew_formula","identifier":"wget"}`),
		"malformed":                 `{"state":`,
	} {
		t.Run(name, func(t *testing.T) {
			refused(t, at.adminToken, body, http.StatusBadRequest, "")
		})
	}
	// Tenant creation seeds the Patched agent's own approved policies, so
	// count only the identifiers these bodies carry.
	if n := countRows(t, `SELECT COUNT(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid
		AND lower(bundle_id) IN ('com.example.strict', 'com.x', 'x', 'wget')`, at.tenantID); n != 0 {
		t.Fatalf("invalid input wrote %d policy rows", n)
	}
	t.Run("safari extension is accepted", func(t *testing.T) {
		const safariID = "com.example.notes.SafariExtension"
		out := mustApprove(t, at.adminToken, approvalBody("unapproved", "Not on our list", extItem("safari", safariID)))
		if out.ChangedCount != 1 || out.Results[0].ProductKey != "browser_extension:safari:"+safariID {
			t.Fatalf("safari result = %+v", out)
		}
		if p, ok := extPolicy(t, at.tenantID, "safari", safariID); !ok || p != "unapproved" {
			t.Fatalf("safari policy row = %q ok=%v", p, ok)
		}
		if n := countRows(t, `SELECT COUNT(*) FROM software_approval_decisions
			WHERE tenant_id = $1::uuid AND browser = 'safari' AND identifier = $2
			  AND previous_state = 'unreviewed' AND new_state = 'unapproved' AND reason = 'Not on our list'`, at.tenantID, safariID); n != 1 {
			t.Fatalf("safari audit rows = %d, want 1", n)
		}
	})
	t.Run("reason of exactly 1000 chars is accepted", func(t *testing.T) {
		mustApprove(t, at.adminToken, approvalBody("approved", strings.Repeat("r", 1000), item))
	})
}

func TestPortalApprovalRefusesOperatorMandatory(t *testing.T) {
	at := newApprovalTenant(t, "mandatory", false)
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'MANDTEAM01', 'com.example.mandatory', 'macos', 'mandatory', 'report_deploy')`, at.tenantID); err != nil {
		t.Fatalf("seed mandatory: %v", err)
	}
	out := refused(t, at.adminToken, approvalBody("unreviewed", "", seen(t, at.tenantID, macApp("com.example.mandatory", "MANDTEAM01"))), http.StatusConflict, "refused")
	if len(out.Items) != 1 || out.Items[0].Code != "operator_managed" {
		t.Fatalf("items = %+v", out.Items)
	}
	if p, _, _, _ := appPolicy(t, at.tenantID, "com.example.mandatory"); p != "mandatory" {
		t.Fatalf("mandatory row changed to %q", p)
	}
}

func TestPortalApprovalProtectedProductWarning(t *testing.T) {
	at := newApprovalTenant(t, "protected", false)
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO protected_software (tenant_id, category, vendor, product_name, bundle_id, team_id, reason, added_by)
		VALUES ($1::uuid, 'edr', 'Acme', 'Acme EDR', 'com.acme.edr', 'ACMEEDR123', 'test', 'test')`, at.tenantID); err != nil {
		t.Fatalf("seed protected software: %v", err)
	}
	protectedItem := seen(t, at.tenantID, macApp("com.acme.edr", "ACMEEDR123"))
	plainItem := seen(t, at.tenantID, macApp("com.example.plain", "PLAINTEAM1"))

	out := mustApprove(t, at.adminToken, approvalBody("unapproved", "Testing the warning", protectedItem, plainItem))
	if out.WarningCount != 1 || out.ChangedCount != 2 {
		t.Fatalf("result = %+v", out)
	}
	if r := out.Results[0]; !r.ProtectedWarning || r.Protected == nil || r.Protected.Category != "edr" || r.Protected.ProductName != "Acme EDR" {
		t.Fatalf("protected result = %+v", r)
	}
	if r := out.Results[1]; r.ProtectedWarning || r.Protected != nil {
		t.Fatalf("plain result carries a warning: %+v", r)
	}
	// The write still succeeded.
	if p, _, _, _ := appPolicy(t, at.tenantID, "com.acme.edr"); p != "unapproved" {
		t.Fatalf("protected product policy = %q, want unapproved", p)
	}
	var flagged bool
	if err := env.pool.QueryRow(context.Background(), `
		SELECT protected_warning FROM software_approval_decisions
		WHERE tenant_id = $1::uuid AND identifier = 'com.acme.edr'`, at.tenantID).Scan(&flagged); err != nil || !flagged {
		t.Fatalf("audit protected_warning = %v err %v", flagged, err)
	}
	// Approving a protected product carries no warning.
	if out := mustApprove(t, at.adminToken, approvalBody("approved", "", protectedItem)); out.WarningCount != 0 {
		t.Fatalf("approve warned: %+v", out)
	}
}

// ---------------------------------------------------------------------------
// No path to actuation
// ---------------------------------------------------------------------------

// approvalAgentDevice gives tenantID an agent_config row and one device
// credential, so the signed config the agent actually receives can be read.
func approvalAgentDevice(t *testing.T, tenantID string) (token string, secret []byte) {
	t.Helper()
	ctx := context.Background()
	body, err := json.Marshal(agentconfig.DefaultConfigBody())
	if err != nil {
		t.Fatalf("marshal default config: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO agent_config (tenant_id, config_version, body, issued_at, updated_by)
		VALUES ($1::uuid, 1, $2::jsonb, now(), 'pat2007-test')
		ON CONFLICT (tenant_id) DO NOTHING`, tenantID, body); err != nil {
		t.Fatalf("seed agent_config: %v", err)
	}
	var deviceID string
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.1') RETURNING id::text`,
		tenantID, "PAT2007-"+randomHex(4), "approvals-"+randomHex(4)).Scan(&deviceID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	token = "pat2007-device-" + randomHex(8)
	secret = []byte("pat2007-device-secret-" + randomHex(8))
	hash := sha256.Sum256([]byte(token))
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)`, tenantID, deviceID, hash[:], secret); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	return token, secret
}

type signedAppControl struct {
	Enabled            bool                                  `json:"enabled"`
	ExtensionBlocklist []agentconfig.ExtensionBlocklistEntry `json:"extension_blocklist"`
	ExtensionRemovals  []map[string]any                      `json:"extension_removals"`
}

func signedAgentAppControl(t *testing.T, token string, secret []byte) signedAppControl {
	t.Helper()
	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v2\n" + ts + "\n" + nonce + "\n"))
	req, _ := http.NewRequest(http.MethodGet, env.publicSrv.URL+"/v1/agent-config", nil)
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
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("agent-config = %d: %s", resp.StatusCode, b)
	}
	var envelope struct {
		Payload string `json:"signed_payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var cfg struct {
		AppControl *signedAppControl `json:"app_control"`
	}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		t.Fatalf("decode signed config: %v", err)
	}
	if cfg.AppControl == nil {
		t.Fatalf("signed config has no app_control block: %s", payload)
	}
	return *cfg.AppControl
}

func actuationRowCounts(t *testing.T, tenantID string) map[string]int {
	t.Helper()
	return map[string]int{
		"removal_campaigns":                 countRows(t, `SELECT COUNT(*) FROM removal_campaigns WHERE tenant_id = $1::uuid`, tenantID),
		"device_removal_tasks":              countRows(t, `SELECT COUNT(*) FROM device_removal_tasks WHERE tenant_id = $1::uuid`, tenantID),
		"tenant_extension_removal_requests": countRows(t, `SELECT COUNT(*) FROM tenant_extension_removal_requests WHERE tenant_id = $1::uuid`, tenantID),
		"mandatory_install_intents":         countRows(t, `SELECT COUNT(*) FROM mandatory_install_intents WHERE tenant_id = $1::uuid`, tenantID),
		"tenant_allowlists":                 countRows(t, `SELECT COUNT(*) FROM tenant_allowlists WHERE tenant_id = $1::uuid`, tenantID),
	}
}

// On an assurance (v1) tenant, an Unapproved decision from the portal, for
// an application or a browser extension, creates nothing an agent acts on:
// no removal campaign, removal task, extension removal, install intent or
// allowlist entry, and nothing in the signed extension blocklist or
// removals. The same holds for an operator-set unapproved extension row,
// because the blocklist projection itself is gated on App Control.
func TestPortalUnapprovedCreatesNoActuationOnAssuranceTenant(t *testing.T) {
	at := newApprovalTenant(t, "noremoval", false)
	token, secret := approvalAgentDevice(t, at.tenantID)
	const extID = "noremovalextensionidabcdefghijkl"

	mustApprove(t, at.adminToken, approvalBody("unapproved", "Not permitted",
		seen(t, at.tenantID, macApp("com.example.noremoval", "NOREMOVE01")), extItem("chrome", extID), extItem("any", "any@noremoval.example")))
	if p, _ := extPolicy(t, at.tenantID, "chrome", extID); p != "unapproved" {
		t.Fatalf("extension policy = %q, want unapproved (the decision is recorded)", p)
	}
	// An operator-set row, as the admin API would write it.
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'edge', 'operatorsetextensionabcdefghijkl', 'Operator', 'unapproved')`, at.tenantID); err != nil {
		t.Fatalf("seed operator extension policy: %v", err)
	}

	for table, n := range actuationRowCounts(t, at.tenantID) {
		if n != 0 {
			t.Errorf("%s has %d rows for the tenant after Unapproved writes", table, n)
		}
	}
	ac := signedAgentAppControl(t, token, secret)
	if ac.Enabled {
		t.Fatal("app_control.enabled is true on an assurance tenant")
	}
	if len(ac.ExtensionBlocklist) != 0 {
		t.Fatalf("signed extension_blocklist = %+v, want empty on an assurance tenant", ac.ExtensionBlocklist)
	}
	if len(ac.ExtensionRemovals) != 0 {
		t.Fatalf("signed extension_removals = %+v, want empty", ac.ExtensionRemovals)
	}
}

// On an App Control tenant the operator's unapproved extensions still reach
// the signed blocklist (no regression for managed tenants), and the portal
// cannot add one: an extension Unapproved is refused with 409. Applications
// keep the ruling as written and may still be marked Unapproved.
func TestPortalApprovalAppControlTenant(t *testing.T) {
	at := newApprovalTenant(t, "appcontrol", true)
	token, secret := approvalAgentDevice(t, at.tenantID)
	const operatorExt = "operatorblockedextensionabcdefgh"
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', $2, 'Operator blocked', 'unapproved')`, at.tenantID, operatorExt); err != nil {
		t.Fatalf("seed operator extension policy: %v", err)
	}

	ac := signedAgentAppControl(t, token, secret)
	if !ac.Enabled || len(ac.ExtensionBlocklist) != 1 ||
		ac.ExtensionBlocklist[0].Browser != "chrome" || ac.ExtensionBlocklist[0].ExtensionID != operatorExt {
		t.Fatalf("managed tenant signed app_control = %+v, want the operator's entry", ac)
	}

	const portalExt = "portalextensionabcdefghijklmnopq"
	out := refused(t, at.adminToken, approvalBody("unapproved", "", extItem("chrome", portalExt)), http.StatusConflict, "refused")
	if len(out.Items) != 1 || out.Items[0].Code != "app_control_managed" {
		t.Fatalf("items = %+v", out.Items)
	}
	if _, ok := extPolicy(t, at.tenantID, "chrome", portalExt); ok {
		t.Fatal("refused extension Unapproved wrote a row")
	}
	// Safari never reaches the blocklist, so its Unapproved is allowed here.
	const safariExt = "com.example.appcontrol.SafariExtension"
	mustApprove(t, at.adminToken, approvalBody("unapproved", "", extItem("safari", safariExt)))
	if p, _ := extPolicy(t, at.tenantID, "safari", safariExt); p != "unapproved" {
		t.Fatalf("safari policy on App Control tenant = %q", p)
	}
	// Approve and ignore stay available for extensions.
	mustApprove(t, at.adminToken, approvalBody("approved", "", extItem("chrome", portalExt)))
	// Applications may still be marked Unapproved.
	mustApprove(t, at.adminToken, approvalBody("unapproved", "", seen(t, at.tenantID, macApp("com.example.appcontrol", "APPCTRL001"))))

	ac = signedAgentAppControl(t, token, secret)
	if len(ac.ExtensionBlocklist) != 1 || ac.ExtensionBlocklist[0].ExtensionID != operatorExt {
		t.Fatalf("blocklist after portal writes = %+v, want only the operator's entry", ac.ExtensionBlocklist)
	}
	for table, n := range actuationRowCounts(t, at.tenantID) {
		if n != 0 {
			t.Errorf("%s has %d rows for the tenant after portal writes", table, n)
		}
	}
}

// ---------------------------------------------------------------------------
// Isolation, history and export
// ---------------------------------------------------------------------------

func getHistory(t *testing.T, token, query string) (int, map[string]any) {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/software-approvals/history"+query, token, nil)
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestPortalApprovalCrossTenantIsolation(t *testing.T) {
	a := newApprovalTenant(t, "iso-a", false)
	b := newApprovalTenant(t, "iso-b", false)
	const bundle, team = "com.example.shared", "SHAREDTM01"
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, platform, policy, enforcement_tier, notes)
		VALUES ($1::uuid, $2, $3, 'macos', 'approved', 'report_deploy', 'B decided')`, b.tenantID, team, bundle); err != nil {
		t.Fatalf("seed tenant B policy: %v", err)
	}

	out := mustApprove(t, a.adminToken, approvalBody("unapproved", "", seen(t, a.tenantID, macApp(bundle, team))))
	if out.Results[0].PreviousState != "unreviewed" {
		t.Fatalf("tenant A saw tenant B's decision as its previous state: %+v", out.Results[0])
	}
	if p, _, notes, _ := appPolicy(t, b.tenantID, bundle); p != "approved" || notes != "B decided" {
		t.Fatalf("tenant A's write changed tenant B's row: %q %q", p, notes)
	}
	if p, _, _, _ := appPolicy(t, a.tenantID, bundle); p != "unapproved" {
		t.Fatalf("tenant A row = %q", p)
	}

	// B's history, whole-tenant and for the same product, holds none of A's decisions.
	filter := "?type=application&platform=macos&identifier=" + bundle + "&team_id=" + team
	for _, q := range []string{"", filter} {
		status, h := getHistory(t, b.adminToken, q)
		if status != http.StatusOK || h["total"].(float64) != 0 {
			t.Fatalf("tenant B history%s = %d %v, want empty", q, status, h)
		}
	}
	for _, tok := range []string{a.viewerToken, a.adminToken} {
		if status, h := getHistory(t, tok, filter); status != http.StatusOK || h["total"].(float64) != 1 {
			t.Fatalf("tenant A history = %d %v", status, h)
		}
	}
	// B's export likewise.
	resp := portalDo(t, http.MethodGet, "/v1/portal/software-approvals/history/export?format=json", b.viewerToken, nil)
	var exp map[string]any
	decodeJSON(t, resp, &exp)
	if exp["total"].(float64) != 0 {
		t.Fatalf("tenant B export = %v", exp)
	}
	// A client-supplied tenant id is not a thing: the key is refused.
	refused(t, a.adminToken, `{"tenant_id":"`+b.tenantID+`","state":"approved","items":[`+macApp(bundle, team)+`]}`, http.StatusBadRequest, "")
	if status, _ := getHistory(t, a.adminToken, "?tenant_id="+b.tenantID); status != http.StatusBadRequest {
		t.Fatalf("history with tenant_id = %d, want 400", status)
	}
}

func TestPortalApprovalHistoryPagingAndExport(t *testing.T) {
	at := newApprovalTenant(t, "history", false)
	item := seen(t, at.tenantID, macApp("com.example.history", "HISTTEAM01"))
	other := extItem("firefox", "history@example.org")
	injection := "=HYPERLINK(\"http://evil.example\",\"x\")"

	mustApprove(t, at.adminToken, approvalBody("approved", "first", item))
	mustApprove(t, at.adminToken, approvalBody("unapproved", injection, item))
	mustApprove(t, at.adminToken, approvalBody("ignored", "", item))
	mustApprove(t, at.adminToken, approvalBody("unreviewed", "", item))
	mustApprove(t, at.adminToken, approvalBody("approved", "", other))

	filter := "type=application&platform=macos&identifier=com.example.history&team_id=HISTTEAM01"
	status, page1 := getHistory(t, at.viewerToken, "?"+filter+"&limit=2")
	if status != http.StatusOK || page1["total"].(float64) != 4 || page1["returned"].(float64) != 2 {
		t.Fatalf("page 1 = %d %v", status, page1)
	}
	d1 := page1["decisions"].([]any)
	if d1[0].(map[string]any)["new_state"] != "unreviewed" || d1[1].(map[string]any)["new_state"] != "ignored" {
		t.Fatalf("page 1 not newest first: %v", d1)
	}
	if d1[0].(map[string]any)["previous_state"] != "ignored" {
		t.Fatalf("page 1 previous_state: %v", d1[0])
	}
	_, page2 := getHistory(t, at.viewerToken, "?"+filter+"&limit=2&offset=2")
	d2 := page2["decisions"].([]any)
	if len(d2) != 2 || d2[1].(map[string]any)["new_state"] != "approved" || d2[1].(map[string]any)["reason"] != "first" {
		t.Fatalf("page 2 = %v", d2)
	}
	_, page3 := getHistory(t, at.viewerToken, "?"+filter+"&limit=2&offset=4")
	if page3["returned"].(float64) != 0 {
		t.Fatalf("page 3 = %v", page3)
	}
	if _, all := getHistory(t, at.viewerToken, ""); all["total"].(float64) != 5 {
		t.Fatalf("tenant history total = %v, want 5", all["total"])
	}

	for q, want := range map[string]int{
		"?limit=0":                     http.StatusBadRequest,
		"?limit=501":                   http.StatusBadRequest,
		"?offset=-1":                   http.StatusBadRequest,
		"?limit=abc":                   http.StatusBadRequest,
		"?platform=macos":              http.StatusBadRequest,
		"?type=application&platform=x": http.StatusBadRequest,
		"?format=csv":                  http.StatusBadRequest,
		"?limit=500":                   http.StatusOK,
	} {
		if status, _ := getHistory(t, at.viewerToken, q); status != want {
			t.Errorf("history%s = %d, want %d", q, status, want)
		}
	}

	t.Run("csv export", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/software-approvals/history/export?format=csv", at.viewerToken, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
			!strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") || resp.Header.Get("X-Patched-Export-Rows") != "5" {
			t.Fatalf("csv export status %d headers %v", resp.StatusCode, resp.Header)
		}
		records, err := csv.NewReader(resp.Body).ReadAll()
		if err != nil {
			t.Fatalf("parse csv: %v", err)
		}
		reasonColumn := -1
		if len(records) > 0 {
			for i, heading := range records[0] {
				if heading == "reason" {
					reasonColumn = i
					break
				}
			}
		}
		if len(records) != 6 || records[0][0] != "decided_at" || reasonColumn < 0 {
			t.Fatalf("csv = %v", records)
		}
		found := false
		for _, r := range records[1:] {
			if strings.Contains(r[reasonColumn], "HYPERLINK") {
				found = true
				if !strings.HasPrefix(r[reasonColumn], "'=") {
					t.Fatalf("formula not neutralised: %q", r[reasonColumn])
				}
			}
		}
		if !found {
			t.Fatal("injection reason missing from csv")
		}
	})
	t.Run("json export for one product", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/software-approvals/history/export?"+filter, at.adminToken, nil)
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			resp.Body.Close()
			t.Fatalf("json export = %d", resp.StatusCode)
		}
		var out map[string]any
		decodeJSON(t, resp, &out)
		if out["total"].(float64) != 4 || len(out["decisions"].([]any)) != 4 ||
			out["product_key"] != "application:macos:com.example.history:HISTTEAM01" {
			t.Fatalf("json export = %v", out)
		}
	})
	t.Run("export rejects paging and unknown formats", func(t *testing.T) {
		for _, q := range []string{"?format=xlsx", "?limit=10", "?offset=1"} {
			resp := portalDo(t, http.MethodGet, "/v1/portal/software-approvals/history/export"+q, at.viewerToken, nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("export%s = %d, want 400", q, resp.StatusCode)
			}
		}
	})

	t.Run("reads need a portal identity", func(t *testing.T) {
		for _, path := range []string{"/v1/portal/me", "/v1/portal/software-approvals/history"} {
			resp := portalDo(t, http.MethodGet, path, "", nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s without token = %d, want 401", path, resp.StatusCode)
			}
		}
		resp := portalDo(t, http.MethodPut, "/v1/portal/software-approvals", "", bytes.NewReader([]byte(`{}`)))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("write without token = %d, want 401", resp.StatusCode)
		}
	})
}

// Review P1: on an App Control tenant the portal cannot lift or reshape an
// operator's extension block, whatever the new state and whichever browser
// the item names ('any' included). Safari stays exempt.
func TestPortalApprovalCannotLiftOperatorExtensionBlock(t *testing.T) {
	at := newApprovalTenant(t, "liftblock", true)
	token, secret := approvalAgentDevice(t, at.tenantID)
	const chromeBlocked = "operatorchromeblockabcdefghijklm"
	const anyBlocked = "operatoranyblockabcdefghijklmnop"
	for browser, extID := range map[string]string{"chrome": chromeBlocked, "any": anyBlocked} {
		if _, err := env.pool.Exec(context.Background(), `
			INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
			VALUES ($1::uuid, $2, $3, 'Operator blocked', 'unapproved')`, at.tenantID, browser, extID); err != nil {
			t.Fatalf("seed operator block: %v", err)
		}
	}
	before := signedAgentAppControl(t, token, secret).ExtensionBlocklist
	if len(before) != 4 { // chrome row + 'any' fanned out to chrome, edge, firefox
		t.Fatalf("operator blocklist = %+v, want 4 entries", before)
	}
	sameBlocklist := func(t *testing.T) {
		t.Helper()
		after := signedAgentAppControl(t, token, secret).ExtensionBlocklist
		if fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("signed blocklist changed: before %+v after %+v", before, after)
		}
	}

	for _, tc := range []struct{ name, state, browser, extID string }{
		{"approve the operator's chrome block", "approved", "chrome", chromeBlocked},
		{"unreview the operator's chrome block", "unreviewed", "chrome", chromeBlocked},
		{"ignore the operator's chrome block", "ignored", "chrome", chromeBlocked},
		{"approve it as any", "approved", "any", chromeBlocked},
		{"approve it on another browser", "approved", "edge", chromeBlocked},
		{"unreview the operator's any block", "unreviewed", "any", anyBlocked},
		{"approve the operator's any block", "approved", "any", anyBlocked},
		{"approve the any block on chrome", "approved", "chrome", anyBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := refused(t, at.adminToken, approvalBody(tc.state, "", extItem(tc.browser, tc.extID)), http.StatusConflict, "refused")
			if len(out.Items) != 1 || out.Items[0].Code != "app_control_managed" {
				t.Fatalf("items = %+v", out.Items)
			}
			sameBlocklist(t)
		})
	}
	if p, _ := extPolicy(t, at.tenantID, "chrome", chromeBlocked); p != "unapproved" {
		t.Fatalf("operator chrome row = %q", p)
	}
	if p, _ := extPolicy(t, at.tenantID, "any", anyBlocked); p != "unapproved" {
		t.Fatalf("operator any row = %q", p)
	}
	if n := countRows(t, `SELECT COUNT(*) FROM software_approval_decisions WHERE tenant_id = $1::uuid`, at.tenantID); n != 0 {
		t.Fatalf("refused attempts wrote %d audit rows", n)
	}

	t.Run("safari stays exempt", func(t *testing.T) {
		mustApprove(t, at.adminToken, approvalBody("approved", "", extItem("safari", chromeBlocked)))
		if p, _ := extPolicy(t, at.tenantID, "safari", chromeBlocked); p != "approved" {
			t.Fatalf("safari row = %q", p)
		}
		sameBlocklist(t)
	})
}

// Review P3: a portal row keyed more specifically (bundle plus Team ID) must
// not be able to outrank an operator's mandatory row keyed on the bundle
// alone, and a Team ID the tenant has never observed for that bundle is not
// confirmed identity.
func TestPortalApprovalMandatoryShadowAndTeamEvidence(t *testing.T) {
	at := newApprovalTenant(t, "shadow", false)
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.shadow', 'macos', 'mandatory', 'report_deploy')`, at.tenantID); err != nil {
		t.Fatalf("seed bundle-only mandatory: %v", err)
	}
	item := seen(t, at.tenantID, macApp("com.example.shadow", "SHADOWTM01"))
	for _, state := range []string{"approved", "unapproved", "ignored"} {
		out := refused(t, at.adminToken, approvalBody(state, "", item), http.StatusConflict, "refused")
		if len(out.Items) != 1 || out.Items[0].Code != "operator_managed" {
			t.Fatalf("%s: items = %+v", state, out.Items)
		}
	}
	if n := countRows(t, `SELECT COUNT(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid AND lower(bundle_id) = 'com.example.shadow'`, at.tenantID); n != 1 {
		t.Fatalf("policy rows for the mandatory bundle = %d, want only the operator's", n)
	}

	t.Run("mandatory keyed on name", func(t *testing.T) {
		if _, err := env.pool.Exec(context.Background(), `
			INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
			VALUES ($1::uuid, 'com.example.named', 'any', 'mandatory', 'report_deploy')`, at.tenantID); err != nil {
			t.Fatalf("seed name mandatory: %v", err)
		}
		// seen() records the bundle ID as the app's name too.
		refused(t, at.adminToken, approvalBody("approved", "", seen(t, at.tenantID, macApp("com.example.named", "NAMEDTEAM1"))), http.StatusConflict, "refused")
	})

	t.Run("mismatched team id is unconfirmed", func(t *testing.T) {
		seen(t, at.tenantID, macApp("com.example.teamcheck", "REALTEAM01"))
		out := refused(t, at.adminToken, approvalBody("approved", "", macApp("com.example.teamcheck", "FAKETEAM01")), http.StatusUnprocessableEntity, "unconfirmed_identity")
		if len(out.Items) != 1 || out.Items[0].Code != "unconfirmed_identity" {
			t.Fatalf("items = %+v", out.Items)
		}
		// The observed pair is accepted.
		mustApprove(t, at.adminToken, approvalBody("approved", "", macApp("com.example.teamcheck", "REALTEAM01")))
	})
	t.Run("team id with no inventory evidence at all is unconfirmed", func(t *testing.T) {
		refused(t, at.adminToken, approvalBody("approved", "", macApp("com.example.neverseen", "NEVERSEEN1")), http.StatusUnprocessableEntity, "unconfirmed_identity")
	})
}
