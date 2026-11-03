//go:build integration

package integration

// PAT-1883 over real HTTP, on the database TestMain migrated from zero.
//
// The feature's behaviour is tested through the production router in
// cmd/patched-api. What belongs here is what only this harness has: every
// migration applied in order to an empty database, and requests over a real
// listener.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Migrations 0229 and 0230 applied from zero leave the schema the handlers
// need, with the guards attached.
func TestPAT1883SchemaFromZero(t *testing.T) {
	ctx := context.Background()
	for what, sql := range map[string]string{
		"portal_users.role accepts owner, admin, viewer": `
			SELECT pg_get_constraintdef(oid) LIKE '%owner%admin%viewer%' FROM pg_constraint
			WHERE conrelid = 'portal_users'::regclass AND conname = 'portal_users_role_check'`,
		"feedback.reporter_role accepts owner": `
			SELECT count(*) = 1 AND bool_and(pg_get_constraintdef(oid) LIKE '%owner%') FROM pg_constraint
			WHERE conrelid = 'feedback'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%reporter_role%'`,
		"portal_users.disabled_by is nullable, has no default and is checked against disabled_at": `
			SELECT (SELECT is_nullable = 'YES' AND column_default IS NULL AND data_type = 'text' FROM information_schema.columns
			         WHERE table_name = 'portal_users' AND column_name = 'disabled_by')
			   AND (SELECT pg_get_constraintdef(oid) LIKE '%disabled_by IS NULL%operator%owner%disabled_at IS NOT NULL%' FROM pg_constraint
			         WHERE conrelid = 'portal_users'::regclass AND conname = 'portal_users_disabled_by_check')`,
		"tenants.created_via defaults to operator for existing tenants": `
			SELECT created_via = 'operator' FROM tenants WHERE id = '` + env.tenantID + `'::uuid`,
		"tenants.created_via is constrained": `
			SELECT pg_get_constraintdef(oid) LIKE '%operator%self_service%' FROM pg_constraint
			WHERE conrelid = 'tenants'::regclass AND conname = 'tenants_created_via_check'`,
		"portal_invitations cascades from tenants": `
			SELECT confdeltype = 'c' FROM pg_constraint
			WHERE conrelid = 'portal_invitations'::regclass AND contype = 'f' AND confrelid = 'tenants'::regclass`,
		"one pending invitation per tenant and address": `
			SELECT indexdef LIKE '%UNIQUE%(tenant_id, email)%pending%' FROM pg_indexes WHERE indexname = 'uq_portal_invitations_pending'`,
		"portal_access_audit has no foreign key": `
			SELECT count(*) = 0 FROM pg_constraint WHERE conrelid = 'portal_access_audit'::regclass AND contype = 'f'`,
		"portal_access_audit is guarded against UPDATE, DELETE and TRUNCATE": `
			SELECT count(*) = 2 FROM pg_trigger WHERE tgrelid = 'portal_access_audit'::regclass AND NOT tgisinternal AND tgenabled = 'O'
			AND tgname IN ('trg_portal_access_audit_append_only', 'trg_portal_access_audit_append_only_truncate')`,
		"the tenant purge redaction trigger is attached": `
			SELECT count(*) = 1 FROM pg_trigger WHERE tgrelid = 'tenants'::regclass AND NOT tgisinternal AND tgenabled = 'O'
			AND tgname = 'trg_tenants_redact_portal_access_audit_before_purge'`,
		"the application role can write invitations": `
			SELECT has_table_privilege('patched', 'portal_invitations', 'SELECT, INSERT, UPDATE, DELETE')`,
		"the application role can append to the ledger": `
			SELECT has_table_privilege('patched', 'portal_access_audit', 'SELECT, INSERT')
			   AND has_sequence_privilege('patched', 'portal_access_audit_id_seq', 'USAGE')`,
		"both migrations are recorded": `
			SELECT count(*) = 2 FROM schema_migrations
			WHERE version IN ('0229_portal_owner_role', '0230_portal_invitations_and_access_audit')`,
	} {
		var ok *bool
		if err := env.pool.QueryRow(ctx, sql).Scan(&ok); err != nil || ok == nil || !*ok {
			t.Errorf("%s: not so (err %v)", what, err)
		}
	}
}

// 0229 and 0230, and their rollbacks, take table locks that conflict with the
// portal's and the ingest path's ordinary work. Each bounds how long it will
// wait for one: the first thing its transaction does is set a 30 second
// lock_timeout, so a deploy behind a long transaction fails cleanly with
// nothing applied instead of queueing every sign-in and ingest behind it.
// This pins the statement and its position. That the bound works (cancelled
// at 30 seconds, nothing applied, a retry succeeds) is shown with psql against
// each file; TestMain has already run the two forward files as they are.
func TestPAT1883MigrationsBoundTheirLockWait(t *testing.T) {
	for _, name := range []string{
		"0229_portal_owner_role.sql", "0229_portal_owner_role_rollback.sql",
		"0230_portal_invitations_and_access_audit.sql", "0230_portal_invitations_and_access_audit_rollback.sql",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		// Statements in order, comments and blank lines dropped. Good enough
		// for the head of these files: nothing before the first lock is a
		// dollar-quoted body.
		var stmts []string
		var cur strings.Builder
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.Index(line, "--"); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			cur.WriteString(line + " ")
			if strings.HasSuffix(line, ";") {
				stmts = append(stmts, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			if len(stmts) == 2 {
				break
			}
		}
		if len(stmts) < 2 || stmts[0] != "BEGIN;" {
			t.Errorf("%s: does not open with BEGIN: %q", name, stmts)
			continue
		}
		if stmts[1] != "SET LOCAL lock_timeout = '30s';" {
			t.Errorf("%s: the first statement of the transaction is %q, want SET LOCAL lock_timeout = '30s'; so no lock is asked for without a bound on the wait", name, stmts[1])
		}
		// LOCAL: the setting must end with the transaction, not leak into
		// whatever the same session runs next.
		if n := strings.Count(strings.ToLower(string(raw)), "set lock_timeout") + strings.Count(strings.ToLower(string(raw)), "set session lock_timeout"); n != 0 {
			t.Errorf("%s: sets lock_timeout for the session, not the transaction", name)
		}
	}
}

// With SELF_SERVICE_SIGNUP_ENABLED unset, which is how this harness and
// production run, the sign-up and access routes are 404 for anyone verified,
// the operator route does not make an owner, and an owner row that exists is
// still an owner everywhere else.
func TestPAT1883OffByDefaultAndOwnerRecognisedOverHTTP(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat1883-http-"+randomHex(4))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	suffix := randomHex(4)
	owner, viewer, stranger := "owner-"+suffix+"@pat1883.example", "viewer-"+suffix+"@pat1883.example", "stranger-"+suffix+"@pat1883.example"
	// The operator route does not make an owner while the flag is off, so the
	// owner row is put there directly: what is under test from here on is that
	// an owner row which exists is honoured.
	if code, b := postPortalUser(t, fmt.Sprintf(`{"email":%q,"tenant_id":%q,"role":"owner"}`, owner, tenantID)); code != http.StatusBadRequest {
		t.Fatalf("operator owner grant with the feature off = %d %s, want 400", code, b)
	}
	if _, err := env.pool.Exec(context.Background(),
		`INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'owner')`, owner, tenantID); err != nil {
		t.Fatalf("insert owner row: %v", err)
	}
	mapPortalUserWithRole(t, viewer, tenantID, "viewer")

	status := func(method, path, email, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		token := ""
		if email != "" {
			token = env.idp.token(t, email)
		}
		resp := portalDo(t, method, path, token, rdr)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	for _, route := range [][2]string{
		{"GET", "/v1/portal/signup/state"},
		{"POST", "/v1/portal/signup/organisation"},
		{"POST", "/v1/portal/signup/invitations/00000000-0000-4000-8000-000000000000/accept"},
	} {
		for _, who := range []string{stranger, owner, viewer} {
			if code, body := status(route[0], route[1], who, `{"name":"PAT1883 HTTP"}`); code != http.StatusNotFound {
				t.Errorf("%s %s as %s = %d %s, want 404 (feature off)", route[0], route[1], who, code, body)
			}
		}
		if code, _ := status(route[0], route[1], "", ""); code != http.StatusUnauthorized {
			t.Errorf("%s %s with no token = %d, want 401", route[0], route[1], code)
		}
	}
	for _, route := range [][2]string{
		{"GET", "/v1/portal/access"},
		{"POST", "/v1/portal/access/invitations"},
		{"POST", "/v1/portal/access/invitations/00000000-0000-4000-8000-000000000000/revoke"},
		{"PUT", "/v1/portal/access/members/" + viewer + "/role"},
		{"POST", "/v1/portal/access/members/" + viewer + "/disable"},
		{"POST", "/v1/portal/access/members/" + viewer + "/enable"},
	} {
		for _, who := range []string{owner, viewer} {
			if code, body := status(route[0], route[1], who, `{"email":"x@pat1883.example","role":"viewer"}`); code != http.StatusNotFound {
				t.Errorf("%s %s as %s = %d %s, want 404 (feature off)", route[0], route[1], who, code, body)
			}
		}
		// A person who belongs to no tenant never gets past the tenant middleware.
		if code, _ := status(route[0], route[1], stranger, `{}`); code != http.StatusForbidden {
			t.Errorf("%s %s as a non-member = %d, want 403", route[0], route[1], code)
		}
	}
	var n int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenants WHERE name = 'PAT1883 HTTP'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a tenant was created with the feature off (%d, %v)", n, err)
	}

	// The owner role itself does not depend on the flag.
	if code, body := status("GET", "/v1/portal/me", owner, ""); code != http.StatusOK || !strings.Contains(body, `"role":"owner"`) {
		t.Fatalf("GET /me as owner = %d %s", code, body)
	}
	const settings = `{"unapproved_alerts_enabled":true,"new_software_enabled":false}`
	if code, body := status("PUT", "/v1/portal/software-notifications", owner, settings); code != http.StatusOK {
		t.Errorf("owner admin-level write = %d %s, want 200", code, body)
	}
	if code, body := status("PUT", "/v1/portal/software-notifications", viewer, settings); code != http.StatusForbidden || !strings.Contains(body, "admin_role_required") {
		t.Errorf("viewer admin-level write = %d %s, want 403 admin_role_required", code, body)
	}
	// An admin-only read: the report catalogue offers the Local Admin report
	// to an owner and not to a viewer.
	if code, body := status("GET", "/v1/portal/reports/catalogue", owner, ""); code != http.StatusOK || !strings.Contains(body, `"local-admin"`) {
		t.Errorf("owner's report catalogue = %d, offers local-admin: %v; want 200 and offered", code, strings.Contains(body, `"local-admin"`))
	}
	if code, body := status("GET", "/v1/portal/reports/catalogue", viewer, ""); code != http.StatusOK || strings.Contains(body, `"local-admin"`) {
		t.Errorf("viewer's report catalogue = %d, offers local-admin: %v; want 200 and not offered", code, strings.Contains(body, `"local-admin"`))
	}
}
