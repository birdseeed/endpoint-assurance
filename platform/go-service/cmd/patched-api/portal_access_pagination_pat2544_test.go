package main

// PAT-2544 exercises bounded access-management reads through the production
// router, PostgreSQL and verified person/service JWTs. All rows are synthetic.
import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

func pat2544Snapshot(t *testing.T, f *signupFx, tenant string) string {
	t.Helper()
	return f.text(t, `SELECT jsonb_build_object(
		'members', (SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY email), '[]') FROM portal_users p WHERE tenant_id=$1::uuid),
		'invitations', (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY id), '[]') FROM portal_invitations i WHERE tenant_id=$1::uuid),
		'audit', (SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id), '[]') FROM portal_access_audit a WHERE tenant_id=$1::uuid)
	)::text`, tenant)
}

func pat2544Page(t *testing.T, r pat1883Resp, total, limit, offset, count int) []map[string]any {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("access page = %d: %s", r.Code, r.Raw)
	}
	for key, want := range map[string]int{"members_total": total, "members_limit": limit, "members_offset": offset} {
		if got, ok := r.JSON[key].(float64); !ok || got != float64(want) {
			t.Fatalf("%s = %v, want %d; %s", key, r.JSON[key], want, r.Raw)
		}
	}
	if got, ok := r.JSON["members_truncated"].(bool); !ok || got != (count < total) {
		t.Fatalf("members_truncated = %v, want %t", r.JSON["members_truncated"], count < total)
	}
	rows, ok := r.JSON["members"].([]any)
	if !ok || len(rows) != count {
		t.Fatalf("members count = %d, want %d", len(rows), count)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		member, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("invalid member: %v", row)
		}
		out = append(out, member)
	}
	return out
}

func TestPAT2544AccessPagesIncludeDisabledAndStableTies(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	foreign := f.newOrg(t, on)
	admin := f.member(t, org.Tenant, "admin")
	// More than the maximum page size. Reverse insertion deliberately differs
	// from the required created_at/email ordering. All timestamps tie.
	f.exec(t, `INSERT INTO portal_users (email, tenant_id, role, created_at, disabled_at, disabled_by)
		SELECT 'member-' || lpad(n::text, 4, '0') || '@' || $2 || '.pat1883.invalid', $1::uuid, 'viewer',
		       '2026-07-01'::timestamptz,
		       CASE WHEN n % 3 = 0 THEN '2026-07-02'::timestamptz END,
		       CASE WHEN n % 3 = 0 THEN 'operator' END
		FROM generate_series(1, 503) n ORDER BY n DESC`, org.Tenant, pat1883Rand())
	f.exec(t, `UPDATE portal_users SET created_at='2026-07-01' WHERE tenant_id=$1::uuid`, org.Tenant)
	f.member(t, foreign.Tenant, "viewer")
	before, foreignBefore := pat2544Snapshot(t, f, org.Tenant), pat2544Snapshot(t, f, foreign.Tenant)
	owner := f.token(t, org.Owner)
	pat2544Page(t, f.do(t, on, "GET", "/v1/portal/access", owner, nil), 505, 100, 0, 100)
	pat2544Page(t, f.do(t, on, "GET", "/v1/portal/access?limit=500", owner, nil), 505, 500, 0, 500)
	pat2544Page(t, f.do(t, on, "GET", "/v1/portal/access?limit=1&offset=2147483647", owner, nil), 505, 1, 2147483647, 0)
	var emails []string
	disabled := 0
	seen := map[string]bool{}
	for offset := 0; offset < 505; offset += 73 {
		count := 73
		if 505-offset < count {
			count = 505 - offset
		}
		url := fmt.Sprintf("/v1/portal/access?limit=73&offset=%d", offset)
		r := f.do(t, on, "GET", url, owner, nil)
		rows := pat2544Page(t, r, 505, 73, offset, count)
		// Repeated reads of a tied boundary must produce the same page.
		if again := f.do(t, on, "GET", url, owner, nil); again.Raw != r.Raw {
			t.Fatalf("page at %d changed without a write", offset)
		}
		for _, row := range rows {
			email, _ := row["email"].(string)
			if email == "" || seen[email] || email == foreign.Owner {
				t.Fatalf("empty, duplicated or foreign member: %v", row)
			}
			seen[email] = true
			emails = append(emails, email)
			if row["status"] == "disabled" {
				disabled++
				if row["disabled_by"] != "operator" || row["disabled_at"] == nil {
					t.Fatalf("disabled member lost its state: %v", row)
				}
			}
		}
	}
	if len(seen) != 505 || disabled != 167 || !sort.StringsAreSorted(emails) {
		t.Fatalf("traversal: distinct=%d disabled=%d ordered=%t", len(seen), disabled, sort.StringsAreSorted(emails))
	}
	pat2544Page(t, f.do(t, on, "GET", "/v1/portal/access?limit=73&offset=505", owner, nil), 505, 73, 505, 0)
	pat2544Page(t, f.do(t, on, "GET", "/v1/portal/access?limit=1&offset=504", f.token(t, admin), nil), 505, 1, 504, 1)
	if pat2544Snapshot(t, f, org.Tenant) != before || pat2544Snapshot(t, f, foreign.Tenant) != foreignBefore {
		t.Fatal("access reads changed membership, invitations or access audit")
	}
}

func TestPAT2544InvitationCapHasSeparateCompleteness(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	foreign := f.newOrg(t, on)
	f.exec(t, `INSERT INTO portal_invitations (tenant_id, email, role, invited_by_email, created_at, expires_at)
		SELECT $1::uuid, 'invite-' || n || '@' || $3 || '.pat1883.invalid', 'viewer', $2,
		       '2026-07-01'::timestamptz, '2027-07-01'::timestamptz
		FROM generate_series(1, 503) n`, org.Tenant, org.Owner, pat1883Rand())
	f.exec(t, `INSERT INTO portal_invitations (tenant_id, email, role, invited_by_email, expires_at)
		VALUES ($1::uuid, $2, 'viewer', $3, now()+interval '1 day')`, foreign.Tenant, pat1883Email("foreign"), foreign.Owner)
	before := pat2544Snapshot(t, f, org.Tenant)
	for _, tenant := range []pat1883Org{org, foreign} {
		r := f.do(t, on, "GET", "/v1/portal/access?limit=1&offset=9", f.token(t, tenant.Owner), nil)
		pat2544Page(t, r, 1, 1, 9, 0)
		total, count := 503, 500
		if tenant.Tenant == foreign.Tenant {
			total, count = 1, 1
		}
		if r.JSON["invitations_total"] != float64(total) || r.JSON["invitations_limit"] != float64(500) || r.JSON["invitations_truncated"] != (total > count) {
			t.Fatalf("invitation completeness: %s", r.Raw)
		}
		rows, ok := r.JSON["invitations"].([]any)
		if !ok || len(rows) != count {
			t.Fatalf("invitation count=%d, want %d", len(rows), count)
		}
	}
	if pat2544Snapshot(t, f, org.Tenant) != before {
		t.Fatal("invitation reads changed state")
	}
}

func TestPAT2544AccessPageValidationAndIdentityBoundary(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	viewer := f.member(t, org.Tenant, "viewer")
	disabled := f.member(t, org.Tenant, "admin")
	f.admin(t, "DELETE", "/admin/portal-users/"+disabled, nil).want(t, "disable admin", http.StatusOK, "")
	owner := f.token(t, org.Owner)
	before := pat2544Snapshot(t, f, org.Tenant)
	for _, query := range []string{
		"limit=0", "limit=501", "limit=-1", "limit=", "limit=abc", "limit=1.5", "limit=999999999999999999999999",
		"offset=-1", "offset=2147483648", "offset=", "offset=abc", "offset=1.5",
		"limit=1&limit=2", "offset=0&offset=1", "page=1", "tenant_id=" + org.Tenant,
	} {
		r := f.do(t, on, "GET", "/v1/portal/access?"+query, owner, nil)
		if r.Code != http.StatusBadRequest || r.JSON["members"] != nil || r.JSON["invitations"] != nil {
			t.Fatalf("query %q = %d: %s, want 400 without access data", query, r.Code, r.Raw)
		}
	}
	for name, token := range map[string]string{
		"viewer": f.token(t, viewer), "disabled admin": f.token(t, disabled),
		"service": f.serviceToken(t), "unknown identity": f.token(t, pat1883Email("unknown")),
	} {
		for _, query := range []string{"limit=1&offset=0", "limit=bad"} {
			r := f.do(t, on, "GET", "/v1/portal/access?"+query, token, nil)
			if r.Code != http.StatusForbidden || strings.Contains(r.Raw, org.Owner) || r.JSON["members"] != nil {
				t.Fatalf("%s query %q = %d: %s", name, query, r.Code, r.Raw)
			}
		}
	}
	if pat2544Snapshot(t, f, org.Tenant) != before {
		t.Fatal("refused reads changed access state")
	}
}
