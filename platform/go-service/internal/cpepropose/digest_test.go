package cpepropose

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildDigest(t *testing.T) {
	now := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)
	fresh := DigestItem{ID: 7, DisplayName: "Notion", Platform: "macos", Reason: ReasonMatchNameTooBroad,
		ModelChoice: "notion:notion", FirstSeenAt: now.Add(-3 * time.Hour), AffectedDevices: 4, AffectedTenants: 2}

	empty := BuildDigest(nil, now, "ok", "")
	if empty.Count != 0 || empty.Escalated || empty.Title != "0 CVE mappings awaiting review" ||
		!strings.Contains(empty.Body, "queue is empty") || !strings.HasPrefix(empty.Body, DigestMarker) {
		t.Fatalf("empty digest = %+v", empty)
	}

	one := BuildDigest([]DigestItem{fresh}, now, "ok", "")
	if one.Title != "1 CVE mapping awaiting review" || one.Escalated || one.Priority != 3 {
		t.Fatalf("one-item digest = %+v", one)
	}
	if !strings.Contains(one.Body, "`Notion` (#7)") || !strings.Contains(one.Body, "name would cover other products") {
		t.Fatalf("one-item body:\n%s", one.Body)
	}

	// Exactly 48 hours is not yet overdue; a minute past is.
	at48 := fresh
	at48.FirstSeenAt = now.Add(-48 * time.Hour)
	if d := BuildDigest([]DigestItem{at48}, now, "ok", ""); d.Escalated {
		t.Fatal("escalated at exactly 48h")
	}
	at49 := fresh
	at49.FirstSeenAt = now.Add(-49 * time.Hour)
	if d := BuildDigest([]DigestItem{at49}, now, "ok", ""); !d.Escalated || d.Priority != 2 {
		t.Fatalf("not escalated at 49h: %+v", d)
	}
	old := fresh
	old.ID = 8
	old.FirstSeenAt = now.Add(-73 * time.Hour)
	esc := BuildDigest([]DigestItem{old, fresh}, now, "degraded", ReasonModelUnavailable)
	if !esc.Escalated || esc.Priority != 2 || esc.Title != "2 CVE mappings awaiting review, oldest 3d (overdue)" {
		t.Fatalf("escalated digest = %+v", esc)
	}
	if !strings.Contains(esc.Body, "**Escalated:**") || !strings.Contains(esc.Body, "Proposer degraded (model_unavailable)") {
		t.Fatalf("escalated body:\n%s", esc.Body)
	}
}

// Product names are endpoint data: they must not break out of the table or
// the code span into Linear markdown.
func TestBuildDigestSanitisesProductNames(t *testing.T) {
	now := time.Now()
	hostile := DigestItem{ID: 1, DisplayName: "Evil` | [click](https://x) <script>\n# heading", Platform: "macos",
		FirstSeenAt: now, AffectedTenants: 2}
	d := BuildDigest([]DigestItem{hostile}, now, "ok", "")
	for _, line := range strings.Split(d.Body, "\n") {
		if strings.HasPrefix(line, "# heading") {
			t.Fatalf("newline in a product name started a markdown line:\n%s", d.Body)
		}
	}
	if strings.Contains(d.Body, "<script>") || strings.Contains(d.Body, "Evil`") {
		t.Fatalf("unsanitised name in body:\n%s", d.Body)
	}
	row := ""
	for _, line := range strings.Split(d.Body, "\n") {
		if strings.Contains(line, "(#1)") {
			row = line
		}
	}
	if strings.Count(row, "|") != 8 {
		t.Fatalf("table row has %d pipes, want 8: %q", strings.Count(row, "|"), row)
	}
}

// fakeLinear records GraphQL operations and answers them.
type fakeLinear struct {
	ops         []string
	issueState  string // "" (none) or a state type
	description string
	title       string
	priority    float64
	// foreign is an open issue carrying the marker that another user
	// created. The fake ignores the creator filter on purpose, so the
	// client's own check is what keeps it out.
	foreign     bool
	viewerAsked bool
}

func (f *fakeLinear) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "lin-test" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(raw, &req)
		q := req.Query
		var data any
		switch {
		case strings.Contains(q, "teams("):
			f.ops = append(f.ops, "team")
			data = map[string]any{"teams": map[string]any{"nodes": []any{map[string]any{"id": "team-1"}}}}
		case strings.Contains(q, "viewer {"):
			f.viewerAsked = true
			data = map[string]any{"viewer": map[string]any{"id": "user-bot"}}
		case strings.Contains(q, "issues("):
			f.ops = append(f.ops, "find")
			if req.Variables["viewerId"] != "user-bot" || !strings.Contains(q, "creator: { id: { eq: $viewerId } }") {
				t.Errorf("issue search is not scoped to the token's viewer: %s %v", q, req.Variables)
			}
			nodes := []any{}
			if f.foreign {
				nodes = append(nodes, map[string]any{"id": "issue-foreign", "description": DigestMarker + " pasted by someone",
					"creator": map[string]any{"id": "user-someone-else"}})
			}
			if f.issueState == "started" {
				nodes = append(nodes, map[string]any{"id": "issue-1", "description": f.description,
					"creator": map[string]any{"id": "user-bot"}})
			}
			data = map[string]any{"issues": map[string]any{"nodes": nodes}}
		case strings.Contains(q, "issue(id"):
			f.ops = append(f.ops, "get")
			if f.issueState == "" {
				data = map[string]any{"issue": nil}
			} else {
				data = map[string]any{"issue": map[string]any{"state": map[string]any{"type": f.issueState}}}
			}
		case strings.Contains(q, "issueCreate"):
			f.ops = append(f.ops, "create")
			f.issueState, f.title, f.description = "started", req.Variables["title"].(string), req.Variables["description"].(string)
			f.priority = req.Variables["priority"].(float64)
			data = map[string]any{"issueCreate": map[string]any{"success": true, "issue": map[string]any{"id": "issue-1", "identifier": "PAT-9999"}}}
		case strings.Contains(q, "workflowStates"):
			f.ops = append(f.ops, "states")
			data = map[string]any{"workflowStates": map[string]any{"nodes": []any{map[string]any{"id": "done-1"}}}}
		case strings.Contains(q, "stateId"):
			f.ops = append(f.ops, "close")
			f.issueState, f.description = "completed", req.Variables["description"].(string)
			data = map[string]any{"issueUpdate": map[string]any{"success": true}}
		case strings.Contains(q, "issueUpdate"):
			f.ops = append(f.ops, "update")
			f.title, f.description = req.Variables["title"].(string), req.Variables["description"].(string)
			f.priority = req.Variables["priority"].(float64)
			data = map[string]any{"issueUpdate": map[string]any{"success": true}}
		default:
			t.Errorf("unexpected query %s", q)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The digest adopts only an issue its own token created: a marker pasted
// into somebody else's issue must never let the digest retitle or close it.
func TestLinearClientFindOpenIssueIgnoresOtherCreators(t *testing.T) {
	f := &fakeLinear{foreign: true}
	srv := f.server(t)
	c := &LinearClient{Endpoint: srv.URL, Token: "lin-test", TeamKey: "PAT", HTTP: srv.Client()}
	id, err := c.FindOpenIssue(context.Background(), DigestMarker)
	if err != nil || id != "" {
		t.Fatalf("FindOpenIssue = %q, %v; want no issue (the only marker issue is someone else's)", id, err)
	}
	if !f.viewerAsked {
		t.Fatal("FindOpenIssue never asked Linear who the token's user is")
	}
	f.issueState, f.description = "started", DigestMarker+" body"
	if id, err := c.FindOpenIssue(context.Background(), DigestMarker); err != nil || id != "issue-1" {
		t.Fatalf("FindOpenIssue = %q, %v; want its own issue-1", id, err)
	}
}

func TestLinearClientIssueLifecycle(t *testing.T) {
	f := &fakeLinear{}
	srv := f.server(t)
	c := &LinearClient{Endpoint: srv.URL, Token: "lin-test", TeamKey: "PAT", HTTP: srv.Client()}
	ctx := context.Background()
	if id, err := c.FindOpenIssue(ctx, DigestMarker); err != nil || id != "" {
		t.Fatalf("find before create = %q, %v", id, err)
	}
	id, ident, err := c.CreateIssue(ctx, "2 CVE mappings awaiting review", DigestMarker+" body", 3)
	if err != nil || id != "issue-1" || ident != "PAT-9999" {
		t.Fatalf("create = %q %q %v", id, ident, err)
	}
	if open, err := c.IssueOpen(ctx, id); err != nil || !open {
		t.Fatalf("open after create = %v, %v", open, err)
	}
	if err := c.UpdateIssue(ctx, id, "3 CVE mappings awaiting review", "b2", 2); err != nil || f.priority != 2 {
		t.Fatalf("update err=%v priority=%v", err, f.priority)
	}
	if err := c.CloseIssue(ctx, id, "empty"); err != nil {
		t.Fatal(err)
	}
	if open, _ := c.IssueOpen(ctx, id); open {
		t.Fatal("issue still open after close")
	}
	if got := strings.Join(f.ops, ","); got != "team,find,create,get,update,states,close,get" {
		t.Fatalf("operations = %s", got)
	}
	if NewLinearClient("", "PAT") != nil {
		t.Fatal("NewLinearClient without a token must return nil")
	}
}

// A single_tenant proposal may be a customer's in-house software: the
// digest (which goes to Linear, outside the platform) never names it, never
// counts it in the title and never escalates on it; it says only how many
// are held back.
func TestBuildDigestHoldsBackPrivateProducts(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	private := DigestItem{ID: 7, DisplayName: "Acme Payroll Internal", Platform: "windows",
		Reason: "single_tenant", FirstSeenAt: now.Add(-100 * time.Hour), AffectedTenants: 1}
	public := DigestItem{ID: 8, DisplayName: "Notion", Platform: "macos", Reason: "signer_not_aliased",
		FirstSeenAt: now.Add(-time.Hour), AffectedTenants: 2}
	d := BuildDigest([]DigestItem{private, public}, now, "ok", "")
	if strings.Contains(d.Body, "Acme Payroll") || strings.Contains(d.Body, "(#7)") {
		t.Fatalf("private product named in the digest:\n%s", d.Body)
	}
	if d.Escalated || d.Priority != 3 || d.Count != 1 || !strings.HasPrefix(d.Title, "1 CVE mapping awaiting review") {
		t.Fatalf("digest = count %d escalated %v priority %d title %q; the private item must not count or escalate",
			d.Count, d.Escalated, d.Priority, d.Title)
	}
	if !strings.Contains(d.Body, "1 product held back (reported by fewer than two customers)") {
		t.Fatalf("no aggregate held-back line:\n%s", d.Body)
	}
	only := BuildDigest([]DigestItem{private}, now, "ok", "")
	if strings.Contains(only.Body, "Acme Payroll") || only.Escalated || only.Count != 0 {
		t.Fatalf("private-only digest = %+v", only)
	}
}

// Every proposal fewer than two tenants report is held back, whatever its
// reason: a Chrome web-app wrapper for one customer's intranet ("Acme Corp
// HR Portal", signed with Google's Team ID) waiting as signer_not_aliased
// must not reach Linear by name either.
func TestBuildDigestHoldsBackEverySingleTenantProposal(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	wrapper := DigestItem{ID: 9, DisplayName: "Acme Corp HR Portal", Platform: "macos",
		Reason: "signer_vendor_mismatch", FirstSeenAt: now.Add(-100 * time.Hour), AffectedTenants: 1}
	d := BuildDigest([]DigestItem{wrapper}, now, "ok", "")
	if strings.Contains(d.Body, "Acme Corp") || d.Count != 0 || d.Escalated || d.HeldBack != 1 {
		t.Fatalf("single-tenant proposal reached the digest: count %d held %d escalated %v\n%s",
			d.Count, d.HeldBack, d.Escalated, d.Body)
	}
}
