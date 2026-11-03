package feedback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// discoverySuccessBody returns the default success response for one of
// discover()'s four split queries, or "" if query doesn't match one.
func discoverySuccessBody(query, team, project, state string) string {
	switch {
	case strings.Contains(query, "teams("):
		return `{"data":{"teams":{"nodes":[{"id":"` + team + `"}]}}}`
	case strings.Contains(query, "projects("):
		return `{"data":{"projects":{"nodes":[{"id":"` + project + `"}]}}}`
	case strings.Contains(query, "workflowStates("):
		return `{"data":{"workflowStates":{"nodes":[{"id":"` + state + `"}]}}}`
	case strings.Contains(query, "issueLabels("):
		return `{"data":{"issueLabels":{"nodes":[` +
			`{"id":"a","name":"source:portal","team":{"id":"` + team + `"}},` +
			`{"id":"b","name":"needs-triage","team":{"id":"` + team + `"}},` +
			`{"id":"c","name":"Bug","team":{"id":"` + team + `"}},` +
			`{"id":"d","name":"Feature","team":{"id":"` + team + `"}}` +
			`]}}}`
	default:
		return ""
	}
}

func TestLinearDiscoveryRetryDoesNotPoisonCache(t *testing.T) {
	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if strings.Contains(in.Query, "teams(") {
			attempt++
			_, _ = w.Write([]byte(discoverySuccessBody(in.Query, "team", "project", "backlog")))
			return
		}
		if strings.Contains(in.Query, "projects(") && attempt == 1 {
			// First discover() attempt: team resolves but the project is
			// missing, so discover() must fail without ever caching team.
			_, _ = w.Write([]byte(`{"data":{"projects":{"nodes":[]}}}`))
			return
		}
		if body := discoverySuccessBody(in.Query, "team", "project", "backlog"); body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		t.Errorf("unexpected discovery query: %s", in.Query)
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()
	if err := c.discover(context.Background()); err == nil {
		t.Fatal("incomplete discovery accepted")
	}
	if c.team != "" {
		t.Fatalf("failed discovery poisoned cache: %q", c.team)
	}
	if err := c.discover(context.Background()); err != nil {
		t.Fatalf("retry discovery: %v", err)
	}
	if c.team != "team" || c.project != "project" || c.state != "backlog" {
		t.Fatalf("incomplete retry cache: %#v", c)
	}
}

func TestLinearDiscoveryRejectsMissingOrAmbiguousRequiredResources(t *testing.T) {
	for _, tc := range []struct{ name, teams, projects, states, labels string }{
		{name: "no team", teams: `{"data":{"teams":{"nodes":[]}}}`},
		{name: "two teams", teams: `{"data":{"teams":{"nodes":[{"id":"t1"},{"id":"t2"}]}}}`},
		{name: "missing project", projects: `{"data":{"projects":{"nodes":[]}}}`},
		{name: "ambiguous project", projects: `{"data":{"projects":{"nodes":[{"id":"p1"},{"id":"p2"}]}}}`},
		{name: "missing Backlog state", states: `{"data":{"workflowStates":{"nodes":[]}}}`},
		{name: "ambiguous Backlog state", states: `{"data":{"workflowStates":{"nodes":[{"id":"s1"},{"id":"s2"}]}}}`},
		{name: "missing label", labels: `{"data":{"issueLabels":{"nodes":[{"id":"b","name":"needs-triage","team":{"id":"t"}},{"id":"c","name":"Bug","team":{"id":"t"}},{"id":"d","name":"Feature","team":{"id":"t"}}]}}}`},
		{name: "duplicate team-scoped Bug label", labels: `{"data":{"issueLabels":{"nodes":[{"id":"a","name":"source:portal","team":{"id":"t"}},{"id":"b","name":"needs-triage","team":{"id":"t"}},{"id":"c1","name":"Bug","team":{"id":"t"}},{"id":"c2","name":"Bug","team":{"id":"t"}},{"id":"d","name":"Feature","team":{"id":"t"}}]}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Query string `json:"query"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				switch {
				case strings.Contains(in.Query, "teams(") && tc.teams != "":
					_, _ = w.Write([]byte(tc.teams))
				case strings.Contains(in.Query, "projects(") && tc.projects != "":
					_, _ = w.Write([]byte(tc.projects))
				case strings.Contains(in.Query, "workflowStates(") && tc.states != "":
					_, _ = w.Write([]byte(tc.states))
				case strings.Contains(in.Query, "issueLabels(") && tc.labels != "":
					_, _ = w.Write([]byte(tc.labels))
				default:
					if body := discoverySuccessBody(in.Query, "t", "p", "s"); body != "" {
						_, _ = w.Write([]byte(body))
						return
					}
					t.Errorf("unexpected discovery query: %s", in.Query)
				}
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint = srv.URL
			c.HTTP = srv.Client()
			if c.discover(context.Background()) == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

func TestLinearConcurrentCreateUsesCompleteDiscovery(t *testing.T) {
	var mu sync.Mutex
	creates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.Header.Get("Authorization") != "key" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing Linear auth/json headers")
		}
		if body := discoverySuccessBody(in.Query, "t", "p", "s"); body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		if strings.Contains(in.Query, "issues(filter") {
			if creates > 0 {
				_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[{"id":"i","identifier":"PAT-1","description":"<!-- feedback-id: FB-123 -->\nbody","team":{"id":"t"},"project":{"id":"p"},"state":{"name":"Backlog"}}]}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
			return
		}
		creates++
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"i","identifier":"PAT-1","state":{"name":"Backlog"}}}}}`))
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()
	c2 := NewLinearClient("key")
	c2.Endpoint, c2.HTTP = srv.URL, srv.Client()
	clients := []*LinearClient{c, c2}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		client := clients[i%len(clients)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, key, state, e := client.createWithState(context.Background(), Submission{Reference: "FB-123", Type: TypeBug, Title: "Valid title", Description: "x", Severity: SeverityLow})
			if e != nil || id != "i" || key != "PAT-1" || state == nil || *state != "Backlog" {
				t.Errorf("concurrent result: %q,%q,%v,%v", id, key, state, e)
			}
		}()
	}
	wg.Wait()
	if creates != 1 {
		t.Fatalf("creates=%d", creates)
	}
}

func TestLinearDiscoveryAndCreateContract(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if body := discoverySuccessBody(in.Query, "team", "project", "backlog"); body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		if strings.Contains(in.Query, "issues(filter") {
			_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
			return
		}
		created = true
		v := in.Variables["i"].(map[string]any)
		if v["teamId"] != "team" || v["projectId"] != "project" || v["stateId"] != "backlog" || v["title"] != "[FB-123] Valid title" {
			t.Errorf("bad create payload %#v", v)
		}
		d := v["description"].(string)
		if strings.Contains(d, "person@example.test") || strings.Contains(d, "Planted Person") || strings.Contains(d, "```bad") {
			t.Errorf("unsafe body %q", d)
		}
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"issue","identifier":"PAT-1"}}}}`))
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()
	s := Submission{Reference: "FB-123", Type: TypeBug, Title: "Valid title", Description: "```bad", Severity: SeverityLow, TenantDisplaySlug: "tenant", ReporterRole: "viewer", ReporterEmail: "person@example.test", ReporterName: "Planted Person", SubmittedAt: time.Now()}
	id, key, e := c.create(context.Background(), s)
	if e != nil || id != "issue" || key != "PAT-1" || !created {
		t.Fatalf("create=%q,%q,%v", id, key, e)
	}
}

// TestLinearDiscoveryRejectsOverlyComplexSingleQuery pins the production
// incident (2026-09-28): Linear answers a discover() query that nests
// projects()/states()/labels() three connections deep under teams() with
// HTTP 400 "Query too complex". A stub that emulates that limit must still
// let discovery succeed, proving discover() issues small, separately
// bounded queries instead of one oversized one.
func TestLinearDiscoveryRejectsOverlyComplexSingleQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if i := strings.Index(in.Query, "teams("); i != -1 {
			rest := in.Query[i:]
			if strings.Contains(rest, "projects(") || strings.Contains(rest, "states(") || strings.Contains(rest, "labels(") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":[{"message":"Query too complex"}]}`))
				return
			}
		}
		switch {
		case strings.Contains(in.Query, "teams("):
			_, _ = w.Write([]byte(`{"data":{"teams":{"nodes":[{"id":"team"}]}}}`))
		case strings.Contains(in.Query, "projects("):
			_, _ = w.Write([]byte(`{"data":{"projects":{"nodes":[{"id":"project"}]}}}`))
		case strings.Contains(in.Query, "workflowStates("):
			_, _ = w.Write([]byte(`{"data":{"workflowStates":{"nodes":[{"id":"backlog"}]}}}`))
		case strings.Contains(in.Query, "issueLabels("):
			_, _ = w.Write([]byte(`{"data":{"issueLabels":{"nodes":[{"id":"a","name":"source:portal","team":{"id":"team"}},{"id":"b","name":"needs-triage","team":{"id":"team"}},{"id":"c","name":"Bug","team":{"id":"team"}},{"id":"d","name":"Feature","team":{"id":"team"}}]}}}`))
		default:
			t.Errorf("unexpected discovery query: %s", in.Query)
		}
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()
	if err := c.discover(context.Background()); err != nil {
		t.Fatalf("discover() sent a query too complex for Linear: %v", err)
	}
	if c.team != "team" || c.project != "project" || c.state != "backlog" {
		t.Fatalf("incomplete discovery: %#v", c)
	}
	for _, n := range []string{"source:portal", "needs-triage", "Bug", "Feature"} {
		if c.labels[n] == "" {
			t.Fatalf("missing label %s: %#v", n, c.labels)
		}
	}
}

// TestLinearDoSurfacesLinearErrorBody pins the second half of the PAT-2233
// bug: do() used to discard Linear's response body on any non-2xx status,
// so failed syncs never recorded why. It must now surface Linear's own
// error message, bounded and without echoing anything we sent.
func TestLinearDoSurfacesLinearErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Query too complex"}]}`))
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()
	err := c.do(context.Background(), `query{teams(filter:{key:{eq:"PAT"}}){nodes{id}}}`, nil, &struct{}{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Query too complex") {
		t.Fatalf("do() did not surface Linear's error body: %v", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("do() dropped the HTTP status: %v", err)
	}
}

func TestLinearFetchIssueUsesNarrowBoundedContract(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query     string            `json:"query"`
			Variables map[string]string `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if strings.Contains(in.Query, "title") || strings.Contains(in.Query, "description") || in.Variables["id"] != "issue-1" {
			t.Errorf("reconcile query is not narrow: %#v", in)
		}
		id := "issue-1"
		if calls.Add(1) > 1 {
			id = "issue-2"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"issue": map[string]any{
			"id": id, "updatedAt": "2026-09-27T12:00:00Z", "state": map[string]string{"name": "In Review"},
			"labels": map[string]any{"nodes": []map[string]string{{"name": "claude-triaged"}}},
		}}})
	}))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()
	got, err := c.FetchIssue(context.Background(), "issue-1")
	if err != nil || got.IssueID != "issue-1" || got.State != "In Review" || len(got.Labels) != 1 || got.Source != "reconcile" {
		t.Fatalf("FetchIssue=%+v err=%v", got, err)
	}
	if _, err := c.FetchIssue(context.Background(), "issue-1"); err == nil {
		t.Fatal("unexpected Linear issue identity accepted")
	}
}

// PAT-2347: Support and Design are applied when the team has them and are
// never required, so deploying before the labels exist cannot stop feedback
// reaching Linear.
func TestLinearDiscoverySupportAndDesignLabelsAreOptional(t *testing.T) {
	required := `{"id":"a","name":"source:portal","team":{"id":"team"}},{"id":"b","name":"needs-triage","team":{"id":"team"}},{"id":"c","name":"Bug","team":{"id":"team"}},{"id":"d","name":"Feature","team":{"id":"team"}}`
	for _, tc := range []struct {
		name, extra          string
		wantSupport, wantDes string
	}{
		{name: "absent", extra: ""},
		{name: "unique team support overrides ambiguous workspace labels", extra: `,{"id":"w1","name":"Support","team":null},{"id":"w2","name":"Support","team":null},{"id":"s","name":"Support","team":{"id":"team"}}`, wantSupport: "s"},
		{name: "team support precedes ambiguous workspace labels", extra: `,{"id":"s","name":"Support","team":{"id":"team"}},{"id":"w1","name":"Support","team":null},{"id":"w2","name":"Support","team":null}`, wantSupport: "s"},
		{name: "present", extra: `,{"id":"s","name":"Support","team":{"id":"team"}},{"id":"g","name":"Design","team":{"id":"team"}}`, wantSupport: "s", wantDes: "g"},
		{name: "ambiguous support is skipped, not fatal", extra: `,{"id":"s1","name":"Support","team":{"id":"team"}},{"id":"s2","name":"Support","team":{"id":"team"}},{"id":"g","name":"Design","team":{"id":"team"}}`, wantDes: "g"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Query string `json:"query"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				if strings.Contains(in.Query, "issueLabels(") {
					_, _ = w.Write([]byte(`{"data":{"issueLabels":{"nodes":[` + required + tc.extra + `]}}}`))
					return
				}
				_, _ = w.Write([]byte(discoverySuccessBody(in.Query, "team", "project", "backlog")))
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint = srv.URL
			c.HTTP = srv.Client()
			if err := c.discover(context.Background()); err != nil {
				t.Fatalf("discover: %v", err)
			}
			if c.labels["Support"] != tc.wantSupport || c.labels["Design"] != tc.wantDes {
				t.Fatalf("labels: %#v", c.labels)
			}
			for _, n := range []string{"source:portal", "needs-triage", "Bug", "Feature"} {
				if c.labels[n] == "" {
					t.Fatalf("required label %s lost: %#v", n, c.labels)
				}
			}
		})
	}
}
