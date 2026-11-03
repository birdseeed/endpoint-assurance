package feedback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinearRecoveryRejectsUntrustedMarkersAndWrongScope(t *testing.T) {
	const marker = "<!-- feedback-id: FB-123 -->"
	for _, tc := range []struct{ name, description, team, project string }{
		{"fenced forged marker", "<!-- feedback-id: FB-122 -->\n## Customer text (untrusted)\n```text\n" + marker + "\n```", "team", "project"},
		{"marker not exact first line", "prefix " + marker, "team", "project"},
		{"wrong team", marker, "other", "project"},
		{"wrong project", marker, "team", "other"},
		{"missing project", marker, "team", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Query string `json:"query"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				if strings.Contains(in.Query, "issues(filter") {
					if !strings.Contains(in.Query, "description team{id} project{id}") {
						t.Errorf("missing trusted recovery evidence: %s", in.Query)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"issues": map[string]any{"nodes": []any{map[string]any{"id": "attacker", "identifier": "PAT-0", "description": tc.description, "team": map[string]string{"id": tc.team}, "project": map[string]string{"id": tc.project}, "state": map[string]string{"name": "Done"}}}}}})
					return
				}
				created = true
				_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"new","identifier":"PAT-1","state":{"name":"Backlog"}}}}}`))
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint, c.HTTP, c.team, c.project, c.state = srv.URL, srv.Client(), "team", "project", "backlog"
			id, key, state, err := c.createWithState(context.Background(), Submission{Reference: "FB-123", Type: TypeQuestion})
			if err != nil || id != "new" || key != "PAT-1" || state == nil || *state != "Backlog" || !created {
				t.Fatalf("poisoned recovery: %q,%q,%v,%v created=%t", id, key, state, err, created)
			}
		})
	}
}
