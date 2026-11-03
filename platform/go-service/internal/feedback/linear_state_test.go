package feedback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinearWorkflowStateCreationAndMarkerRecovery(t *testing.T) {
	for _, tc := range []struct{ name, found, created, want string }{
		{"creation", "", "Backlog", "Backlog"},
		{"recovered moved issue", "In Progress", "", "In Progress"},
		{"missing state stays unknown", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creates := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Query string `json:"query"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error(err)
					return
				}
				if !strings.Contains(in.Query, "state{name}") {
					t.Errorf("workflow state not requested: %s", in.Query)
				}
				if strings.Contains(in.Query, "issues(filter") {
					if tc.found == "" {
						_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"issues": map[string]any{"nodes": []any{map[string]any{"id": "issue", "identifier": "PAT-1", "description": "<!-- feedback-id: FB-123 -->\nbody", "team": map[string]string{"id": "team"}, "project": map[string]string{"id": "project"}, "state": map[string]string{"name": tc.found}}}}}})
					return
				}
				creates++
				var state any
				if tc.created != "" {
					state = map[string]string{"name": tc.created}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"issueCreate": map[string]any{"success": true, "issue": map[string]any{"id": "issue", "identifier": "PAT-1", "state": state}}}})
			}))
			defer srv.Close()
			c := NewLinearClient("key")
			c.Endpoint, c.HTTP, c.team, c.project, c.state = srv.URL, srv.Client(), "team", "project", "backlog"
			id, key, state, err := c.createWithState(context.Background(), Submission{Reference: "FB-123", Type: TypeQuestion})
			if err != nil || id != "issue" || key != "PAT-1" {
				t.Fatalf("result=%q,%q,%v", id, key, err)
			}
			if tc.want == "" {
				if state != nil {
					t.Fatalf("invented state: %q", *state)
				}
			} else if state == nil || *state != tc.want {
				t.Fatalf("workflow state=%v want %q", state, tc.want)
			}
			if tc.found != "" && creates != 0 {
				t.Fatalf("recovery created duplicate: %d", creates)
			}
		})
	}
}
