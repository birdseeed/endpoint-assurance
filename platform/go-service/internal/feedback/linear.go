package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const linearURL = "https://api.linear.app/graphql"
const maxLinearResponseBytes = 4 << 20

var ErrLinearIssueNotFound = fmt.Errorf("Linear issue not found")

type issueCreateLock struct {
	slot  chan struct{}
	users int
}

var issueCreateLocks = struct {
	sync.Mutex
	keys map[string]*issueCreateLock
}{keys: make(map[string]*issueCreateLock)}

// Serialize find+create across clients, while pruning keys once all waiters
// leave. This complements durable marker recovery after process restarts.
func acquireIssueCreate(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	issueCreateLocks.Lock()
	l := issueCreateLocks.keys[key]
	if l == nil {
		l = &issueCreateLock{slot: make(chan struct{}, 1)}
		issueCreateLocks.keys[key] = l
	}
	l.users++
	issueCreateLocks.Unlock()
	drop := func() {
		issueCreateLocks.Lock()
		defer issueCreateLocks.Unlock()
		l.users--
		if l.users == 0 {
			delete(issueCreateLocks.keys, key)
		}
	}
	select {
	case l.slot <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.slot
			drop()
			return nil, err
		}
		return func() { <-l.slot; drop() }, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

type LinearClient struct {
	Endpoint, Key        string
	HTTP                 *http.Client
	team, project, state string
	labels               map[string]string
	mu                   sync.Mutex
	put                  func(context.Context, string, map[string]string, []byte) (int, error)
}

func NewLinearClient(key string) *LinearClient {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	return &LinearClient{Endpoint: linearURL, Key: key, HTTP: &http.Client{Timeout: 30 * time.Second}, labels: map[string]string{}}
}
func (c *LinearClient) do(ctx context.Context, q string, v any, out any) error {
	b, e := json.Marshal(map[string]any{"query": q, "variables": v})
	if e != nil {
		return fmt.Errorf("marshal Linear request: %w", e)
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", c.Key)
	r.Header.Set("Content-Type", "application/json")
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	resp, e := h.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, maxLinearResponseBytes+1))
	if e != nil {
		return e
	}
	if len(raw) > maxLinearResponseBytes {
		return fmt.Errorf("Linear response exceeds 4MiB")
	}
	if resp.StatusCode != 200 {
		return linearHTTPError(resp.StatusCode, raw)
	}
	var x struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if e = json.Unmarshal(raw, &x); e != nil {
		return e
	}
	if len(x.Errors) > 0 {
		return fmt.Errorf("Linear: %s", x.Errors[0].Message)
	}
	return json.Unmarshal(x.Data, out)
}

// linearHTTPError turns a non-2xx Linear response into an error that
// explains why, bounded to 300 characters. Linear's own response body never
// contains anything we sent (no secrets, no request contents), so it is
// safe to surface verbatim into last_error. Prefer the GraphQL error
// message when the body parses as one; fall back to the raw body text
// otherwise, since some 400s (e.g. "Query too complex") arrive without the
// usual {"data":...} envelope.
func linearHTTPError(status int, raw []byte) error {
	var x struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	detail := ""
	if json.Unmarshal(raw, &x) == nil && len(x.Errors) > 0 {
		detail = x.Errors[0].Message
	} else {
		detail = strings.TrimSpace(string(raw))
	}
	msg := fmt.Sprintf("Linear HTTP %d", status)
	if detail != "" {
		msg += ": " + detail
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return fmt.Errorf("%s", msg)
}

// discover resolves the team, project, workflow state and labels feedback
// issues are filed against, caching the result on the client so it only
// runs once. It used to be one query nesting three 100-item connections
// (projects, states, labels) under the team connection; Linear rejects that
// shape with HTTP 400 "Query too complex" (proven against production on
// 2026-09-28), so every resolve failed and every feedback row stuck at
// pending/failed. Each resource is now its own small, separately bounded
// query well under Linear's complexity limit.
func (c *LinearClient) discover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.team != "" {
		return nil
	}
	team, e := c.discoverTeam(ctx)
	if e != nil {
		return e
	}
	project, e := c.discoverProject(ctx)
	if e != nil {
		return e
	}
	state, e := c.discoverState(ctx, team)
	if e != nil {
		return e
	}
	labels, e := c.discoverLabels(ctx, team)
	if e != nil {
		return e
	}
	c.team, c.project, c.state, c.labels = team, project, state, labels
	return nil
}

func (c *LinearClient) discoverTeam(ctx context.Context) (string, error) {
	var o struct {
		Teams struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"teams"`
	}
	if e := c.do(ctx, `query{teams(filter:{key:{eq:"PAT"}},first:2){nodes{id}}}`, nil, &o); e != nil {
		return "", e
	}
	if len(o.Teams.Nodes) != 1 {
		return "", fmt.Errorf("PAT team missing or ambiguous")
	}
	return o.Teams.Nodes[0].ID, nil
}

func (c *LinearClient) discoverProject(ctx context.Context) (string, error) {
	var o struct {
		Projects struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"projects"`
	}
	if e := c.do(ctx, `query{projects(filter:{name:{eq:"Endpoint Assurance SaaS v1"}},first:2){nodes{id}}}`, nil, &o); e != nil {
		return "", e
	}
	if len(o.Projects.Nodes) == 0 {
		return "", fmt.Errorf("feedback Linear project missing")
	}
	if len(o.Projects.Nodes) > 1 {
		return "", fmt.Errorf("project ambiguous")
	}
	return o.Projects.Nodes[0].ID, nil
}

func (c *LinearClient) discoverState(ctx context.Context, team string) (string, error) {
	var o struct {
		WorkflowStates struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"workflowStates"`
	}
	q := `query($team:ID!){workflowStates(filter:{team:{id:{eq:$team}},name:{eq:"Backlog"}},first:2){nodes{id}}}`
	if e := c.do(ctx, q, map[string]any{"team": team}, &o); e != nil {
		return "", e
	}
	if len(o.WorkflowStates.Nodes) == 0 {
		return "", fmt.Errorf("feedback Linear Backlog state missing")
	}
	if len(o.WorkflowStates.Nodes) > 1 {
		return "", fmt.Errorf("Backlog state ambiguous")
	}
	return o.WorkflowStates.Nodes[0].ID, nil
}

// discoverLabels resolves the four labels feedback issues are filed with,
// preferring the team-scoped label when a name exists both team-level and
// workspace-level. Two labels of the same name that are both scoped to our
// team is kept as an ambiguous error, same as before the split.
func (c *LinearClient) discoverLabels(ctx context.Context, team string) (map[string]string, error) {
	names := []string{"source:portal", "needs-triage", "Bug", "Feature"}
	// PAT-2347: the Support and Design labels are applied when the team has
	// them and skipped when it does not, so deploying this before the labels
	// exist cannot stop feedback reaching Linear. The type is always in the
	// issue body table either way.
	optional := []string{"Support", "Design"}
	nameList, e := json.Marshal(append(append([]string{}, names...), optional...))
	if e != nil {
		return nil, e
	}
	var o struct {
		IssueLabels struct {
			Nodes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Team *struct {
					ID string `json:"id"`
				} `json:"team"`
			} `json:"nodes"`
		} `json:"issueLabels"`
	}
	q := fmt.Sprintf(`query{issueLabels(filter:{name:{in:%s}},first:20){nodes{id name team{id}}}}`, nameList)
	if e := c.do(ctx, q, nil, &o); e != nil {
		return nil, e
	}
	labels := map[string]string{}
	teamScoped := map[string]bool{}
	skipped := map[string]bool{}
	isOptional := func(name string) bool { return name == "Support" || name == "Design" }
	for _, x := range o.IssueLabels.Nodes {
		if x.Team != nil && x.Team.ID == team {
			if teamScoped[x.Name] {
				if isOptional(x.Name) {
					skipped[x.Name] = true // ambiguous optional label: apply none rather than guess
					continue
				}
				return nil, fmt.Errorf("label %s ambiguous", x.Name)
			}
			teamScoped[x.Name] = true
			delete(skipped, x.Name) // a unique team label overrides ambiguous workspace labels
			labels[x.Name] = x.ID
			continue
		}
		if teamScoped[x.Name] {
			continue // a team-scoped match already wins over this workspace/other-team one
		}
		if _, exists := labels[x.Name]; exists {
			if isOptional(x.Name) {
				skipped[x.Name] = true
				continue
			}
			return nil, fmt.Errorf("label %s ambiguous", x.Name)
		}
		labels[x.Name] = x.ID
	}
	for n := range skipped {
		delete(labels, n)
	}
	for _, n := range names {
		if labels[n] == "" {
			return nil, fmt.Errorf("missing label %s", n)
		}
	}
	return labels, nil
}
func (c *LinearClient) find(ctx context.Context, marker string) (string, string, error) {
	id, key, _, err := c.findWithState(ctx, marker)
	return id, key, err
}
func (c *LinearClient) findWithState(ctx context.Context, marker string) (string, string, *string, error) {
	var o struct {
		Issues struct {
			Nodes []struct {
				ID          string `json:"id"`
				Identifier  string `json:"identifier"`
				Description string `json:"description"`
				Team        struct {
					ID string `json:"id"`
				} `json:"team"`
				Project *struct {
					ID string `json:"id"`
				} `json:"project"`
				State *struct {
					Name string `json:"name"`
				} `json:"state"`
			} `json:"nodes"`
		} `json:"issues"`
	}
	e := c.do(ctx, `query($m:String!){issues(filter:{description:{contains:$m}},first:10){nodes{id identifier description team{id} project{id} state{name}}}}`, map[string]any{"m": marker}, &o)
	if e != nil || len(o.Issues.Nodes) == 0 {
		return "", "", nil, e
	}
	matched := -1
	for i, x := range o.Issues.Nodes {
		// Contains-search also matches fenced customer text. Only the trusted
		// first-line marker in the configured team/project authorises recovery.
		firstLine, _, _ := strings.Cut(x.Description, "\n")
		if firstLine != marker || x.Team.ID != c.team || x.Project == nil || x.Project.ID != c.project {
			continue
		}
		if matched != -1 {
			return "", "", nil, fmt.Errorf("feedback marker ambiguous")
		}
		matched = i
	}
	if matched == -1 {
		return "", "", nil, nil
	}
	x := o.Issues.Nodes[matched]
	var state *string
	if x.State != nil && x.State.Name != "" {
		state = &x.State.Name
	}
	return x.ID, x.Identifier, state, nil
}
func (c *LinearClient) create(ctx context.Context, s Submission) (string, string, error) {
	id, key, _, err := c.createWithState(ctx, s)
	return id, key, err
}
func (c *LinearClient) createWithState(ctx context.Context, s Submission) (string, string, *string, error) {
	if e := c.discover(ctx); e != nil {
		return "", "", nil, e
	}
	release, err := acquireIssueCreate(ctx, c.team+"\x00"+c.project+"\x00"+s.Reference)
	if err != nil {
		return "", "", nil, err
	}
	defer release()
	marker := "<!-- feedback-id: " + s.Reference + " -->"
	if id, key, state, e := c.findWithState(ctx, marker); e != nil || id != "" {
		return id, key, state, e
	}
	labels := []string{c.labels["source:portal"], c.labels["needs-triage"]}
	if s.Type == TypeBug {
		labels = append(labels, c.labels["Bug"])
	} else if s.Type == TypeFeature {
		labels = append(labels, c.labels["Feature"])
	} else if s.Type == TypeSupport {
		if id := c.labels["Support"]; id != "" {
			labels = append(labels, id)
		}
	} else if s.Type == TypeDesign {
		if id := c.labels["Design"]; id != "" {
			labels = append(labels, id)
		}
	}
	var o struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
				State      *struct {
					Name string `json:"name"`
				} `json:"state"`
			} `json:"issue"`
		} `json:"issueCreate"`
	}
	e := c.do(ctx, `mutation($i:IssueCreateInput!){issueCreate(input:$i){success issue{id identifier state{name}}}}`, map[string]any{"i": map[string]any{"teamId": c.team, "projectId": c.project, "stateId": c.state, "labelIds": labels, "title": "[" + s.Reference + "] " + s.Title, "description": BuildLinearIssueBody(s)}}, &o)
	if e != nil {
		return "", "", nil, e
	}
	if !o.IssueCreate.Success {
		return "", "", nil, fmt.Errorf("issueCreate failed")
	}
	x := o.IssueCreate.Issue
	var state *string
	if x.State != nil && x.State.Name != "" {
		state = &x.State.Name
	}
	return x.ID, x.Identifier, state, nil
}

// FetchIssue returns only the state needed by feedback reconciliation. The
// query is deliberately narrow: customer text, URLs and comments never enter
// the reconciliation process or its logs.
func (c *LinearClient) FetchIssue(ctx context.Context, issueID string) (LinearUpdate, error) {
	var out struct {
		Issue *struct {
			ID        string    `json:"id"`
			UpdatedAt time.Time `json:"updatedAt"`
			State     *struct {
				Name string `json:"name"`
			} `json:"state"`
			Labels struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"labels"`
		} `json:"issue"`
	}
	if err := c.do(ctx, `query($id:String!){issue(id:$id){id updatedAt state{name} labels(first:100){nodes{name}}}}`, map[string]any{"id": issueID}, &out); err != nil {
		return LinearUpdate{}, err
	}
	if out.Issue == nil {
		return LinearUpdate{}, ErrLinearIssueNotFound
	}
	if out.Issue.ID != issueID {
		return LinearUpdate{}, fmt.Errorf("Linear returned an unexpected issue")
	}
	if out.Issue.State == nil || strings.TrimSpace(out.Issue.State.Name) == "" || len(out.Issue.State.Name) > 128 || out.Issue.UpdatedAt.IsZero() {
		return LinearUpdate{}, fmt.Errorf("Linear issue state is incomplete")
	}
	if len(out.Issue.Labels.Nodes) > 100 {
		return LinearUpdate{}, fmt.Errorf("Linear issue has too many labels")
	}
	labels := make([]string, 0, len(out.Issue.Labels.Nodes))
	for _, label := range out.Issue.Labels.Nodes {
		if len(label.Name) > 128 {
			return LinearUpdate{}, fmt.Errorf("Linear issue label is too long")
		}
		labels = append(labels, label.Name)
	}
	return LinearUpdate{IssueID: out.Issue.ID, State: out.Issue.State.Name, Labels: labels, UpdatedAt: out.Issue.UpdatedAt, Source: "reconcile"}, nil
}
