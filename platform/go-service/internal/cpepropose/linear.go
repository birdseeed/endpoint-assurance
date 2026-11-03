package cpepropose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultLinearURL is Linear's GraphQL endpoint.
const DefaultLinearURL = "https://api.linear.app/graphql"

// LinearClient is a minimal Linear GraphQL client for the review digest, the
// Go counterpart of the updater repository's verifier/linear_client.py
// (PAT-912): a workspace API key sent raw in the Authorization header, one
// team found by key, errors on a transport failure or a GraphQL errors[]
// response. It never logs the token or a response body.
type LinearClient struct {
	Endpoint string
	Token    string
	TeamKey  string // e.g. "PAT"
	HTTP     *http.Client

	teamID   string
	viewerID string
}

// NewLinearClient returns nil when token is empty (the digest then reports
// linear_token_missing).
func NewLinearClient(token, teamKey string) *LinearClient {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	if teamKey == "" {
		teamKey = "PAT"
	}
	return &LinearClient{Endpoint: DefaultLinearURL, Token: token, TeamKey: teamKey,
		HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *LinearClient) do(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.Token)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("linear request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("linear read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("linear http %d", resp.StatusCode)
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("linear decode: %w", err)
	}
	if len(env.Errors) > 0 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, capRunes(e.Message, 200))
		}
		return fmt.Errorf("linear graphql errors: %s", strings.Join(msgs, "; "))
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return errors.New("linear response has no data")
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

func (c *LinearClient) team(ctx context.Context) (string, error) {
	if c.teamID != "" {
		return c.teamID, nil
	}
	var out struct {
		Teams struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"teams"`
	}
	if err := c.do(ctx, `query($key: String!) { teams(filter: { key: { eq: $key } }) { nodes { id } } }`,
		map[string]any{"key": c.TeamKey}, &out); err != nil {
		return "", err
	}
	if len(out.Teams.Nodes) == 0 {
		return "", fmt.Errorf("no Linear team with key %q", c.TeamKey)
	}
	c.teamID = out.Teams.Nodes[0].ID
	return c.teamID, nil
}

// viewer returns the id of the user the token belongs to.
func (c *LinearClient) viewer(ctx context.Context) (string, error) {
	if c.viewerID != "" {
		return c.viewerID, nil
	}
	var out struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	}
	if err := c.do(ctx, `query { viewer { id } }`, nil, &out); err != nil {
		return "", err
	}
	if out.Viewer.ID == "" {
		return "", errors.New("linear viewer has no id")
	}
	c.viewerID = out.Viewer.ID
	return c.viewerID, nil
}

// FindOpenIssue implements IssueTracker. It adopts only an open issue that
// the token's own user created and whose description carries the marker:
// anyone in the workspace can paste the marker into an issue, and the digest
// must never take over (retitle, reprioritise, close) somebody else's.
func (c *LinearClient) FindOpenIssue(ctx context.Context, marker string) (string, error) {
	teamID, err := c.team(ctx)
	if err != nil {
		return "", err
	}
	viewerID, err := c.viewer(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		Issues struct {
			Nodes []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				Creator     *struct {
					ID string `json:"id"`
				} `json:"creator"`
			} `json:"nodes"`
		} `json:"issues"`
	}
	if err := c.do(ctx, `query($teamId: ID!, $marker: String!, $viewerId: ID!) {
		issues(filter: {
			team: { id: { eq: $teamId } }
			creator: { id: { eq: $viewerId } }
			description: { contains: $marker }
			completedAt: { null: true }
			canceledAt: { null: true }
		}, first: 10) { nodes { id description creator { id } } }
	}`, map[string]any{"teamId": teamID, "marker": marker, "viewerId": viewerID}, &out); err != nil {
		return "", err
	}
	// The filter is checked again here: the server's filter is not the
	// only line of defence.
	for _, n := range out.Issues.Nodes {
		if n.Creator != nil && n.Creator.ID == viewerID && strings.Contains(n.Description, marker) {
			return n.ID, nil
		}
	}
	return "", nil
}

// IssueOpen implements IssueTracker.
func (c *LinearClient) IssueOpen(ctx context.Context, id string) (bool, error) {
	var out struct {
		Issue *struct {
			State struct {
				Type string `json:"type"`
			} `json:"state"`
		} `json:"issue"`
	}
	err := c.do(ctx, `query($id: String!) { issue(id: $id) { state { type } } }`, map[string]any{"id": id}, &out)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") || strings.Contains(err.Error(), "Entity not found") {
			return false, nil
		}
		return false, err
	}
	if out.Issue == nil {
		return false, nil
	}
	switch out.Issue.State.Type {
	case "completed", "canceled":
		return false, nil
	}
	return true, nil
}

// CreateIssue implements IssueTracker.
func (c *LinearClient) CreateIssue(ctx context.Context, title, body string, priority int) (string, string, error) {
	teamID, err := c.team(ctx)
	if err != nil {
		return "", "", err
	}
	var out struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   *struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
			} `json:"issue"`
		} `json:"issueCreate"`
	}
	if err := c.do(ctx, `mutation($teamId: String!, $title: String!, $description: String!, $priority: Int!) {
		issueCreate(input: { teamId: $teamId, title: $title, description: $description, priority: $priority }) {
			success issue { id identifier }
		}
	}`, map[string]any{"teamId": teamID, "title": title, "description": body, "priority": priority}, &out); err != nil {
		return "", "", err
	}
	if !out.IssueCreate.Success || out.IssueCreate.Issue == nil {
		return "", "", errors.New("linear issueCreate did not succeed")
	}
	return out.IssueCreate.Issue.ID, out.IssueCreate.Issue.Identifier, nil
}

// UpdateIssue implements IssueTracker.
func (c *LinearClient) UpdateIssue(ctx context.Context, id, title, body string, priority int) error {
	var out struct {
		IssueUpdate struct {
			Success bool `json:"success"`
		} `json:"issueUpdate"`
	}
	if err := c.do(ctx, `mutation($id: String!, $title: String!, $description: String!, $priority: Int!) {
		issueUpdate(id: $id, input: { title: $title, description: $description, priority: $priority }) { success }
	}`, map[string]any{"id": id, "title": title, "description": body, "priority": priority}, &out); err != nil {
		return err
	}
	if !out.IssueUpdate.Success {
		return errors.New("linear issueUpdate did not succeed")
	}
	return nil
}

// CloseIssue implements IssueTracker: the description becomes the "queue is
// empty" text and the issue moves to the team's first completed state.
func (c *LinearClient) CloseIssue(ctx context.Context, id, body string) error {
	teamID, err := c.team(ctx)
	if err != nil {
		return err
	}
	var states struct {
		WorkflowStates struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"workflowStates"`
	}
	if err := c.do(ctx, `query($teamId: ID!) {
		workflowStates(filter: { team: { id: { eq: $teamId } }, type: { eq: "completed" } }, first: 1) { nodes { id } }
	}`, map[string]any{"teamId": teamID}, &states); err != nil {
		return err
	}
	if len(states.WorkflowStates.Nodes) == 0 {
		return errors.New("linear team has no completed workflow state")
	}
	var out struct {
		IssueUpdate struct {
			Success bool `json:"success"`
		} `json:"issueUpdate"`
	}
	if err := c.do(ctx, `mutation($id: String!, $description: String!, $stateId: String!) {
		issueUpdate(id: $id, input: { title: "0 CVE mappings awaiting review", description: $description, stateId: $stateId }) { success }
	}`, map[string]any{"id": id, "description": body, "stateId": states.WorkflowStates.Nodes[0].ID}, &out); err != nil {
		return err
	}
	if !out.IssueUpdate.Success {
		return errors.New("linear issueUpdate (close) did not succeed")
	}
	return nil
}
