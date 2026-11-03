package msgraph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// newTestClient wires a Client to a real TokenSource pointed at a token
// httptest.Server that always succeeds, and a Graph httptest.Server driven
// by graphHandler. This exercises the full "tenant id + certificate ->
// usable Graph token -> authenticated Graph request" path end to end with
// no real network access.
func newTestClient(t *testing.T, graphHandler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
			AccessToken: "graph-access-token",
			ExpiresIn:   3600,
		})
	}))
	t.Cleanup(tokenServer.Close)

	graphServer := httptest.NewServer(graphHandler)
	t.Cleanup(graphServer.Close)

	cert := generateTestCertificate(t, time.Now().Add(24*time.Hour))
	ts := NewTokenSource("client-id", cert)
	ts.AuthorityBase = tokenServer.URL

	c := NewClient(ts)
	c.BaseURL = graphServer.URL
	// Tests drive time explicitly; never really sleep for Retry-After.
	c.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	return c, graphServer
}

func TestClient_GetAll_SelectPassthroughAndAuth(t *testing.T) {
	var seenAuth []string
	var seenSelect []string

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
		seenSelect = append(seenSelect, r.URL.Query().Get("$select"))
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"1"}`)},
			NextLink: "",
		})
	})

	results, err := c.GetAll(context.Background(), "tenant-a", "/resource", url.Values{"$select": {"id,displayName"}})
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d items, want 1", len(results))
	}
	if len(seenSelect) == 0 || seenSelect[0] != "id,displayName" {
		t.Errorf("$select not passed through, got %v", seenSelect)
	}
	if len(seenAuth) == 0 || seenAuth[0] != "Bearer graph-access-token" {
		t.Errorf("Authorization header = %v, want Bearer graph-access-token", seenAuth)
	}
}

// TestClient_GetAll_ThreePages is the acceptance-criteria case: paging
// across at least 3 simulated pages via @odata.nextLink, following to full
// exhaustion.
func TestClient_GetAll_ThreePages(t *testing.T) {
	var requestCount int
	var mux *http.ServeMux
	c, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	})

	mux = http.NewServeMux()
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"1"}`)},
			NextLink: server.URL + "/resource/page2",
		})
	})
	mux.HandleFunc("/resource/page2", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"2"}`), json.RawMessage(`{"id":"3"}`)},
			NextLink: server.URL + "/resource/page3",
		})
	})
	mux.HandleFunc("/resource/page3", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"4"}`)},
			NextLink: "", // exhausted
		})
	})

	results, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("made %d requests, want exactly 3 (one per page)", requestCount)
	}
	if len(results) != 4 {
		t.Fatalf("got %d total items across 3 pages, want 4", len(results))
	}
	var ids []string
	for _, r := range results {
		var obj struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r, &obj); err != nil {
			t.Fatalf("unmarshal item: %v", err)
		}
		ids = append(ids, obj.ID)
	}
	want := []string{"1", "2", "3", "4"}
	for i, w := range want {
		if ids[i] != w {
			t.Errorf("item %d = %s, want %s", i, ids[i], w)
		}
	}
}

func TestClient_GetAll_ThrottledRespectsRetryAfter(t *testing.T) {
	var attempts int
	var sleptFor time.Duration

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"1"}`)},
			NextLink: "",
		})
	})
	c.sleep = func(ctx context.Context, d time.Duration) error {
		sleptFor = d
		return nil
	}

	results, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d items, want 1 (after one throttled retry)", len(results))
	}
	if attempts != 2 {
		t.Fatalf("made %d attempts, want 2 (one 429 then one success)", attempts)
	}
	if sleptFor != 3*time.Second {
		t.Errorf("backed off %v, want exactly the Retry-After value of 3s", sleptFor)
	}
}

func TestClient_GetAll_ThrottledGivesUpAfterMaxRetries(t *testing.T) {
	var attempts int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err == nil {
		t.Fatal("expected error after exhausting throttle retries")
	}
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("errors.Is(err, ErrThrottled) = false, got %v", err)
	}
	if attempts != maxThrottleRetries+1 {
		t.Errorf("made %d attempts, want %d (maxThrottleRetries + final failing attempt)", attempts, maxThrottleRetries+1)
	}
}

func TestClient_GetAll_PermissionDenied(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(graphErrorBody{
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "Authorization_RequestDenied", Message: "Insufficient privileges to complete the operation."},
		})
	})

	_, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("errors.Is(err, ErrPermissionDenied) = false, got %v", err)
	}
	var ge *GraphError
	if !errors.As(err, &ge) {
		t.Fatalf("expected *GraphError, got %T", err)
	}
	if ge.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", ge.Status)
	}
}

// TestClient_GetAll_RefusesNextLinkToUnexpectedHost guards against a
// compromised or malformed Graph response redirecting pagination to a
// different host: every request attaches our bearer token, so blindly
// following an off-host nextLink would leak it.
func TestClient_GetAll_RefusesNextLinkToUnexpectedHost(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"1"}`)},
			NextLink: "https://attacker.example.com/steal",
		})
	})

	_, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err == nil {
		t.Fatal("expected error refusing the off-host nextLink, got nil")
	}
}

func TestClient_GetAll_RefusesMalformedNextLink(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(graphPage{
			Value:    []json.RawMessage{json.RawMessage(`{"id":"1"}`)},
			NextLink: "://not-a-valid-url",
		})
	})

	_, err := c.GetAll(context.Background(), "tenant-a", "/resource", nil)
	if err == nil {
		t.Fatal("expected error refusing a malformed nextLink, got nil")
	}
}
