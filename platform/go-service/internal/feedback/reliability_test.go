package feedback

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSyncRetryDecision(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		state   string
		delay   time.Duration
	}{
		{1, "pending", time.Minute}, {2, "pending", 2 * time.Minute}, {6, "pending", 32 * time.Minute},
		{7, "pending", time.Hour}, {9, "pending", time.Hour}, {10, "failed", 0}, {11, "failed", 0},
	} {
		state, delay := syncRetryDecision(tc.attempt)
		if state != tc.state || delay != tc.delay {
			t.Errorf("attempt%d: %s/%s want%s/%s", tc.attempt, state, delay, tc.state, tc.delay)
		}
	}
	if feedbackLeaseDuration != 10*time.Minute {
		t.Fatalf("lease=%s", feedbackLeaseDuration)
	}
}

func TestSanitizeContextRemovesSensitiveURLAndBoundsCharacters(t *testing.T) {
	for _, route := range []string{"/devices?token=secret#private", "https://user:secret@example.test/devices?token=secret#private", "/devices#private?secret"} {
		s := Submission{Route: route}
		if err := s.SanitizeContext(); err != nil || s.Route != "/devices" {
			t.Errorf("sanitize%q: %q %v", route, s.Route, err)
		}
	}
	s := Submission{Route: "/" + strings.Repeat("x", 600) + "?private=yes", PortalBuild: strings.Repeat("é", 129), BrowserUserAgent: strings.Repeat("界", 513)}
	if err := s.SanitizeContext(); err != nil {
		t.Fatal(err)
	}
	if len([]rune(s.Route)) != 512 || len([]rune(s.PortalBuild)) != 128 || len([]rune(s.BrowserUserAgent)) != 512 {
		t.Fatalf("unexpected captured limits: %+v", s)
	}
	if err := (&Submission{Route: "/%zz?secret"}).SanitizeContext(); err == nil {
		t.Fatal("invalid URL accepted")
	}
	valid := Submission{Type: TypeQuestion, Title: "Valid title", Description: "text"}
	for _, change := range []func(*Submission){func(s *Submission) { s.Route = strings.Repeat("x", 513) }, func(s *Submission) { s.PortalBuild = strings.Repeat("x", 129) }, func(s *Submission) { s.BrowserUserAgent = strings.Repeat("x", 513) }} {
		s := valid
		change(&s)
		if s.Validate() == nil {
			t.Fatal("oversized context accepted by model")
		}
	}
}

func TestIssueCreateLockCancellationAndPruning(t *testing.T) {
	const key = "test-keyed-cancellation"
	release, err := acquireIssueCreate(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		unlock, err := acquireIssueCreate(ctx, key)
		if unlock != nil {
			unlock()
		}
		result <- err
	}()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation:%v", err)
	}
	release()
	issueCreateLocks.Lock()
	_, retained := issueCreateLocks.keys[key]
	issueCreateLocks.Unlock()
	if retained {
		t.Fatal("idle keyed lock retained")
	}
}

func TestLinearRequestMarshalAndResponseLimit(t *testing.T) {
	requests := 0
	body := `{"data":{}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	c := NewLinearClient("key")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()
	var out map[string]any
	if err := c.do(context.Background(), "query", make(chan int), &out); err == nil || !strings.Contains(err.Error(), "marshal") || requests != 0 {
		t.Fatalf("marshal failure: %v requests%d", err, requests)
	}
	body += strings.Repeat(" ", maxLinearResponseBytes-len(body))
	if err := c.do(context.Background(), "query", nil, &out); err != nil {
		t.Fatalf("exact response bound:%v", err)
	}
	body += " "
	if err := c.do(context.Background(), "query", nil, &out); err == nil || !strings.Contains(err.Error(), "exceeds 4MiB") {
		t.Fatalf("oversized response:%v", err)
	}
}
