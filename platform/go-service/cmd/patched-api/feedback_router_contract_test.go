package main

import (
	"os"
	"strings"
	"testing"
)

func TestFeedbackIsDisabledByDefault(t *testing.T) {
	t.Setenv("FEEDBACK_ENABLED", "")
	if loadConfig().FeedbackEnabled {
		t.Fatal("FEEDBACK_ENABLED must default to false")
	}
}

func TestFeedbackRoutesAreMountedInsidePortalRouter(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	portalStart := strings.Index(string(source), `r.Route("/v1/portal"`)
	if portalStart < 0 {
		t.Fatal("could not locate the /v1/portal router group")
	}
	portalSource := string(source[portalStart:])
	for _, route := range []string{`pr.Post("/feedback"`, `pr.Get("/feedback"`} {
		if !strings.Contains(portalSource, route) {
			t.Errorf("feedback route %s is not mounted under /v1/portal", route)
		}
	}
}
