package releasecontrol

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSkippedObservationIsVisible(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	now := time.Now()
	for _, tc := range []struct {
		version   string
		collected time.Time
		reason    string
	}{{"", now, "invalid_agent_version"}, {strings.Repeat("a", 101), now, "invalid_agent_version"}, {"1.2.3", time.Time{}, "invalid_collection_time"}, {"1.2.3", now.Add(-time.Hour), "stale_collection_time"}, {"1.2.3", now.Add(time.Hour), "future_collection_time"}} {
		buf.Reset()
		if err := Observe(context.Background(), nil, "tenant", "device", "macos", tc.version, 1, now, tc.collected, true); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "release observation skipped") || !strings.Contains(buf.String(), tc.reason) {
			t.Fatalf("missing skip signal: %s", buf.String())
		}
		if strings.Contains(buf.String(), "agent_version=") {
			t.Fatal("rejected data logged")
		}
	}
	if reason := observationSkipReason("1.2.3", now, now); reason != "" {
		t.Fatal(reason)
	}
}
