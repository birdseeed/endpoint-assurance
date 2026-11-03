package feedback

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// PAT-2216: on 2026-09-28 every feedback sync failed against Linear for
// hours (a discovery query Linear rejected as too complex) and the
// journal showed nothing, because a failed attempt was recorded only in
// the database. Each failure must now leave a journal line, and the last
// one must say plainly that the row will not be retried.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestFeedbackSyncFailureIsLoggedWithRetry(t *testing.T) {
	buf := captureSlog(t)
	logSyncFailure(42, 3, "pending", 4*time.Minute, "Linear HTTP 400: Query too complex")
	out := buf.String()
	for _, want := range []string{`"level":"WARN"`, `"msg":"feedback sync attempt failed"`, `"id":42`, `"attempt":3`, `"retry_in":"4m0s"`, `Query too complex`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %s", out, want)
		}
	}
}

func TestFeedbackSyncExhaustionIsLoggedAsAnError(t *testing.T) {
	buf := captureSlog(t)
	state, delay := syncRetryDecision(maxSyncAttempts)
	logSyncFailure(7, maxSyncAttempts, state, delay, "Linear HTTP 400: Query too complex")
	out := buf.String()
	for _, want := range []string{`"level":"ERROR"`, `"msg":"feedback sync failed permanently"`, `"id":7`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %s", out, want)
		}
	}
}

func TestFeedbackSyncFailureLogIsBounded(t *testing.T) {
	buf := captureSlog(t)
	logSyncFailure(1, 1, "pending", time.Minute, strings.Repeat("x", 5000))
	if n := strings.Count(buf.String(), "x"); n > 300 {
		t.Fatalf("logged %d characters of error text, want at most 300", n)
	}
}
