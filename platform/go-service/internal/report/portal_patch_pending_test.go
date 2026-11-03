package report

import (
	"strconv"
	"testing"
	"time"
)

// PAT-2294: osUpdatePatchPending maps the stored agent verdict onto the
// roster's tri-state. The HTTP-level behaviour is covered by
// integration/portal_device_update_state_test.go; this locks the mapping and
// the exact freshness boundary without a database.
func TestOSUpdatePatchPending(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	window := portalEvidenceStaleAfter

	tests := []struct {
		name       string
		state      string
		checkedAt  *time.Time
		reportedAt *time.Time
		want       string // "true", "false" or "nil"
	}{
		{"up to date", "up_to_date", at(-time.Hour), at(-time.Hour), "false"},
		{"update recommended", "update_recommended", at(-time.Hour), at(-time.Hour), "true"},
		{"update required", "update_required", at(-time.Hour), at(-time.Hour), "true"},
		{"deadline passed", "deadline_passed", at(-time.Hour), at(-time.Hour), "true"},
		{"unsupported hardware", "unsupported_hardware", at(-time.Hour), at(-time.Hour), "true"},
		{"unknown is no claim", "unknown", at(-time.Hour), at(-time.Hour), "nil"},
		{"unrecognised state is no claim", "restart_pending_maybe", at(-time.Hour), at(-time.Hour), "nil"},
		{"empty state is no claim", "", at(-time.Hour), at(-time.Hour), "nil"},
		// The rollup's exact-match discipline: case variants are not mapped.
		{"case variant is not up_to_date", "Up_To_Date", at(-time.Hour), at(-time.Hour), "nil"},

		{"exactly at the window is still fresh", "update_required", at(-window), at(-window), "true"},
		{"one second past the window is stale", "update_required", at(-window - time.Second), at(-window - time.Second), "nil"},
		{"stale up to date is not current", "up_to_date", at(-window - time.Hour), at(-window - time.Hour), "nil"},

		{"old verdict re-uploaded now is stale", "update_required", at(-window - time.Hour), at(-time.Minute), "nil"},
		{"pre-0147 row falls back to reported_at, fresh", "update_required", nil, at(-time.Hour), "true"},
		{"pre-0147 row falls back to reported_at, stale", "update_required", nil, at(-window - time.Hour), "nil"},
		{"checked_at ahead of receipt is capped at receipt, fresh", "update_required", at(10 * time.Minute), at(-time.Minute), "true"},
		{"far future checked_at cannot revive an old receipt", "up_to_date", at(30 * 24 * time.Hour), at(-window - time.Hour), "nil"},
		{"no timestamps at all is no claim", "up_to_date", nil, nil, "nil"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := "nil"
			if p := osUpdatePatchPending(tc.state, tc.checkedAt, tc.reportedAt, now); p != nil {
				got = strconv.FormatBool(*p)
			}
			if got != tc.want {
				t.Fatalf("osUpdatePatchPending(%q) = %s, want %s", tc.state, got, tc.want)
			}
		})
	}
}
