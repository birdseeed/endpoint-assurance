package removal

import (
	"strings"
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

// TestCheckStaleness covers every branch of the rule an authorisation is
// refused by. The rule is pure so these need no database, which is the point
// of keeping it out of the handler: the endpoint and this test cannot drift.
func TestCheckStaleness(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	computed := now.Add(-30 * time.Minute)
	watermark := computed.Add(-5 * time.Minute)

	cases := []struct {
		name        string
		computedAt  time.Time
		then        *time.Time
		current     Watermark
		wantStale   bool
		wantReason  string // substring, "" when fresh
		wantReasons int
	}{
		{
			name:       "fresh: nothing has uploaded since",
			computedAt: computed,
			then:       tp(watermark),
			current:    Watermark{LastUpload: tp(watermark), DeviceCount: 3},
			wantStale:  false,
		},
		{
			name:        "stale: inventory uploaded since the preview",
			computedAt:  computed,
			then:        tp(watermark),
			current:     Watermark{LastUpload: tp(watermark.Add(time.Minute)), DeviceCount: 3},
			wantStale:   true,
			wantReason:  "inventory has been uploaded since",
			wantReasons: 1,
		},
		{
			name:        "stale: older than the age ceiling even with an unchanged estate",
			computedAt:  now.Add(-DryRunMaxAge - time.Minute),
			then:        tp(watermark),
			current:     Watermark{LastUpload: tp(watermark), DeviceCount: 3},
			wantStale:   true,
			wantReason:  "beyond the 24h0m0s ceiling",
			wantReasons: 1,
		},
		{
			name:        "stale: tenant had no devices at compute time and has some now",
			computedAt:  computed,
			then:        nil,
			current:     Watermark{LastUpload: tp(now), DeviceCount: 2},
			wantStale:   true,
			wantReason:  "had no devices when the dry run was computed",
			wantReasons: 1,
		},
		{
			name:       "fresh: tenant had no devices and still has none",
			computedAt: computed,
			then:       nil,
			current:    Watermark{LastUpload: nil, DeviceCount: 0},
			wantStale:  false,
		},
		{
			name:        "stale: the previewed devices are gone",
			computedAt:  computed,
			then:        tp(watermark),
			current:     Watermark{LastUpload: nil, DeviceCount: 0},
			wantStale:   true,
			wantReason:  "no longer exist",
			wantReasons: 1,
		},
		{
			name:        "both causes are reported, not just the first",
			computedAt:  now.Add(-DryRunMaxAge - time.Hour),
			then:        tp(watermark),
			current:     Watermark{LastUpload: tp(now), DeviceCount: 4},
			wantStale:   true,
			wantReason:  "inventory has been uploaded since",
			wantReasons: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckStaleness(c.computedAt, c.then, now, c.current)
			if got.Stale != c.wantStale {
				t.Fatalf("Stale = %v, want %v (reasons: %v)", got.Stale, c.wantStale, got.Reasons)
			}
			if c.wantReasons > 0 && len(got.Reasons) != c.wantReasons {
				t.Fatalf("got %d reasons, want %d: %v", len(got.Reasons), c.wantReasons, got.Reasons)
			}
			if c.wantReason != "" && !strings.Contains(strings.Join(got.Reasons, "; "), c.wantReason) {
				t.Fatalf("reasons %v do not mention %q", got.Reasons, c.wantReason)
			}
			if !c.wantStale && len(got.Reasons) != 0 {
				t.Fatalf("fresh verdict carried reasons: %v", got.Reasons)
			}
		})
	}
}

// TestCheckStalenessBoundary pins the ceiling as strictly greater-than, so a
// preview computed exactly DryRunMaxAge ago is still usable and one second
// more is not. Worth pinning: a sloppy >= would make the boundary depend on
// clock resolution.
func TestCheckStalenessBoundary(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	w := tp(now.Add(-DryRunMaxAge))
	current := Watermark{LastUpload: w, DeviceCount: 1}

	if s := CheckStaleness(now.Add(-DryRunMaxAge), w, now, current); s.Stale {
		t.Fatalf("exactly at the ceiling should not be stale: %v", s.Reasons)
	}
	if s := CheckStaleness(now.Add(-DryRunMaxAge-time.Second), w, now, current); !s.Stale {
		t.Fatal("one second past the ceiling should be stale")
	}
}
