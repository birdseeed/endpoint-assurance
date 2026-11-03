package reportsched

import (
	"testing"
	"time"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestNextRun(t *testing.T) {
	tests := []struct {
		name     string
		cadence  string
		weekday  int
		monthDay int
		hourUTC  int
		after    time.Time
		want     time.Time
	}{
		// ── daily ────────────────────────────────────────────────────────────
		{"daily hour still ahead today", CadenceDaily, 0, 0, 7,
			ts("2026-07-03T06:59:00Z"), ts("2026-07-03T07:00:00Z")},
		{"daily exactly at slot rolls to tomorrow", CadenceDaily, 0, 0, 7,
			ts("2026-07-03T07:00:00Z"), ts("2026-07-04T07:00:00Z")},
		{"daily hour passed rolls to tomorrow", CadenceDaily, 0, 0, 7,
			ts("2026-07-03T09:30:00Z"), ts("2026-07-04T07:00:00Z")},
		{"daily crosses month boundary", CadenceDaily, 0, 0, 1,
			ts("2026-07-31T02:00:00Z"), ts("2026-08-01T01:00:00Z")},
		{"daily crosses year boundary", CadenceDaily, 0, 0, 23,
			ts("2026-12-31T23:30:00Z"), ts("2027-01-01T23:00:00Z")},

		// ── weekly (weekday 0=Sunday..6=Saturday) ────────────────────────────
		// 2026-07-03 is a Friday (weekday 5).
		{"weekly same day hour ahead", CadenceWeekly, 5, 0, 18,
			ts("2026-07-03T10:00:00Z"), ts("2026-07-03T18:00:00Z")},
		{"weekly same day hour passed waits a week", CadenceWeekly, 5, 0, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-07-10T07:00:00Z")},
		{"weekly Monday from Friday", CadenceWeekly, 1, 0, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-07-06T07:00:00Z")},
		{"weekly Sunday from Friday", CadenceWeekly, 0, 0, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-07-05T07:00:00Z")},

		// ── monthly ──────────────────────────────────────────────────────────
		{"monthly later this month", CadenceMonthly, 0, 15, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-07-15T07:00:00Z")},
		{"monthly day passed rolls to next month", CadenceMonthly, 0, 1, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-08-01T07:00:00Z")},
		{"monthly same day hour passed rolls a month", CadenceMonthly, 0, 3, 7,
			ts("2026-07-03T08:00:00Z"), ts("2026-08-03T07:00:00Z")},
		{"monthly December rolls to January", CadenceMonthly, 0, 5, 7,
			ts("2026-12-10T00:00:00Z"), ts("2027-01-05T07:00:00Z")},

		// ── month-end clamp (days 29-31) ─────────────────────────────────────
		{"day 31 clamps to Feb 28 (non-leap)", CadenceMonthly, 0, 31, 7,
			ts("2026-02-01T00:00:00Z"), ts("2026-02-28T07:00:00Z")},
		{"day 31 clamps to Feb 29 (leap)", CadenceMonthly, 0, 31, 7,
			ts("2028-02-01T00:00:00Z"), ts("2028-02-29T07:00:00Z")},
		{"day 30 clamps to Feb 28 (non-leap)", CadenceMonthly, 0, 30, 7,
			ts("2026-02-01T00:00:00Z"), ts("2026-02-28T07:00:00Z")},
		{"day 29 clamps to Feb 28 (non-leap)", CadenceMonthly, 0, 29, 7,
			ts("2026-02-01T00:00:00Z"), ts("2026-02-28T07:00:00Z")},
		{"day 29 keeps Feb 29 (leap)", CadenceMonthly, 0, 29, 7,
			ts("2028-02-10T00:00:00Z"), ts("2028-02-29T07:00:00Z")},
		{"day 31 clamps to Apr 30", CadenceMonthly, 0, 31, 7,
			ts("2026-04-01T00:00:00Z"), ts("2026-04-30T07:00:00Z")},
		{"clamp does not skip the short month", CadenceMonthly, 0, 31, 7,
			ts("2026-01-31T08:00:00Z"), ts("2026-02-28T07:00:00Z")},
		{"after clamped Feb run, next is Mar 31", CadenceMonthly, 0, 31, 7,
			ts("2026-02-28T07:00:00Z"), ts("2026-03-31T07:00:00Z")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NextRun(tc.cadence, tc.weekday, tc.monthDay, tc.hourUTC, tc.after)
			if err != nil {
				t.Fatalf("NextRun() error = %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("NextRun() = %s, want %s", got.Format(time.RFC3339), tc.want.Format(time.RFC3339))
			}
			if got.Location() != time.UTC {
				t.Errorf("NextRun() location = %v, want UTC", got.Location())
			}
			if !got.After(tc.after) {
				t.Errorf("NextRun() = %s is not strictly after %s", got, tc.after)
			}
		})
	}
}

// TestNextRunNonUTCInput — a non-UTC `after` must produce the same instant as
// its UTC equivalent.
func TestNextRunNonUTCInput(t *testing.T) {
	loc := time.FixedZone("UTC+5", 5*3600)
	after := time.Date(2026, 7, 3, 11, 30, 0, 0, loc) // 06:30 UTC
	got, err := NextRun(CadenceDaily, 0, 0, 7, after)
	if err != nil {
		t.Fatalf("NextRun() error = %v", err)
	}
	want := ts("2026-07-03T07:00:00Z")
	if !got.Equal(want) {
		t.Errorf("NextRun() = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestNextRunInvalidInputs(t *testing.T) {
	after := ts("2026-07-03T00:00:00Z")
	cases := []struct {
		name     string
		cadence  string
		weekday  int
		monthDay int
		hourUTC  int
	}{
		{"unknown cadence", "quarterly", 0, 1, 7},
		{"empty cadence", "", 0, 1, 7},
		{"hour too high", CadenceDaily, 0, 0, 24},
		{"hour negative", CadenceDaily, 0, 0, -1},
		{"weekday too high", CadenceWeekly, 7, 0, 7},
		{"weekday negative", CadenceWeekly, -1, 0, 7},
		{"month_day zero", CadenceMonthly, 0, 0, 7},
		{"month_day too high", CadenceMonthly, 0, 32, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NextRun(tc.cadence, tc.weekday, tc.monthDay, tc.hourUTC, after); err == nil {
				t.Errorf("NextRun(%q, %d, %d, %d) expected error, got nil",
					tc.cadence, tc.weekday, tc.monthDay, tc.hourUTC)
			}
		})
	}
}
