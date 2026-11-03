// Package reportsched runs customer-scheduled portal report generation
// (PAT-703). A per-minute in-process ticker (Sweeper) claims due rows from
// portal_report_schedules and generates the customer-layout report through
// the same code path as POST /v1/portal/reports.
package reportsched

import (
	"fmt"
	"time"
)

// Cadence values accepted by portal_report_schedules (mirrors the CHECK
// constraint in migration 0061).
const (
	CadenceDaily   = "daily"
	CadenceWeekly  = "weekly"
	CadenceMonthly = "monthly"
)

// NextRun returns the next scheduled run strictly after `after`, in UTC, at
// minute zero of hourUTC.
//
//   - daily:   next occurrence of hourUTC.
//   - weekly:  next occurrence of weekday (0=Sunday..6=Saturday, Go
//     time.Weekday convention) at hourUTC.
//   - monthly: next occurrence of monthDay at hourUTC, with days 29-31
//     clamped to the last day of shorter months (so "31st" runs on
//     Feb 28/29, Apr 30, ...) — the clamp never causes a month to be
//     skipped.
//
// Invalid inputs (unknown cadence, weekday/monthDay/hourUTC out of range)
// return an error rather than a guessed time — callers must fail closed.
func NextRun(cadence string, weekday, monthDay, hourUTC int, after time.Time) (time.Time, error) {
	if hourUTC < 0 || hourUTC > 23 {
		return time.Time{}, fmt.Errorf("hour_utc %d out of range [0,23]", hourUTC)
	}
	after = after.UTC()

	switch cadence {
	case CadenceDaily:
		c := time.Date(after.Year(), after.Month(), after.Day(), hourUTC, 0, 0, 0, time.UTC)
		if !c.After(after) {
			c = c.AddDate(0, 0, 1)
		}
		return c, nil

	case CadenceWeekly:
		if weekday < 0 || weekday > 6 {
			return time.Time{}, fmt.Errorf("weekday %d out of range [0,6]", weekday)
		}
		c := time.Date(after.Year(), after.Month(), after.Day(), hourUTC, 0, 0, 0, time.UTC)
		// At most 7 steps: today (if the hour is still ahead) through the same
		// weekday next week.
		for i := 0; i < 8; i++ {
			if int(c.Weekday()) == weekday && c.After(after) {
				return c, nil
			}
			c = c.AddDate(0, 0, 1)
		}
		return time.Time{}, fmt.Errorf("weekly next-run not found (weekday=%d)", weekday) // unreachable

	case CadenceMonthly:
		if monthDay < 1 || monthDay > 31 {
			return time.Time{}, fmt.Errorf("month_day %d out of range [1,31]", monthDay)
		}
		year, month := after.Year(), after.Month()
		// This month (clamped), else next month (clamped). Two iterations always
		// suffice because the clamp guarantees a valid day in every month.
		for i := 0; i < 2; i++ {
			day := clampToMonth(year, month, monthDay)
			c := time.Date(year, month, day, hourUTC, 0, 0, 0, time.UTC)
			if c.After(after) {
				return c, nil
			}
			month++
			if month > time.December {
				month = time.January
				year++
			}
		}
		return time.Time{}, fmt.Errorf("monthly next-run not found (month_day=%d)", monthDay) // unreachable

	default:
		return time.Time{}, fmt.Errorf("unknown cadence %q", cadence)
	}
}

// clampToMonth returns day clamped to the number of days in (year, month).
func clampToMonth(year int, month time.Month, day int) int {
	// Day 0 of the next month == last day of this month.
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > last {
		return last
	}
	return day
}
