package report

import (
	"testing"
	"time"
)

func TestToolingEvidenceLastUsedLabel(t *testing.T) {
	when := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		item ToolingEvidenceItem
		want string
	}{
		{name: "timestamp", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "metered", LastUsedAt: &when}, want: "27 Sep 2026"},
		{name: "metered without launch", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "metered"}, want: "No launch recorded"},
		{name: "stale", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "stale"}, want: "Stale"},
		{name: "unmetered", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "unmetered"}, want: "Unavailable"},
		{name: "unknown", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "unknown"}, want: "Unknown"},
		{name: "partial", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "partial"}, want: "Unknown"},
		{name: "not applicable", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "not_applicable"}, want: "Not applicable"},
		{name: "unrecognised", item: ToolingEvidenceItem{EntryKind: "application", MeteringState: "unexpected"}, want: "Unknown"},
		{name: "package is not metered", item: ToolingEvidenceItem{EntryKind: "package", MeteringState: "unknown"}, want: "Not applicable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolingEvidenceLastUsedLabel(tc.item); got != tc.want {
				t.Fatalf("label = %q, want %q", got, tc.want)
			}
		})
	}
}
