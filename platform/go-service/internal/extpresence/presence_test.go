package extpresence

import (
	"strings"
	"testing"
)

// The report that listed an extension stamps its last_seen and its own
// last_complete_at with the same now(), so the comparison must be strict or a
// complete report would prove its own extensions gone.
func TestAbsenceIsStrictlyAfterLastSeen(t *testing.T) {
	sql := AbsenceAuthorisedSQL("x")
	if strings.Count(sql, "last_complete_at > x.last_seen") != 2 {
		t.Fatalf("absence must compare strictly after last_seen at device and pair level:\n%s", sql)
	}
	if strings.Contains(sql, ">=") {
		t.Fatalf("non-strict comparison in:\n%s", sql)
	}
	for _, col := range []string{"bes_p.user_account = x.user_account", "bes_p.browser = x.browser", "bes_d.device_id = x.device_id"} {
		if !strings.Contains(sql, col) {
			t.Fatalf("missing %q in:\n%s", col, sql)
		}
	}
}

// PAT-2064: the device-level branch must never authorise a Safari row's
// absence, because browser_extensions_status has no Safari vocabulary to be
// complete about. The per-pair branch is untouched since it already can
// never match a Safari row (bes_p.browser is only ever chrome/edge/firefox).
func TestAbsenceNeverAuthorisedForSafariByDeviceLevelBranch(t *testing.T) {
	sql := AbsenceAuthorisedSQL("dbe")
	if !strings.Contains(sql, "dbe.browser <> 'safari'") {
		t.Fatalf("device-level branch must exclude safari:\n%s", sql)
	}
	// The safari exclusion must guard the device-level (bes_d) branch, not
	// the per-pair (bes_p) branch, which is unconditional on its own.
	deviceBranch := sql[:strings.Index(sql, "bes_p")]
	if !strings.Contains(deviceBranch, "bes_d") {
		t.Fatalf("safari exclusion not paired with the device-level branch:\n%s", sql)
	}
}

// PAT-2067: Safari's own branch reads only safari_complete_at, strictly
// after last_seen, and only for Safari rows.
func TestSafariAbsenceHasItsOwnStrictBranch(t *testing.T) {
	sql := AbsenceAuthorisedSQL("dbe")
	i := strings.Index(sql, "dbe.browser = 'safari'")
	if i < 0 {
		t.Fatalf("no safari-only branch:\n%s", sql)
	}
	branch := sql[i:strings.Index(sql, "bes_p")]
	for _, want := range []string{"bes_s.device_id = dbe.device_id", "bes_s.safari_complete_at > dbe.last_seen"} {
		if !strings.Contains(branch, want) {
			t.Fatalf("safari branch missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(branch, "last_complete_at") {
		t.Fatalf("safari branch must not read chrome/edge/firefox completeness:\n%s", sql)
	}
}

// A device that has never sent the block decides by the legacy expression
// alone.
func TestPresentFallsBackToLegacy(t *testing.T) {
	sql := PresentSQL("dbe", "LEGACY_RULE")
	if !strings.Contains(sql, "ELSE (LEGACY_RULE) END") || !strings.Contains(sql, StatusKnownSQL("dbe")) {
		t.Fatalf("legacy fallback not wired:\n%s", sql)
	}
}
