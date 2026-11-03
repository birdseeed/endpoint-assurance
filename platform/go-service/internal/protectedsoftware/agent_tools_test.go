package protectedsoftware

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// pat2268AgentEmittedIDs is copied by hand from the agents' own fixed
// detection tables, not derived from AgentToolBaselineProductName or
// unmappedAgentToolIDs — copying it separately is the point: it is a
// fixture of what the agents actually emit today, so this test fails when
// an agent gains a new id nobody has made a mapping decision about yet.
//
// Sources (2026-09-29):
//   - macOS: updater/macos/lib/sectools.sh, collect_sectools()'s
//     _check_for_tool calls.
//   - Windows (shipped): updater/windows/src/Service/
//     SecurityToolDetector.cs, KnownTools.
//   - Windows (in-flight, read-only, not yet shipped): updater-pat-2267/
//     windows/src/Shared/SecurityTools/SecurityToolLogic.cs, KnownTools'
//     fixed ids only — its SlugId-generated ids for an unrecognised
//     Security Center product are dynamic, not stable, and out of scope
//     for an id-based pin.
var pat2268AgentEmittedIDs = []string{
	"crowdstrike-falcon",
	"sentinelone",
	"sophos-endpoint",
	"defender-for-endpoint",
	"jamf-protect",
	"huntress",
	"malwarebytes",
	"carbon-black",
	"bitdefender",
	"eset-endpoint",
	"microsoft-defender-antivirus",
}

// TestAgentEmittedIDsHaveADecision pins that every id an agent's fixed
// detection table can actually emit has gone through a deliberate
// mapped/explicitly-unmapped decision in this package (PAT-2268), rather
// than silently falling through to name matching with nobody having looked
// at it. Add a new agent id to pat2268AgentEmittedIDs (copying it from the
// agent's table) at the same time it is added to either
// AgentToolBaselineProductName or unmappedAgentToolIDs; adding it to only
// one of the two fails this test.
func TestAgentEmittedIDsHaveADecision(t *testing.T) {
	for _, id := range pat2268AgentEmittedIDs {
		_, mapped := AgentToolBaselineProductName[id]
		_, explicitlyUnmapped := unmappedAgentToolIDs[id]
		switch {
		case mapped && explicitlyUnmapped:
			t.Errorf("agent id %q is both mapped and explicitly unmapped — pick one", id)
		case !mapped && !explicitlyUnmapped:
			t.Errorf("agent id %q has no mapping decision recorded — add it to AgentToolBaselineProductName "+
				"(with the baseline row it resolves to) or to unmappedAgentToolIDs (with why not)", id)
		}
	}
}

// TestMicrosoftDefenderAntivirusNeverResolves pins the one decision this
// ticket exists to protect: microsoft-defender-antivirus (built-in
// Defender AV, PAT-2267's in-flight Windows detector) must never resolve to
// any protected_software row, however its display name is spelled, because
// doing so would mark every Windows device EDR-covered whether or not
// Defender for Endpoint (the actual EDR, id defender-for-endpoint) is
// onboarded.
func TestMicrosoftDefenderAntivirusNeverResolves(t *testing.T) {
	if _, ok := AgentToolBaselineProductName["microsoft-defender-antivirus"]; ok {
		t.Fatal("microsoft-defender-antivirus must never be added to AgentToolBaselineProductName")
	}
	q := &captureQuerier{}
	m, err := CheckAgentSecurityTool(context.Background(), q, "tenant",
		"microsoft-defender-antivirus", "Microsoft Defender Antivirus")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Fatalf("microsoft-defender-antivirus resolved to a baseline row: %+v", m)
	}
}

// TestCheckAgentSecurityTool_IDResolvesBeforeName proves the id, mapped
// through AgentToolBaselineProductName, is tried before the reported name —
// and that it resolves even when the agent's name differs from the
// baseline's product_name, the exact PAT-2268 defect (Sophos: agent name
// "Sophos Endpoint", baseline product_name "Sophos Intercept X").
func TestCheckAgentSecurityTool_IDResolvesBeforeName(t *testing.T) {
	q := &matchOnQuerier{matchOn: "Sophos Intercept X"}
	m, err := CheckAgentSecurityTool(context.Background(), q, "tenant", "sophos-endpoint", "Sophos Endpoint")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("sophos-endpoint / \"Sophos Endpoint\" did not resolve to the Sophos Intercept X baseline row")
	}
	if len(q.queries) != 1 {
		t.Fatalf("expected the id-mapped lookup to short-circuit (1 query), got %d: %v", len(q.queries), q.queries)
	}
}

// TestCheckAgentSecurityTool_UnmappedIDFallsBackToName proves an agent id
// with no mapping decision (or none at all) still resolves by name, exactly
// as protectedsoftware.Check already did before PAT-2268 — this ticket adds
// an id-first path, it does not remove the name fallback.
func TestCheckAgentSecurityTool_UnmappedIDFallsBackToName(t *testing.T) {
	q := &matchOnQuerier{matchOn: "Malwarebytes"}
	m, err := CheckAgentSecurityTool(context.Background(), q, "tenant", "malwarebytes", "Malwarebytes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("unmapped id malwarebytes with matching name did not resolve")
	}
}

// matchOnQuerier returns a Match whenever the second bind argument
// case-insensitively equals matchOn, otherwise pgx.ErrNoRows (via the
// absentRow helper defined in protectedsoftware_test.go) — enough to drive
// scanMatch's two outcomes without a real database.
type matchOnQuerier struct {
	matchOn string
	queries []string
}

func (q *matchOnQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.queries = append(q.queries, sql)
	if len(args) >= 2 {
		if s, ok := args[1].(string); ok && strings.EqualFold(s, q.matchOn) {
			return matchRow{}
		}
	}
	return absentRow{}
}

// matchRow is a pgx.Row stub that scans a fixed, valid Match — enough to
// prove CheckAgentSecurityTool returns a non-nil match without asserting
// on specific field values a real database would supply.
type matchRow struct{}

func (matchRow) Scan(dest ...any) error {
	*dest[0].(*int64) = 1
	*dest[1].(*string) = "edr"
	*dest[2].(*string) = "Test Vendor"
	*dest[3].(*string) = "Test Product"
	*dest[4].(*bool) = true
	return nil
}
