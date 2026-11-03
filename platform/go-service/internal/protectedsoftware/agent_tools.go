package protectedsoftware

import (
	"context"
	"strings"
)

// PAT-2268: agents report security_tools as [{id, name}] (docs/
// PAYLOAD_SCHEMA.md). id is the agent's own stable slug for the product it
// detected; name is a human display string the agent chooses independently
// of what any protected_software baseline row happens to be called. The
// two can legitimately differ for the SAME product — the macOS and Windows
// agents report {"id":"sophos-endpoint","name":"Sophos Endpoint"} while
// PAT-1801's baseline seed named the row "Sophos Intercept X"; both name
// CrowdStrike's and SentinelOne's sensors differently from their baseline
// product_name too. Matching on name alone (edr_coverage.go's pre-PAT-2268
// edrToolMatches) therefore told a real, baseline-covered device it was
// running unrecognised security software.
//
// AgentToolBaselineProductName is the single authoritative id -> baseline
// product_name resolution. CheckAgentSecurityTool is the one function every
// reader of security_tools must call to resolve an entry against
// protected_software — do not add a second id/name matcher elsewhere; grep
// this package's callers before writing a new one.
//
// Each key here is an id one of the agents' own fixed detection tables can
// actually emit today: macOS updater/macos/lib/sectools.sh
// (collect_sectools' _check_for_tool calls) and Windows
// updater/windows/src/Service/SecurityToolDetector.cs (KnownTools). A value
// must name exactly one existing protected_software baseline row of the
// SAME product (verified by the tests in agent_tools_test.go and
// edr_coverage_migrated_db_test.go) — this map does not create baseline
// rows, only resolves an id to one that migrations/0139 or 0212 already
// seeded.
var AgentToolBaselineProductName = map[string]string{
	"crowdstrike-falcon":    "CrowdStrike Falcon Sensor",       // migration 0139
	"sentinelone":           "SentinelOne Agent",               // migration 0139
	"sophos-endpoint":       "Sophos Intercept X",              // migration 0139
	"defender-for-endpoint": "Microsoft Defender for Endpoint", // migration 0139
	"bitdefender":           "Bitdefender",                     // migration 0212
}

// unmappedAgentToolIDs are agent ids that were deliberately reviewed and
// left out of AgentToolBaselineProductName — a recorded decision, not an
// oversight. Kept here, next to the map, so the reasoning travels with the
// code rather than living only in a test fixture or a ticket comment.
// agent_tools_test.go pins that every id an agent's table emits appears in
// one of these two sets.
//
//   - jamf-protect, huntress, malwarebytes, carbon-black, eset-endpoint:
//     no protected_software baseline row exists for any of these products.
//     PAT-1801's seed (migration 0139) covers CrowdStrike, SentinelOne,
//     Microsoft Defender for Endpoint and Sophos only. An id cannot resolve
//     to a row that was never seeded; add the baseline row (and this
//     mapping) together if one of these should start counting as EDR
//     coverage.
//   - microsoft-defender-antivirus: emitted by the in-flight, not-yet-
//     shipped Windows detector at updater-pat-2267/windows/src/Shared/
//     SecurityTools/SecurityToolLogic.cs. That file deliberately keeps this
//     id distinct from defender-for-endpoint: built-in Defender Antivirus
//     ships on every Windows client regardless of whether the device is
//     onboarded to Defender for Endpoint (the actual EDR). Mapping this id
//     to the "Microsoft Defender for Endpoint" baseline row would mark
//     every Windows device EDR-covered whether or not MDE is actually
//     running. This entry must never move into the map above.
var unmappedAgentToolIDs = map[string]bool{
	"jamf-protect":                 true,
	"huntress":                     true,
	"malwarebytes":                 true,
	"carbon-black":                 true,
	"eset-endpoint":                true,
	"microsoft-defender-antivirus": true,
}

// CheckAgentSecurityTool resolves one agent-reported security_tools entry
// (its stable id and display name) against protected_software for
// tenantID — the shared baseline (minus any tenant override) plus the
// tenant's own additions. It returns (nil, nil) when nothing matches: an
// unrecognised tool is NOT protected/covered, the same fail-closed contract
// Check documents.
//
// Precedence mirrors Check's own strong-identifier-before-name rule,
// applied to the id/name pair security_tools carries instead of
// team_id/bundle_id: the id, resolved through AgentToolBaselineProductName,
// is tried FIRST. Only when the id is unmapped, or the mapped baseline row
// doesn't actually resolve for this tenant (e.g. overridden), does this
// fall back to the reported display name and then the raw id string,
// through Check's existing process_name/product_name weak-match tier — so
// a tenant's own protected_software addition, or an agent id this map
// hasn't been taught yet, can still match on name exactly as before
// PAT-2268.
func CheckAgentSecurityTool(ctx context.Context, q Querier, tenantID, id, name string) (*Match, error) {
	trimmedID := strings.TrimSpace(id)
	if canonical, ok := AgentToolBaselineProductName[trimmedID]; ok {
		m, err := checkProductName(ctx, q, tenantID, canonical)
		if err != nil {
			return nil, err
		}
		if m != nil {
			return m, nil
		}
	}
	for _, candidate := range []string{name, id} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		m, err := checkProcessName(ctx, q, tenantID, candidate)
		if err != nil {
			return nil, err
		}
		if m != nil {
			return m, nil
		}
	}
	return nil, nil
}
