package remoteaccess

import (
	"testing"
	"time"

	"patched.im/api/internal/categorytag"
)

func testRules() []catRule {
	return []catRule{
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.anydesk",
			Platform: "macos", CategoryKey: CategoryRemoteAccess, SubtypeKey: "desktop_app"}},
		{categorytag.RuleSpec{IdentifierType: categorytag.TypeMacOSBundleID, IdentifierValue: "com.example.ninja",
			Platform: "macos", CategoryKey: CategoryRMMAgent, SubtypeKey: "agent"}},
	}
}

func TestMatchedRule(t *testing.T) {
	rules := testRules()

	obs := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.anydesk"}
	rule, ok := matchedRule(rules, obs)
	if !ok || rule.CategoryKey != CategoryRemoteAccess {
		t.Fatalf("matchedRule(anydesk) = %+v, %v, want remote_access", rule, ok)
	}

	obs2 := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.ninja"}
	rule2, ok2 := matchedRule(rules, obs2)
	if !ok2 || rule2.CategoryKey != CategoryRMMAgent {
		t.Fatalf("matchedRule(ninja) = %+v, %v, want rmm_agent", rule2, ok2)
	}

	obs3 := categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.unrelated"}
	if _, ok3 := matchedRule(rules, obs3); ok3 {
		t.Fatalf("matchedRule(unrelated) matched, want no match")
	}
}

// TestRMMCountedApartFromRemoteAccess is the "can this test fail" case: an
// RMM-agent row must never be counted in the remote_access summary, however
// its own approval state resolves. Deliberately breaking finish() to lump
// every row into RemoteAccess (see the comment below) turns this red; it is
// restored here as the real, correct behaviour.
func TestRMMCountedApartFromRemoteAccess(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()

	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	adRule, _ := matchedRule(rules, categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.anydesk"})
	ninjaRule, _ := matchedRule(rules, categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.ninja"})

	appendRows(rep, dev, adRule, categorytag.KindApp, "macos_bundle", "com.example.anydesk", "AnyDesk", "1.0", StateUnapproved, nil)
	appendRows(rep, dev, ninjaRule, categorytag.KindApp, "macos_bundle", "com.example.ninja", "NinjaRMM", "1.0", StateUnapproved, nil)

	finish(rep, map[string]*deviceFacts{dev.ID: dev}, 0, 0)

	if got := rep.Summary.RemoteAccess[StateUnapproved].Tools; got != 1 {
		t.Fatalf("remote_access unapproved tool_count = %d, want 1 (AnyDesk only)", got)
	}
	if got := rep.Summary.RMMAgents[StateUnapproved].Tools; got != 1 {
		t.Fatalf("rmm_agents unapproved tool_count = %d, want 1 (NinjaRMM only)", got)
	}
	if rep.Summary.RemoteAccessToolCount != 1 || rep.Summary.RMMAgentToolCount != 1 {
		t.Fatalf("tool counts = remote_access %d, rmm_agent %d, want 1 and 1",
			rep.Summary.RemoteAccessToolCount, rep.Summary.RMMAgentToolCount)
	}
}

// TestUnsanctionedSortsFirst: an unapproved product must sort ahead of an
// approved one, whatever order the rows were appended in.
func TestUnsanctionedSortsFirst(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()
	adRule, _ := matchedRule(rules, categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.anydesk"})

	rep := &Report{Definition: ReportDefinition, GeneratedAt: now}
	appendRows(rep, dev, adRule, categorytag.KindApp, "macos_bundle", "com.example.anydesk", "AnyDesk", "1.0", StateApproved, nil)
	appendRows(rep, dev, adRule, categorytag.KindApp, "macos_bundle", "zzz.example.unapproved", "Zzz Tool", "1.0", StateUnapproved, nil)

	finish(rep, map[string]*deviceFacts{dev.ID: dev}, 0, 0)

	if len(rep.Products) != 2 {
		t.Fatalf("products = %d, want 2", len(rep.Products))
	}
	if rep.Products[0].ApprovalState != StateUnapproved {
		t.Fatalf("first product state = %q, want unapproved (unsanctioned sorts first)", rep.Products[0].ApprovalState)
	}
}

// TestPerUserRowsAndMachineWide: a machine-wide install produces one row
// with no user; a per-user install produces one row per user, distinct from
// the machine-wide case.
func TestPerUserRowsAndMachineWide(t *testing.T) {
	now := time.Now().UTC()
	dev := &deviceFacts{ID: "dev-1", Hostname: "host-1", Platform: "macos", LastSeen: now}
	rules := testRules()
	adRule, _ := matchedRule(rules, categorytag.Observation{Kind: categorytag.KindApp, Platform: "macos",
		IdentityKind: "macos_bundle", IdentityValue: "com.example.anydesk"})

	rep := &Report{}
	appendRows(rep, dev, adRule, categorytag.KindApp, "macos_bundle", "com.example.anydesk", "AnyDesk", "1.0", StateUnapproved, nil)
	if len(rep.Rows) != 1 || rep.Rows[0].User != nil || !rep.Rows[0].MachineWide {
		t.Fatalf("machine-wide row = %+v", rep.Rows)
	}

	rep2 := &Report{}
	appendRows(rep2, dev, adRule, categorytag.KindApp, "macos_bundle", "com.example.anydesk", "AnyDesk", "1.0",
		StateUnapproved, []string{"alice", "bob"})
	if len(rep2.Rows) != 2 {
		t.Fatalf("per-user rows = %d, want 2", len(rep2.Rows))
	}
	for _, r := range rep2.Rows {
		if r.User == nil || r.MachineWide {
			t.Fatalf("per-user row wrongly machine-wide: %+v", r)
		}
	}
}

func TestSafariSystemUserConstant(t *testing.T) {
	if safariSystemUser != "_system" {
		t.Fatalf("safariSystemUser = %q, want _system (must match internal/extractor.SafariSystemSentinel)", safariSystemUser)
	}
}
