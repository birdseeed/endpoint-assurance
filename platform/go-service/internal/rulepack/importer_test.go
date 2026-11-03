package rulepack

import "testing"

// planImport is pure — tests exercise it without a DB.

func TestPlanImport_AllNew(t *testing.T) {
	rules := []RuleSpec{
		{RuleKey: "rule_a"},
		{RuleKey: "rule_b"},
	}
	got := planImport(map[string]bool{}, rules)
	for _, r := range got {
		if r.Action != "insert" {
			t.Errorf("rule %q: want insert, got %q", r.RuleKey, r.Action)
		}
	}
}

func TestPlanImport_AllExisting(t *testing.T) {
	existing := map[string]bool{"rule_a": true, "rule_b": true}
	rules := []RuleSpec{
		{RuleKey: "rule_a"},
		{RuleKey: "rule_b"},
	}
	got := planImport(existing, rules)
	for _, r := range got {
		if r.Action != "update" {
			t.Errorf("rule %q: want update, got %q", r.RuleKey, r.Action)
		}
	}
}

func TestPlanImport_Mixed(t *testing.T) {
	existing := map[string]bool{"rule_existing": true}
	rules := []RuleSpec{
		{RuleKey: "rule_existing"},
		{RuleKey: "rule_new"},
	}
	got := planImport(existing, rules)

	if got[0].Action != "update" {
		t.Errorf("rule_existing: want update, got %q", got[0].Action)
	}
	if got[1].Action != "insert" {
		t.Errorf("rule_new: want insert, got %q", got[1].Action)
	}
}

func TestPlanImport_RuleKeyPreserved(t *testing.T) {
	rules := []RuleSpec{{RuleKey: "cis_win_1_1"}}
	got := planImport(map[string]bool{}, rules)
	if got[0].RuleKey != "cis_win_1_1" {
		t.Errorf("rule_key not preserved: got %q", got[0].RuleKey)
	}
}

func TestPlanImport_EmptyPack(t *testing.T) {
	got := planImport(map[string]bool{}, nil)
	if len(got) != 0 {
		t.Errorf("empty rules: expected empty result, got %d rows", len(got))
	}
}

func TestPlanImport_Counts(t *testing.T) {
	existing := map[string]bool{"e1": true, "e2": true}
	rules := []RuleSpec{
		{RuleKey: "e1"},
		{RuleKey: "e2"},
		{RuleKey: "n1"},
		{RuleKey: "n2"},
		{RuleKey: "n3"},
	}
	got := planImport(existing, rules)

	var inserts, updates int
	for _, r := range got {
		switch r.Action {
		case "insert":
			inserts++
		case "update":
			updates++
		}
	}
	if inserts != 3 || updates != 2 {
		t.Errorf("want 3 inserts + 2 updates, got %d inserts + %d updates", inserts, updates)
	}
}

func TestStringDefault(t *testing.T) {
	if stringDefault("", "fail") != "fail" {
		t.Error("empty string should return default")
	}
	if stringDefault("pass", "fail") != "pass" {
		t.Error("non-empty string should return itself")
	}
}

func TestBoolDefault(t *testing.T) {
	if boolDefault(nil, true) != true {
		t.Error("nil pointer should return default true")
	}
	if boolDefault(nil, false) != false {
		t.Error("nil pointer should return default false")
	}
	f := false
	if boolDefault(&f, true) != false {
		t.Error("false pointer should return false regardless of default")
	}
	tr := true
	if boolDefault(&tr, false) != true {
		t.Error("true pointer should return true regardless of default")
	}
}

func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Error("empty string should return nil")
	}
	p := nullIfEmpty("hello")
	if p == nil || *p != "hello" {
		t.Error("non-empty string should return pointer to value")
	}
}

func TestNilIfEmpty(t *testing.T) {
	if nilIfEmpty(nil) != nil {
		t.Error("nil slice should return nil")
	}
	if nilIfEmpty([]string{}) != nil {
		t.Error("empty slice should return nil")
	}
	ss := nilIfEmpty([]string{"a", "b"})
	if len(ss) != 2 {
		t.Error("non-empty slice should be returned unchanged")
	}
}
