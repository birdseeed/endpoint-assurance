package extractor

import (
	"encoding/json"
	"testing"
)

// PAT-2328: the field must survive the same typed decode used by extraction.
// JSON round-tripping lets this regression run before the new struct member
// exists, so failure is dropped evidence rather than a compile error.
func TestUsageEvidenceDecodedWithoutInventingUsage(t *testing.T) {
	for _, state := range []string{"recorded", "no_record", "unmapped", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			body := readFixture(t, "valid", "usage-evidence-"+state+".json")
			if err := ValidatePayload(body); err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			var p payload
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
			decoded, err := json.Marshal(p.Apps[0])
			if err != nil {
				t.Fatal(err)
			}
			var app map[string]any
			if err := json.Unmarshal(decoded, &app); err != nil {
				t.Fatal(err)
			}
			if got := app["usage_evidence"]; got != state {
				t.Errorf("decoded usage_evidence = %v, want %q (raw evidence discarded)", got, state)
			}
			if state == "recorded" {
				if p.Apps[0].LastUsedAt == nil || *p.Apps[0].LastUsedAt != "2026-11-01T12:00:00Z" || p.Apps[0].LaunchCount == nil || *p.Apps[0].LaunchCount != 3 {
					t.Error("recorded usage changed during decode")
				}
			} else if p.Apps[0].LastUsedAt != nil || p.Apps[0].LaunchCount != nil {
				t.Error("non-recorded evidence invented a timestamp or count")
			}
		})
	}
}

func TestUsageEvidenceOlderAgentRemainsNotReported(t *testing.T) {
	body := readFixture(t, "valid", "minimal.json")
	if err := ValidatePayload(body); err != nil {
		t.Fatal(err)
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	decoded, err := json.Marshal(p.Apps[0])
	if err != nil {
		t.Fatal(err)
	}
	var app map[string]any
	if err := json.Unmarshal(decoded, &app); err != nil {
		t.Fatal(err)
	}
	if got := app["usage_evidence"]; got != nil && got != "" {
		t.Errorf("older agent assigned usage evidence %v", got)
	}
	if p.Apps[0].LastUsedAt != nil || p.Apps[0].LaunchCount != nil {
		t.Error("older agent invented usage")
	}
}

func TestUsageEvidenceMalformedRejected(t *testing.T) {
	for _, tag := range []string{"unknown", "wrong-type", "empty"} {
		t.Run(tag, func(t *testing.T) {
			if err := ValidatePayload(readFixture(t, "invalid", "usage-evidence-"+tag+".json")); err == nil {
				t.Error("malformed usage evidence accepted; it must never acquire non-use authority")
			}
		})
	}
}

func TestUsageEvidencePositiveCountWithoutTimestamp(t *testing.T) {
	body := fixtureWith(t, "usage-evidence-recorded.json", func(p map[string]any) { p["apps"].([]any)[0].(map[string]any)["last_used_at"] = nil })
	if err := ValidatePayload(body); err != nil {
		t.Fatalf("positive count is recorded evidence: %v", err)
	}
}
func TestUsageEvidenceClaimsRequireRawSupport(t *testing.T) {
	for _, state := range []string{"recorded", "no_record", "unmapped"} {
		t.Run(state, func(t *testing.T) {
			body := fixtureWith(t, "usage-evidence-"+state+".json", func(p map[string]any) {
				app := p["apps"].([]any)[0].(map[string]any)
				if state == "recorded" {
					app["last_used_at"] = nil
					app["launch_count"] = 0
				} else {
					app["last_used_at"] = "2026-11-01T12:00:00Z"
				}
			})
			if err := ValidatePayload(body); err == nil {
				t.Error("contradictory or unsupported evidence accepted")
			}
		})
	}
}
func TestUsageEvidencePartialCannotSupportNonUse(t *testing.T) {
	if usageEvidenceComplete(appsSignalIncomplete, "", nil) || usageEvidenceComplete(appsSignalNone, "", nil) || usageEvidenceComplete(appsSignalComplete, "unread-user", nil) {
		t.Fatal("incomplete or unreported scope gained non-use authority")
	}
	if !usageEvidenceComplete(appsSignalComplete, "", nil) || !usageEvidenceComplete(appsSignalIncomplete, "read-user", []string{"read-user"}) {
		t.Fatal("complete scope lost its authority")
	}
}

func TestUsageEvidenceConflictingScopesCannotGainAuthority(t *testing.T) {
	recorded, unavailable, date := "recorded", "unavailable", "2026-07-01T00:00:00Z"
	a := appPart{Identifier: "example", Version: "1", UsageEvidence: &recorded, LastUsedAt: &date}
	b := a
	b.UserAccount = "alice"
	b.UsageEvidence = &unavailable
	b.LastUsedAt = nil
	for _, rows := range [][]appPart{{a, b}, {b, a}} {
		if !appUsageConflicts(rows)[appUsageKey(a)] {
			t.Fatal("shared app row gained authority from one readable user scope")
		}
	}
}

func TestUsageEvidenceCountValidation(t *testing.T) {
	for _, key := range []string{"metering_user_hive_count", "metering_record_count", "launch_count"} {
		for _, invalid := range []any{-1, 1.5, 2147483648, "1", true} {
			body := fixtureWith(t, "usage-evidence-recorded.json", func(p map[string]any) {
				if key == "launch_count" {
					p["apps"].([]any)[0].(map[string]any)[key] = invalid
				} else {
					p[key] = invalid
				}
			})
			if err := ValidatePayload(body); err == nil {
				t.Errorf("%s accepted %v", key, invalid)
			}
		}
	}
}
