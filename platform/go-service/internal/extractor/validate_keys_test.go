package extractor

import (
	"errors"
	"strings"
	"testing"
)

// Review P1: case and Unicode-fold variants of a payload field are rejected
// at the top level and in nested objects the struct decoder reads.
func TestFoldVariantKeysRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		guard bool
		edit  func(m map[string]any)
	}{
		{"MCP_SERVERS top level", true, func(m map[string]any) { m["MCP_SERVERS"] = m["mcp_servers"]; delete(m, "mcp_servers") }},
		{"long s fold top level", true, func(m map[string]any) { m["mcp_ſervers"] = m["mcp_servers"]; delete(m, "mcp_servers") }},
		{"both spellings present", true, func(m map[string]any) { m["Mcp_Servers"] = map[string]any{"collection_status": "failed"} }},
		{"Homebrew top level", false, func(m map[string]any) { m["Homebrew"] = map[string]any{"collection_status": "failed"} }},
		{"Kelvin sign fold top level", false, func(m map[string]any) {
			// U+212A KELVIN SIGN folds to k: "bac\u212aup_status" is backup_status.
			m["bac\u212aup_status"] = map[string]any{"has_backup": "not validated"}
		}},
		{"nested server field", true, func(m map[string]any) {
			s := firstServer(m)
			s["HOST"] = "user:pw@evil.example.test"
		}},
		{"nested model field", false, func(m map[string]any) {
			md := m["local_models"].(map[string]any)["models"].([]any)[0].(map[string]any)
			md["Name"] = "other"
		}},
		{"nested source summary", false, func(m map[string]any) {
			src := m["package_managers"].(map[string]any)["sources"].(map[string]any)["pipx"].(map[string]any)
			src["Collection_Status"] = "complete"
		}},
		{"device field", false, func(m map[string]any) { m["device"].(map[string]any)["Serial"] = "X" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", tc.edit))
			if err == nil {
				t.Fatal("accepted a case or fold variant key")
			}
			var guard *MCPPrivacyGuardError
			if tc.guard != errors.As(err, &guard) {
				t.Fatalf("guard error = %v, want guard %v", err, tc.guard)
			}
			for _, leak := range []string{"evil.example.test", "ſ", "K"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error echoes %q: %v", leak, err)
				}
			}
		})
	}
}

// Keys the decoder ignores stay accepted: fixtures carry "_comment", and the
// Windows agent sends a top-level "installation_evidence" summary, which has
// no field (only apps[].installation_evidence is decoded, PAT-2113).
func TestUnknownNonFoldKeysStillAccepted(t *testing.T) {
	err := ValidatePayload(fixtureWith(t, "with-tooling-complete-windows.json", func(m map[string]any) {
		m["_comment"] = "fixture note"
		m["installation_evidence"] = map[string]any{"schema_version": 1}
	}))
	if err != nil {
		t.Fatal(err)
	}
}

// A duplicated tooling or Homebrew block would be merged by the struct
// decoder while the validator sees only the last copy.
func TestDuplicateStrictBlockKeysRejected(t *testing.T) {
	body := readFixture(t, "valid", "with-tooling-complete-macos.json")
	s := string(body)
	i := strings.Index(s, `"mcp_servers"`)
	dup := s[:i] + `"mcp_servers": {"collection_status": "failed"}, ` + s[i:]
	if err := ValidatePayload([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate mcp_servers accepted: %v", err)
	}
}
