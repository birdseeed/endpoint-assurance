package extractor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// PAT-2055: browser_extensions_status validation.

func beUser(user, status, chrome, edge, firefox string) map[string]any {
	return map[string]any{"user": user, "user_id": nil, "collection_status": status,
		"browsers": map[string]any{"chrome": chrome, "edge": edge, "firefox": firefox}}
}

// with-browser-extensions.json lists alice's Chrome and Firefox extensions.
func beFixture(t *testing.T, block any) []byte {
	t.Helper()
	return fixtureWith(t, "with-browser-extensions.json", func(m map[string]any) {
		if block != nil {
			m["browser_extensions_status"] = block
		}
	})
}

func TestBrowserExtensionsStatusAccepted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block any
	}{
		{"absent (older agent)", nil},
		{"complete", map[string]any{"collection_status": "complete", "cap_reached": false,
			"users": []any{beUser("alice", "complete", "complete", "not_present", "complete")}}},
		{"partial with a failed browser", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "partial", "complete", "failed", "complete")}}},
		{"partial and capped", map[string]any{"collection_status": "partial", "cap_reached": true,
			"users": []any{beUser("alice", "partial", "complete", "partial", "complete")}}},
		{"failed, bare", map[string]any{"collection_status": "failed"}},
		{"failed user may omit browsers", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{
				beUser("alice", "complete", "complete", "not_present", "complete"),
				map[string]any{"user": "bob", "user_id": nil, "collection_status": "failed", "browsers": map[string]any{}},
			}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := beFixture(t, tc.block)
			if err := ValidatePayload(data); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			var p payload
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			if (tc.block == nil) != (p.BrowserExtensionsStatus == nil) {
				t.Fatalf("decoded block = %+v", p.BrowserExtensionsStatus)
			}
		})
	}
}

// Malformed STRUCTURE is still a 400.
func TestBrowserExtensionsStatusRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block any
		want  string
	}{
		{"not an object", "complete", "must be an object"},
		{"no status", map[string]any{"cap_reached": false, "users": []any{}}, "collection_status: required"},
		{"unknown status", map[string]any{"collection_status": "done", "cap_reached": false, "users": []any{}}, "not in enum"},
		{"unknown key", map[string]any{"collection_status": "partial", "cap_reached": false, "users": []any{}, "truncated": true}, "additional properties"},
		{"partial without users", map[string]any{"collection_status": "partial", "cap_reached": false}, "users: required"},
		{"partial without cap_reached", map[string]any{"collection_status": "partial", "users": []any{}}, "cap_reached: required"},
		{"cap_reached not a bool", map[string]any{"collection_status": "partial", "cap_reached": "yes", "users": []any{}}, "must be a boolean"},
		{"users not an array", map[string]any{"collection_status": "partial", "cap_reached": false, "users": map[string]any{}}, "must be an array"},
		{"browser missing", map[string]any{"collection_status": "complete", "cap_reached": false,
			"users": []any{map[string]any{"user": "alice", "user_id": nil, "collection_status": "complete",
				"browsers": map[string]any{"chrome": "complete", "firefox": "complete"}}}}, "edge: required"},
		{"unknown browser", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{map[string]any{"user": "alice", "user_id": nil, "collection_status": "partial",
				"browsers": map[string]any{"chrome": "complete", "edge": "partial", "firefox": "complete", "brave": "complete"}}}}, "additional properties"},
		{"bad browser status", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "partial", "complete", "done", "complete")}}, "not in enum"},
		{"empty user", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("", "partial", "complete", "partial", "complete")}}, "must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(beFixture(t, tc.block))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			for _, leak := range []string{"alice", "bob"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error echoes a user name: %v", err)
				}
			}
		})
	}
}

// Review P2: a structurally valid block that is inconsistent, with itself or
// with the rows, is ACCEPTED (the device's inventory must not be dropped) and
// the extractor withholds its authority for the named reason.
func TestBrowserExtensionsStatusInconsistentAcceptedButWithheld(t *testing.T) {
	complete := func(users ...any) map[string]any {
		return map[string]any{"collection_status": "complete", "cap_reached": false, "users": users}
	}
	manyUsers := make([]any, 0, 501)
	for i := 0; i < 501; i++ {
		manyUsers = append(manyUsers, beUser(fmt.Sprintf("u%03d", i), "partial", "partial", "partial", "partial"))
	}
	for _, tc := range []struct {
		name   string
		block  map[string]any
		reason string
	}{
		{"complete and capped", map[string]any{"collection_status": "complete", "cap_reached": true,
			"users": []any{beUser("alice", "complete", "complete", "not_present", "complete")}}, beWithheldCapNotPartial},
		{"not_present and capped", map[string]any{"collection_status": "not_present", "cap_reached": true, "users": []any{}}, beWithheldCapNotPartial},
		{"501 users", map[string]any{"collection_status": "partial", "cap_reached": false, "users": manyUsers}, beWithheldTooManyUsers},
		{"duplicate user", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "partial", "complete", "partial", "complete"), beUser("alice", "partial", "complete", "partial", "complete")}}, beWithheldDuplicateUser},
		{"complete block, partial user", complete(beUser("alice", "partial", "complete", "complete", "complete")), beWithheldUserStatus},
		{"complete block, failed browser", complete(beUser("alice", "complete", "complete", "failed", "complete")), beWithheldBrowserStatus},
		{"complete user, partial browser", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "complete", "complete", "partial", "complete")}}, beWithheldBrowserStatus},
		{"row under a not_present pair", map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "partial", "complete", "partial", "not_present")}}, beWithheldRowUnderNotPresent},
		{"not_present block with rows", map[string]any{"collection_status": "not_present", "cap_reached": false, "users": []any{}}, beWithheldRowsWhenNotPresent},
		{"complete block misses a listed user", complete(beUser("bob", "not_present", "not_present", "not_present", "not_present")), beWithheldRowNotCoveredByBlock},
		{"user case differs from rows", complete(beUser("Alice", "complete", "complete", "not_present", "complete")), beWithheldRowNotCoveredByBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := beFixture(t, tc.block)
			if err := ValidatePayload(data); err != nil {
				t.Fatalf("an inconsistent but well-formed block rejected the payload: %v", err)
			}
			var p payload
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			if got := browserExtensionsStatusProblem(p.BrowserExtensionsStatus, p.BrowserExtensions); got != tc.reason {
				t.Fatalf("problem = %q, want %q", got, tc.reason)
			}
		})
	}

	// Consistent blocks, and failed ones, carry no problem.
	for _, block := range []map[string]any{
		complete(beUser("alice", "complete", "complete", "not_present", "complete")),
		{"collection_status": "partial", "cap_reached": true, "users": []any{beUser("alice", "partial", "complete", "partial", "complete")}},
		{"collection_status": "failed", "cap_reached": true},
	} {
		var p payload
		if err := json.Unmarshal(beFixture(t, block), &p); err != nil {
			t.Fatal(err)
		}
		if got := browserExtensionsStatusProblem(p.BrowserExtensionsStatus, p.BrowserExtensions); got != "" {
			t.Fatalf("consistent block %v flagged %q", block, got)
		}
	}
}

// PAT-2021: Go's decoder would read any of these into the typed block, so the
// key walk must reject them before the exact-key checks run.
func TestBrowserExtensionsStatusCaseVariantKeysRejected(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{"collection_status": "partial", "cap_reached": false,
			"users": []any{beUser("alice", "partial", "complete", "partial", "complete")}}
	}
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"top-level key upper-cased", func(m map[string]any) { m["Browser_Extensions_Status"] = valid() }},
		{"top-level key long-s fold", func(m map[string]any) { m["browser_extenſions_status"] = valid() }},
		{"both spellings", func(m map[string]any) {
			m["browser_extensions_status"] = valid()
			m["BROWSER_EXTENSIONS_STATUS"] = valid()
		}},
		{"block field", func(m map[string]any) {
			b := valid()
			b["Collection_Status"] = "complete"
			m["browser_extensions_status"] = b
		}},
		{"user field", func(m map[string]any) {
			b := valid()
			b["users"].([]any)[0].(map[string]any)["User"] = "bob"
			m["browser_extensions_status"] = b
		}},
		{"browser key", func(m map[string]any) {
			b := valid()
			b["users"].([]any)[0].(map[string]any)["browsers"].(map[string]any)["Chrome"] = "complete"
			m["browser_extensions_status"] = b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(fixtureWith(t, "with-browser-extensions.json", tc.edit)); err == nil {
				t.Fatal("accepted a case or fold variant key")
			}
		})
	}
}

// A duplicated block key is rejected: the decoder would merge both copies.
func TestBrowserExtensionsStatusDuplicateKeyRejected(t *testing.T) {
	data := beFixture(t, map[string]any{"collection_status": "partial", "cap_reached": false, "users": []any{}})
	dup := strings.Replace(string(data), `"browser_extensions_status":`,
		`"browser_extensions_status":{"collection_status":"complete","cap_reached":false,"users":[]},"browser_extensions_status":`, 1)
	if dup == string(data) {
		t.Fatal("test did not inject the duplicate")
	}
	if err := ValidatePayload([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("error = %v, want duplicate key", err)
	}
}

func TestBrowserExtensionPairStates(t *testing.T) {
	s := func(v string) *string { return &v }
	st := &browserExtensionsStatusPart{CollectionStatus: "partial", Users: []browserExtensionsStatusUserPart{
		{User: "alice", CollectionStatus: "partial", Browsers: browserExtensionsStatusBrowserMap{Chrome: s("complete"), Edge: s("failed"), Firefox: s("not_present")}},
		{User: "bob", CollectionStatus: "failed", Browsers: browserExtensionsStatusBrowserMap{Chrome: s("complete")}},
	}}
	got := map[string]bool{}
	for _, p := range browserExtensionPairStates(st) {
		got[p.user+"/"+p.browser] = p.authoritative
	}
	want := map[string]bool{"alice/chrome": true, "alice/edge": false, "alice/firefox": true, "bob/chrome": false}
	if len(got) != len(want) {
		t.Fatalf("pairs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("pairs = %v, want %v", got, want)
		}
	}

	st.CapReached = true
	for _, p := range browserExtensionPairStates(st) {
		if p.authoritative {
			t.Fatalf("capped block granted authority to %s/%s", p.user, p.browser)
		}
	}
	if browserExtensionsBlockAuthoritative(st) {
		t.Fatal("capped block is authoritative")
	}
	if got := browserExtensionPairStates(&browserExtensionsStatusPart{CollectionStatus: "failed"}); got != nil {
		t.Fatalf("failed block recorded pairs %v", got)
	}
	for status, want := range map[string]bool{"complete": true, "not_present": true, "partial": false, "failed": false} {
		if got := browserExtensionsBlockAuthoritative(&browserExtensionsStatusPart{CollectionStatus: status}); got != want {
			t.Fatalf("%s authoritative = %v", status, got)
		}
	}
}
