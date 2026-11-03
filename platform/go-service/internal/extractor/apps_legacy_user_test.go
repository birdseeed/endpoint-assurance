package extractor

import (
	"strings"
	"testing"
)

func strptr(s string) *string { return &s }

func TestLegacyUserHomeIsExactlyUsersSegment(t *testing.T) {
	for _, home := range []string{"/Users/alice", "/Users/profile-alias", "/Users/a b", "/Users/shared"} {
		if !legacyUserHome(home) {
			t.Errorf("%q refused", home)
		}
	}
	for _, home := range []string{
		"", " ", "/", "/Users", "/Users/", "/Users/alice/", "//Users/alice", "/Users//alice",
		"/Users/./alice", "/Users/.", "/Users/..", "/Users/alice/..", "/Users/alice/../bob",
		"Users/alice", "alice", "~", "~/", "/Users/Shared", "/private/Users/alice",
		"/users/alice", "/Users/alice/Applications", "/Users/alice\x00", " /Users/alice",
	} {
		if legacyUserHome(home) {
			t.Errorf("%q accepted as a home", home)
		}
	}
}

func TestLegacyRowHome(t *testing.T) {
	for path, want := range map[string]string{
		"/Users/alice/Applications/A.app": "/Users/alice",
		"/Users/alice/A.app":              "/Users/alice",
		"/Users/al/Applications/A.app":    "/Users/al",
	} {
		if got, ok := legacyRowHome(path); !ok || got != want {
			t.Errorf("%q: home %q ok=%v, want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{
		"", "/Applications/A.app", "/Users/A.app", "/Users/alice", "/Users/alice/",
		"/Users/Shared/Applications/A.app", "/Users//Applications/A.app",
		"/Users/../Applications/A.app", "/Users/./Applications/A.app",
		"Users/alice/Applications/A.app", `C:\Users\alice\AppData\A`, "/private/Users/alice/A.app",
	} {
		if home, ok := legacyRowHome(path); ok {
			t.Errorf("%q treated as inside home %q", path, home)
		}
	}
}

func legacyHoldFor(entries ...appsUserStatusPart) legacyUserHold {
	p := &payload{SchemaVersion: 3, AppsPresent: true,
		CollectionStatus: &collectionStatusPart{Apps: "complete", AppsUsers: entries}}
	complete, _ := appsUserCompleteSet(p)
	return resolveLegacyUserHold(p, complete)
}

func TestResolveLegacyUserHold(t *testing.T) {
	if h := resolveLegacyUserHold(&payload{}, nil); h.Active {
		t.Fatal("a report with no collection_status is active")
	}
	if h := resolveLegacyUserHold(&payload{CollectionStatus: &collectionStatusPart{Apps: "complete"}}, nil); h.Active {
		t.Fatal("a report with no apps_users key is active")
	}
	empty := &payload{CollectionStatus: &collectionStatusPart{AppsUsers: []appsUserStatusPart{}}}
	if h := resolveLegacyUserHold(empty, nil); !h.Active || len(h.owner) != 0 || len(h.homeOf) != 0 {
		t.Fatalf("empty apps_users: %+v", h)
	}

	h := legacyHoldFor(
		appsUserStatusPart{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/profile-alias")},
		appsUserStatusPart{UserAccount: "bob", CollectionStatus: "partial", Home: strptr("/Users/bob-home")},
		appsUserStatusPart{UserAccount: "carol", CollectionStatus: "complete"},
	)
	if h.owner["/Users/profile-alias"] != "alice" || len(h.owner) != 1 {
		t.Fatalf("owner = %v, want only alice", h.owner)
	}
	if h.homeOf["bob"] != "/Users/bob-home" || h.homeOf["alice"] != "/Users/profile-alias" || len(h.homeOf) != 2 {
		t.Fatalf("homeOf = %v", h.homeOf)
	}

	for name, entries := range map[string][]appsUserStatusPart{
		"two users one home": {
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h")},
			{UserAccount: "bob", CollectionStatus: "complete", Home: strptr("/Users/h")}},
		"one user two homes": {
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h")},
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/i")}},
		"one user, a valid and an unusable home": {
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h")},
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/")}},
		"duplicate entry not complete": {
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h")},
			{UserAccount: "alice", CollectionStatus: "partial", Home: strptr("/Users/h")}},
		"trailing slash": {
			{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h/")}},
		"over-long user": {
			{UserAccount: strings.Repeat("u", 129), CollectionStatus: "complete", Home: strptr("/Users/h")}},
		"empty user": {
			{UserAccount: " ", CollectionStatus: "complete", Home: strptr("/Users/h")}},
	} {
		if h := legacyHoldFor(entries...); len(h.owner) != 0 {
			t.Errorf("%s: owner = %v, want none", name, h.owner)
		}
	}

	// Authority needs schema v3 and an apps array, like any per-user prune.
	p := &payload{SchemaVersion: 2, AppsPresent: true, CollectionStatus: &collectionStatusPart{
		AppsUsers: []appsUserStatusPart{{UserAccount: "alice", CollectionStatus: "complete", Home: strptr("/Users/h")}}}}
	complete, _ := appsUserCompleteSet(p)
	if h := resolveLegacyUserHold(p, complete); !h.Active || len(h.owner) != 0 || h.homeOf["alice"] != "/Users/h" {
		t.Fatalf("schema v2: %+v", h)
	}
}

func TestValidateAppsUsersHome(t *testing.T) {
	entry := func(home any) []any {
		return []any{map[string]any{"user_account": "alice", "collection_status": "complete", "home": home}}
	}
	for _, home := range []any{"/Users/alice", "", "/", "relative", "/Users/alice/.."} {
		if err := validateAppsUsers(entry(home)); err != nil {
			t.Errorf("string home %q refused: %v", home, err)
		}
	}
	for _, home := range []any{7.0, true, nil, []any{"/Users/alice"}, map[string]any{"path": "/Users/alice"}} {
		if err := validateAppsUsers(entry(home)); err == nil {
			t.Errorf("non-string home %#v accepted", home)
		}
	}
	if err := validateAppsUsers([]any{map[string]any{"user_account": "alice", "collection_status": "complete", "Home": "/Users/alice"}}); err == nil {
		t.Error("a key other than home was accepted")
	}
}
