package extractor

import (
	"reflect"
	"strings"
	"testing"
)

func TestAppsUserCompleteSet(t *testing.T) {
	long := strings.Repeat("x", appsMaxUserAccountLen+10)
	cs := &collectionStatusPart{AppsUsers: []appsUserStatusPart{
		{UserAccount: " alice ", CollectionStatus: "complete"},
		{UserAccount: "bob", CollectionStatus: "partial"},
		{UserAccount: "carol", CollectionStatus: "complete"},
		{UserAccount: "carol", CollectionStatus: "unavailable"},
		{UserAccount: "", CollectionStatus: "complete"},
		{UserAccount: "dave", CollectionStatus: "done"},
		{UserAccount: long, CollectionStatus: "complete"},
	}}
	got, sent := appsUserCompleteSet(&payload{SchemaVersion: 3, AppsPresent: true, CollectionStatus: cs})
	// The over-long entry is ignored, never truncated into another key.
	want := []string{"alice"}
	if !sent || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete users = %v (sent %v), want %v", got, sent, want)
	}
	for name, p := range map[string]*payload{
		"schema v2":     {SchemaVersion: 2, AppsPresent: true, CollectionStatus: cs},
		"no apps array": {SchemaVersion: 3, CollectionStatus: cs},
	} {
		if got, sent := appsUserCompleteSet(p); got != nil || !sent {
			t.Errorf("%s: complete users = %v (sent %v), want none", name, got, sent)
		}
	}
	if got, sent := appsUserCompleteSet(&payload{SchemaVersion: 3, AppsPresent: true}); got != nil || sent {
		t.Errorf("no block: %v %v", got, sent)
	}
}

func TestHasMachineWideApps(t *testing.T) {
	if hasMachineWideApps([]appPart{{UserAccount: "alice"}, {UserAccount: "  "}}) != true {
		t.Fatal("a whitespace user_account is machine-wide")
	}
	if hasMachineWideApps([]appPart{{UserAccount: "alice"}}) {
		t.Fatal("per-user rows only is not machine-wide")
	}
}

func TestValidateAppsUsers(t *testing.T) {
	ok := []any{map[string]any{"user_account": "S-1", "collection_status": "complete"}}
	if err := validateAppsUsers(ok); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}
	for name, raw := range map[string]any{
		"object":         map[string]any{},
		"entry string":   []any{"alice"},
		"extra key":      []any{map[string]any{"user_account": "a", "collection_status": "complete", "sid": "x"}},
		"missing user":   []any{map[string]any{"collection_status": "complete"}},
		"missing status": []any{map[string]any{"user_account": "a"}},
		"user not str":   []any{map[string]any{"user_account": 1.0, "collection_status": "complete"}},
		"bad status":     []any{map[string]any{"user_account": "a", "collection_status": "Complete"}},
	} {
		if err := validateAppsUsers(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAppsUserKeyNeverTruncates(t *testing.T) {
	prefix := strings.Repeat("u", appsMaxUserAccountLen)
	if k, ok := appsUserKey(" " + prefix + " "); !ok || k != prefix {
		t.Fatalf("128-character key: %q %v", k, ok)
	}
	for _, long := range []string{prefix + "A", prefix + "B", strings.Repeat("é", appsMaxUserAccountLen+1)} {
		if k, ok := appsUserKey(long); ok || k == prefix {
			t.Fatalf("over-long key accepted or truncated: %q %v", k, ok)
		}
	}
}
