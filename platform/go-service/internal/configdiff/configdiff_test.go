package configdiff

import (
	"encoding/json"
	"reflect"
	"testing"
)

func keysOf(changes []FieldChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Key)
	}
	return out
}

// TestFields_KeyOrderAndWhitespaceAreNotChanges is the property every caller
// of this package depends on: a document re-serialised differently has not
// changed.
func TestFields_KeyOrderAndWhitespaceAreNotChanges(t *testing.T) {
	before := json.RawMessage(`{"a":1,"b":{"x":true,"y":[1,2]}}`)
	after := json.RawMessage("{\n  \"b\" : { \"y\" : [1, 2], \"x\" : true },\n  \"a\": 1\n}")

	changes, err := Fields(before, after, nil)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("got %d changes, want 0: %+v", len(changes), changes)
	}
}

func TestFields_ReportsChangedAddedAndRemovedKeys(t *testing.T) {
	before := json.RawMessage(`{"kept":1,"changed":"old","removed":true}`)
	after := json.RawMessage(`{"kept":1,"changed":"new","added":[1]}`)

	changes, err := Fields(before, after, nil)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	// Sorted by key, deterministically.
	if got, want := keysOf(changes), []string{"added", "changed", "removed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}

	byKey := map[string]FieldChange{}
	for _, c := range changes {
		byKey[c.Key] = c
	}
	// An absent side is JSON null, not an absent field, so a reader never
	// has to guess which side the key was missing from.
	if string(byKey["added"].Before) != "null" || string(byKey["added"].After) != "[1]" {
		t.Errorf("added = %+v", byKey["added"])
	}
	if string(byKey["removed"].Before) != "true" || string(byKey["removed"].After) != "null" {
		t.Errorf("removed = %+v", byKey["removed"])
	}
	if string(byKey["changed"].Before) != `"old"` || string(byKey["changed"].After) != `"new"` {
		t.Errorf("changed = %+v", byKey["changed"])
	}
}

func TestFields_SkipSuppressesKeys(t *testing.T) {
	before := json.RawMessage(`{"id":"a","noise":"2026-07-01","real":1}`)
	after := json.RawMessage(`{"id":"b","noise":"2026-08-02","real":2}`)

	changes, err := Fields(before, after, map[string]bool{"id": true, "noise": true})
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if got, want := keysOf(changes), []string{"real"}; !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

func TestFields_EmptyDocumentIsAnEmptyObject(t *testing.T) {
	changes, err := Fields(nil, json.RawMessage(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if got, want := keysOf(changes), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

func TestFields_MalformedDocumentErrors(t *testing.T) {
	if _, err := Fields(json.RawMessage(`not json`), json.RawMessage(`{}`), nil); err == nil {
		t.Error("Fields accepted a malformed prior document")
	}
	if _, err := Fields(json.RawMessage(`{}`), json.RawMessage(`[1,2]`), nil); err == nil {
		t.Error("Fields accepted a JSON array where an object was required")
	}
}

func TestCanonicalise(t *testing.T) {
	// An array canonicalises too, not just an object — the macOS profile
	// payload path depends on that.
	got, ok := Canonicalise(json.RawMessage(`[ {"b":2,  "a":1} ]`))
	if !ok {
		t.Fatal("Canonicalise reported a well-formed array as unparseable")
	}
	if string(got) != `[{"a":1,"b":2}]` {
		t.Errorf("got %s, want canonical key order", got)
	}

	// A truncated fragment — the head-capped payload case — must report
	// ok=false and hand the input straight back, so the caller can fall
	// back to a verbatim comparison and say it did.
	fragment := json.RawMessage(`[{"PayloadType": "com.apple.secu`)
	back, ok := Canonicalise(fragment)
	if ok {
		t.Error("Canonicalise reported a truncated fragment as parseable")
	}
	if string(back) != string(fragment) {
		t.Errorf("got %s, want the input unchanged", back)
	}

	if _, ok := Canonicalise(nil); ok {
		t.Error("Canonicalise reported an empty document as parseable")
	}
}

func TestCanonicalJSON_AbsentFieldIsNull(t *testing.T) {
	got, err := CanonicalJSON(nil, false)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != "null" {
		t.Errorf("got %s, want null", got)
	}
}

// TestFieldChange_NoActorField: this type is the shared shape every
// change-detection path in the service reports through, so the honesty rule
// that forbids an actor field is enforced at its definition rather than once
// per caller.
func TestFieldChange_NoActorField(t *testing.T) {
	typ := reflect.TypeOf(FieldChange{})
	want := []string{"Key", "Before", "After"}
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FieldChange fields = %v, want exactly %v — a new field here reaches every caller", got, want)
	}
}
