// Package configdiff holds the canonical-JSON field comparison primitives
// shared by every configuration change-detection path in this service.
//
// It was extracted from PAT-1664's internal/intune/diff.go by PAT-1668 so
// the macOS applied-configuration path could reuse the exact comparison
// semantics rather than grow a second, subtly different copy of them. The
// package is deliberately vocabulary-free: it knows about JSON documents
// and field keys, and nothing about Intune objects, Graph, MDM, profiles,
// devices or policies. Each caller keeps its own domain vocabulary and its
// own honesty rules on top.
//
// The one behaviour every caller depends on: two documents that differ only
// in key order or whitespace compare equal and produce zero changes. That is
// what makes a repeated, byte-different-but-semantically-identical
// observation a no-op instead of a fabricated change.
package configdiff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// FieldChange is one changed top-level field of a JSON object: the field's
// key and its value on each side of the comparison. Before and After are
// canonicalised JSON (re-marshalled after decoding, so key order and
// whitespace differences never appear here) rather than the verbatim bytes
// the source sent — that canonicalisation is exactly what makes the
// "reordered keys produce zero changes" rule hold. A field that did not
// exist on one side is represented as JSON null on that side, not as an
// absent field.
//
// There is deliberately no field on this type that holds or implies who
// made a change. Every caller of this package observes state, not authorship,
// and none of them has an actor to record; leaving a slot for one here would
// invite exactly the fabrication their honesty rules forbid.
type FieldChange struct {
	Key    string
	Before json.RawMessage
	After  json.RawMessage
}

// Fields compares two JSON object documents field by field, skipping any key
// present in skip, and returns every field that differs — sorted by key for
// deterministic output. Values are compared after JSON-decoding both sides
// (reflect.DeepEqual on the decoded form), so key reordering or whitespace
// differences between the two raw documents never produce a spurious change.
//
// skip may be nil. Callers use it for two distinct kinds of key, and it is
// worth keeping the distinction straight in the caller rather than here:
// identity keys (the join key, the display name — already represented
// elsewhere in the caller's own entry type) and noise keys (bookkeeping
// timestamps that churn on every re-save without the content changing).
func Fields(beforeRaw, afterRaw json.RawMessage, skip map[string]bool) ([]FieldChange, error) {
	before, err := DecodeObject(beforeRaw)
	if err != nil {
		return nil, fmt.Errorf("configdiff: decode prior document: %w", err)
	}
	after, err := DecodeObject(afterRaw)
	if err != nil {
		return nil, fmt.Errorf("configdiff: decode current document: %w", err)
	}

	keys := make(map[string]bool, len(before)+len(after))
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}

	var changes []FieldChange
	for k := range keys {
		if skip[k] {
			continue
		}
		bv, bok := before[k]
		av, aok := after[k]
		if bok && aok && reflect.DeepEqual(bv, av) {
			continue
		}
		beforeJSON, err := CanonicalJSON(bv, bok)
		if err != nil {
			return nil, fmt.Errorf("configdiff: re-marshal prior value of %q: %w", k, err)
		}
		afterJSON, err := CanonicalJSON(av, aok)
		if err != nil {
			return nil, fmt.Errorf("configdiff: re-marshal current value of %q: %w", k, err)
		}
		changes = append(changes, FieldChange{Key: k, Before: beforeJSON, After: afterJSON})
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes, nil
}

// DecodeObject unmarshals a JSON object document into a map, treating an
// empty document as an empty object rather than an error — a tombstone or
// malformed side should not itself blow up the comparison of an otherwise
// well-formed counterpart.
func DecodeObject(raw json.RawMessage) (map[string]interface{}, error) {
	if len(raw) == 0 {
		return map[string]interface{}{}, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// CanonicalJSON re-marshals a decoded value (or JSON null when the field was
// absent on this side) so FieldChange.Before/After are always canonical
// JSON — deterministic key order and formatting — never the verbatim bytes
// the source happened to send.
func CanonicalJSON(v interface{}, present bool) (json.RawMessage, error) {
	if !present {
		return json.RawMessage("null"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// Canonicalise re-marshals an arbitrary JSON document (object, array, scalar)
// into its canonical form. It reports ok=false when raw is empty or does not
// parse as JSON at all, in which case the returned bytes are raw unchanged —
// callers that may be handed a truncated or otherwise non-JSON body (a
// head-capped payload, for instance) use that signal to fall back to a
// verbatim byte comparison and to say so in their output rather than
// pretending a structural comparison happened.
func Canonicalise(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, false
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw, false
	}
	return out, true
}
