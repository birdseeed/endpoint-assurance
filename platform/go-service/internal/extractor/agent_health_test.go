package extractor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseUpdateChannelObservationIndependentOfDegraded(t *testing.T) {
	for _, raw := range []string{
		`{"update_channel":{"channel":"beta","source":"device_override","config_version":12}}`,
		`{"update_channel":{"channel":"stable","source":"tenant","config_version":1}}`,
	} {
		if _, ok := parseUpdateChannelObservation(json.RawMessage(raw), nil); !ok {
			t.Fatalf("valid observation rejected: %s", raw)
		}
	}
	for _, raw := range []string{
		`{}`, `{"update_channel":{"channel":"beta","config_version":12}}`,
		`{"update_channel":{"channel":"beta","source":"made_up","config_version":12}}`,
		`{"update_channel":{"channel":"beta","source":"tenant","config_version":0}}`,
		`{"update_channel":{"CHANNEL":"beta","source":"tenant","config_version":1}}`,
		`{"update_channel":{"channel":"beta","source":"tenant","config_version":1,"SOURCE":"device_override"}}`,
		`{"update_channel":{"channel":"stable","channel":"beta","source":"tenant","config_version":1}}`,
		`{"update_channel":{"channel":"stable","source":"tenant","config_version":1},"update_channel":{"channel":"beta","source":"tenant","config_version":2}}`,
	} {
		if _, ok := parseUpdateChannelObservation(json.RawMessage(raw), nil); ok {
			t.Fatalf("invalid observation accepted: %s", raw)
		}
	}
}

// ── Payload parsing ───────────────────────────────────────────────────────────

// TestAgentHealthAbsentKey verifies that a payload without the "agent_health"
// key produces an empty AgentHealth RawMessage — the "older agent" case that
// parseAgentHealth must treat as no opinion, not as an all-clear.
func TestAgentHealthAbsentKey(t *testing.T) {
	var p payload
	if err := json.Unmarshal(loadFixture(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.AgentHealth) != 0 {
		t.Errorf("AgentHealth must be empty when key is absent; got %q", p.AgentHealth)
	}
}

// TestAgentHealthPayloadParse verifies a payload carrying agent_health
// unmarshals the raw section, and that section decodes into the expected
// envelope shape.
func TestAgentHealthPayloadParse(t *testing.T) {
	base := loadFixture(t)
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	m["agent_health"] = map[string]any{
		"degraded": []any{
			map[string]any{
				"kind":           "directive_skipped",
				"subject":        "log_upload",
				"reason":         "device_id_mismatch",
				"first_seen":     "2026-12-01T09:00:00Z",
				"last_seen":      "2026-07-28T09:00:00Z",
				"count":          1119,
				"ever_succeeded": false,
			},
		},
	}
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal patched: %v", err)
	}

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	if len(p.AgentHealth) == 0 {
		t.Fatal("AgentHealth: empty raw section after patching in agent_health")
	}

	envelope, present := parseAgentHealth(p.AgentHealth, nil)
	if !present {
		t.Fatal("parseAgentHealth: present=false for a well-formed section")
	}
	if envelope.Degraded == nil {
		t.Fatal("Degraded: nil pointer for a well-formed present-with-entries section")
	}
	if got, want := len(*envelope.Degraded), 1; got != want {
		t.Fatalf("Degraded len: got %d want %d", got, want)
	}

	var e agentHealthEntryPart
	if err := json.Unmarshal((*envelope.Degraded)[0], &e); err != nil {
		t.Fatalf("unmarshal degraded[0]: %v", err)
	}
	if e.Kind != "directive_skipped" {
		t.Errorf("kind: got %q want directive_skipped", e.Kind)
	}
	if e.Subject != "log_upload" {
		t.Errorf("subject: got %q want log_upload", e.Subject)
	}
	if e.Reason != "device_id_mismatch" {
		t.Errorf("reason: got %q want device_id_mismatch", e.Reason)
	}
	if e.Count != 1119 {
		t.Errorf("count: got %d want 1119", e.Count)
	}
	if e.EverSucceeded == nil {
		t.Fatal("ever_succeeded: got nil pointer, want non-nil pointing to false")
	}
	if *e.EverSucceeded {
		t.Error("ever_succeeded: got true want false")
	}
}

// ── parseAgentHealth: absent / null ───────────────────────────────────────────

func TestParseAgentHealth_AbsentOrNull(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{"nil slice (key absent)", nil},
		{"empty slice", json.RawMessage{}},
		{"JSON null", json.RawMessage(`null`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope, present := parseAgentHealth(tc.raw, nil)
			if present {
				t.Errorf("parseAgentHealth(%q) present=true; want false", tc.raw)
			}
			if envelope != nil {
				t.Errorf("parseAgentHealth(%q) envelope=%+v; want nil", tc.raw, envelope)
			}
		})
	}
}

// ── parseAgentHealth: the critical absent-vs-present-empty distinction ───────

// TestParseAgentHealth_PresentEmpty is the load-bearing test for this
// ticket: a payload with agent_health present and degraded: [] must be
// distinguishable from agent_health being absent entirely. Absent means "no
// opinion" (parseAgentHealth returns present=false); present-with-empty
// means "reporting all clear" (present=true, zero-length Degraded). Getting
// this wrong in either direction either wipes a genuinely degraded record on
// every old-agent payload, or never lets a recovered device clear itself.
func TestParseAgentHealth_PresentEmpty(t *testing.T) {
	envelope, present := parseAgentHealth(json.RawMessage(`{"degraded":[]}`), nil)
	if !present {
		t.Fatal("parseAgentHealth({\"degraded\":[]}) present=false; want true (agent actively reported all-clear)")
	}
	if envelope == nil {
		t.Fatal("parseAgentHealth({\"degraded\":[]}) envelope=nil; want non-nil")
	}
	if envelope.Degraded == nil {
		t.Fatal("Degraded: nil pointer for an explicit \"degraded\":[] — must be a non-nil pointer to an empty slice")
	}
	if len(*envelope.Degraded) != 0 {
		t.Errorf("Degraded len: got %d want 0", len(*envelope.Degraded))
	}
}

// TestParseAgentHealth_PresentWithEntries exercises the ordinary non-empty case.
func TestParseAgentHealth_PresentWithEntries(t *testing.T) {
	raw := json.RawMessage(`{"degraded":[{"kind":"a"},{"kind":"b"},{"kind":"c"}]}`)
	envelope, present := parseAgentHealth(raw, nil)
	if !present {
		t.Fatal("present=false for a well-formed non-empty section")
	}
	if envelope.Degraded == nil {
		t.Fatal("Degraded: nil pointer for a well-formed non-empty section")
	}
	if got, want := len(*envelope.Degraded), 3; got != want {
		t.Errorf("Degraded len: got %d want %d", got, want)
	}
}

// ── parseAgentHealth: {} / degraded:null must NOT be a positive all-clear (review round 4, FIX 13) ──

// TestParseAgentHealth_MissingOrNullDegraded_IsNotPresent is the regression
// test for FIX 13: an agent_health object of {} or {"degraded": null} must
// be treated exactly like an absent/malformed section (present=false,
// no-op) — NOT as an assertion that the device has no faults. Both {} and
// null-degraded unmarshal cleanly (no decode error) into a Go zero value
// that, before this fix, was indistinguishable from a genuine
// {"degraded": []}: upsertAgentHealth read that zero value as "agent
// reports all clear" and deleted every existing health row for the device.
// This is sharper than FIX 1/5/8: no malformed entry and no race is needed —
// one agent shipping a bare {} silently resolves real faults on every
// device it runs on.
//
// Only {"degraded": []} (an explicit, present, non-null array) may clear.
func TestParseAgentHealth_MissingOrNullDegraded_IsNotPresent(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{`{} (degraded key entirely absent)`, json.RawMessage(`{}`)},
		{`{"degraded": null} (explicit null)`, json.RawMessage(`{"degraded":null}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope, present := parseAgentHealth(tc.raw, nil)
			if present {
				t.Errorf("parseAgentHealth(%s) present=true; want false (must not be read as an all-clear assertion)", tc.raw)
			}
			if envelope != nil {
				t.Errorf("parseAgentHealth(%s) envelope=%+v; want nil", tc.raw, envelope)
			}
		})
	}
}

// TestParseAgentHealth_MissingNullEmpty_ThreeWayDistinction is the direct
// side-by-side proof that {}, {"degraded":null}, and {"degraded":[]} are
// three genuinely different outcomes, not two cases that happen to both
// pass individually. Written as one test over all three so a future change
// that collapses any pair back together fails immediately here rather than
// only in one of two separate tests someone could edit out of sync.
func TestParseAgentHealth_MissingNullEmpty_ThreeWayDistinction(t *testing.T) {
	_, presentMissing := parseAgentHealth(json.RawMessage(`{}`), nil)
	_, presentNull := parseAgentHealth(json.RawMessage(`{"degraded":null}`), nil)
	envelopeEmpty, presentEmpty := parseAgentHealth(json.RawMessage(`{"degraded":[]}`), nil)

	if presentMissing {
		t.Error(`{} : present=true, want false`)
	}
	if presentNull {
		t.Error(`{"degraded":null} : present=true, want false`)
	}
	if !presentEmpty {
		t.Fatal(`{"degraded":[]} : present=false, want true`)
	}
	if envelopeEmpty.Degraded == nil {
		t.Fatal(`{"degraded":[]} : Degraded is nil, want a non-nil pointer to an empty slice`)
	}
	if len(*envelopeEmpty.Degraded) != 0 {
		t.Errorf(`{"degraded":[]} : Degraded len = %d, want 0`, len(*envelopeEmpty.Degraded))
	}
}

// ── parseAgentHealth: malformed top-level section ─────────────────────────────

// TestParseAgentHealth_Malformed_ReturnsAbsent mirrors
// TestParseBackupStatus_Malformed_ReturnsNil: a malformed agent_health
// object must not panic or propagate an error — it is logged (when a logger
// is given) and treated exactly like "absent" (PAT-948 posture, applied here).
func TestParseAgentHealth_Malformed_ReturnsAbsent(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "not even an object",
			raw:  json.RawMessage(`"degraded"`),
		},
		{
			name: "degraded is an object, not an array",
			raw:  json.RawMessage(`{"degraded":{"kind":"a"}}`),
		},
		{
			name: "truncated / invalid JSON",
			raw:  json.RawMessage(`{"degraded":[`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope, present := parseAgentHealth(tc.raw, nil)
			if present {
				t.Errorf("parseAgentHealth(%s) present=true; want false", tc.raw)
			}
			if envelope != nil {
				t.Errorf("parseAgentHealth(%s) envelope=%+v; want nil", tc.raw, envelope)
			}
		})
	}
}

// TestPayloadUnmarshal_MalformedAgentHealth_DoesNotPoisonOtherFields is the
// struct-unmarshal-level regression test mirroring
// TestPayloadUnmarshal_MalformedBackupStatus_DoesNotPoisonOtherFields:
// AgentHealth is carried as json.RawMessage precisely so a malformed
// agent_health section (wrong shape entirely) cannot abort the json.Unmarshal
// call in processRow and take the whole device snapshot down with it.
func TestPayloadUnmarshal_MalformedAgentHealth_DoesNotPoisonOtherFields(t *testing.T) {
	data := readFixture(t, "valid", "full.json")

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal base fixture: %v", err)
	}
	// Deliberately schema-invalid: agent_health should be an object, not a string.
	m["agent_health"] = "not an object"
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal patched fixture: %v", err)
	}

	var p payload
	if err := json.Unmarshal(patched, &p); err != nil {
		t.Fatalf("json.Unmarshal must succeed despite malformed agent_health (AgentHealth must be json.RawMessage): %v", err)
	}

	if p.Device.Serial == "" {
		t.Error("Device.Serial: empty — other fields were not populated")
	}
	if len(p.Apps) == 0 {
		t.Error("Apps: empty — other fields were not populated")
	}

	if len(p.AgentHealth) == 0 {
		t.Fatal("AgentHealth: empty — expected the raw malformed bytes to be captured")
	}
	if _, present := parseAgentHealth(p.AgentHealth, nil); present {
		t.Error("parseAgentHealth(malformed) present=true; want false")
	}
}

// ── ValidatePayload: agent_health must never reject the whole upload (review round 3, FIX 9) ──

// TestValidatePayload_GarbageAgentHealth_StillValidates is the regression
// test for FIX 9: ValidatePayload runs at the ingestion gate BEFORE a
// payload is ever persisted to raw_payloads, so any error it returns
// rejects the ENTIRE POST /v1/inventory request, not just the agent_health
// section. An earlier version of ValidatePayload checked agent_health's
// shape (key presence on "degraded" and its items) and, in doing so,
// rejected the whole device's inventory upload — apps, compliance,
// extensions, everything — over one malformed health entry. That is exactly
// the blast radius PAYLOAD_SCHEMA.md promises will never happen for this
// section ("a malformed entry is skipped and logged, never fatal") and
// exactly the failure mode the coordinator explicitly ruled out when
// declining to enum-enforce the kind/subject/reason vocabulary, arriving by
// a different door.
//
// Every case here must pass ValidatePayload (err == nil): agent_health's
// shape is the extractor's problem (parseAgentHealth /
// sanitizeAgentHealthEntries), never the ingestion gate's.
func TestValidatePayload_GarbageAgentHealth_StillValidates(t *testing.T) {
	cases := []struct {
		name        string
		agentHealth any
	}{
		{"a string, not an object", "not an object"},
		{"a number", 42},
		{"an array, not an object", []any{"degraded"}},
		{"an empty object (degraded key missing)", map[string]any{}},
		{"degraded is an object, not an array", map[string]any{"degraded": map[string]any{"kind": "a"}}},
		{"degraded is an array of strings, not objects", map[string]any{"degraded": []any{"not-an-object"}}},
		{"degraded item missing every field", map[string]any{"degraded": []any{map[string]any{}}}},
		{"degraded item with wrong-typed count", map[string]any{"degraded": []any{
			map[string]any{
				"kind": "k", "subject": "s", "reason": "r",
				"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
				"count": "not-a-number", "ever_succeeded": false,
			},
		}}},
	}

	base := readFixture(t, "valid", "full.json")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(base, &m); err != nil {
				t.Fatalf("unmarshal base fixture: %v", err)
			}
			m["agent_health"] = tc.agentHealth
			patched, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal patched fixture: %v", err)
			}

			if err := ValidatePayload(patched); err != nil {
				t.Errorf("ValidatePayload must accept any agent_health shape (extractor owns validation, not the ingestion gate): %v", err)
			}

			// The rest of the payload must still unmarshal and carry every
			// other section — this is what "did not reject the whole upload"
			// actually means in practice.
			var p payload
			if err := json.Unmarshal(patched, &p); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if p.Device.Serial == "" {
				t.Error("Device.Serial: empty — other sections were not populated")
			}
			if len(p.Apps) == 0 {
				t.Error("Apps: empty — other sections were not populated")
			}
		})
	}
}

// ── sanitizeAgentHealthEntries: truncation (PAT-933 precedent) ───────────────

func TestSanitizeAgentHealthEntries_Truncation(t *testing.T) {
	longKind := "kind-" + strings.Repeat("k", 200)
	longSubject := "subject-" + strings.Repeat("s", 200)
	longReason := "reason-" + strings.Repeat("r", 200)

	entry := map[string]any{
		"kind":           longKind,
		"subject":        longSubject,
		"reason":         longReason,
		"first_seen":     "2026-12-01T09:00:00Z",
		"last_seen":      "2026-07-28T09:00:00Z",
		"count":          1,
		"ever_succeeded": true,
	}
	raw := mustMarshalRaw(t, entry)

	result := sanitizeAgentHealthEntries([]json.RawMessage{raw}, "dev-1", nil)
	if len(result.Entries) != 1 {
		t.Fatalf("sanitized len: got %d want 1", len(result.Entries))
	}
	if result.Dropped != 0 || result.Capped {
		t.Errorf("Dropped/Capped: got (%d, %v) want (0, false)", result.Dropped, result.Capped)
	}
	got := result.Entries[0]

	if n := len([]rune(got.Kind)); n != agentHealthMaxFieldLen {
		t.Errorf("Kind rune length: got %d want %d", n, agentHealthMaxFieldLen)
	}
	if !strings.HasPrefix(longKind, got.Kind) {
		t.Errorf("Kind %q is not a prefix of the original %q", got.Kind, longKind)
	}
	if n := len([]rune(got.Subject)); n != agentHealthMaxFieldLen {
		t.Errorf("Subject rune length: got %d want %d", n, agentHealthMaxFieldLen)
	}
	if n := len([]rune(got.Reason)); n != agentHealthMaxFieldLen {
		t.Errorf("Reason rune length: got %d want %d", n, agentHealthMaxFieldLen)
	}
}

// ── sanitizeAgentHealthEntries: array capping (PAT-933 precedent) ────────────

func TestSanitizeAgentHealthEntries_Capping(t *testing.T) {
	const submitted = agentHealthMaxEntries + 20
	raws := make([]json.RawMessage, 0, submitted)
	for i := 0; i < submitted; i++ {
		raws = append(raws, mustMarshalRaw(t, map[string]any{
			"kind":           "k",
			"subject":        subjectFor(i),
			"reason":         "r",
			"first_seen":     "2026-12-01T09:00:00Z",
			"last_seen":      "2026-07-28T09:00:00Z",
			"count":          1,
			"ever_succeeded": false,
		}))
	}

	result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
	if len(result.Entries) != agentHealthMaxEntries {
		t.Fatalf("capped len: got %d want %d", len(result.Entries), agentHealthMaxEntries)
	}
	// Capping must keep the FIRST agentHealthMaxEntries, not an arbitrary subset.
	if result.Entries[0].Subject != subjectFor(0) {
		t.Errorf("first retained subject: got %q want %q", result.Entries[0].Subject, subjectFor(0))
	}
	if result.Entries[len(result.Entries)-1].Subject != subjectFor(agentHealthMaxEntries-1) {
		t.Errorf("last retained subject: got %q want %q", result.Entries[len(result.Entries)-1].Subject, subjectFor(agentHealthMaxEntries-1))
	}
	if !result.Capped {
		t.Error("Capped: got false, want true (submitted more than agentHealthMaxEntries)")
	}
	if result.Dropped != 20 {
		t.Errorf("Dropped: got %d want 20 (the entries beyond the cap)", result.Dropped)
	}
}

func subjectFor(i int) string { return fmt.Sprintf("subject-%d", i) }

// ── sanitizeAgentHealthEntries: malformed-element guard (PAT-871 precedent) ──

// TestSanitizeAgentHealthEntries_SkipsMalformed proves one malformed element
// among several — a decode error, an empty kind/subject, a count < 1, or an
// unparseable timestamp — is skipped and logged rather than aborting the
// whole batch. This is the per-element isolation the ticket calls out as the
// subtlest requirement: Degraded is carried as []json.RawMessage precisely
// so a wrong-typed field in ONE element can't fail json.Unmarshal for the
// whole slice.
func TestSanitizeAgentHealthEntries_SkipsMalformed(t *testing.T) {
	good := func(subject string) map[string]any {
		return map[string]any{
			"kind":           "directive_skipped",
			"subject":        subject,
			"reason":         "device_id_mismatch",
			"first_seen":     "2026-12-01T09:00:00Z",
			"last_seen":      "2026-07-28T09:00:00Z",
			"count":          5,
			"ever_succeeded": false,
		}
	}

	raws := []json.RawMessage{
		mustMarshalRaw(t, good("good-one")),
		json.RawMessage(`{"kind":"x","subject":"y","reason":"z","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":"not-a-number","ever_succeeded":false}`), // decode error: count wrong type
		mustMarshalRaw(t, map[string]any{ // empty kind
			"kind": "", "subject": "s", "reason": "r",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 1, "ever_succeeded": false,
		}),
		mustMarshalRaw(t, map[string]any{ // count < 1
			"kind": "k", "subject": "s", "reason": "r",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 0, "ever_succeeded": false,
		}),
		mustMarshalRaw(t, map[string]any{ // unparseable first_seen
			"kind": "k", "subject": "s2", "reason": "r",
			"first_seen": "not-a-timestamp", "last_seen": "2026-07-28T09:00:00Z",
			"count": 1, "ever_succeeded": false,
		}),
		mustMarshalRaw(t, map[string]any{ // unparseable last_seen
			"kind": "k", "subject": "s3", "reason": "r",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "not-a-timestamp",
			"count": 1, "ever_succeeded": false,
		}),
		mustMarshalRaw(t, good("good-two")),
	}

	result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
	if len(result.Entries) != 2 {
		t.Fatalf("sanitized len: got %d want 2 (only the two valid entries), got entries: %+v", len(result.Entries), result.Entries)
	}
	if result.Entries[0].Subject != "good-one" || result.Entries[1].Subject != "good-two" {
		t.Errorf("sanitized subjects: got [%q, %q] want [good-one, good-two]", result.Entries[0].Subject, result.Entries[1].Subject)
	}
	// Five of the seven submitted entries were malformed; none of them were
	// removed by the cap (well under agentHealthMaxEntries).
	if result.Dropped != 5 {
		t.Errorf("Dropped: got %d want 5", result.Dropped)
	}
	if result.Capped {
		t.Error("Capped: got true, want false (array was well under agentHealthMaxEntries)")
	}
}

// ── sanitizeAgentHealthEntries: dropped/capped signal (PAT-1064 review fix) ──

// TestSanitizeAgentHealthEntries_DroppedAndCappedSignal is the pure-unit
// surface for the review finding that a snapshot lost to malformed entries
// or capping must never be treated as complete: upsertAgentHealth needs to
// know, precisely, whether anything was lost this ingest before it decides
// whether the clear-on-recovery prune is safe to run. This test pins the
// three cases that decision depends on.
func TestSanitizeAgentHealthEntries_DroppedAndCappedSignal(t *testing.T) {
	validEntry := func(subject string) json.RawMessage {
		return mustMarshalRaw(t, map[string]any{
			"kind": "k", "subject": subject, "reason": "r",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 1, "ever_succeeded": false,
		})
	}

	t.Run("all valid: Dropped=0, Capped=false", func(t *testing.T) {
		raws := []json.RawMessage{validEntry("a"), validEntry("b")}
		result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
		if len(result.Entries) != 2 {
			t.Fatalf("Entries len: got %d want 2", len(result.Entries))
		}
		if result.Dropped != 0 {
			t.Errorf("Dropped: got %d want 0", result.Dropped)
		}
		if result.Capped {
			t.Error("Capped: got true want false")
		}
	})

	t.Run("one malformed among valid: Dropped=1, Capped=false", func(t *testing.T) {
		raws := []json.RawMessage{
			validEntry("a"),
			json.RawMessage(`{"kind":"k","subject":"bad","reason":"r","first_seen":"not-a-timestamp","last_seen":"2026-07-28T09:00:00Z","count":1,"ever_succeeded":false}`),
			validEntry("c"),
		}
		result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
		if len(result.Entries) != 2 {
			t.Fatalf("Entries len: got %d want 2", len(result.Entries))
		}
		if result.Dropped != 1 {
			t.Errorf("Dropped: got %d want 1", result.Dropped)
		}
		if result.Capped {
			t.Error("Capped: got true want false")
		}
	})

	t.Run("array exceeds cap: Capped=true, Dropped includes capped-away count", func(t *testing.T) {
		raws := make([]json.RawMessage, 0, agentHealthMaxEntries+3)
		for i := 0; i < agentHealthMaxEntries+3; i++ {
			raws = append(raws, validEntry(subjectFor(i)))
		}
		result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
		if len(result.Entries) != agentHealthMaxEntries {
			t.Fatalf("Entries len: got %d want %d", len(result.Entries), agentHealthMaxEntries)
		}
		if !result.Capped {
			t.Error("Capped: got false want true")
		}
		if result.Dropped != 3 {
			t.Errorf("Dropped: got %d want 3", result.Dropped)
		}
	})
}

// ── agentHealthCollectedAtTooFarFuture: tolerance boundary (review round 5, FIX 14) ──

// TestAgentHealthCollectedAtTooFarFuture_ToleranceBoundary pins the exact
// edge of agentHealthFutureTolerance: comfortably inside is accepted, just
// inside the boundary is accepted (inclusive), and just past it is
// rejected. Uses a fixed reference "now" rather than time.Now() so the test
// is deterministic and never flaky near the boundary.
func TestAgentHealthCollectedAtTooFarFuture_ToleranceBoundary(t *testing.T) {
	now := mustRFC3339(t, "2026-07-28T12:00:00Z")

	cases := []struct {
		name        string
		collectedAt time.Time
		wantTooFar  bool
	}{
		{"comfortably in the past", now.Add(-24 * time.Hour), false},
		{"exactly now", now, false},
		{"just inside tolerance (tolerance - 1s)", now.Add(agentHealthFutureTolerance - time.Second), false},
		{"exactly at tolerance boundary (inclusive)", now.Add(agentHealthFutureTolerance), false},
		{"just outside tolerance (tolerance + 1s)", now.Add(agentHealthFutureTolerance + time.Second), true},
		{"far future (2099)", mustRFC3339(t, "2099-01-01T00:00:00Z"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := agentHealthCollectedAtTooFarFuture(tc.collectedAt, now)
			if got != tc.wantTooFar {
				t.Errorf("agentHealthCollectedAtTooFarFuture(%v, now=%v) = %v, want %v",
					tc.collectedAt, now, got, tc.wantTooFar)
			}
		})
	}
}

// ── sanitizeAgentHealthEntries: reported-set computation ─────────────────────

// TestSanitizeAgentHealthEntries_ReportedSetForDelete verifies the
// (kind, subject) pairs sanitizeAgentHealthEntries returns are exactly the
// set upsertAgentHealth uses to decide which existing rows survive the
// clear-on-recovery delete — this is the pure-unit surface for that logic,
// since the delete itself needs a DB.
func TestSanitizeAgentHealthEntries_ReportedSetForDelete(t *testing.T) {
	raws := []json.RawMessage{
		mustMarshalRaw(t, map[string]any{
			"kind": "directive_skipped", "subject": "log_upload", "reason": "device_id_mismatch",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 1119, "ever_succeeded": false,
		}),
		mustMarshalRaw(t, map[string]any{
			"kind": "capability_missing", "subject": "extension_removal", "reason": "lib_not_installed",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 1105, "ever_succeeded": false,
		}),
	}

	result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
	if len(result.Entries) != 2 {
		t.Fatalf("sanitized len: got %d want 2", len(result.Entries))
	}

	reported := map[[2]string]bool{}
	for _, e := range result.Entries {
		reported[[2]string{e.Kind, e.Subject}] = true
	}
	want := [][2]string{
		{"directive_skipped", "log_upload"},
		{"capability_missing", "extension_removal"},
	}
	for _, w := range want {
		if !reported[w] {
			t.Errorf("reported set missing (%q, %q)", w[0], w[1])
		}
	}
	if len(reported) != 2 {
		t.Errorf("reported set size: got %d want 2", len(reported))
	}
}

func mustMarshalRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return json.RawMessage(b)
}

// mustRFC3339 parses an RFC3339 timestamp for test fixtures, failing the
// test immediately on a typo rather than silently producing the zero time.
func mustRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q as RFC3339: %v", s, err)
	}
	return tm
}

// ── sanitizeAgentHealthEntries: NUL-byte guard (PAT-1064 review FIX 4) ───────

// TestSanitizeAgentHealthEntries_RejectsNULByte proves an entry with a NUL
// byte embedded in kind, subject, or reason is dropped rather than reaching
// the INSERT — PostgreSQL text columns reject \x00 outright, and without
// this guard that error would propagate out of upsertAgentHealth and abort
// the WHOLE device's extraction transaction (apps, compliance, extensions,
// everything), retried forever against the same poisoned row. Valid
// neighbours on either side of the bad entry must still survive.
func TestSanitizeAgentHealthEntries_RejectsNULByte(t *testing.T) {
	good := func(subject string) json.RawMessage {
		return mustMarshalRaw(t, map[string]any{
			"kind": "directive_skipped", "subject": subject, "reason": "device_id_mismatch",
			"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
			"count": 1, "ever_succeeded": false,
		})
	}

	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "NUL in kind",
			raw: mustMarshalRaw(t, map[string]any{
				"kind": "directive_\x00skipped", "subject": "s", "reason": "r",
				"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
				"count": 1, "ever_succeeded": false,
			}),
		},
		{
			name: "NUL in subject",
			raw: mustMarshalRaw(t, map[string]any{
				"kind": "k", "subject": "log\x00_upload", "reason": "r",
				"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
				"count": 1, "ever_succeeded": false,
			}),
		},
		{
			name: "NUL in reason",
			raw: mustMarshalRaw(t, map[string]any{
				"kind": "k", "subject": "s", "reason": "device_id\x00_mismatch",
				"first_seen": "2026-12-01T09:00:00Z", "last_seen": "2027-01-28T09:00:00Z",
				"count": 1, "ever_succeeded": false,
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raws := []json.RawMessage{good("neighbour-one"), tc.raw, good("neighbour-two")}
			result := sanitizeAgentHealthEntries(raws, "dev-1", nil)
			if len(result.Entries) != 2 {
				t.Fatalf("Entries len: got %d want 2 (only the two well-formed neighbours), entries: %+v", len(result.Entries), result.Entries)
			}
			if result.Entries[0].Subject != "neighbour-one" || result.Entries[1].Subject != "neighbour-two" {
				t.Errorf("neighbour subjects: got [%q, %q] want [neighbour-one, neighbour-two]",
					result.Entries[0].Subject, result.Entries[1].Subject)
			}
			if result.Dropped != 1 {
				t.Errorf("Dropped: got %d want 1", result.Dropped)
			}
		})
	}
}

// ── sanitizeAgentHealthEntries: ever_succeeded null guard (PAT-1064 review FIX 6) ──

// TestSanitizeAgentHealthEntries_RejectsNullEverSucceeded proves an entry
// with ever_succeeded explicitly null, or the key omitted entirely, is
// dropped rather than silently persisted as false. encoding/json decodes a
// JSON null (or an absent key) for a bool field into the zero value (false)
// without any error — which would assert "this capability has never
// worked", the more alarming of the two states, on no evidence at all. Only
// the agent knows the answer, so a missing one must be dropped, not invented.
func TestSanitizeAgentHealthEntries_RejectsNullEverSucceeded(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "explicit null",
			raw:  json.RawMessage(`{"kind":"k","subject":"s","reason":"r","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":1,"ever_succeeded":null}`),
		},
		{
			name: "key omitted entirely",
			raw:  json.RawMessage(`{"kind":"k","subject":"s","reason":"r","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":1}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeAgentHealthEntries([]json.RawMessage{tc.raw}, "dev-1", nil)
			if len(result.Entries) != 0 {
				t.Fatalf("Entries len: got %d want 0 (null/absent ever_succeeded must be dropped), entries: %+v", len(result.Entries), result.Entries)
			}
			if result.Dropped != 1 {
				t.Errorf("Dropped: got %d want 1", result.Dropped)
			}
		})
	}
}

// ── upsertAgentHealth DB round-trip ───────────────────────────────────────────
//
// Run with:
//
//	TEST_DATABASE_URL="postgres://..." go test ./internal/extractor/ -run TestUpsertAgentHealth -v

func newAgentHealthTestDevice(t *testing.T, ctx context.Context, tx pgx.Tx, tenantName, serial string) string {
	t.Helper()
	var tenantID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x00', '\x00')
		RETURNING id::text
	`, tenantName).Scan(&tenantID); err != nil {
		t.Fatalf("insert test tenant: %v", err)
	}

	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, os, serial)
		VALUES ($1::uuid, 'macOS', $2)
		RETURNING id::text
	`, tenantID, serial).Scan(&deviceID); err != nil {
		t.Fatalf("insert test device: %v", err)
	}
	return deviceID
}

func countAgentHealthRows(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM device_agent_health WHERE device_id = $1::uuid`, deviceID,
	).Scan(&n); err != nil {
		t.Fatalf("count device_agent_health: %v", err)
	}
	return n
}

// getAgentHealthWatermark reads the current device_agent_health_watermark
// value for a device directly (bypassing lockAgentHealthWatermark's
// create-if-absent behaviour) — callers use this only after a prior
// upsertAgentHealth call is known to have created the row.
func getAgentHealthWatermark(t *testing.T, ctx context.Context, tx pgx.Tx, deviceID string) time.Time {
	t.Helper()
	var watermark time.Time
	if err := tx.QueryRow(ctx,
		`SELECT collected_at FROM device_agent_health_watermark WHERE device_id = $1::uuid`, deviceID,
	).Scan(&watermark); err != nil {
		t.Fatalf("select device_agent_health_watermark: %v", err)
	}
	return watermark
}

// TestUpsertAgentHealth_AbsentIsNoOp proves a payload with no agent_health
// section leaves existing device_agent_health rows untouched — the "older
// agent" case must never look like a healthy device clearing its degraded
// history.
func TestUpsertAgentHealth_AbsentIsNoOp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-absent-test", "AHABSENT001")

	// Seed one existing degraded row directly (as if a prior payload wrote it).
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_agent_health (device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at)
		VALUES ($1::uuid, 'sync_never_succeeded', 'catalogue', 'fetch_failed', now(), now(), 3, false, now())
	`, deviceID); err != nil {
		t.Fatalf("seed existing row: %v", err)
	}

	written, dropped, err := upsertAgentHealth(ctx, tx, deviceID, nil, mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("upsertAgentHealth(absent): %v", err)
	}
	if written != 0 {
		t.Errorf("written: want 0, got %d", written)
	}
	if dropped != 0 {
		t.Errorf("dropped: want 0, got %d", dropped)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 1 {
		t.Errorf("row count after absent-section ingest: want 1 (untouched), got %d", n)
	}
}

// TestUpsertAgentHealth_BareObjectAndNullDegradedAreNoOps is the DB
// round-trip regression test for review round 4, FIX 13: an agent_health
// section shaped as {} or {"degraded": null} must leave existing
// device_agent_health rows untouched, exactly like an absent section —
// NOT clear them the way a genuine {"degraded": []} does. Before the fix,
// both {} and {"degraded": null} unmarshaled into the same Go zero value as
// an explicit empty array, so upsertAgentHealth read them as "agent asserts
// all clear" and deleted the seeded row.
func TestUpsertAgentHealth_BareObjectAndNullDegradedAreNoOps(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{"bare object {}", json.RawMessage(`{}`)},
		{`{"degraded": null}`, json.RawMessage(`{"degraded":null}`)},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
			if err != nil {
				t.Fatalf("begin tx: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-bare-null-test", fmt.Sprintf("AHBARENULL%03d", i))

			// Seed one existing degraded row directly (as if a prior payload wrote it).
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_agent_health (device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at)
				VALUES ($1::uuid, 'sync_never_succeeded', 'catalogue', 'fetch_failed', now(), now(), 3, false, now())
			`, deviceID); err != nil {
				t.Fatalf("seed existing row: %v", err)
			}

			written, dropped, err := upsertAgentHealth(ctx, tx, deviceID, tc.raw, mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
			if err != nil {
				t.Fatalf("upsertAgentHealth(%s): %v", tc.raw, err)
			}
			if written != 0 {
				t.Errorf("written: want 0, got %d", written)
			}
			if dropped != 0 {
				t.Errorf("dropped: want 0, got %d", dropped)
			}
			if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 1 {
				t.Errorf("row count after %s ingest: want 1 (untouched — must NOT be read as an all-clear), got %d", tc.raw, n)
			}
		})
	}
}

// TestUpsertAgentHealth_EmptyArrayClears proves degraded: [] deletes every
// existing row for the device — the explicit "all clear" case.
func TestUpsertAgentHealth_EmptyArrayClears(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-empty-clear-test", "AHEMPTYCLEAR001")

	if _, err := tx.Exec(ctx, `
		INSERT INTO device_agent_health (device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at)
		VALUES
		    ($1::uuid, 'directive_skipped', 'log_upload', 'device_id_mismatch', now(), now(), 1119, false, $2::timestamptz),
		    ($1::uuid, 'capability_missing', 'extension_removal', 'lib_not_installed', now(), now(), 1105, false, $2::timestamptz)
	`, deviceID, mustRFC3339(t, "2026-07-01T09:00:00Z")); err != nil {
		t.Fatalf("seed existing rows: %v", err)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 2 {
		t.Fatalf("precondition: want 2 seeded rows, got %d", n)
	}

	// collectedAt (2026-07-28) is newer than the seeded rows' collected_at
	// (2026-07-01), so the clear is expected to run rather than be skipped
	// as stale.
	written, dropped, err := upsertAgentHealth(ctx, tx, deviceID, json.RawMessage(`{"degraded":[]}`), mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("upsertAgentHealth(empty array): %v", err)
	}
	if written != 0 {
		t.Errorf("written: want 0, got %d", written)
	}
	if dropped != 0 {
		t.Errorf("dropped: want 0, got %d", dropped)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 0 {
		t.Errorf("row count after degraded:[] ingest: want 0 (all cleared), got %d", n)
	}
}

// TestUpsertAgentHealth_UpsertInPlace proves re-sending the same (kind,
// subject) updates the existing row instead of adding a duplicate.
func TestUpsertAgentHealth_UpsertInPlace(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-upsert-test", "AHUPSERT001")

	raw1 := json.RawMessage(`{"degraded":[
		{"kind":"sync_never_succeeded","subject":"catalogue","reason":"fetch_failed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":10,"ever_succeeded":false}
	]}`)
	written1, dropped1, err := upsertAgentHealth(ctx, tx, deviceID, raw1, mustRFC3339(t, "2026-07-01T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("first upsertAgentHealth: %v", err)
	}
	if written1 != 1 {
		t.Fatalf("first written: want 1, got %d", written1)
	}
	if dropped1 != 0 {
		t.Errorf("first dropped: want 0, got %d", dropped1)
	}

	// Second ingest's collected_at (2026-07-28) is newer than the first
	// (2026-07-01), so the per-row recency guard must let this overwrite go
	// through.
	raw2 := json.RawMessage(`{"degraded":[
		{"kind":"sync_never_succeeded","subject":"catalogue","reason":"fetch_failed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":25,"ever_succeeded":false}
	]}`)
	written2, dropped2, err := upsertAgentHealth(ctx, tx, deviceID, raw2, mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("second upsertAgentHealth: %v", err)
	}
	if written2 != 1 {
		t.Fatalf("second written: want 1, got %d", written2)
	}
	if dropped2 != 0 {
		t.Errorf("second dropped: want 0, got %d", dropped2)
	}

	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 1 {
		t.Fatalf("row count after re-ingest: want 1 (no duplicate), got %d", n)
	}

	var gotCount int64
	var gotLastSeen time.Time
	if err := tx.QueryRow(ctx, `
		SELECT count, last_seen FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'sync_never_succeeded' AND subject = 'catalogue'
	`, deviceID).Scan(&gotCount, &gotLastSeen); err != nil {
		t.Fatalf("select updated row: %v", err)
	}
	if gotCount != 25 {
		t.Errorf("count after re-ingest: want 25, got %d", gotCount)
	}
	wantLastSeen, _ := time.Parse(time.RFC3339, "2026-07-28T09:00:00Z")
	if !gotLastSeen.Equal(wantLastSeen) {
		t.Errorf("last_seen after re-ingest: want %v, got %v", wantLastSeen, gotLastSeen)
	}
}

// TestUpsertAgentHealth_ClearOnRecovery is the load-bearing regression test
// for this ticket's central requirement: a capability that recovers (drops
// out of a subsequent payload's degraded array) must have its row deleted,
// not left standing forever.
//
// This test was written FIRST and confirmed to FAIL against a version of
// upsertAgentHealth that early-returns on a non-nil-but-structurally-empty
// input the way upsertBrowserExtensions does (`if len(exts) == 0 { return
// 0, nil }`) — i.e. a version that treats "reported fewer entries than
// before" as "nothing to do" instead of computing the reported set and
// pruning what fell out of it. That early-return shape is exactly the bug
// PAT-1064 exists to avoid; a guard that cannot fail against the bug it
// targets is not a guard.
func TestUpsertAgentHealth_ClearOnRecovery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-recovery-test", "AHRECOVERY001")

	// First ingest: two degraded capabilities.
	raw1 := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":1119,"ever_succeeded":false},
		{"kind":"capability_missing","subject":"extension_removal","reason":"lib_not_installed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":1105,"ever_succeeded":false}
	]}`)
	written1, dropped1, err := upsertAgentHealth(ctx, tx, deviceID, raw1, mustRFC3339(t, "2026-07-01T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("first upsertAgentHealth: %v", err)
	}
	if written1 != 2 {
		t.Fatalf("first written: want 2, got %d", written1)
	}
	if dropped1 != 0 {
		t.Fatalf("first dropped: want 0 (nothing malformed/capped), got %d", dropped1)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 2 {
		t.Fatalf("precondition: want 2 rows after first ingest, got %d", n)
	}

	// Second ingest: only ONE of the two capabilities is still reported — the
	// agent's log_upload directive now succeeds. The extension_removal
	// capability must be deleted; it has recovered and must stop being
	// reported as degraded. Both entries here are well-formed (dropped=0,
	// capped=false), so the prune is expected to run — this is the "complete
	// snapshot" case; TestUpsertAgentHealth_SkipsPruneWhenSnapshotIncomplete
	// below covers the incomplete-snapshot case FIX 1 added.
	raw2 := json.RawMessage(`{"degraded":[
		{"kind":"capability_missing","subject":"extension_removal","reason":"lib_not_installed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":1200,"ever_succeeded":false}
	]}`)
	written2, dropped2, err := upsertAgentHealth(ctx, tx, deviceID, raw2, mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("second upsertAgentHealth: %v", err)
	}
	if written2 != 1 {
		t.Fatalf("second written: want 1, got %d", written2)
	}
	if dropped2 != 0 {
		t.Fatalf("second dropped: want 0 (nothing malformed/capped), got %d", dropped2)
	}

	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 1 {
		t.Fatalf("row count after recovery ingest: want 1 (log_upload cleared), got %d", n)
	}

	var remainingKind, remainingSubject string
	if err := tx.QueryRow(ctx, `
		SELECT kind, subject FROM device_agent_health WHERE device_id = $1::uuid
	`, deviceID).Scan(&remainingKind, &remainingSubject); err != nil {
		t.Fatalf("select remaining row: %v", err)
	}
	if remainingKind != "capability_missing" || remainingSubject != "extension_removal" {
		t.Errorf("remaining row: got (%q, %q), want (capability_missing, extension_removal)", remainingKind, remainingSubject)
	}

	var recoveredCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'directive_skipped' AND subject = 'log_upload'
	`, deviceID).Scan(&recoveredCount); err != nil {
		t.Fatalf("count recovered row: %v", err)
	}
	if recoveredCount != 0 {
		t.Error("directive_skipped/log_upload must be deleted after recovery — it is still present")
	}
}

// TestUpsertAgentHealth_SkipsPruneWhenSnapshotIncomplete is the regression
// test for review FIX 1 (PAT-1064): the clear-on-recovery prune must only
// run against a COMPLETE reported set. A payload carrying one malformed
// entry alongside a valid one is an incomplete snapshot — the malformed
// entry's true (kind, subject) is unknown, so a third, previously-recorded
// capability that this payload doesn't mention at all must NOT be pruned as
// "recovered". It may really still be degraded; the payload just can't prove
// either way this ingest.
//
// This test was confirmed to FAIL before the fix: with the pre-fix code
// (prune always runs off whatever survived sanitization, regardless of
// Dropped/Capped), the third capability's row was deleted here exactly as
// if it had recovered, even though nothing about it was reported one way or
// the other. Before / after:
//
//	before fix: row count after second ingest = 1 (survivor row deleted, FAIL)
//	after fix:  row count after second ingest = 2 (survivor row intact, PASS)
func TestUpsertAgentHealth_SkipsPruneWhenSnapshotIncomplete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-incomplete-snapshot-test", "AHINCOMPLETE001")

	// First ingest: three degraded capabilities, all well-formed.
	raw1 := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":1119,"ever_succeeded":false},
		{"kind":"capability_missing","subject":"extension_removal","reason":"lib_not_installed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":1105,"ever_succeeded":false},
		{"kind":"sync_never_succeeded","subject":"catalogue","reason":"fetch_failed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":40,"ever_succeeded":false}
	]}`)
	written1, dropped1, err := upsertAgentHealth(ctx, tx, deviceID, raw1, mustRFC3339(t, "2026-07-01T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("first upsertAgentHealth: %v", err)
	}
	if written1 != 3 || dropped1 != 0 {
		t.Fatalf("first ingest: want written=3 dropped=0, got written=%d dropped=%d", written1, dropped1)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 3 {
		t.Fatalf("precondition: want 3 rows after first ingest, got %d", n)
	}

	// Second ingest: log_upload re-reported (still degraded), one malformed
	// entry (unparseable last_seen — gets dropped), and NO mention at all of
	// sync_never_succeeded/catalogue. If the prune ran off this incomplete
	// set, it would delete the catalogue row as "recovered" — but the
	// payload never said that; it just failed to report on it cleanly this
	// cycle.
	raw2 := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":1200,"ever_succeeded":false},
		{"kind":"capability_missing","subject":"extension_removal","reason":"lib_not_installed","first_seen":"2026-12-01T09:00:00Z","last_seen":"not-a-timestamp","count":1105,"ever_succeeded":false}
	]}`)
	written2, dropped2, err := upsertAgentHealth(ctx, tx, deviceID, raw2, mustRFC3339(t, "2026-07-28T09:00:00Z"), nil)
	if err != nil {
		t.Fatalf("second upsertAgentHealth: %v", err)
	}
	if written2 != 1 {
		t.Fatalf("second written: want 1 (only log_upload survived sanitization), got %d", written2)
	}
	if dropped2 != 1 {
		t.Fatalf("second dropped: want 1 (the malformed extension_removal entry), got %d", dropped2)
	}

	// The malformed entry's own prior row (extension_removal) is untouched —
	// it was neither upserted (malformed) nor pruned (snapshot incomplete).
	// The unrelated, unmentioned catalogue row is ALSO untouched — that is
	// the actual regression this test targets.
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 3 {
		t.Errorf("row count after incomplete-snapshot ingest: want 3 (nothing pruned), got %d", n)
	}

	var catalogueCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'sync_never_succeeded' AND subject = 'catalogue'
	`, deviceID).Scan(&catalogueCount); err != nil {
		t.Fatalf("count catalogue row: %v", err)
	}
	if catalogueCount != 1 {
		t.Error("sync_never_succeeded/catalogue must survive an incomplete-snapshot ingest — it was never actually reported as recovered")
	}

	var extensionRemovalCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'capability_missing' AND subject = 'extension_removal'
	`, deviceID).Scan(&extensionRemovalCount); err != nil {
		t.Fatalf("count extension_removal row: %v", err)
	}
	if extensionRemovalCount != 1 {
		t.Error("capability_missing/extension_removal (whose new report was malformed) must survive with its PRIOR row intact, not be pruned or duplicated")
	}
}

// TestUpsertAgentHealth_SkipsRecoveryOnStalePayload is the regression test
// for review FIX 5/FIX 8 (PAT-1064): an out-of-order OLDER payload must not
// be able to clear or prune faults a NEWER payload already recorded. The
// extractor's claim/retry ordering is unspecified, so an older payload can
// genuinely be processed after a newer one — e.g. a row that failed
// extraction gets retried after a later row from the same device already
// succeeded. For every other section that is a harmless stale overwrite;
// for this section, which is the only one that deletes, it would show a
// still-degraded device as recovered.
//
// This test ingests a NEWER snapshot first (two capabilities), then an
// OLDER snapshot that omits one of them, and proves the omitted capability
// survives. As of FIX 8, the device_agent_health_watermark lock rejects the
// WHOLE older section up front (locked and read as the first statement of
// the second upsertAgentHealth call) — no clear, no upsert, no prune, all
// as one all-or-nothing decision — rather than gating the delete alone and
// leaving individual row writes to a separate, narrower guard. That is
// stronger than a per-row overwrite guard would be: it also protects a
// (kind, subject) that the older payload names but that ISN'T currently in
// device_agent_health (a per-row ON CONFLICT ... WHERE guard only blocks
// UPDATEs, so that case would otherwise take the unguarded INSERT path —
// exactly the second hole FIX 8 closed).
//
// This test was confirmed to FAIL before FIX 5 (no collected_at column, no
// staleness check at all — the prune ran unconditionally off whatever the
// current payload reported) and again, differently, before FIX 8 (a
// MAX(collected_at)-over-rows watermark that a `degraded: []` payload could
// wipe out along with every fault row). Before / after:
//
//	before fix: row count after second (older) ingest = 1 (omitted capability wrongly pruned, FAIL)
//	after fix:  row count after second (older) ingest = 2 (omitted capability survives, PASS)
func TestUpsertAgentHealth_SkipsRecoveryOnStalePayload(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-stale-payload-test", "AHSTALE001")

	older := mustRFC3339(t, "2026-12-01T09:00:00Z")
	newer := mustRFC3339(t, "2026-07-28T09:00:00Z")

	// First ingest processed: the NEWER snapshot, two capabilities.
	rawNewer := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":1200,"ever_succeeded":false},
		{"kind":"sync_never_succeeded","subject":"catalogue","reason":"fetch_failed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-28T09:00:00Z","count":40,"ever_succeeded":false}
	]}`)
	writtenNewer, droppedNewer, err := upsertAgentHealth(ctx, tx, deviceID, rawNewer, newer, nil)
	if err != nil {
		t.Fatalf("newer upsertAgentHealth: %v", err)
	}
	if writtenNewer != 2 || droppedNewer != 0 {
		t.Fatalf("newer ingest: want written=2 dropped=0, got written=%d dropped=%d", writtenNewer, droppedNewer)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 2 {
		t.Fatalf("precondition: want 2 rows after newer ingest, got %d", n)
	}

	// Second ingest processed: an OLDER snapshot (out of order — the
	// extractor retried a row that was claimed before the newer one but
	// failed and only succeeded on a later attempt). It re-reports
	// log_upload with STALE values and OMITS catalogue entirely. Naive
	// last-write-wins handling would downgrade log_upload's data and prune
	// catalogue as "recovered" — neither may happen.
	rawOlder := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2026-12-01T09:00:00Z","count":1,"ever_succeeded":false}
	]}`)
	writtenOlder, droppedOlder, err := upsertAgentHealth(ctx, tx, deviceID, rawOlder, older, nil)
	if err != nil {
		t.Fatalf("older upsertAgentHealth: %v", err)
	}
	if droppedOlder != 0 {
		t.Fatalf("older ingest dropped: want 0 (both entries are well-formed), got %d", droppedOlder)
	}
	// The watermark lock must reject this WHOLE section: the device's
	// watermark is already at "newer" (from the first ingest), and this
	// payload's collected_at ("older") is before it — so nothing is
	// upserted, nothing is pruned, and the watermark itself stays at
	// "newer".
	if writtenOlder != 0 {
		t.Errorf("older ingest written: want 0 (watermark lock must reject the whole stale section), got %d", writtenOlder)
	}

	// Both rows must survive: catalogue because the prune never ran (the
	// whole section was rejected at the watermark), log_upload because its
	// existing row was never touched by the rejected section either.
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 2 {
		t.Errorf("row count after older, out-of-order ingest: want 2 (nothing pruned or downgraded), got %d", n)
	}

	var catalogueCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'sync_never_succeeded' AND subject = 'catalogue'
	`, deviceID).Scan(&catalogueCount); err != nil {
		t.Fatalf("count catalogue row: %v", err)
	}
	if catalogueCount != 1 {
		t.Error("sync_never_succeeded/catalogue must survive an older, out-of-order ingest that omitted it — it was never actually reported as recovered")
	}

	// log_upload's row must still carry the NEWER ingest's values (count
	// 1200, last_seen 2026-07-28), not the older ingest's stale attempt
	// (count 1, last_seen).
	var gotCount int64
	var gotLastSeen time.Time
	if err := tx.QueryRow(ctx, `
		SELECT count, last_seen FROM device_agent_health
		WHERE device_id = $1::uuid AND kind = 'directive_skipped' AND subject = 'log_upload'
	`, deviceID).Scan(&gotCount, &gotLastSeen); err != nil {
		t.Fatalf("select log_upload row: %v", err)
	}
	if gotCount != 1200 {
		t.Errorf("log_upload count after stale ingest: want 1200 (newer value preserved), got %d", gotCount)
	}
	if !gotLastSeen.Equal(newer) {
		t.Errorf("log_upload last_seen after stale ingest: want %v (newer value preserved), got %v", newer, gotLastSeen)
	}
}

// TestUpsertAgentHealth_WatermarkSurvivesAllClear is the regression test for
// review round 3, FIX 8: the recency watermark must be per-device and must
// survive the device having zero fault rows.
//
// The FIX 5 design derived staleness from MAX(collected_at) over
// device_agent_health's own rows. That fails exactly when it matters most:
// a newer payload reporting degraded: [] deletes every row for the device —
// and, with a rows-derived watermark, deletes the server's only memory of
// how recent the device's health data is. A delayed OLDER payload arriving
// afterwards (e.g. a retried extraction attempt for a row claimed before
// the all-clear but only successfully processed after it) then finds no
// rows, computes no watermark, is treated as not stale, and resurrects
// faults the all-clear had correctly resolved.
//
// This test: ingests two faults, then a NEWER degraded: [] (resolving
// them), then an OLDER payload re-reporting the ORIGINAL two faults, and
// proves they stay resolved — the third ingest must be rejected outright by
// the per-device watermark table, not silently accepted because the fault
// table happened to be empty.
//
// This test was confirmed to FAIL against the FIX-5-era code (MAX(rows)
// watermark, no dedicated watermark table): after the all-clear,
// device_agent_health has zero rows, MAX(collected_at) over zero rows is
// SQL NULL, "no rows to compare against" was read as "not stale", and the
// third ingest resurrected both faults. Before / after:
//
//	before fix: row count after third (older, resurrecting) ingest = 2 (faults wrongly resurrected, FAIL)
//	after fix:  row count after third (older, resurrecting) ingest = 0 (stay resolved, PASS)
func TestUpsertAgentHealth_WatermarkSurvivesAllClear(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-watermark-survives-clear-test", "AHWATERMARK001")

	original := mustRFC3339(t, "2026-12-01T09:00:00Z") // first ingest: faults reported
	resolved := mustRFC3339(t, "2026-07-28T09:00:00Z") // second ingest: newer all-clear
	retryOld := mustRFC3339(t, "2026-07-01T09:00:00Z") // third ingest: older retry of the original report, but AFTER "original" chronologically — still older than "resolved"

	// First ingest: two faults.
	rawFaults := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2026-12-01T09:00:00Z","count":1119,"ever_succeeded":false},
		{"kind":"capability_missing","subject":"extension_removal","reason":"lib_not_installed","first_seen":"2026-12-01T09:00:00Z","last_seen":"2026-12-01T09:00:00Z","count":1105,"ever_succeeded":false}
	]}`)
	written1, dropped1, err := upsertAgentHealth(ctx, tx, deviceID, rawFaults, original, nil)
	if err != nil {
		t.Fatalf("first upsertAgentHealth (faults): %v", err)
	}
	if written1 != 2 || dropped1 != 0 {
		t.Fatalf("first ingest: want written=2 dropped=0, got written=%d dropped=%d", written1, dropped1)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 2 {
		t.Fatalf("precondition: want 2 rows after first ingest, got %d", n)
	}

	// Second ingest: NEWER, degraded: [] — resolves both faults. This is the
	// step that must leave a durable watermark even though it empties the
	// fault table.
	written2, dropped2, err := upsertAgentHealth(ctx, tx, deviceID, json.RawMessage(`{"degraded":[]}`), resolved, nil)
	if err != nil {
		t.Fatalf("second upsertAgentHealth (all-clear): %v", err)
	}
	if written2 != 0 || dropped2 != 0 {
		t.Fatalf("second ingest: want written=0 dropped=0, got written=%d dropped=%d", written2, dropped2)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 0 {
		t.Fatalf("precondition: want 0 rows after all-clear, got %d", n)
	}

	// Third ingest: OLDER than the all-clear, re-reporting the SAME two
	// faults from the first ingest (e.g. a retried extraction attempt for a
	// payload claimed before the all-clear but only processed after it).
	// This must be rejected outright — the faults must stay resolved.
	written3, dropped3, err := upsertAgentHealth(ctx, tx, deviceID, rawFaults, retryOld, nil)
	if err != nil {
		t.Fatalf("third upsertAgentHealth (stale retry): %v", err)
	}
	if dropped3 != 0 {
		t.Fatalf("third ingest dropped: want 0 (both entries are well-formed), got %d", dropped3)
	}
	if written3 != 0 {
		t.Errorf("third ingest written: want 0 (watermark must reject the whole stale section even though the fault table was empty), got %d", written3)
	}

	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 0 {
		t.Errorf("row count after stale retry of resolved faults: want 0 (must stay resolved), got %d", n)
	}
}

// TestUpsertAgentHealth_RejectsFarFutureCollectedAt is the regression test
// for review round 5, FIX 14: a payload whose collected_at is implausibly
// far in the future (a broken clock, a timezone bug, or malice) must be
// rejected outright — not accepted as "newer than the watermark" — and it
// must not be able to wedge the device permanently.
//
// Sequence: a legitimate first ingest establishes a normal watermark: a
// far-future degraded: [] payload is then rejected — it must NOT clear the
// existing row and must NOT advance the watermark to 2099; finally, an
// ordinary, legitimately newer payload is ingested to prove the device is
// NOT wedged — this is the part that distinguishes this fix from merely
// "reject the bad payload": the coordinator's concern was specifically that
// a naive fix (e.g. clamping to now()) would still let a broken-clock
// device advance its own watermark and re-wedge itself on the very next
// upload, one step more slowly. A reject-and-leave-the-watermark-alone fix
// must let a subsequent NORMAL payload through untouched.
//
// This test was confirmed to FAIL before the fix: with no future bound at
// all, the far-future degraded: [] payload passed the "not older than
// watermark" check, cleared the existing row, and advanced the watermark to
// 2099 — after which the final legitimate payload (dated 2026) was itself
// rejected as "older than the watermark", exactly the permanent-wedge
// failure this fix exists to prevent. Before / after:
//
//	before fix: row count after far-future ingest = 0 (wrongly cleared, FAIL); watermark = 2099 (wedged)
//	after fix:  row count after far-future ingest = 1 (untouched, PASS); watermark unchanged; device still reports normally afterward
func TestUpsertAgentHealth_RejectsFarFutureCollectedAt(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping agent health DB round-trip test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	defer pool.Close()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceID := newAgentHealthTestDevice(t, ctx, tx, "ah-far-future-test", "AHFARFUTURE001")

	legit := mustRFC3339(t, "2026-07-01T09:00:00Z")
	farFuture := mustRFC3339(t, "2099-01-01T00:00:00Z")
	laterLegit := mustRFC3339(t, "2026-07-28T09:00:00Z")

	// First ingest: one legitimate fault, establishing a normal watermark.
	rawFault := json.RawMessage(`{"degraded":[
		{"kind":"directive_skipped","subject":"log_upload","reason":"device_id_mismatch","first_seen":"2026-12-01T09:00:00Z","last_seen":"2027-01-01T09:00:00Z","count":1119,"ever_succeeded":false}
	]}`)
	written1, dropped1, err := upsertAgentHealth(ctx, tx, deviceID, rawFault, legit, nil)
	if err != nil {
		t.Fatalf("first upsertAgentHealth (legit): %v", err)
	}
	if written1 != 1 || dropped1 != 0 {
		t.Fatalf("first ingest: want written=1 dropped=0, got written=%d dropped=%d", written1, dropped1)
	}
	watermarkAfterFirst := getAgentHealthWatermark(t, ctx, tx, deviceID)
	if !watermarkAfterFirst.Equal(legit) {
		t.Fatalf("precondition: watermark after first ingest = %v, want %v", watermarkAfterFirst, legit)
	}

	// Second ingest: degraded: [] dated 2099 — a device with a broken clock
	// (or worse) trying to clear the device's real fault. Must be rejected
	// outright: no clear, watermark untouched.
	written2, dropped2, err := upsertAgentHealth(ctx, tx, deviceID, json.RawMessage(`{"degraded":[]}`), farFuture, nil)
	if err != nil {
		t.Fatalf("second upsertAgentHealth (far future): %v", err)
	}
	if written2 != 0 || dropped2 != 0 {
		t.Fatalf("second ingest: want written=0 dropped=0, got written=%d dropped=%d", written2, dropped2)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 1 {
		t.Errorf("row count after far-future ingest: want 1 (untouched — must NOT be cleared), got %d", n)
	}
	watermarkAfterFuture := getAgentHealthWatermark(t, ctx, tx, deviceID)
	if !watermarkAfterFuture.Equal(watermarkAfterFirst) {
		t.Errorf("watermark after far-future ingest: want unchanged at %v, got %v (device would be wedged)", watermarkAfterFirst, watermarkAfterFuture)
	}

	// Third ingest: an ORDINARY, legitimately newer payload. This is the
	// proof the device is not wedged — if the far-future ingest had
	// advanced the watermark, this would now be rejected as "older than the
	// watermark" even though it postdates the first ingest by weeks.
	written3, dropped3, err := upsertAgentHealth(ctx, tx, deviceID, json.RawMessage(`{"degraded":[]}`), laterLegit, nil)
	if err != nil {
		t.Fatalf("third upsertAgentHealth (later legit): %v", err)
	}
	if written3 != 0 || dropped3 != 0 {
		t.Fatalf("third ingest: want written=0 dropped=0 (degraded: [] never writes rows), got written=%d dropped=%d", written3, dropped3)
	}
	if n := countAgentHealthRows(t, ctx, tx, deviceID); n != 0 {
		t.Errorf("row count after later legitimate all-clear: want 0 (device must not be wedged), got %d", n)
	}
	watermarkFinal := getAgentHealthWatermark(t, ctx, tx, deviceID)
	if !watermarkFinal.Equal(laterLegit) {
		t.Errorf("final watermark: want %v (the later legitimate ingest), got %v", laterLegit, watermarkFinal)
	}
}

// ── Migration file sanity ─────────────────────────────────────────────────────

// TestMigration0090Files verifies that both migration files for PAT-1064 are
// present and contain the expected DDL landmarks, mirroring
// TestMigration0018Files.
func TestMigration0090Files(t *testing.T) {
	forward := filepath.Join("..", "..", "migrations", "0090_agent_health.sql")
	rollback := filepath.Join("..", "..", "migrations", "0090_agent_health_rollback.sql")

	for _, tc := range []struct {
		file        string
		mustContain []string
	}{
		{
			file: forward,
			mustContain: []string{
				"CREATE TABLE device_agent_health",
				"PRIMARY KEY (device_id, kind, subject)",
				"ever_succeeded",
				"collected_at",
				"REFERENCES devices(id) ON DELETE CASCADE",
				"CREATE TABLE device_agent_health_watermark",
				"0090_agent_health",
			},
		},
		{
			file: rollback,
			mustContain: []string{
				"DROP TABLE IF EXISTS device_agent_health",
				"0090_agent_health",
			},
		},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("migration file not readable (%s): %v", tc.file, err)
			continue
		}
		body := string(b)
		for _, needle := range tc.mustContain {
			if !strings.Contains(body, needle) {
				t.Errorf("%s: missing expected SQL fragment %q", tc.file, needle)
			}
		}
	}
}
