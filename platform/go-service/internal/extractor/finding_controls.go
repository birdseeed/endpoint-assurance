package extractor

import (
	"encoding/json"
	"fmt"

	"patched.im/api/docs"
)

// findingControlIDs is the approved set of finding-control IDs, derived
// MECHANICALLY at package init from the embedded canonical contract
// (docs/payload.schema.json via docs.PayloadSchemaJSON). There is exactly one
// hand-maintained copy of the enum — the schema file itself; this set cannot
// drift from it because it IS it (PAT-913 gate round 4, replacing the earlier
// hand-written literal that a review round correctly flagged as a second copy
// of contract data).
//
// The set defines a RESERVED NAMESPACE over compliance signal keys: the
// free-form compliance bag may never use these IDs as keys, while
// compliance_findings and controls_assessed may ONLY use these IDs. Fail state
// arrives exclusively via compliance_findings, Pass state exclusively via
// controls_assessed, and neither can be forged through the bag. Enforced at
// both layers:
//
//   - ValidatePayload (validate.go) — the canonical enforcement point on the
//     ingestion path: rejects any payload whose controls_assessed or
//     compliance_findings names an ID outside this set, or whose compliance
//     bag uses an ID inside it, before the payload reaches raw_payloads.
//   - buildSignalsMap (upsert.go) — belt-and-braces on the extraction path:
//     skips (with a warn log) any violation of the same partition in an
//     already-stored payload, e.g. one ingested before this enforcement
//     existed or one that bypassed the validator.
//
// Adding a new finding control now means editing ONLY docs/payload.schema.json
// (both enum sites — the loader asserts they stay identical) plus the prose in
// PAYLOAD_SCHEMA.md; this code picks the change up at the next build.
var findingControlIDs = mustLoadFindingControlIDs(docs.PayloadSchemaJSON)

// isFindingControlID reports whether id is in the finding-control enum
// declared by docs/payload.schema.json.
func isFindingControlID(id string) bool {
	_, ok := findingControlIDs[id]
	return ok
}

// mustLoadFindingControlIDs parses the embedded payload schema and extracts
// the finding-control enum from BOTH sites that declare it:
//
//	properties.compliance_assessments.properties.controls_assessed.items.enum
//	properties.compliance_findings.items.properties.id.enum
//
// The two must be identical and non-empty — they are one contract stated in
// two positions, and a divergence would mean the schema file itself is
// self-contradictory. Any parse or extraction failure panics: this runs at
// package init, so a broken or restructured schema fails closed at process
// start (and instantly in any test run) rather than silently weakening the
// reserved-namespace enforcement.
func mustLoadFindingControlIDs(schemaJSON []byte) map[string]struct{} {
	var schema map[string]any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		panic(fmt.Sprintf("finding_controls: embedded payload.schema.json does not parse: %v", err))
	}

	assessed := mustEnumAt(schema,
		"properties", "compliance_assessments", "properties", "controls_assessed", "items", "enum")
	findings := mustEnumAt(schema,
		"properties", "compliance_findings", "items", "properties", "id", "enum")

	if len(assessed) == 0 {
		panic("finding_controls: controls_assessed enum in payload.schema.json is empty")
	}
	if len(assessed) != len(findings) {
		panic(fmt.Sprintf("finding_controls: payload.schema.json enum sites disagree: controls_assessed has %v, compliance_findings id has %v", assessed, findings))
	}
	out := make(map[string]struct{}, len(assessed))
	for _, id := range assessed {
		out[id] = struct{}{}
	}
	for _, id := range findings {
		if _, ok := out[id]; !ok {
			panic(fmt.Sprintf("finding_controls: payload.schema.json enum sites disagree: controls_assessed has %v, compliance_findings id has %v", assessed, findings))
		}
	}
	return out
}

// mustEnumAt walks nested JSON objects along path and returns the string
// slice found at the final key. Panics with the failing path on any missing
// key, wrong type, or non-string enum entry.
func mustEnumAt(root map[string]any, path ...string) []string {
	cur := any(root)
	for i, key := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			panic(fmt.Sprintf("finding_controls: payload.schema.json: %v is not an object", path[:i]))
		}
		cur, ok = obj[key]
		if !ok {
			panic(fmt.Sprintf("finding_controls: payload.schema.json: missing %v", path[:i+1]))
		}
	}
	raw, ok := cur.([]any)
	if !ok {
		panic(fmt.Sprintf("finding_controls: payload.schema.json: %v is not an array", path))
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			panic(fmt.Sprintf("finding_controls: payload.schema.json: %v contains non-string entry %v", path, v))
		}
		out = append(out, s)
	}
	return out
}
