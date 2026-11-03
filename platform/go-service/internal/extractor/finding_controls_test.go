package extractor

import (
	"testing"

	"patched.im/api/docs"
)

// The expected IDs below are a deliberate literal: tests PIN behavior, they
// are not a second production copy of the contract. If the schema enum grows,
// this test fails and is updated in the same change — that is the test doing
// its job, not drift. Production code carries no hand-written copy; the
// enforcement source is the embedded schema itself (finding_controls.go).
var expectedFindingControls = []string{
	"disk_encryption_off",
	"removable_storage_unencrypted",
}

// TestFindingControlIDs_DerivedFromEmbeddedSchema asserts the package-level
// set (parsed at init from the embedded docs/payload.schema.json) contains
// exactly the expected finding-control IDs. Reaching this test at all also
// proves init did not panic, i.e. the embedded schema parsed and both enum
// sites were extracted successfully.
func TestFindingControlIDs_DerivedFromEmbeddedSchema(t *testing.T) {
	if len(findingControlIDs) != len(expectedFindingControls) {
		t.Fatalf("findingControlIDs has %d entries, want %d: %v",
			len(findingControlIDs), len(expectedFindingControls), findingControlIDs)
	}
	for _, id := range expectedFindingControls {
		if !isFindingControlID(id) {
			t.Errorf("expected %q in the schema-derived finding-control set", id)
		}
	}
	if isFindingControlID("filevault") {
		t.Error("filevault must not be a finding control")
	}
	if isFindingControlID("") {
		t.Error("empty string must not be a finding control")
	}
}

// TestMustLoadFindingControlIDs_SchemaSitesIdentical re-runs the loader
// against the embedded schema and asserts it returns the expected set — the
// loader itself panics if the two enum sites (controls_assessed items and
// compliance_findings id) disagree or are empty, so a green run here asserts
// site identity too.
func TestMustLoadFindingControlIDs_SchemaSitesIdentical(t *testing.T) {
	got := mustLoadFindingControlIDs(docs.PayloadSchemaJSON)
	if len(got) != len(expectedFindingControls) {
		t.Fatalf("loader returned %d entries, want %d: %v", len(got), len(expectedFindingControls), got)
	}
	for _, id := range expectedFindingControls {
		if _, ok := got[id]; !ok {
			t.Errorf("loader result missing %q", id)
		}
	}
}

// TestMustLoadFindingControlIDs_FailsClosed asserts the loader panics on a
// schema it cannot mechanically interpret, rather than degrading to an empty
// (enforce-nothing) or partial set. Three shapes: unparseable JSON, a
// restructured schema missing the enum path, and enum sites that disagree.
func TestMustLoadFindingControlIDs_FailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		schema string
	}{
		{"unparseable", `{not json`},
		{"missing_enum_path", `{"properties": {}}`},
		{"sites_disagree", `{
			"properties": {
				"compliance_assessments": {"properties": {"controls_assessed": {"items": {"enum": ["disk_encryption_off"]}}}},
				"compliance_findings": {"items": {"properties": {"id": {"enum": ["disk_encryption_off", "removable_storage_unencrypted"]}}}}
			}
		}`},
		{"empty_enum", `{
			"properties": {
				"compliance_assessments": {"properties": {"controls_assessed": {"items": {"enum": []}}}},
				"compliance_findings": {"items": {"properties": {"id": {"enum": []}}}}
			}
		}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected loader to panic (fail closed) but it returned")
				}
			}()
			mustLoadFindingControlIDs([]byte(tc.schema))
		})
	}
}
