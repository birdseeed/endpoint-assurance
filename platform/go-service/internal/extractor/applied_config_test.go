package extractor

import (
	"encoding/json"
	"testing"
)

// appliedConfigWire is the exact shape the macOS agent emits (PAT-1667,
// updater/macos/patched-collect.sh's applied_configuration block). Keeping a
// verbatim copy here means a wire-format change shows up as a test failure
// rather than as silently dropped fields.
const appliedConfigWire = `{
  "profiles": [
    {
      "identifier": "org.example.firewall",
      "display_name": "Firewall",
      "organization": "Example Ltd",
      "payload": "[{\"PayloadType\": \"com.apple.security.firewall\"}]",
      "payload_capped": false
    },
    {
      "identifier": "org.example.big",
      "display_name": "Big Profile",
      "organization": "Example Ltd",
      "payload": "[{\"PayloadType\": \"com.apple.secu",
      "payload_capped": true
    },
    {
      "identifier": "org.example.broken",
      "display_name": "",
      "organization": "",
      "payload": "",
      "payload_capped": false,
      "decode_error": true
    }
  ],
  "profiles_count": 3,
  "profiles_truncated": false,
  "collection_status": "ok",
  "mdm_server_url": "https://jamf.example.org/mdm",
  "mdm_supervised": "Yes"
}`

func TestParseAppliedConfiguration_RealAgentShape(t *testing.T) {
	a := parseAppliedConfiguration(json.RawMessage(appliedConfigWire), nil)
	if a == nil {
		t.Fatal("parseAppliedConfiguration returned nil for a valid agent shape")
	}
	if a.CollectionStatus != "ok" {
		t.Errorf("collection_status = %q, want ok", a.CollectionStatus)
	}
	if a.ProfilesCount != 3 || len(a.Profiles) != 3 {
		t.Errorf("profiles_count = %d, len(profiles) = %d, want 3 and 3", a.ProfilesCount, len(a.Profiles))
	}
	if a.ProfilesTruncated {
		t.Error("profiles_truncated = true, want false")
	}
	if a.MDMServerURL == nil || *a.MDMServerURL != "https://jamf.example.org/mdm" {
		t.Errorf("mdm_server_url = %v", a.MDMServerURL)
	}
	if a.MDMSupervised != "Yes" {
		t.Errorf("mdm_supervised = %q", a.MDMSupervised)
	}

	// The payload is a STRING on the wire, not a nested object, and must
	// survive verbatim — including the capped fragment, which is not valid
	// JSON and would be lost by any reparse.
	if got, want := a.Profiles[0].Payload, `[{"PayloadType": "com.apple.security.firewall"}]`; got != want {
		t.Errorf("payload[0] = %q, want %q", got, want)
	}
	if !a.Profiles[1].PayloadCapped {
		t.Error("payload_capped = false on the capped profile")
	}
	if got, want := a.Profiles[1].Payload, `[{"PayloadType": "com.apple.secu`; got != want {
		t.Errorf("capped payload = %q, want the verbatim fragment %q", got, want)
	}
	if !a.Profiles[2].DecodeError {
		t.Error("decode_error = false on the undecodable profile")
	}
	// A profile the agent could not decode is still present on the device.
	// Its payload is unknown, not empty, and nothing here may pretend
	// otherwise.
	if a.Profiles[2].Identifier != "org.example.broken" {
		t.Errorf("decode_error profile lost its identifier: %q", a.Profiles[2].Identifier)
	}
}

func TestParseAppliedConfiguration_AbsentOrNull(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"absent", nil},
		{"empty", json.RawMessage("")},
		{"null", json.RawMessage("null")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAppliedConfiguration(tc.raw, nil); got != nil {
				t.Errorf("parseAppliedConfiguration(%q) = %+v; want nil", tc.raw, got)
			}
		})
	}
}

func TestParseAppliedConfiguration_MalformedReturnsNil(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"not an object", `"a string"`},
		{"wrong type for profiles", `{"profiles":"not-an-array","collection_status":"ok"}`},
		{"wrong type for count", `{"profiles":[],"profiles_count":"three"}`},
		{"wrong type for payload", `{"profiles":[{"identifier":"x","payload":{"nested":true}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAppliedConfiguration(json.RawMessage(tc.raw), nil); got != nil {
				t.Errorf("parseAppliedConfiguration(%s) = %+v; want nil", tc.raw, got)
			}
		})
	}
}

// TestPayloadUnmarshal_MalformedAppliedConfiguration_DoesNotPoisonOtherFields
// is the reason AppliedConfiguration is json.RawMessage rather than a typed
// struct field: a malformed section must not abort the entire payload
// unmarshal and take the device's whole inventory upload down with it. Same
// property backup_status and agent_health already have.
func TestPayloadUnmarshal_MalformedAppliedConfiguration_DoesNotPoisonOtherFields(t *testing.T) {
	raw := []byte(`{
		"schema_version": 3,
		"platform": "macos",
		"agent_version": "0.16.0",
		"collected_at": "2026-09-12T09:00:00Z",
		"applied_configuration": {"profiles": "this should be an array"},
		"device": {"serial": "C02ABC123"}
	}`)

	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("a malformed applied_configuration aborted the whole payload unmarshal: %v", err)
	}
	if p.SchemaVersion != 3 {
		t.Errorf("schema_version = %d, want 3", p.SchemaVersion)
	}
	if p.Device.Serial != "C02ABC123" {
		t.Errorf("device.serial = %q; the rest of the payload must survive", p.Device.Serial)
	}
	if got := parseAppliedConfiguration(p.AppliedConfiguration, nil); got != nil {
		t.Errorf("parseAppliedConfiguration = %+v, want nil for the malformed section", got)
	}
}

// TestParseAppliedConfiguration_EmptyOKCollectionIsNotAbsence: an unenrolled
// Mac reports zero profiles with collection_status ok. That is a real
// observation and must not decode to the same thing as "the agent never sent
// the section".
func TestParseAppliedConfiguration_EmptyOKCollectionIsNotAbsence(t *testing.T) {
	raw := `{"profiles":[],"profiles_count":0,"profiles_truncated":false,"collection_status":"ok","mdm_server_url":null,"mdm_supervised":"Unknown"}`
	a := parseAppliedConfiguration(json.RawMessage(raw), nil)
	if a == nil {
		t.Fatal("an unenrolled Mac's genuine empty observation decoded as absent")
	}
	if a.CollectionStatus != "ok" || len(a.Profiles) != 0 {
		t.Errorf("got %+v, want an ok collection with zero profiles", a)
	}
	if a.MDMServerURL != nil {
		t.Errorf("mdm_server_url = %v, want nil for an unenrolled Mac", a.MDMServerURL)
	}
}

// TestParseAppliedConfiguration_RateLimitedShape: the agent serves its
// last-known-good cache on a rate-limited run, so the profile list can look
// perfectly healthy. Only collection_status distinguishes it.
func TestParseAppliedConfiguration_RateLimitedShape(t *testing.T) {
	raw := `{"profiles":[{"identifier":"org.example.firewall","display_name":"Firewall","organization":"","payload":"[]","payload_capped":false}],
	         "profiles_count":1,"profiles_truncated":false,"collection_status":"rate_limited",
	         "mdm_server_url":"https://jamf.example.org/mdm","mdm_supervised":"Yes"}`
	a := parseAppliedConfiguration(json.RawMessage(raw), nil)
	if a == nil {
		t.Fatal("parseAppliedConfiguration returned nil for the rate-limited shape")
	}
	if a.CollectionStatus != "rate_limited" {
		t.Errorf("collection_status = %q, want rate_limited — this is the only signal that the list is cached", a.CollectionStatus)
	}
}
