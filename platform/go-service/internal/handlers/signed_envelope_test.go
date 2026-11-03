package handlers

import (
	"strings"
	"testing"
)

// decodeStrictEnvelope guards the {signed_payload, signature, key_id} shape
// the agent artifact metadata envelope still uses. These cases were first
// exercised through the retired signed-catalogue publish handler (PAT-495)
// and now run against the decoder directly (PAT-2246).

func TestDecodeStrictEnvelope_AcceptsExactShape(t *testing.T) {
	env, err := decodeStrictEnvelope([]byte(`{"signed_payload":"YWJj","signature":"ZGVm","key_id":"0123456789abcdef"}`))
	if err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if env.SignedPayload != "YWJj" || env.Signature != "ZGVm" || env.KeyID != "0123456789abcdef" {
		t.Fatalf("decoded envelope = %+v", env)
	}
}

func TestDecodeStrictEnvelope_RejectsMalformed(t *testing.T) {
	const keyID = "0123456789abcdef"
	for name, body := range map[string]string{
		"not_json":               `not json at all`,
		"missing_signature":      `{"signed_payload":"YWJj","key_id":"` + keyID + `"}`,
		"missing_signed_payload": `{"signature":"YWJj","key_id":"` + keyID + `"}`,
		"missing_key_id":         `{"signed_payload":"YWJj","signature":"YWJj"}`,
		"empty_body":             ``,
		"array_not_object":       `["signed_payload","signature","key_id"]`,
		"trailing_data":          `{"signed_payload":"YWJj","signature":"YWJj","key_id":"` + keyID + `"}  {"x":1}`,
		"non_string_field":       `{"signed_payload":123,"signature":"YWJj","key_id":"` + keyID + `"}`,
		"empty_string_field":     `{"signed_payload":"","signature":"YWJj","key_id":"` + keyID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictEnvelope([]byte(body)); err == nil {
				t.Fatalf("malformed envelope accepted: %s", body)
			}
		})
	}
}

// Go's encoding/json matches keys case-insensitively and keeps the last of a
// duplicate key, while the Python verifiers on endpoints are case-sensitive.
// Any envelope two parsers could read differently must be rejected outright.
func TestDecodeStrictEnvelope_RejectsParserDifferential(t *testing.T) {
	const keyID = "0123456789abcdef"
	const payload = "YWJj"
	const sig = "ZGVm"
	for name, body := range map[string]string{
		"duplicate_signed_payload_same_case":       `{"signed_payload":"amunkYQ==","signed_payload":"` + payload + `","signature":"` + sig + `","key_id":"` + keyID + `"}`,
		"case_variant_key":                         `{"SIGNED_PAYLOAD":"` + payload + `","signature":"` + sig + `","key_id":"` + keyID + `"}`,
		"junk_lowercase_plus_genuine_case_variant": `{"signed_payload":"amunkYQ==","SIGNED_PAYLOAD":"` + payload + `","signature":"` + sig + `","key_id":"` + keyID + `"}`,
		"duplicate_signature":                      `{"signed_payload":"` + payload + `","signature":"amunkYQ==","signature":"` + sig + `","key_id":"` + keyID + `"}`,
		"duplicate_key_id":                         `{"signed_payload":"` + payload + `","signature":"` + sig + `","key_id":"wrong","key_id":"` + keyID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictEnvelope([]byte(body)); err == nil {
				t.Fatalf("ambiguous envelope accepted: %s", body)
			}
		})
	}
}

func TestDecodeStrictEnvelope_UnknownField(t *testing.T) {
	_, err := decodeStrictEnvelope([]byte(`{"signed_payload":"a","signature":"b","key_id":"c","extra":"z"}`))
	if err == nil {
		t.Fatal("want error for an envelope with an unexpected extra field")
	}
	if !strings.Contains(err.Error(), "extra") {
		t.Errorf("expected error mentioning the unexpected field name, got: %v", err)
	}
}
