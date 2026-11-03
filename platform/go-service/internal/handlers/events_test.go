package handlers

// Unit tests for parseAndValidateAuditEvent — no DB, no HTTP. Covers the
// malformed-payload rejection cases PAT-1022 asks for directly, since
// validation here has no DB dependency at all (unlike enforcement_audit.go's
// per-event loop, which still needed a DI seam because ITS handler-level
// tests exercise the full request path). See events_db_test.go for the
// full end-to-end auth + valid-ingestion coverage against a real DB.

import (
	"strings"
	"testing"
)

const evValidBody = `{
	"event_type": "verification_failed",
	"tenant_id": "11111111-1111-1111-1111-111111111111",
	"device_id": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
	"label": "googlechrome",
	"version": "125.0.6422.60",
	"verified_signer": null,
	"reason": "signer_mismatch",
	"expected": null,
	"actual": null,
	"platform": "macos",
	"timestamp": "2026-12-20T16:00:00Z"
}`

func TestParseAndValidateAuditEvent_Valid(t *testing.T) {
	evt, occurredAt, err := parseAndValidateAuditEvent([]byte(evValidBody))
	if err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if evt.EventType != "verification_failed" {
		t.Errorf("EventType = %q, want verification_failed", evt.EventType)
	}
	if evt.DeviceID != "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" {
		t.Errorf("DeviceID = %q, want the macOS HW UUID", evt.DeviceID)
	}
	if evt.Platform != "macos" {
		t.Errorf("Platform = %q, want macos", evt.Platform)
	}
	if occurredAt.IsZero() {
		t.Error("occurredAt must not be zero for a valid timestamp")
	}
	if evt.Label == nil || *evt.Label != "googlechrome" {
		t.Errorf("Label = %v, want googlechrome", evt.Label)
	}
	if evt.VerifiedSigner != nil {
		t.Errorf("VerifiedSigner = %v, want nil for a JSON null", evt.VerifiedSigner)
	}
}

func TestParseAndValidateAuditEvent_AllContractEventTypes(t *testing.T) {
	// All event_type values from
	// updater/docs/audit-events-contract.md's "Event types" table must be
	// accepted — this closed set must never silently drift from the
	// contract both agents already implement against.
	types := []string{
		"verification_passed",
		"verification_failed",
		"install_completed",
		"install_failed",
		"posture_warning",
		"allowlist_tamper_detected",
		"version_blocked",
	}
	for _, et := range types {
		t.Run(et, func(t *testing.T) {
			body := strings.Replace(evValidBody, "verification_failed", et, 1)
			if _, _, err := parseAndValidateAuditEvent([]byte(body)); err != nil {
				t.Errorf("event_type %q rejected: %v", et, err)
			}
		})
	}
}

func TestParseAndValidateAuditEvent_MalformedJSON(t *testing.T) {
	_, _, err := parseAndValidateAuditEvent([]byte(`{"event_type": "verification_failed", `))
	if err == nil {
		t.Fatal("want error for truncated/malformed JSON, got nil")
	}
}

func TestParseAndValidateAuditEvent_NotJSONAtAll(t *testing.T) {
	_, _, err := parseAndValidateAuditEvent([]byte(`not json`))
	if err == nil {
		t.Fatal("want error for non-JSON body, got nil")
	}
}

func TestParseAndValidateAuditEvent_UnknownEventType(t *testing.T) {
	body := strings.Replace(evValidBody, "verification_failed", "made_up_event", 1)
	_, _, err := parseAndValidateAuditEvent([]byte(body))
	if err == nil {
		t.Fatal("want error for unknown event_type, got nil")
	}
}

func TestParseAndValidateAuditEvent_MissingDeviceID(t *testing.T) {
	body := strings.Replace(evValidBody, `"device_id": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",`, `"device_id": "",`, 1)
	_, _, err := parseAndValidateAuditEvent([]byte(body))
	if err == nil {
		t.Fatal("want error for empty device_id, got nil")
	}
}

func TestParseAndValidateAuditEvent_UnknownPlatform(t *testing.T) {
	body := strings.Replace(evValidBody, `"platform": "macos",`, `"platform": "linux",`, 1)
	_, _, err := parseAndValidateAuditEvent([]byte(body))
	if err == nil {
		t.Fatal("want error for unknown platform, got nil")
	}
}

func TestParseAndValidateAuditEvent_BadTimestamp(t *testing.T) {
	body := strings.Replace(evValidBody, `"timestamp": "2026-12-20T16:00:00Z"`, `"timestamp": "not-a-time"`, 1)
	_, _, err := parseAndValidateAuditEvent([]byte(body))
	if err == nil {
		t.Fatal("want error for non-RFC3339 timestamp, got nil")
	}
}

func TestParseAndValidateAuditEvent_MissingTimestampField(t *testing.T) {
	body := strings.Replace(evValidBody, `"timestamp": "2026-12-20T16:00:00Z"`, `"timestamp": ""`, 1)
	_, _, err := parseAndValidateAuditEvent([]byte(body))
	if err == nil {
		t.Fatal("want error for empty timestamp, got nil")
	}
}

// TestParseAndValidateAuditEvent_OptionalFieldsAbsent proves the minimal
// windows-shaped envelope (no label/version/reason etc — install_completed
// on a fresh device, say) is still accepted; only event_type, device_id,
// platform, and timestamp are actually required by the contract.
func TestParseAndValidateAuditEvent_OptionalFieldsAbsent(t *testing.T) {
	body := `{
		"event_type": "install_completed",
		"device_id": "SOME-WINDOWS-MACHINE",
		"platform": "windows",
		"timestamp": "2026-12-20T16:00:00Z"
	}`
	evt, _, err := parseAndValidateAuditEvent([]byte(body))
	if err != nil {
		t.Fatalf("minimal envelope rejected: %v", err)
	}
	if evt.Label != nil {
		t.Errorf("Label = %v, want nil when absent from the body", evt.Label)
	}
}
