package report

import (
	"encoding/json"
	"testing"
	"time"
)

func evidencePayload(t *testing.T, observed time.Time, certificates any, hardware map[string]any) []byte {
	t.Helper()
	payload := map[string]any{"collected_at": observed.Format(time.RFC3339)}
	if certificates != nil {
		payload["collection_status"] = map[string]any{"certificates": certificates}
	}
	if hardware != nil {
		payload["hardware_health"] = map[string]any{"collection_status": hardware}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal evidence payload: %v", err)
	}
	return b
}

func sectionValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func TestDeriveDeviceEvidenceStates(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	observed := now.Add(-time.Hour)
	received := now.Add(-30 * time.Minute)
	staleObserved := now.Add(-portalEvidenceStaleAfter - time.Second)

	tests := []struct {
		name          string
		payload       []byte
		wantAuthority string
		wantFreshness string
	}{
		{
			name: "fresh complete section is explicitly section scoped",
			payload: evidencePayload(t, observed, "complete", map[string]any{
				"battery": "complete", "storage": "complete", "disks": "complete",
			}),
			wantAuthority: EvidenceAuthoritySectionScoped,
			wantFreshness: EvidenceFreshnessFresh,
		},
		{
			name:          "fresh partial-only evidence is presence only",
			payload:       evidencePayload(t, observed, "partial", nil),
			wantAuthority: EvidenceAuthorityPresenceOnly,
			wantFreshness: EvidenceFreshnessFresh,
		},
		{
			name:          "fresh unavailable-only evidence has no authority",
			payload:       evidencePayload(t, observed, nil, map[string]any{"storage": "unavailable"}),
			wantAuthority: EvidenceAuthorityUnavailable,
			wantFreshness: EvidenceFreshnessFresh,
		},
		{
			name:          "missing collection status is unknown",
			payload:       evidencePayload(t, observed, nil, nil),
			wantAuthority: EvidenceAuthorityUnknown,
			wantFreshness: EvidenceFreshnessFresh,
		},
		{
			name:          "stale named evidence cannot make a current claim",
			payload:       evidencePayload(t, staleObserved, "complete", nil),
			wantAuthority: EvidenceAuthorityStale,
			wantFreshness: EvidenceFreshnessStale,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := deriveDeviceEvidence(tt.payload, &received, now)
			if evidence.Authority != tt.wantAuthority || evidence.Freshness != tt.wantFreshness {
				t.Fatalf("evidence = %+v, want authority=%q freshness=%q",
					evidence, tt.wantAuthority, tt.wantFreshness)
			}
			if evidence.ObservedAt == nil || !evidence.ObservedAt.Equal(observed) && !evidence.ObservedAt.Equal(staleObserved) {
				t.Fatalf("observed_at = %v, want payload collection time", evidence.ObservedAt)
			}
			if evidence.ReceivedAt != &received {
				t.Fatalf("received_at pointer changed: got %p want %p", evidence.ReceivedAt, &received)
			}
		})
	}
}

func TestDeriveDeviceEvidenceExposesOnlyExplicitSections(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	received := now.Add(-time.Minute)
	evidence := deriveDeviceEvidence(evidencePayload(t, now.Add(-time.Hour), "complete", map[string]any{
		"storage": "partial", "disks": "unavailable",
	}), &received, now)

	if evidence.Authority != EvidenceAuthoritySectionScoped {
		t.Fatalf("authority = %q, want section_scoped", evidence.Authority)
	}
	if sectionValue(evidence.Sections.Certificates) != EvidenceSectionComplete || evidence.Sections.HardwareHealth == nil ||
		sectionValue(evidence.Sections.HardwareHealth.Battery) != "" ||
		sectionValue(evidence.Sections.HardwareHealth.Storage) != EvidenceSectionPartial ||
		sectionValue(evidence.Sections.HardwareHealth.Disks) != EvidenceSectionUnavailable {
		t.Fatalf("sections = %+v, want only explicitly reported statuses", evidence.Sections)
	}
}

func TestDeriveDeviceEvidenceRequiresObservationAndReceipt(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	observed := now.Add(-time.Hour)
	received := now.Add(-time.Minute)
	complete := evidencePayload(t, observed, "complete", nil)

	tests := []struct {
		name       string
		payload    []byte
		receivedAt *time.Time
	}{
		{"missing receipt", complete, nil},
		{"missing observation", []byte(`{"collection_status":{"certificates":"complete"}}`), &received},
		{"future observation", evidencePayload(t, now.Add(time.Minute), "complete", nil), &received},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := deriveDeviceEvidence(tt.payload, tt.receivedAt, now)
			if evidence.Authority != EvidenceAuthorityUnknown || evidence.Freshness != EvidenceFreshnessUnknown {
				t.Fatalf("evidence = %+v, want unknown authority and freshness", evidence)
			}
		})
	}
}

func TestDeriveDeviceEvidenceFreshnessBoundaries(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	received := now.Add(-time.Minute)
	tests := []struct {
		name          string
		observed      time.Time
		wantFreshness string
		wantAuthority string
	}{
		{"exactly seven days is fresh", now.Add(-portalEvidenceStaleAfter), EvidenceFreshnessFresh, EvidenceAuthoritySectionScoped},
		{"one nanosecond beyond seven days is stale", now.Add(-portalEvidenceStaleAfter - time.Nanosecond), EvidenceFreshnessStale, EvidenceAuthorityStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := deriveDeviceEvidence(evidencePayload(t, tt.observed, "complete", nil), &received, now)
			if evidence.Freshness != tt.wantFreshness || evidence.Authority != tt.wantAuthority {
				t.Fatalf("evidence = %+v, want freshness=%q authority=%q", evidence, tt.wantFreshness, tt.wantAuthority)
			}
		})
	}
}

func TestDeriveDeviceEvidenceDelayedUploadUsesObservationTime(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	received := now.Add(-time.Minute)
	observed := now.Add(-portalEvidenceStaleAfter - time.Minute)
	evidence := deriveDeviceEvidence(evidencePayload(t, observed, "complete", nil), &received, now)
	if evidence.Freshness != EvidenceFreshnessStale || evidence.Authority != EvidenceAuthorityStale {
		t.Fatalf("delayed upload evidence = %+v, want stale despite fresh receipt", evidence)
	}
}

func TestDeriveDeviceEvidenceMalformedStatusFailsClosed(t *testing.T) {
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	received := now.Add(-time.Minute)
	evidence := deriveDeviceEvidence(evidencePayload(t, now.Add(-time.Hour), "complete", map[string]any{
		"storage": "not-a-status",
	}), &received, now)
	if evidence.Authority != EvidenceAuthorityUnknown || len(evidence.Sections.statuses()) != 0 {
		t.Fatalf("malformed evidence = %+v, want empty sections and unknown authority", evidence)
	}
}
