package mdmsync

import "testing"

// TestJoinDevices covers the four fixture scenarios required by PAT-1654:
// a device present in both ledgers, a device only in Entra, a device only
// in Intune, and a managed device with a missing/all-zero azureADDeviceId.
func TestJoinDevices(t *testing.T) {
	entra := []EntraDevice{
		{DeviceID: "11111111-1111-1111-1111-111111111111", DisplayName: "both-sides"},
		{DeviceID: "22222222-2222-2222-2222-222222222222", DisplayName: "entra-only"},
	}
	managed := []ManagedDevice{
		{ID: "managed-1", AzureADDeviceID: "11111111-1111-1111-1111-111111111111", DeviceName: "both-sides"},
		{ID: "managed-2", AzureADDeviceID: "33333333-3333-3333-3333-333333333333", DeviceName: "intune-only"},
		{ID: "managed-3", AzureADDeviceID: "00000000-0000-0000-0000-000000000000", DeviceName: "zero-guid"},
		{ID: "managed-4", AzureADDeviceID: "", DeviceName: "empty-key"},
	}

	got := JoinDevices(entra, managed)

	byManagedID := map[string]JoinedDevice{}
	var entraOnly []JoinedDevice
	for _, j := range got {
		if j.Managed != nil {
			byManagedID[j.Managed.ID] = j
			continue
		}
		entraOnly = append(entraOnly, j)
	}

	// Device present in both.
	both, ok := byManagedID["managed-1"]
	if !ok {
		t.Fatalf("managed-1 missing from join output")
	}
	if both.Status != JoinStatusJoined {
		t.Errorf("managed-1 status = %q, want %q", both.Status, JoinStatusJoined)
	}
	if both.Entra == nil || both.Entra.DeviceID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("managed-1 Entra = %+v, want matched entra device", both.Entra)
	}

	// Device only in Intune (real key, no matching Entra device).
	intuneOnly, ok := byManagedID["managed-2"]
	if !ok {
		t.Fatalf("managed-2 missing from join output")
	}
	if intuneOnly.Status != JoinStatusIntuneOnly {
		t.Errorf("managed-2 status = %q, want %q", intuneOnly.Status, JoinStatusIntuneOnly)
	}
	if intuneOnly.Entra != nil {
		t.Errorf("managed-2 Entra = %+v, want nil", intuneOnly.Entra)
	}

	// All-zero GUID key: unjoinable, not dropped.
	zeroGUID, ok := byManagedID["managed-3"]
	if !ok {
		t.Fatalf("managed-3 (all-zero azureADDeviceId) missing from join output — must never be dropped")
	}
	if zeroGUID.Status != JoinStatusUnjoinable {
		t.Errorf("managed-3 status = %q, want %q", zeroGUID.Status, JoinStatusUnjoinable)
	}

	// Empty key: also unjoinable, not dropped.
	emptyKey, ok := byManagedID["managed-4"]
	if !ok {
		t.Fatalf("managed-4 (empty azureADDeviceId) missing from join output — must never be dropped")
	}
	if emptyKey.Status != JoinStatusUnjoinable {
		t.Errorf("managed-4 status = %q, want %q", emptyKey.Status, JoinStatusUnjoinable)
	}

	// Device only in Entra.
	if len(entraOnly) != 1 {
		t.Fatalf("got %d entra-only rows, want 1: %+v", len(entraOnly), entraOnly)
	}
	if entraOnly[0].Status != JoinStatusEntraOnly {
		t.Errorf("entra-only status = %q, want %q", entraOnly[0].Status, JoinStatusEntraOnly)
	}
	if entraOnly[0].Entra == nil || entraOnly[0].Entra.DeviceID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("entra-only Entra = %+v, want the unmatched entra device", entraOnly[0].Entra)
	}

	wantTotal := len(entra) + len(managed) - 1 // one pair merges into a single joined row
	if len(got) != wantTotal {
		t.Errorf("got %d total join rows, want %d (every input record represented exactly once)", len(got), wantTotal)
	}
}

func TestIsUnjoinableKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"00000000-0000-0000-0000-000000000000", true},
		{"{00000000-0000-0000-0000-000000000000}", true},
		{"11111111-1111-1111-1111-111111111111", false},
		{"00000000-0000-0000-0000-000000000001", false},
	}
	for _, c := range cases {
		if got := IsUnjoinableKey(c.key); got != c.want {
			t.Errorf("IsUnjoinableKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}

// TestJoinDevices_CaseInsensitiveMatch guards the join against Graph
// returning differently-cased GUIDs between the two endpoints.
func TestJoinDevices_CaseInsensitiveMatch(t *testing.T) {
	entra := []EntraDevice{{DeviceID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}}
	managed := []ManagedDevice{{ID: "m1", AzureADDeviceID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}

	got := JoinDevices(entra, managed)
	if len(got) != 1 || got[0].Status != JoinStatusJoined {
		t.Fatalf("got %+v, want a single joined row", got)
	}
}
