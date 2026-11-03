package mdmsync

import "strings"

// IsUnjoinableKey reports whether an azureADDeviceId value can never be
// matched to an Entra device: empty, or an all-zero GUID (with or without
// dashes/braces). Some Intune management agents never populate this field —
// PAT-1654 requires those records surface as an explicit unjoinable row
// rather than being silently dropped from the join.
func IsUnjoinableKey(azureADDeviceID string) bool {
	s := strings.TrimSpace(azureADDeviceID)
	if s == "" {
		return true
	}
	stripped := strings.NewReplacer("-", "", "{", "", "}", "").Replace(s)
	for _, c := range stripped {
		if c != '0' {
			return false
		}
	}
	return true
}

// JoinDevices computes the join between an Entra device ledger and an
// Intune managed-device ledger on managedDevice.azureADDeviceId ==
// device.deviceId (case-insensitive, per Graph's GUID formatting). Every
// input record produces exactly one output row: matched pairs, Entra-only
// devices, Intune-only devices, and unjoinable managed devices (missing or
// all-zero azureADDeviceId) are all represented, never dropped.
func JoinDevices(entraDevices []EntraDevice, managedDevices []ManagedDevice) []JoinedDevice {
	byDeviceID := make(map[string]*EntraDevice, len(entraDevices))
	for i := range entraDevices {
		byDeviceID[strings.ToLower(entraDevices[i].DeviceID)] = &entraDevices[i]
	}
	matched := make(map[string]bool, len(entraDevices))

	joined := make([]JoinedDevice, 0, len(entraDevices)+len(managedDevices))

	for i := range managedDevices {
		m := &managedDevices[i]

		if IsUnjoinableKey(m.AzureADDeviceID) {
			joined = append(joined, JoinedDevice{
				Status:  JoinStatusUnjoinable,
				JoinKey: m.AzureADDeviceID, // preserved as-is (often empty) for audit
				Managed: m,
			})
			continue
		}

		key := strings.ToLower(m.AzureADDeviceID)
		if entra, ok := byDeviceID[key]; ok {
			matched[key] = true
			joined = append(joined, JoinedDevice{
				Status:  JoinStatusJoined,
				JoinKey: m.AzureADDeviceID,
				Entra:   entra,
				Managed: m,
			})
			continue
		}

		joined = append(joined, JoinedDevice{
			Status:  JoinStatusIntuneOnly,
			JoinKey: m.AzureADDeviceID,
			Managed: m,
		})
	}

	for i := range entraDevices {
		e := &entraDevices[i]
		if matched[strings.ToLower(e.DeviceID)] {
			continue
		}
		joined = append(joined, JoinedDevice{
			Status: JoinStatusEntraOnly,
			Entra:  e,
		})
	}

	return joined
}
