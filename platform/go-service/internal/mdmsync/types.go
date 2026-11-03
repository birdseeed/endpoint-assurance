package mdmsync

import "time"

// EntraDevice is the parsed shape of one item from
// GET https://graph.microsoft.com/v1.0/devices, narrowed to the fields
// PAT-1654 needs. JSON tags match the Graph field names verbatim so this
// unmarshals directly from a raw response item.
type EntraDevice struct {
	DeviceID                      string    `json:"deviceId"`
	DisplayName                   string    `json:"displayName"`
	OperatingSystem               string    `json:"operatingSystem"`
	OperatingSystemVersion        string    `json:"operatingSystemVersion"`
	ApproximateLastSignInDateTime time.Time `json:"approximateLastSignInDateTime"`
	AccountEnabled                bool      `json:"accountEnabled"`
	TrustType                     string    `json:"trustType"`
	IsManaged                     bool      `json:"isManaged"`
}

// ManagedDevice is the parsed shape of one item from
// GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices,
// narrowed to the fields PAT-1654 needs. AzureADDeviceID is the join key
// back to EntraDevice.DeviceID — it can be empty or an all-zero GUID for
// some management agents; see IsUnjoinableKey.
type ManagedDevice struct {
	ID                      string    `json:"id"`
	AzureADDeviceID         string    `json:"azureADDeviceId"`
	DeviceName              string    `json:"deviceName"`
	OperatingSystem         string    `json:"operatingSystem"`
	OSVersion               string    `json:"osVersion"`
	LastSyncDateTime        time.Time `json:"lastSyncDateTime"`
	EnrolledDateTime        time.Time `json:"enrolledDateTime"`
	ComplianceState         string    `json:"complianceState"`
	ManagedDeviceOwnerType  string    `json:"managedDeviceOwnerType"`
	ManagementAgent         string    `json:"managementAgent"`
	DeviceRegistrationState string    `json:"deviceRegistrationState"`
}

// JoinStatus classifies one row of the computed join between the Entra
// device ledger and the Intune managed-device ledger.
type JoinStatus string

const (
	// JoinStatusJoined is a managed device whose azureADDeviceId matched an
	// Entra device's deviceId.
	JoinStatusJoined JoinStatus = "joined"
	// JoinStatusEntraOnly is an Entra device with no matching managed
	// device (not enrolled in Intune, or enrolled under a different join
	// key than we could match).
	JoinStatusEntraOnly JoinStatus = "entra_only"
	// JoinStatusIntuneOnly is a managed device with a well-formed
	// azureADDeviceId that did not match any fetched Entra device.
	JoinStatusIntuneOnly JoinStatus = "intune_only"
	// JoinStatusUnjoinable is a managed device whose azureADDeviceId is
	// empty or an all-zero GUID, so it can never be matched to an Entra
	// device at all. Surfaced explicitly, never dropped.
	JoinStatusUnjoinable JoinStatus = "unjoinable"
)

// JoinedDevice is one row of the computed join. Exactly one of Entra /
// Managed is nil for EntraOnly / IntuneOnly / Unjoinable rows; both are set
// for Joined rows.
type JoinedDevice struct {
	Status  JoinStatus
	JoinKey string // the azureADDeviceId used to match, "" for Unjoinable
	Entra   *EntraDevice
	Managed *ManagedDevice
}
