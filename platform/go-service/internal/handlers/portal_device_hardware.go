// Portal device identity + hardware blocks (PAT-2141).
//
// Extends GET /v1/portal/devices/{deviceID} with the identity and hardware
// data the staff console's GET /admin/devices/{deviceID} already shows
// (admin_overview.go's DeviceDetailHandler) and the portal PDF's Hardware
// health section already reads (PAT-2130, internal/report/portal_pdf.go),
// but which the JSON device-detail endpoint never surfaced to a customer.
//
// No new SQL: report.Fetch (called once by PortalDeviceDetailHandler) already
// loads rep.Device, rep.Hardware and rep.HardwareHealth via the same
// fetchHardwareHealth query the admin endpoint uses, and
// report.FetchPortalDeviceEvidence already loads the section-scoped evidence
// envelope this file reduces into per-block evidence stamps. This file only
// shapes JSON from data the handler already has in hand.
package handlers

import (
	"time"

	"patched.im/api/internal/report"
)

// Collection-status vocabulary reused verbatim from the existing evidence
// envelope (report.EvidenceSection*), plus one value this ticket adds:
// "not_collected" for a block with no stored data and no explicit collection
// status at all — never zeros or empty arrays standing in for absence (root
// AGENTS.md: "Absence requires authority").
const (
	portalCollectionComplete     = report.EvidenceSectionComplete
	portalCollectionPartial      = report.EvidenceSectionPartial
	portalCollectionUnavailable  = report.EvidenceSectionUnavailable
	portalCollectionNotCollected = "not_collected"
)

// portalEvidenceStamp is the reduced evidence-timing view carried on the
// identity and hardware blocks: the same observed/received timestamps and
// freshness vocabulary the device-wide evidence envelope
// (report.DeviceEvidence, already returned at device.evidence) uses, scoped
// to one block instead of repeating the whole section map on every block.
type portalEvidenceStamp struct {
	ObservedAt *time.Time `json:"observed_at"`
	ReceivedAt *time.Time `json:"received_at"`
	Freshness  string     `json:"freshness"`
}

func portalEvidenceStampFrom(evidence report.DeviceEvidence) portalEvidenceStamp {
	return portalEvidenceStamp{
		ObservedAt: evidence.ObservedAt,
		ReceivedAt: evidence.ReceivedAt,
		Freshness:  evidence.Freshness,
	}
}

// portalDeviceIdentity is the customer-facing identity band (PAT-2141): the
// same devices columns GET /admin/devices/{deviceID} reads, minus hw_uuid,
// which stays internal-only and is never sent on this tenant-scoped surface.
//
// hardware_model carries devices.hw_model verbatim. There is no separate
// "model identifier" column or payload field anywhere in this platform:
// hw_model IS the identifier form (sysctl hw.model on macOS, e.g. "Mac16,1";
// WMI ComputerSystemProduct.Name on Windows) — see
// go-service/docs/PAYLOAD_SCHEMA.md's Device object table. A human-readable
// model name ("MacBook Pro") is not collected or stored anywhere today, so
// this field is not fabricated here.
type portalDeviceIdentity struct {
	// Status is "complete" once this device has delivered at least one
	// inventory payload (every required identity field is validated
	// atomically at ingest, so there is no partial state for this block),
	// or "not_collected" when the device row exists (e.g. enrolled) but no
	// payload has ever been received — never rendered as blank/zeroed
	// fields.
	Status        string              `json:"status"`
	Serial        string              `json:"serial,omitempty"`
	HardwareModel string              `json:"hardware_model,omitempty"`
	ComputerName  string              `json:"computer_name,omitempty"`
	Architecture  string              `json:"architecture,omitempty"`
	OSName        string              `json:"os_name,omitempty"`
	OSVersion     string              `json:"os_version,omitempty"`
	OSBuild       string              `json:"os_build,omitempty"`
	AgentVersion  string              `json:"agent_version,omitempty"`
	FirstSeen     *time.Time          `json:"first_seen,omitempty"`
	LastSeen      *time.Time          `json:"last_seen,omitempty"`
	Evidence      portalEvidenceStamp `json:"evidence"`
}

// buildPortalDeviceIdentity shapes the identity block from data report.Fetch
// already loaded. evidence.ReceivedAt is the "has this device ever reported"
// signal: rep.Device.* string columns are COALESCE(..., ”) in report.Fetch's
// query, so an enrolled-but-never-reported device would otherwise render as a
// wall of empty strings rather than an explicit absence.
func buildPortalDeviceIdentity(rep report.Report, evidence report.DeviceEvidence) portalDeviceIdentity {
	id := portalDeviceIdentity{
		Serial:        rep.Device.Serial,
		HardwareModel: rep.Device.HWModel,
		ComputerName:  rep.Device.ComputerName,
		Architecture:  rep.Device.Arch,
		OSName:        rep.Device.OS,
		OSVersion:     rep.Device.OSVersion,
		OSBuild:       rep.Device.OSBuild,
		AgentVersion:  rep.Device.AgentVersion,
		Evidence:      portalEvidenceStampFrom(evidence),
	}
	if !rep.Device.FirstSeen.IsZero() {
		t := rep.Device.FirstSeen
		id.FirstSeen = &t
	}
	if !rep.Device.LastSeen.IsZero() {
		t := rep.Device.LastSeen
		id.LastSeen = &t
	}
	if evidence.ReceivedAt == nil {
		id.Status = portalCollectionNotCollected
		return id
	}
	id.Status = portalCollectionComplete
	return id
}

type portalHardwareCPU struct {
	Status string `json:"status"`
	Model  string `json:"model,omitempty"`
	Cores  int    `json:"cores,omitempty"`
}

type portalHardwareMemory struct {
	Status  string  `json:"status"`
	TotalGB float64 `json:"total_gb,omitempty"`
}

// portalHardwareDisk deliberately has no model or size field: device_disk
// (migrations/*_hardware_health.sql) stores only device_node, smart_status,
// internal and solid_state — diskutil's physical-disk output the macOS
// collector reads carries no disk model or capacity today. Adding either
// would require a new collector field and a migration, out of scope for this
// ticket (PAT-2141 is platform-only; report if a migration turns out to be
// needed — it does not).
type portalHardwareDisk struct {
	Device      string `json:"device"`
	SMARTStatus string `json:"smart_status,omitempty"`
	Internal    *bool  `json:"internal,omitempty"`
	SolidState  *bool  `json:"solid_state,omitempty"`
}

type portalHardwareDisks struct {
	Status string               `json:"status"`
	Items  []portalHardwareDisk `json:"items"`
}

type portalHardwareVolume struct {
	Mount      string `json:"mount"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedPct    int    `json:"used_pct"`
}

type portalHardwareVolumes struct {
	Status string                 `json:"status"`
	Items  []portalHardwareVolume `json:"items"`
}

type portalHardwareBattery struct {
	Status         string  `json:"status"`
	Present        *bool   `json:"present,omitempty"`
	CycleCount     *int    `json:"cycle_count,omitempty"`
	Condition      *string `json:"condition,omitempty"`
	MaxCapacityPct *int    `json:"max_capacity_pct,omitempty"`
}

// portalDeviceHardware is the customer-facing hardware band (PAT-2141):
// CPU/memory from the same devices.hardware JSONB report.Fetch already
// decodes into rep.Hardware, and battery/disks/volumes from the same
// device_hardware/device_disk/device_storage_volume tables
// fetchHardwareHealth (internal/report/report.go) already reads for the
// admin endpoint and the portal PDF's Hardware health section (PAT-2130) —
// reused via rep.HardwareHealth, no duplicate query.
type portalDeviceHardware struct {
	// Status is a rollup across the five sub-blocks below: "not_collected"
	// only when every sub-block is, "partial" when any sub-block is partial
	// or unavailable, "complete" otherwise. Always inspect the sub-block's
	// own status for the actual claim — this field is a glance-level
	// summary, not a substitute for it.
	Status   string                `json:"status"`
	Evidence portalEvidenceStamp   `json:"evidence"`
	CPU      portalHardwareCPU     `json:"cpu"`
	Memory   portalHardwareMemory  `json:"memory"`
	Disks    portalHardwareDisks   `json:"disks"`
	Volumes  portalHardwareVolumes `json:"volumes"`
	Battery  portalHardwareBattery `json:"battery"`
}

// hardwareSectionStatus resolves one hardware_health sub-section's status.
// The latest payload's explicit collection_status wins (PAT-1720
// complete/partial/unavailable vocabulary, carried on evidence.Sections);
// with no explicit status this run, stored data presence stands in for
// "complete" (an absent collection_status key means the section was
// collected in full, per PAYLOAD_SCHEMA.md's "collection_status sub-object"
// section); "not_collected" only when there is neither an explicit status
// nor any stored data — this device has never reported hardware_health at
// all.
func hardwareSectionStatus(explicit *string, dataPresent bool) string {
	if explicit != nil {
		return *explicit
	}
	if dataPresent {
		return portalCollectionComplete
	}
	return portalCollectionNotCollected
}

func rollupHardwareStatus(statuses ...string) string {
	allNotCollected := true
	anyDegraded := false
	for _, s := range statuses {
		if s != portalCollectionNotCollected {
			allNotCollected = false
		}
		if s == portalCollectionPartial || s == portalCollectionUnavailable {
			anyDegraded = true
		}
	}
	switch {
	case allNotCollected:
		return portalCollectionNotCollected
	case anyDegraded:
		return portalCollectionPartial
	default:
		return portalCollectionComplete
	}
}

// buildPortalDeviceHardware shapes the hardware block from data report.Fetch
// already loaded (rep.Hardware, rep.HardwareHealth) plus the same
// section-scoped evidence envelope (evidence.Sections.HardwareHealth) the
// device-wide evidence already carries.
func buildPortalDeviceHardware(rep report.Report, evidence report.DeviceEvidence) portalDeviceHardware {
	hw := portalDeviceHardware{Evidence: portalEvidenceStampFrom(evidence)}

	// CPU / memory: devices.hardware JSONB has no collection_status of its
	// own — either the whole object was sent (macOS; absent on Windows
	// schema_version=3 today, see report.go's comment on hardwareRaw) or it
	// wasn't.
	if rep.Hardware != nil {
		hw.CPU = portalHardwareCPU{
			Status: portalCollectionComplete,
			Model:  rep.Hardware.CPUModel,
			Cores:  rep.Hardware.CPUCores,
		}
		hw.Memory = portalHardwareMemory{
			Status:  portalCollectionComplete,
			TotalGB: rep.Hardware.RAMgb,
		}
	} else {
		hw.CPU = portalHardwareCPU{Status: portalCollectionNotCollected}
		hw.Memory = portalHardwareMemory{Status: portalCollectionNotCollected}
	}

	var hhSections *report.DeviceEvidenceHardwareHealth
	if evidence.Sections.HardwareHealth != nil {
		hhSections = evidence.Sections.HardwareHealth
	}

	// Disks.
	var diskStatus *string
	if hhSections != nil {
		diskStatus = hhSections.Disks
	}
	diskItems := make([]portalHardwareDisk, 0)
	if rep.HardwareHealth != nil {
		for _, d := range rep.HardwareHealth.Disks {
			var smart string
			if d.SMARTStatus != nil {
				smart = *d.SMARTStatus
			}
			internal := d.Internal
			solid := d.SolidState
			diskItems = append(diskItems, portalHardwareDisk{
				Device:      d.DeviceNode,
				SMARTStatus: smart,
				Internal:    &internal,
				SolidState:  &solid,
			})
		}
	}
	hw.Disks = portalHardwareDisks{
		Status: hardwareSectionStatus(diskStatus, len(diskItems) > 0),
		Items:  diskItems,
	}

	// Storage volumes.
	var storageStatus *string
	if hhSections != nil {
		storageStatus = hhSections.Storage
	}
	volItems := make([]portalHardwareVolume, 0)
	if rep.HardwareHealth != nil {
		for _, v := range rep.HardwareHealth.Volumes {
			volItems = append(volItems, portalHardwareVolume{
				Mount:      v.Mount,
				TotalBytes: v.TotalBytes,
				FreeBytes:  v.FreeBytes,
				UsedPct:    v.UsedPct,
			})
		}
	}
	hw.Volumes = portalHardwareVolumes{
		Status: hardwareSectionStatus(storageStatus, len(volItems) > 0),
		Items:  volItems,
	}

	// Battery.
	var battStatus *string
	if hhSections != nil {
		battStatus = hhSections.Battery
	}
	battDataPresent := rep.HardwareHealth != nil && rep.HardwareHealth.Battery != nil
	hw.Battery = portalHardwareBattery{
		Status: hardwareSectionStatus(battStatus, battDataPresent),
	}
	if battDataPresent {
		b := rep.HardwareHealth.Battery
		present := b.Present
		hw.Battery.Present = &present
		hw.Battery.CycleCount = b.CycleCount
		hw.Battery.Condition = b.Condition
		hw.Battery.MaxCapacityPct = b.MaxCapacityPct
	}

	hw.Status = rollupHardwareStatus(
		hw.CPU.Status, hw.Memory.Status,
		hw.Disks.Status, hw.Volumes.Status, hw.Battery.Status,
	)
	return hw
}
