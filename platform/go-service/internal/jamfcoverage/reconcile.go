package jamfcoverage

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"patched.im/api/internal/devicelist"
)

// Matching rule, per Jamf device and Patched device:
//
//   - serials are normalised and placeholders count as absent, exactly as
//     internal/devicelist does for the customer device list (PAT-2135).
//   - when both carry a real serial they match only if the serials are
//     equal; two different real serials are two different Macs.
//   - otherwise they match if the Jamf UDID equals the device's hardware
//     UUID (on a Mac, Jamf's computer UDID is IOPlatformUUID, which the
//     agent reports as devices.hw_uuid).
//
// Buckets:
//
//  1. Gap: Jamf reports it, Patched has never seen it.
//  2. Not reported by Jamf: a macOS device Patched sees that no Jamf event
//     matches, classified from the agent's own MDM enrolment evidence. This
//     is not a claim the Mac is unmanaged: Jamf's silence is not authority
//     (no backfill, no delete event). Only MDMUnmanaged, read from the
//     agent's own evidence, says "no MDM".
//  3. Covered: both.
//  4. OS not reported: any live device with no reported OS. This
//     diagnostic overlaps Covered when identity matches a Jamf event.
//
// A Jamf device that matches only retired Patched devices is in no bucket
// (counted as RetiredExcluded); retired devices are never in bucket 2.
// Windows devices are never in bucket 2: Jamf Pro manages Macs.
//
// No bucket ever says a Mac was removed or is unmanaged because Jamf went
// quiet. Jamf sends no delete event, so silence is reported as silence.

// SilentAfterDays is when a Jamf device's last event is old enough to say
// "not heard from Jamf in N days" rather than just showing the date.
const SilentAfterDays = 30

// JamfDevice is one jamf_devices row as reconciliation needs it.
type JamfDevice struct {
	ID               int64
	Serial           string
	SerialNormalized string
	UDID             string
	UDIDNormalized   string
	JamfID           *int64
	DeviceName       string
	Model            string
	OSVersion        string
	Enrolled         bool
	DEPAssigned      bool
	LastEventType    string
	FirstReceivedAt  time.Time
	LastEventAt      time.Time
}

// MDMEvidence is what the agent itself reports about MDM enrolment.
type MDMEvidence struct {
	// AppliedConfigOK: the latest applied-configuration snapshot (PAT-1667)
	// that was collected successfully exists. ServerURL is its
	// mdm_server_url ("" when that snapshot saw no enrolment).
	AppliedConfigOK bool
	ServerURL       string
	// EnrolledSignal is the latest mdm_enrolled compliance signal: "Yes",
	// "No", "Unknown" or "" when never reported.
	EnrolledSignal string
}

// PatchedDevice is one devices row as reconciliation needs it.
type PatchedDevice struct {
	ID        string
	Hostname  string
	Serial    string
	HWUUID    string
	OS        string
	OSVersion string
	LastSeen  time.Time
	Retired   bool
	MDM       MDMEvidence
}

// MDM states for bucket 2.
const (
	// MDMOther: the Mac is enrolled with an MDM that is not this tenant's Jamf.
	MDMOther = "other_mdm"
	// MDMJamfNoEvent: the Mac says it is enrolled with the Jamf Pro
	// instance this tenant's events claim, but Jamf has sent no event for it
	// since setup. Never used when no instance is claimed: a Jamf host is
	// then just another MDM (MDMOther, vendor Jamf).
	MDMJamfNoEvent = "jamf_no_event_yet"
	// MDMEnrolledUnidentified: enrolled per the OS, server not reported.
	MDMEnrolledUnidentified = "enrolled_mdm_unidentified"
	// MDMUnmanaged: the agent's evidence says it is enrolled with no MDM.
	MDMUnmanaged = "unmanaged"
	// MDMUnknown: no usable enrolment evidence.
	MDMUnknown = "unknown"
)

// vendorSuffixes maps an MDM server host suffix to a vendor name. Matched on
// a dot boundary. Hosts not listed are reported by host with no vendor.
var vendorSuffixes = []struct{ suffix, vendor string }{
	{"jamfcloud.com", "Jamf"},
	{"manage.microsoft.com", "Microsoft Intune"},
	{"mosyle.com", "Mosyle"},
	{"kandji.io", "Kandji"},
	{"iru.com", "Kandji"},
	{"addigy.com", "Addigy"},
	{"simplemdm.com", "SimpleMDM"},
	{"jumpcloud.com", "JumpCloud"},
	{"hexnode.com", "Hexnode"},
	{"fleetdm.com", "Fleet"},
	{"awmdm.com", "Workspace ONE"},
	{"meraki.com", "Cisco Meraki"},
	{"manageengine.com", "ManageEngine"},
	{"miradore.com", "Miradore"},
}

// VendorOf names the MDM vendor for a server host, or "".
func VendorOf(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, v := range vendorSuffixes {
		if host == v.suffix || strings.HasSuffix(host, "."+v.suffix) {
			return v.vendor
		}
	}
	return ""
}

// Classification is bucket 2's reading of one device's MDM evidence.
type Classification struct {
	State      string
	Vendor     string // "" when not identified
	ServerHost string // "" when not reported
}

// ClassifyMDM reads the agent's evidence. jamfHost is the host of the Jamf
// Pro instance the tenant's events claim ("" when none claimed).
func ClassifyMDM(ev MDMEvidence, jamfHost string) Classification {
	if ev.AppliedConfigOK && strings.TrimSpace(ev.ServerURL) != "" {
		host := HostOf(ev.ServerURL)
		vendor := VendorOf(host)
		if jamfHost != "" && host == jamfHost {
			return Classification{State: MDMJamfNoEvent, Vendor: "Jamf", ServerHost: host}
		}
		return Classification{State: MDMOther, Vendor: vendor, ServerHost: host}
	}
	switch {
	case ev.EnrolledSignal == "Yes":
		return Classification{State: MDMEnrolledUnidentified}
	case ev.AppliedConfigOK, ev.EnrolledSignal == "No":
		// A successful applied-configuration read with no server URL is a
		// real observation of an unenrolled Mac (PAYLOAD_SCHEMA.md,
		// "a genuine empty is still evidence").
		return Classification{State: MDMUnmanaged}
	}
	return Classification{State: MDMUnknown}
}

// Pair is one bucket 3 match.
type Pair struct {
	Jamf       JamfDevice
	Device     PatchedDevice
	MatchBasis string // "serial" | "udid"
}

// NotReported is one bucket 2 row.
type NotReported struct {
	Device PatchedDevice
	MDM    Classification
}

// Result is the reconciliation.
type Result struct {
	Gap           []JamfDevice    // bucket 1, by device name then id
	NotReported   []NotReported   // bucket 2, by hostname then id
	Covered       []Pair          // bucket 3, by hostname then device id
	OSNotReported []PatchedDevice // bucket 4, by hostname then id
	// RetiredExcluded is the number of Jamf devices that match only retired
	// Patched devices.
	RetiredExcluded int
	// NonMacExcluded is the number of live known non-macOS Patched devices left
	// out of bucket 2.
	NonMacExcluded int
}

func isMac(os string) bool { return strings.EqualFold(strings.TrimSpace(os), "macos") }

// Reconcile applies the matching rule.
func Reconcile(jamf []JamfDevice, devices []PatchedDevice, jamfHost string) Result {
	bySerial := map[string][]int{}
	byUUID := map[string][]int{}
	serials := make([]string, len(devices))
	for i, d := range devices {
		serials[i] = devicelist.NormalizeSerial(d.Serial)
		if serials[i] != "" {
			bySerial[serials[i]] = append(bySerial[serials[i]], i)
		}
		if u := NormalizeUDID(d.HWUUID); u != "" {
			byUUID[u] = append(byUUID[u], i)
		}
	}
	var res Result
	res.Gap, res.NotReported, res.Covered = []JamfDevice{}, []NotReported{}, []Pair{}
	res.OSNotReported = []PatchedDevice{}
	matched := make([]bool, len(devices))
	for _, j := range jamf {
		type cand struct {
			i     int
			basis string
		}
		var cands []cand
		if j.SerialNormalized != "" {
			for _, i := range bySerial[j.SerialNormalized] {
				cands = append(cands, cand{i, "serial"})
			}
		}
		if len(cands) == 0 && j.UDIDNormalized != "" {
			for _, i := range byUUID[j.UDIDNormalized] {
				// Two real serials that differ are two Macs, whatever the UUID says.
				if j.SerialNormalized != "" && serials[i] != "" {
					continue
				}
				cands = append(cands, cand{i, "udid"})
			}
		}
		live := false
		for _, c := range cands {
			matched[c.i] = true
			if devices[c.i].Retired {
				continue
			}
			live = true
			res.Covered = append(res.Covered, Pair{Jamf: j, Device: devices[c.i], MatchBasis: c.basis})
		}
		switch {
		case live:
		case len(cands) > 0:
			res.RetiredExcluded++
		default:
			res.Gap = append(res.Gap, j)
		}
	}
	for i, d := range devices {
		if d.Retired {
			continue
		}
		if strings.TrimSpace(d.OS) == "" {
			res.OSNotReported = append(res.OSNotReported, d)
			continue
		}
		if matched[i] {
			continue
		}
		if !isMac(d.OS) {
			res.NonMacExcluded++
			continue
		}
		res.NotReported = append(res.NotReported, NotReported{Device: d, MDM: ClassifyMDM(d.MDM, jamfHost)})
	}
	sort.SliceStable(res.Gap, func(a, b int) bool {
		na, nb := strings.ToLower(res.Gap[a].DeviceName), strings.ToLower(res.Gap[b].DeviceName)
		if na != nb {
			return na < nb
		}
		return res.Gap[a].ID < res.Gap[b].ID
	})
	sort.SliceStable(res.NotReported, func(a, b int) bool {
		return lessDevice(res.NotReported[a].Device, res.NotReported[b].Device)
	})
	sort.SliceStable(res.OSNotReported, func(a, b int) bool {
		return lessDevice(res.OSNotReported[a], res.OSNotReported[b])
	})
	sort.SliceStable(res.Covered, func(a, b int) bool {
		if res.Covered[a].Device.ID == res.Covered[b].Device.ID {
			return res.Covered[a].Jamf.ID < res.Covered[b].Jamf.ID
		}
		return lessDevice(res.Covered[a].Device, res.Covered[b].Device)
	})
	return res
}

func lessDevice(a, b PatchedDevice) bool {
	ha, hb := strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)
	if ha != hb {
		return ha < hb
	}
	return a.ID < b.ID
}

// DaysSince is whole days from t to now, never negative.
func DaysSince(t, now time.Time) int {
	if t.IsZero() || !now.After(t) {
		return 0
	}
	return int(now.Sub(t) / (24 * time.Hour))
}

// SilenceNote is the wording for a Jamf device's last event: "" while it is
// recent, otherwise "not heard from Jamf in N days". Never "removed" or
// "unmanaged": Jamf sends no delete event.
func SilenceNote(lastEvent, now time.Time) string {
	d := DaysSince(lastEvent, now)
	if d < SilentAfterDays {
		return ""
	}
	return "not heard from Jamf in " + strconv.Itoa(d) + " days"
}

// EnrolledSignal picks the agent's MDM enrolment answer from the neutral
// mdm_enrolled signal ("Yes" | "No" | "Unknown", PAT-1752) and, only when
// that is absent, the deprecated macOS mdm_enrolment value
// ("dep=Yes mdm=Yes"), read by its exact mdm= token as the evaluator's
// PAT-1752 bridge does. Anything else gives "Unknown"; nothing gives "".
func EnrolledSignal(neutral, legacy *string) string {
	if neutral != nil {
		switch v := strings.TrimSpace(*neutral); v {
		case "Yes", "No":
			return v
		default:
			return "Unknown"
		}
	}
	if legacy == nil {
		return ""
	}
	result, n := "", 0
	for _, f := range strings.Fields(*legacy) {
		if !strings.HasPrefix(f, "mdm=") {
			continue
		}
		n++
		result = strings.TrimPrefix(f, "mdm=")
	}
	if n != 1 || (result != "Yes" && result != "No") {
		return "Unknown"
	}
	return result
}
