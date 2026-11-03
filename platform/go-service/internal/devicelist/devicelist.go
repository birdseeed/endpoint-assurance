// Package devicelist validates a customer's uploaded device list and
// reconciles it against the devices Patched has seen (PAT-2135). Pure
// functions only; the portal handlers fetch and store the rows.
//
// Matching rule, per list entry and device:
//
//   - serials are normalised (trimmed, upper case) and a placeholder serial
//     ("To be filled by O.E.M.", "0", all zeros, under 4 characters and the
//     rest of IsPlaceholderSerial) counts as no serial, on both sides.
//   - when the entry and the device both carry a real serial, they match
//     only if the serials are equal. The hostname is not consulted: two
//     different serials are two different machines even if they share a
//     name.
//   - otherwise they match if the normalised hostnames are equal: trimmed,
//     lower case, trailing dots removed, then one trailing ".local" removed
//     (and any dots before it). "DESKTOP-ROBWIN" (a Windows NetBIOS name),
//     "desktop-robwin" and "Desktop-RobWin." all match; "mac-01.local"
//     matches "mac-01".
//   - last, for an entry and a device still unmatched: when exactly one of
//     the two hostnames has a dot, they match on the first DNS label
//     ("pc01.corp.example.com" and "pc01"), but only if that label is
//     unique among the unmatched entries and among the unmatched devices.
//     A collision leaves all of them unmatched. Two fully qualified names
//     never match through this ("pc01.a.com" is not "pc01.b.com").
//
// Patched is never the authority on what devices exist. An entry that
// matches no device is reported as on the list but never seen; nothing here
// treats its absence as proof it is gone.
package devicelist

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxEntries caps one upload.
	MaxEntries = 10000
	// MaxFieldChars caps a hostname, a serial and the filename, in characters.
	MaxFieldChars = 255
)

// NormalizeHostname applies the hostname matching rule. "" means no usable
// hostname.
func NormalizeHostname(s string) string {
	h := strings.ToLower(strings.TrimSpace(s))
	h = strings.TrimRight(h, ".")
	if strings.HasSuffix(h, ".local") {
		h = strings.TrimRight(strings.TrimSuffix(h, ".local"), ".")
	}
	return h
}

// Placeholder serials are treated as no serial at all, on both the list
// side and the device side, so matching falls back to the hostname. Firmware
// and virtual machines commonly report these instead of a real serial, and
// letting one decide a match would either pair unrelated machines or block a
// real hostname match. Compared lower case, after trimming.
var placeholderSerials = map[string]bool{
	"to be filled by o.e.m.": true,
	"default string":         true,
	"system serial number":   true,
	"none":                   true,
	"n/a":                    true,
	"not specified":          true,
	"not applicable":         true,
	"0":                      true,
	"123456789":              true,
}

// minSerialChars: anything shorter after trimming is not a usable serial.
const minSerialChars = 4

// IsPlaceholderSerial reports a serial that must not be used for matching:
// empty, a known placeholder, shorter than minSerialChars, or one character
// repeated (all zeros included).
func IsPlaceholderSerial(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if utf8.RuneCountInString(t) < minSerialChars || placeholderSerials[t] {
		return true
	}
	first, _ := utf8.DecodeRuneInString(t)
	return strings.Trim(t, string(first)) == ""
}

// NormalizeSerial applies the serial matching rule: trimmed, upper case, and
// "" for a placeholder (see IsPlaceholderSerial).
func NormalizeSerial(s string) string {
	if IsPlaceholderSerial(s) {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(s))
}

// firstLabel is the part of a normalised hostname before its first dot.
func firstLabel(h string) string {
	if i := strings.IndexByte(h, '.'); i >= 0 {
		return h[:i]
	}
	return h
}

// InputEntry is one entry as the portal sends it.
type InputEntry struct {
	Hostname *string `json:"hostname"`
	Serial   *string `json:"serial"`
}

// Entry is a validated, de-duplicated list entry.
type Entry struct {
	// ID is the entry's stable device_list_entries.id (PAT-2271). Zero for
	// an entry that has not been persisted yet (Validate's output, before
	// PUT inserts it); the read path (GET) always populates it.
	ID int64
	// Position is the index of the entry's first occurrence in the upload.
	Position           int
	Hostname           string // trimmed as sent; "" when absent
	HostnameNormalized string
	Serial             string // trimmed as sent; "" when absent
	SerialNormalized   string
}

// EntryError names the first bad entry.
type EntryError struct {
	Index   int
	Code    string
	Message string
}

func (e *EntryError) Error() string { return fmt.Sprintf("entries[%d]: %s", e.Index, e.Message) }

// HasControlChars reports a control character (Unicode Cc, including tab,
// CR and LF) or a format character (Unicode Cf: zero-width space and joiner,
// bidirectional overrides, the BOM, soft hyphen), which can make two values
// that look identical compare unequal or display misleadingly.
func HasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// CheckField validates one free-text field: valid UTF-8, no control or
// format characters (HasControlChars), at most MaxFieldChars characters
// after trimming.
func CheckField(s string) (string, string) {
	t := strings.TrimSpace(s)
	switch {
	case !utf8.ValidString(t):
		return "", "is not valid UTF-8"
	case HasControlChars(t):
		return "", "contains control characters"
	case utf8.RuneCountInString(t) > MaxFieldChars:
		return "", fmt.Sprintf("is longer than %d characters", MaxFieldChars)
	}
	return t, ""
}

// Validate checks every entry and collapses duplicates (same normalised
// hostname and serial). It returns the first bad entry, by index, as an
// *EntryError. The caller checks the entry count cap before calling.
func Validate(in []InputEntry) ([]Entry, int, *EntryError) {
	out := make([]Entry, 0, len(in))
	seen := make(map[[2]string]bool, len(in))
	dups := 0
	for i, it := range in {
		var e Entry
		e.Position = i
		if it.Hostname != nil {
			h, bad := CheckField(*it.Hostname)
			if bad != "" {
				return nil, 0, &EntryError{Index: i, Code: "invalid_hostname", Message: "hostname " + bad}
			}
			e.Hostname, e.HostnameNormalized = h, NormalizeHostname(h)
		}
		if it.Serial != nil {
			s, bad := CheckField(*it.Serial)
			if bad != "" {
				return nil, 0, &EntryError{Index: i, Code: "invalid_serial", Message: "serial " + bad}
			}
			e.Serial, e.SerialNormalized = s, NormalizeSerial(s)
		}
		if e.HostnameNormalized == "" && e.SerialNormalized == "" {
			return nil, 0, &EntryError{Index: i, Code: "missing_identifier",
				Message: "a hostname is required unless a real serial number is given (placeholder serials do not count)"}
		}
		if e.HostnameNormalized == "" {
			e.Hostname = ""
		}
		key := [2]string{e.HostnameNormalized, e.SerialNormalized}
		if seen[key] {
			dups++
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out, dups, nil
}

// Device is one device Patched has seen, as reconciliation needs it.
type Device struct {
	ID       string
	Hostname string
	Serial   string
	Retired  bool
}

// Result is the reconciliation of a list against the seen devices.
type Result struct {
	// OnListNeverSeen are entries that match no device, in upload order.
	OnListNeverSeen []Entry
	// SeenNotOnList are devices no entry matches, retired devices excluded,
	// sorted by hostname then id.
	SeenNotOnList []Device
	// Matched is one row per matched entry (PAT-2271), always the same
	// length as MatchedCount: the entry paired with the device it matched.
	// When an entry's candidates include more than one device (a serial
	// match and an unrelated hostname match, say), a live device is
	// reported over a retired one, matching the live/retired distinction
	// MatchedRetiredCount already makes; otherwise the first candidate.
	Matched []MatchedPair
	// MatchedCount is the number of entries that match at least one device
	// (a retired device included).
	MatchedCount int
	// MatchedRetiredCount is how many of those match only retired devices.
	MatchedRetiredCount int
}

// MatchedPair is one uploaded entry paired with the device it matched.
type MatchedPair struct {
	Entry  Entry
	Device Device
}

func matches(e Entry, dSerial, dHost string) bool {
	if e.SerialNormalized != "" && dSerial != "" {
		return e.SerialNormalized == dSerial
	}
	return e.HostnameNormalized != "" && e.HostnameNormalized == dHost
}

// Reconcile applies the matching rule in the package doc.
func Reconcile(entries []Entry, devices []Device) Result {
	type norm struct {
		serial, host string
	}
	bySerial := map[string][]int{}
	byHost := map[string][]int{}
	ns := make([]norm, len(devices))
	for i, d := range devices {
		ns[i] = norm{NormalizeSerial(d.Serial), NormalizeHostname(d.Hostname)}
		if ns[i].serial != "" {
			bySerial[ns[i].serial] = append(bySerial[ns[i].serial], i)
		}
		if ns[i].host != "" {
			byHost[ns[i].host] = append(byHost[ns[i].host], i)
		}
	}

	var res Result
	res.OnListNeverSeen = []Entry{}
	res.Matched = []MatchedPair{}
	matchedDevice := make([]bool, len(devices))
	matchedEntry := make([]bool, len(entries))
	record := func(ei int, live bool) {
		matchedEntry[ei] = true
		res.MatchedCount++
		if !live {
			res.MatchedRetiredCount++
		}
	}
	for ei, e := range entries {
		var cand []int
		if e.SerialNormalized != "" {
			cand = append(cand, bySerial[e.SerialNormalized]...)
		}
		if e.HostnameNormalized != "" {
			cand = append(cand, byHost[e.HostnameNormalized]...)
		}
		hit, hitLive := false, false
		matchedIdx := -1
		for _, i := range cand {
			if !matches(e, ns[i].serial, ns[i].host) {
				continue
			}
			hit = true
			matchedDevice[i] = true
			live := !devices[i].Retired
			if live {
				hitLive = true
			}
			// Report a live device over a retired one when an entry's
			// candidates include both; otherwise the first candidate.
			if matchedIdx == -1 || (live && devices[matchedIdx].Retired) {
				matchedIdx = i
			}
		}
		if hit {
			record(ei, hitLive)
			res.Matched = append(res.Matched, MatchedPair{Entry: e, Device: devices[matchedIdx]})
		}
	}

	// First-label fallback: an entry and a device still unmatched whose
	// hostnames share a first DNS label, where exactly one of the two is
	// fully qualified ("pc01.corp.example.com" and "pc01"). Only when that
	// label is unique among the unmatched entries and among the unmatched
	// devices; a collision leaves every party unmatched rather than guess.
	// Two real serials that differ still rule a pair out.
	entryByLabel := map[string][]int{}
	for ei, e := range entries {
		if !matchedEntry[ei] && e.HostnameNormalized != "" {
			l := firstLabel(e.HostnameNormalized)
			entryByLabel[l] = append(entryByLabel[l], ei)
		}
	}
	deviceByLabel := map[string][]int{}
	for i := range devices {
		if !matchedDevice[i] && ns[i].host != "" {
			l := firstLabel(ns[i].host)
			deviceByLabel[l] = append(deviceByLabel[l], i)
		}
	}
	for l, eis := range entryByLabel {
		dis := deviceByLabel[l]
		if l == "" || len(eis) != 1 || len(dis) != 1 {
			continue
		}
		e, i := entries[eis[0]], dis[0]
		eDot, dDot := strings.Contains(e.HostnameNormalized, "."), strings.Contains(ns[i].host, ".")
		if eDot == dDot {
			continue
		}
		if e.SerialNormalized != "" && ns[i].serial != "" {
			continue
		}
		matchedDevice[i] = true
		record(eis[0], !devices[i].Retired)
		res.Matched = append(res.Matched, MatchedPair{Entry: e, Device: devices[i]})
	}
	for ei, e := range entries {
		if !matchedEntry[ei] {
			res.OnListNeverSeen = append(res.OnListNeverSeen, e)
		}
	}

	res.SeenNotOnList = []Device{}
	for i, d := range devices {
		if matchedDevice[i] || d.Retired {
			continue
		}
		res.SeenNotOnList = append(res.SeenNotOnList, d)
	}
	sort.SliceStable(res.SeenNotOnList, func(a, b int) bool {
		ha, hb := strings.ToLower(res.SeenNotOnList[a].Hostname), strings.ToLower(res.SeenNotOnList[b].Hostname)
		if ha != hb {
			return ha < hb
		}
		return res.SeenNotOnList[a].ID < res.SeenNotOnList[b].ID
	})
	return res
}
