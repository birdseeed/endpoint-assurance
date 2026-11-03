// Package jamfcoverage parses Jamf Pro webhook payloads down to device
// identifiers and reconciles the Macs Jamf reports against the devices
// Patched has seen (PAT-2145). Pure functions only; the handlers fetch and
// store the rows.
//
// Patched never holds a Jamf API credential (PAT-1666). The customer's Jamf
// Pro pushes webhooks; this package decides what of each payload is kept.
//
// # What is kept
//
// Identifiers only: serial number, UDID, Jamf ID (jssID), device name, model,
// OS version, the event type and the event time. Everything else in the
// payload is dropped here, before anything is stored or logged. That is an
// allowlist, not a denylist: a field Jamf adds in a future release is dropped
// by default. PersonalFields lists the documented personal fields purely so
// the tests can plant them and prove they never reach the database or logs.
//
// # Payload shape (Jamf Pro developer docs, webhooks, checked 2026-09-26)
//
//	{"webhook": {"eventTimestamp": <epoch ms>, "id": <int>, "name": "...", "webhookEvent": "<type>"},
//	 "event":   {...}}
//
// ComputerAdded and ComputerInventoryCompleted carry the computer fields
// directly under "event"; ComputerCheckIn nests them under "event.computer"
// (with "trigger" and "username" beside it); DeviceAddedToDEP carries
// serialNumber and model plus DEP fields. Jamf payloads carry no Jamf Pro
// server URL, so the instance a tenant's events claim comes from a header
// (see InstanceHeader), not the body.
//
// # Strictness
//
// Keys are matched exactly (Go's encoding/json folds case when decoding into
// structs, the PAT-2021 trap, so nothing here decodes into a struct).
// Unknown top-level or "webhook" keys, a wrong type on a kept field, a
// missing or unsupported event type, or an event with no usable identifier
// are refused. Unknown keys inside "event" are dropped, not refused, because
// they are never kept and Jamf adds event fields between releases.
package jamfcoverage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"patched.im/api/internal/devicelist"
)

// Event types.
const (
	EventComputerAdded              = "ComputerAdded"
	EventComputerInventoryCompleted = "ComputerInventoryCompleted"
	EventComputerCheckIn            = "ComputerCheckIn"
	EventDeviceAddedToDEP           = "DeviceAddedToDEP"
)

// SupportedEvents lists every event type the endpoint understands, in the
// order the setup page shows them. ComputerCheckIn is optional per tenant.
var SupportedEvents = []string{EventComputerAdded, EventComputerInventoryCompleted, EventDeviceAddedToDEP, EventComputerCheckIn}

// IsOptionalEvent reports an event type the tenant must opt in to.
func IsOptionalEvent(t string) bool { return t == EventComputerCheckIn }

// InstanceHeader is the header the setup page tells the admin to add to the
// Jamf webhook's Header Authentication JSON, naming their Jamf Pro URL.
const InstanceHeader = "X-Patched-Jamf-Instance"

// PersonalFields are the documented personal or location fields in Jamf Pro
// computer and DEP webhook payloads. None of them is ever kept (Parse keeps
// an allowlist), and this list exists only so tests can plant every one.
var PersonalFields = []string{
	"emailAddress", "username", "realName", "phone", "position", "building",
	"department", "room", "ipAddress", "reportedIpAddress", "macAddress",
	"alternateMacAddress", "userDirectoryID", "assetTag", "description",
}

// Reject reasons (also the jamf_webhook_connectors.last_rejected_reason
// values).
const (
	ReasonInvalidPayload     = "invalid_payload"
	ReasonMissingIdentifier  = "missing_identifier"
	ReasonUnsupportedEvent   = "unsupported_event"
	ReasonEventNotSubscribed = "event_not_subscribed"
	ReasonInvalidInstanceURL = "invalid_instance_url"
	ReasonDeviceCapReached   = "device_cap_reached"
)

// ParseError is a refused payload. Message never quotes payload content.
type ParseError struct {
	Reason  string
	Message string
}

func (e *ParseError) Error() string { return e.Reason + ": " + e.Message }

func perr(reason, format string, a ...any) *ParseError {
	return &ParseError{Reason: reason, Message: fmt.Sprintf(format, a...)}
}

// Event is what Patched keeps of one webhook: identifiers only.
type Event struct {
	Type string
	// Time is Jamf's eventTimestamp, or the zero time when absent.
	Time time.Time

	Serial           string // trimmed as sent; "" when absent
	SerialNormalized string // "" for a placeholder serial
	UDID             string // trimmed as sent
	UDIDNormalized   string // upper-case UUID text; "" unless UUID-shaped
	JamfID           *int64
	DeviceName       string
	Model            string
	OSVersion        string
}

var uuidRe = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`)

// NormalizeUDID returns the upper-case UUID text of a UDID, or "" when it is
// not UUID-shaped (or is all zeros).
func NormalizeUDID(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	if !uuidRe.MatchString(u) || strings.Trim(u, "0-") == "" {
		return ""
	}
	return u
}

var (
	allowedTop     = map[string]bool{"webhook": true, "event": true}
	allowedWebhook = map[string]bool{"eventTimestamp": true, "id": true, "name": true, "webhookEvent": true}
)

func objectOf(raw json.RawMessage, what string) (map[string]json.RawMessage, *ParseError) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return nil, perr(ReasonInvalidPayload, "%s must be a JSON object", what)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(t, &m); err != nil {
		return nil, perr(ReasonInvalidPayload, "%s is not a valid JSON object", what)
	}
	return m, nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// optString reads an optional string field. Absent or null gives "".
func optString(m map[string]json.RawMessage, key, what string) (string, *ParseError) {
	raw, ok := m[key]
	if !ok || isNull(raw) {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", perr(ReasonInvalidPayload, "%s.%s must be a string", what, key)
	}
	v, bad := devicelist.CheckField(s)
	if bad != "" {
		return "", perr(ReasonInvalidPayload, "%s.%s %s", what, key, bad)
	}
	return v, nil
}

// optPositiveInt reads an optional positive integer field.
func optPositiveInt(m map[string]json.RawMessage, key, what string) (*int64, *ParseError) {
	raw, ok := m[key]
	if !ok || isNull(raw) {
		return nil, nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return nil, perr(ReasonInvalidPayload, "%s.%s must be a number", what, key)
	}
	v, err := n.Int64()
	if err != nil || v < 0 {
		return nil, perr(ReasonInvalidPayload, "%s.%s must be a non-negative integer", what, key)
	}
	if v == 0 {
		return nil, nil
	}
	return &v, nil
}

// Parse validates one webhook body and keeps identifiers only.
func Parse(body []byte) (Event, *ParseError) {
	var ev Event
	top, pe := objectOf(body, "body")
	if pe != nil {
		return ev, pe
	}
	for k := range top {
		if !allowedTop[k] {
			return ev, perr(ReasonInvalidPayload, "unknown top-level key")
		}
	}
	whRaw, ok := top["webhook"]
	if !ok {
		return ev, perr(ReasonInvalidPayload, "webhook is required")
	}
	wh, pe := objectOf(whRaw, "webhook")
	if pe != nil {
		return ev, pe
	}
	for k := range wh {
		if !allowedWebhook[k] {
			return ev, perr(ReasonInvalidPayload, "unknown key in webhook")
		}
	}
	var typ string
	if raw, ok := wh["webhookEvent"]; !ok || json.Unmarshal(raw, &typ) != nil || typ == "" {
		return ev, perr(ReasonInvalidPayload, "webhook.webhookEvent must be a non-empty string")
	}
	switch typ {
	case EventComputerAdded, EventComputerInventoryCompleted, EventComputerCheckIn, EventDeviceAddedToDEP:
	default:
		return ev, perr(ReasonUnsupportedEvent, "this endpoint does not accept that event type")
	}
	ev.Type = typ
	if _, pe := optPositiveInt(wh, "id", "webhook"); pe != nil {
		return ev, pe
	}
	if _, pe := optString(wh, "name", "webhook"); pe != nil {
		return ev, pe
	}
	if raw, ok := wh["eventTimestamp"]; ok && !isNull(raw) {
		var f float64
		if err := json.Unmarshal(raw, &f); err != nil || f < 0 || math.IsInf(f, 0) || math.IsNaN(f) || f > 1e15 {
			return ev, perr(ReasonInvalidPayload, "webhook.eventTimestamp must be epoch milliseconds")
		}
		if f > 0 {
			ev.Time = time.UnixMilli(int64(f)).UTC()
		}
	}

	evRaw, ok := top["event"]
	if !ok {
		return ev, perr(ReasonInvalidPayload, "event is required")
	}
	e, pe := objectOf(evRaw, "event")
	if pe != nil {
		return ev, pe
	}
	what := "event"
	if typ == EventComputerCheckIn {
		cRaw, ok := e["computer"]
		if !ok {
			return ev, perr(ReasonInvalidPayload, "event.computer is required for ComputerCheckIn")
		}
		if e, pe = objectOf(cRaw, "event.computer"); pe != nil {
			return ev, pe
		}
		what = "event.computer"
	}

	var serial, udid string
	if serial, pe = optString(e, "serialNumber", what); pe != nil {
		return ev, pe
	}
	if ev.Model, pe = optString(e, "model", what); pe != nil {
		return ev, pe
	}
	if typ != EventDeviceAddedToDEP {
		if udid, pe = optString(e, "udid", what); pe != nil {
			return ev, pe
		}
		if ev.JamfID, pe = optPositiveInt(e, "jssID", what); pe != nil {
			return ev, pe
		}
		if ev.DeviceName, pe = optString(e, "deviceName", what); pe != nil {
			return ev, pe
		}
		if ev.OSVersion, pe = optString(e, "osVersion", what); pe != nil {
			return ev, pe
		}
	}
	ev.Serial, ev.SerialNormalized = serial, devicelist.NormalizeSerial(serial)
	if ev.SerialNormalized != "" && !isAlnum(ev.SerialNormalized) {
		// Apple serial numbers are letters and digits only.
		return ev, perr(ReasonInvalidPayload, "%s.serialNumber must be letters and digits only", what)
	}
	ev.UDID, ev.UDIDNormalized = udid, NormalizeUDID(udid)
	if ev.SerialNormalized == "" {
		ev.Serial = strings.TrimSpace(serial)
	}
	if ev.SerialNormalized == "" && ev.UDIDNormalized == "" && ev.JamfID == nil {
		return ev, perr(ReasonMissingIdentifier, "the event carries no usable serial number, UDID or Jamf ID")
	}
	return ev, nil
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ErrInvalidInstanceURL is returned for a malformed instance header.
var ErrInvalidInstanceURL = errors.New("the Jamf instance header must be an https URL")

// NormalizeInstanceURL reduces a claimed Jamf Pro URL to https://host[:port],
// lower case. "" in gives "" out (no claim).
func NormalizeInstanceURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > 300 || devicelist.HasControlChars(s) {
		return "", ErrInvalidInstanceURL
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil || u.Hostname() == "" {
		return "", ErrInvalidInstanceURL
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// HostOf returns the lower-case host name (no port) of a URL, or "".
func HostOf(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
