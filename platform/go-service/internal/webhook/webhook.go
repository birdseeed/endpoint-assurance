// Package webhook implements outbound webhook dispatch for tenant integrations (PAT-134).
//
// v1 event types: score.changed, vulnerability.discovered,
// software.unapproved_detected (PAT-2009)
//
// Each tenant may configure multiple webhook endpoints. When an event fires,
// every enabled endpoint subscribed to that event type receives a signed POST
// request. Delivery is recorded in webhook_deliveries. Failed deliveries are
// retried with exponential backoff for up to 24 h.
//
// Payload wire format:
//
//	{
//	  "event_type":     "score.changed",
//	  "tenant_id":      "<uuid>",
//	  "timestamp":      "<RFC3339>",
//	  "data":           { ... event-specific ... },
//	  "dashboard_link": "https://dashboard.patched.im/tenants/<id>"  // omitted when empty
//	}
//
// The header X-Patched-Signature carries "sha256=<hex>" computed as
// HMAC-SHA256(secret_bytes, body), where secret_bytes is the UTF-8 encoding
// of the hex secret string shown to the user at creation time. This matches
// the GitHub / Stripe webhook signature convention.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// EventKind is a webhook event type string.
type EventKind string

const (
	// EventScoreChanged fires after a device's compliance evaluations are updated.
	EventScoreChanged EventKind = "score.changed"
	// EventVulnerabilityDiscovered fires when new CVE findings are added for a device.
	EventVulnerabilityDiscovered EventKind = "vulnerability.discovered"
	// EventTestPing fires when the staff console sends a manual test.
	EventTestPing EventKind = "test.ping"
	// EventSoftwareUnapprovedDetected (PAT-2009) fires when a product the
	// tenant has marked Unapproved is present on a device: once when the mark
	// is made (listing every device it was on), and once per device newly
	// observed with it afterwards. It is a presence claim from endpoint
	// inventory, never a removal instruction.
	EventSoftwareUnapprovedDetected EventKind = "software.unapproved_detected"
	// EventSoftwareFirstSeen (PAT-2009) is the daily new-software digest. It is
	// delivered through PAT-1888 notification channels only, and only when the
	// tenant has turned the new software notification on.
	EventSoftwareFirstSeen EventKind = "software.first_seen"
	// EventAIToolingFirstSeen (PAT-2205) is an independent, opt-in daily
	// digest of newly observed named AI-tooling identities.
	EventAIToolingFirstSeen EventKind = "ai_tooling.first_seen"

	// PAT-1888 finding notification events. Each one maps 1:1 onto a transition
	// the finding lifecycle already produces, so none of them can be raised
	// without a lifecycle event on record to back it.
	//
	// EventFindingOpened fires on the first observed failure of a finding.
	EventFindingOpened EventKind = "finding.opened"
	// EventFindingRecurred fires when a previously verified-fixed finding fails again.
	EventFindingRecurred EventKind = "finding.recurred"
	// EventEvidenceStale fires when verification was requested but the evidence
	// needed to judge it is missing or too old. It never means the finding cleared.
	EventEvidenceStale EventKind = "evidence.stale"
	// EventVerificationPassed fires when fresh, authoritative evidence shows the
	// finding now passes.
	EventVerificationPassed EventKind = "verification.passed"
	// EventVerificationFailed fires when fresh, authoritative evidence shows the
	// finding still fails after a customer action.
	EventVerificationFailed EventKind = "verification.failed"
)

// KnownEvents is the set of event types a legacy PAT-134 tenant_webhooks row may
// subscribe to (excludes test.ping).
//
// It is deliberately NOT widened with the PAT-1888 finding events: nothing fires
// those through tenant_webhooks, so accepting a subscription to one there would
// create a configuration that looks healthy and silently never delivers. Finding
// events are subscribed to on a notification channel instead
// (internal/notifications), which is the code path that actually raises them.
var KnownEvents = []string{
	string(EventScoreChanged),
	string(EventVulnerabilityDiscovered),
	string(EventSoftwareUnapprovedDetected),
}

// FindingEvents is the PAT-1888 event catalogue: the event types a tenant
// notification channel may subscribe to (excludes test.ping, which every channel
// can always be sent explicitly).
var FindingEvents = []string{
	string(EventFindingOpened),
	string(EventFindingRecurred),
	string(EventEvidenceStale),
	string(EventVerificationPassed),
	string(EventVerificationFailed),
}

// SoftwareChannelEvents (PAT-2009) are the non-finding events a PAT-1888
// notification channel may also subscribe to. Kept apart from FindingEvents
// because they are not lifecycle transitions.
var SoftwareChannelEvents = []string{
	string(EventSoftwareFirstSeen),
	string(EventAIToolingFirstSeen),
}

// ChannelEvents is every event type a PAT-1888 notification channel may
// subscribe to.
func ChannelEvents() []string {
	out := make([]string, 0, len(FindingEvents)+len(SoftwareChannelEvents))
	out = append(out, FindingEvents...)
	return append(out, SoftwareChannelEvents...)
}

// Hook is a tenant webhook configuration (secret is omitted; use store.go to load).
type Hook struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Delivery is one delivery-attempt record from webhook_deliveries.
type Delivery struct {
	ID             int64      `json:"id"`
	WebhookID      string     `json:"webhook_id"`
	EventType      string     `json:"event_type"`
	ResponseStatus *int       `json:"response_status"`
	AttemptCount   int        `json:"attempt_count"`
	LastAttemptAt  *time.Time `json:"last_attempt_at"`
	SucceededAt    *time.Time `json:"succeeded_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Payload is the JSON body posted to the customer's webhook endpoint.
type Payload struct {
	EventType     string    `json:"event_type"`
	TenantID      string    `json:"tenant_id"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
	DashboardLink string    `json:"dashboard_link,omitempty"`
}

// ScoreChangedData is the data block for a score.changed event.
type ScoreChangedData struct {
	DeviceID      string  `json:"device_id"`
	Hostname      string  `json:"hostname"`
	PassCount     int     `json:"pass_count"`
	FailCount     int     `json:"fail_count"`
	TotalCount    int     `json:"total_count"`
	CompliancePct float64 `json:"compliance_pct"`
}

// VulnCVE is one CVE entry inside a vulnerability.discovered event.
type VulnCVE struct {
	CVEID    string   `json:"cve_id"`
	Severity string   `json:"severity"`
	Score    *float64 `json:"cvss_v3_score"`
	AppName  string   `json:"app_name"`
}

// VulnDiscoveredData is the data block for a vulnerability.discovered event.
type VulnDiscoveredData struct {
	DeviceID string    `json:"device_id"`
	Hostname string    `json:"hostname"`
	NewCVEs  []VulnCVE `json:"new_cves"`
}

// Sign returns the HMAC-SHA256 signature of body using secret, formatted as
// "sha256=<hex>". This is the value placed in X-Patched-Signature.
//
// secret is the raw bytes of the secret string (the 64-char hex string given
// to the customer at webhook creation time, treated as UTF-8 bytes).
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// SignedTimestampMaterial returns the exact bytes signed by SignWithTimestamp:
// the decimal Unix second count, a full stop, then the request body.
//
// Exported so a receiver's verification recipe and our signer cannot drift, and
// so tests assert against one definition rather than two.
func SignedTimestampMaterial(unixSeconds int64, body []byte) []byte {
	prefix := strconv.FormatInt(unixSeconds, 10) + "."
	material := make([]byte, 0, len(prefix)+len(body))
	material = append(material, prefix...)
	material = append(material, body...)
	return material
}

// SignWithTimestamp returns "sha256=<hex>" over "<unix seconds>.<body>".
//
// Binding the timestamp into the signed material (rather than relying on the
// timestamp field inside the JSON body) lets a receiver reject a replayed
// delivery by comparing X-Patched-Timestamp against its own clock before it
// parses anything, and stops an attacker re-dating a captured delivery without
// invalidating the signature.
//
// Used by PAT-1888 notification channels. The PAT-134 tenant_webhooks path keeps
// using Sign, unchanged, so existing receivers do not break.
func SignWithTimestamp(secret []byte, unixSeconds int64, body []byte) string {
	return Sign(secret, SignedTimestampMaterial(unixSeconds, body))
}

// maxRetryAge is how long we retry before giving up.
const maxRetryAge = 24 * time.Hour

// maxAttempts caps the number of attempts (after creation + 7 retries ≈ 31 h at max backoff).
const maxAttempts = 8

// RetryBackoff returns the delay before attempt number attempt (1-indexed).
// Uses 2^(attempt-1) * 30 s, capped at 1 h.
//
//	attempt 1 → immediate (first try, no backoff)
//	attempt 2 → 30 s
//	attempt 3 → 60 s
//	attempt 4 → 120 s
//	attempt 5 → 240 s
//	attempt 6 → 480 s
//	attempt 7 → 960 s
//	attempt 8 → 1920 s (capped at 3600 s = 1 h)
func RetryBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	d := time.Duration(1<<(attempt-2)) * 30 * time.Second
	if d > time.Hour {
		d = time.Hour
	}
	return d
}
