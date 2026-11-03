// Package notifications delivers finding, stale-evidence and verification
// events to tenant-configured channels (PAT-1888).
//
// The shape is deliberately two-stage and the two stages never touch:
//
//  1. Raising an event writes delivery rows and nothing else (store.go,
//     Notify). It is a pure INSERT against notification_deliveries, called
//     after the lifecycle transaction has already committed. There is no
//     network call on this path, so a destination that is down, slow or hostile
//     cannot fail, delay or roll back the transaction that established the
//     finding. This is the whole mechanism behind "delivery failure never
//     changes finding truth" — it is structural, not a promise about error
//     handling.
//
//  2. Delivering is a separate sweeper (dispatch.go) that polls due rows,
//     attempts one send, and records the outcome. Every attempt updates the
//     same row, so attempt count, last status, last error and terminal state
//     are one auditable record per event per channel.
//
// Truthfulness rules that the payload builder enforces, because a notification
// is a product claim:
//
//   - evidence.stale says verification could not be judged. It never says a
//     finding cleared. Absence of evidence is not authority.
//   - verification.passed is only ever raised from the lifecycle's
//     verified_fixed transition, which itself requires fresh, authoritative
//     endpoint evidence.
//   - an event whose severity is unknown is delivered, not filtered out. A
//     severity threshold suppresses findings we know are below it, never
//     findings we merely failed to grade.
package notifications

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"patched.im/api/internal/webhook"
)

// Channel types.
const (
	ChannelWebhook = "webhook"
	ChannelEmail   = "email"
)

// Delivery states. These mirror the CHECK constraint in migration 0157.
const (
	// StatePending — awaiting a first attempt or a scheduled retry.
	StatePending = "pending"
	// StateDelivered — accepted by the destination.
	StateDelivered = "delivered"
	// StateDeadLetter — terminal failure, listable by the tenant owner.
	StateDeadLetter = "dead_letter"
)

// Dead-letter reasons, recorded alongside StateDeadLetter so an owner can tell
// a broken endpoint from a spent retry budget without reading raw errors.
const (
	ReasonPermanent     = "permanent_error"
	ReasonMaxAttempts   = "max_attempts"
	ReasonUndeliverable = "undeliverable_configuration"
)

// MaxAttempts bounds the total attempts for one delivery. Combined with
// webhook.RetryBackoff (30s doubling, capped at 1h) the worst case is roughly
// two hours of retrying before a row dead-letters, which is bounded work per
// event and a bounded wait before an owner can see the failure.
const MaxAttempts = 6

// MaxDeliveryPageSize caps any delivery listing so a tenant with a long history
// cannot ask for an unbounded response.
const MaxDeliveryPageSize = 200

// DefaultDeliveryPageSize is used when a caller does not ask for a page size.
const DefaultDeliveryPageSize = 50

// maxStoredErrorLen truncates a stored transport error. Errors are operator
// breadcrumbs, not logs.
const maxStoredErrorLen = 300

// Severity ordering for the per-channel threshold filter.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// ValidSeverity reports whether s is a severity this platform grades findings
// with.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// HighestSeverity returns the highest-ranked valid severity in candidates,
// normalised to lower case, or "" when none of them is a severity this platform
// grades with.
//
// It exists so that nothing outside this package invents a second ordering.
// Severity is stored as text in several tables, and text ordering is not
// severity ordering: sorted alphabetically, "critical" comes before "low",
// so a SQL max() or a Go string comparison silently grades a critical finding
// as the lowest one present. Every ranking decision goes through severityRank,
// which is the same table MeetsThreshold filters on.
//
// Values outside the vocabulary (for example the feed's "NONE", or anything
// unrecognised) never win over a valid grade and never produce one on their own.
func HighestSeverity(candidates []string) string {
	best, bestRank := "", 0
	for _, candidate := range candidates {
		normalised := strings.ToLower(strings.TrimSpace(candidate))
		rank, ok := severityRank[normalised]
		if !ok || rank <= bestRank {
			continue
		}
		best, bestRank = normalised, rank
	}
	return best
}

// MeetsThreshold reports whether an event of severity eventSeverity should be
// delivered to a channel whose minimum is minSeverity.
//
// An unrecognised or absent event severity always passes. Suppressing a finding
// because we could not grade it would let missing metadata hide real evidence,
// which is the same failure shape as letting missing evidence close a finding.
func MeetsThreshold(eventSeverity, minSeverity string) bool {
	eventRank, graded := severityRank[strings.ToLower(strings.TrimSpace(eventSeverity))]
	if !graded {
		return true
	}
	minRank, ok := severityRank[strings.ToLower(strings.TrimSpace(minSeverity))]
	if !ok {
		return true
	}
	return eventRank >= minRank
}

// Channel is a tenant's configured destination. The stored secret is never a
// field here: it has no representation that could be serialised by accident.
type Channel struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Type        string    `json:"channel_type"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Events      []string  `json:"events"`
	MinSeverity string    `json:"min_severity"`
	URL         string    `json:"destination_url,omitempty"`
	Recipients  []string  `json:"recipients,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Delivery is one auditable delivery record.
type Delivery struct {
	ID             int64      `json:"id"`
	ChannelID      string     `json:"channel_id"`
	EventType      string     `json:"event_type"`
	Subject        string     `json:"subject"`
	IdempotencyKey string     `json:"idempotency_key"`
	State          string     `json:"state"`
	FailureReason  *string    `json:"failure_reason"`
	ResponseStatus *int       `json:"response_status"`
	AttemptCount   int        `json:"attempt_count"`
	LastError      *string    `json:"last_error"`
	NextAttemptAt  *time.Time `json:"next_attempt_at"`
	LastAttemptAt  *time.Time `json:"last_attempt_at"`
	SucceededAt    *time.Time `json:"succeeded_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Event is one thing that happened to one finding, ready to be matched against
// a tenant's channels.
//
// Subject is the deduplication unit. For a lifecycle transition it is built by
// Subject() as "<kind>/<device or ->/<finding key>@<observed_at>": a replay of
// the same transition produces the same subject and therefore the same
// idempotency key, while a transition drawn from a later collection produces a
// new one.
type Event struct {
	TenantID  string
	Type      webhook.EventKind
	Subject   string
	Severity  string
	Timestamp time.Time
	Data      map[string]any
}

// Payload is the JSON body delivered to a webhook channel.
type Payload struct {
	EventType      string         `json:"event_type"`
	TenantID       string         `json:"tenant_id"`
	Subject        string         `json:"subject"`
	Severity       string         `json:"severity,omitempty"`
	IdempotencyKey string         `json:"idempotency_key"`
	Timestamp      time.Time      `json:"timestamp"`
	Data           map[string]any `json:"data,omitempty"`
}

// IdempotencyKey is the deterministic key for one (channel, event type,
// subject). Identical inputs always produce an identical key, and the unique
// index on (channel_id, idempotency_key) turns a duplicate trigger into a
// no-op insert rather than a second delivery.
//
// The components are joined with a unit separator so no component's content can
// impersonate a boundary and collide with a different triple.
func IdempotencyKey(channelID string, eventType webhook.EventKind, subject string) string {
	material := strings.Join([]string{channelID, string(eventType), subject}, "\x1f")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// ownerFacingBlockedDestination is the last_error stored for a delivery the
// SSRF guard refused at dial time. It names the refusal and nothing else: no
// hostname, no resolved address, no port.
const ownerFacingBlockedDestination = "destination address is not permitted"

// ownerFacingConnectionFailed is the last_error stored for any other
// transport-level failure that could carry the address that was dialed
// (connection refused, timeout, DNS failure and so on).
const ownerFacingConnectionFailed = "could not connect to destination"

// storedDeliveryError is the last_error text persisted for one delivery
// attempt (PAT-1956).
//
// Go wraps every dial failure in a *net.OpError whose Addr field is the
// concrete address that was actually dialed, and whose Error() string embeds
// it verbatim, e.g. "dial tcp 100.64.10.1:8443: ...". A hostname is
// accepted at channel configuration time by design, because DNS can change
// afterwards — which means a tenant owner can point a channel at any
// internal-looking name and, if that raw string were ever stored, read back
// what it resolves to. The same string also discloses which address ranges
// the guard blocks. Neither belongs in an owner-visible column.
//
// This maps every error that can carry that address to a fixed, generic
// string, whether or not the SSRF guard was the reason the dial failed: a
// blocked destination gets its own fixed wording, any other dial-time failure
// (refused connection, timeout, DNS failure) gets a second, equally address-free
// wording. Only errors that cannot carry a dialed address (HTTP status text,
// mailer credential detail) fall through to redactError unchanged — that
// detail is useful to an operator and carries no address.
//
// The address this function removes is not lost: dispatch.go logs the error
// through redactError on both the dead-letter and the retry branch, correlated
// with the delivery id. redactError strips secrets and bounds the length but
// deliberately keeps the host and resolved address, which is exactly the
// detail an operator needs and exactly the detail a tenant must not be given.
// The order of the checks below matters and must not be inverted. A refusal
// from the SSRF guard reaches here as ErrBlockedDestination wrapped inside the
// *net.OpError produced by the dial, inside the *url.Error produced by the
// client, so it satisfies both the errors.Is and the errors.As test. The
// blocked case is tested first so it keeps its own specific wording; checking
// for *net.OpError first would silently collapse every guard refusal into the
// generic connection-failed text.
func storedDeliveryError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, webhook.ErrBlockedDestination) {
		return ownerFacingBlockedDestination
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return ownerFacingConnectionFailed
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ownerFacingConnectionFailed
	}
	return redactError(err)
}

// redactError trims a transport error down to something safe and bounded to
// store: single line, truncated, and with anything that looks like a bearer
// token or a query string removed.
func redactError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")

	// A URL in a transport error can carry a signed or tokenised query string.
	// Cutting at the first '?' keeps the useful host-and-path part.
	if i := strings.Index(msg, "?"); i >= 0 {
		msg = msg[:i] + "?[redacted]"
	}
	for _, marker := range []string{"Bearer ", "bearer ", "secret=", "client_secret="} {
		if i := strings.Index(msg, marker); i >= 0 {
			msg = msg[:i] + "[redacted]"
		}
	}
	if len(msg) > maxStoredErrorLen {
		msg = msg[:maxStoredErrorLen] + "..."
	}
	return msg
}
