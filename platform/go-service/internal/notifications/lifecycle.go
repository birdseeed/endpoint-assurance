package notifications

import (
	"strings"
	"time"

	"patched.im/api/internal/findinglifecycle"
	"patched.im/api/internal/webhook"
)

// The bridge from the finding lifecycle (PAT-1878) to the notification
// catalogue (PAT-1888).
//
// Every notification event is derived from a lifecycle transition that has
// already been written. Nothing here invents a transition, re-judges evidence
// or decides that a finding is closed: the lifecycle reducer made that call
// under its own freshness and authority rules, and this map only names the
// result for a customer.
//
// Transitions with no entry raise nothing. first_observed and recurred are
// notable; currently_observed is the daily restatement of an already-notified
// failure and would be noise. Operator actions (acknowledged, risk_accepted,
// guidance_issued, customer_applied, pending_verification) are the customer's
// own actions coming back at them and are also left out. withdrawn (PAT-2107)
// is deliberately absent: it is a matcher correction, not a fix, and Andy
// ruled (2026-09-25) that it notifies no one.
var lifecycleEventMap = map[string]webhook.EventKind{
	findinglifecycle.EventFirstObserved:       webhook.EventFindingOpened,
	findinglifecycle.EventRecurred:            webhook.EventFindingRecurred,
	findinglifecycle.EventVerificationUnknown: webhook.EventEvidenceStale,
	findinglifecycle.EventVerifiedFixed:       webhook.EventVerificationPassed,
	findinglifecycle.EventStillFailing:        webhook.EventVerificationFailed,
}

// EventForLifecycle maps one lifecycle event type onto a notification event
// kind. The second result is false when that transition is not notifiable.
func EventForLifecycle(lifecycleEventType string) (webhook.EventKind, bool) {
	kind, ok := lifecycleEventMap[strings.TrimSpace(lifecycleEventType)]
	return kind, ok
}

// Subject builds the deduplication subject for one lifecycle transition:
//
//	<kind>/<device id or ->/<finding key>@<observed_at>
//
// The observation time is part of it on purpose, and it is the evidence's own
// timestamp rather than a row id or the wall clock. Without a discriminator, a
// second genuine transition of the same kind on the same finding (a finding
// that recurs twice, or verification that goes unknown across two separate
// cycles) would collide with the first and be silently dropped as a duplicate.
// With the evidence timestamp, re-processing the same payload dedupes — which
// is exactly the replay we want suppressed — while a transition drawn from a
// later collection does not.
func Subject(kind string, deviceID *string, findingKey string, observedAt time.Time) string {
	device := "-"
	if deviceID != nil && strings.TrimSpace(*deviceID) != "" {
		device = *deviceID
	}
	return strings.Join([]string{kind, device, findingKey}, "/") +
		"@" + observedAt.UTC().Format(time.RFC3339Nano)
}
