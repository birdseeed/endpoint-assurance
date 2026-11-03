package findinglifecycle

import (
	"testing"
	"time"
)

func event(kind string, observed, recorded time.Time) Event {
	var observedPtr *time.Time
	if !observed.IsZero() {
		observedPtr = &observed
	}
	return Event{Type: kind, ObservedAt: observedPtr, RecordedAt: recorded, Authoritative: observedPtr != nil}
}

func observation(outcome ObservationOutcome, at time.Time) Observation {
	return Observation{Outcome: outcome, ObservedAt: at, ReceivedAt: at, Authoritative: true}
}

func TestNextObservationEventCompleteLifecycleAndRecurrence(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{}
	obs := observation(OutcomeFailing, t0)
	if got := NextObservationEvent(history, obs); got == nil || *got != EventFirstObserved {
		t.Fatalf("first failure = %v, want first_observed", got)
	}
	history = append(history, event(EventFirstObserved, t0, t0))
	if got := NextObservationEvent(history, observation(OutcomeFailing, t0.Add(time.Hour))); got == nil || *got != EventCurrentlyObserved {
		t.Fatalf("re-observation = %v, want currently_observed", got)
	}
	history = append(history,
		event(EventAcknowledged, time.Time{}, t0.Add(2*time.Hour)),
		event(EventGuidanceIssued, time.Time{}, t0.Add(3*time.Hour)),
		event(EventCustomerApplied, time.Time{}, t0.Add(4*time.Hour)),
		event(EventPendingVerification, time.Time{}, t0.Add(5*time.Hour)),
	)
	if got := NextObservationEvent(history, observation(OutcomeFailing, t0.Add(6*time.Hour))); got == nil || *got != EventStillFailing {
		t.Fatalf("failed verification = %v, want still_failing", got)
	}
	history = append(history, event(EventStillFailing, t0.Add(6*time.Hour), t0.Add(6*time.Hour)))
	if got := NextObservationEvent(history, observation(OutcomePassing, t0.Add(7*time.Hour))); got == nil || *got != EventVerifiedFixed {
		t.Fatalf("passing verification = %v, want verified_fixed", got)
	}
	history = append(history, event(EventVerifiedFixed, t0.Add(7*time.Hour), t0.Add(7*time.Hour)))
	if got := NextObservationEvent(history, observation(OutcomeFailing, t0.Add(8*time.Hour))); got == nil || *got != EventRecurred {
		t.Fatalf("failure after closure = %v, want recurred", got)
	}
}

func TestNextObservationEventStaleOrIncompleteNeverCloses(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventPendingVerification, time.Time{}, t0.Add(2*time.Hour)),
	}
	for name, obs := range map[string]Observation{
		"stale pass":      {Outcome: OutcomePassing, ObservedAt: t0.Add(time.Hour), ReceivedAt: t0.Add(3 * time.Hour), Authoritative: true},
		"incomplete pass": {Outcome: OutcomePassing, ObservedAt: t0.Add(3 * time.Hour), ReceivedAt: t0.Add(3 * time.Hour), Authoritative: false},
		"unknown":         {Outcome: OutcomeUnknown, ObservedAt: t0.Add(3 * time.Hour), ReceivedAt: t0.Add(3 * time.Hour), Authoritative: false},
	} {
		t.Run(name, func(t *testing.T) {
			got := NextObservationEvent(history, obs)
			if got == nil || *got != EventVerificationUnknown {
				t.Fatalf("got %v, want verification_unknown", got)
			}
		})
	}
}

func TestNextObservationEventReceiptMustPostdateVerificationRequest(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventPendingVerification, time.Time{}, t0.Add(time.Hour)),
	}
	// The endpoint clock is within tolerated future skew, but the evidence
	// reached the server before the later verification request.
	obs := Observation{
		Outcome: OutcomePassing, ObservedAt: t0.Add(time.Hour + time.Minute),
		ReceivedAt: t0.Add(59 * time.Minute), Authoritative: true,
	}
	if got := NextObservationEvent(history, obs); got == nil || *got != EventVerificationUnknown {
		t.Fatalf("got %v, want verification_unknown", got)
	}
}

func TestNextObservationEventDelayedPayloadCannotClose(t *testing.T) {
	receivedAt := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, receivedAt.Add(-48*time.Hour), receivedAt.Add(-48*time.Hour)),
		event(EventPendingVerification, time.Time{}, receivedAt.Add(-time.Hour)),
	}
	obs := Observation{
		Outcome: OutcomePassing, ObservedAt: receivedAt.Add(-ObservationEvidenceMaxAge - time.Second),
		ReceivedAt: receivedAt, Authoritative: true,
	}
	if got := NextObservationEvent(history, obs); got == nil || *got != EventVerificationUnknown {
		t.Fatalf("got %v, want verification_unknown", got)
	}
}

func TestNextObservationEventUsesLatestPendingRequest(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventPendingVerification, time.Time{}, t0.Add(time.Hour)),
		event(EventPendingVerification, time.Time{}, t0.Add(3*time.Hour)),
	}
	staleForLatest := observation(OutcomePassing, t0.Add(2*time.Hour))
	if got := NextObservationEvent(history, staleForLatest); got == nil || *got != EventVerificationUnknown {
		t.Fatalf("before latest pending got %v, want verification_unknown", got)
	}
	if got := NextObservationEvent(history, observation(OutcomePassing, t0.Add(4*time.Hour))); got == nil || *got != EventVerifiedFixed {
		t.Fatalf("after latest pending got %v, want verified_fixed", got)
	}
}

func TestNextObservationEventFixedThenPending(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventVerifiedFixed, t0.Add(time.Hour), t0.Add(time.Hour)),
		event(EventPendingVerification, time.Time{}, t0.Add(2*time.Hour)),
	}
	if got := NextObservationEvent(history, observation(OutcomePassing, t0.Add(3*time.Hour))); got == nil || *got != EventVerifiedFixed {
		t.Fatalf("pass after renewed pending got %v, want verified_fixed", got)
	}
	if got := NextObservationEvent(history, observation(OutcomeFailing, t0.Add(3*time.Hour))); got == nil || *got != EventRecurred {
		t.Fatalf("failure after fixed got %v, want recurred", got)
	}
}

func TestNextObservationEventRecurredPendingPass(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	history := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventVerifiedFixed, t0.Add(time.Hour), t0.Add(time.Hour)),
		event(EventRecurred, t0.Add(2*time.Hour), t0.Add(2*time.Hour)),
		event(EventPendingVerification, time.Time{}, t0.Add(3*time.Hour)),
	}
	if got := NextObservationEvent(history, observation(OutcomePassing, t0.Add(4*time.Hour))); got == nil || *got != EventVerifiedFixed {
		t.Fatalf("pass after recurrence pending got %v, want verified_fixed", got)
	}
}

func TestIdentityNeutralShape(t *testing.T) {
	deviceID := "00000000-0000-0000-0000-000000000001"
	for _, identity := range []Identity{
		{TenantID: "tenant", Kind: KindCIS, DeviceID: &deviceID, FindingKey: "cis_rule"},
		{TenantID: "tenant", Kind: KindCVE, FindingKey: "CVE-2026-0001"},
		{TenantID: "tenant", Kind: KindSoftware, DeviceID: &deviceID, FindingKey: "unapproved_present:policy"},
	} {
		if err := identity.Validate(); err != nil {
			t.Errorf("%+v: %v", identity, err)
		}
	}
}

// PAT-2107: withdrawn ends a finding without fixing it.
func TestWithdrawnIsNeverAFix(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	open := []Event{
		event(EventFirstObserved, t0, t0),
		event(EventPendingVerification, time.Time{}, t0.Add(time.Hour)),
	}
	if !Withdrawable(open) {
		t.Fatal("an open finding must be withdrawable")
	}
	withdrawn := append(append([]Event{}, open...), event(EventWithdrawn, time.Time{}, t0.Add(2*time.Hour)))
	if Withdrawable(withdrawn) {
		t.Fatal("a withdrawn finding must not be withdrawn twice")
	}
	fixed := []Event{event(EventFirstObserved, t0, t0), event(EventVerifiedFixed, t0.Add(time.Hour), t0.Add(time.Hour))}
	if Withdrawable(fixed) {
		t.Fatal("a verified fix must not be rewritten as withdrawn")
	}
	if Withdrawable(nil) || Withdrawable([]Event{event(EventAcknowledged, time.Time{}, t0)}) {
		t.Fatal("an identity with no failure must not be withdrawable")
	}

	// A later fresh pass does not verify a fix that never happened, and the
	// verification requested before the withdrawal is moot, so stale evidence
	// does not raise verification_unknown either.
	if got := NextObservationEvent(withdrawn, observation(OutcomePassing, t0.Add(3*time.Hour))); got != nil {
		t.Fatalf("pass after withdrawal = %v, want nothing", *got)
	}
	if got := NextObservationEvent(withdrawn, observation(OutcomeUnknown, t0.Add(3*time.Hour))); got != nil {
		t.Fatalf("unknown after withdrawal = %v, want nothing", *got)
	}
	// A match after the withdrawal is a new finding, not a recurrence.
	if got := NextObservationEvent(withdrawn, observation(OutcomeFailing, t0.Add(3*time.Hour))); got == nil || *got != EventFirstObserved {
		t.Fatalf("failure after withdrawal = %s, want first_observed", describe(got))
	}
	reopened := append(append([]Event{}, withdrawn...), event(EventFirstObserved, t0.Add(3*time.Hour), t0.Add(3*time.Hour)))
	if !Withdrawable(reopened) {
		t.Fatal("a re-opened finding must be withdrawable again")
	}
	if got := NextObservationEvent(reopened, observation(OutcomePassing, t0.Add(4*time.Hour))); got == nil || *got != EventVerifiedFixed {
		t.Fatalf("pass after re-open = %s, want verified_fixed", describe(got))
	}
}

// PAT-2107 review: the failure that follows a withdrawal is decided from the
// history ending in withdrawn, so it is first_observed, never recurred, even
// when the withdrawn finding had an earlier genuine fix and recurrence. Once
// re-opened, later failures are currently_observed, and a genuine
// fix -> recurrence after the re-open still records recurred.
func TestFailureAfterWithdrawalIsFirstObservedNeverRecurred(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }
	next := func(history []Event, outcome ObservationOutcome, h int) string {
		t.Helper()
		got := NextObservationEvent(history, observation(outcome, at(h)))
		if got == nil {
			return ""
		}
		return *got
	}

	// fixed -> recurred -> withdrawn -> failure
	history := []Event{
		event(EventFirstObserved, at(0), at(0)),
		event(EventVerifiedFixed, at(1), at(1)),
		event(EventRecurred, at(2), at(2)),
		event(EventWithdrawn, time.Time{}, at(3)),
	}
	if got := next(history, OutcomeFailing, 4); got != EventFirstObserved {
		t.Fatalf("failure after fix, recurrence and withdrawal = %q, want first_observed", got)
	}
	history = append(history, event(EventFirstObserved, at(4), at(4)))
	if got := next(history, OutcomeFailing, 5); got != EventCurrentlyObserved {
		t.Fatalf("second failure after the re-open = %q, want currently_observed", got)
	}
	history = append(history, event(EventCurrentlyObserved, at(5), at(5)))
	if got := next(history, OutcomePassing, 6); got != EventVerifiedFixed {
		t.Fatalf("pass after the re-open = %q, want verified_fixed", got)
	}
	history = append(history, event(EventVerifiedFixed, at(6), at(6)))
	if got := next(history, OutcomeFailing, 7); got != EventRecurred {
		t.Fatalf("failure after a genuine fix = %q, want recurred", got)
	}

	// first_observed -> withdrawn -> failure (no fix anywhere)
	simple := []Event{event(EventFirstObserved, at(0), at(0)), event(EventWithdrawn, time.Time{}, at(1))}
	if got := next(simple, OutcomeFailing, 2); got != EventFirstObserved {
		t.Fatalf("failure after withdrawal = %q, want first_observed", got)
	}
}

func describe(e *string) string {
	if e == nil {
		return "no event"
	}
	return *e
}
