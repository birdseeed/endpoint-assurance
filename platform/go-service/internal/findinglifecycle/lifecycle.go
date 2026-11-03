// Package findinglifecycle owns the platform-neutral finding lifecycle.
// Operator actions and endpoint observations are deliberately separate:
// callers may request verification, but only a fresh, complete endpoint
// observation can produce verified_fixed, still_failing or recurred.
package findinglifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	KindCIS      = "cis"
	KindCVE      = "cve"
	KindSoftware = "software"

	EventFirstObserved       = "first_observed"
	EventCurrentlyObserved   = "currently_observed"
	EventAcknowledged        = "acknowledged"
	EventRiskAccepted        = "risk_accepted"
	EventGuidanceIssued      = "guidance_issued"
	EventCustomerApplied     = "customer_applied"
	EventPendingVerification = "pending_verification"
	EventVerificationUnknown = "verification_unknown"
	EventVerifiedFixed       = "verified_fixed"
	EventStillFailing        = "still_failing"
	EventRecurred            = "recurred"
	// EventWithdrawn (PAT-2107) records that Patched retracted a finding it
	// should never have raised: the CVE matcher's verdict changed while the
	// device kept reporting the same software at the same version. It is a
	// matcher correction, not a fix, carries SourceMatcher and is never
	// authoritative, and it raises no customer notification.
	EventWithdrawn = "withdrawn"

	// SourceMatcher is the source_type of a withdrawn event. The decision is
	// Patched's own (a matcher or CVE feed change), so it is neither an
	// endpoint observation nor an operator action.
	SourceMatcher = "matcher"

	// ObservationEvidenceMaxAge matches the product's daily endpoint upload
	// cycle: evidence delayed by more than one full cycle is audit history,
	// not authority for a present-tense closure decision.
	ObservationEvidenceMaxAge = 24 * time.Hour
	// ObservationFutureSkew admits ordinary endpoint/server clock drift while
	// preventing a bad endpoint clock from poisoning freshness indefinitely.
	ObservationFutureSkew = 5 * time.Minute
)

var actionEvents = map[string]bool{
	EventAcknowledged:        true,
	EventRiskAccepted:        true,
	EventGuidanceIssued:      true,
	EventCustomerApplied:     true,
	EventPendingVerification: true,
}

// Identity is stable across the three finding domains. CIS and software
// findings are device-scoped; CVEs retain PAT-1829's tenant-aggregate shape.
type Identity struct {
	TenantID   string
	Kind       string
	DeviceID   *string
	FindingKey string
}

func (i Identity) Validate() error {
	i.TenantID = strings.TrimSpace(i.TenantID)
	i.Kind = strings.TrimSpace(i.Kind)
	i.FindingKey = strings.TrimSpace(i.FindingKey)
	if i.TenantID == "" || i.FindingKey == "" {
		return errors.New("finding lifecycle identity requires tenant_id and finding_key")
	}
	switch i.Kind {
	case KindCVE:
		if i.DeviceID != nil {
			return errors.New("cve lifecycle identity must not carry device_id")
		}
	case KindCIS, KindSoftware:
		if i.DeviceID == nil || strings.TrimSpace(*i.DeviceID) == "" {
			return fmt.Errorf("%s lifecycle identity requires device_id", i.Kind)
		}
	default:
		return fmt.Errorf("unknown finding kind %q", i.Kind)
	}
	return nil
}

type Event struct {
	ID            int64
	Type          string
	ObservedAt    *time.Time
	RecordedAt    time.Time
	Authoritative bool
}

type ObservationOutcome string

const (
	OutcomeFailing ObservationOutcome = "failing"
	OutcomePassing ObservationOutcome = "passing"
	OutcomeUnknown ObservationOutcome = "unknown"
)

type Observation struct {
	Identity      Identity
	Outcome       ObservationOutcome
	ObservedAt    time.Time
	ReceivedAt    time.Time
	Authoritative bool
	Reason        string
	Evidence      map[string]any
}

// EvidenceTimeAuthoritative applies the platform-wide temporal trust window
// to endpoint evidence using server receipt as the trusted clock.
func EvidenceTimeAuthoritative(observedAt, receivedAt time.Time) bool {
	if observedAt.IsZero() || receivedAt.IsZero() {
		return false
	}
	return !observedAt.Before(receivedAt.Add(-ObservationEvidenceMaxAge)) &&
		!observedAt.After(receivedAt.Add(ObservationFutureSkew))
}

type Action struct {
	Identity Identity
	Type     string
	Actor    string
	Reason   string
	Evidence map[string]any
}

// NextObservationEvent is the pure lifecycle reducer. A nil result means the
// observation adds no state transition (for example, a pass before the first
// observed failure). Stale/incomplete evidence can only produce
// verification_unknown and can never close a finding.
func NextObservationEvent(history []Event, obs Observation) *string {
	var firstFailure, lastEvidence *time.Time
	var pendingRecorded *time.Time
	lastFailureIndex, lastFixedIndex, lastPendingIndex, lastWithdrawnIndex := -1, -1, -1, -1
	latestType := ""
	for index, event := range history {
		latestType = event.Type
		if event.Type == EventPendingVerification {
			t := event.RecordedAt
			pendingRecorded = &t
			lastPendingIndex = index
		}
		if event.Type == EventWithdrawn {
			// Withdrawn carries no observed_at: it is not endpoint evidence.
			lastWithdrawnIndex = index
		}
		if event.ObservedAt == nil {
			continue
		}
		// verification_unknown carries the attempted collection time for
		// audit, but it is not evidence and must not become a freshness
		// watermark that blocks a later genuine endpoint observation.
		if event.Authoritative && (lastEvidence == nil || event.ObservedAt.After(*lastEvidence)) {
			t := *event.ObservedAt
			lastEvidence = &t
		}
		switch event.Type {
		case EventFirstObserved, EventCurrentlyObserved, EventStillFailing, EventRecurred:
			if firstFailure == nil {
				t := *event.ObservedAt
				firstFailure = &t
			}
			lastFailureIndex = index
		case EventVerifiedFixed:
			lastFixedIndex = index
		}
	}

	// A withdrawal (PAT-2107) ends the finding without fixing it: a
	// verification requested before it is moot, and a later pass must not
	// turn the retraction into a verified fix.
	withdrawn := lastWithdrawnIndex > lastFailureIndex && lastWithdrawnIndex > lastFixedIndex
	verificationPending := lastPendingIndex > lastFixedIndex && lastPendingIndex > lastWithdrawnIndex
	currentlyFixed := lastFixedIndex > lastFailureIndex
	temporallyAuthoritative := obs.Authoritative && EvidenceTimeAuthoritative(obs.ObservedAt, obs.ReceivedAt)
	fresh := temporallyAuthoritative &&
		(lastEvidence == nil || obs.ObservedAt.After(*lastEvidence)) &&
		// Receipt must postdate the request. A collected_at slightly ahead of
		// server time is tolerated, but cannot make evidence received before a
		// customer action appear to verify that later action.
		(pendingRecorded == nil || (obs.ObservedAt.After(*pendingRecorded) && obs.ReceivedAt.After(*pendingRecorded)))

	if obs.Outcome == OutcomeUnknown || !fresh {
		if verificationPending && latestType != EventVerificationUnknown {
			e := EventVerificationUnknown
			return &e
		}
		return nil
	}

	switch obs.Outcome {
	case OutcomeFailing:
		// A match after a withdrawal is a new finding, not a recurrence of
		// a fix that never happened, so it opens again as first_observed.
		if firstFailure == nil || withdrawn {
			e := EventFirstObserved
			return &e
		}
		if currentlyFixed {
			e := EventRecurred
			return &e
		}
		if verificationPending {
			e := EventStillFailing
			return &e
		}
		e := EventCurrentlyObserved
		return &e
	case OutcomePassing:
		if firstFailure == nil || withdrawn || (currentlyFixed && !verificationPending) {
			return nil
		}
		e := EventVerifiedFixed
		return &e
	default:
		return nil
	}
}

// RecordAction appends one operator/customer milestone. It cannot accept any
// observation-only event, in particular verified_fixed.
func RecordAction(ctx context.Context, tx pgx.Tx, action Action) error {
	if err := action.Identity.Validate(); err != nil {
		return err
	}
	if !actionEvents[action.Type] {
		return fmt.Errorf("event %q is not an operator action", action.Type)
	}
	if strings.TrimSpace(action.Actor) == "" {
		return errors.New("finding lifecycle action requires actor")
	}
	if err := lockIdentity(ctx, tx, action.Identity); err != nil {
		return err
	}
	return insertEvent(ctx, tx, action.Identity, action.Type, "operator_action",
		action.Actor, action.Reason, nil, false, action.Evidence)
}

// RecordObservation serialises one identity, loads its immutable history and
// appends the transition selected by NextObservationEvent.
func RecordObservation(ctx context.Context, tx pgx.Tx, obs Observation) (string, error) {
	if err := obs.Identity.Validate(); err != nil {
		return "", err
	}
	if obs.Outcome != OutcomeFailing && obs.Outcome != OutcomePassing && obs.Outcome != OutcomeUnknown {
		return "", fmt.Errorf("unknown observation outcome %q", obs.Outcome)
	}

	if err := lockIdentity(ctx, tx, obs.Identity); err != nil {
		return "", err
	}
	history, err := loadHistory(ctx, tx, obs.Identity)
	if err != nil {
		return "", err
	}

	eventType := NextObservationEvent(history, obs)
	if eventType == nil {
		return "", nil
	}
	if obs.Evidence == nil {
		obs.Evidence = map[string]any{}
	}
	obs.Evidence["trusted_received_at"] = obs.ReceivedAt
	authoritative := obs.Authoritative && EvidenceTimeAuthoritative(obs.ObservedAt, obs.ReceivedAt) &&
		*eventType != EventVerificationUnknown
	if err := insertEvent(ctx, tx, obs.Identity, *eventType, "endpoint_observation",
		"endpoint", obs.Reason, &obs.ObservedAt, authoritative, obs.Evidence); err != nil {
		return "", err
	}
	return *eventType, nil
}

// Withdrawal is a matcher correction (PAT-2107) for one identity.
type Withdrawal struct {
	Identity Identity
	Reason   string
	Evidence map[string]any
}

// Withdrawable reports whether a withdrawal would add a transition to
// history: only an open finding (a failure after any fix or earlier
// withdrawal) can be withdrawn. A finding already verified fixed keeps that
// closure, and one already withdrawn is not withdrawn twice, which is what
// makes a repeated reconcile idempotent.
func Withdrawable(history []Event) bool {
	lastFailureIndex, lastClosedIndex := -1, -1
	for index, event := range history {
		switch event.Type {
		case EventFirstObserved, EventCurrentlyObserved, EventStillFailing, EventRecurred:
			if event.ObservedAt != nil {
				lastFailureIndex = index
			}
		case EventVerifiedFixed, EventWithdrawn:
			lastClosedIndex = index
		}
	}
	return lastFailureIndex >= 0 && lastFailureIndex > lastClosedIndex
}

// RecordWithdrawal appends a withdrawn event when the identity is open, under
// the same identity lock as every other lifecycle writer. It returns
// EventWithdrawn when a row was written and "" when the identity was not open.
// The event is never authoritative and carries no observed_at: it records
// Patched's decision, not endpoint evidence.
func RecordWithdrawal(ctx context.Context, tx pgx.Tx, w Withdrawal) (string, error) {
	if err := w.Identity.Validate(); err != nil {
		return "", err
	}
	if err := lockIdentity(ctx, tx, w.Identity); err != nil {
		return "", err
	}
	history, err := loadHistory(ctx, tx, w.Identity)
	if err != nil {
		return "", err
	}
	if !Withdrawable(history) {
		return "", nil
	}
	if err := insertEvent(ctx, tx, w.Identity, EventWithdrawn, SourceMatcher,
		SourceMatcher, w.Reason, nil, false, w.Evidence); err != nil {
		return "", err
	}
	return EventWithdrawn, nil
}

func loadHistory(ctx context.Context, tx pgx.Tx, identity Identity) ([]Event, error) {
	deviceID := any(nil)
	if identity.DeviceID != nil {
		deviceID = *identity.DeviceID
	}
	rows, err := tx.Query(ctx, `
		SELECT id, event_type, observed_at, recorded_at, authoritative
		FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = $2
		  AND device_id IS NOT DISTINCT FROM $3::uuid AND finding_key = $4
		ORDER BY id
	`, identity.TenantID, identity.Kind, deviceID, identity.FindingKey)
	if err != nil {
		return nil, fmt.Errorf("load finding lifecycle history: %w", err)
	}
	defer rows.Close()
	var history []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Type, &event.ObservedAt, &event.RecordedAt, &event.Authoritative); err != nil {
			return nil, fmt.Errorf("scan finding lifecycle history: %w", err)
		}
		history = append(history, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding lifecycle history: %w", err)
	}
	return history, nil
}

// lockIdentity serialises every lifecycle writer, including human actions and
// endpoint reductions, on the same transaction-scoped identity lock.
func lockIdentity(ctx context.Context, tx pgx.Tx, identity Identity) error {
	deviceID := any(nil)
	if identity.DeviceID != nil {
		deviceID = *identity.DeviceID
	}
	lockKey := strings.Join([]string{identity.TenantID, identity.Kind, fmt.Sprint(deviceID), identity.FindingKey}, "\x1f")
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return fmt.Errorf("lock finding lifecycle identity: %w", err)
	}
	return nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, identity Identity, eventType, sourceType,
	actor, reason string, observedAt *time.Time, authoritative bool, evidence map[string]any) error {
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal finding lifecycle evidence: %w", err)
	}
	deviceID := any(nil)
	if identity.DeviceID != nil {
		deviceID = *identity.DeviceID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO finding_lifecycle_events (
			tenant_id, finding_kind, device_id, finding_key, event_type,
			source_type, actor, reason, observed_at, authoritative, evidence
		) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
	`, identity.TenantID, identity.Kind, deviceID, identity.FindingKey, eventType,
		sourceType, actor, reason, observedAt, authoritative, evidenceJSON)
	if err != nil {
		return fmt.Errorf("append finding lifecycle event: %w", err)
	}
	return nil
}
