// Package intune snapshots Intune configuration objects (compliance
// policies, and later Settings Catalog / legacy device configurations / app
// protection policies) and their assignments into versioned, immutable,
// per-tenant snapshots — the raw material a later ticket diffs to produce a
// change list / rollback artefact (PAT-1662).
//
// This ticket implements exactly one ObjectSource: CompliancePolicySource,
// against /deviceManagement/deviceCompliancePolicies (v1.0). Two of the
// three remaining object types (Settings Catalog, legacy device
// configurations) are beta-only Graph endpoints; ObjectSource is the seam
// that isolates each object type's endpoint/version/permission from the
// shared orchestration in snapshot.go, so a Microsoft beta change has a
// blast radius of one ObjectSource implementation, not this package's core.
//
// Auth is entirely the existing internal/msgraph certificate-based
// app-only token flow (PAT-1653) — no per-tenant secret is introduced here.
package intune

import (
	"bytes"
	"encoding/json"
	"reflect"
	"time"
)

// ObjectType identifies which Intune configuration object collection a
// snapshot belongs to. Only ObjectTypeCompliancePolicy is implemented by
// this ticket.
type ObjectType string

const (
	ObjectTypeCompliancePolicy ObjectType = "compliance_policy"
)

// GraphAPIVersion is recorded on every snapshot (even though this ticket
// only ever uses v1.0) so a later beta-object addition's failures trace to
// the beta surface changing, not to core snapshot code.
type GraphAPIVersion string

const (
	APIVersionV1   GraphAPIVersion = "v1.0"
	APIVersionBeta GraphAPIVersion = "beta"
)

// ChangeKind classifies why an object row is present in a given snapshot.
type ChangeKind string

const (
	// ChangeAppeared: object id was not present in the prior complete
	// snapshot's alive-object set.
	ChangeAppeared ChangeKind = "appeared"
	// ChangeUnchanged: lastModifiedDateTime matched the prior snapshot, so
	// the body and assignments were carried forward verbatim without
	// calling Graph again.
	ChangeUnchanged ChangeKind = "unchanged"
	// ChangeRefreshed: lastModifiedDateTime moved, so the body and
	// assignments were refetched. BodyChanged/AssignmentsChanged on the
	// record say which of the two actually differed after refetching —
	// Graph moving lastModifiedDateTime does not guarantee the body text
	// itself changed (an assignment-only change is the common case where it
	// does not).
	ChangeRefreshed ChangeKind = "refreshed"
	// ChangeDisappeared: object id was in the prior complete snapshot's
	// alive-object set but absent from this run's list. A tombstone row —
	// RawBody/RawAssignments are nil. This is itself a change, not dropped.
	ChangeDisappeared ChangeKind = "disappeared"
)

// PullStatus records whether a snapshot's pull completed fully or failed
// partway through. A StatusPartial snapshot must never be used as the
// baseline for a later run's change detection (see Store.PriorObjects) or
// as a diff input — a partial pull looks identical to mass deletion
// otherwise.
type PullStatus string

const (
	StatusComplete PullStatus = "complete"
	StatusPartial  PullStatus = "partial"
)

// ObjectRecord is one object's row within a Snapshot.
type ObjectRecord struct {
	GraphObjectID        string
	LastModifiedDateTime time.Time // zero value for ChangeDisappeared
	ChangeKind           ChangeKind
	BodyChanged          bool // meaningful only for ChangeRefreshed
	AssignmentsChanged   bool // meaningful only for ChangeRefreshed
	RawBody              json.RawMessage
	RawAssignments       json.RawMessage
}

// Snapshot is one append-only pull run for one tenant and one ObjectType.
type Snapshot struct {
	TenantID    string
	ObjectType  ObjectType
	APIVersion  GraphAPIVersion
	StartedAt   time.Time
	CompletedAt time.Time
	Status      PullStatus
	// Error holds the pull failure detail when Status == StatusPartial.
	Error   string
	Objects []ObjectRecord
}

// jsonEqual reports whether two verbatim Graph JSON bodies are semantically
// equal, ignoring key order and formatting differences that carry no
// meaning (Graph gives no guarantee of stable key ordering across calls).
// Two nils (or empties) compare equal; exactly one nil never does.
func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	var av, bv interface{}
	if err := json.Unmarshal(a, &av); err != nil {
		return bytes.Equal(a, b)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(av, bv)
}

// bodyContentEqual reports whether two object bodies are equal ignoring the
// top-level lastModifiedDateTime field. Graph bumps lastModifiedDateTime on
// an assignment-only change too (that field change is exactly what gates a
// refetch in the first place), so comparing raw bodies verbatim would mark
// BodyChanged true on every refresh regardless of whether anything a human
// would call "the policy content" actually moved. Stripping the timestamp
// before comparing is what lets ChangeRefreshed correctly distinguish a real
// body edit from an assignments-only change with an otherwise identical
// body — see the "assignment-only change" scenario in PAT-1662.
func bodyContentEqual(a, b json.RawMessage) bool {
	strip := func(raw json.RawMessage) (json.RawMessage, bool) {
		if len(raw) == 0 {
			return raw, false
		}
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return raw, false
		}
		delete(m, "lastModifiedDateTime")
		out, err := json.Marshal(m)
		if err != nil {
			return raw, false
		}
		return out, true
	}
	sa, oka := strip(a)
	sb, okb := strip(b)
	if !oka || !okb {
		return jsonEqual(a, b)
	}
	return jsonEqual(sa, sb)
}
