package intune

import (
	"context"
	"encoding/json"
	"time"

	"patched.im/api/internal/msgraph"
)

// IndexEntry is one row of the cheap $select=id,lastModifiedDateTime list
// used for change detection before any full object body is fetched.
type IndexEntry struct {
	ID                   string
	LastModifiedDateTime time.Time
}

// ObjectSource is the seam that isolates one Intune object type's Graph
// surface — its endpoint, API version and permission — from the shared
// snapshot orchestration in snapshot.go. Adding Settings Catalog or legacy
// device configurations later (both beta-only) means writing a new
// ObjectSource implementation; it never requires changing
// CompliancePolicySource or Snapshotter. A breaking change to the beta
// Graph surface therefore has a blast radius of one ObjectSource
// implementation.
type ObjectSource interface {
	// Type identifies which object collection this source snapshots.
	Type() ObjectType
	// APIVersion is recorded on every snapshot produced from this source.
	APIVersion() GraphAPIVersion
	// ListIndex fetches the cheap id+lastModifiedDateTime list for every
	// object of this type in the tenant.
	ListIndex(ctx context.Context, client *msgraph.Client, tenantID string) ([]IndexEntry, error)
	// FetchBody fetches one object's full body, verbatim.
	FetchBody(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error)
	// FetchAssignments fetches one object's assignments child collection,
	// verbatim (as a JSON array of whatever Graph returned).
	FetchAssignments(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error)
}
