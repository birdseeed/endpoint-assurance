package intune

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"patched.im/api/internal/msgraph"
)

// compliancePoliciesPath is v1.0, not beta — see the table in PAT-1662.
// Requires DeviceManagementConfiguration.Read.All.
const compliancePoliciesPath = "/deviceManagement/deviceCompliancePolicies"

// CompliancePolicySource snapshots /deviceManagement/deviceCompliancePolicies.
// It is the only ObjectSource this ticket implements: it is v1.0 (not
// beta), small, and proves the whole snapshot pipeline end to end.
//
// Intune-managed Macs appear in this same collection as Windows devices —
// this source does not filter by platform, and must not start to.
type CompliancePolicySource struct{}

func (CompliancePolicySource) Type() ObjectType            { return ObjectTypeCompliancePolicy }
func (CompliancePolicySource) APIVersion() GraphAPIVersion { return APIVersionV1 }

func (CompliancePolicySource) ListIndex(ctx context.Context, client *msgraph.Client, tenantID string) ([]IndexEntry, error) {
	raw, err := client.GetAll(ctx, tenantID, compliancePoliciesPath, url.Values{
		"$select": {"id,lastModifiedDateTime"},
	})
	if err != nil {
		return nil, fmt.Errorf("intune: list compliance policies: %w", err)
	}
	entries := make([]IndexEntry, 0, len(raw))
	for _, r := range raw {
		var e struct {
			ID                   string    `json:"id"`
			LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			return nil, fmt.Errorf("intune: decode compliance policy index entry: %w", err)
		}
		entries = append(entries, IndexEntry{ID: e.ID, LastModifiedDateTime: e.LastModifiedDateTime})
	}
	return entries, nil
}

func (CompliancePolicySource) FetchBody(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error) {
	body, err := client.Get(ctx, tenantID, compliancePoliciesPath+"/"+url.PathEscape(objectID), nil)
	if err != nil {
		return nil, fmt.Errorf("intune: fetch compliance policy %s: %w", objectID, err)
	}
	return body, nil
}

func (CompliancePolicySource) FetchAssignments(ctx context.Context, client *msgraph.Client, tenantID, objectID string) (json.RawMessage, error) {
	items, err := client.GetAll(ctx, tenantID, compliancePoliciesPath+"/"+url.PathEscape(objectID)+"/assignments", nil)
	if err != nil {
		return nil, fmt.Errorf("intune: fetch compliance policy %s assignments: %w", objectID, err)
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	arr, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("intune: marshal compliance policy %s assignments: %w", objectID, err)
	}
	return arr, nil
}
