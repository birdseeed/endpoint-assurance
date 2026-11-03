package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// TestComputeTenantRuleChanges verifies the change-detection logic for the
// tenant_rules audit log. Pure function; no DB required.
func TestComputeTenantRuleChanges(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)
	past := now.Add(-1 * time.Hour)

	boolPtr := func(b bool) *bool { return &b }
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name                string
		prevEnabled         *bool
		rowExisted          bool
		newEnabled          bool
		prevSeverity        *string
		newSeverity         *string
		prevSuppressedUntil *time.Time
		newSuppressedUntil  *time.Time
		suppressionReason   *string
		wantTypes           []string
	}{
		{
			name:       "no prior row, enabling T2 rule",
			rowExisted: false,
			newEnabled: true,
			wantTypes:  []string{"enabled"},
		},
		{
			name:        "disabling an enabled rule",
			prevEnabled: boolPtr(true),
			rowExisted:  true,
			newEnabled:  false,
			wantTypes:   []string{"disabled"},
		},
		{
			name:        "no change in enabled state",
			prevEnabled: boolPtr(true),
			rowExisted:  true,
			newEnabled:  true,
			wantTypes:   nil,
		},
		{
			name:       "no prior row, keeping disabled — no change logged",
			rowExisted: false,
			newEnabled: false,
			wantTypes:  nil,
		},
		{
			name:        "severity override added",
			prevEnabled: boolPtr(true),
			rowExisted:  true,
			newEnabled:  true,
			newSeverity: strPtr("critical"),
			wantTypes:   []string{"severity_overridden"},
		},
		{
			name:         "severity override reset",
			prevEnabled:  boolPtr(true),
			rowExisted:   true,
			newEnabled:   true,
			prevSeverity: strPtr("critical"),
			newSeverity:  nil,
			wantTypes:    []string{"severity_reset"},
		},
		{
			name:               "suppression added",
			prevEnabled:        boolPtr(true),
			rowExisted:         true,
			newEnabled:         true,
			newSuppressedUntil: &future,
			wantTypes:          []string{"suppressed"},
		},
		{
			name:                "suppression removed",
			prevEnabled:         boolPtr(true),
			rowExisted:          true,
			newEnabled:          true,
			prevSuppressedUntil: &future,
			newSuppressedUntil:  nil,
			wantTypes:           []string{"unsuppressed"},
		},
		{
			name:                "expired suppression not counted as active",
			prevEnabled:         boolPtr(true),
			rowExisted:          true,
			newEnabled:          true,
			prevSuppressedUntil: &past, // expired — was not active
			newSuppressedUntil:  nil,
			wantTypes:           nil, // no semantic change
		},
		{
			name:                "multiple changes at once",
			prevEnabled:         boolPtr(true),
			rowExisted:          true,
			newEnabled:          false,
			prevSeverity:        strPtr("high"),
			newSeverity:         nil,
			prevSuppressedUntil: &future,
			newSuppressedUntil:  nil,
			wantTypes:           []string{"disabled", "severity_reset", "unsuppressed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeTenantRuleChanges(
				tc.prevEnabled, tc.rowExisted, tc.newEnabled,
				tc.prevSeverity, tc.newSeverity,
				tc.prevSuppressedUntil, tc.newSuppressedUntil,
				tc.suppressionReason,
			)

			gotTypes := make([]string, len(got))
			for i, e := range got {
				gotTypes[i] = e.changeType
			}

			if len(gotTypes) != len(tc.wantTypes) {
				t.Fatalf("want change types %v, got %v", tc.wantTypes, gotTypes)
			}
			for i, want := range tc.wantTypes {
				if gotTypes[i] != want {
					t.Errorf("change[%d]: want %q, got %q", i, want, gotTypes[i])
				}
			}
		})
	}
}

// TestTenantRulesPutHandler_AuditAttribution pins the PAT-1135 property for
// tenant_rule_changes: like tenant_platform_changes, this handler's request
// body has no actor field at all, so before PAT-1135 changed_by relied
// entirely on the column's DEFAULT 'system'. changed_by must now be
// explicitly the server-established constant, claimed_actor must be NULL,
// and source_addr must be populated.
func TestTenantRulesPutHandler_AuditAttribution(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1135-rule-attribution-tenant")

	// tenant_rules.rule_id has a FK to compliance_rules -- pick any seeded rule.
	var ruleID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM compliance_rules LIMIT 1`).Scan(&ruleID); err != nil {
		t.Fatalf("fetch a compliance_rules id to test against: %v", err)
	}

	router := chi.NewRouter()
	router.Put("/admin/tenant-rules/{tenantID}/{ruleID}", TenantRulesPutHandler(pool))

	req := httptest.NewRequest(http.MethodPut, "/admin/tenant-rules/"+tenantID+"/"+ruleID,
		strings.NewReader(`{"enabled":true}`))
	req.RemoteAddr = "198.51.100.40:7777"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var changedBy string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT changed_by, claimed_actor, source_addr FROM tenant_rule_changes
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&changedBy, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch tenant_rule_changes row: %v", err)
	}

	if changedBy != adminSharedTokenActor {
		t.Errorf("changed_by = %q, want %q", changedBy, adminSharedTokenActor)
	}
	if claimedActor != nil {
		t.Errorf("claimed_actor = %q, want nil — this request body has no actor field", *claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "198.51.100.40" {
		t.Errorf("source_addr = %v, want \"198.51.100.40\" (port stripped)", sourceAddr)
	}
}
