//go:build integration

package integration

// PAT-2138 round 5: which tenants count, unaliased signers never stored,
// one name normalisation in Go and SQL, and the due-review index.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cpepropose"
)

// Only current customer tenants on active devices count towards the
// two-tenant outbound rule. A second tenant whose only device is stale, any
// trial (active or expired), an internal tenant or a decommissioning tenant does not;
// an active paying second tenant does.
func TestCPEProposalOnlyCurrentCustomerTenantsCount(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		label    string
		spoil    func(t *testing.T, tenantID, deviceID string)
		eligible bool
	}{
		{"stale device", func(t *testing.T, _, dev string) {
			exec5(t, `UPDATE devices SET last_seen = now() - interval '40 days' WHERE id = $1::uuid`, dev)
		}, false},
		{"expired trial", func(t *testing.T, tn, _ string) {
			exec5(t, `UPDATE tenants SET is_trial = true, trial_expires_at = now() - interval '1 day' WHERE id = $1::uuid`, tn)
		}, false},
		{"active trial", func(t *testing.T, tn, _ string) {
			// Self-provisioned without email verification, so even an
			// unexpired trial never counts (fifth review, P2-1).
			exec5(t, `UPDATE tenants SET is_trial = true, trial_expires_at = now() + interval '10 days' WHERE id = $1::uuid`, tn)
		}, false},
		{"internal tenant", func(t *testing.T, tn, _ string) {
			exec5(t, `UPDATE tenants SET tenant_kind = 'internal' WHERE id = $1::uuid`, tn)
		}, false},
		{"decommissioning tenant", func(t *testing.T, tn, _ string) {
			exec5(t, `INSERT INTO tenant_decommission (tenant_id, mode) VALUES ($1::uuid, 'immediate')`, tn)
		}, false},
		{"active paying tenant", func(*testing.T, string, string) {}, true},
	}
	for i, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			sfx := randomHex(4)
			h := newSecHarness(t)
			app := fmt.Sprintf("Pat2138 Tenantrule%d %s", i, sfx)
			setNVD(h.nvd, app, "cpe:2.3:a:pat2138t"+sfx+":pat2138_tenantrule"+fmt.Sprint(i)+"_"+sfx+":1.0:*:*:*:*:*:*:*")
			a := newCVETestTenant(t, "pat2138-r5-a-"+sfx)
			postSignedAppsPayload(t, a, strings.ToUpper(sfx+"-2138-4000-8000-0000000005a1"),
				[]signedApp{{app, "1.0", "com.example.tenantrule." + sfx, "", ""}}, time.Now())
			b := alsoReportedBy(t, app, "com.example.tenantrule."+sfx, "")
			var dev string
			if err := env.pool.QueryRow(ctx, `SELECT id::text FROM devices WHERE tenant_id = $1::uuid`, b.tenantID).Scan(&dev); err != nil {
				t.Fatal(err)
			}
			tc.spoil(t, b.tenantID, dev)
			p := runSecProposer(t, h, "macos", app)
			searched := h.nvdSeen.searchedFor(app) > 0
			if searched != tc.eligible {
				t.Fatalf("%s: NVD searched = %v, want %v (proposal %+v %s)", tc.label, searched, tc.eligible, p, derefStr(p.Reason))
			}
			if !tc.eligible && derefStr(p.Reason) != cpepropose.ReasonSingleTenant {
				t.Fatalf("%s: reason %s, want single_tenant", tc.label, derefStr(p.Reason))
			}
			detail := cpAdminJSON(t, http.MethodGet, fmt.Sprintf("/admin/cve-mapping-proposals/%d", p.ID), nil, http.StatusOK)
			want := 1.0
			if tc.eligible {
				want = 2
			}
			if got := detail["proposal"].(map[string]any)["affected_tenants"]; got != want {
				t.Fatalf("%s: affected_tenants = %v, want %v", tc.label, got, want)
			}
		})
	}
}

func exec5(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// An unaliased signer (one customer's own Developer ID team) that every
// installation agrees on is never stored in the global evidence nor shown
// on the admin API.
func TestCPEProposalUnaliasedSignerNeverStored(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	h := newProposerHarness(t, true)
	vendor := "pat2138u" + sfx
	product := "pat2138_unaliased_" + sfx
	app := "Pat2138 Unaliased " + sfx
	team := testTeamID()
	setNVD(h.nvd, app, "cpe:2.3:a:"+vendor+":"+product+":1.0:*:*:*:*:*:*:*")
	seedFeedEntry(t, "CVE-2099-"+sfx+"U", vendor, product, "2.0", false)
	h.model.answer = pickVendor(vendor, "high")
	tn := newCVETestTenant(t, "pat2138-r5-unal-"+sfx)
	postSignedAppsPayload(t, tn, strings.ToUpper(sfx+"-2138-4000-8000-0000000005b1"),
		[]signedApp{{app, "1.0", "com.example.unaliased." + sfx, team, "signed"}}, time.Now())
	alsoReportedBy(t, app, "com.example.unaliased."+sfx, team)
	p := runProposer(t, h, app)
	if derefStr(p.Reason) != cpepropose.ReasonSignerNotAliased {
		t.Fatalf("proposal = %+v reason %s, want signer_not_aliased", p, derefStr(p.Reason))
	}
	var evidence string
	if err := env.pool.QueryRow(ctx, `SELECT evidence::text FROM cpe_mapping_proposals WHERE id = $1`, p.ID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	detail := cpAdminJSON(t, http.MethodGet, fmt.Sprintf("/admin/cve-mapping-proposals/%d", p.ID), nil, http.StatusOK)
	if strings.Contains(evidence, team) || strings.Contains(fmt.Sprint(detail), team) {
		t.Fatalf("unaliased signer %s stored or shown: evidence %s", team, evidence)
	}
}

// Go and the database normalise a product name identically, whatever the
// collation, including non-ASCII letters and Unicode spaces (NEL and the
// titlecase "ǅ" are where Unicode Go and the old SQL form disagreed); and a
// non-ASCII product is found in inventory by its proposal.
func TestCPEProposalNameNormalisationMatchesSQL(t *testing.T) {
	ctx := context.Background()
	for _, n := range []string{"ÄRZTE App", "Zoom\u00a0Meetings", "  Tab\tName \n", "École Directe", "Café\u202fPlus", "MixedCASE ÉÈ", "K\u212aelvin", "Line\u0085Next", "\u01c5ungla App"} {
		var sql string
		if err := env.pool.QueryRow(ctx, `SELECT `+sqlNormalizeExpr+``, n).Scan(&sql); err != nil {
			t.Fatal(err)
		}
		if goN := cpepropose.NormalizeName(n); goN != sql {
			t.Errorf("normalise %q: Go %q, SQL %q", n, goN, sql)
		}
	}
	sfx := randomHex(4)
	name := "\u01c5ungla\u0085Praxis " + sfx
	tn := newCVETestTenant(t, "pat2138-r5-norm-"+sfx)
	seedCVEDevice(t, tn.tenantID, "pat2138-r5-norm-"+sfx, []cveTestApp{{name, "1.0", "com.example.norm." + sfx}})
	if _, err := cpepropose.RecordUnmapped(ctx, env.pool, "", "macos", []string{name}, nil); err != nil {
		t.Fatal(err)
	}
	p, ok := proposalFor(t, "macos", name)
	if !ok {
		t.Fatalf("no proposal for %q", name)
	}
	detail := cpAdminJSON(t, http.MethodGet, fmt.Sprintf("/admin/cve-mapping-proposals/%d", p.ID), nil, http.StatusOK)
	if got := detail["proposal"].(map[string]any)["affected_devices"]; got != float64(1) {
		t.Fatalf("non-ASCII product: affected_devices = %v, want 1 (Go and SQL normalisation disagree)", got)
	}
}

// The due-review partial index covers every needs_review reason the claim
// re-reads.
func TestCPEProposalDueReviewIndexCoversClaim(t *testing.T) {
	var def string
	if err := env.pool.QueryRow(context.Background(), `SELECT indexdef FROM pg_indexes WHERE indexname = 'cpe_mapping_proposals_due_review_idx'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"model_unavailable", "single_tenant", "corroboration_lost"} {
		if !strings.Contains(def, r) {
			t.Errorf("due-review index omits %s: %s", r, def)
		}
	}
}

// sqlNormalizeExpr is the database's product-name normalisation.
const sqlNormalizeExpr = `cpe_normalize_name($1)`
