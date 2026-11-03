//go:build integration

package integration

// PAT-2138 round 3: the two-tenant outbound rule, browser web-app wrappers,
// neutral absent evidence, truncated evidence, the expire/reopen race and
// stale terminal states.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/extractor"
)

// pathApp is one macOS app with an explicit install path.
type pathApp struct{ name, bundle, path, teamID string }

func postPathApps(t *testing.T, tn cveTestTenant, hwUUID string, apps []pathApp) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "full.json"), &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p["tenant_id"] = tn.tenantID
	p["collected_at"] = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	device := p["device"].(map[string]any)
	device["hw_uuid"] = hwUUID
	tail := strings.ReplaceAll(hwUUID, "-", "")
	tail = tail[len(tail)-12:]
	device["serial"] = "R3SERIAL" + strings.ToUpper(tail)
	device["hostname"] = "r3host-" + strings.ToLower(tail)
	list := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		e := map[string]any{"name": a.name, "version": "1.0", "bundle_id": a.bundle, "path": a.path}
		if a.teamID != "" {
			e["team_id"] = a.teamID
			e["signed_by"] = "Developer ID Application: Test (" + a.teamID + ")"
			e["signing_status"] = "signed"
		}
		list = append(list, e)
	}
	p["apps"] = list
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, tn.hmacSecret)
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tn.bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", randomHex(16))
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory: %d %s", resp.StatusCode, raw)
	}
	var ingest struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingest); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(context.Background(), env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, ingest.RawPayloadID)
}

// Andy's ruling: one tenant is never enough to go outbound, even with an
// aliased vendor signer (the browser web-app wrapper case: one customer's
// intranet app signed with Google's Team ID).
func TestCPEProposalSingleTenantAliasedSignerStaysLocal(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2138-r3-alias1-"+sfx)
	h := newSecHarness(t)
	vendor := "pat2138g" + sfx
	app := "Pat2138 Intranet " + sfx
	team := testTeamID()
	seedTeamAlias(t, team, vendor)
	setNVD(h.nvd, app, "cpe:2.3:a:"+vendor+":pat2138_intranet_"+sfx+":1.0:*:*:*:*:*:*:*")
	h.model.answer = pickVendor(vendor, "high")
	postSignedAppsPayload(t, tn, strings.ToUpper(sfx+"-2138-4000-8000-0000000003a1"),
		[]signedApp{{app, "1.0", "com.example.intranet." + sfx, team, "signed"}}, time.Now())
	p := runSecProposer(t, h, "macos", app)
	if n := h.nvdSeen.searchedFor(app); n != 0 {
		t.Errorf("%d NVD requests for a single-tenant product with an aliased signer", n)
	}
	if n := h.modelMentioning(strings.ToLower(app)); n != 0 {
		t.Errorf("%d model requests for a single-tenant product with an aliased signer", n)
	}
	if derefStr(p.Reason) != cpepropose.ReasonSingleTenant {
		t.Fatalf("proposal = %+v reason %s, want single_tenant", p, derefStr(p.Reason))
	}
}

// Browser web-app wrappers are never proposed, at ingest or by backfill;
// the real app beside them is.
func TestCPEProposalWebAppWrappersNeverProposed(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2138-r3-pwa-"+sfx)
	chrome := "Acme Corp HR Portal " + sfx
	edge := "Jira - acme.atlassian.net " + sfx
	real := "Pat2138 Realapp " + sfx
	postPathApps(t, tn, strings.ToUpper(sfx+"-2138-4000-8000-0000000003b1"), []pathApp{
		{chrome, "com.google.Chrome.app.ahiigpfcghkbjfcibpojancebdfjmoop", "/Users/u/Applications/Chrome Apps.localized/" + chrome + ".app", "EQHXZ8M8AV"},
		{edge, "com.microsoft.edgemac.app.pnibofkfjkhbdfahlpfkdbnbokbpeloi", "/Users/u/Applications/Edge Apps.localized/" + edge + ".app", "UBF8T346G9"},
		{real, "com.example.realapp." + sfx, "/Applications/" + real + ".app", ""},
	})
	for _, n := range []string{chrome, edge} {
		if _, ok := proposalFor(t, "macos", n); ok {
			t.Errorf("ingest proposed the web-app wrapper %q", n)
		}
	}
	if _, ok := proposalFor(t, "macos", real); !ok {
		t.Fatalf("ingest did not propose the real app %q", real)
	}
	backfilled := "Acme Wiki " + sfx
	seedCVEDevice(t, tn.tenantID, "pat2138-r3-pwa-bf-"+sfx, []cveTestApp{{backfilled, "1.0", "com.google.Chrome.app.abcdefghijklmnopabcdefghijklmnop"}})
	if _, err := cpepropose.Backfill(ctx, env.pool); err != nil {
		t.Fatal(err)
	}
	if _, ok := proposalFor(t, "macos", backfilled); ok {
		t.Fatalf("backfill proposed the web-app wrapper %q", backfilled)
	}
}

// Absent evidence is neutral: when the corroborating tenants' installations
// stop reporting any signer (an agent that does not report signing), the
// automatic mapping stays.
func TestCPEProposalRecheckAbsentEvidenceIsNeutral(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	tenants := []cveTestTenant{newCVETestTenant(t, "pat2138-r3-abs-a-"+sfx), newCVETestTenant(t, "pat2138-r3-abs-b-"+sfx)}
	h := newProposerHarness(t, true)
	a := autoPublishedOn(t, h, tenants, "absent")
	for i, tn := range tenants {
		postSignedAppsPayload(t, tn, a.hws[i], []signedApp{{a.app, "1.0", "com.example.absent." + sfx, "", ""}}, time.Now())
	}
	forceRecheck(t, a.p.ID)
	if _, err := h.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := proposalFor(t, "macos", a.app); p.State != cpepropose.StateAutoPublished {
		t.Fatalf("absent signer evidence demoted the mapping: %+v %s", p, derefStr(p.Reason))
	}
}

// Truncated evidence cannot shield a mapping: one tenant reporting more
// signer variants than the per-tenant cap, together with a second
// dissenting tenant, already meets the demotion rule on what was read, so
// the mapping is demoted (unread variants could only add dissent). A keep on
// truncated evidence (one flooding dissenter against two corroborating
// tenants) is recorded as evidence_truncated.
func TestCPEProposalRecheckTruncatedEvidenceStillDemotes(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	h := newProposerHarness(t, true)
	flood := func(tn cveTestTenant, a autoProduct, prefix string, n int) {
		for i := 0; i < n; i++ {
			team := testTeamID()
			postSecApps(t, tn, strings.ToUpper(fmt.Sprintf("%s-2138-4000-8000-%s%02d", sfx, prefix, i)),
				[]secApp{{a.app, "1.0", "com.example.trunc." + sfx, team, "Developer ID Application: Other (" + team + ")", "signed"}})
		}
	}

	// Keep: 1 flooding dissenter, 2 corroborating tenants.
	keepTenants := []cveTestTenant{newCVETestTenant(t, "pat2138-r3-keep-a-"+sfx), newCVETestTenant(t, "pat2138-r3-keep-b-"+sfx),
		newCVETestTenant(t, "pat2138-r3-keep-c-"+sfx)}
	kept := autoPublishedOn(t, h, keepTenants, "keeptrunc")
	flood(keepTenants[0], kept, "0000000005", 21)
	forceRecheck(t, kept.p.ID)
	if _, err := h.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	p, _ := proposalFor(t, "macos", kept.app)
	if p.State != cpepropose.StateAutoPublished {
		t.Fatalf("one flooding dissenter of three demoted the mapping: %+v %s", p, derefStr(p.Reason))
	}
	var reason string
	if err := env.pool.QueryRow(ctx, `SELECT COALESCE(evidence->>'recheck_reason', '') FROM cpe_mapping_proposals WHERE id = $1`,
		kept.p.ID).Scan(&reason); err != nil || reason != "evidence_truncated" {
		t.Fatalf("recheck_reason = %q, %v; want evidence_truncated", reason, err)
	}

	// Demote: a flooding dissenter plus a second dissenting tenant.
	tenants := []cveTestTenant{newCVETestTenant(t, "pat2138-r3-trunc-a-"+sfx), newCVETestTenant(t, "pat2138-r3-trunc-b-"+sfx)}
	a := autoPublishedOn(t, h, tenants, "trunc")
	flood(tenants[0], a, "0000000004", 21)
	flood(tenants[1], a, "0000000006", 1)
	forceRecheck(t, a.p.ID)
	if _, err := h.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := proposalFor(t, "macos", a.app); p.State != cpepropose.StateNeedsReview || derefStr(p.Reason) != "corroboration_lost" {
		t.Fatalf("flooding shielded a mapping two tenants contradict: %+v %s", p, derefStr(p.Reason))
	}
}

// An expired proposal whose product an active device reports again is
// reopened by the proposer's sweep, even when ingest never re-recorded it.
func TestCPEProposalExpiredReopenedWhenReportedAgain(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	name := "Pat2138 Comeback " + sfx
	if _, err := cpepropose.RecordUnmapped(ctx, env.pool, "", "macos", []string{name}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE cpe_mapping_proposals SET state = 'expired', state_reason = 'not_seen_30_days'
		WHERE normalized_name = $1`, cpepropose.NormalizeName(name)); err != nil {
		t.Fatal(err)
	}
	tn := newCVETestTenant(t, "pat2138-r3-comeback-"+sfx)
	seedCVEDevice(t, tn.tenantID, "pat2138-r3-comeback-"+sfx, []cveTestApp{{name, "1.0", "com.example.comeback." + sfx}})
	w := &cpepropose.Worker{Pool: env.pool, Config: cpepropose.Config{BatchSize: 1, ProposeDisabled: true}}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	p, _ := proposalFor(t, "macos", name)
	if p.State != cpepropose.StatePending {
		t.Fatalf("expired proposal reported again = %+v, want pending", p)
	}
	if n := countRows(t, `SELECT count(*) FROM cpe_mapping_proposal_audit WHERE proposal_id = $1 AND action = 'reopen'`, p.ID); n != 1 {
		t.Fatalf("%d reopen audit rows, want 1", n)
	}
}

// A person deleting the mapping behind an approved or superseded proposal
// returns it to staff (mapping_deleted), instead of the product reading
// no_mapping forever.
func TestCPEProposalStaleTerminalStatesReconciled(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	approvedName, supersededName := "Pat2138 Approvedgone "+sfx, "Pat2138 Supersededgone "+sfx
	var mappingID, supersedingID int64
	if err := env.pool.QueryRow(ctx, `INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, 'pat2138ag', 'approvedgone', 'test', 'app_name', 'curated') RETURNING id`, approvedName).Scan(&mappingID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO cpe_mapping_proposals (platform, normalized_name, display_name, state,
		chosen_cpe_vendor, chosen_cpe_product, mapping_id) VALUES ('macos', $1, $2, 'approved', 'pat2138ag', 'approvedgone', $3)`,
		cpepropose.NormalizeName(approvedName), approvedName, mappingID); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(ctx, `INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, 'pat2138sg', 'supersededgone', 'test', 'app_name', 'curated') RETURNING id`, supersededName).Scan(&supersedingID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO cpe_mapping_proposals (platform, normalized_name, display_name, state, state_reason)
		VALUES ('macos', $1, $2, 'superseded', 'mapped_by_other_path')`, cpepropose.NormalizeName(supersededName), supersededName); err != nil {
		t.Fatal(err)
	}
	w := &cpepropose.Worker{Pool: env.pool, Config: cpepropose.Config{BatchSize: 1, ProposeDisabled: true}}
	// While the mappings exist, nothing changes.
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := proposalFor(t, "macos", supersededName); p.State != cpepropose.StateSuperseded {
		t.Fatalf("superseded proposal with its mapping in place = %+v", p)
	}
	if _, err := env.pool.Exec(ctx, `DELETE FROM app_cpe_mappings WHERE id = ANY($1::bigint[])`, []int64{mappingID, supersedingID}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{approvedName, supersededName} {
		p, _ := proposalFor(t, "macos", n)
		if p.State != cpepropose.StateNeedsReview || derefStr(p.Reason) != "mapping_deleted" || p.MappingID != nil {
			t.Errorf("%s after its mapping was deleted = %+v %s, want needs_review/mapping_deleted", n, p, derefStr(p.Reason))
		}
		if c := countRows(t, `SELECT count(*) FROM cpe_mapping_proposal_audit WHERE proposal_id = $1 AND action = 'demote'`, p.ID); c != 1 {
			t.Errorf("%s: %d demote audit rows, want 1", n, c)
		}
	}
}
