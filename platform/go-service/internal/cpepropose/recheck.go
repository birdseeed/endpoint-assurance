package cpepropose

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/cvematch"
)

// Automatic mappings are re-checked, not trusted forever (PAT-2138 security
// review, P1). A mapping was published because its evidence agreed at that
// moment; the evidence is endpoint-reported and changes. Every
// recheckInterval each automatic mapping's current evidence is run through
// the deterministic checks (not the model, which is not asked again): the
// CPE product must still name the product (ProductMatches), and each
// tenant's current installations are judged for the mapping's vendor
// (installVerdict):
//
//   - corroborating: a public signer that resolves through the curated
//     aliases to the vendor;
//   - contradicting: explicitly untrusted or invalid signing (macOS ad hoc,
//     unsigned, error, untrusted or invalid; Windows Authenticode invalid or
//     unsigned), or a public signer that does not resolve to the vendor
//     (aliased to another vendor, or not aliased at all: positive evidence
//     of a different signer);
//   - neutral: no signer evidence either way (no signing status or Team ID
//     reported, a development certificate, Authenticode not collected or
//     unknown, an enterprise root the platform cannot check). Absence of
//     evidence is not evidence against the mapping.
//
// A tenant with any contradicting installation dissents; otherwise one with
// a corroborating installation corroborates; otherwise it is neutral. The
// mapping is DEMOTED exactly when at least two tenants dissent, or at least
// one does and the dissenting tenants are at least as many as the
// corroborating ones (a 1-1 tie demotes). Neutral tenants count on neither
// side. So one tenant can not remove a mapping two others corroborate, and
// a second dissenting tenant always does. A narrower dissent is recorded in
// the evidence (recheck_reason, recheck_dissent_tenants of recheck_tenants)
// and the mapping stays. With truncated evidence (a tenant over
// maxTuplesPerTenant), the tenants read still demote when they already meet
// the rule, since unread variants can only add dissent; otherwise the keep
// is recorded as evidence_truncated. So flooding variants never shields a
// mapping.
// A product with no current installation is left alone.
//
// On demotion the automatic mapping is deleted (the mapping-publish path
// re-matches every device carrying the product and withdraws its findings,
// as a revoke does) and the proposal returns to staff as needs_review /
// corroboration_lost with a 'demote' audit row. It is offered to the gate
// again automatically once its signer evidence changes
// (Evidence.SignerFingerprint). The publish-time "no other installed name
// with the same tokens" check is not repeated: an automatic mapping only
// covers names with exactly its tokens, so a newly reported such name is
// the same product name, not a wider reach.

// reasonEvidenceTruncated is recorded (never as a state reason) when a
// re-check could not read every tenant's evidence and so did not act.
const reasonEvidenceTruncated = "evidence_truncated"

// autoRow is one automatic proposal the re-check reads.
type autoRow struct {
	proposal
	Vendor, Product string
}

// recheckAuto re-checks up to recheckBatch automatic mappings not checked in
// the last recheckInterval, least recently checked first. Returns how many
// it demoted.
func (w *Worker) recheckAuto(ctx context.Context, aliases []Alias) (int, error) {
	rows, err := w.Pool.Query(ctx, `
		SELECT id, platform, normalized_name, display_name, state, mapping_id,
		       chosen_cpe_vendor, chosen_cpe_product
		FROM cpe_mapping_proposals
		WHERE state = 'auto_published'
		  AND (rechecked_at IS NULL OR rechecked_at < now() - make_interval(secs => $1))
		ORDER BY rechecked_at NULLS FIRST, id
		LIMIT $2
	`, recheckInterval.Seconds(), recheckBatch)
	if err != nil {
		return 0, fmt.Errorf("load automatic proposals: %w", err)
	}
	var due []autoRow
	for rows.Next() {
		var r autoRow
		if err := rows.Scan(&r.ID, &r.Platform, &r.Normalized, &r.DisplayName, &r.State, &r.MappingID,
			&r.Vendor, &r.Product); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan automatic proposal: %w", err)
		}
		due = append(due, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	demoted := 0
	for _, r := range due {
		ev, err := loadEvidence(ctx, w.Pool, r.Platform, r.Normalized, aliases)
		if err != nil {
			return demoted, err
		}
		reason, dissent, corroborating, tenants := "", 0, 0, 0
		if ev.InstallCount > 0 {
			reason, dissent, corroborating, tenants = recheckDissent(r, &ev, aliases)
		}
		demote := reason != "" && demoteOn(dissent, corroborating)
		if !demote && ev.TooManyTuples {
			// Every tenant is read, but a tenant over the per-tenant bound
			// may have unread variants. Unread variants can only add
			// contradictions (a tenant contradicts on any one), so what was
			// read is a lower bound on dissent and an upper bound on
			// corroboration: a demotion the read tenants already justify
			// stands (above), and a keep is recorded as truncated rather
			// than as a clean pass.
			reason = reasonEvidenceTruncated
		}
		ev.RecheckReason, ev.RecheckDissentTenants, ev.RecheckTenants = reason, dissent, tenants
		if !demote {
			var evJSON []byte
			if reason != "" {
				// Narrow dissent: recorded, not acted on.
				if evJSON, err = json.Marshal(ev); err != nil {
					return demoted, err
				}
				w.logger().Info("cpe proposer kept an automatic mapping: dissent too narrow to demote it",
					"proposal_id", r.ID, "recheck_reason", reason, "dissent_tenants", dissent, "tenants", tenants)
			}
			if _, err := w.Pool.Exec(ctx, `
				UPDATE cpe_mapping_proposals SET rechecked_at = now(), evidence = COALESCE($2::jsonb, evidence)
				WHERE id = $1 AND state = 'auto_published'`, r.ID, evJSON); err != nil {
				return demoted, fmt.Errorf("record re-check: %w", err)
			}
			continue
		}
		ok, err := w.demote(ctx, r.proposal, ReasonCorroborationLost, &ev)
		if err != nil {
			return demoted, err
		}
		if ok {
			demoted++
			w.logger().Warn("cpe proposer demoted an automatic mapping: its evidence no longer corroborates it",
				"proposal_id", r.ID, "recheck_reason", reason, "dissent_tenants", dissent, "tenants", tenants)
		}
	}
	return demoted, nil
}

// demoteOn is the demotion rule: at least two dissenting tenants, or at
// least one and no fewer than the corroborating tenants (a tie demotes).
func demoteOn(dissent, corroborating int) bool {
	return dissent >= 2 || (dissent >= 1 && dissent >= corroborating)
}

// verdict is one installation's or tenant's position on a mapping's vendor.
type verdict int

const (
	neutral verdict = iota
	corroborates
	contradicts
)

// installVerdict judges one installation for vendor (see the rule above),
// with the reason when it contradicts.
func installVerdict(platform string, in Installation, ix aliasIndex, aliases []Alias, vendor string) (verdict, string) {
	switch platform {
	case "macos":
		switch strings.ToLower(in.SigningStatus) {
		case "adhoc", "unsigned", "error", "untrusted", "invalid":
			return contradicts, ReasonSignerUntrusted
		}
	case "windows":
		switch strings.ToLower(in.SignatureState) {
		case "invalid", "unsigned":
			return contradicts, ReasonSignerUntrusted
		}
	}
	if _, _, ok := publicSigner(platform, in); !ok {
		return neutral, ""
	}
	if _, _, ok := ix.aliasedSigner(platform, in); !ok {
		return contradicts, ReasonSignerNotAliased
	}
	if c := Corroborate(platform, []Installation{in}, aliases, vendor); c.OK {
		return corroborates, ""
	}
	return contradicts, ReasonSignerVendorMismatch
}

// recheckDissent returns the first contradicting reason and how many tenants
// dissent, corroborate and report the product. A CPE product that no longer
// names the product is a global failure (every tenant dissents).
func recheckDissent(r autoRow, ev *Evidence, aliases []Alias) (reason string, dissent, corroborating, tenants int) {
	byTenant := map[string][]Installation{}
	var order []string
	for _, in := range ev.Installations {
		if _, ok := byTenant[in.Tenant]; !ok {
			order = append(order, in.Tenant)
		}
		byTenant[in.Tenant] = append(byTenant[in.Tenant], in)
	}
	tenants = len(order)
	m := ProductMatches(r.Normalized, r.Vendor, r.Product)
	ev.ProductNameMatch = &m
	if !m {
		return ReasonProductNameMismatch, tenants, 0, tenants
	}
	ev.Corroboration = corroborateEvidence(r.Platform, *ev, aliases, r.Vendor)
	ix := indexAliases(aliases)
	sort.Strings(order)
	for _, t := range order {
		tv, treason := neutral, ""
		for _, in := range byTenant[t] {
			v, why := installVerdict(r.Platform, in, ix, aliases, r.Vendor)
			if v == contradicts {
				tv, treason = contradicts, why
				break
			}
			if v == corroborates {
				tv = corroborates
			}
		}
		switch tv {
		case contradicts:
			dissent++
			if reason == "" {
				reason = treason
			}
		case corroborates:
			corroborating++
		}
	}
	return reason, dissent, corroborating, tenants
}

// reconcileDeletedMappings returns to staff, as needs_review /
// mapping_deleted, every proposal whose product has lost the mapping it
// relied on by another path (not the admin API, which moves the proposal
// itself): an auto_published or approved proposal whose mapping row is gone,
// and a superseded one that no mapping covers any more (a person deleted
// the mapping that superseded it). Otherwise the product would read
// no_mapping forever, and approving an automatic one would 409 forever.
func (w *Worker) reconcileDeletedMappings(ctx context.Context) (int, error) {
	mappings, err := loadAppMappings(ctx, w.Pool)
	if err != nil {
		return 0, err
	}
	rows, err := w.Pool.Query(ctx, `
		SELECT p.id, p.platform, p.normalized_name, p.display_name, p.state, p.mapping_id
		FROM cpe_mapping_proposals p
		WHERE (p.state IN ('auto_published', 'approved')
		       AND NOT EXISTS (SELECT 1 FROM app_cpe_mappings m WHERE m.id = p.mapping_id))
		   OR p.state = 'superseded'
		ORDER BY p.id
		LIMIT 5000`)
	if err != nil {
		return 0, fmt.Errorf("find orphaned automatic proposals: %w", err)
	}
	var orphans []proposal
	for rows.Next() {
		var p proposal
		if err := rows.Scan(&p.ID, &p.Platform, &p.Normalized, &p.DisplayName, &p.State, &p.MappingID); err != nil {
			rows.Close()
			return 0, err
		}
		if p.State == StateSuperseded && coveredOn(p, mappings) {
			continue
		}
		orphans = append(orphans, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, p := range orphans {
		ok, err := w.demote(ctx, p, ReasonMappingDeleted, nil)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// coveredOn reports whether a mapping covers the proposal's product on its
// platform, exactly as the matcher decides it.
func coveredOn(p proposal, mappings []cvematch.CPEMapping) bool {
	return len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(p.DisplayName, mappings), p.Platform)) > 0
}

// demote moves a published (or superseded) proposal back to needs_review with reason,
// deleting its automatic mapping row if it still exists, in one transaction
// with a 'demote' audit row. It re-reads the proposal under lock and does
// nothing (false) when a person or another worker changed it meanwhile.
// ev, when set, replaces the stored evidence snapshot.
func (w *Worker) demote(ctx context.Context, p proposal, reason string, ev *Evidence) (bool, error) {
	var evJSON []byte
	if ev != nil {
		b, err := json.Marshal(ev)
		if err != nil {
			return false, err
		}
		evJSON = b
	}
	done := false
	err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		before, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		if before.State != p.State || !sameID(before.MappingID, p.MappingID) {
			return nil
		}
		if p.State == StateSuperseded {
			// Re-check under the publish lock that nothing covers it now.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cpepropose.publish', 0))`); err != nil {
				return fmt.Errorf("lock publish: %w", err)
			}
			mappings, err := loadAppMappings(ctx, tx)
			if err != nil {
				return err
			}
			if coveredOn(p, mappings) {
				return nil
			}
		}
		if before.MappingID != nil {
			// Only an automatic row: a person may have curated it in place
			// through a path that did not move the proposal.
			if _, err := tx.Exec(ctx, `DELETE FROM app_cpe_mappings WHERE id = $1 AND review_state = 'auto'`,
				*before.MappingID); err != nil {
				return fmt.Errorf("delete demoted mapping: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cpe_mapping_proposals SET state = 'needs_review', state_reason = $2, mapping_id = NULL,
				evidence = COALESCE($3::jsonb, evidence), rechecked_at = now(), updated_at = now()
			WHERE id = $1
		`, p.ID, reason, evJSON); err != nil {
			return fmt.Errorf("demote proposal: %w", err)
		}
		after, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		done = true
		return writeAudit(ctx, tx, p.ID, "demote", Actor{Actor: SystemActor}, &before, after)
	})
	return done, err
}

func sameID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// expireBatch bounds the proposals one run expires.
const expireBatch = 200

// expireUnseen closes open proposals (pending, needs_review) whose product
// no active device has reported for the active-device window (30 days), and
// whose last_seen_at is at least that old, as state expired / reason
// not_seen_30_days with an 'expire' audit row (re-review P2-c). The row is
// kept, like every decided proposal, because its audit trail references it;
// ingest reopens it to pending if the product is reported again.
func (w *Worker) expireUnseen(ctx context.Context) (int, error) {
	ids, err := collectIDs(w.Pool.Query(ctx, `
		SELECT p.id FROM cpe_mapping_proposals p
		WHERE p.state IN ('pending', 'needs_review')
		  AND p.last_seen_at < now() - INTERVAL '`+activeDeviceWindow+`'
		  AND NOT EXISTS (
			SELECT 1 FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
			  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
			            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = p.platform
			  AND cpe_normalize_name(da.name) = p.normalized_name)
		ORDER BY p.last_seen_at, p.id
		LIMIT $1`, expireBatch))
	if err != nil {
		return 0, fmt.Errorf("find unseen cpe proposals: %w", err)
	}
	n := 0
	for _, id := range ids {
		err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
			before, err := snapshotProposal(ctx, tx, id)
			if err != nil {
				return err
			}
			if before.State != StatePending && before.State != StateNeedsReview {
				return nil
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cpe_mapping_proposals SET state = 'expired', state_reason = $2,
					decided_at = now(), decided_by = $3, updated_at = now()
				WHERE id = $1`, id, ReasonNotSeen30Days, SystemActor); err != nil {
				return fmt.Errorf("expire proposal: %w", err)
			}
			after, err := snapshotProposal(ctx, tx, id)
			if err != nil {
				return err
			}
			n++
			return writeAudit(ctx, tx, id, "expire", Actor{Actor: SystemActor}, &before, after)
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// reopenReported returns to pending every expired proposal whose product an
// active device reports again. Ingest also reopens on sight, but it skips a
// row another transaction holds (expireUnseen, at that very moment), and it
// only sees names whose version changed; this sweep closes that gap.
func (w *Worker) reopenReported(ctx context.Context) (int, error) {
	ids, err := collectIDs(w.Pool.Query(ctx, `
		SELECT p.id FROM cpe_mapping_proposals p
		WHERE p.state = 'expired'
		  AND EXISTS (
			SELECT 1 FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE cpe_normalize_name(da.name) = p.normalized_name
			  AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
			  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
			            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = p.platform)
		ORDER BY p.id
		LIMIT $1`, expireBatch))
	if err != nil {
		return 0, fmt.Errorf("find reported expired proposals: %w", err)
	}
	n := 0
	for _, id := range ids {
		err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
			before, err := snapshotProposal(ctx, tx, id)
			if err != nil {
				return err
			}
			if before.State != StateExpired {
				return nil
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cpe_mapping_proposals SET state = 'pending', state_reason = NULL, next_attempt_at = now(),
					last_seen_at = now(), decided_at = NULL, decided_by = NULL, updated_at = now()
				WHERE id = $1`, id); err != nil {
				return fmt.Errorf("reopen proposal: %w", err)
			}
			after, err := snapshotProposal(ctx, tx, id)
			if err != nil {
				return err
			}
			n++
			return writeAudit(ctx, tx, id, "reopen", Actor{Actor: SystemActor}, &before, after)
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
