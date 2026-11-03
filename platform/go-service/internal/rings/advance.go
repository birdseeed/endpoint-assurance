package rings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/notify"
)

// ErrNoObservations is returned by queryFailureRate when the eligible devices
// produced no install observations at all for this rollout's current ring.
//
// PAT-1002 (second review round): this used to be signalled by returning
// rate=0 with observedCount=0 and a comment telling callers they MUST check
// observedCount before trusting rate. A comment is not a contract — a future
// caller reading rate without that check reads an empty sample as 0% failure,
// i.e. as perfectly healthy, which is precisely the fail-open shape defect 11
// exists to prevent. Returning a sentinel error instead makes the no-data case
// unignorable: rate is not a number a caller can accidentally compare, because
// there is no rate to compare.
//
// It is NOT a failure to query. Callers must distinguish it from a real error
// (errors.Is) and map it to "do not advance, do not pause" — an empty sample
// is neither a pass nor a fail.
var ErrNoObservations = errors.New("rings: no install observations for this rollout's current ring")

// immediateLabels are deployed to all rings on day 0, bypassing staged rollout.
// Security-critical apps where rapid patching outweighs canary risk.
var immediateLabels = map[string]bool{
	// Browsers
	"googlechrome":  true,
	"firefox":       true,
	"microsoftedge": true,
	"brave":         true,
	"arcbrowser":    true,
	"opera":         true,
	"vivaldi":       true,
	"orion":         true,
	// Password managers
	"1password":  true,
	"1password8": true,
	"bitwarden":  true,
	"enpass":     true,
	"keepassxc":  true,
	"lastpass":   true,
	// Security tools
	"malwarebytes": true,
}

// approvalRow holds one ring_version_approvals row.
type approvalRow struct {
	ID             string
	TenantID       string
	Platform       string
	Label          string
	Version        string
	ApprovedRing   int16
	State          string
	LastAdvancedAt time.Time
}

// ringConfigRow holds a tenant_ring_config row.
type ringConfigRow struct {
	Enabled             bool
	RingCount           int
	Percentages         []int16
	SoakGapHours        int
	FailureThresholdPct float64
	MinFailuresToPause  int
	MinEstateSize       int
	ConfigVersion       int
}

// AdvanceAll runs the ring-advancement pass for all active tenants.
// Called periodically from the extractor (every ~5 min).
func AdvanceAll(ctx context.Context, pool *pgxpool.Pool, notifier *notify.Notifier) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT rva.tenant_id::text
		FROM ring_version_approvals rva
		WHERE rva.state IN ('rolling', 'paused')
	`)
	if err != nil {
		slog.Error("rings: list active tenants failed", "err", err)
		return
	}
	var tenantIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			tenantIDs = append(tenantIDs, id)
		}
	}
	rows.Close()

	for _, tenantID := range tenantIDs {
		advanceTenant(ctx, pool, tenantID, notifier)
	}
}

// advanceTenant processes all active rollout rows for one tenant.
func advanceTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, notifier *notify.Notifier) {
	cfg, found, err := loadRingConfig(ctx, pool, tenantID)
	if err != nil || !found || !cfg.Enabled {
		return
	}

	rows, err := pool.Query(ctx, `
		SELECT id::text, tenant_id::text, platform, label, version,
		       approved_ring, state, last_advanced_at
		FROM ring_version_approvals
		WHERE tenant_id = $1::uuid AND state IN ('rolling', 'paused')
		FOR UPDATE SKIP LOCKED
	`, tenantID)
	if err != nil {
		slog.Error("rings: load approvals failed", "tenant_id", tenantID, "err", err)
		return
	}
	var approvals []approvalRow
	for rows.Next() {
		var a approvalRow
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.Platform, &a.Label, &a.Version,
			&a.ApprovedRing, &a.State, &a.LastAdvancedAt,
		); err != nil {
			continue
		}
		approvals = append(approvals, a)
	}
	rows.Close()

	for _, a := range approvals {
		if err := processApproval(ctx, pool, a, cfg, notifier); err != nil {
			slog.Error("rings: process approval failed",
				"tenant_id", tenantID, "id", a.ID, "err", err)
		}
	}

	// Rebuild is also a repair pass for rows written before PAT-1134. New
	// mutations publish in the same transaction as their state change.
	if err := rebuildRingPromotions(ctx, pool, tenantID); err != nil {
		slog.Error("rings: rebuild ring_promotions failed", "tenant_id", tenantID, "err", err)
	}
}

// AutoAdvanceNote is surfaced by the rollout dashboard.
const AutoAdvanceNote = "Automatic rollout creation, advancement, completion and pause are active for macOS. Decisions use platform- and ring-scoped per-device evidence and publish atomically. Windows remains manual-only until provenance carries a stable per-device identifier."

// AutoAdvanceDisabledReason is retained for dashboard callers compiled before
// PAT-1134; it names the same current policy.
const AutoAdvanceDisabledReason = AutoAdvanceNote

// processApproval evaluates and applies one automatic rollout decision. The
// mutation helpers use compare-and-set updates and publish the resulting
// platform-scoped agent decision in the same transaction (PAT-1134), so a
// concurrent manual action wins instead of being overwritten by a stale tick.
//
// PAT-1002 made the decision logic fail closed. PAT-1134 made publication
// platform-aware and transactional. Together they make the mutations below
// safe to enable. The important retained properties are:
//
//   - Windows approvals are excluded from the automatic gate entirely and are
//     manual-only (see the branch at the top of this function). This does not
//     change when automatic advancement returns.
//   - Ring traversal follows the tenant's configured ring list rather than
//     approved_ring+1, which parked rollouts on rings no device is assigned
//     to for every ring_count except 4 (defect 8, see ConfiguredAgentRings).
//   - The two zero-sample cases are evaluated first and reported separately,
//     so no threshold comparison is ever applied to a sample that does not
//     exist and a permanent stall is distinguishable from a transient wait
//     (defect 11).
//   - queryFailureRate scopes eligible devices by platform as well as ring,
//     and returns the eligible-device count (defects 5 and 11).
//
// Manual controls remain separate and always available. Windows remains
// explicitly excluded from automatic decisions below.
func processApproval(ctx context.Context, pool *pgxpool.Pool, a approvalRow, cfg ringConfigRow, notifier *notify.Notifier) error {
	if a.State != "rolling" {
		return nil
	}

	// PAT-1002 (defect 9): Windows rollouts are MANUAL-ONLY, end to end. The
	// automatic gate is skipped for them here rather than being allowed to run
	// and always come up empty.
	//
	// Why: every automatic gate in this package is per-device — dedupe by
	// device, count one observation per device, scope devices to the ring
	// being exposed. The Windows agent's provenance payload
	// (windows/src/Service/ProvenancePoster.cs, BuildPayload, updater repo)
	// carries no per-device identifier at all: it emits tenant_id, label,
	// installed_version, available_version, state, platform and computer_name,
	// and nothing else. There is no hw_uuid, no device id, no stable
	// per-machine key. A Windows approval therefore cannot satisfy a
	// per-device evidence gate in principle, not merely in practice, and no
	// amount of Windows evidence will ever move one.
	//
	// Running the gate anyway produced the worst available outcome: a Windows
	// rollout logged "no install observations yet" forever, identical to a
	// macOS rollout whose devices genuinely had not reported, so the
	// structural impossibility read as a transient wait. Skipping explicitly
	// and saying so on every pass makes the manual-only property visible in
	// the one place an operator action cannot erase (a previous attempt
	// encoded it as state='paused' on the row, which the first resume or skip
	// silently cleared — see insertNewVersion).
	//
	// Out of scope here: the real fix is an `updater`-repo change adding a
	// per-device identifier to the Windows provenance payload (the macOS
	// emitter already sends device.hw_uuid). Once Windows emits one, this
	// branch comes out and Windows gates exactly like macOS.
	//
	// The comparison is case-insensitive on purpose. platform is constrained to
	// ('macos','windows') by a DB CHECK, so today a bare == is correct — but
	// this branch is a fail-CLOSED guard whose whole job is to stop a Windows
	// row entering the per-device gate it can never satisfy, and leaning on a
	// constraint means a value that ever bypasses it (raw SQL, a migration that
	// rebuilds the table, a future platform written by another service) falls
	// straight through into automatic gating instead. EqualFold costs nothing
	// and removes the dependency.
	if strings.EqualFold(a.Platform, "windows") {
		slog.Info("rings: windows rollout — automatic gating skipped, manual advancement only (PAT-1002)",
			"tenant_id", a.TenantID, "id", a.ID, "label", a.Label, "version", a.Version,
			"ring", a.ApprovedRing,
			"reason", "windows provenance carries no per-device identifier; a per-device evidence gate cannot be satisfied")
		return nil
	}

	now := time.Now().UTC()
	soakDur := time.Duration(cfg.SoakGapHours) * time.Hour
	soakElapsed := now.Sub(a.LastAdvancedAt) >= soakDur

	// PAT-1002 (second review round): ErrNoObservations is a VERDICT, not a
	// query failure — "the sample is empty" — and has to be separated from a
	// real error before anything else happens. eligibleDevices is still
	// populated alongside it, because the two zero-sample causes below are told
	// apart by exactly that number.
	failureRate, failureCount, observedCount, eligibleDevices, err := queryFailureRate(ctx, pool, a)
	noObservations := errors.Is(err, ErrNoObservations)
	if err != nil && !noObservations {
		slog.Warn("rings: failure rate query failed; skipping", "id", a.ID, "err", err)
		return nil
	}

	logFields := []any{
		"tenant_id", a.TenantID, "id", a.ID, "label", a.Label, "version", a.Version,
		"ring", a.ApprovedRing, "soak_elapsed", soakElapsed, "observed_count", observedCount,
		"eligible_devices", eligibleDevices,
		"failure_rate", failureRate, "failure_count", failureCount,
	}

	// Every branch below either logs why no mutation was safe or applies an
	// atomic mutation whose helper and caller both emit structured evidence.
	// PAT-1002 (defect 11): the two zero-sample cases come FIRST, before any
	// arithmetic on failureRate is allowed to influence a decision.
	//
	// Previously the auto-pause test ran first and only failed to fire on an
	// empty sample because 0.0 > threshold happens to be false for every
	// threshold >= 0 and 0 >= min_failures_to_pause happens to be false for
	// every minimum >= 1. That is a coincidence of the configured ranges, not
	// a decision: a threshold or minimum of 0 would have turned "we have no
	// data" into a real verdict. Neither branch below advances and neither
	// pauses — "no observations" is explicitly its own outcome, not a pass and
	// not a failure — but they are reported separately because their causes
	// are structurally different and only one of them ever resolves on its
	// own.
	wouldAutoPause := failureRate > cfg.FailureThresholdPct && failureCount >= cfg.MinFailuresToPause
	switch {
	case eligibleDevices == 0:
		// No device is assigned to the ring this rollout is currently
		// exposing, so no evidence for it can ever arrive and the rollout will
		// sit here indefinitely. Unlike "not reported yet" this never resolves
		// by waiting — it needs a ring-config or estate change — so it is
		// logged at Warn rather than folded into the line below. Reachable
		// with a small estate, a band that rounds to zero devices, or an
		// approved_ring stranded on a phantom value by a pre-PAT-1002
		// numeric-increment advance.
		slog.Warn("rings: no devices are assigned to this rollout's current ring — it cannot gather evidence here", logFields...)

	case noObservations:
		// PAT-1002 (second review round): this branch is now selected by
		// queryFailureRate's ErrNoObservations sentinel rather than by
		// re-deriving "observedCount == 0" here. Same outcome, but the empty
		// sample is now impossible to walk past by accident: there is no
		// meaningless 0.0 rate for a later branch to compare against, because
		// the no-data case never reaches one.
		//
		// PAT-997: an empty observation set is NOT a 0% failure rate — the
		// original fail-closed reasoning this project's second review round
		// established, kept here as an observation-only log line: even once
		// automatic advancement is re-enabled, zero observations must never
		// read as healthy. Devices DO exist in this ring (the case above
		// covers the alternative); they simply have not reported yet, so this
		// resolves on its own as they do.
		slog.Info("rings: no install observations yet from this ring's devices", logFields...)

	case wouldAutoPause:
		if err := autoPause(ctx, pool, a, failureRate, notifier); err != nil {
			return fmt.Errorf("auto-pause approval %s: %w", a.ID, err)
		}
		slog.Warn("rings: auto-paused rollout on failure-rate breach", logFields...)

	case !soakElapsed:
		slog.Debug("rings: soak not yet elapsed; not advancing this pass", logFields...)

	case failureRate > cfg.FailureThresholdPct:
		// Above threshold but below MinFailuresToPause — real signal, just
		// not (yet) enough of it to auto-pause on. Would not have advanced.
		slog.Info("rings: failure rate above threshold but below auto-pause minimum; not advancing this pass", logFields...)

	default:
		nextRing, hasNext := NextConfiguredRing(int(a.ApprovedRing), cfg.RingCount)
		if !hasNext {
			if err := completeApproval(ctx, pool, a); err != nil {
				return fmt.Errorf("complete approval %s: %w", a.ID, err)
			}
			slog.Info("rings: completed rollout at its final configured ring", logFields...)
			return nil
		}
		if err := advanceApproval(ctx, pool, a, int16(nextRing)); err != nil {
			return fmt.Errorf("advance approval %s: %w", a.ID, err)
		}
		slog.Info("rings: advanced rollout to next configured ring",
			append(logFields, "advanced_to_ring", nextRing)...)
	}
	return nil
}

// advanceApproval bumps approved_ring and atomically publishes and audits the
// decision. Its compare-and-set predicate rejects a stale scheduler snapshot.
func advanceApproval(ctx context.Context, pool *pgxpool.Pool, a approvalRow, newRing int16) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE ring_version_approvals
		SET approved_ring = $1, last_advanced_at = now(), updated_at = now()
		WHERE id = $2::uuid
		  AND state = 'rolling' AND approved_ring = $3
	`, newRing, a.ID, a.ApprovedRing)
	if err != nil {
		return fmt.Errorf("advance ring: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("advance ring: rollout changed concurrently")
	}

	if err := insertAudit(ctx, tx, a.TenantID, "rollout_advanced", a.Label, a.Version, nil,
		map[string]interface{}{"old_ring": a.ApprovedRing, "new_ring": newRing}); err != nil {
		return err
	}

	if err := PublishRingPromotionsTx(ctx, tx, a.TenantID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	slog.Info("rings: advanced",
		"tenant_id", a.TenantID, "label", a.Label, "version", a.Version,
		"from", a.ApprovedRing, "to", newRing)
	return nil
}

// completeApproval marks the rollout as completed (reached GA), publishes the
// resulting projection and rejects a stale scheduler snapshot.
func completeApproval(ctx context.Context, pool *pgxpool.Pool, a approvalRow) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE ring_version_approvals
		SET state = 'completed', updated_at = now()
		WHERE id = $1::uuid
		  AND state = 'rolling' AND approved_ring = $2
	`, a.ID, a.ApprovedRing)
	if err != nil {
		return fmt.Errorf("complete approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("complete approval: rollout changed concurrently")
	}

	if err := insertAudit(ctx, tx, a.TenantID, "rollout_completed", a.Label, a.Version, nil,
		map[string]interface{}{"final_ring": a.ApprovedRing}); err != nil {
		return err
	}
	if err := PublishRingPromotionsTx(ctx, tx, a.TenantID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	slog.Info("rings: completed", "tenant_id", a.TenantID, "label", a.Label, "version", a.Version)
	return nil
}

// autoPause pauses a rolling rollout due to failure threshold breach, then
// atomically publishes the explicit nobody-approved decision.
func autoPause(ctx context.Context, pool *pgxpool.Pool, a approvalRow, rate float64, notifier *notify.Notifier) error {
	reason := fmt.Sprintf("auto: failure rate %.1f%%", rate)

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE ring_version_approvals
		SET state = 'paused', paused_reason = $1, updated_at = now()
		WHERE id = $2::uuid
		  AND state = 'rolling' AND approved_ring = $3
	`, reason, a.ID, a.ApprovedRing)
	if err != nil {
		return fmt.Errorf("auto-pause: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("auto-pause: rollout changed concurrently")
	}

	if err := insertAudit(ctx, tx, a.TenantID, "rollout_auto_paused", a.Label, a.Version, nil,
		map[string]interface{}{"failure_rate": rate, "reason": reason, "ring": a.ApprovedRing}); err != nil {
		return err
	}
	if err := PublishRingPromotionsTx(ctx, tx, a.TenantID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	slog.Warn("rings: auto-paused",
		"tenant_id", a.TenantID, "label", a.Label, "version", a.Version,
		"ring", a.ApprovedRing, "failure_rate", rate)

	if notifier != nil {
		notifier.Dispatch(ctx, notify.Event{
			TenantID: a.TenantID,
			Kind:     notify.KindRolloutAutoPaused,
			Label:    a.Label,
			Version:  a.Version,
			Reason:   reason,
		})
	}
	return nil
}

// ObserveNewVersion checks provenance records for a label+platform combo and
// inserts a rolling row if we see a version that has no existing approval row.
//
// This and AdvanceAll are sibling calls from the extractor's ring tick. They
// stay separate so observation creates rows before the same tick evaluates
// active rollouts.
//
// PAT-997: body is client-defined and archived verbatim (see docs/API.md), and
// the two live emitters in the updater repo have never shared one shape:
//
//   - macOS (endpoint/patched-update.sh, emit_provenance): nests under a
//     top-level "app" object — body->'app'->>'label',
//     body->'app'->>'available_version'.
//   - Windows (windows/src/Service/ProvenancePoster.cs, BuildPayload): always
//     top-level — body->>'label', body->>'available_version'.
//
// So the "mixed shapes" seen in provenance_records are a platform split, not
// a shape that drifted over time within one emitter — both shapes are live
// and permanent. COALESCE reads whichever this row actually has.
//
// PAT-997 (third review round): the version field used to be
// version_after/installed_version — the version actually installed after the
// attempt, which a FAILED attempt never advances (see queryFailureRate's doc
// comment for the full emitter-behaviour citation). That meant a failed 2.0
// install attempt on a device still running 1.0 would surface "1.0" here as
// the "latest observed version" — a version that isn't new at all — and
// insertNewVersion's supersede step (below) would then supersede the
// genuinely active 2.0 rolling/paused row, because its own version-inequality
// check ("version <> $4") only compares against that wrong "1.0". Reading
// available_version instead — the ATTEMPTED version, populated identically on
// success and failure by both emitters — fixes the wrong-version case: a
// failed 2.0 attempt now correctly surfaces "2.0", not "1.0".
//
// PAT-997 (fourth review round): that fix was incomplete. available_version
// alone doesn't distinguish "a version was genuinely seen working" from "a
// version was merely attempted and failed" — so a FAILED attempt at a
// DIFFERENT, newer version (e.g. a failed 3.0 attempt while an active,
// healthy 2.0 rollout is rolling) still superseded the healthy rollout,
// because insertNewVersion's supersede step doesn't care why it was called,
// only that the version differs. A single flaky failed download at some
// version number should never be able to kill an in-flight rollout for a
// completely different version. Fixed by requiring a SUCCESS-vocabulary
// outcome/state (the same lists queryFailureRate uses for "success") before a
// row counts as "observed" at all: only a version that has actually been
// seen working somewhere creates or supersedes anything. A failed attempt —
// at any version, matching or not — now produces no row and supersedes
// nothing, full stop. record_type is also now an ALLOWLIST
// (COALESCE(record_type,'third_party_update') = 'third_party_update',
// matching queryFailureRate/queryWaveBars — permissive of an ABSENT
// record_type since Windows never sends one, strict on any other explicit
// value) rather than the implicit "anything with a label survives" behaviour
// silently relied on before: a forged record_type could otherwise carry
// update-shaped fields and create/supersede rollouts same as a real one.
//
// Known design gap, not a bug fixed here (PAT-1002): a version that only
// ever FAILS never gets an approval row at all — success is now required for
// "observed" (see above), and a version with zero successful installs
// anywhere never satisfies that, so it never appears in
// ring_version_approvals or the dashboard. That's the correct call for THIS
// ticket's scope (a failure isn't evidence a version is safe to track), but
// it means there is currently no visibility path for "this version has been
// attempted N times and failed every time" — an operator has no signal that
// something is being tried and not working, only silence. Not a live
// regression while this function is scheduler-unreachable (see the call
// site in extractor.go), but PAT-1002 needs to design real visibility for
// failure-only versions, not just carry this gap forward silently.
func ObserveNewVersions(ctx context.Context, pool *pgxpool.Pool) {
	// Find the most recent version per (tenant, platform, label) seen in provenance
	// that has no ring_version_approvals row for that tenant.
	rows, err := pool.Query(ctx, `
		WITH latest_prov AS (
			SELECT DISTINCT ON (
				r.tenant_id,
				COALESCE(r.body->>'platform', 'macos'),
				COALESCE(r.body->'app'->>'label', r.body->>'label')
			)
				r.tenant_id::text AS tenant_id,
				COALESCE(r.body->>'platform', 'macos') AS platform,
				COALESCE(r.body->'app'->>'label', r.body->>'label') AS label,
				COALESCE(r.body->'app'->>'available_version', r.body->>'available_version') AS version
			FROM provenance_records r
			JOIN tenant_ring_config trc ON trc.tenant_id = r.tenant_id AND trc.enabled = true
			WHERE COALESCE(r.body->'app'->>'label', r.body->>'label') IS NOT NULL
			  AND COALESCE(r.body->'app'->>'available_version', r.body->>'available_version') IS NOT NULL
			  AND COALESCE(r.body->>'outcome', r.body->>'state') IN ('installed', 'already_current', 'uptodate')
			  AND COALESCE(r.body->>'record_type', 'third_party_update') = 'third_party_update'
			ORDER BY
				r.tenant_id,
				COALESCE(r.body->>'platform', 'macos'),
				COALESCE(r.body->'app'->>'label', r.body->>'label'),
				r.received_at DESC
		)
		SELECT lp.tenant_id, lp.platform, lp.label, lp.version
		FROM latest_prov lp
		LEFT JOIN ring_version_approvals rva
			ON rva.tenant_id::text = lp.tenant_id
			AND rva.platform = lp.platform
			AND rva.label = lp.label
			AND rva.version = lp.version
		WHERE rva.id IS NULL
	`)
	if err != nil {
		slog.Error("rings: observe new versions query failed", "err", err)
		return
	}
	defer rows.Close()

	type newVer struct{ tenantID, platform, label, version string }
	var newVersions []newVer
	for rows.Next() {
		var nv newVer
		if err := rows.Scan(&nv.tenantID, &nv.platform, &nv.label, &nv.version); err == nil {
			newVersions = append(newVersions, nv)
		}
	}

	for _, nv := range newVersions {
		insertNewVersion(ctx, pool, nv.tenantID, nv.platform, nv.label, nv.version)
	}
}

func insertNewVersion(ctx context.Context, pool *pgxpool.Pool, tenantID, platform, label, version string) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize observers for one tenant/platform/label even when no approval
	// row exists yet. Row locks cannot protect an empty result set, so without
	// this transaction-scoped lock concurrent observations of two versions can
	// both decide they are newest and leave whichever commits last active.
	lockKey := fmt.Sprintf("%s|%d:%s|%d:%s", tenantID, len(platform), platform, len(label), label)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		slog.Error("rings: lock observed version stream failed", "err", err)
		return
	}

	// received_at orders reports, not software versions: an older queued
	// success can arrive after a newer one. Refuse any candidate that is not
	// strictly newer than every version already recorded for this stream. The
	// comparator deliberately fails closed on ambiguous/equivalent numeric
	// forms (e.g. prerelease suffixes compare equal), requiring an operator to
	// resolve a genuine vendor version reset rather than rolling the gate back.
	rows, err := tx.Query(ctx, `
		SELECT version
		FROM ring_version_approvals
		WHERE tenant_id = $1::uuid AND platform = $2 AND label = $3
	`, tenantID, platform, label)
	if err != nil {
		slog.Error("rings: load observed version history failed", "err", err)
		return
	}
	var priorVersions []string
	for rows.Next() {
		var prior string
		if err := rows.Scan(&prior); err != nil {
			rows.Close()
			slog.Error("rings: scan observed version history failed", "err", err)
			return
		}
		priorVersions = append(priorVersions, prior)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		slog.Error("rings: read observed version history failed", "err", err)
		return
	}
	rows.Close()
	for _, prior := range priorVersions {
		if cvematch.CompareVersions(version, prior) <= 0 {
			slog.Warn("rings: ignored non-monotonic observed version",
				"tenant_id", tenantID, "platform", platform, "label", label,
				"candidate_version", version, "recorded_version", prior)
			return
		}
	}

	// Supersede any older rolling/paused rows for this label.
	superseded, err := tx.Exec(ctx, `
		UPDATE ring_version_approvals
		SET state = 'superseded', updated_at = now()
		WHERE tenant_id = $1::uuid AND platform = $2 AND label = $3
		  AND state IN ('rolling', 'paused')
		  AND version <> $4
	`, tenantID, platform, label, version)
	if err != nil {
		slog.Error("rings: supersede old versions failed", "err", err)
		return
	}

	// PAT-1002 (defect 9): a newly observed Windows version starts "rolling"
	// at ring 0, exactly like macOS. It used to start "paused" with an
	// explanatory paused_reason, as a way of surfacing that Windows can never
	// auto-advance (no per-device identifier in Windows provenance — see
	// processApproval's Windows branch). That marker did not survive contact
	// with the manual endpoints it was telling operators to use: both
	// RingRolloutResumeHandler and RingRolloutSkipHandler set paused_reason =
	// NULL and state = 'rolling' (internal/handlers/ring_rollout.go), so the
	// FIRST manual action an operator took erased it. After that the row was
	// byte-identical to a macOS rolling row, and the stall it was warning
	// about was silently back — with no way to tell the two apart, which is
	// the precise failure mode the marker existed to prevent.
	//
	// Overloading 'paused' also conflated two different facts: "an operator
	// deliberately halted this rollout" and "this platform is manual-only".
	// Only the first belongs in a mutable state column. The second is a
	// property of the platform, so it now lives in code (processApproval's
	// Windows branch) where no operator action can clear it, and is restated
	// on every pass in the log.
	approvedRing := int16(0)
	state := "rolling"
	var pausedReason *string
	if immediateLabels[label] {
		approvedRing = 3
		state = "completed"
	}

	inserted, err := tx.Exec(ctx, `
		INSERT INTO ring_version_approvals (tenant_id, platform, label, version, approved_ring, state, paused_reason)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, platform, label, version) DO NOTHING
	`, tenantID, platform, label, version, approvedRing, state, pausedReason)
	if err != nil {
		slog.Error("rings: insert new version failed", "err", err)
		return
	}
	if inserted.RowsAffected() != 1 {
		// A concurrent observer inserted this exact version first. Roll back this
		// transaction so it cannot duplicate supersede or audit side effects.
		return
	}

	if superseded.RowsAffected() > 0 {
		if err := insertAudit(ctx, tx, tenantID, "rollout_superseded", label, version, nil,
			map[string]interface{}{"superseded_count": superseded.RowsAffected()}); err != nil {
			slog.Error("rings: audit superseded versions failed", "err", err)
			return
		}
	}

	// The new approval and its signed agent projection commit together. In
	// particular, an immediate completed label clears any prior active gate
	// without waiting for a later extractor tick.
	if err := PublishRingPromotionsTx(ctx, tx, tenantID); err != nil {
		slog.Error("rings: publish new version failed", "err", err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("rings: commit new version failed", "err", err)
		return
	}
	if immediateLabels[label] {
		slog.Info("rings: immediate label — approved ring 3 on day 0",
			"tenant_id", tenantID, "label", label, "version", version)
	} else if platform == "windows" {
		slog.Info("rings: windows platform — rolling at ring 0, advancement is manual only (PAT-1002)",
			"tenant_id", tenantID, "label", label, "version", version)
	}
	slog.Info("rings: observed new version and published rollout decision",
		"tenant_id", tenantID, "platform", platform, "label", label,
		"version", version, "state", state, "approved_ring", approvedRing)
}

// rolloutPromotion is the platform-aware wire entry. approval="nobody" is an
// explicit deny: agents must not reinterpret an absent approved_ring as GA.
// It is emitted for paused rows, including a pause in the first ring.
type rolloutPromotion struct {
	Approval     string `json:"approval"`
	ApprovedRing *int16 `json:"approved_ring,omitempty"`
	Version      string `json:"version"`
}

// rebuildRingPromotions is the periodic repair path. All normal mutations use
// PublishRingPromotionsTx before committing their rollout state.
func rebuildRingPromotions(ctx context.Context, pool *pgxpool.Pool, tenantID string) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := PublishRingPromotionsTx(ctx, tx, tenantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PublishRingPromotionsTx derives both rollout projections and writes them in
// the transaction which changed the source rows. The scoped projection is the
// authority for current agents. The legacy label-only projection remains for
// old agents and deliberately takes the most restrictive platform decision,
// never the most permissive one.
func PublishRingPromotionsTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	// Serialize publication before reading rollout rows. Without this lock two
	// actions on different labels could each read a pre-commit snapshot, then
	// take turns overwriting agent_config with projections missing the other's
	// decision. The config row is the per-tenant publication mutex.
	var configTenant string
	if err := tx.QueryRow(ctx, `
		SELECT tenant_id::text FROM agent_config
		WHERE tenant_id = $1::uuid
		FOR UPDATE
	`, tenantID).Scan(&configTenant); err != nil {
		return fmt.Errorf("lock agent config for rollout publication: %w", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT platform, label, version, approved_ring, state
		FROM (
			SELECT *, row_number() OVER (
				PARTITION BY platform, label
				ORDER BY updated_at DESC, created_at DESC
			) AS selection_rank
			FROM ring_version_approvals
			WHERE tenant_id = $1::uuid AND state IN ('rolling', 'paused')
		) selected
		WHERE selection_rank = 1
		ORDER BY platform, label
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load approvals for promotions: %w", err)
	}
	defer rows.Close()

	scoped := map[string]map[string]rolloutPromotion{}
	legacy := map[string]struct {
		Version string
		Ring    int16
	}{}
	for rows.Next() {
		var platform, label, version, state string
		var approvedRing int16
		if err := rows.Scan(&platform, &label, &version, &approvedRing, &state); err != nil {
			return fmt.Errorf("scan approval for promotions: %w", err)
		}
		if scoped[platform] == nil {
			scoped[platform] = map[string]rolloutPromotion{}
		}
		entry := rolloutPromotion{Version: version}
		legacyRing := approvedRing
		if state == "paused" {
			entry.Approval = "nobody"
			// Old agents cannot represent nobody. Ring 0 is their most
			// restrictive valid value. It cannot represent a first-ring pause;
			// automatic mutation must only be enabled after scoped-capable agents
			// are deployed. PAT-1118 verified that prerequisite before activation.
			legacyRing = 0
		} else {
			entry.Approval = "up_to_ring"
			entry.ApprovedRing = &approvedRing
		}
		scoped[platform][label] = entry

		// Old clients consume only a label and ring. Cross-platform collision
		// therefore resolves toward denial, while current clients consume the
		// scoped entry and retain exact platform semantics.
		if current, ok := legacy[label]; !ok || legacyRing < current.Ring {
			legacy[label] = struct {
				Version string
				Ring    int16
			}{Version: version, Ring: legacyRing}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate approvals for promotions: %w", err)
	}

	legacyWire := map[string]struct {
		Version      string `json:"version"`
		ApprovedRing int16  `json:"approved_ring"`
	}{}
	for label, entry := range legacy {
		legacyWire[label] = struct {
			Version      string `json:"version"`
			ApprovedRing int16  `json:"approved_ring"`
		}{Version: entry.Version, ApprovedRing: entry.Ring}
	}
	legacyRaw := json.RawMessage("null")
	if len(legacyWire) != 0 {
		b, err := json.Marshal(legacyWire)
		if err != nil {
			return fmt.Errorf("marshal legacy ring_promotions: %w", err)
		}
		legacyRaw = b
	}
	// {} is intentional: its presence tells new agents that this scoped
	// contract is authoritative, even when no current rollout exists.
	scopedRaw, err := json.Marshal(scoped)
	if err != nil {
		return fmt.Errorf("marshal scoped ring_promotions: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE agent_config
		SET body = jsonb_set(
				jsonb_set(body, '{ring_promotions}', $1::jsonb, true),
				'{ring_promotions_scoped}', $2::jsonb, true),
		    config_version = config_version + 1,
		    issued_at = now()
		WHERE tenant_id = $3::uuid
		  AND (body->'ring_promotions' IS DISTINCT FROM $1::jsonb
		       OR body->'ring_promotions_scoped' IS DISTINCT FROM $2::jsonb)
	`, string(legacyRaw), string(scopedRaw), tenantID)
	if err != nil {
		return fmt.Errorf("update ring promotions in agent_config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		slog.Debug("rings: promotions unchanged, config_version not bumped", "tenant_id", tenantID)
	}
	return nil
}

// queryFailureRate computes the failure rate for a given approval row.
// Counts installs that failed vs succeeded, one observation per device, among
// devices in the ring CURRENTLY being exposed (effective ring == approved_ring
// — not <=) on THIS approval's platform, since last_advanced_at.
//
// PAT-997 follow-up review (Codex, second pass) found the first version of
// this fix still wrong in four ways. All four are addressed here:
//
//  1. Version match field. The WHERE clause used to require
//     version_after/installed_version (the POST-attempt version) to equal the
//     target. But on a failed install both emitters leave that field at the
//     PRE-attempt version — see insertProvenanceMacOSInstall's doc comment in
//     advance_db_test.go and InventoryCollector.ProcessEntryAsync (updater
//     repo): a failure never advances installed_version/version_after. So
//     that filter silently excluded every genuine failure of the target
//     version while keeping every success — a gate meant to catch bad
//     rollouts was structurally fed only good news. The field that carries
//     the ATTEMPTED version regardless of outcome is available_version:
//     macOS scrapes it from the Installomator log before the verification
//     step that can fail (patched-update.sh, "Latest version of ... is ..." /
//     PATCHED_AVAIL_VER, set prior to the rc-based outcome case statement);
//     Windows sets AvailableVersion identically on both the success and
//     failure branches of ProcessEntryAsync. Matching on available_version
//     instead of version_after/installed_version now catches failures.
//  2. Ring scope. "<= approved_ring" let a device from an EARLIER ring (already
//     exposed and already justified its own past advance) keep re-satisfying
//     observedCount forever — e.g. ring-0 devices pinging "already_current"
//     after the rollout had already widened to ring 1, letting ring 1 advance
//     to ring 2 on ring-0's old evidence with zero ring-1 devices having
//     reported anything. Changed to "= approved_ring": only the ring actually
//     opened by the last advance counts as evidence for the NEXT advance.
//  3. Platform scope. a.Platform was never passed to the query, so in a mixed
//     macOS/Windows estate, macOS installs of the same label+version could
//     satisfy (or auto-pause) a Windows approval row and vice versa — quietly
//     defeating the platform-blind-Windows-fails-closed behavior this
//     package's tests assert. Added COALESCE(body->>'platform','macos') = $N.
//  4. One observation per device, and no non-update record types. Without a
//     latest-per-device pick, a single device polling/retrying repeatedly
//     could inflate observedCount, or single-handedly satisfy
//     min_failures_to_pause by retrying a failed install. provenance is
//     client-supplied JSON archived verbatim under a shared tenant secret —
//     this is decision-signal injection, not SQL injection, but the fix is
//     the same instinct: don't let one client-controlled stream of events
//     out-vote reality. DISTINCT ON (hw_uuid) ORDER BY received_at DESC picks
//     one row per device (mirrors ObserveNewVersions' PAT-995-safe pattern:
//     DISTINCT ON list matches the ORDER BY's leading expressions). record_type
//     is an ALLOWLIST (third-review-round fix — a denylist of just
//     'app_uninstall' let any OTHER forged record_type, e.g. 'inventory',
//     through with update-shaped fields): permissive of an ABSENT record_type,
//     since the Windows emitter never sends one at all, but requires an
//     explicit value to be exactly 'third_party_update' — nothing else, forged
//     or otherwise, can be laundered into install evidence.
//
// Success/failure vocabulary differs by emitter and lives in different
// top-level keys, but the two vocabularies never collide, so one COALESCE
// plus one pair of IN-lists covers both:
//   - macOS: top-level "outcome" (endpoint/patched-update.sh) — failures are
//     "verification_failed" / "error" / "version_blocked"; successes are
//     "installed" / "already_current". "ring_gated" is also a value of this
//     same field (not a separate boolean key — PAT-506,
//     endpoint/patched-update.sh:1425), so it's excluded from both lists by
//     construction, same effect as the old (nonexistent) ring_gated filter.
//   - Windows: top-level "state" (ProvenancePoster.cs BuildPayload, values
//     from AppState.ToString().ToLowerInvariant()) — failures are
//     "verificationfailed" / "error"; successes are "uptodate" (Windows uses
//     this one state for both "was already current" and "just installed
//     successfully", disambiguated only by last_action, which we don't need
//     here). RingGated is never present in the Windows payload at all (see
//     above), so a ring-gated Windows skip surfaces as state
//     "uptodate"/"updateavailable" with no update having actually happened —
//     already excluded from both lists since neither is in them.
//
// hw_uuid is compared case-insensitively (lower() both sides): devices.hw_uuid
// is a Postgres uuid column, which normalizes to lowercase on ::text cast,
// while macOS's IOPlatformUUID (what patched-update.sh sends) is
// conventionally uppercase. A bare text equality check against production
// data confirmed this: it silently matched zero rows despite the same
// device appearing on both sides. Deliberately not a ::uuid cast on the
// body-derived side — body is arbitrary client JSON, and a malformed value
// there must fail the match, not throw and abort the whole query.
//
// PAT-1002: two further changes.
//
//	a. Platform scoping now applies to the DEVICE side too, not just the
//	   provenance side. Filtering only the provenance rows left the device
//	   join open: a body claiming "platform":"windows" while carrying the
//	   device.hw_uuid of a macOS device joined to that macOS device and
//	   satisfied a Windows approval's gate (and vice versa). devices.os is
//	   NULLABLE between enrolment and the first inventory upload
//	   (migrations/0039_nullable_os.sql), so the filter is permissive of NULL
//	   and strict on any explicit value — the same "absent is fine, wrong is
//	   not" shape already used for record_type. A device with no os yet has
//	   never uploaded inventory and so has no provenance to contribute
//	   anyway; narrowing it out would only risk shrinking the eligible set for
//	   no gain.
//	b. The eligible-device count is returned alongside the observation counts.
//	   "Zero observations" has two structurally different causes that used to
//	   be indistinguishable in the log: devices exist in this ring but none
//	   has reported yet (transient — wait), versus no device is assigned to
//	   this ring at all (permanent — the rollout can never gather evidence
//	   here and will sit forever). Both must block advancement, but only the
//	   second is a stall an operator needs to act on, so processApproval
//	   reports them as distinct outcomes. Costs one scalar subquery on an
//	   already-materialized CTE, on a ~5-minute cadence.
//	c. An empty sample returns ErrNoObservations rather than a zero rate. See
//	   that sentinel's doc comment and the total == 0 branch below.
func queryFailureRate(ctx context.Context, pool *pgxpool.Pool, a approvalRow) (rate float64, failCount int, observedCount int, eligibleDevices int, err error) {
	var failures, successes int
	err = pool.QueryRow(ctx, `
		WITH eligible_devices AS (
			SELECT id, lower(hw_uuid::text) AS hw_uuid
			FROM devices
			WHERE tenant_id = $1::uuid
			  AND COALESCE(ring_override, ring_computed, 3) = $2
			  AND (os IS NULL OR lower(os) = $4)
		),
		prov AS (
			SELECT DISTINCT ON (lower(pr.body->'device'->>'hw_uuid'))
				COALESCE(pr.body->>'outcome', pr.body->>'state') AS outcome_or_state
			FROM provenance_records pr
			JOIN eligible_devices ed ON ed.hw_uuid = lower(pr.body->'device'->>'hw_uuid')
			WHERE pr.tenant_id = $1::uuid
			  AND pr.received_at > $3
			  AND COALESCE(pr.body->>'platform', 'macos') = $4
			  AND COALESCE(pr.body->'app'->>'label', pr.body->>'label') = $5
			  AND COALESCE(pr.body->'app'->>'available_version', pr.body->>'available_version') = $6
			  AND COALESCE(pr.body->>'record_type', 'third_party_update') = 'third_party_update'
			ORDER BY lower(pr.body->'device'->>'hw_uuid'), pr.received_at DESC
		)
		SELECT
			(SELECT COUNT(*) FROM eligible_devices)                                                                              AS eligible,
			COUNT(*) FILTER (WHERE outcome_or_state IN ('verification_failed', 'error', 'version_blocked', 'verificationfailed')) AS failures,
			COUNT(*) FILTER (WHERE outcome_or_state IN ('installed', 'already_current', 'uptodate'))                              AS successes
		FROM prov
	`, a.TenantID, a.ApprovedRing, a.LastAdvancedAt, a.Platform, a.Label, a.Version,
	).Scan(&eligibleDevices, &failures, &successes)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	total := failures + successes
	if total == 0 {
		// PAT-1002 (defect 11, tightened in the second review round): an empty
		// sample has NO failure rate. There is deliberately no 0/0 here and no
		// default-to-pass.
		//
		// The first version of this returned (0, 0, 0, eligible, nil) and
		// documented that callers MUST branch on observedCount == 0 before
		// reading rate. That made correctness optional: the padding 0.0 is
		// indistinguishable from a real, healthy 0% rate, so a caller that
		// forgets the check silently treats "we know nothing" as "everything
		// passed" — the exact fail-open reading defect 11 exists to remove.
		// ErrNoObservations makes the check mandatory: the only way to get a
		// rate out of this function is for a rate to exist. eligibleDevices is
		// still returned so the caller can tell "nobody has reported yet" from
		// "nobody is in this ring".
		return 0, 0, 0, eligibleDevices, ErrNoObservations
	}
	return float64(failures) / float64(total) * 100, failures, total, eligibleDevices, nil
}

// loadRingConfig reads the tenant_ring_config row.
func loadRingConfig(ctx context.Context, pool *pgxpool.Pool, tenantID string) (ringConfigRow, bool, error) {
	var cfg ringConfigRow
	err := pool.QueryRow(ctx, `
		SELECT enabled, ring_count, percentages, soak_gap_hours,
		       failure_threshold_pct, min_failures_to_pause, min_estate_size, config_version
		FROM tenant_ring_config
		WHERE tenant_id = $1::uuid
	`, tenantID).Scan(
		&cfg.Enabled, &cfg.RingCount, &cfg.Percentages, &cfg.SoakGapHours,
		&cfg.FailureThresholdPct, &cfg.MinFailuresToPause, &cfg.MinEstateSize, &cfg.ConfigVersion,
	)
	if err != nil {
		if isNoRows(err) {
			return ringConfigRow{}, false, nil
		}
		return ringConfigRow{}, false, err
	}
	return cfg, true, nil
}

func insertAudit(ctx context.Context, tx pgx.Tx, tenantID, changeType, label, version string, deviceID *string, extra interface{}) error {
	var extraJSON []byte
	if extra != nil {
		var err error
		extraJSON, err = json.Marshal(extra)
		if err != nil {
			return fmt.Errorf("marshal audit extra: %w", err)
		}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO ring_config_changes (tenant_id, change_type, label, version, device_id, new_value)
		VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6::jsonb)
	`, tenantID, changeType, label, version, deviceID, extraJSON)
	return err
}

func isNoRows(err error) bool {
	return err != nil && err.Error() == "no rows in result set"
}
