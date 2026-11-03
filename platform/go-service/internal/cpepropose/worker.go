package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/metrics"
)

// SystemActor is the audit actor for every automatic proposer action.
const SystemActor = "cpe_proposer"

// Config is the worker's configuration (see LoadConfig for the env).
type Config struct {
	// AutoPublish allows the gate to publish. False sends every proposal to
	// staff review whatever the evidence (CPE_AUTO_PUBLISH_ENABLED=false).
	AutoPublish bool
	// BatchSize bounds the proposals one RunOnce processes.
	BatchSize int
	// MaxNVDAttempts is how many failed candidate searches a proposal gets
	// before it goes to staff review as nvd_unavailable.
	MaxNVDAttempts int
	// ModelRetryAfter is how long a model_unavailable proposal waits before
	// the worker offers it to the model again (only when a model is
	// configured).
	ModelRetryAfter time.Duration
	// ProposeDisabled stops claiming and processing proposals (no NVD or
	// model call) while the maintenance sweeps (reconciliation, the
	// automatic-mapping re-check, expiry) keep running
	// (CPE_PROPOSER_ENABLED=false).
	ProposeDisabled bool
}

// DefaultConfig is the production default.
func DefaultConfig() Config {
	return Config{AutoPublish: true, BatchSize: 10, MaxNVDAttempts: 5, ModelRetryAfter: 6 * time.Hour}
}

// Worker processes pending proposals: candidates, model choice, gate,
// publish or needs_review. Never runs inside an ingest transaction.
type Worker struct {
	Pool    *pgxpool.Pool
	Dict    CandidateSource
	Chooser Chooser // nil: no model configured
	// NoModelReason is the degraded reason when Chooser is nil:
	// model_unavailable (no key) or model_zdr_unconfirmed (a key, but
	// CPE_MODEL_ZDR_CONFIRMED is not true). "" reads as model_unavailable.
	NoModelReason string
	Config        Config
	Logger        *slog.Logger
}

func (w *Worker) noModelReason() string {
	if w.NoModelReason != "" {
		return w.NoModelReason
	}
	return ReasonModelUnavailable
}

// RunResult summarises one RunOnce.
type RunResult struct {
	Claimed       int
	AutoPublished int
	NeedsReview   int
	Superseded    int
	Retrying      int
	Failed        int
	// Demoted counts automatic mappings the re-check removed because their
	// evidence no longer passes the gate; Reconciled counts automatic
	// proposals whose mapping another path deleted.
	Demoted    int
	Reconciled int
	// Expired counts open proposals closed because no active device has
	// reported the product for 30 days; Reopened counts expired ones an
	// active device reports again.
	Expired  int
	Reopened int
	// Degraded is the worker's health reason this run ("" when ok):
	// model_unavailable when no model is configured or a call failed,
	// nvd_unavailable when a candidate search failed.
	Degraded string
}

// proposal is one claimed row.
type proposal struct {
	ID          int64
	Platform    string
	Normalized  string
	DisplayName string
	State       string
	Reason      *string
	Candidates  []Candidate
	FetchedAt   *time.Time
	Attempts    int
	MappingID   *int64
	// Fingerprint is the stored evidence's signer_fingerprint.
	Fingerprint string
}

// Lease and per-row bound. Rows are claimed one at a time, so a lease only
// has to outlast one row: at worst two keyword searches (each up to four
// paced attempts under httpretry's 3 minute cap) and one model call (2
// minute cap). rowTimeout cuts a row off well before its lease can expire,
// so a second extractor never processes a row this one still holds.
const (
	leaseDuration = 30 * time.Minute
	rowTimeout    = 20 * time.Minute
	// rankWindow bounds how many due rows one run ranks by reach.
	rankWindow = 500
	// privateRecheckAfter is how often a single_tenant proposal is re-read
	// from local data in case a second tenant has started reporting it.
	// Nothing leaves the platform for it until one has.
	privateRecheckAfter = 24 * time.Hour
	// recheckInterval and recheckBatch pace the automatic-mapping re-check.
	recheckInterval = 6 * time.Hour
	recheckBatch    = 50
)

// RunOnce reconciles published proposals, re-checks automatic mappings,
// then claims up to BatchSize due proposals one at a time, those affecting
// the most tenants and devices first, and processes each. Claiming is a
// lease (next_attempt_at pushed forward under FOR UPDATE SKIP LOCKED), so
// two extractors never process the same row, and a crash mid-row only
// delays it. Errors on one row are recorded on that row; RunOnce returns an
// error only when it could not claim at all.
func (w *Worker) RunOnce(ctx context.Context) (RunResult, error) {
	var res RunResult
	logger := w.logger()
	cfg := w.Config
	if cfg.BatchSize <= 0 {
		cfg = DefaultConfig()
	}
	modelConfigured := w.Chooser != nil
	aliases, err := w.maintain(ctx, &res)
	if err != nil {
		return res, err
	}
	if cfg.ProposeDisabled {
		w.recordDisabled(ctx, res)
		return res, nil
	}
	ranked, err := w.rankDue(ctx, modelConfigured)
	if err != nil {
		return res, err
	}
	if !modelConfigured {
		res.Degraded = w.noModelReason()
	}
	var mappings []cvematch.CPEMapping
	if len(ranked) > 0 {
		if mappings, err = loadAppMappings(ctx, w.Pool); err != nil {
			return res, err
		}
	}
	for res.Claimed < cfg.BatchSize && len(ranked) > 0 {
		p, ok, err := w.claimOne(ctx, ranked, modelConfigured)
		if err != nil {
			return res, err
		}
		if !ok {
			break
		}
		res.Claimed++
		rowCtx, cancel := context.WithTimeout(ctx, rowTimeout)
		outcome, degraded, err := w.process(rowCtx, p, aliases, mappings, cfg)
		cancel()
		if degraded != "" && res.Degraded == "" {
			res.Degraded = degraded
		}
		if err != nil {
			res.Failed++
			metrics.CPEProposals.WithLabelValues("error").Inc()
			logger.Warn("cpe proposal processing failed; will retry", "proposal_id", p.ID, "err", err)
			w.recordFailure(ctx, p, err, cfg)
			continue
		}
		if outcome == "unchanged" {
			continue
		}
		metrics.CPEProposals.WithLabelValues(outcome).Inc()
		switch outcome {
		case StateAutoPublished:
			res.AutoPublished++
		case StateNeedsReview:
			res.NeedsReview++
		case StateSuperseded:
			res.Superseded++
		case "retry":
			res.Retrying++
		}
	}
	w.recordStatus(ctx, res, modelConfigured, cfg)
	if res.Claimed > 0 || res.Demoted > 0 || res.Reconciled > 0 || res.Expired > 0 {
		logger.Info("cpe proposer run", "claimed", res.Claimed, "auto_published", res.AutoPublished,
			"needs_review", res.NeedsReview, "superseded", res.Superseded, "retrying", res.Retrying,
			"failed", res.Failed, "demoted", res.Demoted, "reconciled", res.Reconciled, "expired", res.Expired, "degraded", res.Degraded)
	}
	if !modelConfigured && res.Claimed > 0 {
		// Loud on purpose: without a model every proposal waits for a person.
		logger.Warn("cpe proposer degraded: no model available, proposals sent to staff review with candidates only",
			"reason", w.noModelReason(), "model_configured", modelConfigured)
	}
	return res, nil
}

// maintain runs the sweeps that need no outbound call and keep published
// state honest: superseding, deleted-mapping reconciliation, the
// automatic-mapping re-check and expiry. They run even when proposing is
// disabled. Returns the alias table for the caller.
func (w *Worker) maintain(ctx context.Context, res *RunResult) ([]Alias, error) {
	logger := w.logger()
	if n, err := w.sweepSuperseded(ctx); err != nil {
		logger.Warn("cpe proposer supersede sweep failed", "err", err)
	} else {
		res.Superseded += n
	}
	if n, err := w.reconcileDeletedMappings(ctx); err != nil {
		logger.Warn("cpe proposer deleted-mapping reconciliation failed", "err", err)
	} else {
		res.Reconciled = n
	}
	if n, err := w.expireUnseen(ctx); err != nil {
		logger.Warn("cpe proposer expiry sweep failed", "err", err)
	} else {
		res.Expired = n
	}
	if n, err := w.reopenReported(ctx); err != nil {
		logger.Warn("cpe proposer reopen sweep failed", "err", err)
	} else {
		res.Reopened = n
	}
	aliases, err := loadAliases(ctx, w.Pool)
	if err != nil {
		return nil, err
	}
	n, err := w.recheckAuto(ctx, aliases)
	res.Demoted = n
	if err != nil {
		logger.Warn("cpe proposer automatic-mapping re-check failed", "err", err)
	}
	return aliases, nil
}

// recordDisabled records the proposer as disabled (maintenance only).
func (w *Worker) recordDisabled(ctx context.Context, res RunResult) {
	detail, _ := json.Marshal(map[string]any{"last_run_at": time.Now().UTC(), "last_run": res})
	if _, err := w.Pool.Exec(ctx, `
		INSERT INTO cpe_proposer_status (component, status, reason, detail, updated_at)
		VALUES ('proposer', 'disabled', 'proposer_disabled', $1::jsonb, now())
		ON CONFLICT (component) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
			detail = EXCLUDED.detail, updated_at = EXCLUDED.updated_at
	`, detail); err != nil {
		w.logger().Warn("recording cpe proposer status failed", "err", err)
	}
}

func (w *Worker) logger() *slog.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	return slog.Default()
}

// dueSQL is the claimable condition: pending; model_unavailable when a model
// is configured ($1); single_tenant and corroboration_lost always
// (a local re-read first; they go further only when their evidence changed).
const dueSQL = `next_attempt_at <= now()
	AND (state = 'pending'
	     OR (state = 'needs_review' AND (($1::bool AND state_reason = 'model_unavailable')
	                                     OR state_reason IN ('single_tenant', 'corroboration_lost'))))`

// rankDue returns up to rankWindow due proposal ids, most affected tenants
// first, then most affected devices (active devices, the matcher's scope),
// then oldest due. One pass over the matching device_apps rows; no lock.
func (w *Worker) rankDue(ctx context.Context, modelConfigured bool) ([]int64, error) {
	rows, err := w.Pool.Query(ctx, `
		WITH due AS (
			SELECT id, platform, normalized_name, next_attempt_at, state
			FROM cpe_mapping_proposals
			WHERE `+dueSQL+`
			ORDER BY next_attempt_at, id
			LIMIT $2
		), hits AS (
			SELECT due.id, d.tenant_id, d.id AS device_id
			FROM due
			JOIN device_apps da ON cpe_normalize_name(da.name) = due.normalized_name
			JOIN devices d ON d.id = da.device_id
			JOIN tenants tn ON tn.id = d.tenant_id
			WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
			  AND `+currentCustomerTenantSQL("tn")+`
			  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
			            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = due.platform
		)
		SELECT due.id
		FROM due LEFT JOIN hits h ON h.id = due.id
		GROUP BY due.id, due.next_attempt_at, due.state
		ORDER BY count(DISTINCT h.tenant_id) DESC, count(DISTINCT h.device_id) DESC,
		         (due.state = 'pending') DESC, due.next_attempt_at, due.id
	`, modelConfigured, rankWindow)
	if err != nil {
		return nil, fmt.Errorf("rank due cpe proposals: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan ranked proposal: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// claimOne leases the first of ranked that is still due and not locked by
// another worker.
func (w *Worker) claimOne(ctx context.Context, ranked []int64, modelConfigured bool) (proposal, bool, error) {
	var p proposal
	var raw []byte
	err := w.Pool.QueryRow(ctx, `
		UPDATE cpe_mapping_proposals p
		SET next_attempt_at = now() + make_interval(secs => $3), updated_at = now()
		WHERE p.id = (
			SELECT id FROM cpe_mapping_proposals
			WHERE id = ANY($2::bigint[]) AND `+dueSQL+`
			ORDER BY array_position($2::bigint[], id)
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING p.id, p.platform, p.normalized_name, p.display_name, p.state, p.state_reason,
		          p.candidates, p.candidates_fetched_at, p.attempts, p.mapping_id,
		          COALESCE(p.evidence->>'signer_fingerprint', '')
	`, modelConfigured, ranked, leaseDuration.Seconds()).Scan(&p.ID, &p.Platform, &p.Normalized, &p.DisplayName,
		&p.State, &p.Reason, &raw, &p.FetchedAt, &p.Attempts, &p.MappingID, &p.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, false, nil
	}
	if err != nil {
		return p, false, fmt.Errorf("claim cpe proposal: %w", err)
	}
	if err := json.Unmarshal(raw, &p.Candidates); err != nil {
		return p, false, fmt.Errorf("decode candidates of proposal %d: %w", p.ID, err)
	}
	return p, true, nil
}

// candidateTTL is how long stored candidates are reused before a re-search.
const candidateTTL = 30 * 24 * time.Hour

// process runs one proposal through the pipeline and writes its outcome.
// outcome is a state, or "retry" when the candidate search failed and the row
// will be tried again later.
//
// Evidence is read first, from local data only: a product fewer than
// MinOutboundTenants tenants report (!Evidence.Eligible) goes to staff as
// single_tenant without any NVD search or model call, so nothing about one
// customer's possibly private product ever leaves the platform.
func (w *Worker) process(ctx context.Context, p proposal, aliases []Alias, mappings []cvematch.CPEMapping, cfg Config) (outcome, degraded string, err error) {
	// A mapping that appeared by any other path (a person, a migration)
	// supersedes the proposal.
	if len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(p.DisplayName, mappings), p.Platform)) > 0 {
		return StateSuperseded, "", w.supersede(ctx, p)
	}

	ev, err := loadEvidence(ctx, w.Pool, p.Platform, p.Normalized, aliases)
	if err != nil {
		return "", "", err
	}
	// A demoted automatic mapping is offered to the gate again only when its
	// signer evidence has changed since the demotion; until then it waits
	// for staff without any outbound call.
	if p.State == StateNeedsReview && p.Reason != nil && *p.Reason == ReasonCorroborationLost &&
		ev.SignerFingerprint == p.Fingerprint {
		_, err := w.Pool.Exec(ctx, `UPDATE cpe_mapping_proposals SET next_attempt_at = now() + make_interval(secs => $2)
			WHERE id = $1 AND state = 'needs_review'`, p.ID, privateRecheckAfter.Seconds())
		return "unchanged", "", err
	}
	if !ev.Eligible() {
		return StateNeedsReview, "", w.writeOutcome(ctx, p, outcomeRow{
			Decision:   Decision{State: StateNeedsReview, Reason: ReasonSingleTenant},
			Candidates: p.Candidates, Evidence: ev, Attempts: p.Attempts, RetryAfter: privateRecheckAfter,
		})
	}

	cands := p.Candidates
	fresh := false
	if len(cands) == 0 || p.FetchedAt == nil || time.Since(*p.FetchedAt) > candidateTTL {
		fresh = true
		cands, err = w.search(ctx, p.Normalized)
		if err != nil {
			if p.Attempts+1 >= cfg.MaxNVDAttempts {
				return StateNeedsReview, ReasonNVDUnavailable, w.writeOutcome(ctx, p, outcomeRow{
					Decision: Decision{State: StateNeedsReview, Reason: ReasonNVDUnavailable},
					Evidence: ev, LastError: err.Error(), Attempts: p.Attempts + 1,
				})
			}
			return "retry", ReasonNVDUnavailable, w.retryLater(ctx, p, err, cfg)
		}
		if err := annotateCVECounts(ctx, w.Pool, cands); err != nil {
			return "", "", err
		}
		for i := range cands {
			cands[i].ID = fmt.Sprintf("C%d", i+1)
		}
	}

	if ev.OtherCoveredNames, err = coveredNames(ctx, w.Pool, p.Platform, p.DisplayName, true); err != nil {
		return "", "", err
	}

	in := GateInput{AutoPublishEnabled: cfg.AutoPublish, NormalizedName: p.Normalized, Candidates: cands,
		OtherCoveredNames: ev.OtherCoveredNames}
	if len(cands) > 0 {
		if w.Chooser == nil {
			in.ModelErr = fmt.Errorf("%w: %s", ErrModelUnavailable, w.noModelReason())
		} else {
			in.Choice, in.ModelErr = w.Chooser.Choose(ctx, ev.Product, cands)
		}
		if in.ModelErr != nil && !errors.Is(in.ModelErr, ErrInvalidModelResponse) {
			degraded = ReasonModelUnavailable
			if w.Chooser == nil {
				degraded = w.noModelReason()
			}
		}
	}
	if in.Choice.Choice != "" && in.Choice.Choice != ChoiceNone {
		if cand, ok := candidateByKey(cands, in.Choice.Choice); ok {
			ev.Corroboration = corroborateEvidence(p.Platform, ev, aliases, cand.Vendor)
			in.Corroboration = ev.Corroboration
			m := ProductMatches(p.Normalized, cand.Vendor, cand.Product)
			ev.ProductNameMatch = &m
		}
	}
	d := Decide(in)
	lastErr := ""
	if in.ModelErr != nil {
		lastErr = in.ModelErr.Error()
	}
	return d.State, degraded, w.writeOutcome(ctx, p, outcomeRow{
		Decision: d, Candidates: cands, FreshCandidates: fresh, Choice: in.Choice, Evidence: ev, LastError: lastErr,
		Attempts: p.Attempts, RetryAfter: cfg.ModelRetryAfter,
	})
}

// corroborateEvidence is Corroborate over loaded evidence; more distinct
// evidence tuples than were read can never agree on one signer.
func corroborateEvidence(platform string, ev Evidence, aliases []Alias, vendor string) Corroboration {
	c := Corroborate(platform, ev.Installations, aliases, vendor)
	if ev.TooManyTuples {
		c.OK = false
		c.Reason = ReasonSignerInconsistent
	}
	return c
}

// search runs the keyword searches for a normalised name, most specific
// first, stopping at the first that returns candidates. The keyword is the
// only data NVD receives.
func (w *Worker) search(ctx context.Context, normalizedName string) ([]Candidate, error) {
	if w.Dict == nil {
		return nil, errors.New("no CPE dictionary configured")
	}
	for _, kw := range Keywords(normalizedName) {
		cands, err := w.Dict.Search(ctx, kw)
		if err != nil {
			return nil, err
		}
		if len(cands) > 0 {
			return cands, nil
		}
	}
	return []Candidate{}, nil
}

type outcomeRow struct {
	Decision        Decision
	Candidates      []Candidate
	FreshCandidates bool // Candidates came from a search this run
	Choice          ModelChoice
	Evidence        Evidence
	LastError       string
	Attempts        int
	// RetryAfter is when a row the claim picks up again (model_unavailable,
	// single_tenant) is next due.
	RetryAfter time.Duration
}

// writeOutcome records the gate's decision in one transaction: the proposal
// row, the audit row and, for an automatic publish, the app_cpe_mappings row.
// The publish re-checks, under an advisory lock, that no mapping covers the
// name, so two workers (or a person and a worker) cannot both map it.
func (w *Worker) writeOutcome(ctx context.Context, p proposal, o outcomeRow) error {
	return pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		before, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		if before.State != p.State {
			return nil // a person acted on it while we worked; their decision stands
		}
		d := o.Decision
		var mappingID *int64
		if d.State == StateAutoPublished {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cpepropose.publish', 0))`); err != nil {
				return fmt.Errorf("lock publish: %w", err)
			}
			mappings, err := loadAppMappings(ctx, tx)
			if err != nil {
				return err
			}
			if len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(p.DisplayName, mappings), p.Platform)) > 0 {
				d = Decision{State: StateSuperseded, Reason: ReasonMappedByOtherPath}
			} else {
				var id int64
				if err := tx.QueryRow(ctx, `
					INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
					VALUES ($1, $2, $3, $4, $5, 'app_name', 'auto')
					RETURNING id
				`, p.Platform, p.DisplayName, d.Vendor, d.Product,
					fmt.Sprintf("PAT-2138 automatic mapping, proposal %d", p.ID)).Scan(&id); err != nil {
					return fmt.Errorf("publish mapping: %w", err)
				}
				mappingID = &id
			}
		}
		candJSON, err := json.Marshal(nonNilCandidates(o.Candidates))
		if err != nil {
			return err
		}
		evJSON, err := json.Marshal(o.Evidence)
		if err != nil {
			return err
		}
		var choice, confidence, rationale, modelID *string
		if o.Choice.Choice != "" {
			choice, confidence, rationale, modelID = &o.Choice.Choice, &o.Choice.Confidence, &o.Choice.Rationale, &o.Choice.Model
			if o.Choice.Model == "" {
				modelID = nil
			}
		}
		var vendor, product *string
		if d.Vendor != "" && d.Product != "" {
			vendor, product = &d.Vendor, &d.Product
		}
		var reason *string
		if d.Reason != "" {
			reason = &d.Reason
		}
		var lastErr *string
		if o.LastError != "" {
			e := capRunes(o.LastError, 500)
			lastErr = &e
		}
		// A model_unavailable row is offered to the model again later (only
		// when one is configured), a single_tenant one re-read from
		// local data; every other decided row is never claimed.
		retry := o.RetryAfter
		if retry <= 0 {
			retry = DefaultConfig().ModelRetryAfter
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cpe_mapping_proposals SET
				state = $2, state_reason = $3, candidates = $4::jsonb,
				candidates_fetched_at = CASE WHEN $5::bool THEN now() ELSE candidates_fetched_at END,
				model_id = $6, model_choice = $7, model_confidence = $8, model_rationale = $9,
				evidence = $10::jsonb, chosen_cpe_vendor = $11, chosen_cpe_product = $12,
				mapping_id = $13, attempts = $14, last_error = $15,
				next_attempt_at = now() + make_interval(secs => $16),
				proposed_at = COALESCE(proposed_at, now()),
				decided_at = CASE WHEN $2 IN ('auto_published', 'superseded') THEN now() ELSE decided_at END,
				decided_by = CASE WHEN $2 IN ('auto_published', 'superseded') THEN $17 ELSE decided_by END,
				rechecked_at = CASE WHEN $2 = 'auto_published' THEN now() ELSE rechecked_at END,
				updated_at = now()
			WHERE id = $1
		`, p.ID, d.State, reason, candJSON, o.FreshCandidates, modelID, choice, confidence, rationale,
			evJSON, vendor, product, mappingID, o.Attempts, lastErr, retry.Seconds(), SystemActor); err != nil {
			return fmt.Errorf("record proposal outcome: %w", err)
		}
		after, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		// A periodic re-read that changes nothing (a single-tenant product still
		// private, a model still unavailable) is not a state change: no
		// audit row, so the audit trail is not flooded.
		if d.State == StateNeedsReview && before.State == StateNeedsReview &&
			before.StateReason != nil && *before.StateReason == d.Reason {
			return nil
		}
		action := "needs_review"
		switch d.State {
		case StateAutoPublished:
			action = "auto_publish"
		case StateSuperseded:
			action = "supersede"
		}
		return writeAudit(ctx, tx, p.ID, action, Actor{Actor: SystemActor}, &before, after)
	})
}

func nonNilCandidates(c []Candidate) []Candidate {
	if c == nil {
		return []Candidate{}
	}
	return c
}

func (w *Worker) supersede(ctx context.Context, p proposal) error {
	return pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		before, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		if before.State != p.State {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cpe_mapping_proposals SET state = 'superseded', state_reason = $2,
				decided_at = now(), decided_by = $3, updated_at = now()
			WHERE id = $1
		`, p.ID, ReasonMappedByOtherPath, SystemActor); err != nil {
			return fmt.Errorf("supersede proposal: %w", err)
		}
		after, err := snapshotProposal(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		return writeAudit(ctx, tx, p.ID, "supersede", Actor{Actor: SystemActor}, &before, after)
	})
}

// sweepSuperseded closes needs_review proposals that a mapping now covers
// (a person mapped the product by hand, or a migration seeded it), so the
// review queue and the digest never show work that is already done.
func (w *Worker) sweepSuperseded(ctx context.Context) (int, error) {
	rows, err := w.Pool.Query(ctx, `
		SELECT id, platform, normalized_name, display_name, state
		FROM cpe_mapping_proposals WHERE state = 'needs_review' ORDER BY id LIMIT 1000`)
	if err != nil {
		return 0, err
	}
	var open []proposal
	for rows.Next() {
		var p proposal
		if err := rows.Scan(&p.ID, &p.Platform, &p.Normalized, &p.DisplayName, &p.State); err != nil {
			rows.Close()
			return 0, err
		}
		open = append(open, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(open) == 0 {
		return 0, err
	}
	mappings, err := loadAppMappings(ctx, w.Pool)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range open {
		if len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(p.DisplayName, mappings), p.Platform)) == 0 {
			continue
		}
		if err := w.supersede(ctx, p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// retryLater records a failed candidate search and backs the row off:
// 15 minutes doubling per attempt, capped at a day.
func (w *Worker) retryLater(ctx context.Context, p proposal, cause error, cfg Config) error {
	backoff := 15 * time.Minute << uint(min(p.Attempts, 6))
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	_, err := w.Pool.Exec(ctx, `
		UPDATE cpe_mapping_proposals SET attempts = attempts + 1, last_error = $2,
			next_attempt_at = now() + make_interval(secs => $3), updated_at = now()
		WHERE id = $1 AND state = $4
	`, p.ID, capRunes(cause.Error(), 500), backoff.Seconds(), p.State)
	return err
}

func (w *Worker) recordFailure(ctx context.Context, p proposal, cause error, cfg Config) {
	if err := w.retryLater(ctx, p, cause, cfg); err != nil {
		w.logger().Warn("recording cpe proposal failure failed", "proposal_id", p.ID, "err", err)
	}
}

// recordStatus publishes the worker's health to cpe_proposer_status (read by
// the admin API) and the degraded gauge.
func (w *Worker) recordStatus(ctx context.Context, res RunResult, modelConfigured bool, cfg Config) {
	status, reason := "ok", (*string)(nil)
	if res.Degraded != "" {
		status = "degraded"
		r := res.Degraded
		reason = &r
	}
	for _, r := range []string{ReasonModelUnavailable, ReasonModelZDRUnconfirmed, ReasonNVDUnavailable} {
		v := 0.0
		if res.Degraded == r {
			v = 1
		}
		metrics.CPEProposerDegraded.WithLabelValues(r).Set(v)
	}
	detail, _ := json.Marshal(map[string]any{
		"model_configured":     modelConfigured,
		"auto_publish_enabled": cfg.AutoPublish,
		"last_run_at":          time.Now().UTC(),
		"last_run":             res,
	})
	if _, err := w.Pool.Exec(ctx, `
		INSERT INTO cpe_proposer_status (component, status, reason, detail, updated_at)
		VALUES ('proposer', $1, $2, $3::jsonb, now())
		ON CONFLICT (component) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
			detail = EXCLUDED.detail, updated_at = EXCLUDED.updated_at
	`, status, reason, detail); err != nil {
		w.logger().Warn("recording cpe proposer status failed", "err", err)
	}
	var awaiting int
	if err := w.Pool.QueryRow(ctx, `SELECT count(*)::int FROM cpe_mapping_proposals WHERE state = 'needs_review'`).Scan(&awaiting); err == nil {
		metrics.CPEProposalsAwaitingReview.Set(float64(awaiting))
	}
}
