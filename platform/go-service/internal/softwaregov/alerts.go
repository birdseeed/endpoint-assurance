package softwaregov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/webhook"
)

// The unapproved software alert (PAT-2009, owner ruling 2026-09-24).
//
// Two triggers raise software.unapproved_detected:
//
//   - marked:   a customer admin (PUT /v1/portal/software-approvals) or the
//     operator admin API sets a product Unapproved while it is installed on
//     at least one device. One alert, listing every device, immediately.
//   - observed: an Unapproved product is newly observed on a device during
//     extraction. One alert per (product, device) per unapproved episode,
//     however often the device reports.
//
// Dedupe is a ledger, not a timer. An episode is one transition of one
// policy row into Unapproved (software_unapproved_episodes). Every
// (episode, device) pair an alert has covered is recorded in
// software_unapproved_alerted_devices, including the pairs the marked alert
// listed, so ingest never re-alerts a device the admin action already
// reported. A new transition into Unapproved opens a new episode and so
// alerts again.
//
// The episode row is written inside the policy-write transaction
// (OpenEpisodeTx), so the episode boundary always matches the policy state.
// The marked alert is raised by the Runner (RaiseEpisodes), which the policy
// writer wakes after its commit (PAT-2095: never on the request path); a
// failed raise is retried at the next tick, so an alert is delayed, never
// lost. The raise reads the Unapproved-present summary (presence.go), not the
// whole estate. Marked alerts of one request share one email; webhooks stay
// one per product, because a ticketing integration wants one event per
// product.
//
// Outbox semantics: the alert row, the ledger rows and the webhook
// deliveries are written in one transaction. The webhook is delivered by the
// PAT-134 sweeper; the email by Runner. Raising an alert never makes a
// network call, and a failure here is logged by the caller and never fails
// the approval write or the extraction that triggered it.
//
// All writes for one tenant are serialised by a transaction advisory lock,
// so two extractor workers cannot both open an episode or both alert a pair.
// Holders keep it briefly: a marked raise holds it for one episode at a time,
// and a policy writer takes it only for its alert operations just before
// committing, so an ingest's DetectOnDevice never waits behind a bulk mark.

// Alert triggers.
const (
	TriggerMarked   = "marked"
	TriggerObserved = "observed"
)

// Episode sources.
const (
	SourcePortal   = "portal"
	SourceOperator = "operator"
	SourceObserved = "observed"
	// SourceBaseline episodes were seeded by migration 0183 for policies
	// already Unapproved at deploy; their devices were recorded as known.
	SourceBaseline = "baseline"
)

// MaxAlertDevices caps the devices listed in one marked alert payload. The
// ledger still records every device; DeviceCount stays exact.
const MaxAlertDevices = 500

// Mark is one transition of a policy row into Unapproved.
type Mark struct {
	TenantID   string
	PolicyKind string // TypeApplication | TypeBrowserExtension
	PolicyID   int64
	Source     string // SourcePortal | SourceOperator
	MarkedBy   string // verified portal email; empty for the operator
	// MarkedAt is the decision time, captured inside the write transaction.
	MarkedAt time.Time
	// BatchID groups the marks of one policy-write request into one email.
	BatchID string
}

// AlertDevice is one device in an alert payload.
type AlertDevice struct {
	DeviceID      string    `json:"device_id"`
	Hostname      string    `json:"hostname"`
	Platform      string    `json:"platform"`
	ObservedSince time.Time `json:"observed_since"`
	LastSeen      time.Time `json:"last_seen"`
	Stale         bool      `json:"stale"`
}

// AlertProduct is one product in an alert payload.
type AlertProduct struct {
	Product
	DeviceCount int           `json:"device_count"`
	Devices     []AlertDevice `json:"devices"`
}

// AlertPolicy identifies the tenant policy row that made the product
// Unapproved.
type AlertPolicy struct {
	Kind string `json:"kind"`
	ID   int64  `json:"id"`
}

// AlertPayload is the data block of software.unapproved_detected, stored on
// the alert row and delivered in the webhook. It carries product identity,
// hostnames, who marked it and when. No secret, token or credential is ever
// part of it.
type AlertPayload struct {
	AlertID     int64          `json:"alert_id"`
	Trigger     string         `json:"trigger"`
	Policy      AlertPolicy    `json:"policy"`
	MarkedBy    *string        `json:"marked_by"`
	MarkedVia   string         `json:"marked_via"`
	MarkedAt    time.Time      `json:"marked_at"`
	DetectedAt  time.Time      `json:"detected_at"`
	DeviceCount int            `json:"device_count"`
	Truncated   bool           `json:"devices_truncated"`
	Products    []AlertProduct `json:"products"`
}

// RaiseResult reports what one raise did.
type RaiseResult struct {
	EpisodeID int64
	AlertIDs  []int64
	Devices   int
	Webhooks  int
	Skipped   string // why nothing was alerted, when nothing was
}

type episode struct {
	id        int64
	source    string
	markedBy  *string
	markedAt  time.Time
	createdAt time.Time
	raisedAt  *time.Time
}

func lockTenantAlerts(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, tenantID)
	return err
}

func tryLockTenantAlerts(ctx context.Context, tx pgx.Tx, tenantID string) (bool, error) {
	var locked bool
	err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, tenantID).Scan(&locked)
	return locked, err
}

func latestEpisode(ctx context.Context, tx pgx.Tx, tenantID, kind string, policyID int64) (*episode, error) {
	var e episode
	err := tx.QueryRow(ctx, `
		SELECT id, source, marked_by, marked_at, created_at, raised_at
		FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND policy_kind = $2 AND policy_id = $3
		ORDER BY id DESC
		LIMIT 1
	`, tenantID, kind, policyID).Scan(&e.id, &e.source, &e.markedBy, &e.markedAt, &e.createdAt, &e.raisedAt)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest unapproved episode: %w", err)
	}
	return &e, nil
}

func insertEpisode(ctx context.Context, tx pgx.Tx, tenantID, kind string, policyID int64, source string, markedBy *string, markedAt time.Time) (*episode, error) {
	e := episode{source: source, markedBy: markedBy, markedAt: markedAt.UTC()}
	if err := tx.QueryRow(ctx, `
		INSERT INTO software_unapproved_episodes (tenant_id, policy_kind, policy_id, source, marked_by, marked_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`, tenantID, kind, policyID, source, markedBy, markedAt).Scan(&e.id, &e.createdAt); err != nil {
		return nil, fmt.Errorf("open unapproved episode: %w", err)
	}
	return &e, nil
}

func tenantActive(ctx context.Context, q Querier, tenantID string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID).Scan(&ok)
	return ok, err
}

func markedVia(source string) string {
	if source == SourceObserved || source == SourceBaseline {
		return "unknown"
	}
	return source
}

func alertDevices(devs []Presence) []AlertDevice {
	out := make([]AlertDevice, 0, len(devs))
	for _, d := range devs {
		out = append(out, AlertDevice{DeviceID: d.DeviceID, Hostname: d.Hostname, Platform: d.Platform,
			ObservedSince: d.ObservedSince, LastSeen: d.LastSeen, Stale: d.Stale})
	}
	return out
}

func nextAlertID(ctx context.Context, tx pgx.Tx) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `SELECT nextval('software_unapproved_alerts_id_seq')`).Scan(&id)
	return id, err
}

func insertAlert(ctx context.Context, tx pgx.Tx, tenantID string, id, episodeID int64, trigger string, deviceID *string, payload AlertPayload, now time.Time) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal alert payload: %w", err)
	}
	webhooks, err := webhook.Enqueue(ctx, tx, tenantID, webhook.EventSoftwareUnapprovedDetected, payload, now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_unapproved_alerts
		    (id, tenant_id, episode_id, trigger, device_id, payload, webhook_deliveries, created_at)
		VALUES ($1, $2::uuid, $3, $4, $5::uuid, $6::jsonb, $7, $8)
	`, id, tenantID, episodeID, trigger, deviceID, string(body), webhooks, now); err != nil {
		return 0, fmt.Errorf("insert unapproved alert: %w", err)
	}
	return webhooks, nil
}

// OpenEpisodeTx records one transition of a policy row into Unapproved. Call
// it inside the policy-write transaction, so the episode boundary commits
// with the policy state or not at all. It is one INSERT and sends nothing;
// RaiseEpisodes, after the commit, or the Runner if that fails, raises the
// alert. Every mark of one request should carry the same BatchID; an empty
// BatchID makes the mark a batch of its own.
func OpenEpisodeTx(ctx context.Context, tx pgx.Tx, m Mark) (int64, error) {
	if m.PolicyKind != TypeApplication && m.PolicyKind != TypeBrowserExtension {
		return 0, fmt.Errorf("softwaregov: unknown policy kind %q", m.PolicyKind)
	}
	if m.Source != SourcePortal && m.Source != SourceOperator {
		return 0, fmt.Errorf("softwaregov: unknown mark source %q", m.Source)
	}
	var markedBy *string
	if m.Source == SourcePortal {
		by := strings.ToLower(strings.TrimSpace(m.MarkedBy))
		if by == "" {
			return 0, errors.New("softwaregov: a portal mark needs the admin's email")
		}
		markedBy = &by
	}
	var batch *string
	if m.BatchID != "" {
		batch = &m.BatchID
	}
	// PAT-2097: the tenant alert lock, after the caller's policy lock and
	// policy row locks (never the other way round), so the episode boundary
	// and the lifecycle rows change together with no reconcile in between.
	if err := lockTenantAlerts(ctx, tx, m.TenantID); err != nil {
		return 0, fmt.Errorf("lock tenant alerts: %w", err)
	}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO software_unapproved_episodes
		    (tenant_id, policy_kind, policy_id, source, marked_by, marked_at, batch_id, policy_version)
		VALUES ($1::uuid, $2, $3, $4, $5, COALESCE($6, now()), COALESCE($7::uuid, gen_random_uuid()),
		        -- PAT-2095: the tenant policy version including this write, so
		        -- the raise waits for a summary rebuilt at least that far.
		        (SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid))
		RETURNING id
	`, m.TenantID, m.PolicyKind, m.PolicyID, m.Source, markedBy, nullTime(m.MarkedAt), batch).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("open unapproved episode: %w", err)
	}
	if err := supersedePriorEpisodesTx(ctx, tx, m.TenantID, m.PolicyKind, m.PolicyID, id); err != nil {
		return 0, err
	}
	return id, nil
}

// supersedePriorEpisodesTx resolves every open or acknowledged alert of the
// policy row's earlier episodes as superseded, so a (policy, device) never
// has two active alerts. The caller holds lockTenantAlerts.
func supersedePriorEpisodesTx(ctx context.Context, tx pgx.Tx, tenantID, kind string, policyID, newEpisode int64) error {
	if _, err := tx.Exec(ctx, `
		WITH target AS (
			SELECT ad.id, ad.status
			FROM software_unapproved_alerted_devices ad
			JOIN software_unapproved_episodes e ON e.id = ad.episode_id AND e.tenant_id = ad.tenant_id
			WHERE ad.tenant_id = $1::uuid AND e.policy_kind = $2 AND e.policy_id = $3 AND e.id < $4
			  AND ad.status IN ('open', 'acknowledged')
			FOR UPDATE OF ad
		), upd AS (
			UPDATE software_unapproved_alerted_devices ad
			SET status = 'resolved', status_changed_at = now(), resolved_at = now(),
			    resolved_reason = 'superseded', reopen_digest_pending = false
			FROM target WHERE ad.id = target.id
			RETURNING ad.id, ad.episode_id, ad.device_id, target.status AS from_status
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, reason, detail)
		SELECT $1::uuid, id, episode_id, device_id, from_status, 'resolved', 'system', 'superseded',
		       jsonb_build_object('evidence', 'superseded_episode', 'episode_id', $4::bigint)
		FROM upd
	`, tenantID, kind, policyID, newEpisode); err != nil {
		return fmt.Errorf("supersede prior episode alerts: %w", err)
	}
	return nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

type pendingEpisode struct {
	episode
	kind     string
	policyID int64
	batchID  *string
}

// RaiseEpisodes raises the marked alerts for episodes OpenEpisodeTx recorded
// and nobody has raised yet. For each episode whose product is installed on
// at least one device while the tenant's alert is on, it writes one alert
// (one webhook per subscribed endpoint, per product) and records every
// listed device in the dedupe ledger; the alerts of one batch share one
// email. Every episode passed is marked raised, including one that is not
// installed or whose tenant has the alert off, so nothing is raised twice.
// Safe to call concurrently and repeatedly: the tenant lock and the
// raised_at check make a second caller a no-op.
//
// PAT-2095: the devices come from the Unapproved-present summary, not a
// whole-estate load. The summary is first brought up to the policy version
// the episodes were opened at (ReconcileTenant, outside any alert lock), and
// each episode is then raised in its own short transaction under the tenant
// alert lock. Ingest's DetectOnDevice tries that lock and defers its durable
// check rather than waiting behind a marked raise.
// Inside that transaction dirty devices are resolved live, which keeps the
// old guarantee: a device whose DetectOnDevice deferred to this marked alert
// (the episode was still unraised) is listed by it. The Runner is the only
// production caller; policy writers wake it (WakeRunner) instead of raising
// on the request path.
func RaiseEpisodes(ctx context.Context, pool *pgxpool.Pool, tenantID string, episodeIDs []int64, now time.Time) (RaiseResult, error) {
	ctx, cancel := context.WithTimeout(ctx, markedBatchTimeout)
	defer cancel()
	var res RaiseResult
	if len(episodeIDs) == 0 {
		return res, nil
	}
	now = now.UTC()
	rows, err := pool.Query(ctx, `
		SELECT id, policy_version
		FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND id = ANY($2) AND raised_at IS NULL
		  AND source IN ('portal', 'operator')
		ORDER BY id
	`, tenantID, episodeIDs)
	if err != nil {
		return res, fmt.Errorf("load unraised episodes: %w", err)
	}
	var ids []int64
	var need int64
	for rows.Next() {
		var id int64
		var v *int64
		if err := rows.Scan(&id, &v); err != nil {
			rows.Close()
			return res, err
		}
		ids = append(ids, id)
		if v != nil && *v > need {
			need = *v
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(ids) == 0 {
		res.Skipped = "already_raised"
		return res, nil
	}
	if err := ensureSummary(ctx, pool, tenantID, need, now); err != nil {
		return res, err
	}
	for _, id := range ids {
		var one RaiseResult
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			one, err = raiseEpisode(ctx, pool, tenantID, id, now)
			if !errors.Is(err, ErrSummaryUnusable) && !isSerializationFailure(err) {
				break
			}
			// A policy write or new dirty devices raced preparation. The
			// failed transaction has released the alert lock before repair.
			if err = ensureSummary(ctx, pool, tenantID, need, now); err != nil {
				break
			}
			// Preserve a retryable failure if the final repair exhausted the
			// budget without a successful raise; the runner retries next pass.
			err = ErrSummaryUnusable
		}
		if err != nil {
			return res, err
		}
		if one.EpisodeID != 0 {
			res.EpisodeID = one.EpisodeID
		}
		res.AlertIDs = append(res.AlertIDs, one.AlertIDs...)
		res.Devices += one.Devices
		res.Webhooks += one.Webhooks
		if one.Skipped != "" {
			res.Skipped = one.Skipped
		}
	}
	if len(res.AlertIDs) > 0 {
		res.Skipped = ""
	}
	return res, nil
}

// ensureSummary makes the tenant's summary current to at least policy
// version need and the current policy version,
// and refreshes the tenant's dirty devices, so the per-episode raise reads
// the summary rather than resolving many devices live under the alert lock.
func ensureSummary(ctx context.Context, pool *pgxpool.Pool, tenantID string, need int64, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, summaryWorkTimeout)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		st, err := readPresenceState(ctx, pool, tenantID)
		if err != nil {
			return err
		}
		if st.policyVersion > need {
			need = st.policyVersion
		}
		if !st.current() || st.summaryVersion < need {
			if err := ReconcileTenant(ctx, pool, tenantID, now); err != nil {
				if errors.Is(err, ErrSummaryUnusable) {
					continue
				}
				return fmt.Errorf("rebuild unapproved summary: %w", err)
			}
		}
		if _, err := RefreshTenantDirty(ctx, pool, tenantID, now); err != nil {
			return fmt.Errorf("refresh dirty devices: %w", err)
		}
		return nil
	}
	return ErrSummaryUnusable
}

// raiseEpisode raises one episode in its own transaction under the tenant
// alert lock. A no-op for an episode already raised.
func raiseEpisode(ctx context.Context, pool *pgxpool.Pool, tenantID string, episodeID int64, now time.Time) (RaiseResult, error) {
	ctx, cancel := context.WithTimeout(ctx, markedEpisodeTimeout)
	defer cancel()
	var res RaiseResult
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Release()
	// Acquire the advisory lock BEFORE opening the snapshot. Acquiring it
	// as the first statement of a repeatable-read transaction would freeze
	// inventory from before the wait, omitting devices ingested meanwhile.
	// A pinned connection keeps this to one pool slot. Never return a session
	// lock to the pool: failed cleanup discards the connection instead.
	locked := false
	defer func() {
		if conn.Conn().IsClosed() {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if locked && conn.Conn().PgConn().TxStatus() == 'I' {
			err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended('softwaregov-alerts:' || $1, 0))`, tenantID).Scan(&unlocked)
			if err == nil && unlocked {
				return
			}
		}
		// A failed acquisition has ambiguous ownership; failed BEGIN can
		// leave a transaction open without a pgx.Tx to roll back. Discard any
		// non-idle session or failed unlock through this sole close path.
		if !conn.Conn().IsClosed() {
			_ = conn.Conn().Close(cleanup)
		}
	}()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, tenantID); err != nil {
		return res, fmt.Errorf("lock tenant alerts: %w", err)
	}
	locked = true
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	// Policy writers take the state row before the alert lock. NOWAIT is
	// essential: waiting here would invert that order and deadlock. Under
	// repeatable read, a state row changed since the snapshot started causes
	// serialization failure, rather than accepting its old version.
	var st presenceState
	if err := tx.QueryRow(ctx, `SELECT policy_version, summary_version
		FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid FOR SHARE NOWAIT`,
		tenantID).Scan(&st.policyVersion, &st.summaryVersion); err != nil {
		if isLockNotAvailable(err) || isSerializationFailure(err) {
			return res, ErrSummaryUnusable
		}
		if !isNoRows(err) {
			return res, err
		}
	} else {
		st.initialized = true
	}
	if !st.current() {
		return res, ErrSummaryUnusable
	}
	var ep pendingEpisode
	var policyVersion *int64
	err = tx.QueryRow(ctx, `
		SELECT id, source, marked_by, marked_at, created_at, policy_kind, policy_id, batch_id::text, policy_version
		FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND id = $2 AND raised_at IS NULL
		  AND source IN ('portal', 'operator')
		FOR UPDATE
	`, tenantID, episodeID).Scan(&ep.id, &ep.source, &ep.markedBy, &ep.markedAt, &ep.createdAt, &ep.kind, &ep.policyID, &ep.batchID, &policyVersion)
	if isNoRows(err) {
		res.Skipped = "already_raised"
		return res, tx.Commit(ctx)
	}
	if err != nil {
		return res, fmt.Errorf("load unraised episode: %w", err)
	}
	if policyVersion != nil && st.summaryVersion < *policyVersion {
		return res, ErrSummaryUnusable
	}
	res.EpisodeID = ep.id
	markRaised := func() error {
		_, err := tx.Exec(ctx, `UPDATE software_unapproved_episodes SET raised_at = $2 WHERE id = $1`, ep.id, now)
		return err
	}

	active, err := tenantActive(ctx, tx, tenantID)
	if err != nil {
		return res, err
	}
	settings, err := GetSettings(ctx, tx, tenantID)
	if err != nil {
		return res, err
	}
	if !active || !settings.UnapprovedAlertsEnabled {
		res.Skipped = "alerts_disabled"
		if !active {
			res.Skipped = "tenant_inactive"
		}
		if err := markRaised(); err != nil {
			return res, err
		}
		return res, tx.Commit(ctx)
	}

	assessments, err := policyAssessments(ctx, tx, tenantID, ep.kind, ep.policyID, now)
	if err != nil {
		return res, err
	}
	payload := AlertPayload{
		Trigger: TriggerMarked, Policy: AlertPolicy{Kind: ep.kind, ID: ep.policyID},
		MarkedBy: ep.markedBy, MarkedVia: markedVia(ep.source), MarkedAt: ep.markedAt.UTC(), DetectedAt: now,
	}
	// Each device with the first product that put it on the list: the
	// PAT-2097 lifecycle row's product snapshot.
	devices := map[string]Product{}
	var deviceOrder []string
	listed := 0
	for _, a := range assessments {
		if len(a.Devices) == 0 {
			continue
		}
		p := AlertProduct{Product: a.Product, DeviceCount: len(a.Devices)}
		for _, d := range a.Devices {
			if _, ok := devices[d.DeviceID]; !ok {
				devices[d.DeviceID] = a.Product
				deviceOrder = append(deviceOrder, d.DeviceID)
			}
			if listed < MaxAlertDevices {
				p.Devices = append(p.Devices, alertDevices([]Presence{d})...)
				listed++
			} else {
				payload.Truncated = true
			}
		}
		payload.Products = append(payload.Products, p)
	}
	if len(devices) == 0 {
		// Not installed anywhere: nothing is sent. A later ingest that
		// finds it alerts per device.
		res.Skipped = "not_installed"
		if err := markRaised(); err != nil {
			return res, err
		}
		return res, tx.Commit(ctx)
	}
	payload.DeviceCount = len(devices)
	alertID, err := nextAlertID(ctx, tx)
	if err != nil {
		return res, err
	}
	payload.AlertID = alertID
	webhooks, err := insertAlert(ctx, tx, tenantID, alertID, ep.id, TriggerMarked, nil, payload, now)
	if err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `UPDATE software_unapproved_alerts SET email_batch_id = $2::uuid WHERE id = $1`,
		alertID, ep.batchID); err != nil {
		return res, fmt.Errorf("set alert email batch: %w", err)
	}
	// Paired UNNEST vectors have one slot per device, filled by the same
	// index. PostgreSQL pads unequal vectors with NULL; never rely on that.
	devIDs := make([]string, len(deviceOrder))
	products := make([]string, len(deviceOrder))
	for i, deviceID := range deviceOrder {
		productJSON, err := json.Marshal(devices[deviceID])
		if err != nil {
			return res, err
		}
		devIDs[i] = deviceID
		products[i] = string(productJSON)
	}
	var inserted int
	if err := tx.QueryRow(ctx, insertTrackedAlertsBulkSQL, ep.id, devIDs, tenantID, alertID, now, products).Scan(&inserted); err != nil {
		return res, fmt.Errorf("record alerted devices: %w", err)
	}
	res.AlertIDs = append(res.AlertIDs, alertID)
	res.Devices += inserted
	res.Webhooks += webhooks
	if err := markRaised(); err != nil {
		return res, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RaiseResult{}, err
	}
	return res, nil
}

// insertTrackedAlertsBulkSQL is insertTrackedAlertSQL(true) for many devices
// in one statement. Args: episode, device ids, tenant, alert id, time,
// product JSON per device.
const insertTrackedAlertsBulkSQL = `
	WITH ins AS (
		INSERT INTO software_unapproved_alerted_devices
		    (episode_id, device_id, tenant_id, alert_id, alerted_at, status_changed_at, product)
		SELECT $1, u.device_id, $3::uuid, $4, $5, $5, u.product::jsonb
		FROM unnest($2::uuid[], $6::text[]) AS u(device_id, product)
		ON CONFLICT (episode_id, device_id) DO NOTHING
		RETURNING id, episode_id, device_id, tenant_id, alerted_at
	), transitions AS (
	INSERT INTO software_unapproved_alert_transitions
	    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, created_at)
	SELECT tenant_id, id, episode_id, device_id, NULL, 'open', 'system', alerted_at FROM ins
	RETURNING id
	)
	SELECT count(*)::int FROM ins`

// RaiseMarks opens an episode for each mark and raises them as one batch, in
// two transactions. It exists for callers with no policy transaction of
// their own; policy writers use OpenEpisodeTx inside theirs.
func RaiseMarks(ctx context.Context, pool *pgxpool.Pool, tenantID string, marks []Mark, now time.Time) (RaiseResult, error) {
	if len(marks) == 0 {
		return RaiseResult{}, nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return RaiseResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	var batch string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&batch); err != nil {
		return RaiseResult{}, err
	}
	ids := make([]int64, 0, len(marks))
	for _, m := range marks {
		if m.TenantID != tenantID {
			return RaiseResult{}, errors.New("softwaregov: every mark in a batch must be for the same tenant")
		}
		if m.BatchID == "" {
			m.BatchID = batch
		}
		id, err := OpenEpisodeTx(ctx, tx, m)
		if err != nil {
			return RaiseResult{}, err
		}
		ids = append(ids, id)
	}
	if err := tx.Commit(ctx); err != nil {
		return RaiseResult{}, err
	}
	return RaiseEpisodes(ctx, pool, tenantID, ids, now)
}

// UnraisedBatch is a group of episodes still waiting for their marked alert.
type UnraisedBatch struct {
	TenantID   string
	BatchKey   string
	EpisodeIDs []int64
}

// UnraisedBatches lists portal and operator episodes whose post-commit raise
// has not happened, older than grace, grouped by tenant and batch.
func UnraisedBatches(ctx context.Context, q Querier, now time.Time, grace time.Duration, limit int) ([]UnraisedBatch, error) {
	rows, err := q.Query(ctx, `
		SELECT e.tenant_id::text, COALESCE(e.batch_id::text, ''), array_agg(e.id ORDER BY e.id)
		FROM software_unapproved_episodes e
		LEFT JOIN software_unapproved_runner_attempts a ON a.work_kind = 'marked'
		  AND a.tenant_id = e.tenant_id AND a.batch_key = COALESCE(e.batch_id::text, '')
		WHERE e.raised_at IS NULL AND e.source IN ('portal', 'operator') AND e.created_at <= $1
		GROUP BY e.tenant_id, e.batch_id
		ORDER BY min(a.attempted_at) NULLS FIRST, min(e.created_at), e.tenant_id, e.batch_id
		LIMIT $2
	`, now.Add(-grace), limit)
	if err != nil {
		return nil, fmt.Errorf("unraised episodes: %w", err)
	}
	defer rows.Close()
	var out []UnraisedBatch
	for rows.Next() {
		var b UnraisedBatch
		if err := rows.Scan(&b.TenantID, &b.BatchKey, &b.EpisodeIDs); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// hasUnapprovedPolicies is a cheap pre-check so extraction pays nothing for a
// tenant with no Unapproved policy or with the alert turned off.
func hasUnapprovedPolicies(ctx context.Context, q Querier, tenantID string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT COALESCE((SELECT unapproved_alerts_enabled FROM tenant_software_notification_settings WHERE tenant_id = $1::uuid), $2)
		   AND (EXISTS (SELECT 1 FROM tenant_app_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved')
		     OR EXISTS (SELECT 1 FROM tenant_extension_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved'))
	`, tenantID, DefaultUnapprovedAlertsEnabled).Scan(&ok)
	return ok, err
}

// DetectOnDevice raises an observed alert for every Unapproved product on
// one device whose (episode, device) pair has not been alerted. Call it after
// the extraction that wrote the device's inventory has committed, and only
// for a report whose evidence time is authoritative.
// A busy tenant alert lock leaves a durable check for DetectDeferred; it
// never waits behind a marked raise. Inventory triggers enqueue atomically
// before this post-commit hook, including when the hook fails outright.
func DetectOnDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time) (res RaiseResult, retErr error) {
	return detectOnDevice(ctx, pool, tenantID, deviceID, now, true)
}

func detectOnDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time, acknowledge bool) (res RaiseResult, retErr error) {
	now = now.UTC()
	var seq int64
	err := pool.QueryRow(ctx, `SELECT seq FROM software_unapproved_detection_queue WHERE device_id = $1::uuid`, deviceID).Scan(&seq)
	if err != nil && !isNoRows(err) {
		return res, err
	}
	// Acknowledge only after the alert transaction has finished. Holding a
	// queue row while holding the alert lock would block inventory writers.
	defer func() {
		if acknowledge && retErr == nil && res.Skipped != "alerts_busy" && res.Skipped != "tenant_inactive" && seq != 0 {
			// Best effort: locked marks and acknowledgement failures retain
			// the durable check; replay is safe through the alert ledger.
			ackDeviceCheck(ctx, pool, deviceID, seq)
		}
	}()
	relevant, err := hasUnapprovedPolicies(ctx, pool, tenantID)
	if err != nil {
		return res, fmt.Errorf("unapproved alert pre-check: %w", err)
	}
	if !relevant {
		res.Skipped = "nothing_to_check"
		return res, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer rollbackDeviceCheckTx(tx)
	locked, err := tryLockTenantAlerts(ctx, tx, tenantID)
	if err != nil {
		return res, fmt.Errorf("lock tenant alerts: %w", err)
	}
	if !locked {
		res.Skipped = "alerts_busy"
		// Normally the inventory trigger already queued this device. Also
		// cover explicit callers whose inventory predates migration 0202.
		// An explicit detection caller supplies observation evidence, not
		// application absence authority. Do not replace an extractor stamp.
		if _, err := tx.Exec(ctx, `INSERT INTO software_unapproved_detection_queue (device_id, seq, apps_complete, detect_allowed)
			VALUES ($1::uuid, txid_current(), FALSE, TRUE) ON CONFLICT (device_id) DO NOTHING`, deviceID); err != nil {
			return res, err
		}
		return res, tx.Commit(ctx)
	}
	if ok, err := tenantActive(ctx, tx, tenantID); err != nil || !ok {
		res.Skipped = "tenant_inactive"
		return res, err
	}
	assessments, err := loadAssessments(ctx, tx, tenantID, deviceID, now)
	if err != nil {
		return res, err
	}
	for _, a := range assessments {
		if a.State != StateUnapproved || a.PolicyID == 0 || len(a.Devices) == 0 {
			continue
		}
		// PAT-2058: Homebrew is deliberately excluded from unapproved-alert
		// generation. software_unapproved_episodes.policy_kind's CHECK only
		// admits 'application'/'browser_extension' (0183); insertEpisode
		// below would fail the whole detection pass for every product on
		// this device if a Homebrew assessment reached it. Homebrew
		// approval decisions still feed the drift report and the decision
		// audit (software_approval_decisions) -- they just never raise a
		// software.unapproved email or webhook.
		if a.PolicyKind != TypeApplication && a.PolicyKind != TypeBrowserExtension {
			continue
		}
		ep, err := latestEpisode(ctx, tx, tenantID, a.PolicyKind, a.PolicyID)
		if err != nil {
			return res, err
		}
		if ep == nil {
			// No recorded transition: the policy was Unapproved before this
			// feature existed, or was set by a path that opens no episode.
			// Its row's updated_at is the best evidence of when.
			markedAt := now
			if a.PolicyUpdatedAt != nil {
				markedAt = *a.PolicyUpdatedAt
			}
			if ep, err = insertEpisode(ctx, tx, tenantID, a.PolicyKind, a.PolicyID, SourceObserved, nil, markedAt); err != nil {
				return res, err
			}
		}
		if (ep.source == SourcePortal || ep.source == SourceOperator) && ep.raisedAt == nil {
			// The marked alert for this transition has not been raised yet.
			// It will list this device; alerting here as well would send
			// the device twice and break the one-email batch.
			continue
		}
		res.EpisodeID = ep.id
		for _, d := range a.Devices {
			var covered bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM software_unapproved_alerted_devices WHERE episode_id = $1 AND device_id = $2::uuid)
			`, ep.id, d.DeviceID).Scan(&covered); err != nil {
				return res, fmt.Errorf("check alerted device: %w", err)
			}
			if covered {
				continue
			}
			alertID, err := nextAlertID(ctx, tx)
			if err != nil {
				return res, err
			}
			payload := AlertPayload{
				AlertID: alertID, Trigger: TriggerObserved, Policy: AlertPolicy{Kind: a.PolicyKind, ID: a.PolicyID},
				MarkedBy: ep.markedBy, MarkedVia: markedVia(ep.source), MarkedAt: ep.markedAt, DetectedAt: now,
				DeviceCount: 1,
				Products:    []AlertProduct{{Product: a.Product, DeviceCount: 1, Devices: alertDevices([]Presence{d})}},
			}
			devID := d.DeviceID
			webhooks, err := insertAlert(ctx, tx, tenantID, alertID, ep.id, TriggerObserved, &devID, payload, now)
			if err != nil {
				return res, err
			}
			productJSON, err := json.Marshal(a.Product)
			if err != nil {
				return res, err
			}
			if _, err := tx.Exec(ctx, insertTrackedAlertSQL(false),
				ep.id, d.DeviceID, tenantID, alertID, now, string(productJSON)); err != nil {
				return res, fmt.Errorf("record alerted device: %w", err)
			}
			res.AlertIDs = append(res.AlertIDs, alertID)
			res.Devices++
			res.Webhooks += webhooks
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// QueueDeviceCheckTx stamps the actual prune decision and evidence-time gate
// after all inventory writes, in their transaction. Triggers alone cannot
// know whether a report supplied application absence authority.
func QueueDeviceCheckTx(ctx context.Context, tx pgx.Tx, deviceID string, appsComplete, detectAllowed bool) error {
	_, err := tx.Exec(ctx, `INSERT INTO software_unapproved_detection_queue
		(device_id, seq, apps_complete, detect_allowed) VALUES ($1::uuid, txid_current(), $2, $3)
		ON CONFLICT (device_id) DO UPDATE SET seq = EXCLUDED.seq,
		apps_complete = EXCLUDED.apps_complete, detect_allowed = EXCLUDED.detect_allowed, queued_at = now()`,
		deviceID, appsComplete, detectAllowed)
	return err
}

func ackDeviceCheck(ctx context.Context, pool *pgxpool.Pool, deviceID string, seq int64) {
	_, _ = pool.Exec(ctx, `DELETE FROM software_unapproved_detection_queue
		WHERE device_id IN (SELECT device_id FROM software_unapproved_detection_queue
		WHERE device_id = $1::uuid AND seq = $2 FOR UPDATE SKIP LOCKED)`, deviceID, seq)
}

// ProcessDeviceCheck completes detection and lifecycle before acknowledging
// queued work. A busy lock in either phase leaves the check durable.
func ProcessDeviceCheck(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, auth DeviceAuthority, now time.Time) (RaiseResult, ReconcileResult, error) {
	var seq int64
	var complete, allowed bool
	err := pool.QueryRow(ctx, `SELECT seq, apps_complete, detect_allowed
		FROM software_unapproved_detection_queue WHERE device_id = $1::uuid`, deviceID).Scan(&seq, &complete, &allowed)
	if err != nil && !isNoRows(err) {
		return RaiseResult{}, ReconcileResult{}, err
	}
	if err == nil {
		if !allowed {
			ackDeviceCheck(ctx, pool, deviceID, seq)
			return RaiseResult{Skipped: "evidence_not_authoritative"}, ReconcileResult{}, nil
		}
		auth = DeviceAuthority{AppsComplete: complete, queueSeq: seq}
	}
	raised, err := detectOnDevice(ctx, pool, tenantID, deviceID, now, false)
	if err != nil || raised.Skipped == "alerts_busy" || raised.Skipped == "tenant_inactive" {
		return raised, ReconcileResult{}, err
	}
	reconciled, err := ReconcileDevice(ctx, pool, tenantID, deviceID, auth, now)
	if err == nil && reconciled.Skipped != "alerts_busy" && reconciled.Skipped != "tenant_inactive" && seq != 0 {
		ackDeviceCheck(ctx, pool, deviceID, seq)
	}
	return raised, reconciled, err
}

// deferredDeviceCheckTimeout bounds a single device's database work, including
// lifecycle row locks. Five seconds leaves room for ordinary multi-query checks
// while preventing one stuck transaction from indefinitely holding up delivery
// and other queued devices on the runner's long-lived context.
const deferredDeviceCheckTimeout = 5 * time.Second

// DetectDeferred retries durable device checks after marked raises. It takes
// no queue row lock while checking inventory or acquiring the alert lock.
// Failures remain queued, are rotated behind older work, and are returned
// together after other selected devices have had their opportunity to run.
func DetectDeferred(ctx context.Context, pool *pgxpool.Pool, limit int, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, runnerStageTimeout)
	defer cancel()
	if _, err := pool.Exec(ctx, `DELETE FROM software_unapproved_detection_queue q
		WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.id = q.device_id)`); err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT d.tenant_id::text, q.device_id::text, q.seq
		FROM software_unapproved_detection_queue q JOIN devices d ON d.id = q.device_id
		JOIN tenants t ON t.id = d.tenant_id AND t.revoked_at IS NULL
		ORDER BY q.queued_at, q.device_id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	type check struct {
		tenant, device string
		seq            int64
	}
	var checks []check
	for rows.Next() {
		var c check
		if err := rows.Scan(&c.tenant, &c.device, &c.seq); err != nil {
			rows.Close()
			return err
		}
		checks = append(checks, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var failures error
	for _, c := range checks {
		if ctx.Err() != nil {
			return errors.Join(failures, ctx.Err())
		}
		deviceCtx, cancel := context.WithTimeout(ctx, deferredDeviceCheckTimeout)
		_, _, err := ProcessDeviceCheck(deviceCtx, pool, c.tenant, c.device, DeviceAuthority{}, now)
		cancel()
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("deferred device %s: %w", c.device, err))
			if ctx.Err() != nil {
				break
			}
			// Keep failed work, but move it behind older checks so a poison
			// device cannot monopolise successive bounded batches. Never
			// reorder a newer report that arrived while this check ran.
			_, retryErr := pool.Exec(ctx, `UPDATE software_unapproved_detection_queue
				SET queued_at = now() WHERE device_id IN (
				SELECT device_id FROM software_unapproved_detection_queue
				WHERE device_id = $1::uuid AND seq = $2 FOR UPDATE SKIP LOCKED)`, c.device, c.seq)
			failures = errors.Join(failures, retryErr)
		}
	}
	return failures
}

// insertTrackedAlertSQL records one (episode, device) pair in the dedupe
// ledger, which is also the PAT-2097 tracked alert, open, with its first
// transition. Args: episode, device, tenant, outbound alert id, time,
// product JSON.
func insertTrackedAlertSQL(onConflictNothing bool) string {
	conflict := ""
	if onConflictNothing {
		conflict = "ON CONFLICT (episode_id, device_id) DO NOTHING"
	}
	return `
		WITH ins AS (
			INSERT INTO software_unapproved_alerted_devices
			    (episode_id, device_id, tenant_id, alert_id, alerted_at, status_changed_at, product)
			VALUES ($1, $2::uuid, $3::uuid, $4, $5, $5, $6::jsonb)
			` + conflict + `
			RETURNING id, episode_id, device_id, tenant_id, alerted_at
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, created_at)
		SELECT tenant_id, id, episode_id, device_id, NULL, 'open', 'system', alerted_at FROM ins`
}
