package extractor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/automations"
	"patched.im/api/internal/evaluator"
	"patched.im/api/internal/findinglifecycle"
	"patched.im/api/internal/healthsignals"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/notify"
	"patched.im/api/internal/releasecontrol"
	"patched.im/api/internal/softwaregov"
	"patched.im/api/internal/webhook"
)

// minSupportedSchemaVersion / maxSupportedSchemaVersion bracket the payload
// shapes this extractor understands. Rows outside this range are marked with
// extraction_error and skipped — fail loudly rather than silently misparse.
//
// v2 = current production shape (collector 0.2.0+).
// v3 = adds T2 compliance signals once the first T2 collector batch ships
//
//	(ADR-0001 action item 5). The compliance bag is additionalProperties:true
//	so new keys flow through without any code change here.
const (
	minSupportedSchemaVersion = 2
	maxSupportedSchemaVersion = 3
)

func clearLegacyInventoryAuthority(p *payload) {
	if p == nil || p.SchemaVersion >= 3 {
		return
	}
	// Inventory authority is an authenticated schema-v3 contract. Ignore
	// capability/kind fields smuggled into otherwise valid legacy payloads.
	p.InventoryCapabilities = nil
	for i := range p.Apps {
		p.Apps[i].IdentifierKind = ""
	}
}

// maxAttempts caps how many times the extractor will re-claim a failing row.
// At the cap we leave extracted_at NULL and stop attempting — the partial
// index keeps the row visible to the worker but the in-process filter drops
// it. Operators can manually clear extraction_error to retry, or write a
// later migration to triage the dead-letter set.
const maxAttempts = 10

// healthSignalsInterval is the minimum gap between health-signals recompute runs.
// Runs nightly; the extractor checks at most once per hour to keep the poll overhead low.
const healthSignalsInterval = 24 * time.Hour

// Worker is the polling extractor. One goroutine per Worker.
type Worker struct {
	Pool                   *pgxpool.Pool
	Logger                 *slog.Logger
	BatchSize              int              // rows per poll, default 50
	PollEvery              time.Duration    // sleep when the queue is empty, default 5s
	Notifier               *notify.Notifier // nil = notifications disabled
	lastHealthSignalsCheck time.Time
	lastCVEQueueMetrics    time.Time
}

// claimedRow is everything Run needs about one raw_payloads row to extract
// from it. Fetched inside the claim transaction; processed under a fresh tx.
type claimedRow struct {
	ID         int64
	ReceivedAt time.Time
	TenantID   string
	Attempts   int32
	Body       []byte
}

// Run polls until ctx is cancelled. Returns ctx.Err() on shutdown.
func (w *Worker) Run(ctx context.Context) error {
	if w.BatchSize <= 0 {
		w.BatchSize = 50
	}
	if w.PollEvery <= 0 {
		w.PollEvery = 5 * time.Second
	}
	logger := w.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Info("extractor starting",
		"batch_size", w.BatchSize,
		"poll_every", w.PollEvery.String(),
		"min_schema_version", minSupportedSchemaVersion,
		"max_schema_version", maxSupportedSchemaVersion,
	)

	for {
		select {
		case <-ctx.Done():
			logger.Info("extractor shutdown")
			return ctx.Err()
		default:
		}

		batch, err := w.claimBatch(ctx)
		if err != nil {
			logger.Error("claim batch failed", "err", err)
			// Back off slightly on persistent DB failures rather than hammer.
			if !sleep(ctx, w.PollEvery) {
				return ctx.Err()
			}
			continue
		}

		// PAT-1570: this check must run every poll cycle regardless of batch
		// content, not just when there's data to extract. It used to live
		// below the `len(batch) == 0` early-continue, which meant a quiet
		// ingest period (no pending raw_payloads rows) silently starved it
		// forever -- the loop never reached this code at all while idle, no
		// matter how many hours passed. It's already self-throttled to at
		// most once per hour via lastHealthSignalsCheck, so hoisting it above
		// the empty-batch guard doesn't change how often the recompute can
		// run -- it only removes the traffic-dependency on when the check
		// gets a chance to evaluate that gate at all.
		if time.Since(w.lastHealthSignalsCheck) >= time.Hour {
			w.lastHealthSignalsCheck = time.Now()
			if automations.ShouldRun(ctx, w.Pool, "health_signals_recompute", healthSignalsInterval) {
				w.runHealthSignalsRecompute(ctx, logger)
			}
		}

		// PAT-2024: drain the event-driven CVE match queue every cycle,
		// busy or idle, so a queued product is matched within one poll
		// interval of its payload committing. Bounded per cycle.
		w.drainCVEQueue(ctx, logger)

		if len(batch) == 0 {
			if !sleep(ctx, w.PollEvery) {
				return ctx.Err()
			}
			continue
		}

		metrics.ExtractorBatchSize.Observe(float64(len(batch)))

		// Roll over any deferred new-app rows whose snooze window has expired
		// before processing the batch so the DB is tidy on every cycle.
		rolloverDeferredNewApps(ctx, w.Pool, logger)

		// Track which tenants appear in this batch so we run the new-app sweep
		// once per tenant after all their rows are processed.
		tenantsSeen := map[string]struct{}{}

		for _, row := range batch {
			rowLogger := logger.With(
				"raw_payload_id", row.ID,
				"tenant_id", row.TenantID,
				"attempt", row.Attempts,
			)
			if err := w.processRow(ctx, row, rowLogger); err != nil {
				rowLogger.Warn("extraction failed", "err", err)
				recordProcessError(row.Attempts)
				if markErr := w.markFailed(ctx, row, err); markErr != nil {
					rowLogger.Error("mark failed update failed", "err", markErr)
				}
				continue
			}
			metrics.ExtractorRowsProcessed.WithLabelValues("success").Inc()
			rowLogger.Info("extracted")
			tenantsSeen[row.TenantID] = struct{}{}
		}

		// Post-ingest new-app discovery sweep — one pass per tenant in the batch.
		for tenantID := range tenantsSeen {
			detectNewTenantApps(ctx, w.Pool, tenantID, w.Notifier, logger.With("sweep", "new_apps"))
		}
	}
}

// shouldRunLegacyRingTick remains as a narrow invariant seam: retained legacy
// rollouts are permanently quarantined, so extraction never observes, advances
// or publishes them. Reintroduction needs a separately reviewed implementation.
func (w *Worker) shouldRunLegacyRingTick(time.Time) bool { return false }

// claimBatch atomically grabs up to BatchSize unprocessed rows, increments
// attempts, and returns the row payloads for processing in a fresh transaction.
// The CTE+UPDATE pattern is the canonical pgsql idiom for "claim and bump":
// the inner SELECT FOR UPDATE SKIP LOCKED grabs row locks (safe for future
// worker concurrency) and the outer UPDATE acts on the locked rows in the
// same statement, all in one round trip. RETURNING gives us the payload.
func (w *Worker) claimBatch(ctx context.Context) ([]claimedRow, error) {
	const stmt = `
		WITH claimed AS (
			SELECT id, received_at FROM raw_payloads
			WHERE extracted_at IS NULL
			  AND extraction_attempts < $1
			ORDER BY received_at
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE raw_payloads r
		SET extraction_attempts = r.extraction_attempts + 1
		FROM claimed c
		WHERE r.id = c.id AND r.received_at = c.received_at
		RETURNING r.id, r.received_at, r.tenant_id::text, r.extraction_attempts, r.body::text
	`
	rows, err := w.Pool.Query(ctx, stmt, maxAttempts, w.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("claim query: %w", err)
	}
	defer rows.Close()

	var out []claimedRow
	for rows.Next() {
		var r claimedRow
		var body string
		if err := rows.Scan(&r.ID, &r.ReceivedAt, &r.TenantID, &r.Attempts, &body); err != nil {
			return nil, fmt.Errorf("scan claim row: %w", err)
		}
		r.Body = []byte(body)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claim rows: %w", err)
	}
	return out, nil
}

// processRow runs the full extraction for one row in a single transaction.
// Either everything commits (and extracted_at gets set) or nothing does
// (caller bumps the error counter).
func (w *Worker) processRow(ctx context.Context, row claimedRow, logger *slog.Logger) error {
	var p payload
	if err := json.Unmarshal(row.Body, &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	var fieldPresence struct {
		Apps              json.RawMessage `json:"apps"`
		BrowserExtensions json.RawMessage `json:"browser_extensions"`
	}
	if err := json.Unmarshal(row.Body, &fieldPresence); err != nil {
		return fmt.Errorf("inspect payload fields: %w", err)
	}
	p.AppsPresent = bytes.HasPrefix(bytes.TrimSpace(fieldPresence.Apps), []byte("["))
	p.BrowserExtensionsPresent = bytes.HasPrefix(bytes.TrimSpace(fieldPresence.BrowserExtensions), []byte("["))
	if p.SchemaVersion < minSupportedSchemaVersion || p.SchemaVersion > maxSupportedSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (supported: %d–%d)", p.SchemaVersion, minSupportedSchemaVersion, maxSupportedSchemaVersion)
	}
	clearLegacyInventoryAuthority(&p)

	// Resolve platform — v2 payloads omit the field; default to "macos".
	platform := p.Platform
	if platform == "" {
		platform = "macos"
	}

	// Check the per-tenant, per-OS master switch. When the platform is disabled
	// for this tenant, we skip evaluation entirely — no compliance_evaluations
	// rows are written. This overrides T1 always-on rules. Extraction of device,
	// apps, signals, and patches continues normally; only the verdict is absent.
	platformEnabled, switchErr := isPlatformEnabled(ctx, w.Pool, row.TenantID, platform)
	if switchErr != nil {
		logger.Warn("platform switch check failed; skipping evaluation", "err", switchErr, "platform", platform)
		platformEnabled = false
	}

	// Load app_group_rules once per row — outside the write transaction so a
	// missing table (pre-migration env) degrades gracefully rather than aborting
	// extraction. On error we log and proceed with an empty rule set (no Layer B
	// rewriting, but Layer A suppression is unaffected — it's purely in-process).
	groupRules, grErr := loadAppGroupRules(ctx, w.Pool)
	if grErr != nil {
		logger.Warn("failed to load app_group_rules; proceeding without vendor prefix grouping", "err", grErr)
		groupRules = nil
	}

	tx, err := w.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op if Commit succeeded
	// Acquire release locks before device/health writes, in the same order as
	// portal changes. Tenant serialization preserves an exact pre-beta health
	// baseline while shared gate participation lets unrelated tenants ingest
	// concurrently without racing an exclusive promotion.
	if err := releasecontrol.SharedLock(ctx, tx); err != nil {
		return err
	}
	if err := releasecontrol.TenantLock(ctx, tx, row.TenantID); err != nil {
		return err
	}

	deviceID, deviceClass, err := upsertDevice(ctx, tx, row.TenantID, row.ReceivedAt, &p, logger)
	if err != nil {
		return err
	}

	// Rule loading (PAT-1960) happens AFTER upsertDevice, deliberately, and
	// uses the device_class upsertDevice actually returns — never the
	// payload's own top-level device_class field in isolation. Those two can
	// disagree: an already-classified device (e.g. a known 'server') whose
	// LATEST payload omits device_class, or reports the agent's own literal
	// "unknown", still preserves its stored classification (see
	// upsertDevice's deviceClassGiven CASE), and rule loading must follow
	// that preserved value, not silently fall back to 'unknown' and evaluate
	// the device against the wrong rule set for this one ingest — that would
	// reintroduce exactly the wrong-pass risk this whole ticket exists to
	// close.
	var allRules []evaluator.Rule
	if platformEnabled {
		// Load T1 rules for this device's platform and class. Failures are
		// non-fatal: extraction proceeds without evaluations rather than
		// blocking the row.
		rules, ruleErr := evaluator.LoadRules(ctx, w.Pool, platform, deviceClass)
		if ruleErr != nil {
			logger.Warn("loadrules failed; extracting without T1 evaluations", "err", ruleErr)
		} else {
			allRules = append(allRules, rules...)
		}

		// Load T2 rules enabled for this tenant, platform and class. Same non-fatal policy.
		t2Rules, t2Err := evaluator.LoadRulesForTenant(ctx, w.Pool, row.TenantID, platform, deviceClass)
		if t2Err != nil {
			logger.Warn("loadrulesfortenant failed; extracting without T2 evaluations", "err", t2Err)
		} else {
			allRules = append(allRules, t2Rules...)
		}
	} else {
		logger.Info("platform disabled for tenant; skipping evaluation",
			"platform", platform, "tenant_id", row.TenantID)
	}

	// PAT-1825: upsertDevice just set devices.last_seen (from received_at,
	// PAT-2102) above — check
	// whether this device carries a live disposition record it should
	// therefore supersede (see disposition_reappearance.go for why "any
	// ingest while a disposition is live" is exactly the reappearance
	// condition). No-op for the overwhelming common case of a device with no
	// disposition at all. PAT-2108: compares against this report's own
	// received_at, not extraction-time now() — a report received before the
	// disposition was recorded must never read as reappearance just because
	// extraction fell behind.
	if _, err := checkAndSupersedeReappearedDisposition(ctx, tx, row.TenantID, deviceID, row.ReceivedAt, logger); err != nil {
		return err
	}

	if err := linkRawPayloadToDevice(ctx, tx, row.ID, row.ReceivedAt, deviceID); err != nil {
		return err
	}

	// PAT-2024: capture the device's products before upsertApps rewrites
	// them, so the CVE match queue receives only what this payload changed.
	cveBefore := snapshotAppsForCVEQueue(ctx, tx, deviceID, logger)

	// observed_at uses received_at rather than now() so re-extraction of
	// an old row preserves the original timeline.
	// PAT-2063: the prune of unreported apps, and every application absence
	// scope after it, needs authority from collection_status.apps or, for an
	// agent that sends no status, the safety valve (apps_authority.go).
	appsSig, appsWithheldReason, appsSigDetail := resolveAppsSignal(&p)
	// PAT-2075: per-user rows carry their own authority. Only users this
	// report lists as complete in collection_status.apps_users are pruned.
	appsCompleteUsers, _ := appsUserCompleteSet(&p)
	// PAT-2393: whether a declared Windows approval is effective follows the
	// tenant's installation evidence, so this report can suspend or restore
	// one for every device. Fingerprint it either side of the inventory writes.
	declaredBefore := ""
	if platform == "windows" {
		if declaredBefore, err = softwaregov.DeclaredWindowsEligibility(ctx, tx, row.TenantID); err != nil {
			return err
		}
	}
	appCount, appsDecision, err := upsertApps(ctx, tx, deviceID, row.ReceivedAt, p.Apps, groupRules, platform, appsSig, appsWithheldReason, appsCompleteUsers,
		resolveLegacyUserHold(&p, appsCompleteUsers))
	if err != nil {
		return err
	}
	// PAT-2097: only an explicit, schema v3 "complete" whose prune ran may
	// resolve an unapproved software alert as not observed. The no-signal
	// safety valve is a backstop, not authority, so it never resolves one.
	appsAbsenceComplete := appsSig == appsSignalComplete && appsDecision.Pruned
	if !appsDecision.Pruned {
		p.AppsAbsenceWithheld = true
		recordAppsWithheld(logger, deviceID, appsDecision, appsSigDetail)
	}
	// The software-policy lifecycle holds every per-user scope this report
	// did not list (loadHeldUserApps).
	p.AppsUserScopesSeen = appsDecision.UserScopesSeen
	// PAT-2075: machine-wide rows located in a user's home that this report
	// had no authority over. Held, counted in the run's coverage, and kept
	// present for the installation closure and the policy lifecycle.
	p.AppsLegacyHeld = appsDecision.LegacyHeld
	if len(appsDecision.LegacyHeld) > 0 {
		logger.Warn("apps: legacy user-located rows held; no report has had authority over their home directory",
			"device_id", deviceID, "rows", len(appsDecision.LegacyHeld))
	}
	if appsDecision.LegacyRehomed > 0 || appsDecision.LegacyOwnerPruned > 0 {
		logger.Info("apps: legacy user-located rows resolved",
			"device_id", deviceID, "rehomed", appsDecision.LegacyRehomed,
			"owner_pruned", appsDecision.LegacyOwnerPruned, "deleted_rows", appsDecision.LegacyRowsDeleted)
	}
	if appsDecision.DroppedOverlong > 0 {
		logger.Warn("apps: rows with an over-long user_account dropped; that user's apps were not stored and grant no authority",
			"device_id", deviceID, "rows", appsDecision.DroppedOverlong, "max_runes", appsMaxUserAccountLen)
	}
	if appsDecision.UserScopesPruned > 0 {
		logger.Info("apps: per-user scopes pruned for users reported complete",
			"device_id", deviceID, "users", len(appsCompleteUsers),
			"scope_rows", appsDecision.UserScopesPruned, "deleted_rows", appsDecision.UserRowsDeleted)
	}
	// Removals are queued for a CVE re-match only for rows actually deleted:
	// the full prune, the superseded-version and time-release prunes that
	// still run while a report is held, or a complete user's prune
	// (PAT-2075). Held rows, machine-wide or per-user, stay in device_apps,
	// so the before/after diff cannot report them as removed.
	enqueueCVEIngestDelta(ctx, tx, row.TenantID, deviceID, platform, cveBefore,
		p.AppsPresent && appsDecision.MayHaveRemovedRows(), logger)

	// PAT-1461: preserve every reported application as immutable evidence and
	// maintain the read-only normalised installation projection. This runs
	// beside device_apps and has no policy, package, deployment, or remediation
	// side effects.
	// PAT-2023: the Homebrew block is stored inside upsertSoftwareInventory,
	// so its CVE delta is snapshotted around that call, exactly as the app
	// delta is around upsertApps.
	brewCVEBefore := snapshotHomebrewForCVEQueue(ctx, tx, deviceID, homebrewForPlatform(&p, platform), logger)
	softwareObservationCount, err := upsertSoftwareInventory(ctx, tx, row, deviceID, &p, platform)
	if err != nil {
		return err
	}
	enqueueCVEHomebrewDelta(ctx, tx, row.TenantID, deviceID, brewCVEBefore, logger)
	declaredEligibilityChanged := false
	if platform == "windows" {
		declaredAfter, err := softwaregov.DeclaredWindowsEligibility(ctx, tx, row.TenantID)
		if err != nil {
			return err
		}
		declaredEligibilityChanged = declaredAfter != declaredBefore
	}

	// macOS patch history. Empty slice (older collectors) is fine — function
	// returns 0 without touching the DB.
	patchCount, err := upsertPatches(ctx, tx, deviceID, p.Patches)
	if err != nil {
		return err
	}

	// Certificate inventory (PAT-216; collection_status semantics PAT-1732).
	// Absent collection_status object/key + absent certs key → no-op; absent
	// collection_status + explicit empty → prune all; absent collection_status
	// + non-empty → upsert + prune stale; partial → upsert sent, prune
	// nothing; unavailable → write nothing at all. All in the same transaction.
	certCount, err := upsertCertificates(ctx, tx, deviceID, p.Certificates, p.CollectionStatus, logger)
	if err != nil {
		return err
	}

	// Hardware health snapshot (PAT-251). Absent key → no-op; present →
	// upsert device_hardware + replace storage/disk child rows.
	hwHealthCount, err := upsertHardwareHealth(ctx, tx, deviceID, platform, p.HardwareHealth, logger)
	if err != nil {
		return err
	}

	// Standing local administrator roster (PAT-1974). Absent key → no-op
	// (agent predates PAT-1974); present → replace/upsert local_admin_accounts
	// per the object's own collection_status. local_admin_count itself is
	// unchanged — it still flows through the flat compliance bag below.
	// Each account's optional account_state (PAT-1992, the built-in RID-500
	// Administrator's enabled state) rides on the same localAdminPart and is
	// persisted by upsertLocalAdmins; a partial run never blanks a stored one.
	localAdminCount, err := upsertLocalAdmins(ctx, tx, deviceID, p.LocalAdmins, logger)
	if err != nil {
		return err
	}

	// Firmware identity (PAT-2262). Absent key → no-op ("not reported");
	// present → immutable observation plus the per-device projection, see
	// upsertFirmware. collected_at is recorded as observed_at only when it
	// parses; the projection is ordered by the raw payload's received_at.
	fwCollectedAt, _ := time.Parse(time.RFC3339, p.CollectedAt)
	if err := upsertFirmware(ctx, tx, row, deviceID, p.Firmware, fwCollectedAt, logger); err != nil {
		return err
	}

	// Kernel drivers and blocklist enforcement (PAT-2263). Absent key → no-op
	// ("not reported"); present → immutable header observation plus the
	// per-device projection, see upsertKernelDrivers.
	if err := upsertKernelDrivers(ctx, tx, row, deviceID, p.KernelDrivers, fwCollectedAt, logger); err != nil {
		return err
	}

	// OS-update-currency verdict (PAT-1806). Absent/malformed key → no-op,
	// existing device_os_update row preserved; present → upsert. Neither
	// endpoint agent sends this yet — this is the receiving half only.
	if err := upsertOSUpdate(ctx, tx, deviceID, parseOSUpdate(p.OSUpdate, logger), logger); err != nil {
		return err
	}

	// devices.collection_status snapshot (PAT-1732, migration 0128): makes a
	// degraded top-level or hardware_health collection visible on the
	// platform. Merges in place — a payload carrying neither object leaves
	// the column untouched; see upsertCollectionStatus.
	var hwCollectionStatus *hwCollectionStatusPart
	if p.HardwareHealth != nil {
		hwCollectionStatus = p.HardwareHealth.CollectionStatus
	}
	var laCollectionStatus string
	if p.LocalAdmins != nil {
		laCollectionStatus = p.LocalAdmins.CollectionStatus
	}
	if err := upsertCollectionStatus(ctx, tx, deviceID, p.CollectionStatus, hwCollectionStatus, laCollectionStatus, logger); err != nil {
		return err
	}

	// Browser extension inventory (PAT-125). Absent key or empty array → no-op.
	// Risk level is computed server-side so it can be retuned without an agent release.
	// PAT-2055: one stamp, read under the device row lock, for this report's
	// last_seen and its completion time (see browserExtensionSeenAt).
	extSeenAt, err := browserExtensionSeenAt(ctx, tx, deviceID)
	if err != nil {
		return err
	}
	extCount, err := upsertBrowserExtensions(ctx, tx, deviceID, p.BrowserExtensions, extSeenAt, logger)
	if err != nil {
		return err
	}
	// PAT-2055: the array's completeness. Absent block → no-op, and readers
	// keep the pre-PAT-2055 presence rule.
	if err := upsertBrowserExtensionsStatus(ctx, tx, row, deviceID, p.BrowserExtensionsStatus, p.BrowserExtensions, extSeenAt, logger); err != nil {
		return err
	}
	// PAT-2067: Safari's own completeness signal. Runs after the status
	// block so the per-device state row a current macOS agent creates in the
	// same report exists. Absent signal → no-op, Safari rows never absent.
	if err := upsertSafariExtensionsAuthority(ctx, tx, row, deviceID, &p, extSeenAt, logger); err != nil {
		return err
	}

	// PAT-2015: category tags for the apps and extensions written above.
	// Savepoint-guarded; can never fail this extraction.
	evaluateCategoryTags(ctx, tx, row.TenantID, deviceID, logger)

	// Degraded-capability channel (PAT-1064). Absent/malformed top-level
	// section → no opinion, existing rows untouched; present + degraded: []
	// → agent reports all clear, rows cleared; present + entries → upsert and
	// (only when the reported set is complete AND the payload isn't stale)
	// clear-on-recovery. See upsertAgentHealth's doc comment for the full
	// three-way semantics, the prune-safety reasoning, and the recency guard.
	// agentHealthDropped is entries lost to the array cap or per-entry
	// validation this ingest — logged below so a device silently losing
	// health entries is visible, even though no single bad entry ever fails
	// the payload.
	//
	// agentHealthCollectedAt is p.CollectedAt (a required top-level field)
	// parsed as RFC3339. A parse failure falls back to the zero time.Time,
	// which always loses the recency comparisons inside upsertAgentHealth —
	// an unparseable timestamp must never be treated as "newest", since that
	// would let it clear or prune data it has no real claim to supersede.
	agentHealthCollectedAt, caErr := time.Parse(time.RFC3339, p.CollectedAt)
	if caErr != nil {
		if logger != nil {
			logger.Warn("agent_health: payload collected_at did not parse as RFC3339; treating as oldest possible (this ingest cannot clear or prune)",
				"device_id", deviceID, "collected_at_raw", p.CollectedAt, "err", caErr)
		}
		agentHealthCollectedAt = time.Time{}
	}
	if err := upsertUpdateChannelObservation(ctx, tx, row.TenantID, deviceID, p.AgentHealth, agentHealthCollectedAt, row.ReceivedAt, row.ID, logger); err != nil {
		return err
	}
	agentHealthCount, agentHealthDropped, err := upsertAgentHealth(ctx, tx, deviceID, p.AgentHealth, agentHealthCollectedAt, logger)
	if err != nil {
		return err
	}
	healthComplete := releaseHealthSnapshotComplete(p.AgentHealth, agentHealthCount, agentHealthDropped)
	if err := releasecontrol.Observe(ctx, tx, row.TenantID, deviceID, platform, p.AgentVersion, row.ID, row.ReceivedAt, agentHealthCollectedAt, healthComplete); err != nil {
		return err
	}

	softwareLifecycleCount, softwareNotifications, err := recordSoftwareFindingObservations(
		ctx, tx, row.TenantID, deviceID, platform, &p,
		agentHealthCollectedAt, row.ID, row.ReceivedAt,
	)
	if err != nil {
		return err
	}
	// PAT-1888: held until after the commit below. See raiseFindingNotifications.
	pendingNotifications := softwareNotifications
	if softwareLifecycleCount > 0 && logger != nil {
		logger.Info("finding lifecycle events recorded", "device_id", deviceID, "kind", "software", "count", softwareLifecycleCount)
	}

	// Applied configuration observed on the device (PAT-1667 agent, PAT-1668
	// server). Append-only: one immutable snapshot per device per collection
	// run, never an update of a previous one. Absent/malformed section →
	// no snapshot row at all, which is deliberately distinguishable from a
	// stored snapshot reporting zero profiles.
	//
	// agentHealthCollectedAt is reused as the observation time — it is the
	// same payload collected_at, already parsed once above, and a parse
	// failure leaves it zero, which insertAppliedConfigSnapshot replaces
	// with received_at rather than storing an invented instant.
	appliedConfigProfileCount, err := insertAppliedConfigSnapshot(
		ctx, tx, row.TenantID, deviceID, row.ID, row.ReceivedAt, agentHealthCollectedAt,
		parseAppliedConfiguration(p.AppliedConfiguration, logger), logger)
	if err != nil {
		return err
	}

	// Build the signals map once — fed both to insertComplianceSignals (the
	// storage path) and to evaluator.Evaluate (the rule-engine path) so the
	// two stay in lockstep. Drift here would make audit reports lie.
	signals := buildSignalsMap(&p, logger)
	signalCount, err := insertComplianceSignals(ctx, tx, deviceID, signals, row.ReceivedAt)
	if err != nil {
		return err
	}

	// Evaluate T1 + T2 rules against the signals and store one row per rule.
	// Same transaction as the rest of the row's data — a device is never in a
	// state where its signals exist but its verdict doesn't (or vice versa).
	evalCount := 0
	if len(allRules) > 0 {
		evaluations := evaluator.Evaluate(allRules, signals, p.Device.Arch)
		evalRecords := make([]eval, 0, len(evaluations))
		for _, e := range evaluations {
			var obs any
			if e.ObservedValue != nil {
				obs = *e.ObservedValue
			}
			evalRecords = append(evalRecords, eval{
				ruleID:           e.RuleID,
				status:           e.Status,
				observedValue:    obs,
				severity:         e.Severity,
				benchmarkVersion: e.BenchmarkVersion,
			})
		}
		var werr error
		evalCount, werr = insertEvaluations(ctx, tx, deviceID, evalRecords, row.ReceivedAt)
		if werr != nil {
			return werr
		}

		// PAT-1549: application of a remediation artefact is observed, never
		// asked. A rule that now evaluates to 'pass' for a device that still
		// carries an issued (not-yet-superseded) artefact for that exact rule
		// is the only signal that ever flips an artefact to 'applied' — same
		// transaction as the evaluations that prove it, so an artefact can
		// never read 'applied' without a corresponding passing evaluation on
		// record. See internal/extractor/upsert.go markArtefactsApplied.
		if appliedCount, aerr := markArtefactsApplied(ctx, tx, deviceID, evalRecords, row.ReceivedAt); aerr != nil {
			return aerr
		} else if appliedCount > 0 && logger != nil {
			logger.Info("remediation artefacts marked applied", "device_id", deviceID, "count", appliedCount)
		}

		lifecycleCount, cisNotifications, lifecycleErr := recordCISFindingObservations(
			ctx, tx, row.TenantID, deviceID, allRules, evalRecords,
			agentHealthCollectedAt, row.ID, row.ReceivedAt,
		)
		if lifecycleErr != nil {
			return lifecycleErr
		}
		pendingNotifications = append(pendingNotifications, cisNotifications...)
		if lifecycleCount > 0 && logger != nil {
			logger.Info("finding lifecycle events recorded", "device_id", deviceID, "kind", "cis", "count", lifecycleCount)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE raw_payloads
		SET extracted_at = now(),
		    extraction_error = NULL
		WHERE id = $1 AND received_at = $2
	`, row.ID, row.ReceivedAt); err != nil {
		return fmt.Errorf("mark extracted: %w", err)
	}

	if err := softwaregov.QueueDeviceCheckTx(ctx, tx, deviceID, appsAbsenceComplete,
		findinglifecycle.EvidenceTimeAuthoritative(agentHealthCollectedAt, row.ReceivedAt)); err != nil {
		return fmt.Errorf("queue unapproved device check: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// PAT-2393: no policy row changed, so no trigger tells the
	// Unapproved-present summary that other devices now resolve differently.
	// After the commit and in its own statement, so the extraction holds no
	// device lock while it waits on the tenant's summary state row. A failure
	// leaves the summary stale until the next policy change; say so loudly.
	if declaredEligibilityChanged {
		if err := softwaregov.MarkPolicyResolutionChanged(ctx, w.Pool, row.TenantID); err != nil {
			logger.Error("declared approval eligibility changed but the unapproved summary was not invalidated", "tenant_id", row.TenantID, "err", err)
		} else {
			softwaregov.WakeRunner()
		}
	}

	// PAT-1888: raise finding, stale-evidence and verification notifications for
	// the transitions this extraction committed.
	//
	// After the commit, deliberately. The lifecycle rows are already durable, so
	// nothing here can change what the finding says: the worst case is a
	// notification that is not enqueued, which is logged and leaves the finding
	// intact. Enqueuing before the commit would allow the opposite, which is a
	// notification about a finding that was rolled back.
	raiseFindingNotifications(w.Pool, pendingNotifications, logger)

	// PAT-2009: the customer's unapproved software alert for a device newly
	// observed with a product the tenant marked Unapproved. After the commit,
	// like the notifications above, and only for a report whose evidence time
	// is authoritative: a replayed or back-dated report must not announce
	// presence as new. It only ever enqueues (a ledger row, webhook
	// deliveries); a failure is logged and never fails this extraction.
	// PAT-2097: the same hook then applies the alert lifecycle to the
	// device (resolve on policy or authoritative absence, re-open).
	if findinglifecycle.EvidenceTimeAuthoritative(agentHealthCollectedAt, row.ReceivedAt) {
		raiseUnapprovedObservations(ctx, w.Pool, row.TenantID, deviceID, appsAbsenceComplete, logger)
	}

	// Fire score.changed webhook after a successful extraction that wrote evaluations.
	// Best-effort: errors are logged inside Fire, never propagated to the extractor loop.
	if evalCount > 0 {
		tenantID := row.TenantID
		pool := w.Pool
		go func(dID string) {
			data := fetchScoreData(context.Background(), pool, tenantID, dID)
			webhook.Fire(pool, tenantID, webhook.EventScoreChanged, data, "")
		}(deviceID)
	}

	logger.Debug("row processed",
		"device_id", deviceID,
		"apps_upserted", appCount,
		"software_observations", softwareObservationCount,
		"patches_upserted", patchCount,
		"certs_upserted", certCount,
		"hw_health_rows", hwHealthCount,
		"local_admin_accounts_upserted", localAdminCount,
		"browser_exts_upserted", extCount,
		"agent_health_rows", agentHealthCount,
		"agent_health_dropped", agentHealthDropped,
		"applied_config_profiles", appliedConfigProfileCount,
		"signals_inserted", signalCount,
		"evaluations_inserted", evalCount,
	)
	return nil
}

// recordProcessError updates the extractor's row-processed counters for one
// failed row. attempts is claimedRow.Attempts, the post-increment attempt
// count already bumped by claimBatch's UPDATE before processRow ran. Split
// out from the Run loop so the maxAttempts boundary (the exact attempt that
// tips a row into dead-letter) is unit-testable without a live Postgres pool
// (PAT-1377).
//
// claimBatch only ever claims rows WHERE extraction_attempts < maxAttempts,
// so a row's attempts count can never exceed maxAttempts via this path: the
// only way to observe attempts == maxAttempts here is on the single failed
// attempt that permanently exhausts retries. "dead_letter" is incremented in
// addition to, not instead of, "error": both are true of that one event.
func recordProcessError(attempts int32) {
	metrics.ExtractorRowsProcessed.WithLabelValues("error").Inc()
	if attempts >= maxAttempts {
		metrics.ExtractorRowsProcessed.WithLabelValues("dead_letter").Inc()
	}
}

// markFailed records the error on the row in its own transaction. The claim
// transaction has already bumped extraction_attempts, so we just stamp the
// message — it's diagnostic only, not used for retry logic.
func (w *Worker) markFailed(ctx context.Context, row claimedRow, processErr error) error {
	// Truncate the message to keep one rogue error from bloating the row.
	msg := processErr.Error()
	if len(msg) > 2000 {
		msg = msg[:2000] + "…"
	}

	if errors.Is(processErr, context.Canceled) {
		// Don't stamp shutdown-induced cancellations as a row error.
		return nil
	}

	_, err := w.Pool.Exec(ctx, `
		UPDATE raw_payloads
		SET extraction_error = $1
		WHERE id = $2 AND received_at = $3
	`, msg, row.ID, row.ReceivedAt)
	return err
}

func (w *Worker) runHealthSignalsRecompute(ctx context.Context, logger *slog.Logger) {
	runID, err := automations.StartRun(ctx, w.Pool, "health_signals_recompute")
	if err != nil {
		logger.Warn("health signals recompute: could not start run", "err", err)
		return
	}
	recomputeErr := healthsignals.Recompute(ctx, w.Pool)
	status, errMsg := "success", ""
	if recomputeErr != nil {
		status, errMsg = "failed", recomputeErr.Error()
		logger.Warn("health signals recompute failed", "err", recomputeErr)
	} else {
		logger.Info("health signals recompute completed")
	}
	if finErr := automations.FinishRun(ctx, w.Pool, runID, status, "", errMsg); finErr != nil {
		logger.Warn("health signals recompute: could not finish run", "err", finErr)
	}
}

// isPlatformEnabled returns the per-tenant master-switch state for the given
// platform. A missing tenant row is treated as enabled=false (safe default —
// caller skips evaluation rather than evaluating blindly on a phantom tenant).
func isPlatformEnabled(ctx context.Context, pool *pgxpool.Pool, tenantID, platform string) (bool, error) {
	// Map the platform to a fixed column literal rather than concatenating the
	// caller-supplied value into SQL. Defence in depth against identifier
	// injection even though callers currently pass validated values.
	var col string
	switch platform {
	case "macos":
		col = "macos_enabled"
	case "windows":
		col = "windows_enabled"
	default:
		return false, fmt.Errorf("platform switch check: unknown platform %q", platform)
	}
	var enabled bool
	err := pool.QueryRow(ctx,
		"SELECT "+col+" FROM tenants WHERE id = $1::uuid",
		tenantID,
	).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("platform switch check: %w", err)
	}
	return enabled, nil
}

// fetchScoreData computes the aggregate compliance score for a device from its
// most recent evaluation batch. Returns a ScoreChangedData for the webhook payload.
// On error (e.g. no evaluations yet) returns a zero-value struct — the webhook
// is still fired; the recipient receives zeroed counts.
func fetchScoreData(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) webhook.ScoreChangedData {
	var hostname string
	_ = pool.QueryRow(ctx, `SELECT COALESCE(hostname, '') FROM devices WHERE id = $1::uuid`, deviceID).Scan(&hostname)

	var pass, fail, total int
	_ = pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pass')             AS pass_count,
			COUNT(*) FILTER (WHERE status = 'fail')             AS fail_count,
			COUNT(*) FILTER (WHERE status IN ('pass','fail'))   AS total_count
		FROM compliance_evaluations
		WHERE device_id = $1::uuid
		  AND evaluated_at = (
		      SELECT MAX(evaluated_at)
		      FROM compliance_evaluations
		      WHERE device_id = $1::uuid
		  )
	`, deviceID).Scan(&pass, &fail, &total)

	var pct float64
	if total > 0 {
		pct = float64(pass) / float64(total) * 100
	}
	return webhook.ScoreChangedData{
		DeviceID:      deviceID,
		Hostname:      hostname,
		PassCount:     pass,
		FailCount:     fail,
		TotalCount:    total,
		CompliancePct: pct,
	}
}

// sleep is context-aware. Returns false if ctx is cancelled mid-sleep.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
