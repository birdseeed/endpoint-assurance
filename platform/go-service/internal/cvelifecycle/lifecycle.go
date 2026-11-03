// Package cvelifecycle reduces current CVE matches into the neutral finding
// lifecycle (PAT-1878). It was lifted out of cmd/patched-cve-sync unchanged
// so the event-driven matcher in the extractor (PAT-2024) records lifecycle
// transitions through exactly the same code as the nightly run: one reducer,
// one advisory-lock discipline, one closure-requires-authority rule.
package cvelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/findinglifecycle"
	"patched.im/api/internal/notifications"
)

const (
	identityBatchSize  = 500
	maxReconcileErrors = 50
)

type affectedDevice struct {
	DeviceID        string  `json:"device_id"`
	RequiredScope   string  `json:"required_scope"`
	AppName         string  `json:"app_name,omitempty"`
	AppVersion      string  `json:"app_version,omitempty"`
	MatchConfidence string  `json:"match_confidence,omitempty"`
	FixedVersion    *string `json:"fixed_version,omitempty"`
}

type currentIdentity struct {
	TenantID        string
	CVEID           string
	ObservedAt      time.Time
	ReceivedAt      time.Time
	AffectedDevices []affectedDevice
}

// Identity is one tenant-aggregate CVE finding (PAT-1829 shape).
type Identity struct{ TenantID, CVEID string }

// OSPseudoAppNames are the device_apps / finding app names the NVD CPE engine
// emits for the operating system itself (matching the app_cpe_mappings
// "macOS"/"Windows" rows). Their required verification scope is "os".
var OSPseudoAppNames = []string{"macOS", "Windows"}

// ReconcileIdentities reduces only the named tenant/CVE identities, each in
// its own short transaction, exactly as ReconcileAll does for every identity.
// The event-driven matcher calls it for the identities a targeted re-match
// touched, so a finding written between nightly runs still gets its
// first_observed (or recurred) lifecycle event and notification, and a
// removed one still goes through the authority-gated closure path.
// Duplicates are collapsed; order is deterministic.
func ReconcileIdentities(ctx context.Context, pool *pgxpool.Pool, identities []Identity, logger *slog.Logger) error {
	seen := make(map[Identity]bool, len(identities))
	unique := make([]Identity, 0, len(identities))
	for _, identity := range identities {
		if identity.TenantID == "" || identity.CVEID == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		unique = append(unique, identity)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].TenantID != unique[j].TenantID {
			return unique[i].TenantID < unique[j].TenantID
		}
		return unique[i].CVEID < unique[j].CVEID
	})
	var errs []error
	errorCount := 0
	for _, identity := range unique {
		if _, err := reconcileIdentity(ctx, pool, identity); err != nil {
			errorCount++
			if len(errs) < maxReconcileErrors {
				errs = append(errs, fmt.Errorf("tenant %s CVE %s: %w", identity.TenantID, identity.CVEID, err))
			}
		}
	}
	if logger != nil && len(unique) > 0 {
		logger.Info("targeted CVE finding lifecycle reconciled", "identities", len(unique), "errors", errorCount)
	}
	if suppressed := errorCount - len(errs); suppressed > 0 {
		errs = append(errs, fmt.Errorf("%d additional CVE lifecycle errors suppressed", suppressed))
	}
	return errors.Join(errs...)
}

// reconcileCVEFindingLifecycles runs only after the matcher has refreshed and
// pruned device_cve_findings. Identities are snapshotted in bounded pages, then
// each identity is re-read and reduced in its own short transaction. No
// advisory lock is held while another tenant/CVE identity is processed.
func ReconcileAll(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	afterTenant, afterCVE := "", ""
	currentCount, closureCount, errorCount := 0, 0, 0
	reconcileErrors := make([]error, 0, maxReconcileErrors+1)
	for {
		identities, err := loadCVELifecycleIdentityBatch(ctx, pool, afterTenant, afterCVE, identityBatchSize)
		if err != nil {
			errorCount++
			if len(reconcileErrors) < maxReconcileErrors {
				reconcileErrors = append(reconcileErrors, err)
			}
			break
		}
		if len(identities) == 0 {
			break
		}
		for _, identity := range identities {
			current, err := reconcileIdentity(ctx, pool, identity)
			if err != nil {
				errorCount++
				if len(reconcileErrors) < maxReconcileErrors {
					reconcileErrors = append(reconcileErrors, fmt.Errorf("tenant %s CVE %s: %w", identity.TenantID, identity.CVEID, err))
				}
				continue
			}
			if current {
				currentCount++
			} else {
				closureCount++
			}
		}
		last := identities[len(identities)-1]
		afterTenant, afterCVE = last.TenantID, last.CVEID
		if len(identities) < identityBatchSize {
			break
		}
	}
	if logger != nil {
		logger.Info("CVE finding lifecycle reconciled", "currently_observed", currentCount,
			"closure_candidates", closureCount, "errors", errorCount)
	}
	if suppressed := errorCount - len(reconcileErrors); suppressed > 0 {
		reconcileErrors = append(reconcileErrors, fmt.Errorf("%d additional CVE lifecycle errors suppressed", suppressed))
	}
	return errors.Join(reconcileErrors...)
}

func loadCVELifecycleIdentityBatch(ctx context.Context, pool *pgxpool.Pool, afterTenant, afterCVE string, limit int) ([]Identity, error) {
	rows, err := pool.Query(ctx, `
		WITH identities AS (
			SELECT d.tenant_id, f.cve_id
			FROM device_cve_findings f
			JOIN devices d ON d.id = f.device_id
			GROUP BY d.tenant_id, f.cve_id
			UNION
			SELECT tenant_id, finding_key
			FROM finding_lifecycle_events
			WHERE finding_kind = 'cve'
			GROUP BY tenant_id, finding_key
		)
		SELECT tenant_id::text, cve_id
		FROM identities
		WHERE $1::text = '' OR (tenant_id::text, cve_id) > ($1::text, $2::text)
		ORDER BY tenant_id::text, cve_id
		LIMIT $3
	`, afterTenant, afterCVE, limit)
	if err != nil {
		return nil, fmt.Errorf("load CVE lifecycle identity batch: %w", err)
	}
	defer rows.Close()
	identities := make([]Identity, 0, limit)
	for rows.Next() {
		var identity Identity
		if err := rows.Scan(&identity.TenantID, &identity.CVEID); err != nil {
			return nil, fmt.Errorf("scan CVE lifecycle identity: %w", err)
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate CVE lifecycle identities: %w", err)
	}
	return identities, nil
}

func reconcileIdentity(ctx context.Context, pool *pgxpool.Pool, identity Identity) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin CVE lifecycle identity transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// PAT-1888: the transition this reconciliation writes, held until the
	// transaction commits. Notifications are raised from committed lifecycle
	// rows only, and never from inside the transaction that writes them.
	var pending *notifications.Event

	current, err := loadCurrentCVEIdentity(ctx, tx, identity)
	if err != nil {
		return false, err
	}
	if len(current.AffectedDevices) > 0 {
		eventType, err := findinglifecycle.RecordObservation(ctx, tx, findinglifecycle.Observation{
			Identity: findinglifecycle.Identity{
				TenantID: identity.TenantID, Kind: findinglifecycle.KindCVE, FindingKey: identity.CVEID,
			},
			Outcome: findinglifecycle.OutcomeFailing, ObservedAt: current.ObservedAt, ReceivedAt: current.ReceivedAt,
			Authoritative: !current.ObservedAt.IsZero(),
			Reason:        "CVE match from endpoint software inventory",
			Evidence:      map[string]any{"affected_devices": current.AffectedDevices},
		})
		if err != nil {
			return true, fmt.Errorf("record current CVE lifecycle %s: %w", identity.CVEID, err)
		}
		pending = cveLifecycleNotification(identity, eventType, current.ObservedAt,
			map[string]any{"affected_device_count": len(current.AffectedDevices)})
		if err := tx.Commit(ctx); err != nil {
			return true, fmt.Errorf("commit current CVE lifecycle %s: %w", identity.CVEID, err)
		}
		raiseCVENotification(ctx, pool, identity, pending)
		return true, nil
	}

	pending, err = reconcileAbsentCVEIdentity(ctx, tx, identity)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit absent CVE lifecycle %s: %w", identity.CVEID, err)
	}
	raiseCVENotification(ctx, pool, identity, pending)
	return false, nil
}

// cveLifecycleNotification builds the notification event for one CVE lifecycle
// transition, or nil when the transition is not notifiable.
//
// It reads nothing. Everything it needs is already in hand, which is what keeps
// it safe to call while the lifecycle transaction is still open: a failed query
// here would abort that transaction in Postgres and lose the lifecycle write
// this event is reporting on. Severity is graded later, after the commit, by
// Severity.
func cveLifecycleNotification(identity Identity, lifecycleEventType string,
	observedAt time.Time, data map[string]any) *notifications.Event {
	kind, ok := notifications.EventForLifecycle(lifecycleEventType)
	if !ok {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if data == nil {
		data = map[string]any{}
	}
	data["finding_kind"] = findinglifecycle.KindCVE
	data["finding_key"] = identity.CVEID
	data["cve_id"] = identity.CVEID
	data["lifecycle_event"] = lifecycleEventType
	data["observed_at"] = observedAt.UTC()

	return &notifications.Event{
		TenantID:  identity.TenantID,
		Type:      kind,
		Subject:   notifications.Subject(findinglifecycle.KindCVE, nil, identity.CVEID, observedAt),
		Timestamp: observedAt.UTC(),
		Data:      data,
	}
}

// Severity grades a CVE event from the tenant's retained findings, returning
// "" when it cannot.
//
// Three outcomes, kept distinct on purpose:
//
//   - a grade was read, so the event is filtered against channel thresholds;
//   - no findings remain, which is legitimate on the closure path because the
//     matcher has already pruned them, so the event is ungraded and silent;
//   - the query failed, which is a fault rather than a clean miss. The event is
//     still delivered ungraded, because a lookup failure must never suppress a
//     real transition, but it is logged rather than passed off as an absence.
func Severity(ctx context.Context, pool *pgxpool.Pool, identity Identity, event string) string {
	// The distinct stored grades, ranked in Go rather than by the database.
	// device_cve_findings.severity is TEXT holding CRITICAL/HIGH/MEDIUM/LOW/NONE
	// (migration 0025), and text ordering is not severity ordering: a SQL
	// max() over those values sorts alphabetically, so a CVE with CRITICAL and
	// LOW findings would grade as LOW and slip past a high threshold. Ranking
	// belongs to notifications.HighestSeverity, which shares its table with the
	// threshold filter.
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT btrim(f.severity)
		FROM device_cve_findings f
		JOIN devices d ON d.id = f.device_id
		WHERE d.tenant_id = $1::uuid AND f.cve_id = $2 AND f.severity IS NOT NULL
	`, identity.TenantID, identity.CVEID)
	if err != nil {
		slog.Warn("CVE lifecycle: severity lookup failed, delivering the notification ungraded",
			"tenant_id", identity.TenantID, "cve_id", identity.CVEID, "event", event, "err", err)
		return ""
	}
	defer rows.Close()

	var candidates []string
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			slog.Warn("CVE lifecycle: severity row unreadable, delivering the notification ungraded",
				"tenant_id", identity.TenantID, "cve_id", identity.CVEID, "event", event, "err", err)
			return ""
		}
		candidates = append(candidates, stored)
	}

	switch err := rows.Err(); {
	case err == nil, errors.Is(err, pgx.ErrNoRows):
		// No retained findings is legitimate on the closure path, because the
		// matcher has already pruned them. The event goes out ungraded.
	default:
		slog.Warn("CVE lifecycle: severity lookup failed, delivering the notification ungraded",
			"tenant_id", identity.TenantID, "cve_id", identity.CVEID, "event", event, "err", err)
		return ""
	}

	return notifications.HighestSeverity(candidates)
}

// raiseCVENotification grades and enqueues a committed transition's event.
//
// It runs after the commit and on the pool, never on the lifecycle transaction.
// Failures are logged and dropped: the lifecycle row is already durable, so
// nothing here can change what the finding says.
func raiseCVENotification(ctx context.Context, pool *pgxpool.Pool, identity Identity, ev *notifications.Event) {
	if ev == nil {
		return
	}
	if severity := Severity(ctx, pool, identity, string(ev.Type)); severity != "" {
		ev.Severity = severity
		ev.Data["severity"] = severity
	}
	notifications.NotifyAsync(pool, *ev)
}

func loadCurrentCVEIdentity(ctx context.Context, tx pgx.Tx, identity Identity) (currentIdentity, error) {
	rows, err := tx.Query(ctx, `
		WITH affected AS (
			SELECT d.tenant_id, f.cve_id, f.device_id, f.app_name,
			       f.app_version, f.match_confidence, f.fixed_version,
			       CASE
			         WHEN f.app_name = ANY($1::text[]) THEN 'os'
			         -- PAT-2023: a Homebrew finding is closed only by a
			         -- complete or not_present Homebrew report, never by the
			         -- application snapshot.
			         WHEN f.package_source IS NOT NULL THEN 'homebrew'
			         WHEN lower(d.os) LIKE 'windows%'
			          AND bool_and(COALESCE(da.identifier_kind, '') = 'winget')
			           THEN 'windows_winget'
			         WHEN lower(d.os) LIKE 'windows%' THEN 'unsupported'
			         ELSE 'all_software'
			       END AS required_scope
			FROM device_cve_findings f
			JOIN devices d ON d.id = f.device_id
			LEFT JOIN device_apps da
			  ON da.device_id = f.device_id AND lower(da.name) = lower(f.app_name)
			WHERE d.tenant_id = $2::uuid AND f.cve_id = $3
			GROUP BY d.tenant_id, f.cve_id, f.device_id, f.app_name,
			         f.app_version, f.match_confidence, f.fixed_version, d.os,
			         f.package_source
		)
		SELECT a.device_id::text, latest.collected_at, latest.received_at,
		       a.app_name, a.app_version, a.match_confidence, a.fixed_version, a.required_scope
		FROM affected a
		LEFT JOIN LATERAL (
			SELECT collected_at, received_at
			FROM software_inventory_runs sir
			WHERE sir.tenant_id = a.tenant_id AND sir.device_id = a.device_id
			  AND sir.collected_at IS NOT NULL
			  AND sir.collected_at <= sir.received_at + INTERVAL '5 minutes'
			  AND sir.collected_at >= sir.received_at - INTERVAL '24 hours'
			ORDER BY sir.collected_at DESC, sir.id DESC
			LIMIT 1
		) latest ON true
		ORDER BY a.device_id, a.app_name
	`, OSPseudoAppNames, identity.TenantID, identity.CVEID)
	if err != nil {
		return currentIdentity{}, fmt.Errorf("load current CVE lifecycle %s: %w", identity.CVEID, err)
	}
	defer rows.Close()
	current := currentIdentity{TenantID: identity.TenantID, CVEID: identity.CVEID}
	for rows.Next() {
		var deviceID, appName, appVersion, matchConfidence, requiredScope string
		var fixedVersion *string
		var observedAt, receivedAt *time.Time
		if err := rows.Scan(&deviceID, &observedAt, &receivedAt, &appName,
			&appVersion, &matchConfidence, &fixedVersion, &requiredScope); err != nil {
			return currentIdentity{}, fmt.Errorf("scan current CVE lifecycle observation: %w", err)
		}
		if observedAt != nil && observedAt.After(current.ObservedAt) {
			current.ObservedAt, current.ReceivedAt = *observedAt, *receivedAt
		}
		current.AffectedDevices = append(current.AffectedDevices, affectedDevice{
			DeviceID: deviceID, RequiredScope: requiredScope, AppName: appName,
			AppVersion: appVersion, MatchConfidence: matchConfidence, FixedVersion: fixedVersion,
		})
	}
	if err := rows.Err(); err != nil {
		return currentIdentity{}, fmt.Errorf("iterate current CVE lifecycle observations: %w", err)
	}
	return current, nil
}

func reconcileAbsentCVEIdentity(ctx context.Context, tx pgx.Tx, identity Identity) (*notifications.Event, error) {
	var evidenceJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT evidence
		FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'cve' AND finding_key = $2
		  AND event_type IN ('first_observed','currently_observed','still_failing','recurred')
		ORDER BY id DESC LIMIT 1
	`, identity.TenantID, identity.CVEID).Scan(&evidenceJSON)
	var evidence struct {
		AffectedDevices []affectedDevice `json:"affected_devices"`
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load failing evidence for CVE lifecycle %s: %w", identity.CVEID, err)
	}
	if err == nil {
		if unmarshalErr := json.Unmarshal(evidenceJSON, &evidence); unmarshalErr != nil {
			return nil, fmt.Errorf("decode failing evidence for CVE lifecycle %s: %w", identity.CVEID, unmarshalErr)
		}
	}
	if len(evidence.AffectedDevices) == 0 {
		// No retained failing observation means there is no affected-device
		// scope. This includes migrated action-only history. It stays
		// pending/unknown rather than being closed from absence.
		now := time.Now().UTC()
		eventType, recordErr := findinglifecycle.RecordObservation(ctx, tx, findinglifecycle.Observation{
			Identity: findinglifecycle.Identity{TenantID: identity.TenantID, Kind: findinglifecycle.KindCVE, FindingKey: identity.CVEID},
			Outcome:  findinglifecycle.OutcomeUnknown, ObservedAt: now, ReceivedAt: now,
			Authoritative: false, Reason: "CVE verification scope unavailable",
		})
		if recordErr != nil {
			return nil, fmt.Errorf("record unknown CVE lifecycle %s: %w", identity.CVEID, recordErr)
		}
		return cveLifecycleNotification(identity, eventType, now,
			map[string]any{"reason": "CVE verification scope unavailable"}), nil
	}

	// PAT-2107: a finding that disappeared while a device that backed it
	// still reports the same software at the same version was not fixed on
	// that device: the matcher's verdict changed (a matcher correction, a CVE
	// feed revision or a mapping change). It is withdrawn, never verified
	// fixed, and raises no notification. Freshness is not required, because
	// the matcher only ever reads this same inventory: if it is unchanged,
	// nothing on the device can have caused the disappearance.
	unchanged, err := unchangedAffectedDevices(ctx, tx, identity, evidence.AffectedDevices)
	if err != nil {
		return nil, err
	}
	if len(unchanged) > 0 {
		if _, err := findinglifecycle.RecordWithdrawal(ctx, tx, findinglifecycle.Withdrawal{
			Identity: findinglifecycle.Identity{TenantID: identity.TenantID, Kind: findinglifecycle.KindCVE, FindingKey: identity.CVEID},
			Reason:   WithdrawnReason,
			Evidence: map[string]any{
				"affected_devices":  evidence.AffectedDevices,
				"unchanged_devices": unchanged,
			},
		}); err != nil {
			return nil, fmt.Errorf("record CVE withdrawal %s: %w", identity.CVEID, err)
		}
		// Deliberately no notification, whether or not a row was written:
		// a withdrawal is not a customer-facing transition, and an identity
		// that was already withdrawn or closed stays as it is.
		return nil, nil
	}

	deviceIDs := make([]string, 0, len(evidence.AffectedDevices))
	requiredScopes := make([]string, 0, len(evidence.AffectedDevices))
	for _, device := range evidence.AffectedDevices {
		deviceIDs = append(deviceIDs, device.DeviceID)
		requiredScopes = append(requiredScopes, device.RequiredScope)
	}
	var authoritative bool
	var verifiedAt, verifiedReceivedAt *time.Time
	err = tx.QueryRow(ctx, `
		WITH required AS (
			SELECT device_id, required_scope
			FROM unnest($2::text[], $3::text[]) AS input(device_id, required_scope)
		), newest_runs AS (
			SELECT required.required_scope, latest.collected_at, latest.received_at,
			       latest.authoritative_scopes
			FROM required
			LEFT JOIN LATERAL (
				SELECT collected_at, received_at, authoritative_scopes
				FROM software_inventory_runs sir
				WHERE sir.tenant_id = $1::uuid
				  AND sir.device_id = required.device_id::uuid
				ORDER BY sir.received_at DESC, sir.id DESC
				LIMIT 1
			) latest ON true
		)
		SELECT COALESCE(bool_and(
		           collected_at IS NOT NULL
		       AND received_at IS NOT NULL
		       AND collected_at <= received_at + INTERVAL '5 minutes'
		       AND collected_at >= received_at - INTERVAL '24 hours'
		       AND (
		             required_scope = 'os'
		          OR (required_scope <> 'unsupported' AND COALESCE(required_scope = ANY(authoritative_scopes), false))
		       )
		       ), false),
		       min(collected_at), min(received_at)
		FROM newest_runs
	`, identity.TenantID, deviceIDs, requiredScopes).Scan(&authoritative, &verifiedAt, &verifiedReceivedAt)
	if err != nil {
		return nil, fmt.Errorf("load authoritative inventories for CVE lifecycle %s: %w", identity.CVEID, err)
	}
	if verifiedAt == nil || verifiedReceivedAt == nil {
		authoritative = false
	}
	outcome := findinglifecycle.OutcomePassing
	verifiedAtValue, verifiedReceivedAtValue := time.Time{}, time.Time{}
	if authoritative {
		verifiedAtValue, verifiedReceivedAtValue = *verifiedAt, *verifiedReceivedAt
	}
	if !authoritative {
		outcome = findinglifecycle.OutcomeUnknown
		verifiedAtValue = time.Now().UTC()
		verifiedReceivedAtValue = verifiedAtValue
	}
	eventType, err := findinglifecycle.RecordObservation(ctx, tx, findinglifecycle.Observation{
		Identity: findinglifecycle.Identity{TenantID: identity.TenantID, Kind: findinglifecycle.KindCVE, FindingKey: identity.CVEID},
		Outcome:  outcome, ObservedAt: verifiedAtValue, ReceivedAt: verifiedReceivedAtValue,
		Authoritative: authoritative,
		Reason:        "CVE absence checked against fresh authoritative endpoint inventory",
		Evidence:      map[string]any{"affected_devices": evidence.AffectedDevices},
	})
	if err != nil {
		return nil, fmt.Errorf("record CVE closure lifecycle %s: %w", identity.CVEID, err)
	}
	return cveLifecycleNotification(identity, eventType, verifiedAtValue,
		map[string]any{"affected_device_count": len(evidence.AffectedDevices)}), nil
}

// WithdrawnReason is the reason recorded on every CVE withdrawn event.
const WithdrawnReason = "withdrawn: matcher correction, not a fix. The CVE is no longer matched " +
	"while the device still reports the same software at the same version"

// unchangedAffectedDevices returns the ids of the affected devices, taken from
// the last failing evidence, whose current inventory still reports the
// software that backed the finding at the same version: the same inputs the
// matcher read when it raised the finding.
//
//   - Applications (and OS pseudo-apps) are compared with device_apps by
//     case-insensitive name and exact version, exactly the rows the matchers
//     load.
//   - An OS finding also counts as unchanged when its version is still the
//     device's os_build or os_version, which is what the vendor OS matcher
//     reports.
//   - A Homebrew finding is compared with the device's current Homebrew list
//     (homebrew_current_entries under the device's authority, joined to the
//     reported version), the same rows the Homebrew matcher loads.
//
// A device that is gone, or evidence with no app name, never counts as
// unchanged, so the existing closure rules decide it.
func unchangedAffectedDevices(ctx context.Context, tx pgx.Tx, identity Identity, devices []affectedDevice) ([]string, error) {
	n := len(devices)
	ids, scopes, names, versions := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	brewKinds, brewNames := make([]string, 0, n), make([]string, 0, n)
	for _, d := range devices {
		if d.DeviceID == "" || d.AppName == "" {
			continue
		}
		kind, name := "", ""
		if d.RequiredScope == "homebrew" {
			k, nm, ok := ParseHomebrewAppName(d.AppName)
			if !ok {
				continue
			}
			kind, name = k, nm
		}
		ids, scopes = append(ids, d.DeviceID), append(scopes, d.RequiredScope)
		names, versions = append(names, d.AppName), append(versions, d.AppVersion)
		brewKinds, brewNames = append(brewKinds, kind), append(brewNames, name)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT a.device_id
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
		     AS a(device_id, required_scope, app_name, app_version, brew_kind, brew_name)
		JOIN devices d ON d.id::text = a.device_id AND d.tenant_id = $1::uuid
		WHERE CASE
		  WHEN a.required_scope = 'homebrew' THEN EXISTS (
			SELECT 1
			FROM homebrew_current_entries c
			JOIN homebrew_device_state s
			  ON s.device_id = c.device_id AND s.tenant_id = c.tenant_id
			JOIN homebrew_observation_details h
			  ON h.inventory_run_id = c.inventory_run_id AND h.device_id = c.device_id
			 AND h.package_kind = c.package_kind AND h.prefix = c.prefix AND h.name = c.name
			 AND (h.package_kind <> 'formula' OR h.version = c.version_key)
			 AND h.tenant_id = c.tenant_id
			WHERE c.device_id = d.id AND c.tenant_id = d.tenant_id
			  AND c.package_kind = a.brew_kind AND c.name = a.brew_name
			  AND (s.authority_at IS NULL OR c.observed_at >= s.authority_at)
			  AND COALESCE(h.version, '') = a.app_version)
		  ELSE EXISTS (
			SELECT 1 FROM device_apps da
			WHERE da.device_id = d.id AND lower(da.name) = lower(a.app_name)
			  AND COALESCE(da.version, '') = a.app_version)
		    OR (a.required_scope = 'os' AND a.app_version <> ''
		        AND a.app_version IN (COALESCE(d.os_build, ''), COALESCE(d.os_version, '')))
		END
		ORDER BY a.device_id
	`, identity.TenantID, ids, scopes, names, versions, brewKinds, brewNames)
	if err != nil {
		return nil, fmt.Errorf("load unchanged devices for CVE lifecycle %s: %w", identity.CVEID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan unchanged device for CVE lifecycle %s: %w", identity.CVEID, err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unchanged devices for CVE lifecycle %s: %w", identity.CVEID, err)
	}
	return out, nil
}

// ParseHomebrewAppName splits a Homebrew finding's app_name ("<name> (Homebrew
// formula)" or "<name> (Homebrew cask)") into its package kind and name. It
// mirrors cvematch.ParseHomebrewDisplayName, which this package cannot import
// (cvematch's tests import cvelifecycle); TestHomebrewAppNameParsersAgree in
// cvematch keeps the two from drifting.
func ParseHomebrewAppName(s string) (kind, name string, ok bool) {
	switch {
	case strings.HasSuffix(s, " (Homebrew formula)"):
		kind, name = "formula", strings.TrimSuffix(s, " (Homebrew formula)")
	case strings.HasSuffix(s, " (Homebrew cask)"):
		kind, name = "cask", strings.TrimSuffix(s, " (Homebrew cask)")
	default:
		return "", "", false
	}
	return kind, name, name != ""
}
