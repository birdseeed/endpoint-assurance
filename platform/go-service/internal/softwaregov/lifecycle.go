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

	"patched.im/api/internal/apppolicy"
	"patched.im/api/internal/extpresence"
)

// The unapproved software alert lifecycle (PAT-2097, migration 0184).
//
// One tracked alert is one software_unapproved_alerted_devices row: one
// (unapproved episode, device) pair, whichever outbound alert first reported
// it. Its status moves open -> acknowledged -> resolved, and a resolved alert
// re-opens when the product is observed on the device again while still
// Unapproved. Every change appends a row to
// software_unapproved_alert_transitions.
//
// Nothing resolves on a timer. An alert resolves only on evidence:
//
//   - policy: the product's policy row moved to approved, mandatory,
//     ignored/unmanaged, or was deleted. The policy write paths call
//     ResolvePolicyAlertsTx inside their own transaction, so the alert and
//     the policy change commit together. ReconcileDevice applies the same
//     rule at ingest as a safety net for a path that does not.
//   - not_observed: an authoritative report proved the product gone from the
//     device. For an application that is a report whose
//     collection_status.apps was "complete" and whose prune ran (PAT-2063);
//     a partial, unavailable, inconsistent, legacy or valve-held report never
//     resolves anything. A per-user install stays in device_apps while any
//     user scope still asserts it (PAT-2075), so a user missing from the
//     report keeps it present. For a browser extension it is the PAT-2055
//     extpresence rule: every matching row must have an authoritative
//     complete report strictly after its last_seen.
//
// A re-open sends no immediate email and no webhook. It is listed in the
// tenant's next daily unapproved software digest (reopen_digest_pending).
//
// All lifecycle writes for one tenant take the same transaction advisory
// lock as the alert raise paths (lockTenantAlerts). A policy writer takes the
// tenant policy lock first and this one second; nothing takes them in the
// other order.

// Alert statuses.
const (
	AlertOpen         = "open"
	AlertAcknowledged = "acknowledged"
	AlertResolved     = "resolved"
)

// Resolve reasons.
const (
	ReasonNotObserved   = "not_observed"
	ReasonApproved      = "approved"
	ReasonIgnored       = "ignored"
	ReasonPolicyRemoved = "policy_removed"
	// ReasonSuperseded: the alert no longer describes an active case, for
	// one of two reasons recorded in the transition detail's evidence:
	// "governed_by_other_policy" (the product is still installed but another
	// policy row, or none, now decides its state) or "superseded_episode" (a
	// newer unapproved episode of the same policy row replaced this one).
	ReasonSuperseded = "superseded"
)

// Transition actor kinds.
const (
	ActorPortalUser = "portal_user"
	ActorOperator   = "operator"
	ActorSystem     = "system"
)

// MaxAlertNoteLen caps an acknowledgement note, in characters.
const MaxAlertNoteLen = 1000

// Errors returned by AcknowledgeAlertTx.
var (
	ErrAlertNotFound = errors.New("softwaregov: alert not found")
	ErrAlertResolved = errors.New("softwaregov: alert is resolved")
)

// Actor is who made a lifecycle change. Email is set only for a portal user.
type Actor struct {
	Kind  string
	Email string
}

func (a Actor) actorArg() *string {
	if a.Kind != ActorPortalUser {
		return nil
	}
	e := strings.ToLower(strings.TrimSpace(a.Email))
	return &e
}

func (a Actor) valid() error {
	switch a.Kind {
	case ActorPortalUser:
		if strings.TrimSpace(a.Email) == "" {
			return errors.New("softwaregov: a portal user actor needs an email")
		}
	case ActorOperator, ActorSystem:
	default:
		return fmt.Errorf("softwaregov: unknown actor kind %q", a.Kind)
	}
	return nil
}

// ResolveReasonForPolicy maps a policy value (storage or portal vocabulary)
// to the reason an alert resolves with when its policy becomes that value.
// ok is false for 'unapproved', which resolves nothing. An empty value, or
// 'unreviewed', means the policy row is gone.
func ResolveReasonForPolicy(policy string) (reason string, ok bool) {
	switch policy {
	case "approved", "mandatory":
		return ReasonApproved, true
	case "ignored", "unmanaged":
		return ReasonIgnored, true
	case "", StateUnreviewed:
		return ReasonPolicyRemoved, true
	}
	return "", false
}

// ResolvePolicyAlertsTx resolves every open and acknowledged alert of the
// policy row (kind, policyID), across all its episodes, because the policy
// has become newPolicy. Call it inside the policy-write transaction, after
// the tenant policy lock. It returns the number of alerts resolved; a
// newPolicy of 'unapproved' resolves nothing.
func ResolvePolicyAlertsTx(ctx context.Context, tx pgx.Tx, tenantID, kind string, policyID int64, newPolicy string, actor Actor) (int, error) {
	reason, ok := ResolveReasonForPolicy(newPolicy)
	if !ok || policyID == 0 {
		return 0, nil
	}
	if err := actor.valid(); err != nil {
		return 0, err
	}
	if err := lockTenantAlerts(ctx, tx, tenantID); err != nil {
		return 0, fmt.Errorf("lock tenant alerts: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		WITH target AS (
			SELECT ad.id, ad.status
			FROM software_unapproved_alerted_devices ad
			JOIN software_unapproved_episodes e ON e.id = ad.episode_id
			WHERE ad.tenant_id = $1::uuid AND e.tenant_id = $1::uuid
			  AND e.policy_kind = $2 AND e.policy_id = $3
			  AND ad.status IN ('open', 'acknowledged')
			FOR UPDATE OF ad
		), upd AS (
			UPDATE software_unapproved_alerted_devices ad
			SET status = 'resolved', status_changed_at = now(), resolved_at = now(),
			    resolved_reason = $4, reopen_digest_pending = false
			FROM target
			WHERE ad.id = target.id
			RETURNING ad.id, ad.episode_id, ad.device_id, target.status AS from_status
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, actor, reason, detail)
		SELECT $1::uuid, id, episode_id, device_id, from_status, 'resolved', $5, $6, $4,
		       jsonb_build_object('evidence', 'policy_state', 'policy_kind', $2::text, 'policy_id', $3::bigint)
		FROM upd
	`, tenantID, kind, policyID, reason, actor.Kind, actor.actorArg())
	if err != nil {
		return 0, fmt.Errorf("resolve policy alerts: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// AcknowledgeAlertTx acknowledges one open alert of the tenant. An alert of
// another tenant, or no alert, is ErrAlertNotFound; a resolved alert is
// ErrAlertResolved. Acknowledging an acknowledged alert changes nothing and
// records nothing (changed false), so the call is idempotent.
func AcknowledgeAlertTx(ctx context.Context, tx pgx.Tx, tenantID string, id int64, actor Actor, note string) (changed bool, err error) {
	if actor.Kind == ActorSystem {
		return false, errors.New("softwaregov: the system does not acknowledge alerts")
	}
	if err := actor.valid(); err != nil {
		return false, err
	}
	note = strings.TrimSpace(note)
	if len([]rune(note)) > MaxAlertNoteLen {
		return false, fmt.Errorf("softwaregov: note longer than %d characters", MaxAlertNoteLen)
	}
	if err := lockTenantAlerts(ctx, tx, tenantID); err != nil {
		return false, fmt.Errorf("lock tenant alerts: %w", err)
	}
	var status string
	err = tx.QueryRow(ctx, `
		SELECT status FROM software_unapproved_alerted_devices
		WHERE id = $1 AND tenant_id = $2::uuid
		FOR UPDATE
	`, id, tenantID).Scan(&status)
	if isNoRows(err) {
		return false, ErrAlertNotFound
	}
	if err != nil {
		return false, fmt.Errorf("load alert: %w", err)
	}
	switch status {
	case AlertAcknowledged:
		return false, nil
	case AlertResolved:
		return false, ErrAlertResolved
	}
	var noteArg *string
	if note != "" {
		noteArg = &note
	}
	if _, err := tx.Exec(ctx, `
		WITH upd AS (
			UPDATE software_unapproved_alerted_devices
			SET status = 'acknowledged', status_changed_at = now(), acknowledged_at = now(),
			    acknowledged_by = $3, acknowledged_by_kind = $4, reopen_digest_pending = false
			WHERE id = $1 AND tenant_id = $2::uuid AND status = 'open'
			RETURNING id, episode_id, device_id
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, actor, note)
		SELECT $2::uuid, id, episode_id, device_id, 'open', 'acknowledged', $4, $3, $5
		FROM upd
	`, id, tenantID, actor.actorArg(), actor.Kind, noteArg); err != nil {
		return false, fmt.Errorf("acknowledge alert: %w", err)
	}
	return true, nil
}

// ReconcileResult reports what one ReconcileDevice call changed.
type ReconcileResult struct {
	Resolved []int64
	Reopened []int64
	Skipped  string
}

type lifecycleRow struct {
	id             int64
	episodeID      int64
	status         string
	resolvedReason string
	// resolvedEvidence is the detail.evidence of the transition that
	// resolved the row ("" when none), read in the same statement.
	resolvedEvidence string
	product          *Product
	policyKind       string
	policyID         int64
	latestForPol     bool
	// policy is the policy row's current value, "" when the row is gone,
	// read in the same statement as latestForPol.
	policy string
	// The policy row's identity, for a row with no product snapshot.
	polTeam, polBundle, polWinget, polName, polBrowser, polExt string
}

// DeviceAuthority is the absence authority of the report ReconcileDevice
// runs for.
type DeviceAuthority struct {
	// AppsComplete: the report's collection_status.apps was "complete" on a
	// schema v3 payload and its machine-wide prune ran (PAT-2063). Only then
	// may an application alert resolve as not_observed.
	AppsComplete bool
	// queueSeq ties deferred absence authority to the inventory write that
	// supplied it. A newer queued write invalidates that authority.
	queueSeq int64
}

// ReconcileDevice applies the lifecycle rules to every tracked alert on one
// device after an extraction committed: resolve on policy state, resolve as
// not_observed under authority, and re-open a resolved alert whose product
// is observed again while still Unapproved. Call it only for a report whose
// evidence time is authoritative.
func ReconcileDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, auth DeviceAuthority, now time.Time) (ReconcileResult, error) {
	var res ReconcileResult
	now = now.UTC()
	var hasAlerts bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid AND tenant_id = $2::uuid)
	`, deviceID, tenantID).Scan(&hasAlerts); err != nil {
		return res, fmt.Errorf("alert lifecycle pre-check: %w", err)
	}
	if !hasAlerts {
		res.Skipped = "no_alerts"
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
		return res, nil
	}
	if ok, err := tenantActive(ctx, tx, tenantID); err != nil || !ok {
		res.Skipped = "tenant_inactive"
		return res, err
	}

	// One statement reads each row with its policy's current value and
	// whether its episode is the policy's latest, so the two cannot disagree.
	// Writers of either hold lockTenantAlerts until they commit.
	rows, err := tx.Query(ctx, `
		SELECT ad.id, ad.episode_id, ad.status, COALESCE(ad.resolved_reason, ''),
		       COALESCE((SELECT t.detail->>'evidence' FROM software_unapproved_alert_transitions t
		                 WHERE t.alert_device_id = ad.id AND t.tenant_id = ad.tenant_id AND t.to_status = 'resolved'
		                 ORDER BY t.id DESC LIMIT 1), ''),
		       ad.product::text,
		       e.policy_kind, e.policy_id,
		       e.id = (SELECT max(e2.id) FROM software_unapproved_episodes e2
		               WHERE e2.tenant_id = e.tenant_id AND e2.policy_kind = e.policy_kind AND e2.policy_id = e.policy_id),
		       COALESCE(ap.policy, xp.policy, ''),
		       COALESCE(ap.team_id, ''), COALESCE(ap.bundle_id, ''), COALESCE(ap.winget_id, ''),
		       COALESCE(ap.name, xp.name, ''), COALESCE(xp.browser, ''), COALESCE(xp.extension_id, '')
		FROM software_unapproved_alerted_devices ad
		JOIN software_unapproved_episodes e ON e.id = ad.episode_id AND e.tenant_id = ad.tenant_id
		LEFT JOIN tenant_app_policies ap
		       ON e.policy_kind = 'application' AND ap.id = e.policy_id AND ap.tenant_id = e.tenant_id
		LEFT JOIN tenant_extension_policies xp
		       ON e.policy_kind = 'browser_extension' AND xp.id = e.policy_id AND xp.tenant_id = e.tenant_id
		WHERE ad.tenant_id = $1::uuid AND ad.device_id = $2::uuid
		ORDER BY ad.id
		FOR UPDATE OF ad
	`, tenantID, deviceID)
	if err != nil {
		return res, fmt.Errorf("load device alerts: %w", err)
	}
	var tracked []lifecycleRow
	for rows.Next() {
		var r lifecycleRow
		var product *string
		if err := rows.Scan(&r.id, &r.episodeID, &r.status, &r.resolvedReason, &r.resolvedEvidence, &product, &r.policyKind, &r.policyID,
			&r.latestForPol, &r.policy, &r.polTeam, &r.polBundle, &r.polWinget, &r.polName, &r.polBrowser, &r.polExt); err != nil {
			rows.Close()
			return res, err
		}
		if product != nil {
			var p Product
			if err := json.Unmarshal([]byte(*product), &p); err != nil {
				rows.Close()
				return res, fmt.Errorf("decode alert %d product: %w", r.id, err)
			}
			r.product = &p
		}
		tracked = append(tracked, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(tracked) == 0 {
		res.Skipped = "no_alerts"
		return res, nil
	}

	pol, err := loadPolicies(ctx, tx, tenantID)
	if err != nil {
		return res, err
	}
	inv, err := loadDeviceInventory(ctx, tx, deviceID, pol, now)
	if err != nil {
		return res, err
	}
	if auth.AppsComplete && auth.queueSeq != 0 {
		var stillCurrent bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue
			WHERE device_id = $1::uuid AND seq = $2 AND apps_complete AND detect_allowed)`, deviceID, auth.queueSeq).Scan(&stillCurrent); err != nil {
			return res, err
		}
		auth.AppsComplete = stillCurrent
	}
	settings, err := GetSettings(ctx, tx, tenantID)
	if err != nil {
		return res, err
	}

	for _, r := range tracked {
		ob := inv.observe(r)
		switch r.status {
		case AlertOpen, AlertAcknowledged:
			reason := ""
			var detail map[string]any
			switch {
			case r.policy != "unapproved":
				reason, _ = ResolveReasonForPolicy(r.policy)
				detail = map[string]any{"evidence": "policy_state"}
			case ob.underPolicy != nil:
				// Still installed and still governed by this policy.
			case ob.elsewhere != nil:
				// Still installed, but another policy row (or none) now
				// decides its state: never "not observed".
				reason = ReasonSuperseded
				detail = map[string]any{"evidence": "governed_by_other_policy",
					"winning_policy_kind": nullIfEmpty(ob.elsewhere.winKind), "winning_policy_id": nullIfZero(ob.elsewhere.winID),
					"winning_state": ob.elsewhere.winState}
			case ob.identityUnknown:
				// No product snapshot and nothing to match it by: absence
				// cannot be proven.
			case r.policyKind == TypeApplication && auth.AppsComplete && ob.appsAbsent:
				reason = ReasonNotObserved
				detail = map[string]any{"evidence": "apps_collection_complete"}
			case r.policyKind == TypeBrowserExtension && ob.extAbsent:
				reason = ReasonNotObserved
				detail = map[string]any{"evidence": "extension_absence_authorised"}
			}
			if reason != "" {
				if err := resolveRowTx(ctx, tx, tenantID, r, reason, detail); err != nil {
					return res, err
				}
				res.Resolved = append(res.Resolved, r.id)
				continue
			}
		case AlertResolved:
			// Only an absence, or a hand-over to another policy row, re-opens,
			// and only when this row's own Unapproved policy governs the
			// product again in the policy's latest episode. A policy
			// resolution or a superseded episode comes back, if at all, as a
			// new episode.
			if reopenable(r) && r.policy == "unapproved" && r.latestForPol && ob.underPolicy != nil {
				dev := inv.device
				dev.ObservedSince = ob.underPolicy.firstSeen
				if err := reopenRowTx(ctx, tx, tenantID, deviceID, r, ob.underPolicy.product, dev, settings.UnapprovedAlertsEnabled, now); err != nil {
					return res, err
				}
				res.Reopened = append(res.Reopened, r.id)
				continue
			}
		}
		if r.product == nil && ob.underPolicy != nil {
			if err := setProductTx(ctx, tx, r.id, ob.underPolicy.product); err != nil {
				return res, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ReconcileResult{}, err
	}
	return res, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// invItem is one current inventory row on the device with the policy row
// that decides its state now.
type invItem struct {
	product    Product
	identifier string // lower, trimmed (applications)
	name       string // lower, trimmed
	team       string // upper, trimmed (applications)
	absent     bool   // extensions: an authoritative report proved it gone
	firstSeen  time.Time
	winKind    string
	winID      int64
	winState   string
}

type deviceInventory struct {
	device Presence
	apps   []invItem
	exts   []invItem
}

// loadDeviceInventory reads the device's current applications and browser
// extensions and resolves each to the policy row that governs it now.
func loadDeviceInventory(ctx context.Context, tx pgx.Tx, deviceID string, pol policies, now time.Time) (deviceInventory, error) {
	var inv deviceInventory
	var osName string
	if err := tx.QueryRow(ctx, `
		SELECT id::text, COALESCE(hostname, ''), COALESCE(os, ''), last_seen FROM devices WHERE id = $1::uuid
	`, deviceID).Scan(&inv.device.DeviceID, &inv.device.Hostname, &osName, &inv.device.LastSeen); err != nil {
		return inv, fmt.Errorf("load device: %w", err)
	}
	platform := apppolicy.DevicePlatform(osName)
	inv.device.Platform = platform
	inv.device.Stale = inv.device.LastSeen.Before(now.Add(-StaleAfter))

	rows, err := tx.Query(ctx, `
		SELECT identifier, COALESCE(identifier_kind, ''), COALESCE(team_id, ''), name, first_seen
		FROM device_apps WHERE device_id = $1::uuid
	`, deviceID)
	if err != nil {
		return inv, fmt.Errorf("load device apps: %w", err)
	}
	for rows.Next() {
		var identifier, kind, team, name string
		var firstSeen time.Time
		if err := rows.Scan(&identifier, &kind, &team, &name, &firstSeen); err != nil {
			rows.Close()
			return inv, err
		}
		ident := strings.TrimSpace(identifier)
		teamKey := normalisedTeamID(platform, team)
		it := invItem{
			product: Product{Type: TypeApplication, ProductKey: ApplicationKey(platform, ident, teamKey),
				Name: name, Platform: platform, Identifier: ident, TeamID: teamKey},
			identifier: strings.ToLower(ident), name: strings.ToLower(strings.TrimSpace(name)),
			team: strings.ToUpper(strings.TrimSpace(team)), firstSeen: firstSeen.UTC(),
		}
		state, row := pol.resolveApp(team, identifier, kind, name, osName)
		it.winState = state
		if row != nil {
			it.winKind, it.winID = TypeApplication, row.policy.ID
		}
		inv.apps = append(inv.apps, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return inv, err
	}

	rows, err = tx.Query(ctx, `
		SELECT dbe.browser, dbe.extension_id, dbe.name, dbe.first_seen, `+extpresence.AbsenceAuthorisedSQL("dbe")+`
		FROM device_browser_extensions dbe
		WHERE dbe.device_id = $1::uuid
	`, deviceID)
	if err != nil {
		return inv, fmt.Errorf("load device extensions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var browser, extID, name string
		var firstSeen time.Time
		var absent bool
		if err := rows.Scan(&browser, &extID, &name, &firstSeen, &absent); err != nil {
			return inv, err
		}
		it := invItem{
			product: Product{Type: TypeBrowserExtension, ProductKey: ExtensionKey(browser, extID),
				Name: name, Browser: browser, ExtensionID: extID},
			identifier: extID, name: strings.ToLower(strings.TrimSpace(name)), absent: absent, firstSeen: firstSeen.UTC(),
		}
		state, row := pol.resolveExtension(browser, extID)
		it.winState = state
		if row != nil {
			it.winKind, it.winID = TypeBrowserExtension, row.id
		}
		inv.exts = append(inv.exts, it)
	}
	return inv, rows.Err()
}

// observation is what the device's inventory says about one tracked alert.
type observation struct {
	// underPolicy: an item still present and governed by the alert's policy.
	underPolicy *invItem
	// elsewhere: the alert's product is still present but governed by
	// another policy row, or by none.
	elsewhere *invItem
	// appsAbsent: no application on the device matches the product's
	// identity (identifier or display name). Only proof of absence under a
	// complete report (DeviceAuthority.AppsComplete).
	appsAbsent bool
	// extAbsent: at least one stored row of the extension, and every one is
	// proven gone by an authoritative report (PAT-2055).
	extAbsent bool
	// identityUnknown: no product snapshot and no policy identity to match.
	identityUnknown bool
}

// observe decides presence per product identity across the whole device,
// independent of which policy row wins today. An application matches the
// alert's product when it has the same identifier (ignoring case and Team
// ID, so a re-signed build still matches) or the same display name (so a
// changed identifier under the same name still matches). A browser
// extension matches on its extension id, on the product's browser unless
// the product or its policy covers any browser.
func (inv deviceInventory) observe(r lifecycleRow) observation {
	var ob observation
	if r.policyKind == TypeApplication {
		ident, name := "", ""
		if r.product != nil {
			ident = strings.ToLower(strings.TrimSpace(r.product.Identifier))
			name = strings.ToLower(strings.TrimSpace(r.product.Name))
		}
		polIdents := []string{}
		for _, v := range []string{r.polBundle, r.polWinget} {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				polIdents = append(polIdents, v)
			}
		}
		polName := strings.ToLower(strings.TrimSpace(r.polName))
		polTeam := strings.ToUpper(strings.TrimSpace(r.polTeam))
		if r.product == nil && len(polIdents) == 0 && polName == "" && polTeam == "" {
			ob.identityUnknown = true
		}
		matches := func(it invItem) bool {
			if r.product != nil {
				return (ident != "" && it.identifier == ident) || (name != "" && it.name == name)
			}
			// No snapshot (a baseline row not reported since 0184): match
			// on any identity field of the policy, the wide 0183 rule.
			for _, v := range polIdents {
				if it.identifier == v {
					return true
				}
			}
			return (polName != "" && it.name == polName) || (polTeam != "" && it.team == polTeam)
		}
		ob.appsAbsent = true
		for i := range inv.apps {
			it := &inv.apps[i]
			if it.winKind == TypeApplication && it.winID == r.policyID && ob.underPolicy == nil {
				ob.underPolicy = it
			}
			if matches(*it) {
				ob.appsAbsent = false
				if ob.elsewhere == nil && !(it.winKind == TypeApplication && it.winID == r.policyID) {
					ob.elsewhere = it
				}
			}
		}
		if ob.underPolicy != nil {
			ob.elsewhere = nil
		}
		return ob
	}

	extID, browser := r.polExt, r.polBrowser
	if r.product != nil {
		extID, browser = r.product.ExtensionID, r.product.Browser
		if r.polBrowser == "any" {
			browser = "any"
		}
	}
	if extID == "" {
		ob.identityUnknown = true
		return ob
	}
	matched, gone := 0, 0
	for i := range inv.exts {
		it := &inv.exts[i]
		if it.identifier != extID || (browser != "" && browser != "any" && it.product.Browser != browser) {
			if !it.absent && it.winKind == TypeBrowserExtension && it.winID == r.policyID && ob.underPolicy == nil {
				ob.underPolicy = it
			}
			continue
		}
		matched++
		if it.absent {
			gone++
			continue
		}
		if it.winKind == TypeBrowserExtension && it.winID == r.policyID {
			if ob.underPolicy == nil {
				ob.underPolicy = it
			}
		} else if ob.elsewhere == nil {
			ob.elsewhere = it
		}
	}
	if ob.underPolicy != nil {
		ob.elsewhere = nil
	}
	ob.extAbsent = matched > 0 && gone == matched
	return ob
}

func resolveRowTx(ctx context.Context, tx pgx.Tx, tenantID string, r lifecycleRow, reason string, detail map[string]any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		WITH upd AS (
			UPDATE software_unapproved_alerted_devices
			SET status = 'resolved', status_changed_at = now(), resolved_at = now(),
			    resolved_reason = $3, reopen_digest_pending = false
			WHERE id = $1 AND tenant_id = $2::uuid AND status IN ('open', 'acknowledged')
			RETURNING id, episode_id, device_id, $4::text AS from_status
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, reason, detail)
		SELECT $2::uuid, id, episode_id, device_id, from_status, 'resolved', 'system', $3, $5::jsonb
		FROM upd
	`, r.id, tenantID, reason, r.status, string(body)); err != nil {
		return fmt.Errorf("resolve alert: %w", err)
	}
	return nil
}

func reopenRowTx(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, r lifecycleRow, product Product, device Presence, digest bool, now time.Time) error {
	productJSON, err := json.Marshal(product)
	if err != nil {
		return err
	}
	// The digest renders a re-open from this detail, in the same shape as an
	// observed alert payload.
	detail, err := json.Marshal(map[string]any{
		"evidence": "observed",
		"payload": AlertPayload{
			Trigger: "reopened", Policy: AlertPolicy{Kind: r.policyKind, ID: r.policyID},
			MarkedVia: "unknown", DetectedAt: now, DeviceCount: 1,
			Products: []AlertProduct{{Product: product, DeviceCount: 1, Devices: alertDevices([]Presence{device})}},
		},
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		WITH upd AS (
			UPDATE software_unapproved_alerted_devices
			SET status = 'open', status_changed_at = now(), resolved_at = NULL, resolved_reason = NULL,
			    acknowledged_at = NULL, acknowledged_by = NULL, acknowledged_by_kind = NULL,
			    reopened_count = reopened_count + 1, last_reopened_at = now(),
			    reopen_digest_pending = $4, product = $5::jsonb
			WHERE id = $1 AND tenant_id = $2::uuid AND device_id = $3::uuid AND status = 'resolved'
			RETURNING id, episode_id, device_id
		)
		INSERT INTO software_unapproved_alert_transitions
		    (tenant_id, alert_device_id, episode_id, device_id, from_status, to_status, actor_kind, detail)
		SELECT $2::uuid, id, episode_id, device_id, 'resolved', 'open', 'system', $6::jsonb
		FROM upd
	`, r.id, tenantID, deviceID, digest, string(productJSON), string(detail)); err != nil {
		return fmt.Errorf("reopen alert: %w", err)
	}
	return nil
}

func setProductTx(ctx context.Context, tx pgx.Tx, id int64, product Product) error {
	body, err := json.Marshal(product)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_unapproved_alerted_devices SET product = $2::jsonb WHERE id = $1 AND product IS NULL
	`, id, string(body)); err != nil {
		return fmt.Errorf("record alert product: %w", err)
	}
	return nil
}

// reopenable reports whether a resolved row's resolution can be undone by
// the product being observed under its policy again.
func reopenable(r lifecycleRow) bool {
	switch r.resolvedReason {
	case ReasonNotObserved:
		return true
	case ReasonSuperseded:
		return r.resolvedEvidence == "governed_by_other_policy"
	}
	return false
}
