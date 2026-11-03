package extractor

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/apppolicy"
	"patched.im/api/internal/evaluator"
	"patched.im/api/internal/findinglifecycle"
	"patched.im/api/internal/notifications"
)

const (
	softwareMandatoryMissing    = "mandatory_missing"
	softwareUnapprovedPresent   = "unapproved_present"
	softwareVersionBelowMinimum = "version_below_minimum"
)

type lifecycleSoftwarePolicy = apppolicy.Policy

// recordCISFindingObservations folds the rule results from this exact payload
// into PAT-1878's immutable lifecycle. A pass derived from missing/unknown
// evidence is deliberately non-authoritative and therefore cannot close a
// finding. collectedAt, not server receive time, is the freshness clock.
// It also returns the notification events those transitions imply (PAT-1888).
// They are returned rather than raised here on purpose: this runs inside the
// extraction transaction, and notifying from inside it would let a notification
// failure roll back the finding it was reporting. The caller raises them after
// the commit.
func recordCISFindingObservations(ctx context.Context, tx pgx.Tx, tenantID, deviceID string,
	rules []evaluator.Rule, evals []eval, collectedAt time.Time, rawPayloadID int64, receivedAt time.Time) (int, []notifications.Event, error) {
	ruleKeys := make(map[string]string, len(rules))
	ruleSeverity := make(map[string]string, len(rules))
	for _, rule := range rules {
		ruleKeys[rule.ID] = rule.RuleKey
		ruleSeverity[rule.ID] = rule.Severity
	}
	written := 0
	var events []notifications.Event
	for _, evaluation := range evals {
		ruleKey := ruleKeys[evaluation.ruleID]
		if ruleKey == "" {
			return written, events, fmt.Errorf("finding lifecycle: no rule key for rule id %s", evaluation.ruleID)
		}
		outcome := findinglifecycle.OutcomeUnknown
		authoritative := findinglifecycle.EvidenceTimeAuthoritative(collectedAt, receivedAt) && evaluation.observedValue != nil
		if authoritative {
			switch evaluation.status {
			case evaluator.StatusFail, evaluator.StatusError:
				outcome = findinglifecycle.OutcomeFailing
			case evaluator.StatusPass:
				outcome = findinglifecycle.OutcomePassing
			default:
				authoritative = false
			}
		}
		eventType, err := findinglifecycle.RecordObservation(ctx, tx, findinglifecycle.Observation{
			Identity: findinglifecycle.Identity{
				TenantID: tenantID, Kind: findinglifecycle.KindCIS,
				DeviceID: &deviceID, FindingKey: ruleKey,
			},
			Outcome: outcome, ObservedAt: collectedAt, ReceivedAt: receivedAt, Authoritative: authoritative,
			Reason: "CIS evaluation from authenticated endpoint inventory",
			Evidence: map[string]any{
				"raw_payload_id":    rawPayloadID,
				"received_at":       receivedAt,
				"rule_id":           evaluation.ruleID,
				"status":            evaluation.status,
				"observed_value":    evaluation.observedValue,
				"severity":          evaluation.severity,
				"benchmark_version": evaluation.benchmarkVersion,
			},
		})
		if err != nil {
			return written, events, fmt.Errorf("record CIS lifecycle for %s: %w", ruleKey, err)
		}
		if eventType != "" {
			written++
			if ev, ok := lifecycleNotification(tenantID, findinglifecycle.KindCIS, &deviceID, ruleKey,
				eventType, ruleSeverity[evaluation.ruleID], collectedAt, map[string]any{
					"device_id":         deviceID,
					"rule_key":          ruleKey,
					"status":            evaluation.status,
					"severity":          ruleSeverity[evaluation.ruleID],
					"benchmark_version": evaluation.benchmarkVersion,
				}); ok {
				events = append(events, ev)
			}
		}
	}
	return written, events, nil
}

// raiseFindingNotifications enqueues the events from a committed extraction.
//
// Every failure is logged and dropped. The caller has already committed the
// lifecycle rows, so there is nothing here that could alter finding truth even
// if every channel in the estate were unreachable.
func raiseFindingNotifications(pool *pgxpool.Pool, events []notifications.Event, logger *slog.Logger) {
	if pool == nil || len(events) == 0 {
		return
	}
	for _, ev := range events {
		notifications.NotifyAsync(pool, ev)
	}
	if logger != nil {
		logger.Debug("finding notifications raised", "count", len(events))
	}
}

// lifecycleNotification turns one committed lifecycle transition into a
// notification event, or reports that the transition is not notifiable.
//
// It reads the lifecycle's own decision and never re-derives it. Nothing here
// can raise verification.passed for evidence the lifecycle judged stale: that
// mapping only fires for the verified_fixed transition, which the reducer only
// produces from fresh, authoritative evidence.
func lifecycleNotification(tenantID, kind string, deviceID *string, findingKey, lifecycleEventType,
	severity string, observedAt time.Time, data map[string]any) (notifications.Event, bool) {
	eventKind, ok := notifications.EventForLifecycle(lifecycleEventType)
	if !ok {
		return notifications.Event{}, false
	}
	if data == nil {
		data = map[string]any{}
	}
	data["finding_kind"] = kind
	data["finding_key"] = findingKey
	data["lifecycle_event"] = lifecycleEventType
	data["observed_at"] = observedAt.UTC()
	return notifications.Event{
		TenantID:  tenantID,
		Type:      eventKind,
		Subject:   notifications.Subject(kind, deviceID, findingKey, observedAt),
		Severity:  severity,
		Timestamp: observedAt.UTC(),
		Data:      data,
	}, true
}

// recordSoftwareFindingObservations evaluates the same three software-policy
// drift identities exposed by app-policy-drift. Absence can close a finding
// only when this payload has explicit inventory authority for the relevant
// platform scope; partial Windows inventory therefore leaves verification
// unknown rather than reading omission as remediation.
//
// Like recordCISFindingObservations it returns the notification events its
// transitions imply, for the caller to raise after the commit.
func recordSoftwareFindingObservations(ctx context.Context, tx pgx.Tx, tenantID, deviceID, platform string,
	p *payload, collectedAt time.Time, rawPayloadID int64, receivedAt time.Time) (int, []notifications.Event, error) {
	var events []notifications.Event
	rows, err := tx.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, source
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return 0, events, fmt.Errorf("load software policies for lifecycle: %w", err)
	}
	policies := map[int64]lifecycleSoftwarePolicy{}
	var policyList []apppolicy.Policy
	candidates := map[string]struct{}{}
	for rows.Next() {
		var policy lifecycleSoftwarePolicy
		if err := rows.Scan(&policy.ID, &policy.TeamID, &policy.BundleID, &policy.WingetID,
			&policy.Name, &policy.Platform, &policy.Policy, &policy.EnforcementTier, &policy.MinVersion, &policy.Source); err != nil {
			rows.Close()
			return 0, events, fmt.Errorf("scan software policy for lifecycle: %w", err)
		}
		policies[policy.ID] = policy
		policyList = append(policyList, policy)
		if policy.Policy == "unapproved" {
			candidates[softwareUnapprovedPresent+":"+strconv.FormatInt(policy.ID, 10)] = struct{}{}
		}
		if policy.Policy == "mandatory" {
			candidates[softwareMandatoryMissing+":"+strconv.FormatInt(policy.ID, 10)] = struct{}{}
			if policy.MinVersion != nil && strings.TrimSpace(*policy.MinVersion) != "" {
				candidates[softwareVersionBelowMinimum+":"+strconv.FormatInt(policy.ID, 10)] = struct{}{}
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, events, fmt.Errorf("iterate software policies for lifecycle: %w", err)
	}
	rows.Close()
	activePolicies := map[int64]bool{}
	for _, policy := range apppolicy.EffectivePolicies(policyList, platform) {
		activePolicies[policy.ID] = true
	}
	policyIndex := apppolicy.BuildIndex(policyList)

	// Policies can change after a finding is opened. Keep evaluating every
	// historical identity so the next authoritative endpoint snapshot can
	// close it without erasing the earlier policy/action history.
	historyRows, err := tx.Query(ctx, `
		SELECT DISTINCT finding_key
		FROM finding_lifecycle_events
		WHERE tenant_id = $1::uuid AND finding_kind = 'software' AND device_id = $2::uuid
	`, tenantID, deviceID)
	if err != nil {
		return 0, events, fmt.Errorf("load historical software lifecycle identities: %w", err)
	}
	for historyRows.Next() {
		var key string
		if err := historyRows.Scan(&key); err != nil {
			historyRows.Close()
			return 0, events, fmt.Errorf("scan historical software lifecycle identity: %w", err)
		}
		candidates[key] = struct{}{}
	}
	if err := historyRows.Err(); err != nil {
		historyRows.Close()
		return 0, events, fmt.Errorf("iterate historical software lifecycle identities: %w", err)
	}
	historyRows.Close()

	scopes := authoritativeSoftwareScopes(p, platform)
	allSoftwareAuthoritative := false
	wingetAuthoritative := false
	for _, scope := range scopes {
		allSoftwareAuthoritative = allSoftwareAuthoritative || scope == "all_software"
		wingetAuthoritative = wingetAuthoritative || scope == "windows_winget"
	}

	// PAT-2075: the report's apps plus the per-user apps it did not list
	// because their user was logged off or read only partially. Those are
	// still installed as far as anything knows, so they are neither
	// "removed" nor "missing" for a policy finding. Loaded only when the
	// report is authoritative for some application scope.
	apps := p.Apps
	if allSoftwareAuthoritative || wingetAuthoritative {
		held, err := loadHeldUserApps(ctx, tx, deviceID, p.AppsUserScopesSeen)
		if err != nil {
			return 0, events, err
		}
		// And the legacy user-located rows the report had no authority
		// over (apps_legacy_user.go).
		legacyHeld, err := loadHeldLegacyApps(ctx, tx, p.AppsLegacyHeld)
		if err != nil {
			return 0, events, err
		}
		if len(held)+len(legacyHeld) > 0 {
			apps = append(append(append([]appPart{}, p.Apps...), held...), legacyHeld...)
		}
	}

	written := 0
	for key := range candidates {
		driftType, policyRaw, found := strings.Cut(key, ":")
		policyID, parseErr := strconv.ParseInt(policyRaw, 10, 64)
		policy, policyFound := policies[policyID]
		outcome := findinglifecycle.OutcomeUnknown
		authoritative := false
		if found && parseErr == nil && policyFound {
			authoritative = findinglifecycle.EvidenceTimeAuthoritative(collectedAt, receivedAt) &&
				(allSoftwareAuthoritative || (wingetAuthoritative && policy.WingetID != nil && strings.TrimSpace(*policy.WingetID) != ""))
			if authoritative {
				matches := matchingPolicyApps(policy, apps, platform)
				active := activePolicies[policy.ID]
				switch driftType {
				case softwareUnapprovedPresent:
					if active && policy.Policy == "unapproved" && policySelectedForAnyApp(policyIndex, policy.ID, apps, platform) {
						outcome = findinglifecycle.OutcomeFailing
					} else {
						outcome = findinglifecycle.OutcomePassing
					}
				case softwareMandatoryMissing:
					if active && policy.Policy == "mandatory" && len(matches) == 0 {
						outcome = findinglifecycle.OutcomeFailing
					} else {
						outcome = findinglifecycle.OutcomePassing
					}
				case softwareVersionBelowMinimum:
					outcome, authoritative = versionBelowMinimumOutcome(active && policy.Policy == "mandatory", policy.MinVersion, matches, authoritative)
				default:
					authoritative = false
				}
			}
		}
		evidence := map[string]any{
			"raw_payload_id":       rawPayloadID,
			"received_at":          receivedAt,
			"authoritative_scopes": scopes,
			"drift_type":           driftType,
			"policy_id":            policyID,
		}
		if policyFound {
			evidence["policy_snapshot"] = softwarePolicySnapshot(policy)
		}
		eventType, err := findinglifecycle.RecordObservation(ctx, tx, findinglifecycle.Observation{
			Identity: findinglifecycle.Identity{
				TenantID: tenantID, Kind: findinglifecycle.KindSoftware,
				DeviceID: &deviceID, FindingKey: key,
			},
			Outcome: outcome, ObservedAt: collectedAt, ReceivedAt: receivedAt, Authoritative: authoritative,
			Reason:   "software policy drift evaluated from authenticated endpoint inventory",
			Evidence: evidence,
		})
		if err != nil {
			return written, events, fmt.Errorf("record software lifecycle for %s: %w", key, err)
		}
		if eventType != "" {
			written++
			severity := ""
			if policyFound {
				severity = softwareDriftSeverity(driftType, policy)
			}
			if ev, ok := lifecycleNotification(tenantID, findinglifecycle.KindSoftware, &deviceID, key,
				eventType, severity, collectedAt, map[string]any{
					"device_id":  deviceID,
					"drift_type": driftType,
					"policy_id":  policyID,
				}); ok {
				events = append(events, ev)
			}
		}
	}
	return written, events, nil
}

// softwareDriftSeverity grades a software-policy drift finding for the
// per-channel severity threshold.
//
// An enforced policy is graded high because the customer has already declared
// it matters; everything else is medium. This is a notification filter only: it
// never reaches the finding, the lifecycle or any report.
func softwareDriftSeverity(driftType string, policy lifecycleSoftwarePolicy) string {
	if strings.EqualFold(strings.TrimSpace(policy.EnforcementTier), "enforced") {
		return notifications.SeverityHigh
	}
	switch driftType {
	case softwareUnapprovedPresent, softwareMandatoryMissing, softwareVersionBelowMinimum:
		return notifications.SeverityMedium
	default:
		return ""
	}
}

func softwarePolicySnapshot(policy lifecycleSoftwarePolicy) map[string]any {
	return map[string]any{
		"team_id": policy.TeamID, "bundle_id": policy.BundleID,
		"winget_id": policy.WingetID, "name": policy.Name,
		"platform": policy.Platform, "policy": policy.Policy,
		"enforcement_tier": policy.EnforcementTier,
		"min_version":      policy.MinVersion,
	}
}

func versionBelowMinimumOutcome(active bool, minimum *string, matches []appPart, authoritative bool) (findinglifecycle.ObservationOutcome, bool) {
	if !active || minimum == nil {
		return findinglifecycle.OutcomePassing, authoritative
	}
	unknownVersion := false
	for _, app := range matches {
		comparison, comparable := compareLifecycleVersions(app.Version, *minimum)
		if !comparable {
			unknownVersion = true
			continue
		}
		if comparison < 0 {
			return findinglifecycle.OutcomeFailing, authoritative
		}
	}
	if unknownVersion {
		return findinglifecycle.OutcomeUnknown, false
	}
	return findinglifecycle.OutcomePassing, authoritative
}

func matchingPolicyApps(policy lifecycleSoftwarePolicy, apps []appPart, platform string) []appPart {
	var matches []appPart
	for _, app := range apps {
		identifier := firstIdentityValue(app.Identifier, app.BundleID)
		if apppolicy.Matches(policy, apppolicy.InstalledIdentity{
			TeamID: app.TeamID, BundleID: identifier,
			WingetID: apppolicy.InstalledWingetID(identifier, app.IdentifierKind, platform),
			Name:     app.Name,
		}) {
			matches = append(matches, app)
		}
	}
	return matches
}

func policySelectedForAnyApp(index apppolicy.Index, policyID int64, apps []appPart, platform string) bool {
	for _, app := range apps {
		identifier := firstIdentityValue(app.Identifier, app.BundleID)
		selected, ok := index.Resolve(app.TeamID, identifier, app.IdentifierKind, app.Name, platform)
		if ok && selected.ID == policyID && selected.Policy == "unapproved" {
			return true
		}
	}
	return false
}

func compareLifecycleVersions(a, b string) (int, bool) {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return 0, false
	}
	parse := func(raw string) ([]int, bool) {
		parts := strings.Split(raw, ".")
		parsed := make([]int, len(parts))
		for i, part := range parts {
			if part == "" {
				return nil, false
			}
			value, err := strconv.Atoi(part)
			if err != nil {
				return nil, false
			}
			parsed[i] = value
		}
		return parsed, true
	}
	aParts, aOK := parse(strings.TrimSpace(a))
	bParts, bOK := parse(strings.TrimSpace(b))
	if !aOK || !bOK {
		return 0, false
	}
	count := len(aParts)
	if len(bParts) > count {
		count = len(bParts)
	}
	for i := 0; i < count; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}
