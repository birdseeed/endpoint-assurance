package report

// Cyber Essentials readiness (PAT-1927): the read model behind
// GET /v1/portal/ce-readiness. It lists, per device, what stands between the
// device and the Cyber Essentials v3.3 14-day update rule and the malware,
// firewall and secure configuration controls the platform can evidence.
//
// It deliberately carries no verdict. A device is at most not_passing or
// no_outstanding_items_evidenced; the estate block is counts only. Nothing
// here says, or can be read as, passes, compliant or certified.
//
// Conventions follow the Overview cards (portal_overview_cards.go): the same
// reporting buckets and thresholds on the database clock, every value names
// its source and freshness, and absence of evidence is unknown or
// not_evidenced, never healthy. The tenant is the caller's, which on the
// portal is always the portalauth-resolved tenant.
//
// Failure isolation: only the base device query fails the read. A failing
// findings, evaluations, KEV or EDR source degrades what rests on it to
// unknown or not_evidenced with reason query_failed, which can only move a
// device away from no_outstanding_items_evidenced, never towards it.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/exploitation"
)

// CEUpdateDueAfter is the Cyber Essentials v3.3 window for critical and high
// updates.
const CEUpdateDueAfter = 14 * 24 * time.Hour

// CEDueBasis names how due_at is derived: the advisory publication date
// (cve_feed_entries.published_at) plus 14 days. The platform stores no
// fix-release date, and an advisory is normally published no later than its
// fix, so this is a conservative proxy that can overstate how overdue an
// item is. days_overdue is never presented without it.
const CEDueBasis = "advisory_published_plus_14_days"

// Device states. No passing state exists by design.
const (
	CEDeviceNotPassing   = "not_passing"
	CEDeviceUnknown      = "unknown"
	CEDeviceNoItemsFound = "no_outstanding_items_evidenced"
)

// Control states.
const (
	CEControlEvidencedOK  = "evidenced_ok"
	CEControlNotPassing   = "not_passing"
	CEControlNotEvidenced = "not_evidenced"
)

// Evidence states for the CVE and OS update evidence blocks.
const (
	CEEvidenceEvidenced   = "evidenced"
	CEEvidenceUnknown     = "unknown"
	CEEvidenceUnavailable = "unavailable"
)

// KEV states.
const (
	CEKEVListed    = "listed"
	CEKEVNotListed = "not_listed"
	CEKEVUnknown   = "unknown"
)

// Reason codes (bounded, snake_case) specific to this read model; the
// Overview card codes (query_failed, source_not_migrated,
// no_completed_match_run, version_evidence_pending) are reused.
const (
	CEReasonOutstandingItems    = "outstanding_items"
	CEReasonControlNotPassing   = "control_not_passing"
	CEReasonDeviceStale         = "device_stale"
	CEReasonDeviceSilent        = "device_silent"
	CEReasonDeviceNoReportTime  = "device_no_report_time"
	CEReasonMatchPending        = "cve_match_pending"
	CEReasonAdvisoryDateUnknown = "advisory_date_unknown"
	CEReasonNoEvaluation        = "no_evaluation"
	CEReasonEvaluationFailed    = "evaluation_failed"
	CEReasonUndetermined        = "undetermined"
	CEReasonEvaluationError     = "evaluation_error"
	CEReasonNotApplicable       = "not_applicable"
	CEReasonEDRUnrecognised     = "edr_unrecognised"
	CEReasonNoEDREvidence       = "no_edr_evidence"
)

// Control categories, named for the Cyber Essentials technical controls.
const (
	CECategoryMalware  = "malware_protection"
	CECategoryFirewall = "firewalls"
	CECategorySecure   = "secure_configuration"
)

type ceControlDef struct {
	control, category, ruleKey string
}

// ceControlsByOS is every control the platform can evidence. A rule absent
// from here is not claimed at all; a rule listed here with no evaluation is
// not_evidenced.
var ceControlsByOS = map[string][]ceControlDef{
	"Windows": {
		{"defender_realtime_protection", CECategoryMalware, "cis_win_18_9_45_defender_realtime"},
		{"defender_cloud_protection", CECategoryMalware, "cis_win_18_9_47_4_1_defender_cloud_protection"},
		{"defender_definition_age", CECategoryMalware, "nist_win_si3_defender_definition_age"},
		{"firewall_domain", CECategoryFirewall, "cis_win_9_1_1_firewall_domain"},
		{"firewall_private", CECategoryFirewall, "cis_win_9_2_1_firewall_private"},
		{"firewall_public", CECategoryFirewall, "cis_win_9_3_1_firewall_public"},
	},
	"macOS": {
		{"xprotect_running", CECategoryMalware, "cis_macos_5_10_xprotect_running"},
		{"xprotect_data_auto_update", CECategoryMalware, "cis_macos_1_6a_xprotect_data_auto"},
		{"gatekeeper", CECategorySecure, "cis_macos_2_5_2_1_gatekeeper"},
		{"system_integrity_protection", CECategorySecure, "cis_macos_2_5_3_sip"},
		{"firewall", CECategoryFirewall, "cis_macos_2_5_2_2_firewall"},
	},
}

// CEThresholds echoes the thresholds the read model used.
type CEThresholds struct {
	UpdateDueAfterDays int `json:"update_due_after_days"`
	ActiveWithinHours  int `json:"active_within_hours"`
	SilentAfterDays    int `json:"silent_after_days"`
}

// CEEvidence is an evidence block: its state, a bounded reason when not
// evidenced, the named source and the newest evidence time.
type CEEvidence struct {
	State      string     `json:"state"`
	Reason     *string    `json:"reason"`
	Source     string     `json:"source"`
	ObservedAt *time.Time `json:"observed_at"`
}

// CEFreshness pairs a figure's platform generation time with the newest
// evidence it rests on.
type CEFreshness struct {
	GeneratedAt time.Time  `json:"generated_at"`
	ObservedAt  *time.Time `json:"observed_at"`
}

// CEKEV is the CISA KEV listing state of one CVE, from the platform's
// retained catalogue snapshot.
type CEKEV struct {
	State     string     `json:"state"`
	Source    string     `json:"source"`
	FetchedAt *time.Time `json:"fetched_at"`
	Reason    *string    `json:"reason"`
}

// CEItem is one outstanding critical or high update past its due date.
type CEItem struct {
	Kind             string     `json:"kind"`
	CVEID            string     `json:"cve_id"`
	Severity         string     `json:"severity"`
	Product          string     `json:"product"`
	InstalledVersion string     `json:"installed_version"`
	FixedVersion     *string    `json:"fixed_version"`
	PublishedAt      time.Time  `json:"published_at"`
	DueBasis         string     `json:"due_basis"`
	DueAt            time.Time  `json:"due_at"`
	AgeDays          int        `json:"age_days"`
	DaysOverdue      int        `json:"days_overdue"`
	KEV              CEKEV      `json:"kev"`
	Source           string     `json:"source"`
	ObservedAt       *time.Time `json:"observed_at"`
}

// CEControl is one evidenced (or not) control on one device.
type CEControl struct {
	Control    string     `json:"control"`
	Category   string     `json:"category"`
	State      string     `json:"state"`
	Reason     *string    `json:"reason"`
	Source     string     `json:"source"`
	RuleKey    *string    `json:"rule_key"`
	ObservedAt *time.Time `json:"observed_at"`
}

// CEReporting is the device's reporting bucket, as on the Overview devices
// card.
type CEReporting struct {
	Bucket     string     `json:"bucket"`
	Source     string     `json:"source"`
	ObservedAt *time.Time `json:"observed_at"`
}

// CEDevice is one in-scope (non-retired) device.
type CEDevice struct {
	DeviceID         string      `json:"device_id"`
	Hostname         string      `json:"hostname"`
	Platform         string      `json:"platform"`
	State            string      `json:"state"`
	StateReasons     []string    `json:"state_reasons"`
	Reporting        CEReporting `json:"reporting"`
	CVEEvidence      CEEvidence  `json:"cve_evidence"`
	OSUpdateEvidence CEEvidence  `json:"os_update_evidence"`
	Items            []CEItem    `json:"items"`
	Controls         []CEControl `json:"controls"`
}

// CEEstate is counts only. not_passing + unknown +
// no_outstanding_items_evidenced = devices_total; with_outstanding_items and
// with_controls_not_passing are subsets of not_passing.
type CEEstate struct {
	DevicesTotal               int         `json:"devices_total"`
	NotPassing                 int         `json:"not_passing"`
	WithOutstandingItems       int         `json:"with_outstanding_items"`
	WithControlsNotPassing     int         `json:"with_controls_not_passing"`
	Unknown                    int         `json:"unknown"`
	NoOutstandingItemsEvidence int         `json:"no_outstanding_items_evidenced"`
	RetiredExcluded            int         `json:"retired_excluded"`
	Source                     string      `json:"source"`
	Freshness                  CEFreshness `json:"freshness"`
}

// PortalCEReadiness is the GET /v1/portal/ce-readiness response.
type PortalCEReadiness struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Thresholds  CEThresholds `json:"thresholds"`
	CVEMatching CEEvidence   `json:"cve_matching"`
	Estate      CEEstate     `json:"estate"`
	Devices     []CEDevice   `json:"devices"`
}

func ceReason(s string) *string { return &s }

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

type ceDeviceRow struct {
	dev          *CEDevice
	os           string
	lastSeen     *time.Time
	matchPending bool
	lastMatched  *time.Time
	undated      bool
}

// FetchPortalCEReadiness builds the CE readiness read model for tenantID. It
// returns an error only when the tenant or base device query fails.
func FetchPortalCEReadiness(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalCEReadiness, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return PortalCEReadiness{}, err
	}
	now, rows, retired, err := fetchCEDevices(ctx, pool, tenantID, sw)
	if err != nil {
		return PortalCEReadiness{}, err
	}
	out := PortalCEReadiness{
		GeneratedAt: now,
		Thresholds: CEThresholds{
			UpdateDueAfterDays: int(CEUpdateDueAfter / (24 * time.Hour)),
			ActiveWithinHours:  int(OverviewActiveWithin / time.Hour),
			SilentAfterDays:    int(OverviewSilentAfter / (24 * time.Hour)),
		},
		Devices: []CEDevice{},
	}
	byID := make(map[string]*ceDeviceRow, len(rows))
	for i := range rows {
		byID[rows[i].dev.DeviceID] = &rows[i]
	}

	// CVE matching, estate-wide: a zero is only authoritative after a
	// completed full match, exactly as on the vulnerabilities card.
	out.CVEMatching = CEEvidence{State: CEEvidenceEvidenced, Source: "cve_match_runs.full_match"}
	lastFull, migrated, err := lastFullMatchAt(ctx, pool)
	switch {
	case err != nil:
		slog.Warn("ce readiness: cve match run read failed", "tenant_id", tenantID, "err", err)
		out.CVEMatching.State, out.CVEMatching.Reason = CEEvidenceUnavailable, ceReason(CardReasonQueryFailed)
	case !migrated:
		out.CVEMatching.State, out.CVEMatching.Reason = CEEvidenceUnavailable, ceReason(CardReasonSourceNotMigrated)
	case lastFull == nil:
		out.CVEMatching.State, out.CVEMatching.Reason = CEEvidenceUnknown, ceReason(CardReasonNoCompletedMatchRun)
	}
	out.CVEMatching.ObservedAt = lastFull

	if out.CVEMatching.State != CEEvidenceUnavailable {
		if err := fetchCEItems(ctx, pool, tenantID, now, byID); err != nil {
			slog.Warn("ce readiness: findings read failed", "tenant_id", tenantID, "err", err)
			out.CVEMatching.State, out.CVEMatching.Reason = CEEvidenceUnavailable, ceReason(CardReasonQueryFailed)
			for _, r := range byID {
				r.dev.Items = []CEItem{}
				r.undated = false
			}
		}
	}
	evals, evalErr := fetchCEEvaluations(ctx, pool, tenantID)
	if evalErr != nil {
		slog.Warn("ce readiness: evaluations read failed", "tenant_id", tenantID, "err", evalErr)
	}
	edr, edrErr := FetchEDRCoverageReport(ctx, pool, tenantID)
	if edrErr != nil {
		slog.Warn("ce readiness: edr coverage read failed", "tenant_id", tenantID, "err", edrErr)
	}
	edrByID := map[string]EDRState{}
	for _, d := range edr.Devices {
		edrByID[d.DeviceID] = d.State
	}

	var newest *time.Time
	for i := range rows {
		r := &rows[i]
		d := r.dev
		if r.lastSeen != nil && !r.lastSeen.After(now) && (newest == nil || r.lastSeen.After(*newest)) {
			newest = r.lastSeen
		}
		d.CVEEvidence = ceDeviceCVEEvidence(out.CVEMatching, r, lastFull)
		d.Controls = ceDeviceControls(r, evals, evalErr, edrByID, edrErr)
		ceDeviceState(d)
		out.Devices = append(out.Devices, *d)

		e := &out.Estate
		e.DevicesTotal++
		switch d.State {
		case CEDeviceNotPassing:
			e.NotPassing++
		case CEDeviceUnknown:
			e.Unknown++
		default:
			e.NoOutstandingItemsEvidence++
		}
		if len(d.Items) > 0 {
			e.WithOutstandingItems++
		}
		for _, c := range d.Controls {
			if c.State == CEControlNotPassing {
				e.WithControlsNotPassing++
				break
			}
		}
	}
	out.Estate.RetiredExcluded = retired
	out.Estate.Source = "devices"
	out.Estate.Freshness = CEFreshness{GeneratedAt: now, ObservedAt: newest}
	return out, nil
}

// fetchCEDevices is the base query: every device on an enabled platform,
// bucketed exactly as fetchOverviewDeviceBuckets does, retired devices
// counted and excluded.
func fetchCEDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, sw platformSwitches) (time.Time, []ceDeviceRow, int, error) {
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return now, nil, 0, fmt.Errorf("ce readiness clock: %w", err)
	}
	now = now.UTC()
	rows, err := pool.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen, r.retired,
		       CASE WHEN d.last_seen IS NULL OR d.last_seen > $2::timestamptz THEN 'unknown'
		            WHEN d.last_seen > $2::timestamptz - ($3::bigint * interval '1 second') THEN 'active'
		            WHEN d.last_seen >= $2::timestamptz - ($4::bigint * interval '1 second') THEN 'stale'
		            ELSE 'silent' END,
		       EXISTS (SELECT 1 FROM cve_match_queue q WHERE q.kind = 'observation' AND q.device_id = d.id),
		       (SELECT MAX(a.last_matched_at) FROM cve_match_assessments a WHERE a.device_id = d.id),
		       dou.reported_at
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		LEFT JOIN device_os_update dou ON dou.device_id = d.id
		WHERE d.tenant_id = $1::uuid
		  AND `+enabledOSFilter(sw)+`
		ORDER BY COALESCE(d.hostname, ''), d.id
	`, tenantID, now, int64(OverviewActiveWithin/time.Second), int64(OverviewSilentAfter/time.Second))
	if err != nil {
		return now, nil, 0, fmt.Errorf("ce readiness devices: %w", err)
	}
	defer rows.Close()
	var out []ceDeviceRow
	retired := 0
	for rows.Next() {
		d := &CEDevice{StateReasons: []string{}, Items: []CEItem{}, Controls: []CEControl{}}
		var r ceDeviceRow
		var isRetired bool
		var osReported *time.Time
		if err := rows.Scan(&d.DeviceID, &d.Hostname, &r.os, &r.lastSeen, &isRetired, &d.Reporting.Bucket,
			&r.matchPending, &r.lastMatched, &osReported); err != nil {
			return now, nil, 0, fmt.Errorf("scan ce readiness device: %w", err)
		}
		if isRetired {
			retired++
			continue
		}
		r.lastSeen, r.lastMatched = utcPtr(r.lastSeen), utcPtr(r.lastMatched)
		d.Platform = cePlatform(r.os)
		d.Reporting.Source = "devices.last_seen"
		d.Reporting.ObservedAt = r.lastSeen
		// OS update posture is not version-level evidence until
		// PAT-2133/PAT-2191, so it is unknown on every device, never passing.
		d.OSUpdateEvidence = CEEvidence{State: CEEvidenceUnknown, Reason: ceReason(CardReasonVersionEvidence),
			Source: "device_os_update", ObservedAt: utcPtr(osReported)}
		r.dev = d
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return now, nil, 0, fmt.Errorf("iterate ce readiness devices: %w", err)
	}
	return now, out, retired, nil
}

func cePlatform(os string) string {
	switch os {
	case "macOS":
		return "macos"
	case "Windows":
		return "windows"
	case "":
		return "unknown"
	}
	return strings.ToLower(os)
}

// fetchCEItems loads every confirmed critical or high finding whose advisory
// is more than 14 days old, using fetchPortalCVEAttention's confirmation
// rule: a CVE counts only when no in-scope finding for it in the tenant is
// version_unverified (weakest signal wins), and low-tier Homebrew rows take
// no part in that vote. A confirmed critical or high finding with no
// advisory date cannot be dated, so it marks the device's CVE evidence
// unknown instead of inventing a due date.
func fetchCEItems(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time, byID map[string]*ceDeviceRow) error {
	rows, err := pool.Query(ctx, `
		WITH scoped AS (
			SELECT f.device_id, f.cve_id, f.app_name, f.app_version, f.fixed_version, f.last_seen_at,
			       f.match_confidence, LOWER(COALESCE(e.severity, '')) AS severity, e.published_at
			FROM device_cve_findings f
			JOIN cve_feed_entries e ON e.cve_id = f.cve_id
			JOIN devices d          ON d.id     = f.device_id
			WHERE d.tenant_id = $1::uuid
			  AND NOT (f.package_source IS NOT NULL
			           AND (f.confidence_tier = 'low' OR f.match_confidence = 'version_unverified'))
		), confirmed AS (
			SELECT cve_id FROM scoped GROUP BY cve_id
			HAVING NOT BOOL_OR(match_confidence = 'version_unverified' OR match_confidence IS NULL)
		)
		SELECT s.device_id::text, s.cve_id, s.severity, s.app_name, s.app_version, s.fixed_version,
		       s.published_at, s.last_seen_at
		FROM scoped s JOIN confirmed c ON c.cve_id = s.cve_id
		WHERE s.severity IN ('critical', 'high')
		  AND (s.published_at IS NULL OR s.published_at < $2::timestamptz - ($3::bigint * interval '1 second'))
		ORDER BY s.device_id, s.published_at, s.cve_id, s.app_name
	`, tenantID, now, int64(CEUpdateDueAfter/time.Second))
	if err != nil {
		if isUndefinedTable(err) {
			return nil
		}
		return fmt.Errorf("ce readiness findings: %w", err)
	}
	defer rows.Close()
	var cves []string
	for rows.Next() {
		var deviceID, fixed string
		var it CEItem
		var published *time.Time
		var lastSeen time.Time
		if err := rows.Scan(&deviceID, &it.CVEID, &it.Severity, &it.Product, &it.InstalledVersion, &fixed,
			&published, &lastSeen); err != nil {
			return fmt.Errorf("scan ce readiness finding: %w", err)
		}
		r, ok := byID[deviceID]
		if !ok {
			continue // retired or on a disabled platform
		}
		if published == nil {
			r.undated = true
			continue
		}
		it.Kind = "cve"
		if fixed != "" {
			it.FixedVersion = &fixed
		}
		it.PublishedAt = published.UTC()
		it.DueBasis = CEDueBasis
		it.DueAt = it.PublishedAt.Add(CEUpdateDueAfter)
		it.AgeDays = int(now.Sub(it.PublishedAt) / (24 * time.Hour))
		it.DaysOverdue = it.AgeDays - int(CEUpdateDueAfter/(24*time.Hour))
		it.Source = "device_cve_findings"
		ls := lastSeen.UTC()
		it.ObservedAt = &ls
		r.dev.Items = append(r.dev.Items, it)
		cves = append(cves, it.CVEID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate ce readiness findings: %w", err)
	}
	kev := fetchCEKEV(ctx, pool, cves, now)
	for _, r := range byID {
		for i := range r.dev.Items {
			r.dev.Items[i].KEV = kev(r.dev.Items[i].CVEID)
		}
	}
	return nil
}

// fetchCEKEV reads the CISA KEV snapshot in one statement (so source state
// and matches agree) and returns a lookup. It applies the exploitation
// package's freshness rule: a missing, failed or stale catalogue is
// unknown, never not_listed.
func fetchCEKEV(ctx context.Context, pool *pgxpool.Pool, cves []string, now time.Time) func(string) CEKEV {
	unknown := func(reason string) func(string) CEKEV {
		return func(string) CEKEV {
			return CEKEV{State: CEKEVUnknown, Source: exploitation.SourceCISAKEV, Reason: ceReason(reason)}
		}
	}
	if len(cves) == 0 {
		return unknown(exploitation.UnavailableSourceMissing)
	}
	var status string
	var fetched *time.Time
	var listed []string
	err := pool.QueryRow(ctx, `
		SELECT s.status, s.fetched_at,
		       ARRAY(SELECT e.cve_id FROM cve_exploitation_evidence e
		             WHERE e.source = s.source AND e.cve_id = ANY($1::text[]) AND e.fetched_at = s.fetched_at)
		FROM cve_exploitation_source_state s
		WHERE s.source = $2
	`, cves, exploitation.SourceCISAKEV).Scan(&status, &fetched, &listed)
	switch {
	case errors.Is(err, pgx.ErrNoRows) || isUndefinedTable(err):
		return unknown(exploitation.UnavailableSourceMissing)
	case err != nil:
		slog.Warn("ce readiness: kev read failed", "err", err)
		return unknown(CardReasonQueryFailed)
	case status != "succeeded" || fetched == nil:
		return unknown(exploitation.UnavailableSourceFailed)
	case now.Sub(fetched.UTC()) > exploitation.SourceFreshFor:
		return unknown(exploitation.UnavailableSourceStale)
	}
	at := fetched.UTC()
	set := make(map[string]bool, len(listed))
	for _, id := range listed {
		set[strings.ToUpper(id)] = true
	}
	return func(cve string) CEKEV {
		k := CEKEV{State: CEKEVNotListed, Source: exploitation.SourceCISAKEV, FetchedAt: &at}
		if set[strings.ToUpper(cve)] {
			k.State = CEKEVListed
		}
		return k
	}
}

type ceEval struct {
	status       string
	undetermined bool
	at           time.Time
}

// fetchCEEvaluations returns the latest evaluation of every evidencing rule
// per device, keyed device id then rule key.
func fetchCEEvaluations(ctx context.Context, pool *pgxpool.Pool, tenantID string) (map[string]map[string]ceEval, error) {
	var keys []string
	for _, defs := range ceControlsByOS {
		for _, d := range defs {
			keys = append(keys, d.ruleKey)
		}
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (e.device_id, r.rule_key)
		       e.device_id::text, r.rule_key, e.status, e.observed_value IS NULL, e.evaluated_at
		FROM compliance_evaluations e
		JOIN compliance_rules r ON r.id = e.rule_id
		JOIN devices d          ON d.id = e.device_id
		WHERE d.tenant_id = $1::uuid AND r.rule_key = ANY($2::text[])
		ORDER BY e.device_id, r.rule_key, e.evaluated_at DESC, e.id DESC
	`, tenantID, keys)
	if err != nil {
		return nil, fmt.Errorf("ce readiness evaluations: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]ceEval{}
	for rows.Next() {
		var deviceID, key string
		var ev ceEval
		if err := rows.Scan(&deviceID, &key, &ev.status, &ev.undetermined, &ev.at); err != nil {
			return nil, fmt.Errorf("scan ce readiness evaluation: %w", err)
		}
		ev.at = ev.at.UTC()
		if out[deviceID] == nil {
			out[deviceID] = map[string]ceEval{}
		}
		out[deviceID][key] = ev
	}
	return out, rows.Err()
}

// ceDeviceControls maps evaluations onto the device's controls. Only a
// passing evaluation (or recognised EDR) is evidenced_ok; a failure with an
// observed value is not_passing; an undetermined failure (no observed value,
// PAT-1762), an error, not_applicable or no evaluation is not_evidenced.
func ceDeviceControls(r *ceDeviceRow, evals map[string]map[string]ceEval, evalErr error, edr map[string]EDRState, edrErr error) []CEControl {
	defs, ok := ceControlsByOS[r.os]
	if !ok {
		return []CEControl{}
	}
	out := make([]CEControl, 0, len(defs)+1)
	for _, def := range defs {
		key := def.ruleKey
		c := CEControl{Control: def.control, Category: def.category, Source: "compliance_evaluations", RuleKey: &key,
			State: CEControlNotEvidenced}
		ev, found := evals[r.dev.DeviceID][def.ruleKey]
		switch {
		case evalErr != nil:
			c.Reason = ceReason(CardReasonQueryFailed)
		case !found:
			c.Reason = ceReason(CEReasonNoEvaluation)
		default:
			at := ev.at
			c.ObservedAt = &at
			switch {
			case ev.status == "pass":
				c.State = CEControlEvidencedOK
			case ev.status == "fail" && ev.undetermined:
				c.Reason = ceReason(CEReasonUndetermined)
			case ev.status == "fail":
				c.State, c.Reason = CEControlNotPassing, ceReason(CEReasonEvaluationFailed)
			case ev.status == "not_applicable":
				c.Reason = ceReason(CEReasonNotApplicable)
			default:
				c.Reason = ceReason(CEReasonEvaluationError)
			}
		}
		out = append(out, c)
	}
	// EDR coverage (PAT-2226): recognised EDR is malware protection
	// evidence; unrecognised or absent tools prove nothing either way.
	c := CEControl{Control: "edr_coverage", Category: CECategoryMalware, Source: "devices.security_inventory",
		State: CEControlNotEvidenced}
	switch {
	case edrErr != nil:
		c.Reason = ceReason(CardReasonQueryFailed)
	case edr[r.dev.DeviceID] == EDRStateCovered:
		c.State, c.ObservedAt = CEControlEvidencedOK, r.lastSeen
	case edr[r.dev.DeviceID] == EDRStateUnrecognised:
		c.Reason, c.ObservedAt = ceReason(CEReasonEDRUnrecognised), r.lastSeen
	default:
		c.Reason = ceReason(CEReasonNoEDREvidence)
	}
	return append(out, c)
}

// ceDeviceCVEEvidence: a device's CVE evidence is unknown while the estate
// has no completed full match, while it has observations still queued for
// matching, or when a confirmed critical or high finding has no advisory
// date.
func ceDeviceCVEEvidence(matching CEEvidence, r *ceDeviceRow, lastFull *time.Time) CEEvidence {
	e := CEEvidence{State: CEEvidenceEvidenced, Source: "device_cve_findings", ObservedAt: r.lastMatched}
	if e.ObservedAt == nil {
		e.ObservedAt = lastFull
	}
	switch {
	case matching.State != CEEvidenceEvidenced:
		e.State, e.Reason = CEEvidenceUnknown, matching.Reason
	case r.matchPending:
		e.State, e.Reason = CEEvidenceUnknown, ceReason(CEReasonMatchPending)
	case r.undated:
		e.State, e.Reason = CEEvidenceUnknown, ceReason(CEReasonAdvisoryDateUnknown)
	}
	return e
}

// ceDeviceState: positive evidence of an outstanding item or failing
// control is not_passing whatever the device's freshness. Otherwise any gap
// (not reporting within 24 hours, CVE evidence unknown) is unknown. Only an
// active device with complete CVE evidence and nothing outstanding is
// no_outstanding_items_evidenced. OS update evidence, unknown everywhere
// until PAT-2133/PAT-2191, is reported but does not decide the state.
func ceDeviceState(d *CEDevice) {
	failing := false
	for _, c := range d.Controls {
		if c.State == CEControlNotPassing {
			failing = true
		}
	}
	var gaps []string
	switch d.Reporting.Bucket {
	case "stale":
		gaps = append(gaps, CEReasonDeviceStale)
	case "silent":
		gaps = append(gaps, CEReasonDeviceSilent)
	case "unknown":
		gaps = append(gaps, CEReasonDeviceNoReportTime)
	}
	if d.CVEEvidence.State != CEEvidenceEvidenced && d.CVEEvidence.Reason != nil {
		gaps = append(gaps, *d.CVEEvidence.Reason)
	}
	reasons := []string{}
	if len(d.Items) > 0 {
		reasons = append(reasons, CEReasonOutstandingItems)
	}
	if failing {
		reasons = append(reasons, CEReasonControlNotPassing)
	}
	switch {
	case len(reasons) > 0:
		d.State = CEDeviceNotPassing
	case len(gaps) > 0:
		d.State = CEDeviceUnknown
	default:
		d.State = CEDeviceNoItemsFound
	}
	d.StateReasons = append(reasons, gaps...)
	sort.SliceStable(d.Items, func(i, j int) bool { return d.Items[i].PublishedAt.Before(d.Items[j].PublishedAt) })
}
