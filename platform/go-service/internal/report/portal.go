// Portal data layer (PAT-693). Customer-facing, tenant-scoped, read-only
// views built ON TOP of the existing admin query logic (PAT-340):
// FetchExecutiveSummary and FetchTenantDevices do the heavy lifting; this
// file only adds the portal-specific supplements (CIS trend, per-device
// encryption/patch flags, CVE aggregation) that no admin path computes.
//
// Every function takes tenantID from the caller — on the portal surface that
// is ALWAYS the portal_users-resolved tenant, never client input.
package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/exploitation"
)

// PortalOverview is the tenant-wide posture summary for GET /v1/portal/overview.
type PortalOverview struct {
	TenantName          string
	GeneratedAt         time.Time
	DevicesTotal        int
	DevicesReporting24h int
	// OldestSuccessfulIngest is the least-recently-heard-from device still
	// counted in DevicesTotal - nil when the tenant has zero devices.
	// "Absence requires authority" (root AGENTS.md): this is the honesty
	// signal that DevicesTotal alone can't provide - a large, stale count
	// of "known" devices is a weaker coverage claim than a fresh one.
	OldestSuccessfulIngest *time.Time
	// DevicesRetired (PAT-2135) counts devices the customer has retired.
	// They stay in DevicesTotal, and OldestSuccessfulIngest ignores them: a
	// retired device that has gone quiet is the customer's decision, not a
	// coverage gap.
	DevicesRetired int
	// DevicesDegraded is the count of devices with at least one open row
	// in device_agent_health (the agent's own admitted collection faults -
	// PAT-1064, internal-only until this ticket). Zero for the common case.
	DevicesDegraded int
	CISScoreCurrent float64
	CISTrend        []PortalTrendPoint
	FindingsOpen    PortalSeverityCounts
	PatchStatus     PortalPatchStatus
	// CVEAttention is the confirmed critical/high CVE-exposure summary
	// (PAT-1953). Deliberately a separate field from FindingsOpen: that one
	// buckets CIS/compliance-control failures, this one buckets
	// device_cve_findings rows — the ticket's own requirement to "keep CIS
	// and CVE counts and resolution paths separate". See
	// fetchPortalCVEAttention for the confirmed-match and severity rules.
	CVEAttention PortalCVEAttention
}

// PortalTrendPoint is one day's fleet-average CIS score.
type PortalTrendPoint struct {
	Date  string  `json:"date"` // YYYY-MM-DD
	Score float64 `json:"score"`
}

// PortalSeverityCounts buckets open (failing) compliance findings by severity.
type PortalSeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// PortalCVEAttention is the critical/high confirmed-CVE risk summary for
// GET /v1/portal/overview (PAT-1953). It counts DISTINCT CVEs affecting the
// tenant's estate, not per-device observations — a CVE on 50 devices counts
// once, matching how the ticket frames "critical/high CVE risk" rather than
// "critical/high CVE observations".
//
// Available distinguishes "we checked and there is genuinely nothing to
// report" from "we could not check" (e.g. the CVE matcher tables are not
// migrated yet on a fresh install, or the underlying query failed).
// "Absence requires authority" (root AGENTS.md): a customer must never be
// told "you have zero critical CVEs" when the true answer is "unknown yet".
// Critical and High are meaningless zero values whenever Available is
// false; callers must check Available before reading them. This mirrors how
// DevicesDegraded/OldestSuccessfulIngest already separate "no evidence" from
// "checked, none found" elsewhere on this same response, except those two
// fields use a true zero / nil pointer because their own degrade case is a
// genuine zero — CVE attention needs an explicit flag because zero devices
// degraded IS the correct steady state, but zero critical CVEs during an
// aggregation failure is not.
type PortalCVEAttention struct {
	Available bool `json:"available"`
	Critical  int  `json:"critical"`
	High      int  `json:"high"`
}

// PortalPatchStatus buckets devices by patch posture. Failed is 0 until the
// platform records patch-failure telemetry (documented degradation).
//
// Unknown (PAT-1805) counts devices no collector has ever reported an update
// state for — every Windows device today, since pending_updates is populated
// only by the macOS collector. It is deliberately separate from UpToDate:
// "no evidence" is not the same claim as "checked and clean".
type PortalPatchStatus struct {
	UpToDate int `json:"up_to_date"`
	Pending  int `json:"pending"`
	Failed   int `json:"failed"`
	Unknown  int `json:"unknown"`
}

// portalTrendDays is the CIS-trend window. 30 days matches the monthly
// collection cadence the platform recommends.
const portalTrendDays = 30

// FetchPortalOverview builds the portal overview by reusing
// FetchExecutiveSummary (estate, compliance, patching aggregates) and adding
// the daily CIS trend.
func FetchPortalOverview(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalOverview, error) {
	s, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		return PortalOverview{}, err
	}

	ov := PortalOverview{
		TenantName:          s.Tenant,
		GeneratedAt:         s.GeneratedAt,
		DevicesTotal:        s.Estate.TotalDevices,
		DevicesReporting24h: s.Estate.ActiveLast24h,
		CISScoreCurrent:     s.Compliance.OverallPct,
		FindingsOpen: PortalSeverityCounts{
			Critical: s.Compliance.CriticalFails,
			High:     s.Compliance.HighFails,
			Medium:   s.Compliance.MediumFails,
			Low:      s.Compliance.LowFails,
		},
		PatchStatus: PortalPatchStatus{
			UpToDate: s.Patching.DevicesUpToDate,
			Pending:  s.Patching.DevicesPendingUpdates,
			Failed:   0, // no patch-failure telemetry yet — degrade to 0
			Unknown:  s.Patching.DevicesUpdateStateUnknown,
		},
	}

	trend, err := fetchPortalTrend(ctx, pool, tenantID)
	if err != nil {
		return PortalOverview{}, err
	}
	ov.CISTrend = trend

	oldestIngest, devicesDegraded, devicesRetired, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		return PortalOverview{}, err
	}
	ov.OldestSuccessfulIngest = oldestIngest
	ov.DevicesDegraded = devicesDegraded
	ov.DevicesRetired = devicesRetired

	cveAttention, err := fetchPortalCVEAttention(ctx, pool, tenantID)
	if err != nil {
		return PortalOverview{}, err
	}
	ov.CVEAttention = cveAttention

	return ov, nil
}

// fetchPortalCVEAttention counts distinct critical/high CVEs with a
// confirmed match currently affecting the tenant's estate (PAT-1953).
//
// Confidence rule — "confirmed" per CVE, not per row: a CVE can be backed by
// findings on several devices, and those findings do not always share one
// match_confidence. This reuses the exact "weakest signal wins" aggregation
// PAT-1831 already established for cross-device CVE confidence
// (internal/handlers/cve.go's agg CTE): if ANY device backing this CVE has
// an unverified (or NULL) match, the whole CVE is unverified — never
// averaged or majority-voted into "confirmed" by the other devices. This is
// the ticket's explicit requirement, "do not count unknown/unsupported
// matches as confirmed exposure", applied at the CVE granularity this field
// reports at.
//
// device_cve_findings.match_confidence takes three values, not two:
// "version_confirmed" (NVD version-range match), "version_vendor_confirmed"
// (oscve.MatchConfidenceVendorConfirmed — Apple security releases / MSRC,
// PAT-409), and "version_unverified". Only the last is ever treated as
// "not confirmed" anywhere else in this codebase
// (report.confirmedConfidence, handlers.confirmedConfidence, cve.go's own
// CASE) — a literal equality check against "version_confirmed" alone would
// silently exclude vendor-confirmed CVEs, which are stronger evidence, not
// weaker, and would disagree with how /v1/portal/findings and the CVE
// PDF/report already classify confidence. So the SQL below matches on
// "<> 'version_unverified'" (this file's confidence source of truth),
// not on a positive match against "version_confirmed".
//
// Severity rule: only "critical" and "high" (case-insensitive, same
// LOWER(COALESCE(e.severity, ”)) pattern FetchPortalCVEFindingsPage uses)
// count towards attention. Medium/low/absent severity CVEs are excluded.
//
// Freshness rule: no recency filter on last_seen_at. /v1/portal/findings —
// the sibling endpoint this count must reconcile with — applies no
// recency filter either (checked: neither FetchPortalCVEFindings nor
// FetchPortalCVEFindingsPage reference last_seen_at in a WHERE clause), so
// matching that precedent here rather than inventing a new freshness rule.
// A CVE match is derived from currently-installed software at the last
// extraction, not a point-in-time event like a compliance evaluation — the
// matcher itself (patched-cve-sync) is what retires a finding when the
// software is no longer observed or is upgraded past the vulnerable range,
// not a query-side age window on this endpoint.
//
// Degrades to Available=false (never a false "zero") when the CVE matcher
// tables are not migrated yet on a fresh install (isUndefinedTable, same
// pattern as fetchPortalCoverage's device_agent_health degrade and
// FetchPortalCVEFindingsPage's own CVE-table degrade) or when the query
// itself fails.
func fetchPortalCVEAttention(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalCVEAttention, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			LOWER(COALESCE(e.severity, '')) AS severity,
			NOT BOOL_OR(f.match_confidence = 'version_unverified' OR f.match_confidence IS NULL) AS confirmed
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		JOIN devices d          ON d.id     = f.device_id
		WHERE d.tenant_id = $1::uuid
		  -- PAT-2023 review: a low-tier Homebrew row (a HEAD build, a
		  -- letter-suffixed or otherwise uncomparable version) carries no
		  -- version evidence at all. It must not take part in the
		  -- weakest-signal-wins vote, or one HEAD build could pull a
		  -- vendor-confirmed CVE out of attention. It still lists on
		  -- /v1/portal/findings.
		  AND NOT (f.package_source IS NOT NULL
		           AND (f.confidence_tier = 'low' OR f.match_confidence = 'version_unverified'))
		GROUP BY f.cve_id, LOWER(COALESCE(e.severity, ''))
	`, tenantID)
	if err != nil {
		if isUndefinedTable(err) {
			return PortalCVEAttention{}, nil // CVE matcher tables absent — Available stays false, never a false zero
		}
		return PortalCVEAttention{}, fmt.Errorf("portal cve attention: %w", err)
	}
	defer rows.Close()

	att := PortalCVEAttention{Available: true}
	for rows.Next() {
		var severity string
		var confirmed bool
		if err := rows.Scan(&severity, &confirmed); err != nil {
			return PortalCVEAttention{}, fmt.Errorf("scan portal cve attention: %w", err)
		}
		if !confirmed {
			continue
		}
		switch severity {
		case "critical":
			att.Critical++
		case "high":
			att.High++
		}
	}
	if err := rows.Err(); err != nil {
		return PortalCVEAttention{}, fmt.Errorf("iterate portal cve attention: %w", err)
	}
	return att, nil
}

// fetchPortalTrend computes the fleet-average CIS score per day over the
// trend window: latest evaluation per (device, rule, day) → per-device daily
// % → daily fleet average. Days with no evaluations are simply absent.
//
// PAT-1762 review: this query only ever produces a single percentage per day
// (no separate pass/fail/undetermined counts are exposed to callers), and its
// pct expression already counts every status='fail' row — undetermined ones
// (observed_value IS NULL) included — as a fail in the denominator without
// ever counting it in the pass numerator. That already matches "undetermined
// stays in the denominator so missing evidence never raises the score" with
// no code change needed; there is no "failing count" surfaced here for
// undetermined evidence to be wrongly folded into. See
// fetchComplianceStats/fetchTopFailingControls/fetchWorstDevices in
// executive.go and FetchTenantDevices in admin.go for the sibling queries
// that DO need the observed_value split, because they expose fail counts.
func fetchPortalTrend(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]PortalTrendPoint, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return nil, err
	}
	osFilter := enabledOSFilter(sw)

	rows, err := pool.Query(ctx, `
		WITH daily AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id, date_trunc('day', e.evaluated_at))
				e.device_id,
				date_trunc('day', e.evaluated_at)::date AS day,
				e.status
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1::uuid
			  AND e.evaluated_at > now() - make_interval(days => $2)
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, date_trunc('day', e.evaluated_at), e.evaluated_at DESC
		),
		device_day AS (
			SELECT day, device_id,
				COUNT(*) FILTER (WHERE status = 'pass')::float
				  / NULLIF(COUNT(*) FILTER (WHERE status IN ('pass','fail','error')), 0)::float * 100.0 AS pct
			FROM daily
			GROUP BY day, device_id
		)
		SELECT day::text, AVG(pct)::float
		FROM device_day
		WHERE pct IS NOT NULL
		GROUP BY day
		ORDER BY day
	`, tenantID, portalTrendDays)
	if err != nil {
		return nil, fmt.Errorf("portal trend: %w", err)
	}
	defer rows.Close()

	var trend []PortalTrendPoint
	for rows.Next() {
		var p PortalTrendPoint
		if err := rows.Scan(&p.Date, &p.Score); err != nil {
			return nil, fmt.Errorf("scan trend point: %w", err)
		}
		trend = append(trend, p)
	}
	return trend, rows.Err()
}

// fetchPortalCoverage computes the two coverage-honesty fields for the
// overview: the oldest device still counted as known, and how many devices
// have an admitted collection fault. Scoped by the same enabled-OS filter
// as devices_total/devices_reporting_24h so a customer with (say) Windows
// evaluation disabled doesn't see coverage numbers that include devices
// devices_total itself excludes.
func fetchPortalCoverage(ctx context.Context, pool *pgxpool.Pool, tenantID string) (oldestIngest *time.Time, devicesDegraded, devicesRetired int, err error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return nil, 0, 0, err
	}
	osFilter := enabledOSFilter(sw)

	// PAT-2135: a retired device is counted separately and does not set the
	// oldest ingest.
	err = pool.QueryRow(ctx, `
		SELECT MIN(last_seen) FILTER (WHERE `+osFilter+` AND NOT r.retired),
		       COUNT(*) FILTER (WHERE `+osFilter+` AND r.retired)::int
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
	`, tenantID).Scan(&oldestIngest, &devicesRetired)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("portal coverage oldest ingest: %w", err)
	}

	devicesDegraded, available, err := fetchDegradedDevices(ctx, pool, tenantID, osFilter)
	if err != nil {
		return nil, 0, 0, err
	}
	if !available {
		devicesDegraded = 0 // device_agent_health not migrated on this install yet - degrade, don't 500
	}

	return oldestIngest, devicesDegraded, devicesRetired, nil
}

// fetchDegradedDevices counts the tenant's devices with at least one open
// device_agent_health row. available is false when that table is not
// migrated, so a caller that must not present a false zero (the Overview
// cards, PAT-2207) can say unavailable instead; the legacy overview field
// keeps its established degrade-to-zero.
func fetchDegradedDevices(ctx context.Context, pool *pgxpool.Pool, tenantID, osFilter string) (n int, available bool, err error) {
	err = pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT dah.device_id)::int
		FROM device_agent_health dah
		JOIN devices d ON d.id = dah.device_id
		WHERE d.tenant_id = $1::uuid
		  AND `+osFilter+`
	`, tenantID).Scan(&n)
	if err != nil {
		if isUndefinedTable(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("portal coverage degraded devices: %w", err)
	}
	return n, true, nil
}

// PortalDeviceRow is one roster row for GET /v1/portal/devices — the admin
// TenantDeviceRow plus the two portal-only flags.
type PortalDeviceRow struct {
	TenantDeviceRow
	EncryptionOK *bool // nil = not evaluated / not applicable
	// PatchPending is nil when no collector has reported a usable update
	// state for this device (PAT-1805), the same "unknown, not compliant"
	// convention EncryptionOK already uses above, rather than reading
	// missing evidence as "up to date". An explicit device_os_update verdict
	// wins over legacy pending_updates, including unknown and stale verdicts
	// (PAT-2338). Only without an OS row does the legacy array decide.
	PatchPending *bool
	// Evidence is section-scoped provenance from the latest immutable inventory
	// payload linked to this device. It confers no authority on the roster's
	// derived findings or on any domain not explicitly named in Sections.
	Evidence DeviceEvidence
	// Retirement (PAT-2135) is nil unless the customer has retired the
	// device. A retired device stays on the roster.
	Retirement *deviceretirement.Retirement
	// DeviceClass and OSCaption (PAT-2324) are the portal's server-versus-
	// workstation figures. Both come from derivePortalDeviceClass, the one
	// derivation the device page's PortalDeviceSummary also uses.
	DeviceClass string
	OSCaption   *string
}

// The customer-facing device_class vocabulary (PAT-2324). It is narrower than
// devices.device_class, which also stores domain_controller; a domain
// controller is a Windows Server, so it is reported as server.
const (
	PortalDeviceClassServer      = "server"
	PortalDeviceClassWorkstation = "workstation"
	PortalDeviceClassUnknown     = "unknown"
)

// derivePortalDeviceClass turns a device's stored class, OS family and stored
// caption into the portal's device_class and os_caption (PAT-2324). The
// roster and the device page both call it, so they cannot disagree.
//
// device_class is always exactly one of PortalDeviceClassServer,
// PortalDeviceClassWorkstation or PortalDeviceClassUnknown. The stored value is
// trimmed and compared exactly. A stored domain_controller reads as server,
// because a domain controller is a Windows Server. Any other stored value reads
// as unknown rather than being passed through.
//
// The one derivation here is by OS family, not a collected fact: a macOS
// device whose stored class is unknown or empty is reported as workstation,
// because macOS has no server edition and the Mac agent sends no class. A
// Windows device stored as unknown stays unknown, because Windows has both
// editions and an absent class must not be read as either (absence requires
// authority). A stored server or workstation is never overridden.
//
// os_caption is the stored caption trimmed, or nil when it is empty. It is
// never derived.
func derivePortalDeviceClass(d TenantDeviceRow) (class string, caption *string) {
	switch strings.TrimSpace(d.StoredDeviceClass) {
	case PortalDeviceClassServer, "domain_controller":
		class = PortalDeviceClassServer
	case PortalDeviceClassWorkstation:
		class = PortalDeviceClassWorkstation
	case "", PortalDeviceClassUnknown:
		class = PortalDeviceClassUnknown
		if strings.EqualFold(strings.TrimSpace(d.OS), "macOS") {
			class = PortalDeviceClassWorkstation
		}
	default:
		class = PortalDeviceClassUnknown
	}
	if c := strings.TrimSpace(d.StoredOSCaption); c != "" {
		caption = &c
	}
	return class, caption
}

const portalEvidenceStaleAfter = 7 * 24 * time.Hour

const (
	EvidenceSectionComplete    = "complete"
	EvidenceSectionPartial     = "partial"
	EvidenceSectionUnavailable = "unavailable"

	EvidenceAuthoritySectionScoped = "section_scoped"
	EvidenceAuthorityPresenceOnly  = "presence_only"
	EvidenceAuthorityUnavailable   = "unavailable"
	EvidenceAuthorityUnknown       = "unknown"
	EvidenceAuthorityStale         = "stale"

	EvidenceFreshnessFresh   = "fresh"
	EvidenceFreshnessStale   = "stale"
	EvidenceFreshnessUnknown = "unknown"
)

// DeviceEvidence is the additive evidence contract for one portal device
// roster row. observed_at is endpoint-reported collected_at, while
// received_at is the server-side timestamp of the same immutable raw_payloads
// record. The two are intentionally distinct: an endpoint may collect before
// it can upload.
//
// Sections contains only collection-status fields explicitly present in that
// same raw payload. It deliberately does not use devices.collection_status:
// that column is a merged latest-known snapshot whose keys can come from
// different payloads, so it cannot truthfully describe one observation.
//
// Authority is never device-wide. section_scoped means only that at least one
// named section is fresh and complete; consumers must inspect Sections and may
// make an absence claim only for a named section whose value is complete.
// Unlisted domains, including apps, updates, CIS and extensions, gain no
// authority from this envelope.
type DeviceEvidence struct {
	ObservedAt *time.Time             `json:"observed_at"`
	ReceivedAt *time.Time             `json:"received_at"`
	Sections   DeviceEvidenceSections `json:"sections"`
	Authority  string                 `json:"authority"`
	Freshness  string                 `json:"freshness"`
}

// DeviceEvidenceSections mirrors only the collection-status domains the
// current agent contract names. Pointer fields plus omitempty keep an omitted
// wire status omitted here rather than manufacturing "complete" or "unknown".
type DeviceEvidenceSections struct {
	Certificates   *string                       `json:"certificates,omitempty"`
	HardwareHealth *DeviceEvidenceHardwareHealth `json:"hardware_health,omitempty"`
}

type DeviceEvidenceHardwareHealth struct {
	Battery *string `json:"battery,omitempty"`
	Storage *string `json:"storage,omitempty"`
	Disks   *string `json:"disks,omitempty"`
}

// PortalDevicesResult is the paged roster.
type PortalDevicesResult struct {
	Total   int
	Devices []PortalDeviceRow
}

// FetchPortalDevices reuses FetchTenantDevices for the roster + compliance
// summaries, then decorates each row with encryption and patch-pending flags
// from one supplemental query.
func FetchPortalDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (PortalDevicesResult, error) {
	now := time.Now().UTC()
	base, err := FetchTenantDevices(ctx, pool, tenantID, limit, offset)
	if err != nil {
		return PortalDevicesResult{}, err
	}

	ids := make([]string, 0, len(base.Devices))
	for _, d := range base.Devices {
		ids = append(ids, d.ID)
	}
	flagsByID, err := fetchPortalDeviceFlags(ctx, pool, tenantID, ids, now)
	if err != nil {
		return PortalDevicesResult{}, err
	}

	evidenceByID, err := fetchPortalDeviceEvidence(ctx, pool, tenantID, base.Devices, now)
	if err != nil {
		return PortalDevicesResult{}, err
	}

	retirements, err := deviceretirement.Fetch(ctx, pool, tenantID, ids)
	if err != nil {
		return PortalDevicesResult{}, err
	}

	res := PortalDevicesResult{Total: base.Total}
	for _, d := range base.Devices {
		row := PortalDeviceRow{TenantDeviceRow: d}
		if f, ok := flagsByID[d.ID]; ok {
			row.EncryptionOK = f.encryptionOK
			row.PatchPending = f.patchPending
		}
		if evidence, ok := evidenceByID[d.ID]; ok {
			row.Evidence = evidence
		} else {
			row.Evidence = unknownDeviceEvidence()
		}
		row.Retirement = deviceretirement.Of(retirements, d.ID)
		row.DeviceClass, row.OSCaption = derivePortalDeviceClass(d)
		res.Devices = append(res.Devices, row)
	}
	return res, nil
}

// PortalDeviceSummary is the figures a device carries on both the customer
// portal's roster (GET /v1/portal/devices) and its device page
// (GET /v1/portal/devices/{id}): open findings, disk encryption, update state
// (PAT-2294) and device class with OS caption (PAT-2324). It is built by the
// same queries and the same derivations as the roster row, so the two
// endpoints cannot disagree.
type PortalDeviceSummary struct {
	FindingsOpen int
	EncryptionOK *bool // nil = not evaluated, undetermined or not applicable
	PatchPending *bool // nil = update state not reported, unrecognised or stale
	// DeviceClass is server, workstation or unknown; OSCaption is nil when
	// the device has reported none. See derivePortalDeviceClass.
	DeviceClass string
	OSCaption   *string
}

// FetchPortalDeviceSummary returns the roster's figures for one device of the
// tenant. The tenant is always the caller's verified one; deviceID only
// narrows within it, so a device outside the tenant is ErrDeviceNotFound
// exactly as if it did not exist. deviceID must be a valid UUID.
func FetchPortalDeviceSummary(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (PortalDeviceSummary, error) {
	now := time.Now().UTC()
	base, err := fetchTenantDevices(ctx, pool, tenantID, 1, 0, deviceID)
	if err != nil {
		return PortalDeviceSummary{}, err
	}
	if len(base.Devices) == 0 {
		return PortalDeviceSummary{}, ErrDeviceNotFound
	}
	flagsByID, err := fetchPortalDeviceFlags(ctx, pool, tenantID, []string{deviceID}, now)
	if err != nil {
		return PortalDeviceSummary{}, err
	}
	f := flagsByID[deviceID]
	class, caption := derivePortalDeviceClass(base.Devices[0])
	return PortalDeviceSummary{
		FindingsOpen: base.Devices[0].FindingsOpen(),
		EncryptionOK: f.encryptionOK,
		PatchPending: f.patchPending,
		DeviceClass:  class,
		OSCaption:    caption,
	}, nil
}

type portalDeviceFlags struct {
	encryptionOK *bool
	patchPending *bool
}

// fetchPortalDeviceFlags derives encryption_ok and patch_pending for the
// given tenant devices. Both portal endpoints call it, which is what keeps
// their answers identical. encryption_ok is read from FetchEncryptionStates,
// the one definition of a device's encryption state that the insurance
// evidence pack and the posture report share (PAT-2496); this function does
// not classify an evaluation itself.
func fetchPortalDeviceFlags(ctx context.Context, pool *pgxpool.Pool, tenantID string, deviceIDs []string, now time.Time) (map[string]portalDeviceFlags, error) {
	flagsByID := map[string]portalDeviceFlags{}
	if len(deviceIDs) == 0 {
		return flagsByID, nil
	}

	states, err := FetchEncryptionStates(ctx, pool, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("portal device flags: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT
			d.id::text,
			CASE
				WHEN d.pending_updates IS NULL THEN NULL
				WHEN jsonb_array_length(d.pending_updates) > 0 THEN true
				ELSE false
			END,
			dou.state,
			dou.checked_at,
			dou.reported_at
		FROM devices d
		LEFT JOIN device_os_update dou ON dou.device_id = d.id
		WHERE d.tenant_id = $1::uuid
		  AND d.id = ANY($2::uuid[])
	`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("portal device flags: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		// PAT-1805: nil (SQL NULL) means no collector has reported an update
		// state for this device — kept distinct from a real false ("checked,
		// nothing pending").
		var pending *bool
		var osState *string
		var osCheckedAt, osReportedAt *time.Time
		if err := rows.Scan(&id, &pending, &osState, &osCheckedAt, &osReportedAt); err != nil {
			return nil, fmt.Errorf("scan device flags: %w", err)
		}
		// PAT-2338: an explicit OS verdict takes precedence over the legacy
		// update list, including when unknown or stale. An empty list cannot
		// turn unavailable OS evidence into a healthy claim.
		if osState != nil {
			pending = osUpdatePatchPending(*osState, osCheckedAt, osReportedAt, now)
		}
		f := portalDeviceFlags{patchPending: pending, encryptionOK: encryptionOKFromState(encryptionStateOf(states, id))}
		flagsByID[id] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device flags: %w", err)
	}
	return flagsByID, nil
}

// osUpdatePatchPending turns a device's stored OS-update verdict
// (device_os_update, PAT-1806) into the roster's tri-state patch_pending
// (PAT-2294). An explicit verdict outranks devices.pending_updates (PAT-2338).
//
// The state vocabulary is the agents' own contract
// (updater contracts/update-status.schema.json), interpreted in one place,
// osUpdateStates in os_update.go, which FetchOSUpdateStatus also reads (PAT-2295):
//
//   - up_to_date -> false.
//   - update_recommended, update_required, deadline_passed and
//     unsupported_hardware -> true: the device is not up to date.
//   - unknown, and any state this server does not recognise -> nil. The agent
//     saying it could not tell is not a claim either way, and a state added
//     by a later agent release must not be read as "pending" or "current"
//     until it is mapped (absence requires authority, root AGENTS.md). The
//     tenant rollup reports the same devices as not reported.
//
// A verdict older than the roster's evidence freshness window
// (portalEvidenceStaleAfter) is nil, so an old answer cannot read as current.
// The verdict is dated by the agent's checked_at, which is what makes an old
// verdict the agent re-uploaded recently read as old. checked_at is capped at
// reported_at, the server's own receipt time, so a wrong agent clock cannot
// keep a verdict fresh; a row from before migration 0147 has no checked_at
// and falls back to reported_at.
func osUpdatePatchPending(state string, checkedAt, reportedAt *time.Time, now time.Time) *bool {
	var verdictAt time.Time
	switch {
	case checkedAt != nil && reportedAt != nil && checkedAt.After(*reportedAt):
		verdictAt = *reportedAt
	case checkedAt != nil:
		verdictAt = *checkedAt
	case reportedAt != nil:
		verdictAt = *reportedAt
	default:
		return nil
	}
	if now.Sub(verdictAt) > portalEvidenceStaleAfter {
		return nil
	}

	var pending bool
	switch classifyOSUpdateState(state) {
	case osUpdateCurrent:
		pending = false
	case osUpdatePending:
		pending = true
	default:
		return nil
	}
	return &pending
}

// FetchPortalDeviceEvidence returns the same additive, section-scoped evidence
// envelope used by the portal roster for one already tenant-scoped device. A
// caller must establish ownership before calling this helper; the query keeps
// tenant_id as a second boundary, so a supplied device ID cannot cross tenants.
func FetchPortalDeviceEvidence(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (DeviceEvidence, error) {
	evidenceByID, err := fetchPortalDeviceEvidence(ctx, pool, tenantID, []TenantDeviceRow{{ID: deviceID}}, time.Now().UTC())
	if err != nil {
		return DeviceEvidence{}, err
	}
	if evidence, ok := evidenceByID[deviceID]; ok {
		return evidence, nil
	}
	return unknownDeviceEvidence(), nil
}

// fetchPortalDeviceEvidence reads the newest immutable payload successfully
// linked to each device. It is intentionally a
// supplemental query rather than a change to FetchTenantDevices so existing
// admin readers and their pagination contract remain untouched.
func fetchPortalDeviceEvidence(ctx context.Context, pool *pgxpool.Pool, tenantID string, devices []TenantDeviceRow, now time.Time) (map[string]DeviceEvidence, error) {
	if len(devices) == 0 {
		return map[string]DeviceEvidence{}, nil
	}

	deviceIDs := make([]string, 0, len(devices))
	for _, device := range devices {
		deviceIDs = append(deviceIDs, device.ID)
	}

	rows, err := pool.Query(ctx, `
		SELECT
			d.id::text,
			payload.received_at,
			jsonb_build_object(
				'collected_at', payload.body->'collected_at',
				'collection_status', payload.body->'collection_status',
				'hardware_health', jsonb_build_object(
					'collection_status', payload.body->'hardware_health'->'collection_status'
				)
			)::text
		FROM devices d
		LEFT JOIN LATERAL (
			SELECT received_at, body
			FROM raw_payloads
			WHERE tenant_id = d.tenant_id
			  AND device_id = d.id
			ORDER BY received_at DESC, id DESC
			LIMIT 1
		) payload ON true
		WHERE d.tenant_id = $1::uuid
		  AND d.id = ANY($2::uuid[])
	`, tenantID, deviceIDs)
	if err != nil {
		if isUndefinedTable(err) {
			return map[string]DeviceEvidence{}, nil
		}
		return nil, fmt.Errorf("portal device evidence: %w", err)
	}
	defer rows.Close()

	result := make(map[string]DeviceEvidence, len(devices))
	for rows.Next() {
		var (
			deviceID   string
			receivedAt *time.Time
			payload    []byte
		)
		if err := rows.Scan(&deviceID, &receivedAt, &payload); err != nil {
			return nil, fmt.Errorf("scan portal device evidence: %w", err)
		}
		result[deviceID] = deriveDeviceEvidence(payload, receivedAt, now)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate portal device evidence: %w", err)
	}
	return result, nil
}

func unknownDeviceEvidence() DeviceEvidence {
	return DeviceEvidence{
		Authority: EvidenceAuthorityUnknown,
		Freshness: EvidenceFreshnessUnknown,
	}
}

// deriveDeviceEvidence is deliberately section-scoped. Missing section keys
// stay absent, malformed status values fail the whole envelope closed, and no
// state from an older payload is consulted.
func deriveDeviceEvidence(payload []byte, receivedAt *time.Time, now time.Time) DeviceEvidence {
	evidence := unknownDeviceEvidence()
	evidence.ReceivedAt = receivedAt
	var raw struct {
		CollectedAt      string          `json:"collected_at"`
		CollectionStatus json.RawMessage `json:"collection_status"`
		HardwareHealth   json.RawMessage `json:"hardware_health"`
	}
	if len(payload) > 0 && json.Unmarshal(payload, &raw) == nil {
		if observedAt, err := time.Parse(time.RFC3339, raw.CollectedAt); err == nil {
			observedAt = observedAt.UTC()
			evidence.ObservedAt = &observedAt
		}
		if sections, ok := evidenceSections(raw.CollectionStatus, raw.HardwareHealth); ok {
			evidence.Sections = sections
		}
	}
	if receivedAt == nil {
		return evidence
	}

	// Freshness is the age of the endpoint observation, not the age of its
	// upload. A payload collected while offline and uploaded today is old
	// evidence with a fresh receipt. Receipt is still required for authority
	// because it is the server-trusted provenance boundary.
	if evidence.ObservedAt != nil {
		if evidence.ObservedAt.After(now) {
			return evidence
		}
		if now.Sub(*evidence.ObservedAt) > portalEvidenceStaleAfter {
			evidence.Freshness = EvidenceFreshnessStale
		} else {
			evidence.Freshness = EvidenceFreshnessFresh
		}
	}
	if evidence.Freshness == EvidenceFreshnessUnknown {
		return evidence
	}

	statuses := evidence.Sections.statuses()
	if len(statuses) == 0 {
		return evidence
	}
	if evidence.Freshness == EvidenceFreshnessStale {
		evidence.Authority = EvidenceAuthorityStale
		return evidence
	}

	hasPartial := false
	for _, status := range statuses {
		switch status {
		case EvidenceSectionComplete:
			evidence.Authority = EvidenceAuthoritySectionScoped
			return evidence
		case EvidenceSectionPartial:
			hasPartial = true
		}
	}
	if hasPartial {
		evidence.Authority = EvidenceAuthorityPresenceOnly
	} else {
		evidence.Authority = EvidenceAuthorityUnavailable
	}
	return evidence
}

func evidenceSections(topRaw, hardwareRaw json.RawMessage) (DeviceEvidenceSections, bool) {
	var sections DeviceEvidenceSections
	if len(topRaw) > 0 && string(topRaw) != "null" {
		var top struct {
			Certificates json.RawMessage `json:"certificates"`
		}
		if err := json.Unmarshal(topRaw, &top); err != nil {
			return DeviceEvidenceSections{}, false
		}
		var ok bool
		if sections.Certificates, ok = evidenceSectionStatus(top.Certificates); !ok {
			return DeviceEvidenceSections{}, false
		}
	}
	if len(hardwareRaw) > 0 && string(hardwareRaw) != "null" {
		var hardware struct {
			CollectionStatus json.RawMessage `json:"collection_status"`
		}
		if err := json.Unmarshal(hardwareRaw, &hardware); err != nil {
			return DeviceEvidenceSections{}, false
		}
		if len(hardware.CollectionStatus) == 0 || string(hardware.CollectionStatus) == "null" {
			return sections, true
		}
		var statuses struct {
			Battery json.RawMessage `json:"battery"`
			Storage json.RawMessage `json:"storage"`
			Disks   json.RawMessage `json:"disks"`
		}
		if err := json.Unmarshal(hardware.CollectionStatus, &statuses); err != nil {
			return DeviceEvidenceSections{}, false
		}
		h := &DeviceEvidenceHardwareHealth{}
		var ok bool
		if h.Battery, ok = evidenceSectionStatus(statuses.Battery); !ok {
			return DeviceEvidenceSections{}, false
		}
		if h.Storage, ok = evidenceSectionStatus(statuses.Storage); !ok {
			return DeviceEvidenceSections{}, false
		}
		if h.Disks, ok = evidenceSectionStatus(statuses.Disks); !ok {
			return DeviceEvidenceSections{}, false
		}
		if h.Battery != nil || h.Storage != nil || h.Disks != nil {
			sections.HardwareHealth = h
		}
	}
	return sections, true
}

func evidenceSectionStatus(raw json.RawMessage) (*string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	var status string
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, false
	}
	switch status {
	case EvidenceSectionComplete, EvidenceSectionPartial, EvidenceSectionUnavailable:
		return &status, true
	default:
		return nil, false
	}
}

func (s DeviceEvidenceSections) statuses() []string {
	statuses := make([]string, 0, 4)
	if s.Certificates != nil {
		statuses = append(statuses, *s.Certificates)
	}
	if s.HardwareHealth != nil {
		for _, status := range []*string{s.HardwareHealth.Battery, s.HardwareHealth.Storage, s.HardwareHealth.Disks} {
			if status != nil {
				statuses = append(statuses, *status)
			}
		}
	}
	return statuses
}

// portalFindingsMaxDevices caps the per-finding device drill-down list
// (PAT-1587), same cap as portalExtensionsMaxDevices in portal_extensions.go
// for consistency - no principled reason to differ.
const portalFindingsMaxDevices = 50

// PortalCVEFindingDevice is one device affected by a finding, for the
// findings drill-down (PAT-1587). Mirrors PortalExtensionDevice in
// portal_extensions.go - same shape, same reason (device_id + hostname is
// all the portal needs to link to /devices/{id}).
type PortalCVEFindingDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

// PortalCVEFinding is one aggregated open CVE finding for
// GET /v1/portal/findings: one row per (CVE, app, version) with the count of
// affected devices — no per-device identifiers at this level.
type PortalCVEFinding struct {
	CVEID    string
	Severity string // lowercased; "" when the feed has no severity
	CVSS     *float64
	App      string
	Version  string
	// MatchConfidence is the raw device_cve_findings.match_confidence value
	// ("version_confirmed", "version_unverified", or "version_vendor_confirmed" —
	// do not treat this as a fixed two-value enum, see internal/report/cve_report.go's
	// confirmedConfidence). DevicesAffected devices agreeing to aggregate under one
	// (cve, app, version) row always share the same matcher-assigned confidence.
	MatchConfidence string
	// FixedVersion is the version that resolves this CVE, "" when unknown.
	// device_cve_findings.fixed_version is TEXT NOT NULL DEFAULT '', never NULL.
	FixedVersion    string
	DevicesAffected int
	// Devices is the first portalFindingsMaxDevices affected devices by
	// hostname, for the drill-down link to /devices/{id}. DevicesTruncated
	// is true when DevicesAffected exceeds that cap.
	//
	// Only FetchPortalCVEFindingsPage (the paginated, portal-facing fetcher)
	// populates these two fields. FetchPortalCVEFindings — the unpaginated
	// fetcher used by PDF report generation — was not touched by PAT-1587
	// and always leaves them zero-valued (nil / false), indistinguishable
	// from "genuinely zero devices". Nothing reads per-finding device lists
	// off that path today; a future caller must not assume otherwise.
	Devices           []PortalCVEFindingDevice
	DevicesTruncated  bool
	FirstSeen         time.Time
	Summary           string
	DescriptionSource string
	// Exploitation is a tri-state, provenance-bearing assessment. Severity is
	// never an input; missing, failed or stale source state is explicit Unknown.
	Exploitation exploitation.Assessment
	// PAT-2023, Homebrew findings only (all nil/empty for applications and
	// the OS). PackageSource is homebrew_formula or homebrew_cask.
	// ConfidenceTier is the weakest across the aggregated devices.
	// InstallReasons is the distinct on_request / dependency / unknown values
	// across them, so a CVE carried only as a dependency is visible as such.
	// Populated by FetchPortalCVEFindingsPage only.
	PackageSource  *string
	ConfidenceTier *string
	InstallReasons []string
	// MappingBasis (PAT-2138) is "auto" when every aggregated device's
	// finding came only from an automatically published CPE mapping, nil
	// otherwise. Populated by FetchPortalCVEFindingsPage only.
	MappingBasis *string
}

// PortalCVEFindingsPage is one bounded page of open CVE findings for
// GET /v1/portal/findings, plus the total row count (across all pages, same
// filter set) needed for the portal's pager.
type PortalCVEFindingsPage struct {
	Total    int
	Findings []PortalCVEFinding
}

// FetchPortalCVEFindingsPage is the paginated counterpart of
// FetchPortalCVEFindings (PAT-1201). Same aggregation and ordering, but
// bounded by LIMIT/OFFSET with the total row count carried back via
// COUNT(*) OVER() — the same convention TenantCVEFindingsHandler and
// FetchTenantDevices already use, so one page never has to run a second
// COUNT query. Degrades gracefully (empty page, zero total) when the CVE
// store tables don't exist yet.
func FetchPortalCVEFindingsPage(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (PortalCVEFindingsPage, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			f.cve_id,
			LOWER(COALESCE(e.severity, '')),
			e.cvss_v3_score,
			f.app_name,
			f.app_version,
			f.match_confidence,
			f.fixed_version,
			COUNT(DISTINCT f.device_id)::int,
			devs.devices,
			COUNT(DISTINCT f.device_id) > $4 AS devices_truncated,
			MIN(f.first_seen_at),
			COALESCE(e.description, ''),
			COALESCE(e.description_source, ''),
			MIN(f.package_source),
			CASE
				WHEN BOOL_OR(f.confidence_tier = 'low') THEN 'low'
				WHEN BOOL_OR(f.confidence_tier = 'medium') THEN 'medium'
				WHEN BOOL_OR(f.confidence_tier = 'high') THEN 'high'
			END,
			ARRAY_REMOVE(ARRAY_AGG(DISTINCT f.install_reason ORDER BY f.install_reason), NULL),
			CASE WHEN BOOL_AND(f.mapping_basis IS NOT DISTINCT FROM 'auto') THEN 'auto' END,
			COUNT(*) OVER()::int
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		JOIN devices d ON d.id = f.device_id
		LEFT JOIN LATERAL (
			SELECT jsonb_agg(jsonb_build_object('device_id', dd.device_id, 'hostname', dd.hostname)
			                 ORDER BY dd.hostname, dd.device_id) AS devices
			FROM (
				SELECT f2.device_id,
				       MIN(COALESCE(d2.hostname, d2.serial, f2.device_id::text)) AS hostname
				FROM device_cve_findings f2
				JOIN devices d2 ON d2.id = f2.device_id
				WHERE d2.tenant_id = $1::uuid
				  AND f2.cve_id = f.cve_id
				  AND f2.app_name = f.app_name
				  AND f2.app_version = f.app_version
				GROUP BY f2.device_id
				ORDER BY MIN(COALESCE(d2.hostname, d2.serial, f2.device_id::text)), f2.device_id
				LIMIT $4
			) dd
		) devs ON true
		WHERE d.tenant_id = $1::uuid
		GROUP BY f.cve_id, e.severity, e.cvss_v3_score, f.app_name, f.app_version,
			f.match_confidence, f.fixed_version, e.description, e.description_source, devs.devices
		ORDER BY e.cvss_v3_score DESC NULLS LAST, f.cve_id, f.app_name
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset, portalFindingsMaxDevices)
	if err != nil {
		if isUndefinedTable(err) {
			return PortalCVEFindingsPage{}, nil // CVE matcher data absent — degrade, don't 500
		}
		return PortalCVEFindingsPage{}, fmt.Errorf("portal cve findings page: %w", err)
	}
	defer rows.Close()

	var page PortalCVEFindingsPage
	for rows.Next() {
		var f PortalCVEFinding
		var devicesBytes []byte
		var total int
		if err := rows.Scan(&f.CVEID, &f.Severity, &f.CVSS, &f.App, &f.Version,
			&f.MatchConfidence, &f.FixedVersion,
			&f.DevicesAffected, &devicesBytes, &f.DevicesTruncated,
			&f.FirstSeen, &f.Summary, &f.DescriptionSource,
			&f.PackageSource, &f.ConfidenceTier, &f.InstallReasons, &f.MappingBasis, &total); err != nil {
			return PortalCVEFindingsPage{}, fmt.Errorf("scan portal cve finding page: %w", err)
		}
		if len(devicesBytes) > 0 {
			if err := json.Unmarshal(devicesBytes, &f.Devices); err != nil {
				return PortalCVEFindingsPage{}, fmt.Errorf("decode devices for finding %s: %w", f.CVEID, err)
			}
		}
		page.Total = total
		page.Findings = append(page.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return PortalCVEFindingsPage{}, fmt.Errorf("iterate portal cve finding page: %w", err)
	}
	ids := make([]string, 0, len(page.Findings))
	for _, finding := range page.Findings {
		ids = append(ids, finding.CVEID)
	}
	assessments, err := exploitation.FetchAssessments(ctx, pool, ids, time.Now().UTC())
	if err != nil {
		return PortalCVEFindingsPage{}, fmt.Errorf("portal exploitation evidence: %w", err)
	}
	for i := range page.Findings {
		page.Findings[i].Exploitation = assessments[page.Findings[i].CVEID]
	}
	return page, nil
}

// FetchPortalCVEFindings aggregates device_cve_findings across the tenant's
// fleet. Degrades gracefully (empty result) when the CVE store tables don't
// exist yet — patched-cve-sync may not have run on a fresh install. Returns
// the FULL unpaginated set — used by portal PDF report generation, which
// must render every finding, not just one page. The paginated
// GET /v1/portal/findings handler uses FetchPortalCVEFindingsPage instead.
func FetchPortalCVEFindings(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]PortalCVEFinding, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			f.cve_id,
			LOWER(COALESCE(e.severity, '')),
			e.cvss_v3_score,
			f.app_name,
			f.app_version,
			COUNT(DISTINCT f.device_id)::int,
			MIN(f.first_seen_at),
			COALESCE(e.description, ''),
			COALESCE(e.description_source, '')
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		JOIN devices d ON d.id = f.device_id
		WHERE d.tenant_id = $1::uuid
		GROUP BY f.cve_id, e.severity, e.cvss_v3_score, f.app_name, f.app_version, e.description, e.description_source
		ORDER BY e.cvss_v3_score DESC NULLS LAST, f.cve_id, f.app_name
	`, tenantID)
	if err != nil {
		if isUndefinedTable(err) {
			return nil, nil // CVE matcher data absent — degrade, don't 500
		}
		return nil, fmt.Errorf("portal cve findings: %w", err)
	}
	defer rows.Close()

	var findings []PortalCVEFinding
	for rows.Next() {
		var f PortalCVEFinding
		if err := rows.Scan(&f.CVEID, &f.Severity, &f.CVSS, &f.App, &f.Version,
			&f.DevicesAffected, &f.FirstSeen, &f.Summary, &f.DescriptionSource); err != nil {
			return nil, fmt.Errorf("scan portal cve finding: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.CVEID)
	}
	assessments, err := exploitation.FetchAssessments(ctx, pool, ids, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("portal exploitation evidence: %w", err)
	}
	for i := range findings {
		findings[i].Exploitation = assessments[findings[i].CVEID]
	}
	return findings, nil
}

// PortalUnapprovedApp is one unapproved-policy app aggregated across a
// tenant's fleet for GET /v1/portal/unapproved-apps: one row per app, with
// the count of devices it's currently installed on.
type PortalUnapprovedApp struct {
	AppName         string
	EnforcementTier string
	DevicesAffected int
	// EvidenceBasis (PAT-1725) is one of "identifier_match", "name_match_only"
	// or "unknown" — see AppPolicyRow.EvidenceBasis for the full contract.
	EvidenceBasis          string
	IdentifierMatchedCount int
	NameMatchedCount       int
	// RemovalState (PAT-1726) is always PortalAppRemovalStateNotAvailable:
	// PAT-1598 added a platform record of authorised-removal campaigns but
	// deliberately no pathway that delivers a removal to a device, and this
	// endpoint is not fed from those records. See contracts/portal-api.md for why this must not be
	// rendered as "not requested" — that would imply removal is something
	// this app could have but simply hasn't had yet.
	RemovalState string
}

// PortalAppRemovalStateNotAvailable is the only removal_state value
// GET /v1/portal/unapproved-apps ever emits (PAT-1726). There is no
// application-removal data model on the platform to derive a real state
// from — inventing "not_requested" would misrepresent an absent capability
// as an available-but-unused one.
const PortalAppRemovalStateNotAvailable = "not_available"

// FetchPortalUnapprovedApps reuses FetchAppPolicyDriftReport (PAT-479's
// tenant_app_policies x device_apps join, keyed on the same team_id >
// bundle_id > name precedence as fetchAppPolicy) and keeps only the
// policy=unapproved rows, so the customer-facing device counts are exactly
// the same aggregation the staff app-policy-drift report already computes —
// no separate matching logic to keep in sync. Sorted by devices affected
// (most widespread first), then app name, for a stable customer-facing order.
// Empty (not an error) when the tenant has no unapproved policy entries
// configured, or when tenant_app_policies/device_apps don't exist yet.
func FetchPortalUnapprovedApps(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]PortalUnapprovedApp, error) {
	drift, err := FetchAppPolicyDriftReport(ctx, pool, tenantID)
	if err != nil {
		return nil, fmt.Errorf("portal unapproved apps: %w", err)
	}

	apps := make([]PortalUnapprovedApp, 0, len(drift.Policies))
	for _, p := range drift.Policies {
		if p.Policy != "unapproved" {
			continue
		}
		apps = append(apps, PortalUnapprovedApp{
			AppName:                p.AppName,
			EnforcementTier:        p.EnforcementTier,
			DevicesAffected:        p.DevicesWithApp,
			EvidenceBasis:          p.EvidenceBasis,
			IdentifierMatchedCount: p.IdentifierMatchedCount,
			NameMatchedCount:       p.NameMatchedCount,
			RemovalState:           PortalAppRemovalStateNotAvailable,
		})
	}

	sort.Slice(apps, func(i, j int) bool {
		if apps[i].DevicesAffected != apps[j].DevicesAffected {
			return apps[i].DevicesAffected > apps[j].DevicesAffected
		}
		return apps[i].AppName < apps[j].AppName
	})

	return apps, nil
}

// DeviceTenant returns the owning tenant of a device, or ErrDeviceNotFound.
// The portal device-detail handler uses this for the ownership check before
// reusing report.Fetch — a mismatch is reported as "not found" (never 403)
// so the endpoint can't be used as a device-existence oracle across tenants.
func DeviceTenant(ctx context.Context, pool *pgxpool.Pool, deviceID string) (string, error) {
	var tenantID string
	err := pool.QueryRow(ctx,
		`SELECT tenant_id::text FROM devices WHERE id = $1::uuid`, deviceID,
	).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrDeviceNotFound
		}
		return "", fmt.Errorf("device tenant lookup: %w", err)
	}
	return tenantID, nil
}

// isUndefinedTable reports whether err is Postgres 42P01 (relation missing).
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
