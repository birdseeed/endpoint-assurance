// Portal read API handlers (PAT-693) — the PUBLIC-listener, CF-Access-JWT-
// authenticated, customer-scoped, READ-ONLY surface consumed by the
// app.patched.im portal.
//
// Invariants (locked by PAT-330):
//   - Tenant identity comes ONLY from portalauth.FromContext (the verified
//     email → portal_users mapping). No handler reads a tenant identifier
//     from the URL, query string, or body.
//   - Cross-tenant probes answer 404 (never 403) so nothing on this surface
//     acts as an existence oracle for other tenants' resources.
//   - Query logic is reused from the PAT-340 admin read layer
//     (report.Fetch / report.FetchExecutiveSummary / report.FetchTenant*);
//     this file only shapes JSON.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvepipeline"
	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/driverblock"
	"patched.im/api/internal/exploitation"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
	"patched.im/api/internal/softwaregov"
)

// identity pulls the authenticated portal identity from the context. A miss
// means the route was mounted without portalauth.Middleware — fail closed.
func identity(w http.ResponseWriter, r *http.Request) (portalauth.Identity, bool) {
	id, ok := portalauth.FromContext(r.Context())
	if !ok || id.TenantID == "" {
		slog.Error("portal handler reached without identity — middleware missing?",
			"path", r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return portalauth.Identity{}, false
	}
	return id, true
}

// ---------------------------------------------------------------------------
// GET /v1/portal/overview
// ---------------------------------------------------------------------------

type portalOverviewResp struct {
	TenantName             string     `json:"tenant_name"`
	GeneratedAt            time.Time  `json:"generated_at"`
	DevicesTotal           int        `json:"devices_total"`
	DevicesReporting24h    int        `json:"devices_reporting_24h"`
	OldestSuccessfulIngest *time.Time `json:"oldest_successful_ingest"`
	// DevicesRetired (PAT-2135): devices the customer has retired, still in
	// devices_total but not setting oldest_successful_ingest.
	DevicesRetired  int                         `json:"devices_retired"`
	DevicesDegraded int                         `json:"devices_degraded"`
	CISScoreCurrent float64                     `json:"cis_score_current"`
	CISTrend        []report.PortalTrendPoint   `json:"cis_trend"`
	FindingsOpen    report.PortalSeverityCounts `json:"findings_open"`
	PatchStatus     report.PortalPatchStatus    `json:"patch_status"`
	// CVEAttention is deliberately a separate field from FindingsOpen
	// (PAT-1953): FindingsOpen is CIS/compliance-control failures,
	// cve_attention is CVE-matcher findings from device_cve_findings. See
	// report.PortalCVEAttention for the confirmed-match, severity and
	// availability rules.
	CVEAttention report.PortalCVEAttention `json:"cve_attention"`
	// UnapprovedPresent (PAT-2009) is the number of distinct products marked
	// Unapproved that at least one device currently reports. null means it
	// could not be assessed (for example the estate is over the load cap),
	// which is not the same as zero.
	UnapprovedPresent        *int                       `json:"unapproved_present"`
	UnapprovedPresentDevices *int                       `json:"unapproved_present_devices"`
	UnapprovedPresentItems   []softwaregov.OverviewItem `json:"unapproved_present_items"`
	// UnapprovedAlertsOpen and UnapprovedAlertsAcknowledged (PAT-2097) count
	// tracked unapproved software alerts, one per (product policy, device).
	// They are not the same measure as UnapprovedPresent, which counts
	// distinct products from the live inventory: see contracts/portal-api.md
	// for why the two can differ. null means the count could not be read.
	UnapprovedAlertsOpen         *int `json:"unapproved_alerts_open"`
	UnapprovedAlertsAcknowledged *int `json:"unapproved_alerts_acknowledged"`
	// NewSoftware (PAT-2093) is products first seen in the last 14 days, or
	// since the tenant's last review when that is more recent, each with an
	// urgency level from its trust evidence and CVE state. null means the
	// block could not be computed, which is not "nothing new".
	NewSoftware *softwaregov.NewSoftwareUrgency `json:"new_software"`
}

// overviewUnapprovedLimit is the length of the overview's short list.
const overviewUnapprovedLimit = 5

// PortalOverviewHandler returns the tenant-wide posture summary.
func PortalOverviewHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_overview", "tenant_id", id.TenantID)

		ov, err := report.FetchPortalOverview(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch portal overview failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ov.CISTrend == nil {
			ov.CISTrend = []report.PortalTrendPoint{}
		}

		// PAT-2009: Unapproved software present. A failure degrades this one
		// figure to null and leaves the rest of the overview intact.
		var unapproved, unapprovedDevices *int
		unapprovedItems := []softwaregov.OverviewItem{}
		if sum, err := softwaregov.UnapprovedOverview(r.Context(), pool, id.TenantID, time.Now(), overviewUnapprovedLimit); err != nil {
			logger.Warn("unapproved present summary unavailable", "err", err)
		} else {
			unapproved, unapprovedDevices, unapprovedItems = &sum.Products, &sum.Devices, sum.Items
		}

		var alertsOpen, alertsAcked *int
		if open, acked, err := softwaregov.ActiveAlertCounts(r.Context(), pool, id.TenantID); err != nil {
			logger.Warn("unapproved alert counts unavailable", "err", err)
		} else {
			alertsOpen, alertsAcked = &open, &acked
		}

		// PAT-2093: new software by urgency. Degrades to null like the
		// figures above.
		var newSoftware *softwaregov.NewSoftwareUrgency
		if ns, err := softwaregov.FetchNewSoftwareUrgency(r.Context(), pool, id.TenantID, time.Now()); err != nil {
			logger.Warn("new software urgency unavailable", "err", err)
		} else {
			newSoftware = &ns
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalOverviewResp{
			TenantName:             ov.TenantName,
			GeneratedAt:            ov.GeneratedAt,
			DevicesTotal:           ov.DevicesTotal,
			DevicesReporting24h:    ov.DevicesReporting24h,
			OldestSuccessfulIngest: ov.OldestSuccessfulIngest,
			DevicesRetired:         ov.DevicesRetired,
			DevicesDegraded:        ov.DevicesDegraded,
			CISScoreCurrent:        ov.CISScoreCurrent,
			CISTrend:               ov.CISTrend,
			FindingsOpen:           ov.FindingsOpen,
			PatchStatus:            ov.PatchStatus,
			CVEAttention:           ov.CVEAttention,

			UnapprovedPresent:        unapproved,
			UnapprovedPresentDevices: unapprovedDevices,
			UnapprovedPresentItems:   unapprovedItems,

			UnapprovedAlertsOpen:         alertsOpen,
			UnapprovedAlertsAcknowledged: alertsAcked,

			NewSoftware: newSoftware,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/control-coverage
// ---------------------------------------------------------------------------

type portalControlCounts struct {
	Total                   int `json:"total"`
	Evaluated               int `json:"evaluated"`
	OutOfScope              int `json:"out_of_scope"`
	UndeterminedEvaluations int `json:"undetermined_evaluations"`
}

type portalControlMeasurements struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Undetermined  int `json:"undetermined"`
	NotApplicable int `json:"not_applicable"`
}

type portalControlIdentifiers struct {
	CISMapped   int `json:"cis_mapped"`
	CISUnmapped int `json:"cis_unmapped"`
	NonCIS      int `json:"non_cis"`
}

type portalControlCoverageBenchmark struct {
	Benchmark        string                    `json:"benchmark"`
	BenchmarkVersion string                    `json:"benchmark_version"`
	Controls         portalControlCounts       `json:"controls"`
	Measurements     portalControlMeasurements `json:"measurements"`
	Identifiers      portalControlIdentifiers  `json:"identifiers"`
}

type portalControlCoverageResp struct {
	GeneratedAt  time.Time                        `json:"generated_at"`
	Platforms    []string                         `json:"platforms"`
	Controls     portalControlCounts              `json:"controls"`
	Measurements portalControlMeasurements        `json:"measurements"`
	Identifiers  portalControlIdentifiers         `json:"identifiers"`
	Benchmarks   []portalControlCoverageBenchmark `json:"benchmarks"`
	TotalZero    bool                             `json:"total_zero"`

	// PAT-1960: devices whose device_class matches no enabled rule for
	// their platform (e.g. a server under the workstation-only Windows 11
	// pack). Never folded into Measurements.Undetermined — that means "we
	// tried and could not tell", this means "we correctly did not try".
	NotAssessedDevices int    `json:"not_assessed_devices"`
	NotAssessedReason  string `json:"not_assessed_reason,omitempty"`

	// DeviceClassUnreportedDevices counts devices whose device_class is
	// still 'unknown' — no agent has reported a real class for them yet.
	// Scored exactly as before PAT-1960; this labels that scoring honestly.
	DeviceClassUnreportedDevices int    `json:"device_class_unreported_devices"`
	DeviceClassUnreportedReason  string `json:"device_class_unreported_reason,omitempty"`
}

// PortalControlCoverageHandler returns the tenant's live rule-library
// coverage. It deliberately does not alter /overview's cis_score_current:
// coverage explains what is configured for evaluation, while the score keeps
// its established latest-evaluation denominator and unknown-evidence rules.
func PortalControlCoverageHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_control_coverage", "tenant_id", id.TenantID)

		coverage, err := report.FetchControlCoverage(r.Context(), pool, id.TenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				// This should be unreachable after authenticated portal identity
				// lookup, but preserves the surface's no-existence-oracle rule.
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch portal control coverage failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := portalControlCoverageResp{
			GeneratedAt:                  coverageGeneratedAt(),
			Platforms:                    coverage.Platforms,
			Controls:                     portalControlCountsFromCoverage(coverage),
			Measurements:                 portalControlMeasurementsFromCoverage(coverage.Measurements),
			Identifiers:                  portalControlIdentifiersFromCoverage(coverage.Identifiers),
			Benchmarks:                   make([]portalControlCoverageBenchmark, 0, len(coverage.Benchmarks)),
			TotalZero:                    coverage.TotalZero,
			NotAssessedDevices:           coverage.NotAssessedDevices,
			NotAssessedReason:            coverage.NotAssessedReason,
			DeviceClassUnreportedDevices: coverage.DeviceClassUnreportedDevices,
			DeviceClassUnreportedReason:  coverage.DeviceClassUnreportedReason,
		}
		for _, benchmark := range coverage.Benchmarks {
			resp.Benchmarks = append(resp.Benchmarks, portalControlCoverageBenchmark{
				Benchmark:        benchmark.Benchmark,
				BenchmarkVersion: benchmark.BenchmarkVersion,
				Controls: portalControlCounts{
					Total:                   benchmark.ControlsTotal,
					Evaluated:               benchmark.ControlsEvaluated,
					OutOfScope:              benchmark.ControlsOutOfScope,
					UndeterminedEvaluations: benchmark.UndeterminedEvaluations,
				},
				Measurements: portalControlMeasurementsFromCoverage(benchmark.Measurements),
				Identifiers:  portalControlIdentifiersFromCoverage(benchmark.Identifiers),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Warn("encode portal control coverage response failed", "err", err)
		}
	}
}

func portalControlMeasurementsFromCoverage(measurements report.ControlCoverageMeasurements) portalControlMeasurements {
	return portalControlMeasurements{
		Pass:          measurements.Pass,
		Fail:          measurements.Fail,
		Undetermined:  measurements.Undetermined,
		NotApplicable: measurements.NotApplicable,
	}
}

func portalControlIdentifiersFromCoverage(identifiers report.ControlCoverageIdentifiers) portalControlIdentifiers {
	return portalControlIdentifiers{
		CISMapped:   identifiers.CISMapped,
		CISUnmapped: identifiers.CISUnmapped,
		NonCIS:      identifiers.NonCIS,
	}
}

func portalControlCountsFromCoverage(coverage report.ControlCoverage) portalControlCounts {
	return portalControlCounts{
		Total:                   coverage.ControlsTotal,
		Evaluated:               coverage.ControlsEvaluated,
		OutOfScope:              coverage.ControlsOutOfScope,
		UndeterminedEvaluations: coverage.UndeterminedEvaluations,
	}
}

// coverageGeneratedAt exists to keep the coverage fetch narrowly about its
// live SQL definition. The endpoint timestamp is its response-generation
// time, like the portal overview's generated_at value.
func coverageGeneratedAt() time.Time {
	return time.Now().UTC()
}

// ---------------------------------------------------------------------------
// GET /v1/portal/devices
// ---------------------------------------------------------------------------

type portalDeviceEntry struct {
	DeviceID     string    `json:"device_id"`
	Hostname     string    `json:"hostname"`
	Platform     string    `json:"platform"`
	OSVersion    string    `json:"os_version"`
	LastSeen     time.Time `json:"last_seen"`
	CISScore     float64   `json:"cis_score"`
	FindingsOpen int       `json:"findings_open"`
	EncryptionOK *bool     `json:"encryption_ok"` // null = not evaluated
	PatchPending *bool     `json:"patch_pending"` // null = update state not reported (PAT-1805)
	// DeviceClass and OSCaption (PAT-2324): server, workstation or unknown,
	// and the OS edition caption (null when not reported). Derived by
	// report.derivePortalDeviceClass, shared with the device page. A Mac
	// reads workstation by OS family, not from a collected class; see
	// contracts/portal-api.md.
	DeviceClass string  `json:"device_class"`
	OSCaption   *string `json:"os_caption"`
	// Evidence is additive, section-scoped provenance. It confers no authority
	// on the derived CIS/finding values above or on any domain not explicitly
	// named in evidence.sections. See contracts/portal-api.md.
	Evidence report.DeviceEvidence `json:"evidence"`
	// CVEAssessment (PAT-2024) is additive: whether a CVE statement can be
	// made about this device's software at all. finding_count is null unless
	// state is "assessed"; see docs/API.md.
	CVEAssessment cvepipeline.DeviceAssessment `json:"cve_assessment"`
	// Retirement (PAT-2135) is null unless the customer has retired this
	// device. A retired device stays on the roster.
	Retirement *deviceretirement.Retirement `json:"retirement"`
}

type portalDevicesResp struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Total       int                 `json:"total"`
	Limit       int                 `json:"limit"`
	Offset      int                 `json:"offset"`
	Devices     []portalDeviceEntry `json:"devices"`
}

// PortalDevicesHandler returns the tenant's device roster.
func PortalDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_devices", "tenant_id", id.TenantID)

		limit, offset := parsePagination(r)
		res, err := report.FetchPortalDevices(r.Context(), pool, id.TenantID, limit, offset)
		if err != nil {
			logger.Error("fetch portal devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		ids := make([]string, 0, len(res.Devices))
		for _, d := range res.Devices {
			ids = append(ids, d.ID)
		}
		assessments, err := cvepipeline.AssessDevices(r.Context(), pool, id.TenantID, ids, false)
		if err != nil {
			logger.Error("fetch cve assessment failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		devices := make([]portalDeviceEntry, 0, len(res.Devices))
		for _, d := range res.Devices {
			devices = append(devices, portalDeviceEntry{
				DeviceID:      d.ID,
				Hostname:      d.Hostname,
				Platform:      d.OS,
				OSVersion:     d.OSVersion,
				LastSeen:      d.LastSeen,
				CISScore:      d.CompliancePct,
				FindingsOpen:  d.FindingsOpen(),
				EncryptionOK:  d.EncryptionOK,
				PatchPending:  d.PatchPending,
				DeviceClass:   d.DeviceClass,
				OSCaption:     d.OSCaption,
				Evidence:      d.Evidence,
				CVEAssessment: deviceAssessmentOrNotAssessed(assessments, d.ID),
				Retirement:    d.Retirement,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalDevicesResp{
			GeneratedAt: time.Now().UTC(),
			Total:       res.Total,
			Limit:       limit,
			Offset:      offset,
			Devices:     devices,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/devices/{deviceID}
// ---------------------------------------------------------------------------

type portalComplianceSignal struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Advisory string `json:"advisory"`
	// Undetermined (PAT-2496) is true exactly when status is "fail" only
	// because the value could not be read (an absent signal or the
	// collector's "Unknown"), so no value was observed failing. It is
	// report.EvalRow.Undetermined, the predicate the roster and the reports
	// already use. Additive; status is unchanged.
	Undetermined bool `json:"undetermined"`
}

type portalAppFinding struct {
	App             string   `json:"app"`
	Version         string   `json:"version"`
	CVEIDs          []string `json:"cve_ids"`
	MaxSeverity     string   `json:"max_severity"`
	MatchConfidence string   `json:"match_confidence"`
	FixedVersion    string   `json:"fixed_version"`
}

type portalDeviceDetailResp struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Device      portalDeviceDetailInfo `json:"device"`
	// Identity and Hardware (PAT-2141): the same devices/device_hardware/
	// device_disk/device_storage_volume data GET /admin/devices/{deviceID}
	// and the portal PDF's Hardware health section already read, minus
	// hw_uuid. Additive — every field above is unchanged.
	Identity          portalDeviceIdentity     `json:"identity"`
	Hardware          portalDeviceHardware     `json:"hardware"`
	ComplianceSignals []portalComplianceSignal `json:"compliance_signals"`
	AppsWithFindings  []portalAppFinding       `json:"apps_with_findings"`
	// CVEAssessment (PAT-2024): per observed product state. An empty
	// apps_with_findings only means "no known CVEs" for products listed here
	// as assessed; not_assessed products carry no CVE statement at all.
	CVEAssessment cvepipeline.DeviceAssessment `json:"cve_assessment"`
	// AgentHealthDegraded (PAT-2099): this device's currently open
	// degraded-capability entries (PAT-1064's agent_health.degraded
	// channel) — kind/subject/reason/first_seen/last_seen/count, tenant-
	// scoped. Empty (never null) when the device has no open faults; a
	// cleared entry stops appearing here as soon as device_agent_health
	// deletes its row, no separate "resolved" state to track.
	AgentHealthDegraded []report.DeviceAgentHealthEntry `json:"agent_health_degraded"`
	// Firmware (PAT-2262): BIOS, system and baseboard identity as the
	// firmware reports it. Always present; status "not_reported" when the
	// device has never sent the block. Observation only. See
	// portal_device_firmware.go.
	Firmware portalDeviceFirmware `json:"firmware"`
	// KernelDrivers (PAT-2263): the device's kernel drivers matched by hash
	// against Microsoft's recommended driver block rules and loldrivers.io,
	// with the blocklist enforcement state. Always present; status
	// "not_reported" when the device has never sent the block. Listed and
	// Unknown rows are returned (listed first); clean rows are counted in
	// summary only. See internal/driverblock.
	KernelDrivers driverblock.DeviceDrivers `json:"kernel_drivers"`
}

type portalDeviceDetailInfo struct {
	DeviceID  string                `json:"device_id"`
	Hostname  string                `json:"hostname"`
	Serial    string                `json:"serial"`
	Platform  string                `json:"platform"`
	OSVersion string                `json:"os_version"`
	OSBuild   string                `json:"os_build"`
	FirstSeen time.Time             `json:"first_seen"`
	LastSeen  time.Time             `json:"last_seen"`
	CISScore  float64               `json:"cis_score"`
	Evidence  report.DeviceEvidence `json:"evidence"`
	// FindingsOpen, EncryptionOK and PatchPending (PAT-2294) are the same
	// three figures GET /v1/portal/devices carries for this device, read
	// through the same report.FetchPortalDeviceSummary path, so the roster
	// and the device page cannot disagree. Null means not evaluated / not
	// reported, never "fine". Additive: every field above is unchanged.
	FindingsOpen int   `json:"findings_open"`
	EncryptionOK *bool `json:"encryption_ok"`
	PatchPending *bool `json:"patch_pending"`
	// DeviceClass and OSCaption (PAT-2324) are the roster's values for this
	// device, from the same report.FetchPortalDeviceSummary derivation.
	DeviceClass string  `json:"device_class"`
	OSCaption   *string `json:"os_caption"`
	// Retirement (PAT-2135): null unless the customer has retired this
	// device; the same object as the roster's.
	Retirement *deviceretirement.Retirement `json:"retirement"`
}

// PortalDeviceDetailHandler returns one device's compliance signals and
// vulnerable apps. Ownership is checked BEFORE any data is fetched; devices
// outside the caller's tenant answer 404.
func PortalDeviceDetailHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_device_detail", "tenant_id", id.TenantID)

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		owner, err := report.DeviceTenant(r.Context(), pool, deviceID)
		if err != nil || owner != id.TenantID {
			if err != nil && !errors.Is(err, report.ErrDeviceNotFound) {
				logger.Error("device ownership check failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Not found and not-yours are deliberately indistinguishable.
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		rep, err := report.Fetch(r.Context(), pool, deviceID)
		if err != nil {
			if errors.Is(err, report.ErrDeviceNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch device report failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		evidence, err := report.FetchPortalDeviceEvidence(r.Context(), pool, id.TenantID, deviceID)
		if err != nil {
			logger.Error("fetch device evidence failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		summary, err := report.FetchPortalDeviceSummary(r.Context(), pool, id.TenantID, deviceID)
		if err != nil {
			if errors.Is(err, report.ErrDeviceNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch device summary failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		assessments, err := cvepipeline.AssessDevices(r.Context(), pool, id.TenantID, []string{deviceID}, true)
		if err != nil {
			logger.Error("fetch cve assessment failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		agentHealth, err := report.FetchPortalDeviceAgentHealth(r.Context(), pool, id.TenantID, deviceID)
		if err != nil {
			logger.Error("fetch device agent health failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		firmware, err := fetchPortalDeviceFirmware(r.Context(), pool, id.TenantID, deviceID)
		if err != nil {
			logger.Error("fetch device firmware failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		kernelDrivers, err := driverblock.FetchDevice(r.Context(), pool, id.TenantID, deviceID, time.Now().UTC())
		if err != nil {
			logger.Error("fetch device kernel drivers failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		retirements, err := deviceretirement.Fetch(r.Context(), pool, id.TenantID, []string{deviceID})
		if err != nil {
			logger.Error("fetch device retirement failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		signals := make([]portalComplianceSignal, 0, len(rep.Evaluations))
		for _, e := range rep.Evaluations {
			signals = append(signals, portalComplianceSignal{
				RuleID:       e.RuleKey,
				Title:        e.Title,
				Severity:     e.Severity,
				Status:       e.Status,
				Advisory:     e.Description,
				Undetermined: e.Undetermined(),
			})
		}

		s := rep.Summary()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalDeviceDetailResp{
			GeneratedAt: rep.GeneratedAt,
			Device: portalDeviceDetailInfo{
				DeviceID:     rep.Device.ID,
				Hostname:     rep.Device.Hostname,
				Serial:       rep.Device.Serial,
				Platform:     rep.Device.OS,
				OSVersion:    rep.Device.OSVersion,
				OSBuild:      rep.Device.OSBuild,
				FirstSeen:    rep.Device.FirstSeen,
				LastSeen:     rep.Device.LastSeen,
				CISScore:     s.CompliancePct,
				Evidence:     evidence,
				FindingsOpen: summary.FindingsOpen,
				EncryptionOK: summary.EncryptionOK,
				PatchPending: summary.PatchPending,
				DeviceClass:  summary.DeviceClass,
				OSCaption:    summary.OSCaption,
				Retirement:   deviceretirement.Of(retirements, rep.Device.ID),
			},
			Identity:            buildPortalDeviceIdentity(rep, evidence),
			Hardware:            buildPortalDeviceHardware(rep, evidence),
			ComplianceSignals:   signals,
			AppsWithFindings:    groupAppFindings(rep.CVEFindings),
			CVEAssessment:       deviceAssessmentOrNotAssessed(assessments, deviceID),
			AgentHealthDegraded: agentHealth,
			Firmware:            firmware,
			KernelDrivers:       kernelDrivers,
		})
	}
}

// deviceAssessmentOrNotAssessed never lets a missing assessment read as a
// clean result: a device absent from the map is reported not_assessed.
func deviceAssessmentOrNotAssessed(m map[string]cvepipeline.DeviceAssessment, deviceID string) cvepipeline.DeviceAssessment {
	if a, ok := m[deviceID]; ok {
		return a
	}
	return cvepipeline.DeviceAssessment{State: cvepipeline.StateNotAssessed}
}

// severityRank orders CVE severities for max_severity derivation.
var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// confirmedFlavorRank orders the confirmed match_confidence flavors for
// folding a bucket that contains more than one: vendor/security-bulletin
// confirmation ("version_vendor_confirmed") is stronger evidence than a bare
// CPE-range match ("version_confirmed"), so it wins ties rather than
// whichever hit iteration happens to visit last. Any other confirmed value
// not in this table ranks below both (zero, via the unknown-key default —
// same idiom as severityRank above), so it only wins when it's the only
// confirmed flavor present in the bucket.
var confirmedFlavorRank = map[string]int{"version_vendor_confirmed": 2, "version_confirmed": 1}

// isConfirmedConfidence mirrors internal/report/cve_report.go's
// confirmedConfidence (unexported there, so duplicated here rather than
// imported): only "version_unverified" counts as not-confirmed — every
// other value (e.g. "version_confirmed", "version_vendor_confirmed") is
// confirmed. Do not hardcode a two-value enum; this is the one distinguished
// "not confirmed" value, everything else is confirmed.
func isConfirmedConfidence(matchConfidence string) bool {
	return matchConfidence != "version_unverified"
}

// appFindingAccum folds a bucket of per-CVE hits for one (app, version) into
// a single portalAppFinding, alongside the transient state needed to fold
// match_confidence and fixed_version across the bucket.
type appFindingAccum struct {
	finding portalAppFinding
	// hasUnverified is true once any hit in the bucket carries
	// "version_unverified" — that value wins over any confirmed hit also in
	// the bucket, mirroring the confirmed/unverified split in
	// internal/report/cve_report.go's BuildCVEActions.
	hasUnverified bool
	// confirmedSeen holds the highest-priority confirmed match_confidence
	// value observed so far (per confirmedFlavorRank), not merely any one —
	// a bucket mixing confirmed flavors (e.g. version_confirmed and
	// version_vendor_confirmed for the same app+version) resolves
	// deterministically to the stronger-evidence flavor, not iteration order.
	confirmedSeen string
	// maxFixedVersion is the highest FixedVersion seen so far, folded via
	// cvematch.CompareVersions (never lexicographically — see
	// internal/report/cve_report.go's cveAppBucket.targetVersion, the same
	// algorithm this mirrors). "" when no hit in the bucket carries one.
	maxFixedVersion string
}

// groupAppFindings collapses per-CVE device findings into one row per
// (app, version) with the CVE list, worst severity, folded match confidence
// and the highest known fixed version. Pure; unit-tested.
func groupAppFindings(findings []report.DeviceCVEFinding) []portalAppFinding {
	type key struct{ app, version string }
	byApp := map[key]*appFindingAccum{}
	var order []key

	for _, f := range findings {
		k := key{f.AppName, f.AppVersion}
		acc, ok := byApp[k]
		if !ok {
			acc = &appFindingAccum{finding: portalAppFinding{App: f.AppName, Version: f.AppVersion, CVEIDs: []string{}}}
			byApp[k] = acc
			order = append(order, k)
		}
		acc.finding.CVEIDs = append(acc.finding.CVEIDs, f.CVEID)
		sev := strings.ToLower(f.Severity)
		if severityRank[sev] > severityRank[acc.finding.MaxSeverity] {
			acc.finding.MaxSeverity = sev
		}

		if isConfirmedConfidence(f.MatchConfidence) {
			if acc.confirmedSeen == "" || confirmedFlavorRank[f.MatchConfidence] > confirmedFlavorRank[acc.confirmedSeen] {
				acc.confirmedSeen = f.MatchConfidence
			}
		} else {
			acc.hasUnverified = true
		}

		if f.FixedVersion != "" {
			acc.maxFixedVersion = cvematch.MaxVersion(acc.maxFixedVersion, f.FixedVersion)
		}
	}

	out := make([]portalAppFinding, 0, len(order))
	for _, k := range order {
		acc := byApp[k]
		sort.Strings(acc.finding.CVEIDs)
		if acc.hasUnverified {
			acc.finding.MatchConfidence = "version_unverified"
		} else {
			acc.finding.MatchConfidence = acc.confirmedSeen
		}
		acc.finding.FixedVersion = acc.maxFixedVersion
		out = append(out, acc.finding)
	}
	return out
}

// ---------------------------------------------------------------------------
// GET /v1/portal/findings
// ---------------------------------------------------------------------------

type portalFindingDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

type portalFindingEntry struct {
	CVEID             string                  `json:"cve_id"`
	Severity          string                  `json:"severity"`
	CVSS              *float64                `json:"cvss"`
	App               string                  `json:"app"`
	Version           string                  `json:"version"`
	MatchConfidence   string                  `json:"match_confidence"`
	FixedVersion      string                  `json:"fixed_version"`
	DevicesAffected   int                     `json:"devices_affected"`
	Devices           []portalFindingDevice   `json:"devices"`
	DevicesTruncated  bool                    `json:"devices_truncated"`
	FirstSeen         time.Time               `json:"first_seen"`
	Summary           string                  `json:"summary"`
	DescriptionSource string                  `json:"description_source"`
	Exploitation      exploitation.Assessment `json:"exploitation"`
	// PAT-2023: set only on Homebrew findings (source "homebrew_formula" or
	// "homebrew_cask"); omitted for applications and the OS.
	Source         *string  `json:"source,omitempty"`
	ConfidenceTier *string  `json:"confidence_tier,omitempty"`
	InstallReasons []string `json:"install_reasons,omitempty"`
	// PAT-2138: "auto" when the finding comes only from an automatically
	// published CPE mapping; omitted otherwise.
	MappingBasis *string `json:"mapping_basis,omitempty"`
}

type portalFindingsResp struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Total       int                  `json:"total"`
	Limit       int                  `json:"limit"`
	Offset      int                  `json:"offset"`
	Findings    []portalFindingEntry `json:"findings"`
	// CVEAssessment (PAT-2024): tenant-level coverage and freshness. An
	// empty findings list is only "no known CVEs" for the assessed products
	// counted here.
	CVEAssessment cvepipeline.TenantAssessment `json:"cve_assessment"`
}

// PortalFindingsHandler returns one bounded page of the tenant's open CVE
// findings, aggregated per (CVE, app, version), ordered by CVSS score
// descending (highest severity first) with cve_id/app as stable tie-breakers
// so results don't reorder across pages. Empty (not an error) when the CVE
// matcher hasn't produced data yet, or when the page is beyond the last one.
//
// PAT-1201: paginated via the same ?limit/?offset convention as
// GET /v1/portal/devices (parsePagination — default and max page size
// defaultPageLimit/maxPageLimit). Client-side search (CVE/app/severity)
// stays scoped to the currently-loaded page — no server-side search param
// here by design (Andy, 2026-08-10).
func PortalFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_findings", "tenant_id", id.TenantID)

		limit, offset := parsePagination(r)
		page, err := report.FetchPortalCVEFindingsPage(r.Context(), pool, id.TenantID, limit, offset)
		if err != nil {
			logger.Error("fetch portal findings failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		tenantAssessment, err := cvepipeline.AssessTenant(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch tenant cve assessment failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		findings := make([]portalFindingEntry, 0, len(page.Findings))
		for _, f := range page.Findings {
			devices := make([]portalFindingDevice, 0, len(f.Devices))
			for _, d := range f.Devices {
				devices = append(devices, portalFindingDevice{DeviceID: d.DeviceID, Hostname: d.Hostname})
			}
			findings = append(findings, portalFindingEntry{
				CVEID:             f.CVEID,
				Severity:          f.Severity,
				CVSS:              f.CVSS,
				App:               f.App,
				Version:           f.Version,
				MatchConfidence:   f.MatchConfidence,
				FixedVersion:      f.FixedVersion,
				DevicesAffected:   f.DevicesAffected,
				Devices:           devices,
				DevicesTruncated:  f.DevicesTruncated,
				FirstSeen:         f.FirstSeen,
				Summary:           f.Summary,
				DescriptionSource: f.DescriptionSource,
				Exploitation:      f.Exploitation,
				Source:            f.PackageSource,
				ConfidenceTier:    f.ConfidenceTier,
				InstallReasons:    f.InstallReasons,
				MappingBasis:      f.MappingBasis,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalFindingsResp{
			GeneratedAt:   time.Now().UTC(),
			Total:         page.Total,
			Limit:         limit,
			Offset:        offset,
			Findings:      findings,
			CVEAssessment: tenantAssessment,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/unapproved-apps
// ---------------------------------------------------------------------------

type portalUnapprovedAppEntry struct {
	AppName         string `json:"app_name"`
	EnforcementTier string `json:"enforcement_tier"`
	DevicesAffected int    `json:"devices_affected"`
	// EvidenceBasis (PAT-1725): "identifier_match", "name_match_only" or
	// "unknown" — see contracts/portal-api.md. Identity evidence, not
	// version evidence: the platform's matcher confirms which product this
	// row is, not which version is installed.
	EvidenceBasis          string `json:"evidence_basis"`
	IdentifierMatchedCount int    `json:"identifier_matched_devices"`
	NameMatchedCount       int    `json:"name_matched_devices"`
	// RemovalState (PAT-1726) is always "not_available": PAT-1598's
	// authorised-removal campaign records carry no delivery pathway and do
	// not feed this endpoint. See
	// contracts/portal-api.md — the portal must not render this as "not
	// requested".
	RemovalState string `json:"removal_state"`
}

type portalUnapprovedAppsResp struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Total       int                        `json:"total"`
	Apps        []portalUnapprovedAppEntry `json:"apps"`
}

// PortalUnapprovedAppsHandler returns the tenant's unapproved-policy apps,
// each with the count of devices it's installed on (PAT-729). Empty (not an
// error) when the tenant has no unapproved policy entries configured.
func PortalUnapprovedAppsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_unapproved_apps", "tenant_id", id.TenantID)

		rows, err := report.FetchPortalUnapprovedApps(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch portal unapproved apps failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		apps := make([]portalUnapprovedAppEntry, 0, len(rows))
		for _, a := range rows {
			apps = append(apps, portalUnapprovedAppEntry{
				AppName:                a.AppName,
				EnforcementTier:        a.EnforcementTier,
				DevicesAffected:        a.DevicesAffected,
				EvidenceBasis:          a.EvidenceBasis,
				IdentifierMatchedCount: a.IdentifierMatchedCount,
				NameMatchedCount:       a.NameMatchedCount,
				RemovalState:           a.RemovalState,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalUnapprovedAppsResp{
			GeneratedAt: time.Now().UTC(),
			Total:       len(apps),
			Apps:        apps,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/extensions
// ---------------------------------------------------------------------------

type portalExtensionDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

type portalExtensionEntry struct {
	ExtensionID   string   `json:"extension_id"`
	Name          string   `json:"name"`
	Browser       string   `json:"browser"`
	RiskLevel     string   `json:"risk_level"`
	Versions      []string `json:"versions"`
	VersionsTrunc bool     `json:"versions_truncated"`
	// VersionCount (PAT-1799) is the exact distinct-version count this
	// (extension_id, browser) pair was observed at, before the Versions
	// display cap — see report.PortalExtension.VersionCount.
	VersionCount  int                     `json:"version_count"`
	DeviceCount   int                     `json:"device_count"`
	Devices       []portalExtensionDevice `json:"devices"`
	DevicesTrunc  bool                    `json:"devices_truncated"`
	ApprovalState string                  `json:"approval_state"`
	// EvidenceBasis (PAT-1725) is always "identifier_match": extensions are
	// grouped and matched by extension_id, the browser store's own
	// identifier, never by display name. Ingestion rejects a row with an
	// empty extension_id (internal/extractor/validate.go), so every row
	// reaching this endpoint carries a real identifier. See
	// contracts/portal-api.md.
	EvidenceBasis string `json:"evidence_basis"`
	// RemovalState (PAT-1726): "not_requested" / "requested" / "in_progress"
	// / "removal_completed" — see report.PortalExtension.RemovalState and
	// contracts/portal-api.md. Populated on every row but only meaningful
	// when ApprovalState is "unapproved". "removal_completed" does NOT mean
	// the extension is gone from the estate — see the doc comment on
	// report.PortalExtension.RemovalState for why the row's mere presence
	// here already proves it is still installed somewhere.
	RemovalState            string `json:"removal_state"`
	RemovalTargetsTotal     int    `json:"removal_targets_total"`
	RemovalTargetsCompleted int    `json:"removal_targets_completed"`
	// DecidedBy / DecidedAt / Justification (PAT-1800): who approved,
	// unapproved or ignored this extension, when, and why. All three null
	// when ApprovalState is "unreviewed" — see
	// report.PortalExtension.DecidedBy's doc comment and
	// contracts/portal-api.md.
	DecidedBy     *string    `json:"decided_by"`
	DecidedAt     *time.Time `json:"decided_at"`
	Justification *string    `json:"justification"`
}

// portalExtensionEvidenceBasis is always "identifier_match" — see
// portalExtensionEntry.EvidenceBasis doc comment.
const portalExtensionEvidenceBasis = "identifier_match"

type portalExtensionsResp struct {
	GeneratedAt time.Time `json:"generated_at"`
	Total       int       `json:"total"`
	Truncated   bool      `json:"truncated"`
	// EstateTooLarge (PAT-933 gate round 5) is true only when
	// report.FetchPortalExtensions' fail-closed source-row-cap guard fired:
	// the tenant's raw device_browser_extensions row count exceeded
	// report.PortalExtensionsMaxSourceRows and the GROUP BY/sort was never
	// run at all. Total 0 / Extensions [] / Truncated true also occur for an
	// ordinary tenant with genuinely no extension telemetry yet — this field
	// is the ONLY way to tell the two cases apart. See
	// report.PortalExtensionsResult's doc comment for the full rationale.
	EstateTooLarge bool                   `json:"estate_too_large"`
	Extensions     []portalExtensionEntry `json:"extensions"`
}

// PortalExtensionsHandler returns the tenant's browser extension estate,
// each extension carrying its PAT-826 approval state (approved / unapproved
// / ignored / unreviewed — PAT-933).
//
// Empty (not an error) in two cases that are NOT the same thing:
//  1. Ordinary: the tenant has no browser extension telemetry yet.
//     estate_too_large is false.
//  2. Degraded (PAT-933 gate round 5): the tenant's raw
//     device_browser_extensions row count has exceeded
//     report.PortalExtensionsMaxSourceRows, so FetchPortalExtensions fails
//     closed before ever running the aggregate query. estate_too_large is
//     true. This can happen to a genuinely large or long-lived legitimate
//     tenant with zero abuse involved (the table is append-only — rows are
//     never deleted, see report.FetchPortalExtensions' doc comment), and
//     once it happens it is PERMANENT for that tenant: the row count can
//     only grow. Callers/UI must check estate_too_large, not just an empty
//     extensions array, before concluding "this customer has no extensions".
//
// Abuse resistance (GitHub-Non-Author-Review): the extension list and each per-extension
// device drill-down are capped in SQL (see report.FetchPortalExtensions);
// total stays the exact pre-cap count EXCEPT in the estate_too_large branch
// above (total is always 0 there — see report.PortalExtensionsResult), and
// truncated / devices_truncated flag what was cut so the portal can render
// honestly.
// PAT-2156: an optional ?device_id= query param narrows this to that
// device's own current extensions. Validated against the verified tenant
// before any extensions query runs, with the same malformed->400 /
// unknown-or-cross-tenant->404 (indistinguishable) rule PortalSoftwareHandler
// and PortalDeviceDetailHandler already follow.
func PortalExtensionsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_extensions", "tenant_id", id.TenantID)

		deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
		if deviceID != "" {
			if !looksLikeUUID(deviceID) {
				http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
				return
			}
			owner, err := report.DeviceTenant(r.Context(), pool, deviceID)
			if err != nil || owner != id.TenantID {
				if err != nil && !errors.Is(err, report.ErrDeviceNotFound) {
					logger.Error("device ownership check failed", "err", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}

		var res report.PortalExtensionsResult
		var err error
		if deviceID != "" {
			res, err = report.FetchPortalExtensionsForDevice(r.Context(), pool, id.TenantID, deviceID)
		} else {
			res, err = report.FetchPortalExtensions(r.Context(), pool, id.TenantID)
		}
		if err != nil {
			logger.Error("fetch portal extensions failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if res.EstateTooLarge {
			// PAT-933 gate round 5: this branch is otherwise silent and, in
			// the JSON response, indistinguishable from an ordinary
			// zero-extensions tenant — log it so the fail-closed state is at
			// least operationally discoverable, since the portal page itself
			// can never show real data here until the tenant's row count is
			// addressed (raise the cap, prune stale rows, or paginate).
			//
			// source_rows (round 6): report.FetchPortalExtensions' pre-check
			// is now a bounded existence probe capped at
			// report.PortalExtensionsMaxSourceRows()+1, not a plain
			// COUNT(*) — see report.PortalExtensionsResult.SourceRowCount's
			// doc comment. Since this Warn only ever fires once
			// SourceRowCount is at/over the cap, the logged value is always
			// exactly max_source_rows+1 ("at least this many rows"), never
			// the tenant's true accumulated total; do not read it as exact.
			logger.Warn("portal extensions fail-closed: source row count at least cap",
				"source_rows_at_least", res.SourceRowCount,
				"max_source_rows", report.PortalExtensionsMaxSourceRows())
		}

		extensions := make([]portalExtensionEntry, 0, len(res.Extensions))
		for _, e := range res.Extensions {
			devices := make([]portalExtensionDevice, 0, len(e.Devices))
			for _, d := range e.Devices {
				devices = append(devices, portalExtensionDevice{DeviceID: d.DeviceID, Hostname: d.Hostname})
			}
			versions := e.Versions
			if versions == nil {
				versions = []string{}
			}
			extensions = append(extensions, portalExtensionEntry{
				ExtensionID:             e.ExtensionID,
				Name:                    e.Name,
				Browser:                 e.Browser,
				RiskLevel:               e.RiskLevel,
				Versions:                versions,
				VersionsTrunc:           e.VersionsTrunc,
				VersionCount:            e.VersionCount,
				DeviceCount:             e.DeviceCount,
				Devices:                 devices,
				DevicesTrunc:            e.DevicesTrunc,
				ApprovalState:           e.ApprovalState,
				EvidenceBasis:           portalExtensionEvidenceBasis,
				RemovalState:            e.RemovalState,
				RemovalTargetsTotal:     e.RemovalTargetsTotal,
				DecidedBy:               e.DecidedBy,
				DecidedAt:               e.DecidedAt,
				Justification:           e.Justification,
				RemovalTargetsCompleted: e.RemovalTargetsCompleted,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalExtensionsResp{
			GeneratedAt:    time.Now().UTC(),
			Total:          res.Total,
			Truncated:      res.Truncated,
			EstateTooLarge: res.EstateTooLarge,
			Extensions:     extensions,
		})
	}
}

// ---------------------------------------------------------------------------
// GET/POST /v1/portal/reports, GET /v1/portal/reports/{id}
// ---------------------------------------------------------------------------

type portalReportEntry struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ReportType  string    `json:"report_type"`
	ReportLabel string    `json:"report_label"`
	GeneratedAt time.Time `json:"generated_at"`
	// Formats lists the files this report can be downloaded as with
	// GET /v1/portal/reports/{id}?format=: ["pdf","csv"], or ["pdf"] for a
	// report generated before CSV renderings existed (PAT-2405).
	Formats []string `json:"formats"`
}

// portalReportFormats derives the downloadable formats from the stored
// paths. "archived" is the cold-storage marker the download refuses.
func portalReportFormats(pdfPath, csvPath *string) []string {
	formats := []string{}
	if portalReportFileAvailable(pdfPath) {
		formats = append(formats, "pdf")
	}
	if portalReportFileAvailable(csvPath) {
		formats = append(formats, "csv")
	}
	return formats
}

func portalReportFileAvailable(p *string) bool {
	return p != nil && *p != "" && *p != "archived"
}

type portalReportsResp struct {
	Total   int                 `json:"total"`
	Reports []portalReportEntry `json:"reports"`
}

// PortalReportsListHandler returns the tenant's portal-generated report
// history (source='portal' rows in report_records), newest first. Records of
// an admin-only report type are left out for a caller who is not an admin
// (PAT-2406), and total counts only the rows that caller can see.
func PortalReportsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	roleLookup := portalDBRoleLookup(pool)
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_reports_list", "tenant_id", id.TenantID)

		hidden, ok := hiddenReportTypesFor(w, r, roleLookup, id, logger)
		if !ok {
			return
		}

		limit, offset := parsePagination(r)
		rows, err := pool.Query(r.Context(), `
			SELECT id::text, name, report_type, generated_at, pdf_path, csv_path, COUNT(*) OVER()::int
			FROM report_records
			WHERE tenant_id = $1::uuid AND source = 'portal'
			  AND NOT (report_type = ANY($4::text[]))
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`, id.TenantID, limit, offset, hidden)
		if err != nil {
			logger.Error("list portal reports failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		resp := portalReportsResp{Reports: []portalReportEntry{}}
		for rows.Next() {
			var e portalReportEntry
			var pdfPath, csvPath *string
			if err := rows.Scan(&e.ID, &e.Name, &e.ReportType, &e.GeneratedAt, &pdfPath, &csvPath, &resp.Total); err != nil {
				logger.Error("scan portal report row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if def, found := report.LookupReportDefinition(e.ReportType); found {
				e.ReportLabel = def.Label
			}
			e.Formats = portalReportFormats(pdfPath, csvPath)
			resp.Reports = append(resp.Reports, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate portal report rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// portalReportDeviceLimit caps the roster fetched for the PDF. The renderer
// itself truncates the printed tables; this only bounds the query.
const portalReportDeviceLimit = 500

// PortalReportGenerateHandler generates the customer-layout PDF for the
// caller's tenant, stores it as a source='portal' report_records row, and
// returns the record. report_type is strict; type is accepted as a rollout
// alias. Omitting both keeps the pre-PAT-1847 executive-summary behaviour.
// Every role may generate, except that an admin-only report type (PAT-2406)
// is refused 403 admin_role_required for anyone but an admin.
func PortalReportGenerateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	roleLookup := portalDBRoleLookup(pool)
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_report_generate", "tenant_id", id.TenantID)

		var req struct {
			Name       string `json:"name"`
			ReportType string `json:"report_type"`
			Type       string `json:"type"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		if len(body) > 0 {
			dec := json.NewDecoder(strings.NewReader(string(body)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
		}
		reportType := strings.TrimSpace(req.ReportType)
		aliasType := strings.TrimSpace(req.Type)
		if reportType != "" && aliasType != "" && reportType != aliasType {
			http.Error(w, "report_type and type must match when both are supplied", http.StatusBadRequest)
			return
		}
		if reportType == "" {
			reportType = aliasType
		}
		if reportType == "" {
			reportType = "executive-summary"
		}
		def, found := report.LookupReportDefinition(reportType)
		if !found || !def.CustomerFacing || def.Subject != report.SubjectTenant {
			http.Error(w, "unknown or unavailable report_type", http.StatusBadRequest)
			return
		}
		if !requireAdminForReportType(w, r, roleLookup, id, reportType, "generate", logger) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = def.Label + " " + time.Now().UTC().Format("2006-01-02")
		}
		if len(name) > 120 {
			name = name[:120]
		}

		rec, err := generatePortalReport(r.Context(), pool, id.TenantID, reportType, name, nil, logger)
		if err != nil {
			logger.Error("generate portal report failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("portal report generated", "record_id", rec.ID, "email", id.Email)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(portalReportEntry{
			ID:          rec.ID,
			Name:        rec.Name,
			ReportType:  rec.ReportType,
			ReportLabel: def.Label,
			GeneratedAt: rec.GeneratedAt,
			Formats:     portalReportFormats(rec.PDFPath, rec.CSVPath),
		})
	}
}

// generatePortalReport is the single generation path for customer-layout
// reports: fetch summary/overview/findings/roster, render the portal PDF,
// store it as a source='portal' report_records row. Used by BOTH
// POST /v1/portal/reports and the PAT-703 schedule sweeper, so scheduled and
// manual reports are byte-for-byte the same layout and land in the same
// history.
//
// scheduleSlot is nil for manual/customer-triggered generation and non-nil
// ONLY when called from the PAT-703 sweeper (reportsched.Sweeper via
// PortalReportGenerator), in which case it is the portal_report_schedules
// slot (next_run_at) this report was generated for. It is threaded straight
// through to storeReportFiles so PAT-874's crash-recovery guard can tell a
// scheduler-generated report apart from a customer's own manual one.
func generatePortalReport(ctx context.Context, pool *pgxpool.Pool, tenantID, reportType, name string, scheduleSlot *time.Time, logger *slog.Logger) (*reportRecord, error) {
	def, found := report.LookupReportDefinition(reportType)
	if !found || !def.CustomerFacing || def.Subject != report.SubjectTenant {
		return nil, fmt.Errorf("unknown or unavailable report type %q", reportType)
	}

	out, err := renderPortalReportFiles(ctx, pool, tenantID, reportType, logger)
	if err != nil {
		return nil, err
	}

	rec, err := storeReportRecord(ctx, pool, tenantID, name, nil,
		report.ContentTypeFull, time.Time{}, time.Time{}, out.pdf, nil, out.csv,
		"portal", reportType, logger, scheduleSlot, out.coverage, nil)
	if err != nil {
		return nil, fmt.Errorf("store portal report: %w", err)
	}
	return rec, nil
}

// portalRenderedReport is one generation's output: the PDF and the CSV are
// both rendered from the single data fetch the renderer made (PAT-2405), so
// the two files describe the same moment. coverage is the frozen coverage
// snapshot for report_records.
type portalRenderedReport struct {
	pdf      []byte
	csv      []byte
	coverage map[string]any
}

// portalReportRenderer is one entry of the portal report registry. hasCSV is
// set by the constructor only when it was given a CSV renderer, so a type
// registered with a PDF renderer and no CSV renderer is visible to
// TestPortalReportCSVRenderersCoverCustomerCatalogue.
type portalReportRenderer struct {
	run    func(context.Context, *pgxpool.Pool, string, *slog.Logger) (portalRenderedReport, error)
	hasCSV bool
}

// portalReportRenderers (also the CSV registry: every entry renders both files
// from one fetch) is deliberately a keyed dispatch registry rather than
// a switch. TestPortalReportRenderersMatchCustomerCatalogue makes additions
// fail closed unless the product registry and generation engine change
// together, and also prevents an internal report type from being dispatched.
// Every entry below (other than executive-summary, which already has its
// own dedicated customer renderer in portal_pdf.go) renders through the
// *Customer variant of the shared report package renderer, never the plain
// Render*PDF used by the staff/admin routes in reports.go and
// portal_software_governance.go: a customer download must never carry the
// staff header's "Staff report" wording (PAT-2264).
var portalReportRenderers = map[string]portalReportRenderer{
	"executive-summary":  {run: renderPortalExecutiveFiles, hasCSV: true},
	"cis-compliance":     newPortalReportRenderer("cis-compliance", "CIS compliance report", report.FetchCISComplianceReport, report.RenderCISCompliancePDFCustomer, report.CISComplianceCSV),
	"cve-report":         newPortalReportRenderer("cve-report", "CVE report", report.FetchFreeCVEReport, report.RenderFreeCVEPDFCustomer, report.FreeCVECSV),
	"patch-status":       newPortalReportRenderer("patch-status", "patch status report", report.FetchPatchStatusReport, report.RenderPatchStatusPDFCustomer, report.PatchStatusCSV),
	"stale-endpoints":    newPortalReportRenderer("stale-endpoints", "stale endpoints report", fetchPortalStaleEndpointsReport, report.RenderStaleEndpointsPDFCustomer, report.StaleEndpointsCSV),
	"cert-expiry":        newPortalReportRenderer("cert-expiry", "certificate expiry report", report.FetchCertExpiryReport, report.RenderCertExpiryPDFCustomer, report.CertExpiryCSV),
	"edr-coverage":       newPortalReportRenderer("edr-coverage", "EDR coverage report", report.FetchEDRCoverageReport, report.RenderEDRCoveragePDFCustomer, report.EDRCoverageCSV),
	"encryption-posture": newPortalReportRenderer("encryption-posture", "encryption posture report", report.FetchEncryptionPostureReport, report.RenderEncryptionPosturePDFCustomer, report.EncryptionPostureCSV),
	"local-admin":        newPortalReportRenderer("local-admin", "local admin report", report.FetchLocalAdminReport, report.RenderLocalAdminPDFCustomer, report.LocalAdminCSV),
	// PAT-2009 software governance reports.
	"new-software":      newPortalReportRenderer("new-software", "new software report", report.FetchNewSoftwareReport, report.RenderNewSoftwarePDFCustomer, report.NewSoftwareCSV),
	"software-drift":    newPortalReportRenderer("software-drift", "software drift report", report.FetchSoftwareDriftReport, report.RenderSoftwareDriftPDFCustomer, report.SoftwareDriftCSV),
	"approved-software": newPortalReportRenderer("approved-software", "approved software report", report.FetchApprovedSoftwareReport, report.RenderApprovedSoftwarePDFCustomer, report.ApprovedSoftwareCSV),
	// PAT-2258: the cyber insurance evidence pack.
	"insurance-evidence": {hasCSV: true, run: func(ctx context.Context, pool *pgxpool.Pool, tenantID string, _ *slog.Logger) (portalRenderedReport, error) {
		data, err := report.FetchInsuranceEvidence(ctx, pool, tenantID)
		if err != nil {
			return portalRenderedReport{}, fmt.Errorf("fetch insurance evidence: %w", err)
		}
		return renderBoth(data, report.RenderInsuranceEvidencePDFCustomer, report.InsuranceEvidenceCSV, insuranceCoverageSnapshot(data))
	}},
	"ai-tooling-evidence": {hasCSV: true, run: func(ctx context.Context, pool *pgxpool.Pool, tenantID string, _ *slog.Logger) (portalRenderedReport, error) {
		data, err := report.BuildToolingEvidence(ctx, pool, tenantID, time.Now())
		if err != nil {
			return portalRenderedReport{}, fmt.Errorf("build AI tooling evidence report: %w", err)
		}
		return renderBoth(data, report.RenderToolingEvidencePDFCustomer, report.ToolingEvidenceCSV,
			map[string]any{"source": "ai-tooling-evidence", "devices_total": data.Coverage.DevicesTotal,
				"devices_with_tooling": data.Coverage.DevicesWithTooling, "lower_bound_devices": data.Coverage.LowerBoundDevices,
				"unknown_devices": data.Coverage.UnknownDevices})
	}},
}

// renderBoth renders one fetched data model as both the PDF and the CSV. It is
// the only place the two renderings meet, so they cannot come from different
// fetches. A nil renderCSV leaves the entry without a CSV, which the registry
// guard test reports.
func renderBoth[T any](data T, renderPDF, renderCSV func(T) ([]byte, error), coverage map[string]any) (portalRenderedReport, error) {
	pdf, err := renderPDF(data)
	if err != nil {
		return portalRenderedReport{}, err
	}
	var csv []byte
	if renderCSV != nil {
		if csv, err = renderCSV(data); err != nil {
			return portalRenderedReport{}, fmt.Errorf("render csv: %w", err)
		}
	}
	return portalRenderedReport{pdf: pdf, csv: csv, coverage: coverage}, nil
}

func newPortalReportRenderer[T any](reportType, fetchDescription string, fetch func(context.Context, *pgxpool.Pool, string) (T, error), renderPDF, renderCSV func(T) ([]byte, error)) portalReportRenderer {
	return portalReportRenderer{
		hasCSV: renderCSV != nil,
		run: func(ctx context.Context, pool *pgxpool.Pool, tenantID string, _ *slog.Logger) (portalRenderedReport, error) {
			data, err := fetch(ctx, pool, tenantID)
			if err != nil {
				return portalRenderedReport{}, fmt.Errorf("fetch %s: %w", fetchDescription, err)
			}
			return renderBoth(data, renderPDF, renderCSV, map[string]any{"source": reportType})
		},
	}
}

func fetchPortalStaleEndpointsReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (report.StaleEndpointsReport, error) {
	return report.FetchStaleEndpointsReport(ctx, pool, tenantID, 14)
}

// renderPortalReportFiles dispatches customer generation directly to the report
// package's fetch and render engines. Admin HTTP handlers are never reused.
func renderPortalReportFiles(ctx context.Context, pool *pgxpool.Pool, tenantID, reportType string, logger *slog.Logger) (portalRenderedReport, error) {
	renderer, found := portalReportRenderers[reportType]
	if !found || renderer.run == nil {
		return portalRenderedReport{}, fmt.Errorf("unknown or unavailable report type %q", reportType)
	}
	return renderer.run(ctx, pool, tenantID, logger)
}

// renderPortalReport is the PDF-and-coverage view of renderPortalReportFiles.
func renderPortalReport(ctx context.Context, pool *pgxpool.Pool, tenantID, reportType string, logger *slog.Logger) ([]byte, map[string]any, error) {
	out, err := renderPortalReportFiles(ctx, pool, tenantID, reportType, logger)
	return out.pdf, out.coverage, err
}

// renderPortalExecutiveSummary is the PDF-and-coverage view of
// renderPortalExecutiveFiles.
func renderPortalExecutiveSummary(ctx context.Context, pool *pgxpool.Pool, tenantID string, logger *slog.Logger) ([]byte, map[string]any, error) {
	out, err := renderPortalExecutiveFiles(ctx, pool, tenantID, logger)
	return out.pdf, out.coverage, err
}

func renderPortalExecutiveFiles(ctx context.Context, pool *pgxpool.Pool, tenantID string, logger *slog.Logger) (portalRenderedReport, error) {
	summary, err := report.FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("fetch summary: %w", err)
	}
	// PII guardrail: the portal PDF never carries user attribution,
	// regardless of the tenant's admin-report toggle.
	summary.UserAttributionToggle = "off"

	ov, err := report.FetchPortalOverview(ctx, pool, tenantID)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("fetch overview: %w", err)
	}

	// Findings + roster for the report body. Both reuse the existing
	// portal fetchers; FetchPortalCVEFindings already degrades to nil
	// when the CVE store is absent.
	findings, err := report.FetchPortalCVEFindings(ctx, pool, tenantID)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("fetch cve findings: %w", err)
	}
	devices, err := report.FetchPortalDevices(ctx, pool, tenantID,
		portalReportDeviceLimit, 0)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("fetch devices: %w", err)
	}

	// PAT-2130 (ruled 24 September 2026): one plan, no report gating. The
	// Hardware health section used to be gated behind subTierManaged
	// (PAT-686, provisionally defaulted pending a product call per the
	// PAT-1599 FLAG comment this replaces); every tenant now gets it
	// unconditionally, so no tier lookup happens here any more.
	pdfBytes, err := report.RenderPortalReportPDF(summary, ov, findings, devices, true)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("render portal pdf: %w", err)
	}
	// The CSV is rendered from the same five inputs as the PDF above.
	csvBytes, err := report.PortalExecutiveCSV(summary, ov, findings, devices)
	if err != nil {
		return portalRenderedReport{}, fmt.Errorf("render portal csv: %w", err)
	}
	return portalRenderedReport{pdf: pdfBytes, csv: csvBytes, coverage: portalCoverageSnapshot(ov)}, nil
}

// portalCoverageSnapshot is the estate coverage the portal report was rendered
// from, frozen onto report_records.coverage_snapshot (PAT-1613) so an issued
// report keeps showing the coverage it was issued with rather than today's.
//
// It carries the honesty fields alongside the headline counts on purpose: a
// devices_total with no oldest_successful_ingest beside it is a coverage claim
// with nothing behind it (root AGENTS.md, "absence requires authority"), and
// re-deriving those two later is exactly what freezing the figure exists to
// avoid.
func portalCoverageSnapshot(ov report.PortalOverview) map[string]any {
	snap := map[string]any{
		"source":                "portal_overview",
		"devices_total":         ov.DevicesTotal,
		"devices_reporting_24h": ov.DevicesReporting24h,
		"devices_degraded":      ov.DevicesDegraded,
		"devices_retired":       ov.DevicesRetired,
		"cis_score_current":     ov.CISScoreCurrent,
	}
	if ov.OldestSuccessfulIngest != nil {
		snap["oldest_successful_ingest"] = ov.OldestSuccessfulIngest.UTC().Format(time.RFC3339)
	}
	return snap
}

// PortalReportGenerator adapts generatePortalReport to the reportsched
// sweeper's GenerateFunc signature. This is how PAT-703 scheduled runs reuse
// the exact POST /v1/portal/reports generation path. slot is the schedule's
// next_run_at, passed straight through as generatePortalReport's
// scheduleSlot so PAT-874's crash-recovery guard has a real idempotency key.
func PortalReportGenerator(pool *pgxpool.Pool) func(ctx context.Context, tenantID, reportType, name string, slot time.Time) (string, error) {
	return func(ctx context.Context, tenantID, reportType, name string, slot time.Time) (string, error) {
		logger := slog.With("component", "reportsched", "tenant_id", tenantID, "report_type", reportType)
		rec, err := generatePortalReport(ctx, pool, tenantID, reportType, name, &slot, logger)
		if err != nil {
			return "", err
		}
		return rec.ID, nil
	}
}

// portalReportFormat reads the download's ?format= parameter. Absent or empty
// is the PDF, so existing links keep working; "pdf" and "csv" are the only
// other values, and a repeated parameter is refused rather than guessed at.
func portalReportFormat(r *http.Request) (string, bool) {
	values, present := r.URL.Query()["format"]
	if !present {
		return "pdf", true
	}
	if len(values) != 1 {
		return "", false
	}
	switch values[0] {
	case "", "pdf":
		return "pdf", true
	case "csv":
		return "csv", true
	}
	return "", false
}

// PortalReportDownloadHandler streams a portal-generated report as a PDF
// (the default) or, with ?format=csv, as the CSV rendered from the same data
// in the same generation. The record must belong to the caller's tenant AND be
// source='portal'; anything else is 404. The format only selects which of the
// record's two stored paths is read: the path always comes from the record,
// never from the request. A record of an admin-only report type (PAT-2406) is
// refused 403 admin_role_required for anyone but an admin, in either format
// and however it was generated (by an admin or by a schedule); another
// tenant's record stays 404 whatever its type.
func PortalReportDownloadHandler(pool *pgxpool.Pool) http.HandlerFunc {
	roleLookup := portalDBRoleLookup(pool)
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_report_download", "tenant_id", id.TenantID)

		format, ok := portalReportFormat(r)
		if !ok {
			http.Error(w, "format must be pdf or csv", http.StatusBadRequest)
			return
		}

		rid := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(rid) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var name, reportType string
		var pdfPath, csvPath *string
		err := pool.QueryRow(r.Context(), `
			SELECT name, report_type, pdf_path, csv_path
			FROM report_records
			WHERE id = $1::uuid AND tenant_id = $2::uuid AND source = 'portal'
		`, rid, id.TenantID).Scan(&name, &reportType, &pdfPath, &csvPath)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch portal report record failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !requireAdminForReportType(w, r, roleLookup, id, reportType, "download", logger) {
			return
		}

		stored, contentType, ext := pdfPath, "application/pdf", ".pdf"
		if format == "csv" {
			stored, contentType, ext = csvPath, "text/csv; charset=utf-8", ".csv"
		}
		if !portalReportFileAvailable(stored) {
			portalReportFileMissing(w, format)
			return
		}

		data, err := readReportFile(*stored)
		if err != nil {
			logger.Error("read portal report file failed", "format", format, "err", err)
			portalReportFileMissing(w, format)
			return
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+sanitiseFilename(name)+ext+`"`)
		if format == "csv" {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		logger.Info("portal report downloaded", "record_id", rid, "format", format, "email", id.AuditName(), "bytes", len(data))
	}
}

// portalReportFileMissing answers a download whose file is not there. The PDF
// keeps its plain 404; a missing CSV (a report generated before CSV renderings
// existed) is a JSON 404 carrying the code csv_not_available, so a client can
// tell it from "no such report" and offer the PDF.
func portalReportFileMissing(w http.ResponseWriter, format string) {
	if format != "csv" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "csv_not_available",
		"message": "A CSV is not available for this report. The PDF can still be downloaded.",
	})
}
