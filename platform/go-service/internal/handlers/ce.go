package handlers

// Cyber Essentials scoring engine + attestation store (PAT-367).
//
// Two routes, both on the internal Tailscale-bound listener (:8081):
//
//	GET /admin/tenants/{tenantID}/ce-status
//	    Returns per-control-area CE status computed from:
//	    - Compliance evaluations for mapped CIS L1 rule keys (auto-evidenced controls)
//	    - Manual attestation answers stored in ce_attestations (non-automatable controls)
//
//	PUT /admin/tenant-attestations/{tenantID}/{controlID}
//	    Upserts a single attestation answer for a non-automatable CE control.
//
// ⚠️  Write path: note GitHub-Non-Author-Review pre-ship gate before any attestation data drives
// customer-facing output. At MVP the data is Patched-internal only.
//
// Platform coverage (PAT-1973). This engine was written before
// the Windows CIS rules were seeded, so every auto-evidenced control listed
// macOS rule keys only. Counts are summed across a control's rule keys and
// across the tenant's devices, so on a mixed estate that resolved the control
// from the Mac evidence alone and silently excluded every Windows device from
// both sides of the ratio. A control could read "pass" for the host firewall
// while every Windows firewall in the estate was off. Windows keys are now
// listed wherever an equivalent rule exists. Where one does not, the control
// carries a comment saying so rather than leaving the absence to be rediscovered.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// CE model — five control areas, static definition.
// Adding a new area or control is a code + migration change.
// ---------------------------------------------------------------------------

type ceControlSource string

const (
	ceSourceAuto        ceControlSource = "auto"
	ceSourceAttestation ceControlSource = "attestation"
	// ceSourceAutoWithAttestationFallback (PAT-1975) is coexistence, not a
	// flip: device evidence over RuleKeys resolves the control when any
	// exists, and a stored attestation is used only when there is none. An
	// existing attestation is never discarded when evidence takes over — see
	// ceAttestationJSON.Superseded.
	ceSourceAutoWithAttestationFallback ceControlSource = "auto_with_attestation_fallback"
)

type ceControlDef struct {
	ID          string
	Title       string
	Description string
	Source      ceControlSource
	RuleKeys    []string // for ceSourceAuto and ceSourceAutoWithAttestationFallback controls
}

type ceAreaDef struct {
	ID          string
	Title       string
	Description string
	Controls    []ceControlDef
}

var ceModel = []ceAreaDef{
	{
		ID:          "ce_firewalls",
		Title:       "Firewalls",
		Description: "Boundary firewalls and host-based firewall configuration.",
		Controls: []ceControlDef{
			{
				ID:          "ce_fw_host",
				Title:       "Host-based firewall enabled",
				Description: "A host-based firewall is enabled on each managed device.",
				Source:      ceSourceAuto,
				// PAT-1973: the three Windows profile rules join the macOS
				// rule here. Counts are summed across rule keys, so a real
				// fail on any profile on any device fails the control,
				// which is the behaviour this control already had for macOS.
				RuleKeys: []string{
					"cis_macos_2_5_2_2_firewall",
					"cis_win_9_1_1_firewall_domain",
					"cis_win_9_2_1_firewall_private",
					"cis_win_9_3_1_firewall_public",
				},
			},
			{
				ID:          "ce_fw_boundary",
				Title:       "Boundary firewall at internet gateway",
				Description: "A firewall or router with firewall capability protects the internet connection for all office locations and remote workers.",
				Source:      ceSourceAttestation,
			},
		},
	},
	{
		ID:          "ce_secure_cfg",
		Title:       "Secure Configuration",
		Description: "Secure baseline configuration of devices and services.",
		Controls: []ceControlDef{
			{
				ID:          "ce_cfg_screen_lock",
				Title:       "Screen lock on inactivity",
				Description: "Devices lock automatically on inactivity and require a password to unlock.",
				Source:      ceSourceAuto,
				RuleKeys: []string{
					"cis_macos_2_10_screensaver_password",
					// cis_macos_2_10_1_screensaver_timeout retired by
					// migrations/0129 (PAT-1746) — it read
					// screensaver_delay_seconds as an idle-to-activation
					// interval, but that signal is actually the
					// password-after-screensaver delay. Swapped for the
					// correctly-scoped replacement so this CE control keeps
					// getting live evaluations instead of freezing on
					// evaluations from a rule that no longer evaluates.
					"cis_macos_2_10_2_password_after_screensaver_delay",
					// cis_macos_2_10_1_screensaver_inactivity added by
					// migrations/0130 (PAT-1753) — the correctly-scoped
					// replacement idle-timeout rule, using the new
					// screensaver_idle_seconds signal rather than the
					// retired cis_macos_2_10_1_screensaver_timeout's
					// misread of screensaver_delay_seconds.
					"cis_macos_2_10_1_screensaver_inactivity",
					// PAT-1973: Windows equivalents. Enabled, password on
					// resume and idle timeout together express the same
					// control the macOS rules above express.
					"cis_win_19_1_3_2_screensaver_enabled",
					"cis_win_19_1_3_3_screensaver_password",
					"cis_win_19_1_3_4_screensaver_timeout",
				},
			},
			{
				ID:          "ce_cfg_auto_login",
				Title:       "Auto-login disabled",
				Description: "Automatic login is disabled, requiring authentication on boot.",
				Source:      ceSourceAuto,
				// PAT-1973: macOS only. No Windows rule evaluates automatic
				// logon, so a Windows device contributes nothing here and
				// this control reads from the Macs in the estate alone.
				RuleKeys: []string{"cis_macos_5_1_auto_login_disabled"},
			},
			{
				ID:          "ce_cfg_default_passwords",
				Title:       "Default passwords changed",
				Description: "Default passwords on all devices, services, and network equipment have been changed to non-default values.",
				Source:      ceSourceAttestation,
			},
		},
	},
	{
		ID:          "ce_uac",
		Title:       "User Access Control",
		Description: "User accounts, privileges, and authentication controls.",
		Controls: []ceControlDef{
			{
				ID:          "ce_uac_admin_count",
				Title:       "Admin accounts limited",
				Description: "Devices have no more than the required number of local administrator accounts.",
				Source:      ceSourceAuto,
				// PAT-1974: cross-platform now. Both collectors emit the
				// identical local_admin_count signal (Patched-LTD/updater
				// #631), and cis_win_5_8_local_admin_count (migration 0160)
				// evaluates it on Windows with the same threshold and
				// severity as the macOS rule.
				RuleKeys: []string{"cis_macos_5_8_local_admin_count", "cis_win_5_8_local_admin_count"},
			},
			{
				ID:          "ce_uac_password_policy",
				Title:       "Password policy enforced",
				Description: "Accounts use strong passwords meeting minimum length, history, and lockout requirements.",
				Source:      ceSourceAuto,
				// PAT-1973: macOS only, deliberately. Windows account and
				// password policy rules exist (migrations/0024) but are T2,
				// evaluated only where a tenant has activated them in
				// tenant_rules. Folding an opt-in rule into an
				// always-evaluated control would make this control mean
				// different things for different tenants, which is worse
				// than it plainly covering one platform. Needs a decision on
				// T2 activation before the Windows keys belong here.
				RuleKeys: []string{
					"cis_macos_5_x_password_policy_non_default",
					"cis_macos_5_2_2_min_length",
					"cis_macos_5_2_7_max_age_days",
					"cis_macos_5_2_1a_lockout_threshold",
				},
			},
			{
				ID:          "ce_uac_mfa",
				Title:       "MFA for internet-facing services",
				Description: "Multi-factor authentication is enforced for all administrator accounts and internet-facing services.",
				Source:      ceSourceAttestation,
			},
			{
				ID:          "ce_uac_access_review",
				Title:       "User access reviewed regularly",
				Description: "User access rights are reviewed at least quarterly and revoked when no longer needed.",
				Source:      ceSourceAttestation,
			},
		},
	},
	{
		ID:          "ce_malware",
		Title:       "Malware Protection",
		Description: "Protection from malicious code and software.",
		Controls: []ceControlDef{
			{
				ID:          "ce_mal_gatekeeper",
				Title:       "Gatekeeper enabled",
				Description: "Gatekeeper restricts application installation to identified developers.",
				Source:      ceSourceAuto,
				RuleKeys:    []string{"cis_macos_2_5_2_1_gatekeeper"},
			},
			{
				ID:          "ce_mal_sip",
				Title:       "System Integrity Protection enabled",
				Description: "SIP protects core system files and processes from modification.",
				Source:      ceSourceAuto,
				RuleKeys:    []string{"cis_macos_2_5_3_sip"},
			},
			{
				ID:          "ce_mal_endpoint_protection",
				Title:       "Endpoint protection deployed",
				Description: "Anti-malware or endpoint detection and response software is deployed and active on all devices.",
				// PAT-1975 (Andy, 2026-09-21): coexistence, not a flip.
				// cis_win_18_9_45_defender_realtime evidences Windows
				// real-time protection state directly, so this control
				// resolves from that evidence where it exists and falls back
				// to the tenant's stored attestation only where it doesn't.
				// An existing attestation is kept and surfaced as superseded
				// rather than dropped once evidence takes over (see
				// ceAttestationJSON.Superseded). Third-party EDR presence
				// rule keys are deliberately excluded: edr_coverage.go
				// matches on presence only, which is not the same claim as
				// "deployed and active" this control makes. Gatekeeper and
				// SIP above stay macOS-only concepts with no Windows
				// equivalent.
				Source:   ceSourceAutoWithAttestationFallback,
				RuleKeys: []string{"cis_win_18_9_45_defender_realtime"},
			},
		},
	},
	{
		ID:          "ce_patching",
		Title:       "Patch Management",
		Description: "Keeping software and firmware up to date.",
		Controls: []ceControlDef{
			{
				ID:          "ce_patch_auto_updates",
				Title:       "Automatic updates enabled",
				Description: "Devices are configured to automatically check for and install security and critical updates.",
				Source:      ceSourceAuto,
				RuleKeys: []string{
					"cis_macos_1_2_update_check_auto",
					"cis_macos_1_3_update_download_auto",
					"cis_macos_1_4_auto_security_updates",
					"cis_macos_1_6b_critical_updates_auto",
					// PAT-1973: Windows automatic update policy.
					"cis_win_18_9_102_auto_updates",
				},
			},
			{
				ID:          "ce_patch_pending",
				Title:       "No pending security updates",
				Description: "All devices have applied available security updates.",
				Source:      ceSourceAuto,
				// PAT-1973: macOS only. Windows pending updates are carried
				// on devices.pending_updates and surfaced by the patch-status
				// report, but no CIS rule evaluates them, so there is no rule
				// key to add here yet.
				RuleKeys: []string{"cis_macos_1_1_pending_security_updates"},
			},
			{
				ID:          "ce_patch_policy",
				Title:       "Patch management policy in place",
				Description: "A documented patch management policy specifies timelines for applying OS and application updates.",
				Source:      ceSourceAttestation,
			},
		},
	},
}

// attestationControlIDs is the set of valid attestation control IDs, derived
// from the model at init time to avoid repeated iteration in the PUT handler.
var attestationControlIDs = func() map[string]bool {
	m := make(map[string]bool)
	for _, area := range ceModel {
		for _, ctrl := range area.Controls {
			// PAT-1975: a coexistence control still accepts attestation
			// writes — it's the fallback source when there's no evidence yet,
			// and the answer is retained (superseded, not deleted) once
			// evidence exists.
			if ctrl.Source == ceSourceAttestation || ctrl.Source == ceSourceAutoWithAttestationFallback {
				m[ctrl.ID] = true
			}
		}
	}
	return m
}()

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

type ruleEvalCounts struct {
	PassCount  int
	FailCount  int
	ErrorCount int
	NACount    int
	TotalCount int
	// UndeterminedCount is the number of latest evaluations that resolved to
	// fail with no observed value (PAT-1758/PAT-1762/PAT-1776): unreadable
	// evidence (an absent signal, or the collector's literal "Unknown"
	// sentinel), not a real observation of non-compliance. Excluded from
	// FailCount above; TotalCount is unaffected (still every row) so it stays
	// in any percentage denominator built from it.
	UndeterminedCount int
}

type dbAttestation struct {
	Answer     string
	Notes      string
	AttestedAt time.Time
}

func fetchCERuleEvalCounts(ctx context.Context, pool *pgxpool.Pool, tenantID string, ruleKeys []string) (map[string]ruleEvalCounts, error) {
	if len(ruleKeys) == 0 {
		return map[string]ruleEvalCounts{}, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT
			r.rule_key,
			COUNT(*) FILTER (WHERE e.status = 'pass')                                     AS pass_count,
			COUNT(*) FILTER (WHERE e.status = 'fail' AND e.observed_value IS NOT NULL)     AS fail_count,
			COUNT(*) FILTER (WHERE e.status = 'error')                                     AS error_count,
			COUNT(*) FILTER (WHERE e.status = 'not_applicable')                            AS na_count,
			COUNT(*)                                                                       AS total_count,
			-- PAT-1776: a 'fail' row with no observed value is unreadable
			-- evidence (absent signal, or the collector's "Unknown" sentinel),
			-- not a real observation of non-compliance — same predicate as
			-- isUndeterminedEval (internal/report/pdf.go). Excluded from
			-- fail_count above; total_count is unaffected so it stays in any
			-- percentage denominator built from it.
			COUNT(*) FILTER (WHERE e.status = 'fail' AND e.observed_value IS NULL)         AS undetermined_count
		FROM compliance_evaluations e
		JOIN compliance_rules r ON r.id = e.rule_id
		JOIN devices d ON d.id = e.device_id
		WHERE d.tenant_id = $1::uuid
		  AND r.rule_key = ANY($2::text[])
		GROUP BY r.rule_key
	`, tenantID, ruleKeys)
	if err != nil {
		return nil, fmt.Errorf("query rule eval counts: %w", err)
	}
	defer rows.Close()

	result := make(map[string]ruleEvalCounts)
	for rows.Next() {
		var rk string
		var c ruleEvalCounts
		if err := rows.Scan(&rk, &c.PassCount, &c.FailCount, &c.ErrorCount, &c.NACount, &c.TotalCount, &c.UndeterminedCount); err != nil {
			return nil, fmt.Errorf("scan rule eval row: %w", err)
		}
		result[rk] = c
	}
	return result, rows.Err()
}

func fetchCEAttestations(ctx context.Context, pool *pgxpool.Pool, tenantID string) (map[string]dbAttestation, error) {
	rows, err := pool.Query(ctx, `
		SELECT control_id, answer, notes, attested_at
		FROM ce_attestations
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query ce_attestations: %w", err)
	}
	defer rows.Close()

	result := make(map[string]dbAttestation)
	for rows.Next() {
		var controlID string
		var a dbAttestation
		if err := rows.Scan(&controlID, &a.Answer, &a.Notes, &a.AttestedAt); err != nil {
			return nil, fmt.Errorf("scan attestation row: %w", err)
		}
		result[controlID] = a
	}
	return result, rows.Err()
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

type ceAutoEvidenceJSON struct {
	RuleKeys   []string `json:"rule_keys"`
	PassCount  int      `json:"pass_count"`
	FailCount  int      `json:"fail_count"`
	TotalCount int      `json:"total_count"`
	PassPct    float64  `json:"pass_pct"`
	// UndeterminedCount is the number of latest evaluations across this
	// control's rule keys that could not be determined (PAT-1758/PAT-1762/
	// PAT-1776) — unreadable evidence, not a real fail. Excluded from
	// FailCount; included in TotalCount so it stays in PassPct's denominator.
	UndeterminedCount int `json:"undetermined_count"`
}

type ceAttestationJSON struct {
	Answer     *string    `json:"answer"`
	Notes      string     `json:"notes"`
	AttestedAt *time.Time `json:"attested_at"`
	// Superseded (PAT-1975) is true when this attestation answer exists but
	// was not what decided the control's status on this call — device
	// evidence resolved it instead. The attestation is still returned in
	// full; it is never dropped just because evidence took over. Always
	// false for a pure ceSourceAttestation control, where the attestation is
	// the only possible source.
	Superseded bool `json:"superseded"`
}

type ceControlJSON struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Source      string `json:"source"`
	Status      string `json:"status"`
	// ResolvedVia (PAT-1975) names which source actually decided Status on
	// this call: "evidence" or "attestation" for controls with only one
	// possible source, and "evidence" or "attestation_fallback" for a
	// ceSourceAutoWithAttestationFallback control, where either can win
	// depending on whether device evidence exists for this tenant.
	ResolvedVia  string              `json:"resolved_via"`
	AutoEvidence *ceAutoEvidenceJSON `json:"auto_evidence,omitempty"`
	Attestation  *ceAttestationJSON  `json:"attestation,omitempty"`
}

type ceAreaJSON struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Status      string          `json:"status"`
	Controls    []ceControlJSON `json:"controls"`
}

type ceStatusResp struct {
	TenantID      string       `json:"tenant_id"`
	OverallStatus string       `json:"overall_status"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Areas         []ceAreaJSON `json:"areas"`
}

// ceEvidenceCounts aggregates pass/fail/undetermined/total evaluation counts
// across a control's rule keys. Shared by ceSourceAuto and
// ceSourceAutoWithAttestationFallback (PAT-1975), which both resolve from
// device evidence over the same RuleKeys whenever any evidence exists.
func ceEvidenceCounts(ruleKeys []string, evalMap map[string]ruleEvalCounts) (totalPass, totalFail, totalUndetermined, totalEvals int) {
	for _, rk := range ruleKeys {
		if c, ok := evalMap[rk]; ok {
			totalPass += c.PassCount
			// PAT-1776: totalFail counts only real, evidenced fails —
			// c.FailCount already excludes undetermined rows (see
			// fetchCERuleEvalCounts). An "error" row is never undetermined by
			// this rule, so it stays counted here.
			totalFail += c.FailCount + c.ErrorCount
			totalUndetermined += c.UndeterminedCount
			totalEvals += c.TotalCount
		}
	}
	return totalPass, totalFail, totalUndetermined, totalEvals
}

// ceStatusFromEvidence resolves a status from evidence-count aggregates
// already produced by ceEvidenceCounts. ok is false when there is no
// evidence at all (totalEvals == 0), telling the caller to fall back to
// another source rather than reporting "unknown" itself — pure
// ceSourceAuto controls have no fallback, so they treat ok==false as
// "unknown" directly (PAT-1776's existing guarantee, unchanged).
func ceStatusFromEvidence(totalPass, totalFail, totalUndetermined, totalEvals int) (status string, ok bool) {
	if totalEvals == 0 {
		return "", false
	}
	if totalFail > 0 {
		return "fail", true
	}
	if totalPass == 0 && totalUndetermined > 0 {
		// Every evaluation for this control is unreadable evidence — no real
		// pass and no real fail. Reporting "pass" here would be a false
		// compliance claim, so this control cannot be determined, same as
		// the no-evaluations-at-all case.
		return "unknown", true
	}
	return "pass", true
}

// ceStatusFromAttestation resolves a status from the stored attestation
// answer for ctrlID, or "needs_attestation" when there isn't one.
func ceStatusFromAttestation(ctrlID string, attestMap map[string]dbAttestation) string {
	a, ok := attestMap[ctrlID]
	if !ok {
		return "needs_attestation"
	}
	switch a.Answer {
	case "yes":
		return "pass"
	case "no":
		return "fail"
	case "partial":
		return "partial"
	case "not_applicable":
		return "not_applicable"
	}
	return "needs_attestation"
}

// ceControlStatus returns "pass", "fail", "partial", "needs_attestation",
// "not_applicable", or "unknown" for one control.
func ceControlStatus(ctrlDef ceControlDef, evalMap map[string]ruleEvalCounts, attestMap map[string]dbAttestation) string {
	switch ctrlDef.Source {
	case ceSourceAuto:
		totalPass, totalFail, totalUndetermined, totalEvals := ceEvidenceCounts(ctrlDef.RuleKeys, evalMap)
		if status, ok := ceStatusFromEvidence(totalPass, totalFail, totalUndetermined, totalEvals); ok {
			return status
		}
		return "unknown"
	case ceSourceAutoWithAttestationFallback:
		// PAT-1975 coexistence: resolve from evidence when there is any,
		// falling back to the stored attestation only when there is none.
		totalPass, totalFail, totalUndetermined, totalEvals := ceEvidenceCounts(ctrlDef.RuleKeys, evalMap)
		if status, ok := ceStatusFromEvidence(totalPass, totalFail, totalUndetermined, totalEvals); ok {
			return status
		}
		return ceStatusFromAttestation(ctrlDef.ID, attestMap)
	default: // ceSourceAttestation
		return ceStatusFromAttestation(ctrlDef.ID, attestMap)
	}
}

// ceResolvedVia names which source actually decided ceControlStatus's result
// for ctrlDef on this call (PAT-1975). Pure-source controls always report
// their one possible source; a ceSourceAutoWithAttestationFallback control
// reports "evidence" or "attestation_fallback" depending on whether device
// evidence existed for this tenant.
func ceResolvedVia(ctrlDef ceControlDef, evalMap map[string]ruleEvalCounts) string {
	switch ctrlDef.Source {
	case ceSourceAuto:
		return "evidence"
	case ceSourceAutoWithAttestationFallback:
		_, _, _, totalEvals := ceEvidenceCounts(ctrlDef.RuleKeys, evalMap)
		if totalEvals > 0 {
			return "evidence"
		}
		return "attestation_fallback"
	default: // ceSourceAttestation
		return "attestation"
	}
}

// ceAreaStatus derives the area status from its control statuses.
func ceAreaStatus(ctrlStatuses []string) string {
	status := "pass"
	for _, s := range ctrlStatuses {
		switch s {
		case "fail":
			return "fail"
		case "partial":
			if status != "fail" {
				status = "partial"
			}
		case "needs_attestation", "unknown":
			if status == "pass" {
				status = "needs_attestation"
			}
		}
	}
	return status
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/ce-status
// ---------------------------------------------------------------------------

func TenantCEStatusHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_ce_status")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// Collect all rule keys needed across the model in one pass.
		var allRuleKeys []string
		for _, area := range ceModel {
			for _, ctrl := range area.Controls {
				if ctrl.Source == ceSourceAuto || ctrl.Source == ceSourceAutoWithAttestationFallback {
					allRuleKeys = append(allRuleKeys, ctrl.RuleKeys...)
				}
			}
		}

		evalMap, err := fetchCERuleEvalCounts(r.Context(), pool, tenantID, allRuleKeys)
		if err != nil {
			logger.Error("fetch rule eval counts failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		attestMap, err := fetchCEAttestations(r.Context(), pool, tenantID)
		if err != nil {
			logger.Error("fetch attestations failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		areas := make([]ceAreaJSON, 0, len(ceModel))
		var areaStatuses []string

		for _, areaDef := range ceModel {
			controls := make([]ceControlJSON, 0, len(areaDef.Controls))
			var ctrlStatuses []string

			for _, ctrlDef := range areaDef.Controls {
				status := ceControlStatus(ctrlDef, evalMap, attestMap)
				resolvedVia := ceResolvedVia(ctrlDef, evalMap)
				ctrlStatuses = append(ctrlStatuses, status)

				ctrl := ceControlJSON{
					ID:          ctrlDef.ID,
					Title:       ctrlDef.Title,
					Description: ctrlDef.Description,
					Source:      string(ctrlDef.Source),
					Status:      status,
					ResolvedVia: resolvedVia,
				}

				if ctrlDef.Source == ceSourceAuto || ctrlDef.Source == ceSourceAutoWithAttestationFallback {
					var agg ruleEvalCounts
					for _, rk := range ctrlDef.RuleKeys {
						if c, ok := evalMap[rk]; ok {
							agg.PassCount += c.PassCount
							agg.FailCount += c.FailCount
							agg.ErrorCount += c.ErrorCount
							agg.NACount += c.NACount
							agg.TotalCount += c.TotalCount
							agg.UndeterminedCount += c.UndeterminedCount
						}
					}
					var passPct float64
					if agg.TotalCount > 0 {
						passPct = math.Round(float64(agg.PassCount)/float64(agg.TotalCount)*1000) / 10
					}
					ctrl.AutoEvidence = &ceAutoEvidenceJSON{
						RuleKeys:          ctrlDef.RuleKeys,
						PassCount:         agg.PassCount,
						FailCount:         agg.FailCount + agg.ErrorCount,
						TotalCount:        agg.TotalCount,
						PassPct:           passPct,
						UndeterminedCount: agg.UndeterminedCount,
					}
				}

				// PAT-1975: a coexistence control also carries its
				// attestation (if any) alongside AutoEvidence above — evidence
				// resolving the status must never make an existing attestation
				// answer vanish from the response. Superseded marks that case.
				if ctrlDef.Source == ceSourceAttestation || ctrlDef.Source == ceSourceAutoWithAttestationFallback {
					att := &ceAttestationJSON{Notes: ""}
					if a, ok := attestMap[ctrlDef.ID]; ok {
						ans := a.Answer
						att.Answer = &ans
						att.Notes = a.Notes
						att.AttestedAt = &a.AttestedAt
						att.Superseded = ctrlDef.Source == ceSourceAutoWithAttestationFallback && resolvedVia == "evidence"
					}
					ctrl.Attestation = att
				}

				controls = append(controls, ctrl)
			}

			areaStatus := ceAreaStatus(ctrlStatuses)
			areaStatuses = append(areaStatuses, areaStatus)
			areas = append(areas, ceAreaJSON{
				ID:          areaDef.ID,
				Title:       areaDef.Title,
				Description: areaDef.Description,
				Status:      areaStatus,
				Controls:    controls,
			})
		}

		overall := ceAreaStatus(areaStatuses)

		logger.Info("CE status served", "tenant_id", tenantID, "overall", overall)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ceStatusResp{
			TenantID:      tenantID,
			OverallStatus: overall,
			GeneratedAt:   time.Now().UTC(),
			Areas:         areas,
		})
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenant-attestations/{tenantID}/{controlID}
// ---------------------------------------------------------------------------

type attestationPutReq struct {
	Answer string `json:"answer"`
	Notes  string `json:"notes"`
}

type attestationPutResp struct {
	TenantID   string    `json:"tenant_id"`
	ControlID  string    `json:"control_id"`
	Answer     string    `json:"answer"`
	Notes      string    `json:"notes"`
	AttestedAt time.Time `json:"attested_at"`
}

func TenantAttestationPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	validAnswers := map[string]bool{
		"yes": true, "no": true, "partial": true, "not_applicable": true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_attestation_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		controlID := strings.TrimSpace(chi.URLParam(r, "controlID"))

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !attestationControlIDs[controlID] {
			http.Error(w, "unknown control_id", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req attestationPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if !validAnswers[req.Answer] {
			http.Error(w, `answer must be one of: yes, no, partial, not_applicable`, http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		now := time.Now().UTC()
		_, err = pool.Exec(r.Context(), `
			INSERT INTO ce_attestations (tenant_id, control_id, answer, notes, attested_at)
			VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, control_id)
			DO UPDATE SET
				answer      = EXCLUDED.answer,
				notes       = EXCLUDED.notes,
				attested_at = EXCLUDED.attested_at
		`, tenantID, controlID, req.Answer, req.Notes, now)
		if err != nil {
			logger.Error("upsert attestation failed", "err", err, "tenant_id", tenantID, "control_id", controlID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("attestation saved", "tenant_id", tenantID, "control_id", controlID, "answer", req.Answer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(attestationPutResp{
			TenantID:   tenantID,
			ControlID:  controlID,
			Answer:     req.Answer,
			Notes:      req.Notes,
			AttestedAt: now,
		})
	}
}
