package handlers

// GET /v1/portal/local-admins (PAT-2215): the standing local-administrator
// roster (PAT-1974's local_admin_accounts, PAT-1988/1992's built-in-
// Administrator account_state), tenant-scoped and read-only, reusing
// report.FetchLocalAdminReport — the exact query that already backs the
// "local-admin" report-catalogue PDF (report.RenderLocalAdminPDFCustomer,
// dispatched through portal.go's portalReportRenderers) — rather than a
// second query. This is the JSON shape the portal's new Governance ->
// Local admins page needs for both its "by account" and "by device" views,
// and for the estate summary tiles, without a bespoke customer-layout PDF
// generator.
//
// Account names are personal data (PAT-1974's own pii_observed note on
// cis_macos_5_8_local_admin_count / cis_win_5_8_local_admin_count), so this
// route checks the caller's portal role itself and refuses a viewer with
// 403 admin_role_required — the same body shape every write route in this
// package already uses (writeApprovalError), even though this is a read.
// It is, as far as this package's routes go, the first /v1/portal/* GET to
// gate on role: every other admin-role check here gates a write, because
// nothing else on this surface exposes personal data at this resolution.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

// localAdminRuleThreshold mirrors the cis_macos_5_8_local_admin_count /
// cis_win_5_8_local_admin_count rule threshold (migrations 0005, 0160): at
// most 2 standing admins. Both platform rules share this exact threshold
// (same heuristic, same severity — see 0160's own comment), so one constant
// serves both rather than re-deriving it from compliance_rules at request
// time.
const localAdminRuleThreshold = 2

type portalLocalAdminPrincipal struct {
	Name          string  `json:"name"`
	PrincipalType string  `json:"principal_type"` // user | group | unresolved
	Builtin       bool    `json:"builtin"`
	AccountState  *string `json:"account_state"` // enabled | disabled | unknown | null
}

type portalLocalAdminDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	// ReportedAdminCount/AssessedAdminCount/Pass are all null when the
	// device carries no usable local_admin_count signal at all — never 0,
	// which would silently claim a clean device this platform has no
	// evidence for.
	ReportedAdminCount *int  `json:"reported_admin_count"`
	AssessedAdminCount *int  `json:"assessed_admin_count"`
	Pass               *bool `json:"pass"`
	// MembershipReadable is false when the roster itself (as opposed to the
	// bare count) could not be read: local_admins.collection_status was
	// "unavailable", or the key has never been reported at all. A device
	// can have MembershipReadable=false and a real ReportedAdminCount at
	// the same time — the scalar count and the named roster are read by
	// separate collectors and can be independently degraded.
	MembershipReadable bool                        `json:"membership_readable"`
	CollectionStatus   string                      `json:"collection_status"`
	BuiltinAdminState  string                      `json:"builtin_admin_state"`
	BuiltinAdminNote   string                      `json:"builtin_admin_note"`
	Principals         []portalLocalAdminPrincipal `json:"principals"`
}

type portalLocalAdminsResp struct {
	GeneratedAt time.Time                `json:"generated_at"`
	Threshold   int                      `json:"threshold"`
	Devices     []portalLocalAdminDevice `json:"devices"`
	// OverLimitDevices counts devices with a known assessed count that
	// fails the threshold (report.LocalAdminDevice.Risk "at-risk" or
	// "critical") — never devices whose count is simply unknown.
	OverLimitDevices int `json:"over_limit_devices"`
	// DistinctAccounts counts distinct (principal_type, name) pairs holding
	// standing admin anywhere in the estate — the same principal on two
	// devices counts once.
	DistinctAccounts int `json:"distinct_accounts"`
	// UnreadableDevices counts devices whose roster could not be read
	// (MembershipReadable false on that device) — kept as its own tile,
	// never folded into a zero.
	UnreadableDevices int `json:"unreadable_devices"`
}

// PortalLocalAdminsHandler serves GET /v1/portal/local-admins.
func PortalLocalAdminsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx),
			"handler", "portal_local_admins", "tenant_id", id.TenantID)

		role, err := portalauth.DBRole(ctx, pool, id.Email, id.TenantID, false)
		if err != nil {
			logger.Error("role lookup failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		if !portalauth.CanWrite(role) {
			writeApprovalError(w, http.StatusForbidden, "admin_role_required",
				"only a portal admin can view the local administrators roster; your role is "+role, nil)
			return
		}

		rep, err := report.FetchLocalAdminReport(ctx, pool, id.TenantID)
		if err != nil {
			logger.Error("fetch local admin report failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := portalLocalAdminsResp{
			GeneratedAt: rep.GeneratedAt,
			Threshold:   localAdminRuleThreshold,
			Devices:     make([]portalLocalAdminDevice, 0, len(rep.Devices)),
		}
		distinctAccounts := map[string]bool{}
		for _, d := range rep.Devices {
			hostname := d.Hostname
			if hostname == "" || hostname == "—" { // "—", report.fallback's own placeholder
				hostname = "Unknown device"
			}
			platform := strings.ToLower(d.OS)
			if platform == "" || platform == "—" {
				platform = ""
			}
			dev := portalLocalAdminDevice{
				DeviceID:           d.DeviceID,
				Hostname:           hostname,
				Platform:           platform,
				CollectionStatus:   d.LocalAdminsCollectionStatus,
				MembershipReadable: d.LocalAdminsCollectionStatus != "" && d.LocalAdminsCollectionStatus != "unavailable",
				BuiltinAdminState:  d.BuiltinAdmin,
				BuiltinAdminNote:   d.BuiltinAdminNote,
			}
			if d.ReportedAdminCount >= 0 {
				rc := d.ReportedAdminCount
				dev.ReportedAdminCount = &rc
			}
			if d.Risk != "unknown" {
				ac := d.AdminCount
				dev.AssessedAdminCount = &ac
				pass := d.Risk == "compliant"
				dev.Pass = &pass
				if !pass {
					resp.OverLimitDevices++
				}
			}
			if !dev.MembershipReadable {
				resp.UnreadableDevices++
			}
			for _, a := range d.AdminAccounts {
				dev.Principals = append(dev.Principals, portalLocalAdminPrincipal{
					Name: a.Name, PrincipalType: a.PrincipalType, Builtin: a.Builtin,
					AccountState: a.AccountState,
				})
				distinctAccounts[a.PrincipalType+"|"+a.Name] = true
			}
			resp.Devices = append(resp.Devices, dev)
		}
		resp.DistinctAccounts = len(distinctAccounts)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
