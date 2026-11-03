package handlers

// Role rules for portal reports (PAT-2406, PAT-2408; ruled 2026-10-05):
// "Viewers can generate reports but only admins change schedules; the Local
// Admin report is admin-only."
//
// Which reports are admin-only is recorded once, on the registry entry
// (report.ReportDefinition.AdminOnly). The role is read exactly as
// PortalLocalAdminsHandler reads it (portalauth.DBRole at the point of use,
// never cached on the identity), and a refusal is the same
// 403 admin_role_required body every admin-only portal route answers with.
// The read-only service identity has no email and is never more than a
// viewer here, as on GET /v1/portal/local-admins.

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

// portalRoleLookup resolves the caller's role. It is a parameter so a handler
// can be tested without a database.
type portalRoleLookup func(ctx context.Context, id portalauth.Identity) (string, error)

func portalDBRoleLookup(pool *pgxpool.Pool) portalRoleLookup {
	return func(ctx context.Context, id portalauth.Identity) (string, error) {
		return portalauth.DBRole(ctx, pool, id.Email, id.TenantID, false)
	}
}

// portalReportCallerIsAdmin reads the caller's role. On a failed lookup it
// writes the 500 itself and returns ok=false: a caller whose role cannot be
// read is never treated as an admin and never served admin-only content.
func portalReportCallerIsAdmin(w http.ResponseWriter, r *http.Request, lookup portalRoleLookup, id portalauth.Identity, logger *slog.Logger) (admin bool, role string, ok bool) {
	role, err := lookup(r.Context(), id)
	if err != nil {
		logger.Error("role lookup failed", "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		return false, "", false
	}
	return portalauth.CanWrite(role), role, true
}

// requireAdminForReportType refuses a caller who is not an admin when
// reportType is an admin-only report. It writes the response itself and
// returns false when the caller may not proceed. A report type that is not
// admin-only costs no role read.
func requireAdminForReportType(w http.ResponseWriter, r *http.Request, lookup portalRoleLookup, id portalauth.Identity, reportType, what string, logger *slog.Logger) bool {
	def, found := report.LookupReportDefinition(reportType)
	if !found || !def.AdminOnly {
		return true
	}
	admin, role, ok := portalReportCallerIsAdmin(w, r, lookup, id, logger)
	if !ok {
		return false
	}
	if !admin {
		writeApprovalError(w, http.StatusForbidden, "admin_role_required",
			"only a portal admin can "+what+" the "+def.Label+" report; your role is "+role, nil)
		return false
	}
	return true
}

// hiddenReportTypesFor returns the report types the caller must not see in
// the report history: none for an admin, every admin-only type otherwise.
func hiddenReportTypesFor(w http.ResponseWriter, r *http.Request, lookup portalRoleLookup, id portalauth.Identity, logger *slog.Logger) ([]string, bool) {
	adminOnly := report.AdminOnlyReportTypes()
	if len(adminOnly) == 0 {
		return adminOnly, true
	}
	admin, _, ok := portalReportCallerIsAdmin(w, r, lookup, id, logger)
	if !ok {
		return nil, false
	}
	if admin {
		return []string{}, true
	}
	return adminOnly, true
}
