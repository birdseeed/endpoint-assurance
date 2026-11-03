package portalauth

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Portal roles (PAT-2007, ruled 2026-09-24; owner added by PAT-1883).
//
//   - owner: everything an admin can do, and the only role that manages who
//     has access to the tenant (invitations, role changes, disabling a
//     member). The first verified person to create an organisation is its
//     owner; an operator can designate one for an existing tenant.
//   - admin: may write (software approval state, device decisions, schedules,
//     enrolment credentials and so on).
//   - viewer: read-only. The default for every new portal_users row and the
//     only role a domain-matched identity (PAT-127, no portal_users row) can
//     hold.
//
// Handlers never compare against a role name. They ask CanWrite or IsOwner,
// so a role added later is decided here once and cannot be forgotten in one
// handler.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// ValidRole reports whether role is one of the portal roles a portal_users
// row may hold.
func ValidRole(role string) bool {
	return role == RoleOwner || role == RoleAdmin || role == RoleViewer
}

// CanWrite reports whether role may make the portal's admin-level writes and
// read its admin-only data: an owner or an admin. Anything else, including a
// role this binary does not know, may not.
func CanWrite(role string) bool { return role == RoleOwner || role == RoleAdmin }

// IsOwner reports whether role may manage who has access to the tenant.
func IsOwner(role string) bool { return role == RoleOwner }

// OwnerAssignable reports whether role is one an owner may hand out, through
// an invitation or a role change: admin or viewer. Never owner: ownership is
// not granted through the portal (transfer is out of scope, PAT-1883).
func OwnerAssignable(role string) bool { return role == RoleAdmin || role == RoleViewer }

// RoleQuerier is satisfied by *pgxpool.Pool and pgx.Tx.
type RoleQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DBRole resolves the caller's role for the tenant the middleware already
// resolved. It is read at the point of use (inside the write transaction
// for a write) rather than cached on Identity, so a demotion or disable
// takes effect on the next request.
//
// The row must be active, belong to tenantID and sit on a live tenant.
// Anything else (no row because the identity resolved through an email
// domain, a disabled row, a row for another tenant) is RoleViewer: the
// fallback is the least privileged role, never admin or owner. lock takes
// FOR SHARE on the portal_users row so a concurrent demotion cannot commit
// between the check and the write it gates.
func DBRole(ctx context.Context, q RoleQuerier, email, tenantID string, lock bool) (string, error) {
	// PAT-2257: the service identity (and anything else with no email) never
	// matches a portal_users row, so it is never more than a viewer here.
	if strings.TrimSpace(email) == "" {
		return RoleViewer, nil
	}
	sql := `
		SELECT pu.role
		FROM portal_users pu
		JOIN tenants t ON t.id = pu.tenant_id
		WHERE pu.email = lower(btrim($1))
		  AND pu.tenant_id = $2::uuid
		  AND pu.disabled_at IS NULL
		  AND t.revoked_at IS NULL`
	if lock {
		sql += ` FOR SHARE OF pu`
	}
	var role string
	err := q.QueryRow(ctx, sql, email, tenantID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleViewer, nil
	}
	if err != nil {
		return "", err
	}
	if !ValidRole(role) {
		return RoleViewer, nil
	}
	return role, nil
}
