package handlers

// Self-service organisation sign-up and access management (PAT-1883).
//
// Two groups of routes, both on the public listener, both behind the feature
// flag SELF_SERVICE_SIGNUP_ENABLED (default off: every route here is 404).
//
// Pre-membership (/v1/portal/signup, portalauth.SignupMiddleware). The caller
// is a person with a verified Cloudflare Access email and, possibly, no
// tenant yet:
//
//	GET  /v1/portal/signup/state                           what this person can do
//	POST /v1/portal/signup/organisation                    create an organisation, become its owner
//	POST /v1/portal/signup/invitations/{invitationID}/accept  join the organisation that invited them
//
// Access management (/v1/portal/access, the ordinary portalauth.Middleware,
// so the caller is a member and the tenant comes from their identity):
//
//	GET  /v1/portal/access                                 members and invitations (owner, admin)
//	POST /v1/portal/access/invitations                     invite someone (owner)
//	POST /v1/portal/access/invitations/{invitationID}/revoke  (owner)
//	PUT  /v1/portal/access/members/{memberEmail}/role      (owner)
//	POST /v1/portal/access/members/{memberEmail}/disable   (owner)
//	POST /v1/portal/access/members/{memberEmail}/enable    (owner)
//
// Rules that hold for every route here:
//
//   - Identity is the verified JWT email and nothing else. No body, query or
//     header names the caller or a tenant. A request body is decoded strictly,
//     as on every other portal write (decodeStrictJSON): a key the route does
//     not define, including a tenant id, an email, a role or a case or
//     Unicode-fold variant of a real key, is 400 and changes nothing. A route
//     that takes no input accepts no body, {} or a bare JSON null (the shared
//     requireEmptyOrEmptyObject helper) and refuses anything else.
//   - The sign-up handlers read only a portalauth.Applicant and never a
//     tenant id from the request. The access handlers read only a
//     portalauth.Identity. Neither can serve the other's caller.
//   - An invitation id or member address that belongs to another tenant
//     answers exactly as one that does not exist.
//   - Creating an invitation looks at this tenant only, so it cannot be used
//     to learn whether an address is known to another tenant.
//   - Every change writes its portal_access_audit row in the same
//     transaction as the change.
//   - Nothing here sends email.
//
// The rate limiters are in memory, like every limiter in this service: they
// reset on restart and are per process.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

const (
	signupMaxBodyBytes = 4 << 10

	organisationNameMinChars = 2
	organisationNameMaxChars = 80
	// organisationNameMinLettersOrDigits: a name of punctuation or symbols
	// alone reads as blank or as decoration, not as a name.
	organisationNameMinLettersOrDigits = 2

	// maxPendingInvitations is how many live (pending and unexpired)
	// invitations one tenant may have at a time.
	maxPendingInvitations = 50
	// accessListInvitationCap bounds GET /v1/portal/access: the newest
	// invitations, whatever their state.
	accessListInvitationCap = 500
	// signupStateInvitationCap bounds the invitations offered to one person.
	signupStateInvitationCap = 50

	inviteEmailMaxBytes = 254

	defaultInvitationTTL               = 168 * time.Hour
	defaultInvitationsPerTenantPerHour = 20
	defaultOrgCreationsPerHour         = 20

	// tenantCreatedViaSelfService is tenants.created_via for a tenant made by
	// POST /v1/portal/signup/organisation (migration 0229).
	tenantCreatedViaSelfService = "self_service"
)

// Access audit actions (portal_access_audit.action, migration 0230).
const (
	accessAuditOrganisationCreated = "organisation_created"
	accessAuditInvitationCreated   = "invitation_created"
	accessAuditInvitationAccepted  = "invitation_accepted"
	accessAuditInvitationRevoked   = "invitation_revoked"
	accessAuditRoleChanged         = "role_changed"
	accessAuditMemberDisabled      = "member_disabled"
	accessAuditMemberEnabled       = "member_enabled"
)

// PortalSignupConfig configures self-service sign-up. The zero value is the
// feature switched off with every limit at its default.
type PortalSignupConfig struct {
	// Enabled is SELF_SERVICE_SIGNUP_ENABLED. When false every route this
	// feature adds answers 404.
	Enabled bool
	// InvitationTTL is how long an invitation can be accepted for
	// (PORTAL_INVITATION_TTL_HOURS, default 168 hours).
	InvitationTTL time.Duration
	// InvitationsPerTenantPerHour caps invitations one tenant can create per
	// hour (PORTAL_INVITATIONS_PER_HOUR, default 20).
	InvitationsPerTenantPerHour int
	// OrgCreationsPerHour is the ceiling on organisations created in any hour
	// across every caller (SIGNUP_ORG_CREATIONS_PER_HOUR, default 20). It
	// counts tenants that were created, not requests: see orgCeiling.
	//
	// There is deliberately no per-client-address limit beside it. The portal
	// calls this API from its own server, so every sign-up reaches the
	// platform from the portal server's address: a per-address bucket would
	// be one more global cap under another name, and a lower one. Telling
	// clients apart would need the portal to forward the browser's address,
	// and the platform does not trust the portal for that.
	OrgCreationsPerHour int
}

// withDefaults fills every unset limit. A zero or negative value is never
// "no limit".
func (c PortalSignupConfig) withDefaults() PortalSignupConfig {
	if c.InvitationTTL <= 0 {
		c.InvitationTTL = defaultInvitationTTL
	}
	if c.InvitationsPerTenantPerHour <= 0 {
		c.InvitationsPerTenantPerHour = defaultInvitationsPerTenantPerHour
	}
	if c.OrgCreationsPerHour <= 0 {
		c.OrgCreationsPerHour = defaultOrgCreationsPerHour
	}
	return c
}

// PortalSignup holds the sign-up and access-management handlers and their
// limiters. Every handler it returns is gated on cfg.Enabled.
type PortalSignup struct {
	pool *pgxpool.Pool
	cfg  PortalSignupConfig

	// inviteRL: invitations created per tenant per hour.
	inviteRL *ratelimit.TenantLimiter
	// orgCeiling: organisations created per hour by everyone.
	orgCeiling *orgCeiling
}

// NewPortalSignup builds the handlers. When the feature is off no limiter is
// created: no handler gets far enough to use one.
func NewPortalSignup(pool *pgxpool.Pool, cfg PortalSignupConfig) *PortalSignup {
	s := &PortalSignup{pool: pool, cfg: cfg.withDefaults()}
	if s.cfg.Enabled {
		n := s.cfg.InvitationsPerTenantPerHour
		s.inviteRL = ratelimit.New(ratelimit.Config{RPM: n, Burst: n, Period: time.Hour})
		s.orgCeiling = newOrgCeiling(s.cfg.OrgCreationsPerHour, time.Hour)
	}
	return s
}

// gated wraps a handler so that it answers 404, with the body an unmounted
// route gives, while the feature is off. The check is in the handler rather
// than in the route table so that a disabled route cannot be reached by
// calling the handler directly either (the FEEDBACK_ENABLED model).
//
// The route stays in the table, so a disabled route is not identical to an
// unmounted one: the router answers 405 for a wrong method, and whatever the
// group's middleware decides (503, 401, 429, the service identity's 403, a
// non-member's 403 in the tenant group) is decided before this runs.
func (s *PortalSignup) gated(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s == nil || !s.cfg.Enabled {
			http.NotFound(w, r)
			return
		}
		fn(w, r)
	}
}

// Pre-membership routes.
func (s *PortalSignup) StateHandler() http.HandlerFunc { return s.gated(s.state) }
func (s *PortalSignup) CreateOrganisationHandler() http.HandlerFunc {
	return s.gated(s.createOrganisation)
}
func (s *PortalSignup) AcceptInvitationHandler() http.HandlerFunc {
	return s.gated(s.acceptInvitation)
}

// Access-management routes.
func (s *PortalSignup) AccessListHandler() http.HandlerFunc { return s.gated(s.accessList) }
func (s *PortalSignup) InvitationCreateHandler() http.HandlerFunc {
	return s.gated(s.createInvitation)
}
func (s *PortalSignup) InvitationRevokeHandler() http.HandlerFunc {
	return s.gated(s.revokeInvitation)
}
func (s *PortalSignup) MemberRoleHandler() http.HandlerFunc {
	return s.gated(s.memberWrite(memberSetRole))
}
func (s *PortalSignup) MemberDisableHandler() http.HandlerFunc {
	return s.gated(s.memberWrite(memberDisable))
}
func (s *PortalSignup) MemberEnableHandler() http.HandlerFunc {
	return s.gated(s.memberWrite(memberEnable))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// signupApplicant pulls the verified applicant from the context. A miss means
// the route was mounted without portalauth.SignupMiddleware: fail closed.
func signupApplicant(w http.ResponseWriter, r *http.Request) (portalauth.Applicant, bool) {
	a, ok := portalauth.ApplicantFromContext(r.Context())
	if !ok {
		slog.Error("sign-up handler reached without an applicant: is SignupMiddleware missing?", "path", r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return portalauth.Applicant{}, false
	}
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))
	return a, true
}

// validOrganisationName trims the name and applies the rule: 2 to 80
// characters, at least two of them letters or digits, and none that a reader
// cannot see.
//
// The name is shown to the people its owner invites, who have nothing else to
// judge the invitation by, so it must not be blank-looking and must not
// render in another order than it was typed. Refused anywhere in the name:
//
//   - control characters (Cc);
//   - format characters (Cf): zero-width space, joiners and marks, the
//     bidirectional embeddings, overrides and isolates, the byte order mark,
//     the soft hyphen, tag characters;
//   - line and paragraph separators (Zl, Zp), private-use code points (Co)
//     and surrogates (Cs);
//   - Other_Default_Ignorable_Code_Point: characters that are letters or
//     marks by category and draw nothing, such as the Hangul fillers.
//
// A variation selector is none of these, so an emoji keeps its presentation.
// White space at either end is trimmed before the rule is applied, whatever
// kind it is.
func validOrganisationName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if !utf8.ValidString(name) {
		return "", false
	}
	chars, lettersOrDigits := 0, 0
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs,
			unicode.Other_Default_Ignorable_Code_Point) {
			return "", false
		}
		chars++
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			lettersOrDigits++
		}
	}
	return name, chars >= organisationNameMinChars && chars <= organisationNameMaxChars &&
		lettersOrDigits >= organisationNameMinLettersOrDigits
}

// normaliseInviteEmail lower-cases and validates an address to invite. It
// must be one bare address: no display name, no list, no comment.
func normaliseInviteEmail(raw string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > inviteEmailMaxBytes || !utf8.ValidString(email) || hasControlChars(email) {
		return "", false
	}
	if strings.ContainsAny(email, " \t<>(),;:\\\"[]") || strings.Count(email, "@") != 1 {
		return "", false
	}
	at := strings.IndexByte(email, '@')
	domain := email[at+1:]
	if at == 0 || !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", false
	}
	return email, true
}

// emailDomainOf is the part after the "@", or "".
func emailDomainOf(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// writeRateLimited answers 429 with Retry-After.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
	writeApprovalError(w, http.StatusTooManyRequests, "rate_limited", msg, nil)
}

// lockMembershipOf serialises everything that can give one address its
// membership (creating an organisation, accepting an invitation), so two
// simultaneous attempts by one person run one after the other. The
// portal_users primary key on email remains the arbiter; this only means the
// loser is refused before doing the work rather than after.
func lockMembershipOf(ctx context.Context, tx pgx.Tx, email string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "portal-membership|"+email)
	return err
}

// membershipOf reports whether email already has a portal_users row (in any
// tenant, enabled or not) and whether an active tenant has claimed its
// domain. Either means the address already belongs somewhere.
func membershipOf(ctx context.Context, q rowQuerier, email string) (hasRow, domainClaimed bool, err error) {
	err = q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM portal_users WHERE email = $1),
		       EXISTS (SELECT 1 FROM tenant_email_domains ted
		                 JOIN tenants t ON t.id = ted.tenant_id
		                WHERE ted.domain = $2 AND $2 <> ''
		                  AND ted.disabled_at IS NULL AND t.revoked_at IS NULL)
	`, email, emailDomainOf(email)).Scan(&hasRow, &domainClaimed)
	return hasRow, domainClaimed, err
}

// insertAccessAudit writes one portal_access_audit row inside tx.
func insertAccessAudit(ctx context.Context, tx pgx.Tx, tenantID, actor, action, subject string, oldRole, newRole, invitationID *string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO portal_access_audit (tenant_id, actor_email, action, subject_email, old_role, new_role, invitation_id)
		VALUES ($1::uuid, lower(btrim($2)), $3, lower(btrim($4)), $5, $6, $7::uuid)
	`, tenantID, actor, action, subject, oldRole, newRole, invitationID)
	return err
}

// insertMembership creates the portal_users row. A unique violation means
// the address already has one (the arbiter); a check violation means the
// address is not in the lower-case form the table requires.
func insertMembership(ctx context.Context, tx pgx.Tx, email, tenantID, role string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, $3)
	`, email, tenantID, role)
	return err
}

// signupBeforeMembershipInsert is a test seam, nil in production. It runs
// after every check has passed and immediately before the portal_users
// insert, in both organisation creation and invitation acceptance, so a test
// can give the address a membership at the one moment those checks cannot
// see and prove that the primary key on email still refuses.
var signupBeforeMembershipInsert func(ctx context.Context, email string)

func pgErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

const (
	pgUniqueViolation = "23505"
	pgCheckViolation  = "23514"
)

// portal_users.disabled_by (migration 0229): who disabled a member.
const (
	disabledByOperator = "operator"
	disabledByOwner    = "owner"
)

// effectiveDisabledBy is who a member row counts as disabled by: nil when it
// is enabled, otherwise the stored marker. A disabled row with no marker was
// disabled before the column existed, when only an operator could have done
// it through a route that still exists, so it counts as the operator's.
func effectiveDisabledBy(disabledAt *time.Time, stored *string) *string {
	if disabledAt == nil {
		return nil
	}
	if stored == nil || *stored != disabledByOwner {
		by := disabledByOperator
		return &by
	}
	by := disabledByOwner
	return &by
}

// errNoActiveOwner is ensureActiveOwnerRemains' refusal.
var errNoActiveOwner = errors.New("tenant would be left with no active owner")

// ensureActiveOwnerRemains is the last check before an access change
// commits: the tenant must still have at least one enabled owner. The route
// rules already make that so (the caller is an enabled owner whose row is
// held FOR SHARE, and no route changes an owner), so this never fires in
// normal operation. It is here so that a later change to those rules cannot
// strand a tenant without the transaction being refused.
func ensureActiveOwnerRemains(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var owners int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM portal_users
		WHERE tenant_id = $1::uuid AND role = $2 AND disabled_at IS NULL
	`, tenantID, portalauth.RoleOwner).Scan(&owners); err != nil {
		return err
	}
	if owners < 1 {
		return errNoActiveOwner
	}
	return nil
}

// requirePortalOwner re-reads the caller's role inside tx, holding the
// portal_users row FOR SHARE so a concurrent demotion or disable waits for
// this write. It writes the 403 or 500 itself and returns false when the
// caller is not an owner.
func requirePortalOwner(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, id portalauth.Identity, what string, logger *slog.Logger) bool {
	role, err := portalauth.DBRole(ctx, tx, id.Email, id.TenantID, true)
	if err != nil {
		logger.Error("role lookup failed", "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		return false
	}
	if !portalauth.IsOwner(role) {
		writeApprovalError(w, http.StatusForbidden, "owner_role_required",
			"only the owner of this organisation can "+what+"; your role is "+role, nil)
		return false
	}
	return true
}

func writeSignupJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// GET /v1/portal/signup/state
// ---------------------------------------------------------------------------

type signupInvitation struct {
	ID               string `json:"id"`
	OrganisationName string `json:"organisation_name"`
	// InvitedBy is the verified address of the owner who sent the invitation.
	// The organisation's name is whatever that owner typed; this is the one
	// thing the invitee is shown that the inviter did not choose.
	InvitedBy string    `json:"invited_by"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type signupStateResp struct {
	Email                 string             `json:"email"`
	Member                bool               `json:"member"`
	CanCreateOrganisation bool               `json:"can_create_organisation"`
	PendingInvitations    []signupInvitation `json:"pending_invitations"`
}

// state answers, for the caller's own verified email only: are they already
// a member of a tenant, may they create an organisation, and which live
// invitations are addressed to them. Each invitation names the organisation
// and the owner who sent it (invited_by): an invitation nobody asked for is
// then judged by a verified address, not only by a name its sender chose.
// An invitation whose sender is no longer an enabled owner of that tenant is
// not offered, because acceptInvitation would refuse it (inviterStillOwner).
func (s *PortalSignup) state(w http.ResponseWriter, r *http.Request) {
	a, ok := signupApplicant(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_signup_state")
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}

	resp := signupStateResp{Email: a.Email, PendingInvitations: []signupInvitation{}}
	// member: exactly what the tenant middleware would decide for this person.
	switch _, err := portalauth.DBLookup(s.pool)(ctx, a.Email); {
	case err == nil:
		resp.Member = true
	case !errors.Is(err, portalauth.ErrNoPortalUser):
		fail("membership lookup failed", err)
		return
	}
	hasRow, claimed, err := membershipOf(ctx, s.pool, a.Email)
	if err != nil {
		fail("membership check failed", err)
		return
	}
	storable, err := signupEmailStorable(ctx, s.pool, a.Email)
	if err != nil {
		fail("email check failed", err)
		return
	}
	resp.CanCreateOrganisation = !hasRow && !claimed && storable

	rows, err := s.pool.Query(ctx, `
		SELECT i.id::text, t.name, i.invited_by_email, i.role, i.expires_at
		FROM portal_invitations i
		JOIN tenants t ON t.id = i.tenant_id
		WHERE i.email = $1 AND i.status = 'pending' AND i.expires_at > now() AND t.revoked_at IS NULL
		  AND EXISTS (SELECT 1 FROM portal_users pu
		               WHERE pu.email = i.invited_by_email AND pu.tenant_id = i.tenant_id
		                 AND pu.role = $3 AND pu.disabled_at IS NULL)
		ORDER BY i.created_at DESC, i.id
		LIMIT $2
	`, a.Email, signupStateInvitationCap, portalauth.RoleOwner)
	if err != nil {
		fail("invitation lookup failed", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var inv signupInvitation
		if err := rows.Scan(&inv.ID, &inv.OrganisationName, &inv.InvitedBy, &inv.Role, &inv.ExpiresAt); err != nil {
			fail("invitation scan failed", err)
			return
		}
		resp.PendingInvitations = append(resp.PendingInvitations, inv)
	}
	if err := rows.Err(); err != nil {
		fail("invitation lookup failed", err)
		return
	}
	writeSignupJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// POST /v1/portal/signup/organisation
// ---------------------------------------------------------------------------

type createOrganisationReq struct {
	Name string `json:"name"`
}

type signupMembershipResp struct {
	TenantID         string `json:"tenant_id"`
	OrganisationName string `json:"organisation_name"`
	Role             string `json:"role"`
}

// createOrganisation creates a tenant and makes the caller its owner, in one
// transaction. The body is {"name"} and nothing else: any other key is 400
// before any database work. Single use per verified email and safe under
// concurrency:
//
//   - a person who already has a portal_users row, or whose email domain an
//     active tenant has claimed, is refused 409 before anything is created;
//   - simultaneous requests by one person are serialised on an advisory lock
//     keyed by their email, so all but the first see that row and are refused;
//   - the portal_users primary key on email is the final arbiter: if any other
//     writer got there first the insert fails, everything rolls back and the
//     answer is the same 409.
//
// The ceiling on organisations created per hour counts tenants that were
// created (orgCeiling). A request takes a slot only once every check that
// needs no provisioning has passed, so a person who can never succeed (they
// already belong somewhere, sent an invalid name, or have an address the
// table could not store) takes none; and it gives the slot back on every
// outcome except a committed tenant, so a request that gets further and then
// creates nothing (the primary key refuses it, the database fails, the caller
// goes away, the handler panics) cannot be repeated to hold sign-up shut for
// everyone else. A caller who finds the ceiling full is refused before any
// provisioning work. The per-email limit is the middleware's. There is no
// per-client-address limit: see PortalSignupConfig.
//
// The tenant is provisioned by provisionTenant, the same function
// POST /admin/tenants uses, with tenants.contact_email set to the caller's
// verified email. The tenant-level ingest credential it generates is not
// returned and not logged: endpoints enrol through enrolment tokens and
// keys, which issue per-device credentials. No trial or subscription state
// is set (PAT-1886).
func (s *PortalSignup) createOrganisation(w http.ResponseWriter, r *http.Request) {
	a, ok := signupApplicant(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_signup_organisation")
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}
	alreadyMember := func() {
		writeApprovalError(w, http.StatusConflict, "already_member",
			"this email address already belongs to an organisation", nil)
	}
	unsupportedEmail := func() {
		writeApprovalError(w, http.StatusBadRequest, "unsupported_email",
			"this email address cannot be used to create an organisation", nil)
	}

	body, ok := readLimitedBody(w, r, signupMaxBodyBytes)
	if !ok {
		return
	}
	var req createOrganisationReq
	if err := decodeStrictJSON(body, &req); err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", `body must be {"name": "..."} with no other fields`, nil)
		return
	}
	name, valid := validOrganisationName(req.Name)
	if !valid {
		writeApprovalError(w, http.StatusBadRequest, "invalid_name",
			"name must be 2 to 80 characters, at least two of them letters or digits, with no control or invisible characters", nil)
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		fail("begin tx failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if err := lockMembershipOf(ctx, tx, a.Email); err != nil {
		fail("membership lock failed", err)
		return
	}
	hasRow, claimed, err := membershipOf(ctx, tx, a.Email)
	if err != nil {
		fail("membership check failed", err)
		return
	}
	if hasRow || claimed {
		alreadyMember()
		return
	}
	// What portal_users would refuse is refused here, before a slot is taken.
	storable, err := signupEmailStorable(ctx, tx, a.Email)
	if err != nil {
		fail("email check failed", err)
		return
	}
	if !storable {
		unsupportedEmail()
		return
	}

	// From here the request will try to create a tenant, so it holds a slot
	// under the ceiling. The slot is given back on every way out of this
	// function except a committed tenant: a refusal, an error, a panic, a
	// caller who went away.
	slot, retryAfter := s.orgCeiling.reserve()
	if slot == nil {
		logger.Warn("organisation creation refused: ceiling reached")
		writeRateLimited(w, retryAfter, "sign-up is busy; try again later")
		return
	}
	defer slot.release()

	// The tenant's contact is the owner: the verified JWT email, never
	// anything from the request. Alert and report mail is addressed to
	// tenants.contact_email, so without this a self-service tenant would
	// have nobody to send it to until an operator set one.
	created, err := provisionTenant(ctx, tx, tenantProvision{Name: name, ContactEmail: a.Email})
	if err != nil {
		fail("tenant provisioning failed", err)
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET created_via = $2 WHERE id = $1::uuid`,
		created.TenantID, tenantCreatedViaSelfService); err != nil {
		fail("tenant marker update failed", err)
		return
	}
	if signupBeforeMembershipInsert != nil {
		signupBeforeMembershipInsert(ctx, a.Email)
	}
	if err := insertMembership(ctx, tx, a.Email, created.TenantID, portalauth.RoleOwner); err != nil {
		switch pgErrorCode(err) {
		case pgUniqueViolation:
			// Someone else gave this address a membership first. The deferred
			// rollback discards the tenant this transaction built.
			alreadyMember()
		case pgCheckViolation:
			// signupEmailStorable asked the same question; kept so that a
			// rule added to the table later is still a refusal, not a 500.
			unsupportedEmail()
		default:
			fail("owner insert failed", err)
		}
		return
	}
	owner := portalauth.RoleOwner
	if err := insertAccessAudit(ctx, tx, created.TenantID, a.Email, accessAuditOrganisationCreated, a.Email, nil, &owner, nil); err != nil {
		fail("access audit insert failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		// The one outcome the error cannot tell: the tenant may exist (only
		// the acknowledgement was lost) or not.
		if s.tenantExists(created.TenantID) {
			slot.keep()
		}
		fail("commit failed", err)
		return
	}
	slot.keep()

	logger.Info("self-service organisation created", "tenant_id", created.TenantID, "email", a.Email)
	writeSignupJSON(w, http.StatusCreated, signupMembershipResp{
		TenantID: created.TenantID, OrganisationName: name, Role: portalauth.RoleOwner,
	})
}

// tenantExists answers, after a COMMIT that returned an error, whether the
// tenant was created all the same. It asks on a context the caller cannot
// cancel. If it cannot find out it says yes: the ceiling would rather count a
// tenant that is not there than miss one that is.
func (s *PortalSignup) tenantExists(tenantID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1::uuid)`, tenantID).Scan(&exists); err != nil {
		return true
	}
	return exists
}

// ---------------------------------------------------------------------------
// POST /v1/portal/signup/invitations/{invitationID}/accept
// ---------------------------------------------------------------------------

// acceptInvitation makes the caller a member of the tenant that invited
// them, with the invited role. The invitation is found by id AND the caller's
// verified email, so an invitation addressed to someone else is not found:
// the same 404 as an id that does not exist. It must be pending and
// unexpired, and it is single use: the row is locked FOR UPDATE and marked
// accepted in the transaction that creates the membership. The owner who
// sent it must still be an enabled owner of that tenant (inviterStillOwner);
// otherwise it answers as a withdrawn invitation does. It takes no body:
// anything but an empty body or {} is 400 before any database work, the same
// for an id that exists and one that does not.
func (s *PortalSignup) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	a, ok := signupApplicant(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_signup_accept")
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}
	notFound := func() {
		writeApprovalError(w, http.StatusNotFound, "not_found", "invitation not found", nil)
	}
	if !requireEmptyOrEmptyObject(w, r) {
		return
	}
	invitationID := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "invitationID")))
	if !looksLikeUUID(invitationID) {
		notFound()
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		fail("begin tx failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if err := lockMembershipOf(ctx, tx, a.Email); err != nil {
		fail("membership lock failed", err)
		return
	}
	var tenantID, tenantName, role, status, invitedBy string
	var expired, tenantRevoked bool
	err = tx.QueryRow(ctx, `
		SELECT i.tenant_id::text, t.name, i.role, i.status, i.expires_at <= now(), t.revoked_at IS NOT NULL, i.invited_by_email
		FROM portal_invitations i
		JOIN tenants t ON t.id = i.tenant_id
		WHERE i.id = $1::uuid AND i.email = $2
		FOR UPDATE OF i
	`, invitationID, a.Email).Scan(&tenantID, &tenantName, &role, &status, &expired, &tenantRevoked, &invitedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		notFound()
		return
	}
	if err != nil {
		fail("invitation lookup failed", err)
		return
	}
	switch {
	case tenantRevoked:
		// The organisation is no longer live; there is nothing to join.
		notFound()
		return
	case status == "accepted":
		writeApprovalError(w, http.StatusGone, "invitation_accepted", "this invitation has already been used", nil)
		return
	case status == "revoked":
		// The same body as the inviter-lost-authority refusal below.
		writeApprovalError(w, http.StatusGone, "invitation_revoked", "this invitation has been withdrawn", nil)
		return
	case status != "pending":
		fail("invitation in an unknown state", errors.New(status))
		return
	case expired:
		writeApprovalError(w, http.StatusGone, "invitation_expired", "this invitation has expired", nil)
		return
	case !portalauth.OwnerAssignable(role):
		// The table cannot hold another role; never grant one if it somehow does.
		fail("invitation carries a role that cannot be granted", errors.New(role))
		return
	}
	// An invitation carries its sender's authority, and only for as long as
	// they have it. If the owner who sent it has since been disabled, demoted
	// or moved to another tenant, it grants nothing: the same answer as an
	// invitation that was withdrawn. The stored status is left pending.
	stillOwner, err := inviterStillOwner(ctx, tx, invitedBy, tenantID)
	if err != nil {
		fail("inviter lookup failed", err)
		return
	}
	if !stillOwner {
		writeApprovalError(w, http.StatusGone, "invitation_revoked", "this invitation has been withdrawn", nil)
		return
	}

	alreadyMember := func() {
		writeApprovalError(w, http.StatusConflict, "already_member",
			"this email address already belongs to an organisation", nil)
	}
	var hasRow bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM portal_users WHERE email = $1)`, a.Email).Scan(&hasRow); err != nil {
		fail("membership check failed", err)
		return
	}
	if hasRow {
		alreadyMember()
		return
	}
	if signupBeforeMembershipInsert != nil {
		signupBeforeMembershipInsert(ctx, a.Email)
	}
	if err := insertMembership(ctx, tx, a.Email, tenantID, role); err != nil {
		switch pgErrorCode(err) {
		case pgUniqueViolation:
			alreadyMember()
		case pgCheckViolation:
			writeApprovalError(w, http.StatusBadRequest, "unsupported_email",
				"this email address cannot be used to accept an invitation", nil)
		default:
			fail("member insert failed", err)
		}
		return
	}
	tag, err := tx.Exec(ctx, `
		UPDATE portal_invitations SET status = 'accepted', accepted_at = now()
		WHERE id = $1::uuid AND status = 'pending'
	`, invitationID)
	if err != nil {
		fail("invitation update failed", err)
		return
	}
	if tag.RowsAffected() != 1 {
		fail("invitation was not pending at update", errors.New("no row updated"))
		return
	}
	if err := insertAccessAudit(ctx, tx, tenantID, a.Email, accessAuditInvitationAccepted, a.Email, nil, &role, &invitationID); err != nil {
		fail("access audit insert failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail("commit failed", err)
		return
	}

	logger.Info("portal invitation accepted", "tenant_id", tenantID, "invitation_id", invitationID, "role", role, "email", a.Email)
	writeSignupJSON(w, http.StatusOK, signupMembershipResp{TenantID: tenantID, OrganisationName: tenantName, Role: role})
}

// inviterStillOwner reports whether the address that sent an invitation is,
// now, an enabled owner of the tenant it invited to. The row is held
// FOR SHARE until the accepting transaction ends, as requirePortalOwner holds
// a caller's, so a disable or demotion that is committing at the same moment
// either came first and is seen here, or waits for the acceptance.
func inviterStillOwner(ctx context.Context, tx pgx.Tx, invitedBy, tenantID string) (bool, error) {
	var one int
	err := tx.QueryRow(ctx, `
		SELECT 1 FROM portal_users
		WHERE email = $1 AND tenant_id = $2::uuid AND role = $3 AND disabled_at IS NULL
		FOR SHARE
	`, invitedBy, tenantID, portalauth.RoleOwner).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ---------------------------------------------------------------------------
// GET /v1/portal/access
// ---------------------------------------------------------------------------

type accessMember struct {
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
	// DisabledBy is "operator" or "owner" on a disabled member and null on an
	// active one. An owner can enable only a member an owner disabled.
	DisabledBy *string `json:"disabled_by"`
}

type accessInvitation struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	InvitedBy  string     `json:"invited_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	RevokedBy  *string    `json:"revoked_by"`
}

type accessListResp struct {
	Role                 string             `json:"role"`
	Members              []accessMember     `json:"members"`
	Invitations          []accessInvitation `json:"invitations"`
	MembersTotal         int64              `json:"members_total"`
	MembersLimit         int                `json:"members_limit"`
	MembersOffset        int                `json:"members_offset"`
	MembersTruncated     bool               `json:"members_truncated"`
	InvitationsTotal     int64              `json:"invitations_total"`
	InvitationsLimit     int                `json:"invitations_limit"`
	InvitationsTruncated bool               `json:"invitations_truncated"`
}

// invitationStatus is the status shown for an invitation: its stored status,
// except that a pending invitation past expires_at reads as expired. Expiry
// is never stored.
func invitationStatus(stored string, expired bool) string {
	if stored == "pending" && expired {
		return "expired"
	}
	return stored
}

// accessList returns the caller's tenant's members and invitations. Owner
// and admin may read it; a viewer, a domain-matched identity and the service
// identity are refused (the list is personal data: who works here).
func (s *PortalSignup) accessList(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_access_list", "tenant_id", id.TenantID)
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}
	role, err := portalauth.DBRole(ctx, s.pool, id.Email, id.TenantID, false)
	if err != nil {
		fail("role lookup failed", err)
		return
	}
	if !portalauth.CanWrite(role) {
		writeApprovalError(w, http.StatusForbidden, "admin_role_required",
			"only an owner or admin can see who has access; your role is "+role, nil)
		return
	}

	// ParseQuery reports malformed escaping rather than silently dropping an
	// argument as URL.Query does. No caller may select a tenant here.
	query, err := url.ParseQuery(r.URL.RawQuery)
	limit, offset := 100, 0
	valid := err == nil
	for key, values := range query {
		if len(values) != 1 || (key != "limit" && key != "offset") {
			valid = false
			break
		}
		value := values[0]
		// Accept only decimal digits, not signs, fractions or whitespace.
		if value == "" || strings.IndexFunc(value, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			valid = false
			break
		}
		n, parseErr := strconv.ParseInt(value, 10, 32)
		if parseErr != nil || (key == "limit" && (n < 1 || n > 500)) {
			valid = false
			break
		}
		if key == "limit" {
			limit = int(n)
		} else {
			offset = int(n)
		}
	}
	if !valid {
		writeApprovalError(w, http.StatusBadRequest, "invalid_pagination", "use limit 1..500 and offset 0..2147483647 exactly once", nil)
		return
	}
	// Counts and both lists describe one committed snapshot, even when another
	// request changes membership or invitations between these queries.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		fail("access snapshot failed", err)
		return
	}
	defer tx.Rollback(ctx)
	resp := accessListResp{Role: role, Members: []accessMember{}, Invitations: []accessInvitation{},
		MembersLimit: limit, MembersOffset: offset, InvitationsLimit: accessListInvitationCap}
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid),
		(SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid)`, id.TenantID).
		Scan(&resp.MembersTotal, &resp.InvitationsTotal); err != nil {
		fail("access totals failed", err)
		return
	}
	rows, err := tx.Query(ctx, `
		SELECT email, role, created_at, disabled_at, disabled_by
		FROM portal_users WHERE tenant_id = $1::uuid
		ORDER BY created_at, email
		LIMIT $2 OFFSET $3
	`, id.TenantID, limit, offset)
	if err != nil {
		fail("member list failed", err)
		return
	}
	for rows.Next() {
		var m accessMember
		var storedBy *string
		if err := rows.Scan(&m.Email, &m.Role, &m.CreatedAt, &m.DisabledAt, &storedBy); err != nil {
			rows.Close()
			fail("member scan failed", err)
			return
		}
		m.Status = "active"
		if m.DisabledAt != nil {
			m.Status = "disabled"
		}
		m.DisabledBy = effectiveDisabledBy(m.DisabledAt, storedBy)
		resp.Members = append(resp.Members, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fail("member list failed", err)
		return
	}

	rows, err = tx.Query(ctx, `
		SELECT id::text, email, role, status, expires_at <= now(), invited_by_email,
		       created_at, expires_at, accepted_at, revoked_at, revoked_by_email
		FROM portal_invitations WHERE tenant_id = $1::uuid
		ORDER BY created_at DESC, id
		LIMIT $2
	`, id.TenantID, accessListInvitationCap)
	if err != nil {
		fail("invitation list failed", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var inv accessInvitation
		var expired bool
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Status, &expired, &inv.InvitedBy,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt, &inv.RevokedAt, &inv.RevokedBy); err != nil {
			fail("invitation scan failed", err)
			return
		}
		inv.Status = invitationStatus(inv.Status, expired)
		resp.Invitations = append(resp.Invitations, inv)
	}
	if err := rows.Err(); err != nil {
		fail("invitation list failed", err)
		return
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		fail("access snapshot commit failed", err)
		return
	}
	resp.MembersTruncated = int64(len(resp.Members)) < resp.MembersTotal
	resp.InvitationsTruncated = int64(len(resp.Invitations)) < resp.InvitationsTotal
	writeSignupJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// POST /v1/portal/access/invitations
// ---------------------------------------------------------------------------

type createInvitationReq struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// createInvitation invites one address to the caller's tenant as admin or
// viewer. Owner only, and the role is checked before the body is read, so
// anyone else gets the same 403 whatever they send.
//
// It looks at the caller's tenant only: the address is refused if it is
// already a member here or already has a live invitation here, and never
// because of anything in another tenant. Whether the address belongs
// elsewhere is not this tenant's to know; the invitee finds out when they
// try to accept.
//
// A pending invitation that has expired would otherwise block the address
// for ever (one pending row per tenant and address), so inviting it again
// retires the expired one, recorded as a revocation by the inviting owner.
func (s *PortalSignup) createInvitation(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_access_invitation_create", "tenant_id", id.TenantID)
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		fail("begin tx failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if !requirePortalOwner(ctx, tx, w, id, "invite people", logger) {
		return
	}

	body, ok := readLimitedBody(w, r, signupMaxBodyBytes)
	if !ok {
		return
	}
	var req createInvitationReq
	if err := decodeStrictJSON(body, &req); err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", `body must be {"email": "...", "role": "admin" or "viewer"} with no other fields`, nil)
		return
	}
	email, valid := normaliseInviteEmail(req.Email)
	if !valid {
		writeApprovalError(w, http.StatusBadRequest, "invalid_email", "email must be one valid email address", nil)
		return
	}
	if !portalauth.OwnerAssignable(req.Role) {
		writeApprovalError(w, http.StatusBadRequest, "invalid_role", "role must be admin or viewer", nil)
		return
	}

	if allowed, retryAfter := s.inviteRL.Allow(id.TenantID); !allowed {
		writeRateLimited(w, retryAfter, "too many invitations created; try again later")
		return
	}

	// One invitation writer per tenant at a time, so the checks below and
	// the insert cannot interleave with another owner's.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "portal-invitations|"+id.TenantID); err != nil {
		fail("invitation lock failed", err)
		return
	}
	var memberHere bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM portal_users WHERE email = $1 AND tenant_id = $2::uuid)
	`, email, id.TenantID).Scan(&memberHere); err != nil {
		fail("member check failed", err)
		return
	}
	if memberHere {
		writeApprovalError(w, http.StatusConflict, "already_member", "this person is already a member of your organisation", nil)
		return
	}

	var staleID, staleRole string
	var staleExpired bool
	err = tx.QueryRow(ctx, `
		SELECT id::text, role, expires_at <= now() FROM portal_invitations
		WHERE tenant_id = $1::uuid AND email = $2 AND status = 'pending'
		FOR UPDATE
	`, id.TenantID, email).Scan(&staleID, &staleRole, &staleExpired)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		fail("pending invitation check failed", err)
		return
	case !staleExpired:
		writeApprovalError(w, http.StatusConflict, "invitation_pending", "this person already has a pending invitation", nil)
		return
	default:
		if _, err := tx.Exec(ctx, `
			UPDATE portal_invitations SET status = 'revoked', revoked_at = now(), revoked_by_email = lower(btrim($3))
			WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'
		`, staleID, id.TenantID, id.Email); err != nil {
			fail("expired invitation retire failed", err)
			return
		}
		if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditInvitationRevoked, email, &staleRole, nil, &staleID); err != nil {
			fail("access audit insert failed", err)
			return
		}
	}

	var live int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM portal_invitations
		WHERE tenant_id = $1::uuid AND status = 'pending' AND expires_at > now()
	`, id.TenantID).Scan(&live); err != nil {
		fail("pending invitation count failed", err)
		return
	}
	if live >= maxPendingInvitations {
		writeApprovalError(w, http.StatusConflict, "invitation_limit_reached",
			"your organisation has "+strconv.Itoa(maxPendingInvitations)+" pending invitations; revoke one or wait for one to be accepted", nil)
		return
	}

	inv := accessInvitation{Status: "pending"}
	if err := tx.QueryRow(ctx, `
		INSERT INTO portal_invitations (tenant_id, email, role, invited_by_email, expires_at)
		VALUES ($1::uuid, lower(btrim($2)), $3, lower(btrim($4)), now() + make_interval(secs => $5))
		RETURNING id::text, email, role, invited_by_email, created_at, expires_at
	`, id.TenantID, email, req.Role, id.Email, s.cfg.InvitationTTL.Seconds()).Scan(
		&inv.ID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
		fail("invitation insert failed", err)
		return
	}
	if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditInvitationCreated, inv.Email, nil, &inv.Role, &inv.ID); err != nil {
		fail("access audit insert failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail("commit failed", err)
		return
	}

	logger.Info("portal invitation created", "invitation_id", inv.ID, "role", inv.Role, "expires_at", inv.ExpiresAt, "email", id.Email)
	writeSignupJSON(w, http.StatusCreated, inv)
}

// ---------------------------------------------------------------------------
// POST /v1/portal/access/invitations/{invitationID}/revoke
// ---------------------------------------------------------------------------

// revokeInvitation withdraws a pending invitation (expired or not). Owner
// only. Revoking one that is already revoked is a no-op (changed false); an
// accepted one cannot be revoked, because the person is a member now and is
// disabled instead. An id that does not exist or belongs to another tenant
// is 404, indistinguishably. It takes no body: anything but an empty body or
// {} is 400.
func (s *PortalSignup) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_access_invitation_revoke", "tenant_id", id.TenantID)
	fail := func(msg string, err error) {
		logger.Error(msg, "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
	}
	notFound := func() {
		writeApprovalError(w, http.StatusNotFound, "not_found", "invitation not found", nil)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		fail("begin tx failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if !requirePortalOwner(ctx, tx, w, id, "revoke an invitation", logger) {
		return
	}
	if !requireEmptyOrEmptyObject(w, r) {
		return
	}
	invitationID := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "invitationID")))
	if !looksLikeUUID(invitationID) {
		notFound()
		return
	}

	var status, email, role string
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT status, email, role, revoked_at FROM portal_invitations
		WHERE id = $1::uuid AND tenant_id = $2::uuid
		FOR UPDATE
	`, invitationID, id.TenantID).Scan(&status, &email, &role, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		notFound()
		return
	}
	if err != nil {
		fail("invitation lookup failed", err)
		return
	}
	changed := false
	switch status {
	case "accepted":
		writeApprovalError(w, http.StatusConflict, "invitation_accepted",
			"this invitation has been accepted; disable the member instead", nil)
		return
	case "revoked":
	case "pending":
		var at time.Time
		if err := tx.QueryRow(ctx, `
			UPDATE portal_invitations SET status = 'revoked', revoked_at = now(), revoked_by_email = lower(btrim($3))
			WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'
			RETURNING revoked_at
		`, invitationID, id.TenantID, id.Email).Scan(&at); err != nil {
			fail("invitation revoke failed", err)
			return
		}
		if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditInvitationRevoked, email, &role, nil, &invitationID); err != nil {
			fail("access audit insert failed", err)
			return
		}
		revokedAt, changed = &at, true
	default:
		fail("invitation in an unknown state", errors.New(status))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail("commit failed", err)
		return
	}
	if changed {
		logger.Info("portal invitation revoked", "invitation_id", invitationID, "email", id.Email)
	}
	writeSignupJSON(w, http.StatusOK, map[string]any{"id": invitationID, "status": "revoked", "revoked_at": revokedAt, "changed": changed})
}

// ---------------------------------------------------------------------------
// Member writes: role, disable, enable
// ---------------------------------------------------------------------------

type memberOp int

const (
	memberSetRole memberOp = iota
	memberDisable
	memberEnable
)

func (op memberOp) what() string {
	switch op {
	case memberSetRole:
		return "change a member's role"
	case memberDisable:
		return "disable a member"
	default:
		return "enable a member"
	}
}

type memberRoleReq struct {
	Role string `json:"role"`
}

// memberEmailParam is the {memberEmail} path segment, percent-decoded exactly
// once, trimmed and lower-cased. "" when it cannot be an address.
//
// chi matches a request against r.URL.RawPath when net/url kept one, and
// against the already decoded r.URL.Path otherwise (Mux.routeHTTP). net/url
// keeps RawPath only when the path was not in its canonical encoding. So the
// parameter arrives still encoded in the first case ("a%40b.example") and
// decoded in the second: "x%2541y@d.example" is canonical, and reaches here
// as "x%41y@d.example". Decoding that again would make it "xAy@d.example",
// and a request naming one member would act on another. Decode only what is
// still encoded.
func memberEmailParam(r *http.Request) string {
	raw := chi.URLParam(r, "memberEmail")
	if r.URL.RawPath != "" {
		dec, err := url.PathUnescape(raw)
		if err != nil {
			return ""
		}
		raw = dec
	}
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 320 || !utf8.ValidString(email) || hasControlChars(email) {
		return ""
	}
	return email
}

// memberWrite serves the three owner-only writes on one member of the
// caller's tenant: PUT .../role, POST .../disable and POST .../enable. The
// role change takes {"role"} and nothing else; disable and enable take no
// body. In each case the owner check comes first, so anyone else gets the
// same 403 whatever they send.
//
// The member is looked up by address AND the caller's tenant, so an address
// that belongs to another tenant is not found: the same 404 as one nobody
// has. An owner cannot act on themselves or on another owner (ownership
// transfer is out of scope), which is also why these routes can never leave
// a tenant without an active owner; ensureActiveOwnerRemains checks it
// anyway before the commit.
//
// Who disabled a member is recorded in portal_users.disabled_by, and an owner
// can enable only a member an owner disabled. A member the operator disabled
// (or one disabled before the column existed) answers 409
// disabled_by_operator to enable, and an owner's disable of a member who is
// already disabled changes nothing, so it can never be used to take an
// operator's disable over and then undo it.
//
// Lock order: the caller's own row FOR SHARE (requirePortalOwner), then the
// target's row FOR UPDATE. The target is first read without a lock and
// refused if it is the caller or an owner, so no request ever asks for
// FOR UPDATE on an owner's row: two owners acting on each other at the same
// moment are both refused instead of deadlocking.
func (s *PortalSignup) memberWrite(op memberOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_access_member", "tenant_id", id.TenantID)
		fail := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}
		notFound := func() {
			writeApprovalError(w, http.StatusNotFound, "not_found", "member not found", nil)
		}

		tx, err := s.pool.Begin(ctx)
		if err != nil {
			fail("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalOwner(ctx, tx, w, id, op.what(), logger) {
			return
		}

		newRole := ""
		if op == memberSetRole {
			body, ok := readLimitedBody(w, r, signupMaxBodyBytes)
			if !ok {
				return
			}
			var req memberRoleReq
			if err := decodeStrictJSON(body, &req); err != nil {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", `body must be {"role": "admin" or "viewer"} with no other fields`, nil)
				return
			}
			if !portalauth.OwnerAssignable(req.Role) {
				writeApprovalError(w, http.StatusBadRequest, "invalid_role", "role must be admin or viewer", nil)
				return
			}
			newRole = req.Role
		} else if !requireEmptyOrEmptyObject(w, r) {
			// Disable and enable take no input.
			return
		}

		target := memberEmailParam(r)
		if target == "" {
			notFound()
			return
		}
		guard := func(role string) bool {
			switch {
			case target == strings.ToLower(strings.TrimSpace(id.Email)):
				writeApprovalError(w, http.StatusConflict, "cannot_change_own_access",
					"you cannot change your own access", nil)
			case portalauth.IsOwner(role):
				writeApprovalError(w, http.StatusConflict, "cannot_change_owner",
					"an owner's access cannot be changed here", nil)
			default:
				return true
			}
			return false
		}

		var role string
		err = tx.QueryRow(ctx, `
			SELECT role FROM portal_users WHERE email = $1 AND tenant_id = $2::uuid
		`, target, id.TenantID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			notFound()
			return
		}
		if err != nil {
			fail("member lookup failed", err)
			return
		}
		if !guard(role) {
			return
		}
		// Now lock it and decide again on what is actually there.
		var disabledAt *time.Time
		var storedBy *string
		err = tx.QueryRow(ctx, `
			SELECT role, disabled_at, disabled_by FROM portal_users WHERE email = $1 AND tenant_id = $2::uuid
			FOR UPDATE
		`, target, id.TenantID).Scan(&role, &disabledAt, &storedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			notFound()
			return
		}
		if err != nil {
			fail("member lock failed", err)
			return
		}
		if !guard(role) {
			return
		}

		changed, action := false, ""
		resp := map[string]any{"email": target}
		switch op {
		case memberSetRole:
			oldRole := role
			if oldRole != newRole {
				if _, err := tx.Exec(ctx, `
					UPDATE portal_users SET role = $3 WHERE email = $1 AND tenant_id = $2::uuid
				`, target, id.TenantID, newRole); err != nil {
					fail("role update failed", err)
					return
				}
				if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditRoleChanged, target, &oldRole, &newRole, nil); err != nil {
					fail("access audit insert failed", err)
					return
				}
				changed, action = true, accessAuditRoleChanged
			}
			resp["role"] = newRole
		case memberDisable:
			// A member who is already disabled stays exactly as they are,
			// whoever disabled them: an owner's request never takes over an
			// operator's disable, and never turns it into one the owner
			// could undo.
			if disabledAt == nil {
				var at time.Time
				by := disabledByOwner
				if err := tx.QueryRow(ctx, `
					UPDATE portal_users SET disabled_at = now(), disabled_by = $3
					WHERE email = $1 AND tenant_id = $2::uuid
					RETURNING disabled_at
				`, target, id.TenantID, by).Scan(&at); err != nil {
					fail("disable failed", err)
					return
				}
				if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditMemberDisabled, target, &role, &role, nil); err != nil {
					fail("access audit insert failed", err)
					return
				}
				disabledAt, storedBy, changed, action = &at, &by, true, accessAuditMemberDisabled
			}
			resp["disabled_at"] = disabledAt
			resp["disabled_by"] = effectiveDisabledBy(disabledAt, storedBy)
		case memberEnable:
			if disabledAt != nil {
				// Only an owner's disable is an owner's to undo. The row is
				// held FOR UPDATE, so an operator's disable either came first
				// and is seen here, or waits for this transaction.
				if by := effectiveDisabledBy(disabledAt, storedBy); by == nil || *by != disabledByOwner {
					writeApprovalError(w, http.StatusConflict, "disabled_by_operator",
						"this member was disabled by Patched support and cannot be enabled here", nil)
					return
				}
				if _, err := tx.Exec(ctx, `
					UPDATE portal_users SET disabled_at = NULL, disabled_by = NULL
					WHERE email = $1 AND tenant_id = $2::uuid
				`, target, id.TenantID); err != nil {
					fail("enable failed", err)
					return
				}
				if err := insertAccessAudit(ctx, tx, id.TenantID, id.Email, accessAuditMemberEnabled, target, &role, &role, nil); err != nil {
					fail("access audit insert failed", err)
					return
				}
				changed, action = true, accessAuditMemberEnabled
			}
			resp["disabled_at"] = nil
			resp["disabled_by"] = nil
		}
		resp["changed"] = changed

		if changed {
			if err := ensureActiveOwnerRemains(ctx, tx, id.TenantID); err != nil {
				if errors.Is(err, errNoActiveOwner) {
					writeApprovalError(w, http.StatusConflict, "last_owner",
						"an organisation must keep at least one active owner", nil)
					return
				}
				fail("owner check failed", err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			fail("commit failed", err)
			return
		}
		if changed {
			logger.Info("portal member access changed", "action", action, "email", id.Email)
		}
		writeSignupJSON(w, http.StatusOK, resp)
	}
}
