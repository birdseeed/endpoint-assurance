package handlers

// Declarations retain authored intent independently of device observations.
// Verified resolution links to the existing policy store and decision ledger.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/softwaregov"
)

type declarationRequest struct {
	Name          string  `json:"name"`
	Publisher     string  `json:"publisher"`
	Platform      string  `json:"platform"`
	Justification string  `json:"justification"`
	AliasID       *string `json:"alias_id"`
	MinVersion    *string `json:"min_version"`
	ReviewDate    *string `json:"review_date"`
}
type declarationAlias struct {
	ID         string `json:"alias_id"`
	ProductID  string `json:"product_id"`
	Name       string `json:"canonical_name"`
	Publisher  string `json:"vendor_name"`
	Platform   string `json:"platform"`
	Kind       string `json:"identity_kind"`
	Identifier string `json:"identity_value_normalized"`
	Companion  string `json:"companion_value_normalized"`
}

const declarationAliasColumns = `a.id::text,a.product_id::text,sp.canonical_name,sp.vendor_name,a.platform,a.identity_kind,a.identity_value_normalized,a.companion_value_normalized`

// declarationResolvableAlias is the curated identity a declaration may resolve
// to: active product, reviewed, not retired, exact or high, and never a name. macOS needs
// the bundle ID with its Team ID. Windows needs the publisher-qualified native
// identity; that registry publisher identifies the catalogue product only and
// is never signer proof, which comes from observed Authenticode evidence.
const declarationResolvableAlias = `a.provenance='reviewed' AND a.retired_at IS NULL AND a.match_confidence IN ('exact','high') AND sp.lifecycle_state='active'
 AND ((a.platform='macos' AND a.identity_kind='macos_bundle_team' AND a.companion_value_normalized ~ '^[A-Z0-9]{10}$')
 OR (a.platform='windows' AND a.identity_kind='windows_native_publisher' AND btrim(a.companion_value_normalized)<>''))`

// declarationSelectableAlias is what a declaration may name as the product it
// means. It adds the Windows identities that carry no publisher. Selecting one
// only dedupes the declaration: it stays unmatched and confers nothing, and it
// cannot be resolved through that alias.
const declarationSelectableAlias = `a.provenance='reviewed' AND a.retired_at IS NULL AND a.match_confidence IN ('exact','high') AND sp.lifecycle_state='active'
 AND ((a.platform='macos' AND a.identity_kind='macos_bundle_team' AND a.companion_value_normalized ~ '^[A-Z0-9]{10}$')
 OR (a.platform='windows' AND a.identity_kind IN ('windows_native_publisher','windows_winget','windows_native')))`

func declarationFailure(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		writeApprovalError(w, 409, "duplicate_declaration", "this product already has a declaration or policy", nil)
		return
	}
	slog.Error("software declaration failed", "err", err)
	writeApprovalError(w, 500, "internal_error", "could not complete the software declaration request", nil)
}
func declarationText(s string, max int) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}
func declarationJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(b) > 16384 || decodeStrictJSON(b, v) != nil {
		writeApprovalError(w, 400, "invalid_request", "invalid declaration fields", nil)
		return false
	}
	return true
}
func declarationWriteTx(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, id portalauth.Identity) pgx.Tx {
	if id.IsService() {
		writeApprovalError(w, 403, "admin_role_required", "a portal admin is required", nil)
		return nil
	}
	tx, err := pool.Begin(r.Context())
	if err != nil {
		declarationFailure(w, err)
		return nil
	}
	refuse := func() { _ = tx.Rollback(r.Context()) }
	if err = lockMandatoryTenantPolicy(r.Context(), tx, id.TenantID); err != nil {
		refuse()
		declarationFailure(w, err)
		return nil
	}
	role, err := portalauth.DBRole(r.Context(), tx, id.Email, id.TenantID, true)
	if err != nil {
		refuse()
		declarationFailure(w, err)
		return nil
	}
	if !portalauth.CanWrite(role) {
		refuse()
		writeApprovalError(w, 403, "admin_role_required", "a portal admin is required", nil)
		return nil
	}
	return tx
}
func loadDeclarationAlias(ctx context.Context, tx pgx.Tx, aliasID, platform, predicate string) (declarationAlias, error) {
	var a declarationAlias
	err := tx.QueryRow(ctx, `SELECT `+declarationAliasColumns+` FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.id=$1::uuid AND a.platform=$2 AND `+predicate+` FOR SHARE OF a,sp`, aliasID, platform).Scan(&a.ID, &a.ProductID, &a.Name, &a.Publisher, &a.Platform, &a.Kind, &a.Identifier, &a.Companion)
	return a, err
}
func PortalSoftwareProductsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := identity(w, r); !ok {
			return
		}
		if _, ok := governanceFormat(w, r, "query", "platform"); !ok {
			return
		}
		query, platform := strings.TrimSpace(r.URL.Query().Get("query")), r.URL.Query().Get("platform")
		if len(query) > 128 || (platform != "macos" && platform != "windows") {
			writeApprovalError(w, 400, "invalid_request", "choose macos or windows and a search of at most 128 characters", nil)
			return
		}
		rows, err := pool.Query(r.Context(), `SELECT `+declarationAliasColumns+` FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.platform=$1 AND `+declarationResolvableAlias+` AND ($2='' OR strpos(lower(sp.canonical_name||' '||sp.vendor_name),lower($2))>0) ORDER BY sp.canonical_name,a.id LIMIT 51`, platform, query)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		defer rows.Close()
		out := []declarationAlias{}
		for rows.Next() {
			var a declarationAlias
			if err = rows.Scan(&a.ID, &a.ProductID, &a.Name, &a.Publisher, &a.Platform, &a.Kind, &a.Identifier, &a.Companion); err != nil {
				declarationFailure(w, err)
				return
			}
			out = append(out, a)
		}
		if err = rows.Err(); err != nil {
			declarationFailure(w, err)
			return
		}
		more := len(out) > 50
		if more {
			out = out[:50]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"products": out, "total": len(out), "has_more": more})
	}
}
func declarationRead(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, tenantID, declarationID string, status int) {
	var value any
	if declarationID != "" {
		// Another tenant's id, an unknown id and a malformed id all answer the
		// same 404, so the route cannot be used to probe for existence.
		if !looksLikeUUID(declarationID) {
			http.NotFound(w, r)
			return
		}
		d, found, err := softwaregov.FetchDeclaration(r.Context(), pool, tenantID, declarationID)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		value = d
	} else {
		ds, err := softwaregov.FetchDeclarations(r.Context(), pool, tenantID)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		value = map[string]any{"declarations": ds, "total": len(ds)}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func PortalSoftwareDeclarationsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if _, ok = governanceFormat(w, r); !ok {
			return
		}
		declarationRead(w, r, pool, id.TenantID, chi.URLParam(r, "declarationID"), 200)
	}
}
func PortalSoftwareDeclarationCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if _, ok = governanceFormat(w, r); !ok {
			return
		}
		tx := declarationWriteTx(w, r, pool, id)
		if tx == nil {
			return
		}
		defer tx.Rollback(r.Context())
		var req declarationRequest
		if !declarationJSON(w, r, &req) {
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.Publisher = strings.TrimSpace(req.Publisher)
		req.Justification = strings.TrimSpace(req.Justification)
		if !declarationText(req.Name, 256) || !declarationText(req.Publisher, 256) || !declarationText(req.Justification, 1000) || (req.Platform != "macos" && req.Platform != "windows") || (req.MinVersion != nil && !softwaregov.MinimumVersionPattern.MatchString(*req.MinVersion)) || (req.AliasID != nil && !looksLikeUUID(*req.AliasID)) {
			writeApprovalError(w, 400, "invalid_request", "provide name, publisher, platform, justification and a numeric dotted minimum version", nil)
			return
		}
		if req.ReviewDate != nil {
			if _, err := time.Parse("2006-01-02", *req.ReviewDate); err != nil {
				writeApprovalError(w, 400, "invalid_request", "review date must be YYYY-MM-DD", nil)
				return
			}
		}
		var count int
		err := tx.QueryRow(r.Context(), `SELECT count(*) FROM tenant_software_declarations WHERE tenant_id=$1::uuid`, id.TenantID).Scan(&count)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		if count >= softwaregov.DeclarationLimit {
			writeApprovalError(w, 409, "declaration_limit", "declaration limit reached", nil)
			return
		}
		var alias declarationAlias
		if req.AliasID != nil {
			alias, err = loadDeclarationAlias(r.Context(), tx, *req.AliasID, req.Platform, declarationSelectableAlias)
			if errors.Is(err, pgx.ErrNoRows) {
				writeApprovalError(w, 422, "unverified_identity", "select an active reviewed exact product identity", nil)
				return
			}
			if err != nil {
				declarationFailure(w, err)
				return
			}
		}
		var declarationID string
		err = tx.QueryRow(r.Context(), `INSERT INTO tenant_software_declarations(tenant_id,name,publisher,platform,justification,min_version,review_date,selected_alias_id,created_by) VALUES($1::uuid,$2,$3,$4,$5,$6,$7::date,$8::uuid,lower($9)) RETURNING id::text`, id.TenantID, req.Name, req.Publisher, req.Platform, req.Justification, req.MinVersion, req.ReviewDate, req.AliasID, id.Email).Scan(&declarationID)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		if req.AliasID != nil && req.Platform == "macos" {
			if !resolveDeclarationPolicy(w, r, tx, id, declarationID, alias, req.MinVersion, req.Justification) {
				return
			}
		}
		if err = recordDeclarationDecision(r.Context(), tx, id, declarationID, "created", req.Justification); err != nil {
			declarationFailure(w, err)
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			declarationFailure(w, err)
			return
		}
		declarationRead(w, r, pool, id.TenantID, declarationID, 201)
	}
}
func PortalSoftwareDeclarationResolveHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if _, ok = governanceFormat(w, r); !ok {
			return
		}
		tx := declarationWriteTx(w, r, pool, id)
		if tx == nil {
			return
		}
		defer tx.Rollback(r.Context())
		declarationID := chi.URLParam(r, "declarationID")
		if !looksLikeUUID(declarationID) {
			http.NotFound(w, r)
			return
		}
		var platform string
		var minVersion *string
		var resolvedAt *time.Time
		err := tx.QueryRow(r.Context(), `SELECT platform,min_version,resolved_at FROM tenant_software_declarations WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, declarationID, id.TenantID).Scan(&platform, &minVersion, &resolvedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			declarationFailure(w, err)
			return
		}
		var req struct {
			AliasID       string `json:"alias_id"`
			Justification string `json:"justification"`
		}
		if !declarationJSON(w, r, &req) {
			return
		}
		req.Justification = strings.TrimSpace(req.Justification)
		if !looksLikeUUID(req.AliasID) || !declarationText(req.Justification, 1000) {
			writeApprovalError(w, 400, "invalid_request", "provide a curated alias and justification", nil)
			return
		}
		if resolvedAt != nil {
			writeApprovalError(w, 409, "already_resolved", "this declaration already has a resolved identity", nil)
			return
		}
		alias, err := loadDeclarationAlias(r.Context(), tx, req.AliasID, platform, declarationResolvableAlias)
		if errors.Is(err, pgx.ErrNoRows) {
			writeApprovalError(w, 422, "unverified_identity", "select an active reviewed exact product identity on the same platform", nil)
			return
		}
		if err != nil {
			declarationFailure(w, err)
			return
		}
		if !resolveDeclarationPolicy(w, r, tx, id, declarationID, alias, minVersion, req.Justification) {
			return
		}
		if err = recordDeclarationDecision(r.Context(), tx, id, declarationID, "resolved", req.Justification); err != nil {
			declarationFailure(w, err)
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			declarationFailure(w, err)
			return
		}
		declarationRead(w, r, pool, id.TenantID, declarationID, 200)
	}
}
func resolveDeclarationPolicy(w http.ResponseWriter, r *http.Request, tx pgx.Tx, id portalauth.Identity, declarationID string, a declarationAlias, minVersion *string, reason string) bool {
	p := approvalProduct{Type: "application", Platform: a.Platform, Identifier: a.Identifier}
	if a.Platform == "macos" {
		p.TeamID = a.Companion
	}
	p.Key = softwaregov.ApplicationKey(p.Platform, p.Identifier, p.TeamID)
	var publisherKey *string
	if a.Platform == "windows" {
		// Require current verified catalogue evidence before deriving a signing key.
		// No fallback to historical observations is permitted for declaration resolution.
		var current bool
		err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM software_installations si JOIN devices dv ON dv.id=si.device_id AND dv.tenant_id=si.tenant_id WHERE si.tenant_id=$1::uuid AND si.platform=$2 AND si.alias_id=$3::uuid AND si.identity_kind=$4 AND si.identity_value_normalized=$5 AND si.companion_value_normalized=$6 AND si.removed_at IS NULL AND si.resolution_confidence IN ('exact','high'))`, id.TenantID, a.Platform, a.ID, a.Kind, a.Identifier, a.Companion).Scan(&current)
		if err != nil {
			declarationFailure(w, err)
			return false
		}
		key, err := softwaregov.DeriveAuthenticodePublisherKey(r.Context(), tx, id.TenantID, a.Identifier)
		if err != nil {
			declarationFailure(w, err)
			return false
		}
		if !current || key == "" {
			writeApprovalError(w, 422, "unverified_signing_identity", "resolution needs current compatible catalogue evidence and one verified stable Authenticode publisher", nil)
			return false
		}
		publisherKey = &key
	}
	rowID, _, err := currentAppDecision(r.Context(), tx, id.TenantID, p)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	mandatory, err := mandatoryResolvesFor(r.Context(), tx, id.TenantID, p)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	if rowID != 0 || mandatory {
		writeApprovalError(w, 409, "existing_policy", "this identity already has an authored policy; manage that policy", nil)
		return false
	}
	policyID, err := applyApproval(r.Context(), tx, id, p, 0, "approved", reason)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	_, err = tx.Exec(r.Context(), `UPDATE tenant_app_policies SET min_version=$3 WHERE id=$1 AND tenant_id=$2::uuid`, policyID, id.TenantID, minVersion)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	_, err = tx.Exec(r.Context(), `UPDATE tenant_software_declarations SET resolved_alias_id=$3::uuid,policy_id=$4,resolved_identifier=$5,resolved_kind=$6,resolved_companion=$7,resolved_publisher_key=$8,resolved_at=now() WHERE id=$1::uuid AND tenant_id=$2::uuid`, declarationID, id.TenantID, a.ID, policyID, a.Identifier, a.Kind, a.Companion, publisherKey)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	if a.Platform == "windows" {
		// Refuse now rather than suspend afterwards: the approval this writes
		// must be effective under exactly the rule every reader applies. One
		// current installation of this identifier that is another catalogue
		// identity, unresolved, or not signed by the pinned publisher fails it,
		// even when the signers agree.
		var effective bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM effective_tenant_app_policies($2::uuid) WHERE id=$1)`, policyID, id.TenantID).Scan(&effective); err != nil {
			declarationFailure(w, err)
			return false
		}
		if !effective {
			writeApprovalError(w, 422, "unverified_signing_identity", "resolution needs every current installation of this product to be the selected identity, signed by one verified stable Authenticode publisher", nil)
			return false
		}
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO software_approval_decisions(tenant_id,batch_id,product_type,product_key,platform,identifier,team_id,previous_state,new_state,reason,actor_email,protected_warning) VALUES($1::uuid,gen_random_uuid(),'application',$2,$3,$4,$5,'unreviewed','approved',$6,lower($7),false)`, id.TenantID, p.Key, p.Platform, p.Identifier, nilIfEmpty(p.TeamID), reason, id.Email)
	if err != nil {
		declarationFailure(w, err)
		return false
	}
	return true
}
func recordDeclarationDecision(ctx context.Context, tx pgx.Tx, id portalauth.Identity, declarationID, action, reason string) error {
	_, err := tx.Exec(ctx, `INSERT INTO software_declaration_decisions(tenant_id,declaration_id,action,actor_email,justification,declaration) SELECT tenant_id,id,$3,lower($4),$5,to_jsonb(d) FROM tenant_software_declarations d WHERE id=$1::uuid AND tenant_id=$2::uuid`, declarationID, id.TenantID, action, id.Email, reason)
	return err
}
func PortalSoftwareDeclarationHistoryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if _, ok = governanceFormat(w, r); !ok {
			return
		}
		did := chi.URLParam(r, "declarationID")
		if !looksLikeUUID(did) {
			http.NotFound(w, r)
			return
		}
		var exists bool
		err := pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenant_software_declarations WHERE id=$1::uuid AND tenant_id=$2::uuid)`, did, id.TenantID).Scan(&exists)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		if !exists {
			http.NotFound(w, r)
			return
		}
		rows, err := pool.Query(r.Context(), `SELECT action,actor_email,justification,decided_at,declaration FROM software_declaration_decisions WHERE tenant_id=$1::uuid AND declaration_id=$2::uuid ORDER BY id`, id.TenantID, did)
		if err != nil {
			declarationFailure(w, err)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var action, actor, reason string
			var at time.Time
			var snapshot json.RawMessage
			if err = rows.Scan(&action, &actor, &reason, &at, &snapshot); err != nil {
				declarationFailure(w, err)
				return
			}
			out = append(out, map[string]any{"action": action, "actor_email": actor, "justification": reason, "decided_at": at, "declaration": snapshot})
		}
		if err = rows.Err(); err != nil {
			declarationFailure(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"decisions": out, "total": len(out)})
	}
}
