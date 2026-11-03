package handlers

// Customer portal software approval writes (PAT-2007, part of PAT-1786).
//
//   GET /v1/portal/me                                    caller's email, tenant and role
//   PUT /v1/portal/software-approvals                    set approval state, 1 to 500 products
//   GET /v1/portal/software-approvals/history            paged decision history (tenant or one product)
//   GET /v1/portal/software-approvals/history/export     the same history as a CSV or JSON file
//
// Same auth seam as the portal read API (PAT-693): the CF Access JWT
// resolves to one tenant through portalauth.Middleware, and every query here
// is scoped to that tenant. No tenant identifier is read from the client.
//
// Writes go into the existing policy store, not a new one:
//
//   state        application (tenant_app_policies)   browser extension (tenant_extension_policies)
//   approved     policy 'approved'                    policy 'approved'
//   unapproved   policy 'unapproved'                  policy 'unapproved'
//   ignored      policy 'unmanaged'                   policy 'ignored'
//   unreviewed   row deleted                          row deleted
//
// Rulings this file implements (PAT-2007 ticket, 2026-09-22 and 2026-09-24):
//
//   - Only a portal user with role 'admin' may write. The role is read from
//     portal_users inside the write transaction; a domain-matched identity
//     has no row and is always a viewer.
//   - An application needs confirmed identity: a macOS bundle ID with its
//     Team ID, or an identifier that a curated software_product_aliases row
//     (not a name-based kind) vouches for. A display name alone is refused.
//   - enforcement_tier is always the lowest rung ('report', stored in its
//     canonical spelling) and is never taken from the caller.
//   - A protected product (PAT-1801) set to unapproved succeeds with a
//     warning. PAT-2088: the operator admin API follows the same rule, one
//     function for both (checkProtectedUnapprovedApp, protected_unapproved.go),
//     which refuses only where an Unapproved would feed enforcement.
//   - Nothing here creates a removal, a removal campaign, an install intent
//     or anything else an agent acts on. The one projection of this store
//     that reaches agents, the extension blocklist in the signed agent
//     config, is empty unless the tenant has App Control on
//     (dbGetExtensionBlocklist), and on such a tenant this endpoint refuses
//     an extension 'unapproved' outright: the operator manages it there.
//     Safari is the exception: the blocklist never carries Safari rows, so
//     a Safari 'unapproved' is allowed on any tenant.
//   - PAT-2089: every row this endpoint writes carries source = 'portal',
//     and only source = 'operator' rows feed the blocklist, so a customer's
//     extension 'unapproved' set while App Control was off stays a
//     governance decision if the operator switches App Control on later.
//     The operator sees it then as a suggestion (portal_suggestions on
//     GET /admin/tenants/{id}/extension-policies).
//   - An operator-set 'mandatory' application is refused (409): mandatory
//     carries install intent, and changing it would cancel that work. The
//     check uses the resolver's matching, so a portal row cannot shadow a
//     mandatory row keyed less specifically (mandatoryResolvesFor).
//     PAT-2091: that check only sees identities already observed, so an
//     approval written before the app is first reported (a curated alias)
//     passes it. Every application row written here therefore carries
//     source = 'portal', and the resolver (apppolicy.Resolve) never lets a
//     portal row outrank an operator mandatory row, whatever the
//     specificity, once the app appears.
//   - On an App Control tenant, a non-Safari extension that the operator
//     has blocked (any operator-set unapproved row for it, 'any' included)
//     cannot be changed from the portal at all. The customer's own earlier
//     unapproved rows are not a block and stay editable.
//   - PAT-2121: an approved Windows application row records the
//     Authenticode publisher key its own evidence agrees on
//     (approvalPublisherKey), derived server-side; publisher_key is not a
//     request field, so the strict decoder refuses one from the client.
//
// A call is all or nothing: every item is checked first, and if any item is
// refused nothing is written. Each product whose state actually changes gets
// one row in software_approval_decisions (0182).

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
	"patched.im/api/internal/softwaregov"
)

const (
	// ApprovalMaxItems caps one write call (PAT-2007).
	ApprovalMaxItems = 500
	// ApprovalMaxReasonChars caps the optional reason, in characters.
	ApprovalMaxReasonChars = 1000
	// approvalMaxBodyBytes comfortably holds 500 maximal items plus a reason.
	approvalMaxBodyBytes     = 512 << 10
	approvalMaxIdentifierLen = 512
	// approvalMaxHomebrewLen matches tenant_homebrew_policies' name/tap CHECK
	// constraints (migration 0195: length(name) <= 256, length(tap) <= 256).
	// Using approvalMaxIdentifierLen (512) here would let a 257-511 character
	// value pass validation and then fail the DB CHECK as a 500, instead of
	// the intended 400.
	approvalMaxHomebrewLen    = 256
	approvalHistoryDefaultLim = 100
	approvalHistoryMaxLim     = 500
	// ApprovalExportMaxRows fails an export closed rather than silently
	// truncating the file.
	ApprovalExportMaxRows = 50000
	// portalApprovalEnforcementTier is the lowest rung, canonical spelling of
	// the legacy 'report' (see legacyTierToCanonical).
	portalApprovalEnforcementTier = "report_deploy"
)

var (
	approvalTeamIDPattern      = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	approvalExtensionIDPattern = regexp.MustCompile(`^[A-Za-z0-9@._{}\-]{1,255}$`)
	approvalStates             = map[string]bool{"approved": true, "unapproved": true, "ignored": true, "unreviewed": true}
	approvalBrowsers           = map[string]bool{"chrome": true, "edge": true, "firefox": true, "safari": true, "any": true}
)

// approvalItem is one product reference on the wire. Pointers let the
// validator tell "absent" from "empty" and refuse a field that does not
// belong to the item's type.
type approvalItem struct {
	Type        string  `json:"type"`
	Platform    *string `json:"platform"`
	Identifier  *string `json:"identifier"`
	TeamID      *string `json:"team_id"`
	Browser     *string `json:"browser"`
	ExtensionID *string `json:"extension_id"`
	// Name / Tap (PAT-2058) address a Homebrew formula or cask: the formula
	// name or cask token, and its tap ("" or omitted means the package's own
	// default tap or an unrecorded one -- see softwaregov.NormalizeHomebrewTap).
	Name *string `json:"name"`
	Tap  *string `json:"tap"`
	// IdentityKind / Source address one named PAT-2021 tooling observation.
	// They are accepted only with type "observation"; unnamed and
	// unidentified observations are not valid policy targets.
	IdentityKind *string `json:"identity_kind"`
	Source       *string `json:"source"`
}

type approvalWriteRequest struct {
	Items  []approvalItem `json:"items"`
	State  string         `json:"state"`
	Reason *string        `json:"reason"`
}

// approvalProduct is a validated, normalised product reference.
type approvalProduct struct {
	Type         string // application | browser_extension | homebrew_formula | homebrew_cask | observation
	Platform     string // application only
	Identifier   string // application identifier, extension id, or homebrew name (normalised)
	TeamID       string // application, macOS only, upper case; "" when absent
	Browser      string // browser_extension only
	ExtensionID  string
	Tap          string // homebrew_formula/homebrew_cask only, raw (pre-NormalizeHomebrewTap) tap
	IdentityKind string // observation only
	Source       string // observation only, normalised companion identity
	Key          string
}

type approvalItemError struct {
	Index   int    `json:"index"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type approvalErrorResp struct {
	Error   string              `json:"error"`
	Message string              `json:"message"`
	Items   []approvalItemError `json:"items,omitempty"`
}

type approvalProtectedMatch struct {
	Category    string `json:"category"`
	Vendor      string `json:"vendor"`
	ProductName string `json:"product_name"`
}

type approvalResult struct {
	Index            int                     `json:"index"`
	Type             string                  `json:"type"`
	ProductKey       string                  `json:"product_key"`
	PreviousState    string                  `json:"previous_state"`
	NewState         string                  `json:"new_state"`
	Changed          bool                    `json:"changed"`
	ProtectedWarning bool                    `json:"protected_warning"`
	Protected        *approvalProtectedMatch `json:"protected"`
	// ResolvedAlerts (PAT-2097) is how many open or acknowledged unapproved
	// software alerts this change resolved (approved, ignored or
	// policy_removed), in the same transaction.
	ResolvedAlerts int `json:"resolved_alerts"`
}

type approvalWriteResp struct {
	BatchID      string           `json:"batch_id"`
	State        string           `json:"state"`
	ChangedCount int              `json:"changed_count"`
	WarningCount int              `json:"warning_count"`
	Results      []approvalResult `json:"results"`
}

func writeApprovalError(w http.ResponseWriter, status int, code, msg string, items []approvalItemError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(approvalErrorResp{Error: code, Message: msg, Items: items})
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// normalizeApprovalItem validates one item's shape. A shape error is a
// client bug and fails the whole request (400); a missing application
// identifier is the name-only refusal (422, code name_only).
func normalizeApprovalItem(it approvalItem) (approvalProduct, *approvalItemError) {
	bad := func(msg string) (approvalProduct, *approvalItemError) {
		return approvalProduct{}, &approvalItemError{Code: "invalid_item", Message: msg}
	}
	switch it.Type {
	case "application":
		if it.Browser != nil || it.ExtensionID != nil || it.Name != nil || it.Tap != nil || it.IdentityKind != nil || it.Source != nil {
			return bad("an application takes platform, identifier and team_id only")
		}
		if it.Platform == nil || (*it.Platform != "macos" && *it.Platform != "windows") {
			return bad("platform must be macos or windows")
		}
		p := approvalProduct{Type: "application", Platform: *it.Platform}
		if it.TeamID != nil {
			if p.Platform != "macos" {
				return bad("team_id applies to macos only")
			}
			team := strings.ToUpper(strings.TrimSpace(*it.TeamID))
			if !approvalTeamIDPattern.MatchString(team) {
				return bad("team_id must be a 10 character Apple Team ID")
			}
			p.TeamID = team
		}
		if it.Identifier == nil || strings.TrimSpace(*it.Identifier) == "" {
			return approvalProduct{}, &approvalItemError{Code: "name_only",
				Message: "this product is known by its display name only, so it has no confirmed identity to record a decision against"}
		}
		ident := strings.TrimSpace(*it.Identifier)
		if utf8.RuneCountInString(ident) > approvalMaxIdentifierLen || hasControlChars(ident) {
			return bad("identifier is too long or contains control characters")
		}
		p.Identifier = ident
		p.Key = "application:" + p.Platform + ":" + strings.ToLower(ident)
		if p.TeamID != "" {
			p.Key += ":" + p.TeamID
		}
		return p, nil
	case "browser_extension":
		if it.Platform != nil || it.Identifier != nil || it.TeamID != nil || it.Name != nil || it.Tap != nil || it.IdentityKind != nil || it.Source != nil {
			return bad("a browser extension takes browser and extension_id only")
		}
		if it.Browser == nil || !approvalBrowsers[*it.Browser] {
			return bad("browser must be chrome, edge, firefox, safari or any")
		}
		if it.ExtensionID == nil || !approvalExtensionIDPattern.MatchString(strings.TrimSpace(*it.ExtensionID)) {
			return bad("extension_id is missing or not a store extension id")
		}
		ext := strings.TrimSpace(*it.ExtensionID)
		return approvalProduct{Type: "browser_extension", Browser: *it.Browser, ExtensionID: ext, Identifier: ext,
			Key: "browser_extension:" + *it.Browser + ":" + ext}, nil
	case "homebrew_formula", "homebrew_cask":
		if it.Platform != nil || it.Identifier != nil || it.TeamID != nil || it.Browser != nil || it.ExtensionID != nil || it.IdentityKind != nil || it.Source != nil {
			return bad("a homebrew item takes name and tap only")
		}
		if it.Name == nil || strings.TrimSpace(*it.Name) == "" {
			return bad("name is required (the formula name or cask token)")
		}
		name := strings.TrimSpace(*it.Name)
		if utf8.RuneCountInString(name) > approvalMaxHomebrewLen || hasControlChars(name) {
			return bad("name is too long or contains control characters")
		}
		tap := ""
		if it.Tap != nil {
			tap = strings.TrimSpace(*it.Tap)
			if utf8.RuneCountInString(tap) > approvalMaxHomebrewLen || hasControlChars(tap) {
				return bad("tap is too long or contains control characters")
			}
		}
		p := approvalProduct{Type: it.Type, Identifier: strings.ToLower(strings.Join(strings.Fields(name), " ")), Tap: tap}
		if it.Type == "homebrew_cask" {
			p.Key = softwaregov.HomebrewCaskKey(name, tap)
		} else {
			p.Key = softwaregov.HomebrewFormulaKey(name, tap)
		}
		return p, nil
	case "observation":
		if it.Platform != nil || it.Identifier != nil || it.TeamID != nil || it.Browser != nil || it.ExtensionID != nil || it.Tap != nil {
			return bad("an observation takes identity_kind, name and optional source only")
		}
		if it.IdentityKind == nil || !softwaregov.ObservationPolicyKind(*it.IdentityKind) {
			return bad("identity_kind must be one named tooling identity")
		}
		if it.Name == nil || strings.TrimSpace(*it.Name) == "" {
			return bad("name is required")
		}
		if hasControlChars(*it.Name) {
			return bad("name is too long or contains control characters")
		}
		name := strings.ToLower(strings.Join(strings.Fields(*it.Name), " "))
		if utf8.RuneCountInString(name) > approvalMaxHomebrewLen {
			return bad("name is too long or contains control characters")
		}
		source := ""
		if it.Source != nil {
			if hasControlChars(*it.Source) {
				return bad("source is too long or contains control characters")
			}
			source = strings.ToLower(strings.Join(strings.Fields(*it.Source), " "))
			if utf8.RuneCountInString(source) > approvalMaxHomebrewLen {
				return bad("source is too long or contains control characters")
			}
		}
		return approvalProduct{Type: "observation", Identifier: name, IdentityKind: *it.IdentityKind, Source: source,
			Key: softwaregov.ObservationKey(*it.IdentityKind, name, source)}, nil
	}
	return bad("type must be application, browser_extension, homebrew_formula, homebrew_cask or observation")
}

// validateApprovalRequest checks everything that needs no database. It
// returns the normalised products, or a status and error body.
func validateApprovalRequest(req approvalWriteRequest) ([]approvalProduct, *string, int, *approvalErrorResp) {
	if !approvalStates[req.State] {
		return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request",
			Message: "state must be approved, unapproved, ignored or unreviewed"}
	}
	if len(req.Items) == 0 {
		return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request", Message: "items must list at least one product"}
	}
	if len(req.Items) > ApprovalMaxItems {
		return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "too_many_items",
			Message: fmt.Sprintf("a single call can change at most %d products", ApprovalMaxItems)}
	}
	var reason *string
	if req.Reason != nil {
		trimmed := strings.TrimSpace(*req.Reason)
		if utf8.RuneCountInString(trimmed) > ApprovalMaxReasonChars {
			return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request",
				Message: fmt.Sprintf("reason must be at most %d characters", ApprovalMaxReasonChars)}
		}
		if strings.ContainsRune(trimmed, 0) || !utf8.ValidString(trimmed) {
			return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request", Message: "reason contains invalid characters"}
		}
		if trimmed != "" {
			reason = &trimmed
		}
	}

	products := make([]approvalProduct, len(req.Items))
	seen := map[string]int{}
	var nameOnly []approvalItemError
	for i, it := range req.Items {
		p, ie := normalizeApprovalItem(it)
		if ie != nil {
			ie.Index = i
			if ie.Code == "name_only" {
				nameOnly = append(nameOnly, *ie)
				continue
			}
			return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request",
				Message: fmt.Sprintf("items[%d]: %s", i, ie.Message), Items: []approvalItemError{*ie}}
		}
		if j, dup := seen[p.Key]; dup {
			return nil, nil, http.StatusBadRequest, &approvalErrorResp{Error: "invalid_request",
				Message: fmt.Sprintf("items[%d] is the same product as items[%d]", i, j)}
		}
		seen[p.Key] = i
		products[i] = p
	}
	if len(nameOnly) > 0 {
		return nil, nil, http.StatusUnprocessableEntity, &approvalErrorResp{Error: "name_only",
			Message: "some products are known by display name only and cannot be marked; nothing was changed", Items: nameOnly}
	}
	return products, reason, 0, nil
}

// appIdentityConfirmed applies ruling 4: a macOS bundle ID with its Team ID,
// or an identifier a curated alias vouches for. Name-based alias kinds do
// not count.
//
// A client-supplied Team ID is a claim, not evidence: it confirms the
// product only when this tenant's own inventory has seen that bundle ID
// signed by that Team ID (device_apps, or a macos_bundle_team installation).
// Without that evidence the item is unconfirmed, even if the bundle ID alone
// has a curated alias, because the row written would carry a Team ID nobody
// observed and, being more specific, could outrank an operator's row.
func appIdentityConfirmed(ctx context.Context, q pgx.Tx, tenantID string, p approvalProduct) (bool, error) {
	var ok bool
	if p.TeamID != "" {
		err := q.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM device_apps da
				JOIN devices d ON d.id = da.device_id
				WHERE d.tenant_id = $1::uuid
				  AND lower(btrim(da.identifier)) = lower(btrim($2))
				  AND upper(btrim(da.team_id)) = $3)
			    OR EXISTS (
				SELECT 1 FROM software_installations si
				WHERE si.tenant_id = $1::uuid
				  AND si.platform = 'macos'
				  AND si.identity_kind = 'macos_bundle_team'
				  AND si.identity_value_normalized = lower(btrim($2))
				  AND si.companion_value_normalized = $3)
		`, tenantID, p.Identifier, p.TeamID).Scan(&ok)
		return ok, err
	}
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM software_product_aliases
			WHERE platform = $1
			  AND identity_value_normalized = lower(btrim($2))
			  AND identity_kind NOT IN ('name_publisher', 'display_name')
			  AND match_confidence IN ('exact', 'high')
			  AND retired_at IS NULL)
	`, p.Platform, p.Identifier).Scan(&ok)
	return ok, err
}

// homebrewIdentityConfirmed reports whether this tenant's own evidence has
// ever observed this formula or cask under this exact tap (PAT-2058). Unlike
// an application, a Homebrew name carries no display-name ambiguity to
// confirm away -- the formula name or cask token the portal already shows
// (GET /v1/portal/homebrew/formulae|casks, identity.name/identity.tap) is
// already the package's own namespaced identity (PAT-2013). This check only
// guards against a client inventing a name this tenant never reported.
// software_installations is checked without a removed_at filter, so a
// formula or cask that was later removed can still be re-addressed (the
// same latitude appIdentityConfirmed's alias branch gives an application).
func homebrewIdentityConfirmed(ctx context.Context, q pgx.Tx, tenantID, kind, name, tap string) (bool, error) {
	identityKind := "homebrew_formula"
	if kind == "homebrew_cask" {
		identityKind = "homebrew_cask"
	}
	normTap := softwaregov.NormalizeHomebrewTap(strings.TrimPrefix(kind, "homebrew_"), tap)
	defaultTap := "homebrew/core"
	if kind == "homebrew_cask" {
		defaultTap = "homebrew/cask"
	}
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM software_installations si
			WHERE si.tenant_id = $1::uuid
			  AND si.identity_kind = $2
			  AND si.identity_value_normalized = lower(btrim($3))
			  AND (($4 = '' AND (si.companion_value_normalized = '' OR si.companion_value_normalized = $5))
			       OR si.companion_value_normalized = $4))
	`, tenantID, identityKind, name, normTap, defaultTap).Scan(&ok)
	return ok, err
}

// currentHomebrewDecision locks and returns this tenant's own policy row for
// this exact (kind, name, tap) identity, keyed the same way
// homebrewIdentityConfirmed and the resolver (softwaregov.homebrewPolicyKey)
// match it.
func currentHomebrewDecision(ctx context.Context, tx pgx.Tx, tenantID, kind, name, tap string) (int64, string, error) {
	k := strings.TrimPrefix(kind, "homebrew_")
	normTap := softwaregov.NormalizeHomebrewTap(k, tap)
	var id int64
	var policy string
	err := tx.QueryRow(ctx, `
		SELECT id, policy FROM tenant_homebrew_policies
		WHERE tenant_id = $1::uuid AND kind = $2 AND name = lower(btrim($3)) AND tap = $4
		FOR UPDATE
	`, tenantID, k, name, normTap).Scan(&id, &policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	return id, policy, err
}

// currentCaskLinkedToApp reports a live Homebrew cask installation linked to
// a live application installation. Linked casks inherit the application
// policy at read time, so accepting a cask write would create a second,
// misleading decision. The exact identity comparison deliberately mirrors
// homebrewIdentityConfirmed's default-tap handling.
func currentCaskLinkedToApp(ctx context.Context, tx pgx.Tx, tenantID, name, tap string) (bool, error) {
	normTap := softwaregov.NormalizeHomebrewTap("cask", tap)
	var linked bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM software_installations ci
			JOIN homebrew_cask_app_links l ON l.cask_installation_id = ci.id
			JOIN software_installations ai ON ai.id = l.app_installation_id
			  AND ai.tenant_id = ci.tenant_id AND ai.removed_at IS NULL
			WHERE ci.tenant_id = $1::uuid AND ci.removed_at IS NULL
			  AND ci.identity_kind = 'homebrew_cask'
			  AND ci.identity_value_normalized = lower(btrim($2))
			  AND (($3 = '' AND (ci.companion_value_normalized = '' OR ci.companion_value_normalized = 'homebrew/cask'))
		       OR ci.companion_value_normalized = $3)
		)
	`, tenantID, name, normTap).Scan(&linked)
	return linked, err
}

// observationIdentityConfirmed proves the exact named tooling identity came
// from this tenant's own immutable inventory. No client can create a policy
// for another tenant's observation, and unidentified identity kinds never
// reach this function because strict validation refuses them first.
func observationIdentityConfirmed(ctx context.Context, tx pgx.Tx, tenantID string, p approvalProduct) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM software_installations
			WHERE tenant_id = $1::uuid AND identity_kind = $2
			  AND identity_value_normalized = $3 AND companion_value_normalized = $4
		)
	`, tenantID, p.IdentityKind, p.Identifier, p.Source).Scan(&ok)
	return ok, err
}

func currentObservationDecision(ctx context.Context, tx pgx.Tx, tenantID string, p approvalProduct) (int64, string, error) {
	var id int64
	var policy string
	err := tx.QueryRow(ctx, `
		SELECT id, policy FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid AND identity_kind = $2 AND name = $3 AND source = $4
		FOR UPDATE
	`, tenantID, p.IdentityKind, p.Identifier, p.Source).Scan(&id, &policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	return id, policy, err
}

// mandatoryResolvesFor reports whether any operator 'mandatory' row would
// resolve for this application under the resolver's own matching
// (apppolicy.Matches), not just the row keyed exactly like the portal's.
// The resolver lets a more specific row win (candidatePrecedes), so a portal
// row with the same bundle ID plus a Team ID would otherwise outrank a
// mandatory row keyed on the bundle ID alone, or on the Team ID or the name.
// The identities tried are the item's own plus every identity this tenant's
// inventory has reported for the identifier on the item's platform.
func mandatoryResolvesFor(ctx context.Context, tx pgx.Tx, tenantID string, p approvalProduct) (bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version
		FROM tenant_app_policies
		WHERE tenant_id = $1::uuid AND source = 'operator'
		  AND policy = 'mandatory' AND platform IN ($2, 'any')
	`, tenantID, p.Platform)
	if err != nil {
		return false, err
	}
	var mandatory []tenantPolicy
	for rows.Next() {
		var m tenantPolicy
		if err := rows.Scan(&m.ID, &m.TeamID, &m.BundleID, &m.WingetID, &m.Name, &m.Platform,
			&m.Policy, &m.EnforcementTier, &m.MinVersion); err != nil {
			rows.Close()
			return false, err
		}
		mandatory = append(mandatory, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(mandatory) == 0 {
		return false, err
	}

	osLabel := "macOS"
	if p.Platform == "windows" {
		osLabel = "Windows"
	}
	candidates := []installedAppPolicyIdentity{{
		TeamID: p.TeamID, BundleID: p.Identifier,
		WingetID: installedWingetID(p.Identifier, "winget", osLabel),
	}}
	// Every observed identity, no cap (PAT-2091): a LIMIT on these distinct
	// combinations could drop the very name a mandatory row is keyed on and
	// let the write through. The comparisons are case-insensitive (and
	// trim team and name), so the DISTINCT folds those to keep the set as
	// small as the matching allows. The identifier is not trimmed: its exact
	// spelling decides whether it is a valid Winget ID (installedWingetID).
	obs, err := tx.Query(ctx, `
		SELECT DISTINCT upper(btrim(COALESCE(da.team_id, ''))), lower(da.identifier),
		       lower(btrim(da.name)), COALESCE(da.identifier_kind, ''), COALESCE(d.os, '')
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid
		  AND lower(btrim(da.identifier)) = lower(btrim($2))
	`, tenantID, p.Identifier)
	if err != nil {
		return false, err
	}
	for obs.Next() {
		var team, ident, name, kind, deviceOS string
		if err := obs.Scan(&team, &ident, &name, &kind, &deviceOS); err != nil {
			obs.Close()
			return false, err
		}
		if devicePolicyPlatform(deviceOS) != p.Platform {
			continue
		}
		if p.TeamID != "" && !strings.EqualFold(strings.TrimSpace(team), strings.TrimSpace(p.TeamID)) {
			continue
		}
		candidates = append(candidates, installedAppPolicyIdentity{
			TeamID: team, BundleID: ident, WingetID: installedWingetID(ident, kind, deviceOS), Name: name,
		})
	}
	obs.Close()
	if err := obs.Err(); err != nil {
		return false, err
	}
	for _, m := range mandatory {
		for _, c := range candidates {
			if policyMatchesInstalledApp(m, c) {
				return true, nil
			}
		}
	}
	return false, nil
}

// extensionBlockedByOperator reports whether any row that feeds, or could
// feed, the signed extension blocklist for this extension id is
// 'unapproved': operator-set (PAT-2089), any non-Safari browser, 'any'
// included. On an App Control
// tenant such a block is the operator's, and no portal write may touch that
// extension while it stands, whatever the new state and whichever browser
// the item names. FOR SHARE holds the rows until commit.
func extensionBlockedByOperator(ctx context.Context, tx pgx.Tx, tenantID, extensionID string) (bool, error) {
	var blocked bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_extension_policies
			WHERE tenant_id = $1::uuid
			  AND extension_id = $2
			  AND browser IN ('chrome', 'edge', 'firefox', 'any')
			  AND policy = 'unapproved'
			  AND source = 'operator'
			FOR SHARE)
	`, tenantID, extensionID).Scan(&blocked)
	return blocked, err
}

// portalProtectionIdentity is a portal application item as the shared
// protected-software rule addresses it: the identifier as the bundle ID, with
// the Team ID on macOS.
func portalProtectionIdentity(p approvalProduct) appProtectionIdentity {
	ident := p.Identifier
	id := appProtectionIdentity{Platform: p.Platform, BundleID: &ident}
	if p.TeamID != "" {
		team := p.TeamID
		id.TeamID = &team
	}
	return id
}

func appPolicyToApprovalState(policy string) string {
	switch policy {
	case "":
		return "unreviewed"
	case "unmanaged":
		return "ignored"
	}
	return policy // approved | unapproved | mandatory
}

func approvalStateToAppPolicy(state string) string {
	if state == "ignored" {
		return "unmanaged"
	}
	return state
}

func extPolicyToApprovalState(policy string) string {
	if policy == "" {
		return "unreviewed"
	}
	return policy // approved | unapproved | ignored
}

// currentAppDecision locks and returns this product's own policy row: the
// row keyed on exactly this identifier (and Team ID) for this platform, with
// no winget_id or name. Rows keyed differently (an operator's name or 'any'
// platform row) are separate decisions and are left alone.
func currentAppDecision(ctx context.Context, tx pgx.Tx, tenantID string, p approvalProduct) (int64, string, error) {
	var id int64
	var policy string
	err := tx.QueryRow(ctx, `
		SELECT id, policy FROM tenant_app_policies
		WHERE tenant_id = $1::uuid
		  AND platform = $2
		  AND winget_id IS NULL
		  AND name IS NULL
		  AND lower(COALESCE(bundle_id, '')) = lower($3)
		  AND upper(COALESCE(team_id, '')) = $4
		ORDER BY id
		LIMIT 1
		FOR UPDATE
	`, tenantID, p.Platform, p.Identifier, p.TeamID).Scan(&id, &policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	return id, policy, err
}

// currentExtensionDecision locks and returns this extension's own policy row
// for this browser, with who set it (PAT-2089: 'operator' or 'portal').
func currentExtensionDecision(ctx context.Context, tx pgx.Tx, tenantID string, p approvalProduct) (int64, string, string, error) {
	var id int64
	var policy, source string
	err := tx.QueryRow(ctx, `
		SELECT id, policy, source FROM tenant_extension_policies
		WHERE tenant_id = $1::uuid AND browser = $2 AND extension_id = $3
		FOR UPDATE
	`, tenantID, p.Browser, p.ExtensionID).Scan(&id, &policy, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", "", nil
	}
	return id, policy, source, err
}

// PortalMeHandler serves GET /v1/portal/me: who the portal caller is and
// what role they hold, so the portal can hide write controls from viewers.
// Display only; every write re-checks the role server-side.
func PortalMeHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if id.IsService() {
			// PAT-2257: the read-only service identity. No email and no
			// portal_users row; its role is fixed, never looked up.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"email": "", "tenant_id": id.TenantID, "role": portalauth.RoleServiceReadOnly})
			return
		}
		role, err := portalauth.DBRole(r.Context(), pool, id.Email, id.TenantID, false)
		if err != nil {
			slog.Error("portal me: role lookup failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"email": id.Email, "tenant_id": id.TenantID, "role": role})
	}
}

// approvalBeforeExtensionRowLock is a test seam: nil in production. Tests set
// it to act between the App Control block check and the FOR UPDATE row lock,
// to prove the locked re-check refuses a block that appeared in between.
var approvalBeforeExtensionRowLock func(ctx context.Context, tenantID, browser, extensionID string)

type pendingApproval struct {
	product   approvalProduct
	rowID     int64
	prevState string
	protected protectedUnapprovedVerdict
}

// PortalSoftwareApprovalsPutHandler serves PUT /v1/portal/software-approvals.
func PortalSoftwareApprovalsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_software_approvals", "tenant_id", id.TenantID)
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

		// The tenant policy advisory lock comes first, before any row lock.
		// Every writer of this tenant's policy store takes it first too: the
		// operator app-policy handlers and, since the PAT-2007 review, the
		// operator extension-policy insert, update and delete. So a portal
		// write and an operator write serialise, and taking it before the
		// FOR SHARE and FOR UPDATE row locks below keeps one lock order in
		// every path (no deadlock).
		if err := lockMandatoryTenantPolicy(ctx, tx, id.TenantID); err != nil {
			internal("policy lock failed", err)
			return
		}

		// Role before the body is even read: a viewer gets 403 for any
		// request. FOR SHARE holds the row so a concurrent demotion waits.
		role, err := portalauth.DBRole(ctx, tx, id.Email, id.TenantID, true)
		if err != nil {
			internal("role lookup failed", err)
			return
		}
		if !portalauth.CanWrite(role) {
			writeApprovalError(w, http.StatusForbidden, "admin_role_required",
				"only a portal admin can change software approval state; your role is "+role, nil)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, approvalMaxBodyBytes+1))
		if err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "could not read the request body", nil)
			return
		}
		if len(body) > approvalMaxBodyBytes {
			writeApprovalError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large", nil)
			return
		}
		var req approvalWriteRequest
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error(), nil)
			return
		}
		products, reason, status, verr := validateApprovalRequest(req)
		if verr != nil {
			writeApprovalError(w, status, verr.Error, verr.Message, verr.Items)
			return
		}

		// Tenant row FOR SHARE: the tier change that flips App Control takes
		// this row for update, so the App Control check below cannot go stale
		// before commit.
		var appControl bool
		if err := tx.QueryRow(ctx, `
			SELECT app_control_enabled FROM tenants
			WHERE id = $1::uuid AND revoked_at IS NULL
			FOR SHARE
		`, id.TenantID).Scan(&appControl); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeApprovalError(w, http.StatusForbidden, "forbidden", "forbidden", nil)
				return
			}
			internal("tenant lookup failed", err)
			return
		}

		// Pass 1: check every item, write nothing.
		pending := make([]pendingApproval, len(products))
		var refusals []approvalItemError
		status = 0
		for i, p := range products {
			pending[i].product = p
			if p.Type == "application" {
				confirmed, err := appIdentityConfirmed(ctx, tx, id.TenantID, p)
				if err != nil {
					internal("identity confirmation failed", err)
					return
				}
				if !confirmed {
					refusals = append(refusals, approvalItemError{Index: i, Code: "unconfirmed_identity",
						Message: "this product has no confirmed identity (a macOS bundle ID with its Team ID, or a curated product match), so it cannot be marked"})
					status = http.StatusUnprocessableEntity
					continue
				}
				rowID, policy, err := currentAppDecision(ctx, tx, id.TenantID, p)
				if err != nil {
					internal("current app decision lookup failed", err)
					return
				}
				shadowsMandatory, err := mandatoryResolvesFor(ctx, tx, id.TenantID, p)
				if err != nil {
					internal("mandatory resolution check failed", err)
					return
				}
				if policy == "mandatory" || shadowsMandatory {
					refusals = append(refusals, approvalItemError{Index: i, Code: "operator_managed",
						Message: "this application is set as mandatory by your Patched operator and cannot be changed here"})
					if status == 0 {
						status = http.StatusConflict
					}
					continue
				}
				// PAT-2088: the shared protected-software rule, in pass 1 so
				// a refusal (only where Unapproved would feed enforcement)
				// keeps the call all or nothing.
				if req.State == "unapproved" {
					verdict, err := checkProtectedUnapprovedApp(ctx, tx, id.TenantID, portalProtectionIdentity(p))
					if err != nil {
						internal("protected software check failed", err)
						return
					}
					if verdict.Refuse {
						refusals = append(refusals, approvalItemError{Index: i, Code: "protected_software",
							Message: fmt.Sprintf("%s (%s) is protected software and cannot be marked unapproved here", verdict.Match.ProductName, verdict.Match.Category)})
						if status == 0 {
							status = http.StatusConflict
						}
						continue
					}
					pending[i].protected = verdict
				}
				pending[i].rowID, pending[i].prevState = rowID, appPolicyToApprovalState(policy)
				continue
			}
			if p.Type == "homebrew_formula" || p.Type == "homebrew_cask" {
				confirmed, err := homebrewIdentityConfirmed(ctx, tx, id.TenantID, p.Type, p.Identifier, p.Tap)
				if err != nil {
					internal("homebrew identity confirmation failed", err)
					return
				}
				if !confirmed {
					refusals = append(refusals, approvalItemError{Index: i, Code: "unconfirmed_identity",
						Message: "this tenant's inventory has never reported this formula or cask under this tap, so it cannot be marked"})
					status = http.StatusUnprocessableEntity
					continue
				}
				if p.Type == "homebrew_cask" {
					linked, err := currentCaskLinkedToApp(ctx, tx, id.TenantID, p.Identifier, p.Tap)
					if err != nil {
						internal("linked cask lookup failed", err)
						return
					}
					if linked {
						refusals = append(refusals, approvalItemError{Index: i, Code: "linked_app_policy",
							Message: "this cask is linked to an application bundle and follows that application's policy; change the application instead"})
						if status == 0 {
							status = http.StatusConflict
						}
						continue
					}
				}
				rowID, policy, err := currentHomebrewDecision(ctx, tx, id.TenantID, p.Type, p.Identifier, p.Tap)
				if err != nil {
					internal("current homebrew decision lookup failed", err)
					return
				}
				// No 'mandatory' vocabulary for Homebrew (PAT-2058 scope:
				// Approved, Unapproved, Ignored, Unreviewed only), so no
				// operator-managed shadow check applies here.
				pending[i].rowID, pending[i].prevState = rowID, appPolicyToApprovalState(policy)
				continue
			}
			if p.Type == "observation" {
				confirmed, err := observationIdentityConfirmed(ctx, tx, id.TenantID, p)
				if err != nil {
					internal("observation identity confirmation failed", err)
					return
				}
				if !confirmed {
					refusals = append(refusals, approvalItemError{Index: i, Code: "unconfirmed_identity",
						Message: "this tenant's inventory has never reported this named tooling identity, so it cannot be marked"})
					status = http.StatusUnprocessableEntity
					continue
				}
				rowID, policy, err := currentObservationDecision(ctx, tx, id.TenantID, p)
				if err != nil {
					internal("current observation decision lookup failed", err)
					return
				}
				pending[i].rowID, pending[i].prevState = rowID, appPolicyToApprovalState(policy)
				continue
			}
			// On an App Control tenant the operator owns extension blocking:
			// the portal may neither add a block (new state unapproved) nor
			// lift or reshape an existing one (any blocklist-feeding row for
			// this extension already unapproved). Safari rows never reach the
			// agent blocklist (it fans out to chrome, edge and firefox only,
			// and Safari removal is not actuated at all, 0178), so App Control
			// does not gate them.
			operatorBlock := false
			if appControl && p.Browser != "safari" {
				blocked, err := extensionBlockedByOperator(ctx, tx, id.TenantID, p.ExtensionID)
				if err != nil {
					internal("extension blocklist check failed", err)
					return
				}
				operatorBlock = blocked || req.State == "unapproved"
			}
			if operatorBlock {
				refusals = append(refusals, approvalItemError{Index: i, Code: "app_control_managed",
					Message: "App Control is on for this organisation, so blocking browser extensions is managed by your Patched operator"})
				if status == 0 {
					status = http.StatusConflict
				}
				continue
			}
			if approvalBeforeExtensionRowLock != nil {
				approvalBeforeExtensionRowLock(ctx, id.TenantID, p.Browser, p.ExtensionID)
			}
			rowID, policy, source, err := currentExtensionDecision(ctx, tx, id.TenantID, p)
			if err != nil {
				internal("current extension decision lookup failed", err)
				return
			}
			// Re-check on the row as locked for this write. The check above
			// ran before the lock; a writer that does not take the advisory
			// lock could have blocked the extension in between. With the row
			// now held FOR UPDATE, this read is the authoritative one. Only
			// an operator-set row is a block (PAT-2089).
			if appControl && p.Browser != "safari" && policy == "unapproved" && source == "operator" {
				refusals = append(refusals, approvalItemError{Index: i, Code: "app_control_managed",
					Message: "App Control is on for this organisation, so blocking browser extensions is managed by your Patched operator"})
				if status == 0 {
					status = http.StatusConflict
				}
				continue
			}
			pending[i].rowID, pending[i].prevState = rowID, extPolicyToApprovalState(policy)
		}
		if len(refusals) > 0 {
			code := "refused"
			if status == http.StatusUnprocessableEntity {
				code = "unconfirmed_identity"
			}
			writeApprovalError(w, status, code, "some products cannot be changed; nothing was changed", refusals)
			return
		}

		// Pass 2: apply and audit.
		var batchID string
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&batchID); err != nil {
			internal("batch id failed", err)
			return
		}
		notes := ""
		if reason != nil {
			notes = *reason
		}
		// PAT-2009: the decision time the unapproved alert reports, read from
		// this transaction so it precedes anything an ingest does after the
		// commit.
		var decidedAt time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&decidedAt); err != nil {
			internal("decision time failed", err)
			return
		}
		var episodes []int64
		// PAT-2095: the alert operations run after the loop, just before the
		// commit. Each takes the tenant alert lock (lockTenantAlerts), which
		// every ingest's post-commit DetectOnDevice also takes; taken inside
		// the loop, a bulk mark held it for the rest of the loop. The lock
		// order is unchanged: policy lock, policy rows, then alert lock.
		type alertOp struct {
			result   int // index into resp.Results
			kind     string
			rowID    int64 // the policy row leaving Unapproved (resolve)
			policyID int64 // the policy row entering Unapproved (open)
			resolve  bool
			open     bool
		}
		var alertOps []alertOp
		resp := approvalWriteResp{BatchID: batchID, State: req.State, Results: make([]approvalResult, 0, len(pending))}
		for i, pa := range pending {
			p := pa.product
			res := approvalResult{Index: i, Type: p.Type, ProductKey: p.Key, PreviousState: pa.prevState, NewState: req.State}
			if pa.protected.Warn() {
				m := pa.protected.Match
				res.ProtectedWarning = true
				res.Protected = &approvalProtectedMatch{Category: m.Category, Vendor: m.Vendor, ProductName: m.ProductName}
				resp.WarningCount++
			}
			if pa.prevState == req.State {
				resp.Results = append(resp.Results, res)
				continue
			}
			policyID, err := applyApproval(ctx, tx, id, p, pa.rowID, req.State, notes)
			if err != nil {
				internal("apply approval failed", err)
				return
			}
			// PAT-2058: Homebrew is deliberately excluded from the unapproved
			// alert machinery below (software_unapproved_episodes.policy_kind's
			// CHECK only admits application/browser_extension, 0183) -- see
			// the matching comment in softwaregov.DetectOnDevice. A Homebrew
			// approval still gets its software_approval_decisions audit row
			// below; it just never opens or resolves an alert episode.
			alertable := p.Type == "application" || p.Type == "browser_extension"
			// PAT-2097: leaving Unapproved resolves the policy row's open and
			// acknowledged alerts in this transaction, so the alert state can
			// never disagree with the committed decision.
			// PAT-2009: entering Unapproved opens an episode that commits
			// with the decision; the runner raises its alert.
			op := alertOp{result: len(resp.Results), kind: p.Type, rowID: pa.rowID, policyID: policyID,
				resolve: alertable && pa.prevState == "unapproved" && req.State != "unapproved" && pa.rowID != 0,
				open:    alertable && req.State == "unapproved" && policyID != 0}
			if op.resolve || op.open {
				alertOps = append(alertOps, op)
			}
			var observationKind, observationSource any
			if p.Type == "observation" {
				observationKind, observationSource = p.IdentityKind, p.Source
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO software_approval_decisions
				    (tenant_id, batch_id, product_type, product_key, platform, identifier, team_id, browser,
				     observation_kind, observation_source, previous_state, new_state, reason, actor_email, protected_warning)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, lower($14), $15)
			`, id.TenantID, batchID, p.Type, p.Key, nilIfEmpty(p.Platform), p.Identifier, nilIfEmpty(p.TeamID),
				nilIfEmpty(p.Browser), observationKind, observationSource, pa.prevState, req.State, reason, id.Email, res.ProtectedWarning); err != nil {
				internal("audit insert failed", err)
				return
			}
			res.Changed = true
			resp.ChangedCount++
			resp.Results = append(resp.Results, res)
		}
		for _, op := range alertOps {
			if op.resolve {
				n, err := softwaregov.ResolvePolicyAlertsTx(ctx, tx, id.TenantID, op.kind, op.rowID, req.State,
					softwaregov.Actor{Kind: softwaregov.ActorPortalUser, Email: id.Email})
				if err != nil {
					internal("resolve unapproved alerts failed", err)
					return
				}
				resp.Results[op.result].ResolvedAlerts = n
			}
			if op.open {
				episodeID, err := softwaregov.OpenEpisodeTx(ctx, tx, softwaregov.Mark{
					TenantID: id.TenantID, PolicyKind: op.kind, PolicyID: op.policyID,
					Source: softwaregov.SourcePortal, MarkedBy: id.Email, MarkedAt: decidedAt, BatchID: batchID,
				})
				if err != nil {
					internal("open unapproved episode failed", err)
					return
				}
				episodes = append(episodes, episodeID)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		logger.Info("portal software approvals written", "batch_id", batchID, "state", req.State,
			"items", len(pending), "changed", resp.ChangedCount, "protected_warnings", resp.WarningCount)
		// PAT-2009: the unapproved software alert for the admin action. After
		// the commit and on its own context: an alert failure is logged and
		// never changes the decision that was just recorded.
		raiseUnapprovedEpisodes(pool, id.TenantID, episodes, logger)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// approvalPublisherKey is the publisher_key an application policy row stores
// for a write to state (PAT-2121): the Windows Authenticode publisher key
// derived from the tenant's own evidence when the row is approved on the
// windows platform, NULL otherwise (another state, macOS or 'any', or no
// agreeing public-root evidence). Shared by the portal and operator writes.
func approvalPublisherKey(ctx context.Context, tx pgx.Tx, tenantID, platform, identifier, state string) (*string, error) {
	if state != "approved" || platform != "windows" || strings.TrimSpace(identifier) == "" {
		return nil, nil
	}
	key, err := softwaregov.DeriveAuthenticodePublisherKey(ctx, tx, tenantID, identifier)
	if err != nil || key == "" {
		return nil, err
	}
	return &key, nil
}

// applyApproval writes one product's new state and returns the id of the
// policy row now holding it (0 for unreviewed, which deletes the row).
func applyApproval(ctx context.Context, tx pgx.Tx, id portalauth.Identity, p approvalProduct, rowID int64, state, notes string) (int64, error) {
	if p.Type == "application" {
		if state == "unreviewed" {
			if rowID == 0 {
				return 0, nil
			}
			_, err := tx.Exec(ctx, `DELETE FROM tenant_app_policies WHERE id = $1 AND tenant_id = $2::uuid`, rowID, id.TenantID)
			return 0, err
		}
		// PAT-2121: an approved Windows application records the publisher
		// its own evidence vouches for, derived here from this tenant's
		// observations and never from the request. Any other state clears it.
		publisherKey, err := approvalPublisherKey(ctx, tx, id.TenantID, p.Platform, p.Identifier, state)
		if err != nil {
			return 0, err
		}
		if rowID != 0 {
			// PAT-2091: the row is the customer's now (source 'portal'), so
			// the resolver never lets it outrank an operator mandatory row.
			_, err := tx.Exec(ctx, `
				UPDATE tenant_app_policies
				SET policy = $3, enforcement_tier = $4, notes = $5, publisher_key = $6, source = 'portal', updated_at = now()
				WHERE id = $1 AND tenant_id = $2::uuid
			`, rowID, id.TenantID, approvalStateToAppPolicy(state), portalApprovalEnforcementTier, notes, publisherKey)
			return rowID, err
		}
		var newID int64
		err = tx.QueryRow(ctx, `
			INSERT INTO tenant_app_policies (tenant_id, team_id, bundle_id, platform, policy, enforcement_tier, notes, publisher_key, source)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'portal')
			RETURNING id
		`, id.TenantID, nilIfEmpty(p.TeamID), p.Identifier, p.Platform, approvalStateToAppPolicy(state),
			portalApprovalEnforcementTier, notes, publisherKey).Scan(&newID)
		return newID, err
	}
	if p.Type == "homebrew_formula" || p.Type == "homebrew_cask" {
		kind := "formula"
		if p.Type == "homebrew_cask" {
			kind = "cask"
		}
		normTap := softwaregov.NormalizeHomebrewTap(kind, p.Tap)
		if state == "unreviewed" {
			if rowID == 0 {
				return 0, nil
			}
			_, err := tx.Exec(ctx, `DELETE FROM tenant_homebrew_policies WHERE id = $1 AND tenant_id = $2::uuid`, rowID, id.TenantID)
			return 0, err
		}
		if rowID != 0 {
			_, err := tx.Exec(ctx, `
				UPDATE tenant_homebrew_policies
				SET policy = $3, notes = $4, updated_at = now()
				WHERE id = $1 AND tenant_id = $2::uuid
			`, rowID, id.TenantID, approvalStateToAppPolicy(state), notes)
			return rowID, err
		}
		var newID int64
		err := tx.QueryRow(ctx, `
			INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, tap, policy, notes)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			RETURNING id
		`, id.TenantID, kind, p.Identifier, normTap, approvalStateToAppPolicy(state), notes).Scan(&newID)
		return newID, err
	}
	if p.Type == "observation" {
		if state == "unreviewed" {
			if rowID == 0 {
				return 0, nil
			}
			_, err := tx.Exec(ctx, `DELETE FROM tenant_observation_policies WHERE id = $1 AND tenant_id = $2::uuid`, rowID, id.TenantID)
			return 0, err
		}
		if rowID != 0 {
			_, err := tx.Exec(ctx, `
				UPDATE tenant_observation_policies SET policy = $3, notes = $4, updated_at = now()
				WHERE id = $1 AND tenant_id = $2::uuid
			`, rowID, id.TenantID, approvalStateToAppPolicy(state), notes)
			return rowID, err
		}
		var newID int64
		err := tx.QueryRow(ctx, `
			INSERT INTO tenant_observation_policies (tenant_id, identity_kind, name, source, policy, notes)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			RETURNING id
		`, id.TenantID, p.IdentityKind, p.Identifier, p.Source, approvalStateToAppPolicy(state), notes).Scan(&newID)
		return newID, err
	}
	switch {
	case state == "unreviewed":
		if rowID == 0 {
			return 0, nil
		}
		_, err := tx.Exec(ctx, `DELETE FROM tenant_extension_policies WHERE id = $1 AND tenant_id = $2::uuid`, rowID, id.TenantID)
		return 0, err
	case rowID != 0:
		// PAT-2089: the customer now owns this row's decision, so it stops
		// feeding the App Control blocklist even if an operator set it before.
		_, err := tx.Exec(ctx, `
			UPDATE tenant_extension_policies
			SET policy = $3, approved_by = $4, notes = $5, source = 'portal', updated_at = now()
			WHERE id = $1 AND tenant_id = $2::uuid
		`, rowID, id.TenantID, state, id.Email, notes)
		return rowID, err
	default:
		// Display label from this tenant's own inventory, best effort.
		var newID int64
		err := tx.QueryRow(ctx, `
			INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy, approved_by, notes, source)
			VALUES ($1::uuid, $2, $3,
			        COALESCE((SELECT dbe.name FROM device_browser_extensions dbe
			                  JOIN devices d ON d.id = dbe.device_id
			                  WHERE d.tenant_id = $1::uuid AND dbe.extension_id = $3
			                    AND ($2 = 'any' OR dbe.browser = $2)
			                  ORDER BY dbe.last_seen DESC LIMIT 1), ''),
			        $4, $5, $6, 'portal')
			RETURNING id
		`, id.TenantID, p.Browser, p.ExtensionID, state, id.Email, notes).Scan(&newID)
		return newID, err
	}
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

type approvalDecision struct {
	ID                int64     `json:"id"`
	BatchID           string    `json:"batch_id"`
	ProductType       string    `json:"product_type"`
	ProductKey        string    `json:"product_key"`
	Platform          *string   `json:"platform"`
	Identifier        string    `json:"identifier"`
	TeamID            *string   `json:"team_id"`
	Browser           *string   `json:"browser"`
	ObservationKind   *string   `json:"observation_kind"`
	ObservationSource *string   `json:"observation_source"`
	PreviousState     string    `json:"previous_state"`
	NewState          string    `json:"new_state"`
	Reason            *string   `json:"reason"`
	ActorEmail        string    `json:"actor_email"`
	ProtectedWarning  bool      `json:"protected_warning"`
	DecidedAt         time.Time `json:"decided_at"`
}

// approvalHistoryFilter reads the optional product filter. No filter means
// the tenant's whole history. A filter takes the same fields as a write
// item, so the portal can pass the row it already holds.
func approvalHistoryFilter(q map[string][]string) (string, *approvalErrorResp) {
	get := func(k string) *string {
		v, ok := q[k]
		if !ok || len(v) == 0 {
			return nil
		}
		s := v[0]
		return &s
	}
	allowed := map[string]bool{"type": true, "platform": true, "identifier": true, "team_id": true,
		"browser": true, "extension_id": true, "name": true, "tap": true, "identity_kind": true, "source": true, "limit": true, "offset": true, "format": true}
	for k := range q {
		if !allowed[k] {
			return "", &approvalErrorResp{Error: "invalid_request", Message: "unknown query parameter " + strconv.Quote(k)}
		}
	}
	t := get("type")
	if t == nil {
		for _, k := range []string{"platform", "identifier", "team_id", "browser", "extension_id", "name", "tap", "identity_kind", "source"} {
			if get(k) != nil {
				return "", &approvalErrorResp{Error: "invalid_request", Message: "a product filter needs type"}
			}
		}
		return "", nil
	}
	p, ie := normalizeApprovalItem(approvalItem{Type: *t, Platform: get("platform"), Identifier: get("identifier"),
		TeamID: get("team_id"), Browser: get("browser"), ExtensionID: get("extension_id"),
		Name: get("name"), Tap: get("tap"), IdentityKind: get("identity_kind"), Source: get("source")})
	if ie != nil {
		return "", &approvalErrorResp{Error: "invalid_request", Message: ie.Message}
	}
	return p.Key, nil
}

func strictPositiveInt(v string, min, max int) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

const approvalDecisionColumns = `
	id, batch_id::text, product_type, product_key, platform, identifier, team_id, browser,
	observation_kind, observation_source, previous_state, new_state, reason, actor_email, protected_warning, decided_at`

func scanApprovalDecisions(rows pgx.Rows) ([]approvalDecision, error) {
	defer rows.Close()
	out := []approvalDecision{}
	for rows.Next() {
		var d approvalDecision
		if err := rows.Scan(&d.ID, &d.BatchID, &d.ProductType, &d.ProductKey, &d.Platform, &d.Identifier,
			&d.TeamID, &d.Browser, &d.ObservationKind, &d.ObservationSource, &d.PreviousState, &d.NewState, &d.Reason, &d.ActorEmail,
			&d.ProtectedWarning, &d.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PortalSoftwareApprovalHistoryHandler serves
// GET /v1/portal/software-approvals/history. Readable by every portal role.
func PortalSoftwareApprovalHistoryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		if _, ok := q["format"]; ok {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format applies to the export endpoint only", nil)
			return
		}
		key, ferr := approvalHistoryFilter(q)
		if ferr != nil {
			writeApprovalError(w, http.StatusBadRequest, ferr.Error, ferr.Message, nil)
			return
		}
		limit, offset := approvalHistoryDefaultLim, 0
		if v := q.Get("limit"); v != "" {
			n, ok := strictPositiveInt(v, 1, approvalHistoryMaxLim)
			if !ok {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be 1 to %d", approvalHistoryMaxLim), nil)
				return
			}
			limit = n
		}
		if v := q.Get("offset"); v != "" {
			n, ok := strictPositiveInt(v, 0, 1<<30)
			if !ok {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "offset must be 0 or more", nil)
				return
			}
			offset = n
		}

		var total int
		if err := pool.QueryRow(r.Context(), `
			SELECT COUNT(*) FROM software_approval_decisions
			WHERE tenant_id = $1::uuid AND ($2 = '' OR product_key = $2)
		`, id.TenantID, key).Scan(&total); err != nil {
			slog.Error("approval history count failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rows, err := pool.Query(r.Context(), `
			SELECT `+approvalDecisionColumns+`
			FROM software_approval_decisions
			WHERE tenant_id = $1::uuid AND ($2 = '' OR product_key = $2)
			ORDER BY decided_at DESC, id DESC
			LIMIT $3 OFFSET $4
		`, id.TenantID, key, limit, offset)
		if err != nil {
			slog.Error("approval history query failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		decisions, err := scanApprovalDecisions(rows)
		if err != nil {
			slog.Error("approval history scan failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"product_key": optionalString(key), "total": total, "limit": limit, "offset": offset,
			"returned": len(decisions), "decisions": decisions,
		})
	}
}

// csvSafe neutralises a cell a spreadsheet would read as a formula (CSV
// injection): reasons and identifiers are customer-supplied text.
func csvSafe(s string) string { return report.CSVSafe(s) }

func derefOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// PortalSoftwareApprovalHistoryExportHandler serves
// GET /v1/portal/software-approvals/history/export?format=csv|json (default
// json), the same optional product filter as the history endpoint, and no
// paging. Over ApprovalExportMaxRows it fails closed (413) rather than send
// a silently truncated file.
func PortalSoftwareApprovalHistoryExportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		if _, ok := q["limit"]; ok {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "the export is not paged", nil)
			return
		}
		if _, ok := q["offset"]; ok {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "the export is not paged", nil)
			return
		}
		format := q.Get("format")
		if format == "" {
			format = "json"
		}
		if format != "json" && format != "csv" {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format must be csv or json", nil)
			return
		}
		key, ferr := approvalHistoryFilter(q)
		if ferr != nil {
			writeApprovalError(w, http.StatusBadRequest, ferr.Error, ferr.Message, nil)
			return
		}
		rows, err := pool.Query(r.Context(), `
			SELECT `+approvalDecisionColumns+`
			FROM software_approval_decisions
			WHERE tenant_id = $1::uuid AND ($2 = '' OR product_key = $2)
			ORDER BY decided_at DESC, id DESC
			LIMIT $3
		`, id.TenantID, key, ApprovalExportMaxRows+1)
		if err != nil {
			slog.Error("approval export query failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		decisions, err := scanApprovalDecisions(rows)
		if err != nil {
			slog.Error("approval export scan failed", "err", err, "tenant_id", id.TenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(decisions) > ApprovalExportMaxRows {
			writeApprovalError(w, http.StatusRequestEntityTooLarge, "export_too_large",
				fmt.Sprintf("the history has more than %d decisions; export one product at a time", ApprovalExportMaxRows), nil)
			return
		}

		filename := "software-approval-history-" + time.Now().UTC().Format("2006-01-02") + "." + format
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("X-Patched-Export-Rows", strconv.Itoa(len(decisions)))
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"generated_at": time.Now().UTC(), "product_key": optionalString(key),
				"total": len(decisions), "decisions": decisions,
			})
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"decided_at", "actor_email", "product_type", "product_key", "platform", "identifier",
			"team_id", "browser", "observation_kind", "observation_source", "previous_state", "new_state", "reason", "protected_warning", "batch_id", "id"})
		for _, d := range decisions {
			_ = cw.Write([]string{
				d.DecidedAt.UTC().Format(time.RFC3339), csvSafe(d.ActorEmail), d.ProductType, csvSafe(d.ProductKey),
				derefOr(d.Platform), csvSafe(d.Identifier), csvSafe(derefOr(d.TeamID)), derefOr(d.Browser), csvSafe(derefOr(d.ObservationKind)), csvSafe(derefOr(d.ObservationSource)),
				d.PreviousState, d.NewState, csvSafe(derefOr(d.Reason)), strconv.FormatBool(d.ProtectedWarning),
				d.BatchID, strconv.FormatInt(d.ID, 10),
			})
		}
		cw.Flush()
	}
}
