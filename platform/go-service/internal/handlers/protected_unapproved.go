package handlers

// The one rule for marking protected software (PAT-1801) Unapproved,
// shared by the operator admin API (PUT /admin/tenants/{id}/app-policies)
// and the customer portal (PUT /v1/portal/software-approvals). PAT-2088:
// the two used to disagree, the admin API refusing with 409 and the portal
// (PAT-2007 ruling) allowing with a warning.
//
// Ruling: warn and allow. Unapproved is a governance decision. It is
// refused only where it would feed enforcement for the tenant, because the
// point of PAT-1801 is that security tooling (EDR, MDM agent, backup agent,
// Patched's own collector) can never be switched off by a policy write, not
// that nobody may record an opinion about it.
//
// Where does Unapproved feed enforcement? Worked through for PAT-2088:
//
//   - The one projection of the policy store that reaches agents is the
//     signed App Control extension blocklist (dbGetExtensionBlocklist):
//     operator-set (PAT-2089) non-Safari extension rows on a tenant with
//     App Control on. An extension row carries no application identity, and
//     the protected-software list is keyed only on application identity
//     (Team ID or signer, bundle ID, Windows publisher and product code,
//     process or product name), so no extension row can match it.
//   - An application Unapproved reaches no agent as enforcement. It shows
//     in the signed posture as unapproved_present drift (a text notice on
//     the device), raises the PAT-2009 alert and can be cited to authorise
//     a removal campaign, but the removal campaign create and authorise
//     paths refuse a protected target themselves (removal_campaigns.go,
//     inside the authorising transaction). The Slack notice the admin API
//     sends on the transition is a notification.
//
// So today no application Unapproved feeds enforcement and every protected
// application is warn-and-allow on both paths. The refusal branch stays in
// the rule so that the day an application Unapproved does reach an agent,
// that caller passes feedsEnforcement=true and gets a refusal, from the
// same function, without a second copy of the rule.

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/protectedsoftware"
)

// applicationUnapprovedFeedsEnforcement records the finding above: no
// application Unapproved decision is projected to an agent as enforcement.
const applicationUnapprovedFeedsEnforcement = false

// protectedUnapprovedVerdict is the outcome of the shared rule.
type protectedUnapprovedVerdict struct {
	// Match is the protected_software row the product matched; nil when the
	// product is not protected.
	Match *protectedsoftware.Match
	// Refuse is true only for a protected product whose Unapproved would
	// feed enforcement. Otherwise a non-nil Match is a warning.
	Refuse bool
}

// Warn reports whether the write goes ahead with a protected warning.
func (v protectedUnapprovedVerdict) Warn() bool { return v.Match != nil && !v.Refuse }

// protectedUnapprovedRule is the PAT-2088 rule itself.
func protectedUnapprovedRule(match *protectedsoftware.Match, feedsEnforcement bool) protectedUnapprovedVerdict {
	return protectedUnapprovedVerdict{Match: match, Refuse: match != nil && feedsEnforcement}
}

// appProtectionIdentity is an application as either writer addresses it.
// Pointers are nil when absent. Platform is macos, windows or any.
type appProtectionIdentity struct {
	Platform string
	TeamID   *string
	BundleID *string
	WingetID *string
	Name     *string
}

// checkProtectedUnapprovedApp applies the shared rule to an application being
// set Unapproved, inside the caller's write transaction so a protection
// added concurrently is either seen here or committed after this write.
func checkProtectedUnapprovedApp(ctx context.Context, tx pgx.Tx, tenantID string, id appProtectionIdentity) (protectedUnapprovedVerdict, error) {
	match, err := protectedMatchForApp(ctx, tx, tenantID, id)
	if err != nil {
		return protectedUnapprovedVerdict{}, err
	}
	return protectedUnapprovedRule(match, applicationUnapprovedFeedsEnforcement), nil
}

// protectedMatchForApp checks an application against the tenant's effective
// protected-software list. Written and observed strong identities retain
// Check's rule that a failed strong match never falls back to a name.
// Windows package identifiers are not MSI ProductCodes, and display names
// are compared only with product_name, never with process_name.
func protectedMatchForApp(ctx context.Context, tx pgx.Tx, tenantID string, id appProtectionIdentity) (*protectedsoftware.Match, error) {
	written := protectedsoftware.Identity{TeamID: id.TeamID, ProductName: id.Name}
	if id.Platform != "windows" {
		written.BundleID = id.BundleID
	}
	if m, err := protectedsoftware.Check(ctx, tx, tenantID, written); m != nil || err != nil {
		return m, err
	}

	identifier := ""
	switch {
	case id.BundleID != nil && *id.BundleID != "":
		identifier = *id.BundleID
	case id.WingetID != nil && *id.WingetID != "":
		identifier = *id.WingetID
	}
	if identifier == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT si.platform, si.identity_kind, si.current_name,
		       si.identity_value_normalized, si.companion_value_normalized,
		       CASE WHEN so.observed_signature_state = 'valid'
		            THEN COALESCE(so.observed_authenticode_signer, '') ELSE '' END
		FROM software_installations si
		LEFT JOIN software_observations so ON so.id = si.latest_observation_id
		  AND so.tenant_id = si.tenant_id AND so.device_id = si.device_id
		WHERE si.tenant_id = $1::uuid
		  AND ($2 = 'any' OR si.platform = $2)
		  AND si.identity_value_normalized = lower(btrim($3))
		  AND si.identity_kind IN ('macos_bundle_team', 'macos_bundle', 'windows_winget',
		                           'windows_native_publisher', 'windows_native')
		  AND si.removed_at IS NULL
	`, tenantID, id.Platform, identifier)
	if err != nil {
		return nil, err
	}
	var seen []observedProtectionIdentity
	for rows.Next() {
		var o observedProtectionIdentity
		if err := rows.Scan(&o.platform, &o.kind, &o.name, &o.identifier, &o.companion, &o.signer); err != nil {
			rows.Close()
			return nil, err
		}
		seen = append(seen, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, o := range seen {
		identity := o.protectedIdentity()
		// A policy with a Team ID must not borrow the identity or name of a
		// different signer reporting the same bundle/package identifier.
		if id.TeamID != nil && strings.TrimSpace(*id.TeamID) != "" &&
			(identity.TeamID == nil || !strings.EqualFold(strings.TrimSpace(*id.TeamID), strings.TrimSpace(*identity.TeamID))) {
			continue
		}
		if m, err := protectedsoftware.Check(ctx, tx, tenantID, identity); m != nil || err != nil {
			return m, err
		}
	}
	return nil, nil
}

type observedProtectionIdentity struct {
	platform, kind, name, identifier, companion, signer string
}

func (o observedProtectionIdentity) protectedIdentity() protectedsoftware.Identity {
	id := protectedsoftware.Identity{ProductName: &o.name}
	if o.platform == "macos" {
		id.BundleID = &o.identifier
		if o.kind == "macos_bundle_team" && o.companion != "" {
			id.TeamID = &o.companion
		}
	} else if o.platform == "windows" && o.signer != "" {
		id.TeamID = &o.signer
	}
	return id
}
