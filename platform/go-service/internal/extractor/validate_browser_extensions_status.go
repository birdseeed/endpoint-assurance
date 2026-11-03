package extractor

import (
	"fmt"
	"math"
)

// validateBrowserExtensionsStatus checks the STRUCTURE of the PAT-2055
// browser_extensions_status block: types, enums, required and unknown keys.
// A structural error rejects the payload (400). It echoes no payload value,
// and the block has already been through the PAT-2021 case-variant and
// duplicate-key walk (checkPayloadKeys, strictBlockKeys).
//
// It deliberately does NOT reject a structurally valid block whose statuses
// disagree with each other or with the browser_extensions array, or that
// lists too many users. Rejecting would drop the whole device inventory
// (apps, CVEs, CIS, last_seen) every cycle over a completeness claim, for
// example a user_account whose case differs from the block's user. Those
// problems are found at ingest by browserExtensionsStatusProblem and the
// block is stored with its authority withheld, which is always safe: absence
// needs authority, and a withheld block grants none.
//
// Structure:
//
//   - collection_status is required. "failed" may omit cap_reached and users;
//     every other status sends both.
//   - users[] rows: user (non-empty), user_id (string or null),
//     collection_status, browsers {chrome, edge, firefox}. Every browser is
//     required unless the user is "failed".
func validateBrowserExtensionsStatus(m map[string]any) error {
	const block = "browser_extensions_status"
	v := tv{echoKeys: true}
	obj, err := tvObject(m[block], block)
	if err != nil {
		return err
	}
	path := block + "."
	topKeys := []string{"collection_status", "cap_reached", "users"}
	if err := v.keys(path, obj, false, topKeys...); err != nil {
		return err
	}
	status, err := tvEnum(obj, path, "collection_status", toolingStatuses, false)
	if err != nil {
		return err
	}
	if status == "" {
		return fmt.Errorf("%scollection_status: required field is missing", path)
	}
	if status != "failed" {
		if err := v.keys(path, obj, true, topKeys...); err != nil {
			return fmt.Errorf("%w (required when collection_status is %q)", err, status)
		}
	}
	if err := tvBool(obj, path, "cap_reached", false); err != nil {
		return err
	}

	// The 500-user contract bound is a downgrade, not a rejection; the body
	// cap (6 MB) bounds the work here.
	users, err := tvItems(obj, path, "users", math.MaxInt32)
	if err != nil {
		return err
	}
	for i, u := range users {
		p := fmt.Sprintf("%susers[%d].", path, i)
		if err := v.keys(p, u, true, "user", "user_id", "collection_status", "browsers"); err != nil {
			return err
		}
		if err := tvString(u, p, "user", false); err != nil {
			return err
		}
		if err := tvString(u, p, "user_id", true); err != nil {
			return err
		}
		ust, err := tvEnum(u, p, "collection_status", toolingStatuses, false)
		if err != nil {
			return err
		}
		browsers, err := tvObject(u["browsers"], p+"browsers")
		if err != nil {
			return err
		}
		bp := p + "browsers."
		if err := v.keys(bp, browsers, ust != "failed", browserExtensionStatusBrowsers...); err != nil {
			return err
		}
		for _, browser := range browserExtensionStatusBrowsers {
			if _, err := tvEnum(browsers, bp, browser, toolingStatuses, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reasons a structurally valid block has its authority withheld. Fixed
// tokens: logged and stored in browser_extension_device_state.
// authority_withheld, never a payload value.
const (
	beWithheldCapNotPartial        = "cap_reached_not_partial"
	beWithheldTooManyUsers         = "too_many_users"
	beWithheldDuplicateUser        = "duplicate_user"
	beWithheldUserStatus           = "user_status_inconsistent"
	beWithheldBrowserStatus        = "browser_status_inconsistent"
	beWithheldRowsWhenNotPresent   = "rows_listed_when_not_present"
	beWithheldRowUnderNotPresent   = "row_under_not_present_pair"
	beWithheldRowNotCoveredByBlock = "row_not_reported_complete"
)

// browserExtensionsStatusMaxUsers is the contract bound on users[].
const browserExtensionsStatusMaxUsers = toolingMaxUsers

// browserExtensionsStatusProblem returns "" when the block is internally
// consistent and agrees with the browser_extensions rows, or the fixed reason
// its authority must be withheld. A failed block grants no authority anyway,
// so it is never checked.
//
// Consistency rules:
//
//   - cap_reached is only valid with "partial";
//   - at most 500 users, unique by user;
//   - a complete block has only complete or not_present users and browsers;
//     a not_present block only not_present ones; a complete user only
//     complete or not_present browsers; a not_present user only not_present
//     browsers;
//   - against the array (chrome, edge and firefox rows with a non-empty
//     user_account; Safari rows carry no user): a not_present block lists no
//     such row, no row sits under a (user, browser) reported not_present, and
//     a complete block reports every such row's (user, browser) complete.
//
// Users match user_account exactly, on both platforms. A case difference is
// therefore a mismatch: it withholds authority rather than risk one account's
// complete report proving another account's extensions gone.
func browserExtensionsStatusProblem(st *browserExtensionsStatusPart, rows []browserExtensionPart) string {
	if st == nil || st.CollectionStatus == "failed" {
		return ""
	}
	status := st.CollectionStatus
	if st.CapReached && status != "partial" {
		return beWithheldCapNotPartial
	}
	if len(st.Users) > browserExtensionsStatusMaxUsers {
		return beWithheldTooManyUsers
	}
	pairs := map[[2]string]string{}
	seen := map[string]bool{}
	for _, u := range st.Users {
		if seen[u.User] {
			return beWithheldDuplicateUser
		}
		seen[u.User] = true
		if !statusFits(status, u.CollectionStatus) {
			return beWithheldUserStatus
		}
		for _, browser := range browserExtensionStatusBrowsers {
			s := u.Browsers.get(browser)
			if s == nil {
				continue
			}
			if !statusFits(status, *s) || !statusFits(u.CollectionStatus, *s) {
				return beWithheldBrowserStatus
			}
			pairs[[2]string{u.User, browser}] = *s
		}
	}
	for _, r := range rows {
		if r.UserAccount == "" || !isBrowserExtensionStatusBrowser(r.Browser) {
			continue
		}
		pst, listed := pairs[[2]string{r.UserAccount, r.Browser}]
		switch {
		case status == "not_present":
			return beWithheldRowsWhenNotPresent
		case listed && pst == "not_present":
			return beWithheldRowUnderNotPresent
		case status == "complete" && pst != "complete":
			return beWithheldRowNotCoveredByBlock
		}
	}
	return ""
}

// statusFits is userStatusFits as a predicate: a complete parent allows only
// complete or not_present below it, a not_present parent only not_present.
func statusFits(parent, child string) bool {
	switch parent {
	case "complete":
		return child == "complete" || child == "not_present"
	case "not_present":
		return child == "not_present"
	}
	return true
}

func isBrowserExtensionStatusBrowser(browser string) bool {
	for _, b := range browserExtensionStatusBrowsers {
		if b == browser {
			return true
		}
	}
	return false
}
