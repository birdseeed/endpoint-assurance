package categorytag

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackfillChunkSize bounds the observations one backfill transaction reads,
// so a publish over a large estate commits in steps well inside the 60s
// internal request budget instead of rolling back as one huge transaction.
var BackfillChunkSize = 1000

// observed is one taggable observation with its tenant binding.
type observed struct {
	TenantID           string
	DeviceID           string
	InstallationID     string // app
	BrowserExtensionID int64  // browser_extension
	ProductID          string // app, when resolved to a software_products row
	Removed            bool   // app installation closed under authoritative scope
	Obs                Observation
}

// ref identifies an observation independent of its kind. Every
// installation-backed kind shares the "app:" prefix, which the live-tag query
// in EvaluateDevice builds from installation_id.
func (o observed) ref() string {
	if o.InstallationID != "" {
		return "app:" + o.InstallationID
	}
	return "ext:" + strconv.FormatInt(o.BrowserExtensionID, 10)
}

// appColumns reads an app from the installation projection plus its latest
// observation. A missing team_id or signer reads as "" (no opinion).
const appColumns = `
	si.id::text, si.tenant_id::text, si.device_id::text, COALESCE(si.product_id::text, ''),
	si.removed_at IS NOT NULL,
	si.platform, si.identity_kind, si.identity_value_normalized,
	COALESCE(so.observed_team_id,
	         CASE WHEN si.identity_kind = 'macos_bundle_team' THEN si.companion_value_normalized END, ''),
	COALESCE(so.observed_signer, ''),
	COALESCE(so.observed_name, si.current_name),
	-- The extractor stores a fallback (path, identifier or "unknown
	-- software") when the payload has no display name, and only the stored
	-- value survives. Any name equal to a fallback reads as no opinion. That
	-- is conservative: it only stops the name contradicting a rule (a real
	-- name that happens to equal the identifier never retires a tag); it
	-- never changes what matches.
	COALESCE(so.observed_name IS NULL OR so.observed_name = 'unknown software'
	    OR so.observed_name = so.observed_path OR so.observed_name = so.observed_identifier, true),
	si.companion_value_normalized`

const appFrom = `
	FROM software_installations si
	LEFT JOIN software_observations so ON so.id = si.latest_observation_id`

func scanApp(row pgx.Row, extra ...any) (observed, error) {
	o := observed{Obs: Observation{Kind: KindApp}}
	var companion string
	dest := append(extra, &o.InstallationID, &o.TenantID, &o.DeviceID, &o.ProductID, &o.Removed,
		&o.Obs.Platform, &o.Obs.IdentityKind, &o.Obs.IdentityValue, &o.Obs.TeamID,
		&o.Obs.Signer, &o.Obs.Name, &o.Obs.NameUnknown, &companion)
	if err := row.Scan(dest...); err != nil {
		return o, err
	}
	// PAT-2021: IDE extensions, packages, MCP servers and local models are
	// installations too; give the matcher their own view.
	if kind, view := InstallationObservation(o.Obs.IdentityKind, o.Obs.IdentityValue, companion); kind != KindApp {
		view.Platform = o.Obs.Platform
		view.IdentityKind, view.IdentityValue = o.Obs.IdentityKind, o.Obs.IdentityValue
		o.Obs = view
	}
	return o, nil
}

// extensionColumns: the platform is the device's. An unrecognised OS reads
// "any", so only unscoped rules can match it: no platform is guessed.
const extensionColumns = `
	dbe.id, d.tenant_id::text, dbe.device_id::text, dbe.browser, dbe.extension_id,
	CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
	     WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos'
	     ELSE 'any' END`

const extensionFrom = `
	FROM device_browser_extensions dbe
	JOIN devices d ON d.id = dbe.device_id`

func scanExtension(row pgx.Row, extra ...any) (observed, error) {
	o := observed{Obs: Observation{Kind: KindBrowserExtension}}
	dest := append(extra, &o.BrowserExtensionID, &o.TenantID, &o.DeviceID, &o.Obs.Browser,
		&o.Obs.Identifier, &o.Obs.Platform)
	return o, row.Scan(dest...)
}

func collect(ctx context.Context, tx pgx.Tx, what string, scan func(pgx.Row) (observed, error), sql string, args ...any) ([]observed, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", what, err)
	}
	defer rows.Close()
	var out []observed
	for rows.Next() {
		o, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func loadApps(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]observed, error) {
	return collect(ctx, tx, "app observations", func(r pgx.Row) (observed, error) { return scanApp(r) },
		`SELECT `+appColumns+appFrom+` `+where, args...)
}

func loadExtensions(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]observed, error) {
	return collect(ctx, tx, "browser extension observations", func(r pgx.Row) (observed, error) { return scanExtension(r) },
		`SELECT `+extensionColumns+extensionFrom+` `+where, args...)
}

// candidateFilter returns the SQL that selects the present observations a
// rule can match, by exact normalised value wherever the stored value is
// normalised by the extractor itself (bundle IDs, Winget IDs, extension IDs),
// so a backfill never scans a whole table into memory. It must never be
// stricter than Matches, which decides. ok is false for observation kinds
// this filter does not (yet) know how to select. PAT-2021 added IDE
// extensions, npm, pip and MCP servers, filtered on the identity the
// extractor stores; PAT-2094 added Homebrew formulae and casks (already
// ingested onto the same software_installations seam by
// internal/extractor/homebrew_inventory.go, just not previously wired to the
// matcher) and the kind-level filter for TypeKind.
func candidateFilter(rule Rule) (kind, where string, args []any, ok bool) {
	switch rule.IdentifierType {
	case TypeMacOSBundleID:
		return KindApp, `si.removed_at IS NULL AND si.platform = 'macos'
			AND si.identity_kind IN ('macos_bundle_team', 'macos_bundle')
			AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
	case TypeMacOSTeamID:
		return KindApp, `si.removed_at IS NULL AND si.platform = 'macos'
			AND si.identity_kind IN ('macos_bundle_team', 'macos_bundle')
			AND si.identity_value_normalized = $1`, []any{rule.Qualifier}, true
	case TypeWindowsAuthenticode:
		// Deliberately coarse: Go and PostgreSQL fold case and whitespace
		// differently for non-ASCII text (a non-breaking space, an accented
		// publisher), so an exact SQL comparison could be stricter than Go
		// and silently drop real matches. The filter is a superset (present
		// Windows apps that report a signer, walked in bounded chunks) and
		// Matches is the single exact authority. The agent reports no app
		// signer today, so this set is empty in production.
		return KindApp, `si.removed_at IS NULL AND si.platform = 'windows'
			AND so.observed_signer IS NOT NULL`, nil, true
	case TypePackage:
		switch rule.Qualifier {
		case SourceWinget:
			return KindApp, `si.removed_at IS NULL AND si.platform = 'windows'
				AND si.identity_kind = 'windows_winget'
				AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
		case SourceNPM:
			return KindApp, `si.removed_at IS NULL AND si.identity_kind = 'npm_package'
				AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
		case SourcePip:
			return KindApp, `si.removed_at IS NULL AND si.identity_kind = 'pip_package'
				AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
		case SourceBrewFormula:
			return KindApp, `si.removed_at IS NULL AND si.platform = 'macos'
				AND si.identity_kind = 'homebrew_formula'
				AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
		case SourceBrewCask:
			return KindApp, `si.removed_at IS NULL AND si.platform = 'macos'
				AND si.identity_kind = 'homebrew_cask'
				AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
		}
	case TypeIDEExtension:
		return KindApp, `si.removed_at IS NULL AND si.identity_kind = 'ide_extension'
			AND si.identity_value_normalized = $1 AND si.companion_value_normalized = $2`,
			[]any{rule.IdentifierValue, rule.Qualifier}, true
	case TypeMCPServer:
		return KindApp, `si.removed_at IS NULL AND si.identity_kind = 'mcp_server'
			AND si.identity_value_normalized = $1`, []any{rule.IdentifierValue}, true
	case TypeKind:
		// Every present installation of the target kind, no identifier
		// equality: kindRuleKinds keeps this to mcp_server only.
		if rule.IdentifierValue == KindMCPServer {
			return KindApp, `si.removed_at IS NULL
				AND si.identity_kind IN ('mcp_server', 'mcp_server_unnamed')`, nil, true
		}
	case TypeBrowserExtension:
		return KindBrowserExtension, `lower(dbe.extension_id) = $1`, []any{rule.IdentifierValue}, true
	}
	return "", "", nil, false
}

type tagRow struct {
	obs          observed
	ruleID       int64
	productTagID int64
}

func insertTags(ctx context.Context, tx pgx.Tx, tags []tagRow) (int, error) {
	if len(tags) == 0 {
		return 0, nil
	}
	n := len(tags)
	tenants, devices, kinds := make([]string, n), make([]string, n), make([]string, n)
	installs := make([]*string, n)
	exts, rules, products := make([]*int64, n), make([]*int64, n), make([]*int64, n)
	for i, t := range tags {
		tenants[i], devices[i], kinds[i] = t.obs.TenantID, t.obs.DeviceID, t.obs.Obs.Kind
		if t.obs.InstallationID != "" {
			id := t.obs.InstallationID
			installs[i] = &id
		} else {
			id := t.obs.BrowserExtensionID
			exts[i] = &id
		}
		if t.ruleID != 0 {
			id := t.ruleID
			rules[i] = &id
		} else {
			id := t.productTagID
			products[i] = &id
		}
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO software_category_tags
			(tenant_id, device_id, observation_kind, installation_id, browser_extension_id, rule_id, product_tag_id)
		SELECT u.tenant_id::uuid, u.device_id::uuid, u.kind, u.installation_id::uuid, u.ext_id, u.rule_id, u.product_tag_id
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[])
			AS u(tenant_id, device_id, kind, installation_id, ext_id, rule_id, product_tag_id)
		ON CONFLICT DO NOTHING
	`, tenants, devices, kinds, installs, exts, rules, products)
	if err != nil {
		return 0, fmt.Errorf("insert category tags: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func retireTagIDs(ctx context.Context, tx pgx.Tx, ids []int64, reason string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `
		UPDATE software_category_tags SET retired_at = now(), retired_reason = $2
		WHERE id = ANY($1::bigint[]) AND retired_at IS NULL`, ids, reason)
	if err != nil {
		return 0, fmt.Errorf("retire category tags: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// retireAllForRule retires every live tag a rule produced, in one statement.
// Used by retire (rule_retired) and by editing a draft (rule_changed).
func retireAllForRule(ctx context.Context, tx pgx.Tx, ruleID int64, reason string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE software_category_tags SET retired_at = now(), retired_reason = $2
		WHERE rule_id = $1 AND retired_at IS NULL`, ruleID, reason)
	if err != nil {
		return 0, fmt.Errorf("retire rule tags: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// lockRuleShared takes FOR SHARE on the rule for the rest of the chunk's
// transaction, so a concurrent retire (FOR UPDATE) waits for the chunk to
// commit and then retires what it wrote, and a chunk that starts after a
// retire sees the new state. The expected state and version guard against
// an edit or retire landing between chunks.
func lockRuleShared(ctx context.Context, tx pgx.Tx, id int64, wantState string, wantVersion int) (Rule, error) {
	rule, err := scanRule(tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM software_category_rules WHERE id = $1 FOR SHARE`, id))
	if err != nil {
		return Rule{}, err
	}
	if rule.State != wantState || rule.Version != wantVersion {
		return Rule{}, fmt.Errorf("%w: the rule changed while its tags were being reconciled; retry", ErrConflict)
	}
	return rule, nil
}

// chunked runs step in its own transaction until it reports a short chunk.
// Totals are only counted once a chunk's transaction has committed.
func chunked(ctx context.Context, pool *pgxpool.Pool, total *Result, step func(tx pgx.Tx) (int, Result, error)) error {
	for {
		var n int
		var res Result
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			n, res, err = step(tx)
			return err
		}); err != nil {
			return err
		}
		total.add(res)
		if n < BackfillChunkSize {
			return nil
		}
	}
}

// reconcileRuleChunked brings a rule's tags in line with its definition in
// bounded transactions. Pass one walks the rule's live tags and retires
// those whose observation positively contradicts the rule (rule_changed) or
// whose installation has been removed (no_longer_matches); a missing field
// keeps the tag. Pass two walks the exact-value candidates and tags matches.
func reconcileRuleChunked(ctx context.Context, pool *pgxpool.Pool, ruleID int64, wantState string, wantVersion int) (Result, error) {
	var total Result

	var appTagCursor int64
	if err := chunked(ctx, pool, &total, func(tx pgx.Tx) (int, Result, error) {
		rule, err := lockRuleShared(ctx, tx, ruleID, wantState, wantVersion)
		if err != nil {
			return 0, Result{}, err
		}
		type tagged struct {
			id  int64
			obs observed
		}
		rows, err := tx.Query(ctx, `SELECT t.id, `+appColumns+`
			FROM software_category_tags t
			JOIN software_installations si ON si.id = t.installation_id
			LEFT JOIN software_observations so ON so.id = si.latest_observation_id
			WHERE t.rule_id = $1 AND t.retired_at IS NULL AND t.id > $2
			ORDER BY t.id LIMIT $3`, ruleID, appTagCursor, BackfillChunkSize)
		if err != nil {
			return 0, Result{}, fmt.Errorf("load rule app tags: %w", err)
		}
		var list []tagged
		for rows.Next() {
			var tg tagged
			if tg.obs, err = scanApp(rows, &tg.id); err != nil {
				rows.Close()
				return 0, Result{}, err
			}
			list = append(list, tg)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, Result{}, err
		}
		var changed, gone []int64
		for _, tg := range list {
			appTagCursor = tg.id
			switch {
			case tg.obs.Removed:
				gone = append(gone, tg.id)
			case Contradicts(rule.RuleSpec, tg.obs.Obs):
				changed = append(changed, tg.id)
			}
		}
		var res Result
		a, err := retireTagIDs(ctx, tx, changed, ReasonRuleChanged)
		if err != nil {
			return 0, Result{}, err
		}
		b, err := retireTagIDs(ctx, tx, gone, ReasonNoLongerMatches)
		res.Retired = a + b
		return len(list), res, err
	}); err != nil {
		return total, err
	}

	var extTagCursor int64
	if err := chunked(ctx, pool, &total, func(tx pgx.Tx) (int, Result, error) {
		rule, err := lockRuleShared(ctx, tx, ruleID, wantState, wantVersion)
		if err != nil {
			return 0, Result{}, err
		}
		rows, err := tx.Query(ctx, `SELECT t.id, `+extensionColumns+`
			FROM software_category_tags t
			JOIN device_browser_extensions dbe ON dbe.id = t.browser_extension_id
			JOIN devices d ON d.id = dbe.device_id
			WHERE t.rule_id = $1 AND t.retired_at IS NULL AND t.id > $2
			ORDER BY t.id LIMIT $3`, ruleID, extTagCursor, BackfillChunkSize)
		if err != nil {
			return 0, Result{}, fmt.Errorf("load rule extension tags: %w", err)
		}
		var changed []int64
		n := 0
		for rows.Next() {
			var id int64
			o, err := scanExtension(rows, &id)
			if err != nil {
				rows.Close()
				return 0, Result{}, err
			}
			n++
			extTagCursor = id
			if Contradicts(rule.RuleSpec, o.Obs) {
				changed = append(changed, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, Result{}, err
		}
		retired, err := retireTagIDs(ctx, tx, changed, ReasonRuleChanged)
		return n, Result{Retired: retired}, err
	}); err != nil {
		return total, err
	}

	// Pass two: candidates, keyset-paginated so each chunk is bounded.
	var appCursor = "00000000-0000-0000-0000-000000000000"
	var extCursor int64
	err := chunked(ctx, pool, &total, func(tx pgx.Tx) (int, Result, error) {
		rule, err := lockRuleShared(ctx, tx, ruleID, wantState, wantVersion)
		if err != nil {
			return 0, Result{}, err
		}
		kind, where, args, ok := candidateFilter(rule)
		if !ok {
			return 0, Result{}, nil
		}
		var cands []observed
		if kind == KindApp {
			args = append(args, appCursor, BackfillChunkSize)
			cands, err = loadApps(ctx, tx, fmt.Sprintf(`WHERE %s AND si.id > $%d::uuid ORDER BY si.id LIMIT $%d`,
				where, len(args)-1, len(args)), args...)
			if len(cands) > 0 {
				appCursor = cands[len(cands)-1].InstallationID
			}
		} else {
			args = append(args, extCursor, BackfillChunkSize)
			cands, err = loadExtensions(ctx, tx, fmt.Sprintf(`WHERE %s AND dbe.id > $%d ORDER BY dbe.id LIMIT $%d`,
				where, len(args)-1, len(args)), args...)
			if len(cands) > 0 {
				extCursor = cands[len(cands)-1].BrowserExtensionID
			}
		}
		if err != nil {
			return 0, Result{}, err
		}
		var rows []tagRow
		for _, c := range cands {
			if Matches(rule.RuleSpec, c.Obs) {
				rows = append(rows, tagRow{obs: c, ruleID: ruleID})
			}
		}
		tagged, err := insertTags(ctx, tx, rows)
		return len(cands), Result{Tagged: tagged}, err
	})
	return total, err
}

// ReconcileProductTag brings one product tag's live tags in line with its
// state: a published tag covers every present installation resolved to the
// product; a retired one retires all of its tags. Tags on installations that
// were removed or re-resolved to a different product are retired.
func ReconcileProductTag(ctx context.Context, tx pgx.Tx, id int64) (Result, error) {
	tag, err := scanProductTag(tx.QueryRow(ctx, `SELECT `+productTagColumns+` FROM software_category_product_tags pt
		JOIN software_products sp ON sp.id = pt.product_id WHERE pt.id = $1 FOR SHARE OF pt`, id))
	if err != nil {
		return Result{}, err
	}
	var res Result
	if tag.State != StatePublished {
		t, err := tx.Exec(ctx, `UPDATE software_category_tags SET retired_at = now(), retired_reason = $2
			WHERE product_tag_id = $1 AND retired_at IS NULL`, id, ReasonRuleRetired)
		if err != nil {
			return Result{}, err
		}
		res.Retired = int(t.RowsAffected())
		return res, nil
	}
	t, err := tx.Exec(ctx, `
		UPDATE software_category_tags t SET retired_at = now(), retired_reason = $2
		FROM software_installations si
		WHERE t.product_tag_id = $1 AND t.retired_at IS NULL AND si.id = t.installation_id
		  AND (si.removed_at IS NOT NULL OR (si.product_id IS NOT NULL AND si.product_id <> $3::uuid))`,
		id, ReasonNoLongerMatches, tag.ProductID)
	if err != nil {
		return Result{}, err
	}
	res.Retired = int(t.RowsAffected())
	matched, err := loadApps(ctx, tx, `WHERE si.product_id = $1::uuid AND si.removed_at IS NULL`, tag.ProductID)
	if err != nil {
		return Result{}, err
	}
	rows := make([]tagRow, 0, len(matched))
	for _, m := range matched {
		rows = append(rows, tagRow{obs: m, productTagID: id})
	}
	if res.Tagged, err = insertTags(ctx, tx, rows); err != nil {
		return Result{}, err
	}
	return res, nil
}

// EvaluateDevice reconciles one device's tags against every published rule
// and product tag. The extractor calls it inside the ingest transaction,
// under a savepoint, after apps and browser extensions are written.
//
// Rules and product tags are read FOR SHARE, so a concurrent retire either
// commits first (and this evaluation no longer sees the rule as published)
// or waits for this ingest to commit and then retires what it wrote. A
// retired rule therefore never gains a live tag.
//
// A live tag is retired only on authority: its installation was removed
// under an authoritative inventory scope, or the observation now carries a
// different identifying value (Contradicts). A payload that merely omits a
// field keeps the tag.
//
// Cost is one existence probe when nothing is published, otherwise a handful
// of indexed queries bounded by the device's own inventory.
func EvaluateDevice(ctx context.Context, tx pgx.Tx, tenantID, deviceID string) (Result, error) {
	var anyPublished bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM software_category_rules WHERE state = 'published')
		    OR EXISTS (SELECT 1 FROM software_category_product_tags WHERE state = 'published')
	`).Scan(&anyPublished); err != nil {
		return Result{}, fmt.Errorf("probe published category rules: %w", err)
	}
	if !anyPublished {
		return Result{}, nil
	}

	apps, err := loadApps(ctx, tx, `WHERE si.device_id = $1::uuid AND si.tenant_id = $2::uuid`, deviceID, tenantID)
	if err != nil {
		return Result{}, err
	}
	exts, err := loadExtensions(ctx, tx, `WHERE dbe.device_id = $1::uuid AND d.tenant_id = $2::uuid`, deviceID, tenantID)
	if err != nil {
		return Result{}, err
	}
	byRef := map[string]observed{}
	var present []observed
	for _, o := range append(apps, exts...) {
		byRef[o.ref()] = o
		if !o.Removed {
			present = append(present, o)
		}
	}

	var types, platforms, qualifiers, values []string
	productIDs := []string{}
	seen := map[Key]bool{}
	for _, o := range present {
		for _, k := range Keys(o.Obs) {
			if !seen[k] {
				seen[k] = true
				types, platforms = append(types, k.Type), append(platforms, k.Platform)
				qualifiers, values = append(qualifiers, k.Qualifier), append(values, k.Value)
			}
		}
		if o.ProductID != "" {
			productIDs = append(productIDs, o.ProductID)
		}
	}

	rulesByKey := map[Key][]int64{}
	if len(types) > 0 {
		rows, err := tx.Query(ctx, `
			SELECT r.id, r.identifier_type, r.platform, r.qualifier, r.identifier_value
			FROM software_category_rules r
			JOIN unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS k(t, p, q, v)
			  ON r.identifier_type = k.t AND r.platform = k.p AND r.qualifier = k.q AND r.identifier_value = k.v
			WHERE r.state = 'published'
			FOR SHARE OF r
		`, types, platforms, qualifiers, values)
		if err != nil {
			return Result{}, fmt.Errorf("load matching category rules: %w", err)
		}
		for rows.Next() {
			var id int64
			var k Key
			if err := rows.Scan(&id, &k.Type, &k.Platform, &k.Qualifier, &k.Value); err != nil {
				rows.Close()
				return Result{}, err
			}
			rulesByKey[k] = append(rulesByKey[k], id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return Result{}, err
		}
	}

	tagsByProduct := map[string][]int64{}
	if len(productIDs) > 0 {
		rows, err := tx.Query(ctx, `
			SELECT id, product_id::text FROM software_category_product_tags
			WHERE state = 'published' AND product_id = ANY($1::text[]::uuid[])
			FOR SHARE
		`, productIDs)
		if err != nil {
			return Result{}, fmt.Errorf("load matching product tags: %w", err)
		}
		for rows.Next() {
			var id int64
			var pid string
			if err := rows.Scan(&id, &pid); err != nil {
				rows.Close()
				return Result{}, err
			}
			tagsByProduct[pid] = append(tagsByProduct[pid], id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return Result{}, err
		}
	}

	desired := map[[3]string]tagRow{}
	pairKey := func(ref string, rule, ptag int64) [3]string {
		return [3]string{ref, strconv.FormatInt(rule, 10), strconv.FormatInt(ptag, 10)}
	}
	for _, o := range present {
		for _, k := range Keys(o.Obs) {
			for _, id := range rulesByKey[k] {
				desired[pairKey(o.ref(), id, 0)] = tagRow{obs: o, ruleID: id}
			}
		}
		for _, id := range tagsByProduct[o.ProductID] {
			desired[pairKey(o.ref(), 0, id)] = tagRow{obs: o, productTagID: id}
		}
	}

	// Live tags from published sources only. A draft's hidden tags (a
	// publish still backfilling) are the publish's business, not this one's.
	rows, err := tx.Query(ctx, `
		SELECT t.id, COALESCE('app:' || t.installation_id::text, 'ext:' || t.browser_extension_id::text),
		       COALESCE(t.rule_id, 0), COALESCE(t.product_tag_id, 0),
		       COALESCE(r.identifier_type, ''), COALESCE(r.platform, ''), COALESCE(r.qualifier, ''),
		       COALESCE(r.identifier_value, ''), COALESCE(pt.product_id::text, '')
		FROM software_category_tags t
		LEFT JOIN software_category_rules r ON r.id = t.rule_id
		LEFT JOIN software_category_product_tags pt ON pt.id = t.product_tag_id
		WHERE t.device_id = $1::uuid AND t.tenant_id = $2::uuid AND t.retired_at IS NULL
		  AND (r.state = 'published' OR pt.state = 'published')
	`, deviceID, tenantID)
	if err != nil {
		return Result{}, fmt.Errorf("load live category tags: %w", err)
	}
	var stale []int64
	for rows.Next() {
		var id, rule, ptag int64
		var ref, productID string
		var spec RuleSpec
		if err := rows.Scan(&id, &ref, &rule, &ptag, &spec.IdentifierType, &spec.Platform,
			&spec.Qualifier, &spec.IdentifierValue, &productID); err != nil {
			rows.Close()
			return Result{}, err
		}
		k := pairKey(ref, rule, ptag)
		if _, ok := desired[k]; ok {
			delete(desired, k)
			continue
		}
		o, ok := byRef[ref]
		switch {
		case !ok:
			// The observation row is gone; its cascade removes the tag.
		case o.Removed:
			stale = append(stale, id)
		case rule != 0 && Contradicts(spec, o.Obs):
			stale = append(stale, id)
		case ptag != 0 && o.ProductID != "" && o.ProductID != productID:
			stale = append(stale, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Result{}, err
	}

	var res Result
	if res.Retired, err = retireTagIDs(ctx, tx, stale, ReasonNoLongerMatches); err != nil {
		return Result{}, err
	}
	add := make([]tagRow, 0, len(desired))
	for _, t := range desired {
		add = append(add, t)
	}
	if res.Tagged, err = insertTags(ctx, tx, add); err != nil {
		return Result{}, err
	}
	return res, nil
}
