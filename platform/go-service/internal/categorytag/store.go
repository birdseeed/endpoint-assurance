package categorytag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rule states.
const (
	StateDraft     = "draft"
	StatePublished = "published"
	StateRetired   = "retired"
)

// Retire reasons written to software_category_tags.retired_reason.
const (
	ReasonRuleRetired     = "rule_retired"
	ReasonRuleChanged     = "rule_changed"
	ReasonNoLongerMatches = "no_longer_matches"
)

var (
	// ErrNotFound: no rule or product tag with that id.
	ErrNotFound = errors.New("not found")
	// ErrConflict: the transition is not allowed from the current state.
	ErrConflict = errors.New("conflict")
	// ErrDuplicate: a live rule or product tag already covers this identifier
	// and classification.
	ErrDuplicate = errors.New("duplicate")
	// ErrReconcileIncomplete: the change is committed but its tag reconcile
	// did not finish; retrying the call or the backfill completes it.
	ErrReconcileIncomplete = errors.New("reconcile incomplete")
)

// Actor is the audit attribution for one admin write (PAT-1135 split: the
// server-established actor, the caller's untrusted claim, the source addr).
type Actor struct {
	Actor      string
	Claimed    *string
	SourceAddr *string
}

// Rule is one software_category_rules row.
type Rule struct {
	ID int64 `json:"id"`
	RuleSpec
	Version          int        `json:"version"`
	State            string     `json:"state"`
	CreatedBy        string     `json:"created_by"`
	CreatedByClaimed *string    `json:"created_by_claimed"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	PublishedAt      *time.Time `json:"published_at"`
	RetiredAt        *time.Time `json:"retired_at"`
}

// ProductTag is one software_category_product_tags row.
type ProductTag struct {
	ID               int64      `json:"id"`
	ProductID        string     `json:"product_id"`
	CanonicalKey     string     `json:"canonical_key"`
	CategoryKey      string     `json:"category"`
	SubtypeKey       string     `json:"subtype"`
	Notes            string     `json:"notes"`
	State            string     `json:"state"`
	CreatedBy        string     `json:"created_by"`
	CreatedByClaimed *string    `json:"created_by_claimed"`
	CreatedAt        time.Time  `json:"created_at"`
	RetiredAt        *time.Time `json:"retired_at"`
}

// Result counts tags written and retired by one evaluation or reconcile.
type Result struct {
	Tagged  int `json:"tagged"`
	Retired int `json:"retired"`
}

func (r *Result) add(o Result) { r.Tagged += o.Tagged; r.Retired += o.Retired }

// DB is the subset of pgx shared by a pool and a transaction.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const ruleColumns = `id, identifier_type, identifier_value, qualifier, platform, category_key,
	subtype_key, notes, version, state, created_by, created_by_claimed, created_at, updated_at,
	published_at, retired_at`

func scanRule(row pgx.Row) (Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.IdentifierType, &r.IdentifierValue, &r.Qualifier, &r.Platform,
		&r.CategoryKey, &r.SubtypeKey, &r.Notes, &r.Version, &r.State, &r.CreatedBy,
		&r.CreatedByClaimed, &r.CreatedAt, &r.UpdatedAt, &r.PublishedAt, &r.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	return r, err
}

// GetRule loads one rule.
func GetRule(ctx context.Context, db DB, id int64) (Rule, error) {
	return scanRule(db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM software_category_rules WHERE id = $1`, id))
}

// ListRules lists rules, optionally filtered by state, newest first.
func ListRules(ctx context.Context, db DB, state string) ([]Rule, error) {
	rows, err := db.Query(ctx, `SELECT `+ruleColumns+` FROM software_category_rules
		WHERE ($1 = '' OR state = $1) ORDER BY id DESC`, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func mapWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%w: a live entry already covers this identifier and classification", ErrDuplicate)
		case "23503":
			return fmt.Errorf("%w: unknown category, subtype or product", ErrInvalidRule)
		case "23514":
			return fmt.Errorf("%w: %s", ErrInvalidRule, pgErr.ConstraintName)
		}
	}
	return err
}

func writeAudit(ctx context.Context, tx pgx.Tx, entity string, id int64, action string, actor Actor, before, after any) error {
	var beforeJSON []byte
	if before != nil {
		b, err := json.Marshal(before)
		if err != nil {
			return err
		}
		beforeJSON = b
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO software_category_audit
			(entity_type, entity_id, action, actor, claimed_actor, source_addr, before, after)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)
	`, entity, id, action, actor.Actor, actor.Claimed, actor.SourceAddr, nullJSON(beforeJSON), string(afterJSON))
	if err != nil {
		return fmt.Errorf("write category audit: %w", err)
	}
	return nil
}

func nullJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// CreateRule inserts a draft rule and audits it. A draft never matches.
func CreateRule(ctx context.Context, tx pgx.Tx, spec RuleSpec, actor Actor) (Rule, error) {
	norm, err := NormalizeRule(spec)
	if err != nil {
		return Rule{}, err
	}
	rule, err := scanRule(tx.QueryRow(ctx, `
		INSERT INTO software_category_rules
			(identifier_type, identifier_value, qualifier, platform, category_key, subtype_key,
			 notes, created_by, created_by_claimed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+ruleColumns,
		norm.IdentifierType, norm.IdentifierValue, norm.Qualifier, norm.Platform,
		norm.CategoryKey, norm.SubtypeKey, norm.Notes, actor.Actor, actor.Claimed))
	if err != nil {
		return Rule{}, mapWriteErr(err)
	}
	if err := writeAudit(ctx, tx, "rule", rule.ID, "create", actor, nil, rule); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func lockRule(ctx context.Context, tx pgx.Tx, id int64) (Rule, error) {
	return scanRule(tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM software_category_rules WHERE id = $1 FOR UPDATE`, id))
}

// reconcileAfterEdit is a variable so a test can make the post-edit
// reconcile fail and prove the backfill finishes it.
var reconcileAfterEdit = reconcileRuleChunked

// UpdateRule edits a draft or published rule. Each change bumps version and
// is audited. Editing a draft retires any hidden tags an unfinished publish
// left behind. Editing a published rule commits the edit, then reconciles
// its tags in bounded chunks: new matches are tagged, and observations that
// now positively contradict the rule are retired with reason rule_changed.
// An edit that changes nothing writes nothing but still re-runs that
// reconcile, so a retried request converges.
func UpdateRule(ctx context.Context, pool *pgxpool.Pool, id int64, spec RuleSpec, actor Actor) (Rule, Result, error) {
	norm, err := NormalizeRule(spec)
	if err != nil {
		return Rule{}, Result{}, err
	}
	var after Rule
	var res Result
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		before, err := lockRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if before.State == StateRetired {
			return fmt.Errorf("%w: a retired rule cannot be edited; create a new rule", ErrConflict)
		}
		if norm == before.RuleSpec {
			after = before
			return nil
		}
		// A published rule may not change what kind of observation it tests:
		// its existing tags sit on the old kind, which neither matches nor
		// contradicts the new definition, so they would stay live. The
		// package source picks the kind too (winget apps versus npm or pip
		// packages). Platform changes are safe: narrowing contradicts the
		// other platform's observations and retires their tags.
		if before.State == StatePublished && (norm.IdentifierType != before.IdentifierType ||
			(norm.IdentifierType == TypePackage && norm.Qualifier != before.Qualifier)) {
			return fmt.Errorf("%w: a published rule cannot change its identifier type or package source; retire it and create a new rule", ErrConflict)
		}
		if after, err = scanRule(tx.QueryRow(ctx, `
			UPDATE software_category_rules
			SET identifier_type = $2, identifier_value = $3, qualifier = $4, platform = $5,
			    category_key = $6, subtype_key = $7, notes = $8,
			    version = version + 1, updated_at = now()
			WHERE id = $1
			RETURNING `+ruleColumns,
			id, norm.IdentifierType, norm.IdentifierValue, norm.Qualifier, norm.Platform,
			norm.CategoryKey, norm.SubtypeKey, norm.Notes)); err != nil {
			return mapWriteErr(err)
		}
		if after.State == StateDraft {
			if res.Retired, err = retireAllForRule(ctx, tx, id, ReasonRuleChanged); err != nil {
				return err
			}
		}
		return writeAudit(ctx, tx, "rule", id, "edit", actor, before, after)
	}); err != nil {
		return Rule{}, Result{}, err
	}
	if after.State == StatePublished {
		more, err := reconcileAfterEdit(ctx, pool, id, StatePublished, after.Version)
		res.add(more)
		if err != nil {
			return after, res, fmt.Errorf("%w: the edit is saved but its tags are not fully reconciled (%v); run POST /admin/software-categories/backfill to finish", ErrReconcileIncomplete, err)
		}
	}
	return after, res, nil
}

// PublishRule publishes a draft. Order: backfill first, then flip. The
// backfill runs in bounded chunks while the rule is still a draft; its tags
// are invisible to the read API and ignored by ingest because the rule is not
// published. Only when every chunk has committed does one short transaction
// re-lock the rule, check it is still the same draft version, flip it to
// published and audit it. So the rule reads published only once its tags
// exist, a failed or timed-out publish leaves a draft that a retry completes
// (inserts are idempotent), and an edit or retire mid-publish makes the flip
// refuse with a conflict instead of publishing a stale backfill. An
// observation first reported during the backfill is tagged by its device's
// next ingest. Publishing an already published rule re-runs its reconcile
// and is not audited.
func PublishRule(ctx context.Context, pool *pgxpool.Pool, id int64, actor Actor) (Rule, Result, error) {
	current, err := GetRule(ctx, pool, id)
	if err != nil {
		return Rule{}, Result{}, err
	}
	if current.State == StateRetired {
		return Rule{}, Result{}, fmt.Errorf("%w: a retired rule cannot be published; create a new rule", ErrConflict)
	}
	res, err := reconcileRuleChunked(ctx, pool, id, current.State, current.Version)
	if err != nil {
		return Rule{}, res, err
	}
	if current.State == StatePublished {
		return current, res, nil
	}
	var after Rule
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		before, err := lockRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if before.State != StateDraft || before.Version != current.Version {
			return fmt.Errorf("%w: the rule changed during publish; retry", ErrConflict)
		}
		if after, err = scanRule(tx.QueryRow(ctx, `
			UPDATE software_category_rules
			SET state = 'published', published_at = now(), updated_at = now()
			WHERE id = $1 RETURNING `+ruleColumns, id)); err != nil {
			return mapWriteErr(err)
		}
		return writeAudit(ctx, tx, "rule", id, "publish", actor, before, after)
	})
	if err != nil {
		return Rule{}, res, err
	}
	return after, res, nil
}

// RetireRule retires a rule in one transaction: it stops matching at once and
// every live tag it produced is retired with reason rule_retired, never
// deleted. FOR UPDATE here pairs with FOR SHARE in ingest and backfill.
func RetireRule(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (Rule, Result, error) {
	before, err := lockRule(ctx, tx, id)
	if err != nil {
		return Rule{}, Result{}, err
	}
	if before.State == StateRetired {
		return Rule{}, Result{}, fmt.Errorf("%w: rule is already retired", ErrConflict)
	}
	after, err := scanRule(tx.QueryRow(ctx, `
		UPDATE software_category_rules
		SET state = 'retired', retired_at = now(), updated_at = now()
		WHERE id = $1 RETURNING `+ruleColumns, id))
	if err != nil {
		return Rule{}, Result{}, mapWriteErr(err)
	}
	if err := writeAudit(ctx, tx, "rule", id, "retire", actor, before, after); err != nil {
		return Rule{}, Result{}, err
	}
	retired, err := retireAllForRule(ctx, tx, id, ReasonRuleRetired)
	if err != nil {
		return Rule{}, Result{}, err
	}
	return after, Result{Retired: retired}, nil
}

const productTagColumns = `pt.id, pt.product_id::text, sp.canonical_key, pt.category_key, pt.subtype_key,
	pt.notes, pt.state, pt.created_by, pt.created_by_claimed, pt.created_at, pt.retired_at`

func scanProductTag(row pgx.Row) (ProductTag, error) {
	var p ProductTag
	err := row.Scan(&p.ID, &p.ProductID, &p.CanonicalKey, &p.CategoryKey, &p.SubtypeKey, &p.Notes,
		&p.State, &p.CreatedBy, &p.CreatedByClaimed, &p.CreatedAt, &p.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProductTag{}, ErrNotFound
	}
	return p, err
}

func getProductTag(ctx context.Context, db DB, id int64, lock bool) (ProductTag, error) {
	q := `SELECT ` + productTagColumns + ` FROM software_category_product_tags pt
		JOIN software_products sp ON sp.id = pt.product_id WHERE pt.id = $1`
	if lock {
		q += ` FOR UPDATE OF pt`
	}
	return scanProductTag(db.QueryRow(ctx, q, id))
}

// ListProductTags lists product-identity tags, newest first.
func ListProductTags(ctx context.Context, db DB, state string) ([]ProductTag, error) {
	rows, err := db.Query(ctx, `SELECT `+productTagColumns+` FROM software_category_product_tags pt
		JOIN software_products sp ON sp.id = pt.product_id
		WHERE ($1 = '' OR pt.state = $1) ORDER BY pt.id DESC`, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProductTag{}
	for rows.Next() {
		p, err := scanProductTag(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProductTagSpec is what an admin submits to tag a product identity.
type ProductTagSpec struct {
	CanonicalKey string `json:"canonical_key"`
	CategoryKey  string `json:"category"`
	SubtypeKey   string `json:"subtype"`
	Notes        string `json:"notes"`
}

// CreateProductTag tags a normalised product identity, live at once, and
// tags every existing installation resolved to that product.
func CreateProductTag(ctx context.Context, tx pgx.Tx, spec ProductTagSpec, actor Actor) (ProductTag, Result, error) {
	if !categoryKeyPattern.MatchString(spec.CategoryKey) || !categoryKeyPattern.MatchString(spec.SubtypeKey) {
		return ProductTag{}, Result{}, invalid("category and subtype must be keys")
	}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO software_category_product_tags
			(product_id, category_key, subtype_key, notes, created_by, created_by_claimed)
		SELECT sp.id, $2, $3, $4, $5, $6 FROM software_products sp WHERE sp.canonical_key = $1
		RETURNING id
	`, strings.ToLower(strings.Trim(spec.CanonicalKey, " ")), spec.CategoryKey, spec.SubtypeKey, spec.Notes, actor.Actor, actor.Claimed).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProductTag{}, Result{}, invalid("no software product has canonical_key %q", spec.CanonicalKey)
	}
	if err != nil {
		return ProductTag{}, Result{}, mapWriteErr(err)
	}
	tag, err := getProductTag(ctx, tx, id, false)
	if err != nil {
		return ProductTag{}, Result{}, err
	}
	if err := writeAudit(ctx, tx, "product_tag", id, "create", actor, nil, tag); err != nil {
		return ProductTag{}, Result{}, err
	}
	res, err := ReconcileProductTag(ctx, tx, id)
	return tag, res, err
}

// RetireProductTag retires a product tag and its live tags.
func RetireProductTag(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (ProductTag, Result, error) {
	before, err := getProductTag(ctx, tx, id, true)
	if err != nil {
		return ProductTag{}, Result{}, err
	}
	if before.State == StateRetired {
		return ProductTag{}, Result{}, fmt.Errorf("%w: product tag is already retired", ErrConflict)
	}
	if _, err := tx.Exec(ctx, `UPDATE software_category_product_tags
		SET state = 'retired', retired_at = now() WHERE id = $1`, id); err != nil {
		return ProductTag{}, Result{}, err
	}
	after, err := getProductTag(ctx, tx, id, false)
	if err != nil {
		return ProductTag{}, Result{}, err
	}
	if err := writeAudit(ctx, tx, "product_tag", id, "retire", actor, before, after); err != nil {
		return ProductTag{}, Result{}, err
	}
	res, err := ReconcileProductTag(ctx, tx, id)
	return after, res, err
}

// AuditEntry is one software_category_audit row.
type AuditEntry struct {
	ID           int64           `json:"id"`
	EntityType   string          `json:"entity_type"`
	EntityID     int64           `json:"entity_id"`
	Action       string          `json:"action"`
	Actor        string          `json:"actor"`
	ClaimedActor *string         `json:"claimed_actor"`
	SourceAddr   *string         `json:"source_addr"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after"`
	At           time.Time       `json:"at"`
}

// ListAudit returns the audit trail for one entity, oldest first.
func ListAudit(ctx context.Context, db DB, entity string, id int64) ([]AuditEntry, error) {
	rows, err := db.Query(ctx, `
		SELECT id, entity_type, entity_id, action, actor, claimed_actor, source_addr,
		       COALESCE(before, 'null'::jsonb), after, at
		FROM software_category_audit
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY id`, entity, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.EntityType, &e.EntityID, &e.Action, &e.Actor, &e.ClaimedActor,
			&e.SourceAddr, &e.Before, &e.After, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Subtype is one row of the category vocabulary.
type Subtype struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
}

// Category is one category with its subtypes.
type Category struct {
	Key         string    `json:"key"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	Subtypes    []Subtype `json:"subtypes"`
}

// ListCategories returns the category vocabulary.
func ListCategories(ctx context.Context, db DB) ([]Category, error) {
	rows, err := db.Query(ctx, `
		SELECT c.key, c.display_name, c.description, s.key, s.display_name
		FROM software_categories c
		LEFT JOIN software_category_subtypes s ON s.category_key = c.key
		ORDER BY c.key, s.key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Category{}
	for rows.Next() {
		var c Category
		var sk, sn *string
		if err := rows.Scan(&c.Key, &c.DisplayName, &c.Description, &sk, &sn); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Key != c.Key {
			c.Subtypes = []Subtype{}
			out = append(out, c)
		}
		if sk != nil {
			last := &out[len(out)-1]
			last.Subtypes = append(last.Subtypes, Subtype{Key: *sk, DisplayName: *sn})
		}
	}
	return out, rows.Err()
}

// ReconcileAll re-runs every published rule (chunked) and product tag (one
// transaction each). It is the recovery path for a reconcile that could not
// finish and is safe to run at any time. Totals count committed work only.
func ReconcileAll(ctx context.Context, pool *pgxpool.Pool) (Result, error) {
	var total Result
	rows, err := pool.Query(ctx, `SELECT id, version FROM software_category_rules WHERE state = 'published' ORDER BY id`)
	if err != nil {
		return total, err
	}
	type idVersion struct {
		id      int64
		version int
	}
	rules, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (idVersion, error) {
		var v idVersion
		return v, r.Scan(&v.id, &v.version)
	})
	if err != nil {
		return total, err
	}
	rows, err = pool.Query(ctx, `SELECT id FROM software_category_product_tags WHERE state = 'published' ORDER BY id`)
	if err != nil {
		return total, err
	}
	tagIDs, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return total, err
	}
	for _, r := range rules {
		res, err := reconcileRuleChunked(ctx, pool, r.id, StatePublished, r.version)
		total.add(res)
		if err != nil {
			return total, fmt.Errorf("reconcile rule %d: %w", r.id, err)
		}
	}
	for _, id := range tagIDs {
		var res Result
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			res, err = ReconcileProductTag(ctx, tx, id)
			return err
		}); err != nil {
			return total, fmt.Errorf("reconcile product tag %d: %w", id, err)
		}
		total.add(res)
	}
	return total, nil
}

// RetryDeadlock runs fn and, if it fails with a PostgreSQL deadlock
// (SQLSTATE 40P01), runs it once more. Every admin write is safe to repeat:
// creates fail as duplicates, edits converge, publish is idempotent.
func RetryDeadlock(fn func() error) error {
	err := fn()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
		return fn()
	}
	return err
}
