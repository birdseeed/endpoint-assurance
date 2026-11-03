package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/cvematch"
)

var (
	// ErrNotFound: no proposal with that id.
	ErrNotFound = errors.New("not found")
	// ErrConflict: the proposal is not in a state the action allows, or a
	// mapping already covers the product.
	ErrConflict = errors.New("conflict")
	// ErrInvalidRequest: the request itself is invalid, including a CPE that
	// is not one of the proposal's own candidates.
	ErrInvalidRequest = errors.New("invalid request")
)

// Actor is the audit attribution for one write (PAT-1135 split: the
// server-established actor, the caller's untrusted claim, the source
// address).
type Actor struct {
	Actor      string
	Claimed    *string
	SourceAddr *string
}

// Proposal is one proposal as the admin API returns it.
type Proposal struct {
	ID               int64           `json:"id"`
	Platform         string          `json:"platform"`
	NormalizedName   string          `json:"normalized_name"`
	DisplayName      string          `json:"display_name"`
	State            string          `json:"state"`
	StateReason      *string         `json:"state_reason"`
	Candidates       []Candidate     `json:"candidates"`
	ModelID          *string         `json:"model_id"`
	ModelChoice      *string         `json:"model_choice"`
	ModelConfidence  *string         `json:"model_confidence"`
	ModelRationale   *string         `json:"model_rationale"`
	Evidence         json.RawMessage `json:"evidence"`
	ChosenCPEVendor  *string         `json:"chosen_cpe_vendor"`
	ChosenCPEProduct *string         `json:"chosen_cpe_product"`
	MappingID        *int64          `json:"mapping_id"`
	Attempts         int             `json:"attempts"`
	LastError        *string         `json:"last_error"`
	FirstSeenAt      time.Time       `json:"first_seen_at"`
	LastSeenAt       time.Time       `json:"last_seen_at"`
	ProposedAt       *time.Time      `json:"proposed_at"`
	DecidedAt        *time.Time      `json:"decided_at"`
	DecidedBy        *string         `json:"decided_by"`
	UpdatedAt        time.Time       `json:"updated_at"`
	// Live, not stored: devices and tenants on active devices currently
	// reporting the product on this platform. Counts only.
	AffectedDevices int `json:"affected_devices"`
	AffectedTenants int `json:"affected_tenants"`
}

// AuditEntry is one cpe_mapping_proposal_audit row.
type AuditEntry struct {
	Action       string          `json:"action"`
	Actor        string          `json:"actor"`
	ClaimedActor *string         `json:"claimed_actor"`
	SourceAddr   *string         `json:"source_addr"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after"`
	At           time.Time       `json:"at"`
}

// ProposalDetail is GET /admin/cve-mapping-proposals/{id}.
type ProposalDetail struct {
	Proposal
	// CoveredNames are the installed names (this platform, active devices)
	// the display name would cover as a match_name, its own included, so a
	// reviewer sees an approval's blast radius before making it.
	CoveredNames []string     `json:"covered_names"`
	Audit        []AuditEntry `json:"audit"`
}

const proposalColumns = `p.id, p.platform, p.normalized_name, p.display_name, p.state, p.state_reason,
	p.candidates, p.model_id, p.model_choice, p.model_confidence, p.model_rationale, p.evidence,
	p.chosen_cpe_vendor, p.chosen_cpe_product, p.mapping_id, p.attempts, p.last_error,
	p.first_seen_at, p.last_seen_at, p.proposed_at, p.decided_at, p.decided_by, p.updated_at`

func scanProposal(row pgx.Row, extra ...any) (Proposal, error) {
	var p Proposal
	var cands []byte
	dest := []any{&p.ID, &p.Platform, &p.NormalizedName, &p.DisplayName, &p.State, &p.StateReason,
		&cands, &p.ModelID, &p.ModelChoice, &p.ModelConfidence, &p.ModelRationale, &p.Evidence,
		&p.ChosenCPEVendor, &p.ChosenCPEProduct, &p.MappingID, &p.Attempts, &p.LastError,
		&p.FirstSeenAt, &p.LastSeenAt, &p.ProposedAt, &p.DecidedAt, &p.DecidedBy, &p.UpdatedAt}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return p, err
	}
	if err := json.Unmarshal(cands, &p.Candidates); err != nil {
		return p, fmt.Errorf("decode candidates: %w", err)
	}
	if p.Candidates == nil {
		p.Candidates = []Candidate{}
	}
	return p, nil
}

// affectedCountsSQL is a LATERAL computing live affected device and tenant
// counts for proposal p (same scope as loadEvidence): active devices of
// current customer tenants only (currentCustomerTenantSQL), the one tenant
// definition every gate uses, so the digest's hold-back and the proposer's
// eligibility can never disagree.
var affectedCountsSQL = `LEFT JOIN LATERAL (
	SELECT count(DISTINCT d.id)::int AS devices, count(DISTINCT d.tenant_id)::int AS tenants
	FROM device_apps da
	JOIN devices d ON d.id = da.device_id
	JOIN tenants tn ON tn.id = d.tenant_id
	WHERE d.last_seen > NOW() - INTERVAL '` + activeDeviceWindow + `'
	  AND ` + currentCustomerTenantSQL("tn") + `
	  AND (CASE WHEN d.os ILIKE 'windows%' THEN 'windows'
	            WHEN d.os ILIKE 'mac%' OR d.os ILIKE 'darwin%' THEN 'macos' END) = p.platform
	  AND cpe_normalize_name(da.name) = p.normalized_name
) ac ON true`

// ListFilter selects proposals. State "" means every open proposal
// (pending and needs_review); "all" means every state.
type ListFilter struct {
	State  string
	Limit  int
	Offset int
}

// ValidListState reports whether s is a state filter List accepts.
func ValidListState(s string) bool {
	switch s {
	case "", "all", StatePending, StateNeedsReview, StateAutoPublished, StateApproved, StateRejected, StateSuperseded, StateExpired:
		return true
	}
	return false
}

// List returns proposals, oldest first within the filter, with live
// affected counts, and the total the filter matches.
func List(ctx context.Context, q DB, f ListFilter) ([]Proposal, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	var states []string
	switch f.State {
	case "":
		states = []string{StatePending, StateNeedsReview}
	case "all":
		states = []string{StatePending, StateNeedsReview, StateAutoPublished, StateApproved, StateRejected, StateSuperseded, StateExpired}
	default:
		states = []string{f.State}
	}
	rows, err := q.Query(ctx, `
		SELECT `+proposalColumns+`, COALESCE(ac.devices, 0), COALESCE(ac.tenants, 0), count(*) OVER()::int
		FROM cpe_mapping_proposals p
		`+affectedCountsSQL+`
		WHERE p.state = ANY($1::text[])
		ORDER BY p.first_seen_at, p.id
		LIMIT $2 OFFSET $3
	`, states, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list cpe proposals: %w", err)
	}
	defer rows.Close()
	out := []Proposal{}
	total := 0
	for rows.Next() {
		var devices, tenants int
		p, err := scanProposal(rows, &devices, &tenants, &total)
		if err != nil {
			return nil, 0, fmt.Errorf("scan cpe proposal: %w", err)
		}
		p.AffectedDevices, p.AffectedTenants = devices, tenants
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// Counts returns the number of proposals in each state.
func Counts(ctx context.Context, q DB) (map[string]int, error) {
	out := map[string]int{StatePending: 0, StateNeedsReview: 0, StateAutoPublished: 0,
		StateApproved: 0, StateRejected: 0, StateSuperseded: 0, StateExpired: 0}
	rows, err := q.Query(ctx, `SELECT state, count(*)::int FROM cpe_mapping_proposals GROUP BY state`)
	if err != nil {
		return nil, fmt.Errorf("count cpe proposals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// ComponentStatus is one cpe_proposer_status row.
type ComponentStatus struct {
	Status    string          `json:"status"`
	Reason    *string         `json:"reason"`
	Detail    json.RawMessage `json:"detail"`
	UpdatedAt *time.Time      `json:"updated_at"`
}

// Status returns the proposer's and the digest's recorded health. A
// component that has never run reads as status "unknown": absence of a
// heartbeat is never reported as ok.
func Status(ctx context.Context, q DB) (map[string]ComponentStatus, error) {
	out := map[string]ComponentStatus{
		"proposer": {Status: "unknown", Detail: json.RawMessage(`{}`)},
		"digest":   {Status: "unknown", Detail: json.RawMessage(`{}`)},
	}
	rows, err := q.Query(ctx, `SELECT component, status, reason, detail, updated_at FROM cpe_proposer_status`)
	if err != nil {
		return nil, fmt.Errorf("load cpe proposer status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var comp string
		var s ComponentStatus
		var at time.Time
		if err := rows.Scan(&comp, &s.Status, &s.Reason, &s.Detail, &at); err != nil {
			return nil, err
		}
		s.UpdatedAt = &at
		out[comp] = s
	}
	return out, rows.Err()
}

// Get returns one proposal with its blast radius and audit trail.
func Get(ctx context.Context, q DB, id int64) (ProposalDetail, error) {
	var d ProposalDetail
	var devices, tenants int
	p, err := scanProposal(q.QueryRow(ctx, `
		SELECT `+proposalColumns+`, COALESCE(ac.devices, 0), COALESCE(ac.tenants, 0)
		FROM cpe_mapping_proposals p
		`+affectedCountsSQL+`
		WHERE p.id = $1
	`, id), &devices, &tenants)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, fmt.Errorf("get cpe proposal: %w", err)
	}
	p.AffectedDevices, p.AffectedTenants = devices, tenants
	d.Proposal = p
	others, err := coveredNames(ctx, q, p.Platform, p.DisplayName, false)
	if err != nil {
		return d, err
	}
	d.CoveredNames = append([]string{p.DisplayName}, others...)
	rows, err := q.Query(ctx, `
		SELECT action, actor, claimed_actor, source_addr, before, after, at
		FROM cpe_mapping_proposal_audit WHERE proposal_id = $1 ORDER BY at, id
	`, id)
	if err != nil {
		return d, fmt.Errorf("load proposal audit: %w", err)
	}
	defer rows.Close()
	d.Audit = []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.Action, &a.Actor, &a.ClaimedActor, &a.SourceAddr, &a.Before, &a.After, &a.At); err != nil {
			return d, err
		}
		d.Audit = append(d.Audit, a)
	}
	return d, rows.Err()
}

// proposalSnapshot is the audited before/after shape.
type proposalSnapshot struct {
	State            string  `json:"state"`
	StateReason      *string `json:"state_reason"`
	ModelChoice      *string `json:"model_choice"`
	ModelConfidence  *string `json:"model_confidence"`
	ChosenCPEVendor  *string `json:"chosen_cpe_vendor"`
	ChosenCPEProduct *string `json:"chosen_cpe_product"`
	MappingID        *int64  `json:"mapping_id"`
	MappingState     *string `json:"mapping_review_state,omitempty"`
}

func snapshotProposal(ctx context.Context, q DB, id int64) (proposalSnapshot, error) {
	var s proposalSnapshot
	err := q.QueryRow(ctx, `
		SELECT p.state, p.state_reason, p.model_choice, p.model_confidence,
		       p.chosen_cpe_vendor, p.chosen_cpe_product, p.mapping_id, m.review_state
		FROM cpe_mapping_proposals p
		LEFT JOIN app_cpe_mappings m ON m.id = p.mapping_id
		WHERE p.id = $1
		FOR UPDATE OF p
	`, id).Scan(&s.State, &s.StateReason, &s.ModelChoice, &s.ModelConfidence,
		&s.ChosenCPEVendor, &s.ChosenCPEProduct, &s.MappingID, &s.MappingState)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, fmt.Errorf("snapshot proposal: %w", err)
	}
	return s, nil
}

func writeAudit(ctx context.Context, q DB, id int64, action string, actor Actor, before *proposalSnapshot, after proposalSnapshot) error {
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
	if _, err := q.Exec(ctx, `
		INSERT INTO cpe_mapping_proposal_audit (proposal_id, action, actor, claimed_actor, source_addr, before, after)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb)
	`, id, action, actor.Actor, actor.Claimed, actor.SourceAddr, beforeJSON, afterJSON); err != nil {
		return fmt.Errorf("write proposal audit: %w", err)
	}
	return nil
}

// Approve curates a proposal. The CPE is the model's choice unless the
// caller names another; either way it must be one of the proposal's own
// candidates, never free-form. An automatically published proposal becomes
// curated in place (its mapping row's review_state, and its CPE when a
// different candidate was chosen); any other open proposal gets a new
// curated app_cpe_mappings row. The existing mapping-publish path re-matches
// every device carrying the product; changing an auto mapping's CPE retracts
// the old CPE's findings as withdrawn.
func Approve(ctx context.Context, tx pgx.Tx, id int64, vendor, product string, actor Actor) (Proposal, error) {
	before, err := snapshotProposal(ctx, tx, id)
	if err != nil {
		return Proposal{}, err
	}
	switch before.State {
	case StatePending, StateNeedsReview, StateAutoPublished:
	default:
		return Proposal{}, fmt.Errorf("%w: proposal is %s", ErrConflict, before.State)
	}
	p, err := scanProposal(tx.QueryRow(ctx, `SELECT `+proposalColumns+` FROM cpe_mapping_proposals p WHERE p.id = $1`, id))
	if err != nil {
		return Proposal{}, fmt.Errorf("load proposal: %w", err)
	}
	key := ""
	vendor, product = strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product))
	switch {
	case vendor == "" && product == "":
		if p.ModelChoice == nil || *p.ModelChoice == ChoiceNone || *p.ModelChoice == "" {
			return Proposal{}, fmt.Errorf("%w: the model chose no candidate; name cpe_vendor and cpe_product from the candidates", ErrInvalidRequest)
		}
		key = *p.ModelChoice
	case vendor == "" || product == "":
		return Proposal{}, fmt.Errorf("%w: cpe_vendor and cpe_product go together", ErrInvalidRequest)
	default:
		key = vendor + ":" + product
	}
	cand, ok := candidateByKey(p.Candidates, key)
	if !ok {
		return Proposal{}, fmt.Errorf("%w: %s is not one of this proposal's candidates", ErrInvalidRequest, capRunes(key, 120))
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cpepropose.publish', 0))`); err != nil {
		return Proposal{}, fmt.Errorf("lock publish: %w", err)
	}
	var mappingID int64
	if before.State == StateAutoPublished && before.MappingID != nil {
		tag, err := tx.Exec(ctx, `
			UPDATE app_cpe_mappings SET review_state = 'curated', cpe_vendor = $2, cpe_product = $3,
				notes = $4
			WHERE id = $1 AND source_type = 'app_name' AND review_state = 'auto'
		`, *before.MappingID, cand.Vendor, cand.Product, fmt.Sprintf("PAT-2138 proposal %d, approved by staff", id))
		if err != nil {
			return Proposal{}, fmt.Errorf("curate mapping: %w", err)
		}
		// Only the automatic row this proposal published is curated in
		// place: a row someone else deleted or already changed is never
		// overwritten.
		if tag.RowsAffected() != 1 {
			return Proposal{}, fmt.Errorf("%w: the published automatic mapping no longer exists or is no longer automatic", ErrConflict)
		}
		mappingID = *before.MappingID
	} else {
		mappings, err := loadAppMappings(ctx, tx)
		if err != nil {
			return Proposal{}, err
		}
		if len(cvematch.FilterMappingsForPlatform(cvematch.MappingsFor(p.DisplayName, mappings), p.Platform)) > 0 {
			return Proposal{}, fmt.Errorf("%w: a mapping already covers %q on %s", ErrConflict, p.DisplayName, p.Platform)
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
			VALUES ($1, $2, $3, $4, $5, 'app_name', 'curated')
			RETURNING id
		`, p.Platform, p.DisplayName, cand.Vendor, cand.Product,
			fmt.Sprintf("PAT-2138 proposal %d, approved by staff", id)).Scan(&mappingID); err != nil {
			return Proposal{}, fmt.Errorf("publish curated mapping: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE cpe_mapping_proposals SET state = 'approved', state_reason = NULL,
			chosen_cpe_vendor = $2, chosen_cpe_product = $3, mapping_id = $4,
			decided_at = now(), decided_by = $5, updated_at = now()
		WHERE id = $1
	`, id, cand.Vendor, cand.Product, mappingID, decidedBy(actor)); err != nil {
		return Proposal{}, fmt.Errorf("approve proposal: %w", err)
	}
	after, err := snapshotProposal(ctx, tx, id)
	if err != nil {
		return Proposal{}, err
	}
	if err := writeAudit(ctx, tx, id, "approve", actor, &before, after); err != nil {
		return Proposal{}, err
	}
	return scanProposal(tx.QueryRow(ctx, `SELECT `+proposalColumns+` FROM cpe_mapping_proposals p WHERE p.id = $1`, id))
}

// Reject closes a proposal. On an open proposal nothing is mapped. On a
// published one (automatic or approved) it is a revoke: the mapping row is
// deleted, the mapping-publish path re-matches every device carrying the
// product, and because the software on those devices is unchanged the
// lifecycle reducer records each finding that disappears as withdrawn
// (PAT-2107), never verified_fixed, and raises no notification. A rejected
// proposal is never re-proposed: ingest only refreshes its last_seen_at.
func Reject(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (Proposal, error) {
	before, err := snapshotProposal(ctx, tx, id)
	if err != nil {
		return Proposal{}, err
	}
	action, reason := "reject", ReasonRejectedByStaff
	switch before.State {
	case StatePending, StateNeedsReview:
	case StateAutoPublished, StateApproved:
		action, reason = "revoke", ReasonRevoked
		if before.MappingID != nil {
			// Serialise with Approve and the worker's publish path, which take
			// the same lock before writing app_cpe_mappings.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cpepropose.publish', 0))`); err != nil {
				return Proposal{}, fmt.Errorf("revoke lock: %w", err)
			}
			// An automatic proposal only ever owns an automatic mapping: if
			// staff curated that row in the meantime, the revoke leaves it
			// alone rather than deleting a person's decision. An approved
			// proposal's mapping is staff-curated by definition, and revoking
			// it is the staff action being recorded here.
			del := `DELETE FROM app_cpe_mappings WHERE id = $1 AND source_type = 'app_name'`
			if before.State == StateAutoPublished {
				del += ` AND review_state = 'auto'`
			}
			if _, err := tx.Exec(ctx, del, *before.MappingID); err != nil {
				return Proposal{}, fmt.Errorf("revoke mapping: %w", err)
			}
		}
	default:
		return Proposal{}, fmt.Errorf("%w: proposal is %s", ErrConflict, before.State)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE cpe_mapping_proposals SET state = 'rejected', state_reason = $2, mapping_id = NULL,
			decided_at = now(), decided_by = $3, updated_at = now()
		WHERE id = $1
	`, id, reason, decidedBy(actor)); err != nil {
		return Proposal{}, fmt.Errorf("reject proposal: %w", err)
	}
	after, err := snapshotProposal(ctx, tx, id)
	if err != nil {
		return Proposal{}, err
	}
	if err := writeAudit(ctx, tx, id, action, actor, &before, after); err != nil {
		return Proposal{}, err
	}
	return scanProposal(tx.QueryRow(ctx, `SELECT `+proposalColumns+` FROM cpe_mapping_proposals p WHERE p.id = $1`, id))
}

// decidedBy is what decided_by records: the unverified claim when one was
// given (it is also in the audit row, labelled as a claim), else the
// server-established actor.
func decidedBy(a Actor) string {
	if a.Claimed != nil && strings.TrimSpace(*a.Claimed) != "" {
		return capRunes("claimed:"+strings.TrimSpace(*a.Claimed), 200)
	}
	return a.Actor
}
