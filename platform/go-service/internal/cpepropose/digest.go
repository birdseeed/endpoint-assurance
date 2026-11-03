package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// DigestMarker is embedded in the digest issue's description so the issue
// can be found again when its id is not stored locally.
const DigestMarker = "<!-- patched:cpe-mapping-review-digest -->"

// EscalateAfter is how long the oldest proposal may wait before the digest
// escalates.
const EscalateAfter = 48 * time.Hour

// maxDigestItems bounds the items listed in the issue body.
const maxDigestItems = 25

// ErrLinearNotConfigured: LINEAR_API_TOKEN is unset. The digest records its
// status as degraded rather than silently doing nothing (PAT-912).
var ErrLinearNotConfigured = errors.New("LINEAR_API_TOKEN not set: the CVE mapping review digest cannot reach Linear")

// DigestItem is one proposal awaiting review.
type DigestItem struct {
	ID              int64
	DisplayName     string
	Platform        string
	Reason          string
	ModelChoice     string
	FirstSeenAt     time.Time
	AffectedDevices int
	AffectedTenants int
}

// Digest is the computed issue content.
type Digest struct {
	// Count is the proposals listed; HeldBack is the single-tenant
	// proposals, which are never named in the issue and never escalate it.
	Count     int
	HeldBack  int
	Oldest    time.Duration
	Escalated bool
	Title     string
	Body      string
	Priority  int // Linear priority: 2 high when escalated, 3 normal
}

// BuildDigest computes the digest issue for the items awaiting review. Pure:
// the same items and clock always produce the same text. Product names come
// from customer endpoints, so every one is reduced to plain text inside a
// code span before it reaches Linear's markdown.
//
// A proposal fewer than MinOutboundTenants tenants report (by its live
// affected-tenant count, or its single_tenant reason) may name one
// customer's own software, such as a browser web-app wrapper for its
// intranet, so it is never listed, never counted in the title and never
// drives the overdue escalation: the body carries only how many are held
// back. Linear is outside the platform.
func BuildDigest(all []DigestItem, now time.Time, proposerStatus, proposerReason string) Digest {
	var items []DigestItem
	held := 0
	for _, it := range all {
		if it.Reason == ReasonSingleTenant || it.AffectedTenants < MinOutboundTenants {
			held++
			continue
		}
		items = append(items, it)
	}
	d := Digest{Count: len(items), HeldBack: held, Priority: 3}
	for _, it := range items {
		if age := now.Sub(it.FirstSeenAt); age > d.Oldest {
			d.Oldest = age
		}
	}
	noun := "mappings"
	if d.Count == 1 {
		noun = "mapping"
	}
	d.Title = fmt.Sprintf("%d CVE %s awaiting review", d.Count, noun)
	if d.Count > 0 && d.Oldest > EscalateAfter {
		d.Escalated = true
		d.Priority = 2
		d.Title = fmt.Sprintf("%d CVE %s awaiting review, oldest %s (overdue)", d.Count, noun, humanAge(d.Oldest))
	}

	var b strings.Builder
	b.WriteString(DigestMarker + "\n\n")
	heldLine := func() {
		if d.HeldBack > 0 {
			fmt.Fprintf(&b, "%d %s held back (reported by fewer than two customers): not listed here and never sent outside Patched. Review them in the staff console.\n",
				d.HeldBack, pluralProduct(d.HeldBack))
		}
	}
	if d.Count == 0 {
		if d.HeldBack > 0 {
			heldLine()
		} else {
			b.WriteString("The CVE mapping review queue is empty. Every installed product without a CPE mapping has been decided.\n")
		}
		d.Body = b.String()
		return d
	}
	fmt.Fprintf(&b, "%d installed %s %s no CPE mapping that could be published automatically, so %s not CVE-checked. ",
		d.Count, pluralProduct(d.Count), hasHave(d.Count), itThey(d.Count))
	b.WriteString("Customers see them as \"Not yet assessed: mapping under review\" until someone approves or rejects each one.\n\n")
	if d.Escalated {
		fmt.Fprintf(&b, "**Escalated:** the oldest has waited %s, more than 48 hours.\n\n", humanAge(d.Oldest))
	}
	if proposerStatus == "degraded" {
		fmt.Fprintf(&b, "**Proposer degraded (%s).** ", sanitizeInline(proposerReason, 64))
		if proposerReason == ReasonModelUnavailable {
			b.WriteString("No model is configured or the model API is failing, so nothing is auto-published and every proposal needs a person.")
		}
		b.WriteString("\n\n")
	}
	b.WriteString("| Product | Platform | Why it needs review | Model pick | Devices | Tenants | Waiting |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for i, it := range items {
		if i == maxDigestItems {
			fmt.Fprintf(&b, "\n%d more not listed.\n", len(items)-maxDigestItems)
			break
		}
		pick := it.ModelChoice
		if pick == "" {
			pick = "-"
		}
		fmt.Fprintf(&b, "| `%s` (#%d) | %s | %s | `%s` | %d | %d | %s |\n",
			sanitizeInline(it.DisplayName, 80), it.ID, sanitizeInline(it.Platform, 16),
			sanitizeInline(reasonText(it.Reason), 80), sanitizeInline(pick, 80),
			it.AffectedDevices, it.AffectedTenants, humanAge(now.Sub(it.FirstSeenAt)))
	}
	if d.HeldBack > 0 {
		b.WriteString("\n")
		heldLine()
	}
	b.WriteString("\nReview them in the staff console, or through the admin API: `GET /admin/cve-mapping-proposals`, then `POST /admin/cve-mapping-proposals/{id}/approve` or `/reject`.\n")
	b.WriteString("\nThis issue is maintained by the nightly CVE pipeline: it is updated in place each day and closes itself when the queue is empty.\n")
	d.Body = b.String()
	return d
}

func pluralProduct(n int) string {
	if n == 1 {
		return "product"
	}
	return "products"
}

func hasHave(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

func itThey(n int) string {
	if n == 1 {
		return "it is"
	}
	return "they are"
}

func reasonText(r string) string {
	switch r {
	case ReasonModelUnavailable:
		return "no model available"
	case ReasonModelInvalidResponse:
		return "model answer rejected"
	case ReasonModelChoseNone:
		return "model found no match"
	case ReasonModelNotConfident:
		return "model not confident"
	case ReasonNoCandidates:
		return "no NVD candidates"
	case ReasonNVDUnavailable:
		return "NVD search failed"
	case ReasonCandidateDeprecated:
		return "chosen CPE deprecated"
	case ReasonAutoPublishDisabled:
		return "auto-publish disabled"
	case ReasonNoSignerEvidence:
		return "no signer evidence"
	case ReasonSignerUntrusted:
		return "signature not trusted"
	case ReasonSignerInconsistent:
		return "installations disagree on signer"
	case ReasonSignerNotAliased:
		return "signer not in alias table"
	case ReasonSignerVendorMismatch:
		return "signer is a different vendor"
	case ReasonMatchNameTooBroad:
		return "name would cover other products"
	case ReasonProductNameMismatch:
		return "CPE does not name the product"
	case ReasonCandidateHasNoCVEs:
		return "chosen CPE has no CVEs"
	case ReasonAmbiguousCandidates:
		return "another CPE of the vendor fits better"
	case ReasonCorroborationLost:
		return "automatic mapping lost corroboration"
	case ReasonMappingDeleted:
		return "automatic mapping deleted elsewhere"
	case "":
		return "pending"
	}
	return r
}

// sanitizeInline reduces untrusted text to one line of plain text safe inside
// a markdown code span or table cell: control characters, backticks, pipes,
// angle brackets and newlines removed, length capped.
func sanitizeInline(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r):
			return ' '
		case r == '`' || r == '|' || r == '<' || r == '>':
			return ' '
		}
		return r
	}, s)
	return capRunes(strings.Join(strings.Fields(s), " "), n)
}

func humanAge(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// LoadDigestItems reads every proposal awaiting review, oldest first, with
// live affected counts.
func LoadDigestItems(ctx context.Context, q DB) ([]DigestItem, error) {
	rows, err := q.Query(ctx, `
		SELECT p.id, p.display_name, p.platform, COALESCE(p.state_reason, ''), COALESCE(p.model_choice, ''),
		       p.first_seen_at, COALESCE(ac.devices, 0), COALESCE(ac.tenants, 0)
		FROM cpe_mapping_proposals p
		`+affectedCountsSQL+`
		WHERE p.state = 'needs_review'
		ORDER BY p.first_seen_at, p.id
	`)
	if err != nil {
		return nil, fmt.Errorf("load digest items: %w", err)
	}
	defer rows.Close()
	var out []DigestItem
	for rows.Next() {
		var it DigestItem
		if err := rows.Scan(&it.ID, &it.DisplayName, &it.Platform, &it.Reason, &it.ModelChoice,
			&it.FirstSeenAt, &it.AffectedDevices, &it.AffectedTenants); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// IssueTracker is the Linear surface the digest needs.
type IssueTracker interface {
	// FindOpenIssue returns the id of an open issue whose description
	// contains marker, or "".
	FindOpenIssue(ctx context.Context, marker string) (string, error)
	// IssueOpen reports whether the issue exists and is neither completed
	// nor canceled.
	IssueOpen(ctx context.Context, id string) (bool, error)
	CreateIssue(ctx context.Context, title, body string, priority int) (id, identifier string, err error)
	UpdateIssue(ctx context.Context, id, title, body string, priority int) error
	CloseIssue(ctx context.Context, id, body string) error
}

// DigestResult is what one RunDigest did.
type DigestResult struct {
	Count      int    `json:"count"`
	Escalated  bool   `json:"escalated"`
	Action     string `json:"action"` // created, updated, closed, none
	IssueID    string `json:"issue_id,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

type digestState struct {
	IssueID    string `json:"issue_id,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// RunDigest maintains ONE Linear issue for the review queue: created when
// proposals first await review, updated in place on every run (title,
// description, priority on escalation), closed when the queue is empty. A
// nil tracker (no token) records the digest as degraded and returns
// ErrLinearNotConfigured, so the gap is visible on the admin API and in the
// run's exit log line rather than silent.
//
// One run at a time: the run holds a transaction-scoped advisory lock, so a
// manual --mode=cpe-review-digest overlapping the nightly run cannot create
// a second issue; the loser returns Action "locked" and touches nothing.
func RunDigest(ctx context.Context, q DB, tracker IssueTracker, now time.Time, logger *slog.Logger) (DigestResult, error) {
	if logger == nil {
		logger = slog.Default()
	}
	b, ok := q.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return DigestResult{}, errors.New("cve mapping digest: database handle cannot begin a transaction")
	}
	tx, err := b.Begin(ctx)
	if err != nil {
		return DigestResult{}, fmt.Errorf("begin digest: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('cpepropose.digest', 0))`).Scan(&locked); err != nil {
		return DigestResult{}, fmt.Errorf("lock digest: %w", err)
	}
	if !locked {
		logger.Info("cve mapping review digest skipped: another run holds the lock")
		return DigestResult{Action: "locked"}, nil
	}
	res, runErr := runDigestLocked(ctx, tx, tracker, now, logger)
	if err := tx.Commit(ctx); err != nil && runErr == nil {
		runErr = fmt.Errorf("commit digest: %w", err)
	}
	return res, runErr
}

func runDigestLocked(ctx context.Context, q DB, tracker IssueTracker, now time.Time, logger *slog.Logger) (DigestResult, error) {
	var res DigestResult
	items, err := LoadDigestItems(ctx, q)
	if err != nil {
		return res, err
	}
	statuses, err := Status(ctx, q)
	if err != nil {
		return res, err
	}
	proposer := statuses["proposer"]
	reason := ""
	if proposer.Reason != nil {
		reason = *proposer.Reason
	}
	d := BuildDigest(items, now, proposer.Status, reason)
	res.Count, res.Escalated = d.Count, d.Escalated

	var state digestState
	stateErr := ""
	if raw := statuses["digest"].Detail; len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			// The stored issue id is unreadable: carry on without it (the
			// issue is found again by its marker and creator), but say so.
			stateErr = capRunes(err.Error(), 200)
			logger.Error("cve mapping digest state unreadable; locating the issue by its marker", "err", err)
			state = digestState{}
		}
	}
	record := func(status, reason string) {
		recordDigestStatus(ctx, q, status, reason, state, res, stateErr, now, logger)
	}
	if tracker == nil {
		record("degraded", "linear_token_missing")
		return res, ErrLinearNotConfigured
	}
	fail := func(err error) (DigestResult, error) {
		record("degraded", "linear_api_error")
		return res, err
	}

	issueID := state.IssueID
	if issueID != "" {
		open, err := tracker.IssueOpen(ctx, issueID)
		if err != nil {
			return fail(err)
		}
		if !open {
			issueID = ""
		}
	}
	if issueID == "" {
		found, err := tracker.FindOpenIssue(ctx, DigestMarker)
		if err != nil {
			return fail(err)
		}
		issueID = found
		if found != state.IssueID {
			state.Identifier = ""
		}
	}

	switch {
	case d.Count == 0 && d.HeldBack > 0 && issueID != "":
		// Only held-back proposals: keep the issue, with the aggregate line.
		if err := tracker.UpdateIssue(ctx, issueID, d.Title, d.Body, d.Priority); err != nil {
			return fail(err)
		}
		res.Action = "updated"
	case d.Count == 0 && d.HeldBack > 0:
		res.Action = "none"
	case d.Count == 0 && issueID != "":
		if err := tracker.CloseIssue(ctx, issueID, d.Body); err != nil {
			return fail(err)
		}
		res.Action = "closed"
	case d.Count == 0:
		res.Action = "none"
	case issueID != "":
		if err := tracker.UpdateIssue(ctx, issueID, d.Title, d.Body, d.Priority); err != nil {
			return fail(err)
		}
		res.Action = "updated"
	default:
		id, ident, err := tracker.CreateIssue(ctx, d.Title, d.Body, d.Priority)
		if err != nil {
			return fail(err)
		}
		issueID, state.Identifier = id, ident
		res.Action = "created"
	}
	state.IssueID = issueID
	if res.Action == "closed" {
		state = digestState{}
	}
	res.IssueID, res.Identifier = issueID, state.Identifier
	record("ok", "")
	logger.Info("cve mapping review digest", "count", res.Count, "escalated", res.Escalated,
		"action", res.Action, "issue", res.Identifier)
	return res, nil
}

func recordDigestStatus(ctx context.Context, q DB, status, reason string, state digestState, res DigestResult,
	stateErr string, now time.Time, logger *slog.Logger) {
	var r *string
	if reason != "" {
		r = &reason
	}
	fields := map[string]any{
		"issue_id":    state.IssueID,
		"identifier":  state.Identifier,
		"last_run_at": now.UTC(),
		"last_run":    res,
	}
	if stateErr != "" {
		fields["state_error"] = stateErr
	}
	detail, err := json.Marshal(fields)
	if err != nil {
		logger.Error("cve mapping digest status unencodable; recording a minimal status", "err", err)
		detail = []byte(`{"state_error":"status detail could not be encoded"}`)
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO cpe_proposer_status (component, status, reason, detail, updated_at)
		VALUES ('digest', $1, $2, $3::jsonb, now())
		ON CONFLICT (component) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
			detail = EXCLUDED.detail, updated_at = EXCLUDED.updated_at
	`, status, r, detail); err != nil {
		logger.Warn("recording cve mapping digest status failed", "err", err)
	}
}
