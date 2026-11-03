package feedback

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StatusReceived         = "received"
	StatusPlanned          = "planned"
	StatusRoadmap          = "on_the_roadmap"
	StatusInProgress       = "in_progress"
	StatusShipped          = "shipped"
	StatusClosedNotPlanned = "closed_not_planned"
	StatusClosedMerged     = "closed_merged"
)

// LinearUpdate is the complete status evidence consumed from either a
// verified webhook or the reconciliation reader.
type LinearUpdate struct {
	IssueID   string
	State     string
	Labels    []string
	UpdatedAt time.Time
	Delivery  string
	Source    string
}

type ApplyResult struct {
	Outcome string
	Changed bool
	Replay  bool
}

func statusForLinear(state string, labels []string, feedbackType string) (string, bool) {
	hasTriage := false
	for _, label := range labels {
		switch strings.ToLower(strings.TrimSpace(label)) {
		case "needs-triage", "claude-triaged":
			hasTriage = true
		}
	}
	var status string
	switch strings.TrimSpace(state) {
	case "Backlog":
		if hasTriage {
			status = StatusReceived
		} else {
			status = StatusPlanned
		}
	case "Todo", "Blocked":
		status = StatusPlanned
	case "RoadMap":
		status = StatusRoadmap
	case "In Progress", "In Review":
		status = StatusInProgress
	case "Done":
		status = StatusShipped
	case "Canceled":
		status = StatusClosedNotPlanned
	case "Duplicate":
		status = StatusClosedMerged
	default:
		return "", false
	}
	if feedbackType == TypeQuestion && status == StatusPlanned {
		return StatusReceived, true
	}
	return status, true
}

func terminalCustomerStatus(status string) bool {
	return status == StatusShipped || status == StatusClosedNotPlanned || status == StatusClosedMerged
}

// ApplyLinearUpdate serialises updates for one Linear issue and commits the
// customer status, audit row and any email obligation atomically. Webhook
// delivery ids are inserted in the same transaction, making replay a no-op.
func ApplyLinearUpdate(ctx context.Context, pool *pgxpool.Pool, update LinearUpdate) (ApplyResult, error) {
	if pool == nil {
		return ApplyResult{}, errors.New("feedback status: nil pool")
	}
	if strings.TrimSpace(update.IssueID) == "" || update.UpdatedAt.IsZero() {
		return ApplyResult{}, errors.New("feedback status: issue id and updated_at are required")
	}
	if update.Source != "webhook" && update.Source != "reconcile" {
		return ApplyResult{}, errors.New("feedback status: source must be webhook or reconcile")
	}
	if update.Source == "webhook" && strings.TrimSpace(update.Delivery) == "" {
		return ApplyResult{}, errors.New("feedback status: webhook delivery id is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer tx.Rollback(ctx)

	if update.Delivery != "" {
		tag, err := tx.Exec(ctx, `INSERT INTO feedback_linear_webhook_deliveries(delivery_id,linear_issue_id,event_updated_at,outcome) VALUES($1,$2,$3,'processing') ON CONFLICT (delivery_id) DO NOTHING`, update.Delivery, update.IssueID, update.UpdatedAt.UTC())
		if err != nil {
			return ApplyResult{}, err
		}
		if tag.RowsAffected() == 0 {
			return ApplyResult{Outcome: "replay", Replay: true}, nil
		}
	}

	var id int64
	var tenantID, typ, fromStatus, recipient, reference, title string
	var lastUpdated *time.Time
	err = tx.QueryRow(ctx, `SELECT id,tenant_id::text,type,status,reporter_email,reference,title,linear_updated_at FROM feedback WHERE linear_issue_id=$1 FOR UPDATE`, update.IssueID).Scan(&id, &tenantID, &typ, &fromStatus, &recipient, &reference, &title, &lastUpdated)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := completeWebhookDelivery(ctx, tx, update.Delivery, "unknown_issue"); err != nil {
			return ApplyResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{Outcome: "unknown_issue"}, nil
	}
	if err != nil {
		return ApplyResult{}, err
	}
	if lastUpdated != nil && !update.UpdatedAt.After(*lastUpdated) {
		// This schedules only the next reconciliation read. A later, newer
		// webhook does not consult next_reconcile_at and is applied immediately.
		if _, err := tx.Exec(ctx, `UPDATE feedback SET linear_checked_at=clock_timestamp(),reconcile_attempts=0,reconcile_last_error=NULL,next_reconcile_at=clock_timestamp()+interval '24 hours',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			return ApplyResult{}, err
		}
		if err := completeWebhookDelivery(ctx, tx, update.Delivery, "stale"); err != nil {
			return ApplyResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{Outcome: "stale"}, nil
	}

	toStatus, known := statusForLinear(update.State, update.Labels, typ)
	if !known {
		_, err = tx.Exec(ctx, `UPDATE feedback SET linear_state=$2,linear_updated_at=$3,linear_checked_at=clock_timestamp(),reconcile_attempts=0,reconcile_last_error=NULL,next_reconcile_at=clock_timestamp()+interval '24 hours',updated_at=clock_timestamp() WHERE id=$1`, id, update.State, update.UpdatedAt.UTC())
		if err != nil {
			return ApplyResult{}, err
		}
		if err := completeWebhookDelivery(ctx, tx, update.Delivery, "unknown_state"); err != nil {
			return ApplyResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplyResult{}, err
		}
		slog.Warn("feedback Linear update has unknown state", "issue_id", update.IssueID, "state", safeLinearState(update.State))
		return ApplyResult{Outcome: "unknown_state"}, nil
	}

	if toStatus == fromStatus {
		_, err = tx.Exec(ctx, `UPDATE feedback SET linear_state=$2,linear_updated_at=$3,linear_checked_at=clock_timestamp(),reconcile_attempts=0,reconcile_last_error=NULL,next_reconcile_at=clock_timestamp()+interval '24 hours',updated_at=clock_timestamp() WHERE id=$1`, id, update.State, update.UpdatedAt.UTC())
		if err != nil {
			return ApplyResult{}, err
		}
		if err := completeWebhookDelivery(ctx, tx, update.Delivery, "unchanged"); err != nil {
			return ApplyResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{Outcome: "unchanged"}, nil
	}

	_, err = tx.Exec(ctx, `UPDATE feedback SET status=$2,linear_state=$3,linear_updated_at=$4,linear_checked_at=clock_timestamp(),status_changed_at=$4,reconcile_attempts=0,reconcile_last_error=NULL,next_reconcile_at=clock_timestamp()+interval '24 hours',updated_at=clock_timestamp() WHERE id=$1`, id, toStatus, update.State, update.UpdatedAt.UTC())
	if err != nil {
		return ApplyResult{}, err
	}
	var auditID int64
	err = tx.QueryRow(ctx, `INSERT INTO feedback_status_audit(feedback_id,tenant_id,from_status,to_status,changed_at,linear_state,source) VALUES($1,$2::uuid,$3,$4,$5,$6,$7) RETURNING id`, id, tenantID, fromStatus, toStatus, update.UpdatedAt.UTC(), update.State, update.Source).Scan(&auditID)
	if err != nil {
		return ApplyResult{}, err
	}
	if terminalCustomerStatus(toStatus) {
		_, err = tx.Exec(ctx, `INSERT INTO feedback_status_email_outbox(audit_id,feedback_id,tenant_id,recipient,feedback_reference,feedback_title,customer_status,next_attempt_at) VALUES($1,$2,$3::uuid,$4,$5,$6,$7,clock_timestamp())`, auditID, id, tenantID, recipient, reference, title, toStatus)
		if err != nil {
			return ApplyResult{}, err
		}
	}
	if err := completeWebhookDelivery(ctx, tx, update.Delivery, "transitioned"); err != nil {
		return ApplyResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Outcome: "transitioned", Changed: true}, nil
}

func completeWebhookDelivery(ctx context.Context, tx pgx.Tx, delivery, outcome string) error {
	if delivery == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE feedback_linear_webhook_deliveries SET outcome=$2,completed_at=clock_timestamp() WHERE delivery_id=$1`, delivery, outcome)
	return err
}

func safeLinearState(state string) string {
	state = strings.Join(strings.Fields(state), " ")
	if len(state) > 80 {
		state = state[:80]
	}
	return state
}

func reconcileBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Hour
	for i := 1; i < attempt && d < 24*time.Hour; i++ {
		d *= 2
	}
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

func recordReconcileFailure(ctx context.Context, pool *pgxpool.Pool, id int64, attempt int, err error) {
	msg := strings.Join(strings.Fields(fmt.Sprintf("%v", err)), " ")
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, updateErr := pool.Exec(ctx, `UPDATE feedback SET reconcile_attempts=$2,next_reconcile_at=clock_timestamp()+$3*interval '1 microsecond',reconcile_last_error=$4,updated_at=clock_timestamp() WHERE id=$1`, id, attempt, reconcileBackoff(attempt).Microseconds(), msg)
	if updateErr != nil {
		slog.Warn("feedback reconciliation failure could not be recorded", "feedback_id", id, "err", updateErr)
	}
}
