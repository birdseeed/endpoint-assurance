package feedback

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/graphmail"
)

const (
	feedbackEmailMaxAttempts = 6
	feedbackEmailLease       = 2 * time.Minute
)

type statusEmail struct {
	id, attempt                 int64
	recipient, reference, title string
	status                      string
}

type StatusEmailSweeper struct {
	pool *pgxpool.Pool
	mail graphmail.Sender
}

func NewStatusEmailSweeper(pool *pgxpool.Pool, mail graphmail.Sender) *StatusEmailSweeper {
	return &StatusEmailSweeper{pool: pool, mail: mail}
}

func (s *StatusEmailSweeper) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *StatusEmailSweeper) run(ctx context.Context) {
	// A process loss during Graph sendMail creates an unknowable acceptance
	// boundary. Preserve it as ambiguous and stop: automatic retry could send a
	// duplicate, while marking delivered could hide an omitted email.
	if tag, err := s.pool.Exec(ctx, `WITH expired AS (
 UPDATE feedback_status_email_outbox SET state='ambiguous',lease_until=NULL,last_error='delivery outcome unknown after sender interruption',updated_at=clock_timestamp()
 WHERE state='sending' AND lease_until<=clock_timestamp() RETURNING id,attempt_count
) UPDATE feedback_status_email_attempts a SET outcome='ambiguous',completed_at=clock_timestamp(),error='delivery outcome unknown after sender interruption'
FROM expired e WHERE a.outbox_id=e.id AND a.attempt_number=e.attempt_count AND a.outcome='sending'`); err != nil {
		slog.Warn("feedback email expired-lease recovery failed", "err", err)
	} else if tag.RowsAffected() > 0 {
		slog.Error("feedback email delivery requires manual review", "ambiguous_deliveries", tag.RowsAffected())
	}

	rows, err := s.pool.Query(ctx, `WITH due AS (
 SELECT id FROM feedback_status_email_outbox
 WHERE state='pending' AND next_attempt_at<=clock_timestamp() AND attempt_count<$1
 ORDER BY next_attempt_at,id LIMIT 10 FOR UPDATE SKIP LOCKED
), claimed AS (
 UPDATE feedback_status_email_outbox o SET state='sending',attempt_count=attempt_count+1,next_attempt_at=NULL,lease_until=clock_timestamp()+$2*interval '1 microsecond',updated_at=clock_timestamp()
 FROM due WHERE o.id=due.id
 RETURNING o.id,o.attempt_count,o.recipient,o.feedback_reference,o.feedback_title,o.customer_status
), attempts AS (
 INSERT INTO feedback_status_email_attempts(outbox_id,attempt_number,outcome)
 SELECT id,attempt_count,'sending' FROM claimed
)
SELECT id,attempt_count,recipient,feedback_reference,feedback_title,customer_status FROM claimed`, feedbackEmailMaxAttempts, feedbackEmailLease.Microseconds())
	if err != nil {
		slog.Warn("feedback email claim failed", "err", err)
		return
	}
	var due []statusEmail
	for rows.Next() {
		var item statusEmail
		if err := rows.Scan(&item.id, &item.attempt, &item.recipient, &item.reference, &item.title, &item.status); err != nil {
			slog.Warn("feedback email claim scan failed", "err", err)
			continue
		}
		due = append(due, item)
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		slog.Warn("feedback email claim rows failed", "err", scanErr)
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, item := range due {
		item := item
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.send(ctx, item)
		}()
	}
	wg.Wait()
}

func (s *StatusEmailSweeper) send(ctx context.Context, item statusEmail) {
	subject, body := renderFeedbackStatusEmail(item.reference, item.title, item.status)
	var err error
	if s.mail == nil {
		err = graphmail.ErrNotConfigured
	} else {
		err = s.mail.Send(ctx, graphmail.Message{To: []string{item.recipient}, Subject: subject, Body: body})
	}
	if err == nil {
		tag, updateErr := s.pool.Exec(ctx, `WITH done AS (
 UPDATE feedback_status_email_outbox SET state='delivered',lease_until=NULL,last_error=NULL,delivered_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE id=$1 AND state='sending' AND attempt_count=$2 AND lease_until>clock_timestamp() RETURNING id
) UPDATE feedback_status_email_attempts a SET outcome='delivered',completed_at=clock_timestamp(),error=NULL FROM done d
WHERE a.outbox_id=d.id AND a.attempt_number=$2 AND a.outcome='sending'`, item.id, item.attempt)
		if updateErr != nil || tag.RowsAffected() != 1 {
			slog.Error("feedback email accepted but delivery receipt could not be committed; lease will become ambiguous", "outbox_id", item.id, "err", updateErr)
		}
		return
	}

	uncertain := feedbackEmailUncertain(err)
	retry := !uncertain && feedbackEmailRetriable(err) && item.attempt < feedbackEmailMaxAttempts
	state, outcome := "dead_letter", "dead_letter"
	var next any
	if uncertain {
		state, outcome = "ambiguous", "ambiguous"
	} else if retry {
		state, outcome = "pending", "retry"
		next = feedbackEmailBackoff(int(item.attempt)).Microseconds()
	}
	msg := safeEmailError(err)
	tag, updateErr := s.pool.Exec(ctx, `WITH done AS (
 UPDATE feedback_status_email_outbox SET state=$3,lease_until=NULL,next_attempt_at=CASE WHEN $3='pending' THEN clock_timestamp()+$4::bigint*interval '1 microsecond' ELSE NULL END,last_error=$5,updated_at=clock_timestamp()
 WHERE id=$1 AND state='sending' AND attempt_count=$2 AND lease_until>clock_timestamp() RETURNING id
) UPDATE feedback_status_email_attempts a SET outcome=$6,completed_at=clock_timestamp(),error=$5 FROM done d
WHERE a.outbox_id=d.id AND a.attempt_number=$2 AND a.outcome='sending'`, item.id, item.attempt, state, next, msg, outcome)
	if updateErr != nil || tag.RowsAffected() != 1 {
		slog.Warn("feedback email failure could not be recorded", "outbox_id", item.id, "err", updateErr)
	} else if uncertain {
		slog.Error("feedback email delivery requires manual review", "outbox_id", item.id)
	}
}

func feedbackEmailUncertain(err error) bool {
	// Feedback status mail is at-most-once across an unknowable Graph boundary:
	// surface it for manual review instead of risking a duplicate customer mail.
	var uncertain *graphmail.DeliveryUncertainError
	return errors.As(err, &uncertain)
}

func renderFeedbackStatusEmail(reference, title, status string) (string, string) {
	label := map[string]string{
		StatusShipped:          "Shipped",
		StatusClosedNotPlanned: "Closed, not planned",
		StatusClosedMerged:     "Closed, merged",
	}[status]
	title = strings.Join(strings.Fields(title), " ")
	body := fmt.Sprintf("Your feedback has been updated.\n\nReference: %s\nTitle: %s\nStatus: %s\n", reference, title, label)
	if status == StatusClosedMerged {
		body += "\nThis has been merged with an existing request.\n"
	}
	return fmt.Sprintf("Feedback %s: %s", reference, label), body
}

func feedbackEmailRetriable(err error) bool {
	if errors.Is(err, graphmail.ErrNotConfigured) {
		return false
	}
	var sendErr *graphmail.SendError
	if errors.As(err, &sendErr) {
		return sendErr.Retriable()
	}
	var tokenErr *graphmail.TokenError
	if errors.As(err, &tokenErr) {
		return tokenErr.Retriable()
	}
	return true
}

func feedbackEmailBackoff(attempt int) time.Duration {
	d := time.Minute
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		return time.Hour
	}
	return d
}

func safeEmailError(err error) string {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}
