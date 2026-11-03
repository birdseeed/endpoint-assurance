package releasecontrol

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/graphmail"
)

// DeliverNotice sends one due email and records its result durably. Row locking
// permits multiple API instances without concurrent delivery. Graph sendMail is
// at-least-once: a crash after acceptance but before commit, or an unknowable
// Graph acceptance, can cause a retry and duplicate notice.
// The schedule and release authority never depend on customer subscriptions.
func DeliverNotice(ctx context.Context, pool *pgxpool.Pool, sender graphmail.Sender) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id int64
	var tenantID, recipient, version, banner string
	var scheduled time.Time
	err = tx.QueryRow(ctx, `SELECT id,tenant_id::text,email_recipient,version,banner,scheduled_at FROM agent_release_p0_notices WHERE email_status IN ('pending','failed') AND email_next_attempt_at<=clock_timestamp() AND email_attempts<288 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &tenantID, &recipient, &version, &banner, &scheduled)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var sendErr error
	if sender == nil {
		sendErr = graphmail.ErrNotConfigured
	} else {
		sendErr = sender.Send(sendCtx, graphmail.Message{To: []string{recipient}, Subject: "Patched critical agent security update scheduled", Body: fmt.Sprintf("%s\n\nPatched will apply agent version %s at %s. This critical security update applies even when updates are held.\n\nView the notice in your Patched portal.", banner, version, scheduled.UTC().Format(time.RFC3339))})
	}
	status := "delivered"
	var safeError *string
	if sendErr != nil {
		status = "failed"
		msg := "email transport failed; see operator logs"
		if sendErr == graphmail.ErrNotConfigured {
			msg = "email transport not configured"
		}
		safeError = &msg
		slog.Error("P0 email delivery failed", "notice_id", id, "err", sendErr)
	}
	// Preserve result even if shutdown cancelled the send context.
	recordCtx, recordCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer recordCancel()
	_, err = tx.Exec(recordCtx, `UPDATE agent_release_p0_notices SET email_status=$2,email_attempts=email_attempts+1,email_last_error=$3,email_next_attempt_at=clock_timestamp()+interval '5 minutes',email_delivered_at=CASE WHEN $2='delivered' THEN clock_timestamp() ELSE NULL END WHERE id=$1`, id, status, safeError)
	if err != nil {
		return false, err
	}
	if err = Audit(recordCtx, tx, &tenantID, "p0-mail-worker", "internal", "p0_email_attempt", map[string]any{"notice_id": id, "status": status}); err != nil {
		return false, err
	}
	return true, tx.Commit(recordCtx)
}

func RunMail(ctx context.Context, pool *pgxpool.Pool, sender graphmail.Sender) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		// Bound each iteration, so a growing queue cannot starve shutdown.
		for i := 0; i < 25; i++ {
			handled, err := DeliverNotice(ctx, pool, sender)
			if err != nil {
				slog.Error("P0 mail queue failed", "err", err)
				break
			}
			if !handled {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
