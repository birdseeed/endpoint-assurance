package feedback

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/graphmail"
)

func feedbackStatusDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := feedbackDBPool(t)
	var ready bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('public.feedback_status_audit') IS NOT NULL AND EXISTS(SELECT 1 FROM schema_migrations WHERE version='0207_feedback_linear_updates')`).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	if !ready {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED: feedback status acceptance requires migration 0207")
		}
		t.Skip("feedback status acceptance requires migration 0207")
	}
	return pool
}

func TestFeedbackStatusMigrationGrantsAndRollbackGuard(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	ctx := context.Background()
	for table, privileges := range map[string][]string{
		"feedback_linear_webhook_deliveries": {"SELECT", "INSERT", "UPDATE"},
		"feedback_status_audit":              {"SELECT", "INSERT"},
		"feedback_status_email_outbox":       {"SELECT", "INSERT", "UPDATE"},
		"feedback_status_email_attempts":     {"SELECT", "INSERT", "UPDATE"},
	} {
		for _, privilege := range privileges {
			var granted bool
			if err := pool.QueryRow(ctx, `SELECT has_table_privilege('patched',$1,$2)`, "public."+table, privilege).Scan(&granted); err != nil || !granted {
				t.Errorf("missing %s on %s: %v", privilege, table, err)
			}
		}
	}
	for _, sequence := range []string{"feedback_status_audit_id_seq", "feedback_status_email_outbox_id_seq", "feedback_status_email_attempts_id_seq"} {
		var granted bool
		if err := pool.QueryRow(ctx, `SELECT has_sequence_privilege('patched',$1,'USAGE')`, "public."+sequence).Scan(&granted); err != nil || !granted {
			t.Errorf("missing sequence grant on %s: %v", sequence, err)
		}
	}

	tenant := feedbackDBTenant(t, pool)
	suffix := feedbackDBSuffix(t)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "rollback@example.test"))
	issueID := "issue-rollback-guard-" + suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-25*time.Hour))
	_, err := ApplyLinearUpdate(ctx, pool, LinearUpdate{IssueID: issueID, State: "In Progress", UpdatedAt: time.Now(), Delivery: "rollback-guard-" + suffix, Source: "webhook"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0207_feedback_linear_updates_rollback.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(raw)); err == nil || !strings.Contains(err.Error(), "Refusing 0207 rollback") {
		t.Fatalf("rollback did not refuse retained evidence: %v", err)
	}
	var stillPresent bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.feedback_status_audit') IS NOT NULL`).Scan(&stillPresent); err != nil || !stillPresent {
		t.Fatalf("failed rollback removed schema: present=%t err=%v", stillPresent, err)
	}
}

func attachLinearIssue(t *testing.T, pool *pgxpool.Pool, id int64, issue string, checked time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `UPDATE feedback SET linear_issue_id=$2,linear_issue_identifier='PAT-TEST',sync_state='synced',synced_at=$3,linear_checked_at=$3,next_reconcile_at=clock_timestamp() WHERE id=$1`, id, issue, checked)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFeedbackLinearUpdateIsTenantScopedAuditedAndReplaySafe(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	a, b := feedbackDBTenant(t, pool), feedbackDBTenant(t, pool)
	ra := feedbackDBCreate(t, pool, feedbackDBSubmission(a, "submitter-a@example.test"))
	rb := feedbackDBCreate(t, pool, feedbackDBSubmission(b, "submitter-b@example.test"))
	issueA, issueB := "issue-tenant-a-"+suffix, "issue-tenant-b-"+suffix
	delivery := "delivery-a-" + suffix
	attachLinearIssue(t, pool, ra.ID, issueA, time.Now().Add(-25*time.Hour))
	attachLinearIssue(t, pool, rb.ID, issueB, time.Now().Add(-25*time.Hour))
	at := time.Now().UTC().Truncate(time.Microsecond)
	result, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueA, State: "Done", UpdatedAt: at, Delivery: delivery, Source: "webhook"})
	if err != nil || !result.Changed {
		t.Fatalf("apply: %+v %v", result, err)
	}
	result, err = ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueA, State: "Canceled", UpdatedAt: at.Add(time.Hour), Delivery: delivery, Source: "webhook"})
	if err != nil || !result.Replay {
		t.Fatalf("replay: %+v %v", result, err)
	}
	for _, tc := range []struct {
		id   int64
		want string
	}{{ra.ID, StatusShipped}, {rb.ID, StatusReceived}} {
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM feedback WHERE id=$1`, tc.id).Scan(&got); err != nil || got != tc.want {
			t.Fatalf("feedback %d status=%q want %q err=%v", tc.id, got, tc.want, err)
		}
	}
	var audits, outbox int
	var tenant, recipient, reference, title, status string
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM feedback_status_audit WHERE feedback_id=$1`, ra.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit count=%d err=%v", audits, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*),min(tenant_id::text),min(recipient),min(feedback_reference),min(feedback_title),min(customer_status) FROM feedback_status_email_outbox WHERE feedback_id=$1`, ra.ID).Scan(&outbox, &tenant, &recipient, &reference, &title, &status); err != nil {
		t.Fatal(err)
	}
	if outbox != 1 || tenant != a || recipient != "submitter-a@example.test" || reference != ra.Reference || title != ra.Title || status != StatusShipped {
		t.Fatalf("wrong tenant-scoped outbox: count=%d tenant=%s recipient=%s reference=%s title=%s status=%s", outbox, tenant, recipient, reference, title, status)
	}
}

func TestFeedbackLinearUpdateNewestWinsAndUnknownStateDoesNotTransition(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	tenant := feedbackDBTenant(t, pool)
	in := feedbackDBSubmission(tenant, "newest@example.test")
	in.Type, in.Severity = TypeBug, SeverityLow
	r := feedbackDBCreate(t, pool, in)
	issueID := "issue-newest-" + suffix
	newerDelivery, olderDelivery, unknownDelivery := "delivery-newer-"+suffix, "delivery-older-"+suffix, "delivery-unknown-"+suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-25*time.Hour))
	newer := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: "In Progress", UpdatedAt: newer, Delivery: newerDelivery, Source: "webhook"}); err != nil {
		t.Fatal(err)
	}
	if got, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: "Done", UpdatedAt: newer.Add(-time.Minute), Delivery: olderDelivery, Source: "webhook"}); err != nil || got.Outcome != "stale" {
		t.Fatalf("older result=%+v err=%v", got, err)
	}
	unknownAt := newer.Add(time.Minute)
	if got, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: "Not A Patched State", UpdatedAt: unknownAt, Delivery: unknownDelivery, Source: "webhook"}); err != nil || got.Outcome != "unknown_state" {
		t.Fatalf("unknown result=%+v err=%v", got, err)
	}
	var status, linearState string
	var linearUpdated time.Time
	if err := pool.QueryRow(context.Background(), `SELECT status,linear_state,linear_updated_at FROM feedback WHERE id=$1`, r.ID).Scan(&status, &linearState, &linearUpdated); err != nil {
		t.Fatal(err)
	}
	if status != StatusInProgress || linearState != "Not A Patched State" || !linearUpdated.Equal(unknownAt) {
		t.Fatalf("status=%s linear=%s updated=%s", status, linearState, linearUpdated)
	}
	var auditCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM feedback_status_audit WHERE feedback_id=$1`, r.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
	for delivery, want := range map[string]string{newerDelivery: "transitioned", olderDelivery: "stale", unknownDelivery: "unknown_state"} {
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT outcome FROM feedback_linear_webhook_deliveries WHERE delivery_id=$1`, delivery).Scan(&got); err != nil || got != want {
			t.Errorf("delivery %s outcome=%s want=%s err=%v", delivery, got, want, err)
		}
	}
}

func TestFeedbackQuestionNeverTransitionsToPlannedInDatabase(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	tenant := feedbackDBTenant(t, pool)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "question@example.test"))
	issueID := "issue-question-" + suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-25*time.Hour))
	for i, state := range []string{"Backlog", "Todo", "Blocked"} {
		_, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: state, UpdatedAt: time.Now().Add(time.Duration(i) * time.Minute), Delivery: fmt.Sprintf("question-%s-%d", suffix, i), Source: "webhook"})
		if err != nil {
			t.Fatal(err)
		}
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM feedback WHERE id=$1`, r.ID).Scan(&got); err != nil || got != StatusReceived {
			t.Fatalf("state=%s status=%s err=%v", state, got, err)
		}
	}
}

func TestFeedbackStatusAuditRejectsMutation(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	tenant := feedbackDBTenant(t, pool)
	in := feedbackDBSubmission(tenant, "audit@example.test")
	in.Type, in.Severity = TypeBug, SeverityMedium
	r := feedbackDBCreate(t, pool, in)
	issueID := "issue-audit-" + suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-25*time.Hour))
	_, _ = ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: "In Review", UpdatedAt: time.Now(), Delivery: "audit-delivery-" + suffix, Source: "webhook"})
	for _, query := range []string{`UPDATE feedback_status_audit SET linear_state='changed' WHERE feedback_id=$1`, `DELETE FROM feedback_status_audit WHERE feedback_id=$1`} {
		_, err := pool.Exec(context.Background(), query, r.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Errorf("audit mutation not refused: %v", err)
		}
	}
}

type feedbackMailFake struct {
	mu       sync.Mutex
	messages []graphmail.Message
	err      error
}

func (f *feedbackMailFake) From() string { return "noreply@example.test" }
func (f *feedbackMailFake) Send(_ context.Context, msg graphmail.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, msg)
	return f.err
}

func TestFeedbackStatusEmailTenantContentIdempotencyFailureAndAmbiguity(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	tenant := feedbackDBTenant(t, pool)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "only-this-submitter@example.test"))
	issueID := "issue-email-" + suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-25*time.Hour))
	_, err := ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: issueID, State: "Duplicate", UpdatedAt: time.Now(), Delivery: "email-delivery-" + suffix, Source: "webhook"})
	if err != nil {
		t.Fatal(err)
	}
	fake := &feedbackMailFake{}
	sweeper := NewStatusEmailSweeper(pool, fake)
	sweeper.run(context.Background())
	sweeper.run(context.Background())
	if len(fake.messages) != 1 || len(fake.messages[0].To) != 1 || fake.messages[0].To[0] != "only-this-submitter@example.test" {
		t.Fatalf("wrong or duplicate messages: %+v", fake.messages)
	}
	if !strings.Contains(fake.messages[0].Body, "This has been merged with an existing request.") || strings.Contains(fake.messages[0].Body, "PAT-") || strings.Contains(fake.messages[0].Body, "linear.app") {
		t.Fatalf("wrong customer email: %+v", fake.messages[0])
	}

	// A known transient Graph refusal is retried from the durable row.
	r2 := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "retry@example.test"))
	retryIssueID := "issue-email-retry-" + suffix
	attachLinearIssue(t, pool, r2.ID, retryIssueID, time.Now().Add(-25*time.Hour))
	_, _ = ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: retryIssueID, State: "Done", UpdatedAt: time.Now().Add(time.Second), Delivery: "email-retry-" + suffix, Source: "webhook"})
	fake.err = &graphmail.SendError{Status: 503}
	sweeper.run(context.Background())
	if _, err := pool.Exec(context.Background(), `UPDATE feedback_status_email_outbox SET next_attempt_at=clock_timestamp() WHERE feedback_id=$1 AND state='pending'`, r2.ID); err != nil {
		t.Fatal(err)
	}
	fake.err = nil
	sweeper.run(context.Background())
	var state string
	var attempts int
	if err := pool.QueryRow(context.Background(), `SELECT state,attempt_count FROM feedback_status_email_outbox WHERE feedback_id=$1`, r2.ID).Scan(&state, &attempts); err != nil || state != "delivered" || attempts != 2 {
		t.Fatalf("retry state=%s attempts=%d err=%v", state, attempts, err)
	}

	// An expired in-flight attempt is never automatically resent.
	r3 := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "ambiguous@example.test"))
	ambiguousIssueID := "issue-email-ambiguous-" + suffix
	attachLinearIssue(t, pool, r3.ID, ambiguousIssueID, time.Now().Add(-25*time.Hour))
	_, _ = ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: ambiguousIssueID, State: "Canceled", UpdatedAt: time.Now().Add(2 * time.Second), Delivery: "email-ambiguous-" + suffix, Source: "webhook"})
	var outboxID int64
	if err := pool.QueryRow(context.Background(), `UPDATE feedback_status_email_outbox SET state='sending',attempt_count=1,next_attempt_at=NULL,lease_until=clock_timestamp()-interval '1 second' WHERE feedback_id=$1 RETURNING id`, r3.ID).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO feedback_status_email_attempts(outbox_id,attempt_number,outcome) VALUES($1,1,'sending')`, outboxID); err != nil {
		t.Fatal(err)
	}
	before := len(fake.messages)
	sweeper.run(context.Background())
	if err := pool.QueryRow(context.Background(), `SELECT state FROM feedback_status_email_outbox WHERE id=$1`, outboxID).Scan(&state); err != nil || state != "ambiguous" || len(fake.messages) != before {
		t.Fatalf("ambiguous state=%s messages=%d/%d err=%v", state, len(fake.messages), before, err)
	}

	// A transport failure after sendMail begins has an unknowable provider
	// outcome, so it is made visible for manual review and is never retried.
	r4 := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "transport-ambiguous@example.test"))
	transportIssueID := "issue-email-transport-ambiguous-" + suffix
	attachLinearIssue(t, pool, r4.ID, transportIssueID, time.Now().Add(-25*time.Hour))
	_, _ = ApplyLinearUpdate(context.Background(), pool, LinearUpdate{IssueID: transportIssueID, State: "Done", UpdatedAt: time.Now().Add(3 * time.Second), Delivery: "email-transport-ambiguous-" + suffix, Source: "webhook"})
	fake.err = &graphmail.DeliveryUncertainError{}
	sweeper.run(context.Background())
	if err := pool.QueryRow(context.Background(), `SELECT state,attempt_count FROM feedback_status_email_outbox WHERE feedback_id=$1`, r4.ID).Scan(&state, &attempts); err != nil || state != "ambiguous" || attempts != 1 {
		t.Fatalf("transport ambiguity state=%s attempts=%d err=%v", state, attempts, err)
	}
	fake.err = nil
	sweeper.run(context.Background())
	if err := pool.QueryRow(context.Background(), `SELECT state,attempt_count FROM feedback_status_email_outbox WHERE feedback_id=$1`, r4.ID).Scan(&state, &attempts); err != nil || state != "ambiguous" || attempts != 1 {
		t.Fatalf("transport ambiguity retried state=%s attempts=%d err=%v", state, attempts, err)
	}
}

func TestFeedbackReconciliationGateHealingAndBackoff(t *testing.T) {
	pool := feedbackStatusDBPool(t)
	suffix := feedbackDBSuffix(t)
	tenant := feedbackDBTenant(t, pool)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "reconcile@example.test"))
	issueID := "issue-reconcile-" + suffix
	attachLinearIssue(t, pool, r.ID, issueID, time.Now().Add(-48*time.Hour))
	updated := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":{"issue":{"id":%q,"updatedAt":%q,"state":{"name":"Done"},"labels":{"nodes":[]}}}}`, issueID, updated.Format(time.RFC3339Nano))
	}))
	defer server.Close()
	disabled := NewReconciler(pool, "key", false)
	disabled.client.Endpoint = server.URL
	disabled.run(context.Background())
	var status string
	_ = pool.QueryRow(context.Background(), `SELECT status FROM feedback WHERE id=$1`, r.ID).Scan(&status)
	if status != StatusReceived {
		t.Fatalf("disabled reconciliation changed status to %s", status)
	}
	enabled := NewReconciler(pool, "key", true)
	enabled.client.Endpoint = server.URL
	enabled.run(context.Background())
	_ = pool.QueryRow(context.Background(), `SELECT status FROM feedback WHERE id=$1`, r.ID).Scan(&status)
	if status != StatusShipped {
		t.Fatalf("reconciliation did not heal status: %s", status)
	}

	r2 := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "reconcile-fail@example.test"))
	attachLinearIssue(t, pool, r2.ID, "issue-reconcile-fail-"+suffix, time.Now().Add(-48*time.Hour))
	enabled.client.Endpoint = "http://127.0.0.1:1"
	enabled.run(context.Background())
	var attempt int
	var next time.Time
	var lastErr string
	if err := pool.QueryRow(context.Background(), `SELECT reconcile_attempts,next_reconcile_at,reconcile_last_error FROM feedback WHERE id=$1`, r2.ID).Scan(&attempt, &next, &lastErr); err != nil || attempt != 1 || !next.After(time.Now()) || lastErr == "" {
		t.Fatalf("backoff attempt=%d next=%s err=%q query=%v", attempt, next, lastErr, err)
	}
}
