//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func postLinearFeedbackWebhook(t *testing.T, delivery, issue, state string, updated time.Time) (int, string) {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"action":"update","type":"Issue","webhookTimestamp":%d,"data":{"id":%q,"updatedAt":%q,"state":{"name":%q},"labels":[]}}`, time.Now().UnixMilli(), issue, updated.UTC().Format(time.RFC3339Nano), state))
	mac := hmac.New(sha256.New, []byte(integrationLinearWebhookSecret))
	_, _ = mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/public/linear-webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Linear-Event", "Issue")
	req.Header.Set("Linear-Delivery", delivery)
	req.Header.Set("Linear-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestLinearFeedbackWebhookRouteTransitionReplayAndUnknownIssue(t *testing.T) {
	ctx := context.Background()
	issue := "linear-feedback-" + randomHex(8)
	var feedbackID int64
	err := env.pool.QueryRow(ctx, `INSERT INTO feedback(tenant_id,tenant_display_slug,reporter_email,reporter_role,type,title,description,route,portal_build,user_agent,linear_issue_id,linear_issue_identifier,sync_state,synced_at,updated_at)
VALUES($1::uuid,'integration','submitter@example.test','viewer','feature','Integration feedback title','Integration feedback body','','integration','',$2,'PAT-TEST','synced',clock_timestamp()-interval '25 hours',clock_timestamp()) RETURNING id`, env.tenantID, issue).Scan(&feedbackID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = env.pool.Exec(context.Background(), `DELETE FROM feedback WHERE id=$1`, feedbackID) })

	updated := time.Now().UTC().Truncate(time.Microsecond)
	if status, body := postLinearFeedbackWebhook(t, "route-delivery-"+randomHex(8), issue, "Done", updated); status != http.StatusOK {
		t.Fatalf("valid webhook status=%d body=%s", status, body)
	}
	var customerStatus string
	var audits, emails int
	if err := env.pool.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM feedback_status_audit WHERE feedback_id=f.id),(SELECT count(*) FROM feedback_status_email_outbox WHERE feedback_id=f.id) FROM feedback f WHERE id=$1`, feedbackID).Scan(&customerStatus, &audits, &emails); err != nil {
		t.Fatal(err)
	}
	if customerStatus != "shipped" || audits != 1 || emails != 1 {
		t.Fatalf("status=%s audits=%d emails=%d", customerStatus, audits, emails)
	}

	delivery := "route-replay-" + randomHex(8)
	if status, _ := postLinearFeedbackWebhook(t, delivery, issue, "Canceled", updated.Add(time.Minute)); status != http.StatusOK {
		t.Fatalf("first replay delivery status=%d", status)
	}
	if status, _ := postLinearFeedbackWebhook(t, delivery, issue, "Duplicate", updated.Add(2*time.Minute)); status != http.StatusOK {
		t.Fatalf("second replay delivery status=%d", status)
	}
	if err := env.pool.QueryRow(ctx, `SELECT status FROM feedback WHERE id=$1`, feedbackID).Scan(&customerStatus); err != nil || customerStatus != "closed_not_planned" {
		t.Fatalf("replay changed status=%s err=%v", customerStatus, err)
	}

	if status, body := postLinearFeedbackWebhook(t, "route-unknown-"+randomHex(8), "unknown-"+randomHex(8), "Done", updated); status != http.StatusOK {
		t.Fatalf("unknown issue status=%d body=%s", status, body)
	}
}
