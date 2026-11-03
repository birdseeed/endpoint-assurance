package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/feedback"
)

const maxLinearWebhookBytes = 256 * 1024

type linearWebhookPayload struct {
	Action           string `json:"action"`
	Type             string `json:"type"`
	WebhookTimestamp int64  `json:"webhookTimestamp"`
	Data             struct {
		ID        string          `json:"id"`
		UpdatedAt string          `json:"updatedAt"`
		State     json.RawMessage `json:"state"`
		Labels    json.RawMessage `json:"labels"`
	} `json:"data"`
}

// LinearWebhookHandler consumes only signed Issue update events. The exact
// bytes are authenticated before any JSON parsing, and the timestamp is then
// checked against a deliberately narrow replay window.
func LinearWebhookHandler(pool *pgxpool.Pool, secret string) http.HandlerFunc {
	return linearWebhookHandler(pool, secret, time.Now)
}

func linearWebhookHandler(pool *pgxpool.Pool, secret string, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(secret) == "" {
			http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxLinearWebhookBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid webhook body", http.StatusRequestEntityTooLarge)
			return
		}
		if !validLinearSignature([]byte(secret), raw, r.Header.Get("Linear-Signature")) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		var payload linearWebhookPayload
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		if err := dec.Decode(&payload); err != nil {
			http.Error(w, "invalid webhook JSON", http.StatusBadRequest)
			return
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid webhook JSON", http.StatusBadRequest)
			return
		}
		nowMillis := now().UTC().UnixMilli()
		if payload.WebhookTimestamp < nowMillis-60_000 || payload.WebhookTimestamp > nowMillis+60_000 {
			http.Error(w, "stale webhook", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Linear-Event") != "Issue" || payload.Type != "Issue" || payload.Action != "update" {
			w.WriteHeader(http.StatusOK)
			return
		}
		delivery := strings.TrimSpace(r.Header.Get("Linear-Delivery"))
		if !validLinearIdentifier(delivery, 128) || !validLinearIdentifier(payload.Data.ID, 128) {
			http.Error(w, "invalid webhook identity", http.StatusBadRequest)
			return
		}
		updatedAt, err := time.Parse(time.RFC3339Nano, payload.Data.UpdatedAt)
		if err != nil {
			http.Error(w, "invalid issue updatedAt", http.StatusBadRequest)
			return
		}
		state, err := linearStateName(payload.Data.State)
		if err != nil {
			http.Error(w, "invalid issue state", http.StatusBadRequest)
			return
		}
		labels, err := linearLabelNames(payload.Data.Labels)
		if err != nil {
			http.Error(w, "invalid issue labels", http.StatusBadRequest)
			return
		}
		result, err := feedback.ApplyLinearUpdate(r.Context(), pool, feedback.LinearUpdate{
			IssueID: payload.Data.ID, State: state, Labels: labels, UpdatedAt: updatedAt,
			Delivery: delivery, Source: "webhook",
		})
		if err != nil {
			slog.Error("Linear feedback webhook processing failed", "delivery", delivery, "err", err)
			http.Error(w, "webhook processing failed", http.StatusInternalServerError)
			return
		}
		if result.Outcome == "unknown_issue" {
			slog.Info("Linear feedback webhook ignored unknown issue", "issue_id", payload.Data.ID)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func validLinearSignature(secret, body []byte, provided string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(provided))
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), decoded)
}

func validLinearIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func linearStateName(raw json.RawMessage) (string, error) {
	var state struct {
		Name string `json:"name"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &state) != nil {
		return "", errors.New("missing state")
	}
	state.Name = strings.TrimSpace(state.Name)
	if state.Name == "" || len(state.Name) > 128 {
		return "", errors.New("missing state name")
	}
	return state.Name, nil
}

func linearLabelNames(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	var objects []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &objects); err == nil {
		if len(objects) > 100 {
			return nil, errors.New("too many labels")
		}
		out := make([]string, 0, len(objects))
		for _, label := range objects {
			if len(label.Name) > 128 {
				return nil, errors.New("label too long")
			}
			out = append(out, label.Name)
		}
		return out, nil
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil || len(names) > 100 {
		return nil, errors.New("invalid labels")
	}
	for _, name := range names {
		if len(name) > 128 {
			return nil, errors.New("label too long")
		}
	}
	return names, nil
}
