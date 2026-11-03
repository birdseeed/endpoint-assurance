package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/feedback"
	"patched.im/api/internal/portalauth"
)

// PortalFeedbackEnabled is configured once at process start. Keeping the gate
// at handler entry makes disabled requests return 404 after portal auth.
var PortalFeedbackEnabled bool

// Shared across all handler instances: bound multipart/decode memory process-wide.
var feedbackDecodeSlots = make(chan struct{}, 2)

func acquireFeedbackDecode(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case feedbackDecodeSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-feedbackDecodeSlots
			return nil, err
		}
		return func() { <-feedbackDecodeSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func captureFeedbackContext(r *http.Request) (feedback.Submission, error) {
	in := feedback.Submission{Route: r.FormValue("route"), PortalBuild: r.Header.Get("X-Portal-Build"), BrowserUserAgent: r.UserAgent()}
	err := in.SanitizeContext()
	return in, err
}

// PortalFeedbackHandler serves both portal feedback methods. The feature gate
// is deliberately inside the handler so disabled routes are indistinguishable
// from absent routes even when called directly in tests.
func PortalFeedbackHandler(pool *pgxpool.Pool, enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		id, ok := portalauth.FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		store := feedback.Store{Pool: pool}
		switch r.Method {
		case http.MethodGet:
			// PAT-2347: ?door=feedback|support gives one list per portal door;
			// no parameter keeps the pre-split behaviour of returning everything.
			door := r.URL.Query().Get("door")
			if door != "" && door != feedback.DoorFeedback && door != feedback.DoorSupport {
				writeFeedbackInvalid(w, "door must be feedback or support.")
				return
			}
			rows, err := store.List(r.Context(), id.TenantID, door)
			if err != nil {
				http.Error(w, "internal error", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rows)
		case http.MethodPost:
			release, err := acquireFeedbackDecode(r.Context())
			if err != nil {
				http.Error(w, "request cancelled", http.StatusRequestTimeout)
				return
			}
			defer release()
			r.Body = http.MaxBytesReader(w, r.Body, 6*1024*1024)
			if err := r.ParseMultipartForm(6 * 1024 * 1024); err != nil {
				writeFeedbackInvalid(w, "The feedback could not be read. Send it again from the portal.")
				return
			}
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			captured, err := captureFeedbackContext(r)
			if err != nil {
				writeFeedbackInvalid(w, "The page route could not be read. Send it again from the portal.")
				return
			}
			// PAT-2216: decide the customer's own fields from the form alone,
			// before any database round trip, and answer in JSON the portal
			// can show verbatim. Create re-validates the complete submission.
			in := feedback.Submission{TenantID: id.TenantID, ReporterEmail: id.Email, Type: r.FormValue("type"), Title: r.FormValue("title"), Description: r.FormValue("description"), Severity: r.FormValue("severity"), Category: r.FormValue("category"), Route: captured.Route, PortalBuild: captured.PortalBuild, BrowserUserAgent: captured.BrowserUserAgent}
			if err := in.Validate(); err != nil {
				writeFeedbackInvalid(w, err.Error())
				return
			}
			role, err := portalauth.DBRole(r.Context(), pool, id.Email, id.TenantID, false)
			if err != nil {
				http.Error(w, "internal error", 500)
				return
			}
			var shot *feedback.Screenshot
			if f, _, err := r.FormFile("screenshot"); err == nil {
				defer f.Close()
				raw, readErr := io.ReadAll(io.LimitReader(f, 5*1024*1024+1))
				if readErr != nil {
					writeFeedbackInvalid(w, feedbackScreenshotUnreadable)
					return
				}
				shot, err = feedback.SanitizeScreenshot(raw)
				if err != nil {
					writeFeedbackInvalid(w, feedbackScreenshotUnreadable)
					return
				}
			} else if err != http.ErrMissingFile {
				writeFeedbackInvalid(w, feedbackScreenshotUnreadable)
				return
			}
			var tenantName string
			if err := pool.QueryRow(r.Context(), `SELECT name FROM tenants WHERE id=$1::uuid`, id.TenantID).Scan(&tenantName); err != nil {
				http.Error(w, "internal error", 500)
				return
			}
			in.TenantDisplaySlug, in.ReporterRole, in.SubmittedAt, in.Screenshot = slug(tenantName), role, time.Now().UTC(), shot
			rec, decision, err := store.Create(r.Context(), in)
			if err != nil {
				http.Error(w, "internal error", 500)
				return
			}
			if !decision.Allowed {
				retry := "3600"
				if decision.Reason == feedback.RateLimitTenantDaily {
					retry = "86400"
				}
				w.Header().Set("Retry-After", retry)
				http.Error(w, "feedback rate limit exceeded", 429)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"reference": rec.Reference, "status": rec.Status})
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
		}
	}
}

const feedbackScreenshotUnreadable = "The screenshot could not be read. Attach a PNG or JPEG under 5 MiB and 12 million pixels, or remove it."

// writeFeedbackInvalid answers a refused submission with a customer-grade
// reason. The portal shows `message` in place of its generic failure text.
func writeFeedbackInvalid(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_feedback", "message": message})
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Join(strings.Fields(s), "-")
	return s
}
