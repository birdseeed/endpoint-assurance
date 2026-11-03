package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"patched.im/api/internal/portalauth"
	"strings"
	"testing"
)

func TestPortalFeedbackHandlerDisabledReturnsNotFound(t *testing.T) {
	h := PortalFeedbackHandler(nil, false)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(method, "/v1/portal/feedback", nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("disabled %s /v1/portal/feedback = %d, want 404", method, rr.Code)
			}
		})
	}
}

func TestCaptureFeedbackContextStripsSensitiveURLAndCapsHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", nil)
	r.PostForm = url.Values{"route": {"/devices?token=secret#private"}}
	r.Header.Set("X-Portal-Build", strings.Repeat("b", 129))
	r.Header.Set("User-Agent", strings.Repeat("u", 513))
	in, err := captureFeedbackContext(r)
	if err != nil || in.Route != "/devices" || len(in.PortalBuild) != 128 || len(in.BrowserUserAgent) != 512 {
		t.Fatalf("captured context:%+v %v", in, err)
	}
	r.PostForm.Set("route", "/"+strings.Repeat("d", 600)+"?secret")
	r.Form = nil // FormValue cached the previous parsed form on the first call.
	in, err = captureFeedbackContext(r)
	if err != nil || len(in.Route) != 512 || strings.ContainsAny(in.Route, "?#") {
		t.Fatalf("captured long route:%q %v", in.Route, err)
	}
}

type feedbackBodyProbe struct{ reads int }

func (p *feedbackBodyProbe) Read([]byte) (int, error) { p.reads++; return 0, io.EOF }
func (p *feedbackBodyProbe) Close() error             { return nil }

func TestFeedbackDecodeReservationCancellationBeforeMultipart(t *testing.T) {
	first, err := acquireFeedbackDecode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	second, err := acquireFeedbackDecode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		release, err := acquireFeedbackDecode(ctx)
		if release != nil {
			release()
		}
		result <- err
	}()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation = %v", err)
	}
	body := &feedbackBodyProbe{}
	r := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", body)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=test")
	r = r.WithContext(portalauth.WithIdentity(ctx, portalauth.Identity{Email: "test@example.test", TenantID: "tenant"}))
	w := httptest.NewRecorder()
	PortalFeedbackHandler(nil, true).ServeHTTP(w, r)
	if w.Code != http.StatusRequestTimeout || body.reads != 0 {
		t.Fatalf("cancelled request: status=%d reads=%d", w.Code, body.reads)
	}
}

func TestFeedbackDecodeReservationReleasedOnMultipartError(t *testing.T) {
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", nil)
		r = r.WithContext(portalauth.WithIdentity(r.Context(), portalauth.Identity{Email: "test@example.test", TenantID: "tenant"}))
		w := httptest.NewRecorder()
		PortalFeedbackHandler(nil, true).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || len(feedbackDecodeSlots) != 0 {
			t.Fatalf("multipart error leaked reservation: status=%d slots=%d", w.Code, len(feedbackDecodeSlots))
		}
	}
}

// PAT-2216: severity is bug-only (PAT-2034). The portal drops a stale
// severity before forwarding, so the platform can refuse one outright; the
// refusal must be a clear JSON 400 the portal can show the customer, and it
// must be decided from the form alone, before any database work.
func feedbackMultipart(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, mw.FormDataContentType()
}

func TestPortalFeedbackValidationIsAClearJSON400BeforeAnyDatabaseWork(t *testing.T) {
	base := map[string]string{"title": "Please add an export filter", "description": "Filter the export by owner.", "route": "/devices"}
	cases := []struct {
		name, typ, severity, message string
	}{
		{"feature with severity", "feature", "low", "Severity applies only to bug reports."},
		{"question with severity", "question", "critical", "Severity applies only to bug reports."},
		{"bug without severity", "bug", "", "Bug reports need a severity of low, medium, high or critical."},
		{"unknown type", "praise", "", "Feedback type must be feature, design, support, bug or question."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]string{"type": tc.typ}
			for k, v := range base {
				fields[k] = v
			}
			if tc.severity != "" {
				fields["severity"] = tc.severity
			}
			body, contentType := feedbackMultipart(t, fields)
			r := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", body)
			r.Header.Set("Content-Type", contentType)
			r = r.WithContext(portalauth.WithIdentity(r.Context(), portalauth.Identity{Email: "test@example.test", TenantID: "11111111-2222-3333-4444-555555555555"}))
			w := httptest.NewRecorder()
			// A nil pool: reaching the database at all would panic, so a
			// pass proves the refusal needs no database round trip.
			PortalFeedbackHandler(nil, true).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %q", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var got struct{ Error, Message string }
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not JSON: %v (%q)", err, w.Body.String())
			}
			if got.Error != "invalid_feedback" || got.Message != tc.message {
				t.Fatalf("body = %+v, want invalid_feedback / %q", got, tc.message)
			}
		})
	}
}
