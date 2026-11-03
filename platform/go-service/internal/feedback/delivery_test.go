package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type fakeDeliveryStore struct {
	mu                 sync.Mutex
	d                  deliveryRecord
	events             []string
	expired, completed bool
	completeErr        error
	lastError          string
	syncState          string
}

func (s *fakeDeliveryStore) event(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}
func (s *fakeDeliveryStore) load(context.Context, int64, int) (deliveryRecord, error) {
	s.event("load")
	if s.expired {
		return deliveryRecord{}, ErrStaleFeedbackClaim
	}
	return s.d, nil
}
func (s *fakeDeliveryStore) reserveUpload(context.Context, int64, int) (int, error) {
	s.event("reserve")
	if s.expired {
		return 0, ErrStaleFeedbackClaim
	}
	s.d.ScreenshotAttempts++
	return s.d.ScreenshotAttempts, nil
}
func (s *fakeDeliveryStore) persistAsset(_ context.Context, _ int64, _ int, asset string) error {
	s.event("persistAsset")
	if s.expired {
		return ErrStaleFeedbackClaim
	}
	s.d.ScreenshotAssetURL = asset
	return nil
}
func (s *fakeDeliveryStore) uploadFailed(_ context.Context, _ int64, _ int, msg string) error {
	s.event("uploadFailed")
	if s.expired {
		return ErrStaleFeedbackClaim
	}
	s.lastError = msg
	return nil
}
func (s *fakeDeliveryStore) complete(context.Context, int64, int, string, string, *string) error {
	s.event("complete")
	if s.expired {
		return ErrStaleFeedbackClaim
	}
	if s.completeErr != nil {
		return s.completeErr
	}
	s.completed = true
	s.syncState = "synced"
	if s.d.ScreenshotAssetURL != "" {
		s.d.Screenshot = nil
		s.lastError = ""
	}
	return nil
}
func (s *fakeDeliveryStore) eventList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

func screenshotDeliveryRecord() deliveryRecord {
	return deliveryRecord{Submission: Submission{Reference: "FB-123", Type: TypeQuestion, Title: "Valid title", Description: "Customer text", Screenshot: &Screenshot{Bytes: []byte("raw pixels"), ContentType: "image/png", Filename: "FB-123.png"}}}
}

type fakeLinearDelivery struct {
	mu      sync.Mutex
	creates int
	body    string
}

func fakeDeliveryClient(t *testing.T, store *fakeDeliveryStore, putStatus int) (*LinearClient, *fakeLinearDelivery) {
	t.Helper()
	remote := &fakeLinearDelivery{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote.mu.Lock()
		defer remote.mu.Unlock()
		var in struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(in.Query, "fileUpload(") {
			store.event("fileUpload")
			_, _ = w.Write([]byte(`{"data":{"fileUpload":{"success":true,"uploadFile":{"uploadUrl":"https://storage.example.test/upload","assetUrl":"https://cdn.example.test/asset.png","headers":[]}}}}`))
			return
		}
		if strings.Contains(in.Query, "issues(filter") {
			store.event("find")
			if remote.creates == 0 {
				_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"issues": map[string]any{"nodes": []any{map[string]any{"id": "issue", "identifier": "PAT-1", "description": remote.body, "team": map[string]string{"id": "team"}, "project": map[string]string{"id": "project"}, "state": map[string]string{"name": "Backlog"}}}}}})
			return
		}
		store.event("issueCreate")
		remote.creates++
		remote.body = in.Variables["i"].(map[string]any)["description"].(string)
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"issue","identifier":"PAT-1","state":{"name":"Backlog"}}}}}`))
	}))
	t.Cleanup(srv.Close)
	c := NewLinearClient("key")
	c.Endpoint, c.HTTP, c.team, c.project, c.state = srv.URL, srv.Client(), "team", "project", "backlog"
	c.put = func(context.Context, string, map[string]string, []byte) (int, error) {
		store.event("PUT")
		return putStatus, nil
	}
	return c, remote
}

func TestDeliverFeedbackUploadsBeforeCreateAndClearsBlobOnlyOnCompletion(t *testing.T) {
	s := &fakeDeliveryStore{d: screenshotDeliveryRecord()}
	c, remote := fakeDeliveryClient(t, s, 204)
	if err := deliverFeedback(context.Background(), s, c, 1, 1); err != nil {
		t.Fatal(err)
	}
	want := []string{"load", "reserve", "fileUpload", "PUT", "persistAsset", "find", "issueCreate", "complete"}
	if got := s.eventList(); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong durable/external order:%v", got)
	}
	if !s.completed || s.d.Screenshot != nil || s.d.ScreenshotAssetURL == "" || s.d.ScreenshotAttempts != 1 {
		t.Fatalf("wrong completed upload state:%+v", s.d)
	}
	remote.mu.Lock()
	body := remote.body
	remote.mu.Unlock()
	if !strings.Contains(body, "| Submitted |") || !strings.Contains(body, "\n![Feedback screenshot](<https://cdn.example.test/asset.png>)\n\n## Customer text (untrusted)") {
		t.Fatalf("screenshot not placed between table and untrusted block:%s", body)
	}
}

func TestDeliverFeedbackNoIssueBeforeFifthUploadFailure(t *testing.T) {
	for prior := 0; prior < 5; prior++ {
		t.Run(string(rune('1'+prior)), func(t *testing.T) {
			d := screenshotDeliveryRecord()
			d.ScreenshotAttempts = prior
			s := &fakeDeliveryStore{d: d}
			c, remote := fakeDeliveryClient(t, s, 500)
			err := deliverFeedback(context.Background(), s, c, 1, prior+1)
			if s.d.ScreenshotAttempts != prior+1 || s.d.Screenshot == nil || s.d.ScreenshotAssetURL != "" {
				t.Fatalf("upload failure lost retained data:%+v", s.d)
			}
			remote.mu.Lock()
			creates, body := remote.creates, remote.body
			remote.mu.Unlock()
			if prior < 4 {
				if err == nil || creates != 0 || s.completed {
					t.Fatalf("issue created before upload budget:%v creates%d", err, creates)
				}
			} else {
				if err != nil || creates != 1 || !s.completed || s.syncState != "synced" || s.lastError == "" || !strings.Contains(body, "\nScreenshot upload failed\n\n## Customer text (untrusted)") {
					t.Fatalf("fifth failure fallback:%v creates%d body%s", err, creates, body)
				}
			}
		})
	}
}

func TestDeliverFeedbackReusesPersistedAssetAndRecoversIssueAfterCrash(t *testing.T) {
	d := screenshotDeliveryRecord()
	d.ScreenshotAssetURL = "https://cdn.example.test/asset.png"
	d.ScreenshotAttempts = 1
	crash := errors.New("crash after issueCreate before persistence")
	s := &fakeDeliveryStore{d: d, completeErr: crash}
	c, remote := fakeDeliveryClient(t, s, 204)
	if err := deliverFeedback(context.Background(), s, c, 1, 1); !errors.Is(err, crash) {
		t.Fatalf("missing crash:%v", err)
	}
	if s.d.Screenshot == nil {
		t.Fatal("blob cleared before successful issue persistence")
	}
	s.completeErr = nil
	if err := deliverFeedback(context.Background(), s, c, 1, 2); err != nil {
		t.Fatal(err)
	}
	for _, event := range s.eventList() {
		if event == "PUT" || event == "fileUpload" || event == "reserve" {
			t.Fatalf("persisted asset reuploaded:%v", s.eventList())
		}
	}
	remote.mu.Lock()
	creates := remote.creates
	remote.mu.Unlock()
	if creates != 1 || !s.completed || s.d.Screenshot != nil {
		t.Fatalf("crash recovery created duplicate or failed completion: creates%d", creates)
	}
}

func TestDeliverFeedbackExhaustedUploadBudgetNeverUploadsAgain(t *testing.T) {
	d := screenshotDeliveryRecord()
	d.ScreenshotAttempts = 5
	s := &fakeDeliveryStore{d: d}
	c, _ := fakeDeliveryClient(t, s, 204)
	if err := deliverFeedback(context.Background(), s, c, 1, 6); err != nil {
		t.Fatal(err)
	}
	if !s.completed || s.d.Screenshot == nil || s.d.ScreenshotAttempts != 5 {
		t.Fatal("exhausted fallback did not retain blob")
	}
	for _, event := range s.eventList() {
		if event == "PUT" || event == "fileUpload" || event == "reserve" {
			t.Fatal("sixth upload attempted")
		}
	}
}

func TestDeliverFeedbackExpiredLeaseCannotPersistAssetOrCreateIssue(t *testing.T) {
	s := &fakeDeliveryStore{d: screenshotDeliveryRecord()}
	c, remote := fakeDeliveryClient(t, s, 204)
	c.put = func(context.Context, string, map[string]string, []byte) (int, error) {
		s.event("PUT")
		s.expired = true
		return 204, nil
	}
	if err := deliverFeedback(context.Background(), s, c, 1, 1); !errors.Is(err, ErrStaleFeedbackClaim) {
		t.Fatalf("expired lease accepted:%v", err)
	}
	remote.mu.Lock()
	creates := remote.creates
	remote.mu.Unlock()
	if creates != 0 || s.completed || s.d.ScreenshotAssetURL != "" || s.d.Screenshot == nil {
		t.Fatal("expired worker persisted upload or created issue")
	}
}

func TestRequireFeedbackClaimDetectsZeroRows(t *testing.T) {
	if err := requireFeedbackClaim(pgconn.NewCommandTag("UPDATE 0"), nil); !errors.Is(err, ErrStaleFeedbackClaim) {
		t.Fatalf("zero-row update accepted:%v", err)
	}
	if err := requireFeedbackClaim(pgconn.NewCommandTag("UPDATE 1"), nil); err != nil {
		t.Fatal(err)
	}
}
