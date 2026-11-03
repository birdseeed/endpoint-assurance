package intune

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/msgraph"
)

// generateTestCertificate builds a throwaway self-signed RSA certificate for
// test use only — mirrors internal/msgraph's own testhelpers_test.go, which
// is unexported and unavailable outside that package.
func generateTestCertificate(t *testing.T) *msgraph.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intune-test-fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	return msgraph.NewCertificate(cert, key)
}

// newTestGraphClient wires a msgraph.Client to a real TokenSource pointed at
// an always-succeeding token httptest.Server, and to graphHandler for
// resource requests. Same shape as msgraph's own newTestClient.
func newTestGraphClient(t *testing.T, graphHandler http.Handler) *msgraph.Client {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "graph-access-token",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(tokenServer.Close)

	graphServer := httptest.NewServer(graphHandler)
	t.Cleanup(graphServer.Close)

	ts := msgraph.NewTokenSource("client-id", generateTestCertificate(t))
	ts.AuthorityBase = tokenServer.URL

	c := msgraph.NewClient(ts)
	c.BaseURL = graphServer.URL
	return c
}

// fakePolicy is one compliance policy held by fakeGraphServer.
type fakePolicy struct {
	id                   string
	lastModifiedDateTime time.Time
	displayName          string
	assignments          []json.RawMessage
}

func (p *fakePolicy) body() json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"id":                   p.id,
		"displayName":          p.displayName,
		"lastModifiedDateTime": p.lastModifiedDateTime.UTC().Format(time.RFC3339Nano),
	})
	return b
}

// fakeGraphServer simulates the compliance-policies surface: the cheap
// $select list, per-object GET, and per-object assignments GET. It counts
// calls so tests can assert "no full body fetch happened" on an unchanged
// second run.
type fakeGraphServer struct {
	mu       sync.Mutex
	order    []string
	policies map[string]*fakePolicy
	failBody map[string]bool // object id -> return 500 on body fetch

	listCalls         int
	bodyFetches       map[string]int
	assignmentFetches map[string]int
}

func newFakeGraphServer() *fakeGraphServer {
	return &fakeGraphServer{
		policies:          map[string]*fakePolicy{},
		failBody:          map[string]bool{},
		bodyFetches:       map[string]int{},
		assignmentFetches: map[string]int{},
	}
}

func (f *fakeGraphServer) addPolicy(id string, lastModified time.Time, displayName string, assignments ...json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.policies[id]; !exists {
		f.order = append(f.order, id)
	}
	f.policies[id] = &fakePolicy{
		id:                   id,
		lastModifiedDateTime: lastModified,
		displayName:          displayName,
		assignments:          assignments,
	}
}

func (f *fakeGraphServer) removePolicy(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, id)
	for i, existing := range f.order {
		if existing == id {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
}

func (f *fakeGraphServer) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /deviceManagement/deviceCompliancePolicies", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.listCalls++
		values := make([]json.RawMessage, 0, len(f.order))
		for _, id := range f.order {
			p := f.policies[id]
			entry, _ := json.Marshal(map[string]any{
				"id":                   p.id,
				"lastModifiedDateTime": p.lastModifiedDateTime.UTC().Format(time.RFC3339Nano),
			})
			values = append(values, entry)
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"value": values})
	})

	mux.HandleFunc("GET /deviceManagement/deviceCompliancePolicies/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		f.bodyFetches[id]++
		fail := f.failBody[id]
		p, ok := f.policies[id]
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"InternalServerError","message":"simulated failure"}}`))
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(p.body())
	})

	mux.HandleFunc("GET /deviceManagement/deviceCompliancePolicies/{id}/assignments", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		f.assignmentFetches[id]++
		p, ok := f.policies[id]
		var items []json.RawMessage
		if ok {
			items = p.assignments
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": items})
	})

	return mux
}

func (f *fakeGraphServer) bodyFetchCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodyFetches[id]
}

func (f *fakeGraphServer) assignmentFetchCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assignmentFetches[id]
}

// fakeStore is an in-memory Store so snapshot orchestration tests need no
// database.
type fakeStore struct {
	mu        sync.Mutex
	snapshots []Snapshot
}

func (s *fakeStore) PriorObjects(ctx context.Context, tenantID string, objectType ObjectType) (map[string]PriorObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var latest *Snapshot
	for i := range s.snapshots {
		sn := &s.snapshots[i]
		if sn.TenantID != tenantID || sn.ObjectType != objectType || sn.Status != StatusComplete {
			continue
		}
		if latest == nil || sn.StartedAt.After(latest.StartedAt) {
			latest = sn
		}
	}

	result := map[string]PriorObject{}
	if latest == nil {
		return result, nil
	}
	for _, o := range latest.Objects {
		if o.ChangeKind == ChangeDisappeared {
			continue
		}
		result[o.GraphObjectID] = PriorObject{
			LastModifiedDateTime: o.LastModifiedDateTime,
			RawBody:              o.RawBody,
			RawAssignments:       o.RawAssignments,
		}
	}
	return result, nil
}

func (s *fakeStore) WriteSnapshot(ctx context.Context, snap Snapshot) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots = append(s.snapshots, snap)
	return fmt.Sprintf("%d", len(s.snapshots)), nil
}

// LatestCompletePair mirrors PostgresStore's query in memory: the two most
// recent complete snapshots for tenantID/objectType, newest first split into
// current/prior, with disappeared rows stripped (same exclusion
// PostgresStore applies at the SQL layer).
func (s *fakeStore) LatestCompletePair(ctx context.Context, tenantID string, objectType ObjectType) (Snapshot, Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var complete []Snapshot
	for _, sn := range s.snapshots {
		if sn.TenantID != tenantID || sn.ObjectType != objectType || sn.Status != StatusComplete {
			continue
		}
		complete = append(complete, sn)
	}
	if len(complete) < 2 {
		return Snapshot{}, Snapshot{}, false, nil
	}
	sort.Slice(complete, func(i, j int) bool { return complete[i].CompletedAt.After(complete[j].CompletedAt) })

	stripDisappeared := func(sn Snapshot) Snapshot {
		out := make([]ObjectRecord, 0, len(sn.Objects))
		for _, o := range sn.Objects {
			if o.ChangeKind == ChangeDisappeared {
				continue
			}
			out = append(out, o)
		}
		sn.Objects = out
		return sn
	}
	current, prior := stripDisappeared(complete[0]), stripDisappeared(complete[1])
	return prior, current, true, nil
}

func (s *fakeStore) latest() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshots[len(s.snapshots)-1]
}

func objectByID(objs []ObjectRecord, id string) (ObjectRecord, bool) {
	for _, o := range objs {
		if o.GraphObjectID == id {
			return o, true
		}
	}
	return ObjectRecord{}, false
}
