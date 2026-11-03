//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestPAT2389ConcurrentDuplicateUpload(t *testing.T) {
	at := newApprovalTenant(t, "cert-race", false)
	der, _, _ := pat2389Fixture(t, "race.example", 40)
	body := pat2389Body(t, map[string]any{"label": "One certificate", "certificate": der})
	type result struct {
		status int
		body   []byte
		err    error
	}
	const clients = 8
	results := make(chan result, clients)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+pat2389Path, strings.NewReader(body))
			if err != nil {
				results <- result{err: err}
				return
			}
			req.Header.Set("Cf-Access-Jwt-Assertion", at.adminToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			results <- result{resp.StatusCode, raw, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	created := 0
	certID := ""
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.status != http.StatusOK && result.status != http.StatusCreated {
			t.Fatalf("concurrent upload %d: %s", result.status, result.body)
		}
		if result.status == http.StatusCreated {
			created++
		}
		var got pat2389Cert
		if err := json.Unmarshal(result.body, &got); err != nil {
			t.Fatal(err)
		}
		if certID != "" && got.ID != certID {
			t.Fatalf("duplicate ids %s / %s", certID, got.ID)
		}
		certID = got.ID
	}
	if created != 1 {
		t.Fatalf("created=%d", created)
	}
	var audits int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenant_uploaded_certificate_audit WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("duplicate upload audits=%d", audits)
	}
}

func TestPAT2389ReplacementCollisionIsAtomic(t *testing.T) {
	at := newApprovalTenant(t, "cert-collision", false)
	derA, _, _ := pat2389Fixture(t, "a.example", 40)
	derB, _, _ := pat2389Fixture(t, "b.example", 50)
	a := pat2389Upload(t, at, derA, "A", http.StatusCreated)
	pat2389Upload(t, at, derB, "B", http.StatusCreated)
	pat2389Write(t, http.MethodPatch, pat2389Path+"/"+a.ID, at.adminToken, map[string]any{"label": "Changed", "certificate": derB}, http.StatusConflict)
	rows := pat2389List(t, at.adminToken, "")
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", rows)
	}
	for _, row := range rows {
		if row.ID == a.ID && (row.Label != "A" || row.Fingerprint != a.Fingerprint) {
			t.Fatalf("collision partially applied: %+v", row)
		}
	}
	var audits int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenant_uploaded_certificate_audit WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 2 {
		t.Fatalf("failed replacement wrote audit: %d", audits)
	}
}
