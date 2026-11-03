//go:build integration

package integration

// PAT-2389 accepts public certificates only. These cases exercise HTTP,
// verified portal identity and PostgreSQL rather than a future handler stub.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const pat2389Path = "/v1/portal/certificates"

type pat2389Cert struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Label       string    `json:"label"`
	DeviceID    *string   `json:"device_id"`
	SubjectCN   string    `json:"subject_cn"`
	IssuerCN    string    `json:"issuer_cn"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Days        *int      `json:"days_until_expiry"`
	Status      string    `json:"status"`
}

func pat2389Fixture(t *testing.T, name string, days int) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Half a day avoids a countdown boundary crossing during a test.
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second), NotAfter: time.Now().UTC().Add(time.Duration(days)*24*time.Hour + 12*time.Hour).Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), cert
}

func pat2389Body(t *testing.T, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pat2389Write(t *testing.T, method, path, token string, fields map[string]any, want int) []byte {
	t.Helper()
	body := ""
	if fields != nil {
		body = pat2389Body(t, fields)
	}
	status, b := portalCall(t, method, path, token, body)
	if status != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, b)
	}
	return b
}

func pat2389Upload(t *testing.T, at *approvalTenant, data []byte, label string, want int) pat2389Cert {
	t.Helper()
	var out pat2389Cert
	mustJSON(t, pat2389Write(t, http.MethodPost, pat2389Path, at.adminToken, map[string]any{"certificate": data, "label": label}, want), &out)
	if out.ID == "" || out.Source != "uploaded" || (out.DeviceID != nil && *out.DeviceID != "") {
		t.Fatalf("manual source must have its own id and no synthetic device: %+v", out)
	}
	return out
}

func pat2389List(t *testing.T, token, query string) []pat2389Cert {
	t.Helper()
	var out []pat2389Cert
	mustJSON(t, pat2389Write(t, http.MethodGet, pat2389Path+query, token, nil, http.StatusOK), &out)
	return out
}

func TestPAT2389UploadParsingAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		days   int
		status string
		pem    bool
	}{{"expired", -2, "expired", true}, {"critical-zero", 0, "critical", false}, {"critical-seven", 7, "critical", true}, {"warning-eight", 8, "warning", false}, {"warning-thirty", 30, "warning", true}, {"healthy", 31, "healthy", false}} {
		t.Run(tc.name, func(t *testing.T) {
			at := newApprovalTenant(t, "cert-"+tc.name, false)
			der, _, cert := pat2389Fixture(t, tc.name+".example", tc.days)
			raw := der
			if tc.pem {
				raw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			}
			got := pat2389Upload(t, at, raw, "  Example certificate  ", http.StatusCreated)
			fingerprint := sha256.Sum256(der)
			if got.Label != "Example certificate" || got.SubjectCN != cert.Subject.CommonName || got.IssuerCN != cert.Issuer.CommonName || !got.NotBefore.Equal(cert.NotBefore) || !got.NotAfter.Equal(cert.NotAfter) || got.Fingerprint != hex.EncodeToString(fingerprint[:]) {
				t.Fatalf("metadata extraction: %+v", got)
			}
			if got.Days == nil || *got.Days != tc.days || got.Status != tc.status {
				t.Fatalf("current expiry: %+v, want days=%d status=%s", got, tc.days, tc.status)
			}
			rows := pat2389List(t, at.viewerToken, "")
			if len(rows) != 1 || rows[0].ID != got.ID || rows[0].Status != tc.status {
				t.Fatalf("viewer read-back: %+v", rows)
			}
		})
	}
}

func TestPAT2389RBACAndFreshDemotion(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			at := newApprovalTenant(t, "cert-role", false)
			der, _, _ := pat2389Fixture(t, "role.example", 50)
			existing := pat2389Upload(t, at, der, "Role original", http.StatusCreated)
			path := pat2389Path
			fields := map[string]any{"certificate": der, "label": "Role test"}
			if method != http.MethodPost {
				path += "/" + existing.ID
			}
			pat2389Write(t, method, path, at.viewerToken, fields, http.StatusForbidden)
			if _, err := env.pool.Exec(context.Background(), `UPDATE portal_users SET role='viewer' WHERE email=$1`, at.adminEmail); err != nil {
				t.Fatal(err)
			}
			// Use the already issued JWT: the database role must be re-read.
			pat2389Write(t, method, path, at.adminToken, fields, http.StatusForbidden)
			if rows := pat2389List(t, at.viewerToken, ""); len(rows) != 1 || rows[0].Label != "Role original" {
				t.Fatalf("forbidden mutation changed rows: %+v", rows)
			}
		})
	}
}

func TestPAT2389TenantIsolation(t *testing.T) {
	a := newApprovalTenant(t, "cert-a", false)
	b := newApprovalTenant(t, "cert-b", false)
	der, _, _ := pat2389Fixture(t, "isolation.example", 40)
	own := pat2389Upload(t, b, der, "B private metadata", http.StatusCreated)
	rows := pat2389List(t, a.adminToken, "?tenant_id="+b.tenantID)
	if len(rows) != 0 {
		t.Fatalf("tenant query overrides verified identity: %+v", rows)
	}
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		pat2389Write(t, method, pat2389Path+"/"+own.ID, a.adminToken, map[string]any{"label": "Tampered", "certificate": der, "tenant_id": b.tenantID}, http.StatusNotFound)
	}
	// Identical public certificate in A cannot resolve to B's metadata/id.
	raw := pat2389Write(t, http.MethodPost, pat2389Path, a.adminToken, map[string]any{"certificate": der, "label": "A certificate", "tenant_id": b.tenantID}, http.StatusCreated)
	var created pat2389Cert
	mustJSON(t, raw, &created)
	if created.ID == own.ID {
		t.Fatal("deduplication crosses tenant boundary")
	}
	if rows = pat2389List(t, b.viewerToken, ""); len(rows) != 1 || rows[0].Label != "B private metadata" {
		t.Fatalf("B changed: %+v", rows)
	}
}

func TestPAT2389RejectUnsafeInputWithoutWrite(t *testing.T) {
	for _, name := range []string{"invalid", "private-key", "mixed-key", "trailing-pem", "trailing-der", "raw-oversize", "json-oversize", "blank-label", "long-label", "control-label"} {
		t.Run(name, func(t *testing.T) {
			at := newApprovalTenant(t, "cert-invalid", false)
			der, key, _ := pat2389Fixture(t, "invalid.example", 50)
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			fields := map[string]any{"certificate": der, "label": "Valid label"}
			switch name {
			case "invalid":
				fields["certificate"] = []byte("not a certificate")
			case "private-key":
				fields["certificate"] = key
			case "mixed-key":
				fields["certificate"] = append(certPEM, key...)
			case "trailing-pem":
				fields["certificate"] = append(certPEM, []byte("unexpected trailing bytes")...)
			case "trailing-der":
				fields["certificate"] = append(der, 1)
			case "raw-oversize":
				fields["certificate"] = append(certPEM, []byte(strings.Repeat(" ", 64*1024))...)
			case "json-oversize":
				fields["padding"] = strings.Repeat(" ", 96*1024)
			case "blank-label":
				fields["label"] = "  "
			case "long-label":
				fields["label"] = strings.Repeat("界", 201)
			case "control-label":
				fields["label"] = "Certificate\nspoof"
			}
			code, body := portalCall(t, http.MethodPost, pat2389Path, at.adminToken, pat2389Body(t, fields))
			if code != http.StatusBadRequest && code != http.StatusRequestEntityTooLarge {
				t.Fatalf("unsafe %s = %d, want 400/413: %s", name, code, body)
			}
			if rows := pat2389List(t, at.adminToken, ""); len(rows) != 0 {
				t.Fatalf("unsafe upload persisted record: %+v", rows)
			}
			var saved int
			if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			if saved != 0 {
				t.Fatalf("unsafe upload saved %d metadata records", saved)
			}
		})
	}
}

func TestPAT2389DedupeReplaceAndRemove(t *testing.T) {
	at := newApprovalTenant(t, "cert-lifecycle", false)
	der, _, _ := pat2389Fixture(t, "before.example", 40)
	first := pat2389Upload(t, at, der, "First", http.StatusCreated)
	duplicate := pat2389Upload(t, at, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "Duplicate", http.StatusOK)
	if first.ID != duplicate.ID || len(pat2389List(t, at.adminToken, "")) != 1 {
		t.Fatal("PEM/DER duplicate creates another record")
	}
	var edited pat2389Cert
	mustJSON(t, pat2389Write(t, http.MethodPatch, pat2389Path+"/"+first.ID, at.adminToken, map[string]any{"label": strings.Repeat("界", 200)}, http.StatusOK), &edited)
	if edited.ID != first.ID || edited.Fingerprint != first.Fingerprint || edited.Label != strings.Repeat("界", 200) {
		t.Fatalf("label edit: %+v", edited)
	}
	replacement, _, cert := pat2389Fixture(t, "after.example", 3)
	mustJSON(t, pat2389Write(t, http.MethodPatch, pat2389Path+"/"+first.ID, at.adminToken, map[string]any{"label": "Renewed", "certificate": replacement}, http.StatusOK), &edited)
	if edited.ID != first.ID || edited.SubjectCN != cert.Subject.CommonName || edited.Fingerprint == first.Fingerprint || edited.Status != "critical" {
		t.Fatalf("replacement: %+v", edited)
	}
	pat2389Write(t, http.MethodPatch, pat2389Path+"/"+first.ID, at.adminToken, map[string]any{"label": "Broken replacement", "certificate": []byte("invalid")}, http.StatusBadRequest)
	if rows := pat2389List(t, at.adminToken, ""); len(rows) != 1 || rows[0].Label != "Renewed" || rows[0].Fingerprint != edited.Fingerprint {
		t.Fatalf("invalid replacement partially applied: %+v", rows)
	}
	pat2389Write(t, http.MethodDelete, pat2389Path+"/"+first.ID, at.adminToken, nil, http.StatusNoContent)
	if rows := pat2389List(t, at.adminToken, ""); len(rows) != 0 {
		t.Fatalf("deleted certificate visible: %+v", rows)
	}
	pat2389Write(t, http.MethodDelete, pat2389Path+"/"+first.ID, at.adminToken, nil, http.StatusNotFound)
}

func TestPAT2389AgentCompatibility(t *testing.T) {
	at := newApprovalTenant(t, "cert-agent", false)
	device := seedSelfServiceDevice(t, at.tenantID, "certificate-device", "cert-"+randomHex(4), "macOS", time.Now())
	if _, err := env.pool.Exec(context.Background(), `INSERT INTO device_certificates(device_id,subject_cn,issuer_cn,sha1,not_after,days_until_expiry_at_collection) VALUES($1::uuid,'agent.example','Agent issuer','0123456789012345678901234567890123456789',$2,999)`, device, time.Now().Add(3*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	der, _, _ := pat2389Fixture(t, "manual.example", 40)
	manual := pat2389Upload(t, at, der, "Manual", http.StatusCreated)
	for _, query := range []string{"", "?device_id=" + device} {
		resp, err := http.Get(fmt.Sprintf("%s/admin/tenant/%s/certs%s", env.internalSrv.URL, at.tenantID, query))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("admin certs = %d: %s", resp.StatusCode, raw)
		}
		var rows []map[string]any
		mustJSON(t, raw, &rows)
		want := 2
		if query != "" {
			want = 1
		}
		if len(rows) != want {
			t.Fatalf("admin %s rows=%+v, want %d", query, rows, want)
		}
		agent, uploaded := false, false
		for _, row := range rows {
			if row["device_id"] == device {
				agent = true
				if row["subject_cn"] != "agent.example" || row["sha1"] != "0123456789012345678901234567890123456789" || row["days_until_expiry_at_collection"] != float64(999) {
					t.Fatalf("legacy agent shape changed: %+v", row)
				}
			}
			if row["id"] == manual.ID && row["source"] == "uploaded" {
				uploaded = true
			}
		}
		if !agent || (query == "" && !uploaded) || (query != "" && uploaded) {
			t.Fatalf("source/filter compatibility: %+v", rows)
		}
	}
	rows := pat2389List(t, at.viewerToken, "")
	if len(rows) != 2 {
		t.Fatalf("portal omits agent/manual source: %+v", rows)
	}
	// Agent rows are observations, not editable upload records.
	var agentID string
	if err := env.pool.QueryRow(context.Background(), `SELECT id::text FROM device_certificates WHERE device_id=$1::uuid`, device).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		pat2389Write(t, method, pat2389Path+"/"+agentID, at.adminToken, map[string]any{"label": "Agent mutation"}, http.StatusNotFound)
	}
}

// The audit keeps actor and metadata evidence after a removal. Raw certificate
// and private-key material must never become a persisted upload/audit payload.
func TestPAT2389AuditAndMetadataOnlyStorage(t *testing.T) {
	at := newApprovalTenant(t, "cert-audit", false)
	der, _, _ := pat2389Fixture(t, "audit-before.example", 40)
	cert := pat2389Upload(t, at, der, "Audit first", http.StatusCreated)
	var metadata []byte
	if err := env.pool.QueryRow(context.Background(), `SELECT to_jsonb(c)::text FROM tenant_uploaded_certificates c WHERE tenant_id=$1::uuid AND id=$2::uuid`, at.tenantID, cert.ID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	pat2389AssertNoPayload(t, metadata, der)
	pat2389Write(t, http.MethodPatch, pat2389Path+"/"+cert.ID, at.adminToken, map[string]any{"label": "Audit edited"}, http.StatusOK)
	replacement, _, _ := pat2389Fixture(t, "audit-after.example", 50)
	pat2389Write(t, http.MethodPatch, pat2389Path+"/"+cert.ID, at.adminToken, map[string]any{"label": "Audit replaced", "certificate": replacement}, http.StatusOK)
	pat2389Write(t, http.MethodDelete, pat2389Path+"/"+cert.ID, at.adminToken, nil, http.StatusNoContent)
	rows, err := env.pool.Query(context.Background(), `SELECT action, actor_email, created_at FROM tenant_uploaded_certificate_audit WHERE tenant_id=$1::uuid AND certificate_id=$2::uuid`, at.tenantID, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for rows.Next() {
		var action, email string
		var timestamp time.Time
		if err := rows.Scan(&action, &email, &timestamp); err != nil {
			t.Fatal(err)
		}
		if email != at.adminEmail {
			t.Fatalf("unverified audit actor %q", email)
		}
		if timestamp.IsZero() || timestamp.After(time.Now().Add(time.Minute)) || timestamp.Before(time.Now().Add(-5*time.Minute)) {
			t.Fatalf("invalid audit timestamp %v", timestamp)
		}
		actions[action]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"upload", "update_label", "replace", "delete"} {
		if actions[action] != 1 {
			t.Fatalf("audit action %s count=%d; all=%v", action, actions[action], actions)
		}
	}
	var count int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("deleted upload still stored: %d", count)
	}
	// Inspect actual persisted row JSON, so bytea/base64/text payload retention
	// is caught even if a future column has an unexpected name.
	var persisted []byte
	if err := env.pool.QueryRow(context.Background(), `SELECT coalesce(jsonb_agg(to_jsonb(a)),'[]'::jsonb)::text FROM tenant_uploaded_certificate_audit a WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	pat2389AssertNoPayload(t, persisted, der, replacement)
	// Synthetic tenant deletion checks the new tables' FK lifecycle directly,
	// without exercising or changing the separately held purge implementation.
	if _, err := env.pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, at.tenantID); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenant_uploaded_certificate_audit WHERE tenant_id=$1::uuid`, at.tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("audit escaped tenant FK cascade: %d", count)
	}
}

func pat2389AssertNoPayload(t *testing.T, persisted []byte, raws ...[]byte) {
	t.Helper()
	for _, raw := range raws {
		encoded, _ := json.Marshal(raw)
		if bytes.Contains(persisted, encoded[1:len(encoded)-1]) || bytes.Contains(persisted, []byte(hex.EncodeToString(raw))) || bytes.Contains(persisted, []byte("BEGIN CERTIFICATE")) || bytes.Contains(persisted, []byte("PRIVATE KEY")) {
			t.Fatal("raw certificate/key payload retained")
		}
	}
}
