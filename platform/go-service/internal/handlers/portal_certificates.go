package handlers

import (
	"bytes"
	"context"
	"crypto/sha1" // Existing certificate classification fingerprint, never an authentication primitive.
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/extractor"
)

const certificateMaxBytes = 64 << 10
const certificateJSONMaxBytes = 96 << 10

// Uploaded certificates carry no device or collection provenance. Only parsed
// metadata reaches this type, SQL, audit history or the response.
type uploadedCertificate struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Label       string    `json:"label"`
	SubjectCN   string    `json:"subject_cn"`
	IssuerCN    string    `json:"issuer_cn"`
	Fingerprint string    `json:"fingerprint_sha256"`
	SHA1        string    `json:"sha1"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	EKU         []string  `json:"ext_key_usage"`
	CA          bool      `json:"basic_constraints_ca"`
	SelfSigned  bool      `json:"is_self_signed"`
	Days        *int      `json:"days_until_expiry,omitempty"`
	Status      string    `json:"status,omitempty"`
}

// Avoid time.Duration saturation for certificates with dates centuries away.
// Floor (rather than integer truncation) keeps a just-expired cert negative.
func certificateExpiry(expiry, now time.Time) (*int, string) {
	if expiry.IsZero() {
		return nil, "unknown"
	}
	days := int(math.Floor(float64(expiry.Unix()-now.Unix())/86400 - float64(now.Nanosecond()-expiry.Nanosecond())/(86400*1e9)))
	status := "healthy"
	switch {
	case days < 0:
		status = "expired"
	case days <= 7:
		status = "critical"
	case days <= 30:
		status = "warning"
	}
	return &days, status
}

func parseUploadedCertificate(raw []byte) (uploadedCertificate, error) {
	var out uploadedCertificate
	invalid := errors.New("provide exactly one public X.509 certificate as PEM or DER")
	if len(raw) == 0 || len(raw) > certificateMaxBytes {
		return out, invalid
	}
	der := raw
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		// pem.Decode can skip arbitrary leading text or malformed PEM blocks.
		// Requiring a canonical header and a single canonical envelope prevents
		// it from silently skipping a private key or malformed earlier block.
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return out, invalid
		}
		if bytes.Count(trimmed, []byte("-----BEGIN")) != 1 {
			return out, invalid
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return out, invalid
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.NotAfter.Before(cert.NotBefore) || cert.NotAfter.IsZero() || cert.NotBefore.IsZero() {
		return out, invalid
	}
	sha := sha256.Sum256(cert.Raw)
	legacy := sha1.Sum(cert.Raw)
	out = uploadedCertificate{Source: "uploaded", SubjectCN: cert.Subject.CommonName, IssuerCN: cert.Issuer.CommonName,
		Fingerprint: hex.EncodeToString(sha[:]), SHA1: hex.EncodeToString(legacy[:]), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		EKU: []string{}, CA: cert.IsCA,
		SelfSigned: bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil}
	// Preserve actual OIDs (including unknown EKUs) for existing classification.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			var oids []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(ext.Value, &oids); err != nil || len(rest) != 0 {
				return uploadedCertificate{}, invalid
			}
			for _, oid := range oids {
				out.EKU = append(out.EKU, oid.String())
			}
		}
	}
	return out, nil
}

func certificateLabel(raw string) (string, bool) {
	if !utf8.ValidString(raw) {
		return "", false
	}
	// Check before trimming so controls at either end are rejected too.
	for _, c := range raw {
		if unicode.IsControl(c) {
			return "", false
		}
	}
	label := strings.TrimSpace(raw)
	return label, utf8.RuneCountInString(label) >= 1 && utf8.RuneCountInString(label) <= 200
}

const uploadedCertificateColumns = `id::text, label, subject_cn, issuer_cn, fingerprint_sha256, sha1, not_before, not_after, ext_key_usage, basic_constraints_ca, is_self_signed`

func scanUploadedCertificate(row pgx.Row) (uploadedCertificate, error) {
	c := uploadedCertificate{Source: "uploaded"}
	err := row.Scan(&c.ID, &c.Label, &c.SubjectCN, &c.IssuerCN, &c.Fingerprint, &c.SHA1, &c.NotBefore, &c.NotAfter, &c.EKU, &c.CA, &c.SelfSigned)
	c.NotBefore = c.NotBefore.UTC()
	c.NotAfter = c.NotAfter.UTC()
	return c, err
}

func listUploadedCertificates(ctx context.Context, pool *pgxpool.Pool, tenant string, f extractor.ListCertsFilter) ([]uploadedCertificate, error) {
	out := []uploadedCertificate{}
	if f.DeviceID != "" {
		return out, nil
	}
	q := `SELECT ` + uploadedCertificateColumns + ` FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid`
	args := []any{tenant}
	if f.ExpiringWithinDays > 0 {
		q += ` AND not_after < now() + ($2 * INTERVAL '1 day')`
		args = append(args, f.ExpiringWithinDays)
	}
	q += ` ORDER BY not_after,id`
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	for rows.Next() {
		c, err := scanUploadedCertificate(rows)
		if err != nil {
			return nil, err
		}
		c.Days, c.Status = certificateExpiry(c.NotAfter, now)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PortalCertificatesGetHandler merges customer metadata and genuine agent
// observations. Tenant identity comes exclusively from verified portal auth.
func PortalCertificatesGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		filter, ok := certificateFilter(w, r)
		if !ok {
			return
		}
		agent, err := extractor.ListCertificates(r.Context(), pool, id.TenantID, filter)
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		uploaded, err := listUploadedCertificates(r.Context(), pool, id.TenantID, filter)
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		out := make([]any, 0, len(agent)+len(uploaded))
		now := time.Now().UTC()
		for _, c := range agent {
			days, status := certificateExpiry(c.NotAfter, now)
			out = append(out, struct {
				certResp
				Source string `json:"source"`
				Days   *int   `json:"days_until_expiry"`
				Status string `json:"status"`
			}{certToResp(c), "agent", days, status})
		}
		for _, c := range uploaded {
			out = append(out, c)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// PortalCertificatesWriteHandler is mounted for POST, PATCH and DELETE only.
// Each operation locks the fresh role inside the transaction before writing.
func PortalCertificatesWriteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if !requirePortalAdmin(ctx, tx, w, id, "manage uploaded certificates", slog.Default()) {
			return
		}
		method := r.Method
		certID := chi.URLParam(r, "id")
		var before uploadedCertificate
		if method != http.MethodPost {
			if !looksLikeUUID(certID) {
				http.NotFound(w, r)
				return
			}
			before, err = scanUploadedCertificate(tx.QueryRow(ctx, `SELECT `+uploadedCertificateColumns+` FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE`, id.TenantID, certID))
			if errors.Is(err, pgx.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			if err != nil {
				http.Error(w, "internal error", 500)
				return
			}
		}
		after := before
		action := "delete"
		status := http.StatusOK
		if method != http.MethodDelete {
			body, ok := readLimitedBody(w, r, certificateJSONMaxBytes)
			if !ok {
				return
			}
			var req struct {
				Label       *string         `json:"label"`
				Certificate json.RawMessage `json:"certificate"`
			}
			// Unknown tenant fields are ignored, never used for scoping. Unmarshal
			// requires exactly one JSON value, preventing trailing payloads.
			if !utf8.Valid(body) || json.Unmarshal(body, &req) != nil {
				http.Error(w, "invalid JSON", 400)
				return
			}
			label := before.Label
			if req.Label != nil {
				label, ok = certificateLabel(*req.Label)
				if !ok {
					http.Error(w, "label must contain 1 to 200 characters and no controls", 400)
					return
				}
			} else if method == http.MethodPost {
				http.Error(w, "label is required", 400)
				return
			}
			hasCertificate := len(req.Certificate) > 0
			if hasCertificate {
				var raw []byte
				if json.Unmarshal(req.Certificate, &raw) != nil {
					http.Error(w, "certificate must be base64 encoded", 400)
					return
				}
				if len(raw) > certificateMaxBytes {
					http.Error(w, "certificate is too large", 413)
					return
				}
				after, err = parseUploadedCertificate(raw)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				after.ID = before.ID
			} else if method == http.MethodPost {
				http.Error(w, "certificate is required", 400)
				return
			}
			after.Label = label
			if method == http.MethodPost {
				action = "upload"
				status = http.StatusCreated
				err = tx.QueryRow(ctx, `INSERT INTO tenant_uploaded_certificates(tenant_id,label,subject_cn,issuer_cn,fingerprint_sha256,sha1,not_before,not_after,ext_key_usage,basic_constraints_ca,is_self_signed)
                    VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (tenant_id,fingerprint_sha256) DO NOTHING RETURNING id::text`,
					id.TenantID, after.Label, after.SubjectCN, after.IssuerCN, after.Fingerprint, after.SHA1, after.NotBefore, after.NotAfter, after.EKU, after.CA, after.SelfSigned).Scan(&after.ID)
				if errors.Is(err, pgx.ErrNoRows) {
					// A concurrent insert may win. A new READ COMMITTED statement
					// sees it; retain its label and do not invent a second audit.
					after, err = scanUploadedCertificate(tx.QueryRow(ctx, `SELECT `+uploadedCertificateColumns+` FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid AND fingerprint_sha256=$2 FOR SHARE`, id.TenantID, after.Fingerprint))
					action = ""
					status = http.StatusOK
				}
			} else {
				action = "update_label"
				if hasCertificate {
					action = "replace"
				}
				_, err = tx.Exec(ctx, `UPDATE tenant_uploaded_certificates SET label=$3,subject_cn=$4,issuer_cn=$5,fingerprint_sha256=$6,sha1=$7,not_before=$8,not_after=$9,ext_key_usage=$10,basic_constraints_ca=$11,is_self_signed=$12,updated_at=now() WHERE tenant_id=$1::uuid AND id=$2::uuid`,
					id.TenantID, after.ID, after.Label, after.SubjectCN, after.IssuerCN, after.Fingerprint, after.SHA1, after.NotBefore, after.NotAfter, after.EKU, after.CA, after.SelfSigned)
			}
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM tenant_uploaded_certificates WHERE tenant_id=$1::uuid AND id=$2::uuid`, id.TenantID, certID)
		}
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				http.Error(w, "certificate already exists", 409)
				return
			}
			http.Error(w, "internal error", 500)
			return
		}
		if action != "" {
			var oldJSON, newJSON []byte
			if method != http.MethodPost {
				oldJSON, _ = json.Marshal(before)
			}
			if method != http.MethodDelete {
				newJSON, _ = json.Marshal(after)
			}
			auditID := after.ID
			if method == http.MethodDelete {
				auditID = before.ID
			}
			_, err = tx.Exec(ctx, `INSERT INTO tenant_uploaded_certificate_audit(tenant_id,certificate_id,action,actor_email,old_metadata,new_metadata) VALUES($1::uuid,$2::uuid,$3,$4,$5::jsonb,$6::jsonb)`, id.TenantID, auditID, action, id.Email, oldJSON, newJSON)
			if err != nil {
				http.Error(w, "internal error", 500)
				return
			}
		}
		if err = tx.Commit(ctx); err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		if method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		after.Days, after.Status = certificateExpiry(after.NotAfter, time.Now().UTC())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(after)
	}
}
