package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/extractor"
)

// certResp is the per-certificate JSON response shape.
// Do not embed extractor.CertRow directly — explicit snake_case tags and
// RFC3339-formatted timestamps are required.
type certResp struct {
	DeviceID                    string   `json:"device_id"`
	SubjectCN                   string   `json:"subject_cn"`
	IssuerCN                    string   `json:"issuer_cn"`
	SHA1                        string   `json:"sha1"`
	NotAfter                    string   `json:"not_after"`
	DaysUntilExpiryAtCollection int      `json:"days_until_expiry_at_collection"`
	ExtKeyUsage                 []string `json:"ext_key_usage"`
	BasicConstraintsCA          bool     `json:"basic_constraints_ca"`
	IsSelfSigned                bool     `json:"is_self_signed"`
	CollectedAt                 string   `json:"collected_at"`
}

// certToResp maps one CertRow to the HTTP response shape.
// EKU nil → empty JSON array; timestamps are UTC RFC3339.
func certToResp(r extractor.CertRow) certResp {
	eku := r.EKU
	if eku == nil {
		eku = []string{}
	}
	return certResp{
		DeviceID:                    r.DeviceID,
		SubjectCN:                   r.SubjectCN,
		IssuerCN:                    r.IssuerCN,
		SHA1:                        r.SHA1,
		NotAfter:                    r.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiryAtCollection: r.DaysUntilExpiryAtCollection,
		ExtKeyUsage:                 eku,
		BasicConstraintsCA:          r.BasicConstraintsCA,
		IsSelfSigned:                r.IsSelfSigned,
		CollectedAt:                 r.CollectedAt.UTC().Format(time.RFC3339),
	}
}

// tenantCertsExistsFn reports whether a tenant row exists.
type tenantCertsExistsFn func(ctx context.Context, tenantID string) (bool, error)

// tenantCertsListFn fetches certificates for a tenant.
type tenantCertsListFn func(ctx context.Context, tenantID string, f extractor.ListCertsFilter) ([]extractor.CertRow, error)

// TenantCertsHandler returns GET /admin/tenant/{tenant_id}/certs.
// Symmetric to the tenant-rules and tenant-platforms admin handlers; all live
// on the internal Tailscale-bound listener behind the operator token middleware.
func TenantCertsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	existsFn := func(ctx context.Context, tenantID string) (bool, error) {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`,
			tenantID,
		).Scan(&exists)
		return exists, err
	}
	listFn := func(ctx context.Context, tenantID string, f extractor.ListCertsFilter) ([]extractor.CertRow, error) {
		return extractor.ListCertificates(ctx, pool, tenantID, f)
	}
	return newTenantCertsHandler(existsFn, listFn, func(ctx context.Context, tenantID string, f extractor.ListCertsFilter) ([]uploadedCertificate, error) {
		return listUploadedCertificates(ctx, pool, tenantID, f)
	})
}

// newTenantCertsHandler builds the handler with injectable DB functions.
// Separated from TenantCertsHandler so tests can pass mock implementations
// without a live database connection.
func newTenantCertsHandler(existsFn tenantCertsExistsFn, listFn tenantCertsListFn, uploads ...func(context.Context, string, extractor.ListCertsFilter) ([]uploadedCertificate, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_certs")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenant_id"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenant_id must be a UUID", http.StatusBadRequest)
			return
		}

		exists, err := existsFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("tenant existence check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		filter, ok := certificateFilter(w, r)
		if !ok {
			return
		}

		rows, err := listFn(r.Context(), tenantID, filter)
		if err != nil {
			logger.Error("list certificates failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := make([]any, len(rows))
		for i, row := range rows {
			resp[i] = certToResp(row)
		}

		if len(uploads) > 0 {
			uploaded, err := uploads[0](r.Context(), tenantID, filter)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, c := range uploaded {
				resp = append(resp, c)
			}
		}

		logger.Info("tenant certs listed", "tenant_id", tenantID, "count", len(resp))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// certificateFilter preserves the existing operator filter semantics.
func certificateFilter(w http.ResponseWriter, r *http.Request) (extractor.ListCertsFilter, bool) {
	var filter extractor.ListCertsFilter

	if rawDeviceID := strings.TrimSpace(r.URL.Query().Get("device_id")); rawDeviceID != "" {
		if !looksLikeUUID(rawDeviceID) {
			http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
			return filter, false
		}
		filter.DeviceID = rawDeviceID
	}

	if rawDays := strings.TrimSpace(r.URL.Query().Get("expiring_within_days")); rawDays != "" {
		days, parseErr := strconv.Atoi(rawDays)
		if parseErr != nil || days < 0 {
			http.Error(w, "expiring_within_days must be a non-negative integer", http.StatusBadRequest)
			return filter, false
		}
		filter.ExpiringWithinDays = days
	}

	return filter, true
}
