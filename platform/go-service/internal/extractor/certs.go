package extractor

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CertRow is one row from device_certificates as returned by ListCertificates.
type CertRow struct {
	DeviceID                    string
	SubjectCN                   string
	IssuerCN                    string
	SHA1                        string
	NotAfter                    time.Time
	DaysUntilExpiryAtCollection int
	CollectedAt                 time.Time
	EKU                         []string
	BasicConstraintsCA          bool
	IsSelfSigned                bool
	Store                       string // PAT-1738: "My"/"Root"/"CA" (Windows) or "System" (macOS)
}

// ListCertsFilter scopes a ListCertificates query. Zero values mean "no filter".
type ListCertsFilter struct {
	DeviceID           string // empty → all devices for the tenant
	ExpiringWithinDays int    // 0 → no expiry filter; > 0 → certs whose not_after < now() + N days
}

// buildListCertsQuery constructs the SQL and argument list for ListCertificates.
// Separated from the pool call so the query can be verified in unit tests
// without a live database connection.
func buildListCertsQuery(tenantID string, f ListCertsFilter) (string, []any) {
	q := `
		SELECT dc.device_id::text, dc.subject_cn, dc.issuer_cn, dc.sha1,
		       dc.not_after, dc.days_until_expiry_at_collection, dc.collected_at,
		       dc.ext_key_usage, dc.basic_constraints_ca, dc.is_self_signed, dc.store
		FROM device_certificates dc
		JOIN devices d ON d.id = dc.device_id
		WHERE d.tenant_id = $1::uuid`
	args := []any{tenantID}

	if f.DeviceID != "" {
		args = append(args, f.DeviceID)
		q += fmt.Sprintf("\n\t\tAND dc.device_id = $%d::uuid", len(args))
	}
	if f.ExpiringWithinDays > 0 {
		// Recompute the live value from not_after at query time — never use the
		// stored days_until_expiry_at_collection snapshot, which goes stale
		// between agent check-ins.
		args = append(args, f.ExpiringWithinDays)
		q += fmt.Sprintf("\n\t\tAND dc.not_after < now() + ($%d * INTERVAL '1 day')", len(args))
	}
	q += "\n\t\tORDER BY dc.not_after ASC"
	return q, args
}

// ListCertificates returns device_certificates rows for a tenant, optionally
// filtered by device and/or expiry window. The expiring-within-N-days filter
// recomputes from the live not_after timestamp — the stored
// days_until_expiry_at_collection column is for audit purposes only.
//
// Tenant isolation is enforced via a JOIN through devices.tenant_id, matching
// the pattern used by LoadRules / LoadRulesForTenant.
func ListCertificates(ctx context.Context, pool *pgxpool.Pool, tenantID string, f ListCertsFilter) ([]CertRow, error) {
	q, args := buildListCertsQuery(tenantID, f)
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []CertRow
	for rows.Next() {
		var r CertRow
		if err := rows.Scan(
			&r.DeviceID, &r.SubjectCN, &r.IssuerCN, &r.SHA1,
			&r.NotAfter, &r.DaysUntilExpiryAtCollection, &r.CollectedAt,
			&r.EKU, &r.BasicConstraintsCA, &r.IsSelfSigned, &r.Store,
		); err != nil {
			return nil, fmt.Errorf("scan cert row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cert rows: %w", err)
	}
	return out, nil
}
