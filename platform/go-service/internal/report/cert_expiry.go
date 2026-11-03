package report

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/platformroot"
)

// ExpiryCert holds one certificate approaching expiry.
type ExpiryCert struct {
	SubjectCN string
	IssuerCN  string
	SHA1      string
	Hostname  string
	NotAfter  time.Time
	DaysUntil int
}

// CertExpiryReport contains certs expiring within 90 days for a tenant.
type CertExpiryReport struct {
	GeneratedAt time.Time
	Tenant      string

	// Certs is the actionable expiry finding set: certificates the tenant
	// can and should do something about. Platform-root certificates and
	// suspicious (unclassified but platform-named) certificates are
	// deliberately excluded here — see PlatformRootCerts / SuspiciousCerts
	// below — because flooding every assessment with expired-but-legitimate
	// platform roots (the Windows staging VM's Root store alone holds 27,
	// 8 already expired) drowns the findings nobody can act on.
	Certs         []ExpiryCert
	ExpiredCount  int
	CriticalCount int
	WarningCount  int

	// PlatformRootCerts (PAT-1738) lists certificates expiring within the
	// same 90-day window whose SHA-1 thumbprint matched a known Microsoft or
	// Apple platform-root certificate (platform_root_certificates). Listed
	// separately, not dropped from the report entirely — a platform root can
	// still expire and matter operationally, it is just not an actionable
	// finding for the tenant.
	PlatformRootCerts []ExpiryCert

	// SuspiciousCerts (PAT-1738) lists certificates whose subject text looks
	// like a platform root (contains "Microsoft"/"Windows" on a Windows
	// device, or "Apple" on a macOS device) but whose thumbprint did not
	// match platform_root_certificates. This is a distinct flag, not an
	// expiry finding — the certificate may not be anywhere near expiry — and
	// is never folded into Certs/PlatformRootCerts.
	SuspiciousCerts []ExpiryCert
}

// FetchCertExpiryReport fetches certificates expiring within 90 days,
// classified against the known platform-root thumbprint list (PAT-1738).
func FetchCertExpiryReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (CertExpiryReport, error) {
	var r CertExpiryReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	// is_platform_root and is_suspicious are computed live via the LEFT JOIN
	// below, never stored on device_certificates (PAT-1738) — a
	// platform_root_certificates refresh reclassifies every row on the very
	// next read, with no backfill step. The suspicious regexes come from
	// internal/platformroot so this query and the Windows-filter substrings
	// PAT-1737 removed never drift apart.
	rows, err := pool.Query(ctx, `
		SELECT dc.subject_cn, dc.issuer_cn, dc.sha1, COALESCE(d.hostname,'—'),
		       dc.not_after, dc.days_until_expiry_at_collection,
		       (prc.thumbprint_sha1 IS NOT NULL) AS is_platform_root,
		       (prc.thumbprint_sha1 IS NULL AND (
		           (d.os = 'Windows' AND dc.subject_cn ~* $2)
		           OR (d.os = 'macOS' AND dc.subject_cn ~* $3)
		       )) AS is_suspicious
		FROM device_certificates dc
		JOIN devices d ON d.id = dc.device_id
		LEFT JOIN platform_root_certificates prc
		       ON prc.thumbprint_sha1 = dc.sha1
		      AND prc.platform = CASE d.os WHEN 'Windows' THEN 'windows' WHEN 'macOS' THEN 'macos' END
		WHERE d.tenant_id = $1
		  AND dc.not_after < now() + interval '90 days'
		ORDER BY dc.not_after
	`, tenantID,
		platformroot.SuspiciousSubjectRegexOrNoMatch(platformroot.PlatformWindows),
		platformroot.SuspiciousSubjectRegexOrNoMatch(platformroot.PlatformMacOS),
	)
	if err != nil {
		return r, fmt.Errorf("fetch cert expiry: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c ExpiryCert
		var isPlatformRoot, isSuspicious bool
		if err := rows.Scan(&c.SubjectCN, &c.IssuerCN, &c.SHA1, &c.Hostname, &c.NotAfter, &c.DaysUntil,
			&isPlatformRoot, &isSuspicious); err != nil {
			return r, fmt.Errorf("scan cert: %w", err)
		}
		switch {
		case isPlatformRoot:
			r.PlatformRootCerts = append(r.PlatformRootCerts, c)
		case isSuspicious:
			r.SuspiciousCerts = append(r.SuspiciousCerts, c)
		default:
			r.Certs = append(r.Certs, c)
		}
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	now := time.Now().UTC()
	for _, c := range r.Certs {
		switch {
		case c.NotAfter.Before(now):
			r.ExpiredCount++
		case time.Until(c.NotAfter) <= 7*24*time.Hour:
			r.CriticalCount++
		case time.Until(c.NotAfter) <= 30*24*time.Hour:
			r.WarningCount++
		}
	}

	return r, nil
}
