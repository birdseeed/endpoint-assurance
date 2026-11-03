package platformroot

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UpsertRootCertificates writes RootCert records to platform_root_certificates,
// idempotent on the (thumbprint_sha1, platform) primary key. fetched_at (and
// source/source_url/subject_cn) are refreshed on every run even when the
// thumbprint already exists, per PAT-1738's "source and date recorded on
// every run" requirement — this is what makes staleness detectable. Mirrors
// internal/oscve.UpsertAdvisories' batched-upsert shape.
func UpsertRootCertificates(ctx context.Context, pool *pgxpool.Pool, certs []RootCert) (int, error) {
	const batchSize = 500
	total := 0
	for i := 0; i < len(certs); i += batchSize {
		end := i + batchSize
		if end > len(certs) {
			end = len(certs)
		}
		batch := &pgx.Batch{}
		for _, c := range certs[i:end] {
			batch.Queue(`
				INSERT INTO platform_root_certificates
					(thumbprint_sha1, platform, source, source_url, fetched_at, subject_cn)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (thumbprint_sha1, platform) DO UPDATE SET
					source     = EXCLUDED.source,
					source_url = EXCLUDED.source_url,
					fetched_at = EXCLUDED.fetched_at,
					subject_cn = EXCLUDED.subject_cn
			`, c.ThumbprintSHA1, c.Platform, c.Source, c.SourceURL, c.FetchedAt, c.SubjectCN)
		}
		br := pool.SendBatch(ctx, batch)
		for j := 0; j < batch.Len(); j++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return total, fmt.Errorf("upsert platform root cert at offset %d: %w", i+j, err)
			}
		}
		if err := br.Close(); err != nil {
			return total, fmt.Errorf("batch close at offset %d: %w", i, err)
		}
		total += batch.Len()
	}
	return total, nil
}
