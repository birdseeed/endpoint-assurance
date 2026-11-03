package extractor

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ProcessOnce claims all currently-pending raw_payloads rows, processes each
// one synchronously, and returns when the queue is empty.
//
// Extraction errors for individual rows are recorded in raw_payloads.extraction_error
// but do not stop the batch.  Hard DB errors (claim or commit failures) are
// returned immediately.
//
// Intended for integration tests that need to drain the ingest queue before
// reading back results through the admin endpoints.  Production code uses
// Worker.Run.
func ProcessOnce(ctx context.Context, pool *pgxpool.Pool) error {
	w := &Worker{Pool: pool, BatchSize: 1000}
	logger := slog.Default()
	for {
		batch, err := w.claimBatch(ctx)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, row := range batch {
			rowLogger := logger.With("raw_payload_id", row.ID, "tenant_id", row.TenantID)
			if procErr := w.processRow(ctx, row, rowLogger); procErr != nil {
				rowLogger.Warn("extraction failed", "err", procErr)
				_ = w.markFailed(ctx, row, procErr)
			}
		}
	}
}
