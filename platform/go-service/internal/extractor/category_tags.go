package extractor

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/categorytag"
)

// categoryTagEvaluator is a variable so the savepoint guard can be tested
// with an evaluator that fails inside the ingest transaction.
var categoryTagEvaluator = categorytag.EvaluateDevice

// evaluateCategoryTags applies the published category rules (PAT-2015) to
// this device's apps and browser extensions. It runs in the ingest
// transaction under a savepoint, the same guard PAT-2024 gave the CVE queue:
// a failure rolls back only the tag writes, is logged, and never fails or
// aborts the extraction. Tags missed that way are written by the device's
// next ingest or by POST /admin/software-categories/backfill.
func evaluateCategoryTags(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, logger *slog.Logger) {
	var res categorytag.Result
	err := withSavepoint(ctx, tx, func(sp pgx.Tx) error {
		var err error
		res, err = categoryTagEvaluator(ctx, sp, tenantID, deviceID)
		return err
	})
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("category tag evaluation failed; this device's tags will catch up on its next ingest or a backfill",
			"device_id", deviceID, "err", err)
		return
	}
	if res.Tagged > 0 || res.Retired > 0 {
		logger.Info("category tags reconciled", "device_id", deviceID, "tagged", res.Tagged, "retired", res.Retired)
	}
}
