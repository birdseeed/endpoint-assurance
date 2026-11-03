package feedback

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrStaleFeedbackClaim = errors.New("feedback claim no longer owned")

type deliveryRecord struct {
	Submission
	ScreenshotAttempts int
}
type deliveryStore interface {
	load(context.Context, int64, int) (deliveryRecord, error)
	reserveUpload(context.Context, int64, int) (int, error)
	persistAsset(context.Context, int64, int, string) error
	uploadFailed(context.Context, int64, int, string) error
	complete(context.Context, int64, int, string, string, *string) error
}

func requireFeedbackClaim(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStaleFeedbackClaim
	}
	return nil
}
func claimReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleFeedbackClaim
	}
	return err
}

type postgresDeliveryStore struct{ pool *pgxpool.Pool }

func (s postgresDeliveryStore) load(ctx context.Context, id int64, attempt int) (deliveryRecord, error) {
	var d deliveryRecord
	var shot Screenshot
	err := s.pool.QueryRow(ctx, `SELECT reference,tenant_id::text,type,title,description,coalesce(severity,''),route,portal_build,tenant_display_slug,reporter_role,user_agent,created_at,screenshot,coalesce(screenshot_content_type,''),coalesce(screenshot_filename,''),coalesce(linear_asset_url,''),screenshot_attempts FROM feedback WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$2 AND lease_until>clock_timestamp()`, id, attempt).Scan(&d.Reference, &d.TenantID, &d.Type, &d.Title, &d.Description, &d.Severity, &d.Route, &d.PortalBuild, &d.TenantDisplaySlug, &d.ReporterRole, &d.BrowserUserAgent, &d.SubmittedAt, &shot.Bytes, &shot.ContentType, &shot.Filename, &d.ScreenshotAssetURL, &d.ScreenshotAttempts)
	if shot.Bytes != nil {
		d.Screenshot = &shot
	}
	return d, claimReadError(err)
}
func (s postgresDeliveryStore) reserveUpload(ctx context.Context, id int64, attempt int) (int, error) {
	var uploadAttempt int
	err := s.pool.QueryRow(ctx, `UPDATE feedback SET screenshot_attempts=screenshot_attempts+1,updated_at=clock_timestamp() WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$2 AND lease_until>clock_timestamp() AND linear_asset_url IS NULL AND screenshot IS NOT NULL AND screenshot_attempts<$3 RETURNING screenshot_attempts`, id, attempt, maxScreenshotAttempts).Scan(&uploadAttempt)
	return uploadAttempt, claimReadError(err)
}
func (s postgresDeliveryStore) persistAsset(ctx context.Context, id int64, attempt int, asset string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE feedback SET linear_asset_url=$3,updated_at=clock_timestamp() WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$2 AND lease_until>clock_timestamp()`, id, attempt, asset)
	return requireFeedbackClaim(tag, err)
}
func (s postgresDeliveryStore) uploadFailed(ctx context.Context, id int64, attempt int, msg string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE feedback SET last_error=left($3,1000),updated_at=clock_timestamp() WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$2 AND lease_until>clock_timestamp()`, id, attempt, msg)
	return requireFeedbackClaim(tag, err)
}
func (s postgresDeliveryStore) complete(ctx context.Context, id int64, attempt int, issue, key string, state *string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE feedback SET sync_state='synced',linear_state=$4,linear_issue_id=$2,linear_issue_identifier=$3,synced_at=clock_timestamp(),lease_until=NULL,
 last_error=CASE WHEN linear_asset_url IS NULL AND screenshot IS NOT NULL THEN last_error ELSE NULL END,
 screenshot=CASE WHEN linear_asset_url IS NOT NULL THEN NULL ELSE screenshot END,
 screenshot_content_type=CASE WHEN linear_asset_url IS NOT NULL THEN NULL ELSE screenshot_content_type END,
 screenshot_filename=CASE WHEN linear_asset_url IS NOT NULL THEN NULL ELSE screenshot_filename END,
 updated_at=clock_timestamp() WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$5 AND lease_until>clock_timestamp()`, id, issue, key, state, attempt)
	return requireFeedbackClaim(tag, err)
}

// Deliver makes upload ordering and recovery explicit. Persisted asset URLs are
// reused after a crash; blobs are only cleared by successful issue persistence.
func deliverFeedback(ctx context.Context, store deliveryStore, client *LinearClient, id int64, attempt int) error {
	d, err := store.load(ctx, id, attempt)
	if err != nil {
		return err
	}
	if d.ScreenshotAssetURL != "" && !validScreenshotAssetURL(d.ScreenshotAssetURL) {
		return fmt.Errorf("invalid persisted screenshot asset URL")
	}
	if d.Screenshot != nil && d.ScreenshotAssetURL == "" {
		if d.ScreenshotAttempts < maxScreenshotAttempts {
			uploadAttempt, err := store.reserveUpload(ctx, id, attempt)
			if err != nil {
				return err
			}
			asset, uploadErr := client.uploadScreenshot(ctx, d.Screenshot)
			if uploadErr == nil {
				if err := store.persistAsset(ctx, id, attempt, asset); err != nil {
					return err
				}
				d.ScreenshotAssetURL = asset
			} else {
				if err := store.uploadFailed(ctx, id, attempt, uploadErr.Error()); err != nil {
					return err
				}
				if uploadAttempt < maxScreenshotAttempts {
					return uploadErr
				}
				d.ScreenshotUploadFailed = true
			}
		} else {
			d.ScreenshotUploadFailed = true
		}
	}
	issue, key, state, err := client.createWithState(ctx, d.Submission)
	if err != nil {
		return err
	}
	return store.complete(ctx, id, attempt, issue, key, state)
}
