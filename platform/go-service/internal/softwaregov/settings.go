package softwaregov

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Defaults, ruled by the owner on 2026-09-24: the unapproved software alert
// is on for every tenant unless turned off, the new software notification is
// off unless turned on.
const (
	DefaultUnapprovedAlertsEnabled       = true
	DefaultNewSoftwareEnabled            = false
	DefaultAIToolingNotificationsEnabled = false
)

// Settings is a tenant's notification settings. IsDefault is true when the
// tenant has never saved them, so the values are the defaults above.
type Settings struct {
	UnapprovedAlertsEnabled       bool       `json:"unapproved_alerts_enabled"`
	NewSoftwareEnabled            bool       `json:"new_software_enabled"`
	AIToolingNotificationsEnabled bool       `json:"ai_tooling_notifications_enabled"`
	IsDefault                     bool       `json:"is_default"`
	UpdatedAt                     *time.Time `json:"updated_at"`
	UpdatedBy                     *string    `json:"updated_by"`
}

// SettingsUpdate changes only the fields that are set.
type SettingsUpdate struct {
	UnapprovedAlertsEnabled       *bool `json:"unapproved_alerts_enabled"`
	NewSoftwareEnabled            *bool `json:"new_software_enabled"`
	AIToolingNotificationsEnabled *bool `json:"ai_tooling_notifications_enabled"`
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// GetSettings reads a tenant's settings, falling back to the defaults.
func GetSettings(ctx context.Context, q Querier, tenantID string) (Settings, error) {
	s := Settings{UnapprovedAlertsEnabled: DefaultUnapprovedAlertsEnabled, NewSoftwareEnabled: DefaultNewSoftwareEnabled,
		AIToolingNotificationsEnabled: DefaultAIToolingNotificationsEnabled, IsDefault: true}
	var updatedAt time.Time
	var updatedBy *string
	err := q.QueryRow(ctx, `
		SELECT unapproved_alerts_enabled, new_software_enabled, ai_tooling_notifications_enabled, updated_at, updated_by
		FROM tenant_software_notification_settings
		WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&s.UnapprovedAlertsEnabled, &s.NewSoftwareEnabled, &s.AIToolingNotificationsEnabled, &updatedAt, &updatedBy)
	if isNoRows(err) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read software notification settings: %w", err)
	}
	// A row the runner created only to hold its cursors has no updated_by:
	// the values in it are still the defaults it was created with.
	s.IsDefault = updatedBy == nil
	if updatedBy != nil {
		u := updatedAt.UTC()
		s.UpdatedAt, s.UpdatedBy = &u, updatedBy
	}
	return s, nil
}

// PutSettings applies an update. actor is the verified portal email or
// "operator".
func PutSettings(ctx context.Context, q Querier, tenantID string, upd SettingsUpdate, actor string) (Settings, error) {
	actor = strings.ToLower(strings.TrimSpace(actor))
	if actor == "" {
		return Settings{}, errors.New("softwaregov: settings update needs an actor")
	}
	cur, err := GetSettings(ctx, q, tenantID)
	if err != nil {
		return cur, err
	}
	if upd.UnapprovedAlertsEnabled != nil {
		cur.UnapprovedAlertsEnabled = *upd.UnapprovedAlertsEnabled
	}
	if upd.NewSoftwareEnabled != nil {
		cur.NewSoftwareEnabled = *upd.NewSoftwareEnabled
	}
	auditAI := upd.AIToolingNotificationsEnabled != nil
	if auditAI {
		cur.AIToolingNotificationsEnabled = *upd.AIToolingNotificationsEnabled
	}
	if _, err := q.Exec(ctx, `
		WITH previous AS MATERIALIZED (
		    SELECT COALESCE((SELECT ai_tooling_notifications_enabled
		                     FROM tenant_software_notification_settings WHERE tenant_id=$1::uuid), $5) AS old_enabled
		), saved AS (
		    INSERT INTO tenant_software_notification_settings
		        (tenant_id, unapproved_alerts_enabled, new_software_enabled, ai_tooling_notifications_enabled, updated_at, updated_by)
		    VALUES ($1::uuid, $2, $3, $4, now(), $6)
		    ON CONFLICT (tenant_id) DO UPDATE SET
		        unapproved_alerts_enabled = EXCLUDED.unapproved_alerts_enabled,
		        new_software_enabled = EXCLUDED.new_software_enabled,
		        ai_tooling_notifications_enabled = EXCLUDED.ai_tooling_notifications_enabled,
		        updated_at = now(), updated_by = EXCLUDED.updated_by
		    RETURNING ai_tooling_notifications_enabled
		)
		INSERT INTO ai_tooling_notification_changes(tenant_id,old_enabled,new_enabled,changed_by)
		SELECT $1::uuid,p.old_enabled,s.ai_tooling_notifications_enabled,$6
		FROM previous p CROSS JOIN saved s
		WHERE $7 AND p.old_enabled IS DISTINCT FROM s.ai_tooling_notifications_enabled
	`, tenantID, cur.UnapprovedAlertsEnabled, cur.NewSoftwareEnabled, cur.AIToolingNotificationsEnabled,
		DefaultAIToolingNotificationsEnabled, actor, auditAI); err != nil {
		return cur, fmt.Errorf("write software notification settings: %w", err)
	}
	return GetSettings(ctx, q, tenantID)
}

// ensureSettingsRow creates a defaults row to hold runner cursors, without
// changing any value a tenant saved.
func ensureSettingsRow(ctx context.Context, q Querier, tenantID string) error {
	_, err := q.Exec(ctx, `
		INSERT INTO tenant_software_notification_settings
			(tenant_id, unapproved_alerts_enabled, new_software_enabled, ai_tooling_notifications_enabled)
		VALUES ($1::uuid, $2, $3, $4)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID, DefaultUnapprovedAlertsEnabled, DefaultNewSoftwareEnabled, DefaultAIToolingNotificationsEnabled)
	return err
}

// Recipient is where the unapproved software email goes: the tenant's
// contact email (tenants.contact_email, 0049). Configured is false when there
// is no usable address; the webhook still goes out.
type Recipient struct {
	Email      *string `json:"email"`
	Configured bool    `json:"configured"`
}

// TenantRecipient reads and validates the tenant contact email.
func TenantRecipient(ctx context.Context, q Querier, tenantID string) (Recipient, error) {
	var email *string
	if err := q.QueryRow(ctx, `SELECT contact_email FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&email); err != nil {
		if isNoRows(err) {
			return Recipient{}, nil
		}
		return Recipient{}, fmt.Errorf("read tenant contact: %w", err)
	}
	if email == nil {
		return Recipient{}, nil
	}
	e := strings.TrimSpace(*email)
	if !validEmail(e) {
		return Recipient{}, nil
	}
	return Recipient{Email: &e, Configured: true}, nil
}

// validEmail is a shape check only, deliberately conservative: one @, a dot
// in the domain, no whitespace or control characters, and no characters that
// could split a header.
func validEmail(e string) bool {
	if e == "" || len(e) > 320 || strings.ContainsAny(e, " \t\r\n,;<>\"") {
		return false
	}
	at := strings.LastIndex(e, "@")
	if at <= 0 || at != strings.Index(e, "@") || at == len(e)-1 {
		return false
	}
	domain := e[at+1:]
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}
