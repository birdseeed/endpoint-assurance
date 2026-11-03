package handlers

// PAT-2009 software governance reporting and notification settings.
//
//   GET /v1/portal/software/new                   products first seen since a date or the last review
//   GET /v1/portal/software/drift                 Unapproved and Unreviewed products, trend, top devices,
//                                                 and the Unapproved-present list
//   GET /v1/portal/software/approved              every Approved product with who approved it and when
//   GET /v1/portal/software-notifications         the tenant's notification settings
//   PUT /v1/portal/software-notifications         change them (portal admin role only)
//   GET /admin/tenants/{tenantID}/software-notifications
//   PUT /admin/tenants/{tenantID}/software-notifications
//   GET /admin/reports/{new-software|software-drift|approved-software}/{tenantID}.pdf
//
// Every read takes ?format=json (default) or ?format=csv. The portal routes
// take the tenant only from the verified portal identity; no tenant id is
// read from the client. Unknown query parameters are refused so a typo cannot
// silently return the wrong window.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
	"patched.im/api/internal/softwaregov"
	"patched.im/api/internal/webhook"
)

// raiseUnapprovedEpisodes hands the unapproved software alert for episodes a
// policy write opened inside its own transaction (softwaregov.OpenEpisodeTx)
// to the runner. PAT-2095: the raise used to run here, after the commit and
// before the response, and a bulk mark on a large estate held the request
// (and every ingest behind the tenant alert lock) for up to 30 seconds. The
// episode rows committed with the decision are the durable job: the runner
// raises every unraised episode, is woken here to do it straight away, and
// retries on its next tick if that fails. Nothing here can fail the request.
func raiseUnapprovedEpisodes(pool *pgxpool.Pool, tenantID string, episodeIDs []int64, logger *slog.Logger) {
	if pool == nil || len(episodeIDs) == 0 {
		return
	}
	softwaregov.WakeRunner()
	logger.Info("unapproved software alert queued for the runner", "episodes", len(episodeIDs))
}

func governanceFormat(w http.ResponseWriter, r *http.Request, allowed ...string) (string, bool) {
	q := r.URL.Query()
	ok := map[string]bool{"format": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range q {
		if !ok[k] {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "unknown query parameter "+strconv.Quote(k), nil)
			return "", false
		}
	}
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "format must be csv or json", nil)
		return "", false
	}
	return format, true
}

func governanceError(w http.ResponseWriter, logger *slog.Logger, msg string, err error) {
	if errors.Is(err, softwaregov.ErrEstateTooLarge) {
		writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
			"the estate inventory is too large to assess in one request", nil)
		return
	}
	logger.Error(msg, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// parseSince accepts RFC 3339 or a YYYY-MM-DD date (midnight UTC).
func parseSince(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		u := t.UTC()
		return &u, nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return &t, nil
	}
	return nil, errors.New("since must be an RFC 3339 time or a YYYY-MM-DD date")
}

func csvAttachment(w http.ResponseWriter, stem string, rows int) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+stem+"-"+time.Now().UTC().Format("2006-01-02")+`.csv"`)
	w.Header().Set("X-Patched-Export-Rows", strconv.Itoa(rows))
	return csv.NewWriter(w)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// PortalNewSoftwareHandler serves GET /v1/portal/software/new.
func PortalNewSoftwareHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, ok := governanceFormat(w, r, "since")
		if !ok {
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_new_software", "tenant_id", id.TenantID)
		ns, err := softwaregov.FetchNewSoftware(r.Context(), pool, id.TenantID, since, time.Now())
		if err != nil {
			governanceError(w, logger, "fetch new software failed", err)
			return
		}
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ns)
			return
		}
		cw := csvAttachment(w, "new-software", len(ns.Products))
		_ = cw.Write([]string{"first_seen_at", "name", "platform", "identifier", "team_id", "identity_basis",
			"product_key", "approval_state", "device_count", "first_device_hostname", "first_device_id",
			"first_device_still_installed", "since", "since_basis"})
		for _, p := range ns.Products {
			_ = cw.Write([]string{fmtTime(p.FirstSeenAt), csvSafe(p.Name), p.Platform, csvSafe(p.Identifier), p.TeamID,
				p.IdentityBasis, csvSafe(strOrEmpty(p.ProductKey)), p.ApprovalState, strconv.Itoa(p.DeviceCount),
				csvSafe(p.FirstDevice.Hostname), p.FirstDevice.DeviceID, strconv.FormatBool(p.FirstDevice.StillInstalled),
				fmtTimePtr(ns.Since), ns.SinceBasis})
		}
		cw.Flush()
	}
}

// PortalSoftwareDriftHandler serves GET /v1/portal/software/drift. The CSV
// form is every Unapproved and Unreviewed product, uncapped, with who marked
// each Unapproved one and since when.
func PortalSoftwareDriftHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, ok := governanceFormat(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_software_drift", "tenant_id", id.TenantID)
		estate, err := softwaregov.LoadEstate(r.Context(), pool, id.TenantID, time.Now())
		if err != nil {
			governanceError(w, logger, "load estate failed", err)
			return
		}
		if format == "json" {
			d, err := softwaregov.BuildDrift(r.Context(), pool, id.TenantID, estate)
			if err != nil {
				governanceError(w, logger, "build drift failed", err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(d)
			return
		}
		products := softwaregov.DriftProducts(estate.Assessments)
		present, err := softwaregov.UnapprovedPresentList(r.Context(), pool, id.TenantID, estate.Assessments)
		if err != nil {
			governanceError(w, logger, "unapproved present failed", err)
			return
		}
		marks := map[string]softwaregov.UnapprovedPresent{}
		for _, u := range present {
			if _, seen := marks[u.ProductKey]; !seen {
				marks[u.ProductKey] = u
			}
		}
		cw := csvAttachment(w, "software-drift", len(products))
		_ = cw.Write([]string{"approval_state", "name", "type", "platform", "identifier", "team_id", "browser",
			"extension_id", "product_key", "device_count", "stale_device_count", "observed_since",
			"unapproved_since", "marked_by", "marked_via"})
		for _, p := range products {
			var since, by, via string
			if u, ok := marks[p.ProductKey]; ok && p.ApprovalState == softwaregov.StateUnapproved {
				since, by, via = fmtTime(u.Since), strOrEmpty(u.MarkedBy), u.MarkedVia
			}
			_ = cw.Write([]string{p.ApprovalState, csvSafe(p.Name), p.Type, p.Platform, csvSafe(p.Identifier), p.TeamID,
				p.Browser, csvSafe(p.ExtensionID), csvSafe(p.ProductKey), strconv.Itoa(p.DeviceCount),
				strconv.Itoa(p.StaleDeviceCount), fmtTime(p.ObservedSince), since, csvSafe(by), via})
		}
		cw.Flush()
	}
}

// PortalApprovedSoftwareHandler serves GET /v1/portal/software/approved.
func PortalApprovedSoftwareHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, ok := governanceFormat(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_approved_software", "tenant_id", id.TenantID)
		list, err := softwaregov.FetchApproved(r.Context(), pool, id.TenantID, time.Now())
		if err != nil {
			governanceError(w, logger, "fetch approved software failed", err)
			return
		}
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		cw := csvAttachment(w, "approved-software", len(list.Products))
		_ = cw.Write([]string{"name", "type", "platform", "identifier", "team_id", "winget_id", "match_name",
			"browser", "extension_id", "product_key", "approved_by", "approved_via", "approved_at",
			"approved_at_basis", "justification", "policy_id", "declaration_id", "source", "identity_state", "observation_state", "observed_installation_count", "effective_approval_state", "publisher", "min_version", "review_date", "outside_constraint_count", "unknown_version_count"})
		for _, p := range list.Products {
			_ = cw.Write([]string{csvSafe(p.Name), p.Type, p.Platform, csvSafe(p.Identifier), csvSafe(p.TeamID),
				csvSafe(p.WingetID), csvSafe(p.MatchName), p.Browser, csvSafe(p.ExtensionID),
				csvSafe(strOrEmpty(p.ProductKey)), csvSafe(strOrEmpty(p.ApprovedBy)), p.ApprovedVia,
				fmtTime(p.ApprovedAt), p.ApprovedAtBasis, csvSafe(strOrEmpty(p.Justification)),
				strconv.FormatInt(p.PolicyID, 10),
				// PAT-2393. Plain strings, empty for a row with no declaration;
				// neutralised like every other text cell.
				csvSafe(p.DeclarationID), csvSafe(p.Source), csvSafe(p.IdentityState), csvSafe(p.ObservationState),
				strconv.Itoa(p.ObservedInstallationCount), csvSafe(p.EffectiveApprovalState), csvSafe(p.Publisher),
				csvSafe(strOrEmpty(p.MinVersion)), csvSafe(strOrEmpty(p.ReviewDate)),
				strconv.Itoa(p.OutsideConstraintCount), strconv.Itoa(p.UnknownVersionCount)})
		}
		cw.Flush()
	}
}

// softwareNotificationsResp is the settings view: the two switches, where the
// unapproved alert email goes, and how many destinations each event reaches,
// so the portal can say plainly when an alert has nowhere to go.
type softwareNotificationsResp struct {
	softwaregov.Settings
	UnapprovedAlert struct {
		Event              string                `json:"event"`
		EmailRecipient     softwaregov.Recipient `json:"email_recipient"`
		WebhookEndpoints   int                   `json:"webhook_endpoints"`
		EmailSchedule      string                `json:"email_schedule"`
		DigestHourUTC      int                   `json:"digest_hour_utc"`
		WebhookSubscribeTo string                `json:"webhook_subscribe_to"`
	} `json:"unapproved_alert"`
	NewSoftware struct {
		Event         string `json:"event"`
		Channels      int    `json:"channels"`
		DigestHourUTC int    `json:"digest_hour_utc"`
	} `json:"new_software"`
	AITooling struct {
		Event         string `json:"event"`
		Channels      int    `json:"channels"`
		DigestHourUTC int    `json:"digest_hour_utc"`
	} `json:"ai_tooling"`
}

func loadSoftwareNotifications(ctx context.Context, pool *pgxpool.Pool, tenantID string) (softwareNotificationsResp, error) {
	var out softwareNotificationsResp
	s, err := softwaregov.GetSettings(ctx, pool, tenantID)
	if err != nil {
		return out, err
	}
	out.Settings = s
	rcpt, err := softwaregov.TenantRecipient(ctx, pool, tenantID)
	if err != nil {
		return out, err
	}
	out.UnapprovedAlert.Event = string(webhook.EventSoftwareUnapprovedDetected)
	out.UnapprovedAlert.WebhookSubscribeTo = string(webhook.EventSoftwareUnapprovedDetected)
	out.UnapprovedAlert.EmailRecipient = rcpt
	out.UnapprovedAlert.EmailSchedule = "marked: immediately; newly observed: daily digest"
	out.UnapprovedAlert.DigestHourUTC = softwaregov.DigestHourUTC
	if err := pool.QueryRow(ctx, `
		SELECT count(*)::int FROM tenant_webhooks
		WHERE tenant_id = $1::uuid AND enabled AND events @> ARRAY[$2::text]
	`, tenantID, string(webhook.EventSoftwareUnapprovedDetected)).Scan(&out.UnapprovedAlert.WebhookEndpoints); err != nil {
		return out, err
	}
	out.NewSoftware.Event = string(webhook.EventSoftwareFirstSeen)
	out.NewSoftware.DigestHourUTC = softwaregov.DigestHourUTC
	if err := pool.QueryRow(ctx, `
		SELECT count(*)::int FROM notification_channels
		WHERE tenant_id = $1::uuid AND enabled AND events @> ARRAY[$2::text]
	`, tenantID, string(webhook.EventSoftwareFirstSeen)).Scan(&out.NewSoftware.Channels); err != nil {
		return out, err
	}
	out.AITooling.Event = string(webhook.EventAIToolingFirstSeen)
	out.AITooling.DigestHourUTC = softwaregov.DigestHourUTC
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM notification_channels
		WHERE tenant_id=$1::uuid AND enabled AND events @> ARRAY[$2::text]`, tenantID,
		string(webhook.EventAIToolingFirstSeen)).Scan(&out.AITooling.Channels); err != nil {
		return out, err
	}
	return out, nil
}

const settingsMaxBodyBytes = 4096

func readSettingsUpdate(w http.ResponseWriter, r *http.Request) (softwaregov.SettingsUpdate, bool) {
	var upd softwaregov.SettingsUpdate
	body, err := io.ReadAll(io.LimitReader(r.Body, settingsMaxBodyBytes+1))
	if err != nil || len(body) > settingsMaxBodyBytes {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "could not read the request body", nil)
		return upd, false
	}
	if err := decodeStrictJSON(body, &upd); err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error(), nil)
		return upd, false
	}
	if upd.UnapprovedAlertsEnabled == nil && upd.NewSoftwareEnabled == nil && upd.AIToolingNotificationsEnabled == nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request",
			"set unapproved_alerts_enabled, new_software_enabled, ai_tooling_notifications_enabled, or a combination", nil)
		return upd, false
	}
	return upd, true
}

func writeSoftwareNotifications(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, tenantID string, logger *slog.Logger) {
	out, err := loadSoftwareNotifications(r.Context(), pool, tenantID)
	if err != nil {
		logger.Error("load software notification settings failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// PortalSoftwareNotificationsGetHandler serves GET /v1/portal/software-notifications.
func PortalSoftwareNotificationsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_software_notifications", "tenant_id", id.TenantID)
		writeSoftwareNotifications(w, r, pool, id.TenantID, logger)
	}
}

// PortalSoftwareNotificationsPutHandler serves PUT /v1/portal/software-notifications.
// Admin role only, checked server-side like every PAT-2007 portal write.
func PortalSoftwareNotificationsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "portal_software_notifications_put", "tenant_id", id.TenantID)
		role, err := portalauth.DBRole(r.Context(), pool, id.Email, id.TenantID, false)
		if err != nil {
			logger.Error("role lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !portalauth.CanWrite(role) {
			writeApprovalError(w, http.StatusForbidden, "admin_role_required",
				"only a portal admin can change notification settings; your role is "+role, nil)
			return
		}
		upd, ok := readSettingsUpdate(w, r)
		if !ok {
			return
		}
		if _, err := softwaregov.PutSettings(r.Context(), pool, id.TenantID, upd, id.Email); err != nil {
			logger.Error("write software notification settings failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Info("software notification settings changed", "email", id.Email)
		writeSoftwareNotifications(w, r, pool, id.TenantID, logger)
	}
}

// AdminSoftwareNotificationsGetHandler serves
// GET /admin/tenants/{tenantID}/software-notifications.
func AdminSoftwareNotificationsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "admin_software_notifications")
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}
		writeSoftwareNotifications(w, r, pool, tenantID, logger)
	}
}

// AdminSoftwareNotificationsPutHandler serves
// PUT /admin/tenants/{tenantID}/software-notifications.
func AdminSoftwareNotificationsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "admin_software_notifications_put")
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if err := ensureTenantExists(r, pool, tenantID); err != nil {
			writeTenantLookupError(w, logger, err)
			return
		}
		upd, ok := readSettingsUpdate(w, r)
		if !ok {
			return
		}
		if _, err := softwaregov.PutSettings(r.Context(), pool, tenantID, upd, "operator"); err != nil {
			logger.Error("write software notification settings failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeSoftwareNotifications(w, r, pool, tenantID, logger)
	}
}

// governanceAdminPDF serves one of the three admin PDF routes.
func governanceAdminPDF[T any](pool *pgxpool.Pool, stem string, fetch func(context.Context, *pgxpool.Pool, string) (T, error), render func(T) ([]byte, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", stem+"_report")
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		data, err := fetch(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			governanceError(w, logger, "fetch "+stem+" report failed", err)
			return
		}
		pdf, err := render(data)
		if err != nil {
			logger.Error("render "+stem+" pdf failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s-%s.pdf"`,
			stem, tenantID, time.Now().UTC().Format("20060102T150405Z")))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdf)
	}
}

// NewSoftwareReportHandler serves GET /admin/reports/new-software/{tenantID}.pdf.
func NewSoftwareReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return governanceAdminPDF(pool, "new-software", report.FetchNewSoftwareReport, report.RenderNewSoftwarePDF)
}

// SoftwareDriftReportHandler serves GET /admin/reports/software-drift/{tenantID}.pdf.
func SoftwareDriftReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return governanceAdminPDF(pool, "software-drift", report.FetchSoftwareDriftReport, report.RenderSoftwareDriftPDF)
}

// ApprovedSoftwareReportHandler serves GET /admin/reports/approved-software/{tenantID}.pdf.
func ApprovedSoftwareReportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return governanceAdminPDF(pool, "approved-software", report.FetchApprovedSoftwareReport, report.RenderApprovedSoftwarePDF)
}
