package handlers

// Customer portal Jamf Pro coverage (PAT-2145).
//
//   GET    /v1/portal/mdm/jamf/coverage  connector health, counts, the three buckets (paged), CSV
//   GET    /v1/portal/mdm/jamf/setup     webhook URL, token status, events to tick
//   PUT    /v1/portal/mdm/jamf/setup     turn the optional ComputerCheckIn event on or off (admin)
//   POST   /v1/portal/mdm/jamf/token     create or rotate the webhook token, plaintext shown once (admin)
//   DELETE /v1/portal/mdm/jamf/token     revoke the webhook token (admin)
//
// Every portal role reads; writes need role 'admin', re-read from
// portal_users inside the write transaction (requirePortalAdmin, the
// PAT-2007/PAT-2135 seam), and each write is recorded in the append-only
// jamf_webhook_audit with the verified portal email. The tenant comes only
// from the verified portal identity. The token itself is never readable
// after the response that created it: only its SHA-256 is stored.
//
// Patched never holds a Jamf API credential (PAT-1666). Everything here is
// built from what the customer's Jamf Pro pushed to
// POST /v1/webhooks/jamf/{webhookID} (jamf_webhook.go) and from the agents'
// own evidence.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/jamfcoverage"
)

// JamfWebhookPublicBaseURL is the public origin the setup page builds the
// webhook URL from. Set from JAMF_WEBHOOK_PUBLIC_BASE_URL in
// cmd/patched-api; the default is the production public API host.
var JamfWebhookPublicBaseURL = "https://api.patched.im"

const (
	jamfTokenPrefix         = "pjwh_"
	jamfCoverageDefaultPage = 100
	jamfCoverageMaxPage     = 500
	jamfWriteMaxBodyBytes   = 4 << 10
	// jamfAmberAfter: no event for this long turns the connector amber.
	jamfAmberAfter = 24 * time.Hour
	// jamfCoverageMaxRows caps each side of the reconciliation, like the
	// other estate-wide portal reports.
	jamfCoverageMaxRows = 50000
)

// jamfWebhookURL is the public webhook URL for a webhook ID.
func jamfWebhookURL(webhookID string) string {
	return strings.TrimRight(JamfWebhookPublicBaseURL, "/") + "/v1/webhooks/jamf/" + webhookID
}

func jamfRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Connector read
// ---------------------------------------------------------------------------

type jamfConnector struct {
	WebhookID              string
	TokenActive            bool
	CreatedAt              time.Time
	TokenIssuedAt          *time.Time
	TokenRevokedAt         *time.Time
	CheckInEnabled         bool
	FirstEventAt           *time.Time
	LastEventAt            *time.Time
	EventsRejected         int64
	LastRejectedAt         *time.Time
	LastRejectedReason     *string
	InstanceURL            *string
	InstanceLastClaimed    *string
	InstanceMismatchSeenAt *time.Time
}

type jamfQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// loadJamfConnector returns nil when the tenant has no connector.
func loadJamfConnector(ctx context.Context, q jamfQuerier, tenantID string) (*jamfConnector, error) {
	var c jamfConnector
	err := q.QueryRow(ctx, `
		SELECT webhook_id, token_hash IS NOT NULL, created_at, token_issued_at, token_revoked_at, check_in_enabled,
		       first_event_at, last_event_at, events_rejected, last_rejected_at, last_rejected_reason,
		       jamf_instance_url, jamf_instance_last_claimed, jamf_instance_mismatch_at
		FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&c.WebhookID, &c.TokenActive, &c.CreatedAt, &c.TokenIssuedAt, &c.TokenRevokedAt, &c.CheckInEnabled,
		&c.FirstEventAt, &c.LastEventAt, &c.EventsRejected, &c.LastRejectedAt, &c.LastRejectedReason,
		&c.InstanceURL, &c.InstanceLastClaimed, &c.InstanceMismatchSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	for _, t := range []*time.Time{c.TokenIssuedAt, c.TokenRevokedAt, c.FirstEventAt, c.LastEventAt, c.LastRejectedAt, c.InstanceMismatchSeenAt} {
		if t != nil {
			*t = t.UTC()
		}
	}
	return &c, nil
}

type jamfInstanceOut struct {
	// URL is the first Jamf Pro instance the tenant's events claimed
	// (X-Patched-Jamf-Instance); LastClaimed the most recent claim.
	URL         *string `json:"url"`
	LastClaimed *string `json:"last_claimed"`
	// Mismatch is true when the latest claim differs from the first.
	// MismatchSeenAt is the last time any event claimed a different
	// instance, kept after the claims agree again.
	Mismatch       bool       `json:"mismatch"`
	MismatchSeenAt *time.Time `json:"mismatch_seen_at"`
}

func (c *jamfConnector) instance() jamfInstanceOut {
	if c == nil {
		return jamfInstanceOut{}
	}
	return jamfInstanceOut{
		URL: c.InstanceURL, LastClaimed: c.InstanceLastClaimed, MismatchSeenAt: c.InstanceMismatchSeenAt,
		Mismatch: c.InstanceURL != nil && c.InstanceLastClaimed != nil && *c.InstanceURL != *c.InstanceLastClaimed,
	}
}

type jamfHealthOut struct {
	// Status: not_configured | revoked | awaiting_first_event | amber | ok.
	Status              string          `json:"status"`
	Amber               bool            `json:"amber"`
	Message             string          `json:"message"`
	TokenActive         bool            `json:"token_active"`
	FirstEventAt        *time.Time      `json:"first_event_at"`
	LastEventAt         *time.Time      `json:"last_event_at"`
	HoursSinceLastEvent *int            `json:"hours_since_last_event"`
	EventsRejected      int64           `json:"events_rejected"`
	LastRejectedAt      *time.Time      `json:"last_rejected_at"`
	LastRejectedReason  *string         `json:"last_rejected_reason"`
	CheckInEnabled      bool            `json:"check_in_enabled"`
	JamfInstance        jamfInstanceOut `json:"jamf_instance"`
	AmberAfterHours     int             `json:"amber_after_hours"`
}

func jamfHealth(c *jamfConnector, now time.Time) jamfHealthOut {
	h := jamfHealthOut{AmberAfterHours: int(jamfAmberAfter / time.Hour)}
	if c == nil {
		h.Status, h.Message = "not_configured", "Jamf is not connected. An admin can create a webhook token on the setup page."
		return h
	}
	h.TokenActive, h.FirstEventAt, h.LastEventAt = c.TokenActive, c.FirstEventAt, c.LastEventAt
	h.EventsRejected, h.LastRejectedAt, h.LastRejectedReason = c.EventsRejected, c.LastRejectedAt, c.LastRejectedReason
	h.CheckInEnabled, h.JamfInstance = c.CheckInEnabled, c.instance()
	if c.LastEventAt != nil {
		hrs := int(now.Sub(*c.LastEventAt) / time.Hour)
		if hrs < 0 {
			hrs = 0
		}
		h.HoursSinceLastEvent = &hrs
	}
	switch {
	case !c.TokenActive:
		h.Status, h.Amber = "revoked", true
		h.Message = "The webhook token is revoked, so Jamf events are refused. An admin can create a new token."
	case c.LastEventAt == nil && now.Sub(c.CreatedAt) < jamfAmberAfter:
		h.Status = "awaiting_first_event"
		h.Message = "No Jamf event yet. Events appear once Jamf Pro sends its first webhook."
	case c.LastEventAt == nil:
		h.Status, h.Amber = "amber", true
		h.Message = "No Jamf event has been received since setup, more than 24 hours ago. Check the webhooks in Jamf Pro."
	case now.Sub(*c.LastEventAt) >= jamfAmberAfter:
		h.Status, h.Amber = "amber", true
		h.Message = "No Jamf event in the last 24 hours. Check the webhooks in Jamf Pro."
	default:
		h.Status, h.Message = "ok", "Receiving Jamf events."
	}
	if h.JamfInstance.Mismatch {
		h.Amber = true
		if h.Status == "ok" {
			h.Status = "amber"
		}
		h.Message += " The latest events claim a different Jamf Pro instance from the first ones."
	}
	return h
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

type jamfEventOut struct {
	Event      string `json:"event"`
	Required   bool   `json:"required"`
	Subscribed bool   `json:"subscribed"`
	Purpose    string `json:"purpose"`
}

var jamfEventPurpose = map[string]string{
	jamfcoverage.EventComputerAdded:              "a Mac enrolled in Jamf Pro",
	jamfcoverage.EventComputerInventoryCompleted: "a Mac sent Jamf its inventory",
	jamfcoverage.EventDeviceAddedToDEP:           "a Mac was assigned to Jamf in Apple Business Manager",
	jamfcoverage.EventComputerCheckIn:            "optional: a Mac checked in (collapsed to one update per Mac per hour)",
}

type jamfTokenStatusOut struct {
	Exists         bool       `json:"exists"`
	CreatedAt      *time.Time `json:"created_at"`
	IssuedAt       *time.Time `json:"issued_at"`
	LastRotatedAt  *time.Time `json:"last_rotated_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	PlaintextShown string     `json:"plaintext_shown"`
}

type jamfSetupOut struct {
	Configured     bool               `json:"configured"`
	WebhookURL     *string            `json:"webhook_url"`
	Token          jamfTokenStatusOut `json:"token"`
	CheckInEnabled bool               `json:"check_in_enabled"`
	Events         []jamfEventOut     `json:"events"`
	Authentication map[string]any     `json:"authentication"`
	JamfInstance   jamfInstanceOut    `json:"jamf_instance"`
	PatchedHolds   string             `json:"patched_holds"`
}

func jamfSetup(c *jamfConnector) jamfSetupOut {
	out := jamfSetupOut{
		Token:        jamfTokenStatusOut{PlaintextShown: "once, when created or rotated"},
		JamfInstance: c.instance(),
		PatchedHolds: "no Jamf credential; Jamf Pro pushes webhooks to Patched",
		Authentication: map[string]any{
			"type":         "Header Authentication",
			"content_type": "JSON",
			"header_json":  `{"Authorization":"Bearer <your webhook token>","` + jamfcoverage.InstanceHeader + `":"https://<your instance>.jamfcloud.com"}`,
			"alternative":  "Basic Authentication with any username and the webhook token as the password",
			"instance_header_note": "The " + jamfcoverage.InstanceHeader + " header is optional. Jamf Pro webhooks do not name the Jamf Pro server, " +
				"so this is how Patched records which instance the events come from and flags a change.",
		},
	}
	if c != nil {
		out.Configured = true
		u := jamfWebhookURL(c.WebhookID)
		out.WebhookURL = &u
		out.CheckInEnabled = c.CheckInEnabled
		out.Token.Exists = c.TokenActive
		ca := c.CreatedAt
		out.Token.CreatedAt = &ca
		out.Token.RevokedAt = c.TokenRevokedAt
		if c.TokenActive {
			out.Token.IssuedAt = c.TokenIssuedAt
			if c.TokenIssuedAt != nil && c.TokenIssuedAt.After(c.CreatedAt) {
				out.Token.LastRotatedAt = c.TokenIssuedAt
			}
		}
	}
	for _, e := range jamfcoverage.SupportedEvents {
		req := !jamfcoverage.IsOptionalEvent(e)
		out.Events = append(out.Events, jamfEventOut{
			Event: e, Required: req, Subscribed: req || out.CheckInEnabled, Purpose: jamfEventPurpose[e],
		})
	}
	return out
}

// PortalJamfSetupGetHandler serves GET /v1/portal/mdm/jamf/setup.
func PortalJamfSetupGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if len(r.URL.Query()) > 0 {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "this endpoint takes no query parameters", nil)
			return
		}
		ctx := r.Context()
		c, err := loadJamfConnector(ctx, pool, id.TenantID)
		if err != nil {
			slog.Error("jamf connector read failed", "req_id", middleware.GetReqID(ctx), "tenant_id", id.TenantID, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jamfSetup(c))
	}
}

type jamfSetupPutRequest struct {
	CheckInEnabled    *bool `json:"check_in_enabled"`
	ResetJamfInstance *bool `json:"reset_jamf_instance"`
}

// PortalJamfSetupPutHandler serves PUT /v1/portal/mdm/jamf/setup:
// {"check_in_enabled": true|false, "reset_jamf_instance": true}, either or
// both. check_in_enabled subscribes or unsubscribes ComputerCheckIn;
// reset_jamf_instance forgets the pinned Jamf Pro instance, so the next
// event's claim is pinned afresh (after a planned instance move). Admin
// only, each change audited. 409 not_configured when the tenant has no
// connector yet.
func PortalJamfSetupPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_jamf_setup_put", "tenant_id", id.TenantID)
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, "change the Jamf webhook settings", logger) {
			return
		}
		body, ok := readLimitedBody(w, r, jamfWriteMaxBodyBytes)
		if !ok {
			return
		}
		var req jamfSetupPutRequest
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error(), nil)
			return
		}
		if req.CheckInEnabled == nil && req.ResetJamfInstance == nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request",
				"send check_in_enabled (true or false), reset_jamf_instance (true), or both", nil)
			return
		}
		if req.ResetJamfInstance != nil && !*req.ResetJamfInstance {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "reset_jamf_instance can only be true", nil)
			return
		}
		var current bool
		var pinned *string
		err = tx.QueryRow(ctx, `SELECT check_in_enabled, jamf_instance_url FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid FOR UPDATE`,
			id.TenantID).Scan(&current, &pinned)
		if errors.Is(err, pgx.ErrNoRows) {
			writeApprovalError(w, http.StatusConflict, "not_configured", "create a Jamf webhook token first", nil)
			return
		}
		if err != nil {
			internal("connector lock failed", err)
			return
		}
		changed := false
		if req.CheckInEnabled != nil && current != *req.CheckInEnabled {
			changed = true
			action := "check_in_disabled"
			if *req.CheckInEnabled {
				action = "check_in_enabled"
			}
			if _, err := tx.Exec(ctx, `UPDATE jamf_webhook_connectors SET check_in_enabled = $2 WHERE tenant_id = $1::uuid`,
				id.TenantID, *req.CheckInEnabled); err != nil {
				internal("connector update failed", err)
				return
			}
			if err := jamfAudit(ctx, tx, id.TenantID, action, id.Email, nil); err != nil {
				internal("audit insert failed", err)
				return
			}
		}
		if req.ResetJamfInstance != nil && pinned != nil {
			changed = true
			if err := jamfClearInstance(ctx, tx, id.TenantID); err != nil {
				internal("instance reset failed", err)
				return
			}
			if err := jamfAudit(ctx, tx, id.TenantID, "instance_reset", id.Email, nil); err != nil {
				internal("audit insert failed", err)
				return
			}
		}
		c, err := loadJamfConnector(ctx, tx, id.TenantID)
		if err != nil {
			internal("connector read-back failed", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		if changed {
			logger.Info("portal jamf setup changed")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"changed": changed, "setup": jamfSetup(c)})
	}
}

func jamfClearInstance(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE jamf_webhook_connectors
		SET jamf_instance_url = NULL, jamf_instance_last_claimed = NULL, jamf_instance_mismatch_at = NULL
		WHERE tenant_id = $1::uuid
	`, tenantID)
	return err
}

func jamfAudit(ctx context.Context, tx pgx.Tx, tenantID, action, email string, affected *int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO jamf_webhook_audit (tenant_id, action, actor_email, affected_rows) VALUES ($1::uuid, $2, lower(btrim($3)), $4)
	`, tenantID, action, email, affected)
	return err
}

// requireEmptyOrEmptyObject accepts no body or {} and refuses anything else,
// so a write that takes no input cannot be sent input by mistake.
func requireEmptyOrEmptyObject(w http.ResponseWriter, r *http.Request) bool {
	body, ok := readLimitedBody(w, r, jamfWriteMaxBodyBytes)
	if !ok {
		return false
	}
	if strings.TrimSpace(string(body)) == "" {
		return true
	}
	var empty struct{}
	if err := decodeStrictJSON(body, &empty); err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "this request takes no body, or {}", nil)
		return false
	}
	return true
}

// jamfAdminWrite runs one admin-only connector write: identity, role
// re-read inside the transaction, empty body, the per-tenant connector lock,
// then fn, then commit. fn returns the JSON response; a nil response means
// fn already wrote an error.
func jamfAdminWrite(pool *pgxpool.Pool, handler, what string,
	fn func(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, email, tenantID string, internal func(string, error)) (int, map[string]any, func())) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", handler, "tenant_id", id.TenantID)
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
		if !requirePortalAdmin(ctx, tx, w, id, what, logger) {
			return
		}
		if !requireEmptyOrEmptyObject(w, r) {
			return
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, id.TenantID+"|jamf-connector"); err != nil {
			internal("connector lock failed", err)
			return
		}
		status, resp, afterCommit := fn(ctx, tx, w, id.Email, id.TenantID, internal)
		if resp == nil {
			return
		}
		c, err := loadJamfConnector(ctx, tx, id.TenantID)
		if err != nil {
			internal("connector read-back failed", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		if afterCommit != nil {
			afterCommit()
		}
		logger.Info("portal jamf write", "result", resp["action"], "changed", resp["changed"])
		resp["setup"] = jamfSetup(c)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// PortalJamfTokenPostHandler serves POST /v1/portal/mdm/jamf/token: create
// the tenant's connector and first token, or rotate the token. The old
// token stops working when this commits (an in-flight event that
// authenticated with it is refused by the ingest's locked re-check). A new
// token starts a new token generation and clears the pinned Jamf instance,
// so the next event's claim is pinned afresh. The plaintext is in this
// response only. Admin only.
func PortalJamfTokenPostHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return jamfAdminWrite(pool, "portal_jamf_token_post", "create or rotate the Jamf webhook token",
		func(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, email, tenantID string, internal func(string, error)) (int, map[string]any, func()) {
			secret, err := jamfRandom(32)
			if err != nil {
				internal("token generation failed", err)
				return 0, nil, nil
			}
			token := jamfTokenPrefix + secret
			hash := sha256.Sum256([]byte(token))

			var hadToken bool
			err = tx.QueryRow(ctx, `SELECT token_hash IS NOT NULL FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid FOR UPDATE`,
				tenantID).Scan(&hadToken)
			action := "token_rotated"
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				action = "token_created"
				webhookID, gerr := jamfRandom(24)
				if gerr != nil {
					internal("webhook id generation failed", gerr)
					return 0, nil, nil
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO jamf_webhook_connectors (tenant_id, webhook_id, token_hash, token_issued_at)
					VALUES ($1::uuid, $2, $3, now())
				`, tenantID, webhookID, hash[:]); err != nil {
					internal("connector insert failed", err)
					return 0, nil, nil
				}
			case err != nil:
				internal("connector read failed", err)
				return 0, nil, nil
			default:
				if !hadToken {
					action = "token_created"
				}
				if _, err := tx.Exec(ctx, `
					UPDATE jamf_webhook_connectors
					SET token_hash = $2, token_issued_at = now(), token_revoked_at = NULL,
					    token_generation = token_generation + 1,
					    jamf_instance_url = NULL, jamf_instance_last_claimed = NULL, jamf_instance_mismatch_at = NULL
					WHERE tenant_id = $1::uuid
				`, tenantID, hash[:]); err != nil {
					internal("connector update failed", err)
					return 0, nil, nil
				}
			}
			if err := jamfAudit(ctx, tx, tenantID, action, email, nil); err != nil {
				internal("audit insert failed", err)
				return 0, nil, nil
			}
			var webhookID string
			if err := tx.QueryRow(ctx, `SELECT webhook_id FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid`, tenantID).Scan(&webhookID); err != nil {
				internal("connector read failed", err)
				return 0, nil, nil
			}
			status := http.StatusOK
			if action == "token_created" {
				status = http.StatusCreated
			}
			issued := hash
			return status, map[string]any{
				"action": action, "token": token, "webhook_url": jamfWebhookURL(webhookID),
				"note": "This token is shown once. Paste it into the Jamf Pro webhook's Header Authentication now; Patched keeps only a hash.",
			}, func() { jamfConnectorIssued(webhookID, issued[:]) }
		})
}

// PortalJamfTokenDeleteHandler serves DELETE /v1/portal/mdm/jamf/token:
// revoke the token. Jamf events are refused (401) until a new token is
// created. The Macs first recorded under the revoked token are deleted
// (anything a leaked token fabricated); Macs recorded under an earlier
// token are kept, and every Mac returns with Jamf's next event under a new
// token. The count is in the response and the audit row. Revoking when
// there is no active token is a no-op (changed false). Admin only.
func PortalJamfTokenDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return jamfAdminWrite(pool, "portal_jamf_token_delete", "revoke the Jamf webhook token",
		func(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, email, tenantID string, internal func(string, error)) (int, map[string]any, func()) {
			var generation int
			var webhookID string
			err := tx.QueryRow(ctx, `
				UPDATE jamf_webhook_connectors SET token_hash = NULL, token_revoked_at = now()
				WHERE tenant_id = $1::uuid AND token_hash IS NOT NULL
				RETURNING token_generation, webhook_id
			`, tenantID).Scan(&generation, &webhookID)
			if errors.Is(err, pgx.ErrNoRows) {
				return http.StatusOK, map[string]any{"action": "token_revoked", "changed": false, "devices_deleted": 0,
					"note": "There was no active token, so nothing was revoked or deleted."}, nil
			}
			if err != nil {
				internal("token revoke failed", err)
				return 0, nil, nil
			}
			tag, err := tx.Exec(ctx, `DELETE FROM jamf_devices WHERE tenant_id = $1::uuid AND first_token_generation = $2`, tenantID, generation)
			if err != nil {
				internal("device delete failed", err)
				return 0, nil, nil
			}
			n := tag.RowsAffected()
			if err := jamfAudit(ctx, tx, tenantID, "token_revoked", email, &n); err != nil {
				internal("audit insert failed", err)
				return 0, nil, nil
			}
			return http.StatusOK, map[string]any{"action": "token_revoked", "changed": true, "devices_deleted": n,
				"note": fmt.Sprintf("Revoking deleted the %d Jamf device records first seen under this token. "+
					"Jamf events are refused until a new token is created; coverage then refills from Jamf's next events.", n)}, func() { jamfConnectorRevoked(webhookID) }
		})
}

// PortalJamfDevicesDeleteHandler serves DELETE /v1/portal/mdm/jamf/devices:
// delete every Mac Jamf has reported for the tenant. The connector, token
// and webhook URL are kept; the list refills from Jamf's next events.
// Audited with the count. Admin only.
func PortalJamfDevicesDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return jamfAdminWrite(pool, "portal_jamf_devices_delete", "delete the Macs Jamf has reported",
		func(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, email, tenantID string, internal func(string, error)) (int, map[string]any, func()) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jamf_webhook_connectors WHERE tenant_id = $1::uuid)`, tenantID).Scan(&exists); err != nil {
				internal("connector read failed", err)
				return 0, nil, nil
			}
			if !exists {
				writeApprovalError(w, http.StatusConflict, "not_configured", "Jamf is not connected", nil)
				return 0, nil, nil
			}
			tag, err := tx.Exec(ctx, `DELETE FROM jamf_devices WHERE tenant_id = $1::uuid`, tenantID)
			if err != nil {
				internal("device delete failed", err)
				return 0, nil, nil
			}
			n := tag.RowsAffected()
			if err := jamfAudit(ctx, tx, tenantID, "devices_purged", email, &n); err != nil {
				internal("audit insert failed", err)
				return 0, nil, nil
			}
			return http.StatusOK, map[string]any{"action": "devices_purged", "changed": n > 0, "devices_deleted": n}, nil
		})
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

const (
	jamfBucketGap           = "gap"
	jamfBucketNotReported   = "not_reported_by_jamf"
	jamfBucketCovered       = "covered"
	jamfBucketOSNotReported = "os_not_reported"
)

type jamfGapRow struct {
	JamfID             *int64    `json:"jamf_id"`
	Serial             *string   `json:"serial"`
	UDID               *string   `json:"udid"`
	DeviceName         *string   `json:"device_name"`
	Model              *string   `json:"model"`
	OSVersion          *string   `json:"os_version"`
	JamfState          string    `json:"jamf_state"`
	FirstJamfEventAt   time.Time `json:"first_jamf_event_at"`
	LastJamfEventAt    time.Time `json:"last_jamf_event_at"`
	LastJamfEventType  string    `json:"last_jamf_event_type"`
	DaysSinceJamfEvent int       `json:"days_since_jamf_event"`
	Note               string    `json:"note"`
}

type jamfNotReportedRow struct {
	DeviceID      string    `json:"device_id"`
	Hostname      *string   `json:"hostname"`
	Serial        *string   `json:"serial"`
	OSVersion     *string   `json:"os_version"`
	LastSeen      time.Time `json:"last_seen"`
	MDMState      string    `json:"mdm_state"`
	MDMVendor     *string   `json:"mdm_vendor"`
	MDMServerHost *string   `json:"mdm_server_host"`
	Note          string    `json:"note"`
}

type jamfOSNotReportedRow struct {
	DeviceID  string    `json:"device_id"`
	Hostname  *string   `json:"hostname"`
	Serial    *string   `json:"serial"`
	OSVersion *string   `json:"os_version"`
	LastSeen  time.Time `json:"last_seen"`
}

type jamfCoveredRow struct {
	DeviceID           string    `json:"device_id"`
	Hostname           *string   `json:"hostname"`
	Serial             *string   `json:"serial"`
	LastSeen           time.Time `json:"last_seen"`
	JamfID             *int64    `json:"jamf_id"`
	JamfDeviceName     *string   `json:"jamf_device_name"`
	LastJamfEventAt    time.Time `json:"last_jamf_event_at"`
	DaysSinceJamfEvent int       `json:"days_since_jamf_event"`
	MatchBasis         string    `json:"match_basis"`
	Note               string    `json:"note"`
}

type jamfBucketOut[T any] struct {
	Total int `json:"total"`
	Rows  []T `json:"rows"`
}

type jamfCountsOut struct {
	Gap                int `json:"gap"`
	GapDEPAssignedOnly int `json:"gap_dep_assigned_only"`
	GapSilent          int `json:"gap_silent"`
	// NotReportedByJamf: Macs Patched sees that no Jamf event matches. Not
	// a claim they are unmanaged: see the by-state breakdown, where only
	// "unmanaged" (the agent's own evidence) means no MDM.
	NotReportedByJamf           int            `json:"not_reported_by_jamf"`
	NotReportedByJamfByMDMState map[string]int `json:"not_reported_by_jamf_by_mdm_state"`
	// AgentReportsNoMDM: of those, the Macs whose agent reports no MDM
	// enrolment (mdm_state "unmanaged").
	AgentReportsNoMDM     int `json:"agent_reports_no_mdm"`
	Covered               int `json:"covered"`
	CoveredJamfSilent     int `json:"covered_jamf_silent"`
	JamfDevicesTotal      int `json:"jamf_devices_total"`
	RetiredExcluded       int `json:"retired_excluded"`
	NonMacDevicesExcluded int `json:"non_mac_devices_excluded"`
	OSNotReported         int `json:"os_not_reported"`
}

type jamfBasisOut struct {
	Since           *time.Time `json:"since"`
	Statement       string     `json:"statement"`
	NoBackfill      string     `json:"no_backfill"`
	NoDeleteEvent   string     `json:"no_delete_event"`
	SilentAfterDays int        `json:"silent_after_days"`
	MatchBasis      string     `json:"match_basis"`
	Scope           string     `json:"scope"`
	Seed            string     `json:"seed"`
}

func jamfBasis(c *jamfConnector) jamfBasisOut {
	b := jamfBasisOut{
		NoBackfill: "Patched only knows Macs Jamf has sent a webhook for since setup. A Mac Jamf has not reported since then " +
			"is not in these lists yet, so a Mac missing from 'managed by Jamf' is not evidence Jamf does not manage it.",
		NoDeleteEvent: "Jamf Pro sends no event when a Mac is removed. A Mac that goes quiet is shown as 'not heard from Jamf " +
			"in N days', never as removed or unmanaged.",
		SilentAfterDays: jamfcoverage.SilentAfterDays,
		MatchBasis:      "serial_then_udid",
		Scope:           "macOS devices only. Devices you have retired are left out, as on every other page.",
		Seed: "To cover Macs Jamf had before setup, upload a Jamf Pro computer export (Computer Name and Serial Number) as your " +
			"device list on the Devices page. Its 'on your list, never seen' view shows those Macs; it does not change these counts.",
	}
	if c == nil || c.FirstEventAt == nil {
		b.Statement = "No Jamf webhook has been received yet."
		return b
	}
	since := *c.FirstEventAt
	b.Since = &since
	b.Statement = "From Jamf webhooks since " + since.Format("2 January 2006") + "."
	return b
}

type jamfCoverageOut struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Connector   jamfHealthOut `json:"connector"`
	Basis       jamfBasisOut  `json:"basis"`
	Counts      jamfCountsOut `json:"counts"`
	Bucket      *string       `json:"bucket"`
	Limit       int           `json:"limit"`
	Offset      int           `json:"offset"`

	Gap               *jamfBucketOut[jamfGapRow]           `json:"gap,omitempty"`
	NotReportedByJamf *jamfBucketOut[jamfNotReportedRow]   `json:"not_reported_by_jamf,omitempty"`
	Covered           *jamfBucketOut[jamfCoveredRow]       `json:"covered,omitempty"`
	OSNotReported     *jamfBucketOut[jamfOSNotReportedRow] `json:"os_not_reported,omitempty"`
}

var errJamfEstateTooLarge = errors.New("estate too large")

func loadJamfDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]jamfcoverage.JamfDevice, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, COALESCE(serial, ''), COALESCE(serial_normalized, ''), COALESCE(udid, ''), COALESCE(udid_normalized, ''),
		       jamf_id, COALESCE(device_name, ''), COALESCE(model, ''), COALESCE(os_version, ''),
		       enrolled, dep_assigned, last_event_type, first_received_at, last_event_at
		FROM jamf_devices WHERE tenant_id = $1::uuid ORDER BY id LIMIT $2
	`, tenantID, jamfCoverageMaxRows+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []jamfcoverage.JamfDevice
	for rows.Next() {
		var d jamfcoverage.JamfDevice
		if err := rows.Scan(&d.ID, &d.Serial, &d.SerialNormalized, &d.UDID, &d.UDIDNormalized, &d.JamfID, &d.DeviceName,
			&d.Model, &d.OSVersion, &d.Enrolled, &d.DEPAssigned, &d.LastEventType, &d.FirstReceivedAt, &d.LastEventAt); err != nil {
			return nil, err
		}
		d.FirstReceivedAt, d.LastEventAt = d.FirstReceivedAt.UTC(), d.LastEventAt.UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > jamfCoverageMaxRows {
		return nil, errJamfEstateTooLarge
	}
	return out, nil
}

// loadJamfPatchedDevices reads every device in the tenant with its
// retirement and the agent's own MDM enrolment evidence: the latest
// successfully collected applied-configuration snapshot (PAT-1667/1668)
// and the latest mdm_enrolled (or legacy mdm_enrolment) signal.
func loadJamfPatchedDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]jamfcoverage.PatchedDevice, error) {
	rows, err := pool.Query(ctx, `
		SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.serial, ''), COALESCE(d.hw_uuid::text, ''),
		       d.os, COALESCE(d.os_version, ''), d.last_seen, `+deviceretirement.RetiredSQL("d")+`,
		       ac.present IS NOT NULL, COALESCE(ac.mdm_server_url, ''), sig.value, legacy.value
		FROM devices d
		LEFT JOIN LATERAL (
			SELECT true AS present, s.mdm_server_url FROM applied_config_snapshots s
			WHERE s.device_id = d.id AND s.tenant_id = d.tenant_id AND s.collection_status = 'ok'
			ORDER BY s.observed_at DESC, s.id DESC LIMIT 1
		) ac ON true
		LEFT JOIN LATERAL (
			SELECT cs.value FROM compliance_signals cs
			WHERE cs.device_id = d.id AND cs.key = 'mdm_enrolled'
			ORDER BY cs.observed_at DESC, cs.id DESC LIMIT 1
		) sig ON true
		LEFT JOIN LATERAL (
			SELECT cs.value FROM compliance_signals cs
			WHERE cs.device_id = d.id AND cs.key = 'mdm_enrolment'
			ORDER BY cs.observed_at DESC, cs.id DESC LIMIT 1
		) legacy ON true
		WHERE d.tenant_id = $1::uuid
		ORDER BY d.id
		LIMIT $2
	`, tenantID, jamfCoverageMaxRows+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []jamfcoverage.PatchedDevice
	for rows.Next() {
		var d jamfcoverage.PatchedDevice
		var neutral, legacy, osName *string
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.HWUUID, &osName, &d.OSVersion, &d.LastSeen, &d.Retired,
			&d.MDM.AppliedConfigOK, &d.MDM.ServerURL, &neutral, &legacy); err != nil {
			return nil, err
		}
		// devices.os is nullable; an absent OS reads as "", as hostname,
		// serial and the other nullable columns above already do (PAT-2538).
		if osName != nil {
			d.OS = *osName
		}
		d.LastSeen = d.LastSeen.UTC()
		d.MDM.EnrolledSignal = jamfcoverage.EnrolledSignal(neutral, legacy)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > jamfCoverageMaxRows {
		return nil, errJamfEstateTooLarge
	}
	return out, nil
}

func jamfStateOf(d jamfcoverage.JamfDevice) string {
	if !d.Enrolled && d.DEPAssigned {
		return "dep_assigned_only"
	}
	return "enrolled"
}

func jamfGapNote(d jamfcoverage.JamfDevice, now time.Time) string {
	var parts []string
	if jamfStateOf(d) == "dep_assigned_only" {
		parts = append(parts, "assigned to Jamf in Apple Business Manager, no enrolment event from Jamf since")
	}
	if s := jamfcoverage.SilenceNote(d.LastEventAt, now); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

func jamfMDMNote(c jamfcoverage.Classification) string {
	switch c.State {
	case jamfcoverage.MDMOther:
		if c.Vendor != "" {
			return "enrolled with " + c.Vendor + " (" + c.ServerHost + ")"
		}
		return "enrolled with another MDM at " + c.ServerHost
	case jamfcoverage.MDMJamfNoEvent:
		return "the Mac reports enrolment with Jamf (" + c.ServerHost + "), but Jamf has sent no event for it since setup"
	case jamfcoverage.MDMEnrolledUnidentified:
		return "the Mac reports MDM enrolment, but not which server"
	case jamfcoverage.MDMUnmanaged:
		return "the Mac reports no MDM enrolment"
	}
	return "no MDM enrolment evidence from the agent yet"
}

type jamfCoverageBuilt struct {
	out           jamfCoverageOut
	gap           []jamfGapRow
	notReported   []jamfNotReportedRow
	covered       []jamfCoveredRow
	osNotReported []jamfOSNotReportedRow
}

func buildJamfCoverage(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) (jamfCoverageBuilt, error) {
	var b jamfCoverageBuilt
	c, err := loadJamfConnector(ctx, pool, tenantID)
	if err != nil {
		return b, err
	}
	jd, err := loadJamfDevices(ctx, pool, tenantID)
	if err != nil {
		return b, err
	}
	pd, err := loadJamfPatchedDevices(ctx, pool, tenantID)
	if err != nil {
		return b, err
	}
	jamfHost := ""
	if c != nil && c.InstanceURL != nil {
		jamfHost = jamfcoverage.HostOf(*c.InstanceURL)
	}
	res := jamfcoverage.Reconcile(jd, pd, jamfHost)

	counts := jamfCountsOut{
		Gap: len(res.Gap), NotReportedByJamf: len(res.NotReported), Covered: len(res.Covered), JamfDevicesTotal: len(jd),
		RetiredExcluded: res.RetiredExcluded, NonMacDevicesExcluded: res.NonMacExcluded, OSNotReported: len(res.OSNotReported),
		NotReportedByJamfByMDMState: map[string]int{
			jamfcoverage.MDMOther: 0, jamfcoverage.MDMJamfNoEvent: 0, jamfcoverage.MDMEnrolledUnidentified: 0,
			jamfcoverage.MDMUnmanaged: 0, jamfcoverage.MDMUnknown: 0,
		},
	}
	b.gap = make([]jamfGapRow, 0, len(res.Gap))
	for _, d := range res.Gap {
		row := jamfGapRow{
			JamfID: d.JamfID, Serial: nilIfEmpty(d.Serial), UDID: nilIfEmpty(d.UDID),
			DeviceName: nilIfEmpty(d.DeviceName), Model: nilIfEmpty(d.Model), OSVersion: nilIfEmpty(d.OSVersion),
			JamfState: jamfStateOf(d), FirstJamfEventAt: d.FirstReceivedAt, LastJamfEventAt: d.LastEventAt,
			LastJamfEventType: d.LastEventType, DaysSinceJamfEvent: jamfcoverage.DaysSince(d.LastEventAt, now),
			Note: jamfGapNote(d, now),
		}
		if row.JamfState == "dep_assigned_only" {
			counts.GapDEPAssignedOnly++
		}
		if row.DaysSinceJamfEvent >= jamfcoverage.SilentAfterDays {
			counts.GapSilent++
		}
		b.gap = append(b.gap, row)
	}
	b.notReported = make([]jamfNotReportedRow, 0, len(res.NotReported))
	for _, u := range res.NotReported {
		counts.NotReportedByJamfByMDMState[u.MDM.State]++
		if u.MDM.State == jamfcoverage.MDMUnmanaged {
			counts.AgentReportsNoMDM++
		}
		b.notReported = append(b.notReported, jamfNotReportedRow{
			DeviceID: u.Device.ID, Hostname: nilIfEmpty(u.Device.Hostname), Serial: nilIfEmpty(strings.TrimSpace(u.Device.Serial)),
			OSVersion: nilIfEmpty(u.Device.OSVersion), LastSeen: u.Device.LastSeen,
			MDMState: u.MDM.State, MDMVendor: nilIfEmpty(u.MDM.Vendor), MDMServerHost: nilIfEmpty(u.MDM.ServerHost),
			Note: jamfMDMNote(u.MDM),
		})
	}
	b.osNotReported = make([]jamfOSNotReportedRow, 0, len(res.OSNotReported))
	for _, d := range res.OSNotReported {
		b.osNotReported = append(b.osNotReported, jamfOSNotReportedRow{
			DeviceID: d.ID, Hostname: nilIfEmpty(d.Hostname), Serial: nilIfEmpty(strings.TrimSpace(d.Serial)),
			OSVersion: nilIfEmpty(d.OSVersion), LastSeen: d.LastSeen,
		})
	}
	b.covered = make([]jamfCoveredRow, 0, len(res.Covered))
	for _, p := range res.Covered {
		row := jamfCoveredRow{
			DeviceID: p.Device.ID, Hostname: nilIfEmpty(p.Device.Hostname), Serial: nilIfEmpty(strings.TrimSpace(p.Device.Serial)),
			LastSeen: p.Device.LastSeen, JamfID: p.Jamf.JamfID, JamfDeviceName: nilIfEmpty(p.Jamf.DeviceName),
			LastJamfEventAt: p.Jamf.LastEventAt, DaysSinceJamfEvent: jamfcoverage.DaysSince(p.Jamf.LastEventAt, now),
			MatchBasis: p.MatchBasis, Note: jamfcoverage.SilenceNote(p.Jamf.LastEventAt, now),
		}
		if row.DaysSinceJamfEvent >= jamfcoverage.SilentAfterDays {
			counts.CoveredJamfSilent++
		}
		b.covered = append(b.covered, row)
	}
	b.out = jamfCoverageOut{
		GeneratedAt: now, Connector: jamfHealth(c, now), Basis: jamfBasis(c), Counts: counts,
	}
	return b, nil
}

// PortalJamfCoverageHandler serves GET /v1/portal/mdm/jamf/coverage
// ?bucket=gap|not_reported_by_jamf|covered|os_not_reported&limit=&offset=&format=json|csv.
//
// Without bucket, every bucket is returned, each paged by the same
// limit/offset. The CSV is unpaged (every row of the chosen bucket, or of
// all four with a bucket column), with formula injection neutralised.
func PortalJamfCoverageHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		format, ok := governanceFormat(w, r, "bucket", "limit", "offset")
		if !ok {
			return
		}
		q := r.URL.Query()
		bucket := q.Get("bucket")
		switch bucket {
		case "", jamfBucketGap, jamfBucketNotReported, jamfBucketCovered, jamfBucketOSNotReported:
		default:
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "bucket must be gap, not_reported_by_jamf, covered or os_not_reported", nil)
			return
		}
		limit, offset := jamfCoverageDefaultPage, 0
		if v := q.Get("limit"); v != "" {
			n, ok := strictPositiveInt(v, 1, jamfCoverageMaxPage)
			if !ok {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "limit must be 1 to 500", nil)
				return
			}
			limit = n
		}
		if v := q.Get("offset"); v != "" {
			n, ok := strictPositiveInt(v, 0, 1<<30)
			if !ok {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "offset must be 0 or more", nil)
				return
			}
			offset = n
		}
		ctx := r.Context()
		built, err := buildJamfCoverage(ctx, pool, id.TenantID, time.Now().UTC())
		if err != nil {
			if errors.Is(err, errJamfEstateTooLarge) {
				writeApprovalError(w, http.StatusUnprocessableEntity, "estate_too_large",
					"the estate is too large to reconcile in one request", nil)
				return
			}
			slog.Error("jamf coverage build failed", "req_id", middleware.GetReqID(ctx), "tenant_id", id.TenantID, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		if format == "csv" {
			writeJamfCoverageCSV(w, built, bucket)
			return
		}
		out := built.out
		out.Limit, out.Offset = limit, offset
		if bucket != "" {
			out.Bucket = &bucket
		}
		if bucket == "" || bucket == jamfBucketGap {
			out.Gap = &jamfBucketOut[jamfGapRow]{Total: len(built.gap), Rows: page(built.gap, limit, offset)}
		}
		if bucket == "" || bucket == jamfBucketNotReported {
			out.NotReportedByJamf = &jamfBucketOut[jamfNotReportedRow]{Total: len(built.notReported), Rows: page(built.notReported, limit, offset)}
		}
		if bucket == "" || bucket == jamfBucketCovered {
			out.Covered = &jamfBucketOut[jamfCoveredRow]{Total: len(built.covered), Rows: page(built.covered, limit, offset)}
		}
		if bucket == "" || bucket == jamfBucketOSNotReported {
			out.OSNotReported = &jamfBucketOut[jamfOSNotReportedRow]{Total: len(built.osNotReported), Rows: page(built.osNotReported, limit, offset)}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func jamfIDString(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

func writeJamfCoverageCSV(w http.ResponseWriter, b jamfCoverageBuilt, bucket string) {
	n := 0
	if bucket == "" || bucket == jamfBucketGap {
		n += len(b.gap)
	}
	if bucket == "" || bucket == jamfBucketNotReported {
		n += len(b.notReported)
	}
	if bucket == "" || bucket == jamfBucketCovered {
		n += len(b.covered)
	}
	if bucket == "" || bucket == jamfBucketOSNotReported {
		n += len(b.osNotReported)
	}
	cw := csvAttachment(w, "jamf-coverage", n)
	_ = cw.Write([]string{"bucket", "device_id", "hostname", "serial", "udid", "jamf_id", "jamf_device_name", "model",
		"os_version", "patched_last_seen", "first_jamf_event_at", "last_jamf_event_at", "days_since_jamf_event",
		"jamf_state", "mdm_state", "mdm_vendor", "mdm_server_host", "match_basis", "note", "basis", "generated_at"})
	basis, gen := b.out.Basis.Statement, fmtTime(b.out.GeneratedAt)
	if bucket == "" || bucket == jamfBucketGap {
		for _, r := range b.gap {
			_ = cw.Write([]string{jamfBucketGap, "", "", csvSafe(strOrEmpty(r.Serial)), csvSafe(strOrEmpty(r.UDID)),
				jamfIDString(r.JamfID), csvSafe(strOrEmpty(r.DeviceName)), csvSafe(strOrEmpty(r.Model)),
				csvSafe(strOrEmpty(r.OSVersion)), "", fmtTime(r.FirstJamfEventAt), fmtTime(r.LastJamfEventAt),
				strconv.Itoa(r.DaysSinceJamfEvent), r.JamfState, "", "", "", "", r.Note, basis, gen})
		}
	}
	if bucket == "" || bucket == jamfBucketNotReported {
		for _, r := range b.notReported {
			_ = cw.Write([]string{jamfBucketNotReported, r.DeviceID, csvSafe(strOrEmpty(r.Hostname)), csvSafe(strOrEmpty(r.Serial)),
				"", "", "", "", csvSafe(strOrEmpty(r.OSVersion)), fmtTime(r.LastSeen), "", "", "", "", r.MDMState,
				csvSafe(strOrEmpty(r.MDMVendor)), csvSafe(strOrEmpty(r.MDMServerHost)), "", csvSafe(r.Note), basis, gen})
		}
	}
	if bucket == "" || bucket == jamfBucketCovered {
		for _, r := range b.covered {
			_ = cw.Write([]string{jamfBucketCovered, r.DeviceID, csvSafe(strOrEmpty(r.Hostname)), csvSafe(strOrEmpty(r.Serial)),
				"", jamfIDString(r.JamfID), csvSafe(strOrEmpty(r.JamfDeviceName)), "", "", fmtTime(r.LastSeen), "",
				fmtTime(r.LastJamfEventAt), strconv.Itoa(r.DaysSinceJamfEvent), "", "", "", "", r.MatchBasis, r.Note, basis, gen})
		}
	}
	if bucket == "" || bucket == jamfBucketOSNotReported {
		for _, r := range b.osNotReported {
			_ = cw.Write([]string{jamfBucketOSNotReported, r.DeviceID, csvSafe(strOrEmpty(r.Hostname)), csvSafe(strOrEmpty(r.Serial)),
				"", "", "", "", csvSafe(strOrEmpty(r.OSVersion)), fmtTime(r.LastSeen), "", "", "", "", "",
				"", "", "", "", basis, gen})
		}
	}
	cw.Flush()
}
