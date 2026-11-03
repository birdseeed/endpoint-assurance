package handlers

// Customer portal device self-service writes (PAT-2135).
//
//   PUT    /v1/portal/devices/{deviceID}/retirement          retire or unretire one device
//   GET    /v1/portal/devices/{deviceID}/retirement/history  that device's retirement decisions
//   PUT    /v1/portal/device-list                            replace the customer's device list
//   GET    /v1/portal/device-list                            the list, reconciled against seen devices
//   DELETE /v1/portal/device-list                            clear the list (recorded, not erased)
//   DELETE /v1/portal/device-list/entries/{entryID}          remove one entry from the current list
//                                                             (PAT-2271; recorded in device_list_entry_deletions)
//
// These replace the /devices page's "Tell us it's gone" and "Send us a
// device list" mailto links: under the self-service model the customer
// makes the decision, nobody at Patched acts for them (ruled 2026-09-25).
//
// Same seam and rules as the software approval writes (PAT-2007,
// portal_software_approvals.go): tenant from the verified portal identity
// only, never from the client; writes need role 'admin', read from
// portal_users inside the write transaction (FOR SHARE), and any other role
// gets 403 admin_role_required with the same body shape; the actor recorded
// is the verified portal email. A device outside the caller's tenant
// answers 404, indistinguishable from a device that does not exist.
//
// Nothing here is reachable from the operator admin API, so no operator
// action is ever recorded as a customer decision. The operator-side device
// dispositions (0143) and device uploads (0140) are separate records.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/devicelist"
	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

const (
	retirementMaxBodyBytes    = 16 << 10
	retirementHistoryDefault  = 100
	retirementHistoryMax      = 500
	deviceListMaxBodyBytes    = 2 << 20
	deviceListResponseCap     = 500
	deviceListMatchBasisLabel = "serial_then_hostname"
)

// requirePortalAdmin re-reads the caller's role inside tx, holding the
// portal_users row FOR SHARE so a concurrent demotion waits for this write.
// It writes the 403 or 500 itself and returns false when the caller may not
// write.
func requirePortalAdmin(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, id portalauth.Identity, what string, logger *slog.Logger) bool {
	role, err := portalauth.DBRole(ctx, tx, id.Email, id.TenantID, true)
	if err != nil {
		logger.Error("role lookup failed", "err", err)
		writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		return false
	}
	if !portalauth.CanWrite(role) {
		writeApprovalError(w, http.StatusForbidden, "admin_role_required",
			"only a portal admin can "+what+"; your role is "+role, nil)
		return false
	}
	return true
}

// readLimitedBody reads at most max bytes, answering 400 or 413 itself.
func readLimitedBody(w http.ResponseWriter, r *http.Request, max int) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil {
		writeApprovalError(w, http.StatusBadRequest, "invalid_request", "could not read the request body", nil)
		return nil, false
	}
	if len(body) > max {
		writeApprovalError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large", nil)
		return nil, false
	}
	return body, true
}

// ---------------------------------------------------------------------------
// Retire device
// ---------------------------------------------------------------------------

type retirementWriteRequest struct {
	Retired *bool   `json:"retired"`
	Reason  *string `json:"reason"`
}

type retirementWriteResp struct {
	DeviceID   string                       `json:"device_id"`
	Retired    bool                         `json:"retired"`
	Changed    bool                         `json:"changed"`
	Retirement *deviceretirement.Retirement `json:"retirement"`
}

// validateRetirementReason trims the optional reason. Line breaks and tabs
// are allowed (it is free text); any other control character is refused.
func validateRetirementReason(in *string) (*string, string) {
	if in == nil {
		return nil, ""
	}
	t := strings.TrimSpace(*in)
	if !utf8.ValidString(t) {
		return nil, "reason is not valid UTF-8"
	}
	for _, c := range t {
		if unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t' {
			return nil, "reason contains control characters"
		}
	}
	if utf8.RuneCountInString(t) > deviceretirement.MaxReasonChars {
		return nil, fmt.Sprintf("reason must be at most %d characters", deviceretirement.MaxReasonChars)
	}
	if t == "" {
		return nil, ""
	}
	return &t, ""
}

// retirementBeforeDeviceLock is a test seam, nil in production: it runs
// after the role and body checks and before the per-device lock.
var retirementBeforeDeviceLock func(ctx context.Context, tenantID, deviceID string)

// PortalDeviceRetirementPutHandler serves PUT /v1/portal/devices/{deviceID}/retirement.
//
// Body {"retired": true|false, "reason": "..."}. Setting a device to the
// state it is already in is a no-op: 200, changed false, no row. Otherwise
// one device_retirement_decisions row records the change. Unretiring is a
// new 'unretire' row; nothing is updated or deleted.
func PortalDeviceRetirementPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_retirement", "tenant_id", id.TenantID)
		deviceID := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "deviceID")))
		if !looksLikeUUID(deviceID) {
			writeApprovalError(w, http.StatusNotFound, "not_found", "device not found", nil)
			return
		}
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err, "device_id", deviceID)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

		if !requirePortalAdmin(ctx, tx, w, id, "retire or unretire a device", logger) {
			return
		}
		body, ok := readLimitedBody(w, r, retirementMaxBodyBytes)
		if !ok {
			return
		}
		var req retirementWriteRequest
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error(), nil)
			return
		}
		if req.Retired == nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "retired must be true or false", nil)
			return
		}
		reason, bad := validateRetirementReason(req.Reason)
		if bad != "" {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", bad, nil)
			return
		}

		if retirementBeforeDeviceLock != nil {
			retirementBeforeDeviceLock(ctx, id.TenantID, deviceID)
		}
		// One writer per device at a time: the read of the current state
		// and the insert below cannot interleave with another retirement
		// write for the same device. An advisory lock rather than FOR UPDATE
		// on the devices row, so a retirement never blocks ingestion's
		// devices update; FOR KEY SHARE still holds the row against deletion.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			id.TenantID+"|"+deviceID+"|device-retirement"); err != nil {
			internal("retirement lock failed", err)
			return
		}
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT true FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid FOR KEY SHARE
		`, deviceID, id.TenantID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeApprovalError(w, http.StatusNotFound, "not_found", "device not found", nil)
				return
			}
			internal("device lookup failed", err)
			return
		}
		var current string
		if err := tx.QueryRow(ctx, `
			SELECT action FROM device_retirement_decisions
			WHERE tenant_id = $1::uuid AND device_id = $2::uuid
			ORDER BY id DESC LIMIT 1
		`, id.TenantID, deviceID).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			internal("current retirement lookup failed", err)
			return
		}
		wasRetired := current == deviceretirement.ActionRetire
		changed := wasRetired != *req.Retired
		if changed {
			action := deviceretirement.ActionUnretire
			if *req.Retired {
				action = deviceretirement.ActionRetire
			}
			// clock_timestamp, not now(): the decision time is when it was
			// recorded under the lock, not when this transaction began.
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_retirement_decisions (tenant_id, device_id, action, reason, actor_email, decided_at)
				VALUES ($1::uuid, $2::uuid, $3, $4, lower(btrim($5)), clock_timestamp())
			`, id.TenantID, deviceID, action, reason, id.Email); err != nil {
				internal("retirement insert failed", err)
				return
			}
		}
		ret, err := deviceretirement.Fetch(ctx, tx, id.TenantID, []string{deviceID})
		if err != nil {
			internal("retirement read-back failed", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		if changed {
			logger.Info("portal device retirement recorded", "device_id", deviceID, "retired", *req.Retired)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(retirementWriteResp{
			DeviceID: deviceID, Retired: *req.Retired, Changed: changed,
			Retirement: deviceretirement.Of(ret, deviceID),
		})
	}
}

type retirementDecision struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action"`
	Reason     *string   `json:"reason"`
	ActorEmail string    `json:"actor_email"`
	DecidedAt  time.Time `json:"decided_at"`
}

// PortalDeviceRetirementHistoryHandler serves
// GET /v1/portal/devices/{deviceID}/retirement/history?limit=&offset=,
// newest first. Readable by every portal role.
func PortalDeviceRetirementHistoryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_retirement_history", "tenant_id", id.TenantID)
		deviceID := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "deviceID")))
		if !looksLikeUUID(deviceID) {
			writeApprovalError(w, http.StatusNotFound, "not_found", "device not found", nil)
			return
		}
		q := r.URL.Query()
		for k := range q {
			if k != "limit" && k != "offset" {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", "unknown query parameter "+k, nil)
				return
			}
		}
		limit, offset := retirementHistoryDefault, 0
		if v := q.Get("limit"); v != "" {
			n, ok := strictPositiveInt(v, 1, retirementHistoryMax)
			if !ok {
				writeApprovalError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be 1 to %d", retirementHistoryMax), nil)
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

		owner, err := report.DeviceTenant(ctx, pool, deviceID)
		if err != nil || owner != id.TenantID {
			if err != nil && !errors.Is(err, report.ErrDeviceNotFound) {
				logger.Error("device ownership check failed", "err", err)
				writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
				return
			}
			writeApprovalError(w, http.StatusNotFound, "not_found", "device not found", nil)
			return
		}

		var total int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM device_retirement_decisions WHERE tenant_id = $1::uuid AND device_id = $2::uuid
		`, id.TenantID, deviceID).Scan(&total); err != nil {
			logger.Error("retirement history count failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		rows, err := pool.Query(ctx, `
			SELECT id, action, reason, actor_email, decided_at
			FROM device_retirement_decisions
			WHERE tenant_id = $1::uuid AND device_id = $2::uuid
			ORDER BY id DESC
			LIMIT $3 OFFSET $4
		`, id.TenantID, deviceID, limit, offset)
		if err != nil {
			logger.Error("retirement history query failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		decisions := []retirementDecision{}
		for rows.Next() {
			var d retirementDecision
			if err := rows.Scan(&d.ID, &d.Action, &d.Reason, &d.ActorEmail, &d.DecidedAt); err != nil {
				rows.Close()
				logger.Error("retirement history scan failed", "err", err)
				writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
				return
			}
			d.DecidedAt = d.DecidedAt.UTC()
			decisions = append(decisions, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			logger.Error("retirement history iterate failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		ret, err := deviceretirement.Fetch(ctx, pool, id.TenantID, []string{deviceID})
		if err != nil {
			logger.Error("retirement read failed", "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": deviceID, "retirement": deviceretirement.Of(ret, deviceID),
			"total": total, "limit": limit, "offset": offset, "returned": len(decisions), "decisions": decisions,
		})
	}
}

// ---------------------------------------------------------------------------
// Customer device list
// ---------------------------------------------------------------------------

type deviceListWriteRequest struct {
	Filename *string                 `json:"filename"`
	Entries  []devicelist.InputEntry `json:"entries"`
}

type deviceListSummary struct {
	UploadedAt time.Time `json:"uploaded_at"`
	UploadedBy string    `json:"uploaded_by"`
	Filename   *string   `json:"filename"`
	EntryCount int       `json:"entry_count"`
}

type deviceListCleared struct {
	ClearedAt time.Time `json:"cleared_at"`
	ClearedBy string    `json:"cleared_by"`
}

type deviceListWriteResp struct {
	List                *deviceListSummary `json:"list"`
	ReceivedCount       int                `json:"received_count"`
	DuplicatesCollapsed int                `json:"duplicates_collapsed"`
}

// lockTenantDeviceList serialises writers of one tenant's device list, so
// "the latest upload" is well defined.
func lockTenantDeviceList(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID+"|device-list")
	return err
}

// PortalDeviceListPutHandler serves PUT /v1/portal/device-list.
//
// Body {"filename": "...", "entries": [{"hostname": "...", "serial": "..."|null}]}.
// Replaces the tenant's current list wholesale; the previous upload is kept
// as history. An empty entries array is refused: clearing the list is
// DELETE, so an empty upload can never be sent by mistake.
func PortalDeviceListPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_list_put", "tenant_id", id.TenantID)
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

		if !requirePortalAdmin(ctx, tx, w, id, "upload a device list", logger) {
			return
		}
		body, ok := readLimitedBody(w, r, deviceListMaxBodyBytes)
		if !ok {
			return
		}
		var req deviceListWriteRequest
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error(), nil)
			return
		}
		if req.Entries == nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_request", "entries is required", nil)
			return
		}
		if len(req.Entries) == 0 {
			writeApprovalError(w, http.StatusBadRequest, "empty_list",
				"entries is empty; to remove your device list, clear it instead", nil)
			return
		}
		if len(req.Entries) > devicelist.MaxEntries {
			writeApprovalError(w, http.StatusBadRequest, "too_many_entries",
				fmt.Sprintf("a device list can have at most %d entries", devicelist.MaxEntries), nil)
			return
		}
		var filename *string
		if req.Filename != nil {
			f, bad := devicelist.CheckField(*req.Filename)
			if bad != "" {
				writeApprovalError(w, http.StatusBadRequest, "invalid_filename", "filename "+bad, nil)
				return
			}
			if f != "" {
				filename = &f
			}
		}
		entries, dups, verr := devicelist.Validate(req.Entries)
		if verr != nil {
			writeApprovalError(w, http.StatusBadRequest, "invalid_entry", verr.Error(),
				[]approvalItemError{{Index: verr.Index, Code: verr.Code, Message: verr.Message}})
			return
		}

		if err := lockTenantDeviceList(ctx, tx, id.TenantID); err != nil {
			internal("device list lock failed", err)
			return
		}
		var uploadID int64
		sum := deviceListSummary{Filename: filename, EntryCount: len(entries)}
		if err := tx.QueryRow(ctx, `
			INSERT INTO device_list_uploads (tenant_id, actor_email, filename, entry_count)
			VALUES ($1::uuid, lower(btrim($2)), $3, $4)
			RETURNING id, uploaded_at, actor_email
		`, id.TenantID, id.Email, filename, len(entries)).Scan(&uploadID, &sum.UploadedAt, &sum.UploadedBy); err != nil {
			internal("device list upload insert failed", err)
			return
		}
		positions := make([]int32, len(entries))
		hosts, hostsN, serials, serialsN := make([]*string, len(entries)), make([]*string, len(entries)),
			make([]*string, len(entries)), make([]*string, len(entries))
		for i, e := range entries {
			positions[i] = int32(e.Position)
			hosts[i], hostsN[i] = nilIfEmpty(e.Hostname), nilIfEmpty(e.HostnameNormalized)
			serials[i], serialsN[i] = nilIfEmpty(e.Serial), nilIfEmpty(e.SerialNormalized)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_list_entries (upload_id, position, hostname, hostname_normalized, serial, serial_normalized)
			SELECT $1, u.position, u.hostname, u.hostname_normalized, u.serial, u.serial_normalized
			FROM unnest($2::int[], $3::text[], $4::text[], $5::text[], $6::text[])
			     AS u(position, hostname, hostname_normalized, serial, serial_normalized)
		`, uploadID, positions, hosts, hostsN, serials, serialsN); err != nil {
			internal("device list entries insert failed", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		sum.UploadedAt = sum.UploadedAt.UTC()
		logger.Info("portal device list uploaded", "upload_id", uploadID, "entries", len(entries), "duplicates", dups)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deviceListWriteResp{List: &sum, ReceivedCount: len(req.Entries), DuplicatesCollapsed: dups})
	}
}

// PortalDeviceListDeleteHandler serves DELETE /v1/portal/device-list: the
// customer clears their list. Recorded as a cleared upload row, so the
// history keeps the previous list and who cleared it. Clearing when there
// is no current list is a no-op (200, changed false).
func PortalDeviceListDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_list_delete", "tenant_id", id.TenantID)
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

		if !requirePortalAdmin(ctx, tx, w, id, "clear the device list", logger) {
			return
		}
		if err := lockTenantDeviceList(ctx, tx, id.TenantID); err != nil {
			internal("device list lock failed", err)
			return
		}
		var cleared bool
		err = tx.QueryRow(ctx, `
			SELECT cleared FROM device_list_uploads WHERE tenant_id = $1::uuid ORDER BY id DESC LIMIT 1
		`, id.TenantID).Scan(&cleared)
		if errors.Is(err, pgx.ErrNoRows) {
			cleared = true // nothing to clear
		} else if err != nil {
			internal("current device list lookup failed", err)
			return
		}
		resp := map[string]any{"changed": false, "cleared": nil}
		if !cleared {
			var c deviceListCleared
			if err := tx.QueryRow(ctx, `
				INSERT INTO device_list_uploads (tenant_id, actor_email, filename, entry_count, cleared)
				VALUES ($1::uuid, lower(btrim($2)), NULL, 0, TRUE)
				RETURNING uploaded_at, actor_email
			`, id.TenantID, id.Email).Scan(&c.ClearedAt, &c.ClearedBy); err != nil {
				internal("device list clear insert failed", err)
				return
			}
			c.ClearedAt = c.ClearedAt.UTC()
			resp["changed"], resp["cleared"] = true, c
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

type deviceListEntryOut struct {
	// EntryID is device_list_entries.id (PAT-2271): stable across reads of
	// the same upload, so the portal can target it for
	// DELETE /v1/portal/device-list/entries/{entryID}.
	EntryID  int64   `json:"entry_id"`
	Index    int     `json:"index"`
	Hostname *string `json:"hostname"`
	Serial   *string `json:"serial"`
}

type deviceListDeviceOut struct {
	DeviceID string  `json:"device_id"`
	Hostname *string `json:"hostname"`
	Serial   *string `json:"serial"`
}

// deviceListMatchDeviceOut is deviceListDeviceOut plus the one field a
// matched device needs that a seen-not-on-list device doesn't: whether the
// match is against a retired device (PAT-2271).
type deviceListMatchDeviceOut struct {
	deviceListDeviceOut
	Retired bool `json:"retired"`
}

// deviceListMatchOut is one matched entry (PAT-2271): the uploaded entry,
// in the same shape as an on_list_never_seen row, plus the device it
// matched.
type deviceListMatchOut struct {
	deviceListEntryOut
	Device deviceListMatchDeviceOut `json:"device"`
}

type deviceListReadResp struct {
	GeneratedAt time.Time          `json:"generated_at"`
	List        *deviceListSummary `json:"list"`
	Cleared     *deviceListCleared `json:"cleared"`
	MatchBasis  string             `json:"match_basis"`
	// MatchedCount is the number of list entries that match a seen device;
	// MatchedRetiredCount is how many of those match only retired devices.
	// Matched is one row per matched entry (PAT-2271) — always exactly
	// MatchedCount long, never capped or truncated, unlike the two arrays
	// below.
	MatchedCount          int                   `json:"matched_count"`
	MatchedRetiredCount   int                   `json:"matched_retired_count"`
	Matched               []deviceListMatchOut  `json:"matched"`
	OnListNeverSeen       []deviceListEntryOut  `json:"on_list_never_seen"`
	OnListNeverSeenTotal  int                   `json:"on_list_never_seen_total"`
	SeenNotOnList         []deviceListDeviceOut `json:"seen_not_on_list"`
	SeenNotOnListTotal    int                   `json:"seen_not_on_list_total"`
	Limit                 int                   `json:"limit"`
	Truncated             bool                  `json:"truncated"`
	OnListNeverSeenCapped bool                  `json:"on_list_never_seen_truncated"`
	SeenNotOnListCapped   bool                  `json:"seen_not_on_list_truncated"`
}

// PortalDeviceListGetHandler serves GET /v1/portal/device-list: the current
// list and its reconciliation against the devices Patched has seen.
// Readable by every portal role. Each of the two lists is capped at
// deviceListResponseCap rows, with its full total alongside.
func PortalDeviceListGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_list_get", "tenant_id", id.TenantID)
		fail := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}
		resp := deviceListReadResp{
			GeneratedAt: time.Now().UTC(), MatchBasis: deviceListMatchBasisLabel, Limit: deviceListResponseCap,
			OnListNeverSeen: []deviceListEntryOut{}, SeenNotOnList: []deviceListDeviceOut{}, Matched: []deviceListMatchOut{},
		}

		var uploadID int64
		var cleared bool
		var sum deviceListSummary
		err := pool.QueryRow(ctx, `
			SELECT id, uploaded_at, actor_email, filename, entry_count, cleared
			FROM device_list_uploads WHERE tenant_id = $1::uuid ORDER BY id DESC LIMIT 1
		`, id.TenantID).Scan(&uploadID, &sum.UploadedAt, &sum.UploadedBy, &sum.Filename, &sum.EntryCount, &cleared)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			fail("device list lookup failed", err)
			return
		case cleared:
			resp.Cleared = &deviceListCleared{ClearedAt: sum.UploadedAt.UTC(), ClearedBy: sum.UploadedBy}
		default:
			sum.UploadedAt = sum.UploadedAt.UTC()
			resp.List = &sum
		}
		if resp.List == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		rows, err := pool.Query(ctx, `
			SELECT id, position, COALESCE(hostname, ''), COALESCE(hostname_normalized, ''),
			       COALESCE(serial, ''), COALESCE(serial_normalized, '')
			FROM device_list_entries WHERE upload_id = $1 ORDER BY position
		`, uploadID)
		if err != nil {
			fail("device list entries query failed", err)
			return
		}
		var entries []devicelist.Entry
		for rows.Next() {
			var e devicelist.Entry
			if err := rows.Scan(&e.ID, &e.Position, &e.Hostname, &e.HostnameNormalized, &e.Serial, &e.SerialNormalized); err != nil {
				rows.Close()
				fail("device list entries scan failed", err)
				return
			}
			entries = append(entries, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			fail("device list entries iterate failed", err)
			return
		}

		drows, err := pool.Query(ctx, `
			SELECT d.id::text, COALESCE(d.hostname, ''), COALESCE(d.serial, ''), `+deviceretirement.RetiredSQL("d")+`
			FROM devices d WHERE d.tenant_id = $1::uuid
		`, id.TenantID)
		if err != nil {
			fail("device list devices query failed", err)
			return
		}
		var devices []devicelist.Device
		for drows.Next() {
			var d devicelist.Device
			if err := drows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.Retired); err != nil {
				drows.Close()
				fail("device list devices scan failed", err)
				return
			}
			devices = append(devices, d)
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			fail("device list devices iterate failed", err)
			return
		}

		res := devicelist.Reconcile(entries, devices)
		resp.MatchedCount, resp.MatchedRetiredCount = res.MatchedCount, res.MatchedRetiredCount
		resp.OnListNeverSeenTotal, resp.SeenNotOnListTotal = len(res.OnListNeverSeen), len(res.SeenNotOnList)
		// Matched is never capped: it must agree exactly with MatchedCount.
		for _, m := range res.Matched {
			resp.Matched = append(resp.Matched, deviceListMatchOut{
				deviceListEntryOut: deviceListEntryOut{
					EntryID: m.Entry.ID, Index: m.Entry.Position, Hostname: nilIfEmpty(m.Entry.Hostname), Serial: nilIfEmpty(m.Entry.Serial)},
				Device: deviceListMatchDeviceOut{
					deviceListDeviceOut: deviceListDeviceOut{
						DeviceID: m.Device.ID, Hostname: nilIfEmpty(m.Device.Hostname), Serial: nilIfEmpty(strings.TrimSpace(m.Device.Serial))},
					Retired: m.Device.Retired,
				},
			})
		}
		for i, e := range res.OnListNeverSeen {
			if i == deviceListResponseCap {
				resp.OnListNeverSeenCapped = true
				break
			}
			resp.OnListNeverSeen = append(resp.OnListNeverSeen, deviceListEntryOut{
				EntryID: e.ID, Index: e.Position, Hostname: nilIfEmpty(e.Hostname), Serial: nilIfEmpty(e.Serial)})
		}
		for i, d := range res.SeenNotOnList {
			if i == deviceListResponseCap {
				resp.SeenNotOnListCapped = true
				break
			}
			resp.SeenNotOnList = append(resp.SeenNotOnList, deviceListDeviceOut{
				DeviceID: d.ID, Hostname: nilIfEmpty(d.Hostname), Serial: nilIfEmpty(strings.TrimSpace(d.Serial))})
		}
		resp.Truncated = resp.OnListNeverSeenCapped || resp.SeenNotOnListCapped
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

type deviceListEntryDeleteResp struct {
	Deleted bool  `json:"deleted"`
	EntryID int64 `json:"entry_id"`
}

// PortalDeviceListEntryDeleteHandler serves
// DELETE /v1/portal/device-list/entries/{entryID} (PAT-2271): removes
// exactly one entry from the tenant's *current* device list (the latest
// upload, when it is not cleared) and records the deletion in
// device_list_entry_deletions. Same role, per-tenant lock and CSRF/auth
// pattern (the portalauth middleware mounted on the whole /v1/portal group)
// as PortalDeviceListDeleteHandler. An entryID from another tenant, from a
// superseded (non-current) upload, or with no current list at all all
// answer 404 not_found, indistinguishable from an entry that never existed.
func PortalDeviceListEntryDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		logger := slog.With("req_id", middleware.GetReqID(ctx), "handler", "portal_device_list_entry_delete", "tenant_id", id.TenantID)
		internal := func(msg string, err error) {
			logger.Error(msg, "err", err)
			writeApprovalError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		}
		notFound := func() {
			writeApprovalError(w, http.StatusNotFound, "not_found", "device list entry not found", nil)
		}
		entryID, perr := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "entryID")), 10, 64)
		if perr != nil || entryID <= 0 {
			notFound()
			return
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			internal("begin tx failed", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

		if !requirePortalAdmin(ctx, tx, w, id, "delete a device list entry", logger) {
			return
		}
		if err := lockTenantDeviceList(ctx, tx, id.TenantID); err != nil {
			internal("device list lock failed", err)
			return
		}

		var uploadID int64
		var cleared bool
		err = tx.QueryRow(ctx, `
			SELECT id, cleared FROM device_list_uploads WHERE tenant_id = $1::uuid ORDER BY id DESC LIMIT 1
		`, id.TenantID).Scan(&uploadID, &cleared)
		if errors.Is(err, pgx.ErrNoRows) {
			notFound()
			return
		}
		if err != nil {
			internal("current device list lookup failed", err)
			return
		}
		if cleared {
			notFound()
			return
		}

		var position int
		var hostname, serial *string
		err = tx.QueryRow(ctx, `
			DELETE FROM device_list_entries WHERE id = $1 AND upload_id = $2
			RETURNING position, hostname, serial
		`, entryID, uploadID).Scan(&position, &hostname, &serial)
		if errors.Is(err, pgx.ErrNoRows) {
			notFound()
			return
		}
		if err != nil {
			internal("device list entry delete failed", err)
			return
		}
		if _, err := tx.Exec(ctx, `
			UPDATE device_list_uploads SET entry_count = entry_count - 1 WHERE id = $1
		`, uploadID); err != nil {
			internal("device list entry count update failed", err)
			return
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_list_entry_deletions (tenant_id, upload_id, entry_id, position, hostname, serial, actor_email)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, lower(btrim($7)))
		`, id.TenantID, uploadID, entryID, position, hostname, serial, id.Email); err != nil {
			internal("device list entry deletion audit failed", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			internal("commit failed", err)
			return
		}
		logger.Info("portal device list entry deleted", "entry_id", entryID, "upload_id", uploadID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deviceListEntryDeleteResp{Deleted: true, EntryID: entryID})
	}
}
