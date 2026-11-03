package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/releasecontrol"
)

func releaseError(w http.ResponseWriter, err error) {
	slog.Error("agent release request failed", "err", err)
	writeApprovalError(w, 500, "internal_error", "release control unavailable", nil)
}
func releaseJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func isSafeVersionSegment(v string) bool { return len(v) <= 100 && isValidArtifactPathComponent(v) }
func projectAgentReleaseConfig(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, row *agentConfigRow) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = releasecontrol.TenantLock(ctx, tx, tenantID); err != nil {
		return err
	}
	// Every due notice gets durable activation provenance. One projection needs
	// one new generation even when several notices became due since the last GET.
	var activated bool
	err = tx.QueryRow(ctx, `WITH due AS (SELECT id FROM agent_release_p0_notices WHERE tenant_id=$1::uuid AND scheduled_at<=clock_timestamp()), ins AS (INSERT INTO agent_release_p0_activations (notice_id,tenant_id) SELECT id,$1::uuid FROM due ON CONFLICT DO NOTHING RETURNING notice_id) SELECT EXISTS(SELECT 1 FROM ins)`, tenantID).Scan(&activated)
	if err != nil {
		return err
	}
	if activated {
		if _, err = bumpAgentConfigVersionForDecommission(ctx, tx, tenantID); err != nil {
			return err
		}
	}
	current, found, err := dbGetAgentConfigViaQuerier(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if found {
		*row = current
	}
	if err = releasecontrol.Project(ctx, tx, tenantID, deviceID, &row.Body); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type releaseWrite struct {
	Action    string   `json:"action"`
	DeviceIDs []string `json:"device_ids,omitempty"`
	Channel   *string  `json:"channel,omitempty"`
}

// PortalAgentReleaseWriteHandler is one atomic control endpoint. Tenant and
// actor come exclusively from the authenticated identity; JWT roles are not
// write authority. A DB role lock prevents concurrent demotion racing the write.
func PortalAgentReleaseWriteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if !requirePortalAdmin(ctx, tx, w, id, "change agent release settings", slog.Default()) {
			return
		}
		body, ok := readLimitedBody(w, r, 64<<10)
		if !ok {
			return
		}
		var req releaseWrite
		if err = decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		if err = releasecontrol.SharedLock(ctx, tx); err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.TenantLock(ctx, tx, id.TenantID); err != nil {
			releaseError(w, err)
			return
		}
		var pin *string
		switch req.Action {
		case "device_channels":
			if len(req.DeviceIDs) == 0 || len(req.DeviceIDs) > 500 || req.Channel != nil && *req.Channel != "beta" {
				writeApprovalError(w, 400, "invalid_request", "device_ids must contain 1 to 500 devices; channel must be beta, or null/omitted to clear", nil)
				return
			}
			sort.Strings(req.DeviceIDs)
			for i, deviceID := range req.DeviceIDs {
				if !looksLikeUUID(deviceID) || i > 0 && deviceID == req.DeviceIDs[i-1] {
					writeApprovalError(w, 400, "invalid_request", "device IDs must be unique UUIDs", nil)
					return
				}
				var exists bool
				err = tx.QueryRow(ctx, `SELECT true FROM devices WHERE id=$1::uuid AND tenant_id=$2::uuid FOR KEY SHARE`, deviceID, id.TenantID).Scan(&exists)
				if errors.Is(err, pgx.ErrNoRows) {
					writeApprovalError(w, 404, "not_found", "device not found", nil)
					return
				}
				if err != nil {
					releaseError(w, err)
					return
				}
				if req.Channel == nil {
					_, err = tx.Exec(ctx, `DELETE FROM agent_device_channels WHERE device_id=$1::uuid`, deviceID)
				} else {
					_, err = tx.Exec(ctx, `INSERT INTO agent_device_channels (device_id,channel,baseline_faults,baseline_health_at,actor)
      SELECT $1::uuid,$2,COALESCE((SELECT jsonb_agg(jsonb_build_array(kind,subject) ORDER BY kind,subject) FROM device_agent_health WHERE device_id=$1::uuid),'[]'::jsonb),
      (SELECT collected_at FROM device_agent_health_watermark WHERE device_id=$1::uuid),$3
      ON CONFLICT (device_id) DO UPDATE SET channel=EXCLUDED.channel,entered_at=EXCLUDED.entered_at,baseline_faults=EXCLUDED.baseline_faults,baseline_health_at=EXCLUDED.baseline_health_at,actor=EXCLUDED.actor
      WHERE agent_device_channels.channel<>EXCLUDED.channel`, deviceID, *req.Channel, id.Email)
				}
				if err != nil {
					releaseError(w, err)
					return
				}
			}
		case "hold", "clear_hold", "approve":
			if len(req.DeviceIDs) > 0 || req.Channel != nil {
				writeApprovalError(w, 400, "invalid_request", "device fields are only allowed for device_channels", nil)
				return
			}
			if req.Action != "clear_hold" {
				var v string
				if req.Action == "hold" {
					// Existing effective stable pin is the version to hold, if present.
					var current *string
					err = tx.QueryRow(ctx, `SELECT COALESCE(s.pinned_version,a.body->>'pinned_version') FROM tenants t LEFT JOIN agent_release_settings s ON s.tenant_id=t.id LEFT JOIN agent_config a ON a.tenant_id=t.id WHERE t.id=$1::uuid`, id.TenantID).Scan(&current)
					if err != nil {
						releaseError(w, err)
						return
					}
					if current != nil {
						v = *current
					}
				}
				if v == "" {
					v, err = releasecontrol.CommonStable(ctx, tx, id.TenantID)
					if err != nil {
						writeApprovalError(w, 409, "stable_version_unavailable", err.Error(), nil)
						return
					}
				}
				// Existing pins must also resolve to stable on every estate platform.
				var missing bool
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM (VALUES ('macos'),('windows')) p(platform)
 WHERE (EXISTS(SELECT 1 FROM devices WHERE tenant_id=$1::uuid AND lower(os)=p.platform)
 OR NOT EXISTS(SELECT 1 FROM devices WHERE tenant_id=$1::uuid AND lower(os) IN ('macos','windows')))
 AND NOT EXISTS(SELECT 1 FROM agent_versions WHERE platform=p.platform AND channel='stable' AND version=$2))`, id.TenantID, v).Scan(&missing)
				if err != nil {
					releaseError(w, err)
					return
				}
				if missing {
					writeApprovalError(w, 409, "stable_version_unavailable", "pin is not stable on every estate platform", nil)
					return
				}
				pin = &v
				if req.Action == "approve" {
					effective, active, e := releasecontrol.P0Pin(ctx, tx, id.TenantID, pin)
					if e != nil {
						writeApprovalError(w, 409, "version_order_ambiguous", e.Error(), nil)
						return
					}
					if active && *effective != v {
						writeApprovalError(w, 409, "p0_floor_required", "latest stable is below the required critical security update", nil)
						return
					}
				}
			}
			if req.Action == "clear_hold" {
				_, err = tx.Exec(ctx, `INSERT INTO agent_release_settings (tenant_id,hold,pinned_version) VALUES ($1::uuid,false,NULL) ON CONFLICT (tenant_id) DO UPDATE SET hold=false,pinned_version=NULL`, id.TenantID)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO agent_release_settings (tenant_id,hold,pinned_version) VALUES ($1::uuid,$2,$3) ON CONFLICT (tenant_id) DO UPDATE SET hold=EXCLUDED.hold,pinned_version=EXCLUDED.pinned_version`, id.TenantID, req.Action == "hold", pin)
			}
			if err != nil {
				releaseError(w, err)
				return
			}
		default:
			writeApprovalError(w, 400, "invalid_request", "action must be device_channels, hold, clear_hold, or approve", nil)
			return
		}
		if err = releasecontrol.Audit(ctx, tx, &id.TenantID, id.Email, "portal", req.Action, map[string]any{"request": req, "pinned_version": pin}); err != nil {
			releaseError(w, err)
			return
		}
		if _, err = bumpAgentConfigVersionForDecommission(ctx, tx, id.TenantID); err != nil {
			releaseError(w, err)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]any{"action": req.Action, "pinned_version": pin})
	}
}

type releaseDevice struct {
	DeviceID                 string                            `json:"device_id,omitempty"`
	Platform                 string                            `json:"platform"`
	Override                 *string                           `json:"override"`
	EffectiveChannel         string                            `json:"effective_channel"`
	EffectiveVersion         *string                           `json:"effective_version"`
	ObservedVersion          *string                           `json:"observed_version"`
	CanaryHealth             *releasecontrol.DeviceHealth      `json:"canary_health"`
	UpdateChannelObservation *updateChannelObservationResponse `json:"update_channel_observation,omitempty"`
}
type updateChannelObservationResponse struct {
	Channel       string    `json:"channel"`
	Source        string    `json:"source"`
	ConfigVersion int       `json:"config_version"`
	ObservedAt    time.Time `json:"observed_at"`
}
type releaseNotice struct {
	ID               int64      `json:"id"`
	Version          string     `json:"version"`
	Banner           string     `json:"banner"`
	ScheduledAt      time.Time  `json:"scheduled_at"`
	EmailDueAt       time.Time  `json:"email_due_at"`
	EmailStatus      string     `json:"email_status"`
	EmailAttempts    int        `json:"email_attempts"`
	EmailDeliveredAt *time.Time `json:"email_delivered_at"`
}

func PortalAgentReleaseGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		var channel string
		var pin *string
		var hold bool
		err = tx.QueryRow(ctx, `SELECT COALESCE(a.body->>'update_channel','stable'),COALESCE(s.pinned_version,a.body->>'pinned_version'),COALESCE(s.hold,false) FROM tenants t LEFT JOIN agent_config a ON a.tenant_id=t.id LEFT JOIN agent_release_settings s ON s.tenant_id=t.id WHERE t.id=$1::uuid`, id.TenantID).Scan(&channel, &pin, &hold)
		if err != nil {
			releaseError(w, err)
			return
		}
		latest := map[string]map[string]string{}
		health := map[string]releasecontrol.Health{}
		for _, p := range validAgentVersionPlatforms {
			latest[p] = map[string]string{}
			for _, ch := range []string{"beta", "stable"} {
				var v string
				err = tx.QueryRow(ctx, `SELECT version FROM agent_versions WHERE platform=$1 AND channel=$2 ORDER BY published_at DESC,id DESC LIMIT 1`, p, ch).Scan(&v)
				if err != nil && err != pgx.ErrNoRows {
					releaseError(w, err)
					return
				}
				if err == nil {
					latest[p][ch] = v
				}
			}
			if v, ok := latest[p]["beta"]; ok {
				h, e := releasecontrol.Gate(ctx, tx, p, v, time.Now().UTC())
				if e != nil {
					releaseError(w, e)
					return
				}
				health[p] = h
			}
		}
		var p0 *releaseNotice
		n := releaseNotice{}
		err = tx.QueryRow(ctx, `SELECT id,version,banner,scheduled_at,email_due_at,email_status,email_attempts,email_delivered_at FROM agent_release_p0_notices WHERE tenant_id=$1::uuid ORDER BY scheduled_at DESC,id DESC LIMIT 1`, id.TenantID).Scan(&n.ID, &n.Version, &n.Banner, &n.ScheduledAt, &n.EmailDueAt, &n.EmailStatus, &n.EmailAttempts, &n.EmailDeliveredAt)
		if err != nil && err != pgx.ErrNoRows {
			releaseError(w, err)
			return
		}
		if err == nil {
			p0 = &n
		}
		duePin, activeP0, err := releasecontrol.P0Pin(ctx, tx, id.TenantID, pin)
		if err != nil {
			releaseError(w, err)
			return
		}
		if !activeP0 {
			duePin = nil
		}
		rows, err := tx.Query(ctx, `SELECT d.id::text,lower(d.os),c.channel,d.agent_version,o.channel,o.source,o.config_version,o.observed_at FROM devices d LEFT JOIN agent_device_channels c ON c.device_id=d.id LEFT JOIN LATERAL (SELECT channel,source,config_version,observed_at FROM agent_update_channel_observations WHERE tenant_id=d.tenant_id AND device_id=d.id ORDER BY observed_at DESC,received_at DESC,id DESC LIMIT 1) o ON true WHERE d.tenant_id=$1::uuid ORDER BY d.id`, id.TenantID)
		if err != nil {
			releaseError(w, err)
			return
		}
		devices := []releaseDevice{}
		for rows.Next() {
			var d releaseDevice
			var platform, observedChannel, observedSource *string
			var configVersion *int
			var observedAt *time.Time
			if err = rows.Scan(&d.DeviceID, &platform, &d.Override, &d.ObservedVersion, &observedChannel, &observedSource, &configVersion, &observedAt); err != nil {
				rows.Close()
				releaseError(w, err)
				return
			}
			// devices.os is nullable. A device that reported no OS has no
			// platform, so it matches no latest-version or canary entry and is
			// offered no version (PAT-2538).
			if platform != nil {
				d.Platform = *platform
			}
			if observedChannel != nil && observedSource != nil && configVersion != nil && observedAt != nil {
				d.UpdateChannelObservation = &updateChannelObservationResponse{Channel: *observedChannel, Source: *observedSource, ConfigVersion: *configVersion, ObservedAt: *observedAt}
			}
			d.EffectiveChannel = channel
			if d.Override != nil {
				d.EffectiveChannel = *d.Override
			}
			v := latest[d.Platform][d.EffectiveChannel]
			if pin != nil {
				v = *pin
			}
			if duePin != nil {
				d.EffectiveChannel = "stable"
				v = *duePin
			}
			if v != "" {
				d.EffectiveVersion = &v
			}
			for _, ch := range health[d.Platform].Devices {
				if ch.DeviceID == d.DeviceID {
					c := ch
					d.CanaryHealth = &c
				}
			}
			devices = append(devices, d)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			releaseError(w, err)
			return
		}
		// Do not leak other tenants' device IDs or faults from the global gate.
		for p, h := range health {
			h.Devices = nil
			health[p] = h
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]any{"channel": channel, "pinned_version": pin, "hold": hold, "latest": latest, "devices": devices, "canary_health": health, "p0_notice": p0, "p0_effective_version": duePin})
	}
}

type releaseEvidenceReq struct {
	DeviceID    string    `json:"device_id"`
	Platform    string    `json:"platform"`
	Version     string    `json:"version"`
	Metric      string    `json:"metric"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Attempts    int64     `json:"attempts"`
	Failures    int64     `json:"failures"`
	Provenance  string    `json:"provenance"`
}

func validReleaseEvidence(req releaseEvidenceReq, now time.Time) error {
	if !isValidAgentVersionPlatform(req.Platform) || !isSafeVersionSegment(req.Version) {
		return errors.New("platform or version is invalid")
	}
	switch req.Metric {
	case "artifact_verification", "config_verification", "service_crash", "restart_loop", "enrolment", "upload":
	default:
		return errors.New("unknown metric")
	}
	if req.Metric == "enrolment" || req.Metric == "upload" {
		if req.DeviceID != "" {
			return errors.New("rate evidence is aggregate and must omit device_id")
		}
	} else if !looksLikeUUID(req.DeviceID) {
		return errors.New("blocker evidence needs a device_id UUID")
	}
	if req.WindowStart.IsZero() || !req.WindowEnd.After(req.WindowStart) || req.WindowEnd.After(now.Add(5*time.Minute)) {
		return errors.New("invalid evidence window")
	}
	if req.Attempts < 1 || req.Attempts > 1000000000 || req.Failures < 0 || req.Failures > req.Attempts {
		return errors.New("attempts/failures invalid")
	}
	if strings.TrimSpace(req.Provenance) == "" || len(req.Provenance) > 500 || strings.ContainsAny(req.Provenance, "\x00\r\n") {
		return errors.New("bounded single-line provenance required")
	}
	return nil
}

// Internal token authenticates the reporting service; callers cannot claim a
// customer actor. Provenance identifies the monitor/run behind the window.
func AdminAgentReleaseEvidenceHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readLimitedBody(w, r, 16<<10)
		if !ok {
			return
		}
		var req releaseEvidenceReq
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		if err := validReleaseEvidence(req, time.Now()); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if err = releasecontrol.Lock(ctx, tx); err != nil {
			releaseError(w, err)
			return
		}
		var tenantID *string
		var deviceID *string
		if req.DeviceID != "" {
			deviceID = &req.DeviceID
			err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM devices WHERE id=$1::uuid AND (lower(os)=$2 OR ($2='macos-menubar' AND lower(os)='macos')) AND EXISTS(SELECT 1 FROM agent_versions WHERE platform=$2 AND version=$3)`, req.DeviceID, req.Platform, req.Version).Scan(&tenantID)
		} else {
			var exists bool
			err = tx.QueryRow(ctx, `SELECT true FROM agent_versions WHERE platform=$1 AND version=$2 LIMIT 1`, req.Platform, req.Version).Scan(&exists)
		}
		if err == pgx.ErrNoRows {
			writeApprovalError(w, 404, "not_found", "device platform or registered version not found", nil)
			return
		}
		if err != nil {
			releaseError(w, err)
			return
		}
		var same bool
		err = tx.QueryRow(ctx, `SELECT attempts=$7 AND failures=$8 FROM agent_release_evidence WHERE device_id IS NOT DISTINCT FROM $1::uuid AND platform=$2 AND version=$3 AND metric=$4 AND window_start=$5 AND window_end=$6 AND provenance=$9`, deviceID, req.Platform, req.Version, req.Metric, req.WindowStart, req.WindowEnd, req.Attempts, req.Failures, req.Provenance).Scan(&same)
		if err != nil && err != pgx.ErrNoRows {
			releaseError(w, err)
			return
		}
		if err == nil && !same {
			writeApprovalError(w, 409, "evidence_conflict", "provenance window already has different counts", nil)
			return
		}
		if err == pgx.ErrNoRows {
			_, err = tx.Exec(ctx, `INSERT INTO agent_release_evidence (device_id,platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,'internal-admin')`, deviceID, req.Platform, req.Version, req.Metric, req.WindowStart, req.WindowEnd, req.Attempts, req.Failures, req.Provenance)
		}
		if err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.Audit(ctx, tx, tenantID, "internal-admin", "internal", "evidence", req); err != nil {
			releaseError(w, err)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]bool{"recorded": true})
	}
}

func validatePromotedArtifact(req adminRegisterVersionReq) error {
	if req.Channel != "stable" || !isValidAgentVersionPlatform(req.Platform) || !isSafeVersionSegment(req.Version) {
		return errors.New("valid platform/version and stable channel required")
	}
	u, err := url.Parse(req.ArtifactURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("artifact_url must be HTTPS")
	}
	for _, v := range []string{req.ArtifactSHA256, req.ArtifactHMAC} {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 32 || v != strings.ToLower(v) {
			return errors.New("SHA256 and HMAC must be lowercase 64-digit hex")
		}
	}
	if err := validateArtifactMetadataSignature(req.ArtifactMetadataSignature, req.Version, req.Platform, "stable"); err != nil {
		return err
	}
	// Bind the newly signed stable envelope to the copied bytes and stable URL.
	var env struct {
		SignedPayload string `json:"signed_payload"`
	}
	if err = json.Unmarshal(req.ArtifactMetadataSignature, &env); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		return err
	}
	var p struct {
		ArtifactURL    string `json:"artifact_url"`
		ArtifactSHA256 string `json:"artifact_sha256"`
	}
	// Unknown payload metadata is allowed, but duplicate keys at every level
	// are forbidden and the binding keys must have their exact spelling.
	var payload map[string]json.RawMessage
	if err = decodeStrictJSON(raw, &payload); err != nil {
		return err
	}
	for _, field := range []string{"version", "platform", "channel", "artifact_url", "artifact_sha256"} {
		for k := range payload {
			if k != field && strings.EqualFold(k, field) {
				return fmt.Errorf("unexpected spelling of %s", field)
			}
		}
		if _, ok := payload[field]; !ok {
			return fmt.Errorf("%s missing", field)
		}
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if p.ArtifactURL != req.ArtifactURL || p.ArtifactSHA256 != req.ArtifactSHA256 {
		return errors.New("stable envelope does not bind artifact URL/SHA256")
	}
	if _, ok := payload["artifact_url"]; !ok {
		return errors.New("artifact_url missing")
	}
	if _, ok := payload["artifact_sha256"]; !ok {
		return errors.New("artifact_sha256 missing")
	}
	return nil
}

type releaseProbeReq struct {
	DeviceID       string     `json:"device_id"`
	Platform       string     `json:"platform"`
	Version        string     `json:"version"`
	ObservedAt     time.Time  `json:"observed_at"`
	HealthComplete *bool      `json:"health_complete"`
	FaultKeys      [][]string `json:"fault_keys"`
	Provenance     string     `json:"provenance"`
}

// Internal probes cover the menu-bar binary, whose version is not the daemon's
// inventory agent_version. They never overwrite devices.agent_version.
func AdminAgentReleaseObservationHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readLimitedBody(w, r, 64<<10)
		if !ok {
			return
		}
		var req releaseProbeReq
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		now := time.Now().UTC()
		if !looksLikeUUID(req.DeviceID) || req.Platform != "macos-menubar" || !isSafeVersionSegment(req.Version) || req.HealthComplete == nil || req.FaultKeys == nil || len(req.FaultKeys) > 128 || req.ObservedAt.Before(now.Add(-5*time.Minute)) || req.ObservedAt.After(now.Add(5*time.Minute)) || strings.TrimSpace(req.Provenance) == "" || len(req.Provenance) > 500 || strings.ContainsAny(req.Provenance, "\x00\r\n") {
			writeApprovalError(w, 400, "invalid_request", "bounded fresh macos-menubar observation, explicit health and provenance required", nil)
			return
		}
		seen := map[string]bool{}
		for _, f := range req.FaultKeys {
			if len(f) != 2 || f[0] == "" || f[1] == "" || len(f[0]) > 255 || len(f[1]) > 255 || strings.ContainsAny(f[0]+f[1], "\x00\r\n") || seen[f[0]+"\x00"+f[1]] {
				writeApprovalError(w, 400, "invalid_request", "fault_keys must contain unique bounded kind/subject pairs", nil)
				return
			}
			seen[f[0]+"\x00"+f[1]] = true
		}
		sort.Slice(req.FaultKeys, func(i, j int) bool {
			if req.FaultKeys[i][0] != req.FaultKeys[j][0] {
				return req.FaultKeys[i][0] < req.FaultKeys[j][0]
			}
			return req.FaultKeys[i][1] < req.FaultKeys[j][1]
		})
		faults, _ := json.Marshal(req.FaultKeys)
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if err = releasecontrol.Lock(ctx, tx); err != nil {
			releaseError(w, err)
			return
		}
		var tenantID string
		err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM devices WHERE id=$1::uuid AND lower(os)='macos' AND EXISTS(SELECT 1 FROM agent_versions WHERE platform=$2 AND version=$3)`, req.DeviceID, req.Platform, req.Version).Scan(&tenantID)
		if err == pgx.ErrNoRows {
			writeApprovalError(w, 404, "not_found", "device or registered version not found", nil)
			return
		}
		if err != nil {
			releaseError(w, err)
			return
		}
		var same bool
		err = tx.QueryRow(ctx, `SELECT version=$3 AND observed_at=$4 AND health_complete=$5 AND fault_keys=$6::jsonb FROM agent_release_observations WHERE device_id=$1::uuid AND platform=$2 AND source='internal_probe' AND provenance=$7`, req.DeviceID, req.Platform, req.Version, req.ObservedAt, *req.HealthComplete, faults, req.Provenance).Scan(&same)
		if err != nil && err != pgx.ErrNoRows {
			releaseError(w, err)
			return
		}
		if err == nil && !same {
			writeApprovalError(w, 409, "observation_conflict", "provenance already has different evidence", nil)
			return
		}
		if err == pgx.ErrNoRows {
			_, err = tx.Exec(ctx, `INSERT INTO agent_release_observations(device_id,platform,version,observed_at,received_at,health_complete,fault_keys,source,provenance) VALUES ($1::uuid,$2,$3,$4,clock_timestamp(),$5,$6::jsonb,'internal_probe',$7)`, req.DeviceID, req.Platform, req.Version, req.ObservedAt, *req.HealthComplete, faults, req.Provenance)
			if err != nil {
				releaseError(w, err)
				return
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_release_cohorts(device_id,platform,version,entered_at,baseline_version,baseline_faults,baseline_health_at)
   SELECT c.device_id,$2,$3,c.entered_at,s.version,COALESCE(o.fault_keys,'[]'::jsonb),o.observed_at
   FROM agent_device_channels c
   LEFT JOIN LATERAL (SELECT version FROM agent_versions WHERE platform=$2 AND channel='stable' AND published_at<=c.entered_at ORDER BY published_at DESC,id DESC LIMIT 1) s ON true
   LEFT JOIN LATERAL (SELECT fault_keys,observed_at FROM agent_release_observations WHERE device_id=c.device_id AND platform=$2 AND version=s.version AND received_at<c.entered_at AND health_complete ORDER BY received_at DESC LIMIT 1) o ON true
   WHERE c.device_id=$1::uuid AND c.channel='beta' AND EXISTS(SELECT 1 FROM agent_versions WHERE platform=$2 AND channel='beta' AND version=$3)
   ON CONFLICT DO NOTHING`, req.DeviceID, req.Platform, req.Version)
		if err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.Audit(ctx, tx, &tenantID, "internal-admin", "internal", "version_observation", req); err != nil {
			releaseError(w, err)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]bool{"recorded": true})
	}
}

// Promotion takes CI's stable-channel envelope; private artifact signing keys
// stay in CI. Beta metadata is preserved, and stable byte identity is immutable.
func AdminAgentReleasePromoteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readLimitedBody(w, r, 64<<10)
		if !ok {
			return
		}
		var req adminRegisterVersionReq
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		if err := validatePromotedArtifact(req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if err = releasecontrol.Lock(ctx, tx); err != nil {
			releaseError(w, err)
			return
		}
		var sha, hmac string
		err = tx.QueryRow(ctx, `SELECT artifact_sha256,artifact_hmac FROM agent_versions WHERE platform=$1 AND channel='beta' AND version=$2 FOR SHARE`, req.Platform, req.Version).Scan(&sha, &hmac)
		if err == pgx.ErrNoRows {
			writeApprovalError(w, 404, "not_found", "beta candidate not found", nil)
			return
		}
		if err != nil {
			releaseError(w, err)
			return
		}
		if sha != req.ArtifactSHA256 || hmac != req.ArtifactHMAC {
			writeApprovalError(w, 409, "artifact_conflict", "stable artifact must contain the gated beta bytes", nil)
			return
		}
		var same bool
		err = tx.QueryRow(ctx, `SELECT artifact_sha256=$3 AND artifact_hmac=$4 AND artifact_url=$5 AND artifact_metadata_signature::jsonb=$6::jsonb FROM agent_versions WHERE platform=$1 AND channel='stable' AND version=$2`, req.Platform, req.Version, sha, hmac, req.ArtifactURL, req.ArtifactMetadataSignature).Scan(&same)
		if err != nil && err != pgx.ErrNoRows {
			releaseError(w, err)
			return
		}
		if err == nil {
			if !same {
				writeApprovalError(w, 409, "artifact_conflict", "existing stable artifact differs", nil)
				return
			}
			if err = releasecontrol.Audit(ctx, tx, nil, "internal-admin", "internal", "promotion_idempotent", map[string]any{"platform": req.Platform, "version": req.Version}); err != nil {
				releaseError(w, err)
				return
			}
			if err = tx.Commit(ctx); err != nil {
				releaseError(w, err)
				return
			}
			releaseJSON(w, map[string]bool{"promoted": true, "idempotent": true})
			return
		}
		h, err := releasecontrol.Gate(ctx, tx, req.Platform, req.Version, time.Now().UTC())
		if err != nil {
			releaseError(w, err)
			return
		}
		if !h.Ready {
			if err = releasecontrol.Audit(ctx, tx, nil, "internal-admin", "internal", "promotion_refused", h); err != nil {
				releaseError(w, err)
				return
			}
			if err = tx.Commit(ctx); err != nil {
				releaseError(w, err)
				return
			}
			w.WriteHeader(409)
			releaseJSON(w, h)
			return
		}
		var compact bytes.Buffer
		if err = json.Compact(&compact, req.ArtifactMetadataSignature); err != nil {
			releaseError(w, err)
			return
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_versions (platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,released_by,artifact_metadata_signature) VALUES ($1,'stable',$2,$3,$4,$5,'internal-admin:promotion',$6)`, req.Platform, req.Version, req.ArtifactURL, sha, hmac, compact.String())
		if err != nil {
			releaseError(w, err)
			return
		}
		if _, err = tx.Exec(ctx, `INSERT INTO agent_release_promotions (platform,version,artifact_sha256,actor) VALUES ($1,$2,$3,'internal-admin')`, req.Platform, req.Version, sha); err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.Audit(ctx, tx, nil, "internal-admin", "internal", "promotion", map[string]any{"platform": req.Platform, "version": req.Version, "artifact_sha256": sha, "health": h}); err != nil {
			releaseError(w, err)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]bool{"promoted": true, "idempotent": false})
	}
}

type releaseP0Req struct {
	Version     string    `json:"version"`
	Banner      string    `json:"banner"`
	ScheduledAt time.Time `json:"scheduled_at"`
}

func AdminAgentReleaseP0Handler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := chi.URLParam(r, "tenantID")
		if !looksLikeUUID(tenantID) {
			writeApprovalError(w, 400, "invalid_request", "tenantID must be UUID", nil)
			return
		}
		body, ok := readLimitedBody(w, r, 16<<10)
		if !ok {
			return
		}
		var req releaseP0Req
		if err := decodeStrictJSON(body, &req); err != nil {
			writeApprovalError(w, 400, "invalid_request", err.Error(), nil)
			return
		}
		createdAt := time.Now().UTC()
		if !isSafeVersionSegment(req.Version) || strings.TrimSpace(req.Banner) == "" || len(req.Banner) > 2000 || strings.ContainsRune(req.Banner, '\x00') || req.ScheduledAt.Before(createdAt.Add(24*time.Hour)) {
			writeApprovalError(w, 400, "invalid_request", "version, banner and schedule at least 24h ahead are required", nil)
			return
		}
		ctx := r.Context()
		tx, err := pool.Begin(ctx)
		if err != nil {
			releaseError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if err = releasecontrol.Lock(ctx, tx); err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.TenantLock(ctx, tx, tenantID); err != nil {
			releaseError(w, err)
			return
		}
		latest, err := releasecontrol.CommonStable(ctx, tx, tenantID)
		if err != nil || latest != req.Version {
			writeApprovalError(w, 409, "stable_version_unavailable", "P0 version must be latest stable for every estate platform", nil)
			return
		}
		var recipient *string
		err = tx.QueryRow(ctx, `SELECT contact_email FROM tenants WHERE id=$1::uuid`, tenantID).Scan(&recipient)
		if err != nil {
			releaseError(w, err)
			return
		}
		if recipient == nil {
			writeApprovalError(w, 409, "contact_email_missing", "P0 requires the tenant contact email", nil)
			return
		}
		if err = graphmail.ValidateRecipients([]string{*recipient}); err != nil {
			writeApprovalError(w, 409, "contact_email_invalid", "P0 requires a valid tenant contact email", nil)
			return
		}
		var noticeID int64
		err = tx.QueryRow(ctx, `INSERT INTO agent_release_p0_notices (tenant_id,version,banner,actor,created_at,scheduled_at,email_due_at,email_recipient) VALUES ($1::uuid,$2,$3,'internal-admin',$4,$5,$4,$6) RETURNING id`, tenantID, req.Version, req.Banner, createdAt, req.ScheduledAt, *recipient).Scan(&noticeID)
		if err != nil {
			releaseError(w, err)
			return
		}
		if err = releasecontrol.Audit(ctx, tx, &tenantID, "internal-admin", "internal", "p0_scheduled", map[string]any{"notice_id": noticeID, "schedule": req}); err != nil {
			releaseError(w, err)
			return
		}
		if _, err = bumpAgentConfigVersionForDecommission(ctx, tx, tenantID); err != nil {
			releaseError(w, err)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			releaseError(w, err)
			return
		}
		releaseJSON(w, map[string]any{"notice_id": noticeID, "scheduled_at": req.ScheduledAt, "email_delivery": "scheduled"})
	}
}

// registerAgentRelease is shared by the legacy registration route. New stable
// rows require the full gate. Beta identities cannot be silently overwritten,
// since doing so would reuse observations from a different binary.
func registerAgentRelease(ctx context.Context, pool *pgxpool.Pool, req adminRegisterVersionReq, envelope *string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = releasecontrol.Lock(ctx, tx); err != nil {
		return err
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT artifact_url=$4 AND artifact_sha256=$5 AND artifact_hmac=$6 AND artifact_metadata_signature IS NOT DISTINCT FROM $7::text FROM agent_versions WHERE platform=$1 AND channel=$2 AND version=$3 FOR UPDATE`, req.Platform, req.Channel, req.Version, req.ArtifactURL, req.ArtifactSHA256, req.ArtifactHMAC, envelope).Scan(&same)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil && !same {
		return fmt.Errorf("release_conflict: version already has a different artifact")
	}
	if err == pgx.ErrNoRows {
		if req.Channel == "stable" {
			return errors.New("promotion_required: publish stable through /admin/agent-releases/promote")
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_versions (platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,released_by,artifact_metadata_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, req.Platform, req.Channel, req.Version, req.ArtifactURL, req.ArtifactSHA256, req.ArtifactHMAC, req.ReleasedBy, envelope)
		if err != nil {
			return err
		}
	}
	if err = releasecontrol.Audit(ctx, tx, nil, "internal-admin", "internal", "register", map[string]string{"platform": req.Platform, "channel": req.Channel, "version": req.Version}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
