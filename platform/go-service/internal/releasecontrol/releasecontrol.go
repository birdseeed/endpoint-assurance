// Package releasecontrol owns release authority, not agent-side execution.
package releasecontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/cvematch"
)

const Soak = 72 * time.Hour

// InventoryCadenceTolerance allows daily uploads plus scheduling jitter. Monitor
// windows still must continuously cover the soak through promotion time.
const InventoryCadenceTolerance = 26 * time.Hour

// Lock is exclusive for promotion and publication. Participants take SharedLock
// so the gate cannot race evidence or membership changes, while ordinary
// inventory and tenant writes remain concurrent with each other.
func Lock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(2004, 1)`)
	return err
}

func SharedLock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(2004,1)`)
	return err
}

// TenantLock serialises one tenant's release settings and config generations.
// Read projection does not acquire the global gate lock: it is not gate input.
func TenantLock(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID+"|agent-releases")
	return err
}

func Audit(ctx context.Context, tx pgx.Tx, tenantID *string, actor, source, action string, details any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_release_audit (tenant_id,actor,source,action,details) VALUES ($1::uuid,$2,$3,$4,$5::jsonb)`, tenantID, actor, source, action, raw)
	return err
}

// Project reads under the tenant release lock owned by the caller. P0
// schedules apply at their due time regardless of a customer's hold or pin.
// Beta retains the tenant pin as a ceiling; a due P0 can supersede that ceiling.
func Project(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, body *agentconfig.ConfigBody) error {
	var hold bool
	var pin *string
	err := tx.QueryRow(ctx, `SELECT hold,pinned_version FROM agent_release_settings WHERE tenant_id=$1::uuid`, tenantID).Scan(&hold, &pin)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil {
		body.PinnedVersion = pin
	}
	body.DeviceChannelOverrides = nil
	body.UpdateChannelSource = ""
	rows, err := tx.Query(ctx, `SELECT c.device_id::text,c.channel FROM agent_device_channels c JOIN devices d ON d.id=c.device_id WHERE d.tenant_id=$1::uuid ORDER BY c.device_id`, tenantID)
	if err != nil {
		return err
	}
	overrides := map[string]string{}
	for rows.Next() {
		var id, ch string
		if err = rows.Scan(&id, &ch); err != nil {
			rows.Close()
			return err
		}
		overrides[id] = ch
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if deviceID == "" {
		body.DeviceChannelOverrides = overrides
	} else if ch, ok := overrides[deviceID]; ok {
		body.UpdateChannel = ch
		body.UpdateChannelSource = "device_override"
	} else {
		body.UpdateChannelSource = "tenant"
	}
	forced, active, err := P0Pin(ctx, tx, tenantID, body.PinnedVersion)
	if err != nil {
		return err
	}
	if active {
		body.PinnedVersion = forced
		body.UpdateChannel = "stable"
		body.DeviceChannelOverrides = nil
		body.UpdateChannelSource = ""
	}
	return nil
}

// P0Pin computes the maximum of every due security floor and the customer's
// stable pin. A later, lower P0 notice cannot remove a prior security floor.
// Identical opaque versions are safe; distinct unordered versions fail closed.
func P0Pin(ctx context.Context, tx pgx.Tx, tenantID string, customerPin *string) (*string, bool, error) {
	rows, err := tx.Query(ctx, `SELECT version FROM agent_release_p0_notices WHERE tenant_id=$1::uuid AND scheduled_at<=clock_timestamp() ORDER BY id`, tenantID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	floor := ""
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, false, err
		}
		if floor == "" {
			floor = v
			continue
		}
		if v == floor {
			continue
		}
		cmp, ok := cvematch.CompareVersionsStrict(v, floor)
		if !ok {
			return nil, false, fmt.Errorf("P0 floor versions cannot be safely ordered")
		}
		if cmp > 0 {
			floor = v
		}
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	if floor == "" {
		return customerPin, false, nil
	}
	if customerPin != nil && *customerPin != floor {
		cmp, ok := cvematch.CompareVersionsStrict(*customerPin, floor)
		if !ok {
			return nil, true, fmt.Errorf("customer pin and P0 floor cannot be safely ordered")
		}
		if cmp > 0 {
			floor = *customerPin
		}
	}
	return &floor, true, nil
}

// Observe is called only after successful extraction and validated health
// projection, in the same transaction as the device inventory. Replay rows are
// idempotent; received_at, not a backdated agent clock, starts the soak.
func Observe(ctx context.Context, tx pgx.Tx, tenantID, deviceID, platform, version string, rawID int64, receivedAt, collectedAt time.Time, healthComplete bool) error {
	if reason := observationSkipReason(version, receivedAt, collectedAt); reason != "" {
		// Never log the rejected version or payload. This bounded signal makes
		// degraded release evidence visible while inventory remains resilient.
		slog.Warn("release observation skipped", "device_id", deviceID, "reason", reason)
		return nil
	}
	if err := SharedLock(ctx, tx); err != nil {
		return err
	}
	// Keep unknown versions too: a revert or unexpected binary must interrupt
	// the candidate's soak rather than vanish because it was not registered.
	var err error
	// Health is complete only if the watermark proves THIS payload was accepted.
	var accepted bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_agent_health_watermark WHERE device_id=$1::uuid AND collected_at=$2)`, deviceID, collectedAt).Scan(&accepted); err != nil {
		return err
	}
	healthComplete = healthComplete && accepted
	_, err = tx.Exec(ctx, `INSERT INTO agent_release_observations (device_id,platform,version,observed_at,received_at,raw_payload_id,health_complete,fault_keys,provenance)
 SELECT $1::uuid,$2,$3,$4,$5,$6,$7,COALESCE((SELECT jsonb_agg(jsonb_build_array(kind,subject) ORDER BY kind,subject) FROM device_agent_health WHERE device_id=$1::uuid),'[]'::jsonb),$8
 ON CONFLICT DO NOTHING`, deviceID, platform, version, collectedAt, receivedAt, rawID, healthComplete, fmt.Sprintf("raw:%d:%s", rawID, receivedAt.UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_release_cohorts (device_id,platform,version,entered_at,baseline_version,baseline_faults,baseline_health_at)
 SELECT c.device_id,$2,$3,c.entered_at,
 (SELECT version FROM agent_versions WHERE platform=$2 AND channel='stable' AND published_at<=c.entered_at ORDER BY published_at DESC,id DESC LIMIT 1),c.baseline_faults,c.baseline_health_at
 FROM agent_device_channels c WHERE c.device_id=$1::uuid AND c.channel='beta'
 AND EXISTS(SELECT 1 FROM agent_versions WHERE platform=$2 AND channel='beta' AND version=$3)
 ON CONFLICT DO NOTHING`, deviceID, platform, version)
	return err
}

func observationSkipReason(version string, receivedAt, collectedAt time.Time) string {
	if version == "" || len(version) > 100 || strings.ContainsRune(version, '\x00') {
		return "invalid_agent_version"
	}
	if collectedAt.IsZero() {
		return "invalid_collection_time"
	}
	if collectedAt.Before(receivedAt.Add(-5 * time.Minute)) {
		return "stale_collection_time"
	}
	if collectedAt.After(receivedAt.Add(5 * time.Minute)) {
		return "future_collection_time"
	}
	return ""
}

type DeviceHealth struct {
	DeviceID   string   `json:"device_id"`
	TenantZero bool     `json:"tenant_zero"`
	Ready      bool     `json:"ready"`
	Reasons    []string `json:"reasons"`
}
type Health struct {
	Platform string         `json:"platform"`
	Version  string         `json:"version"`
	Ready    bool           `json:"ready"`
	Reasons  []string       `json:"reasons"`
	Devices  []DeviceHealth `json:"devices"`
}

// Gate never infers absence of failure from absence of telemetry. A complete
// version-attributed window is required for each metric for every participant.
func Gate(ctx context.Context, tx pgx.Tx, platform, version string, now time.Time) (Health, error) {
	h := Health{Platform: platform, Version: version, Reasons: []string{}, Devices: []DeviceHealth{}}
	var publishedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT published_at FROM agent_versions WHERE platform=$1 AND channel='beta' AND version=$2`, platform, version).Scan(&publishedAt); err != nil {
		if err == pgx.ErrNoRows {
			h.Reasons = append(h.Reasons, "beta_candidate_missing")
			return h, nil
		}
		return h, err
	}
	rows, err := tx.Query(ctx, `SELECT d.id::text,t.tenant_kind='internal' AND c.channel='beta',c.entered_at
 FROM devices d JOIN tenants t ON t.id=d.tenant_id
 LEFT JOIN agent_device_channels c ON c.device_id=d.id
 LEFT JOIN agent_config a ON a.tenant_id=t.id
 WHERE (CASE WHEN $1='macos-menubar' THEN lower(d.os)='macos' ELSE lower(d.os)=$1 END)
 AND COALESCE(c.channel,a.body->>'update_channel','stable')='beta'
 ORDER BY d.id`, platform)
	if err != nil {
		return h, err
	}
	type participant struct {
		id      string
		zero    bool
		entered *time.Time
	}
	ps := []participant{}
	hasZero := false
	for rows.Next() {
		var p participant
		if err = rows.Scan(&p.id, &p.zero, &p.entered); err != nil {
			rows.Close()
			return h, err
		}
		hasZero = hasZero || p.zero
		ps = append(ps, p)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return h, err
	}
	if !hasZero {
		h.Reasons = append(h.Reasons, "tenant_zero_explicit_beta_missing")
	}
	if len(ps) == 0 {
		h.Reasons = append(h.Reasons, "beta_devices_missing")
	}
	for _, p := range ps {
		d := DeviceHealth{DeviceID: p.id, TenantZero: p.zero, Reasons: []string{}}
		var first, last *time.Time
		var incomplete, introduced, other bool
		var baseline *string
		var baselineHealth *time.Time
		if p.entered == nil {
			d.Reasons = append(d.Reasons, "explicit_beta_baseline_missing")
		} else {
			err = tx.QueryRow(ctx, `SELECT baseline_version,baseline_health_at FROM agent_release_cohorts WHERE device_id=$1::uuid AND platform=$2 AND version=$3 AND entered_at=$4`, p.id, platform, version, *p.entered).Scan(&baseline, &baselineHealth)
			if err != nil && err != pgx.ErrNoRows {
				return h, err
			}
			if err == pgx.ErrNoRows {
				d.Reasons = append(d.Reasons, "version_baseline_missing")
			}
			if baselineHealth == nil || baselineHealth.Before(p.entered.Add(-InventoryCadenceTolerance)) || baselineHealth.After(*p.entered) {
				d.Reasons = append(d.Reasons, "pre_beta_health_baseline_missing_or_stale")
			}
			err = tx.QueryRow(ctx, `SELECT min(o.received_at),max(o.received_at),COALESCE(bool_or(NOT o.health_complete),false),
    COALESCE(bool_or(EXISTS(SELECT 1 FROM jsonb_array_elements(o.fault_keys) f WHERE NOT c.baseline_faults @> jsonb_build_array(f))),false)
    FROM agent_release_observations o JOIN agent_release_cohorts c ON c.device_id=o.device_id AND c.platform=o.platform AND c.version=o.version AND c.entered_at=$4
    WHERE o.device_id=$1::uuid AND o.platform=$2 AND o.version=$3 AND o.received_at >= $4 AND o.received_at >= $5`, p.id, platform, version, *p.entered, publishedAt).Scan(&first, &last, &incomplete, &introduced)
			if err != nil {
				return h, err
			}
			if first == nil || now.Sub(*first) < Soak {
				d.Reasons = append(d.Reasons, "candidate_not_observed_for_72h")
			}
			if last == nil || now.Sub(*last) > InventoryCadenceTolerance {
				d.Reasons = append(d.Reasons, "candidate_observation_missing_or_stale")
			}
			if incomplete {
				d.Reasons = append(d.Reasons, "candidate_health_incomplete")
			}
			if introduced {
				d.Reasons = append(d.Reasons, "introduced_agent_health_fault")
			}
			if first != nil {
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_release_observations WHERE device_id=$1::uuid AND platform=$2 AND version<>$3 AND received_at>=$4)`, p.id, platform, version, *first).Scan(&other)
				if err != nil {
					return h, err
				}
				if other {
					d.Reasons = append(d.Reasons, "candidate_runtime_interrupted")
				}
				for _, metric := range []string{"artifact_verification", "config_verification", "service_crash", "restart_loop", "enrolment", "upload"} {
					var failures, attempts int64
					err = tx.QueryRow(ctx, `SELECT failures,attempts FROM agent_release_evidence WHERE (device_id=$1::uuid OR (device_id IS NULL AND metric IN ('enrolment','upload'))) AND platform=$2 AND version=$3 AND metric=$4 AND window_start<=$5 AND window_end>=$6 ORDER BY recorded_at DESC,id DESC LIMIT 1`, p.id, platform, version, metric, *first, now.Add(-5*time.Minute)).Scan(&failures, &attempts)
					if err != nil && err != pgx.ErrNoRows {
						return h, err
					}
					if err == pgx.ErrNoRows {
						d.Reasons = append(d.Reasons, metric+"_coverage_missing")
						continue
					}
					var anyFailure bool
					err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_release_evidence WHERE device_id=$1::uuid AND platform=$2 AND version=$3 AND metric=$4 AND window_end>=$5 AND failures>0)`, p.id, platform, version, metric, *first).Scan(&anyFailure)
					if err != nil {
						return h, err
					}
					if metric != "enrolment" && metric != "upload" {
						if anyFailure {
							d.Reasons = append(d.Reasons, metric+"_failure")
						}
						continue
					}
					if baseline == nil {
						d.Reasons = append(d.Reasons, metric+"_previous_stable_baseline_missing")
						continue
					}
					var baseFailures, baseAttempts int64
					err = tx.QueryRow(ctx, `SELECT failures,attempts FROM agent_release_evidence WHERE device_id IS NULL AND platform=$1 AND version=$2 AND metric=$3 AND window_end<=$4 AND window_end>=$5 AND window_end-window_start>=interval '72 hours' ORDER BY window_end DESC,id DESC LIMIT 1`, platform, *baseline, metric, *p.entered, p.entered.Add(-InventoryCadenceTolerance)).Scan(&baseFailures, &baseAttempts)
					if err != nil && err != pgx.ErrNoRows {
						return h, err
					}
					if err == pgx.ErrNoRows {
						d.Reasons = append(d.Reasons, metric+"_previous_stable_baseline_missing")
						continue
					}
					// Values are bounded to 1e9 by SQL, so cross-products fit int64.
					var above bool
					err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_release_evidence WHERE device_id IS NULL AND platform=$1 AND version=$2 AND metric=$3 AND window_end>=$4 AND failures*$5 > $6*attempts)`, platform, version, metric, *first, baseAttempts, baseFailures).Scan(&above)
					if err != nil {
						return h, err
					}
					if failures*baseAttempts > baseFailures*attempts || above {
						d.Reasons = append(d.Reasons, metric+"_rate_above_previous_stable")
					}
				}
			}
		}
		d.Ready = len(d.Reasons) == 0
		h.Devices = append(h.Devices, d)
	}
	h.Ready = len(h.Reasons) == 0
	for _, d := range h.Devices {
		h.Ready = h.Ready && d.Ready
	}
	return h, nil
}

// CommonStable refuses platform skew instead of guessing one pin for both OSes.
func CommonStable(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT lower(os) AS platform FROM devices WHERE tenant_id=$1::uuid AND lower(os) IN ('macos','windows') ORDER BY platform`, tenantID)
	if err != nil {
		return "", err
	}
	platforms := []string{}
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			rows.Close()
			return "", err
		}
		platforms = append(platforms, p)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return "", err
	}
	if len(platforms) == 0 {
		platforms = []string{"macos", "windows"}
	}
	common := ""
	for _, p := range platforms {
		var v string
		err = tx.QueryRow(ctx, `SELECT version FROM agent_versions WHERE platform=$1 AND channel='stable' ORDER BY published_at DESC,id DESC LIMIT 1`, p).Scan(&v)
		if err != nil {
			return "", fmt.Errorf("stable version missing for %s", p)
		}
		if common != "" && common != v {
			return "", fmt.Errorf("latest stable versions differ by platform")
		}
		common = v
	}
	return common, nil
}
