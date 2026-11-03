// Package rings implements deterministic device-to-ring assignment and the
// ring-version-approval rollout state machine for customer-facing patching
// rings (PAT-117).
package rings

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// parseUUIDBytes parses a UUID string (with or without hyphens) into 16 bytes.
// Returns nil on parse error — callers default to ring 3 (GA) on nil.
func parseUUIDBytes(uuidStr string) []byte {
	s := strings.ReplaceAll(uuidStr, "-", "")
	if len(s) != 32 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil
	}
	return b
}

// ComputeRing returns the ring index (0 to len(percentages)-1) for a device
// given its stable UUID string and the tenant's ring percentage bands.
//
// Algorithm: crc32(device_id bytes) % 100 maps the device to a bucket in
// [0,100). The bucket is compared against cumulative percentage bands.
// For percentages=[10,30,60]:
//   - ring 0 = buckets [0,10)
//   - ring 1 = buckets [10,40)
//   - ring 2 = buckets [40,100)
//
// The bucket is stable across calls (same device_id always → same bucket).
// Changing percentages only moves band boundaries — it does not re-shuffle
// devices that are deep within a band. Only boundary devices move ring.
func ComputeRing(deviceIDStr string, percentages []int) int {
	b := parseUUIDBytes(deviceIDStr)
	if b == nil {
		return len(percentages) - 1 // default to last ring (GA) on bad input
	}
	raw := crc32.ChecksumIEEE(b)
	bucket := int(raw) % 100
	if bucket < 0 {
		bucket = -bucket
	}
	cumulative := 0
	for i, pct := range percentages {
		cumulative += pct
		if bucket < cumulative {
			return i
		}
	}
	return len(percentages) - 1
}

// RingToAgentValue maps a ring band index (0..ring_count-1) to the agent's
// fixed ring integer space (0..3). The last/largest ring always maps to 3 (GA)
// so the soak progression terminates at GA regardless of ring_count.
//
// Mapping by ring_count:
//
//	2 rings: 0→0, 1→3
//	3 rings: 0→0, 1→1, 2→3
//	4 rings: 0→0, 1→1, 2→2, 3→3
//	5 rings: 0→0, 1→1, 2→2, 3→2, 4→3   (rings 2 and 3 share agent value 2)
func RingToAgentValue(ringIdx, ringCount int) int {
	if ringIdx >= ringCount-1 {
		return 3
	}
	switch ringCount {
	case 2:
		return 0
	case 3:
		return ringIdx
	case 4:
		return ringIdx
	default: // 5
		if ringIdx < 3 {
			return ringIdx
		}
		return 2
	}
}

// ConfiguredAgentRings returns the ascending, de-duplicated list of agent ring
// values (0-3) that a tenant on ringCount bands actually assigns devices to.
//
// PAT-1002: this list is the ONLY legitimate source of "what ring comes next".
// Agent ring values are not contiguous for every ring_count, because
// RingToAgentValue always pins the last band to 3 (GA) regardless of how many
// bands there are:
//
//	ring_count 2 -> [0, 3]        (1 and 2 are never assigned to any device)
//	ring_count 3 -> [0, 1, 3]     (2 is never assigned)
//	ring_count 4 -> [0, 1, 2, 3]
//	ring_count 5 -> [0, 1, 2, 3]  (bands 2 and 3 share agent value 2)
//
// Anything that walks a rollout forward by approved_ring+1 therefore parks it
// on a phantom ring for every ring_count except 4: no device ever computes to
// that value, so the evidence query finds zero eligible devices, the rollout
// can never gather the observations it needs to move again, and it stalls
// silently at a ring nobody is in. That is the PAT-1002 defect-8 deadlock.
//
// Percentages (tenant_ring_config.percentages) is deliberately NOT the source
// here: it holds per-band SIZE percentages indexed by band, not ring numbers,
// and the DB CHECK already pins array_length(percentages,1) = ring_count
// (migrations/0042_patching_rings.sql), so ring_count is the equivalent and
// simpler input.
// Out-of-range ringCount is CLAMPED into [2,5] rather than rejected, and the
// clamp is deliberate: tenant_ring_config.ring_count has a DB CHECK pinning it
// to that range, so an out-of-range value here means the constraint was
// bypassed (raw SQL, a migration that rebuilt the table) — and failing hard at
// that point would strand an already-running rollout with no way to advance,
// which is worse than proceeding on the nearest valid shape.
//
// PAT-1002 (second review round): the clamp used to be silent, which made it a
// corruption LAUNDERER — a bad ring_count was quietly replaced with a good one
// and the estate looked healthy while running a shape nobody configured. It
// now warns, so the substitution shows up in the logs. There is no tenant id in
// scope here (the function takes only the count), so the warning names the
// value; the caller's own log lines carry the tenant.
func ConfiguredAgentRings(ringCount int) []int {
	if ringCount < 2 || ringCount > 5 {
		clamped := ringCount
		if clamped < 2 {
			clamped = 2
		}
		if clamped > 5 {
			clamped = 5
		}
		slog.Warn("rings: ring_count outside the supported range — clamping",
			"ring_count", ringCount, "clamped_to", clamped,
			"reason", "tenant_ring_config.ring_count has a CHECK constraint for 2-5, so this value bypassed it")
		ringCount = clamped
	}
	seen := map[int]bool{}
	var out []int
	for i := 0; i < ringCount; i++ {
		v := RingToAgentValue(i, ringCount)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// NextConfiguredRing returns the next agent ring value a rollout currently
// approved at `current` should move to, and whether such a ring exists.
//
// ok == false means `current` is at (or past) the tenant's final configured
// ring, so the correct next action is completion, not advancement.
//
// `current` need not itself be a configured ring value: a manual skip or
// emergency deploy can park approved_ring on any value in 0-3, and a
// ring_count change can strand it. The next configured ring is simply the
// smallest configured value strictly greater than `current`, which recovers
// from a stranded value instead of deadlocking on it.
func NextConfiguredRing(current, ringCount int) (int, bool) {
	for _, v := range ConfiguredAgentRings(ringCount) {
		if v > current {
			return v, true
		}
	}
	return current, false
}

// EffectiveAgentRing returns the ring integer (0-3) to deliver to the agent for
// a device. Override wins; falls back to computed; falls back to 3 (GA, safe default).
func EffectiveAgentRing(ringOverride, ringComputed *int16) int {
	if ringOverride != nil {
		return int(*ringOverride)
	}
	if ringComputed != nil {
		return int(*ringComputed)
	}
	return 3
}

// RecomputeFleet recomputes ring_computed for every device in the tenant
// inside the provided transaction. Called from the ring-config PUT handler
// (write-time materialisation) so agent polls always find a correct value.
//
// The MIN estate size check is the caller's responsibility — if the estate is
// below min_estate_size, the caller should set ring_computed = 3 for all devices
// rather than calling this function with actual computed values.
func RecomputeFleet(ctx context.Context, tx pgx.Tx, tenantID string, percentages []int, ringCount int) error {
	rows, err := tx.Query(ctx, `
		SELECT id::text FROM devices
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	type deviceRing struct {
		id    string
		value int16
	}
	var assignments []deviceRing
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return fmt.Errorf("scan device id: %w", err)
		}
		ringIdx := ComputeRing(idStr, percentages)
		agentVal := RingToAgentValue(ringIdx, ringCount)
		assignments = append(assignments, deviceRing{id: idStr, value: int16(agentVal)})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate devices: %w", err)
	}

	for _, a := range assignments {
		// The IS DISTINCT FROM guard skips the write when this device's
		// ring_computed already matches the freshly computed value, so a PUT
		// that doesn't actually change a device's ring doesn't write it.
		// Unlike rebuildRingPromotions' config_version, ring_computed carries
		// no version/signed-artifact semantics of its own — nothing reads a
		// "did this change" signal off it — so this guard is a cheap
		// no-op-write avoidance, not a correctness fix.
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET ring_computed = $1 WHERE id = $2::uuid AND ring_computed IS DISTINCT FROM $1`,
			a.value, a.id,
		); err != nil {
			return fmt.Errorf("update ring_computed for device %s: %w", a.id, err)
		}
	}
	return nil
}

// RecomputeFleetGA sets ring_computed = 3 for all devices in the tenant
// (used when estate is below min_estate_size — every device gets GA).
func RecomputeFleetGA(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE devices SET ring_computed = 3 WHERE tenant_id = $1::uuid AND ring_computed IS DISTINCT FROM 3`,
		tenantID,
	); err != nil {
		return fmt.Errorf("recompute fleet GA: %w", err)
	}
	return nil
}

// DeviceCount returns the active (non-revoked) device count for a tenant.
func DeviceCount(ctx context.Context, pool *pgxpool.Pool, tenantID string) (int, error) {
	var count int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&count)
	return count, err
}

// SetDeviceRingComputed lazily assigns ring_computed for a device that has none.
// Called opportunistically — non-fatal on error.
func SetDeviceRingComputed(ctx context.Context, pool *pgxpool.Pool, deviceID, tenantID string, percentages []int, ringCount int) (int16, error) {
	ringIdx := ComputeRing(deviceID, percentages)
	agentVal := int16(RingToAgentValue(ringIdx, ringCount))
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET ring_computed = $1 WHERE id = $2::uuid AND ring_computed IS NULL`,
		agentVal, deviceID,
	); err != nil {
		slog.Warn("lazy ring_computed assignment failed", "device_id", deviceID, "err", err)
	}
	return agentVal, nil
}
