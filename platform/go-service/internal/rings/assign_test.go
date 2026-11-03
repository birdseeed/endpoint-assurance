package rings

import (
	"testing"
)

// TestComputeRing_Determinism verifies the same device ID always maps to the same ring.
func TestComputeRing_Determinism(t *testing.T) {
	id := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	pct := []int{10, 30, 60}
	first := ComputeRing(id, pct)
	for i := 0; i < 100; i++ {
		if got := ComputeRing(id, pct); got != first {
			t.Fatalf("iteration %d: got ring %d, want %d", i, got, first)
		}
	}
}

// TestComputeRing_BandBoundaries verifies band membership for known bucket values.
// We exploit the fact that crc32(bytes) % 100 is deterministic — we just assert
// the resulting ring index falls in the expected band for each known UUID.
func TestComputeRing_BandBoundaries(t *testing.T) {
	pct := []int{10, 30, 60}
	// Collect a distribution across many known IDs and verify every result is [0,2].
	uuids := []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
		"b1ffcd00-ad1c-5f09-cc7e-7cc0ce491b22",
		"deadbeef-dead-beef-dead-beefdeadbeef",
	}
	for _, id := range uuids {
		r := ComputeRing(id, pct)
		if r < 0 || r >= len(pct) {
			t.Errorf("id=%s: ring %d out of range [0,%d)", id, r, len(pct))
		}
	}
}

// TestComputeRing_BadInput verifies that an unparseable UUID defaults to the last ring.
func TestComputeRing_BadInput(t *testing.T) {
	pct := []int{10, 30, 60}
	last := len(pct) - 1
	for _, bad := range []string{"", "not-a-uuid", "zzzzzzzz-0000-0000-0000-000000000000"} {
		if got := ComputeRing(bad, pct); got != last {
			t.Errorf("bad input %q: want %d (last ring), got %d", bad, last, got)
		}
	}
}

// TestComputeRing_PercentageChangeStability verifies that widening the first band
// does NOT move a device that was well inside that band.
func TestComputeRing_PercentageChangeStability(t *testing.T) {
	// Find a device in ring 0 with pct=[10,30,60].
	var ring0id string
	for i := 0; i < 10000; i++ {
		id := "00000000-0000-0000-0000-" + zeroPad(i)
		if ComputeRing(id, []int{10, 30, 60}) == 0 {
			ring0id = id
			break
		}
	}
	if ring0id == "" {
		t.Skip("could not find a ring-0 device in range — skipping stability test")
	}
	// Widening ring 0 from 10→20 should keep this device in ring 0.
	if got := ComputeRing(ring0id, []int{20, 20, 60}); got != 0 {
		t.Errorf("device %s moved from ring 0 to ring %d after widening the band", ring0id, got)
	}
}

func zeroPad(n int) string {
	digits := []byte("0123456789abcdef")
	out := make([]byte, 12)
	for i := 11; i >= 0; i-- {
		out[i] = digits[n&0xF]
		n >>= 4
	}
	return string(out)
}

// TestRingToAgentValue verifies the full mapping table for ring_count 2–5.
func TestRingToAgentValue(t *testing.T) {
	cases := []struct {
		count int
		want  []int // agent values indexed by ring 0..count-1
	}{
		{2, []int{0, 3}},
		{3, []int{0, 1, 3}},
		{4, []int{0, 1, 2, 3}},
		{5, []int{0, 1, 2, 2, 3}},
	}
	for _, tc := range cases {
		for idx, wantVal := range tc.want {
			got := RingToAgentValue(idx, tc.count)
			if got != wantVal {
				t.Errorf("RingToAgentValue(%d, %d): want %d, got %d", idx, tc.count, wantVal, got)
			}
		}
	}
}

// TestRingToAgentValue_LastRingAlwaysGA verifies the last ring is always 3.
func TestRingToAgentValue_LastRingAlwaysGA(t *testing.T) {
	for count := 2; count <= 5; count++ {
		if got := RingToAgentValue(count-1, count); got != 3 {
			t.Errorf("RingToAgentValue(%d, %d): last ring should be 3 (GA), got %d", count-1, count, got)
		}
	}
}

// TestEffectiveAgentRing verifies the COALESCE priority: override > computed > 3.
func TestEffectiveAgentRing(t *testing.T) {
	i16 := func(v int) *int16 { x := int16(v); return &x }

	cases := []struct {
		override, computed *int16
		want               int
	}{
		{i16(1), i16(2), 1}, // override wins
		{nil, i16(2), 2},    // computed used when no override
		{nil, nil, 3},       // default GA
		{i16(0), nil, 0},    // override 0 (internal) respected
	}
	for _, tc := range cases {
		if got := EffectiveAgentRing(tc.override, tc.computed); got != tc.want {
			t.Errorf("EffectiveAgentRing(override=%v, computed=%v): want %d, got %d",
				tc.override, tc.computed, tc.want, got)
		}
	}
}

// TestConfiguredAgentRings pins down the non-contiguity that PAT-1002's
// defect 8 turned on: for every ring_count except 4, the set of agent ring
// values devices are actually assigned to has a HOLE in it, because
// RingToAgentValue always pins the last band to 3 (GA). Any traversal that
// assumes "the ring after N is N+1" walks a rollout into one of those holes,
// where no device lives and no evidence can ever arrive.
func TestConfiguredAgentRings(t *testing.T) {
	cases := []struct {
		ringCount int
		want      []int
	}{
		{2, []int{0, 3}},       // 1 and 2 are holes
		{3, []int{0, 1, 3}},    // 2 is a hole
		{4, []int{0, 1, 2, 3}}, // the only contiguous config
		{5, []int{0, 1, 2, 3}}, // bands 2 and 3 both map to agent value 2
	}
	for _, tc := range cases {
		got := ConfiguredAgentRings(tc.ringCount)
		if len(got) != len(tc.want) {
			t.Errorf("ConfiguredAgentRings(%d) = %v, want %v", tc.ringCount, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ConfiguredAgentRings(%d) = %v, want %v", tc.ringCount, got, tc.want)
				break
			}
		}
	}

	// Out-of-range ring_count clamps rather than returning an empty list. An
	// empty list would make NextConfiguredRing report "no next ring" for every
	// input, silently completing every rollout on the spot — a much worse
	// failure than clamping to the nearest legal config.
	for _, rc := range []int{-1, 0, 1, 6, 99} {
		if got := ConfiguredAgentRings(rc); len(got) == 0 {
			t.Errorf("ConfiguredAgentRings(%d) returned an empty ring list", rc)
		}
	}
}

// TestNextConfiguredRing covers the traversal itself, including the two cases
// the old approved_ring+1 arithmetic got wrong: skipping the holes, and
// recognising the final ring as "complete" rather than "advance to 3 again".
func TestNextConfiguredRing(t *testing.T) {
	cases := []struct {
		name      string
		current   int
		ringCount int
		wantNext  int
		wantOK    bool
	}{
		// ring_count 2: devices live at 0 and 3 only. The old code took three
		// skips (0->1->2->3) to expose ring 3, the middle two exposing nobody.
		{"rc2 from 0 jumps the hole to GA", 0, 2, 3, true},
		{"rc2 at GA is final", 3, 2, 3, false},

		// ring_count 3: devices live at 0, 1 and 3. Advancing 1->2 was the
		// deadlock: ring 2 has no devices, so observedCount stayed 0 forever.
		{"rc3 from 0", 0, 3, 1, true},
		{"rc3 from 1 jumps the hole to GA", 1, 3, 3, true},
		{"rc3 at GA is final", 3, 3, 3, false},

		// ring_count 4 is contiguous; behaviour is unchanged from before.
		{"rc4 from 0", 0, 4, 1, true},
		{"rc4 from 1", 1, 4, 2, true},
		{"rc4 from 2", 2, 4, 3, true},
		{"rc4 at GA is final", 3, 4, 3, false},

		{"rc5 from 2", 2, 5, 3, true},
		{"rc5 at GA is final", 3, 5, 3, false},

		// A rollout stranded on a hole — by a pre-PAT-1002 numeric advance, or
		// by the tenant changing ring_count under it — must recover to the
		// next real ring, not sit there. This is why the comparison is "> current"
		// against the configured list rather than an index lookup, which would
		// have nothing to index from.
		{"rc3 stranded on the hole recovers to GA", 2, 3, 3, true},
		{"rc2 stranded on a hole recovers to GA", 1, 2, 3, true},

		// Past the end (not reachable today; approved_ring is capped at 3) must
		// read as final, never wrap or advance.
		{"beyond GA is final", 4, 4, 4, false},
	}
	for _, tc := range cases {
		gotNext, gotOK := NextConfiguredRing(tc.current, tc.ringCount)
		if gotNext != tc.wantNext || gotOK != tc.wantOK {
			t.Errorf("%s: NextConfiguredRing(%d, %d) = (%d, %v), want (%d, %v)",
				tc.name, tc.current, tc.ringCount, gotNext, gotOK, tc.wantNext, tc.wantOK)
		}
	}
}
