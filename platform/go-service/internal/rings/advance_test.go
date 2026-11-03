package rings

import (
	"encoding/json"
	"testing"
)

// TestRingPromotionsMapMarshal_IsDeterministic pins down the assumption
// noted in rebuildRingPromotions' doc comment (advance.go): Go's
// encoding/json package always emits map[string]T keys in sorted order, so
// the same logical ring_promotions content always marshals to
// byte-identical JSON no matter what order the map was built up in or how
// its (randomized) internal iteration order happens to land on a given run.
//
// This isn't actually load-bearing for the PAT-1003 fix's correctness: the
// WHERE clause in rebuildRingPromotions compares body->'ring_promotions'
// (jsonb) against $1::jsonb, and Postgres's jsonb type normalizes key order
// on parse — so IS DISTINCT FROM is a semantic comparison either way, even
// if this test failed. But it's the assumption called out explicitly in the
// PAT-1003 ticket ("promos is a map[string]promo") and worth pinning in Go
// too, so a future change that starts comparing raw marshaled JSON text
// elsewhere (rather than relying on Postgres jsonb equality) doesn't
// silently inherit an ordering bug.
func TestRingPromotionsMapMarshal_IsDeterministic(t *testing.T) {
	type promo struct {
		Version      string `json:"version"`
		ApprovedRing int16  `json:"approved_ring"`
	}

	// Same logical content, built up in two different insertion orders.
	a := map[string]promo{}
	for _, label := range []string{"zoom", "firefox", "1password", "googlechrome"} {
		a[label] = promo{Version: "1.0", ApprovedRing: 1}
	}
	b := map[string]promo{}
	for _, label := range []string{"googlechrome", "1password", "firefox", "zoom"} {
		b[label] = promo{Version: "1.0", ApprovedRing: 1}
	}

	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(ab) != string(bb) {
		t.Fatalf("map[string]promo marshaled to different bytes for identical content built up in a "+
			"different insertion order:\n a: %s\n b: %s", ab, bb)
	}

	// Repeated marshals of the SAME map value must also agree with each
	// other — this is the part that actually exercises "sorted before
	// marshal" rather than two calls getting lucky once, since Go
	// deliberately randomizes map iteration order per range/per run.
	first, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a (repeat): %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal a (iteration %d): %v", i, err)
		}
		if string(got) != string(first) {
			t.Fatalf("iteration %d: map[string]promo marshal is non-deterministic across repeated calls: "+
				"%s vs %s", i, got, first)
		}
	}
}
