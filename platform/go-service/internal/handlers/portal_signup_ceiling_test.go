package handlers

// PAT-1883: the organisation ceiling as a counter, with no database.

import (
	"sync"
	"testing"
	"time"
)

func TestOrgCeilingCountsWhatWasCreated(t *testing.T) {
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.FixedZone("BST", 3600))
	c := newOrgCeiling(2, time.Hour)
	c.now = func() time.Time { return now }

	a, _ := c.reserve()
	b, _ := c.reserve()
	if a == nil || b == nil {
		t.Fatal("a ceiling of two refused one of the first two reservations")
	}
	// Full while both are in flight, and the wait is short: one may fail.
	if s, retry := c.reserve(); s != nil || retry <= 0 || retry > 5*time.Second {
		t.Fatalf("third reservation with two in flight = %v, retry %s; want refused with a short wait", s != nil, retry)
	}
	// A reservation that created nothing gives its slot back, once.
	a.release()
	a.release()
	a.keep() // settled already: must not turn a released slot into a created one
	d, _ := c.reserve()
	if d == nil {
		t.Fatal("a released slot was not available again")
	}
	if s, _ := c.reserve(); s != nil {
		t.Fatal("releasing one slot twice freed two")
	}
	// A created tenant keeps its slot for the window, however often it is released.
	b.keep()
	b.release()
	d.keep()
	if s, retry := c.reserve(); s != nil || retry != time.Hour {
		t.Fatalf("with two created = %v, retry %s; want refused for the whole window", s != nil, retry)
	}
	now = now.Add(59 * time.Minute)
	if s, retry := c.reserve(); s != nil || retry != time.Minute {
		t.Fatalf("59 minutes on = %v, retry %s; want refused for one more minute", s != nil, retry)
	}
	now = now.Add(time.Minute)
	e, _ := c.reserve()
	f, _ := c.reserve()
	if e == nil || f == nil {
		t.Fatal("slots did not come free when the window passed")
	}
	if s, _ := c.reserve(); s != nil {
		t.Fatal("more slots than the ceiling after the window passed")
	}
}

func TestOrgCeilingNeverExceedsItsLimitUnderConcurrency(t *testing.T) {
	const limit, callers = 5, 200
	c := newOrgCeiling(limit, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	kept, inFlightMax, inFlight := 0, 0, 0
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _ := c.reserve()
			if s == nil {
				return
			}
			defer s.release()
			mu.Lock()
			inFlight++
			if inFlight+kept > inFlightMax {
				inFlightMax = inFlight + kept
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inFlight--
			if i%3 != 0 { // two in three "commit"
				kept++
				s.keep()
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if inFlightMax > limit {
		t.Fatalf("%d slots were held at once, the ceiling is %d", inFlightMax, limit)
	}
	if kept > limit {
		t.Fatalf("%d creations were kept, the ceiling is %d", kept, limit)
	}
	if s, _ := c.reserve(); (s != nil) != (kept < limit) {
		t.Fatalf("after the run kept=%d of %d but a further reservation succeeded=%v", kept, limit, s != nil)
	}
}
