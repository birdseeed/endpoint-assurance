package handlers

import (
	"context"
	"sync"
	"time"
	"unicode/utf8"
)

// orgCeiling is the ceiling on organisations created per window by every
// caller together (PAT-1883). It counts tenants that were created, not
// requests that tried: a creation reserves a slot before it does any work and
// gives the slot back unless a tenant is committed, and a slot that became a
// tenant stays taken for one window. So the ceiling is never exceeded, a
// caller over it is refused before any provisioning work, and a request that
// creates nothing (refused, failed, abandoned) costs the shared budget
// nothing, however often it is repeated.
//
// In memory and per process, like every limiter in this service: a restart
// forgets what was created in the last window.
type orgCeiling struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	now      func() time.Time
	created  []time.Time // when each tenant still inside the window was created, oldest first
	inFlight int         // reservations not yet settled
}

func newOrgCeiling(limit int, window time.Duration) *orgCeiling {
	return &orgCeiling{limit: limit, window: window, now: time.Now}
}

// reserve takes a slot for one creation that is about to start. With the
// ceiling full it returns nil and how long until a slot can come free.
func (c *orgCeiling) reserve() (*orgSlot, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for len(c.created) > 0 && !now.Before(c.created[0].Add(c.window)) {
		c.created = c.created[1:]
	}
	if len(c.created)+c.inFlight >= c.limit {
		// With a creation in flight a slot may come free in moments, if it
		// fails. Otherwise the next one is the oldest tenant leaving the window.
		retry := time.Second
		if c.inFlight == 0 && len(c.created) > 0 {
			retry = c.created[0].Add(c.window).Sub(now)
		}
		return nil, retry
	}
	c.inFlight++
	return &orgSlot{c: c}, 0
}

// orgSlot is one reservation. It is settled exactly once, by keep or by
// release, whichever comes first; later calls do nothing.
type orgSlot struct {
	c       *orgCeiling
	settled bool // guarded by c.mu
}

// keep records that the reservation became a tenant.
func (s *orgSlot) keep() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.settled {
		return
	}
	s.settled = true
	s.c.inFlight--
	s.c.created = append(s.c.created, s.c.now())
}

// release gives the slot back. Safe to defer: it does nothing after keep.
func (s *orgSlot) release() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.settled {
		return
	}
	s.settled = true
	s.c.inFlight--
}

// signupEmailStorable reports whether portal_users can hold email as the
// primary key of a membership: a plausible length, valid text, and already in
// the lower-case form the table's check requires. The last is asked of the
// database, because lower() there follows the database's collation and need
// not agree with Go's. Organisation creation calls this before it reserves a
// slot under the ceiling, so an address that could never be stored is refused
// without holding one.
func signupEmailStorable(ctx context.Context, q rowQuerier, email string) (bool, error) {
	if email == "" || len(email) > inviteEmailMaxBytes || !utf8.ValidString(email) || hasControlChars(email) {
		return false, nil
	}
	var lower bool
	if err := q.QueryRow(ctx, `SELECT $1::text = lower($1::text)`, email).Scan(&lower); err != nil {
		return false, err
	}
	return lower, nil
}
