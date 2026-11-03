// Package ratelimit provides per-tenant token-bucket rate limiting.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config holds rate-limit parameters.
type Config struct {
	RPM   int // requests per Period (default: per minute — see Period below)
	Burst int // burst size (tokens immediately available)

	// Period is the window RPM is expressed against. Zero (the common case)
	// means "per minute", preserving the historical RPM-per-minute meaning
	// for every existing caller. Set it explicitly for coarser windows —
	// e.g. Period: time.Hour, RPM: 10 means "10 requests/hour sustained"
	// (PAT-453's portal enrolment-mint limiter). The field is still named
	// RPM for git-blame/back-compat reasons; read it as "requests per
	// Period" once Period is set.
	Period time.Duration
}

// period returns the configured window, defaulting to one minute.
func (c Config) period() time.Duration {
	if c.Period <= 0 {
		return time.Minute
	}
	return c.Period
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// TenantLimiter holds per-tenant token-bucket limiters, evicting idle entries
// periodically so the map doesn't grow unboundedly.
//
// Limits are in-memory only — they reset on service restart. This is acceptable
// for pre-production use; the alternative is a Redis-backed or Caddy-module
// approach (noted in the PAT-338 PR description).
type TenantLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	cfg     Config
	idleTTL time.Duration // entries idle longer than this are evicted
}

// New creates a TenantLimiter with the given config and starts the background
// eviction goroutine. The goroutine runs until the process exits.
func New(cfg Config) *TenantLimiter {
	// An idle entry must not be evicted (and so silently reset to a full
	// burst) before a continuously-active caller would have naturally
	// refilled anyway — otherwise an idle gap longer than the fixed 10-minute
	// default, but shorter than a coarse window (e.g. Config.Period: time.Hour),
	// would let a caller "renew" their burst far more often than the
	// configured rate intends. Default 10 minutes matches the historical
	// per-minute-scale callers, where full refill completes well inside that.
	idleTTL := 10 * time.Minute
	if p := cfg.period(); p > idleTTL {
		idleTTL = p
	}
	tl := &TenantLimiter{
		entries: make(map[string]*entry),
		cfg:     cfg,
		idleTTL: idleTTL,
	}
	go tl.evictLoop()
	return tl
}

// Allow returns (true, 0) if the request is within limits, or (false, retryAfter)
// if the bucket is exhausted. The token is consumed only on allow.
func (tl *TenantLimiter) Allow(tenantID string) (bool, time.Duration) {
	tl.mu.Lock()
	e := tl.getOrCreate(tenantID)
	e.lastSeen = time.Now()
	r := e.limiter.Reserve()
	tl.mu.Unlock()

	delay := r.Delay()
	if delay == 0 {
		return true, 0
	}
	r.Cancel() // put the token back
	return false, delay
}

// Blocked reports whether key's bucket currently has less than one token,
// without consuming one. A key never seen is not blocked, and Blocked does
// not create an entry for it, so probing arbitrary keys cannot grow the map.
func (tl *TenantLimiter) Blocked(key string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	e, ok := tl.entries[key]
	if !ok {
		return false
	}
	return e.limiter.Tokens() < 1
}

func (tl *TenantLimiter) getOrCreate(tenantID string) *entry {
	e, ok := tl.entries[tenantID]
	if !ok {
		ratePerSec := rate.Limit(tl.cfg.RPM) / rate.Limit(tl.cfg.period().Seconds())
		e = &entry{
			limiter: rate.NewLimiter(ratePerSec, tl.cfg.Burst),
		}
		tl.entries[tenantID] = e
	}
	return e
}

// evictLoop removes entries that have been idle longer than idleTTL. Runs
// every 5 minutes in the background — always fine-grained enough since
// idleTTL is never below 10 minutes (see New).
func (tl *TenantLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-tl.idleTTL)
		tl.mu.Lock()
		for k, e := range tl.entries {
			if e.lastSeen.Before(cutoff) {
				delete(tl.entries, k)
			}
		}
		tl.mu.Unlock()
	}
}
