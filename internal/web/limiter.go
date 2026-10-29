package web

import (
	"context"
	"sync"
	"time"
)

// Login limiting. Goals: slow password guessing, and never let failures
// from anywhere else lock the administrator out.
//
//   - Failures are tracked per (user, client address) pair. After
//     pairThreshold failures the pair waits limiterBase, doubling with each
//     further failure up to limiterMax. A success resets the pair.
//   - Per client address (all user names): the same backoff after
//     ipThreshold failures, against one address spraying user names.
//   - Per user name, across all addresses: a token bucket of
//     userBurst attempts refilled at userRate. An attempt from an address
//     with recent failures (its pair or its address has any) needs a token
//     and is refused (429 + Retry-After) without one. An attempt from a
//     clean address is never refused: when the bucket is empty it is
//     delayed at most limiterMaxDelay (and not at all once
//     limiterMaxDelayed callers are already waiting), then proceeds.
//     So a flood from many addresses only ever slows the administrator.
//   - The attempt is reserved (counted as pending) before the argon2 check,
//     so concurrent attempts cannot overrun a threshold; a pair may have at
//     most as many attempts in flight as it has failures left.
//   - Entries idle for limiterForget are pruned, lazily at most once per
//     limiterPruneEvery. Each table holds at most maxKeys entries; when full
//     the least recently used idle entry is evicted. This intentionally
//     replaces the earlier fail-closed saturation (refuse unknown keys when
//     the table is full of locks): that was a global lockout an attacker
//     could trigger. A flood large enough to evict an attacker's own entry
//     only gives that attacker a fresh budget of a few guesses, still under
//     the per-user bucket.
//   - A new admin credential generation (password change, `doorwarden
//     admin unlock`/`reset-password`) clears everything.
const (
	pairThreshold     = 5
	ipThreshold       = 20
	limiterBase       = 30 * time.Second
	limiterMax        = 15 * time.Minute
	limiterForget     = time.Hour
	limiterPruneEvery = time.Minute
	limiterMaxKeys    = 10000
	userBurst         = 30
	userRate          = 30 // per minute
	limiterMaxDelay   = 5 * time.Second
	limiterMaxDelayed = 16
)

type limEntry struct {
	fails       int
	pending     int
	lockedUntil time.Time
	last        time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

type limiter struct {
	mu        sync.Mutex
	now       func() time.Time
	pairs     map[string]*limEntry
	ips       map[string]*limEntry
	users     map[string]*bucket
	maxKeys   int
	lastPrune time.Time
	gen       int64
	genSeen   bool
	delayed   int
}

func newLimiter(now func() time.Time) *limiter {
	l := &limiter{now: now, maxKeys: limiterMaxKeys}
	l.reset()
	return l
}

func (l *limiter) reset() {
	l.pairs = map[string]*limEntry{}
	l.ips = map[string]*limEntry{}
	l.users = map[string]*bucket{}
}

// observeGeneration clears all state when the admin credential generation
// differs from the one seen last.
func (l *limiter) observeGeneration(g int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.genSeen && g != l.gen {
		l.reset()
	}
	l.gen, l.genSeen = g, true
}

// attempt is a reserved login attempt.
type attempt struct {
	l     *limiter
	pairK string
	ipK   string
	// delay is how long the caller should wait before checking the
	// password (clean address, bucket empty); release it with undelay.
	delay   time.Duration
	delayed bool
	closed  bool
}

func (l *limiter) maybePrune(now time.Time) {
	if now.Sub(l.lastPrune) < limiterPruneEvery {
		return
	}
	l.lastPrune = now
	for _, m := range []map[string]*limEntry{l.pairs, l.ips} {
		for k, e := range m {
			if e.pending == 0 && !now.Before(e.lockedUntil) && now.Sub(e.last) > limiterForget {
				delete(m, k)
			}
		}
	}
	for k, b := range l.users {
		if now.Sub(b.at) > limiterForget {
			delete(l.users, k)
		}
	}
}

// entry returns m[k], creating it (evicting the least recently used idle
// entry when the table is full).
func (l *limiter) entry(m map[string]*limEntry, k string, now time.Time) *limEntry {
	if e := m[k]; e != nil {
		return e
	}
	if len(m) >= l.maxKeys {
		var oldK string
		var old *limEntry
		for kk, e := range m {
			if e.pending == 0 && (old == nil || e.last.Before(old.last)) {
				oldK, old = kk, e
			}
		}
		if old != nil {
			delete(m, oldK)
		}
	}
	e := &limEntry{last: now}
	m[k] = e
	return e
}

func (e *limEntry) refusal(now time.Time, threshold int) (time.Duration, bool) {
	if now.Before(e.lockedUntil) {
		return e.lockedUntil.Sub(now), true
	}
	left := threshold - e.fails
	if left < 1 {
		left = 1 // past the threshold: one attempt per backoff window
	}
	if e.pending >= left {
		return time.Second, true
	}
	return 0, false
}

func (b *bucket) refill(now time.Time) {
	b.tokens += now.Sub(b.at).Minutes() * userRate
	if b.tokens > userBurst {
		b.tokens = userBurst
	}
	b.at = now
}

// begin reserves an attempt for user from ip, or refuses it with a
// throttledError. user is the submitted name (any string); "" is used for
// setup, which is limited per address only.
func (l *limiter) begin(user, ip string) (*attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybePrune(now)
	at := &attempt{l: l, pairK: user + "\x00" + ip}
	pair := l.entry(l.pairs, at.pairK, now)
	if d, refused := pair.refusal(now, pairThreshold); refused {
		return nil, throttledError{d}
	}
	var ipe *limEntry
	if user != "" {
		at.ipK = ip
		ipe = l.entry(l.ips, ip, now)
		if d, refused := ipe.refusal(now, ipThreshold); refused {
			return nil, throttledError{d}
		}
		b := l.users[user]
		if b == nil {
			b = &bucket{tokens: userBurst, at: now}
			l.users[user] = b
		}
		b.refill(now)
		dirty := pair.fails > 0 || ipe.fails > 0
		switch {
		case b.tokens >= 1:
			b.tokens--
		case dirty:
			need := (1 - b.tokens) / userRate * float64(time.Minute)
			return nil, throttledError{time.Duration(need)}
		default:
			// Clean address: delay, never refuse.
			wait := time.Duration((1 - b.tokens) / userRate * float64(time.Minute))
			if wait <= limiterMaxDelay && l.delayed < limiterMaxDelayed {
				b.tokens-- // reserved: may go negative by at most the delay
				at.delay, at.delayed = wait, true
				l.delayed++
			}
		}
	}
	pair.pending++
	pair.last = now
	if ipe != nil {
		ipe.pending++
		ipe.last = now
	}
	return at, nil
}

// undelay marks the caller's delay as over.
func (at *attempt) undelay() {
	if !at.delayed {
		return
	}
	at.l.mu.Lock()
	at.l.delayed--
	at.delayed = false
	at.l.mu.Unlock()
}

// recheck reports a backoff that started while the attempt was queued
// (other attempts of the pair or address failed meanwhile).
func (at *attempt) recheck() error {
	l := at.l
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, e := range []*limEntry{l.pairs[at.pairK], l.ips[at.ipK]} {
		if e != nil && now.Before(e.lockedUntil) {
			return throttledError{e.lockedUntil.Sub(now)}
		}
	}
	return nil
}

func (e *limEntry) fail(now time.Time, threshold int) {
	e.fails++
	e.last = now
	if e.fails >= threshold {
		d := limiterBase << min(e.fails-threshold, 10)
		if d > limiterMax || d <= 0 {
			d = limiterMax
		}
		e.lockedUntil = now.Add(d)
	}
}

// done completes the attempt: ok resets the pair and the address, a
// failure counts against both.
func (at *attempt) done(ok bool) { at.finish(true, ok) }

// cancel releases the reservation without counting anything (the password
// was never checked).
func (at *attempt) cancel() { at.finish(false, false) }

func (at *attempt) finish(checked, ok bool) {
	at.undelay()
	l := at.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if at.closed {
		return
	}
	at.closed = true
	now := l.now()
	for _, x := range []struct {
		m         map[string]*limEntry
		k         string
		threshold int
	}{{l.pairs, at.pairK, pairThreshold}, {l.ips, at.ipK, ipThreshold}} {
		if x.k == "" {
			continue
		}
		e := x.m[x.k]
		if e == nil {
			continue // reset meanwhile
		}
		if e.pending > 0 {
			e.pending--
		}
		switch {
		case !checked:
		case ok:
			e.fails, e.lockedUntil = 0, time.Time{}
			e.last = now
		default:
			e.fail(now, x.threshold)
		}
	}
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
