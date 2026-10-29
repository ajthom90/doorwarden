package web

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Login limiting. Model:
//
//   - Source: the client address, IPv4 per /32, IPv6 per /64.
//   - Scopes: "login" and "setup" each have their own tables and buckets,
//     so traffic in one cannot exhaust the other.
//   - A source is DIRTY for a user when its (user, source) pair, or (login
//     only) the source across all names, has a recorded failure within
//     limiterForget; otherwise CLEAN. Entries exist only for recorded
//     failures (a success deletes them), so a clean source needs no entry.
//   - Dirty attempts: refused (429 + Retry-After) while the pair or source
//     is in backoff (pairThreshold / ipThreshold failures, then limiterBase
//     doubling to limiterMax), while the pair already has as many attempts
//     in flight as failures left, or when the user's DIRTY bucket is
//     empty.
//   - Clean attempts draw only from the user's CLEAN bucket, which dirty
//     attempts never touch. With it empty the attempt is delayed until its
//     token is due, at most limiterMaxDelay, with at most limiterMaxDelayed
//     callers waiting; beyond that it gets 429 + Retry-After for that
//     attempt only. The clean bucket refills one token per limiterMaxDelay,
//     so a dirty flood of any size never keeps a clean source out: its
//     login gets in within limiterMaxDelay. Nothing ever runs uncharged.
//   - Buckets exist for the administrator's name and one shared
//     unknownUser (every other name), so name sprays cannot grow tables.
//   - Tables are bounded (maxKeys). Recording a failure in a full table
//     evicts the least recently used entry that is not in backoff; when
//     every entry is in backoff the failure is not recorded (fail closed
//     for dirty state only: the source then stays clean, which is still
//     throttled by the small clean bucket). Idle entries are pruned after
//     limiterForget, lazily at most once per limiterPruneEvery.
//   - Attempts are reserved before the argon2 check and re-checked for a
//     new backoff once a hashing slot is held.
//   - All state is cleared on a new credential generation (password change,
//     `doorwarden admin unlock`/`reset-password`) and when the
//     administrator is created.
const (
	pairThreshold     = 5
	ipThreshold       = 20
	limiterBase       = 30 * time.Second
	limiterMax        = 15 * time.Minute
	limiterForget     = time.Hour
	limiterPruneEvery = time.Minute
	limiterMaxKeys    = 10000
	dirtyBurst        = 30
	dirtyRate         = 30.0 // per minute
	cleanBurst        = 5
	limiterMaxDelay   = 5 * time.Second
	cleanRate         = float64(time.Minute) / float64(limiterMaxDelay) // per minute: one per max delay
	limiterMaxDelayed = 16
	// unknownUser is the shared bucket of every name that is not the
	// administrator's.
	unknownUser = "\x00unknown"
)

type limEntry struct {
	fails       int
	lockedUntil time.Time
	last        time.Time
}

func (e *limEntry) locked(now time.Time) bool { return e != nil && now.Before(e.lockedUntil) }

type bucket struct {
	tokens float64
	at     time.Time
	rate   float64 // per minute
	burst  float64
}

func (b *bucket) refill(now time.Time) {
	b.tokens += now.Sub(b.at).Minutes() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.at = now
}

// due is how long until the next token.
func (b *bucket) due() time.Duration {
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Minute))
}

type userBuckets struct{ dirty, clean bucket }

type scope struct {
	pairs    map[string]*limEntry
	ips      map[string]*limEntry // login only
	inflight map[string]int       // dirty pair/source keys with attempts in flight
	users    map[string]*userBuckets
}

func newScope() *scope {
	return &scope{pairs: map[string]*limEntry{}, ips: map[string]*limEntry{}, inflight: map[string]int{}, users: map[string]*userBuckets{}}
}

type limiter struct {
	mu        sync.Mutex
	now       func() time.Time
	login     *scope
	setup     *scope
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
	l.login, l.setup = newScope(), newScope()
}

// resetAll clears every limit (the administrator was just created).
func (l *limiter) resetAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reset()
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

// sourceKey is the limiter's key for a client address: IPv4 per /32, IPv6
// per /64.
func sourceKey(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

// attempt is a reserved login attempt.
type attempt struct {
	l     *limiter
	sc    *scope
	pairK string
	ipK   string // "" for setup
	// trackPair, trackIP: the attempt is counted in sc.inflight under
	// pairK / ipK (dirty source).
	trackPair, trackIP bool
	// delay is how long the caller must wait before checking the password
	// (its clean token is not due yet); undelay ends the wait.
	delay   time.Duration
	delayed bool
	closed  bool
}

func (l *limiter) maybePrune(now time.Time) {
	if now.Sub(l.lastPrune) < limiterPruneEvery {
		return
	}
	l.lastPrune = now
	for _, sc := range []*scope{l.login, l.setup} {
		for _, m := range []map[string]*limEntry{sc.pairs, sc.ips} {
			for k, e := range m {
				if !e.locked(now) && now.Sub(e.last) > limiterForget && sc.inflight[k] == 0 {
					delete(m, k)
				}
			}
		}
		for k, b := range sc.users {
			if now.Sub(b.dirty.at) > limiterForget && now.Sub(b.clean.at) > limiterForget {
				delete(sc.users, k)
			}
		}
	}
}

func (l *limiter) buckets(sc *scope, user string, now time.Time) *userBuckets {
	if b := sc.users[user]; b != nil {
		return b
	}
	if len(sc.users) >= l.maxKeys {
		user = unknownUser
		if b := sc.users[user]; b != nil {
			return b
		}
	}
	b := &userBuckets{
		dirty: bucket{tokens: dirtyBurst, at: now, rate: dirtyRate, burst: dirtyBurst},
		clean: bucket{tokens: cleanBurst, at: now, rate: cleanRate, burst: cleanBurst},
	}
	sc.users[user] = b
	return b
}

// begin reserves an attempt for user (the bucket name from limitUser; ""
// for setup) from ip, or refuses it with a throttledError.
func (l *limiter) begin(user string, ip netip.Addr) (*attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybePrune(now)
	src := sourceKey(ip)
	sc := l.login
	if user == "" {
		sc = l.setup
	}
	at := &attempt{l: l, sc: sc, pairK: user + "\x00" + src}
	if sc == l.login {
		at.ipK = src
	}
	pair, ipe := sc.pairs[at.pairK], sc.ips[at.ipK]
	b := l.buckets(sc, user, now)
	if pair != nil || ipe != nil { // dirty
		for _, x := range []struct {
			e         *limEntry
			k         string
			threshold int
		}{{pair, at.pairK, pairThreshold}, {ipe, at.ipK, ipThreshold}} {
			if x.e == nil {
				continue
			}
			if x.e.locked(now) {
				return nil, throttledError{x.e.lockedUntil.Sub(now)}
			}
			if sc.inflight[x.k] >= max(1, x.threshold-x.e.fails) {
				return nil, throttledError{time.Second}
			}
		}
		b.dirty.refill(now)
		if b.dirty.tokens < 1 {
			return nil, throttledError{b.dirty.due()}
		}
		b.dirty.tokens--
		if pair != nil {
			sc.inflight[at.pairK]++
			at.trackPair = true
		}
		if ipe != nil {
			sc.inflight[at.ipK]++
			at.trackIP = true
		}
		return at, nil
	}
	b.clean.refill(now)
	if b.clean.tokens < 1 {
		wait := b.clean.due()
		if wait > limiterMaxDelay || l.delayed >= limiterMaxDelayed {
			return nil, throttledError{wait}
		}
		at.delay, at.delayed = wait, true
		l.delayed++
	}
	b.clean.tokens--
	return at, nil
}

// undelay marks the caller's delay as over.
func (at *attempt) undelay() {
	at.l.mu.Lock()
	defer at.l.mu.Unlock()
	if at.delayed {
		at.l.delayed--
		at.delayed = false
	}
}

// recheck reports a backoff that started while the attempt was queued
// (other attempts of the pair or source failed meanwhile).
func (at *attempt) recheck() error {
	l := at.l
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, e := range []*limEntry{at.sc.pairs[at.pairK], at.sc.ips[at.ipK]} {
		if e.locked(now) {
			return throttledError{e.lockedUntil.Sub(now)}
		}
	}
	return nil
}

// done completes the attempt: ok deletes the pair's and the source's
// failure state, a failure is recorded against both.
func (at *attempt) done(ok bool) { at.finish(true, ok) }

// cancel releases the reservation without counting anything (the password
// was never checked).
func (at *attempt) cancel() { at.finish(false, false) }

// record adds a failure for k in m, evicting the least recently used entry
// not in backoff when m is full; when every entry is in backoff the
// failure is dropped (existing backoffs are never lost).
func (l *limiter) record(sc *scope, m map[string]*limEntry, k string, threshold int, now time.Time) {
	e := m[k]
	if e == nil {
		if len(m) >= l.maxKeys {
			var oldK string
			var old *limEntry
			for kk, v := range m {
				if !v.locked(now) && sc.inflight[kk] == 0 && (old == nil || v.last.Before(old.last)) {
					oldK, old = kk, v
				}
			}
			if old == nil {
				return
			}
			delete(m, oldK)
		}
		e = &limEntry{}
		m[k] = e
	}
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

func (at *attempt) finish(checked, ok bool) {
	at.undelay()
	l := at.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if at.closed {
		return
	}
	at.closed = true
	sc := at.sc
	for _, x := range []struct {
		k       string
		tracked bool
	}{{at.pairK, at.trackPair}, {at.ipK, at.trackIP}} {
		if n, ok := sc.inflight[x.k]; x.tracked && ok {
			if n > 1 {
				sc.inflight[x.k] = n - 1
			} else {
				delete(sc.inflight, x.k)
			}
		}
	}
	if !checked {
		return
	}
	now := l.now()
	if ok {
		delete(sc.pairs, at.pairK)
		delete(sc.ips, at.ipK)
		return
	}
	l.record(sc, sc.pairs, at.pairK, pairThreshold, now)
	if at.ipK != "" {
		l.record(sc, sc.ips, at.ipK, ipThreshold, now)
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
