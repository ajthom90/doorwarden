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
//     limiterForget; otherwise CLEAN. Failure entries exist only for
//     recorded failures (a success deletes them).
//   - Every attempt, clean or dirty, is counted in flight under its pair
//     and (login) source key, bounded by max(1, threshold - fails) with
//     fails = 0 when there is no entry, so a concurrent burst cannot
//     overrun a threshold before its failures are recorded.
//   - Dirty attempts are refused (429 + Retry-After) while the pair or
//     source is in backoff (pairThreshold / ipThreshold failures, then
//     limiterBase doubling to limiterMax).
//   - Login budget: one TOTAL bucket per user name (totalBurst, totalRate)
//     charged by every attempt. cleanReserve tokens of it are a share that
//     only clean attempts may use: a dirty attempt is refused when taking a
//     token would leave less than cleanReserve, so a dirty flood of any
//     size exhausts only the dirty share. A clean attempt may use any
//     token; with none left it is delayed until its token is due, at most
//     limiterMaxDelay, with at most limiterMaxDelayed callers waiting, and
//     beyond that gets 429 + Retry-After for that attempt only. Nothing
//     ever runs uncharged.
//   - Accepted residual risk: rotating fresh (clean) sources cannot exceed
//     the total rate, i.e. at most totalBurst + 60*totalRate = 1830 guesses
//     in any hour (about 43k a day) against the administrator's name, each
//     an argon2id check of a password of at least 15 characters.
//   - Buckets exist for the administrator's name and one shared
//     unknownUser (every other name), so name sprays cannot grow tables.
//   - Setup budget: per SOURCE only (setupBurst, setupRate), no shared
//     bucket: the setup token is 192-bit random, so global brute-force
//     protection is unnecessary and a shared bucket would only let anyone
//     block first-run setup. A full setup bucket table evicts the least
//     recently used bucket.
//   - Tables are bounded (maxKeys). Recording a failure in a full table
//     evicts the least recently used entry that is not in backoff; when
//     every entry is in backoff the failure is not recorded (fail closed
//     for dirty state only: the source then stays clean, which is still
//     charged against the total bucket). Idle entries are pruned after
//     limiterForget, lazily at most once per limiterPruneEvery.
//   - Attempts are reserved before the argon2 check and re-checked for a
//     new backoff once a hashing slot is held. A charged attempt the
//     client abandons (disconnect, timeout) or the hashing queue refuses
//     counts as a failure, so starting and dropping attempts turns a
//     source dirty instead of draining the clean share for free.
//   - Waiting (delayed) clean callers are capped per scope
//     (limiterMaxDelayed) and per source (limiterMaxDelayedPerSource).
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
	totalBurst        = 30
	totalRate         = 30.0 // per minute
	cleanReserve      = 5
	setupBurst        = 5
	setupRate         = 12.0 // per minute
	limiterMaxDelay   = 5 * time.Second
	limiterMaxDelayed = 16 // per scope
	// limiterMaxDelayedPerSource bounds one source's waiting callers.
	limiterMaxDelayedPerSource = 2
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

// due is how long until the bucket holds n tokens.
func (b *bucket) due(n float64) time.Duration {
	return time.Duration((n - b.tokens) / b.rate * float64(time.Minute))
}

type scope struct {
	pairs    map[string]*limEntry
	ips      map[string]*limEntry // login only
	inflight map[string]int       // pair/source keys with attempts in flight
	// buckets: login per user name (limitUser), setup per source.
	buckets map[string]*bucket
	setup   bool
	// delayed counts callers waiting for a clean token, in this scope and
	// per source (delayedBy), so a few sources cannot hold every slot.
	delayed   int
	delayedBy map[string]int
	reserve   float64
	burst     float64
	rate      float64
}

func newScope(setup bool) *scope {
	sc := &scope{pairs: map[string]*limEntry{}, ips: map[string]*limEntry{}, inflight: map[string]int{}, buckets: map[string]*bucket{}, delayedBy: map[string]int{}, setup: setup}
	if setup {
		sc.burst, sc.rate = setupBurst, setupRate
	} else {
		sc.burst, sc.rate, sc.reserve = totalBurst, totalRate, cleanReserve
	}
	return sc
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
}

func newLimiter(now func() time.Time) *limiter {
	l := &limiter{now: now, maxKeys: limiterMaxKeys}
	l.reset()
	return l
}

func (l *limiter) reset() {
	l.login, l.setup = newScope(false), newScope(true)
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
	src   string
	pairK string
	ipK   string // "" for setup
	// trackPair, trackIP: the attempt is counted in sc.inflight under
	// pairK / ipK.
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
		for k, b := range sc.buckets {
			if now.Sub(b.at) > limiterForget {
				delete(sc.buckets, k)
			}
		}
	}
}

// bucket returns the bucket for key. A full table falls back to the shared
// unknownUser bucket (login) or evicts the least recently used bucket
// (setup: per source only, never shared).
func (l *limiter) bucket(sc *scope, key string, now time.Time) *bucket {
	if b := sc.buckets[key]; b != nil {
		return b
	}
	if len(sc.buckets) >= l.maxKeys {
		if !sc.setup {
			key = unknownUser
			if b := sc.buckets[key]; b != nil {
				return b
			}
		} else {
			var oldK string
			var old *bucket
			for k, b := range sc.buckets {
				if old == nil || b.at.Before(old.at) {
					oldK, old = k, b
				}
			}
			delete(sc.buckets, oldK)
		}
	}
	b := &bucket{tokens: sc.burst, at: now, rate: sc.rate, burst: sc.burst}
	sc.buckets[key] = b
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
	at := &attempt{l: l, sc: sc, src: src, pairK: user + "\x00" + src}
	if !sc.setup {
		at.ipK = src
	}
	pair, ipe := sc.pairs[at.pairK], sc.ips[at.ipK]
	dirty := pair != nil || ipe != nil
	for _, x := range []struct {
		e         *limEntry
		k         string
		threshold int
	}{{pair, at.pairK, pairThreshold}, {ipe, at.ipK, ipThreshold}} {
		if x.k == "" {
			continue
		}
		fails := 0
		if x.e != nil {
			if x.e.locked(now) {
				return nil, throttledError{x.e.lockedUntil.Sub(now)}
			}
			fails = x.e.fails
		}
		if sc.inflight[x.k] >= max(1, x.threshold-fails) {
			return nil, throttledError{time.Second}
		}
	}
	bk := user
	if sc.setup {
		bk = src
	}
	b := l.bucket(sc, bk, now)
	b.refill(now)
	switch {
	case dirty && b.tokens < 1+sc.reserve:
		// Dirty attempts never take the clean share.
		return nil, throttledError{b.due(1 + sc.reserve)}
	case !dirty && b.tokens < 1:
		wait := b.due(1)
		if wait > limiterMaxDelay || sc.delayed >= limiterMaxDelayed || sc.delayedBy[src] >= limiterMaxDelayedPerSource {
			return nil, throttledError{max(wait, time.Second)}
		}
		at.delay, at.delayed = wait, true
		sc.delayed++
		sc.delayedBy[src]++
	}
	b.tokens--
	sc.inflight[at.pairK]++
	at.trackPair = true
	if at.ipK != "" {
		sc.inflight[at.ipK]++
		at.trackIP = true
	}
	return at, nil
}

// undelay marks the caller's delay as over.
func (at *attempt) undelay() {
	at.l.mu.Lock()
	defer at.l.mu.Unlock()
	if at.delayed {
		sc := at.sc
		sc.delayed--
		if sc.delayedBy[at.src]--; sc.delayedBy[at.src] <= 0 {
			delete(sc.delayedBy, at.src)
		}
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

// cancel releases the reservation without counting anything. Only for an
// attempt the server itself refused after begin (a backoff found by
// recheck); the token stays spent.
func (at *attempt) cancel() { at.finish(false, false) }

// abandon ends an attempt the client gave up (disconnect, timeout) or the
// hashing queue refused after it was charged: it counts as a failure, so
// the source turns dirty and can no longer spend the clean share by
// starting and dropping attempts. The token stays spent.
func (at *attempt) abandon() { at.finish(true, false) }

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
