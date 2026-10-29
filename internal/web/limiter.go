package web

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Login limiting. Goals: slow password guessing, never run an attempt
// unthrottled, and never let failures from elsewhere lock the
// administrator out for longer than the rate limit's refill.
//
//   - Source: the client address; IPv6 is aggregated to its /64 so one host
//     cannot mint unlimited keys.
//   - Failures are tracked per (user bucket, source) pair. After
//     pairThreshold failures the pair waits limiterBase, doubling with each
//     further failure up to limiterMax. A success deletes the pair.
//   - Per source (all names): the same backoff after ipThreshold failures.
//   - Per user name, across all sources: a token bucket of userBurst
//     attempts refilled at userRate. Every attempt is charged a token. When
//     the bucket is empty, an attempt from a source with recent failures is
//     refused (429 + Retry-After); one from a clean source is delayed until
//     its token is due if that is at most limiterMaxDelay away and fewer
//     than limiterMaxDelayed callers are waiting, else refused too. Tokens
//     refill with time, so this is a delay, never a lasting lock: once the
//     bucket refills a clean source gets in whatever other sources did.
//     Buckets exist only for the administrator's name; every other name
//     shares one unknownUser bucket (and one pair per source), so spraying
//     names cannot grow the tables. Setup ("" user) has no bucket: it is
//     limited per source only.
//   - The attempt is reserved (in flight) before the argon2 check, so
//     concurrent attempts cannot overrun a threshold: a pair may have at
//     most as many attempts in flight as it has failures left.
//   - Entries are created only when a failure is recorded, and a success
//     deletes them, so every entry holds failure state; entries idle for
//     limiterForget are pruned, lazily at most once per limiterPruneEvery.
//     A table holds at most maxKeys entries; a full table never drops
//     failure state: attempts from sources it does not know are refused
//     (fail closed) until pruning frees room. With the buckets capping
//     failures at about 2*userRate per minute (admin + unknown), filling
//     10000 entries within limiterForget takes far more than an hour.
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
	// unknownUser is the shared bucket of every name that is not the
	// administrator's.
	unknownUser = "\x00unknown"
)

type limEntry struct {
	fails       int
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
	inflight  map[string]int // pair and source keys with attempts in flight
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
	l.inflight = map[string]int{}
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

// sourceKey is the limiter's key for a client address: IPv4 as is, IPv6
// as its /64.
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
	pairK string
	ipK   string
	// delay is how long the caller must wait before checking the password
	// (its token is not due yet); undelay ends the wait.
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
			if !now.Before(e.lockedUntil) && now.Sub(e.last) > limiterForget && l.inflight[k] == 0 {
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

// refusal applies e's backoff and the in-flight bound for key.
func (l *limiter) refusal(e *limEntry, key string, now time.Time, threshold int) (time.Duration, bool) {
	fails := 0
	if e != nil {
		if now.Before(e.lockedUntil) {
			return e.lockedUntil.Sub(now), true
		}
		fails = e.fails
	}
	left := threshold - fails
	if left < 1 {
		left = 1 // past the threshold: one attempt per backoff window
	}
	if l.inflight[key] >= left {
		return time.Second, true
	}
	return 0, false
}

// room reports whether m can take key (present, or not full).
func (l *limiter) room(m map[string]*limEntry, key string) bool {
	_, ok := m[key]
	return ok || len(m) < l.maxKeys
}

func (b *bucket) refill(now time.Time) {
	b.tokens += now.Sub(b.at).Minutes() * userRate
	if b.tokens > userBurst {
		b.tokens = userBurst
	}
	b.at = now
}

// begin reserves an attempt for user (the bucket name from limitUser;
// "" for setup) from ip, or refuses it with a throttledError. A refused
// attempt changes no state.
func (l *limiter) begin(user string, ip netip.Addr) (*attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybePrune(now)
	src := sourceKey(ip)
	at := &attempt{l: l, pairK: "p\x00" + user + "\x00" + src}
	full := throttledError{limiterBase}
	if !l.room(l.pairs, at.pairK) || (l.inflight[at.pairK] == 0 && len(l.inflight) >= 2*l.maxKeys) {
		return nil, full // fail closed: no room to record a failure
	}
	pair := l.pairs[at.pairK]
	if d, refused := l.refusal(pair, at.pairK, now, pairThreshold); refused {
		return nil, throttledError{d}
	}
	var b *bucket
	if user != "" {
		at.ipK = "s\x00" + src
		if !l.room(l.ips, at.ipK) {
			return nil, full
		}
		ipe := l.ips[at.ipK]
		if d, refused := l.refusal(ipe, at.ipK, now, ipThreshold); refused {
			return nil, throttledError{d}
		}
		b = l.users[user]
		if b == nil {
			if len(l.users) >= l.maxKeys {
				return nil, full
			}
			b = &bucket{tokens: userBurst, at: now}
		}
		b.refill(now)
		if b.tokens < 1 {
			wait := time.Duration((1 - b.tokens) / userRate * float64(time.Minute))
			dirty := (pair != nil && pair.fails > 0) || (ipe != nil && ipe.fails > 0)
			if dirty || wait > limiterMaxDelay || l.delayed >= limiterMaxDelayed {
				return nil, throttledError{wait}
			}
			at.delay, at.delayed = wait, true
			l.delayed++
		}
		b.tokens-- // every attempt is charged
		l.users[user] = b
	}
	l.inflight[at.pairK]++
	if at.ipK != "" {
		l.inflight[at.ipK]++
	}
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
	for _, e := range []*limEntry{l.pairs[at.pairK], l.ips[at.ipK]} {
		if e != nil && now.Before(e.lockedUntil) {
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
		if n := l.inflight[x.k]; n > 1 {
			l.inflight[x.k] = n - 1
		} else {
			delete(l.inflight, x.k)
		}
		switch {
		case !checked:
		case ok:
			delete(x.m, x.k)
		default:
			e := x.m[x.k]
			if e == nil {
				if len(x.m) >= l.maxKeys {
					continue // cannot happen: begin checked for room
				}
				e = &limEntry{}
				x.m[x.k] = e
			}
			e.fails++
			e.last = now
			if e.fails >= x.threshold {
				d := limiterBase << min(e.fails-x.threshold, 10)
				if d > limiterMax || d <= 0 {
					d = limiterMax
				}
				e.lockedUntil = now.Add(d)
			}
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
