package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultArgon2Params: 64 MiB, 3 passes, 2 lanes (RFC 9106's second
// recommended option, with the memory the OWASP cheat sheet suggests).
var DefaultArgon2Params = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

// Upper bounds accepted when verifying a stored hash, so a tampered row
// cannot make one login allocate gigabytes or spin for minutes.
const (
	maxArgonMemory  = 256 * 1024
	maxArgonTime    = 10
	maxArgonThreads = 16
)

// maxPasswordLen bounds the input to the hash.
const maxPasswordLen = 1024

// maxHashWaiters bounds the callers queued for a hashing slot. Past it a
// caller gets ErrHasherBusy at once (the API answers 503 + Retry-After), so
// a login flood holds at most parallel+maxHashWaiters goroutines in the
// password path instead of an unbounded backlog.
const maxHashWaiters = 8

// ErrHasherBusy is returned when every hashing slot is busy and the wait
// queue is full.
var ErrHasherBusy = errors.New("password hashing is busy")

// Hasher hashes and verifies passwords with argon2id. At most `parallel`
// hashes run at once (each one allocates Params.Memory), so a login flood
// cannot exhaust memory; at most maxHashWaiters callers queue behind them,
// and a queued caller leaves when its context ends.
type Hasher struct {
	p       Argon2Params
	sem     chan struct{}
	waiting atomic.Int32
	// kdf derives the key (argon2.IDKey; replaced in tests).
	kdf   func(pw, salt []byte, p Argon2Params) []byte
	once  sync.Once
	dummy string
}

// NewHasher returns a Hasher; parallel < 1 means 2.
func NewHasher(p Argon2Params, parallel int) *Hasher {
	if parallel < 1 {
		parallel = 2
	}
	return &Hasher{p: p, sem: make(chan struct{}, parallel), kdf: func(pw, salt []byte, p Argon2Params) []byte {
		return argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	}}
}

// acquire takes a hashing slot, waiting (bounded, cancellable) when all are
// busy. The returned func releases it.
func (h *Hasher) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release := func() { <-h.sem }
	select {
	case h.sem <- struct{}{}:
		return release, nil
	default:
	}
	if h.waiting.Add(1) > maxHashWaiters {
		h.waiting.Add(-1)
		return nil, ErrHasherBusy
	}
	defer h.waiting.Add(-1)
	select {
	case h.sem <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// run acquires a slot, runs recheck (a non-nil error aborts before any
// work: state such as a throttle may have changed while queued), then fn.
func (h *Hasher) run(ctx context.Context, recheck func() error, fn func()) error {
	release, err := h.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if recheck != nil {
		if err := recheck(); err != nil {
			return err
		}
	}
	fn()
	return nil
}

func (h *Hasher) newHash(password string) (string, error) {
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := h.kdf([]byte(password), salt, h.p)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.p.Memory, h.p.Time, h.p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(k)), nil
}

// Hash returns the PHC string $argon2id$v=19$m=..,t=..,p=..$salt$key.
func (h *Hasher) Hash(password string) (string, error) {
	return h.HashContext(context.Background(), password)
}

// HashContext is Hash through the bounded queue: ErrHasherBusy or the
// context's error when no slot could be had.
func (h *Hasher) HashContext(ctx context.Context, password string) (string, error) {
	if len(password) > maxPasswordLen {
		return "", errors.New("password too long")
	}
	var out string
	var herr error
	if err := h.run(ctx, nil, func() { out, herr = h.newHash(password) }); err != nil {
		return "", err
	}
	return out, herr
}

// Verify reports whether password matches encoded (constant-time compare).
// A malformed or out-of-bounds encoding never verifies.
func (h *Hasher) Verify(encoded, password string) bool {
	ok, _ := h.VerifyContext(context.Background(), encoded, password, nil)
	return ok
}

// VerifyContext is Verify through the bounded queue; recheck runs once a
// slot is held, before the KDF, and its error aborts the attempt. err is
// ErrHasherBusy, the context's error or recheck's.
func (h *Hasher) VerifyContext(ctx context.Context, encoded, password string, recheck func() error) (bool, error) {
	p, salt, want, ok := parsePHC(encoded)
	if !ok || len(password) > maxPasswordLen {
		// Still take a slot so a malformed row costs the same and is
		// throttled the same.
		return false, h.run(ctx, recheck, func() {})
	}
	var match bool
	err := h.run(ctx, recheck, func() {
		got := h.kdf([]byte(password), salt, p)
		match = subtle.ConstantTimeCompare(got, want) == 1
	})
	return match, err
}

// VerifyDummy spends the same work as Verify against a fixed hash, so a
// login for an unknown user takes as long as one for the real user.
func (h *Hasher) VerifyDummy(password string) {
	_ = h.VerifyDummyContext(context.Background(), password, nil)
}

// VerifyDummyContext is VerifyDummy through the same bounded queue, so
// unknown-user attempts cannot bypass it.
func (h *Hasher) VerifyDummyContext(ctx context.Context, password string, recheck func() error) error {
	h.once.Do(func() {
		// Computed outside the queue (once per process).
		h.dummy, _ = h.newHash("doorwarden-dummy-password")
	})
	_, err := h.VerifyContext(ctx, h.dummy, password, recheck)
	return err
}

func parsePHC(s string) (Argon2Params, []byte, []byte, bool) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return Argon2Params{}, nil, nil, false
	}
	var p Argon2Params
	var threads uint32
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &threads); err != nil || n != 3 {
		return Argon2Params{}, nil, nil, false
	}
	if p.Memory < 8 || p.Memory > maxArgonMemory || p.Time < 1 || p.Time > maxArgonTime || threads < 1 || threads > maxArgonThreads {
		return Argon2Params{}, nil, nil, false
	}
	p.Threads = uint8(threads)
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	key, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(salt) > 64 || len(key) < 16 || len(key) > 64 {
		return Argon2Params{}, nil, nil, false
	}
	p.KeyLen, p.SaltLen = uint32(len(key)), uint32(len(salt))
	return p, salt, key, true
}

// Login throttling: after throttleThreshold failures for a key (client IP
// or user name) the key is locked for throttleBase, doubling with every
// further failure up to throttleMax. A success resets the key; an entry
// with no failure for throttleForget is dropped.
//
// Fail closed under table pressure: pinned keys (the administrator's user
// name) live in their own map that is never evicted, so the per-user lock
// always holds however many addresses or names an attacker cycles through.
// The general table holds at most throttleMaxKeys entries; when it is full
// of locked entries a new key cannot be recorded and every key not in the
// table is refused until the earliest lock ends (saturated).
const (
	throttleThreshold = 5
	throttleBase      = 30 * time.Second
	throttleMax       = 15 * time.Minute
	throttleForget    = time.Hour
	throttleMaxKeys   = 10000
	throttleMaxPinned = 8
)

type throttleEntry struct {
	fails       int
	lockedUntil time.Time
	last        time.Time
}

type throttle struct {
	mu        sync.Mutex
	m         map[string]*throttleEntry
	pinned    map[string]*throttleEntry
	saturated time.Time // until: keys not in m are refused
	now       func() time.Time
	maxKeys   int
}

func newThrottle(now func() time.Time) *throttle {
	return &throttle{m: map[string]*throttleEntry{}, pinned: map[string]*throttleEntry{}, now: now, maxKeys: throttleMaxKeys}
}

// pin makes key non-evictable (bounded; the oldest unlocked pin is
// replaced when full).
func (t *throttle) pin(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.pinned[key]; ok {
		return
	}
	if len(t.pinned) >= throttleMaxPinned {
		now := t.now()
		for k, v := range t.pinned {
			if !now.Before(v.lockedUntil) {
				delete(t.pinned, k)
				break
			}
		}
		if len(t.pinned) >= throttleMaxPinned {
			return
		}
	}
	e := t.m[key]
	if e == nil {
		e = &throttleEntry{}
	}
	delete(t.m, key)
	t.pinned[key] = e
}

// allowed reports whether key may try now; when not, how long to wait.
func (t *throttle) allowed(key string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e := t.pinned[key]
	if e == nil {
		e = t.m[key]
	}
	if e == nil {
		if now.Before(t.saturated) {
			return false, t.saturated.Sub(now)
		}
		if len(t.m) >= t.maxKeys {
			// A failure of this key could not be recorded: refuse it
			// while every entry is locked.
			t.prune(now)
			if until := t.allLocked(now); !until.IsZero() {
				t.saturated = until
				return false, until.Sub(now)
			}
		}
		return true, 0
	}
	if now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// fail records a failure for key.
func (t *throttle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e := t.pinned[key]
	if e == nil {
		e = t.m[key]
	}
	if e == nil {
		if len(t.m) >= t.maxKeys {
			t.prune(now)
		}
		if len(t.m) >= t.maxKeys {
			// Full: forget the oldest unlocked entry.
			var oldK string
			var old *throttleEntry
			earliest := time.Time{}
			for k, v := range t.m {
				if now.Before(v.lockedUntil) {
					if earliest.IsZero() || v.lockedUntil.Before(earliest) {
						earliest = v.lockedUntil
					}
					continue
				}
				if old == nil || v.last.Before(old.last) {
					oldK, old = k, v
				}
			}
			if old == nil {
				// Every entry is locked: the key cannot be recorded, so
				// unrecorded keys are refused until a lock ends.
				t.saturated = earliest
				return
			}
			delete(t.m, oldK)
		}
		e = &throttleEntry{}
		t.m[key] = e
	}
	e.fails++
	e.last = now
	if e.fails >= throttleThreshold {
		d := throttleBase << min(e.fails-throttleThreshold, 10)
		if d > throttleMax || d <= 0 {
			d = throttleMax
		}
		e.lockedUntil = now.Add(d)
	}
}

// success resets key.
func (t *throttle) success(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.pinned[key]; e != nil {
		*e = throttleEntry{}
		return
	}
	delete(t.m, key)
}

// allLocked returns the earliest lock end when the table is full and every
// entry is locked, else the zero time.
func (t *throttle) allLocked(now time.Time) time.Time {
	if len(t.m) < t.maxKeys {
		return time.Time{}
	}
	var earliest time.Time
	for _, v := range t.m {
		if !now.Before(v.lockedUntil) {
			return time.Time{}
		}
		if earliest.IsZero() || v.lockedUntil.Before(earliest) {
			earliest = v.lockedUntil
		}
	}
	return earliest
}

func (t *throttle) prune(now time.Time) {
	for k, v := range t.m {
		if now.After(v.lockedUntil) && now.Sub(v.last) > throttleForget {
			delete(t.m, k)
		}
	}
}
