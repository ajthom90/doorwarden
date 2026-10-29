package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// Hasher hashes and verifies passwords with argon2id. At most `parallel`
// hashes run at once (each one allocates Params.Memory), so a login flood
// cannot exhaust memory; callers queue instead.
type Hasher struct {
	p     Argon2Params
	sem   chan struct{}
	once  sync.Once
	dummy string
}

// NewHasher returns a Hasher; parallel < 1 means 2.
func NewHasher(p Argon2Params, parallel int) *Hasher {
	if parallel < 1 {
		parallel = 2
	}
	return &Hasher{p: p, sem: make(chan struct{}, parallel)}
}

func (h *Hasher) key(pw, salt []byte, p Argon2Params) []byte {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// Hash returns the PHC string $argon2id$v=19$m=..,t=..,p=..$salt$key.
func (h *Hasher) Hash(password string) (string, error) {
	if len(password) > maxPasswordLen {
		return "", errors.New("password too long")
	}
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := h.key([]byte(password), salt, h.p)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.p.Memory, h.p.Time, h.p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(k)), nil
}

// Verify reports whether password matches encoded (constant-time compare).
// A malformed or out-of-bounds encoding never verifies.
func (h *Hasher) Verify(encoded, password string) bool {
	p, salt, want, ok := parsePHC(encoded)
	if !ok || len(password) > maxPasswordLen {
		return false
	}
	got := h.key([]byte(password), salt, p)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VerifyDummy spends the same work as Verify against a fixed hash, so a
// login for an unknown user takes as long as one for the real user.
func (h *Hasher) VerifyDummy(password string) {
	h.once.Do(func() {
		h.dummy, _ = h.Hash("doorwarden-dummy-password")
	})
	_ = h.Verify(h.dummy, password)
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
const (
	throttleThreshold = 5
	throttleBase      = 30 * time.Second
	throttleMax       = 15 * time.Minute
	throttleForget    = time.Hour
	throttleMaxKeys   = 10000
)

type throttleEntry struct {
	fails       int
	lockedUntil time.Time
	last        time.Time
}

type throttle struct {
	mu  sync.Mutex
	m   map[string]*throttleEntry
	now func() time.Time
}

func newThrottle(now func() time.Time) *throttle {
	return &throttle{m: map[string]*throttleEntry{}, now: now}
}

// allowed reports whether key may try now; when not, how long to wait.
func (t *throttle) allowed(key string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	if e == nil {
		return true, 0
	}
	now := t.now()
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
	e := t.m[key]
	if e == nil {
		if len(t.m) >= throttleMaxKeys {
			t.prune(now)
		}
		if len(t.m) >= throttleMaxKeys {
			// Full of live entries: forget the oldest unlocked one.
			var oldK string
			var old *throttleEntry
			for k, v := range t.m {
				if now.Before(v.lockedUntil) {
					continue
				}
				if old == nil || v.last.Before(old.last) {
					oldK, old = k, v
				}
			}
			if old == nil {
				return // every entry is locked; this key stays unthrottled until one expires
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
	delete(t.m, key)
}

func (t *throttle) prune(now time.Time) {
	for k, v := range t.m {
		if now.After(v.lockedUntil) && now.Sub(v.last) > throttleForget {
			delete(t.m, k)
		}
	}
}
