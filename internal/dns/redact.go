package dns

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Keeping credentials out of formatted output
//
// fmt walks struct fields by reflection. When it enters a struct through an
// unexported field (or through a verb that is invalid for a pointer) it cannot
// call String/Format methods on what it finds, and it dereferences pointers,
// so ANY secret-bearing value reachable from a Provider through fields,
// pointers, interfaces, slices or maps can be printed, whatever type it has.
//
// The rule every provider follows: no secret-bearing value is reachable by
// reflection from a Provider value through the fields and containers the
// provider and doorwarden's httpx.Client own. (net/http's transport keeps
// recently written request bytes, headers included, in its keep-alive buffers;
// fmt cannot reach those through a Provider, and we do not disable keep-alives
// to hide them. all_test.go's walker documents that skip list.) Credentials, session tokens, derived
// authorization strings, scrub lists and SDK clients that embed credentials
// are held only inside closures (func-typed fields print as an address under
// every verb). The helpers below build such closures. Each Provider also has
// value-receiver String, GoString and Format methods that print only
// "<type> <redacted>". all_test.go enforces both the formatting behaviour and,
// with a reflection walk, the structural property.

// RedactedFormat is the body of a provider's Format method.
func RedactedFormat(f fmt.State, typ string) { _, _ = f.Write([]byte(typ + " <redacted>")) }

// StaticSecret returns an accessor for a fixed secret.
func StaticSecret(s secrets.Secret) func() secrets.Secret { return func() secrets.Secret { return s } }

// SecretCell holds a secret that changes over time (a session token) behind
// closures: get returns the current value, set replaces it, and compareAndClear
// clears it only if it still equals stale (so a goroutine does not discard a
// session another goroutine just created).
func SecretCell(initial secrets.Secret) (get func() secrets.Secret, set func(secrets.Secret), compareAndClear func(stale secrets.Secret)) {
	var mu sync.Mutex
	cur := initial
	get = func() secrets.Secret { mu.Lock(); defer mu.Unlock(); return cur }
	set = func(s secrets.Secret) { mu.Lock(); cur = s; mu.Unlock() }
	compareAndClear = func(stale secrets.Secret) {
		mu.Lock()
		if cur == stale {
			cur = ""
		}
		mu.Unlock()
	}
	return get, set, compareAndClear
}

// Scrubber collects secret values and returns closures to register more and to
// replace every registered value in a string with "[redacted]".
func Scrubber(initial ...secrets.Secret) (add func(secrets.Secret), scrub func(string) string) {
	var mu sync.RWMutex
	list := append([]secrets.Secret(nil), initial...)
	add = func(s secrets.Secret) { mu.Lock(); list = append(list, s); mu.Unlock() }
	scrub = func(s string) string {
		mu.RLock()
		defer mu.RUnlock()
		for _, sec := range list {
			if v := sec.Reveal(); v != "" {
				s = strings.ReplaceAll(s, v, "[redacted]")
			}
		}
		return s
	}
	return add, scrub
}
