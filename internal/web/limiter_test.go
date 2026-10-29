package web

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
)

func ipa(s string) netip.Addr { return netip.MustParseAddr(s) }

func failN(t *testing.T, l *limiter, user, ip string, n int) {
	t.Helper()
	for i := range n {
		at, err := l.begin(user, ipa(ip))
		if err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
		at.done(false)
	}
}

// Failures are tracked per (user, address): five lock that pair with a
// doubling backoff; the same user from another address is not affected.
func TestLimiterPairBackoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	failN(t, l, "admin", "198.51.100.1", pairThreshold)
	_, err := l.begin("admin", ipa("198.51.100.1"))
	var te throttledError
	if !errors.As(err, &te) || te.retry <= 0 {
		t.Fatalf("pair not locked: %v", err)
	}
	if at, err := l.begin("admin", ipa("198.51.100.2")); err != nil {
		t.Fatalf("other address refused: %v", err)
	} else {
		at.done(true)
	}
	now = now.Add(te.retry + time.Second)
	failN(t, l, "admin", "198.51.100.1", 1)
	_, err = l.begin("admin", ipa("198.51.100.1"))
	var te2 throttledError
	if !errors.As(err, &te2) || te2.retry <= te.retry {
		t.Fatalf("backoff did not grow: %v then %v", te.retry, te2.retry)
	}
	now = now.Add(te2.retry + time.Second)
	at, err := l.begin("admin", ipa("198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	at.done(true)
	failN(t, l, "admin", "198.51.100.1", pairThreshold-1) // reset by the success
}

// Attempts are reserved before the password check: concurrent attempts
// from one pair cannot overrun the threshold, and a cancelled reservation
// is not a failure.
func TestLimiterReservesBeforeVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	var held []*attempt
	for range pairThreshold {
		at, err := l.begin("admin", ipa("198.51.100.1"))
		if err != nil {
			t.Fatalf("reservation %d refused: %v", len(held), err)
		}
		held = append(held, at)
	}
	if _, err := l.begin("admin", ipa("198.51.100.1")); err == nil {
		t.Fatal("more in-flight attempts than the threshold allows")
	}
	held[0].cancel()
	at, err := l.begin("admin", ipa("198.51.100.1"))
	if err != nil {
		t.Fatalf("cancelled reservation still counted: %v", err)
	}
	for _, h := range append(held[1:], at) {
		h.done(false)
	}
	if _, err := l.begin("admin", ipa("198.51.100.1")); err == nil {
		t.Fatal("not locked after the reserved failures completed")
	}
}

// Every attempt is charged a token from the user's bucket. With it empty,
// an address with recent failures is refused, and a clean one is delayed
// until its token is due (at most limiterMaxDelay) or refused: no attempt
// ever runs uncharged. Refill lets a clean address in again.
func TestLimiterBucketAlwaysCharged(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	ran := 0
	for i := range 300 {
		at, err := l.begin("admin", ipa(fmt.Sprintf("203.0.113.%d", i%200)))
		if err != nil {
			continue
		}
		if at.delay > limiterMaxDelay {
			t.Fatalf("delay %v", at.delay)
		}
		ran++
		at.done(false)
	}
	// The burst plus the clean attempts whose token was due within the
	// maximum delay.
	if limit := userBurst + int(limiterMaxDelay.Minutes()*userRate) + 1; ran > limit {
		t.Fatalf("%d attempts ran, the bucket allows %d", ran, limit)
	}
	if _, err := l.begin("admin", ipa("198.51.100.77")); err == nil {
		t.Fatal("clean address ran uncharged with the bucket empty")
	}
	now = now.Add(time.Minute)
	at, err := l.begin("admin", ipa("198.51.100.77"))
	if err != nil || at.delay > limiterMaxDelay {
		t.Fatalf("clean address after refill: %v %+v", err, at)
	}
	at.done(true)
}

// A table full of failure state never drops it: a new source is refused
// (fail closed) until pruning frees room. Entries exist only for recorded
// failures.
func TestLimiterTableFullFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	l.maxKeys = 20
	for i := range 20 { // setup scope: no bucket to run dry
		failN(t, l, "", fmt.Sprintf("198.51.100.%d", i), pairThreshold)
	}
	if len(l.pairs) != 20 {
		t.Fatalf("pairs = %d", len(l.pairs))
	}
	if _, err := l.begin(unknownUser, ipa("203.0.113.1")); err == nil {
		t.Fatal("full table of locked entries accepted a new source")
	}
	if _, err := l.begin("", ipa("203.0.113.2")); err == nil || len(l.pairs) != 20 {
		t.Fatalf("state dropped or new source accepted: %v %d", err, len(l.pairs))
	}
	// A success creates nothing.
	l2 := newLimiter(func() time.Time { return now })
	at, _ := l2.begin("admin", ipa("198.51.100.1"))
	at.done(true)
	if len(l2.pairs)+len(l2.ips)+len(l2.inflight) != 0 {
		t.Fatalf("entries without failures: %d %d %d", len(l2.pairs), len(l2.ips), len(l2.inflight))
	}
	// Idle entries are pruned after limiterForget: room again.
	now = now.Add(limiterMax + limiterForget + 2*time.Minute)
	at, err := l.begin(unknownUser, ipa("203.0.113.1"))
	if err != nil {
		t.Fatalf("not pruned: %v", err)
	}
	at.cancel()
	if len(l.pairs) != 0 {
		t.Fatalf("pairs after prune = %d", len(l.pairs))
	}
}

// Spraying 100k random user names keeps every table bounded: names other
// than the administrator's share one bucket.
func TestLimiterNameSprayBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	l.maxKeys = 500
	adm := store.Admin{Username: "admin"}
	for i := range 100_000 {
		name := fmt.Sprintf("u%x", rand.Uint64())
		ip := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		if at, err := l.begin(limitUser(name, adm, true), ip); err == nil {
			at.done(false)
		}
		now = now.Add(50 * time.Millisecond)
	}
	if len(l.users) > 2 || len(l.pairs) > l.maxKeys || len(l.ips) > l.maxKeys || len(l.inflight) != 0 {
		t.Fatalf("tables grew: users=%d pairs=%d ips=%d inflight=%d", len(l.users), len(l.pairs), len(l.ips), len(l.inflight))
	}
	if got := limitUser("ADMIN", adm, true); got != "admin" {
		t.Fatalf("admin bucket = %q", got)
	}
	if limitUser("bad name!", adm, true) != unknownUser || limitUser("admin", adm, false) != unknownUser {
		t.Fatal("invalid or unknown names must share the unknown bucket")
	}
}

// IPv6 sources are aggregated to their /64: one host cannot mint keys.
func TestLimiterIPv6Aggregation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	for i := range pairThreshold {
		at, err := l.begin("admin", ipa(fmt.Sprintf("2001:db8:0:1::%x", i+1)))
		if err != nil {
			t.Fatal(err)
		}
		at.done(false)
	}
	if _, err := l.begin("admin", ipa("2001:db8:0:1:ffff::9")); err == nil {
		t.Fatal("another address in the same /64 not locked")
	}
	at, err := l.begin("admin", ipa("2001:db8:0:2::1"))
	if err != nil {
		t.Fatalf("another /64 locked: %v", err)
	}
	at.cancel()
	if sourceKey(ipa("::ffff:192.0.2.1")) != "192.0.2.1" {
		t.Fatal("v4-mapped address not unmapped")
	}
}

// A new credential generation (password change, `doorwarden admin unlock`
// or reset-password) clears all throttle state.
func TestLimiterGenerationReset(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	l.observeGeneration(0)
	failN(t, l, "admin", "198.51.100.1", pairThreshold)
	if _, err := l.begin("admin", ipa("198.51.100.1")); err == nil {
		t.Fatal("not locked")
	}
	l.observeGeneration(0)
	if _, err := l.begin("admin", ipa("198.51.100.1")); err == nil {
		t.Fatal("same generation reset the lock")
	}
	l.observeGeneration(1)
	if at, err := l.begin("admin", ipa("198.51.100.1")); err != nil {
		t.Fatalf("new generation kept the lock: %v", err)
	} else {
		at.cancel()
	}
}

// 101 attacker failures spaced over a simulated day, from addresses other
// than the administrator's, never stop the administrator's correct
// password from a clean address.
func TestAttackerFloodNeverLocksAdmin(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	var maxDelay time.Duration
	e.srv.auth.sleep = func(_ context.Context, d time.Duration) {
		maxDelay = max(maxDelay, d)
	}
	for i := range 101 {
		c := e.anon()
		c.remote = fmt.Sprintf("203.0.113.%d:1", i%7)
		w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong-password-xyz"})
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusTooManyRequests {
			t.Fatalf("attacker attempt %d: %d", i, w.Code)
		}
		e.advance(24 * time.Hour / 101)
		if i%10 == 0 {
			if _, w := e.login("admin", testPassword); w.Code != 200 {
				t.Fatalf("admin refused after %d attacker failures: %d %s", i+1, w.Code, w.Body)
			}
		}
	}
	if _, w := e.login("admin", testPassword); w.Code != 200 {
		t.Fatalf("admin refused at the end: %d", w.Code)
	}
	if maxDelay > limiterMaxDelay {
		t.Fatalf("admin delayed %v", maxDelay)
	}
}

// Behind a trusted proxy, five failures by one client (its own
// X-Forwarded-For address) lock only that client, not the others behind
// the same proxy.
func TestProxyClientFailuresIsolated(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Config.Web.TrustedProxies = []string{"192.0.2.0/24"}
	})
	e.setupAdmin()
	via := func() *client {
		c := e.anon()
		c.remote = "192.0.2.10:443" // the proxy
		return c
	}
	for range pairThreshold {
		c := via()
		c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong-password-xyz"},
			withHeader("X-Forwarded-For", "198.51.100.66"))
	}
	c := via()
	if w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": testPassword},
		withHeader("X-Forwarded-For", "198.51.100.66")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker client not locked: %d", w.Code)
	}
	c = via()
	if w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": testPassword},
		withHeader("X-Forwarded-For", "203.0.113.200, 198.51.100.20")); w.Code != 200 {
		t.Fatalf("other client behind the proxy refused: %d %s", w.Code, w.Body)
	}
}

// Setup failures are throttled per address only: wrong tokens from many
// addresses never block the right token from another.
func TestSetupThrottlePerAddressOnly(t *testing.T) {
	e := newTestEnv(t)
	for i := range 50 {
		c := e.anon()
		c.remote = fmt.Sprintf("203.0.113.%d:1", i)
		c.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": testPassword, "token": "wrong"})
	}
	bad := e.anon()
	bad.remote = "203.0.113.1:1"
	for range pairThreshold {
		bad.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": testPassword, "token": "wrong"})
	}
	if w := bad.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": testPassword, "token": testToken}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("setup address not throttled: %d", w.Code)
	}
	e.setupAdmin() // from a clean address
}

// `doorwarden admin unlock` (store.ResetCredentials) takes effect on the
// running server: the next login sees the new generation and the limits
// are gone.
func TestUnlockClearsRunningLimits(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	for range pairThreshold {
		e.login("admin", "wrong-password-xyz")
	}
	if _, w := e.login("admin", testPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("not locked: %d", w.Code)
	}
	if err := e.st.ResetCredentials(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, w := e.login("admin", testPassword); w.Code != 200 {
		t.Fatalf("still locked after unlock: %d %s", w.Code, w.Body)
	}
}
