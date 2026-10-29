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

type fakeNow struct{ t time.Time }

func (f *fakeNow) now() time.Time      { return f.t }
func (f *fakeNow) add(d time.Duration) { f.t = f.t.Add(d) }
func newFakeNow() *fakeNow             { return &fakeNow{time.Unix(1_800_000_000, 0)} }
func lockedEntry(now time.Time) *limEntry {
	return &limEntry{fails: pairThreshold, lockedUntil: now.Add(10 * time.Minute), last: now}
}

// failN makes n failed attempts, advancing the clock past any clean-bucket
// delay so the attempts themselves are never the thing refused.
func failN(t *testing.T, l *limiter, clk *fakeNow, user, ip string, n int) {
	t.Helper()
	for i := range n {
		at, err := l.begin(user, ipa(ip))
		if err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
		at.done(false)
		clk.add(limiterMaxDelay)
	}
}

// Failures are tracked per (user, address): five lock that pair with a
// doubling backoff; the same user from another address is not affected,
// and a success clears the pair.
func TestLimiterPairBackoff(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	failN(t, l, clk, "admin", "198.51.100.1", pairThreshold)
	_, err := l.begin("admin", ipa("198.51.100.1"))
	var te throttledError
	if !errors.As(err, &te) || te.retry <= 0 {
		t.Fatalf("pair not locked: %v", err)
	}
	at, err := l.begin("admin", ipa("198.51.100.2"))
	if err != nil {
		t.Fatalf("other address refused: %v", err)
	}
	at.done(true)
	clk.add(te.retry + time.Second)
	failN(t, l, clk, "admin", "198.51.100.1", 1)
	_, err = l.begin("admin", ipa("198.51.100.1"))
	var te2 throttledError
	if !errors.As(err, &te2) || te2.retry <= te.retry-limiterMaxDelay {
		t.Fatalf("backoff did not grow: %v then %v", te.retry, te2.retry)
	}
	clk.add(te2.retry + time.Second)
	at, err = l.begin("admin", ipa("198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	at.done(true)
	if len(l.login.pairs) != 0 {
		t.Fatal("success left failure state")
	}
}

// A dirty pair's attempts are reserved before the password check:
// concurrent attempts cannot overrun the threshold, and a cancelled
// reservation is not a failure.
func TestLimiterReservesBeforeVerify(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	failN(t, l, clk, "admin", "198.51.100.1", 1)
	var held []*attempt
	for range pairThreshold - 1 {
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
	if len(l.login.inflight) != 0 {
		t.Fatalf("inflight leaked: %v", l.login.inflight)
	}
}

// Point 1: dirty attempts cannot drain the clean bucket. After a flood of
// 10k dirty attempts from many addresses, a clean address gets in within
// limiterMaxDelay. Clean attempts are always charged: over the clean
// waiter cap or beyond the max delay they get a transient refusal, and
// refill lets them in again.
func TestLimiterCleanSurvivesDirtyFlood(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	for i := range 200 {
		failN(t, l, clk, "admin", fmt.Sprintf("203.0.113.%d", i), 1)
	}
	clk.add(time.Minute) // clean bucket refills; failures stay recent
	ran := 0
	for i := range 10_000 {
		at, err := l.begin("admin", ipa(fmt.Sprintf("203.0.113.%d", i%200)))
		if err != nil {
			continue
		}
		if at.delay != 0 {
			t.Fatal("dirty attempt was given a clean delay")
		}
		ran++
		at.done(false)
	}
	if ran > totalBurst-cleanReserve {
		t.Fatalf("%d dirty attempts ran, the dirty share is %d", ran, totalBurst-cleanReserve)
	}
	at, err := l.begin("admin", ipa("198.51.100.77"))
	if err != nil || at.delay > limiterMaxDelay {
		t.Fatalf("clean address after a dirty flood: %v %+v", err, at)
	}
	at.done(true)

	// Clean attempts that never complete: the bucket runs dry, the next
	// ones are delayed (up to limiterMaxDelay), then refused (transiently).
	l2 := newLimiter(clk.now)
	var got []error
	for i := range totalBurst + 3 {
		at, err := l2.begin("admin", ipa(fmt.Sprintf("198.51.100.%d", i)))
		got = append(got, err)
		if err == nil && i >= totalBurst && (at.delay == 0 || at.delay > limiterMaxDelay) {
			t.Fatalf("clean attempt %d past the burst: delay %v", i, at.delay)
		}
	}
	if got[totalBurst] != nil || got[totalBurst+1] != nil || got[totalBurst+2] == nil {
		t.Fatalf("clean refusals = %v", got[totalBurst:])
	}
	clk.add(time.Minute)
	if _, err := l2.begin("admin", ipa("198.51.100.99")); err != nil {
		t.Fatalf("bucket did not refill: %v", err)
	}
}

// The clean waiter cap refuses (429) rather than letting attempts through.
func TestLimiterCleanWaiterCap(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.delayed = limiterMaxDelayed
	for i := range totalBurst {
		at, err := l.begin("admin", ipa(fmt.Sprintf("198.51.100.%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		at.cancel()
	}
	if _, err := l.begin("admin", ipa("198.51.100.200")); err == nil {
		t.Fatal("waiter cap full but the attempt ran")
	}
}

// Point 2: a full table evicts the least recently used entry not in
// backoff; when every entry is in backoff the new failure is dropped
// (existing backoffs are kept) and clean sources still get in.
func TestLimiterTablePressure(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.maxKeys = 20
	now := clk.now()
	for i := range 20 {
		l.login.pairs[fmt.Sprintf("admin\x00198.51.100.%d", i)] = lockedEntry(now)
	}
	failN(t, l, clk, "admin", "203.0.113.1", 1)
	if len(l.login.pairs) != 20 {
		t.Fatalf("pairs = %d", len(l.login.pairs))
	}
	if _, ok := l.login.pairs["admin\x00203.0.113.1"]; ok {
		t.Fatal("a locked entry was evicted")
	}
	at, err := l.begin("admin", ipa("203.0.113.2"))
	if err != nil {
		t.Fatalf("clean source refused under table pressure: %v", err)
	}
	at.done(true)
	// One entry whose backoff ended is evictable (the oldest such).
	old := l.login.pairs["admin\x00198.51.100.3"]
	old.lockedUntil, old.last = now.Add(-time.Second), now.Add(-time.Minute)
	failN(t, l, clk, "admin", "203.0.113.3", 1)
	if _, ok := l.login.pairs["admin\x00198.51.100.3"]; ok {
		t.Fatal("expired entry not evicted")
	}
	if _, ok := l.login.pairs["admin\x00203.0.113.3"]; !ok || len(l.login.pairs) != 20 {
		t.Fatal("new failure not recorded after eviction")
	}
	// Idle entries are pruned.
	clk.add(limiterMax + limiterForget + 2*time.Minute)
	at, err = l.begin("admin", ipa("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	at.cancel()
	if len(l.login.pairs) != 0 {
		t.Fatalf("pairs after prune = %d", len(l.login.pairs))
	}
}

// Point 3: setup has its own tables and buckets; login pressure does not
// reach it and vice versa. Creating the administrator clears everything.
func TestLimiterSetupSeparate(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.maxKeys = 5
	now := clk.now()
	for i := range 5 {
		l.login.pairs[fmt.Sprintf("admin\x00198.51.100.%d", i)] = lockedEntry(now)
		l.login.ips[fmt.Sprintf("198.51.100.%d", i)] = lockedEntry(now)
	}
	for range totalBurst {
		if at, err := l.begin("admin", ipa("203.0.113.50")); err == nil {
			at.cancel()
		}
	}
	failN(t, l, clk, "", "198.51.100.1", 1) // setup from a login-locked source
	if _, ok := l.setup.pairs["\x00198.51.100.1"]; !ok {
		t.Fatal("setup failure not recorded in its own table")
	}
	if len(l.login.pairs) != 5 {
		t.Fatal("setup touched the login table")
	}
	failN(t, l, clk, "", "198.51.100.1", pairThreshold-1)
	if _, err := l.begin("", ipa("198.51.100.1")); err == nil {
		t.Fatal("setup source not backed off")
	}
	if at, err := l.begin("", ipa("198.51.100.2")); err != nil {
		t.Fatalf("other setup source refused: %v", err)
	} else {
		at.cancel()
	}
	l.resetAll()
	if len(l.login.pairs)+len(l.setup.pairs)+len(l.login.ips) != 0 {
		t.Fatal("resetAll kept state")
	}
}

// Point 4: IPv6 sources are aggregated to their /64, IPv4 to /32.
func TestLimiterSourceAggregation(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	for i := range pairThreshold {
		failN(t, l, clk, "admin", fmt.Sprintf("2001:db8:0:1::%x", i+1), 1)
	}
	if _, err := l.begin("admin", ipa("2001:db8:0:1:ffff::9")); err == nil {
		t.Fatal("another address in the same /64 not locked")
	}
	at, err := l.begin("admin", ipa("2001:db8:0:2::1"))
	if err != nil {
		t.Fatalf("another /64 locked: %v", err)
	}
	at.cancel()
	if sourceKey(ipa("::ffff:192.0.2.1")) != "192.0.2.1" || sourceKey(ipa("192.0.2.1")) == sourceKey(ipa("192.0.2.2")) {
		t.Fatal("IPv4 must be per /32 (and v4-mapped unmapped)")
	}
}

// Point 5: spraying 100k random user names keeps every table bounded:
// names other than the administrator's share one bucket.
func TestLimiterNameSprayBounded(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.maxKeys = 500
	adm := store.Admin{Username: "admin"}
	for i := range 100_000 {
		name := fmt.Sprintf("u%x", rand.Uint64())
		ip := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		if at, err := l.begin(limitUser(name, adm, true), ip); err == nil {
			at.done(false)
		}
		clk.add(50 * time.Millisecond)
	}
	sc := l.login
	if len(sc.buckets) > 2 || len(sc.pairs) > l.maxKeys || len(sc.ips) > l.maxKeys || len(sc.inflight) != 0 {
		t.Fatalf("tables grew: buckets=%d pairs=%d ips=%d inflight=%d", len(sc.buckets), len(sc.pairs), len(sc.ips), len(sc.inflight))
	}
	if got := limitUser("ADMIN", adm, true); got != "admin" {
		t.Fatalf("admin bucket = %q", got)
	}
	if limitUser("bad name!", adm, true) != unknownUser || limitUser("admin", adm, false) != unknownUser {
		t.Fatal("invalid or unknown names must share the unknown bucket")
	}
}

// A new credential generation (password change, `doorwarden admin unlock`
// or reset-password) clears all throttle state.
func TestLimiterGenerationReset(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.observeGeneration(0)
	failN(t, l, clk, "admin", "198.51.100.1", pairThreshold)
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
	e.srv.auth.sleep = func(context.Context, time.Duration) {}
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
	// Setup budgets are per source: setup from another address goes
	// through at once.
	e.setupAdmin()
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

// Amendment 1: clean attempts are counted in flight like dirty ones, so a
// concurrent burst from one new address admits at most the pair bound.
func TestLimiterCleanBurstBounded(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	admitted := 0
	var held []*attempt
	for range 200 {
		if at, err := l.begin("admin", ipa("198.51.100.5")); err == nil {
			admitted++
			held = append(held, at)
		}
	}
	if admitted != pairThreshold {
		t.Fatalf("admitted %d concurrent attempts from one new address, bound %d", admitted, pairThreshold)
	}
	for _, at := range held {
		at.done(false)
	}
	if _, err := l.begin("admin", ipa("198.51.100.5")); err == nil {
		t.Fatal("pair not locked after the burst's failures")
	}
	// Across names, one source is bounded by ipThreshold.
	admitted = 0
	for i := range 200 {
		if _, err := l.begin(fmt.Sprintf("u%d", i), ipa("198.51.100.6")); err == nil {
			admitted++
		}
	}
	if admitted != ipThreshold {
		t.Fatalf("admitted %d across names from one source, bound %d", admitted, ipThreshold)
	}
	if len(l.login.inflight) == 0 {
		t.Fatal("clean attempts not counted in flight")
	}
}

// Amendment 2: every attempt is charged to the user's total bucket, so
// rotating fresh sources cannot exceed the total rate; dirty traffic
// exhausts only the dirty share and the clean reserve stays available.
func TestLimiterTotalCap(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	admitted := 0
	for i := range 36_000 { // one fresh source every 100ms for an hour
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if at, err := l.begin("admin", ip); err == nil {
			admitted++
			at.done(false)
		}
		clk.add(100 * time.Millisecond)
	}
	if limit := totalBurst + int(60*totalRate) + 2; admitted > limit {
		t.Fatalf("%d guesses in an hour from rotating sources, cap %d", admitted, limit)
	}
	if admitted < int(60*totalRate)/2 {
		t.Fatalf("only %d admitted: clean sources starved", admitted)
	}

	// Reserve: dirty sources drain only down to cleanReserve.
	l = newLimiter(clk.now)
	for i := range 100 {
		failN(t, l, clk, "admin", fmt.Sprintf("203.0.113.%d", i), 1)
	}
	clk.add(time.Minute)
	for i := range 1000 {
		if at, err := l.begin("admin", ipa(fmt.Sprintf("203.0.113.%d", i%100))); err == nil {
			at.cancel()
		}
	}
	for i := range cleanReserve {
		at, err := l.begin("admin", ipa(fmt.Sprintf("192.0.2.%d", i)))
		if err != nil || at.delay != 0 {
			t.Fatalf("clean reserve %d not available: %v", i, err)
		}
		at.cancel()
	}
}

// Amendment 3: setup budgets are per source only. Exhausting one source's
// setup budget, or more sources than the table holds, never delays or
// refuses a new source's first attempt.
func TestLimiterSetupPerSource(t *testing.T) {
	clk := newFakeNow()
	l := newLimiter(clk.now)
	l.maxKeys = 50
	for range 3 * setupBurst {
		if at, err := l.begin("", ipa("203.0.113.9")); err == nil {
			at.cancel()
		}
	}
	if _, err := l.begin("", ipa("203.0.113.9")); err == nil {
		t.Fatal("one source's setup budget is unbounded")
	}
	for i := range 1000 {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		at, err := l.begin("", ip)
		if err != nil || at.delay != 0 {
			t.Fatalf("new setup source %d: %v delay %v", i, err, at)
		}
		at.cancel()
	}
	if len(l.setup.buckets) > l.maxKeys {
		t.Fatalf("setup buckets = %d", len(l.setup.buckets))
	}
	if len(l.login.buckets) != 0 {
		t.Fatal("setup charged a login bucket")
	}
}
