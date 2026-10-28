package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeSender struct {
	name, typ string
	mu        sync.Mutex
	got       []Event
	calls     int
	fn        func(call int) error
	block     chan struct{} // if set, Send waits for it or ctx
}

func (f *fakeSender) Name() string { return f.name }
func (f *fakeSender) Type() string {
	if f.typ == "" {
		return "webhook"
	}
	return f.typ
}
func (f *fakeSender) Send(ctx context.Context, e Event) error {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.fn != nil {
		if err := f.fn(n); err != nil {
			return err
		}
	}
	f.mu.Lock()
	f.got = append(f.got, e)
	f.mu.Unlock()
	return nil
}
func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.got) }
func (f *fakeSender) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type sleepRec struct {
	mu sync.Mutex
	ds []time.Duration
}

func (s *sleepRec) Sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.ds = append(s.ds, d)
	s.mu.Unlock()
	return ctx.Err()
}

func newTestDispatcher(t *testing.T, o Options) (*Dispatcher, *fakeClock, *sleepRec) {
	t.Helper()
	clk, sl := newClock(), &sleepRec{}
	o.Now, o.Sleep = clk.Now, sl.Sleep
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	d := NewDispatcher(o)
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = d.Close(ctx)
	})
	return d, clk, sl
}

func ev(sev Severity, key string) Event {
	return Event{Kind: "test", Severity: sev, Subject: "s", Message: "m", DedupeKey: key}
}

func TestDeliverFanOut(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	a, b := &fakeSender{name: "a"}, &fakeSender{name: "b", typ: "ntfy"}
	d.Add(a, SenderOptions{})
	d.Add(b, SenderOptions{})
	if err := d.Deliver(context.Background(), ev(Info, "")); err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || b.count() != 1 {
		t.Fatalf("a=%d b=%d", a.count(), b.count())
	}
}

func TestDeliverPartialFailureAndRetry(t *testing.T) {
	var obs sync.Map
	d, _, sl := newTestDispatcher(t, Options{RetryBackoff: 3 * time.Second,
		Observe: func(typ, res string) {
			v, _ := obs.LoadOrStore(typ+"/"+res, new(atomic.Int32))
			v.(*atomic.Int32).Add(1)
		}})
	bad := &fakeSender{name: "bad", typ: "smtp", fn: func(int) error { return errors.New("boom") }}
	good := &fakeSender{name: "good"}
	d.Add(bad, SenderOptions{})
	d.Add(good, SenderOptions{})
	err := d.Deliver(context.Background(), ev(Warning, ""))
	if err == nil || !strings.Contains(err.Error(), "bad") || strings.Contains(err.Error(), "good") {
		t.Fatalf("err = %v", err)
	}
	if good.count() != 1 {
		t.Fatal("good sender blocked by failing one")
	}
	if bad.callCount() != 2 {
		t.Fatalf("bad attempts = %d, want 2 (one retry)", bad.callCount())
	}
	if len(sl.ds) != 1 || sl.ds[0] != 3*time.Second {
		t.Fatalf("sleeps %v", sl.ds)
	}
	if v, ok := obs.Load("smtp/error"); !ok || v.(*atomic.Int32).Load() != 1 {
		t.Fatal("error not observed once")
	}
	if v, ok := obs.Load("webhook/ok"); !ok || v.(*atomic.Int32).Load() != 1 {
		t.Fatal("ok not observed")
	}
}

func TestDeliverRetrySucceeds(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	s := &fakeSender{name: "s", fn: func(n int) error {
		if n == 1 {
			return errors.New("transient")
		}
		return nil
	}}
	d.Add(s, SenderOptions{})
	if err := d.Deliver(context.Background(), ev(Info, "")); err != nil || s.count() != 1 {
		t.Fatalf("err=%v count=%d", err, s.count())
	}
}

func TestDeliverNoRetryOnPermanent(t *testing.T) {
	d, _, sl := newTestDispatcher(t, Options{})
	s := &fakeSender{name: "s", fn: func(int) error { return permanent(errors.New("HTTP 401")) }}
	d.Add(s, SenderOptions{})
	if err := d.Deliver(context.Background(), ev(Info, "")); err == nil {
		t.Fatal("want error")
	}
	if s.callCount() != 1 || len(sl.ds) != 0 {
		t.Fatalf("calls=%d sleeps=%v", s.callCount(), sl.ds)
	}
}

func TestSeverityFilter(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	s := &fakeSender{name: "s"}
	all := &fakeSender{name: "all"}
	d.Add(s, SenderOptions{MinSeverity: Warning})
	d.Add(all, SenderOptions{})
	for _, sev := range []Severity{Info, Warning, Critical} {
		if err := d.Deliver(context.Background(), ev(sev, "")); err != nil {
			t.Fatal(err)
		}
	}
	if s.count() != 2 || all.count() != 3 {
		t.Fatalf("filtered=%d all=%d", s.count(), all.count())
	}
	for _, e := range s.got {
		if e.Severity == Info {
			t.Fatal("info passed a warning filter")
		}
	}
}

func TestRateLimitTokenBucket(t *testing.T) {
	d, clk, _ := newTestDispatcher(t, Options{})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{RatePerMinute: 3})
	send := func() { _ = d.Deliver(context.Background(), ev(Info, "")) }
	for i := 0; i < 5; i++ {
		send()
	}
	if s.count() != 3 {
		t.Fatalf("burst delivered %d, want 3", s.count())
	}
	clk.Advance(20 * time.Second) // 3/min => one token per 20s
	send()
	send()
	if s.count() != 4 {
		t.Fatalf("after refill delivered %d, want 4", s.count())
	}
	clk.Advance(10 * time.Minute) // capped at burst
	for i := 0; i < 6; i++ {
		send()
	}
	if s.count() != 7 {
		t.Fatalf("after long idle delivered %d, want 7", s.count())
	}
}

func TestRateLimitReportsDropped(t *testing.T) {
	var dropped atomic.Int32
	d, _, _ := newTestDispatcher(t, Options{Observe: func(_, res string) {
		if res == "rate_limited" {
			dropped.Add(1)
		}
	}})
	d.Add(&fakeSender{name: "s"}, SenderOptions{RatePerMinute: 1})
	_ = d.Deliver(context.Background(), ev(Info, ""))
	err := d.Deliver(context.Background(), ev(Info, ""))
	if dropped.Load() != 1 || err == nil || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("dropped=%d err=%v", dropped.Load(), err)
	}
}

func TestDedupeWindow(t *testing.T) {
	d, clk, _ := newTestDispatcher(t, Options{DedupeWindow: time.Hour})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{RatePerMinute: 1000})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := d.Notify(ctx, ev(Critical, "cert:a")); err != nil {
			t.Fatal(err)
		}
	}
	_ = d.Notify(ctx, ev(Critical, "cert:b"))
	_ = d.Notify(ctx, ev(Critical, "")) // no key: never suppressed
	_ = d.Notify(ctx, ev(Critical, ""))
	clk.Advance(59 * time.Minute)
	_ = d.Notify(ctx, ev(Critical, "cert:a")) // still inside window
	clk.Advance(2 * time.Minute)
	_ = d.Notify(ctx, ev(Critical, "cert:a")) // window over
	closeAll(t, d)
	if got := s.count(); got != 1+1+2+1 {
		t.Fatalf("delivered %d, want 5", got)
	}
}

func TestDedupeDisabledByNegativeWindow(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{DedupeWindow: -1})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{RatePerMinute: 1000})
	for i := 0; i < 3; i++ {
		_ = d.Notify(context.Background(), ev(Info, "k"))
	}
	closeAll(t, d)
	if s.count() != 3 {
		t.Fatalf("got %d", s.count())
	}
}

// dedupeKeys returns how many deliveries carried each DedupeKey.
func deliveredByKey(s *fakeSender) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.got {
		out[e.DedupeKey]++
	}
	return out
}

func notifyKeys(t *testing.T, d *Dispatcher, prefix string, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		if err := d.Notify(context.Background(), ev(Info, fmt.Sprintf("%s-%d", prefix, i))); err != nil {
			t.Fatalf("notify %s-%d: %v", prefix, i, err)
		}
	}
}

// The suppression map stays bounded, live keys survive a prune, and expired
// keys no longer suppress.
func TestDedupePruneBoundsMapKeepsLiveKeys(t *testing.T) {
	d, clk, _ := newTestDispatcher(t, Options{DedupeWindow: time.Hour, QueueSize: 6000})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{RatePerMinute: 1000000})
	notifyKeys(t, d, "old", 0, 1000) // expires at t0+1h
	clk.Advance(59 * time.Minute)
	notifyKeys(t, d, "live", 0, 1000) // expires at t0+1h59m
	clk.Advance(2 * time.Minute)      // old expired, live not
	notifyKeys(t, d, "new", 0, 200)   // pushes past maxDedupeKeys: prune runs
	d.mu.Lock()
	n := len(d.seen)
	d.mu.Unlock()
	if n > maxDedupeKeys {
		t.Fatalf("map grew to %d (> %d)", n, maxDedupeKeys)
	}
	if n < 1000 {
		t.Fatalf("live keys were wiped: %d entries", n)
	}
	notifyKeys(t, d, "live", 0, 1000) // must all be suppressed still
	notifyKeys(t, d, "old", 0, 10)    // expired: accepted again
	closeAll(t, d)
	got := deliveredByKey(s)
	for i := 0; i < 1000; i++ {
		if c := got[fmt.Sprintf("live-%d", i)]; c != 1 {
			t.Fatalf("live-%d delivered %d times, want 1 (suppression lost after prune)", i, c)
		}
	}
	for i := 0; i < 10; i++ {
		if c := got[fmt.Sprintf("old-%d", i)]; c != 2 {
			t.Fatalf("old-%d delivered %d times, want 2 (expired key still suppressed)", i, c)
		}
	}
}

func TestDropsAreObserved(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	obs := func(typ, res string) { mu.Lock(); seen[typ+"/"+res]++; mu.Unlock() }
	d, _, _ := newTestDispatcher(t, Options{Observe: obs, QueueSize: 1, Timeout: time.Minute})
	s := &fakeSender{name: "s", block: make(chan struct{})}
	d.Add(s, SenderOptions{MinSeverity: Warning})
	_ = d.Notify(context.Background(), ev(Critical, "k"))
	_ = d.Notify(context.Background(), ev(Critical, "k")) // suppressed
	for s.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	_ = d.Notify(context.Background(), ev(Critical, "")) // fills the queue
	if err := d.Notify(context.Background(), ev(Critical, "")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("err = %v", err)
	}
	_ = d.Deliver(context.Background(), ev(Info, "")) // filtered
	mu.Lock()
	defer mu.Unlock()
	for _, k := range []string{"dispatcher/suppressed_dedupe", "dispatcher/dropped_queue_full", "webhook/filtered_severity"} {
		if seen[k] != 1 {
			t.Errorf("%s = %d, want 1 (all: %v)", k, seen[k], seen)
		}
	}
}

func TestSeverityMixedCaseThroughFilter(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{MinSeverity: Warning})
	for _, sev := range []Severity{"CRITICAL", " Warning", "INFO", "weird"} {
		_ = d.Deliver(context.Background(), ev(sev, ""))
	}
	if s.count() != 2 {
		t.Fatalf("delivered %d, want 2", s.count())
	}
	for _, e := range s.got {
		if e.Severity != Critical && e.Severity != Warning {
			t.Fatalf("not normalized: %q", e.Severity)
		}
	}
}

func closeAll(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCloseFlushesQueue(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{QueueSize: 16, DedupeWindow: -1})
	gate := make(chan struct{})
	s := &fakeSender{name: "s", block: gate}
	d.Add(s, SenderOptions{RatePerMinute: 1000})
	for i := 0; i < 10; i++ {
		if err := d.Notify(context.Background(), ev(Info, "")); err != nil {
			t.Fatal(err)
		}
	}
	close(gate)
	closeAll(t, d)
	if s.count() != 10 {
		t.Fatalf("flushed %d of 10", s.count())
	}
}

func TestCloseDeadlineAbortsStuckSender(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{Timeout: time.Minute})
	s := &fakeSender{name: "s", block: make(chan struct{})}
	d.Add(s, SenderOptions{})
	_ = d.Notify(context.Background(), ev(Info, ""))
	for s.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, c := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer c()
	start := time.Now()
	err := d.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("Close did not abort the stuck sender")
	}
}

func TestNotifyQueueFullDoesNotBlock(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{QueueSize: 2, DedupeWindow: -1, Timeout: time.Minute})
	s := &fakeSender{name: "s", block: make(chan struct{})}
	d.Add(s, SenderOptions{RatePerMinute: 1000})
	var full int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if err := d.Notify(context.Background(), ev(Info, "")); errors.Is(err, ErrQueueFull) {
				full++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Notify blocked on a full queue")
	}
	if full == 0 {
		t.Fatal("never reported ErrQueueFull")
	}
}

func TestNotifyAfterCloseAndNilReceiver(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	closeAll(t, d)
	closeAll(t, d) // idempotent
	if err := d.Notify(context.Background(), ev(Info, "")); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	var nd *Dispatcher
	if err := nd.Notify(context.Background(), ev(Info, "")); err != nil {
		t.Fatalf("nil dispatcher: %v", err)
	}
	if err := nd.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPanickingSenderIsContained(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{})
	p := &fakeSender{name: "p", fn: func(int) error { panic("kaboom") }}
	g := &fakeSender{name: "g"}
	d.Add(p, SenderOptions{})
	d.Add(g, SenderOptions{})
	err := d.Deliver(context.Background(), ev(Info, ""))
	if err == nil || g.count() != 1 {
		t.Fatalf("err=%v good=%d", err, g.count())
	}
	if err := d.Notify(context.Background(), ev(Info, "")); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentNotifyRaceClean(t *testing.T) {
	d, _, _ := newTestDispatcher(t, Options{QueueSize: 1024})
	s := &fakeSender{name: "s"}
	d.Add(s, SenderOptions{RatePerMinute: 100000})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = d.Notify(context.Background(), ev(Info, "k"+string(rune('a'+g))))
				if i == 25 {
					d.Add(&fakeSender{name: "late"}, SenderOptions{})
				}
			}
		}(g)
	}
	wg.Wait()
	closeAll(t, d)
}

func TestFromConfig(t *testing.T) {
	c := config.Notifications{
		Timeout: time.Second, QueueSize: 4, DedupeWindow: time.Hour,
		Webhooks: []config.WebhookCfg{{NotifyCommon: config.NotifyCommon{Name: "wh", MinSeverity: "warning", RatePerMinute: 5},
			URL: secrets.Secret("https://hooks.example.test/x")}},
		Ntfy: []config.NtfyCfg{{NotifyCommon: config.NotifyCommon{Name: "nt"}, Server: "https://ntfy.example.test", Topic: "t"}},
		SMTP: []config.SMTPCfg{{NotifyCommon: config.NotifyCommon{Name: "sm"}, Host: "mail.example.test",
			From: "a@example.test", To: []string{"b@example.test"}}},
	}
	d, err := FromConfig(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Senders(); strings.Join(got, ",") != "wh,nt,sm" {
		t.Fatalf("senders %v", got)
	}
	closeAll(t, d)
	c.Webhooks[0].URL = "ftp://x"
	c.Ntfy[0].Topic = "bad/topic"
	_, err = FromConfig(c, Options{})
	if err == nil || !strings.Contains(err.Error(), "wh") || !strings.Contains(err.Error(), "nt") {
		t.Fatalf("want joined errors, got %v", err)
	}
}
