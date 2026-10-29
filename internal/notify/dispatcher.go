package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// Dispatcher errors.
var (
	ErrQueueFull   = errors.New("notify: queue full, event dropped")
	ErrClosed      = errors.New("notify: dispatcher closed")
	ErrRateLimited = errors.New("rate limited")
)

// Sender delivers one event to one destination.
type Sender interface {
	Name() string // configured name (for logs/errors)
	Type() string // bounded kind: webhook|ntfy|smtp (for metrics)
	Send(ctx context.Context, e Event) error
}

// SenderOptions are per-sender policies.
type SenderOptions struct {
	MinSeverity   Severity // events below it are skipped (default info)
	RatePerMinute int      // token bucket size and refill per minute (default 10)
}

// Options configures a Dispatcher. Zero values pick the documented defaults.
type Options struct {
	// DedupeWindow suppresses repeats of a DedupeKey. 0 => 1h, <0 => off.
	DedupeWindow time.Duration
	// Timeout bounds each delivery attempt per sender (default 10s).
	Timeout time.Duration
	// QueueSize bounds queued events (default 64).
	QueueSize int
	// RetryBackoff is the pause before the single retry (default 2s).
	RetryBackoff time.Duration

	Now   func() time.Time                                 // injectable clock
	Sleep func(ctx context.Context, d time.Duration) error // injectable sleeper
	// Observe counts outcomes as (senderType, result). Per sender: ok, error,
	// rate_limited, filtered_severity. Dispatcher-level (senderType
	// "dispatcher"): dropped_queue_full, suppressed_dedupe. The set is closed.
	// Typically wired to Metrics.Notification.
	Observe func(senderType, result string)
	Logger  *slog.Logger
}

const (
	maxDedupeKeys = 2048
	maxDedupeKey  = 256
)

// Dispatcher fans events out to all configured senders.
//
// Concurrency model: Notify never blocks. It applies dedupe, then enqueues
// onto a bounded queue (ErrQueueFull when full) drained by one worker
// goroutine; each event is sent to all senders concurrently, each attempt
// bounded by Timeout, with one retry after RetryBackoff for transient errors.
// Dedupe is global (one window per DedupeKey across all senders) and is
// recorded when the event is enqueued, so an event that is then rate limited
// or fails everywhere still suppresses repeats for the window. A black-holed
// sender can delay delivery to the others by up to ~2*Timeout+RetryBackoff
// per event (~22s with defaults), and a burst beyond QueueSize is dropped
// (ErrQueueFull); per-sender queues would remove both limits.
// Delivery uses the dispatcher's own context, never the caller's, so a
// cancelled reconcile does not lose an alert. Close stops intake, drains the
// queue until its context expires, then aborts in-flight sends.
type Dispatcher struct {
	o   Options
	log *slog.Logger

	mu      sync.Mutex
	senders []*entry
	seen    map[string]time.Time // dedupe key -> expiry
	closed  bool
	queue   chan Event

	base   context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type entry struct {
	s    Sender
	min  Severity
	rate float64 // tokens per second
	cap  float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewDispatcher starts the worker. Add senders, then Notify; always Close.
func NewDispatcher(o Options) *Dispatcher {
	if o.DedupeWindow == 0 {
		o.DedupeWindow = time.Hour
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 64
	}
	if o.RetryBackoff <= 0 {
		o.RetryBackoff = 2 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	d := &Dispatcher{o: o, log: o.Logger, seen: map[string]time.Time{}, queue: make(chan Event, o.QueueSize), done: make(chan struct{})}
	d.base, d.cancel = context.WithCancel(context.Background())
	go d.run()
	return d
}

// FromConfig builds a dispatcher with every sender in cfg. opts supplies the
// clock/observer/logger; cfg supplies dedupe window, timeout and queue size
// when set. Invalid senders are reported together.
func FromConfig(cfg config.Notifications, opts Options) (*Dispatcher, error) {
	if cfg.DedupeWindow != 0 {
		opts.DedupeWindow = cfg.DedupeWindow
	}
	if cfg.Timeout != 0 {
		opts.Timeout = cfg.Timeout
	}
	if cfg.QueueSize != 0 {
		opts.QueueSize = cfg.QueueSize
	}
	var errs []error
	type built struct {
		s  Sender
		so SenderOptions
	}
	var all []built
	add := func(s Sender, err error, c config.NotifyCommon) {
		if err != nil {
			errs = append(errs, err)
			return
		}
		sev, ok := ParseSeverity(c.MinSeverity)
		if !ok {
			errs = append(errs, fmt.Errorf("sender %q: invalid min_severity", c.Name))
			return
		}
		all = append(all, built{s, SenderOptions{MinSeverity: sev, RatePerMinute: c.RatePerMinute}})
	}
	for _, w := range cfg.Webhooks {
		s, err := NewWebhook(w, opts.Timeout)
		add(s, err, w.NotifyCommon)
	}
	for _, n := range cfg.Ntfy {
		s, err := NewNtfy(n, opts.Timeout)
		add(s, err, n.NotifyCommon)
	}
	for _, m := range cfg.SMTP {
		s, err := NewSMTP(m, opts.Timeout)
		add(s, err, m.NotifyCommon)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	d := NewDispatcher(opts)
	for _, b := range all {
		d.Add(b.s, b.so)
	}
	return d, nil
}

// Add registers a sender; safe to call while running.
func (d *Dispatcher) Add(s Sender, so SenderOptions) {
	if so.RatePerMinute <= 0 {
		so.RatePerMinute = 10
	}
	e := &entry{s: s, min: so.MinSeverity, rate: float64(so.RatePerMinute) / 60, cap: float64(so.RatePerMinute), tokens: float64(so.RatePerMinute), last: d.o.Now()}
	d.mu.Lock()
	d.senders = append(d.senders, e)
	d.mu.Unlock()
}

// Senders lists the configured sender names in registration order.
func (d *Dispatcher) Senders() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.senders))
	for i, e := range d.senders {
		out[i] = e.s.Name()
	}
	return out
}

// Notify queues e for delivery. It never blocks and never panics. A nil
// *Dispatcher is a no-op. Events suppressed by DedupeKey return nil.
func (d *Dispatcher) Notify(_ context.Context, e Event) (err error) {
	if d == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("notify: internal error: %v", r)
		}
	}()
	e = e.normalized()
	result, err := d.enqueue(e)
	if result != "" {
		d.observe("dispatcher", result)
	}
	return err
}

// enqueue applies dedupe and queues e. result is a drop reason to observe.
func (d *Dispatcher) enqueue(e Event) (result string, err error) {
	now := d.o.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", ErrClosed
	}
	key := truncate(e.DedupeKey, maxDedupeKey)
	if key != "" && d.o.DedupeWindow > 0 {
		if exp, ok := d.seen[key]; ok && now.Before(exp) {
			return "suppressed_dedupe", nil
		}
	}
	select {
	case d.queue <- e:
	default:
		return "dropped_queue_full", ErrQueueFull
	}
	if key != "" && d.o.DedupeWindow > 0 {
		if len(d.seen) >= maxDedupeKeys {
			d.pruneLocked(now)
		}
		d.seen[key] = now.Add(d.o.DedupeWindow)
	}
	return "", nil
}

// pruneLocked drops expired keys; if that frees nothing the map is reset
// (bounded memory beats perfect suppression under a key flood).
func (d *Dispatcher) pruneLocked(now time.Time) {
	for k, exp := range d.seen {
		if !now.Before(exp) {
			delete(d.seen, k)
		}
	}
	if len(d.seen) >= maxDedupeKeys {
		d.seen = map[string]time.Time{}
	}
}

func (d *Dispatcher) run() {
	defer close(d.done)
	for e := range d.queue {
		if d.base.Err() != nil {
			continue // Close deadline passed: drop the rest
		}
		if err := d.Deliver(d.base, e); err != nil {
			d.log.Warn("notification delivery failed", "kind", e.Kind, "error", err)
		}
	}
}

// Close stops intake and waits for queued events to be delivered. When ctx
// expires first, in-flight sends are aborted, remaining events are dropped
// and ctx's error is returned. Safe to call more than once.
func (d *Dispatcher) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	select {
	case <-d.done:
		d.cancel()
		return nil
	case <-ctx.Done():
		d.cancel()
		<-d.done
		return ctx.Err()
	}
}

// Deliver synchronously sends e to every eligible sender (severity filter,
// rate limit, timeout, one retry) and returns the joined per-sender errors.
// Dedupe is applied by Notify, not here.
func (d *Dispatcher) Deliver(ctx context.Context, e Event) error {
	e = e.normalized()
	d.mu.Lock()
	senders := append([]*entry(nil), d.senders...)
	d.mu.Unlock()
	errs := make([]error, len(senders))
	var wg sync.WaitGroup
	for i, s := range senders {
		if e.Severity.Rank() < s.min.Rank() {
			d.observe(s.s.Type(), "filtered_severity")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = d.deliverOne(ctx, s, e)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (d *Dispatcher) observe(typ, res string) {
	if d.o.Observe != nil {
		d.o.Observe(typ, res)
	}
}

func (d *Dispatcher) deliverOne(ctx context.Context, s *entry, e Event) error {
	name, typ := s.s.Name(), s.s.Type()
	if !s.allow(d.o.Now()) {
		d.observe(typ, "rate_limited")
		return fmt.Errorf("sender %q: %w", name, ErrRateLimited)
	}
	err := d.attempt(ctx, s.s, e)
	if err != nil && !IsPermanent(err) && ctx.Err() == nil {
		if d.o.Sleep(ctx, d.o.RetryBackoff) == nil {
			err = d.attempt(ctx, s.s, e)
		}
	}
	if err != nil {
		d.observe(typ, "error")
		return fmt.Errorf("sender %q: %w", name, err)
	}
	d.observe(typ, "ok")
	return nil
}

func (d *Dispatcher) attempt(ctx context.Context, s Sender, e Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = permanent(fmt.Errorf("sender panicked: %v", r))
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, d.o.Timeout)
	defer cancel()
	return s.Send(cctx, e)
}

// allow takes one token, refilling by elapsed time.
func (s *entry) allow(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el := now.Sub(s.last).Seconds(); el > 0 {
		s.tokens += el * s.rate
		if s.tokens > s.cap {
			s.tokens = s.cap
		}
		s.last = now
	}
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

var _ Notifier = (*Dispatcher)(nil)
